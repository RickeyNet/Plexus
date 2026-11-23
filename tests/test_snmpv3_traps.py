"""SNMPv3 trap decoding (``netcontrol.snmpv3_traps``): the keyless header
read, USM authentication and decryption for every protocol the poll offers,
the security-level, user and timeliness checks, and the credentials a host's
traps are checked with.

Messages are framed here by hand (so every field can be bent) and signed /
encrypted with pysnmp's own USM services; a second set is sent by a real
pysnmp engine over loopback. User names, passphrases and engine IDs are
invented; addresses are from the documentation ranges.
"""

from __future__ import annotations

import random
import socket
from functools import cache

import netcontrol.routes.state as state
import netcontrol.snmpv3_traps as v3
import pytest
from netcontrol.routes.snmp import SNMP_TRAP_OID, decode_snmp_trap, usm_protocols
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.entity import config as usm
from pysnmp.proto import api
from pysnmp.proto.mpmod.rfc3412 import ScopedPDU
from pysnmp.proto.secmod.rfc3414.service import SnmpUSMSecurityModel

P = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]

USER = "trap-user"
AUTH_PASS = "auth-passphrase-1"
PRIV_PASS = "priv-passphrase-1"
ENGINE = bytes.fromhex("80001f8880aabbccddeeff0011")  # invented, RFC 3411 format
SOURCE = "192.0.2.10"
OTHER_SOURCE = "198.51.100.20"
TRAP_OID = "1.3.6.1.4.1.8072.2.3.0.1"
NODE = "edge-sw-01.example.com"

AUTH = {
    "md5": usm.USM_AUTH_HMAC96_MD5,
    "sha": usm.USM_AUTH_HMAC96_SHA,
    "sha256": usm.USM_AUTH_HMAC192_SHA256,
    "sha512": usm.USM_AUTH_HMAC384_SHA512,
}
PRIV = {
    "des": usm.USM_PRIV_CBC56_DES,
    "aes128": usm.USM_PRIV_CFB128_AES,
    "aes192": usm.USM_PRIV_CFB192_AES,  # Reeder: what the poll maps "aes192" to
    "aes256": usm.USM_PRIV_CFB256_AES,
}
BLUMENTHAL = {"aes192": usm.USM_PRIV_CFB192_AES_BLUMENTHAL, "aes256": usm.USM_PRIV_CFB256_AES_BLUMENTHAL}

AUTH_SERVICES = SnmpUSMSecurityModel.AUTH_SERVICES
PRIV_SERVICES = SnmpUSMSecurityModel.PRIV_SERVICES


# ── Message builder ──────────────────────────────────────────────────────────


def tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + value


def integer(value: int) -> bytes:
    return encoder.encode(univ.Integer(value))


def octets(value: bytes) -> bytes:
    return tlv(0x04, value)


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def trap_pdu(trap_oid: str = TRAP_OID, kind: str = "trap"):
    pdu = {
        "trap": P.SNMPv2TrapPDU,
        "inform": P.InformRequestPDU,
        "get": P.GetRequestPDU,
        "report": P.ReportPDU,
    }[kind]()
    P.apiPDU.set_defaults(pdu)
    P.apiPDU.set_varbinds(
        pdu,
        [
            ("1.3.6.1.2.1.1.3.0", P.TimeTicks(4242)),
            (SNMP_TRAP_OID, P.ObjectIdentifier(trap_oid)),
            ("1.3.6.1.2.1.1.5.0", P.OctetString(NODE)),
        ],
    )
    return pdu


def scoped_pdu(pdu, context: bytes = b"") -> bytes:
    scoped = ScopedPDU()
    scoped.setComponentByPosition(0, ENGINE)
    scoped.setComponentByPosition(1, context)
    scoped.setComponentByPosition(2)
    scoped.getComponentByPosition(2).setComponentByType(
        pdu.tagSet, pdu, verifyConstraints=False, matchTags=False, matchConstraints=False
    )
    return encoder.encode(scoped)


@cache
def auth_key(proto: tuple, passphrase: str, engine: bytes) -> univ.OctetString:
    service = AUTH_SERVICES[proto]
    return univ.OctetString(service.localize_key(service.hash_passphrase(passphrase), univ.OctetString(engine)))


@cache
def priv_key(priv: tuple, auth: tuple, passphrase: str, engine: bytes) -> univ.OctetString:
    service = PRIV_SERVICES[priv]
    return univ.OctetString(service.localize_key(auth, service.hash_passphrase(auth, passphrase), univ.OctetString(engine)))


def message(
    *,
    auth: str | None = "sha",
    priv: str | tuple | None = "aes128",
    user: str = USER,
    auth_pass: str = AUTH_PASS,
    priv_pass: str = PRIV_PASS,
    engine: bytes = ENGINE,
    boots: int = 7,
    engine_time: int = 1000,
    pdu=None,
    flags: int | None = None,
    msg_id: int = 31337,
    version: int = 3,
    security_model: int = 3,
    max_size: int = 65507,
    scoped: bytes | None = None,
    auth_params_len: int | None = None,
    priv_params: bytes | None = None,
    flags_octets: bytes | None = None,
    header_extra: bytes = b"",
    usm_extra: bytes = b"",
    sp_extra: bytes = b"",
    body_extra: bytes = b"",
    mangle_ciphertext=None,
) -> bytes:
    """One SNMPv3 message: framed by hand, encrypted with pysnmp's privacy
    service and signed with its authentication service."""
    auth_proto = AUTH[auth] if auth else None
    priv_proto = (PRIV[priv] if isinstance(priv, str) else priv) if priv else None
    body = scoped if scoped is not None else scoped_pdu(pdu if pdu is not None else trap_pdu())
    salt = b""
    if priv_proto is not None:
        assert auth_proto is not None
        ciphertext, salt_os = PRIV_SERVICES[priv_proto].encrypt_data(
            priv_key(priv_proto, auth_proto, priv_pass, engine), (boots, engine_time, None), body
        )
        salt = bytes(salt_os)
        ciphertext = bytes(ciphertext)
        msg_data = octets(mangle_ciphertext(ciphertext) if mangle_ciphertext else ciphertext)
    else:
        msg_data = body
    if priv_params is not None:
        salt = priv_params
    digest_len = AUTH_SERVICES[auth_proto].digest_length if auth_proto else 0
    if auth_params_len is not None:
        digest_len = auth_params_len
    if flags is None:
        flags = (1 if auth_proto else 0) | (2 if priv_proto else 0)
    usm = seq(
        octets(engine),
        integer(boots),
        integer(engine_time),
        octets(user.encode()),
        octets(bytes(digest_len)),
        octets(salt),
        usm_extra,
    )
    whole = seq(
        integer(version),
        seq(
            integer(msg_id),
            integer(max_size),
            octets(bytes([flags]) if flags_octets is None else flags_octets),
            integer(security_model),
            header_extra,
        ),
        octets(usm + sp_extra),
        msg_data,
        body_extra,
    )
    if auth_proto and digest_len == AUTH_SERVICES[auth_proto].digest_length:
        whole = bytes(AUTH_SERVICES[auth_proto].authenticate_outgoing_message(auth_key(auth_proto, auth_pass, engine), whole))
    return whole


def config(auth: str = "sha", priv: str | None = "aes128", user: str = USER, **extra) -> dict:
    return {
        "enabled": True,
        "version": "3",
        "v3": {
            "username": user,
            "auth_protocol": auth,
            "auth_password": AUTH_PASS,
            "priv_protocol": priv or "aes128",
            "priv_password": PRIV_PASS if priv else "",
        },
        **extra,
    }


def creds(auth: str = "sha", priv: str | None = "aes128", user: str = USER) -> v3.TrapV3Credentials:
    found = v3.trap_v3_credentials(config(auth, priv, user))
    assert found is not None
    return found


def decode(data: bytes, credentials=None, guard: v3.ReplayGuard | None = None, source: str = SOURCE):
    return v3.decode_snmpv3_trap(
        data, credentials if credentials is not None else creds(), guard if guard is not None else v3.ReplayGuard(), source
    )


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# ── Round trip, every protocol ───────────────────────────────────────────────


@pytest.mark.parametrize("auth", list(AUTH))
@pytest.mark.parametrize("priv", [None, *PRIV])
def test_every_auth_and_priv_protocol_round_trips(auth, priv):
    data = message(auth=auth, priv=priv)
    result = decode(data, creds(auth, priv))
    assert result.failure is None and result.ok
    trap = result.trap
    assert trap is not None
    assert trap["version"] == "v3"
    assert trap["trap_oid"] == TRAP_OID
    assert trap["community"] == "" and trap["agent_address"] == ""
    assert trap["varbinds"][-1] == ("1.3.6.1.2.1.1.5.0", NODE)
    assert trap["user"] == USER
    assert trap["engine_id"] == ENGINE.hex()
    assert trap["security_level"] == ("authPriv" if priv else "authNoPriv")


@pytest.mark.parametrize("priv", list(BLUMENTHAL))
@pytest.mark.parametrize("auth", ["md5", "sha"])
def test_aes_192_and_256_decrypt_in_both_key_extension_variants(auth, priv):
    """The poll maps aes192 / aes256 to the Reeder (Cisco) key extension; an
    agent using Blumenthal (net-snmp) is decoded too."""
    result = decode(message(auth=auth, priv=BLUMENTHAL[priv]), creds(auth, priv))
    assert result.ok and result.trap["trap_oid"] == TRAP_OID


def test_the_trap_has_decode_snmp_trap_shape_plus_v3_fields():
    from test_apc_ups_traps import v2c_trap

    v2c = decode_snmp_trap(v2c_trap(TRAP_OID))
    trap = decode(message()).trap
    assert set(v2c) <= set(trap)
    assert set(trap) - set(v2c) == {"user", "engine_id", "security_level", "context_name"}


def test_the_context_name_is_kept():
    trap = decode(message(scoped=scoped_pdu(trap_pdu(), context=b"vrf-blue"), priv=None), creds(priv=None)).trap
    assert trap["context_name"] == "vrf-blue"


async def _send_with_pysnmp(auth: str, priv: str | None, priv_proto=None) -> bytes:
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData,
        NotificationType,
        ObjectIdentity,
        OctetString,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        send_notification,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)
    port = sock.getsockname()[1]
    auth_proto, mapped_priv = usm_protocols({"auth_protocol": auth, "priv_protocol": priv or "aes128"})
    kwargs = {"authKey": AUTH_PASS, "authProtocol": auth_proto}
    if priv:
        kwargs.update(privKey=PRIV_PASS, privProtocol=priv_proto or mapped_priv)
    engine = SnmpEngine(snmpEngineID=univ.OctetString(ENGINE))
    try:
        error, *_ = await send_notification(
            engine,
            UsmUserData(USER, **kwargs),
            await UdpTransportTarget.create(("127.0.0.1", port)),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity(TRAP_OID)).add_varbinds(("1.3.6.1.2.1.1.5.0", OctetString(NODE))),
        )
        assert error is None
        data = sock.recv(65535)  # already sent: send_notification returns after the send
    finally:
        engine.close_dispatcher()
        sock.close()
    return data


@pytest.mark.parametrize(
    ("auth", "priv", "priv_proto"),
    [
        ("md5", None, None),
        ("sha", "des", None),
        ("sha256", "aes128", None),
        ("sha512", "aes256", None),
        ("sha", "aes192", None),
        ("sha", "aes256", BLUMENTHAL["aes256"]),
    ],
)
async def test_a_trap_sent_by_a_pysnmp_engine_decodes(auth, priv, priv_proto):
    data = await _send_with_pysnmp(auth, priv, priv_proto)
    header = v3.parse_snmpv3_header(data)
    assert header is not None and header.engine_id == ENGINE and not header.reportable
    result = decode(data, creds(auth, priv))
    assert result.ok, result.failure
    assert result.trap["trap_oid"] == TRAP_OID
    assert ("1.3.6.1.2.1.1.5.0", NODE) in result.trap["varbinds"]


# ── Header ───────────────────────────────────────────────────────────────────


def test_the_header_is_read_without_a_key():
    header = v3.parse_snmpv3_header(message(boots=12, engine_time=3456, msg_id=99))
    assert header is not None
    assert (header.engine_id, header.engine_boots, header.engine_time) == (ENGINE, 12, 3456)
    assert header.user_name == USER.encode() and header.user == USER
    assert header.engine_id_hex == ENGINE.hex()
    assert header.msg_id == 99 and header.msg_max_size == 65507
    assert header.auth and header.priv and not header.reportable
    assert header.security_level == "authPriv"
    assert len(header.priv_params) == 8
    assert v3.parse_snmpv3_header(message(priv=None)).security_level == "authNoPriv"
    assert v3.parse_snmpv3_header(message(auth=None, priv=None)).security_level == "noAuthNoPriv"
    assert v3.parse_snmpv3_header(bytearray(message())) is not None


def test_a_v2c_trap_is_not_v3():
    from test_apc_ups_traps import v1_trap, v2c_trap

    for data in (v2c_trap(TRAP_OID), v1_trap(5)):
        assert v3.parse_snmpv3_header(data) is None
        assert decode(data).failure is v3.V3Failure.NOT_V3


def test_every_truncation_is_refused_without_raising():
    data = message()
    for cut in range(len(data)):
        assert v3.parse_snmpv3_header(data[:cut]) is None
        assert decode(data[:cut]).failure is v3.V3Failure.NOT_V3


def test_garbage_is_refused():
    rng = random.Random(3414)
    for size in (0, 1, 15, 16, 100, 1500):
        for _ in range(50):
            junk = bytes(rng.getrandbits(8) for _ in range(size))
            assert v3.parse_snmpv3_header(junk) is None
    assert v3.parse_snmpv3_header(b"\x30" + b"\xff" * 40) is None
    assert v3.parse_snmpv3_header("not bytes") is None  # type: ignore[arg-type]
    assert v3.parse_snmpv3_header(None) is None  # type: ignore[arg-type]
    assert v3.parse_snmpv3_header(message() + b"\x00") is None  # trailing octets


def test_an_oversized_datagram_is_refused_before_parsing():
    big = message(scoped=scoped_pdu(_big_pdu()), priv=None)
    assert len(big) > v3.MAX_V3_MESSAGE_SIZE
    assert v3.parse_snmpv3_header(big) is None
    assert decode(big, creds(priv=None)).failure is v3.V3Failure.NOT_V3


def _big_pdu():
    pdu = trap_pdu()
    P.apiPDU.set_varbinds(pdu, [("1.3.6.1.2.1.1.1.0", P.OctetString("x" * (v3.MAX_V3_MESSAGE_SIZE + 10)))])
    return pdu


@pytest.mark.parametrize(
    "kwargs",
    [
        {"version": 1},  # msgVersion is not 3
        {"security_model": 2},  # not USM
        {"max_size": 483},  # under RFC 3412's 484
        {"flags": 0x02},  # privFlag without authFlag (RFC 3412 7.2 step 5)
        {"flags": 0x01},  # authNoPriv flags over an encryptedPDU
        {"engine": b"\x80\x00\x01"},  # engine ID shorter than 5 octets
        {"engine": b"\x80" * 33},  # engine ID longer than 32
        {"user": "u" * 33},  # user name longer than 32
        {"auth_params_len": 65},  # no digest is that long
        {"priv_params": b"\x00" * 9},  # the salt is 8 octets
        {"msg_id": -3},  # a negative INTEGER
        {"msg_id": 2**31},  # over INTEGER (0..2147483647)
        {"flags_octets": b""},  # msgFlags is one octet
        {"flags_octets": b"\x03\x00"},
        {"header_extra": integer(9)},  # a fifth HeaderData field
        {"usm_extra": integer(9)},  # a seventh UsmSecurityParameters field
        {"sp_extra": bytes(2)},  # octets after UsmSecurityParameters
        {"body_extra": integer(9)},  # a fifth SNMPv3Message field
    ],
)
def test_malformed_headers_are_refused(kwargs):
    assert v3.parse_snmpv3_header(message(**kwargs)) is None


def test_ber_the_header_never_needs_is_refused():
    data = bytearray(message(priv=None))
    # An indefinite outer length (X.690 8.1.3.6).
    assert v3.parse_snmpv3_header(bytes([0x30, 0x80]) + bytes(data[2:]) + b"\x00\x00") is None
    # A five-octet length field.
    body = bytes(data[2:]) if data[1] < 0x80 else bytes(data[2 + (data[1] & 0x7F) :])
    assert v3.parse_snmpv3_header(b"\x30\x85\x00" + len(body).to_bytes(4, "big") + body) is None


def test_a_long_form_length_is_accepted():
    data = message(scoped=scoped_pdu(_padded_pdu()), priv=None)
    assert data[1] & 0x80
    assert decode(data, creds(priv=None)).ok


def _padded_pdu():
    pdu = trap_pdu()
    P.apiPDU.set_varbinds(pdu, [(SNMP_TRAP_OID, P.ObjectIdentifier(TRAP_OID)), ("1.3.6.1.2.1.1.1.0", P.OctetString("y" * 300))])
    return pdu


# ── Refusals ─────────────────────────────────────────────────────────────────


def test_a_wrong_auth_passphrase_fails_authentication():
    assert decode(message(auth_pass="not-the-passphrase")).failure is v3.V3Failure.AUTHENTICATION


def test_a_wrong_auth_protocol_fails_authentication():
    assert decode(message(auth="md5"), creds("sha256")).failure is v3.V3Failure.AUTHENTICATION
    assert decode(message(auth="md5", priv=None), creds("sha", None)).failure is v3.V3Failure.AUTHENTICATION


def test_a_wrong_priv_passphrase_fails_decryption():
    assert decode(message(priv_pass="not-the-passphrase")).failure is v3.V3Failure.DECRYPTION


def test_a_wrong_priv_protocol_fails_decryption():
    assert decode(message(priv="des"), creds(priv="aes128")).failure is v3.V3Failure.DECRYPTION
    assert decode(message(priv="aes128"), creds(priv="des")).failure is v3.V3Failure.DECRYPTION


def test_another_user_is_unknown():
    assert decode(message(user="someone-else")).failure is v3.V3Failure.UNKNOWN_USER
    assert decode(message(), creds(user="someone-else")).failure is v3.V3Failure.UNKNOWN_USER


def test_a_host_without_v3_credentials_knows_no_user():
    result = v3.decode_snmpv3_trap(message(), None, v3.ReplayGuard(), SOURCE)
    assert result.failure is v3.V3Failure.UNKNOWN_USER
    assert result.header is not None and result.header.user == USER


def test_a_weaker_message_is_refused_for_a_stronger_host():
    """A host configured authPriv never accepts authNoPriv or noAuthNoPriv,
    even signed with the right key; an authNoPriv host never accepts
    noAuthNoPriv."""
    priv_host = creds()
    assert decode(message(priv=None), priv_host).failure is v3.V3Failure.SECURITY_LEVEL
    assert decode(message(auth=None, priv=None), priv_host).failure is v3.V3Failure.SECURITY_LEVEL
    auth_host = creds(priv=None)
    assert decode(message(auth=None, priv=None), auth_host).failure is v3.V3Failure.SECURITY_LEVEL


def test_a_stronger_message_is_refused_for_a_host_without_privacy():
    assert decode(message(), creds(priv=None)).failure is v3.V3Failure.SECURITY_LEVEL


@pytest.mark.parametrize("where", ["payload", "digest", "boots", "user"])
def test_a_tampered_message_fails_authentication(where):
    data = bytearray(message(boots=7))
    header = v3.parse_snmpv3_header(bytes(data))
    if where == "payload":
        data[-3] ^= 0x01
    elif where == "digest":
        data[header.auth_params_span[0]] ^= 0x80
    elif where == "boots":
        pos = bytes(data).index(integer(7) + integer(1000))
        data[pos + 2] = 8
    else:  # same length, different user: the key no longer matches the name
        assert decode(bytes(data).replace(b"trap-user", b"trap-usex"), creds(user="trap-usex")).failure is (
            v3.V3Failure.AUTHENTICATION
        )
        return
    assert decode(bytes(data)).failure is v3.V3Failure.AUTHENTICATION


def test_a_digest_of_the_wrong_length_fails_authentication():
    data = message(priv=None, auth_params_len=8)
    assert decode(data, creds(priv=None)).failure is v3.V3Failure.AUTHENTICATION


def test_an_empty_engine_id_is_a_discovery_probe():
    data = message(engine=b"", auth=None, priv=None)
    assert v3.parse_snmpv3_header(data).engine_id == b""
    assert decode(data).failure is v3.V3Failure.UNKNOWN_ENGINE_ID


def test_informs_are_not_answered():
    reportable = message(flags=0x07)
    assert v3.parse_snmpv3_header(reportable).reportable
    assert decode(reportable).failure is v3.V3Failure.INFORM
    # An InformRequest without the reportable flag is refused all the same.
    assert decode(message(pdu=trap_pdu(kind="inform"))).failure is v3.V3Failure.INFORM


@pytest.mark.parametrize("kind", ["get", "report"])
def test_a_pdu_other_than_a_trap_is_not_a_trap(kind):
    result = decode(message(pdu=trap_pdu(kind=kind)))
    assert result.failure is v3.V3Failure.NOT_A_TRAP
    assert result.trap is None and not result.ok


def test_an_authenticated_but_malformed_scoped_pdu_is_refused():
    junk = seq(octets(ENGINE), octets(b""), tlv(0xA7, b"\x02\x01"))
    assert decode(message(priv=None, scoped=junk), creds(priv=None)).failure is v3.V3Failure.MALFORMED
    # Encrypted junk decrypts to junk.
    assert decode(message(scoped=b"\x01" * 40)).failure is v3.V3Failure.DECRYPTION
    # Decrypted ScopedPDU followed by more than padding.
    assert decode(message(scoped=scoped_pdu(trap_pdu()) + bytes(40))).failure is v3.V3Failure.DECRYPTION


def test_a_salt_of_the_wrong_length_fails_decryption():
    assert decode(message(priv_params=b"\x01\x02\x03")).failure is v3.V3Failure.DECRYPTION


def test_a_des_ciphertext_not_in_whole_blocks_fails_decryption():
    data = message(priv="des", mangle_ciphertext=lambda c: c[:-3])
    assert decode(data, creds(priv="des")).failure is v3.V3Failure.DECRYPTION


def test_unusable_credentials_fail_without_raising(monkeypatch):
    data = message()
    bad_name = v3.TrapV3Credentials(user_name=USER.encode(), auth_protocol=AUTH["sha"], auth_passphrase="пароль-€")
    result = decode(message(priv=None), bad_name)
    assert result.failure is v3.V3Failure.AUTHENTICATION
    unknown_auth = v3.TrapV3Credentials(user_name=USER.encode(), auth_protocol=(1, 3, 6, 1, 99), auth_passphrase=AUTH_PASS)
    assert decode(message(priv=None), unknown_auth).failure is v3.V3Failure.AUTHENTICATION
    unknown_priv = v3.TrapV3Credentials(
        user_name=USER.encode(),
        auth_protocol=AUTH["sha"],
        auth_passphrase=AUTH_PASS,
        priv_protocol=(1, 3, 6, 1, 99),
        priv_passphrase=PRIV_PASS,
    )
    assert decode(data, unknown_priv).failure is v3.V3Failure.DECRYPTION

    def boom(*_args, **_kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(v3, "_decrypt", boom)
    assert decode(data).failure is v3.V3Failure.DECRYPTION
    monkeypatch.setattr(v3, "_varbinds", boom)
    assert decode(message(priv=None), creds(priv=None)).failure is v3.V3Failure.MALFORMED


# ── Replay protection ────────────────────────────────────────────────────────


def test_the_first_message_from_an_engine_is_accepted_and_starts_its_timeline():
    guard = v3.ReplayGuard()
    assert decode(message(boots=3, engine_time=50), guard=guard).ok
    assert guard.size == 1


def test_an_exact_replay_is_refused():
    guard = v3.ReplayGuard()
    data = message()
    assert decode(data, guard=guard).ok
    assert decode(data, guard=guard).failure is v3.V3Failure.REPLAYED


def test_messages_outside_the_time_window_are_refused():
    clock = Clock()
    guard = v3.ReplayGuard(clock=clock)
    assert decode(message(boots=5, engine_time=1000), guard=guard).ok
    # Same boots, at most 150 s behind: timely (a reordered trap).
    assert decode(message(boots=5, engine_time=860), guard=guard).ok
    # More than 150 s behind the latest seen.
    assert decode(message(boots=5, engine_time=849), guard=guard).failure is v3.V3Failure.NOT_IN_TIME_WINDOW
    # An older boot.
    assert decode(message(boots=4, engine_time=5000), guard=guard).failure is v3.V3Failure.NOT_IN_TIME_WINDOW
    # The engine's clock runs with ours: 1000 s later, time 900 (timely a
    # moment ago) is stale.
    clock.now += 1000
    assert decode(message(boots=5, engine_time=900), guard=guard).failure is v3.V3Failure.NOT_IN_TIME_WINDOW
    # A message newer than any seen resynchronizes the notion (3.2.7 b) ...
    assert decode(message(boots=5, engine_time=1100), guard=guard).ok
    # ... and the window then hangs off it.
    assert decode(message(boots=5, engine_time=949), guard=guard).failure is v3.V3Failure.NOT_IN_TIME_WINDOW
    assert decode(message(boots=5, engine_time=950), guard=guard).ok
    # A reboot (boots up, time restarts) moves the timeline forward.
    assert decode(message(boots=6, engine_time=2), guard=guard).ok
    assert decode(message(boots=5, engine_time=2000), guard=guard).failure is v3.V3Failure.NOT_IN_TIME_WINDOW


def test_a_latched_engine_is_never_timely():
    guard = v3.ReplayGuard()
    assert decode(message(boots=v3.MAX_ENGINE_VALUE), guard=guard).failure is v3.V3Failure.NOT_IN_TIME_WINDOW
    assert decode(message(boots=1, engine_time=10), guard=guard).ok
    assert decode(message(boots=v3.MAX_ENGINE_VALUE, engine_time=10), guard=guard).failure is (
        v3.V3Failure.NOT_IN_TIME_WINDOW
    )


def test_a_forged_message_does_not_move_the_timeline():
    guard = v3.ReplayGuard()
    assert decode(message(boots=5, engine_time=1000), guard=guard).ok
    forged = message(boots=900, engine_time=1, auth_pass="attacker-guess")
    assert decode(forged, guard=guard).failure is v3.V3Failure.AUTHENTICATION
    assert decode(message(boots=5, engine_time=1001), guard=guard).ok


def test_each_source_keeps_its_own_timeline():
    guard = v3.ReplayGuard()
    data = message()
    assert decode(data, guard=guard, source=SOURCE).ok
    assert decode(data, guard=guard, source=OTHER_SOURCE).ok
    assert guard.size == 2


def test_the_guard_is_bounded():
    guard = v3.ReplayGuard(max_engines=2, recent_per_engine=2)
    for i in range(5):
        assert guard.admit(f"203.0.113.{i}", ENGINE, 1, 10, b"d") is None
    assert guard.size == 2
    # The least recently seen were evicted: the first source starts over.
    assert guard.admit("203.0.113.0", ENGINE, 1, 10, b"d") is None
    # Only the last ``recent_per_engine`` digests are remembered.
    for digest in (b"a", b"b", b"c"):
        assert guard.admit(SOURCE, ENGINE, 1, 10, digest) is None
    assert guard.admit(SOURCE, ENGINE, 1, 10, b"c") is v3.V3Failure.REPLAYED
    assert guard.admit(SOURCE, ENGINE, 1, 10, b"a") is None


# ── Credentials ──────────────────────────────────────────────────────────────


def test_credentials_are_the_polls_v3_user():
    found = v3.trap_v3_credentials(config("sha256", "aes256"))
    expected_auth, expected_priv = usm_protocols({"auth_protocol": "sha256", "priv_protocol": "aes256"})
    assert found.user_name == USER.encode()
    assert found.auth_protocol == tuple(expected_auth)
    assert found.priv_protocol == tuple(expected_priv)
    assert found.security_level == "authPriv"
    assert v3.trap_v3_credentials(config("md5", None)).security_level == "authNoPriv"
    assert AUTH_PASS not in repr(found) and PRIV_PASS not in repr(found)


def test_an_unknown_protocol_name_falls_back_as_the_poll_does():
    found = v3.trap_v3_credentials(config("whirlpool", "rot13"))
    assert found.auth_protocol == AUTH["sha"] and found.priv_protocol == PRIV["aes128"]


@pytest.mark.parametrize(
    "cfg",
    [
        None,
        {},
        {"version": "2c", "community": "ro", "v3": config()["v3"]},
        {"version": "3"},
        {"version": "3", "v3": "nope"},
        config(user=""),
        {"version": "3", "v3": {**config()["v3"], "auth_password": ""}},
        {"version": "3", "v3": {**config()["v3"], "auth_password": "{{secret.snmp_auth}}"}},
        {"version": "3", "v3": {**config()["v3"], "priv_password": "{{secret.snmp_priv}}"}},
        config(user="пользователь"),
    ],
)
def test_no_credentials_without_a_usable_v3_user(cfg):
    assert v3.trap_v3_credentials(cfg) is None


def test_no_credentials_without_pysnmp_protocols(monkeypatch):
    """``usm_protocols`` gives None when pysnmp's hlapi did not import."""
    monkeypatch.setattr(v3, "usm_protocols", lambda _v3: (None, None))
    assert v3.trap_v3_credentials(config()) is None


@pytest.fixture
def snmp_state(monkeypatch):
    monkeypatch.setattr(state, "SNMP_PROFILES", {})
    monkeypatch.setattr(state, "GROUP_SNMP_ASSIGNMENTS", {})
    monkeypatch.setattr(state, "SNMP_DISCOVERY_PROFILES", {})
    monkeypatch.setattr(state, "SNMP_DISCOVERY_CONFIG", {"enabled": True, "version": "2c", "community": "global-ro"})


async def test_a_host_resolves_to_its_own_profile_user(snmp_state, monkeypatch):
    monkeypatch.setattr(state, "SNMP_PROFILES", {"p-v3": state._sanitize_snmp_profile("p-v3", config("sha512", "des"))})
    host = {"id": 1, "group_id": None, "snmp_profile_id": "p-v3", "ip_address": "192.0.2.30"}
    found = await v3.resolve_trap_v3_credentials(host)
    assert found is not None and found.priv_protocol == PRIV["des"] and found.auth_protocol == AUTH["sha512"]
    assert decode(message(auth="sha512", priv="des"), found).ok


async def test_a_host_without_a_profile_uses_the_global_config(snmp_state, monkeypatch):
    host = {"id": 2, "group_id": None, "snmp_profile_id": ""}
    assert await v3.resolve_trap_v3_credentials(host) is None
    monkeypatch.setattr(state, "SNMP_DISCOVERY_CONFIG", config("md5", None))
    found = await v3.resolve_trap_v3_credentials(host)
    assert found is not None and found.security_level == "authNoPriv"


async def test_secret_references_are_resolved_like_the_poll(snmp_state, monkeypatch):
    import routes.secret_resolver as secret_resolver

    async def fake_resolve(values, **_kwargs):
        return [AUTH_PASS if "auth" in v else PRIV_PASS for v in values]

    monkeypatch.setattr(secret_resolver, "resolve_secrets", fake_resolve)
    cfg = config()
    cfg["v3"].update(auth_password="{{secret.trap_auth}}", priv_password="{{secret.trap_priv}}")
    monkeypatch.setattr(state, "SNMP_DISCOVERY_CONFIG", cfg)
    found = await v3.resolve_trap_v3_credentials({"id": 3, "group_id": None})
    assert found is not None and decode(message(), found).ok


def test_master_keys_are_cached():
    v3._auth_master_key.cache_clear()
    decode(message())
    decode(message(boots=8))
    info = v3._auth_master_key.cache_info()
    assert info.misses == 1 and info.hits >= 1


def test_the_receiver_never_raises_on_random_bytes_inside_a_valid_frame():
    """Random msgData inside an otherwise valid, correctly signed frame."""
    rng = random.Random(3826)
    for size in range(30, 50):
        junk = seq(bytes(rng.getrandbits(8) for _ in range(size)))
        result = decode(message(priv=None, scoped=junk), creds(priv=None))
        assert result.failure in {v3.V3Failure.MALFORMED, v3.V3Failure.NOT_A_TRAP}
