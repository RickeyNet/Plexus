"""SNMPv3 informs (``netcontrol.snmpv3_traps``, authoritative side): the
local engine, engine ID discovery, the authenticated inform and its
Response at every security level and protocol, the Reports a sender needs
(unknown engine ID, not in time window) and the ones never sent, the
amplification bound, and a real pysnmp sender end to end.

Messages are built by ``test_snmpv3_traps.message`` (framed by hand,
signed and encrypted with pysnmp's USM services). User names, passphrases
and engine IDs are invented; addresses are from the documentation ranges.
"""

from __future__ import annotations

import asyncio

import netcontrol.snmpv3_traps as v3
import pytest
from netcontrol.routes.snmp import usm_protocols
from pysnmp.proto import api

from test_snmpv3_traps import (
    AUTH,
    AUTH_PASS,
    BLUMENTHAL,
    PRIV,
    PRIV_PASS,
    SOURCE,
    USER,
    Clock,
    creds,
    message,
    seq,
    trap_pdu,
)

P = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]
LOCAL_ID = bytes.fromhex("80004fb805aabbccddeeff001122334455")  # invented, the format new_engine_id makes
OTHER_ENGINE = bytes.fromhex("80001f8880aabbccddeeff0011")


def engine(boots: int = 4, clock: Clock | None = None) -> v3.LocalEngine:
    return v3.LocalEngine(LOCAL_ID, boots, clock=clock or Clock())


def inform(eng: v3.LocalEngine, *, auth="sha", priv="aes128", pdu=None, flags=None, **kwargs) -> bytes:
    """An InformRequest to ``eng``: its engine ID, boots and time."""
    if flags is None:
        flags = 0x04 | (0x01 if auth else 0) | (0x02 if priv else 0)
    kwargs.setdefault("engine", eng.engine_id)
    kwargs.setdefault("boots", eng.boots)
    kwargs.setdefault("engine_time", eng.engine_time)
    return message(auth=auth, priv=priv, pdu=pdu if pdu is not None else trap_pdu(kind="inform"), flags=flags, **kwargs)


def decode(data: bytes, eng: v3.LocalEngine, credentials=None, guard: v3.ReplayGuard | None = None):
    return v3.decode_snmpv3_inform(
        data, credentials if credentials is not None else creds(), eng, guard or v3.ReplayGuard(), SOURCE
    )


def opened(reply: bytes, credentials: v3.TrapV3Credentials | None = None):
    """(header, PDU) of a reply, its digest checked and its ScopedPDU
    decrypted with ``credentials`` (keys localized to the local engine)."""
    header = v3.parse_snmpv3_header(reply)
    assert header is not None and not header.reportable
    if header.auth:
        assert credentials is not None and v3._authenticated(reply, header, credentials)
    if header.priv:
        scoped = v3._decrypt(reply, header, credentials)
    else:
        start, end = header.msg_data_span
        scoped = v3._decode_scoped_pdu(reply[start:end], 0)
    assert scoped is not None
    return header, scoped, scoped.getComponentByName("data").getComponent()


def probe(*, pdu_kind: str = "get", flags: int = 0x04, request_id: int = 4711) -> bytes:
    """The RFC 3414 section 4 discovery probe: no engine ID, no user,
    noAuthNoPriv, an empty varbind list."""
    pdu = trap_pdu(kind=pdu_kind)
    P.apiPDU.set_request_id(pdu, request_id)
    P.apiPDU.set_varbinds(pdu, [])
    return message(auth=None, priv=None, engine=b"", user="", boots=0, engine_time=0, pdu=pdu, flags=flags)


# ── The local engine ─────────────────────────────────────────────────────────


def test_a_new_engine_id_has_the_rfc_3411_format():
    first, second = v3.new_engine_id(), v3.new_engine_id()
    assert len(first) == 17 and first[:5] == bytes.fromhex("80004fb805")
    assert first != second


def test_engine_time_counts_from_the_start_and_boots_latch():
    clock = Clock()
    eng = v3.LocalEngine(LOCAL_ID, 3, clock=clock)
    assert eng.engine_time == 0 and not eng.latched
    clock.now += 125.7
    assert eng.engine_time == 125
    assert v3.LocalEngine(LOCAL_ID, v3.MAX_ENGINE_VALUE + 5).latched
    assert v3.LocalEngine(LOCAL_ID, -1).boots == 0
    with pytest.raises(ValueError):
        v3.LocalEngine(b"\x80\x00", 1)
    eng.stats["wrong_digests"] = (1 << 32) - 1
    assert eng.count("wrong_digests") == 0  # a Counter32 wraps


# ── Discovery ────────────────────────────────────────────────────────────────


def test_a_discovery_probe_gets_the_unknown_engine_id_report():
    clock = Clock()
    eng = engine(boots=9, clock=clock)
    clock.now += 42
    data = probe()
    reply = v3.engine_discovery_report(data, eng)
    assert reply is not None
    header, scoped, pdu = opened(reply)
    request = v3.parse_snmpv3_header(data)
    assert header.engine_id == LOCAL_ID and (header.engine_boots, header.engine_time) == (9, 42)
    assert header.msg_id == request.msg_id and header.security_level == "noAuthNoPriv"
    assert header.user_name == b""
    assert pdu.isSameTypeWith(P.ReportPDU())
    assert int(P.apiPDU.get_request_id(pdu)) == 4711
    ((oid, value),) = P.apiPDU.get_varbinds(pdu)
    assert oid.prettyPrint() == v3.USM_STATS_OIDS["unknown_engine_ids"] and int(value) == 1
    assert eng.stats["unknown_engine_ids"] == 1 and eng.reports == 1
    # The context is the request's (here the test builder's engine ID).
    assert bytes(scoped.getComponentByName("contextEngineId")) == OTHER_ENGINE


def test_a_message_for_another_engine_is_reported_too():
    """A sender that knows a wrong engine ID learns the right one; an
    encrypted request's PDU cannot be read, so request-id is 0."""
    eng = engine()
    reply = v3.engine_discovery_report(inform(eng, engine=OTHER_ENGINE), eng)
    _header, scoped, pdu = opened(reply)
    assert int(P.apiPDU.get_request_id(pdu)) == 0
    assert bytes(scoped.getComponentByName("contextEngineId")) == LOCAL_ID


def test_no_report_without_the_reportable_flag_or_for_an_unconfirmed_pdu():
    eng = engine()
    assert v3.engine_discovery_report(probe(flags=0x00), eng) is None
    # The reportable flag on a trap (Unconfirmed Class): RFC 3412 7.1 3b.
    assert v3.engine_discovery_report(probe(pdu_kind="trap"), eng) is None
    assert v3.engine_discovery_report(probe(pdu_kind="report"), eng) is None
    # Not SNMPv3, or already for the local engine: nothing to discover.
    assert v3.engine_discovery_report(b"not snmp", eng) is None
    assert v3.engine_discovery_report(inform(eng), eng) is None
    assert eng.reports == 0


def test_an_unreadable_plaintext_pdu_still_gets_the_report():
    eng = engine()
    junk = seq(b"\x04\x00", b"\x04\x00", b"\xa7\x02\x02\x01")
    data = message(auth=None, priv=None, engine=b"", user="", scoped=junk, flags=0x04)
    _header, _scoped, pdu = opened(v3.engine_discovery_report(data, eng))
    assert int(P.apiPDU.get_request_id(pdu)) == 0


def test_the_report_is_never_much_larger_than_the_probe(monkeypatch):
    eng = engine()
    data = probe()
    reply = v3.engine_discovery_report(data, eng)
    assert len(reply) <= v3.MAX_REPLY_FACTOR * len(data)
    monkeypatch.setattr(v3, "MAX_REPLY_FACTOR", 1)
    assert v3.engine_discovery_report(data, eng) is None
    assert eng.stats["unknown_engine_ids"] == 2  # still counted


def test_a_report_that_cannot_be_built_is_not_sent(monkeypatch):
    eng = engine()

    def boom(*_a, **_k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(v3, "_report", boom)
    assert v3.engine_discovery_report(probe(), eng) is None


def test_the_inform_path_reports_an_unknown_engine():
    eng = engine()
    result = decode(probe(), eng)
    assert result.failure is v3.V3Failure.UNKNOWN_ENGINE_ID and result.reply is not None


# ── The inform and its Response ──────────────────────────────────────────────


@pytest.mark.parametrize("auth", list(AUTH))
@pytest.mark.parametrize("priv", [None, *PRIV])
def test_an_inform_at_every_level_and_protocol_is_answered(auth, priv):
    eng = engine()
    credentials = creds(auth, priv)
    data = inform(eng, auth=auth, priv=priv, msg_id=777)
    result = decode(data, eng, credentials)
    assert result.failure is None and result.ok
    trap = result.trap
    assert trap["pdu"] == "inform" and trap["version"] == "v3" and trap["user"] == USER
    assert trap["engine_id"] == LOCAL_ID.hex()
    assert trap["security_level"] == ("authPriv" if priv else "authNoPriv")
    header, scoped, pdu = opened(result.reply, credentials)
    assert header.msg_id == 777 and header.engine_id == LOCAL_ID
    assert (header.engine_boots, header.engine_time) == (eng.boots, eng.engine_time)
    assert header.security_level == trap["security_level"] and header.user == USER
    assert pdu.isSameTypeWith(P.ResponsePDU())
    assert int(P.apiPDU.get_request_id(pdu)) == trap["request_id"]
    assert int(P.apiPDU.get_error_status(pdu)) == 0
    assert [(o.prettyPrint(), v.prettyPrint()) for o, v in P.apiPDU.get_varbinds(pdu)] == trap["varbinds"]
    assert bytes(scoped.getComponentByName("contextEngineId")) == OTHER_ENGINE  # the request's context
    assert eng.responses == 1


@pytest.mark.parametrize("priv", list(BLUMENTHAL))
def test_the_response_uses_the_key_extension_the_inform_used(priv):
    eng = engine()
    credentials = creds("sha", priv)
    result = decode(inform(eng, priv=BLUMENTHAL[priv]), eng, credentials)
    assert result.ok
    header = v3.parse_snmpv3_header(result.reply)
    found = v3._decrypt_with_protocol(result.reply, header, credentials)
    assert found is not None and found[1] == BLUMENTHAL[priv]


def test_a_large_response_is_not_sent_but_the_inform_is_accepted():
    eng = engine()
    pdu = trap_pdu(kind="inform")
    P.apiPDU.set_varbinds(pdu, [("1.3.6.1.2.1.1.1.0", P.OctetString("z" * 600))])
    result = decode(inform(eng, pdu=pdu, max_size=484), eng)
    assert result.ok and result.reply is None and eng.responses == 0


# ── Refusals ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("kwargs", "failure", "stat"),
    [
        ({"user": "someone-else"}, v3.V3Failure.UNKNOWN_USER, "unknown_user_names"),
        ({"priv": None, "flags": 0x05}, v3.V3Failure.SECURITY_LEVEL, "unsupported_sec_levels"),
        ({"auth_pass": "not-the-passphrase"}, v3.V3Failure.AUTHENTICATION, "wrong_digests"),
        ({"priv_pass": "not-the-passphrase"}, v3.V3Failure.DECRYPTION, "decryption_errors"),
    ],
)
def test_a_refused_inform_is_counted_and_never_answered(kwargs, failure, stat):
    eng = engine()
    result = decode(inform(eng, **kwargs), eng)
    assert result.failure is failure and result.reply is None and not result.ok
    assert eng.stats[stat] == 1 and eng.reports == 0 and eng.responses == 0


def test_a_host_without_a_v3_user_knows_no_user():
    eng = engine()
    result = v3.decode_snmpv3_inform(inform(eng), None, eng, v3.ReplayGuard(), SOURCE)
    assert result.failure is v3.V3Failure.UNKNOWN_USER and result.reply is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"boots": 3},  # another boot
        {"boots": 0, "engine_time": 0},  # the RFC 3414 section 4 time synchronization request
        {"engine_time": 251},  # more than 150 s ahead of the local time (100)
    ],
)
def test_outside_the_time_window_gets_the_authenticated_report(kwargs):
    clock = Clock()
    eng = engine(boots=4, clock=clock)
    clock.now += 100
    credentials = creds()
    data = inform(eng, msg_id=91, **kwargs)
    result = decode(data, eng, credentials)
    assert result.failure is v3.V3Failure.NOT_IN_TIME_WINDOW
    header, _scoped, pdu = opened(result.reply, credentials)
    # RFC 3414 3.2 step 7a: authNoPriv, with the local boots and time.
    assert header.security_level == "authNoPriv" and header.msg_id == 91
    assert (header.engine_boots, header.engine_time) == (4, 100)
    assert pdu.isSameTypeWith(P.ReportPDU())
    assert int(P.apiPDU.get_request_id(pdu)) == 0  # the encrypted PDU was not read
    ((oid, value),) = P.apiPDU.get_varbinds(pdu)
    assert oid.prettyPrint() == v3.USM_STATS_OIDS["not_in_time_windows"] and int(value) == 1


def test_the_time_window_is_150_seconds_either_way():
    clock = Clock()
    eng = engine(clock=clock)
    clock.now += 1000
    assert decode(inform(eng, engine_time=850), eng).ok
    assert decode(inform(eng, engine_time=1150), eng).ok
    assert decode(inform(eng, engine_time=849), eng).failure is v3.V3Failure.NOT_IN_TIME_WINDOW


def test_an_authnopriv_time_window_report_carries_the_request_id():
    eng = engine()
    credentials = creds(priv=None)
    result = decode(inform(eng, priv=None, boots=1), eng, credentials)
    _header, _scoped, pdu = opened(result.reply, credentials)
    assert int(P.apiPDU.get_request_id(pdu)) != 0


def test_a_latched_engine_accepts_nothing():
    eng = engine(boots=v3.MAX_ENGINE_VALUE)
    result = decode(inform(eng), eng)
    assert result.failure is v3.V3Failure.NOT_IN_TIME_WINDOW


def test_an_exact_copy_of_an_inform_is_refused():
    eng = engine()
    guard = v3.ReplayGuard()
    data = inform(eng)
    assert decode(data, eng, guard=guard).ok
    copy = decode(data, eng, guard=guard)
    assert copy.failure is v3.V3Failure.REPLAYED and copy.reply is None


def test_a_message_without_the_reportable_flag_is_not_an_inform():
    eng = engine()
    assert decode(inform(eng, flags=0x03), eng).failure is v3.V3Failure.NOT_A_TRAP
    assert decode(b"junk", eng).failure is v3.V3Failure.NOT_V3


@pytest.mark.parametrize("kind", ["trap", "get"])
def test_a_pdu_other_than_an_inform_is_not_answered(kind):
    eng = engine()
    result = decode(inform(eng, pdu=trap_pdu(kind=kind)), eng)
    assert result.failure is v3.V3Failure.NOT_A_TRAP and result.reply is None


def test_a_malformed_scoped_pdu_is_refused(monkeypatch):
    eng = engine()
    junk = seq(b"\x04\x00", b"\x04\x00", b"\xa6\x02\x02\x01")
    assert decode(inform(eng, priv=None, scoped=junk), eng, creds(priv=None)).failure is v3.V3Failure.MALFORMED

    def boom(*_a, **_k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(v3, "_encode_reply", boom)
    assert decode(inform(eng), eng).failure is v3.V3Failure.MALFORMED
    monkeypatch.setattr(v3, "_decrypt_with_protocol", boom)
    assert decode(inform(eng), eng).failure is v3.V3Failure.DECRYPTION


def test_an_unusable_credential_is_a_failed_check():
    eng = engine()
    bad = v3.TrapV3Credentials(user_name=USER.encode(), auth_protocol=AUTH["sha"], auth_passphrase="пароль-€")
    result = decode(inform(eng, priv=None), eng, bad)
    assert result.failure is v3.V3Failure.AUTHENTICATION and eng.stats["wrong_digests"] == 1


def test_the_trap_path_still_refuses_informs():
    eng = engine()
    assert v3.decode_snmpv3_trap(inform(eng), creds(), v3.ReplayGuard(), SOURCE).failure is v3.V3Failure.INFORM


# ── A real sender ────────────────────────────────────────────────────────────


class _Receiver(asyncio.DatagramProtocol):
    """A loopback stand-in for the trap receiver's inform handling."""

    def __init__(self, eng: v3.LocalEngine, credentials: v3.TrapV3Credentials) -> None:
        self.eng, self.credentials, self.guard, self.informs = eng, credentials, v3.ReplayGuard(), []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        header = v3.parse_snmpv3_header(data)
        if header is not None and header.engine_id != self.eng.engine_id:
            reply = v3.engine_discovery_report(data, self.eng)
        else:
            result = v3.decode_snmpv3_inform(data, self.credentials, self.eng, self.guard, addr[0])
            reply = result.reply
            if result.ok:
                self.informs.append(result.trap)
        if reply is not None:
            self.transport.sendto(reply, addr)


@pytest.mark.parametrize(
    ("auth", "priv", "priv_proto"),
    [("md5", None, None), ("sha", "des", None), ("sha256", "aes128", None), ("sha512", "aes256", BLUMENTHAL["aes256"])],
)
async def test_a_pysnmp_sender_discovers_the_engine_and_gets_its_response(auth, priv, priv_proto):
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData,
        NotificationType,
        ObjectIdentity,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        send_notification,
    )

    eng = v3.LocalEngine(v3.new_engine_id(), 12)
    loop = asyncio.get_running_loop()
    transport, receiver = await loop.create_datagram_endpoint(
        lambda: _Receiver(eng, creds(auth, priv)), local_addr=("127.0.0.1", 0)
    )
    port = transport.get_extra_info("sockname")[1]
    auth_proto, mapped_priv = usm_protocols({"auth_protocol": auth, "priv_protocol": priv or "aes128"})
    kwargs = {"authKey": AUTH_PASS, "authProtocol": auth_proto}
    if priv:
        kwargs.update(privKey=PRIV_PASS, privProtocol=priv_proto or mapped_priv)
    sender = SnmpEngine()
    try:
        error, *_ = await send_notification(
            sender,
            UsmUserData(USER, **kwargs),
            await UdpTransportTarget.create(("127.0.0.1", port), timeout=2, retries=2),
            ContextData(),
            "inform",
            NotificationType(ObjectIdentity("1.3.6.1.6.3.1.1.5.1")),
        )
    finally:
        sender.close_dispatcher()
        transport.close()
    assert error is None  # the sender accepted the Response
    assert len(receiver.informs) == 1 and receiver.informs[0]["trap_oid"] == "1.3.6.1.6.3.1.1.5.1"
    assert eng.stats["unknown_engine_ids"] >= 1 and eng.responses == 1
