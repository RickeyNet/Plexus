"""SNMPv3 trap decoding: the USM checks a trap receiver makes before it
believes an SNMPv3 SNMPv2-Trap.

A trap receiver is the *non-authoritative* side of USM: the agent that sends
a trap is authoritative, so the message carries the agent's own engine ID,
boots and time, and the user's keys are localized to that engine ID (RFC
3414 section 2.5.2). Everything here is synchronous and free of I/O except
``resolve_trap_v3_credentials``, which reads the host's stored config and
resolves ``{{secret.NAME}}`` references the way the poll does.

* ``parse_snmpv3_header`` -- a bounded, keyless read of the unencrypted
  RFC 3412 / RFC 3414 header. Cheap enough for the UDP hot path.
* ``decode_snmpv3_trap`` -- authenticates (RFC 3414 section 3.2.6, constant
  time), checks the timeliness window against a caller-owned
  ``ReplayGuard`` (section 3.2.7), decrypts (section 3.2.8: CBC-DES RFC 3414
  section 8, CFB-AES RFC 3826, AES-192/256 in both key-extension variants)
  and returns the trap in the shape ``netcontrol.routes.snmp.decode_snmp_trap``
  returns, or a typed ``V3Failure``.
* ``trap_v3_credentials`` / ``resolve_trap_v3_credentials`` -- the stored
  poll credentials of a host, as the trap decoder needs them.

InformRequest is not answered: a receiver of an inform is the authoritative
engine, which needs its own engine ID and an snmpEngineBoots that survives a
restart (RFC 3414 section 2.2.2). A message with the reportable flag set, or
an InformRequest PDU, is refused as ``V3Failure.INFORM``.

Key derivation (password to key, key localization, AES key extension) and
the ciphers are pysnmp's own USM services; this module frames the message
itself so it can read the exact byte offsets the HMAC covers, and compares
digests with ``hmac.compare_digest`` (pysnmp's own check does not).
"""

from __future__ import annotations

import enum
import hmac
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.type import univ
from pysnmp.entity import config as usm
from pysnmp.proto import api as snmp_api
from pysnmp.proto.mpmod.rfc3412 import ScopedPDU
from pysnmp.proto.secmod.rfc3414.service import SnmpUSMSecurityModel

from netcontrol.routes.snmp import SNMP_TRAP_OID, _resolve_snmp_secrets, usm_protocols

# ── Limits ───────────────────────────────────────────────────────────────────

# The largest datagram looked at. RFC 3417 section 3.2 only obliges 484
# octets; agents keep traps under the path MTU. Anything larger is refused
# before a byte of it is parsed.
MAX_V3_MESSAGE_SIZE = 16 * 1024

# RFC 3414 section 2.2.3: a message is timely within 150 seconds.
TIME_WINDOW_SECONDS = 150

# RFC 3414 section 2.2.2: snmpEngineBoots and snmpEngineTime are 0..2^31-1;
# boots at the maximum latches the engine (no message is ever timely).
MAX_ENGINE_VALUE = 2147483647

# RFC 3411 SnmpEngineID: SIZE(5..32). RFC 3414 msgUserName: SIZE(0..32).
_ENGINE_ID_MIN, _ENGINE_ID_MAX = 5, 32
_USER_NAME_MAX = 32
# RFC 3412 HeaderData msgMaxSize: INTEGER (484..2147483647).
_MIN_MSG_MAX_SIZE = 484
# RFC 3412 section 6: SNMPv3 is msgVersion 3; USM is security model 3.
_SNMP_V3 = 3
_USM = 3
# msgAuthenticationParameters is the digest (at most 48 octets: HMAC-384-
# SHA-512); msgPrivacyParameters is the 8-octet salt (RFC 3414 8.1.1.1,
# RFC 3826 3.1.2.1).
_AUTH_PARAMS_MAX = 64
_PRIV_PARAMS_LEN = 8
# Trailing octets after a decrypted ScopedPDU: CBC-DES pads to a multiple of
# 8 (RFC 3414 section 8.1.1.2); more than that is a wrong key.
_MAX_PLAINTEXT_PADDING = 16

# msgFlags bits, RFC 3412 section 6.4.
_FLAG_AUTH = 0x01
_FLAG_PRIV = 0x02
_FLAG_REPORTABLE = 0x04

# BER tags (X.690): the only ones the SNMPv3 framing uses.
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_SEQUENCE = 0x30

# RFC 3411 securityLevel names.
NO_AUTH_NO_PRIV = "noAuthNoPriv"
AUTH_NO_PRIV = "authNoPriv"
AUTH_PRIV = "authPriv"

# ── pysnmp USM services ──────────────────────────────────────────────────────

_AUTH_SERVICES = SnmpUSMSecurityModel.AUTH_SERVICES
_PRIV_SERVICES = SnmpUSMSecurityModel.PRIV_SERVICES

# The HMAC digest of each authentication protocol: HMAC-MD5-96 and
# HMAC-SHA-96 (RFC 3414 sections 6 and 7) are RFC 2104 HMAC truncated to 12
# octets, the SHA-2 family RFC 7860 section 4.2. The protocol mandates MD5 /
# SHA-1 here; they are not chosen by Plexus.
_HMAC_DIGEST = {
    usm.USM_AUTH_HMAC96_MD5: "md5",
    usm.USM_AUTH_HMAC96_SHA: "sha1",
    usm.USM_AUTH_HMAC128_SHA224: "sha224",
    usm.USM_AUTH_HMAC192_SHA256: "sha256",
    usm.USM_AUTH_HMAC256_SHA384: "sha384",
    usm.USM_AUTH_HMAC384_SHA512: "sha512",
}

# AES-192 / AES-256 key extension is vendor-specific: the poll maps the
# stored names to the Reeder variant (Cisco and most vendors), net-snmp uses
# Blumenthal (draft-blumenthal-aes-usm-04). The cipher is the same, so a
# trap that does not decrypt under one is tried under the other.
_AES_KEY_EXTENSION_PEER = {
    usm.USM_PRIV_CFB192_AES: usm.USM_PRIV_CFB192_AES_BLUMENTHAL,
    usm.USM_PRIV_CFB192_AES_BLUMENTHAL: usm.USM_PRIV_CFB192_AES,
    usm.USM_PRIV_CFB256_AES: usm.USM_PRIV_CFB256_AES_BLUMENTHAL,
    usm.USM_PRIV_CFB256_AES_BLUMENTHAL: usm.USM_PRIV_CFB256_AES,
}

_V2C = snmp_api.PROTOCOL_MODULES[snmp_api.SNMP_VERSION_2C]


# ── Results ──────────────────────────────────────────────────────────────────


class V3Failure(enum.StrEnum):
    """Why an SNMPv3 datagram was not accepted as a trap. The values are
    stable counter names."""

    NOT_V3 = "not_v3"  # not a well-formed SNMPv3 / USM message
    UNKNOWN_ENGINE_ID = "unknown_engine_id"  # empty engine ID: a discovery probe (RFC 3414 3.2.3)
    UNKNOWN_USER = "unknown_user"  # no credentials, or another user name (RFC 3414 3.2.4)
    SECURITY_LEVEL = "wrong_security_level"  # not the host's configured level (RFC 3414 3.2.5)
    AUTHENTICATION = "authentication_failed"  # wrong digest (RFC 3414 3.2.6)
    NOT_IN_TIME_WINDOW = "not_in_time_window"  # stale boots / time (RFC 3414 3.2.7)
    REPLAYED = "replayed"  # the same authenticated message seen before
    DECRYPTION = "decryption_failed"  # RFC 3414 3.2.8
    MALFORMED = "malformed_scoped_pdu"  # authenticated, but the ScopedPDU is not valid BER
    INFORM = "inform_unsupported"  # confirmed class: Plexus is not an authoritative engine
    NOT_A_TRAP = "not_a_trap"  # a PDU other than SNMPv2-Trap


# The failures that mean the message did not come from the host's own SNMPv3
# user as configured (a forgery, a replay, or a device whose trap user is not
# the host's poll user). A receiver drops these; the others (an inform, a
# discovery probe, another PDU, a malformed ScopedPDU) say nothing about the
# sender and are kept as undecoded traps.
REFUSED = frozenset(
    {
        V3Failure.UNKNOWN_USER,
        V3Failure.SECURITY_LEVEL,
        V3Failure.AUTHENTICATION,
        V3Failure.NOT_IN_TIME_WINDOW,
        V3Failure.REPLAYED,
        V3Failure.DECRYPTION,
    }
)


@dataclass(frozen=True)
class PendingV3Trap:
    """An SNMPv3 datagram queued by the receiver for the keyed decode in its
    batch writer: the whole datagram (at most ``MAX_V3_MESSAGE_SIZE``), its
    unauthenticated header already read."""

    data: bytes = field(repr=False)
    header: V3Header


@dataclass(frozen=True)
class V3Header:
    """The unencrypted part of an SNMPv3 / USM message (RFC 3412 section 6,
    RFC 3414 section 2.4). Nothing here is authenticated yet."""

    msg_id: int
    msg_max_size: int
    flags: int
    engine_id: bytes
    engine_boots: int
    engine_time: int
    user_name: bytes
    auth_params: bytes
    priv_params: bytes
    # Byte offsets in the datagram: the digest the HMAC is computed with
    # zeroed (RFC 3414 6.3.2 / 7.3.2 step 3) and the msgData TLV.
    auth_params_span: tuple[int, int] = field(repr=False)
    msg_data_span: tuple[int, int] = field(repr=False)

    @property
    def auth(self) -> bool:
        return bool(self.flags & _FLAG_AUTH)

    @property
    def priv(self) -> bool:
        return bool(self.flags & _FLAG_PRIV)

    @property
    def reportable(self) -> bool:
        return bool(self.flags & _FLAG_REPORTABLE)

    @property
    def security_level(self) -> str:
        if self.priv:
            return AUTH_PRIV
        return AUTH_NO_PRIV if self.auth else NO_AUTH_NO_PRIV

    @property
    def engine_id_hex(self) -> str:
        return self.engine_id.hex()

    @property
    def user(self) -> str:
        return self.user_name.decode("utf-8", "replace")


@dataclass(frozen=True)
class TrapV3Result:
    """``trap`` (the decoded trap) when accepted, else ``failure``.
    ``header`` is set whenever the datagram was well-formed SNMPv3."""

    trap: dict | None = None
    failure: V3Failure | None = None
    header: V3Header | None = None

    @property
    def ok(self) -> bool:
        return self.trap is not None


@dataclass(frozen=True)
class TrapV3Credentials:
    """One host's SNMPv3 user as the trap decoder needs it: the stored poll
    user (``trap_v3_credentials``). Passphrases are not in the repr."""

    user_name: bytes
    auth_protocol: tuple[int, ...]
    auth_passphrase: str = field(repr=False)
    priv_protocol: tuple[int, ...] | None = None
    priv_passphrase: str = field(default="", repr=False)

    @property
    def security_level(self) -> str:
        return AUTH_PRIV if self.priv_protocol is not None else AUTH_NO_PRIV


# ── Header parsing (keyless, hot path) ───────────────────────────────────────


class _Malformed(Exception):
    """Internal: the bytes are not the expected BER."""


def _tlv(data: bytes, pos: int, end: int, tag: int) -> tuple[int, int]:
    """The (value start, value end) of the definite-length TLV with ``tag``
    at ``pos``, which must lie within ``end``. Indefinite lengths and length
    fields over 4 octets are refused (X.690 8.1.3; SNMP never needs them)."""
    if pos + 2 > end or data[pos] != tag:
        raise _Malformed
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > end:
            raise _Malformed
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + length > end:
        raise _Malformed
    return pos, pos + length


def _integer(data: bytes, pos: int, end: int) -> tuple[int, int]:
    """A non-negative BER INTEGER no larger than 2^31-1 (every SNMPv3 header
    integer is ``INTEGER (0..2147483647)``): (value, next position)."""
    start, stop = _tlv(data, pos, end, _TAG_INTEGER)
    if not 1 <= stop - start <= 5 or data[start] & 0x80:
        raise _Malformed
    value = int.from_bytes(data[start:stop], "big")
    if value > MAX_ENGINE_VALUE:
        raise _Malformed
    return value, stop


def _octets(data: bytes, pos: int, end: int, max_len: int) -> tuple[int, int]:
    start, stop = _tlv(data, pos, end, _TAG_OCTET_STRING)
    if stop - start > max_len:
        raise _Malformed
    return start, stop


def _parse_header(data: bytes) -> V3Header:
    end = len(data)
    # RFC 3412 section 6: SNMPv3Message ::= SEQUENCE { msgVersion,
    # msgGlobalData, msgSecurityParameters, msgData }, filling the datagram.
    body, body_end = _tlv(data, 0, end, _TAG_SEQUENCE)
    if body_end != end:
        raise _Malformed
    version, pos = _integer(data, body, body_end)
    if version != _SNMP_V3:
        raise _Malformed
    # HeaderData ::= SEQUENCE { msgID, msgMaxSize, msgFlags, msgSecurityModel }
    hdr, hdr_end = _tlv(data, pos, body_end, _TAG_SEQUENCE)
    msg_id, p = _integer(data, hdr, hdr_end)
    msg_max_size, p = _integer(data, p, hdr_end)
    flags_start, p = _octets(data, p, hdr_end, 1)
    security_model, p = _integer(data, p, hdr_end)
    if p != hdr_end or p == flags_start or msg_max_size < _MIN_MSG_MAX_SIZE or security_model != _USM:
        raise _Malformed
    flags = data[flags_start]
    # RFC 3412 section 7.2 step 5: privFlag without authFlag is invalid.
    if flags & _FLAG_PRIV and not flags & _FLAG_AUTH:
        raise _Malformed
    # msgSecurityParameters: an OCTET STRING holding the BER of RFC 3414
    # section 2.4 UsmSecurityParameters.
    sp, sp_end = _tlv(data, hdr_end, body_end, _TAG_OCTET_STRING)
    usm, usm_end = _tlv(data, sp, sp_end, _TAG_SEQUENCE)
    if usm_end != sp_end:
        raise _Malformed
    engine_start, p = _octets(data, usm, usm_end, _ENGINE_ID_MAX)
    if 0 < p - engine_start < _ENGINE_ID_MIN:
        raise _Malformed
    engine_id = data[engine_start:p]
    boots, p = _integer(data, p, usm_end)
    engine_time, p = _integer(data, p, usm_end)
    user_start, p = _octets(data, p, usm_end, _USER_NAME_MAX)
    user_name = data[user_start:p]
    auth_start, p = _octets(data, p, usm_end, _AUTH_PARAMS_MAX)
    auth_end = p
    priv_start, p = _octets(data, p, usm_end, _PRIV_PARAMS_LEN)
    if p != usm_end:
        raise _Malformed
    # msgData: ScopedPduData ::= CHOICE { plaintext ScopedPDU, encryptedPDU
    # OCTET STRING }; RFC 3414 3.2.8 -- the choice must match privFlag.
    data_tag = _TAG_OCTET_STRING if flags & _FLAG_PRIV else _TAG_SEQUENCE
    _value_start, data_end = _tlv(data, sp_end, body_end, data_tag)
    if data_end != body_end:
        raise _Malformed
    return V3Header(
        msg_id=msg_id,
        msg_max_size=msg_max_size,
        flags=flags,
        engine_id=engine_id,
        engine_boots=boots,
        engine_time=engine_time,
        user_name=user_name,
        auth_params=data[auth_start:auth_end],
        priv_params=data[priv_start:p],
        auth_params_span=(auth_start, auth_end),
        msg_data_span=(sp_end, data_end),
    )


def parse_snmpv3_header(data: bytes) -> V3Header | None:
    """The unencrypted SNMPv3 / USM header of a datagram, or None for
    anything that is not one well-formed SNMPv3 message with the USM
    security model (including a datagram over ``MAX_V3_MESSAGE_SIZE``).
    Needs no key, does a bounded amount of work and never raises."""
    if not isinstance(data, bytes | bytearray) or not 16 <= len(data) <= MAX_V3_MESSAGE_SIZE:
        return None
    try:
        return _parse_header(bytes(data))
    except Exception:  # noqa: BLE001 - untrusted network input: anything malformed is "not SNMPv3"
        return None


# ── Replay protection (RFC 3414 section 3.2.7 b, non-authoritative) ──────────


@dataclass
class _Timeline:
    """The local notion of one remote authoritative engine's clock."""

    boots: int
    engine_time: int  # snmpEngineTime as of ``anchored``
    latest_received: int  # latestReceivedEngineTime
    anchored: float  # local monotonic seconds when engine_time was set
    recent: deque[bytes] = field(default_factory=deque)
    recent_set: set[bytes] = field(default_factory=set)


class ReplayGuard:
    """Per (source address, authoritative engine ID) timeliness state for a
    trap receiver, owned by the caller (one per receiver) and bounded to
    ``max_engines`` entries, least recently seen evicted first.

    RFC 3414 section 3.2.7 b: after an *authenticated* message, the local
    notion of the sender's boots / time moves forward when the message is
    newer; the message is then outside the window when the local boots is
    2^31-1, the message's boots is lower, or (same boots) its time is more
    than 150 seconds behind the local notion of the engine's time (which
    advances with the local clock). The first authenticated message from an
    engine not yet known (or evicted) is accepted and starts its timeline:
    a receiver has no other reference. Within the window, a message whose
    digest was already accepted (an exact replay) is refused too.

    The state is in memory: a restart forgets every engine. Thread safe.
    """

    def __init__(
        self,
        max_engines: int = 4096,
        recent_per_engine: int = 256,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_engines = max(1, int(max_engines))
        self._recent_per_engine = max(1, int(recent_per_engine))
        self._clock = clock
        self._timelines: OrderedDict[tuple[str, bytes], _Timeline] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        """How many (source, engine ID) timelines are held."""
        return len(self._timelines)

    def admit(self, source: str, engine_id: bytes, boots: int, engine_time: int, digest: bytes) -> V3Failure | None:
        """Record an authenticated message; None when it is timely and new,
        else ``NOT_IN_TIME_WINDOW`` or ``REPLAYED``. Call only after the
        message's digest was verified."""
        now = self._clock()
        key = (str(source), bytes(engine_id))
        with self._lock:
            entry = self._timelines.get(key)
            if entry is None:
                if boots >= MAX_ENGINE_VALUE:
                    return V3Failure.NOT_IN_TIME_WINDOW
                entry = _Timeline(boots=boots, engine_time=engine_time, latest_received=engine_time, anchored=now)
                self._timelines[key] = entry
                self._evict()
            else:
                self._timelines.move_to_end(key)
                # 3.2.7 b: update the local notion when the message is newer.
                if boots > entry.boots or (boots == entry.boots and engine_time > entry.latest_received):
                    if boots > entry.boots:
                        entry.recent.clear()
                        entry.recent_set.clear()
                    entry.boots = boots
                    entry.engine_time = engine_time
                    entry.latest_received = engine_time
                    entry.anchored = now
                local_time = min(MAX_ENGINE_VALUE, entry.engine_time + int(max(0.0, now - entry.anchored)))
                # 3.2.7 b: outside the time window.
                if (
                    entry.boots >= MAX_ENGINE_VALUE
                    or boots < entry.boots
                    or (boots == entry.boots and engine_time < local_time - TIME_WINDOW_SECONDS)
                ):
                    return V3Failure.NOT_IN_TIME_WINDOW
                if digest in entry.recent_set:
                    return V3Failure.REPLAYED
            entry.recent.append(digest)
            entry.recent_set.add(digest)
            if len(entry.recent) > self._recent_per_engine:
                entry.recent_set.discard(entry.recent.popleft())
            return None

    def _evict(self) -> None:
        while len(self._timelines) > self._max_engines:
            self._timelines.popitem(last=False)


# ── Keys ─────────────────────────────────────────────────────────────────────


@lru_cache(maxsize=256)
def _auth_master_key(auth_protocol: tuple[int, ...], passphrase: str) -> bytes:
    """Ku: the password-to-key hash (RFC 3414 A.2, RFC 7860 9.3) -- a
    megabyte of hashing, so it is computed once per credential."""
    return bytes(_AUTH_SERVICES[auth_protocol].hash_passphrase(passphrase).asOctets())


@lru_cache(maxsize=256)
def _priv_master_key(priv_protocol: tuple[int, ...], auth_protocol: tuple[int, ...], passphrase: str) -> bytes:
    """The privacy Ku, hashed with the authentication protocol's hash."""
    service: Any = _PRIV_SERVICES[priv_protocol]
    return bytes(service.hash_passphrase(auth_protocol, passphrase).asOctets())


def _localized_auth_key(credentials: TrapV3Credentials, engine_id: bytes) -> bytes:
    """Kul: Ku localized to the sender's authoritative engine ID (RFC 3414
    section 2.6)."""
    master = _auth_master_key(credentials.auth_protocol, credentials.auth_passphrase)
    service = _AUTH_SERVICES[credentials.auth_protocol]
    return bytes(service.localize_key(master, univ.OctetString(engine_id)).asOctets())


def _localized_priv_key(
    priv_protocol: tuple[int, ...], credentials: TrapV3Credentials, engine_id: bytes
) -> univ.OctetString:
    master = _priv_master_key(priv_protocol, credentials.auth_protocol, credentials.priv_passphrase)
    service: Any = _PRIV_SERVICES[priv_protocol]
    return univ.OctetString(service.localize_key(credentials.auth_protocol, master, univ.OctetString(engine_id)))


# ── Decoding ─────────────────────────────────────────────────────────────────


def _authenticated(data: bytes, header: V3Header, credentials: TrapV3Credentials) -> bool:
    """RFC 3414 6.3.2 / 7.3.2 (RFC 7860 4.2.2): the digest is the HMAC of
    the whole message with msgAuthenticationParameters zeroed, under the key
    localized to msgAuthoritativeEngineID; compared in constant time."""
    service = _AUTH_SERVICES.get(credentials.auth_protocol)
    digest_name = _HMAC_DIGEST.get(credentials.auth_protocol)
    if service is None or digest_name is None:
        return False
    length = int(service.digest_length)
    # Steps 1-2: msgAuthenticationParameters must be the digest's length.
    if len(header.auth_params) != length:
        return False
    start, end = header.auth_params_span
    # Step 3: the message as it was when the digest was computed.
    zeroed = data[:start] + bytes(length) + data[end:]
    key = _localized_auth_key(credentials, header.engine_id)
    # Steps 4-6.
    expected = hmac.new(key, zeroed, digest_name).digest()[:length]
    return hmac.compare_digest(expected, header.auth_params)


def _decode_scoped_pdu(plaintext: bytes, padding: int) -> Any:
    """A ScopedPDU from its BER, allowing at most ``padding`` trailing
    octets; raises on anything else."""
    scoped, rest = ber_decoder.decode(plaintext, asn1Spec=ScopedPDU())
    if len(rest) > padding:
        raise _Malformed
    return scoped


def _decrypt(data: bytes, header: V3Header, credentials: TrapV3Credentials) -> Any | None:
    """RFC 3414 3.2.8: the decrypted ScopedPDU, or None when it does not
    decrypt to one under the configured privacy protocol (or, for AES-192 /
    AES-256, the other key-extension variant)."""
    priv_protocol = credentials.priv_protocol
    if priv_protocol is None or len(header.priv_params) != _PRIV_PARAMS_LEN:
        return None
    start, end = header.msg_data_span
    value_start, value_end = _tlv(data, start, end, _TAG_OCTET_STRING)
    ciphertext = univ.OctetString(data[value_start:value_end])
    # RFC 3414 8.3.2 / RFC 3826 3.3.2: boots, time and the salt form the IV.
    params = (header.engine_boots, header.engine_time, univ.OctetString(header.priv_params))
    candidates = [priv_protocol]
    peer = _AES_KEY_EXTENSION_PEER.get(priv_protocol)
    if peer is not None:
        candidates.append(peer)
    for candidate in candidates:
        service: Any = _PRIV_SERVICES.get(candidate)
        if service is None:
            continue
        try:
            key = _localized_priv_key(candidate, credentials, header.engine_id)
            plaintext = bytes(service.decrypt_data(key, params, ciphertext))
            return _decode_scoped_pdu(plaintext, _MAX_PLAINTEXT_PADDING)
        except Exception:  # nosec B112 - a wrong key decrypts to garbage: try the next variant
            continue
    return None


def _varbinds(pdu: Any) -> list[tuple[str, str]]:
    return [(oid.prettyPrint(), value.prettyPrint()) for oid, value in _V2C.apiTrapPDU.get_varbinds(pdu)]


def _trap(header: V3Header, scoped: Any) -> TrapV3Result:
    pdu = scoped.getComponentByName("data").getComponent()
    if pdu.isSameTypeWith(_V2C.InformRequestPDU()):
        return TrapV3Result(failure=V3Failure.INFORM, header=header)
    if not pdu.isSameTypeWith(_V2C.SNMPv2TrapPDU()):
        return TrapV3Result(failure=V3Failure.NOT_A_TRAP, header=header)
    varbinds = _varbinds(pdu)
    trap = {
        "version": "v3",
        "community": "",
        "trap_oid": next((value for oid, value in varbinds if oid == SNMP_TRAP_OID), ""),
        "agent_address": "",
        "varbinds": varbinds,
        "pdu": "trap",
        "request_id": int(_V2C.apiPDU.get_request_id(pdu)),
        "user": header.user,
        "engine_id": header.engine_id_hex,
        "security_level": header.security_level,
        "context_name": bytes(scoped.getComponentByName("contextName").asOctets()).decode("utf-8", "replace"),
    }
    return TrapV3Result(trap=trap, header=header)


def decode_snmpv3_trap(
    data: bytes,
    credentials: TrapV3Credentials | None,
    replay_guard: ReplayGuard,
    source: str,
) -> TrapV3Result:
    """Authenticate, check, decrypt and decode an SNMPv3 SNMPv2-Trap from
    ``source`` (the datagram's own address) with that host's stored
    ``credentials`` (``resolve_trap_v3_credentials``; None for a host with
    no SNMPv3 user). ``replay_guard`` is the receiver's one ``ReplayGuard``.

    On success ``result.trap`` is shaped like ``decode_snmp_trap``'s dict
    (``version`` "v3", empty ``community`` and ``agent_address``) plus
    ``user``, ``engine_id`` (hex), ``security_level`` and ``context_name``.
    Otherwise ``result.failure`` says why. The replay state changes only for
    an authenticated message. Never raises."""
    header = parse_snmpv3_header(data)
    if header is None:
        return TrapV3Result(failure=V3Failure.NOT_V3)
    data = bytes(data)
    try:
        # RFC 3412 section 6.4: the reportable flag marks a confirmed-class
        # PDU (InformRequest, a request); only an authoritative engine answers.
        if header.reportable:
            return TrapV3Result(failure=V3Failure.INFORM, header=header)
        # RFC 3414 3.2.3: an empty engine ID asks for discovery.
        if not header.engine_id:
            return TrapV3Result(failure=V3Failure.UNKNOWN_ENGINE_ID, header=header)
        # RFC 3414 3.2.4: the user must be the host's configured user.
        if credentials is None or not hmac.compare_digest(header.user_name, credentials.user_name):
            return TrapV3Result(failure=V3Failure.UNKNOWN_USER, header=header)
        # RFC 3414 3.2.5: the message's level must be the user's. A weaker
        # message (noAuthNoPriv / authNoPriv for an authPriv user) would let
        # anyone who can spoof the source address inject a trap; a stronger
        # one names a privacy protocol the user does not have.
        if header.security_level != credentials.security_level:
            return TrapV3Result(failure=V3Failure.SECURITY_LEVEL, header=header)
        # RFC 3414 3.2.6.
        if not _authenticated(data, header, credentials):
            return TrapV3Result(failure=V3Failure.AUTHENTICATION, header=header)
        # RFC 3414 3.2.7 b.
        refused = replay_guard.admit(source, header.engine_id, header.engine_boots, header.engine_time, header.auth_params)
        if refused is not None:
            return TrapV3Result(failure=refused, header=header)
    except Exception:  # noqa: BLE001 - a bad credential (an unencodable passphrase) is a failed check
        return TrapV3Result(failure=V3Failure.AUTHENTICATION, header=header)
    # RFC 3414 3.2.8.
    if header.priv:
        try:
            scoped = _decrypt(data, header, credentials)
        except Exception:  # noqa: BLE001 - untrusted network input
            scoped = None
        if scoped is None:
            return TrapV3Result(failure=V3Failure.DECRYPTION, header=header)
    else:
        start, end = header.msg_data_span
        try:
            scoped = _decode_scoped_pdu(data[start:end], 0)
        except Exception:  # noqa: BLE001 - untrusted network input
            return TrapV3Result(failure=V3Failure.MALFORMED, header=header)
    try:
        return _trap(header, scoped)
    except Exception:  # noqa: BLE001 - untrusted network input
        return TrapV3Result(failure=V3Failure.MALFORMED, header=header)


# ── Credentials ──────────────────────────────────────────────────────────────


def trap_v3_credentials(snmp_config: dict | None) -> TrapV3Credentials | None:
    """The SNMPv3 user a host's traps are checked with: the poll's own user
    from its effective SNMP config (``state._resolve_host_snmp_config``),
    with secrets already resolved. Protocols come from the poll's mapping
    (``snmp.usm_protocols``). None unless the config is SNMPv3 with a user
    and an authentication passphrase (the poll needs both too), or when a
    ``{{secret.NAME}}`` reference was left unresolved. A privacy passphrase
    makes it authPriv, else authNoPriv."""
    from routes.secret_resolver import has_secret_references

    cfg = snmp_config or {}
    if str(cfg.get("version", "2c")) != "3":
        return None
    v3 = cfg.get("v3")
    if not isinstance(v3, dict):
        return None
    username = str(v3.get("username", "")).strip()
    auth_passphrase = str(v3.get("auth_password", "")).strip()
    priv_passphrase = str(v3.get("priv_password", "")).strip()
    if not username or not auth_passphrase:
        return None
    if has_secret_references(auth_passphrase) or has_secret_references(priv_passphrase):
        return None
    auth_protocol, priv_protocol = usm_protocols(v3)
    if auth_protocol is None or tuple(auth_protocol) not in _HMAC_DIGEST:
        return None
    try:
        # The poll's UsmUserData turns the name into octets the same way.
        user_name = bytes(univ.OctetString(username).asOctets())
    except Exception:  # noqa: BLE001 - a name pysnmp cannot encode cannot be the poll's user either
        return None
    return TrapV3Credentials(
        user_name=user_name,
        auth_protocol=tuple(auth_protocol),
        auth_passphrase=auth_passphrase,
        priv_protocol=tuple(priv_protocol) if priv_passphrase and priv_protocol is not None else None,
        priv_passphrase=priv_passphrase,
    )


async def resolve_trap_v3_credentials(host: dict | None) -> TrapV3Credentials | None:
    """``trap_v3_credentials`` for an inventory host: its own SNMP profile,
    else its group's config, else the global config -- resolved as the poll
    resolves it -- with ``{{secret.NAME}}`` passphrases decrypted."""
    import netcontrol.routes.state as state

    cfg = state._resolve_host_snmp_config(host)
    return trap_v3_credentials(await _resolve_snmp_secrets(cfg))
