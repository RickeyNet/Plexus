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

For an InformRequest the roles turn round (RFC 3414 section 1.5.1): the
receiver is the authoritative engine, and the inform carries the
*receiver's* engine ID, boots and time, with keys localized to it. That
side is ``LocalEngine`` (its engine ID and boots are stored by
``netcontrol.snmpv3_engine``):

* ``engine_discovery_report`` -- the usmStatsUnknownEngineIDs Report that
  answers a discovery probe (RFC 3414 section 4), keyless.
* ``decode_snmpv3_inform`` -- the same user, level and digest checks as a
  trap, the authoritative time window (section 3.2 step 7a; a stale
  message gets the authenticated usmStatsNotInTimeWindows Report the sender
  resynchronizes with), decryption, and the Response PDU (RFC 3416 section
  4.2.7) built with the local engine ID, boots and time at the request's
  security level.

No Report is sent for an unknown user, a wrong security level, a wrong
digest or a decryption failure: a standard sender needs only the two above,
and the others would tell an off-path sender which user names exist. Every
reply is refused when it is more than ``MAX_REPLY_FACTOR`` times the
request's size. ``decode_snmpv3_trap`` (the non-authoritative path) still
refuses a message with the reportable flag, or an InformRequest PDU, as
``V3Failure.INFORM``.

Key derivation (password to key, key localization, AES key extension) and
the ciphers are pysnmp's own USM services; this module frames the message
itself so it can read the exact byte offsets the HMAC covers, and compares
digests with ``hmac.compare_digest`` (pysnmp's own check does not).
"""

from __future__ import annotations

import enum
import hmac
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from pyasn1.type import univ
from pysnmp.entity import config as usm
from pysnmp.proto import api as snmp_api, rfc3411
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

# A reply (Report or Response) is never more than this many times the size
# of the datagram it answers: the receiver must not amplify forged traffic.
MAX_REPLY_FACTOR = 3

# RFC 3411 SnmpEngineID: the first bit set, a 31-bit IANA enterprise number,
# a format octet (5: octets, administratively assigned) and 1..27 octets.
# The enterprise is pysnmp's (20408), the SNMP engine Plexus is built on;
# the rest is random, generated once (``new_engine_id``).
_ENGINE_ID_ENTERPRISE = 20408
_ENGINE_ID_FORMAT_OCTETS = 5
_ENGINE_ID_RANDOM_OCTETS = 12

# SNMP-USER-BASED-SM-MIB usmStats (RFC 3414 section 5): the counters a
# Report carries, by the names ``LocalEngine.stats`` keeps them under.
_USM_STATS = "1.3.6.1.6.3.15.1.1"
USM_STATS_OIDS = {
    "unsupported_sec_levels": f"{_USM_STATS}.1.0",
    "not_in_time_windows": f"{_USM_STATS}.2.0",
    "unknown_user_names": f"{_USM_STATS}.3.0",
    "unknown_engine_ids": f"{_USM_STATS}.4.0",
    "wrong_digests": f"{_USM_STATS}.5.0",
    "decryption_errors": f"{_USM_STATS}.6.0",
}

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
    unauthenticated header already read. ``reply_to`` is the socket address
    it came from, set for an inform (a datagram the batch writer answers)."""

    data: bytes = field(repr=False)
    header: V3Header
    reply_to: tuple | None = None


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
    ``header`` is set whenever the datagram was well-formed SNMPv3.
    ``reply`` (informs only) is the datagram to send back to the sender: the
    Response of an accepted inform, or a Report."""

    trap: dict | None = None
    failure: V3Failure | None = None
    header: V3Header | None = None
    reply: bytes | None = field(default=None, repr=False)

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

    The timelines (not the recent digests) can be saved and restored across
    a restart: ``take_changed`` gives the ones that moved since the last
    call, ``restore`` loads saved ones, with the engine's clock advanced by
    the wall-clock time that passed since. Thread safe.
    """

    def __init__(
        self,
        max_engines: int = 4096,
        recent_per_engine: int = 256,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._max_engines = max(1, int(max_engines))
        self._recent_per_engine = max(1, int(recent_per_engine))
        self._clock = clock
        self._wall_clock = wall_clock
        self._timelines: OrderedDict[tuple[str, bytes], _Timeline] = OrderedDict()
        # Keys whose timeline started or moved since ``take_changed``.
        self._changed: set[tuple[str, bytes]] = set()
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        """How many (source, engine ID) timelines are held."""
        return len(self._timelines)

    @property
    def max_engines(self) -> int:
        return self._max_engines

    def take_changed(self) -> list[tuple[str, str, int, int, str]]:
        """The timelines that started or moved since the last call, as
        ``(source, engine ID hex, boots, engine time, seen_at)`` rows:
        ``seen_at`` is the UTC wall-clock time (``YYYY-MM-DD HH:MM:SS``) at
        which the engine's time was ``engine time``. Clears the set."""
        with self._lock:
            now, wall = self._clock(), self._wall_clock()
            rows = []
            for key in self._changed:
                entry = self._timelines.get(key)
                if entry is None:
                    continue
                anchored_wall = wall - max(0.0, now - entry.anchored)
                rows.append((key[0], key[1].hex(), entry.boots, entry.engine_time, _utc_text(anchored_wall)))
            self._changed.clear()
        return sorted(rows)

    def restore(self, rows: Iterable[dict]) -> int:
        """Load saved timelines (``take_changed`` rows as dicts: ``source``,
        ``engine_id``, ``boots``, ``engine_time``, ``seen_at``), newest
        first, at most ``max_engines``. A timeline already held is kept; a
        row that does not parse is skipped. The engine's clock is taken to
        have run since ``seen_at`` (never backwards). Returns how many were
        loaded."""
        loaded = 0
        with self._lock:
            now, wall = self._clock(), self._wall_clock()
            for row in reversed(list(rows)[: self._max_engines]):
                try:
                    source = str(row["source"])
                    engine_id = bytes.fromhex(str(row["engine_id"]))
                    boots, engine_time = int(row["boots"]), int(row["engine_time"])
                    seen = datetime.strptime(str(row["seen_at"]), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC).timestamp()
                except KeyError, TypeError, ValueError:
                    continue
                if not (
                    source
                    and _ENGINE_ID_MIN <= len(engine_id) <= _ENGINE_ID_MAX
                    and 0 <= boots <= MAX_ENGINE_VALUE
                    and 0 <= engine_time <= MAX_ENGINE_VALUE
                ):
                    continue
                key = (source, engine_id)
                if key in self._timelines:
                    continue
                anchored = now - max(0.0, wall - seen)
                self._timelines[key] = _Timeline(
                    boots=boots, engine_time=engine_time, latest_received=engine_time, anchored=anchored
                )
                loaded += 1
            self._evict()
        return loaded

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
                self._changed.add(key)
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
                    self._changed.add(key)
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
            key, _entry = self._timelines.popitem(last=False)
            self._changed.discard(key)


def _utc_text(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d %H:%M:%S")


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
    found = _decrypt_with_protocol(data, header, credentials)
    return found[0] if found is not None else None


def _decrypt_with_protocol(
    data: bytes, header: V3Header, credentials: TrapV3Credentials
) -> tuple[Any, tuple[int, ...]] | None:
    """``_decrypt``, with the privacy protocol (key-extension variant) that
    decrypted it: a Response is encrypted the same way."""
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
            return _decode_scoped_pdu(plaintext, _MAX_PLAINTEXT_PADDING), candidate
        except Exception:  # nosec B112 - a wrong key decrypts to garbage: try the next variant
            continue
    return None


def _varbinds(pdu: Any) -> list[tuple[str, str]]:
    return [(oid.prettyPrint(), value.prettyPrint()) for oid, value in _V2C.apiTrapPDU.get_varbinds(pdu)]


def _trap(header: V3Header, scoped: Any, inform: bool = False) -> TrapV3Result:
    """The decoded notification of an accepted ScopedPDU: an SNMPv2-Trap
    (``inform`` False, the trap path) or an InformRequest (``inform`` True,
    the authoritative path); any other PDU is refused."""
    pdu = scoped.getComponentByName("data").getComponent()
    is_inform = pdu.isSameTypeWith(_V2C.InformRequestPDU())
    if is_inform and not inform:
        return TrapV3Result(failure=V3Failure.INFORM, header=header)
    if not (is_inform if inform else pdu.isSameTypeWith(_V2C.SNMPv2TrapPDU())):
        return TrapV3Result(failure=V3Failure.NOT_A_TRAP, header=header)
    varbinds = _varbinds(pdu)
    trap = {
        "version": "v3",
        "community": "",
        "trap_oid": next((value for oid, value in varbinds if oid == SNMP_TRAP_OID), ""),
        "agent_address": "",
        "varbinds": varbinds,
        "pdu": "inform" if inform else "trap",
        "request_id": int(_V2C.apiPDU.get_request_id(pdu)),
        "user": header.user,
        "engine_id": header.engine_id_hex,
        "security_level": header.security_level,
        "context_name": bytes(scoped.getComponentByName("contextName").asOctets()).decode("utf-8", "replace"),
    }
    return TrapV3Result(trap=trap, header=header)


def _check_user(data: bytes, header: V3Header, credentials: TrapV3Credentials | None) -> V3Failure | None:
    """RFC 3414 3.2.4 - 3.2.6, the same for a trap and an inform: None when
    the message is from the host's user at exactly its level, correctly
    signed. May raise for an unusable credential (a failed check)."""
    # 3.2.4: the user must be the host's configured user.
    if credentials is None or not hmac.compare_digest(header.user_name, credentials.user_name):
        return V3Failure.UNKNOWN_USER
    # 3.2.5: the message's level must be the user's. A weaker message
    # (noAuthNoPriv / authNoPriv for an authPriv user) would let anyone who
    # can spoof the source address inject a trap; a stronger one names a
    # privacy protocol the user does not have.
    if header.security_level != credentials.security_level:
        return V3Failure.SECURITY_LEVEL
    # 3.2.6.
    if not _authenticated(data, header, credentials):
        return V3Failure.AUTHENTICATION
    return None


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
        refused_user = _check_user(data, header, credentials)
        if refused_user is not None or credentials is None:
            return TrapV3Result(failure=refused_user or V3Failure.UNKNOWN_USER, header=header)
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


# ── The authoritative engine (informs) ───────────────────────────────────────


def new_engine_id() -> bytes:
    """A new snmpEngineID in the RFC 3411 format: the enterprise with its
    first bit set, format 5 (octets) and ``_ENGINE_ID_RANDOM_OCTETS`` random
    octets. Generated once and stored (``netcontrol.snmpv3_engine``)."""
    prefix = (0x80000000 | _ENGINE_ID_ENTERPRISE).to_bytes(4, "big") + bytes([_ENGINE_ID_FORMAT_OCTETS])
    return prefix + secrets.token_bytes(_ENGINE_ID_RANDOM_OCTETS)


class LocalEngine:
    """The trap receiver's own SNMPv3 engine, the authoritative side of an
    inform: its snmpEngineID, its snmpEngineBoots (incremented and stored
    each time the receiver starts) and its snmpEngineTime, the seconds since
    then (RFC 3414 section 2.2.2). ``stats`` are the usmStats counters a
    Report carries (``USM_STATS_OIDS``), ``responses`` and ``reports`` the
    replies built. Not thread safe: used from the event loop only."""

    def __init__(self, engine_id: bytes, boots: int, clock: Callable[[], float] = time.monotonic) -> None:
        engine_id = bytes(engine_id)
        if not _ENGINE_ID_MIN <= len(engine_id) <= _ENGINE_ID_MAX:
            raise ValueError("an snmpEngineID is 5 to 32 octets")
        self.engine_id = engine_id
        self.boots = max(0, min(MAX_ENGINE_VALUE, int(boots)))
        self._clock = clock
        self._started = clock()
        self.stats: dict[str, int] = dict.fromkeys(USM_STATS_OIDS, 0)
        self.responses = 0
        self.reports = 0

    @property
    def engine_time(self) -> int:
        """snmpEngineTime: whole seconds since this boot, at most 2^31-1."""
        return min(MAX_ENGINE_VALUE, int(max(0.0, self._clock() - self._started)))

    @property
    def latched(self) -> bool:
        """RFC 3414 section 2.2.2: at boots 2^31-1 no message is timely."""
        return self.boots >= MAX_ENGINE_VALUE

    def count(self, stat: str) -> int:
        """Increment one usmStats counter; its new value (a Counter32)."""
        self.stats[stat] = (self.stats[stat] + 1) % (1 << 32)
        return self.stats[stat]


# The usmStats counter each refusal of an inform increments (RFC 3414 3.2).
_FAILURE_STAT = {
    V3Failure.UNKNOWN_USER: "unknown_user_names",
    V3Failure.SECURITY_LEVEL: "unsupported_sec_levels",
    V3Failure.AUTHENTICATION: "wrong_digests",
}


def _ber(tag: int, value: bytes) -> bytes:
    """One definite-length BER TLV (X.690 8.1.3)."""
    size = len(value)
    if size < 0x80:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + value


def _ber_integer(value: int) -> bytes:
    return bytes(ber_encoder.encode(univ.Integer(value)))


def _scoped_pdu_octets(context_engine_id: bytes, context_name: bytes, pdu: Any) -> bytes:
    scoped = ScopedPDU()
    scoped.setComponentByPosition(0, context_engine_id)
    scoped.setComponentByPosition(1, context_name)
    scoped.setComponentByPosition(2)
    scoped.getComponentByPosition(2).setComponentByType(
        pdu.tagSet, pdu, verifyConstraints=False, matchTags=False, matchConstraints=False
    )
    return bytes(ber_encoder.encode(scoped))


def _encode_reply(
    request: V3Header,
    engine: LocalEngine,
    scoped: bytes,
    credentials: TrapV3Credentials | None = None,
    priv_protocol: tuple[int, ...] | None = None,
) -> bytes:
    """An SNMPv3 message from ``engine`` answering ``request`` (RFC 3412
    section 7.1, RFC 3414 section 3.1): the request's msgID and user name,
    the local engine ID, boots and time (3.1 step 6), reportableFlag 0.
    With ``credentials`` it is signed with the user's key localized to the
    local engine ID (authNoPriv), with ``priv_protocol`` too encrypted
    (authPriv); without, noAuthNoPriv."""
    boots, engine_time = engine.boots, engine.engine_time
    flags, salt, msg_data, digest_length = 0, b"", scoped, 0
    if credentials is not None:
        flags |= _FLAG_AUTH
        digest_length = int(_AUTH_SERVICES[credentials.auth_protocol].digest_length)
        if priv_protocol is not None:
            flags |= _FLAG_PRIV
            service: Any = _PRIV_SERVICES[priv_protocol]
            key = _localized_priv_key(priv_protocol, credentials, engine.engine_id)
            ciphertext, salt_octets = service.encrypt_data(key, (boots, engine_time, None), scoped)
            msg_data, salt = _ber(_TAG_OCTET_STRING, bytes(ciphertext)), bytes(salt_octets)
    security_parameters = _ber(
        _TAG_SEQUENCE,
        _ber(_TAG_OCTET_STRING, engine.engine_id)
        + _ber_integer(boots)
        + _ber_integer(engine_time)
        + _ber(_TAG_OCTET_STRING, request.user_name)
        + _ber(_TAG_OCTET_STRING, bytes(digest_length))
        + _ber(_TAG_OCTET_STRING, salt),
    )
    header_data = _ber(
        _TAG_SEQUENCE,
        _ber_integer(request.msg_id)
        + _ber_integer(MAX_V3_MESSAGE_SIZE)
        + _ber(_TAG_OCTET_STRING, bytes([flags]))
        + _ber_integer(_USM),
    )
    whole = _ber(
        _TAG_SEQUENCE, _ber_integer(_SNMP_V3) + header_data + _ber(_TAG_OCTET_STRING, security_parameters) + msg_data
    )
    if credentials is not None:
        # RFC 3414 6.3.1 / 7.3.1 (RFC 7860 4.2.1): the HMAC of the whole
        # message with the digest zeroed, written in its place.
        start, end = _parse_header(whole).auth_params_span
        key = _localized_auth_key(credentials, engine.engine_id)
        digest = hmac.new(key, whole, _HMAC_DIGEST[credentials.auth_protocol]).digest()[:digest_length]
        whole = whole[:start] + digest + whole[end:]
    return whole


def _bounded(reply: bytes, request: bytes, header: V3Header) -> bytes | None:
    """``reply``, or None when it is more than ``MAX_REPLY_FACTOR`` times
    the request or larger than the sender accepts (msgMaxSize)."""
    if len(reply) > MAX_REPLY_FACTOR * len(request) or len(reply) > header.msg_max_size:
        return None
    return reply


def _plaintext_pdu(data: bytes, header: V3Header) -> tuple[Any, Any] | None:
    """The (ScopedPDU, PDU) of an unencrypted message; None when encrypted
    or not a ScopedPDU."""
    if header.priv:
        return None
    start, end = header.msg_data_span
    try:
        scoped = _decode_scoped_pdu(data[start:end], 0)
        return scoped, scoped.getComponentByName("data").getComponent()
    except Exception:  # noqa: BLE001 - untrusted network input: the PDU class is unknown
        return None


def _report(
    data: bytes, header: V3Header, engine: LocalEngine, stat: str, credentials: TrapV3Credentials | None = None
) -> bytes | None:
    """The Report PDU carrying usmStats counter ``stat`` (RFC 3412 section
    7.1 step 3), or None when none may be sent: the reportable flag is
    clear, or the request's PDU can be read and is not of the Confirmed
    Class (3b). request-id is the request's when its PDU can be read, else
    0 (3c); the context is the request's for an unknown engine ID (as
    pysnmp does), else the local engine ID and the default context (3d).
    noAuthNoPriv, or authNoPriv with ``credentials`` (RFC 3414 3.2 step
    7a: a notInTimeWindow Report is authenticated)."""
    if not header.reportable:
        return None
    request_id, context_engine_id, context_name = 0, engine.engine_id, b""
    found = _plaintext_pdu(data, header)
    if found is not None:
        scoped, pdu = found
        if pdu.tagSet not in rfc3411.CONFIRMED_CLASS_PDUS:
            return None
        request_id = int(_V2C.apiPDU.get_request_id(pdu))
        if stat == "unknown_engine_ids":
            context_engine_id = bytes(scoped.getComponentByName("contextEngineId").asOctets())
            context_name = bytes(scoped.getComponentByName("contextName").asOctets())
    report = _V2C.ReportPDU()
    _V2C.apiPDU.set_defaults(report)
    _V2C.apiPDU.set_request_id(report, request_id)
    _V2C.apiPDU.set_varbinds(report, [(USM_STATS_OIDS[stat], _V2C.Counter32(engine.stats[stat]))])
    reply = _bounded(
        _encode_reply(header, engine, _scoped_pdu_octets(context_engine_id, context_name, report), credentials),
        data,
        header,
    )
    if reply is not None:
        engine.reports += 1
    return reply


def engine_discovery_report(data: bytes, engine: LocalEngine) -> bytes | None:
    """RFC 3414 section 3.2 step 3b and section 4: a reportable message
    whose msgAuthoritativeEngineID is not ``engine``'s (empty, for a
    discovery probe) counts usmStatsUnknownEngineIDs and is answered with
    a noAuthNoPriv Report that carries the local engine ID, boots and time.
    None (nothing to send) for anything else, or when ``_report`` sends
    none. Needs no key; never raises."""
    header = parse_snmpv3_header(data)
    if header is None or not header.reportable or header.engine_id == engine.engine_id:
        return None
    engine.count("unknown_engine_ids")
    try:
        return _report(bytes(data), header, engine, "unknown_engine_ids")
    except Exception:  # noqa: BLE001 - untrusted network input: no answer
        return None


def decode_snmpv3_inform(
    data: bytes,
    credentials: TrapV3Credentials | None,
    engine: LocalEngine,
    replay_guard: ReplayGuard,
    source: str,
) -> TrapV3Result:
    """Authenticate, check, decrypt and decode an SNMPv3 InformRequest sent
    to the local ``engine`` by ``source``, with that host's ``credentials``
    (as for a trap), and build its answer.

    The checks are the trap's (``_check_user``: user, exact security level,
    digest, keys localized to the local engine ID), then the authoritative
    time window (RFC 3414 3.2 step 7a: the local boots, the message's boots
    equal to it, its time within 150 seconds of the local time), an exact
    copy of an accepted message (``replay_guard``, per source), decryption
    and the PDU, which must be an InformRequest.

    On success ``result.trap`` is shaped as ``decode_snmpv3_trap``'s with
    ``pdu`` "inform", and ``result.reply`` is the Response (RFC 3416 4.2.7:
    the same request-id and varbinds, error-status 0) at the request's
    security level, or None when it would be too large (``_bounded``).
    Otherwise ``result.failure`` says why; ``result.reply`` is the Report
    for an unknown engine ID or a message outside the time window, and None
    for every other failure (no Report for an unknown user, level, digest
    or decryption failure). Never raises."""
    header = parse_snmpv3_header(data)
    if header is None:
        return TrapV3Result(failure=V3Failure.NOT_V3)
    data = bytes(data)
    if not header.reportable:
        return TrapV3Result(failure=V3Failure.NOT_A_TRAP, header=header)
    if header.engine_id != engine.engine_id:
        return TrapV3Result(
            failure=V3Failure.UNKNOWN_ENGINE_ID, header=header, reply=engine_discovery_report(data, engine)
        )
    try:
        refused_user = _check_user(data, header, credentials)
        if refused_user is not None or credentials is None:
            failure = refused_user or V3Failure.UNKNOWN_USER
            engine.count(_FAILURE_STAT[failure])
            return TrapV3Result(failure=failure, header=header)
        # RFC 3414 3.2 step 7a: the local engine is authoritative.
        if (
            engine.latched
            or header.engine_boots != engine.boots
            or abs(header.engine_time - engine.engine_time) > TIME_WINDOW_SECONDS
        ):
            engine.count("not_in_time_windows")
            return TrapV3Result(
                failure=V3Failure.NOT_IN_TIME_WINDOW,
                header=header,
                reply=_report(data, header, engine, "not_in_time_windows", credentials),
            )
        refused = replay_guard.admit(
            source, engine.engine_id, header.engine_boots, header.engine_time, header.auth_params
        )
        if refused is not None:
            return TrapV3Result(failure=refused, header=header)
    except Exception:  # noqa: BLE001 - a bad credential (an unencodable passphrase) is a failed check
        engine.count("wrong_digests")
        return TrapV3Result(failure=V3Failure.AUTHENTICATION, header=header)
    priv_protocol: tuple[int, ...] | None = None
    if header.priv:
        try:
            found = _decrypt_with_protocol(data, header, credentials)
        except Exception:  # noqa: BLE001 - untrusted network input
            found = None
        if found is None:
            engine.count("decryption_errors")
            return TrapV3Result(failure=V3Failure.DECRYPTION, header=header)
        scoped, priv_protocol = found
    else:
        plain = _plaintext_pdu(data, header)
        if plain is None:
            return TrapV3Result(failure=V3Failure.MALFORMED, header=header)
        scoped = plain[0]
    try:
        result = _trap(header, scoped, inform=True)
        if result.trap is None:
            return result
        request = scoped.getComponentByName("data").getComponent()
        response = _V2C.apiPDU.get_response(request)
        _V2C.apiPDU.set_varbinds(response, _V2C.apiPDU.get_varbinds(request))
        context_engine_id = bytes(scoped.getComponentByName("contextEngineId").asOctets())
        context_name = bytes(scoped.getComponentByName("contextName").asOctets())
        reply = _bounded(
            _encode_reply(
                header,
                engine,
                _scoped_pdu_octets(context_engine_id, context_name, response),
                credentials,
                priv_protocol,
            ),
            data,
            header,
        )
    except Exception:  # noqa: BLE001 - untrusted network input
        return TrapV3Result(failure=V3Failure.MALFORMED, header=header)
    if reply is not None:
        engine.responses += 1
    return TrapV3Result(trap=result.trap, header=header, reply=reply)


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
