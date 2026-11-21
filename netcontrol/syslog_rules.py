"""Syslog alert rules: received syslog messages acted on by the server.

The syslog receiver (``netcontrol/routes/metrics_engine.py``) stores every
message in ``trap_syslog_events``. Its batch writer then hands the messages
whose source is an inventory host to ``process_syslog_batch`` here, which

- matches them against the alert rules (the built-in ones below and the
  operator's custom rules in ``syslog_alert_rules``) and raises or resolves
  monitoring alerts (``alert_type`` ``syslog``, ``metric``
  ``syslog_<rule key>``) under a dedup key per rule, host and *instance*
  (the interface or neighbor a message names),
- starts a configuration backup and drift check of a host that logged a
  configuration change (``SYS-5-CONFIG_I`` and its equivalents), debounced
  and rate limited per host, and
- schedules an immediate monitoring re-poll of a host that logged an
  interface going down or a reload / restart
  (``netcontrol.monitoring_repoll``).

``process_recollect_batch`` gets every syslog message, from inventory hosts
or not, with its source address: an OPNsense gateway alarm, CARP
transition, VPN tunnel up / down or configuration save starts an immediate
collection of the firewall's topology source
(``netcontrol.source_recollect``), so the availability tracker (which owns
those alerts) and the config.xml backup catch up within seconds.

Each behaviour has a switch in ``state.EVENT_RECEIVER_CONFIG``
(``syslog_alerts``, ``config_change_trigger``, ``repoll_trigger``,
``recollect_trigger``; on when unset). Alerts and re-polls also need
monitoring to be enabled.

Parsing is pure (``parse_syslog_message``): the event *tag* of a message is
the Cisco-style ``%FACILITY-SEVERITY-MNEMONIC`` (IOS, IOS XE, IOS XR,
NX-OS, ASA, Arista EOS), compared without its severity digit
(``LINK-UPDOWN``), the Junos ``TAG_NAME`` (``SNMP_TRAP_LINK_DOWN``), or
the tag ``netcontrol.syslog_vendor_formats`` gives a FortiOS, PAN-OS,
AOS-CX or AOS-Switch message (``FGT-0100032002``, ``PAN-SYSTEM-AUTH-FAIL``,
``AOSCX-404``, ``AOSS-00077``). Its *program* is the RFC 5424 APP-NAME or the RFC 3164 ``program[pid]:``
(``dpinger``, ``charon``, ``audit``): messages without a tag, OPNsense's
among them, are matched by program and the text after it.
Built-in patterns are fixed and written for Python ``re``; custom regex
patterns are user input and run on RE2 (``routes.user_regex``), validated
when the rule is saved.

The threshold counters and pending configuration-change runs live in
memory; ``restore_state`` rebuilds them at startup from the stored
messages. ``netcontrol.syslog_activity`` reports what the rules matched in
the stored traffic and what they missed.

``docs/syslog-rules.md`` describes the rules and the triggers.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial

import routes.database as db
from routes.user_regex import UserRegex, compile_user_regex

import netcontrol.routes.state as state
from netcontrol import source_recollect
from netcontrol.bounded_map import BoundedDict
from netcontrol.monitoring_repoll import keep_task, schedule_repoll
from netcontrol.syslog_vendor_formats import aos_switch_tag, vendor_tag

LOGGER = logging.getLogger("plexus.syslog_rules")

ALERT_TYPE = "syslog"
# Recorded on the config backup and drift snapshot rows a configuration
# change message starts.
CAPTURE_METHOD = "syslog"

SEVERITIES: tuple[str, ...] = ("info", "warning", "critical")
MATCH_TYPES: tuple[str, ...] = ("tag", "contains", "regex")
NAME_MAX = 100
PATTERN_MAX = 500
THRESHOLD_COUNT_MAX = 1000
THRESHOLD_WINDOW_MAX = 86400
AUTO_RESOLVE_MAX = 10080
CACHE_TTL_SECONDS = 30.0

# Two matches of one rule for the same host and instance closer together
# than this are one event (a link going down logs both LINK-3-UPDOWN and
# LINEPROTO-5-UPDOWN).
COALESCE_SECONDS = 5.0
# The most host / rule / instance counters kept in memory.
COUNTERS_MAX = 10000

# Re-poll: after an interface-down or restart message, after a reload
# message (the device is still up when it logs one), and at most once per
# host in this many seconds.
REPOLL_DELAY_SECONDS = 5.0
RELOAD_REPOLL_DELAY_SECONDS = 30.0
REPOLL_MIN_INTERVAL_SECONDS = 60.0

# Configuration change: the run starts this long after the host's last
# configuration message (one session logs several), at most one run per
# host in COOLDOWN, and the drift snapshot reuses a backup the device
# confirmed within CONFIG_REUSE_SECONDS instead of opening a second session.
CONFIG_DEBOUNCE_SECONDS = 60.0
CONFIG_COOLDOWN_SECONDS = 300.0
CONFIG_REUSE_SECONDS = 300
# The debounce never holds a pending run back longer than this after its
# first message: a stream of (possibly forged) configuration messages cannot
# postpone the backup for ever. The cooldown still applies.
CONFIG_MAX_DEFER_SECONDS = 600.0

_MESSAGE_SNIPPET = 300
_TAG_SEARCH_CHARS = 512

# Monotonic clock, replaced in tests.
_clock: Callable[[], float] = time.monotonic


def receiver_flag(name: str) -> bool:
    """A switch of ``state.EVENT_RECEIVER_CONFIG`` (on when unset)."""
    return bool(state.EVENT_RECEIVER_CONFIG.get(name, True))


def _monitoring_enabled() -> bool:
    return bool(state.MONITORING_CONFIG.get("enabled"))


# ── Parsing ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ParsedSyslog:
    """A syslog message: ``tag`` (the key rules match: ``LINK-UPDOWN``,
    ``ASA-111008``, ``SNMP_TRAP_LINK_DOWN``; empty when none was found),
    ``raw_tag`` as written (``LINK-3-UPDOWN``), ``text`` (what follows the
    tag, or the whole message without one), ``message`` (the message
    without its priority), ``program`` (the RFC 5424 APP-NAME or RFC 3164
    program, as written; empty when none was found) and ``body`` (the
    message after its header and program; ``text`` when there is no
    program)."""

    tag: str
    raw_tag: str
    text: str
    message: str
    program: str = ""
    body: str = ""


# %FACILITY-SEVERITY-MNEMONIC: (IOS XR facilities have two parts and a
# space before the colon: %ROUTING-BGP-5-ADJCHANGE :).
_CISCO_TAG = re.compile(r"%([A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z][A-Za-z0-9_]*){0,3}?)-([0-7])-([A-Za-z0-9_]+)\s?:")
# Junos: daemon[pid]: TAG_NAME: text (upper case with an underscore).
_JUNOS_TAG = re.compile(r"(?:^|[\s:])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+):(?:\s|$)")
_JUNOS_TAG_ONLY = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_PRI = re.compile(r"^<(\d{1,3})>")
# RFC 5424: VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG.
_RFC5424 = re.compile(r"^\d{1,2} \S+ \S+ (\S+) \S+ (\S+) ")
# RFC 3164: [TIMESTAMP] [HOSTNAME] PROGRAM[PID]: MSG.
_BSD_TIMESTAMP = re.compile(r"^[A-Z][a-z]{2} [ \d]?\d \d{2}:\d{2}:\d{2} ")
_PROGRAM_NAME = r"([A-Za-z][\w.\-/]*)(?:\[\d+\])?: "
# Anchored: both are only ever matched at the start of a message, and without
# the anchor ``\S+`` could be retried from every position of a long word.
_PROGRAM = re.compile("^" + _PROGRAM_NAME)
_HOST_PROGRAM = re.compile(r"^\S+ " + _PROGRAM_NAME)
_MNEMONIC = re.compile(r"[A-Za-z0-9_]+")


def _strip_sd(rest: str) -> str:
    """The MSG of an RFC 5424 message after its MSGID: the structured data
    (``-`` or ``[...]`` elements, quotes and escapes honoured) removed."""
    if rest.startswith("-"):
        return rest[1:].lstrip()
    i, n = 0, len(rest)
    while i < n and rest[i] == "[":
        i += 1
        quoted = False
        while i < n:
            ch = rest[i]
            if ch == "\\" and quoted:
                i += 2
                continue
            if ch == '"':
                quoted = not quoted
            elif ch == "]" and not quoted:
                i += 1
                break
            i += 1
    return rest[i:].lstrip()


def normalize_tag(tag: str) -> str:
    """The key a tag is matched by: ``%LINK-3-UPDOWN`` -> ``LINK-UPDOWN``
    (the severity digit dropped, upper case); a Junos tag unchanged."""
    tag = tag.strip().lstrip("%").strip()
    # FACILITY-<severity>-MNEMONIC, split on the last hyphen: a regular
    # expression over the facility backtracks on text a device sends.
    head, _, mnemonic = tag.rpartition("-")
    facility = head[:-2]
    if (
        facility
        and "\n" not in facility
        and head[-2] == "-"
        and head[-1] in "01234567"
        and _MNEMONIC.fullmatch(mnemonic)
    ):
        return f"{facility}-{mnemonic}".upper()
    return tag.upper()


def _bsd_rest(text: str) -> str:
    """An RFC 3164 message without its timestamp (when it has one)."""
    stamp = _BSD_TIMESTAMP.match(text)
    return text[stamp.end() :].lstrip() if stamp else text


def _bsd_program(text: str) -> tuple[str, str]:
    """``(program, MSG)`` of an RFC 3164 message (its timestamp and host
    name optional), or ``("", text)`` when it names no program."""
    rest = _bsd_rest(text)
    found = _PROGRAM.match(rest) or _HOST_PROGRAM.match(rest)
    if found is None:
        return "", text
    return found.group(1), rest[found.end() :].strip()


def parse_syslog_message(message: str) -> ParsedSyslog:
    """The event tag, program and text of a syslog message (RFC 3164 or RFC
    5424, with or without its priority, timestamps and sequence numbers)."""
    text = (message or "").strip()
    pri = _PRI.match(text)
    if pri:
        text = text[pri.end() :].lstrip()
    text = text.replace("\ufeff", "")
    m5424 = _RFC5424.match(text)
    if m5424:
        app_name, msgid = m5424.groups()
        program = "" if app_name == "-" else app_name
        body = _strip_sd(text[m5424.end() :])
        if _JUNOS_TAG_ONLY.fullmatch(msgid):
            return ParsedSyslog(msgid, msgid, body, text, program, body)
        search_in = body
    else:
        program, body = _bsd_program(text)
        search_in = text
    if not program:
        body = search_in
    vendor = vendor_tag(search_in)
    if vendor is not None:
        return ParsedSyslog(vendor.tag, vendor.raw_tag, vendor.text, text, program, body)
    head = search_in[:_TAG_SEARCH_CHARS]
    cisco = _CISCO_TAG.search(head)
    if cisco:
        facility, sev, mnemonic = cisco.groups()
        raw = f"{facility}-{sev}-{mnemonic}"
        return ParsedSyslog(
            f"{facility}-{mnemonic}".upper(), raw, search_in[cisco.end() :].strip(), text, program, body
        )
    junos = _JUNOS_TAG.search(head)
    if junos:
        tag = junos.group(1)
        return ParsedSyslog(tag, tag, search_in[junos.end() :].strip(), text, program, body)
    if not m5424:
        aoss = aos_switch_tag(_bsd_rest(text))
        if aoss is not None:
            return ParsedSyslog(aoss.tag, aoss.raw_tag, aoss.text, text, aoss.program, aoss.text)
    return ParsedSyslog("", "", search_in, text, program, body)


# ── Built-in rules ───────────────────────────────────────────────────────────

_I = re.IGNORECASE


def _clean_instance(value: str) -> str:
    return value.strip().strip(",.;:()'\"")[:100]


@dataclass(frozen=True)
class Matcher:
    """One message form a built-in rule or trigger acts on: its tags (or
    tag prefixes) or its programs (or program prefixes, lower case), a
    pattern its text must contain (``text``) and must not (``exclude``), and
    the pattern whose groups name the instance (joined with ``/``). A tag
    match tests the text after the tag; a program match the text after the
    program (``ParsedSyslog.body``)."""

    tags: frozenset[str] = frozenset()
    tag_prefixes: tuple[str, ...] = ()
    text: re.Pattern[str] | None = None
    exclude: re.Pattern[str] | None = None
    instance: re.Pattern[str] | None = None
    programs: frozenset[str] = frozenset()
    program_prefixes: tuple[str, ...] = ()

    def has_tag(self, tag: str) -> bool:
        """``tag`` is one of this matcher's tags (or starts with one of its
        prefixes), whatever the text says."""
        return bool(tag) and (tag in self.tags or any(tag.startswith(p) for p in self.tag_prefixes))

    def _subject(self, parsed: ParsedSyslog) -> str | None:
        """The text the patterns test, or None when neither the tag nor the
        program is one of this matcher's."""
        if self.has_tag(parsed.tag):
            return parsed.text
        program = parsed.program.lower()
        if program and (program in self.programs or any(program.startswith(p) for p in self.program_prefixes)):
            return parsed.body
        return None

    def match(self, parsed: ParsedSyslog) -> str | None:
        """The instance ("" when none) when the message matches, else None."""
        subject = self._subject(parsed)
        if subject is None:
            return None
        if self.text is not None and self.text.search(subject) is None:
            return None
        if self.exclude is not None and self.exclude.search(subject) is not None:
            return None
        if self.instance is None:
            return ""
        m = self.instance.search(subject)
        if m is None:
            return ""
        return _clean_instance("/".join(g for g in m.groups() if g))


def _m(*tags: str, prefixes: tuple[str, ...] = (), text: str = "", exclude: str = "", instance: str = "") -> Matcher:
    return Matcher(
        tags=frozenset(tags),
        tag_prefixes=prefixes,
        text=re.compile(text, _I) if text else None,
        exclude=re.compile(exclude, _I) if exclude else None,
        instance=re.compile(instance, _I) if instance else None,
    )


def _p(
    *programs: str, prefixes: tuple[str, ...] = (), text: str = "", exclude: str = "", instance: str = ""
) -> Matcher:
    """A matcher by program name (``dpinger``) or prefix (``openvpn``)."""
    return Matcher(
        programs=frozenset(p.lower() for p in programs),
        program_prefixes=tuple(p.lower() for p in prefixes),
        text=re.compile(text, _I) if text else None,
        exclude=re.compile(exclude, _I) if exclude else None,
        instance=re.compile(instance, _I) if instance else None,
    )


def _first(matchers: Iterable[Matcher], parsed: ParsedSyslog) -> str | None:
    for matcher in matchers:
        found = matcher.match(parsed)
        if found is not None:
            return found
    return None


@dataclass(frozen=True)
class BuiltinRule:
    key: str
    name: str
    description: str
    families: tuple[str, ...]
    severity: str
    raise_on: tuple[Matcher, ...]
    clear_on: tuple[Matcher, ...] = ()
    threshold_count: int = 1
    threshold_window_seconds: int = 300
    auto_resolve_minutes: int = 0


_IFACE = r"([^\s,]+)"
_JUNOS_FRU = r"jnxContentsDescr ([^,)]+)"

# An interface going down (not by an operator): the link_flap rule counts
# these, and the re-poll trigger acts on the first one.
INTERFACE_DOWN: tuple[Matcher, ...] = (
    # IOS / IOS XE / IOS XR physical link.
    _m(
        "LINK-UPDOWN",
        "PKT_INFRA-LINK-UPDOWN",
        text=r"changed state to down\b",
        instance=rf"Interface {_IFACE}",
    ),
    # IOS / IOS XE / IOS XR / Arista EOS line protocol, ASA 411002.
    _m(
        "LINEPROTO-UPDOWN",
        "PKT_INFRA-LINEPROTO-UPDOWN",
        "ASA-411002",
        text=r"changed state to down\b",
        instance=rf"Line protocol on Interface {_IFACE}",
    ),
    # NX-OS.
    _m(
        "ETHPORT-IF_DOWN_LINK_FAILURE",
        "ETHPORT-IF_DOWN_ERROR_DISABLED",
        "ETHPORT-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN",
        instance=rf"Interface {_IFACE} is down",
    ),
    # Junos (an interface an operator disabled has ifAdminStatus down).
    _m("SNMP_TRAP_LINK_DOWN", text=r"ifAdminStatus up\b", instance=rf"ifName {_IFACE}"),
    # FortiOS 20099 "Interface status changed": "Link monitor: Interface
    # wan1 was turned down" (the up form says "turned up").
    _m("FGT-0100020099", text=r"\bwas turned down\b", instance=rf"\bInterface {_IFACE} was turned down"),
    # PAN-OS link-change: "Port ethernet1/3: Down 1Gb/s-full duplex",
    # "ethernet1/3: Down ...", "Port MGT: Down ...", "Port X: MAC Down".
    _m("PAN-SYSTEM-LINK-CHANGE", text=r":(?: MAC)? Down\b", instance=r"^(?:Port )?([^\s:,]+):"),
    # AOS-CX 404: "Link status for interface 1/1/1 is down".
    _m("AOSCX-404", text=r"\bis down\b", instance=rf"\binterface {_IFACE} is down"),
    # AOS-Switch 77: "port 1 is now off-line" (stacked: "port 2/16").
    _m("AOSS-00077", text=r"\bis now off-line\b", instance=rf"\bport {_IFACE} is now off-line"),
)

# ADJCHG: IOS, IOS XE, IOS XR. NBRSTATE: NX-OS (newer releases; older ones log
# ADJCHANGE "went DOWN"). Both read "... Nbr X on IF from STATE to STATE".
_OSPF_TAGS = ("OSPF-ADJCHG", "OSPFV3-ADJCHG", "ROUTING-OSPF-ADJCHG", "ROUTING-OSPFV3-ADJCHG", "OSPF-NBRSTATE")
# FortiOS 20300 "BGP neighbor status changed" carries the same text in its
# msg ("BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor X Down Hold Timer Expired").
_BGP_TAGS = ("BGP-ADJCHANGE", "ROUTING-BGP-ADJCHANGE", "FGT-0103020300")
# FortiOS 20302 "OSPF neighbor status changed": "OSPF: %OSPF-5-ADJCHANGE:
# neighbor port1:192.0.2.1-192.0.2.2 Down" (the neighbor is IF:local-remote).
_FGT_OSPF = "FGT-0103020302"
_PAN_BGP_PEER = r"\bpeer IP: ([^\s,]+)"
_ARISTA_PSU = r"\b(PowerSupply\d+)"
_ARISTA_FAN = r"\b(Fan\d+(?:/\d+)?)"

BUILTIN_RULES: tuple[BuiltinRule, ...] = (
    BuiltinRule(
        key="link_flap",
        name="Interface flapping",
        description=(
            "An interface went down 3 times within 10 minutes. One down is not an alert (access ports go "
            "down all day); resolves 30 minutes after the last down."
        ),
        families=(
            "Cisco IOS / IOS XE",
            "Cisco IOS XR",
            "Cisco NX-OS",
            "Cisco ASA",
            "Arista EOS",
            "Juniper Junos",
            "Fortinet FortiOS",
            "Palo Alto PAN-OS",
            "HPE Aruba AOS-CX",
            "HPE Aruba AOS-Switch",
        ),
        severity="warning",
        raise_on=INTERFACE_DOWN,
        threshold_count=3,
        threshold_window_seconds=600,
        auto_resolve_minutes=30,
    ),
    BuiltinRule(
        key="ospf_neighbor",
        name="OSPF neighbor down",
        description="An OSPF adjacency went down; resolved when it is back to FULL.",
        families=(
            "Cisco IOS / IOS XE",
            "Cisco IOS XR",
            "Cisco NX-OS",
            "Arista EOS",
            "Juniper Junos",
            "Fortinet FortiOS",
            "Palo Alto PAN-OS",
        ),
        severity="critical",
        raise_on=(
            _m(*_OSPF_TAGS, text=r"\bto DOWN\b", instance=rf"Nbr {_IFACE}"),
            _m("OSPF-ADJCHANGE", text=r"\bwent DOWN\b", instance=rf"Nbr {_IFACE}"),
            _m("OSPF-OSPF_ADJACENCY_TEARDOWN", instance=rf"NGB {_IFACE}"),
            _m("RPD_OSPF_NBRDOWN", instance=rf"neighbor {_IFACE}"),
            _m(_FGT_OSPF, text=r"\bADJCHANGE: neighbor \S+ Down\b", instance=rf"\bADJCHANGE: neighbor {_IFACE}"),
            # PAN-OS (legacy routing engine): the description names no
            # neighbor, so one alert per firewall.
            _m("PAN-SYSTEM-ROUTED-OSPF-NEIGHBOR-DOWN"),
        ),
        clear_on=(
            _m(*_OSPF_TAGS, text=r"\bto FULL\b", instance=rf"Nbr {_IFACE}"),
            _m("OSPF-ADJCHANGE", text=r"\bwent FULL\b", instance=rf"Nbr {_IFACE}"),
            _m("OSPF-OSPF_ADJACENCY_ESTABLISHED", instance=rf"NGB {_IFACE}"),
            _m("RPD_OSPF_NBRUP", text=r"\bto Full\b", instance=rf"neighbor {_IFACE}"),
            _m(_FGT_OSPF, text=r"\bADJCHANGE: neighbor \S+ Up\b", instance=rf"\bADJCHANGE: neighbor {_IFACE}"),
            _m("PAN-SYSTEM-ROUTED-OSPF-NEIGHBOR-FULL"),
        ),
    ),
    BuiltinRule(
        key="bgp_neighbor",
        name="BGP neighbor down",
        description="A BGP session left Established or was reset; resolved when it is Up / Established again.",
        families=(
            "Cisco IOS / IOS XE",
            "Cisco IOS XR",
            "Cisco NX-OS",
            "Arista EOS",
            "Juniper Junos",
            "Fortinet FortiOS",
            "Palo Alto PAN-OS",
        ),
        severity="critical",
        raise_on=(
            _m(*_BGP_TAGS, text=r"neighbor \S+(?: vpn vrf \S+)? Down\b", instance=rf"neighbor {_IFACE}"),
            _m("BGP-NBR_RESET", instance=rf"Neighbor {_IFACE}"),
            _m(
                "BGP-ADJCHANGE",
                text=r"old state Established\b.*\bnew state (?!Established)",
                instance=rf"peer {_IFACE}",
            ),
            _m(
                "RPD_BGP_NEIGHBOR_STATE_CHANGED",
                text=r"from Established to (?!Established)",
                instance=r"peer ([^\s,+]+)",
            ),
            _m("PAN-SYSTEM-ROUTED-BGP-PEER-LEFT-ESTABLISHED", instance=_PAN_BGP_PEER),
        ),
        clear_on=(
            _m(*_BGP_TAGS, text=r"neighbor \S+(?: vpn vrf \S+)? Up\b", instance=rf"neighbor {_IFACE}"),
            _m("BGP-ADJCHANGE", text=r"\bnew state Established\b", instance=rf"peer {_IFACE}"),
            _m("RPD_BGP_NEIGHBOR_STATE_CHANGED", text=r"\bto Established\b", instance=r"peer ([^\s,+]+)"),
            _m("PAN-SYSTEM-ROUTED-BGP-PEER-ENTER-ESTABLISHED", instance=_PAN_BGP_PEER),
        ),
    ),
    BuiltinRule(
        key="power_supply",
        name="Power supply fault",
        description="A power supply failed or lost its input; resolved when it reports OK, or after 24 hours.",
        families=(
            "Cisco IOS XE (ASR 1000, ISR 4000, Catalyst 9000)",
            "Cisco Catalyst 3750-X / 3560-X",
            "Cisco NX-OS",
            "Arista EOS",
            "Juniper Junos",
            "Fortinet FortiOS",
            "Palo Alto PAN-OS",
            "HPE Aruba AOS-CX",
        ),
        severity="critical",
        raise_on=(
            _m("IOSXE_PEM-PEMFAIL", instance=rf"slot {_IFACE}"),
            _m("PLATFORM_FEP-FRU_PS_SIGNAL_FAULTY", instance=r"Switch (\d+):.*power supply ([A-Za-z0-9]+)"),
            _m("PLATFORM-PS_FAIL", instance=r"Power supply (\d+)"),
            _m(prefixes=("CHASSISD_SNMP_TRAP",), text=r"Power Supply fail", instance=_JUNOS_FRU),
            # Catalyst 3750-X / 3560-X: "<signal> signal on power supply is
            # faulty" (names no supply).
            _m("PLATFORM_ENV-FRU_PS_SIGNAL_FAULTY"),
            # Arista EOS: "PowerSupply2 has failed and has stopped providing
            # power to the system." / "PowerSupply2 has lost input power."
            _m("PWRMGMT-PSU_STATUS_FAILED", "PWRMGMT-INPUT_POWER_LOSS", instance=_ARISTA_PSU),
            # FortiOS 22105 "Power supply failed" (msg "PSU [2] not detected";
            # 22104 "Power supply restored" names no supply in a known form,
            # so one alert per firewall).
            _m("FGT-0100022105"),
            # PAN-OS ps-failure: "Alarm on Power Supply #2".
            _m("PAN-SYSTEM-PS-FAILURE", instance=r"\bPower Supply #(\d+)"),
            # AOS-CX 304: "PSU 1/1 faulted."
            _m("AOSCX-304", instance=r"\bPSU (\S+?) faulted"),
        ),
        clear_on=(
            _m("IOSXE_PEM-PEMOK", instance=rf"slot {_IFACE}"),
            _m("PLATFORM_FEP-FRU_PS_SIGNAL_OK", instance=r"Switch (\d+):.*power supply ([A-Za-z0-9]+)"),
            _m("PLATFORM-PS_OK", instance=r"Power supply (\d+)"),
            _m(prefixes=("CHASSISD_SNMP_TRAP",), text=r"Power Supply OK", instance=_JUNOS_FRU),
            _m("PWRMGMT-PSU_STATUS_OK", instance=_ARISTA_PSU),
            _m("FGT-0100022104"),
        ),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="fan",
        name="Fan fault",
        description="A fan failed; resolved when it reports OK, or after 24 hours.",
        families=(
            "Cisco IOS XE (ASR 1000, ISR 4000)",
            "Cisco Catalyst 2960 / 3560 / 3750 (classic IOS)",
            "Cisco ISR G2 (1900, 2900, 3900)",
            "Cisco NX-OS",
            "Arista EOS",
            "Juniper Junos",
            "Palo Alto PAN-OS",
        ),
        severity="warning",
        raise_on=(
            _m("IOSXE_PEM-FANFAIL", instance=rf"slot {_IFACE}"),
            _m("PLATFORM-FANMOD_FAN_FAIL", instance=r"Fan module (\d+)"),
            _m(prefixes=("CHASSISD_SNMP_TRAP",), text=r"Fan(?:/Blower)? fail", instance=_JUNOS_FRU),
            # Catalyst 2960 / 3560 / 3750: "Fan 1 Failure."; 3750-X / 3560-X:
            # "Faulty fan detected." and "Power supply fan failure detected."
            _m("HARDWARE-FAN_ERROR", instance=r"\bFan (\S+?)\s+Failure\b"),
            _m("PLATFORM_ENV-FAN", "PLATFORM_ENV-FRU_PS_FAN_FAILED"),
            # ISR G2 (and ISR 4000): "Fan 1 is malfunctioning"; older ISRs
            # log FAN_FAILED.
            _m("ENVMON-FAN_FAIL", "ENVMON-FAN_FAILED", instance=r"\bFan (\d+)"),
            # Arista EOS: "Fan1/1 failure detected".
            _m("ENVMON-FANFAILED", instance=_ARISTA_FAN),
            # PAN-OS fan-failure: "Alarm on Fan Tray #1".
            _m("PAN-SYSTEM-FAN-FAILURE", instance=r"\bFan Tray #(\d+)"),
        ),
        clear_on=(
            _m("IOSXE_PEM-FANOK", instance=rf"slot {_IFACE}"),
            _m("PLATFORM-FANMOD_FAN_OK", instance=r"Fan module (\d+)"),
            _m(prefixes=("CHASSISD_SNMP_TRAP",), text=r"Fan(?:/Blower)? OK", instance=_JUNOS_FRU),
            _m("ENVMON-FAN_OK", instance=r"\bFan (\d+)"),
            _m("ENVMON-FANOK", instance=_ARISTA_FAN),
        ),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="auth_failure",
        name="Repeated login failures",
        description=(
            "5 failed logins to one device within 5 minutes (from any source); resolves 30 minutes after "
            "the last failure."
        ),
        families=(
            "Cisco IOS / IOS XE",
            "Cisco IOS XR",
            "Cisco NX-OS",
            "Cisco ASA",
            "Arista EOS",
            "Juniper Junos",
            "OPNsense",
            "Fortinet FortiOS",
            "Palo Alto PAN-OS",
            "HPE Aruba AOS-CX",
            "HPE Aruba AOS-Switch",
        ),
        severity="warning",
        raise_on=(
            _m(
                "SEC_LOGIN-LOGIN_FAILED",
                "SECURITY-LOGIN-AUTHEN_FAILED",
                "ASA-113005",
                "ASA-113015",
                "ASA-605004",
                "ASA-611102",
                "SSHD_LOGIN_FAILED",
                "LOGIN_FAILED",
                "FGT-0100032002",  # FortiOS "Admin login failed"
                "AOSCX-5210",  # AOS-CX SSH login failed (password)
                "AOSCX-5216",  # AOS-CX SSH login failed (public key)
                "AOSS-00419",  # AOS-Switch invalid user name / password
                "AOSS-03345",  # AOS-Switch SSH login failed
            ),
            # PAN-OS auth-fail, except the ones that report the
            # authentication server's setup rather than a login.
            _m(
                "PAN-SYSTEM-AUTH-FAIL",
                exclude=r"^(?:Time clock does not match|Wrong realm|Server certificate:|KDC Spoofing)",
            ),
            # OpenSSH (Arista EOS, and any host that sends sshd's lines):
            # "Failed password for [invalid user ]NAME from ADDR port N ssh2".
            _p("sshd", text=r"^Failed (?:password|keyboard-interactive/pam) for "),
            _m("AUTHPRIV-SYSTEM_MSG", text=r"authentication failed"),
            # OPNsense: a login the firewall authenticates (web GUI, and SSH
            # through pam_opnsense) that no authenticator accepted
            # (AuthenticationFactory, ident "audit"; the per-authenticator
            # "failed authentication" lines are debug level and not counted).
            _p("audit", text=r"^user .{1,200}? could not authenticate for "),
        ),
        threshold_count=5,
        threshold_window_seconds=300,
        auto_resolve_minutes=30,
    ),
)
BUILTIN_BY_KEY: dict[str, BuiltinRule] = {r.key: r for r in BUILTIN_RULES}

# ── Triggers ─────────────────────────────────────────────────────────────────

CONFIG_CHANGE: tuple[Matcher, ...] = (
    _m(
        "SYS-CONFIG_I",  # IOS, IOS XE, Arista EOS
        "VSHD-VSHD_SYSLOG_CONFIG_I",  # NX-OS
        "MGBL-CONFIG-DB_COMMIT",  # IOS XR
        "ASA-111008",  # ASA: a configuration command
        "UI_COMMIT_COMPLETED",  # Junos
    ),
    # ASA 111010 logs every command run through ASDM or the CLI, show
    # commands too: only the others count.
    _m("ASA-111010", text=r"executed '", exclude=r"executed '(?:show|ping|traceroute|more|dir)\b"),
    # FortiOS applies each change at once: 44544 "Path configured", 44545
    # "Object configured", 44546 "Attribute configured", 44547 "Object
    # attribute configured" (44548 "Action performed", an execute command,
    # is no change).
    _m("FGT-0100044544", "FGT-0100044545", "FGT-0100044546", "FGT-0100044547"),
    # PAN-OS CONFIG log of a commit that succeeded (Command, Admin, Client,
    # Result): a candidate edit (set, edit, delete ...) changes nothing yet.
    _m("PAN-CONFIG", text=r'^commit,(?:"[^"]*"|[^,]*),(?:"[^"]*"|[^,]*),Succeeded(?:,|$)'),
    # A commit runs as a job, so its CONFIG log may only say "Submitted":
    # the SYSTEM log reports the job's end ("Commit job succeeded[ for user
    # NAME]").
    _m("PAN-SYSTEM-GENERAL", text=r"^Commit job succeeded\b"),
)
# Messages a device logs when it is about to reload.
RELOAD: tuple[Matcher, ...] = (
    _m("SYS-RELOAD", "ASA-199001", "UI_REBOOT_EVENT", "PLATFORM-PFM_SYSTEM_RESET"),
    # FortiOS 32138 "Device rebooted", 32200 "Device shutdown"; AOS-Switch 63
    # "System went down".
    _m("FGT-0100032138", "FGT-0100032200", "AOSS-00063"),
)
# Messages a device logs once it is back up.
RESTART: tuple[Matcher, ...] = (
    _m("SYS-RESTART", "SYS-BOOTTIME", "ASA-199002", "SNMPD_TRAP_COLD_START"),
    # FortiOS 32009 "FortiGate started"; AOS-Switch 64 "System Booted".
    _m("FGT-0100032009", "AOSS-00064"),
)


# OPNsense: messages that say a state its topology source collects just
# changed. Each starts a re-collection of the source
# (``netcontrol.source_recollect``); none raises an alert (the availability
# tracker owns gateway, tunnel and CARP alerts). Formats from the upstream
# sources, see ``docs/opnsense-topology.md`` "Syslog".
OPNSENSE_RECOLLECT: tuple[tuple[str, tuple[Matcher, ...]], ...] = (
    (
        "gateway",
        (
            # The gateway watcher (opnsense/core scripts/routes/gateway_watcher.php,
            # ident dpinger): "ALERT|MONITOR: GW (Addr: a Alarm: old -> new RTT: ...)".
            _p("dpinger", text=r"^(?:ALERT|MONITOR): \S+ \(Addr: \S* Alarm: ", instance=r"^\w+: (\S+)"),
            # dpinger itself: "GW 192.0.2.1: Alarm|Clear latency 1us stddev 1us loss 0%".
            _p("dpinger", text=r": (?:Alarm|Clear) latency \d+us stddev \d+us loss \d+%", instance=r"^(\S+) "),
        ),
    ),
    (
        "carp",
        # FreeBSD ip_carp.c (kernel): "carp: VHID@IF: OLD -> NEW (reason)" and
        # "carp: demoted by N to M (reason)".
        (
            _p(
                "kernel",
                text=r"^carp: (?:\d+@\S+: (?:INIT|BACKUP|MASTER) -> (?:INIT|BACKUP|MASTER)\b|demoted by -?\d+ to )",
                instance=r"^carp: (\d+@[^\s:]+)",
            ),
        ),
    ),
    (
        "vpn",
        (
            # strongSwan charon, IKE_SA (phase 1) up or down. CHILD_SA
            # "established" / "closing" lines repeat on every rekey and are
            # left out; "CHILD_SA name{n} closed" is a close without rekey.
            _p(
                "charon",
                text=r"\bIKE_SA \S+\[\d+\] established between |\bdeleting IKE_SA \S+\[\d+\] between |"
                r"\bIKE_SA deleted\b|\bCHILD_SA \S+\{\d+\} closed\b",
                instance=r"\bIKE_SA ([^\s\[]+)\[|\bCHILD_SA ([^\s{]+)\{",
            ),
            # An OpenVPN instance (daemon openvpn_server1 / openvpn_client2) up
            # or restarting / stopping. Lines of one client of a server
            # instance start with "name/address:port " and are left out.
            _p(
                prefixes=("openvpn",),
                text=r"^(?:Initialization Sequence Completed\b|SIG(?:USR1|HUP|TERM|INT)\[[^\]]*\] received, process )",
            ),
        ),
    ),
    (
        "config",
        (
            # opnsense/core Config.php: "config-event: new_config <backup>"
            # (ident config) and the audit line of the same save.
            _p("config", text=r"\bconfig-event: new_config\b"),
            _p("audit", text=r"^user .{1,200}? changed configuration to "),
        ),
    ),
    (
        "ids",
        # Suricata's alert lines (IDS "Enable syslog alerts", alert-syslog.c:
        # "[Drop] [1:sid:rev] signature [Classification: ...] [Priority: n]
        # {PROTO} src -> dst") and its eve records over syslog ("Enable eve
        # syslog output": JSON with "event_type":"alert"). Not a
        # re-collection: only the source's IDS alerts are read
        # (``opnsense_ids.read_source_now``).
        (
            _p("suricata", text=r'^(?:\[w?Drop\] )?\[\d+:\d+:\d+\] |"event_type": ?"alert"'),
        ),
    ),
)
RECOLLECT_REASONS: tuple[str, ...] = tuple(reason for reason, _matchers in OPNSENSE_RECOLLECT)
# The program names (and prefixes) of those matchers: a message whose head
# names none of them is not parsed a second time for the trigger.
_RECOLLECT_PROGRAMS: tuple[str, ...] = tuple(
    sorted(
        {p for _reason, matchers in OPNSENSE_RECOLLECT for m in matchers for p in (*m.programs, *m.program_prefixes)}
    )
)


def recollect_reason(parsed: ParsedSyslog) -> str:
    """``gateway``, ``carp``, ``vpn``, ``config``, ``ids`` (a read of the
    IDS alerts only) or "" for a message that does not start an OPNsense
    re-collection."""
    if not parsed.program:
        return ""
    for reason, matchers in OPNSENSE_RECOLLECT:
        if _first(matchers, parsed) is not None:
            return reason
    return ""


def is_config_change(parsed: ParsedSyslog) -> bool:
    return _first(CONFIG_CHANGE, parsed) is not None


def repoll_reason(parsed: ParsedSyslog) -> str:
    """``interface_down``, ``reload``, ``restart`` or "" for a message that
    does not trigger a re-poll."""
    if _first(INTERFACE_DOWN, parsed) is not None:
        return "interface_down"
    if _first(RELOAD, parsed) is not None:
        return "reload"
    if _first(RESTART, parsed) is not None:
        return "restart"
    return ""


# The built-in rules and triggers by the tags their message forms carry.
_TAG_OWNERS: tuple[tuple[str, tuple[Matcher, ...]], ...] = (
    *((rule.key, (*rule.raise_on, *rule.clear_on)) for rule in BUILTIN_RULES),
    ("config_change", CONFIG_CHANGE),
    ("repoll", (*RELOAD, *RESTART)),
)


def tag_owner(tag: str) -> str:
    """The built-in rule (its key) or trigger (``config_change``, ``repoll``)
    that has a message form with ``tag``, or "". A message with such a tag
    that nothing acted on did not meet the text pattern of that form: the
    opposite event (``LINK-UPDOWN`` ... ``to up``), or wording the pattern
    does not cover."""
    for owner, matchers in _TAG_OWNERS:
        if any(m.has_tag(tag) for m in matchers):
            return owner
    return ""


# ── Rules: built-in and custom, merged ───────────────────────────────────────


class RuleError(ValueError):
    """An invalid custom rule: ``message`` for the API."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass
class Rule:
    """A rule the engine evaluates: a built-in (with its stored override)
    or a custom rule. ``key`` names it in the alert's metric and dedup key."""

    key: str
    name: str
    severity: str
    enabled: bool
    builtin: bool
    threshold_count: int
    threshold_window_seconds: int
    auto_resolve_minutes: int
    raise_match: Callable[[ParsedSyslog], str | None]
    clear_match: Callable[[ParsedSyslog], str | None] | None = None
    id: int | None = None
    description: str = ""
    families: tuple[str, ...] = ()
    match_type: str = ""
    pattern: str = ""
    clear_pattern: str = ""
    tags: tuple[str, ...] = ()
    clear_tags: tuple[str, ...] = ()
    created_by: str = ""
    created_at: str = ""
    updated_at: str = ""
    overridden: bool = field(default=False)

    @property
    def metric(self) -> str:
        return metric_name(self.key)

    def payload(self) -> dict:
        """The API form of the rule."""
        return {
            "id": self.id,
            "key": self.key,
            "metric": self.metric,
            "name": self.name,
            "description": self.description,
            "builtin": self.builtin,
            "enabled": self.enabled,
            "severity": self.severity,
            "match_type": self.match_type,
            "pattern": self.pattern,
            "clear_pattern": self.clear_pattern,
            "tags": list(self.tags),
            "clear_tags": list(self.clear_tags),
            "families": list(self.families),
            "threshold_count": self.threshold_count,
            "threshold_window_seconds": self.threshold_window_seconds,
            "auto_resolve_minutes": self.auto_resolve_minutes,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def metric_name(rule_key: str) -> str:
    return f"syslog_{rule_key}"


def dedup_key(rule_key: str, host_id: int, instance: str) -> str:
    return f"syslog:{rule_key}:{host_id}:{instance}"


def custom_rule_key(rule_id: int) -> str:
    return f"custom_{int(rule_id)}"


def _matcher_tags(matchers: Iterable[Matcher]) -> tuple[str, ...]:
    out: set[str] = set()
    for m in matchers:
        out.update(m.tags)
        out.update(f"{p}*" for p in m.tag_prefixes)
        out.update(f"program:{p}" for p in m.programs)
        out.update(f"program:{p}*" for p in m.program_prefixes)
    return tuple(sorted(out))


def _builtin(rule: BuiltinRule, override: dict | None) -> Rule:
    return Rule(
        key=rule.key,
        name=rule.name,
        severity=(override or {}).get("severity") or rule.severity,
        enabled=bool(override["enabled"]) if override else True,
        builtin=True,
        threshold_count=rule.threshold_count,
        threshold_window_seconds=rule.threshold_window_seconds,
        auto_resolve_minutes=rule.auto_resolve_minutes,
        raise_match=partial(_first, rule.raise_on),
        clear_match=partial(_first, rule.clear_on) if rule.clear_on else None,
        description=rule.description,
        families=rule.families,
        match_type="builtin",
        tags=_matcher_tags(rule.raise_on),
        clear_tags=_matcher_tags(rule.clear_on),
        updated_at=(override or {}).get("updated_at", ""),
        overridden=override is not None,
    )


def _split_tags(pattern: str) -> frozenset[str]:
    return frozenset(normalize_tag(t) for t in re.split(r"[,\s]+", pattern or "") if t.strip().lstrip("%"))


def _custom_matcher(match_type: str, pattern: str) -> Callable[[ParsedSyslog], str | None]:
    """The match function of a custom pattern (ValueError for a regex RE2
    rejects). ``tag``: comma separated tags, with or without the severity
    digit; ``contains``: text anywhere in the message, ignoring case;
    ``regex``: an RE2 pattern searched in the message, ignoring case, whose
    group ``instance`` (else its first group) names the instance."""
    if match_type == "tag":
        tags = _split_tags(pattern)
        return lambda parsed: "" if parsed.tag and parsed.tag in tags else None
    if match_type == "contains":
        needle = pattern.casefold()
        return lambda parsed: "" if needle and needle in parsed.message.casefold() else None
    compiled: UserRegex = compile_user_regex(pattern)

    def _regex(parsed: ParsedSyslog) -> str | None:
        m = compiled.search(parsed.message)
        if m is None:
            return None
        groups = m.groupdict() if hasattr(m, "groupdict") else {}
        if groups.get("instance"):
            return _clean_instance(groups["instance"])
        first = m.groups() if hasattr(m, "groups") else ()
        return _clean_instance(first[0]) if first and first[0] else ""

    return _regex


def _custom(row: dict, key: str | None = None) -> Rule:
    match_type = row["match_type"]
    clear = row.get("clear_pattern") or ""
    return Rule(
        key=key or custom_rule_key(row["id"]),
        name=row["name"],
        severity=row["severity"],
        enabled=bool(row.get("enabled", True)),
        builtin=False,
        threshold_count=int(row["threshold_count"]),
        threshold_window_seconds=int(row["threshold_window_seconds"]),
        auto_resolve_minutes=int(row["auto_resolve_minutes"]),
        raise_match=_custom_matcher(match_type, row["pattern"]),
        clear_match=_custom_matcher(match_type, clear) if clear else None,
        id=row.get("id"),
        match_type=match_type,
        pattern=row["pattern"],
        clear_pattern=clear,
        created_by=row.get("created_by", ""),
        created_at=row.get("created_at", ""),
        updated_at=row.get("updated_at", ""),
    )


def _int_field(body: dict, name: str, default: int, low: int, high: int) -> int:
    raw = body.get(name, default)
    if isinstance(raw, bool):
        raise RuleError(f"{name} must be a whole number.")
    try:
        value = int(raw)
    except TypeError, ValueError:
        raise RuleError(f"{name} must be a whole number.") from None
    if not low <= value <= high:
        raise RuleError(f"{name} must be from {low} to {high}.")
    return value


def _check_pattern(match_type: str, pattern: str, label: str) -> None:
    if len(pattern) > PATTERN_MAX:
        raise RuleError(f"The {label} is longer than {PATTERN_MAX} characters.")
    if match_type == "tag" and not _split_tags(pattern):
        raise RuleError(f"The {label} needs at least one tag.")
    if match_type == "regex":
        try:
            compile_user_regex(pattern)
        except ValueError as exc:
            raise RuleError(f"The {label} is not a valid regular expression: {exc}") from None


def clean_custom_rule(body: dict) -> dict:
    """The stored values of a custom rule from an API body, or
    ``RuleError``. Regex patterns are compiled with RE2 here, so a pattern
    RE2 rejects (or one with lookarounds or backreferences) is refused when
    it is saved, never on the receive path."""
    if not isinstance(body, dict):
        raise RuleError("The rule must be an object.")
    name = str(body.get("name") or "").strip()
    if not name:
        raise RuleError("The rule needs a name.")
    if len(name) > NAME_MAX:
        raise RuleError(f"The name is longer than {NAME_MAX} characters.")
    match_type = str(body.get("match_type") or "").strip()
    if match_type not in MATCH_TYPES:
        raise RuleError(f"match_type must be one of: {', '.join(MATCH_TYPES)}.")
    pattern = str(body.get("pattern") or "").strip()
    if not pattern:
        raise RuleError("The rule needs a pattern.")
    _check_pattern(match_type, pattern, "pattern")
    clear_pattern = str(body.get("clear_pattern") or "").strip()
    if clear_pattern:
        _check_pattern(match_type, clear_pattern, "clear pattern")
    severity = str(body.get("severity") or "warning").strip()
    if severity not in SEVERITIES:
        raise RuleError(f"severity must be one of: {', '.join(SEVERITIES)}.")
    return {
        "name": name,
        "enabled": bool(body.get("enabled", True)),
        "match_type": match_type,
        "pattern": pattern,
        "clear_pattern": clear_pattern,
        "severity": severity,
        "threshold_count": _int_field(body, "threshold_count", 1, 1, THRESHOLD_COUNT_MAX),
        "threshold_window_seconds": _int_field(body, "threshold_window_seconds", 300, 1, THRESHOLD_WINDOW_MAX),
        "auto_resolve_minutes": _int_field(body, "auto_resolve_minutes", 0, 0, AUTO_RESOLVE_MAX),
    }


def draft_rule(body: dict) -> Rule:
    """A custom rule from an unsaved API body (the test endpoint), or
    ``RuleError``."""
    return _custom({**clean_custom_rule(body), "id": None}, key="draft")


def merge_rules(rows: list[dict]) -> list[Rule]:
    """The built-in rules (with their stored overrides) then the custom
    rules, from the rows of ``syslog_alert_rules``. A custom row that no
    longer compiles is skipped (logged)."""
    overrides = {r["builtin_key"]: r for r in rows if r.get("builtin_key")}
    rules = [_builtin(b, overrides.get(b.key)) for b in BUILTIN_RULES]
    for row in rows:
        if row.get("builtin_key"):
            continue
        try:
            rules.append(_custom(row))
        except (ValueError, KeyError) as exc:
            LOGGER.warning("syslog rules: custom rule %s skipped: %s", row.get("id"), exc)
    return rules


_rules_cache: tuple[float, list[Rule]] | None = None


def invalidate_rules_cache() -> None:
    """Drop the cached rule set: called on every rule write."""
    global _rules_cache
    _rules_cache = None


async def get_rules() -> list[Rule]:
    """Every rule, enabled or not, cached for ``CACHE_TTL_SECONDS`` (so
    other worker processes pick up a change too)."""
    global _rules_cache
    now = _clock()
    if _rules_cache is not None and _rules_cache[0] > now:
        return _rules_cache[1]
    rules = merge_rules(await db.list_syslog_alert_rules())
    _rules_cache = (now + CACHE_TTL_SECONDS, rules)
    return rules


# ── Threshold counters ───────────────────────────────────────────────────────

_counters: OrderedDict[tuple[str, int, str], deque[float]] = OrderedDict()


def _count(key: tuple[str, int, str], threshold: int, window: int, now: float) -> tuple[bool, bool]:
    """Record a match: ``(counted, met)``. ``counted`` is False for a
    repeat of the previous match within ``COALESCE_SECONDS``; ``met`` when
    the last ``threshold`` matches fall within ``window`` seconds."""
    dq = _counters.get(key)
    if dq is None or dq.maxlen != threshold:
        dq = deque(dq or (), maxlen=threshold)
        _counters[key] = dq
        while len(_counters) > COUNTERS_MAX:
            _counters.popitem(last=False)
    _counters.move_to_end(key)
    if dq and now - dq[-1] < COALESCE_SECONDS:
        return False, False
    dq.append(now)
    return True, len(dq) >= threshold and now - dq[0] <= window


def _track(rule: Rule, host_id: int, parsed: ParsedSyslog, now: float) -> tuple[bool, str] | None:
    """Count a message of ``host_id`` for ``rule`` at ``now``: a raise match
    is counted, a clear match drops the counter. ``(True, instance)`` when
    the match meets the threshold (raise), ``(False, instance)`` on a clear
    match (resolve), else None."""
    instance = rule.raise_match(parsed)
    if instance is not None:
        counted, met = _count((rule.key, host_id, instance), rule.threshold_count, rule.threshold_window_seconds, now)
        return (True, instance) if counted and met else None
    instance = rule.clear_match(parsed) if rule.clear_match is not None else None
    if instance is not None:
        _counters.pop((rule.key, host_id, instance), None)
        return False, instance
    return None


# ── The engine ───────────────────────────────────────────────────────────────


def alert_message(rule: Rule, instance: str, parsed: ParsedSyslog) -> str:
    title = rule.name + (f" on {instance}" if instance else "")
    if rule.threshold_count > 1:
        title += f" ({rule.threshold_count} times within {_duration(rule.threshold_window_seconds)})"
    line = f"{parsed.raw_tag}: {parsed.text}" if parsed.raw_tag else parsed.text
    if len(line) > _MESSAGE_SNIPPET:
        line = line[: _MESSAGE_SNIPPET - 3] + "..."
    return f"{title}: {line}"


def _duration(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    if seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds} s"


async def process_syslog_batch(rows: Iterable[tuple[int, str]]) -> dict:
    """Act on received syslog messages of inventory hosts: ``rows`` of
    ``(host_id, message)``. Returns counts: ``raised`` (alerts raised or
    bumped), ``resolved``, ``repolls`` (scheduled), ``config_changes``."""
    outcome = {"raised": 0, "resolved": 0, "repolls": 0, "config_changes": 0}
    monitoring = _monitoring_enabled()
    alerts_on = monitoring and receiver_flag("syslog_alerts")
    repoll_on = monitoring and receiver_flag("repoll_trigger")
    config_on = receiver_flag("config_change_trigger")
    if not (alerts_on or repoll_on or config_on):
        return outcome
    rules = [r for r in await get_rules() if r.enabled] if alerts_on else []
    actions: list[tuple[bool, Rule, int, str, ParsedSyslog]] = []
    for host_id, message in rows:
        parsed = parse_syslog_message(message)
        now = _clock()
        for rule in rules:
            step = _track(rule, host_id, parsed, now)
            if step is not None:
                actions.append((step[0], rule, host_id, step[1], parsed))
        if repoll_on:
            reason = repoll_reason(parsed)
            if reason:
                delay = RELOAD_REPOLL_DELAY_SECONDS if reason == "reload" else REPOLL_DELAY_SECONDS
                if schedule_repoll(host_id, delay, min_interval=REPOLL_MIN_INTERVAL_SECONDS):
                    outcome["repolls"] += 1
        if config_on and is_config_change(parsed):
            note_config_change(host_id)
            outcome["config_changes"] += 1
    if actions:
        await _apply(actions, outcome)
    return outcome


async def process_recollect_batch(rows: Iterable[tuple[str, int | None, str]]) -> int:
    """Start the OPNsense re-collections received syslog messages ask for:
    ``rows`` of ``(source_ip, host_id or None, message)``, from inventory
    hosts or not (a firewall need not be one). Returns how many runs were
    newly scheduled. Does not need monitoring: it is a topology collection."""
    if not receiver_flag("recollect_trigger"):
        return 0
    events = []
    for source_ip, host_id, message in rows:
        head = message[:_TAG_SEARCH_CHARS].lower()
        if not any(program in head for program in _RECOLLECT_PROGRAMS):
            continue
        reason = recollect_reason(parse_syslog_message(message))
        if reason:
            events.append((source_ip, host_id, reason))
    if not events:
        return 0
    return await source_recollect.schedule_for_events(events)


async def _apply(actions: list[tuple[bool, Rule, int, str, ParsedSyslog]], outcome: dict) -> None:
    hosts = {int(h["id"]): h for h in await db.get_hosts_by_ids(sorted({a[2] for a in actions}))}
    for raise_it, rule, host_id, instance, parsed in actions:
        key = dedup_key(rule.key, host_id, instance)
        if not raise_it:
            # A syslog source can be forged: a clear message resolves only
            # an alert syslog raised for this host, never one polling owns.
            outcome["resolved"] += await db.resolve_monitoring_alerts(key, alert_type=ALERT_TYPE, host_id=host_id)
            continue
        host = hosts.get(host_id)
        if host is None:
            continue
        if await db.is_alert_suppressed(host_id, rule.metric, host.get("group_id")):
            continue
        await db.create_monitoring_alert(
            host_id=host_id,
            poll_id=None,
            alert_type=ALERT_TYPE,
            metric=rule.metric,
            message=alert_message(rule, instance, parsed),
            severity=rule.severity,
            dedup_key=key,
            hostname=host.get("hostname") or "",
        )
        outcome["raised"] += 1


async def resolve_expired_alerts() -> int:
    """Resolve the open syslog alerts of every rule with an
    ``auto_resolve_minutes`` that have not been seen again for that long.
    Called by a periodic loop; returns how many were resolved."""
    resolved = 0
    for rule in await get_rules():
        if rule.auto_resolve_minutes > 0:
            resolved += await db.resolve_stale_monitoring_alerts(
                ALERT_TYPE, rule.metric, rule.auto_resolve_minutes, "auto-resolved (no new syslog match)"
            )
    return resolved


async def resolve_rule_alerts(rule_key: str) -> int:
    """Resolve every open alert of a rule (it was deleted)."""
    return await db.resolve_stale_monitoring_alerts(ALERT_TYPE, metric_name(rule_key), 0, "rule deleted")


async def explain_message(message: str, draft: dict | None = None) -> dict:
    """What the engine would do with ``message``: its parsed tag and text,
    the rules it raises or clears (with the instance) and the triggers it
    starts (``recollect``: why an OPNsense firewall's message would start a
    re-collection of its source, or ""). ``draft``: an unsaved custom rule to test too (``RuleError``
    when invalid)."""
    parsed = parse_syslog_message(message)
    rules = await get_rules()
    draft_result = None
    if draft is not None:
        rule = draft_rule(draft)
        draft_result = _evaluate(rule, parsed) or {"action": "", "instance": ""}
    matches = []
    for rule in rules:
        found = _evaluate(rule, parsed)
        if found:
            matches.append(
                {"key": rule.key, "name": rule.name, "builtin": rule.builtin, "enabled": rule.enabled, **found}
            )
    return {
        "tag": parsed.raw_tag,
        "match_tag": parsed.tag,
        "text": parsed.text,
        "matches": matches,
        "draft": draft_result,
        "config_change": is_config_change(parsed),
        "repoll": repoll_reason(parsed),
        "program": parsed.program,
        "recollect": recollect_reason(parsed),
    }


def evaluate_rule(rule: Rule, parsed: ParsedSyslog) -> dict | None:
    """``{"action": "raise" | "clear", "instance": ...}`` when ``rule``
    raises or clears on the message, else None."""
    instance = rule.raise_match(parsed)
    if instance is not None:
        return {"action": "raise", "instance": instance}
    instance = rule.clear_match(parsed) if rule.clear_match is not None else None
    if instance is not None:
        return {"action": "clear", "instance": instance}
    return None


# The earlier private name (tests use it).
_evaluate = evaluate_rule


# ── Configuration change: backup and drift check ─────────────────────────────

# Keyed by inventory host id, bounded all the same (BoundedDict).
# host_id -> monotonic time its pending run is due.
_config_due: BoundedDict = BoundedDict(COUNTERS_MAX)
# host_id -> monotonic time the first message of its pending run arrived.
_config_first_noted: BoundedDict = BoundedDict(COUNTERS_MAX)
# host_id -> monotonic time its last run started.
_config_last_run: BoundedDict = BoundedDict(COUNTERS_MAX)
_config_tasks: dict[int, asyncio.Task] = {}


def note_config_change(host_id: int) -> None:
    """A configuration change message from ``host_id``: (re)schedule its
    run ``CONFIG_DEBOUNCE_SECONDS`` after this message, but no later than
    ``CONFIG_MAX_DEFER_SECONDS`` after the first message of the pending run
    and not sooner than ``CONFIG_COOLDOWN_SECONDS`` after its last run (the
    per-host cooldown: at most one backup session per host per cooldown).
    One pending run per host: later messages move it, never queue a second
    one."""
    now = _clock()
    last = _config_last_run.get(host_id)
    first = _config_first_noted.get(host_id)
    if first is None or host_id not in _config_due:
        first = now
        _config_first_noted[host_id] = first
    due = min(now + CONFIG_DEBOUNCE_SECONDS, first + CONFIG_MAX_DEFER_SECONDS)
    if last is not None:
        due = max(due, last + CONFIG_COOLDOWN_SECONDS)
    _config_due[host_id] = due
    task = _config_tasks.get(host_id)
    if task is None or task.done():
        _config_tasks[host_id] = keep_task(asyncio.ensure_future(_config_waiter(host_id)))


async def _config_waiter(host_id: int) -> None:
    try:
        while host_id in _config_due:
            wait = _config_due[host_id] - _clock()
            if wait > 0:
                await asyncio.sleep(wait)
                continue
            del _config_due[host_id]
            _config_first_noted.pop(host_id, None)
            _config_last_run[host_id] = _clock()
            try:
                await run_config_change(host_id)
            except Exception as exc:  # noqa: BLE001 - one host's run must not stop the waiter
                LOGGER.warning("syslog rules: config change run for host %s failed: %s", host_id, exc)
    finally:
        _config_tasks.pop(host_id, None)


async def run_config_change(host_id: int) -> dict:
    """Back up ``host_id`` through its group's backup policy (``capture_method``
    ``syslog``), then, when drift checking is on and the host has a
    baseline, store the configuration as a drift snapshot and compare it
    with the baseline. Returns what was done: ``backup`` (``stored``,
    ``unchanged``, ``failed``, ``no_policy``, ``no_host``) and ``drift``
    (the drift result, or None)."""
    from netcontrol.routes import config_backups, config_drift

    outcome: dict = {"host_id": host_id, "backup": "no_host", "drift": None}
    host = await db.get_host(host_id)
    if not host:
        return outcome
    target = await config_backups.host_backup_policy(host)
    if target is None:
        outcome["backup"] = "no_policy"
        LOGGER.info("syslog rules: host %s logged a configuration change but no backup policy covers it", host_id)
        return outcome
    policy, cred = target
    async with state.device_op_semaphore():
        result = await config_backups.backup_host(
            host, cred, policy_id=int(policy["id"]), capture_method=CAPTURE_METHOD
        )
    outcome["backup"] = "stored" if result is True else ("unchanged" if result == "skipped" else "failed")
    if result is False:
        return outcome
    if not state.CONFIG_DRIFT_CHECK_CONFIG.get("enabled") or not await db.get_config_baseline_for_host(host_id):
        return outcome
    config_text = await config_drift._capture_for_drift(host, cred, max_age_seconds=CONFIG_REUSE_SECONDS)
    outcome["drift"] = await config_drift.snapshot_and_analyze(host_id, config_text, capture_method=CAPTURE_METHOD)
    return outcome


def reset_state() -> None:
    """Forget counters, pending runs and the rule cache (tests)."""
    _counters.clear()
    _config_due.clear()
    _config_first_noted.clear()
    _config_last_run.clear()
    invalidate_rules_cache()


# ── Restart: counters and pending configuration runs restored ────────────────

# The threshold counters are rebuilt from the messages of at most this many
# seconds (the longest enabled threshold window, capped) and at most this
# many of the newest messages.
RESTORE_WINDOW_MAX_SECONDS = 3600
RESTORE_ROWS_MAX = 20000
# Yield to the event loop every this many replayed messages.
_RESTORE_YIELD_EVERY = 1000


def _received(value: object) -> datetime | None:
    """A stored ``received_at`` / ``captured_at`` as an aware datetime."""
    from netcontrol.routes.metrics_engine import _parse_db_time

    return _parse_db_time(value)


def _restore_transports() -> tuple[str, ...] | None:
    """The transports whose stored messages a restore replays: all (None),
    or only TCP and TLS while ``syslog_udp_actions`` is off (UDP syslog is
    then stored and never acted on)."""
    if receiver_flag("syslog_udp_actions"):
        return None
    from netcontrol.syslog_stream import TRANSPORTS

    return TRANSPORTS


async def _restore_counters() -> int:
    """Replay the stored messages of inventory hosts through the counters of
    the enabled threshold rules, each counted at its age before now. Raises
    and resolves nothing, schedules nothing. A counter a live message
    already reached takes no older replayed match (``_count`` treats it as
    a repeat), so a race with the receiver can only under-count. Returns
    how many messages were replayed."""
    rules = [r for r in await get_rules() if r.enabled and r.threshold_count > 1]
    if not rules:
        return 0
    window = min(max(r.threshold_window_seconds for r in rules), RESTORE_WINDOW_MAX_SECONDS)
    rows = await db.list_syslog_messages_since(
        window, limit=RESTORE_ROWS_MAX, hosts_only=True, transports=_restore_transports()
    )
    now_utc = datetime.now(UTC)
    now = _clock()
    replayed = 0
    for row in reversed(rows):  # oldest first
        stamp = _received(row["received_at"])
        if stamp is None:
            continue
        at = now - max(0.0, (now_utc - stamp).total_seconds())
        parsed = parse_syslog_message(row["message"] or "")
        for rule in rules:
            _track(rule, int(row["host_id"]), parsed, at)
        replayed += 1
        if replayed % _RESTORE_YIELD_EVERY == 0:
            await asyncio.sleep(0)
    return replayed


async def _restore_config_changes() -> int:
    """Re-arm the configuration-change run of each host whose newest
    configuration message of the last ``CONFIG_COOLDOWN_SECONDS`` has no
    backup captured (or re-read unchanged) at or after it. Returns how many
    runs were scheduled."""
    rows = await db.list_syslog_messages_since(
        int(CONFIG_COOLDOWN_SECONDS), limit=RESTORE_ROWS_MAX, hosts_only=True, transports=_restore_transports()
    )
    newest: dict[int, datetime] = {}
    for row in rows:  # newest first
        host_id = int(row["host_id"])
        if host_id in newest or not is_config_change(parse_syslog_message(row["message"] or "")):
            continue
        stamp = _received(row["received_at"])
        if stamp is not None:
            newest[host_id] = stamp
    armed = 0
    for host_id, stamp in newest.items():
        backup = await db.get_newest_host_config_backup(host_id)
        if backup is not None:
            done = [t for t in (_received(backup.get("captured_at")), _received(backup.get("checked_at"))) if t]
            if done and max(done) >= stamp:
                continue
        note_config_change(host_id)
        armed += 1
    return armed


async def restore_state() -> dict:
    """Rebuild what a restart forgot from the stored messages
    (``trap_syslog_events``): the threshold counters (monitoring on and the
    ``syslog_alerts`` switch on) and the pending configuration-change runs
    (``config_change_trigger`` on). Called once at startup in the process
    whose syslog receiver listens. Raises, resolves and writes nothing;
    never raises (a failure is logged). Returns counts: ``messages``
    replayed, ``counters`` held, ``config_changes`` re-armed."""
    outcome = {"messages": 0, "counters": 0, "config_changes": 0}
    try:
        if _monitoring_enabled() and receiver_flag("syslog_alerts"):
            outcome["messages"] = await _restore_counters()
        if receiver_flag("config_change_trigger"):
            outcome["config_changes"] = await _restore_config_changes()
    except Exception as exc:  # noqa: BLE001 - a failed restore must not block startup
        LOGGER.warning("syslog rules: state restore failed: %s", exc)
    outcome["counters"] = len(_counters)
    if outcome["counters"] or outcome["config_changes"]:
        LOGGER.info(
            "syslog rules: restored %d threshold counters from %d stored messages and %d pending config change runs",
            outcome["counters"],
            outcome["messages"],
            outcome["config_changes"],
        )
    return outcome
