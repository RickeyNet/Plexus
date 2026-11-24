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
  interface going down, a module (line card, supervisor, stack member)
  going down or back online, or a reload / restart
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

The engine has a second message source: the SNMP trap rules
(``netcontrol.trap_rules``, ``docs/snmp-traps.md``) build ``Rule`` objects
with ``source`` ``trap`` and go through the same threshold counters
(``_track``), alert raise / resolve (``apply_actions``), auto-resolve
(``resolve_expired_rule_alerts``), stored overrides (``rule_rows``,
``builtin_override``) and configuration-change trigger
(``note_config_change``). Their alerts are their own family: type
``trap``, metric ``trap_<key>``, dedup key ``trap:<key>:<host>:<instance>``.
A custom trap rule is a row of ``syslog_alert_rules`` with ``source``
``trap`` (``custom_rule`` builds both kinds); ``merge_rules`` here leaves
those rows out. The syslog line of a ``clogMessageGenerated`` trap comes
back here through ``process_syslog_batch``, and the trap restore reuses
``replay_stored``.
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
from typing import Any, Protocol

import routes.database as db
from routes.user_regex import UserRegex, compile_user_regex

import netcontrol.routes.state as state
from netcontrol import source_recollect
from netcontrol.bounded_map import BoundedDict
from netcontrol.monitoring_repoll import keep_task, mark_hardware_stale, schedule_repoll
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

# Re-poll: after an interface-down, module (down or online again) or
# restart message, after a reload message (the device is still up when it
# logs one), and at most once per host in this many seconds.
REPOLL_DELAY_SECONDS = 5.0
RELOAD_REPOLL_DELAY_SECONDS = 30.0
REPOLL_MIN_INTERVAL_SECONDS = 60.0
# Re-poll reasons after which the hardware may have changed: the re-poll
# (or the next poll that reaches the device) reads its hardware components.
HARDWARE_REPOLL_REASONS = frozenset({"module", "reload", "restart"})

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


def _asa_ftd(*ids: int) -> tuple[str, ...]:
    """The tags of Cisco ASA message ids and of the same ids on FTD, which
    logs them as ``%FTD-<level>-<id>`` from release 6.3 (FTD Syslog
    Messages guide)."""
    return tuple(f"{prefix}-{i}" for i in ids for prefix in ("ASA", "FTD"))


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
    # IOS / IOS XE / IOS XR / Arista EOS line protocol, ASA 411002 and FTD
    # 411002 ("Line protocol on Interface inside, changed state to down").
    _m(
        "LINEPROTO-UPDOWN",
        "PKT_INFRA-LINEPROTO-UPDOWN",
        *_asa_ftd(411002),
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
    # AOS-Switch 77: "port 1 is now off-line" (stacked: "port 2/16"). A port
    # disabled in the configuration logs the same message, so it counts too.
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
# AOS-CX 2401 / 2404: "AdjChg: Nbr <router-id> on <interface>[(<area>)]:
# <old state> -> <new state>[ (<event>)]"; the new state is the last one.
_AOSCX_OSPF = ("AOSCX-2401", "AOSCX-2404")
_AOSCX_OSPF_NBR = r"\bNbr (\S+) on "
# AOS-CX 2901 / 2902: "<peer address>: Peer up. vrf-name: <vrf>" / "...:
# Peer down. error-code: ...".
_AOSCX_BGP_PEER = r"^(\S+): Peer (?:up|down)\b"
# AOS-Switch 2703: "ADJCHG: Neighbor with Router ID <id> on <interface>
# moved to <state> state - adj formed" (or "- adj lost").
_AOSS_OSPF_NBR = r"\bRouter ID (\S+) on "
# AOS-Switch 70: "Fan failure: Fan: 1  Failures: 1" (or "Fan OK: ...");
# 71: "Power Supply failure:  Supply: Main- Failures: 1" (Main or RPS);
# 2797: "Internal power supply 2 is faulted. Total fault count: 1" (or "is ok").
_AOSS_FAN = r"\bFan: ([A-Za-z0-9/]+)"
_AOSS_SUPPLY = r"\bSupply: ([A-Za-z0-9/]+)"
_AOSS_INTERNAL_PSU = r"\bInternal power supply (\S+) is\b"
_ARISTA_PSU = r"\b(PowerSupply\d+)"
_ARISTA_FAN = r"\b(Fan\d+(?:/\d+)?)"
_XR_NONOP = r"^(.+?) (?:is Non-Operational|has become operational)\b"
_XR_FAN = r"\bon slot ([^\s,]+), fan (\d+)|^(\S+) FAILED\b"
_XR_FANTRAY = r"\bon slot ([^\s,]+)"
_CAT9K_FAN = r"^Switch (\d+): System fan (\d+)"
# ASA / FTD 735xxx: "Cooling Fan 1: OK", "Power Supply 1: Failure Detected",
# "Power Supply 1: Fan OK", "Power Supply Unit Redundancy Lost".
_ASA_FAN = r"\b(Cooling Fan [^\s:]+):"
_ASA_PSU = r"\b(Power Supply [^\s:]+):"
_ASA_PSU_FAN = r"\b(Power Supply [^\s:]+): Fan\b"
_ASA_PSU_REDUNDANCY = r"\b(Power Supply Unit Redundancy)\b"

# Modules: the slot of an IOS XE card or SPA ("... in slot R1", "... from
# chassis 2 slot 1" on StackWise Virtual: "2/1", "... in subslot 6/0"), an
# NX-OS module, supervisor or fabric module (Xbar) number, a classic stack
# member's switch number and the jnxFruName of a Junos FRU.
_IOSXE_SLOT = r"\b(?:in|from) (?:chassis (\d+) )?(?:sub)?slot ([^\s,]+)"
_NXOS_MODULE = r"\b(?:Module|Supervisor) (\d+)"
_NXOS_XBAR = r"\b(Xbar \d+)"
_C4K_MODULE = r"\bModule (\d+)|\bslot (\d+)"
_ARISTA_CARD = r"\bCard (\S+)"
_JUNOS_FRU_NAME = r"\bjnxFruName ([^,)]+)"
# JUNIPER-MIB jnxFruType of the FRUs that are modules: FPC (3), SFM (4),
# control board (5), routing engine (6), SIB (9), PIC (11), line card
# chassis (14), FEB (15), switch fabric board (19), adapter card (20). Power
# entry modules, fans and power supplies have their own rules.
_JUNOS_MODULE_FRU = r" \([^)]*\bjnxFruType (?:3|4|5|6|9|11|14|15|19|20)\b"

# A module (line card, supervisor, SPA / sub-module, fabric module, stack
# member) that failed, went offline, lost power or was removed: the module
# rule raises on these, and the re-poll trigger acts on them and on
# MODULE_UP.
MODULE_DOWN: tuple[Matcher, ...] = (
    # IOS XE (Catalyst 9400 / 9600 and StackWise Virtual, ASR 1000, ISR
    # 4000), System Message Guide for Catalyst Series Switches 17.3.x:
    # "Card (rp) offline in slot R1", "Card (cc) removed from chassis 2 slot
    # 1". INSCARD (inserted) is no fault.
    _m("IOSXE_OIR-OFFLINECARD", "IOSXE_OIR-REMCARD", instance=_IOSXE_SLOT),
    # SPAs and line card sub-modules: "SPA removed from subslot 6/0,
    # interfaces disabled", "SPA (C9600-LC-48TX) offline in subslot 6/0",
    # "Card removed from subslot 0/1, interfaces disabled". A SPA an
    # operator stops (hw-module subslot ... stop) logs IOSXE_OIR
    # SOFT_STOPSPA instead and is not counted.
    _m("IOSXE_OIR-REMSPA", "SPA_OIR-OFFLINECARD", "SPA_OIR-REMCARD", instance=_IOSXE_SLOT),
    # Catalyst 3750 / 2975 stack (Catalyst 3750 ... 2960 Switch System
    # Message Guide): "Switch 2 has been REMOVED from the stack."
    _m("STACKMGR-SWITCH_REMOVED", instance=r"\bSwitch (\d+) has been removed from the stack\b"),
    # Catalyst 6500 (Cisco TechNote "Line Cards Power Down due to
    # Communication Failures"): "power to module in slot 2 set off (Module
    # Failed SCP dnld)"; the facility names the processor (C6KPWR-SP).
    _m(prefixes=("C6KPWR-",), text=r"\bpower to module in slot \d+ set off\b", instance=r"\bmodule in slot (\d+)"),
    # NX-OS (Nexus 9000 System Messages Reference): "Initialization of
    # module 3 (Serial number: X) failed", "Re-initializing module 3 ...
    # failed", "Module 3 not responding... resetting", "Module 3 removed
    # (Serial number X)", "Module 3 powered down (...)", "Module 3 failed
    # to power up (...)", "... can not be powered up due to insufficient
    # power", "Giving up after multiple attempts were made to bring up the
    # Module 3".
    _m(
        "MODULE-MOD_FAIL",
        "MODULE-MOD_FAILURE",
        "MODULE-MOD_NOT_ALIVE",
        "PLATFORM-MOD_REMOVE",
        "PLATFORM-MOD_PWRDN",
        "PLATFORM-MOD_PWRFAIL",
        "PLATFORM-MOD_PWRFAIL_MULTI",
        "PLATFORM-MOD_PWRDENY",
        "PLATFORM-MOD_BRINGUP_MULTI_LIMIT",
        instance=_NXOS_MODULE,
    ),
    # NX-OS fabric modules: "Xbar 2 removed (...)", "Xbar 2 powered down
    # (...)", "Xbar 2 failed to power up (...)".
    _m("PLATFORM-XBAR_REMOVE", "PLATFORM-XBAR_PWRDN", "PLATFORM-XBAR_PWRFAIL", instance=_NXOS_XBAR),
    # Junos (JUNIPER-MIB jnxFruRemoval, jnxFruPowerOff, jnxFruFailed,
    # jnxFruOffline): "SNMP trap generated: FRU power off (jnxFruContentsIndex
    # 7, ..., jnxFruName FPC: ... @ 0/*/*, jnxFruType 3, jnxFruSlot 0,
    # jnxFruOfflineReason 2, ...)". An operator's power off, CLI command or
    # offline button (jnxFruOfflineReason 5, 7, 8) is not counted.
    _m(
        prefixes=("CHASSISD_SNMP_TRAP",),
        text=r"\bFRU (?:removal|power off|failed|offline)" + _JUNOS_MODULE_FRU,
        exclude=r"\bjnxFruOfflineReason [578]\b",
        instance=_JUNOS_FRU_NAME,
    ),
    # Catalyst 4500 (Catalyst 4500 System Message Guide 15.1(1)SG): "Module 3
    # is removed", "Module 3 is offline", "Module 3 software bring up did not
    # complete within allocated time", "Holding module in slot 3 in reset,
    # due to insufficient power".
    _m(
        "C4K_IOSMODPORTMAN-MODULEREMOVED",
        "C4K_IOSMODPORTMAN-MODULEOFFLINE",
        "C4K_CHASSIS-MODULEBRINGUPTIMEDOUT",
        "C4K_CHASSIS-INSUFFICIENTPOWERSHUTDOWN",
        instance=_C4K_MODULE,
    ),
    # IOS XR (System Error Message Reference 5.1.1, category PLATFORM): "OIR:
    # Node 0/1/CPU0 removed", "Reset node 0/1/CPU0 due to heartbeat loss",
    # "Node 0/1/CPU0 is shutdown due to a critical alarm", "Node ... fails to
    # load IOS XR image ...", "Cannot boot node ... due to multiple resets
    # ...", "Power off node ... due to multiple critical environmental
    # alarms ...".
    _m(
        "PLATFORM-INVMGR-OIROUT",
        "PLATFORM-OIRD-OIROUT",
        "PLATFORM-SHELFMGR-NODE_RESET_BRINGDOWN",
        "PLATFORM-SHELFMGR-SHUTDOWN",
        "PLATFORM-SHELFMGR-FAILED_LOAD",
        "PLATFORM-SHELFMGR-INRESET_BRINGDOWN",
        "PLATFORM-SHELFMGR-SHUTDOWN_ON_ENVMON_ALARM",
        instance=r"\bnode (\S+)",
    ),
    # Arista EOS (EOS System Message Guide 4.12.10): "Linecard3 unexpectedly
    # lost power. ...", "Communication with Linecard3 has been lost. ...",
    # "Card Linecard3 failed to power on in state ...", "Card Linecard3 has
    # been removed. ...", "Hardware failure when reading the card in slot 3".
    # CARD_POWERED_OFF (also an operator's power off) is not counted.
    _m("HARDWARE-CARD_LOST_POWER", instance=r"^(\S+) unexpectedly lost power\b"),
    _m("HARDWARE-CARD_LOST_COMMUNICATION", instance=r"\bCommunication with (\S+) has been lost\b"),
    _m(
        "HARDWARE-CARD_FAIL_TO_POWER_ON",
        "HARDWARE-CARD_FAIL_TO_POWER_ON_FINAL",
        "FRU-CARD_REMOVED",
        instance=_ARISTA_CARD,
    ),
    _m("FRU-CARD_FAILURE", instance=r"\bin slot (\S+)"),
    # FortiOS 22111 "FPC down due to PSU action" (FortiGate 6000 / 7000; the
    # reference gives no msg text, so one alert per chassis).
    _m("FGT-0100022111"),
    # AOS-CX (Event Log Message Reference, Module and VSF events): 3202
    # "<type> module <name> removed", 3207 "<type> module <name> has failed:
    # <reason>", 9913 "Lost member <id> with <reason>".
    _m("AOSCX-3202", "AOSCX-3207", instance=r"\bmodule (\S+) (?:removed|has failed)\b"),
    _m("AOSCX-9913", instance=r"\bLost member (\S+)"),
    # AOS-Switch 402 "Stack member <id> lost." (Fault events).
    _m("AOSS-00402", instance=r"\bStack member (\S+) lost\b"),
)
# The same module online again: clears the module rule, and re-polls.
MODULE_UP: tuple[Matcher, ...] = (
    # IOS XE: "Card (cc) online in slot 1", "SPA (C9600-LC-24C) online in
    # subslot 1/0".
    _m("IOSXE_OIR-ONLINECARD", "SPA_OIR-ONLINECARD", instance=_IOSXE_SLOT),
    # Catalyst 3750 / 2975 stack: "Switch 2 is READY."
    _m("STACKMGR-SWITCH_READY", instance=r"\bSwitch (\d+) is ready\b"),
    # NX-OS: "Module 3 is online (Serial number: X)", "Supervisor 2 is
    # standby", "Supervisor 1 is active (...)", "Xbar 2 is online (...)".
    _m("MODULE-MOD_OK", "MODULE-ACTIVE_SUP_OK", "MODULE-STANDBY_SUP_OK", instance=_NXOS_MODULE),
    _m("MODULE-XBAR_OK", instance=_NXOS_XBAR),
    # Junos jnxFruOnline: "SNMP trap generated: FRU online (...)".
    _m(prefixes=("CHASSISD_SNMP_TRAP",), text=r"\bFRU online" + _JUNOS_MODULE_FRU, instance=_JUNOS_FRU_NAME),
    # Catalyst 4500: "Module 3 (<model> S/N:<serial> Hw:1.0) is online".
    _m("C4K_IOSMODPORTMAN-MODULEONLINE", instance=_C4K_MODULE),
    # Arista EOS: "Card Linecard3 has been powered on. model: ...".
    _m("HARDWARE-CARD_POWERED_ON", instance=_ARISTA_CARD),
    # FortiOS 22112 "FPC up due to PSU action" (LOG_ID_PSU_ACTION_FPC_UP).
    _m("FGT-0100022112"),
)


# ASA / FTD environment (735xxx): "CPU 0: Temp: 80 C, Critical", "Chassis
# Ambient 1: Temp: 45 C, Warm", "Power Supply 1: Temp: ...", "IO Hub 0:
# Temp: ..." (FTD may write "IPMI: " first).
_ASA_TEMP_SENSOR = r"\b((?:CPU|Chassis Ambient|Power Supply|IO Hub) [^\s:]+): Temp:"
_C4K_MODULE_SENSOR = r"^Module (\d+) Sensor (.+?) temperature\b"
_ARISTA_HOT = r"^(.+?) (?:is overheating|temperature critical)\b"
_ARISTA_COOL = r"^(.+?) temperature has returned to normal\b"
_IOSXE_SENSOR = r"^Temp:\s*(.+?),?\s+Location:\s*([^,\s]+)"
_ENVMON_HOT = r"^(?:Warning|Critical): (.+?) temperature \d"
_ENVMON_COOL = r"^(.+?) temperature normal\b"
_NXOS_TEMP = r"^(.+?) (?:reported|recovered from|powered down due to) .*?\bSensor[= ](\d+)"
_XR_SLOT_TEMP = r"^Slot (\S+) temperature\b"
_MLAG = r"^(MLAG)\b"
_JSRPD_LINK = r"^HA (control link|fabric link)\b"

# A temperature sensor over its warning or critical threshold, a thermal
# shutdown, or (where documented) an under-temperature alarm.
TEMPERATURE_HIGH: tuple[Matcher, ...] = (
    # IOS XE (System Message Guide for Catalyst Series Switches 17.3.x and
    # 16.12.x; ASR 1000 / ISR 4000 TechNotes): "Temp: Inlet 1, Location: R0,
    # State: Critical, Reading: 60 Celsius". The same mnemonic reports
    # voltage and fan sensors ("V: ...", "RPM: ..."): only Temp counts.
    _m("ENVIRONMENTAL-ALERT", text=r"^Temp:", instance=_IOSXE_SENSOR),
    # "Critical limit reached for PVT temperature sensor on Asic: 0 ...".
    _m("ENVIRONMENTAL-ALERT", text=r"\bPVT temperature sensor\b", instance=r"\bon (Asic): ?(\d+)"),
    # "Sensor <name> has reached maximum temperature value ...".
    _m("IOSXE_PEM-TEMPERATURE_RAISE", instance=r"^Sensor (\S+)"),
    # Catalyst 9000: "Switch 2: <text>".
    _m(
        "PLATFORM_THERMAL-OVERTEMP",
        "PLATFORM_THERMAL-SECONDARY_OVERTEMP",
        "PLATFORM_THERMAL-OVERTEMP_SHUTDOWN",
        "PLATFORM_THERMAL-UNDERTEMP",
        "PLATFORM_THERMAL-UNDERTEMP_SHUTDOWN",
        instance=r"^Switch (\d+):",
    ),
    # Classic Catalyst 2960 / 3560 / 3750 (System Message Guide 15.2(6)E2):
    # "Temperature has reached warning / critical threshold", "PSU <name>
    # temperature has reached ... threshold", "Abnormal temperature detected".
    _m(
        "HARDWARE-THERMAL_WARNING",
        "HARDWARE-THERMAL_CRITICAL",
        "PLATFORM_ENV-TEMP",
        "PLATFORM_ENV-THERMAL_WARNING",
        "PLATFORM_ENV-THERMAL_CRITICAL",
    ),
    _m("HARDWARE-PSU_THERMAL_WARNING", "HARDWARE-PSU_THERMAL_CRITICAL", instance=r"^PSU (\S+)"),
    # ENVMON (Catalyst guide 17.3.x, CGS 2520 and 3900 components): "Warning:
    # CPU temperature 80C exceeds threshold 75C. ...", "Warning: Inlet
    # Temperature 50C Exceeds 45C. ...".
    _m(
        "ENVMON-CPU_WARNING_OVERTEMP",
        "ENVMON-CPU_CRITICAL_OVERTEMP",
        "ENVMON-IN_OUTLET_OVERTEMP",
        "ENVMON-INTAKE_ABNORMTEMP",
        "ENVMON-ONBOARD_OVERTEMP",
        "ENVMON-MODULE_OVERTEMP",
        "ENVMON-POWER_OVERTEMP",
        instance=_ENVMON_HOT,
    ),
    # Catalyst 4500 (System Message Guide 15.1(1)SG).
    _m("C4K_IOSMODPORTMAN-TEMPHIGH", "C4K_IOSMODPORTMAN-CRITICALTEMP", instance=r"^(Chassis) temperature\b"),
    _m(
        "C4K_IOSMODPORTMAN-MODULETEMPHIGH",
        "C4K_IOSMODPORTMAN-MODULECRITICALTEMP",
        "C4K_IOSMODPORTMAN-MODULESHUTDOWNTEMP",
        instance=_C4K_MODULE_SENSOR,
    ),
    _m("C4K_CHASSIS-OVERHEATINGSHUTDOWN"),
    # NX-OS (Nexus 9000 System Messages Reference 10.6(2)F): "Module 1
    # reported Major temperature alarm. Sensor=3 Temperature=80
    # MajThreshold=75", "... powered down due to major temperature alarm for
    # Sensor 3.", "System shutdown in 120 seconds due to major temperature
    # alarm".
    _m(
        "PLATFORM-MOD_TEMPMAJALRM",
        "PLATFORM-MOD_TEMPMINALRM",
        "PLATFORM-MOD_TEMPWARMALRM",
        "PLATFORM-MOD_TEMPSHUTDOWN",
        instance=_NXOS_TEMP,
    ),
    _m("PLATFORM-SYS_SHUTDOWN", text=r"\btemperature alarm\b"),
    # IOS XR (System Error Message Reference 5.1.1, %PLATFORM-ENVMON-...):
    # "Chassis ambient temperature 45.0C at or above rising T3 threshold
    # ...", "Slot 0/1/CPU0 temperature 80.0C at or above rising T4 threshold
    # ...", and the shutdown (STT) forms.
    _m(
        "PLATFORM-ENVMON-CHASSIS_OVERTEMP",
        "PLATFORM-ENVMON-CHASSIS_OVERTEMP_SHUTDOWN",
        instance=r"^(Chassis) ambient temperature\b",
    ),
    _m("PLATFORM-ENVMON-CARD_OVERTEMP", "PLATFORM-ENVMON-CARD_OVERTEMP_SHUTDOWN", instance=_XR_SLOT_TEMP),
    # ASA / FTD (ASA Series Syslog Messages, FTD Syslog Messages): Critical
    # and Warm, and the thermal shutdowns (no sensor named).
    _m(*_asa_ftd(735007, 735008, 735015, 735016, 735018, 735019), instance=_ASA_TEMP_SENSOR),
    _m(*_asa_ftd(735022, 735024, 735027, 735029)),
    # Arista EOS (EOS System Message Guide 4.12.10): "Linecard3 is
    # overheating", "... temperature critical and is being shutdown", "The
    # system is overheating", "System temperature critical ...".
    _m(
        "ENVMON-CARDOVERHEATWARNING",
        "ENVMON-CARDOVERHEATSHUTDOWN",
        "ENVMON-POWERSUPPLY_OVERHEAT_WARNING",
        "ENVMON-POWERSUPPLY_OVERHEAT_CRITICAL",
        instance=_ARISTA_HOT,
    ),
    _m("ENVMON-SYSTEMOVERHEATWARNING", "ENVMON-SYSTEMOVERHEATSHUTDOWN"),
    # Junos (System Log Explorer): chassis-wide over-temperature and
    # shutdown, a FRU or Routing Engine over its limit.
    _m(
        "CHASSISD_OVER_TEMP_CONDITION",
        "CHASSISD_OVER_TEMP_SHUTDOWN_TIME",
        "CHASSISD_HIGH_TEMP_CONDITION",
        "CHASSISD_CHASSIS_FIRE_TEMP",
    ),
    _m("CHASSISD_TEMP_HOT_NOTICE", instance=r"^(.+?) temperature of "),
    _m(
        "CHASSISD_FRU_HIGH_TEMP_CONDITION",
        "CHASSISD_FRU_OVER_TEMP_CONDITION",
        instance=r"^(.+?) temperature \S+ over ",
    ),
    _m("CHASSISD_FRU_SENSOR_TEMP_WARNING", instance=r":\s*(.+?) temperature sensor (\S+)"),
    _m(
        "CHASSISD_RE_WARM_TEMP_CONDITION",
        "CHASSISD_RE_OVER_TEMP_CONDITION",
        "CHASSISD_RE_OVER_TEMP_WARNING",
        "CHASSISD_RE_OVER_TEMP_SHUTDOWN",
        instance=r"^(Routing Engine \S+) temperature\b",
    ),
    # Junos jnxOverTemperature as chassisd logs it: "SNMP trap generated:
    # Over Temperature! (..., jnxContentsDescr Routing Engine, ...)".
    _m(prefixes=("CHASSISD_SNMP_TRAP",), text=r"\bOver Temperature\b", instance=_JUNOS_FRU),
    # FortiOS 22109 "Temperature too high", 22152 "Temperature too low" (the
    # reference gives no msg text: one alert per firewall).
    _m("FGT-0100022109", "FGT-0100022152"),
    # AOS-CX 803: "Over-temperature for sensor <name>, <temp> degC".
    _m("AOSCX-803", instance=r"\bsensor ([^\s,]+)"),
    # AOS-Switch 424 (16.10): "Over-temperature detected ...". The id
    # differs by release, so the text is checked too.
    _m("AOSS-00424", text=r"\bOver-temperature detected\b"),
)
# The same sensor back to normal: clears the temperature rule.
TEMPERATURE_OK: tuple[Matcher, ...] = (
    # "Temp: Inlet 1, Location: R0, State: normal".
    _m("ENVIRONMENTAL-SENSOROK", text=r"^Temp:", instance=_IOSXE_SENSOR),
    _m("PLATFORM_THERMAL-TEMP_NORMAL", instance=r"^Switch (\d+):"),
    _m("HARDWARE-THERMAL_NORMAL"),
    _m("HARDWARE-PSU_THERMAL_NORMAL", instance=r"^PSU (\S+)"),
    # "CPU temperature normal", "Inlet temperature normal".
    _m(
        "ENVMON-CPU_TEMP_OK",
        "ENVMON-IN_OUTLET_TEMP_OK",
        "ENVMON-ONBOARD_TEMP_OK",
        "ENVMON-MODULE_TEMP_OK",
        "ENVMON-POWER_TEMP_OK",
        instance=_ENVMON_COOL,
    ),
    _m("C4K_IOSMODPORTMAN-TEMPOK", instance=r"^(Chassis) temperature\b"),
    _m("C4K_IOSMODPORTMAN-MODULETEMPOK", instance=_C4K_MODULE_SENSOR),
    _m("C4K_CHASSIS-OVERHEATINGOVER"),
    # NX-OS: "Module 1 recovered from minor / major temperature alarm.
    # Sensor=3 ..." (not MOD_TEMPRECOVER: a minor alarm is still pending).
    _m("PLATFORM-MOD_TEMPOK", "PLATFORM-MOD_TEMPMAJOR_OK", instance=_NXOS_TEMP),
    # IOS XR: "... returned below falling T3 / T4 threshold ...".
    _m("PLATFORM-ENVMON-CHASSIS_OVERTEMP_CLEAR", instance=r"^(Chassis) ambient temperature\b"),
    _m("PLATFORM-ENVMON-CARD_OVERTEMP_CLEAR", instance=_XR_SLOT_TEMP),
    # ASA / FTD: "CPU 0: Temp: 50 C, OK" and the chassis, power supply and
    # IO hub forms.
    _m(*_asa_ftd(735017, 735020, 735021, 735026), instance=_ASA_TEMP_SENSOR),
    # Arista EOS: "Linecard3 temperature has returned to normal", "System
    # temperature has returned to normal".
    _m("ENVMON-CARDTEMPNORMAL", "ENVMON-POWERSUPPLY_TEMP_NORMAL", instance=_ARISTA_COOL),
    _m("ENVMON-SYSTEMTEMPNORMAL"),
    # Junos jnxTemperatureOK: "SNMP trap generated: Temperature back to
    # normal (...)".
    _m(prefixes=("CHASSISD_SNMP_TRAP",), text=r"\bTemperature back to normal\b", instance=_JUNOS_FRU),
    # FortiOS 22153 "Temperature normal".
    _m("FGT-0100022153"),
)

# A redundancy switchover, failover, new stack master / commander, or the
# loss of an HA peer, member, heartbeat or failover link. Most name no
# instance (one alert per device; the rule resolves by time); a failover
# link that has a documented up message names itself.
HA_SWITCHOVER: tuple[Matcher, ...] = (
    # IOS XE (Catalyst guide 17.3.x / 16.12.x): "RP switchover <reason>",
    # "Standby processor fault <reason>"; Catalyst 4500 "Switchover activity
    # detected changing role from STANDBY to ACTIVE".
    _m("REDUNDANCY-SWITCHOVER", "REDUNDANCY-STANDBY_LOST", "C4K_REDUNDANCY-SWITCHOVER"),
    # Classic Catalyst 3750 stack: "Switch 1 has been elected as MASTER of the stack".
    _m("STACKMGR-MASTER_ELECTED", instance=r"^Switch (\d+) has been elected\b"),
    # NX-OS (Nexus 9000 System Messages Reference 10.6(2)F and 9.3(10)).
    _m(
        "SYSMGR-HASWITCHOVER_PRE_START",
        "SYSMGR-HASWITCHOVER_START",
        "SYSMGR-WARMSWITCHOVER_START",
        "SYSMGR-SWITCHOVER_OVER",
        "SYSMGR-SWITCHOVER_THRESHOLD_EXCEEDED",
        "SYSMGR-STANDBY_BOOT_FAILED",
        "SYSMGR-REDUNDANCY_HEARTBEAT_FAILURE",
    ),
    # IOS XR (System Error Message Reference 5.1.1): "this card going
    # active", "connection to standby card is DOWN", "Card is becoming
    # active.", "Detected role change to ACTIVE state due to ...".
    _m("HA-REDCON-GO_ACTIVE", "HA-REDCON-STANDBY_CONNECTION_DOWN", "PLATFORM-REDDRV-GO_ACTIVE"),
    _m("PLATFORM-REDDRV-ROLE_CHANGE", text=r"\brole change to active\b"),
    # ASA / FTD failover: this unit switching to active, standby or failed
    # (104001 to 104003, cloud HA 104500 / 104501), no response from or
    # failed by the mate (103001, 103004), failover communication lost on an
    # interface (105005), failover cable or LAN failover link down (105011,
    # 105032, 105043) and both units switching back and forth (105037).
    _m(*_asa_ftd(104001, 104002, 104003, 104500, 104501, 103001, 103004, 105005, 105011, 105032, 105043, 105037)),
    # Arista EOS supervisor redundancy (EOS System Message Guide 4.12.10).
    _m(
        "REDUNDANCY-SWITCHOVER_START",
        "REDUNDANCY-SWITCHOVER_COMPLETE",
        "REDUNDANCY-IS_DISABLED",
        "REDUNDANCY-OTHER_DISABLED",
    ),
    # Arista MLAG inactive or failed over: "MLAG is inactive with peer ...",
    # "MLAG failed over to (or remained at) the primary state because the
    # peer link ... is down", "MLAG stopped receiving heartbeats ...".
    _m(
        "MLAG-STATE_INACTIVE_CONNECTION_CLOSED",
        "MLAG-STATE_INACTIVE_HEARTBEAT_TIMEOUT",
        "MLAG-STATE_INACTIVE_LOCAL_INTERFACE_DOWN",
        "MLAG-STATE_PRIMARY_PEER_LINK_DOWN",
        "MLAG-PEER_EVENT_HEARTBEAT_TIMEOUT",
        instance=_MLAG,
    ),
    # Junos (System Log Explorer): Routing Engine mastership, SRX chassis
    # cluster redundancy group and node changes, Multinode HA, the cluster
    # control and fabric links, split brain.
    _m("CHASSISD_LOST_MASTERSHIP", "UI_MASTERSHIP_EVENT", "JSRPD_SPLIT_BRAIN"),
    _m("JSRPD_RG_STATE_CHANGE", instance=r"^(Redundancy-group \S+)"),
    _m("JSRPD_HA_SRG_STATE_CHANGE", instance=r"^(SRG\[[^\]]*\])"),
    _m("JSRPD_HA_CONTROL_LINK_DOWN", "JSRPD_HA_FAB_LINK_DOWN", instance=_JSRPD_LINK),
    # FortiOS HA (logid 0108...): 37892 "Virtual cluster member state
    # moved", 37893 "Virtual cluster member dead", 37898 "HA device
    # interface failed", 37901 "Heartbeat device interface down", 35013 "HA
    # failover failed", 35016 "HA failover success".
    _m("FGT-0108037892", "FGT-0108037893", "FGT-0108037898", "FGT-0108037901", "FGT-0108035013", "FGT-0108035016"),
    # PAN-OS HA state change: "HA Group 1: Moved from state Active to state
    # Non-Functional" (Palo Alto knowledge base example).
    _m("PAN-SYSTEM-STATE-CHANGE", text=r"^HA Group \d+: Moved from state ", instance=r"^(HA Group \d+):"),
    # AOS-CX VSX: 7001 "VSX ISL port <port> is down", 7005 "VSX Keepalive
    # failed".
    _m("AOSCX-7001", "AOSCX-7005", instance=r"^(VSX (?:ISL|Keepalive))\b"),
    # AOS-Switch stacking 3278: "Member <id> elected as commander. Reason: ...".
    _m("AOSS-03278", text=r"\belected as commander\b"),
)
# The documented recoveries of a link or peer that names itself.
HA_RESTORED: tuple[Matcher, ...] = (
    # Arista: "MLAG is active as primary / secondary with peer ...", "MLAG
    # connection restored with peer ...".
    _m("MLAG-STATE_PRIMARY", "MLAG-STATE_SECONDARY", "MLAG-STATE_PRIMARY_PEER_LINK_UP", instance=_MLAG),
    # Junos: "HA control link monitor status is marked up", "HA fabric link is UP".
    _m("JSRPD_HA_CONTROL_LINK_UP", "JSRPD_HA_FAB_LINK_UP", instance=_JSRPD_LINK),
)

# Messages a device logs when it is about to reload: the re-poll trigger
# (``repoll_reason`` ``reload``) and the device_restart rule.
RELOAD: tuple[Matcher, ...] = (
    _m("SYS-RELOAD", "UI_REBOOT_EVENT", "PLATFORM-PFM_SYSTEM_RESET", *_asa_ftd(199001)),
    # FortiOS 32138 "Device rebooted", 32200 "Device shutdown", 32545
    # "Scheduled daily reboot started"; AOS-Switch 63 "SYSTEM went down:
    # <reason>"; AOS-CX 706 "Initiating system reboot", 707 "Initiating
    # chassis thermal reboot".
    _m("FGT-0100032138", "FGT-0100032200", "FGT-0100032545", "AOSS-00063", "AOSCX-706", "AOSCX-707"),
    # IOS XR (category INSTALL): "Install manager is about to request a
    # router reload to complete the install operation".
    _m("INSTALL-INSTMGR-CALLING_PLATFORM_RELOAD_NODES_ALL"),
)
# Messages a device logs once it is back up: the re-poll trigger
# (``restart``) and the device_restart rule.
RESTART: tuple[Matcher, ...] = (
    _m("SYS-RESTART", "SYS-BOOTTIME", "SNMPD_TRAP_COLD_START", "SNMPD_TRAP_WARM_START", *_asa_ftd(199002)),
    # FortiOS 32009 "FortiGate started"; AOS-Switch 66 "System Booted" and
    # 64 (the crash reason of a switch that went down); AOS-CX 1206 "Module
    # rebooted. Reason: ...", 1236 "Module unexpected reboot. Reason: ...".
    _m("FGT-0100032009", "AOSS-00066", "AOSS-00064", "AOSCX-1206", "AOSCX-1236"),
    # Arista EOS (EOS System Message Guide 4.12.10): "System restarted",
    # "Reboot due to kernel panic", "Reboot due to system watchdog".
    _m("SYS-SYSTEM_RESTARTED", "SYS-KERNEL_PANIC", "HARDWARE-WATCHDOG_ERROR"),
    # IOS XR: "System cold start detected. Resetting Line Cards."
    _m("PLATFORM-SHELFMGR-SYSTEM_COLD_START"),
)

# ── Event rule packs: layer 2, routing and tunnel neighbors, device health ───
#
# Message forms from the Cisco System Message Guide for Catalyst Series
# Switches (IOS XE 17.3.x) unless a comment names another source; the
# sample texts are those of the Cisco documents named in
# docs/syslog-rules.md "Event rule packs". The rules are appended to
# BUILTIN_RULES after the rules above.

_CISCO_FAMILIES = ("Cisco IOS / IOS XE",)
# STP: "Root Changed for vlan 10: New Root Port is ..." (Catalyst 3750 ...
# 2960 Switch System Message Guide), "Topology Change Trap for vlan 10".
_STP_VLAN = r"\bfor (\S+ \d+)"
# Root guard / loop guard: "Root guard blocking port Gi1/0/1 on VLAN0010."
# and "... unblocking port ... on ...".
_STP_GUARD_PORT = r"\b(?:un)?blocking port (\S+) on ([^\s.]+)"
# Cisco TechNote "Errdisable Port State Recovery": "bpduguard error detected
# on Gi4/1, putting Gi4/1 in err-disable state" (the -SP- facility on a
# Catalyst 6500 supervisor); the _VP form adds "vlan <n>".
_ERR_DISABLED_PORT = r"\berror detected on ([^\s,]+)(?: vlan (\d+))?"
# HSRP (Cisco TechNote "Understand and Troubleshoot HSRP Problems"): "Vlan10
# Grp 110 state Standby -> Active", older "Standby: 49: Vlan149 state Active
# -> Speak" (the interface first in both instances).
_HSRP_ACTIVE_CHANGE = r"\bstate (?:Active ?-> ?\w+|\w+ ?-> ?Active)\b"
# EIGRP (Cisco TechNote 118974, NX-OS EIGRP-5-NBRCHANGE_DUAL): "IP-EIGRP(0)
# 1: Neighbor 192.0.2.1 (Ethernet0/0) is down: holding time expired".
_EIGRP_NBR = r"\bNeighbor (\S+) \("
# IS-IS (Cisco "Troubleshoot IS-IS Adjacency Issues"): "ISIS: Adjacency to
# DeviceB (TenGigabitEthernet0/0/4) Down, hold time expired"; NX-OS
# (System Routing Messages Reference) "<process> adj L<level> <neighbor>
# over <interface> - <state> on MT-<n>".
_ISIS_NBR = r"\bAdjacency to (\S+) \(([^)]+)\)"
_NXOS_ISIS_NBR = r"\badj L\S* (\S+) over (\S+)"
# Cisco "IP Security VPN Monitoring": "Crypto session is DOWN. Peer
# 192.0.2.1:500 fvrf=... Id: ..." (also "Crypto tunnel is UP. ...").
_CRYPTO_PEER = r"\bPeer (\S+)"
# Enhanced object tracking of an IP SLA operation: "100 ip sla 100
# reachability Up -> Down" (or "state"), sample from the ipSpace.net
# reliable static routing article.
_TRACK_SLA = r"^(\d+ ip sla \d+) (?:state|reachability) "
_ILPOWER_PORT = r"\bInterface ([^\s:,]+)"
_RADIUS_SERVER = r"\bRADIUS server (\S+)"

_LAYER2_RULES: tuple[BuiltinRule, ...] = (
    BuiltinRule(
        key="stp_root_change",
        name="Spanning tree root changed",
        description="The spanning tree root of a VLAN or instance changed; resolves 60 minutes after the last change.",
        families=_CISCO_FAMILIES,
        severity="warning",
        raise_on=(_m("SPANTREE-ROOTCHANGE", instance=_STP_VLAN),),
        auto_resolve_minutes=60,
    ),
    BuiltinRule(
        key="stp_topology_change",
        name="Spanning tree topology changes",
        description=(
            "5 spanning tree topology changes in one VLAN or instance within 10 minutes; resolves 30 minutes "
            "after the last one."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        raise_on=(_m("SPANTREE-TOPOTRAP", instance=_STP_VLAN),),
        threshold_count=5,
        threshold_window_seconds=600,
        auto_resolve_minutes=30,
    ),
    BuiltinRule(
        key="stp_guard",
        name="Spanning tree guard blocking a port",
        description=(
            "Root guard, loop guard or Bridge Assurance put a port in blocking state; resolved when it unblocks "
            "the port, or after 24 hours."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        raise_on=(
            _m("SPANTREE-ROOTGUARD_BLOCK", "SPANTREE-LOOPGUARD_BLOCK", instance=_STP_GUARD_PORT),
            _m("SPANTREE-BRIDGE_ASSURANCE_BLOCK", instance=r"\bblocking port ([^\s.,]+)"),
        ),
        clear_on=(
            _m("SPANTREE-ROOTGUARD_UNBLOCK", "SPANTREE-LOOPGUARD_UNBLOCK", instance=_STP_GUARD_PORT),
            _m("SPANTREE-BRIDGE_ASSURANCE_UNBLOCK", instance=r"\bunblocking port ([^\s.,]+)"),
        ),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="port_err_disabled",
        name="Port error-disabled",
        description=(
            "A port was put in err-disable state (BPDU guard, UDLD, port security, storm control, link flap, "
            "loopback ...); resolves 24 hours after the last err-disable message."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        # PM-4-ERR_RECOVER only says a recovery is attempted: a port that
        # fails again logs ERR_DISABLE again and keeps the alert open.
        raise_on=(_m("PM-ERR_DISABLE", "PM-SP-ERR_DISABLE", "PM-ERR_DISABLE_VP", instance=_ERR_DISABLED_PORT),),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="port_security",
        name="Port security violation",
        description="An unknown MAC address reached a secure port; resolves 60 minutes after the last violation.",
        families=_CISCO_FAMILIES,
        severity="warning",
        # "Security violation occurred, caused by MAC address <mac> on port
        # <interface>." (Cisco Community log samples; the guide gives the
        # mnemonic and says the message names the MAC address and port).
        raise_on=(
            _m(
                "PORT_SECURITY-PSECURE_VIOLATION",
                "PORT_SECURITY-PSECURE_VIOLATION_VLAN",
                instance=r"\bon port ([^\s,]+)",
            ),
        ),
        auto_resolve_minutes=60,
    ),
    BuiltinRule(
        key="storm_control",
        name="Traffic storm",
        description=(
            "Storm control filtered a traffic storm on a port or shut the port down; resolved when the storm "
            "abates, or after 24 hours."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        # "A broadcast storm detected on Gi1/0/1. A packet filter action has
        # been applied ...", "A packet storm was detected on Gi1/0/1. The
        # interface has been disabled.", "Storm control shut down Gi1/0/1".
        raise_on=(
            _m("STORM_CONTROL-FILTERED", instance=r"\bstorm detected on (\S+)"),
            _m("STORM_CONTROL-SHUTDOWN", instance=r"\b(?:storm was detected on|shut down) (\S+)"),
        ),
        clear_on=(_m("STORM_CONTROL-ABATED", instance=r"\bstorm abated on (\S+)"),),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="mac_flap",
        name="MAC address flapping",
        description=(
            "Hosts in one VLAN moved between ports 3 times within 10 minutes (a loop or a misconfigured "
            "channel); resolves 30 minutes after the last move."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        # Cisco "Troubleshoot MAC Address Flap Notifications": "Host
        # 0011.2233.4455 in vlan 10 is flapping between port Gi1/0/10 and
        # port Po1."
        raise_on=(_m("SW_MATM-MACFLAP_NOTIF", instance=r"\bin (vlan \d+) is flapping\b"),),
        threshold_count=3,
        threshold_window_seconds=600,
        auto_resolve_minutes=30,
    ),
    BuiltinRule(
        key="duplex_mismatch",
        name="Duplex mismatch",
        description=(
            "CDP found a duplex mismatch with the neighbor on a port; resolves 60 minutes after the last report "
            "(CDP repeats it while the mismatch lasts)."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        # "duplex mismatch discovered on Gi1/0/1 (not full duplex), with ..."
        raise_on=(_m("CDP-DUPLEX_MISMATCH", instance=r"\bdiscovered on ([^\s,]+)"),),
        auto_resolve_minutes=60,
    ),
)

_NEIGHBOR_RULES: tuple[BuiltinRule, ...] = (
    BuiltinRule(
        key="hsrp_state",
        name="HSRP failover",
        description=(
            "An HSRP group became active on this router or left the active state; resolves 60 minutes after "
            "the last change."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        raise_on=(
            _m("HSRP-STATECHANGE", text=_HSRP_ACTIVE_CHANGE, instance=r"^(\S+) Grp (\d+)"),
            _m("STANDBY-STATECHANGE", text=_HSRP_ACTIVE_CHANGE, instance=r"^Standby: (?=\d+: (\S+))(\d+):"),
        ),
        auto_resolve_minutes=60,
    ),
    BuiltinRule(
        key="eigrp_neighbor",
        name="EIGRP neighbor down",
        description="An EIGRP neighbor went down; resolved when it is up again.",
        families=(*_CISCO_FAMILIES, "Cisco NX-OS"),
        severity="critical",
        raise_on=(_m("DUAL-NBRCHANGE", "EIGRP-NBRCHANGE_DUAL", text=r"\) is down\b", instance=_EIGRP_NBR),),
        clear_on=(_m("DUAL-NBRCHANGE", "EIGRP-NBRCHANGE_DUAL", text=r"\) is up\b", instance=_EIGRP_NBR),),
    ),
    BuiltinRule(
        key="isis_adjacency",
        name="IS-IS adjacency down",
        description="An IS-IS adjacency went down; resolved when it is up again.",
        families=(*_CISCO_FAMILIES, "Cisco NX-OS"),
        severity="critical",
        raise_on=(
            _m("CLNS-ADJCHANGE", text=r"\) Down\b", instance=_ISIS_NBR),
            _m("ISIS-ADJCHANGE", text=r"\bover \S+ - Down\b", instance=_NXOS_ISIS_NBR),
        ),
        clear_on=(
            _m("CLNS-ADJCHANGE", text=r"\) Up\b", instance=_ISIS_NBR),
            _m("ISIS-ADJCHANGE", text=r"\bover \S+ - Up\b", instance=_NXOS_ISIS_NBR),
        ),
    ),
    BuiltinRule(
        key="ipsec_tunnel",
        name="IPsec tunnel down",
        description="An IPsec (crypto) session to a peer went down; resolved when it is up again.",
        families=_CISCO_FAMILIES,
        severity="critical",
        raise_on=(_m("CRYPTO-SESSION_STATUS", text=r"\bCrypto (?:session|tunnel) is DOWN\b", instance=_CRYPTO_PEER),),
        clear_on=(_m("CRYPTO-SESSION_STATUS", text=r"\bCrypto (?:session|tunnel) is UP\b", instance=_CRYPTO_PEER),),
    ),
    BuiltinRule(
        key="ip_sla",
        name="IP SLA probe down",
        description="A tracked IP SLA operation went down; resolved when it is up again.",
        families=_CISCO_FAMILIES,
        severity="warning",
        raise_on=(_m("TRACK-STATE", text=_TRACK_SLA + r"Up ?-> ?Down\b", instance=_TRACK_SLA),),
        clear_on=(_m("TRACK-STATE", text=_TRACK_SLA + r"Down ?-> ?Up\b", instance=_TRACK_SLA),),
    ),
)

_HEALTH_RULES: tuple[BuiltinRule, ...] = (
    BuiltinRule(
        key="poe_fault",
        name="PoE fault",
        description=(
            "A PoE port reported a controller fault, was denied power, drew more than its maximum or was shut "
            "down for it; resolved when the port is granted power again, or after 24 hours."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        raise_on=(
            _m(
                "ILPOWER-CONTROLLER_PORT_ERR",
                "ILPOWER-ILPOWER_POWER_DENY",
                "ILPOWER-INVALID_IEEE_CLASS",
                "ILPOWER-LOG_OVERDRAWN",
                "ILPOWER-SHUT_OVERDRAWN",
                instance=_ILPOWER_PORT,
            ),
        ),
        clear_on=(_m("ILPOWER-POWER_GRANTED", "ILPOWER-CLR_OVERDRAWN", instance=_ILPOWER_PORT),),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="optic_power",
        name="Optic light level out of range",
        description=(
            "A transceiver's receive or transmit power crossed its low or high warning or alarm threshold; "
            "resolves 24 hours after the last crossing."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        # "Te1/4/1: Rx power low alarm; Operating value: -40.0 dBm, Threshold
        # value: -18.4 dBm." (Cisco Community samples; temperature, voltage
        # and bias current crossings of the same message are not counted).
        raise_on=(
            _m(
                "SFF8472-THRESHOLD_VIOLATION",
                text=r"\b[RT]x power (?:high|low) (?:alarm|warning)\b",
                instance=r"^([^\s:]+):",
            ),
        ),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="aaa_server",
        name="AAA server not responding",
        description=(
            "A RADIUS server stopped answering the device; resolved when it is marked alive again, or after 24 hours."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        # Classic RADIUS-4-RADIUS_DEAD and, on IOS XE 17 (Cisco "Understand
        # AAA Dead Detection"), "RADIUS_AUDIT_MESSAGE-6-RADIUS_DEAD: R0/0:
        # sessmgrd: RADIUS server 192.0.2.5:1812,1813 is not responding."
        raise_on=(_m("RADIUS-RADIUS_DEAD", "RADIUS_AUDIT_MESSAGE-RADIUS_DEAD", instance=_RADIUS_SERVER),),
        clear_on=(_m("RADIUS-RADIUS_ALIVE", instance=_RADIUS_SERVER),),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="ntp_sync",
        name="NTP synchronization lost",
        description="The device lost NTP synchronization; resolved when it synchronizes to a peer again.",
        families=_CISCO_FAMILIES,
        severity="warning",
        raise_on=(_m("NTP-UNSYNC"),),
        clear_on=(_m("NTP-PEERSYNC"),),
    ),
    BuiltinRule(
        key="license_expiry",
        name="License expiring or expired",
        description=(
            "Smart Licensing reported an evaluation, authorization or registration that expires soon or has "
            "expired, or a failed authorization renewal; resolves 24 hours after the last such message."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        raise_on=(
            _m(
                "SMART_LIC-EVAL_WILL_EXPIRE_WARNING",
                "SMART_LIC-EVAL_EXPIRED",
                "SMART_LIC-EVAL_EXPIRED_WARNING",
                "SMART_LIC-AUTHORIZATION_EXPIRED",
                "SMART_LIC-AUTH_RENEW_FAILED",
                "SMART_LIC-ID_CERT_EXPIRED",
                "SMART_LIC-ID_CERT_EXPIRED_WARNING",
            ),
        ),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="certificate_expiry",
        name="Certificate expiring or expired",
        description=(
            "A PKI certificate expires soon, has expired or failed to renew; resolves 24 hours after the last "
            "such message."
        ),
        families=_CISCO_FAMILIES,
        severity="warning",
        # "Certificate renewal failed for trustpoint <name> Reason : ...",
        # "... The certificate SN: <serial> has expired."
        raise_on=(
            _m(
                "PKI-CERT_EXPIRY_WARNING",
                "PKI-CERT_EXPIRY_ALERT",
                "PKI-CERT_RENEW_FAIL",
                "PKI-CERTIFICATE_INVALID_EXPIRED",
                instance=r"\btrustpoint (\S+)|\bcertificate SN: (\S+)",
            ),
        ),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="software_fault",
        name="Software crash or memory failure",
        description=(
            "A memory allocation failed, the device reported a crash, or an NX-OS service crashed; resolves 24 "
            "hours after the last such message."
        ),
        families=(*_CISCO_FAMILIES, "Cisco NX-OS"),
        severity="critical",
        raise_on=(
            _m("SYS-MALLOCFAIL", "PLATFORM-CRASHED"),
            # Cisco Field Notice FN64180: "Service "snmpd" (PID 28063) hasn't
            # caught signal 11 (core will be saved)."
            _m("SYSMGR-SERVICE_CRASHED", instance=r'\bService "([^"]+)"'),
        ),
        auto_resolve_minutes=1440,
    ),
)

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
            "Cisco FTD",
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
            "HPE Aruba AOS-CX",
            "HPE Aruba AOS-Switch",
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
            _m(*_AOSCX_OSPF, text=r"\bDown\s*(?:\([^)]*\))?$", instance=_AOSCX_OSPF_NBR),
            _m("AOSS-02703", text=r"\badj lost\b", instance=_AOSS_OSPF_NBR),
        ),
        clear_on=(
            _m(*_OSPF_TAGS, text=r"\bto FULL\b", instance=rf"Nbr {_IFACE}"),
            _m("OSPF-ADJCHANGE", text=r"\bwent FULL\b", instance=rf"Nbr {_IFACE}"),
            _m("OSPF-OSPF_ADJACENCY_ESTABLISHED", instance=rf"NGB {_IFACE}"),
            _m("RPD_OSPF_NBRUP", text=r"\bto Full\b", instance=rf"neighbor {_IFACE}"),
            _m(_FGT_OSPF, text=r"\bADJCHANGE: neighbor \S+ Up\b", instance=rf"\bADJCHANGE: neighbor {_IFACE}"),
            _m("PAN-SYSTEM-ROUTED-OSPF-NEIGHBOR-FULL"),
            _m(*_AOSCX_OSPF, text=r"\bFull\s*(?:\([^)]*\))?$", instance=_AOSCX_OSPF_NBR),
            _m("AOSS-02703", text=r"\badj formed\b", instance=_AOSS_OSPF_NBR),
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
            "HPE Aruba AOS-CX",
            "HPE Aruba AOS-Switch",
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
            _m("AOSCX-2902", text=r"^\S+: Peer down\b", instance=_AOSCX_BGP_PEER),
            # AOS-Switch 3073 "BGP: Peer down" names no peer: one alert per switch.
            _m("AOSS-03073", text=r"\bPeer down\b"),
        ),
        clear_on=(
            _m(*_BGP_TAGS, text=r"neighbor \S+(?: vpn vrf \S+)? Up\b", instance=rf"neighbor {_IFACE}"),
            _m("BGP-ADJCHANGE", text=r"\bnew state Established\b", instance=rf"peer {_IFACE}"),
            _m("RPD_BGP_NEIGHBOR_STATE_CHANGED", text=r"\bto Established\b", instance=r"peer ([^\s,+]+)"),
            _m("PAN-SYSTEM-ROUTED-BGP-PEER-ENTER-ESTABLISHED", instance=_PAN_BGP_PEER),
            _m("AOSCX-2901", text=r"^\S+: Peer up\b", instance=_AOSCX_BGP_PEER),
            _m("AOSS-03072", text=r"\bPeer up\b"),
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
            "Cisco IOS XR",
            "Cisco ASA",
            "Cisco FTD",
            "Arista EOS",
            "Juniper Junos",
            "Fortinet FortiOS",
            "Palo Alto PAN-OS",
            "HPE Aruba AOS-CX",
            "HPE Aruba AOS-Switch",
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
            # so one alert per firewall) and, from 7.2, 22114 "Power supply
            # failed warning" (6.4: "power redundancy degrade").
            _m("FGT-0100022105", "FGT-0100022114"),
            # PAN-OS ps-failure: "Alarm on Power Supply #2".
            _m("PAN-SYSTEM-PS-FAILURE", instance=r"\bPower Supply #(\d+)"),
            # AOS-CX 304: "PSU 1/1 faulted. Total fault count: 1"
            _m("AOSCX-304", instance=r"\bPSU (\S+?) faulted"),
            _m("AOSS-00071", text=r"\bPower Supply failure\b", instance=_AOSS_SUPPLY),
            _m("AOSS-02797", text=r"\bis faulted\b", instance=_AOSS_INTERNAL_PSU),
            # IOS XR (System Error Message Reference 5.1.1, category
            # PLATFORM): "Power-module 0/PS0/M1/SP failure condition ...",
            # "<module> is Non-Operational".
            _m("PLATFORM-PWR_MGMT-MODULE_FAILURE", "PLATFORM-PWRMON-MODULE_FAILURE", instance=r"^Power-module (\S+)"),
            _m("PLATFORM-ENVMON-POWERSUPPLY_NONOP", instance=_XR_NONOP),
            # ASA / FTD (ASA Series Syslog Messages 722001-776020, FTD
            # syslogs9): 735004 "Power Supply <n>: Failure Detected", 735006
            # "Power Supply Unit Redundancy Lost".
            _m(*_asa_ftd(735004), instance=_ASA_PSU),
            _m(*_asa_ftd(735006), instance=_ASA_PSU_REDUNDANCY),
        ),
        clear_on=(
            _m("IOSXE_PEM-PEMOK", instance=rf"slot {_IFACE}"),
            _m("PLATFORM_FEP-FRU_PS_SIGNAL_OK", instance=r"Switch (\d+):.*power supply ([A-Za-z0-9]+)"),
            _m("PLATFORM-PS_OK", instance=r"Power supply (\d+)"),
            _m(prefixes=("CHASSISD_SNMP_TRAP",), text=r"Power Supply OK", instance=_JUNOS_FRU),
            _m("PWRMGMT-PSU_STATUS_OK", instance=_ARISTA_PSU),
            # FortiOS 22104 "Power supply restored" (to 7.4; not in 7.6) and,
            # from 7.2, 22115 "Power supply restored notification". In 6.4
            # 22115 is "power redundancy failure": a message that says so
            # must not resolve the alert.
            _m("FGT-0100022104"),
            _m("FGT-0100022115", exclude=r"\bfail|\bredundan|\bdegrad"),
            _m("AOSS-00071", text=r"\bPower Supply OK\b", instance=_AOSS_SUPPLY),
            _m("AOSS-02797", text=r"\bis ok\b", instance=_AOSS_INTERNAL_PSU),
            # IOS XR: "<module> has become operational".
            _m("PLATFORM-ENVMON-POWERSUPPLY_NONOP_CLEAR", instance=_XR_NONOP),
            # ASA / FTD 735003 "Power Supply <n>: OK", 735005 "Power Supply
            # Unit Redundancy OK".
            _m(*_asa_ftd(735003), instance=_ASA_PSU),
            _m(*_asa_ftd(735005), instance=_ASA_PSU_REDUNDANCY),
        ),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="fan",
        name="Fan fault",
        description="A fan failed; resolved when it reports OK, or after 24 hours.",
        families=(
            "Cisco IOS XE (ASR 1000, ISR 4000, Catalyst 9000)",
            "Cisco Catalyst 2960 / 3560 / 3750 (classic IOS)",
            "Cisco ISR G2 (1900, 2900, 3900)",
            "Cisco NX-OS",
            "Cisco IOS XR",
            "Cisco ASA",
            "Cisco FTD",
            "Arista EOS",
            "Juniper Junos",
            "Fortinet FortiOS",
            "Palo Alto PAN-OS",
            "HPE Aruba AOS-CX",
            "HPE Aruba AOS-Switch",
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
            # FortiOS 22108 "Fan anomaly" (the msg names the fan in no
            # documented form, so one alert per firewall).
            _m("FGT-0100022108"),
            # AOS-CX 214: "<function>: Fan 1/1/1 faulted, reason: <reason>."
            _m("AOSCX-214", instance=r"\bFan (\S+) faulted\b"),
            _m("AOSS-00070", text=r"\bFan failure\b", instance=_AOSS_FAN),
            # IOS XR: "Fan failure on slot 0/FT0/SP, fan 2, RPM 0" (or "<fan>
            # FAILED."), "Fan tray failure on slot 0/FT0/SP".
            _m("PLATFORM-ENVMON-FAN_FAIL", instance=_XR_FAN),
            _m("PLATFORM-ENVMON-FANTRAY_FAIL", instance=_XR_FANTRAY),
            # Catalyst 9000 (Catalyst guide 17.3.x / 16.12.x): "Switch 2:
            # System fan 1 failed".
            _m("PLATFORM_THERMAL-FRU_FAN_FAILURE", instance=_CAT9K_FAN),
            # ASA / FTD 735002 "Cooling Fan <n>: Failure Detected", 735012
            # "Power Supply <n>: Fan Failure Detected".
            _m(*_asa_ftd(735002), instance=_ASA_FAN),
            _m(*_asa_ftd(735012), instance=_ASA_PSU_FAN),
        ),
        clear_on=(
            _m("IOSXE_PEM-FANOK", instance=rf"slot {_IFACE}"),
            _m("PLATFORM-FANMOD_FAN_OK", instance=r"Fan module (\d+)"),
            _m(prefixes=("CHASSISD_SNMP_TRAP",), text=r"Fan(?:/Blower)? OK", instance=_JUNOS_FRU),
            _m("ENVMON-FAN_OK", instance=r"\bFan (\d+)"),
            _m("ENVMON-FANOK", instance=_ARISTA_FAN),
            # FortiOS 22151 "Fan normal".
            _m("FGT-0100022151"),
            _m("AOSS-00070", text=r"\bFan OK\b", instance=_AOSS_FAN),
            # IOS XR: "Fan failure cleared on slot ..., fan 2, RPM 5000",
            # "Fan tray failure cleared on slot ...".
            _m("PLATFORM-ENVMON-FAN_CLEAR", instance=_XR_FAN),
            _m("PLATFORM-ENVMON-FANTRAY_CLEAR", instance=_XR_FANTRAY),
            # Catalyst 9000: "Switch 2: System fan 1 recovered to normal status".
            _m("PLATFORM_THERMAL-FRU_FAN_RECOVERY", instance=_CAT9K_FAN),
            # ASA / FTD 735001 "Cooling Fan <n>: OK", 735011 "Power Supply
            # <n>: Fan OK".
            _m(*_asa_ftd(735001), instance=_ASA_FAN),
            _m(*_asa_ftd(735011), instance=_ASA_PSU_FAN),
        ),
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="module",
        name="Module down",
        description=(
            "A line card, supervisor, SPA, fabric module or stack member failed, went offline, lost power or was "
            "removed; resolved when it is online again, or after 24 hours."
        ),
        families=(
            "Cisco IOS XE (Catalyst 9400 / 9600, StackWise Virtual, ASR 1000, ISR 4000)",
            "Cisco Catalyst 3750 / 2975 stacks (classic IOS)",
            "Cisco Catalyst 6500 (classic IOS)",
            "Cisco Catalyst 4500",
            "Cisco NX-OS",
            "Cisco IOS XR",
            "Arista EOS",
            "Juniper Junos",
            "Fortinet FortiOS (FortiGate 6000 / 7000)",
            "HPE Aruba AOS-CX",
            "HPE Aruba AOS-Switch",
        ),
        severity="critical",
        raise_on=MODULE_DOWN,
        clear_on=MODULE_UP,
        # The Catalyst 6500 power-off has no documented recovery message.
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="temperature",
        name="Temperature alarm",
        description=(
            "A temperature sensor reached its warning or critical threshold (or the device started a thermal "
            "shutdown); resolved when it reports normal, or after 24 hours."
        ),
        families=(
            "Cisco IOS XE (ASR 1000, ISR 4000, Catalyst 9000)",
            "Cisco Catalyst 2960 / 3560 / 3750 (classic IOS)",
            "Cisco Catalyst 4500",
            "Cisco NX-OS",
            "Cisco IOS XR",
            "Cisco ASA",
            "Cisco FTD",
            "Arista EOS",
            "Juniper Junos",
            "Fortinet FortiOS",
            "HPE Aruba AOS-CX",
            "HPE Aruba AOS-Switch",
        ),
        severity="critical",
        raise_on=TEMPERATURE_HIGH,
        clear_on=TEMPERATURE_OK,
        auto_resolve_minutes=1440,
    ),
    BuiltinRule(
        key="ha_switchover",
        name="HA failover or switchover",
        description=(
            "A redundancy switchover, firewall failover, new stack master or HA peer, heartbeat or failover link "
            "loss; resolves 60 minutes after the last such message (or when the link or peer is back)."
        ),
        families=(
            "Cisco IOS XE (supervisor / RP redundancy)",
            "Cisco Catalyst 3750 stacks (classic IOS)",
            "Cisco NX-OS",
            "Cisco IOS XR",
            "Cisco ASA",
            "Cisco FTD",
            "Arista EOS (supervisor redundancy, MLAG)",
            "Juniper Junos (RE mastership, SRX chassis cluster)",
            "Fortinet FortiOS (HA)",
            "Palo Alto PAN-OS (HA)",
            "HPE Aruba AOS-CX (VSX)",
            "HPE Aruba AOS-Switch (stacking)",
        ),
        severity="warning",
        raise_on=HA_SWITCHOVER,
        clear_on=HA_RESTORED,
        auto_resolve_minutes=60,
    ),
    BuiltinRule(
        key="device_restart",
        name="Device restarted",
        description=(
            "The device restarted, or announced it is reloading or shutting down; resolves 60 minutes after the "
            "last such message."
        ),
        families=(
            "Cisco IOS / IOS XE",
            "Cisco IOS XR",
            "Cisco NX-OS",
            "Cisco ASA",
            "Cisco FTD",
            "Arista EOS",
            "Juniper Junos",
            "Fortinet FortiOS",
            "HPE Aruba AOS-CX",
            "HPE Aruba AOS-Switch",
        ),
        severity="warning",
        # The same forms as the reload / restart re-poll trigger.
        raise_on=(*RELOAD, *RESTART),
        auto_resolve_minutes=60,
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
            "Cisco FTD",
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
                # FTD logs the same ids except 605004 (not in its guide).
                "FTD-113005",
                "FTD-113015",
                "FTD-611102",
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
    *_LAYER2_RULES,
    *_NEIGHBOR_RULES,
    *_HEALTH_RULES,
)
BUILTIN_BY_KEY: dict[str, BuiltinRule] = {r.key: r for r in BUILTIN_RULES}

# ── Triggers ─────────────────────────────────────────────────────────────────

CONFIG_CHANGE: tuple[Matcher, ...] = (
    _m(
        "SYS-CONFIG_I",  # IOS, IOS XE, Arista EOS
        "VSHD-VSHD_SYSLOG_CONFIG_I",  # NX-OS
        "MGBL-CONFIG-DB_COMMIT",  # IOS XR
        "ASA-111008",  # ASA: a configuration command
        "FTD-111008",  # FTD: the same message
        "UI_COMMIT_COMPLETED",  # Junos
    ),
    # ASA (and FTD) 111010 logs every command run through ASDM or the CLI,
    # show commands too: only the others count.
    _m(
        "ASA-111010",
        "FTD-111010",
        text=r"executed '",
        exclude=r"executed '(?:show|ping|traceroute|more|dir)\b",
    ),
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
    # AOS-Switch 3125 "new Startup Config Seq Num = <n> by <UI>": the
    # startup configuration was saved (write memory).
    _m("AOSS-03125", text=r"\bnew Startup Config Seq Num\b"),
)
# RELOAD and RESTART (the re-poll trigger's reload / restart forms) are
# defined above BUILTIN_RULES: the device_restart rule raises on them.


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
    """``interface_down``, ``module`` (a module down or online again, or a
    temperature alarm raised or cleared), ``reload``, ``restart``,
    ``state_change`` (an HA switchover, failover or its recovery) or "" for a message
    that does not trigger a re-poll. The temperature and HA reasons are
    those of the trap rules with the same keys (``trap_rules`` ``repoll``)."""
    if _first(INTERFACE_DOWN, parsed) is not None:
        return "interface_down"
    if _first(MODULE_DOWN, parsed) is not None or _first(MODULE_UP, parsed) is not None:
        return "module"
    if _first(RELOAD, parsed) is not None:
        return "reload"
    if _first(RESTART, parsed) is not None:
        return "restart"
    if _first(TEMPERATURE_HIGH, parsed) is not None or _first(TEMPERATURE_OK, parsed) is not None:
        return "module"
    if _first(HA_SWITCHOVER, parsed) is not None or _first(HA_RESTORED, parsed) is not None:
        return "state_change"
    return ""


# The built-in rules and triggers by the tags their message forms carry.
_TAG_OWNERS: tuple[tuple[str, tuple[Matcher, ...]], ...] = (
    *((rule.key, (*rule.raise_on, *rule.clear_on)) for rule in BUILTIN_RULES),
    ("config_change", CONFIG_CHANGE),
    ("repoll", (*RELOAD, *RESTART)),
)


def tag_owner(tag: str) -> str:
    """The built-in rule (its key) or trigger (``config_change``, ``repoll``)
    that has a message form with ``tag``, or "" (a module message is owned by
    the ``module`` rule and a reload or restart message by the
    ``device_restart`` rule, which share their forms with the re-poll
    trigger). A
    message with such a tag
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
    or a custom rule. ``key`` names it in the alert's metric and dedup key.
    ``source`` is the message source: ``syslog`` (its match functions take
    a ``ParsedSyslog``) or ``trap`` (``netcontrol.trap_rules``: they take a
    ``netcontrol.snmp_traps.NamedTrap``)."""

    key: str
    name: str
    severity: str
    enabled: bool
    builtin: bool
    threshold_count: int
    threshold_window_seconds: int
    auto_resolve_minutes: int
    raise_match: Callable[[Any], str | None]
    clear_match: Callable[[Any], str | None] | None = None
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
    source: str = ALERT_TYPE
    # A custom trap rule's varbind conditions and instance
    # (``trap_rules.clean_custom_trap_rule``); None for every other rule.
    trap_match: dict | None = None

    @property
    def metric(self) -> str:
        return metric_name(self.key, self.source)

    @property
    def ref(self) -> str:
        """The rule's name across sources: its key for a syslog rule, its
        metric (``trap_<key>``) otherwise. Keys the threshold counters and
        the stored override row (``builtin_key``)."""
        return self.key if self.source == ALERT_TYPE else self.metric

    def payload(self) -> dict:
        """The API form of the rule (a custom trap rule adds ``trap_match``)."""
        extra = {"trap_match": self.trap_match} if self.trap_match is not None else {}
        return {
            **extra,
            "id": self.id,
            "key": self.key,
            "source": self.source,
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


def metric_name(rule_key: str, source: str = ALERT_TYPE) -> str:
    return f"{source}_{rule_key}"


def dedup_key(rule_key: str, host_id: int, instance: str, source: str = ALERT_TYPE) -> str:
    return f"{source}:{rule_key}:{host_id}:{instance}"


def builtin_override(override: dict | None, severity: str) -> dict:
    """The fields a stored override row (``syslog_alert_rules`` with a
    ``builtin_key``) sets on a built-in rule of either source: ``severity``
    (the rule's own when unset), ``enabled`` (on without a row),
    ``updated_at`` and ``overridden``."""
    return {
        "severity": (override or {}).get("severity") or severity,
        "enabled": bool(override["enabled"]) if override else True,
        "updated_at": (override or {}).get("updated_at", ""),
        "overridden": override is not None,
    }


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
        **builtin_override(override, rule.severity),
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


MatchFn = Callable[[Any], str | None]


def _syslog_matchers(row: dict) -> tuple[MatchFn, MatchFn | None]:
    """The raise and clear match functions of a custom syslog row."""
    clear = row.get("clear_pattern") or ""
    return (
        _custom_matcher(row["match_type"], row["pattern"]),
        _custom_matcher(row["match_type"], clear) if clear else None,
    )


def custom_rule(
    row: dict,
    key: str | None = None,
    *,
    matchers: Callable[[dict], tuple[MatchFn, MatchFn | None]] = _syslog_matchers,
    source: str = ALERT_TYPE,
    trap_match: dict | None = None,
) -> Rule:
    """The ``Rule`` of a custom row (syslog by default; a custom trap rule
    passes its own ``matchers``, ``source`` and ``trap_match``). ValueError
    when a pattern no longer compiles."""
    raise_match, clear_match = matchers(row)
    return Rule(
        key=key or custom_rule_key(row["id"]),
        name=row["name"],
        severity=row["severity"],
        enabled=bool(row.get("enabled", True)),
        builtin=False,
        threshold_count=int(row["threshold_count"]),
        threshold_window_seconds=int(row["threshold_window_seconds"]),
        auto_resolve_minutes=int(row["auto_resolve_minutes"]),
        raise_match=raise_match,
        clear_match=clear_match,
        id=row.get("id"),
        match_type=row["match_type"],
        pattern=row["pattern"],
        clear_pattern=row.get("clear_pattern") or "",
        created_by=row.get("created_by", ""),
        created_at=row.get("created_at", ""),
        updated_at=row.get("updated_at", ""),
        source=source,
        trap_match=trap_match,
    )


_custom = custom_rule


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


def clean_rule_settings(body: dict) -> dict:
    """The values every custom rule (syslog or trap) has, from an API body,
    or ``RuleError``: ``name``, ``enabled``, ``severity`` and the threshold
    and auto-resolve numbers."""
    if not isinstance(body, dict):
        raise RuleError("The rule must be an object.")
    name = str(body.get("name") or "").strip()
    if not name:
        raise RuleError("The rule needs a name.")
    if len(name) > NAME_MAX:
        raise RuleError(f"The name is longer than {NAME_MAX} characters.")
    severity = str(body.get("severity") or "warning").strip()
    if severity not in SEVERITIES:
        raise RuleError(f"severity must be one of: {', '.join(SEVERITIES)}.")
    return {
        "name": name,
        "enabled": bool(body.get("enabled", True)),
        "severity": severity,
        "threshold_count": _int_field(body, "threshold_count", 1, 1, THRESHOLD_COUNT_MAX),
        "threshold_window_seconds": _int_field(body, "threshold_window_seconds", 300, 1, THRESHOLD_WINDOW_MAX),
        "auto_resolve_minutes": _int_field(body, "auto_resolve_minutes", 0, 0, AUTO_RESOLVE_MAX),
    }


def clean_custom_rule(body: dict) -> dict:
    """The stored values of a custom rule from an API body, or
    ``RuleError``. Regex patterns are compiled with RE2 here, so a pattern
    RE2 rejects (or one with lookarounds or backreferences) is refused when
    it is saved, never on the receive path."""
    settings = clean_rule_settings(body)
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
    return {**settings, "match_type": match_type, "pattern": pattern, "clear_pattern": clear_pattern}


def draft_rule(body: dict) -> Rule:
    """A custom rule from an unsaved API body (the test endpoint), or
    ``RuleError``."""
    return _custom({**clean_custom_rule(body), "id": None}, key="draft")


def merge_rules(rows: list[dict]) -> list[Rule]:
    """The built-in rules (with their stored overrides) then the custom
    rules, from the rows of ``syslog_alert_rules``. A custom row that no
    longer compiles is skipped (logged); a custom trap rule's row
    (``source`` ``trap``, ``netcontrol.trap_rules``) is not a syslog rule."""
    overrides = {r["builtin_key"]: r for r in rows if r.get("builtin_key")}
    rules = [_builtin(b, overrides.get(b.key)) for b in BUILTIN_RULES]
    for row in rows:
        if row.get("builtin_key") or (row.get("source") or ALERT_TYPE) != ALERT_TYPE:
            continue
        try:
            rules.append(_custom(row))
        except (ValueError, KeyError) as exc:
            LOGGER.warning("syslog rules: custom rule %s skipped: %s", row.get("id"), exc)
    return rules


_rules_cache: tuple[float, list[Rule]] | None = None
_rows_cache: tuple[float, list[dict]] | None = None


def invalidate_rules_cache() -> None:
    """Drop the cached rule set and stored rows: called on every rule write
    (syslog or trap)."""
    global _rules_cache, _rows_cache
    _rules_cache = None
    _rows_cache = None


async def rule_rows() -> list[dict]:
    """The rows of ``syslog_alert_rules`` (custom rules and the overrides of
    the built-in syslog and trap rules), cached for ``CACHE_TTL_SECONDS``."""
    global _rows_cache
    now = _clock()
    if _rows_cache is not None and _rows_cache[0] > now:
        return _rows_cache[1]
    rows = await db.list_syslog_alert_rules()
    _rows_cache = (now + CACHE_TTL_SECONDS, rows)
    return rows


async def get_rules() -> list[Rule]:
    """Every syslog rule, enabled or not, cached for ``CACHE_TTL_SECONDS``
    (so other worker processes pick up a change too)."""
    global _rules_cache
    now = _clock()
    if _rules_cache is not None and _rules_cache[0] > now:
        return _rules_cache[1]
    rules = merge_rules(await rule_rows())
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


def _track(rule: Rule, host_id: int, parsed: Any, now: float) -> tuple[bool, str] | None:
    """Count a message (a ``ParsedSyslog``, or a ``NamedTrap`` for a trap
    rule) of ``host_id`` for ``rule`` at ``now``: a raise match is counted,
    a clear match drops the counter. ``(True, instance)`` when the match
    meets the threshold (raise), ``(False, instance)`` on a clear match
    (resolve), else None."""
    instance = rule.raise_match(parsed)
    if instance is not None:
        counted, met = _count((rule.ref, host_id, instance), rule.threshold_count, rule.threshold_window_seconds, now)
        return (True, instance) if counted and met else None
    instance = rule.clear_match(parsed) if rule.clear_match is not None else None
    if instance is not None:
        _counters.pop((rule.ref, host_id, instance), None)
        return False, instance
    return None


track = _track


# ── The engine ───────────────────────────────────────────────────────────────


class RuleEvent(Protocol):
    """What an alert message quotes of the message that raised it: a
    ``ParsedSyslog`` or a ``NamedTrap`` (``raw_tag``: the tag or trap name,
    ``text``: what follows it)."""

    @property
    def raw_tag(self) -> str: ...

    @property
    def text(self) -> str: ...


def alert_message(rule: Rule, instance: str, parsed: RuleEvent) -> str:
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
                if reason in HARDWARE_REPOLL_REASONS:
                    mark_hardware_stale(host_id)
                delay = RELOAD_REPOLL_DELAY_SECONDS if reason == "reload" else REPOLL_DELAY_SECONDS
                if schedule_repoll(host_id, delay, min_interval=REPOLL_MIN_INTERVAL_SECONDS):
                    outcome["repolls"] += 1
        if config_on and is_config_change(parsed):
            note_config_change(host_id)
            outcome["config_changes"] += 1
    if actions:
        await apply_actions(actions, outcome)
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


async def apply_actions(actions: list[tuple[bool, Rule, int, str, Any]], outcome: dict) -> None:
    """Raise or resolve the alerts of ``actions`` (``(raise_it, rule,
    host_id, instance, message)`` from ``_track``), adding to ``outcome``'s
    ``raised`` / ``resolved``. The alert's type is the rule's source
    (``syslog`` or ``trap``): each source raises and resolves only its own
    alerts."""
    hosts = {int(h["id"]): h for h in await db.get_hosts_by_ids(sorted({a[2] for a in actions}))}
    for raise_it, rule, host_id, instance, parsed in actions:
        key = dedup_key(rule.key, host_id, instance, rule.source)
        if not raise_it:
            # A syslog (or trap) source can be forged: a clear message
            # resolves only an alert its own source raised for this host,
            # never one polling owns.
            outcome["resolved"] += await db.resolve_monitoring_alerts(key, alert_type=rule.source, host_id=host_id)
            continue
        host = hosts.get(host_id)
        if host is None:
            continue
        if await db.is_alert_suppressed(host_id, rule.metric, host.get("group_id")):
            continue
        await db.create_monitoring_alert(
            host_id=host_id,
            poll_id=None,
            alert_type=rule.source,
            metric=rule.metric,
            message=alert_message(rule, instance, parsed),
            severity=rule.severity,
            dedup_key=key,
            hostname=host.get("hostname") or "",
        )
        outcome["raised"] += 1


async def resolve_expired_rule_alerts(rules: Iterable[Rule]) -> int:
    """Resolve the open alerts of every rule in ``rules`` with an
    ``auto_resolve_minutes`` that have not been seen again for that long
    (each under its source's alert type)."""
    resolved = 0
    for rule in rules:
        if rule.auto_resolve_minutes > 0:
            resolved += await db.resolve_stale_monitoring_alerts(
                rule.source, rule.metric, rule.auto_resolve_minutes, f"auto-resolved (no new {rule.source} match)"
            )
    return resolved


async def resolve_expired_alerts() -> int:
    """Resolve the open syslog alerts of every rule with an
    ``auto_resolve_minutes`` that have not been seen again for that long.
    Called by a periodic loop; returns how many were resolved."""
    return await resolve_expired_rule_alerts(await get_rules())


async def resolve_rule_alerts(rule_key: str, source: str = ALERT_TYPE, reason: str = "rule deleted") -> int:
    """Resolve every open alert of a rule of ``source`` (it was deleted, or
    a custom trap rule was disabled)."""
    return await db.resolve_stale_monitoring_alerts(source, metric_name(rule_key, source), 0, reason)


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


def evaluate_rule(rule: Rule, parsed: Any) -> dict | None:
    """``{"action": "raise" | "clear", "instance": ...}`` when ``rule``
    raises or clears on the message (a ``ParsedSyslog``, or a ``NamedTrap``
    for a trap rule), else None."""
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
    # No credential only for an OPNsense firewall, whose drift snapshot is
    # its newest backup (no SSH): a host read over SSH failed above without one.
    config_text = await config_drift._capture_for_drift(host, cred or {}, max_age_seconds=CONFIG_REUSE_SECONDS)
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


def threshold_rules(rules: Iterable[Rule]) -> list[Rule]:
    """The enabled rules with a threshold above one: the ones whose counters
    a restore rebuilds."""
    return [r for r in rules if r.enabled and r.threshold_count > 1]


def restore_window(rules: Iterable[Rule]) -> int:
    """Seconds of stored events a restore reads for ``rules``: the longest
    threshold window, capped at ``RESTORE_WINDOW_MAX_SECONDS``."""
    return min(max((r.threshold_window_seconds for r in rules), default=0), RESTORE_WINDOW_MAX_SECONDS)


async def replay_stored(rows: list[dict], replay: Callable[[dict, float], bool]) -> int:
    """Replay stored events (``trap_syslog_events`` rows, newest first, with
    ``received_at``), oldest first, each at its age before now on the
    engine's clock: ``replay(row, at)`` counts the row in the threshold
    counters (``_track``) and returns whether it was an event to count.
    Shared by the syslog and the trap restore. Returns how many rows were
    replayed."""
    now_utc = datetime.now(UTC)
    now = _clock()
    replayed = 0
    for row in reversed(rows):  # oldest first
        stamp = _received(row["received_at"])
        if stamp is None:
            continue
        if not replay(row, now - max(0.0, (now_utc - stamp).total_seconds())):
            continue
        replayed += 1
        if replayed % _RESTORE_YIELD_EVERY == 0:
            await asyncio.sleep(0)
    return replayed


def track_all(rules: Iterable[Rule], host_id: int, event: Any, at: float) -> None:
    """Count ``event`` of ``host_id`` at ``at`` for each of ``rules``
    (raises and resolves nothing: the restore's replay)."""
    for rule in rules:
        _track(rule, host_id, event, at)


async def _restore_counters() -> int:
    """Replay the stored messages of inventory hosts through the counters of
    the enabled threshold rules, each counted at its age before now. Raises
    and resolves nothing, schedules nothing. A counter a live message
    already reached takes no older replayed match (``_count`` treats it as
    a repeat), so a race with the receiver can only under-count. Returns
    how many messages were replayed."""
    rules = threshold_rules(await get_rules())
    if not rules:
        return 0
    rows = await db.list_syslog_messages_since(
        restore_window(rules), limit=RESTORE_ROWS_MAX, hosts_only=True, transports=_restore_transports()
    )

    def replay(row: dict, at: float) -> bool:
        track_all(rules, int(row["host_id"]), parse_syslog_message(row["message"] or ""), at)
        return True

    return await replay_stored(rows, replay)


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
