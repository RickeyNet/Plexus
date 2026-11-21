"""Syslog rule activity: what the rules matched in the received traffic and
what they missed.

The built-in message patterns (``netcontrol.syslog_rules``) come from
vendor documentation. ``analyze`` reads the stored syslog messages
(``trap_syslog_events``) of a recent window and reports, per rule, how often
it raised and cleared; per trigger (configuration change, re-poll, OPNsense
re-collection) how often it fired; the messages of inventory hosts no rule
or trigger acted on, grouped by event tag (else program), each with a hint
of the built-in rule it looks related to; the source addresses that are no
inventory host; and how the inventory hosts' messages arrived (UDP, TCP or
TLS), so an admin can see who still sends UDP. A UDP message that meets a
rule or trigger while UDP messages are not acted on is counted apart
(``udp_stored_only``), not as a match. Computed on demand, nothing stored,
nothing on the receive path. ``docs/syslog-rules.md`` "Checking the rules against received
traffic" describes it; the API is ``GET /api/monitoring/syslog-rules/activity``.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

import routes.database as db

from netcontrol import syslog_rules
from netcontrol.syslog_rules import ParsedSyslog, Rule

# At most this many messages are read per analysis, in pages of PAGE_SIZE
# (newest first): each page is aggregated and dropped.
SCAN_LIMIT = 50000
PAGE_SIZE = 5000
UNMATCHED_TOP = 100
UNKNOWN_SOURCES_TOP = 20
SAMPLE_MAX = 300

# ``related`` hints: an unmatched message group whose tag (an untagged one:
# its program and sample) contains one of these words looks like the subject
# of that built-in rule or trigger. Tested in order against the text as
# upper-case words joined by single spaces (``SEC_LOGIN-LOGIN_FAILED`` ->
# ``SEC LOGIN LOGIN FAILED``), so ``\b`` is a word boundary and ``FAN`` does
# not match ``FANOUT``.
_RELATED: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (key, re.compile(pattern))
    for key, pattern in (
        ("ospf_neighbor", r"\bOSPF\w*"),
        ("bgp_neighbor", r"\bBGP\w*"),
        ("fan", r"\bFAN(?:S|FAIL|OK|MOD|TRAY)?\b|\bBLOWER\b"),
        ("power_supply", r"\bPOWER ?SUPPL\w*|\bPSU?\b|\bPEM\w*|\bPWR\w*"),
        ("link_flap", r"\bLINK\b|\bLINEPROTO\b|\bUPDOWN\b|\bETHPORT\b|\bIF DOWN\b|\bPORT STATE\b"),
        ("auth_failure", r"\bLOGIN\w*|\bAUTH\w*|\bFAILED PASSWORD\b|\bSSHD?\b.*\bFAIL\w*"),
        ("config_change", r"\bCONFIG\w*|\bCOMMIT\w*"),
        ("repoll", r"\bRELOAD\w*|\bRESTART\w*|\bREBOOT\w*|\bBOOTTIME\b|\bCOLD START\b"),
    )
)
_WORD = re.compile(r"[A-Za-z0-9]+")


def related_rule(tag: str, program: str = "", sample: str = "", raw_tag: str = "") -> str:
    """A hint, not a match: the key of the built-in rule (or ``config_change``
    / ``repoll`` trigger) an unmatched message group looks like the subject
    of, from keywords in its ``tag`` and ``raw_tag`` (a numeric vendor tag
    such as ``FGT-0100032002`` says nothing, its ``raw_tag``, the FortiOS
    log description, does; an untagged group: its ``program`` and
    ``sample``), or "" when none fits. It points at a message form the
    rules may have missed; it says nothing about whether the rule should
    have acted on it."""
    text = f"{tag} {raw_tag}" if tag else f"{program} {sample}"
    words = " ".join(_WORD.findall(text.upper()))
    for key, pattern in _RELATED:
        if pattern.search(words):
            return key
    return ""


@dataclass
class _RuleStat:
    raised: int = 0
    cleared: int = 0
    hosts: set[int] = field(default_factory=set)
    last_at: str = ""


@dataclass
class _Group:
    tag: str
    raw_tag: str
    program: str
    sample: str
    last_at: str
    count: int = 0
    hosts: set[int] = field(default_factory=set)
    device_types: set[str] = field(default_factory=set)


@dataclass
class _Source:
    count: int = 0
    last_at: str = ""


@dataclass
class _Tally:
    scanned: int = 0
    matched: int = 0
    unmatched: int = 0
    unknown_source: int = 0
    oldest_at: str = ""
    rules: dict[str, _RuleStat] = field(default_factory=dict)
    triggers: dict[str, int] = field(default_factory=lambda: {"config_change": 0, "repoll": 0, "recollect": 0})
    groups: dict[tuple[str, str], _Group] = field(default_factory=dict)
    sources: dict[str, _Source] = field(default_factory=dict)
    # Inventory host messages per transport, and the hosts that sent over UDP.
    transports: dict[str, int] = field(default_factory=lambda: {"udp": 0, "tcp": 0, "tls": 0})
    udp_hosts: set[int] = field(default_factory=set)
    # Messages a rule or trigger meets that arrived over UDP while UDP
    # messages are not acted on (counted in neither matched nor unmatched).
    udp_stored_only: int = 0


def _later(a: str, b: str) -> str:
    return a if a >= b else b


def _host_message(tally: _Tally, rules: list[Rule], row: dict, parsed: ParsedSyslog, acted: bool) -> None:
    """Count one message of an inventory host. ``acted`` False: it arrived
    over UDP while UDP messages are not acted on, so a rule or trigger it
    meets counts in ``udp_stored_only`` and not as a match."""
    host_id = int(row["host_id"])
    at = str(row["received_at"] or "")
    found = [(rule, hit) for rule in rules if (hit := syslog_rules.evaluate_rule(rule, parsed)) is not None]
    fired = [
        name
        for name, on in (
            ("config_change", syslog_rules.is_config_change(parsed)),
            ("repoll", bool(syslog_rules.repoll_reason(parsed))),
            ("recollect", bool(syslog_rules.recollect_reason(parsed))),
        )
        if on
    ]
    if (found or fired) and not acted:
        tally.udp_stored_only += 1
        return
    if found or fired:
        tally.matched += 1
        for rule, hit in found:
            stat = tally.rules.setdefault(rule.key, _RuleStat())
            if hit["action"] == "raise":
                stat.raised += 1
            else:
                stat.cleared += 1
            stat.hosts.add(host_id)
            stat.last_at = _later(stat.last_at, at)
        for name in fired:
            tally.triggers[name] += 1
        return
    tally.unmatched += 1
    program = "" if parsed.tag else parsed.program.lower()
    group = tally.groups.get((parsed.tag, program))
    if group is None:
        # Rows arrive newest first: the first one of a group is its newest.
        group = _Group(parsed.tag, parsed.raw_tag, program, str(row["message"] or "")[:SAMPLE_MAX], at)
        tally.groups[(parsed.tag, program)] = group
    group.count += 1
    group.hosts.add(host_id)
    if row.get("device_type"):
        group.device_types.add(str(row["device_type"]))
    group.last_at = _later(group.last_at, at)


def _aggregate(tally: _Tally, rules: list[Rule], rows: Iterable[dict], udp_actions: bool) -> None:
    """Add one page of messages to ``tally`` (pure CPU, run in a thread).
    ``udp_actions``: the **Act on UDP messages** switch."""
    for row in rows:
        tally.scanned += 1
        at = str(row["received_at"] or "")
        if at and (not tally.oldest_at or at < tally.oldest_at):
            tally.oldest_at = at
        if row["host_id"] is None:
            tally.unknown_source += 1
            source = tally.sources.setdefault(str(row["source_ip"] or ""), _Source())
            source.count += 1
            source.last_at = _later(source.last_at, at)
            continue
        transport = str(row.get("transport") or "udp")
        tally.transports[transport] = tally.transports.get(transport, 0) + 1
        if transport == "udp":
            tally.udp_hosts.add(int(row["host_id"]))
        parsed = syslog_rules.parse_syslog_message(str(row["message"] or ""))
        _host_message(tally, rules, row, parsed, udp_actions or transport != "udp")


def _group_payload(group: _Group) -> dict:
    """The API form of an unmatched group. ``known_tag``: a built-in rule or
    trigger has a message form with this tag (``related`` names it), so the
    text of these messages did not meet its pattern; otherwise ``related``
    is the keyword hint."""
    owner = syslog_rules.tag_owner(group.tag)
    return {
        "tag": group.tag,
        "raw_tag": group.raw_tag,
        "program": group.program,
        "count": group.count,
        "hosts": len(group.hosts),
        "device_types": sorted(group.device_types),
        "last_at": group.last_at,
        "sample": group.sample,
        "related": owner or related_rule(group.tag, group.program, group.sample, group.raw_tag),
        "known_tag": bool(owner),
    }


def _result(tally: _Tally, rules: list[Rule], hours: int, limit: int, truncated: bool, udp_actions: bool) -> dict:
    groups = sorted(tally.groups.values(), key=lambda g: (-g.count, g.tag, g.program))[:UNMATCHED_TOP]
    sources = sorted(tally.sources.items(), key=lambda kv: (-kv[1].count, kv[0]))[:UNKNOWN_SOURCES_TOP]
    return {
        "hours": hours,
        "limit": limit,
        "scanned": tally.scanned,
        "truncated": truncated,
        "oldest_at": tally.oldest_at,
        "matched": tally.matched,
        "unmatched": tally.unmatched,
        "unknown_source": tally.unknown_source,
        "transports": dict(tally.transports),
        "udp_hosts": len(tally.udp_hosts),
        "udp_actions": udp_actions,
        "udp_stored_only": tally.udp_stored_only,
        "rules": [
            {
                "key": rule.key,
                "raised": stat.raised,
                "cleared": stat.cleared,
                "hosts": len(stat.hosts),
                "last_at": stat.last_at,
            }
            for rule in rules
            if (stat := tally.rules.get(rule.key)) is not None
        ],
        "triggers": dict(tally.triggers),
        "unmatched_tags": [_group_payload(g) for g in groups],
        "unknown_sources": [{"source_ip": ip, "count": s.count, "last_at": s.last_at} for ip, s in sources],
    }


async def analyze(hours: int, group_ids: Iterable[int] | None = None) -> dict:
    """What the rules (all of them, enabled or not) and triggers did with
    the syslog messages received in the last ``hours``, newest first, at
    most ``SCAN_LIMIT`` of them (``truncated`` when the window held more).
    ``group_ids``: only the messages of hosts in those inventory groups
    (object scope; messages from unknown sources are left out).

    While **Act on UDP messages** is off, a message that arrived over UDP
    and meets a rule or trigger is counted in ``udp_stored_only`` instead
    of as a match, as the receiver stores it and does nothing more. The
    switch is read now: the scan does not know what it was when a message
    arrived."""
    rules = await syslog_rules.get_rules()
    udp_actions = syslog_rules.receiver_flag("syslog_udp_actions")
    limit = SCAN_LIMIT
    seconds = int(hours) * 3600
    tally = _Tally()
    before_id: int | None = None
    truncated = False
    while True:
        want = min(PAGE_SIZE, limit - tally.scanned)
        if want <= 0:
            probe = await db.list_syslog_messages_since(seconds, before_id=before_id, limit=1, group_ids=group_ids)
            truncated = bool(probe)
            break
        page = await db.list_syslog_messages_since(seconds, before_id=before_id, limit=want, group_ids=group_ids)
        if page:
            await asyncio.to_thread(_aggregate, tally, rules, page, udp_actions)
            before_id = int(page[-1]["id"])
        if len(page) < want:
            break
    return _result(tally, rules, hours, limit, truncated, udp_actions)
