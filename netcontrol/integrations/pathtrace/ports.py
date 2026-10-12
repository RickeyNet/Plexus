"""Which ports of which protocol a rule set lets through.

A port set says, for each protocol the trace asks about (``tcp``, ``udp``
and ``icmp`` for any traffic, else the one asked), the status of every port
asked about (one port, or 0-65535): ``ok`` (allowed), ``partial`` (allowed
for only part of the addresses asked about), ``unknown`` (a rule Plexus
cannot evaluate matched, rules were cut at collection, the default action
or the rule set itself was not collected) or ``blocked``. ICMP has no
ports: the whole protocol has one status. Sets combine port by port, the
worst status winning, as ``model.worst`` ranks them.

Rules are seen through ``Match``: how much of the addresses asked about a
rule covers (``FULL``, ``PART`` or ``NONE``, as in ``model``), its protocol,
the ports on the side the set enumerates (the destination port of a
request, the source port of a reply), the ports on the other side, and its
action. ``first_match`` evaluates an ordered rule set the way the tracer's
rule set evaluator does, so a set asked about every port agrees with the
status the tracer gives for any one of them; ``allow_list`` evaluates an
unordered union of allow rules (AWS security groups).

Self-contained (``aws.reachability`` uses it, and ``model`` imports that
module); the statuses and covers are the values ``model`` uses. Pure (no I/O).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

OK, BLOCKED, PARTIAL, UNKNOWN = "ok", "blocked", "partial", "unknown"
FULL, PART, NONE = 2, 1, 0
PROTOCOLS = ("tcp", "udp", "icmp")
ALL_PORTS = (0, 65535)

_RANK = {OK: 0, PARTIAL: 1, UNKNOWN: 2, BLOCKED: 3}
_ALLOWING = ("allow", "trust", "fastpath", "analyze")
_ANY_PROTOCOL = ("", "any", "all", "ip", "-1")
_PROTOCOL_NUMBERS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
_WORDS = ((OK, "allowed", "allowed"), (PARTIAL, "partial", "in part"), (UNKNOWN, "unknown", "not decided"))

Segment = tuple[int, int, str]
Range = tuple[int, int]


@dataclass(frozen=True)
class Asked:
    """The traffic asked about: ``protocol`` (``""``: any), the ports of the
    side the set enumerates and those of the other side (``None``: every port)."""

    protocol: str
    ports: tuple[int, int] | None = None
    fixed: tuple[int, int] | None = None

    @property
    def protocols(self) -> tuple[str, ...]:
        return (self.protocol,) if self.protocol else PROTOCOLS

    def span(self, protocol: str) -> Range:
        """The ports asked about of ``protocol`` (ICMP: a single position)."""
        if protocol == "icmp":
            return (0, 0)
        return self.ports or ALL_PORTS


@dataclass(frozen=True)
class Match:
    """One rule: ``cover`` of the addresses (and zones, selectors...) asked
    about, ``protocol``, ``ports`` on the enumerated side (an expression such
    as ``"80,443"``, a ``(low, high)`` pair or a list of them, ``None`` for
    every port; ``None`` in a pair is an open end, as AWS writes it),
    ``action``, ``other_ports`` (an expression matched against
    ``Asked.fixed``) and ``unresolved`` (it also matches on something
    Plexus cannot evaluate)."""

    cover: int
    protocol: str
    ports: Any
    action: str
    other_ports: Any = None
    unresolved: bool = False


@dataclass(frozen=True)
class Ports:
    """Per protocol, sorted segments ``(low, high, status)`` covering the
    ports asked about."""

    asked: Asked
    segments: dict[str, tuple[Segment, ...]] = field(default_factory=dict)


# ── Ranges ──────────────────────────────────────────────────────────────────


def _protocol(raw: Any) -> str:
    """A rule's protocol, normalised as ``model.protocol_match`` reads it
    (``any`` for every protocol)."""
    text = str(raw or "").strip().lower()
    text = _PROTOCOL_NUMBERS.get(text, text)
    return "any" if text in _ANY_PROTOCOL else text


def _pair(low: Any, high: Any) -> Range:
    if low is None and high is None:
        return ALL_PORTS
    low = 0 if low is None else int(low)
    return (low, low if high is None else int(high))


def _ranges(expression: Any) -> list[Range] | None:
    """The port ranges of an expression; ``None`` when it cannot be read
    (``model.ports_match`` counts such a rule as covering in part)."""
    if expression is None:
        return [ALL_PORTS]
    if isinstance(expression, tuple) and len(expression) == 2 and not isinstance(expression[0], tuple):
        return [_pair(*expression)]
    if isinstance(expression, list):
        found: list[Range] = []
        for each in expression:
            if isinstance(each, tuple):
                found.append(_pair(*each))
                continue
            parsed = _ranges(each)
            if parsed is None:
                return None
            found.extend(parsed)
        return found or [ALL_PORTS]
    text = str(expression or "").strip().lower()
    if text in ("", "any", "*"):
        return [ALL_PORTS]
    ranges: list[Range] = []
    for part in text.replace(" ", "").split(","):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not match:
            return None
        ranges.append(_pair(int(match.group(1)), int(match.group(2) or match.group(1))))
    return ranges


def _merge(ranges: list[Range]) -> list[Range]:
    merged: list[Range] = []
    for low, high in sorted(ranges):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return merged


def _clip(ranges: list[Range], span: Range) -> list[Range]:
    return _merge(
        [(max(low, span[0]), min(high, span[1])) for low, high in ranges if low <= span[1] and high >= span[0]]
    )


def _subtract(ranges: list[Range], taken: list[Range]) -> list[Range]:
    left = list(ranges)
    for t_low, t_high in taken:
        kept: list[Range] = []
        for low, high in left:
            if t_high < low or t_low > high:
                kept.append((low, high))
                continue
            if low < t_low:
                kept.append((low, t_low - 1))
            if high > t_high:
                kept.append((t_high + 1, high))
        left = kept
    return left


def _intersect(a: list[Range], b: list[Range]) -> list[Range]:
    return _merge([(max(l1, l2), min(h1, h2)) for l1, h1 in a for l2, h2 in b if l1 <= h2 and l2 <= h1])


def _fixed_cover(expression: Any, ports: tuple[int, int] | None) -> int:
    """How much of ``ports`` (``None``: any port) an expression covers, as
    ``model.ports_match`` says."""
    ranges = _ranges(expression)
    if ranges is None:
        return PART
    if any(low <= 0 and high >= 65535 for low, high in ranges):
        return FULL
    if ports is None:
        return PART
    if any(low <= ports[0] and ports[1] <= high for low, high in ranges):
        return FULL
    if any(not (ports[1] < low or ports[0] > high) for low, high in ranges):
        return PART
    return NONE


def _family(action: str) -> str:
    if action in _ALLOWING:
        return "allow"
    return "deny" if action == "deny" else action


def _normalise(segments: list[Segment]) -> tuple[Segment, ...]:
    """Sorted, adjacent segments of one status joined."""
    joined: list[Segment] = []
    for low, high, status in sorted(segments):
        if joined and joined[-1][2] == status and low == joined[-1][1] + 1:
            joined[-1] = (joined[-1][0], high, status)
        else:
            joined.append((low, high, status))
    return tuple(joined)


def _worse(a: str, b: str) -> str:
    return a if _RANK[a] >= _RANK[b] else b


# ── Building sets ───────────────────────────────────────────────────────────


def uniform(status: str, asked: Asked) -> Ports:
    """Every port asked about with one status."""
    return Ports(asked, {p: ((*asked.span(p), status),) for p in asked.protocols})


def _rule_ranges(rule: Match, protocol: str, asked: Asked) -> tuple[list[Range], int]:
    """The ports asked about a rule covers for ``protocol``, and how much of
    the addresses and the other side's ports it covers."""
    span = asked.span(protocol)
    if protocol == "icmp":
        return [span], rule.cover
    cover = min(rule.cover, _fixed_cover(rule.other_ports, asked.fixed))
    ranges = _ranges(rule.ports)
    if ranges is None:
        ranges, cover = [ALL_PORTS], min(cover, PART)
    return _clip(ranges, span), cover


def _targets(rule: Match, asked: Asked) -> tuple[str, ...]:
    protocol = _protocol(rule.protocol)
    if protocol == "any":
        return asked.protocols
    return (protocol,) if protocol in asked.protocols else ()


def _decide(free: list[Range], status: str, family: str, pending: list[tuple[int, int, str]]) -> list[Segment]:
    """``free`` decided ``status``; where an earlier rule that covers part of
    the addresses goes the other way, an allow or deny is partial."""
    if status not in (OK, BLOCKED):
        return [(low, high, status) for low, high in free]
    other = _merge([(low, high) for low, high, f in pending if f != family])
    partial = _intersect(free, other)
    rest = _subtract(free, partial)
    return [(low, high, PARTIAL) for low, high in partial] + [(low, high, status) for low, high in rest]


def first_match(rules: list[Match], asked: Asked, default: str, complete: bool = True) -> Ports:
    """An ordered rule set where the first rule that covers a port decides
    it; ``default`` (``allow``, ``deny``, anything else: not known) decides
    the rest, unless the rules were cut at collection (``complete`` false)."""
    decided: dict[str, list[Segment]] = {p: [] for p in asked.protocols}
    pending: dict[str, list[tuple[int, int, str]]] = {p: [] for p in asked.protocols}
    for rule in rules:
        if rule.cover == NONE:
            continue
        for protocol in _targets(rule, asked):
            ranges, cover = _rule_ranges(rule, protocol, asked)
            if cover == NONE:
                continue
            free = _subtract(ranges, [(low, high) for low, high, _s in decided[protocol]])
            if not free:
                continue
            if cover == PART:
                if rule.action != "monitor":
                    pending[protocol].extend((low, high, _family(rule.action)) for low, high in free)
                continue
            if rule.unresolved:
                decided[protocol].extend((low, high, UNKNOWN) for low, high in free)
                continue
            if rule.action == "monitor":
                continue
            status = BLOCKED if rule.action == "deny" else OK if rule.action in _ALLOWING else UNKNOWN
            decided[protocol].extend(_decide(free, status, _family(rule.action), pending[protocol]))
    segments: dict[str, tuple[Segment, ...]] = {}
    for protocol in asked.protocols:
        free = _subtract([asked.span(protocol)], [(low, high) for low, high, _s in decided[protocol]])
        if not complete:
            rest = [(low, high, UNKNOWN) for low, high in free]
        else:
            status = OK if default == "allow" else BLOCKED if default == "deny" else UNKNOWN
            rest = _decide(free, status, _family(default), pending[protocol])
        segments[protocol] = _normalise(decided[protocol] + rest)
    return Ports(asked, segments)


def allow_list(rules: list[Match], asked: Asked, missing: bool = False) -> Ports:
    """A union of allow rules: what a rule covering all the addresses allows
    is allowed, what one covering part of them allows is partial, the rest
    is denied (not known when a part of the list was not collected)."""
    allowed: dict[str, list[Range]] = {p: [] for p in asked.protocols}
    partly: dict[str, list[Range]] = {p: [] for p in asked.protocols}
    for rule in rules:
        if rule.cover == NONE:
            continue
        for protocol in _targets(rule, asked):
            ranges, cover = _rule_ranges(rule, protocol, asked)
            if cover == FULL:
                allowed[protocol].extend(ranges)
            elif cover == PART:
                partly[protocol].extend(ranges)
    rest = UNKNOWN if missing else BLOCKED
    segments: dict[str, tuple[Segment, ...]] = {}
    for protocol in asked.protocols:
        span = [asked.span(protocol)]
        ok = _merge(allowed[protocol])
        part = _subtract(_merge(partly[protocol]), ok)
        left = _subtract(_subtract(span, ok), part)
        found = [(lo, hi, OK) for lo, hi in ok] + [(lo, hi, PARTIAL) for lo, hi in part]
        segments[protocol] = _normalise(found + [(lo, hi, rest) for lo, hi in left])
    return Ports(asked, segments)


def combine(a: Ports, b: Ports) -> Ports:
    """Port by port, the worse of two sets."""
    segments: dict[str, tuple[Segment, ...]] = {}
    for protocol in dict.fromkeys([*a.segments, *b.segments]):
        first, second = a.segments.get(protocol, ()), b.segments.get(protocol, ())
        if not first or not second:
            segments[protocol] = first or second
            continue
        bounds = sorted({s[0] for s in first + second} | {s[1] + 1 for s in first + second})
        found: list[Segment] = []
        for low, nxt in zip(bounds, bounds[1:], strict=False):
            statuses = [s[2] for s in first + second if s[0] <= low <= s[1]]
            if statuses:
                status = statuses[0]
                for other in statuses[1:]:
                    status = _worse(status, other)
                found.append((low, nxt - 1, status))
        segments[protocol] = _normalise(found)
    return Ports(a.asked, segments)


def status_of(ports: Ports, protocol: str, port: int | None = None) -> str:
    """The status of one port (ICMP, or ``None``: the first one asked about)."""
    segments = ports.segments[protocol]
    if protocol == "icmp" or port is None:
        return segments[0][2]
    return next(status for low, high, status in segments if low <= port <= high)


# ── JSON ────────────────────────────────────────────────────────────────────


def _show(ranges: list[Range]) -> str:
    if any(low <= 1 and high >= 65535 for low, high in ranges):
        return "any"
    return ", ".join(str(low) if low == high else f"{low}-{high}" for low, high in ranges)


def _phrase(found: dict[str, str]) -> str:
    return " · ".join("icmp" if p == "icmp" else f"{p} {found[p]}" for p in PROTOCOLS if p in found)


def to_json(ports: Ports) -> dict[str, Any]:
    """``{"allowed": {"tcp": "80, 443"}, "partial": {...}, "unknown": {...},
    "text": "allowed tcp 80, 443; ..."}``; ports listed nowhere are denied."""
    result: dict[str, Any] = {}
    phrases: list[str] = []
    for status, key, word in _WORDS:
        found: dict[str, str] = {}
        for protocol in PROTOCOLS:
            ranges = _merge([(lo, hi) for lo, hi, s in ports.segments.get(protocol, ()) if s == status])
            if ranges:
                found[protocol] = "any" if protocol == "icmp" else _show(ranges)
        result[key] = found
        if found:
            phrases.append(f"{word} {_phrase(found)}")
        elif status == OK:
            phrases.append("allowed none")
    result["text"] = "; ".join(phrases)
    return result


def from_json(data: dict[str, Any], asked: Asked) -> Ports:
    """A set back from its JSON, over the ports ``asked``. When one port is
    asked about, a protocol listed under a status has it whatever port it
    names: a destination NAT may have changed the port a later rule set saw."""
    single = asked.ports is not None and asked.ports[0] == asked.ports[1]
    segments: dict[str, tuple[Segment, ...]] = {}
    for protocol in asked.protocols:
        span = asked.span(protocol)
        found: list[Segment] = [(*span, BLOCKED)]
        for status, key, _word in _WORDS:
            text = (data.get(key) or {}).get(protocol)
            if not text:
                continue
            if single or protocol == "icmp" or text == "any":
                ranges = [span]
            else:
                ranges = _clip(_ranges(text) or [], span)
            for low, high in ranges:
                found = _paint(found, low, high, status)
        segments[protocol] = _normalise(found)
    return Ports(asked, segments)


def _paint(segments: list[Segment], low: int, high: int, status: str) -> list[Segment]:
    """``segments`` with ``low``-``high`` set to ``status``."""
    painted = [(lo, hi, s) for s_low, s_high, s in segments for lo, hi in _subtract([(s_low, s_high)], [(low, high)])]
    return sorted([*painted, (low, high, status)])
