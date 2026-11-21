"""The filter rules of an OPNsense firewall, analysed for the rule views.

``analyze`` lists the rules of a ``config.xml``
(``netcontrol.integrations.pathtrace.opnsense_config.parse_document``) in
evaluation order, numbered as path traces number them, with their aliases
resolved, and flags each one:

- ``any_any``: an enabled pass rule from any source to any destination,
  any protocol and port;
- ``shadowed``: an enabled rule that never decides a flow because another
  enabled rule on every interface and direction it applies to, of its
  address family or both, takes every flow it matches first (pf: the first
  matching ``quick`` rule, else the last matching rule without ``quick``).
  Only provable coverage counts: both rules fully resolved, neither
  negated, the other's protocol, addresses and ports holding all of this
  rule's. ``shadow`` says whether the covering rule does the same
  (``redundant``) or the opposite (``conflicting``);
- ``disabled``;
- ``missing_alias``: the rule names an alias the configuration does not
  define (``missing_aliases``);
- ``unused``: the firewall's rule counters (``rule_stats``, read by the
  collection) show the enabled rule matched no packet since they were last
  reset. Without counters for a rule the flag is not set. The counters are
  keyed by the rule's pf label (``FilterRule.label``: the uuid of an MVC
  rule, the hash of a legacy one), and by its uuid as a fallback;
- ``unused_90d``: the stored counter history (``history``: the
  ``opnsense_rule_counters`` rows of the host by label, looked up as the
  counters are) shows the enabled rule was tracked for at least
  ``UNUSED_DAYS`` and its packet counter did not grow in the last
  ``UNUSED_DAYS`` of that tracking, across counter resets. Both spans end
  at the last read (or ``now`` when that is earlier), so a pause in the
  collections never counts as idle time. Each rule's ``history``
  (``rule_history``) says how long it was tracked, when it last matched
  and what it counted; ``None`` without a row.

``diff`` compares two configurations of the same firewall: rules matched
by their uuid (a legacy rule without one by what it matches), aliases by
name, port forwards, outbound and 1:1 NAT rules by uuid or what they match,
and the outbound NAT mode. ``rule_change_findings`` says which rules of
two configurations became any-to-any or shadowed (and which no longer
are), for the rule change alerts.

``parse_rule_stats`` reads the answer of ``firewall/filter_util/rule_stats``.

Pure (no I/O).
"""

from __future__ import annotations

import re
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.meraki.forwarding import ANY
from netcontrol.integrations.pathtrace.model import FULL, cover, net, ports_match
from netcontrol.integrations.pathtrace.opnsense_config import (
    TIERS,
    Endpoint,
    FilterRule,
    OpnsenseConfig,
    rule_bindings,
)
from netcontrol.integrations.traffic import parse_time

__all__ = [
    "FINDING_KINDS",
    "FLAGS",
    "UNUSED_DAYS",
    "analyze",
    "diff",
    "parse_rule_stats",
    "rule_change_findings",
    "rule_history",
    "rule_view",
]

FLAGS = ("any_any", "shadowed", "disabled", "missing_alias", "unused", "unused_90d")
# Days of counter history with no packet before an enabled rule is ``unused_90d``.
UNUSED_DAYS = 90
_USERINFO = re.compile(r"(\w+://)[^/@\s]+@")
# The counters kept of a rule's statistics.
_COUNTERS = ("evaluations", "packets", "bytes", "states", "pf_rules")
_RULE_FIELDS = (
    "action",
    "interfaces",
    "direction",
    "family",
    "protocol",
    "quick",
    "disabled",
    "description",
    "gateway",
    "log",
)


# ── Rule statistics ──────────────────────────────────────────────────────────


def parse_rule_stats(body: Any) -> dict[str, dict[str, int]]:
    """The counters by rule label (a rule's pf label) of a ``rule_stats``
    answer (``{"status": "ok", "stats": {label: {...}}}``, or the map alone)."""
    found = body.get("stats", body) if isinstance(body, dict) else None
    if not isinstance(found, dict):
        return {}
    stats: dict[str, dict[str, int]] = {}
    for label, counters in found.items():
        if not isinstance(counters, dict):
            continue
        kept = {}
        for name in _COUNTERS:
            value = counters.get(name)
            if isinstance(value, bool):
                continue
            if isinstance(value, int | float) or (isinstance(value, str) and value.isdigit()):
                kept[name] = int(value)
        if kept:
            stats[str(label)] = kept
    return stats


# ── Coverage ─────────────────────────────────────────────────────────────────


def _resolved(rule: FilterRule) -> bool:
    return not (
        rule.unresolved
        or rule.source.unresolved
        or rule.destination.unresolved
        or rule.source.negate
        or rule.destination.negate
    )


def _bindings_cover(outer: set[tuple[str, str]], inner: set[tuple[str, str]]) -> bool:
    return bool(inner) and inner <= outer


def _family_covers(outer: str, inner: str) -> bool:
    return outer == inner or outer == "inet46"


def _protocol_covers(outer: str, inner: str) -> bool:
    if outer in ("", "any"):
        return True
    if outer == inner:
        return True
    return outer == "tcp/udp" and inner in ("tcp", "udp")


def _addresses_cover(outer: Endpoint, inner: Endpoint, family: str) -> bool:
    if outer.cidrs == [ANY]:
        return True
    if inner.cidrs == [ANY]:
        return False
    for cidr in inner.cidrs:
        found = net(cidr)
        if found is None:
            return False
        if family in ("inet", "inet6") and ("inet6" if found.version == 6 else "inet") != family:
            continue  # pf leaves the other family's addresses out of the rule
        if cover(outer.cidrs, found) != FULL:
            return False
    return True


def _ports_cover(outer: Endpoint, inner: Endpoint) -> bool:
    if outer.ports is None:
        return True
    if inner.ports is None:
        return False
    expression = outer.port_expression
    return all(ports_match(expression, span) == FULL for span in inner.ports)


def covers(outer: FilterRule, inner: FilterRule, config: OpnsenseConfig) -> bool:
    """Whether every flow ``inner`` matches is matched by ``outer`` (provably)."""
    if not (_resolved(outer) and _resolved(inner)):
        return False
    return (
        _bindings_cover(rule_bindings(outer, config), rule_bindings(inner, config))
        and _family_covers(outer.family, inner.family)
        and _protocol_covers(outer.protocol, inner.protocol)
        and _addresses_cover(outer.source, inner.source, inner.family)
        and _addresses_cover(outer.destination, inner.destination, inner.family)
        and _ports_cover(outer.source, inner.source)
        and _ports_cover(outer.destination, inner.destination)
    )


def _shadowing(rule: FilterRule, config: OpnsenseConfig) -> FilterRule | None:
    """The rule that takes every flow ``rule`` matches before it decides, or ``None``."""
    if rule.disabled:
        return None
    others = [r for r in config.rules if r is not rule and not r.disabled]
    quick = [r for r in others if r.quick and (not rule.quick or r.number < rule.number)]
    for other in sorted(quick, key=lambda r: r.number):
        if covers(other, rule, config):
            return other
    if not rule.quick:
        later = [r for r in others if not r.quick and r.number > rule.number]
        for other in sorted(later, key=lambda r: r.number, reverse=True):
            if covers(other, rule, config):
                return other
    return None


# ── Views ────────────────────────────────────────────────────────────────────


def _endpoint(point: Endpoint) -> dict[str, Any]:
    return {
        "text": ("! " if point.negate else "") + point.text,
        "port": point.port_text or "any",
        "any": point.any,
        "negate": point.negate,
        "cidrs": list(point.cidrs),
        "ports": point.port_expression,
        "aliases": list(point.aliases),
        "missing_aliases": list(point.missing),
        "unresolved": list(point.unresolved),
    }


def rule_view(rule: FilterRule, config: OpnsenseConfig) -> dict[str, Any]:
    """One rule as the rules view shows it (without its flags)."""
    zones = config.zones(rule.interfaces) if rule.interfaces else ["*"]
    return {
        "number": rule.number,
        "key": rule.key,
        "uuid": rule.uuid,
        "label": rule.label,
        "tier": rule.tier,
        "action": rule.action,
        "interfaces": list(rule.interfaces),
        "zones": zones,
        "direction": rule.direction,
        "family": rule.family,
        "protocol": rule.protocol,
        "quick": rule.quick,
        "disabled": rule.disabled,
        "description": rule.description,
        "gateway": rule.gateway,
        "log": rule.log,
        "source": _endpoint(rule.source),
        "destination": _endpoint(rule.destination),
        "unresolved": list(rule.unresolved),
    }


def _any_any(rule: FilterRule) -> bool:
    return (
        rule.action == "pass"
        and not rule.disabled
        and rule.protocol in ("", "any")
        and rule.source.any
        and rule.destination.any
        and not rule.source.negate
        and not rule.destination.negate
        and rule.source.ports is None
        and rule.destination.ports is None
    )


def _counters_of(rule: FilterRule, stats: dict[str, Any]) -> Any:
    """A rule's counters (or counter history): by its pf label, else by its uuid."""
    for key in (rule.label, rule.uuid):
        if key and key in stats:
            return stats[key]
    return None


def rule_history(row: dict[str, Any] | None, now: datetime) -> dict[str, Any] | None:
    """A rule's counter history as the rules view shows it, from its stored
    row (``routes.db.opnsense_rule_counters``): when it was first and last
    read, when its packet counter last grew (``None`` when never),
    ``tracked_days`` (first read to last read), ``idle_days`` (last hit, else
    first read, to last read) and the packets and bytes counted, across
    resets. The spans end at ``now`` when the last read is later."""
    if not row:
        return None
    first = parse_time(row.get("first_seen_at"))
    if first is None:
        return None
    last_seen = parse_time(row.get("last_seen_at")) or first
    last_hit = parse_time(row.get("last_hit_at"))
    until = max(min(now, last_seen), first)
    return {
        "first_seen_at": row.get("first_seen_at"),
        "last_seen_at": row.get("last_seen_at") or None,
        "last_hit_at": row.get("last_hit_at") or None,
        "tracked_days": (until - first).days,
        "idle_days": max((until - (last_hit or first)).days, 0),
        "total_packets": int(row.get("total_packets") or 0),
        "total_bytes": int(row.get("total_bytes") or 0),
    }


def _unused_for_days(rule: FilterRule, history: dict[str, Any] | None) -> bool:
    return (
        history is not None
        and not rule.disabled
        and history["tracked_days"] >= UNUSED_DAYS
        and history["idle_days"] >= UNUSED_DAYS
    )


def analyze(
    config: OpnsenseConfig,
    stats: dict[str, dict[str, int]] | None = None,
    *,
    history: dict[str, dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The rules view of a configuration: interfaces, rules in evaluation
    order with their flags, counters and counter history, aliases, NAT and
    a summary. ``history``: the stored counter rows of the host by label
    (``None`` when not read); ``now`` defaults to the current time."""
    rules: list[dict[str, Any]] = []
    counted = stats is not None
    moment = now or datetime.now(UTC)
    for rule in config.rules:
        view = rule_view(rule, config)
        flags: list[str] = []
        if _any_any(rule):
            flags.append("any_any")
        shadow = _shadowing(rule, config)
        view["shadowed_by"] = shadow.number if shadow is not None else None
        view["shadow"] = ""
        if shadow is not None:
            flags.append("shadowed")
            same = (shadow.action == "pass") == (rule.action == "pass")
            view["shadow"] = "redundant" if same else "conflicting"
        if rule.disabled:
            flags.append("disabled")
        missing = list(dict.fromkeys([*rule.source.missing, *rule.destination.missing]))
        view["missing_aliases"] = missing
        if missing:
            flags.append("missing_alias")
        counters = _counters_of(rule, stats or {})
        view["stats"] = counters
        if counters is not None and not rule.disabled and counters.get("packets", 1) == 0:
            flags.append("unused")
        view["history"] = rule_history(_counters_of(rule, history or {}), moment)
        if _unused_for_days(rule, view["history"]):
            flags.append("unused_90d")
        view["flags"] = flags
        rules.append(view)
    summary = {flag: sum(1 for r in rules if flag in r["flags"]) for flag in FLAGS}
    summary["rules"] = len(rules)
    return {
        "hostname": config.hostname,
        "interfaces": [
            {
                "key": iface.key,
                "device": iface.device,
                "description": iface.description,
                "enabled": iface.enabled,
                "addresses": [pair[1] for pair in (iface.ipv4, iface.ipv6) if pair is not None],
                "dynamic": list(iface.dynamic),
            }
            for iface in config.interfaces.values()
        ],
        "groups": {name: list(members) for name, members in config.groups.items()},
        "tiers": list(TIERS),
        "rules": rules,
        "aliases": [_alias_view(alias) for alias in config.aliases.values()],
        "nat": _nat_view(config),
        "notes": list(config.notes),
        "stats_available": counted,
        "history_available": history is not None,
        "unused_days": UNUSED_DAYS,
        "summary": summary,
    }


def _alias_view(alias: Any) -> dict[str, Any]:
    return {
        "name": alias.name,
        "type": alias.type,
        # A URL table may name its credentials in the URL: they are never shown.
        "content": [_USERINFO.sub(r"\1***@", entry) for entry in alias.content],
        "description": alias.description,
        "enabled": alias.enabled,
    }


def _nat_view(config: OpnsenseConfig) -> dict[str, Any]:
    return {
        "outbound_mode": config.outbound_mode,
        "port_forwards": [
            {
                "key": f.key,
                "interfaces": list(f.interfaces),
                "protocol": f.protocol,
                "source": _endpoint(f.source),
                "destination": _endpoint(f.destination),
                "target": f.target,
                "local_port": f.local_port,
                "disabled": f.disabled,
                "no_redirect": f.no_redirect,
                "filter_rule": f.filter_rule,
                "description": f.description,
            }
            for f in config.port_forwards
        ],
        "outbound": [
            {
                "key": r.key,
                "origin": r.origin,
                "interface": r.interface,
                "protocol": r.protocol,
                "source": _endpoint(r.source),
                "destination": _endpoint(r.destination),
                "target": r.target or "interface address",
                "no_nat": r.no_nat,
                "disabled": r.disabled,
                "description": r.description,
            }
            for r in config.outbound
        ],
        "one_to_one": [
            {
                "key": r.key,
                "interface": r.interface,
                "external": r.external,
                "source": _endpoint(r.source),
                "destination": _endpoint(r.destination),
                "type": r.type,
                "disabled": r.disabled,
                "description": r.description,
            }
            for r in config.one_to_one
        ],
    }


# ── Diff ─────────────────────────────────────────────────────────────────────


def _rule_fields(rule: FilterRule) -> dict[str, Any]:
    found = {name: getattr(rule, name) for name in _RULE_FIELDS}
    found["source"] = f"{'! ' if rule.source.negate else ''}{rule.source.text} port {rule.source.port_text or 'any'}"
    found["destination"] = (
        f"{'! ' if rule.destination.negate else ''}{rule.destination.text} port {rule.destination.port_text or 'any'}"
    )
    return found


def _changes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"field": name, "before": before.get(name), "after": after.get(name)}
        for name in dict.fromkeys([*before, *after])
        if before.get(name) != after.get(name)
    ]


def _keyed(items: list[Any]) -> dict[str, Any]:
    return {item.key: item for item in items}


def _plain(item: Any) -> dict[str, Any]:
    """A NAT rule's configured fields (resolved addresses left out)."""
    found = asdict(item)
    for side in ("source", "destination"):
        point = found.pop(side, None)
        if isinstance(point, dict):
            negate = "! " if point.get("negate") else ""
            found[side] = f"{negate}{point.get('text')} port {point.get('port_text') or 'any'}"
    for name in ("key", "uuid", "target_cidrs", "unresolved"):
        found.pop(name, None)
    return found


def _diff_items(before: list[Any], after: list[Any], view) -> dict[str, list[dict[str, Any]]]:
    old, new = _keyed(before), _keyed(after)
    changed = []
    for key in old.keys() & new.keys():
        fields = _changes(view(old[key]), view(new[key]))
        if fields:
            changed.append({"key": key, "before": view(old[key]), "after": view(new[key]), "changes": fields})
    return {
        "added": [{"key": key, "after": view(new[key])} for key in new if key not in old],
        "removed": [{"key": key, "before": view(old[key])} for key in old if key not in new],
        "changed": sorted(changed, key=lambda c: str(c["key"])),
    }


def diff(before: OpnsenseConfig, after: OpnsenseConfig) -> dict[str, Any]:
    """What changed between two configurations of one firewall."""
    old, new = _keyed(before.rules), _keyed(after.rules)
    common = [r.key for r in before.rules if r.key in new]
    rank_after = {key: i for i, key in enumerate(r.key for r in after.rules if r.key in old)}
    rules_changed = []
    for rank, key in enumerate(common):
        fields = _changes(_rule_fields(old[key]), _rule_fields(new[key]))
        moved = rank_after.get(key) != rank
        if fields or moved:
            rules_changed.append(
                {
                    "key": key,
                    "number_before": old[key].number,
                    "number_after": new[key].number,
                    "moved": moved,
                    "changes": fields,
                    "before": rule_view(old[key], before),
                    "after": rule_view(new[key], after),
                }
            )
    rules = {
        "added": [rule_view(r, after) for r in after.rules if r.key not in old],
        "removed": [rule_view(r, before) for r in before.rules if r.key not in new],
        "changed": rules_changed,
    }
    old_aliases = {name: _alias_view(a) for name, a in before.aliases.items()}
    new_aliases = {name: _alias_view(a) for name, a in after.aliases.items()}
    aliases = {
        "added": [new_aliases[n] for n in new_aliases if n not in old_aliases],
        "removed": [old_aliases[n] for n in old_aliases if n not in new_aliases],
        "changed": [
            {"name": n, "changes": _changes(old_aliases[n], new_aliases[n])}
            for n in old_aliases
            if n in new_aliases and old_aliases[n] != new_aliases[n]
        ],
    }
    parts = {
        "port_forwards": _diff_items(before.port_forwards, after.port_forwards, _plain),
        "outbound": _diff_items(before.outbound, after.outbound, _plain),
        "one_to_one": _diff_items(before.one_to_one, after.one_to_one, _plain),
    }
    mode = (
        {"before": before.outbound_mode, "after": after.outbound_mode}
        if before.outbound_mode != after.outbound_mode
        else None
    )
    counts = {
        "rules": sum(len(v) for v in rules.values()),
        "aliases": sum(len(v) for v in aliases.values()),
        "nat": sum(len(v) for part in parts.values() for v in part.values()) + (1 if mode else 0),
    }
    return {"rules": rules, "aliases": aliases, "nat": {"outbound_mode": mode, **parts}, "summary": counts}


# ── Rule change findings ─────────────────────────────────────────────────────

# The flags a configuration change is alerted on when it brings them in
# (``netcontrol.routes.opnsense_rule_alerts``).
FINDING_KINDS = ("any_any", "shadowed")


def _finding(view: dict[str, Any], kind: str, keys: dict[int, str]) -> dict[str, Any]:
    """One flagged rule of an ``analyze`` view as a finding: the parsed rule
    fields an operator needs, never alias contents."""
    shadowed = kind == "shadowed"
    return {
        "kind": kind,
        "key": view["key"],
        "number": view["number"],
        "interfaces": list(view["interfaces"]),
        "direction": view["direction"],
        "family": view["family"],
        "protocol": view["protocol"],
        "action": view["action"],
        "source": view["source"]["text"],
        "source_port": view["source"]["port"],
        "destination": view["destination"]["text"],
        "destination_port": view["destination"]["port"],
        "description": view["description"],
        "shadowed_by": view["shadowed_by"] if shadowed else None,
        "shadowed_by_key": keys.get(view["shadowed_by"]) if shadowed else None,
        "shadow": view["shadow"] if shadowed else "",
    }


def _findings(config: OpnsenseConfig) -> dict[tuple[str, str], dict[str, Any]]:
    """The any-to-any and shadowed rules of a configuration by (kind, rule
    key), in evaluation order. Disabled rules carry neither flag."""
    views = analyze(config)["rules"]
    keys = {view["number"]: view["key"] for view in views}
    return {
        (kind, str(view["key"])): _finding(view, kind, keys)
        for view in views
        for kind in FINDING_KINDS
        if kind in view["flags"]
    }


def rule_change_findings(before: OpnsenseConfig, after: OpnsenseConfig) -> dict[str, Any]:
    """The risky flags a change from ``before`` to ``after`` brings in or
    takes away, rules matched by their key as ``diff`` matches them:

    - ``new``: the rules any-to-any in ``after`` and not in ``before`` (a new
      rule, or one widened or enabled), and the rules shadowed in ``after``
      and not in ``before`` (a new rule shadowed on arrival, or a rule a new,
      moved or widened rule now covers), numbered as in ``after``;
    - ``gone``: the findings of ``before`` that ``after`` no longer has,
      numbered as in ``before``;
    - ``summary``: how many new findings of each kind."""
    old, new = _findings(before), _findings(after)
    added = [finding for key, finding in new.items() if key not in old]
    return {
        "new": added,
        "gone": [finding for key, finding in old.items() if key not in new],
        "summary": {kind: sum(1 for f in added if f["kind"] == kind) for kind in FINDING_KINDS},
    }
