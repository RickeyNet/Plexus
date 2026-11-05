"""Cato Network Rules: which rule routes a flow to the internet, and the
public address it leaves Cato with.

Cato's Network Rules policy (``policy.wanNetwork``, "Network Rules" in the
Cato Management Application) decides, per flow, how traffic leaves the
Cato Cloud: an ``INTERNET`` rule's route is ``NAT`` (out of one of the
account's allocated IPs), ``VIA`` (out of a chosen PoP), ``BACKHAUL`` (out of
a site's own internet connection), ``OPTIMIZED`` (the PoP Cato picks nearest
the destination) or ``NONE`` (the PoP the flow is on). The first enabled
rule that matches applies; an exception of a rule excludes the traffic it
names. With no rule matching, Cato's default is the PoP the flow is on
("By default, traffic will egress from connected PoP", Cato's schema).

A rule matches on source, destination and application. Sources and
destinations name addresses (IPs, ranges, sites, users, groups...), which
``normalize.network_rule_policy`` resolves into CIDRs with the address book
the firewall rules use. The application field can be decided from an
address and port (global IP ranges, groups of addresses, custom services,
custom applications defined by destination IP, port or protocol) or only
by name: a domain, an FQDN, an application, an app category, a custom
category, a custom application defined by domain. Cato tells those from the
hostname it sees (its DNS, the TLS SNI) or from application identification;
a connection made to a bare IP gives it no name. So a trace, which knows
addresses only, follows the first rule that matches on addresses (the
"bare IP" path) and lists every earlier rule that matches only by name,
with the route it would take. What cannot be resolved (a users group whose
members were not read, a custom application whose definition was not
collected) makes a rule one that may apply: unknown, never guessed.

The address a NAT rule leaves with is read from the account's allocated IP
list (``popLocations.allocatedIpList``) by the allocated IP's id, else from
the reference's name ("NAT IP Ashburn - 192.0.2.101"). Every other route
leaves behind a shared Cato address that the API does not report.

``evaluate`` is pure and takes the compiled policy (see
``normalize.network_rule_policy``; the Cato Cloud's forwarding block
carries it as ``egress_policy``), so a background check can call it without
the tracer; ``trace_egress`` words its result as path trace items. Only the
standard library and the path trace's model are imported: the HTML export
runs this module in the browser (``pathtrace.offline.MODULES``).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from netcontrol.integrations.pathtrace.model import (
    FULL,
    INFO,
    NAT,
    NONE,
    OK,
    PART,
    PARTIAL,
    ROUTE,
    UNKNOWN,
    Network,
    cover,
    ports_match,
    protocol_match,
    show,
)

# The ``kind`` of a compiled policy, which the tracer dispatches on.
KIND = "cato_network_rules"
NAME = "Network rules"
EGRESS = "Cato egress address"

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Routes that leave Cato from a PoP's shared address.
_SHARED = ("NONE", "VIA", "OPTIMIZED")
_BACKHAUL = ("BACKHAUL", "BACKHAUL_HAIRPINNING")
_YES, _NO, _PARTLY, _BY_NAME, _MAYBE = "yes", "no", "part", "name", "unknown"


def not_collected() -> dict[str, Any]:
    """The compiled policy of an account whose network rules were not read."""
    return {
        "kind": KIND,
        "name": NAME,
        "collected": False,
        "enabled": True,
        "reduced": False,
        "rules": [],
        "allocated": None,
    }


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _ref_name(ref: Any) -> str:
    return _text(ref.get("name") or ref.get("id")) if isinstance(ref, dict) else _text(ref)


def _address_in(text: str) -> str:
    """The IPv4 address written in ``text``, else ``""``."""
    for found in _IPV4.findall(text):
        try:
            return str(ipaddress.ip_address(found))
        except ValueError:
            continue
    return ""


def allocated_addresses(allocated: Any) -> list[dict[str, str]] | None:
    """The account's allocated IP list as collected
    (``popLocations.allocatedIpList``) as ``[{"ip", "pop"}]``, ``None`` when
    it was not collected."""
    if allocated is None:
        return None
    found: list[dict[str, str]] = []
    for entry in _list(allocated):
        address = _address_in(_text(entry.get("ip"))) if isinstance(entry, dict) else ""
        if address:
            found.append({"ip": address, "pop": _ref_name(entry.get("popLocation"))})
    return found


def egress_of(rule: dict, allocated: Any = None) -> dict[str, Any]:
    """The route of a raw network rule and where it leaves Cato:
    ``{"route", "addresses": [{"ip", "label", "pop", "from"}],
    "unresolved": [names], "pops": [names], "sites": [names]}``.

    ``allocated`` is the account's allocated IP list as collected
    (``{"id", "ip", "popLocation": {"name"}}`` each), or ``None`` when it
    was not: a NAT rule's allocated IP is found there by id, else its
    address is read from its name; one that has neither is unresolved."""
    raw_config = rule.get("configuration")
    config: dict = raw_config if isinstance(raw_config, dict) else {}
    by_id = {_text(a.get("id")): a for a in _list(allocated) if isinstance(a, dict) and _text(a.get("id"))}
    addresses: list[dict[str, str]] = []
    unresolved: list[str] = []
    for ref in _list(config.get("allocationIp")):
        label = _ref_name(ref)
        listed = by_id.get(_text(ref.get("id"))) if isinstance(ref, dict) else None
        address, source = "", ""
        if listed is not None and _address_in(_text(listed.get("ip"))):
            address, source = _address_in(_text(listed.get("ip"))), "allocated IP list"
        elif _address_in(label):
            address, source = _address_in(label), "its name"
        if not address:
            unresolved.append(label)
            continue
        pop = _ref_name((listed or {}).get("popLocation")) if listed else ""
        addresses.append({"ip": address, "label": label, "pop": pop, "from": source})
    return {
        "route": _text(rule.get("routeType")).upper() or "NONE",
        "addresses": addresses,
        "unresolved": unresolved,
        "pops": [_ref_name(p) for p in _list(config.get("popLocation")) if _ref_name(p)],
        "sites": [_ref_name(s) for s in _list(config.get("backhaulingSite")) if _ref_name(s)],
    }


# ── Matching ────────────────────────────────────────────────────────────────


def _service_cover(services: list, protocol: str, ports: tuple[int, int] | None) -> int:
    """How much of the traffic asked about any ``[protocol, ports]`` covers."""
    best = NONE
    for entry in services:
        rule_protocol, expression = (list(entry) + ["any", "any"])[:2]
        icmp = protocol.startswith("icmp")
        best = max(
            best,
            min(protocol_match(rule_protocol, protocol), FULL if icmp else ports_match(expression, ports)),
        )
    return best


def _criterion(criterion: dict, dst: Network, protocol: str, ports: tuple[int, int] | None) -> int | str:
    kind = criterion.get("kind")
    if kind == "name":
        return _BY_NAME
    if kind not in ("ip", "service"):
        return _MAYBE
    # An address criterion with no CIDR (a group with no address now) matches nothing.
    found = cover(criterion.get("cidrs") or [], dst) if kind == "ip" else FULL
    if criterion.get("services"):
        found = min(found, _service_cover(criterion["services"], protocol, ports))
    return found


def _application(
    criteria: list[dict], dst: Network, protocol: str, ports: tuple[int, int] | None
) -> tuple[str, list[str]]:
    """Whether a rule's application field matches: ``yes``, ``no``,
    ``part``, ``name`` (only what Cato identifies by name could) or
    ``unknown``, with the criteria that leave it so. An empty field is any
    application."""
    if not criteria:
        return _YES, []
    named: list[str] = []
    partly: list[str] = []
    doubtful: list[str] = []
    for criterion in criteria:
        found = _criterion(criterion, dst, protocol, ports)
        text = _text(criterion.get("text"))
        if found == FULL:
            return _YES, []
        if found == _BY_NAME:
            named.append(text)
        elif found == _MAYBE:
            doubtful.append(text)
        elif found == PART:
            partly.append(text)
    if doubtful:
        return _MAYBE, doubtful
    if partly:
        return _PARTLY, partly
    if named:
        return _BY_NAME, named
    return _NO, []


def _matches(
    entry: dict, src: Network, dst: Network, protocol: str, ports: tuple[int, int] | None
) -> tuple[str, list[str]]:
    """Whether a rule (or an exception) matches a flow: ``yes``, ``no``,
    ``part``, ``name`` or ``unknown``, and why it is not a plain yes."""
    src_cover, dst_cover = cover(entry.get("src"), src), cover(entry.get("dst"), dst)
    if src_cover == NONE or dst_cover == NONE:
        return _NO, []
    state, detail = _application(entry.get("app") or [], dst, protocol, ports)
    if state == _NO:
        return _NO, []
    unresolved = [_text(u) for u in (entry.get("src_unresolved") or []) + (entry.get("dst_unresolved") or [])]
    if unresolved:
        return _MAYBE, unresolved + (detail if state == _MAYBE else [])
    if src_cover == PART or dst_cover == PART:
        what = "the source" if src_cover == PART else "the destination"
        return (_PARTLY, [f"part of {what}"]) if state in (_YES, _PARTLY) else (state, detail)
    return state, detail


def evaluate(
    policy: Any, src: Network, dst: Network, protocol: str = "", ports: tuple[int, int] | None = None
) -> dict[str, Any]:
    """The network rule that routes a flow from ``src`` to ``dst`` to the
    internet, for a connection made to the bare IP ``dst``.

    Returns ``state``: ``not_collected``, ``reduced`` (read with the reduced
    query, the match fields missing), ``disabled``, ``matched`` (``rule``
    is the first rule that matches on addresses) or ``default`` (none does:
    Cato egresses from the connected PoP); ``candidates``, the enabled
    rules ahead of it that may match instead (``why``: ``name``, matched only
    if Cato identifies the traffic by name; ``unknown``, a criterion or an
    exception that cannot be resolved; ``part``, part of the traffic asked
    about), each with ``detail``; ``skipped``, the rules ahead whose
    exception excludes the flow; and ``caveats``, the matched rule's
    exceptions that exclude it only by name."""
    found: dict[str, Any] = {"state": "", "rule": None, "candidates": [], "skipped": [], "caveats": []}
    if not isinstance(policy, dict) or not policy.get("collected"):
        return {**found, "state": "not_collected"}
    if policy.get("reduced"):
        return {**found, "state": "reduced"}
    if policy.get("enabled", True) is False:
        return {**found, "state": "disabled"}
    protocol = _text(protocol).lower()
    for rule in policy.get("rules") or []:
        if not isinstance(rule, dict) or rule.get("enabled", True) is False:
            continue
        state, detail = _matches(rule, src, dst, protocol, ports)
        if state == _NO:
            continue
        if state != _YES:
            found["candidates"].append({"rule": rule, "why": state, "detail": detail})
            continue
        caveats: list[dict] = []
        excluded: dict | None = None
        doubt: dict | None = None
        for exception in rule.get("exceptions") or []:
            ex_state, ex_detail = _matches(exception, src, dst, protocol, ports)
            name = _text(exception.get("name")) or "unnamed"
            if ex_state == _NO:
                continue
            if ex_state == _YES:
                excluded = {"rule": rule, "exception": name}
                break
            if ex_state == _BY_NAME:
                caveats.append({"exception": name, "detail": ex_detail})
            else:
                doubt = {"rule": rule, "why": _MAYBE, "detail": [f"its exception {name} ({', '.join(ex_detail)})"]}
                break
        if excluded is not None:
            found["skipped"].append(excluded)
            continue
        if doubt is not None:
            found["candidates"].append(doubt)
            continue
        return {**found, "state": "matched", "rule": rule, "caveats": caveats}
    return {**found, "state": "default"}


# ── Path trace items ────────────────────────────────────────────────────────


def _label(rule: dict) -> str:
    name = _text(rule.get("name"))
    return f"Rule {rule.get('index')} {name}".strip() if name else f"Rule {rule.get('index')}"


def _and(names: list[str]) -> str:
    if len(names) <= 1:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def _address_text(entry: dict) -> str:
    where = f", PoP {entry['pop']}" if entry.get("pop") else ""
    origin = ", address read from its name" if entry.get("from") == "its name" else ""
    return f"{entry['ip']} ({entry['label']}{where}{origin})"


def _route_text(egress: dict) -> tuple[str, str]:
    """``(what the route does, why the address it leaves with is not known)``;
    the second is ``""`` when the allocated IPs are known."""
    route = _text(egress.get("route")).upper()
    addresses = egress.get("addresses") or []
    pops = _and(list(egress.get("pops") or []))
    if route == "NAT":
        unresolved = list(egress.get("unresolved") or [])
        if addresses:
            text = f"NAT out of the allocated IP{'s' if len(addresses) > 1 else ''} "
            text += _and([_address_text(a) for a in addresses])
            if unresolved:
                text += f" (the address of {_and(unresolved)} could not be read)"
            return text, ""
        if unresolved:
            return (
                f"NAT out of {_and(unresolved)}, whose address could not be read",
                f"The flow leaves Cato from the allocated IP {_and(unresolved)}, whose address could not be read",
            )
        return "NAT, with no allocated IP named", "The flow leaves Cato from an address the rule does not name"
    if route == "VIA":
        where = f"PoP {pops}" if pops else "the PoP the rule names"
        return (
            f"egress via {where}, behind that PoP's shared Cato address, which Cato does not report",
            f"The flow leaves Cato from the shared address of {where}, which Cato does not report",
        )
    if route == "OPTIMIZED":
        return (
            "optimized egress from the PoP Cato picks nearest the destination, behind that PoP's shared address, "
            "which Cato does not report",
            "The flow leaves Cato from the shared address of the PoP nearest the destination, "
            "which Cato does not report",
        )
    if route in _BACKHAUL:
        sites = _and(list(egress.get("sites") or [])) or "the site the rule names"
        return (
            f"backhauled to {sites}, which takes it to the internet over its own connection: the path from there "
            "is not traced",
            f"The flow leaves to the internet through {sites}, whose public address is not collected",
        )
    if route == "NONE":
        return (
            "no special routing: it leaves from the PoP it is connected to, behind that PoP's shared Cato address, "
            "which Cato does not report",
            "The flow leaves Cato from the shared address of its PoP, which Cato does not report",
        )
    return (
        f"route {route.lower() or 'not set'}, which Plexus does not evaluate",
        "The address the flow leaves Cato with is not known",
    )


# For checks that word a rule and its route the way a trace does.
rule_label = _label
route_text = _route_text


def _route_status(egress: dict) -> str:
    route = _text(egress.get("route")).upper()
    if route == "NAT":
        return OK if egress.get("addresses") else UNKNOWN
    return OK if route in _SHARED else UNKNOWN


def trace_egress(
    policy: Any, src: Network, dst: Network, protocol: str = "", ports: tuple[int, int] | None = None
) -> dict[str, Any]:
    """``evaluate`` as path trace items at the hop where the flow leaves
    Cato: ``items`` (``(stage, status, where, text, rule index)``), the
    ``addresses`` the source becomes (several when the rule NATs to several
    allocated IPs; which one Cato uses is not reported) and, when none is
    known, ``unknown``: why, in a sentence."""
    found = evaluate(policy, src, dst, protocol, ports)
    items: list[tuple[str, str, str, str, int | None]] = []
    state = found["state"]
    bare = show(dst)
    if state in ("not_collected", "reduced", "disabled"):
        text = {
            "not_collected": "The network rules are not collected (they are read with the other policies)",
            "reduced": "The network rules were read with the reduced query, without the fields a rule matches on",
            "disabled": "The network rules policy is turned off, and how Cato then routes a flow is not reported",
        }[state]
        items.append(
            (
                ROUTE,
                UNKNOWN,
                NAME,
                f"{text}: which rule routes this flow to the internet, and the address it leaves Cato with, "
                "are not known.",
                None,
            )
        )
        why = "The address the flow leaves Cato with is not known: " + text[0].lower() + text[1:]
        items.append((NAT, INFO, EGRESS, f"{why}. From here on the source is an unknown public address.", None))
        return {"items": items, "addresses": [], "unknown": why}

    rule = found["rule"]
    fallen = f"falls to {_label(rule)}" if rule is not None else "matches no rule"
    for candidate in found["candidates"]:
        other = candidate["rule"]
        detail = ", ".join(candidate["detail"])
        would, _why = _route_text(other["egress"])
        if candidate["why"] == _BY_NAME:
            items.append(
                (
                    ROUTE,
                    INFO,
                    NAME,
                    f"{_label(other)} matches only if Cato identifies the traffic by name (a hostname from Cato's "
                    f"DNS or the TLS SNI, an application or a category): it names {detail}. A connection made to "
                    f"the bare IP {bare} {fallen}. Matched by name, its route would be: {would}.",
                    other.get("index"),
                )
            )
        elif candidate["why"] == _PARTLY:
            items.append(
                (
                    ROUTE,
                    PARTIAL,
                    NAME,
                    f"{_label(other)} matches part of the traffic asked about ({detail}): that part's route would "
                    f"be: {would}.",
                    other.get("index"),
                )
            )
        else:
            items.append(
                (
                    ROUTE,
                    UNKNOWN,
                    NAME,
                    f"{_label(other)} may apply: {detail} cannot be resolved to addresses. Its route would be: "
                    f"{would}.",
                    other.get("index"),
                )
            )
    for skipped in found["skipped"]:
        items.append(
            (
                ROUTE,
                INFO,
                NAME,
                f"{_label(skipped['rule'])} would apply, but its exception {skipped['exception']} excludes this flow.",
                skipped["rule"].get("index"),
            )
        )

    egress: dict[str, Any]
    if rule is None:
        egress = {"route": "NONE", "addresses": [], "unresolved": [], "pops": [], "sites": []}
        text = (
            "No internet network rule matches: by default the flow leaves from the PoP it is connected to, behind "
            "that PoP's shared Cato address, which Cato does not report."
        )
        items.append((ROUTE, OK, NAME, text, None))
    else:
        egress = rule["egress"]
        what, _why = _route_text(egress)
        text = f"{_label(rule)} routes it: {what}."
        if any(c["why"] == _BY_NAME for c in found["candidates"]):
            text += f" This is the rule for a connection made to the bare IP {bare}."
        items.append((ROUTE, _route_status(egress), NAME, text, rule.get("index")))
        for caveat in found["caveats"]:
            items.append(
                (
                    ROUTE,
                    INFO,
                    NAME,
                    f"Its exception {caveat['exception']} excludes the traffic Cato identifies by name "
                    f"({', '.join(caveat['detail'])}); a connection made to the bare IP is not excluded.",
                    rule.get("index"),
                )
            )

    _what, why = _route_text(egress)
    addresses = [a for a in egress.get("addresses") or [] if a.get("ip")] if not why else []
    origin = show(src)
    if addresses:
        if len(addresses) == 1:
            text = f"Source {origin} becomes {_address_text(addresses[0])}."
        else:
            text = (
                f"Source {origin} becomes one of {_and([_address_text(a) for a in addresses])}: which one Cato "
                "uses is not reported, so each is checked from here on."
            )
        items.append((NAT, OK, EGRESS, text, rule.get("index") if rule else None))
        return {"items": items, "addresses": [a["ip"] for a in addresses], "unknown": ""}
    items.append(
        (
            NAT,
            INFO,
            EGRESS,
            f"Source {origin}: {why[0].lower() + why[1:]}. From here on the source is an unknown public address.",
            rule.get("index") if rule else None,
        )
    )
    return {"items": items, "addresses": [], "unknown": why}


__all__ = [
    "EGRESS",
    "KIND",
    "NAME",
    "allocated_addresses",
    "egress_of",
    "evaluate",
    "not_collected",
    "route_text",
    "rule_label",
    "trace_egress",
]
