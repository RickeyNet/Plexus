"""Statuses, stages and matching helpers of a path trace.

A trace is a list of hops; each hop holds the items a device applied to the
flow, in order. An item is one rule set, NAT rule, route lookup or link,
with a status: ``ok``, ``blocked``, ``partial`` (only part of the traffic
asked about passes), ``unknown`` (not collected, or not something Plexus
can evaluate) or ``info``. The verdict ranks them as the AWS check does:
blocked, then unknown, then partial, then allowed. ``info`` never changes it.

Matching is three-valued, like the AWS engine's: a rule covers the traffic
asked about fully, in part, or not at all. Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from netcontrol.integrations.aws.reachability import (
    BLOCKED,
    EPHEMERAL_PORTS,
    FULL,
    INFO,
    NONE,
    OK,
    PART,
    PARTIAL,
    UNKNOWN,
    cidr_cover,
)

__all__ = [
    "ACL",
    "ALLOWED",
    "BLOCKED",
    "EPHEMERAL_PORTS",
    "FULL",
    "INFO",
    "LINK",
    "NAT",
    "NONE",
    "NOTE",
    "OK",
    "PART",
    "PARTIAL",
    "POLICY",
    "ROUTE",
    "SECURITY_GROUP",
    "UNKNOWN",
    "Network",
    "contains",
    "cover",
    "hop",
    "is_default",
    "item",
    "longest_route",
    "net",
    "ports_match",
    "protocol_match",
    "show",
    "verdict_of",
    "worst",
]

POLICY, ACL, SECURITY_GROUP, NAT, ROUTE, LINK, NOTE = (
    "policy",
    "acl",
    "security_group",
    "nat",
    "route",
    "link",
    "note",
)
ALLOWED = "allowed"

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

_RANK = {BLOCKED: 3, UNKNOWN: 2, PARTIAL: 1, OK: 0}
_PROTOCOL_NUMBERS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
# Route kinds on a tie of prefix length, most preferred first.
_ROUTE_PREFERENCE = {
    "connected": 0,
    "static": 1,
    "blackhole": 1,
    "pbr": 2,
    "autovpn": 3,
    "vpn3p": 3,
    "dynamic": 3,
    "default": 4,
}
_DEFAULTS = ("0.0.0.0/0", "::/0")


def net(raw: Any) -> Network | None:
    """``raw`` as a network (an address becomes a /32 or /128), else ``None``."""
    try:
        return ipaddress.ip_network(str(raw or "").strip(), strict=False)
    except ValueError:
        return None


def contains(outer: Network, inner: Network) -> bool:
    """Whether ``outer`` holds all of ``inner`` (``False`` across IP versions)."""
    return outer.version == inner.version and outer.supernet_of(inner)  # type: ignore[arg-type]


def show(network: Network) -> str:
    """An address without its /32, a network with its length."""
    return str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)


def cover(cidrs: list[str] | None, network: Network) -> int:
    """How much of ``network`` a list of CIDRs (or ``["any"]``) covers."""
    best = NONE
    for cidr in cidrs or []:
        text = str(cidr or "").strip().lower()
        if text == "any":
            return FULL
        best = max(best, cidr_cover(text, network))
        if best == FULL:
            break
    return best


def _port_ranges(expression: str) -> list[tuple[int, int]] | None:
    ranges: list[tuple[int, int]] = []
    for part in expression.replace(" ", "").split(","):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not match:
            return None
        low = int(match.group(1))
        ranges.append((low, int(match.group(2) or low)))
    return ranges


def ports_match(expression: Any, ports: tuple[int, int] | None) -> int:
    """How much of the port range ``ports`` (``None``: any port) a port
    expression (``any``, ``443``, ``80,443``, ``1000-2000``) covers."""
    text = str(expression or "").strip().lower()
    if text in ("", "any", "*"):
        return FULL
    ranges = _port_ranges(text)
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


def protocol_match(rule_protocol: Any, protocol: str) -> int:
    """How much of the traffic asked about (``""``: any traffic) a rule's
    protocol covers."""
    wanted = str(rule_protocol or "").strip().lower()
    wanted = _PROTOCOL_NUMBERS.get(wanted, wanted)
    if wanted in ("", "any", "all", "ip", "-1"):
        return FULL
    if not protocol:
        return PART
    return FULL if wanted == protocol else NONE


def is_default(route: dict) -> bool:
    """A default route: kind ``default``, or any route to 0.0.0.0/0 or ::/0."""
    return route.get("kind") == "default" or str(route.get("prefix")) in _DEFAULTS


def longest_route(routes: list[dict], network: Network, vrf: str = "") -> tuple[dict | None, list[dict]]:
    """The route a device uses for ``network`` in ``vrf`` and the narrower
    enabled routes that send part of it elsewhere. Longest prefix wins; on a
    tie connected beats static, policy-based, VPN and dynamic, then default
    routes; then the lower metric; then the first listed."""
    best: dict | None = None
    best_key: tuple | None = None
    narrower: list[dict] = []
    for route in routes:
        if not isinstance(route, dict) or not route.get("enabled", True) or (route.get("vrf") or "") != vrf:
            continue
        prefix = net(route.get("prefix"))
        if prefix is None or prefix.version != network.version:
            continue
        if contains(prefix, network):
            metric = route.get("metric")
            key = (
                prefix.prefixlen,
                -_ROUTE_PREFERENCE.get(str(route.get("kind")), 3),
                -(metric if isinstance(metric, int) else 0),
            )
            if best_key is None or key > best_key:
                best, best_key = route, key
        elif contains(network, prefix):
            narrower.append(route)
    return best, narrower


def worst(statuses: list[str]) -> str:
    """The worst of ``statuses`` (``info`` ignored); ``ok`` when none counts."""
    found = OK
    for status in statuses:
        if _RANK.get(status, -1) > _RANK[found]:
            found = status
    return found


def item(stage: str, status: str, where: str, text: str, rule: int | None = None) -> dict[str, Any]:
    return {"stage": stage, "status": status, "where": where, "text": text, "rule": rule}


def hop(
    node: Any, edge: Any, label: str, site: str, provider: str, ingress: str = "", egress: str = ""
) -> dict[str, Any]:
    return {
        "node": node,
        "edge": edge,
        "label": label,
        "site": site,
        "provider": provider,
        "in": ingress,
        "out": egress,
        "status": OK,
        "items": [],
    }


def verdict_of(hops: list[dict]) -> tuple[str, dict | None, dict | None]:
    """``(verdict, deciding hop, deciding item)`` of a direction: the first
    blocked item, else the first unknown, else the first partial."""
    for status, verdict in ((BLOCKED, BLOCKED), (UNKNOWN, UNKNOWN), (PARTIAL, PARTIAL)):
        for each in hops:
            for entry in each["items"]:
                if entry["status"] == status:
                    return verdict, each, entry
    return ALLOWED, None, None
