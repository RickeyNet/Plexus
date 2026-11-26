"""IPAM namespaces, route targets, VLAN groups, RIRs and aggregates: the
limits and rules, with no I/O.

A namespace holds VRFs and prefixes; the same prefix may exist once per
namespace and VRF. Row 1 is the Global namespace every existing VRF and
prefix belongs to (migration 0110). A route target is a BGP extended
community a VRF imports or exports. A VLAN group is a pool of VLAN ids,
optionally scoped to a site or a region; a VLAN id is unique within a group.
An aggregate is a top-level block of address space allocated by a RIR;
prefixes inside it report it, and its utilisation is the share of its
addresses its prefixes cover.

Storage: ``routes.db.ipam_model``; API: ``netcontrol.routes.ipam_model``;
docs: ``docs/ipam.md`` and ``docs/vrfs-and-vlans.md``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from netcontrol.circuits import clean_date
from netcontrol.custom_fields import CustomFieldError, clean_name
from netcontrol.integrations.pathtrace.model import Network, contains, net
from netcontrol.network_objects import DESCRIPTION_MAX, VID_MAX, VID_MIN, clean_description
from netcontrol.prefix_index import longest_prefix_match

__all__ = [
    "DESCRIPTION_MAX",
    "GLOBAL_NAMESPACE_ID",
    "NAME_MAX",
    "RT_DIRECTIONS",
    "aggregate_usage",
    "clean_aggregate_prefix",
    "clean_date",
    "clean_description",
    "clean_record_name",
    "clean_route_target",
    "clean_vid_range",
    "containing_aggregate",
    "next_free_vid",
    "vid_outside_range",
]

# The Global namespace (migration 0110): the default of every namespace column.
GLOBAL_NAMESPACE_ID = 1
NAME_MAX = 100
RT_DIRECTIONS: tuple[str, ...] = ("import", "export")

_RT = re.compile(r"^(?P<admin>[^:\s]+):(?P<assigned>\d{1,10})$")
_UINT16 = 65_535
_UINT32 = 4_294_967_295


def clean_record_name(raw: object, label: str) -> str:
    """A record name trimmed; 1 to ``NAME_MAX`` characters."""
    return clean_name(raw, label, NAME_MAX)


def clean_route_target(raw: object) -> str:
    """A route target as ``ASN:number`` or ``IPv4:number`` (RFC 4360): a
    2-byte ASN with a 4-byte number, a 4-byte ASN with a 2-byte number, or
    an IPv4 address with a 2-byte number. Returned trimmed, the ASN and the
    number without leading zeros."""
    text = raw.strip() if isinstance(raw, str) else ""
    message = "Route target must be ASN:number (65000:100) or IPv4:number (192.0.2.1:100)."
    match = _RT.match(text)
    if not match:
        raise CustomFieldError(message)
    admin, assigned = match["admin"], int(match["assigned"])
    if admin.isdigit():
        asn = int(admin)
        if asn <= _UINT16 and assigned <= _UINT32:
            return f"{asn}:{assigned}"
        if asn <= _UINT32 and assigned <= _UINT16:
            return f"{asn}:{assigned}"
        raise CustomFieldError(
            "Route target numbers are out of range: a 2-byte ASN takes a number up to 4294967295, "
            "a 4-byte ASN one up to 65535."
        )
    try:
        address = ipaddress.IPv4Address(admin)
    except ValueError as exc:
        raise CustomFieldError(message) from exc
    if assigned > _UINT16:
        raise CustomFieldError("An IPv4 route target takes a number up to 65535.")
    return f"{address}:{assigned}"


def clean_vid_range(min_vid: object, max_vid: object) -> tuple[int, int]:
    """A VLAN group's range: two VLAN ids, the first not above the second."""
    for value in (min_vid, max_vid):
        if isinstance(value, bool) or not isinstance(value, int) or not VID_MIN <= value <= VID_MAX:
            raise CustomFieldError(f"VLAN ids must be numbers from {VID_MIN} to {VID_MAX}.")
    if int(min_vid) > int(max_vid):  # type: ignore[call-overload]
        raise CustomFieldError("The lowest VLAN id must not be above the highest.")
    return int(min_vid), int(max_vid)  # type: ignore[call-overload]


def vid_outside_range(vid: int, group: dict) -> str | None:
    """Why ``vid`` cannot be in the group, or ``None`` when it can."""
    low, high = int(group["min_vid"]), int(group["max_vid"])
    if not low <= int(vid) <= high:
        return f"VLAN group '{group['name']}' takes VLAN ids {low} to {high}."
    return None


def next_free_vid(min_vid: int, max_vid: int, used: Iterable[int]) -> int | None:
    """The lowest VLAN id from ``min_vid`` to ``max_vid`` not in ``used``;
    ``None`` when every one is taken."""
    taken = {int(v) for v in used}
    for vid in range(int(min_vid), int(max_vid) + 1):
        if vid not in taken:
            return vid
    return None


def clean_aggregate_prefix(raw: object) -> str:
    """An aggregate's prefix in CIDR form, with no host bits set."""
    text = raw.strip() if isinstance(raw, str) else ""
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        loose = net(text) if "/" in text else None
        if loose is not None:
            raise CustomFieldError(f"Prefix has host bits set; did you mean {loose}?") from exc
        raise CustomFieldError("Prefix must be a network in CIDR form, such as 192.0.2.0/24.") from exc
    return str(network)


def containing_aggregate(subnet: str, aggregates: Iterable[dict]) -> dict | None:
    """The aggregate (a row with ``prefix``) that holds ``subnet``: the most
    specific one when several do; ``None`` when none does or the subnet does
    not parse."""
    inner = net(subnet)
    if inner is None:
        return None
    parsed = ((net(aggregate.get("prefix")), aggregate) for aggregate in aggregates)
    return longest_prefix_match(inner, [(outer, aggregate) for outer, aggregate in parsed if outer is not None])


def aggregate_usage(prefix: str, subnets: Iterable[str]) -> dict:
    """How much of the aggregate ``prefix`` the given subnets cover:
    ``prefix_count`` (subnets inside it), ``total_addresses``,
    ``used_addresses`` (the covered addresses, overlaps counted once) and
    ``utilization_pct`` (one decimal)."""
    outer = net(prefix)
    if outer is None:
        return {"prefix_count": 0, "total_addresses": 0, "used_addresses": 0, "utilization_pct": 0.0}
    inside: list[Network] = []
    for subnet in subnets:
        inner = net(subnet)
        if inner is not None and contains(outer, inner):
            inside.append(inner)
    collapsed: list[Network] = list(ipaddress.collapse_addresses(inside))  # type: ignore[type-var]
    used = sum(n.num_addresses for n in collapsed)
    total = outer.num_addresses
    return {
        "prefix_count": len(inside),
        "total_addresses": total,
        "used_addresses": used,
        "utilization_pct": round(used / total * 100, 1) if total else 0.0,
    }
