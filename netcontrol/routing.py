"""Routing objects (the intended BGP state of devices): the limits and rules,
and the comparison of intended peerings with observed BGP neighbors, with
no I/O.

Storage lives in ``routes.db.routing``, the API in
``netcontrol.routes.routing``. The observed side is what neighbor discovery
already stores (``topology_links`` rows with ``protocol = 'bgp'``, written
by the SNMP BGP4-MIB walk in ``netcontrol.routes.snmp``); this module only
reads those rows. See ``docs/routing.md``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from netcontrol.custom_fields import CustomFieldError, clean_name, clean_text

__all__ = [
    "ADDRESS_FAMILIES",
    "ASN_MAX",
    "ASN_MIN",
    "COMPLIANCE_STATES",
    "INSTANCE_STATUSES",
    "NAME_MAX",
    "PEERING_STATUSES",
    "POLICY_MAX",
    "RIR_MAX",
    "TEXT_MAX",
    "clean_address",
    "clean_address_families",
    "clean_asn",
    "clean_instance_name",
    "clean_policy",
    "clean_router_id",
    "clean_status",
    "compare",
    "join_families",
    "observed_neighbor",
    "same_family",
    "split_families",
    "summarize",
]

ASN_MIN = 1
ASN_MAX = 4294967295
NAME_MAX = 64
RIR_MAX = 64
POLICY_MAX = 200
TEXT_MAX = 2000

INSTANCE_STATUSES: tuple[str, ...] = ("planned", "active", "decommissioned")
PEERING_STATUSES: tuple[str, ...] = ("planned", "active", "disabled", "decommissioned")
# The address families a peering may carry (AFI-SAFI names as Plexus spells them).
ADDRESS_FAMILIES: tuple[str, ...] = (
    "ipv4-unicast",
    "ipv4-multicast",
    "ipv4-labeled-unicast",
    "ipv4-flowspec",
    "ipv6-unicast",
    "ipv6-multicast",
    "ipv6-labeled-unicast",
    "ipv6-flowspec",
    "vpnv4-unicast",
    "vpnv6-unicast",
    "l2vpn-evpn",
    "l2vpn-vpls",
    "link-state",
    "rtc",
)
# ``vpnv4`` and ``vpnv6`` are accepted as the unicast family they name.
_FAMILY_ALIASES = {"vpnv4": "vpnv4-unicast", "vpnv6": "vpnv6-unicast", "evpn": "l2vpn-evpn"}

# matched: observed and established; down: observed, not established;
# missing: intended (active), not observed; unexpected: observed, not
# intended; asn_mismatch: observed with another remote AS; no_data: the
# device's neighbors were never discovered, so nothing can be said.
COMPLIANCE_STATES: tuple[str, ...] = ("matched", "down", "missing", "unexpected", "asn_mismatch", "no_data")

# BGP4-MIB bgpPeerState: 1 idle, 2 connect, 3 active, 4 opensent,
# 5 openconfirm, 6 established.
_PEER_STATES = {
    "1": "idle",
    "2": "connect",
    "3": "active",
    "4": "opensent",
    "5": "openconfirm",
    "6": "established",
}
_PLATFORM_AS = re.compile(r"\bAS\s*(\d+)", re.IGNORECASE)
_PLATFORM_STATE = re.compile(r"\bstate\s*=\s*([A-Za-z0-9]+)", re.IGNORECASE)
_NAME_AS = re.compile(r"^AS\s*(\d+)\b", re.IGNORECASE)


# ── Field rules ──────────────────────────────────────────────────────────────


def clean_asn(raw: object, label: str = "ASN") -> int:
    """An AS number from ``ASN_MIN`` to ``ASN_MAX``: an integer, its text, or
    asdot text (``1.10`` = 65546)."""
    value: int | None = None
    if isinstance(raw, bool):
        value = None
    elif isinstance(raw, int):
        value = raw
    elif isinstance(raw, str):
        text = raw.strip()
        if text.upper().startswith("AS"):
            text = text[2:].strip()
        high_text, dot, low_text = text.partition(".")
        if not text.isascii():
            value = None
        elif text.isdigit():
            value = int(text)
        elif dot and high_text.isdigit() and low_text.isdigit():
            high, low = int(high_text), int(low_text)
            value = high * 65536 + low if high <= 65535 and low <= 65535 else None
    if value is None or not ASN_MIN <= value <= ASN_MAX:
        raise CustomFieldError(f"{label} must be a number from {ASN_MIN} to {ASN_MAX}.")
    return value


def clean_address(raw: object, label: str, *, required: bool = True) -> str:
    """An IPv4 or IPv6 address in canonical text ('' when optional and empty)."""
    text = raw.strip() if isinstance(raw, str) else ""
    if not text:
        if required:
            raise CustomFieldError(f"{label} must not be empty.")
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise CustomFieldError(f"{label} must be an IPv4 or IPv6 address.") from exc


def same_family(first: str, second: str) -> bool:
    """Whether two canonical addresses are both IPv4 or both IPv6 (an empty
    one matches anything)."""
    if not first or not second:
        return True
    return ipaddress.ip_address(first).version == ipaddress.ip_address(second).version


def clean_router_id(raw: object) -> str:
    """A router id: an IPv4 address in dotted form, or ''."""
    text = raw.strip() if isinstance(raw, str) else ""
    if not text:
        return ""
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError as exc:
        raise CustomFieldError("Router ID must be an IPv4 address (dotted quad).") from exc


def clean_policy(raw: object, label: str) -> str:
    """A route policy (route-map) name; may be empty."""
    return clean_text(raw, label, POLICY_MAX)


def clean_status(raw: object, allowed: tuple[str, ...]) -> str:
    text = raw.strip().lower() if isinstance(raw, str) else ""
    if text not in allowed:
        raise CustomFieldError(f"Status must be one of {', '.join(allowed)}.")
    return text


def clean_instance_name(raw: object) -> str:
    return clean_name(raw, "Name", NAME_MAX)


def clean_address_families(raw: object) -> list[str]:
    """Distinct address families from the fixed set, in the set's order. A
    list or comma-separated text; empty is allowed."""
    if raw is None:
        return []
    if isinstance(raw, str):
        items: Iterable[object] = raw.split(",")
    elif isinstance(raw, (list, tuple)):
        items = raw
    else:
        raise CustomFieldError("Address families must be a list.")
    chosen: set[str] = set()
    for item in items:
        name = item.strip().lower() if isinstance(item, str) else ""
        if not name:
            continue
        name = _FAMILY_ALIASES.get(name, name)
        if name not in ADDRESS_FAMILIES:
            raise CustomFieldError(f"Address family '{str(item)[:40]}' is not one of {', '.join(ADDRESS_FAMILIES)}.")
        chosen.add(name)
    return [f for f in ADDRESS_FAMILIES if f in chosen]


def join_families(families: list[str]) -> str:
    return ",".join(families)


def split_families(stored: str | None) -> list[str]:
    return [f for f in str(stored or "").split(",") if f]


# ── Observed neighbors ───────────────────────────────────────────────────────


def _canonical(raw: object) -> str:
    try:
        return str(ipaddress.ip_address(str(raw or "").strip()))
    except ValueError:
        return ""


def observed_neighbor(link: dict) -> dict | None:
    """One stored BGP neighbor (a ``topology_links`` row with ``protocol``
    ``bgp``) as ``{host_id, remote_address, remote_asn, state,
    established, discovered_at}``; ``None`` for another protocol or a row
    without a usable peer address. ``remote_asn`` is ``None`` and ``state``
    ``""`` when the device did not report them."""
    if str(link.get("protocol") or "").lower() != "bgp":
        return None
    address = _canonical(link.get("target_ip"))
    if not address:
        return None
    platform = str(link.get("target_platform") or "")
    asn: int | None = None
    match = _PLATFORM_AS.search(platform) or _NAME_AS.match(str(link.get("target_device_name") or "").strip())
    if match:
        value = int(match.group(1))
        asn = value if ASN_MIN <= value <= ASN_MAX else None
    state = ""
    state_match = _PLATFORM_STATE.search(platform)
    if state_match:
        raw_state = state_match.group(1).lower()
        state = _PEER_STATES.get(raw_state, raw_state)
    return {
        "host_id": int(link["source_host_id"]),
        "remote_address": address,
        "remote_asn": asn,
        "state": state,
        "established": state == "established",
        "discovered_at": str(link.get("discovered_at") or ""),
    }


# ── Intended vs observed ─────────────────────────────────────────────────────


def _row(state: str, *, host: dict, peering: dict | None, neighbor: dict | None, detail: str) -> dict:
    return {
        "state": state,
        "host_id": host["id"],
        "hostname": host.get("hostname") or "",
        "peering_id": peering["id"] if peering else None,
        "routing_instance_id": peering["routing_instance_id"] if peering else None,
        "routing_instance": peering.get("routing_instance_name", "") if peering else "",
        "status": peering["status"] if peering else None,
        "remote_address": peering["remote_address"] if peering else neighbor["remote_address"],  # type: ignore[index]
        "intended_remote_asn": peering.get("remote_asn") if peering else None,
        "observed_remote_asn": neighbor["remote_asn"] if neighbor else None,
        "observed_state": neighbor["state"] if neighbor else "",
        "discovered_at": neighbor["discovered_at"] if neighbor else "",
        "detail": detail,
    }


def compare(
    hosts: list[dict],
    peerings: list[dict],
    neighbors: list[dict],
    hosts_with_data: set[int],
    *,
    unexpected_for: set[int],
) -> list[dict]:
    """The compliance rows of ``hosts`` (``{id, hostname}``).

    ``peerings``: the intended peerings of those hosts (each with ``id``,
    ``host_id``, ``routing_instance_id``, ``routing_instance_name``,
    ``remote_address``, ``remote_asn``, ``status``). ``neighbors``: their
    observed neighbors (``observed_neighbor`` output). ``hosts_with_data``:
    the hosts whose neighbors were discovered at least once; the peerings of
    any other host are ``no_data``. ``unexpected_for``: the hosts whose
    observed neighbors without a peering are reported as ``unexpected``.

    Only ``active`` peerings are expected; a peering of another status is
    reported only when its neighbor is observed (and then claims it, so it
    is never ``unexpected``)."""
    by_host_neighbors: dict[int, dict[str, dict]] = {}
    for n in neighbors:
        by_host_neighbors.setdefault(n["host_id"], {})[n["remote_address"]] = n
    rows: list[dict] = []
    for host in hosts:
        hid = host["id"]
        observed = by_host_neighbors.get(hid, {})
        claimed: set[str] = set()
        has_data = hid in hosts_with_data
        for p in (x for x in peerings if x["host_id"] == hid):
            address = _canonical(p["remote_address"]) or p["remote_address"]
            neighbor = observed.get(address)
            if neighbor is not None:
                claimed.add(address)
            if not has_data:
                if p["status"] == "active":
                    rows.append(
                        _row(
                            "no_data",
                            host=host,
                            peering=p,
                            neighbor=None,
                            detail="No neighbor discovery data for this device yet.",
                        )
                    )
                continue
            if neighbor is None:
                if p["status"] == "active":
                    rows.append(
                        _row("missing", host=host, peering=p, neighbor=None, detail="Not seen among the BGP neighbors.")
                    )
                continue
            if neighbor["remote_asn"] is not None and neighbor["remote_asn"] != p.get("remote_asn"):
                rows.append(
                    _row(
                        "asn_mismatch",
                        host=host,
                        peering=p,
                        neighbor=neighbor,
                        detail=f"Observed AS {neighbor['remote_asn']}, intended AS {p.get('remote_asn')}.",
                    )
                )
            elif neighbor["established"]:
                rows.append(_row("matched", host=host, peering=p, neighbor=neighbor, detail="Session established."))
            else:
                state = neighbor["state"] or "unknown"
                rows.append(_row("down", host=host, peering=p, neighbor=neighbor, detail=f"Session state {state}."))
        if has_data and hid in unexpected_for:
            for address in sorted(set(observed) - claimed, key=_sort_key):
                neighbor = observed[address]
                rows.append(
                    _row(
                        "unexpected",
                        host=host,
                        peering=None,
                        neighbor=neighbor,
                        detail="Observed BGP neighbor with no intended peering.",
                    )
                )
    return rows


def _sort_key(address: str) -> tuple[int, int]:
    ip = ipaddress.ip_address(address)
    return ip.version, int(ip)


def summarize(rows: list[dict]) -> dict[str, int]:
    """Rows per compliance state (every state present, zero when none)."""
    counts = dict.fromkeys(COMPLIANCE_STATES, 0)
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    return counts
