"""Subnet index of a topology snapshot: which device owns which subnet.

Path mode lets a user pick subnets instead of devices. The index is derived
from the detail sections a snapshot already carries (VLANs, single LAN,
static routes, switch SVIs, VPN participation, non-Meraki VPN peers, the
network ranges of a Cato site, the subnets of an AWS VPC), so it
works on snapshots collected before the index existed and on the merged
snapshot of the HTML export alike.
"""

from __future__ import annotations

import ipaddress
from typing import Any

# A VPC's own router owns its subnets even when the VPC holds an appliance.
_GATEWAY_ORDER = ("vpc", "appliance", "switch", "wireless")
_NOT_A_GATEWAY = ("wan", "external", "vpn_peer", "cloud", "users")


def _cidr(raw: Any) -> str:
    """Canonical network for ``raw``, or ``""`` when it is not one."""
    try:
        return str(ipaddress.ip_network(str(raw or "").strip(), strict=False))
    except ValueError:
        return ""


def _rows(sections: list[dict], title: str) -> list[list[str]]:
    for section in sections:
        if section.get("title") == title and section.get("kind") in ("table", "kv"):
            return [row for row in section.get("rows") or [] if isinstance(row, list)]
    return []


def _cell(row: list[str], index: int) -> str:
    return str(row[index]) if len(row) > index else ""


def subnet_index(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Every subnet the snapshot knows an owner for, sorted by address.

    ``node_id`` is the device traffic for the subnet enters and leaves by: the
    site's appliance, the L3 switch holding the SVI, or the non-Meraki VPN
    peer the subnet sits behind. ``in_vpn`` is whether the site advertises the
    subnet into the VPN (``None`` when the snapshot does not say).
    """
    nodes = [n for n in snapshot.get("nodes") or [] if isinstance(n, dict)]
    gateways: dict[str, tuple[int, str]] = {}
    peers: dict[str, dict] = {}
    for node in nodes:
        kind = node.get("kind") or ""
        if kind == "vpn_peer":
            peers.setdefault(str(node.get("label") or ""), node)
        if kind in _NOT_A_GATEWAY or not node.get("site"):
            continue
        rank = _GATEWAY_ORDER.index(kind) if kind in _GATEWAY_ORDER else len(_GATEWAY_ORDER)
        if node["site"] not in gateways or rank < gateways[node["site"]][0]:
            gateways[node["site"]] = (rank, node["id"])

    site_names = {s["id"]: s.get("name") or s["id"] for s in snapshot.get("sites") or []}
    entries: dict[tuple[str, str], dict[str, Any]] = {}

    def add(cidr: str, node_id: str, site_id: str, kind: str, name: str, in_vpn: bool | None) -> None:
        if not cidr or not node_id or cidr in ("0.0.0.0/0", "::/0"):
            return
        entries.setdefault(
            (cidr, node_id),
            {
                "cidr": cidr,
                "name": name.strip(),
                "kind": kind,
                "site_id": site_id,
                "site_name": site_names.get(site_id, ""),
                "node_id": node_id,
                "in_vpn": in_vpn,
            },
        )

    vpn_by_site: dict[str, dict[str, bool]] = {}
    for site in snapshot.get("sites") or []:
        sections = site.get("sections") or []
        in_vpn = {_cidr(_cell(r, 0)): _cell(r, 1) == "Yes" for r in _rows(sections, "VPN local subnets")}
        in_vpn.pop("", None)
        vpn_by_site[site["id"]] = in_vpn
        gateway = gateways.get(site["id"], (0, ""))[1]

        def advertised(cidr: str, known: dict[str, bool] = in_vpn) -> bool | None:
            return known.get(cidr) if known else None

        for row in _rows(sections, "VLANs"):
            cidr = _cidr(_cell(row, 2))
            add(cidr, gateway, site["id"], "vlan", f"VLAN {_cell(row, 0)} {_cell(row, 1)}", advertised(cidr))
        # A Cato site: the cloud routes every range of every site.
        for row in _rows(sections, "Network ranges"):
            vlan = f" (VLAN {_cell(row, 3)})" if _cell(row, 3) else ""
            add(_cidr(_cell(row, 0)), gateway, site["id"], "range", f"{_cell(row, 1)}{vlan}", True)
        # An AWS VPC: Subnet, Name, Availability zone...
        for row in _rows(sections, "Subnets"):
            zone = f" ({_cell(row, 2)})" if _cell(row, 2) else ""
            add(_cidr(_cell(row, 0)), gateway, site["id"], "subnet", f"{_cell(row, 1)}{zone}", None)
        for row in _rows(sections, "Single LAN"):
            if _cell(row, 0) == "Subnet":
                cidr = _cidr(_cell(row, 1))
                add(cidr, gateway, site["id"], "lan", "Single LAN", advertised(cidr))
        for row in _rows(sections, "Static routes"):
            if _cell(row, 3) == "No":
                continue
            cidr = _cidr(_cell(row, 1))
            listed = advertised(cidr)
            add(
                cidr,
                gateway,
                site["id"],
                "static",
                f"Static route {_cell(row, 0)}",
                listed if listed is not None else _cell(row, 4) == "Yes",
            )
        for row in _rows(sections, "Effective routes (derived)"):
            peer = peers.get(_cell(row, 2))
            if _cell(row, 1) == "Non-Meraki VPN" and peer:
                add(
                    _cidr(_cell(row, 0)),
                    peer["id"],
                    peer.get("site") or "",
                    "peer",
                    f"Behind {peer.get('label')}",
                    None,
                )

    # Subnets routed by an L3 switch rather than the appliance.
    for node in nodes:
        if node.get("kind") != "switch" or not node.get("site"):
            continue
        known = vpn_by_site.get(node["site"]) or {}
        for row in _rows(node.get("sections") or [], "Layer 3 interfaces (SVIs)"):
            cidr = _cidr(_cell(row, 2))
            add(
                cidr,
                node["id"],
                node["site"],
                "svi",
                f"VLAN {_cell(row, 1)} {_cell(row, 0)}",
                known.get(cidr) if known else None,
            )

    def order(entry: dict[str, Any]) -> tuple:
        network = ipaddress.ip_network(entry["cidr"])
        return (network.version, int(network.network_address), network.prefixlen, entry["site_name"], entry["node_id"])

    return sorted(entries.values(), key=order)
