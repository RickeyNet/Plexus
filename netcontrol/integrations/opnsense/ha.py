"""CARP pairs across OPNsense sources, for the Topology map.

Each firewall of a CARP pair is a source of its own, collected on its own.
``carp_pairs`` finds the pairs among the latest snapshots: two sources whose
``ha`` blocks (``normalize.ha_block``) both report the same VHID with the
same virtual address. The map then draws the two firewalls in one box
joined by an HA link (``netcontrol.integrations.meraki.unified``).

The pair's status is display only: the two snapshots are collected at
different times, so comparing their roles could show a split brain that
never happened. Alerts come from availability tracking of each firewall's
own CARP groups (``availability.ha_entity_states``) and its failovers.

Pure: no database, no network.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.opnsense.normalize import PROVIDER, _dict, _dicts, _text

HA_BOX_PREFIX = "opnsense-ha:"


def _address(text: str) -> str:
    """``192.0.2.3`` of ``192.0.2.3/24``, lower case (an IPv6 address)."""
    return _text(text).split("/", 1)[0].lower()


def _member(org_ref: int, snapshot: dict) -> dict | None:
    """What a snapshot brings to a pair: its firewall and its CARP groups by
    ``(vhid, address)``. ``None`` when CARP was not read or the firewall is
    not in the snapshot."""
    if _text(snapshot.get("provider")) != PROVIDER:
        return None
    ha = _dict(snapshot.get("ha"))
    device_id = _text(ha.get("device"))
    node = next((n for n in _dicts(snapshot.get("nodes")) if n.get("id") == device_id), None)
    if node is None:
        return None
    vips: dict[tuple[str, str], dict] = {}
    for vip in _dicts(ha.get("vips")):
        for address in vip.get("addresses") or []:
            if _address(address):
                vips.setdefault((_text(vip.get("vhid")), _address(address)), vip)
    if not vips:
        return None
    sites = {_text(s.get("id")): _text(s.get("name")) for s in _dicts(snapshot.get("sites"))}
    site_id = _text(node.get("site"))
    return {
        "org_ref": org_ref,
        "node_id": device_id,
        "label": _text(node.get("label")) or device_id,
        "site_id": site_id,
        "site_name": sites.get(site_id) or _text(node.get("label")),
        "vips": vips,
    }


def _role_summary(roles: list[str]) -> str:
    """The role a firewall has across the pair's shared VIPs: the one role,
    or ``mixed``."""
    found = set(roles)
    return roles[0] if len(found) == 1 else "mixed"


def carp_pairs(snapshots: list[tuple[int, dict]]) -> list[dict]:
    """The CARP pairs among ``(org_ref, snapshot)``: two OPNsense sources
    that report the same VHID with the same virtual address. Sources linked
    that way form a group; only a group of exactly two firewalls (with
    different firewall ids: one firewall added twice is no pair) is a pair.
    Three or more sharing a VIP are ambiguous and left alone.

    Each pair: ``id`` (``opnsense-ha:<org_ref>:<org_ref>``, the shared box
    id), ``name``, ``members`` (two ``{org_ref, node_id, label, site_id,
    site_name, role}``, ``role`` summed up over the shared VIPs), ``vips``
    (``{interface, vhid, address, roles}``, ``roles`` in member order),
    ``status``: ``active`` when every shared VIP has exactly one MASTER,
    else ``failed`` (two masters, a split brain, or none)."""
    members: dict[int, dict] = {}
    for org_ref, snapshot in snapshots:
        member = _member(org_ref, snapshot or {})
        if member is not None:
            members[org_ref] = member
    holders: dict[tuple[str, str], list[int]] = {}
    for org_ref, member in members.items():
        for key in member["vips"]:
            holders.setdefault(key, []).append(org_ref)

    # Group the sources that share a VIP (union-find).
    parent = {org_ref: org_ref for org_ref in members}

    def find(item: int) -> int:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for refs in holders.values():
        for other in refs[1:]:
            parent[find(other)] = find(refs[0])
    groups: dict[int, list[int]] = {}
    for org_ref in members:
        groups.setdefault(find(org_ref), []).append(org_ref)

    pairs: list[dict] = []
    for refs in groups.values():
        if len(refs) != 2:
            continue
        a, b = (members[r] for r in sorted(refs))
        if a["node_id"] == b["node_id"]:
            continue
        shared = sorted(set(a["vips"]) & set(b["vips"]), key=lambda k: (k[0].zfill(4), k[1]))
        vips: list[dict[str, Any]] = []
        for key in shared:
            vip_a, vip_b = a["vips"][key], b["vips"][key]
            vips.append(
                {
                    "interface": _text(vip_a.get("interface")) or _text(vip_b.get("interface")),
                    "vhid": key[0],
                    "address": key[1],
                    "roles": [_text(vip_a.get("role")).upper(), _text(vip_b.get("role")).upper()],
                }
            )
        healthy = all(v["roles"].count("MASTER") == 1 for v in vips)
        pairs.append(
            {
                "id": f"{HA_BOX_PREFIX}{a['org_ref']}:{b['org_ref']}",
                "name": f"{a['site_name']} / {b['site_name']} (CARP)",
                "members": [
                    {
                        **{k: m[k] for k in ("org_ref", "node_id", "label", "site_id", "site_name")},
                        "role": _role_summary([v["roles"][i] for v in vips]),
                    }
                    for i, m in enumerate((a, b))
                ],
                "vips": vips,
                "status": "active" if healthy else "failed",
            }
        )
    return sorted(pairs, key=lambda p: p["id"])
