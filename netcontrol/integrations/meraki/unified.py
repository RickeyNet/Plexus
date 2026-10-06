"""Join Meraki snapshots with the Plexus topology graph.

The Topology page has one graph. This module is the seam between the two
data models:

  ``merge_meraki_into_graph``  - adds Meraki devices, WAN uplinks, VPN peers and
      their links (and the Cato, AWS and Azure snapshots, which share the format) to
      the node/edge graph served by ``/api/topology``. A Meraki
      device or LLDP/CDP neighbor that is also a Plexus inventory host
      collapses into that host's node, which is what stitches a Meraki site
      onto the SNMP-discovered network around it.
  ``node_details`` / ``build_search_index`` / ``search_index``  - serve the
      per-node detail sections and whole-map search for Meraki content.
  ``graph_to_snapshot``  - converts the merged graph (inventory + Meraki) into
      the viewer snapshot used for the self-contained HTML export.

Everything here is pure (no I/O); the routes own database access and caching.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.meraki.normalize import (
    SCHEMA_VERSION,
    _add,
    _is_ip,
    _layout,
    _worst,
    kv_section,
)

# Meraki nodes carry layout hints so a large organization opens instantly
# instead of going through force-directed physics. The block is placed to the
# right of the origin, where physics gathers the inventory nodes.
MERAKI_X_OFFSET = 1600.0
MERAKI_ORG_GAP = 600.0

# Meraki product type -> Topology device_category (drives the node icon).
_CATEGORY = {
    "appliance": "firewall",
    "switch": "switch",
    "wireless": "wireless",
    "cellularGateway": "router",
}
# Snapshot kinds that are not devices: neighbors, WAN stubs, VPN peers and the
# nodes of a SASE cloud (its PoPs and backbone, and the remote-user group).
NON_DEVICE_KINDS = ("external", "wan", "vpn_peer", "cloud", "users")
_GRAPH_STATUS = {"online": "up", "offline": "down", "alerting": "alerting"}
# Snapshot edge kind -> Topology edge protocol.
# ``attach`` is a cloud attachment (VPC to transit gateway, peering...);
# ``manage`` is a management relationship (an FMC and the FTD it manages),
# which carries no traffic and is left out of Path Mode and the tree layout.
_PROTOCOL = {
    "lan": "lldp",
    "stack": "stack",
    "uplink": "wan",
    "vpn": "vpn",
    "vpn3p": "vpn-ipsec",
    "attach": "cloud",
    "manage": "management",
}
_EDGE_KIND = {
    "stack": "stack",
    "wan": "uplink",
    "vpn": "vpn",
    "vpn-ipsec": "vpn3p",
    "cloud": "attach",
    "management": "manage",
}
# Inventory device_category -> viewer node kind.
_VIEWER_KIND = {
    "router": "router",
    "switch": "switch",
    "firewall": "firewall",
    "wireless": "wireless",
    "wlc": "wlc",
    "phone": "phone",
    "server": "server",
}

EXTERNAL_SITE_ID = "__external__"
_SOURCE_NAME = {
    "meraki": "Meraki Dashboard",
    "cato": "Cato API",
    "aws": "AWS API",
    "azure": "Azure API",
    "anyconnect": "FMC API",
}


def meraki_graph_id(org_ref: int, node_id: str) -> str:
    """Stable Topology node id for a Meraki snapshot node (survives rebuilds,
    so saved node positions keep working)."""
    return f"meraki:{org_ref}:{node_id}"


def external_key(name: str, ip: str) -> str:
    """The ``ext_`` id the SNMP topology gives an unknown neighbor, used to find
    a neighbor that discovery already put on the map."""
    norm = (name or "").strip().lower().split(".")[0]
    return f"ext_{norm}" if norm else f"ext_{(ip or '').strip()}"


def _name_or_blank(label: str) -> str:
    """A neighbor labelled only by its address has no name to match on."""
    return "" if _is_ip(label) else label


def _global_ips(*values: Any) -> list[str]:
    """The public addresses among ``values`` (strings or lists of strings).
    Private addresses repeat from site to site and identify nothing."""
    found: list[str] = []
    for value in values:
        for raw in value if isinstance(value, (list, tuple)) else [value]:
            try:
                address = ipaddress.ip_address(str(raw or "").strip())
            except ValueError:
                continue
            if address.is_global and str(address) not in found:
                found.append(str(address))
    return found


def _uplink_address(wan: dict) -> str:
    """The address a WAN uplink has on its own interface: behind a NAT it is
    not the public address the uplink is known by. A stub that only knows
    its interface address (an FTD access interface) reports that."""
    for section in wan.get("sections") or []:
        if section.get("title") == "WAN uplink" and section.get("kind") == "kv":
            for row in section.get("rows") or []:
                if len(row) > 1 and row[0] == "IP":
                    return str(row[1] or "").strip()
    own = str(wan.get("ip") or "").strip()
    return own if own and _is_ip(own) and not _global_ips(own) else ""


def _is_virtual_model(model: Any) -> bool:
    """A virtual appliance (Meraki vMX, FTDv, "Threat Defense for AWS" or for Azure)."""
    lowered = str(model or "").lower()
    return lowered.startswith("vmx") or any(t in lowered for t in ("ftdv", "threat defense for", "virtual"))


def virtual_appliance_pairs(snapshots: list[tuple[int, dict]]) -> dict[tuple[int, str], tuple[int, str]]:
    """Cloud instances that are a device another snapshot manages (a Meraki
    vMX, a Cato vSocket), as ``(org_ref, instance node id) -> (org_ref,
    device node id)``.

    An instance is the device that answers on one of its public addresses
    (its own, or that of its WAN uplink). An appliance in a private subnet
    has none: its uplink is known by the address of the NAT in front of it.
    It is then matched by the private address of the uplink, which repeats
    from site to site, so only when a single forwarding instance and a single
    uplink have the address and either the device is a virtual model or its
    public address is that of a NAT gateway of the instance's VPC.
    """
    public: dict[str, tuple[int, str]] = {}
    private: dict[str, list[dict[str, Any]]] = {}
    for org_ref, snapshot in snapshots:
        nodes = {n["id"]: n for n in snapshot.get("nodes") or []}

        def is_device(node: dict | None) -> bool:
            return node is not None and node["kind"] not in NON_DEVICE_KINDS and "alias_ips" not in node

        for node in nodes.values():
            if is_device(node):
                for address in _global_ips(node.get("ip")):
                    public.setdefault(address, (org_ref, node["id"]))
        for edge in snapshot.get("edges") or []:
            for wan_id, device_id in ((edge["a"], edge["b"]), (edge["b"], edge["a"])):
                wan, device = nodes.get(wan_id), nodes.get(device_id)
                if wan is None or wan["kind"] != "wan" or not is_device(device):
                    continue
                known_by = _global_ips(wan.get("ip"))
                for address in known_by:
                    public.setdefault(address, (org_ref, device_id))
                inside = _uplink_address(wan)
                if inside and not _global_ips(inside):
                    private.setdefault(inside, []).append(
                        {
                            "ref": (org_ref, device_id),
                            "public": known_by,
                            "virtual": _is_virtual_model(device.get("model")),
                        }
                    )

    pairs: dict[tuple[int, str], tuple[int, str]] = {}
    for org_ref, snapshot in snapshots:
        nodes = [n for n in snapshot.get("nodes") or [] if isinstance(n, dict)]
        instances = [n for n in nodes if "alias_ips" in n]
        if not instances:
            continue

        def inside_addresses(node: dict) -> list[str]:
            every = [str(a or "").strip() for a in (node.get("ip"), *(node.get("alias_ips") or []))]
            return [a for a in dict.fromkeys(every) if a and _is_ip(a) and not _global_ips(a)]

        holders: dict[str, int] = {}
        for node in instances:
            if node["kind"] == "appliance":
                for address in inside_addresses(node):
                    holders[address] = holders.get(address, 0) + 1
        # Public addresses of the gateways (NAT) of each VPC.
        gateways: dict[str, set[str]] = {}
        for node in nodes:
            if node["kind"] == "cloud":
                gateways.setdefault(node.get("site") or "", set()).update(_global_ips(node.get("ip")))

        for node in instances:
            match: tuple[int, str] | None = None
            for address in _global_ips(node.get("ip"), node.get("alias_ips")):
                holder = public.get(address)
                if holder and holder[0] != org_ref:
                    match = holder
                    break
            if match is None and node["kind"] == "appliance":
                for address in inside_addresses(node):
                    found = [c for c in private.get(address, []) if c["ref"][0] != org_ref]
                    if len(found) != 1 or holders.get(address) != 1:
                        continue
                    behind_nat = set(found[0]["public"]) & gateways.get(node.get("site") or "", set())
                    if found[0]["virtual"] or behind_nat:
                        match = found[0]["ref"]
                        break
            if match is not None and match not in pairs.values():
                pairs[(org_ref, node["id"])] = match
    return pairs


def merge_meraki_into_graph(
    nodes_by_id: dict[Any, dict],
    edges: list[dict],
    snapshots: list[tuple[int, dict]],
    *,
    host_node: Callable[[int], dict | None],
    resolve_external: Callable[[str, str], Any],
    match_host: Callable[[int, dict], int | None] | None = None,
) -> None:
    """Merge ``(org_ref, snapshot)`` pairs into the topology graph in place.

    ``host_node(host_id)`` returns the graph node for an inventory host,
    adding it to the graph if it was not there yet (``None`` if the host no
    longer exists). ``resolve_external(name, ip)`` returns the id of a graph
    node that already represents that neighbor, or ``None``.
    ``match_host(org_ref, snapshot_node)`` looks a node up in the *current* inventory,
    so a host added after the snapshot was built still collapses.

    Snapshots of different integrations are stitched together by public
    address: the device that answers on an address (its own, or that of its
    WAN uplink) is the far end of any VPN peer configured with that address.
    A cloud instance that is a device of another snapshot becomes that device
    (``virtual_appliance_pairs``).
    """
    y_cursor = 0.0
    # Public address -> graph node that answers on it. First claim wins.
    claims: dict[str, Any] = {}
    plans: list[dict[str, Any]] = []
    virtual = virtual_appliance_pairs(snapshots)

    def claim(plan: dict, node: dict, graph_id: Any) -> None:
        for address in _global_ips(node.get("ip"), node.get("alias_ips")):
            claims.setdefault(address, graph_id)
        # Addresses a gateway terminates tunnels on: whoever already
        # answers on one is the far end of that tunnel.
        for address in _global_ips(node.get("endpoint_ips")):
            holder = claims.setdefault(address, graph_id)
            if holder != graph_id:
                plan["links"].append((holder, graph_id, node["id"], address))

    def new_node(ref: dict, node: dict, provider: str, x: float, y: float) -> Any:
        # A neighbor nothing else knows stays per site: names such as
        # "Unknown neighbor" or a phone model repeat at every site, and one
        # shared node would cable all of those sites together.
        is_external = node["kind"] == "external"
        graph_id = meraki_graph_id(ref["org_ref"], node["id"])
        nodes_by_id[graph_id] = {
            "id": graph_id,
            "label": node.get("label") or graph_id,
            "ip": node.get("ip") or "",
            "device_type": "unknown" if is_external else provider,
            "device_category": "" if is_external else _CATEGORY.get(node["kind"], node["kind"]),
            "model": node.get("model") or "",
            "group_id": None,
            "group_name": "" if is_external else ref["site_name"],
            "status": "unknown" if is_external else _GRAPH_STATUS.get(ref["status"], "unknown"),
            "in_inventory": False,
            "ipam_subnet": "",
            "ipam_utilization_pct": None,
            "ipam_source_types": [],
            "meraki": ref,
            "x": x,
            "y": y,
        }
        if not is_external:
            nodes_by_id[graph_id]["source"] = "meraki"
        return graph_id

    def collapse(target: dict, ref: dict, x: float, y: float) -> Any:
        target.setdefault("meraki", ref)
        target.setdefault("x", x)
        target.setdefault("y", y)
        return target["id"]

    # Pass 1: devices. VPN peers wait until every device has claimed its addresses.
    for org_ref, snapshot in snapshots:
        snap_nodes = snapshot.get("nodes") or []
        if not snap_nodes:
            continue
        site_names = {s["id"]: s.get("name") or s["id"] for s in snapshot.get("sites") or []}
        # Which integration built the snapshot; they share this whole pipeline.
        provider = str(snapshot.get("provider") or "meraki")
        min_x = min(n.get("x", 0.0) for n in snap_nodes)
        min_y = min(n.get("y", 0.0) for n in snap_nodes)
        max_y = max(n.get("y", 0.0) for n in snap_nodes)
        plan: dict[str, Any] = {
            "org_ref": org_ref,
            "snapshot": snapshot,
            "provider": provider,
            "id_map": {},
            "peers": [],
            "instances": [],
            "links": [],
        }
        plans.append(plan)
        id_map: dict[str, Any] = plan["id_map"]

        for node in snap_nodes:
            ref = {
                "org_ref": org_ref,
                "node_id": node["id"],
                "site_id": node.get("site") or "",
                "site_name": site_names.get(node.get("site"), ""),
                "kind": node["kind"],
                "status": node.get("status") or "unknown",
                "serial": node.get("serial") or "",
                "provider": provider,
            }
            x = round(node.get("x", 0.0) - min_x + MERAKI_X_OFFSET, 1)
            y = round(node.get("y", 0.0) - min_y + y_cursor, 1)
            if node["kind"] == "vpn_peer":
                plan["peers"].append((node, ref, x, y))
                continue

            target: dict | None = None
            host_id = (node.get("inventory") or {}).get("host_id")
            if host_id is not None:
                target = host_node(int(host_id))
            if target is None and match_host is not None:
                live_id = match_host(org_ref, node)
                target = host_node(live_id) if live_id is not None else None
            if target is None and node["kind"] == "external":
                existing = resolve_external(_name_or_blank(node.get("label") or ""), node.get("ip") or "")
                target = nodes_by_id.get(existing) if existing is not None else None
            if target is None and (org_ref, node["id"]) in virtual:
                # A cloud instance that is a device of another snapshot (a
                # virtual appliance) waits until that device is on the map.
                plan["instances"].append((node, ref, x, y))
                continue
            graph_id = collapse(target, ref, x, y) if target is not None else new_node(ref, node, provider, x, y)
            id_map[node["id"]] = graph_id

            if node["kind"] in ("external", "wan"):
                continue  # a WAN stub's address belongs to the device behind it
            claim(plan, node, graph_id)

        wan_ids = {n["id"] for n in snap_nodes if n["kind"] == "wan"}
        wan_ips = {n["id"]: n.get("ip") for n in snap_nodes if n["kind"] == "wan"}
        for edge in snapshot.get("edges") or []:
            for wan, device in ((edge["a"], edge["b"]), (edge["b"], edge["a"])):
                if wan in wan_ids and device not in wan_ids and device in id_map:
                    for address in _global_ips(wan_ips[wan]):
                        claims.setdefault(address, id_map[device])
        y_cursor += (max_y - min_y) + MERAKI_ORG_GAP

    # Virtual appliances: the instance is the device that manages it.
    device_ids = {plan["org_ref"]: plan["id_map"] for plan in plans}
    for plan in plans:
        for node, ref, x, y in plan["instances"]:
            other_ref, other_id = virtual[(plan["org_ref"], node["id"])]
            target = nodes_by_id.get(device_ids.get(other_ref, {}).get(other_id))
            graph_id = (
                collapse(target, ref, x, y) if target is not None else new_node(ref, node, plan["provider"], x, y)
            )
            plan["id_map"][node["id"]] = graph_id
            claim(plan, node, graph_id)

    # Pass 2: VPN peers. One whose address a device on the map answers on is
    # that device; the rest stay as peers (shared when two snapshots name the
    # same address).
    for plan in plans:
        for node, ref, x, y in plan["peers"]:
            address = str(node.get("ip") or "").strip()
            target: dict | None = None
            if address:
                existing = resolve_external("", address)
                target = nodes_by_id.get(existing) if existing is not None else None
            public = _global_ips(address)
            if target is None and public:
                target = nodes_by_id.get(claims.get(public[0]))
            if target is not None:
                plan["id_map"][node["id"]] = collapse(target, ref, x, y)
                continue
            graph_id = new_node(ref, node, plan["provider"], x, y)
            plan["id_map"][node["id"]] = graph_id
            for item in public:
                claims.setdefault(item, graph_id)

    # Pass 3: links.
    for plan in plans:
        org_ref, provider, id_map = plan["org_ref"], plan["provider"], plan["id_map"]
        # Links Plexus discovered itself win over the Meraki view of the same
        # adjacency (they carry utilization and STP state).
        discovered_pairs = {frozenset((str(e["from"]), str(e["to"]))) for e in edges}
        for edge in plan["snapshot"].get("edges") or []:
            a, b = id_map.get(edge["a"]), id_map.get(edge["b"])
            if a is None or b is None or a == b:
                continue
            if edge["kind"] == "lan" and frozenset((str(a), str(b))) in discovered_pairs:
                continue
            a_port, b_port = str(edge.get("a_port") or ""), str(edge.get("b_port") or "")
            edges.append(
                {
                    "id": f"meraki:{org_ref}:{edge['id']}",
                    "from": a,
                    "to": b,
                    "label": " -- ".join(p for p in (a_port, b_port) if p),
                    "protocol": _PROTOCOL.get(edge["kind"], "lldp"),
                    "source_interface": a_port,
                    "target_interface": b_port,
                    "color": "#808080",
                    "width": 1,
                    "source": "meraki",
                    "provider": provider,
                    "status": edge.get("status") or "",
                }
            )
        for holder, graph_id, node_id, address in plan["links"]:
            if frozenset((str(holder), str(graph_id))) in {frozenset((str(e["from"]), str(e["to"]))) for e in edges}:
                continue  # the tunnel is already drawn from the other side
            edges.append(
                {
                    "id": f"meraki:{org_ref}:ip:{node_id}:{address}",
                    "from": holder,
                    "to": graph_id,
                    "label": "",
                    "protocol": "vpn",
                    "source_interface": "",
                    "target_interface": "",
                    "color": "#808080",
                    "width": 1,
                    "source": "meraki",
                    "provider": provider,
                    "status": "",
                }
            )


# ── Node details and search ──────────────────────────────────────────────────


SITE_ADDRESSING_TITLES = ("VLANs", "Single LAN", "Network ranges", "Subnets", "VPN address pools")


def node_details(snapshot: dict, node_id: str) -> dict | None:
    """Detail payload for one snapshot node (plus its site's configuration
    when the node is the site's security appliance)."""
    node = next((n for n in snapshot.get("nodes") or [] if n["id"] == node_id), None)
    if node is None:
        return None
    site = next((s for s in snapshot.get("sites") or [] if s["id"] == node.get("site")), None)
    site_sections = (site or {}).get("sections") or []
    managed = node["kind"] not in NON_DEVICE_KINDS
    return {
        "node_id": node_id,
        "provider": str(snapshot.get("provider") or "meraki"),
        "label": node.get("label") or "",
        "kind": node["kind"],
        "model": node.get("model") or "",
        "status": node.get("status") or "unknown",
        "generated_at": snapshot.get("generated_at") or "",
        "site_name": (site or {}).get("name") or "",
        "sections": node.get("sections") or [],
        "site_sections": site_sections if node.get("site_sections") else [],
        # The site's VLANs apply to every device in it, not just the appliance.
        "site_addressing": [s for s in site_sections if s["title"] in SITE_ADDRESSING_TITLES] if managed else [],
    }


def _section_rows(section: dict) -> list[str]:
    if section.get("kind") == "kv":
        return [f"{row[0]}: {row[1]}" for row in section.get("rows") or []]
    if section.get("kind") == "table":
        return [" · ".join(row) for row in section.get("rows") or []]
    return str(section.get("text") or "").splitlines()


def build_search_index(snapshot: dict) -> list[dict]:
    """Flatten a snapshot into per-node searchable text.

    Site-level content (VLANs, routes, firewall rules...) is attributed to the
    site's appliance node, falling back to any node of the site, so every
    match resolves to something on the map.
    """
    by_site: dict[str, list[dict]] = {}
    for node in snapshot.get("nodes") or []:
        by_site.setdefault(node.get("site") or "", []).append(node)
    site_owner: dict[str, str] = {}
    for site_id, members in by_site.items():
        owner = next((n for n in members if n.get("site_sections")), None) or members[0]
        site_owner[site_id] = owner["id"]

    entries: dict[str, dict] = {}
    for node in snapshot.get("nodes") or []:
        head = " ".join(str(node.get(k) or "") for k in ("label", "serial", "mac", "ip", "model", "status"))
        rows = [(s["title"], row) for s in node.get("sections") or [] for row in _section_rows(s)]
        entries[node["id"]] = {
            "node_id": node["id"],
            "label": node.get("label") or "",
            "head": head.lower(),
            "rows": rows,
        }
    for site in snapshot.get("sites") or []:
        owner_id = site_owner.get(site["id"])
        if owner_id is None:
            continue
        entry = entries[owner_id]
        entry["head"] += f" {str(site.get('name') or '').lower()}"
        entry["rows"].extend(
            (f"{site.get('name')} · {s['title']}", row) for s in site.get("sections") or [] for row in _section_rows(s)
        )
    for entry in entries.values():
        entry["blob"] = entry["head"] + "\n" + "\n".join(text.lower() for _title, text in entry["rows"])
    return list(entries.values())


def search_index(index: list[dict], tokens: list[str], limit: int) -> list[dict]:
    """All-token substring match. Returns ``{node_id, label, snippet}`` rows."""
    hits: list[dict] = []
    for entry in index:
        if not all(token in entry["blob"] for token in tokens):
            continue
        snippet = ""
        if not all(token in entry["head"] for token in tokens):
            # Prefer the row that matches the whole query; otherwise show
            # where the first term was found.
            partial = ""
            for title, text in entry["rows"]:
                lowered = text.lower()
                if all(token in lowered for token in tokens):
                    snippet = f"{title}: {text}"[:240]
                    break
                if not partial and tokens[0] in lowered:
                    partial = f"{title}: {text}"[:240]
            snippet = snippet or partial
        hits.append({"node_id": entry["node_id"], "label": entry["label"], "snippet": snippet})
        if len(hits) >= limit:
            break
    return hits


# ── Whole-topology HTML export ───────────────────────────────────────────────


def _viewer_status(status: str) -> str:
    return {"up": "online", "down": "offline", "alerting": "alerting"}.get(status or "", "unknown")


def graph_to_snapshot(
    graph: dict,
    snapshots: dict[int, dict],
    host_sections: dict[int, list[dict]],
    *,
    title: str = "Plexus",
) -> dict[str, Any]:
    """Convert the merged ``/api/topology`` graph into a viewer snapshot.

    ``snapshots`` maps org_ref -> latest Meraki snapshot (source of Meraki
    detail sections); ``host_sections`` maps inventory host id -> sections
    built from data Plexus collected over SNMP/SSH.
    """
    snap_nodes = {(org_ref, n["id"]): n for org_ref, snap in snapshots.items() for n in snap.get("nodes") or []}
    snap_sites = {(org_ref, s["id"]): s for org_ref, snap in snapshots.items() for s in snap.get("sites") or []}

    sites: dict[str, dict] = {}

    def site_for(node: dict) -> str:
        ref = node.get("meraki")
        if ref:
            site_id = f"m{ref['org_ref']}:{ref['site_id']}"
            if site_id not in sites:
                src = snap_sites.get((ref["org_ref"], ref["site_id"])) or {}
                sites[site_id] = {
                    "id": site_id,
                    "name": src.get("name") or ref.get("site_name") or "Meraki site",
                    "tags": list(src.get("tags") or []),
                    "vpn_mode": src.get("vpn_mode") or "none",
                    "sections": list(src.get("sections") or []),
                }
            return site_id
        if node.get("in_inventory"):
            site_id = f"g:{node.get('group_id')}"
            sites.setdefault(
                site_id,
                {
                    "id": site_id,
                    "name": node.get("group_name") or "Inventory",
                    "tags": [],
                    "vpn_mode": "none",
                    "sections": [],
                },
            )
            return site_id
        sites.setdefault(
            EXTERNAL_SITE_ID,
            {"id": EXTERNAL_SITE_ID, "name": "External neighbors", "tags": [], "vpn_mode": "none", "sections": []},
        )
        return EXTERNAL_SITE_ID

    nodes: dict[str, dict] = {}
    for g in graph.get("nodes") or []:
        ref = g.get("meraki")
        src = snap_nodes.get((ref["org_ref"], ref["node_id"])) if ref else None
        sections: list[dict] = []
        if g.get("in_inventory"):
            kind = _VIEWER_KIND.get(str(g.get("device_category") or "").lower(), "device")
            status = _viewer_status(str(g.get("status") or ""))
            _add(
                sections,
                kv_section(
                    "Overview",
                    [
                        ("Hostname", g.get("label")),
                        ("IP address", g.get("ip")),
                        ("Status", g.get("status")),
                        ("Device type", g.get("device_type")),
                        ("Role", g.get("device_category")),
                        ("Model", g.get("model")),
                        ("Inventory group", g.get("group_name")),
                        ("IPAM subnet", g.get("ipam_subnet")),
                    ],
                ),
            )
            sections.extend(host_sections.get(g["id"], []) if isinstance(g["id"], int) else [])
            if src:
                sections.extend(s for s in src.get("sections") or [] if s.get("title") != "Plexus inventory")
        elif src:
            kind = src["kind"]
            status = src.get("status") or "unknown"
            sections.extend(src.get("sections") or [])
        else:
            kind = "external"
            status = "unknown"
            _add(
                sections,
                kv_section(
                    "Discovered neighbor",
                    [
                        ("Name", g.get("label")),
                        ("Address", g.get("ip")),
                        ("Platform", g.get("platform") or g.get("model")),
                        ("Source", "CDP/LLDP as seen by inventory devices (not in Plexus inventory)"),
                    ],
                ),
            )
        node_id = str(g["id"])
        nodes[node_id] = {
            "id": node_id,
            "kind": kind,
            "label": g.get("label") or node_id,
            "site": site_for(g),
            "status": status,
            "model": g.get("model") or "",
            "serial": (src or {}).get("serial") or "",
            "mac": (src or {}).get("mac") or "",
            "ip": g.get("ip") or "",
            "sections": sections,
        }
        if src and src.get("site_sections"):
            nodes[node_id]["site_sections"] = True
        if g.get("in_inventory"):
            nodes[node_id]["inventory"] = {"host_id": g["id"]}

    edges: list[dict] = []
    for index, g in enumerate(graph.get("edges") or [], start=1):
        a, b = str(g.get("from")), str(g.get("to"))
        if a not in nodes or b not in nodes or a == b:
            continue
        protocol = str(g.get("protocol") or "")
        kind = _EDGE_KIND.get(protocol, "lan")
        util = g.get("utilization") or {}
        edge: dict[str, Any] = {
            "id": f"e{index}",
            "a": a,
            "b": b,
            "kind": kind,
            "a_port": g.get("source_interface") or "",
            "b_port": g.get("target_interface") or "",
            "status": g.get("status") or "",
            "sections": [],
        }
        _add(
            edge["sections"],
            kv_section(
                "Link",
                [
                    ("A end", nodes[a]["label"]),
                    ("A port", edge["a_port"]),
                    ("B end", nodes[b]["label"]),
                    ("B port", edge["b_port"]),
                    ("Discovered via", _SOURCE_NAME.get(str(g.get("provider") or g.get("source")), protocol.upper())),
                    ("Status", edge["status"]),
                    ("Utilization", f"{util['utilization_pct']}%" if util.get("utilization_pct") is not None else ""),
                ],
            ),
        )
        edges.append(edge)
        # WAN stubs are laid out above the appliance they hang off.
        for wan, parent in ((a, b), (b, a)):
            if kind == "uplink" and nodes[wan]["kind"] == "wan":
                nodes[wan]["parent"] = parent

    site_list = list(sites.values())
    for site in site_list:
        members = [n for n in nodes.values() if n["site"] == site["id"] and n["kind"] not in ("external", "wan")]
        site["status"] = _worst([m["status"] for m in members]) if members else "unknown"
        site["device_count"] = len(members)

    # Inside a cloud site, attachments shape the box like cables do.
    _layout(site_list, nodes, [{**e, "kind": "lan"} if e["kind"] == "attach" else e for e in edges])
    node_list = list(nodes.values())
    for node in node_list:
        node.pop("parent", None)

    counted = [n for n in node_list if n["kind"] not in NON_DEVICE_KINDS]
    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in counted:
        by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
        by_status[node["status"]] = by_status.get(node["status"], 0) + 1
    edge_counts: dict[str, int] = {}
    for edge in edges:
        edge_counts[edge["kind"]] = edge_counts.get(edge["kind"], 0) + 1

    sources = ["Plexus topology discovery (SNMP CDP/LLDP/OSPF/BGP)", "Plexus inventory (SNMP/SSH-collected data)"]
    errors: list[dict] = []
    for snap in snapshots.values():
        collection = snap.get("collection") or {}
        errors.extend(collection.get("errors") or [])
        for source in collection.get("sources") or []:
            if source not in sources:
                sources.append(source)

    return {
        "schema": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": {"id": "", "name": title, "url": ""},
        "summary": {
            "sites": len(site_list),
            "devices": len(counted),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": sum(1 for n in node_list if n["kind"] == "external"),
            "inventory_matches": sum(1 for n in node_list if n.get("inventory")),
            "lan_links": edge_counts.get("lan", 0) + edge_counts.get("stack", 0),
            "vpn_tunnels": edge_counts.get("vpn", 0) + edge_counts.get("vpn3p", 0),
            "wan_uplinks": edge_counts.get("uplink", 0),
            "cloud_links": edge_counts.get("attach", 0),
            "vlans": sum((snap.get("summary") or {}).get("vlans", 0) for snap in snapshots.values()),
        },
        "collection": {"sources": sources, "stats": {}, "errors": errors, "options": {}},
        "sites": site_list,
        "nodes": node_list,
        "edges": edges,
    }
