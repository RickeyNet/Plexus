"""Turn raw Cato payloads into a positioned topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), so the merge
into the Topology graph, node details, deep search, the subnet index and the
HTML export need no Cato-specific code.

How a Cato account maps onto the map:

  - every site is a site box holding its Socket(s) and their WAN links; a
    site with no Socket (IPsec, cloud interconnect) gets one node standing
    for its connection
  - every PoP in use is a node in a "Cato Cloud" box, joined to a single
    backbone node; each Socket has a tunnel to the PoP it is connected to
  - connected remote users are one node with the users listed behind it
    (one node per user would bury the map)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.meraki.normalize import (
    SCHEMA_VERSION,
    InventoryIndex,
    _add,
    _inventory_ref,
    _layout,
    _s,
    _worst,
    kv_section,
    table_section,
)
from netcontrol.integrations.meraki.subnets import _cidr

CLOUD_SITE_ID = "__cato_cloud__"
CLOUD_NODE_ID = "cato:cloud"
USERS_NODE_ID = "cato:users"

# Kinds that are part of the Cato cloud rather than devices at a site.
CLOUD_KINDS = ("cloud", "users")

RANGE_SECTION_TITLE = "Network ranges"
RANGE_COLUMNS = ["Subnet", "Name", "Interface", "VLAN", "Source"]

MAX_LISTED_USERS = 5000

_SITE_STATUS = {"connected": "online", "degraded": "alerting", "disconnected": "offline"}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _status(raw: Any) -> str:
    return _SITE_STATUS.get(_text(raw).lower(), "unknown")


def _mbps(value: Any) -> str:
    return f"{value} Mbps" if value not in (None, "") else ""


def _is_primary(device: dict) -> bool:
    socket = device.get("socketInfo") or {}
    return bool(socket.get("isPrimary")) or _text(device.get("haRole")).lower() in ("primary", "master")


class _Builder:
    def __init__(self, raw: dict, inventory: InventoryIndex) -> None:
        self.raw = raw
        self.inventory = inventory
        self.sites_raw: list[dict] = [s for s in raw.get("sites") or [] if isinstance(s, dict) and s.get("id")]
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.sites: list[dict] = []
        self.range_count = 0
        # PoP name -> [site name, device label, state] rows.
        self._pop_sites: dict[str, list[list[str]]] = {}
        self._cloud_sites: list[list[str]] = []

    # ── Graph primitives ───────────────────────────────────────────────────

    def _node(self, node_id: str, kind: str, label: str, site: str, status: str, **fields: Any) -> dict:
        node = {
            "id": node_id,
            "kind": kind,
            "label": label,
            "site": site,
            "status": status,
            "model": "",
            "serial": "",
            "mac": "",
            "ip": "",
            "sections": [],
        }
        node.update(fields)
        self.nodes[node_id] = node
        return node

    def _edge(self, a: str, b: str, kind: str, **fields: Any) -> None:
        if a == b or a not in self.nodes or b not in self.nodes:
            return
        edge = {"id": f"e{len(self.edges) + 1}", "a": a, "b": b, "kind": kind, "a_port": "", "b_port": "", "status": ""}
        edge.update(fields)
        self.edges.append(edge)

    def _pop_node(self, name: str) -> str:
        node_id = f"pop:{name}"
        if node_id not in self.nodes:
            self._node(node_id, "cloud", f"PoP {name}", CLOUD_SITE_ID, "online", model="Cato PoP")
        return node_id

    # ── Subnets ────────────────────────────────────────────────────────────

    def _ranges_by_site(self) -> dict[str, list[list[str]]]:
        """Network range rows per site id, from the entity lookups."""
        by_id = {_text(s["id"]): s for s in self.sites_raw}
        by_name = {_text((s.get("info") or {}).get("name")).lower(): _text(s["id"]) for s in self.sites_raw}
        rows: dict[str, dict[str, list[str]]] = {}
        # Ranges first: they name the range; an interface only adds a native
        # range that no range entity covered.
        for source, items in (("Range", self.raw.get("ranges")), ("Interface", self.raw.get("interfaces"))):
            for item in items or []:
                if not isinstance(item, dict):
                    continue
                entity = item.get("entity") or {}
                helper = item.get("helperFields") if isinstance(item.get("helperFields"), dict) else {}
                # Entity names read "Site \ Interface \ Range".
                parts = [p.strip() for p in _text(entity.get("name")).split("\\") if p.strip()]
                site_id = _text(helper.get("siteId") or helper.get("siteID"))
                if site_id not in by_id:
                    site_name = _text(helper.get("siteName")) or (parts[0] if parts else "")
                    site_id = by_name.get(site_name.lower(), "")
                cidr = _cidr(helper.get("subnet") or helper.get("range"))
                if not site_id or not cidr or cidr in ("0.0.0.0/0", "::/0"):
                    continue
                interface = _text(helper.get("interfaceName")) or (parts[1] if len(parts) > 1 else "")
                name = parts[-1] if len(parts) > 2 else ("Native range" if source == "Interface" else interface)
                vlan = _text(helper.get("vlanTag") or helper.get("vlan"))
                rows.setdefault(site_id, {}).setdefault(cidr, [cidr, name, interface, vlan, source])
        return {site_id: list(found.values()) for site_id, found in rows.items()}

    # ── Sites, Sockets and their links ─────────────────────────────────────

    def build_sites(self) -> None:
        ranges = self._ranges_by_site()
        self._node(CLOUD_NODE_ID, "cloud", "Cato Cloud", CLOUD_SITE_ID, "online", model="Cato backbone")
        for site in sorted(self.sites_raw, key=lambda s: _text((s.get("info") or {}).get("name")).lower()):
            site_id = _text(site["id"])
            info = site.get("info") or {}
            name = _text(info.get("name")) or f"Site {site_id}"
            status = _status(site.get("connectivityStatus"))
            members = self._site_devices(site, site_id, name, status)

            sections: list[dict] = []
            ha = site.get("haStatus") or {}
            _add(
                sections,
                kv_section(
                    "Site overview",
                    [
                        ("Site", name),
                        ("Site ID", site_id),
                        ("Type", info.get("type")),
                        ("Connection", info.get("connType")),
                        ("Connectivity", site.get("connectivityStatus")),
                        ("Operational status", site.get("operationalStatus")),
                        ("PoP", site.get("popName")),
                        ("High availability", info.get("isHA")),
                        ("HA readiness", ha.get("readiness")),
                        ("HA WAN connectivity", ha.get("wanConnectivity")),
                        ("HA keys in sync", ha.get("keys")),
                        ("HA routes in sync", ha.get("routes")),
                        ("Hosts seen", site.get("hostCount")),
                        ("City", info.get("cityName")),
                        ("State", info.get("countryStateName")),
                        ("Country", info.get("countryName") or info.get("countryCode")),
                        ("Address", info.get("address")),
                        ("Description", info.get("description")),
                        ("Connected since", site.get("connectedSince")),
                        ("Last connected", site.get("lastConnected")),
                    ],
                ),
            )
            site_ranges = sorted(ranges.get(site_id, []), key=lambda r: (r[2], r[0]))
            self.range_count += len(site_ranges)
            _add(sections, table_section(RANGE_SECTION_TITLE, RANGE_COLUMNS, site_ranges))
            _add(
                sections,
                table_section(
                    "Site interfaces",
                    ["Interface", "Role", "Destination", "Upstream", "Downstream"],
                    [
                        [
                            i.get("name") or i.get("id"),
                            i.get("wanRole"),
                            i.get("destType"),
                            _mbps(i.get("upBandwidth")),
                            _mbps(i.get("downBandwidth")),
                        ]
                        for i in info.get("interfaces") or []
                        if isinstance(i, dict)
                    ],
                ),
            )
            ipsec = info.get("ipsec") or {}
            _add(
                sections,
                kv_section(
                    "IPsec tunnel",
                    [
                        ("Cato IP", ipsec.get("catoIP")),
                        ("Remote IP", ipsec.get("remoteIP")),
                        ("IKE version", ipsec.get("ikeVersion")),
                        ("Primary", ipsec.get("isPrimary")),
                    ],
                ),
            )
            self.sites.append(
                {
                    "id": site_id,
                    "name": name,
                    "tags": [],
                    "vpn_mode": "spoke",
                    "status": _worst([status, *(m["status"] for m in members)]),
                    "device_count": len(members),
                    "sections": sections,
                }
            )

    def _site_devices(self, site: dict, site_id: str, site_name: str, site_status: str) -> list[dict]:
        info = site.get("info") or {}
        devices = [d for d in site.get("devices") or [] if isinstance(d, dict)]
        site_pop = _text(site.get("popName"))
        members: list[dict] = []

        if not devices:
            # No Socket: the site is an IPsec / cloud connection to a PoP.
            ipsec = info.get("ipsec") or {}
            node = self._node(
                f"s:{site_id}",
                "appliance",
                site_name,
                site_id,
                site_status,
                model=_text(info.get("connType")) or _text(info.get("type")),
                ip=_text(ipsec.get("remoteIP")),
                site_sections=True,
            )
            _add(
                node["sections"],
                kv_section(
                    "Overview",
                    [
                        ("Site", site_name),
                        ("Status", site_status),
                        ("Connection", info.get("connType")),
                        ("Type", info.get("type")),
                        ("PoP", site_pop),
                        ("Source", "Cato site without a Socket (connected to the PoP directly)"),
                    ],
                ),
            )
            self._tunnel(node, site_name, [site_pop] if site_pop else [], site_status != "offline")
            return [node]

        primary = next((d for d in devices if _is_primary(d)), devices[0])
        for index, device in enumerate(devices):
            socket = device.get("socketInfo") or {}
            connected = bool(device.get("connected"))
            status = "offline" if not connected else ("alerting" if site_status == "alerting" else "online")
            ident = _text(device.get("id")) or f"{site_id}:{index}"
            role = _text(device.get("haRole"))
            label = _text(device.get("name")) or site_name
            if len(devices) > 1 and role and role.lower() not in label.lower():
                label = f"{label} ({role.lower()})"
            serial = _text(socket.get("serial"))
            node = self._node(
                f"d:{ident}",
                "appliance",
                label,
                site_id,
                status,
                model=_text(socket.get("platform")) or _text(device.get("type")),
                serial=serial,
                ip=_text(device.get("internalIP")),
            )
            if device is primary:
                node["site_sections"] = True
            host = self.inventory.match(serial=serial, ips=[node["ip"]])
            if host:
                node["inventory"] = _inventory_ref(host)

            interfaces = [i for i in device.get("interfaces") or [] if isinstance(i, dict)]
            _add(
                node["sections"],
                kv_section(
                    "Overview",
                    [
                        ("Name", device.get("name")),
                        ("Status", status),
                        ("Site", site_name),
                        ("Model", node["model"]),
                        ("Serial", serial),
                        ("HA role", role),
                        ("Socket version", socket.get("version") or device.get("version")),
                        ("Internal IP", node["ip"]),
                        ("PoP", device.get("lastPopName") or site_pop),
                        ("Connected since", device.get("connectedSince")),
                        ("Last connected", device.get("lastConnected")),
                        ("Identifier", device.get("identifier")),
                    ],
                ),
            )
            _add(
                node["sections"],
                table_section(
                    "WAN links",
                    ["Interface", "Port", "Connected", "PoP", "Public IP", "Provider", "Tunnel uptime (s)", "Role"],
                    [
                        [
                            i.get("name") or i.get("id"),
                            i.get("physicalPort"),
                            bool(i.get("connected")),
                            i.get("popName"),
                            i.get("tunnelRemoteIP"),
                            (i.get("tunnelRemoteIPInfo") or {}).get("provider"),
                            i.get("tunnelUptime"),
                            (i.get("info") or {}).get("wanRole"),
                        ]
                        for i in interfaces
                    ],
                ),
            )
            if host:
                _add(
                    node["sections"],
                    kv_section(
                        "Plexus inventory",
                        [
                            ("Hostname", host.get("hostname")),
                            ("IP address", host.get("ip_address")),
                            ("Device type", host.get("device_type")),
                        ],
                    ),
                )
            self._wan_links(node, ident, interfaces)

            pops = sorted({_text(i.get("popName")) for i in interfaces if i.get("connected") and i.get("popName")})
            if not pops and connected:
                fallback = _text(device.get("lastPopName")) or site_pop
                pops = [fallback] if fallback else []
            self._tunnel(node, site_name, pops if connected else [], connected)
            members.append(node)
        return members

    def _wan_links(self, node: dict, ident: str, interfaces: list[dict]) -> None:
        for index, iface in enumerate(interfaces):
            connected = bool(iface.get("connected"))
            address = _text(iface.get("tunnelRemoteIP"))
            if not connected and not address:
                continue  # an unused port, not a WAN link
            name = _text(iface.get("name")) or _text(iface.get("id")) or f"wan{index + 1}"
            remote = iface.get("tunnelRemoteIPInfo") or {}
            info = iface.get("info") or {}
            wan_id = f"w:{ident}:{_text(iface.get('id')) or index}"
            wan = self._node(
                wan_id,
                "wan",
                f"{name} {address}".strip(),
                node["site"],
                "online" if connected else "offline",
                ip=address,
                parent=node["id"],
            )
            _add(
                wan["sections"],
                kv_section(
                    "WAN link",
                    [
                        ("Socket", node["label"]),
                        ("Interface", name),
                        ("Port", iface.get("physicalPort")),
                        ("Connected", connected),
                        ("Public IP", address),
                        ("Provider", remote.get("provider")),
                        ("Location", [remote.get("city"), remote.get("countryName")]),
                        ("PoP", iface.get("popName")),
                        ("Role", info.get("wanRole")),
                        ("Upstream", _mbps(info.get("upBandwidth"))),
                        ("Downstream", _mbps(info.get("downBandwidth"))),
                        ("Tunnel uptime (s)", iface.get("tunnelUptime")),
                    ],
                ),
            )
            self._edge(wan_id, node["id"], "uplink", b_port=name, status="active" if connected else "failed")

    def _tunnel(self, node: dict, site_name: str, pops: list[str], connected: bool) -> None:
        """Join a site's device to the PoP(s) it is connected to. A device
        that is down keeps a (down) link to the cloud so it stays attached."""
        if not connected or not pops:
            state = "reachable" if connected else "unreachable"
            self._edge(node["id"], CLOUD_NODE_ID, "vpn", status=state, label="Cato tunnel")
            self._cloud_sites.append([site_name, node["label"], "connected" if connected else "disconnected"])
            return
        for pop in pops:
            self._edge(node["id"], self._pop_node(pop), "vpn", status="reachable", label="Cato tunnel")
            self._pop_sites.setdefault(pop, []).append([site_name, node["label"], "connected"])

    # ── The Cato cloud: PoPs, backbone, remote users ───────────────────────

    def build_cloud(self) -> None:
        users = [u for u in self.raw.get("users") or [] if isinstance(u, dict)]
        include_users = bool((self.raw.get("options") or {}).get("include_users", True))
        connected = [u for u in users if _text(u.get("connectivityStatus")).lower() != "disconnected"]
        users_by_pop: dict[str, int] = {}
        for user in connected:
            pop = _text(user.get("popName"))
            if pop:
                users_by_pop[pop] = users_by_pop.get(pop, 0) + 1
                self._pop_node(pop)

        pop_rows: list[list[Any]] = []
        for node in [n for n in self.nodes.values() if n["id"].startswith("pop:")]:
            name = node["id"][len("pop:") :]
            site_rows = self._pop_sites.get(name, [])
            pop_rows.append([name, len({r[0] for r in site_rows}), users_by_pop.get(name, 0)])
            _add(
                node["sections"],
                kv_section(
                    "Cato PoP",
                    [
                        ("PoP", name),
                        ("Sites connected", len({r[0] for r in site_rows})),
                        ("Remote users connected", users_by_pop.get(name, 0)),
                    ],
                ),
            )
            _add(node["sections"], table_section("Connected sites", ["Site", "Device", "State"], site_rows))
            self._edge(node["id"], CLOUD_NODE_ID, "vpn", status="reachable", label="Cato backbone")

        cloud = self.nodes[CLOUD_NODE_ID]
        account = self.raw.get("account") or {}
        _add(
            cloud["sections"],
            kv_section(
                "Cato Cloud",
                [
                    ("Account", account.get("name")),
                    ("Account ID", account.get("id")),
                    ("Sites", len(self.sites_raw)),
                    ("PoPs in use", len(pop_rows)),
                    ("Remote users connected", len(connected) if include_users else ""),
                    ("Snapshot time", self.raw.get("timestamp")),
                ],
            ),
        )
        _add(cloud["sections"], table_section("PoPs in use", ["PoP", "Sites", "Remote users"], sorted(pop_rows)))
        _add(
            cloud["sections"],
            table_section("Sites without a PoP", ["Site", "Device", "State"], self._cloud_sites),
        )

        if include_users:
            self._users_node(connected)

    def _users_node(self, connected: list[dict]) -> None:
        node = self._node(
            USERS_NODE_ID,
            "users",
            f"Remote users ({len(connected)})",
            CLOUD_SITE_ID,
            "online" if connected else "unknown",
            model="Cato Client",
        )
        _add(
            node["sections"],
            kv_section(
                "Remote users",
                [
                    ("Connected now", len(connected)),
                    ("Connected from an office", sum(1 for u in connected if u.get("connectedInOffice"))),
                    ("Source", "Users connected to Cato with the Cato Client when the collection ran"),
                ],
            ),
        )
        ordered = sorted(connected, key=lambda u: _text(u.get("name") or (u.get("info") or {}).get("name")).lower())
        _add(
            node["sections"],
            table_section(
                "Connected users",
                ["User", "Email", "Device", "VPN IP", "Public IP", "PoP", "Location", "OS", "Client", "Uptime (s)"],
                [
                    [
                        u.get("name") or (u.get("info") or {}).get("name"),
                        (u.get("info") or {}).get("email"),
                        u.get("deviceName"),
                        u.get("internalIP"),
                        u.get("remoteIP"),
                        u.get("popName"),
                        [(u.get("remoteIPInfo") or {}).get("city"), (u.get("remoteIPInfo") or {}).get("countryName")],
                        [u.get("osType"), u.get("osVersion")],
                        u.get("version"),
                        u.get("uptime"),
                    ]
                    for u in ordered[:MAX_LISTED_USERS]
                ],
            ),
        )
        self._edge(USERS_NODE_ID, CLOUD_NODE_ID, "vpn", status="reachable" if connected else "", label="Cato Client")

    def build_edge_sections(self) -> None:
        titles = {"vpn": "Cato tunnel", "uplink": "WAN link"}
        for edge in self.edges:
            a, b = self.nodes[edge["a"]], self.nodes[edge["b"]]
            edge["sections"] = [
                s
                for s in [
                    kv_section(
                        edge.get("label") or titles.get(edge["kind"], "Link"),
                        [
                            ("A end", a["label"]),
                            ("B end", b["label"]),
                            ("B port", edge.get("b_port")),
                            ("Status", edge.get("status")),
                            ("Discovered via", "Cato API"),
                        ],
                    )
                ]
                if s
            ]


def build_snapshot(raw: dict, inventory: InventoryIndex | None = None) -> dict[str, Any]:
    """Build the positioned topology snapshot from raw collector output."""
    builder = _Builder(raw, inventory or InventoryIndex())
    builder.build_sites()
    builder.build_cloud()
    builder.build_edge_sections()

    cloud_members = [n for n in builder.nodes.values() if n["site"] == CLOUD_SITE_ID]
    sites = builder.sites + [
        {
            "id": CLOUD_SITE_ID,
            "name": "Cato Cloud",
            "tags": [],
            # Sorts the cloud ahead of the sites, like a VPN hub.
            "vpn_mode": "hub",
            "status": "online",
            "device_count": len(cloud_members),
            "sections": [],
        }
    ]
    _layout(sites, builder.nodes, builder.edges)

    nodes = list(builder.nodes.values())
    for node in nodes:
        node.pop("parent", None)

    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in nodes:
        if node["kind"] == "wan" or node["kind"] in CLOUD_KINDS:
            continue
        by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
        by_status[node["status"]] = by_status.get(node["status"], 0) + 1
    edge_counts: dict[str, int] = {}
    for edge in builder.edges:
        edge_counts[edge["kind"]] = edge_counts.get(edge["kind"], 0) + 1

    account = raw.get("account") or {}
    users = [u for u in raw.get("users") or [] if isinstance(u, dict)]
    return {
        "schema": SCHEMA_VERSION,
        "provider": "cato",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": {
            "id": _s(account.get("id")),
            "name": account.get("name") or "Cato account",
            "url": "",
        },
        "summary": {
            "sites": len(builder.sites),
            "devices": sum(by_kind.values()),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": 0,
            "inventory_matches": sum(1 for n in nodes if n.get("inventory")),
            "lan_links": 0,
            "vpn_tunnels": edge_counts.get("vpn", 0),
            "wan_uplinks": edge_counts.get("uplink", 0),
            "vlans": builder.range_count,
            "remote_users": sum(1 for u in users if _text(u.get("connectivityStatus")).lower() != "disconnected"),
        },
        "collection": {
            "sources": ["Cato Networks API"],
            "stats": raw.get("stats") or {},
            "errors": raw.get("errors") or [],
            "options": raw.get("options") or {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }
