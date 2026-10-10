"""Turn the GCP discovery Cloud Visibility stores into a topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), the format the
AWS and Azure integrations produce too, so the merge into the Topology
graph, node details, deep search, the subnet index and the HTML export need
no GCP-specific code.

Every enabled GCP account (project) goes into one snapshot: resource uids
carry the project, so a peering between two projects joins up without any
matching.

How GCP maps onto the map:

  - every VPC network is a site box. GCP networks are global, so the box is
    named after the network alone (with the project when several are on the
    map). Its node stands for the network's router and owns every subnet of
    every region; the default internet gateway hangs off it like a WAN
    uplink (one per network that has a route to it), and its Cloud Routers,
    their Cloud NATs and its HA VPN gateways sit beside it
  - a VM instance is a node only when it forwards traffic (``canIpForward``:
    firewalls, routers, SD-WAN and VPN appliances) or is a Plexus inventory
    host (by address). Every instance is listed in its network's details
  - external VPN gateways (the far end of an HA VPN), Interconnect VLAN
    attachments and Interconnects share a "GCP VPN and Interconnect" box; a
    VPN tunnel is a tunnel from its gateway to the external VPN gateway (or
    the peer GCP gateway), red when it is not established
"""

from __future__ import annotations

import json
from typing import Any

from netcontrol.integrations.gcp.collect import WARNING_TYPE
from netcontrol.integrations.meraki.normalize import (
    SCHEMA_VERSION,
    InventoryIndex,
    _add,
    _inventory_ref,
    _layout,
    _worst,
    kv_section,
    table_section,
)

PROVIDER = "gcp"
TRANSIT_SITE_ID = "__gcp_transit__"
TRANSIT_SITE_NAME = "GCP VPN and Interconnect"

SUBNET_SECTION_TITLE = "Subnets"
SUBNET_COLUMNS = [
    "Subnet",
    "Name",
    "Region",
    "Secondary ranges",
    "Default route",
    "Cloud NAT",
    "Private Google access",
    "Addresses in use",
]
ROUTE_COLUMNS = ["Route", "Destination", "Priority", "Next hop", "Tags", "Type"]
FIREWALL_COLUMNS = [
    "Rule",
    "Priority",
    "Direction",
    "Action",
    "Protocols and ports",
    "Source",
    "Destination",
    "Targets",
    "State",
]
# The two rules every VPC network ends with; they are not listed by the API.
IMPLIED_RULES = [
    ["implied allow egress", 65535, "EGRESS", "allow", "all", "", "0.0.0.0/0", "every instance", "implied"],
    ["implied deny ingress", 65535, "INGRESS", "deny", "all", "0.0.0.0/0", "", "every instance", "implied"],
]

# Detail tables are capped so one large network cannot bloat the snapshot.
MAX_SITE_ROWS = 3000

_UP_STATES = (
    "",
    "active",
    "running",
    "established",
    "up",
    "ready",
    "available",
    "attached",
    "os_active",
    "enforced",
)
_PENDING = (
    "provisioning",
    "pending",
    "first_handshake",
    "waiting_for_full_config",
    "allocating_resources",
    "staging",
    "unknown",
)

# Connections that describe a resource rather than join two nodes.
_NOT_A_LINK = (
    "route_table_association",
    "security_boundary",
    "route_next_hop",
    "subnet_attachment",
    "router_attachment",
    "internet_gateway_attachment",
    "vpn_gateway_attachment",
    "vpn_tunnel",
)
_LINK_LABELS = {
    "vpc_peering": "VPC peering",
    "interconnect_attachment": "Interconnect attachment",
    "interconnect_link": "Interconnect",
}
_NEXT_HOP_NAMES = {
    "gateway": "Internet gateway",
    "ip": "Instance",
    "instance": "Instance",
    "ilb": "Internal load balancer",
    "vpn_tunnel": "VPN tunnel",
    "interconnect_attachment": "Interconnect attachment",
    "peering": "VPC peering",
    "network": "VPC network",
    "hub": "Network Connectivity Center hub",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _meta(row: dict) -> dict:
    meta = row.get("metadata")
    if isinstance(meta, dict):
        return meta
    try:
        parsed = json.loads(_text(row.get("metadata_json")) or "{}")
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _rid(uid: str) -> str:
    """``gcp:vpc:P:hub`` -> ``P:hub``."""
    parts = uid.split(":", 2)
    return parts[2] if len(parts) == 3 else uid


def _short(rid: str) -> str:
    """The name part of a resource id: ``P:us-central1:cr-hub`` -> ``cr-hub``."""
    return rid.rsplit(":", 1)[-1]


def _project(rid: str) -> str:
    return rid.split(":", 1)[0]


def _status(state: Any) -> str:
    state = _text(state).lower()
    if state in _UP_STATES:
        return "online"
    if state.startswith(_PENDING):
        return "unknown"
    return "offline"


def _link_status(state: Any) -> str:
    """Edge status of a connection: ``failed`` takes it out of path tracing."""
    return {"online": "active", "unknown": ""}.get(_status(state), "failed")


def next_hop_name(meta: dict) -> str:
    """How a route's next hop reads: ``Internet gateway``, ``Instance 10.0.0.5``,
    ``VPN tunnel tunnel-hq-0``..."""
    kind = _text(meta.get("next_hop_type"))
    name = _NEXT_HOP_NAMES.get(kind, kind or "unknown")
    target = _text(meta.get("next_hop_target"))
    if kind == "gateway":
        return "Default internet gateway" if _text(meta.get("next_hop_id")) == "default-internet-gateway" else name
    if kind in ("ip",) or (kind == "ilb" and "/" not in target):
        return f"{name} {target}".strip()
    shown = _short(_text(meta.get("next_hop_id"))) or target.rsplit("/", 1)[-1]
    return f"{name} {shown}".strip()


def protocols_text(entries: Any) -> str:
    """``[{"protocol": "tcp", "ports": ["22", "443"]}, {"protocol": "icmp"}]`` -> ``tcp:22,443; icmp``."""
    shown = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        protocol = _text(entry.get("protocol")) or "all"
        ports = [_text(p) for p in entry.get("ports") or [] if _text(p)]
        shown.append(f"{protocol}:{','.join(ports)}" if ports else protocol)
    return "; ".join(shown) or "all"


def firewall_row(rule: dict) -> list[Any]:
    """One VPC firewall rule as a row of ``FIREWALL_COLUMNS``."""
    meta = rule["meta"]
    allowed, denied = meta.get("allowed") or [], meta.get("denied") or []
    ingress = _text(meta.get("direction")).upper() != "EGRESS"
    source = [*(meta.get("source_ranges") or [])]
    source += [f"tag {t}" for t in meta.get("source_tags") or []]
    source += [f"service account {s}" for s in meta.get("source_service_accounts") or []]
    targets = [f"tag {t}" for t in meta.get("target_tags") or []]
    targets += [f"service account {s}" for s in meta.get("target_service_accounts") or []]
    return [
        rule.get("name") or _short(rule["rid"]),
        meta.get("priority"),
        "INGRESS" if ingress else "EGRESS",
        "deny" if denied else "allow",
        protocols_text(denied or allowed),
        source or ("0.0.0.0/0" if ingress else ""),
        meta.get("destination_ranges") or ("" if ingress else "0.0.0.0/0"),
        targets or "every instance",
        "disabled" if meta.get("disabled") else "enabled",
    ]


class _Builder:
    def __init__(
        self, accounts: list[dict], resources: list[dict], connections: list[dict], inventory: InventoryIndex
    ) -> None:
        self.accounts = accounts
        self.inventory = inventory
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.sites: list[dict] = []
        self.errors: list[dict] = []
        self.subnet_count = 0
        self._edge_keys: set[tuple] = set()
        # Resource uid -> node id, for the resources that are nodes.
        self._node_of: dict[str, str] = {}
        self._account_names = {a.get("id"): _text(a.get("name")) for a in accounts}

        # A resource shared between accounts is discovered by each of them.
        self.resources: dict[str, dict] = {}
        for row in resources:
            uid = _text(row.get("resource_uid"))
            if not uid:
                continue
            item = {**row, "meta": _meta(row), "rid": _rid(uid)}
            known = self.resources.get(uid)
            if known is None or (not _text(known.get("name")) and _text(item.get("name"))):
                self.resources[uid] = item
        self.connections: list[dict] = []
        seen: set[tuple] = set()
        for row in connections:
            key = (
                _text(row.get("source_resource_uid")),
                _text(row.get("target_resource_uid")),
                _text(row.get("connection_type")),
            )
            if all(key) and key not in seen:
                seen.add(key)
                self.connections.append({"src": key[0], "dst": key[1], "type": key[2], **row, "meta": _meta(row)})

        self.vpcs = self._of_type("vpc")
        self._vpc_rids = {v["rid"] for v in self.vpcs}

    # ── Lookups ────────────────────────────────────────────────────────────

    def _of_type(self, resource_type: str) -> list[dict]:
        found = [r for r in self.resources.values() if r.get("resource_type") == resource_type]
        return sorted(found, key=lambda r: (_text(r.get("name")).lower(), r["rid"]))

    def _network_of(self, resource: dict) -> str:
        """The rid of the network a resource belongs to (``""`` for none)."""
        meta = resource["meta"]
        return _text(meta.get("network_id")) or _text(meta.get("vpc_id"))

    def _account(self, resource: dict) -> str:
        return _text(resource.get("account_name")) or self._account_names.get(resource.get("account_id"), "")

    def _name(self, uid: str) -> str:
        resource = self.resources.get(uid) or {}
        return _text(resource.get("name")) or _short(_rid(uid))

    # ── Graph primitives ───────────────────────────────────────────────────

    def _node(self, uid: str, node_id: str, kind: str, label: str, site: str, status: str, **fields: Any) -> dict:
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
        if uid:
            self._node_of[uid] = node_id
        return node

    def _edge(self, a: str, b: str, kind: str, *, status: str = "", label: str = "", detail: str = "") -> None:
        if a == b or a not in self.nodes or b not in self.nodes:
            return
        # Two tunnels between the same gateways are two edges.
        key = (*sorted((a, b)), kind, detail if kind == "vpn" else "")
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(
            {
                "id": f"e{len(self.edges) + 1}",
                "a": a,
                "b": b,
                "kind": kind,
                "a_port": "",
                "b_port": "",
                "status": status,
                "label": label,
                "detail": detail,
            }
        )

    # ── VPC networks ───────────────────────────────────────────────────────

    def build_vpcs(self) -> None:
        many = len({_project(v["rid"]) for v in self.vpcs}) > 1 or len({self._account(v) for v in self.vpcs}) > 1
        by_network: dict[str, dict[str, list[dict]]] = {}
        for resource_type in (
            "subnet",
            "instance",
            "route_entry",
            "firewall_policy",
            "cloud_router",
            "internet_gateway",
            "ha_vpn_gateway",
            "target_vpn_gateway",
        ):
            for resource in self._of_type(resource_type):
                by_network.setdefault(self._network_of(resource), {}).setdefault(resource_type, []).append(resource)
        peerings: dict[str, list[dict]] = {}
        for conn in self.connections:
            if conn["type"] == "vpc_peering":
                peerings.setdefault(_rid(conn["src"]), []).append(conn)
        policies: dict[str, list[str]] = {}
        for policy in self._of_type("network_firewall_policy"):
            for network_id in policy["meta"].get("network_ids") or []:
                policies.setdefault(_text(network_id), []).append(_text(policy.get("name")) or _short(policy["rid"]))

        for vpc in self.vpcs:
            uid = _text(vpc["resource_uid"])
            rid = site_id = vpc["rid"]
            name = _text(vpc.get("name")) or _short(rid)
            project = _text(vpc["meta"].get("project")) or _project(rid)
            account = self._account(vpc)
            meta = vpc["meta"]
            owned = by_network.get(rid, {})
            subnets = owned.get("subnet", [])
            instances = owned.get("instance", [])
            routers = owned.get("cloud_router", [])
            routing = _text(meta.get("routing_mode")).upper() or "REGIONAL"
            mode = _text(meta.get("subnet_mode")) or "custom"
            regions = sorted({_text(s.get("region")) for s in subnets if _text(s.get("region"))})
            firewall_policy = [p for p in [_text(meta.get("firewall_policy")).rsplit("/", 1)[-1]] if p]
            firewall_policy += [p for p in policies.get(rid, []) if p not in firewall_policy]
            node = self._node(
                uid,
                f"vpc:{rid}",
                "vpc",
                name,
                site_id,
                _status(vpc.get("status")),
                model=f"GCP VPC network ({mode} subnets, {routing.lower()} routing)",
                site_sections=True,
            )
            _add(
                node["sections"],
                kv_section(
                    "Overview",
                    [
                        ("VPC network", name),
                        ("Project", project),
                        ("Account", account),
                        ("Routing mode", routing),
                        ("Subnet mode", mode),
                        ("Regions", regions),
                        ("State", vpc.get("status")),
                        ("Source", "The network's own router: every subnet of the network is reached through it"),
                    ],
                ),
            )
            _add(
                node["sections"],
                table_section(
                    "VPC peerings",
                    ["Peering", "Peered network", "Project", "State", "Exports custom routes", "Imports custom routes"],
                    [
                        [
                            conn["meta"].get("peering_name"),
                            _short(_rid(conn["dst"])),
                            _project(_rid(conn["dst"])),
                            conn.get("state"),
                            bool(conn["meta"].get("export_custom_routes")),
                            bool(conn["meta"].get("import_custom_routes")),
                        ]
                        for conn in peerings.get(rid, [])
                    ],
                ),
            )

            subnet_names = {s["rid"]: _text(s.get("name")) or _short(s["rid"]) for s in subnets}
            sections: list[dict] = []
            _add(
                sections,
                kv_section(
                    "VPC network overview",
                    [
                        ("VPC network", name),
                        ("Project", project),
                        ("Account", account),
                        ("Routing mode", routing),
                        ("Subnet mode", mode),
                        ("MTU", meta.get("mtu")),
                        ("Regions", regions),
                        ("Network firewall policies", firewall_policy),
                        ("Subnets", len(subnets) or ""),
                        ("VM instances", len(instances) or ""),
                        ("Cloud Routers", len(routers) or ""),
                    ],
                ),
            )
            routes = sorted(
                owned.get("route_entry", []),
                key=lambda r: (_text(r.get("cidr")), r["meta"].get("priority") or 0, _text(r.get("name"))),
            )
            _add(
                sections,
                table_section(
                    SUBNET_SECTION_TITLE, SUBNET_COLUMNS, self._subnet_rows(subnets, routes, routers, instances)
                ),
            )
            self.subnet_count += len(subnets)
            route_rows: list[list[Any]] = [
                [
                    s.get("name"),
                    cidr,
                    0,
                    f"VPC network {name}",
                    "",
                    "Subnet",
                ]
                for s in subnets
                for cidr in [
                    _text(s.get("cidr")),
                    *[_text(r.get("cidr")) for r in s["meta"].get("secondary_ranges") or []],
                ]
                if cidr
            ]
            route_rows += [
                [
                    r.get("name"),
                    r.get("cidr"),
                    r["meta"].get("priority"),
                    next_hop_name(r["meta"]),
                    r["meta"].get("tags"),
                    _text(r["meta"].get("route_type")).capitalize() or "Static",
                ]
                for r in routes
            ]
            _add(sections, table_section("VPC routes", ROUTE_COLUMNS, route_rows[:MAX_SITE_ROWS]))
            _add(
                sections,
                table_section(
                    "Dynamic routes",
                    ["Prefix", "Cloud Router", "Region", "Next hop", "Learned over", "Priority"],
                    [
                        [
                            route.get("prefix"),
                            router.get("name"),
                            router.get("region"),
                            route.get("next_hop_ip"),
                            self._over(route),
                            route.get("priority"),
                        ]
                        for router in routers
                        for route in router["meta"].get("learned_routes") or []
                        if isinstance(route, dict)
                    ][:MAX_SITE_ROWS],
                ),
            )
            _add(
                sections,
                table_section(
                    "VM instances",
                    [
                        "Name",
                        "Zone",
                        "Internal IP",
                        "External IP",
                        "Subnet",
                        "Forwards traffic",
                        "Network tags",
                        "Status",
                    ],
                    [
                        [
                            i.get("name"),
                            i["meta"].get("zone"),
                            i["meta"].get("private_ip"),
                            i["meta"].get("public_ip"),
                            subnet_names.get(_text(i["meta"].get("subnet_id")))
                            or _short(_text(i["meta"].get("subnet_id"))),
                            bool(i["meta"].get("can_ip_forward")),
                            i["meta"].get("network_tags"),
                            i.get("status"),
                        ]
                        for i in instances[:MAX_SITE_ROWS]
                    ],
                ),
            )
            rules = sorted(
                owned.get("firewall_policy", []),
                key=lambda r: (
                    _text(r["meta"].get("direction")),
                    r["meta"].get("priority") if isinstance(r["meta"].get("priority"), int) else 1000,
                    _text(r.get("name")),
                ),
            )
            _add(
                sections,
                table_section(
                    "VPC firewall rules",
                    FIREWALL_COLUMNS,
                    [firewall_row(r) for r in rules][: MAX_SITE_ROWS - 2] + [list(row) for row in IMPLIED_RULES],
                ),
            )

            members = [node, *self._instance_nodes(instances, node, site_id, subnet_names)]
            members += self._vpc_gateways(owned, node, site_id, subnet_names)
            self.sites.append(
                {
                    "id": site_id,
                    "name": f"{project} / {name}" if many else name,
                    "tags": [t for t in (project, f"{routing.lower()} routing", account) if t],
                    "vpn_mode": "spoke",
                    "status": _worst([m["status"] for m in members if m["kind"] != "wan"]),
                    "device_count": sum(1 for m in members if m["kind"] in ("vpc", "appliance", "server")),
                    "sections": sections,
                }
            )

    def _over(self, route: dict) -> str:
        if _text(route.get("vpn_tunnel")):
            return f"VPN tunnel {_short(_text(route['vpn_tunnel']))}"
        if _text(route.get("interconnect_attachment")):
            return f"Interconnect attachment {_short(_text(route['interconnect_attachment']))}"
        return f"BGP peer {_text(route.get('peer'))}".strip() if route.get("peer") else ""

    @staticmethod
    def _nat_serves(nat: dict, subnet: dict, router: dict) -> bool:
        """Whether a Cloud NAT of ``router`` serves the primary range of ``subnet``."""
        if _text(router.get("region")) != _text(subnet.get("region")):
            return False
        scope = _text(nat.get("scope"))
        if scope in ("all", "primary"):
            return True
        return any(_text(s.get("subnet_id")) == subnet["rid"] for s in nat.get("subnets") or [] if isinstance(s, dict))

    def _subnet_rows(
        self, subnets: list[dict], routes: list[dict], routers: list[dict], instances: list[dict]
    ) -> list[list[Any]]:
        defaults = [r for r in routes if _text(r.get("cidr")) == "0.0.0.0/0"]
        untagged = [r for r in defaults if not r["meta"].get("tags")]
        untagged.sort(key=lambda r: r["meta"].get("priority") if isinstance(r["meta"].get("priority"), int) else 1000)
        default = next_hop_name(untagged[0]["meta"]) if untagged else ("Tagged instances only" if defaults else "None")
        in_use: dict[str, int] = {}
        for instance in instances:
            for interface in instance["meta"].get("interfaces") or []:
                if isinstance(interface, dict) and _text(interface.get("subnet_id")):
                    in_use[_text(interface["subnet_id"])] = in_use.get(_text(interface["subnet_id"]), 0) + 1
        rows = []
        for subnet in subnets:
            meta = subnet["meta"]
            nats = [
                _text(nat.get("name"))
                for router in routers
                for nat in router["meta"].get("nats") or []
                if isinstance(nat, dict) and self._nat_serves(nat, subnet, router)
            ]
            rows.append(
                [
                    subnet.get("cidr"),
                    subnet.get("name") or _short(subnet["rid"]),
                    subnet.get("region"),
                    [
                        f"{_text(r.get('name'))} {_text(r.get('cidr'))}".strip()
                        for r in meta.get("secondary_ranges") or []
                    ],
                    default,
                    nats,
                    bool(meta.get("private_google_access")),
                    in_use.get(subnet["rid"], ""),
                ]
            )
        return rows

    def _instance_nodes(
        self, instances: list[dict], vpc_node: dict, site_id: str, subnet_names: dict[str, str]
    ) -> list[dict]:
        members: list[dict] = []
        for instance in instances:
            meta = instance["meta"]
            interfaces = [i for i in meta.get("interfaces") or [] if isinstance(i, dict)]
            primary = _text(meta.get("private_ip"))
            addresses = [primary, _text(meta.get("public_ip"))]
            for interface in interfaces:
                addresses += [_text(ip) for ip in (interface.get("private_ips") or [])]
                addresses += [_text(ip) for ip in (interface.get("public_ips") or [])]
            addresses = list(dict.fromkeys(a for a in addresses if a))
            forwards = bool(meta.get("can_ip_forward"))
            host = self.inventory.match(ips=addresses)
            if not forwards and not host:
                continue
            state = _text(instance.get("status")).lower()
            node = self._node(
                _text(instance["resource_uid"]),
                f"i:{instance['rid']}",
                "appliance" if forwards else "server",
                _text(instance.get("name")) or _short(instance["rid"]),
                site_id,
                "offline" if state in ("terminated", "stopped", "stopping", "suspended") else _status(state),
                model=f"GCP VM instance {_text(meta.get('machine_type'))}".strip(),
                ip=primary,
                # Other addresses of the instance; an external one identifies
                # it to the rest of the map (an SD-WAN appliance's WAN address).
                alias_ips=[a for a in addresses if a != primary],
            )
            if host:
                node["inventory"] = _inventory_ref(host)
            subnet = subnet_names.get(_text(meta.get("subnet_id"))) or _short(_text(meta.get("subnet_id")))
            _add(
                node["sections"],
                kv_section(
                    "Overview",
                    [
                        ("Name", instance.get("name")),
                        ("Status", instance.get("status")),
                        ("Machine type", meta.get("machine_type")),
                        ("Zone", meta.get("zone")),
                        ("VPC network", vpc_node["label"]),
                        ("Subnet", subnet),
                        ("Internal IP", primary),
                        ("External IP", meta.get("public_ip")),
                        ("Forwards traffic (IP forwarding on)", forwards),
                        ("Network tags", meta.get("network_tags")),
                        ("Service accounts", meta.get("service_accounts")),
                        ("Project", meta.get("project")),
                        ("Account", self._account(instance)),
                    ],
                ),
            )
            _add(
                node["sections"],
                table_section(
                    "Network interfaces",
                    ["Interface", "VPC network", "Subnet", "Internal IP", "Alias IP ranges", "External IPs"],
                    [
                        [
                            i.get("name"),
                            _short(_text(i.get("network_id"))),
                            subnet_names.get(_text(i.get("subnet_id"))) or _short(_text(i.get("subnet_id"))),
                            i.get("private_ips"),
                            i.get("alias_ranges"),
                            i.get("public_ips"),
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
            self._edge(
                node["id"],
                vpc_node["id"],
                "attach",
                status="failed" if node["status"] == "offline" else "active",
                label="VM instance in VPC network",
            )
            members.append(node)
        return members

    def _vpc_gateways(
        self, owned: dict[str, list[dict]], vpc_node: dict, site_id: str, subnet_names: dict[str, str]
    ) -> list[dict]:
        """The internet gateway, Cloud Routers, Cloud NATs and VPN gateways of one network."""
        members: list[dict] = []
        for gateway in owned.get("internet_gateway", []):
            node = self._node(
                _text(gateway["resource_uid"]),
                f"igw:{gateway['rid']}",
                "wan",
                "Internet gateway",
                site_id,
                "online",
                model="Default internet gateway",
                parent=vpc_node["id"],
            )
            _add(
                node["sections"],
                kv_section(
                    "Internet gateway",
                    [
                        ("Name", gateway.get("name")),
                        ("VPC network", vpc_node["label"]),
                        ("Source", "The next hop of the network's routes to default-internet-gateway"),
                    ],
                ),
            )
            self._edge(node["id"], vpc_node["id"], "uplink", status="active", label="Internet gateway")
            members.append(node)
        for router in owned.get("cloud_router", []):
            members += self._router_nodes(router, vpc_node, site_id, subnet_names)
        for kind in ("ha_vpn_gateway", "target_vpn_gateway"):
            for gateway in owned.get(kind, []):
                members.append(self._vpn_gateway_node(gateway, site_id, vpc_node))
        return members

    def _router_nodes(self, router: dict, vpc_node: dict, site_id: str, subnet_names: dict[str, str]) -> list[dict]:
        meta = router["meta"]
        name = _text(router.get("name")) or _short(router["rid"])
        asn = meta.get("bgp_asn")
        node = self._node(
            _text(router["resource_uid"]),
            f"router:{router['rid']}",
            "cloud",
            f"CR {name}",
            site_id,
            _status(router.get("status")),
            model=f"Cloud Router ASN {asn}" if asn else "Cloud Router",
        )
        _add(
            node["sections"],
            kv_section(
                "Cloud Router",
                [
                    ("Name", name),
                    ("Region", router.get("region")),
                    ("VPC network", vpc_node["label"]),
                    ("BGP ASN", asn),
                    ("Advertises", meta.get("advertise_mode")),
                    ("Advertised groups", meta.get("advertised_groups")),
                    ("Advertised ranges", meta.get("advertised_ip_ranges")),
                    ("Session state collected", bool(meta.get("status_collected"))),
                    ("Account", self._account(router)),
                ],
            ),
        )
        interfaces = [i for i in meta.get("interfaces") or [] if isinstance(i, dict)]
        linked = {
            _text(i.get("name")): (
                f"VPN tunnel {_short(_text(i['vpn_tunnel']))}"
                if _text(i.get("vpn_tunnel"))
                else f"Interconnect attachment {_short(_text(i['interconnect_attachment']))}"
                if _text(i.get("interconnect_attachment"))
                else ""
            )
            for i in interfaces
        }
        _add(
            node["sections"],
            table_section(
                "Router interfaces",
                ["Interface", "IP range", "Linked to"],
                [[i.get("name"), i.get("ip_range"), linked.get(_text(i.get("name")), "")] for i in interfaces],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "BGP sessions",
                ["Peer", "Interface", "Peer IP", "Peer ASN", "Status", "State", "Uptime", "Learned routes", "Over"],
                [
                    [
                        p.get("name"),
                        p.get("interface"),
                        p.get("peer_ip"),
                        p.get("peer_asn"),
                        p.get("status") or ("disabled" if p.get("enabled") is False else ""),
                        p.get("state"),
                        p.get("uptime"),
                        p.get("learned_routes"),
                        linked.get(_text(p.get("interface")), ""),
                    ]
                    for p in meta.get("bgp_peers") or []
                    if isinstance(p, dict)
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Learned routes",
                ["Prefix", "Next hop", "Priority", "BGP peer", "Learned over"],
                [
                    [r.get("prefix"), r.get("next_hop_ip"), r.get("priority"), r.get("peer"), self._over(r)]
                    for r in meta.get("learned_routes") or []
                    if isinstance(r, dict)
                ][:MAX_SITE_ROWS],
            ),
        )
        self._edge(
            node["id"], vpc_node["id"], "attach", status=_link_status(router.get("status")), label="Cloud Router"
        )
        members = [node]
        for nat in meta.get("nats") or []:
            if not isinstance(nat, dict) or not _text(nat.get("name")):
                continue
            serves = {
                "all": "Every range of every subnet in the region",
                "primary": "Primary ranges of every subnet in the region",
            }
            subnets = [
                f"{subnet_names.get(_text(s.get('subnet_id'))) or _short(_text(s.get('subnet_id')))} ({', '.join(s.get('ranges') or [])})"
                for s in nat.get("subnets") or []
                if isinstance(s, dict)
            ]
            ips = [_text(ip) for ip in nat.get("nat_ips") or [] if _text(ip)]
            nat_node = self._node(
                "",
                f"nat:{router['rid']}:{nat['name']}",
                "cloud",
                f"NAT {nat['name']}",
                site_id,
                node["status"],
                model="Cloud NAT",
                ip=ips[0] if ips else "",
            )
            _add(
                nat_node["sections"],
                kv_section(
                    "Cloud NAT",
                    [
                        ("Name", nat.get("name")),
                        ("Cloud Router", name),
                        ("Region", router.get("region")),
                        ("Serves", serves.get(_text(nat.get("scope"))) or subnets),
                        ("NAT IPs", ips or nat.get("nat_ip_names")),
                        ("NAT IP allocation", nat.get("allocation")),
                        ("VPC network", vpc_node["label"]),
                    ],
                ),
            )
            self._edge(nat_node["id"], node["id"], "attach", status="active", label="Cloud NAT")
            members.append(nat_node)
        return members

    def _vpn_gateway_node(self, gateway: dict, site_id: str, vpc_node: dict | None) -> dict:
        meta = gateway["meta"]
        ha = gateway.get("resource_type") == "ha_vpn_gateway"
        public = [_text(ip) for ip in meta.get("public_ips") or []]
        name = _text(gateway.get("name")) or _short(gateway["rid"])
        node = self._node(
            _text(gateway["resource_uid"]),
            f"{'vpngw' if ha else 'tvpngw'}:{gateway['rid']}",
            "cloud",
            f"VPN {name}",
            site_id,
            _status(gateway.get("status")),
            model="HA VPN gateway" if ha else "Classic VPN gateway",
            ip=public[0] if public else "",
            # The GCP ends of the tunnels: how another integration's view of
            # the same VPN (a Meraki or Cato IPsec peer) is recognised.
            endpoint_ips=list(public),
        )
        _add(
            node["sections"],
            kv_section(
                "HA VPN gateway" if ha else "Classic VPN gateway",
                [
                    ("Name", name),
                    ("Region", gateway.get("region")),
                    (
                        "Interfaces",
                        [
                            f"{i.get('id')}: {i.get('ip_address')}"
                            for i in meta.get("interfaces") or []
                            if isinstance(i, dict)
                        ],
                    ),
                    ("Public IPs", public),
                    ("VPC network", vpc_node["label"] if vpc_node else _short(_text(meta.get("network_id")))),
                    ("Account", self._account(gateway)),
                ],
            ),
        )
        if vpc_node:
            self._edge(
                node["id"],
                vpc_node["id"],
                "attach",
                status=_link_status(gateway.get("status")),
                label="HA VPN gateway" if ha else "Classic VPN gateway",
            )
        return node

    # ── Transit: Interconnect and the far ends of VPNs ─────────────────────

    def build_transit(self) -> None:
        for kind in ("ha_vpn_gateway", "target_vpn_gateway"):
            for gateway in self._of_type(kind):
                if _text(gateway["resource_uid"]) not in self._node_of:
                    self._vpn_gateway_node(gateway, TRANSIT_SITE_ID, None)
        for attachment in self._of_type("interconnect_attachment"):
            meta = attachment["meta"]
            bandwidth = _text(meta.get("bandwidth")).replace("BPS_", "")
            node = self._node(
                _text(attachment["resource_uid"]),
                f"ia:{attachment['rid']}",
                "cloud",
                f"IA {_text(attachment.get('name')) or _short(attachment['rid'])}",
                TRANSIT_SITE_ID,
                _status(attachment.get("status")),
                model=f"Interconnect attachment {bandwidth}".strip(),
            )
            _add(
                node["sections"],
                kv_section(
                    "Interconnect attachment",
                    [
                        ("Name", attachment.get("name")),
                        ("Type", meta.get("type")),
                        ("Bandwidth", bandwidth),
                        ("State", meta.get("state")),
                        ("Operational status", meta.get("operational_status")),
                        ("Interconnect", meta.get("interconnect_name")),
                        ("Partner", meta.get("partner")),
                        ("VLAN", meta.get("vlan")),
                        ("Cloud Router", _short(_text(meta.get("router_id")))),
                        ("Cloud Router address", meta.get("cloud_router_ip")),
                        ("On-premises router address", meta.get("customer_router_ip")),
                        ("Edge availability domain", meta.get("edge_availability_domain")),
                        ("Region", attachment.get("region")),
                        ("Account", self._account(attachment)),
                    ],
                ),
            )
        for interconnect in self._of_type("interconnect"):
            meta = interconnect["meta"]
            node = self._node(
                _text(interconnect["resource_uid"]),
                f"ic:{interconnect['rid']}",
                "cloud",
                f"IC {_text(interconnect.get('name')) or _short(interconnect['rid'])}",
                TRANSIT_SITE_ID,
                _status(interconnect.get("status")),
                model=f"{_text(meta.get('type')).capitalize() or 'Dedicated'} Interconnect",
            )
            _add(
                node["sections"],
                kv_section(
                    "Interconnect",
                    [
                        ("Name", interconnect.get("name")),
                        ("Type", meta.get("type")),
                        ("Link type", meta.get("link_type")),
                        (
                            "Links (provisioned / requested)",
                            f"{meta.get('provisioned_link_count')} / {meta.get('requested_link_count')}",
                        ),
                        ("Location", meta.get("location")),
                        ("State", meta.get("state")),
                        ("Account", self._account(interconnect)),
                        (
                            "Source",
                            "The edge of the map: the on-premises router behind the Interconnect is not collected",
                        ),
                    ],
                ),
            )
        for gateway in self._of_type("external_vpn_gateway"):
            meta = gateway["meta"]
            name = _text(gateway.get("name")) or _short(gateway["rid"])
            interfaces = [i for i in meta.get("interfaces") or [] if isinstance(i, dict) and _text(i.get("ip_address"))]
            # One node per interface: each address can be a device of its own
            # (a pair of on-premises routers), which the merge recognises by it.
            ends = [
                (f"evpn:{gateway['rid']}/{i.get('id')}", f"{name} (interface {i.get('id')})", i) for i in interfaces
            ]
            if len(interfaces) <= 1:
                ends = [(f"evpn:{gateway['rid']}", name, interfaces[0] if interfaces else {})]
            for node_id, label, interface in ends:
                node = self._node(
                    "",
                    node_id,
                    "vpn_peer",
                    label,
                    TRANSIT_SITE_ID,
                    "unknown",
                    model="External VPN gateway",
                    ip=_text(interface.get("ip_address")),
                )
                _add(
                    node["sections"],
                    kv_section(
                        "External VPN gateway",
                        [
                            ("Name", name),
                            ("Interface", interface.get("id")),
                            ("Public IP", interface.get("ip_address")),
                            ("Redundancy", meta.get("redundancy_type")),
                            ("Every interface", [i.get("ip_address") for i in interfaces]),
                            ("Source", "The far end of a GCP HA VPN, as configured in GCP"),
                        ],
                    ),
                )
            self._node_of[_text(gateway["resource_uid"])] = ends[0][0]

    def _far_node(self, conn: dict) -> str:
        """The node at the far end of a VPN tunnel connection."""
        target, meta = conn["dst"], conn["meta"]
        tunnel = (self.resources.get(conn["src"]) or {}).get("meta") or {}
        if target.startswith("gcp:external_vpn_gateway:"):
            rid = _rid(target)
            interface = tunnel.get("peer_external_gateway_interface")
            if f"evpn:{rid}/{interface}" in self.nodes:
                return f"evpn:{rid}/{interface}"
        found = self._node_of.get(target)
        if found:
            return found
        address = _text(meta.get("peer_ip"))
        # Discovered without the far end's gateway: keep it as a peer by address.
        return self._node(
            target,
            f"vpn:{_rid(target)}",
            "vpn_peer",
            address or _short(_rid(target)),
            TRANSIT_SITE_ID,
            "unknown",
            model="VPN peer",
            ip=address,
        )["id"]

    def _stub(self, uid: str) -> str | None:
        """A node for a peering whose far end was not discovered: a network
        of a project Plexus does not collect."""
        parts = uid.split(":", 2)
        if len(parts) != 3 or parts[1] != "vpc":
            return None
        rid = parts[2]
        site_id = f"x:{rid}"
        node = self._node(uid, f"x:vpc:{rid}", "vpc", f"VPC {_short(rid)}", site_id, "unknown", model="Not collected")
        self.sites.append(
            {
                "id": site_id,
                "name": f"{_short(rid)} (not collected)",
                "tags": [],
                "vpn_mode": "spoke",
                "status": "unknown",
                "device_count": 0,
                "sections": [],
                "not_collected": True,
            }
        )
        _add(
            node["sections"],
            kv_section(
                "Not collected",
                [
                    ("VPC network", _short(rid)),
                    ("Project", _project(rid)),
                    ("Source", "Referenced by a VPC peering; it belongs to a project Plexus does not collect"),
                ],
            ),
        )
        return node["id"]

    def build_links(self) -> None:
        attachments: dict[str, list[list[Any]]] = {}
        for conn in self.connections:
            if conn["type"] in _NOT_A_LINK:
                continue
            a = self._node_of.get(conn["src"]) or self._stub(conn["src"])
            b = self._node_of.get(conn["dst"]) or self._stub(conn["dst"])
            if not a or not b:
                continue
            label = _LINK_LABELS.get(conn["type"], conn["type"].replace("_", " ").capitalize())
            state = conn.get("state")
            name = _text(conn["meta"].get("peering_name"))
            self._edge(a, b, "attach", status=_link_status(state), label=label, detail=name)
            for own, other in ((a, b), (b, a)):
                attachments.setdefault(own, []).append([label, self.nodes[other]["label"], state, name])
        for node_id, rows in attachments.items():
            if self.nodes[node_id]["kind"] == "cloud":
                _add(
                    self.nodes[node_id]["sections"],
                    table_section("Attachments", ["Type", "Attached to", "State", "Name"], sorted(rows, key=str)),
                )

    def build_vpns(self) -> None:
        """VPN tunnels: a tunnel from the VPN gateway to the external VPN
        gateway (or the peer GCP gateway), with the tunnel's detail on both ends."""
        rows_by_node: dict[str, list[list[Any]]] = {}
        for conn in self.connections:
            if conn["type"] != "vpn_tunnel":
                continue
            meta = conn["meta"]
            gateway = self._node_of.get(_text(meta.get("gateway")))
            if not gateway:
                continue
            peer = self._far_node(conn)
            name = _text(meta.get("name")) or _short(_rid(conn["src"]))
            state = _text(meta.get("status") or conn.get("state")).upper()
            self._edge(
                gateway,
                peer,
                "vpn",
                status="reachable" if state == "ESTABLISHED" else "unreachable",
                label="HA VPN tunnel" if self.nodes[gateway]["id"].startswith("vpngw:") else "Classic VPN tunnel",
                detail=name,
            )
            router = _text(meta.get("router_id"))
            session = ""
            router_meta = (self.resources.get(f"gcp:cloud_router:{router}") or {}).get("meta") or {}
            for interface in router_meta.get("interfaces") or []:
                if isinstance(interface, dict) and _text(interface.get("vpn_tunnel")) == _rid(conn["src"]):
                    peer_row = next(
                        (
                            p
                            for p in router_meta.get("bgp_peers") or []
                            if isinstance(p, dict) and p.get("interface") == interface.get("name")
                        ),
                        None,
                    )
                    if peer_row:
                        session = f"{peer_row.get('name')} {peer_row.get('status') or ''}".strip()
            row = [
                name,
                meta.get("status"),
                meta.get("detailed_status"),
                meta.get("peer_ip"),
                f"IKEv{meta.get('ike_version')}" if meta.get("ike_version") else "",
                _short(router),
                session or ("Static routes" if not router else ""),
            ]
            rows_by_node.setdefault(gateway, []).append([self.nodes[peer]["label"], *row])
            rows_by_node.setdefault(peer, []).append([self.nodes[gateway]["label"], *row])
        for node_id, rows in rows_by_node.items():
            _add(
                self.nodes[node_id]["sections"],
                table_section(
                    "VPN tunnels",
                    ["Far end", "Tunnel", "Status", "Detail", "Peer IP", "IKE", "Cloud Router", "BGP session"],
                    rows,
                ),
            )

    def build_report(self) -> None:
        for account in self.accounts:
            if _text(account.get("last_sync_status")) == "error":
                self.errors.append(
                    {
                        "scope": f"GCP account {_text(account.get('name'))}",
                        "path": "discovery",
                        "status": None,
                        "message": "The last discovery failed; the map shows the discovery before it. "
                        + _text(account.get("last_sync_message")),
                    }
                )
        for warning in self._of_type(WARNING_TYPE):
            meta = warning["meta"]
            self.errors.append(
                {
                    "scope": f"GCP account {self._account(warning)}",
                    "path": _text(meta.get("section")) or _text(warning.get("name")),
                    "status": None,
                    "message": f"Not collected: GCP answered {_text(meta.get('error')) or 'with an error'}. "
                    "The role of the account may not allow this call, or the API is not enabled for the project.",
                }
            )

    def build_edge_sections(self) -> None:
        for edge in self.edges:
            a, b = self.nodes[edge["a"]], self.nodes[edge["b"]]
            section = kv_section(
                edge.pop("label") or "Link",
                [
                    ("A end", a["label"]),
                    ("B end", b["label"]),
                    ("Connection", edge.pop("detail")),
                    ("Status", edge.get("status")),
                    ("Discovered via", "GCP API"),
                ],
            )
            edge["sections"] = [section] if section else []


def build_snapshot(
    accounts: list[dict],
    resources: list[dict],
    connections: list[dict],
    inventory: InventoryIndex | None = None,
) -> dict[str, Any]:
    """Build the positioned topology snapshot of every GCP account given.

    ``resources`` and ``connections`` are Cloud Visibility rows (or the
    records a collector returns) of those accounts.
    """
    builder = _Builder(accounts, resources, connections, inventory or InventoryIndex())
    builder.build_vpcs()
    builder.build_transit()
    builder.build_links()
    builder.build_vpns()
    builder.build_report()

    transit_members = [n for n in builder.nodes.values() if n["site"] == TRANSIT_SITE_ID]
    sites = list(builder.sites)
    if transit_members:
        sites.append(
            {
                "id": TRANSIT_SITE_ID,
                "name": TRANSIT_SITE_NAME,
                "tags": [],
                # Sorts the transit box ahead of the networks, like a VPN hub.
                "vpn_mode": "hub",
                "status": _worst([m["status"] for m in transit_members if m["kind"] != "vpn_peer"]),
                "device_count": 0,
                "sections": [],
            }
        )
    # Inside a box, anything joined is laid out as a tree under its gateway.
    layout_edges = [{**e, "kind": "lan"} if e["kind"] in ("attach", "vpn") else e for e in builder.edges]
    _layout(sites, builder.nodes, layout_edges)
    builder.build_edge_sections()

    nodes = list(builder.nodes.values())
    for node in nodes:
        node.pop("parent", None)

    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in nodes:
        if node["kind"] in ("wan", "cloud", "vpn_peer") or node.get("model") == "Not collected":
            continue
        by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
        by_status[node["status"]] = by_status.get(node["status"], 0) + 1
    edge_counts: dict[str, int] = {}
    for edge in builder.edges:
        edge_counts[edge["kind"]] = edge_counts.get(edge["kind"], 0) + 1

    synced = sorted(_text(a.get("last_sync_at")) for a in accounts if _text(a.get("last_sync_at")))
    names = [_text(a.get("name")) for a in accounts if _text(a.get("name"))]
    return {
        "schema": SCHEMA_VERSION,
        "provider": PROVIDER,
        "generated_at": synced[-1] if synced else "",
        "org": {"id": "", "name": "GCP" + (f" ({', '.join(names)})" if names else ""), "url": ""},
        "summary": {
            "sites": sum(1 for s in builder.sites if not s.get("not_collected")),
            "devices": sum(by_kind.values()),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": 0,
            "inventory_matches": sum(1 for n in nodes if n.get("inventory")),
            "lan_links": 0,
            "vpn_tunnels": edge_counts.get("vpn", 0),
            "wan_uplinks": edge_counts.get("uplink", 0),
            "vlans": builder.subnet_count,
            "cloud_links": edge_counts.get("attach", 0),
        },
        "collection": {
            "sources": ["GCP API (Cloud Visibility discovery)"],
            "stats": {"accounts": len(accounts), "resources": len(builder.resources)},
            "errors": builder.errors,
            "options": {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }
