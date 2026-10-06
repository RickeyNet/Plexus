"""Turn the Azure discovery Cloud Visibility stores into a topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), the format the
AWS integration produces too, so the merge into the Topology graph, node
details, deep search, the subnet index and the HTML export need no
Azure-specific code.

Every enabled Azure account goes into one snapshot: resource uids carry the
subscription, so a peering between two subscriptions joins up without any
matching.

How Azure maps onto the map:

  - every virtual network is a site box. Its node stands for the VNet's
    router and owns the VNet's subnets; VPN and ExpressRoute gateways, NAT
    gateways and the Azure Firewall of the VNet sit beside it
  - a virtual machine is a node only when it forwards traffic (IP forwarding
    on: firewalls, routers, SD-WAN and VPN appliances) or is a Plexus
    inventory host. Every virtual machine is listed in its VNet's details
  - ExpressRoute circuits and local network gateways (the far end of a
    site-to-site VPN) share an "Azure VPN and ExpressRoute" box; a gateway
    connection is a tunnel from the VPN gateway to the local network gateway
"""

from __future__ import annotations

import json
from typing import Any

from netcontrol.integrations.azure.collect import WARNING_TYPE
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

PROVIDER = "azure"
TRANSIT_SITE_ID = "__azure_transit__"
TRANSIT_SITE_NAME = "Azure VPN and ExpressRoute"

SUBNET_SECTION_TITLE = "Subnets"
SUBNET_COLUMNS = [
    "Subnet",
    "Name",
    "Route table",
    "Default route",
    "Network security group",
    "NAT gateway",
    "Delegated to",
    "Addresses in use",
]

# Detail tables are capped so one large VNet cannot bloat the snapshot.
MAX_SITE_ROWS = 3000

_UP_STATES = (
    "",
    "succeeded",
    "connected",
    "provisioned",
    "enabled",
    "up",
    "available",
    "active",
    "attached",
    "fullyinsync",
)
_PENDING_PREFIXES = ("updating", "connecting", "initiated", "provisioning", "deploying", "creating", "notprovisioned")
_UNKNOWN_STATES = ("unknown",)

# Connections that describe a resource rather than join two nodes.
_NOT_A_LINK = ("route_table_association", "security_boundary", "route_next_hop")
# Gateway connections: the connection type Azure reports, lower case.
_VPN_LINKS = ("ipsec", "vnet2vnet")
_CIRCUIT_LINKS = ("expressroute",)
_LINK_LABELS = {
    "vnet_peering": "VNet peering",
    "virtual_network_gateway_attachment": "Virtual network gateway",
    "nat_gateway_attachment": "NAT gateway",
    "expressroute": "ExpressRoute connection",
}
_NEXT_HOP_NAMES = {
    "internet": "Internet",
    "virtualnetworkgateway": "Virtual network gateway",
    "virtualappliance": "Virtual appliance",
    "vnetlocal": "VNet local",
    "virtualnetwork": "VNet local",
    "vnetpeering": "VNet peering",
    "virtualnetworkpeering": "VNet peering",
    "virtualnetworkserviceendpoint": "Service endpoint",
    "none": "Dropped",
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
    """``azure:vnet:S:RG:hub`` -> ``S:RG:hub``."""
    parts = uid.split(":", 2)
    return parts[2] if len(parts) == 3 else uid


def _short(rid: str) -> str:
    """The name part of a resource id: ``S:RG:hub`` -> ``hub``, ``S:RG:hub/app`` -> ``app``."""
    return rid.rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def _group(rid: str) -> str:
    parts = rid.split(":")
    return parts[1] if len(parts) == 3 else ""


def _status(state: Any) -> str:
    state = _text(state).lower()
    if state in _UP_STATES:
        return "online"
    if state in _UNKNOWN_STATES or state.startswith(_PENDING_PREFIXES):
        return "unknown"
    return "offline"


def _link_status(state: Any) -> str:
    """Edge status of a connection: ``failed`` takes it out of path tracing."""
    return {"online": "active", "unknown": ""}.get(_status(state), "failed")


def next_hop_name(route: dict) -> str:
    kind = _text(route.get("next_hop_type")).lower()
    name = _NEXT_HOP_NAMES.get(kind, _text(route.get("next_hop_type")))
    ip = _text(route.get("next_hop_ip"))
    return f"{name} {ip}".strip() if ip else name


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

        self.vnets = self._of_type("vnet")
        self._vnet_uid_by_rid = {v["rid"]: _text(v["resource_uid"]) for v in self.vnets}
        # Resource uid -> VNet uid, from the attachments a discovery records.
        self._vnet_links: dict[str, str] = {}
        for conn in self.connections:
            for vnet_end, other in ((conn["src"], conn["dst"]), (conn["dst"], conn["src"])):
                if vnet_end in self.resources and self.resources[vnet_end]["resource_type"] == "vnet":
                    if (self.resources.get(other) or {}).get("resource_type") != "vnet":
                        self._vnet_links.setdefault(other, vnet_end)

    # ── Lookups ────────────────────────────────────────────────────────────

    def _of_type(self, resource_type: str) -> list[dict]:
        found = [r for r in self.resources.values() if r.get("resource_type") == resource_type]
        return sorted(found, key=lambda r: (_text(r.get("name")).lower(), r["rid"]))

    def _vnet_uid(self, resource: dict) -> str:
        """The VNet a resource belongs to (``""`` when it belongs to none)."""
        meta = resource["meta"]
        candidates = [_text(meta.get("vnet_id")), *[_text(v) for v in meta.get("vnet_ids") or []]]
        for rid in candidates:
            if rid in self._vnet_uid_by_rid:
                return self._vnet_uid_by_rid[rid]
        return self._vnet_links.get(_text(resource["resource_uid"]), "")

    def _account(self, resource: dict) -> str:
        return _text(resource.get("account_name")) or self._account_names.get(resource.get("account_id"), "")

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
        key = (*sorted((a, b)), kind)
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

    # ── Virtual networks ───────────────────────────────────────────────────

    def build_vnets(self) -> None:
        many_accounts = len({self._account(v) for v in self.vnets}) > 1
        by_vnet: dict[str, dict[str, list[dict]]] = {}
        for resource_type in ("subnet", "vm", "route_table", "network_security_group", "nat_gateway"):
            for resource in self._of_type(resource_type):
                owners = [self._vnet_uid(resource)]
                if resource_type in ("route_table", "network_security_group"):
                    # Applied per subnet: a table or group can serve several VNets.
                    owners = (
                        list(
                            dict.fromkeys(
                                self._vnet_uid_by_rid.get(_text(s).rsplit("/", 1)[0], "")
                                for s in resource["meta"].get("subnet_ids") or []
                            )
                        )
                        or owners
                    )
                for owner in owners:
                    by_vnet.setdefault(owner, {}).setdefault(resource_type, []).append(resource)
        peerings: dict[str, list[dict]] = {}
        for conn in self.connections:
            if conn["type"] == "vnet_peering":
                peerings.setdefault(conn["src"], []).append(conn)

        for vnet in self.vnets:
            uid = _text(vnet["resource_uid"])
            site_id = vnet["rid"]
            name = _text(vnet.get("name")) or _short(vnet["rid"])
            region = _text(vnet.get("region"))
            account = self._account(vnet)
            meta = vnet["meta"]
            owned = by_vnet.get(uid, {})
            prefixes = [_text(p) for p in meta.get("address_prefixes") or []] or [_text(vnet.get("cidr"))]
            node = self._node(
                uid,
                f"vnet:{vnet['rid']}",
                "vpc",
                name,
                site_id,
                _status(vnet.get("status")),
                model=f"Azure VNet {', '.join(p for p in prefixes if p)}".strip(),
                site_sections=True,
            )
            _add(
                node["sections"],
                kv_section(
                    "Overview",
                    [
                        ("Virtual network", name),
                        ("Address space", prefixes),
                        ("Region", region),
                        ("Resource group", meta.get("resource_group") or _group(vnet["rid"])),
                        ("Subscription", vnet["rid"].split(":")[0]),
                        ("Account", account),
                        ("State", vnet.get("status")),
                        ("Source", "The VNet's own router: every subnet of the VNet is reached through it"),
                    ],
                ),
            )
            _add(
                node["sections"],
                table_section(
                    "VNet peerings",
                    ["Peering", "Remote VNet", "State", "Forwarded traffic", "Gateway transit", "Uses remote gateways"],
                    [
                        [
                            conn["meta"].get("name"),
                            _text((self.resources.get(conn["dst"]) or {}).get("name")) or _short(_rid(conn["dst"])),
                            conn.get("state"),
                            bool(conn["meta"].get("allow_forwarded_traffic")),
                            bool(conn["meta"].get("allow_gateway_transit")),
                            bool(conn["meta"].get("use_remote_gateways")),
                        ]
                        for conn in peerings.get(uid, [])
                    ],
                ),
            )

            subnets = owned.get("subnet", [])
            vms = owned.get("vm", [])
            route_tables = owned.get("route_table", [])
            groups = owned.get("network_security_group", [])
            sections: list[dict] = []
            _add(
                sections,
                kv_section(
                    "VNet overview",
                    [
                        ("Virtual network", name),
                        ("Address space", prefixes),
                        ("Region", region),
                        ("Resource group", meta.get("resource_group") or _group(vnet["rid"])),
                        ("Subscription", vnet["rid"].split(":")[0]),
                        ("Account", account),
                        ("State", vnet.get("status")),
                        ("DNS servers", meta.get("dns_servers")),
                        ("Subnets", len(subnets) or ""),
                        ("Virtual machines", len(vms) or ""),
                    ],
                ),
            )
            subnet_names = {s["rid"]: _text(s.get("name")) for s in subnets}
            _add(
                sections,
                table_section(
                    SUBNET_SECTION_TITLE, SUBNET_COLUMNS, self._subnet_rows(subnets, route_tables, groups, owned)
                ),
            )
            self.subnet_count += len(subnets)
            _add(
                sections,
                table_section(
                    "Route tables",
                    ["Route table", "Route", "Destination", "Next hop", "Applied to"],
                    [
                        [
                            table.get("name") or _short(table["rid"]),
                            r.get("name"),
                            r.get("prefix"),
                            next_hop_name(r),
                            [
                                subnet_names.get(_text(s)) or _short(_text(s))
                                for s in table["meta"].get("subnet_ids") or []
                            ],
                        ]
                        for table in route_tables
                        for r in table["meta"].get("routes") or []
                        if isinstance(r, dict)
                    ][:MAX_SITE_ROWS],
                ),
            )
            _add(
                sections,
                table_section(
                    "Virtual machines",
                    ["Name", "Private IP", "Public IP", "Subnet", "Forwards traffic", "Network security group"],
                    [
                        [
                            vm.get("name"),
                            vm["meta"].get("private_ip"),
                            vm["meta"].get("public_ip"),
                            subnet_names.get(_text(vm["meta"].get("subnet_id")))
                            or _short(_text(vm["meta"].get("subnet_id"))),
                            bool(vm["meta"].get("ip_forwarding")),
                            [_short(_text(g)) for g in vm["meta"].get("network_security_group_ids") or []],
                        ]
                        for vm in vms[:MAX_SITE_ROWS]
                    ],
                ),
            )
            _add(
                sections,
                table_section(
                    "Network security group rules",
                    [
                        "Group",
                        "Priority",
                        "Direction",
                        "Action",
                        "Protocol",
                        "Ports",
                        "Source",
                        "Destination",
                        "Applied to",
                    ],
                    [
                        [
                            group.get("name") or _short(group["rid"]),
                            "default" if (rule.get("metadata") or {}).get("is_default") else rule.get("priority"),
                            rule.get("direction"),
                            rule.get("action"),
                            rule.get("protocol"),
                            rule.get("port_expression"),
                            rule.get("source_selector"),
                            rule.get("destination_selector"),
                            [
                                subnet_names.get(_text(s)) or _short(_text(s))
                                for s in group["meta"].get("subnet_ids") or []
                            ]
                            + [f"NIC {_short(_text(n))}" for n in group["meta"].get("nic_ids") or []],
                        ]
                        for group in groups
                        for rule in sorted(
                            (r for r in group["meta"].get("policy_rules") or [] if isinstance(r, dict)),
                            key=lambda r: (
                                _text(r.get("direction")),
                                r.get("priority") if isinstance(r.get("priority"), int) else 0,
                            ),
                        )
                    ][:MAX_SITE_ROWS],
                ),
            )

            members = [node, *self._vm_nodes(vms, node, site_id, subnet_names)]
            members += self._vnet_gateways(uid, node, site_id, subnet_names)
            site_name = f"{name} ({region})" if region else name
            self.sites.append(
                {
                    "id": site_id,
                    "name": f"{account} / {site_name}" if many_accounts and account else site_name,
                    "tags": [t for t in (region, meta.get("resource_group") or _group(vnet["rid"]), account) if t],
                    "vpn_mode": "spoke",
                    "status": _worst([m["status"] for m in members if m["kind"] != "wan"]),
                    "device_count": sum(1 for m in members if m["kind"] in ("vpc", "appliance", "server")),
                    "sections": sections,
                }
            )

    def _subnet_rows(
        self, subnets: list[dict], route_tables: list[dict], groups: list[dict], owned: dict[str, list[dict]]
    ) -> list[list[Any]]:
        tables = {t["rid"]: t for t in route_tables}
        group_names = {g["rid"]: g.get("name") or _short(g["rid"]) for g in groups}
        nats = {n["rid"]: n.get("name") or _short(n["rid"]) for n in owned.get("nat_gateway", [])}
        rows = []
        for subnet in subnets:
            meta = subnet["meta"]
            table = tables.get(_rid(_text(meta.get("route_table"))))
            default = ""
            for route in (table["meta"].get("routes") if table else None) or []:
                if isinstance(route, dict) and _text(route.get("prefix")) == "0.0.0.0/0":
                    default = next_hop_name(route)
            if not default:
                default = "NAT gateway" if _text(meta.get("nat_gateway")) else "Internet (system route)"
            rows.append(
                [
                    subnet.get("cidr"),
                    subnet.get("name") or _short(subnet["rid"]),
                    (table.get("name") or _short(table["rid"])) if table else "",
                    default,
                    group_names.get(_rid(_text(meta.get("network_security_group"))), ""),
                    nats.get(_rid(_text(meta.get("nat_gateway"))), ""),
                    meta.get("delegations"),
                    meta.get("ip_configuration_count"),
                ]
            )
        return rows

    def _vm_nodes(self, vms: list[dict], vnet_node: dict, site_id: str, subnet_names: dict[str, str]) -> list[dict]:
        members: list[dict] = []
        for vm in vms:
            meta = vm["meta"]
            interfaces = [i for i in meta.get("interfaces") or [] if isinstance(i, dict)]
            primary = _text(meta.get("private_ip"))
            addresses = [primary, _text(meta.get("public_ip"))]
            for interface in interfaces:
                addresses += [_text(ip) for ip in (interface.get("private_ips") or [])]
                addresses += [_text(ip) for ip in (interface.get("public_ips") or [])]
            addresses = list(dict.fromkeys(a for a in addresses if a))
            forwards = bool(meta.get("ip_forwarding"))
            host = self.inventory.match(ips=addresses)
            if not forwards and not host:
                continue
            node = self._node(
                _text(vm["resource_uid"]),
                f"vm:{vm['rid']}",
                "appliance" if forwards else "server",
                _text(vm.get("name")) or _short(vm["rid"]),
                site_id,
                _status(vm.get("status")),
                model="Azure virtual machine",
                ip=primary,
                # Other addresses of the machine; a public one identifies it
                # to the rest of the map (an SD-WAN appliance's WAN address).
                alias_ips=[a for a in addresses if a != primary],
            )
            if host:
                node["inventory"] = _inventory_ref(host)
            _add(
                node["sections"],
                kv_section(
                    "Overview",
                    [
                        ("Name", vm.get("name")),
                        ("Resource group", meta.get("resource_group")),
                        ("Virtual network", vnet_node["label"]),
                        (
                            "Subnet",
                            subnet_names.get(_text(meta.get("subnet_id"))) or _short(_text(meta.get("subnet_id"))),
                        ),
                        ("Private IP", primary),
                        ("Public IP", meta.get("public_ip")),
                        ("Forwards traffic (IP forwarding on)", forwards),
                        (
                            "Network security groups",
                            [_short(_text(g)) for g in meta.get("network_security_group_ids") or []],
                        ),
                        ("Account", self._account(vm)),
                    ],
                ),
            )
            _add(
                node["sections"],
                table_section(
                    "Network interfaces",
                    [
                        "Interface",
                        "Primary",
                        "Subnet",
                        "Private IPs",
                        "Public IPs",
                        "IP forwarding",
                        "Network security group",
                    ],
                    [
                        [
                            i.get("name") or _short(_text(i.get("id"))),
                            bool(i.get("primary")),
                            subnet_names.get(_text(i.get("subnet_id"))) or _short(_text(i.get("subnet_id"))),
                            i.get("private_ips"),
                            i.get("public_ips"),
                            bool(i.get("ip_forwarding")),
                            _short(_text(i.get("network_security_group"))),
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
            self._edge(node["id"], vnet_node["id"], "attach", status="active", label="Virtual machine in VNet")
            members.append(node)
        return members

    def _vnet_gateways(self, vnet_uid: str, vnet_node: dict, site_id: str, subnet_names: dict[str, str]) -> list[dict]:
        """VPN / ExpressRoute gateways, NAT gateways and the Azure Firewall of one VNet."""
        members: list[dict] = []
        for gateway in self._of_type("virtual_network_gateway"):
            if self._vnet_uid(gateway) == vnet_uid:
                members.append(self._virtual_network_gateway_node(gateway, site_id, vnet_node))
        for gateway in self._of_type("nat_gateway"):
            if self._vnet_uid(gateway) != vnet_uid:
                continue
            meta = gateway["meta"]
            public = [_text(ip) for ip in meta.get("public_ips") or []]
            node = self._node(
                _text(gateway["resource_uid"]),
                f"nat:{gateway['rid']}",
                "cloud",
                f"NAT {_text(gateway.get('name')) or _short(gateway['rid'])}",
                site_id,
                _status(gateway.get("status")),
                model="NAT gateway",
                ip=public[0] if public else "",
            )
            _add(
                node["sections"],
                kv_section(
                    "NAT gateway",
                    [
                        ("Name", gateway.get("name")),
                        ("State", gateway.get("status")),
                        ("Public IPs", public),
                        (
                            "Subnets",
                            [subnet_names.get(_text(s)) or _short(_text(s)) for s in meta.get("subnet_ids") or []],
                        ),
                        ("Idle timeout (minutes)", meta.get("idle_timeout_minutes")),
                        ("Virtual network", vnet_node["label"]),
                    ],
                ),
            )
            self._edge(
                node["id"], vnet_node["id"], "attach", status=_link_status(gateway.get("status")), label="NAT gateway"
            )
            members.append(node)
        for firewall in self._of_type("azure_firewall"):
            if self._vnet_uid(firewall) != vnet_uid:
                continue
            meta = firewall["meta"]
            public = [_text(ip) for ip in meta.get("public_ips") or []]
            node = self._node(
                _text(firewall["resource_uid"]),
                f"fw:{firewall['rid']}",
                "appliance",
                _text(firewall.get("name")) or _short(firewall["rid"]),
                site_id,
                _status(firewall.get("status")),
                model=f"Azure Firewall {_text(meta.get('tier'))}".strip(),
                ip=_text(meta.get("private_ip")),
                alias_ips=public,
            )
            _add(
                node["sections"],
                kv_section(
                    "Azure Firewall",
                    [
                        ("Name", firewall.get("name")),
                        ("State", firewall.get("status")),
                        ("Tier", meta.get("tier")),
                        ("Firewall policy", meta.get("firewall_policy")),
                        ("Threat intelligence", meta.get("threat_intel_mode")),
                        ("Private IP", meta.get("private_ip")),
                        ("Public IPs", public),
                        (
                            "Subnet",
                            subnet_names.get(_text(meta.get("subnet_id"))) or _short(_text(meta.get("subnet_id"))),
                        ),
                        ("Virtual network", vnet_node["label"]),
                        ("Source", "Its rules are decided by its firewall policy, which is not collected"),
                    ],
                ),
            )
            self._edge(
                node["id"],
                vnet_node["id"],
                "attach",
                status=_link_status(firewall.get("status")),
                label="Azure Firewall",
            )
            members.append(node)
        return members

    def _virtual_network_gateway_node(self, gateway: dict, site_id: str, vnet_node: dict | None) -> dict:
        meta = gateway["meta"]
        kind = _text(meta.get("gateway_type"))
        model = "ExpressRoute gateway" if kind.lower() == "expressroute" else "VPN gateway"
        public = [_text(ip) for ip in meta.get("public_ips") or []]
        node = self._node(
            _text(gateway["resource_uid"]),
            f"vng:{gateway['rid']}",
            "cloud",
            f"{'ERGW' if model.startswith('Express') else 'VGW'} {_text(gateway.get('name')) or _short(gateway['rid'])}",
            site_id,
            _status(gateway.get("status")),
            model=f"{model} {_text(meta.get('sku'))}".strip(),
            ip=public[0] if public else "",
            # The Azure ends of the tunnels: how another integration's view
            # of the same VPN (a Meraki or Cato IPsec peer) is recognised.
            endpoint_ips=list(public),
        )
        _add(
            node["sections"],
            kv_section(
                "Virtual network gateway",
                [
                    ("Name", gateway.get("name")),
                    ("Type", model),
                    ("VPN type", meta.get("vpn_type")),
                    ("SKU", meta.get("sku")),
                    ("State", gateway.get("status")),
                    ("Active-active", bool(meta.get("active_active")) if meta.get("active_active") else ""),
                    ("Public IPs", public),
                    ("BGP", f"ASN {_text(meta.get('bgp_asn'))}" if meta.get("enable_bgp") else ""),
                    ("BGP peering addresses", meta.get("bgp_peering_addresses")),
                    ("Virtual network", vnet_node["label"] if vnet_node else ""),
                    ("Subnet", _short(_text(meta.get("subnet_id")))),
                    ("Region", gateway.get("region")),
                    ("Account", self._account(gateway)),
                ],
            ),
        )
        if vnet_node:
            self._edge(
                node["id"],
                vnet_node["id"],
                "attach",
                status=_link_status(gateway.get("status")),
                label="Virtual network gateway",
            )
        return node

    # ── Transit: circuits and the far ends of VPNs ─────────────────────────

    def build_transit(self) -> None:
        for gateway in self._of_type("virtual_network_gateway"):
            if _text(gateway["resource_uid"]) not in self._node_of:
                self._virtual_network_gateway_node(gateway, TRANSIT_SITE_ID, None)
        for circuit in self._of_type("expressroute"):
            meta = circuit["meta"]
            bandwidth = meta.get("bandwidth_mbps")
            node = self._node(
                _text(circuit["resource_uid"]),
                f"er:{circuit['rid']}",
                "cloud",
                f"ER {_text(circuit.get('name')) or _short(circuit['rid'])}",
                TRANSIT_SITE_ID,
                _status(circuit.get("status")),
                model=f"ExpressRoute {bandwidth} Mbps" if bandwidth else "ExpressRoute circuit",
            )
            _add(
                node["sections"],
                kv_section(
                    "ExpressRoute circuit",
                    [
                        ("Name", circuit.get("name")),
                        ("Provider", meta.get("service_provider")),
                        ("Peering location", meta.get("peering_location")),
                        ("Bandwidth (Mbps)", bandwidth),
                        ("Circuit state", meta.get("circuit_provisioning_state")),
                        ("Provider state", meta.get("service_provider_provisioning_state")),
                        ("SKU", " ".join(t for t in (_text(meta.get("sku_tier")), _text(meta.get("sku_family"))) if t)),
                        ("Region", circuit.get("region")),
                        ("Account", self._account(circuit)),
                        ("Source", "The edge of the map: the on-premises router behind the circuit is not collected"),
                    ],
                ),
            )
            _add(
                node["sections"],
                table_section(
                    "ExpressRoute peerings",
                    ["Peering", "State", "Azure ASN", "Peer ASN", "Primary prefix", "Secondary prefix", "VLAN"],
                    [
                        [
                            p.get("type"),
                            p.get("state"),
                            p.get("azure_asn"),
                            p.get("peer_asn"),
                            p.get("primary_peer_prefix"),
                            p.get("secondary_peer_prefix"),
                            p.get("vlan"),
                        ]
                        for p in meta.get("peerings") or []
                        if isinstance(p, dict)
                    ],
                ),
            )
        for gateway in self._of_type("local_network_gateway"):
            meta = gateway["meta"]
            address = _text(meta.get("gateway_ip_address")) or _text(meta.get("fqdn"))
            node = self._node(
                _text(gateway["resource_uid"]),
                f"lng:{gateway['rid']}",
                "vpn_peer",
                _text(gateway.get("name")) or address or _short(gateway["rid"]),
                TRANSIT_SITE_ID,
                "unknown",
                model="Local network gateway",
                ip=_text(meta.get("gateway_ip_address")),
            )
            _add(
                node["sections"],
                kv_section(
                    "Local network gateway",
                    [
                        ("Name", gateway.get("name")),
                        ("Public IP", meta.get("gateway_ip_address")),
                        ("FQDN", meta.get("fqdn")),
                        ("Address space", meta.get("address_prefixes")),
                        ("BGP ASN", meta.get("bgp_asn")),
                        ("BGP peering address", meta.get("bgp_peering_addresses")),
                        ("State", gateway.get("status")),
                        ("Source", "The far end of an Azure site-to-site VPN, as configured in Azure"),
                    ],
                ),
            )

    def _stub(self, uid: str) -> str | None:
        """A node for a peering whose far end was not discovered: a VNet of a
        subscription Plexus does not collect."""
        parts = uid.split(":", 2)
        if len(parts) != 3 or parts[1] != "vnet":
            return None
        rid = parts[2]
        node = self._node(
            uid, f"x:vnet:{rid}", "cloud", f"VNet {_short(rid)}", TRANSIT_SITE_ID, "unknown", model="Not collected"
        )
        _add(
            node["sections"],
            kv_section(
                "Not collected",
                [
                    ("Virtual network", _short(rid)),
                    ("Resource group", _group(rid)),
                    ("Subscription", rid.split(":")[0]),
                    ("Source", "Referenced by a VNet peering; it belongs to a subscription Plexus does not collect"),
                ],
            ),
        )
        return node["id"]

    def build_links(self) -> None:
        attachments: dict[str, list[list[Any]]] = {}
        for conn in self.connections:
            if conn["type"] in _NOT_A_LINK or conn["type"] in _VPN_LINKS:
                continue
            a = self._node_of.get(conn["src"]) or self._stub(conn["src"])
            b = self._node_of.get(conn["dst"]) or self._stub(conn["dst"])
            if not a or not b:
                continue
            label = _LINK_LABELS.get(conn["type"], conn["type"].replace("_", " ").capitalize())
            state = conn["meta"].get("connection_status") or conn.get("state")
            if conn["type"] in _CIRCUIT_LINKS:
                state = conn["meta"].get("connection_status") or state
            self._edge(a, b, "attach", status=_link_status(state), label=label, detail=_text(conn["meta"].get("name")))
            for own, other in ((a, b), (b, a)):
                attachments.setdefault(own, []).append(
                    [label, self.nodes[other]["label"], state, conn["meta"].get("name")]
                )
        for node_id, rows in attachments.items():
            if self.nodes[node_id]["kind"] == "cloud":
                _add(
                    self.nodes[node_id]["sections"],
                    table_section("Attachments", ["Type", "Attached to", "State", "Name"], sorted(rows, key=str)),
                )

    def build_vpns(self) -> None:
        """Gateway connections: a tunnel from the VPN gateway to the local
        network gateway (or the other VPN gateway), with the connection's
        detail on both ends."""
        rows_by_node: dict[str, list[list[Any]]] = {}
        for conn in self.connections:
            if conn["type"] not in _VPN_LINKS:
                continue
            gateway = self._node_of.get(conn["src"])
            if not gateway:
                continue
            meta = conn["meta"]
            name = _text(meta.get("name")) or conn["type"]
            peer = self._node_of.get(conn["dst"])
            if not peer:
                # Discovered without its local network gateway: keep the far
                # end on the map as an unnamed peer.
                peer = self._node(
                    conn["dst"], f"vpn:{_rid(conn['dst'])}", "vpn_peer", name, TRANSIT_SITE_ID, "unknown"
                )["id"]
            connection_status = _text(meta.get("connection_status")).lower()
            if connection_status == "connected":
                status = "reachable"
            elif connection_status in ("notconnected",):
                status = "unreachable"
            else:
                status = "" if _status(conn.get("state")) != "offline" else "unreachable"
            self._edge(
                gateway,
                peer,
                "vpn",
                status=status,
                label="VNet-to-VNet VPN" if conn["type"] == "vnet2vnet" else "Site-to-site VPN",
                detail=name,
            )
            far = self.resources.get(conn["dst"]) or {}
            row = [
                name,
                meta.get("connection_type") or conn["type"],
                meta.get("connection_status"),
                conn.get("state"),
                "BGP" if meta.get("enable_bgp") else "Static",
                meta.get("connection_protocol"),
                meta.get("routing_weight"),
                meta.get("ingress_bytes_transferred"),
                meta.get("egress_bytes_transferred"),
                (far.get("meta") or {}).get("address_prefixes"),
            ]
            rows_by_node.setdefault(gateway, []).append([self.nodes[peer]["label"], *row])
            rows_by_node.setdefault(peer, []).append([self.nodes[gateway]["label"], *row])
        for node_id, rows in rows_by_node.items():
            _add(
                self.nodes[node_id]["sections"],
                table_section(
                    "VPN connections",
                    [
                        "Far end",
                        "Connection",
                        "Type",
                        "Status",
                        "Provisioning",
                        "Routing",
                        "Protocol",
                        "Routing weight",
                        "Bytes received",
                        "Bytes sent",
                        "Remote address space",
                    ],
                    rows,
                ),
            )

    def build_report(self) -> None:
        for account in self.accounts:
            if _text(account.get("last_sync_status")) == "error":
                self.errors.append(
                    {
                        "scope": f"Azure account {_text(account.get('name'))}",
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
                    "scope": f"Azure account {self._account(warning)}",
                    "path": _text(meta.get("section")) or _text(warning.get("name")),
                    "status": None,
                    "message": f"Not collected: Azure answered {_text(meta.get('error')) or 'with an error'}. "
                    "The role of the account may not allow this call.",
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
                    ("Discovered via", "Azure API"),
                ],
            )
            edge["sections"] = [section] if section else []


def build_snapshot(
    accounts: list[dict],
    resources: list[dict],
    connections: list[dict],
    inventory: InventoryIndex | None = None,
) -> dict[str, Any]:
    """Build the positioned topology snapshot of every Azure account given.

    ``resources`` and ``connections`` are Cloud Visibility rows (or the
    records a collector returns) of those accounts.
    """
    builder = _Builder(accounts, resources, connections, inventory or InventoryIndex())
    builder.build_vnets()
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
                # Sorts the transit box ahead of the VNets, like a VPN hub.
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
        if node["kind"] in ("wan", "cloud", "vpn_peer"):
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
        "org": {"id": "", "name": "Azure" + (f" ({', '.join(names)})" if names else ""), "url": ""},
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
            "vlans": builder.subnet_count,
            "cloud_links": edge_counts.get("attach", 0),
        },
        "collection": {
            "sources": ["Azure API (Cloud Visibility discovery)"],
            "stats": {"accounts": len(accounts), "resources": len(builder.resources)},
            "errors": builder.errors,
            "options": {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }
