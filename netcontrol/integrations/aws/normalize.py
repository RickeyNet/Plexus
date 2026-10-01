"""Turn the AWS discovery Cloud Visibility stores into a topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), so the merge
into the Topology graph, node details, deep search, the subnet index and the
HTML export need no AWS-specific code.

Every enabled AWS account goes into one snapshot: resource ids are unique
across AWS, so a transit gateway shared between accounts, or a peering
between two of them, joins up without any matching.

How AWS maps onto the map:

  - every VPC is a site box. Its node stands for the VPC's router and owns
    the VPC's subnets; the internet gateway hangs off it like a WAN uplink,
    NAT and virtual private gateways sit beside it
  - an instance is a node only when it forwards traffic (source/destination
    check off: firewalls, routers, SD-WAN and VPN appliances) or is a Plexus
    inventory host. Every instance is listed in its VPC's details
  - transit gateways, Direct Connect and customer gateways share an
    "AWS transit and VPN" box; a site-to-site VPN is a tunnel from its
    gateway to the customer gateway
"""

from __future__ import annotations

import json
from typing import Any

from netcontrol.integrations.aws.collect import WARNING_TYPE
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

PROVIDER = "aws"
TRANSIT_SITE_ID = "__aws_transit__"
TRANSIT_SITE_NAME = "AWS transit and VPN"

SUBNET_SECTION_TITLE = "Subnets"
SUBNET_COLUMNS = ["Subnet", "Name", "Availability zone", "Subnet ID", "Route table", "Default route", "Free IPs"]

# Detail tables are capped so one large VPC cannot bloat the snapshot.
MAX_SITE_ROWS = 3000

_UP_STATES = ("", "available", "active", "attached", "associated", "up", "enabled", "running", "enforced")
_PENDING_PREFIXES = ("pending", "initiating", "provisioning", "requested", "associating", "attaching", "modifying")
_DOWN_INSTANCE_STATES = ("stopped", "stopping")

# Connections that describe a resource rather than join two nodes.
_NOT_A_LINK = ("route_table_association", "security_boundary", "route_next_hop")
_VPN_LINKS = ("vpn_tunnel", "vpn_attachment", "customer_gateway_attachment")
_LINK_LABELS = {
    "transit_gateway_attachment": "Transit gateway attachment",
    "vpc_peering": "VPC peering",
    "internet_gateway_attachment": "Internet gateway",
    "nat_gateway_attachment": "NAT gateway",
    "vpn_gateway_attachment": "Virtual private gateway",
    "direct_connect_virtual_interface": "Direct Connect virtual interface",
    "direct_connect_gateway_association": "Direct Connect gateway association",
    "direct_connect_gateway": "Direct Connect",
}
_DEFAULT_ROUTE_VIA = (
    ("igw-", "Internet gateway"),
    ("eigw-", "Egress-only internet gateway"),
    ("nat-", "NAT gateway"),
    ("tgw-", "Transit gateway"),
    ("vgw-", "Virtual private gateway"),
    ("pcx-", "VPC peering"),
    ("eni-", "Appliance interface"),
    ("i-", "Instance"),
    ("vpce-", "Gateway load balancer endpoint"),
)


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
    """``aws:vpc:vpc-0abc`` -> ``vpc-0abc``."""
    parts = uid.split(":", 2)
    return parts[2] if len(parts) == 3 else uid


def _status(state: Any) -> str:
    state = _text(state).lower()
    if state in _UP_STATES:
        return "online"
    if state.startswith(_PENDING_PREFIXES):
        return "unknown"
    return "offline"


def _link_status(state: Any) -> str:
    """Edge status of a connection: ``failed`` takes it out of path tracing."""
    return {"online": "active", "unknown": ""}.get(_status(state), "failed")


def _default_route_via(target: str) -> str:
    for prefix, name in _DEFAULT_ROUTE_VIA:
        if target.startswith(prefix):
            return name
    return target


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
        self._vpc_uid_by_rid = {v["rid"]: _text(v["resource_uid"]) for v in self.vpcs}
        # Resource uid -> VPC uid, from the attachments a discovery records.
        self._vpc_links: dict[str, str] = {}
        for conn in self.connections:
            for vpc_end, other in ((conn["src"], conn["dst"]), (conn["dst"], conn["src"])):
                if vpc_end in self.resources and self.resources[vpc_end]["resource_type"] == "vpc":
                    other_type = (self.resources.get(other) or {}).get("resource_type")
                    if other_type not in ("vpc", "transit_gateway"):
                        self._vpc_links.setdefault(other, vpc_end)
        # A NAT gateway recorded only as a route's next hop is in that route table's VPC.
        for conn in self.connections:
            target = self.resources.get(conn["dst"])
            table = self.resources.get(conn["src"])
            if conn["type"] == "route_next_hop" and table and target and target["resource_type"] == "nat_gateway":
                vpc_uid = self._vpc_uid(table)
                if vpc_uid:
                    self._vpc_links.setdefault(conn["dst"], vpc_uid)

    # ── Lookups ────────────────────────────────────────────────────────────

    def _of_type(self, resource_type: str) -> list[dict]:
        found = [r for r in self.resources.values() if r.get("resource_type") == resource_type]
        return sorted(found, key=lambda r: (_text(r.get("name")).lower(), r["rid"]))

    def _vpc_uid(self, resource: dict) -> str:
        """The VPC a resource belongs to (``""`` when it belongs to none)."""
        meta = resource["meta"]
        candidates = [_text(meta.get("vpc_id")), *[_text(v) for v in meta.get("vpc_ids") or []]]
        for rid in candidates:
            if rid in self._vpc_uid_by_rid:
                return self._vpc_uid_by_rid[rid]
        return self._vpc_links.get(_text(resource["resource_uid"]), "")

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

    def _linked(self, a: str, b: str) -> bool:
        return any(key[:2] == tuple(sorted((a, b))) for key in self._edge_keys)

    # ── VPCs ───────────────────────────────────────────────────────────────

    def build_vpcs(self) -> None:
        many_accounts = len({self._account(v) for v in self.vpcs}) > 1
        by_vpc: dict[str, dict[str, list[dict]]] = {}
        for resource_type in ("subnet", "route_table", "instance", "security_group"):
            for resource in self._of_type(resource_type):
                by_vpc.setdefault(self._vpc_uid(resource), {}).setdefault(resource_type, []).append(resource)

        for vpc in self.vpcs:
            uid = _text(vpc["resource_uid"])
            site_id = vpc["rid"]
            name = _text(vpc.get("name")) or vpc["rid"]
            region = _text(vpc.get("region"))
            account = self._account(vpc)
            owned = by_vpc.get(uid, {})
            node = self._node(
                uid,
                f"vpc:{vpc['rid']}",
                "vpc",
                name,
                site_id,
                _status(vpc.get("status")),
                model=f"AWS VPC {_text(vpc.get('cidr'))}".strip(),
                site_sections=True,
            )
            _add(
                node["sections"],
                kv_section(
                    "Overview",
                    [
                        ("VPC", name),
                        ("VPC ID", vpc["rid"]),
                        ("CIDR", vpc.get("cidr")),
                        ("Region", region),
                        ("Account", account),
                        ("State", vpc.get("status")),
                        ("Source", "The VPC's own router: every subnet of the VPC is reached through it"),
                    ],
                ),
            )

            subnets = owned.get("subnet", [])
            instances = owned.get("instance", [])
            route_tables = owned.get("route_table", [])
            sections: list[dict] = []
            _add(
                sections,
                kv_section(
                    "VPC overview",
                    [
                        ("VPC", name),
                        ("VPC ID", vpc["rid"]),
                        ("CIDR", vpc.get("cidr")),
                        ("Region", region),
                        ("Account", account),
                        ("State", vpc.get("status")),
                        ("Default VPC", vpc["meta"].get("is_default")),
                        ("Subnets", len(subnets) or ""),
                        ("Instances", len(instances) or ""),
                    ],
                ),
            )
            subnet_names = {s["rid"]: _text(s.get("name")) for s in subnets}
            _add(
                sections,
                table_section(SUBNET_SECTION_TITLE, SUBNET_COLUMNS, self._subnet_rows(subnets, route_tables)),
            )
            self.subnet_count += len(subnets)
            _add(
                sections,
                table_section(
                    "Route tables",
                    ["Route table", "Destination", "Target", "State", "Origin"],
                    [
                        [
                            table.get("name") or table["rid"],
                            r.get("destination"),
                            r.get("target"),
                            r.get("state"),
                            r.get("origin"),
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
                    "Instances",
                    ["Name", "Instance ID", "Private IP", "Public IP", "Type", "State", "Subnet", "Forwards traffic"],
                    [
                        [
                            i.get("name"),
                            i["rid"],
                            i["meta"].get("private_ip"),
                            i["meta"].get("public_ip"),
                            i["meta"].get("instance_type"),
                            i.get("status"),
                            subnet_names.get(_text(i["meta"].get("subnet_id"))) or i["meta"].get("subnet_id"),
                            not i["meta"].get("source_dest_check", True),
                        ]
                        for i in instances[:MAX_SITE_ROWS]
                    ],
                ),
            )
            _add(
                sections,
                table_section(
                    "Security group rules",
                    ["Group", "Direction", "Protocol", "Ports", "Source", "Destination"],
                    [
                        [
                            group.get("name") or group["rid"],
                            rule.get("direction"),
                            rule.get("protocol"),
                            rule.get("port_expression"),
                            rule.get("source_selector"),
                            rule.get("destination_selector"),
                        ]
                        for group in owned.get("security_group", [])
                        for rule in group["meta"].get("policy_rules") or []
                        if isinstance(rule, dict)
                    ][:MAX_SITE_ROWS],
                ),
            )

            members = [node, *self._instance_nodes(instances, node, site_id, subnet_names)]
            members += self._vpc_gateways(uid, node, site_id)
            site_name = f"{name} ({region})" if region else name
            self.sites.append(
                {
                    "id": site_id,
                    "name": f"{account} / {site_name}" if many_accounts and account else site_name,
                    "tags": [t for t in (region, account) if t],
                    "vpn_mode": "spoke",
                    "status": _worst([m["status"] for m in members if m["kind"] != "wan"]),
                    "device_count": sum(1 for m in members if m["kind"] in ("vpc", "appliance", "server")),
                    "sections": sections,
                }
            )

    def _subnet_rows(self, subnets: list[dict], route_tables: list[dict]) -> list[list[Any]]:
        explicit: dict[str, dict] = {}
        main: dict | None = None
        for table in route_tables:
            if table["meta"].get("main"):
                main = table
            for subnet_id in table["meta"].get("associated_subnet_ids") or []:
                explicit[_text(subnet_id)] = table
        rows = []
        for subnet in subnets:
            table = explicit.get(subnet["rid"]) or main
            default = ""
            for route in (table["meta"].get("routes") if table else None) or []:
                if isinstance(route, dict) and _text(route.get("destination")) == "0.0.0.0/0":
                    default = _default_route_via(_text(route.get("target")))
            rows.append(
                [
                    subnet.get("cidr"),
                    subnet.get("name") or subnet["rid"],
                    subnet["meta"].get("availability_zone"),
                    subnet["rid"],
                    (table.get("name") or table["rid"]) if table else "",
                    default,
                    subnet["meta"].get("available_ips"),
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
            forwards = not meta.get("source_dest_check", True)
            host = self.inventory.match(ips=addresses)
            if not forwards and not host:
                continue
            state = _text(instance.get("status")).lower()
            status = "offline" if state in _DOWN_INSTANCE_STATES else _status(state)
            node = self._node(
                _text(instance["resource_uid"]),
                f"i:{instance['rid']}",
                "appliance" if forwards else "server",
                _text(instance.get("name")) or instance["rid"],
                site_id,
                status,
                model=_text(meta.get("instance_type")),
                ip=primary,
                # Other addresses of the instance; a public one identifies it
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
                        ("Name", instance.get("name")),
                        ("Instance ID", instance["rid"]),
                        ("State", instance.get("status")),
                        ("Type", meta.get("instance_type")),
                        ("Platform", meta.get("platform")),
                        ("VPC", vpc_node["label"]),
                        ("Availability zone", meta.get("availability_zone")),
                        ("Private IP", primary),
                        ("Public IP", meta.get("public_ip")),
                        ("Forwards traffic (source/destination check off)", forwards),
                        ("Security groups", meta.get("security_groups")),
                        ("Launched", meta.get("launched")),
                        ("Account", self._account(instance)),
                    ],
                ),
            )
            _add(
                node["sections"],
                table_section(
                    "Network interfaces",
                    ["Interface", "Index", "Subnet", "Private IPs", "Public IPs", "Source/dest check", "Description"],
                    [
                        [
                            i.get("id"),
                            i.get("device_index"),
                            subnet_names.get(_text(i.get("subnet_id"))) or i.get("subnet_id"),
                            i.get("private_ips"),
                            i.get("public_ips"),
                            bool(i.get("source_dest_check", True)),
                            i.get("description"),
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
                status="failed" if status == "offline" else "active",
                label="Instance in VPC",
            )
            members.append(node)
        return members

    def _vpc_gateways(self, vpc_uid: str, vpc_node: dict, site_id: str) -> list[dict]:
        """Internet, NAT and virtual private gateways of one VPC."""
        members: list[dict] = []
        for gateway in self._of_type("internet_gateway"):
            if self._vpc_uid(gateway) != vpc_uid:
                continue
            node = self._node(
                _text(gateway["resource_uid"]),
                f"igw:{gateway['rid']}",
                "wan",
                "Internet gateway",
                site_id,
                "online",
                model="Internet gateway",
                parent=vpc_node["id"],
            )
            _add(
                node["sections"],
                kv_section(
                    "Internet gateway",
                    [("ID", gateway["rid"]), ("VPC", vpc_node["label"]), ("Region", gateway.get("region"))],
                ),
            )
            self._edge(node["id"], vpc_node["id"], "uplink", status="active", label="Internet gateway")
            members.append(node)
        for gateway in self._of_type("nat_gateway"):
            if self._vpc_uid(gateway) != vpc_uid:
                continue
            meta = gateway["meta"]
            public = [_text(ip) for ip in meta.get("public_ips") or []]
            node = self._node(
                _text(gateway["resource_uid"]),
                f"nat:{gateway['rid']}",
                "cloud",
                f"NAT {_text(gateway.get('name')) or gateway['rid']}",
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
                        ("ID", gateway["rid"]),
                        ("State", gateway.get("status")),
                        ("Connectivity", meta.get("connectivity_type")),
                        ("Public IPs", public),
                        ("Private IPs", meta.get("private_ips")),
                        ("Subnet", meta.get("subnet_id")),
                        ("VPC", vpc_node["label"]),
                    ],
                ),
            )
            self._edge(
                node["id"], vpc_node["id"], "attach", status=_link_status(gateway.get("status")), label="NAT gateway"
            )
            members.append(node)
        for gateway in self._of_type("vpn_gateway"):
            if self._vpc_uid(gateway) == vpc_uid:
                members.append(self._vpn_gateway_node(gateway, site_id))
        return members

    def _vpn_gateway_node(self, gateway: dict, site_id: str) -> dict:
        node = self._node(
            _text(gateway["resource_uid"]),
            f"vgw:{gateway['rid']}",
            "cloud",
            f"VGW {_text(gateway.get('name')) or gateway['rid']}",
            site_id,
            _status(gateway.get("status")),
            model="Virtual private gateway",
        )
        _add(
            node["sections"],
            kv_section(
                "Virtual private gateway",
                [
                    ("ID", gateway["rid"]),
                    ("State", gateway.get("status")),
                    ("Region", gateway.get("region")),
                    ("Account", self._account(gateway)),
                ],
            ),
        )
        return node

    # ── Transit: gateways between VPCs and to the outside ──────────────────

    def build_transit(self) -> None:
        for gateway in self._of_type("vpn_gateway"):
            if _text(gateway["resource_uid"]) not in self._node_of:
                self._vpn_gateway_node(gateway, TRANSIT_SITE_ID)
        for gateway in self._of_type("transit_gateway"):
            meta = gateway["meta"]
            node = self._node(
                _text(gateway["resource_uid"]),
                f"tgw:{gateway['rid']}",
                "cloud",
                f"TGW {_text(gateway.get('name')) or gateway['rid']}",
                TRANSIT_SITE_ID,
                _status(gateway.get("status")),
                model="Transit gateway",
            )
            _add(
                node["sections"],
                kv_section(
                    "Transit gateway",
                    [
                        ("Name", gateway.get("name")),
                        ("ID", gateway["rid"]),
                        ("State", gateway.get("status")),
                        ("Region", gateway.get("region")),
                        ("Amazon ASN", meta.get("amazon_asn")),
                        ("Owner account", meta.get("owner_id")),
                        ("Discovered in", self._account(gateway)),
                    ],
                ),
            )
        for connection in self._of_type("direct_connect"):
            node = self._node(
                _text(connection["resource_uid"]),
                f"dx:{connection['rid']}",
                "cloud",
                f"DX {_text(connection.get('name')) or connection['rid']}",
                TRANSIT_SITE_ID,
                _status(connection.get("status")),
                model=f"Direct Connect {_text(connection['meta'].get('bandwidth'))}".strip(),
            )
            _add(
                node["sections"],
                kv_section(
                    "Direct Connect connection",
                    [
                        ("Name", connection.get("name")),
                        ("ID", connection["rid"]),
                        ("State", connection.get("status")),
                        ("Bandwidth", connection["meta"].get("bandwidth")),
                        ("Location region", connection.get("region")),
                        ("Account", self._account(connection)),
                    ],
                ),
            )
        for gateway in self._of_type("direct_connect_gateway"):
            node = self._node(
                _text(gateway["resource_uid"]),
                f"dxgw:{gateway['rid']}",
                "cloud",
                f"DXGW {_text(gateway.get('name')) or gateway['rid']}",
                TRANSIT_SITE_ID,
                _status(gateway.get("status")),
                model="Direct Connect gateway",
            )
            _add(
                node["sections"],
                kv_section(
                    "Direct Connect gateway",
                    [
                        ("Name", gateway.get("name")),
                        ("ID", gateway["rid"]),
                        ("State", gateway.get("status")),
                        ("Amazon ASN", gateway["meta"].get("amazon_asn")),
                    ],
                ),
            )
        for gateway in self._of_type("customer_gateway"):
            meta = gateway["meta"]
            node = self._node(
                _text(gateway["resource_uid"]),
                f"cgw:{gateway['rid']}",
                "vpn_peer",
                _text(gateway.get("name")) or _text(meta.get("ip_address")) or gateway["rid"],
                TRANSIT_SITE_ID,
                "unknown",
                model="Customer gateway",
                ip=_text(meta.get("ip_address")),
            )
            _add(
                node["sections"],
                kv_section(
                    "Customer gateway",
                    [
                        ("Name", gateway.get("name")),
                        ("ID", gateway["rid"]),
                        ("Public IP", meta.get("ip_address")),
                        ("BGP ASN", meta.get("bgp_asn")),
                        ("Device", meta.get("device_name")),
                        ("State", gateway.get("status")),
                        ("Source", "The far end of an AWS site-to-site VPN, as configured in AWS"),
                    ],
                ),
            )

    def _stub(self, uid: str) -> str | None:
        """A node for an attachment whose far end was not discovered: a VPC
        or transit gateway of an account or region Plexus does not collect."""
        parts = uid.split(":", 2)
        if len(parts) != 3:
            return None
        kind, rid = parts[1], parts[2]
        if kind == "peering" and rid.startswith("tgw-"):
            known = self._node_of.get(f"aws:tgw:{rid}")
            if known:
                return known
            label = f"TGW {rid}"
        elif kind == "vpc":
            label = f"VPC {rid}"
        elif kind == "direct-connect-gateway":
            label = f"DXGW {rid}"
        else:
            return None
        node = self._node(uid, f"x:{kind}:{rid}", "cloud", label, TRANSIT_SITE_ID, "unknown", model="Not collected")
        _add(
            node["sections"],
            kv_section(
                "Not collected",
                [
                    ("ID", rid),
                    (
                        "Source",
                        "Referenced by an attachment; it belongs to an account or region Plexus does not collect",
                    ),
                ],
            ),
        )
        return node["id"]

    def build_links(self) -> None:
        attachments: dict[str, list[list[Any]]] = {}
        route_tables = {_text(t["resource_uid"]): t for t in self._of_type("route_table")}
        for conn in self.connections:
            if conn["type"] in _NOT_A_LINK or conn["type"] in _VPN_LINKS:
                continue
            a = self._node_of.get(conn["src"]) or self._stub(conn["src"])
            b = self._node_of.get(conn["dst"]) or self._stub(conn["dst"])
            if not a or not b:
                continue
            label = _LINK_LABELS.get(conn["type"], conn["type"].replace("_", " ").capitalize())
            kind = "uplink" if "wan" in (self.nodes[a]["kind"], self.nodes[b]["kind"]) else "attach"
            self._edge(a, b, kind, status=_link_status(conn.get("state")), label=label)
            for own, other in ((a, b), (b, a)):
                attachments.setdefault(own, []).append(
                    [label, self.nodes[other]["label"], conn.get("state"), conn["meta"].get("attachment_id")]
                )
        # A route to a gateway shows the VPC uses it even when no attachment
        # was recorded for the pair.
        for conn in self.connections:
            table = route_tables.get(conn["src"]) if conn["type"] == "route_next_hop" else None
            a = self._node_of.get(self._vpc_uid(table)) if table else None
            b = self._node_of.get(conn["dst"])
            if a and b and not self._linked(a, b):
                self._edge(a, b, "attach", status=_link_status(conn.get("state")), label="Route next hop")
        for node_id, rows in attachments.items():
            if self.nodes[node_id]["kind"] == "cloud":
                _add(
                    self.nodes[node_id]["sections"],
                    table_section(
                        "Attachments", ["Type", "Attached to", "State", "Attachment ID"], sorted(rows, key=str)
                    ),
                )

    def build_vpns(self) -> None:
        """Site-to-site VPN connections: a tunnel from the AWS gateway to the
        customer gateway, with the connection's detail on both ends."""
        ends: dict[str, dict[str, str]] = {}
        for conn in self.connections:
            if conn["type"] in _VPN_LINKS:
                role = "peer" if conn["type"] == "customer_gateway_attachment" else "gateway"
                ends.setdefault(conn["src"], {})[role] = conn["dst"]
        rows_by_node: dict[str, list[list[Any]]] = {}
        for vpn in self._of_type("vpn_connection"):
            uid = _text(vpn["resource_uid"])
            meta = vpn["meta"]
            state = _text(vpn.get("status")).lower()
            if state in ("deleted", "deleting"):
                continue
            gateway = self._node_of.get(ends.get(uid, {}).get("gateway", ""))
            if not gateway:
                continue
            peer = self._node_of.get(ends.get(uid, {}).get("peer", ""))
            name = _text(vpn.get("name")) or vpn["rid"]
            if not peer:
                # Discovered without its customer gateway: keep the far end
                # on the map as an unnamed peer.
                peer = self._node(uid, f"vpn:{vpn['rid']}", "vpn_peer", name, TRANSIT_SITE_ID, "unknown")["id"]
            tunnels = [t for t in meta.get("tunnels") or [] if isinstance(t, dict)]
            up = [t for t in tunnels if _text(t.get("status")).upper() == "UP"]
            if tunnels:
                status = "reachable" if up else "unreachable"
            else:
                status = "" if _status(state) != "offline" else "unreachable"
            outside = [_text(t.get("outside_ip")) for t in tunnels if _text(t.get("outside_ip"))]
            # The AWS ends of the tunnels: how another integration's view of
            # the same VPN (a Meraki or Cato IPsec peer) is recognised.
            known = self.nodes[gateway].setdefault("endpoint_ips", [])
            known.extend(ip for ip in outside if ip not in known)
            self._edge(gateway, peer, "vpn", status=status, label="Site-to-site VPN", detail=name)
            row = [
                name,
                vpn["rid"],
                vpn.get("status"),
                f"{len(up)} of {len(tunnels)} up" if tunnels else "",
                outside,
                [t.get("status_message") for t in tunnels if _text(t.get("status_message"))],
                "Static" if meta.get("static_routes_only") else ("BGP" if tunnels else ""),
                meta.get("static_routes"),
                meta.get("tunnel_inside_cidrs"),
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
                        "ID",
                        "State",
                        "Tunnels",
                        "AWS tunnel addresses",
                        "Tunnel status",
                        "Routing",
                        "Static routes",
                        "Inside CIDRs",
                    ],
                    rows,
                ),
            )

    def build_report(self) -> None:
        for account in self.accounts:
            if _text(account.get("last_sync_status")) == "error":
                self.errors.append(
                    {
                        "scope": f"AWS account {_text(account.get('name'))}",
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
                    "scope": f"AWS account {self._account(warning)}",
                    "path": f"{_text(meta.get('section')) or warning.get('name')} ({_text(warning.get('region'))})",
                    "status": None,
                    "message": f"Not collected: AWS answered {_text(meta.get('error')) or 'with an error'}. "
                    "The read-only policy of the account may not allow this call.",
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
                    ("Discovered via", "AWS API"),
                ],
            )
            edge["sections"] = [section] if section else []


def build_snapshot(
    accounts: list[dict],
    resources: list[dict],
    connections: list[dict],
    inventory: InventoryIndex | None = None,
) -> dict[str, Any]:
    """Build the positioned topology snapshot of every AWS account given.

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
                # Sorts the transit box ahead of the VPCs, like a VPN hub.
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
        "org": {"id": "", "name": "AWS" + (f" ({', '.join(names)})" if names else ""), "url": ""},
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
            "sources": ["AWS API (Cloud Visibility discovery)"],
            "stats": {"accounts": len(accounts), "resources": len(builder.resources)},
            "errors": builder.errors,
            "options": {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }
