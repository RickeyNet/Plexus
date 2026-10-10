"""Turn raw Appgate SDP payloads into a positioned topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), so the merge
into the Topology graph, node details, deep search, the subnet index, IPAM,
the HTML export and the software tracker need no Appgate-specific code.

How an Appgate collective maps onto the map:

  - every site is a site box holding its appliances: its Gateways first
    (active/active, by name: the first one owns the site's network ranges
    in the subnet index and shows the site's details), then the
    Controllers, Portals, LogServers and Connectors placed at the site
  - the collective itself is one "Appgate Collective" node in a box of its
    own, with the appliances that belong to no site; every appliance is
    joined to it by a management link (``Appgate Controller`` for a
    Controller, ``Appgate peer link`` for the rest) that Path Mode and the
    tidy-tree layout ignore
  - every user connected with the Appgate Client is a node of its own in an
    "Appgate clients" box, with one ``Appgate tunnel`` to each Gateway it
    has a tunnel to (from its per-user access details; without them, to the
    collective node)
  - there is no internet node: what an Appgate Client sends outside its
    entitlements leaves the device directly (split tunnel), and what a
    Gateway sends on leaves by its own interfaces

The site's network subnets, and the networks of its Gateways' interfaces,
are its "Network ranges", so they can be picked in Path Mode and are listed
on IPAM. The users and the collective own no subnet.

Forwarding data (``node["forwarding"]``) is built by ``forwarding``: each
Gateway carries the Entitlements of its site as a rule set, the client
tunnel addresses of the users connected to it as routes, and its SNAT; each
user routes what its entitlements cover to the Gateway that grants them.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.meraki.forwarding import canonical
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

COLLECTIVE_SITE_ID = "__appgate_sdp__"
COLLECTIVE_NODE_ID = "appgate:collective"
USERS_SITE_ID = "__appgate_users__"
USER_NODE_PREFIX = "appgate:user:"
APPLIANCE_NODE_PREFIX = "a:"

# Kinds that are part of the Appgate fabric rather than devices at a site.
CLOUD_KINDS = ("cloud", "user")

SOURCE = "Appgate SDP API"
RANGE_SECTION_TITLE = "Network ranges"
RANGE_COLUMNS = ["Subnet", "Name", "Interface", "VLAN", "Source"]
ENTITLEMENT_COLUMNS = ["Entitlement", "Action", "Protocol", "Hosts", "Ports", "Conditions", "Policies", "Status"]
USER_COLUMNS = [
    "User",
    "Provider",
    "Device",
    "Tunnel IP",
    "Public IP",
    "Client",
    "OS",
    "Connected since",
    "Entitlements",
]
MAX_LISTED_USERS = 5000

# The roles an appliance can run, in the order they are named.
ROLES = (
    ("controller", "Controller"),
    ("gateway", "Gateway"),
    ("portal", "Portal"),
    ("logServer", "LogServer"),
    ("logForwarder", "LogForwarder"),
    ("connector", "Connector"),
    ("metricsAggregator", "Metrics Aggregator"),
    ("connectionBroker", "Connection Broker"),
)

_APPLIANCE_STATUS = {
    "healthy": "online",
    "warning": "alerting",
    "busy": "alerting",
    "error": "offline",
    "offline": "offline",
}
_SITE_STATUS = {
    "healthy": "online",
    "warning": "alerting",
    "unhealthy": "offline",
    "noactivegateways": "offline",
}
_RESOLVERS = (
    ("dnsResolvers", "DNS"),
    ("awsResolvers", "AWS"),
    ("azureResolvers", "Azure"),
    ("gcpResolvers", "GCP"),
    ("esxResolvers", "ESX"),
)
_EXCLUDE = "exclude (not tunnelled)"


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _dicts(value: Any) -> list[dict]:
    return [v for v in _list(value) if isinstance(v, dict)]


def appliance_status(raw: Any) -> str:
    return _APPLIANCE_STATUS.get(_text(raw).lower(), "unknown")


def site_status(raw: Any) -> str:
    return _SITE_STATUS.get(_text(raw).lower(), "unknown")


def prefix_length(netmask: Any, version: int = 4) -> int | None:
    """An Appgate netmask (a prefix length, or a dotted mask) as a prefix length."""
    text = _text(netmask)
    if text.isdigit():
        return int(text)
    try:
        return ipaddress.ip_network(f"0.0.0.0/{text}").prefixlen if version == 4 and text else None
    except ValueError:
        return None


def network(address: Any, netmask: Any) -> str:
    """The network of ``address``/``netmask`` (``""`` when it is not one)."""
    text = _text(address)
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return ""
    prefix = prefix_length(netmask, parsed.version)
    if prefix is None:
        prefix = parsed.max_prefixlen
    return canonical(f"{text}/{prefix}")


def site_subnets(site: dict) -> list[tuple[str, str]]:
    """``(cidr, comment)`` of a site's network subnets: the text after
    ``#`` is a comment."""
    found: list[tuple[str, str]] = []
    for entry in _list(site.get("networkSubnets")):
        text, _sep, comment = _text(entry).partition("#")
        cidr = canonical(text.strip())
        if cidr:
            found.append((cidr, comment.strip()))
    return found


def roles(appliance: dict) -> list[str]:
    return [label for key, label in ROLES if _dict(appliance.get(key)).get("enabled")]


def is_gateway(appliance: dict) -> bool:
    return bool(_dict(appliance.get("gateway")).get("enabled"))


def is_controller(appliance: dict) -> bool:
    return bool(_dict(appliance.get("controller")).get("enabled"))


def static_addresses(appliance: dict) -> list[tuple[str, str, str, bool]]:
    """``(nic, address, network, snat)`` of every static IPv4 and IPv6
    address of an appliance."""
    found: list[tuple[str, str, str, bool]] = []
    for nic in _dicts(_dict(appliance.get("networking")).get("nics")):
        name = _text(nic.get("name"))
        for family in ("ipv4", "ipv6"):
            for item in _dicts(_dict(nic.get(family)).get("static")):
                cidr = network(item.get("address"), item.get("netmask"))
                if cidr:
                    found.append((name, _text(item.get("address")), cidr, bool(item.get("snat"))))
    return found


def dhcp_nics(appliance: dict) -> list[str]:
    """The NICs of an appliance that take their IPv4 address from DHCP."""
    return [
        _text(nic.get("name"))
        for nic in _dicts(_dict(appliance.get("networking")).get("nics"))
        if _dict(_dict(_dict(nic.get("ipv4")).get("dhcp"))).get("enabled")
    ]


def static_routes(appliance: dict) -> list[tuple[str, str, str]]:
    """``(prefix, gateway, nic)`` of an appliance's static routes."""
    found: list[tuple[str, str, str]] = []
    for item in _dicts(_dict(appliance.get("networking")).get("routes")):
        prefix = network(item.get("address"), item.get("netmask"))
        if prefix:
            found.append((prefix, _text(item.get("gateway")), _text(item.get("nic"))))
    return found


def allowed_destinations(appliance: dict) -> list[tuple[str, str]]:
    """``(network, nic)`` a Gateway lets client traffic reach (empty: any)."""
    vpn = _dict(_dict(appliance.get("gateway")).get("vpn"))
    found: list[tuple[str, str]] = []
    for item in _dicts(vpn.get("allowDestinations")):
        cidr = network(item.get("address"), item.get("netmask"))
        if cidr:
            found.append((cidr, _text(item.get("nic"))))
    return found


def action_label(action: dict) -> str:
    verdict = _text(action.get("action")).lower()
    return _EXCLUDE if verdict == "exclude" else verdict


def ports_text(action: dict) -> str:
    subtype = _text(action.get("subtype")).lower()
    if subtype.startswith("icmp"):
        types = ", ".join(_text(t) for t in _list(action.get("types")) if _text(t))
        return f"types {types}" if types else ""
    return ", ".join(_text(p) for p in _list(action.get("ports")) if _text(p))


def _join(values: Any) -> str:
    return ", ".join(_text(v) for v in _list(values) if _text(v))


class _Builder:
    def __init__(self, raw: dict, inventory: InventoryIndex) -> None:
        self.raw = raw
        self.inventory = inventory
        self.options = _dict(raw.get("options"))
        self.collective = _dict(raw.get("collective"))
        self.appliances = [a for a in _dicts(raw.get("appliances")) if _text(a.get("id"))]
        self.status_by_id = {_text(s.get("id")): s for s in _dicts(raw.get("appliance_status"))}
        self.sites_raw = sorted(
            (s for s in _dicts(raw.get("sites")) if _text(s.get("id"))), key=lambda s: _text(s.get("name")).lower()
        )
        self.site_by_id = {_text(s["id"]): s for s in self.sites_raw}
        self.site_status_by_id = {_text(s.get("id")): s for s in _dicts(raw.get("site_status"))}
        self.entitlements_collected = isinstance(raw.get("entitlements"), list)
        self.entitlements = sorted(
            (e for e in _dicts(raw.get("entitlements")) if _text(e.get("id"))),
            key=lambda e: _text(e.get("name")).lower(),
        )
        self.policies = sorted(_dicts(raw.get("policies")), key=lambda p: _text(p.get("name")).lower())
        self.conditions_by_id = {_text(c.get("id")): c for c in _dicts(raw.get("conditions"))}
        self.ip_pools = _dicts(raw.get("ip_pools"))
        self.identity_providers = _dicts(raw.get("identity_providers"))
        self.session_details_collected = isinstance(raw.get("session_details"), dict)

        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.sites: list[dict] = []
        self.boxes: list[dict] = []
        self.range_count = 0
        # Node id -> the appliance it stands for; appliance name -> node id;
        # site id -> its Gateways' node ids, first one first.
        self.appliance_of: dict[str, dict] = {}
        self.node_of_name: dict[str, str] = {}
        self.gateways_of_site: dict[str, list[str]] = {}
        # Connected users: one record per session (see ``_user_records``).
        self.users: list[dict] = []
        # Edge id -> (user record, gateway node id), for the tunnel details.
        self._tunnel_of_edge: dict[str, tuple[dict, str]] = {}

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

    def _edge(self, a: str, b: str, kind: str, **fields: Any) -> dict | None:
        if a == b or a not in self.nodes or b not in self.nodes:
            return None
        edge = {"id": f"e{len(self.edges) + 1}", "a": a, "b": b, "kind": kind, "a_port": "", "b_port": "", "status": ""}
        edge.update(fields)
        self.edges.append(edge)
        return edge

    # ── Lookups ────────────────────────────────────────────────────────────

    def site_name(self, site_id: str) -> str:
        site = self.site_by_id.get(site_id)
        return _text((site or {}).get("name")) or site_id

    def site_entitlements(self, site_id: str) -> list[dict]:
        """The entitlements of a site, by name."""
        return [e for e in self.entitlements if _text(e.get("site")) == site_id]

    def policy_names(self, entitlement: dict) -> list[str]:
        """The policies that grant an entitlement, by id or by tag link."""
        ident = _text(entitlement.get("id"))
        tags = {_text(t) for t in _list(entitlement.get("tags")) if _text(t)}
        found = []
        for policy in self.policies:
            linked = {_text(t) for t in _list(policy.get("entitlementLinks")) if _text(t)}
            if ident in {_text(e) for e in _list(policy.get("entitlements"))} or tags & linked:
                found.append(_text(policy.get("name")))
        return found

    def condition_names(self, entitlement: dict) -> list[str]:
        return [
            _text(self.conditions_by_id.get(_text(c), {}).get("name")) or _text(c)
            for c in _list(entitlement.get("conditions"))
            if _text(c)
        ]

    def entitlement_rows(self, entitlements: list[dict], *, with_site: bool = False) -> list[list[Any]]:
        rows: list[list[Any]] = []
        for entitlement in entitlements:
            logic = f" {_text(entitlement.get('conditionLogic')) or 'and'} "
            conditions = logic.join(self.condition_names(entitlement))
            policies = ", ".join(self.policy_names(entitlement))
            state = "disabled" if entitlement.get("disabled") else "enabled"
            for action in _dicts(entitlement.get("actions")):
                row = [
                    entitlement.get("name"),
                    action_label(action),
                    action.get("subtype"),
                    _join(action.get("hosts")),
                    ports_text(action),
                    conditions,
                    policies,
                    state,
                ]
                rows.append(
                    [entitlement.get("siteName") or self.site_name(_text(entitlement.get("site"))), *row]
                    if with_site
                    else row
                )
        return rows

    def pool_name(self, pool_id: Any) -> str:
        pool = next((p for p in self.ip_pools if _text(p.get("id")) == _text(pool_id)), None)
        return _text((pool or {}).get("name")) or _text(pool_id)

    # ── Appliances ─────────────────────────────────────────────────────────

    def build_appliances(self) -> None:
        """A node per appliance: per site its Gateways first, by name (the
        first one is the site's gateway for the subnet index), then the
        rest; the appliances of no known site in the collective box."""
        by_site: dict[str, list[dict]] = {}
        for appliance in self.appliances:
            site_id = _text(appliance.get("site"))
            by_site.setdefault(site_id if site_id in self.site_by_id else "", []).append(appliance)

        def order(appliance: dict) -> tuple[bool, str]:
            return (not is_gateway(appliance), _text(appliance.get("name")).lower())

        for site in [*self.sites_raw, None]:
            site_id = _text(site["id"]) if site else ""
            box = site_id or COLLECTIVE_SITE_ID
            for appliance in sorted(by_site.get(site_id, []), key=order):
                node = self._appliance_node(appliance, box)
                if site_id and is_gateway(appliance):
                    self.gateways_of_site.setdefault(site_id, []).append(node["id"])
            members = [n for n in self.nodes.values() if n["site"] == site_id] if site_id else []
            if members:
                members[0]["site_sections"] = True

    def _appliance_node(self, appliance: dict, box: str) -> dict:
        ident = _text(appliance["id"])
        found = _dict(self.status_by_id.get(ident))
        names = roles(appliance)
        status = appliance_status(found.get("status"))
        gateway = _dict(appliance.get("gateway"))
        suspended = is_gateway(appliance) and bool(gateway.get("suspended"))
        if appliance.get("activated") is False:
            status = "unknown"
        elif suspended and status != "offline":
            status = "alerting"
        addresses = static_addresses(appliance)
        ips = [a[1] for a in addresses] + self._status_ips(found)
        name = _text(appliance.get("name")) or ident
        node = self._node(
            f"{APPLIANCE_NODE_PREFIX}{ident}",
            "appliance",
            name,
            box,
            status,
            model="Appgate " + " / ".join(names) if names else "Appgate appliance",
            ip=next((ip for ip in ips if ip), ""),
        )
        self.appliance_of[node["id"]] = appliance
        self.node_of_name.setdefault(name.lower(), node["id"])
        host = self.inventory.match(ips=[ip for ip in ips if ip], name=_text(appliance.get("hostname")))
        if host:
            node["inventory"] = _inventory_ref(host)
            node["_host"] = host
        return node

    @staticmethod
    def _status_ips(found: dict) -> list[str]:
        details = _dict(_dict(_dict(found.get("details")).get("network")).get("details"))
        return [_text(ip) for nic in details.values() if isinstance(nic, dict) for ip in _list(nic.get("ips"))]

    def _health_details(self, found: dict) -> str:
        parts: list[str] = []
        for role, info in _dict(found.get("roles")).items():
            info = _dict(info)
            detail = _text(info.get("details"))
            if detail:
                parts.append(f"{role}: {detail}")
            if info.get("maintenanceMode"):
                parts.append(f"{role}: maintenance mode")
        details = found.get("details")
        if isinstance(details, str) and details.strip():
            parts.insert(0, details.strip())
        return "; ".join(parts)

    def appliance_sections(self) -> None:
        """The detail sections of every appliance, once the users are known."""
        for node_id, appliance in self.appliance_of.items():
            node = self.nodes[node_id]
            sections = node["sections"]
            found = _dict(self.status_by_id.get(_text(appliance["id"])))
            _add(sections, self._overview(node, appliance, found))
            _add(sections, self._interfaces(appliance, found))
            _add(
                sections,
                table_section(
                    "Static routes",
                    ["Destination", "Gateway", "Interface"],
                    [list(r) for r in static_routes(appliance)],
                ),
            )
            if is_gateway(appliance):
                _add(
                    sections,
                    table_section(
                        "Allowed destinations",
                        ["Network", "Interface"],
                        [list(r) for r in allowed_destinations(appliance)],
                    ),
                )
                site_id = _text(appliance.get("site"))
                _add(
                    sections,
                    table_section(
                        "Entitlements", ENTITLEMENT_COLUMNS, self.entitlement_rows(self.site_entitlements(site_id))
                    ),
                )
                rows = [self.user_row(u, node_id) for u in self.users if node_id in u["gateways"]]
                _add(sections, table_section("Connected users", USER_COLUMNS, rows[:MAX_LISTED_USERS]))
            _add(sections, self._connector_clients(appliance))
            host = node.pop("_host", None)
            if host:
                _add(
                    sections,
                    kv_section(
                        "Plexus inventory",
                        [
                            ("Hostname", host.get("hostname")),
                            ("IP address", host.get("ip_address")),
                            ("Device type", host.get("device_type")),
                        ],
                    ),
                )

    def _overview(self, node: dict, appliance: dict, found: dict) -> dict | None:
        client = _dict(appliance.get("clientInterface"))
        admin = _dict(appliance.get("adminInterface"))
        gateway = _dict(appliance.get("gateway"))

        def endpoint(item: dict) -> str:
            host = _text(item.get("hostname"))
            port = _text(item.get("httpsPort"))
            return f"{host}:{port}" if host and port else host

        def percent(value: Any) -> str:
            return f"{value}%" if value not in (None, "") else ""

        upgrade = _text(_dict(found.get("upgrade")).get("status"))
        site_id = _text(appliance.get("site"))
        return kv_section(
            "Overview",
            [
                ("Name", appliance.get("name")),
                ("Roles", roles(appliance)),
                ("Site", appliance.get("siteName") or (self.site_name(site_id) if site_id else "")),
                ("Status", found.get("status") or node["status"]),
                ("Health details", self._health_details(found)),
                ("Version", found.get("applianceVersion") or _dict(found.get("details")).get("version")),
                ("Peer version", appliance.get("version")),
                ("Hostname", appliance.get("hostname")),
                ("Client interface", endpoint(client)),
                ("Admin interface", endpoint(admin)),
                ("Sessions", found.get("numberOfSessions")),
                ("CPU", percent(found.get("cpu"))),
                ("Memory", percent(found.get("memory"))),
                ("Disk", percent(found.get("disk"))),
                ("Activated", "Not activated" if appliance.get("activated") is False else "Yes"),
                ("Suspended", "Yes" if is_gateway(appliance) and gateway.get("suspended") else ""),
                ("Gateway weight", _dict(gateway.get("vpn")).get("weight") if is_gateway(appliance) else ""),
                ("Tags", appliance.get("tags")),
                ("Notes", appliance.get("notes")),
                ("Upgrade", upgrade if upgrade and upgrade.lower() not in ("idle", "none") else ""),
                ("Source", SOURCE),
            ],
        )

    def _interfaces(self, appliance: dict, found: dict) -> dict | None:
        state = _dict(_dict(_dict(found.get("details")).get("network")).get("details"))
        rows: list[list[Any]] = []
        for nic in _dicts(_dict(appliance.get("networking")).get("nics")):
            name = _text(nic.get("name"))
            nic_state = _dict(state.get(name))
            status = nic_state.get("status")
            enabled = nic.get("enabled", True) is not False
            for family in ("ipv4", "ipv6"):
                for item in _dicts(_dict(nic.get(family)).get("static")):
                    cidr = network(item.get("address"), item.get("netmask"))
                    rows.append([name, item.get("address"), cidr, "No", bool(item.get("snat")), status, enabled])
            if _dict(_dict(nic.get("ipv4")).get("dhcp")).get("enabled"):
                ips = [_text(ip) for ip in _list(nic_state.get("ips")) if _text(ip)]
                rows.append([name, ", ".join(ips), "", "Yes", "", status, enabled])
        return table_section(
            "Interfaces", ["Interface", "Address", "Subnet", "DHCP", "SNAT", "Status", "Enabled"], rows
        )

    @staticmethod
    def _connector_clients(appliance: dict) -> dict | None:
        connector = _dict(appliance.get("connector"))
        if not connector.get("enabled"):
            return None
        rows: list[list[Any]] = []
        for kind, label in (("expressClients", "Express"), ("advancedClients", "Advanced")):
            for client in _dicts(connector.get(kind)):
                resources = [
                    network(r.get("address"), r.get("netmask")) or _text(r.get("address"))
                    for r in _dicts(client.get("allowResources"))
                ]
                snat = client.get("snatToTunnel") if kind == "advancedClients" else client.get("snatToResources")
                rows.append([client.get("name"), label, resources, bool(snat), client.get("defaultGateway")])
        return table_section("Connector clients", ["Client", "Type", "Resources", "SNAT", "Default gateway"], rows)

    # ── Sites ──────────────────────────────────────────────────────────────

    def site_ranges(self, site: dict) -> list[list[str]]:
        """The "Network ranges" rows of a site: its network subnets, then the
        networks of its Gateways' interfaces, each once."""
        site_id = _text(site["id"])
        rows: dict[str, list[str]] = {}
        for cidr, comment in site_subnets(site):
            rows.setdefault(cidr, [cidr, comment, "", "", "Site network subnet"])
        for node_id in self.gateways_of_site.get(site_id, []):
            for nic, _address, cidr, _snat in static_addresses(self.appliance_of[node_id]):
                rows.setdefault(cidr, [cidr, nic, nic, "", "Gateway interface"])
        return list(rows.values())

    def build_sites(self) -> None:
        for site in self.sites_raw:
            site_id = _text(site["id"])
            name = _text(site.get("name")) or site_id
            members = [n for n in self.nodes.values() if n["site"] == site_id]
            gateways = self.gateways_of_site.get(site_id, [])
            found = _dict(self.site_status_by_id.get(site_id))
            state = site_status(found.get("status")) if found else "unknown"
            default = _dict(site.get("defaultGateway"))
            default_text = ", ".join(v for k, v in (("enabledV4", "IPv4"), ("enabledV6", "IPv6")) if default.get(k))
            vpn = _dict(site.get("vpn"))
            route_via = _dict(vpn.get("routeVia"))
            fallback = _text(site.get("fallbackSite"))
            sessions = sum(
                int(_dict(self.status_by_id.get(_text(self.appliance_of[g]["id"]))).get("numberOfSessions") or 0)
                for g in gateways
            )

            sections: list[dict] = []
            _add(
                sections,
                kv_section(
                    "Site overview",
                    [
                        ("Site", name),
                        ("Short name", site.get("shortName")),
                        ("Status", found.get("status")),
                        ("Gateways", len(gateways)),
                        ("Sessions", sessions if self.status_by_id else ""),
                        ("Entitlement-based routing", bool(site.get("entitlementBasedRouting"))),
                        ("Default gateway", default_text or "No"),
                        ("SNAT to gateway", bool(vpn.get("snat"))),
                        ("Route via", [route_via.get("ipv4"), route_via.get("ipv6")]),
                        ("Fallback site", self.site_name(fallback) if fallback else ""),
                        ("Tags", site.get("tags")),
                        ("Notes", site.get("notes")),
                    ],
                ),
            )
            ranges = self.site_ranges(site)
            self.range_count += len(ranges)
            _add(sections, table_section(RANGE_SECTION_TITLE, RANGE_COLUMNS, ranges))
            protected = [
                [host, entitlement.get("name"), action_label(action), action.get("subtype"), ports_text(action)]
                for entitlement in self.site_entitlements(site_id)
                if not entitlement.get("disabled")
                for action in _dicts(entitlement.get("actions"))
                for host in _list(action.get("hosts"))
                if _text(host)
            ]
            _add(
                sections,
                table_section(
                    "Protected resources", ["Resource", "Entitlement", "Action", "Protocol", "Ports"], protected
                ),
            )
            _add(
                sections,
                table_section(
                    "Name resolution",
                    ["Resolver", "Type", "Servers / scope", "Match domains"],
                    self._resolver_rows(_dict(site.get("nameResolution"))),
                ),
            )
            forwarding = _dict(site.get("dnsForwarding"))
            if forwarding.get("siteIpv4") or forwarding.get("dnsServers"):
                _add(
                    sections,
                    table_section(
                        "Site DNS forwarding",
                        ["Site IP", "DNS servers"],
                        [[forwarding.get("siteIpv4"), forwarding.get("dnsServers")]],
                    ),
                )
            self.sites.append(
                {
                    "id": site_id,
                    "name": name,
                    "tags": [],
                    "vpn_mode": "spoke",
                    "status": _worst([state, *(m["status"] for m in members)]),
                    "device_count": len(members),
                    "sections": sections,
                }
            )

    @staticmethod
    def _resolver_rows(resolution: dict) -> list[list[Any]]:
        rows: list[list[Any]] = []
        for key, label in _RESOLVERS:
            for resolver in _dicts(resolution.get(key)):
                scope = (
                    _list(resolver.get("servers"))
                    + _list(resolver.get("regions"))
                    + _list(resolver.get("vpcs"))
                    + [resolver.get("subscriptionId"), resolver.get("projectFilter"), resolver.get("hostname")]
                )
                rows.append([resolver.get("name"), label, scope, resolver.get("matchDomains")])
        return rows

    # ── Users ──────────────────────────────────────────────────────────────

    def _user_records(self) -> list[dict]:
        """One record per session: who, from which device, and per Gateway
        it has a tunnel to the details the Controller holds."""
        details = _dict(self.raw.get("session_details"))
        registered = _text(self.raw.get("sessions_source")) == "on-boarded-devices"
        sessions = _dicts(self.raw.get("sessions"))
        counts: dict[str, int] = {}
        for session in sessions:
            counts[_text(session.get("username")).lower()] = counts.get(_text(session.get("username")).lower(), 0) + 1
        records: list[dict] = []
        for index, session in enumerate(sessions):
            dn = _text(session.get("distinguishedName"))
            detail = _dict(details.get(dn)) if dn in details else None
            entries = {
                _text(name): _dict(entry) for name, entry in _dict((detail or {}).get("data")).items() if _text(name)
            }
            claims = [_dict(e.get("systemClaims")) for e in entries.values()]
            username = _text(session.get("username")) or _text((detail or {}).get("username"))
            hostname = _text(session.get("hostname"))
            label = username or hostname or dn or f"user {index + 1}"
            if username and counts.get(username.lower(), 0) > 1 and hostname:
                label = f"{username} ({hostname})"
            gateways: dict[str, dict] = {}
            unknown: list[str] = []
            for name, entry in entries.items():
                node_id = self.node_of_name.get(name.lower())
                if node_id:
                    gateways[node_id] = entry
                else:
                    unknown.append(name)
            records.append(
                {
                    "session": session,
                    "dn": dn,
                    "detail": detail,
                    "registered": registered,
                    "device": _text(session.get("deviceId")) or _text((detail or {}).get("deviceId")),
                    "username": username,
                    "label": label,
                    "provider": _text(session.get("providerName")) or _text((detail or {}).get("providerName")),
                    "hostname": hostname,
                    "entries": entries,
                    "gateways": gateways,
                    "unknown_gateways": unknown,
                    "tun_ip": next((_text(c.get("tunIPv4")) for c in claims if _text(c.get("tunIPv4"))), ""),
                    "public_ip": next((_text(c.get("clientSrcIP")) for c in claims if _text(c.get("clientSrcIP"))), ""),
                    "connected": min(
                        (_text(c.get("connectTime")) for c in claims if _text(c.get("connectTime"))), default=""
                    ),
                }
            )
        return sorted(records, key=lambda r: (r["label"].lower(), r["dn"]))

    def user_row(self, record: dict, gateway: str | None = None) -> list[Any]:
        """A user in the "Connected users" table of a Gateway (its
        entitlements there) or of the users box (all of them)."""
        session = record["session"]
        entries = [record["gateways"][gateway]] if gateway else list(record["entries"].values())
        infos = [_dict(i) for e in entries for i in _dict(e.get("entitlementInfos")).values()]
        claims = _dict(entries[0].get("systemClaims")) if gateway and entries else {}
        client = " ".join(_text(session.get(k)) for k in ("clientType", "clientVersion") if _text(session.get(k)))
        return [
            record["username"] or record["label"],
            record["provider"],
            record["hostname"],
            record["tun_ip"],
            record["public_ip"],
            client,
            session.get("osName") or session.get("osFamily"),
            claims.get("connectTime") or record["connected"],
            f"{sum(1 for i in infos if i.get('access'))} / {len(infos)}" if infos else "",
        ]

    def build_users(self) -> None:
        if not isinstance(self.raw.get("sessions"), list):
            return
        self.users = self._user_records()
        used: set[str] = set()
        for index, record in enumerate(self.users):
            node_id = f"{USER_NODE_PREFIX}{record['device'] or record['dn'] or index}"
            if node_id in used or node_id in self.nodes:
                node_id = f"{node_id}:{index}"
            used.add(node_id)
            record["node_id"] = node_id
            node = self._user_node(node_id, record)
            if index == 0:
                node["site_sections"] = True
            targets = list(record["gateways"]) or [COLLECTIVE_NODE_ID]
            for target in targets:
                down = target != COLLECTIVE_NODE_ID and self.nodes[target]["status"] == "offline"
                edge = self._edge(
                    node_id,
                    target,
                    "vpn",
                    status="unreachable" if down else "reachable",
                    label="Appgate tunnel",
                    a_port=record["tun_ip"],
                )
                if edge is not None:
                    self._tunnel_of_edge[edge["id"]] = (record, target)

        sections: list[dict] = []
        with_details = sum(1 for r in self.users if r["detail"] is not None)
        registered = any(r["registered"] for r in self.users)
        _add(
            sections,
            kv_section(
                "Remote users",
                [
                    ("Connected now", "" if registered else len(self.users)),
                    ("Registered devices (connection unknown)", len(self.users) if registered else ""),
                    ("With access details", with_details if self.session_details_collected else "Not read"),
                    ("Skipped (over the cap)", self.raw.get("sessions_skipped") or ""),
                    ("Source", "Users connected with the Appgate Client when the collection ran"),
                ],
            ),
        )
        _add(
            sections,
            table_section("Connected users", USER_COLUMNS, [self.user_row(r) for r in self.users[:MAX_LISTED_USERS]]),
        )
        self.boxes.append(
            {
                "id": USERS_SITE_ID,
                "name": "Appgate clients",
                "tags": [],
                # Sorts the users next to the collective, ahead of the sites.
                "vpn_mode": "hub",
                "status": "unknown" if registered else "online",
                "device_count": len(self.users),
                "sections": sections,
            }
        )

    def _user_node(self, node_id: str, record: dict) -> dict:
        session = record["session"]
        entries = record["entries"]
        node = self._node(
            node_id,
            "user",
            record["label"],
            USERS_SITE_ID,
            "unknown" if record["registered"] else "online",
            model="Appgate Client",
            ip=record["tun_ip"],
        )
        sections = node["sections"]
        _add(
            sections,
            kv_section(
                "Remote user",
                [
                    ("User", record["username"]),
                    ("Identity provider", record["provider"]),
                    ("Device ID", record["device"]),
                    ("Hostname", record["hostname"]),
                    ("OS", session.get("osName") or session.get("osFamily")),
                    ("Client version", [session.get("clientType"), session.get("clientVersion")]),
                    ("Client support", session.get("clientSupport")),
                    ("Connection", "Registered, connection unknown" if record["registered"] else ""),
                    ("On-boarded", session.get("onBoardedAt")),
                    ("Last seen", session.get("lastSeenAt")),
                ],
            ),
        )
        latitude, longitude = session.get("geoIpLatitude"), session.get("geoIpLongitude")
        _add(
            sections,
            kv_section(
                "Connecting from",
                [
                    ("Public IP", record["public_ip"]),
                    (
                        "Coordinates",
                        f"{latitude}, {longitude}" if latitude is not None and longitude is not None else "",
                    ),
                ],
            ),
        )
        gateway_names = [self.nodes[g]["label"] for g in record["gateways"]] + record["unknown_gateways"]
        primary = next((_text(e.get("primarySite")) for e in entries.values() if _text(e.get("primarySite"))), "")
        policies = list(
            dict.fromkeys(_text(p) for e in entries.values() for p in _list(e.get("policyNames")) if _text(p))
        )
        _add(
            sections,
            kv_section(
                "Connected to (Appgate)",
                [
                    ("Gateways", gateway_names),
                    ("Primary site", primary),
                    (
                        "Sites",
                        list(dict.fromkeys(_text(e.get("site")) for e in entries.values() if _text(e.get("site")))),
                    ),
                    ("Tunnel IP", record["tun_ip"]),
                    ("Policies", policies),
                    ("Connected since", record["connected"]),
                    (
                        "Access details",
                        ""
                        if record["detail"] is not None
                        else ("Not read" if not self.session_details_collected else "Not available"),
                    ),
                ],
            ),
        )
        results: dict[tuple[str, str], list[Any]] = {}
        rules: list[list[Any]] = []
        for gateway, entry in entries.items():
            for name, info in _dict(entry.get("entitlementInfos")).items():
                info = _dict(info)
                conditions = "; ".join(
                    f"{c}: {'met' if ok else 'not met'}" for c, ok in _dict(info.get("conditionResults")).items()
                )
                results.setdefault(
                    (_text(name), _text(entry.get("site"))),
                    [name, entry.get("site"), bool(info.get("access")), conditions],
                )
            for item in _dicts(entry.get("firewallRules")):
                rules.append(
                    [
                        gateway,
                        item.get("name"),
                        item.get("protocol"),
                        item.get("direction"),
                        item.get("action"),
                        item.get("subnets") or item.get("urls"),
                        item.get("ports") or item.get("types"),
                    ]
                )
        _add(
            sections,
            table_section(
                "Entitlement results", ["Entitlement", "Site", "Access", "Conditions"], list(results.values())
            ),
        )
        _add(
            sections,
            table_section(
                "Firewall rules", ["Gateway", "Rule", "Protocol", "Direction", "Action", "Subnets", "Ports"], rules
            ),
        )
        return node

    # ── The collective ─────────────────────────────────────────────────────

    def build_collective_node(self) -> None:
        self._node(COLLECTIVE_NODE_ID, "cloud", "Appgate Collective", COLLECTIVE_SITE_ID, "online", model="Appgate SDP")

    def build_collective(self) -> None:
        """The collective's details, and its management links."""
        collective = self.collective
        node = self.nodes[COLLECTIVE_NODE_ID]
        controllers = [n for n, a in self.appliance_of.items() if is_controller(a)]
        gateways = [n for n, a in self.appliance_of.items() if is_gateway(a)]
        license_info = _dict(self.raw.get("license"))
        settings = _dict(self.raw.get("global_settings"))
        _add(
            node["sections"],
            kv_section(
                "Appgate Collective",
                [
                    ("Collective", collective.get("collective_name") or collective.get("name")),
                    ("Collective ID", collective.get("collective_id")),
                    ("Controller URL host", collective.get("controller")),
                    ("Peer version", collective.get("peer_version")),
                    ("Controllers", len(controllers)),
                    ("Gateways", len(gateways)),
                    ("Sites", len(self.sites_raw)),
                    ("Connected users", len(self.users) if isinstance(self.raw.get("sessions"), list) else ""),
                    ("Policies", len(self.policies) if isinstance(self.raw.get("policies"), list) else ""),
                    ("Entitlements", len(self.entitlements) if self.entitlements_collected else ""),
                    ("Identity providers", len(self.identity_providers) if self.identity_providers else ""),
                    ("Licensed users", license_info.get("users") or license_info.get("maxUsers")),
                    ("Licensed portal users", license_info.get("portalUsers") or license_info.get("maxPortalUsers")),
                    ("Licensed sites", license_info.get("sites") or license_info.get("maxSites")),
                    ("License expires", license_info.get("expiration") or license_info.get("expiry")),
                    ("Inactivity timeout (min)", settings.get("inactivityTimeoutMinutes")),
                    ("SPA mode", settings.get("spaMode")),
                    ("Snapshot time", self.raw.get("timestamp")),
                    ("Source", SOURCE),
                ],
            ),
        )
        sections = node["sections"]
        appliance_rows = []
        for node_id, appliance in self.appliance_of.items():
            found = _dict(self.status_by_id.get(_text(appliance["id"])))
            appliance_rows.append(
                [
                    appliance.get("name"),
                    roles(appliance),
                    appliance.get("siteName") or self.site_name(_text(appliance.get("site"))),
                    found.get("status") or self.nodes[node_id]["status"],
                    found.get("applianceVersion"),
                    found.get("numberOfSessions"),
                ]
            )
        _add(
            sections,
            table_section(
                "Appliances", ["Appliance", "Roles", "Site", "Status", "Version", "Sessions"], appliance_rows
            ),
        )
        site_rows = []
        for site in self.sites:
            raw_site = self.site_by_id[site["id"]]
            found = _dict(self.site_status_by_id.get(site["id"]))
            default = _dict(raw_site.get("defaultGateway"))
            overview = dict(next((s["rows"] for s in site["sections"] if s["title"] == "Site overview"), []))
            site_rows.append(
                [
                    site["name"],
                    found.get("status"),
                    len(self.gateways_of_site.get(site["id"], [])),
                    [c for c, _comment in site_subnets(raw_site)],
                    "Yes" if default.get("enabledV4") or default.get("enabledV6") else "No",
                    overview.get("Sessions", ""),
                ]
            )
        _add(
            sections,
            table_section(
                "Sites", ["Site", "Status", "Gateways", "Network subnets", "Default gateway", "Sessions"], site_rows
            ),
        )
        by_id = {_text(e.get("id")): e for e in self.entitlements}
        policy_rows = []
        for policy in self.policies:
            linked = {_text(t) for t in _list(policy.get("entitlementLinks"))}
            granted = [
                _text(by_id[_text(e)].get("name")) if _text(e) in by_id else _text(e)
                for e in _list(policy.get("entitlements"))
            ]
            granted += [
                _text(e.get("name"))
                for e in self.entitlements
                if linked & {_text(t) for t in _list(e.get("tags"))} and _text(e.get("name")) not in granted
            ]
            override = _text(policy.get("overrideSite"))
            expression = _text(policy.get("expression"))
            policy_rows.append(
                [
                    policy.get("name"),
                    policy.get("type"),
                    "disabled" if policy.get("disabled") else "enabled",
                    expression if len(expression) <= 200 else expression[:197] + "...",
                    granted,
                    self.site_name(override) if override else "",
                ]
            )
        _add(
            sections,
            table_section(
                "Policies", ["Policy", "Type", "Status", "Expression", "Entitlements", "Override site"], policy_rows
            ),
        )
        _add(
            sections,
            table_section(
                "Entitlements", ["Site", *ENTITLEMENT_COLUMNS], self.entitlement_rows(self.entitlements, with_site=True)
            ),
        )
        _add(
            sections,
            table_section(
                "Conditions",
                ["Condition", "Expression", "Remedy"],
                [
                    [
                        c.get("name"),
                        _text(c.get("expression"))[:200],
                        [m.get("type") for m in _dicts(c.get("remedyMethods"))],
                    ]
                    for c in sorted(self.conditions_by_id.values(), key=lambda c: _text(c.get("name")).lower())
                ],
            ),
        )
        _add(
            sections,
            table_section(
                "Ringfence rules",
                ["Rule", "Action", "Protocol", "Direction", "Hosts", "Ports"],
                [
                    [
                        rule.get("name"),
                        action.get("action"),
                        action.get("protocol"),
                        action.get("direction"),
                        action.get("hosts"),
                        action.get("ports") or action.get("types"),
                    ]
                    for rule in _dicts(self.raw.get("ringfence_rules"))
                    for action in _dicts(rule.get("actions"))
                ],
            ),
        )
        users_of_pool: dict[str, list[str]] = {}
        for provider in self.identity_providers:
            for key in ("ipPoolV4", "ipPoolV6"):
                if _text(provider.get(key)):
                    users_of_pool.setdefault(_text(provider[key]), []).append(_text(provider.get("name")))
        _add(
            sections,
            table_section(
                "IP pools",
                ["Pool", "Ranges", "Size", "In use", "Reserved", "Identity providers"],
                [
                    [
                        pool.get("name"),
                        [f"{_text(r.get('first'))}-{_text(r.get('last'))}" for r in _dicts(pool.get("ranges"))],
                        pool.get("total"),
                        pool.get("currentlyUsed"),
                        pool.get("reserved"),
                        users_of_pool.get(_text(pool.get("id")), []),
                    ]
                    for pool in self.ip_pools
                ],
            ),
        )
        _add(
            sections,
            table_section(
                "Identity providers",
                ["Provider", "Type", "IPv4 pool", "Admin provider", "Device limit"],
                [
                    [
                        provider.get("name"),
                        provider.get("type"),
                        self.pool_name(provider.get("ipPoolV4")) if provider.get("ipPoolV4") else "",
                        bool(provider.get("adminProvider")),
                        provider.get("deviceLimitPerUser"),
                    ]
                    for provider in self.identity_providers
                ],
            ),
        )
        # Every appliance is a peer of the collective: a management link
        # that carries no traffic.
        for node_id, appliance in self.appliance_of.items():
            status = "failed" if self.nodes[node_id]["status"] == "offline" else "active"
            label = "Appgate Controller" if is_controller(appliance) else "Appgate peer link"
            self._edge(node_id, COLLECTIVE_NODE_ID, "manage", label=label, status=status)

    def build_edge_sections(self) -> None:
        for edge in self.edges:
            a, b = self.nodes[edge["a"]], self.nodes[edge["b"]]
            rows: list[tuple[str, Any]] = [("A end", a["label"]), ("B end", b["label"])]
            tunnel = self._tunnel_of_edge.get(edge["id"])
            if tunnel is not None:
                record, gateway = tunnel
                entry = record["gateways"].get(gateway) or {}
                rows += [
                    ("Tunnel IP", record["tun_ip"]),
                    ("Site", entry.get("site")),
                    ("Connected since", _dict(entry.get("systemClaims")).get("connectTime")),
                ]
            rows += [("Status", edge.get("status")), ("Discovered via", SOURCE)]
            section = kv_section(edge.get("label") or "Link", rows)
            edge["sections"] = [section] if section else []


def build_snapshot(raw: dict, inventory: InventoryIndex | None = None) -> dict[str, Any]:
    """Build the positioned topology snapshot from raw collector output."""
    # Imported here: the forwarding module reads this one's helpers.
    from netcontrol.integrations.appgate.forwarding import build_forwarding

    builder = _Builder(raw, inventory or InventoryIndex())
    builder.build_appliances()
    builder.build_collective_node()
    builder.build_users()
    builder.appliance_sections()
    builder.build_sites()
    builder.build_collective()
    build_forwarding(builder)
    builder.build_edge_sections()

    collective_members = [n for n in builder.nodes.values() if n["site"] == COLLECTIVE_SITE_ID]
    sites = [
        *builder.sites,
        *builder.boxes,
        {
            "id": COLLECTIVE_SITE_ID,
            "name": "Appgate SDP",
            "tags": [],
            # Sorts the collective ahead of the sites, like a VPN hub.
            "vpn_mode": "hub",
            "status": _worst([n["status"] for n in collective_members]),
            "device_count": len(collective_members),
            "sections": [],
        },
    ]
    _layout(sites, builder.nodes, builder.edges)

    nodes = list(builder.nodes.values())
    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in nodes:
        if node["kind"] in CLOUD_KINDS:
            continue
        by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
        by_status[node["status"]] = by_status.get(node["status"], 0) + 1
    tunnels = sum(1 for e in builder.edges if e["kind"] == "vpn")

    collective = builder.collective
    controller = _text(collective.get("controller"))
    return {
        "schema": SCHEMA_VERSION,
        "provider": "appgate",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": {
            "id": _s(collective.get("collective_id") or controller),
            "name": collective.get("name") or "Appgate collective",
            "url": f"https://{controller}" if controller else "",
        },
        "summary": {
            "sites": len(builder.sites),
            "devices": sum(by_kind.values()),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": 0,
            "inventory_matches": sum(1 for n in nodes if n.get("inventory")),
            "lan_links": 0,
            "vpn_tunnels": tunnels,
            "wan_uplinks": 0,
            "vlans": builder.range_count,
            "remote_users": len(builder.users),
            "gateways": sum(len(g) for g in builder.gateways_of_site.values()),
            "entitlements": len(builder.entitlements),
        },
        "collection": {
            "sources": [SOURCE],
            "stats": raw.get("stats") or {},
            "errors": raw.get("errors") or [],
            "options": raw.get("options") or {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }
