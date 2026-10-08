"""Turn raw FMC payloads into a positioned topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), so the merge
into the Topology graph, node details, deep search, the subnet index, IPAM,
the HTML export and the software tracker need no FMC-specific code.

How an FMC maps onto the map:

  - the FMC itself is one node in a box of its own, joined to each device
    by a management link that Path Mode and the tidy-tree layout ignore
  - a standalone FTD is a box of its own; an HA pair is one box holding
    both members joined by an ``HA`` link (primary first); a cluster is one
    box with the control unit over its data units
  - each outside interface of a device (a public address, the egress of
    the default route, or a remote access VPN access interface) is a WAN
    stub over the device, carrying the interface's own address
  - a device that terminates remote access VPN gets the policy's sections
    on its box, its address pools as subnets and one "AnyConnect users"
    node with the connected users listed behind it (one node per user would
    bury the map)
  - site-to-site VPN topologies are tunnels between the FTDs they join
    (the primary member for an HA pair) and IPsec links to an extranet
    peer, a node shared by every topology that names it
  - interfaces, connected subnets, routing, NAT, access control, VPN and
    health are detail sections of each device; the objects, zones and
    policies of the FMC are detail sections of the FMC node

How an FTD joins the rest of the map: a Plexus inventory host matching its
serial, management or interface address becomes the device; an FTDv in
AWS is matched to its instance by the private address of an outside
interface, like a Meraki vMX behind a NAT gateway; and the addresses its
site-to-site VPN endpoints use (``endpoint_ips``) make the far end another
integration draws (an AWS customer gateway, a Meraki non-Meraki peer)
collapse into it. A device never carries ``alias_ips``: that marks a cloud
instance.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from itertools import combinations
from typing import Any

from netcontrol.integrations.fmc.collector import (
    ACCESS_POLICY_TYPES,
    DEFAULT_OPTIONS,
    MAX_ACCESS_RULES,
    NAT_POLICY_TYPES,
    PREFILTER_POLICY_TYPES,
    RA_VPN_POLICY_TYPES,
    TargetResolver,
    assigned_devices,
    cluster_members,
    ha_members,
    is_ra_vpn_policy,
)
from netcontrol.integrations.meraki.normalize import (
    SCHEMA_VERSION,
    VPN_PEER_SITE_ID,
    InventoryIndex,
    _add,
    _inventory_ref,
    _is_ip,
    _layout,
    _s,
    _worst,
    kv_section,
    table_section,
    text_section,
)

FMC_SITE_ID = "__fmc__"
FMC_NODE_ID = "fmc"

# Kinds that stand for the management plane rather than devices at a site.
MANAGEMENT_KINDS = ("cloud",)

POOL_SECTION_TITLE = "VPN address pools"
POOL_COLUMNS = ["Subnet", "Pool", "Range", "Connection profiles"]
INTERFACES_SECTION_TITLE = "FTD interfaces"
CONNECTED_SECTION_TITLE = "Connected subnets"
STATIC_ROUTES_SECTION_TITLE = "Static routes"

MAX_LISTED_SESSIONS = 5000
MAX_LISTED_OBJECTS = 2000
MAX_LISTED_GROUPS = 500
_MAX_GROUP_DEPTH = 6

_HEALTH = {
    "green": "online",
    "normal": "online",
    "recovered": "online",
    "yellow": "alerting",
    "warning": "alerting",
    "red": "offline",
    "critical": "offline",
    "error": "offline",
    "disabled": "dormant",
}

_INTERFACE_TYPES = {
    "physicalinterface": "Physical",
    "subinterface": "Sub-interface",
    "etherchannelinterface": "EtherChannel",
    "redundantinterface": "Redundant",
    "vlaninterface": "VLAN",
    "vtiinterface": "VTI",
    "virtualtunnelinterface": "VTI",
    "loopbackinterface": "Loopback",
    "bridgegroupinterface": "Bridge group",
    "inlineset": "Inline set",
}

_TOPOLOGY_TYPES = {
    "pointtopoint": "Point to point",
    "hubandspoke": "Hub and spoke",
    "fullmesh": "Full mesh",
}

_PROTOCOLS = {"1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP", "58": "ICMPv6"}

_TUNNEL_EDGE_STATUS = {"up": "reachable", "down": "unreachable"}

# Documentation ranges (RFC 5737, RFC 3849) stand in for public addresses in
# examples, labs and the bundled demo, so an interface in one is drawn as
# outside like any public one.
_DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _name(value: Any) -> str:
    """A reference's display name: ``{"name": ...}`` objects, or the text."""
    if isinstance(value, dict):
        return _text(value.get("name") or value.get("ifname") or value.get("id"))
    if isinstance(value, list):
        return ", ".join(n for n in (_name(v) for v in value) if n)
    return _text(value)


def _ident(value: Any) -> str:
    if isinstance(value, dict):
        return _text(value.get("id") or value.get("uuid"))
    return _text(value)


def _first(item: dict, *keys: str) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _dict(value: Any) -> dict[str, Any]:
    """``value`` when it is an object, else an empty one."""
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> list[dict]:
    return [i for i in value if isinstance(i, dict)] if isinstance(value, list) else []


def _kind(value: Any) -> str:
    return str(value or "").lower().replace("_", "").replace("-", "").replace(" ", "")


def _health(raw: Any) -> str:
    return _HEALTH.get(_text(raw).lower(), "unknown")


def _yes(value: Any) -> str:
    return "Yes" if value else "No"


def _is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_global or any(parsed in net for net in _DOCUMENTATION_NETS if net.version == parsed.version)


def is_virtual_model(model: Any) -> bool:
    """A virtual firewall model (FTDv, "Threat Defense for AWS", vMX...)."""
    lowered = _text(model).lower()
    return lowered.startswith("vmx") or any(t in lowered for t in ("ftdv", "threat defense for", "virtual"))


def _covering_network(first: str, last: str) -> str:
    """The smallest network that holds the range ``first``-``last``."""
    try:
        start, end = ipaddress.ip_address(first), ipaddress.ip_address(last if _is_ip(last) else first)
    except ValueError:
        return ""
    if start.version != end.version:
        return ""
    if int(end) < int(start):
        start, end = end, start
    for prefix in range(start.max_prefixlen, -1, -1):
        network = ipaddress.ip_network(f"{start}/{prefix}", strict=False)
        if end in network:
            return str(network)
    return ""


def pool_cidr(pool: dict) -> str:
    """The network of an FMC IPv4 address pool: its range under its mask, or
    the smallest network that holds the range when no mask is given."""
    rng = _text(pool.get("ipAddressRange") or pool.get("range"))
    first, _sep, last = rng.partition("-")
    first, last = first.strip(), (last or first).strip()
    if not _is_ip(first):
        return ""
    mask = _text(pool.get("mask") or pool.get("netmask"))
    if mask:
        try:
            return str(ipaddress.ip_network(f"{first}/{mask}", strict=False))
        except ValueError:
            pass
    return _covering_network(first, last)


def value_cidr(value: Any) -> str:
    """The network an object or literal value stands for: a host as /32 (or
    /128), a network as itself, a range as the smallest covering network;
    ``""`` for anything else (an FQDN, "any")."""
    text = _text(value)
    if not text:
        return ""
    if "-" in text and "/" not in text:
        first, _sep, last = text.partition("-")
        return _covering_network(first.strip(), last.strip())
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return ""


def _interface_cidr(address: str, mask: str) -> str:
    if not address or not mask:
        return ""
    try:
        return str(ipaddress.ip_network(f"{address}/{mask}", strict=False))
    except ValueError:
        return ""


class _Objects:
    """Network objects, groups and zones by id and by name, so the
    references in routes, NAT rules, VPN endpoints and policies resolve to
    names and networks."""

    KINDS = (
        ("networks", "Network"),
        ("hosts", "Host"),
        ("ranges", "Range"),
        ("fqdns", "FQDN"),
        ("groups", "Network group"),
    )

    def __init__(self, raw: Any) -> None:
        objects = _dict(raw)
        self.by_kind: dict[str, list[dict]] = {key: _dicts(objects.get(key)) for key, _label in self.KINDS}
        self.zones = _dicts(objects.get("zones"))
        self.interface_groups = _dicts(objects.get("interface_groups"))
        self.by_id: dict[str, dict] = {}
        self.by_name: dict[str, dict] = {}
        self.label: dict[int, str] = {}
        for key, label in self.KINDS:
            for item in self.by_kind[key]:
                self.label[id(item)] = label
                if _ident(item):
                    self.by_id.setdefault(_ident(item), item)
                if _text(item.get("name")):
                    self.by_name.setdefault(_text(item.get("name")).lower(), item)
        self.zone_by_id = {_ident(z): z for z in self.zones if _ident(z)}

    def count(self) -> int:
        return sum(len(items) for items in self.by_kind.values())

    def get(self, ref: Any) -> dict | None:
        if not isinstance(ref, dict):
            return self.by_name.get(_text(ref).lower()) if _text(ref) else None
        return self.by_id.get(_ident(ref)) or self.by_name.get(_text(ref.get("name")).lower())

    def kind_of(self, item: dict) -> str:
        if id(item) in self.label:
            return self.label[id(item)]
        kind = _kind(item.get("type"))
        if kind in ("networkgroup", "group"):
            return "Network group"
        return {"host": "Host", "network": "Network", "range": "Range", "fqdn": "FQDN"}.get(kind, "")

    def value(self, ref: Any) -> str:
        """The address an object stands for (``value``), when known."""
        found = self.get(ref)
        item = found or _dict(ref)
        return _text(item.get("value"))

    def describe(self, ref: Any) -> str:
        """An object reference as "name (value)", or just the name/value."""
        name, value = _name(ref), self.value(ref)
        if name and value and value != name:
            return f"{name} ({value})"
        return name or value

    def expand(self, ref: Any, depth: int = 0) -> list[tuple[str, str]]:
        """``(name, cidr)`` for every network a reference stands for: one
        entry for a host, network, range or FQDN (blank cidr), one per
        member for a group (``"group / member"``)."""
        item = self.get(ref) or _dict(ref)
        if not item and isinstance(ref, str):
            return [(ref, value_cidr(ref))]
        name = _text(item.get("name")) or _text(item.get("value"))
        members = _dicts(item.get("objects")) + _dicts(item.get("literals"))
        if self.kind_of(item) == "Network group" or (members and not item.get("value")):
            if depth >= _MAX_GROUP_DEPTH:
                return []
            rows: list[tuple[str, str]] = []
            for member in members:
                for member_name, cidr in self.expand(member, depth + 1):
                    rows.append((f"{name} / {member_name}" if name else member_name, cidr))
            return rows
        if self.kind_of(item) == "FQDN":
            return [(_text(item.get("value")) or name, "")]
        return [(name, value_cidr(item.get("value")))]

    def names(self, block: Any) -> str:
        """Names in a ``{"objects": [...], "literals": [...]}`` block (or a
        list of references): objects by name, literals by value."""
        if isinstance(block, list):
            return ", ".join(n for n in (self._one(b) for b in block) if n)
        block = _dict(block)
        if not block:
            return ""
        if "objects" in block or "literals" in block or "networks" in block:
            refs = _dicts(block.get("objects")) + _dicts(block.get("networks")) + _dicts(block.get("literals"))
            return ", ".join(n for n in (self._one(r) for r in refs) if n)
        return self._one(block)

    @staticmethod
    def _one(ref: Any) -> str:
        if not isinstance(ref, dict):
            return _text(ref)
        if _text(ref.get("name")):
            return _text(ref["name"])
        if "port" in ref or "protocol" in ref or "icmpType" in ref:
            protocol = _PROTOCOLS.get(_text(ref.get("protocol")), _text(ref.get("protocol")))
            port = _text(ref.get("port") or ref.get("icmpType"))
            return f"{protocol}/{port}" if protocol and port else protocol or port
        return _text(ref.get("value") or ref.get("url") or ref.get("id"))


def _ha_state(pair: dict, role: str) -> str:
    """The failover state of a pair member ("Active", "Standby"...), read
    from the several shapes FMC releases answer with."""
    meta = _dict(pair.get("metadata"))
    key = f"{role}Status"
    for holder in (meta.get(key), pair.get(key)):
        holder = _dict(holder)
        state = _first(holder, "currentStatus", "status", "state", "haState")
        if state:
            return _text(state)
    flat = _first(meta, f"{role}State", f"{role}HAState")
    return _text(flat)


def _failover_link(pair: dict) -> str:
    bootstrap = _dict(pair.get("ftdHABootstrap") or pair.get("haBootstrap"))
    link = _dict(bootstrap.get("lanFailover"))
    return _text(link.get("logicalName")) or _name(link.get("interfaceObject")) or _name(link.get("interface"))


class _Builder:
    def __init__(self, raw: dict, inventory: InventoryIndex) -> None:
        self.raw = raw
        self.inventory = inventory
        self.options = _dict(raw.get("options"))
        self.devices = [d for d in raw.get("devices") or [] if isinstance(d, dict) and d.get("id")]
        self.device_by_id = {_text(d["id"]): d for d in self.devices}
        self.ha_pairs = [p for p in _dicts(raw.get("ha_pairs")) if _ident(p) or _text(p.get("name"))]
        self.clusters = [c for c in _dicts(raw.get("clusters")) if _ident(c) or _text(c.get("name"))]
        self.resolver = TargetResolver(self.devices, self.ha_pairs, self.clusters)
        self.ha_monitored = _dict(raw.get("ha_monitored"))
        self.objects = _Objects(raw.get("objects"))
        self.assignments = _dicts(raw.get("assignments"))

        self.policies = [
            p
            for p in raw.get("policies") or []
            if isinstance(p, dict) and p.get("id") and (is_ra_vpn_policy(p) or not p.get("type"))
        ]
        self.policy_by_id = {_text(p["id"]): p for p in self.policies}
        self.details = _dict(raw.get("policy_details"))
        self.pools = [p for p in raw.get("pools") or [] if isinstance(p, dict)]
        self.pool_by_id = {_text(p.get("id")): p for p in self.pools if p.get("id")}
        self.pool_by_name = {_text(p.get("name")).lower(): p for p in self.pools if p.get("name")}
        self.interfaces = _dict(raw.get("interfaces"))
        self.routing = _dict(raw.get("routing"))
        sessions = raw.get("sessions")
        self.sessions_collected = isinstance(sessions, list)
        self.sessions = [s for s in sessions or [] if isinstance(s, dict)]

        self.nat_policies = [p for p in _dicts(raw.get("nat_policies")) if p.get("id")]
        self.nat_rules = _dict(raw.get("nat_rules"))
        self.access_policies = [p for p in _dicts(raw.get("access_policies")) if p.get("id")]
        self.access_rules = _dict(raw.get("access_rules"))
        self.access_rule_counts = _dict(raw.get("access_rule_counts"))
        self.prefilter_policies = _dicts(raw.get("prefilter_policies"))
        self.s2s_vpns = [t for t in _dicts(raw.get("s2s_vpns")) if t.get("id") or t.get("name")]
        self.s2s_details = _dict(raw.get("s2s_details"))
        status = raw.get("tunnel_status")
        self.tunnel_status = _dicts(status)
        alerts = raw.get("health_alerts")
        self.alerts = _dicts(alerts)
        deployable = raw.get("deployable")
        self.deployable_collected = isinstance(deployable, list)
        self.deployable = _dicts(deployable)
        self.unsupported = [_text(p) for p in raw.get("unsupported") or [] if _text(p)]

        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.sites: list[dict] = []
        self.pool_count = 0
        self.connected_count = 0

        # Membership: device id -> its HA pair / cluster, and the role in it.
        self.pair_of: dict[str, dict] = {}
        self.ha_role: dict[str, str] = {}
        for pair in self.ha_pairs:
            for index, member in enumerate(self.resolver.containers.get(_ident(pair), [])):
                self.pair_of[member] = pair
                self.ha_role[member] = "primary" if index == 0 else "secondary"
        self.cluster_of: dict[str, dict] = {}
        self.cluster_role: dict[str, str] = {}
        for cluster in self.clusters:
            for index, member in enumerate(self.resolver.containers.get(_ident(cluster), [])):
                self.cluster_of[member] = cluster
                self.cluster_role[member] = "control" if index == 0 else "data"

        # device id -> the remote access VPN policy assigned to it, and
        # policy id -> names of the devices it is assigned to.
        self.device_policy: dict[str, dict] = {}
        self.policy_devices: dict[str, list[str]] = {}
        self._map_ra_policies()
        self.device_nat = self._map_policies(self.nat_policies, NAT_POLICY_TYPES)
        self.device_acp = self._map_policies(self.access_policies, ACCESS_POLICY_TYPES)
        for device in self.devices:
            # A device record names its access policy even when no assignment does.
            ref = _dict(device.get("accessPolicy"))
            if _text(device["id"]) not in self.device_acp and ref:
                found = next((p for p in self.access_policies if _ident(p) == _ident(ref)), None)
                self.device_acp[_text(device["id"])] = found or ref
        self.device_prefilter = self._map_policies(self.prefilter_policies, PREFILTER_POLICY_TYPES)
        self.device_sessions: dict[str, list[dict]] = {}
        self._map_sessions()
        self.device_alerts: dict[str, list[dict]] = {}
        self._map_by_device(self.alerts, self.device_alerts)
        self.device_deployable: dict[str, list[dict]] = {}
        self._map_by_device(self.deployable, self.device_deployable)

        # Filled while drawing.
        self.rows: dict[str, list[dict[str, Any]]] = {}
        self.s2s_rows: dict[str, list[list[Any]]] = {}
        self.s2s_names: dict[str, list[str]] = {}
        self.endpoint_ips: dict[str, list[str]] = {}
        self.s2s_summary: dict[str, dict[str, Any]] = {}

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

    def _device_name(self, device_id: str) -> str:
        return _text(self.device_by_id.get(device_id, {}).get("name")) or device_id

    # ── Policy, session, alert mapping ─────────────────────────────────────

    def _map_ra_policies(self) -> None:
        targets = assigned_devices(self.assignments, RA_VPN_POLICY_TYPES, self.resolver, self.policies)
        for policy_id, device_ids in targets.items():
            policy = self.policy_by_id.get(policy_id)
            if policy is None:
                ref = next(
                    (
                        _dict(a.get("policy"))
                        for a in self.assignments
                        if is_ra_vpn_policy(a.get("policy")) and _ident(a.get("policy")) == policy_id
                    ),
                    {},
                )
                policy = {"id": policy_id, "name": _name(ref), "type": "RAVpn"}
            for device_id in device_ids:
                self.device_policy.setdefault(device_id, policy)
                names = self.policy_devices.setdefault(policy_id, [])
                if self._device_name(device_id) not in names:
                    names.append(self._device_name(device_id))

    def _map_policies(self, policies: list[dict], types: tuple[str, ...]) -> dict[str, dict]:
        """device id -> the policy of ``types`` assigned to it."""
        by_id = {_ident(p): p for p in policies}
        found: dict[str, dict] = {}
        for policy_id, device_ids in assigned_devices(self.assignments, types, self.resolver, policies).items():
            policy = by_id.get(policy_id)
            if policy is None:
                ref = next(
                    (
                        _dict(a.get("policy"))
                        for a in self.assignments
                        if _ident(a.get("policy")) == policy_id and _kind(_dict(a.get("policy")).get("type")) in types
                    ),
                    {"id": policy_id},
                )
                policy = ref
            for device_id in device_ids:
                found.setdefault(device_id, policy)
        return found

    def _device_of(
        self, item: dict, *ref_keys: str, id_keys: tuple[str, ...] = (), name_keys: tuple[str, ...] = ()
    ) -> str:
        """The device an item (a session, an alert...) belongs to."""
        ids = set(self.device_by_id)
        by_name = {_text(d.get("name")).lower(): _text(d["id"]) for d in self.devices}
        for key in ref_keys:
            ref = item.get(key)
            if _ident(ref) in ids:
                return _ident(ref)
            if _name(ref).lower() in by_name:
                return by_name[_name(ref).lower()]
        for key in id_keys:
            if _text(item.get(key)) in ids:
                return _text(item.get(key))
        for key in name_keys:
            if _text(item.get(key)).lower() in by_name:
                return by_name[_text(item.get(key)).lower()]
        return ""

    def _map_sessions(self) -> None:
        for session in self.sessions:
            device_id = self._device_of(
                session,
                "device",
                id_keys=("deviceId", "deviceUUID", "deviceUuid"),
                name_keys=("deviceName", "hostName", "hostname", "firewall"),
            )
            if device_id:
                self.device_sessions.setdefault(device_id, []).append(session)

    def _map_by_device(self, items: list[dict], into: dict[str, list[dict]]) -> None:
        for item in items:
            device_id = self._device_of(
                item,
                "device",
                "deviceInfo",
                id_keys=("deviceUUID", "deviceUuid", "deviceId"),
                name_keys=("deviceName", "name", "hostName"),
            )
            if device_id:
                into.setdefault(device_id, []).append(item)

    def _pending(self, device_id: str) -> list[dict]:
        return [d for d in self.device_deployable.get(device_id, []) if d.get("upToDate") is not True]

    # ── Interfaces ─────────────────────────────────────────────────────────

    def _vr_of(self, device_id: str) -> dict[str, str]:
        """interface id / name / logical name (lower-case) -> virtual router."""
        found: dict[str, str] = {}
        for router in _dicts(_dict(self.routing.get(device_id)).get("virtual_routers")):
            name = _text(router.get("name"))
            for ref in _dicts(router.get("interfaces")):
                for key in (_ident(ref), _text(ref.get("name")), _text(ref.get("ifname"))):
                    if key:
                        found.setdefault(key.lower(), name)
        return found

    def _interface_rows(self, device_id: str) -> list[dict[str, Any]]:
        vr_of = self._vr_of(device_id)
        has_vrs = bool(vr_of)
        rows: list[dict[str, Any]] = []
        for iface in self.interfaces.get(device_id) or []:
            if not isinstance(iface, dict):
                continue
            ipv4 = _dict(iface.get("ipv4"))
            static = _dict(ipv4.get("static"))
            address = _text(static.get("address"))
            mask = _text(static.get("netmask") or static.get("mask"))
            if not address:
                address = _text(_dict(ipv4.get("dhcp")).get("address") or _dict(ipv4.get("pppoe")).get("address"))
            zone = _dict(iface.get("securityZone"))
            zone_name = _text(zone.get("name")) or _text(self.objects.zone_by_id.get(_ident(zone), {}).get("name"))
            kind = _INTERFACE_TYPES.get(_kind(iface.get("type")), _text(iface.get("type")))
            name = _text(iface.get("name"))
            if kind == "EtherChannel" and not name and iface.get("etherChannelId") not in (None, ""):
                name = f"Port-channel{iface.get('etherChannelId')}"
            if iface.get("vlanId") not in (None, "") and kind in ("Sub-interface", "") and "." not in name:
                name = f"{name}.{iface.get('subIntfId') or iface.get('vlanId')}"
            ifname = _text(iface.get("ifname"))
            ipv6: list[tuple[str, str]] = []
            for entry in _dicts(_dict(iface.get("ipv6")).get("addresses")):
                v6 = _text(entry.get("address"))
                if _is_ip(v6):
                    ipv6.append((v6, _interface_cidr(v6, _text(entry.get("prefix") or entry.get("prefixLength")))))
            description = _text(iface.get("description"))
            if kind == "VTI" and not description:
                source = _name(iface.get("tunnelSource"))
                peer = _text(_first(iface, "tunnelDestination", "tunnelDest", "peerIP", "remoteIp"))
                parts = [f"Tunnel source {source}" if source else "", f"peer {peer}" if peer else ""]
                borrowed = _name(iface.get("borrowIPfrom"))
                if borrowed:
                    parts.append(f"unnumbered from {borrowed}")
                description = ", ".join(p for p in parts if p)
            vr = ""
            for key in (_ident(iface), ifname, name):
                if key and key.lower() in vr_of:
                    vr = vr_of[key.lower()]
                    break
            if not vr and has_vrs and (address or ifname):
                vr = "Global"
            rows.append(
                {
                    "id": _ident(iface),
                    "name": name,
                    "ifname": ifname,
                    "type": kind,
                    "zone_id": _ident(zone),
                    "zone": zone_name,
                    "vr": vr,
                    "ip": address if _is_ip(address) else "",
                    "cidr": _interface_cidr(address, mask) if _is_ip(address) else "",
                    "mask": mask,
                    "ipv6": ipv6,
                    "enabled": bool(iface.get("enabled", True)),
                    "mode": _text(iface.get("mode")),
                    "mtu": _text(iface.get("MTU") or iface.get("mtu")),
                    "description": description,
                    "management_only": bool(iface.get("managementOnly")),
                }
            )
        pair = self.pair_of.get(device_id)
        if pair is not None and self.ha_role.get(device_id) == "secondary":
            self._standby(rows, pair)
        return rows

    def _standby(self, rows: list[dict[str, Any]], pair: dict) -> None:
        """A secondary's rows that carry the pair's active address take the
        standby address of the monitored interface (both members share one
        configuration; the standby unit answers on the standby address)."""
        monitored = {
            _text(m.get("name") or m.get("ifname")).lower(): _dict(m.get("ipv4Configuration"))
            for m in _dicts(self.ha_monitored.get(_ident(pair)))
        }
        for row in rows:
            config = monitored.get(row["ifname"].lower()) or monitored.get(row["name"].lower())
            if not config:
                continue
            standby = _text(config.get("standbyIPv4Address") or config.get("standbyIPAddress"))
            active = _text(config.get("activeIPv4Address") or config.get("activeIPAddress"))
            if _is_ip(standby) and (not active or not row["ip"] or row["ip"] == active):
                row["ip"] = standby
                mask = row["mask"] or _text(config.get("activeIPv4Mask") or config.get("mask"))
                row["cidr"] = _interface_cidr(standby, mask)

    @staticmethod
    def _find_interface(rows: list[dict[str, Any]], ref: Any) -> dict[str, Any] | None:
        wanted_id, wanted = _ident(ref), _name(ref).lower()
        for row in rows:
            if wanted_id and row["id"] == wanted_id:
                return row
        for row in rows:
            if wanted and wanted in (row["ifname"].lower(), row["name"].lower(), row["zone"].lower()):
                return row
        return None

    # ── Routing ────────────────────────────────────────────────────────────

    def _route_list(self, device_id: str, key: str) -> list[dict]:
        return _dicts(_dict(self.routing.get(device_id)).get(key))

    def _gateway(self, route: dict) -> str:
        gateway = route.get("gateway")
        if not isinstance(gateway, dict):
            return _text(gateway)
        literal = _dict(gateway.get("literal"))
        if literal:
            return _text(literal.get("value"))
        ref = gateway.get("object")
        if ref:
            return self.objects.describe(ref)
        return _text(gateway.get("value")) or _name(gateway)

    def _static_rows(self, device_id: str) -> list[list[Any]]:
        rows: list[list[Any]] = []
        for route in self._route_list(device_id, "static_v4") + self._route_list(device_id, "static_v6"):
            refs = route.get("selectedNetworks") or route.get("networks") or []
            tracking = route.get("routeTracking")
            for ref in refs if isinstance(refs, list) else [refs]:
                for destination, cidr in self.objects.expand(ref) or [(_name(ref), "")]:
                    rows.append(
                        [
                            destination,
                            cidr,
                            _text(route.get("interfaceName")) or _name(route.get("interface")),
                            self._gateway(route),
                            _text(_first(route, "metricValue", "metric")),
                            _text(route.get("vr")),
                            _yes(route.get("isTunneled")),
                            _name(tracking) if tracking else "No",
                        ]
                    )
        return rows

    def _default_egress(self, device_id: str) -> dict[str, str]:
        """Logical name (lower-case) of each egress interface of an IPv4
        default route -> its gateway."""
        found: dict[str, str] = {}
        for row in self._static_rows(device_id):
            if row[1] == "0.0.0.0/0" and row[2]:
                found.setdefault(row[2].lower(), row[3])
        return found

    def _routing_sections(self, device_id: str, rows: list[dict[str, Any]], sections: list[dict]) -> list[str]:
        """Static routes, virtual routers and dynamic routing. Returns the
        virtual router names."""
        statics = self._static_rows(device_id)
        _add(
            sections,
            table_section(
                STATIC_ROUTES_SECTION_TITLE,
                ["Destination", "Subnet", "Interface", "Gateway", "Metric", "Virtual router", "Tunneled", "Tracked"],
                statics,
            ),
        )
        routers = self._route_list(device_id, "virtual_routers")
        named = {_text(r.get("name")) for r in routers if _text(r.get("name"))}
        for key in ("static_v4", "static_v6", "bgp", "ospf", "eigrp", "ecmp"):
            named.update(_text(i.get("vr")) for i in self._route_list(device_id, key) if _text(i.get("vr")))
        vr_names = sorted(named, key=lambda n: (n.lower() != "global", n.lower()))
        if any(n.lower() != "global" for n in vr_names):
            vr_rows: list[list[Any]] = []
            listed = {_text(r.get("name")).lower(): r for r in routers}
            for vr_name in vr_names:
                router = listed.get(vr_name.lower(), {})
                members = [r for r in rows if r["vr"] == vr_name and (r["ifname"] or r["ip"])]
                vr_rows.append(
                    [
                        vr_name,
                        ", ".join(r["ifname"] or r["name"] for r in members)
                        or ", ".join(_name(i) for i in _dicts(router.get("interfaces"))),
                        router.get("description"),
                    ]
                )
            _add(sections, table_section("Virtual routers", ["Name", "Interfaces", "Description"], vr_rows))

        neighbor_rows: list[list[Any]] = []
        for bgp in self._route_list(device_id, "bgp"):
            family = _dict(bgp.get("addressFamilyIPv4") or bgp.get("ipv4AddressFamily"))
            general = _dict(bgp.get("generalSettings") or bgp.get("bgpGeneralSettings"))
            networks = [
                self.objects.describe(_first(n, "ipv4Address", "network", "networkObject") or n)
                for n in _dicts(family.get("networks"))
            ]
            redistributes = [
                _text(_first(r, "type", "protocol", "redistributeProtocol")).removeprefix("Redistribute")
                for r in _dicts(family.get("redistributeProtocols"))
            ]
            router_id = _first(bgp, "routerId", "routerID") or _first(general, "routerId", "routerID")
            restart = _first(bgp, "gracefulRestart") or _first(general, "gracefulRestart")
            _add(
                sections,
                kv_section(
                    "BGP",
                    [
                        ("AS number", _first(bgp, "asNumber", "asn") or _first(general, "asNumber")),
                        ("Router ID", _name(router_id) if isinstance(router_id, dict) else router_id),
                        ("Virtual router", bgp.get("vr")),
                        ("Networks advertised", ", ".join(n for n in networks if n)),
                        ("Redistributes", ", ".join(r for r in redistributes if r)),
                        ("Graceful restart", _name(restart) if isinstance(restart, dict) else restart),
                    ],
                ),
            )
            for neighbor in _dicts(family.get("neighbors")):
                general_n = _dict(neighbor.get("neighborGeneral"))
                advanced = _dict(neighbor.get("neighborAdvanced"))
                enabled = _first(general_n, "enableAddress", "enabled")
                if enabled is None:
                    enabled = neighbor.get("enabled", True)
                neighbor_rows.append(
                    [
                        _text(_first(neighbor, "ipv4Address", "address", "neighborAddress")),
                        _text(_first(neighbor, "remoteAs", "remoteAS")),
                        _text(_first(neighbor, "description") or _first(general_n, "description")),
                        _text(bgp.get("vr")),
                        _name(
                            _first(neighbor, "updateSource", "neighborUpdateSource")
                            or _first(advanced, "neighborUpdateSource", "updateSource")
                        ),
                        _yes(enabled),
                    ]
                )
        _add(
            sections,
            table_section(
                "BGP neighbors",
                ["Neighbor", "Remote AS", "Description", "Virtual router", "Update source", "Enabled"],
                neighbor_rows,
            ),
        )

        area_rows: list[list[Any]] = []
        for ospf in self._route_list(device_id, "ospf"):
            process = _dict(ospf.get("processConfiguration"))
            router_id = _first(ospf, "routerId") or _first(process, "routerId")
            if isinstance(router_id, dict):
                router_id = _first(router_id, "ipAddress", "value", "type")
            _add(
                sections,
                kv_section(
                    "OSPF",
                    [
                        ("Process ID", _first(ospf, "processId", "processID") or _first(process, "processId")),
                        ("Router ID", router_id),
                        ("Virtual router", ospf.get("vr")),
                    ],
                ),
            )
            for area in _dicts(ospf.get("areas")):
                area_type = area.get("areaType")
                area_rows.append(
                    [
                        _text(_first(area, "areaId", "id", "name")),
                        _text(_first(area_type, "type", "name")) if isinstance(area_type, dict) else _text(area_type),
                        ", ".join(
                            self.objects.describe(n) for n in _dicts(area.get("areaNetworks") or area.get("networks"))
                        ),
                    ]
                )
        _add(sections, table_section("OSPF areas", ["Area", "Type", "Networks"], area_rows))

        for eigrp in self._route_list(device_id, "eigrp"):
            networks = eigrp.get("networks") or eigrp.get("eigrpNetworks") or []
            _add(
                sections,
                kv_section(
                    "EIGRP",
                    [
                        ("AS number", _first(eigrp, "asNumber", "asn", "autonomousSystem")),
                        ("Networks", ", ".join(self.objects.describe(n) for n in _dicts(networks))),
                        ("Virtual router", eigrp.get("vr")),
                    ],
                ),
            )

        pbr_rows: list[list[Any]] = []
        for pbr in self._route_list(device_id, "pbr"):
            ingress = _name(_first(pbr, "ingressInterfaces", "ingressInterface"))
            actions = _dicts(pbr.get("forwardingActions")) or [pbr]
            for index, action in enumerate(actions, start=1):
                pbr_rows.append(
                    [
                        ingress,
                        _name(_first(action, "matchCriteriaAccessList", "matchCriteria", "accessList")),
                        _name(_first(action, "egressInterfaces", "egressInterface", "defaultInterface"))
                        or _text(action.get("forwardingAction")),
                        _text(_first(action, "sequence", "order")) or index,
                    ]
                )
        _add(
            sections,
            table_section(
                "Policy-based routes", ["Ingress interface", "Match (ACL)", "Egress interfaces", "Order"], pbr_rows
            ),
        )

        _add(
            sections,
            table_section(
                "ECMP zones",
                ["Zone", "Interfaces", "Virtual router"],
                [
                    [_text(z.get("name")), _name(z.get("interfaces")), _text(z.get("vr"))]
                    for z in self._route_list(device_id, "ecmp")
                ],
            ),
        )
        return vr_names

    # ── NAT and access control ─────────────────────────────────────────────

    def _nat_rows(self, policy: dict | None) -> list[list[Any]]:
        if not policy:
            return []
        rules = _dicts(self.nat_rules.get(_ident(policy)))
        names = self.objects.names
        before: list[list[Any]] = []
        auto: list[list[Any]] = []
        after: list[list[Any]] = []
        for rule in rules:
            meta = _dict(rule.get("metadata"))
            is_auto = "auto" in _kind(rule.get("type")) and "manual" not in _kind(rule.get("type"))
            section = _kind(_first(meta, "section") or rule.get("section"))
            translated_source = rule.get("translatedSource") or rule.get("translatedNetwork")
            if not translated_source and rule.get(
                "interfaceInTranslatedNetwork", rule.get("interfaceInTranslatedSource")
            ):
                translated_source = "Destination interface IP"
            protocol = _text(rule.get("serviceProtocol"))
            original_service = names(rule.get("originalSourcePort") or rule.get("originalPort")) or (
                f"{protocol}/{_text(rule.get('originalPort'))}" if protocol and rule.get("originalPort") else ""
            )
            translated_service = names(rule.get("translatedSourcePort") or rule.get("translatedPort")) or (
                f"{protocol}/{_text(rule.get('translatedPort'))}" if protocol and rule.get("translatedPort") else ""
            )
            row = [
                "Auto" if is_auto else "Manual",
                "Auto NAT" if is_auto else ("After auto" if "after" in section else "Before auto"),
                names(rule.get("originalSource") or rule.get("originalNetwork")),
                names(rule.get("originalDestination")),
                translated_source if isinstance(translated_source, str) else names(translated_source),
                names(rule.get("translatedDestination")),
                _name(rule.get("sourceInterface")) or "any",
                _name(rule.get("destinationInterface")) or "any",
                original_service or names(rule.get("originalDestinationPort")),
                translated_service or names(rule.get("translatedDestinationPort")),
                _yes(rule.get("enabled", True)),
                _text(rule.get("description")) or _text(rule.get("natType")),
            ]
            (auto if is_auto else after if "after" in section else before).append(row)
        return [[index, *row] for index, row in enumerate(before + auto + after, start=1)]

    def _access_sections(self, device_id: str, sections: list[dict]) -> None:
        policy = self.device_acp.get(device_id)
        if not policy:
            return
        pid = _ident(policy)
        full = next((p for p in self.access_policies if _ident(p) == pid), policy)
        rules = _dicts(self.access_rules.get(pid))[:MAX_ACCESS_RULES]
        try:
            total = int(self.access_rule_counts.get(pid) or len(rules))
        except TypeError, ValueError:
            total = len(rules)
        default = _dict(full.get("defaultAction"))
        logging = [
            label
            for label, on in (
                ("begin", default.get("logBegin")),
                ("end", default.get("logEnd")),
                ("FMC", default.get("sendEventsToFMC")),
            )
            if on
        ]
        prefilter = self.device_prefilter.get(device_id) or _dict(full.get("prefilterPolicySetting"))
        _add(
            sections,
            kv_section(
                "Access control",
                [
                    ("Policy", _name(full)),
                    ("Default action", _text(default.get("action"))),
                    ("Rules", total if pid in self.access_rules or pid in self.access_rule_counts else "not collected"),
                    ("Prefilter policy", _name(prefilter)),
                    ("Logging", ", ".join(logging) or ("none" if default else "")),
                    ("Description", full.get("description")),
                ],
            ),
        )
        names = self.objects.names
        rows: list[list[Any]] = []
        for index, rule in enumerate(rules, start=1):
            meta = _dict(rule.get("metadata"))
            urls = _dict(rule.get("urls"))
            url_names = [names(urls)] + [
                _name(_dict(c).get("category")) for c in _dicts(urls.get("urlCategoriesWithReputation"))
            ]
            apps = _dict(rule.get("applications"))
            app_names = [_name(apps.get("applications")), _name(apps.get("applicationFilters"))]
            log = [
                label
                for label, on in (
                    ("begin", rule.get("logBegin")),
                    ("end", rule.get("logEnd")),
                    ("FMC", rule.get("sendEventsToFMC")),
                )
                if on
            ]
            rows.append(
                [
                    _text(meta.get("ruleIndex")) or index,
                    _text(rule.get("name")),
                    _text(rule.get("action")),
                    _yes(rule.get("enabled", True)),
                    names(rule.get("sourceZones")) or "any",
                    names(rule.get("destinationZones")) or "any",
                    names(rule.get("sourceNetworks")) or "any",
                    names(rule.get("destinationNetworks")) or "any",
                    names(rule.get("sourcePorts")) or "any",
                    names(rule.get("destinationPorts")) or "any",
                    ", ".join(a for a in app_names if a) or "any",
                    ", ".join(u for u in url_names if u) or "any",
                    names(rule.get("users")) or "any",
                    _name(rule.get("ipsPolicy")),
                    _name(rule.get("filePolicy")),
                    ", ".join(log) or "No",
                ]
            )
        _add(
            sections,
            table_section(
                "Access control rules",
                [
                    "#",
                    "Name",
                    "Action",
                    "Enabled",
                    "Source zones",
                    "Destination zones",
                    "Source networks",
                    "Destination networks",
                    "Source ports",
                    "Destination ports",
                    "Applications",
                    "URLs",
                    "Users",
                    "IPS policy",
                    "File policy",
                    "Log",
                ],
                rows,
            ),
        )
        if total > len(rows) and rows:
            _add(
                sections,
                text_section("Access control rules (note)", f"Showing the first {len(rows)} of {total} rules"),
            )

    # ── Site-to-site VPN ───────────────────────────────────────────────────

    def _endpoint(self, endpoint: dict, rows_of: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
        """One end of a VPN topology: a device on the map (the primary
        member for an HA pair) or an extranet peer."""
        role = {"hub": "hub", "spoke": "spoke"}.get(_kind(endpoint.get("peerType")), "peer")
        protected = _dict(endpoint.get("protectedNetworks"))
        networks = self.objects.names(protected) or _name(protected.get("acl"))
        acl = _name(protected.get("acl"))
        # The protected networks as CIDRs (an ACL-based endpoint protects
        # whatever its ACL says: any, as far as Plexus can tell).
        cidrs: list[str] = ["any"] if acl else []
        if not acl:
            refs = (
                _dicts(protected.get("networks")) + _dicts(protected.get("objects")) + _dicts(protected.get("literals"))
            )
            for ref in refs:
                for _member, cidr in self.objects.expand(ref):
                    if cidr and cidr not in cidrs:
                        cidrs.append(cidr)
        info = _dict(endpoint.get("extranetInfo"))
        device_ids = [] if endpoint.get("extranet") else self.resolver.resolve(endpoint.get("device"))
        if not device_ids:
            name = _text(info.get("name")) or _text(endpoint.get("name")) or _name(endpoint.get("device"))
            address = _text(info.get("ipAddress") or endpoint.get("ipAddress")).split(",")[0].strip()
            if not name and not address:
                return None
            return {
                "kind": "peer",
                "node": f"p:{name or address}",
                "name": name or address,
                "ip": address,
                "dynamic": info.get("isDynamicIP"),
                "role": role,
                "networks": networks,
                "cidrs": cidrs,
                "acl": acl,
                "iface": "",
                "members": [],
                "tokens": {t.lower() for t in (name, address) if t},
            }
        primary = device_ids[0]
        iface = self._find_interface(rows_of.get(primary, []), endpoint.get("interface"))
        local_ip = iface["ip"] if iface else ""
        natted = _text(endpoint.get("nattedInterfaceAddress"))
        container = self.pair_of.get(primary) or self.cluster_of.get(primary) or {}
        name = self._device_name(primary)
        tokens = {name.lower(), primary.lower(), _text(container.get("name")).lower(), _ident(container).lower()}
        tokens.update(self._device_name(d).lower() for d in device_ids)
        tokens.update(t for t in (local_ip, natted) if t)
        tokens.discard("")
        return {
            "kind": "device",
            "node": f"d:{primary}",
            "device": primary,
            "members": device_ids,
            "name": _text(container.get("name")) if self.pair_of.get(primary) else name,
            "ip": natted or local_ip,
            "local_ip": local_ip,
            "addresses": [a for a in (local_ip, natted) if a],
            "role": role,
            "networks": networks,
            "cidrs": cidrs,
            "acl": acl,
            "iface": (iface["ifname"] or iface["name"]) if iface else _name(endpoint.get("interface")),
            "tokens": tokens,
        }

    def _tunnel_state(self, topology: dict, a: dict, b: dict) -> str:
        """ "up" / "down" / "unknown" from ``tunnel_status``, ``""`` when no
        entry names this topology and either end."""
        topo_tokens = {_ident(topology).lower(), _text(topology.get("name")).lower()} - {""}
        states: list[str] = []
        for entry in self.tunnel_status:
            leaves: set[str] = set()

            def walk(value: Any, into: set[str] = leaves) -> None:
                if isinstance(value, dict):
                    for item in value.values():
                        walk(item)
                elif isinstance(value, list):
                    for item in value:
                        walk(item)
                elif value not in (None, ""):
                    into.add(str(value).strip().lower())

            walk({k: v for k, v in entry.items() if k not in ("status", "state", "tunnelStatus")})
            names_topology = entry.get("topology") or entry.get("vpnTopology") or entry.get("topologyName")
            if names_topology and not (leaves & topo_tokens):
                continue
            if not (leaves & (a["tokens"] | b["tokens"])):
                continue
            states.append(_text(_first(entry, "status", "state", "tunnelStatus")).lower())
        if not states:
            return ""
        if "up" in states:
            return "up"
        if "down" in states:
            return "down"
        return "unknown"

    def plan_s2s(self, rows_of: dict[str, list[dict[str, Any]]]) -> list[tuple[dict, dict, dict, str]]:
        """Every tunnel ``(topology, end a, end b, state)`` and the per-device
        VPN rows, before any node exists."""
        tunnels: list[tuple[dict, dict, dict, str]] = []
        for topology in self.s2s_vpns:
            tid = _ident(topology) or _text(topology.get("name"))
            detail = _dict(self.s2s_details.get(tid))
            ends = [e for e in (self._endpoint(ep, rows_of) for ep in _dicts(detail.get("endpoints"))) if e]
            kind = _kind(topology.get("topologyType"))
            if kind == "hubandspoke":
                hubs = [e for e in ends if e["role"] == "hub"]
                spokes = [e for e in ends if e["role"] != "hub"]
                pairs = [(h, s) for h in hubs for s in spokes]
            else:
                pairs = list(combinations(ends, 2))
            ike = ", ".join(
                v for v, on in (("IKEv1", topology.get("ikeV1Enabled")), ("IKEv2", topology.get("ikeV2Enabled"))) if on
            )
            proposals: list[str] = []
            for setting in _dicts(detail.get("ipsec")):
                for key in ("ikeV2IpsecProposal", "ikeV1IpsecProposal", "ikeV2IpsecProposals", "ikeV1IpsecProposals"):
                    proposals += [n for n in (_name(p) for p in _dicts(setting.get(key))) if n not in proposals]
            type_label = _TOPOLOGY_TYPES.get(kind, _text(topology.get("topologyType")))
            up = down = 0
            for a, b in pairs:
                if a["node"] == b["node"]:
                    continue
                state = self._tunnel_state(topology, a, b)
                up += state == "up"
                down += state == "down"
                tunnels.append((topology, a, b, state))
                for here, there in ((a, b), (b, a)):
                    if here["kind"] != "device":
                        continue
                    row = [
                        _text(topology.get("name")),
                        type_label,
                        here["role"],
                        there["name"],
                        there.get("ip") or "",
                        here["iface"],
                        here.get("local_ip") or "",
                        here["networks"],
                        there["networks"],
                        ike,
                        ", ".join(proposals),
                        state or "unknown",
                    ]
                    for member in here["members"]:
                        self.s2s_rows.setdefault(member, []).append(row)
                        names = self.s2s_names.setdefault(member, [])
                        if _text(topology.get("name")) not in names:
                            names.append(_text(topology.get("name")))
                    known = self.endpoint_ips.setdefault(here["device"], [])
                    known.extend(ip for ip in here["addresses"] if ip not in known)
            self.s2s_summary[tid] = {
                "name": _text(topology.get("name")),
                "type": type_label,
                "ike": ike,
                "endpoints": ", ".join(dict.fromkeys(e["name"] for e in ends)),
                "tunnels": f"{up} / {down}",
            }
        return tunnels

    def build_s2s(self, tunnels: list[tuple[dict, dict, dict, str]]) -> None:
        seen: set[tuple[str, frozenset]] = set()
        for topology, a, b, state in tunnels:
            # Only tunnels with a device on the map are drawn (and their peers).
            if not any(end["kind"] == "device" and end["node"] in self.nodes for end in (a, b)):
                continue
            for end in (a, b):
                if end["kind"] == "peer" and end["node"] not in self.nodes:
                    self._peer_node(end)
            key = (_ident(topology) or _text(topology.get("name")), frozenset((a["node"], b["node"])))
            if key in seen:
                continue
            seen.add(key)
            status = _TUNNEL_EDGE_STATUS.get(state, "")
            if a["kind"] == "device" and b["kind"] == "device":
                self._edge(
                    a["node"],
                    b["node"],
                    "vpn",
                    a_port=a["iface"],
                    b_port=b["iface"],
                    status=status,
                    label="Site-to-site VPN",
                    detail=_text(topology.get("name")),
                )
            else:
                device, peer = (a, b) if a["kind"] == "device" else (b, a)
                if device["kind"] != "device":
                    continue
                self._edge(
                    device["node"],
                    peer["node"],
                    "vpn3p",
                    a_port=device["iface"],
                    status=status,
                    label="IPsec",
                    detail=_text(topology.get("name")),
                )

    def _peer_node(self, end: dict) -> None:
        topologies = sorted(
            {
                _text(t.get("name"))
                for t in self.s2s_vpns
                for ep in _dicts(_dict(self.s2s_details.get(_ident(t) or _text(t.get("name")))).get("endpoints"))
                if (_text(_dict(ep.get("extranetInfo")).get("name")) or _text(ep.get("name"))) == end["name"]
            }
        )
        node = self._node(end["node"], "vpn_peer", end["name"], VPN_PEER_SITE_ID, "unknown", ip=end["ip"])
        _add(
            node["sections"],
            kv_section(
                "Site-to-site VPN peer",
                [
                    ("Name", end["name"]),
                    ("Address", end["ip"]),
                    ("Dynamic address", end.get("dynamic")),
                    ("Protected networks", end["networks"]),
                    ("Topologies", ", ".join(topologies)),
                    ("Source", "An extranet endpoint of an FMC site-to-site VPN topology"),
                ],
            ),
        )

    # ── Devices ────────────────────────────────────────────────────────────

    def _boxes(self) -> list[tuple[str, str, list[str], str]]:
        """``(site id, name, member ids, kind)`` of every box of devices on
        the map: one per HA pair, cluster or standalone device."""
        wanted = self.raw.get("on_map")
        include_all = bool(self.options.get("include_all_devices", DEFAULT_OPTIONS["include_all_devices"]))
        if isinstance(wanted, list):
            ids = {_text(i) for i in wanted}
            drawn = [d for d in self.devices if _text(d["id"]) in ids or include_all]
        else:
            drawn = [d for d in self.devices if include_all or _text(d["id"]) in self.device_policy]
        drawn_ids = {_text(d["id"]) for d in drawn}
        boxes: list[tuple[str, str, list[str], str]] = []
        placed: set[str] = set()
        for container, kind, prefix in [(p, "ha", "ha") for p in self.ha_pairs] + [
            (c, "cluster", "cluster") for c in self.clusters
        ]:
            members = [
                m for m in self.resolver.containers.get(_ident(container), []) if m in drawn_ids and m not in placed
            ]
            if not members:
                continue
            placed.update(members)
            name = _text(container.get("name")) or self._device_name(members[0])
            boxes.append((f"{prefix}:{_ident(container) or name}", name, members, kind))
        for device in drawn:
            did = _text(device["id"])
            if did not in placed:
                boxes.append((f"dev:{did}", self._device_name(did), [did], "device"))
        return sorted(boxes, key=lambda b: b[1].lower())

    def build_devices(self) -> list[tuple[dict, dict, dict, str]]:
        boxes = self._boxes()
        on_map = [m for _site, _name, members, _kind in boxes for m in members]
        for device_id in on_map:
            self.rows[device_id] = self._interface_rows(device_id)
        tunnels = self.plan_s2s(self.rows)
        for site_id, box_name, members, kind in boxes:
            site_sections: list[dict] = []
            box_nodes: list[dict] = []
            ra_members = [m for m in members if m in self.device_policy]
            access_rows: list[list[Any]] = []
            for device_id in members:
                node = self._device(self.device_by_id[device_id], device_id, site_id)
                box_nodes.append(node)
                policy = self.device_policy.get(device_id)
                if policy is not None:
                    box_nodes += self._headend(node, device_id, policy, access_rows)
                box_nodes += self._wan_stubs(node, device_id)
            if ra_members:
                policy = self.device_policy[ra_members[0]]
                sessions = [s for m in ra_members for s in self.device_sessions.get(m, [])]
                self._ra_site_sections(site_sections, box_name, policy, access_rows, sessions)
            if kind == "ha":
                self._ha_edge(members)
            elif kind == "cluster":
                self._cluster_edges(members)
            self.sites.append(
                {
                    "id": site_id,
                    "name": box_name,
                    "tags": [kind] if kind != "device" else [],
                    "vpn_mode": "spoke",
                    "status": _worst([n["status"] for n in box_nodes]),
                    "device_count": len(members),
                    "sections": site_sections,
                }
            )
        return tunnels

    def _ha_edge(self, members: list[str]) -> None:
        if len(members) < 2:
            return
        pair = self.pair_of.get(members[0]) or {}
        link = _failover_link(pair)
        states = [_ha_state(pair, "primary").lower(), _ha_state(pair, "secondary").lower()]
        statuses = [self.nodes[f"d:{m}"]["status"] for m in members]
        failed = "offline" in statuses or any(s and ("fail" in s or "disabled" in s) for s in states)
        self._edge(
            f"d:{members[0]}",
            f"d:{members[1]}",
            "stack",
            a_port=link,
            b_port=link,
            status="failed" if failed else "active",
            label="HA",
        )

    def _cluster_edges(self, members: list[str]) -> None:
        control = members[0]
        for unit in members[1:]:
            statuses = [self.nodes[f"d:{control}"]["status"], self.nodes[f"d:{unit}"]["status"]]
            self._edge(
                f"d:{control}",
                f"d:{unit}",
                "stack",
                status="failed" if "offline" in statuses else "active",
                label="Cluster",
            )

    def _status(self, device: dict, device_id: str) -> str:
        status = _health(device.get("healthStatus"))
        severities = {
            _text(_first(a, "status", "severity", "alertStatus")).lower() for a in self.device_alerts.get(device_id, [])
        }
        if severities & {"red", "critical"}:
            return "offline"
        if status == "unknown" and severities & {"yellow", "warning", "major", "minor"}:
            return "alerting"
        return status

    def _device(self, device: dict, did: str, site_id: str) -> dict:
        name = _text(device.get("name")) or did
        status = self._status(device, did)
        meta = _dict(device.get("metadata"))
        serial = _text(_first(meta, "deviceSerialNumber", "serialNumber") or _first(device, "serialNumber", "serial"))
        mgmt = _text(device.get("hostName"))
        rows = self.rows.get(did, [])
        policy = self.device_policy.get(did)

        node = self._node(
            f"d:{did}",
            "appliance",
            name,
            site_id,
            status,
            model=_text(device.get("model")),
            serial=serial,
            ip=mgmt if _is_ip(mgmt) else "",
            site_sections=True,
        )
        if self.endpoint_ips.get(did):
            node["endpoint_ips"] = list(self.endpoint_ips[did])
        host = self.inventory.match(serial=serial, ips=[node["ip"], *(r["ip"] for r in rows if r["ip"])])
        if host:
            node["inventory"] = _inventory_ref(host)

        sections = node["sections"]
        overview_at = len(sections)
        _add(
            sections,
            table_section(
                INTERFACES_SECTION_TITLE,
                [
                    "Interface",
                    "Name",
                    "Type",
                    "Zone",
                    "Virtual router",
                    "IP address",
                    "Subnet",
                    "Enabled",
                    "Mode",
                    "MTU",
                    "Description",
                ],
                [
                    [
                        r["name"],
                        r["ifname"],
                        r["type"],
                        r["zone"],
                        r["vr"],
                        ", ".join([r["ip"], *(a for a, _c in r["ipv6"])]).strip(", "),
                        ", ".join([r["cidr"], *(c for _a, c in r["ipv6"] if c)]).strip(", "),
                        r["enabled"],
                        r["mode"],
                        r["mtu"],
                        r["description"],
                    ]
                    for r in rows
                ],
            ),
        )
        connected: list[list[Any]] = []
        for r in rows:
            for cidr in [r["cidr"], *(c for _a, c in r["ipv6"])]:
                if cidr:
                    connected.append([cidr, r["name"], r["ifname"], r["zone"], r["vr"]])
        self.connected_count += len(connected)
        _add(
            sections,
            table_section(
                CONNECTED_SECTION_TITLE, ["Subnet", "Interface", "Name", "Zone", "Virtual router"], connected
            ),
        )
        vr_names = self._routing_sections(did, rows, sections)
        nat_policy = self.device_nat.get(did)
        _add(
            sections,
            table_section(
                "NAT rules",
                [
                    "#",
                    "Type",
                    "Section",
                    "Original source",
                    "Original destination",
                    "Translated source",
                    "Translated destination",
                    "Source interface",
                    "Destination interface",
                    "Original service",
                    "Translated service",
                    "Enabled",
                    "Description",
                ],
                self._nat_rows(nat_policy),
            ),
        )
        self._access_sections(did, sections)
        _add(
            sections,
            table_section(
                "Site-to-site VPN",
                [
                    "Topology",
                    "Type",
                    "Role",
                    "Peer",
                    "Peer address",
                    "Local interface",
                    "Local address",
                    "Protected networks",
                    "Peer networks",
                    "IKE",
                    "IPsec",
                    "Status",
                ],
                self.s2s_rows.get(did, []),
            ),
        )
        alerts = self.device_alerts.get(did, [])
        _add(
            sections,
            table_section(
                "Health alerts",
                ["Severity", "Module", "Description", "Since"],
                [self._alert_row(a)[1:] for a in alerts],
            ),
        )
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

        pair = self.pair_of.get(did)
        cluster = self.cluster_of.get(did)
        role = self.ha_role.get(did, "")
        domain = _dict(meta.get("domain"))
        overview = kv_section(
            "Overview",
            [
                ("Name", name),
                ("Status", status),
                ("Health", device.get("healthStatus")),
                ("Model", node["model"]),
                ("Software", device.get("sw_version") or device.get("softwareVersion")),
                ("Management address", mgmt),
                ("Serial", serial),
                ("FMC domain", domain.get("name") or _dict(self.raw.get("fmc")).get("domain")),
                ("Deployment status", device.get("deploymentStatus")),
                ("Mode", device.get("ftdMode")),
                ("Snort version", meta.get("snortVersion")),
                ("HA pair", _name(pair) if pair else ""),
                ("HA role", role),
                ("HA state", _ha_state(pair, role) if pair and role else ""),
                ("Cluster", _name(cluster) if cluster else ""),
                ("Cluster role", self.cluster_role.get(did, "")),
                ("Access control policy", _name(self.device_acp.get(did))),
                ("Prefilter policy", _name(self._prefilter_of(did))),
                ("NAT policy", _name(nat_policy)),
                ("Remote access VPN policy", _name(policy) if policy else "none"),
                ("Virtual routers", ", ".join(vr_names) if len(vr_names) > 1 else ""),
                ("Site-to-site VPN topologies", ", ".join(self.s2s_names.get(did, []))),
                ("Pending deployment", _yes(self._pending(did)) if self.deployable_collected else ""),
                ("Health alerts", len(alerts) if alerts else ""),
                ("Description", device.get("description")),
                ("Device ID", did),
            ],
        )
        if overview:
            sections.insert(overview_at, overview)
        return node

    def _prefilter_of(self, device_id: str) -> dict | None:
        found = self.device_prefilter.get(device_id)
        if found:
            return found
        policy = self.device_acp.get(device_id)
        full = next((p for p in self.access_policies if policy and _ident(p) == _ident(policy)), policy or {})
        setting = _dict(full.get("prefilterPolicySetting"))
        return setting or None

    def _alert_row(self, alert: dict) -> list[Any]:
        device_id = self._device_of(
            alert,
            "device",
            "deviceInfo",
            id_keys=("deviceUUID", "deviceUuid", "deviceId"),
            name_keys=("deviceName", "name", "hostName"),
        )
        return [
            self._device_name(device_id) if device_id else _name(alert.get("device")),
            _text(_first(alert, "status", "severity", "alertStatus")),
            _text(_first(alert, "moduleName", "module", "healthModule")),
            _text(_first(alert, "description", "alertDescription", "message", "text")),
            _text(_first(alert, "timestamp", "time", "since", "lastUpdated")),
        ]

    def _wan_stubs(self, node: dict, did: str) -> list[dict]:
        """A WAN stub per outside interface not already drawn as a remote
        access VPN access interface: one with a public address, or the
        egress of the IPv4 default route."""
        egress = self._default_egress(did)
        added: list[dict] = []
        for row in self.rows.get(did, []):
            key = row["ifname"] or row["name"]
            if not key or not row["ip"]:
                continue
            via = egress.get(row["ifname"].lower()) if row["ifname"] else None
            if not _is_public(row["ip"]) and via is None:
                continue
            wan_id = f"w:{did}:{key}"
            if wan_id in self.nodes:
                continue
            wan = self._node(
                wan_id,
                "wan",
                f"{key} {row['ip']}",
                node["site"],
                "online" if row["enabled"] else "offline",
                ip=row["ip"],
                parent=node["id"],
            )
            _add(
                wan["sections"],
                kv_section(
                    "WAN interface",
                    [
                        ("Device", node["label"]),
                        ("Interface", row["name"]),
                        ("Name", row["ifname"]),
                        ("Zone", row["zone"]),
                        ("IP address", row["ip"]),
                        ("Subnet", row["cidr"]),
                        ("Default route via", via),
                        ("Virtual router", row["vr"]),
                    ],
                ),
            )
            self._edge(wan_id, node["id"], "uplink", b_port=key, status="active" if row["enabled"] else "failed")
            added.append(wan)
        return added

    # ── Remote access VPN ──────────────────────────────────────────────────

    def _policy_detail(self, policy: dict | None) -> dict[str, list[dict]]:
        found = _dict(self.details.get(_text(policy.get("id")))) if policy else {}
        return {
            key: [i for i in found.get(key) or [] if isinstance(i, dict)]
            for key in ("connection_profiles", "address_assignment", "access_interfaces")
        }

    def _pool(self, ref: Any) -> dict:
        pool = self.pool_by_id.get(_ident(ref)) or self.pool_by_name.get(_name(ref).lower())
        return pool if pool else {"name": _name(ref)}

    def _pool_rows(self, profiles: list[dict]) -> list[list[Any]]:
        """Address pool rows of a policy: Subnet, Pool, Range, Profiles."""
        by_pool: dict[str, tuple[dict, list[str]]] = {}
        for profile in profiles:
            refs = profile.get("ipv4AddressPool") or profile.get("ipv4AddressPools") or []
            for ref in refs if isinstance(refs, list) else [refs]:
                pool = self._pool(ref)
                key = _text(pool.get("id")) or _text(pool.get("name"))
                if not key:
                    continue
                entry = by_pool.setdefault(key, (pool, []))
                if _text(profile.get("name")) not in entry[1]:
                    entry[1].append(_text(profile.get("name")))
        rows: list[list[Any]] = []
        for pool, names in by_pool.values():
            cidr = pool_cidr(pool)
            rows.append([cidr, pool.get("name"), pool.get("ipAddressRange") or pool.get("range"), ", ".join(names)])
        return sorted(rows, key=lambda r: (r[0] == "", r[0], _text(r[1])))

    def _session_rows(self, sessions: list[dict]) -> list[list[Any]]:
        rows: list[list[Any]] = []
        for s in sessions[:MAX_LISTED_SESSIONS]:
            rows.append(
                [
                    _name(_first(s, "username", "userName", "user")),
                    _text(
                        _first(
                            s, "assignedIp", "assignedIpv4", "assignedIpv4Address", "assignedIPv4", "clientIp", "vpnIp"
                        )
                    ),
                    _text(_first(s, "publicIp", "publicIpAddress", "publicIpv4", "remoteIp", "clientPublicIp")),
                    _name(_first(s, "connectionProfile", "tunnelGroup", "connectionProfileName")),
                    _name(_first(s, "groupPolicy", "groupPolicyName")),
                    _name(_first(s, "clientApplication", "clientVersion", "anyConnectVersion", "clientType")),
                    _name(_first(s, "clientOs", "clientOS", "osType", "clientOsType")),
                    _name(_first(s, "protocol", "encryption", "tunnelProtocol")),
                    _text(_first(s, "loginTime", "loginTimeStamp", "connectedSince")),
                    _text(_first(s, "duration", "connectionDuration", "sessionDuration")),
                    _text(_first(s, "bytesRx", "rxBytes", "bytesReceived")),
                    _text(_first(s, "bytesTx", "txBytes", "bytesTransmitted")),
                ]
            )
        return sorted(rows, key=lambda r: (str(r[0]).lower(), str(r[1])))

    def _access(self, policy: dict) -> tuple[list[dict], dict]:
        """The access interface entries of a policy and its port settings."""
        settings = self._policy_detail(policy)["access_interfaces"]
        ports = next((s for s in settings if s.get("sslPort") or s.get("dtlsPort")), settings[0] if settings else {})
        access: list[dict] = []
        for setting in settings:
            entries = setting.get("accessInterfaceSettings") or setting.get("interfaces") or []
            access.extend(e for e in (entries if isinstance(entries, list) else [entries]) if isinstance(e, dict))
        return access, ports

    def _ra_site_sections(
        self, site_sections: list[dict], headend: str, policy: dict, access_rows: list[list[Any]], sessions: list[dict]
    ) -> None:
        detail = self._policy_detail(policy)
        profiles = detail["connection_profiles"]
        assignment = detail["address_assignment"][0] if detail["address_assignment"] else {}
        access, ports = self._access(policy)
        protocols = sorted(
            {
                p
                for e in access
                for p, on in (("SSL", e.get("enableSSL")), ("IPsec IKEv2", e.get("enableIPSecIKEv2")))
                if on
            }
        )
        assignment_sources = [
            label
            for label, on in (
                ("authorization server", assignment.get("useAuthorizationServer")),
                ("DHCP", assignment.get("useDhcp")),
                ("local pools", assignment.get("useLocalPools", True if not assignment else None)),
            )
            if on
        ]
        pool_rows = self._pool_rows(profiles)
        self.pool_count += len(pool_rows)
        _add(
            site_sections,
            kv_section(
                "Remote access VPN",
                [
                    ("Policy", policy.get("name")),
                    ("Headend", headend),
                    ("Description", policy.get("description")),
                    ("Connection profiles", ", ".join(_text(p.get("name")) for p in profiles)),
                    ("Access interfaces", ", ".join(_name(e.get("accessInterface")) for e in access)),
                    ("Protocols", ", ".join(protocols)),
                    ("SSL port", ports.get("sslPort")),
                    ("DTLS port", ports.get("dtlsPort")),
                    ("Address assignment", ", ".join(assignment_sources)),
                    ("Connected users", len(sessions) if self.sessions_collected else "not collected"),
                    ("Policy ID", policy.get("id")),
                ],
            ),
        )
        _add(
            site_sections,
            table_section(
                "Connection profiles",
                [
                    "Profile",
                    "Group policy",
                    "Address pools",
                    "Authentication",
                    "Authentication server",
                    "Group alias",
                    "Group URL",
                ],
                [
                    [
                        p.get("name"),
                        _name(p.get("groupPolicy")),
                        _name(p.get("ipv4AddressPool") or p.get("ipv4AddressPools")),
                        p.get("authenticationMethod"),
                        _name(p.get("primaryAuthenticationServer") or p.get("authenticationServer")),
                        ", ".join(_text(a.get("name")) for a in p.get("groupAlias") or [] if isinstance(a, dict)),
                        ", ".join(_text(u.get("url")) for u in p.get("groupUrl") or [] if isinstance(u, dict)),
                    ]
                    for p in profiles
                ],
            ),
        )
        _add(site_sections, table_section(POOL_SECTION_TITLE, POOL_COLUMNS, pool_rows))
        _add(
            site_sections,
            table_section("Access interfaces", ["Interface", "Zone", "IP address", "SSL", "IPsec IKEv2"], access_rows),
        )

    def _headend(self, node: dict, did: str, policy: dict, access_rows: list[list[Any]]) -> list[dict]:
        """The remote access VPN side of one device: its access interface
        stubs (rows appended to ``access_rows``) and its users node.
        Returns the nodes added."""
        access, ports = self._access(policy)
        interfaces = self.rows.get(did, [])
        added: list[dict] = []
        for index, entry in enumerate(access):
            zone = entry.get("accessInterface")
            zone_id, zone_name = _ident(zone), _name(zone)
            matched = [
                i
                for i in interfaces
                if (zone_id and i["zone_id"] == zone_id)
                or (zone_name and zone_name.lower() in (i["zone"].lower(), i["ifname"].lower(), i["name"].lower()))
            ]
            stub: dict[str, Any] = {
                "name": "",
                "ifname": zone_name,
                "zone": zone_name,
                "ip": "",
                "cidr": "",
                "enabled": True,
            }
            for iface in matched or [stub]:
                label = iface["ifname"] or iface["name"] or zone_name or f"access {index + 1}"
                row = [label, zone_name, iface["ip"], bool(entry.get("enableSSL")), bool(entry.get("enableIPSecIKEv2"))]
                if row not in access_rows:
                    access_rows.append(row)
                wan_id = f"w:{did}:{iface['ifname'] or iface['name'] or index}"
                if wan_id in self.nodes:
                    continue
                wan = self._node(
                    wan_id,
                    "wan",
                    f"{label} {iface['ip']}".strip(),
                    node["site"],
                    "online" if iface["enabled"] else "offline",
                    ip=iface["ip"],
                    parent=node["id"],
                )
                _add(
                    wan["sections"],
                    kv_section(
                        "VPN access interface",
                        [
                            ("Device", node["label"]),
                            ("Interface", iface["name"]),
                            ("Name", iface["ifname"]),
                            ("Zone", zone_name),
                            ("IP address", iface["ip"]),
                            ("Subnet", iface.get("cidr")),
                            ("SSL", bool(entry.get("enableSSL"))),
                            ("IPsec IKEv2", bool(entry.get("enableIPSecIKEv2"))),
                            ("DTLS", entry.get("enableDTLS")),
                            ("SSL port", ports.get("sslPort")),
                            ("DTLS port", ports.get("dtlsPort")),
                        ],
                    ),
                )
                self._edge(
                    wan_id, node["id"], "uplink", b_port=label, status="active" if iface["enabled"] else "failed"
                )
                added.append(wan)
        added.append(self._users_node(node, did, policy, self.device_sessions.get(did, [])))
        return added

    def _users_node(self, node: dict, did: str, policy: dict, sessions: list[dict]) -> dict:
        count = len(sessions)
        label = f"AnyConnect users ({count})" if self.sessions_collected else "AnyConnect users"
        users = self._node(
            f"u:{did}",
            "users",
            label,
            node["site"],
            "online" if count else "unknown",
            model="Cisco Secure Client",
        )
        _add(
            users["sections"],
            kv_section(
                "Remote access users",
                [
                    ("Headend", node["label"]),
                    ("Policy", policy.get("name")),
                    ("Connected now", count if self.sessions_collected else "not collected"),
                    (
                        "Source",
                        "Users connected to this device with AnyConnect / Secure Client when the collection ran"
                        if self.sessions_collected
                        else "Sessions were not collected (option off, or the FMC does not serve them)",
                    ),
                ],
            ),
        )
        _add(
            users["sections"],
            table_section(
                "Connected users",
                [
                    "User",
                    "Assigned IP",
                    "Public IP",
                    "Connection profile",
                    "Group policy",
                    "Client",
                    "OS",
                    "Protocol",
                    "Login time",
                    "Duration",
                    "Bytes in",
                    "Bytes out",
                ],
                self._session_rows(sessions),
            ),
        )
        self._edge(users["id"], node["id"], "vpn", status="reachable" if count else "", label="AnyConnect")
        return users

    # ── The FMC ────────────────────────────────────────────────────────────

    def _policy_device_names(self, policies: list[dict], device_map: dict[str, dict]) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for device_id, policy in device_map.items():
            names = found.setdefault(_ident(policy), [])
            if self._device_name(device_id) not in names:
                names.append(self._device_name(device_id))
        return {k: sorted(v, key=str.lower) for k, v in found.items()}

    def build_fmc(self) -> None:
        fmc = _dict(self.raw.get("fmc"))
        host = _text(fmc.get("url")).removeprefix("https://").split("/", 1)[0].strip("[]")
        host_only = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        label = _text(fmc.get("name")) or (f"FMC {host_only}" if host_only else "FMC")
        node = self._node(
            FMC_NODE_ID,
            "cloud",
            label,
            FMC_SITE_ID,
            "online",
            model="Cisco Secure Firewall Management Center",
            ip=host_only if _is_ip(host_only) else "",
        )
        on_map = {n["id"].removeprefix("d:") for n in self.nodes.values() if n["kind"] == "appliance"}
        pending = [d for d in self.devices if self._pending(_text(d["id"]))]
        _add(
            node["sections"],
            kv_section(
                "Cisco FMC",
                [
                    ("Name", fmc.get("name")),
                    ("Address", fmc.get("url")),
                    ("Version", fmc.get("version")),
                    ("Domain", fmc.get("domain")),
                    ("Devices managed", len(self.devices)),
                    ("Devices on the map", len(on_map)),
                    ("HA pairs", len(self.ha_pairs)),
                    ("Clusters", len(self.clusters)),
                    ("Devices with remote access VPN", len(self.device_policy)),
                    ("Remote access VPN policies", len(self.policies)),
                    ("Address pools", len(self.pools)),
                    ("Access control policies", len(self.access_policies)),
                    ("NAT policies", len(self.nat_policies)),
                    ("Site-to-site VPN topologies", len(self.s2s_vpns)),
                    ("Network objects", self.objects.count()),
                    ("Security zones", len(self.objects.zones)),
                    (
                        "Health alerts",
                        len(self.alerts) if self.raw.get("health_alerts") is not None else "not collected",
                    ),
                    ("Devices pending deployment", len(pending) if self.deployable_collected else "not collected"),
                    ("Connected users", len(self.sessions) if self.sessions_collected else "not collected"),
                    ("Unsupported resources", len(self.unsupported)),
                    ("Snapshot time", self.raw.get("timestamp")),
                ],
            ),
        )
        container_of = {
            **{m: f"HA {_name(p)}" for m, p in self.pair_of.items()},
            **{m: f"Cluster {_name(c)}" for m, c in self.cluster_of.items()},
        }
        _add(
            node["sections"],
            table_section(
                "Managed devices",
                [
                    "Device",
                    "Model",
                    "Software",
                    "Management address",
                    "Health",
                    "HA pair / cluster",
                    "Remote access VPN policy",
                    "NAT policy",
                    "Access control policy",
                    "Pending deployment",
                    "On the map",
                ],
                [
                    [
                        d.get("name"),
                        d.get("model"),
                        d.get("sw_version") or d.get("softwareVersion"),
                        d.get("hostName"),
                        d.get("healthStatus"),
                        container_of.get(_text(d["id"]), ""),
                        _name(self.device_policy.get(_text(d["id"]))),
                        _name(self.device_nat.get(_text(d["id"]))),
                        _name(self.device_acp.get(_text(d["id"]))),
                        _yes(self._pending(_text(d["id"]))) if self.deployable_collected else "",
                        _text(d["id"]) in on_map,
                    ]
                    for d in sorted(self.devices, key=lambda d: _text(d.get("name")).lower())
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "High availability pairs",
                ["Pair", "Primary", "Secondary", "Primary state", "Secondary state", "Failover link"],
                [
                    [
                        _name(p),
                        _name(ha_members(p)[0]) if ha_members(p) else "",
                        _name(ha_members(p)[1]) if len(ha_members(p)) > 1 else "",
                        _ha_state(p, "primary"),
                        _ha_state(p, "secondary"),
                        _failover_link(p),
                    ]
                    for p in sorted(self.ha_pairs, key=lambda p: _name(p).lower())
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Clusters",
                ["Cluster", "Control unit", "Data units"],
                [
                    [
                        _name(c),
                        _name(cluster_members(c)[0]) if cluster_members(c) else "",
                        _name(cluster_members(c)[1:]),
                    ]
                    for c in sorted(self.clusters, key=lambda c: _name(c).lower())
                ],
            ),
        )
        acp_devices = self._policy_device_names(self.access_policies, self.device_acp)
        _add(
            node["sections"],
            table_section(
                "Access control policies",
                ["Policy", "Default action", "Rules", "Devices"],
                [
                    [
                        _name(p),
                        _text(_dict(p.get("defaultAction")).get("action")),
                        self.access_rule_counts.get(_ident(p))
                        or (len(_dicts(self.access_rules.get(_ident(p)))) if _ident(p) in self.access_rules else ""),
                        ", ".join(acp_devices.get(_ident(p), [])),
                    ]
                    for p in sorted(self.access_policies, key=lambda p: _name(p).lower())
                ],
            ),
        )
        nat_devices = self._policy_device_names(self.nat_policies, self.device_nat)
        _add(
            node["sections"],
            table_section(
                "NAT policies",
                ["Policy", "Rules", "Devices"],
                [
                    [
                        _name(p),
                        len(_dicts(self.nat_rules.get(_ident(p)))) if _ident(p) in self.nat_rules else "",
                        ", ".join(nat_devices.get(_ident(p), [])),
                    ]
                    for p in sorted(self.nat_policies, key=lambda p: _name(p).lower())
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Site-to-site VPN topologies",
                ["Topology", "Type", "IKE", "Endpoints", "Tunnels up / down"],
                [
                    [s["name"], s["type"], s["ike"], s["endpoints"], s["tunnels"]]
                    for s in sorted(self.s2s_summary.values(), key=lambda s: s["name"].lower())
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Remote access VPN policies",
                ["Policy", "Devices", "Connection profiles", "Address pools"],
                [
                    [
                        p.get("name"),
                        ", ".join(self.policy_devices.get(_text(p["id"]), [])),
                        ", ".join(_text(c.get("name")) for c in self._policy_detail(p)["connection_profiles"]),
                        ", ".join(r[1] for r in self._pool_rows(self._policy_detail(p)["connection_profiles"])),
                    ]
                    for p in self.policies
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Address pools",
                ["Pool", "Range", "Mask", "Subnet", "Description"],
                [
                    [
                        p.get("name"),
                        p.get("ipAddressRange") or p.get("range"),
                        p.get("mask"),
                        pool_cidr(p),
                        p.get("description"),
                    ]
                    for p in sorted(self.pools, key=lambda p: _text(p.get("name")).lower())
                ],
            ),
        )
        object_rows = [
            [_text(o.get("name")), label, _text(o.get("value")), _text(o.get("description"))]
            for key, label in _Objects.KINDS
            if key != "groups"
            for o in self.objects.by_kind[key]
        ]
        _add(
            node["sections"],
            table_section(
                "Network objects",
                ["Name", "Type", "Value", "Description"],
                sorted(object_rows, key=lambda r: (r[0].lower(), r[1]))[:MAX_LISTED_OBJECTS],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Network groups",
                ["Group", "Members"],
                sorted(
                    [[_text(g.get("name")), self.objects.names(g)] for g in self.objects.by_kind["groups"]],
                    key=lambda r: r[0].lower(),
                )[:MAX_LISTED_GROUPS],
            ),
        )
        raw_objects = _dict(self.raw.get("objects"))
        port_rows = [
            [
                _text(o.get("name")),
                "Port group" if key == "port_groups" else ("ICMP" if key == "icmp" else "Port"),
                _text(o.get("protocol")) or ("ICMP" if key == "icmp" else ""),
                _text(o.get("port")) or _text(o.get("icmpType")),
                self.objects.names(o) if key == "port_groups" else "",
            ]
            for key in ("ports", "port_groups", "icmp")
            for o in _dicts(raw_objects.get(key))
        ]
        _add(
            node["sections"],
            table_section(
                "Port objects",
                ["Name", "Type", "Protocol", "Port / ICMP type", "Members"],
                sorted(port_rows, key=lambda r: (r[0].lower(), r[1]))[:MAX_LISTED_OBJECTS],
            ),
        )
        prefilter_names = {_ident(p): _name(p) for p in self.prefilter_policies if _ident(p)}
        prefilter_rows: list[list[Any]] = []
        for pid, rules in _dict(self.raw.get("prefilter_rules")).items():
            for index, rule in enumerate(_dicts(rules), start=1):
                prefilter_rows.append(
                    [
                        prefilter_names.get(pid, pid),
                        _text(_dict(rule.get("metadata")).get("ruleIndex")) or index,
                        _text(rule.get("name")),
                        _text(rule.get("ruleType")),
                        _text(rule.get("action")),
                        _yes(rule.get("enabled", True)),
                        self.objects.names(rule.get("sourceInterfaces")) or "any",
                        self.objects.names(rule.get("destinationInterfaces")) or "any",
                        self.objects.names(rule.get("sourceNetworks")) or "any",
                        self.objects.names(rule.get("destinationNetworks")) or "any",
                        self.objects.names(rule.get("sourcePorts")) or "any",
                        self.objects.names(rule.get("destinationPorts")) or "any",
                    ]
                )
        _add(
            node["sections"],
            table_section(
                "Prefilter rules",
                [
                    "Policy",
                    "#",
                    "Name",
                    "Type",
                    "Action",
                    "Enabled",
                    "Source zones",
                    "Destination zones",
                    "Source networks",
                    "Destination networks",
                    "Source ports",
                    "Destination ports",
                ],
                prefilter_rows,
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Security zones",
                ["Zone", "Type", "Interfaces"],
                [self._zone_row(z) for z in sorted(self.objects.zones, key=lambda z: _name(z).lower())],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Health alerts",
                ["Device", "Severity", "Module", "Description", "Since"],
                [self._alert_row(a) for a in self.alerts],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Pending deployment",
                ["Device", "Version", "Since"],
                [
                    [
                        self._device_name(_text(d["id"])),
                        ", ".join(_text(e.get("version")) for e in self._pending(_text(d["id"])) if e.get("version")),
                        ", ".join(
                            _text(_first(e, "lastDeployTime", "since", "modifiedTime"))
                            for e in self._pending(_text(d["id"]))
                            if _first(e, "lastDeployTime", "since", "modifiedTime")
                        ),
                    ]
                    for d in sorted(pending, key=lambda d: _text(d.get("name")).lower())
                ],
            ),
        )
        for device_id in sorted(on_map):
            self._edge(FMC_NODE_ID, f"d:{device_id}", "manage", label="Managed by FMC")

    def _zone_row(self, zone: dict) -> list[Any]:
        members: list[str] = []
        for ref in _dicts(zone.get("interfaces")):
            device = _name(ref.get("device"))
            ifname = _text(ref.get("ifname")) or _text(ref.get("name"))
            if device and ifname:
                members.append(f"{device}:{ifname}")
        for device_id, rows in self.rows.items():
            for row in rows:
                if (row["zone_id"] and row["zone_id"] == _ident(zone)) or (
                    not row["zone_id"] and row["zone"] and row["zone"] == _name(zone)
                ):
                    entry = f"{self._device_name(device_id)}:{row['ifname'] or row['name']}"
                    if entry not in members:
                        members.append(entry)
        return [_name(zone), _text(_first(zone, "interfaceMode", "zoneType", "type")), ", ".join(members)]

    def build_edge_sections(self) -> None:
        titles = {
            "vpn": "AnyConnect",
            "vpn3p": "IPsec",
            "uplink": "WAN interface",
            "manage": "Managed by FMC",
        }
        for edge in self.edges:
            a, b = self.nodes[edge["a"]], self.nodes[edge["b"]]
            if edge["kind"] == "stack":
                title = "High availability" if edge.get("label") == "HA" else "Cluster"
            elif edge["kind"] == "uplink":
                # The stub's own section says which kind of outside interface it is.
                stub = a if a["kind"] == "wan" else b
                title = next((s["title"] for s in stub["sections"]), titles["uplink"])
            else:
                title = edge.get("label") or titles.get(edge["kind"], "Link")
            edge["sections"] = [
                s
                for s in [
                    kv_section(
                        title,
                        [
                            ("A end", a["label"]),
                            ("B end", b["label"]),
                            ("A port", edge.get("a_port")),
                            ("B port", edge.get("b_port")),
                            ("Topology", edge.get("detail")),
                            ("Status", edge.get("status")),
                            ("Discovered via", "FMC API"),
                        ],
                    )
                ]
                if s
            ]


def build_snapshot(raw: dict, inventory: InventoryIndex | None = None) -> dict[str, Any]:
    """Build the positioned topology snapshot from raw collector output.

    Tolerates a capture of an earlier release (no HA pairs, routing, NAT,
    policies, VPN topologies or health): those parts are simply absent."""
    # Imported here: the forwarding module reads this one's helpers.
    from netcontrol.integrations.fmc.forwarding import build_forwarding

    builder = _Builder(raw, inventory or InventoryIndex())
    tunnels = builder.build_devices()
    builder.build_s2s(tunnels)
    build_forwarding(builder, tunnels)
    builder.build_fmc()
    builder.build_edge_sections()

    sites = [
        {
            "id": FMC_SITE_ID,
            "name": "Cisco FMC",
            "tags": [],
            # Sorts the FMC ahead of the devices, like a VPN hub.
            "vpn_mode": "hub",
            "status": "online",
            "device_count": 1,
            "sections": [],
        },
        *builder.sites,
    ]
    if any(n["kind"] == "vpn_peer" for n in builder.nodes.values()):
        sites.append(
            {
                "id": VPN_PEER_SITE_ID,
                "name": "Site-to-site VPN peers",
                "tags": [],
                "vpn_mode": "none",
                "status": "unknown",
                "device_count": sum(1 for n in builder.nodes.values() if n["kind"] == "vpn_peer"),
                "sections": [],
            }
        )
    _layout(sites, builder.nodes, builder.edges)

    nodes = list(builder.nodes.values())
    for node in nodes:
        node.pop("parent", None)

    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in nodes:
        if node["kind"] in ("wan", "users", "vpn_peer") or node["kind"] in MANAGEMENT_KINDS:
            continue
        by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
        by_status[node["status"]] = by_status.get(node["status"], 0) + 1
    edge_counts: dict[str, int] = {}
    for edge in builder.edges:
        edge_counts[edge["kind"]] = edge_counts.get(edge["kind"], 0) + 1

    fmc = _dict(raw.get("fmc"))
    return {
        "schema": SCHEMA_VERSION,
        "provider": "fmc",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": {
            "id": _s(fmc.get("domain_uuid") or fmc.get("url")),
            "name": fmc.get("name") or "FMC",
            "url": _s(fmc.get("url")),
        },
        "summary": {
            "sites": len(builder.sites),
            "devices": sum(by_kind.values()),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": 0,
            "inventory_matches": sum(1 for n in nodes if n.get("inventory")),
            "lan_links": edge_counts.get("stack", 0),
            "vpn_tunnels": edge_counts.get("vpn", 0) + edge_counts.get("vpn3p", 0),
            "wan_uplinks": edge_counts.get("uplink", 0),
            "vlans": builder.connected_count + builder.pool_count,
            "remote_users": len(builder.sessions) if builder.sessions_collected else 0,
            "ha_pairs": len(builder.ha_pairs),
            "clusters": len(builder.clusters),
            "s2s_topologies": len(builder.s2s_vpns),
            "nat_rules": sum(len(_dicts(v)) for v in builder.nat_rules.values()),
            "access_rules": sum(len(_dicts(v)[:MAX_ACCESS_RULES]) for v in builder.access_rules.values()),
        },
        "collection": {
            "sources": ["Cisco FMC REST API"],
            "stats": raw.get("stats") or {},
            "errors": raw.get("errors") or [],
            "unsupported": list(builder.unsupported),
            "options": raw.get("options") or {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }
