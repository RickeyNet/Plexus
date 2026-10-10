"""Turn raw Panorama payloads into a positioned topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), so the merge
into the Topology graph, node details, deep search, the subnet index, IPAM,
the HTML export and the software tracker need no Panorama-specific code.

How a Panorama maps onto the map:

  - Panorama itself is one node in a box of its own, joined to each firewall
    by a management link that Path Mode and the tidy-tree layout ignore
  - a standalone firewall is a box of its own; an HA pair is one box holding
    both members joined by an ``HA`` link (the active member first)
  - each outside interface of a firewall (a public address, the egress of
    the default route, or a GlobalProtect gateway interface) is a WAN stub
    over the firewall, carrying the interface's own address
  - a firewall with a GlobalProtect gateway gets its address pools as
    subnets and one "GlobalProtect users" node with the connected users
    listed behind it (one node per user would bury the map)
  - IPsec tunnels between two managed firewalls are VPN tunnels between
    them (the active member for an HA pair); a tunnel to a peer Panorama
    does not manage is an IPsec link to a node shared by every tunnel to
    that address
  - interfaces, zones, routing, VPN, the security and NAT rules each
    firewall inherits are detail sections of each firewall; the device
    groups, templates, objects and the firewalls waiting for a push are
    detail sections of the Panorama node

Rule order: a firewall applies the shared pre-rules, then those of each
ancestor device group from the top down, then its own device group's; then
the rules configured on the firewall itself (not read); then its device
group's post-rules, the ancestors' from the bottom up, the shared ones; then
the two default rules. A rule whose ``target`` leaves the firewall out is
not shown on it.

How a firewall joins the rest of the map: a Plexus inventory host matching
its serial, management or interface address becomes the firewall; a
VM-Series in a cloud is matched to its instance by the private address of an
outside interface, like an FTDv; and the addresses its IKE gateways use
(``endpoint_ips``) make the far end another integration draws collapse into
it.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

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
from netcontrol.integrations.panorama.collector import (
    DEFAULT_OPTIONS,
    SHARED,
    ancestors,
    device_group_members,
    entries,
    ha_peer,
    members,
    stack_of_devices,
    stack_templates,
)

PANORAMA_SITE_ID = "__panorama__"
PANORAMA_NODE_ID = "panorama"

# Kinds that stand for the management plane rather than devices at a site.
MANAGEMENT_KINDS = ("cloud",)

INTERFACES_SECTION_TITLE = "Firewall interfaces"
CONNECTED_SECTION_TITLE = "Connected subnets"
STATIC_ROUTES_SECTION_TITLE = "Static routes"
POOL_SECTION_TITLE = "VPN address pools"
POOL_COLUMNS = ["Subnet", "Pool", "Range", "Gateways"]
SECURITY_RULE_COLUMNS = [
    "#",
    "Name",
    "Rulebase",
    "Action",
    "Enabled",
    "From",
    "To",
    "Source",
    "Source user",
    "Destination",
    "Application",
    "Service",
    "Profile",
    "Log",
    "Tags",
    "Description",
]
NAT_RULE_COLUMNS = [
    "#",
    "Name",
    "Rulebase",
    "Enabled",
    "From",
    "To",
    "To interface",
    "Source",
    "Destination",
    "Service",
    "Source translation",
    "Destination translation",
    "Description",
]

MAX_LISTED_USERS = 5000
MAX_LISTED_OBJECTS = 2000
MAX_LISTED_GROUPS = 500
_MAX_GROUP_DEPTH = 6

# Services every PAN-OS has without configuring them.
PREDEFINED_SERVICES = {
    "service-http": [("tcp", "80,8080")],
    "service-https": [("tcp", "443")],
}
DEFAULT_RULES = (("intrazone-default", "allow"), ("interzone-default", "deny"))
_TUNNEL_EDGE_STATUS = {"up": "reachable", "down": "unreachable"}
_FLAG_PROTOCOLS = (
    ("B", "BGP"),
    ("Oi", "OSPF"),
    ("Oo", "OSPF"),
    ("O1", "OSPF"),
    ("O2", "OSPF"),
    ("O", "OSPF"),
    ("R", "RIP"),
    ("S", "Static"),
    ("C", "Connected"),
    ("H", "Host"),
)

# Documentation ranges (RFC 5737, RFC 3849) stand in for public addresses in
# examples, labs and the bundled demo, so an interface in one is drawn as
# outside like any public one.
_DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


# ── Small value helpers ──────────────────────────────────────────────────────


def _text(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("#text") or value.get("@name") or ""
    if isinstance(value, list):
        return ", ".join(t for t in (_text(v) for v in value) if t)
    return str(value or "").strip()


def _dict(value: Any) -> dict[str, Any]:
    """``value`` when it is an object, else an empty one."""
    return value if isinstance(value, dict) else {}


def _name(item: Any) -> str:
    return _text(_dict(item).get("@name")) if isinstance(item, dict) else _text(item)


def _yes(value: Any) -> bool:
    return _text(value).lower() in ("yes", "true", "1", "on")


def _yes_no(value: bool) -> str:
    return "Yes" if value else "No"


def _first(item: dict, *keys: str) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_global or any(parsed in net for net in _DOCUMENTATION_NETS if net.version == parsed.version)


def is_virtual_model(model: Any) -> bool:
    """A VM-Series firewall (``PA-VM``, ``PA-VM-AWS``...)."""
    return _text(model).lower().startswith("pa-vm")


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


def value_cidr(value: Any) -> str:
    """The network an address value stands for: a host as /32 (or /128), a
    network as itself, a range as the smallest covering network; ``""`` for
    anything else (an FQDN, a name)."""
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


def interface_address(value: Any) -> tuple[str, str]:
    """``(address, subnet)`` of an interface address such as ``10.1.1.1/24``."""
    text = _text(value)
    address, _sep, length = text.partition("/")
    if not _is_ip(address.strip()):
        return "", ""
    address = address.strip()
    if not length:
        return address, str(ipaddress.ip_network(address))
    try:
        return address, str(ipaddress.ip_interface(f"{address}/{length.strip()}").network)
    except ValueError:
        return address, ""


def _bare(value: Any) -> str:
    """An address without its prefix length (``203.0.113.2/30`` -> ``203.0.113.2``)."""
    return _text(value).split("/", 1)[0].strip()


def merge_config(first: Any, second: Any) -> Any:
    """Two configuration trees merged, ``first`` winning: a template stack
    over its templates, a template over the next one. Entry lists merge by
    name."""
    if first in (None, "", [], {}):
        return second
    if second in (None, "", [], {}):
        return first
    if isinstance(first, dict) and isinstance(second, dict):
        merged = dict(second)
        for key, value in first.items():
            merged[key] = merge_config(value, second.get(key))
        return merged
    if isinstance(first, list) and isinstance(second, list):
        if all(isinstance(i, dict) and "@name" in i for i in first + second):
            by_name = {i["@name"]: i for i in second}
            merged_list = [merge_config(i, by_name.get(i["@name"])) for i in first]
            seen = {i["@name"] for i in first}
            return merged_list + [i for i in second if i["@name"] not in seen]
        return first
    return first


def _variables(*lists: Any) -> dict[str, str]:
    """Template variables by name, the first list winning."""
    found: dict[str, str] = {}
    for items in lists:
        for item in entries(items):
            name = _name(item)
            value = _dict(item.get("type"))
            text = next((_text(v) for v in value.values() if _text(v)), "") if value else _text(item.get("value"))
            if name and text:
                found.setdefault(name, text)
    return found


def _substitute(value: Any, variables: dict[str, str], unresolved: set[str]) -> Any:
    """``value`` with every ``$variable`` replaced by its value; one with no
    value stays as written and is added to ``unresolved``."""
    if isinstance(value, dict):
        return {k: _substitute(v, variables, unresolved) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, variables, unresolved) for v in value]
    if isinstance(value, str) and value.startswith("$"):
        if value in variables:
            return variables[value]
        unresolved.add(value)
    return value


# ── Objects ──────────────────────────────────────────────────────────────────


class Objects:
    """Address and service objects of shared and every device group, so the
    names in rules resolve to networks and ports through the device group
    hierarchy: the firewall's own device group, its ancestors, then shared."""

    def __init__(self, raw: Any, parents: dict[str, str]) -> None:
        self.parents = parents
        self.by_scope: dict[str, dict[str, dict[str, dict]]] = {}
        for scope, kinds in _dict(raw).items():
            self.by_scope[scope] = {
                kind: {_name(item).lower(): item for item in entries(items) if _name(item)}
                for kind, items in _dict(kinds).items()
            }

    def chain(self, device_group: str) -> list[str]:
        if not device_group:
            return [SHARED]
        return [device_group, *ancestors(device_group, self.parents), SHARED]

    def find(self, kind: str, name: str, device_group: str) -> tuple[dict | None, str]:
        key = _text(name).lower()
        for scope in self.chain(device_group):
            item = self.by_scope.get(scope, {}).get(kind, {}).get(key)
            if item is not None:
                return item, scope
        return None, ""

    def count(self, kind: str) -> int:
        return sum(len(kinds.get(kind, {})) for kinds in self.by_scope.values())

    def listed(self, kind: str) -> list[tuple[str, dict]]:
        """``(scope, object)`` of every object of ``kind``, shared first."""
        scopes = sorted(self.by_scope, key=lambda s: (s != SHARED, s.lower()))
        return [(scope, item) for scope in scopes for item in self.by_scope[scope].get(kind, {}).values()]

    @staticmethod
    def address_value(item: dict) -> tuple[str, str]:
        """``(type, value)`` of an address object."""
        for key, label in (("ip-netmask", "IP netmask"), ("ip-range", "IP range"), ("fqdn", "FQDN")):
            if _text(item.get(key)):
                return label, _text(item.get(key))
        if _text(item.get("ip-wildcard")):
            return "IP wildcard", _text(item.get("ip-wildcard"))
        return "", ""

    def addresses(self, name: str, device_group: str, depth: int = 0) -> tuple[list[str], list[str]]:
        """``(cidrs, unresolved)`` an address name stands for: ``any``, a
        literal address, network or range, an address object or a static
        group (every member); an FQDN, a wildcard, a dynamic group or a name
        that is no object (a region, an external list) is unresolved."""
        text = _text(name)
        if not text or text.lower() == "any":
            return ["any"], []
        literal = value_cidr(text)
        if literal:
            return [literal], []
        item, _scope = self.find("address", text, device_group)
        if item is not None:
            kind, value = self.address_value(item)
            cidr = value_cidr(value) if kind in ("IP netmask", "IP range") else ""
            if cidr:
                return [cidr], []
            return [], [f"{kind or 'address'} {text}" + (f" ({value})" if value and value != text else "")]
        group, _scope = self.find("address-group", text, device_group)
        if group is not None:
            dynamic = _dict(group.get("dynamic"))
            if dynamic or "dynamic" in group:
                return [], [f"dynamic address group {text} ({_text(dynamic.get('filter'))})".replace(" ()", "")]
            if depth >= _MAX_GROUP_DEPTH:
                return [], [f"address group {text}"]
            cidrs: list[str] = []
            unresolved: list[str] = []
            for member in members(group.get("static")):
                found, bad = self.addresses(member, device_group, depth + 1)
                cidrs += [c for c in found if c not in cidrs]
                unresolved += bad
            return cidrs, unresolved
        return [], [text]

    def describe(self, name: str, device_group: str) -> str:
        """An address name as "name (value)" when it is an object."""
        text = _text(name)
        item, _scope = self.find("address", text, device_group)
        if item is not None:
            _kind, value = self.address_value(item)
            return f"{text} ({value})" if value and value != text else text
        return text

    def services(self, name: str, device_group: str, depth: int = 0) -> tuple[list[tuple[str, str]], list[str]]:
        """``([(protocol, ports)], unresolved)`` a service name stands for."""
        text = _text(name)
        if not text or text.lower() == "any":
            return [("any", "any")], []
        item, _scope = self.find("service", text, device_group)
        if item is not None:
            protocol = _dict(item.get("protocol"))
            for proto in ("tcp", "udp"):
                if proto in protocol:
                    port = _text(_dict(protocol[proto]).get("port")).replace(" ", "") or "any"
                    unresolved = []
                    if _text(_dict(protocol[proto]).get("source-port")):
                        unresolved.append(f"source port {_text(_dict(protocol[proto]).get('source-port'))}")
                    return [(proto, port)], unresolved
            return [], [f"service {text}"]
        if text.lower() in PREDEFINED_SERVICES:
            return list(PREDEFINED_SERVICES[text.lower()]), []
        group, _scope = self.find("service-group", text, device_group)
        if group is not None and depth < _MAX_GROUP_DEPTH:
            found: list[tuple[str, str]] = []
            unresolved: list[str] = []
            for member in members(group.get("members")):
                entries_found, bad = self.services(member, device_group, depth + 1)
                found += entries_found
                unresolved += bad
            return found, unresolved
        return [], [f"service {text}"]

    def service_text(self, name: str, device_group: str) -> str:
        """A service name as "name (tcp/443)" when it is an object."""
        text = _text(name)
        if text.lower() in ("any", "application-default"):
            return text
        found, bad = self.services(text, device_group)
        ports = ", ".join(f"{p}/{port}" for p, port in found)
        return f"{text} ({ports})" if ports and not bad else text


# ── The builder ──────────────────────────────────────────────────────────────


class _Builder:
    def __init__(self, raw: dict, inventory: InventoryIndex) -> None:
        self.raw = raw
        self.inventory = inventory
        self.options = {**DEFAULT_OPTIONS, **_dict(raw.get("options"))}
        self.devices = [d for d in entries(raw.get("devices")) if _text(d.get("serial")) or _name(d)]
        for device in self.devices:
            device.setdefault("serial", _name(device))
        self.device_by_serial = {_text(d["serial"]): d for d in self.devices}
        self.device_groups = entries(raw.get("device_groups"))
        self.parents = {str(k): _text(v) for k, v in _dict(raw.get("dg_parents")).items()}
        for group in self.device_groups:
            self.parents.setdefault(_name(group), "")
        self.dg_of = device_group_members(self.device_groups)
        self.objects = Objects(raw.get("objects"), self.parents)
        self.templates = entries(raw.get("templates"))
        self.stacks = entries(raw.get("template_stacks"))
        self.stack_config = entries(raw.get("stack_config"))
        self.assignment = stack_of_devices(self.stacks, self.templates, self.stack_config)
        self.stack_by_name: dict[str, dict] = {_name(s): s for s in self.stack_config if _name(s)}
        for stack in self.stacks:
            self.stack_by_name.setdefault(_name(stack), stack)
        self.template_config = _dict(raw.get("template_config"))
        self.state = _dict(raw.get("state"))
        self.state_skipped = _dict(raw.get("state_skipped"))
        security = raw.get("security_rules")
        self.security_collected = isinstance(security, dict)
        self.security_rules = _dict(security)
        self.default_rules = _dict(raw.get("default_rules"))
        nat = raw.get("nat_rules")
        self.nat_collected = isinstance(nat, dict)
        self.nat_rules = _dict(nat)
        self.unsupported = [_text(p) for p in raw.get("unsupported") or [] if _text(p)]

        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.sites: list[dict] = []
        self.pool_count = 0
        self.connected_count = 0
        self.user_count = 0
        self.users_collected = False

        # Filled while drawing.
        self.config: dict[str, dict[str, Any]] = {}
        self.rows: dict[str, list[dict[str, Any]]] = {}
        self.tunnels: dict[str, list[dict[str, Any]]] = {}
        self.box_of: dict[str, str] = {}
        self.primary_of: dict[str, str] = {}
        self.endpoint_ips: dict[str, list[str]] = {}

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

    def hostname(self, serial: str) -> str:
        return _text(self.device_by_serial.get(serial, {}).get("hostname")) or serial

    def device_group(self, serial: str) -> str:
        return self.dg_of.get(serial, "")

    def dg_chain_text(self, serial: str) -> str:
        group = self.device_group(serial)
        chain = [*reversed(ancestors(group, self.parents)), group] if group else []
        return " > ".join(["Shared", *chain])

    def vsys_names(self, serial: str) -> list[str]:
        names = [_name(v) for v in entries(self.device_by_serial.get(serial, {}).get("vsys")) if _name(v)]
        return names or ["vsys1"]

    def state_of(self, serial: str) -> dict[str, Any]:
        return _dict(self.state.get(serial))

    # ── Template configuration ─────────────────────────────────────────────

    def stack_name(self, serial: str) -> str:
        return _text(_dict(self.assignment.get(serial)).get("stack"))

    def template_names(self, serial: str) -> list[str]:
        assigned = _dict(self.assignment.get(serial))
        stack = self.stack_by_name.get(_text(assigned.get("stack")), {})
        return stack_templates(stack) or [n for n in [_text(assigned.get("template"))] if n]

    def firewall_config(self, serial: str) -> dict[str, Any]:
        """The merged configuration of a firewall's template stack: the
        stack's own settings over its templates, in order, with the template
        variables substituted."""
        if serial in self.config:
            return self.config[serial]
        stack = self.stack_by_name.get(self.stack_name(serial), {})
        names = self.template_names(serial)
        parts = [_dict(self.template_config.get(n)) for n in names]
        stack_device = next(iter(entries(_dict(_dict(stack.get("config")).get("devices")))), {})
        own = {
            "interface": _dict(stack_device.get("network")).get("interface"),
            "virtual-router": entries(_dict(stack_device.get("network")).get("virtual-router")),
            "vsys": entries(stack_device.get("vsys")),
            "ike-gateway": entries(_dict(_dict(stack_device.get("network")).get("ike")).get("gateway")),
            "ipsec": entries(_dict(_dict(stack_device.get("network")).get("tunnel")).get("ipsec")),
            "global-protect-gateway": entries(
                _dict(_dict(stack_device.get("network")).get("tunnel")).get("global-protect-gateway")
            ),
        }
        merged: dict[str, Any] = {}
        read: set[str] = set()
        for key in ("interface", "virtual-router", "vsys", "ike-gateway", "ipsec", "global-protect-gateway"):
            value: Any = own.get(key)
            for part in parts:
                if key in part:
                    read.add(key)
                value = merge_config(value, part.get(key))
            merged[key] = value
        variables = _variables(stack.get("variable"), *[p.get("variable") for p in parts])
        unresolved: set[str] = set()
        merged = _substitute(merged, variables, unresolved)
        merged["read"] = read
        merged["unresolved"] = sorted(unresolved)
        merged["templates"] = names
        self.config[serial] = merged
        return merged

    # ── Interfaces ─────────────────────────────────────────────────────────

    def _config_rows(self, serial: str) -> list[dict[str, Any]]:
        config = self.firewall_config(serial)
        interface = _dict(config.get("interface"))
        rows: list[dict[str, Any]] = []

        def add(entry: dict, kind: str, *, mode: str = "", ips: Any = None, tag: str = "", parent: str = "") -> None:
            addresses = [_name(i) for i in entries(ips)] or members(ips)
            v4 = [a for a in addresses if interface_address(a)[0] and ":" not in interface_address(a)[0]]
            v6 = [interface_address(a) for a in addresses if interface_address(a)[0] and ":" in interface_address(a)[0]]
            ip, cidr = interface_address(v4[0]) if v4 else ("", "")
            literal = next((a for a in addresses if not interface_address(a)[0]), "")
            rows.append(
                {
                    "name": _name(entry),
                    "type": kind,
                    "mode": mode,
                    "zone": "",
                    "vsys": "",
                    "vr": "",
                    "ip": ip,
                    "cidr": cidr,
                    "ipv6": v6,
                    "address_text": literal,
                    "enabled": _text(entry.get("link-state")).lower() != "down",
                    "state": "",
                    "comment": _text(entry.get("comment")),
                    "profile": _text(entry.get("interface-management-profile")),
                    "tag": tag,
                    "parent": parent,
                    "source": "template",
                }
            )

        for key, label in (("ethernet", "Ethernet"), ("aggregate-ethernet", "Aggregate ethernet")):
            for entry in entries(interface.get(key)):
                if _text(entry.get("aggregate-group")):
                    add(entry, "Aggregate member", mode=f"member of {_text(entry.get('aggregate-group'))}")
                    continue
                layer3 = _dict(entry.get("layer3"))
                mode = next(
                    (
                        m
                        for k, m in (
                            ("layer3", "Layer 3"),
                            ("layer2", "Layer 2"),
                            ("virtual-wire", "Virtual wire"),
                            ("tap", "Tap"),
                            ("ha", "HA"),
                            ("decrypt-mirror", "Decrypt mirror"),
                        )
                        if k in entry
                    ),
                    "",
                )
                if "dhcp-client" in layer3:
                    mode = "Layer 3 (DHCP)"
                profile = _text(layer3.get("interface-management-profile"))
                add(entry, label, mode=mode, ips=layer3.get("ip"))
                if profile:
                    rows[-1]["profile"] = profile
                for unit in entries(layer3.get("units")):
                    add(unit, "Sub-interface", mode="Layer 3", ips=unit.get("ip"), tag=_text(unit.get("tag")))
                    rows[-1]["parent"] = _name(entry)
                    rows[-1]["profile"] = _text(unit.get("interface-management-profile"))
        for key, label in (("vlan", "VLAN"), ("loopback", "Loopback"), ("tunnel", "Tunnel")):
            holder = _dict(interface.get(key))
            for unit in entries(holder.get("units")):
                add(unit, label, mode="Layer 3", ips=unit.get("ip"), tag=_text(unit.get("tag")))
        return rows

    def _zone_maps(self, serial: str) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
        """interface name -> zone, -> vsys, -> virtual router (from the templates)."""
        config = self.firewall_config(serial)
        zone_of: dict[str, str] = {}
        vsys_of: dict[str, str] = {}
        vr_of: dict[str, str] = {}
        for vsys in entries(config.get("vsys")):
            for zone in entries(vsys.get("zone")):
                for _mode, names in _dict(zone.get("network")).items():
                    for name in members(names):
                        zone_of.setdefault(name, _name(zone))
                        vsys_of.setdefault(name, _name(vsys))
            imported = _dict(_dict(vsys.get("import")).get("network"))
            for name in members(imported.get("interface")):
                vsys_of.setdefault(name, _name(vsys))
        for router in entries(config.get("virtual-router")):
            for name in members(router.get("interface")):
                vr_of.setdefault(name, _name(router))
        return zone_of, vsys_of, vr_of

    def zones(self, serial: str) -> list[dict[str, Any]]:
        """Every zone of a firewall: name, vsys, type, interfaces."""
        found: list[dict[str, Any]] = []
        for vsys in entries(self.firewall_config(serial).get("vsys")):
            for zone in entries(vsys.get("zone")):
                network = _dict(zone.get("network"))
                kind = next(iter(network), "")
                names = [n for _m, value in network.items() for n in members(value)]
                found.append({"zone": _name(zone), "vsys": _name(vsys), "type": kind, "interfaces": names})
        if not found:
            # No template zones read: the zones the firewall reported.
            by_zone: dict[tuple[str, str], list[str]] = {}
            for row in self.rows.get(serial, []):
                if row["zone"]:
                    by_zone.setdefault((row["zone"], row["vsys"]), []).append(row["name"])
            found = [{"zone": z, "vsys": v, "type": "", "interfaces": n} for (z, v), n in by_zone.items()]
        return found

    def interface_rows(self, serial: str) -> list[dict[str, Any]]:
        """The interfaces of a firewall: the templates' configuration, with
        what the firewall reported (real addresses, zone, state) winning."""
        rows = self._config_rows(serial)
        zone_of, vsys_of, vr_of = self._zone_maps(serial)
        multi = len(self.vsys_names(serial)) > 1
        for row in rows:
            row["zone"] = zone_of.get(row["name"], "")
            row["vsys"] = vsys_of.get(row["name"], "") or ("vsys1" if not multi and (row["ip"] or row["zone"]) else "")
            row["vr"] = vr_of.get(row["name"], "")
        state = _dict(self.state_of(serial).get("interfaces"))
        if state:
            by_name = {r["name"]: r for r in rows}
            hardware = {_text(h.get("name")): h for h in entries(state.get("hw"))}
            for entry in entries(state.get("ifnet")):
                name = _text(entry.get("name"))
                if not name:
                    continue
                row = by_name.get(name)
                if row is None:
                    row = {
                        "name": name,
                        "type": _kind_of_name(name),
                        "mode": "",
                        "zone": "",
                        "vsys": "",
                        "vr": "",
                        "ip": "",
                        "cidr": "",
                        "ipv6": [],
                        "address_text": "",
                        "enabled": True,
                        "state": "",
                        "comment": "",
                        "profile": "",
                        "tag": _text(entry.get("tag")) if _text(entry.get("tag")) not in ("", "0") else "",
                        "parent": name.split(".", 1)[0] if "." in name else "",
                        "source": "state",
                    }
                    rows.append(row)
                    by_name[name] = row
                ip, cidr = interface_address(entry.get("ip"))
                if ip:
                    row["ip"], row["cidr"] = ip, cidr
                    row["source"] = "state"
                zone = _text(entry.get("zone"))
                if zone and zone.upper() != "N/A":
                    row["zone"] = zone
                vsys = _text(entry.get("vsys"))
                if vsys.isdigit():
                    row["vsys"] = f"vsys{vsys}"
                forward = _text(entry.get("fwd"))
                if forward.startswith("vr:"):
                    row["vr"] = forward.removeprefix("vr:")
                hw = hardware.get(name) or hardware.get(name.split(".", 1)[0]) or {}
                link = _text(hw.get("state")).lower()
                if link:
                    row["state"] = link
                    row["enabled"] = link == "up"
        return rows

    @staticmethod
    def find_interface(rows: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
        wanted = _text(name).lower()
        return next((r for r in rows if wanted and r["name"].lower() == wanted), None)

    # ── Routing ────────────────────────────────────────────────────────────

    def virtual_routers(self, serial: str) -> list[dict]:
        return entries(self.firewall_config(serial).get("virtual-router"))

    def static_routes(self, serial: str) -> list[dict[str, Any]]:
        """The configured static routes: name, destination, its network,
        interface, next hop, metric, virtual router, enabled, tracked."""
        found: list[dict[str, Any]] = []
        for router in self.virtual_routers(serial):
            table = _dict(_dict(router.get("routing-table")).get("ip"))
            for route in entries(table.get("static-route")):
                destination = _text(route.get("destination"))
                nexthop = _dict(route.get("nexthop"))
                gateway = _text(nexthop.get("ip-address"))
                next_vr = _text(nexthop.get("next-vr"))
                found.append(
                    {
                        "name": _name(route),
                        "destination": destination,
                        "cidr": value_cidr(destination),
                        "interface": _text(route.get("interface")),
                        "gateway": gateway,
                        "next_vr": next_vr,
                        "discard": "discard" in nexthop,
                        "fqdn": _text(nexthop.get("fqdn")),
                        "metric": _text(route.get("metric")),
                        "vr": _name(router),
                        "tracked": _yes(_dict(route.get("path-monitor")).get("enable")),
                        "bfd": bool(_dict(route.get("bfd"))),
                    }
                )
        return found

    def route_table(self, serial: str) -> list[dict[str, Any]] | None:
        """The routing table the firewall reported (active and inactive
        entries), ``None`` when it was not read."""
        state = self.state_of(serial)
        if "routes" not in state:
            return None
        found: list[dict[str, Any]] = []
        for entry in entries(_dict(state.get("routes")).get("entry") if isinstance(state.get("routes"), dict) else []):
            flags = _text(entry.get("flags"))
            found.append(
                {
                    "destination": _text(entry.get("destination")),
                    "nexthop": _text(entry.get("nexthop")),
                    "interface": _text(entry.get("interface")),
                    "metric": _text(entry.get("metric")),
                    "flags": flags,
                    "protocol": _route_protocol(flags),
                    "active": "A" in flags.split(),
                    "vr": _text(entry.get("virtual-router")),
                    "age": _text(entry.get("age")),
                }
            )
        return found

    def default_egress(self, serial: str) -> dict[str, str]:
        """Interface name (lower-case) of each egress of an IPv4 default
        route -> its gateway."""
        found: dict[str, str] = {}
        for route in self.route_table(serial) or []:
            if route["destination"] == "0.0.0.0/0" and route["interface"] and route["active"]:
                found.setdefault(route["interface"].lower(), route["nexthop"])
        for route in self.static_routes(serial):
            if route["cidr"] == "0.0.0.0/0" and route["interface"]:
                found.setdefault(route["interface"].lower(), route["gateway"])
        return found

    def bgp_peers(self, serial: str) -> list[dict[str, Any]]:
        """The configured BGP peers, with the state the firewall reported."""
        state = {}
        for entry in entries(self.state_of(serial).get("bgp_peers")):
            state[(_text(entry.get("@vr")), _text(entry.get("@peer")))] = entry
        found: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for router in self.virtual_routers(serial):
            bgp = _dict(_dict(router.get("protocol")).get("bgp"))
            for group in entries(bgp.get("peer-group")):
                for peer in entries(group.get("peer")):
                    key = (_name(router), _name(peer))
                    seen.add(key)
                    live = state.get(key, {})
                    found.append(
                        {
                            "peer": _name(peer),
                            "group": _name(group),
                            "address": _bare(_dict(peer.get("peer-address")).get("ip"))
                            or _bare(live.get("peer-address")).split(":")[0],
                            "remote_as": _text(peer.get("peer-as")) or _text(live.get("remote-as")),
                            "local": _bare(_dict(peer.get("local-address")).get("ip"))
                            or _text(_dict(peer.get("local-address")).get("interface")),
                            "vr": _name(router),
                            "enabled": _text(peer.get("enable")).lower() != "no",
                            "state": _text(live.get("status")),
                            "since": _text(live.get("status-duration")),
                        }
                    )
        for (vr, name), live in state.items():
            if (vr, name) not in seen:
                found.append(
                    {
                        "peer": name,
                        "group": _text(live.get("peer-group")),
                        "address": _text(live.get("peer-address")).split(":")[0],
                        "remote_as": _text(live.get("remote-as")),
                        "local": _text(live.get("local-address")).split(":")[0],
                        "vr": vr,
                        "enabled": True,
                        "state": _text(live.get("status")),
                        "since": _text(live.get("status-duration")),
                    }
                )
        return found

    def _routing_sections(self, serial: str, rows: list[dict[str, Any]], sections: list[dict]) -> None:
        statics = self.static_routes(serial)
        _add(
            sections,
            table_section(
                STATIC_ROUTES_SECTION_TITLE,
                ["Destination", "Subnet", "Interface", "Gateway", "Metric", "Virtual router", "Tunneled", "Tracked"],
                [
                    [
                        r["name"] or r["destination"],
                        r["cidr"],
                        r["interface"],
                        r["gateway"]
                        or (f"next VR {r['next_vr']}" if r["next_vr"] else "")
                        or ("discard" if r["discard"] else r["fqdn"]),
                        r["metric"],
                        r["vr"],
                        _yes_no(r["interface"].lower().startswith("tunnel")),
                        _yes_no(r["tracked"]),
                    ]
                    for r in statics
                ],
            ),
        )
        table = self.route_table(serial)
        if table:
            _add(
                sections,
                table_section(
                    "Routing table",
                    ["Destination", "Next hop", "Interface", "Metric", "Protocol", "Flags", "Virtual router", "Age"],
                    [
                        [
                            r["destination"],
                            r["nexthop"],
                            r["interface"],
                            r["metric"],
                            r["protocol"],
                            r["flags"],
                            r["vr"],
                            r["age"],
                        ]
                        for r in table
                    ],
                ),
            )
        routers = self.virtual_routers(serial)
        vr_rows: list[list[Any]] = []
        for router in routers:
            protocol = _dict(router.get("protocol"))
            enabled = [
                label
                for key, label in (("bgp", "BGP"), ("ospf", "OSPF"), ("ospfv3", "OSPFv3"), ("rip", "RIP"))
                if _yes(_dict(protocol.get(key)).get("enable"))
            ]
            vr_rows.append(
                [
                    _name(router),
                    ", ".join(members(router.get("interface")))
                    or ", ".join(r["name"] for r in rows if r["vr"] == _name(router)),
                    sum(1 for r in statics if r["vr"] == _name(router)),
                    ", ".join(enabled),
                ]
            )
        if not routers:
            names = sorted({r["vr"] for r in rows if r["vr"]})
            vr_rows = [[n, ", ".join(r["name"] for r in rows if r["vr"] == n), "", ""] for n in names]
        _add(sections, table_section("Virtual routers", ["Name", "Interfaces", "Static routes", "Protocols"], vr_rows))

        for router in routers:
            bgp = _dict(_dict(router.get("protocol")).get("bgp"))
            if not bgp or not _yes(bgp.get("enable")):
                continue
            groups = entries(bgp.get("peer-group"))
            _add(
                sections,
                kv_section(
                    "BGP",
                    [
                        ("Virtual router", _name(router)),
                        ("Router ID", bgp.get("router-id")),
                        ("Local AS", bgp.get("local-as")),
                        ("Peer groups", ", ".join(_name(g) for g in groups)),
                        ("Peers", sum(len(entries(g.get("peer"))) for g in groups)),
                        ("Install routes", _text(_dict(bgp.get("routing-options")).get("as-format"))),
                    ],
                ),
            )
        _add(
            sections,
            table_section(
                "BGP peers",
                [
                    "Peer",
                    "Peer group",
                    "Peer address",
                    "Remote AS",
                    "Local address",
                    "Virtual router",
                    "Enabled",
                    "State",
                    "For (s)",
                ],
                [
                    [
                        p["peer"],
                        p["group"],
                        p["address"],
                        p["remote_as"],
                        p["local"],
                        p["vr"],
                        _yes_no(p["enabled"]),
                        p["state"],
                        p["since"],
                    ]
                    for p in self.bgp_peers(serial)
                ],
            ),
        )
        ospf_rows: list[list[Any]] = []
        for router in routers:
            ospf = _dict(_dict(router.get("protocol")).get("ospf"))
            if not ospf or not _yes(ospf.get("enable")):
                continue
            for area in entries(ospf.get("area")) or [{}]:
                area_type = _dict(area.get("type"))
                ospf_rows.append(
                    [
                        _name(router),
                        _text(ospf.get("router-id")),
                        _name(area),
                        next(iter(area_type), ""),
                        ", ".join(_name(i) for i in entries(area.get("interface"))),
                    ]
                )
        _add(sections, table_section("OSPF", ["Virtual router", "Router ID", "Area", "Type", "Interfaces"], ospf_rows))

    # ── VPN ────────────────────────────────────────────────────────────────

    def ike_gateways(self, serial: str) -> list[dict[str, Any]]:
        rows = self.rows.get(serial, [])
        found: list[dict[str, Any]] = []
        for gateway in entries(self.firewall_config(serial).get("ike-gateway")):
            local = _dict(gateway.get("local-address"))
            peer = _dict(gateway.get("peer-address"))
            local_if = _text(local.get("interface"))
            local_ip = _bare(local.get("ip"))
            if not _is_ip(local_ip):
                iface = self.find_interface(rows, local_if)
                local_ip = iface["ip"] if iface else ""
            protocol = _dict(gateway.get("protocol"))
            version = _text(protocol.get("version")) or ("ikev2" if "ikev2" in protocol else "ikev1")
            found.append(
                {
                    "name": _name(gateway),
                    "version": {"ikev1": "IKEv1", "ikev2": "IKEv2", "ikev2-preferred": "IKEv2 preferred"}.get(
                        version.lower(), version
                    ),
                    "local_if": local_if,
                    "local_ip": local_ip,
                    "peer_ip": _bare(peer.get("ip")),
                    "peer_text": _bare(peer.get("ip"))
                    or _text(peer.get("fqdn"))
                    or ("dynamic" if "dynamic" in peer else ""),
                    "disabled": _yes(gateway.get("disabled")),
                }
            )
        return found

    def _tunnel_states(self, serial: str) -> tuple[dict[str, dict], set[str] | None]:
        """Tunnel name -> its ``show vpn flow`` entry, and the tunnel names
        with an IPsec SA (``None`` when not read)."""
        state = self.state_of(serial)
        flow_holder = state.get("vpn_flow")
        flows: dict[str, dict] = {}
        if isinstance(flow_holder, dict):
            for entry in entries(flow_holder.get("IPSec") or flow_holder.get("ipsec")):
                flows[_text(entry.get("name"))] = entry
        sa_names: set[str] | None = None
        if "ipsec_sa" in state:
            sa_names = set()
            holder = state.get("ipsec_sa")
            found = entries(_dict(holder).get("entries")) if isinstance(holder, dict) else entries(holder)
            for entry in found:
                sa_names.add(_text(entry.get("name")).split(":", 1)[0])
        return flows, sa_names

    def plan_tunnels(self, serial: str) -> list[dict[str, Any]]:
        gateways = {g["name"]: g for g in self.ike_gateways(serial)}
        flows, sa_names = self._tunnel_states(serial)
        found: list[dict[str, Any]] = []
        for tunnel in entries(self.firewall_config(serial).get("ipsec")):
            auto = _dict(tunnel.get("auto-key"))
            gateway_names = [_name(g) for g in entries(auto.get("ike-gateway"))]
            gateway = gateways.get(gateway_names[0], {}) if gateway_names else {}
            proxies = [
                (
                    value_cidr(p.get("local")) or _text(p.get("local")),
                    value_cidr(p.get("remote")) or _text(p.get("remote")),
                )
                for p in entries(auto.get("proxy-id"))
            ]
            flow = flows.get(_name(tunnel), {})
            state = ""
            if flow:
                state = "up" if _text(flow.get("state")).lower() == "active" else "down"
            elif sa_names is not None:
                state = "up" if _name(tunnel) in sa_names else "down"
            elif "vpn_flow" in self.state_of(serial):
                state = "down"
            found.append(
                {
                    "name": _name(tunnel),
                    "iface": _text(tunnel.get("tunnel-interface")),
                    "gateway": _text(gateway.get("name")) or ", ".join(gateway_names),
                    "peer_ip": _text(gateway.get("peer_ip")),
                    "peer_text": _text(gateway.get("peer_text")),
                    "local_if": _text(gateway.get("local_if")),
                    "local_ip": _text(gateway.get("local_ip")),
                    "version": _text(gateway.get("version")),
                    "proxies": proxies,
                    "crypto": _text(auto.get("ipsec-crypto-profile")),
                    "state": state,
                    "monitor": _text(flow.get("mon") or flow.get("monitor"))
                    or ("on" if _yes(_dict(tunnel.get("tunnel-monitor")).get("enable")) else ""),
                    "disabled": _yes(tunnel.get("disabled")),
                    "far": "",
                    "far_kind": "",
                    "far_label": "",
                }
            )
        return found

    def gp_gateways(self, serial: str) -> list[dict[str, Any]]:
        """GlobalProtect gateways of a firewall: name, vsys, interface,
        address, tunnel interface, address pools."""
        config = self.firewall_config(serial)
        rows = self.rows.get(serial, [])
        network = {_text(g.get("tunnel-interface")): g for g in entries(config.get("global-protect-gateway"))}
        found: list[dict[str, Any]] = []
        used: set[str] = set()

        def pools(item: Any) -> list[str]:
            collected: list[str] = []

            def walk(value: Any) -> None:
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key == "ip-pool":
                            collected.extend(p for p in members(child) if p not in collected)
                        else:
                            walk(child)
                elif isinstance(value, list):
                    for child in value:
                        walk(child)

            walk(item)
            return collected

        def add(gateway: dict, vsys: str, tunnel_if: str, extra: dict) -> None:
            local = _dict(gateway.get("local-address")) or _dict(extra.get("local-address"))
            local_if = _text(local.get("interface"))
            ip_holder = local.get("ip")
            address = _bare(_dict(ip_holder).get("ipv4") if isinstance(ip_holder, dict) else ip_holder)
            if not _is_ip(address):
                iface = self.find_interface(rows, local_if)
                address = iface["ip"] if iface else ""
            found.append(
                {
                    "name": _name(gateway),
                    "vsys": vsys,
                    "interface": local_if,
                    "ip": address,
                    "tunnel": tunnel_if,
                    "pools": pools(gateway) or pools(extra),
                }
            )

        for vsys in entries(config.get("vsys")):
            for gateway in entries(_dict(vsys.get("global-protect")).get("global-protect-gateway")):
                tunnel_if = _text(gateway.get("remote-user-tunnel")) or _text(gateway.get("tunnel-interface"))
                used.add(tunnel_if)
                add(gateway, _name(vsys), tunnel_if, network.get(tunnel_if, {}))
        for tunnel_if, gateway in network.items():
            if tunnel_if not in used:
                add(gateway, "", tunnel_if, {})
        return found

    def gp_users(self, serial: str) -> list[dict] | None:
        """The connected GlobalProtect users, ``None`` when not read."""
        state = self.state_of(serial)
        if "gp_users" not in state:
            return None
        return entries(state.get("gp_users"))

    # ── Rules ──────────────────────────────────────────────────────────────

    def _targets(self, rule: dict, serial: str) -> bool:
        target = _dict(rule.get("target"))
        devices = entries(target.get("devices"))
        if not devices:
            return True
        vsys = set(self.vsys_names(serial))
        hit = False
        for device in devices:
            if _name(device) != serial:
                continue
            listed = {_name(v) for v in entries(device.get("vsys"))}
            hit = hit or not listed or bool(listed & vsys)
        return hit != _yes(target.get("negate"))

    def _chain(self, rules: dict[str, Any], serial: str) -> list[tuple[str, str, dict]]:
        """``(rulebase label, device group, rule)`` in the order the firewall
        applies them, without the rules whose target leaves it out."""
        group = self.device_group(serial)
        above = ancestors(group, self.parents) if group else []
        pre = [SHARED, *reversed(above), *([group] if group else [])]
        post = list(reversed(pre))
        found: list[tuple[str, str, dict]] = []
        for base, scopes in (("pre", pre), ("post", post)):
            for scope in scopes:
                for rule in entries(_dict(rules.get(scope)).get(base)):
                    if self._targets(rule, serial):
                        label = "Shared" if scope == SHARED else scope
                        found.append((f"{label} {base}", group, rule))
        return found

    def security_chain(self, serial: str) -> list[tuple[str, str, dict]]:
        return self._chain(self.security_rules, serial)

    def nat_chain(self, serial: str) -> list[tuple[str, str, dict]]:
        return self._chain(self.nat_rules, serial)

    def excluded_rules(self, serial: str) -> int:
        """Rules of the firewall's device groups whose target leaves it out."""
        group = self.device_group(serial)
        scopes = [SHARED, *ancestors(group, self.parents), *([group] if group else [])]
        count = 0
        for scope in scopes:
            for base in ("pre", "post"):
                count += sum(
                    1
                    for rule in entries(_dict(self.security_rules.get(scope)).get(base))
                    if not self._targets(rule, serial)
                )
        return count

    def default_actions(self, serial: str) -> dict[str, tuple[str, str, bool]]:
        """``name -> (action, where, logged)`` of the two default rules: an
        override of the nearest device group wins, then shared, then the
        built-in action."""
        group = self.device_group(serial)
        scopes = [*([group] if group else []), *ancestors(group, self.parents), SHARED]
        found: dict[str, tuple[str, str, bool]] = {}
        for name, builtin in DEFAULT_RULES:
            found[name] = (builtin, "built-in", False)
            for scope in scopes:
                rule = next((r for r in entries(self.default_rules.get(scope)) if _name(r) == name), None)
                if rule is not None and _text(rule.get("action")):
                    found[name] = (
                        _text(rule.get("action")),
                        "Shared" if scope == SHARED else scope,
                        _yes(rule.get("log-end")),
                    )
                    break
        return found

    def _security_rows(self, serial: str) -> list[list[Any]]:
        objects = self.objects
        rows: list[list[Any]] = []
        for index, (base, group, rule) in enumerate(self.security_chain(serial), start=1):
            source = ", ".join(objects.describe(s, group) for s in members(rule.get("source")))
            destination = ", ".join(objects.describe(d, group) for d in members(rule.get("destination")))
            log = [label for key, label in (("log-start", "start"), ("log-end", "end")) if _yes(rule.get(key))]
            profile = _dict(rule.get("profile-setting"))
            rows.append(
                [
                    index,
                    _name(rule),
                    base,
                    _text(rule.get("action")),
                    _yes_no(not _yes(rule.get("disabled"))),
                    ", ".join(members(rule.get("from"))) or "any",
                    ", ".join(members(rule.get("to"))) or "any",
                    ("not " if _yes(rule.get("negate-source")) else "") + (source or "any"),
                    ", ".join(members(rule.get("source-user"))) or "any",
                    ("not " if _yes(rule.get("negate-destination")) else "") + (destination or "any"),
                    ", ".join(members(rule.get("application"))) or "any",
                    ", ".join(objects.service_text(s, group) for s in members(rule.get("service"))) or "any",
                    ", ".join(members(profile.get("group"))) or ("profiles" if _dict(profile.get("profiles")) else ""),
                    ", ".join(log) or "No",
                    ", ".join(members(rule.get("tag"))),
                    _text(rule.get("description")),
                ]
            )
        offset = len(rows)
        for position, (name, (action, where, logged)) in enumerate(self.default_actions(serial).items(), start=1):
            rows.append(
                [
                    offset + position,
                    name,
                    f"default ({where})",
                    action,
                    "Yes",
                    "any",
                    "same zone" if name == "intrazone-default" else "any other zone",
                    "any",
                    "any",
                    "any",
                    "any",
                    "any",
                    "",
                    "end" if logged else "No",
                    "",
                    "Allows traffic within a zone"
                    if name == "intrazone-default"
                    else "Denies traffic between zones that no rule allows",
                ]
            )
        return rows

    def _nat_rows(self, serial: str) -> list[list[Any]]:
        objects = self.objects
        rows: list[list[Any]] = []
        for index, (base, group, rule) in enumerate(self.nat_chain(serial), start=1):
            rows.append(
                [
                    index,
                    _name(rule),
                    base,
                    _yes_no(not _yes(rule.get("disabled"))),
                    ", ".join(members(rule.get("from"))) or "any",
                    ", ".join(members(rule.get("to"))) or "any",
                    _text(rule.get("to-interface")) or "any",
                    ", ".join(objects.describe(s, group) for s in members(rule.get("source"))) or "any",
                    ", ".join(objects.describe(d, group) for d in members(rule.get("destination"))) or "any",
                    objects.service_text(_text(rule.get("service")) or "any", group),
                    source_translation_text(rule),
                    destination_translation_text(rule),
                    _text(rule.get("description")),
                ]
            )
        return rows

    # ── Firewalls ──────────────────────────────────────────────────────────

    def _boxes(self) -> list[tuple[str, str, list[str], str]]:
        """``(site id, name, member serials, kind)`` of every box of
        firewalls on the map: one per HA pair or standalone firewall."""
        wanted = self.raw.get("on_map")
        ids = [_text(i) for i in wanted] if isinstance(wanted, list) else list(self.device_by_serial)
        drawn = [s for s in ids if s in self.device_by_serial]
        boxes: list[tuple[str, str, list[str], str]] = []
        placed: set[str] = set()
        for serial in drawn:
            if serial in placed:
                continue
            peer = ha_peer(self.device_by_serial[serial])
            if peer in drawn and peer not in placed and peer != serial:
                pair = sorted([serial, peer], key=lambda s: (not self._is_active(s), self.hostname(s).lower()))
                placed.update(pair)
                name = f"{self.hostname(pair[0])} / {self.hostname(pair[1])}"
                boxes.append((f"ha:{pair[0]}", name, pair, "ha"))
            else:
                placed.add(serial)
                boxes.append((f"dev:{serial}", self.hostname(serial), [serial], "device"))
        return sorted(boxes, key=lambda b: b[1].lower())

    def ha_state(self, serial: str) -> dict[str, str]:
        """``local``, ``peer``, ``mode``, ``sync`` of a firewall's HA state:
        what it reported, else what Panorama lists."""
        state = _dict(self.state_of(serial).get("ha"))
        group = _dict(state.get("group"))
        local = _dict(group.get("local-info"))
        peer = _dict(group.get("peer-info"))
        listed = _dict(self.device_by_serial.get(serial, {}).get("ha"))
        return {
            "enabled": _text(state.get("enabled")),
            "local": _text(local.get("state")) or _text(listed.get("state")),
            "peer": _text(peer.get("state")),
            "mode": _text(group.get("mode")),
            "sync": _text(group.get("running-sync")),
            "peer_link": _text(peer.get("conn-status")),
        }

    def _is_active(self, serial: str) -> bool:
        return self.ha_state(serial)["local"].lower().startswith("active")

    def _status(self, serial: str) -> str:
        device = self.device_by_serial.get(serial, {})
        if _text(device.get("connected")).lower() not in ("yes", ""):
            return "offline"
        local = self.ha_state(serial)["local"].lower()
        if local in ("suspended", "non-functional", "tentative"):
            return "alerting"
        return "online"

    def pending(self, serial: str) -> list[str]:
        """What a push has not yet reached on the firewall."""
        device = self.device_by_serial.get(serial, {})
        found: list[str] = []
        for key, label in (("shared-policy-status", "shared policy"), ("template-status", "template")):
            value = _text(device.get(key)).lower()
            if value and value not in ("in sync", "insync", "in-sync"):
                found.append(label)
        return found

    def build_firewalls(self) -> None:
        boxes = self._boxes()
        on_map = [m for _site, _name, ids, _kind in boxes for m in ids]
        for site_id, _box, ids, _kind in boxes:
            for serial in ids:
                self.box_of[serial] = site_id
                self.primary_of[serial] = ids[0]
        for serial in on_map:
            self.rows[serial] = self.interface_rows(serial)
        for serial in on_map:
            self.tunnels[serial] = self.plan_tunnels(serial)
        self._resolve_tunnel_ends(on_map)
        for site_id, box_name, ids, kind in boxes:
            site_sections: list[dict] = []
            box_nodes: list[dict] = []
            pools: dict[str, tuple[dict, list[str]]] = {}
            for serial in ids:
                node = self._firewall(serial, site_id, primary=serial == ids[0])
                box_nodes.append(node)
                box_nodes += self._wan_stubs(node, serial)
                gateways = self.gp_gateways(serial)
                if gateways and self.options.get("include_global_protect", True):
                    box_nodes.append(self._users_node(node, serial, gateways))
                for gateway in gateways:
                    for pool in gateway["pools"]:
                        entry = pools.setdefault(pool, (gateway, []))
                        if gateway["name"] not in entry[1]:
                            entry[1].append(gateway["name"])
            pool_rows = sorted(
                [
                    [value_cidr(pool), pool if "-" not in pool else f"{gateway['name']} pool", pool, ", ".join(names)]
                    for pool, (gateway, names) in pools.items()
                ],
                key=lambda r: (r[0] == "", r[0]),
            )
            self.pool_count += len(pool_rows)
            _add(site_sections, table_section(POOL_SECTION_TITLE, POOL_COLUMNS, pool_rows))
            if kind == "ha":
                self._ha_edge(ids)
            self.sites.append(
                {
                    "id": site_id,
                    "name": box_name,
                    "tags": ["ha"] if kind == "ha" else [],
                    "vpn_mode": "spoke",
                    "status": _worst([n["status"] for n in box_nodes]),
                    "device_count": len(ids),
                    "sections": site_sections,
                }
            )

    def _resolve_tunnel_ends(self, on_map: list[str]) -> None:
        """Which managed firewall (the first member of its box) answers on
        each tunnel's peer address."""
        owner: dict[str, str] = {}
        for serial in on_map:
            primary = self.primary_of.get(serial, serial)
            for row in self.rows.get(serial, []):
                if row["ip"]:
                    owner.setdefault(row["ip"], primary)
            for gateway in self.ike_gateways(serial):
                if gateway["local_ip"]:
                    owner.setdefault(gateway["local_ip"], primary)
                    known = self.endpoint_ips.setdefault(serial, [])
                    if gateway["local_ip"] not in known:
                        known.append(gateway["local_ip"])
        for serial in on_map:
            primary = self.primary_of.get(serial, serial)
            for tunnel in self.tunnels.get(serial, []):
                far = owner.get(tunnel["peer_ip"], "")
                if far and far != primary:
                    tunnel.update(far=f"d:{far}", far_kind="device", far_label=self.hostname(far))
                elif tunnel["peer_ip"] or tunnel["peer_text"]:
                    peer = tunnel["peer_ip"] or tunnel["peer_text"]
                    tunnel.update(far=f"p:{peer}", far_kind="peer", far_label=peer)

    def _ha_edge(self, ids: list[str]) -> None:
        if len(ids) < 2:
            return
        states = [self.ha_state(s)["local"].lower() for s in ids]
        statuses = [self.nodes[f"d:{s}"]["status"] for s in ids]
        failed = "offline" in statuses or any(s in ("suspended", "non-functional") for s in states)
        self._edge(
            f"d:{ids[0]}",
            f"d:{ids[1]}",
            "stack",
            a_port=states[0],
            b_port=states[1],
            status="failed" if failed else "active",
            label="HA",
            detail=self.ha_state(ids[0])["mode"],
        )

    def _firewall(self, serial: str, site_id: str, *, primary: bool) -> dict:
        device = self.device_by_serial[serial]
        name = self.hostname(serial)
        status = self._status(serial)
        mgmt = _text(device.get("ip-address"))
        rows = self.rows.get(serial, [])
        node = self._node(
            f"d:{serial}",
            "appliance",
            name,
            site_id,
            status,
            model=_text(device.get("model")),
            serial=serial,
            ip=mgmt if _is_ip(mgmt) else "",
            site_sections=True,
        )
        if self.endpoint_ips.get(serial):
            node["endpoint_ips"] = list(self.endpoint_ips[serial])
        host = self.inventory.match(serial=serial, ips=[node["ip"], *(r["ip"] for r in rows if r["ip"])])
        if host:
            node["inventory"] = _inventory_ref(host)

        sections = node["sections"]
        overview_at = len(sections)
        config = self.firewall_config(serial)
        _add(
            sections,
            table_section(
                INTERFACES_SECTION_TITLE,
                [
                    "Interface",
                    "Type",
                    "Zone",
                    "Virtual router",
                    "Vsys",
                    "IP address",
                    "Subnet",
                    "State",
                    "Tag",
                    "Management profile",
                    "Comment",
                    "Source",
                ],
                [
                    [
                        r["name"],
                        r["type"] + (f" ({r['mode']})" if r["mode"] and r["mode"] != "Layer 3" else ""),
                        r["zone"],
                        r["vr"],
                        r["vsys"],
                        ", ".join([r["ip"] or r["address_text"], *(a for a, _c in r["ipv6"])]).strip(", "),
                        ", ".join([r["cidr"], *(c for _a, c in r["ipv6"] if c)]).strip(", "),
                        r["state"] or ("enabled" if r["enabled"] else "down"),
                        r["tag"],
                        r["profile"],
                        r["comment"],
                        "firewall" if r["source"] == "state" else "template",
                    ]
                    for r in rows
                ],
            ),
        )
        _add(
            sections,
            table_section(
                "Zones",
                ["Zone", "Vsys", "Type", "Interfaces"],
                [[z["zone"], z["vsys"], z["type"], ", ".join(z["interfaces"])] for z in self.zones(serial)],
            ),
        )
        if config["unresolved"]:
            _add(
                sections,
                text_section(
                    "Template variables (note)",
                    "Not resolved from the template stack: " + ", ".join(config["unresolved"]),
                ),
            )
        # A passive HA member does not forward: the active member owns the subnets.
        owns = primary or not self._has_active_peer(serial) or "active-active" in self.ha_state(serial)["mode"].lower()
        connected: list[list[Any]] = []
        for r in rows:
            for cidr in [r["cidr"], *(c for _a, c in r["ipv6"])]:
                if cidr:
                    connected.append([cidr, r["name"], r["comment"], r["zone"], r["vr"]])
        if owns:
            self.connected_count += len(connected)
            _add(
                sections,
                table_section(
                    CONNECTED_SECTION_TITLE, ["Subnet", "Interface", "Name", "Zone", "Virtual router"], connected
                ),
            )
            self._routing_sections(serial, rows, sections)
        else:
            _add(
                sections,
                text_section(
                    "Connected subnets (note)",
                    f"This member is passive: its HA peer {self.hostname(self.primary_of.get(serial, ''))} "
                    "forwards the traffic and owns the subnets.",
                ),
            )
            routing: list[dict] = []
            self._routing_sections(serial, rows, routing)
            sections.extend(
                s for s in routing if s["title"] not in (STATIC_ROUTES_SECTION_TITLE, CONNECTED_SECTION_TITLE)
            )
        self._vpn_sections(serial, sections)
        self._policy_sections(serial, sections)
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
        ha = self.ha_state(serial)
        peer = ha_peer(device)
        state_note = (
            "read"
            if serial in self.state
            else (
                f"not read: {self.state_skipped[serial]}"
                if serial in self.state_skipped
                else ("not collected" if not self.options.get("include_device_state", True) else "not read")
            )
        )
        overview = kv_section(
            "Overview",
            [
                ("Name", name),
                ("Status", status),
                ("Model", node["model"]),
                ("Software", device.get("sw-version")),
                ("Serial", serial),
                ("Management address", mgmt),
                ("Connected to Panorama", _text(device.get("connected"))),
                ("Device group", self.device_group(serial)),
                ("Device group chain", self.dg_chain_text(serial)),
                ("Template stack", self.stack_name(serial)),
                ("Templates", ", ".join(config["templates"])),
                ("Virtual systems", ", ".join(self.vsys_names(serial)) if len(self.vsys_names(serial)) > 1 else ""),
                ("HA peer", self.hostname(peer) if peer else ""),
                ("HA state", ha["local"]),
                ("HA peer state", ha["peer"]),
                ("HA mode", ha["mode"]),
                ("HA config sync", ha["sync"]),
                ("Shared policy", device.get("shared-policy-status")),
                ("Template status", device.get("template-status")),
                ("Pending push", _yes_no(bool(self.pending(serial)))),
                ("App version", device.get("app-version")),
                ("Threat version", device.get("threat-version")),
                ("Uptime", device.get("uptime")),
                ("Device state", state_note),
            ],
        )
        if overview:
            sections.insert(overview_at, overview)
        return node

    def _has_active_peer(self, serial: str) -> bool:
        primary = self.primary_of.get(serial, serial)
        return primary != serial and f"d:{primary}" in self.nodes

    def _vpn_sections(self, serial: str, sections: list[dict]) -> None:
        tunnels = self.tunnels.get(serial, [])
        far_of = {t["gateway"]: t["far_label"] for t in tunnels if t["far_kind"] == "device"}
        _add(
            sections,
            table_section(
                "IKE gateways",
                ["Gateway", "Version", "Local interface", "Local address", "Peer address", "Peer"],
                [
                    [g["name"], g["version"], g["local_if"], g["local_ip"], g["peer_text"], far_of.get(g["name"], "")]
                    for g in self.ike_gateways(serial)
                ],
            ),
        )
        _add(
            sections,
            table_section(
                "IPsec tunnels",
                [
                    "Tunnel",
                    "Tunnel interface",
                    "IKE gateway",
                    "Peer",
                    "Peer address",
                    "Proxy IDs",
                    "Crypto profile",
                    "State",
                    "Monitor",
                ],
                [
                    [
                        t["name"],
                        t["iface"],
                        t["gateway"],
                        t["far_label"] if t["far_kind"] == "device" else "",
                        t["peer_text"],
                        ", ".join(f"{local} > {remote}" for local, remote in t["proxies"]),
                        t["crypto"],
                        t["state"] or "unknown",
                        t["monitor"],
                    ]
                    for t in tunnels
                ],
            ),
        )
        users = self.gp_users(serial)
        _add(
            sections,
            table_section(
                "GlobalProtect gateways",
                ["Gateway", "Vsys", "Interface", "Address", "Tunnel interface", "Address pools", "Connected users"],
                [
                    [
                        g["name"],
                        g["vsys"],
                        g["interface"],
                        g["ip"],
                        g["tunnel"],
                        ", ".join(g["pools"]),
                        len(users) if users is not None else "not collected",
                    ]
                    for g in self.gp_gateways(serial)
                ],
            ),
        )

    def _policy_sections(self, serial: str, sections: list[dict]) -> None:
        chain = self.security_chain(serial)
        defaults = self.default_actions(serial)
        nat = self.nat_chain(serial)
        _add(
            sections,
            kv_section(
                "Security policy",
                [
                    ("Device group", self.device_group(serial) or "none"),
                    ("Device group chain", self.dg_chain_text(serial)),
                    ("Security rules", len(chain) if self.security_collected else "not collected"),
                    (
                        "Pre-rules",
                        sum(1 for b, _g, _r in chain if b.endswith(" pre")) if self.security_collected else "",
                    ),
                    (
                        "Post-rules",
                        sum(1 for b, _g, _r in chain if b.endswith(" post")) if self.security_collected else "",
                    ),
                    ("Disabled rules", sum(1 for _b, _g, r in chain if _yes(r.get("disabled"))) or ""),
                    ("Rules targeting other firewalls", self.excluded_rules(serial) or ""),
                    ("Intrazone default", f"{defaults['intrazone-default'][0]} ({defaults['intrazone-default'][1]})"),
                    ("Interzone default", f"{defaults['interzone-default'][0]} ({defaults['interzone-default'][1]})"),
                    ("NAT rules", len(nat) if self.nat_collected else "not collected"),
                    ("Local rules", "not collected (rules configured on the firewall itself)"),
                ],
            ),
        )
        if self.security_collected:
            _add(sections, table_section("Security rules", SECURITY_RULE_COLUMNS, self._security_rows(serial)))
        if self.nat_collected:
            _add(sections, table_section("NAT rules", NAT_RULE_COLUMNS, self._nat_rows(serial)))

    def _wan_stubs(self, node: dict, serial: str) -> list[dict]:
        """A WAN stub per outside interface: one with a public address, the
        egress of the IPv4 default route, or a GlobalProtect gateway's."""
        egress = self.default_egress(serial)
        portals = {g["interface"].lower(): g["name"] for g in self.gp_gateways(serial) if g["interface"]}
        added: list[dict] = []
        for row in self.rows.get(serial, []):
            name = row["name"]
            if not name or not row["ip"] or row["type"] in ("Tunnel", "Loopback"):
                continue
            via = egress.get(name.lower())
            gateway = portals.get(name.lower())
            if not _is_public(row["ip"]) and via is None and gateway is None:
                continue
            wan_id = f"w:{serial}:{name}"
            if wan_id in self.nodes:
                continue
            wan = self._node(
                wan_id,
                "wan",
                f"{name} {row['ip']}",
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
                        ("Firewall", node["label"]),
                        ("Interface", name),
                        ("Zone", row["zone"]),
                        ("IP address", row["ip"]),
                        ("Subnet", row["cidr"]),
                        ("Default route via", via),
                        ("GlobalProtect gateway", gateway),
                        ("Virtual router", row["vr"]),
                        ("Comment", row["comment"]),
                    ],
                ),
            )
            self._edge(wan_id, node["id"], "uplink", b_port=name, status="active" if row["enabled"] else "failed")
            added.append(wan)
        return added

    def _users_node(self, node: dict, serial: str, gateways: list[dict]) -> dict:
        users = self.gp_users(serial)
        collected = users is not None
        self.users_collected = self.users_collected or collected
        count = len(users or [])
        self.user_count += count
        label = f"GlobalProtect users ({count})" if collected else "GlobalProtect users"
        node_users = self._node(
            f"u:{serial}",
            "users",
            label,
            node["site"],
            "online" if count else "unknown",
            model="GlobalProtect",
        )
        _add(
            node_users["sections"],
            kv_section(
                "Remote access users",
                [
                    ("Gateway", node["label"]),
                    ("GlobalProtect gateways", ", ".join(g["name"] for g in gateways)),
                    ("Connected now", count if collected else "not collected"),
                    (
                        "Source",
                        "Users connected to this firewall's GlobalProtect gateways when the collection ran"
                        if collected
                        else "Users were not collected (option off, or the firewall was not read)",
                    ),
                ],
            ),
        )
        rows = [
            [
                _text(u.get("username")),
                _text(u.get("domain")),
                _text(u.get("virtual-ip")),
                _text(u.get("public-ip")),
                _text(u.get("computer")),
                _text(u.get("client")),
                _text(u.get("app-version")),
                _text(u.get("tunnel-type")),
                _text(u.get("login-time")),
                _text(u.get("lifetime")),
            ]
            for u in (users or [])[:MAX_LISTED_USERS]
        ]
        _add(
            node_users["sections"],
            table_section(
                "Connected users",
                [
                    "User",
                    "Domain",
                    "Virtual IP",
                    "Public IP",
                    "Computer",
                    "Client",
                    "App version",
                    "Tunnel",
                    "Login time",
                    "Lifetime (s)",
                ],
                sorted(rows, key=lambda r: (str(r[0]).lower(), str(r[2]))),
            ),
        )
        self._edge(node_users["id"], node["id"], "vpn", status="reachable" if count else "", label="GlobalProtect")
        return node_users

    # ── Tunnels ────────────────────────────────────────────────────────────

    def build_tunnels(self) -> None:
        seen: dict[frozenset, dict] = {}
        for serial in [s for s in self.tunnels if self.primary_of.get(s) == s]:
            for tunnel in self.tunnels[serial]:
                if not tunnel["far"] or tunnel["disabled"]:
                    continue
                here = f"d:{serial}"
                if tunnel["far_kind"] == "peer" and tunnel["far"] not in self.nodes:
                    self._peer_node(tunnel)
                key = frozenset((here, tunnel["far"]))
                status = _TUNNEL_EDGE_STATUS.get(tunnel["state"], "")
                if key in seen:
                    edge = seen[key]
                    if status == "unreachable" or not edge["status"]:
                        edge["status"] = status or edge["status"]
                    if tunnel["name"] not in edge["detail"]:
                        edge["detail"] += f", {tunnel['name']}"
                    if edge["a"] == tunnel["far"]:
                        edge["a_port"] = edge["a_port"] or tunnel["iface"]
                    continue
                edge = self._edge(
                    here,
                    tunnel["far"],
                    "vpn" if tunnel["far_kind"] == "device" else "vpn3p",
                    a_port=tunnel["iface"],
                    status=status,
                    label="Site-to-site VPN" if tunnel["far_kind"] == "device" else "IPsec",
                    detail=tunnel["name"],
                )
                if edge is not None:
                    seen[key] = edge
        # The far end's tunnel interface of a tunnel between two firewalls.
        for edge in seen.values():
            if edge["kind"] != "vpn":
                continue
            far = edge["b"].removeprefix("d:")
            back = next((t for t in self.tunnels.get(far, []) if t["far"] == edge["a"]), None)
            if back is not None:
                edge["b_port"] = back["iface"]
                if _TUNNEL_EDGE_STATUS.get(back["state"]) == "unreachable":
                    edge["status"] = "unreachable"

    def _peer_node(self, tunnel: dict) -> None:
        peer = tunnel["far"].removeprefix("p:")
        names = sorted(
            {
                f"{self.hostname(s)} {t['name']}"
                for s, items in self.tunnels.items()
                for t in items
                if t["far"] == tunnel["far"]
            }
        )
        node = self._node(tunnel["far"], "vpn_peer", peer, VPN_PEER_SITE_ID, "unknown", ip=peer if _is_ip(peer) else "")
        _add(
            node["sections"],
            kv_section(
                "Site-to-site VPN peer",
                [
                    ("Address", peer),
                    ("IKE gateway", tunnel["gateway"]),
                    ("IKE version", tunnel["version"]),
                    ("Protected networks", ", ".join(r for _l, r in tunnel["proxies"])),
                    ("Tunnels", ", ".join(names)),
                    ("Source", "The peer of an IPsec tunnel of a firewall Panorama manages"),
                ],
            ),
        )

    # ── Panorama ───────────────────────────────────────────────────────────

    def build_panorama(self) -> None:
        info = _dict(self.raw.get("panorama"))
        host = _text(info.get("url")).removeprefix("https://").split("/", 1)[0].strip("[]")
        host_only = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        label = _text(info.get("name")) or (
            f"Panorama {_text(info.get('hostname')) or host_only}" if host_only else "Panorama"
        )
        address = _text(info.get("ip")) if _is_ip(_text(info.get("ip"))) else host_only
        node = self._node(
            PANORAMA_NODE_ID,
            "cloud",
            label,
            PANORAMA_SITE_ID,
            "online",
            model=_text(info.get("model")) or "Palo Alto Networks Panorama",
            serial=_text(info.get("serial")),
            ip=address if _is_ip(address) else "",
        )
        on_map = [n["id"].removeprefix("d:") for n in self.nodes.values() if n["kind"] == "appliance"]
        pending = [s for s in self.device_by_serial if self.pending(s)]
        pairs = self._pairs()
        not_connected = [s for s in self.device_by_serial if _text(self.device_by_serial[s].get("connected")) == "no"]
        security_count = sum(
            len(entries(_dict(v).get(b))) for v in self.security_rules.values() for b in ("pre", "post")
        )
        nat_count = sum(len(entries(_dict(v).get(b))) for v in self.nat_rules.values() for b in ("pre", "post"))
        _add(
            node["sections"],
            kv_section(
                "Palo Alto Panorama",
                [
                    ("Name", info.get("name")),
                    ("Hostname", info.get("hostname")),
                    ("Address", info.get("url")),
                    ("Version", info.get("version")),
                    ("Model", info.get("model")),
                    ("Serial", info.get("serial")),
                    ("Device group collected", info.get("device_group") or "every device group"),
                    ("Firewalls managed", len(self.devices)),
                    ("Firewalls on the map", len(on_map)),
                    ("HA pairs", len(pairs)),
                    ("Device groups", len(self.parents)),
                    ("Templates", len(self.templates)),
                    ("Template stacks", len(self.stack_by_name)),
                    ("Address objects", self.objects.count("address")),
                    ("Services", self.objects.count("service")),
                    ("Security rules", security_count if self.security_collected else "not collected"),
                    ("NAT rules", nat_count if self.nat_collected else "not collected"),
                    ("Firewalls pending push", len(pending)),
                    ("Firewalls not connected", len(not_connected)),
                    ("Connected users", self.user_count if self.users_collected else "not collected"),
                    ("Unsupported", ", ".join(self.unsupported)),
                    ("Snapshot time", self.raw.get("timestamp")),
                ],
            ),
        )
        pair_of = {s: f"{self.hostname(a)} / {self.hostname(b)}" for a, b in pairs for s in (a, b)}
        _add(
            node["sections"],
            table_section(
                "Managed firewalls",
                [
                    "Firewall",
                    "Serial",
                    "Model",
                    "Software",
                    "Management address",
                    "Connected",
                    "Device group",
                    "Template stack",
                    "HA pair",
                    "HA state",
                    "Shared policy",
                    "Template",
                    "On the map",
                ],
                [
                    [
                        self.hostname(s),
                        s,
                        d.get("model"),
                        d.get("sw-version"),
                        d.get("ip-address"),
                        d.get("connected"),
                        self.device_group(s),
                        self.stack_name(s) or _text(_dict(self.assignment.get(s)).get("template")),
                        pair_of.get(s, ""),
                        self.ha_state(s)["local"],
                        d.get("shared-policy-status"),
                        d.get("template-status"),
                        s in on_map,
                    ]
                    for s, d in sorted(self.device_by_serial.items(), key=lambda i: self.hostname(i[0]).lower())
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "High availability pairs",
                ["Pair", "Firewall", "Peer", "State", "Peer state", "Mode", "Config sync"],
                [
                    [
                        pair_of.get(a, ""),
                        self.hostname(a),
                        self.hostname(b),
                        self.ha_state(a)["local"],
                        self.ha_state(a)["peer"] or self.ha_state(b)["local"],
                        self.ha_state(a)["mode"],
                        self.ha_state(a)["sync"],
                    ]
                    for a, b in pairs
                ],
            ),
        )
        group_rows: list[list[Any]] = []
        for group in sorted(self.parents, key=str.lower):
            firewalls = sorted(self.hostname(s) for s, g in self.dg_of.items() if g == group)
            rules = _dict(self.security_rules.get(group))
            group_rows.append(
                [
                    group,
                    self.parents.get(group) or "Shared",
                    ", ".join(firewalls),
                    len(entries(rules.get("pre"))) if group in self.security_rules else "",
                    len(entries(rules.get("post"))) if group in self.security_rules else "",
                    sum(len(entries(_dict(self.nat_rules.get(group)).get(b))) for b in ("pre", "post"))
                    if group in self.nat_rules
                    else "",
                    len(_dict(self.objects.by_scope.get(group)).get("address", {}))
                    if group in self.objects.by_scope
                    else "",
                ]
            )
        _add(
            node["sections"],
            table_section(
                "Device groups",
                ["Device group", "Parent", "Firewalls", "Pre-rules", "Post-rules", "NAT rules", "Address objects"],
                group_rows,
            ),
        )
        stacks_of_template: dict[str, list[str]] = {}
        for name, stack in self.stack_by_name.items():
            for template in stack_templates(stack):
                stacks_of_template.setdefault(template, []).append(name)
        _add(
            node["sections"],
            table_section(
                "Templates",
                ["Template", "Template stacks", "Firewalls", "Variables", "Description"],
                [
                    [
                        _name(t),
                        ", ".join(stacks_of_template.get(_name(t), [])),
                        ", ".join(
                            sorted(
                                self.hostname(s) for s in self.device_by_serial if _name(t) in self.template_names(s)
                            )
                        ),
                        len(entries(_dict(self.template_config.get(_name(t))).get("variable"))) or "",
                        _text(t.get("description")),
                    ]
                    for t in sorted(self.templates, key=lambda t: _name(t).lower())
                ],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Template stacks",
                ["Template stack", "Templates", "Firewalls", "Variables"],
                [
                    [
                        name,
                        ", ".join(stack_templates(stack)),
                        ", ".join(
                            sorted(self.hostname(s) for s in self.device_by_serial if self.stack_name(s) == name)
                        ),
                        ", ".join(_name(v) for v in entries(stack.get("variable"))),
                    ]
                    for name, stack in sorted(self.stack_by_name.items(), key=lambda i: i[0].lower())
                ],
            ),
        )
        location = {SHARED: "Shared"}
        _add(
            node["sections"],
            table_section(
                "Address objects",
                ["Name", "Location", "Type", "Value", "Description", "Tags"],
                [
                    [
                        _name(o),
                        location.get(scope, scope),
                        *self.objects.address_value(o),
                        _text(o.get("description")),
                        ", ".join(members(o.get("tag"))),
                    ]
                    for scope, o in self.objects.listed("address")
                ][:MAX_LISTED_OBJECTS],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Address groups",
                ["Name", "Location", "Type", "Members / filter"],
                [
                    [
                        _name(g),
                        location.get(scope, scope),
                        "Dynamic" if "dynamic" in g else "Static",
                        _text(_dict(g.get("dynamic")).get("filter"))
                        if "dynamic" in g
                        else ", ".join(members(g.get("static"))),
                    ]
                    for scope, g in self.objects.listed("address-group")
                ][:MAX_LISTED_GROUPS],
            ),
        )
        service_rows: list[list[Any]] = []
        for scope, service in self.objects.listed("service"):
            protocol = _dict(service.get("protocol"))
            proto = next(iter(protocol), "")
            detail = _dict(protocol.get(proto))
            service_rows.append(
                [
                    _name(service),
                    location.get(scope, scope),
                    proto,
                    _text(detail.get("port")),
                    _text(detail.get("source-port")),
                    _text(service.get("description")),
                ]
            )
        _add(
            node["sections"],
            table_section(
                "Services",
                ["Name", "Location", "Protocol", "Port", "Source port", "Description"],
                service_rows[:MAX_LISTED_OBJECTS],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Service groups",
                ["Name", "Location", "Members"],
                [
                    [_name(g), location.get(scope, scope), ", ".join(members(g.get("members")))]
                    for scope, g in self.objects.listed("service-group")
                ][:MAX_LISTED_GROUPS],
            ),
        )
        _add(
            node["sections"],
            table_section(
                "Pending push",
                ["Firewall", "Device group", "Template stack", "Out of sync", "Shared policy", "Template"],
                [
                    [
                        self.hostname(s),
                        self.device_group(s),
                        self.stack_name(s),
                        ", ".join(self.pending(s)),
                        self.device_by_serial[s].get("shared-policy-status"),
                        self.device_by_serial[s].get("template-status"),
                    ]
                    for s in sorted(pending, key=lambda s: self.hostname(s).lower())
                ],
            ),
        )
        for serial in sorted(on_map):
            self._edge(PANORAMA_NODE_ID, f"d:{serial}", "manage", label="Managed by Panorama")

    def _pairs(self) -> list[tuple[str, str]]:
        """Every HA pair Panorama lists, ``(firewall, peer)`` once each."""
        found: list[tuple[str, str]] = []
        seen: set[str] = set()
        for serial in sorted(self.device_by_serial, key=lambda s: (not self._is_active(s), self.hostname(s).lower())):
            peer = ha_peer(self.device_by_serial[serial])
            if peer and peer in self.device_by_serial and serial not in seen and peer not in seen:
                seen.update((serial, peer))
                found.append((serial, peer))
        return found

    def build_edge_sections(self) -> None:
        titles = {
            "vpn": "Site-to-site VPN",
            "vpn3p": "IPsec",
            "uplink": "WAN interface",
            "manage": "Managed by Panorama",
        }
        for edge in self.edges:
            a, b = self.nodes[edge["a"]], self.nodes[edge["b"]]
            if edge["kind"] == "stack":
                title = "High availability"
            elif edge["kind"] == "uplink":
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
                            ("Tunnels" if edge["kind"] in ("vpn", "vpn3p") else "Detail", edge.get("detail")),
                            ("Status", edge.get("status")),
                            ("Discovered via", "Panorama API"),
                        ],
                    )
                ]
                if s
            ]


def _kind_of_name(name: str) -> str:
    lowered = name.lower()
    for prefix, label in (
        ("tunnel", "Tunnel"),
        ("loopback", "Loopback"),
        ("vlan", "VLAN"),
        ("ae", "Aggregate ethernet"),
        ("ethernet", "Ethernet"),
    ):
        if lowered.startswith(prefix):
            return "Sub-interface" if prefix in ("ethernet", "ae") and "." in lowered else label
    return ""


def _route_protocol(flags: str) -> str:
    words = flags.split()
    for flag, label in _FLAG_PROTOCOLS:
        if flag in words:
            return label
    return ""


def source_translation_text(rule: dict) -> str:
    """A NAT rule's source translation as text."""
    translation = _dict(rule.get("source-translation"))
    if not translation:
        return "none"
    dynamic = _dict(translation.get("dynamic-ip-and-port"))
    if "dynamic-ip-and-port" in translation:
        interface = _dict(dynamic.get("interface-address"))
        if interface:
            ip = _text(interface.get("ip"))
            return f"dynamic IP and port, interface {_text(interface.get('interface'))}" + (f" ({ip})" if ip else "")
        return f"dynamic IP and port, {', '.join(members(dynamic.get('translated-address')))}"
    static = _dict(translation.get("static-ip"))
    if "static-ip" in translation:
        text = f"static IP {_text(static.get('translated-address'))}"
        return text + (", bi-directional" if _yes(static.get("bi-directional")) else "")
    if "dynamic-ip" in translation:
        return f"dynamic IP {', '.join(members(_dict(translation.get('dynamic-ip')).get('translated-address')))}"
    return _s(translation)


def destination_translation_text(rule: dict) -> str:
    """A NAT rule's destination translation as text."""
    for key, label in (("destination-translation", ""), ("dynamic-destination-translation", "dynamic ")):
        translation = _dict(rule.get(key))
        if translation:
            port = _text(translation.get("translated-port"))
            return f"{label}{_text(translation.get('translated-address'))}" + (f" port {port}" if port else "")
    return "none"


def build_snapshot(raw: dict, inventory: InventoryIndex | None = None) -> dict[str, Any]:
    """Build the positioned topology snapshot from raw collector output."""
    # Imported here: the forwarding module reads this one's helpers.
    from netcontrol.integrations.panorama.forwarding import build_forwarding

    builder = _Builder(raw, inventory or InventoryIndex())
    builder.build_firewalls()
    builder.build_tunnels()
    build_forwarding(builder)
    builder.build_panorama()
    builder.build_edge_sections()

    sites = [
        {
            "id": PANORAMA_SITE_ID,
            "name": "Palo Alto Panorama",
            "tags": [],
            # Sorts Panorama ahead of the firewalls, like a VPN hub.
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

    info = _dict(raw.get("panorama"))
    return {
        "schema": SCHEMA_VERSION,
        "provider": "panorama",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": {
            "id": _s(info.get("serial") or info.get("url")),
            "name": info.get("name") or "Panorama",
            "url": _s(info.get("url")),
        },
        "summary": {
            "sites": len(builder.sites),
            "devices": sum(by_kind.values()),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": 0,
            "inventory_matches": sum(1 for n in nodes if n.get("inventory")),
            "lan_links": edge_counts.get("stack", 0),
            "vpn_tunnels": edge_counts.get("vpn", 0) + edge_counts.get("vpn3p", 0) - _users_links(builder),
            "wan_uplinks": edge_counts.get("uplink", 0),
            "vlans": builder.connected_count + builder.pool_count,
            "remote_users": builder.user_count,
            "ha_pairs": len(builder._pairs()),
            "device_groups": len(builder.parents),
            "security_rules": sum(
                len(entries(_dict(v).get(b))) for v in builder.security_rules.values() for b in ("pre", "post")
            ),
            "nat_rules": sum(
                len(entries(_dict(v).get(b))) for v in builder.nat_rules.values() for b in ("pre", "post")
            ),
        },
        "collection": {
            "sources": ["Palo Alto Panorama XML API"],
            "stats": raw.get("stats") or {},
            "errors": raw.get("errors") or [],
            "unsupported": list(builder.unsupported),
            "options": raw.get("options") or {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }


def _users_links(builder: _Builder) -> int:
    """The links of the GlobalProtect users nodes, which are ``vpn`` edges
    but no tunnel."""
    return sum(1 for e in builder.edges if e["kind"] == "vpn" and e.get("label") == "GlobalProtect")
