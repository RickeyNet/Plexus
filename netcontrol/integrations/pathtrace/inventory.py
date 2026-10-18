"""Forwarding data of a Plexus inventory host, built at trace time.

An inventory host has no integration snapshot. What Plexus stores for it is
its interfaces (SNMP), its address and aliases, the route table the
monitoring poll captures over SSH (``show ip route``, with ``show ip route
vrf *`` on IOS / IOS-XE, or ``show route``) and, from Config Backups, its
latest running configuration. ``forwarding_for_host`` turns those into the
``forwarding`` block every integration emits
(``netcontrol.integrations.meraki.forwarding``). On a Cisco IOS / IOS-XE or
NX-OS host with a configuration backup (read by ``ios_config``) that adds
the interface access lists, the interface addresses, VRFs and HSRP / VRRP
addresses, and the routes of VRFs the capture lacks. Without a backup the
access lists are not collected, so a trace reports them as unknown.
``subnets_for_host`` lists the host's networks for the subnet index.

``parse_route_table`` reads Cisco IOS / IOS-XE, NX-OS, ASA / FTD and Arista
EOS captures. A capture in any other format gives no routes and says so.

Pure (no I/O): the API handler loads the rows.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from netcontrol.integrations.meraki.forwarding import (
    ANY,
    canonical,
    interface,
    is_address,
    new_block,
    note,
    policy_set,
    rule,
)
from netcontrol.integrations.pathtrace.ios_config import (
    ConfigInterface,
    RunningConfig,
    mask_length,
    parse_config,
    supported,
)
from netcontrol.integrations.pathtrace.model import INVENTORY_ORG_REF, PROVIDER_INVENTORY

ACCESS_LISTS = "Access lists"
NOT_RECOGNISED = "Route table (format not recognised)"
EMPTY_CAPTURE = "Route table (empty capture)"
NO_CAPTURE = "Route table (no SSH capture)"
# The monitoring poll stores the first CAPTURE_LIMIT characters of a capture
# (the global table, then the VRF tables); routes past it are not read.
CAPTURE_LIMIT = 250_000
TRUNCATED = f"Routes past the first {CAPTURE_LIMIT} characters of the capture"

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_CODE_LINE = re.compile(
    rf"^\s*(?P<code>[A-Za-z][A-Za-z0-9*%+&]{{0,4}})(?:\s+(?P<sub>[A-Za-z][A-Za-z0-9]?\*?))?\s+"
    rf"(?P<prefix>{_IPV4})(?:/(?P<length>\d{{1,2}})|\s+(?P<mask>{_IPV4}))?(?=\s|$)(?P<rest>.*)$"
)
_CONTINUATION = re.compile(r"^\s+(?:\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+)?via\s+(?P<body>.+)$")
_SUBNETTED = re.compile(rf"^\s+(?P<prefix>{_IPV4})/(?P<length>\d{{1,2}}) is subnetted")
_DISTANCE = re.compile(r"\[(\d+)/(\d+)\]")
_VRF_IOS = re.compile(r"^\s*Routing Table:\s*(?P<vrf>\S+)")
_VRF_EOS = re.compile(r"^\s*VRF:\s*(?P<vrf>\S+)")
_VRF_NXOS = re.compile(r'^\s*IP Route Table for VRF "(?P<vrf>[^"]+)"')
_NXOS_PREFIX = re.compile(r"^(?P<prefix>[0-9A-Fa-f:.]+/\d{1,3}), ubest/mbest: \d+/\d+")
_NXOS_VIA = re.compile(r"^\s+(?P<best>\*)?via\s+(?P<body>.+)$")

_PROTOCOLS = {
    "O": "OSPF",
    "B": "BGP",
    "D": "EIGRP",
    "R": "RIP",
    "i": "IS-IS",
    "I": "IS-IS",
    "V": "VPN",
    "K": "Kernel",
    "M": "Mobile",
    "U": "Per-user static",
    "o": "ODR",
    "P": "Periodic downloaded static",
    "H": "NHRP",
    "l": "LISP",
    "a": "Application",
    "A": "Aggregate",
    "E": "EGP",
    "N": "NAT",
    "G": "gRIBI",
}
# Arista codes that differ from Cisco's.
_EOS_PROTOCOLS = {"L": "VRF leaked", "DH": "DHCP", "NG": "Nexthop group", "DP": "Dynamic policy", "RC": "Route cache"}
_NXOS_CONNECTED = {
    "direct": "Connected",
    "local": "Local address",
    "hsrp": "HSRP address",
    "vrrp": "VRRP address",
    "glbp": "GLBP address",
    "am": "ARP adjacency",
}
_NXOS_PROTOCOLS = {
    "bgp": "BGP",
    "ospf": "OSPF",
    "ospfv3": "OSPFv3",
    "eigrp": "EIGRP",
    "rip": "RIP",
    "isis": "IS-IS",
}
_SUB_CODES = {
    "IA": "inter area",
    "ia": "inter area",
    "E1": "external type 1",
    "E2": "external type 2",
    "N1": "NSSA external type 1",
    "N2": "NSSA external type 2",
    "EX": "external",
    "E": "external",
    "I": "internal",
    "L1": "level 1",
    "L2": "level 2",
    "su": "summary",
}
_LOCAL = "Local address"
_DEFAULTS = ("0.0.0.0/0", "::/0")

# Interface name prefixes and their long form, so "Eth1/1" in a route table
# and "Ethernet1/1" from SNMP are the same interface.
_ABBREVIATIONS = {
    "e": "ethernet",
    "et": "ethernet",
    "eth": "ethernet",
    "ethernet": "ethernet",
    "fa": "fastethernet",
    "fastethernet": "fastethernet",
    "gi": "gigabitethernet",
    "gig": "gigabitethernet",
    "gigabitethernet": "gigabitethernet",
    "te": "tengigabitethernet",
    "ten": "tengigabitethernet",
    "tengigabitethernet": "tengigabitethernet",
    "twe": "twentyfivegige",
    "twentyfivegige": "twentyfivegige",
    "fo": "fortygigabitethernet",
    "fortygigabitethernet": "fortygigabitethernet",
    "hu": "hundredgige",
    "hundredgige": "hundredgige",
    "po": "port-channel",
    "port-channel": "port-channel",
    "portchannel": "port-channel",
    "vl": "vlan",
    "vlan": "vlan",
    "lo": "loopback",
    "loopback": "loopback",
    "tu": "tunnel",
    "tunnel": "tunnel",
    "mgmt": "management",
    "ma": "management",
    "management": "management",
}


def interface_key(name: str) -> str:
    """A loose key for an interface name: lower-case, abbreviations expanded."""
    text = str(name or "").strip().lower().replace(" ", "")
    match = re.match(r"^([a-z-]+)(.*)$", text)
    if not match:
        return text
    return _ABBREVIATIONS.get(match.group(1), match.group(1)) + match.group(2)


def _route(
    prefix: str,
    kind: str,
    *,
    next_hop: str = "",
    iface: str = "",
    vrf: str = "",
    metric: int | None = None,
    source: str,
) -> dict[str, Any]:
    if iface.lower().startswith("null"):
        kind = "blackhole"
    elif kind == "static" and prefix in _DEFAULTS:
        kind = "default"
    return {
        "prefix": prefix,
        "kind": kind,
        "next_hop": next_hop if is_address(next_hop) else "",
        "interface": iface,
        "peer": None,
        "vrf": vrf,
        "metric": metric,
        "enabled": True,
        "source": source,
        "advertised": None,
    }


def _vrf(name: str) -> str:
    return "" if name.lower() in ("default", "global") else name


def _length(prefix: str, length: str | None, mask: str | None, subnetted: dict[str, int]) -> int | None:
    if length:
        return int(length)
    if mask:
        return mask_length(mask)
    major = _classful(prefix)
    return subnetted.get(major, int(major.rsplit("/", 1)[1]))


def _classful(address: str) -> str:
    """The classful network of an IPv4 address (how IOS groups its routes)."""
    first = int(address.split(".")[0])
    length = 8 if first < 128 else 16 if first < 192 else 24
    return str(ipaddress.ip_network(f"{address}/{length}", strict=False))


def _next_hop_and_interface(body: str) -> tuple[str, str]:
    """``via`` text: the next hop and the egress interface (the last field
    that is a name, not an uptime)."""
    fields = [f.strip() for f in body.split(",") if f.strip()]
    hop = re.sub(r"\(.*\)$", "", fields[0]).strip() if fields else ""
    iface = ""
    for field in fields[1:]:
        if re.match(r"^[A-Za-z]", field) and not field.startswith("["):
            iface = field.split()[0]
    if not is_address(hop) and re.match(r"^[A-Za-z]", hop):
        hop, iface = "", iface or hop
    return hop, iface


def _cisco_kind(code: str, sub: str, eos: bool) -> tuple[str, str]:
    """``(kind, source)`` of a Cisco / Arista route code."""
    base = re.sub(r"[*%+&]", "", code)
    letters = re.match(r"^[A-Za-z]+", base)
    word = letters.group(0) if letters else base
    if eos and word in _EOS_PROTOCOLS:
        return "dynamic", _EOS_PROTOCOLS[word]
    head = word[:1]
    if head == "C":
        return "connected", "Connected"
    if head == "L" and not eos:
        return "connected", _LOCAL
    if head == "S":
        return ("default" if "*" in code else "static"), "Static route"
    protocol = _PROTOCOLS.get(head, word)
    detail = _SUB_CODES.get(sub, "")
    return "dynamic", f"{protocol} {detail}" if detail else protocol


def _parse_cisco(lines: list[str], eos: bool) -> list[dict]:
    routes: list[dict] = []
    vrf = ""
    subnetted: dict[str, int] = {}
    current: dict[str, Any] | None = None
    for line in lines:
        header = _VRF_IOS.match(line) or _VRF_EOS.match(line)
        if header:
            vrf, current = _vrf(header.group("vrf")), None
            continue
        sub_header = _SUBNETTED.match(line)
        if sub_header:
            # "10.0.0.0/24 is subnetted": the lines below give 10.x networks without a length.
            subnetted[_classful(sub_header.group("prefix"))] = int(sub_header.group("length"))
            continue
        more = _CONTINUATION.match(line)
        if more and current is not None:
            hop, iface = _next_hop_and_interface(more.group("body"))
            metric = int(more.group("metric")) if more.group("metric") else current["metric"]
            routes.append(
                _route(
                    current["prefix"],
                    current["kind"],
                    next_hop=hop,
                    iface=iface,
                    vrf=vrf,
                    metric=metric,
                    source=current["source"],
                )
            )
            continue
        match = _CODE_LINE.match(line)
        if not match:
            continue
        length = _length(match.group("prefix"), match.group("length"), match.group("mask"), subnetted)
        prefix = canonical(f"{match.group('prefix')}/{length}") if length is not None else ""
        if not prefix:
            current = None
            continue
        kind, source = _cisco_kind(match.group("code"), match.group("sub") or "", eos)
        rest = match.group("rest")
        distance = _DISTANCE.search(rest)
        metric = int(distance.group(2)) if distance else None
        current = {"prefix": prefix, "kind": kind, "source": source, "metric": metric}
        if "directly connected" in rest:
            iface = rest.split("directly connected", 1)[1].strip(" ,").split(",")[0].strip()
            routes.append(_route(prefix, kind, iface=iface.split()[0] if iface else "", vrf=vrf, source=source))
        elif " via " in f" {rest} ":
            hop, iface = _next_hop_and_interface(rest.split("via", 1)[1])
            routes.append(_route(prefix, kind, next_hop=hop, iface=iface, vrf=vrf, metric=metric, source=source))
        elif "connected by VPN" in rest:
            # An ASA's route to a remote access VPN client.
            fields = [f.strip() for f in rest.split(",") if f.strip()]
            iface = fields[-1] if len(fields) > 1 and re.match(r"^[A-Za-z]", fields[-1]) else ""
            routes.append(_route(prefix, "dynamic", iface=iface, vrf=vrf, metric=metric, source="VPN client"))
        elif "is a summary" in rest:
            fields = [f.strip() for f in rest.split(",") if f.strip()]
            iface = fields[-1] if fields and re.match(r"^[A-Za-z]", fields[-1]) else ""
            routes.append(_route(prefix, kind, iface=iface, vrf=vrf, metric=metric, source=f"{source} summary"))
        # Otherwise the next hops follow on continuation lines.
    return routes


def _nxos_kind(protocol: str) -> tuple[str, str]:
    name = protocol.lower()
    if name in _NXOS_CONNECTED:
        return "connected", _NXOS_CONNECTED[name]
    if name == "static":
        return "static", "Static route"
    if name == "discard":
        return "blackhole", "Discard"
    family = name.split("-", 1)[0]
    return "dynamic", _NXOS_PROTOCOLS.get(family, protocol)


def _parse_nxos(lines: list[str]) -> list[dict]:
    routes: list[dict] = []
    vrf = ""
    prefix = ""
    for line in lines:
        header = _VRF_NXOS.match(line)
        if header:
            vrf, prefix = _vrf(header.group("vrf")), ""
            continue
        match = _NXOS_PREFIX.match(line)
        if match:
            prefix = canonical(match.group("prefix"))
            continue
        via = _NXOS_VIA.match(line)
        if not via or not prefix or not via.group("best"):
            continue
        fields = [f.strip() for f in via.group("body").split(",") if f.strip()]
        hop = fields[0].split("%", 1)[0] if fields else ""
        iface = ""
        metric: int | None = None
        protocol = ""
        for field in fields[1:]:
            distance = _DISTANCE.match(field)
            if distance:
                metric = int(distance.group(2))
            elif metric is None and re.match(r"^[A-Za-z]", field) and not iface:
                iface = field.split()[0]
            elif metric is not None and re.match(r"^[A-Za-z]", field) and not protocol:
                protocol = field.split()[0]
        if not is_address(hop):
            hop, iface = "", iface or hop
        kind, source = _nxos_kind(protocol)
        routes.append(
            _route(
                prefix,
                kind,
                next_hop="" if kind == "connected" else hop,
                iface=iface,
                vrf=vrf,
                metric=metric,
                source=source,
            )
        )
    return routes


def parse_route_table(text: str, device_type: str) -> tuple[list[dict], list[str]]:
    """Routes of a ``show ip route`` / ``show route`` capture as forwarding
    routes, and the names of what could not be parsed (for not_collected)."""
    raw = str(text or "")
    if not raw.strip():
        return [], [EMPTY_CAPTURE]
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    flavour = str(device_type or "").lower()
    if "ubest/mbest" in raw:
        routes = _parse_nxos(lines)
    else:
        routes = _parse_cisco(lines, eos="arista" in flavour or "eos" in flavour)
    unique: dict[tuple, dict] = {}
    for item in routes:
        unique.setdefault((item["vrf"], item["prefix"], item["kind"], item["next_hop"], item["interface"]), item)
    missing: list[str] = []
    if not unique:
        return [], [NOT_RECOGNISED]
    if len(raw) >= CAPTURE_LIMIT:
        missing.append(TRUNCATED)
    return list(unique.values()), missing


def _interface_kind(name: str, has_address: bool) -> str:
    key = interface_key(name)
    for prefix, kind in (("vlan", "svi"), ("loopback", "loopback"), ("tunnel", "tunnel"), ("management", "management")):
        if key.startswith(prefix):
            return kind
    return "routed" if has_address else ""


def _config(host: dict, config_backup: dict | None) -> RunningConfig | None:
    """The parsed configuration backup of a host whose platform is read."""
    if config_backup is None or not supported(str(host.get("device_type") or "")):
        return None
    text = str(config_backup.get("config_text") or "")
    return parse_config(text) if text.strip() else None


def _acl_policies(config: RunningConfig, names: dict[str, str]) -> list[dict[str, Any]]:
    """One stateless rule set per ``ip access-group`` binding, bound to its
    interface and direction, ending in the implicit deny. A binding to an
    access list the configuration does not define is unknown when a flow
    meets it."""
    policies: list[dict[str, Any]] = []
    for conf in config.interfaces:
        name = names.get(interface_key(conf.name), conf.name)
        for direction in ("in", "out"):
            acl = conf.access_groups.get(direction)
            if not acl:
                continue
            src_zones = [name] if direction == "in" else None
            dst_zones = [name] if direction == "out" else None
            label = f"ACL {acl} {direction} on {name}"
            entries = config.access_lists.get(acl) or []
            if not entries:
                missing = f"access list {acl} (not in the configuration)"
                policies.append(
                    policy_set(
                        label,
                        "acl",
                        ANY,
                        [rule(1, "allow", unresolved=[missing], src_zones=src_zones, dst_zones=dst_zones)],
                        stateful=False,
                        default="unknown",
                        interface=name,
                        direction=direction,
                    )
                )
                continue
            rules = [
                rule(
                    entry.sequence if entry.sequence is not None else position,
                    entry.action,
                    protocol=entry.protocol,
                    src=entry.src,
                    src_ports=entry.src_ports,
                    dst=entry.dst,
                    dst_ports=entry.dst_ports,
                    comment=entry.comment,
                    unresolved=entry.unresolved,
                    established=entry.established,
                    src_zones=src_zones,
                    dst_zones=dst_zones,
                )
                for position, entry in enumerate(entries, start=1)
            ]
            policies.append(
                policy_set(label, "acl", ANY, rules, stateful=False, default="deny", interface=name, direction=direction)
            )
    return policies


def _configured_interfaces(name: str, conf: ConfigInterface, kind: str, vrf: str, up: bool) -> list[dict[str, Any]]:
    """The secondary addresses and the HSRP / VRRP / GLBP addresses of a
    configured interface, each an interface entry in the zone of the real
    one, so the flows sent to them arrive on it."""
    extra: list[dict[str, Any]] = []
    for address, cidr in conf.addresses[1:]:
        extra.append(
            interface(f"{name} (secondary {address})", kind, ip=address, cidr=cidr, zone=name, vrf=vrf, enabled=up)
        )
    for virtual in conf.virtual:
        parsed = ipaddress.ip_address(virtual.address)
        holder = next((c for _a, c in conf.addresses if parsed in ipaddress.ip_network(c)), "")
        extra.append(
            interface(
                f"{name} ({virtual.protocol} {virtual.address})",
                kind,
                ip=virtual.address,
                cidr=holder,
                zone=name,
                vrf=vrf,
                enabled=up,
            )
        )
    if conf.description:
        for entry in extra:
            entry["description"] = conf.description
    return extra


def forwarding_for_host(
    host: dict,
    aliases: list[str],
    route_capture: dict | None,
    interfaces: list[dict],
    *,
    config_backup: dict | None = None,
) -> dict[str, Any]:
    """The forwarding block of an inventory host: its interfaces, the routes
    of its latest SSH route capture and, from its latest configuration
    backup (``config_backup``, a ``config_backups`` row with
    ``config_text``) on Cisco IOS / IOS-XE and NX-OS, its interface access
    lists, addresses, VRFs, HSRP / VRRP addresses and the routes of the
    VRFs the capture lacks. Without a backup the access lists are not
    collected."""
    block = new_block()
    config = _config(host, config_backup)
    if route_capture is None:
        routes: list[dict] = []
        missing = [NO_CAPTURE]
    else:
        routes, missing = parse_route_table(
            str(route_capture.get("routes_text") or ""), str(host.get("device_type") or "")
        )

    # What the connected and local routes say about each interface.
    cidr_of: dict[str, str] = {}
    ip_of: dict[str, str] = {}
    vrf_of: dict[str, str] = {}
    spelled: dict[str, str] = {}
    for item in routes:
        if item["kind"] != "connected" or not item["interface"]:
            continue
        key = interface_key(item["interface"])
        spelled.setdefault(key, item["interface"])
        vrf_of.setdefault(key, item["vrf"])
        network = ipaddress.ip_network(item["prefix"])
        if item["source"] == _LOCAL and network.num_addresses == 1:
            ip_of.setdefault(key, str(network.network_address))
        elif network.num_addresses > 1:
            cidr_of.setdefault(key, item["prefix"])

    # The configuration names interfaces first, then SNMP, then the route table.
    configured = {interface_key(i.name): i for i in config.interfaces} if config else {}
    names: dict[str, str] = {key: conf.name for key, conf in configured.items()}
    enabled: dict[str, bool] = {}
    for row in interfaces:
        name = str((row or {}).get("name") or "").strip()
        if not name or interface_key(name) in enabled:
            continue
        names.setdefault(interface_key(name), name)
        enabled[interface_key(name)] = str(row.get("admin_state") or "").strip().lower() != "down"
    for key, name in spelled.items():
        names.setdefault(key, name)

    for key, name in names.items():
        conf = configured.get(key)
        up = enabled.get(key, True) and not (conf is not None and conf.shutdown)
        if conf is not None and conf.addresses:
            ip, cidr = conf.addresses[0]
        else:
            ip, cidr = ip_of.get(key, ""), cidr_of.get(key, "")
        vrf = _vrf(conf.vrf) if conf is not None else vrf_of.get(key, "")
        kind = _interface_kind(name, bool(ip or cidr))
        # A configured interface is its own zone: its access lists match by it.
        entry = interface(name, kind, ip=ip, cidr=cidr, zone=name if conf else "", vrf=vrf, enabled=up)
        if conf is not None and conf.description:
            entry["description"] = conf.description
        block["interfaces"].append(entry)
        if conf is not None:
            block["interfaces"].extend(_configured_interfaces(name, conf, kind, vrf, up))
    # Routes name interfaces the way the block does.
    for item in routes:
        if item["interface"]:
            item["interface"] = names.get(interface_key(item["interface"]), item["interface"])

    if config is not None:
        # The connected and static routes of every VRF the capture has no
        # table for (all of them without a capture). A VRF it has is taken
        # as captured: a configured static route missing from it is not
        # installed (a floating route, or its next hop is down).
        captured = {item["vrf"] for item in routes}
        for conf in config.interfaces:
            vrf = _vrf(conf.vrf)
            if vrf in captured or conf.shutdown:
                continue
            name = names.get(interface_key(conf.name), conf.name)
            for _address, cidr in conf.addresses:
                routes.append(_route(cidr, "connected", iface=name, vrf=vrf, source=f"Connected {name}"))
        for static in config.static_routes:
            vrf = _vrf(static.vrf)
            if vrf in captured:
                continue
            iface = names.get(interface_key(static.interface), static.interface) if static.interface else ""
            source = f"Static route {static.name}".strip()
            routes.append(
                _route(static.prefix, "static", next_hop=static.next_hop, iface=iface, vrf=vrf, source=source)
            )
        if route_capture is None:
            # The configuration names the routing protocols whose routes are missing.
            missing = [f"Routes learned by {protocol}" for protocol in config.routing]
        block["policies"] = _acl_policies(config, names)
    block["routes"] = routes

    # The host's own addresses: on the interface whose network holds them
    # when that interface has no address yet, else an interface of their own.
    for address in [str(host.get("ip_address") or "").strip(), *(str(a or "").strip() for a in aliases)]:
        if not is_address(address) or any(i["ip"] == address for i in block["interfaces"]):
            continue
        parsed = ipaddress.ip_address(address)
        holders = [i for i in block["interfaces"] if i["cidr"] and parsed in ipaddress.ip_network(i["cidr"])]
        if len(holders) == 1 and not holders[0]["ip"]:
            holders[0]["ip"] = address
            continue
        covering = holders[0]["cidr"] if holders else ""
        block["interfaces"].append(interface(address, "", ip=address, cidr=covering))

    if config is None:
        note(block, ACCESS_LISTS)
    else:
        for name in config.notes:
            note(block, name)
    for name in missing:
        note(block, name)
    return block


_VLAN_ID = re.compile(r"^vlan(\d+)$")


def subnets_for_host(node: dict, block: dict) -> list[dict[str, Any]]:
    """The networks of an inventory host as ``subnet_index`` rows, so they
    can be picked as path ends and swept: each interface network (``svi``,
    named ``VLAN <id> <description>``, for a VLAN interface; ``connected``,
    named by the interface and its description, for any other) and each
    static route (``static``). ``node`` is the host's graph node: its id is
    the ``node_id``, its inventory group the site. Default routes, host
    addresses, loopbacks and management interfaces are left out."""
    host_id = str(node.get("id"))
    group_id = node.get("group_id")
    found: dict[str, dict[str, Any]] = {}

    def add(cidr: str, kind: str, name: str) -> None:
        network = ipaddress.ip_network(cidr)
        if network.prefixlen == 0 or network.num_addresses == 1 or cidr in found:
            return
        found[cidr] = {
            "cidr": cidr,
            "name": name.strip(),
            "kind": kind,
            "site_id": "" if group_id is None else str(group_id),
            "site_name": str(node.get("group_name") or ""),
            "node_id": host_id,
            "in_vpn": None,
            "org_ref": INVENTORY_ORG_REF,
            "provider": PROVIDER_INVENTORY,
            "org_name": "Inventory",
        }

    for entry in block.get("interfaces") or []:
        if not isinstance(entry, dict) or not entry.get("cidr") or entry.get("kind") in ("loopback", "management"):
            continue
        base = str(entry.get("zone") or entry.get("name") or "")
        description = str(entry.get("description") or "")
        vlan = _VLAN_ID.match(interface_key(base))
        secondary = " (secondary)" if "(secondary " in str(entry.get("name") or "") else ""
        if entry.get("kind") == "svi" and vlan:
            add(entry["cidr"], "svi", f"VLAN {vlan.group(1)} {description}".strip() + secondary)
        else:
            add(entry["cidr"], "connected", f"{base} {description}".strip() + secondary)
    for item in block.get("routes") or []:
        if isinstance(item, dict) and item.get("kind") == "static" and canonical(item.get("prefix")):
            via = item.get("next_hop") or item.get("interface") or ""
            add(canonical(item["prefix"]), "static", f"Static route via {via}" if via else "Static route")

    def order(row: dict[str, Any]) -> tuple:
        network = ipaddress.ip_network(row["cidr"])
        return (network.version, int(network.network_address), network.prefixlen)

    return sorted(found.values(), key=order)
