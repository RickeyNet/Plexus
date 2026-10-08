"""Forwarding data of a Plexus inventory host, built at trace time.

An inventory host has no integration snapshot. What Plexus stores for it is
enough for routing: its interfaces (SNMP), its address and aliases, and the
route table the monitoring poll captures over SSH (``show ip route`` or
``show route``). ``forwarding_for_host`` turns those into the ``forwarding``
block every integration emits (``netcontrol.integrations.meraki.forwarding``).
Access lists are not collected, so a trace reports them as unknown.

``parse_route_table`` reads Cisco IOS / IOS-XE, NX-OS, ASA / FTD and Arista
EOS captures. A capture in any other format gives no routes and says so.

Pure (no I/O): the API handler loads the rows.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from netcontrol.integrations.meraki.forwarding import canonical, interface, is_address, new_block, note

ACCESS_LISTS = "Access lists"
NOT_RECOGNISED = "Route table (format not recognised)"
EMPTY_CAPTURE = "Route table (empty capture)"
NO_CAPTURE = "Route table (no SSH capture)"
# The monitoring poll stores the first 10000 characters of a capture.
CAPTURE_LIMIT = 10000
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
        try:
            return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
        except ValueError:
            return None
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


def forwarding_for_host(
    host: dict, aliases: list[str], route_capture: dict | None, interfaces: list[dict]
) -> dict[str, Any]:
    """The forwarding block of an inventory host: its interfaces, the routes
    of its latest SSH route capture, no policies (access lists are not
    collected)."""
    block = new_block()
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
    spelled: dict[str, str] = {}
    for item in routes:
        if item["kind"] != "connected" or not item["interface"]:
            continue
        key = interface_key(item["interface"])
        spelled.setdefault(key, item["interface"])
        network = ipaddress.ip_network(item["prefix"])
        if item["source"] == _LOCAL and network.num_addresses == 1:
            ip_of.setdefault(key, str(network.network_address))
        elif network.num_addresses > 1:
            cidr_of.setdefault(key, item["prefix"])

    names: dict[str, str] = {}
    enabled: dict[str, bool] = {}
    for row in interfaces:
        name = str((row or {}).get("name") or "").strip()
        if not name or interface_key(name) in names:
            continue
        names[interface_key(name)] = name
        enabled[interface_key(name)] = str(row.get("admin_state") or "").strip().lower() != "down"
    for key, name in spelled.items():
        names.setdefault(key, name)

    for key, name in names.items():
        ip, cidr = ip_of.get(key, ""), cidr_of.get(key, "")
        block["interfaces"].append(
            interface(name, _interface_kind(name, bool(ip or cidr)), ip=ip, cidr=cidr, enabled=enabled.get(key, True))
        )
    # Routes name interfaces the way the block does.
    for item in routes:
        if item["interface"]:
            item["interface"] = names.get(interface_key(item["interface"]), item["interface"])
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

    note(block, ACCESS_LISTS)
    for name in missing:
        note(block, name)
    return block
