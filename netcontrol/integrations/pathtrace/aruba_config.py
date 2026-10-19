"""The running configuration and route table of an Aruba AOS-CX or
AOS-Switch (HP ProCurve) switch, read for path tracing.

``parse_config`` tells the two dialects apart and reads either into a
``RunningConfig`` (see ``device_config``), with the building blocks of the
Cisco reader (``ios_config``): the same access list entry, address, port
and object group parsing, and on AOS-CX the same interface block.

AOS-CX names its interfaces ``1/1/1``, ``lag1``, ``vlan10``, ``loopback0``
and ``mgmt``, binds access lists with ``apply access-list ip NAME in|out``
(``routed-in`` / ``routed-out`` on a VLAN interface), writes addresses as
``A/len``, puts a route in a VRF with a trailing ``vrf NAME`` and answers
on its VSX ``active-gateway ip`` and VRRP addresses. An interface is taken
as up unless it says ``shutdown``: the backup lists ``no shutdown`` for the
ports that are up, but a port the configuration says nothing about is left
to the SNMP admin state rather than taken as down.

AOS-Switch holds its routed interfaces in ``vlan N`` blocks (``ip address A
MASK``, every address after the first a secondary one, ``ip access-group
"NAME" in|out``, ``vrrp vrid N`` / ``virtual-ip-address A``), names them
``VLAN10`` (``DEFAULT_VLAN`` for VLAN 1, or the VLAN's name, as aliases),
quotes its names, and prints ``any`` as ``0.0.0.0 255.255.255.255``.

What either uses and is not read is noted: IPv6 and MAC access lists,
access lists applied to a VLAN or a port, classifier policies, policy-based
routing, and VSX (the peer's state is not in this switch's backup).

``parse_routes`` reads the ``show ip route`` capture of either: the AOS-CX
table (``Prefix Nexthop Interface VRF(egress) Origin/Type Distance/Metric
Age`` columns, under ``VRF: NAME`` headers with ``all-vrfs``, or the older
``PREFIX, vrf NAME`` / ``via ...`` lines) and the AOS-Switch one
(``Destination Gateway VLAN Type Sub-Type Metric Dist.``).

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re

from netcontrol.integrations.meraki.forwarding import ANY, canonical, is_address
from netcontrol.integrations.pathtrace.device_config import ConfigInterface, RunningConfig, StaticRoute
from netcontrol.integrations.pathtrace.ios_config import (
    CLASSIFIER_POLICIES,
    IPV6_ACCESS_LISTS,
    MAC_ACCESS_LISTS,
    POLICY_BASED_ROUTES,
    PORT_ACCESS_LISTS,
    ROUTING_PROTOCOLS,
    Block,
    Groups,
    acl_lines,
    add_address,
    add_note,
    add_virtual,
    blocks,
    network,
    read_interface,
    read_object_group,
    static_route,
)
from netcontrol.integrations.pathtrace.route_tables import LOCAL, route_entry, vrf_name

__all__ = ["CLASSIFIER_POLICIES", "VLAN_ACCESS_LISTS", "VSX", "parse_config", "parse_routes"]

# Not-collected names of what the Aruba configurations use and is not read.
VLAN_ACCESS_LISTS = "Access lists applied to VLANs"
VSX = "VSX (the peer's state)"

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_AOSCX = re.compile(
    r"^(?:!Version ArubaOS-CX|interface (?:vlan|lag|mgmt)\b|interface \d+/\d+/\d+|access-list ip |vsx\b)",
    re.MULTILINE | re.IGNORECASE,
)
_WORD = re.compile(r'"[^"]*"|\S+')


def _words(line: str) -> list[str]:
    """The tokens of a line, a quoted name (``"Users In"``) as one, unquoted."""
    return [t[1:-1] if len(t) > 1 and t.startswith('"') and t.endswith('"') else t for t in _WORD.findall(line)]


def _routing(config: RunningConfig, words: list[str]) -> None:
    if words[0] == "router" and len(words) > 1 and words[1] in ROUTING_PROTOCOLS:
        name = ROUTING_PROTOCOLS[words[1]]
        if name not in config.routing:
            config.routing.append(name)


def _route(tokens: list[str]) -> StaticRoute | None:
    """``ip route PREFIX [MASK] (NEXT_HOP | IFACE | vlan N | blackhole |
    reject) [vrf X] [distance N] [tag N]`` (the tokens after ``ip route``)."""
    vrf, distance = "", None
    rest: list[str] = []
    i = 0
    while i < len(tokens):
        word = tokens[i].lower()
        if word in ("vrf", "distance", "metric", "tag") and i + 1 < len(tokens):
            if word == "vrf":
                vrf = tokens[i + 1]
            elif word == "distance" and tokens[i + 1].isdigit():
                distance = int(tokens[i + 1])
            i += 2
            continue
        if word == "vlan" and i + 1 < len(tokens) and tokens[i + 1].isdigit():
            rest.append(f"VLAN{tokens[i + 1]}")
            i += 2
            continue
        rest.append(tokens[i])
        i += 1
    found = static_route(rest, vrf)
    if found is not None and distance is not None:
        found.distance = distance
    return found


def _any(config: RunningConfig) -> None:
    """``0.0.0.0/0`` is ``any`` (AOS-Switch prints ``any`` as ``0.0.0.0 255.255.255.255``)."""
    for entries in config.access_lists.values():
        for entry in entries:
            entry.src = [ANY if c == "0.0.0.0/0" else c for c in entry.src]
            entry.dst = [ANY if c == "0.0.0.0/0" else c for c in entry.dst]


def _aoscx_mgmt(block: Block, found: ConfigInterface, config: RunningConfig) -> None:
    """The ``mgmt`` interface: its ``ip static`` address and ``default-gateway``, in the mgmt VRF."""
    found.vrf = found.vrf or "mgmt"
    for _indent, line in block.children:
        tokens = line.split()
        words = [t.lower() for t in tokens]
        if words[:2] == ["ip", "static"] and len(tokens) > 2 and "/" in tokens[2]:
            add_address(found, tokens[2].split("/", 1)[0], canonical(tokens[2]), secondary=False, primary=False)
        elif words[0] == "default-gateway" and len(tokens) > 1 and is_address(tokens[1]):
            config.static_routes.append(StaticRoute("0.0.0.0/0", next_hop=tokens[1], vrf=found.vrf))


def _parse_aoscx(found_blocks: list[Block]) -> RunningConfig:
    config = RunningConfig()
    groups = Groups()
    acls: list[tuple[str, list[list[str]]]] = []
    for block in found_blocks:
        tokens = _words(block.header)
        words = [t.lower() for t in tokens]
        children = [_words(line) for _indent, line in block.children]
        if read_object_group(tokens, children, groups):
            continue
        if words[:2] == ["access-list", "ip"] and len(tokens) > 2:
            acls.append((tokens[2], children))
        elif words[0] == "interface" and len(tokens) > 1:
            name = "".join(tokens[1:])
            found = read_interface(name, block.children, config)
            if name.lower() == "mgmt":
                _aoscx_mgmt(block, found, config)
            config.interfaces.append(found)
        elif words[:2] == ["ip", "route"]:
            route = _route(tokens[2:])
            if route is not None:
                config.static_routes.append(route)
        elif words[0] == "vlan" and len(tokens) > 1:
            if any([w.lower() for w in c[:2]] == ["apply", "access-list"] for c in children):
                add_note(config, VLAN_ACCESS_LISTS)
            if any([w.lower() for w in c[:2]] == ["apply", "policy"] for c in children):
                add_note(config, CLASSIFIER_POLICIES)
        elif words[0] == "vsx":
            add_note(config, VSX)
        else:
            _routing(config, words)
    for name, lines in acls:
        acl_lines(config.access_lists.setdefault(name, []), lines, False, groups)
    _any(config)
    return config


def _vlan(vid: str, children: list[tuple[int, str]], config: RunningConfig) -> ConfigInterface:
    """An AOS-Switch ``vlan N`` block as the VLAN's routed interface."""
    found = ConfigInterface(f"VLAN{vid}")
    names = ["DEFAULT_VLAN"] if vid == "1" else []
    # A ``vrrp vrid N`` sub-block: (group, its indentation).
    vrrp: tuple[str, int] | None = None
    primary = False
    for indent, line in children:
        tokens = _words(line)
        words = [t.lower() for t in tokens]
        if vrrp is not None and indent > vrrp[1]:
            if words[0] == "virtual-ip-address" and len(tokens) > 1:
                add_virtual(found, "VRRP", vrrp[0], tokens[1])
            continue
        vrrp = None
        if words[0] == "name" and len(tokens) > 1:
            names.append(tokens[1])
        elif words[:2] == ["ip", "address"] and len(tokens) > 2:
            if "/" in tokens[2]:
                value, cidr = tokens[2].split("/", 1)[0], canonical(tokens[2])
            elif len(tokens) > 3:
                value, cidr = tokens[2], network(tokens[2], tokens[3])
            else:
                continue  # ``ip address dhcp-bootp``
            # Every address after the first is a secondary one.
            primary = add_address(found, value, cidr, secondary=primary, primary=primary)
        elif words[:2] == ["ip", "access-group"] and len(tokens) > 3:
            if words[3] in ("in", "out"):
                found.access_groups[words[3]] = tokens[2]
            else:
                add_note(config, VLAN_ACCESS_LISTS)
        elif words[:2] == ["vrrp", "vrid"] and len(tokens) > 2:
            vrrp = (tokens[2], indent)
        elif words[:2] in (["ipv6", "access-group"], ["ipv6", "traffic-filter"]):
            add_note(config, IPV6_ACCESS_LISTS)
        elif words[:2] == ["mac", "access-group"]:
            add_note(config, MAC_ACCESS_LISTS)
        elif words[0] == "service-policy":
            add_note(config, CLASSIFIER_POLICIES)
        elif words[:2] == ["ip", "policy"] or words[:2] == ["policy", "route"]:
            add_note(config, POLICY_BASED_ROUTES)
    found.aliases = [n for n in dict.fromkeys(names) if n.lower() != found.name.lower()]
    return found


def _parse_aos_switch(found_blocks: list[Block]) -> RunningConfig:
    config = RunningConfig()
    groups = Groups()
    acls: list[tuple[str, bool, list[list[str]]]] = []
    for block in found_blocks:
        tokens = _words(block.header)
        words = [t.lower() for t in tokens]
        children = [_words(line) for _indent, line in block.children]
        if words[:2] == ["ip", "access-list"] and len(tokens) > 3 and words[2] in ("standard", "extended"):
            acls.append((tokens[3], words[2] == "standard", children))
        elif words[0] == "vlan" and len(tokens) == 2 and tokens[1].isdigit():
            config.interfaces.append(_vlan(tokens[1], block.children, config))
        elif words[0] == "interface":
            # A port: an access list applied to it filters what it bridges too.
            for child in children:
                head = [w.lower() for w in child[:2]]
                if head == ["ip", "access-group"]:
                    add_note(config, PORT_ACCESS_LISTS)
                elif head in (["ipv6", "access-group"], ["ipv6", "traffic-filter"]):
                    add_note(config, IPV6_ACCESS_LISTS)
                elif head and head[0] == "service-policy":
                    add_note(config, CLASSIFIER_POLICIES)
        elif words[:2] == ["ip", "route"]:
            route = _route(tokens[2:])
            if route is not None:
                config.static_routes.append(route)
        else:
            _routing(config, words)
    for name, standard, lines in acls:
        acl_lines(config.access_lists.setdefault(name, []), lines, standard, groups)
    _any(config)
    return config


def parse_config(text: str) -> RunningConfig:
    """What an Aruba AOS-CX or AOS-Switch (ProCurve) switch running
    configuration says about forwarding: interfaces, access lists, static
    routes, routing protocols."""
    found_blocks = blocks(text)
    if _AOSCX.search(str(text or "")):
        return _parse_aoscx(found_blocks)
    return _parse_aos_switch(found_blocks)


# ── Route tables ─────────────────────────────────────────────────────────────

_SWITCH_HEADER = re.compile(r"^\s*Destination\s+Gateway\s+VLAN\s+Type", re.IGNORECASE)
_SWITCH_TYPES = {
    "connected": ("connected", "Connected"),
    "static": ("static", "Static route"),
    "ospf": ("dynamic", "OSPF"),
    "rip": ("dynamic", "RIP"),
    "bgp": ("dynamic", "BGP"),
}
_CX_VRF = re.compile(r"^\s*VRF:\s*(?P<vrf>\S+)")
_CX_ROW = re.compile(rf"^(?P<prefix>{_IPV4}/\d{{1,2}})\s+(?P<rest>\S.*)$")
_CX_MORE = re.compile(r"^\s+(?P<rest>\S.*\[\d+/\d+\].*)$")
_CX_OLD_PREFIX = re.compile(rf"^(?P<prefix>{_IPV4}/\d{{1,2}}),\s*vrf\s+(?P<vrf>[^,\s]+)")
_CX_VIA = re.compile(r"^\s+via\s+(?P<body>.+)$")
_CX_DISTANCE = re.compile(r"^\[(\d+)/(\d+)\]$")
_CX_ORIGINS = {
    "c": ("connected", "Connected"),
    "connected": ("connected", "Connected"),
    "l": ("connected", LOCAL),
    "local": ("connected", LOCAL),
    "s": ("static", "Static route"),
    "static": ("static", "Static route"),
    "o": ("dynamic", "OSPF"),
    "ospf": ("dynamic", "OSPF"),
    "b": ("dynamic", "BGP"),
    "bgp": ("dynamic", "BGP"),
    "r": ("dynamic", "RIP"),
    "rip": ("dynamic", "RIP"),
}
_CX_TYPES = {
    "E": "external",
    "I": "internal",
    "V": "VPN",
    "EV": "EVPN",
    "IA": "internal area",
    "E1": "external type 1",
    "E2": "external type 2",
}


def _loopback(prefix: str) -> bool:
    return ipaddress.ip_network(prefix).network_address.is_loopback


def _switch_routes(lines: list[str]) -> list[dict]:
    """An AOS-Switch table: ``DESTINATION GATEWAY [VLAN] TYPE [SUB-TYPE] METRIC DIST``.
    A connected route names its VLAN in the gateway column."""
    routes: list[dict] = []
    for line in lines:
        tokens = line.split()
        if len(tokens) < 4 or "/" not in tokens[0] or not is_address(tokens[0].split("/", 1)[0]):
            continue
        prefix = canonical(tokens[0])
        at = next((i for i, t in enumerate(tokens[1:], start=1) if t.lower() in _SWITCH_TYPES), None)
        if not prefix or at is None or _loopback(prefix):
            continue
        middle, tail = tokens[1:at], tokens[at + 1 :]
        vlan = middle[-1] if len(middle) > 1 and middle[-1].isdigit() else ""
        gateway = " ".join(middle[:-1] if vlan else middle)
        kind, source = _SWITCH_TYPES[tokens[at].lower()]
        numbers = [t for t in tail if t.isdigit()]
        sub = [t for t in tail if not t.isdigit()]
        if sub and kind == "dynamic":
            source = f"{source} {sub[0]}"
        metric = int(numbers[0]) if numbers else None
        hop = gateway if is_address(gateway) else ""
        iface = f"VLAN{vlan}" if vlan else ("" if hop else gateway)
        routes.append(route_entry(prefix, kind, next_hop=hop, iface=iface, metric=metric, source=source))
    return routes


def _cx_origin(text: str) -> tuple[str, str]:
    """``(kind, source)`` of an AOS-CX origin (``C``, ``O/E2``, ``B/I``, or a word)."""
    code, _slash, kind_code = text.partition("/")
    kind, source = _CX_ORIGINS.get(code.lower(), ("dynamic", code))
    detail = _CX_TYPES.get(kind_code.upper(), kind_code)
    return kind, f"{source} {detail}" if detail and kind == "dynamic" else source


def _value(text: str) -> str:
    return "" if text in ("-", "") else text


def _cx_route(prefix: str, vrf: str, fields: list[str], origin: str) -> dict | None:
    """One AOS-CX route from the fields before and after its ``[d/m]``."""
    at = next((i for i, f in enumerate(fields) if _CX_DISTANCE.match(f)), None)
    if at is None or not origin:
        return None
    distance = _CX_DISTANCE.match(fields[at])
    metric = int(distance.group(2)) if distance else None
    before = [_value(f) for f in fields[:at]]
    hop = before[0] if before else ""
    iface = before[1] if len(before) > 1 else ""
    if hop and not is_address(hop):
        hop, iface = "", iface or hop
    kind, source = _cx_origin(origin)
    return route_entry(
        prefix, kind, next_hop="" if kind == "connected" else hop, iface=iface, vrf=vrf, metric=metric, source=source
    )


def _cx_routes(lines: list[str]) -> list[dict]:
    """An AOS-CX table, in the columns of 10.4 and later or the ``via`` lines of the releases before."""
    routes: list[dict] = []
    vrf = ""
    prefix, origin = "", ""
    for line in lines:
        header = _CX_VRF.match(line)
        if header:
            vrf, prefix = vrf_name(header.group("vrf")), ""
            continue
        old = _CX_OLD_PREFIX.match(line)
        if old:
            prefix, vrf = canonical(old.group("prefix")), vrf_name(old.group("vrf"))
            continue
        via = _CX_VIA.match(line)
        if via and prefix:
            fields = [f.strip() for f in via.group("body").split(",") if f.strip()]
            words = [f for f in fields if re.match(r"^[A-Za-z]", f) and not _CX_DISTANCE.match(f)]
            entry = _cx_route(prefix, vrf, [f for f in fields if f not in words[-1:]], words[-1] if words else "")
            if entry is not None:
                routes.append(entry)
            continue
        row = _CX_ROW.match(line)
        if row:
            prefix = canonical(row.group("prefix"))
            # NEXTHOP INTERFACE VRF(egress) ORIGIN/TYPE [D/M] AGE
            fields = row.group("rest").split()
            at = next((i for i, f in enumerate(fields) if _CX_DISTANCE.match(f)), None)
            origin = fields[at - 1] if at is not None and at >= 1 else ""
            entry = _cx_route(prefix, vrf, [*fields[: max(0, (at or 0) - 1)], *fields[(at or 0) :]], origin)
            if entry is not None:
                routes.append(entry)
            continue
        more = _CX_MORE.match(line)
        if more and prefix and origin:
            # Another next hop of the route above: NEXTHOP INTERFACE VRF(egress) [ORIGIN] [D/M] AGE.
            fields = more.group("rest").split()
            at = next((i for i, f in enumerate(fields) if _CX_DISTANCE.match(f)), 0)
            if at >= 4:
                fields = [*fields[: at - 1], *fields[at:]]
            entry = _cx_route(prefix, vrf, fields, origin)
            if entry is not None:
                routes.append(entry)
    return routes


def parse_routes(lines: list[str]) -> list[dict]:
    """An Aruba ``show ip route`` capture: the AOS-Switch table when it has
    its ``Destination Gateway VLAN Type`` header, else the AOS-CX one."""
    if any(_SWITCH_HEADER.match(line) for line in lines):
        return _switch_routes(lines)
    return _cx_routes(lines)
