"""Route table captures of inventory hosts, read into forwarding routes.

The monitoring poll stores what ``show ip route`` (or the platform's
equivalent) printed. Each platform's parser here turns those lines into the
forwarding routes of ``netcontrol.integrations.meraki.forwarding.route``:
``parse_cisco`` reads Cisco IOS / IOS-XE / IOS-XR and ASA / FTD tables
(``eos=True``: Arista EOS, whose codes differ), ``parse_nxos`` NX-OS tables,
and ``parse_cisco_family`` picks between them. The tables of every VRF
follow one another, each under its header (``Routing Table: NAME`` on IOS,
``VRF: NAME`` on IOS-XR and EOS, ``IP Route Table for VRF "NAME"`` on
NX-OS). The parsers of the other platforms live beside their configuration
readers (see ``platforms``); ``parse_route_table`` wraps any of them with
the empty, unrecognised and truncated checks.

``route_entry`` builds one route, ``interface_key`` matches interface names
across the abbreviations the platforms print, ``vrf_name`` drops the names
of the global table.

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any

from netcontrol.integrations.meraki.forwarding import canonical, is_address
from netcontrol.integrations.pathtrace.ios_config import mask_length

RouteParser = Callable[[list[str]], list[dict]]

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
# IOS-XR and EOS (``VRF name:`` on older EOS releases).
_VRF_EOS = re.compile(r"^\s*VRF(?: name)?:\s*(?P<vrf>\S+)")
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
LOCAL = "Local address"
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
    # IOS-XR.
    "mg": "management",
    "mgmteth": "management",
    "tengige": "tengigabitethernet",
    "fortygige": "fortygigabitethernet",
    "be": "bundle-ether",
    "bundle-ether": "bundle-ether",
}
# The interfaces a route to nowhere names: IOS Null0, Aruba blackhole / reject.
_DISCARD = ("blackhole", "reject")


def interface_key(name: str) -> str:
    """A loose key for an interface name: lower-case, abbreviations expanded."""
    text = str(name or "").strip().lower().replace(" ", "")
    match = re.match(r"^([a-z-]+)(.*)$", text)
    if not match:
        return text
    return _ABBREVIATIONS.get(match.group(1), match.group(1)) + match.group(2)


def route_entry(
    prefix: str,
    kind: str,
    *,
    next_hop: str = "",
    iface: str = "",
    vrf: str = "",
    metric: int | None = None,
    source: str,
) -> dict[str, Any]:
    if iface.lower().startswith("null") or iface.lower() in _DISCARD:
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


def vrf_name(name: str) -> str:
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
        return "connected", LOCAL
    if head == "S":
        return ("default" if "*" in code else "static"), "Static route"
    protocol = _PROTOCOLS.get(head, word)
    detail = _SUB_CODES.get(sub, "")
    return "dynamic", f"{protocol} {detail}" if detail else protocol


def parse_cisco(lines: list[str], eos: bool) -> list[dict]:
    routes: list[dict] = []
    vrf = ""
    subnetted: dict[str, int] = {}
    current: dict[str, Any] | None = None
    for line in lines:
        header = _VRF_IOS.match(line) or _VRF_EOS.match(line)
        if header:
            vrf, current = vrf_name(header.group("vrf")), None
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
                route_entry(
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
            # IOS: ``, Vlan10``; IOS-XR: ``, 2w0d, GigabitEthernet0/0/0/0`` (the uptime first).
            fields = [f.strip() for f in rest.split("directly connected", 1)[1].split(",") if f.strip()]
            iface = next((f.split()[0] for f in fields if re.match(r"^[A-Za-z]", f)), "")
            routes.append(route_entry(prefix, kind, iface=iface, vrf=vrf, source=source))
        elif " via " in f" {rest} ":
            hop, iface = _next_hop_and_interface(rest.split("via", 1)[1])
            routes.append(route_entry(prefix, kind, next_hop=hop, iface=iface, vrf=vrf, metric=metric, source=source))
        elif "connected by VPN" in rest:
            # An ASA's route to a remote access VPN client.
            fields = [f.strip() for f in rest.split(",") if f.strip()]
            iface = fields[-1] if len(fields) > 1 and re.match(r"^[A-Za-z]", fields[-1]) else ""
            routes.append(route_entry(prefix, "dynamic", iface=iface, vrf=vrf, metric=metric, source="VPN client"))
        elif "is a summary" in rest:
            fields = [f.strip() for f in rest.split(",") if f.strip()]
            iface = fields[-1] if fields and re.match(r"^[A-Za-z]", fields[-1]) else ""
            routes.append(route_entry(prefix, kind, iface=iface, vrf=vrf, metric=metric, source=f"{source} summary"))
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


def parse_nxos(lines: list[str]) -> list[dict]:
    routes: list[dict] = []
    vrf = ""
    prefix = ""
    for line in lines:
        header = _VRF_NXOS.match(line)
        if header:
            vrf, prefix = vrf_name(header.group("vrf")), ""
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
            route_entry(
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


def parse_cisco_family(lines: list[str]) -> list[dict]:
    """A Cisco capture: NX-OS when it has NX-OS's ``ubest/mbest`` lines, else
    IOS / IOS-XE / IOS-XR / ASA (``show ip route`` or ``show route``)."""
    if any("ubest/mbest" in line for line in lines):
        return parse_nxos(lines)
    return parse_cisco(lines, eos=False)


def parse_eos(lines: list[str]) -> list[dict]:
    """An Arista EOS ``show ip route`` capture (with ``show ip route vrf all``)."""
    return parse_cisco(lines, eos=True)


def parse_route_table(text: str, parser: RouteParser | None) -> tuple[list[dict], list[str]]:
    """Routes of a route table capture as forwarding routes, read by the
    platform's ``parser`` (``None``: a platform whose captures are not read),
    and the names of what could not be parsed (for not_collected)."""
    raw = str(text or "")
    if not raw.strip():
        return [], [EMPTY_CAPTURE]
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    routes = parser(lines) if parser is not None else []
    unique: dict[tuple, dict] = {}
    for item in routes:
        unique.setdefault((item["vrf"], item["prefix"], item["kind"], item["next_hop"], item["interface"]), item)
    missing: list[str] = []
    if not unique:
        return [], [NOT_RECOGNISED]
    if len(raw) >= CAPTURE_LIMIT:
        missing.append(TRUNCATED)
    return list(unique.values()), missing
