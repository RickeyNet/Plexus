"""The running configuration of a Fortinet FortiGate (FortiOS), read for
path tracing.

The config backup feature stores what ``show`` or ``show
full-configuration`` printed. That text is a tree: ``config <path>`` opens
a table or a settings block, ``edit "<name>"`` an entry of a table, ``set
<key> <values>`` gives a value (a list when it has several, quoted or
bare), ``next`` closes an entry and ``end`` a block. ``parse_config`` reads
the tree once and takes from it what the forwarding block of an inventory
host needs and the route table capture does not give:

- the interfaces (``config system interface``) with their addresses
  (secondary ones too), VRF, state, alias and VRRP addresses, and the zone
  the policies name them by: a ``config system zone`` zone, or the SD-WAN
  zone of an SD-WAN member;
- the firewall policies (``config firewall policy``), in their order, as one
  stateful rule set applied to every flow that ends in the implicit deny.
  Each policy entry matches by the zones or interfaces of ``srcintf`` /
  ``dstintf``, its address objects and groups resolved to CIDRs and its
  services (custom ones, groups and the predefined ones FortiOS ships) to
  protocols and port expressions. A virtual IP named as a destination
  matches its mapped address: the engine applies destination NAT before it
  evaluates the policies. What cannot be turned into those (an FQDN,
  geography or dynamic address, a negated field, an Internet Service, a
  schedule other than ``always``, users and groups, an ICMP type, an IPsec
  action) is kept in the entry's ``unresolved`` list, so a flow it matches
  is unknown rather than decided;
- the NAT rules in the forwarding ``nat`` shape: each static NAT virtual IP
  (``config firewall vip``, port forwarding included) as destination NAT
  from its external interface, and the source NAT of each policy with ``set
  nat enable``, to the address of the egress interface or to its IP pool,
  between the policy's interfaces. With central NAT the central SNAT map is
  read instead;
- the static routes (blackhole and SD-WAN ones too), which routing
  protocols run, and what the configuration uses that is not read
  (``notes``): other VDOMs, SD-WAN rules, policy routes, IPsec tunnels,
  IPv6, proxy, multicast, local-in and DoS policies.

A configuration with VDOMs (``config vdom`` / ``edit <name>``, the shared
part under ``config global``) is read for its ``root`` VDOM, or its first
one when there is no ``root``; the others are a note. VRF 0 is the global
table; another VRF is named by its number, as ``parse_routes`` names it.

``parse_routes`` reads ``get router info routing-table all`` captures.

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from netcontrol.integrations.meraki.forwarding import ANY, INTERFACE, canonical, is_address, nat
from netcontrol.integrations.pathtrace.device_config import (
    AclEntry,
    ConfigInterface,
    ConfigPolicy,
    RunningConfig,
    StaticRoute,
    VirtualAddress,
)
from netcontrol.integrations.pathtrace.ios_config import ROUTING_PROTOCOLS, add_note as _note, mask_length
from netcontrol.integrations.pathtrace.route_tables import parse_cisco

__all__ = [
    "CENTRAL_NAT",
    "DOS_POLICIES",
    "FIREWALL_POLICIES",
    "IPSEC_TUNNELS",
    "IPV6_POLICIES",
    "LOCAL_IN_POLICIES",
    "MULTICAST_POLICIES",
    "NGFW_SECURITY_POLICIES",
    "POLICY_ROUTES",
    "PROXY_POLICIES",
    "SDWAN_RULES",
    "parse_config",
    "parse_routes",
]

# The rule set every flow meets, and the not-collected names a
# configuration gives when it uses what is not read.
FIREWALL_POLICIES = "Firewall policies"
IPV6_POLICIES = "IPv6 firewall policies"
PROXY_POLICIES = "Proxy policies"
MULTICAST_POLICIES = "Multicast policies"
LOCAL_IN_POLICIES = "Local-in policies (traffic to the FortiGate itself)"
DOS_POLICIES = "DoS policies"
IPSEC_TUNNELS = "IPsec VPN tunnels"
POLICY_ROUTES = "Policy-based routes"
SDWAN_RULES = "Policy-based routes (SD-WAN rules)"
CENTRAL_NAT = "Central NAT"
NGFW_SECURITY_POLICIES = "Security policies (NGFW policy-based mode)"

# The SD-WAN zone of a member that names none.
_SDWAN_ZONE = "virtual-wan-link"
_DEFAULT_ROUTE = "0.0.0.0/0"
# What FortiOS prints for an address, gateway or IP not set.
_UNSET = "0.0.0.0"  # nosec B104 - an unset address in a configuration, not a socket bind
_IP_PROTOCOLS = {"0": ANY, "1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "51": "ah", "58": "icmpv6"}
_PORTS = re.compile(r"^\d+(?:-\d+)?$")
# ICMP echo request (and ICMPv6's): the ICMP a trace asks about.
_ECHO = {"icmp": "8", "icmpv6": "128"}

# The services FortiOS ships, as the settings of a custom service, for a
# configuration (``show`` rather than ``show full-configuration``) that
# does not list them.
_PREDEFINED: dict[str, dict[str, list[str]]] = {
    "ALL": {"protocol": ["IP"]},
    "ALL_TCP": {"tcp-portrange": ["1-65535"]},
    "ALL_UDP": {"udp-portrange": ["1-65535"]},
    "ALL_ICMP": {"protocol": ["ICMP"]},
    "ALL_ICMP6": {"protocol": ["ICMP6"]},
    "GRE": {"protocol": ["IP"], "protocol-number": ["47"]},
    "AH": {"protocol": ["IP"], "protocol-number": ["51"]},
    "ESP": {"protocol": ["IP"], "protocol-number": ["50"]},
    "OSPF": {"protocol": ["IP"], "protocol-number": ["89"]},
    "PING": {"protocol": ["ICMP"], "icmptype": ["8"]},
    "PING6": {"protocol": ["ICMP6"], "icmptype": ["128"]},
    "TIMESTAMP": {"protocol": ["ICMP"], "icmptype": ["13"]},
    "INFO_REQUEST": {"protocol": ["ICMP"], "icmptype": ["15"]},
    "INFO_ADDRESS": {"protocol": ["ICMP"], "icmptype": ["17"]},
    "TRACEROUTE": {"udp-portrange": ["33434-33535"]},
    "HTTP": {"tcp-portrange": ["80"]},
    "HTTPS": {"tcp-portrange": ["443"]},
    "SSH": {"tcp-portrange": ["22"]},
    "TELNET": {"tcp-portrange": ["23"]},
    "FTP": {"tcp-portrange": ["21"]},
    "TFTP": {"udp-portrange": ["69"]},
    "DNS": {"tcp-portrange": ["53"], "udp-portrange": ["53"]},
    "NTP": {"tcp-portrange": ["123"], "udp-portrange": ["123"]},
    "DHCP": {"udp-portrange": ["67-68"]},
    "SMTP": {"tcp-portrange": ["25"]},
    "SMTPS": {"tcp-portrange": ["465"]},
    "IMAP": {"tcp-portrange": ["143"]},
    "IMAPS": {"tcp-portrange": ["993"]},
    "POP3": {"tcp-portrange": ["110"]},
    "POP3S": {"tcp-portrange": ["995"]},
    "NNTP": {"tcp-portrange": ["119"]},
    "SNMP": {"tcp-portrange": ["161-162"], "udp-portrange": ["161-162"]},
    "SYSLOG": {"udp-portrange": ["514"]},
    "RDP": {"tcp-portrange": ["3389"]},
    "VNC": {"tcp-portrange": ["5900"]},
    "SAMBA": {"tcp-portrange": ["139"]},
    "SMB": {"tcp-portrange": ["445"]},
    "DCE-RPC": {"tcp-portrange": ["135"], "udp-portrange": ["135"]},
    "LDAP": {"tcp-portrange": ["389"]},
    "LDAP_UDP": {"udp-portrange": ["389"]},
    "LDAPS": {"tcp-portrange": ["636"]},
    "KERBEROS": {"tcp-portrange": ["88"], "udp-portrange": ["88"]},
    "RADIUS": {"udp-portrange": ["1812", "1813"]},
    "RADIUS-OLD": {"udp-portrange": ["1645", "1646"]},
    "TACACS+": {"tcp-portrange": ["49"]},
    "IKE": {"udp-portrange": ["500", "4500"]},
    "L2TP": {"tcp-portrange": ["1701"], "udp-portrange": ["1701"]},
    "PPTP": {"tcp-portrange": ["1723"]},
    "MS-SQL": {"tcp-portrange": ["1433", "1434"]},
    "MYSQL": {"tcp-portrange": ["3306"]},
    "NFS": {"tcp-portrange": ["111", "2049"], "udp-portrange": ["111", "2049"]},
    "ONC-RPC": {"tcp-portrange": ["111"], "udp-portrange": ["111"]},
    "SIP": {"tcp-portrange": ["5060"], "udp-portrange": ["5060"]},
    "H323": {"tcp-portrange": ["1720", "1503"], "udp-portrange": ["1719"]},
    "IRC": {"tcp-portrange": ["6660-6669"]},
    "BGP": {"tcp-portrange": ["179"]},
    "RIP": {"udp-portrange": ["520"]},
    "SQUID": {"tcp-portrange": ["3128"]},
    "WINS": {"tcp-portrange": ["1512"], "udp-portrange": ["1512"]},
    "X-WINDOWS": {"tcp-portrange": ["6000-6063"]},
    "AFS3": {"tcp-portrange": ["7000-7009"], "udp-portrange": ["7000-7009"]},
    "CVSPSERVER": {"tcp-portrange": ["2401"], "udp-portrange": ["2401"]},
    "SCCP": {"tcp-portrange": ["2000"]},
    "MMS": {"tcp-portrange": ["1755"], "udp-portrange": ["1024-5000"]},
}
_PREDEFINED_GROUPS = {
    "Email Access": ["DNS", "IMAP", "IMAPS", "POP3", "POP3S", "SMTP", "SMTPS"],
    "Web Access": ["DNS", "HTTP", "HTTPS"],
    "Windows AD": ["DCE-RPC", "DNS", "KERBEROS", "LDAP", "LDAP_UDP", "SAMBA", "SMB"],
    "Exchange Server": ["DCE-RPC", "DNS", "HTTPS"],
}
# Routing protocol blocks and the tables that, holding an entry, show the
# protocol runs (``show full-configuration`` prints every block, configured or not).
_ROUTING = {
    "ospf": ("ospf", ("network", "ospf-interface", "area")),
    "ospf6": ("ospfv3", ("ospf6-interface", "area")),
    "bgp": ("bgp", ("neighbor", "neighbor-group", "neighbor-range", "network")),
    "rip": ("rip", ("network", "neighbor")),
    "isis": ("isis", ("isis-net", "isis-interface")),
}
# Tables whose entries are a not-collected note.
_NOTED_TABLES = (
    ("firewall policy6", IPV6_POLICIES),
    ("firewall proxy-policy", PROXY_POLICIES),
    ("firewall multicast-policy", MULTICAST_POLICIES),
    ("firewall local-in-policy", LOCAL_IN_POLICIES),
    ("firewall dos-policy", DOS_POLICIES),
    ("vpn ipsec phase1-interface", IPSEC_TUNNELS),
    ("vpn ipsec phase1", IPSEC_TUNNELS),
    ("router policy", POLICY_ROUTES),
)


# ── The configuration tree ───────────────────────────────────────────────────


@dataclass
class _Node:
    """A ``config`` block or an ``edit`` entry: its ``set`` values (keys in
    lower case), the ``config`` blocks inside it (paths in lower case) and,
    for a table, its entries by name."""

    settings: dict[str, list[str]] = field(default_factory=dict)
    sections: dict[str, _Node] = field(default_factory=dict)
    entries: dict[str, _Node] = field(default_factory=dict)

    def get(self, key: str) -> str:
        values = self.settings.get(key)
        return values[0] if values else ""

    def values(self, key: str) -> list[str]:
        return list(self.settings.get(key) or [])

    def on(self, key: str) -> bool:
        return self.get(key).lower() == "enable"

    def table(self, path: str) -> dict[str, _Node]:
        section = self.sections.get(path)
        return section.entries if section is not None else {}


_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(\n)|([^\s"]+)')


def _statements(text: str) -> list[list[str]]:
    """The statements of a configuration, each a list of words with quotes
    removed. A quoted value may span lines (a comment, a certificate)."""
    statements: list[list[str]] = []
    words: list[str] = []
    bare_head = True
    for match in _TOKEN.finditer(str(text or "").replace("\r\n", "\n").replace("\r", "\n")):
        quoted, newline, bare = match.groups()
        if newline is not None:
            if words and not (bare_head and words[0].startswith("#")):
                statements.append(words)
            words, bare_head = [], True
        elif quoted is not None:
            if not words:
                bare_head = False
            words.append(re.sub(r"\\(.)", r"\1", quoted))
        else:
            words.append(bare)
    if words and not (bare_head and words[0].startswith("#")):
        statements.append(words)
    return statements


def _tree(text: str) -> _Node:
    """The configuration as a tree. A missing ``next`` or ``end`` is
    forgiven: ``end`` closes the entries left open, ``edit`` the previous one."""
    root = _Node()
    stack: list[tuple[str, _Node]] = [("config", root)]
    for words in _statements(text):
        head = words[0].lower()
        kind, top = stack[-1]
        if head == "config" and len(words) > 1:
            node = top.sections.setdefault(" ".join(words[1:]).lower(), _Node())
            stack.append(("config", node))
        elif head == "edit" and len(words) > 1:
            if kind == "edit":
                stack.pop()
                top = stack[-1][1]
            stack.append(("edit", top.entries.setdefault(words[1], _Node())))
        elif head == "next":
            if kind == "edit":
                stack.pop()
        elif head == "end":
            while len(stack) > 1 and stack[-1][0] == "edit":
                stack.pop()
            if len(stack) > 1:
                stack.pop()
        elif head in ("set", "select") and len(words) > 1:
            top.settings[words[1].lower()] = words[2:]
        elif head == "append" and len(words) > 1:
            top.settings.setdefault(words[1].lower(), []).extend(words[2:])
        elif head == "unset" and len(words) > 1:
            top.settings.pop(words[1].lower(), None)
    return root


class _Scope:
    """Where the blocks of the VDOM read live: the VDOM itself, then the
    ``config global`` part, then the top of a configuration without VDOMs."""

    def __init__(self, tree: _Node) -> None:
        vdoms = tree.sections.get("vdom")
        names = [n for n in (vdoms.entries if vdoms is not None else {})]
        self.vdom: str | None = None
        self.others: list[str] = []
        self.nodes: list[_Node] = []
        if vdoms is not None and names:
            self.vdom = "root" if "root" in names else names[0]
            self.others = [n for n in names if n != self.vdom]
            self.nodes.append(vdoms.entries[self.vdom])
        if "global" in tree.sections:
            self.nodes.append(tree.sections["global"])
        self.nodes.append(tree)

    def section(self, path: str) -> _Node | None:
        return next((n.sections[path] for n in self.nodes if path in n.sections), None)

    def table(self, path: str) -> dict[str, _Node]:
        section = self.section(path)
        return section.entries if section is not None else {}

    def settings(self, path: str) -> _Node:
        return self.section(path) or _Node()


# ── Values ───────────────────────────────────────────────────────────────────


def _pair(values: list[str]) -> tuple[str, str] | None:
    """``(address, network)`` of ``A M`` or ``A/len``; ``None`` for none or 0.0.0.0."""
    if not values:
        return None
    address, _slash, length = values[0].partition("/")
    if not length and len(values) > 1:
        bits = mask_length(values[1])
        length = "" if bits is None else str(bits)
    if not is_address(address) or not length or address == _UNSET:
        return None
    network = canonical(f"{address}/{length}")
    return (address, network) if network else None


def _subnet(values: list[str]) -> str:
    """The network of ``A M`` or ``A/len`` (``""`` when it is none); 0.0.0.0/0 is ``any``."""
    if not values:
        return ""
    address, _slash, length = values[0].partition("/")
    if not length and len(values) > 1:
        bits = mask_length(values[1])
        length = "" if bits is None else str(bits)
    network = canonical(f"{address}/{length or 32}") if is_address(address) else ""
    return ANY if network == _DEFAULT_ROUTE else network


def _range(first: str, last: str) -> list[str]:
    """The CIDRs of an address range, ``[]`` when it is not one."""
    try:
        start, end = ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)
        return [str(n) for n in ipaddress.summarize_address_range(start, end)]
    except ValueError:
        return []


def _addresses(text: str) -> list[str]:
    """The CIDRs of ``A``, ``A/len`` or ``A-B`` (a VIP or pool address), ``[]`` when none."""
    first, _dash, last = text.partition("-")
    if last:
        return _range(first.strip(), last.strip())
    found = canonical(text)
    return [found] if found else []


def _vrf(value: str) -> str:
    """A VRF by its number; VRF 0 is the global table."""
    return "" if value.strip() in ("", "0") else value.strip()


def _ports(token: str) -> str | None:
    """A FortiOS port or port range as a port expression (the whole range is
    ``any``); ``None`` when it is not one."""
    if not _PORTS.match(token):
        return None
    low, _dash, high = token.partition("-")
    first, last = int(low), int(high or low)
    if first > last or last > 65535:
        return None
    if first <= 1 and last == 65535:
        return ANY
    return str(first) if first == last else f"{first}-{last}"


def _join(expressions: list[str]) -> str:
    if ANY in expressions:
        return ANY
    return ",".join(dict.fromkeys(expressions))


# ── Objects ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Service:
    protocol: str
    dst_ports: str = ANY
    src_ports: str = ANY
    unresolved: tuple[str, ...] = ()


class _Objects:
    """The address objects, groups, virtual IPs, services and IP pools of
    the VDOM, resolved on demand."""

    def __init__(self, scope: _Scope) -> None:
        self.addresses = scope.table("firewall address")
        self.groups = scope.table("firewall addrgrp")
        self.vips = scope.table("firewall vip")
        self.vip_groups = scope.table("firewall vipgrp")
        self.services = scope.table("firewall service custom")
        self.service_groups = scope.table("firewall service group")
        self.pools = scope.table("firewall ippool")

    def address(self, name: str, seen: frozenset[str] = frozenset()) -> tuple[list[str], list[str]]:
        """``(cidrs, unresolved)`` of an address, address group, virtual IP
        (its mapped address) or virtual IP group."""
        if name.lower() == "all":
            return [ANY], []
        if name in seen:
            return [ANY], [f"address group {name} (nested in itself)"]
        if name in self.addresses:
            return self._object(name, self.addresses[name])
        if name in self.groups:
            group = self.groups[name]
            cidrs, unresolved = self._members(group.values("member"), seen | {name})
            if group.on("exclude"):
                unresolved.append(f"address group {name} (excludes {', '.join(group.values('exclude-member'))})")
            return cidrs, unresolved
        if name in self.vips:
            return self._mapped(name, self.vips[name])
        if name in self.vip_groups:
            return self._members(self.vip_groups[name].values("member"), seen | {name})
        return [ANY], [f"address {name} (not in the configuration)"]

    def addresses_of(self, names: list[str]) -> tuple[list[str], list[str]]:
        if not names:
            return [ANY], ["no address"]
        return self._members(names, frozenset())

    def _members(self, names: list[str], seen: frozenset[str]) -> tuple[list[str], list[str]]:
        cidrs: list[str] = []
        unresolved: list[str] = []
        for member in names:
            found, missing = self.address(member, seen)
            unresolved.extend(missing)
            if not missing:
                cidrs.extend(found)
        if ANY in cidrs:
            return [ANY], unresolved
        if not cidrs:
            return [ANY], unresolved or ["an empty address group"]
        return list(dict.fromkeys(cidrs)), unresolved

    @staticmethod
    def _object(name: str, node: _Node) -> tuple[list[str], list[str]]:
        kind = node.get("type").lower() or "ipmask"
        if kind in ("ipmask", "interface-subnet"):
            network = _subnet(node.values("subnet")) if node.values("subnet") else ANY
            return ([network], []) if network else ([ANY], [f"address {name}"])
        if kind == "iprange":
            cidrs = _range(node.get("start-ip"), node.get("end-ip") or node.get("start-ip"))
            return (cidrs, []) if cidrs else ([ANY], [f"address {name} (range)"])
        detail = {
            "fqdn": node.get("fqdn"),
            "geography": node.get("country"),
            "wildcard": " ".join(node.values("wildcard")),
            "wildcard-fqdn": node.get("wildcard-fqdn"),
            "dynamic": node.get("sdn"),
            "mac": " ".join(node.values("macaddr")),
        }.get(kind, "")
        label = f"{kind} address {name}"
        return [ANY], [f"{label} ({detail})" if detail else label]

    def _mapped(self, name: str, vip: _Node) -> tuple[list[str], list[str]]:
        """A virtual IP as a policy destination: its mapped address, the
        destination a policy sees once destination NAT has applied."""
        kind = vip.get("type").lower() or "static-nat"
        mapped = [c for value in vip.values("mappedip") for c in _addresses(value)]
        if kind != "static-nat" or not mapped:
            return [ANY], [f"virtual IP {name} ({kind})"]
        return mapped, []

    def service(self, name: str, seen: frozenset[str] = frozenset()) -> list[_Service]:
        if name in seen:
            return [_Service(ANY, unresolved=(f"service group {name} (nested in itself)",))]
        if name in self.service_groups or (name not in self.services and name in _PREDEFINED_GROUPS):
            members = (
                self.service_groups[name].values("member") if name in self.service_groups else _PREDEFINED_GROUPS[name]
            )
            found = [s for member in members for s in self.service(member, seen | {name})]
            return found or [_Service(ANY, unresolved=(f"service group {name} (empty)",))]
        if name in self.services:
            return _custom(name, self.services[name].settings)
        if name in _PREDEFINED:
            return _custom(name, _PREDEFINED[name])
        return [_Service(ANY, unresolved=(f"service {name} (not in the configuration)",))]

    def pool(self, name: str) -> list[str]:
        node = self.pools.get(name)
        if node is None:
            return []
        return _range(node.get("startip"), node.get("endip") or node.get("startip"))


def _custom(name: str, settings: dict[str, list[str]]) -> list[_Service]:
    """The services of a custom service (or a predefined one, given as its settings)."""
    node = _Node(settings=settings)
    protocol = node.get("protocol").upper() or "TCP/UDP/SCTP"
    extra: list[str] = []
    for key in ("iprange", "fqdn"):
        value = node.get(key)
        if value and value not in (_UNSET, ""):
            extra.append(f"service {name} (destination {value})")
    if protocol.startswith("TCP/UDP"):
        found: list[_Service] = []
        for key, proto in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"), ("sctp-portrange", "sctp")):
            for token in node.values(key):
                dst_text, _colon, src_text = token.partition(":")
                dst, src = _ports(dst_text), _ports(src_text) if src_text else ANY
                if dst is None or src is None:
                    found.append(_Service(proto, unresolved=(f"service {name} (ports {token})", *extra)))
                else:
                    found.append(_Service(proto, dst, src, tuple(extra)))
        return found or [_Service(ANY, unresolved=(f"service {name} (no ports)", *extra))]
    if protocol in ("ICMP", "ICMP6"):
        proto = "icmp" if protocol == "ICMP" else "icmpv6"
        icmp_type = node.get("icmptype")
        if icmp_type and icmp_type != _ECHO[proto]:
            extra.append(f"service {name} (ICMP type {icmp_type})")
        return [_Service(proto, unresolved=tuple(extra))]
    if protocol == "IP":
        number = node.get("protocol-number") or "0"
        return [_Service(_IP_PROTOCOLS.get(number, number), unresolved=tuple(extra))]
    # Explicit proxy services (HTTP, FTP, CONNECT, SOCKS) apply to proxy policies.
    return [_Service(ANY, unresolved=(f"service {name} ({protocol.lower()})", *extra))]


def _service_entries(services: list[_Service]) -> list[_Service]:
    """Services merged into as few entries as match the same: one per
    protocol, source ports and unresolved parts, their ports joined."""
    if any(s.protocol == ANY and s.dst_ports == ANY and s.src_ports == ANY and not s.unresolved for s in services):
        return [_Service(ANY)]
    merged: dict[tuple[str, str, tuple[str, ...]], list[str]] = {}
    for each in services:
        merged.setdefault((each.protocol, each.src_ports, each.unresolved), []).append(each.dst_ports)
    return [_Service(protocol, _join(ports), src, unresolved) for (protocol, src, unresolved), ports in merged.items()]


# ── Interfaces ───────────────────────────────────────────────────────────────


@dataclass
class _Member:
    """An SD-WAN member: its interface, zone and gateway."""

    interface: str
    zone: str
    gateway: str


def _interfaces(scope: _Scope, config: RunningConfig) -> dict[str, ConfigInterface]:
    found: dict[str, ConfigInterface] = {}
    learned: list[str] = []
    for name, node in scope.table("system interface").items():
        vdom = node.get("vdom")
        if scope.vdom is not None and vdom and vdom != scope.vdom:
            continue
        conf = ConfigInterface(
            name,
            description=node.get("description"),
            vrf=_vrf(node.get("vrf")),
            shutdown=node.get("status").lower() == "down",
        )
        alias = node.get("alias")
        if alias and alias != name:
            conf.aliases.append(alias)
        if node.get("role").lower() == "wan":
            conf.kind = "wan"
        if node.get("mode").lower() in ("dhcp", "pppoe"):
            learned.append(name)
        else:
            primary = _pair(node.values("ip"))
            if primary is not None:
                conf.addresses.append(primary)
            if node.get("secondary-ip").lower() != "disable":
                for secondary in node.table("secondaryip").values():
                    pair = _pair(secondary.values("ip"))
                    if pair is not None:
                        conf.addresses.append(pair)
        for vrid, vrrp in node.table("vrrp").items():
            address = vrrp.get("vrip")
            if is_address(address) and address != _UNSET:
                conf.virtual.append(VirtualAddress("VRRP", vrrp.get("vrid") or vrid, address))
        found[name] = conf
    for zone, node in scope.table("system zone").items():
        for member in node.values("interface"):
            if member in found:
                found[member].zone = zone
    if learned:
        _note(config, f"Interface addresses learned by DHCP or PPPoE ({', '.join(learned)})")
    return found


def _sdwan(scope: _Scope, interfaces: dict[str, ConfigInterface], config: RunningConfig) -> list[_Member]:
    """The SD-WAN members (``config system sdwan``, ``virtual-wan-link``
    before FortiOS 6.4), each interface taking its SD-WAN zone, which the
    policies name."""
    for path in ("system sdwan", "system virtual-wan-link"):
        node = scope.section(path)
        if node is None or not node.on("status"):
            continue
        members: list[_Member] = []
        for member in node.table("members").values():
            name = member.get("interface")
            gateway = member.get("gateway")
            members.append(_Member(name, member.get("zone") or _SDWAN_ZONE, gateway if gateway != _UNSET else ""))
            if name in interfaces and not interfaces[name].zone:
                interfaces[name].zone = member.get("zone") or _SDWAN_ZONE
        if node.table("service"):
            _note(config, SDWAN_RULES)
        return members
    return []


# ── Policies and NAT ─────────────────────────────────────────────────────────


def _zones(values: list[str]) -> list[str]:
    """``srcintf`` / ``dstintf``: zones or interfaces; ``any`` matches every one."""
    return [] if any(v.lower() == "any" for v in values) else list(values)


@dataclass
class _Policy:
    """One firewall policy, read: its entries and what its NAT needs."""

    sequence: int | None
    name: str
    enabled: bool
    action: str
    src_zones: list[str]
    dst_zones: list[str]
    src: list[str]
    dst: list[str]
    services: list[_Service]
    unresolved: list[str]
    nat: bool = False
    pools: list[str] = field(default_factory=list)


def _read_policy(key: str, node: _Node, objects: _Objects, ngfw: bool) -> _Policy | None:
    """A firewall policy; ``None`` for an IPv6-only one (FortiOS 7 policies hold both)."""
    if (
        not node.values("srcaddr")
        and not node.values("dstaddr")
        and (node.values("srcaddr6") or node.values("dstaddr6"))
    ):
        return None
    action = node.get("action").lower() or "deny"
    unresolved: list[str] = []
    src, missing = objects.addresses_of(node.values("srcaddr"))
    unresolved += missing
    dst, missing = objects.addresses_of(node.values("dstaddr"))
    unresolved += missing
    for setting, text in (
        ("srcaddr-negate", "negated source addresses"),
        ("dstaddr-negate", "negated destination addresses"),
        ("service-negate", "negated services"),
        ("internet-service", "Internet Service destinations"),
        ("internet-service-src", "Internet Service sources"),
        ("ztna-status", "ZTNA tags"),
    ):
        if node.on(setting):
            unresolved.append(text)
    schedule = node.get("schedule")
    if schedule and schedule.lower() != "always":
        unresolved.append(f"schedule {schedule}")
    identities = [v for key_ in ("users", "groups", "fsso-groups") for v in node.values(key_)]
    if identities:
        unresolved.append(f"users and groups ({', '.join(identities)})")
    if action == "ipsec":
        unresolved.append(f"policy-based IPsec VPN {node.get('vpntunnel')}".strip())
    if ngfw:
        unresolved.append("the security policies of NGFW policy-based mode")
    services = [s for name in node.values("service") or ["ALL"] for s in objects.service(name)]
    if node.on("ippool"):
        pools = [c for name in node.values("poolname") for c in objects.pool(name)]
    else:
        pools = []
    return _Policy(
        sequence=int(key) if key.isdigit() else None,
        name=node.get("name"),
        enabled=node.get("status").lower() != "disable",
        action="deny" if action == "deny" else "allow",
        src_zones=_zones(node.values("srcintf")),
        dst_zones=_zones(node.values("dstintf")),
        src=src,
        dst=dst,
        services=services,
        unresolved=list(dict.fromkeys(unresolved)),
        nat=action != "deny" and node.on("nat"),
        pools=pools,
    )


def _entries(policy: _Policy, comment: str) -> list[AclEntry]:
    return [
        AclEntry(
            policy.sequence,
            policy.action,
            protocol=service.protocol,
            src=policy.src,
            src_ports=service.src_ports,
            dst=policy.dst,
            dst_ports=service.dst_ports,
            comment=comment,
            unresolved=list(dict.fromkeys([*policy.unresolved, *service.unresolved])),
            name=policy.name,
            src_zones=policy.src_zones,
            dst_zones=policy.dst_zones,
            enabled=policy.enabled,
        )
        for service in _service_entries(policy.services)
    ]


def _pairs(policy: _Policy) -> list[tuple[str, str]]:
    return [(s, d) for s in policy.src_zones or [""] for d in policy.dst_zones or [""]]


def _overlap(a: list[tuple[str, str]], b: list[tuple[str, str]]) -> bool:
    def same(x: str, y: str) -> bool:
        return not x or not y or x.lower() == y.lower()

    return any(same(s1, s2) and same(d1, d2) for s1, d1 in a for s2, d2 in b)


def _protocol_of(services: list[_Service]) -> str:
    protocols = {s.protocol for s in services}
    return protocols.pop() if len(protocols) == 1 else ANY


def _policy_nat(policies: list[_Policy], entries: list[dict]) -> None:
    """The source NAT of the policies with ``set nat enable``: the source
    becomes the address of the egress interface, or of the IP pool, for the
    flows between the policy's interfaces. The engine picks a source NAT
    rule by interfaces, addresses and protocol, not by port, so an earlier
    policy without NAT that a NAT policy's flows also meet is an identity
    rule in front of it, when its addresses and services are all resolved
    and it matches on no port."""
    for position, policy in enumerate(policies):
        if not policy.enabled or policy.action != "allow":
            continue
        number = policy.sequence if policy.sequence is not None else position + 1
        name = policy.name or f"policy {number}"
        if policy.nat:
            translated = policy.pools or [INTERFACE]
        elif (
            not policy.unresolved
            and all(s.dst_ports == ANY and s.src_ports == ANY and not s.unresolved for s in policy.services)
            and any(p.nat and p.enabled and _overlap(_pairs(policy), _pairs(p)) for p in policies[position + 1 :])
        ):
            translated = list(policy.src)
        else:
            continue
        for src_if, dst_if in _pairs(policy):
            entries.append(
                nat(
                    len(entries) + 1,
                    "policy_nat",
                    name=name,
                    original_src=policy.src,
                    original_dst=policy.dst,
                    translated_src=translated,
                    protocol=_protocol_of(policy.services),
                    src_interface=src_if,
                    dst_interface=dst_if,
                )
            )


def _vip_nat(objects: _Objects, entries: list[dict], config: RunningConfig) -> None:
    """Each static NAT virtual IP as destination NAT from its external
    interface (``any``: every interface); a range maps address by address."""
    for name, vip in objects.vips.items():
        kind = vip.get("type").lower() or "static-nat"
        if kind != "static-nat":
            _note(config, f"Virtual IP {name} ({kind})")
            continue
        external = [c for value in vip.values("extip") for c in _addresses(value)]
        if vip.get("extip") == _UNSET:
            external = [INTERFACE]
        mapped = [c for value in vip.values("mappedip") for c in _addresses(value)]
        if not external or not mapped:
            _note(config, f"Virtual IP {name} (its addresses are not read)")
            continue
        if external != [INTERFACE] and len(external) != len(mapped):
            _note(config, f"Virtual IP {name} (its ranges do not line up)")
            continue
        if vip.values("service"):
            _note(config, f"Virtual IP {name} (matches on services)")
            continue
        protocol, original_port, translated_port = ANY, "", ""
        if vip.on("portforward"):
            protocol = vip.get("protocol").lower() or "tcp"
            original_port = _ports(vip.get("extport")) or ""
            translated_port = _ports(vip.get("mappedport")) or original_port
        sources = [c for value in vip.values("src-filter") for c in _addresses(value)] or [ANY]
        interfaces = _zones(vip.values("extintf")) or [""]
        pairs = [(INTERFACE, m) for m in mapped[:1]] if external == [INTERFACE] else list(zip(external, mapped))
        for ext_if in interfaces:
            for original, translated in pairs:
                entries.append(
                    nat(
                        len(entries) + 1,
                        "vip",
                        name=name,
                        enabled=vip.get("status").lower() != "disable",
                        original_src=sources,
                        original_dst=[original],
                        translated_dst=[translated],
                        protocol=protocol,
                        original_port=original_port,
                        translated_port=translated_port,
                        src_interface=ext_if,
                    )
                )
                if vip.on("nat-source-vip") and original != INTERFACE:
                    # The mapped server's own connections leave as the external address.
                    entries.append(
                        nat(
                            len(entries) + 1,
                            "vip",
                            name=f"{name} (source)",
                            original_src=[translated],
                            translated_src=[original],
                            dst_interface=ext_if,
                        )
                    )


def _central_nat(scope: _Scope, objects: _Objects, entries: list[dict], config: RunningConfig) -> None:
    """The central SNAT map, in order. A rule that matches on ports, or
    names an address or pool that does not resolve, is a note instead."""
    for key, node in scope.table("firewall central-snat-map").items():
        label = f"Central SNAT rule {key}"
        if node.get("orig-port") not in ("", "0", "0-0"):
            _note(config, f"{label} (matches on ports)")
            continue
        src, missing = objects.addresses_of(node.values("orig-addr"))
        dst, missing_dst = objects.addresses_of(node.values("dst-addr"))
        if missing or missing_dst:
            _note(config, f"{label} (its addresses are not all resolved)")
            continue
        if node.get("nat").lower() == "disable":
            translated = list(src)
        elif node.values("nat-ippool"):
            translated = [c for name in node.values("nat-ippool") for c in objects.pool(name)]
            if not translated:
                _note(config, f"{label} (its IP pool is not read)")
                continue
        else:
            translated = [INTERFACE]
        number = node.get("protocol") or "0"
        for src_if in _zones(node.values("srcintf")) or [""]:
            for dst_if in _zones(node.values("dstintf")) or [""]:
                entries.append(
                    nat(
                        len(entries) + 1,
                        "central_snat",
                        name=f"rule {key}",
                        enabled=node.get("status").lower() != "disable",
                        original_src=src,
                        original_dst=dst,
                        translated_src=translated,
                        protocol=_IP_PROTOCOLS.get(number, number),
                        src_interface=src_if,
                        dst_interface=dst_if,
                    )
                )


def _policies(scope: _Scope, objects: _Objects, config: RunningConfig) -> list[_Policy]:
    section = scope.section("firewall policy")
    settings = scope.settings("system settings")
    ngfw = settings.get("ngfw-mode").lower() == "policy-based"
    if ngfw:
        _note(config, NGFW_SECURITY_POLICIES)
    read: list[_Policy] = []
    entries: list[AclEntry] = []
    for key, node in (section.entries if section is not None else {}).items():
        policy = _read_policy(key, node, objects, ngfw)
        if policy is not None:
            read.append(policy)
            entries.extend(_entries(policy, node.get("comments")))
    for zone, node in scope.table("system zone").items():
        if node.get("intrazone").lower() == "allow":
            entries.append(
                AclEntry(None, "allow", name=f"Intrazone traffic of {zone}", src_zones=[zone], dst_zones=[zone])
            )
    # Without a policy table the backup is partial: what no entry matches is not known.
    default = "deny" if section is not None else "unknown"
    config.policies.append(ConfigPolicy(FIREWALL_POLICIES, entries, kind="policy", default=default, stateful=True))
    return read


# ── Routes ───────────────────────────────────────────────────────────────────


def _static_routes(
    scope: _Scope,
    objects: _Objects,
    interfaces: dict[str, ConfigInterface],
    members: list[_Member],
    config: RunningConfig,
) -> None:
    for node in scope.table("router static").values():
        if node.get("status").lower() == "disable":
            continue
        if node.get("dstaddr"):
            cidrs, missing = objects.address(node.get("dstaddr"))
            prefix = cidrs[0] if len(cidrs) == 1 and not missing else ""
            prefix = _DEFAULT_ROUTE if prefix == ANY else prefix
            if not prefix:
                _note(config, f"Static route to {node.get('dstaddr')} (not an address)")
                continue
        elif node.values("internet-service"):
            _note(config, f"Static route to Internet Service {node.get('internet-service')}")
            continue
        else:
            prefix = _subnet(node.values("dst")) if node.values("dst") else _DEFAULT_ROUTE
            prefix = _DEFAULT_ROUTE if prefix == ANY else prefix
            if not prefix:
                continue
        device = node.get("device")
        gateway = node.get("gateway")
        gateway = gateway if is_address(gateway) and gateway != _UNSET else ""
        distance = int(node.get("distance")) if node.get("distance").isdigit() else 10
        vrf = _vrf(node.get("vrf")) or (interfaces[device].vrf if device in interfaces else "")
        comment = node.get("comment")
        if node.on("blackhole"):
            config.static_routes.append(StaticRoute(prefix, "", "Null", vrf, distance, comment))
            continue
        zones = node.values("sdwan-zone") or ([_SDWAN_ZONE] if node.on("sdwan") or node.on("virtual-wan-link") else [])
        if zones:
            over = [m for m in members if m.zone in zones]
            if not over:
                _note(config, f"Static route to {prefix} over SD-WAN")
            for member in over:
                vrf_of = interfaces[member.interface].vrf if member.interface in interfaces else vrf
                config.static_routes.append(
                    StaticRoute(prefix, member.gateway, member.interface, vrf_of, distance, comment)
                )
            continue
        if not device and not gateway:
            continue
        config.static_routes.append(StaticRoute(prefix, gateway, device, vrf, distance, comment))


def _routing(scope: _Scope, config: RunningConfig) -> None:
    for block, (protocol, tables) in _ROUTING.items():
        node = scope.section(f"router {block}")
        if node is not None and any(node.table(t) for t in tables):
            name = ROUTING_PROTOCOLS[protocol]
            if name not in config.routing:
                config.routing.append(name)


def parse_config(text: str) -> RunningConfig:
    """What a FortiGate configuration (``show`` or ``show
    full-configuration``) says about forwarding: interfaces and zones,
    firewall policies, NAT, static routes, routing protocols."""
    config = RunningConfig()
    scope = _Scope(_tree(text))
    if scope.others:
        _note(config, f"Other VDOMs ({', '.join(scope.others)})")
    interfaces = _interfaces(scope, config)
    members = _sdwan(scope, interfaces, config)
    config.interfaces = list(interfaces.values())
    objects = _Objects(scope)
    policies = _policies(scope, objects, config)
    _vip_nat(objects, config.nat, config)
    if scope.settings("system settings").on("central-nat"):
        _central_nat(scope, objects, config.nat, config)
    else:
        _policy_nat(policies, config.nat)
    _static_routes(scope, objects, interfaces, members, config)
    _routing(scope, config)
    for path, name in _NOTED_TABLES:
        if scope.table(path):
            _note(config, name)
    return config


# ── Route table captures ─────────────────────────────────────────────────────

_VRF_HEADER = re.compile(r"^\s*Routing table for VRF=(\S+)", re.IGNORECASE)
# ``via 10.255.0.1 (recursive via 10.0.0.2, port2)``: the interface it leaves by.
_RECURSIVE = re.compile(r"\s*\(recursive (?:via [^,()]+,\s*|is directly connected,\s*)([^)\s]+)\)")
_PARENTHESES = re.compile(r"\s*\([^)]*\)")
# ``via VPN-HQ tunnel 203.0.113.9``: an IPsec tunnel interface and its remote gateway.
_TUNNEL = re.compile(r"via (\S+) tunnel \S+?(?=,|$)")
_NULL = re.compile(r"is (?:a summary|blackhole)[^,]*, Null\b|is blackhole\b")
# ``, [1/0]``: the weight and priority FortiOS prints after a route.
_WEIGHT = re.compile(r",\s*\[\d+/\d+\]\s*$")


def parse_routes(lines: list[str]) -> list[dict]:
    """A FortiGate ``get router info routing-table all`` capture: the Cisco
    shape once its VRF headers, recursive next hops, tunnel next hops,
    blackhole routes and weights are put the way ``parse_cisco`` reads them.
    VRF 0 is the global table; another VRF is named by its number."""
    normal: list[str] = []
    for line in lines:
        header = _VRF_HEADER.match(line)
        if header:
            normal.append(f"Routing Table: {_vrf(header.group(1)) or 'default'}")
            continue
        text = _RECURSIVE.sub(r", \1", line)
        text = _PARENTHESES.sub("", text)
        text = _TUNNEL.sub(r"via \1", text)
        text = _NULL.sub("via Null", text)
        normal.append(_WEIGHT.sub("", text))
    return parse_cisco(normal, eos=False)
