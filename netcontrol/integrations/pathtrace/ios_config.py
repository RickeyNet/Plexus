"""The running configuration of a Cisco IOS / IOS-XE or NX-OS device, read
for path tracing.

The config backup feature stores each host's running configuration
(``config_backups.config_text``). ``parse_config`` reads from it what the
forwarding block of an inventory host needs and the route table capture
does not give: the interfaces with their addresses, VRF, state, access
groups and HSRP / VRRP / GLBP virtual addresses; the access lists, with the
object groups they name resolved; the static routes, including those of
VRFs; and which routing protocols run.

Access list entries come out in the forwarding rule terms
(``netcontrol.integrations.meraki.forwarding.rule``): ``allow`` or ``deny``,
CIDRs or ``any``, port expressions such as ``80,443`` or ``1024-65535``.
What cannot be turned into those (an object group or port name the
configuration does not define, a wildcard mask that is not a prefix, a
time range, DSCP or TCP flag match) is kept in the entry's ``unresolved``
list, so a flow it matches is unknown rather than decided.

The IOS and NX-OS dialects are read in one pass: they share the shape of an
interface block, and the differences (``ip address A/len``, ``vrf member``,
``ip access-list NAME`` with no type, ``addrgroup`` / ``portgroup``,
``vrf context`` static routes, ``hsrp`` / ``vrrp`` sub-blocks) do not
collide. IPv6 access lists are not read.

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from netcontrol.integrations.meraki.forwarding import ANY, canonical, is_address

# Not-collected names a configuration gives when it uses what is not read.
IPV6_ACCESS_LISTS = "IPv6 access lists"
PORT_ACCESS_LISTS = "Port access lists"
VLAN_ACCESS_MAPS = "VLAN access maps"
POLICY_BASED_ROUTES = "Policy-based routes (route maps on interfaces)"
ZONE_FIREWALL = "Zone-based firewall policies"

ROUTING_PROTOCOLS = {
    "ospf": "OSPF",
    "ospfv3": "OSPFv3",
    "eigrp": "EIGRP",
    "bgp": "BGP",
    "rip": "RIP",
    "isis": "IS-IS",
    "odr": "ODR",
}

# The port names IOS and NX-OS print in access lists, TCP and UDP together.
PORT_NAMES = {
    "bgp": 179,
    "biff": 512,
    "bootpc": 68,
    "bootps": 67,
    "chargen": 19,
    "cmd": 514,
    "daytime": 13,
    "discard": 9,
    "dnsix": 195,
    "domain": 53,
    "drip": 3949,
    "echo": 7,
    "exec": 512,
    "finger": 79,
    "ftp": 21,
    "ftp-data": 20,
    "gopher": 70,
    "hostname": 101,
    "http": 80,
    "https": 443,
    "ident": 113,
    "irc": 194,
    "isakmp": 500,
    "kerberos": 88,
    "klogin": 543,
    "kshell": 544,
    "ldap": 389,
    "login": 513,
    "lpd": 515,
    "mobile-ip": 434,
    "msrpc": 135,
    "nameserver": 42,
    "netbios-dgm": 138,
    "netbios-ns": 137,
    "netbios-ss": 139,
    "nntp": 119,
    "non500-isakmp": 4500,
    "ntp": 123,
    "pim-auto-rp": 496,
    "pop2": 109,
    "pop3": 110,
    "rip": 520,
    "smtp": 25,
    "snmp": 161,
    "snmptrap": 162,
    "ssh": 22,
    "sunrpc": 111,
    "syslog": 514,
    "tacacs": 49,
    "talk": 517,
    "telnet": 23,
    "tftp": 69,
    "time": 37,
    "uucp": 540,
    "who": 513,
    "whois": 43,
    "www": 80,
    "xdmcp": 177,
}
_PORT_OPERATORS = ("eq", "neq", "lt", "gt", "range")
_PROTOCOL_ALIASES = {"ahp": "ah", "ipinip": "ipip"}
# Tokens after an access list entry that only log or count.
_LOGGING = ("log", "log-input")
_ROUTE_KEYWORDS = ("name", "tag", "permanent", "track", "global", "multicast", "dhcp", "vrf")
# Standard access lists by number: 1-99 and 1300-1999.
_STANDARD_NUMBERS = ((1, 99), (1300, 1999))


@dataclass
class VirtualAddress:
    """An HSRP, VRRP or GLBP address an interface answers on."""

    protocol: str  # "HSRP", "VRRP" or "GLBP"
    group: str
    address: str


@dataclass
class ConfigInterface:
    name: str
    description: str = ""
    # (address, network) pairs, the primary first.
    addresses: list[tuple[str, str]] = field(default_factory=list)
    vrf: str = ""
    shutdown: bool = False
    # "in" / "out" -> access list name.
    access_groups: dict[str, str] = field(default_factory=dict)
    virtual: list[VirtualAddress] = field(default_factory=list)


@dataclass
class AclEntry:
    """One access list entry, in forwarding rule terms."""

    sequence: int | None
    action: str  # "allow" or "deny"
    protocol: str = ANY
    src: list[str] = field(default_factory=lambda: [ANY])
    src_ports: str = ANY
    dst: list[str] = field(default_factory=lambda: [ANY])
    dst_ports: str = ANY
    established: bool = False
    comment: str = ""
    unresolved: list[str] = field(default_factory=list)


@dataclass
class StaticRoute:
    prefix: str
    next_hop: str = ""
    interface: str = ""
    vrf: str = ""
    distance: int | None = None
    name: str = ""


@dataclass
class RunningConfig:
    interfaces: list[ConfigInterface] = field(default_factory=list)
    access_lists: dict[str, list[AclEntry]] = field(default_factory=dict)
    static_routes: list[StaticRoute] = field(default_factory=list)
    # The routing protocols configured (``router ospf 1``...), by display name.
    routing: list[str] = field(default_factory=list)
    # What the configuration uses that is not read, for not_collected.
    notes: list[str] = field(default_factory=list)


@dataclass
class _Block:
    header: str
    children: list[tuple[int, str]]


def supported(device_type: str) -> bool:
    """Whether ``parse_config`` reads the configuration of this device type:
    Cisco IOS, IOS-XE and NX-OS (an empty type is taken as IOS, as the
    monitoring poll does)."""
    flavour = str(device_type or "").strip().lower()
    if not flavour:
        return True
    if any(word in flavour for word in ("asa", "ftd", "xr")):
        return False
    return any(word in flavour for word in ("cisco_ios", "cisco_xe", "nxos", "ios"))


def _blocks(text: str) -> list[_Block]:
    """The top-level lines of a configuration with the indented lines under each."""
    blocks: list[_Block] = []
    for raw in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("!") or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            blocks.append(_Block(stripped, []))
        elif blocks:
            blocks[-1].children.append((indent, stripped))
    return blocks


def mask_length(mask: str) -> int | None:
    """The prefix length of an IPv4 subnet mask (``255.255.255.0`` is 24), or ``None``."""
    try:
        return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _network(address: str, mask: str) -> str:
    """``address`` with a subnet mask as a canonical network, or ``""``."""
    length = mask_length(mask)
    return canonical(f"{address}/{length}") if length is not None and is_address(address) else ""


def _wildcard(address: str, wildcard: str) -> str:
    """``address`` with a wildcard mask as a network, or ``""`` when the
    wildcard is not an inverted contiguous mask."""
    try:
        bits = int(ipaddress.IPv4Address(wildcard))
        ipaddress.IPv4Address(address)
    except ValueError:
        return ""
    if bits & (bits + 1):
        return ""
    return canonical(f"{address}/{32 - bits.bit_length()}")


def _port(token: str) -> int | None:
    if token.isdigit():
        value = int(token)
        return value if value <= 65535 else None
    return PORT_NAMES.get(token.lower())


def _is_port_value(token: str) -> bool:
    return token.isdigit() or token.lower() in PORT_NAMES


def _complement(excluded: list[int]) -> str:
    """Every port but ``excluded``, as a port expression."""
    parts: list[str] = []
    low = 0
    for value in sorted(set(excluded)):
        if value > low:
            parts.append(str(low) if value - 1 == low else f"{low}-{value - 1}")
        low = value + 1
    if low <= 65535:
        parts.append(str(low) if low == 65535 else f"{low}-65535")
    return ",".join(parts)


def _port_expression(operator: str, values: list[str]) -> tuple[str, list[str]]:
    """``(expression, unresolved)`` of ``eq 80 443``, ``range 1000 2000``..."""
    numbers = [_port(v) for v in values]
    unknown = [f"port {v}" for v, n in zip(values, numbers, strict=True) if n is None]
    if unknown or not numbers:
        return ANY, unknown or [f"ports {operator}"]
    found = [n for n in numbers if n is not None]
    if operator == "eq":
        return ",".join(str(n) for n in found), []
    if operator == "neq":
        return _complement(found), []
    if operator == "lt":
        return ("0" if found[0] <= 1 else f"0-{found[0] - 1}"), []
    if operator == "gt":
        return ("65535" if found[0] >= 65534 else f"{found[0] + 1}-65535"), []
    if len(found) == 2:
        low, high = sorted(found)
        return f"{low}-{high}", []
    return ANY, [f"ports {operator} {' '.join(values)}"]


class _Groups:
    """The object groups of a configuration, resolved on demand."""

    def __init__(self) -> None:
        self.networks: dict[str, list[list[str]]] = {}
        self.services: dict[str, list[list[str]]] = {}
        self.ports: dict[str, list[list[str]]] = {}

    def network(self, name: str, seen: frozenset[str] = frozenset()) -> tuple[list[str], list[str]]:
        """``(cidrs, unresolved)`` of a network object group."""
        if name not in self.networks or name in seen:
            return [ANY], [f"object-group {name}"]
        cidrs: list[str] = []
        unresolved: list[str] = []
        for tokens in self.networks[name]:
            head = tokens[0].lower()
            if head == "description":
                continue
            if head == "group-object" and len(tokens) > 1:
                found, missing = self.network(tokens[1], seen | {name})
                cidrs.extend(found)
                unresolved.extend(missing)
            elif head == "host" and len(tokens) > 1 and canonical(tokens[1]):
                cidrs.append(canonical(tokens[1]))
            elif head == "any":
                cidrs.append(ANY)
            elif head == "range" and len(tokens) > 2 and is_address(tokens[1]) and is_address(tokens[2]):
                try:
                    first, last = ipaddress.IPv4Address(tokens[1]), ipaddress.IPv4Address(tokens[2])
                    cidrs.extend(str(n) for n in ipaddress.summarize_address_range(first, last))
                except (TypeError, ValueError):
                    unresolved.append(f"range {tokens[1]} {tokens[2]}")
            elif "/" in head and canonical(head):
                cidrs.append(canonical(head))
            elif is_address(head) and len(tokens) > 1 and is_address(tokens[1]):
                # IOS network groups take a subnet mask, NX-OS ones a wildcard.
                found_cidr = _network(tokens[0], tokens[1]) or _wildcard(tokens[0], tokens[1])
                if found_cidr:
                    cidrs.append(found_cidr)
                else:
                    unresolved.append(f"{tokens[0]} {tokens[1]}")
            elif is_address(head):
                cidrs.append(canonical(head))
            else:
                unresolved.append(" ".join(tokens))
        if unresolved and not cidrs:
            cidrs = [ANY]
        return list(dict.fromkeys(cidrs)), unresolved

    def port_group(self, name: str) -> tuple[str, list[str]]:
        """``(expression, unresolved)`` of an NX-OS port object group."""
        if name not in self.ports:
            return ANY, [f"portgroup {name}"]
        parts: list[str] = []
        unresolved: list[str] = []
        for tokens in self.ports[name]:
            if tokens[0].lower() in _PORT_OPERATORS:
                expression, missing = _port_expression(tokens[0].lower(), tokens[1:])
                unresolved.extend(missing)
                if not missing:
                    parts.append(expression)
        if unresolved or not parts:
            return ANY, unresolved or [f"portgroup {name}"]
        return ",".join(parts), []

    def service(self, name: str, seen: frozenset[str] = frozenset()) -> list[tuple[str, str, list[str]]]:
        """``(protocol, destination ports, unresolved)`` of each item of an
        IOS service object group."""
        if name not in self.services or name in seen:
            return [(ANY, ANY, [f"object-group {name}"])]
        items: list[tuple[str, str, list[str]]] = []
        for tokens in self.services[name]:
            head = tokens[0].lower()
            if head == "description":
                continue
            if head == "group-object" and len(tokens) > 1:
                items.extend(self.service(tokens[1], seen | {name}))
                continue
            protocols = ["tcp", "udp"] if head == "tcp-udp" else [_PROTOCOL_ALIASES.get(head, head)]
            rest = [t.lower() for t in tokens[1:]]
            ports, unresolved = ANY, []
            if rest and rest[0] == "source":
                unresolved = [f"source ports {' '.join(rest[1:])}"]
            elif rest and rest[0] in _PORT_OPERATORS and head in ("tcp", "udp", "tcp-udp"):
                ports, unresolved = _port_expression(rest[0], rest[1:])
            elif rest and head not in ("icmp",):
                unresolved = [" ".join(tokens)]
            items.extend((protocol, ports, list(unresolved)) for protocol in protocols)
        return items or [(ANY, ANY, [f"object-group {name}"])]


def _address(tokens: list[str], i: int, groups: _Groups) -> tuple[list[str], list[str], int]:
    """The address at ``tokens[i]``: ``(cidrs, unresolved, next index)``."""
    if i >= len(tokens):
        return [ANY], ["missing address"], i
    token = tokens[i].lower()
    if token in ("any", "any4"):
        return [ANY], [], i + 1
    if token == "host" and i + 1 < len(tokens):
        found = canonical(tokens[i + 1])
        return ([found], [], i + 2) if found else ([ANY], [f"host {tokens[i + 1]}"], i + 2)
    if token in ("object-group", "addrgroup") and i + 1 < len(tokens):
        cidrs, unresolved = groups.network(tokens[i + 1])
        return cidrs, unresolved, i + 2
    if "/" in token and canonical(token):
        return [canonical(token)], [], i + 1
    if is_address(token):
        if i + 1 < len(tokens) and is_address(tokens[i + 1]):
            found = _wildcard(tokens[i], tokens[i + 1])
            if found:
                return [found], [], i + 2
            return [ANY], [f"wildcard mask {tokens[i]} {tokens[i + 1]}"], i + 2
        return [canonical(token)], [], i + 1
    return [ANY], [f"address {tokens[i]}"], i + 1


def _ports(tokens: list[str], i: int, groups: _Groups) -> tuple[str, list[str], int]:
    """The port match at ``tokens[i]``, if any: ``(expression, unresolved, next index)``."""
    if i >= len(tokens):
        return ANY, [], i
    token = tokens[i].lower()
    if token == "portgroup" and i + 1 < len(tokens):
        expression, unresolved = groups.port_group(tokens[i + 1])
        return expression, unresolved, i + 2
    if token not in _PORT_OPERATORS or i + 1 >= len(tokens):
        return ANY, [], i
    if token == "range":
        values = tokens[i + 1 : i + 3]
        end = i + 3
    elif token in ("lt", "gt"):
        values = tokens[i + 1 : i + 2]
        end = i + 2
    else:
        # ``eq www 443``: the first value always, then every value that reads as a port.
        end = i + 2
        while end < len(tokens) and _is_port_value(tokens[end]):
            end += 1
        values = tokens[i + 1 : end]
    expression, unresolved = _port_expression(token, values)
    return expression, unresolved, end


def _protocol(token: str) -> str:
    name = token.lower()
    return _PROTOCOL_ALIASES.get(name, name)


def _entry(tokens: list[str], standard: bool, groups: _Groups, comment: str) -> list[AclEntry]:
    """The entries of one access list line (``[10] permit tcp any host
    10.1.1.1 eq 443``); a service object group gives one per service. A
    reflexive ``evaluate`` entry may let anything in, so it is unresolved;
    a line that is no permit or deny gives none."""
    sequence: int | None = None
    if tokens and tokens[0].isdigit():
        sequence = int(tokens[0])
        tokens = tokens[1:]
    if len(tokens) > 1 and tokens[0].lower() == "evaluate":
        return [AclEntry(sequence, "allow", comment=comment, unresolved=[f"reflexive access list {tokens[1]}"])]
    if not tokens or tokens[0].lower() not in ("permit", "deny"):
        return []
    action = "allow" if tokens[0].lower() == "permit" else "deny"
    if standard:
        src, unresolved, i = _address(tokens, 1, groups)
        extra = [t for t in tokens[i:] if t.lower() not in _LOGGING]
        if extra:
            unresolved.append(" ".join(extra))
        return [AclEntry(sequence, action, src=src, comment=comment, unresolved=unresolved)]
    if len(tokens) < 2:
        return []
    services: list[tuple[str, str, list[str]]]
    i = 1
    if tokens[1].lower() == "object-group" and len(tokens) > 2:
        services = groups.service(tokens[2])
        protocol_token = ""
        i = 3
    else:
        protocol_token = _protocol(tokens[1])
        services = [(protocol_token, ANY, [])]
        i = 2
    ported = protocol_token in ("tcp", "udp", "sctp")
    src, unresolved, i = _address(tokens, i, groups)
    src_ports = ANY
    if ported:
        src_ports, missing, i = _ports(tokens, i, groups)
        unresolved += missing
    dst, missing, i = _address(tokens, i, groups)
    unresolved += missing
    dst_ports = ANY
    if ported:
        dst_ports, missing, i = _ports(tokens, i, groups)
        unresolved += missing
    established = False
    rest: list[str] = []
    for token in tokens[i:]:
        word = token.lower()
        if word in _LOGGING:
            continue
        if word == "established" and protocol_token == "tcp":
            established = True
        elif protocol_token not in ("icmp",):
            rest.append(token)
    if rest:
        unresolved.append(" ".join(rest))
    entries: list[AclEntry] = []
    for protocol, ports, missing in services:
        entries.append(
            AclEntry(
                sequence,
                action,
                protocol=protocol or ANY,
                src=src,
                src_ports=src_ports,
                dst=dst,
                dst_ports=dst_ports if ported else ports,
                established=established,
                comment=comment,
                unresolved=list(dict.fromkeys(unresolved + missing)),
            )
        )
    return entries


def _standard_number(name: str) -> bool:
    return name.isdigit() and any(low <= int(name) <= high for low, high in _STANDARD_NUMBERS)


def _acl_lines(acl: list[AclEntry], lines: list[list[str]], standard: bool, groups: _Groups) -> None:
    comment = ""
    for tokens in lines:
        words = tokens[1:] if tokens and tokens[0].isdigit() else tokens
        if not words:
            continue
        if words[0].lower() == "remark":
            comment = " ".join(words[1:])
            continue
        entries = _entry(tokens, standard, groups, comment)
        if entries:
            acl.extend(entries)
            comment = ""


def _virtual(interface: ConfigInterface, protocol: str, group: str, address: str) -> None:
    if is_address(address) and all(v.address != address for v in interface.virtual):
        interface.virtual.append(VirtualAddress(protocol, group, address))


def _interface(name: str, children: list[tuple[int, str]], config: RunningConfig) -> ConfigInterface:
    found = ConfigInterface(name)
    # An NX-OS ``hsrp 10`` / ``vrrp 10`` or IOS-XE ``vrrp 10 address-family
    # ipv4`` sub-block: (protocol, group, its indentation).
    sub: tuple[str, str, int] | None = None
    primary = False
    for indent, line in children:
        tokens = line.split()
        words = [t.lower() for t in tokens]
        if sub is not None and indent > sub[2]:
            if words[0] in ("ip", "address") and len(tokens) > 1 and is_address(tokens[1]):
                _virtual(found, sub[0], sub[1], tokens[1])
            continue
        sub = None
        if words[0] in ("hsrp", "vrrp") and len(words) > 1 and words[1].isdigit():
            if len(words) == 2 or words[2:4] == ["address-family", "ipv4"] or words[2] == "ipv4":
                sub = (words[0].upper(), words[1], indent)
            elif words[2] in ("ip", "address") and len(tokens) > 3:
                _virtual(found, words[0].upper(), words[1], tokens[3])
            continue
        if words[0] in ("standby", "glbp"):
            # ``standby [group] ip ADDRESS [secondary]``
            group = words[1] if len(words) > 1 and words[1].isdigit() else "0"
            rest = tokens[2:] if group != "0" or (len(words) > 1 and words[1] == "0") else tokens[1:]
            if rest and rest[0].lower() == "ip" and len(rest) > 1:
                _virtual(found, "HSRP" if words[0] == "standby" else "GLBP", group, rest[1])
            continue
        if words[0] == "description":
            found.description = line.split(None, 1)[1] if len(tokens) > 1 else ""
        elif words[0] == "shutdown":
            found.shutdown = True
        elif words[:2] == ["no", "shutdown"]:
            found.shutdown = False
        elif words[:3] == ["ip", "vrf", "forwarding"] and len(tokens) > 3:
            found.vrf = tokens[3]
        elif words[:2] in (["vrf", "forwarding"], ["vrf", "member"]) and len(tokens) > 2:
            found.vrf = tokens[2]
        elif words[:2] == ["ip", "address"] and len(tokens) > 2:
            secondary = "secondary" in words[3:]
            if "/" in tokens[2]:
                address, network = tokens[2].split("/", 1)[0], canonical(tokens[2])
            elif len(tokens) > 3:
                address, network = tokens[2], _network(tokens[2], tokens[3])
            else:
                continue
            if not is_address(address) or not network:
                continue
            if secondary:
                found.addresses.append((address, network))
            elif primary:
                found.addresses[0] = (address, network)
            else:
                found.addresses.insert(0, (address, network))
                primary = True
        elif words[:2] == ["ip", "access-group"] and len(tokens) > 3 and words[3] in ("in", "out"):
            found.access_groups[words[3]] = tokens[2]
        elif words[:2] in (["ipv6", "traffic-filter"], ["ipv6", "access-group"]):
            _note(config, IPV6_ACCESS_LISTS)
        elif words[:3] == ["ip", "port", "access-group"]:
            _note(config, PORT_ACCESS_LISTS)
        elif words[:3] == ["ip", "policy", "route-map"]:
            _note(config, POLICY_BASED_ROUTES)
        elif words[:2] == ["zone-member", "security"]:
            _note(config, ZONE_FIREWALL)
    return found


def _note(config: RunningConfig, name: str) -> None:
    if name not in config.notes:
        config.notes.append(name)


def _static_route(tokens: list[str], vrf: str) -> StaticRoute | None:
    """``ip route [vrf V] PREFIX MASK|/LEN (NEXT_HOP | IFACE [NEXT_HOP]) [AD] [name X] ...``
    (the tokens after ``ip route``)."""
    words = [t.lower() for t in tokens]
    if words[:1] == ["vrf"] and len(tokens) > 1:
        vrf, tokens, words = tokens[1], tokens[2:], words[2:]
    if not tokens or "dhcp" in words:
        return None
    if "/" in tokens[0]:
        prefix, i = canonical(tokens[0]), 1
    elif len(tokens) > 1:
        prefix, i = _network(tokens[0], tokens[1]), 2
    else:
        return None
    if not prefix:
        return None
    found = StaticRoute(prefix, vrf=vrf)
    while i < len(tokens):
        token, word = tokens[i], words[i]
        if word in ("name", "tag", "track", "vrf") and i + 1 < len(tokens):
            if word == "name":
                found.name = tokens[i + 1]
            i += 2
            continue
        if is_address(token) and not found.next_hop:
            found.next_hop = token
        elif word.isdigit() and found.distance is None and (found.next_hop or found.interface):
            found.distance = int(word)
        elif re.match(r"^[a-z]", word) and word not in _ROUTE_KEYWORDS and not found.interface and not found.next_hop:
            found.interface = token
        i += 1
    if not found.next_hop and not found.interface:
        return None
    return found


def parse_config(text: str) -> RunningConfig:
    """What a Cisco IOS / IOS-XE or NX-OS running configuration says about
    forwarding: interfaces, access lists, static routes, routing protocols."""
    config = RunningConfig()
    blocks = _blocks(text)
    groups = _Groups()
    acl_blocks: list[tuple[str, bool, list[list[str]]]] = []
    numbered: dict[str, list[list[str]]] = {}
    for block in blocks:
        tokens = block.header.split()
        words = [t.lower() for t in tokens]
        children = [line.split() for _indent, line in block.children]
        if words[:2] == ["object-group", "network"] and len(tokens) > 2:
            groups.networks[tokens[2]] = children
        elif words[:3] == ["object-group", "ip", "address"] and len(tokens) > 3:
            groups.networks[tokens[3]] = [c[1:] if c and c[0].isdigit() else c for c in children]
        elif words[:2] == ["object-group", "service"] and len(tokens) > 2:
            groups.services[tokens[2]] = children
        elif words[:3] == ["object-group", "ip", "port"] and len(tokens) > 3:
            groups.ports[tokens[3]] = [c[1:] if c and c[0].isdigit() else c for c in children]
        elif words[:2] == ["ip", "access-list"] and len(tokens) > 2:
            if words[2] in ("standard", "extended") and len(tokens) > 3:
                acl_blocks.append((tokens[3], words[2] == "standard", children))
            elif words[2] not in ("logging", "log-update", "resequence", "role-based", "match-local-traffic"):
                # NX-OS: ``ip access-list NAME``, extended syntax.
                acl_blocks.append((tokens[2], False, children))
        elif words[0] == "access-list" and len(tokens) > 2:
            numbered.setdefault(tokens[1], []).append(tokens[2:])
        elif words[0] == "interface" and len(tokens) > 1:
            config.interfaces.append(_interface("".join(tokens[1:]), block.children, config))
        elif words[:2] == ["ip", "route"]:
            route = _static_route(tokens[2:], "")
            if route is not None:
                config.static_routes.append(route)
        elif words[:2] == ["vrf", "context"] and len(tokens) > 2:
            for child in children:
                if [w.lower() for w in child[:2]] == ["ip", "route"]:
                    route = _static_route(child[2:], tokens[2])
                    if route is not None:
                        config.static_routes.append(route)
        elif words[0] == "router" and len(words) > 1 and words[1] in ROUTING_PROTOCOLS:
            name = ROUTING_PROTOCOLS[words[1]]
            if name not in config.routing:
                config.routing.append(name)
        elif words[:2] in (["vlan", "access-map"], ["vlan", "filter"]):
            _note(config, VLAN_ACCESS_MAPS)
    for name, standard, lines in acl_blocks:
        _acl_lines(config.access_lists.setdefault(name, []), lines, standard, groups)
    for name, lines in numbered.items():
        _acl_lines(config.access_lists.setdefault(name, []), lines, _standard_number(name), groups)
    return config
