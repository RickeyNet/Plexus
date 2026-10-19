"""The running configuration of a Cisco IOS / IOS-XE, NX-OS, IOS-XR or
Arista EOS device, read for path tracing.

The config backup feature stores each host's running configuration
(``config_backups.config_text``). ``parse_config`` reads from it what the
forwarding block of an inventory host needs and the route table capture
does not give: the interfaces with their addresses, VRF, state, access
groups and HSRP / VRRP / GLBP / VARP virtual addresses; the access lists,
with the object groups they name resolved; the static routes, including
those of VRFs; and which routing protocols run.

Access list entries come out in the forwarding rule terms
(``netcontrol.integrations.meraki.forwarding.rule``): ``allow`` or ``deny``,
CIDRs or ``any``, port expressions such as ``80,443`` or ``1024-65535``.
What cannot be turned into those (an object group or port name the
configuration does not define, a wildcard mask that is not a prefix, a
time range, DSCP or TCP flag match, an IOS-XR next hop that redirects the
flow) is kept in the entry's ``unresolved`` list, so a flow it matches is
unknown rather than decided.

The four dialects are read in one pass: they share the shape of an
interface block, and the differences do not collide. NX-OS writes ``ip
address A/len``, ``vrf member``, ``ip access-list NAME`` with no type,
``addrgroup`` / ``portgroup``, ``vrf context`` static routes and ``hsrp`` /
``vrrp`` sub-blocks. EOS writes ``vrf NAME`` under an interface, ``ip
virtual-router address`` (VARP), ``vrrp N ipv4 A`` and ``ip access-list
NAME`` like NX-OS. IOS-XR writes ``ipv4`` for ``ip`` (``ipv4 address``,
``ipv4 access-group NAME ingress``, ``ipv4 access-list``), names its
object groups with ``net-group`` / ``port-group``, keeps its static routes
under ``router static`` and its HSRP / VRRP groups under ``router hsrp`` /
``router vrrp``. IPv6 access lists are not read.

The building blocks (``blocks``, ``Groups``, ``read_object_group``,
``address``, ``ports``, ``acl_lines``, ``read_interface``,
``static_route``) are shared with the Aruba reader (``aruba_config``).

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from netcontrol.integrations.meraki.forwarding import ANY, canonical, is_address
from netcontrol.integrations.pathtrace.device_config import (
    AclEntry,
    ConfigInterface,
    RunningConfig,
    StaticRoute,
    VirtualAddress,
)

# Not-collected names a configuration gives when it uses what is not read.
IPV6_ACCESS_LISTS = "IPv6 access lists"
PORT_ACCESS_LISTS = "Port access lists"
MAC_ACCESS_LISTS = "MAC access lists"
VLAN_ACCESS_MAPS = "VLAN access maps"
POLICY_BASED_ROUTES = "Policy-based routes (route maps on interfaces)"
ZONE_FIREWALL = "Zone-based firewall policies"
TRAFFIC_POLICIES = "Traffic policies"
CLASSIFIER_POLICIES = "Classifier policies"

ROUTING_PROTOCOLS = {
    "ospf": "OSPF",
    "ospfv3": "OSPFv3",
    "eigrp": "EIGRP",
    "bgp": "BGP",
    "rip": "RIP",
    "isis": "IS-IS",
    "odr": "ODR",
}

# The port names IOS, NX-OS, IOS-XR and EOS print in access lists, TCP and
# UDP together.
PORT_NAMES = {
    "bfd": 3784,
    "bfd-echo": 3785,
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
    "ldp": 646,
    "login": 513,
    "lpd": 515,
    "mlag": 4432,
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
    "radius": 1812,
    "radius-acct": 1813,
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
_PROTOCOL_ALIASES = {"ahp": "ah", "ipinip": "ipip", "ipv4": "ip", "1": "icmp", "6": "tcp", "17": "udp"}
# Tokens after an access list entry that only log or count (``count``: AOS-CX).
_LOGGING = ("log", "log-input", "count")
# IOS-XR: ``counter NAME`` counts the matches.
_COUNTERS = ("counter",)
_ROUTE_KEYWORDS = ("name", "tag", "permanent", "track", "global", "multicast", "dhcp", "vrf", "description")
# Standard access lists by number: 1-99 and 1300-1999.
_STANDARD_NUMBERS = ((1, 99), (1300, 1999))
# ``ip access-group NAME DIRECTION``: IOS-XR says ingress / egress, AOS-CX
# routed-in / routed-out on a VLAN interface.
_DIRECTIONS = {
    "in": "in",
    "out": "out",
    "ingress": "in",
    "egress": "out",
    "routed-in": "in",
    "routed-out": "out",
}


@dataclass
class Block:
    header: str
    children: list[tuple[int, str]]


def blocks(text: str) -> list[Block]:
    """The top-level lines of a configuration with the indented lines under each."""
    found: list[Block] = []
    for raw in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("!") or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            found.append(Block(stripped, []))
        elif found:
            found[-1].children.append((indent, stripped))
    return found


def mask_length(mask: str) -> int | None:
    """The prefix length of an IPv4 subnet mask (``255.255.255.0`` is 24), or ``None``."""
    try:
        return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def network(address: str, mask: str) -> str:
    """``address`` with a subnet mask as a canonical network, or ``""``."""
    length = mask_length(mask)
    return canonical(f"{address}/{length}") if length is not None and is_address(address) else ""


def wildcard(address: str, mask: str) -> str:
    """``address`` with a wildcard mask as a network, or ``""`` when the
    wildcard is not an inverted contiguous mask."""
    try:
        bits = int(ipaddress.IPv4Address(mask))
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


class Groups:
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
            if head in ("group-object", "object-group") and len(tokens) > 1:
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
                except TypeError, ValueError:
                    unresolved.append(f"range {tokens[1]} {tokens[2]}")
            elif "/" in head and canonical(head):
                cidrs.append(canonical(head))
            elif is_address(head) and len(tokens) > 1 and is_address(tokens[1]):
                # IOS network groups take a subnet mask, NX-OS ones a wildcard.
                found_cidr = network(tokens[0], tokens[1]) or wildcard(tokens[0], tokens[1])
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
        """``(expression, unresolved)`` of a port object group (NX-OS, IOS-XR, AOS-CX)."""
        if name not in self.ports:
            return ANY, [f"port group {name}"]
        parts: list[str] = []
        unresolved: list[str] = []
        for tokens in self.ports[name]:
            if tokens[0].lower() in _PORT_OPERATORS:
                expression, missing = _port_expression(tokens[0].lower(), tokens[1:])
                unresolved.extend(missing)
                if not missing:
                    parts.append(expression)
        if unresolved or not parts:
            return ANY, unresolved or [f"port group {name}"]
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


def _unnumbered(children: list[list[str]]) -> list[list[str]]:
    return [c[1:] if c and c[0].isdigit() else c for c in children if c]


def read_object_group(tokens: list[str], children: list[list[str]], groups: Groups) -> bool:
    """Keep the object group a top-level line defines in ``groups``: IOS
    ``object-group network|service``, NX-OS and AOS-CX ``object-group ip
    address|port``, IOS-XR ``object-group network ipv4`` and ``object-group
    port``. ``False``: the line defines none."""
    words = [t.lower() for t in tokens]
    if words[:3] == ["object-group", "network", "ipv4"] and len(tokens) > 3:
        groups.networks[tokens[3]] = _unnumbered(children)
    elif words[:3] == ["object-group", "network", "ipv6"]:
        return True
    elif words[:2] == ["object-group", "network"] and len(tokens) > 2:
        groups.networks[tokens[2]] = [c for c in children if c]
    elif words[:3] == ["object-group", "ip", "address"] and len(tokens) > 3:
        groups.networks[tokens[3]] = _unnumbered(children)
    elif words[:2] == ["object-group", "service"] and len(tokens) > 2:
        groups.services[tokens[2]] = [c for c in children if c]
    elif words[:3] == ["object-group", "ip", "port"] and len(tokens) > 3:
        groups.ports[tokens[3]] = _unnumbered(children)
    elif words[:2] == ["object-group", "port"] and len(tokens) > 2:
        groups.ports[tokens[2]] = _unnumbered(children)
    else:
        return False
    return True


def address(tokens: list[str], i: int, groups: Groups) -> tuple[list[str], list[str], int]:
    """The address at ``tokens[i]``: ``(cidrs, unresolved, next index)``.
    ``any``, ``host A``, ``A/len`` (or ``A/mask``), ``A WILDCARD``, an
    object group (``object-group`` / ``addrgroup`` / ``net-group NAME``, or
    the bare name of a group the configuration defines)."""
    if i >= len(tokens):
        return [ANY], ["missing address"], i
    token = tokens[i].lower()
    if token in ("any", "any4"):
        return [ANY], [], i + 1
    if token == "host" and i + 1 < len(tokens):
        found = canonical(tokens[i + 1])
        return ([found], [], i + 2) if found else ([ANY], [f"host {tokens[i + 1]}"], i + 2)
    if token in ("object-group", "addrgroup", "net-group") and i + 1 < len(tokens):
        cidrs, unresolved = groups.network(tokens[i + 1])
        return cidrs, unresolved, i + 2
    if "/" in token and canonical(token):
        return [canonical(token)], [], i + 1
    if is_address(token):
        if i + 1 < len(tokens) and is_address(tokens[i + 1]):
            found = wildcard(tokens[i], tokens[i + 1])
            if found:
                return [found], [], i + 2
            return [ANY], [f"wildcard mask {tokens[i]} {tokens[i + 1]}"], i + 2
        return [canonical(token)], [], i + 1
    if tokens[i] in groups.networks:
        cidrs, unresolved = groups.network(tokens[i])
        return cidrs, unresolved, i + 1
    return [ANY], [f"address {tokens[i]}"], i + 1


def ports(tokens: list[str], i: int, groups: Groups) -> tuple[str, list[str], int]:
    """The port match at ``tokens[i]``, if any: ``(expression, unresolved,
    next index)``. ``eq|neq|lt|gt|range``, or a port object group
    (``portgroup`` / ``port-group`` / ``group NAME``)."""
    if i >= len(tokens):
        return ANY, [], i
    token = tokens[i].lower()
    if token in ("portgroup", "port-group", "group") and i + 1 < len(tokens):
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


def acl_entry(tokens: list[str], standard: bool, groups: Groups, comment: str) -> list[AclEntry]:
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
        src, unresolved, i = address(tokens, 1, groups)
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
    src, unresolved, i = address(tokens, i, groups)
    src_ports = ANY
    if ported:
        src_ports, missing, i = ports(tokens, i, groups)
        unresolved += missing
    dst, missing, i = address(tokens, i, groups)
    unresolved += missing
    dst_ports = ANY
    if ported:
        dst_ports, missing, i = ports(tokens, i, groups)
        unresolved += missing
    established = False
    rest: list[str] = []
    while i < len(tokens):
        token = tokens[i]
        word = token.lower()
        i += 1
        if word in _LOGGING:
            continue
        if word in _COUNTERS:
            i += 1
        elif word == "established" and protocol_token == "tcp":
            established = True
        elif protocol_token not in ("icmp",):
            rest.append(token)
    if rest:
        unresolved.append(" ".join(rest))
    entries: list[AclEntry] = []
    for protocol, service_ports, missing in services:
        entries.append(
            AclEntry(
                sequence,
                action,
                protocol=protocol or ANY,
                src=src,
                src_ports=src_ports,
                dst=dst,
                dst_ports=dst_ports if ported else service_ports,
                established=established,
                comment=comment,
                unresolved=list(dict.fromkeys(unresolved + missing)),
            )
        )
    return entries


def _standard_number(name: str) -> bool:
    return name.isdigit() and any(low <= int(name) <= high for low, high in _STANDARD_NUMBERS)


def acl_lines(acl: list[AclEntry], lines: list[list[str]], standard: bool, groups: Groups) -> None:
    """Add the entries of an access list's lines to ``acl``. A ``remark``
    describes the entry after it; an AOS-CX ``10 comment TEXT`` describes
    the entry with its sequence number, printed before or after it."""
    comment = ""
    comments: dict[int, str] = {}
    first = len(acl)
    for tokens in lines:
        sequence = int(tokens[0]) if tokens and tokens[0].isdigit() else None
        words = tokens[1:] if sequence is not None else tokens
        if not words:
            continue
        if words[0].lower() == "comment" and sequence is not None:
            text = " ".join(words[1:])
            described = [e for e in acl[first:] if e.sequence == sequence]
            for entry in described:
                entry.comment = text
            if not described:
                comments[sequence] = text
            continue
        if words[0].lower() == "remark":
            comment = " ".join(words[1:])
            continue
        entries = acl_entry(tokens, standard, groups, comments.pop(sequence, "") if sequence in comments else comment)
        if entries:
            acl.extend(entries)
            comment = ""


def add_virtual(interface: ConfigInterface, protocol: str, group: str, value: str) -> None:
    """Add a virtual (HSRP, VRRP, VARP...) address to an interface once."""
    if is_address(value) and all(v.address != value for v in interface.virtual):
        interface.virtual.append(VirtualAddress(protocol, group, value))


def add_address(interface: ConfigInterface, value: str, cidr: str, *, secondary: bool, primary: bool) -> bool:
    """Add an address to an interface: a secondary one after the others,
    the primary first (``primary``: the interface has one already, which a
    second replaces). Whether the interface now has a primary address."""
    if not is_address(value) or not cidr:
        return primary
    if secondary:
        interface.addresses.append((value, cidr))
    elif primary:
        interface.addresses[0] = (value, cidr)
    else:
        interface.addresses.insert(0, (value, cidr))
    return primary or not secondary


def _address_and_network(tokens: list[str], i: int) -> tuple[str, str]:
    """``A/len`` (or ``A/mask``) or ``A MASK`` at ``tokens[i]``: the address
    and its network, or empty strings."""
    if i >= len(tokens):
        return "", ""
    if "/" in tokens[i]:
        return tokens[i].split("/", 1)[0], canonical(tokens[i])
    if i + 1 < len(tokens):
        return tokens[i], network(tokens[i], tokens[i + 1])
    return "", ""


def read_interface(name: str, children: list[tuple[int, str]], config: RunningConfig) -> ConfigInterface:
    """An interface block of any of the dialects (and of AOS-CX, whose
    ``vrf attach``, ``apply access-list ip`` and ``active-gateway ip`` lines
    do not collide with them). An interface is up unless it says
    ``shutdown``."""
    found = ConfigInterface(name)
    # An NX-OS ``hsrp 10`` / ``vrrp 10``, IOS-XE or AOS-CX ``vrrp 10
    # address-family ipv4`` sub-block: (protocol, group, its indentation).
    sub: tuple[str, str, int] | None = None
    primary = False
    for indent, line in children:
        tokens = line.split()
        words = [t.lower() for t in tokens]
        if sub is not None and indent > sub[2]:
            if words[0] in ("ip", "address") and len(tokens) > 1 and is_address(tokens[1]):
                add_virtual(found, sub[0], sub[1], tokens[1])
            continue
        sub = None
        if words[0] == "ipv4":
            # IOS-XR: ``ipv4 address``, ``ipv4 access-group``.
            words[0] = "ip"
        if words[0] in ("hsrp", "vrrp") and len(words) > 1 and words[1].isdigit():
            if len(words) == 2 or words[2:4] == ["address-family", "ipv4"] or words[2:] == ["ipv4"]:
                sub = (words[0].upper(), words[1], indent)
            elif words[2] in ("ip", "address", "ipv4") and len(tokens) > 3:
                # IOS ``vrrp 10 ip A``, EOS ``vrrp 10 ipv4 A``.
                add_virtual(found, words[0].upper(), words[1], tokens[3])
            continue
        if words[0] in ("standby", "glbp"):
            # ``standby [group] ip ADDRESS [secondary]``
            group = words[1] if len(words) > 1 and words[1].isdigit() else "0"
            rest = tokens[2:] if group != "0" or (len(words) > 1 and words[1] == "0") else tokens[1:]
            if rest and rest[0].lower() == "ip" and len(rest) > 1:
                add_virtual(found, "HSRP" if words[0] == "standby" else "GLBP", group, rest[1])
            continue
        if words[0] == "description":
            found.description = line.split(None, 1)[1] if len(tokens) > 1 else ""
        elif words[0] == "shutdown":
            found.shutdown = True
        elif words[:2] == ["no", "shutdown"]:
            found.shutdown = False
        elif words[:3] == ["ip", "vrf", "forwarding"] and len(tokens) > 3:
            found.vrf = tokens[3]
        elif words[:2] in (["vrf", "forwarding"], ["vrf", "member"], ["vrf", "attach"]) and len(tokens) > 2:
            found.vrf = tokens[2]
        elif words[0] == "vrf" and len(tokens) == 2:
            # EOS and IOS-XR: ``vrf NAME``.
            found.vrf = tokens[1]
        elif words[:3] == ["ip", "address", "virtual"]:
            # EOS: an anycast gateway address, the interface's own.
            value, cidr = _address_and_network(tokens, 3)
            primary = add_address(found, value, cidr, secondary=primary, primary=primary)
        elif words[:2] == ["ip", "address"] and len(tokens) > 2:
            value, cidr = _address_and_network(tokens, 2)
            primary = add_address(found, value, cidr, secondary="secondary" in words[3:], primary=primary)
        elif words[:2] == ["ip", "virtual-router"] and len(tokens) > 3 and words[2] == "address":
            # EOS VARP: the gateway address every MLAG peer answers on.
            add_virtual(found, "VARP", "", tokens[3].split("/", 1)[0])
        elif words[:2] == ["active-gateway", "ip"] and len(tokens) > 2:
            # AOS-CX: the gateway address both VSX peers answer on.
            add_virtual(found, "Active gateway", "", tokens[2])
        elif words[:2] == ["ip", "access-group"] and len(tokens) > 3 and words[3] in _DIRECTIONS:
            found.access_groups[_DIRECTIONS[words[3]]] = tokens[2]
        elif words[:3] == ["apply", "access-list", "ip"] and len(tokens) > 4 and words[4] in _DIRECTIONS:
            found.access_groups[_DIRECTIONS[words[4]]] = tokens[3]
        elif words[:2] in (["ipv6", "traffic-filter"], ["ipv6", "access-group"]) or words[:3] == [
            "apply",
            "access-list",
            "ipv6",
        ]:
            add_note(config, IPV6_ACCESS_LISTS)
        elif words[:2] == ["mac", "access-group"] or words[:3] == ["apply", "access-list", "mac"]:
            add_note(config, MAC_ACCESS_LISTS)
        elif words[:3] == ["ip", "port", "access-group"]:
            add_note(config, PORT_ACCESS_LISTS)
        elif words[:3] == ["ip", "policy", "route-map"] or words[:3] == ["service-policy", "type", "pbr"]:
            add_note(config, POLICY_BASED_ROUTES)
        elif words[:2] == ["apply", "pbr"]:
            add_note(config, POLICY_BASED_ROUTES)
        elif words[0] == "traffic-policy":
            add_note(config, TRAFFIC_POLICIES)
        elif words[:2] == ["apply", "policy"]:
            # AOS-CX classifier policies.
            add_note(config, CLASSIFIER_POLICIES)
        elif words[:2] == ["zone-member", "security"]:
            add_note(config, ZONE_FIREWALL)
    return found


def add_note(config: RunningConfig, name: str) -> None:
    """Note once that the configuration uses what is not read."""
    if name not in config.notes:
        config.notes.append(name)


def static_route(tokens: list[str], vrf: str) -> StaticRoute | None:
    """``[vrf V] PREFIX MASK|/LEN (NEXT_HOP | IFACE [NEXT_HOP]) [AD] [name X] ...``
    (the tokens after ``ip route``; IOS-XR: a ``router static`` line, with
    ``description X``)."""
    words = [t.lower() for t in tokens]
    if words[:1] == ["vrf"] and len(tokens) > 1:
        vrf, tokens, words = tokens[1], tokens[2:], words[2:]
    if not tokens or "dhcp" in words:
        return None
    if "/" in tokens[0]:
        prefix, i = canonical(tokens[0]), 1
    elif len(tokens) > 1:
        prefix, i = network(tokens[0], tokens[1]), 2
    else:
        return None
    if not prefix:
        return None
    found = StaticRoute(prefix, vrf=vrf)
    while i < len(tokens):
        token, word = tokens[i], words[i]
        if word in ("name", "description", "tag", "track", "vrf") and i + 1 < len(tokens):
            if word in ("name", "description"):
                found.name = tokens[i + 1]
            i += 2
            continue
        if is_address(token) and not found.next_hop:
            found.next_hop = token
        elif word.isdigit() and found.distance is None and (found.next_hop or found.interface):
            found.distance = int(word)
        elif (
            not found.interface
            and not found.next_hop
            and ((re.match(r"^[a-z]", word) and word not in _ROUTE_KEYWORDS) or re.match(r"^\d+(?:/\d+){2,}$", word))
        ):
            # A name (``Null0``, ``Vlan10``) or an AOS-CX port (``1/1/5``).
            found.interface = token
        i += 1
    if not found.next_hop and not found.interface:
        return None
    return found


def _ipv4(prefix: str) -> bool:
    return "." in prefix


def _router_static(children: list[tuple[int, str]], config: RunningConfig) -> None:
    """IOS-XR ``router static``: ``address-family ipv4 unicast`` lines, and
    the same under ``vrf NAME``."""
    vrf, vrf_indent = "", -1
    ipv4 = False
    for indent, line in children:
        tokens = line.split()
        words = [t.lower() for t in tokens]
        if vrf and indent <= vrf_indent:
            vrf, ipv4 = "", False
        if words[0] == "vrf" and len(tokens) > 1:
            vrf, vrf_indent, ipv4 = tokens[1], indent, False
        elif words[0] == "address-family":
            ipv4 = words[1:2] == ["ipv4"]
        elif ipv4 and "/" in tokens[0]:
            route = static_route(tokens, vrf)
            if route is not None and _ipv4(route.prefix):
                config.static_routes.append(route)


def _router_virtual(protocol: str, children: list[tuple[int, str]]) -> list[tuple[str, str, str]]:
    """IOS-XR ``router vrrp`` / ``router hsrp``: ``(interface, group,
    address)`` of each IPv4 group (``interface X`` / ``address-family ipv4``
    / ``vrrp N`` / ``address A``)."""
    found: list[tuple[str, str, str]] = []
    iface, group, ipv4 = "", "", True
    for _indent, line in children:
        tokens = line.split()
        words = [t.lower() for t in tokens]
        if words[0] == "interface" and len(tokens) > 1:
            iface, group, ipv4 = "".join(tokens[1:]), "", True
        elif words[0] == "address-family":
            ipv4, group = words[1:2] == ["ipv4"], ""
        elif words[0] == protocol and len(words) > 1 and words[1].isdigit():
            group = words[1]
            if len(tokens) > 3 and words[2] == "ipv4":
                # XR 4.x: ``vrrp 1 ipv4 A``.
                found.append((iface, group, tokens[3]))
        elif words[0] == "address" and len(tokens) > 1 and ipv4 and group and iface:
            found.append((iface, group, tokens[1]))
    return found


def parse_config(text: str) -> RunningConfig:
    """What a Cisco IOS / IOS-XE, NX-OS, IOS-XR or Arista EOS running
    configuration says about forwarding: interfaces, access lists, static
    routes, routing protocols."""
    config = RunningConfig()
    groups = Groups()
    acl_blocks: list[tuple[str, bool, list[list[str]]]] = []
    numbered: dict[str, list[list[str]]] = {}
    virtual: list[tuple[str, str, str, str]] = []
    for block in blocks(text):
        tokens = block.header.split()
        words = [t.lower() for t in tokens]
        children = [line.split() for _indent, line in block.children]
        if read_object_group(tokens, children, groups):
            continue
        if words[:2] in (["ip", "access-list"], ["ipv4", "access-list"]) and len(tokens) > 2:
            if words[2] in ("standard", "extended") and len(tokens) > 3:
                acl_blocks.append((tokens[3], words[2] == "standard", children))
            elif words[2] not in ("logging", "log-update", "resequence", "role-based", "match-local-traffic"):
                # NX-OS, EOS, IOS-XR: ``ip access-list NAME``, extended syntax.
                acl_blocks.append((tokens[2], False, children))
        elif words[0] == "access-list" and len(tokens) > 2:
            numbered.setdefault(tokens[1], []).append(tokens[2:])
        elif words[0] == "interface" and len(tokens) > 1:
            config.interfaces.append(read_interface("".join(tokens[1:]), block.children, config))
        elif words[:2] == ["ip", "route"]:
            route = static_route(tokens[2:], "")
            if route is not None:
                config.static_routes.append(route)
        elif words[:2] == ["vrf", "context"] and len(tokens) > 2:
            for child in children:
                if [w.lower() for w in child[:2]] == ["ip", "route"]:
                    route = static_route(child[2:], tokens[2])
                    if route is not None:
                        config.static_routes.append(route)
        elif words[:2] == ["router", "static"]:
            _router_static(block.children, config)
        elif words[:2] in (["router", "vrrp"], ["router", "hsrp"]):
            protocol = words[1]
            virtual.extend((iface, protocol.upper(), g, a) for iface, g, a in _router_virtual(protocol, block.children))
        elif words[0] == "router" and len(words) > 1 and words[1] in ROUTING_PROTOCOLS:
            name = ROUTING_PROTOCOLS[words[1]]
            if name not in config.routing:
                config.routing.append(name)
        elif words[:2] in (["vlan", "access-map"], ["vlan", "filter"]):
            add_note(config, VLAN_ACCESS_MAPS)
    for name, standard, lines in acl_blocks:
        acl_lines(config.access_lists.setdefault(name, []), lines, standard, groups)
    for name, lines in numbered.items():
        acl_lines(config.access_lists.setdefault(name, []), lines, _standard_number(name), groups)
    by_name = {i.name.lower(): i for i in config.interfaces}
    for iface, protocol, group, value in virtual:
        holder = by_name.get(iface.lower())
        if holder is not None:
            add_virtual(holder, protocol, group, value)
    return config
