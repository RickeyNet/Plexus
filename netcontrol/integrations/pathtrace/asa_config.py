"""The running configuration of a Cisco ASA / FTD, read for path tracing.

The config backup feature stores each host's running configuration
(``config_backups.config_text``). ``parse_config`` reads an ASA 9.x running
configuration, or the ``show running-config`` of an FTD's LINA engine, into
a ``RunningConfig`` (see ``device_config``): the interfaces with their
``nameif`` (the name the rules, the NAT rules and ``show route`` call them
by, kept as the interface's zone and alias), addresses and state; the
access lists, with the objects and object groups they name resolved; the
access groups that bind them to an interface in or out, or globally; the
implicit rules of the security levels; the NAT rules, object NAT and twice
NAT, in the order the ASA evaluates them; the static routes; and which
routing protocols run.

Access list entries come out in the forwarding rule terms
(``netcontrol.integrations.meraki.forwarding.rule``). What cannot be turned
into those (an object or object group the configuration does not define,
an FQDN object, a time range, an ICMP type, a user or security group, an
FTD rule whose application or URL conditions Snort decides) is kept in the
entry's ``unresolved`` list, so a flow it matches is unknown rather than
decided. An address object that is only partly resolved matches any
address, for the same reason.

The security model is a rule set of its own (``Security levels``): traffic
entering an interface with no inbound access list may leave by one of a
lower security level; between interfaces of the same level, and back out
of the interface it came in by, only with ``same-security-traffic``; an
interface with an inbound access list (or any interface, when a global one
is applied) is left to its access list. A global access list is consulted
after an interface's inbound one, so each inbound list is read with the
global entries after its own.

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from netcontrol.integrations.meraki.forwarding import ANY, INTERFACE, canonical, is_address, nat
from netcontrol.integrations.pathtrace.device_config import (
    AclEntry,
    ConfigInterface,
    ConfigPolicy,
    RunningConfig,
    StaticRoute,
)
from netcontrol.integrations.pathtrace.ios_config import (  # the IOS reader's building blocks
    _PORT_OPERATORS,
    IPV6_ACCESS_LISTS,
    POLICY_BASED_ROUTES,
    PORT_NAMES as IOS_PORT_NAMES,
    ROUTING_PROTOCOLS,
    _port_expression,
    add_note,
    blocks,
    network as subnet,
)

__all__ = ["PORT_NAMES", "SECURITY_LEVELS", "parse_config"]

# Not-collected names a configuration gives when it uses what is not read.
SITE_TO_SITE_VPN = "Site-to-site VPN (crypto maps)"
REMOTE_ACCESS_VPN = "Remote access VPN"
INSPECTION = "Inspection policies (policy-map / class-map)"
CONTEXTS = "Security contexts (multiple context mode)"
TRANSPARENT = "Transparent firewall mode (bridge groups)"
ETHERTYPE_ACCESS_LISTS = "EtherType access lists"
WEBTYPE_ACCESS_LISTS = "WebVPN access lists"
LEGACY_NAT = "NAT rules (pre-8.3 nat / global / static syntax)"

SECURITY_LEVELS = "Security levels"

# The port names an ASA prints, TCP and UDP together: the IOS ones, and
# those only an ASA knows or numbers differently (its kerberos is 750).
PORT_NAMES = {
    **IOS_PORT_NAMES,
    "aol": 5190,
    "cifs": 3020,
    "citrix-ica": 1494,
    "ctiqbe": 2748,
    "diameter": 3868,
    "h323": 1720,
    "imap4": 143,
    "kerberos": 750,
    "ldaps": 636,
    "lotusnotes": 1352,
    "netbios-ssn": 139,
    "nfs": 2049,
    "pcanywhere-data": 5631,
    "pcanywhere-status": 5632,
    "pptp": 1723,
    "radius": 1645,
    "radius-acct": 1646,
    "rsh": 514,
    "rtsp": 554,
    "secureid-udp": 5510,
    "sip": 5060,
    "sqlnet": 1521,
    "vxlan": 4789,
}
_PORTED = ("tcp", "udp", "sctp")
_PROTOCOL_ALIASES = {"ip": ANY, "icmp6": "icmpv6", "ipinip": "ipip", "ahp": "ah"}
_ACTIONS = {"permit": "allow", "trust": "allow", "deny": "deny"}
# Tokens before an address that match a user or a security group.
_IDENTITY = ("user", "user-group", "object-group-user", "security-group", "object-group-security")
_LOG_LEVELS = (
    "disable",
    "default",
    "emergencies",
    "alerts",
    "critical",
    "errors",
    "warnings",
    "notifications",
    "informational",
    "debugging",
)
# The NAT options that do not change what is translated.
_NAT_FLAGS = (
    "unidirectional",
    "no-proxy-arp",
    "route-lookup",
    "dns",
    "net-to-net",
    "round-robin",
    "extended",
    "flat",
    "include-reserve",
    "block-allocation",
    "ipv6",
    "interface",
)
_FTD_RULE = re.compile(r"\bL(\d) RULE:\s*(.*)$")


@dataclass
class _Service:
    """One protocol and its ports, as a service object or group item gives it."""

    protocol: str = ANY
    src_ports: str = ANY
    dst_ports: str = ANY
    unresolved: list[str] = field(default_factory=list)


def _protocol(token: str) -> str:
    name = token.lower()
    return _PROTOCOL_ALIASES.get(name, name)


def _port_op(tokens: list[str], i: int) -> tuple[str, list[str], int] | None:
    """The port match at ``tokens[i]`` (``eq https``, ``range 1024 65535``):
    ``(expression, unresolved, next index)``, or ``None`` when it is none."""
    if i >= len(tokens) or tokens[i].lower() not in _PORT_OPERATORS:
        return None
    operator = tokens[i].lower()
    count = 2 if operator == "range" else 1
    values = [str(PORT_NAMES.get(v.lower(), v)) for v in tokens[i + 1 : i + 1 + count]]
    expression, unresolved = _port_expression(operator, values)
    return expression, unresolved, i + 1 + count


def _service_args(tokens: list[str]) -> list[_Service]:
    """The services of ``tcp destination eq 443``, ``udp source range 1 2``,
    ``tcp eq www`` (the older destination form) or ``icmp echo``."""
    if not tokens:
        return [_Service(unresolved=["empty service"])]
    head = tokens[0].lower()
    protocols = ["tcp", "udp"] if head == "tcp-udp" else [_protocol(head)]
    ports = {"source": ANY, "destination": ANY}
    unresolved: list[str] = []
    i = 1
    while i < len(tokens):
        word = tokens[i].lower()
        side = word if word in ports else "destination"
        found = _port_op(tokens, i + 1 if word in ports else i)
        if found is None:
            what = "type" if head.startswith("icmp") else "match"
            unresolved.append(f"{head} {what} {' '.join(tokens[i:])}")
            break
        ports[side], missing, i = found
        unresolved += missing
    return [_Service(p, ports["source"], ports["destination"], list(unresolved)) for p in protocols]


def _range_cidrs(first: str, last: str) -> list[str]:
    try:
        low, high = ipaddress.ip_address(first), ipaddress.ip_address(last)
        return [str(n) for n in ipaddress.summarize_address_range(low, high)]
    except TypeError, ValueError:
        return []


def _literal(tokens: list[str]) -> tuple[list[str], list[str]]:
    """``(cidrs, unresolved)`` of ``host A``, ``A M``, ``A/len`` or ``A``."""
    if not tokens:
        return [], ["missing address"]
    head = tokens[0].lower()
    if head == "host" and len(tokens) > 1 and canonical(tokens[1]):
        return [canonical(tokens[1])], []
    if len(tokens) > 1 and is_address(tokens[0]) and is_address(tokens[1]):
        found = subnet(tokens[0], tokens[1])
        return ([found], []) if found else ([], [f"{tokens[0]} {tokens[1]}"])
    if canonical(tokens[0]) and (is_address(tokens[0]) or "/" in tokens[0]):
        return [canonical(tokens[0])], []
    return [], [" ".join(tokens)]


class _Objects:
    """The objects and object groups of a configuration, resolved on demand."""

    def __init__(self) -> None:
        self.networks: dict[str, list[list[str]]] = {}
        self.services: dict[str, list[list[str]]] = {}
        self.network_groups: dict[str, list[list[str]]] = {}
        # name -> (the protocol of a port group, or "" for a group of services; its lines)
        self.service_groups: dict[str, tuple[str, list[list[str]]]] = {}
        self.protocol_groups: dict[str, list[list[str]]] = {}

    def network(self, name: str) -> tuple[list[str], list[str]]:
        """``(cidrs, unresolved)`` of an ``object network``."""
        if name not in self.networks:
            return [], [f"object {name}"]
        cidrs: list[str] = []
        unresolved: list[str] = []
        for tokens in self.networks[name]:
            head = tokens[0].lower()
            if head in ("host", "subnet") and len(tokens) > 1:
                found, missing = _literal(tokens if head == "host" else tokens[1:])
            elif head == "range" and len(tokens) > 2:
                found = _range_cidrs(tokens[1], tokens[2])
                missing = [] if found else [f"range {tokens[1]} {tokens[2]}"]
            elif head == "fqdn":
                found, missing = [], [f"fqdn {tokens[-1]} (object {name})"]
            else:
                continue
            cidrs += found
            unresolved += missing
        if not cidrs and not unresolved:
            unresolved = [f"object {name} (no address)"]
        return cidrs, unresolved

    def network_group(self, name: str, seen: frozenset[str] = frozenset()) -> tuple[list[str], list[str]]:
        """``(cidrs, unresolved)`` of an ``object-group network``."""
        if name not in self.network_groups or name in seen:
            return [], [f"object-group {name}"]
        cidrs: list[str] = []
        unresolved: list[str] = []
        for tokens in self.network_groups[name]:
            head = tokens[0].lower()
            if head == "group-object" and len(tokens) > 1:
                found, missing = self.network_group(tokens[1], seen | {name})
            elif head == "network-object" and len(tokens) > 2 and tokens[1].lower() == "object":
                found, missing = self.network(tokens[2])
            elif head == "network-object" and len(tokens) > 1:
                found, missing = _literal(tokens[1:])
            else:
                continue
            cidrs += found
            unresolved += missing
        if not cidrs and not unresolved:
            unresolved = [f"object-group {name} (empty)"]
        return cidrs, unresolved

    def service(self, name: str) -> list[_Service]:
        """The services of an ``object service``."""
        found = [s for t in self.services.get(name, []) if t[0].lower() == "service" for s in _service_args(t[1:])]
        return found or [_Service(unresolved=[f"object {name}"])]

    def port_group(self, name: str, seen: frozenset[str] = frozenset()) -> tuple[str, list[str]]:
        """``(expression, unresolved)`` of an ``object-group service NAME tcp``."""
        parts: list[str] = []
        unresolved: list[str] = []
        for tokens in self.service_groups.get(name, ("", []))[1]:
            head = tokens[0].lower()
            if head == "port-object":
                found = _port_op(tokens, 1)
                if found is None:
                    unresolved.append(" ".join(tokens))
                    continue
                expression, missing, _end = found
            elif head == "group-object" and len(tokens) > 1 and tokens[1] not in seen | {name}:
                expression, missing = self.port_group(tokens[1], seen | {name})
            else:
                continue
            unresolved += missing
            if not missing:
                parts.append(expression)
        if unresolved or not parts:
            return ANY, unresolved or [f"object-group {name}"]
        return ",".join(parts), []

    def service_group(self, name: str, seen: frozenset[str] = frozenset()) -> list[_Service]:
        """The services of an ``object-group service``."""
        if name not in self.service_groups or name in seen:
            return [_Service(unresolved=[f"object-group {name}"])]
        kind, lines = self.service_groups[name]
        if kind:
            ports, unresolved = self.port_group(name, seen)
            protocols = ["tcp", "udp"] if kind == "tcp-udp" else [kind]
            return [_Service(p, ANY, ports, list(unresolved)) for p in protocols]
        found: list[_Service] = []
        for tokens in lines:
            head = tokens[0].lower()
            if head == "service-object" and len(tokens) > 2 and tokens[1].lower() == "object":
                found += self.service(tokens[2])
            elif head == "service-object" and len(tokens) > 1:
                found += _service_args(tokens[1:])
            elif head == "group-object" and len(tokens) > 1:
                found += self.service_group(tokens[1], seen | {name})
        return found or [_Service(unresolved=[f"object-group {name} (empty)"])]

    def protocols(self, name: str, seen: frozenset[str] = frozenset()) -> list[_Service]:
        """The protocols of an ``object-group protocol``."""
        found: list[_Service] = []
        for tokens in self.protocol_groups.get(name, []):
            head = tokens[0].lower()
            if head == "protocol-object" and len(tokens) > 1:
                value = tokens[1].lower()
                found += [_Service(p) for p in (["tcp", "udp"] if value == "tcp-udp" else [_protocol(value)])]
            elif head == "group-object" and len(tokens) > 1 and tokens[1] not in seen | {name}:
                found += self.protocols(tokens[1], seen | {name})
        return found or [_Service(unresolved=[f"object-group {name}"])]

    def address(self, kind: str, name: str) -> tuple[list[str], list[str]]:
        """An ``object`` or ``object-group`` used as an address."""
        return self.network(name) if kind == "object" else self.network_group(name)

    def strict(self, token: str) -> list[str] | None:
        """A NAT rule's network (``any``, an address, an object or a group), or
        ``None`` when it is not all addresses."""
        if token.lower() == "any":
            return [ANY]
        if canonical(token) and (is_address(token) or "/" in token):
            return [canonical(token)]
        if token in self.networks:
            cidrs, missing = self.network(token)
        else:
            cidrs, missing = self.network_group(token)
        return None if missing or not cidrs else cidrs


@dataclass
class _Acl:
    """What an ``access-list`` line says, read in the context of its list."""

    objects: _Objects
    # nameif -> the interface's address, for ``interface NAMEIF`` in an entry.
    addresses: dict[str, str]
    unresolved: list[str] = field(default_factory=list)

    def address(self, tokens: list[str], i: int) -> tuple[list[str], int]:
        """The address at ``tokens[i]``: ``(cidrs, next index)``. One only
        partly resolved matches any address (its ``unresolved`` say why)."""
        i = self._identity(tokens, i)
        if i >= len(tokens):
            self.unresolved.append("missing address")
            return [ANY], i
        word = tokens[i].lower()
        found: list[str]
        missing: list[str] = []
        end = i + 1
        if word == "any":
            found = [ANY]
        elif word in ("any4", "any6"):
            found = ["0.0.0.0/0" if word == "any4" else "::/0"]
        elif word in ("host", "object", "object-group", "interface") and i + 1 < len(tokens):
            end = i + 2
            if word == "host":
                found, missing = _literal(tokens[i : i + 2])
            elif word == "interface":
                ip = self.addresses.get(tokens[i + 1].lower(), "")
                found, missing = ([f"{ip}/32"], []) if ip else ([], [f"interface {tokens[i + 1]}"])
            else:
                found, missing = self.objects.address(word, tokens[i + 1])
        elif i + 1 < len(tokens) and is_address(tokens[i]) and is_address(tokens[i + 1]):
            found, missing = _literal(tokens[i : i + 2])
            end = i + 2
        else:
            found, missing = _literal(tokens[i : i + 1])
        self.unresolved += missing
        return ([ANY] if missing or not found else list(dict.fromkeys(found))), end

    def _identity(self, tokens: list[str], i: int) -> int:
        """Skips a user or security group match before an address, which is unresolved."""
        while i < len(tokens) and tokens[i].lower() in _IDENTITY:
            width = 3 if tokens[i].lower() == "security-group" and i + 1 < len(tokens) else 2
            self.unresolved.append(" ".join(tokens[i : i + width]))
            i += width
        return i

    def ports(self, tokens: list[str], i: int) -> tuple[str, int]:
        """A port match at ``tokens[i]``, if any: an operator or a port group."""
        found = _port_op(tokens, i)
        if found is not None:
            expression, missing, end = found
            self.unresolved += missing
            return expression, end
        if i + 1 < len(tokens) and tokens[i].lower() == "object-group":
            kind = self.objects.service_groups.get(tokens[i + 1], ("", []))[0]
            if kind:
                expression, missing = self.objects.port_group(tokens[i + 1])
                self.unresolved += missing
                return expression, i + 2
        return ANY, i

    def protocol(self, tokens: list[str], i: int) -> tuple[list[_Service], bool, int]:
        """The protocol at ``tokens[i]``: ``(services, whether the entry
        names ports itself, next index)``."""
        word = tokens[i].lower()
        if word in ("object", "object-group") and i + 1 < len(tokens):
            name = tokens[i + 1]
            if word == "object":
                return self.objects.service(name), False, i + 2
            if name in self.objects.protocol_groups:
                services = self.objects.protocols(name)
                return services, all(s.protocol in _PORTED for s in services), i + 2
            return self.objects.service_group(name), False, i + 2
        services = [_Service(p) for p in (["tcp", "udp"] if word == "tcp-udp" else [_protocol(word)])]
        return services, all(s.protocol in _PORTED for s in services), i + 1

    def rest(self, tokens: list[str], icmp: bool) -> bool:
        """The options after the destination; whether the entry is active."""
        enabled = True
        i = 0
        while i < len(tokens):
            word = tokens[i].lower()
            if word == "log":
                i += 1
                while i < len(tokens) and (tokens[i].isdigit() or tokens[i].lower() in _LOG_LEVELS):
                    i += 1
                if i < len(tokens) and tokens[i].lower() == "interval":
                    i += 2
                continue
            if word in ("rule-id", "event-log"):
                i += 2
            elif word == "inactive":
                enabled = False
                i += 1
            elif word == "time-range" and i + 1 < len(tokens):
                self.unresolved.append(f"time-range {tokens[i + 1]}")
                i += 2
            elif icmp and word == "object-group" and i + 1 < len(tokens):
                self.unresolved.append(f"ICMP types (object-group {tokens[i + 1]})")
                i += 2
            elif icmp and not word.isdigit():
                # An ICMP type and its optional code.
                end = i + 2 if i + 1 < len(tokens) and tokens[i + 1].isdigit() else i + 1
                self.unresolved.append(f"ICMP type {' '.join(tokens[i:end])}")
                i = end
            else:
                self.unresolved.append(" ".join(tokens[i:]))
                break
        return enabled


def _ifc(tokens: list[str], i: int) -> tuple[list[str], int]:
    """The ``ifc NAMEIF`` an FTD entry names before an address."""
    if i + 1 < len(tokens) and tokens[i].lower() == "ifc":
        return [tokens[i + 1]], i + 2
    return [], i


def _ace(tokens: list[str], acl: _Acl, sequence: int, comment: str) -> list[AclEntry]:
    """The entries of one ``extended`` / ``advanced`` access list entry (the
    tokens from its action on); a service group gives one per service."""
    if len(tokens) < 2 or tokens[0].lower() not in _ACTIONS:
        return []
    services, ported, i = acl.protocol(tokens, 1)
    src_zones, i = _ifc(tokens, i)
    src, i = acl.address(tokens, i)
    src_ports = dst_ports = ANY
    if ported:
        src_ports, i = acl.ports(tokens, i)
    dst_zones, i = _ifc(tokens, i)
    dst, i = acl.address(tokens, i)
    if ported:
        dst_ports, i = acl.ports(tokens, i)
    icmp = all(s.protocol.startswith("icmp") for s in services)
    enabled = acl.rest(tokens[i:], icmp)
    name = ""
    rule = _FTD_RULE.search(comment)
    if rule:
        name = rule.group(2).strip()
        if rule.group(1) != "4" and tokens[0].lower() != "deny":
            # LINA passes it to Snort, whose application, URL or user conditions decide.
            acl.unresolved.append(f"FTD access control rule {name} (conditions Snort decides)")
    return [
        AclEntry(
            sequence,
            _ACTIONS[tokens[0].lower()],
            protocol=service.protocol,
            src=src,
            src_ports=src_ports if ported else service.src_ports,
            dst=dst,
            dst_ports=dst_ports if ported else service.dst_ports,
            comment=comment,
            unresolved=list(dict.fromkeys(acl.unresolved + service.unresolved)),
            name=name,
            src_zones=src_zones,
            dst_zones=dst_zones,
            enabled=enabled,
        )
        for service in services
    ]


def _access_list(lines: list[list[str]], objects: _Objects, addresses: dict[str, str]) -> list[AclEntry]:
    """The entries of one access list from its lines (the tokens after
    ``access-list NAME``). Each line counts, remarks too, as ``show
    access-list`` numbers them; a remark is the comment of the entries after
    it, up to the next one (as an FTD's name its rule's entries)."""
    entries: list[AclEntry] = []
    comment = ""
    for line, tokens in enumerate(lines, start=1):
        if tokens[:1] and tokens[0].lower() == "line" and len(tokens) > 2:
            tokens = tokens[2:]
        head = tokens[0].lower() if tokens else ""
        if head == "remark":
            comment = " ".join(tokens[1:])
            continue
        if head in ("extended", "advanced"):
            tokens = tokens[1:]
        entries += _ace(tokens, _Acl(objects, addresses), line, comment)
    return entries


@dataclass
class _Interface:
    config: ConfigInterface
    nameif: str = ""
    level: int | None = None
    management: bool = False


def _interface(name: str, children: list[tuple[int, str]]) -> _Interface:
    found = _Interface(ConfigInterface(name))
    conf = found.config
    ipv4: list[tuple[str, str]] = []
    for _indent, line in children:
        tokens = line.split()
        words = [t.lower() for t in tokens]
        if words[0] == "nameif" and len(tokens) > 1:
            found.nameif = tokens[1]
        elif words[0] == "security-level" and len(words) > 1 and words[1].isdigit():
            found.level = int(words[1])
        elif words[0] == "description":
            conf.description = line.split(None, 1)[1] if len(tokens) > 1 else ""
        elif words[0] == "shutdown":
            conf.shutdown = True
        elif words[:2] == ["no", "shutdown"]:
            conf.shutdown = False
        elif words[0] == "management-only":
            found.management = True
        elif words[:2] == ["ip", "address"] and len(tokens) > 3 and subnet(tokens[2], tokens[3]):
            # One address: the standby one is the failover peer's, not this unit's.
            ipv4 = [(tokens[2], subnet(tokens[2], tokens[3]))]
        elif words[:2] == ["ipv6", "address"] and len(tokens) > 2 and "/" in tokens[2]:
            address, network = tokens[2].split("/", 1)[0], canonical(tokens[2])
            if is_address(address) and network:
                conf.addresses.append((address, network))
    conf.addresses[:0] = ipv4
    if found.nameif:
        conf.zone = found.nameif
        conf.aliases = [found.nameif]
        if found.level is None:
            found.level = 100 if found.nameif.lower() == "inside" else 0
        if found.nameif.lower() == "outside":
            conf.kind = "wan"
    return found


def _static_route(tokens: list[str]) -> StaticRoute | None:
    """``route NAMEIF NET MASK GATEWAY [DISTANCE] [tunneled | track N]`` or
    ``ipv6 route NAMEIF PREFIX/LEN GATEWAY [DISTANCE]`` (the tokens after
    ``route``). A ``tunneled`` route carries only the traffic of VPN
    tunnels, so it is left out."""
    if len(tokens) < 3 or "tunneled" in (t.lower() for t in tokens):
        return None
    if "/" in tokens[1]:
        prefix, i = canonical(tokens[1]), 2
    else:
        prefix, i = subnet(tokens[1], tokens[2]), 3
    if not prefix or i >= len(tokens):
        return None
    found = StaticRoute(prefix, interface=tokens[0])
    if is_address(tokens[i]):
        found.next_hop = tokens[i]
        i += 1
    if i < len(tokens) and tokens[i].isdigit():
        found.distance = int(tokens[i])
    return found


@dataclass
class _Reader:
    """What the first pass over the configuration collects."""

    config: RunningConfig = field(default_factory=RunningConfig)
    objects: _Objects = field(default_factory=_Objects)
    interfaces: list[_Interface] = field(default_factory=list)
    acl_lines: dict[str, list[list[str]]] = field(default_factory=dict)
    # (access list, "in" / "out" / "global", nameif)
    groups: list[tuple[str, str, str]] = field(default_factory=list)
    inter_interface: bool = False
    intra_interface: bool = False
    # (section, the tokens after ``nat``) of the twice NAT rules.
    manual_nat: list[tuple[int, list[str]]] = field(default_factory=list)
    # (object, the tokens after ``nat``) of the object NAT rules.
    object_nat: list[tuple[str, list[str]]] = field(default_factory=list)

    def block(self, header: str, children: list[tuple[int, str]]) -> None:
        tokens = header.split()
        words = [t.lower() for t in tokens]
        lines = [line.split() for _indent, line in children]
        config = self.config
        if words[:2] == ["object", "network"] and len(tokens) > 2:
            self.objects.networks.setdefault(tokens[2], []).extend(lines)
            self.object_nat += [(tokens[2], line[1:]) for line in lines if line[0].lower() == "nat"]
        elif words[:2] == ["object", "service"] and len(tokens) > 2:
            self.objects.services.setdefault(tokens[2], []).extend(lines)
        elif words[0] == "object-group" and len(tokens) > 2:
            self._group(words[1], tokens[2], words[3] if len(words) > 3 else "", lines)
        elif words[0] == "access-list" and len(tokens) > 2:
            self._access_list(tokens[1], tokens[2:])
        elif words[:2] == ["ipv6", "access-list"]:
            add_note(config, IPV6_ACCESS_LISTS)
        elif words[0] == "access-group" and len(tokens) > 2 and "control-plane" not in words:
            if words[2] == "global":
                self.groups.append((tokens[1], "global", ""))
            elif words[2] in ("in", "out") and len(tokens) > 4 and words[3] == "interface":
                self.groups.append((tokens[1], words[2], tokens[4]))
        elif words[0] == "interface" and len(tokens) > 1:
            found = _interface("".join(tokens[1:]), children)
            self.interfaces.append(found)
            config.interfaces.append(found.config)
            if any(line.lower().startswith("policy-route route-map") for _indent, line in children):
                add_note(config, POLICY_BASED_ROUTES)
        elif words[:2] == ["same-security-traffic", "permit"] and len(words) > 2:
            self.inter_interface |= words[2] == "inter-interface"
            self.intra_interface |= words[2] == "intra-interface"
        elif words[0] == "route" or words[:2] == ["ipv6", "route"]:
            route = _static_route(tokens[1:] if words[0] == "route" else tokens[2:])
            if route is not None:
                config.static_routes.append(route)
        elif words[0] == "router" or words[:2] == ["ipv6", "router"]:
            kind = words[1] if words[0] == "router" else ("ospfv3" if words[2:3] == ["ospf"] else "")
            name = ROUTING_PROTOCOLS.get(kind)
            if name and name not in config.routing:
                config.routing.append(name)
        elif words[0] == "nat" and len(tokens) > 2:
            if words[1].startswith("(") and "source" in words:
                self.manual_nat.append((3 if "after-auto" in words else 1, tokens[1:]))
            else:
                add_note(config, LEGACY_NAT)
        else:
            self._notes(words)

    def _group(self, kind: str, name: str, protocol: str, lines: list[list[str]]) -> None:
        lines = [line for line in lines if line[0].lower() != "description"]
        if kind == "network":
            self.objects.network_groups.setdefault(name, []).extend(lines)
        elif kind == "service":
            self.objects.service_groups[name] = (protocol if protocol in ("tcp", "udp", "tcp-udp") else "", lines)
        elif kind == "protocol":
            self.objects.protocol_groups.setdefault(name, []).extend(lines)

    def _access_list(self, name: str, rest: list[str]) -> None:
        kind = rest[0].lower()
        if kind == "standard":
            return  # route and VPN filters, not applied to traffic by an access group
        if kind == "ethertype":
            add_note(self.config, ETHERTYPE_ACCESS_LISTS)
        elif kind == "webtype":
            add_note(self.config, WEBTYPE_ACCESS_LISTS)
        else:
            self.acl_lines.setdefault(name, []).append(rest)

    def _notes(self, words: list[str]) -> None:
        config = self.config
        if words[:2] == ["crypto", "map"]:
            add_note(config, SITE_TO_SITE_VPN)
        elif words[0] == "tunnel-group" and len(words) > 3 and words[2] == "type":
            add_note(config, SITE_TO_SITE_VPN if words[3] == "ipsec-l2l" else REMOTE_ACCESS_VPN)
        elif words[0] == "webvpn":
            add_note(config, REMOTE_ACCESS_VPN)
        elif words[0] in ("policy-map", "class-map"):
            add_note(config, INSPECTION)
        elif words[:2] == ["mode", "multiple"] or words[0] == "context":
            add_note(config, CONTEXTS)
        elif words[:2] == ["firewall", "transparent"]:
            add_note(config, TRANSPARENT)
        elif words[0] in ("global", "static") and len(words) > 1 and words[1].startswith("("):
            add_note(config, LEGACY_NAT)


def _bind(reader: _Reader) -> set[str]:
    """Puts the access groups on the interfaces and the global access list
    in the policies; the nameifs whose inbound traffic an access list decides."""
    config = reader.config
    by_nameif = {i.nameif.lower(): i for i in reader.interfaces if i.nameif}
    global_acl = next((name for name, direction, _n in reader.groups if direction == "global"), "")
    decided: set[str] = set(by_nameif) if global_acl else set()
    global_entries = config.access_lists.get(global_acl, [])
    for name, direction, nameif in reader.groups:
        found = by_nameif.get(nameif.lower())
        if direction == "global" or found is None:
            continue
        if direction == "in":
            decided.add(nameif.lower())
        if direction == "in" and global_acl and name in config.access_lists:
            # The global entries follow the interface's own, then the implicit deny.
            merged = f"{name}, then global {global_acl}"
            config.access_lists[merged] = config.access_lists[name] + [
                entry
                for entry in global_entries
                if not entry.src_zones or nameif.lower() in {z.lower() for z in entry.src_zones}
            ]
            name = merged
        found.config.access_groups[direction] = name
    if global_acl:
        rules = [
            AclEntry(
                None,
                "allow",
                src_zones=[i.nameif],
                comment=f"{i.nameif} has an inbound access list, which decides",
            )
            for i in reader.interfaces
            if i.nameif and "in" in i.config.access_groups
        ]
        if global_acl in config.access_lists:
            rules += global_entries
        else:
            rules.append(AclEntry(None, "allow", unresolved=[f"access list {global_acl} (not in the configuration)"]))
        config.policies.append(ConfigPolicy(f"Global ACL {global_acl}", rules, kind="acl", default="deny"))
    return decided


def _security_levels(reader: _Reader, decided: set[str]) -> ConfigPolicy | None:
    """The implicit rules of the security levels, as a rule set: through
    a management-only interface nothing passes; between interfaces of the
    same level, and back out of the interface it came in by, only with
    ``same-security-traffic``; an interface whose inbound traffic an access
    list decides is left to it; any other lets traffic leave by an interface
    of a lower level."""
    named = [i for i in reader.interfaces if i.nameif]
    if not named:
        return None
    entries: list[AclEntry] = []
    for each in named:
        if each.management:
            text = f"{each.nameif} is management-only: no traffic passes through it"
            entries.append(AclEntry(None, "deny", src_zones=[each.nameif], comment=text))
            entries.append(AclEntry(None, "deny", dst_zones=[each.nameif], comment=text))
    through = [i for i in named if not i.management]
    for each in through:
        nameif, level = each.nameif, each.level or 0
        equal = [o.nameif for o in through if o is not each and (o.level or 0) == level]
        if not reader.intra_interface:
            text = f"Back out of {nameif}: no same-security-traffic permit intra-interface"
            entries.append(AclEntry(None, "deny", src_zones=[nameif], dst_zones=[nameif], comment=text))
        if equal and not reader.inter_interface:
            text = f"Security level {level} to the same level: no same-security-traffic permit inter-interface"
            entries.append(AclEntry(None, "deny", src_zones=[nameif], dst_zones=equal, comment=text))
        if nameif.lower() in decided:
            text = f"{nameif} has an inbound access list, which decides"
            entries.append(AclEntry(None, "allow", src_zones=[nameif], comment=text))
            continue
        allowed = [o.nameif for o in through if (o.level or 0) < level]
        allowed += equal if reader.inter_interface else []
        allowed += [nameif] if reader.intra_interface else []
        if allowed:
            text = f"Security level {level} to a lower level"
            entries.append(AclEntry(None, "allow", src_zones=[nameif], dst_zones=allowed, comment=text))
    return ConfigPolicy(SECURITY_LEVELS, entries, kind="policy", default="deny")


def _nat_pair(token: str) -> tuple[str, str] | None:
    """``(real interface, mapped interface)`` of ``(inside,outside)``; ``any`` is ``""``."""
    match = re.fullmatch(r"\(([^,]*),([^)]*)\)", token)
    if match is None:
        return None
    real, mapped = (m.strip() for m in match.groups())
    return ("" if real.lower() == "any" else real), ("" if mapped.lower() == "any" else mapped)


def _mapped(token: str, objects: _Objects) -> list[str] | None:
    return [INTERFACE] if token.lower() == "interface" else objects.strict(token)


def _object_nat(index: int, name: str, tokens: list[str], objects: _Objects) -> list[dict[str, Any]] | None:
    """The entries of ``nat (IN,OUT) static|dynamic MAPPED [service P REAL MAPPED]``
    under ``object network NAME``, as the FMC reader makes those of an auto
    NAT rule: the real source leaves translated and, for a static rule,
    traffic to the mapped address reaches the real one."""
    pair = _nat_pair(tokens[0])
    real = objects.strict(name)
    if pair is None or real is None or len(tokens) < 3:
        return None
    kind = tokens[1].lower()
    i = 2
    if tokens[i].lower() == "pat-pool" and i + 1 < len(tokens):
        i += 1
    mapped = _mapped(tokens[i], objects)
    if mapped is None:
        return None
    protocol, real_port, mapped_port = ANY, "", ""
    words = [t.lower() for t in tokens]
    if "service" in words:
        at = words.index("service")
        if len(tokens) < at + 4:
            return None
        protocol = _protocol(tokens[at + 1])
        real_port, mapped_port = (str(PORT_NAMES.get(v.lower(), v)) for v in tokens[at + 2 : at + 4])
        if not (real_port.isdigit() and mapped_port.isdigit()):
            return None
    src_if, dst_if = pair
    entries = [
        nat(
            index,
            "auto",
            name=name,
            original_src=real,
            translated_src=mapped,
            protocol=protocol,
            src_interface=src_if,
            dst_interface=dst_if,
        )
    ]
    if kind == "static":
        entries.append(
            nat(
                index,
                "auto",
                name=name,
                original_dst=mapped,
                translated_dst=real,
                protocol=protocol,
                original_port=mapped_port,
                translated_port=real_port,
                src_interface=dst_if,
                dst_interface=src_if,
            )
        )
    return entries


def _nat_service(name: str, objects: _Objects) -> _Service | None:
    """The one protocol and destination port of a NAT rule's service object."""
    services = objects.service(name)
    if len(services) != 1 or services[0].unresolved or services[0].src_ports != ANY:
        return None
    return services[0]


def _manual_nat(index: int, kind: str, tokens: list[str], objects: _Objects) -> list[dict[str, Any]] | None:
    """The entry of ``nat (IN,OUT) [after-auto] [LINE] source static|dynamic
    REAL MAPPED [destination static MAPPED REAL] [service REAL MAPPED] ...``,
    as the FMC reader makes that of a manual NAT rule."""
    pair = _nat_pair(tokens[0])
    words = [t.lower() for t in tokens]
    at = words.index("source")
    if pair is None or len(tokens) < at + 4:
        return None
    original_src = objects.strict(tokens[at + 2])
    i = at + 3
    if words[i] == "pat-pool" and i + 1 < len(tokens):
        i += 1
    translated_src = _mapped(tokens[i], objects)
    i += 1
    original_dst: list[str] | None = [ANY]
    translated_dst: list[str] | None = []
    protocol, original_port, translated_port = ANY, "", ""
    enabled, name = True, ""
    while i < len(tokens):
        word = words[i]
        if word == "destination" and i + 3 < len(tokens):
            original_dst, translated_dst = _mapped(tokens[i + 2], objects), objects.strict(tokens[i + 3])
            i += 4
        elif word == "service" and i + 2 < len(tokens):
            first, second = _nat_service(tokens[i + 1], objects), _nat_service(tokens[i + 2], objects)
            if first is None or second is None:
                return None
            protocol, original_port, translated_port = first.protocol, first.dst_ports, second.dst_ports
            if translated_port != ANY and not translated_port.isdigit():
                return None
            original_port = "" if original_port == ANY else original_port
            translated_port = "" if translated_port == ANY else translated_port
            i += 3
        elif word == "description":
            name = " ".join(tokens[i + 1 :])
            break
        else:
            enabled = enabled and word != "inactive"
            i += 1
    if original_src is None or translated_src is None or original_dst is None or translated_dst is None:
        return None
    return [
        nat(
            index,
            kind,
            name=name or f"Manual NAT rule {index}",
            enabled=enabled,
            original_src=original_src,
            original_dst=original_dst,
            translated_src=translated_src,
            translated_dst=translated_dst,
            protocol=protocol,
            original_port=original_port,
            translated_port=translated_port,
            src_interface=pair[0],
            dst_interface=pair[1],
        )
    ]


def _object_order(item: tuple[str, list[str]], objects: _Objects) -> tuple:
    """The order of the object NAT rules: static before dynamic, then the
    fewer real addresses, the lower first address, the name."""
    name, tokens = item
    cidrs = [c for c in objects.network(name)[0] if canonical(c)]
    networks = [ipaddress.ip_network(c) for c in cidrs]
    size = sum(n.num_addresses for n in networks) if networks else 1 << 128
    first = min((int(n.network_address) for n in networks), default=0)
    dynamic = len(tokens) > 1 and tokens[1].lower() != "static"
    return (dynamic, size, first, name)


def _nat(reader: _Reader) -> None:
    """The NAT rules in the order the ASA evaluates them: twice NAT, object
    NAT, twice NAT after auto. A rule whose networks or services are not all
    addresses or single ports is noted instead."""
    config, objects = reader.config, reader.objects
    index = 0
    sections: list[tuple[str, list]] = [
        ("manual_before", [t for s, t in reader.manual_nat if s == 1]),
        ("auto", sorted(reader.object_nat, key=lambda item: _object_order(item, objects))),
        ("manual_after", [t for s, t in reader.manual_nat if s == 3]),
    ]
    for kind, rules in sections:
        for rule in rules:
            index += 1
            if kind == "auto":
                entries = _object_nat(index, rule[0], rule[1], objects)
            else:
                entries = _manual_nat(index, kind, rule, objects)
            if entries is None:
                add_note(config, f"NAT rule {index} (its networks or services are not all addresses or single ports)")
                continue
            config.nat.extend(entries)


def parse_config(text: str) -> RunningConfig:
    """What a Cisco ASA / FTD running configuration says about forwarding:
    interfaces, access lists and their bindings, the security levels, NAT,
    static routes, routing protocols."""
    reader = _Reader()
    for block in blocks(text):
        reader.block(block.header, block.children)
    config = reader.config
    config.stateful = True
    addresses = {
        i.nameif.lower(): i.config.addresses[0][0] for i in reader.interfaces if i.nameif and i.config.addresses
    }
    for name, lines in reader.acl_lines.items():
        config.access_lists[name] = _access_list(lines, reader.objects, addresses)
    decided = _bind(reader)
    levels = _security_levels(reader, decided)
    if levels is not None:
        config.policies.append(levels)
    _nat(reader)
    return config
