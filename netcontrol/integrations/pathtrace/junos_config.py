"""The running configuration of a Juniper Junos device, read for path tracing.

The config backup feature stores what ``show configuration | display set``
prints: one ``set`` line per statement. ``parse_config`` reads from it what
the forwarding block of an inventory host needs and the route table capture
does not give (see ``device_config`` for the shape):

- the logical interfaces (``ge-0/0/0.0``, ``irb.100``, ``ae0.0``, the names
  SNMP and ``show route`` print), with their addresses, the primary first,
  VRRP virtual addresses, state, description, the routing instance they are
  in, the SRX security zone they are in, and the IPv4 firewall filters bound
  to them in and out (a filter list is read as the one filter its filters
  make together, in order, ending in the last one's discard);
- the IPv4 firewall filters, each term in forwarding rule terms: a term
  that lists several addresses, protocols or ports matches any of them, so
  it gives one entry per combination; ``address`` and ``port`` (either
  side) give one entry per side. A term with no ``accept``, ``discard`` or
  ``reject`` accepts; a ``next term`` term only counts or logs, so it gives
  none; a filter ends in an implicit discard, the rule set's default.
  What cannot be turned into rule terms (an ``except`` address, a prefix
  list the configuration does not define, TCP flags other than an
  established match, DSCP, fragments, filter-based forwarding) is kept in
  the entry's ``unresolved`` list, so a flow it matches is unknown;
- on an SRX, the security policies as one stateful rule set: the zone-pair
  policies in their order, then the global policies, then the default
  policy (``deny-all`` unless ``permit-all``), with the addresses resolved
  through the address books (global, named ones attached to zones, and the
  ones under a zone) and the applications through the custom applications,
  the application sets and the common ``junos-*`` defaults. An address or
  application that is not defined, a ``dns-name`` address, a negated match,
  a source identity, a dynamic application or a scheduler is unresolved;
- the SRX static, destination and source NAT rules, in the order the SRX
  applies them, in forwarding ``nat`` terms;
- the static routes, including those of routing instances, and which
  routing protocols run.

The filters bound to interfaces are stateless (``stateful`` is false): the
replies are matched again, so a ``tcp-established`` term lets them in.

The hierarchical (brace) format is not read: a backup in that format gives
only a note. Lines a ``deactivate`` line covers are not in effect and are
left out. IPv6 filters, security screens, IPsec VPNs and configuration
groups are not read and are named in ``notes``.

``parse_routes`` reads ``show route`` captures: the active route of each
destination in ``inet.0`` and every routing instance's ``<instance>.inet.0``.

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field, replace
from typing import Any

from netcontrol.integrations.meraki.forwarding import ANY, INTERFACE, canonical, is_address, nat
from netcontrol.integrations.pathtrace.device_config import (
    AclEntry,
    ConfigInterface,
    ConfigPolicy,
    RunningConfig,
    StaticRoute,
)
from netcontrol.integrations.pathtrace.ios_config import (
    PORT_NAMES,
    ROUTING_PROTOCOLS,
    _complement,
    add_note as _note,
    add_virtual,
)
from netcontrol.integrations.pathtrace.route_tables import LOCAL, route_entry, vrf_name

__all__ = ["JUNOS_APPLICATIONS", "parse_config", "parse_routes"]

# Not-collected names a configuration gives when it uses what is not read.
HIERARCHICAL = "Junos configuration in the hierarchical format (back it up with display set)"
IPV6_FILTERS = "IPv6 firewall filters"
OTHER_FILTERS = "Firewall filters of other families (ethernet-switching, bridge, any)"
SCREENS = "Security screens"
IPSEC_VPNS = "IPsec VPNs"
GROUPS = "Configuration groups (apply-groups)"
LOGICAL_SYSTEMS = "Logical systems"
INTERFACE_RANGES = "Interface ranges"
APPLICATION_SERVICES = "Application services of security policies (IDP, UTM, AppFW)"
SECURITY_POLICIES = "Security policies"

# The port names Junos prints, on top of the names it shares with IOS.
JUNOS_PORT_NAMES = {
    **PORT_NAMES,
    "afs": 1483,
    "cvspserver": 2401,
    "dhcp": 67,
    "eklogin": 2105,
    "ekshell": 2106,
    "http-mgmt": 280,
    "imap": 143,
    "kerberos-sec": 88,
    "kpasswd": 761,
    "krb-prop": 754,
    "krbupdate": 760,
    "ldp": 646,
    "mobileip-agent": 434,
    "mobilip-mn": 435,
    "msdp": 639,
    "netbios-ssn": 139,
    "nfsd": 2049,
    "ntalk": 518,
    "pptp": 1723,
    "printer": 515,
    "radacct": 1813,
    "radius": 1812,
    "rkinit": 2108,
    "snpp": 444,
    "socks": 1080,
    "tacacs-ds": 65,
    "timed": 525,
    "zephyr-clt": 2103,
    "zephyr-hm": 2104,
    "zephyr-srv": 2102,
}

# (protocol, destination ports) of each service of the common predefined
# applications and application sets. Another ``junos-*`` name is unresolved.
JUNOS_APPLICATIONS: dict[str, list[tuple[str, str]]] = {
    "junos-bgp": [("tcp", "179")],
    "junos-cifs": [("tcp", "139"), ("tcp", "445")],
    "junos-dhcp-client": [("udp", "68")],
    "junos-dhcp-server": [("udp", "67")],
    "junos-dns-tcp": [("tcp", "53")],
    "junos-dns-udp": [("udp", "53")],
    "junos-ftp": [("tcp", "21")],
    "junos-gre": [("gre", ANY)],
    "junos-http": [("tcp", "80")],
    "junos-https": [("tcp", "443")],
    "junos-icmp-all": [("icmp", ANY)],
    "junos-icmp-ping": [("icmp", ANY)],
    "junos-ike": [("udp", "500")],
    "junos-ike-nat": [("udp", "4500")],
    "junos-imap": [("tcp", "143")],
    "junos-imaps": [("tcp", "993")],
    "junos-ldap": [("tcp", "389")],
    "junos-ms-rpc-tcp": [("tcp", "135")],
    "junos-ms-rpc-udp": [("udp", "135")],
    "junos-ms-sql": [("tcp", "1433")],
    "junos-mysql": [("tcp", "3306")],
    "junos-nbds": [("udp", "138")],
    "junos-nbname": [("udp", "137")],
    "junos-netbios-session": [("tcp", "139")],
    "junos-nfs": [("udp", "2049")],
    "junos-ntp": [("udp", "123")],
    "junos-ospf": [("ospf", ANY)],
    "junos-ping": [("icmp", ANY)],
    "junos-pop3": [("tcp", "110")],
    "junos-pptp": [("tcp", "1723")],
    "junos-radacct": [("udp", "1813")],
    "junos-radius": [("udp", "1812")],
    "junos-rdp": [("tcp", "3389")],
    "junos-sip": [("udp", "5060")],
    "junos-smb": [("tcp", "139"), ("tcp", "445")],
    "junos-smb-session": [("tcp", "445")],
    "junos-smtp": [("tcp", "25")],
    "junos-smtps": [("tcp", "465")],
    "junos-snmp-agentx": [("tcp", "705")],
    "junos-snmp-get": [("udp", "161")],
    "junos-snmp-trap": [("udp", "162")],
    "junos-sqlnet-v2": [("tcp", "1521")],
    "junos-ssh": [("tcp", "22")],
    "junos-syslog": [("udp", "514")],
    "junos-telnet": [("tcp", "23")],
    "junos-tftp": [("udp", "69")],
}

_PROTOCOL_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "51": "ah", "89": "ospf"}
_PORTED = ("tcp", "udp")
# ICMP types that a forwarding rule's plain ``icmp`` stands for (a ping).
_PING_TYPES = ("echo-request", "echo-reply", "8", "0")
_ESTABLISHED_FLAGS = ("(ack|rst)", "ack|rst", "(rst|ack)", "rst|ack", "established")
# Filter actions that end the evaluation, and those that only count, log or mark.
_TERMINATING = {"accept": "allow", "discard": "deny", "reject": "deny"}
_RESERVED_TABLES = re.compile(r"^__.*__$")


# ── Lines ───────────────────────────────────────────────────────────────────


def _split(line: str) -> list[str]:
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def _values(tokens: list[str]) -> list[str]:
    """The values at the start of ``tokens``: one, or a ``[ a b ]`` list."""
    if not tokens:
        return []
    if tokens[0] != "[":
        return [tokens[0]]
    found: list[str] = []
    for token in tokens[1:]:
        if token == "]":
            break
        found.append(token)
    return found


def _set_lines(text: str) -> tuple[list[list[str]], bool]:
    """The ``set`` statements of a configuration that are in effect (as token
    lists, ``set`` dropped), and whether the text is in the brace format."""
    statements: list[list[str]] = []
    inactive: list[list[str]] = []
    braces = False
    for raw in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if line.startswith("set "):
            statements.append(_split(line[4:]))
        elif line.startswith("deactivate "):
            inactive.append(_split(line[11:]))
        elif line.endswith("{") or line == "}":
            braces = True

    def active(tokens: list[str]) -> bool:
        return not any(tokens[: len(path)] == path for path in inactive if path)

    return [t for t in statements if t and active(t)], braces and not statements


# ── Ports, protocols, addresses ─────────────────────────────────────────────


def _port_number(token: str) -> int | None:
    if token.isdigit():
        value = int(token)
        return value if value <= 65535 else None
    return JUNOS_PORT_NAMES.get(token.lower())


def _port_range(token: str) -> tuple[int, int] | None:
    """``80``, ``http``, ``1024-65535``, ``ftp-data-ftp``: the range, or ``None``."""
    single = _port_number(token)
    if single is not None:
        return single, single
    for i, char in enumerate(token):
        if char == "-" and 0 < i < len(token) - 1:
            low, high = _port_number(token[:i]), _port_number(token[i + 1 :])
            if low is not None and high is not None:
                return min(low, high), max(low, high)
    return None


def _ports(values: list[str]) -> tuple[str, list[str]]:
    """``(expression, unresolved)`` of a list of port values."""
    parts: list[str] = []
    unresolved: list[str] = []
    for value in values:
        found = _port_range(value)
        if found is None:
            unresolved.append(f"port {value}")
        else:
            parts.append(str(found[0]) if found[0] == found[1] else f"{found[0]}-{found[1]}")
    if unresolved or not parts:
        return ANY, unresolved or ["ports"]
    if any(p in ("0-65535",) for p in parts):
        return ANY, []
    return ",".join(dict.fromkeys(parts)), []


def _except_ports(values: list[str]) -> tuple[str, list[str]]:
    """Every port but ``values``, as a port expression."""
    excluded: list[int] = []
    for value in values:
        found = _port_range(value)
        if found is None:
            return ANY, [f"port except {value}"]
        excluded.extend(range(found[0], found[1] + 1))
    return _complement(excluded) or "0", []


def _protocol(token: str) -> str:
    name = token.lower()
    return _PROTOCOL_NUMBERS.get(name, name)


def _range_cidrs(first: str, last: str) -> list[str]:
    try:
        low, high = ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)
        return [str(n) for n in ipaddress.summarize_address_range(low, high)]
    except TypeError, ValueError:
        return []


def _intersect(a: list[str], b: list[str]) -> list[str]:
    """The networks both CIDR lists (or ``any``) hold."""
    if a == [ANY]:
        return list(b)
    if b == [ANY]:
        return list(a)
    found: list[str] = []
    for x in a:
        for y in b:
            nx, ny = ipaddress.ip_network(x), ipaddress.ip_network(y)
            if nx.version != ny.version:
                continue
            if nx.subnet_of(ny):  # type: ignore[arg-type]
                found.append(x)
            elif ny.subnet_of(nx):  # type: ignore[arg-type]
                found.append(y)
    return list(dict.fromkeys(found))


# ── Address books and applications ──────────────────────────────────────────


@dataclass
class _Book:
    addresses: dict[str, tuple[list[str], list[str]]] = field(default_factory=dict)
    sets: dict[str, list[tuple[str, str]]] = field(default_factory=dict)


@dataclass
class _Application:
    # Per term: protocol, source ports values, destination ports values, unresolved.
    terms: dict[str, dict[str, Any]] = field(default_factory=dict)


Service = tuple[str, str, str, list[str]]  # protocol, source ports, destination ports, unresolved


class _Objects:
    """The address books, prefix lists and applications of a configuration."""

    def __init__(self) -> None:
        self.books: dict[str, _Book] = {}
        self.attached: dict[str, list[str]] = {}  # zone -> book names
        self.prefix_lists: dict[str, tuple[list[str], list[str]]] = {}
        self.applications: dict[str, _Application] = {}
        self.application_sets: dict[str, list[tuple[str, str]]] = {}

    def book(self, name: str) -> _Book:
        return self.books.setdefault(name, _Book())

    def read_book(self, book: _Book, rest: list[str]) -> None:
        """``address NAME A/len`` / ``range-address A to B`` / ``dns-name X``
        / ``wildcard-address A/M``, or ``address-set NAME address|address-set X``."""
        if len(rest) < 3:
            return
        kind, name, value = rest[0], rest[1], rest[2]
        if kind == "address":
            cidrs, unresolved = book.addresses.setdefault(name, ([], []))
            if value == "range-address" and len(rest) > 5 and rest[4] == "to":
                found = _range_cidrs(rest[3], rest[5])
                if found:
                    cidrs.extend(found)
                else:
                    unresolved.append(f"address {name} range {rest[3]} to {rest[5]}")
            elif value == "dns-name" and len(rest) > 3:
                unresolved.append(f"address {name} (DNS name {rest[3]})")
            elif value == "wildcard-address" and len(rest) > 3:
                unresolved.append(f"address {name} (wildcard {rest[3]})")
            elif value != "description" and canonical(value):
                cidrs.append(canonical(value))
        elif kind == "address-set" and value in ("address", "address-set") and len(rest) > 3:
            book.sets.setdefault(name, []).append((value, rest[3]))

    def address(self, name: str, zone: str = "", seen: frozenset[str] = frozenset()) -> tuple[list[str], list[str]]:
        """``(cidrs, unresolved)`` of an address or address set named in a
        policy whose zone is ``zone`` (``""``: the global book only)."""
        lowered = name.lower()
        if lowered in ("any", "any-ipv4"):
            return [ANY], []
        if lowered == "any-ipv6":
            return ["::/0"], []
        if canonical(name):
            return [canonical(name)], []
        books = [self.books[b] for b in self.attached.get(zone, []) if b in self.books] if zone else []
        if "global" in self.books:
            books.append(self.books["global"])
        for book in books:
            if name in book.addresses:
                cidrs, unresolved = book.addresses[name]
                return (list(cidrs) or [ANY], list(unresolved)) if unresolved else (list(cidrs), [])
            if name in book.sets and name not in seen:
                members: list[str] = []
                missing: list[str] = []
                for _kind, member in book.sets[name]:
                    found, more = self.address(member, zone, seen | {name})
                    members.extend(found)
                    missing.extend(more)
                if ANY in members:
                    members = [ANY]
                return list(dict.fromkeys(members)) or [ANY], missing
        return [ANY], [f"address {name} (not in the configuration)"]

    def addresses(self, names: list[str], zone: str = "") -> tuple[list[str], list[str]]:
        if not names:
            return [ANY], []
        cidrs: list[str] = []
        unresolved: list[str] = []
        for name in names:
            found, missing = self.address(name, zone)
            if missing:
                unresolved.extend(missing)
            else:
                cidrs.extend(found)
        if ANY in cidrs or not cidrs:
            cidrs = [ANY]
        return list(dict.fromkeys(cidrs)), unresolved

    def prefix_list(self, name: str) -> tuple[list[str], list[str]]:
        if name not in self.prefix_lists:
            return [ANY], [f"prefix-list {name} (not in the configuration)"]
        cidrs, unresolved = self.prefix_lists[name]
        if unresolved:
            return [ANY], [f"prefix-list {name} ({', '.join(unresolved)})"]
        return (list(cidrs), []) if cidrs else (["::/0"], [])

    def application(self, rest: list[str]) -> None:
        """``application NAME [term T] protocol|destination-port|... VALUE``."""
        if len(rest) < 3:
            return
        app = self.applications.setdefault(rest[0], _Application())
        term_name, words = "", rest[1:]
        if words[0] == "term" and len(words) > 2:
            term_name, words = words[1], words[2:]
        term = app.terms.setdefault(term_name, {"protocol": ANY, "src": [], "dst": [], "unresolved": []})
        key, values = words[0], _values(words[1:])
        if key == "protocol" and values:
            term["protocol"] = _protocol(values[0])
        elif key == "destination-port":
            term["dst"].extend(values)
        elif key == "source-port":
            term["src"].extend(values)
        elif key in ("icmp-type", "icmp-code", "icmp6-type"):
            if not all(v.lower() in _PING_TYPES for v in values) or key != "icmp-type":
                term["unresolved"].append(f"{key} {' '.join(values)}")
        elif key in ("rpc-program-number", "uuid", "ether-type"):
            term["unresolved"].append(f"{key} {' '.join(values)}")

    def services(self, name: str, seen: frozenset[str] = frozenset()) -> list[Service]:
        """The services of an application or application set."""
        lowered = name.lower()
        if lowered == "any":
            return [(ANY, ANY, ANY, [])]
        if name in self.applications:
            found: list[Service] = []
            for term in self.applications[name].terms.values():
                protocol = term["protocol"]
                unresolved = list(term["unresolved"])
                src, missing = _ports(term["src"]) if term["src"] else (ANY, [])
                unresolved += missing
                dst, missing = _ports(term["dst"]) if term["dst"] else (ANY, [])
                unresolved += missing
                found.append((protocol, src, dst, [f"application {name} {u}" for u in unresolved]))
            return found or [(ANY, ANY, ANY, [f"application {name} (no protocol)"])]
        if name in self.application_sets and name not in seen:
            found = []
            for _kind, member in self.application_sets[name]:
                found.extend(self.services(member, seen | {name}))
            return found or [(ANY, ANY, ANY, [f"application-set {name} (empty)"])]
        if lowered in JUNOS_APPLICATIONS:
            return [(protocol, ANY, ports, []) for protocol, ports in JUNOS_APPLICATIONS[lowered]]
        if lowered.startswith("junos-"):
            return [(ANY, ANY, ANY, [f"application {name} (a predefined application Plexus does not know)"])]
        return [(ANY, ANY, ANY, [f"application {name} (not in the configuration)"])]


# ── Firewall filters ────────────────────────────────────────────────────────


@dataclass
class _Term:
    name: str
    conditions: dict[str, list[str]] = field(default_factory=dict)
    unresolved: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)


@dataclass
class _Filter:
    terms: dict[str, _Term] = field(default_factory=dict)
    unresolved: list[str] = field(default_factory=list)


_FROM_KEYS = (
    "source-address",
    "destination-address",
    "address",
    "source-prefix-list",
    "destination-prefix-list",
    "prefix-list",
    "protocol",
    "source-port",
    "destination-port",
    "port",
    "source-port-except",
    "destination-port-except",
)


def _read_term(found: _Filter, words: list[str]) -> None:
    """``term T from KEY VALUE [except]`` or ``term T then ACTION ...``."""
    if len(words) < 2:
        return
    term = found.terms.setdefault(words[0], _Term(words[0]))
    rest = words[1:]
    if rest[0] == "from" and len(rest) > 1:
        key = rest[1]
        values = _values(rest[2:])
        trailing = rest[2 + (len(values) + 2 if rest[2:3] == ["["] else 1) :]
        if key == "tcp-established":
            term.conditions.setdefault("established", []).append("yes")
        elif key == "tcp-flags":
            flags = "".join(values).replace(" ", "").lower()
            if flags in _ESTABLISHED_FLAGS:
                term.conditions.setdefault("established", []).append("yes")
            else:
                term.unresolved.append(f"tcp-flags {' '.join(values)}")
        elif key in ("icmp-type", "icmp-code"):
            if key != "icmp-type" or not all(v.lower() in _PING_TYPES for v in values):
                term.unresolved.append(f"{key} {' '.join(values)}")
        elif key in _FROM_KEYS:
            if "except" in trailing:
                term.unresolved.append(f"{key} {' '.join(values)} except")
            else:
                term.conditions.setdefault(key, []).extend(values)
        else:
            term.unresolved.append(" ".join(rest[1:]))
    elif rest[0] == "then" and len(rest) > 1:
        action = rest[1]
        if action == "next" and rest[2:3] == ["term"]:
            term.actions.append("next term")
        elif action == "routing-instance" and len(rest) > 2:
            term.actions.append("accept")
            term.unresolved.append(f"routing-instance {rest[2]} (filter-based forwarding)")
        elif action in _TERMINATING:
            term.actions.append(action)
        elif action == "next" or action == "filter":
            term.unresolved.append(" ".join(rest[1:]))
    elif rest[0] in ("filter", "apply-groups"):
        term.unresolved.append(" ".join(rest))


def _term_entries(term: _Term, sequence: int, objects: _Objects, extra: list[str]) -> list[AclEntry]:
    """The entries of one filter term: one per combination of the sides its
    ``address`` / ``port`` matches take and the protocols it lists."""
    actions = [a for a in term.actions if a != "next term"]
    if "next term" in term.actions and not actions:
        return []
    action = _TERMINATING.get(actions[0], "allow") if actions else "allow"
    cond = term.conditions
    unresolved = list(extra) + list(term.unresolved)

    def side(addresses: str, prefix_lists: str) -> tuple[list[str], bool]:
        cidrs: list[str] = []
        listed = False
        for value in cond.get(addresses, []):
            listed = True
            if canonical(value):
                cidrs.append(canonical(value))
            else:
                unresolved.append(f"{addresses} {value}")
        for name in cond.get(prefix_lists, []):
            listed = True
            found, missing = objects.prefix_list(name)
            cidrs.extend(found)
            unresolved.extend(missing)
        return (list(dict.fromkeys(cidrs)) or [ANY]) if listed else [ANY], listed

    src, _ = side("source-address", "source-prefix-list")
    dst, _ = side("destination-address", "destination-prefix-list")
    either, has_either = side("address", "prefix-list")
    pairs = [(src, dst)]
    if has_either:
        pairs = [(_intersect(src, either), dst), (src, _intersect(dst, either))]
    pairs = [(s, d) for s, d in pairs if s and d]

    def ports(key: str, except_key: str) -> str:
        expression = ANY
        if cond.get(key):
            expression, missing = _ports(cond[key])
            unresolved.extend(missing)
        if cond.get(except_key):
            if expression != ANY:
                unresolved.append(f"{key} with {except_key}")
            expression, missing = _except_ports(cond[except_key])
            unresolved.extend(missing)
        return expression

    src_ports = ports("source-port", "source-port-except")
    dst_ports = ports("destination-port", "destination-port-except")
    port_pairs = [(src_ports, dst_ports)]
    if cond.get("port"):
        either_ports, missing = _ports(cond["port"])
        unresolved.extend(missing)
        if src_ports != ANY or dst_ports != ANY:
            unresolved.append("port with source-port or destination-port")
        port_pairs = [(either_ports, ANY), (ANY, either_ports)]
    ported = any(p != ANY for pair in port_pairs for p in pair)
    protocols = [_protocol(p) for p in cond.get("protocol", [])] or (list(_PORTED) if ported else [ANY])
    established = bool(cond.get("established"))
    entries: list[AclEntry] = []
    for protocol in dict.fromkeys(protocols):
        for s, d in pairs:
            for sp, dp in port_pairs:
                with_ports = protocol in _PORTED
                entries.append(
                    AclEntry(
                        sequence,
                        action,
                        protocol=protocol,
                        src=s,
                        src_ports=sp if with_ports else ANY,
                        dst=d,
                        dst_ports=dp if with_ports else ANY,
                        established=established and protocol in ("tcp", ANY),
                        name=term.name,
                        unresolved=list(dict.fromkeys(unresolved)),
                    )
                )
    return entries


def _filter_entries(found: _Filter, objects: _Objects) -> list[AclEntry]:
    entries: list[AclEntry] = []
    for position, term in enumerate(found.terms.values(), start=1):
        entries.extend(_term_entries(term, position, objects, found.unresolved))
    return entries


# ── Security policies ───────────────────────────────────────────────────────


@dataclass
class _Policy:
    name: str
    from_zones: list[str]
    to_zones: list[str]
    sources: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    applications: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    action: str = ""
    description: str = ""
    global_policy: bool = False


def _read_policy(policy: _Policy, rest: list[str], config: RunningConfig) -> None:
    if not rest:
        return
    head = rest[0]
    if head == "description" and len(rest) > 1:
        policy.description = rest[1]
    elif head == "scheduler-name" and len(rest) > 1:
        policy.unresolved.append(f"scheduler {rest[1]}")
    elif head == "then" and len(rest) > 1:
        if rest[1] in ("permit", "deny", "reject"):
            policy.action = policy.action or rest[1]
            if rest[1] == "permit" and len(rest) > 2:
                if rest[2] == "application-services":
                    _note(config, APPLICATION_SERVICES)
                elif rest[2] == "tunnel":
                    _note(config, IPSEC_VPNS)
    elif head == "match" and len(rest) > 2:
        key, values = rest[1], _values(rest[2:])
        if key == "source-address":
            policy.sources.extend(values)
        elif key == "destination-address":
            policy.destinations.extend(values)
        elif key == "application":
            policy.applications.extend(values)
        elif key == "from-zone":
            policy.from_zones.extend(v for v in values if v != "any")
        elif key == "to-zone":
            policy.to_zones.extend(v for v in values if v != "any")
        elif key in ("dynamic-application", "url-category", "source-identity", "source-end-user-profile"):
            if any(v.lower() not in ("any", "none") for v in values):
                policy.unresolved.append(f"{key} {' '.join(values)}")
        elif key in ("source-address-excluded", "destination-address-excluded"):
            policy.unresolved.append(f"{key} (negated)")
        else:
            policy.unresolved.append(" ".join(rest[1:]))


def _policy_entries(policy: _Policy, sequence: int, objects: _Objects) -> list[AclEntry]:
    src_zone = policy.from_zones[0] if len(policy.from_zones) == 1 else ""
    dst_zone = policy.to_zones[0] if len(policy.to_zones) == 1 else ""
    src, src_missing = objects.addresses(policy.sources, src_zone)
    dst, dst_missing = objects.addresses(policy.destinations, dst_zone)
    unresolved = [*policy.unresolved, *src_missing, *dst_missing]
    if not policy.action:
        unresolved.append("no then action")
    action = "allow" if policy.action == "permit" else "deny"
    services: list[Service] = []
    for name in policy.applications or [ANY]:
        services.extend(objects.services(name))
    return [
        AclEntry(
            sequence,
            action,
            protocol=protocol,
            src=src,
            src_ports=src_ports if protocol in _PORTED else ANY,
            dst=dst,
            dst_ports=dst_ports if protocol in _PORTED else ANY,
            comment=policy.description,
            unresolved=list(dict.fromkeys(unresolved + missing)),
            name=policy.name,
            src_zones=list(policy.from_zones),
            dst_zones=list(policy.to_zones),
        )
        for protocol, src_ports, dst_ports, missing in services
    ]


# ── NAT ─────────────────────────────────────────────────────────────────────


@dataclass
class _NatRule:
    name: str
    match: dict[str, list[str]] = field(default_factory=dict)
    then: list[str] = field(default_factory=list)


@dataclass
class _RuleSet:
    name: str
    context: dict[str, list[str]] = field(default_factory=dict)  # "from"/"to" -> [(kind, value)]
    rules: dict[str, _NatRule] = field(default_factory=dict)


class _Nat:
    # Source NAT rule-sets: an interface context is matched before a zone one,
    # and a zone one before a routing instance one.
    _CONTEXT_ORDER = {"interface": 0, "zone": 1, "routing-instance": 2}

    def __init__(self) -> None:
        self.sections: dict[str, dict[str, _RuleSet]] = {"static": {}, "destination": {}, "source": {}}
        self.pools: dict[str, dict[str, tuple[list[str], str]]] = {"source": {}, "destination": {}}

    def read(self, section: str, rest: list[str]) -> None:
        if section not in self.sections or len(rest) < 3:
            return
        if rest[0] == "pool" and section in self.pools:
            cidrs, port = self.pools[section].get(rest[1], ([], ""))
            words = rest[2:]
            if words[0] == "address" and len(words) > 1:
                if len(words) > 3 and words[2] == "to":
                    cidrs = cidrs + _range_cidrs(words[1].split("/")[0], words[3].split("/")[0])
                elif canonical(words[1]):
                    cidrs = [*cidrs, canonical(words[1])]
                if len(words) > 3 and words[2] == "port":
                    port = words[3]
            self.pools[section][rest[1]] = (cidrs, port)
            return
        if rest[0] != "rule-set":
            return
        rule_set = self.sections[section].setdefault(rest[1], _RuleSet(rest[1]))
        words = rest[2:]
        if words[0] in ("from", "to") and len(words) > 2:
            for value in _values(words[2:]):
                rule_set.context.setdefault(words[0], []).append(f"{words[1]} {value}")
        elif words[0] == "rule" and len(words) > 3:
            found = rule_set.rules.setdefault(words[1], _NatRule(words[1]))
            if words[2] == "match":
                found.match.setdefault(words[3], []).extend(words[4:] if words[4:5] != ["["] else _values(words[4:]))
            elif words[2] == "then" and not found.then:
                found.then = words[3:]

    def _addresses(self, rule: _NatRule, key: str, objects: _Objects) -> tuple[list[str], list[str]]:
        cidrs: list[str] = []
        unresolved: list[str] = []
        for value in rule.match.get(key, []):
            if canonical(value):
                cidrs.append(canonical(value))
            else:
                unresolved.append(f"{key} {value}")
        found, missing = objects.addresses(rule.match.get(f"{key}-name", []))
        if rule.match.get(f"{key}-name"):
            cidrs.extend(found)
        unresolved.extend(missing)
        return (list(dict.fromkeys(cidrs)) or [ANY]), unresolved

    def entries(self, objects: _Objects, notes: list[str]) -> list[dict[str, Any]]:
        """The NAT rules in the order an SRX applies them: static NAT (both
        ways), destination NAT, source NAT."""
        found: list[dict[str, Any]] = []
        index = 0

        def contexts(rule_set: _RuleSet, side: str) -> list[str] | None:
            values = rule_set.context.get(side, [])
            if any(v.startswith("routing-instance ") for v in values):
                return None
            return [v.split(" ", 1)[1] for v in values] or [""]

        sources: list[tuple[int, _RuleSet]] = []
        for rule_set in self.sections["source"].values():
            kinds = [v.split(" ", 1)[0] for v in rule_set.context.get("from", [])]
            sources.append((min((self._CONTEXT_ORDER.get(k, 1) for k in kinds), default=1), rule_set))
        ordered: list[tuple[str, _RuleSet]] = [
            *(("static", r) for r in self.sections["static"].values()),
            *(("destination", r) for r in self.sections["destination"].values()),
            *(("source", r) for _rank, r in sorted(sources, key=lambda pair: pair[0])),
        ]
        for section, rule_set in ordered:
            from_values = contexts(rule_set, "from")
            to_values = contexts(rule_set, "to") if section == "source" else [""]
            if from_values is None or to_values is None:
                notes.append(f"NAT rule-set {rule_set.name} (a routing instance context)")
                continue
            for rule in rule_set.rules.values():
                index += 1
                made = self._rule(section, rule_set, rule, objects, from_values, to_values, index)
                if made is None:
                    notes.append(
                        f"NAT rule {rule_set.name} {rule.name} (its addresses or translation are not all resolved)"
                    )
                    continue
                found.extend(made)
        return found

    def _rule(
        self,
        section: str,
        rule_set: _RuleSet,
        rule: _NatRule,
        objects: _Objects,
        from_values: list[str],
        to_values: list[str],
        index: int,
    ) -> list[dict[str, Any]] | None:
        original_src, src_missing = self._addresses(rule, "source-address", objects)
        original_dst, dst_missing = self._addresses(rule, "destination-address", objects)
        unknown = [m for m in rule.match if m not in _NAT_MATCHES]
        if src_missing or dst_missing or unknown or not rule.then:
            return None
        protocols = [_protocol(p) for p in rule.match.get("protocol", [])] or [ANY]
        port_values = rule.match.get("destination-port", [])
        original_port = ""
        if port_values:
            original_port = (
                f"{port_values[0]}-{port_values[2]}"
                if len(port_values) > 2 and port_values[1] == "to"
                else port_values[0]
            )
            if _port_range(original_port) is None:
                return None
        name = f"{section} rule-set {rule_set.name} rule {rule.name}"
        kind = f"{section}_nat"
        then = rule.then
        made: list[dict[str, Any]] = []
        for protocol in protocols:
            for src_if in from_values:
                if section == "static":
                    if then[:1] != ["static-nat"] or len(then) < 3 or then[1] not in ("prefix", "prefix-name"):
                        return None
                    if then[1] == "prefix":
                        mapped = [canonical(then[2])] if canonical(then[2]) else []
                    else:
                        mapped, missing = objects.addresses([then[2]])
                        mapped = [] if missing or mapped == [ANY] else mapped
                    if not mapped or original_dst == [ANY]:
                        return None
                    made.append(
                        nat(
                            index,
                            kind,
                            name=name,
                            original_src=original_src,
                            original_dst=original_dst,
                            translated_dst=mapped,
                            protocol=protocol,
                            src_interface=src_if,
                        )
                    )
                    # The other way: the mapped host leaves as the address it is reached by.
                    made.append(
                        nat(
                            index,
                            kind,
                            name=f"{name} (reverse)",
                            original_src=mapped,
                            translated_src=original_dst,
                            protocol=protocol,
                            dst_interface=src_if,
                        )
                    )
                elif section == "destination":
                    if then[:1] != ["destination-nat"] or len(then) < 2:
                        return None
                    if then[1] == "off":
                        translated, port = list(original_dst), ""
                    elif then[1] == "pool" and len(then) > 2 and then[2] in self.pools["destination"]:
                        translated, port = self.pools["destination"][then[2]]
                        if not translated:
                            return None
                    else:
                        return None
                    made.append(
                        nat(
                            index,
                            kind,
                            name=name,
                            original_src=original_src,
                            original_dst=original_dst,
                            translated_dst=translated,
                            protocol=protocol,
                            original_port=original_port,
                            translated_port=port,
                            src_interface=src_if,
                        )
                    )
                else:
                    if then[:1] != ["source-nat"] or len(then) < 2:
                        return None
                    if then[1] == "interface":
                        translated = [INTERFACE]
                    elif then[1] == "off":
                        translated = list(original_src)
                    elif then[1] == "pool" and len(then) > 2 and then[2] in self.pools["source"]:
                        translated = self.pools["source"][then[2]][0]
                        if not translated:
                            return None
                    else:
                        return None
                    for dst_if in to_values:
                        made.append(
                            nat(
                                index,
                                kind,
                                name=name,
                                original_src=original_src,
                                original_dst=original_dst,
                                translated_src=translated,
                                protocol=protocol,
                                original_port=original_port,
                                src_interface=src_if,
                                dst_interface=dst_if,
                            )
                        )
        return made


_NAT_MATCHES = (
    "source-address",
    "source-address-name",
    "destination-address",
    "destination-address-name",
    "destination-port",
    "protocol",
)


# ── The configuration ───────────────────────────────────────────────────────


@dataclass
class _Static:
    prefix: str
    vrf: str
    next_hops: list[str] = field(default_factory=list)
    qualified: list[tuple[str, int | None]] = field(default_factory=list)
    blackhole: str = ""
    preference: int | None = None
    next_table: str = ""


class _Reader:
    def __init__(self) -> None:
        self.config = RunningConfig(stateful=False)
        self.units: dict[str, ConfigInterface] = {}
        self.disabled: set[str] = set()
        self.descriptions: dict[str, str] = {}
        self.primary: set[str] = set()
        self.bindings: dict[str, dict[str, list[str]]] = {}
        self.filters: dict[str, _Filter] = {}
        self.objects = _Objects()
        self.statics: dict[tuple[str, str], _Static] = {}
        self.policies: list[_Policy] = []
        self.policy_index: dict[tuple[str, ...], _Policy] = {}
        self.has_zones = False
        self.default_policy = "deny"
        self.nat = _Nat()

    # Interfaces

    def unit(self, name: str) -> ConfigInterface:
        if name not in self.units:
            self.units[name] = ConfigInterface(name)
        return self.units[name]

    def interface(self, tokens: list[str]) -> None:
        if len(tokens) < 3:
            return
        physical, rest = tokens[1], tokens[2:]
        if physical == "interface-range":
            _note(self.config, INTERFACE_RANGES)
            return
        if rest[0] == "apply-groups" or (len(rest) > 2 and rest[2] == "apply-groups"):
            _note(self.config, GROUPS)
        if rest[0] == "disable":
            self.disabled.add(physical)
        elif rest[0] == "description" and len(rest) > 1:
            self.descriptions[physical] = rest[1]
        elif rest[0] == "unit" and len(rest) > 2:
            self.unit_line(f"{physical}.{rest[1]}", rest[2:])

    def unit_line(self, name: str, rest: list[str]) -> None:
        unit = self.unit(name)
        if rest[0] == "disable":
            unit.shutdown = True
        elif rest[0] == "description" and len(rest) > 1:
            unit.description = rest[1]
        elif rest[0] == "family" and len(rest) > 2:
            family, words = rest[1], rest[2:]
            if family == "inet6" and words[0] == "filter":
                _note(self.config, IPV6_FILTERS)
            elif family in ("ethernet-switching", "bridge", "any") and words[0] == "filter":
                _note(self.config, OTHER_FILTERS)
            elif family == "inet":
                self.inet(unit, words)

    def inet(self, unit: ConfigInterface, words: list[str]) -> None:
        if words[0] == "address" and len(words) > 1 and "/" in words[1]:
            address, network = words[1].split("/", 1)[0], canonical(words[1])
            if not is_address(address) or not network:
                return
            pair = (address, network)
            if pair not in unit.addresses:
                unit.addresses.append(pair)
            more = words[2:]
            if more[:1] in (["primary"], ["preferred"]) and unit.name not in self.primary:
                unit.addresses.remove(pair)
                unit.addresses.insert(0, pair)
                self.primary.add(unit.name)
            if more[:1] == ["vrrp-group"] and len(more) > 3 and more[2] == "virtual-address":
                for virtual in _values(more[3:]):
                    add_virtual(unit, "VRRP", more[1], virtual)
        elif words[0] == "filter" and len(words) > 2:
            direction = {"input": "in", "output": "out", "input-list": "in", "output-list": "out"}.get(words[1])
            if direction:
                found = self.bindings.setdefault(unit.name, {}).setdefault(direction, [])
                for value in _values(words[2:]):
                    if value not in found:
                        found.append(value)

    # Routing

    def static(self, rest: list[str], vrf: str) -> None:
        """``static route P next-hop NH | discard | reject | qualified-next-hop
        NH [preference N] | preference N | next-table T`` (after ``routing-options``)."""
        if rest[:1] == ["rib"] and len(rest) > 1:
            if not re.match(r"^(.*\.)?inet\.0$", rest[1]):
                return
            rest = rest[2:]
        if rest[:2] != ["static", "route"] or len(rest) < 4:
            return
        prefix = canonical(rest[2])
        if not prefix or ":" in prefix:
            return
        found = self.statics.setdefault((vrf, prefix), _Static(prefix, vrf))
        words = rest[3:]
        head = words[0]
        if head == "next-hop" and len(words) > 1:
            found.next_hops.extend(v for v in _values(words[1:]) if v not in found.next_hops)
        elif head in ("discard", "reject"):
            found.blackhole = head
        elif head == "qualified-next-hop" and len(words) > 1:
            preference = (
                int(words[3]) if words[2:3] == ["preference"] and len(words) > 3 and words[3].isdigit() else None
            )
            if all(nh != words[1] for nh, _p in found.qualified):
                found.qualified.append((words[1], preference))
            elif preference is not None:
                found.qualified = [(nh, preference if nh == words[1] else p) for nh, p in found.qualified]
        elif head == "preference" and len(words) > 1 and words[1].isdigit():
            found.preference = int(words[1])
        elif head == "next-table" and len(words) > 1:
            found.next_table = words[1]

    def protocol(self, name: str) -> None:
        display = ROUTING_PROTOCOLS.get({"ospf3": "ospfv3"}.get(name, name))
        if display and display not in self.config.routing:
            self.config.routing.append(display)

    def routing_instance(self, tokens: list[str]) -> None:
        if len(tokens) < 4:
            return
        instance, rest = tokens[1], tokens[2:]
        if rest[0] == "interface":
            self.unit(rest[1] if "." in rest[1] else f"{rest[1]}.0").vrf = instance
        elif rest[0] == "routing-options":
            self.static(rest[1:], instance)
        elif rest[0] == "protocols":
            self.protocol(rest[1])

    # Firewall

    def firewall(self, tokens: list[str]) -> None:
        rest = tokens[1:]
        if rest[:1] == ["family"] and len(rest) > 1:
            family, rest = rest[1], rest[2:]
            if family == "inet6":
                _note(self.config, IPV6_FILTERS)
                return
            if family != "inet":
                _note(self.config, OTHER_FILTERS)
                return
        if rest[:1] != ["filter"] or len(rest) < 3:
            return
        found = self.filters.setdefault(rest[1], _Filter())
        words = rest[2:]
        if words[0] == "term":
            _read_term(found, words[1:])
        elif words[0] == "apply-groups":
            _note(self.config, GROUPS)
            found.unresolved.append(f"apply-groups {' '.join(words[1:])}")

    def prefix_list(self, tokens: list[str]) -> None:
        if len(tokens) < 3 or tokens[1] != "prefix-list":
            return
        cidrs, unresolved = self.objects.prefix_lists.setdefault(tokens[2], ([], []))
        if len(tokens) > 3:
            if tokens[3] == "apply-path":
                unresolved.append("apply-path")
            elif canonical(tokens[3]):
                cidrs.append(canonical(tokens[3]))

    # Security

    def security(self, tokens: list[str]) -> None:
        if len(tokens) < 2:
            return
        section, rest = tokens[1], tokens[2:]
        if section == "zones":
            self.zone(rest)
        elif section == "address-book" and len(rest) > 1:
            if rest[1] == "attach" and len(rest) > 3 and rest[2] == "zone":
                self.objects.attached.setdefault(rest[3], []).append(rest[0])
            else:
                self.objects.read_book(self.objects.book(rest[0]), rest[1:])
        elif section == "policies":
            self.policy(rest)
        elif section == "nat" and rest:
            self.nat.read(rest[0], rest[1:])
        elif section == "screen":
            _note(self.config, SCREENS)
        elif section in ("ike", "ipsec"):
            _note(self.config, IPSEC_VPNS)

    def zone(self, rest: list[str]) -> None:
        if len(rest) < 3 or rest[0] not in ("security-zone", "functional-zone"):
            return
        self.has_zones = True
        name, words = rest[1], rest[2:]
        if words[0] == "interfaces" and len(words) > 1:
            self.unit(words[1] if "." in words[1] else f"{words[1]}.0").zone = name
        elif words[0] == "address-book" and len(words) > 1:
            book = f"zone {name}"
            if book not in self.objects.attached.get(name, []):
                self.objects.attached.setdefault(name, []).append(book)
            self.objects.read_book(self.objects.book(book), words[1:])
        elif words[0] == "screen":
            _note(self.config, SCREENS)

    def policy(self, rest: list[str]) -> None:
        if rest[:1] == ["default-policy"] and len(rest) > 1:
            self.default_policy = "allow" if rest[1] == "permit-all" else "deny"
            return
        if rest[:1] == ["from-zone"] and len(rest) > 5 and rest[2] == "to-zone" and rest[4] == "policy":
            key: tuple[str, ...] = (rest[1], rest[3], rest[5])
            words = rest[6:]
            if key not in self.policy_index:
                self.policy_index[key] = _Policy(rest[5], [rest[1]], [rest[3]])
                self.policies.append(self.policy_index[key])
        elif rest[:2] == ["global", "policy"] and len(rest) > 2:
            key = ("", "", rest[2])
            words = rest[3:]
            if key not in self.policy_index:
                self.policy_index[key] = _Policy(rest[2], [], [], global_policy=True)
                self.policies.append(self.policy_index[key])
        else:
            return
        _read_policy(self.policy_index[key], words, self.config)

    def applications(self, tokens: list[str]) -> None:
        if len(tokens) < 4:
            return
        if tokens[1] == "application":
            self.objects.application(tokens[2:])
        elif tokens[1] == "application-set" and tokens[3] in ("application", "application-set") and len(tokens) > 4:
            self.objects.application_sets.setdefault(tokens[2], []).append((tokens[3], tokens[4]))

    # The result

    def read(self, statements: list[list[str]]) -> None:
        for tokens in statements:
            head = tokens[0]
            if head == "interfaces":
                self.interface(tokens)
            elif head == "routing-options":
                self.static(tokens[1:], "")
            elif head == "routing-instances":
                self.routing_instance(tokens)
            elif head == "protocols" and len(tokens) > 1:
                self.protocol(tokens[1])
            elif head == "firewall":
                self.firewall(tokens)
            elif head == "policy-options":
                self.prefix_list(tokens)
            elif head == "security":
                self.security(tokens)
            elif head == "applications":
                self.applications(tokens)
            elif head == "apply-groups":
                _note(self.config, GROUPS)
            elif head == "logical-systems":
                _note(self.config, LOGICAL_SYSTEMS)

    def finish(self) -> RunningConfig:
        config = self.config
        for name, unit in self.units.items():
            physical = name.rsplit(".", 1)[0]
            if physical in self.disabled:
                unit.shutdown = True
            if not unit.description and physical in self.descriptions:
                unit.description = self.descriptions[physical]
            config.interfaces.append(unit)
        for name, found in self.filters.items():
            config.access_lists[name] = _filter_entries(found, self.objects)
        for name, directions in self.bindings.items():
            for direction, filters in directions.items():
                self.units[name].access_groups[direction] = self._bound(filters)
        for static in self.statics.values():
            config.static_routes.extend(self._routes(static))
        if self.has_zones or self.policies:
            entries: list[AclEntry] = []
            ordered = [p for p in self.policies if not p.global_policy] + [p for p in self.policies if p.global_policy]
            for position, policy in enumerate(ordered, start=1):
                entries.extend(_policy_entries(policy, position, self.objects))
            config.policies.append(ConfigPolicy(SECURITY_POLICIES, entries, default=self.default_policy))
        config.nat = self.nat.entries(self.objects, config.notes)
        return config

    def _bound(self, filters: list[str]) -> str:
        """The access list a filter or filter list binds: a list is the filters
        one after the other, ending in the last one's discard."""
        if len(filters) == 1:
            return filters[0]
        name = " + ".join(filters)
        combined: list[AclEntry] = []
        for filter_name in filters:
            offset = max((e.sequence or 0 for e in combined), default=0)
            entries = self.config.access_lists.get(filter_name)
            if not entries:
                missing = f"filter {filter_name} (not in the configuration)"
                combined.append(AclEntry(offset + 1, "allow", unresolved=[missing], name=filter_name))
                continue
            combined.extend(replace(e, sequence=(e.sequence or 0) + offset) for e in entries)
        self.config.access_lists[name] = combined
        return name

    @staticmethod
    def _routes(static: _Static) -> list[StaticRoute]:
        if static.next_table:
            return []
        if static.blackhole:
            # route_entry takes a route to a null interface as a blackhole.
            return [StaticRoute(static.prefix, interface=f"null ({static.blackhole})", vrf=static.vrf)]
        routes = []
        for hop, preference in [*((nh, static.preference) for nh in static.next_hops), *static.qualified]:
            address = is_address(hop)
            routes.append(
                StaticRoute(
                    static.prefix,
                    next_hop=hop if address else "",
                    interface="" if address else hop,
                    vrf=static.vrf,
                    distance=preference if preference is not None else static.preference,
                )
            )
        return routes


def parse_config(text: str) -> RunningConfig:
    """What a Juniper Junos configuration (``show configuration | display
    set``) says about forwarding: interfaces, firewall filters, SRX zones,
    security policies and NAT, static routes, routing protocols."""
    statements, hierarchical = _set_lines(text)
    if hierarchical:
        config = RunningConfig(stateful=False)
        _note(config, HIERARCHICAL)
        return config
    reader = _Reader()
    reader.read(statements)
    config = reader.finish()
    for static in reader.statics.values():
        if static.next_table:
            _note(config, f"Static route to {static.prefix} (next table {static.next_table})")
    return config


# ── show route ──────────────────────────────────────────────────────────────

_TABLE = re.compile(r"^(?P<table>\S+): \d+ destinations?, \d+ routes?")
_ROUTE = re.compile(
    r"^(?P<prefix>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)?\s+(?P<mark>[*+-]?)\[(?P<protocol>[A-Za-z-]+)/(?P<preference>\d+)\](?P<rest>.*)$"
)
_NEXT_HOP = re.compile(r"^\s+(?P<selected>>)?\s*(?:to\s+(?P<hop>\S+)\s+)?via\s+(?P<iface>[^\s,]+)")
_LOCAL = re.compile(r"^\s+Local via (?P<iface>[^\s,]+)")
_BLACKHOLE = re.compile(r"^\s+>?\s*(?P<kind>Discard|Reject|Receive)\b")
_METRIC = re.compile(r"\bmetric (\d+)")
_PROTOCOL_SOURCES = {"ospf": "OSPF", "ospf3": "OSPFv3", "bgp": "BGP", "is-is": "IS-IS", "rip": "RIP"}


def _table_vrf(table: str) -> str | None:
    """The routing instance of a ``show route`` table (``""``: the global
    one), or ``None`` for a table that holds no IPv4 unicast routes."""
    if table == "inet.0":
        return ""
    if table.endswith(".inet.0"):
        instance = table[: -len(".inet.0")]
        return None if _RESERVED_TABLES.match(instance) else vrf_name(instance)
    return None


def _route_kind(protocol: str) -> tuple[str, str]:
    name = protocol.lower()
    if name == "direct":
        return "connected", "Connected"
    if name == "local":
        return "connected", LOCAL
    if name == "static":
        return "static", "Static route"
    return "dynamic", _PROTOCOL_SOURCES.get(name, protocol)


def parse_routes(lines: list[str]) -> list[dict]:
    """The active routes of a Junos ``show route`` capture, in ``inet.0``
    and every routing instance's ``<instance>.inet.0``: the next hops ``>``
    marks (all of them when none is marked), a discard or reject route as a
    blackhole."""
    routes: list[dict] = []
    vrf: str | None = None
    prefix = ""
    current: dict[str, Any] | None = None
    hops: list[tuple[bool, dict]] = []

    def flush() -> None:
        if current is not None and hops:
            selected = [r for chosen, r in hops if chosen]
            routes.extend(selected or [r for _chosen, r in hops])
        hops.clear()

    for line in lines:
        table = _TABLE.match(line)
        if table:
            flush()
            vrf, prefix, current = _table_vrf(table.group("table")), "", None
            continue
        if vrf is None:
            continue
        found = _ROUTE.match(line)
        if found:
            # A destination's first route names it; its other routes follow, indented.
            flush()
            if found.group("prefix"):
                prefix = canonical(found.group("prefix"))
            current = None
            if prefix and found.group("mark") in ("*", "+"):
                kind, source = _route_kind(found.group("protocol"))
                metric = _METRIC.search(found.group("rest"))
                current = {
                    "kind": kind,
                    "source": source,
                    "metric": int(metric.group(1)) if metric else int(found.group("preference")),
                }
            continue
        if current is None:
            continue
        blackhole = _BLACKHOLE.match(line)
        local = _LOCAL.match(line)
        hop = _NEXT_HOP.match(line)
        if blackhole and blackhole.group("kind") != "Receive":
            hops.append(
                (
                    True,
                    route_entry(prefix, "blackhole", vrf=vrf, metric=current["metric"], source=current["source"]),
                )
            )
        elif local:
            hops.append((False, route_entry(prefix, "connected", iface=local.group("iface"), vrf=vrf, source=LOCAL)))
        elif hop:
            kind = current["kind"]
            hops.append(
                (
                    bool(hop.group("selected")),
                    route_entry(
                        prefix,
                        kind,
                        next_hop="" if kind == "connected" else hop.group("hop") or "",
                        iface=hop.group("iface"),
                        vrf=vrf,
                        metric=current["metric"],
                        source=current["source"],
                    ),
                )
            )
    flush()
    return routes
