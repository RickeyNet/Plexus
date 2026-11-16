"""The configuration of an OPNsense firewall (``config.xml``), read for path
tracing and for the firewall's rule views.

The OPNsense collection stores the firewall's ``config.xml`` as a
configuration backup of its inventory host
(``netcontrol.routes.opnsense_collection``). ``parse_document`` reads it into
an ``OpnsenseConfig``: the interfaces, interface groups, aliases, filter
rules in evaluation order, NAT (port forwards, outbound NAT, 1:1), gateways
and static routes, each resolved as far as the configuration allows.
``parse_config`` turns that into the ``RunningConfig`` every platform's
parser returns, for the forwarding block of the inventory host
(``inventory.forwarding_for_host``); ``netcontrol.integrations.opnsense.rules``
builds the rule views from the same ``OpnsenseConfig``.

What is read:

- the interfaces (``<interfaces>``: ``wan``, ``lan``, ``optN``) with their
  device (``<if>``), description, static IPv4 / IPv6 address, state and
  whether they are upstream (a gateway on the interface, or ``wan``); each
  interface's ``zone`` is its key (``lan``), the name its rules bind to.
  VLAN devices (``<vlans>``) describe the interface that uses them; CARP
  and IP alias virtual IPs (``<virtualip>``) are virtual and secondary
  addresses;
- the aliases, of the MVC model (``<OPNsense><Firewall><Alias><aliases>``,
  OPNsense 18.1+) and the legacy ``<aliases>``: host, network, network group
  and port aliases resolve to addresses and ports (nested aliases too); URL
  tables, GeoIP, MAC, ASN, dynamic IPv6, OpenVPN group and external aliases
  and host names hold addresses only the firewall knows, so a rule that
  names one is unresolved (a flow it may match is unknown);
- the filter rules: the MVC rules (``<OPNsense><Firewall><Filter><rules>``,
  the automation / new rules model) first by their sequence, then the
  legacy ``<filter><rule>`` rules, floating ones first, then those of
  interface groups, then those of each interface, each in configuration
  order (the order OPNsense writes them into pf). Per interface and
  direction pf takes the first matching ``quick`` rule, else the last
  matching rule without ``quick`` (floating rules without ``quick``), else
  the default ``block in``; so each interface's access list holds its
  quick rules in order, then its other rules in reverse order, then the
  default block. Outbound rules (floating ones with direction ``out`` or
  any) make an ``out`` list that ends in OPNsense's default ``pass out``.
  The source and destination take ``any``, an address, network or range,
  an alias, an interface's network (``lan``) or address (``lanip``) and
  ``(self)``; a negated one (``<not>``) is unresolved. ``ipprotocol``
  limits a rule to IPv4 or IPv6. Schedules, OS fingerprints, tags and ICMP
  types other than echo are unresolved; a rule's gateway (policy-based
  routing) is a note. Disabled rules are kept, disabled;
- the system rules OPNsense puts before them: the anti-lockout rule on
  ``lan`` and ``Block private networks`` on an interface that sets it;
  ``Block bogon networks`` is a note (the bogon table is downloaded);
- NAT in the forwarding ``nat`` shape: 1:1 NAT (``<nat><onetoone>``, and the
  MVC ``onetoone`` rules) as static NAT both ways, port forwards
  (``<nat><rule>``) as destination NAT from their interfaces (a port forward
  whose filter rule is ``pass`` lets its translated flow in itself, so it
  is an allow entry at the top of its interface's list), then source NAT:
  the MVC source NAT rules, the manual outbound rules (``<nat><outbound>``,
  ``hybrid`` and ``advanced`` mode) and, in ``automatic`` and ``hybrid``
  mode, the automatic rules: the networks of every other interface leave an
  upstream interface as its address;
- the gateways (``<gateways>`` and the MVC ``<OPNsense><Gateways>``), the
  static routes (``<staticroutes>``) with their gateway resolved to its
  address and interface, and the default route (the default gateway, else
  the upstream gateway of lowest priority of each family). Dynamic routing
  (the FRR plugin) is listed by protocol; IPsec, OpenVPN and WireGuard and
  the rules of their interfaces are notes.

Nothing here talks to the firewall. Uses the standard library only.

Pure (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field

from netcontrol.integrations.meraki.forwarding import ANY, INTERFACE, canonical, is_address, nat
from netcontrol.integrations.pathtrace.device_config import (
    AclEntry,
    ConfigInterface,
    RunningConfig,
    StaticRoute,
    VirtualAddress,
)
from netcontrol.integrations.pathtrace.ios_config import ROUTING_PROTOCOLS, add_note as _note

__all__ = [
    "AUTOMATIC_NAT",
    "BOGONS",
    "DEFAULT_DENY",
    "DEFAULT_PASS_OUT",
    "IPSEC",
    "OPENVPN",
    "POLICY_ROUTES",
    "WIREGUARD",
    "Alias",
    "Endpoint",
    "FilterRule",
    "Gateway",
    "Interface",
    "OneToOne",
    "OpnsenseConfig",
    "OutboundRule",
    "PortForward",
    "Route",
    "evaluation_order",
    "parse_config",
    "parse_document",
    "parse_xml",
    "rule_bindings",
]

# Notes (not collected) and the names of the entries OPNsense adds itself.
IPSEC = "IPsec VPN tunnels"
OPENVPN = "OpenVPN tunnels"
WIREGUARD = "WireGuard tunnels"
POLICY_ROUTES = "Policy-based routes (firewall rules with a gateway)"
BOGONS = "Block bogon networks (the downloaded bogon table)"
AUTOMATIC_NAT = "Automatic outbound NAT"
DEFAULT_DENY = "Default deny rule"
DEFAULT_PASS_OUT = "Default pass out rule"
ANTI_LOCKOUT = "Anti-lockout rule"
BLOCK_PRIVATE = "Block private networks"

# The tiers of filter rules, in the order pf evaluates them.
TIERS = ("automation", "floating", "group", "interface")
# The interfaces (groups) OPNsense gives the rules of its VPNs.
_VPN_ZONES = {"enc0": IPSEC, "ipsec": IPSEC, "openvpn": OPENVPN, "wireguard": WIREGUARD}
# Aliases OPNsense defines itself (their tables are filled by the firewall).
_BUILTIN_ALIASES = ("bogons", "bogonsv6", "virusprot", "sshlockout", "__")
# Alias types that resolve to addresses or ports.
_ADDRESS_ALIASES = ("host", "network", "networkgroup")
_PORT_ALIAS = "port"
# RFC 1918 and unique local addresses: what ``Block private networks`` blocks.
_PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
_DEFAULT_ROUTES = {"inet": "0.0.0.0/0", "inet6": "::/0"}
_V4_ANY, _V6_ANY = "0.0.0.0/0", "::/0"
_PORT_NAMES = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "dns": 53,
    "http": 80,
    "www": 80,
    "pop3": 110,
    "ntp": 123,
    "imap": 143,
    "snmp": 161,
    "ldap": 389,
    "https": 443,
    "smtps": 465,
    "submission": 587,
    "ldaps": 636,
    "imaps": 993,
    "pop3s": 995,
    "openvpn": 1194,
    "ms-sql-s": 1433,
    "mysql": 3306,
    "rdp": 3389,
    "ms-wbt-server": 3389,
}
# ICMP types that are the echo request a trace asks about (or any).
_ECHO_TYPES = ("", "any", "echoreq", "8", "echo-request")
_PORT = re.compile(r"^(\d+)(?:\s*[-:]\s*(\d+))?$")
_FQDN = re.compile(r"^(?=.*[a-z])[a-z0-9-]+(\.[a-z0-9-]+)+\.?$", re.IGNORECASE)
_TRUE = ("1", "yes", "on", "true", "enabled")


# ── XML ──────────────────────────────────────────────────────────────────────


def parse_xml(text: str) -> ElementTree.Element | None:
    """The root element of an OPNsense ``config.xml``; ``None`` when the text
    is not one. A document type declaration (and so any entity declaration)
    is refused: ``config.xml`` never has one."""
    raw = str(text or "")
    start = raw.find("<opnsense")
    if start < 0:
        return None
    prolog = raw[:start].lower()
    if "<!doctype" in prolog or "<!entity" in prolog:
        return None
    try:
        # A stored backup Plexus downloaded; DTDs refused above, and expat
        # expands no external entities.
        root = ElementTree.fromstring(raw)  # nosec B314
    except ElementTree.ParseError:
        return None
    return root if root.tag == "opnsense" else None


def _text(element: ElementTree.Element | None, path: str) -> str:
    if element is None:
        return ""
    found = element.find(path)
    return (found.text or "").strip() if found is not None else ""


def _flag(element: ElementTree.Element | None, path: str) -> bool:
    """A flag element: set when present and not ``0`` / ``no`` (``<disabled/>``
    and ``<disabled>1</disabled>`` are both set)."""
    if element is None:
        return False
    found = element.find(path)
    if found is None:
        return False
    return (found.text or "").strip().lower() not in ("0", "no", "off", "false")


def _on(element: ElementTree.Element | None, path: str, default: bool = False) -> bool:
    """An MVC boolean field (``1`` / ``0``), ``default`` when absent or empty."""
    value = _text(element, path).lower()
    return default if not value else value in _TRUE


def _all(root: ElementTree.Element, *paths: str) -> list[ElementTree.Element]:
    return [found for path in paths for found in root.findall(path)]


def _split(value: str, separators: str = ",") -> list[str]:
    return [part.strip() for part in re.split(f"[{re.escape(separators)}]", value or "") if part.strip()]


def _uuid(element: ElementTree.Element) -> str:
    return str(element.get("uuid") or "").strip()


# ── The model ────────────────────────────────────────────────────────────────


@dataclass
class Interface:
    key: str  # lan, wan, opt1...
    device: str  # igb1, vlan0.10...
    description: str = ""
    enabled: bool = True
    ipv4: tuple[str, str] | None = None  # (address, network)
    ipv6: tuple[str, str] | None = None
    dynamic: list[str] = field(default_factory=list)  # "dhcp", "pppoe", "dhcp6", "track6"...
    gateway: str = ""  # the IPv4 gateway the interface names (an upstream interface)
    gateway6: str = ""
    upstream: bool = False
    virtual: list[tuple[str, str, str, str]] = field(default_factory=list)  # (address, network, mode, vhid)
    block_private: bool = False
    block_bogons: bool = False

    def networks(self, family: str = "") -> list[str]:
        found = [pair[1] for pair in (self.ipv4, self.ipv6) if pair is not None]
        found += [network for _a, network, mode, _v in self.virtual if mode == "ipalias" and network]
        return _family_filter(list(dict.fromkeys(found)), family) if family else list(dict.fromkeys(found))

    def addresses(self) -> list[str]:
        found = [pair[0] for pair in (self.ipv4, self.ipv6) if pair is not None]
        found += [address for address, _n, _m, _v in self.virtual]
        return [canonical(a) for a in dict.fromkeys(found) if canonical(a)]


@dataclass
class Alias:
    name: str
    type: str
    content: list[str]
    description: str = ""
    enabled: bool = True
    uuid: str = ""


@dataclass
class Endpoint:
    """The source or destination of a rule, as configured and resolved."""

    text: str = "any"  # how the configuration names it ("lan net", "WebServers")
    port_text: str = ""
    any: bool = True
    negate: bool = False
    # Resolved addresses ([ANY] for any, and when something is unresolved).
    cidrs: list[str] = field(default_factory=lambda: [ANY])
    # Port ranges (None: any port).
    ports: list[tuple[int, int]] | None = None
    aliases: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    @property
    def port_expression(self) -> str:
        return _port_expression(self.ports)


@dataclass
class FilterRule:
    number: int  # the rule's place in evaluation order, 1-based
    key: str  # the rule's uuid, else a key of what it matches
    uuid: str
    tier: str  # automation, floating, group, interface
    action: str  # pass, block, reject
    interfaces: list[str]  # interface keys or groups as configured; [] every interface
    direction: str  # in, out, any
    family: str  # inet, inet6, inet46
    protocol: str  # any, tcp, udp, tcp/udp, icmp...
    quick: bool
    disabled: bool
    description: str
    source: Endpoint
    destination: Endpoint
    gateway: str = ""
    log: bool = False
    unresolved: list[str] = field(default_factory=list)


@dataclass
class PortForward:
    key: str
    uuid: str
    interfaces: list[str]
    protocol: str
    family: str
    source: Endpoint
    destination: Endpoint
    target: str
    target_cidrs: list[str]
    local_port: str
    disabled: bool
    no_redirect: bool
    description: str
    filter_rule: str  # "pass": the redirect passes the flow itself; else the linked rule's id or ""
    unresolved: list[str] = field(default_factory=list)


@dataclass
class OutboundRule:
    key: str
    uuid: str
    origin: str  # "manual" (<nat><outbound>) or "automation" (MVC source NAT)
    interface: str
    protocol: str
    family: str
    source: Endpoint
    destination: Endpoint
    target: str
    target_cidrs: list[str]
    no_nat: bool
    disabled: bool
    description: str
    unresolved: list[str] = field(default_factory=list)


@dataclass
class OneToOne:
    key: str
    uuid: str
    interface: str
    external: str
    source: Endpoint
    destination: Endpoint
    type: str  # binat or nat
    disabled: bool
    description: str


@dataclass
class Gateway:
    name: str
    interface: str
    address: str  # "" for a dynamic gateway
    family: str
    default: bool = False
    disabled: bool = False
    priority: int = 255
    upstream: bool = False
    description: str = ""


@dataclass
class Route:
    network: str
    gateway: str
    disabled: bool = False
    description: str = ""
    uuid: str = ""


@dataclass
class OpnsenseConfig:
    hostname: str = ""
    interfaces: dict[str, Interface] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)
    aliases: dict[str, Alias] = field(default_factory=dict)
    rules: list[FilterRule] = field(default_factory=list)
    port_forwards: list[PortForward] = field(default_factory=list)
    outbound_mode: str = "automatic"
    outbound: list[OutboundRule] = field(default_factory=list)
    one_to_one: list[OneToOne] = field(default_factory=list)
    gateways: dict[str, Gateway] = field(default_factory=dict)
    routes: list[Route] = field(default_factory=list)
    anti_lockout: list[int] = field(default_factory=list)  # its ports; [] when disabled
    routing: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def zones(self, names: list[str]) -> list[str]:
        """Interface keys of rule interfaces (groups expanded); ``[]`` stays every interface."""
        found: list[str] = []
        for name in names:
            found.extend(self.groups.get(name, [name]))
        return list(dict.fromkeys(found))


def _add(notes: list[str], text: str) -> None:
    if text and text not in notes:
        notes.append(text)


# ── Addresses and ports ──────────────────────────────────────────────────────


def _family_of(cidr: str) -> str:
    found = canonical(cidr)
    if not found:
        return ""
    return "inet6" if ":" in found else "inet"


def _family_filter(cidrs: list[str], family: str) -> list[str]:
    """``cidrs`` limited to one address family (``inet46``/``""``: both)."""
    if family not in ("inet", "inet6"):
        return list(cidrs)
    return [c for c in cidrs if c == ANY or _family_of(c) == family]


def _range(first: str, last: str) -> list[str]:
    try:
        start, end = ipaddress.ip_address(first), ipaddress.ip_address(last)
        return [str(n) for n in ipaddress.summarize_address_range(start, end)]
    except TypeError, ValueError:
        return []


def _addresses(value: str) -> list[str]:
    """The networks of an address, network or ``A-B`` range; ``[]`` when it is none."""
    text = value.strip()
    if "-" in text and "/" not in text:
        first, _dash, last = text.partition("-")
        if is_address(first.strip()) and is_address(last.strip()):
            return _range(first.strip(), last.strip())
        return []
    found = canonical(text)
    return [found] if found else []


def _port_range(value: str) -> tuple[int, int] | None:
    text = value.strip().lower()
    match = _PORT.match(text)
    if match:
        low, high = int(match.group(1)), int(match.group(2) or match.group(1))
        if low > high:
            low, high = high, low
        return (low, high) if high <= 65535 else None
    if text in _PORT_NAMES:
        return (_PORT_NAMES[text], _PORT_NAMES[text])
    return None


def _port_expression(ports: list[tuple[int, int]] | None) -> str:
    if ports is None or any(low <= 1 and high >= 65535 for low, high in ports):
        return ANY
    return ",".join(dict.fromkeys(str(low) if low == high else f"{low}-{high}" for low, high in ports))


class _Resolver:
    """Resolves rule addresses and ports against the interfaces and aliases."""

    def __init__(self, config: OpnsenseConfig) -> None:
        self.config = config
        lowered = {name.lower(): alias for name, alias in config.aliases.items()}
        self.aliases = lowered

    def alias(self, name: str) -> Alias | None:
        return self.aliases.get(name.lower())

    def address(
        self, value: str, seen: frozenset[str] = frozenset()
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        """``(cidrs, unresolved, aliases used, missing names)`` of one address value."""
        text = value.strip()
        lowered = text.lower()
        if lowered in ("", "any", "*"):
            return [ANY], [], [], []
        if lowered == "(self)":
            return self._self()
        interfaces = self.config.interfaces
        key = lowered
        if key in interfaces or key in self.config.groups:
            return self._interface_networks(key)
        if key.endswith("ip") and key[:-2] in interfaces:
            iface = interfaces[key[:-2]]
            found = [canonical(pair[0]) for pair in (iface.ipv4, iface.ipv6) if pair is not None]
            if iface.dynamic:
                return [ANY], [f"address of {iface.key} (learned by {', '.join(iface.dynamic)})"], [], []
            return ([c for c in found if c] or [ANY]), ([] if found else [f"address of {iface.key}"]), [], []
        cidrs = _addresses(text)
        if cidrs:
            return cidrs, [], [], []
        alias = self.alias(text)
        if alias is not None:
            return self._alias_addresses(alias, seen)
        if lowered.startswith(_BUILTIN_ALIASES):
            return [ANY], [f"alias {text} (a table the firewall fills)"], [text], []
        return [ANY], [f"alias {text} (not in the configuration)"], [], [text]

    def _self(self) -> tuple[list[str], list[str], list[str], list[str]]:
        found: list[str] = []
        dynamic: list[str] = []
        for iface in self.config.interfaces.values():
            found.extend(iface.addresses())
            if iface.dynamic:
                dynamic.append(iface.key)
        unresolved = [f"addresses of this firewall learned on {', '.join(dynamic)}"] if dynamic else []
        if unresolved or not found:
            return [ANY], unresolved or ["addresses of this firewall"], [], []
        return list(dict.fromkeys(found)), [], [], []

    def _interface_networks(self, key: str) -> tuple[list[str], list[str], list[str], list[str]]:
        found: list[str] = []
        unresolved: list[str] = []
        for member in self.config.groups.get(key, [key]):
            iface = self.config.interfaces.get(member)
            if iface is None:
                unresolved.append(f"network of {member} (not in the configuration)")
                continue
            found.extend(iface.networks())
            if iface.dynamic:
                unresolved.append(f"network of {member} (learned by {', '.join(iface.dynamic)})")
        if unresolved or not found:
            return [ANY], unresolved or [f"network of {key}"], [], []
        return list(dict.fromkeys(found)), [], [], []

    def _alias_addresses(self, alias: Alias, seen: frozenset[str]) -> tuple[list[str], list[str], list[str], list[str]]:
        name = alias.name
        if name.lower() in seen:
            return [ANY], [f"alias {name} (nested in itself)"], [name], []
        if not alias.enabled:
            return [ANY], [f"alias {name} (disabled)"], [name], []
        kind = alias.type.lower()
        if kind not in _ADDRESS_ALIASES:
            what = "port alias" if kind == _PORT_ALIAS else f"{kind or 'unknown'} alias"
            return [ANY], [f"{what} {name}"], [name], []
        cidrs: list[str] = []
        unresolved: list[str] = []
        used = [name]
        missing: list[str] = []
        for entry in alias.content:
            found = _addresses(entry)
            if found:
                cidrs.extend(found)
                continue
            nested = self.alias(entry)
            if nested is not None:
                more, problems, names, absent = self._alias_addresses(nested, seen | {name.lower()})
                used.extend(names)
                missing.extend(absent)
                if problems:
                    unresolved.extend(problems)
                else:
                    cidrs.extend(more)
            elif _FQDN.match(entry):
                unresolved.append(f"alias {name} (host name {entry})")
            else:
                unresolved.append(f"alias {name} ({entry} is not in the configuration)")
                missing.append(entry)
        if unresolved:
            return [ANY], unresolved, used, missing
        if not cidrs:
            return [ANY], [f"alias {name} (empty)"], used, missing
        return list(dict.fromkeys(cidrs)), [], used, missing

    def ports(
        self, value: str, seen: frozenset[str] = frozenset()
    ) -> tuple[list[tuple[int, int]] | None, list[str], list[str], list[str]]:
        """``(ranges, unresolved, aliases used, missing names)`` of a port
        value (``None`` ranges: any port)."""
        text = value.strip()
        if text.lower() in ("", "any", "*"):
            return None, [], [], []
        ranges: list[tuple[int, int]] = []
        unresolved: list[str] = []
        used: list[str] = []
        missing: list[str] = []
        for part in _split(text, ", "):
            found = _port_range(part)
            if found is not None:
                ranges.append(found)
                continue
            alias = self.alias(part)
            if alias is None:
                unresolved.append(f"port alias {part} (not in the configuration)")
                missing.append(part)
                continue
            used.append(alias.name)
            if alias.name.lower() in seen:
                unresolved.append(f"port alias {alias.name} (nested in itself)")
            elif alias.type.lower() != _PORT_ALIAS:
                unresolved.append(f"{alias.type} alias {alias.name} (not a port alias)")
            elif not alias.enabled:
                unresolved.append(f"port alias {alias.name} (disabled)")
            else:
                more, problems, names, absent = self.ports(" ".join(alias.content), seen | {alias.name.lower()})
                used.extend(names)
                missing.extend(absent)
                unresolved.extend(problems)
                if more is None and not problems:
                    return None, unresolved, used, missing
                ranges.extend(more or [])
        if unresolved:
            return None, unresolved, used, missing
        return ranges, [], used, missing

    def endpoint(self, values: list[str], port: str, negate: bool, any_set: bool) -> Endpoint:
        """An ``Endpoint`` from the configured address values (several in
        the MVC model), port and ``not``."""
        values = [v for v in values if v.strip()]
        is_any = any_set or not values or any(v.strip().lower() in ("any", "*") for v in values)
        point = Endpoint(text=_describe(values) if not is_any else "any", port_text=port.strip(), negate=negate)
        point.any = is_any
        cidrs: list[str] = []
        if not is_any:
            for value in values:
                found, unresolved, used, missing = self.address(value)
                cidrs.extend(found)
                point.unresolved.extend(unresolved)
                point.aliases.extend(used)
                point.missing.extend(missing)
        ranges, unresolved, used, missing = self.ports(port)
        point.ports = ranges
        point.unresolved.extend(unresolved)
        point.aliases.extend(used)
        point.missing.extend(missing)
        if negate and not is_any:
            point.unresolved.append(f"negated {point.text}")
        if is_any or point.unresolved or ANY in cidrs:
            point.cidrs = [ANY]
        else:
            point.cidrs = list(dict.fromkeys(cidrs))
        point.aliases = list(dict.fromkeys(point.aliases))
        point.missing = list(dict.fromkeys(point.missing))
        point.unresolved = list(dict.fromkeys(point.unresolved))
        return point


def _describe(values: list[str]) -> str:
    words: list[str] = []
    for value in values:
        lowered = value.strip().lower()
        if lowered == "(self)":
            words.append("This firewall")
        elif re.fullmatch(r"(wan|lan|opt\d+)ip", lowered):
            words.append(f"{lowered[:-2]} address")
        elif re.fullmatch(r"wan|lan|opt\d+", lowered):
            words.append(f"{lowered} net")
        else:
            words.append(value.strip())
    return ", ".join(words)


# ── Reading the document ─────────────────────────────────────────────────────


def _pair(address: str, length: str) -> tuple[str, str] | None:
    if not is_address(address) or not length.isdigit():
        return None
    network = canonical(f"{address}/{length}")
    return (address, network) if network else None


def _interfaces(root: ElementTree.Element, config: OpnsenseConfig) -> None:
    vlans: dict[str, str] = {}
    for vlan in _all(root, "./vlans/vlan"):
        device = _text(vlan, "vlanif") or f"{_text(vlan, 'if')}_vlan{_text(vlan, 'tag')}"
        label = f"VLAN {_text(vlan, 'tag')} on {_text(vlan, 'if')}".strip()
        descr = _text(vlan, "descr")
        vlans[device] = f"{label} ({descr})" if descr else label
    section = root.find("./interfaces")
    for node in list(section) if section is not None else []:
        key = node.tag.lower()
        device = _text(node, "if")
        if not device:
            continue
        if key in ("lo0",) or device.startswith("lo"):
            continue
        # The installer's wan and lan carry <enable>; without it an optional
        # interface is assigned but disabled.
        enabled = _flag(node, "enable") or (node.find("enable") is None and key in ("wan", "lan"))
        iface = Interface(key, device, description=_text(node, "descr") or vlans.get(device, ""), enabled=enabled)
        ipaddr, ipaddr6 = _text(node, "ipaddr"), _text(node, "ipaddrv6")
        if is_address(ipaddr):
            iface.ipv4 = _pair(ipaddr, _text(node, "subnet"))
        elif ipaddr:
            iface.dynamic.append(ipaddr.lower())
        if is_address(ipaddr6):
            iface.ipv6 = _pair(ipaddr6, _text(node, "subnetv6"))
        elif ipaddr6 and ipaddr6.lower() not in ("none",):
            iface.dynamic.append(ipaddr6.lower())
        iface.gateway = _text(node, "gateway")
        iface.gateway6 = _text(node, "gatewayv6")
        iface.upstream = key == "wan" or bool(iface.gateway or iface.gateway6) or ipaddr.lower() in ("dhcp", "pppoe")
        iface.block_private = _flag(node, "blockpriv")
        iface.block_bogons = _flag(node, "blockbogons")
        config.interfaces[key] = iface
    for vip in _all(root, "./virtualip/vip"):
        holder = config.interfaces.get(_text(vip, "interface").lower())
        address, bits = _text(vip, "subnet"), _text(vip, "subnet_bits")
        mode = _text(vip, "mode").lower()
        pair = _pair(address, bits) if holder is not None else None
        if holder is not None and pair is not None and mode in ("carp", "ipalias"):
            holder.virtual.append((pair[0], pair[1], mode, _text(vip, "vhid")))
    for group in _all(root, "./ifgroups/ifgroupentry"):
        name = _text(group, "ifname").lower()
        members = [m.lower() for m in _split(_text(group, "members"), " ,")]
        if name:
            config.groups[name] = members


def _aliases(root: ElementTree.Element, config: OpnsenseConfig) -> None:
    for node in _all(root, "./OPNsense/Firewall/Alias/aliases/alias"):
        name = _text(node, "name")
        if name:
            config.aliases[name] = Alias(
                name,
                _text(node, "type").lower(),
                _split(_text(node, "content"), "\n"),
                _text(node, "description"),
                _on(node, "enabled", True),
                _uuid(node),
            )
    for node in _all(root, "./aliases/alias"):
        name = _text(node, "name")
        if name and name not in config.aliases:
            config.aliases[name] = Alias(
                name,
                _text(node, "type").lower(),
                _split(_text(node, "address") or _text(node, "content"), " \n"),
                _text(node, "descr"),
                True,
                _uuid(node),
            )


def _legacy_side(rule: ElementTree.Element, name: str) -> tuple[list[str], str, bool, bool]:
    """``(values, port, negate, any)`` of a legacy ``<source>`` / ``<destination>``."""
    side = rule.find(name)
    if side is None:
        return [], "", False, True
    values = [v for v in (_text(side, "network"), _text(side, "address")) if v]
    return values, _text(side, "port"), _flag(side, "not"), side.find("any") is not None and not values


def _mvc_side(rule: ElementTree.Element, name: str) -> tuple[list[str], str, bool, bool]:
    values = _split(_text(rule, f"{name}_net"))
    return values, _text(rule, f"{name}_port"), _on(rule, f"{name}_not"), not values


def _criteria(rule: ElementTree.Element, protocol: str) -> list[str]:
    """What a rule matches on that is not evaluated."""
    found: list[str] = []
    # A rule's own <tag> marks what it passes and does not narrow what it matches.
    for path, label in (("sched", "schedule"), ("os", "OS fingerprint"), ("tagged", "packets tagged")):
        value = _text(rule, path)
        if value:
            found.append(f"{label} {value}")
    icmp = _text(rule, "icmptype") or _text(rule, "icmp6-type")
    if protocol.startswith("icmp") or protocol == "ipv6-icmp":
        types = [t for t in _split(icmp) if t.lower() not in _ECHO_TYPES]
        if types:
            found.append(f"ICMP type {', '.join(types)}")
    return found


def _content_key(*parts: object) -> str:
    return "|".join(str(p) for p in parts)


def _rules(root: ElementTree.Element, config: OpnsenseConfig, resolver: _Resolver) -> None:
    read: list[tuple[int, int, FilterRule]] = []
    mvc = _all(root, "./OPNsense/Firewall/Filter/rules/rule")

    def sequence(node: ElementTree.Element) -> int:
        value = _text(node, "sequence")
        return int(value) if value.isdigit() else 0

    for order, node in enumerate(sorted(mvc, key=sequence)):
        protocol = (_text(node, "protocol") or "any").lower()
        values, port, negate, is_any = _mvc_side(node, "source")
        source = resolver.endpoint(values, port, negate, is_any)
        values, port, negate, is_any = _mvc_side(node, "destination")
        destination = resolver.endpoint(values, port, negate, is_any)
        rule = FilterRule(
            number=0,
            key=_uuid(node),
            uuid=_uuid(node),
            tier="automation",
            action=(_text(node, "action") or "pass").lower(),
            interfaces=[i.lower() for i in _split(_text(node, "interface"))],
            direction=(_text(node, "direction") or "in").lower(),
            family=(_text(node, "ipprotocol") or "inet").lower(),
            protocol=protocol,
            quick=_on(node, "quick", True),
            disabled=not _on(node, "enabled", True),
            description=_text(node, "description"),
            source=source,
            destination=destination,
            gateway=_text(node, "gateway"),
            log=_on(node, "log"),
            unresolved=_criteria(node, protocol),
        )
        if _on(node, "interfacenot"):
            rule.unresolved.append("every interface but the ones it names")
        read.append((0, order, rule))
    for order, node in enumerate(_all(root, "./filter/rule")):
        floating = _text(node, "floating").lower() in _TRUE
        interfaces = [i.lower() for i in _split(_text(node, "interface"))]
        if floating:
            tier = "floating"
        elif interfaces and interfaces[0] in config.groups:
            tier = "group"
        else:
            tier = "interface"
        direction = _text(node, "direction").lower()
        if direction not in ("in", "out", "any"):
            direction = "any" if floating else "in"
        protocol = (_text(node, "protocol") or "any").lower()
        values, port, negate, is_any = _legacy_side(node, "source")
        source = resolver.endpoint(values, port, negate, is_any)
        values, port, negate, is_any = _legacy_side(node, "destination")
        destination = resolver.endpoint(values, port, negate, is_any)
        rule = FilterRule(
            number=0,
            key=_uuid(node),
            uuid=_uuid(node),
            tier=tier,
            action=(_text(node, "type") or "pass").lower(),
            interfaces=interfaces,
            direction=direction,
            family=(_text(node, "ipprotocol") or "inet").lower(),
            protocol=protocol,
            # Interface and group rules are always quick; floating ones only when set.
            quick=_flag(node, "quick") if floating else True,
            disabled=_flag(node, "disabled"),
            description=_text(node, "descr"),
            source=source,
            destination=destination,
            gateway=_text(node, "gateway"),
            log=_flag(node, "log"),
            unresolved=_criteria(node, protocol),
        )
        read.append((TIERS.index(tier), order, rule))
    read.sort(key=lambda item: (item[0], item[1]))
    seen: dict[str, int] = {}
    for number, (_tier, _order, rule) in enumerate(read, start=1):
        rule.number = number
        if not rule.key:
            base = _content_key(
                rule.tier,
                ",".join(rule.interfaces),
                rule.direction,
                rule.family,
                rule.protocol,
                rule.action,
                rule.source.text,
                rule.source.port_text,
                rule.source.negate,
                rule.destination.text,
                rule.destination.port_text,
                rule.destination.negate,
            )
            seen[base] = seen.get(base, 0) + 1
            rule.key = f"{base}|{seen[base]}"
        config.rules.append(rule)
        if rule.gateway and not rule.disabled:
            _add(config.notes, POLICY_ROUTES)
        for name in rule.interfaces:
            if name in _VPN_ZONES and not rule.disabled:
                _add(config.notes, f"Firewall rules of {_VPN_ZONES[name]}")


def _nat(root: ElementTree.Element, config: OpnsenseConfig, resolver: _Resolver) -> None:
    for node in _all(root, "./nat/rule"):
        protocol = (_text(node, "protocol") or "any").lower()
        values, port, negate, is_any = _legacy_side(node, "source")
        source = resolver.endpoint(values, port, negate, is_any)
        values, port, negate, is_any = _legacy_side(node, "destination")
        destination = resolver.endpoint(values, port, negate, is_any)
        target = _text(node, "target")
        cidrs, unresolved, _used, _missing = resolver.address(target) if target else ([], ["no target"], [], [])
        interfaces = [i.lower() for i in _split(_text(node, "interface"))]
        forward = PortForward(
            key=_uuid(node)
            or _content_key("rdr", ",".join(interfaces), protocol, destination.text, destination.port_text, target),
            uuid=_uuid(node),
            interfaces=interfaces,
            protocol=protocol,
            family=(_text(node, "ipprotocol") or "inet").lower(),
            source=source,
            destination=destination,
            target=target,
            target_cidrs=[] if cidrs == [ANY] else cidrs,
            local_port=_text(node, "local-port"),
            disabled=_flag(node, "disabled"),
            no_redirect=_flag(node, "nordr"),
            description=_text(node, "descr"),
            filter_rule=_text(node, "associated-rule-id"),
            unresolved=list(unresolved),
        )
        config.port_forwards.append(forward)
    outbound = root.find("./nat/outbound")
    config.outbound_mode = (_text(outbound, "mode") or "automatic").lower()
    for node in _all(root, "./OPNsense/Firewall/Filter/snatrules/rule"):
        values, port, negate, is_any = _mvc_side(node, "source")
        source = resolver.endpoint(values, port, negate, is_any)
        values, port, negate, is_any = _mvc_side(node, "destination")
        destination = resolver.endpoint(values, port, negate, is_any)
        config.outbound.append(
            _outbound(
                node,
                resolver,
                "automation",
                source,
                destination,
                target=_text(node, "target"),
                no_nat=_on(node, "nonat"),
                disabled=not _on(node, "enabled", True),
                description=_text(node, "description"),
            )
        )
    for node in _all(root, "./nat/outbound/rule"):
        values, port, negate, is_any = _legacy_side(node, "source")
        source = resolver.endpoint(values, _text(node, "sourceport") or port, negate, is_any)
        values, port, negate, is_any = _legacy_side(node, "destination")
        destination = resolver.endpoint(values, _text(node, "dstport") or port, negate, is_any)
        target = _text(node, "target")
        if target.lower() == "other-subnet":
            target = f"{_text(node, 'targetip')}/{_text(node, 'targetip_subnet') or 32}"
        config.outbound.append(
            _outbound(
                node,
                resolver,
                "manual",
                source,
                destination,
                target=target,
                no_nat=_flag(node, "nonat"),
                disabled=_flag(node, "disabled"),
                description=_text(node, "descr"),
            )
        )
    legacy = _all(root, "./nat/onetoone")
    mvc = _all(root, "./OPNsense/Firewall/Filter/onetoone/rule")
    for node in legacy + mvc:
        is_mvc = node in mvc
        side = _mvc_side if is_mvc else _legacy_side
        values, port, negate, is_any = side(node, "source")
        source = resolver.endpoint(values, port, negate, is_any)
        values, port, negate, is_any = side(node, "destination")
        destination = resolver.endpoint(values, port, negate, is_any)
        interface = _text(node, "interface").lower()
        external = _text(node, "external")
        config.one_to_one.append(
            OneToOne(
                key=_uuid(node) or _content_key("binat", interface, external, source.text),
                uuid=_uuid(node),
                interface=interface,
                external=external,
                source=source,
                destination=destination,
                type=(_text(node, "type") or "binat").lower(),
                disabled=(not _on(node, "enabled", True)) if is_mvc else _flag(node, "disabled"),
                description=_text(node, "description" if is_mvc else "descr"),
            )
        )
    if _all(root, "./nat/npt") or _all(root, "./OPNsense/Firewall/Filter/npt/rule"):
        _add(config.notes, "NPTv6 rules")


def _outbound(
    node: ElementTree.Element,
    resolver: _Resolver,
    origin: str,
    source: Endpoint,
    destination: Endpoint,
    *,
    target: str,
    no_nat: bool,
    disabled: bool,
    description: str,
) -> OutboundRule:
    interface = _text(node, "interface").lower()
    protocol = (_text(node, "protocol") or "any").lower()
    unresolved: list[str] = []
    cidrs: list[str] = []
    if no_nat:
        cidrs = []
    elif not target:
        cidrs = [INTERFACE]
    else:
        found, problems, _used, _missing = resolver.address(target)
        unresolved.extend(problems)
        cidrs = [] if found == [ANY] else found
    return OutboundRule(
        key=_uuid(node) or _content_key(origin, interface, protocol, source.text, destination.text, target),
        uuid=_uuid(node),
        origin=origin,
        interface=interface,
        protocol=protocol,
        family=(_text(node, "ipprotocol") or "inet").lower(),
        source=source,
        destination=destination,
        target=target,
        target_cidrs=cidrs,
        no_nat=no_nat,
        disabled=disabled,
        description=description,
        unresolved=unresolved,
    )


def _gateways(root: ElementTree.Element, config: OpnsenseConfig) -> None:
    for node in _all(root, "./gateways/gateway_item", "./OPNsense/Gateways/gateway_item"):
        name = _text(node, "name")
        if not name:
            continue
        address = _text(node, "gateway")
        family = (_text(node, "ipprotocol") or ("inet6" if ":" in address else "inet")).lower()
        priority = _text(node, "priority")
        interface = _text(node, "interface").lower()
        iface = config.interfaces.get(interface)
        config.gateways[name] = Gateway(
            name,
            interface,
            address if is_address(address) else "",
            family,
            default=_flag(node, "defaultgw"),
            disabled=_flag(node, "disabled"),
            priority=int(priority) if priority.isdigit() else 255,
            upstream=_flag(node, "upstream") or (iface is not None and name in (iface.gateway, iface.gateway6)),
            description=_text(node, "descr"),
        )
    for node in _all(root, "./staticroutes/route"):
        network = _text(node, "network")
        config.routes.append(
            Route(network, _text(node, "gateway"), _flag(node, "disabled"), _text(node, "descr"), _uuid(node))
        )


def _services(root: ElementTree.Element, config: OpnsenseConfig) -> None:
    if _all(root, "./ipsec/phase1", "./OPNsense/Swanctl/Connections/Connection", "./OPNsense/IPsec/tunnels"):
        _add(config.notes, IPSEC)
    if _all(root, "./openvpn/openvpn-server", "./openvpn/openvpn-client", "./OPNsense/OpenVPN/Instances/Instance"):
        _add(config.notes, OPENVPN)
    if _all(root, "./OPNsense/wireguard/server/servers/server"):
        _add(config.notes, WIREGUARD)
    frr = root.find("./OPNsense/quagga")
    if frr is not None and _on(frr, "general/enabled"):
        for path, protocol in (("ospf", "ospf"), ("ospf6", "ospfv3"), ("bgp", "bgp"), ("rip", "rip")):
            if _on(frr, f"{path}/enabled"):
                config.routing.append(ROUTING_PROTOCOLS[protocol])
    if any(i.block_bogons and i.enabled for i in config.interfaces.values()):
        _add(config.notes, BOGONS)
    webgui = root.find("./system/webgui")
    if "lan" in config.interfaces and not _flag(webgui, "noantilockout"):
        protocol = _text(webgui, "protocol") or "https"
        port = _text(webgui, "port")
        ports = [int(port)] if port.isdigit() else [443 if protocol == "https" else 80]
        if protocol == "https" and not _flag(webgui, "disablehttpredirect"):
            ports.append(80)
        ssh = root.find("./system/ssh")
        if ssh is not None and (_text(ssh, "enabled") == "enabled" or _flag(ssh, "enabled")):
            ssh_port = _text(ssh, "port")
            ports.append(int(ssh_port) if ssh_port.isdigit() else 22)
        config.anti_lockout = list(dict.fromkeys(ports))


def parse_document(text: str) -> OpnsenseConfig | None:
    """An OPNsense ``config.xml`` read into an ``OpnsenseConfig``; ``None``
    when the text is not one."""
    root = parse_xml(text)
    if root is None:
        return None
    config = OpnsenseConfig(
        hostname=".".join(p for p in (_text(root, "system/hostname"), _text(root, "system/domain")) if p)
    )
    _interfaces(root, config)
    _aliases(root, config)
    resolver = _Resolver(config)
    _rules(root, config, resolver)
    _nat(root, config, resolver)
    _gateways(root, config)
    _services(root, config)
    return config


# ── Evaluation order ─────────────────────────────────────────────────────────


def rule_bindings(rule: FilterRule, config: OpnsenseConfig) -> set[tuple[str, str]]:
    """The ``(interface key, direction)`` pairs a rule is evaluated on."""
    zones = config.zones(rule.interfaces) if rule.interfaces else list(config.interfaces)
    directions = ("in", "out") if rule.direction == "any" else (rule.direction,)
    return {(zone, direction) for zone in zones for direction in directions}


def evaluation_order(rules: list[FilterRule], config: OpnsenseConfig, zone: str, direction: str) -> list[FilterRule]:
    """The rules of one interface and direction in the order a first match
    decides, as pf decides them: the quick rules in order, then the others
    in reverse order (the last one that matches wins)."""
    bound = [r for r in rules if (zone, direction) in rule_bindings(r, config)]
    return [r for r in bound if r.quick] + [r for r in reversed(bound) if not r.quick]


# ── RunningConfig ────────────────────────────────────────────────────────────


def _protocols(protocol: str, family: str) -> list[str] | None:
    """The forwarding protocols of a rule's protocol; ``None`` when it matches nothing."""
    text = protocol.lower()
    if text in ("", "any"):
        return [ANY]
    if text == "tcp/udp":
        return ["tcp", "udp"]
    if text in ("icmp6", "ipv6-icmp", "icmpv6"):
        return ["icmpv6"] if family != "inet" else None
    if text == "icmp":
        return ["icmpv6" if family == "inet6" else "icmp"]
    return [text]


def _side(point: Endpoint, family: str) -> list[str] | None:
    """The addresses of a side limited to the rule's family; ``None`` when
    none is left (pf loads no rule then)."""
    if point.cidrs == [ANY]:
        if family == "inet":
            return [_V4_ANY]
        if family == "inet6":
            return [_V6_ANY]
        return [ANY]
    kept = _family_filter(point.cidrs, family)
    return kept or None


def _entries(rule: FilterRule) -> list[AclEntry]:
    protocols = _protocols(rule.protocol, rule.family)
    src = _side(rule.source, rule.family)
    dst = _side(rule.destination, rule.family)
    if protocols is None or src is None or dst is None:
        return []
    unresolved = [*rule.unresolved, *rule.source.unresolved, *rule.destination.unresolved]
    entries = []
    for protocol in protocols:
        ported = protocol in ("tcp", "udp")
        entries.append(
            AclEntry(
                rule.number,
                "allow" if rule.action == "pass" else "deny",
                protocol=protocol,
                src=src,
                src_ports=rule.source.port_expression if ported else ANY,
                dst=dst,
                dst_ports=rule.destination.port_expression if ported else ANY,
                comment=f"{rule.tier} rule",
                unresolved=list(dict.fromkeys(unresolved)),
                name=rule.description,
                enabled=not rule.disabled,
            )
        )
    return entries


def _system_entries(config: OpnsenseConfig, zone: str) -> list[AclEntry]:
    """The rules OPNsense puts in front of the configured ones on ``zone``:
    a port forward that passes its own traffic, the anti-lockout rule and
    ``Block private networks``."""
    iface = config.interfaces[zone]
    entries: list[AclEntry] = []
    # ``rdr pass``: the translated flow is passed before any filter rule.
    for forward in config.port_forwards:
        if forward.filter_rule.lower() != "pass" or forward.no_redirect or not forward.target_cidrs:
            continue
        if zone not in config.zones(forward.interfaces):
            continue
        protocols = _protocols(forward.protocol, forward.family) or []
        for protocol in protocols:
            ported = protocol in ("tcp", "udp")
            entries.append(
                AclEntry(
                    0,
                    "allow",
                    protocol=protocol,
                    src=forward.source.cidrs,
                    dst=forward.target_cidrs,
                    dst_ports=_translated_ports(forward) if ported else ANY,
                    name=f"Port forward {forward.description or forward.target} (pass)",
                    comment="system rule",
                    unresolved=list(forward.source.unresolved),
                    enabled=not forward.disabled,
                )
            )
    if iface.block_private:
        entries.append(AclEntry(0, "deny", src=list(_PRIVATE), name=BLOCK_PRIVATE, comment="system rule"))
    if zone == "lan" and config.anti_lockout and iface.ipv4 is not None:
        entries.append(
            AclEntry(
                0,
                "allow",
                protocol="tcp",
                dst=[canonical(iface.ipv4[0])],
                dst_ports=",".join(str(p) for p in config.anti_lockout),
                name=ANTI_LOCKOUT,
                comment="system rule",
            )
        )
    return entries


def _translated_ports(forward: PortForward) -> str:
    """The destination ports a port forward's flow has once translated."""
    local = _port_range(forward.local_port) if forward.local_port else None
    ports = forward.destination.ports
    if local is None:
        return _port_expression(ports)
    if ports and len(ports) == 1:
        width = ports[0][1] - ports[0][0]
        return _port_expression([(local[0], local[0] + width)])
    return _port_expression([local])


def _access_lists(config: OpnsenseConfig, running: RunningConfig, interfaces: dict[str, ConfigInterface]) -> None:
    for zone, conf in interfaces.items():
        inbound = [*_system_entries(config, zone)]
        for rule in evaluation_order(config.rules, config, zone, "in"):
            inbound.extend(_entries(rule))
        inbound.append(AclEntry(0, "deny", name=DEFAULT_DENY, comment="block in all"))
        running.access_lists[zone] = inbound
        conf.access_groups["in"] = zone
        out_rules = evaluation_order(config.rules, config, zone, "out")
        if out_rules:
            outbound = [e for rule in out_rules for e in _entries(rule)]
            outbound.append(AclEntry(0, "allow", name=DEFAULT_PASS_OUT, comment="pass out all"))
            running.access_lists[f"{zone} out"] = outbound
            conf.access_groups["out"] = f"{zone} out"


def _nat_side(point: Endpoint, family: str) -> list[str] | None:
    if point.negate and not point.any:
        return None
    if point.unresolved:
        return None
    return _side(point, family)


def _nat_protocol(protocol: str) -> str:
    text = protocol.lower()
    return ANY if text in ("", "any", "tcp/udp") else ("icmpv6" if text == "ipv6-icmp" else text)


def _external(external: str, internal: list[str]) -> list[str]:
    """The external networks of a 1:1 rule: its address with the length of the internal network."""
    if not is_address(external):
        return []
    found: list[str] = []
    for cidr in internal:
        network = canonical(cidr)
        if not network:
            continue
        mapped = canonical(f"{external}/{network.split('/')[1]}")
        if mapped:
            found.append(mapped)
    return found


def _nat_entries(config: OpnsenseConfig, running: RunningConfig) -> None:
    entries = running.nat
    for rule in config.one_to_one:
        internal = [] if rule.source.cidrs == [ANY] else rule.source.cidrs
        external = _external(rule.external, internal)
        remote = _nat_side(rule.destination, "")
        if not internal or not external or remote is None:
            _note(running, f"1:1 NAT {rule.description or rule.external} (its addresses are not all read)")
            continue
        if rule.type == "binat":
            entries.append(
                nat(
                    len(entries) + 1,
                    "static_nat",
                    name=rule.description or f"1:1 {rule.external}",
                    enabled=not rule.disabled,
                    original_src=remote,
                    original_dst=external,
                    translated_dst=internal,
                    src_interface=rule.interface,
                )
            )
    for forward in config.port_forwards:
        name = forward.description or f"{forward.destination.text} {forward.destination.port_text}".strip()
        src = _nat_side(forward.source, forward.family)
        if forward.destination.any:
            dst: list[str] | None = [ANY]
        elif forward.destination.text.lower().endswith("address") and forward.destination.unresolved:
            dst = [INTERFACE]
        else:
            dst = _nat_side(forward.destination, forward.family)
        if src is None or dst is None or forward.source.ports is not None:
            _note(running, f"Port forward {name} (matches on what is not read)")
            continue
        translated = forward.target_cidrs if not forward.no_redirect else dst
        if not translated:
            _note(running, f"Port forward {name} (its target is not read)")
            continue
        original_port = forward.destination.port_expression
        translated_port = ""
        if not forward.no_redirect and forward.local_port:
            local = _port_range(forward.local_port)
            translated_port = str(local[0]) if local else ""
        for zone in config.zones(forward.interfaces) or [""]:
            entries.append(
                nat(
                    len(entries) + 1,
                    "destination_nat",
                    name=f"Port forward {name}",
                    enabled=not forward.disabled,
                    original_src=src,
                    original_dst=dst,
                    translated_dst=translated,
                    protocol=_nat_protocol(forward.protocol),
                    original_port="" if original_port == ANY else original_port,
                    translated_port=translated_port,
                    src_interface=zone,
                )
            )
    for rule in config.one_to_one:
        internal = [] if rule.source.cidrs == [ANY] else rule.source.cidrs
        external = _external(rule.external, internal)
        remote = _nat_side(rule.destination, "")
        if not internal or not external or remote is None:
            continue
        entries.append(
            nat(
                len(entries) + 1,
                "static_nat",
                name=rule.description or f"1:1 {rule.external}",
                enabled=not rule.disabled,
                original_src=internal,
                original_dst=remote,
                translated_src=external,
                dst_interface=rule.interface,
            )
        )
    manual = [r for r in config.outbound if r.origin == "automation"]
    if config.outbound_mode in ("hybrid", "advanced"):
        manual += [r for r in config.outbound if r.origin == "manual"]
    for snat in manual:
        label = snat.description or f"{snat.source.text} on {snat.interface}"
        src = _nat_side(snat.source, snat.family)
        dst = _nat_side(snat.destination, snat.family)
        if src is None or dst is None or snat.unresolved:
            _note(running, f"Outbound NAT {label} (matches on what is not read)")
            continue
        if snat.source.ports is not None or snat.destination.ports is not None:
            _note(running, f"Outbound NAT {label} (matches on ports)")
            continue
        translated = list(src) if snat.no_nat else snat.target_cidrs
        if not translated:
            _note(running, f"Outbound NAT {label} (its target is not read)")
            continue
        entries.append(
            nat(
                len(entries) + 1,
                "source_nat",
                name=f"Outbound NAT {label}",
                enabled=not snat.disabled,
                original_src=src,
                original_dst=dst,
                translated_src=translated,
                protocol=_nat_protocol(snat.protocol),
                dst_interface=snat.interface,
            )
        )
    if config.outbound_mode in ("automatic", "hybrid"):
        _automatic_nat(config, entries)


def _automatic_nat(config: OpnsenseConfig, entries: list[dict]) -> None:
    """OPNsense's automatic outbound rules: the IPv4 networks of the other
    interfaces leave each upstream interface as its address."""
    upstream = [i for i in config.interfaces.values() if i.upstream and i.enabled]
    for wan in upstream:
        inside = [
            network
            for iface in config.interfaces.values()
            if iface.key != wan.key and iface.enabled and not iface.upstream
            for network in iface.networks("inet")
        ]
        if not inside:
            continue
        entries.append(
            nat(
                len(entries) + 1,
                "source_nat",
                name=f"{AUTOMATIC_NAT} on {wan.key}",
                original_src=list(dict.fromkeys(inside)),
                translated_src=[INTERFACE],
                dst_interface=wan.key,
            )
        )


def _routes(config: OpnsenseConfig, running: RunningConfig) -> None:
    def device(key: str) -> str:
        iface = config.interfaces.get(key)
        return iface.device if iface is not None else ""

    for route in config.routes:
        if route.disabled:
            continue
        prefix = canonical(route.network)
        if not prefix:
            _note(running, f"Static route to {route.network} (not an address)")
            continue
        if route.gateway.lower() in ("null4", "null6"):
            running.static_routes.append(StaticRoute(prefix, "", "Null", name=route.description))
            continue
        gateway = config.gateways.get(route.gateway)
        if gateway is None or gateway.disabled:
            _note(running, f"Static route to {prefix} (gateway {route.gateway} is not read)")
            continue
        running.static_routes.append(
            StaticRoute(prefix, gateway.address, device(gateway.interface), name=route.description or route.gateway)
        )
    learned: list[str] = []
    for family, prefix in _DEFAULT_ROUTES.items():
        candidates = [g for g in config.gateways.values() if g.family == family and not g.disabled]
        chosen = next((g for g in candidates if g.default), None)
        if chosen is None:
            upstream = sorted((g for g in candidates if g.upstream), key=lambda g: g.priority)
            chosen = upstream[0] if upstream else None
        if chosen is not None:
            # A dynamic gateway: the route leaves by its interface, whose next hop is learned.
            running.static_routes.append(
                StaticRoute(prefix, chosen.address, device(chosen.interface), name=f"default gateway {chosen.name}")
            )
        elif family == "inet":
            dynamic = [i.key for i in config.interfaces.values() if i.upstream and i.dynamic and i.enabled]
            if dynamic:
                learned.append(", ".join(dynamic))
    if learned:
        _note(running, f"Routes learned by DHCP or PPPoE (the default gateway of {', '.join(learned)})")


def _config_interfaces(config: OpnsenseConfig, running: RunningConfig) -> dict[str, ConfigInterface]:
    found: dict[str, ConfigInterface] = {}
    learned: list[str] = []
    for iface in config.interfaces.values():
        conf = ConfigInterface(iface.device, description=iface.description, shutdown=not iface.enabled, zone=iface.key)
        if iface.description and iface.description.lower() not in (iface.device.lower(), iface.key):
            conf.aliases.append(iface.description)
        for pair in (iface.ipv4, iface.ipv6):
            if pair is not None:
                conf.addresses.append(pair)
        for address, network, mode, vhid in iface.virtual:
            if mode == "ipalias":
                conf.addresses.append((address, network))
            else:
                conf.virtual.append(VirtualAddress("CARP", vhid, address))
        if iface.upstream:
            conf.kind = "wan"
        if iface.dynamic:
            learned.append(f"{iface.key}: {', '.join(iface.dynamic)}")
        found[iface.key] = conf
    if learned:
        _note(running, f"Interface addresses learned dynamically ({'; '.join(learned)})")
    return found


def parse_config(text: str) -> RunningConfig:
    """What an OPNsense ``config.xml`` says about forwarding: interfaces,
    filter rules per interface, NAT, static and default routes."""
    running = RunningConfig(stateful=True)
    config = parse_document(text)
    if config is None:
        _note(running, "Configuration (the backup is not an OPNsense config.xml)")
        return running
    interfaces = _config_interfaces(config, running)
    running.interfaces = list(interfaces.values())
    _access_lists(config, running, interfaces)
    _nat_entries(config, running)
    _routes(config, running)
    running.routing = list(config.routing)
    for name in config.notes:
        _note(running, name)
    return running
