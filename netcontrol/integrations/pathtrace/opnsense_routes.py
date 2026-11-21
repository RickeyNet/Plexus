"""The live routing table and interface addresses of an OPNsense firewall,
as the route capture of its inventory host.

The OPNsense collection reads the firewall's routing table
(``diagnostics/interface/get_routes``, FreeBSD ``netstat -rn`` as JSON) and
its interfaces (``interfaces/overview/interfaces_info``). When the firewall
is an inventory host, ``netcontrol.routes.opnsense_collection`` stores both
as one ``route_snapshots`` row of that host, written by ``capture_text`` and
read back here, so the writer and the readers share one format:

- ``capture_text`` turns the rows into a plain text: a header line, one
  ``interface KEY DEVICE ADDRESS/LEN...`` line per interface with an
  address, then one ``route FAMILY DESTINATION GATEWAY FLAGS NETIF`` line
  per route, each part sorted. Only those fields are kept: no counters,
  MTU or expiry, so the text (and its hash) changes only when the routing
  or the addressing does.
- ``parse_routes`` is the ``routes`` parser of the ``opnsense`` platform
  (``platforms``): the forwarding routes of the table (``U`` without a
  gateway is connected; ``S`` static, the default route by its
  destination; the protocol flags ``1``/``2``/``3`` mark a route a routing
  daemon such as FRR installed, and a gateway route without ``S`` is
  learned too, both ``dynamic``; ``B`` / ``R`` blackhole and reject routes
  drop the flow), plus a connected and a local route for every live
  interface address, so an interface whose address config.xml does not
  hold (DHCP, PPPoE, DHCPv6, track6) gets it. The firewall's own addresses
  (host routes through ``lo0``) are local routes of the interface whose
  ``link#N`` they name. Link-local, multicast and loopback entries and the
  IPv4-mapped IPv6 ranges are left out.
- ``live_interfaces`` reads the interface part back for the config.xml
  reader (``opnsense_config.parse_config``), which fills the address of a
  dynamic interface from it; ``has_routes`` says whether the capture holds
  the routing table.
- ``interface_indexes`` reads the kernel interface index of each interface
  off the ``link#N`` gateways of the connected routes, for the NetFlow
  interface names (``netcontrol.routes.opnsense_netflow``).

Pure (no I/O). Uses the standard library only.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any

from netcontrol.integrations.meraki.forwarding import canonical, is_address
from netcontrol.integrations.pathtrace.route_tables import LOCAL, route_entry

__all__ = [
    "HEADER",
    "LiveInterface",
    "capture_text",
    "has_routes",
    "interface_indexes",
    "link_devices",
    "live_address",
    "live_interfaces",
    "parse_routes",
]

HEADER = "OPNsense routing table and interface addresses (OPNsense API)"
_INTERFACE = "interface"
_ROUTE = "route"
_EMPTY = "-"
_DEFAULTS = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
# IPv4-mapped and IPv4-compatible IPv6: FreeBSD installs reject routes for them.
_MAPPED = (ipaddress.IPv6Network("::/96"), ipaddress.IPv6Network("::ffff:0:0/96"))
# The flags a routing daemon sets on the routes it installs (FRR: 1).
_PROTOCOL_FLAGS = ("1", "2", "3")

# (key, device, addresses as "address/length")
LiveInterface = tuple[str, str, list[str]]


def _field(value: Any) -> str:
    """One whitespace-free field of the text (``-`` when empty)."""
    text = "".join(str(value if value is not None else "").split())
    return text or _EMPTY


def _value(field: str) -> str:
    return "" if field == _EMPTY else field


def capture_text(routes: list[dict], interfaces: list[LiveInterface]) -> tuple[str, int]:
    """The stored text of a routing table (``get_routes`` rows) and the live
    interface addresses (``(key, device, ["address/length", ...])``), and
    its route count. Deterministic: the same table and addresses give the
    same text whatever order the API listed them in."""
    lines = [HEADER]
    for key, device, addresses in sorted(interfaces, key=lambda item: (str(item[0]), str(item[1]))):
        kept = [_field(a) for a in dict.fromkeys(addresses) if live_address(_field(a)) is not None]
        if kept and _value(_field(device)):
            lines.append(" ".join([_INTERFACE, _field(key), _field(device), *kept]))
    rows = {
        " ".join(
            [
                _ROUTE,
                _field(row.get("proto")),
                _field(row.get("destination")),
                _field(row.get("gateway")),
                _field(row.get("flags")),
                _field(row.get("netif")),
            ]
        )
        for row in routes
        if isinstance(row, dict) and _value(_field(row.get("destination")))
    }
    lines.extend(sorted(rows))
    return "\n".join(lines) + "\n", len(rows)


def _split(lines: list[str]) -> tuple[list[LiveInterface], list[list[str]]]:
    """The interface lines and the route lines (their fields) of a capture."""
    interfaces: list[LiveInterface] = []
    routes: list[list[str]] = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and fields[0] == _INTERFACE:
            interfaces.append((_value(fields[1]), _value(fields[2]), [_value(f) for f in fields[3:] if _value(f)]))
        elif len(fields) == 6 and fields[0] == _ROUTE:
            routes.append([_value(f) for f in fields[1:]])
    return interfaces, routes


def _text_lines(text: str) -> list[str]:
    return str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")


def live_interfaces(text: str) -> list[LiveInterface]:
    """The interface part of a capture: ``(key, device, addresses)``."""
    return _split(_text_lines(text))[0]


def has_routes(text: str) -> bool:
    """Whether a capture holds the firewall's routing table."""
    return bool(_split(_text_lines(text))[1])


def live_address(value: str) -> tuple[str, str] | None:
    """``(address, network)`` of ``address/length`` (a scope ``%igb0`` is
    dropped); ``None`` for what is no usable interface address."""
    address, _slash, length = value.partition("/")
    address = address.split("%", 1)[0]
    if not is_address(address):
        return None
    parsed = ipaddress.ip_address(address)
    if parsed.is_link_local or parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
        return None
    network = canonical(f"{address}/{length}") if length.isdigit() else canonical(address)
    return (address, network) if network else None


def _destination(family: str, destination: str) -> str:
    """The network of a route's destination (``default``, a network or a
    host, a scope ``%igb0`` dropped); ``""`` for what the trace leaves out."""
    if destination == "default":
        return _DEFAULTS.get(family, "")
    head, slash, length = destination.partition("/")
    head = head.split("%", 1)[0]
    found = canonical(f"{head}/{length}" if slash else head)
    if not found:
        return ""
    network = ipaddress.ip_network(found)
    first = network.network_address
    if first.is_link_local or first.is_multicast or first.is_loopback:
        return ""
    if isinstance(network, ipaddress.IPv6Network) and any(network.subnet_of(m) for m in _MAPPED):
        return ""
    return found


def link_devices(rows: Iterable[tuple[str, str, str]]) -> dict[str, str]:
    """``link#N`` -> the interface it is, from ``(gateway, flags, netif)``
    of routing table rows: what a connected route (a ``link#N`` gateway
    without ``G``) through it names. Routes through ``lo0`` (the firewall's
    own addresses) name the interface they are on, not the netif, so they
    are left out. N is the FreeBSD kernel interface index."""
    links: dict[str, str] = {}
    for gateway, flags, netif in rows:
        if gateway.startswith("link#") and netif and not netif.startswith("lo") and "G" not in flags:
            links.setdefault(gateway, netif)
    return links


def interface_indexes(routes: Any) -> dict[int, str]:
    """Kernel interface index -> device (``igb0``, ``vlan0.10``) of a
    ``get_routes`` answer: the ``link#N`` gateways of its connected routes.
    The same index is what NetFlow records name as their input and output
    interface (``ng_netflow`` takes the receiving interface's and the route
    lookup's ``if_index``). Only interfaces with a connected route (an
    address) are found."""
    rows = routes if isinstance(routes, list) else []
    links = link_devices(
        (_value(_field(r.get("gateway"))), _value(_field(r.get("flags"))), _value(_field(r.get("netif"))))
        for r in rows
        if isinstance(r, dict)
    )
    found: dict[int, str] = {}
    for gateway, device in links.items():
        index = gateway.removeprefix("link#")
        if index.isdigit() and int(index) > 0:
            found[int(index)] = device
    return found


def parse_routes(lines: list[str]) -> list[dict]:
    """The forwarding routes of a capture (see the module docstring)."""
    interfaces, rows = _split(lines)
    links = link_devices((gateway, flags, netif) for _family, _destination_, gateway, flags, netif in rows)
    found: list[dict] = []
    for family, destination, gateway, flags, netif in rows:
        prefix = _destination(family, destination)
        if not prefix:
            continue
        if "B" in flags or "R" in flags:
            source = "Blackhole route" if "B" in flags else "Reject route"
            found.append(route_entry(prefix, "blackhole", source=source))
            continue
        if gateway.startswith("link#") and "G" not in flags:
            if netif.startswith("lo"):
                # The firewall's own address: local on the interface it is on.
                owner = links.get(gateway, "")
                if owner:
                    found.append(route_entry(prefix, "connected", iface=owner, source=LOCAL))
                continue
            found.append(route_entry(prefix, "connected", iface=netif, source="Connected"))
            continue
        if netif.startswith("lo"):
            continue
        if any(flag in flags for flag in _PROTOCOL_FLAGS):
            kind, source = "dynamic", "Route installed by a routing protocol"
        elif "S" in flags:
            kind, source = "static", "Static route"
        else:
            kind, source = "dynamic", "Learned route"
        # A link-local next hop (a router advertisement's) is no address on the map.
        hop = "" if gateway.lower().startswith("fe80") else gateway
        found.append(route_entry(prefix, kind, next_hop=hop, iface=netif, source=source))
    for _key, device, addresses in interfaces:
        for value in addresses:
            pair = live_address(value)
            if pair is None or not device:
                continue
            address, network = pair
            local = canonical(address)
            if network != local:
                found.append(route_entry(network, "connected", iface=device, source="Connected"))
            found.append(route_entry(local, "connected", iface=device, source=LOCAL))
    return found
