"""Managed cloud services as ends of a path trace and of the Cato egress check.

The collectors list a managed service (a load balancer, an application
gateway, a private or VPC endpoint, a database, a Private Service Connect
endpoint) as a record of ``netcontrol.integrations.cloud_services``, with
its endpoints, its private and public addresses and, where the provider
reports them, its listeners or rules. The reachability engines index those
records (``services()``); this module reads them the same way for AWS,
Azure and GCP:

  - ``index`` builds a ``ServiceIndex`` of one engine: which service holds
    a private address of a network, which answers on a public address, the
    DNS names whose addresses the collector reported, and the Azure
    Firewalls whose public addresses take DNAT rules
  - ``annotate`` marks a place an engine located (``locate``) as the
    address of a service, so a trace names it; on AWS and Azure the place
    gets an owner (``owner``) whose security groups the engine checks, as
    it does an instance's (GCP firewall rules aim at the backends, not at
    the address of a forwarding rule, so a GCP place keeps none)
  - ``listener_item`` says which listener or rule of the service takes the
    flow (an Azure load-balancing or inbound NAT rule, an application
    gateway listener, a GCP forwarding rule's ports, a Classic Load
    Balancer's ports, an endpoint's port), and ``dnat_match`` which DNAT
    rule of an Azure Firewall translates it

Nothing is invented: a service whose listeners are not collected is named
without a verdict on its ports, and a public frontend whose backends are
not collected by address ends the trace at the service.

Pure, standard library only: the HTML export runs this module in the
browser (``pathtrace.offline.MODULES``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from netcontrol.integrations.cloud_services import endpoint_rows
from netcontrol.integrations.pathtrace.model import (
    BLOCKED,
    FULL,
    INFO,
    NAT,
    NONE,
    OK,
    PARTIAL,
    POLICY,
    UNKNOWN,
    _port_ranges,
    cover,
    item,
    net,
    ports_match,
    protocol_match,
    show,
)

AZURE_FIREWALL = "azure_firewall"
# Providers whose filters belong to the address itself (AWS security groups
# of the service, Azure network security groups of its subnet).
_OWNED = ("aws", "azure")
# Listener protocols as a trace asks about them.
_PROTOCOLS = {"http": "tcp", "https": "tcp", "tls": "tcp", "tcp": "tcp", "udp": "udp", "l3_default": "all"}
# How many listeners a text lists.
_SHOWN = 4


def _t(value: Any) -> str:
    return str(value or "").strip()


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


@dataclass(frozen=True)
class Listener:
    """One listener or rule of a service: ``protocol`` (``tcp``, ``udp`` or
    ``all``), ``ports`` (a port expression, ``any`` for every port) and the
    frontend it is on (``public``, ``private`` or ``""``: either)."""

    text: str
    protocol: str
    ports: str
    scope: str = ""


@dataclass
class Managed:
    """A managed service as the trace sees it."""

    rid: str
    name: str
    kind: str
    resource_type: str
    network: str
    meta: dict
    private: list[str] = field(default_factory=list)
    public: list[str] = field(default_factory=list)
    # Public address -> the private address it is delivered to.
    pairs: dict[str, str] = field(default_factory=dict)
    # DNS name (lower case) -> the addresses the collector reported for it.
    names: dict[str, list[str]] = field(default_factory=dict)
    listeners: list[Listener] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.kind} {self.name}" if self.kind else self.name


def _protocol(raw: Any) -> str:
    text = _t(raw).lower()
    return _PROTOCOLS.get(text, "all" if text in ("", "all", "any", "*") else text)


def _port_text(raw: Any) -> str:
    text = _t(raw).lower()
    return "any" if text in ("", "all", "*", "0") else text


def listeners(meta: dict) -> list[Listener]:
    """The listeners and rules a service record carries."""
    found: list[Listener] = []
    for rule in _list(meta.get("forwarding_rules")):  # Azure load balancer
        if isinstance(rule, dict):
            what = "inbound NAT rule" if _t(rule.get("label")) == "NAT" else "load-balancing rule"
            text = f"{what} {_t(rule.get('name'))}: {_t(rule.get('protocol'))} {_t(rule.get('frontend_port'))}"
            found.append(
                Listener(
                    f"{text} -> {_t(rule.get('backend_port'))}",
                    _protocol(rule.get("protocol")),
                    _port_text(rule.get("frontend_port")),
                )
            )
    for entry in _list(meta.get("listener_details")):  # Azure application gateway
        if isinstance(entry, dict):
            hosts = ", ".join(_t(h) for h in _list(entry.get("host_names")) if _t(h))
            text = f"listener {_t(entry.get('name'))}: {_t(entry.get('protocol')).upper()} {_t(entry.get('port'))}"
            found.append(
                Listener(
                    f"{text} ({hosts})" if hosts else text,
                    _protocol(entry.get("protocol")),
                    _port_text(entry.get("port")),
                    _t(entry.get("frontend")),
                )
            )
    for port in _list(meta.get("listener_ports")):  # AWS Classic Load Balancer
        found.append(Listener(f"listener port {port}", "tcp", _port_text(port)))
    if "ip_protocol" in meta:  # GCP forwarding rule
        protocol = _t(meta.get("ip_protocol")) or "any protocol"
        for port in _list(meta.get("ports")):
            found.append(Listener(f"forwarding rule {protocol} {port}", _protocol(protocol), _port_text(port)))
    if not found:
        for endpoint in _list(meta.get("endpoints")):
            if isinstance(endpoint, dict) and isinstance(endpoint.get("port"), int):
                role = _t(endpoint.get("role")) or "endpoint"
                found.append(Listener(f"{role} port {endpoint['port']}", "tcp", str(endpoint["port"])))
    return list(dict.fromkeys(found))


def managed(row: dict) -> Managed:
    """A service of an engine's index (``rid``, ``name``, ``resource_type``, ``meta``)."""
    raw = row.get("meta")
    meta: dict = raw if isinstance(raw, dict) else {}
    _rows, private = endpoint_rows(meta)
    public = [_t(a) for a in _list(meta.get("public_ips")) if _t(a)]
    pairs: dict[str, str] = {}
    for interface in _list(meta.get("interfaces")):
        if not isinstance(interface, dict):
            continue
        held = [_t(a) for a in _list(interface.get("private_ips")) if _t(a)]
        for address in _list(interface.get("public_ips")):
            if _t(address) and held:
                pairs.setdefault(_t(address), held[0])
                public.append(_t(address))
    public = list(dict.fromkeys(public))
    if not pairs and len(public) == 1 and len(private) == 1:
        # One public and one private frontend: the provider delivers one to the other.
        pairs[public[0]] = private[0]
    endpoints = [e for e in _list(meta.get("endpoints")) if isinstance(e, dict)]
    # A DNS name with no address of its own (an AWS load balancer's, a VPC
    # endpoint's) resolves to the service's addresses when none of its
    # endpoints names any: they are all the service has.
    unaddressed = not any(_list(e.get("ip_addresses")) for e in endpoints)
    names: dict[str, list[str]] = {}
    for endpoint in endpoints:
        name = _t(endpoint.get("dns_name")).rstrip(".").lower()
        addresses = [_t(a) for a in _list(endpoint.get("ip_addresses")) if _t(a)]
        found = addresses or (private if unaddressed else [])
        if name and found:
            names.setdefault(name, [])
            names[name] += [a for a in found if a not in names[name]]
    return Managed(
        rid=_t(row.get("rid")),
        name=_t(row.get("name")) or _t(row.get("rid")),
        kind=_t(meta.get("kind")),
        resource_type=_t(row.get("resource_type")),
        network=_t(meta.get("vpc_id")),
        meta=meta,
        private=private,
        public=public,
        pairs=pairs,
        names=names,
        listeners=listeners(meta),
    )


class ServiceIndex:
    """The managed services and Azure Firewalls of one cloud's engine."""

    def __init__(self, services: list[Managed], firewalls: list[dict] | None = None) -> None:
        self.services = services
        self._at: dict[tuple[str, str], Managed] = {}
        self._by_address: dict[str, list[Managed]] = {}
        self.frontends: dict[str, Managed] = {}
        for service in services:
            for address in service.private:
                self._at.setdefault((service.network, address), service)
                self._by_address.setdefault(address, []).append(service)
            for address in service.public:
                self.frontends.setdefault(address, service)
        self.firewalls: list[dict] = list(firewalls or [])
        self.dnat: dict[str, dict] = {}
        for firewall in self.firewalls:
            for address in _list((firewall.get("meta") or {}).get("public_ips")):
                if _t(address):
                    self.dnat.setdefault(_t(address), firewall)

    def at(self, network: str, address: str) -> Managed | None:
        """The service holding ``address`` in ``network``; a service that
        names no network is taken when it is the only one with the address."""
        found = self._at.get((network, address))
        if found is None:
            others = self._by_address.get(address, [])
            found = others[0] if len(others) == 1 and not others[0].network else None
        return found

    def paired(self) -> list[tuple[str, str, Managed]]:
        """``(public address, private address, service)`` of every public
        frontend the provider delivers to a private address of the service."""
        return [(public, private, s) for s in self.services for public, private in s.pairs.items()]

    def named(self, text: Any) -> list[tuple[Managed, str]]:
        """``(service, address)`` of every address a collected DNS name
        ``text`` stands for (lower case, a trailing dot ignored)."""
        name = _t(text).rstrip(".").lower()
        if not name:
            return []
        return [(s, address) for s in self.services for address in s.names.get(name, [])]


def index(engine: Any) -> ServiceIndex:
    """The ``ServiceIndex`` of a reachability engine: its ``services()`` and
    the Azure Firewalls among its ``address_owners()``."""
    rows = engine.services() if callable(getattr(engine, "services", None)) else []
    owners = engine.address_owners() if callable(getattr(engine, "address_owners", None)) else {}
    firewalls: dict[str, dict] = {}
    for owner, _interface in owners.values():
        if isinstance(owner, dict) and owner.get("resource_type") == AZURE_FIREWALL:
            firewalls.setdefault(_t(owner.get("rid")), owner)
    return ServiceIndex([managed(r) for r in rows if isinstance(r, dict)], list(firewalls.values()))


def owner(service: Managed, public: str = "") -> dict:
    """An owner of a service's address for the engines' filter checks: its
    security groups, and ``public`` when a public address is delivered to it."""
    return {
        "rid": service.rid,
        "name": service.name,
        "label": service.label,
        "resource_type": service.resource_type,
        "meta": {
            "security_group_ids": list(_list(service.meta.get("security_group_ids"))),
            "public_ip": public,
            "public_ips": [public] if public else [],
            "vpc_id": service.network,
            "vnet_id": service.network,
        },
    }


def annotate(place: dict, services: ServiceIndex, provider: str) -> dict:
    """Mark ``place`` (an engine's ``locate``) as the address of a managed
    service: ``place["service"]`` and its label; on AWS and Azure also an
    owner whose filters the engine checks. Other places are returned as they are."""
    if place.get("subnet") is None or place.get("instance") is not None:
        return place
    network = place.get("net")
    if network is None or network.prefixlen != network.max_prefixlen:
        return place
    address = show(network)
    service = services.at(_t(place.get("vpc_id") or place.get("vnet_id")), address)
    if service is None:
        return place
    place["service"] = service
    place["label"] = f"{service.label} ({address})"
    if provider in _OWNED:
        public = next((p for p, private in service.pairs.items() if private == address), "")
        place["instance"] = owner(service, public)
    return place


def place(engine: Any, services: ServiceIndex, provider: str, address: str, network: str = "") -> dict:
    """``engine.locate`` of ``address``, ``annotate``-d."""
    return annotate(engine.locate(address, network), services, provider)


def has_own_groups(service: Managed) -> bool:
    return bool(_list(service.meta.get("security_group_ids")))


# ── What the service does with the flow ─────────────────────────────────────


def _asked(protocol: str, ports: tuple[int, int] | None) -> str:
    if not protocol:
        return "any traffic"
    if ports is None:
        return f"{protocol} (any port)"
    low, high = ports
    return f"{protocol}/{low}" if low == high else f"{protocol}/{low}-{high}"


def reaches(service: Managed) -> str:
    """What a service connects to, when the record says: `` It connects to …``."""
    meta = service.meta
    target = _t(meta.get("target_name"))
    if target:
        what = ", ".join(p for p in (_t(meta.get("target_type")), ", ".join(_list(meta.get("group_ids")))) if p)
        return f" It connects to {target}" + (f" ({what})." if what else ".")
    for key in ("service_name", "psc_target", "target_service"):
        if _t(meta.get(key)):
            return f" It connects to {_t(meta.get(key))}."
    return ""


def listener_item(service: Managed, protocol: str, ports: tuple[int, int] | None, *, public: bool = False) -> dict:
    """Which listener or rule of ``service`` takes ``protocol``/``ports`` on
    its public (``public``) or private frontend, as a trace item."""
    head = f"The destination is the {service.label}.{reaches(service)}"
    if not service.listeners:
        return item(POLICY, INFO, service.label, f"{head} Which ports it takes is not collected.")
    scope = "public" if public else "private"
    usable = [entry for entry in service.listeners if entry.scope in ("", scope)]
    shown = "; ".join(entry.text for entry in usable[:_SHOWN]) + ("; ..." if len(usable) > _SHOWN else "")
    if not usable:
        others = "; ".join(entry.text for entry in service.listeners[:_SHOWN])
        return item(POLICY, BLOCKED, service.label, f"{head} It has no listener on its {scope} frontend ({others}).")
    best, chosen = NONE, None
    for entry in usable:
        found = min(protocol_match(entry.protocol, protocol), ports_match(entry.ports, ports))
        if found > best:
            best, chosen = found, entry
    asked = _asked(protocol, ports)
    if best == FULL and chosen is not None:
        return item(POLICY, OK, service.label, f"{head} Its {chosen.text} takes {asked}.")
    if best != NONE:
        return item(POLICY, PARTIAL, service.label, f"{head} Only part of {asked} is taken: {shown}.")
    return item(POLICY, BLOCKED, service.label, f"{head} No listener or rule takes {asked}: {shown}.")


def backends_text(service: Managed) -> str:
    """Where a public frontend sends the flow, as far as the record says."""
    names = [_t(s) for s in _list(service.meta.get("backend_services")) if _t(s)]
    where = f" It sends the flow to backend service {', '.join(names)}." if names else ""
    return f"{where} Its backends are not collected by address, so the trace ends at the {service.kind or 'service'}."


# ── Azure Firewall DNAT ─────────────────────────────────────────────────────


def _sources(rule: dict) -> list[str]:
    return ["any" if _t(s) in ("*", "") else _t(s) for s in _list(rule.get("source_addresses"))] or ["any"]


def dnat_covers(rule: dict, address: Any) -> bool:
    """Whether a DNAT rule's source addresses take every one of ``address``."""
    found = net(address)
    return found is not None and cover(_sources(rule), found) == FULL


def dnat_match(
    meta: dict, dst: str, src: Any, protocol: str, ports: tuple[int, int] | None
) -> tuple[dict | None, str, str]:
    """``(rule, status, text)``: the first DNAT rule of an Azure Firewall
    (``meta``) that translates a flow from ``src`` to its public address
    ``dst``, or ``None`` with why none does."""
    asked = _asked(protocol, ports)
    rules = [r for r in _list(meta.get("dnat_rules")) if isinstance(r, dict)]
    source = net(src)
    for rule in rules:
        targets = [_t(d) for d in _list(rule.get("destination_addresses"))]
        if targets and "*" not in targets and dst not in targets:
            continue
        found = min(
            max((protocol_match(_protocol(p), protocol) for p in _list(rule.get("protocols"))), default=FULL),
            max((ports_match(_port_text(p), ports) for p in _list(rule.get("destination_ports"))), default=FULL),
            cover(_sources(rule), source) if source is not None else FULL,
        )
        if found == NONE:
            continue
        translated = _t(rule.get("translated_address"))
        port = _t(rule.get("translated_port"))
        where = f"rule {_t(rule.get('name'))} of collection {_t(rule.get('collection'))}"
        text = f"Its DNAT {where} translates {dst} ({asked}) to {translated}" + (f" port {port}." if port else ".")
        if found != FULL:
            text = f"Only part of the flow matches: {text} Sources: {', '.join(_sources(rule))}."
        return rule, OK if found == FULL else PARTIAL, text
    if rules:
        return None, BLOCKED, f"No DNAT rule takes {asked} to {dst}."
    if _t(meta.get("firewall_policy")):
        return None, UNKNOWN, f"No DNAT rule of firewall policy {_t(meta.get('firewall_policy'))} was collected."
    return None, BLOCKED, f"It has no DNAT rule: nothing takes {asked} to {dst}."


def translated_ports(rule: dict, ports: tuple[int, int] | None) -> tuple[int, int] | None:
    """The destination ports after a DNAT rule: its single translated port
    for a single port asked about, else ``ports`` as they are."""
    ranges = _port_ranges(_t(rule.get("translated_port"))) if _t(rule.get("translated_port")) else None
    if ports is None or ports[0] != ports[1] or not ranges or len(ranges) != 1 or ranges[0][0] != ranges[0][1]:
        return ports
    return ranges[0]


def dnat_item(firewall: dict, status: str, text: str) -> dict:
    name = _t(firewall.get("name")) or _t(firewall.get("rid"))
    return item(NAT, status, f"Azure Firewall {name}, DNAT", text)
