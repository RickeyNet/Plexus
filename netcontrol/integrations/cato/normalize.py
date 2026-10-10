"""Turn raw Cato payloads into a positioned topology snapshot.

``build_snapshot`` is pure (no I/O) and produces the same snapshot format as
``netcontrol.integrations.meraki.normalize`` (``schema`` 1), so the merge
into the Topology graph, node details, deep search, the subnet index and the
HTML export need no Cato-specific code.

How a Cato account maps onto the map:

  - every site is a site box holding its Socket(s) and their WAN links; a
    site with no Socket (IPsec, cloud interconnect) gets one node standing
    for its connection
  - the Cato Cloud is a single backbone node in a box of its own; every
    PoP in use is a "PoP <name>" box, its PoP node joined to the backbone;
    each Socket has a tunnel to the PoP it is connected to, and an IPsec
    site one edge per IPsec tunnel (primary, secondary), whose state is the
    site's: Cato reports none per tunnel
  - every connected remote user is a node of its own, in the box of the
    PoP it is connected to and linked to that PoP (a user with no PoP is in
    a "Remote users" box, linked to the backbone); its details say where it
    connects from (public IP, ISP, location, office) and what it is
    connected to in Cato (PoP, VPN IP)

Forwarding data (``node["forwarding"]``, see
``netcontrol.integrations.meraki.forwarding``): a site's device holds its
ranges and a default route into its PoP; a PoP routes the ranges and users
connected to it to them and everything else to the Cato Cloud; the Cloud
routes every range and user to its PoP, and everything else out of its
"Internet" interface, behind a Cato public address that is not collected.

Cato's API has no route table, so a route lookup that rests on data that
was not collected says so (``not_collected``): a site with a BGP peer may
learn routes from it ("Routes learned by BGP"), and so may every site when
the BGP peers were not read; when the network ranges were not read, no
Socket, PoP or Cloud knows the ranges it routes ("Route table (site network
ranges)"). The tracer then reports a lookup only the default route answers
as unknown rather than following it as if nothing more specific existed.

Cato enforces the account's WAN and Internet firewall policies once per
flow, at the PoP the flow enters by: the WAN rules for a private
destination, the Internet rules for a public one. Both rule sets are on
every PoP and on the Cloud (the way in for a Socket or user attached to no
PoP); the tracer applies an account-wide rule set at the first of them a
flow meets and says it was already applied at the rest. Sockets carry
none: a flow between two LANs of one site is not subject to the WAN
firewall. Rule objects Plexus can turn into addresses (sites, ranges,
connected users) are resolved; the rest (groups, applications, categories,
countries...) is kept in the rule's ``unresolved`` list, so a flow such a
rule may cover is reported as unknown. A policy that was not collected is a
note on the PoPs and the Cloud instead.
"""

from __future__ import annotations

import copy
import ipaddress
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.meraki.forwarding import (
    ANY,
    canonical,
    interface,
    nat,
    new_block,
    note,
    policy_set,
    route,
    rule,
)
from netcontrol.integrations.meraki.normalize import (
    SCHEMA_VERSION,
    InventoryIndex,
    _add,
    _inventory_ref,
    _layout,
    _s,
    _worst,
    kv_section,
    table_section,
)
from netcontrol.integrations.meraki.subnets import _cidr

CLOUD_SITE_ID = "__cato_cloud__"
CLOUD_NODE_ID = "cato:cloud"
# Each PoP is a box with the remote users connected to it: "<prefix>:<PoP name>".
POP_SITE_ID = "__cato_pop__"
# Remote users connected to no PoP are a box of their own.
USERS_SITE_ID = "__cato_users__"
USER_NODE_PREFIX = "cato:user:"

# Kinds that are part of the Cato cloud rather than devices at a site.
CLOUD_KINDS = ("cloud", "user")

RANGE_SECTION_TITLE = "Network ranges"
RANGE_COLUMNS = ["Subnet", "Name", "Interface", "VLAN", "Source"]

MAX_LISTED_USERS = 5000

_SITE_STATUS = {"connected": "online", "degraded": "alerting", "disconnected": "offline"}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _status(raw: Any) -> str:
    return _SITE_STATUS.get(_text(raw).lower(), "unknown")


def _mbps(value: Any) -> str:
    return f"{value} Mbps" if value not in (None, "") else ""


def _user_name(user: dict) -> Any:
    return user.get("name") or (user.get("info") or {}).get("name")


def _user_sort_key(user: dict) -> str:
    return _text(_user_name(user)).lower()


def _pop_site_id(pop: str) -> str:
    return f"{POP_SITE_ID}:{pop}"


def _place(info: Any) -> list[Any]:
    """City, state, country of an IP location."""
    info = info if isinstance(info, dict) else {}
    return [info.get("city"), info.get("state"), info.get("countryName") or info.get("countryCode")]


USER_COLUMNS = ["User", "Email", "Device", "VPN IP", "Public IP", "Location", "ISP", "Uptime (s)"]


def _user_row(user: dict) -> list[Any]:
    """One user in the tables of a PoP and of a remote-user box."""
    remote = user.get("remoteIPInfo") or {}
    return [
        _user_name(user),
        (user.get("info") or {}).get("email"),
        user.get("deviceName"),
        user.get("internalIP"),
        user.get("remoteIP"),
        _place(remote),
        remote.get("provider"),
        user.get("uptime"),
    ]


def _obj(value: Any) -> dict:
    """An object field of the API, which some schema versions return as a
    list of them: the first one."""
    if isinstance(value, list):
        value = next((v for v in value if isinstance(v, dict)), None)
    return value if isinstance(value, dict) else {}


def _is_primary(device: dict) -> bool:
    socket = _obj(device.get("socketInfo"))
    return bool(socket.get("isPrimary")) or _text(device.get("haRole")).lower() in ("primary", "master")


def _ipsec_tunnels(info: dict) -> list[dict]:
    """The IPsec tunnels of a site, primary first. Cato returns a list (one
    per tunnel); older captures hold a single object."""
    raw = info.get("ipsec")
    tunnels = [t for t in (raw if isinstance(raw, list) else [raw]) if isinstance(t, dict)]
    return sorted(tunnels, key=lambda t: not t.get("isPrimary"))


def _tunnel_label(index: int) -> str:
    """The name of a site's IPsec tunnel, by its place in ``_ipsec_tunnels``."""
    if index == 0:
        return "IPsec tunnel (primary)"
    return "IPsec tunnel (secondary)" if index == 1 else f"IPsec tunnel {index + 1} (secondary)"


def _tunnel_status(site_status: str, index: int) -> str:
    """The state of a site's IPsec tunnel. Cato's account snapshot reports
    none per tunnel, only the site's connectivity, so it is derived from
    that: a connected site has its primary up and the rest standing by
    ("ready", up for the map and the trace), a degraded site may be on
    either, and a disconnected one has every tunnel down."""
    if site_status == "online":
        return "reachable" if index == 0 else "ready"
    return {"alerting": "degraded", "offline": "unreachable"}.get(site_status, "unknown")


# What a device routes by that the trace must say was not collected.
_BGP_NOTE = "Routes learned by BGP"
_RANGES_NOTE = "Route table (site network ranges)"
BGP_COLUMNS = ["Peer", "Peer IP", "Peer ASN", "Cato IP", "Cato ASN", "Advertises"]


def _bgp_row(peer: dict) -> list[Any]:
    """One BGP peer in the tables of its site and its device."""
    advertises: list[str] = []
    if peer.get("advertiseAllRoutes"):
        advertises.append("All routes")
    if peer.get("advertiseDefaultRoute"):
        advertises.append("Default route")
    if peer.get("advertiseSummaryRoutes"):
        routes = [_text(r.get("route")) for r in _items_of(peer.get("summaryRoute")) if isinstance(r, dict)]
        advertises.append("Summary routes " + ", ".join(r for r in routes if r) if any(routes) else "Summary routes")
    return [
        peer.get("name") or peer.get("id"),
        peer.get("peerIp"),
        peer.get("peerAsn"),
        peer.get("catoIp"),
        peer.get("catoAsn"),
        ", ".join(advertises),
    ]


# ── Firewall rules ─────────────────────────────────────────────────────────

# Rule objects that stand for addresses Plexus may know, by the field of a
# rule's source or destination that names them. ``AddressBook`` maps each
# to ``{object id or lower-cased name: CIDRs}``; ``None`` marks a name that
# several objects share.
AddressBook = dict[str, dict[str, list[str] | None]]
_RESOLVABLE = ("site", "siteNetworkSubnet", "networkInterface", "floatingSubnet", "user")
# Every object a rule can name, as the trace words it.
_OBJECT_WORDS = {
    "site": "site",
    "siteNetworkSubnet": "network range",
    "networkInterface": "network interface",
    "floatingSubnet": "floating range",
    "user": "user",
    "host": "host",
    "usersGroup": "users group",
    "group": "group",
    "systemGroup": "system group",
    "globalIpRange": "global IP range",
    "country": "country",
    "application": "application",
    "customApp": "custom application",
    "appCategory": "app category",
    "customCategory": "custom category",
    "sanctionedAppsCategory": "sanctioned apps category",
}
# Plain-text values that are not addresses.
_TEXT_WORDS = {"fqdn": "FQDN", "domain": "domain", "remoteAsn": "ASN"}
_ACTIONS = {"ALLOW": "allow", "BLOCK": "deny", "PROMPT": "prompt", "RBI": "allow"}
_PROTOCOLS = {"TCP": ("tcp",), "UDP": ("udp",), "TCP_UDP": ("tcp", "udp"), "ICMP": ("icmp",)}
# Cato's predefined services that are one protocol and port.
_STANDARD_SERVICES = {
    "HTTP": ("tcp", "80"),
    "HTTPS": ("tcp", "443"),
    "SSH": ("tcp", "22"),
    "RDP": ("tcp", "3389"),
    "SMB": ("tcp", "445"),
    "ICMP": ("icmp", ANY),
}
# A rule from the reduced query: what else it matches on is not known.
_REDUCED = "fields Cato did not return"


def _items_of(value: Any) -> list[Any]:
    """A list field of the API (some schema versions return one object)."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _ref_name(ref: Any) -> str:
    return _text(ref.get("name") or ref.get("id")) if isinstance(ref, dict) else _text(ref)


def _resolve(book: AddressBook, field: str, ref: Any) -> list[str] | None:
    """The CIDRs of one object a rule names, by id and then by name."""
    known = book.get(field) or {}
    ref = ref if isinstance(ref, dict) else {"name": ref}
    for key in (_text(ref.get("id")), _text(ref.get("name")).lower()):
        if key and known.get(key):
            return known[key]
    return None


def _rule_addresses(endpoint: Any, book: AddressBook) -> tuple[list[str], list[str]]:
    """``(cidrs, unresolved)`` of a rule's source or destination.

    Cato matches a flow when any object listed matches, and an empty one is
    any address. As in ``forwarding._field``, a field Plexus cannot resolve
    in full is treated as any address with the names kept as unresolved, so
    a flow it might cover is reported as unknown, never as allowed."""
    endpoint = endpoint if isinstance(endpoint, dict) else {}
    cidrs: list[str] = []
    unresolved: list[str] = []
    for value in _items_of(endpoint.get("ip")) + _items_of(endpoint.get("subnet")):
        cidr = canonical(value)
        if cidr:
            cidrs.append(cidr)
        else:
            unresolved.append(f"address {value}")
    for span in _items_of(endpoint.get("ipRange")):
        span = span if isinstance(span, dict) else {}
        try:
            first = ipaddress.ip_address(_text(span.get("from")))
            last = ipaddress.ip_address(_text(span.get("to")))
            cidrs += [str(n) for n in ipaddress.summarize_address_range(first, last)]
        except TypeError, ValueError:
            unresolved.append(f"range {_text(span.get('from'))}-{_text(span.get('to'))}")
    for field, word in _OBJECT_WORDS.items():
        for ref in _items_of(endpoint.get(field)):
            found = _resolve(book, field, ref) if field in _RESOLVABLE else None
            if found:
                cidrs += found
            else:
                unresolved.append(f"{word} {_ref_name(ref)}")
    for field, word in _TEXT_WORDS.items():
        unresolved += [f"{word} {_text(v)}" for v in _items_of(endpoint.get(field))]
    if unresolved:
        return [ANY], unresolved
    return list(dict.fromkeys(cidrs)) or [ANY], []


def _rule_service(service: Any) -> tuple[list[tuple[str, str]], list[str]]:
    """``([(protocol, port expression)], unresolved)`` of a rule's service:
    one entry per protocol, ``[]`` for any service. A predefined service
    that is not a single protocol and port is unresolved, and makes the
    service any."""
    service = service if isinstance(service, dict) else {}
    ports: dict[str, list[str]] = {}
    unresolved: list[str] = []
    for standard in _items_of(service.get("standard")):
        ref = standard if isinstance(standard, dict) else {"name": standard}
        keys = (_text(ref.get("name")).upper(), _text(ref.get("id")).upper())
        known = next((_STANDARD_SERVICES[key] for key in keys if key in _STANDARD_SERVICES), None)
        if known is None:
            unresolved.append(f"service {_ref_name(standard)}")
        else:
            ports.setdefault(known[0], []).append(known[1])
    for custom in _items_of(service.get("custom")):
        custom = custom if isinstance(custom, dict) else {}
        expression = [_text(p) for p in _items_of(custom.get("port")) if _text(p)]
        for span in _items_of(custom.get("portRange")):
            if isinstance(span, dict) and _text(span.get("from")) and _text(span.get("to")):
                expression.append(f"{_text(span['from'])}-{_text(span['to'])}")
        protocol = _text(custom.get("protocol")).upper()
        for name in _PROTOCOLS.get(protocol, (ANY,)):
            ports.setdefault(name, []).append(",".join(expression) if expression else ANY)
    if unresolved:
        return [], unresolved
    found = []
    for protocol, expressions in ports.items():
        # A protocol with any port on one entry is any port.
        found.append((protocol, ANY if ANY in expressions or protocol == "icmp" else ",".join(expressions)))
    return found, []


def _rule_context(item: dict) -> list[str]:
    """What a rule matches on besides addresses and services."""
    unresolved: list[str] = []
    # The WAN firewall's application field narrows a rule further (to
    # applications, categories or destinations of their own): any of it
    # is something Plexus does not evaluate.
    application = _obj(item.get("application"))
    for field, word in {**_OBJECT_WORDS, **_TEXT_WORDS}.items():
        unresolved += [f"{word} {_ref_name(v)}" for v in _items_of(application.get(field))]
    for field in ("ip", "subnet"):
        unresolved += [f"application address {_text(v)}" for v in _items_of(application.get(field))]
    for span in _items_of(application.get("ipRange")):
        if isinstance(span, dict):
            unresolved.append(f"application range {_text(span.get('from'))}-{_text(span.get('to'))}")
    origin = _text(item.get("connectionOrigin")).upper()
    if origin and origin != "ANY":
        unresolved.append(f"connection origin {origin.lower()}")
    unresolved += [f"country {_ref_name(c)}" for c in _items_of(item.get("country"))]
    unresolved += [f"device posture {_ref_name(d)}" for d in _items_of(item.get("device"))]
    unresolved += [f"device OS {_text(o)}" for o in _items_of(item.get("deviceOS"))]
    schedule = item.get("schedule")
    active = _text(schedule.get("activeOn")) if isinstance(schedule, dict) else ""
    if active and active.upper() != "ALWAYS":
        unresolved.append(f"schedule {active.lower().replace('_', ' ')}")
    unresolved += [f"exception {_ref_name(e)}" for e in _items_of(item.get("exceptions"))]
    return unresolved


def _firewall_rules(payload: dict, book: AddressBook, *, directional: bool) -> list[dict]:
    """A Cato firewall policy's rules as forwarding rules, in Cato's order.

    ``directional`` (the WAN firewall): a rule applies from its source to its
    destination (``TO``), the other way (``FROM``), or both ways (``BOTH``,
    a second rule with the ends swapped). A rule matching on more services
    than one protocol is one rule per protocol, with the same index."""
    items = [r for r in payload.get("rules") or [] if isinstance(r, dict)]

    def order(item: dict) -> tuple[int, int]:
        index = _text(item.get("index"))
        return (0, int(index)) if index.isdigit() else (1, 0)

    found: list[dict] = []
    # A stable sort: rules without an index keep their place, after the rest.
    for position, item in enumerate(sorted(items, key=order), start=1):
        index = int(_text(item.get("index"))) if _text(item.get("index")).isdigit() else position
        src, unresolved_src = _rule_addresses(item.get("source"), book)
        dst, unresolved_dst = _rule_addresses(item.get("destination"), book)
        services, unresolved_service = _rule_service(item.get("service"))
        unresolved = unresolved_src + unresolved_dst + unresolved_service + _rule_context(item)
        if payload.get("reduced"):
            src, dst, unresolved = [ANY], [ANY], [*unresolved, _REDUCED]
        raw_action = _text(item.get("action")).upper()
        action = _ACTIONS.get(raw_action, raw_action.lower() or "unknown")
        comment = "Remote browser isolation" if raw_action == "RBI" else _text(item.get("description"))
        direction = _text(item.get("direction")).upper() if directional else "TO"
        ends = {"FROM": [(dst, src, "")], "BOTH": [(src, dst, ""), (dst, src, " (return)")]}.get(
            direction, [(src, dst, "")]
        )
        for rule_src, rule_dst, suffix in ends:
            for protocol, ports in services or [(ANY, ANY)]:
                found.append(
                    rule(
                        index,
                        action,
                        name=_text(item.get("name")) + suffix,
                        enabled=item.get("enabled", True) is not False,
                        protocol=protocol,
                        src=rule_src,
                        dst=rule_dst,
                        dst_ports=ports,
                        comment=comment,
                        unresolved=unresolved,
                    )
                )
    return found


def _firewall_policy(name: str, applies: str, payload: dict, book: AddressBook, *, default: str) -> dict:
    """A collected Cato firewall policy as a rule set. A policy that is
    turned off holds no rules, and what Cato then does with the traffic is
    not documented: the default action is unknown, never a guess."""
    if payload.get("enabled", True) is False:
        return policy_set(name, "firewall", applies, [], default="unknown")
    rules = _firewall_rules(payload, book, directional=applies == "wan_traffic")
    return policy_set(name, "firewall", applies, rules, default=default)


class _Builder:
    def __init__(self, raw: dict, inventory: InventoryIndex) -> None:
        self.raw = raw
        self.inventory = inventory
        self.sites_raw: list[dict] = [s for s in raw.get("sites") or [] if isinstance(s, dict) and s.get("id")]
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.sites: list[dict] = []
        # The boxes of the Cato cloud: one per PoP, and the users with no PoP.
        self.cloud_boxes: list[dict] = []
        self.range_count = 0
        # PoP name -> [site name, device label, state] rows.
        self._pop_sites: dict[str, list[list[str]]] = {}
        self._cloud_sites: list[list[str]] = []
        # For the forwarding blocks: the ranges of each site, the device
        # traffic for a site enters by, the PoPs each device is connected to
        # (none: the Cato Cloud), its WAN links, and the remote users.
        self._ranges: dict[str, list[list[str]]] = {}
        self._gateway: dict[str, str] = {}
        self._pops: dict[str, list[str]] = {}
        self._wans: dict[str, list[tuple[str, str, bool]]] = {}
        self._users: list[tuple[str, str, str]] = []
        # Range and interface entity id -> (site id, source, interface,
        # CIDR), for the objects firewall rules name by id.
        self._entities: dict[str, tuple[str, str, str, str]] = {}
        # The BGP peers of each site id; the IPsec tunnels of each IPsec
        # site's node as (name, remote IP, state); the tunnel behind each
        # IPsec tunnel edge id, for its details.
        self._bgp = self._bgp_by_site()
        self._ipsec: dict[str, list[tuple[str, str, str]]] = {}
        self._tunnel_of_edge: dict[str, dict] = {}

    # ── Graph primitives ───────────────────────────────────────────────────

    def _node(self, node_id: str, kind: str, label: str, site: str, status: str, **fields: Any) -> dict:
        node = {
            "id": node_id,
            "kind": kind,
            "label": label,
            "site": site,
            "status": status,
            "model": "",
            "serial": "",
            "mac": "",
            "ip": "",
            "sections": [],
        }
        node.update(fields)
        self.nodes[node_id] = node
        return node

    def _edge(self, a: str, b: str, kind: str, **fields: Any) -> dict | None:
        if a == b or a not in self.nodes or b not in self.nodes:
            return None
        edge = {"id": f"e{len(self.edges) + 1}", "a": a, "b": b, "kind": kind, "a_port": "", "b_port": "", "status": ""}
        edge.update(fields)
        self.edges.append(edge)
        return edge

    def _pop_node(self, name: str) -> str:
        node_id = f"pop:{name}"
        if node_id not in self.nodes:
            self._node(node_id, "cloud", f"PoP {name}", _pop_site_id(name), "online", model="Cato PoP")
        return node_id

    # ── Subnets ────────────────────────────────────────────────────────────

    def _ranges_by_site(self) -> dict[str, list[list[str]]]:
        """Network range rows per site id, from the entity lookups."""
        by_id = {_text(s["id"]): s for s in self.sites_raw}
        by_name = {_text((s.get("info") or {}).get("name")).lower(): _text(s["id"]) for s in self.sites_raw}
        rows: dict[str, dict[str, list[str]]] = {}
        # Ranges first: they name the range; an interface only adds a native
        # range that no range entity covered.
        for source, items in (("Range", self.raw.get("ranges")), ("Interface", self.raw.get("interfaces"))):
            for item in items or []:
                if not isinstance(item, dict):
                    continue
                entity = item.get("entity") or {}
                helper = item.get("helperFields") if isinstance(item.get("helperFields"), dict) else {}
                # Entity names read "Site \ Interface \ Range".
                parts = [p.strip() for p in _text(entity.get("name")).split("\\") if p.strip()]
                site_id = _text(helper.get("siteId") or helper.get("siteID"))
                if site_id not in by_id:
                    site_name = _text(helper.get("siteName")) or (parts[0] if parts else "")
                    site_id = by_name.get(site_name.lower(), "")
                cidr = _cidr(helper.get("subnet") or helper.get("range"))
                if not site_id or not cidr or cidr in ("0.0.0.0/0", "::/0"):
                    continue
                interface = _text(helper.get("interfaceName")) or (parts[1] if len(parts) > 1 else "")
                name = parts[-1] if len(parts) > 2 else ("Native range" if source == "Interface" else interface)
                vlan = _text(helper.get("vlanTag") or helper.get("vlan"))
                rows.setdefault(site_id, {}).setdefault(cidr, [cidr, name, interface, vlan, source])
                if _text(entity.get("id")):
                    self._entities[_text(entity["id"])] = (site_id, source, interface, cidr)
        return {site_id: list(found.values()) for site_id, found in rows.items()}

    # ── Routing data ───────────────────────────────────────────────────────

    def _bgp_by_site(self) -> dict[str, list[dict]]:
        """The collected BGP peers per site id; each names its site by id,
        or failing that by name."""
        by_name = {_text((s.get("info") or {}).get("name")).lower(): _text(s["id"]) for s in self.sites_raw}
        known = {_text(s["id"]) for s in self.sites_raw}
        found: dict[str, list[dict]] = {}
        for peer in self.raw.get("bgp_peers") or []:
            if not isinstance(peer, dict):
                continue
            site = _obj(peer.get("site"))
            site_id = _text(site.get("id"))
            if site_id not in known:
                site_id = by_name.get(_text(site.get("name")).lower(), "")
            if site_id:
                found.setdefault(site_id, []).append(peer)
        return found

    def _routing_notes(self) -> tuple[str, str]:
        """``(bgp, ranges)``: the routing data that was not collected, as the
        note every Socket and IPsec site gets (``bgp``) and the note they,
        the PoPs and the Cloud get (``ranges``); ``""`` when there is none."""
        if not (self.raw.get("options") or {}).get("include_ranges", True):
            # Neither the ranges nor the BGP peers were asked for.
            return "", _RANGES_NOTE
        errors = [e for e in self.raw.get("errors") or [] if isinstance(e, dict)]
        ranges = _RANGES_NOTE if any(_text(e.get("path")).startswith("entityLookup") for e in errors) else ""
        # Not read: any site may have a BGP peer, so any may learn routes.
        bgp = f"{_BGP_NOTE} (BGP peers were not read)" if self.raw.get("bgp_peers") is None else ""
        return bgp, ranges

    # ── Sites, Sockets and their links ─────────────────────────────────────

    def build_sites(self) -> None:
        ranges = self._ranges_by_site()
        self._ranges = ranges
        self._node(CLOUD_NODE_ID, "cloud", "Cato Cloud", CLOUD_SITE_ID, "online", model="Cato backbone")
        for site in sorted(self.sites_raw, key=lambda s: _text((s.get("info") or {}).get("name")).lower()):
            site_id = _text(site["id"])
            info = site.get("info") or {}
            name = _text(info.get("name")) or f"Site {site_id}"
            status = _status(site.get("connectivityStatus"))
            members = self._site_devices(site, site_id, name, status)

            sections: list[dict] = []
            ha = _obj(site.get("haStatus"))
            _add(
                sections,
                kv_section(
                    "Site overview",
                    [
                        ("Site", name),
                        ("Site ID", site_id),
                        ("Type", info.get("type")),
                        ("Connection", info.get("connType")),
                        ("Connectivity", site.get("connectivityStatus")),
                        ("Operational status", site.get("operationalStatus")),
                        ("PoP", site.get("popName")),
                        ("High availability", info.get("isHA")),
                        ("HA readiness", ha.get("readiness")),
                        ("HA WAN connectivity", ha.get("wanConnectivity")),
                        ("HA keepalive", ha.get("keepalive")),
                        ("HA Socket versions match", ha.get("socketVersion")),
                        ("Hosts seen", site.get("hostCount")),
                        ("City", info.get("cityName")),
                        ("State", info.get("countryStateName")),
                        ("Country", info.get("countryName") or info.get("countryCode")),
                        ("Address", info.get("address")),
                        ("Description", info.get("description")),
                        ("Connected since", site.get("connectedSince")),
                        ("Last connected", site.get("lastConnected")),
                    ],
                ),
            )
            site_ranges = sorted(ranges.get(site_id, []), key=lambda r: (r[2], r[0]))
            self.range_count += len(site_ranges)
            _add(sections, table_section(RANGE_SECTION_TITLE, RANGE_COLUMNS, site_ranges))
            _add(
                sections,
                table_section(
                    "Site interfaces",
                    ["Interface", "Role", "Destination", "Upstream", "Downstream"],
                    [
                        [
                            i.get("name") or i.get("id"),
                            i.get("wanRole"),
                            i.get("destType"),
                            _mbps(i.get("upstreamBandwidth")),
                            _mbps(i.get("downstreamBandwidth")),
                        ]
                        for i in info.get("interfaces") or []
                        if isinstance(i, dict)
                    ],
                ),
            )
            _add(
                sections,
                table_section(
                    "IPsec tunnel",
                    ["Cato IP", "Remote IP", "IKE version", "Primary", "Status"],
                    [
                        [
                            t.get("catoIP"),
                            t.get("remoteIP"),
                            t.get("ikeVersion"),
                            t.get("isPrimary"),
                            _tunnel_status(status, index),
                        ]
                        for index, t in enumerate(_ipsec_tunnels(info))
                    ],
                ),
            )
            bgp = table_section("BGP peers", BGP_COLUMNS, [_bgp_row(p) for p in self._bgp.get(site_id, [])])
            _add(sections, bgp)
            for member in members:
                _add(member["sections"], copy.deepcopy(bgp))
            self.sites.append(
                {
                    "id": site_id,
                    "name": name,
                    "tags": [],
                    "vpn_mode": "spoke",
                    "status": _worst([status, *(m["status"] for m in members)]),
                    "device_count": len(members),
                    "sections": sections,
                }
            )

    def _site_devices(self, site: dict, site_id: str, site_name: str, site_status: str) -> list[dict]:
        info = site.get("info") or {}
        devices = [d for d in site.get("devices") or [] if isinstance(d, dict)]
        site_pop = _text(site.get("popName"))
        members: list[dict] = []

        if not devices:
            # No Socket: the site is an IPsec / cloud connection to a PoP.
            ipsec = next(iter(_ipsec_tunnels(info)), {})
            node = self._node(
                f"s:{site_id}",
                "appliance",
                site_name,
                site_id,
                site_status,
                model=_text(info.get("connType")) or _text(info.get("type")),
                ip=_text(ipsec.get("remoteIP")),
                site_sections=True,
            )
            _add(
                node["sections"],
                kv_section(
                    "Overview",
                    [
                        ("Site", site_name),
                        ("Status", site_status),
                        ("Connection", info.get("connType")),
                        ("Type", info.get("type")),
                        ("PoP", site_pop),
                        ("Source", "Cato site without a Socket (connected to the PoP directly)"),
                    ],
                ),
            )
            self._gateway[site_id] = node["id"]
            tunnels = _ipsec_tunnels(info)
            if not site_pop or not tunnels:
                self._tunnel(node, site_name, [site_pop] if site_pop else [], site_status != "offline")
                self._pops[node["id"]] = [site_pop] if site_pop and site_status != "offline" else []
                return [node]
            self._ipsec_edges(node, site_name, site_pop, site_status, tunnels)
            # Routed by the PoP even when down: the trace stops at its tunnels.
            self._pops[node["id"]] = [site_pop]
            return [node]

        primary = next((d for d in devices if _is_primary(d)), devices[0])
        for index, device in enumerate(devices):
            socket = _obj(device.get("socketInfo"))
            connected = bool(device.get("connected"))
            status = "offline" if not connected else ("alerting" if site_status == "alerting" else "online")
            ident = _text(device.get("id")) or f"{site_id}:{index}"
            role = _text(device.get("haRole"))
            label = _text(device.get("name")) or site_name
            if len(devices) > 1 and role and role.lower() not in label.lower():
                label = f"{label} ({role.lower()})"
            serial = _text(socket.get("serial"))
            node = self._node(
                f"d:{ident}",
                "appliance",
                label,
                site_id,
                status,
                model=_text(socket.get("platform")) or _text(device.get("type")),
                serial=serial,
                ip=_text(device.get("internalIP")),
            )
            if device is primary:
                node["site_sections"] = True
                self._gateway[site_id] = node["id"]
            host = self.inventory.match(serial=serial, ips=[node["ip"]])
            if host:
                node["inventory"] = _inventory_ref(host)

            interfaces = [i for i in device.get("interfaces") or [] if isinstance(i, dict)]
            _add(
                node["sections"],
                kv_section(
                    "Overview",
                    [
                        ("Name", device.get("name")),
                        ("Status", status),
                        ("Site", site_name),
                        ("Model", node["model"]),
                        ("Serial", serial),
                        ("HA role", role),
                        ("Socket version", socket.get("version") or device.get("version")),
                        ("Internal IP", node["ip"]),
                        ("PoP", device.get("lastPopName") or site_pop),
                        ("Connected since", device.get("connectedSince")),
                        ("Last connected", device.get("lastConnected")),
                        ("Identifier", device.get("identifier")),
                    ],
                ),
            )
            _add(
                node["sections"],
                table_section(
                    "WAN links",
                    ["Interface", "Port", "Connected", "PoP", "Public IP", "Provider", "Tunnel uptime (s)", "Role"],
                    [
                        [
                            i.get("name") or i.get("id"),
                            i.get("physicalPort"),
                            bool(i.get("connected")),
                            i.get("popName"),
                            i.get("tunnelRemoteIP"),
                            _obj(i.get("tunnelRemoteIPInfo")).get("provider"),
                            i.get("tunnelUptime"),
                            _obj(i.get("info")).get("wanRole"),
                        ]
                        for i in interfaces
                    ],
                ),
            )
            if host:
                _add(
                    node["sections"],
                    kv_section(
                        "Plexus inventory",
                        [
                            ("Hostname", host.get("hostname")),
                            ("IP address", host.get("ip_address")),
                            ("Device type", host.get("device_type")),
                        ],
                    ),
                )
            self._wan_links(node, ident, interfaces)

            pops = sorted({_text(i.get("popName")) for i in interfaces if i.get("connected") and i.get("popName")})
            if not pops and connected:
                fallback = _text(device.get("lastPopName")) or site_pop
                pops = [fallback] if fallback else []
            self._tunnel(node, site_name, pops if connected else [], connected)
            self._pops[node["id"]] = pops if connected else []
            self._wans[node["id"]] = [
                (
                    _text(i.get("name")) or _text(i.get("id")) or f"wan{n + 1}",
                    _text(i.get("tunnelRemoteIP")),
                    bool(i.get("connected")),
                )
                for n, i in enumerate(interfaces)
                if i.get("connected") or _text(i.get("tunnelRemoteIP"))
            ]
            members.append(node)
        return members

    def _wan_links(self, node: dict, ident: str, interfaces: list[dict]) -> None:
        for index, iface in enumerate(interfaces):
            connected = bool(iface.get("connected"))
            address = _text(iface.get("tunnelRemoteIP"))
            if not connected and not address:
                continue  # an unused port, not a WAN link
            name = _text(iface.get("name")) or _text(iface.get("id")) or f"wan{index + 1}"
            remote = _obj(iface.get("tunnelRemoteIPInfo"))
            info = _obj(iface.get("info"))
            wan_id = f"w:{ident}:{_text(iface.get('id')) or index}"
            wan = self._node(
                wan_id,
                "wan",
                f"{name} {address}".strip(),
                node["site"],
                "online" if connected else "offline",
                ip=address,
                parent=node["id"],
            )
            _add(
                wan["sections"],
                kv_section(
                    "WAN link",
                    [
                        ("Socket", node["label"]),
                        ("Interface", name),
                        ("Port", iface.get("physicalPort")),
                        ("Connected", connected),
                        ("Public IP", address),
                        ("Provider", remote.get("provider")),
                        ("Location", [remote.get("city"), remote.get("countryName")]),
                        ("PoP", iface.get("popName")),
                        ("Role", info.get("wanRole")),
                        ("Upstream", _mbps(info.get("upstreamBandwidth"))),
                        ("Downstream", _mbps(info.get("downstreamBandwidth"))),
                        ("Tunnel uptime (s)", iface.get("tunnelUptime")),
                    ],
                ),
            )
            self._edge(wan_id, node["id"], "uplink", b_port=name, status="active" if connected else "failed")

    def _tunnel(self, node: dict, site_name: str, pops: list[str], connected: bool) -> None:
        """Join a site's device to the PoP(s) it is connected to. A device
        that is down keeps a (down) link to the cloud so it stays attached."""
        if not connected or not pops:
            state = "reachable" if connected else "unreachable"
            self._edge(node["id"], CLOUD_NODE_ID, "vpn", status=state, label="Cato tunnel")
            self._cloud_sites.append([site_name, node["label"], "connected" if connected else "disconnected"])
            return
        for pop in pops:
            self._edge(node["id"], self._pop_node(pop), "vpn", status="reachable", label="Cato tunnel")
            self._pop_sites.setdefault(pop, []).append([site_name, node["label"], "connected"])

    def _ipsec_edges(self, node: dict, site_name: str, pop: str, site_status: str, tunnels: list[dict]) -> None:
        """Join a site with no Socket to its PoP by one edge per IPsec tunnel,
        primary first: the tracer crosses the first one that is up, so the
        secondary carries the flow when the primary is down."""
        pop_id = self._pop_node(pop)
        found: list[tuple[str, str, str]] = []
        for index, tunnel in enumerate(tunnels):
            label = _tunnel_label(index)
            status = _tunnel_status(site_status, index)
            edge = self._edge(
                node["id"],
                pop_id,
                "vpn3p",
                status=status,
                label=label,
                a_port=_text(tunnel.get("remoteIP")),
                b_port=_text(tunnel.get("catoIP")),
            )
            if edge is not None:
                self._tunnel_of_edge[edge["id"]] = tunnel
            found.append((label, _text(tunnel.get("remoteIP")), status))
        self._ipsec[node["id"]] = found
        state = "disconnected" if site_status == "offline" else "connected"
        self._pop_sites.setdefault(pop, []).append([site_name, node["label"], state])

    # ── The Cato cloud: PoPs, backbone, remote users ───────────────────────

    def build_cloud(self) -> None:
        users = [u for u in self.raw.get("users") or [] if isinstance(u, dict)]
        include_users = bool((self.raw.get("options") or {}).get("include_users", True))
        connected = sorted(
            (u for u in users if _text(u.get("connectivityStatus")).lower() != "disconnected"), key=_user_sort_key
        )
        users_by_pop: dict[str, list[dict]] = {}
        for user in connected:
            pop = _text(user.get("popName"))
            users_by_pop.setdefault(pop, []).append(user)
            if pop:
                self._pop_node(pop)

        pop_rows: list[list[Any]] = []
        for node in [n for n in self.nodes.values() if n["id"].startswith("pop:")]:
            name = node["id"][len("pop:") :]
            site_rows = self._pop_sites.get(name, [])
            pop_users = users_by_pop.get(name, [])
            pop_rows.append([name, len({r[0] for r in site_rows}), len(pop_users)])
            _add(
                node["sections"],
                kv_section(
                    "Cato PoP",
                    [
                        ("PoP", name),
                        ("Sites connected", len({r[0] for r in site_rows})),
                        ("Remote users connected", len(pop_users)),
                        ("Connected from an office", sum(1 for u in pop_users if u.get("connectedInOffice"))),
                    ],
                ),
            )
            _add(node["sections"], table_section("Connected sites", ["Site", "Device", "State"], site_rows))
            if include_users:
                rows = [_user_row(u) for u in pop_users[:MAX_LISTED_USERS]]
                _add(node["sections"], table_section("Connected remote users", USER_COLUMNS, rows))
            self._edge(node["id"], CLOUD_NODE_ID, "vpn", status="reachable", label="Cato backbone")
            # The PoP's box: the PoP over the users connected to it.
            self.cloud_boxes.append(
                {
                    "id": _pop_site_id(name),
                    "name": node["label"],
                    "tags": [],
                    # Sorts the PoPs next to the cloud, ahead of the sites.
                    "vpn_mode": "hub",
                    "status": "online",
                    "device_count": 1 + (len(pop_users) if include_users else 0),
                    "sections": list(node["sections"]),
                }
            )

        if include_users:
            offices = self._offices_by_ip()
            for pop, pop_users in sorted(users_by_pop.items()):
                self._users_box(pop, pop_users, offices)

        cloud = self.nodes[CLOUD_NODE_ID]
        account = self.raw.get("account") or {}
        _add(
            cloud["sections"],
            kv_section(
                "Cato Cloud",
                [
                    ("Account", account.get("name")),
                    ("Account ID", account.get("id")),
                    ("Sites", len(self.sites_raw)),
                    ("PoPs in use", len(pop_rows)),
                    ("Remote users connected", len(connected) if include_users else ""),
                    ("Snapshot time", self.raw.get("timestamp")),
                ],
            ),
        )
        _add(cloud["sections"], table_section("PoPs in use", ["PoP", "Sites", "Remote users"], sorted(pop_rows)))
        _add(
            cloud["sections"],
            table_section("Sites without a PoP", ["Site", "Device", "State"], self._cloud_sites),
        )

    def _offices_by_ip(self) -> dict[str, str]:
        """Public address -> the site that answers on it, so a user connected
        from an office is told which one."""
        found: dict[str, str] = {}
        for site in self.sites_raw:
            info = site.get("info") or {}
            name = _text(info.get("name"))
            addresses = [t.get("remoteIP") for t in _ipsec_tunnels(info)]
            for device in site.get("devices") or []:
                if isinstance(device, dict):
                    interfaces = [i for i in device.get("interfaces") or [] if isinstance(i, dict)]
                    addresses += [i.get("tunnelRemoteIP") for i in interfaces]
            for address in addresses:
                if _text(address) and name:
                    found.setdefault(_text(address), name)
        return found

    def _users_box(self, pop: str, users: list[dict], offices: dict[str, str]) -> None:
        """A node per user connected to one PoP, in the PoP's box and linked
        to it. Users connected to no PoP get a box of their own, linked to
        the backbone."""
        target = f"pop:{pop}" if pop else CLOUD_NODE_ID
        site_id = _pop_site_id(pop) if pop else USERS_SITE_ID
        if not pop:
            self._no_pop_box(users)
        for index, user in enumerate(users):
            node_id = f"{USER_NODE_PREFIX}{_text(user.get('id')) or f'{pop}:{index}'}"
            if node_id in self.nodes:
                node_id = f"{node_id}:{index}"
            node = self._user_node(node_id, site_id, user, offices)
            self._edge(node_id, target, "vpn", status="reachable", label="Cato Client", a_port=node["ip"])
            self._users.append((node_id, node["ip"], pop))

    def _no_pop_box(self, users: list[dict]) -> None:
        sections: list[dict] = []
        _add(
            sections,
            kv_section(
                "Remote users",
                [
                    ("PoP", "None reported"),
                    ("Connected now", len(users)),
                    ("Connected from an office", sum(1 for u in users if u.get("connectedInOffice"))),
                    ("Source", "Users connected to Cato with the Cato Client when the collection ran"),
                ],
            ),
        )
        rows = [_user_row(u) for u in users[:MAX_LISTED_USERS]]
        _add(sections, table_section("Connected users", USER_COLUMNS, rows))
        self.cloud_boxes.append(
            {
                "id": USERS_SITE_ID,
                "name": "Remote users",
                "tags": [],
                # Sorts the users next to the cloud, ahead of the sites.
                "vpn_mode": "hub",
                "status": "online",
                "device_count": len(users),
                "sections": sections,
            }
        )

    def _user_node(self, node_id: str, site_id: str, user: dict, offices: dict[str, str]) -> dict:
        info = user.get("info") or {}
        remote = user.get("remoteIPInfo") or {}
        public_ip = _text(user.get("remoteIP")) or _text(remote.get("ip"))
        office = offices.get(public_ip, "")
        if office:
            origin = f"Office: {office}"
        elif user.get("connectedInOffice"):
            origin = "An office"
        else:
            origin = "Remote (not in an office)"
        pop = _text(user.get("popName"))
        label = _text(_user_name(user)) or _text(info.get("email")) or _text(user.get("deviceName")) or node_id
        node = self._node(
            node_id, "user", label, site_id, "online", model="Cato Client", ip=_text(user.get("internalIP"))
        )
        _add(
            node["sections"],
            kv_section(
                "Remote user",
                [
                    ("User", _user_name(user)),
                    ("Email", info.get("email")),
                    ("Phone", info.get("phoneNumber")),
                    ("User ID", user.get("id")),
                    ("Connectivity", user.get("connectivityStatus")),
                    ("Operational status", user.get("operationalStatus")),
                    ("Account status", info.get("status")),
                    ("Directory", info.get("origin")),
                    ("Authentication", info.get("authMethod")),
                ],
            ),
        )
        _add(
            node["sections"],
            kv_section(
                "Connecting from",
                [
                    ("Connected from", origin),
                    ("Public IP", public_ip),
                    ("ISP", remote.get("provider")),
                    ("City", remote.get("city")),
                    ("State", remote.get("state")),
                    ("Country", remote.get("countryName") or remote.get("countryCode")),
                    ("Coordinates", [remote.get("latitude"), remote.get("longitude")]),
                ],
            ),
        )
        _add(
            node["sections"],
            kv_section(
                "Connected to (Cato)",
                [
                    ("PoP", pop),
                    ("VPN IP", user.get("internalIP")),
                    ("Path", f"Cato Client > PoP {pop} > Cato backbone" if pop else ""),
                    ("Uptime (s)", user.get("uptime")),
                    ("Last connected", user.get("lastConnected")),
                ],
            ),
        )
        _add(
            node["sections"],
            kv_section(
                "Device",
                [
                    ("Device", user.get("deviceName")),
                    ("OS", [user.get("osType"), user.get("osVersion")]),
                    ("Cato Client version", user.get("version")),
                ],
            ),
        )
        recent = [c for c in user.get("recentConnections") or [] if isinstance(c, dict)]
        _add(
            node["sections"],
            table_section(
                "Recent connections",
                ["Last connected", "Duration (s)", "Device", "Interface", "PoP", "Public IP", "Location", "ISP"],
                [
                    [
                        c.get("lastConnected"),
                        c.get("duration"),
                        c.get("deviceName"),
                        c.get("interfaceName"),
                        c.get("popName"),
                        c.get("remoteIP"),
                        _place(c.get("remoteIPInfo")),
                        (c.get("remoteIPInfo") or {}).get("provider"),
                    ]
                    for c in recent
                ],
            ),
        )
        return node

    # ── Forwarding data ────────────────────────────────────────────────────

    def build_forwarding(self) -> None:
        """Ranges, users and the tunnels between the sites, the PoPs and the
        Cato Cloud; the Cloud's internet egress; the firewall policies on
        the PoPs and the Cloud; and notes for the routing data that was not
        collected."""
        site_names = {s["id"]: s["name"] for s in self.sites}

        def via(node_id: str) -> str:
            pops = self._pops.get(node_id) or []
            return f"pop:{pops[0]}" if pops else CLOUD_NODE_ID

        bgp_note, ranges_note = self._routing_notes()
        for node_id, pops in self._pops.items():
            node = self.nodes[node_id]
            block = new_block()
            for name, address, connected in self._wans.get(node_id, []):
                block["interfaces"].append(interface(name, "wan", ip=address, enabled=connected))
            for name, address, status in self._ipsec.get(node_id, []):
                block["interfaces"].append(interface(name, "tunnel", ip=address, enabled=status != "unreachable"))
            for row in self._ranges.get(node["site"], []):
                name = f"{row[1] or 'Range'} ({row[0]})"
                block["interfaces"].append(interface(name, "lan", cidr=row[0]))
                block["routes"].append(route(row[0], "connected", interface=name, source=f"Network range {row[1]}"))
            target = via(node_id)
            block["routes"].append(
                route(
                    "0.0.0.0/0",
                    "default",
                    peer={"org_node": target},
                    source=f"Cato tunnel to PoP {pops[0]}" if pops else "Cato tunnel to the Cato Cloud",
                )
            )
            # Cato reports no routes: a site with a BGP peer may learn more
            # specific ones than its ranges and the default route.
            if self._bgp.get(node["site"]):
                note(block, _BGP_NOTE)
            note(block, bgp_note)
            note(block, ranges_note)
            node["forwarding"] = block

        for node in self.nodes.values():
            if node["id"].startswith("pop:"):
                pop = node["id"].removeprefix("pop:")
                block = new_block()
                for site_id, gateway in self._gateway.items():
                    attached = pop in (self._pops.get(gateway) or [])
                    for row in self._ranges.get(site_id, []):
                        block["routes"].append(
                            route(
                                row[0],
                                "static",
                                peer={"org_node": gateway if attached else CLOUD_NODE_ID},
                                source=f"Range of {site_names.get(site_id, site_id)}"
                                + ("" if attached else ", over the Cato backbone"),
                            )
                        )
                for user_id, address, user_pop in self._users:
                    if canonical(address):
                        block["routes"].append(
                            route(
                                canonical(address),
                                "static",
                                peer={"org_node": user_id if user_pop == pop else CLOUD_NODE_ID},
                                source=f"Remote user {self.nodes[user_id]['label']}",
                            )
                        )
                block["routes"].append(
                    route("0.0.0.0/0", "default", peer={"org_node": CLOUD_NODE_ID}, source="Cato backbone")
                )
                node["forwarding"] = block
            elif node["kind"] == "user":
                block = new_block()
                if node["ip"]:
                    block["interfaces"].append(interface("Cato Client", "tunnel", ip=node["ip"], cidr=node["ip"]))
                    block["routes"].append(
                        route(
                            canonical(node["ip"]), "connected", interface="Cato Client", source="Address given by Cato"
                        )
                    )
                pop = next((p for u, _a, p in self._users if u == node["id"]), "")
                block["routes"].append(
                    route(
                        "0.0.0.0/0",
                        "default",
                        peer={"org_node": f"pop:{pop}" if pop else CLOUD_NODE_ID},
                        source=f"Cato Client tunnel to PoP {pop}" if pop else "Cato Client tunnel",
                    )
                )
                node["forwarding"] = block

        cloud = new_block()
        # Cato egresses to the internet from the PoP, behind a Cato public
        # address the API does not report: an interface with no address.
        cloud["interfaces"].append(interface("Internet", "wan"))
        for site_id, gateway in self._gateway.items():
            for row in self._ranges.get(site_id, []):
                cloud["routes"].append(
                    route(
                        row[0],
                        "static",
                        peer={"org_node": via(gateway)} if self._pops.get(gateway) else {"org_node": gateway},
                        source=f"Range of {site_names.get(site_id, site_id)}",
                    )
                )
        for user_id, address, user_pop in self._users:
            if canonical(address):
                cloud["routes"].append(
                    route(
                        canonical(address),
                        "static",
                        peer={"org_node": f"pop:{user_pop}" if user_pop else user_id},
                        source=f"Remote user {self.nodes[user_id]['label']}",
                    )
                )
        cloud["routes"].append(route("0.0.0.0/0", "default", interface="Internet", source="Cato internet egress"))
        cloud["nat"].append(
            nat(1, "interface_pat", name="Cato public address", original_src=[ANY], translated_src=["interface"])
        )
        self.nodes[CLOUD_NODE_ID]["forwarding"] = cloud

        # Cato enforces the account's policy at the PoP a flow enters by: the
        # rule sets go on every PoP, and on the Cloud for a Socket or user
        # attached to no PoP. The tracer applies them once per flow.
        policies, missing = self._firewall_policies()
        for node in self.nodes.values():
            if node["id"] == CLOUD_NODE_ID or node["id"].startswith("pop:"):
                block = node["forwarding"]
                note(block, ranges_note)
                block["policies"] = copy.deepcopy(policies)
                for name in missing:
                    note(block, name)

    def _firewall_policies(self) -> tuple[list[dict], list[str]]:
        """The account's firewall rule sets, and the names of those that
        were not collected."""
        book = self._address_book()
        policies: list[dict] = []
        missing: list[str] = []
        for key, name, applies, default in (
            # The WAN firewall is a whitelist: what no rule allows is blocked.
            ("wan_firewall", "WAN firewall rules", "wan_traffic", "deny"),
            # The Internet firewall is a blacklist: what no rule blocks is allowed.
            ("internet_firewall", "Internet firewall rules", "internet_traffic", "allow"),
        ):
            payload = self.raw.get(key)
            if isinstance(payload, dict):
                policies.append(_firewall_policy(name, applies, payload, book, default=default))
            else:
                missing.append(name)
        return policies, missing

    def _address_book(self) -> AddressBook:
        """The objects firewall rules name that stand for known addresses:
        sites, their ranges and interfaces, and connected users."""
        book: AddressBook = {field: {} for field in _RESOLVABLE}

        def add(field: str, keys: list[str], cidrs: list[str]) -> None:
            known = book[field]
            for key in keys:
                if not key or not cidrs:
                    continue
                if key not in known:
                    known[key] = list(cidrs)
                elif known[key] != cidrs:
                    known[key] = None  # a name several objects share

        site_names = {s["id"]: s["name"] for s in self.sites}
        for site_id, rows in self._ranges.items():
            site = site_names.get(site_id, site_id)
            add("site", [site_id, site.lower()], [r[0] for r in rows])
            for cidr, name, iface, *_rest in rows:
                add("siteNetworkSubnet", [f"{site} \\ {iface} \\ {name}".lower(), name.lower()], [cidr])
            for iface in dict.fromkeys(r[2] for r in rows if r[2]):
                cidrs = [r[0] for r in rows if r[2] == iface]
                add("networkInterface", [f"{site} \\ {iface}".lower(), iface.lower()], cidrs)
        for entity_id, (site_id, source, iface, cidr) in self._entities.items():
            if source == "Range":
                add("siteNetworkSubnet", [entity_id], [cidr])
            else:
                add("networkInterface", [entity_id], [r[0] for r in self._ranges.get(site_id, []) if r[2] == iface])
        # Cato does not list floating ranges; one may share a name with a range.
        book["floatingSubnet"] = book["siteNetworkSubnet"]
        for user in self.raw.get("users") or []:
            if isinstance(user, dict) and _text(user.get("connectivityStatus")).lower() != "disconnected":
                address = canonical(user.get("internalIP"))
                add("user", [_text(user.get("id")), _text(_user_name(user)).lower()], [address] if address else [])
        return book

    def build_edge_sections(self) -> None:
        titles = {"vpn": "Cato tunnel", "uplink": "WAN link"}
        for edge in self.edges:
            a, b = self.nodes[edge["a"]], self.nodes[edge["b"]]
            rows: list[tuple[str, Any]] = [("A end", a["label"]), ("B end", b["label"])]
            tunnel = self._tunnel_of_edge.get(edge["id"])
            if tunnel is not None:
                rows += [
                    ("Site IP", tunnel.get("remoteIP")),
                    ("Cato IP", tunnel.get("catoIP")),
                    ("IKE version", tunnel.get("ikeVersion")),
                    ("Primary", tunnel.get("isPrimary")),
                ]
            else:
                rows.append(("B port", edge.get("b_port")))
            rows += [("Status", edge.get("status")), ("Discovered via", "Cato API")]
            section = kv_section(edge.get("label") or titles.get(edge["kind"], "Link"), rows)
            edge["sections"] = [section] if section else []


def _in_box_as_lan(edge: dict, nodes: dict[str, dict]) -> dict:
    """A tunnel between two nodes of one box (a user and its PoP), for the
    layout: shaped like a cable, so the PoP sits over its users."""
    if nodes[edge["a"]]["site"] == nodes[edge["b"]]["site"]:
        return {**edge, "kind": "lan"}
    return edge


def build_snapshot(raw: dict, inventory: InventoryIndex | None = None) -> dict[str, Any]:
    """Build the positioned topology snapshot from raw collector output."""
    builder = _Builder(raw, inventory or InventoryIndex())
    builder.build_sites()
    builder.build_cloud()
    builder.build_forwarding()
    builder.build_edge_sections()

    cloud_members = [n for n in builder.nodes.values() if n["site"] == CLOUD_SITE_ID]
    sites = (
        builder.sites
        + builder.cloud_boxes
        + [
            {
                "id": CLOUD_SITE_ID,
                "name": "Cato Cloud",
                "tags": [],
                # Sorts the cloud ahead of the sites, like a VPN hub.
                "vpn_mode": "hub",
                "status": "online",
                "device_count": len(cloud_members),
                "sections": [],
            }
        ]
    )
    # Inside a PoP's box its users hang off the PoP as if cabled to it.
    _layout(sites, builder.nodes, [_in_box_as_lan(e, builder.nodes) for e in builder.edges])

    nodes = list(builder.nodes.values())
    for node in nodes:
        node.pop("parent", None)

    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in nodes:
        if node["kind"] == "wan" or node["kind"] in CLOUD_KINDS:
            continue
        by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
        by_status[node["status"]] = by_status.get(node["status"], 0) + 1
    edge_counts: dict[str, int] = {}
    for edge in builder.edges:
        edge_counts[edge["kind"]] = edge_counts.get(edge["kind"], 0) + 1

    account = raw.get("account") or {}
    users = [u for u in raw.get("users") or [] if isinstance(u, dict)]
    return {
        "schema": SCHEMA_VERSION,
        "provider": "cato",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": {
            "id": _s(account.get("id")),
            "name": account.get("name") or "Cato account",
            "url": "",
        },
        "summary": {
            "sites": len(builder.sites),
            "devices": sum(by_kind.values()),
            "devices_by_kind": by_kind,
            "devices_by_status": by_status,
            "external_neighbors": 0,
            "inventory_matches": sum(1 for n in nodes if n.get("inventory")),
            "lan_links": 0,
            "vpn_tunnels": edge_counts.get("vpn", 0) + edge_counts.get("vpn3p", 0),
            "wan_uplinks": edge_counts.get("uplink", 0),
            "vlans": builder.range_count,
            "remote_users": sum(1 for u in users if _text(u.get("connectivityStatus")).lower() != "disconnected"),
        },
        "collection": {
            "sources": ["Cato Networks API"],
            "stats": raw.get("stats") or {},
            "errors": raw.get("errors") or [],
            "options": raw.get("options") or {},
        },
        "sites": sites,
        "nodes": nodes,
        "edges": builder.edges,
    }
