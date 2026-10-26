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
connected users, global IP ranges, and the groups and users groups whose
members were read in full and are all such objects) are resolved; the rest
(hosts, applications, categories, countries, FQDN containers...) is kept in
the rule's ``unresolved`` list, so a flow such a rule may cover is reported
as unknown. A rule whose source or destination names only objects with no
address (a users group none of whose members is connected) matches no flow.
A policy that was not collected is a note on the PoPs and the Cloud instead.

Every other policy Cato's API has (WAN network, Socket LAN, TLS inspection,
client connectivity, IP allocation... ``collector.POLICIES``) is listed, not
applied: a table on the Cato Cloud, the rules of the site-scoped ones on the
Sockets of the sites they name, and the rules of the user-scoped ones that
name a remote user (by name or by users group) on that user. None of them
adds a route, a rule or a note to the forwarding data.

The Split Tunnel policy decides, per remote user, which traffic the Cato
Client sends into the tunnel and which leaves the device directly (out of
``DIRECT_INTERFACE``, the device's own network, which is not collected; the
interface carries the public address the Client connects from as its
``behind_ip`` when that address is a public one, so the trace can follow the
traffic to the device on the map that answers on it). The
first enabled rule that matches the user applies: by user (or users group,
when its members were read in full), OS, country and source network; no
match is all traffic to Cato. A rule that only may match (it names users
groups whose members were not read, managed networks, or an OS or country
Cato did not report) ahead of any that does leaves the choice undetermined,
unless the Client's report for the user's current device settles it
(``client_reports``): "Disabled" is all traffic to Cato, and "Admin
Defined" or "User Defined" decides the rule when only one rule that may
apply has that mode. A report never overrides a rule decided from the
configuration; one that disagrees is a plain note. "Route all
to Cato except" keeps the default route into the PoP and sends the
exceptions' global IP ranges out directly; "route only selected" sends
those ranges to the PoP and the default route out directly. What routes
cannot say (domain, FQDN and application destinations, web-only coverage, a
user-defined file, an undetermined rule, the policy not collected) is a
"Route table (...)" note, so a lookup only the default route answers is
unknown. A user in Office Mode is behind its site: the policy does not
apply, and a plain note says so.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.cato.client_reports import NOT_COLLECTED, ClientReports, describe
from netcontrol.integrations.cato.collector import POLICIES, POLICY_LISTS, PolicySpec
from netcontrol.integrations.cato.site_config import account_config_sections, site_config_sections
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


def _public_ip(user: dict) -> str:
    """The address the user's Cato Client connects from, as Cato sees it."""
    return _text(user.get("remoteIP")) or _text(_obj(user.get("remoteIPInfo")).get("ip"))


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
# several objects share. Only a group or users group can have no CIDRs (``[]``:
# its members were read and none has an address now).
AddressBook = dict[str, dict[str, list[str] | None]]
_RESOLVABLE = (
    "site",
    "siteNetworkSubnet",
    "networkInterface",
    "floatingSubnet",
    "user",
    "globalIpRange",
    "group",
    "usersGroup",
    "ipAddressRangeContainer",
)
# A group's member types (``GroupMemberRefType``) that are book entries.
_GROUP_MEMBER_FIELDS = {
    "SITE": "site",
    "SITE_NETWORK_SUBNET": "siteNetworkSubnet",
    "NETWORK_INTERFACE": "networkInterface",
    "FLOATING_SUBNET": "floatingSubnet",
    "GLOBAL_IP_RANGE": "globalIpRange",
}
# The containers an Internet firewall destination names (``containers {}``).
_CONTAINER_WORDS = {"ipAddressRangeContainer": "IP range container", "fqdnContainer": "FQDN container"}
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
    """The CIDRs of one object a rule names, by id and then by name;
    ``None`` when the object is not known (or its name is shared)."""
    known = book.get(field) or {}
    ref = ref if isinstance(ref, dict) else {"name": ref}
    for key in (_text(ref.get("id")), _text(ref.get("name")).lower()):
        found = known.get(key) if key else None
        if found is not None:
            return found
    return None


def _global_range_cidrs(item: dict) -> list[str]:
    """The networks of one global IP range object: its ``subnet`` when the
    range is one, else its ``ipRange`` (``from-to`` text, or one address or
    network); ``[]`` when neither can be read."""
    subnet = canonical(item.get("subnet"))
    if subnet:
        return [subnet]
    text = _text(item.get("ipRange")).replace(" ", "")
    if "-" in text:
        first, _sep, last = text.partition("-")
        try:
            return [
                str(n)
                for n in ipaddress.summarize_address_range(ipaddress.ip_address(first), ipaddress.ip_address(last))
            ]
        except TypeError, ValueError:
            return []
    single = canonical(text)
    return [single] if single else []


def _rule_addresses(endpoint: Any, book: AddressBook) -> tuple[list[str], list[str]]:
    """``(cidrs, unresolved)`` of a rule's source or destination.

    Cato matches a flow when any object listed matches, and an empty one is
    any address. As in ``forwarding._field``, a field Plexus cannot resolve
    in full is treated as any address with the names kept as unresolved, so
    a flow it might cover is reported as unknown, never as allowed. A field
    that names only objects with no address (a group none of whose members
    has one now) is ``([], [])``: no address at all."""
    endpoint = endpoint if isinstance(endpoint, dict) else {}
    cidrs: list[str] = []
    unresolved: list[str] = []
    named = False
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
    containers = _obj(endpoint.get("containers"))
    named_objects = [(field, word, endpoint.get(field)) for field, word in _OBJECT_WORDS.items()]
    named_objects += [(field, word, containers.get(field)) for field, word in _CONTAINER_WORDS.items()]
    for field, word, refs in named_objects:
        for ref in _items_of(refs):
            named = True
            found = _resolve(book, field, ref) if field in _RESOLVABLE else None
            if found is not None:
                cidrs += found
            else:
                unresolved.append(f"{word} {_ref_name(ref)}")
    for field, word in _TEXT_WORDS.items():
        unresolved += [f"{word} {_text(v)}" for v in _items_of(endpoint.get(field))]
    if unresolved:
        return [ANY], unresolved
    if named and not cidrs:
        return [], []
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


def _ordered_rules(payload: dict) -> list[tuple[int, dict]]:
    """``(index, rule)`` of a collected policy's rules, in Cato's order. A
    stable sort: rules without an index keep their place, after the rest,
    numbered by it."""
    items = [r for r in payload.get("rules") or [] if isinstance(r, dict)]

    def order(item: dict) -> tuple[int, int]:
        index = _text(item.get("index"))
        return (0, int(index)) if index.isdigit() else (1, 0)

    return [
        (int(_text(item.get("index"))) if _text(item.get("index")).isdigit() else position, item)
        for position, item in enumerate(sorted(items, key=order), start=1)
    ]


def _firewall_rules(payload: dict, book: AddressBook, *, directional: bool) -> list[dict]:
    """A Cato firewall policy's rules as forwarding rules, in Cato's order.

    ``directional`` (the WAN firewall): a rule applies from its source to its
    destination (``TO``), the other way (``FROM``), or both ways (``BOTH``,
    a second rule with the ends swapped). A rule matching on more services
    than one protocol is one rule per protocol, with the same index."""
    found: list[dict] = []
    for index, item in _ordered_rules(payload):
        src, unresolved_src = _rule_addresses(item.get("source"), book)
        dst, unresolved_dst = _rule_addresses(item.get("destination"), book)
        services, unresolved_service = _rule_service(item.get("service"))
        unresolved = unresolved_src + unresolved_dst + unresolved_service + _rule_context(item)
        if payload.get("reduced"):
            src, dst, unresolved = [ANY], [ANY], [*unresolved, _REDUCED]
        elif not src or not dst:
            # It names only objects with no address now: it matches no flow.
            continue
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


# ── Groups and users groups ────────────────────────────────────────────────


class GroupIndex:
    """The groups (or users groups) of the account as collected, found by
    id or by name. ``read`` is false when the list itself was not
    collected; a group's ``members`` is ``None`` when they were not read in
    full."""

    def __init__(self, raw: Any) -> None:
        self.read = isinstance(raw, list)
        self._by_key: dict[str, dict | None] = {}
        # The identities of each group's members, by the group's id(), once
        # asked for: a users group is matched against every connected user.
        self._keys: dict[int, set[str]] = {}
        for group in raw if isinstance(raw, list) else []:
            if not isinstance(group, dict):
                continue
            for key in (_text(group.get("id")), _text(group.get("name")).lower()):
                if key:
                    # A name several groups share finds none of them.
                    self._by_key[key] = None if key in self._by_key else group

    def __iter__(self) -> Iterator[dict]:
        seen: set[int] = set()
        for group in self._by_key.values():
            if group is not None and id(group) not in seen:
                seen.add(id(group))
                yield group

    def find(self, ref: Any) -> dict | None:
        ref = ref if isinstance(ref, dict) else {"name": ref}
        for key in (_text(ref.get("id")), _text(ref.get("name")).lower()):
            found = self._by_key.get(key) if key else None
            if found is not None:
                return found
        return None

    def members(self, ref: Any) -> list[dict] | None:
        """The members of the group ``ref`` names, or ``None`` when they are
        not known in full (the group is not listed, or its members were not
        read)."""
        members = (self.find(ref) or {}).get("members")
        return [m for m in members if isinstance(m, dict)] if isinstance(members, list) else None

    def member_keys(self, ref: Any) -> set[str] | None:
        """The identities (``_identity_keys``) of the members of the users
        group ``ref`` names, or ``None`` when they are not known in full."""
        group = self.find(ref)
        if group is None:
            return None
        keys = self._keys.get(id(group))
        if keys is None:
            members = self.members(group)
            if members is None:
                return None
            keys = {key for member in members for key in _identity_keys(member)}
            self._keys[id(group)] = keys
        return keys


def _identity_keys(member: dict) -> set[str]:
    """What identifies a users group member (``{id displayName email
    userId}``): its id, e-mail and lower-cased name, each tagged."""
    keys = {
        f"id:{_text(member.get('id'))}",
        f"email:{_text(member.get('email')).lower()}",
        f"name:{_text(member.get('displayName') or member.get('name')).lower()}",
    }
    return {k for k in keys if not k.endswith(":")}


def _user_keys(user: dict) -> set[str]:
    """What identifies a remote user of the account snapshot, as
    ``_identity_keys`` tags it: id, e-mail, name."""
    return _identity_keys(
        {"id": user.get("id"), "email": (user.get("info") or {}).get("email"), "name": _user_name(user)}
    )


def _member_of(groups: GroupIndex, ref: Any, user: dict) -> bool | None:
    """Whether ``user`` is a member of the users group ``ref`` names (by id,
    e-mail or name); ``None`` when its members are not known in full."""
    keys = groups.member_keys(ref)
    if keys is None:
        return None
    return bool(keys & _user_keys(user))


def _site_in_group(groups: GroupIndex, ref: Any, site_id: str, site_name: str) -> bool | None:
    """Whether a site is a member of the group ``ref`` names; ``None`` when
    its members are not known in full."""
    members = groups.members(ref)
    if members is None:
        return None
    return any(_text(m.get("type")).upper() == "SITE" and _names_object(m, site_id, site_name) for m in members)


def _keys(item: dict) -> list[str]:
    """The address book keys of an object: its id and lower-cased name."""
    return [_text(item.get("id")), _text(item.get("name")).lower()]


def _names_object(ref: Any, ident: str, name: str) -> bool:
    """Whether a reference names the object with ``ident`` or ``name``."""
    ref = ref if isinstance(ref, dict) else {"name": ref}
    return bool((ident and _text(ref.get("id")) == ident) or (name and _text(ref.get("name")).lower() == name.lower()))


# ── Split Tunnel policy ────────────────────────────────────────────────────

# The interface of a remote user's device that traffic the Split Tunnel
# policy keeps out of the tunnel leaves by: the device's own network, whose
# address and gateway are not collected. An interface with no address, like
# the Cloud's "Internet".
DIRECT_INTERFACE = "Local network (direct)"
# What a user's routing rests on that was not collected. A "Route table ("
# note makes a lookup only the default route answers unknown.
SPLIT_TUNNEL_NOTE = "Route table (Split Tunnel policy)"
_SPLIT_USER_DEFINED_NOTE = "Route table (Split Tunnel user-defined routing file)"
_SPLIT_WEB_ONLY_NOTE = "Route table (Split Tunnel web-only coverage: non-web traffic leaves the device directly)"
# Plain notes on the user's hop.
SPLIT_OFFICE_NOTE = "Split Tunnel policy does not apply in Office Mode: the site's configuration steers the traffic"
_SPLIT_LAN_NOTE = "Traffic to the device's local subnet stays on the LAN (the subnet is not collected)"

# A rule's ``action`` as its connection mode. EXCLUDE and INCLUDE are the
# spellings from before January 2026, which Cato still returns.
_SPLIT_MODES = {
    "ROUTE_ALL_TO_CATO_EXCEPT": "except",
    "EXCLUDE": "except",
    "ROUTE_ONLY_SELECTED": "only",
    "INCLUDE": "only",
    "OFF": "off",
    "USER_DEFINED": "user",
}
_SPLIT_MODE_WORDS = {
    "except": "Route all traffic to Cato except the exceptions",
    "only": "Route only the selected destinations to Cato",
    "off": "Off: all traffic to Cato",
    "user": "User-defined (a routing file the user uploads)",
}
# What a mode's destinations are, in the details and the notes.
_SPLIT_DESTINATIONS = {"except": "exceptions", "only": "selected destinations"}
_SPLIT_COVERAGE = {"ALL": "All traffic", "WEB_ONLY": "Web traffic only"}
_SPLIT_PRIORITY = {"LAN": "LAN", "TUNNEL": "Tunnel"}
SPLIT_TUNNEL_COLUMNS = [
    "#",
    "Rule",
    "Enabled",
    "Users",
    "Platforms",
    "Countries",
    "Source network",
    "Mode",
    "Destinations",
    "Coverage",
    "Routing priority",
]
# Cato's ``OperatingSystem`` enum, which a rule's ``platform`` lists. The
# user snapshot's ``osType`` is free text (``OS_WINDOWS``, ``OS_MAC``); the
# aliases are the spellings of it that name a value of the enum.
_OPERATING_SYSTEMS = ("ANDROID", "CHROMEOS", "EMBEDDED", "IOS", "LINUX", "MACOS", "WINDOWS")
_OS_ALIASES = {"MAC": "MACOS", "OSX": "MACOS", "MACOSX": "MACOS"}


def _os_key(raw: Any) -> str:
    """The ``OperatingSystem`` value an OS text names, or ``""``."""
    letters = "".join(c for c in _text(raw).upper() if c.isalpha())
    for key in (letters, letters.removeprefix("OS")):
        key = _OS_ALIASES.get(key, key)
        if key in _OPERATING_SYSTEMS:
            return key
    return ""


def _split_mode(item: dict) -> str:
    """A rule's connection mode (``except``, ``only``, ``off``, ``user``), or
    ``""`` for an action Plexus does not know."""
    return _SPLIT_MODES.get(_text(item.get("action")).upper(), "")


def _managed_unknown(missing: str = NOT_COLLECTED) -> str:
    """Why a rule's source network (any managed or unmanaged network) is not
    decided: Cato's API reports no managed networks. ``missing`` says why
    the Client's own report cannot settle it (``""``: a report is used)."""
    reason = "not reported by Cato's API"
    if missing:
        reason += f"; the Client's last report is {missing}"
    return f"whether the device is on a managed network is not known ({reason})"


def _split_match(
    item: dict, user: dict, *, reduced: bool, groups: GroupIndex | None = None, managed: str = ""
) -> tuple[str, str]:
    """Whether a Split Tunnel rule applies to a connected user, from what was
    collected: ``("yes", "")``, ``("no", "")`` or ``("maybe", why)``. A
    criterion that rests on data Plexus does not have (the members of a
    users group not read in full, managed networks, an OS or country Cato
    did not report) is never guessed. Every criterion must match; an empty
    one is any. ``managed`` is the why for a source network criterion
    (``_managed_unknown``)."""
    why: list[str] = []
    groups = groups or GroupIndex(None)
    source = _obj(item.get("source"))
    users = [u for u in _items_of(source.get("user")) if isinstance(u, dict)]
    named_groups = _items_of(source.get("usersGroup"))
    if users or named_groups:
        ident, name = _text(user.get("id")), _text(_user_name(user)).lower()
        named = any(_names_object(u, ident, name) for u in users)
        member = [_member_of(groups, g, user) for g in named_groups]
        if not named and True not in member:
            if all(m is False for m in member):
                return "no", ""
            if not groups.read:
                why.append("users groups are not collected")
            else:
                unknown = [_ref_name(g) for g, m in zip(named_groups, member, strict=True) if m is None]
                why.append(f"the members of users group {', '.join(unknown)} were not read")
    platforms = {_os_key(p) or _text(p).upper() for p in _items_of(item.get("platform"))}
    if platforms:
        os_key = _os_key(user.get("osType"))
        if not os_key:
            why.append("the device's OS is not known")
        elif os_key not in platforms:
            return "no", ""
    countries = [c for c in _items_of(item.get("country")) if isinstance(c, dict)]
    if reduced:
        why.append(f"its countries are not collected ({_REDUCED})")
    elif countries:
        remote = _obj(user.get("remoteIPInfo"))
        code, country = _text(remote.get("countryCode")).upper(), _text(remote.get("countryName")).lower()
        if not code and not country:
            why.append("the user's country is not known")
        elif not any(
            (code and _text(c.get("id")).upper() == code) or (country and _text(c.get("name")).lower() == country)
            for c in countries
        ):
            return "no", ""
    network = _text(_obj(item.get("sourceNetwork")).get("sourceNetworkType")).upper()
    if network in ("ANY_MANAGED_NETWORK", "ANY_UNMANAGED_NETWORK"):
        why.append(managed or _managed_unknown())
    elif network not in ("", "ANY"):
        why.append(f"source network {network.lower()} is not known")
    return ("maybe", ", ".join(why)) if why else ("yes", "")


# The Split Tunnel configuration a Client reports applying (the
# ``split_tunnel_configuration`` of its Client Connectivity Policy event), as
# the connection modes of the rules it can come from. "Disabled" is no
# exception: no rule matched, or the rule's action is OFF.
_REPORTED_MODES = {
    "disabled": ("off",),
    "admin defined": ("except", "only"),
    "user defined": ("user",),
}


def _rule_label(index: int, item: dict) -> str:
    return f"{index} {_text(item.get('name')) or f'Rule {index}'}"


def _split_choice(
    policy: dict,
    user: dict,
    groups: GroupIndex | None = None,
    report: dict | None = None,
    missing: str = NOT_COLLECTED,
) -> tuple[str, int, dict | None, str]:
    """The Split Tunnel rule that applies to a user: ``(state, index, rule,
    why)``. Cato checks the enabled rules top to bottom and the first that
    matches applies; no match is full tunnel. ``state`` is ``match``
    (``rule`` applies; ``why`` is empty, or says the Client's report decided
    it), ``none`` (no rule does), ``off`` (the policy is disabled),
    ``reported_off`` (``rule`` may apply, for ``why``, but the Client
    reported Split Tunnel "Disabled": all traffic to Cato) or ``maybe``
    (``rule`` may apply, for ``why``, ahead of any that does: which one
    applies is not known).

    ``report`` is the Client's report for the user's current device: when
    the configuration leaves the choice undetermined, the Split Tunnel
    configuration the Client applied settles it if only one rule that may
    apply has that mode. ``missing`` says why there is no report."""
    if policy.get("enabled", True) is False:
        return "off", 0, None, ""
    managed = _managed_unknown("" if report else missing)
    found: list[tuple[int, dict, str, str]] = []
    for index, item in _ordered_rules(policy):
        if item.get("enabled", True) is False:
            continue
        state, why = _split_match(item, user, reduced=bool(policy.get("reduced")), groups=groups, managed=managed)
        if state != "no":
            found.append((index, item, state, why))
        if state == "yes":
            break
    if not found:
        return "none", 0, None, ""
    index, item, state, why = found[0]
    if state == "yes":
        return "match", index, item, ""
    if report is None:
        return "maybe", index, item, why
    value, device, at = describe(report)
    modes = _REPORTED_MODES.get(value.lower())
    if modes is None:
        return "maybe", index, item, f'the Client reported Split Tunnel "{value}", which Plexus does not know'
    if modes == ("off",):
        return "reported_off", index, item, why
    candidates = [(i, rule) for i, rule, _state, _why in found if _split_mode(rule) in modes]
    if len(candidates) == 1:
        index, item = candidates[0]
        return "match", index, item, f'decided by the Client\'s report of Split Tunnel "{value}" on {device} at {at}'
    reported = f'the Client reported Split Tunnel "{value}" at {at}'
    if not candidates:
        return "maybe", index, item, f"{reported}, and no rule that may apply has that mode"
    names = ", ".join(_rule_label(i, rule) for i, rule in candidates)
    index, item = candidates[0]
    return "maybe", index, item, f"{reported}, and rules {names} could be the one applied"


def _report_disagrees(report: dict | None, item: dict) -> bool:
    """Whether a Client's report names a Split Tunnel configuration that the
    rule decided from the configuration cannot give."""
    if report is None:
        return False
    modes = _REPORTED_MODES.get(describe(report)[0].lower())
    return modes is not None and _split_mode(item) not in modes


def _split_destinations(item: dict, book: AddressBook) -> tuple[list[tuple[str, list[str]]], list[str], list[str]]:
    """``(ranges, unresolved, other)`` of a Split Tunnel rule's destinations:
    its global IP ranges with their CIDRs, the names of those Plexus cannot
    resolve (not collected, or a name several share), and what is no
    address (applications, domains, FQDNs)."""
    destination = _obj(item.get("destination"))
    ranges: list[tuple[str, list[str]]] = []
    unresolved: list[str] = []
    for ref in _items_of(destination.get("globalIpRange")):
        cidrs = _resolve(book, "globalIpRange", ref)
        if cidrs:
            ranges.append((_ref_name(ref), cidrs))
        else:
            unresolved.append(_ref_name(ref))
    other = [f"application {_ref_name(a)}" for a in _items_of(destination.get("application"))]
    other += [f"domain {_text(d)}" for d in _items_of(destination.get("domain")) if _text(d)]
    other += [f"FQDN {_text(f)}" for f in _items_of(destination.get("fqdn")) if _text(f)]
    return ranges, unresolved, other


def _global_range_texts(refs: Any, book: AddressBook) -> list[str]:
    """Global IP ranges a rule names, each with its CIDRs when known."""
    texts = []
    for ref in _items_of(refs):
        cidrs = _resolve(book, "globalIpRange", ref)
        name = _ref_name(ref)
        texts.append(f"{name} ({', '.join(cidrs)})" if cidrs else f"global IP range {name} (not resolved)")
    return texts


def _split_destination_texts(item: dict, book: AddressBook) -> list[str]:
    destination = _obj(item.get("destination"))
    _ranges, _unresolved, other = _split_destinations(item, book)
    return _global_range_texts(destination.get("globalIpRange"), book) + other


def _split_rule_row(index: int, item: dict, book: AddressBook) -> list[Any]:
    """One rule in the account's Split Tunnel policy table."""
    network = _text(_obj(item.get("sourceNetwork")).get("sourceNetworkType"))
    coverage = _text(item.get("coverage")).upper()
    priority = _text(item.get("routingPriority")).upper()
    return [
        index,
        item.get("name"),
        item.get("enabled", True) is not False,
        _rule_users(item),
        _any(_names(item.get("platform"))),
        _any(_names(item.get("country"))),
        network.replace("_", " ").lower().capitalize() if network else "",
        _SPLIT_MODE_WORDS.get(_split_mode(item)) or item.get("action"),
        _split_destination_texts(item, book),
        _SPLIT_COVERAGE.get(coverage, coverage),
        _SPLIT_PRIORITY.get(priority, priority),
    ]


# ── Every policy, as tables ────────────────────────────────────────────────

# The most names one cell lists; the rest are counted.
MAX_CELL_NAMES = 20
_EXTRA_WORDS = {"vlan": "VLAN", "mac": "MAC", "service": "service", "tlsInspectCategory": "TLS category"}


def _cap(texts: list[str]) -> list[str]:
    """``texts`` once each, at most ``MAX_CELL_NAMES`` of them and a count
    of the rest."""
    unique = list(dict.fromkeys(t for t in texts if t))
    if len(unique) > MAX_CELL_NAMES:
        return [*unique[:MAX_CELL_NAMES], f"… +{len(unique) - MAX_CELL_NAMES}"]
    return unique


def _any(texts: list[str], word: str = "Any") -> list[str] | str:
    return _cap(texts) or word


def _names(value: Any, word: str = "") -> list[str]:
    """The names of what a rule's field lists: object references (``{ id
    name }``) or plain values, each after ``word``."""
    return [f"{word} {name}".strip() for name in (_ref_name(v) for v in _items_of(value)) if name]


def _span(value: Any) -> str:
    span = _obj(value)
    first, last = _text(span.get("from")), _text(span.get("to"))
    return f"{first}-{last}" if first != last else first


def _endpoint_texts(endpoint: Any) -> list[str]:
    """What a rule's source, destination or application lists, as text."""
    endpoint = _obj(endpoint)
    texts = _names(endpoint.get("ip")) + _names(endpoint.get("subnet"))
    texts += [_span(s) for s in _items_of(endpoint.get("ipRange"))]
    for field, word in {**_OBJECT_WORDS, **_TEXT_WORDS, **_EXTRA_WORDS}.items():
        texts += _names(endpoint.get(field), word)
    containers = _obj(endpoint.get("containers"))
    for field, word in _CONTAINER_WORDS.items():
        texts += _names(containers.get(field), word)
    texts += _service_texts({"custom": endpoint.get("customService")})
    texts += _names(endpoint.get("customServiceIp"), "service")
    return _cap(texts)


def _service_texts(service: Any) -> list[str]:
    service = _obj(service)
    texts = _names(service.get("standard")) + _names(service.get("simple"))
    for custom in _items_of(service.get("custom")):
        custom = _obj(custom)
        ports = _names(custom.get("port")) + [_span(r) for r in _items_of(custom.get("portRange"))]
        texts.append(f"{_text(custom.get('protocol'))} {','.join(ports)}".strip())
    return _cap(texts)


def _rule_users(item: dict) -> list[str] | str:
    """Who a rule of a client policy applies to: users, users groups."""
    source = _obj(item.get("source"))
    texts = _names(source.get("user")) + _names(source.get("usersGroup"), "group")
    return _any(texts + _names(source.get("systemGroup"), "system group"), "Any user")


def _rule_sites(item: dict) -> list[str] | str:
    site = _obj(item.get("site"))
    return _any(_names(site.get("site")) + _names(site.get("group"), "group"), "All sites")


def _on(value: Any, word: str) -> str:
    return word if value is True else ""


def _app_control_rule(item: dict) -> dict:
    """The part of an application control rule its ``ruleType`` names."""
    kind = _text(item.get("ruleType")).upper()
    part = {"APPLICATION": "applicationRule", "DATA": "dataRule", "FILE": "fileRule"}.get(kind, "")
    return _obj(item.get(part)) or _obj(item.get("applicationRule") or item.get("dataRule") or item.get("fileRule"))


def _transport(value: Any) -> str:
    transport = _obj(value)
    roles = "/".join(
        r for r in (_text(transport.get(k)) for k in ("primaryInterfaceRole", "secondaryInterfaceRole")) if r
    )
    kind = _text(transport.get("transportType"))
    return f"{kind} (interfaces {roles})" if kind and roles else kind or roles


# A column of a policy's table: its title, and its cell from a rule and the
# address book.
Column = tuple[str, Callable[[dict, AddressBook], Any]]
_FIREWALL_COLUMNS: list[Column] = [
    ("Source", lambda r, _c: _any(_endpoint_texts(r.get("source")))),
    ("Destination", lambda r, _c: _any(_endpoint_texts(r.get("destination")))),
    ("Service", lambda r, _c: _any(_service_texts(r.get("service")))),
    ("Action", lambda r, _c: r.get("action")),
    ("Conditions", lambda r, _c: _cap(_rule_context(r))),
]
_CLIENT_COLUMNS: list[Column] = [
    ("Users", lambda r, _c: _rule_users(r)),
    ("Platforms", lambda r, _c: _any(_names(r.get("platform")))),
    ("Countries", lambda r, _c: _any(_names(r.get("country")))),
]
# The columns of each policy's table after "#", "Rule" and "Enabled". The
# Split Tunnel policy has a table of its own (``SPLIT_TUNNEL_COLUMNS``).
POLICY_COLUMNS: dict[str, list[Column]] = {
    "wan_firewall": [("Direction", lambda r, _c: r.get("direction")), *_FIREWALL_COLUMNS],
    "internet_firewall": _FIREWALL_COLUMNS,
    "anti_malware_file_hash": [
        ("Action", lambda r, _c: r.get("action")),
        ("File name", lambda r, _c: r.get("fileName")),
        ("SHA-256", lambda r, _c: r.get("sha256")),
        ("Expires", lambda r, _c: r.get("expirationDate")),
    ],
    "application_control": [
        ("Type", lambda r, _c: r.get("ruleType")),
        ("Source", lambda r, _c: _any(_endpoint_texts(_app_control_rule(r).get("source")))),
        ("Applications", lambda r, _c: _any(_endpoint_texts(_app_control_rule(r).get("application")))),
        (
            "Data and files",
            lambda r, _c: _cap(
                _names(_obj(_app_control_rule(r).get("dlpProfile")).get("contentProfile"), "DLP")
                + _names(_obj(_app_control_rule(r).get("dlpProfile")).get("edmProfile"), "EDM")
                + [
                    f"{_text(a.get('fileAttribute'))} {_text(a.get('operator'))} {_text(a.get('value'))}".strip()
                    for a in map(_obj, _items_of(_app_control_rule(r).get("fileAttribute")))
                ]
            ),
        ),
        ("Action", lambda r, _c: _app_control_rule(r).get("action")),
        ("Severity", lambda r, _c: _app_control_rule(r).get("severity")),
    ],
    "app_tenant_restriction": [
        ("Source", lambda r, _c: _any(_endpoint_texts(r.get("source")))),
        ("Application", lambda r, _c: _ref_name(r.get("application"))),
        (
            "Headers",
            lambda r, _c: _cap(
                [f"{_text(h.get('name'))}: {_text(h.get('value'))}" for h in map(_obj, _items_of(r.get("headers")))]
            ),
        ),
        ("Action", lambda r, _c: r.get("action")),
        ("Severity", lambda r, _c: r.get("severity")),
    ],
    "client_connectivity": [
        *_CLIENT_COLUMNS,
        ("Device posture", lambda r, _c: _cap(_names(r.get("device")))),
        ("Source ranges", lambda r, c: _cap(_global_range_texts(_obj(r.get("sourceRange")).get("globalIpRange"), c))),
        ("Origin", lambda r, _c: _cap(_names(r.get("connectionOrigin")))),
        ("Confidence", lambda r, _c: r.get("confidenceLevel")),
        ("Action", lambda r, _c: r.get("action")),
    ],
    "dynamic_ip_allocation": [
        *_CLIENT_COLUMNS,
        ("Device posture", lambda r, _c: _cap(_names(r.get("devicePostureProfile")))),
        ("Allocation ranges", lambda r, c: _cap(_global_range_texts(_obj(r.get("range")).get("globalIpRange"), c))),
    ],
    "private_access": [
        *_CLIENT_COLUMNS,
        ("Applications", lambda r, _c: _any(_names(_obj(r.get("applications")).get("application")))),
        ("Device posture", lambda r, _c: _cap(_names(r.get("device")))),
        ("Origin", lambda r, _c: _cap(_names(r.get("connectionOrigin")))),
        ("Schedule", lambda r, _c: _obj(r.get("schedule")).get("activeOn")),
        ("Action", lambda r, _c: _obj(r.get("action")).get("action")),
    ],
    "remote_port_fwd": [
        ("External IP", lambda r, _c: _ref_name(r.get("externalIp"))),
        ("External ports", lambda r, _c: _span(r.get("externalPortRange"))),
        ("Internal IP", lambda r, _c: r.get("internalIp")),
        ("Internal ports", lambda r, _c: _span(r.get("internalPortRange"))),
        ("Forward ICMP", lambda r, _c: r.get("forwardIcmp")),
        ("Restriction", lambda r, _c: r.get("restrictionType")),
        ("Remote IPs", lambda r, _c: _any(_endpoint_texts(r.get("remoteIPs")))),
    ],
    "sdp_static_ip_allocation": [
        ("Users", lambda r, _c: _rule_users(r)),
        ("IP", lambda r, _c: r.get("ip")),
    ],
    "site_web_proxy": [
        (
            "Sites",
            lambda r, _c: (
                "All sites" if r.get("shouldAssociateWithAllSites") else _cap(_names(r.get("associatedSite")))
            ),
        ),
        ("Proxy", lambda r, _c: ":".join(t for t in (_text(r.get("fqdn")), _text(r.get("port"))) if t)),
        ("Protocol", lambda r, _c: r.get("allowedDestinationProtocol")),
        ("Authentication", lambda r, _c: _obj(r.get("authenticationConfig")).get("method")),
        (
            "Traffic rules",
            lambda r, _c: _cap(
                [
                    f"{_text(t.get('name'))} ({_text(t.get('action'))})"
                    for t in (_obj(_obj(p).get("rule")) for p in _items_of(r.get("webProxyTraffic")))
                ]
            ),
        ),
    ],
    "socket_bypass": [
        ("Sites", lambda r, _c: _rule_sites(r)),
        ("Source", lambda r, _c: _any(_endpoint_texts(r.get("source")))),
        ("Destination", lambda r, _c: _any(_endpoint_texts(r.get("destination")))),
        ("Service", lambda r, _c: _any(_service_texts(r.get("service")))),
        ("Bypass ports", lambda r, _c: _cap(_names(_obj(r.get("action")).get("port")))),
        ("Exceptions", lambda r, _c: _cap(_names(r.get("exception")))),
    ],
    "socket_lan": [
        ("Sites", lambda r, _c: _rule_sites(r)),
        ("Direction", lambda r, _c: r.get("direction")),
        ("Transport", lambda r, _c: r.get("transport")),
        ("Source", lambda r, _c: _any(_endpoint_texts(r.get("source")))),
        ("Destination", lambda r, _c: _any(_endpoint_texts(r.get("destination")))),
        ("Service", lambda r, _c: _any(_service_texts(r.get("service")))),
        ("NAT", lambda r, _c: _text(_obj(r.get("nat")).get("natType")) if _obj(r.get("nat")).get("enabled") else "Off"),
        (
            "LAN firewall rules",
            lambda r, _c: _cap(
                [
                    f"{_text(f.get('name'))} ({_text(f.get('action'))})"
                    for f in (_obj(_obj(p).get("rule")) for p in _items_of(r.get("firewall")))
                ]
            ),
        ),
    ],
    "terminal_server": [
        ("Allowed host IP", lambda r, c: _global_range_texts(r.get("allowedHostIP"), c)),
        ("Excluded traffic", lambda r, c: _cap(_global_range_texts(r.get("excludeTraffic"), c))),
    ],
    "tls_inspect": [
        ("Source", lambda r, _c: _any(_endpoint_texts(r.get("source")))),
        ("Applications", lambda r, _c: _any(_endpoint_texts(r.get("application")))),
        ("Platforms", lambda r, _c: _any(_names(r.get("platform")))),
        ("Countries", lambda r, _c: _any(_names(r.get("country")))),
        ("Device posture", lambda r, _c: _cap(_names(r.get("devicePostureProfile")))),
        ("Untrusted certificate", lambda r, _c: r.get("untrustedCertificateAction")),
        ("Action", lambda r, _c: r.get("action")),
    ],
    "wan_network": [
        ("Type", lambda r, _c: r.get("ruleType")),
        ("Source", lambda r, _c: _any(_endpoint_texts(r.get("source")))),
        ("Destination", lambda r, _c: _any(_endpoint_texts(r.get("destination")))),
        ("Application", lambda r, _c: _any(_endpoint_texts(r.get("application")))),
        ("Bandwidth priority", lambda r, _c: _ref_name(r.get("bandwidthPriority"))),
        (
            "Route",
            lambda r, _c: _cap(
                _names(r.get("routeType"))
                + _names(_obj(r.get("configuration")).get("popLocation"), "PoP")
                + _names(_obj(r.get("configuration")).get("backhaulingSite"), "via site")
                + _names(_obj(r.get("configuration")).get("allocationIp"), "NAT IP")
            ),
        ),
        (
            "Transport",
            lambda r, _c: _cap(
                [
                    f"{word} {_transport(_obj(r.get('configuration')).get(field))}"
                    for word, field in (("primary", "primaryTransport"), ("secondary", "secondaryTransport"))
                    if _transport(_obj(r.get("configuration")).get(field))
                ]
            ),
        ),
        (
            "Optimizations",
            lambda r, _c: _cap(
                [
                    _on(_obj(r.get("configuration")).get("activeTcpAcceleration"), "TCP acceleration"),
                    _on(_obj(r.get("configuration")).get("packetLossMitigation"), "packet loss mitigation"),
                    _on(_obj(r.get("configuration")).get("preserveSourcePort"), "preserve source port"),
                ]
            ),
        ),
        ("Exceptions", lambda r, _c: _cap(_names(r.get("exceptions")))),
    ],
    "ztna_always_on": [
        ("Users", lambda r, _c: _rule_users(r)),
        ("Platforms", lambda r, _c: _any(_names(r.get("platform")))),
        ("Device posture", lambda r, _c: _cap(_names(r.get("devicePostureProfile")))),
        ("Action", lambda r, _c: r.get("action")),
        (
            "Settings",
            lambda r, _c: _cap(
                [
                    _on(r.get("allowFailOpen"), "fail open"),
                    (
                        "user bypass "
                        + " ".join(_text(_obj(r.get("bypassDuration")).get(k)) for k in ("time", "unit")).strip()
                    ).strip()
                    if r.get("allowUserBypass") is True
                    else "",
                    f"anti-tamper {_text(r.get('antiTamperMode'))}" if _text(r.get("antiTamperMode")) else "",
                ]
            ),
        ),
    ],
}
# Policies whose rules name sites: listed on the Sockets of those sites.
SITE_POLICIES = ("socket_lan", "socket_bypass", "site_web_proxy")
# Policies whose rules name remote users: listed on those users' nodes.
CLIENT_POLICIES = (
    "client_connectivity",
    "dynamic_ip_allocation",
    "sdp_static_ip_allocation",
    "ztna_always_on",
    "private_access",
)
CLIENT_POLICY_COLUMNS = ["Policy", "#", "Rule", "Enabled", "Applies", "Settings"]
SUB_POLICY_COLUMNS = ["Name", "Level", "Enabled", "Description"]
_LABELS = {spec.key: spec.label for spec in POLICIES}


def policy_title(key: str, payload: dict) -> str:
    """The title of a policy's table: "<label> policy", and whether it is
    turned off or was read with the reduced query."""
    title = f"{_LABELS[key]} policy"
    if payload.get("enabled", True) is False:
        title += " (disabled)"
    if payload.get("reduced"):
        title += " (reduced)"
    return title


def _policy_row(key: str, index: int, item: dict, book: AddressBook) -> list[Any]:
    """One rule in a policy's table: "#", "Rule", "Enabled" and the policy's
    own columns."""
    cells = [fn(item, book) for _name, fn in POLICY_COLUMNS[key]]
    return [index, item.get("name"), item.get("enabled", True) is not False, *cells]


def _policy_columns(key: str) -> list[str]:
    return ["#", "Rule", "Enabled", *(name for name, _fn in POLICY_COLUMNS[key])]


def _words(key: str) -> str:
    """``camelCase`` as words: ``dataControlEnabled`` -> ``Data control enabled``."""
    return re.sub(r"(?<!^)(?=[A-Z])", " ", key).lower().capitalize()


def _site_applies(key: str, item: dict, groups: GroupIndex, site_id: str, site_name: str) -> str:
    """Why a rule of a site-scoped policy applies to a site ("This site",
    "All sites", "Group X", "Group X: may apply ..."), or ``""``."""
    if key == "site_web_proxy":
        if item.get("shouldAssociateWithAllSites") is True:
            return "All sites"
        named = any(_names_object(s, site_id, site_name) for s in _items_of(item.get("associatedSite")))
        return "This site" if named else ""
    site = _obj(item.get("site"))
    sites, named_groups = _items_of(site.get("site")), _items_of(site.get("group"))
    if not sites and not named_groups:
        return "All sites"
    if any(_names_object(s, site_id, site_name) for s in sites):
        return "This site"
    found = ""
    for group in named_groups:
        member = _site_in_group(groups, group, site_id, site_name)
        if member:
            return f"Group {_ref_name(group)}"
        if member is None and not found:
            found = f"Group {_ref_name(group)}: may apply (its members were not read)"
    return found


def _user_applies(item: dict, user: dict, groups: GroupIndex) -> str:
    """Why a rule of a client policy applies to a remote user ("This user",
    "All users", "Group X", "Group X: may apply ..."), or ``""``."""
    source = _obj(item.get("source"))
    users = _items_of(source.get("user"))
    named_groups, system_groups = _items_of(source.get("usersGroup")), _items_of(source.get("systemGroup"))
    if not users and not named_groups and not system_groups:
        return "All users"
    if any(_names_object(u, _text(user.get("id")), _text(_user_name(user))) for u in users):
        return "This user"
    found = ""
    for group in named_groups:
        member = _member_of(groups, group, user)
        if member:
            return f"Group {_ref_name(group)}"
        if member is None and not found:
            found = f"Group {_ref_name(group)}: may apply (its members were not read)"
    if not found and system_groups:
        found = f"System group {_ref_name(system_groups[0])}: may apply (system groups are not collected)"
    return found


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
        # User node id -> the user as Cato reports it, for its Split Tunnel rule.
        self._user_raw: dict[str, dict] = {}
        # Range and interface entity id -> (site id, source, interface,
        # CIDR), for the objects firewall rules name by id.
        self._entities: dict[str, tuple[str, str, str, str]] = {}
        # The BGP peers of each site id; the IPsec tunnels of each IPsec
        # site's node as (name, remote IP, state); the tunnel behind each
        # IPsec tunnel edge id, for its details.
        self._bgp = self._bgp_by_site()
        self._ipsec: dict[str, list[tuple[str, str, str]]] = {}
        self._tunnel_of_edge: dict[str, dict] = {}
        # The groups and users groups rules name, with their members.
        self.groups = GroupIndex(raw.get("groups"))
        self.users_groups = GroupIndex(raw.get("user_groups"))
        # The Client Connectivity Policy reports of the users' devices.
        self.client_reports = ClientReports(raw.get("client_reports"))
        # The address book, built once the sites are (``_address_book``).
        self._book: AddressBook | None = None

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
                helper_fields = item.get("helperFields")
                helper = helper_fields if isinstance(helper_fields, dict) else {}
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
            node["sections"].extend(site_config_sections(self.raw.get("site_config"), site_id))
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
            # The site's configuration as Cato keeps it (ranges with DHCP,
            # hosts, Socket settings...), when it was collected.
            node["sections"].extend(site_config_sections(self.raw.get("site_config"), site_id, serial=serial))
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
                    ("Split Tunnel policy", self._split_state() if include_users else ""),
                    (
                        "Policies not collected",
                        [spec.label for spec in POLICIES if not self._policy_read(spec) and self._asked(spec.option)],
                    ),
                    ("Policies not asked for", [spec.label for spec in POLICIES if not self._asked(spec.option)]),
                    (
                        "Policies read with the reduced query",
                        [spec.label for spec in POLICIES if (self.raw.get(spec.key) or {}).get("reduced")],
                    ),
                    ("Snapshot time", self.raw.get("timestamp")),
                ],
            ),
        )
        _add(cloud["sections"], table_section("PoPs in use", ["PoP", "Sites", "Remote users"], sorted(pop_rows)))
        _add(
            cloud["sections"],
            table_section("Sites without a PoP", ["Site", "Device", "State"], self._cloud_sites),
        )
        self._policy_tables(cloud["sections"], include_users)
        # The account and its DHCP and DNS configuration, when collected.
        cloud["sections"].extend(account_config_sections(self.raw.get("site_config")))

    def _asked(self, option: str) -> bool:
        """Whether the build asked for what ``option`` governs."""
        return bool((self.raw.get("options") or {}).get(option, True))

    def _policy_read(self, spec: PolicySpec) -> bool:
        return isinstance(self.raw.get(spec.key), dict)

    def _policy_tables(self, sections: list[dict], include_users: bool) -> None:
        """A table per policy collected (the Split Tunnel policy, which the
        users' blocks apply, only with the users), its settings and its
        sub-policies."""
        book = self._address_book()
        sub_policies = {key for key, _field, _input in POLICY_LISTS}
        for spec in POLICIES:
            payload = self.raw.get(spec.key)
            if not isinstance(payload, dict) or (spec.key == "split_tunnel" and not include_users):
                continue
            title = policy_title(spec.key, payload)
            if spec.key == "split_tunnel":
                rows = [_split_rule_row(index, item, book) for index, item in _ordered_rules(payload)]
                _add(sections, table_section(title, SPLIT_TUNNEL_COLUMNS, rows))
            else:
                rows = [_policy_row(spec.key, index, item, book) for index, item in _ordered_rules(payload)]
                _add(sections, table_section(title, _policy_columns(spec.key), rows))
            attributes = _obj(payload.get("attributes"))
            _add(sections, kv_section(f"{spec.label} settings", [(_words(k), v) for k, v in attributes.items()]))
            listed = self.raw.get(f"{spec.key}_policies") if spec.key in sub_policies else None
            _add(
                sections,
                table_section(
                    f"{spec.label} sub-policies",
                    SUB_POLICY_COLUMNS,
                    [
                        [p.get("name"), p.get("policyLevel"), p.get("enabled"), p.get("description")]
                        for p in listed or []
                        if isinstance(p, dict)
                    ],
                ),
            )

    def _split_state(self) -> str:
        split = self.raw.get("split_tunnel")
        if not isinstance(split, dict):
            return "Not collected"
        if split.get("enabled", True) is False:
            return "Disabled: all traffic to Cato"
        count = len(_ordered_rules(split))
        return f"Enabled, {count} rule{'' if count == 1 else 's'}"

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
            self._user_raw[node_id] = user

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
        public_ip = _public_ip(user)
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
            node_id,
            "user",
            label,
            site_id,
            "online",
            model="Cato Client",
            ip=_text(user.get("internalIP")),
            # The name the device reports, which the path trace looks up in
            # the client tables of the network behind its public address.
            device_name=_text(user.get("deviceName")),
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
        _add(node["sections"], self.client_reports.section(user.get("id"), user.get("deviceName")))
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
        book = self._address_book()
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
                node["forwarding"] = self._user_forwarding(node, book)

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
        policies, missing = self._firewall_policies(book)
        for node in self.nodes.values():
            if node["id"] == CLOUD_NODE_ID or node["id"].startswith("pop:"):
                block = node["forwarding"]
                note(block, ranges_note)
                block["policies"] = copy.deepcopy(policies)
                for name in missing:
                    note(block, name)

    def _user_forwarding(self, node: dict, book: AddressBook) -> dict:
        """A remote user's block: its VPN address, and where the Cato Client
        sends the rest, as the Split Tunnel policy decides for this user
        (Cato's default, with no rule matching, is everything to Cato). The
        user's "Split Tunnel" section says which rule decided it."""
        user = self._user_raw.get(node["id"]) or {}
        block = new_block()
        if node["ip"]:
            block["interfaces"].append(interface("Cato Client", "tunnel", ip=node["ip"], cidr=node["ip"]))
            block["routes"].append(
                route(canonical(node["ip"]), "connected", interface="Cato Client", source="Address given by Cato")
            )
        pop = next((p for u, _a, p in self._users if u == node["id"]), "")
        to_cato = {"org_node": f"pop:{pop}" if pop else CLOUD_NODE_ID}
        rows: list[tuple[str, Any]] = []
        policy = self.raw.get("split_tunnel")
        full_tunnel = True
        if user.get("connectedInOffice"):
            # Behind the site: its configuration steers the traffic, not the policy.
            note(block, SPLIT_OFFICE_NOTE)
            rows.append(("Rule", "Office Mode: the policy does not apply"))
        elif not isinstance(policy, dict):
            note(block, SPLIT_TUNNEL_NOTE)
            rows.append(("Rule", "Not collected"))
        else:
            # Only a report for the device connected now speaks for this connection.
            report, current = self.client_reports.for_user(user.get("id"), user.get("deviceName"))
            report = report if current else None
            state, index, item, why = _split_choice(
                policy, user, self.users_groups, report, self.client_reports.missing
            )
            name = _text((item or {}).get("name")) or f"Rule {index}"
            if state == "off":
                rows.append(("Rule", "Policy disabled: all traffic to Cato"))
            elif state == "none":
                rows.append(("Rule", "No rule matches: all traffic to Cato"))
            elif state == "maybe":
                note(block, f"Route table (Split Tunnel rule {name} may apply: {why})")
                rows.append(("Rule", f"Undetermined: rule {index} {name} may apply ({why})"))
            elif state == "reported_off" and report is not None:
                value, device, at = describe(report)
                rows.append(
                    (
                        "Rule",
                        f'All traffic to Cato: the Client reported Split Tunnel "{value}" on {device} at {at} '
                        f"(rule {index} {name} would otherwise be undetermined: {why})",
                    )
                )
            elif item is not None:
                label = f"{index} {name} ({why})" if why else f"{index} {name}"
                full_tunnel = self._split_routes(
                    block, item, label, name, book, to_cato, rows, behind_ip=_public_ip(user)
                )
                if not why and _report_disagrees(report, item):
                    value, _device, at = describe(report or {})
                    note(
                        block,
                        f'The Client reported Split Tunnel "{value}" at {at}, which does not agree with rule {index} {name}',
                    )
        if full_tunnel:
            block["routes"].append(
                route(
                    "0.0.0.0/0",
                    "default",
                    peer=to_cato,
                    source=f"Cato Client tunnel to PoP {pop}" if pop else "Cato Client tunnel",
                )
            )
        _add(node["sections"], kv_section("Split Tunnel", rows))
        return block

    @staticmethod
    def _split_routes(
        block: dict,
        item: dict,
        label: str,
        name: str,
        book: AddressBook,
        to_cato: dict,
        rows: list[tuple[str, Any]],
        *,
        behind_ip: str = "",
    ) -> bool:
        """The routes and notes of the Split Tunnel rule that applies to a
        user; whether the default route still goes to Cato. Only global IP
        ranges become routes: a domain, FQDN or application destination, or
        a web-only coverage, is a note that leaves a default-route lookup
        unknown. The direct interface carries ``behind_ip``, the public
        address the Client connects from, when it is a public one."""
        mode = _split_mode(item)
        coverage = _text(item.get("coverage")).upper()
        priority = _text(item.get("routingPriority")).upper()
        rows += [
            ("Rule", label),
            ("Mode", _SPLIT_MODE_WORDS.get(mode) or item.get("action")),
            ("Coverage", _SPLIT_COVERAGE.get(coverage, coverage)),
            ("Routing priority", _SPLIT_PRIORITY.get(priority, priority)),
        ]
        if priority == "LAN":
            note(block, _SPLIT_LAN_NOTE)
        if mode == "off":
            return True
        if mode == "user":
            note(block, _SPLIT_USER_DEFINED_NOTE)
            return True
        if mode not in _SPLIT_DESTINATIONS:
            note(block, f"Route table (Split Tunnel rule {name}: action {_text(item.get('action')) or 'not set'})")
            return True
        word = _SPLIT_DESTINATIONS[mode]
        ranges, unresolved, other = _split_destinations(item, book)
        rows += [
            (word.capitalize(), _split_destination_texts(item, book)),
            ("DNS exclusions", [_text(d) for d in _items_of(_obj(item.get("dnsExclusion")).get("domain"))]),
        ]
        if other:
            note(block, f"Route table (Split Tunnel {word} by domain, FQDN or application)")
        for range_name in unresolved:
            note(block, f"Route table (Split Tunnel {word}: global IP range {range_name})")
        if coverage == "WEB_ONLY":
            note(block, _SPLIT_WEB_ONLY_NOTE)
        cidrs = list(dict.fromkeys(c for _n, found in ranges for c in found))
        direct = interface(DIRECT_INTERFACE, "wan", behind_ip=behind_ip)
        if mode == "except":
            if cidrs:
                block["interfaces"].append(direct)
            for cidr in cidrs:
                source = f"Split Tunnel rule {name}: exception"
                block["routes"].append(route(cidr, "static", interface=DIRECT_INTERFACE, source=source))
            return True
        block["interfaces"].append(direct)
        for cidr in cidrs:
            block["routes"].append(
                route(cidr, "static", peer=to_cato, source=f"Split Tunnel rule {name}: routed to Cato")
            )
        block["routes"].append(
            route(
                "0.0.0.0/0",
                "default",
                interface=DIRECT_INTERFACE,
                source=f"Split Tunnel rule {name}: everything else leaves the device directly",
            )
        )
        return False

    def _firewall_policies(self, book: AddressBook) -> tuple[list[dict], list[str]]:
        """The account's firewall rule sets, and the names of those that
        were not collected."""
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
        sites, their ranges and interfaces, connected users, the account's
        global IP ranges, and the groups, users groups and IP range
        containers whose members are known in full and all resolve. Built
        once, after the sites (every caller runs after ``build_sites``)."""
        if self._book is not None:
            return self._book
        book: AddressBook = {field: {} for field in _RESOLVABLE}

        def add(field: str, keys: list[str], cidrs: list[str], *, empty: bool = False) -> None:
            """``empty``: the object may stand for no address at all."""
            known = book[field]
            for key in keys:
                if not key or not (cidrs or empty):
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
        connected = [
            u
            for u in self.raw.get("users") or []
            if isinstance(u, dict) and _text(u.get("connectivityStatus")).lower() != "disconnected"
        ]
        for user in connected:
            address = canonical(user.get("internalIP"))
            add("user", [_text(user.get("id")), _text(_user_name(user)).lower()], [address] if address else [])
        # None when not collected: a rule naming one stays unresolved.
        for item in self.raw.get("global_ip_ranges") or []:
            if isinstance(item, dict):
                add(
                    "globalIpRange", [_text(item.get("id")), _text(item.get("name")).lower()], _global_range_cidrs(item)
                )
        # A group resolves member by member through the entries above; one
        # member Plexus cannot turn into addresses (a host, a device, a VLAN,
        # an object not collected) leaves the whole group unresolved.
        for group in self.groups:
            members = self.groups.members(group)
            found: list[str] = []
            for member in members if members is not None else [None]:
                field = _GROUP_MEMBER_FIELDS.get(_text((member or {}).get("type")).upper(), "")
                resolved = _resolve(book, field, member) if field else None
                if resolved is None:
                    break
                found += resolved
            else:
                add("group", _keys(group), list(dict.fromkeys(found)), empty=True)
        # A users group is the VPN addresses of its members that are
        # connected, when the users were read and so were its members.
        if self._users_read():
            addressed = [(canonical(u.get("internalIP")), _user_keys(u)) for u in connected]
            for group in self.users_groups:
                keys = self.users_groups.member_keys(group)
                if keys is not None:
                    found = [address for address, user_keys in addressed if address and keys & user_keys]
                    add("usersGroup", _keys(group), list(dict.fromkeys(found)), empty=True)
        # Cato hands out a container's contents only as a file: one whose
        # ``members`` (CIDRs or ranges) are known resolves, the rest stays
        # unresolved.
        for container in self.raw.get("containers") or []:
            members = container.get("members") if isinstance(container, dict) else None
            if isinstance(members, list) and "Fqdn" not in _text(container.get("__typename")):
                parsed = [_global_range_cidrs({"ipRange": _span(m) if isinstance(m, dict) else m}) for m in members]
                if all(parsed):
                    add("ipAddressRangeContainer", _keys(container), [c for p in parsed for c in p], empty=True)
        self._book = book
        return book

    def _users_read(self) -> bool:
        """Whether the remote users were collected (asked for and read)."""
        if not (self.raw.get("options") or {}).get("include_users", True):
            return False
        errors = [e for e in self.raw.get("errors") or [] if isinstance(e, dict)]
        return not any(_text(e.get("path")) == "accountSnapshot.users" for e in errors)

    def build_policies(self) -> None:
        """The rules of the site-scoped policies on the Sockets of the sites
        they apply to, and the rules of the client policies on the remote
        users they apply to. Listed only: no forwarding data comes of them."""
        book = self._address_book()
        site_names = {s["id"]: s["name"] for s in self.sites}
        for key in SITE_POLICIES:
            payload = self.raw.get(key)
            if not isinstance(payload, dict):
                continue
            columns = ["#", "Rule", "Enabled", "Applies", *_policy_columns(key)[3:]]
            for site_id, site_name in site_names.items():
                rows = []
                for index, item in _ordered_rules(payload):
                    applies = _site_applies(key, item, self.groups, site_id, site_name)
                    if applies:
                        row = _policy_row(key, index, item, book)
                        rows.append([*row[:3], applies, *row[3:]])
                section = table_section(f"{policy_title(key, payload)}: rules for this site", columns, rows)
                for node in self.nodes.values():
                    if section and node["site"] == site_id and node["id"].startswith("d:"):
                        _add(node["sections"], copy.deepcopy(section))
        for node_id, user in self._user_raw.items():
            rows = []
            for key in CLIENT_POLICIES:
                payload = self.raw.get(key)
                if not isinstance(payload, dict):
                    continue
                names = [name for name, _fn in POLICY_COLUMNS[key] if name != "Users"]
                for index, item in _ordered_rules(payload):
                    applies = _user_applies(item, user, self.users_groups)
                    if applies:
                        cells = dict(zip(_policy_columns(key), _policy_row(key, index, item, book), strict=True))
                        settings = [f"{name}: {_s(cells[name])}" for name in names if _s(cells[name])]
                        rows.append(
                            [_LABELS[key], index, item.get("name"), cells["Enabled"], applies, "; ".join(settings)]
                        )
            _add(self.nodes[node_id]["sections"], table_section("Client policies", CLIENT_POLICY_COLUMNS, rows))

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
    builder.build_policies()
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
