"""The tracer: a flow between two addresses, hop by hop, both ways.

``Tracer`` walks a flow over the merged topology graph (what
``GET /api/topology`` returns) using the ``forwarding`` block of each device
(``netcontrol.integrations.meraki.forwarding``), the cloud engines for VPCs
and VNets (``cloud``) and the blocks built for inventory hosts
(``inventory``). At every device it applies, in this order:

  1. destination NAT (a reply is translated back by the request's session)
  2. the rule sets applied to traffic coming in on that kind of interface
  3. the route lookup: longest prefix, then connected, static,
     policy-based, VPN and dynamic, default; then the lower metric
  4. the rule sets applied on the way out, and those applied to all traffic
     (FTD access control, which matches the zones of both interfaces)
  5. source NAT
  6. a policy-based VPN whose protected networks hold both ends, matched
     on the source as NAT left it (as on an ASA or FTD)
  7. the link on the map to the next device

A device with no forwarding data is passed over the shortest way on the map,
each such hop with one unknown item. What a device applies that was not
collected is listed: as unknown when the device would consult it for this
flow, else as a note the direction's summary repeats.

The replies are walked from the destination back, with the addresses the
request left with. Stateful rule sets accept them when the request passed
the same device; stateless ones are matched again. Comparing the two walks
tells whether routing is asymmetric.

Pure (no I/O): the API handler loads the graph, the snapshots, the cloud
engines and the inventory blocks.
"""

from __future__ import annotations

import heapq
import ipaddress
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any

from netcontrol.integrations.meraki.subnets import _GATEWAY_ORDER, _NOT_A_GATEWAY
from netcontrol.integrations.pathtrace.cloud import CloudAdapter
from netcontrol.integrations.pathtrace.model import (
    ACL,
    ALLOWED,
    BLOCKED,
    EPHEMERAL_PORTS,
    FULL,
    INFO,
    LINK,
    NAT,
    NONE,
    NOTE,
    OK,
    PART,
    PARTIAL,
    POLICY,
    ROUTE,
    UNKNOWN,
    Network,
    contains,
    cover,
    hop,
    is_default,
    item,
    longest_route,
    net,
    ports_match,
    protocol_match,
    show,
    verdict_of,
    worst,
)

MAX_HOPS = 32
PROTOCOLS = ("tcp", "udp", "icmp")
STATEFUL_REPLY = "Stateful: the reply of an allowed request is accepted."
_DOWN = ("unreachable", "failed")
_NO_TRAFFIC = ("management",)
_CLOUD_PROVIDERS = ("aws", "azure", "gcp")
# Cloud snapshot nodes the cloud engine does not stand for.
_NOT_CLOUD_HOPS = ("vpn_peer", "external", "appliance", "user", "users")
_VERDICT_RANK = {BLOCKED: 3, UNKNOWN: 2, PARTIAL: 1, ALLOWED: 0}
_ALLOWING = ("allow", "trust", "fastpath", "analyze")

# Rule sets a device consults that may be missing from its block, with when
# it consults them and the stage of the item. A missing one the flow meets
# makes that item unknown; any other missing entry is a note.
_MISSING_SETS = {
    "Layer 3 firewall rules": ("lan_in", POLICY),
    "Inbound firewall rules": ("wan_in", POLICY),
    "Site-to-site VPN firewall rules": ("vpn_out", POLICY),
    "Prefilter rules": ("any", POLICY),
    "Access control rules": ("any", POLICY),
    "Security rules": ("any", POLICY),
    "Switch ACL": ("any", ACL),
    "WAN firewall rules": ("wan_traffic", POLICY),
    "Internet firewall rules": ("internet_traffic", POLICY),
    # An Appgate Gateway's entitlements, applied to every flow it forwards.
    "Entitlements": ("any", POLICY),
    "Allowed destinations": ("any", POLICY),
}
_STATELESS_MISSING = ("Switch ACL",)
# Destination NAT a flow from the WAN may meet.
_MISSING_NAT = ("NAT rules", "1:1 NAT", "Port forwarding", "1:Many NAT")
# Source NAT a flow leaving on the WAN may meet: an MX in routed mode hides
# the source behind its uplink address, and only its collected deployment
# mode says whether it is in that mode.
_MISSING_SNAT = ("Uplink NAT (deployment mode)",)
# Nothing at all is known beyond the device: delivery there is not checked.
_DELIVERY_NOTES = ("Everything behind a non-Meraki VPN peer",)
_ROUTE_NOTE_PREFIXES = (
    "Routes learned by",
    "Static routes and dynamic routing",
    "Route table (",
    "Policy-based routes",
    "Routes past the first",
    "Static route to ",
    "Everything behind a non-Meraki VPN peer",
)
# Words kept capitalised in the middle of a sentence.
_PROPER = ("Layer", "Cato", "Meraki", "BGP", "OSPF", "EIGRP", "NAT", "ACL", "WAN", "VPN", "1:1", "1:Many")

_NAT_KINDS = {
    "one_to_one": "1:1 NAT",
    "port_forward": "Port forwarding",
    "one_to_many": "1:Many NAT",
    "vpn_nat": "VPN subnet translation",
    "interface_pat": "Uplink NAT",
    "auto": "Auto NAT",
    "manual_before": "Manual NAT",
    "manual_after": "Manual NAT after auto NAT",
    "pre_rule": "NAT pre-rule",
    "post_rule": "NAT post-rule",
}
_MERAKI_DNAT = ("one_to_one", "port_forward", "one_to_many")
_LINK_WORDS = {
    "vpn": "VPN tunnel",
    "vpn-ipsec": "IPsec tunnel",
    "lldp": "LAN link",
    "cdp": "LAN link",
    "wan": "WAN uplink",
    "cloud": "Cloud attachment",
    "stack": "Stack link",
}
_PROVIDER_NAMES = {
    "meraki": "Meraki organization",
    "fmc": "Cisco FMC",
    "cato": "Cato account",
    "panorama": "Palo Alto Panorama",
    "appgate": "Appgate SDP",
}


@dataclass(frozen=True)
class Flow:
    """The packet as a device sees it: addresses after any NAT so far."""

    src: Network
    dst: Network
    protocol: str
    src_ports: tuple[int, int] | None
    dst_ports: tuple[int, int] | None


@dataclass
class _Arrival:
    """How the flow reaches the next hop."""

    node: Any
    edge: Any = None
    first: bool = False
    kind: str = ""  # "vpn" or "wan" when known from the way it arrives
    label: str = ""  # the hop's "in"
    via_ip: str = ""  # the next-hop address the previous device sent it to
    interface: str = ""  # the ingress interface, when the way it arrives names it
    address: str = ""  # the previous device's address towards this hop
    prev: Any = None


@dataclass
class _Hop:
    """What the steps of one device hop share."""

    hop: dict
    items: list[dict]
    ingress: dict | None
    kind: str
    in_zone: str
    missing: list[str]
    used: set[str]
    fastpath: bool = False
    # The route item of a lookup that only a default route answered while
    # learned routes are not collected, with its text before that was said.
    default_lookup: tuple[dict, str] | None = None


@dataclass
class _Walk:
    reply: bool
    dest: Any
    flow: Flow
    sessions: dict[Any, list[dict]]
    request_nodes: set
    hops: list[dict] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    delivered: bool = False
    fallback: bool = False
    ended: bool = False
    # Account-wide rule sets already applied (or noted as not collected) in
    # this walk: (organization, rule set name) -> the label of that hop.
    applied: dict[tuple[int | None, str], str] = field(default_factory=dict)


# Address space that is never routed on the internet. The documentation
# ranges are left out on purpose: samples and examples use them as public
# addresses.
_NOT_PUBLIC = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def _public(network: Network) -> bool:
    """Whether an address or network is reached over the internet."""
    return not any(n.version == network.version and n.overlaps(network) for n in _NOT_PUBLIC)


def _applies(applies: str, classes: set, dst: Network) -> bool:
    """Whether a rule set that ``applies`` to a class of traffic is
    consulted at a step that handles ``classes``. ``traffic`` is every flow
    a device takes in: a Cato WAN firewall applies to a private destination
    (``wan_traffic``), its Internet firewall to a public one
    (``internet_traffic``)."""
    if applies == "wan_traffic":
        return "traffic" in classes and not _public(dst)
    if applies == "internet_traffic":
        return "traffic" in classes and _public(dst)
    return applies in classes


def _account_wide(applies: str) -> bool:
    """Whether a rule set is one policy of a whole account, enforced once
    per flow (Cato's, at the PoP the flow enters by), rather than one of
    each device that carries it."""
    return applies in ("wan_traffic", "internet_traffic")


def _pair(a: Any, b: Any) -> frozenset:
    return frozenset((a, b))


def _blocked(items: list[dict]) -> bool:
    return any(i["status"] == BLOCKED for i in items)


def _not_collected(names: list[str]) -> str:
    """``routes learned by BGP are not collected``."""
    verb = "are" if len(names) > 1 or _plural(names[0]) else "is"
    return f"{', '.join(_sentence_item(n) for n in names)} {verb} not collected"


def _and(names: list[str]) -> str:
    """``A``, ``A and B``, ``A, B and C``."""
    if len(names) <= 1:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


_PLURAL_WORDS = ("rules", "routes", "policies", "lists", "ranges", "groups", "objects")


def _plural(name: str) -> bool:
    """Whether a not-collected entry reads as a plural (``rules are``)."""
    head = name.split(" (", 1)[0]
    return " and " in head or any(word in _PLURAL_WORDS for word in head.lower().split())


def _sentence_item(name: str) -> str:
    """``name`` as it reads in the middle of a sentence."""
    if not name or name.startswith(_PROPER) or (len(name) > 1 and name[1].isupper()):
        return name
    return name[0].lower() + name[1:]


def _route_note(name: str) -> bool:
    return name.startswith(_ROUTE_NOTE_PREFIXES)


def _iface_class(interface: dict | None) -> str:
    kind = (interface or {}).get("kind") or ""
    if kind == "wan":
        return "wan"
    if kind == "tunnel":
        return "vpn"
    return "lan"


def _zones(zones: list[str], zone: str) -> int:
    if not zones:
        return FULL
    if not zone:
        return PART
    return FULL if zone.lower() in {str(z).lower() for z in zones} else NONE


def _family(action: str) -> str:
    if action in _ALLOWING:
        return "allow"
    return "deny" if action == "deny" else action


def _describe(rule: dict) -> str:
    """``deny tcp 10.1.30.0/24 → 10.0.0.0/8 443``."""
    parts = [str(rule.get("action") or ""), str(rule.get("protocol") or "any")]
    src = ", ".join(rule.get("src") or ["any"])
    dst = ", ".join(rule.get("dst") or ["any"])
    if rule.get("src_ports") not in (None, "", "any"):
        src += f" port {rule['src_ports']}"
    parts.append(f"{src} → {dst}")
    parts.append(str(rule.get("dst_ports") or "any"))
    zones = []
    if rule.get("src_zones"):
        zones.append(f"from {', '.join(rule['src_zones'])}")
    if rule.get("dst_zones"):
        zones.append(f"to {', '.join(rule['dst_zones'])}")
    text = " ".join(parts)
    if zones:
        text += f", zones {' '.join(zones)}"
    return text


def _rule_name(rule: dict) -> str:
    name = str(rule.get("name") or "").strip()
    comment = str(rule.get("comment") or "").strip()
    label = f"Rule {rule.get('index')}"
    if name:
        label += f" {name}"
    detail = _describe(rule)
    if comment and comment != name:
        detail += f", {comment}"
    return f"{label} ({detail})"


def _translate(network: Network, original: list[str], translated: list[str], interface_ip: str) -> Network | None:
    """``network`` after a NAT rule mapping ``original`` to ``translated``:
    a range maps address by address onto a range of the same size; a single
    address takes everything; ``["interface"]`` is ``interface_ip``."""
    target = str(translated[0]).strip().lower() if translated else ""
    if target == "interface":
        return net(interface_ip) if interface_ip else None
    mapped = net(target)
    if mapped is None:
        return None
    if mapped.prefixlen == mapped.max_prefixlen:
        return mapped
    base = next((n for n in (net(c) for c in original) if n is not None and contains(n, network)), None)
    if base is None or base.prefixlen != mapped.prefixlen or base.version != mapped.version:
        return mapped
    offset = int(network.network_address) - int(base.network_address)
    return ipaddress.ip_network((int(mapped.network_address) + offset, network.prefixlen))


def _port_of(raw: Any) -> tuple[int, int] | None:
    text = str(raw or "").strip()
    return (int(text), int(text)) if text.isdigit() else None


class Tracer:
    """A path tracer over one merged topology graph."""

    def __init__(
        self,
        graph: dict,
        snapshots: dict[int, dict],
        clouds: dict[int, Any],
        host_forwarding: dict[int, dict],
        subnets: list[dict],
    ) -> None:
        self.nodes: dict[Any, dict] = {n["id"]: n for n in graph.get("nodes") or [] if isinstance(n, dict)}
        self.snapshots = snapshots
        self.host_forwarding = host_forwarding
        self.subnets = [s for s in subnets if isinstance(s, dict)]

        # Snapshot node -> graph node, through ``meraki`` and then ``also_refs``.
        self.graph_of: dict[tuple[int, str], Any] = {}
        self.refs_of: dict[Any, list[tuple[int, str, str]]] = {}
        for gid, node in self.nodes.items():
            ref = node.get("meraki")
            if isinstance(ref, dict):
                key = (int(ref["org_ref"]), str(ref["node_id"]))
                self.graph_of.setdefault(key, gid)
                self.refs_of.setdefault(gid, []).append((*key, str(ref.get("provider") or "meraki")))
        for gid, node in self.nodes.items():
            for ref in node.get("also_refs") or []:
                key = (int(ref["org_ref"]), str(ref["node_id"]))
                self.graph_of.setdefault(key, gid)
                self.refs_of.setdefault(gid, []).append((*key, str(ref.get("provider") or "")))

        self.snap_nodes: dict[tuple[int, str], dict] = {}
        self.gateways: dict[tuple[int, str], str] = {}
        self.site_names: dict[tuple[int, str], str] = {}
        for org_ref, snapshot in snapshots.items():
            ranks: dict[str, tuple[int, str]] = {}
            for node in snapshot.get("nodes") or []:
                if not isinstance(node, dict):
                    continue
                self.snap_nodes[(org_ref, node["id"])] = node
                kind, site = node.get("kind") or "", node.get("site") or ""
                if kind in _NOT_A_GATEWAY or not site:
                    continue
                rank = _GATEWAY_ORDER.index(kind) if kind in _GATEWAY_ORDER else len(_GATEWAY_ORDER)
                if site not in ranks or rank < ranks[site][0]:
                    ranks[site] = (rank, node["id"])
            for site, (_rank, node_id) in ranks.items():
                self.gateways[(org_ref, site)] = node_id
            for site in snapshot.get("sites") or []:
                self.site_names[(org_ref, site["id"])] = site.get("name") or site["id"]

        # Links that carry traffic, by pair, and the AutoVPN tunnels of each organization.
        self.between: dict[frozenset, list[dict]] = {}
        self.adjacency: dict[Any, list[tuple[Any, int, dict]]] = {}
        self.tunnels: dict[int, dict[Any, list[tuple[Any, dict]]]] = {}
        for edge in graph.get("edges") or []:
            a, b = edge.get("from"), edge.get("to")
            if a == b or a not in self.nodes or b not in self.nodes or edge.get("protocol") in _NO_TRAFFIC:
                continue
            self.between.setdefault(_pair(a, b), []).append(edge)
            if self._down(edge):
                continue
            cost = 2 if edge.get("protocol") == "vpn-ipsec" else 1
            self.adjacency.setdefault(a, []).append((b, cost, edge))
            self.adjacency.setdefault(b, []).append((a, cost, edge))
            parts = str(edge.get("id") or "").split(":")
            if edge.get("protocol") == "vpn" and len(parts) > 2 and parts[0] == "meraki":
                try:
                    org = int(parts[1])
                except ValueError:
                    continue
                self.tunnels.setdefault(org, {}).setdefault(a, []).append((b, edge))
                self.tunnels.setdefault(org, {}).setdefault(b, []).append((a, edge))

        # Forwarding data per graph node, and who answers on which address.
        self._blocks: dict[Any, tuple[dict | None, int | None]] = {}
        self.ip_owner: dict[str, list[Any]] = {}
        self.nat_owner: list[tuple[Network, Any]] = []
        for gid, node in self.nodes.items():
            block, _org = self.forwarding(gid)
            addresses = [str(i.get("ip") or "") for i in (block or {}).get("interfaces") or [] if isinstance(i, dict)]
            if isinstance(gid, int) and node.get("ip"):
                addresses.append(str(node["ip"]))
            for address in addresses:
                if address and gid not in self.ip_owner.setdefault(address, []):
                    self.ip_owner[address].append(gid)
            for entry in (block or {}).get("nat") or []:
                if not entry.get("translated_dst") or not entry.get("enabled", True):
                    continue
                for cidr in entry.get("original_dst") or []:
                    public = net(cidr) if str(cidr).lower() not in ("any", "interface") else None
                    if public is not None and public.prefixlen > 0:
                        self.nat_owner.append((public, gid))

        # The clouds, with the instances that are a device the trace follows itself.
        self.clouds: dict[int, CloudAdapter] = {}
        for org_ref, engine in clouds.items():
            snapshot = snapshots.get(org_ref) or {}
            # Every cloud snapshot names its provider; the org_ref fallback is for none.
            provider = str(snapshot.get("provider") or {-2: "azure", -3: "gcp"}.get(org_ref, "aws"))
            handoffs: dict[str, str] = {}
            for (ref_org, node_id), gid in self.graph_of.items():
                if ref_org == org_ref and node_id.startswith(("i:", "vm:")) and self.forwarding(gid)[0] is not None:
                    handoffs[node_id.split(":", 1)[1]] = str(self.nodes[gid].get("label") or gid)
            self.clouds[org_ref] = CloudAdapter(provider, org_ref, engine, snapshot, handoffs)

    # ── Lookups ────────────────────────────────────────────────────────────

    @staticmethod
    def _down(edge: dict) -> bool:
        return str(edge.get("status") or "").lower() in _DOWN

    def forwarding(self, gid: Any) -> tuple[dict | None, int | None]:
        """The forwarding block of a graph node and the organization it
        comes from: its own snapshot node's, else a node collapsed into it,
        else the inventory host's."""
        if gid in self._blocks:
            return self._blocks[gid]
        found: tuple[dict | None, int | None] = (None, None)
        for org_ref, node_id, _provider in self.refs_of.get(gid, []):
            block = (self.snap_nodes.get((org_ref, node_id)) or {}).get("forwarding")
            if isinstance(block, dict):
                found = (block, org_ref)
                break
        if found[0] is None and isinstance(gid, int) and isinstance(self.host_forwarding.get(gid), dict):
            found = (self.host_forwarding[gid], None)
        self._blocks[gid] = found
        return found

    def _cloud_of(self, gid: Any) -> tuple[CloudAdapter, str] | None:
        """The cloud a node stands for (a VPC or VNet, a transit gateway...)."""
        if gid is None or self.forwarding(gid)[0] is not None:
            return None
        for org_ref, node_id, _provider in self.refs_of.get(gid, []):
            adapter = self.clouds.get(org_ref)
            kind = (self.snap_nodes.get((org_ref, node_id)) or {}).get("kind")
            if adapter is not None and kind not in _NOT_CLOUD_HOPS:
                return adapter, node_id
        return None

    def _home_network(self, gid: Any) -> tuple[CloudAdapter, str] | None:
        """The cloud and VPC or VNet snapshot node of a device that is also an
        instance in it (a Meraki vMX, an FTDv, a Cato vSocket)."""
        for org_ref, node_id, _provider in self.refs_of.get(gid, []):
            adapter = self.clouds.get(org_ref)
            if adapter is None or not node_id.startswith(("i:", "vm:")):
                continue
            site = str((self.snap_nodes.get((org_ref, node_id)) or {}).get("site") or "")
            network = self.gateways.get((org_ref, site), "")
            if adapter.network_id(network):
                return adapter, network
        return None

    def _cloud_holding(self, address: Any, near: Any = None) -> tuple[CloudAdapter, str] | None:
        """The cloud whose collected subnets hold ``address``, and the graph
        node of its VPC or VNet. For ``near``, a device that is an instance
        in a cloud, its own VPC or VNet is looked in first: a range that
        several VPCs use (every default VPC has the same subnets) is
        ambiguous anywhere else."""
        home = self._home_network(near) if near is not None else None
        if home is not None:
            adapter, network = home
            try:
                place = adapter.locate(address, adapter.network_id(network))
            except ValueError:
                place = {"subnet": None}
            gid = self.graph_of.get((adapter.org_ref, network))
            if place["subnet"] is not None and gid is not None:
                return adapter, gid
        for adapter in self.clouds.values():
            try:
                place = adapter.locate(address)
            except ValueError:
                continue
            if place["subnet"] is not None:
                gid = self.graph_of.get((adapter.org_ref, adapter.network_node(place)))
                if gid is not None:
                    return adapter, gid
        return None

    def label(self, gid: Any) -> str:
        if gid is None:
            return "Internet"
        return str((self.nodes.get(gid) or {}).get("label") or gid)

    def _site(self, gid: Any) -> str:
        node = self.nodes.get(gid) or {}
        ref = node.get("meraki") or {}
        return str(ref.get("site_name") or node.get("group_name") or "")

    def _provider(self, gid: Any) -> str:
        node = self.nodes.get(gid) or {}
        ref = node.get("meraki")
        if isinstance(ref, dict):
            return str(ref.get("provider") or "meraki")
        if isinstance(gid, int) or node.get("in_inventory"):
            return "inventory"
        return "unknown"

    def _new_hop(self, gid: Any, edge: Any, ingress: str = "") -> dict:
        if gid is None:
            return hop(None, edge, "Internet", "", "internet", ingress)
        return hop(gid, edge, self.label(gid), self._site(gid), self._provider(gid), ingress)

    # ── Where an end is ────────────────────────────────────────────────────

    def _locate(self, network: Network, given: Any) -> dict[str, Any]:
        place: dict[str, Any] = {"address": show(network), "node": None, "ambiguous": []}
        if isinstance(given, str) and given.lstrip("-").isdigit() and given not in self.nodes:
            given = int(given)  # an inventory host's id, as a query string carries it
        if given is not None and given in self.nodes:
            place["node"] = given
            return place
        owners: list[Any] = []
        longest = -1
        for entry in self.subnets:
            cidr = net(entry.get("cidr"))
            if cidr is None or not contains(cidr, network):
                continue
            gid = self.graph_of.get((int(entry.get("org_ref", 0)), str(entry.get("node_id") or "")))
            if gid is None or cidr.prefixlen < longest:
                continue
            if cidr.prefixlen > longest:
                owners, longest = [], cidr.prefixlen
            if gid not in owners:
                owners.append(gid)
        if not owners and network.prefixlen == network.max_prefixlen:
            owners = list(self.ip_owner.get(show(network), []))
            if not owners:
                owners = list(dict.fromkeys(g for public, g in self.nat_owner if contains(public, network)))
        if len(owners) > 1:
            place["ambiguous"] = owners
        elif owners:
            place["node"] = owners[0]
        return place

    def _end(self, place: dict) -> dict[str, Any]:
        gid = place["node"]
        return {
            "address": place["address"],
            "node": gid,
            "label": self.label(gid) if gid is not None else "",
            "site": self._site(gid) if gid is not None else "",
        }

    # ── The trace ──────────────────────────────────────────────────────────

    def trace(
        self,
        source: str,
        destination: str,
        *,
        source_node: Any = None,
        destination_node: Any = None,
        protocol: str = "",
        port: int | None = None,
    ) -> dict[str, Any]:
        """Trace ``protocol``/``port`` from ``source`` to ``destination``
        (addresses or networks) and the replies. ``protocol`` ``""`` asks
        about any traffic."""
        protocol = str(protocol or "").strip().lower()
        protocol = "" if protocol in ("any", "all") else protocol
        if protocol and protocol not in PROTOCOLS:
            raise ValueError(f"protocol must be one of {', '.join(PROTOCOLS)}")
        src, dst = net(source), net(destination)
        for raw, parsed in ((source, src), (destination, dst)):
            if parsed is None:
                raise ValueError(f"{raw!r} is not an IP address or network")
        assert src is not None and dst is not None
        if src.version != dst.version:
            raise ValueError("source and destination must both be IPv4 or both be IPv6")
        ports = (port, port) if port is not None and protocol in ("tcp", "udp") else None
        ephemeral = EPHEMERAL_PORTS if protocol in ("tcp", "udp") else None
        flow = Flow(src, dst, protocol, ephemeral, ports)

        start, end = self._locate(src, source_node), self._locate(dst, destination_node)
        result: dict[str, Any] = {
            "applies": True,
            "traffic": "any traffic" if not protocol else protocol + (f"/{port}" if ports else ""),
            "source": self._end(start),
            "destination": self._end(end),
            "verdict": UNKNOWN,
            "summary": "",
            "asymmetric": {"status": "unknown", "text": "Not traced."},
            "request": {"verdict": UNKNOWN, "summary": "Not traced.", "hops": []},
            "reply": {"verdict": UNKNOWN, "summary": "Not traced.", "hops": []},
            "notes": [],
        }
        for place in (start, end):
            if place["ambiguous"]:
                where = ", ".join(sorted(self.label(g) for g in place["ambiguous"]))
                result["summary"] = (
                    f"{place['address']} is in several places ({where}). Pick the subnet of the one you mean."
                )
                return result
        if start["node"] is None and end["node"] is None:
            result["applies"] = False
            result["summary"] = "Neither address is in a collected subnet or on a device of the map."
            return result
        if start["node"] is None and not _public(src):
            result["summary"] = f"{start['address']} is not in a collected subnet, so the trace has no place to start."
            return result

        request = self._walk(
            _Arrival(node=start["node"], first=True), flow, reply=False, dest=end["node"], sessions={}, passed=set()
        )
        result["request"] = self._direction(request)
        if request.delivered:
            back = Flow(request.flow.dst, request.flow.src, protocol, request.flow.dst_ports, ephemeral)
            reply = self._walk(
                _Arrival(node=request.hops[-1]["node"], first=True),
                back,
                reply=True,
                dest=start["node"],
                sessions=request.sessions,
                passed={h["node"] for h in request.hops},
            )
            result["reply"] = self._direction(reply)
            result["asymmetric"] = self._asymmetry(request, reply)
        else:
            reply = None
            result["reply"]["summary"] = "Not traced: the request does not reach the destination."
            result["asymmetric"] = {
                "status": "unknown",
                "text": "The request does not reach the destination, so the replies were not traced.",
            }

        result["notes"] = list(dict.fromkeys(request.notes + (reply.notes if reply else [])))
        forward, backward = result["request"], result["reply"]
        if reply is None or _VERDICT_RANK[forward["verdict"]] >= _VERDICT_RANK[backward["verdict"]]:
            result["verdict"], result["summary"] = forward["verdict"], forward["summary"]
        else:
            result["verdict"], result["summary"] = backward["verdict"], f"Replies: {backward['summary']}"
        return result

    def _direction(self, walk: _Walk) -> dict[str, Any]:
        for each in walk.hops:
            each["status"] = worst([i["status"] for i in each["items"]])
        verdict, at, lead = verdict_of(walk.hops)
        if lead is not None and at is not None:
            where = f"{at['label']}, {lead['where']}" if lead["where"] else at["label"]
            if verdict == BLOCKED:
                summary = f"Blocked at {where}: {lead['text']}"
            elif verdict == UNKNOWN:
                summary = f"Could not be decided at {where}: {lead['text']}"
            else:
                summary = f"Allowed in part. {where}: {lead['text']}"
        elif not walk.delivered:
            verdict, summary = UNKNOWN, "The walk ended before the destination."
        else:
            path = " → ".join(h["label"] for h in walk.hops)
            summary = f"Every hop allows it: {path}."
        if walk.not_checked:
            names = list(dict.fromkeys(walk.not_checked))
            summary += " Not checked: " + ", ".join([names[0], *(_sentence_item(n) for n in names[1:])]) + "."
        return {"verdict": verdict, "summary": summary, "hops": walk.hops}

    def _asymmetry(self, request: _Walk, reply: _Walk) -> dict[str, str]:
        """Whether the replies pass the same devices as the request, in a
        sentence that names where the two ways part, then one sentence per
        side for the stateful firewalls that see only one of them."""
        if request.fallback or reply.fallback or not request.delivered or not reply.delivered:
            return {
                "status": "unknown",
                "text": "Part of a walk follows the links on the map or ended early, so whether the replies take the "
                "same hops back is not known.",
            }
        there = [h["node"] for h in request.hops]
        back = [h["node"] for h in reply.hops]
        if list(reversed(back)) == there:
            return {"status": "no", "text": "Replies take the same hops back."}
        expected = list(reversed(there))
        index = next(
            (i for i in range(min(len(back), len(expected))) if back[i] != expected[i]), min(len(back), len(expected))
        )
        source = show(reply.flow.src) if reply.hops else ""
        if index < len(back) and index < len(expected):
            text = f"Replies from {source} go from {self.label(back[index - 1]) if index else 'the destination'} to "
            text += f"{self.label(back[index])} instead of {self.label(expected[index])}, the way the request came."
        elif index == len(back):
            skipped = _and([self.label(g) for g in expected[index:]])
            text = f"Replies from {source} end at {self.label(back[-1])} and never pass {skipped}, "
            text += "which the request did."
        else:
            extra = _and([self.label(g) for g in back[index:]])
            text = f"Replies from {source} also pass {extra}, which the request did not."
        warnings = []
        unseen = [self.label(g) for g in back if g not in there and g is not None and self._stateful(g, there)]
        if unseen:
            verb, pronoun = ("has", "it") if len(unseen) == 1 else ("have", "they")
            warnings.append(
                f"{_and(unseen)} {verb} a stateful firewall that never saw the request: {pronoun} would drop the replies."
            )
        skipped_stateful = [self.label(g) for g in there if g not in back and g is not None and self._stateful(g, back)]
        if skipped_stateful:
            verb, pronoun = ("has", "its") if len(skipped_stateful) == 1 else ("have", "their")
            warnings.append(
                f"{_and(skipped_stateful)} {verb} a stateful firewall that sees the request but never the replies: "
                f"{pronoun} connection state never completes, so the rest of the connection can be dropped there."
            )
        return {"status": "yes", "text": " ".join([text, *warnings])}

    def _stateful(self, gid: Any, other_way: list) -> bool:
        """Whether a device's stateful firewall misses one direction of the
        connection. Not when all it applies is its account's policy, which
        keeps one state table, and a device of the same account is on the
        other direction's path."""
        block, org_ref = self.forwarding(gid)
        policies = [p for p in (block or {}).get("policies") or [] if isinstance(p, dict) and p.get("stateful", True)]
        if not policies:
            return False
        if all(_account_wide(str(p.get("applies") or "")) for p in policies):
            return not any(g is not None and self.forwarding(g)[1] == org_ref for g in other_way)
        return True

    # ── One direction ──────────────────────────────────────────────────────

    def _walk(self, start: _Arrival, flow: Flow, *, reply: bool, dest: Any, sessions: dict, passed: set) -> _Walk:
        walk = _Walk(reply=reply, dest=dest, flow=flow, sessions=sessions, request_nodes=passed)
        seen: set[tuple[Any, str]] = set()
        arrival: _Arrival | None = start
        for _count in range(MAX_HOPS):
            if arrival is None:
                return walk
            key = (arrival.node, show(walk.flow.dst))
            if key in seen and walk.hops:
                walk.hops[-1]["items"].append(
                    item(
                        ROUTE,
                        BLOCKED,
                        "Routing loop",
                        f"The flow comes back to {self.label(arrival.node)} with the same destination.",
                    )
                )
                walk.ended = True
                return walk
            seen.add(key)
            if arrival.node is None:
                arrival = self._internet(arrival, walk)
                continue
            cloud = self._cloud_of(arrival.node)
            if cloud is not None:
                arrival = self._cloud(arrival, walk, *cloud)
                continue
            block, org_ref = self.forwarding(arrival.node)
            if block is not None:
                arrival = self._device(arrival, walk, block, org_ref)
            else:
                self._fallback(arrival, walk)
                arrival = None
            if walk.delivered or walk.ended:
                return walk
        if walk.hops:
            walk.hops[-1]["items"].append(item(ROUTE, UNKNOWN, "Path trace", f"The trace stops after {MAX_HOPS} hops."))
        walk.ended = True
        return walk

    # ── A device with forwarding data ──────────────────────────────────────

    def _ingress(self, at: _Arrival, flow: Flow, interfaces: list[dict]) -> dict | None:
        def named(name: str) -> dict | None:
            return next((i for i in interfaces if i.get("name") == name), None)

        if at.interface and named(at.interface):
            return named(at.interface)
        if at.via_ip:
            found = next((i for i in interfaces if i.get("ip") == at.via_ip), None)
            if found:
                return found
        if at.kind == "wan":
            wans = [i for i in interfaces if i.get("kind") == "wan"]
            return next((i for i in wans if i.get("ip") == show(flow.dst)), None) or next(
                (i for i in wans if i.get("enabled", True)), None
            )
        if at.first:
            best: dict | None = None
            for interface in interfaces:
                if interface.get("ip") and interface["ip"] == show(flow.src):
                    return interface
                cidr = net(interface.get("cidr"))
                if cidr is not None and contains(cidr, flow.src):
                    if best is None or cidr.prefixlen > net(best["cidr"]).prefixlen:  # type: ignore[union-attr]
                        best = interface
            return best
        return named(at.label)

    def _device(self, at: _Arrival, walk: _Walk, block: dict, org_ref: int | None) -> _Arrival | None:
        gid = at.node
        current = self._new_hop(gid, at.edge)
        walk.hops.append(current)
        interfaces = [i for i in block.get("interfaces") or [] if isinstance(i, dict)]
        ingress = self._ingress(at, walk.flow, interfaces)
        ctx = _Hop(
            hop=current,
            items=current["items"],
            ingress=ingress,
            kind=at.kind or _iface_class(ingress),
            in_zone=str((ingress or {}).get("zone") or ""),
            missing=[str(n) for n in block.get("not_collected") or []],
            used=set(),
        )
        items = ctx.items
        current["in"] = at.label or (ingress or {}).get("name", "")
        vrf = str((ingress or {}).get("vrf") or "")

        # 1. NAT in: the session of the request for a reply, destination NAT for a request.
        if walk.reply:
            self._untranslate(gid, walk, items)
        else:
            self._dnat(gid, block, walk, ctx)
        if _blocked(items):
            return self._stop(walk, ctx)

        # 2. What the device applies to traffic coming in on that kind of interface.
        self._missing_sets(walk, ctx, {f"{ctx.kind}_in", "traffic"})
        self._sets(gid, block, walk, ctx, {f"{ctx.kind}_in", "traffic"}, "")
        if _blocked(items):
            return self._stop(walk, ctx)

        # Notes about what the device applies and Plexus does not collect.
        for name in ctx.missing:
            if (
                name in ctx.used
                or name in _MISSING_SETS
                or name in _MISSING_NAT
                or name in _MISSING_SNAT
                or _route_note(name)
            ):
                continue
            ctx.used.add(name)
            self._note(name, walk, items)

        # 3. The route lookup.
        flow = walk.flow
        if flow.dst.prefixlen == flow.dst.max_prefixlen:
            own = next((i for i in interfaces if i.get("ip") == show(flow.dst)), None)
            if own is not None:
                items.append(
                    item(ROUTE, OK, "Interfaces", f"{show(flow.dst)} is an address of this device ({own['name']}).")
                )
                walk.delivered = True
                self._leftover_notes(walk, ctx)
                return None
        route_notes = [n for n in ctx.missing if _route_note(n)]
        route, narrower = longest_route(block.get("routes") or [], flow.dst, vrf)
        if route is None:
            if route_notes:
                ctx.used.update(route_notes)
                items.append(
                    item(ROUTE, UNKNOWN, "Route table", f"No route to {show(flow.dst)}; {_not_collected(route_notes)}.")
                )
            else:
                items.append(item(ROUTE, BLOCKED, "Route table", f"No route to {show(flow.dst)}."))
            return self._stop(walk, ctx)
        source = str(route.get("source") or "Route table")
        if route.get("kind") == "blackhole":
            items.append(item(ROUTE, BLOCKED, source, f"{route['prefix']} is a blackhole route: the flow is dropped."))
            return self._stop(walk, ctx)
        split = [
            r
            for r in narrower
            if (r.get("next_hop"), r.get("peer"), r.get("interface"))
            != (route.get("next_hop"), route.get("peer"), route.get("interface"))
        ]
        if split:
            other = ", ".join(f"{r['prefix']} ({r.get('source') or r.get('kind')})" for r in split[:3])
            items.append(
                item(ROUTE, PARTIAL, "Route table", f"Part of {show(flow.dst)} is routed differently: {other}.")
            )
        egress = next((i for i in interfaces if route.get("interface") and i.get("name") == route["interface"]), None)

        if route.get("kind") == "connected":
            if egress is None:
                prefix = net(route.get("prefix"))
                egress = next((i for i in interfaces if net(i.get("cidr")) == prefix), None)
            name = (egress or {}).get("name") or route.get("interface") or route["prefix"]
            cloud = self._cloud_holding(flow.dst, gid) if self._cloud_of(gid) is None else None
            if cloud is not None and cloud[1] != gid:
                text = f"{route['prefix']} is connected on {name}: {show(flow.dst)} is in {self.label(cloud[1])}, "
                items.append(item(ROUTE, OK, source, text + "whose router takes it."))
                self._route_info(route_notes, walk, ctx)
                target = {"node": cloud[1], "out": name, "out_kind": "lan", "address": (egress or {}).get("ip") or ""}
                return self._leave(at, walk, block, ctx, egress, target, route)
            items.append(item(ROUTE, OK, source, f"{route['prefix']} is connected: delivered on {name}."))
            self._route_info(route_notes, walk, ctx)
            current["out"] = name
            self._missing_sets(walk, ctx, {"lan_out", "any"})
            self._sets(gid, block, walk, ctx, {"lan_out", "any"}, str((egress or {}).get("zone") or ""))
            for note_name in ctx.missing:
                if note_name in _DELIVERY_NOTES:
                    ctx.used.add(note_name)
                    text = f"{note_name} is not collected: whether it takes the flow is not known."
                    items.append(item(NOTE, UNKNOWN, note_name, text))
            if _blocked(items):
                return self._stop(walk, ctx)
            walk.delivered = True
            self._leftover_notes(walk, ctx)
            return None

        target = self._route_target(gid, org_ref, route, egress, interfaces, items, source)
        if is_default(route) and route_notes:
            # The route item of the lookup: unknown, since a learned route may be more specific.
            ctx.used.update(route_notes)
            lookup = next(i for i in reversed(items) if i["stage"] == ROUTE)
            ctx.default_lookup = (lookup, lookup["text"])
            lookup["status"] = UNKNOWN
            lookup["text"] += (
                f" Only the default route matches {show(flow.dst)}; {_not_collected(route_notes)}, "
                "so a more specific route may exist."
            )
        else:
            self._route_info(route_notes, walk, ctx)
        return self._leave(at, walk, block, ctx, target.get("egress", egress), target, route)

    def _stop(self, walk: _Walk, ctx: _Hop) -> _Arrival | None:
        walk.ended = True
        self._leftover_notes(walk, ctx)
        return None

    def _route_target(
        self,
        gid: Any,
        org_ref: int | None,
        route: dict,
        egress: dict | None,
        interfaces: list[dict],
        items: list[dict],
        source: str,
    ) -> dict:
        """Where a route sends the flow: ``node`` (a graph node; ``None`` when
        it is not on the map, and an item says so), or ``internet``. The
        hop still applies its egress steps to a flow it cannot follow."""
        prefix = route["prefix"]
        peer = route.get("peer") or {}
        if peer.get("site") and org_ref is not None:
            site = str(peer["site"])
            name = self.site_names.get((org_ref, site), site)
            target = self.graph_of.get((org_ref, self.gateways.get((org_ref, site), "")))
            if target is None:
                items.append(item(ROUTE, UNKNOWN, source, f"{prefix} over AutoVPN to {name}, which is not on the map."))
                return {"node": None, "out": f"AutoVPN to {name}", "out_kind": "vpn"}
            items.append(item(ROUTE, OK, source, f"{prefix} over AutoVPN to {name}."))
            return {"node": target, "site": name, "out": f"AutoVPN to {name}", "out_kind": "vpn", "autovpn": org_ref}
        if peer.get("org_node") and org_ref is not None:
            target = self.graph_of.get((org_ref, str(peer["org_node"])))
            if target is None:
                items.append(item(ROUTE, UNKNOWN, source, f"{prefix} to {peer['org_node']}, which is not on the map."))
                return {"node": None, "out": f"Tunnel to {peer['org_node']}", "out_kind": "vpn"}
            items.append(item(ROUTE, OK, source, f"{prefix} over the tunnel to {self.label(target)}."))
            return {"node": target, "out": f"Tunnel to {self.label(target)}", "out_kind": "vpn"}
        hop_ip = str(route.get("next_hop") or "")
        if hop_ip:
            if egress is None:
                address = ipaddress.ip_address(hop_ip)
                egress = next(
                    (
                        i
                        for i in interfaces
                        if net(i.get("cidr")) is not None
                        and net(i.get("cidr")).version == address.version  # type: ignore[union-attr]
                        and address in net(i.get("cidr"))  # type: ignore[operator]
                    ),
                    None,
                )
            on = f" on {egress['name']}" if egress else ""
            text = f"{prefix} via {hop_ip}{on}."
            out = (egress or {}).get("name") or hop_ip
            out_kind = _iface_class(egress)
            owners = [g for g in self.ip_owner.get(hop_ip, []) if g != gid]
            if owners:
                linked = [g for g in owners if _pair(gid, g) in self.between]
                items.append(item(ROUTE, OK, source, text))
                return {
                    "node": (linked or owners)[0],
                    "out": out,
                    "out_kind": out_kind,
                    "via_ip": hop_ip,
                    "egress": egress,
                }
            cloud = self._cloud_holding(hop_ip, gid)
            if cloud is not None and cloud[1] != gid:
                items.append(item(ROUTE, OK, source, f"{text[:-1]}, the router of {self.label(cloud[1])}."))
                return {
                    "node": cloud[1],
                    "out": out,
                    "out_kind": out_kind,
                    "address": (egress or {}).get("ip") or hop_ip,
                    "egress": egress,
                }
            if is_default(route) and out_kind == "wan":
                items.append(item(ROUTE, OK, source, f"{text[:-1]}: to the internet."))
                return {"internet": True, "out": out, "out_kind": "wan", "egress": egress}
            items.append(item(ROUTE, UNKNOWN, source, f"{text[:-1]}: next hop {hop_ip} is not a device on the map."))
            return {"node": None, "out": out, "out_kind": out_kind, "egress": egress}
        if egress is not None and egress.get("kind") == "wan" and is_default(route):
            items.append(item(ROUTE, OK, source, f"{prefix} out of {egress['name']}: to the internet."))
            return {"internet": True, "out": egress["name"], "out_kind": "wan", "egress": egress}
        where_to = f" out of {egress['name']}" if egress else ""
        items.append(item(ROUTE, UNKNOWN, source, f"{prefix}{where_to}: the device at the far end is not on the map."))
        return {
            "node": None,
            "out": (egress or {}).get("name") or "",
            "out_kind": _iface_class(egress),
            "egress": egress,
        }

    def _leave(
        self,
        at: _Arrival,
        walk: _Walk,
        block: dict,
        ctx: _Hop,
        egress: dict | None,
        target: dict,
        route: dict,
    ) -> _Arrival | None:
        """Steps 4 to 7 of a hop that forwards the flow: the rule sets on the
        way out, source NAT, then the policy-based VPN selectors, which see
        the addresses as NAT left them, then the link."""
        gid = at.node
        items = ctx.items
        out_name = (egress or {}).get("name") or ""
        ctx.hop["out"] = target.get("out") or out_name
        out_kind = "wan" if target.get("internet") else target.get("out_kind") or "lan"

        # 4. On the way out, and what applies to all traffic: the real
        # addresses, the zone of the interface the route chose.
        self._missing_sets(walk, ctx, {f"{out_kind}_out", "any"})
        self._sets(gid, block, walk, ctx, {f"{out_kind}_out", "any"}, str((egress or {}).get("zone") or ""))
        if _blocked(items):
            return self._stop(walk, ctx)

        # 5. Source NAT.
        before = walk.flow
        if not walk.reply:
            self._snat(gid, block, ctx, egress, out_kind, route, walk)

        # 6. A policy-based VPN on the egress interface. As on an ASA or FTD,
        # NAT comes first: the selectors see the translated source, which is
        # why a flow to a protected network needs a NAT exemption.
        flow = walk.flow
        selectors = [
            v for v in block.get("vpn") or [] if isinstance(v, dict) and v.get("interface") in ("", None, out_name)
        ]
        chosen = None
        for vpn in selectors:
            match = min(cover(vpn.get("local"), flow.src), cover(vpn.get("remote"), flow.dst))
            if match != NONE:
                chosen = (vpn, match)
                break
        if chosen is None and before.src != flow.src:
            for vpn in selectors:
                if min(cover(vpn.get("local"), before.src), cover(vpn.get("remote"), before.dst)) != NONE:
                    where = f"Site-to-site VPN {vpn.get('name') or ''}".strip()
                    text = (
                        f"The protected networks hold {show(before.src)}, but NAT made the source "
                        f"{show(flow.src)}, which they do not: the flow is not sent over the tunnel."
                    )
                    items.append(item(ROUTE, INFO, where, text))
                    break
        if chosen is not None:
            vpn, match = chosen
            where = f"Site-to-site VPN {vpn.get('name') or ''}".strip()
            peer = vpn.get("peer") or {}
            org_ref = self.forwarding(gid)[1]
            far = self.graph_of.get((org_ref, str(peer.get("org_node") or ""))) if org_ref is not None else None
            far_label = self.label(far) if far is not None else str(peer.get("org_node") or "its peer")
            status = str(vpn.get("status") or "unknown")
            if status == "down":
                text = f"The protected networks match, but the tunnel to {far_label} is down."
                items.append(item(ROUTE, BLOCKED, where, text))
                return self._stop(walk, ctx)
            text = f"The protected networks match: the flow goes over the tunnel to {far_label}"
            if ctx.default_lookup is not None and status == "up":
                # A default route and a crypto map is how a policy-based VPN is
                # built: the selector, not a learned route, says where the flow goes.
                lookup, base = ctx.default_lookup
                lookup["status"] = OK
                lookup["text"] = f"{base} The site-to-site VPN takes it from there."
            if status != "up":
                items.append(item(ROUTE, UNKNOWN, where, f"{text}, whose state is not known."))
            elif match == PART:
                items.append(item(ROUTE, PARTIAL, where, f"{text}. Only part of the traffic is protected."))
            else:
                items.append(item(ROUTE, OK, where, f"{text}."))
            if far is None:
                items.append(item(ROUTE, UNKNOWN, where, f"{far_label} is not on the map."))
                return self._stop(walk, ctx)
            name = str(vpn.get("name") or "").strip()
            target = {
                "node": far,
                "out": f"VPN {name} to {far_label}" if name else f"VPN to {far_label}",
                "out_kind": "vpn",
                "interface": self._tunnel_end(gid, far),
            }
            ctx.hop["out"] = target["out"]
            out_kind = "vpn"
        self._leftover_notes(walk, ctx)

        # 7. The link to the next device.
        if target.get("internet"):
            return _Arrival(node=None, kind="wan", label=ctx.hop["out"], prev=gid)
        nxt = target.get("node")
        if nxt is None:
            walk.ended = True
            return None
        if target.get("autovpn") is not None:
            return self._autovpn(gid, nxt, target, walk, items)
        edge_id, passable = self._link(gid, nxt, items, "vpn" if out_kind == "vpn" else "")
        if not passable:
            walk.ended = True
            return None
        return _Arrival(
            node=nxt,
            edge=edge_id,
            kind="vpn" if out_kind == "vpn" else "",
            label=f"Tunnel from {self.label(gid)}" if out_kind == "vpn" else "",
            via_ip=target.get("via_ip", ""),
            interface=target.get("interface", ""),
            address=target.get("address", ""),
            prev=gid,
        )

    def _tunnel_end(self, sender: Any, receiver: Any) -> str:
        """The interface a policy-based VPN from ``sender`` ends on at ``receiver``."""
        block, org_ref = self.forwarding(receiver)
        names = {node_id for ref, node_id, _p in self.refs_of.get(sender, []) if ref == org_ref}
        for vpn in (block or {}).get("vpn") or []:
            if isinstance(vpn, dict) and str((vpn.get("peer") or {}).get("org_node") or "") in names:
                return str(vpn.get("interface") or "")
        return ""

    def _autovpn(self, gid: Any, target: Any, info: dict, walk: _Walk, items: list[dict]) -> _Arrival | None:
        """Over AutoVPN tunnels that are up, through hubs when there is no direct one."""
        tunnels = self.tunnels.get(info["autovpn"], {})
        parent: dict[Any, tuple[Any, dict] | None] = {gid: None}
        queue = deque([gid])
        while queue:
            at = queue.popleft()
            if at == target:
                break
            for other, edge in tunnels.get(at, []):
                if other not in parent:
                    parent[other] = (at, edge)
                    queue.append(other)
        if target not in parent:
            down = [e for e in self.between.get(_pair(gid, target), []) if self._down(e)]
            state = f" (the direct tunnel is {down[0].get('status')})" if down else ""
            items.append(
                item(
                    LINK,
                    BLOCKED,
                    "AutoVPN",
                    f"No AutoVPN tunnel that is up joins {self.label(gid)} to {self.label(target)}{state}.",
                )
            )
            walk.ended = True
            return None
        path: list[tuple[Any, dict]] = []
        step: Any = target
        while parent[step] is not None:
            previous, edge = parent[step]  # type: ignore[misc]
            path.append((step, edge))
            step = previous
        path.reverse()
        site = info.get("site") or self.label(target)
        sender = gid
        for index, (node, edge) in enumerate(path):
            items.append(
                item(LINK, OK, f"Link to {self.label(node)}", f"AutoVPN tunnel, {edge.get('status') or 'up'}.")
            )
            if index == len(path) - 1:
                return _Arrival(
                    node=node,
                    edge=edge.get("id"),
                    kind="vpn",
                    label=f"AutoVPN from {self._site(gid) or self.label(gid)}",
                    prev=sender,
                )
            hub = self._new_hop(node, edge.get("id"), f"AutoVPN from {self._site(sender) or self.label(sender)}")
            hub["out"] = f"AutoVPN to {site}"
            hub["items"].append(item(ROUTE, INFO, "AutoVPN hub", f"AutoVPN hub, forwards to {site}."))
            walk.hops.append(hub)
            items = hub["items"]
            sender = node
        return None

    def _link(self, a: Any, b: Any, items: list[dict], prefer: str = "") -> tuple[Any, bool]:
        edges = self.between.get(_pair(a, b), [])
        where = f"Link to {self.label(b)}"
        if not edges:
            items.append(
                item(
                    LINK,
                    UNKNOWN,
                    where,
                    f"No link on the map between {self.label(a)} and {self.label(b)}; the route says otherwise.",
                )
            )
            return None, True
        up = [e for e in edges if not self._down(e)]
        if not up:
            states = ", ".join(sorted({str(e.get("status")) for e in edges}))
            items.append(
                item(
                    LINK, BLOCKED, where, f"Every link between {self.label(a)} and {self.label(b)} is down ({states})."
                )
            )
            return edges[0].get("id"), False
        chosen = next((e for e in up if prefer and str(e.get("protocol", "")).startswith(prefer)), up[0])
        word = _LINK_WORDS.get(str(chosen.get("protocol") or ""), f"{chosen.get('protocol') or 'Link'} link")
        state = str(chosen.get("status") or "up")
        items.append(item(LINK, OK, where, f"{word}, {state}."))
        return chosen.get("id"), True

    # ── Rule sets ──────────────────────────────────────────────────────────

    def _note(self, name: str, walk: _Walk, items: list[dict]) -> None:
        items.append(item(NOTE, INFO, name, "Not collected, so not checked."))
        walk.not_checked.append(name)

    def _route_info(self, route_notes: list[str], walk: _Walk, ctx: _Hop) -> None:
        for name in route_notes:
            if name not in ctx.used:
                ctx.used.add(name)
                self._note(name, walk, ctx.items)

    def _leftover_notes(self, walk: _Walk, ctx: _Hop) -> None:
        """Missing rule sets this flow did not need: notes (an account-wide
        one only at the first hop that carries it)."""
        for name in ctx.missing:
            if name not in ctx.used and (name in _MISSING_SETS or name in _MISSING_NAT or name in _MISSING_SNAT):
                ctx.used.add(name)
                if name in _MISSING_SETS and _account_wide(_MISSING_SETS[name][0]) and self._once(walk, ctx, name):
                    continue
                self._note(name, walk, ctx.items)

    def _once(self, walk: _Walk, ctx: _Hop, name: str) -> str:
        """For an account-wide rule set: the label of the hop of this walk
        that already applied it, else ``""`` and this hop is recorded as the
        one that does."""
        key = (self.forwarding(ctx.hop["node"])[1], name)
        if key in walk.applied:
            return walk.applied[key]
        walk.applied[key] = str(ctx.hop["label"])
        return ""

    def _missing_sets(self, walk: _Walk, ctx: _Hop, classes: set) -> None:
        for name in ctx.missing:
            if name in ctx.used or name not in _MISSING_SETS:
                continue
            applies, stage = _MISSING_SETS[name]
            if not _applies(applies, classes, walk.flow.dst):
                continue
            ctx.used.add(name)
            earlier = self._once(walk, ctx, name) if _account_wide(applies) else ""
            if earlier:
                ctx.items.append(item(stage, INFO, name, f"Already noted at {earlier}."))
                continue
            verb = "are" if _plural(name) else "is"
            if walk.reply and name not in _STATELESS_MISSING:
                text = f"{name} {verb} not collected; stateful: the replies follow the request."
                ctx.items.append(item(stage, INFO, name, text))
                walk.not_checked.append(name)
            else:
                they = "they allow" if _plural(name) else "it allows"
                text = f"{name} {verb} not collected: whether {they} this flow is not known."
                ctx.items.append(item(stage, UNKNOWN, name, text))

    def _sets(self, gid: Any, block: dict, walk: _Walk, ctx: _Hop, classes: set, out_zone: str) -> None:
        items = ctx.items
        for policy in block.get("policies") or []:
            if not isinstance(policy, dict) or not _applies(str(policy.get("applies") or ""), classes, walk.flow.dst):
                continue
            name = str(policy.get("name") or "Rule set")
            stage = ACL if policy.get("kind") == "acl" else POLICY
            if ctx.fastpath and policy.get("kind") == "firewall":
                items.append(item(stage, INFO, name, "Skipped: the prefilter fastpaths this flow."))
                continue
            account_wide = _account_wide(str(policy.get("applies") or ""))
            earlier = self._once(walk, ctx, name) if account_wide else ""
            if earlier:
                items.append(item(stage, INFO, name, f"Already applied at {earlier}."))
                continue
            if walk.reply and policy.get("stateful", True):
                # An account's policy keeps one state table across its devices.
                org_ref = self.forwarding(gid)[1]
                passed = (
                    any(self.forwarding(g)[1] == org_ref for g in walk.request_nodes)
                    if account_wide
                    else gid in walk.request_nodes
                )
                if passed:
                    items.append(item(stage, INFO, name, STATEFUL_REPLY))
                else:
                    items.append(
                        item(
                            stage,
                            UNKNOWN,
                            name,
                            "Stateful, and the request did not pass this device: it would drop the replies.",
                        )
                    )
                continue
            found, decided = self._evaluate(policy, walk.flow, ctx.in_zone, out_zone)
            items.extend(found)
            if decided == "fastpath":
                ctx.fastpath = True
            if any(i["status"] == BLOCKED for i in found):
                return

    def _evaluate(self, policy: dict, flow: Flow, in_zone: str, out_zone: str) -> tuple[list[dict], str]:
        """The items of one rule set and the action that decided."""
        name = str(policy.get("name") or "Rule set")
        stage = ACL if policy.get("kind") == "acl" else POLICY
        found: list[dict] = []
        decided: dict | None = None
        partly: list[dict] = []
        icmp = flow.protocol.startswith("icmp")
        rules = [r for r in policy.get("rules") or [] if isinstance(r, dict)]
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            match = min(
                protocol_match(rule.get("protocol"), flow.protocol),
                cover(rule.get("src"), flow.src),
                cover(rule.get("dst"), flow.dst),
                FULL if icmp else ports_match(rule.get("src_ports"), flow.src_ports),
                FULL if icmp else ports_match(rule.get("dst_ports"), flow.dst_ports),
                _zones(rule.get("src_zones") or [], in_zone),
                _zones(rule.get("dst_zones") or [], out_zone),
            )
            if match == NONE:
                continue
            if match == PART:
                partly.append(rule)
                continue
            if rule.get("unresolved"):
                also = ", ".join(str(u) for u in rule["unresolved"])
                found.append(
                    item(
                        stage,
                        UNKNOWN,
                        name,
                        f"{_rule_name(rule)} also matches on {also}, which Plexus cannot evaluate.",
                        rule.get("index"),
                    )
                )
                return found, "unknown"
            if rule.get("action") == "monitor":
                found.append(
                    item(stage, INFO, name, f"{_rule_name(rule)}: logs it, and evaluation goes on.", rule.get("index"))
                )
                continue
            decided = rule
            break

        default = str(policy.get("default") or "unknown")
        action = str(decided.get("action")) if decided else default
        final = f"rule {decided.get('index')}" if decided else "the default action"
        other = [r for r in partly if r.get("action") != "monitor" and _family(str(r.get("action"))) != _family(action)]
        index = decided.get("index") if decided else None
        if decided is None and not policy.get("complete", True):
            count = len({r.get("index") for r in rules})
            found.append(item(stage, UNKNOWN, name, f"Only the first {count} rules were collected, and none matches."))
            return found, "unknown"
        if other and _family(action) in ("allow", "deny"):
            first = ", ".join(f"rule {r.get('index')}" for r in other[:4])
            verb = (
                ("allow" if action == "deny" else "deny")
                if len(other) > 1
                else ("allows" if action == "deny" else "denies")
            )
            rest = "denied" if action == "deny" else "allowed"
            found.append(
                item(stage, PARTIAL, name, f"{first} {verb} part of it; the rest is {rest} by {final}.", index)
            )
            return found, action
        if decided is not None:
            words = {
                "allow": "allows it",
                "trust": "trusts it",
                "fastpath": "fastpaths it: the access control policy is skipped",
                "analyze": "hands it to the access control policy",
                "deny": "denies it",
                "prompt": "prompts the user",
            }
            status = BLOCKED if action == "deny" else OK if action in _ALLOWING else UNKNOWN
            found.append(item(stage, status, name, f"{_rule_name(decided)}: {words.get(action, action)}.", index))
            return found, action
        if default == "allow":
            found.append(item(stage, OK, name, "No rule matches: the default action allows it."))
        elif default == "deny":
            found.append(item(stage, BLOCKED, name, "No rule matches: the default action denies it."))
        else:
            found.append(item(stage, UNKNOWN, name, "No rule matches, and the default action is not known."))
        return found, default

    # ── NAT ────────────────────────────────────────────────────────────────

    @staticmethod
    def _iface_match(spec: Any, interface: dict | None) -> bool:
        wanted = str(spec or "").strip().lower()
        if not wanted:
            return True
        if interface is None:
            return False
        return wanted in (str(interface.get("name") or "").lower(), str(interface.get("zone") or "").lower())

    def _dnat(self, gid: Any, block: dict, walk: _Walk, ctx: _Hop) -> None:
        flow, items, ingress, kind = walk.flow, ctx.items, ctx.ingress, ctx.kind
        if kind == "wan":
            for name in ctx.missing:
                if name in _MISSING_NAT and name not in ctx.used:
                    ctx.used.add(name)
                    items.append(
                        item(
                            NAT,
                            UNKNOWN,
                            name,
                            f"{name} {'are' if _plural(name) else 'is'} not collected: whether a rule translates this flow is not known.",
                        )
                    )
        for entry in block.get("nat") or []:
            if not isinstance(entry, dict) or not entry.get("enabled", True) or not entry.get("translated_dst"):
                continue
            nat_kind = str(entry.get("kind") or "")
            if nat_kind in _MERAKI_DNAT:
                if kind != "wan" or entry.get("dst_interface") not in ("", None, (ingress or {}).get("name")):
                    continue
            elif nat_kind in ("vpn_nat", "interface_pat"):
                continue
            elif not self._iface_match(entry.get("src_interface"), ingress):
                continue
            original_dst = entry.get("original_dst") or ["any"]
            if [str(d).lower() for d in original_dst] == ["interface"]:
                ip = (ingress or {}).get("ip") or ""
                dst_match = FULL if ip and show(flow.dst) == ip else NONE
            else:
                dst_match = cover(original_dst, flow.dst)
            match = min(
                cover(entry.get("original_src") or ["any"], flow.src),
                dst_match,
                protocol_match(entry.get("protocol"), flow.protocol),
                FULL
                if flow.protocol.startswith("icmp")
                else ports_match(entry.get("original_port") or "any", flow.dst_ports),
            )
            if match == NONE:
                continue
            where = f"{_NAT_KINDS.get(nat_kind, 'NAT')} {entry.get('name') or ''}".strip()
            index = entry.get("index")
            translated = _translate(
                flow.dst, list(original_dst), list(entry["translated_dst"]), (ingress or {}).get("ip") or ""
            )
            if translated is None or translated == flow.dst and entry.get("translated_dst") == original_dst:
                items.append(item(NAT, OK, where, "Identity NAT: the destination is left unchanged.", index))
                return
            port = _port_of(entry.get("translated_port"))
            new_ports = port if port and flow.dst_ports and flow.dst_ports[0] == flow.dst_ports[1] else flow.dst_ports
            text = f"Destination {show(flow.dst)} becomes {show(translated)}"
            if new_ports != flow.dst_ports and new_ports:
                text += f", port {new_ports[0]}"
            status = OK if match == FULL else PARTIAL
            if match == PART:
                text += "; only part of the traffic asked about is translated"
            items.append(item(NAT, status, where, text + ".", index))
            walk.sessions.setdefault(gid, []).append(
                {"field": "dst", "original": flow.dst, "translated": translated, "where": where}
            )
            allowed = entry.get("allowed_src") or ["any"]
            allowed_match = cover(allowed, flow.src)
            walk.flow = replace(flow, dst=translated, dst_ports=new_ports)
            if allowed_match == NONE:
                items.append(
                    item(
                        NAT,
                        BLOCKED,
                        where,
                        f"{show(flow.src)} is not among the sources the rule allows ({', '.join(allowed)}).",
                        index,
                    )
                )
            elif allowed_match == PART:
                items.append(
                    item(
                        NAT,
                        PARTIAL,
                        where,
                        f"Only part of {show(flow.src)} is among the sources the rule allows ({', '.join(allowed)}).",
                        index,
                    )
                )
            return

    def _snat(
        self, gid: Any, block: dict, ctx: _Hop, egress: dict | None, out_kind: str, route: dict, walk: _Walk
    ) -> None:
        flow, items, ingress = walk.flow, ctx.items, ctx.ingress
        if out_kind == "wan":
            for name in ctx.missing:
                if name in _MISSING_SNAT and name not in ctx.used:
                    ctx.used.add(name)
                    items.append(
                        item(
                            NAT,
                            UNKNOWN,
                            name,
                            "The deployment mode is not collected: whether this MX is in routed mode and hides "
                            f"{show(flow.src)} behind its uplink address is not known, so the source the next "
                            "hop sees is not known.",
                        )
                    )
        for entry in block.get("nat") or []:
            if not isinstance(entry, dict) or not entry.get("enabled", True) or not entry.get("translated_src"):
                continue
            nat_kind = str(entry.get("kind") or "")
            if nat_kind == "interface_pat" and out_kind != "wan":
                continue
            if nat_kind == "vpn_nat" and route.get("kind") != "autovpn":
                continue
            if nat_kind not in ("interface_pat", "vpn_nat") and not (
                self._iface_match(entry.get("src_interface"), ingress)
                and self._iface_match(entry.get("dst_interface"), egress)
            ):
                continue
            match = min(
                cover(entry.get("original_src") or ["any"], flow.src),
                cover(
                    [d for d in entry.get("original_dst") or ["any"] if str(d).lower() != "interface"] or ["any"],
                    flow.dst,
                ),
                protocol_match(entry.get("protocol"), flow.protocol),
            )
            if match == NONE:
                continue
            where = f"{_NAT_KINDS.get(nat_kind, 'NAT')} {entry.get('name') or ''}".strip()
            index = entry.get("index")
            if list(entry.get("translated_src") or []) == list(entry.get("original_src") or []):
                items.append(item(NAT, OK, where, "Identity NAT: the source is left unchanged.", index))
                return
            interface_ip = (egress or {}).get("ip") or ""
            translated = _translate(
                flow.src, list(entry.get("original_src") or []), list(entry["translated_src"]), interface_ip
            )
            if translated is None:
                name = (egress or {}).get("name") or "the egress interface"
                items.append(
                    item(
                        NAT,
                        OK,
                        where,
                        f"Source {show(flow.src)} becomes the address of {name}, which was not collected.",
                        index,
                    )
                )
                return
            items.append(
                item(
                    NAT,
                    OK if match == FULL else PARTIAL,
                    where,
                    f"Source {show(flow.src)} becomes {show(translated)}.",
                    index,
                )
            )
            walk.sessions.setdefault(gid, []).append(
                {"field": "src", "original": flow.src, "translated": translated, "where": where}
            )
            walk.flow = replace(flow, src=translated)
            return

    def _untranslate(self, gid: Any, walk: _Walk, items: list[dict]) -> None:
        for session in walk.sessions.get(gid, []):
            flow = walk.flow
            if session["field"] == "src" and session["translated"].overlaps(flow.dst):
                items.append(
                    item(
                        NAT,
                        INFO,
                        session["where"],
                        f"Replies to {show(session['translated'])} are translated back to {show(session['original'])} by the session.",
                    )
                )
                walk.flow = replace(flow, dst=session["original"])
            elif session["field"] == "dst" and session["translated"].overlaps(flow.src):
                items.append(
                    item(
                        NAT,
                        INFO,
                        session["where"],
                        f"Replies from {show(session['translated'])} leave as {show(session['original'])}, translated back by the session.",
                    )
                )
                walk.flow = replace(flow, src=session["original"])

    # ── Clouds, the Internet, and devices without data ─────────────────────

    def _cloud(self, at: _Arrival, walk: _Walk, adapter: CloudAdapter, node_id: str) -> _Arrival | None:
        dest_hint = ""
        if walk.dest is not None:
            for org_ref, ref_node, _provider in self.refs_of.get(walk.dest, []):
                if org_ref == adapter.org_ref:
                    dest_hint = adapter.network_id(ref_node)
        result = adapter.cross(
            walk.flow,
            reply=walk.reply,
            first=at.first,
            entry_address=at.address,
            entry_network=adapter.network_id(node_id),
            src_network=adapter.network_id(node_id) if at.first else "",
            dst_network=dest_hint,
        )
        current = self._new_hop(at.node, at.edge, at.label)
        walk.hops.append(current)
        last = current
        for segment_node, found in result["segments"]:
            gid = self.graph_of.get((adapter.org_ref, segment_node))
            if gid is None or gid == last["node"]:
                last["items"].extend(found)
                continue
            edges = self.between.get(_pair(last["node"], gid), [])
            last = self._new_hop(gid, edges[0].get("id") if edges else None)
            last["items"].extend(found)
            walk.hops.append(last)
        if result["kind"] == "delivered":
            # The address of an instance that is a device the trace follows
            # itself (a vMX, an FTDv) is not the end of the way unless that
            # device is the end: the replies to a source it hid behind its
            # uplink address are its to translate back and send on.
            device = self.graph_of.get((adapter.org_ref, str(result.get("instance") or "")))
            if (
                device is not None
                and device not in (walk.dest, last["node"])
                and self.forwarding(device)[0] is not None
            ):
                last["items"].append(
                    item(
                        ROUTE,
                        OK,
                        adapter.term,
                        f"{show(walk.flow.dst)} is an address of {self.label(device)}, which takes the flow from here.",
                    )
                )
                edge_id, passable = self._link(last["node"], device, last["items"])
                if not passable:
                    walk.ended = True
                    return None
                return _Arrival(node=device, edge=edge_id, via_ip=show(walk.flow.dst), prev=last["node"])
            walk.delivered = True
            return None
        if result["kind"] != "exit":
            walk.ended = True
            return None
        nxt = result.get("next") or {}
        if nxt.get("internet"):
            return _Arrival(node=None, label=f"From {adapter.term}", prev=last["node"])
        target = self.graph_of.get((adapter.org_ref, str(nxt.get("node") or "")))
        if target is None:
            last["items"].append(item(ROUTE, UNKNOWN, adapter.term, f"{nxt.get('node')} is not on the map."))
            walk.ended = True
            return None
        address = str(result.get("address") or "")
        edge_id, passable = self._link(last["node"], target, last["items"], "" if address else "vpn")
        if not passable:
            walk.ended = True
            return None
        return _Arrival(
            node=target,
            edge=edge_id,
            kind="" if address else "vpn",
            label="" if address else f"VPN from {adapter.term}",
            via_ip=address,
            prev=last["node"],
        )

    def _internet(self, at: _Arrival, walk: _Walk) -> _Arrival | None:
        current = self._new_hop(None, None, at.label)
        walk.hops.append(current)
        items = current["items"]
        flow = walk.flow
        target = walk.dest
        if target is None and flow.dst.prefixlen == flow.dst.max_prefixlen:
            owners = self.ip_owner.get(show(flow.dst)) or [
                g for public, g in self.nat_owner if contains(public, flow.dst)
            ]
            target = owners[0] if owners else None
        if target is not None and target != at.prev:
            if not _public(flow.dst):
                items.append(
                    item(
                        ROUTE,
                        UNKNOWN,
                        "Internet",
                        f"{show(flow.dst)} is a private address: the internet path to it is not on the map.",
                    )
                )
                walk.ended = True
                return None
            cloud = self._cloud_of(target)
            if cloud is not None or self.forwarding(target)[0] is not None:
                items.append(item(ROUTE, OK, "Internet", f"Crosses the internet to {self.label(target)}."))
                return _Arrival(node=target, kind="" if cloud else "wan", label="Internet", prev=None)
            items.append(
                item(ROUTE, UNKNOWN, "Internet", f"The internet path to {self.label(target)} is not on the map.")
            )
            walk.ended = True
            return None
        if _public(flow.dst):
            items.append(
                item(
                    ROUTE,
                    OK,
                    "Internet",
                    f"{show(flow.dst)} is on the internet: the trace ends where the flow leaves the map.",
                )
            )
            walk.delivered = True
            return None
        items.append(item(ROUTE, UNKNOWN, "Internet", f"The internet path to {show(flow.dst)} is not on the map."))
        walk.ended = True
        return None

    def _fallback(self, at: _Arrival, walk: _Walk) -> None:
        gid = at.node
        current = self._new_hop(gid, at.edge, at.label)
        walk.hops.append(current)
        walk.fallback = True
        self._predates(gid, walk)
        current["items"].append(
            item(
                NOTE,
                UNKNOWN,
                "Routing and policy",
                f"No routing or policy data was collected for {self.label(gid)}; the rest of this path follows the "
                "links on the map.",
            )
        )
        if gid == walk.dest:
            walk.delivered = True
            return
        if walk.dest is None:
            current["items"].append(
                item(ROUTE, UNKNOWN, "Path", "The destination is not on the map, so the path ends here.")
            )
            walk.ended = True
            return
        path = self._shortest(gid, walk.dest)
        if path is None:
            current["items"].append(
                item(LINK, UNKNOWN, "Path", f"No link that is up leads from here to {self.label(walk.dest)}.")
            )
            walk.ended = True
            return
        for node, edge in path:
            self._predates(node, walk)
            passed = self._new_hop(node, edge.get("id"))
            passed["items"].append(
                item(
                    NOTE,
                    UNKNOWN,
                    "Routing and policy",
                    f"Passed over the links on the map: routing and policy at {self.label(node)} were not evaluated.",
                )
            )
            walk.hops.append(passed)
        walk.delivered = True

    def _shortest(self, start: Any, goal: Any) -> list[tuple[Any, dict]] | None:
        """The cheapest way over links that are up: ``[(node, edge into it)]``."""
        best: dict[Any, int] = {start: 0}
        parent: dict[Any, tuple[Any, dict]] = {}
        heap: list[tuple[int, int, Any]] = [(0, 0, start)]
        order = 0
        while heap:
            cost, _order, at = heapq.heappop(heap)
            if at == goal:
                break
            if cost > best.get(at, cost):
                continue
            for other, step, edge in self.adjacency.get(at, []):
                total = cost + step
                if total < best.get(other, total + 1):
                    best[other] = total
                    parent[other] = (at, edge)
                    order += 1
                    heapq.heappush(heap, (total, order, other))
        if goal not in parent:
            return None
        path: list[tuple[Any, dict]] = []
        node = goal
        while node != start:
            previous, edge = parent[node]
            path.append((node, edge))
            node = previous
        return list(reversed(path))

    def _predates(self, gid: Any, walk: _Walk) -> None:
        """A note when the node's snapshot was collected before forwarding data existed."""
        for org_ref, _node_id, provider in self.refs_of.get(gid, []):
            snapshot = self.snapshots.get(org_ref) or {}
            kind = str(snapshot.get("provider") or provider or "meraki")
            if kind not in _PROVIDER_NAMES:
                continue
            if any(isinstance(n, dict) and n.get("forwarding") for n in snapshot.get("nodes") or []):
                continue
            name = str((snapshot.get("org") or {}).get("name") or org_ref)
            note = f"{_PROVIDER_NAMES[kind]} {name}: the snapshot predates forwarding data; collect it again."
            if note not in walk.notes:
                walk.notes.append(note)


def trace(
    graph: dict,
    snapshots: dict[int, dict],
    clouds: dict[int, Any],
    host_forwarding: dict[int, dict],
    subnets: list[dict],
    source: str,
    destination: str,
    **options: Any,
) -> dict[str, Any]:
    """Build a ``Tracer`` and trace one flow."""
    return Tracer(graph, snapshots, clouds, host_forwarding, subnets).trace(source, destination, **options)
