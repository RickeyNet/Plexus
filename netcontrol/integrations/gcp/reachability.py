"""Whether GCP lets traffic between two addresses through.

Path Mode draws how two places are joined on the map. This module answers
the question the map cannot: do the routes of the VPC networks (subnet
routes, VPC peerings, static routes and the dynamic routes Cloud Routers
learn over BGP) and the VPC firewall rules that Cloud Visibility collected
actually carry and permit the traffic, in both directions.

``Reachability`` is pure (no I/O) and is built from the same Cloud Visibility
rows as the topology snapshot. ``check`` returns a verdict and the steps that
led to it:

  - routing belongs to the network, not to the subnet. The candidate routes
    are the subnet routes of every range of the network, the subnet routes
    of every active peered network, the static routes of the network and
    the dynamic routes its Cloud Routers learned (every region's in a
    network with global routing, the router's own region's otherwise). The
    longest prefix wins, then the lowest priority number. A route with
    network tags applies only to an instance that carries one of them; for
    an end that is a whole subnet such routes are left out, and a step says
    so. Return traffic is followed the same way from the other end
  - the default internet gateway takes a flow to the internet only from an
    instance with an external IP or from a subnet a Cloud NAT serves; a
    flow from the internet reaches only an instance with an external IP,
    and a private address sent to the internet gateway goes nowhere
  - a VPC peering carries traffic between its two networks only, and a
    VPN tunnel only while it is established
  - VPC firewall rules are stateful and belong to the network, applied per
    instance: the rules whose targets (network tags, service accounts, or
    none for every instance) match the instance, in priority order (the
    lowest number first; on a tie a deny rule wins), down to the implied
    rules that allow all egress and deny all ingress. The request must pass
    the egress rules at the source and the ingress rules at the
    destination; the reply is then allowed. For an end that is a whole
    subnet only the rules for every instance are applied, and a step says
    that the others were not checked. A network firewall policy
    associated with the network is not evaluated: the firewall step is
    then unknown

An end that is not in a collected network (a branch subnet, an internet
address) is outside GCP: its traffic is followed to the gateway it leaves
through, and back in through the same gateway.

How a walk leaves GCP is an *exit*, a dict with a ``kind``:

  - ``internet``: to the internet through the network's default internet
    gateway (``network``: the network's rid), with ``nat`` the Cloud NAT it
    is translated by (``<router rid>:<NAT name>``) or ``""`` when the
    instance's own external IP is used
  - ``vpn``: over a VPN tunnel (``tunnel``: its rid, ``name``) of a VPN
    gateway (``gateway``: its rid, ``gateway_type`` ``ha`` or ``classic``)
  - ``interconnect``: over an Interconnect VLAN attachment
    (``attachment``: its rid, ``name``)
  - ``appliance``: handed to an instance (``instance``: its record,
    ``address``: the address it receives the flow on, ``name``) that a
    carrier follows on

The ``via`` of a ``vpn`` or ``interconnect`` exit names the route that
sent the flow there.

A route to an instance normally ends what GCP can tell. When the instance
is a virtual appliance another integration manages (a Meraki vMX),
``check`` takes a *carrier* for it: an object with a ``name`` and a
``carry(inside, outside)`` that says, as ``(status, where, text)`` steps,
whether the appliance's VPN carries traffic between an address in GCP and
one outside. The walk then goes on through the appliance.

A step is ``ok``, ``blocked``, ``partial`` (only some of the traffic asked
about is allowed), ``unknown`` (not collected, or handed to something GCP
does not describe) or ``info``. Nothing is reported as allowed that was not
checked.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from netcontrol.integrations.aws.reachability import (
    _FULL,
    _NONE,
    _PART,
    BLOCKED,
    FORWARD,
    INFO,
    OK,
    PARTIAL,
    PROTOCOLS,
    RETURN,
    UNKNOWN,
    _cidr_cover,
    _int,
    _is_host,
    _net,
    _show,
    _traffic_cover,
)
from netcontrol.integrations.gcp.collect import DEFAULT_INTERNET_GATEWAY
from netcontrol.integrations.gcp.normalize import _meta, _rid, _short, _text

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
# Of two routes with the same prefix and priority, the one GCP keeps.
_KIND_RANK = {"subnet": 0, "network": 0, "peering": 1, "static": 2, "dynamic": 3}
_PROTOCOL_NUMBERS = {"6": "tcp", "17": "udp", "1": "icmp"}
_IMPLIED_PRIORITY = 65535
_UP_ATTACHMENT = ("os_active", "active", "")


def _ports_of(ports: Any) -> list[tuple[int | None, int | None]]:
    """``["22", "1000-2000"]`` -> ``[(22, 22), (1000, 2000)]``; none -> every port."""
    ranges: list[tuple[int | None, int | None]] = []
    for raw in ports or []:
        match = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", _text(raw))
        if match:
            ranges.append((int(match.group(1)), int(match.group(2) or match.group(1))))
    return ranges or [(None, None)]


def _priority(value: Any, default: int = 1000) -> int:
    number = _int(value)
    return default if number is None else number


class Reachability:
    """Index of one or more discovered GCP accounts, for ``check``."""

    def __init__(self, resources: list[dict], connections: list[dict]) -> None:
        by_type: dict[str, dict[str, dict]] = {}
        for row in resources:
            uid = _text(row.get("resource_uid"))
            if uid:
                item = {**row, "meta": _meta(row), "rid": _rid(uid)}
                by_type.setdefault(_text(row.get("resource_type")), {}).setdefault(item["rid"], item)
        self._by_type = by_type
        self.networks = by_type.get("vpc", {})

        def per_network(resource_type: str, key: str = "network_id") -> dict[str, list[dict]]:
            found: dict[str, list[dict]] = {}
            for item in by_type.get(resource_type, {}).values():
                found.setdefault(_text(item["meta"].get(key)), []).append(item)
            return found

        # (range, subnet, secondary range name or "").
        self.subnets: list[tuple[_Network, dict, str]] = []
        self._ranges_of: dict[str, list[tuple[_Network, dict, str]]] = {}
        for subnet in by_type.get("subnet", {}).values():
            ranges = [(subnet.get("cidr"), "")]
            ranges += [(r.get("cidr"), _text(r.get("name"))) for r in subnet["meta"].get("secondary_ranges") or []]
            for raw, name in ranges:
                net = _net(raw)
                if net is not None:
                    entry = (net, subnet, name)
                    self.subnets.append(entry)
                    self._ranges_of.setdefault(_text(subnet["meta"].get("network_id")), []).append(entry)

        self._routes = per_network("route_entry")
        self._firewalls = per_network("firewall_policy")
        self._routers = per_network("cloud_router")
        self._tunnels = by_type.get("vpn_tunnel", {})
        self._gateways = {**by_type.get("target_vpn_gateway", {}), **by_type.get("ha_vpn_gateway", {})}
        self._attachments = by_type.get("interconnect_attachment", {})
        self._instances = by_type.get("instance", {})

        # (network, internal address) -> (instance, interface); alias ranges apart.
        self._address_owner: dict[tuple[str, str], tuple[dict, dict]] = {}
        self._aliases: list[tuple[_Network, str, dict, dict]] = []
        for instance in self._instances.values():
            for interface in instance["meta"].get("interfaces") or []:
                if not isinstance(interface, dict):
                    continue
                network = _text(interface.get("network_id")) or _text(instance["meta"].get("vpc_id"))
                for address in interface.get("private_ips") or []:
                    self._address_owner.setdefault((network, _text(address)), (instance, interface))
                for raw in interface.get("alias_ranges") or []:
                    net = _net(raw)
                    if net is not None:
                        self._aliases.append((net, network, instance, interface))

        # Network -> peerings (``name``, ``peer``, ``state``), from the network
        # records and, for a network whose own record is missing, its connections.
        self._peerings: dict[str, list[dict]] = {}
        for network in self.networks.values():
            for peering in network["meta"].get("peerings") or []:
                if isinstance(peering, dict) and _text(peering.get("network_id")):
                    self._peerings.setdefault(network["rid"], []).append(
                        {
                            "name": _text(peering.get("name")),
                            "peer": _text(peering.get("network_id")),
                            "state": _text(peering.get("state")).upper(),
                        }
                    )
        for row in connections:
            if _text(row.get("connection_type")) != "vpc_peering":
                continue
            source = _rid(_text(row.get("source_resource_uid")))
            if source in self.networks and self.networks[source]["meta"].get("peerings") is not None:
                continue
            self._peerings.setdefault(source, []).append(
                {
                    "name": _text(_meta(row).get("peering_name")),
                    "peer": _rid(_text(row.get("target_resource_uid"))),
                    "state": _text(row.get("state")).upper(),
                }
            )

        # Network -> network firewall policies associated with it (not evaluated).
        self._policies: dict[str, list[str]] = {}
        for network in self.networks.values():
            name = _text(network["meta"].get("firewall_policy")).rsplit("/", 1)[-1]
            if name:
                self._policies.setdefault(network["rid"], []).append(name)
        for policy in by_type.get("network_firewall_policy", {}).values():
            for network_id in policy["meta"].get("network_ids") or []:
                name = _text(policy.get("name")) or _short(policy["rid"])
                if name not in self._policies.get(_text(network_id), []):
                    self._policies.setdefault(_text(network_id), []).append(name)

    # ── Names ──────────────────────────────────────────────────────────────

    def _vpc_name(self, network_id: str) -> str:
        name = _text((self.networks.get(network_id) or {}).get("name"))
        return f"VPC network {name or _short(network_id)}"

    @staticmethod
    def _subnet_name(subnet: dict, range_name: str = "") -> str:
        name = _text(subnet.get("name")) or _short(subnet["rid"])
        if range_name:
            cidr = next(
                (
                    _text(r.get("cidr"))
                    for r in subnet["meta"].get("secondary_ranges") or []
                    if r.get("name") == range_name
                ),
                "",
            )
            return f"subnet {name}, range {range_name} ({cidr})"
        return f"subnet {name} ({_text(subnet.get('cidr'))})"

    @staticmethod
    def _instance_name(instance: dict) -> str:
        return f"instance {_text(instance.get('name')) or _short(instance['rid'])}"

    def _name(self, resource_type: str, rid: str) -> str:
        return _text((self._by_type.get(resource_type, {}).get(rid) or {}).get("name")) or _short(rid)

    # ── Where an address is ────────────────────────────────────────────────

    def locate(self, address: str, network_id: str = "") -> dict[str, Any]:
        """The subnet (and instance) of ``address``, an IP address or network.
        ``network_id`` (``project:network``) picks the network when several
        hold the same range. An address in no collected subnet is outside
        GCP (``subnet`` is ``None``)."""
        net = _net(address)
        if net is None:
            raise ValueError(f"{address!r} is not an IP address or network")
        found = [
            (subnet_net.prefixlen, subnet, range_name)
            for subnet_net, subnet, range_name in self.subnets
            if subnet_net.version == net.version
            and subnet_net.supernet_of(net)
            and (not network_id or _text(subnet["meta"].get("network_id")) == network_id)
        ]
        longest = max((length for length, _s, _r in found), default=-1)
        best = [(subnet, range_name) for length, subnet, range_name in found if length == longest]
        place: dict[str, Any] = {
            "net": net,
            "address": _show(net),
            "subnet": None,
            "range": "",
            "vpc_id": "",
            "instance": None,
            "interface": None,
            "label": _show(net),
            "ambiguous": [],
        }
        networks = {_text(s["meta"].get("network_id")) for s, _r in best}
        if len(networks) > 1:
            place["ambiguous"] = sorted(self._vpc_name(n) for n in networks)
        elif best:
            subnet, range_name = best[0]
            place.update(subnet=subnet, range=range_name, vpc_id=_text(subnet["meta"].get("network_id")))
            place["label"] = self._subnet_name(subnet, range_name)
            if _is_host(net):
                owner = self._address_owner.get((place["vpc_id"], _show(net)))
                if owner is None:
                    owner = next(
                        (
                            (instance, interface)
                            for alias, network, instance, interface in self._aliases
                            if network == place["vpc_id"] and alias.version == net.version and alias.supernet_of(net)
                        ),
                        None,
                    )
                if owner:
                    place["instance"], place["interface"] = owner
                    place["label"] = f"{self._instance_name(owner[0])} ({_show(net)})"
        return place

    # ── The routes of a network ────────────────────────────────────────────

    def _region(self, place: dict) -> str:
        subnet = place["subnet"]
        return _text(subnet["meta"].get("region")) or _text(subnet.get("region"))

    def _candidates(self, origin: dict) -> tuple[list[dict], int, list[str]]:
        """The routes that apply to ``origin``, how many tagged routes were left
        out because the end is not an instance, and the active peerings whose
        far network is not collected."""
        network = origin["vpc_id"]
        region = self._region(origin)
        instance = origin["instance"]
        tags = set(instance["meta"].get("network_tags") or []) if instance is not None else None
        routes: list[dict] = []
        for net, subnet, range_name in self._ranges_of.get(network, []):
            routes.append(
                {
                    "net": net,
                    "kind": "subnet",
                    "priority": 0,
                    "peer": network,
                    "name": f"the subnet route of {self._subnet_name(subnet, range_name)}",
                }
            )
        uncollected: list[str] = []
        for peering in self._peerings.get(network, []):
            if peering["state"] != "ACTIVE":
                continue
            if peering["peer"] not in self.networks:
                uncollected.append(f"{peering['name'] or 'peering'} to {_short(peering['peer'])}")
                continue
            for net, subnet, range_name in self._ranges_of.get(peering["peer"], []):
                routes.append(
                    {
                        "net": net,
                        "kind": "peering",
                        "priority": 0,
                        "peer": peering["peer"],
                        "peering": peering["name"],
                        "name": f"peering {peering['name'] or peering['peer']} ({self._subnet_name(subnet, range_name)})",
                    }
                )
        skipped = 0
        for route in self._routes.get(network, []):
            meta = route["meta"]
            net = _net(route.get("cidr"))
            if net is None:
                continue
            route_tags = set(meta.get("tags") or [])
            if route_tags:
                if tags is None:
                    skipped += 1
                    continue
                if not route_tags & tags:
                    continue
            kind = _text(meta.get("next_hop_type"))
            routes.append(
                {
                    "net": net,
                    "kind": "network" if kind == "network" else "static",
                    "hop": kind,
                    "priority": _priority(meta.get("priority")),
                    "target": _text(meta.get("next_hop_target")),
                    "id": _text(meta.get("next_hop_id")),
                    "peer": _text(meta.get("next_hop_id")) if kind == "network" else "",
                    "tags": sorted(route_tags),
                    "name": f"route {_text(route.get('name')) or _short(route['rid'])}",
                }
            )
        global_routing = (
            _text((self.networks.get(network) or {}).get("meta", {}).get("routing_mode")).upper() == "GLOBAL"
        )
        for router in self._routers.get(network, []):
            if not global_routing and _text(router["meta"].get("region")) != region:
                continue
            for learned in router["meta"].get("learned_routes") or []:
                net = _net((learned or {}).get("prefix"))
                if net is None:
                    continue
                routes.append(
                    {
                        "net": net,
                        "kind": "dynamic",
                        "priority": _priority(learned.get("priority")),
                        "router": router,
                        "tunnel": _text(learned.get("vpn_tunnel")),
                        "attachment": _text(learned.get("interconnect_attachment")),
                        "bgp_peer": _text(learned.get("peer")),
                        "name": f"a route Cloud Router {_text(router.get('name'))} learned over BGP",
                    }
                )
        return routes, skipped, uncollected

    @staticmethod
    def _select(routes: list[dict], net: _Network) -> tuple[dict | None, list[dict]]:
        best: dict | None = None
        narrower: list[dict] = []

        def rank(route: dict) -> tuple:
            return (route["net"].prefixlen, -route["priority"], -_KIND_RANK.get(route["kind"], 9))

        for route in routes:
            route_net = route["net"]
            if route_net.version != net.version:
                continue
            if route_net.supernet_of(net):
                if best is None or rank(route) > rank(best):
                    best = route
            elif route_net.subnet_of(net):
                narrower.append(route)
        return best, narrower

    def _down_sessions(self, network: str) -> list[str]:
        found = []
        for router in self._routers.get(network, []):
            for peer in router["meta"].get("bgp_peers") or []:
                if isinstance(peer, dict) and _text(peer.get("status")).upper() == "DOWN":
                    found.append(f"{_text(peer.get('name'))} of Cloud Router {_text(router.get('name'))}")
        return found

    def _nat_for(self, place: dict) -> tuple[dict, dict] | None:
        """The Cloud NAT that serves the address at ``place``: one of a Cloud
        Router of the subnet's network and region that covers its range."""
        subnet, range_name = place["subnet"], place["range"]
        region = self._region(place)
        for router in self._routers.get(place["vpc_id"], []):
            if _text(router["meta"].get("region")) != region:
                continue
            for nat in router["meta"].get("nats") or []:
                if not isinstance(nat, dict):
                    continue
                scope = _text(nat.get("scope"))
                if scope == "all" or (scope == "primary" and not range_name):
                    return router, nat
                for entry in nat.get("subnets") or []:
                    if not isinstance(entry, dict) or _text(entry.get("subnet_id")) != subnet["rid"]:
                        continue
                    ranges = set(entry.get("ranges") or ["ALL_IP_RANGES"])
                    if "ALL_IP_RANGES" in ranges:
                        return router, nat
                    if not range_name and "PRIMARY_IP_RANGE" in ranges:
                        return router, nat
                    if range_name and range_name in (entry.get("secondary_ranges") or []):
                        return router, nat
        return None

    # ── Routing ────────────────────────────────────────────────────────────

    def _walk(
        self, origin: dict, target: dict, direction: str, steps: list[dict], carriers: dict[str, Any] | None = None
    ) -> dict:
        """Follow ``target``'s address from ``origin``. Returns how it ended:
        ``delivered``, ``exit`` (left GCP, with the exit) or ``stop``.
        ``carriers`` maps an instance id to the carrier of that appliance."""

        def step(status: str, stage: str, where: str, text: str) -> None:
            steps.append({"direction": direction, "stage": stage, "status": status, "where": where, "text": text})

        subnet, network, net = origin["subnet"], origin["vpc_id"], target["net"]
        if target["subnet"] is subnet and target["vpc_id"] == network:
            step(OK, "route", self._subnet_name(subnet), "Same subnet: delivered directly, through the subnet route.")
            return {"kind": "delivered"}
        routes, skipped, uncollected = self._candidates(origin)
        end = self._instance_name(origin["instance"]) if origin["instance"] is not None else origin["label"]
        where = f"Routes of {self._vpc_name(network)} for {end}"
        if skipped:
            step(
                INFO,
                "route",
                where,
                f"{skipped} route(s) apply only to instances with given network tags and were not used: "
                "this end is not an instance. Pick an instance's IP address to include them.",
            )
        route, narrower = self._select(routes, net)
        if route is None:
            step(BLOCKED, "route", where, f"No route to {_show(net)}.")
            return {"kind": "stop"}
        priority = f", priority {route['priority']}" if route["kind"] in ("static", "dynamic") else ""
        via = f"{_show(route['net'])} via {route['name']}{priority}"
        split = [
            r
            for r in narrower
            if (r["kind"], r.get("id"), r.get("peer")) != (route["kind"], route.get("id"), route.get("peer"))
        ]
        if split:
            other = ", ".join(f"{_show(r['net'])} via {r['name']}" for r in split[:3])
            step(PARTIAL, "route", where, f"Part of {_show(net)} is routed differently: {other}.")

        in_gcp = target["subnet"] is not None
        outside = f"but {target['label']} is in {self._vpc_name(target['vpc_id'])}" if in_gcp else ""
        kind = route["kind"]
        hop = route.get("hop", "")

        if kind in ("subnet", "network"):
            home = route.get("peer") or network
            if in_gcp and target["vpc_id"] == home:
                step(OK, "route", where, f"{via}: both ends are in {self._vpc_name(home)}.")
                return {"kind": "delivered"}
            step(BLOCKED, "route", where, f"{via} keeps {_show(net)} inside {self._vpc_name(home)}, where it is not.")
            return {"kind": "stop"}

        if kind == "peering" or hop == "peering":
            peer = route.get("peer", "")
            if hop == "peering":
                peering = next((p for p in self._peerings.get(network, []) if p["name"] == route["target"]), None)
                if peering is None:
                    step(UNKNOWN, "route", where, f"{via}: peering {route['target']} was not collected.")
                    return {"kind": "stop"}
                if peering["state"] != "ACTIVE":
                    step(
                        BLOCKED,
                        "route",
                        where,
                        f"{via}: peering {route['target']} is {peering['state'] or 'not active'}.",
                    )
                    return {"kind": "stop"}
                peer = peering["peer"]
            if in_gcp and target["vpc_id"] == peer:
                step(OK, "route", where, f"{via}: the peering to {self._vpc_name(peer)} is active.")
                return {"kind": "delivered"}
            step(
                BLOCKED,
                "route",
                where,
                f"{via} leads to {self._vpc_name(peer)}, which does not hold {_show(net)}. "
                "A VPC peering only carries traffic between its two networks.",
            )
            return {"kind": "stop"}

        if kind == "dynamic":
            if route["tunnel"]:
                return self._over_tunnel(route["tunnel"], via, where, target, step)
            if route["attachment"]:
                return self._over_attachment(route["attachment"], via, where, target, step)
            step(
                UNKNOWN,
                "route",
                where,
                f"{via} from BGP peer {route['bgp_peer'] or route['router'].get('name')}; the tunnel or attachment "
                "it goes over was not collected.",
            )
            return {"kind": "stop"}

        if hop == "gateway":
            return self._to_internet(route, via, where, origin, target, uncollected, step)
        if hop == "vpn_tunnel":
            return self._over_tunnel(route["id"], via, where, target, step)
        if hop == "interconnect_attachment":
            return self._over_attachment(route["id"], via, where, target, step)
        if hop in ("ip", "instance"):
            return self._to_appliance(route, via, where, origin, target, step, carriers)
        if hop == "ilb":
            step(
                UNKNOWN,
                "route",
                where,
                f"{via} hands it to an internal passthrough Network Load Balancer ({_short(route['target'].rsplit('/', 1)[-1])}). "
                "Its backends are not collected.",
            )
            return {"kind": "stop"}
        if hop == "hub":
            step(
                UNKNOWN,
                "route",
                where,
                f"{via} hands it to Network Connectivity Center hub {route['target'].rsplit('/', 1)[-1]}, "
                "which is not collected.",
            )
            return {"kind": "stop"}
        step(UNKNOWN, "route", where, f"{via}: this kind of next hop is not followed.")
        return {"kind": "stop"}

    def _to_internet(
        self, route: dict, via: str, where: str, origin: dict, target: dict, uncollected: list[str], step: Any
    ) -> dict:
        net = target["net"]
        if route["id"] != DEFAULT_INTERNET_GATEWAY:
            step(UNKNOWN, "route", where, f"{via}: next hop gateway {route['id'] or route['target']} is not followed.")
            return {"kind": "stop"}
        if target["subnet"] is not None:
            step(
                BLOCKED,
                "route",
                where,
                f"{via} sends it to the internet, but {target['label']} is in {self._vpc_name(target['vpc_id'])}.",
            )
            return {"kind": "stop"}
        if not net.is_global:
            if uncollected:
                step(
                    UNKNOWN,
                    "route",
                    where,
                    f"No collected route to {_show(net)}; it may be a range of a peered network that is not "
                    f"collected ({', '.join(uncollected)}).",
                )
                return {"kind": "stop"}
            down = self._down_sessions(origin["vpc_id"])
            extra = f" BGP session {', '.join(down)} is down, so routes it would learn are withdrawn." if down else ""
            step(BLOCKED, "route", where, f"{via} sends {_show(net)}, a private address, to the internet.{extra}")
            return {"kind": "stop"}
        network = origin["vpc_id"]
        instance, interface = origin["instance"], origin["interface"] or {}
        external = [_text(ip) for ip in interface.get("public_ips") or [] if _text(ip)]
        if instance is not None and not interface:
            external = [_text(instance["meta"].get("public_ip"))] if _text(instance["meta"].get("public_ip")) else []
        if instance is not None and external:
            step(OK, "route", where, f"{via}: leaves to the internet with the external IP {external[0]}.")
            return {"kind": "exit", "exit": {"kind": "internet", "network": network, "nat": ""}}
        found = self._nat_for(origin)
        if found is not None:
            router, nat = found
            step(
                OK,
                "route",
                where,
                f"{via}: leaves to the internet through Cloud NAT {_text(nat.get('name'))} of Cloud Router "
                f"{_text(router.get('name'))}.",
            )
            return {
                "kind": "exit",
                "exit": {"kind": "internet", "network": network, "nat": f"{router['rid']}:{_text(nat.get('name'))}"},
            }
        if instance is not None:
            step(
                BLOCKED,
                "route",
                where,
                f"{via}, but {self._instance_name(instance)} has no external IP and no Cloud NAT serves "
                f"{self._subnet_name(origin['subnet'], origin['range'])}, so it cannot reach the internet.",
            )
            return {"kind": "stop"}
        step(
            PARTIAL,
            "route",
            where,
            f"{via}: only instances with an external IP reach the internet; no Cloud NAT serves "
            f"{self._subnet_name(origin['subnet'], origin['range'])}.",
        )
        return {"kind": "exit", "exit": {"kind": "internet", "network": network, "nat": ""}}

    def _over_tunnel(self, tunnel_id: str, via: str, where: str, target: dict, step: Any) -> dict:
        tunnel = self._tunnels.get(tunnel_id)
        if tunnel is None:
            step(UNKNOWN, "route", where, f"{via}: VPN tunnel {_short(tunnel_id)} was not collected.")
            return {"kind": "stop"}
        name = _text(tunnel.get("name")) or _short(tunnel_id)
        state = _text(tunnel.get("status")).upper()
        if state != "ESTABLISHED":
            step(BLOCKED, "route", where, f"{via}: VPN tunnel {name} is not established ({state or 'no status'}).")
            return {"kind": "stop"}
        meta = tunnel["meta"]
        peer_gateway = self._gateways.get(_text(meta.get("peer_gcp_gateway")))
        if peer_gateway is not None:
            peer = _text(peer_gateway["meta"].get("network_id"))
            if target["subnet"] is not None and target["vpc_id"] == peer:
                step(OK, "route", where, f"{via}: VPN tunnel {name} is established to {self._vpc_name(peer)}.")
                return {"kind": "delivered"}
        if target["subnet"] is not None:
            step(
                BLOCKED,
                "route",
                where,
                f"{via} sends it out of GCP over VPN tunnel {name}, but {target['label']} is in "
                f"{self._vpc_name(target['vpc_id'])}.",
            )
            return {"kind": "stop"}
        gateway_id = _text(meta.get("gateway_id"))
        step(OK, "route", where, f"{via}: leaves GCP over VPN tunnel {name} (established).")
        return {
            "kind": "exit",
            "exit": {
                "kind": "vpn",
                "gateway": gateway_id,
                "gateway_type": _text(meta.get("gateway_type")) or "ha",
                "tunnel": tunnel_id,
                "name": name,
                "via": via,
            },
        }

    def _over_attachment(self, attachment_id: str, via: str, where: str, target: dict, step: Any) -> dict:
        attachment = self._attachments.get(attachment_id)
        if attachment is None:
            step(UNKNOWN, "route", where, f"{via}: Interconnect attachment {_short(attachment_id)} was not collected.")
            return {"kind": "stop"}
        name = _text(attachment.get("name")) or _short(attachment_id)
        meta = attachment["meta"]
        state = _text(meta.get("operational_status")) or _text(attachment.get("status"))
        if state.lower() not in _UP_ATTACHMENT or meta.get("admin_enabled") is False:
            step(
                BLOCKED, "route", where, f"{via}: Interconnect attachment {name} is not active ({state or 'disabled'})."
            )
            return {"kind": "stop"}
        if target["subnet"] is not None:
            step(
                BLOCKED,
                "route",
                where,
                f"{via} sends it out of GCP over Interconnect attachment {name}, but {target['label']} is in "
                f"{self._vpc_name(target['vpc_id'])}.",
            )
            return {"kind": "stop"}
        step(OK, "route", where, f"{via}: leaves GCP over Interconnect attachment {name}.")
        return {"kind": "exit", "exit": {"kind": "interconnect", "attachment": attachment_id, "name": name, "via": via}}

    def _find_owner(self, address: str, network: str) -> tuple[dict, dict] | None:
        """The instance at ``address``: in the network, else in a peered one, else anywhere collected."""
        owner = self._address_owner.get((network, address))
        if owner is None:
            for peering in self._peerings.get(network, []):
                owner = self._address_owner.get((peering["peer"], address))
                if owner is not None:
                    break
        if owner is None:
            owner = next((o for (_n, ip), o in self._address_owner.items() if ip == address), None)
        return owner

    def _to_appliance(
        self,
        route: dict,
        via: str,
        where: str,
        origin: dict,
        target: dict,
        step: Any,
        carriers: dict[str, Any] | None,
    ) -> dict:
        network = origin["vpc_id"]
        if route["hop"] == "instance":
            instance = self._instances.get(route["id"])
            interface = next(
                (
                    i
                    for i in (instance or {}).get("meta", {}).get("interfaces") or []
                    if isinstance(i, dict) and _text(i.get("network_id")) == network
                ),
                None,
            )
            owner = (instance, interface or {}) if instance is not None else None
            shown = _short(route["id"]) or route["target"].rsplit("/", 1)[-1]
        else:
            owner = self._find_owner(route["target"], network)
            shown = route["target"]
        if owner is None:
            step(UNKNOWN, "route", where, f"{via}: no collected instance is {shown}.")
            return {"kind": "stop"}
        instance, interface = owner
        name = self._instance_name(instance)
        if not instance["meta"].get("can_ip_forward"):
            step(
                BLOCKED,
                "route",
                where,
                f"{via} hands it to {name}, which does not forward traffic (IP forwarding is off), "
                "so it drops traffic for other addresses.",
            )
            return {"kind": "stop"}
        carrier = (carriers or {}).get(instance["rid"])
        if carrier is not None and target["subnet"] is None:
            step(OK, "route", where, f"{via} hands it to {name}, which is {carrier.name}.")
            carried = True
            for status, at, text in carrier.carry(origin["net"], target["net"]):
                step(status, "vpn", at, text)
                carried = carried and status == OK
            if not carried:
                return {"kind": "stop"}
            held = [_text(a) for a in (interface or {}).get("private_ips") or [] if _text(a)]
            address = held[0] if held else _text(instance["meta"].get("private_ip"))
            return {
                "kind": "exit",
                "exit": {"kind": "appliance", "instance": instance, "address": address, "name": carrier.name},
            }
        step(
            UNKNOWN,
            "route",
            where,
            f"{via} hands it to {name}. Whether that appliance forwards it is decided by its own "
            "configuration, which GCP does not describe.",
        )
        return {"kind": "stop"}

    def _enter(self, left: dict, target: dict, direction: str, initiating: bool, steps: list[dict]) -> None:
        """Traffic from outside GCP towards ``target``, coming in through the
        gateway the opposite direction left by. ``initiating`` is whether the
        outside end opens the connection (else this is the reply)."""

        def step(status: str, where: str, text: str) -> None:
            steps.append({"direction": direction, "stage": "route", "status": status, "where": where, "text": text})

        if left["kind"] != "exit":
            step(
                INFO,
                "Entering GCP",
                "Not checked: the opposite direction does not leave GCP, so no entry point is known.",
            )
            return
        gateway = left["exit"]
        vpc = self._vpc_name(target["vpc_id"])
        kind = gateway["kind"]
        if kind == "appliance":
            instance = gateway["instance"]
            origin = self.locate(gateway["address"], _text(instance["meta"].get("vpc_id")))
            if origin["subnet"] is None:
                step(UNKNOWN, gateway["name"], f"The subnet of {self._instance_name(instance)} was not collected.")
                return
            step(OK, gateway["name"], f"Enters GCP at {self._instance_name(instance)} in {origin['label']}.")
            self._walk(origin, target, direction, steps)
            return
        if kind == "vpn":
            tunnel = self._tunnels.get(gateway["tunnel"]) or {}
            owner = self._gateways.get(gateway["gateway"]) or {}
            home = _text((owner.get("meta") or {}).get("network_id"))
            where = f"VPN tunnel {gateway['name']}"
            if _text(tunnel.get("status")).upper() not in ("ESTABLISHED", ""):
                step(BLOCKED, where, f"The tunnel is not established ({_text(tunnel.get('status'))}).")
                return
            if home and home != target["vpc_id"]:
                step(
                    BLOCKED,
                    where,
                    f"Its gateway {self._name(owner.get('resource_type') or 'ha_vpn_gateway', gateway['gateway'])} "
                    f"is in {self._vpc_name(home)}, not in {vpc}.",
                )
                return
            step(OK, where, f"Enters {vpc} over the tunnel; the way back is {gateway.get('via') or 'the same tunnel'}.")
            return
        if kind == "interconnect":
            attachment = self._attachments.get(gateway["attachment"]) or {}
            router = (
                self._by_type.get("cloud_router", {}).get(_text((attachment.get("meta") or {}).get("router_id"))) or {}
            )
            home = _text((router.get("meta") or {}).get("network_id"))
            where = f"Interconnect attachment {gateway['name']}"
            if home and home != target["vpc_id"]:
                step(BLOCKED, where, f"Its Cloud Router is in {self._vpc_name(home)}, not in {vpc}.")
                return
            step(
                OK,
                where,
                f"Enters {vpc} over the attachment; the way back is {gateway.get('via') or 'the same attachment'}.",
            )
            return
        if not initiating:
            step(OK, "Internet", "Replies come back the way the request left.")
        elif gateway.get("nat"):
            step(
                BLOCKED,
                f"Cloud NAT {gateway['nat'].rsplit(':', 1)[-1]}",
                "A Cloud NAT does not accept connections from the internet.",
            )
        elif target["instance"] is None:
            step(PARTIAL, "Internet", "Only instances with an external IP are reachable from the internet.")
        elif _text(target["instance"]["meta"].get("public_ip")):
            step(
                OK,
                "Internet",
                f"{self._instance_name(target['instance'])} has the external IP {target['instance']['meta']['public_ip']}.",
            )
        else:
            step(BLOCKED, "Internet", f"{self._instance_name(target['instance'])} has no external IP.")

    # ── VPC firewall rules ─────────────────────────────────────────────────

    @staticmethod
    def _protocol_cover(entries: list[dict], protocol: str, ports: tuple[int, int] | None) -> int:
        best = _NONE
        for entry in entries:
            name = _text(entry.get("protocol")).lower() or "all"
            name = _PROTOCOL_NUMBERS.get(name, name)
            for low, high in _ports_of(entry.get("ports")):
                best = max(best, _traffic_cover(name, low, high, protocol, ports))
        return best

    def _peer_cover(self, meta: dict, place: dict, peer: dict, outbound: bool) -> int:
        """How much of ``peer`` (the far end) a rule of ``place``'s network names."""
        if outbound:
            ranges = meta.get("destination_ranges") or []
            return max((_cidr_cover(r, peer["net"]) for r in ranges), default=_FULL)
        ranges = meta.get("source_ranges") or []
        tags = set(meta.get("source_tags") or [])
        accounts = set(meta.get("source_service_accounts") or [])
        if not (ranges or tags or accounts):
            return _FULL
        best = max((_cidr_cover(r, peer["net"]) for r in ranges), default=_NONE)
        if tags or accounts:
            # Source tags and service accounts name instances of the same network.
            if peer["subnet"] is not None and peer["vpc_id"] == place["vpc_id"]:
                instance = peer["instance"]
                if instance is None:
                    best = max(best, _PART)
                else:
                    meta_i = instance["meta"]
                    if tags & set(meta_i.get("network_tags") or []) or accounts & set(
                        meta_i.get("service_accounts") or []
                    ):
                        best = _FULL
        return best

    @staticmethod
    def _targets(meta: dict) -> tuple[set[str], set[str]]:
        return set(meta.get("target_tags") or []), set(meta.get("target_service_accounts") or [])

    def _firewall(
        self, place: dict, peer: dict, outbound: bool, protocol: str, ports: tuple[int, int] | None
    ) -> list[dict]:
        """The VPC firewall rule steps at ``place``: egress at the source, ingress at the destination."""
        if place["subnet"] is None:
            return []
        network = place["vpc_id"]
        way, wanted = ("egress", "EGRESS") if outbound else ("ingress", "INGRESS")
        instance = place["instance"]
        at = self._instance_name(instance) if instance is not None else place["label"]
        where = f"Firewall rules of {self._vpc_name(network)} for {at}, {way}"
        candidates: list[dict] = []
        # Rules for some instances only, left out for an end that is not one.
        skipped: list[dict] = []
        for rule in self._firewalls.get(network, []):
            meta = rule["meta"]
            if _text(meta.get("direction")).upper() != wanted or meta.get("disabled"):
                continue
            denied = [e for e in meta.get("denied") or [] if isinstance(e, dict)]
            allowed = [e for e in meta.get("allowed") or [] if isinstance(e, dict)]
            entry = {
                "name": _text(rule.get("name")) or _short(rule["rid"]),
                "priority": _priority(meta.get("priority")),
                "action": "deny" if denied else "allow",
                "cover": min(
                    self._peer_cover(meta, place, peer, outbound),
                    self._protocol_cover(denied or allowed, protocol, ports),
                ),
            }
            tags, accounts = self._targets(meta)
            if tags or accounts:
                if instance is None:
                    skipped.append(entry)
                    continue
                own = instance["meta"]
                if not (tags & set(own.get("network_tags") or []) or accounts & set(own.get("service_accounts") or [])):
                    continue
            candidates.append(entry)
        candidates.append(
            {
                "name": f"implied {'allow egress' if outbound else 'deny ingress'}",
                "priority": _IMPLIED_PRIORITY,
                "action": "allow" if outbound else "deny",
                "cover": _FULL,
            }
        )
        candidates.sort(key=lambda r: (r["priority"], r["action"] != "deny"))

        def name(rule: dict) -> str:
            if rule["priority"] == _IMPLIED_PRIORITY and rule["name"].startswith("implied"):
                return f"the {rule['name']} rule"
            return f"rule {rule['name']} (priority {rule['priority']})"

        decided: dict | None = None
        partly: list[dict] = []
        for rule in candidates:
            if rule["cover"] == _FULL:
                decided = rule
                break
            if rule["cover"] == _PART:
                partly.append(rule)
        assert decided is not None  # the implied rule always matches
        action = decided["action"]
        tie = [
            r
            for r in candidates
            if r is not decided
            and r["priority"] == decided["priority"]
            and r["cover"] == _FULL
            and r["action"] != action
        ]
        result = {"direction": FORWARD, "stage": "security_group", "where": where}
        other = [r for r in partly if r["action"] != action]
        if other:
            first = ", ".join(name(r) for r in other[:4])
            rest = "denied" if action == "deny" else "allowed"
            verb = "allow" if action == "deny" else "deny"
            status, text = PARTIAL, f"{first} {verb}(s) part of it; the rest is {rest} by {name(decided)}."
        elif action == "allow":
            status, text = OK, f"Allowed by {name(decided)}."
        else:
            status, text = BLOCKED, f"Denied by {name(decided)}."
            if tie:
                text += f" On a tie a deny rule wins over {', '.join(name(r) for r in tie[:3])}."
        # A rule for some instances that would decide otherwise for them.
        some = [
            r for r in skipped if r["action"] != action and r["cover"] != _NONE and r["priority"] <= decided["priority"]
        ]
        if some and status != PARTIAL:
            verb = "allow" if action == "deny" else "deny"
            status = PARTIAL
            text = (
                f"{text} For some instances {', '.join(name(r) for r in some[:4])} {verb}(s) it: "
                "they apply only to instances with given network tags or service accounts."
            )
        policies = self._policies.get(network, [])
        if policies:
            status = UNKNOWN
            text = (
                f"The VPC firewall rules decide: {text} But network firewall policy {', '.join(policies)} is "
                "associated with this network, and its rules are not evaluated."
            )
        steps = [{**result, "status": status, "text": text}]
        if skipped:
            what = "no collected instance has this address" if _is_host(place["net"]) else "this end is a whole subnet"
            steps.append(
                {
                    **result,
                    "status": INFO,
                    "where": f"Firewall rules for some instances of {place['label']}, {way}",
                    "text": f"Not checked: {len(skipped)} rule(s) apply only to instances with given network tags or service "
                    f"accounts, and {what}. Pick an instance's IP address to include them.",
                }
            )
        return steps

    # ── One direction at a time (path tracing) ─────────────────────────────
    # Thin public wrappers over the walk ``check`` uses, so a trace across
    # other devices can hand a flow into GCP and get it back at the gateway
    # it leaves by. None of them changes the index.

    def walk(
        self, origin: dict, target: dict, direction: str, steps: list[dict], carriers: dict[str, Any] | None = None
    ) -> dict:
        """Follow ``target``'s address from ``origin``, appending the steps to
        ``steps``: ``delivered``, ``exit`` (with the exit) or ``stop``."""
        return self._walk(origin, target, direction, steps, carriers)

    def enter(self, left: dict, target: dict, direction: str, initiating: bool, steps: list[dict]) -> None:
        """Traffic from outside GCP towards ``target`` through the exit ``left`` names."""
        self._enter(left, target, direction, initiating, steps)

    def firewall(
        self, place: dict, peer: dict, outbound: bool, protocol: str, ports: tuple[int, int] | None
    ) -> list[dict]:
        """The VPC firewall rule steps at ``place``."""
        return self._firewall(place, peer, outbound, protocol, ports)

    security_groups = firewall

    # ── The check ──────────────────────────────────────────────────────────

    def check(
        self,
        source: str,
        destination: str,
        *,
        source_vpc: str = "",
        destination_vpc: str = "",
        protocol: str = "",
        port: int | None = None,
        carriers: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Whether ``source`` can open ``protocol``/``port`` to ``destination``
        and get the reply. ``protocol`` ``""`` asks about any traffic.
        ``source_vpc`` / ``destination_vpc`` name the network
        (``project:network``) of an address whose range exists in several.
        ``carriers`` maps an instance id to the carrier of that appliance."""
        protocol = _text(protocol).lower()
        protocol = "" if protocol in ("any", "all") else protocol
        if protocol and protocol not in PROTOCOLS:
            raise ValueError(f"protocol must be one of {', '.join(PROTOCOLS)}")
        ports = (port, port) if port is not None and protocol in ("tcp", "udp") else None
        src, dst = self.locate(source, source_vpc), self.locate(destination, destination_vpc)
        if src["net"].version != dst["net"].version:
            raise ValueError("source and destination must both be IPv4 or both be IPv6")

        result: dict[str, Any] = {
            "applies": True,
            "source": {"address": src["address"], "label": src["label"], "in_gcp": src["subnet"] is not None},
            "destination": {"address": dst["address"], "label": dst["label"], "in_gcp": dst["subnet"] is not None},
            "traffic": "any traffic" if not protocol else protocol + (f"/{port}" if ports else ""),
            "steps": [],
        }
        for place in (src, dst):
            if place["ambiguous"]:
                where = ", ".join(place["ambiguous"])
                return {
                    **result,
                    "verdict": UNKNOWN,
                    "summary": f"{place['address']} exists in several VPC networks ({where}).",
                }
        if src["subnet"] is None and dst["subnet"] is None:
            return {
                **result,
                "applies": False,
                "verdict": UNKNOWN,
                "summary": "Neither address is in a collected VPC network.",
            }

        forward: list[dict] = []
        back: list[dict] = []
        if src["subnet"] is not None:
            left = self._walk(src, dst, FORWARD, forward, carriers)
            if dst["subnet"] is not None:
                self._walk(dst, src, RETURN, back, carriers)
            else:
                self._enter(left, src, RETURN, False, back)
        else:
            left = self._walk(dst, src, RETURN, back, carriers)
            self._enter(left, dst, FORWARD, True, forward)

        # VPC firewall rules are stateful: a permitted request is answered.
        if src["subnet"] is not dst["subnet"] or src["instance"] is not dst["instance"]:
            forward += self._firewall(src, dst, True, protocol, ports)
            forward += self._firewall(dst, src, False, protocol, ports)

        steps = forward + back
        result["steps"] = steps
        statuses = [s["status"] for s in steps]
        first = {
            status: next((s for s in steps if s["status"] == status), None) for status in (BLOCKED, UNKNOWN, PARTIAL)
        }
        if first[BLOCKED]:
            lead = first[BLOCKED]
            verdict, summary = BLOCKED, f"Blocked at {lead['where']}: {lead['text']}"
        elif first[UNKNOWN]:
            lead = first[UNKNOWN]
            verdict, summary = UNKNOWN, f"Could not be decided at {lead['where']}: {lead['text']}"
        elif first[PARTIAL]:
            lead = first[PARTIAL]
            verdict, summary = PARTIAL, f"Allowed in part. {lead['where']}: {lead['text']}"
        else:
            verdict = "allowed"
            summary = "Allowed by the routes and VPC firewall rules in both directions."
            if INFO in statuses:
                summary += (
                    " Routes and firewall rules that apply only to instances with given network tags or service "
                    "accounts were not checked for an end that is not an instance."
                )
        return {**result, "verdict": verdict, "summary": summary}
