"""Whether Azure lets traffic between two addresses through.

Path Mode draws how two places are joined on the map. This module answers
the question the map cannot: do the effective routes of the subnets (system
routes, VNet peerings, gateway routes and user-defined route tables) and the
network security groups that Cloud Visibility collected actually carry and
permit the traffic, in both directions.

``Reachability`` is pure (no I/O) and is built from the same Cloud Visibility
rows as the topology snapshot. ``check`` returns a verdict and the steps that
led to it:

  - routing follows the effective routes of the source subnet, the way Azure
    builds them: the VNet's own address space (VNet local), the address
    space of every connected peering, the ranges behind the VNet's gateway
    (or the hub's gateway the VNet uses through a peering), the internet,
    and the routes of a user-defined route table, which override the rest.
    Longest prefix wins; on a tie a user route beats a gateway route beats
    a system route. Return traffic is followed the same way from the other
    end
  - network security groups are stateful and are applied at the subnet and
    at the network interface: the request must pass both, in priority
    order, including the default rules; the reply is then allowed

An end that is not in a collected VNet (a branch subnet, an internet
address) is outside Azure: its traffic is followed to the gateway it leaves
through, and back in through the same gateway.

A route to a virtual appliance normally ends what Azure can tell. When the
appliance is one another integration manages (a Meraki vMX), ``check`` takes
a *carrier* for it: an object with a ``name`` and a ``carry(inside,
outside)`` that says, as ``(status, where, text)`` steps, whether the
appliance's VPN carries traffic between an address in Azure and one
outside. The walk then goes on through the appliance. An Azure Firewall is
also an appliance: its policy is not collected, so the walk stops there.

A step is ``ok``, ``blocked``, ``partial`` (only some of the traffic asked
about is allowed), ``unknown`` (not collected, or handed to something Azure
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
from netcontrol.integrations.azure.normalize import _meta, _rid, _short, _text, next_hop_name

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_LOAD_BALANCER_PROBE = "168.63.129.16"
# Routes come from a user-defined table, the VNet's gateway, or Azure itself.
_ORIGIN_RANK = {"user": 0, "gateway": 1, "system": 2}


def _hop_kind(route: dict) -> str:
    return re.sub(r"[^a-z]", "", _text(route.get("next_hop_type")).lower())


def _ports_of(expression: Any) -> list[tuple[int | None, int | None]]:
    """``"80, 443, 1000-2000"`` -> ``[(80, 80), (443, 443), (1000, 2000)]``;
    ``all`` / ``*`` -> ``[(None, None)]`` (every port)."""
    ranges: list[tuple[int | None, int | None]] = []
    for item in _text(expression).replace(";", ",").split(","):
        item = item.strip()
        if item in ("", "*", "all"):
            ranges.append((None, None))
            continue
        match = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", item)
        if match:
            ranges.append((int(match.group(1)), int(match.group(2) or match.group(1))))
    return ranges or [(None, None)]


class Reachability:
    """Index of one or more discovered Azure accounts, for ``check``."""

    def __init__(self, resources: list[dict], connections: list[dict]) -> None:
        by_type: dict[str, dict[str, dict]] = {}
        for row in resources:
            uid = _text(row.get("resource_uid"))
            if uid:
                item = {**row, "meta": _meta(row), "rid": _rid(uid)}
                by_type.setdefault(_text(row.get("resource_type")), {}).setdefault(item["rid"], item)
        self._by_type = by_type

        self.vnets: dict[str, list[_Network]] = {}
        for vnet in by_type.get("vnet", {}).values():
            prefixes = [_net(p) for p in vnet["meta"].get("address_prefixes") or [vnet.get("cidr")]]
            self.vnets[vnet["rid"]] = [p for p in prefixes if p is not None]

        self.subnets: list[tuple[_Network, dict]] = []
        for subnet in by_type.get("subnet", {}).values():
            for raw in subnet["meta"].get("address_prefixes") or [subnet.get("cidr")]:
                net = _net(raw)
                if net is not None:
                    self.subnets.append((net, subnet))

        self._tables = by_type.get("route_table", {})
        self._table_of_subnet: dict[str, dict] = {}
        for table in self._tables.values():
            for subnet_id in table["meta"].get("subnet_ids") or []:
                self._table_of_subnet[_text(subnet_id)] = table
        for subnet in by_type.get("subnet", {}).values():
            table = self._tables.get(_rid(_text(subnet["meta"].get("route_table"))))
            if table is not None:
                self._table_of_subnet.setdefault(subnet["rid"], table)

        self._nsgs = by_type.get("network_security_group", {})
        self._nsg_of_subnet: dict[str, dict] = {}
        self._nsg_of_nic: dict[str, dict] = {}
        for nsg in self._nsgs.values():
            for subnet_id in nsg["meta"].get("subnet_ids") or []:
                self._nsg_of_subnet[_text(subnet_id)] = nsg
            for nic_id in nsg["meta"].get("nic_ids") or []:
                self._nsg_of_nic[_text(nic_id)] = nsg
        for subnet in by_type.get("subnet", {}).values():
            nsg = self._nsgs.get(_rid(_text(subnet["meta"].get("network_security_group"))))
            if nsg is not None:
                self._nsg_of_subnet.setdefault(subnet["rid"], nsg)

        # (VNet, private address) -> (virtual machine or firewall, the interface holding the address).
        self._address_owner: dict[tuple[str, str], tuple[dict, dict | None]] = {}
        for vm in by_type.get("vm", {}).values():
            meta = vm["meta"]
            for interface in meta.get("interfaces") or []:
                if not isinstance(interface, dict):
                    continue
                nsg = self._nsgs.get(_text(interface.get("network_security_group")))
                if nsg is not None:
                    self._nsg_of_nic.setdefault(_text(interface.get("id")), nsg)
                vnet_id = _text(interface.get("vnet_id")) or _text(meta.get("vnet_id"))
                for address in interface.get("private_ips") or []:
                    self._address_owner.setdefault((vnet_id, _text(address)), (vm, interface))
            self._address_owner.setdefault((_text(meta.get("vnet_id")), _text(meta.get("private_ip"))), (vm, None))
        for firewall in by_type.get("azure_firewall", {}).values():
            meta = firewall["meta"]
            for address in meta.get("private_ips") or [meta.get("private_ip")]:
                self._address_owner.setdefault((_text(meta.get("vnet_id")), _text(address)), (firewall, None))

        self._gateways = by_type.get("virtual_network_gateway", {})
        self._gateways_of_vnet: dict[str, list[dict]] = {}
        for gateway in self._gateways.values():
            vnet_id = _text(gateway["meta"].get("vnet_id"))
            if vnet_id:
                self._gateways_of_vnet.setdefault(vnet_id, []).append(gateway)

        self._peerings: dict[str, list[dict]] = {}
        self._connections_of_gateway: dict[str, list[dict]] = {}
        for row in connections:
            kind = _text(row.get("connection_type")).lower()
            meta = _meta(row)
            source, target = _text(row.get("source_resource_uid")), _text(row.get("target_resource_uid"))
            if kind == "vnet_peering":
                remote = _rid(target)
                prefixes = [_net(p) for p in meta.get("remote_address_space") or []]
                self._peerings.setdefault(_rid(source), []).append(
                    {
                        "name": _text(meta.get("name")),
                        "remote": remote,
                        "state": _text(row.get("state")).lower(),
                        "prefixes": [p for p in prefixes if p is not None] or self.vnets.get(remote, []),
                        "forwarded": bool(meta.get("allow_forwarded_traffic")),
                        "transit": bool(meta.get("allow_gateway_transit")),
                        "use_remote_gateways": bool(meta.get("use_remote_gateways")),
                    }
                )
            elif kind == "virtual_network_gateway_attachment":
                gateway = self._gateways.get(_rid(target))
                if gateway is not None and not _text(gateway["meta"].get("vnet_id")):
                    gateway["meta"]["vnet_id"] = _rid(source)
                    self._gateways_of_vnet.setdefault(_rid(source), []).append(gateway)
            elif source in {f"azure:virtual_network_gateway:{g}" for g in self._gateways}:
                far = by_type.get("local_network_gateway", {}).get(_rid(target))
                remote_gateway = self._gateways.get(_rid(target)) if kind == "vnet2vnet" else None
                prefixes = [_net(p) for p in ((far or {}).get("meta") or {}).get("address_prefixes") or []]
                if remote_gateway is not None:
                    prefixes = list(self.vnets.get(_text(remote_gateway["meta"].get("vnet_id")), []))
                self._connections_of_gateway.setdefault(_rid(source), []).append(
                    {
                        "name": _text(meta.get("name")) or kind,
                        "type": kind,
                        "status": _text(meta.get("connection_status")).lower(),
                        "target": target,
                        "far": far,
                        "to_vnet": _text(remote_gateway["meta"].get("vnet_id")) if remote_gateway else "",
                        "prefixes": [p for p in prefixes if p is not None],
                        "bgp": bool(meta.get("enable_bgp")) or kind == "expressroute",
                    }
                )

    # ── Names ──────────────────────────────────────────────────────────────

    def _vnet_name(self, vnet_id: str) -> str:
        name = _text((self._by_type.get("vnet", {}).get(vnet_id) or {}).get("name"))
        return f"VNet {name or _short(vnet_id)}"

    @staticmethod
    def _subnet_name(subnet: dict) -> str:
        return f"subnet {_text(subnet.get('name')) or _short(subnet['rid'])} ({_text(subnet.get('cidr'))})"

    @staticmethod
    def _owner_name(owner: dict) -> str:
        kind = "Azure Firewall" if owner.get("resource_type") == "azure_firewall" else "virtual machine"
        return f"{kind} {_text(owner.get('name')) or _short(owner['rid'])}"

    @staticmethod
    def _gateway_name(gateway: dict) -> str:
        return f"gateway {_text(gateway.get('name')) or _short(gateway['rid'])}"

    # ── Where an address is ────────────────────────────────────────────────

    def locate(self, address: str, vnet_id: str = "") -> dict[str, Any]:
        """The subnet (and virtual machine) of ``address``, an IP address or
        network. ``vnet_id`` picks the VNet when several hold the same range.
        An address in no collected subnet is outside Azure (``subnet`` is ``None``)."""
        net = _net(address)
        if net is None:
            raise ValueError(f"{address!r} is not an IP address or network")
        found = [
            (subnet_net.prefixlen, subnet)
            for subnet_net, subnet in self.subnets
            if subnet_net.version == net.version
            and subnet_net.supernet_of(net)
            and (not vnet_id or _text(subnet["meta"].get("vnet_id")) == vnet_id)
        ]
        longest = max((length for length, _subnet in found), default=-1)
        subnets = [subnet for length, subnet in found if length == longest]
        place: dict[str, Any] = {
            "net": net,
            "address": _show(net),
            "subnet": None,
            "vnet_id": "",
            "instance": None,
            "interface": None,
            "label": _show(net),
            "ambiguous": [],
        }
        if len(subnets) > 1:
            place["ambiguous"] = sorted(self._vnet_name(_text(s["meta"].get("vnet_id"))) for s in subnets)
        elif subnets:
            subnet = subnets[0]
            place["subnet"] = subnet
            place["vnet_id"] = _text(subnet["meta"].get("vnet_id"))
            place["label"] = self._subnet_name(subnet)
            if _is_host(net):
                owner = self._address_owner.get((place["vnet_id"], _show(net)))
                if owner:
                    place["instance"], place["interface"] = owner
                    place["label"] = f"{self._owner_name(owner[0])} ({_show(net)})"
        return place

    # ── Effective routes ───────────────────────────────────────────────────

    def _serving_gateways(self, vnet_id: str) -> list[tuple[dict, str]]:
        """The gateways whose routes a VNet gets: its own, and the hub's when
        a peering uses the remote gateways. ``(gateway, how)``."""
        found = [(g, "") for g in self._gateways_of_vnet.get(vnet_id, [])]
        for peering in self._peerings.get(vnet_id, []):
            if peering["use_remote_gateways"] and peering["state"] == "connected":
                for gateway in self._gateways_of_vnet.get(peering["remote"], []):
                    found.append((gateway, f"through peering {peering['name'] or peering['remote']}"))
        return found

    def _effective_routes(self, subnet: dict, vnet_id: str) -> tuple[list[dict], dict]:
        """The routes Azure applies to a subnet, and what could not be known
        (``bgp``: gateways learn routes over BGP or ExpressRoute)."""
        routes: list[dict] = []
        for prefix in self.vnets.get(vnet_id, []):
            routes.append({"net": prefix, "kind": "vnetlocal", "origin": "system", "name": "VNet local"})
        for peering in self._peerings.get(vnet_id, []):
            if peering["state"] != "connected":
                continue
            for prefix in peering["prefixes"]:
                routes.append(
                    {
                        "net": prefix,
                        "kind": "vnetpeering",
                        "origin": "system",
                        "peer": peering["remote"],
                        "name": f"peering {peering['name'] or peering['remote']}",
                    }
                )
        routes.append(
            {"net": ipaddress.ip_network("0.0.0.0/0"), "kind": "internet", "origin": "system", "name": "Internet"}
        )
        table = self._table_of_subnet.get(subnet["rid"])
        no_bgp = bool(table and table["meta"].get("disable_bgp_route_propagation"))
        unknown = {"bgp": [], "table": table}
        for gateway, how in self._serving_gateways(vnet_id):
            for conn in self._connections_of_gateway.get(gateway["rid"], []):
                if conn["status"] not in ("connected", ""):
                    continue
                if conn["bgp"] and not conn["prefixes"]:
                    if not no_bgp:
                        unknown["bgp"].append((gateway, conn))
                    continue
                if conn["bgp"] and no_bgp:
                    continue
                for prefix in conn["prefixes"]:
                    routes.append(
                        {
                            "net": prefix,
                            "kind": "virtualnetworkgateway",
                            "origin": "gateway",
                            "gateway": gateway,
                            "connection": conn,
                            "name": f"{self._gateway_name(gateway)} {how}".strip(),
                        }
                    )
        for route in (table["meta"].get("routes") if table else None) or []:
            if not isinstance(route, dict):
                continue
            net = _net(route.get("prefix"))
            if net is None:
                continue
            routes.append(
                {
                    "net": net,
                    "kind": _hop_kind(route),
                    "origin": "user",
                    "next_hop_ip": _text(route.get("next_hop_ip")),
                    "name": f"route {_text(route.get('name'))} ({next_hop_name(route)})",
                }
            )
        return routes, unknown

    @staticmethod
    def _longest(routes: list[dict], net: _Network) -> tuple[dict | None, list[dict]]:
        best: dict | None = None
        narrower: list[dict] = []
        for route in routes:
            route_net = route["net"]
            if route_net.version != net.version:
                continue
            if route_net.supernet_of(net):
                if best is None or (route_net.prefixlen, -_ORIGIN_RANK[route["origin"]]) > (
                    best["net"].prefixlen,
                    -_ORIGIN_RANK[best["origin"]],
                ):
                    best = route
            elif route_net.subnet_of(net):
                narrower.append(route)
        return best, narrower

    # ── Routing ────────────────────────────────────────────────────────────

    def _walk(
        self, origin: dict, target: dict, direction: str, steps: list[dict], carriers: dict[str, Any] | None = None
    ) -> dict:
        """Follow ``target``'s address from ``origin``'s subnet. Returns how it
        ended: ``delivered``, ``exit`` (left Azure, with the gateway) or ``stop``.
        ``carriers`` maps a virtual machine id to the carrier of that appliance."""

        def step(status: str, stage: str, where: str, text: str) -> None:
            steps.append({"direction": direction, "stage": stage, "status": status, "where": where, "text": text})

        subnet, vnet_id, net = origin["subnet"], origin["vnet_id"], target["net"]
        if target["subnet"] is subnet:
            step(OK, "route", self._subnet_name(subnet), "Same subnet: delivered directly, no route is used.")
            return {"kind": "delivered"}
        routes, unknown = self._effective_routes(subnet, vnet_id)
        table = unknown["table"]
        where = f"Effective routes of {self._subnet_name(subnet)}"
        if table is not None:
            where += f" (route table {_text(table.get('name')) or _short(table['rid'])})"
        route, narrower = self._longest(routes, net)
        if route is None:
            step(BLOCKED, "route", where, f"No route to {_show(net)}.")
            return {"kind": "stop"}
        via = f"{_show(route['net'])} via {route['name']}"
        split = [r for r in narrower if r["kind"] != route["kind"] or r.get("next_hop_ip") != route.get("next_hop_ip")]
        if split:
            other = ", ".join(f"{_show(r['net'])} via {r['name']}" for r in split[:3])
            step(PARTIAL, "route", where, f"Part of {_show(net)} is routed differently: {other}.")

        in_azure = target["subnet"] is not None
        outside = f"but {target['label']} is in {self._vnet_name(target['vnet_id'])}" if in_azure else ""
        kind = route["kind"]

        if kind in ("vnetlocal", "virtualnetwork"):
            if in_azure and target["vnet_id"] == vnet_id:
                step(OK, "route", where, f"{via}: both ends are in {self._vnet_name(vnet_id)}.")
                return {"kind": "delivered"}
            step(
                BLOCKED, "route", where, f"{via} keeps {_show(net)} inside {self._vnet_name(vnet_id)}, where it is not."
            )
            return {"kind": "stop"}

        if kind in ("vnetpeering", "virtualnetworkpeering"):
            peer = route.get("peer", "")
            if in_azure and target["vnet_id"] == peer:
                step(OK, "route", where, f"{via}: the peering to {self._vnet_name(peer)} is connected.")
                return {"kind": "delivered"}
            step(
                BLOCKED,
                "route",
                where,
                f"{via} leads to {self._vnet_name(peer)}, which does not hold {_show(net)}. "
                "A VNet peering only carries traffic between its two VNets.",
            )
            return {"kind": "stop"}

        if kind == "virtualnetworkgateway":
            if route["origin"] != "gateway":
                return self._through_gateway(route, via, where, origin, target, direction, unknown, steps)
            conn = route["connection"]
            if conn["to_vnet"]:
                if in_azure and target["vnet_id"] == conn["to_vnet"]:
                    step(OK, "route", where, f"{via}: VNet-to-VNet connection {conn['name']} is connected.")
                    return {"kind": "delivered"}
                step(
                    BLOCKED,
                    "route",
                    where,
                    f"{via} leads to {self._vnet_name(conn['to_vnet'])}, which does not hold {_show(net)}.",
                )
                return {"kind": "stop"}
            if in_azure:
                step(BLOCKED, "route", where, f"{via} sends it out of Azure, {outside}.")
                return {"kind": "stop"}
            step(OK, "route", where, f"{via}: leaves Azure over connection {conn['name']}.")
            return {"kind": "exit", "exit": {"kind": "gateway", "gateway": route["gateway"], "connection": conn}}

        if kind == "internet":
            if in_azure:
                step(BLOCKED, "route", where, f"{via} sends it to the internet, {outside}.")
                return {"kind": "stop"}
            if not net.is_global:
                down = self._down_connection(vnet_id, net)
                if down is not None:
                    gateway, conn = down
                    step(
                        BLOCKED,
                        "route",
                        where,
                        f"Connection {conn['name']} of {self._gateway_name(gateway)} leads to {_show(net)} but is "
                        f"{'not connected' if conn['status'] in ('', 'notconnected') else conn['status']}, so its routes are withdrawn and {via} applies.",
                    )
                    return {"kind": "stop"}
                if unknown["bgp"]:
                    names = ", ".join(sorted({c["name"] for _g, c in unknown["bgp"]}))
                    step(
                        UNKNOWN,
                        "route",
                        where,
                        f"No collected route to {_show(net)}; it may be learned over BGP or ExpressRoute ({names}), "
                        "whose routes are not collected.",
                    )
                    return {"kind": "stop"}
                step(BLOCKED, "route", where, f"{via} sends {_show(net)}, a private address, to the internet.")
                return {"kind": "stop"}
            nat = _text(subnet["meta"].get("nat_gateway"))
            how = f"through NAT gateway {_short(_rid(nat))}" if nat else "with the address Azure gives the subnet"
            step(OK, "route", where, f"{via}: leaves to the internet {how}.")
            return {"kind": "exit", "exit": {"kind": "internet", "nat": nat}}

        if kind == "virtualappliance":
            hop = _text(route.get("next_hop_ip"))
            owner = self._find_owner(hop, vnet_id)
            if owner is None:
                step(UNKNOWN, "route", where, f"{via}: no collected virtual machine or firewall has the address {hop}.")
                return {"kind": "stop"}
            name = self._owner_name(owner)
            if owner.get("resource_type") == "azure_firewall":
                step(
                    UNKNOWN,
                    "route",
                    where,
                    f"{via} hands it to {name}. What the firewall does with it is decided by its firewall policy, "
                    "which is not collected.",
                )
                return {"kind": "stop"}
            carrier = (carriers or {}).get(owner["rid"])
            if carrier is not None and not in_azure:
                step(OK, "route", where, f"{via} hands it to {name}, which is {carrier.name}.")
                carried = True
                for status, at, text in carrier.carry(origin["net"], net):
                    step(status, "vpn", at, text)
                    carried = carried and status == OK
                if not carried:
                    return {"kind": "stop"}
                return {
                    "kind": "exit",
                    "exit": {"kind": "appliance", "instance": owner, "address": hop, "name": carrier.name},
                }
            step(
                UNKNOWN,
                "route",
                where,
                f"{via} hands it to {name}. Whether that appliance forwards it is decided by its own "
                "configuration, which Azure does not describe.",
            )
            return {"kind": "stop"}

        if kind == "none":
            step(BLOCKED, "route", where, f"{via}: the route drops the traffic (next hop None).")
            return {"kind": "stop"}

        step(UNKNOWN, "route", where, f"{via}: this kind of next hop is not followed.")
        return {"kind": "stop"}

    def _down_connection(self, vnet_id: str, net: _Network) -> tuple[dict, dict] | None:
        """A gateway connection of the VNet that leads to ``net`` but is not connected."""
        for gateway, _how in self._serving_gateways(vnet_id):
            for conn in self._connections_of_gateway.get(gateway["rid"], []):
                if conn["status"] in ("connected", ""):
                    continue
                if any(p.version == net.version and p.supernet_of(net) for p in conn["prefixes"]):
                    return gateway, conn
        return None

    def _vnet_tag(self, vnet_id: str, place: dict) -> int:
        """How much of the address at ``place`` the ``VirtualNetwork`` service
        tag of a group in ``vnet_id`` covers: the VNet, its peered VNets and
        the ranges behind the gateways it uses."""
        if place["subnet"] is not None:
            if place["vnet_id"] == vnet_id:
                return _FULL
            peered = {p["remote"] for p in self._peerings.get(vnet_id, []) if p["state"] == "connected"}
            return _FULL if place["vnet_id"] in peered else _NONE
        net = place["net"]
        bgp = False
        for gateway, _how in self._serving_gateways(vnet_id):
            for conn in self._connections_of_gateway.get(gateway["rid"], []):
                if conn["status"] not in ("connected", ""):
                    continue
                if any(p.version == net.version and p.supernet_of(net) for p in conn["prefixes"]):
                    return _FULL
                bgp = bgp or conn["bgp"]
        # Ranges learned over BGP or ExpressRoute are part of it too, but not collected.
        return _PART if bgp and not net.is_global else _NONE

    def _find_owner(self, address: str, vnet_id: str) -> dict | None:
        """The virtual machine or firewall at ``address``: in the VNet, else in
        a peered VNet (a hub appliance), else anywhere collected."""
        owner = self._address_owner.get((vnet_id, address))
        if owner is None:
            for peering in self._peerings.get(vnet_id, []):
                owner = self._address_owner.get((peering["remote"], address))
                if owner is not None:
                    break
        if owner is None:
            owner = next((o for (_v, ip), o in self._address_owner.items() if ip == address), None)
        return owner[0] if owner else None

    def _through_gateway(
        self,
        route: dict,
        via: str,
        where: str,
        origin: dict,
        target: dict,
        direction: str,
        unknown: dict,
        steps: list[dict],
    ) -> dict:
        """A user route that hands traffic to the virtual network gateway."""

        def step(status: str, text: str) -> None:
            steps.append({"direction": direction, "stage": "route", "status": status, "where": where, "text": text})

        net = target["net"]
        if target["subnet"] is not None:
            step(
                BLOCKED,
                f"{via} sends it out of Azure, but {target['label']} is in {self._vnet_name(target['vnet_id'])}.",
            )
            return {"kind": "stop"}
        gateways = self._serving_gateways(origin["vnet_id"])
        if not gateways:
            step(BLOCKED, f"{via}, but {self._vnet_name(origin['vnet_id'])} has no virtual network gateway.")
            return {"kind": "stop"}
        for gateway, _how in gateways:
            for conn in self._connections_of_gateway.get(gateway["rid"], []):
                if conn["to_vnet"] or not any(
                    p.version == net.version and p.supernet_of(net) for p in conn["prefixes"]
                ):
                    continue
                if conn["status"] not in ("connected", ""):
                    state = "not connected" if conn["status"] == "notconnected" else conn["status"]
                    step(
                        BLOCKED,
                        f"{via}: connection {conn['name']} of {self._gateway_name(gateway)} leads there but is {state}.",
                    )
                    return {"kind": "stop"}
                step(OK, f"{via}: leaves Azure over connection {conn['name']} of {self._gateway_name(gateway)}.")
                return {"kind": "exit", "exit": {"kind": "gateway", "gateway": gateway, "connection": conn}}
        if unknown["bgp"] or any(
            c["bgp"] for g, _h in gateways for c in self._connections_of_gateway.get(g["rid"], [])
        ):
            step(UNKNOWN, f"{via}: the gateway learns its routes over BGP or ExpressRoute, which are not collected.")
            return {"kind": "stop"}
        step(BLOCKED, f"{via}, but no connection of the gateway leads to {_show(net)}.")
        return {"kind": "stop"}

    def _enter(self, left: dict, target: dict, direction: str, initiating: bool, steps: list[dict]) -> None:
        """Traffic from outside Azure towards ``target``, coming in through the
        gateway the opposite direction left by. ``initiating`` is whether the
        outside end opens the connection (else this is the reply)."""

        def step(status: str, where: str, text: str) -> None:
            steps.append({"direction": direction, "stage": "route", "status": status, "where": where, "text": text})

        if left["kind"] != "exit":
            step(
                INFO,
                "Entering Azure",
                "Not checked: the opposite direction does not leave Azure, so no entry point is known.",
            )
            return
        gateway = left["exit"]
        vnet = self._vnet_name(target["vnet_id"])
        if gateway["kind"] == "appliance":
            instance = gateway["instance"]
            origin = self.locate(gateway["address"], _text(instance["meta"].get("vnet_id")))
            if origin["subnet"] is None:
                step(UNKNOWN, gateway["name"], f"The subnet of {self._owner_name(instance)} was not collected.")
                return
            step(OK, gateway["name"], f"Enters Azure at {self._owner_name(instance)} in {origin['label']}.")
            self._walk(origin, target, direction, steps)
            return
        if gateway["kind"] == "gateway":
            home = _text(gateway["gateway"]["meta"].get("vnet_id"))
            name = f"Virtual network {self._gateway_name(gateway['gateway'])}"
            if target["vnet_id"] == home:
                step(OK, name, f"Enters {vnet} through its gateway, over connection {gateway['connection']['name']}.")
                return
            uses = any(
                p["remote"] == home and p["use_remote_gateways"] and p["state"] == "connected"
                for p in self._peerings.get(target["vnet_id"], [])
            )
            if uses:
                step(
                    OK,
                    name,
                    f"Enters {self._vnet_name(home)} through its gateway and reaches {vnet} over the peering that uses it.",
                )
            else:
                step(
                    BLOCKED,
                    name,
                    f"{vnet} does not use this gateway: no connected peering to {self._vnet_name(home)} uses remote gateways.",
                )
            return
        if not initiating:
            step(OK, "Internet", "Replies come back the way the request left.")
        elif gateway.get("nat"):
            step(
                BLOCKED,
                f"NAT gateway {_short(_rid(gateway['nat']))}",
                "A NAT gateway does not accept connections from the internet.",
            )
        elif target["instance"] is None:
            step(PARTIAL, "Internet", "Only virtual machines with a public address are reachable from the internet.")
        elif _text(target["instance"]["meta"].get("public_ip")) or target["instance"]["meta"].get("public_ips"):
            step(OK, "Internet", f"{self._owner_name(target['instance'])} has a public address.")
        else:
            step(BLOCKED, "Internet", f"{self._owner_name(target['instance'])} has no public address.")

    # ── Network security groups ────────────────────────────────────────────

    def _tag_cover(self, selector: str, place: dict, vnet_id: str) -> int:
        """How much of the address at ``place`` one selector item of a group
        in ``vnet_id`` covers."""
        item = selector.strip()
        lowered = item.lower()
        if lowered in ("*", "any", ""):
            return _FULL
        if lowered == "virtualnetwork":
            return self._vnet_tag(vnet_id, place)
        if lowered == "internet":
            # The public address space outside the VNet.
            return _FULL if place["subnet"] is None and place["net"].is_global else _NONE
        if lowered == "azureloadbalancer":
            return _FULL if _show(place["net"]) == _LOAD_BALANCER_PROBE else _NONE
        if _net(item) is not None:
            return _cidr_cover(item, place["net"])
        # A service tag (Storage, Sql...) or an application security group: entries not collected.
        return _PART

    def _selector_cover(self, selector: Any, place: dict, vnet_id: str) -> int:
        return max((self._tag_cover(item, place, vnet_id) for item in _text(selector).split(",")), default=_NONE)

    def _nsg_step(
        self,
        nsg: dict,
        level: str,
        place: dict,
        peer: dict,
        outbound: bool,
        protocol: str,
        ports: tuple[int, int] | None,
    ) -> dict:
        way = "outbound" if outbound else "inbound"
        where = f"Network security group {_text(nsg.get('name')) or _short(nsg['rid'])} on {level}, {way}"
        rules = [
            r for r in nsg["meta"].get("policy_rules") or [] if isinstance(r, dict) and _text(r.get("direction")) == way
        ]
        rules.sort(key=lambda r: _int(r.get("priority")) if _int(r.get("priority")) is not None else 1 << 20)
        decided: dict | None = None
        partly: list[dict] = []
        for rule in rules:
            own, far = (place, peer) if outbound else (peer, place)
            cover = min(
                self._selector_cover(rule.get("source_selector"), own, place["vnet_id"]),
                self._selector_cover(rule.get("destination_selector"), far, place["vnet_id"]),
                max(
                    (
                        _traffic_cover(_text(rule.get("protocol")), low, high, protocol, ports)
                        for low, high in _ports_of(rule.get("port_expression"))
                    ),
                    default=_NONE,
                ),
            )
            if cover == _FULL:
                decided = rule
                break
            if cover == _PART:
                partly.append(rule)

        def name(rule: dict) -> str:
            label = _text(rule.get("rule_name")) or _text(rule.get("rule_uid"))
            priority = rule.get("priority")
            return f"rule {label} ({priority})" if priority is not None else f"rule {label}"

        result = {"direction": FORWARD, "stage": "security_group", "where": where}
        if decided is None:
            return {**result, "status": UNKNOWN, "text": "No rule matches and the default rules were not collected."}
        action = _text(decided.get("action"))
        other = [r for r in partly if _text(r.get("action")) != action]
        if other:
            first = ", ".join(name(r) for r in other[:4])
            rest = "denied" if action == "deny" else "allowed"
            verb = "allow" if action == "deny" else "deny"
            return {
                **result,
                "status": PARTIAL,
                "text": f"{first} {verb}(s) part of it; the rest is {rest} by {name(decided)}.",
            }
        if action == "allow":
            return {**result, "status": OK, "text": f"Allowed by {name(decided)}."}
        return {**result, "status": BLOCKED, "text": f"Denied by {name(decided)}."}

    def _security_groups(
        self, place: dict, peer: dict, outbound: bool, protocol: str, ports: tuple[int, int] | None
    ) -> list[dict]:
        """The network security groups traffic passes at ``place``: the
        subnet's and, for a virtual machine, its network interface's."""
        if place["subnet"] is None:
            return []
        way = "outbound" if outbound else "inbound"
        subnet = place["subnet"]
        levels: list[tuple[dict | None, str]] = [(self._nsg_of_subnet.get(subnet["rid"]), self._subnet_name(subnet))]
        instance, interface = place["instance"], place["interface"]
        if instance is not None and instance.get("resource_type") == "vm":
            nic = interface or next(
                iter(i for i in instance["meta"].get("interfaces") or [] if isinstance(i, dict)), None
            )
            nic_id = _text((nic or {}).get("id"))
            nic_name = _text((nic or {}).get("name")) or _short(nic_id)
            levels.append((self._nsg_of_nic.get(nic_id), f"interface {nic_name} of {self._owner_name(instance)}"))
        if outbound:
            levels.reverse()  # leaving: the interface's group first, then the subnet's
        steps: list[dict] = []
        for nsg, level in levels:
            if nsg is None:
                steps.append(
                    {
                        "direction": FORWARD,
                        "stage": "security_group",
                        "status": OK,
                        "where": f"Network security group on {level}, {way}",
                        "text": "None applied: Azure allows it.",
                    }
                )
            else:
                steps.append(self._nsg_step(nsg, level, place, peer, outbound, protocol, ports))
        if instance is None:
            what = (
                "no collected virtual machine has this address"
                if _is_host(place["net"])
                else "this end is a whole subnet"
            )
            steps.append(
                {
                    "direction": FORWARD,
                    "stage": "security_group",
                    "status": INFO,
                    "where": f"Network security groups of network interfaces at {place['label']}, {way}",
                    "text": f"Not checked: {what}. Pick a virtual machine's IP address to include its interface's group.",
                }
            )
        return steps

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
        ``source_vpc`` / ``destination_vpc`` name the VNet of an address whose
        range exists in several. ``carriers`` maps a virtual machine id to
        the carrier of that appliance."""
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
            "source": {"address": src["address"], "label": src["label"], "in_azure": src["subnet"] is not None},
            "destination": {"address": dst["address"], "label": dst["label"], "in_azure": dst["subnet"] is not None},
            "traffic": "any traffic" if not protocol else protocol + (f"/{port}" if ports else ""),
            "steps": [],
        }
        for place in (src, dst):
            if place["ambiguous"]:
                where = ", ".join(place["ambiguous"])
                return {
                    **result,
                    "verdict": UNKNOWN,
                    "summary": f"{place['address']} exists in several VNets ({where}).",
                }
        if src["subnet"] is None and dst["subnet"] is None:
            return {
                **result,
                "applies": False,
                "verdict": UNKNOWN,
                "summary": "Neither address is in a collected VNet.",
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

        # Network security groups are stateful: a permitted request is answered.
        if src["subnet"] is not dst["subnet"] or src["instance"] is not dst["instance"]:
            forward += self._security_groups(src, dst, True, protocol, ports)
            forward += self._security_groups(dst, src, False, protocol, ports)

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
            summary = "Allowed by the effective routes and network security groups in both directions."
            if INFO in statuses:
                summary += " The network security groups of network interfaces were not checked for an end that is not a virtual machine."
        return {**result, "verdict": verdict, "summary": summary}
