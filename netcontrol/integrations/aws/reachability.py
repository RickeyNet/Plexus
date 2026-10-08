"""Whether AWS lets traffic between two addresses through.

Path Mode draws how two places are joined on the map. This module answers
the question the map cannot: do the VPC route tables, transit gateway route
tables, VPC peerings, network ACLs and security groups that Cloud Visibility
collected actually carry and permit the traffic, in both directions.

``Reachability`` is pure (no I/O) and is built from the same Cloud Visibility
rows as the topology snapshot. ``check`` returns a verdict and the steps that
led to it:

  - routing is followed hop by hop from the subnet's route table (longest
    prefix wins): local, VPC peering, transit gateway (the route table its
    attachment is associated with, and on through a transit gateway peering),
    virtual private gateway, internet and NAT gateways. Return traffic is
    followed the same way from the other end
  - network ACLs are stateless, so both the request and the reply are matched
    against the ACL of each subnet, the reply on the ephemeral port range
  - security groups are stateful and belong to an instance: they are matched
    when an end is the address of a collected instance

An end that is not in a collected VPC (a branch subnet, an internet address)
is outside AWS: its traffic is followed to the gateway it leaves through,
and back in through the same gateway.

A route to an instance normally ends what AWS can tell. When the instance is
a virtual appliance another integration manages (a Meraki vMX), ``check``
takes a *carrier* for it: an object with a ``name`` and a
``carry(inside, outside)`` that says, as ``(status, where, text)`` steps,
whether the appliance's VPN carries traffic between an address in AWS and
one outside. The walk then goes on through the appliance.

A step is ``ok``, ``blocked``, ``partial`` (only some of the traffic asked
about is allowed), ``unknown`` (not collected, or handed to something AWS
does not describe, such as a firewall instance) or ``info``. Nothing is
reported as allowed that was not checked.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from netcontrol.integrations.aws.normalize import _meta, _rid, _text

OK, BLOCKED, PARTIAL, UNKNOWN, INFO = "ok", "blocked", "partial", "unknown", "info"
FORWARD, RETURN = "forward", "return"

PROTOCOLS = ("tcp", "udp", "icmp")
# Replies go to the port the client picked; AWS documents this range as the
# one a network ACL must let through.
EPHEMERAL_PORTS = (1024, 65535)
ALL_PORTS = (0, 65535)
# Transit gateways crossed in one direction (peered gateways chain).
MAX_TRANSIT_HOPS = 6

_FULL, _PART, _NONE = 2, 1, 0
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _net(raw: Any) -> _Network | None:
    try:
        return ipaddress.ip_network(_text(raw), strict=False)
    except ValueError:
        return None


def _is_host(net: _Network) -> bool:
    return net.prefixlen == net.max_prefixlen


def _show(net: _Network) -> str:
    return str(net.network_address) if _is_host(net) else str(net)


def _cidr_cover(rule_cidr: Any, net: _Network) -> int:
    """How much of ``net`` a rule written for ``rule_cidr`` applies to."""
    rule = _net(rule_cidr)
    if rule is None or rule.version != net.version:
        return _NONE
    if rule.supernet_of(net):
        return _FULL
    return _PART if rule.overlaps(net) else _NONE


def _traffic_cover(
    rule_protocol: str, low: int | None, high: int | None, protocol: str, ports: tuple[int, int] | None
) -> int:
    """How much of the traffic asked about a rule's protocol and ports apply to.
    ``protocol`` ``""`` asks about any traffic; ``ports`` ``None`` about any port."""
    if rule_protocol in ("all", "-1", ""):
        return _FULL
    if not protocol:
        return _PART
    if rule_protocol != protocol:
        return _NONE
    if protocol not in ("tcp", "udp") or (low is None and high is None):
        return _FULL  # ICMP types and codes are not told apart
    low = 0 if low is None else low
    high = low if high is None else high
    if low <= ALL_PORTS[0] and high >= ALL_PORTS[1]:
        return _FULL
    if ports is None:
        return _PART
    if low <= ports[0] and ports[1] <= high:
        return _FULL
    return _NONE if ports[1] < low or ports[0] > high else _PART


# Public names for path tracing (``netcontrol.integrations.pathtrace``).
FULL, PART, NONE = _FULL, _PART, _NONE
cidr_cover = _cidr_cover
traffic_cover = _traffic_cover


def _port_range(expression: Any) -> tuple[int | None, int | None]:
    match = re.fullmatch(r"(\d+)(?:-(\d+))?", _text(expression))
    if not match:
        return None, None
    return int(match.group(1)), int(match.group(2) or match.group(1))


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _longest(routes: list[dict], net: _Network) -> tuple[dict | None, list[dict], int]:
    """The route a table uses for ``net``, the more specific routes that send
    part of ``net`` elsewhere, and how many prefix-list routes were skipped."""
    best: dict | None = None
    best_len = -1
    narrower: list[dict] = []
    prefix_lists = 0
    for route in routes:
        if not isinstance(route, dict):
            continue
        destination = _text(route.get("destination"))
        if destination.startswith("pl-"):
            prefix_lists += 1
            continue
        route_net = _net(destination)
        if route_net is None or route_net.version != net.version:
            continue
        if route_net.supernet_of(net):
            # Of two routes for one prefix AWS prefers the static one.
            propagated = "propagat" in (_text(route.get("origin")) + _text(route.get("type"))).lower()
            if route_net.prefixlen > best_len or (route_net.prefixlen == best_len and not propagated):
                best, best_len = route, route_net.prefixlen
        elif route_net.subnet_of(net):
            narrower.append(route)
    return best, narrower, prefix_lists


class Reachability:
    """Index of one or more discovered AWS accounts, for ``check``."""

    def __init__(self, resources: list[dict], connections: list[dict]) -> None:
        by_type: dict[str, dict[str, dict]] = {}
        for row in resources:
            uid = _text(row.get("resource_uid"))
            if uid:
                item = {**row, "meta": _meta(row), "rid": _rid(uid)}
                by_type.setdefault(_text(row.get("resource_type")), {}).setdefault(item["rid"], item)
        self._by_type = by_type
        self.vpcs = by_type.get("vpc", {})

        self.subnets: list[tuple[_Network, dict]] = []
        for subnet in by_type.get("subnet", {}).values():
            net = _net(subnet.get("cidr"))
            if net is not None:
                self.subnets.append((net, subnet))

        self._table_of_subnet: dict[str, dict] = {}
        self._main_table: dict[str, dict] = {}
        for table in by_type.get("route_table", {}).values():
            meta = table["meta"]
            if meta.get("main"):
                self._main_table[_text(meta.get("vpc_id"))] = table
            for subnet_id in meta.get("associated_subnet_ids") or []:
                self._table_of_subnet[_text(subnet_id)] = table

        self._acl_of_subnet: dict[str, dict] = {}
        for acl in by_type.get("network_acl", {}).values():
            for subnet_id in acl["meta"].get("subnet_ids") or []:
                self._acl_of_subnet[_text(subnet_id)] = acl

        self._groups = by_type.get("security_group", {})
        self._group_by_name = {(_text(g["meta"].get("vpc_id")), _text(g.get("name"))): g for g in self._groups.values()}

        # (VPC, private address) -> (instance, the interface holding the address).
        self._address_owner: dict[tuple[str, str], tuple[dict, dict | None]] = {}
        self._interface_owner: dict[str, dict] = {}
        for instance in by_type.get("instance", {}).values():
            meta = instance["meta"]
            vpc_id = _text(meta.get("vpc_id"))
            self._address_owner.setdefault((vpc_id, _text(meta.get("private_ip"))), (instance, None))
            for interface in meta.get("interfaces") or []:
                if not isinstance(interface, dict):
                    continue
                self._interface_owner[_text(interface.get("id"))] = instance
                for address in interface.get("private_ips") or []:
                    self._address_owner[(vpc_id, _text(address))] = (instance, interface)

        self._tgw_tables = by_type.get("transit_gateway_route_table", {})
        self._attachments: list[dict] = []
        self._peerings: dict[str, dict] = {}
        for row in connections:
            kind = _text(row.get("connection_type"))
            meta = _meta(row)
            source, target = _text(row.get("source_resource_uid")), _text(row.get("target_resource_uid"))
            if kind == "transit_gateway_attachment":
                parts = source.split(":", 2)
                self._attachments.append(
                    {
                        "id": _text(meta.get("attachment_id")),
                        "tgw": _rid(target),
                        "resource_type": _text(meta.get("resource_type")) or (parts[1] if len(parts) == 3 else ""),
                        "resource_id": _text(meta.get("resource_id")) or _rid(source),
                        # Absent on a discovery made before associations were read.
                        "table": _text(meta.get("route_table_id")) if "route_table_id" in meta else None,
                        "state": _text(row.get("state")).lower(),
                    }
                )
            elif kind == "vpc_peering" and _text(meta.get("peering_id")):
                self._peerings[_text(meta.get("peering_id"))] = {
                    "vpcs": (_rid(source), _rid(target)),
                    "state": _text(row.get("state")).lower(),
                }

    # ── Names ──────────────────────────────────────────────────────────────

    def _name(self, resource_type: str, rid: str) -> str:
        name = _text((self._by_type.get(resource_type, {}).get(rid) or {}).get("name"))
        return f"{name} ({rid})" if name and name != rid else rid

    def _vpc_name(self, vpc_id: str) -> str:
        return f"VPC {self._name('vpc', vpc_id)}"

    @staticmethod
    def _subnet_name(subnet: dict) -> str:
        return f"subnet {_text(subnet.get('name')) or subnet['rid']} ({_text(subnet.get('cidr'))})"

    @staticmethod
    def _instance_name(instance: dict) -> str:
        return f"instance {_text(instance.get('name')) or instance['rid']}"

    # ── Where an address is ────────────────────────────────────────────────

    def locate(self, address: str, vpc_id: str = "") -> dict[str, Any]:
        """The subnet (and instance) of ``address``, an IP address or network.
        ``vpc_id`` picks the VPC when several hold the same range. An address
        in no collected subnet is outside AWS (``subnet`` is ``None``)."""
        net = _net(address)
        if net is None:
            raise ValueError(f"{address!r} is not an IP address or network")
        found = [
            (subnet_net.prefixlen, subnet)
            for subnet_net, subnet in self.subnets
            if subnet_net.version == net.version
            and subnet_net.supernet_of(net)
            and (not vpc_id or _text(subnet["meta"].get("vpc_id")) == vpc_id)
        ]
        longest = max((length for length, _subnet in found), default=-1)
        subnets = [subnet for length, subnet in found if length == longest]
        place: dict[str, Any] = {
            "net": net,
            "address": _show(net),
            "subnet": None,
            "vpc_id": "",
            "instance": None,
            "interface": None,
            "label": _show(net),
            "ambiguous": [],
        }
        if len(subnets) > 1:
            place["ambiguous"] = sorted(self._vpc_name(_text(s["meta"].get("vpc_id"))) for s in subnets)
        elif subnets:
            subnet = subnets[0]
            place["subnet"] = subnet
            place["vpc_id"] = _text(subnet["meta"].get("vpc_id"))
            place["label"] = self._subnet_name(subnet)
            if _is_host(net):
                owner = self._address_owner.get((place["vpc_id"], _show(net)))
                if owner:
                    place["instance"], place["interface"] = owner
                    place["label"] = f"{self._instance_name(owner[0])} ({_show(net)})"
        return place

    # ── Routing ────────────────────────────────────────────────────────────

    def _walk(
        self, origin: dict, target: dict, direction: str, steps: list[dict], carriers: dict[str, Any] | None = None
    ) -> dict:
        """Follow ``target``'s address from ``origin``'s subnet. Returns how it
        ended: ``delivered``, ``exit`` (left AWS, with the gateway) or ``stop``.
        ``carriers`` maps an instance id to the carrier of that appliance."""

        def step(status: str, stage: str, where: str, text: str) -> None:
            steps.append({"direction": direction, "stage": stage, "status": status, "where": where, "text": text})

        subnet, vpc_id, net = origin["subnet"], origin["vpc_id"], target["net"]
        if target["subnet"] is subnet:
            step(OK, "route", self._subnet_name(subnet), "Same subnet: delivered directly, no route table is used.")
            return {"kind": "delivered"}
        table = self._table_of_subnet.get(subnet["rid"]) or self._main_table.get(vpc_id)
        if table is None:
            step(UNKNOWN, "route", self._subnet_name(subnet), "No route table was collected for this subnet.")
            return {"kind": "stop"}
        where = f"Route table {_text(table.get('name')) or table['rid']} of {self._subnet_name(subnet)}"
        route, narrower, prefix_lists = _longest(table["meta"].get("routes") or [], net)
        if route is None:
            extra = f" ({prefix_lists} prefix-list route(s) could not be read)" if prefix_lists else ""
            step(UNKNOWN if prefix_lists else BLOCKED, "route", where, f"No route to {_show(net)}{extra}.")
            return {"kind": "stop"}
        hop = _text(route.get("target"))
        via = f"{_text(route.get('destination'))} via {hop}"
        if _text(route.get("state")).lower() == "blackhole":
            step(BLOCKED, "route", where, f"Route {via} is a blackhole: its target no longer exists.")
            return {"kind": "stop"}
        split = [r for r in narrower if _text(r.get("target")) != hop]
        if split:
            other = ", ".join(f"{_text(r.get('destination'))} via {_text(r.get('target'))}" for r in split[:3])
            step(PARTIAL, "route", where, f"Part of {_show(net)} is routed differently: {other}.")

        in_aws = target["subnet"] is not None
        outside = f"but {target['label']} is in {self._vpc_name(target['vpc_id'])}" if in_aws else ""

        if hop == "local":
            if in_aws and target["vpc_id"] == vpc_id:
                step(OK, "route", where, f"{via}: both ends are in {self._vpc_name(vpc_id)}.")
                return {"kind": "delivered"}
            step(BLOCKED, "route", where, f"{via} keeps {_show(net)} inside {self._vpc_name(vpc_id)}, where it is not.")
            return {"kind": "stop"}

        if hop.startswith("pcx-"):
            peering = self._peerings.get(hop)
            if peering is None:
                step(UNKNOWN, "route", where, f"{via}: VPC peering {hop} was not collected.")
                return {"kind": "stop"}
            if peering["state"] != "active":
                step(BLOCKED, "route", where, f"{via}: VPC peering {hop} is {peering['state'] or 'not active'}.")
                return {"kind": "stop"}
            peer = next((v for v in peering["vpcs"] if v != vpc_id), vpc_id)
            if in_aws and target["vpc_id"] == peer:
                step(OK, "route", where, f"{via}: VPC peering to {self._vpc_name(peer)} is active.")
                return {"kind": "delivered"}
            step(
                BLOCKED,
                "route",
                where,
                f"{via} leads to {self._vpc_name(peer)}, which does not hold {_show(net)}. "
                "A VPC peering only carries traffic between its two VPCs.",
            )
            return {"kind": "stop"}

        if hop.startswith("tgw-"):
            attachment = next(
                (
                    a
                    for a in self._attachments
                    if a["tgw"] == hop and a["resource_type"] == "vpc" and a["resource_id"] == vpc_id
                ),
                None,
            )
            if attachment is None:
                step(BLOCKED, "route", where, f"{via}, but {self._vpc_name(vpc_id)} has no attachment to {hop}.")
                return {"kind": "stop"}
            step(OK, "route", where, f"{via} (transit gateway {self._name('transit_gateway', hop)}).")
            return self._through_transit(hop, attachment, target, direction, steps)

        if hop.startswith("vgw-"):
            if in_aws:
                step(BLOCKED, "route", where, f"{via} sends it out of AWS, {outside}.")
                return {"kind": "stop"}
            step(OK, "route", where, f"{via}: leaves AWS through the virtual private gateway (VPN or Direct Connect).")
            return {"kind": "exit", "exit": {"kind": "vgw", "id": hop}}

        if hop.startswith(("igw-", "eigw-", "nat-")):
            gateway = "NAT gateway" if hop.startswith("nat-") else "internet gateway"
            if in_aws:
                step(BLOCKED, "route", where, f"{via} sends it to the {gateway}, {outside}.")
                return {"kind": "stop"}
            if not net.is_global:
                step(BLOCKED, "route", where, f"{via} sends {_show(net)}, a private address, to the {gateway}.")
                return {"kind": "stop"}
            instance = origin["instance"]
            if hop.startswith("igw-") and instance is not None and not _text(instance["meta"].get("public_ip")):
                step(
                    BLOCKED,
                    "route",
                    where,
                    f"{via}, but {self._instance_name(instance)} has no public address: "
                    "an internet gateway only serves addresses that have one.",
                )
                return {"kind": "stop"}
            needs = "" if hop.startswith("nat-") or instance is not None else " (an instance needs a public address)"
            step(OK, "route", where, f"{via}: leaves through the {gateway}{needs}.")
            return {"kind": "exit", "exit": {"kind": "nat" if hop.startswith("nat-") else "igw", "id": hop}}

        if hop.startswith(("eni-", "i-")):
            appliance = self._interface_owner.get(hop) or self._by_type.get("instance", {}).get(hop)
            name = self._instance_name(appliance) if appliance else hop
            carrier = (carriers or {}).get(appliance["rid"]) if appliance else None
            if carrier is not None and not in_aws:
                step(OK, "route", where, f"{via} hands it to {name}, which is {carrier.name}.")
                carried = True
                for status, at, text in carrier.carry(origin["net"], net):
                    step(status, "vpn", at, text)
                    carried = carried and status == OK
                if not carried:
                    return {"kind": "stop"}
                interfaces = [i for i in appliance["meta"].get("interfaces") or [] if isinstance(i, dict)]
                held = next((i.get("private_ips") or [] for i in interfaces if _text(i.get("id")) == hop), [])
                address = _text(held[0]) if held else _text(appliance["meta"].get("private_ip"))
                gateway = {"kind": "appliance", "instance": appliance, "address": address, "name": carrier.name}
                return {"kind": "exit", "exit": gateway}
            step(
                UNKNOWN,
                "route",
                where,
                f"{via} hands it to {name}. Whether that appliance forwards it is decided by its own "
                "configuration, which AWS does not describe.",
            )
            return {"kind": "stop"}

        step(UNKNOWN, "route", where, f"{via}: this kind of target is not followed.")
        return {"kind": "stop"}

    def _through_transit(self, tgw_id: str, attachment: dict, target: dict, direction: str, steps: list[dict]) -> dict:
        """Route ``target``'s address through a transit gateway it reached on
        ``attachment`` (and on through peered transit gateways)."""

        def step(status: str, where: str, text: str) -> None:
            steps.append({"direction": direction, "stage": "transit", "status": status, "where": where, "text": text})

        net = target["net"]
        in_aws = target["subnet"] is not None
        for _hop in range(MAX_TRANSIT_HOPS):
            gateway = f"Transit gateway {self._name('transit_gateway', tgw_id)}"
            if attachment["state"] not in ("", "available"):
                step(BLOCKED, gateway, f"Attachment {attachment['id']} is {attachment['state']}.")
                return {"kind": "stop"}
            if attachment["table"] is None or (attachment["table"] and attachment["table"] not in self._tgw_tables):
                step(
                    UNKNOWN,
                    gateway,
                    "Its route tables were not collected. Run discovery again; it needs "
                    "ec2:DescribeTransitGatewayRouteTables and ec2:SearchTransitGatewayRoutes.",
                )
                return {"kind": "stop"}
            if not attachment["table"]:
                step(BLOCKED, gateway, f"Attachment {attachment['id']} is not associated with a route table.")
                return {"kind": "stop"}
            table = self._tgw_tables[attachment["table"]]
            where = f"{gateway}, route table {_text(table.get('name')) or table['rid']}"
            route, _narrower, prefix_lists = _longest(table["meta"].get("routes") or [], net)
            if route is None:
                unread = prefix_lists or table["meta"].get("truncated")
                extra = " (not every route of the table could be read)" if unread else ""
                step(UNKNOWN if unread else BLOCKED, where, f"No route to {_show(net)}{extra}.")
                return {"kind": "stop"}
            destination = _text(route.get("destination"))
            if _text(route.get("state")).lower() == "blackhole":
                step(BLOCKED, where, f"Route {destination} is a blackhole.")
                return {"kind": "stop"}
            hops = [h for h in route.get("attachments") or [] if isinstance(h, dict)]
            if not hops:
                step(UNKNOWN, where, f"Route {destination} names no attachment.")
                return {"kind": "stop"}
            hop = hops[0]
            kind, resource_id = _text(hop.get("resource_type")), _text(hop.get("resource_id"))
            via = f"{destination} via attachment {_text(hop.get('attachment_id'))}"

            if kind == "vpc":
                if in_aws and target["vpc_id"] == resource_id:
                    step(OK, where, f"{via} to {self._vpc_name(resource_id)}.")
                    return {"kind": "delivered"}
                step(
                    UNKNOWN,
                    where,
                    f"{via} hands it to {self._vpc_name(resource_id)}, which does not hold {_show(net)} "
                    "(an inspection or egress VPC). It is not followed further.",
                )
                return {"kind": "stop"}

            if kind in ("vpn", "direct-connect-gateway"):
                if kind == "vpn":
                    vpn = self._by_type.get("vpn_connection", {}).get(resource_id)
                    name = f"VPN {self._name('vpn_connection', resource_id)}"
                    tunnels = [t for t in ((vpn or {}).get("meta", {}).get("tunnels") or []) if isinstance(t, dict)]
                    if tunnels and not any(_text(t.get("status")).upper() == "UP" for t in tunnels):
                        step(BLOCKED, where, f"{via} to {name}, but every tunnel of that VPN is down.")
                        return {"kind": "stop"}
                else:
                    name = f"Direct Connect gateway {self._name('direct_connect_gateway', resource_id)}"
                if in_aws:
                    where_to = self._vpc_name(target["vpc_id"])
                    step(BLOCKED, where, f"{via} sends it out of AWS over {name}, but {_show(net)} is in {where_to}.")
                    return {"kind": "stop"}
                step(OK, where, f"{via}: leaves AWS over {name}.")
                leaving = next((a for a in self._attachments if a["id"] == _text(hop.get("attachment_id"))), None)
                return {"kind": "exit", "exit": {"kind": "tgw", "id": tgw_id, "attachment": leaving, "name": name}}

            if kind == "peering":
                arriving = next(
                    (
                        a
                        for a in self._attachments
                        if a["id"] == _text(hop.get("attachment_id")) and a["tgw"] == resource_id
                    ),
                    None,
                )
                if arriving is None:
                    step(UNKNOWN, where, f"{via} to peered transit gateway {resource_id}, which was not collected.")
                    return {"kind": "stop"}
                step(OK, where, f"{via} to peered transit gateway {self._name('transit_gateway', resource_id)}.")
                tgw_id, attachment = resource_id, arriving
                continue

            step(UNKNOWN, where, f"{via}: a {kind or 'unknown'} attachment is not followed.")
            return {"kind": "stop"}
        step(BLOCKED, f"Transit gateway {tgw_id}", "Routing loop between transit gateways.")
        return {"kind": "stop"}

    def _enter(self, left: dict, target: dict, direction: str, initiating: bool, steps: list[dict]) -> None:
        """Traffic from outside AWS towards ``target``, coming in through the
        gateway the opposite direction left by. ``initiating`` is whether the
        outside end opens the connection (else this is the reply)."""

        def step(status: str, where: str, text: str) -> None:
            steps.append({"direction": direction, "stage": "route", "status": status, "where": where, "text": text})

        if left["kind"] != "exit":
            step(
                INFO,
                "Entering AWS",
                "Not checked: the opposite direction does not leave AWS, so no entry point is known.",
            )
            return
        gateway = left["exit"]
        if gateway["kind"] == "appliance":
            instance = gateway["instance"]
            origin = self.locate(gateway["address"], _text(instance["meta"].get("vpc_id")))
            if origin["subnet"] is None:
                step(UNKNOWN, gateway["name"], f"The subnet of {self._instance_name(instance)} was not collected.")
                return
            step(OK, gateway["name"], f"Enters AWS at {self._instance_name(instance)} in {origin['label']}.")
            self._walk(origin, target, direction, steps)
            return
        vpc = self._vpc_name(target["vpc_id"])
        if gateway["kind"] == "tgw":
            if gateway["attachment"] is None:
                step(
                    UNKNOWN,
                    f"Transit gateway {gateway['id']}",
                    f"The attachment of {gateway['name']} was not collected.",
                )
                return
            step(
                OK,
                f"Transit gateway {self._name('transit_gateway', gateway['id'])}",
                f"Enters AWS over {gateway['name']}.",
            )
            self._through_transit(gateway["id"], gateway["attachment"], target, direction, steps)
        elif gateway["kind"] == "vgw":
            attached = (self._by_type.get("vpn_gateway", {}).get(gateway["id"]) or {}).get("meta", {}).get(
                "vpc_ids"
            ) or []
            if attached and target["vpc_id"] not in attached:
                step(BLOCKED, f"Virtual private gateway {gateway['id']}", f"It is not attached to {vpc}.")
            else:
                step(
                    OK, f"Virtual private gateway {gateway['id']}", f"Enters {vpc} through the gateway attached to it."
                )
        elif not initiating:
            step(OK, "Internet", "Replies come back through the gateway the request left by.")
        elif gateway["kind"] == "nat":
            step(
                BLOCKED, f"NAT gateway {gateway['id']}", "A NAT gateway does not accept connections from the internet."
            )
        elif target["instance"] is None:
            step(
                PARTIAL,
                f"Internet gateway {gateway['id']}",
                "Only instances with a public address are reachable from the internet.",
            )
        elif _text(target["instance"]["meta"].get("public_ip")):
            step(OK, f"Internet gateway {gateway['id']}", "The instance has a public address.")
        else:
            name = self._instance_name(target["instance"])
            step(BLOCKED, f"Internet gateway {gateway['id']}", f"{name} has no public address.")

    # ── Network ACLs ───────────────────────────────────────────────────────

    def _acl(
        self, place: dict, peer: dict, egress: bool, protocol: str, ports: tuple[int, int] | None, direction: str
    ) -> dict:
        subnet = place["subnet"]
        way = "outbound" if egress else "inbound"
        acl = self._acl_of_subnet.get(subnet["rid"])
        if acl is None:
            return {
                "direction": direction,
                "stage": "acl",
                "status": UNKNOWN,
                "where": f"Network ACL of {self._subnet_name(subnet)}",
                "text": "Not collected. Run discovery again; it needs ec2:DescribeNetworkAcls.",
            }
        where = f"Network ACL {_text(acl.get('name')) or acl['rid']} of {self._subnet_name(subnet)}, {way}"
        entries = [
            e for e in acl["meta"].get("entries") or [] if isinstance(e, dict) and bool(e.get("egress")) == egress
        ]
        entries.sort(key=lambda e: _int(e.get("rule_number")) or 0)
        decided: dict | None = None
        partly: list[dict] = []
        for entry in entries:
            cover = min(
                _cidr_cover(entry.get("cidr"), peer["net"]),
                _traffic_cover(
                    _text(entry.get("protocol")),
                    _int(entry.get("port_from")),
                    _int(entry.get("port_to")),
                    protocol,
                    ports,
                ),
            )
            if cover == _FULL:
                decided = entry
                break
            if cover == _PART:
                partly.append(entry)

        def rule(entry: dict) -> str:
            number = entry.get("rule_number")
            return "the final deny" if number == 32767 else f"rule {number}"

        action = _text(decided.get("action")) if decided else "deny"
        final = rule(decided) if decided else "no rule matches"
        # Earlier rules that take part of the traffic the other way.
        other = [e for e in partly if _text(e.get("action")) != action]
        if other:
            first = ", ".join(rule(e) for e in other[:4])
            verb = (
                ("allow" if action == "deny" else "deny")
                if len(other) > 1
                else ("allows" if action == "deny" else "denies")
            )
            text = f"{first} {verb} part of it; the rest is {'denied' if action == 'deny' else 'allowed'} by {final}."
            status = PARTIAL
        elif action == "allow":
            status, text = OK, f"Allowed by {final}."
        else:
            status, text = BLOCKED, f"Denied by {final}."
        return {"direction": direction, "stage": "acl", "status": status, "where": where, "text": text}

    # ── Security groups ────────────────────────────────────────────────────

    def _groups_of(self, place: dict) -> tuple[list[dict], list[str]]:
        """Security groups of the instance at ``place`` and the ones named but not collected."""
        instance, interface = place["instance"], place["interface"]
        ids = (interface or {}).get("security_group_ids") or instance["meta"].get("security_group_ids") or []
        if ids:
            groups = [self._groups[i] for i in ids if i in self._groups]
            return groups, [i for i in ids if i not in self._groups]
        # A discovery made before group ids were read names the groups only.
        names = [_text(n) for n in instance["meta"].get("security_groups") or []]
        groups = [
            self._group_by_name[(place["vpc_id"], n)] for n in names if (place["vpc_id"], n) in self._group_by_name
        ]
        return groups, [n for n in names if (place["vpc_id"], n) not in self._group_by_name]

    def _peer_cover(self, selector: str, peer: dict, peer_groups: set[str]) -> int:
        best = _NONE
        for item in (part.strip() for part in selector.split(",")):
            if item == "any":
                cover = _FULL
            elif "sg:" in item:
                group_id = item.split("sg:", 1)[1]
                if peer["subnet"] is None:
                    cover = _NONE
                elif peer["instance"] is None:
                    cover = _PART  # depends on which instance of the subnet
                else:
                    cover = _FULL if group_id in peer_groups else _NONE
            elif item.startswith("prefix:"):
                cover = _PART  # the prefix list's entries are not collected
            else:
                cover = _cidr_cover(item, peer["net"])
            best = max(best, cover)
        return best

    def _security_groups(
        self, place: dict, peer: dict, outbound: bool, protocol: str, ports: tuple[int, int] | None
    ) -> dict | None:
        if place["subnet"] is None:
            return None
        way = "outbound" if outbound else "inbound"
        result = {"direction": FORWARD, "stage": "security_group"}
        if place["instance"] is None:
            what = "no collected instance has this address" if _is_host(place["net"]) else "this end is a whole subnet"
            return {
                **result,
                "status": INFO,
                "where": f"Security groups at {place['label']}, {way}",
                "text": f"Not checked: security groups belong to an instance, and {what}. Pick an instance's IP address.",
            }
        groups, missing = self._groups_of(place)
        where = f"Security groups of {self._instance_name(place['instance'])}, {way}"
        if not groups:
            return {**result, "status": UNKNOWN, "where": where, "text": "Its security groups were not collected."}
        peer_groups = {g["rid"] for g in self._groups_of(peer)[0]} if peer["instance"] is not None else set()
        allowing: list[str] = []
        partly: list[str] = []
        for group in groups:
            for rule in group["meta"].get("policy_rules") or []:
                if not isinstance(rule, dict) or _text(rule.get("direction")) != way:
                    continue
                selector = _text(rule.get("destination_selector" if outbound else "source_selector"))
                cover = min(
                    self._peer_cover(selector, peer, peer_groups),
                    _traffic_cover(
                        _text(rule.get("protocol")), *_port_range(rule.get("port_expression")), protocol, ports
                    ),
                )
                if cover == _NONE:
                    continue
                rule_protocol = _text(rule.get("protocol"))
                what = (
                    "all traffic" if rule_protocol == "all" else f"{rule_protocol} {_text(rule.get('port_expression'))}"
                )
                shown = f"{_text(group.get('name')) or group['rid']}: {what} {'to' if outbound else 'from'} {selector}"
                (allowing if cover == _FULL else partly).append(shown)
        names = ", ".join(_text(g.get("name")) or g["rid"] for g in groups)
        if allowing:
            return {**result, "status": OK, "where": where, "text": f"Allowed by {allowing[0]}."}
        if partly:
            return {
                **result,
                "status": PARTIAL,
                "where": where,
                "text": f"Only part of it is allowed: {'; '.join(partly[:4])}.",
            }
        if missing:
            return {
                **result,
                "status": UNKNOWN,
                "where": where,
                "text": f"No rule of {names} allows it; {', '.join(missing)} was not collected.",
            }
        return {**result, "status": BLOCKED, "where": where, "text": f"No rule of {names} allows it."}

    # ── One direction at a time (path tracing) ─────────────────────────────
    # Thin public wrappers over the walk ``check`` uses, so a trace across
    # other devices can hand a flow into AWS and get it back at the gateway
    # it leaves by. None of them changes the index.

    def walk(
        self, origin: dict, target: dict, direction: str, steps: list[dict], carriers: dict[str, Any] | None = None
    ) -> dict:
        """Follow ``target``'s address from ``origin``'s subnet, appending the
        steps to ``steps``: ``delivered``, ``exit`` (with the gateway) or ``stop``."""
        return self._walk(origin, target, direction, steps, carriers)

    def enter(self, left: dict, target: dict, direction: str, initiating: bool, steps: list[dict]) -> None:
        """Traffic from outside AWS towards ``target`` through the gateway ``left`` names."""
        self._enter(left, target, direction, initiating, steps)

    def acl(
        self, place: dict, peer: dict, egress: bool, protocol: str, ports: tuple[int, int] | None, direction: str
    ) -> dict:
        """The network ACL step of ``place``'s subnet for traffic to or from ``peer``."""
        return self._acl(place, peer, egress, protocol, ports, direction)

    def security_groups(
        self, place: dict, peer: dict, outbound: bool, protocol: str, ports: tuple[int, int] | None
    ) -> dict | None:
        """The security group step of the instance at ``place`` (``None`` outside AWS)."""
        return self._security_groups(place, peer, outbound, protocol, ports)

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
        ``carriers`` maps an instance id to the carrier of that appliance."""
        protocol = _text(protocol).lower()
        protocol = "" if protocol in ("any", "all") else protocol
        if protocol and protocol not in PROTOCOLS:
            raise ValueError(f"protocol must be one of {', '.join(PROTOCOLS)}")
        ports = (port, port) if port is not None and protocol in ("tcp", "udp") else None
        reply_ports = EPHEMERAL_PORTS if protocol in ("tcp", "udp") else None
        src, dst = self.locate(source, source_vpc), self.locate(destination, destination_vpc)
        if src["net"].version != dst["net"].version:
            raise ValueError("source and destination must both be IPv4 or both be IPv6")

        result: dict[str, Any] = {
            "applies": True,
            "source": {"address": src["address"], "label": src["label"], "in_aws": src["subnet"] is not None},
            "destination": {"address": dst["address"], "label": dst["label"], "in_aws": dst["subnet"] is not None},
            "traffic": "any traffic" if not protocol else protocol + (f"/{port}" if ports else ""),
            "steps": [],
        }
        for place in (src, dst):
            if place["ambiguous"]:
                where = ", ".join(place["ambiguous"])
                return {
                    **result,
                    "verdict": UNKNOWN,
                    "summary": f"{place['address']} exists in several VPCs ({where}).",
                }
        if src["subnet"] is None and dst["subnet"] is None:
            return {**result, "applies": False, "verdict": UNKNOWN, "summary": "Neither address is in a collected VPC."}

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

        # A network ACL guards the edge of a subnet: not traffic inside one.
        if src["subnet"] is not dst["subnet"]:
            if src["subnet"] is not None:
                forward.append(self._acl(src, dst, True, protocol, ports, FORWARD))
                back.append(self._acl(src, dst, False, protocol, reply_ports, RETURN))
            if dst["subnet"] is not None:
                forward.append(self._acl(dst, src, False, protocol, ports, FORWARD))
                back.insert(
                    next((i for i, s in enumerate(back) if s["stage"] == "acl"), len(back)),
                    self._acl(dst, src, True, protocol, reply_ports, RETURN),
                )
        # Security groups are stateful: a permitted request is answered.
        for step in (
            self._security_groups(src, dst, True, protocol, ports),
            self._security_groups(dst, src, False, protocol, ports),
        ):
            if step:
                forward.append(step)

        steps = forward + back
        result["steps"] = steps
        statuses = [s["status"] for s in steps]
        first = {
            status: next((s for s in steps if s["status"] == status), None) for status in (BLOCKED, UNKNOWN, PARTIAL)
        }
        if first[BLOCKED]:
            verdict, lead = BLOCKED, first[BLOCKED]
            summary = f"Blocked at {lead['where']}: {lead['text']}"
        elif first[UNKNOWN]:
            verdict, lead = UNKNOWN, first[UNKNOWN]
            summary = f"Could not be decided at {lead['where']}: {lead['text']}"
        elif first[PARTIAL]:
            verdict, lead = PARTIAL, first[PARTIAL]
            summary = f"Allowed in part. {lead['where']}: {lead['text']}"
        else:
            verdict = "allowed"
            checked = (
                "route tables, network ACLs and security groups"
                if INFO not in statuses
                else "route tables and network ACLs"
            )
            summary = f"Allowed by the {checked} in both directions."
            if INFO in statuses:
                summary += " Security groups were not checked for an end that is not an instance."
        return {**result, "verdict": verdict, "summary": summary}
