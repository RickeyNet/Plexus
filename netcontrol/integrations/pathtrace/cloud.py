"""The AWS and Azure hops of a path trace.

A flow that reaches a VPC or VNet is handed to that cloud's reachability
engine (``netcontrol.integrations.aws.reachability`` or
``netcontrol.integrations.azure.reachability``), one direction at a time:

  - a flow that starts in the cloud, or arrives from an instance in it (a
    Meraki vMX, an FTDv), is walked from that subnet's route table
  - a flow that arrives from outside enters through the gateway the cloud's
    own walk back to the source leaves by, as the engine's ``check`` does

The engine's steps become the items of the hops, with their ``where`` and
``text`` kept as they are: the route tables and network ACLs of the VPC,
the transit gateway route tables in a hop of the transit gateway, the
security groups or network security groups of the instances at the ends.
How the walk leaves the cloud is mapped back to a snapshot node: the device
at the far end of a VPN, the Internet, or the instance a device on the map is.

Pure (no I/O).
"""

from __future__ import annotations

import re
from typing import Any

from netcontrol.integrations.aws.reachability import FORWARD, RETURN
from netcontrol.integrations.azure.normalize import _rid as azure_rid
from netcontrol.integrations.pathtrace.model import (
    ACL,
    BLOCKED,
    INFO,
    OK,
    ROUTE,
    SECURITY_GROUP,
    UNKNOWN,
    item,
    show,
)

_STAGES = {"route": ROUTE, "transit": ROUTE, "vpn": ROUTE, "acl": ACL, "security_group": SECURITY_GROUP}
_TGW = re.compile(r"\b(tgw-[0-9A-Za-z]+)\b")


class _HandOff:
    """A carrier for an instance that is a device the trace follows itself:
    the engine hands the flow to it and the device's own hop says the rest."""

    def __init__(self, name: str) -> None:
        self.name = name

    def carry(self, _inside: Any, _outside: Any) -> list:
        return []


class CloudAdapter:
    """One cloud (AWS or Azure) of the map, for the tracer."""

    def __init__(
        self, provider: str, org_ref: int, engine: Any, snapshot: dict, handoffs: dict[str, str] | None = None
    ) -> None:
        self.provider = provider
        self.org_ref = org_ref
        self.engine = engine
        self.azure = provider == "azure"
        self.term = "Azure" if self.azure else "AWS"
        self._nodes = {n["id"]: n for n in snapshot.get("nodes") or [] if isinstance(n, dict)}
        self._vpn: dict[str, list[tuple[str, dict]]] = {}
        for edge in snapshot.get("edges") or []:
            if isinstance(edge, dict) and edge.get("kind") in ("vpn", "vpn3p"):
                self._vpn.setdefault(edge["a"], []).append((edge["b"], edge))
                self._vpn.setdefault(edge["b"], []).append((edge["a"], edge))
        self.carriers = {rid: _HandOff(name) for rid, name in (handoffs or {}).items()}

    # ── Places ─────────────────────────────────────────────────────────────

    def locate(self, network: Any, network_id: str = "") -> dict:
        return self.engine.locate(network if isinstance(network, str) else show(network), network_id)

    def holds(self, network: Any, network_id: str = "") -> bool:
        """Whether the address or network is in a collected subnet of this cloud."""
        try:
            return self.locate(network, network_id)["subnet"] is not None
        except ValueError:
            return False

    def network_node(self, place: dict) -> str:
        """The snapshot node of the VPC or VNet of ``place``."""
        return f"vnet:{place['vnet_id']}" if self.azure else f"vpc:{place['vpc_id']}"

    @staticmethod
    def network_id(node_id: Any) -> str:
        """The VPC or VNet id of a ``vpc:`` / ``vnet:`` snapshot node id."""
        for prefix in ("vpc:", "vnet:"):
            if str(node_id).startswith(prefix):
                return str(node_id)[len(prefix) :]
        return ""

    def instance_node(self, rid: str) -> str:
        return f"vm:{rid}" if self.azure else f"i:{rid}"

    # ── One direction through the cloud ────────────────────────────────────

    def cross(
        self,
        flow: Any,
        *,
        reply: bool,
        first: bool,
        entry_address: str = "",
        entry_network: str = "",
        src_network: str = "",
        dst_network: str = "",
    ) -> dict[str, Any]:
        """Walk ``flow`` (``src``, ``dst``, ``protocol``, ``dst_ports``)
        through the cloud. Returns ``segments`` (``[snapshot node id, items]``
        in order), ``kind`` (``delivered``, ``exit`` or ``stop``) and, for
        an exit, ``next`` (``{"node": id}`` or ``{"internet": True}``) and
        ``address`` (the address the next device receives the flow on).
        ``entry_network`` is the VPC or VNet ``entry_address`` is in: a
        range several of them use is otherwise in none."""
        engine = self.engine
        direction = RETURN if reply else FORWARD
        src = self.locate(flow.src, src_network if first else "")
        dst = self.locate(flow.dst, dst_network)
        segments: list[list[Any]] = []

        def segment(node_id: str) -> list[dict]:
            for found in segments:
                if found[0] == node_id:
                    return found[1]
            segments.append([node_id, []])
            return segments[-1][1]

        origin = None
        if first and src["subnet"] is not None:
            origin = src
        elif entry_address:
            place = self.locate(entry_address, entry_network)
            if place["subnet"] is not None:
                origin = place

        if origin is not None:
            home = segment(self.network_node(origin))
            if origin is src:
                home.extend(self._groups(src, dst, True, flow, reply))
                if src["subnet"] is not dst["subnet"]:
                    home.extend(self._acl(src, dst, True, flow, direction))
            steps: list[dict] = []
            left = engine.walk(origin, dst, direction, steps, self.carriers)
            self._place(steps, home, segment)
        else:
            if dst["subnet"] is None:
                text = (
                    f"{show(flow.dst)} is not in a collected subnet of {self.term}, "
                    "so its path through it is not known."
                )
                segment(next(iter(self._nodes), "")).append(item(ROUTE, UNKNOWN, f"{self.term} routing", text))
                return {"segments": segments, "kind": "stop"}
            scratch: list[dict] = []
            back = engine.walk(dst, src, RETURN, scratch, self.carriers)
            steps = []
            engine.enter(back, dst, direction, not reply, steps)
            gateway = self._gateway_node(back)
            home = segment(gateway if gateway in self._nodes else self.network_node(dst))
            self._place(steps, home, segment)
            failed = any(s["status"] in (BLOCKED, UNKNOWN) for s in steps)
            left = {"kind": "stop"} if failed else {"kind": "delivered"}

        result: dict[str, Any] = {"segments": segments, "kind": left["kind"]}
        if left["kind"] == "delivered":
            arrived = segment(self.network_node(dst))
            if src["subnet"] is not dst["subnet"]:
                arrived.extend(self._acl(dst, src, False, flow, direction))
            arrived.extend(self._groups(dst, src, False, flow, reply))
        elif left["kind"] == "exit":
            result.update(self._exit(left["exit"], segment))
        return result

    # ── Steps to items ─────────────────────────────────────────────────────

    def _place(self, steps: list[dict], home: list[dict], segment: Any) -> None:
        """Steps as items: a transit gateway's in the hop of that gateway."""
        for step in steps:
            target = home
            if step.get("stage") == "transit":
                match = _TGW.search(str(step.get("where") or ""))
                if match and f"tgw:{match.group(1)}" in self._nodes:
                    target = segment(f"tgw:{match.group(1)}")
            target.append(_item(step))

    def _acl(self, place: dict, peer: dict, egress: bool, flow: Any, direction: str) -> list[dict]:
        if self.azure or place["subnet"] is None:
            return []  # Azure has no network ACLs; its security groups are stateful.
        return [_item(self.engine.acl(place, peer, egress, flow.protocol, flow.dst_ports, direction))]

    def _groups(self, place: dict, peer: dict, outbound: bool, flow: Any, reply: bool) -> list[dict]:
        if place["subnet"] is None:
            return []
        if reply:
            what = "Network security groups" if self.azure else "Security groups"
            return [
                item(
                    SECURITY_GROUP,
                    INFO,
                    f"{what} at {place['label']}",
                    "Stateful: the reply of an allowed request is accepted.",
                )
            ]
        found = self.engine.security_groups(place, peer, outbound, flow.protocol, flow.dst_ports)
        steps = found if isinstance(found, list) else [found] if found else []
        return [_item(step) for step in steps]

    # ── Where the walk leaves the cloud ────────────────────────────────────

    def _gateway_node(self, left: dict) -> str:
        """The snapshot node of the gateway a walk left by (or enters by)."""
        if left.get("kind") != "exit":
            return ""
        gateway = left["exit"]
        kind = gateway.get("kind")
        if kind in ("vgw", "tgw", "igw", "nat"):
            return f"{kind}:{gateway.get('id')}"
        if kind == "gateway":
            return f"vng:{gateway['gateway']['rid']}"
        if kind == "internet" and gateway.get("nat"):
            return f"nat:{azure_rid(str(gateway['nat']))}"
        return ""

    def _far_end(self, gateway_node: str, name: str = "") -> str:
        """The node at the far end of a VPN of ``gateway_node``."""
        ends = self._vpn.get(gateway_node, [])
        if name:
            named = [far for far, edge in ends if edge.get("detail") and str(edge["detail"]) in name]
            if named:
                return named[0]
        return ends[0][0] if len(ends) == 1 else ""

    def _leaves(self, node: str, segment: Any, text: str) -> None:
        if node in self._nodes:
            segment(node).append(item(ROUTE, INFO, self._nodes[node].get("label") or node, text))

    def _exit(self, gateway: dict, segment: Any) -> dict[str, Any]:
        kind = gateway.get("kind")
        if kind == "appliance":
            rid = gateway["instance"]["rid"]
            return {"kind": "exit", "next": {"node": self.instance_node(rid)}, "address": gateway.get("address") or ""}
        node = self._gateway_node({"kind": "exit", "exit": gateway})
        if kind in ("igw", "nat", "internet"):
            self._leaves(node, segment, f"The flow leaves {self.term} here, to the internet.")
            return {"kind": "exit", "next": {"internet": True}, "address": ""}
        far = ""
        if kind == "tgw":
            attachment = gateway.get("attachment") or {}
            if attachment.get("resource_type") == "direct-connect-gateway":
                far = f"dxgw:{attachment.get('resource_id')}"
            else:
                far = self._far_end(node, str(gateway.get("name") or ""))
        elif kind == "vgw":
            self._leaves(node, segment, f"The flow leaves {self.term} here, over the VPN.")
            far = self._far_end(node)
        elif kind == "gateway":
            connection = gateway.get("connection") or {}
            target = azure_rid(str(connection.get("target") or ""))
            far = next((f"{p}:{target}" for p in ("lng", "vpn", "vng") if f"{p}:{target}" in self._nodes), "")
            name = connection.get("name") or target
            self._leaves(node, segment, f"The flow leaves {self.term} here, over connection {name}.")
        if far and far in self._nodes:
            return {"kind": "exit", "next": {"node": far}, "address": ""}
        where = self._nodes.get(node, {}).get("label") or node or f"{self.term} gateway"
        segment(node if node in self._nodes else next(iter(self._nodes), "")).append(
            item(ROUTE, UNKNOWN, where, f"The far end of this {self.term} gateway is not on the map.")
        )
        return {"kind": "stop"}


def _item(step: dict) -> dict:
    return item(
        _STAGES.get(str(step.get("stage")), ROUTE),
        str(step.get("status") or OK),
        str(step.get("where") or ""),
        str(step.get("text") or ""),
    )
