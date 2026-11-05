"""The AWS, Azure and GCP hops of a path trace.

A flow that reaches a VPC, VNet or VPC network is handed to that cloud's
reachability engine (``netcontrol.integrations.aws.reachability``,
``netcontrol.integrations.azure.reachability`` or
``netcontrol.integrations.gcp.reachability``), one direction at a time:

  - a flow that starts in the cloud, or arrives from an instance in it (a
    Meraki vMX, an FTDv), is walked from that subnet's routes
  - a flow that arrives from outside enters through the gateway the cloud's
    own walk back to the source leaves by, as the engine's ``check`` does
  - a flow from outside to the public address of an instance (an EC2
    public or Elastic IP, an Azure VM's public IP, a GCP external IP, as
    collected on the instance's interfaces) is delivered to the private
    address it stands for (``public_addresses``), and the hop says so

The source a flow from outside carries is the address it left its own
network with. Where that network reported several candidates (a Cato
network rule that NATs to one of several allocated IPs, ``Flow.src_options``)
the network ACLs and security groups are checked for each and the item says
which pass; where it reported none (``Flow.src_unknown``: the shared address
of a Cato PoP) the source is any public address, and an item that only part
of the public address space passes is unknown, with the rules that decide
listed. A private address never stands in for it.

The engine's steps become the items of the hops, with their ``where`` and
``text`` kept as they are: the route tables and network ACLs of the VPC,
the transit gateway route tables in a hop of the transit gateway, the
security groups, network security groups or VPC firewall rules of the
instances at the ends. How the walk leaves the cloud is mapped back to a
snapshot node: the device at the far end of a VPN, the Internet, or the
instance a device on the map is. GCP has no network ACLs; its VPC firewall
rules are stateful, like security groups.

Pure (no I/O).
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from netcontrol.integrations.aws.reachability import FORWARD, RETURN
from netcontrol.integrations.azure.normalize import _rid as azure_rid
from netcontrol.integrations.pathtrace.model import (
    ACL,
    BLOCKED,
    INFO,
    NAT,
    OK,
    PARTIAL,
    ROUTE,
    SECURITY_GROUP,
    UNKNOWN,
    item,
    show,
    worst,
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


_TERMS = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
# Owners whose public addresses are not an instance's own: an Azure Firewall
# answers on its public IPs with DNAT rules, which are not collected.
_NOT_INSTANCES = ("azure_firewall",)


def public_addresses(owners: dict, skip: set[str] | None = None) -> dict[str, tuple[str, str, dict]]:
    """``public address -> (private address, network id, owner)`` of the
    instances in an engine's ``address_owners`` index (``(network, private
    address) -> (instance, interface)``), leaving out the instances in
    ``skip`` (devices the trace follows itself).

    The instance's own ``public_ip`` stands for its primary private address,
    as AWS, Azure and GCP report it. A public address listed on an interface
    stands for that interface's first private address: the collectors keep
    an interface's private and public addresses as two lists, and the
    interface (its subnet, ACL and security groups) is what the trace checks."""
    found: dict[str, tuple[str, str, dict]] = {}
    later: list[tuple[str, str, dict, dict]] = []
    for (network, private), (owner, interface) in owners.items():
        if not isinstance(owner, dict) or owner.get("resource_type") in _NOT_INSTANCES:
            continue
        if str(owner.get("rid") or "") in (skip or set()):
            continue
        meta = owner.get("meta") or {}
        public = str(meta.get("public_ip") or "").strip()
        if public and private == str(meta.get("private_ip") or "").strip():
            found.setdefault(public, (private, str(network), owner))
        if isinstance(interface, dict):
            later.append((str(network), private, owner, interface))
    for network, private, owner, interface in later:
        held = [str(p) for p in interface.get("private_ips") or [] if str(p)]
        if held and private != held[0]:
            continue
        for public in interface.get("public_ips") or []:
            if str(public).strip():
                found.setdefault(str(public).strip(), (private, network, owner))
    return found


class CloudAdapter:
    """One cloud (AWS, Azure or GCP) of the map, for the tracer."""

    def __init__(
        self, provider: str, org_ref: int, engine: Any, snapshot: dict, handoffs: dict[str, str] | None = None
    ) -> None:
        self.provider = provider
        self.org_ref = org_ref
        self.engine = engine
        self.azure = provider == "azure"
        self.gcp = provider == "gcp"
        self.term = _TERMS.get(provider, "AWS")
        self._nodes = {n["id"]: n for n in snapshot.get("nodes") or [] if isinstance(n, dict)}
        self._vpn: dict[str, list[tuple[str, dict]]] = {}
        for edge in snapshot.get("edges") or []:
            if isinstance(edge, dict) and edge.get("kind") in ("vpn", "vpn3p"):
                self._vpn.setdefault(edge["a"], []).append((edge["b"], edge))
                self._vpn.setdefault(edge["b"], []).append((edge["a"], edge))
        self.carriers = {rid: _HandOff(name) for rid, name in (handoffs or {}).items()}
        owners = getattr(engine, "address_owners", None)
        # The public addresses of the instances, but those of a device the
        # trace follows itself (its own block says what it does with them).
        self.public = public_addresses(owners() if callable(owners) else {}, set(self.carriers))

    def public_networks(self) -> dict[str, tuple[str, str]]:
        """``public address -> (snapshot node of its VPC or VNet, instance
        name)``, for the tracer to know who answers on it."""
        return {
            public: (f"vnet:{network}" if self.azure else f"vpc:{network}", str(owner.get("name") or owner.get("rid")))
            for public, (_private, network, owner) in self.public.items()
        }

    # ── Places ─────────────────────────────────────────────────────────────

    def locate(self, network: Any, network_id: str = "") -> dict:
        return self.engine.locate(network if isinstance(network, str) else show(network), network_id)

    def holds(self, network: Any, network_id: str = "") -> bool:
        """Whether the address or network is in a collected subnet of this cloud."""
        try:
            return self.locate(network, network_id)["subnet"] is not None
        except ValueError:
            return False

    def _public_place(self, network: Any) -> dict | None:
        """The place of the private address a public address of an instance
        stands for, else ``None``."""
        found = self.public.get(show(network)) if network.prefixlen == network.max_prefixlen else None
        if found is None:
            return None
        private, network_id, _owner = found
        try:
            place = self.locate(private, network_id)
        except ValueError:
            return None
        return place if place["subnet"] is not None else None

    def network_node(self, place: dict) -> str:
        """The snapshot node of the VPC, VNet or VPC network of ``place``."""
        return f"vnet:{place['vnet_id']}" if self.azure else f"vpc:{place['vpc_id']}"

    @staticmethod
    def network_id(node_id: Any) -> str:
        """The VPC, VNet or VPC network id of a ``vpc:`` / ``vnet:`` snapshot node id."""
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
        ``address`` (the address the next device receives the flow on); a
        delivery to the address of a collected instance names it in
        ``instance`` (its snapshot node id), and a delivery to the public
        address of one names the private address it went on to in
        ``translated_dst``. ``entry_network`` is the VPC or VNet
        ``entry_address`` is in: a range several of them use is otherwise in
        none. A flow from outside with several candidate sources
        (``flow.src_options``) is checked for each."""
        kwargs: dict[str, Any] = {
            "reply": reply,
            "first": first,
            "entry_address": entry_address,
            "entry_network": entry_network,
            "src_network": src_network,
            "dst_network": dst_network,
        }
        options = list(getattr(flow, "src_options", ()) or ())
        if len(options) > 1 and not reply and not first and not self.holds(flow.src):
            found = [self._cross(replace(flow, src=option), **kwargs) for option in options]
            return _merge(found, [show(option) for option in options])
        return self._cross(flow, **kwargs)

    def _cross(
        self,
        flow: Any,
        *,
        reply: bool,
        first: bool,
        entry_address: str,
        entry_network: str,
        src_network: str,
        dst_network: str,
    ) -> dict[str, Any]:
        engine = self.engine
        direction = RETURN if reply else FORWARD
        src = self.locate(flow.src, src_network if first else "")
        unknown = str(getattr(flow, "src_unknown", "") or "")
        if unknown and src["subnet"] is None:
            # A public address nobody reported: any of them, never a private one.
            src["public_unknown"] = True
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
            public = self._public_place(flow.dst) if dst["subnet"] is None and not reply else None
            if public is not None:
                dst = public
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
            if public is not None:
                text = f"{show(flow.dst)} is the public address of {dst['label']}: {self.term} delivers it there."
                home.append(item(NAT, OK, f"{self.term} public address", text))
            self._place(steps, home, segment)
            failed = any(s["status"] in (BLOCKED, UNKNOWN) for s in steps)
            left = {"kind": "stop"} if failed else {"kind": "delivered"}

        result: dict[str, Any] = {"segments": segments, "kind": left["kind"]}
        if left["kind"] == "delivered":
            arrived = segment(self.network_node(dst))
            checked: list[dict] = []
            if src["subnet"] is not dst["subnet"]:
                checked.extend(self._acl(dst, src, False, flow, direction))
            checked.extend(self._groups(dst, src, False, flow, reply))
            arrived.extend(_for_unknown_source(checked, unknown) if src.get("public_unknown") else checked)
            if dst.get("instance") is not None:
                result["instance"] = self.instance_node(str(dst["instance"]["rid"]))
            if dst["address"] != show(flow.dst):
                result["translated_dst"] = dst["address"]
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
        if self.azure or self.gcp or place["subnet"] is None:
            return []  # Azure and GCP have no network ACLs; their filtering is stateful.
        return [_item(self.engine.acl(place, peer, egress, flow.protocol, flow.dst_ports, direction))]

    def _groups(self, place: dict, peer: dict, outbound: bool, flow: Any, reply: bool) -> list[dict]:
        if place["subnet"] is None:
            return []
        if reply:
            what = "Network security groups" if self.azure else "Firewall rules" if self.gcp else "Security groups"
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
        if self.gcp:
            return self._gcp_gateway_node(gateway)
        if kind in ("vgw", "tgw", "igw", "nat"):
            return f"{kind}:{gateway.get('id')}"
        if kind == "gateway":
            return f"vng:{gateway['gateway']['rid']}"
        if kind == "internet" and gateway.get("nat"):
            return f"nat:{azure_rid(str(gateway['nat']))}"
        return ""

    @staticmethod
    def _gcp_gateway_node(gateway: dict) -> str:
        """The snapshot node of a GCP exit (see ``netcontrol.integrations.gcp.reachability``)."""
        kind = gateway.get("kind")
        if kind == "internet":
            return f"nat:{gateway['nat']}" if gateway.get("nat") else f"igw:{gateway.get('network')}"
        if kind == "vpn":
            prefix = "vpngw" if gateway.get("gateway_type", "ha") == "ha" else "tvpngw"
            return f"{prefix}:{gateway.get('gateway')}"
        if kind == "interconnect":
            return f"ia:{gateway.get('attachment')}"
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
        if self.gcp and kind == "vpn":
            self._leaves(node, segment, f"The flow leaves {self.term} here, over VPN tunnel {gateway.get('name')}.")
            far = self._far_end(node, str(gateway.get("name") or ""))
        elif self.gcp and kind == "interconnect":
            # The on-premises router behind an Interconnect is not collected.
            self._leaves(node, segment, f"The flow leaves {self.term} here, over the Interconnect attachment.")
        elif kind == "tgw":
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


def _for_unknown_source(found: list[dict], unknown: str) -> list[dict]:
    """The network ACL and security group items of a flow whose source is a
    public address nobody reported (``unknown`` says why). Only a rule for
    every address decides it; one that passes part of the public address
    space leaves it unknown, and the item lists the rules that would decide."""
    lead = unknown.rstrip(".")
    shown: list[dict] = []
    for entry in found:
        if entry["stage"] not in (ACL, SECURITY_GROUP) or entry["status"] == INFO:
            shown.append(entry)
            continue
        changed = {k: v for k, v in entry.items() if k != "ports"}
        if entry["status"] == PARTIAL:
            changed["status"] = UNKNOWN
            changed["text"] = f"{lead}, so whether this lets it in is not known. {entry['text']}"
        elif entry["status"] == BLOCKED:
            changed["text"] = f"{entry['text']} No public address is allowed, so neither is the one the flow uses."
        else:
            changed = entry
        shown.append(changed)
    return shown


def _merge(results: list[dict[str, Any]], sources: list[str]) -> dict[str, Any]:
    """One crossing of a flow with several candidate sources (``sources``,
    one result each): the walk of the first, with each network ACL and
    security group item saying for which sources it passes."""
    base = results[0]
    merged: list[list[Any]] = []
    for position, (node_id, found) in enumerate(base["segments"]):
        items: list[dict] = []
        for index, entry in enumerate(found):
            if entry["stage"] not in (ACL, SECURITY_GROUP) or entry["status"] == INFO:
                items.append(entry)
                continue
            each: list[dict] = []
            for result in results:
                segments = result["segments"]
                other = segments[position][1] if position < len(segments) and segments[position][0] == node_id else []
                each.append(other[index] if index < len(other) else item(entry["stage"], UNKNOWN, entry["where"], ""))
            items.append(_merged_item(entry, each, sources))
        merged.append([node_id, items])
    return {**base, "segments": merged}


def _merged_item(entry: dict, each: list[dict], sources: list[str]) -> dict:
    statuses = [e["status"] for e in each]
    allowed = [s for s, status in zip(sources, statuses, strict=True) if status == OK]
    refused = [(s, e) for s, e in zip(sources, each, strict=True) if e["status"] != OK]
    found = {k: v for k, v in entry.items() if k != "ports"}
    listed = ", ".join(sources)
    if not refused:
        found["text"] = f"Every address the flow may leave with ({listed}) is allowed. {entry['text']}"
        return found
    first, why = refused[0]
    if allowed:
        found["status"] = PARTIAL
        found["text"] = (
            f"Allowed from {', '.join(allowed)} only, not from {', '.join(s for s, _e in refused)}, "
            f"so it depends on which address the flow leaves with. For {first}: {why['text']}"
        )
        return found
    found["status"] = worst(statuses)
    if all(status == BLOCKED for status in statuses):
        found["text"] = f"None of the addresses the flow may leave with ({listed}) is allowed. {why['text']}"
    else:
        found["text"] = " ".join(f"For {s}: {e['text']}" for s, e in zip(sources, each, strict=True))
    return found


def _item(step: dict) -> dict:
    found = item(
        _STAGES.get(str(step.get("stage")), ROUTE),
        str(step.get("status") or OK),
        str(step.get("where") or ""),
        str(step.get("text") or ""),
    )
    if step.get("ports") is not None:
        found["ports"] = step["ports"]
    return found
