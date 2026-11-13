"""Topology tools: neighbors, interfaces, changes and the path trace.

``trace_path`` runs the same engine as the Topology page against the data
Plexus already holds (snapshots, route captures, configuration backups). It
does not collect anything and does not send a packet.
"""

from __future__ import annotations

import asyncio
from typing import Any

import routes.database as db

from netcontrol.integrations.pathtrace.model import net
from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.dispatch import no_data, page_args
from netcontrol.mcp.registry import Tool, ToolError, register
from netcontrol.mcp.tools._common import PAGING, TIME_RANGE, host_ref, in_window, schema, time_window
from netcontrol.mcp.tools._hosts import HOST_ARG, resolve_host

_ROWS = 5000
PROTOCOLS = ("tcp", "udp", "icmp")
ENDPOINT_ARG = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "description": "An IP address, a network in CIDR form, or an inventory device (its primary address is used).",
}


async def get_neighbors(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    host = await resolve_host(args["host"])
    host_id = int(host["id"])
    links = await db.get_topology_links_for_host(host_id)
    if not links:
        return no_data(f"neighbor discovery of {host['hostname']}")
    rows = []
    for link in links:
        outgoing = int(link["source_host_id"]) == host_id
        rows.append(
            {
                "local_interface": link.get("source_interface") if outgoing else link.get("target_interface"),
                "remote_device": link.get("target_device_name") if outgoing else link.get("source_hostname"),
                "remote_interface": link.get("target_interface") if outgoing else link.get("source_interface"),
                "remote_address": link.get("target_ip") if outgoing else link.get("source_ip"),
                "remote_host_id": link.get("target_host_id") if outgoing else link.get("source_host_id"),
                "remote_platform": link.get("target_platform") if outgoing else link.get("source_device_type"),
                "protocol": link.get("protocol"),
                "discovered_at": link.get("discovered_at"),
            }
        )
    return {"host": host_ref(host), "neighbors": rows}


async def get_interfaces(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    host = await resolve_host(args["host"])
    host_id = int(host["id"])
    wanted = str(args.get("name") or "").strip().lower()
    interfaces = await db.get_interface_inventory_for_host(host_id)
    vlans = await db.get_vlan_definitions_for_host(host_id)
    stp = await db.get_stp_port_states(host_id=host_id)
    if not interfaces and not vlans and not stp:
        return no_data(f"interface inventory of {host['hostname']}")
    drop = ("id", "host_id")
    return {
        "host": host_ref(host),
        "interfaces": [
            {k: v for k, v in row.items() if k not in drop}
            for row in interfaces
            if not wanted or wanted in str(row.get("name") or "").lower()
        ],
        "vlans": [{k: v for k, v in row.items() if k not in drop} for row in vlans],
        "spanning_tree": [
            {k: v for k, v in row.items() if k not in drop}
            for row in stp
            if not wanted or wanted in str(row.get("interface_name") or "").lower()
        ],
    }


async def list_topology_changes(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    since, until = time_window(args)
    rows: list[dict[str, Any]] = []
    for change in await db.get_topology_changes(limit=_ROWS):
        if in_window(change.get("detected_at"), since, until):
            rows.append({"kind": "link", "at": change.get("detected_at"), **change})
    for event in await db.get_stp_topology_events(unacknowledged_only=False, limit=_ROWS):
        if in_window(event.get("created_at"), since, until):
            rows.append({"kind": "spanning_tree", "at": event.get("created_at"), **event})
    rows.sort(key=lambda row: str(row.get("at") or ""), reverse=True)
    return page_args(rows, args)


async def _endpoint(value: str, name: str) -> tuple[str, Any]:
    """``(address, graph node id)`` for a trace end: the address as given,
    or an inventory device's primary address and its node."""
    text = str(value).strip()
    if net(text) is not None:
        return text, None
    try:
        host = await resolve_host(text)
    except ToolError as exc:
        raise ToolError(f"{name}: {exc}") from None
    return str(host["ip_address"]), int(host["id"])


async def trace_path(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    # Imported here: the route module imports half the application, and
    # this is the one place the tracer is assembled from stored data.
    from netcontrol.routes.meraki_topology import _path_tracer

    source, source_node = await _endpoint(args["source"], "source")
    destination, destination_node = await _endpoint(args["destination"], "destination")
    make_tracer = await _path_tracer()
    try:
        # Indexing and walking a large map is CPU-bound.
        tracer = await asyncio.to_thread(make_tracer)
        return await asyncio.to_thread(
            tracer.trace,
            source,
            destination,
            source_node=source_node,
            destination_node=destination_node,
            protocol=str(args.get("protocol") or ""),
            port=args.get("port"),
        )
    except ValueError as exc:
        raise ToolError(f"The path cannot be traced: {exc}") from None


register(
    Tool(
        name="get_neighbors",
        description=(
            "Lists what a device is connected to, from CDP and LLDP neighbor discovery: for each link "
            "the local interface, the neighbor's name, address, interface and platform."
        ),
        category="topology",
        input_schema=schema({"host": HOST_ARG}, required=("host",)),
        handler=get_neighbors,
    )
)
register(
    Tool(
        name="get_interfaces",
        description=(
            "Returns a device's interfaces (name, description, admin and operational state, speed, "
            "duplex, access VLAN, trunk VLANs, last change), its VLANs, and its spanning-tree port roles "
            "and states. 'name' keeps interfaces whose name contains that text."
        ),
        category="topology",
        input_schema=schema({"host": HOST_ARG, "name": {"type": "string", "maxLength": 100}}, required=("host",)),
        handler=get_interfaces,
    )
)
register(
    Tool(
        name="list_topology_changes",
        description=(
            "Lists links that appeared or disappeared and spanning-tree events (root changes, topology "
            "changes) in the time range, newest first. Default range: the last 24 hours. Use it to see "
            "what changed in the network around the time a problem started."
        ),
        category="topology",
        input_schema=schema({**TIME_RANGE, **PAGING}),
        handler=list_topology_changes,
    )
)
register(
    Tool(
        name="trace_path",
        description=(
            "Traces how traffic from a source to a destination would be forwarded, hop by hop, using "
            "the routes, NAT rules, firewall rules and links Plexus has stored, and whether the replies "
            "take the same way back. Answers 'why can't A reach B': the result names the device and "
            "rule that drops the flow, or the point where the path is not known. Nothing is sent on the "
            "network; the answer is as current as the stored data. protocol is tcp, udp or icmp; port "
            "is the destination port."
        ),
        category="topology",
        input_schema=schema(
            {
                "source": ENDPOINT_ARG,
                "destination": ENDPOINT_ARG,
                "protocol": {"type": "string", "enum": list(PROTOCOLS)},
                "port": {"type": "integer", "minimum": 0, "maximum": 65535},
            },
            required=("source", "destination"),
        ),
        handler=trace_path,
    )
)
