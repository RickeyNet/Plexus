"""Traffic tools: where a MAC or IP address was seen, and flow rankings."""

from __future__ import annotations

from typing import Any

import routes.database as db

from netcontrol.integrations.meraki.clients import normalize_mac
from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.dispatch import max_rows, no_data
from netcontrol.mcp.registry import Tool, ToolError, register
from netcontrol.mcp.tools._common import host_ref, schema
from netcontrol.mcp.tools._hosts import HOST_ARG, resolve_host

_MAX_FLOW_ROWS = 50
_HISTORY_ROWS = 200


def _host_of(row: dict[str, Any]) -> dict[str, Any]:
    return {"id": row.get("host_id"), "hostname": row.get("hostname"), "ip_address": row.get("host_ip")}


async def search_mac_or_ip(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    query = str(args["query"]).strip()
    limit = max_rows()
    rows = [
        {
            "mac_address": entry.get("mac_address"),
            "ip_address": entry.get("ip_address") or None,
            "host": _host_of(entry),
            "port": entry.get("port_name"),
            "vlan": entry.get("vlan"),
            "type": entry.get("entry_type"),
            "first_seen": entry.get("first_seen"),
            "last_seen": entry.get("last_seen"),
            "source": "inventory",
        }
        for entry in await db.search_mac_tracking(query, limit=limit)
    ]
    rows += [
        {
            "mac_address": client.get("mac_address"),
            "ip_address": client.get("ip_address") or None,
            "device": client.get("device_name") or client.get("device_serial"),
            "network": client.get("network_name"),
            "organization": client.get("org_name"),
            "port": client.get("port_name") or None,
            "ssid": client.get("ssid") or None,
            "vlan": client.get("vlan"),
            "client_name": client.get("description") or None,
            "manufacturer": client.get("manufacturer") or None,
            "status": client.get("status") or None,
            "first_seen": client.get("first_seen"),
            "last_seen": client.get("last_seen"),
            "source": "meraki",
        }
        for client in await db.search_meraki_clients(query, limit=limit)
    ]
    if not rows and not await db.search_mac_tracking("", limit=1) and not await db.search_meraki_clients("", limit=1):
        return no_data("MAC and ARP tables")
    result: dict[str, Any] = {"items": rows[:limit], "total": len(rows)}
    if args.get("history"):
        mac = normalize_mac(query)
        if not mac:
            raise ToolError("history needs a full MAC address as the query, for example aa:bb:cc:dd:ee:ff.")
        result["history"] = [
            {
                "seen_at": seen.get("seen_at"),
                "host": _host_of(seen),
                "port": seen.get("port_name"),
                "vlan": seen.get("vlan"),
                "ip_address": seen.get("ip_address") or None,
            }
            for seen in await db.get_mac_history(mac, limit=_HISTORY_ROWS)
        ]
    return result


async def get_top_talkers(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    kind = str(args["kind"])
    hours = int(args.get("hours", 24))
    limit = int(args.get("limit", 20))
    host = await resolve_host(args["exporter"]) if args.get("exporter") else None
    host_id = int(host["id"]) if host else None
    if kind == "applications":
        rows = await db.get_flow_top_applications(host_id=host_id, hours=hours, limit=limit)
    elif kind == "conversations":
        rows = await db.get_flow_top_conversations(host_id=host_id, hours=hours, limit=limit)
    else:
        direction = "dst" if str(args.get("direction") or "source") == "destination" else "src"
        rows = await db.get_flow_top_talkers(host_id=host_id, hours=hours, direction=direction, limit=limit)
    if not rows and not await db.list_flow_exporters():
        return no_data("flow records (NetFlow, sFlow, IPFIX)")
    return {"kind": kind, "hours": hours, "exporter": host_ref(host) if host else None, "items": rows}


register(
    Tool(
        name="search_mac_or_ip",
        description=(
            "Finds where a MAC address or IP address was seen: the switch and port (or Meraki device, "
            "network and SSID), VLAN, and first and last time seen. The query is a MAC in any common "
            "format, part of one (six or more hex digits), or an IP address. With history true and a "
            "full MAC, also returns the places it was recorded before, newest first."
        ),
        category="traffic",
        features=("mac-tracking",),
        input_schema=schema(
            {"query": {"type": "string", "minLength": 2, "maxLength": 64}, "history": {"type": "boolean"}},
            required=("query",),
        ),
        handler=search_mac_or_ip,
    )
)
register(
    Tool(
        name="get_top_talkers",
        description=(
            "Ranks traffic from stored flow records (NetFlow, sFlow, IPFIX) by bytes over the last "
            "'hours' (default 24): kind 'talkers' ranks addresses (direction source or destination), "
            "'applications' ranks destination port and protocol, 'conversations' ranks source and "
            "destination pairs. 'exporter' limits it to flows exported by one device."
        ),
        category="traffic",
        features=("traffic-analysis",),
        input_schema=schema(
            {
                "kind": {"type": "string", "enum": ["talkers", "applications", "conversations"]},
                "exporter": HOST_ARG,
                "direction": {"type": "string", "enum": ["source", "destination"]},
                "hours": {"type": "integer", "minimum": 1, "maximum": 168},
                "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_FLOW_ROWS},
            },
            required=("kind",),
        ),
        handler=get_top_talkers,
    )
)
