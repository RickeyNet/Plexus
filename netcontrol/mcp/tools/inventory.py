"""Inventory tools: groups, host search, one host."""

from __future__ import annotations

from typing import Any

import routes.database as db

from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.dispatch import page_args
from netcontrol.mcp.registry import Tool, register
from netcontrol.mcp.tools._common import PAGING, schema
from netcontrol.mcp.tools._hosts import HOST_ARG, alias_index, group_paths, host_row, resolve_host

_SEARCHED = ("hostname", "ip_address", "model", "serial_number", "software_version", "device_type")


async def list_groups(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    groups = await db.get_all_groups()
    names = {int(g["id"]): str(g["name"]) for g in groups}
    rows = [
        {
            "id": g["id"],
            "name": g["name"],
            "path": g.get("path") or g["name"],
            "parent": names.get(int(g["parent_id"])) if g.get("parent_id") else None,
            "description": g.get("description") or "",
            "host_count": int(g.get("host_count") or 0),
        }
        for g in groups
    ]
    return page_args(rows, args)


async def search_hosts(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or "").strip().lower()
    vendor = str(args.get("vendor") or "").strip().lower()
    group = str(args.get("group") or "").strip().lower()
    paths = await group_paths()
    aliases = await alias_index() if query else {}
    rows = []
    for host in await db.get_all_hosts():
        row = host_row(host, paths)
        if vendor and vendor not in str(row["device_type"] or "").lower():
            continue
        if group and group not in row["group"].lower():
            continue
        if query:
            haystack = [str(row[field] or "").lower() for field in _SEARCHED] + aliases.get(int(host["id"]), [])
            if not any(query in value for value in haystack):
                continue
        rows.append(row)
    return page_args(rows, args)


async def get_host(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    host = await resolve_host(args["host"])
    row = host_row(host, await group_paths())
    row["alias_addresses"] = sorted(str(a["ip_address"]) for a in await db.get_ip_aliases_for_hosts([int(host["id"])]))
    return row


register(
    Tool(
        name="list_groups",
        description=(
            "Lists the inventory groups (sites, roles or regions the admin defined) with their parent "
            "group and the number of devices directly in each. Use it to learn how the network is organised."
        ),
        category="inventory",
        input_schema=schema(PAGING),
        handler=list_groups,
    )
)
register(
    Tool(
        name="search_hosts",
        description=(
            "Finds inventory devices. 'query' matches part of the host name, an IP address (primary or "
            "secondary), model, serial number, software version or device type. 'vendor' matches part "
            "of the device type (cisco, juniper, arista, paloalto, fortinet). 'group' matches part of the "
            "group path. With no arguments it lists every device. Returns id, hostname, ip_address, "
            "device_type, model, software_version, status and group."
        ),
        category="inventory",
        input_schema=schema(
            {
                "query": {"type": "string", "maxLength": 255},
                "vendor": {"type": "string", "maxLength": 60},
                "group": {"type": "string", "maxLength": 255},
                **PAGING,
            }
        ),
        handler=search_hosts,
    )
)
register(
    Tool(
        name="get_host",
        description=(
            "Returns one inventory device: identity, platform, software version, status, group and the "
            "secondary interface addresses it owns. If the reference matches several devices the error "
            "lists them with their ids."
        ),
        category="inventory",
        input_schema=schema({"host": HOST_ARG}, required=("host",)),
        handler=get_host,
    )
)
