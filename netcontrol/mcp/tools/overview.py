"""``plexus_overview``: what this token can read and how fresh the data is."""

from __future__ import annotations

from collections import Counter
from typing import Any

import routes.database as db

from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.registry import Tool, register, usable_categories

# The categories whose data comes from the listed sources.
_SOURCE_CATEGORIES = frozenset({"inventory", "monitoring", "topology"})


async def _sources() -> list[dict[str, Any]]:
    # The same list the Dashboard's source-health panel reads. Imported
    # here: the route module imports half the application.
    from netcontrol.routes.meraki_topology import list_topology_sources_api

    listed = (await list_topology_sources_api())["sources"]
    return [
        {
            "name": source.get("name"),
            "type": source.get("type"),
            "status": source.get("status"),
            "last_collected": source.get("last_collected_at"),
            "detail": source.get("detail") or source.get("message") or "",
        }
        for source in listed
    ]


async def plexus_overview(ctx: McpContext, _args: dict[str, Any]) -> dict[str, Any]:
    """Only what the token's usable categories cover: device counts need
    ``inventory``; the data sources need one of ``_SOURCE_CATEGORIES``."""
    categories = usable_categories(ctx)
    result: dict[str, Any] = {"categories": categories}
    if "inventory" in categories:
        hosts = await db.get_all_hosts()
        by_type = Counter(str(host.get("device_type") or "unknown") for host in hosts)
        result["devices"] = {"total": len(hosts), "by_device_type": dict(sorted(by_type.items()))}
    if _SOURCE_CATEGORIES.intersection(categories):
        result["sources"] = await _sources()
    return result


register(
    Tool(
        name="plexus_overview",
        description=(
            "Start here. Returns the data categories this token can use and, where those categories "
            "allow it, the number of inventory devices by device type and every data source Plexus "
            "collects from with its status and last collection time. Use it to judge how current an "
            "answer can be."
        ),
        category=None,
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=plexus_overview,
    )
)
