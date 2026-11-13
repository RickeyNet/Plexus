"""The audit log tool. Only a token whose owner is an admin can see it."""

from __future__ import annotations

from typing import Any

import routes.database as db

from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.dispatch import page_args
from netcontrol.mcp.registry import Tool, register
from netcontrol.mcp.tools._common import DB_TIME_FORMAT, PAGING, TIME_RANGE, schema, time_window

_ROWS = 5000


async def search_audit_log(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    since, until = time_window(args)
    events = await db.get_audit_events(
        limit=_ROWS,
        category=str(args.get("category") or "").strip() or None,
        user=str(args.get("user") or "").strip() or None,
        since=since.strftime(DB_TIME_FORMAT) if since else None,
        until=until.strftime(DB_TIME_FORMAT),
    )
    rows = [
        {
            "timestamp": event.get("timestamp"),
            "category": event.get("category"),
            "action": event.get("action"),
            "user": event.get("user"),
            "detail": event.get("detail"),
        }
        for event in events
    ]
    return page_args(rows, args)


register(
    Tool(
        name="search_audit_log",
        description=(
            "Searches the Plexus audit log: who did what and when (logins, configuration changes, jobs, "
            "settings, AI tool calls under category 'mcp'). Filter by category, by exact user name and "
            "by time range (default: the last 24 hours). Newest first."
        ),
        category="audit",
        admin_only=True,
        input_schema=schema(
            {
                "category": {"type": "string", "maxLength": 60},
                "user": {"type": "string", "maxLength": 150},
                **TIME_RANGE,
                **PAGING,
            }
        ),
        handler=search_audit_log,
    )
)
