"""Argument schemas and time handling shared by the tool modules."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from netcontrol.mcp.registry import ToolError

DB_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

PAGING: dict[str, Any] = {
    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Rows to return (the server caps it)."},
    "cursor": {"type": "string", "maxLength": 20, "description": "next_cursor from the previous page."},
}
TIME_RANGE: dict[str, Any] = {
    "since": {
        "type": "string",
        "maxLength": 40,
        "description": "Start of the time range, ISO 8601 (2026-01-31T14:00:00Z). Times without a zone are UTC.",
    },
    "until": {"type": "string", "maxLength": 40, "description": "End of the time range, ISO 8601. Default: now."},
}


def schema(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    """A closed JSON Schema for a tool's arguments."""
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


def parse_time(value: Any, name: str) -> datetime | None:
    """An ISO 8601 argument as an aware UTC datetime; ``None`` when absent."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        raise ToolError(f"Invalid {name}: use ISO 8601, for example 2026-01-31T14:00:00Z.") from None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def time_window(args: dict[str, Any], default_hours: int | None = 24) -> tuple[datetime | None, datetime]:
    """``(since, until)`` from a tool's arguments. ``until`` defaults to now;
    ``since`` to ``default_hours`` before it, or to no lower bound when
    ``default_hours`` is ``None``."""
    until = parse_time(args.get("until"), "until") or datetime.now(UTC)
    since = parse_time(args.get("since"), "since")
    if since is None and default_hours is not None:
        since = until - timedelta(hours=default_hours)
    if since is not None and since > until:
        raise ToolError("since must be earlier than until.")
    return since, until


def db_time(value: Any) -> datetime | None:
    """A timestamp as Plexus stores it (UTC text, with or without a ``T``,
    fraction or zone) as an aware UTC datetime; ``None`` when unreadable."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def in_window(value: Any, since: datetime | None, until: datetime) -> bool:
    """Whether a stored timestamp falls in the window. A row with no
    readable timestamp is kept only when there is no lower bound."""
    stamp = db_time(value)
    if stamp is None:
        return since is None
    return (since is None or stamp >= since) and stamp <= until


def host_ref(host: dict[str, Any]) -> dict[str, Any]:
    """The short form of a host inside another row."""
    return {"id": host.get("id"), "hostname": host.get("hostname"), "ip_address": host.get("ip_address")}
