"""
route_capture.py -- Read a device's route table over SSH and store it for the path trace.

Shared by the monitoring poll (``netcontrol.routes.monitoring``) and the
topology inventory collection (``netcontrol.routes.inventory_collection``):
both read the table with the commands of the host's driver, assemble the
global table and the VRF tables into one text the same way, and write a
``route_snapshots`` row only when the text changed since the host's latest.
"""

from __future__ import annotations

import hashlib
from typing import Any

import routes.database as db

from netcontrol.drivers import IOS_ROUTE_TABLE_COMMANDS, DriverCapabilityError, RouteTableCommands, get_driver
from netcontrol.integrations.pathtrace.inventory import CAPTURE_LIMIT
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.routes")

# Lines of a route table that are headers, not routes.
_HEADER_PREFIXES = ("Codes:", "Gateway", "---")


def _route_table_commands(device_type: str) -> RouteTableCommands:
    """The route table commands of a device type: its driver's, or the IOS
    ones for a type without a driver (what every device was sent before)."""
    try:
        return get_driver(device_type).route_table_commands()
    except DriverCapabilityError:
        return IOS_ROUTE_TABLE_COMMANDS


def _is_route_table(text: str) -> bool:
    """Whether a route table command printed a table rather than the error a
    platform that lacks the command gives."""
    head = str(text or "").strip()
    if not head:
        return False
    first = head.splitlines()[0].strip().lower()
    return not (
        first.startswith(("%", "^", "error", "syntax error", "unknown command", "command fail"))
        or "invalid input" in first
        or "incomplete command" in first
    )


def _parse_route_summary_count(summary_text: str) -> int | None:
    """Best-effort total route count from `show ip route summary` output.

    Handles IOS/IOS-XE ("Total  <networks> <subnets> ...") and NX-OS
    ("Total number of routes: N"). Returns None when the format is
    unrecognized so the caller falls back to pulling the full table.
    """
    for line in (summary_text or "").splitlines():
        parts = line.split()
        if not parts or parts[0].lower() != "total":
            continue
        if "route" in line.lower():
            try:
                return int(parts[-1])
            except ValueError:
                continue
        if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
            return int(parts[1]) + int(parts[2])
    return None


def read_full_route_tables(conn: Any, commands: RouteTableCommands, read_timeout: float) -> tuple[str, str]:
    """Blocking: the full global table and, best effort, every VRF's table
    (``""`` when the platform has no all-VRFs command or the device rejects it)."""
    table = str(conn.send_command(commands.table, read_timeout=read_timeout) or "")
    vrfs = ""
    if commands.all_vrfs:
        try:
            vrfs = str(conn.send_command(commands.all_vrfs, read_timeout=read_timeout) or "")
        except Exception as exc:  # noqa: BLE001 - a device that rejects it keeps the global table
            LOGGER.debug("route capture: VRF route table not read: %s", type(exc).__name__)
    return table, vrfs


def assemble_route_text(table: str, vrfs: str, summary_count: int | None) -> tuple[str, int]:
    """The stored route text and its route count.

    The text is the global table, then a blank line and the VRF tables when
    the all-VRFs command printed a table. The count prefers the summary total
    (so the monitoring metric stays in one domain across lean and full ticks)
    and otherwise counts the global table's non-header lines; the VRF tables
    never add to it. An empty table gives ``""`` and the summary count (or 0).
    """
    text = str(table or "").strip()
    if not text:
        return "", summary_count if summary_count is not None else 0
    lines = [line for line in text.splitlines() if line.strip() and not line.strip().startswith(_HEADER_PREFIXES)]
    count = summary_count if summary_count is not None else len(lines)
    if _is_route_table(vrfs):
        text += "\n\n" + str(vrfs).strip()
    return text, count


def read_route_table(conn: Any, commands: RouteTableCommands, read_timeout: float) -> tuple[str, int]:
    """Blocking: read the whole route table on an open session, as the
    monitoring poll's full tick does: the summary (best effort, for the
    count), the global table and the VRF tables. Returns ``(text, count)``."""
    summary_count = None
    if commands.summary:
        try:
            summary = conn.send_command(commands.summary, read_timeout=read_timeout)
            summary_count = _parse_route_summary_count(str(summary or ""))
        except Exception as exc:  # noqa: BLE001 - the count falls back to the table's lines
            LOGGER.debug("route capture: route summary not read: %s", type(exc).__name__)
    table, vrfs = read_full_route_tables(conn, commands, read_timeout)
    return assemble_route_text(table, vrfs, summary_count)


def route_text_hash(routes_text: str) -> str:
    return hashlib.sha256(routes_text.encode()).hexdigest()[:16]


async def store_route_snapshot(host_id: int, routes_text: str, route_count: int) -> tuple[bool, dict | None]:
    """Write a ``route_snapshots`` row unless the text equals the host's latest.

    The hash is of the whole text; the stored text is capped at the path
    trace's ``CAPTURE_LIMIT``. Returns ``(written, previous)``: whether a row
    was written, and the host's previous latest snapshot (``None`` for its
    first), which the monitoring poll compares for its route churn alert.
    """
    route_hash = route_text_hash(routes_text)
    previous = await db.get_latest_route_snapshot(host_id)
    if previous is not None and previous["routes_hash"] == route_hash:
        return False, previous
    await db.create_route_snapshot(
        host_id=host_id,
        route_count=route_count,
        routes_text=routes_text[:CAPTURE_LIMIT],
        routes_hash=route_hash,
    )
    return True, previous
