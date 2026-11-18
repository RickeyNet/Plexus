"""Vendor status of inventory hosts (migration 0114).

The newest vendor-specific state the monitoring poll read from a host, one
row per host: an APC Smart-UPS's battery and output state and its
identity (``netcontrol/integrations/apc/snmp.py``). The numeric history is
in ``metric_samples``; this is the current state.

Split out of routes/database.py's domain modules; star re-exported there so
the ``routes.database`` facade keeps its full public surface.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import routes.database as _dbcore
from routes.database import rows_to_list

__all__ = [
    "set_host_vendor_status",
    "get_host_vendor_status",
    "list_host_vendor_status",
]


def _decode(row: dict) -> dict:
    try:
        status = json.loads(row.get("status") or "{}")
    except TypeError, ValueError:
        status = {}
    return {**row, "status": status if isinstance(status, dict) else {}}


async def set_host_vendor_status(host_id: int, kind: str, status: dict) -> None:
    """Store ``status`` as the newest ``kind`` state of ``host_id``."""
    polled_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """INSERT INTO host_vendor_status (host_id, kind, status, polled_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(host_id) DO UPDATE SET
                   kind = excluded.kind,
                   status = excluded.status,
                   polled_at = excluded.polled_at""",
            (host_id, kind, json.dumps(status, sort_keys=True), polled_at),
        )
        await db.commit()
    finally:
        await db.close()


async def get_host_vendor_status(host_id: int) -> dict | None:
    """The newest vendor state of ``host_id`` (``status`` decoded), or None."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM host_vendor_status WHERE host_id = ?", (host_id,))
        rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    return _decode(rows[0]) if rows else None


async def list_host_vendor_status(kind: str) -> list[dict]:
    """Every host's newest ``kind`` state, with the host's name, address
    and inventory group."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT v.*, h.hostname, h.ip_address, h.group_id, g.name AS group_name
               FROM host_vendor_status v
               JOIN hosts h ON h.id = v.host_id
               LEFT JOIN inventory_groups g ON g.id = h.group_id
               WHERE v.kind = ?
               ORDER BY v.host_id""",
            (kind,),
        )
        rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    return [_decode(row) for row in rows]
