"""
Migration 0062: Composite index for per-device flow queries on flow_records.

Top-talkers / top-applications / top-conversations / timeline queries filter
``host_id = ?`` plus a ``received_at`` window (routes/db/flows.py), but the
existing indexes lead with received_at, exporter_ip, src_ip, dst_ip, or
flow_type — so per-device views scanned the whole time window and filtered
host_id row by row on the largest table in the app.
"""

from __future__ import annotations

VERSION = 62
DESCRIPTION = "Add flow_records(host_id, received_at) index"


async def up(db) -> None:
    # Identical SQL on SQLite and Postgres.
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_flow_host_received ON flow_records(host_id, received_at)"
    )
    await db.commit()
