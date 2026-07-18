"""
Migration 0060: Composite index for cloud flow queries on flow_records.

Cloud flow analytics filter with ``flow_type LIKE 'cloud_%'`` (or
``flow_type = 'cloud_<provider>'``) plus a ``received_at`` window.  The
existing indexes cover only (received_at) and (exporter_ip, received_at), so
provider-wide summaries scanned every recent flow row — NetFlow included —
applying the LIKE per row.
"""

from __future__ import annotations

VERSION = 60
DESCRIPTION = "Add flow_records(flow_type, received_at) index"


async def up(db) -> None:
    # Identical SQL on SQLite and Postgres.
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_flow_records_flow_type_received "
        "ON flow_records(flow_type, received_at)"
    )
    await db.commit()
