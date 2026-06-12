"""
Migration 0055: Composite poll-history index + audit category index.

monitoring_polls history is read per host filtered/ordered by time
(device-detail charts, SLA math, response-time percentiles).  The existing
indexes can't serve that without a sort step: 0046's (host_id, id DESC)
targets the latest-per-host lookup and 0049's (polled_at) targets retention
deletes.  The composite (host_id, polled_at) completes the set.

audit_events gains an index on category for the filtered listing endpoint
(``WHERE category = ? ORDER BY id DESC LIMIT ?``), which otherwise
full-scans an append-only table that never shrinks.
"""

from __future__ import annotations

VERSION = 55
DESCRIPTION = "Add monitoring_polls(host_id, polled_at) and audit_events(category) indexes"


async def up(db) -> None:
    # Identical SQL on SQLite and Postgres.
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_monitoring_polls_host_polled "
        "ON monitoring_polls(host_id, polled_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_events_category "
        "ON audit_events(category)"
    )
    await db.commit()
