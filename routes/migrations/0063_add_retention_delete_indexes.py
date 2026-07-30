"""
Migration 0063: Indexes for retention-cleanup DELETE scans.

The periodic retention pass deletes by age, but the existing indexes on
these tables lead with metric_name / host_id, so every cleanup full-scanned
the (ever-growing) table while holding the writer lock:

- metric_samples:          WHERE sampled_at < ...   (idx leads metric_name)
- metric_rollups:          WHERE time_window = ? AND period_start < ...
                           (idx leads metric_name)
- interface_ts:            WHERE sampled_at < ...   (idx leads host_id)
- interface_error_events:  WHERE created_at < ...   (no time index)
"""

from __future__ import annotations

VERSION = 63
DESCRIPTION = "Add age-based indexes for retention deletes"


async def up(db) -> None:
    # Identical SQL on SQLite and Postgres.
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_metric_samples_sampled_at ON metric_samples(sampled_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_metric_rollups_window_start ON metric_rollups(time_window, period_start)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_interface_ts_sampled_at ON interface_ts(sampled_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_interface_error_events_created ON interface_error_events(created_at)"
    )
    await db.commit()
