"""
Migration 0016: Add cloud_traffic_metric_sync_cursors table.

Tracks per-account watermarks for scheduled cloud traffic-metric pulling.
"""

from __future__ import annotations

VERSION = 16
DESCRIPTION = "Add cloud traffic metric sync cursor tracking table"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_traffic_metric_sync_cursors (
            account_id      INTEGER PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            last_pull_end   TEXT    NOT NULL DEFAULT '',
            extra_json      TEXT    NOT NULL DEFAULT '{}',
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
