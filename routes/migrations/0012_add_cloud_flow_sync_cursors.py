"""
Migration 0012: Add cloud_flow_sync_cursors table.

Tracks per-account watermarks for scheduled cloud flow-log pulling.
"""

from __future__ import annotations

VERSION = 12
DESCRIPTION = "Add cloud flow sync cursor tracking table"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_flow_sync_cursors (
            account_id      INTEGER PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            last_pull_end   TEXT    NOT NULL DEFAULT '',
            extra_json      TEXT    NOT NULL DEFAULT '{}',
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
