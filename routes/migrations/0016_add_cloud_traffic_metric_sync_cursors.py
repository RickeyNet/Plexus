"""
Migration 0016: Add cloud_traffic_metric_sync_cursors table.

Tracks per-account watermarks for scheduled cloud traffic-metric pulling.
"""

from __future__ import annotations

import os

VERSION = 16
DESCRIPTION = "Add cloud traffic metric sync cursor tracking table"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_traffic_metric_sync_cursors (
            account_id      INTEGER PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            last_pull_end   TEXT    NOT NULL DEFAULT '',
            extra_json      TEXT    NOT NULL DEFAULT '{}',
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
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


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
