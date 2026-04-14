"""
Migration 0005: Add config drift event history table.

Tracks lifecycle actions for each drift event (detected, status transitions,
revert attempts/outcomes) so operators can review accepted/resolved history.
"""

from __future__ import annotations

import os

VERSION = 5
DESCRIPTION = "Add config drift event history table"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS config_drift_event_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id         INTEGER NOT NULL REFERENCES config_drift_events(id) ON DELETE CASCADE,
            host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            action           TEXT    NOT NULL DEFAULT '',
            from_status      TEXT    NOT NULL DEFAULT '',
            to_status        TEXT    NOT NULL DEFAULT '',
            actor            TEXT    NOT NULL DEFAULT '',
            details          TEXT    NOT NULL DEFAULT '',
            created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_drift_event_history_event_created
        ON config_drift_event_history(event_id, created_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_drift_event_history_host_created
        ON config_drift_event_history(host_id, created_at DESC)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS config_drift_event_history (
            id              BIGSERIAL PRIMARY KEY,
            event_id         INTEGER NOT NULL REFERENCES config_drift_events(id) ON DELETE CASCADE,
            host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            action           TEXT    NOT NULL DEFAULT '',
            from_status      TEXT    NOT NULL DEFAULT '',
            to_status        TEXT    NOT NULL DEFAULT '',
            actor            TEXT    NOT NULL DEFAULT '',
            details          TEXT    NOT NULL DEFAULT '',
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_drift_event_history_event_created
        ON config_drift_event_history(event_id, created_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_drift_event_history_host_created
        ON config_drift_event_history(host_id, created_at DESC)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
