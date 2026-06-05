"""
Migration 0048: Track upgrade campaign operation attempts.

Campaign status only stores the latest phase state.  Operators need a durable
history of scheduled/running/completed attempts, especially for scheduled
activate windows that can fail or be missed after a restart.
"""

from __future__ import annotations

import os

VERSION = 48
DESCRIPTION = "Add upgrade_operations history table"
DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def up(db) -> None:
    id_column = "SERIAL PRIMARY KEY" if DB_ENGINE == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    now_default = "NOW()::text" if DB_ENGINE == "postgres" else "datetime('now')"
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS upgrade_operations (
            id              {id_column},
            campaign_id     INTEGER NOT NULL REFERENCES upgrade_campaigns(id) ON DELETE CASCADE,
            phase           TEXT    NOT NULL DEFAULT '',
            status          TEXT    NOT NULL DEFAULT 'pending',
            requested_by    TEXT    NOT NULL DEFAULT '',
            device_count    INTEGER NOT NULL DEFAULT 0,
            succeeded       INTEGER NOT NULL DEFAULT 0,
            failed          INTEGER NOT NULL DEFAULT 0,
            cancelled       INTEGER NOT NULL DEFAULT 0,
            scheduled_at    TEXT,
            started_at      TEXT,
            completed_at    TEXT,
            error_message   TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT ({now_default}),
            updated_at      TEXT    NOT NULL DEFAULT ({now_default})
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_upgrade_operations_campaign_created
        ON upgrade_operations(campaign_id, created_at DESC)
        """
    )
    await db.commit()
