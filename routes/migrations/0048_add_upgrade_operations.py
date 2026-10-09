"""
Migration 0048: Track upgrade campaign operation attempts.

Campaign status only stores the latest phase state.  Operators need a durable
history of scheduled/running/completed attempts, especially for scheduled
activate windows that can fail or be missed after a restart.
"""

from __future__ import annotations

VERSION = 48
DESCRIPTION = "Add upgrade_operations history table"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS upgrade_operations (
            id              SERIAL PRIMARY KEY,
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
            created_at      TEXT    NOT NULL DEFAULT (NOW()::text),
            updated_at      TEXT    NOT NULL DEFAULT (NOW()::text)
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
