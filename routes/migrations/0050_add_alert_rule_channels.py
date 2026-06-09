"""
Migration 0050: Add notification channel assignment to alert_rules.

`channel_ids` is a TEXT column holding a JSON list (or comma-separated list) of
notification-channel ids that a rule's alerts should be delivered to (email /
PagerDuty / webhook / Teams). Empty means "use the global default channel set"
(see auth_settings `notification_channels.default_channel_ids`), which is also
what built-in threshold / baseline / route-churn alerts fall back to since they
aren't tied to a user rule.
"""

from __future__ import annotations

import os

VERSION = 50
DESCRIPTION = "Add channel_ids to alert_rules for notification routing"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db) -> bool:
    cursor = await db.execute("PRAGMA table_info(alert_rules)")
    rows = await cursor.fetchall()
    return any(row[1] == "channel_ids" for row in rows)


async def _up_sqlite(db) -> None:
    if not await _column_exists_sqlite(db):
        await db.execute(
            "ALTER TABLE alert_rules ADD COLUMN channel_ids TEXT NOT NULL DEFAULT ''"
        )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        "ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS channel_ids TEXT NOT NULL DEFAULT ''"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
