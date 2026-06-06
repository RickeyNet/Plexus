"""
Migration 0049: Index monitoring_polls(polled_at) for retention deletes.

Retention cleanup deletes aged rows with
``WHERE polled_at < datetime('now', '-N days')``. Without an index on
polled_at that is a full-table scan every run; this index turns it into a
range scan on both SQLite and Postgres.
"""

from __future__ import annotations

import os

VERSION = 49
DESCRIPTION = "Add monitoring_polls(polled_at) index for retention deletes"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def up(db) -> None:
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_monitoring_polls_polled_at
        ON monitoring_polls(polled_at)
        """
    )
    await db.commit()
