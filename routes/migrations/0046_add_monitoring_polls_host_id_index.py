"""
Migration 0046: Index monitoring_polls for latest-per-host lookups.

Dashboard and monitoring list endpoints resolve the newest poll per device
via host_id + id; this index speeds that pattern on Postgres and SQLite.
"""

from __future__ import annotations

import os

VERSION = 46
DESCRIPTION = "Add monitoring_polls(host_id, id) index for latest-per-host queries"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def up(db) -> None:
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_monitoring_polls_host_id
        ON monitoring_polls(host_id, id DESC)
        """
    )
    await db.commit()
