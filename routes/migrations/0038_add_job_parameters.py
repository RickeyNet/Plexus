"""
Migration 0038: Add parameters JSON column to jobs.

Per-job parameters (e.g. NetFlow's collector_ip / sampling_rate) are
collected from the launch UI based on each playbook's parameters_schema
and stored as a JSON blob here. The runner deserializes them and assigns
to ``pb.parameters`` before the playbook's ``run()`` executes.

Existing rows default to NULL, which the runner treats as an empty dict
so older jobs replayed via retry continue to work.
"""

from __future__ import annotations

import os

VERSION = 38
DESCRIPTION = "Add jobs.parameters JSON column for per-job playbook parameters"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db) -> bool:
    cursor = await db.execute("PRAGMA table_info(jobs)")
    rows = await cursor.fetchall()
    return any(row[1] == "parameters" for row in rows)


async def _up_sqlite(db) -> None:
    if await _column_exists_sqlite(db):
        return
    await db.execute(
        "ALTER TABLE jobs ADD COLUMN parameters TEXT DEFAULT NULL"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS parameters TEXT DEFAULT NULL"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
