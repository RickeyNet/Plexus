"""
Migration 0043: Audit run scheduler.

Adds `audit_schedules` (cron-style schedules driving the audit engine) and
backfills `audit_runs` with a `schedule_id` foreign key so scheduled runs
can be traced back to the row that produced them. The schedule string
itself reuses reporting's interval grammar (`@hourly`, `daily`, `5m`, ...).
"""

from __future__ import annotations

import os

VERSION = 43
DESCRIPTION = "Add audit_schedules table and audit_runs.schedule_id column"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _sqlite_columns(db, table: str) -> list[str]:
    cursor = await db.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in await cursor.fetchall()]


# ── SQLite ──────────────────────────────────────────────────────────────────

async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_schedules (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    NOT NULL,
            schedule     TEXT    NOT NULL DEFAULT '',
            enabled      INTEGER NOT NULL DEFAULT 1,
            last_run_at  TEXT,
            created_by   TEXT    NOT NULL DEFAULT '',
            created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at   TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_schedules_enabled "
        "ON audit_schedules(enabled, last_run_at)"
    )

    cols = await _sqlite_columns(db, "audit_runs")
    if "schedule_id" not in cols:
        await db.execute(
            "ALTER TABLE audit_runs ADD COLUMN schedule_id INTEGER "
            "REFERENCES audit_schedules(id) ON DELETE SET NULL"
        )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_runs_schedule "
        "ON audit_runs(schedule_id, started_at DESC)"
    )
    await db.commit()


# ── Postgres ────────────────────────────────────────────────────────────────

async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_schedules (
            id           BIGSERIAL PRIMARY KEY,
            name         TEXT NOT NULL,
            schedule     TEXT NOT NULL DEFAULT '',
            enabled      INTEGER NOT NULL DEFAULT 1,
            last_run_at  TIMESTAMPTZ,
            created_by   TEXT NOT NULL DEFAULT '',
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_schedules_enabled "
        "ON audit_schedules(enabled, last_run_at)"
    )

    await db.execute(
        "ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS schedule_id INTEGER "
        "REFERENCES audit_schedules(id) ON DELETE SET NULL"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_runs_schedule "
        "ON audit_runs(schedule_id, started_at DESC)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
