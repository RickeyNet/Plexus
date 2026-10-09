"""
Migration 0043: Audit run scheduler.

Adds `audit_schedules` (cron-style schedules driving the audit engine) and
backfills `audit_runs` with a `schedule_id` foreign key so scheduled runs
can be traced back to the row that produced them. The schedule string
itself reuses reporting's interval grammar (`@hourly`, `daily`, `5m`, ...).
"""

from __future__ import annotations

VERSION = 43
DESCRIPTION = "Add audit_schedules table and audit_runs.schedule_id column"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_schedules (
            id           BIGSERIAL PRIMARY KEY,
            name         TEXT NOT NULL,
            schedule     TEXT NOT NULL DEFAULT '',
            enabled      INTEGER NOT NULL DEFAULT 1,
            last_run_at  TEXT,
            created_by   TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL DEFAULT (NOW()::text),
            updated_at   TEXT NOT NULL DEFAULT (NOW()::text)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_audit_schedules_enabled ON audit_schedules(enabled, last_run_at)")

    await db.execute(
        "ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS schedule_id INTEGER "
        "REFERENCES audit_schedules(id) ON DELETE SET NULL"
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_audit_runs_schedule ON audit_runs(schedule_id, started_at DESC)")
    await db.commit()
