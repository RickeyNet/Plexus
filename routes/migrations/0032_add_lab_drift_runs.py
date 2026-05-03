"""
Migration 0032: Phase B-3a — drift-from-twin checks.

Adds:
  - lab_drift_runs — append-only history of "twin vs production host"
    comparisons. Each row stores the diff between a lab device's snapshot
    and the most recent config snapshot of its source production host, plus
    a status (in_sync | drifted | missing_source | error) and the actor
    that triggered the run (system-scheduler | <username>).

The unique business value of the digital twin is that operators validate
changes against a known-good baseline — but that only stays meaningful
while the production device's running config matches the baseline. When
prod drifts away (cowboy SSH, emergency change, vendor support tweak),
the twin is silently invalidated. This table backs an alerting surface
for that condition.
"""

from __future__ import annotations

import os

VERSION = 32
DESCRIPTION = "Add lab_drift_runs for twin-vs-production drift detection"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_drift_runs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            lab_device_id   INTEGER NOT NULL,
            source_host_id  INTEGER,
            status          TEXT    NOT NULL DEFAULT 'in_sync',
            diff_text       TEXT    NOT NULL DEFAULT '',
            diff_added      INTEGER NOT NULL DEFAULT 0,
            diff_removed    INTEGER NOT NULL DEFAULT 0,
            twin_bytes      INTEGER NOT NULL DEFAULT 0,
            prod_bytes      INTEGER NOT NULL DEFAULT 0,
            actor           TEXT    NOT NULL DEFAULT '',
            error           TEXT    NOT NULL DEFAULT '',
            checked_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (lab_device_id) REFERENCES lab_devices(id) ON DELETE CASCADE,
            FOREIGN KEY (source_host_id) REFERENCES hosts(id) ON DELETE SET NULL
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_drift_runs_device "
        "ON lab_drift_runs (lab_device_id, checked_at)"
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_drift_runs (
            id              SERIAL PRIMARY KEY,
            lab_device_id   INTEGER NOT NULL REFERENCES lab_devices(id) ON DELETE CASCADE,
            source_host_id  INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            status          TEXT    NOT NULL DEFAULT 'in_sync',
            diff_text       TEXT    NOT NULL DEFAULT '',
            diff_added      INTEGER NOT NULL DEFAULT 0,
            diff_removed    INTEGER NOT NULL DEFAULT 0,
            twin_bytes      INTEGER NOT NULL DEFAULT 0,
            prod_bytes      INTEGER NOT NULL DEFAULT 0,
            actor           TEXT    NOT NULL DEFAULT '',
            error           TEXT    NOT NULL DEFAULT '',
            checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_lab_drift_runs_device "
        "ON lab_drift_runs (lab_device_id, checked_at)"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
