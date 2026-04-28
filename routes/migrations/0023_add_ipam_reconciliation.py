"""
Migration 0023: Add IPAM bi-directional reconciliation tables.

Adds:
  - ipam_reconciliation_runs (one row per reconciliation pass for a source)
  - ipam_reconciliation_diffs (one row per detected drift between Plexus
    inventory and an external IPAM source's allocations)
"""

from __future__ import annotations

import os

VERSION = 23
DESCRIPTION = "Add IPAM reconciliation runs and diffs tables"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_reconciliation_runs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id       INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
            started_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            finished_at     TEXT,
            status          TEXT    NOT NULL DEFAULT 'running',
            triggered_by    TEXT    NOT NULL DEFAULT '',
            diff_count      INTEGER NOT NULL DEFAULT 0,
            resolved_count  INTEGER NOT NULL DEFAULT 0,
            message         TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_reconciliation_diffs (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id              INTEGER NOT NULL REFERENCES ipam_reconciliation_runs(id) ON DELETE CASCADE,
            source_id           INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
            address             TEXT    NOT NULL,
            drift_type          TEXT    NOT NULL,
            plexus_state_json   TEXT    NOT NULL DEFAULT '{}',
            ipam_state_json     TEXT    NOT NULL DEFAULT '{}',
            resolution          TEXT    NOT NULL DEFAULT '',
            resolved_by         TEXT    NOT NULL DEFAULT '',
            resolved_at         TEXT,
            resolution_message  TEXT    NOT NULL DEFAULT '',
            created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_reconciliation_runs_source
        ON ipam_reconciliation_runs (source_id, started_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_reconciliation_diffs_open
        ON ipam_reconciliation_diffs (source_id, resolution, address)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_reconciliation_diffs_run
        ON ipam_reconciliation_diffs (run_id)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_reconciliation_runs (
            id              SERIAL PRIMARY KEY,
            source_id       INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
            started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finished_at     TIMESTAMPTZ,
            status          TEXT    NOT NULL DEFAULT 'running',
            triggered_by    TEXT    NOT NULL DEFAULT '',
            diff_count      INTEGER NOT NULL DEFAULT 0,
            resolved_count  INTEGER NOT NULL DEFAULT 0,
            message         TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS ipam_reconciliation_diffs (
            id                  SERIAL PRIMARY KEY,
            run_id              INTEGER NOT NULL REFERENCES ipam_reconciliation_runs(id) ON DELETE CASCADE,
            source_id           INTEGER NOT NULL REFERENCES ipam_sources(id) ON DELETE CASCADE,
            address             TEXT    NOT NULL,
            drift_type          TEXT    NOT NULL,
            plexus_state_json   TEXT    NOT NULL DEFAULT '{}',
            ipam_state_json     TEXT    NOT NULL DEFAULT '{}',
            resolution          TEXT    NOT NULL DEFAULT '',
            resolved_by         TEXT    NOT NULL DEFAULT '',
            resolved_at         TIMESTAMPTZ,
            resolution_message  TEXT    NOT NULL DEFAULT '',
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_reconciliation_runs_source
        ON ipam_reconciliation_runs (source_id, started_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_reconciliation_diffs_open
        ON ipam_reconciliation_diffs (source_id, resolution, address)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ipam_reconciliation_diffs_run
        ON ipam_reconciliation_diffs (run_id)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
