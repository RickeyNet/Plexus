"""
Migration 0010: Add binary payload support for report artifacts.

Adds:
  - report_artifacts table (if missing)
  - content_blob column for binary artifacts (PDF, images)
"""

from __future__ import annotations

import os

VERSION = 10
DESCRIPTION = "Add report artifacts binary payload support"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _ensure_sqlite_column(db, table: str, column: str, ddl: str) -> None:
    cursor = await db.execute(f"PRAGMA table_info({table})")
    rows = await cursor.fetchall()
    names = {str(row[1]) for row in rows}
    if column not in names:
        await db.execute(ddl)


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS report_artifacts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id          INTEGER NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
            report_id       INTEGER REFERENCES report_definitions(id) ON DELETE SET NULL,
            artifact_type   TEXT    NOT NULL DEFAULT 'csv',
            file_name       TEXT    NOT NULL DEFAULT '',
            media_type      TEXT    NOT NULL DEFAULT 'text/plain',
            content_text    TEXT    NOT NULL DEFAULT '',
            content_blob    BLOB,
            size_bytes      INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await _ensure_sqlite_column(
        db,
        "report_artifacts",
        "content_blob",
        "ALTER TABLE report_artifacts ADD COLUMN content_blob BLOB",
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_report_artifacts_run
        ON report_artifacts (run_id, created_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_report_artifacts_report
        ON report_artifacts (report_id, created_at DESC)
        """
    )
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS report_artifacts (
            id              SERIAL PRIMARY KEY,
            run_id          INTEGER NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
            report_id       INTEGER REFERENCES report_definitions(id) ON DELETE SET NULL,
            artifact_type   TEXT    NOT NULL DEFAULT 'csv',
            file_name       TEXT    NOT NULL DEFAULT '',
            media_type      TEXT    NOT NULL DEFAULT 'text/plain',
            content_text    TEXT    NOT NULL DEFAULT '',
            content_blob    BYTEA,
            size_bytes      INTEGER NOT NULL DEFAULT 0,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    cursor = await db.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'report_artifacts'
          AND column_name = 'content_blob'
        LIMIT 1
        """
    )
    exists = await cursor.fetchone()
    if not exists:
        await db.execute(
            "ALTER TABLE report_artifacts ADD COLUMN content_blob BYTEA"
        )

    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_report_artifacts_run
        ON report_artifacts (run_id, created_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_report_artifacts_report
        ON report_artifacts (report_id, created_at DESC)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)

