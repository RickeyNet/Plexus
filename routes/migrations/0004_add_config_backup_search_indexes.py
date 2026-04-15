"""
Migration 0004: Add configuration backup search indexes.

SQLite:
  - FTS5 virtual table over config_backups.config_text
  - Triggers to keep the index in sync on insert/update/delete

Postgres:
  - GIN full-text index on config_backups.config_text

Also adds helper btree indexes used by backup search ordering/filtering.
"""

from __future__ import annotations

import os

VERSION = 4
DESCRIPTION = "Add config backup full-text search indexes"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS config_backups_fts
        USING fts5(config_text, content='config_backups', content_rowid='id')
        """
    )
    await db.execute(
        """
        CREATE TRIGGER IF NOT EXISTS config_backups_ai
        AFTER INSERT ON config_backups BEGIN
            INSERT INTO config_backups_fts(rowid, config_text)
            VALUES (new.id, COALESCE(new.config_text, ''));
        END
        """
    )
    await db.execute(
        """
        CREATE TRIGGER IF NOT EXISTS config_backups_ad
        AFTER DELETE ON config_backups BEGIN
            INSERT INTO config_backups_fts(config_backups_fts, rowid, config_text)
            VALUES ('delete', old.id, COALESCE(old.config_text, ''));
        END
        """
    )
    await db.execute(
        """
        CREATE TRIGGER IF NOT EXISTS config_backups_au
        AFTER UPDATE ON config_backups BEGIN
            INSERT INTO config_backups_fts(config_backups_fts, rowid, config_text)
            VALUES ('delete', old.id, COALESCE(old.config_text, ''));
            INSERT INTO config_backups_fts(rowid, config_text)
            VALUES (new.id, COALESCE(new.config_text, ''));
        END
        """
    )

    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_config_backups_host_captured ON config_backups(host_id, captured_at DESC)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_config_backups_status_captured ON config_backups(status, captured_at DESC)"
    )

    # Backfill/rebuild FTS index for existing rows.
    await db.execute("INSERT INTO config_backups_fts(config_backups_fts) VALUES ('rebuild')")
    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_backups_fts
        ON config_backups
        USING GIN (to_tsvector('simple', COALESCE(config_text, '')))
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_backups_host_captured
        ON config_backups(host_id, captured_at DESC)
        """
    )
    await db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_config_backups_status_captured
        ON config_backups(status, captured_at DESC)
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
