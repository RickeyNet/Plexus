"""
Migration 0039: Maintenance windows and approval gates for production changes.

Adds:

* ``maintenance_windows`` -- scheduled change windows. Each row holds a
  start/end timestamp, an optional weekly recurrence (weekday bitmask:
  Mon=1<<0 ... Sun=1<<6), and a ``policy`` of ``block_outside_window`` |
  ``warn_outside_window`` | ``allow_changes``. Windows with no scope rows
  apply globally; otherwise they apply only to the listed groups.
* ``maintenance_window_scopes`` -- many-to-many of windows to inventory
  groups.
* ``inventory_groups.environment`` -- nullable text column. When set to
  ``production`` deployments targeting any host in such a group are
  auto-flagged ``requires_approval=1``.
* ``deployments`` approval columns (``requires_approval``,
  ``approval_status``, ``approval_requested_at``, ``approved_by``,
  ``approved_at``, ``approval_comment``) so a deployment can be gated on
  human approval before execute is allowed.
"""

from __future__ import annotations

import os

VERSION = 39
DESCRIPTION = "Maintenance windows + deployment approval gates"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


async def _column_exists_sqlite(db, table: str, column: str) -> bool:
    cursor = await db.execute(f"PRAGMA table_info({table})")
    rows = await cursor.fetchall()
    return any(row[1] == column for row in rows)


async def _up_sqlite(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS maintenance_windows (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL,
            description     TEXT    NOT NULL DEFAULT '',
            start_at        TEXT    NOT NULL,
            end_at          TEXT    NOT NULL,
            recurrence      TEXT    NOT NULL DEFAULT 'none',
            weekday_mask    INTEGER NOT NULL DEFAULT 0,
            policy          TEXT    NOT NULL DEFAULT 'block_outside_window',
            enabled         INTEGER NOT NULL DEFAULT 1,
            created_by      TEXT    NOT NULL DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS maintenance_window_scopes (
            window_id   INTEGER NOT NULL REFERENCES maintenance_windows(id) ON DELETE CASCADE,
            group_id    INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
            PRIMARY KEY (window_id, group_id)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_maintenance_scopes_group ON maintenance_window_scopes(group_id)"
    )

    if not await _column_exists_sqlite(db, "inventory_groups", "environment"):
        await db.execute(
            "ALTER TABLE inventory_groups ADD COLUMN environment TEXT DEFAULT NULL"
        )

    deployment_columns = [
        ("requires_approval",     "INTEGER NOT NULL DEFAULT 0"),
        ("approval_status",       "TEXT    NOT NULL DEFAULT 'not_required'"),
        ("approval_requested_at", "TEXT"),
        ("approved_by",           "TEXT    DEFAULT ''"),
        ("approved_at",           "TEXT"),
        ("approval_comment",      "TEXT    DEFAULT ''"),
    ]
    for col, decl in deployment_columns:
        if not await _column_exists_sqlite(db, "deployments", col):
            await db.execute(f"ALTER TABLE deployments ADD COLUMN {col} {decl}")

    await db.commit()


async def _up_postgres(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS maintenance_windows (
            id              SERIAL PRIMARY KEY,
            name            TEXT        NOT NULL,
            description     TEXT        NOT NULL DEFAULT '',
            start_at        TIMESTAMPTZ NOT NULL,
            end_at          TIMESTAMPTZ NOT NULL,
            recurrence      TEXT        NOT NULL DEFAULT 'none',
            weekday_mask    INTEGER     NOT NULL DEFAULT 0,
            policy          TEXT        NOT NULL DEFAULT 'block_outside_window',
            enabled         INTEGER     NOT NULL DEFAULT 1,
            created_by      TEXT        NOT NULL DEFAULT '',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS maintenance_window_scopes (
            window_id   INTEGER NOT NULL REFERENCES maintenance_windows(id) ON DELETE CASCADE,
            group_id    INTEGER NOT NULL REFERENCES inventory_groups(id) ON DELETE CASCADE,
            PRIMARY KEY (window_id, group_id)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_maintenance_scopes_group ON maintenance_window_scopes(group_id)"
    )
    await db.execute(
        "ALTER TABLE inventory_groups ADD COLUMN IF NOT EXISTS environment TEXT DEFAULT NULL"
    )
    await db.execute(
        "ALTER TABLE deployments ADD COLUMN IF NOT EXISTS requires_approval INTEGER NOT NULL DEFAULT 0"
    )
    await db.execute(
        "ALTER TABLE deployments ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'not_required'"
    )
    await db.execute(
        "ALTER TABLE deployments ADD COLUMN IF NOT EXISTS approval_requested_at TIMESTAMPTZ"
    )
    await db.execute(
        "ALTER TABLE deployments ADD COLUMN IF NOT EXISTS approved_by TEXT DEFAULT ''"
    )
    await db.execute(
        "ALTER TABLE deployments ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ"
    )
    await db.execute(
        "ALTER TABLE deployments ADD COLUMN IF NOT EXISTS approval_comment TEXT DEFAULT ''"
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
