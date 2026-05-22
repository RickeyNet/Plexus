"""
Migration 0044: Convert audit-table TIMESTAMPTZ columns to TEXT on Postgres.

Migrations 0042 and 0043 introduced TIMESTAMPTZ columns on the Postgres
branch while every other table in the schema stores timestamps as TEXT.
The codebase's runtime SQL translator rewrites `datetime('now')` to
`NOW()::text` to match that TEXT contract, which then errors against
the TIMESTAMPTZ columns ("column finished_at is of type timestamp with
time zone but expression is of type text").

This migration aligns the audit tables with the rest of the schema by
converting their datetime columns to TEXT in place. On SQLite the
columns are already TEXT, so this is a no-op there.
"""

from __future__ import annotations

import os

VERSION = 44
DESCRIPTION = "Convert audit-table TIMESTAMPTZ columns to TEXT on Postgres"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


_PG_CONVERSIONS = [
    ("interface_inventory", "collected_at"),
    ("vlan_definitions",    "collected_at"),
    ("audit_runs",          "started_at"),
    ("audit_runs",          "finished_at"),
    ("audit_findings",      "created_at"),
    ("audit_rule_overrides", "created_at"),
    ("audit_rule_overrides", "expires_at"),
    ("audit_schedules",     "last_run_at"),
    ("audit_schedules",     "created_at"),
    ("audit_schedules",     "updated_at"),
    ("config_templates",    "created_at"),
    ("config_templates",    "updated_at"),
]


async def _column_type(db, table: str, column: str) -> str | None:
    cursor = await db.execute(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_name = ? AND column_name = ?",
        (table, column),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return row[0] if not isinstance(row, dict) else row["data_type"]


async def _up_postgres(db) -> None:
    for table, column in _PG_CONVERSIONS:
        dtype = await _column_type(db, table, column)
        if dtype is None or dtype == "text":
            continue
        await db.execute(
            f"ALTER TABLE {table} ALTER COLUMN {column} "
            f"TYPE TEXT USING {column}::text"
        )
        await db.execute(
            f"ALTER TABLE {table} ALTER COLUMN {column} DROP DEFAULT"
        )
        await db.execute(
            f"ALTER TABLE {table} ALTER COLUMN {column} "
            f"SET DEFAULT (NOW()::text)"
        )
    await db.commit()


async def _up_sqlite(db) -> None:
    return None


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
