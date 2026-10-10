"""
Migration 0071: Fix Postgres column types that diverged from SQLite.

Schema and migrations are written in SQLite dialect, where ``REAL`` is an
8-byte double and ``INTEGER`` is a signed 64-bit value. On Postgres those
keywords mean float4 and int4, which lost precision (a CVSS score of 8.6
read back as 8.600000381469727) and rejected the int64-clamped counts that
IPAM stores for large IPv6 subnets.

The DDL converter now maps ``REAL`` to ``DOUBLE PRECISION`` for new
databases. This migration widens existing ones:

  - every ``real`` (float4) column in the public schema -> DOUBLE PRECISION
  - ``ipam_subnet_utilization`` count columns -> BIGINT

Both steps only touch columns still at the narrow type, so re-running is a
no-op. SQLite stores these types natively; nothing to migrate there.
"""

from __future__ import annotations

import os

VERSION = 71
DESCRIPTION = "Widen Postgres REAL columns to DOUBLE PRECISION and IPAM utilization counts to BIGINT"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"

_BIGINT_COLUMNS = {
    "ipam_subnet_utilization": ("total", "used", "reserved", "pending", "free"),
}


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


async def _columns_of_type(db, data_type: str) -> list[tuple[str, str]]:
    cursor = await db.execute(
        """SELECT table_name, column_name FROM information_schema.columns
           WHERE table_schema = 'public' AND data_type = ?
           ORDER BY table_name, column_name""",
        (data_type,),
    )
    return [(row[0], row[1]) for row in await cursor.fetchall()]


async def _up_sqlite(db) -> None:
    return


async def _up_postgres(db) -> None:
    # ALTER COLUMN ... TYPE preserves existing values (float4 -> float8 and
    # int4 -> int8 are both lossless widenings).
    for table, column in await _columns_of_type(db, "real"):
        await db.execute(f"ALTER TABLE {_quote_ident(table)} ALTER COLUMN {_quote_ident(column)} TYPE DOUBLE PRECISION")
    for table, column in await _columns_of_type(db, "integer"):
        if column in _BIGINT_COLUMNS.get(table, ()):
            await db.execute(f"ALTER TABLE {_quote_ident(table)} ALTER COLUMN {_quote_ident(column)} TYPE BIGINT")
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
