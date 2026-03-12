#!/usr/bin/env python3
"""Migrate Plexus data from SQLite to PostgreSQL.

Usage:
  python tools/migrate_sqlite_to_postgres.py \
    --sqlite-path routes/netcontrol.db \
    --postgres-url postgresql://plexus:plexus@localhost:5432/plexus

Dry-run mode validates source access and prints row counts without writing:
  python tools/migrate_sqlite_to_postgres.py --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sqlite3
from collections.abc import Iterable

import asyncpg

TABLE_ORDER = [
    "users",
    "access_groups",
    "access_group_features",
    "user_group_memberships",
    "auth_settings",
    "inventory_groups",
    "hosts",
    "playbooks",
    "templates",
    "credentials",
    "jobs",
    "job_events",
    "audit_events",
]

SEQUENCE_TABLES = [
    "users",
    "access_groups",
    "inventory_groups",
    "hosts",
    "playbooks",
    "templates",
    "credentials",
    "jobs",
    "job_events",
    "audit_events",
]


def _default_sqlite_path() -> str:
    return os.getenv("APP_DB_PATH", os.path.join("routes", "netcontrol.db"))


def _default_postgres_url() -> str:
    return os.getenv("APP_DATABASE_URL", "postgresql://plexus:plexus@localhost:5432/plexus")


def _fetch_sqlite_rows(sqlite_path: str, table: str) -> tuple[list[str], list[tuple]]:
    with sqlite3.connect(sqlite_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(f"SELECT * FROM {table}")
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        as_tuples = [tuple(r[c] for c in cols) for r in rows]
        return cols, as_tuples


def _render_placeholders(count: int) -> str:
    return ", ".join(f"${i}" for i in range(1, count + 1))


async def _truncate_target(conn: asyncpg.Connection) -> None:
    tables = ", ".join(TABLE_ORDER)
    await conn.execute(f"TRUNCATE TABLE {tables} RESTART IDENTITY CASCADE")


async def _insert_rows(
    conn: asyncpg.Connection,
    table: str,
    columns: Iterable[str],
    rows: list[tuple],
) -> int:
    cols = list(columns)
    if not rows:
        return 0

    column_csv = ", ".join(cols)
    placeholders = _render_placeholders(len(cols))
    query = f"INSERT INTO {table} ({column_csv}) VALUES ({placeholders})"
    await conn.executemany(query, rows)
    return len(rows)


async def _set_sequences(conn: asyncpg.Connection) -> None:
    for table in SEQUENCE_TABLES:
        await conn.execute(
            """
            SELECT setval(
                pg_get_serial_sequence($1, 'id'),
                COALESCE((SELECT MAX(id) FROM ONLY """ + table + """), 0),
                COALESCE((SELECT MAX(id) FROM ONLY """ + table + """), 0) > 0
            )
            """,
            table,
        )


async def _count_postgres_rows(conn: asyncpg.Connection, table: str) -> int:
    return int(await conn.fetchval(f"SELECT COUNT(*) FROM {table}"))


async def migrate(sqlite_path: str, postgres_url: str, dry_run: bool) -> int:
    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"SQLite file not found: {sqlite_path}")

    sqlite_counts: dict[str, int] = {}
    sqlite_payloads: dict[str, tuple[list[str], list[tuple]]] = {}

    for table in TABLE_ORDER:
        cols, rows = _fetch_sqlite_rows(sqlite_path, table)
        sqlite_payloads[table] = (cols, rows)
        sqlite_counts[table] = len(rows)

    print("Source SQLite row counts:")
    for table in TABLE_ORDER:
        print(f"  {table}: {sqlite_counts[table]}")

    if dry_run:
        print("Dry-run complete. No PostgreSQL writes were performed.")
        return 0

    conn = await asyncpg.connect(postgres_url)
    try:
        async with conn.transaction():
            await _truncate_target(conn)

            inserted_counts: dict[str, int] = {}
            for table in TABLE_ORDER:
                cols, rows = sqlite_payloads[table]
                inserted_counts[table] = await _insert_rows(conn, table, cols, rows)

            await _set_sequences(conn)

        print("Inserted rows into PostgreSQL:")
        for table in TABLE_ORDER:
            print(f"  {table}: {inserted_counts[table]}")

        print("Parity verification (SQLite vs PostgreSQL):")
        mismatches = 0
        for table in TABLE_ORDER:
            pg_count = await _count_postgres_rows(conn, table)
            sqlite_count = sqlite_counts[table]
            status = "OK" if pg_count == sqlite_count else "MISMATCH"
            if status != "OK":
                mismatches += 1
            print(f"  {table}: sqlite={sqlite_count} postgres={pg_count} [{status}]")

        if mismatches:
            print(f"Completed with {mismatches} table count mismatch(es).")
            return 2

        print("Migration completed successfully with full row-count parity.")
        return 0
    finally:
        await conn.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Migrate Plexus SQLite data to PostgreSQL")
    parser.add_argument("--sqlite-path", default=_default_sqlite_path(), help="Path to source SQLite DB")
    parser.add_argument("--postgres-url", default=_default_postgres_url(), help="Target PostgreSQL DSN")
    parser.add_argument("--dry-run", action="store_true", help="Read/validate only; do not write to PostgreSQL")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return asyncio.run(migrate(args.sqlite_path, args.postgres_url, args.dry_run))


if __name__ == "__main__":
    raise SystemExit(main())
