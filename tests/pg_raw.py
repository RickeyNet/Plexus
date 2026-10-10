"""Raw asyncpg access to the per-test Postgres database, bypassing the app facade.

Tests use this to seed or tamper with rows the app API cannot (or must not)
write, and to probe the schema through ``information_schema``.  Each call opens
its own short-lived connection to ``routes.database.APP_DATABASE_URL`` (the
per-test clone tests/conftest.py points the app at) in autocommit mode, so
every statement is committed before the app reads it.  Sync tests that drive a
live TestClient can wrap a call in ``asyncio.run(...)``: the connection never
touches the app's per-loop pools.
"""

from __future__ import annotations

import asyncpg
import routes.database as db_module


async def connect() -> asyncpg.Connection:
    return await asyncpg.connect(db_module.APP_DATABASE_URL)


async def execute(sql: str, *args) -> str:
    conn = await connect()
    try:
        return await conn.execute(sql, *args)
    finally:
        await conn.close()


async def fetch(sql: str, *args) -> list[asyncpg.Record]:
    conn = await connect()
    try:
        return await conn.fetch(sql, *args)
    finally:
        await conn.close()


async def fetchval(sql: str, *args):
    conn = await connect()
    try:
        return await conn.fetchval(sql, *args)
    finally:
        await conn.close()


async def table_exists(table: str) -> bool:
    return bool(
        await fetchval(
            "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1",
            table,
        )
    )


async def table_columns(table: str) -> list[str]:
    rows = await fetch(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position",
        table,
    )
    return [r["column_name"] for r in rows]
