"""Unit tests for the Postgres compat layer that don't need a real database.

These exercise ``_PostgresConnectionCompat`` and the SQL-dialect helpers with a
fake asyncpg connection, pinning the fixes for:
  * ``rollback()`` existing (its absence turned every expected integrity error
    into an AttributeError → 500 on pg)
  * hand-written ``RETURNING`` inserts being fetched (not discarded)
  * allowlisted inserts getting ``RETURNING id`` appended for lastrowid
  * strftime/printf and julianday query sites getting a Postgres branch
"""

from __future__ import annotations

import pytest
import routes.database as db_module
from routes.database import _PostgresConnectionCompat


class _FakeRecord(dict):
    """Stand-in for asyncpg.Record: dict-like with keys()/__getitem__."""


class _FakeConn:
    def __init__(self):
        self.calls = []

    async def fetch(self, query, *params):
        self.calls.append(("fetch", query, params))
        up = query.strip().upper()
        if "RETURNING" in up or up.startswith("SELECT") or up.startswith("WITH"):
            return [_FakeRecord(id=42)]
        return []

    async def execute(self, query, *params):
        self.calls.append(("execute", query, params))
        return "INSERT 0 1"

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_rollback_exists_and_is_noop():
    conn = _PostgresConnectionCompat(_FakeConn())
    # Must not raise AttributeError.
    assert await conn.rollback() is None


@pytest.mark.asyncio
async def test_explicit_returning_insert_is_fetched():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    cur = await conn.execute(
        "INSERT INTO metric_baselines (host_id) VALUES (?) RETURNING id", (1,)
    )
    assert cur.lastrowid == 42
    row = await cur.fetchone()
    assert row["id"] == 42
    # It must have gone through fetch(), not execute() (which discards rows).
    assert any(c[0] == "fetch" for c in fake.calls)


@pytest.mark.asyncio
async def test_allowlisted_insert_appends_returning_id():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    cur = await conn.execute("INSERT INTO dashboards (name) VALUES (?)", ("d",))
    assert cur.lastrowid == 42
    fetched_sql = [c[1] for c in fake.calls if c[0] == "fetch"][0]
    assert "RETURNING id" in fetched_sql


@pytest.mark.asyncio
async def test_non_allowlisted_insert_has_no_lastrowid():
    fake = _FakeConn()
    conn = _PostgresConnectionCompat(fake)
    cur = await conn.execute("INSERT INTO some_junction_tbl (a, b) VALUES (?, ?)", (1, 2))
    assert cur.lastrowid is None
    assert cur.rowcount == 1
    # Should use execute() (status-tag rowcount), not fetch().
    assert any(c[0] == "execute" for c in fake.calls)


def test_minute_bucket_expr_branches(monkeypatch):
    monkeypatch.setattr(db_module, "DB_ENGINE", "postgres")
    pg = db_module._minute_bucket_expr("received_at", 5)
    assert "to_char" in pg and "extract(minute" in pg.lower()

    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    lite = db_module._minute_bucket_expr("received_at", 5)
    assert "strftime" in lite and "printf" in lite


def test_minute_bucket_expr_rejects_bad_column(monkeypatch):
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    with pytest.raises(ValueError):
        db_module._minute_bucket_expr("received_at; DROP TABLE x", 5)


def test_minutes_between_expr_branches(monkeypatch):
    monkeypatch.setattr(db_module, "DB_ENGINE", "postgres")
    pg = db_module._minutes_between_expr("a.acknowledged_at", "a.created_at")
    assert "EXTRACT(EPOCH" in pg and "julianday" not in pg

    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    lite = db_module._minutes_between_expr("a.acknowledged_at", "a.created_at")
    assert "julianday" in lite
