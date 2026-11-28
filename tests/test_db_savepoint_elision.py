"""SQLite-style failure semantics of the Postgres compat layer, on a real
database, after the per-statement savepoint was dropped where it is not
needed (the first statement of a fresh transaction, statements inside an
``atomic()`` block) and the pool reset was trimmed.

The guarantee every case pins: a statement that fails inside a transaction,
and whose error the caller catches, leaves the transaction usable; the
statements before it stay pending and are committed or rolled back exactly
as if the failed statement had never run.
"""

from __future__ import annotations

import asyncio

import asyncpg
import pytest
import routes.database as db_module
import routes.db.audit as audit_module

_TABLE = "w1_sp_items"


async def _fresh_table() -> None:
    conn = await db_module.get_db()
    try:
        await conn.execute(f"DROP TABLE IF EXISTS {_TABLE}")
        await conn.execute(f"CREATE TABLE {_TABLE} (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)")
        await conn.commit()
    finally:
        await conn.close()


async def _names() -> list[str]:
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute(f"SELECT name FROM {_TABLE} ORDER BY id")  # nosec B608 - test constant
        return [row[0] for row in await cursor.fetchall()]
    finally:
        await conn.close()


async def _insert(conn, name: str) -> None:
    await conn.execute(f"INSERT INTO {_TABLE} (name) VALUES (?)", (name,))  # nosec B608 - test constant


async def _insert_dup_caught(conn, name: str) -> None:
    with pytest.raises(asyncpg.UniqueViolationError):
        await _insert(conn, name)


@pytest.fixture
async def table():
    await _fresh_table()
    yield
    conn = await db_module.get_db()
    try:
        await conn.execute(f"DROP TABLE IF EXISTS {_TABLE}")
        await conn.commit()
    finally:
        await conn.close()


async def test_caught_integrity_error_mid_transaction_keeps_earlier_and_later_writes(table):
    conn = await db_module.get_db()
    try:
        await _insert(conn, "alpha")
        await _insert(conn, "bravo")
        await _insert_dup_caught(conn, "alpha")
        await _insert(conn, "charlie")
        await conn.commit()
    finally:
        await conn.close()
    assert await _names() == ["alpha", "bravo", "charlie"]


async def test_repeated_failures_in_one_transaction(table):
    conn = await db_module.get_db()
    try:
        for i in range(30):
            await _insert(conn, f"n{i}")
            if i % 3 == 0:
                await _insert_dup_caught(conn, f"n{i}")
        await conn.commit()
    finally:
        await conn.close()
    assert await _names() == [f"n{i}" for i in range(30)]


async def test_error_on_first_statement_then_more_writes_commit(table):
    conn = await db_module.get_db()
    try:
        await _insert(conn, "seed")
        await conn.commit()
        await _insert_dup_caught(conn, "seed")  # first statement of a fresh transaction
        await _insert(conn, "delta")
        await _insert(conn, "echo")
        await conn.commit()
    finally:
        await conn.close()
    assert await _names() == ["seed", "delta", "echo"]


async def test_error_on_first_statement_then_rollback(table):
    conn = await db_module.get_db()
    try:
        await _insert(conn, "seed")
        await conn.commit()
        await _insert_dup_caught(conn, "seed")
        await _insert(conn, "foxtrot")
        await conn.rollback()
        await _insert(conn, "golf")
        await conn.commit()
    finally:
        await conn.close()
    assert await _names() == ["seed", "golf"]


async def test_failing_select_mid_transaction_keeps_the_transaction(table):
    conn = await db_module.get_db()
    try:
        await _insert(conn, "hotel")
        with pytest.raises(asyncpg.DivisionByZeroError):
            await conn.execute("SELECT 1 / 0")
        cursor = await conn.execute(f"SELECT name FROM {_TABLE}")  # nosec B608 - test constant
        assert [r[0] for r in await cursor.fetchall()] == ["hotel"]  # own uncommitted row
        await _insert(conn, "india")
        await conn.commit()
    finally:
        await conn.close()
    assert await _names() == ["hotel", "india"]


async def test_failing_select_outside_a_transaction(table):
    conn = await db_module.get_db()
    try:
        with pytest.raises(asyncpg.DivisionByZeroError):
            await conn.execute("SELECT 1 / 0")
        await _insert(conn, "juliet")
        await conn.commit()
    finally:
        await conn.close()
    assert await _names() == ["juliet"]


async def test_rollback_after_partial_writes_and_a_caught_failure(table):
    conn = await db_module.get_db()
    try:
        await _insert(conn, "kilo")
        await _insert(conn, "lima")
        await _insert_dup_caught(conn, "kilo")
        await _insert(conn, "mike")
        await conn.rollback()
    finally:
        await conn.close()
    assert await _names() == []


async def test_uncommitted_section_is_rolled_back_on_release(table):
    conn = await db_module.get_db()
    try:
        await _insert(conn, "november")
        await _insert_dup_caught(conn, "november")
    finally:
        await conn.close()
    assert await _names() == []


async def test_nested_get_db_shares_the_transaction(table):
    outer = await db_module.get_db()
    try:
        await _insert(outer, "oscar")
        inner = await db_module.get_db()
        try:
            await _insert_dup_caught(inner, "oscar")
            await _insert(inner, "papa")
        finally:
            await inner.close()
        await _insert(outer, "quebec")
        await outer.commit()
    finally:
        await outer.close()
    assert await _names() == ["oscar", "papa", "quebec"]


async def test_nested_first_statement_failure_then_outer_rollback(table):
    seed = await db_module.get_db()
    try:
        await _insert(seed, "romeo")
        await seed.commit()
    finally:
        await seed.close()
    outer = await db_module.get_db()
    try:
        inner = await db_module.get_db()
        try:
            await _insert_dup_caught(inner, "romeo")  # first statement, via the nested helper
        finally:
            await inner.close()
        await _insert(outer, "sierra")
        await outer.rollback()
    finally:
        await outer.close()
    assert await _names() == ["romeo"]


async def test_raw_outer_transaction_keeps_working_after_a_failed_first_statement(table):
    """bulk_import wraps the compat layer in a raw asyncpg transaction, so the
    compat transaction is itself a savepoint there."""
    seed = await db_module.get_db()
    try:
        await _insert(seed, "tango")
        await seed.commit()
    finally:
        await seed.close()

    for commit in (True, False):
        conn = await db_module.get_db()
        try:
            outer = conn._conn.transaction()
            await outer.start()
            await _insert_dup_caught(conn, "tango")
            await _insert(conn, f"uniform-{commit}")
            await _insert_dup_caught(conn, "tango")
            await _insert(conn, f"victor-{commit}")
            await conn.commit()
            if commit:
                await outer.commit()
            else:
                await outer.rollback()
        finally:
            await conn.close()
    assert await _names() == ["tango", "uniform-True", "victor-True"]


async def test_executemany_and_executescript_keep_semantics(table):
    conn = await db_module.get_db()
    try:
        await _insert(conn, "whiskey")
        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.executemany(
                f"INSERT INTO {_TABLE} (name) VALUES (?)",  # nosec B608 - test constant
                [("xray",), ("whiskey",)],
            )
        await conn.executescript(f"INSERT INTO {_TABLE} (name) VALUES ('yankee'); UPDATE {_TABLE} SET name = name")
        await conn.commit()
    finally:
        await conn.close()
    assert await _names() == ["whiskey", "yankee"]


# -- atomic() -------------------------------------------------------------------


async def test_atomic_block_in_fresh_transaction_is_all_or_nothing(table):
    conn = await db_module.get_db()
    try:
        with pytest.raises(asyncpg.UniqueViolationError):
            async with conn.atomic():
                await _insert(conn, "zulu")
                await _insert(conn, "zulu")
        assert not conn.in_transaction
        await _insert(conn, "after")
        await conn.commit()
    finally:
        await conn.close()
    assert await _names() == ["after"]


async def test_atomic_block_after_earlier_writes_rolls_back_only_itself(table):
    conn = await db_module.get_db()
    try:
        await _insert(conn, "before")
        with pytest.raises(asyncpg.UniqueViolationError):
            async with conn.atomic():
                await _insert(conn, "inside")
                await _insert(conn, "before")
        async with conn.atomic():
            await _insert(conn, "ok-1")
            async with conn.atomic():
                await _insert(conn, "ok-2")
            with pytest.raises(asyncpg.UniqueViolationError):
                async with conn.atomic():
                    await _insert(conn, "nested-lost")
                    await _insert(conn, "ok-1")
            await _insert(conn, "ok-3")
        await conn.commit()
    finally:
        await conn.close()
    assert await _names() == ["before", "ok-1", "ok-2", "ok-3"]


# -- pool reset ------------------------------------------------------------------


def test_session_state_detection():
    touches = db_module._touches_session_state
    for sql in (
        "SELECT pg_advisory_lock(42)",
        "select pg_try_advisory_lock(?)",
        "SET application_name = 'x'",
        "  reset all",
        "LISTEN chan",
        "SELECT set_config('a.b', 'c', false)",
        "CREATE TEMP TABLE t (a INT)",
        "CREATE TEMPORARY TABLE t (a INT)",
        "DECLARE c CURSOR FOR SELECT 1",
        "PREPARE p AS SELECT 1",
    ):
        assert touches(sql), sql
    for sql in (
        "SELECT pg_advisory_xact_lock(42)",
        "SELECT * FROM hosts WHERE id = ?",
        "UPDATE hosts SET name = ? WHERE id = ?",
        "INSERT INTO t (tempo) VALUES (?)",
        "DELETE FROM listeners WHERE id = ?",
    ):
        assert not touches(sql), sql


@pytest.fixture
async def single_conn_pool(monkeypatch):
    """A one-connection pool built the way production builds it, so every
    get_db() reuses the same backend session."""
    pool = await asyncpg.create_pool(
        db_module.APP_DATABASE_URL, min_size=1, max_size=1, **db_module._pool_connection_options()
    )

    async def _get_pool():
        return pool

    monkeypatch.setattr(db_module, "_get_pg_pool", _get_pool)
    yield pool
    await pool.close()


async def _scalar(sql: str):
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute(sql)
        return (await cursor.fetchone())[0]
    finally:
        await conn.close()


async def test_plain_release_sends_no_reset_query(single_conn_pool):
    sent: list[str] = []
    real_execute = asyncpg.Connection.execute

    async def _spy(self, query, *args, **kwargs):
        sent.append(query)
        return await real_execute(self, query, *args, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(asyncpg.Connection, "execute", _spy)
        assert await _scalar("SELECT 1") == 1
    assert not any("RESET ALL" in q or "pg_advisory_unlock_all" in q for q in sent)


async def test_session_state_is_reset_before_reuse(single_conn_pool):
    conn = await db_module.get_db()
    try:
        # Both run outside a transaction, so only the reset can undo them.
        await conn.execute("SELECT set_config('application_name', 'w1-left-behind', false)")
        await conn.execute("SELECT pg_advisory_lock(?)", (4242,))
        assert await _scalar("SELECT current_setting('application_name')") == "w1-left-behind"
    finally:
        await conn.close()
    assert await _scalar("SELECT current_setting('application_name')") != "w1-left-behind"
    held = await _scalar("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()")
    assert held == 0


async def test_open_transaction_is_rolled_back_on_release(single_conn_pool, table):
    conn = await db_module.get_db()
    try:
        await _insert(conn, "abandoned")
    finally:
        await conn.close()
    assert await _scalar("SELECT txid_current_if_assigned() IS NULL") is True
    assert await _names() == []


# -- audit chain -----------------------------------------------------------------


async def _audit_rows() -> list:
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute("SELECT id, prev_hash, row_hash FROM audit_events ORDER BY id")
        return await cursor.fetchall()
    finally:
        await conn.close()


def _assert_linked(rows) -> None:
    prev = rows[0][1] if rows else ""
    for _id, prev_hash, row_hash in rows:
        assert prev_hash == prev
        prev = row_hash


async def test_audit_chain_under_concurrent_writers():
    await db_module.init_db()
    before = len(await _audit_rows())
    ids = await asyncio.gather(*(db_module.add_audit_event("test", "concurrent", detail=str(i)) for i in range(50)))
    assert len(set(ids)) == 50
    rows = await _audit_rows()
    assert len(rows) == before + 50
    _assert_linked(rows)
    assert (await db_module.verify_audit_chain())["ok"] is True


class _NoLock:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


async def test_audit_chain_holds_with_only_the_database_lock(monkeypatch):
    """Without the in-process lock every writer races on its own pooled
    connection, as writers in separate processes would; the Postgres
    advisory lock alone must keep the chain linear."""
    await db_module.init_db()
    monkeypatch.setattr(audit_module, "_audit_chain_lock", _NoLock())
    await asyncio.gather(*(db_module.add_audit_event("test", "racing", detail=str(i)) for i in range(50)))
    rows = await _audit_rows()
    assert len(rows) >= 50
    _assert_linked(rows)
    assert (await db_module.verify_audit_chain())["ok"] is True


async def test_audit_inside_caller_transaction_releases_the_lock():
    await db_module.init_db()
    conn = await db_module.get_db()
    try:
        await conn.execute("UPDATE audit_events SET id = id WHERE 1 = 0")  # opens the caller's transaction
        assert conn.in_transaction
        await db_module.add_audit_event("test", "nested")
        cursor = await conn.execute(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()"
        )
        assert (await cursor.fetchone())[0] == 0
    finally:
        await conn.close()
    rows = await _audit_rows()
    _assert_linked(rows)
    assert (await db_module.verify_audit_chain())["ok"] is True
