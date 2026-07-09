"""SQLite read-only connection pool (get_db(read_only=True)) semantics.

The pool exists so read helpers overlap each other and the writer under WAL
instead of serializing on the process-wide access lock. These tests pin the
contract: reads overlap; a reader never blocks the writer; pooled connections
are query_only; nesting reuses the held connection in both directions that
are legal, and fails loudly for the one that isn't.
"""

from __future__ import annotations

import asyncio
import sqlite3

import pytest
import routes.database as db_module


@pytest.fixture
async def pool_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "read_pool_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    await db_module.init_db()

    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'core')")
        await db.commit()
    finally:
        await db.close()
    return db_path


@pytest.mark.asyncio
async def test_concurrent_readers_overlap(pool_db):
    """Two read sections must be able to hold connections at the same time.

    If read_only ever fell back to the exclusive writer lock, the second
    reader would block behind the first (which waits for it) and the gather
    would deadlock until the timeout.
    """
    first_holding = asyncio.Event()
    second_done = asyncio.Event()

    async def hold_and_wait():
        db = await db_module.get_db(read_only=True)
        try:
            first_holding.set()
            await asyncio.wait_for(second_done.wait(), timeout=5)
        finally:
            await db.close()

    async def read_while_held():
        await asyncio.wait_for(first_holding.wait(), timeout=5)
        db = await db_module.get_db(read_only=True)
        try:
            cursor = await db.execute("SELECT COUNT(*) FROM inventory_groups")
            assert (await cursor.fetchone())[0] == 1
        finally:
            await db.close()
        second_done.set()

    await asyncio.wait_for(asyncio.gather(hold_and_wait(), read_while_held()), timeout=10)


@pytest.mark.asyncio
async def test_writer_not_blocked_by_held_reader(pool_db):
    """A held read connection must not stall the exclusive writer path."""
    reader_holding = asyncio.Event()
    writer_done = asyncio.Event()

    async def reader():
        db = await db_module.get_db(read_only=True)
        try:
            reader_holding.set()
            await asyncio.wait_for(writer_done.wait(), timeout=5)
            # WAL: a fresh read (new implicit transaction) sees the commit.
            cursor = await db.execute(
                "SELECT COUNT(*) FROM inventory_groups WHERE name = 'edge'"
            )
            assert (await cursor.fetchone())[0] == 1
        finally:
            await db.close()

    async def writer():
        await asyncio.wait_for(reader_holding.wait(), timeout=5)
        db = await db_module.get_db()
        try:
            await db.execute("INSERT INTO inventory_groups (id, name) VALUES (2, 'edge')")
            await db.commit()
        finally:
            await db.close()
        writer_done.set()

    await asyncio.wait_for(asyncio.gather(reader(), writer()), timeout=10)


@pytest.mark.asyncio
async def test_read_connection_rejects_writes(pool_db):
    """Pooled connections are PRAGMA query_only: DML must fail."""
    db = await db_module.get_db(read_only=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            await db.execute("INSERT INTO inventory_groups (id, name) VALUES (9, 'nope')")
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_nested_read_inside_write_sees_uncommitted(pool_db):
    """A read helper called while a write transaction is held must reuse the
    write connection (and therefore see its uncommitted rows), not grab a
    pooled snapshot from before the transaction."""
    outer = await db_module.get_db()
    try:
        await outer.execute("INSERT INTO inventory_groups (id, name) VALUES (3, 'wip')")
        nested = await db_module.get_db(read_only=True)
        try:
            cursor = await nested.execute(
                "SELECT COUNT(*) FROM inventory_groups WHERE name = 'wip'"
            )
            assert (await cursor.fetchone())[0] == 1  # same conn: uncommitted visible
        finally:
            await nested.close()
        await outer.rollback()
    finally:
        await outer.close()


@pytest.mark.asyncio
async def test_write_request_inside_read_section_raises(pool_db):
    """Requesting write access while holding only a read-only connection is a
    programming error and must fail loudly, not die later inside SQLite."""
    db = await db_module.get_db(read_only=True)
    try:
        with pytest.raises(RuntimeError, match="read-only"):
            await db_module.get_db()
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_read_only_with_pool_disabled_uses_writer_path(pool_db, monkeypatch):
    """APP_SQLITE_READ_POOL=0 keeps the legacy exclusive-lock behavior."""
    monkeypatch.setattr(db_module, "SQLITE_READ_POOL_SIZE", 0)
    db = await db_module.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM inventory_groups")
        assert (await cursor.fetchone())[0] >= 1
        # Writer path: no readonly marker, so writes are permitted.
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (4, 'rw')")
        await db.rollback()
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_abandoned_transaction_rolled_back_on_release(pool_db):
    """A helper that raises between DML and commit() must not leak its open
    transaction into the next caller's critical section — the next caller's
    commit() would otherwise persist the stranger's partial writes."""
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (5, 'orphan')")
        # simulate the helper raising before commit: close without commit
    finally:
        await db.close()

    db = await db_module.get_db()
    try:
        # an unrelated caller committing must not persist the orphan row
        await db.commit()
        cursor = await db.execute(
            "SELECT COUNT(*) FROM inventory_groups WHERE name = 'orphan'"
        )
        assert (await cursor.fetchone())[0] == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_connections_are_reused_by_the_pool(pool_db):
    """Sequential read sections should reuse the pooled connection object."""
    db = await db_module.get_db(read_only=True)
    first_real = object.__getattribute__(db, "_real")
    await db.close()

    db = await db_module.get_db(read_only=True)
    try:
        assert object.__getattribute__(db, "_real") is first_real
    finally:
        await db.close()
