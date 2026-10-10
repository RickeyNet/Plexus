"""Tests for the audit_events hash chain (migration 0037).

Covers:
  * add_audit_event populates prev_hash/row_hash and links rows correctly
  * verify_audit_chain accepts a clean chain and rejects a mutated one
  * Postgres triggers block raw UPDATE and DELETE against audit_events
  * Migration backfill produces a chain that verifies clean
"""

from __future__ import annotations

import hashlib

import asyncpg
import pytest
import routes.database as db_module

import pg_raw


async def _init_clean_db() -> None:
    await db_module.init_db()


async def test_add_audit_event_populates_chain():
    await _init_clean_db()

    id1 = await db_module.add_audit_event("auth", "login.success", "alice")
    id2 = await db_module.add_audit_event("auth", "login.success", "bob")
    id3 = await db_module.add_audit_event("config", "playbook.create", "alice")

    conn = await db_module.get_db()
    try:
        cursor = await conn.execute("SELECT id, prev_hash, row_hash FROM audit_events ORDER BY id ASC")
        rows = await cursor.fetchall()
    finally:
        await conn.close()

    assert [r[0] for r in rows] == [id1, id2, id3]
    # First row: prev_hash empty, row_hash non-empty.
    assert rows[0][1] == ""
    assert rows[0][2] != ""
    # Each subsequent prev_hash equals the previous row_hash.
    assert rows[1][1] == rows[0][2]
    assert rows[2][1] == rows[1][2]
    # All row_hashes look like sha256 hex.
    for _id, _prev, rh in rows:
        assert len(rh) == 64
        int(rh, 16)


async def test_verify_audit_chain_clean():
    await _init_clean_db()

    for i in range(5):
        await db_module.add_audit_event("auth", "login.success", f"user{i}")

    result = await db_module.verify_audit_chain()
    assert result == {
        "ok": True,
        "total_rows": 5,
        "first_break_id": None,
        "first_break_reason": None,
    }


async def test_verify_audit_chain_empty_db():
    await _init_clean_db()
    result = await db_module.verify_audit_chain()
    assert result["ok"] is True
    assert result["total_rows"] == 0


async def test_verify_audit_chain_detects_tamper():
    await _init_clean_db()

    await db_module.add_audit_event("auth", "login.success", "alice")
    id2 = await db_module.add_audit_event("auth", "login.success", "bob")
    await db_module.add_audit_event("config", "playbook.create", "alice")

    # Tamper via a raw connection (bypassing the trigger requires dropping it first).
    conn = await pg_raw.connect()
    try:
        await conn.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
        await conn.execute("UPDATE audit_events SET detail = 'tampered' WHERE id = $1", id2)
    finally:
        await conn.close()

    result = await db_module.verify_audit_chain()
    assert result["ok"] is False
    # The mutated row's stored row_hash no longer matches its recomputed hash.
    assert result["first_break_id"] == id2
    assert result["first_break_reason"] == "row_hash_mismatch"


async def test_verify_audit_chain_detects_deletion():
    await _init_clean_db()

    await db_module.add_audit_event("auth", "login.success", "alice")
    id2 = await db_module.add_audit_event("auth", "login.success", "bob")
    id3 = await db_module.add_audit_event("config", "playbook.create", "alice")

    conn = await pg_raw.connect()
    try:
        await conn.execute("DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events")
        await conn.execute("DELETE FROM audit_events WHERE id = $1", id2)
    finally:
        await conn.close()

    result = await db_module.verify_audit_chain()
    assert result["ok"] is False
    # Row id3's stored prev_hash points at the deleted id2's row_hash,
    # which no longer matches the recomputed expected prev (row1's hash).
    assert result["first_break_id"] == id3
    assert result["first_break_reason"] == "prev_hash_mismatch"


async def test_update_trigger_blocks_raw_update():
    await _init_clean_db()
    audit_id = await db_module.add_audit_event("auth", "login.success", "alice")

    with pytest.raises(asyncpg.PostgresError, match="audit immutable"):
        await pg_raw.execute("UPDATE audit_events SET detail = 'oops' WHERE id = $1", audit_id)


async def test_delete_trigger_blocks_raw_delete():
    await _init_clean_db()
    audit_id = await db_module.add_audit_event("auth", "login.success", "alice")

    with pytest.raises(asyncpg.PostgresError, match="audit immutable"):
        await pg_raw.execute("DELETE FROM audit_events WHERE id = $1", audit_id)


async def test_backfill_produces_clean_chain():
    """Insert rows directly (no chain), then run migration, then verify."""
    # Stand up the schema, then drop the v37 triggers and forget the
    # migration so re-running init_db() has backfill work to do.
    await db_module.init_db()
    conn = await pg_raw.connect()
    try:
        await conn.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
        await conn.execute("DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events")
        await conn.execute("DELETE FROM schema_migrations WHERE version = 37")
        # Wipe the chain columns to simulate a pre-migration DB.
        await conn.execute("UPDATE audit_events SET prev_hash = '', row_hash = ''")
        # Insert a few rows with NO chain values.
        for i in range(3):
            await conn.execute(
                "INSERT INTO audit_events "
                '(timestamp, category, action, "user", detail, correlation_id) '
                "VALUES ($1, $2, $3, $4, $5, $6)",
                f"2026-01-0{i + 1} 00:00:00",
                "auth",
                "login.success",
                f"user{i}",
                "",
                "",
            )

        # Sanity: rows exist with empty chain columns.
        rows = await conn.fetch("SELECT id, prev_hash, row_hash FROM audit_events ORDER BY id ASC")
        assert len(rows) == 3
        assert all(r["prev_hash"] == "" and r["row_hash"] == "" for r in rows)
    finally:
        await conn.close()

    # Re-run init_db; the migration re-applies and backfills.
    await db_module.init_db()

    # Verify the chain is now clean.
    result = await db_module.verify_audit_chain()
    assert result["ok"] is True
    assert result["total_rows"] == 3

    # Sanity: each prev_hash links to the previous row_hash.
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute("SELECT id, prev_hash, row_hash FROM audit_events ORDER BY id ASC")
        rows = await cursor.fetchall()
    finally:
        await conn.close()
    assert rows[0][1] == ""
    assert rows[1][1] == rows[0][2]
    assert rows[2][1] == rows[1][2]


async def test_row_hash_matches_canonical_formula():
    """add_audit_event must compute the same hash an external observer
    would compute from the canonical row bytes."""
    await _init_clean_db()

    await db_module.add_audit_event(
        category="auth",
        action="login.success",
        user="alice",
        detail="from 10.0.0.1",
        correlation_id="cid-abc",
    )

    conn = await db_module.get_db()
    try:
        cursor = await conn.execute(
            'SELECT timestamp, category, action, "user", detail, correlation_id, '
            "prev_hash, row_hash FROM audit_events ORDER BY id ASC LIMIT 1"
        )
        row = await cursor.fetchone()
    finally:
        await conn.close()

    ts, cat, act, usr, det, corr, prev, stored = row
    canonical = "\x00".join([ts, cat, act, usr, det, corr, prev]).encode("utf-8")
    expected = hashlib.sha256(canonical).hexdigest()
    assert stored == expected
