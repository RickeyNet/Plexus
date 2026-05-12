"""Tests for the audit_events hash chain (migration 0037).

Covers:
  * add_audit_event populates prev_hash/row_hash and links rows correctly
  * verify_audit_chain accepts a clean chain and rejects a mutated one
  * SQLite triggers block raw UPDATE and DELETE against audit_events
  * Migration backfill produces a chain that verifies clean
"""
from __future__ import annotations

import hashlib
import sqlite3

import pytest
import routes.database as db_module


async def _init_clean_db(tmp_path, monkeypatch) -> str:
    db_path = str(tmp_path / "audit.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


async def test_add_audit_event_populates_chain(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)

    id1 = await db_module.add_audit_event("auth", "login.success", "alice")
    id2 = await db_module.add_audit_event("auth", "login.success", "bob")
    id3 = await db_module.add_audit_event("config", "playbook.create", "alice")

    conn = await db_module.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, prev_hash, row_hash FROM audit_events ORDER BY id ASC"
        )
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


async def test_verify_audit_chain_clean(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)

    for i in range(5):
        await db_module.add_audit_event("auth", "login.success", f"user{i}")

    result = await db_module.verify_audit_chain()
    assert result == {
        "ok": True,
        "total_rows": 5,
        "first_break_id": None,
        "first_break_reason": None,
    }


async def test_verify_audit_chain_empty_db(tmp_path, monkeypatch):
    await _init_clean_db(tmp_path, monkeypatch)
    result = await db_module.verify_audit_chain()
    assert result["ok"] is True
    assert result["total_rows"] == 0


async def test_verify_audit_chain_detects_tamper(tmp_path, monkeypatch):
    db_path = await _init_clean_db(tmp_path, monkeypatch)

    await db_module.add_audit_event("auth", "login.success", "alice")
    id2 = await db_module.add_audit_event("auth", "login.success", "bob")
    await db_module.add_audit_event("config", "playbook.create", "alice")

    # Tamper via raw sqlite3 (bypassing triggers requires DROPping first).
    raw = sqlite3.connect(db_path)
    try:
        raw.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        raw.execute(
            "UPDATE audit_events SET detail = 'tampered' WHERE id = ?", (id2,)
        )
        raw.commit()
    finally:
        raw.close()

    result = await db_module.verify_audit_chain()
    assert result["ok"] is False
    # The mutated row's stored row_hash no longer matches its recomputed hash.
    assert result["first_break_id"] == id2
    assert result["first_break_reason"] == "row_hash_mismatch"


async def test_verify_audit_chain_detects_deletion(tmp_path, monkeypatch):
    db_path = await _init_clean_db(tmp_path, monkeypatch)

    await db_module.add_audit_event("auth", "login.success", "alice")
    id2 = await db_module.add_audit_event("auth", "login.success", "bob")
    id3 = await db_module.add_audit_event("config", "playbook.create", "alice")

    raw = sqlite3.connect(db_path)
    try:
        raw.execute("DROP TRIGGER IF EXISTS audit_events_no_delete")
        raw.execute("DELETE FROM audit_events WHERE id = ?", (id2,))
        raw.commit()
    finally:
        raw.close()

    result = await db_module.verify_audit_chain()
    assert result["ok"] is False
    # Row id3's stored prev_hash points at the deleted id2's row_hash,
    # which no longer matches the recomputed expected prev (row1's hash).
    assert result["first_break_id"] == id3
    assert result["first_break_reason"] == "prev_hash_mismatch"


async def test_update_trigger_blocks_raw_update(tmp_path, monkeypatch):
    db_path = await _init_clean_db(tmp_path, monkeypatch)
    await db_module.add_audit_event("auth", "login.success", "alice")

    raw = sqlite3.connect(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="audit immutable"):
            raw.execute("UPDATE audit_events SET detail = 'oops' WHERE id = 1")
    finally:
        raw.close()


async def test_delete_trigger_blocks_raw_delete(tmp_path, monkeypatch):
    db_path = await _init_clean_db(tmp_path, monkeypatch)
    await db_module.add_audit_event("auth", "login.success", "alice")

    raw = sqlite3.connect(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="audit immutable"):
            raw.execute("DELETE FROM audit_events WHERE id = 1")
    finally:
        raw.close()


async def test_backfill_produces_clean_chain(tmp_path, monkeypatch):
    """Insert rows directly (no chain), then run migration, then verify."""
    db_path = str(tmp_path / "backfill.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)

    # Stand up the schema WITHOUT running migrations yet by hitting
    # init_db() then dropping the v37 columns/triggers so the migration
    # has work to do.
    await db_module.init_db()
    raw = sqlite3.connect(db_path)
    try:
        raw.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        raw.execute("DROP TRIGGER IF EXISTS audit_events_no_delete")
        raw.execute("DELETE FROM schema_migrations WHERE version = 37")
        # Wipe the chain columns to simulate a pre-migration DB.
        raw.execute("UPDATE audit_events SET prev_hash = '', row_hash = ''")
        # Insert a few rows with NO chain values.
        for i in range(3):
            raw.execute(
                'INSERT INTO audit_events '
                '(timestamp, category, action, "user", detail, correlation_id) '
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    f"2026-01-0{i+1} 00:00:00",
                    "auth",
                    "login.success",
                    f"user{i}",
                    "",
                    "",
                ),
            )
        raw.commit()

        # Sanity: rows exist with empty chain columns.
        rows = raw.execute(
            "SELECT id, prev_hash, row_hash FROM audit_events ORDER BY id ASC"
        ).fetchall()
        assert len(rows) == 3
        assert all(r[1] == "" and r[2] == "" for r in rows)
    finally:
        raw.close()

    # Re-run init_db; the migration re-applies and backfills.
    await db_module.init_db()

    # Verify the chain is now clean.
    result = await db_module.verify_audit_chain()
    assert result["ok"] is True
    assert result["total_rows"] == 3

    # Sanity: each prev_hash links to the previous row_hash.
    conn = await db_module.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, prev_hash, row_hash FROM audit_events ORDER BY id ASC"
        )
        rows = await cursor.fetchall()
    finally:
        await conn.close()
    assert rows[0][1] == ""
    assert rows[1][1] == rows[0][2]
    assert rows[2][1] == rows[1][2]


async def test_row_hash_matches_canonical_formula(tmp_path, monkeypatch):
    """add_audit_event must compute the same hash an external observer
    would compute from the canonical row bytes."""
    await _init_clean_db(tmp_path, monkeypatch)

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
