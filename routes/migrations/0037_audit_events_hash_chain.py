"""
Migration 0037: Tamper-evident audit log via hash chaining.

Adds two columns to ``audit_events``:

* ``prev_hash`` - the ``row_hash`` of the previous row (empty for the first
  row). Forms a chain so any earlier mutation invalidates everything after
  it.
* ``row_hash`` - sha256 over the canonical row bytes (id, timestamp,
  category, action, user, detail, correlation_id, prev_hash).

Backfills both columns over existing rows in a single transaction, walking
id ASC so each row's prev_hash matches the previous row's row_hash.

Adds BEFORE UPDATE and BEFORE DELETE triggers that abort with
``audit immutable``. The application must only insert; verification of the
chain happens via :func:`routes.database.verify_audit_chain`.
"""

from __future__ import annotations

import hashlib
import os

VERSION = 37
DESCRIPTION = "Hash-chain audit_events and block UPDATE/DELETE via triggers"

DB_ENGINE = os.getenv("APP_DB_ENGINE", "sqlite").strip().lower() or "sqlite"


def _canonical_row_bytes(
    timestamp: str,
    category: str,
    action: str,
    user: str,
    detail: str,
    correlation_id: str,
    prev_hash: str,
) -> bytes:
    """Stable serialization for hashing - must match
    ``routes.database._audit_canonical_bytes``. NUL-separated to make
    cross-field injection impossible. ``id`` is intentionally excluded so
    the application can write row_hash atomically with the INSERT;
    chain integrity rests on the prev_hash linkage.
    """
    parts = [
        timestamp or "",
        category or "",
        action or "",
        user or "",
        detail or "",
        correlation_id or "",
        prev_hash or "",
    ]
    return "\x00".join(parts).encode("utf-8")


def _compute_row_hash(
    timestamp: str,
    category: str,
    action: str,
    user: str,
    detail: str,
    correlation_id: str,
    prev_hash: str,
) -> str:
    return hashlib.sha256(
        _canonical_row_bytes(
            timestamp, category, action, user, detail, correlation_id, prev_hash
        )
    ).hexdigest()


# ── SQLite ──────────────────────────────────────────────────────────────────

async def _column_exists_sqlite(db, table: str, column: str) -> bool:
    cursor = await db.execute(f"PRAGMA table_info({table})")
    rows = await cursor.fetchall()
    return any(r[1] == column for r in rows)


async def _up_sqlite(db) -> None:
    if not await _column_exists_sqlite(db, "audit_events", "prev_hash"):
        await db.execute(
            "ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"
        )
    if not await _column_exists_sqlite(db, "audit_events", "row_hash"):
        await db.execute(
            "ALTER TABLE audit_events ADD COLUMN row_hash TEXT NOT NULL DEFAULT ''"
        )

    # Backfill in id ASC so each prev_hash matches the previous row_hash.
    cursor = await db.execute(
        'SELECT id, timestamp, category, action, "user", detail, correlation_id '
        "FROM audit_events ORDER BY id ASC"
    )
    rows = await cursor.fetchall()

    prev_hash = ""
    for row in rows:
        row_id, ts, cat, act, usr, det, corr = (
            row[0], row[1], row[2], row[3], row[4], row[5], row[6]
        )
        rh = _compute_row_hash(ts, cat, act, usr, det, corr, prev_hash)
        await db.execute(
            "UPDATE audit_events SET prev_hash = ?, row_hash = ? WHERE id = ?",
            (prev_hash, rh, row_id),
        )
        prev_hash = rh

    # Triggers - block UPDATE and DELETE outright. Inserts are allowed.
    await db.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
    await db.execute(
        """
        CREATE TRIGGER audit_events_no_update
        BEFORE UPDATE ON audit_events
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'audit immutable');
        END
        """
    )
    await db.execute("DROP TRIGGER IF EXISTS audit_events_no_delete")
    await db.execute(
        """
        CREATE TRIGGER audit_events_no_delete
        BEFORE DELETE ON audit_events
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'audit immutable');
        END
        """
    )
    await db.commit()


# ── Postgres ────────────────────────────────────────────────────────────────

async def _up_postgres(db) -> None:
    # IF NOT EXISTS for idempotency on re-runs of partially-applied migrations.
    await db.execute(
        "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT ''"
    )
    await db.execute(
        "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS row_hash TEXT NOT NULL DEFAULT ''"
    )

    cursor = await db.execute(
        'SELECT id, timestamp::text, category, action, "user", '
        "COALESCE(detail, ''), COALESCE(correlation_id, '') "
        "FROM audit_events ORDER BY id ASC"
    )
    rows = await cursor.fetchall()

    prev_hash = ""
    for row in rows:
        row_id, ts, cat, act, usr, det, corr = (
            row[0], row[1], row[2], row[3], row[4], row[5], row[6]
        )
        rh = _compute_row_hash(ts, cat, act, usr, det, corr, prev_hash)
        await db.execute(
            "UPDATE audit_events SET prev_hash = ?, row_hash = ? WHERE id = ?",
            (prev_hash, rh, row_id),
        )
        prev_hash = rh

    # Trigger function + triggers. RAISE EXCEPTION aborts the surrounding
    # transaction so both single-statement and multi-statement attempts fail.
    await db.execute(
        """
        CREATE OR REPLACE FUNCTION audit_events_block_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'audit immutable';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    await db.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
    await db.execute(
        """
        CREATE TRIGGER audit_events_no_update
        BEFORE UPDATE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_events_block_mutation()
        """
    )
    await db.execute("DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events")
    await db.execute(
        """
        CREATE TRIGGER audit_events_no_delete
        BEFORE DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_events_block_mutation()
        """
    )
    await db.commit()


async def up(db) -> None:
    if DB_ENGINE == "postgres":
        await _up_postgres(db)
    else:
        await _up_sqlite(db)
