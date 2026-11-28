"""Audit persistence helpers.

Split out of routes/database.py; star re-exported there so the
``routes.database`` facade keeps its full public surface.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
from datetime import UTC, datetime, timedelta

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "set_audit_event_hook",
    "add_audit_event_hook",
    "remove_audit_event_hook",
    "verify_audit_chain",
    "add_audit_event",
    "get_audit_events",
]

# ═════════════════════════════════════════════════════════════════════════════
# Audit Events
# ═════════════════════════════════════════════════════════════════════════════


# Serializes audit-event inserts within this process. The advisory lock
# below is what keeps the chain linear; this lock queues this process's
# writers in memory, so N concurrent audit writes hold one pooled
# connection instead of N connections all blocked on the advisory lock.
_audit_chain_lock = asyncio.Lock()

# Postgres advisory lock key for chain writes, so writers in other processes
# cannot read the same chain tail. Normally taken transaction-scoped
# (``pg_advisory_xact_lock``) inside the transaction that inserts the row,
# so COMMIT or ROLLBACK releases it with no unlock round trip and the next
# writer reads the tail only after this row is committed. When the caller
# already has a transaction open on the connection, that transaction may
# outlive this function, so the session lock is taken and released
# explicitly instead.
_AUDIT_CHAIN_PG_LOCK_KEY = 0x506C_6578_4155_4454  # "PlexAUDT"


# Optional async hooks fired after every successful audit insert. The SIEM
# forwarder registers itself in the primary slot via ``set_audit_event_hook``
# at app startup; other subscribers add themselves to the list with
# ``add_audit_event_hook``. Hooks are fire-and-forget - exceptions never
# propagate to the caller, so a wedged SIEM cannot block audit writes, and
# one failing hook does not stop the others.
_audit_event_hook = None  # type: ignore[var-annotated]
_audit_event_hooks: list = []


def set_audit_event_hook(hook) -> None:
    """Register a coroutine fn(event: dict) -> None called after each insert.

    Replaces the primary slot only (the SIEM forwarder); pass ``None`` to
    clear it. Hooks added with ``add_audit_event_hook`` are untouched.
    """
    global _audit_event_hook
    _audit_event_hook = hook


def add_audit_event_hook(hook) -> None:
    """Add another subscriber; adding the same hook twice is a no-op."""
    if not any(h is hook for h in _audit_event_hooks):
        _audit_event_hooks.append(hook)


def remove_audit_event_hook(hook) -> None:
    _audit_event_hooks[:] = [h for h in _audit_event_hooks if h is not hook]


def _audit_canonical_bytes(
    timestamp: str,
    category: str,
    action: str,
    user: str,
    detail: str,
    correlation_id: str,
    prev_hash: str,
) -> bytes:
    """Stable byte serialization of an audit row for hashing. Matches the
    backfill in migration 0037 and verify_audit_chain. NUL-separated so
    cross-field injection is impossible.
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


def _audit_row_hash(
    timestamp: str,
    category: str,
    action: str,
    user: str,
    detail: str,
    correlation_id: str,
    prev_hash: str,
) -> str:
    return hashlib.sha256(
        _audit_canonical_bytes(timestamp, category, action, user, detail, correlation_id, prev_hash)
    ).hexdigest()


async def verify_audit_chain() -> dict:
    """Walk audit_events in id ASC and verify every prev_hash/row_hash.

    Returns a dict with:
      - ``ok`` (bool)
      - ``total_rows`` (int)
      - ``first_break_id`` (int or None)
      - ``first_break_reason`` (str or None) - ``"row_hash_mismatch"`` or
        ``"prev_hash_mismatch"``
    """
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            'SELECT id, timestamp, category, action, "user", '
            "COALESCE(detail, ''), COALESCE(correlation_id, ''), "
            "prev_hash, row_hash "
            "FROM audit_events ORDER BY id ASC"
        )

        # Stream in batches rather than materializing the entire audit_events
        # table: the chain is verified sequentially, so we only need a window
        # at a time. This keeps memory bounded as the log grows to millions of
        # rows.
        expected_prev = ""
        total = 0
        _BATCH = 2000
        while True:
            rows = await cursor.fetchmany(_BATCH)
            if not rows:
                break
            for row in rows:
                row_id = row[0]
                ts = row[1] if isinstance(row[1], str) else str(row[1])
                cat, act, usr, det, corr, stored_prev, stored_hash = (
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                    row[6],
                    row[7],
                    row[8],
                )
                total += 1

                if (stored_prev or "") != expected_prev:
                    return {
                        "ok": False,
                        "total_rows": total,
                        "first_break_id": row_id,
                        "first_break_reason": "prev_hash_mismatch",
                    }

                recomputed = _audit_row_hash(ts, cat, act, usr, det, corr, stored_prev or "")
                if recomputed != (stored_hash or ""):
                    return {
                        "ok": False,
                        "total_rows": total,
                        "first_break_id": row_id,
                        "first_break_reason": "row_hash_mismatch",
                    }
                expected_prev = stored_hash or ""
    finally:
        await conn.close()

    return {
        "ok": True,
        "total_rows": total,
        "first_break_id": None,
        "first_break_reason": None,
    }


async def add_audit_event(
    category: str,
    action: str,
    user: str = "",
    detail: str = "",
    correlation_id: str = "",
) -> int:
    """Insert an immutable audit record and return its ID.

    Serializes against ``_audit_chain_lock`` so concurrent inserts cannot
    fork the hash chain. The hash covers (timestamp, category, action,
    user, detail, correlation_id, prev_hash); ``id`` is intentionally
    excluded so the row can be inserted with row_hash already populated.
    Chain integrity rests on the prev_hash linkage, which detects any
    insertion, deletion, or reordering of earlier rows.
    """
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

    async with _audit_chain_lock:
        conn = await _dbcore.get_db()
        # See _AUDIT_CHAIN_PG_LOCK_KEY for why the lock scope depends on this.
        session_lock = conn.in_transaction
        pg_locked = False
        try:
            # One unit: BEGIN, lock, tail read, insert, COMMIT with no
            # per-statement savepoints. The lock and the tail read must be
            # separate statements: a statement's snapshot is taken before
            # it waits for the lock, so a combined one could read a stale tail.
            async with conn.atomic():
                if session_lock:
                    await conn.execute("SELECT pg_advisory_lock(?)", (_AUDIT_CHAIN_PG_LOCK_KEY,))
                    pg_locked = True
                else:
                    await conn.execute("SELECT pg_advisory_xact_lock(?)", (_AUDIT_CHAIN_PG_LOCK_KEY,))
                cursor = await conn.execute("SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1")
                tail = await cursor.fetchone()
                prev_hash = (tail[0] if tail else "") or ""

                row_hash = _audit_row_hash(timestamp, category, action, user, detail, correlation_id, prev_hash)

                cursor = await conn.execute(
                    """INSERT INTO audit_events
                       (timestamp, category, action, "user", detail, correlation_id,
                        prev_hash, row_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        timestamp,
                        category,
                        action,
                        user,
                        detail,
                        correlation_id,
                        prev_hash,
                        row_hash,
                    ),
                )
                new_id = cursor.lastrowid
            await conn.commit()
        finally:
            if pg_locked:
                try:
                    await conn.execute("SELECT pg_advisory_unlock(?)", (_AUDIT_CHAIN_PG_LOCK_KEY,))
                except Exception:
                    _LOGGER.warning("audit chain: failed to release pg advisory lock; pool reset will reclaim it")
            await conn.close()

    hooks = ([_audit_event_hook] if _audit_event_hook is not None else []) + list(_audit_event_hooks)
    if hooks:
        event = {
            "id": new_id,
            "timestamp": timestamp,
            "category": category,
            "action": action,
            "user": user,
            "detail": detail,
            "correlation_id": correlation_id,
            "prev_hash": prev_hash,
            "row_hash": row_hash,
        }
        for hook in hooks:
            try:
                await hook(dict(event))
            except Exception as exc:
                # Forwarding must never break audit ingestion. The DB row is
                # already committed; downstream observability is best-effort —
                # but a dropped event must not be invisible.
                _LOGGER.warning(
                    "audit hook dropped event id=%s category=%s action=%s: %s",
                    new_id,
                    category,
                    action,
                    type(exc).__name__,
                )
    return new_id


async def get_audit_events(
    limit: int = 100,
    category: str | None = None,
    *,
    user: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[dict]:
    """Return recent audit events, newest first, optionally filtered by
    category, by user, and by time (``since`` / ``until`` inclusive, UTC
    ``YYYY-MM-DD HH:MM:SS`` text as stored)."""
    clauses: list[str] = []
    params: list = []
    for clause, value in (
        ("category = ?", category),
        ('"user" = ?', user),
        ("timestamp >= ?", since),
        ("timestamp <= ?", until),
    ):
        if value:
            clauses.append(clause)
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?",  # nosec B608 - fixed clauses
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()
