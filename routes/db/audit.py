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

import aiosqlite

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "set_audit_event_hook",
    "verify_audit_chain",
    "add_audit_event",
    "get_audit_events",
]

# ═════════════════════════════════════════════════════════════════════════════
# Audit Events
# ═════════════════════════════════════════════════════════════════════════════


# Serializes audit-event inserts within this process so concurrent writers
# cannot fork the hash chain. On Postgres an advisory lock (below) extends
# the same guarantee across worker processes.
_audit_chain_lock = asyncio.Lock()

# Session-scoped Postgres advisory lock key for chain writes. The asyncio
# lock above cannot stop a second worker process from reading the same
# chain tail; every writer takes this advisory lock around the tail-read +
# insert instead. Session-scoped (not xact-scoped) because the compat
# layer runs autocommit, so there is no surrounding transaction to bind an
# xact lock to. asyncpg's pool reset releases advisory locks when the
# connection is returned, so a dropped connection cannot strand the lock.
_AUDIT_CHAIN_PG_LOCK_KEY = 0x506C_6578_4155_4454  # "PlexAUDT"


# Optional async hook fired after every successful audit insert. The SIEM
# forwarder registers itself here via ``set_audit_event_hook`` at app
# startup. The hook is fire-and-forget - exceptions never propagate to the
# caller, so a wedged SIEM cannot block audit writes.
_audit_event_hook = None  # type: ignore[var-annotated]


def set_audit_event_hook(hook) -> None:
    """Register a coroutine fn(event: dict) -> None called after each insert.

    Pass ``None`` to clear. Tests and the SIEM forwarder are the only
    expected callers.
    """
    global _audit_event_hook
    _audit_event_hook = hook




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
        _audit_canonical_bytes(
            timestamp, category, action, user, detail, correlation_id, prev_hash
        )
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
        rows = await cursor.fetchall()
    finally:
        await conn.close()

    expected_prev = ""
    total = 0
    for row in rows:
        row_id = row[0]
        ts = row[1] if isinstance(row[1], str) else str(row[1])
        cat, act, usr, det, corr, stored_prev, stored_hash = (
            row[2], row[3], row[4], row[5], row[6], row[7], row[8]
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
        pg_locked = False
        try:
            if _dbcore.DB_ENGINE == "postgres":
                await conn.execute(
                    "SELECT pg_advisory_lock(?)", (_AUDIT_CHAIN_PG_LOCK_KEY,)
                )
                pg_locked = True
            cursor = await conn.execute(
                "SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            )
            tail = await cursor.fetchone()
            prev_hash = (tail[0] if tail else "") or ""

            row_hash = _audit_row_hash(
                timestamp, category, action, user, detail, correlation_id, prev_hash
            )

            cursor = await conn.execute(
                """INSERT INTO audit_events
                   (timestamp, category, action, "user", detail, correlation_id,
                    prev_hash, row_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    timestamp, category, action, user, detail, correlation_id,
                    prev_hash, row_hash,
                ),
            )
            new_id = cursor.lastrowid
            await conn.commit()
        finally:
            if pg_locked:
                try:
                    await conn.execute(
                        "SELECT pg_advisory_unlock(?)", (_AUDIT_CHAIN_PG_LOCK_KEY,)
                    )
                except Exception:
                    _LOGGER.warning(
                        "audit chain: failed to release pg advisory lock; "
                        "pool reset will reclaim it"
                    )
            await conn.close()

    if _audit_event_hook is not None:
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
        try:
            await _audit_event_hook(event)
        except Exception as exc:
            # Forwarding must never break audit ingestion. The DB row is
            # already committed; downstream observability is best-effort —
            # but a dropped event must not be invisible.
            _LOGGER.warning(
                "audit hook dropped event id=%s category=%s action=%s: %s",
                new_id, category, action, type(exc).__name__,
            )
    return new_id


async def get_audit_events(
    limit: int = 100,
    category: str | None = None,
) -> list[dict]:
    """Return recent audit events, optionally filtered by category."""
    conn = await _dbcore.get_db()
    try:
        if category:
            cursor = await conn.execute(
                "SELECT * FROM audit_events WHERE category = ? ORDER BY id DESC LIMIT ?",
                (category, limit),
            )
        else:
            cursor = await conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()


