"""Outbound event webhook persistence (migration 0092).

``webhooks`` holds the subscriptions and ``webhook_deliveries`` one row per
delivery attempt. Encryption of the secret and the header map, validation and
everything about sending live in ``netcontrol.routes.webhooks``; this module
stores and returns rows as they are (``*_enc`` columns included), so callers
outside that module must not hand a raw row to a client.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import routes.database as _dbcore
from routes.database import _is_unique_violation, _safe_dynamic_update, row_to_dict, rows_to_list

__all__ = [
    "WEBHOOK_COLUMNS",
    "list_webhooks",
    "get_webhook",
    "create_webhook",
    "update_webhook",
    "delete_webhook",
    "add_webhook_delivery",
    "list_webhook_deliveries",
    "get_webhook_delivery",
    "last_webhook_delivery_attempt",
    "prune_webhook_deliveries",
]

_FMT = "%Y-%m-%d %H:%M:%S"

# Columns a caller may set; ``id`` and the timestamps are managed here.
WEBHOOK_COLUMNS: tuple[str, ...] = (
    "name",
    "enabled",
    "url",
    "http_method",
    "content_type",
    "object_types_json",
    "actions_json",
    "filters_json",
    "headers_enc",
    "body_template",
    "secret_enc",
    "verify_tls",
    "ca_bundle",
    "timeout_seconds",
    "max_retries",
    "concurrency",
)


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def _taken(name: str) -> ValueError:
    return ValueError(f"A webhook named '{name}' already exists.")


async def list_webhooks() -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM webhooks ORDER BY lower(name), id")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_webhook(webhook_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM webhooks WHERE id = ?", (int(webhook_id),))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_webhook(values: dict, created_by: str = "") -> dict:
    """Insert a webhook from ``values`` (keys of ``WEBHOOK_COLUMNS``).
    Raises ``ValueError`` when the name is taken."""
    cols = [c for c in WEBHOOK_COLUMNS if c in values]
    now = _now()
    names = [*cols, "created_by", "created_at", "updated_at"]
    params = [values[c] for c in cols] + [created_by, now, now]
    marks = ", ".join("?" for _ in names)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"INSERT INTO webhooks ({', '.join(names)}) VALUES ({marks}) RETURNING id",  # nosec B608 - fixed columns
            tuple(params),
        )
        new_id = int(cursor.lastrowid)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _taken(str(values.get("name", ""))) from exc
        raise
    finally:
        await db.close()
    row = await get_webhook(new_id)
    assert row is not None  # nosec B101 - just inserted
    return row


async def update_webhook(webhook_id: int, values: dict) -> dict | None:
    """Set the given ``WEBHOOK_COLUMNS``; ``None`` when the webhook does not
    exist. Raises ``ValueError`` when the new name is taken."""
    cols = [c for c in WEBHOOK_COLUMNS if c in values]
    exprs = [f"{c} = ?" for c in cols] + ["updated_at = ?"]
    sql, params = _safe_dynamic_update(
        "webhooks", exprs, [values[c] for c in cols] + [_now()], "id = ?", int(webhook_id)
    )
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        found = (cursor.rowcount or 0) > 0
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _taken(str(values.get("name", ""))) from exc
        raise
    finally:
        await db.close()
    return await get_webhook(webhook_id) if found else None


async def delete_webhook(webhook_id: int) -> bool:
    """Delete a webhook and (by cascade) its delivery log."""
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM webhook_deliveries WHERE webhook_id = ?", (int(webhook_id),))
        cursor = await db.execute("DELETE FROM webhooks WHERE id = ?", (int(webhook_id),))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def add_webhook_delivery(
    *,
    webhook_id: int,
    delivery_id: str,
    event: str,
    object_type: str,
    object_id: str,
    action: str,
    attempt: int,
    status: str,
    status_code: int | None,
    latency_ms: float | None,
    request_body: str,
    response_body: str,
    error: str,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO webhook_deliveries
               (webhook_id, delivery_id, event, object_type, object_id, action, attempt, status,
                status_code, latency_ms, request_body, response_body, error, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            (
                int(webhook_id),
                delivery_id,
                event,
                object_type,
                object_id,
                action,
                int(attempt),
                status,
                status_code,
                latency_ms,
                request_body,
                response_body,
                error,
                _now(),
            ),
        )
        new_id = int(cursor.lastrowid)
        await db.commit()
        return new_id
    finally:
        await db.close()


async def list_webhook_deliveries(webhook_id: int, limit: int = 100) -> list[dict]:
    """The newest attempts first, without the stored request body."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT id, webhook_id, delivery_id, event, object_type, object_id, action, attempt,
                      status, status_code, latency_ms, response_body, error, created_at
               FROM webhook_deliveries WHERE webhook_id = ? ORDER BY id DESC LIMIT ?""",
            (int(webhook_id), max(1, min(int(limit), 1000))),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_webhook_delivery(row_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM webhook_deliveries WHERE id = ?", (int(row_id),))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def last_webhook_delivery_attempt(delivery_id: str) -> int:
    """The highest attempt number logged for a delivery id (0 when none)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT COALESCE(MAX(attempt), 0) FROM webhook_deliveries WHERE delivery_id = ?", (delivery_id,)
        )
        row = await cursor.fetchone()
        return int(row[0] or 0) if row else 0
    finally:
        await db.close()


async def prune_webhook_deliveries(retention_days: int) -> int:
    """Delete delivery log rows older than ``retention_days``."""
    cutoff = (datetime.now(UTC) - timedelta(days=max(1, int(retention_days)))).strftime(_FMT)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM webhook_deliveries WHERE created_at < ?", (cutoff,))
        await db.commit()
        return int(cursor.rowcount or 0)
    finally:
        await db.close()
