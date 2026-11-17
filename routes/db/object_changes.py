"""Per-object change log persistence (migration 0095).

One ``object_changes`` row per structured object-change event
(``routes.db.change_events``). The recorder that writes them, its secret
masking and the access rules of the API live in
``netcontrol.routes.object_changes``; this module only stores, lists and
prunes rows.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as _dbcore
from routes.database import rows_to_list
from routes.db.inventory import group_ids_condition

__all__ = [
    "OBJECT_CHANGE_TIME_FORMAT",
    "add_object_change",
    "list_object_changes",
    "prune_object_changes",
]

OBJECT_CHANGE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

_SELECT_COLUMNS = (
    "id, object_type, object_id, object_label, action, username, correlation_id, changed_at,"
    " scope_group_id, changes_json, before_json, after_json"
)


def _dump(value: Any) -> str | None:
    return None if value is None else json.dumps(value, separators=(",", ":"), default=str)


def _load(value: str | None) -> Any:
    if value is None or value == "":
        return None
    try:
        return json.loads(value)
    except ValueError:
        return None


def _row(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "object_type": row["object_type"],
        "object_id": row["object_id"],
        "object_label": row.get("object_label") or "",
        "action": row["action"],
        "user": row.get("username") or "",
        "correlation_id": row.get("correlation_id") or "",
        "changed_at": row.get("changed_at") or "",
        "changes": _load(row.get("changes_json")) or {},
        "before": _load(row.get("before_json")),
        "after": _load(row.get("after_json")),
    }


async def add_object_change(
    *,
    object_type: str,
    object_id: str,
    action: str,
    changed_at: str,
    user: str = "",
    object_label: str = "",
    correlation_id: str = "",
    scope_group_id: int | None = None,
    changes: dict | None = None,
    before: dict | None = None,
    after: dict | None = None,
) -> int:
    """Store one change; returns its id. ``changed_at`` is UTC
    ``OBJECT_CHANGE_TIME_FORMAT`` text."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO object_changes
               (object_type, object_id, object_label, action, username, correlation_id, changed_at,
                scope_group_id, changes_json, before_json, after_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            (
                object_type,
                str(object_id),
                object_label[:255],
                action,
                user,
                correlation_id[:128],
                changed_at,
                scope_group_id,
                _dump(changes or {}),
                _dump(before),
                _dump(after),
            ),
        )
        new_id = int(cursor.lastrowid or 0)
        await db.commit()
        return new_id
    finally:
        await db.close()


async def list_object_changes(
    *,
    object_types: Iterable[str],
    object_id: str | None = None,
    object_label: str | None = None,
    user: str | None = None,
    action: str | None = None,
    since: str | None = None,
    until: str | None = None,
    group_ids: Iterable[int] | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """The changes of ``object_types`` (newest first) matching the filters,
    and how many match in all. ``since``/``until`` are inclusive
    ``OBJECT_CHANGE_TIME_FORMAT`` bounds. ``group_ids`` (object-level
    permissions) keeps only rows whose ``scope_group_id`` is one of them;
    ``None`` keeps every row."""
    types = sorted(set(object_types))
    if not types:
        return [], 0
    where = [f"object_type IN ({','.join('?' * len(types))})"]
    params: list[Any] = list(types)
    for column, value in (
        ("object_id", object_id),
        ("object_label", object_label),
        ("username", user),
        ("action", action),
    ):
        if value is not None and value != "":
            where.append(f"{column} = ?")
            params.append(str(value))
    if since:
        where.append("changed_at >= ?")
        params.append(since)
    if until:
        where.append("changed_at <= ?")
        params.append(until)
    scope_sql, scope_params = group_ids_condition("scope_group_id", group_ids)
    if scope_sql:
        where.append(scope_sql)
        params.extend(scope_params)
    clause = " AND ".join(where)
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT COUNT(*) FROM object_changes WHERE {clause}",  # nosec B608 - fixed columns, placeholders only
            tuple(params),
        )
        count_row = await cursor.fetchone()
        total = int(count_row[0] or 0) if count_row else 0
        cursor = await db.execute(
            f"SELECT {_SELECT_COLUMNS} FROM object_changes WHERE {clause}"  # nosec B608 - fixed columns, placeholders only
            " ORDER BY changed_at DESC, id DESC LIMIT ? OFFSET ?",
            (*params, max(1, int(limit)), max(0, int(offset))),
        )
        rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    return [_row(r) for r in rows], total


async def prune_object_changes(retention_days: int) -> int:
    """Delete changes older than ``retention_days``; returns how many."""
    cutoff = (datetime.now(UTC) - timedelta(days=max(1, int(retention_days)))).strftime(OBJECT_CHANGE_TIME_FORMAT)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM object_changes WHERE changed_at < ?", (cutoff,))
        await db.commit()
        return int(cursor.rowcount or 0)
    finally:
        await db.close()
