"""Dynamic group persistence (migration 0097).

``dynamic_groups`` holds named, saved host filters. Validation of the filter
definition and resolution to hosts live in ``netcontrol.dynamic_groups``;
this module stores and returns rows, with ``filter`` decoded to a dict.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime

import routes.database as _dbcore
from routes.database import _is_unique_violation, _safe_dynamic_update, row_to_dict, rows_to_list
from routes.db.inventory import group_subtrees_sql

__all__ = [
    "list_dynamic_groups",
    "get_dynamic_group",
    "create_dynamic_group",
    "update_dynamic_group",
    "delete_dynamic_group",
    "get_group_subtree_ids",
    "find_object_keys_with_field",
]

_FMT = "%Y-%m-%d %H:%M:%S"


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def _taken(name: str) -> ValueError:
    return ValueError(f"A dynamic group named '{name}' already exists.")


def _decode(row: dict | None) -> dict | None:
    if row is None:
        return None
    raw = row.get("filter")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {}
    row["filter"] = raw if isinstance(raw, dict) else {}
    return row


async def list_dynamic_groups() -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM dynamic_groups ORDER BY lower(name), id")
        return [r for r in (_decode(row) for row in rows_to_list(await cursor.fetchall())) if r is not None]
    finally:
        await db.close()


async def get_dynamic_group(group_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM dynamic_groups WHERE id = ?", (int(group_id),))
        return _decode(row_to_dict(await cursor.fetchone()))
    finally:
        await db.close()


async def create_dynamic_group(
    *, name: str, description: str, filter_def: dict, created_by: str = "", object_type: str = "host"
) -> dict:
    """Insert a dynamic group. Raises ``ValueError`` when the name is taken
    (ignoring case)."""
    now = _now()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO dynamic_groups
               (name, description, object_type, filter, created_by, created_at, updated_at, updated_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            (name, description, object_type, json.dumps(filter_def), created_by, now, now, created_by),
        )
        new_id = int(cursor.lastrowid)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _taken(name) from exc
        raise
    finally:
        await db.close()
    row = await get_dynamic_group(new_id)
    assert row is not None  # nosec B101 - just inserted
    return row


async def update_dynamic_group(
    group_id: int,
    *,
    name: str | None = None,
    description: str | None = None,
    filter_def: dict | None = None,
    updated_by: str = "",
) -> dict | None:
    """Set the given values; ``None`` when the group does not exist. Raises
    ``ValueError`` when the new name is taken."""
    exprs: list[str] = []
    values: list = []
    if name is not None:
        exprs.append("name = ?")
        values.append(name)
    if description is not None:
        exprs.append("description = ?")
        values.append(description)
    if filter_def is not None:
        exprs.append("filter = ?")
        values.append(json.dumps(filter_def))
    exprs += ["updated_at = ?", "updated_by = ?"]
    values += [_now(), updated_by]
    sql, params = _safe_dynamic_update("dynamic_groups", exprs, values, "id = ?", int(group_id))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        found = (cursor.rowcount or 0) > 0
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _taken(str(name)) from exc
        raise
    finally:
        await db.close()
    return await get_dynamic_group(group_id) if found else None


async def delete_dynamic_group(group_id: int) -> bool:
    """Delete a dynamic group; jobs that targeted it keep running against
    nothing (``jobs.dynamic_group_id`` is cleared by the foreign key)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM dynamic_groups WHERE id = ?", (int(group_id),))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def get_group_subtree_ids(group_ids: Iterable[int]) -> set[int]:
    """The ids of the given inventory groups and all of their sub-groups
    (unknown ids contribute nothing)."""
    result: set[int] = set()
    ids = sorted({int(g) for g in group_ids})
    if not ids:
        return result
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(group_subtrees_sql(len(ids)), tuple(ids))
        result.update(int(r["id"]) for r in rows_to_list(await cursor.fetchall()))
    finally:
        await db.close()
    return result


async def find_object_keys_with_field(object_type: str, field_id: int) -> set[str]:
    """Keys of the objects that hold any value for custom field ``field_id``."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT object_key FROM custom_field_values WHERE field_id = ? AND object_type = ? AND value <> ''",
            (int(field_id), object_type),
        )
        return {r["object_key"] for r in rows_to_list(await cursor.fetchall())}
    finally:
        await db.close()
