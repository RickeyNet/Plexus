"""Data validation rules: storage only.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table: migration 0096 (``validation_rules``). The rule logic (what a rule
checks, parameter validation, the in-memory cache and enforcement) lives in
``netcontrol.data_validation``; the admin API in
``netcontrol.routes.validation_rules``. Names are unique ignoring case.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json

import routes.database as _dbcore
from routes.db.custom_fields import _now
from routes.db.device_model import _insert, _select, _update

__all__ = [
    "create_validation_rule",
    "delete_validation_rule",
    "get_validation_rule",
    "list_validation_rules",
    "update_validation_rule",
]

_SELECT = "SELECT * FROM validation_rules"


def _params(text: str | None) -> dict:
    try:
        value = json.loads(text or "")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _rule(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "object_type": row["object_type"],
        "field": row["field"],
        "rule_type": row["rule_type"],
        "params": _params(row["params_json"]),
        "error_message": row["error_message"] or "",
        "description": row["description"] or "",
        "enabled": bool(row["enabled"]),
        "created_by": row["created_by"] or "",
        "created_at": row["created_at"] or "",
        "updated_by": row["updated_by"] or "",
        "updated_at": row["updated_at"] or "",
    }


def _taken(name: str) -> ValueError:
    return ValueError(f"A validation rule named '{name}' already exists.")


def _written(values: dict, user: str) -> dict:
    out = {k: v for k, v in values.items() if k != "params"}
    if "params" in values:
        out["params_json"] = json.dumps(values["params"], sort_keys=True)
    if "enabled" in out:
        out["enabled"] = 1 if out["enabled"] else 0
    out["updated_at"] = _now()
    out["updated_by"] = user or ""
    return out


async def _name_taken(name: str, rule_id: int | None) -> bool:
    rows = await _select("SELECT id FROM validation_rules WHERE lower(name) = lower(?)", (name,))
    return any(int(r["id"]) != rule_id for r in rows)


async def list_validation_rules(object_type: str | None = None, *, enabled_only: bool = False) -> list[dict]:
    """Rules by object type, field and name; only those of ``object_type``
    when given, only enabled ones on ``enabled_only``."""
    clauses: list[str] = []
    params: list = []
    if object_type is not None:
        clauses.append("object_type = ?")
        params.append(object_type)
    if enabled_only:
        clauses.append("enabled = 1")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await _select(_SELECT + where + " ORDER BY object_type, field, lower(name), id", tuple(params))
    return [_rule(r) for r in rows]


async def get_validation_rule(rule_id: int) -> dict | None:
    rows = await _select(_SELECT + " WHERE id = ?", (int(rule_id),))
    return _rule(rows[0]) if rows else None


async def create_validation_rule(values: dict, user: str = "") -> dict:
    """``values``: name, object_type, field, rule_type, params (a dict),
    error_message, description, enabled, already validated. ``ValueError``
    when a rule has the name, ignoring case."""
    if await _name_taken(values["name"], None):
        raise _taken(values["name"])
    written = _written(values, user)
    written["created_by"] = user or ""
    new_id = await _insert("validation_rules", written, _taken(values["name"]))
    record = await get_validation_rule(new_id)
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record


async def update_validation_rule(rule_id: int, values: dict, user: str = "") -> dict | None:
    """Replace the writable fields. ``None`` when the rule does not exist;
    ``ValueError`` when another rule has the name."""
    if await _name_taken(values["name"], int(rule_id)):
        raise _taken(values["name"])
    if not await _update("validation_rules", int(rule_id), _written(values, user), _taken(values["name"])):
        return None
    return await get_validation_rule(rule_id)


async def delete_validation_rule(rule_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM validation_rules WHERE id = ?", (int(rule_id),))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()
