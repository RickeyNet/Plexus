"""Export templates: storage only.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table: migration 0112 (``export_templates``). The rules (object types,
validation, rendering) live in ``netcontrol.export_templates``; the API in
``netcontrol.routes.export_templates``. A name is unique per object type,
ignoring case.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import routes.database as _dbcore
from routes.db.custom_fields import _now
from routes.db.device_model import _insert, _select, _update

__all__ = [
    "create_export_template",
    "delete_export_template",
    "get_export_template",
    "list_export_templates",
    "update_export_template",
]

_SELECT = "SELECT * FROM export_templates"


def _template(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "object_type": row["object_type"],
        "description": row["description"] or "",
        "template_text": row["template_text"] or "",
        "mime_type": row["mime_type"] or "text/plain",
        "file_extension": row["file_extension"] or "",
        "as_attachment": bool(row["as_attachment"]),
        "created_by": row["created_by"] or "",
        "created_at": row["created_at"] or "",
        "updated_by": row["updated_by"] or "",
        "updated_at": row["updated_at"] or "",
    }


def _taken(values: dict) -> ValueError:
    return ValueError(f"An export template named '{values['name']}' already exists for this object type.")


def _written(values: dict, user: str) -> dict:
    out = dict(values)
    if "as_attachment" in out:
        out["as_attachment"] = 1 if out["as_attachment"] else 0
    out["updated_at"] = _now()
    out["updated_by"] = user or ""
    return out


async def _name_taken(values: dict, template_id: int | None) -> bool:
    rows = await _select(
        "SELECT id FROM export_templates WHERE object_type = ? AND lower(name) = lower(?)",
        (values["object_type"], values["name"]),
    )
    return any(int(r["id"]) != template_id for r in rows)


async def list_export_templates(object_types: list[str] | None = None) -> list[dict]:
    """Templates by object type and name; only those of ``object_types``
    when given (``[]``: none)."""
    if object_types is not None and not object_types:
        return []
    where = ""
    params: tuple = ()
    if object_types is not None:
        where = f" WHERE object_type IN ({','.join('?' * len(object_types))})"
        params = tuple(object_types)
    rows = await _select(_SELECT + where + " ORDER BY object_type, lower(name), id", params)  # nosec B608 - placeholders only
    return [_template(r) for r in rows]


async def get_export_template(template_id: int) -> dict | None:
    rows = await _select(_SELECT + " WHERE id = ?", (int(template_id),))
    return _template(rows[0]) if rows else None


async def create_export_template(values: dict, user: str = "") -> dict:
    """``values``: name, object_type, description, template_text,
    mime_type, file_extension, as_attachment, already validated.
    ``ValueError`` when the object type has a template of that name,
    ignoring case."""
    if await _name_taken(values, None):
        raise _taken(values)
    written = _written(values, user)
    written["created_by"] = user or ""
    new_id = await _insert("export_templates", written, _taken(values))
    record = await get_export_template(new_id)
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record


async def update_export_template(template_id: int, values: dict, user: str = "") -> dict | None:
    """Replace the writable fields. ``None`` when the template does not
    exist; ``ValueError`` when another template of the object type has the
    name."""
    if await _name_taken(values, int(template_id)):
        raise _taken(values)
    if not await _update("export_templates", int(template_id), _written(values, user), _taken(values)):
        return None
    return await get_export_template(template_id)


async def delete_export_template(template_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM export_templates WHERE id = ?", (int(template_id),))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()
