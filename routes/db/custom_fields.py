"""Custom fields and tags on hosts, inventory groups and IPAM prefixes.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables (migration 0083): ``tags``, ``tag_assignments``, ``custom_fields``,
``custom_field_values``. Object data is keyed by ``(object_type,
object_key)``: the row id as text for ``host`` and ``group``, and
``prefix_key(subnet, vrf)`` for ``prefix``, so a prefix keeps its data when
an IPAM source resync replaces its ``ipam_prefixes`` rows.

Values are stored as the canonical text ``netcontrol.custom_fields``
produces; this module stores and returns text and never converts types.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime

import routes.database as _dbcore
from routes.database import _is_unique_violation, row_to_dict, rows_to_list

__all__ = [
    "bulk_update_tags",
    "count_custom_field_values",
    "create_custom_field",
    "create_tag",
    "delete_custom_field",
    "delete_tag",
    "find_object_keys",
    "get_custom_field",
    "get_object_data",
    "get_object_data_bulk",
    "get_tag",
    "list_custom_fields",
    "list_tags",
    "prefix_key",
    "purge_object_data",
    "set_object_data",
    "update_custom_field",
    "update_tag",
]

_FMT = "%Y-%m-%d %H:%M:%S"
# Above this many keys a bulk read selects the whole object type and filters
# in Python rather than sending one very long ``IN`` list.
_IN_LIMIT = 1000
_USAGE_TYPES = ("host", "group", "prefix")


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def _chunks(items: list, size: int = _IN_LIMIT) -> Iterator[list]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _marks(items: Iterable) -> str:
    return ",".join("?" for _ in items)


def prefix_key(subnet: str, vrf: str | None = "") -> str:
    """The object key of an IPAM prefix: canonical network, ``|``, VRF name.

    ``192.0.2.5/24`` and ``192.0.2.0/24`` give the same key. Raises
    ``ValueError`` for a value that is not a network. The only place this
    format is defined.
    """
    network = ipaddress.ip_network(str(subnet).strip(), strict=False)
    return f"{network}|{(vrf or '').strip()}"


# ── Tags ─────────────────────────────────────────────────────────────────────


def _tag(row: dict | None) -> dict | None:
    if row is None:
        return None
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "color": row["color"],
        "description": row.get("description") or "",
    }


async def list_tags(with_usage: bool = False) -> list[dict]:
    """Every tag by name; with ``with_usage`` each carries
    ``usage = {host, group, prefix}`` assignment counts."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT id, name, color, description FROM tags ORDER BY lower(name), id")
        tags = [t for t in (_tag(r) for r in rows_to_list(await cursor.fetchall())) if t]
        if not with_usage:
            return tags
        cursor = await db.execute(
            "SELECT tag_id, object_type, COUNT(*) AS n FROM tag_assignments GROUP BY tag_id, object_type"
        )
        counts: dict[int, dict[str, int]] = {}
        for row in rows_to_list(await cursor.fetchall()):
            counts.setdefault(int(row["tag_id"]), {})[row["object_type"]] = int(row["n"])
    finally:
        await db.close()
    for tag in tags:
        mine = counts.get(tag["id"], {})
        tag["usage"] = {t: mine.get(t, 0) for t in _USAGE_TYPES}
    return tags


async def get_tag(tag_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT id, name, color, description FROM tags WHERE id = ?", (int(tag_id),))
        return _tag(row_to_dict(await cursor.fetchone()))
    finally:
        await db.close()


def _taken(name: str) -> ValueError:
    return ValueError(f"A tag named '{name}' already exists.")


async def create_tag(*, name: str, color: str = "gray", description: str = "", created_by: str = "") -> dict:
    """Store a new tag. Raises ``ValueError`` when the name is taken ignoring case."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO tags (name, color, description, created_by, created_at) VALUES (?,?,?,?,?) RETURNING id",
            (name, color, description, created_by, _now()),
        )
        await db.commit()
        tag_id = int(cursor.lastrowid)
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _taken(name) from exc
        raise
    finally:
        await db.close()
    return {"id": tag_id, "name": name, "color": color, "description": description}


async def update_tag(tag_id: int, *, name: str, color: str, description: str) -> dict | None:
    """Rename, recolor or redescribe a tag. ``None`` when it does not exist;
    ``ValueError`` when another tag has the name ignoring case."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE tags SET name = ?, color = ?, description = ? WHERE id = ?",
            (name, color, description, int(tag_id)),
        )
        await db.commit()
        found = (cursor.rowcount or 0) > 0
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _taken(name) from exc
        raise
    finally:
        await db.close()
    return {"id": int(tag_id), "name": name, "color": color, "description": description} if found else None


async def delete_tag(tag_id: int) -> int:
    """Delete a tag and its assignments; returns how many assignments went."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) AS n FROM tag_assignments WHERE tag_id = ?", (int(tag_id),))
        removed = int((await cursor.fetchone())["n"])
        await db.execute("DELETE FROM tag_assignments WHERE tag_id = ?", (int(tag_id),))
        await db.execute("DELETE FROM tags WHERE id = ?", (int(tag_id),))
        await db.commit()
        return removed
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


# ── Field definitions ────────────────────────────────────────────────────────


def _str_list(text: str | None) -> list[str]:
    try:
        items = json.loads(text or "[]")
    except TypeError, ValueError:
        return []
    return [str(i) for i in items] if isinstance(items, list) else []


def _field(row: dict | None) -> dict | None:
    if row is None:
        return None
    return {
        "id": int(row["id"]),
        "key": row["key"],
        "label": row["label"],
        "field_type": row["field_type"],
        "choices": _str_list(row.get("choices_json")),
        "object_types": _str_list(row.get("object_types_json")),
        "required": bool(row.get("required")),
        "default_value": row.get("default_value") or "",
        "description": row.get("description") or "",
        "sort_order": int(row.get("sort_order") or 0),
    }


async def list_custom_fields(object_type: str | None = None, with_counts: bool = False) -> list[dict]:
    """Field definitions by ``sort_order`` then id; with ``object_type`` only
    the fields that apply to it. With ``with_counts`` each carries
    ``value_count``, its stored values across every object type (one
    grouped query)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM custom_fields ORDER BY sort_order, id")
        fields = [f for f in (_field(r) for r in rows_to_list(await cursor.fetchall())) if f]
        if with_counts:
            cursor = await db.execute("SELECT field_id, COUNT(*) AS n FROM custom_field_values GROUP BY field_id")
            counts = {int(r["field_id"]): int(r["n"]) for r in rows_to_list(await cursor.fetchall())}
            for field in fields:
                field["value_count"] = counts.get(field["id"], 0)
    finally:
        await db.close()
    if object_type is None:
        return fields
    return [f for f in fields if object_type in f["object_types"]]


async def get_custom_field(field_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM custom_fields WHERE id = ?", (int(field_id),))
        return _field(row_to_dict(await cursor.fetchone()))
    finally:
        await db.close()


async def create_custom_field(
    *,
    key: str,
    label: str,
    field_type: str,
    choices: list[str],
    object_types: list[str],
    required: bool,
    default_value: str,
    description: str,
    sort_order: int,
    created_by: str,
) -> dict:
    """Store a field definition. Raises ``ValueError`` when the key is taken."""
    now = _now()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO custom_fields
                   (key, label, field_type, choices_json, object_types_json, required, default_value,
                    description, sort_order, created_by, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id""",
            (
                key,
                label,
                field_type,
                json.dumps(list(choices)),
                json.dumps(list(object_types)),
                1 if required else 0,
                default_value,
                description,
                int(sort_order),
                created_by,
                now,
                now,
            ),
        )
        await db.commit()
        field_id = int(cursor.lastrowid)
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(f"A field with the key '{key}' already exists.") from exc
        raise
    finally:
        await db.close()
    created = await get_custom_field(field_id)
    if created is None:  # pragma: no cover - the row was just inserted
        raise RuntimeError("custom field vanished after insert")
    return created


async def update_custom_field(
    field_id: int,
    *,
    label: str,
    choices: list[str],
    object_types: list[str],
    required: bool,
    default_value: str,
    description: str,
    sort_order: int,
) -> dict | None:
    """Change everything but the key and type. Values on object types the
    field no longer applies to are deleted in the same transaction. ``None``
    when the field does not exist."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT object_types_json FROM custom_fields WHERE id = ?", (int(field_id),))
        row = row_to_dict(await cursor.fetchone())
        if row is None:
            return None
        removed = sorted(set(_str_list(row["object_types_json"])) - set(object_types))
        if removed:
            await db.execute(
                f"DELETE FROM custom_field_values WHERE field_id = ? AND object_type IN ({_marks(removed)})",  # nosec B608 - placeholders only
                (int(field_id), *removed),
            )
        await db.execute(
            """UPDATE custom_fields
               SET label = ?, choices_json = ?, object_types_json = ?, required = ?, default_value = ?,
                   description = ?, sort_order = ?, updated_at = ?
               WHERE id = ?""",
            (
                label,
                json.dumps(list(choices)),
                json.dumps(list(object_types)),
                1 if required else 0,
                default_value,
                description,
                int(sort_order),
                _now(),
                int(field_id),
            ),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
    return await get_custom_field(field_id)


async def count_custom_field_values(field_id: int, object_types: list[str] | None = None) -> int:
    """Stored values of a field, on every object type or only on ``object_types``."""
    if object_types is not None and not object_types:
        return 0
    sql = "SELECT COUNT(*) AS n FROM custom_field_values WHERE field_id = ?"
    params: list = [int(field_id)]
    if object_types is not None:
        sql += f" AND object_type IN ({_marks(object_types)})"
        params.extend(object_types)
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, tuple(params))
        return int((await cursor.fetchone())["n"])
    finally:
        await db.close()


async def delete_custom_field(field_id: int) -> int:
    """Delete a field and its values; returns how many values went."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) AS n FROM custom_field_values WHERE field_id = ?", (int(field_id),))
        removed = int((await cursor.fetchone())["n"])
        await db.execute("DELETE FROM custom_field_values WHERE field_id = ?", (int(field_id),))
        await db.execute("DELETE FROM custom_fields WHERE id = ?", (int(field_id),))
        await db.commit()
        return removed
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


# ── Object data ──────────────────────────────────────────────────────────────


async def get_object_data_bulk(object_type: str, object_keys: list[str] | None = None) -> dict[str, dict]:
    """``{key: {"tags": [TagRef], "fields": {field_key: text}}}`` for the
    given keys (every key of the type with ``None``). Keys with no data are
    absent. Two queries whatever the number of keys."""
    if object_keys is not None and not object_keys:
        return {}
    wanted = None if object_keys is None else {str(k) for k in object_keys}
    where = "x.object_type = ?"
    params: tuple = (object_type,)
    if wanted is not None and len(wanted) <= _IN_LIMIT:
        where += f" AND x.object_key IN ({_marks(wanted)})"
        params = (object_type, *sorted(wanted))
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT x.object_key, t.id, t.name, t.color
                FROM tag_assignments x JOIN tags t ON t.id = x.tag_id
                WHERE {where} ORDER BY lower(t.name), t.id""",  # nosec B608 - fixed clauses, placeholders only
            params,
        )
        tag_rows = rows_to_list(await cursor.fetchall())
        cursor = await db.execute(
            f"""SELECT x.object_key, f.key, x.value
                FROM custom_field_values x JOIN custom_fields f ON f.id = x.field_id
                WHERE {where} ORDER BY f.sort_order, f.id""",  # nosec B608 - fixed clauses, placeholders only
            params,
        )
        value_rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()

    out: dict[str, dict] = {}

    def _entry(key: str) -> dict | None:
        if wanted is not None and key not in wanted:
            return None
        return out.setdefault(key, {"tags": [], "fields": {}})

    for row in tag_rows:
        entry = _entry(row["object_key"])
        if entry is not None:
            entry["tags"].append({"id": int(row["id"]), "name": row["name"], "color": row["color"]})
    for row in value_rows:
        entry = _entry(row["object_key"])
        if entry is not None:
            entry["fields"][row["key"]] = row["value"]
    return out


async def get_object_data(object_type: str, object_key: str) -> dict:
    """``{"tags": [TagRef], "fields": {field_key: text}}`` for one object."""
    data = await get_object_data_bulk(object_type, [str(object_key)])
    return data.get(str(object_key), {"tags": [], "fields": {}})


async def _missing_ids(db, table: str, ids: Iterable[int]) -> list[int]:
    wanted = sorted({int(i) for i in ids})
    if not wanted:
        return []
    cursor = await db.execute(
        f"SELECT id FROM {table} WHERE id IN ({_marks(wanted)})",  # nosec B608 - fixed table names
        tuple(wanted),
    )
    found = {int(r["id"]) for r in rows_to_list(await cursor.fetchall())}
    return [i for i in wanted if i not in found]


async def _check_ids(db, tag_ids: Iterable[int], field_ids: Iterable[int]) -> None:
    problems = []
    missing_tags = await _missing_ids(db, "tags", tag_ids)
    if missing_tags:
        problems.append("Unknown tag id: " + ", ".join(str(i) for i in missing_tags))
    missing_fields = await _missing_ids(db, "custom_fields", field_ids)
    if missing_fields:
        problems.append("Unknown field id: " + ", ".join(str(i) for i in missing_fields))
    if problems:
        raise ValueError("; ".join(problems))


async def set_object_data(object_type: str, object_key: str, tag_ids: list[int], values: dict[int, str]) -> None:
    """Replace an object's tags with ``tag_ids`` and its values with
    ``values`` (field id to canonical text; empty text means no value), in
    one transaction. Raises ``ValueError`` naming every unknown tag or field
    id, before anything is written."""
    key = str(object_key)
    db = await _dbcore.get_db()
    try:
        await _check_ids(db, tag_ids, values)
        await db.execute("DELETE FROM tag_assignments WHERE object_type = ? AND object_key = ?", (object_type, key))
        await db.execute("DELETE FROM custom_field_values WHERE object_type = ? AND object_key = ?", (object_type, key))
        tag_rows = [(int(t), object_type, key) for t in dict.fromkeys(int(t) for t in tag_ids)]
        if tag_rows:
            await db.executemany(
                "INSERT INTO tag_assignments (tag_id, object_type, object_key) VALUES (?,?,?)", tag_rows
            )
        value_rows = [(int(f), object_type, key, v) for f, v in values.items() if v != ""]
        if value_rows:
            await db.executemany(
                "INSERT INTO custom_field_values (field_id, object_type, object_key, value) VALUES (?,?,?,?)",
                value_rows,
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def bulk_update_tags(
    object_type: str, object_keys: list[str], add_tag_ids: list[int], remove_tag_ids: list[int]
) -> int:
    """Add and remove tags on many objects in one transaction; returns the
    number of objects touched. Raises ``ValueError`` on an unknown tag id."""
    keys = list(dict.fromkeys(str(k) for k in object_keys))
    add = list(dict.fromkeys(int(t) for t in add_tag_ids))
    remove = [int(t) for t in remove_tag_ids if int(t) not in add]
    if not keys or not (add or remove):
        return 0
    db = await _dbcore.get_db()
    try:
        await _check_ids(db, add, [])
        if remove:
            for chunk in _chunks(keys):
                await db.execute(
                    f"""DELETE FROM tag_assignments
                        WHERE object_type = ? AND tag_id IN ({_marks(remove)})
                          AND object_key IN ({_marks(chunk)})""",  # nosec B608 - placeholders only
                    (object_type, *remove, *chunk),
                )
        if add:
            await db.executemany(
                "INSERT OR IGNORE INTO tag_assignments (tag_id, object_type, object_key) VALUES (?,?,?)",
                [(t, object_type, k) for k in keys for t in add],
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
    return len(keys)


async def find_object_keys(object_type: str, tag_names: list[str], field_filters: dict[int, str]) -> set[str]:
    """Keys of the objects that carry every tag in ``tag_names`` (ignoring
    case) and hold every value in ``field_filters`` (field id to canonical
    text). No criteria matches nothing."""
    if not tag_names and not field_filters:
        return set()
    result: set[str] | None = None
    db = await _dbcore.get_db(read_only=True)
    try:
        for name in dict.fromkeys(n.strip().lower() for n in tag_names):
            cursor = await db.execute(
                """SELECT x.object_key FROM tag_assignments x JOIN tags t ON t.id = x.tag_id
                   WHERE x.object_type = ? AND lower(t.name) = ?""",
                (object_type, name),
            )
            keys = {r["object_key"] for r in rows_to_list(await cursor.fetchall())}
            result = keys if result is None else result & keys
            if not result:
                return set()
        for field_id, value in field_filters.items():
            cursor = await db.execute(
                "SELECT object_key FROM custom_field_values WHERE field_id = ? AND object_type = ? AND value = ?",
                (int(field_id), object_type, value),
            )
            keys = {r["object_key"] for r in rows_to_list(await cursor.fetchall())}
            result = keys if result is None else result & keys
            if not result:
                return set()
    finally:
        await db.close()
    return result or set()


async def purge_object_data(db, object_type: str, object_keys: list[str]) -> None:
    """Delete the tags and values of the given objects on the caller's open
    connection, inside the caller's transaction. Does not commit."""
    keys = list(dict.fromkeys(str(k) for k in object_keys))
    for chunk in _chunks(keys):
        for table in ("tag_assignments", "custom_field_values"):
            await db.execute(
                f"DELETE FROM {table} WHERE object_type = ? AND object_key IN ({_marks(chunk)})",  # nosec B608 - fixed table names
                (object_type, *chunk),
            )
