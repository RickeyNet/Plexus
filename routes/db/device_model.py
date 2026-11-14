"""Device model for hosts: manufacturers, device types, roles, lifecycle
statuses, and the host columns that point at them (plus ``site_id`` into
``geo_sites`` and free-text ``location_detail``).

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables and columns: migration 0085. ``hardware_locked`` and ``role_locked``
on a host mean a person chose the value; discovery (``link_host_hardware``)
never overwrites a locked device type and never replaces a role.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

from collections.abc import Iterable

from netcontrol.device_model import (
    DEVICE_FILTER_KEYS,
    HOST_DEVICE_FIELDS,
    HOST_DEVICE_ID_FIELDS,
    MAX_ID,
    MODEL_MAX,
    manufacturer_name,
)

import routes.database as _dbcore
from routes.database import _LOGGER, _is_unique_violation, _safe_dynamic_update, row_to_dict, rows_to_list
from routes.db.custom_fields import _IN_LIMIT, _chunks, _marks, _now

__all__ = [
    "CATALOGUE_KINDS",
    "bulk_set_host_device_fields",
    "check_device_refs",
    "count_catalogue_hosts",
    "create_device_role",
    "create_device_type",
    "create_lifecycle_status",
    "create_manufacturer",
    "delete_catalogue_record",
    "find_host_ids_by_device_filters",
    "get_default_host_status_id",
    "get_device_display_objects",
    "get_device_role",
    "get_device_type",
    "get_lifecycle_status",
    "get_manufacturer",
    "link_host_hardware",
    "list_device_roles",
    "list_device_types",
    "list_lifecycle_statuses",
    "list_manufacturers",
    "set_host_device_fields",
    "update_device_role",
    "update_device_type",
    "update_lifecycle_status",
    "update_manufacturer",
]

# kind: (table, hosts using a record (one ``?`` for its id), the SET that
# clears those hosts' reference).
_KINDS: dict[str, tuple[str, str, str]] = {
    "manufacturer": (
        "manufacturers",
        "device_type_id IN (SELECT id FROM device_types WHERE manufacturer_id = ?)",
        "device_type_id = NULL, hardware_locked = 0",
    ),
    "device_type": ("device_types", "device_type_id = ?", "device_type_id = NULL, hardware_locked = 0"),
    "role": ("device_roles", "role_id = ?", "role_id = NULL, role_locked = 0"),
    "status": ("host_statuses", "lifecycle_status_id = ?", "lifecycle_status_id = NULL"),
}
CATALOGUE_KINDS: tuple[str, ...] = tuple(_KINDS)

# Host id column to the table it references.
_REF_TABLES: dict[str, str] = {
    "device_type_id": "device_types",
    "role_id": "device_roles",
    "lifecycle_status_id": "host_statuses",
    "site_id": "geo_sites",
}
# Host id column to the lock it sets when a person writes it.
_LOCKS: dict[str, str] = {"device_type_id": "hardware_locked", "role_id": "role_locked"}


def _taken(what: str, name: str) -> ValueError:
    return ValueError(f"A {what} named '{name}' already exists.")


async def _insert(table: str, values: dict, taken: ValueError) -> int:
    columns = list(values)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"INSERT INTO {table} ({', '.join(columns)}, created_at) VALUES ({_marks(columns)}, ?) RETURNING id",  # nosec B608 - fixed table and column names
            (*values.values(), _now()),
        )
        await db.commit()
        return int(cursor.lastrowid)
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise taken from exc
        raise
    finally:
        await db.close()


async def _update(table: str, record_id: int, values: dict, taken: ValueError) -> bool:
    sql, params = _safe_dynamic_update(
        table, [f"{c} = ?" for c in values], list(values.values()), "id = ?", int(record_id)
    )
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return (cursor.rowcount or 0) > 0
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise taken from exc
        raise
    finally:
        await db.close()


async def _select(sql: str, params: tuple = ()) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Manufacturers ────────────────────────────────────────────────────────────

_MANUFACTURER_SELECT = """
    SELECT m.id, m.name, m.description,
           COALESCE(t.n, 0) AS device_type_count, COALESCE(u.n, 0) AS host_count
    FROM manufacturers m
    LEFT JOIN (SELECT manufacturer_id, COUNT(*) AS n FROM device_types GROUP BY manufacturer_id) t
           ON t.manufacturer_id = m.id
    LEFT JOIN (SELECT dt.manufacturer_id, COUNT(*) AS n FROM hosts h
               JOIN device_types dt ON dt.id = h.device_type_id GROUP BY dt.manufacturer_id) u
           ON u.manufacturer_id = m.id
"""


def _manufacturer(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "description": row["description"] or "",
        "device_type_count": int(row["device_type_count"]),
        "host_count": int(row["host_count"]),
    }


async def list_manufacturers() -> list[dict]:
    """Every manufacturer by name, with ``device_type_count`` and
    ``host_count`` (hosts on any of its device types)."""
    rows = await _select(_MANUFACTURER_SELECT + " ORDER BY lower(m.name), m.id")
    return [_manufacturer(r) for r in rows]


async def get_manufacturer(manufacturer_id: int) -> dict | None:
    rows = await _select(_MANUFACTURER_SELECT + " WHERE m.id = ?", (int(manufacturer_id),))
    return _manufacturer(rows[0]) if rows else None


async def create_manufacturer(*, name: str, description: str = "") -> dict:
    """Raises ``ValueError`` when the name is taken ignoring case."""
    new_id = await _insert("manufacturers", {"name": name, "description": description}, _taken("manufacturer", name))
    return await _must(get_manufacturer(new_id))


async def update_manufacturer(manufacturer_id: int, *, name: str, description: str) -> dict | None:
    """``None`` when it does not exist; ``ValueError`` when the name is taken."""
    found = await _update(
        "manufacturers",
        manufacturer_id,
        {"name": name, "description": description},
        _taken("manufacturer", name),
    )
    return await get_manufacturer(manufacturer_id) if found else None


# ── Device types ─────────────────────────────────────────────────────────────

_DEVICE_TYPE_SELECT = """
    SELECT dt.id, dt.manufacturer_id, m.name AS manufacturer, dt.model, dt.part_number, dt.u_height,
           dt.description, COALESCE(u.n, 0) AS host_count
    FROM device_types dt
    JOIN manufacturers m ON m.id = dt.manufacturer_id
    LEFT JOIN (SELECT device_type_id, COUNT(*) AS n FROM hosts
               WHERE device_type_id IS NOT NULL GROUP BY device_type_id) u
           ON u.device_type_id = dt.id
"""


def _device_type(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "manufacturer_id": int(row["manufacturer_id"]),
        "manufacturer": row["manufacturer"],
        "model": row["model"],
        "part_number": row["part_number"] or "",
        "u_height": int(row["u_height"] or 0),
        "description": row["description"] or "",
        "host_count": int(row["host_count"]),
    }


async def list_device_types(manufacturer_id: int | None = None) -> list[dict]:
    """Device types by manufacturer then model; only one manufacturer's with
    ``manufacturer_id``."""
    where, params = ("", ()) if manufacturer_id is None else (" WHERE dt.manufacturer_id = ?", (int(manufacturer_id),))
    rows = await _select(_DEVICE_TYPE_SELECT + where + " ORDER BY lower(m.name), lower(dt.model), dt.id", params)
    return [_device_type(r) for r in rows]


async def get_device_type(device_type_id: int) -> dict | None:
    rows = await _select(_DEVICE_TYPE_SELECT + " WHERE dt.id = ?", (int(device_type_id),))
    return _device_type(rows[0]) if rows else None


def _model_taken(model: str) -> ValueError:
    return ValueError(f"This manufacturer already has a device type '{model}'.")


async def create_device_type(
    *, manufacturer_id: int, model: str, part_number: str = "", u_height: int = 0, description: str = ""
) -> dict:
    """Raises ``ValueError`` when the manufacturer has the model ignoring
    case. The caller checks that the manufacturer exists."""
    values = {
        "manufacturer_id": int(manufacturer_id),
        "model": model,
        "part_number": part_number,
        "u_height": int(u_height),
        "description": description,
    }
    new_id = await _insert("device_types", values, _model_taken(model))
    return await _must(get_device_type(new_id))


async def update_device_type(
    device_type_id: int, *, manufacturer_id: int, model: str, part_number: str, u_height: int, description: str
) -> dict | None:
    values = {
        "manufacturer_id": int(manufacturer_id),
        "model": model,
        "part_number": part_number,
        "u_height": int(u_height),
        "description": description,
    }
    found = await _update("device_types", device_type_id, values, _model_taken(model))
    return await get_device_type(device_type_id) if found else None


# ── Roles and lifecycle statuses ─────────────────────────────────────────────


def _role(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "color": row["color"],
        "description": row["description"] or "",
        "host_count": int(row["host_count"]),
    }


def _status(row: dict) -> dict:
    return {**_role(row), "is_default": bool(row["is_default"])}


_ROLE_SELECT = """
    SELECT r.id, r.name, r.color, r.description, COALESCE(u.n, 0) AS host_count
    FROM device_roles r
    LEFT JOIN (SELECT role_id, COUNT(*) AS n FROM hosts WHERE role_id IS NOT NULL GROUP BY role_id) u
           ON u.role_id = r.id
"""

_STATUS_SELECT = """
    SELECT s.id, s.name, s.color, s.description, s.is_default, COALESCE(u.n, 0) AS host_count
    FROM host_statuses s
    LEFT JOIN (SELECT lifecycle_status_id, COUNT(*) AS n FROM hosts
               WHERE lifecycle_status_id IS NOT NULL GROUP BY lifecycle_status_id) u
           ON u.lifecycle_status_id = s.id
"""


async def list_device_roles() -> list[dict]:
    rows = await _select(_ROLE_SELECT + " ORDER BY lower(r.name), r.id")
    return [_role(r) for r in rows]


async def get_device_role(role_id: int) -> dict | None:
    rows = await _select(_ROLE_SELECT + " WHERE r.id = ?", (int(role_id),))
    return _role(rows[0]) if rows else None


async def create_device_role(*, name: str, color: str = "gray", description: str = "") -> dict:
    new_id = await _insert(
        "device_roles", {"name": name, "color": color, "description": description}, _taken("role", name)
    )
    return await _must(get_device_role(new_id))


async def update_device_role(role_id: int, *, name: str, color: str, description: str) -> dict | None:
    found = await _update(
        "device_roles", role_id, {"name": name, "color": color, "description": description}, _taken("role", name)
    )
    return await get_device_role(role_id) if found else None


async def list_lifecycle_statuses() -> list[dict]:
    rows = await _select(_STATUS_SELECT + " ORDER BY lower(s.name), s.id")
    return [_status(r) for r in rows]


async def get_lifecycle_status(status_id: int) -> dict | None:
    rows = await _select(_STATUS_SELECT + " WHERE s.id = ?", (int(status_id),))
    return _status(rows[0]) if rows else None


async def get_default_host_status_id() -> int | None:
    rows = await _select("SELECT id FROM host_statuses WHERE is_default = 1 ORDER BY id LIMIT 1")
    return int(rows[0]["id"]) if rows else None


async def _write_status(status_id: int | None, values: dict, make_default: bool) -> int | None:
    """Insert (``status_id`` None) or update a status; with ``make_default``
    the others stop being the default in the same transaction. Returns the
    id, or ``None`` when the status to update does not exist."""
    taken = _taken("status", values["name"])
    db = await _dbcore.get_db()
    try:
        if make_default:
            await db.execute("UPDATE host_statuses SET is_default = 0 WHERE is_default = 1")
            values = {**values, "is_default": 1}
        if status_id is None:
            columns = list(values)
            cursor = await db.execute(
                f"INSERT INTO host_statuses ({', '.join(columns)}, created_at) VALUES ({_marks(columns)}, ?) RETURNING id",  # nosec B608 - fixed column names
                (*values.values(), _now()),
            )
            result: int | None = int(cursor.lastrowid)
        else:
            sql, params = _safe_dynamic_update(
                "host_statuses", [f"{c} = ?" for c in values], list(values.values()), "id = ?", int(status_id)
            )
            cursor = await db.execute(sql, params)
            result = int(status_id) if (cursor.rowcount or 0) > 0 else None
        if result is None:
            await db.rollback()
            return None
        await db.commit()
        return result
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise taken from exc
        raise
    finally:
        await db.close()


async def create_lifecycle_status(
    *, name: str, color: str = "gray", description: str = "", is_default: bool = False
) -> dict:
    """Raises ``ValueError`` when the name is taken ignoring case. With
    ``is_default`` it becomes the one default status."""
    new_id = await _write_status(None, {"name": name, "color": color, "description": description}, is_default)
    return await _must(get_lifecycle_status(int(new_id or 0)))


async def update_lifecycle_status(
    status_id: int, *, name: str, color: str, description: str, make_default: bool = False
) -> dict | None:
    """Rename, recolor, redescribe; ``make_default`` makes it the default
    (a default is never un-set here: make another status the default)."""
    found = await _write_status(status_id, {"name": name, "color": color, "description": description}, make_default)
    return await get_lifecycle_status(status_id) if found else None


async def _must(coro) -> dict:
    record = await coro
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("catalogue record vanished after write")
    return record


# ── Deleting a catalogue record ──────────────────────────────────────────────


async def count_catalogue_hosts(kind: str, record_id: int) -> int:
    """Hosts that refer to the record (for a manufacturer: to any of its
    device types)."""
    _table, using, _clear = _KINDS[kind]
    rows = await _select(f"SELECT COUNT(*) AS n FROM hosts WHERE {using}", (int(record_id),))  # nosec B608 - fixed clauses
    return int(rows[0]["n"])


async def delete_catalogue_record(kind: str, record_id: int) -> int:
    """Delete a record; the hosts that referred to it get NULL (and lose the
    lock that went with it). A manufacturer takes its device types with it.
    Returns the number of hosts changed. Raises ``ValueError`` for the
    default lifecycle status."""
    table, using, clear = _KINDS[kind]
    db = await _dbcore.get_db()
    try:
        if kind == "status":
            cursor = await db.execute("SELECT is_default FROM host_statuses WHERE id = ?", (int(record_id),))
            row = row_to_dict(await cursor.fetchone())
            if row and int(row["is_default"]):
                raise ValueError("The default status cannot be deleted; make another status the default first.")
        cursor = await db.execute(f"UPDATE hosts SET {clear} WHERE {using}", (int(record_id),))  # nosec B608 - fixed clauses
        affected = int(cursor.rowcount or 0)
        await db.execute(f"DELETE FROM {table} WHERE id = ?", (int(record_id),))  # nosec B608 - fixed table names
        await db.commit()
        return affected
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


# ── Host values ──────────────────────────────────────────────────────────────


async def check_device_refs(values: dict) -> dict[str, str]:
    """``{field: message}`` for each id in ``values`` (a host write) that
    names no record. ``None`` values and other keys are not checked."""
    wanted = {f: int(v) for f, v in values.items() if f in _REF_TABLES and v is not None}
    if not wanted:
        return {}
    errors: dict[str, str] = {}
    db = await _dbcore.get_db(read_only=True)
    try:
        for field, value in wanted.items():
            if not 0 < value <= MAX_ID:
                errors[field] = f"No record with id {value}."
                continue
            cursor = await db.execute(f"SELECT 1 FROM {_REF_TABLES[field]} WHERE id = ?", (value,))  # nosec B608 - fixed table names
            if await cursor.fetchone() is None:
                errors[field] = f"No record with id {value}."
    finally:
        await db.close()
    return errors


def _set_clause(values: dict, lock: bool) -> tuple[list[str], list]:
    exprs: list[str] = []
    params: list = []
    for field in HOST_DEVICE_FIELDS:
        if field not in values:
            continue
        value = values[field]
        if field == "location_detail":
            exprs.append("location_detail = ?")
            params.append(str(value or ""))
            continue
        exprs.append(f"{field} = ?")
        params.append(None if value is None else int(value))
        if lock and field in _LOCKS:
            exprs.append(f"{_LOCKS[field]} = ?")
            params.append(0 if value is None else 1)
    return exprs, params


async def set_host_device_fields(host_id: int, values: dict, lock: bool = True) -> bool:
    """Write the given keys of ``HOST_DEVICE_FIELDS`` on one host; other
    keys are ignored. With ``lock`` a device type or role sets its lock and
    ``None`` clears value and lock. ``False`` when the host does not exist."""
    exprs, params = _set_clause(values, lock)
    if not exprs:
        return await _host_exists(host_id)
    sql, sql_params = _safe_dynamic_update("hosts", exprs, params, "id = ?", int(host_id))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, sql_params)
        await db.commit()
        return (cursor.rowcount or 0) > 0
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def _host_exists(host_id: int) -> bool:
    return bool(await _select("SELECT 1 FROM hosts WHERE id = ?", (int(host_id),)))


async def bulk_set_host_device_fields(host_ids: Iterable[int], values: dict, lock: bool = True) -> int:
    """Like ``set_host_device_fields`` on many hosts in one transaction;
    returns how many hosts exist among ``host_ids`` and were written."""
    ids = list(dict.fromkeys(int(h) for h in host_ids))
    exprs, params = _set_clause(values, lock)
    if not ids or not exprs:
        return 0
    updated = 0
    db = await _dbcore.get_db()
    try:
        for chunk in _chunks(ids):
            cursor = await db.execute(
                f"UPDATE hosts SET {', '.join(exprs)} WHERE id IN ({_marks(chunk)})",  # nosec B608 - fixed column names, placeholders only
                (*params, *chunk),
            )
            updated += int(cursor.rowcount or 0)
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
    return updated


async def find_host_ids_by_device_filters(filters: dict[str, list[int | None]]) -> dict[int, int]:
    """The hosts matching every filter in ``filters`` (a key of
    ``DEVICE_FILTER_KEYS`` to alternatives: ids, or ``None`` for no value),
    as host id to group id. No filters match every host."""
    clauses: list[str] = []
    params: list[int] = []
    for key in DEVICE_FILTER_KEYS:
        values = filters.get(key)
        if not values:
            continue
        ids = [int(v) for v in values if v is not None]
        column = "device_type_id" if key == "manufacturer_id" else key
        alternatives: list[str] = []
        if ids and key == "manufacturer_id":
            alternatives.append(
                f"device_type_id IN (SELECT id FROM device_types WHERE manufacturer_id IN ({_marks(ids)}))"
            )
        elif ids:
            alternatives.append(f"{column} IN ({_marks(ids)})")
        if None in values:
            alternatives.append(f"{column} IS NULL")
        clauses.append("(" + " OR ".join(alternatives) + ")")
        params.extend(ids)
    where = " AND ".join(clauses) or "TRUE"
    rows = await _select(f"SELECT id, group_id FROM hosts WHERE {where}", tuple(params))  # nosec B608 - fixed clauses, placeholders only
    return {int(r["id"]): int(r["group_id"]) for r in rows}


async def get_device_display_objects(rows: list[dict]) -> dict[str, dict[int, dict]]:
    """The display objects for the host ``rows``: ``{"hardware": {id: ...},
    "role": ..., "lifecycle_status": ..., "site": ...}``, one query per
    catalogue that any row refers to."""
    wanted = {f: sorted({int(r[f]) for r in rows if r.get(f) is not None}) for f in HOST_DEVICE_ID_FIELDS}
    queries = {
        "device_type_id": (
            "hardware",
            "SELECT dt.id, dt.model, dt.manufacturer_id, m.name AS manufacturer "
            "FROM device_types dt JOIN manufacturers m ON m.id = dt.manufacturer_id",
            "dt.id",
        ),
        "role_id": ("role", "SELECT id, name, color FROM device_roles", "id"),
        "lifecycle_status_id": ("lifecycle_status", "SELECT id, name, color FROM host_statuses", "id"),
        "site_id": ("site", "SELECT id, name FROM geo_sites", "id"),
    }
    out: dict[str, dict[int, dict]] = {name: {} for name, _sql, _col in queries.values()}
    db = await _dbcore.get_db(read_only=True)
    try:
        for field, (name, sql, id_column) in queries.items():
            ids = wanted[field]
            if not ids:
                continue
            if len(ids) <= _IN_LIMIT:
                cursor = await db.execute(f"{sql} WHERE {id_column} IN ({_marks(ids)})", tuple(ids))  # nosec B608 - fixed clauses, placeholders only
            else:
                cursor = await db.execute(sql)
            out[name] = {int(r["id"]): r for r in rows_to_list(await cursor.fetchall())}
    finally:
        await db.close()
    return out


# ── Discovery ────────────────────────────────────────────────────────────────


async def link_host_hardware(host_id: int, vendor: str = "", model: str = "", category: str = "") -> None:
    """Link a discovered host to the catalogues.

    With a ``model`` and no hardware lock, finds or creates the manufacturer
    (from ``vendor`` or the host's driver key) and the device type, matching
    ignoring case, and sets the host's device type. With a ``category`` that
    names a role and no role on the host, sets the role. Never sets a lock.
    Safe when two discoveries race. Never raises: a failure is logged.
    """
    model = (model or "").strip()[:MODEL_MAX]
    category = (category or "").strip()
    if not model and not category:
        return
    try:
        db = await _dbcore.get_db()
        try:
            cursor = await db.execute("SELECT device_type, hardware_locked FROM hosts WHERE id = ?", (int(host_id),))
            host = row_to_dict(await cursor.fetchone())
            if host is None:
                return
            if model and not int(host["hardware_locked"] or 0):
                name = manufacturer_name(vendor, str(host["device_type"] or ""))
                await db.execute(
                    "INSERT INTO manufacturers (name, description, created_at) VALUES (?, '', ?) ON CONFLICT DO NOTHING",
                    (name, _now()),
                )
                cursor = await db.execute("SELECT id FROM manufacturers WHERE lower(name) = lower(?)", (name,))
                manufacturer_id = int((await cursor.fetchone())["id"])
                await db.execute(
                    """INSERT INTO device_types (manufacturer_id, model, created_at) VALUES (?, ?, ?)
                       ON CONFLICT DO NOTHING""",
                    (manufacturer_id, model, _now()),
                )
                cursor = await db.execute(
                    "SELECT id FROM device_types WHERE manufacturer_id = ? AND lower(model) = lower(?)",
                    (manufacturer_id, model),
                )
                device_type_id = int((await cursor.fetchone())["id"])
                await db.execute(
                    "UPDATE hosts SET device_type_id = ? WHERE id = ? AND hardware_locked = 0",
                    (device_type_id, int(host_id)),
                )
            if category:
                await db.execute(
                    """UPDATE hosts SET role_id = r.id FROM device_roles r
                       WHERE hosts.id = ? AND hosts.role_id IS NULL AND lower(r.name) = lower(?)""",
                    (int(host_id), category),
                )
            await db.commit()
        except Exception:
            await db.rollback()
            raise
        finally:
            await db.close()
    except Exception as exc:
        _LOGGER.warning("device model: could not link host %s to its hardware: %s", host_id, exc)
