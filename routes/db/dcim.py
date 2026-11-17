"""Physical DCIM storage: rack roles, racks, reservations, device placement,
patch panel ports, modules and power records (cables and traces live in
``routes.db.dcim_cables``).

Star re-exported by routes/database.py. Tables: migration 0102. Rules (unit
fit, overlap, pairing, power maths) come from ``netcontrol.dcim``; this
module applies them inside the write's transaction, with the rack row
locked, so two concurrent placements cannot take the same units.

Every record kind shares one set of CRUD functions keyed by ``kind``; the
tracked kinds (all but ``rack_role``) emit object-change events through
``tracks_changes``. A write raises ``ValueError`` for a taken name (the
API's 409) and ``DcimRuleError`` for a rule it breaks (422).

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from netcontrol.dcim import device_height, elevation, endpoint_key, placement_error, reservation_error

import routes.database as _dbcore
from routes.database import _is_unique_violation, _safe_dynamic_update, row_to_dict, rows_to_list
from routes.db.change_events import tracks_changes
from routes.db.custom_fields import _marks, _now

__all__ = [
    "DCIM_KINDS",
    "DcimRuleError",
    "count_dcim_usage",
    "count_site_dcim_records",
    "create_dcim_record",
    "delete_dcim_record",
    "get_dcim_record",
    "get_host_placement",
    "get_rack_elevation",
    "host_placement_error",
    "list_dcim_records",
    "missing_dcim_refs",
    "set_host_placement",
    "update_dcim_record",
]


class DcimRuleError(ValueError):
    """A write breaks a DCIM rule (the API answers 422 with the message)."""


Check = Callable[[Any, int | None, dict], Awaitable[None]]


@dataclass(frozen=True)
class _Kind:
    table: str
    alias: str
    select: str
    label: str
    order: str
    filters: dict[str, str]
    search: tuple[str, ...] = ()
    unique_message: str = "A {label} with this name already exists here."
    json_columns: tuple[str, ...] = ()
    bool_columns: tuple[str, ...] = ()


def _cable_join(endpoint_type: str, alias: str) -> str:
    return (
        f"LEFT JOIN cable_endpoints ce ON ce.endpoint_key = '{endpoint_type}:' || {alias}.id "
        "LEFT JOIN cables cb ON cb.id = ce.cable_id"
    )


_KINDS: dict[str, _Kind] = {
    "rack_role": _Kind(
        table="rack_roles",
        alias="x",
        label="rack role",
        select="""SELECT x.*, (SELECT COUNT(*) FROM racks r WHERE r.role_id = x.id) AS rack_count
                  FROM rack_roles x""",
        order="lower(x.name), x.id",
        filters={},
        search=("x.name", "x.description"),
        unique_message="A rack role named '{name}' already exists.",
    ),
    "rack": _Kind(
        table="racks",
        alias="x",
        label="rack",
        select="""SELECT x.*, s.name AS site_name, f.name AS floor_name, rr.name AS role_name,
                         rr.color AS role_color, t.name AS tenant_name,
                         (SELECT COUNT(*) FROM hosts h WHERE h.rack_id = x.id) AS device_count,
                         (SELECT COUNT(*) FROM power_feeds pf WHERE pf.rack_id = x.id) AS power_feed_count
                  FROM racks x
                  JOIN geo_sites s ON s.id = x.site_id
                  LEFT JOIN geo_floors f ON f.id = x.floor_id
                  LEFT JOIN rack_roles rr ON rr.id = x.role_id
                  LEFT JOIN tenants t ON t.id = x.tenant_id""",
        order="lower(s.name), lower(x.name), x.id",
        filters={
            "site_id": "x.site_id = ?",
            "floor_id": "x.floor_id = ?",
            "role_id": "x.role_id = ?",
            "tenant_id": "x.tenant_id = ?",
            "status": "x.status = ?",
        },
        search=("x.name", "x.facility_id", "x.serial", "x.asset_tag", "x.description"),
        unique_message="The site already has a rack named '{name}'.",
        bool_columns=("desc_units",),
    ),
    "rack_reservation": _Kind(
        table="rack_reservations",
        alias="x",
        label="rack reservation",
        select="""SELECT x.*, r.name AS rack_name, r.site_id, t.name AS tenant_name
                  FROM rack_reservations x
                  JOIN racks r ON r.id = x.rack_id
                  LEFT JOIN tenants t ON t.id = x.tenant_id""",
        order="lower(r.name), x.id",
        filters={"rack_id": "x.rack_id = ?", "tenant_id": "x.tenant_id = ?", "site_id": "r.site_id = ?"},
        search=("x.description", "x.user_name"),
        json_columns=("units",),
    ),
    "rear_port": _Kind(
        table="rear_ports",
        alias="x",
        label="rear port",
        select=f"""SELECT x.*, h.hostname AS host_name, ce.cable_id, cb.label AS cable_label,
                          (SELECT COUNT(*) FROM front_ports fp WHERE fp.rear_port_id = x.id) AS front_port_count
                   FROM rear_ports x
                   JOIN hosts h ON h.id = x.host_id
                   {_cable_join("rear_port", "x")}""",
        order="lower(h.hostname), lower(x.name), x.id",
        filters={"host_id": "x.host_id = ?", "type": "x.type = ?"},
        search=("x.name", "x.description", "h.hostname"),
        unique_message="The device already has a rear port named '{name}'.",
    ),
    "front_port": _Kind(
        table="front_ports",
        alias="x",
        label="front port",
        select=f"""SELECT x.*, h.hostname AS host_name, rp.name AS rear_port_name, rp.positions AS rear_port_positions,
                          ce.cable_id, cb.label AS cable_label
                   FROM front_ports x
                   JOIN hosts h ON h.id = x.host_id
                   JOIN rear_ports rp ON rp.id = x.rear_port_id
                   {_cable_join("front_port", "x")}""",
        order="lower(h.hostname), lower(x.name), x.id",
        filters={"host_id": "x.host_id = ?", "type": "x.type = ?", "rear_port_id": "x.rear_port_id = ?"},
        search=("x.name", "x.description", "h.hostname"),
        unique_message="The device already has a front port named '{name}' or the rear port position is mapped.",
    ),
    "module": _Kind(
        table="modules",
        alias="x",
        label="module",
        select="""SELECT x.*, h.hostname AS host_name FROM modules x JOIN hosts h ON h.id = x.host_id""",
        order="lower(h.hostname), lower(x.bay), x.id",
        filters={"host_id": "x.host_id = ?", "status": "x.status = ?"},
        search=("x.bay", "x.module_type", "x.part_number", "x.serial", "x.asset_tag", "h.hostname"),
        unique_message="The device already has a module in bay '{bay}'.",
    ),
    "power_panel": _Kind(
        table="power_panels",
        alias="x",
        label="power panel",
        select="""SELECT x.*, s.name AS site_name, f.name AS floor_name,
                         (SELECT COUNT(*) FROM power_feeds pf WHERE pf.power_panel_id = x.id) AS feed_count
                  FROM power_panels x
                  JOIN geo_sites s ON s.id = x.site_id
                  LEFT JOIN geo_floors f ON f.id = x.floor_id""",
        order="lower(s.name), lower(x.name), x.id",
        filters={"site_id": "x.site_id = ?", "floor_id": "x.floor_id = ?"},
        search=("x.name", "x.description"),
        unique_message="The site already has a power panel named '{name}'.",
    ),
    "power_feed": _Kind(
        table="power_feeds",
        alias="x",
        label="power feed",
        select=f"""SELECT x.*, pp.name AS power_panel_name, pp.site_id, r.name AS rack_name,
                          ce.cable_id, cb.label AS cable_label
                   FROM power_feeds x
                   JOIN power_panels pp ON pp.id = x.power_panel_id
                   LEFT JOIN racks r ON r.id = x.rack_id
                   {_cable_join("power_feed", "x")}""",
        order="lower(pp.name), lower(x.name), x.id",
        filters={
            "power_panel_id": "x.power_panel_id = ?",
            "rack_id": "x.rack_id = ?",
            "site_id": "pp.site_id = ?",
            "status": "x.status = ?",
        },
        search=("x.name", "x.description"),
        unique_message="The panel already has a feed named '{name}'.",
    ),
    "power_port": _Kind(
        table="power_ports",
        alias="x",
        label="power port",
        select=f"""SELECT x.*, h.hostname AS host_name, ce.cable_id, cb.label AS cable_label,
                          (SELECT COUNT(*) FROM power_outlets o WHERE o.power_port_id = x.id) AS outlet_count
                   FROM power_ports x
                   JOIN hosts h ON h.id = x.host_id
                   {_cable_join("power_port", "x")}""",
        order="lower(h.hostname), lower(x.name), x.id",
        filters={"host_id": "x.host_id = ?"},
        search=("x.name", "x.description", "h.hostname"),
        unique_message="The device already has a power port named '{name}'.",
    ),
    "power_outlet": _Kind(
        table="power_outlets",
        alias="x",
        label="power outlet",
        select=f"""SELECT x.*, h.hostname AS host_name, pp.name AS power_port_name, ce.cable_id, cb.label AS cable_label
                   FROM power_outlets x
                   JOIN hosts h ON h.id = x.host_id
                   LEFT JOIN power_ports pp ON pp.id = x.power_port_id
                   {_cable_join("power_outlet", "x")}""",
        order="lower(h.hostname), lower(x.name), x.id",
        filters={"host_id": "x.host_id = ?", "power_port_id": "x.power_port_id = ?"},
        search=("x.name", "x.description", "h.hostname"),
        unique_message="The device already has a power outlet named '{name}'.",
    ),
}
DCIM_KINDS: tuple[str, ...] = tuple(_KINDS)

# Rows a list answers at most.
LIST_MAX = 5000


def _shape(kind: _Kind, row: dict) -> dict:
    out = dict(row)
    for column in kind.json_columns:
        raw = out.get(column)
        try:
            out[column] = json.loads(raw) if isinstance(raw, str) and raw else []
        except ValueError:
            out[column] = []
    for column in kind.bool_columns:
        out[column] = bool(out.get(column))
    if "user_name" in out:
        out["user"] = out.pop("user_name")
    return out


async def _select(sql: str, params: tuple = ()) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def list_dcim_records(
    kind: str, filters: dict[str, Any] | None = None, q: str = "", limit: int = LIST_MAX
) -> list[dict]:
    """Records of ``kind`` matching every filter (keys of the kind's filter
    set; ``None`` values ignored) and the text ``q`` (any search column,
    ignoring case)."""
    spec = _KINDS[kind]
    clauses: list[str] = []
    params: list[Any] = []
    for key, value in (filters or {}).items():
        if value is None or key not in spec.filters:
            continue
        clauses.append(spec.filters[key])
        params.append(value)
    if q and spec.search:
        clauses.append("(" + " OR ".join(f"lower({c}) LIKE ?" for c in spec.search) + ")")
        params.extend([f"%{q.lower()}%"] * len(spec.search))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await _select(
        f"{spec.select}{where} ORDER BY {spec.order} LIMIT ?",  # nosec B608 - fixed clauses, placeholders only
        (*params, max(1, min(int(limit), LIST_MAX))),
    )
    return [_shape(spec, r) for r in rows]


async def get_dcim_record(kind: str, record_id: int) -> dict | None:
    spec = _KINDS[kind]
    rows = await _select(f"{spec.select} WHERE {spec.alias}.id = ?", (int(record_id),))  # nosec B608 - fixed clauses
    return _shape(spec, rows[0]) if rows else None


def _encode(spec: _Kind, values: dict) -> dict:
    out = {}
    for key, value in values.items():
        if key in spec.json_columns:
            value = json.dumps(sorted({int(v) for v in value or []}))
        elif key in spec.bool_columns:
            value = 1 if value else 0
        out["user_name" if key == "user" else key] = value
    return out


def _taken(spec: _Kind, values: dict) -> ValueError:
    return ValueError(
        spec.unique_message.format(label=spec.label, name=values.get("name", ""), bay=values.get("bay", ""))
    )


async def _write(kind: str, record_id: int | None, values: dict, user: str, check: Check | None) -> int | None:
    """Insert (``record_id`` None) or update a record in one transaction,
    running ``check(db, record_id, values)`` first. Returns the id, ``None``
    when the record to update does not exist."""
    spec = _KINDS[kind]
    stored = _encode(spec, values)
    db = await _dbcore.get_db()
    try:
        if check is not None:
            await check(db, record_id, values)
        now = _now()
        if record_id is None:
            stored = {**stored, "created_by": user, "created_at": now, "updated_by": user, "updated_at": now}
            columns = list(stored)
            cursor = await db.execute(
                f"INSERT INTO {spec.table} ({', '.join(columns)}) VALUES ({_marks(columns)}) RETURNING id",  # nosec B608 - fixed table and column names
                tuple(stored.values()),
            )
            result: int | None = int(cursor.lastrowid)
        else:
            stored = {**stored, "updated_by": user, "updated_at": now}
            sql, params = _safe_dynamic_update(
                spec.table, [f"{c} = ?" for c in stored], list(stored.values()), "id = ?", int(record_id)
            )
            cursor = await db.execute(sql, params)
            result = int(record_id) if (cursor.rowcount or 0) > 0 else None
        await db.commit()
        return result
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _taken(spec, values) from exc
        raise
    finally:
        await db.close()


async def _delete(kind: str, record_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(f"DELETE FROM {_KINDS[kind].table} WHERE id = ?", (int(record_id),))  # nosec B608 - fixed table names
        await db.commit()
        return (cursor.rowcount or 0) > 0
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


def _tracked(object_type: str):
    @tracks_changes(object_type, "create")
    async def create(kind: str, values: dict, user: str, check: Check | None) -> int:
        return int(await _write(kind, None, values, user, check) or 0)

    @tracks_changes(object_type, "update", id_arg="record_id")
    async def update(kind: str, record_id: int, values: dict, user: str, check: Check | None) -> bool:
        return await _write(kind, record_id, values, user, check) is not None

    @tracks_changes(object_type, "delete", id_arg="record_id")
    async def delete(kind: str, record_id: int) -> bool:
        return await _delete(kind, record_id)

    return create, update, delete


async def _plain_create(kind: str, values: dict, user: str, check: Check | None) -> int:
    return int(await _write(kind, None, values, user, check) or 0)


async def _plain_update(kind: str, record_id: int, values: dict, user: str, check: Check | None) -> bool:
    return await _write(kind, record_id, values, user, check) is not None


_WRITERS = {kind: _tracked(kind) for kind in DCIM_KINDS if kind != "rack_role"}
_WRITERS["rack_role"] = (_plain_create, _plain_update, _delete)


# ── Rule checks run inside the write ─────────────────────────────────────────


async def _one(db, sql: str, params: tuple) -> dict | None:
    cursor = await db.execute(sql, params)
    return row_to_dict(await cursor.fetchone())


async def _all(db, sql: str, params: tuple) -> list[dict]:
    cursor = await db.execute(sql, params)
    return rows_to_list(await cursor.fetchall())


async def _merged(db, kind: str, record_id: int | None, values: dict) -> dict:
    """The record as it will be: stored values overlaid with ``values``."""
    if record_id is None:
        return dict(values)
    row = await _one(db, f"SELECT * FROM {_KINDS[kind].table} WHERE id = ?", (int(record_id),))  # nosec B608 - fixed table names
    if row is None:
        return dict(values)
    current = _shape(_KINDS[kind], row)
    return {**current, **values}


async def _check_floor(db, site_id: int, floor_id: int | None) -> None:
    if floor_id is None:
        return
    floor = await _one(db, "SELECT site_id FROM geo_floors WHERE id = ?", (int(floor_id),))
    if floor is None or int(floor["site_id"]) != int(site_id):
        raise DcimRuleError("The floor must belong to the site.")


async def _rack_devices(db, rack_id: int, exclude_host: int | None = None) -> list[dict]:
    rows = await _all(
        db,
        """SELECT h.id AS host_id, h.hostname AS name, h.rack_position AS position, h.rack_face AS face,
                  h.site_id, dt.u_height AS height
           FROM hosts h LEFT JOIN device_types dt ON dt.id = h.device_type_id
           WHERE h.rack_id = ? ORDER BY h.rack_position NULLS LAST, lower(h.hostname), h.id""",
        (int(rack_id),),
    )
    for row in rows:
        row["height"] = device_height(row.get("height"))
    return [r for r in rows if exclude_host is None or int(r["host_id"]) != int(exclude_host)]


async def _rack_reservations(db, rack_id: int, exclude: int | None = None) -> list[dict]:
    rows = await _all(
        db,
        "SELECT id, units, user_name, description FROM rack_reservations WHERE rack_id = ? ORDER BY id",
        (int(rack_id),),
    )
    spec = _KINDS["rack_reservation"]
    return [_shape(spec, r) for r in rows if exclude is None or int(r["id"]) != int(exclude)]


async def _lock_rack(db, rack_id: int) -> dict:
    rack = await _one(db, "SELECT * FROM racks WHERE id = ? FOR UPDATE", (int(rack_id),))
    if rack is None:
        raise DcimRuleError(f"No rack with id {rack_id}.")
    return rack


async def _check_rack(db, record_id: int | None, values: dict) -> None:
    rack = await _merged(db, "rack", record_id, values)
    await _check_floor(db, int(rack["site_id"]), rack.get("floor_id"))
    if record_id is None:
        return
    await _lock_rack(db, record_id)
    devices = await _rack_devices(db, record_id)
    if any(d["site_id"] is not None and int(d["site_id"]) != int(rack["site_id"]) for d in devices):
        raise DcimRuleError("The rack holds devices of another site; move them out before changing its site.")
    height = int(rack["u_height"])
    for device in devices:
        if device["position"] is not None and int(device["position"]) + device["height"] - 1 > height:
            raise DcimRuleError(f"Device '{device['name']}' would not fit in a {height}U rack.")
    for reservation in await _rack_reservations(db, record_id):
        if any(int(u) > height for u in reservation["units"]):
            raise DcimRuleError(f"A reservation holds units above {height}.")
    feeds = await _all(
        db,
        "SELECT pf.name FROM power_feeds pf JOIN power_panels pp ON pp.id = pf.power_panel_id "
        "WHERE pf.rack_id = ? AND pp.site_id <> ?",
        (int(record_id), int(rack["site_id"])),
    )
    if feeds:
        raise DcimRuleError("Power feeds of another site's panels feed this rack; detach them first.")


async def _check_reservation(db, record_id: int | None, values: dict) -> None:
    reservation = await _merged(db, "rack_reservation", record_id, values)
    rack = await _lock_rack(db, int(reservation["rack_id"]))
    problem = reservation_error(
        int(rack["u_height"]),
        reservation.get("units") or [],
        await _rack_devices(db, int(rack["id"])),
        await _rack_reservations(db, int(rack["id"]), exclude=record_id),
    )
    if problem:
        raise DcimRuleError(problem)


async def _check_front_port(db, record_id: int | None, values: dict) -> None:
    port = await _merged(db, "front_port", record_id, values)
    rear = await _one(db, "SELECT host_id, positions FROM rear_ports WHERE id = ?", (int(port["rear_port_id"]),))
    if rear is None:
        raise DcimRuleError(f"No rear port with id {port['rear_port_id']}.")
    if int(rear["host_id"]) != int(port["host_id"]):
        raise DcimRuleError("The rear port must be on the same device as the front port.")
    position = int(port.get("rear_port_position") or 1)
    if position > int(rear["positions"]):
        raise DcimRuleError(f"The rear port has {rear['positions']} positions; position {position} does not exist.")


async def _check_rear_port(db, record_id: int | None, values: dict) -> None:
    if record_id is None or "positions" not in values:
        return
    row = await _one(
        db, "SELECT MAX(rear_port_position) AS top FROM front_ports WHERE rear_port_id = ?", (int(record_id),)
    )
    if row and row["top"] is not None and int(row["top"]) > int(values["positions"]):
        raise DcimRuleError(f"A front port maps to position {row['top']}; keep at least that many positions.")


async def _check_power_feed(db, record_id: int | None, values: dict) -> None:
    feed = await _merged(db, "power_feed", record_id, values)
    if feed.get("rack_id") is None:
        return
    row = await _one(
        db,
        "SELECT r.site_id AS rack_site, pp.site_id AS panel_site FROM racks r, power_panels pp "
        "WHERE r.id = ? AND pp.id = ?",
        (int(feed["rack_id"]), int(feed["power_panel_id"])),
    )
    if row is None:
        raise DcimRuleError("Unknown rack or power panel.")
    if int(row["rack_site"]) != int(row["panel_site"]):
        raise DcimRuleError("The rack must be at the power panel's site.")


async def _check_power_panel(db, record_id: int | None, values: dict) -> None:
    panel = await _merged(db, "power_panel", record_id, values)
    await _check_floor(db, int(panel["site_id"]), panel.get("floor_id"))


async def _check_power_outlet(db, record_id: int | None, values: dict) -> None:
    outlet = await _merged(db, "power_outlet", record_id, values)
    if outlet.get("power_port_id") is None:
        return
    port = await _one(db, "SELECT host_id FROM power_ports WHERE id = ?", (int(outlet["power_port_id"]),))
    if port is None or int(port["host_id"]) != int(outlet["host_id"]):
        raise DcimRuleError("The feeding power port must be on the same device as the outlet.")


_CHECKS: dict[str, Check] = {
    "rack": _check_rack,
    "rack_reservation": _check_reservation,
    "front_port": _check_front_port,
    "rear_port": _check_rear_port,
    "power_feed": _check_power_feed,
    "power_panel": _check_power_panel,
    "power_outlet": _check_power_outlet,
}


# ── Public CRUD ──────────────────────────────────────────────────────────────


async def create_dcim_record(kind: str, values: dict, user: str = "") -> dict:
    """Create a record of ``kind`` and return it. ``ValueError`` for a taken
    name, ``DcimRuleError`` for a broken rule. The caller checks that the
    referenced ids exist."""
    create, _update, _remove = _WRITERS[kind]
    new_id = await create(kind, values, user, _CHECKS.get(kind))
    record = await get_dcim_record(kind, new_id)
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("DCIM record vanished after write")
    return record


async def update_dcim_record(kind: str, record_id: int, values: dict, user: str = "") -> dict | None:
    """Change the given columns; ``None`` when the record does not exist."""
    _create, update, _remove = _WRITERS[kind]
    if not values:
        return await get_dcim_record(kind, record_id)
    found = await update(kind, int(record_id), values, user, _CHECKS.get(kind))
    return await get_dcim_record(kind, record_id) if found else None


async def delete_dcim_record(kind: str, record_id: int) -> bool:
    """Delete one record (the caller checks ``count_dcim_usage`` first)."""
    _create, _update, remove = _WRITERS[kind]
    return bool(await remove(kind, int(record_id)))


_CABLED = "SELECT COUNT(*) AS n FROM cable_endpoints WHERE endpoint_key = ?"
# kind -> (what, SQL with one ``?``, True: the parameter is the endpoint key).
_USAGE: dict[str, tuple[tuple[str, str, bool], ...]] = {
    "rack_role": (("racks", "SELECT COUNT(*) AS n FROM racks WHERE role_id = ?", False),),
    "rack": (("devices", "SELECT COUNT(*) AS n FROM hosts WHERE rack_id = ?", False),),
    "rear_port": (
        ("cables", _CABLED, True),
        ("front ports", "SELECT COUNT(*) AS n FROM front_ports WHERE rear_port_id = ?", False),
    ),
    "front_port": (("cables", _CABLED, True),),
    "power_port": (("cables", _CABLED, True),),
    "power_outlet": (("cables", _CABLED, True),),
    "power_feed": (("cables", _CABLED, True),),
    "power_panel": (
        (
            "cabled feeds",
            "SELECT COUNT(*) AS n FROM power_feeds pf JOIN cable_endpoints ce "
            "ON ce.endpoint_key = 'power_feed:' || pf.id WHERE pf.power_panel_id = ?",
            False,
        ),
    ),
}


async def count_dcim_usage(kind: str, record_id: int) -> dict[str, int]:
    """What keeps a record from being deleted: ``{"cables": 1}``; empty when
    nothing does."""
    out: dict[str, int] = {}
    for label, sql, by_key in _USAGE.get(kind, ()):
        param = endpoint_key(kind, int(record_id)) if by_key else int(record_id)
        rows = await _select(sql, (param,))
        if int(rows[0]["n"]):
            out[label] = int(rows[0]["n"])
    return out


async def count_site_dcim_records(site_id: int) -> dict[str, int]:
    """Racks and power panels of a site (a site with any cannot be deleted)."""
    rows = await _select(
        "SELECT (SELECT COUNT(*) FROM racks WHERE site_id = ?) AS racks, "
        "(SELECT COUNT(*) FROM power_panels WHERE site_id = ?) AS power_panels",
        (int(site_id), int(site_id)),
    )
    return {k: int(v) for k, v in rows[0].items() if int(v)}


# Id field of a write -> the table it names.
_REF_TABLES: dict[str, str] = {
    "site_id": "geo_sites",
    "floor_id": "geo_floors",
    "role_id": "rack_roles",
    "tenant_id": "tenants",
    "rack_id": "racks",
    "host_id": "hosts",
    "rear_port_id": "rear_ports",
    "power_panel_id": "power_panels",
    "power_port_id": "power_ports",
}
_MAX_ID = 2_147_483_647


async def missing_dcim_refs(values: dict) -> dict[str, str]:
    """``{field: message}`` for each id in ``values`` that names no record
    (``None`` values and other keys are not checked)."""
    errors: dict[str, str] = {}
    wanted = {k: v for k, v in values.items() if k in _REF_TABLES and v is not None}
    if not wanted:
        return errors
    db = await _dbcore.get_db(read_only=True)
    try:
        for key, value in wanted.items():
            if (
                not 0 < int(value) <= _MAX_ID
                or await _one(
                    db,
                    f"SELECT 1 AS ok FROM {_REF_TABLES[key]} WHERE id = ?",
                    (int(value),),  # nosec B608 - fixed table names
                )
                is None
            ):
                errors[key] = f"No record with id {value}."
    finally:
        await db.close()
    return errors


# ── Device placement ─────────────────────────────────────────────────────────

_UNSET: Any = object()


async def get_host_placement(host_id: int) -> dict | None:
    """A host's rack placement: ``rack_id``, ``rack_position``, ``rack_face``,
    ``site_id``, ``height`` and the rack display fields; ``None`` when the
    host does not exist."""
    rows = await _select(
        """SELECT h.id AS host_id, h.hostname, h.site_id, h.rack_id, h.rack_position, h.rack_face,
                  dt.u_height AS height, r.name AS rack_name, r.site_id AS rack_site_id, s.name AS rack_site_name
           FROM hosts h
           LEFT JOIN device_types dt ON dt.id = h.device_type_id
           LEFT JOIN racks r ON r.id = h.rack_id
           LEFT JOIN geo_sites s ON s.id = r.site_id
           WHERE h.id = ?""",
        (int(host_id),),
    )
    if not rows:
        return None
    row = rows[0]
    row["height"] = device_height(row.get("height"))
    return row


async def _placement_problem(db, host_id: int, values: dict, site_id: Any, lock: bool) -> tuple[str | None, dict]:
    """``(problem, final values)`` for placing a host: ``values`` holds any
    of ``rack_id``, ``rack_position``, ``rack_face`` (others keep their
    stored value); ``site_id`` overrides the host's site (``_UNSET``: the
    stored one). A host with no site takes the rack's site."""
    host = await _one(
        db,
        """SELECT h.id, h.hostname, h.site_id, h.rack_id, h.rack_position, h.rack_face, dt.u_height
           FROM hosts h LEFT JOIN device_types dt ON dt.id = h.device_type_id WHERE h.id = ?""",
        (int(host_id),),
    )
    if host is None:
        return "Host not found.", {}
    final = {
        "rack_id": values.get("rack_id", host["rack_id"]),
        "rack_position": values.get("rack_position", host["rack_position"]),
        "rack_face": values.get("rack_face", host["rack_face"]) or "",
    }
    if "rack_id" in values and values["rack_id"] != host["rack_id"] and "rack_position" not in values:
        final["rack_position"] = None
    site = host["site_id"] if site_id is _UNSET else site_id
    if final["rack_id"] is None:
        return None, {"rack_id": None, "rack_position": None, "rack_face": ""}
    if lock:
        rack = await _lock_rack(db, int(final["rack_id"]))
    else:
        rack = await _one(db, "SELECT * FROM racks WHERE id = ?", (int(final["rack_id"]),))
        if rack is None:
            return f"No rack with id {final['rack_id']}.", final
    if site is None:
        final["site_id"] = int(rack["site_id"])
    elif int(site) != int(rack["site_id"]):
        return "The rack is at another site than the device.", final
    if final["rack_position"] is None:
        final["rack_face"] = ""
        return None, final
    final["rack_face"] = final["rack_face"] or "front"
    problem = placement_error(
        int(rack["u_height"]),
        int(final["rack_position"]),
        device_height(host.get("u_height")),
        await _rack_devices(db, int(rack["id"]), exclude_host=int(host_id)),
        await _rack_reservations(db, int(rack["id"])),
    )
    return problem, final


async def host_placement_error(host_id: int, values: dict, site_id: Any = _UNSET) -> str | None:
    """Why ``values`` cannot be the host's placement (see
    ``set_host_placement``), checked without writing; ``None`` when they can."""
    db = await _dbcore.get_db(read_only=True)
    try:
        problem, _final = await _placement_problem(db, host_id, values, site_id, lock=False)
        return problem
    finally:
        await db.close()


@tracks_changes("host", "update", id_arg="host_id")
async def set_host_placement(host_id: int, values: dict) -> bool:
    """Place a host in a rack: ``values`` holds any of ``rack_id`` (``None``
    takes it out of its rack), ``rack_position`` (the lowest unit; ``None``:
    in the rack, not mounted) and ``rack_face`` (``front``/``rear``,
    default front). Moving to another rack without a position unmounts it.
    The unit fit, the overlap with mounted devices and reservations (every
    device full depth) and the site are checked with the rack locked; a host
    with no site takes the rack's. Raises ``DcimRuleError``; ``False`` when
    the host does not exist."""
    db = await _dbcore.get_db()
    try:
        if await _one(db, "SELECT id FROM hosts WHERE id = ?", (int(host_id),)) is None:
            return False
        problem, final = await _placement_problem(db, host_id, values, _UNSET, lock=True)
        if problem:
            raise DcimRuleError(problem)
        sql, params = _safe_dynamic_update(
            "hosts", [f"{c} = ?" for c in final], list(final.values()), "id = ?", int(host_id)
        )
        await db.execute(sql, params)
        await db.commit()
        return True
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def get_rack_elevation(rack_id: int) -> dict | None:
    """The rack drawn by unit for both faces (``netcontrol.dcim.elevation``)
    with the rack record; ``None`` when it does not exist."""
    rack = await get_dcim_record("rack", rack_id)
    if rack is None:
        return None
    db = await _dbcore.get_db(read_only=True)
    try:
        devices = await _rack_devices(db, rack_id)
        reservations = await _rack_reservations(db, rack_id)
    finally:
        await db.close()
    drawing = elevation(int(rack["u_height"]), bool(rack["desc_units"]), devices, reservations)
    return {"rack": rack, **drawing, "reservations": reservations}
