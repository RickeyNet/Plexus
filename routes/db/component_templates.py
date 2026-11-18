"""Device type component templates and their instantiation on hosts.

Star re-exported by routes/database.py. Table: migration 0110
(``device_component_templates``). Templates live in the generic record
store of ``routes.db.dcim`` as kind ``component_template`` (list, get,
create, update, delete; not change-tracked: a template is catalogue data
like the device type it belongs to). Instantiation creates the missing
DCIM records of a host through the same store, so every rule, unique name
and change event of those records applies. Rules:
``netcontrol.component_templates``.
"""

from __future__ import annotations

from netcontrol.component_templates import COMPONENT_KINDS, missing_interfaces, plan_components

import routes.database as _dbcore
from routes.database import rows_to_list
from routes.db.dcim import (
    DcimRuleError,
    RecordKind,
    create_dcim_record,
    list_dcim_records,
    register_record_kind,
)
from routes.db.dcim_cables import list_host_interface_names

__all__ = [
    "instantiate_host_components",
    "list_component_templates",
]


async def _all(db, sql: str, params: tuple = ()) -> list[dict]:
    cursor = await db.execute(sql, params)
    return rows_to_list(await cursor.fetchall())


async def _check_template(db, record_id: int | None, values: dict) -> None:
    template = dict(values)
    if record_id is not None:
        rows = await _all(db, "SELECT * FROM device_component_templates WHERE id = ?", (int(record_id),))
        template = {**(rows[0] if rows else {}), **values}
    kind = template.get("component_type")
    if kind == "front_port":
        rear_id = template.get("rear_port_template_id")
        if rear_id is None:
            raise DcimRuleError("A front port template maps to a rear port template.")
        rows = await _all(
            db,
            "SELECT device_type_id, component_type, positions FROM device_component_templates WHERE id = ?",
            (int(rear_id),),
        )
        if not rows or rows[0]["component_type"] != "rear_port":
            raise DcimRuleError(f"No rear port template with id {rear_id}.")
        if int(rows[0]["device_type_id"]) != int(template["device_type_id"]):
            raise DcimRuleError("The rear port template must be of the same device type.")
        position = int(template.get("rear_port_position") or 1)
        if position > int(rows[0]["positions"]):
            raise DcimRuleError(
                f"The rear port template has {rows[0]['positions']} positions; position {position} does not exist."
            )
        taken = await _all(
            db,
            "SELECT 1 FROM device_component_templates WHERE rear_port_template_id = ? AND rear_port_position = ? "
            "AND id <> ?",
            (int(rear_id), position, int(record_id or 0)),
        )
        if taken:
            raise DcimRuleError(f"Another front port template maps to position {position} of that rear port.")
    elif kind == "rear_port" and record_id is not None and "positions" in values:
        rows = await _all(
            db,
            "SELECT MAX(rear_port_position) AS top FROM device_component_templates WHERE rear_port_template_id = ?",
            (int(record_id),),
        )
        if rows and rows[0]["top"] is not None and int(rows[0]["top"]) > int(values["positions"]):
            raise DcimRuleError(f"A front port template maps to position {rows[0]['top']}; keep at least that many.")


register_record_kind(
    "component_template",
    RecordKind(
        table="device_component_templates",
        alias="x",
        label="component template",
        select="""SELECT x.*, rp.name AS rear_port_template_name, dt.model AS device_type_model
                  FROM device_component_templates x
                  JOIN device_types dt ON dt.id = x.device_type_id
                  LEFT JOIN device_component_templates rp ON rp.id = x.rear_port_template_id""",
        order="x.device_type_id, x.component_type, lower(x.name), x.id",
        filters={"device_type_id": "x.device_type_id = ?", "component_type": "x.component_type = ?"},
        search=("x.name", "x.description"),
        unique_message="The device type already has a {label} named '{name}' of this component type.",
    ),
    _check_template,
    tracked=False,
    usage=(
        (
            "front port templates",
            "SELECT COUNT(*) AS n FROM device_component_templates WHERE rear_port_template_id = ?",
            False,
        ),
    ),
)


async def list_component_templates(device_type_id: int, component_type: str | None = None) -> list[dict]:
    """The component templates of a device type, by component type then name."""
    filters: dict = {"device_type_id": int(device_type_id), "component_type": component_type}
    return await list_dcim_records("component_template", filters)


async def _existing(host_id: int) -> dict[str, list[str]]:
    db = await _dbcore.get_db(read_only=True)
    try:
        out: dict[str, list[str]] = {}
        for kind, table, column in (
            ("console_port", "console_ports", "name"),
            ("power_port", "power_ports", "name"),
            ("rear_port", "rear_ports", "name"),
            ("front_port", "front_ports", "name"),
            ("module", "modules", "bay"),
        ):
            rows = await _all(db, f"SELECT {column} AS name FROM {table} WHERE host_id = ?", (int(host_id),))  # nosec B608 - fixed tables
            out[kind] = [str(r["name"]) for r in rows]
        return out
    finally:
        await db.close()


async def instantiate_host_components(host_id: int, user: str = "") -> dict | None:
    """Create the components the host's device type lists and the host
    lacks (matched by name, ignoring case; nothing existing is changed).
    ``None`` when the host does not exist. Returns ``device_type_id``
    (``None``: the host has no device type, nothing is created),
    ``created`` (kind -> names), ``created_count``, ``skipped`` (the
    templates whose component the host has already), ``errors`` (``{kind,
    name, message}`` for a record a rule refused) and ``interfaces``:
    ``expected`` (the interface template names) and ``missing`` (those the
    host has no known interface for)."""
    rows = await _dbcore.get_host(int(host_id))
    if rows is None:
        return None
    device_type_id = rows.get("device_type_id")
    result: dict = {
        "host_id": int(host_id),
        "device_type_id": int(device_type_id) if device_type_id is not None else None,
        "created": {},
        "created_count": 0,
        "skipped": 0,
        "errors": [],
        "interfaces": {"expected": [], "missing": []},
    }
    if device_type_id is None:
        return result
    templates = await list_component_templates(int(device_type_id))
    existing = await _existing(host_id)
    plan = plan_components(templates, existing)
    result["skipped"] = sum(1 for t in templates if t["component_type"] in COMPONENT_KINDS) - len(plan)
    rear_ids: dict[str, int] = {}
    for record in await list_dcim_records("rear_port", {"host_id": int(host_id)}):
        rear_ids[str(record["name"]).lower()] = int(record["id"])
    for kind, values in plan:
        values = {**values, "host_id": int(host_id)}
        label = values.get("name") or values.get("bay") or ""
        if kind == "front_port":
            rear_id = rear_ids.get(str(values.pop("rear_port_name", "")).lower())
            if rear_id is None:
                result["errors"].append({"kind": kind, "name": label, "message": "Its rear port does not exist."})
                continue
            values["rear_port_id"] = rear_id
        try:
            record = await create_dcim_record(kind, values, user)
        except ValueError as exc:
            # DcimRuleError, or a name another write took meanwhile.
            result["errors"].append({"kind": kind, "name": label, "message": str(exc)})
            continue
        if kind == "rear_port":
            rear_ids[str(record["name"]).lower()] = int(record["id"])
        result["created"].setdefault(kind, []).append(label)
        result["created_count"] += 1
    expected = [str(t["name"]) for t in templates if t["component_type"] == "interface"]
    result["interfaces"] = {
        "expected": expected,
        "missing": missing_interfaces(templates, await list_host_interface_names(int(host_id))) if expected else [],
    }
    return result
