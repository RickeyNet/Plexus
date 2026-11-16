"""Intended configuration templates, config contexts and the intended
configuration of each host.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables: migration 0087. Template and context scope ids (``role_id``,
``site_id``, ``group_id``, ``host_id``) are plain integers with no foreign
key; the rules that read them live in ``netcontrol.intended_config``. Names
are unique ignoring case. ``intended_configs`` holds one row per host that
has a matching template and is deleted with the host.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

import routes.database as _dbcore
from routes.db.custom_fields import _chunks, _marks, _now
from routes.db.device_model import _insert, _select, _update
from routes.db.git_sources import git_source_name_sql
from routes.db.inventory import group_ids_condition

__all__ = [
    "count_hosts",
    "create_config_context",
    "create_config_template",
    "delete_config_context",
    "delete_config_template",
    "delete_intended_configs",
    "get_config_context",
    "get_config_template",
    "get_intended_config",
    "get_interfaces_for_hosts",
    "get_vrfs_for_hosts",
    "list_config_contexts",
    "list_config_templates",
    "list_intended_configs",
    "list_vlan_records",
    "save_intended_config",
    "set_intended_comparison",
    "summarize_intended_configs",
    "update_config_context",
    "update_config_template",
]

_TEMPLATE_COUNTS = "(SELECT template_id, COUNT(*) AS n FROM intended_configs GROUP BY template_id)"
_TEMPLATE_SELECT = f"""
    SELECT t.id, t.name, t.kind, t.device_type, t.role_id, t.site_id, t.group_id, t.template_text,
           t.description, t.enabled, t.created_at, t.updated_at, t.updated_by, COALESCE(u.n, 0) AS host_count
    FROM config_templates t
    LEFT JOIN {_TEMPLATE_COUNTS} u
           ON u.template_id = t.id
"""
_TEMPLATE_ORDER = " ORDER BY lower(t.name), t.id"


def _template_select(group_ids: Iterable[int] | None) -> tuple[str, tuple]:
    """``_TEMPLATE_SELECT``; with ``group_ids`` its ``host_count`` counts
    only the hosts in those inventory groups."""
    scope_sql, scope_params = group_ids_condition("h.group_id", group_ids)
    if not scope_sql:
        return _TEMPLATE_SELECT, ()
    counted = f"""(SELECT ic.template_id, COUNT(*) AS n FROM intended_configs ic
        JOIN hosts h ON h.id = ic.host_id WHERE {scope_sql} GROUP BY ic.template_id)"""  # nosec B608 - placeholders only
    return _TEMPLATE_SELECT.replace(_TEMPLATE_COUNTS, counted), scope_params


_CONTEXT_SELECT = f"""
    SELECT id, name, weight, data, description, enabled, device_type, role_id, site_id, group_id, host_id,
           created_at, updated_at, updated_by, git_source_id, git_path, git_commit,
           {git_source_name_sql("config_contexts")}
    FROM config_contexts
"""
_CONTEXT_ORDER = " ORDER BY weight, lower(name), id"


def _id(value) -> int | None:
    return int(value) if value is not None else None


def _scope(row: dict) -> dict:
    return {
        "device_type": row["device_type"] or "",
        "role_id": _id(row["role_id"]),
        "site_id": _id(row["site_id"]),
        "group_id": _id(row["group_id"]),
    }


def _stamps(row: dict) -> dict:
    return {
        "created_at": row["created_at"] or "",
        "updated_at": row["updated_at"] or "",
        "updated_by": row["updated_by"] or "",
    }


def _template(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "kind": row["kind"],
        **_scope(row),
        "template_text": row["template_text"] or "",
        "description": row["description"] or "",
        "enabled": bool(row["enabled"]),
        **_stamps(row),
        "host_count": int(row["host_count"]),
    }


def _data(text: str | None) -> dict:
    try:
        data = json.loads(text or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _context(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "weight": int(row["weight"]),
        "data": _data(row["data"]),
        "description": row["description"] or "",
        "enabled": bool(row["enabled"]),
        **_scope(row),
        "host_id": _id(row["host_id"]),
        **_stamps(row),
        # Set when a Git source owns the context (read-only, see git-data-sources.md).
        "git_source_id": _id(row["git_source_id"]),
        "git_source_name": row["git_source_name"] or "",
        "git_path": row["git_path"] or "",
        "git_commit": row["git_commit"] or "",
    }


def _taken(what: str, name: str) -> ValueError:
    return ValueError(f"A {what} named '{name}' already exists.")


async def _name_taken(table: str, name: str, record_id: int | None) -> bool:
    rows = await _select(
        f"SELECT id FROM {table} WHERE lower(name) = lower(?)",  # nosec B608 - fixed table names
        (name,),
    )
    return any(int(r["id"]) != record_id for r in rows)


def _written(values: dict, user: str) -> dict:
    """The stored form of written values: ``enabled`` as 0/1, the update
    stamp."""
    out = dict(values)
    if "enabled" in out:
        out["enabled"] = 1 if out["enabled"] else 0
    out["updated_at"] = _now()
    out["updated_by"] = user or ""
    return out


# ── Templates ────────────────────────────────────────────────────────────────


async def list_config_templates(group_ids: Iterable[int] | None = None) -> list[dict]:
    """Every template by name, with ``host_count``: the hosts whose stored
    intended configuration came from it (``group_ids``: of those hosts, the
    ones in these inventory groups)."""
    sql, params = _template_select(group_ids)
    return [_template(r) for r in await _select(sql + _TEMPLATE_ORDER, params)]


async def get_config_template(template_id: int, group_ids: Iterable[int] | None = None) -> dict | None:
    sql, params = _template_select(group_ids)
    rows = await _select(sql + " WHERE t.id = ?", (*params, int(template_id)))
    return _template(rows[0]) if rows else None


async def create_config_template(values: dict, user: str = "") -> dict:
    """``values``: the writable fields (already validated). Raises
    ``ValueError`` when a template has the name, ignoring case."""
    taken = _taken("template", values["name"])
    if await _name_taken("config_templates", values["name"], None):
        raise taken
    new_id = await _insert("config_templates", _written(values, user), taken)
    return await _must(get_config_template(new_id))


async def update_config_template(template_id: int, values: dict, user: str = "") -> dict | None:
    """Replace the writable fields. ``None`` when the template does not
    exist; ``ValueError`` when another template has the name."""
    taken = _taken("template", values["name"])
    if await _name_taken("config_templates", values["name"], int(template_id)):
        raise taken
    if not await _update("config_templates", int(template_id), _written(values, user), taken):
        return None
    return await get_config_template(template_id)


async def delete_config_template(template_id: int) -> bool:
    return await _delete("config_templates", template_id)


# ── Contexts ─────────────────────────────────────────────────────────────────


async def list_config_contexts() -> list[dict]:
    """Every context by weight, then name; ``data`` parsed."""
    return [_context(r) for r in await _select(_CONTEXT_SELECT + _CONTEXT_ORDER)]


async def get_config_context(context_id: int) -> dict | None:
    rows = await _select(_CONTEXT_SELECT + " WHERE id = ?", (int(context_id),))
    return _context(rows[0]) if rows else None


async def create_config_context(values: dict, user: str = "") -> dict:
    """``values``: the writable fields with ``data`` as JSON text. Raises
    ``ValueError`` when a context has the name, ignoring case."""
    taken = _taken("context", values["name"])
    if await _name_taken("config_contexts", values["name"], None):
        raise taken
    new_id = await _insert("config_contexts", _written(values, user), taken)
    return await _must(get_config_context(new_id))


async def update_config_context(context_id: int, values: dict, user: str = "") -> dict | None:
    taken = _taken("context", values["name"])
    if await _name_taken("config_contexts", values["name"], int(context_id)):
        raise taken
    if not await _update("config_contexts", int(context_id), _written(values, user), taken):
        return None
    return await get_config_context(context_id)


async def delete_config_context(context_id: int) -> bool:
    return await _delete("config_contexts", context_id)


async def _delete(table: str, record_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(f"DELETE FROM {table} WHERE id = ?", (int(record_id),))  # nosec B608 - fixed table names
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


# ── Template variables (bulk reads) ──────────────────────────────────────────


async def list_vlan_records() -> list[dict]:
    """Every VLAN record (``vid``, ``name``, ``description``, ``site_id``)
    by VLAN id; without the counts ``list_vlans`` computes."""
    rows = await _select("SELECT vid, name, description, site_id FROM vlans ORDER BY vid, id")
    return [
        {
            "vid": int(r["vid"]),
            "name": r["name"] or "",
            "description": r["description"] or "",
            "site_id": _id(r["site_id"]),
        }
        for r in rows
    ]


async def get_vrfs_for_hosts(host_ids: Iterable[int]) -> dict[int, list[dict]]:
    """``host id -> [{name, rd, description}]``: the VRFs seen on each host
    (``host_vrfs``) with their record's route distinguisher and description,
    by name."""
    out: dict[int, list[dict]] = {}
    for chunk in _chunks(sorted({int(h) for h in host_ids})):
        rows = await _select(
            f"""SELECT hv.host_id, hv.vrf_name, vr.rd, vr.description FROM host_vrfs hv
                LEFT JOIN vrfs vr ON vr.name = hv.vrf_name
                WHERE hv.host_id IN ({_marks(chunk)}) ORDER BY hv.host_id, lower(hv.vrf_name), hv.vrf_name""",  # nosec B608 - placeholders only
            tuple(chunk),
        )
        for r in rows:
            out.setdefault(int(r["host_id"]), []).append(
                {"name": r["vrf_name"], "rd": r["rd"] or "", "description": r["description"] or ""}
            )
    return out


async def get_interfaces_for_hosts(host_ids: Iterable[int]) -> tuple[dict[int, list[dict]], dict[int, list[dict]]]:
    """The collected interface inventory of each host (``host id -> rows``
    by interface index) and its interface addresses (``host id -> rows``
    with ``interface_key``), two queries per chunk of hosts."""
    interfaces: dict[int, list[dict]] = {}
    addresses: dict[int, list[dict]] = {}
    for chunk in _chunks(sorted({int(h) for h in host_ids})):
        marks = _marks(chunk)
        for row in await _select(
            f"""SELECT host_id, name, description, admin_state, oper_state, speed_mbps, access_vlan, trunk_vlans
                FROM interface_inventory WHERE host_id IN ({marks}) ORDER BY host_id, if_index, id""",  # nosec B608 - placeholders only
            tuple(chunk),
        ):
            interfaces.setdefault(int(row["host_id"]), []).append(row)
        for row in await _select(
            f"""SELECT host_id, interface, interface_key, address, prefix_length, network, vrf_name, role
                FROM interface_addresses WHERE host_id IN ({marks}) ORDER BY host_id, interface, id""",  # nosec B608 - placeholders only
            tuple(chunk),
        ):
            addresses.setdefault(int(row["host_id"]), []).append(row)
    return interfaces, addresses


async def count_hosts() -> int:
    rows = await _select("SELECT COUNT(*) AS n FROM hosts")
    return int(rows[0]["n"])


# ── Intended configurations ──────────────────────────────────────────────────

_ROW_COLUMNS = """ic.host_id, h.hostname, h.ip_address, h.group_id, g.name AS group_name, ic.template_id,
    ic.template_name, ic.status, ic.error, ic.compliance, ic.missing_count, ic.extra_count, ic.backup_id,
    ic.generated_at, ic.changed_at, ic.compared_at"""
_ROW_FROM = """
    FROM intended_configs ic JOIN hosts h ON h.id = ic.host_id
    LEFT JOIN inventory_groups g ON g.id = h.group_id
"""
_ROW_SELECT = f"SELECT {_ROW_COLUMNS} {_ROW_FROM}"


def _row(row: dict) -> dict:
    return {
        "host_id": int(row["host_id"]),
        "hostname": row["hostname"] or "",
        "ip_address": row["ip_address"] or "",
        "group_id": _id(row["group_id"]),
        "group_name": row["group_name"] or "",
        "template_id": _id(row["template_id"]),
        "template_name": row["template_name"] or "",
        "status": row["status"],
        "error": row["error"] or None,
        "compliance": row["compliance"],
        "missing_count": int(row["missing_count"]),
        "extra_count": int(row["extra_count"]),
        "backup_id": _id(row["backup_id"]),
        "generated_at": row["generated_at"] or "",
        "changed_at": row["changed_at"] or "",
        "compared_at": row["compared_at"] or "",
    }


async def list_intended_configs(
    *,
    group_id: int | None = None,
    compliance: str | None = None,
    status: str | None = None,
    group_ids: Iterable[int] | None = None,
) -> list[dict]:
    """The stored rows (without the text) by host name; each filter given
    keeps only matching rows (``group_ids``: hosts in those inventory
    groups)."""
    clauses: list[str] = []
    params: list = []
    scope_sql, scope_params = group_ids_condition("h.group_id", group_ids)
    if scope_sql:
        clauses.append(scope_sql)
        params.extend(scope_params)
    for clause, value in (("h.group_id = ?", group_id), ("ic.compliance = ?", compliance), ("ic.status = ?", status)):
        if value is not None:
            clauses.append(clause)
            params.append(value)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await _select(_ROW_SELECT + where + " ORDER BY lower(h.hostname), ic.host_id", tuple(params))
    return [_row(r) for r in rows]


async def summarize_intended_configs(group_ids: Iterable[int] | None = None) -> dict[str, int]:
    """``{hosts, generated, errors, compliant, non_compliant, unknown,
    no_template}`` over every host (``group_ids``: the hosts in those
    inventory groups)."""
    scope_sql, scope_params = group_ids_condition("h.group_id", group_ids)
    scoped = f" JOIN hosts h ON h.id = ic.host_id WHERE {scope_sql}" if scope_sql else ""
    rows = await _select(
        f"""SELECT COUNT(*) AS generated,
                  SUM(CASE WHEN ic.status = 'error' THEN 1 ELSE 0 END) AS errors,
                  SUM(CASE WHEN ic.compliance = 'compliant' THEN 1 ELSE 0 END) AS compliant,
                  SUM(CASE WHEN ic.compliance = 'non_compliant' THEN 1 ELSE 0 END) AS non_compliant,
                  SUM(CASE WHEN ic.compliance = 'unknown' THEN 1 ELSE 0 END) AS unknown
           FROM intended_configs ic{scoped}""",  # nosec B608 - placeholders only
        scope_params,
    )
    if scope_sql:
        hosts = int((await _select(f"SELECT COUNT(*) AS n FROM hosts h WHERE {scope_sql}", scope_params))[0]["n"])  # nosec B608 - placeholders only
    else:
        hosts = await count_hosts()
    counts = {key: int(rows[0][key] or 0) for key in ("generated", "errors", "compliant", "non_compliant", "unknown")}
    return {"hosts": hosts, **counts, "no_template": max(0, hosts - counts["generated"])}


async def get_intended_config(host_id: int) -> dict | None:
    """The host's row with its ``config_text``, or ``None``."""
    rows = await _select(
        f"SELECT ic.config_text, {_ROW_COLUMNS} {_ROW_FROM} WHERE ic.host_id = ?",  # nosec B608 - fixed clauses
        (int(host_id),),
    )
    if not rows:
        return None
    return {**_row(rows[0]), "config_text": rows[0]["config_text"] or ""}


async def save_intended_config(host_id: int, values: dict) -> bool | None:
    """Write the host's row (``template_id``, ``template_name``, ``status``,
    ``error``, ``config_text``, ``compliance``, ``backup_id``,
    ``missing_count``, ``extra_count``). ``changed_at`` moves only when the
    text differs from the stored one. Returns whether the text changed
    (a new row counts as changed), or ``None`` when the host does not
    exist."""
    now = _now()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT 1 FROM hosts WHERE id = ?", (int(host_id),))
        if await cursor.fetchone() is None:
            return None
        cursor = await db.execute("SELECT config_text FROM intended_configs WHERE host_id = ?", (int(host_id),))
        old = await cursor.fetchone()
        changed = old is None or old["config_text"] != values["config_text"]
        params = (
            values["template_id"],
            values["template_name"],
            values["status"],
            values["error"] or "",
            values["config_text"],
            now,
            now,
            values["compliance"],
            values["backup_id"],
            int(values["missing_count"]),
            int(values["extra_count"]),
            now,
        )
        if old is None:
            await db.execute(
                """INSERT INTO intended_configs
                   (template_id, template_name, status, error, config_text, generated_at, changed_at, compliance,
                    backup_id, missing_count, extra_count, compared_at, host_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (host_id) DO NOTHING""",
                (*params, int(host_id)),
            )
        else:
            await db.execute(
                f"""UPDATE intended_configs SET template_id = ?, template_name = ?, status = ?, error = ?,
                       config_text = ?, generated_at = ?, changed_at = {"?" if changed else "changed_at"},
                       compliance = ?, backup_id = ?, missing_count = ?, extra_count = ?, compared_at = ?
                   WHERE host_id = ?""",  # nosec B608 - fixed clauses
                (*params[:6], *((params[6],) if changed else ()), *params[7:], int(host_id)),
            )
        await db.commit()
        return changed
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def set_intended_comparison(
    host_id: int, *, compliance: str, backup_id: int | None, missing_count: int, extra_count: int
) -> bool:
    """Record a new comparison of the host's stored intended configuration.
    ``False`` when the host has none."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """UPDATE intended_configs SET compliance = ?, backup_id = ?, missing_count = ?, extra_count = ?,
                   compared_at = ? WHERE host_id = ?""",
            (compliance, backup_id, int(missing_count), int(extra_count), _now(), int(host_id)),
        )
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def delete_intended_configs(host_ids: Iterable[int]) -> int:
    """Remove the rows of the hosts (they no longer match a template)."""
    removed = 0
    db = await _dbcore.get_db()
    try:
        for chunk in _chunks(sorted({int(h) for h in host_ids})):
            cursor = await db.execute(
                f"DELETE FROM intended_configs WHERE host_id IN ({_marks(chunk)})",  # nosec B608 - placeholders only
                tuple(chunk),
            )
            removed += int(cursor.rowcount or 0)
        await db.commit()
        return removed
    finally:
        await db.close()


async def _must(coro) -> dict:
    record = await coro
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record
