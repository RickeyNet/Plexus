"""Routing objects: autonomous systems, routing instances, BGP peer groups and
BGP peerings (the intended BGP state of devices), and the observed BGP
neighbors they are compared with.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables: migration 0101. Values arrive validated by the API
(``netcontrol.routing`` rules); this layer stores them, maps a duplicate to
``ValueError`` and wraps every write with ``tracks_changes`` so the change
log records it. The observed side is the ``topology_links`` rows neighbor
discovery writes (``protocol = 'bgp'``); nothing here polls a device.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import routes.database as _dbcore
from routes.database import _is_unique_violation, _safe_dynamic_update, rows_to_list
from routes.db.change_events import tracks_changes
from routes.db.custom_fields import _marks, _now

__all__ = [
    "autonomous_system_usage",
    "create_autonomous_system",
    "create_bgp_peer_group",
    "create_bgp_peering",
    "create_routing_instance",
    "delete_autonomous_system",
    "delete_bgp_peer_group",
    "delete_bgp_peering",
    "delete_routing_instance",
    "get_autonomous_system",
    "get_autonomous_system_by_asn",
    "get_bgp_peer_group",
    "get_bgp_peering",
    "get_routing_instance",
    "hosts_with_neighbor_discovery",
    "list_autonomous_systems",
    "list_bgp_peer_groups",
    "list_bgp_peerings",
    "list_routing_instances",
    "update_autonomous_system",
    "update_bgp_peer_group",
    "update_bgp_peering",
    "update_routing_instance",
]

_STAMP_COLUMNS = ("created_by", "created_at", "updated_by", "updated_at")


async def _select(sql: str, params: tuple | list = ()) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, tuple(params))
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def _one(sql: str, params: tuple | list) -> dict | None:
    rows = await _select(sql, params)
    return rows[0] if rows else None


async def _insert(table: str, values: dict, user: str, duplicate: str) -> int:
    """Insert one row with the stamps; ``ValueError(duplicate)`` on a unique
    violation. ``table`` and the keys of ``values`` are fixed by the callers."""
    now = _now()
    row = {**values, "created_by": user, "created_at": now, "updated_by": user, "updated_at": now}
    columns = list(row)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({_marks(columns)}) RETURNING id",  # nosec B608 - fixed names
            tuple(row[c] for c in columns),
        )
        new_id = int(cursor.lastrowid)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(duplicate) from exc
        raise
    finally:
        await db.close()
    return new_id


async def _update(table: str, row_id: int, values: dict, user: str, duplicate: str) -> bool:
    """Change the given columns and the update stamps; ``False`` when the row
    does not exist."""
    row = {**values, "updated_by": user, "updated_at": _now()}
    sql, params = _safe_dynamic_update(table, [f"{c} = ?" for c in row], list(row.values()), "id = ?", int(row_id))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return (cursor.rowcount or 0) > 0
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(duplicate) from exc
        raise
    finally:
        await db.close()


async def _delete(table: str, row_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(f"DELETE FROM {table} WHERE id = ?", (int(row_id),))  # nosec B608 - fixed names
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


def _like(search: str) -> str:
    escaped = search.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _stamps(row: dict) -> dict:
    return {c: row.get(c) or "" for c in _STAMP_COLUMNS}


def _int_or_none(value) -> int | None:
    return int(value) if value is not None else None


# ── Autonomous systems ───────────────────────────────────────────────────────

_AS_SELECT = """
    SELECT a.*, t.name AS tenant_name,
           (SELECT COUNT(*) FROM routing_instances ri WHERE ri.autonomous_system_id = a.id) AS instance_count,
           (SELECT COUNT(*) FROM bgp_peerings p WHERE p.remote_asn_id = a.id) AS peering_count
    FROM autonomous_systems a
    LEFT JOIN tenants t ON t.id = a.tenant_id
"""


def _as(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "asn": int(row["asn"]),
        "description": row.get("description") or "",
        "tenant_id": _int_or_none(row.get("tenant_id")),
        "tenant_name": row.get("tenant_name") or "",
        "rir": row.get("rir") or "",
        "comments": row.get("comments") or "",
        "instance_count": int(row.get("instance_count") or 0),
        "peering_count": int(row.get("peering_count") or 0),
        **_stamps(row),
    }


async def list_autonomous_systems(*, tenant_id: int | None = None, search: str | None = None) -> list[dict]:
    where: list[str] = []
    params: list = []
    if tenant_id is not None:
        where.append("a.tenant_id = ?")
        params.append(int(tenant_id))
    if search:
        where.append("(CAST(a.asn AS TEXT) LIKE ? OR lower(a.description) LIKE ? OR lower(a.rir) LIKE ?)")
        params += [_like(search)] * 3
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    return [_as(r) for r in await _select(_AS_SELECT + clause + " ORDER BY a.asn", params)]


async def get_autonomous_system(as_id: int) -> dict | None:
    row = await _one(_AS_SELECT + " WHERE a.id = ?", (int(as_id),))
    return _as(row) if row else None


async def get_autonomous_system_by_asn(asn: int) -> dict | None:
    row = await _one(_AS_SELECT + " WHERE a.asn = ?", (int(asn),))
    return _as(row) if row else None


@tracks_changes("autonomous_system", "create")
async def create_autonomous_system(
    *, asn: int, description: str = "", tenant_id: int | None = None, rir: str = "", comments: str = "", user: str = ""
) -> dict:
    """Raises ``ValueError`` when the AS number exists."""
    new_id = await _insert(
        "autonomous_systems",
        {"asn": int(asn), "description": description, "tenant_id": tenant_id, "rir": rir, "comments": comments},
        user,
        f"AS {asn} already exists.",
    )
    return await get_autonomous_system(new_id) or {"id": new_id}


@tracks_changes("autonomous_system", "update", id_arg="as_id")
async def update_autonomous_system(as_id: int, *, values: dict, user: str = "") -> dict | None:
    """``values``: any of description, tenant_id, rir, comments (the AS
    number never changes). ``None`` when it does not exist."""
    allowed = {k: values[k] for k in ("description", "tenant_id", "rir", "comments") if k in values}
    if not await _update("autonomous_systems", as_id, allowed, user, "AS already exists."):
        return None
    return await get_autonomous_system(as_id)


async def autonomous_system_usage(as_id: int) -> dict[str, int]:
    """What refers to the AS: routing instances (local AS), peerings (remote
    AS) and peer groups (remote AS)."""
    row = await _one(
        """SELECT (SELECT COUNT(*) FROM routing_instances WHERE autonomous_system_id = ?) AS routing_instances,
                  (SELECT COUNT(*) FROM bgp_peerings WHERE remote_asn_id = ?) AS bgp_peerings,
                  (SELECT COUNT(*) FROM bgp_peer_groups WHERE remote_asn_id = ?) AS bgp_peer_groups""",
        (int(as_id),) * 3,
    )
    return {k: int((row or {}).get(k) or 0) for k in ("routing_instances", "bgp_peerings", "bgp_peer_groups")}


@tracks_changes("autonomous_system", "delete", id_arg="as_id")
async def delete_autonomous_system(as_id: int) -> bool:
    return await _delete("autonomous_systems", as_id)


# ── Routing instances ────────────────────────────────────────────────────────

_INSTANCE_SELECT = """
    SELECT ri.*, h.hostname, h.tenant_id AS host_tenant_id, a.asn, a.tenant_id AS as_tenant_id,
           v.name AS vrf_name,
           (SELECT COUNT(*) FROM bgp_peerings p WHERE p.routing_instance_id = ri.id) AS peering_count,
           (SELECT COUNT(*) FROM bgp_peer_groups g WHERE g.routing_instance_id = ri.id) AS peer_group_count
    FROM routing_instances ri
    JOIN hosts h ON h.id = ri.host_id
    JOIN autonomous_systems a ON a.id = ri.autonomous_system_id
    LEFT JOIN vrfs v ON v.id = ri.vrf_id
"""


def _instance(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "host_id": int(row["host_id"]),
        "hostname": row.get("hostname") or "",
        "name": row["name"],
        "vrf_id": _int_or_none(row.get("vrf_id")),
        "vrf_name": row.get("vrf_name") or "",
        "autonomous_system_id": int(row["autonomous_system_id"]),
        "asn": int(row["asn"]),
        "router_id": row.get("router_id") or "",
        "status": row["status"],
        "description": row.get("description") or "",
        "peering_count": int(row.get("peering_count") or 0),
        "peer_group_count": int(row.get("peer_group_count") or 0),
        **_stamps(row),
    }


async def list_routing_instances(
    *,
    host_id: int | None = None,
    asn: int | None = None,
    status: str | None = None,
    tenant_id: int | None = None,
    search: str | None = None,
    scope_condition: tuple[str, tuple] = ("", ()),
) -> list[dict]:
    """Filters: the device, the local AS number, the status, the tenant (of
    the device or of the local AS) and text in the name, device or
    description. ``scope_condition``: an object scope SQL condition on
    alias ``ri`` (``object_scope.sql_condition("routing_instance", ...)``)."""
    where: list[str] = [scope_condition[0]] if scope_condition[0] else []
    params: list = list(scope_condition[1])
    if host_id is not None:
        where.append("ri.host_id = ?")
        params.append(int(host_id))
    if asn is not None:
        where.append("a.asn = ?")
        params.append(int(asn))
    if status:
        where.append("ri.status = ?")
        params.append(status)
    if tenant_id is not None:
        where.append("(h.tenant_id = ? OR a.tenant_id = ?)")
        params += [int(tenant_id)] * 2
    if search:
        where.append("(lower(ri.name) LIKE ? OR lower(h.hostname) LIKE ? OR lower(ri.description) LIKE ?)")
        params += [_like(search)] * 3
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    rows = await _select(_INSTANCE_SELECT + clause + " ORDER BY lower(h.hostname), lower(ri.name), ri.id", params)
    return [_instance(r) for r in rows]


async def get_routing_instance(instance_id: int) -> dict | None:
    row = await _one(_INSTANCE_SELECT + " WHERE ri.id = ?", (int(instance_id),))
    return _instance(row) if row else None


_INSTANCE_COLUMNS = ("name", "vrf_id", "autonomous_system_id", "router_id", "status", "description")


@tracks_changes("routing_instance", "create")
async def create_routing_instance(*, host_id: int, values: dict, user: str = "") -> dict:
    """``values``: name, autonomous_system_id and optionally vrf_id,
    router_id, status, description. ``ValueError`` when the device has an
    instance of that name (ignoring case)."""
    row = {"host_id": int(host_id), **{k: values[k] for k in _INSTANCE_COLUMNS if k in values}}
    new_id = await _insert(
        "routing_instances", row, user, f"This device already has a routing instance named '{values.get('name')}'."
    )
    return await get_routing_instance(new_id) or {"id": new_id}


@tracks_changes("routing_instance", "update", id_arg="instance_id")
async def update_routing_instance(instance_id: int, *, values: dict, user: str = "") -> dict | None:
    allowed = {k: values[k] for k in _INSTANCE_COLUMNS if k in values}
    taken = f"This device already has a routing instance named '{values.get('name')}'."
    if not await _update("routing_instances", instance_id, allowed, user, taken):
        return None
    return await get_routing_instance(instance_id)


@tracks_changes("routing_instance", "delete", id_arg="instance_id")
async def delete_routing_instance(instance_id: int) -> bool:
    """Deletes its peer groups and peerings with it."""
    return await _delete("routing_instances", instance_id)


# ── BGP peer groups ──────────────────────────────────────────────────────────

_GROUP_SELECT = """
    SELECT g.*, ri.name AS routing_instance_name, ri.host_id, h.hostname, ra.asn AS remote_asn,
           (SELECT COUNT(*) FROM bgp_peerings p WHERE p.peer_group_id = g.id) AS peering_count
    FROM bgp_peer_groups g
    JOIN routing_instances ri ON ri.id = g.routing_instance_id
    JOIN hosts h ON h.id = ri.host_id
    LEFT JOIN autonomous_systems ra ON ra.id = g.remote_asn_id
"""


def _group(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "routing_instance_id": int(row["routing_instance_id"]),
        "routing_instance_name": row.get("routing_instance_name") or "",
        "host_id": int(row["host_id"]),
        "hostname": row.get("hostname") or "",
        "name": row["name"],
        "remote_asn_id": _int_or_none(row.get("remote_asn_id")),
        "remote_asn": _int_or_none(row.get("remote_asn")),
        "import_policy": row.get("import_policy") or "",
        "export_policy": row.get("export_policy") or "",
        "description": row.get("description") or "",
        "peering_count": int(row.get("peering_count") or 0),
        **_stamps(row),
    }


async def list_bgp_peer_groups(
    *,
    routing_instance_id: int | None = None,
    host_id: int | None = None,
    search: str | None = None,
    scope_condition: tuple[str, tuple] = ("", ()),
) -> list[dict]:
    """``scope_condition``: an object scope SQL condition on alias ``ri``
    (the group's routing instance)."""
    where: list[str] = [scope_condition[0]] if scope_condition[0] else []
    params: list = list(scope_condition[1])
    if routing_instance_id is not None:
        where.append("g.routing_instance_id = ?")
        params.append(int(routing_instance_id))
    if host_id is not None:
        where.append("ri.host_id = ?")
        params.append(int(host_id))
    if search:
        where.append("(lower(g.name) LIKE ? OR lower(h.hostname) LIKE ? OR lower(g.description) LIKE ?)")
        params += [_like(search)] * 3
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    rows = await _select(_GROUP_SELECT + clause + " ORDER BY lower(h.hostname), lower(ri.name), lower(g.name)", params)
    return [_group(r) for r in rows]


async def get_bgp_peer_group(group_id: int) -> dict | None:
    row = await _one(_GROUP_SELECT + " WHERE g.id = ?", (int(group_id),))
    return _group(row) if row else None


_GROUP_COLUMNS = ("name", "remote_asn_id", "import_policy", "export_policy", "description")


@tracks_changes("bgp_peer_group", "create")
async def create_bgp_peer_group(*, routing_instance_id: int, values: dict, user: str = "") -> dict:
    row = {"routing_instance_id": int(routing_instance_id), **{k: values[k] for k in _GROUP_COLUMNS if k in values}}
    taken = f"This routing instance already has a peer group named '{values.get('name')}'."
    new_id = await _insert("bgp_peer_groups", row, user, taken)
    return await get_bgp_peer_group(new_id) or {"id": new_id}


@tracks_changes("bgp_peer_group", "update", id_arg="group_id")
async def update_bgp_peer_group(group_id: int, *, values: dict, user: str = "") -> dict | None:
    allowed = {k: values[k] for k in _GROUP_COLUMNS if k in values}
    taken = f"This routing instance already has a peer group named '{values.get('name')}'."
    if not await _update("bgp_peer_groups", group_id, allowed, user, taken):
        return None
    return await get_bgp_peer_group(group_id)


@tracks_changes("bgp_peer_group", "delete", id_arg="group_id")
async def delete_bgp_peer_group(group_id: int) -> bool:
    """Its peerings stay, without a group."""
    return await _delete("bgp_peer_groups", group_id)


# ── BGP peerings ─────────────────────────────────────────────────────────────

_PEERING_SELECT = """
    SELECT p.*, ri.name AS routing_instance_name, ri.host_id, h.hostname, la.asn AS local_asn,
           ra.asn AS remote_asn, ra.tenant_id AS remote_tenant_id, g.name AS peer_group_name,
           rh.hostname AS remote_hostname
    FROM bgp_peerings p
    JOIN routing_instances ri ON ri.id = p.routing_instance_id
    JOIN hosts h ON h.id = ri.host_id
    JOIN autonomous_systems la ON la.id = ri.autonomous_system_id
    JOIN autonomous_systems ra ON ra.id = p.remote_asn_id
    LEFT JOIN bgp_peer_groups g ON g.id = p.peer_group_id
    LEFT JOIN hosts rh ON rh.id = p.remote_host_id
"""


def _peering(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "routing_instance_id": int(row["routing_instance_id"]),
        "routing_instance_name": row.get("routing_instance_name") or "",
        "host_id": int(row["host_id"]),
        "hostname": row.get("hostname") or "",
        "local_asn": int(row["local_asn"]),
        "peer_group_id": _int_or_none(row.get("peer_group_id")),
        "peer_group_name": row.get("peer_group_name") or "",
        "local_address": row.get("local_address") or "",
        "remote_address": row["remote_address"],
        "remote_asn_id": int(row["remote_asn_id"]),
        "remote_asn": int(row["remote_asn"]),
        "remote_host_id": _int_or_none(row.get("remote_host_id")),
        "remote_hostname": row.get("remote_hostname") or "",
        "status": row["status"],
        "address_families": [f for f in str(row.get("address_families") or "").split(",") if f],
        "import_policy": row.get("import_policy") or "",
        "export_policy": row.get("export_policy") or "",
        "description": row.get("description") or "",
        **_stamps(row),
    }


async def list_bgp_peerings(
    *,
    host_id: int | None = None,
    host_ids: list[int] | None = None,
    routing_instance_id: int | None = None,
    asn: int | None = None,
    status: str | None = None,
    tenant_id: int | None = None,
    search: str | None = None,
    scope_condition: tuple[str, tuple] = ("", ()),
) -> list[dict]:
    """Filters: the device, several devices, the instance, an AS number (the
    local or the remote AS), the status, the tenant (of the device or of
    the remote AS) and text in the addresses, device, peer group or
    description. ``scope_condition``: an object scope SQL condition on
    alias ``ri`` (the peering's routing instance)."""
    where: list[str] = [scope_condition[0]] if scope_condition[0] else []
    params: list = list(scope_condition[1])
    if host_id is not None:
        where.append("ri.host_id = ?")
        params.append(int(host_id))
    if host_ids is not None:
        if not host_ids:
            return []
        where.append(f"ri.host_id IN ({_marks(host_ids)})")
        params += [int(h) for h in host_ids]
    if routing_instance_id is not None:
        where.append("p.routing_instance_id = ?")
        params.append(int(routing_instance_id))
    if asn is not None:
        where.append("(la.asn = ? OR ra.asn = ?)")
        params += [int(asn)] * 2
    if status:
        where.append("p.status = ?")
        params.append(status)
    if tenant_id is not None:
        where.append("(h.tenant_id = ? OR ra.tenant_id = ?)")
        params += [int(tenant_id)] * 2
    if search:
        where.append(
            "(lower(p.remote_address) LIKE ? OR lower(p.local_address) LIKE ? OR lower(h.hostname) LIKE ?"
            " OR lower(COALESCE(g.name, '')) LIKE ? OR lower(p.description) LIKE ?)"
        )
        params += [_like(search)] * 5
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    rows = await _select(
        _PEERING_SELECT + clause + " ORDER BY lower(h.hostname), lower(ri.name), p.remote_address, p.id", params
    )
    return [_peering(r) for r in rows]


async def get_bgp_peering(peering_id: int) -> dict | None:
    row = await _one(_PEERING_SELECT + " WHERE p.id = ?", (int(peering_id),))
    return _peering(row) if row else None


_PEERING_COLUMNS = (
    "peer_group_id",
    "local_address",
    "remote_address",
    "remote_asn_id",
    "remote_host_id",
    "status",
    "address_families",
    "import_policy",
    "export_policy",
    "description",
)


def _peering_taken(values: dict) -> str:
    return f"This routing instance already has a peering with {values.get('remote_address')}."


@tracks_changes("bgp_peering", "create")
async def create_bgp_peering(*, routing_instance_id: int, values: dict, user: str = "") -> dict:
    """``values``: remote_address, remote_asn_id and optionally the other
    columns (``address_families`` comma-separated text). ``ValueError``
    when the instance has a peering with that remote address."""
    row = {"routing_instance_id": int(routing_instance_id), **{k: values[k] for k in _PEERING_COLUMNS if k in values}}
    new_id = await _insert("bgp_peerings", row, user, _peering_taken(values))
    return await get_bgp_peering(new_id) or {"id": new_id}


@tracks_changes("bgp_peering", "update", id_arg="peering_id")
async def update_bgp_peering(peering_id: int, *, values: dict, user: str = "") -> dict | None:
    allowed = {k: values[k] for k in _PEERING_COLUMNS if k in values}
    if not await _update("bgp_peerings", peering_id, allowed, user, _peering_taken(values)):
        return None
    return await get_bgp_peering(peering_id)


@tracks_changes("bgp_peering", "delete", id_arg="peering_id")
async def delete_bgp_peering(peering_id: int) -> bool:
    return await _delete("bgp_peerings", peering_id)


# ── Observed data ───────────────────────────────────────────────────


async def hosts_with_neighbor_discovery(host_ids: list[int] | None = None) -> dict[int, str]:
    """The hosts whose neighbors were discovered at least once (a stored
    neighbor of any protocol, or polled interface counters), each with the
    newest time a neighbor was stored ('' when only counters exist)."""
    filter_links = filter_stats = ""
    params: list = []
    if host_ids is not None:
        if not host_ids:
            return {}
        filter_links = f" WHERE source_host_id IN ({_marks(host_ids)})"
        filter_stats = f" WHERE host_id IN ({_marks(host_ids)})"
        params = [int(h) for h in host_ids] * 2
    rows = await _select(
        f"""SELECT host_id, MAX(seen) AS seen FROM (
                SELECT source_host_id AS host_id, MAX(discovered_at) AS seen FROM topology_links{filter_links}
                GROUP BY source_host_id
                UNION ALL
                SELECT DISTINCT host_id, '' AS seen FROM interface_stats{filter_stats}
            ) d GROUP BY host_id""",  # nosec B608 - fixed clauses, values bound
        params,
    )
    return {int(r["host_id"]): str(r.get("seen") or "") for r in rows}
