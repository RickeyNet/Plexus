"""IPAM namespaces, route targets, VLAN groups, RIRs and aggregates.

Star re-exported by routes/database.py. Tables: migration 0110. The five
record kinds live in the generic record store of ``routes.db.dcim``
(``register_record_kind``): list, get, create, update and delete go through
``list_dcim_records(kind, ...)`` and friends with the kinds ``namespace``,
``route_target``, ``vlan_group``, ``rir`` and ``aggregate``; each write
emits an object-change event. This module adds the rules checked inside a
write's transaction and the queries that span records: a VRF's import and
export route targets, a VLAN group's VLAN ids, the aggregate that holds a
prefix and each aggregate's utilisation, the prefixes of a namespace and
the namespace and VRF uniqueness of a prefix.

Rules: ``netcontrol.ipam_model``. Timestamps are UTC ``YYYY-MM-DD
HH:MM:SS`` text.
"""

from __future__ import annotations

from collections.abc import Iterable

from netcontrol.integrations.pathtrace.model import contains, net
from netcontrol.ipam_model import (
    GLOBAL_NAMESPACE_ID,
    RT_DIRECTIONS,
    aggregate_usage,
    containing_aggregate,
    next_free_vid,
)

import routes.database as _dbcore
from routes.database import rows_to_list
from routes.db.custom_fields import _marks
from routes.db.dcim import DcimRuleError, RecordKind, get_dcim_record, list_dcim_records, register_record_kind
from routes.db.organization import region_subtree_sql

__all__ = [
    "IPAM_MODEL_KINDS",
    "aggregate_for_subnet",
    "find_namespace_prefix",
    "get_aggregate_detail",
    "get_namespace_detail",
    "get_vlan_group_detail",
    "get_route_targets_by_vrf_ids",
    "get_vrf_route_targets",
    "list_aggregates_with_usage",
    "list_route_target_vrfs",
    "next_vlan_group_vid",
    "set_prefix_namespace",
    "set_vrf_route_targets",
    "vlan_group_problem",
    "vrf_namespace_id",
    "with_vlan_group_scope",
]

IPAM_MODEL_KINDS: tuple[str, ...] = ("namespace", "route_target", "vlan_group", "rir", "aggregate")


async def _select(sql: str, params: tuple = ()) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def _all(db, sql: str, params: tuple = ()) -> list[dict]:
    cursor = await db.execute(sql, params)
    return rows_to_list(await cursor.fetchall())


async def _merged(db, table: str, record_id: int | None, values: dict) -> dict:
    if record_id is None:
        return dict(values)
    rows = await _all(db, f"SELECT * FROM {table} WHERE id = ?", (int(record_id),))  # nosec B608 - fixed table names
    return {**(rows[0] if rows else {}), **values}


# ── Rules checked inside a write ─────────────────────────────────────────────


async def vlan_group_problem(db, group: dict, vlans: list[dict]) -> str | None:
    """Why the VLANs (rows with ``vid`` and ``site_id``) cannot be in the
    group (a row with ``name``, ``min_vid``, ``max_vid``, ``site_id``,
    ``region_id``), or ``None``. A VLAN of no site fits any scope."""
    low, high = int(group["min_vid"]), int(group["max_vid"])
    outside = sorted(int(v["vid"]) for v in vlans if not low <= int(v["vid"]) <= high)
    if outside:
        return f"VLAN group '{group['name']}' takes VLAN ids {low} to {high}; VLAN {outside[0]} is outside that range."
    sites = {int(v["site_id"]) for v in vlans if v.get("site_id") is not None}
    if not sites:
        return None
    if group.get("site_id") is not None:
        other = sorted(s for s in sites if s != int(group["site_id"]))
        if other:
            return f"VLAN group '{group['name']}' is scoped to one site; a VLAN of another site cannot be in it."
    elif group.get("region_id") is not None:
        rows = await _all(
            db,
            f"SELECT id FROM geo_sites WHERE region_id IN {region_subtree_sql()}",  # nosec B608 - fixed clauses
            (int(group["region_id"]),),
        )
        allowed = {int(r["id"]) for r in rows}
        if sites - allowed:
            return f"VLAN group '{group['name']}' is scoped to a region; a VLAN of a site outside it cannot be in it."
    return None


async def _check_vlan_group(db, record_id: int | None, values: dict) -> None:
    group = await _merged(db, "vlan_groups", record_id, values)
    if group.get("site_id") is not None and group.get("region_id") is not None:
        raise DcimRuleError("Scope a VLAN group to a site or a region, not both.")
    if record_id is None:
        return
    vlans = await _all(db, "SELECT vid, site_id FROM vlans WHERE vlan_group_id = ?", (int(record_id),))
    problem = await vlan_group_problem(db, group, vlans)
    if problem:
        raise DcimRuleError(problem)


async def _check_aggregate(db, record_id: int | None, values: dict) -> None:
    if "prefix" not in values:
        return
    mine = net(values["prefix"])
    if mine is None:  # pragma: no cover - the API cleans the prefix first
        raise DcimRuleError("Prefix must be a network in CIDR form.")
    for row in await _all(db, "SELECT id, prefix FROM aggregates WHERE id <> ? FOR UPDATE", (int(record_id or 0),)):
        other = net(row["prefix"])
        if other is not None and other.version == mine.version and other.overlaps(mine):  # type: ignore[arg-type]
            raise DcimRuleError(f"The prefix overlaps aggregate {row['prefix']}.")


# ── Record kinds ─────────────────────────────────────────────────────────────

_STAMPED = "lower(x.name), x.id"

register_record_kind(
    "namespace",
    RecordKind(
        table="ipam_namespaces",
        alias="x",
        label="namespace",
        select="""SELECT x.*, (SELECT COUNT(*) FROM vrfs v WHERE v.namespace_id = x.id) AS vrf_count,
                         (SELECT COUNT(*) FROM ipam_prefixes p WHERE p.namespace_id = x.id) AS prefix_count
                  FROM ipam_namespaces x""",
        order=f"x.id <> {GLOBAL_NAMESPACE_ID}, {_STAMPED}",
        filters={},
        search=("x.name", "x.description"),
        unique_message="A namespace named '{name}' already exists.",
    ),
    usage=(
        ("VRFs", "SELECT COUNT(*) AS n FROM vrfs WHERE namespace_id = ?", False),
        ("prefixes", "SELECT COUNT(*) AS n FROM ipam_prefixes WHERE namespace_id = ?", False),
    ),
)
register_record_kind(
    "route_target",
    RecordKind(
        table="route_targets",
        alias="x",
        label="route target",
        select="""SELECT x.*, t.name AS tenant_name,
                         (SELECT COUNT(*) FROM vrf_route_targets l
                          WHERE l.route_target_id = x.id AND l.direction = 'import') AS import_vrf_count,
                         (SELECT COUNT(*) FROM vrf_route_targets l
                          WHERE l.route_target_id = x.id AND l.direction = 'export') AS export_vrf_count
                  FROM route_targets x LEFT JOIN tenants t ON t.id = x.tenant_id""",
        order=_STAMPED,
        filters={
            "tenant_id": "x.tenant_id = ?",
            "vrf_id": "x.id IN (SELECT route_target_id FROM vrf_route_targets WHERE vrf_id = ?)",
        },
        search=("x.name", "x.description"),
        unique_message="Route target {name} already exists.",
    ),
)
register_record_kind(
    "vlan_group",
    RecordKind(
        table="vlan_groups",
        alias="x",
        label="VLAN group",
        select="""SELECT x.*, s.name AS site_name, r.name AS region_name,
                         (SELECT COUNT(*) FROM vlans v WHERE v.vlan_group_id = x.id) AS vlan_count
                  FROM vlan_groups x
                  LEFT JOIN geo_sites s ON s.id = x.site_id
                  LEFT JOIN regions r ON r.id = x.region_id""",
        order=_STAMPED,
        filters={"site_id": "x.site_id = ?", "region_id": "x.region_id = ?"},
        search=("x.name", "x.description"),
        unique_message="A VLAN group named '{name}' already exists.",
    ),
    _check_vlan_group,
)
register_record_kind(
    "rir",
    RecordKind(
        table="rirs",
        alias="x",
        label="RIR",
        select="""SELECT x.*, (SELECT COUNT(*) FROM aggregates a WHERE a.rir_id = x.id) AS aggregate_count
                  FROM rirs x""",
        order=_STAMPED,
        filters={"is_private": "x.is_private = ?"},
        search=("x.name", "x.description"),
        unique_message="A RIR named '{name}' already exists.",
        bool_columns=("is_private",),
    ),
    usage=(("aggregates", "SELECT COUNT(*) AS n FROM aggregates WHERE rir_id = ?", False),),
)
register_record_kind(
    "aggregate",
    RecordKind(
        table="aggregates",
        alias="x",
        label="aggregate",
        select="""SELECT x.*, r.name AS rir_name, r.is_private AS rir_is_private, t.name AS tenant_name
                  FROM aggregates x JOIN rirs r ON r.id = x.rir_id LEFT JOIN tenants t ON t.id = x.tenant_id""",
        order="family(x.prefix::cidr), x.prefix::cidr, x.id",
        filters={"rir_id": "x.rir_id = ?", "tenant_id": "x.tenant_id = ?"},
        search=("x.prefix", "x.description", "r.name"),
        unique_message="An aggregate for this prefix already exists.",
        bool_columns=("rir_is_private",),
    ),
    _check_aggregate,
)


# ── Namespaces and prefixes ──────────────────────────────────────────────────


async def find_namespace_prefix(namespace_id: int, vrf: str, subnet: str, source_id: int | None = None) -> dict | None:
    """The prefix ``subnet`` (CIDR text as stored) of the namespace and VRF
    (exact name; ``''`` the global VRF), of one source when given."""
    sql = "SELECT * FROM ipam_prefixes WHERE namespace_id = ? AND vrf = ? AND subnet = ?"
    params: list = [int(namespace_id), vrf, subnet]
    if source_id is not None:
        sql += " AND source_id = ?"
        params.append(int(source_id))
    rows = await _select(sql + " ORDER BY id LIMIT 1", tuple(params))
    return rows[0] if rows else None


async def vrf_namespace_id(name: str) -> int | None:
    """The namespace of the VRF record named ``name`` (exact name); ``None``
    when there is no such record."""
    rows = await _select("SELECT namespace_id FROM vrfs WHERE name = ?", (name,))
    return int(rows[0]["namespace_id"]) if rows else None


async def set_prefix_namespace(prefix_id: int, namespace_id: int) -> dict | None:
    """Move a prefix to another namespace; ``None`` when it does not exist,
    ``ValueError`` when the namespace has the prefix in its VRF already."""
    db = await _dbcore.get_db()
    try:
        rows = await _all(db, "SELECT * FROM ipam_prefixes WHERE id = ? FOR UPDATE", (int(prefix_id),))
        if not rows:
            await db.rollback()
            return None
        prefix = rows[0]
        clash = await _all(
            db,
            "SELECT id FROM ipam_prefixes WHERE namespace_id = ? AND vrf = ? AND subnet = ? AND source_id = ? AND id <> ?",
            (int(namespace_id), prefix["vrf"], prefix["subnet"], int(prefix["source_id"]), int(prefix_id)),
        )
        if clash:
            await db.rollback()
            raise ValueError(f"The namespace already has {prefix['subnet']} in this VRF.")
        await db.execute("UPDATE ipam_prefixes SET namespace_id = ? WHERE id = ?", (int(namespace_id), int(prefix_id)))
        await db.commit()
    finally:
        await db.close()
    rows = await _select("SELECT * FROM ipam_prefixes WHERE id = ?", (int(prefix_id),))
    return rows[0] if rows else None


async def get_namespace_detail(namespace_id: int, limit: int = 2000) -> dict | None:
    """A namespace with its VRFs and prefixes (at most ``limit``;
    ``truncated`` when more exist)."""
    namespace = await get_dcim_record("namespace", namespace_id)
    if namespace is None:
        return None
    vrfs = await _select(
        "SELECT id, name, rd, tenant_id FROM vrfs WHERE namespace_id = ? ORDER BY lower(name), id", (int(namespace_id),)
    )
    prefixes = await _select(
        """SELECT p.id, p.subnet, p.vrf, p.description, p.tenant_id, s.provider AS source FROM ipam_prefixes p
           JOIN ipam_sources s ON s.id = p.source_id WHERE p.namespace_id = ?
           ORDER BY p.vrf, p.subnet, p.id LIMIT ?""",
        (int(namespace_id), int(limit) + 1),
    )
    return {
        **namespace,
        "vrfs": vrfs,
        "prefixes": prefixes[:limit],
        "truncated": len(prefixes) > limit,
    }


# ── Route targets ────────────────────────────────────────────────────────────


async def get_vrf_route_targets(vrf_id: int) -> dict[str, list[dict]]:
    """``{"import": [...], "export": [...]}``: the route targets of a VRF
    (``id``, ``name``, ``description``, ``tenant_id``), by name."""
    found = await get_route_targets_by_vrf_ids([int(vrf_id)])
    return found.get(int(vrf_id)) or {d: [] for d in RT_DIRECTIONS}


async def get_route_targets_by_vrf_ids(vrf_ids: Iterable[int] | None = None) -> dict[int, dict[str, list[dict]]]:
    """VRF id -> ``get_vrf_route_targets`` of it, for the VRFs of
    ``vrf_ids`` (``None``: every VRF with a route target), in one query.
    VRFs with no route target are absent."""
    sql = """SELECT l.vrf_id, l.direction, r.id, r.name, r.description, r.tenant_id FROM vrf_route_targets l
             JOIN route_targets r ON r.id = l.route_target_id"""
    params: tuple = ()
    if vrf_ids is not None:
        ids = sorted({int(v) for v in vrf_ids})
        if not ids:
            return {}
        sql += f" WHERE l.vrf_id IN ({_marks(ids)})"
        params = tuple(ids)
    out: dict[int, dict[str, list[dict]]] = {}
    for row in await _select(sql + " ORDER BY lower(r.name), r.id", params):  # nosec B608 - placeholders only
        entry = out.setdefault(int(row["vrf_id"]), {d: [] for d in RT_DIRECTIONS})
        entry[row["direction"]].append(
            {
                "id": int(row["id"]),
                "name": row["name"],
                "description": row["description"],
                "tenant_id": row["tenant_id"],
            }
        )
    return out


async def set_vrf_route_targets(vrf_id: int, import_ids: Iterable[int], export_ids: Iterable[int]) -> list[int]:
    """Replace the import and export route targets of a VRF. Returns the ids
    that name no route target (nothing is written then)."""
    wanted = {"import": sorted({int(i) for i in import_ids}), "export": sorted({int(i) for i in export_ids})}
    every = sorted(set(wanted["import"]) | set(wanted["export"]))
    db = await _dbcore.get_db()
    try:
        if every:
            found = await _all(db, f"SELECT id FROM route_targets WHERE id IN ({_marks(every)})", tuple(every))  # nosec B608 - placeholders only
            missing = sorted(set(every) - {int(r["id"]) for r in found})
            if missing:
                await db.rollback()
                return missing
        await db.execute("DELETE FROM vrf_route_targets WHERE vrf_id = ?", (int(vrf_id),))
        for direction, ids in wanted.items():
            for rt_id in ids:
                await db.execute(
                    "INSERT INTO vrf_route_targets (vrf_id, route_target_id, direction) VALUES (?, ?, ?)",
                    (int(vrf_id), rt_id, direction),
                )
        await db.commit()
        return []
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def list_route_target_vrfs(route_target_id: int) -> list[dict]:
    """The VRFs that import or export a route target: ``vrf_id``, ``name``,
    ``direction``."""
    return await _select(
        """SELECT v.id AS vrf_id, v.name, v.tenant_id, l.direction FROM vrf_route_targets l JOIN vrfs v ON v.id = l.vrf_id
           WHERE l.route_target_id = ? ORDER BY lower(v.name), l.direction""",
        (int(route_target_id),),
    )


# ── VLAN groups ──────────────────────────────────────────────────────────────


async def next_vlan_group_vid(group_id: int) -> int | None:
    """The lowest free VLAN id of the group's range; ``None`` when the group
    is full. ``LookupError`` when it does not exist."""
    groups = await _select("SELECT min_vid, max_vid FROM vlan_groups WHERE id = ?", (int(group_id),))
    if not groups:
        raise LookupError(group_id)
    used = await _select("SELECT vid FROM vlans WHERE vlan_group_id = ?", (int(group_id),))
    return next_free_vid(int(groups[0]["min_vid"]), int(groups[0]["max_vid"]), (int(r["vid"]) for r in used))


async def with_vlan_group_scope(groups: Iterable[dict]) -> list[dict]:
    """The VLAN groups with ``scope_site_ids``: the group's site, or the
    sites of its region and the regions under it (empty for a group of no
    scope, or of a region with no site). The object scope model
    ``vlan_group`` reads it."""
    rows = [dict(g) for g in groups]
    regions = sorted({int(g["region_id"]) for g in rows if g.get("site_id") is None and g.get("region_id") is not None})
    sites_of: dict[int, list[int]] = {}
    for region_id in regions:
        found = await _select(
            f"SELECT id FROM geo_sites WHERE region_id IN {region_subtree_sql()} ORDER BY id",  # nosec B608 - fixed clauses
            (region_id,),
        )
        sites_of[region_id] = [int(r["id"]) for r in found]
    for g in rows:
        if g.get("site_id") is not None:
            g["scope_site_ids"] = [int(g["site_id"])]
        elif g.get("region_id") is not None:
            g["scope_site_ids"] = sites_of.get(int(g["region_id"]), [])
        else:
            g["scope_site_ids"] = []
    return rows


async def get_vlan_group_detail(group_id: int) -> dict | None:
    """A VLAN group with its VLANs (``id``, ``vid``, ``name``, ``site_id``),
    ``available`` (free ids in its range) and ``next_vid``."""
    group = await get_dcim_record("vlan_group", group_id)
    if group is None:
        return None
    vlans = await _select(
        "SELECT id, vid, name, site_id, tenant_id FROM vlans WHERE vlan_group_id = ? ORDER BY vid, id", (int(group_id),)
    )
    size = int(group["max_vid"]) - int(group["min_vid"]) + 1
    used = [int(v["vid"]) for v in vlans]
    return {
        **group,
        "vlans": vlans,
        "available": size - len(set(used)),
        "next_vid": next_free_vid(int(group["min_vid"]), int(group["max_vid"]), used),
    }


# ── Aggregates ───────────────────────────────────────────────────────────────


async def _prefix_subnets() -> list[str]:
    rows = await _select("SELECT DISTINCT subnet FROM ipam_prefixes")
    return [str(r["subnet"]) for r in rows]


async def list_aggregates_with_usage(filters: dict | None = None, q: str = "") -> list[dict]:
    """The aggregates (``list_dcim_records``) with ``prefix_count``,
    ``total_addresses``, ``used_addresses`` and ``utilization_pct``: how much
    of each the IPAM prefixes of every namespace and source cover."""
    rows = await list_dcim_records("aggregate", filters or {}, q)
    subnets = await _prefix_subnets() if rows else []
    return [{**row, **aggregate_usage(row["prefix"], subnets)} for row in rows]


async def aggregate_for_subnet(subnet: str) -> dict | None:
    """The aggregate that holds ``subnet`` (the most specific), with its
    usage; ``None`` when none does."""
    rows = await list_dcim_records("aggregate", {}, "")
    found = containing_aggregate(subnet, rows)
    if found is None:
        return None
    return {**found, **aggregate_usage(found["prefix"], await _prefix_subnets())}


async def get_aggregate_detail(aggregate_id: int, limit: int = 2000) -> dict | None:
    """The aggregate with its usage and the IPAM prefixes inside it (``id``,
    ``subnet``, ``vrf``, ``namespace_id``, ``source``; at most ``limit``,
    ``truncated`` when more exist)."""
    record = await get_dcim_record("aggregate", aggregate_id)
    if record is None:
        return None
    outer = net(record["prefix"])
    rows = await _select(
        """SELECT p.id, p.subnet, p.vrf, p.namespace_id, p.tenant_id, s.provider AS source FROM ipam_prefixes p
           JOIN ipam_sources s ON s.id = p.source_id ORDER BY p.subnet, p.id"""
    )
    inside = []
    for row in rows:
        inner = net(row["subnet"])
        if outer is not None and inner is not None and contains(outer, inner):
            inside.append(row)
    usage = aggregate_usage(record["prefix"], {str(r["subnet"]) for r in inside})
    return {**record, **usage, "prefixes": inside[:limit], "truncated": len(inside) > limit}
