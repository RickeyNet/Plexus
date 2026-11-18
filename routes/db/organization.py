"""Location hierarchy and tenancy: regions, tenant groups and tenants.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables: migration 0098. Regions and tenant groups are trees (``parent_id``);
the location tree is region > region ... > site (``geo_sites``) > floor
(``geo_floors``). A tenant owns rows of every table with a ``tenant_id``
column (hosts, prefixes, IP addresses, VLANs, VRFs, sites and whatever later
migrations add); deleting a tenant clears those columns (``ON DELETE SET
NULL``).

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, Final

import routes.database as _dbcore
from routes.database import _is_unique_violation, _safe_dynamic_update, rows_to_list
from routes.db.change_events import tracks_changes
from routes.db.custom_fields import _marks, _now

__all__ = [
    "TENANT_OWNED_LABELS",
    "TENANT_UNCHANGED",
    "TenantArg",
    "create_region",
    "create_tenant",
    "create_tenant_group",
    "delete_region",
    "delete_tenant",
    "delete_tenant_group",
    "get_location_tree",
    "get_region",
    "get_tenant",
    "get_tenant_group",
    "list_regions",
    "list_tenant_groups",
    "list_tenants",
    "region_subtree_ids",
    "region_subtree_sql",
    "region_usage",
    "set_allocation_tenant",
    "set_prefix_tenant",
    "site_region_chains",
    "tenant_group_subtree_ids",
    "tenant_group_usage",
    "tenant_owner_tables",
    "tenant_usage",
    "update_region",
    "update_tenant",
    "update_tenant_group",
]

# Deepest chain a subtree walk follows (a guard against a cycle that slipped
# past the write checks, not a limit anyone reaches).
_MAX_DEPTH = 64

# A table name read from information_schema is used as an identifier only
# when it matches this (lower-case SQL identifier).
_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

# How a tenant's owned rows are named in its counts; other tables with a
# ``tenant_id`` column count under their table name.
TENANT_OWNED_LABELS: Final[dict[str, str]] = {
    "hosts": "hosts",
    "ipam_prefixes": "prefixes",
    "ipam_allocations": "ip_addresses",
    "vlans": "vlans",
    "vrfs": "vrfs",
    "geo_sites": "sites",
}


class _Unchanged:
    """The ``tenant_id`` argument of an update that leaves the tenant alone."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "TENANT_UNCHANGED"


TENANT_UNCHANGED: Final = _Unchanged()
TenantArg = int | None | _Unchanged


def _tree_ordered(nodes: list[dict]) -> list[dict]:
    """The inventory group tree order (``routes.db.inventory``), imported
    when called: that module imports this one's importers at load time."""
    from routes.db.inventory import _tree_ordered as ordered

    return ordered(nodes)


def _subtree_sql(table: str) -> str:
    """A subquery of the ids of row ``?`` of ``table`` (a fixed tree table)
    and all of its descendants."""
    return f"""(
    WITH RECURSIVE sub (id, lvl) AS (
        SELECT id, 0 FROM {table} WHERE id = ?
        UNION ALL
        SELECT t.id, s.lvl + 1 FROM {table} t JOIN sub s ON t.parent_id = s.id
        WHERE s.lvl < {_MAX_DEPTH}
    )
    SELECT id FROM sub
)"""  # nosec B608 - fixed table names


def region_subtree_sql() -> str:
    """The subquery of region ``?`` and its descendants' ids (for filters)."""
    return _subtree_sql("regions")


async def _select(sql: str, params: tuple = ()) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def _subtree_ids(table: str, root_ids: Iterable[int]) -> set[int]:
    result: set[int] = set()
    for root in sorted({int(r) for r in root_ids}):
        if root in result:
            continue
        rows = await _select(f"SELECT id FROM {table} WHERE id IN {_subtree_sql(table)}", (root,))  # nosec B608 - fixed table names
        result.update(int(r["id"]) for r in rows)
    return result


async def region_subtree_ids(region_ids: Iterable[int]) -> set[int]:
    """The given regions and all of their descendants (unknown ids add nothing)."""
    return await _subtree_ids("regions", region_ids)


async def tenant_group_subtree_ids(group_ids: Iterable[int]) -> set[int]:
    """The given tenant groups and all of their descendants."""
    return await _subtree_ids("tenant_groups", group_ids)


def _taken(what: str, name: str) -> ValueError:
    return ValueError(f"A {what} named '{name}' already exists.")


async def _insert(table: str, values: dict, taken: ValueError) -> int:
    columns = list(values)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({_marks(columns)}) RETURNING id",  # nosec B608 - fixed table and column names
            tuple(values.values()),
        )
        new_id = int(cursor.lastrowid)
        await db.commit()
        return new_id
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise taken from exc
        raise
    finally:
        await db.close()


async def _update(table: str, row_id: int, values: dict, taken: ValueError) -> bool:
    sql, params = _safe_dynamic_update(table, [f"{k} = ?" for k in values], list(values.values()), "id = ?", row_id)
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


async def _delete(table: str, row_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(f"DELETE FROM {table} WHERE id = ?", (int(row_id),))  # nosec B608 - fixed table names
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


def _stamped(values: dict, user: str, *, create: bool) -> dict:
    now = _now()
    out = {**values, "updated_at": now, "updated_by": user}
    if create:
        out.update(created_at=now, created_by=user)
    return out


def _node(row: dict) -> dict:
    parent = row.get("parent_id")
    return {
        "id": int(row["id"]),
        "parent_id": int(parent) if parent is not None else None,
        "name": row["name"],
        "description": row.get("description") or "",
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at") or "",
        "updated_by": row.get("updated_by") or "",
        "updated_at": row.get("updated_at") or "",
    }


# ── Regions ──────────────────────────────────────────────────────────────────

_REGION_SELECT = """
    SELECT r.*,
           (SELECT COUNT(*) FROM geo_sites s WHERE s.region_id = r.id) AS site_count,
           (SELECT COUNT(*) FROM regions c WHERE c.parent_id = r.id) AS child_count
    FROM regions r
"""


def _with_totals(nodes: list[dict], own_key: str, total_key: str) -> list[dict]:
    """Set ``total_key`` on every node: its ``own_key`` plus its descendants'."""
    children: dict[int | None, list[dict]] = {}
    for n in nodes:
        children.setdefault(n["parent_id"], []).append(n)
    memo: dict[int, int] = {}

    def total(node: dict, depth: int = 0) -> int:
        if node["id"] in memo:
            return memo[node["id"]]
        value = int(node[own_key])
        if depth < _MAX_DEPTH:
            value += sum(total(c, depth + 1) for c in children.get(node["id"], []))
        memo[node["id"]] = value
        return value

    for n in nodes:
        n[total_key] = total(n)
    return nodes


async def _counts_by(table: str, column: str, ids: Iterable[int]) -> dict[int, int]:
    """``column value -> rows`` of the rows of ``table`` (fixed names) whose
    id is in ``ids``."""
    wanted = sorted({int(i) for i in ids})
    if not wanted:
        return {}
    rows = await _select(
        f"SELECT {column} AS k, COUNT(*) AS n FROM {table} WHERE id IN ({_marks(wanted)}) GROUP BY {column}",  # nosec B608 - fixed names, placeholders only
        tuple(wanted),
    )
    return {int(r["k"]): int(r["n"]) for r in rows if r["k"] is not None}


async def list_regions(*, site_ids: Iterable[int] | None = None) -> list[dict]:
    """Every region in tree order (siblings by name), each with ``path``,
    ``depth``, ``site_count`` (its own sites), ``total_site_count`` (with
    its descendants') and ``child_count``. ``site_ids`` (object scope;
    ``None``: all) counts only those sites."""
    rows = await _select(_REGION_SELECT + " ORDER BY lower(r.name), r.id")
    nodes = [{**_node(r), "site_count": int(r["site_count"]), "child_count": int(r["child_count"])} for r in rows]
    if site_ids is not None:
        own = await _counts_by("geo_sites", "region_id", site_ids)
        for node in nodes:
            node["site_count"] = own.get(node["id"], 0)
    return _with_totals(_tree_ordered(nodes), "site_count", "total_site_count")


async def get_region(region_id: int, *, site_ids: Iterable[int] | None = None) -> dict | None:
    for region in await list_regions(site_ids=site_ids):
        if region["id"] == int(region_id):
            return region
    return None


@tracks_changes("region", "create")
async def create_region(*, name: str, parent_id: int | None = None, description: str = "", user: str = "") -> dict:
    """Raises ``ValueError`` when the parent has a child region of the name
    (ignoring case). The caller checks that the parent exists."""
    values = _stamped({"name": name, "parent_id": parent_id, "description": description}, user, create=True)
    new_id = await _insert("regions", values, _taken("region under this parent", name))
    return await _must(get_region(new_id))


@tracks_changes("region", "update", id_arg="region_id")
async def update_region(region_id: int, *, values: dict, user: str = "") -> dict | None:
    """Change ``name``, ``parent_id`` and/or ``description``. The caller
    refuses a parent that would make a cycle. ``None`` when missing."""
    allowed = {k: v for k, v in values.items() if k in ("name", "parent_id", "description")}
    name = str(allowed.get("name") or "")
    found = await _update(
        "regions", int(region_id), _stamped(allowed, user, create=False), _taken("region under this parent", name)
    )
    return await get_region(region_id) if found else None


async def region_usage(region_id: int) -> dict[str, int]:
    """``{"regions": child regions, "sites": sites}`` directly in the region."""
    rows = await _select(
        "SELECT (SELECT COUNT(*) FROM regions WHERE parent_id = ?) AS regions, "
        "(SELECT COUNT(*) FROM geo_sites WHERE region_id = ?) AS sites",
        (int(region_id), int(region_id)),
    )
    return {"regions": int(rows[0]["regions"]), "sites": int(rows[0]["sites"])}


@tracks_changes("region", "delete", id_arg="region_id")
async def delete_region(region_id: int) -> bool:
    """Delete an empty region (the caller checks ``region_usage`` first)."""
    return await _delete("regions", region_id)


# ── Tenant groups ────────────────────────────────────────────────────────────

_GROUP_SELECT = """
    SELECT g.*,
           (SELECT COUNT(*) FROM tenants t WHERE t.group_id = g.id) AS tenant_count,
           (SELECT COUNT(*) FROM tenant_groups c WHERE c.parent_id = g.id) AS child_count
    FROM tenant_groups g
"""


async def list_tenant_groups(*, tenant_ids: Iterable[int] | None = None) -> list[dict]:
    """Every tenant group in tree order with ``path``, ``depth``,
    ``tenant_count``, ``total_tenant_count`` and ``child_count``.
    ``tenant_ids`` (object scope; ``None``: all) counts only those tenants."""
    rows = await _select(_GROUP_SELECT + " ORDER BY lower(g.name), g.id")
    nodes = [{**_node(r), "tenant_count": int(r["tenant_count"]), "child_count": int(r["child_count"])} for r in rows]
    if tenant_ids is not None:
        own = await _counts_by("tenants", "group_id", tenant_ids)
        for node in nodes:
            node["tenant_count"] = own.get(node["id"], 0)
    return _with_totals(_tree_ordered(nodes), "tenant_count", "total_tenant_count")


async def get_tenant_group(group_id: int, *, tenant_ids: Iterable[int] | None = None) -> dict | None:
    for group in await list_tenant_groups(tenant_ids=tenant_ids):
        if group["id"] == int(group_id):
            return group
    return None


@tracks_changes("tenant_group", "create")
async def create_tenant_group(
    *, name: str, parent_id: int | None = None, description: str = "", user: str = ""
) -> dict:
    """Raises ``ValueError`` when a group has the name (ignoring case)."""
    values = _stamped({"name": name, "parent_id": parent_id, "description": description}, user, create=True)
    new_id = await _insert("tenant_groups", values, _taken("tenant group", name))
    return await _must(get_tenant_group(new_id))


@tracks_changes("tenant_group", "update", id_arg="group_id")
async def update_tenant_group(group_id: int, *, values: dict, user: str = "") -> dict | None:
    allowed = {k: v for k, v in values.items() if k in ("name", "parent_id", "description")}
    name = str(allowed.get("name") or "")
    found = await _update(
        "tenant_groups", int(group_id), _stamped(allowed, user, create=False), _taken("tenant group", name)
    )
    return await get_tenant_group(group_id) if found else None


async def tenant_group_usage(group_id: int) -> dict[str, int]:
    """``{"groups": child groups, "tenants": tenants}`` directly in the group."""
    rows = await _select(
        "SELECT (SELECT COUNT(*) FROM tenant_groups WHERE parent_id = ?) AS groups, "
        "(SELECT COUNT(*) FROM tenants WHERE group_id = ?) AS tenants",
        (int(group_id), int(group_id)),
    )
    return {"groups": int(rows[0]["groups"]), "tenants": int(rows[0]["tenants"])}


@tracks_changes("tenant_group", "delete", id_arg="group_id")
async def delete_tenant_group(group_id: int) -> bool:
    """Delete a group with no child groups (the caller checks); its tenants
    are left in no group."""
    return await _delete("tenant_groups", group_id)


# ── Tenants ──────────────────────────────────────────────────────────────────

_TENANT_SELECT = """
    SELECT t.*, g.name AS group_name
    FROM tenants t LEFT JOIN tenant_groups g ON g.id = t.group_id
"""


def _tenant(row: dict) -> dict:
    group = row.get("group_id")
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "group_id": int(group) if group is not None else None,
        "group_name": row.get("group_name"),
        "description": row.get("description") or "",
        "comments": row.get("comments") or "",
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at") or "",
        "updated_by": row.get("updated_by") or "",
        "updated_at": row.get("updated_at") or "",
    }


async def list_tenants(*, group_ids: Iterable[int] | None = None) -> list[dict]:
    """Every tenant by name; ``group_ids`` keeps those in the given groups."""
    if group_ids is not None:
        ids = sorted({int(g) for g in group_ids})
        if not ids:
            return []
        rows = await _select(
            _TENANT_SELECT + f" WHERE t.group_id IN ({_marks(ids)}) ORDER BY lower(t.name), t.id",  # nosec B608 - placeholders only
            tuple(ids),
        )
    else:
        rows = await _select(_TENANT_SELECT + " ORDER BY lower(t.name), t.id")
    return [_tenant(r) for r in rows]


async def get_tenant(tenant_id: int) -> dict | None:
    rows = await _select(_TENANT_SELECT + " WHERE t.id = ?", (int(tenant_id),))
    return _tenant(rows[0]) if rows else None


@tracks_changes("tenant", "create")
async def create_tenant(
    *, name: str, group_id: int | None = None, description: str = "", comments: str = "", user: str = ""
) -> dict:
    """Raises ``ValueError`` when a tenant has the name (ignoring case)."""
    values = _stamped(
        {"name": name, "group_id": group_id, "description": description, "comments": comments}, user, create=True
    )
    new_id = await _insert("tenants", values, _taken("tenant", name))
    return await _must(get_tenant(new_id))


@tracks_changes("tenant", "update", id_arg="tenant_id")
async def update_tenant(tenant_id: int, *, values: dict, user: str = "") -> dict | None:
    allowed = {k: v for k, v in values.items() if k in ("name", "group_id", "description", "comments")}
    name = str(allowed.get("name") or "")
    found = await _update("tenants", int(tenant_id), _stamped(allowed, user, create=False), _taken("tenant", name))
    return await get_tenant(tenant_id) if found else None


@tracks_changes("tenant", "delete", id_arg="tenant_id")
async def delete_tenant(tenant_id: int) -> bool:
    """Delete the tenant; the rows it owned keep existing with no tenant."""
    return await _delete("tenants", tenant_id)


async def tenant_owner_tables() -> list[str]:
    """The tables with a ``tenant_id`` column, discovered so tables later
    migrations add are counted too. Only plain identifiers are returned."""
    rows = await _select(
        """SELECT c.table_name FROM information_schema.columns c
           JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
           WHERE c.column_name = 'tenant_id' AND c.table_schema = current_schema() AND t.table_type = 'BASE TABLE'
           ORDER BY c.table_name"""
    )
    return [str(r["table_name"]) for r in rows if _IDENTIFIER.match(str(r["table_name"]))]


async def tenant_usage(tenant_id: int) -> dict[str, int]:
    """How many rows of each owning table the tenant owns, by label
    (``TENANT_OWNED_LABELS``; other tables by name). Every discovered table
    is listed, with 0 when it owns none."""
    tables = await tenant_owner_tables()
    if not tables:
        return {}
    parts = " UNION ALL ".join(
        f"SELECT '{table}' AS tbl, COUNT(*) AS n FROM {table} WHERE tenant_id = ?" for table in tables
    )
    rows = await _select(parts, tuple(int(tenant_id) for _ in tables))  # nosec B608 - identifiers checked by _IDENTIFIER
    return {TENANT_OWNED_LABELS.get(str(r["tbl"]), str(r["tbl"])): int(r["n"]) for r in rows}


# ── Tenant on IPAM rows ──────────────────────────────────────────────────────


async def _set_tenant(table: str, row_id: int, tenant_id: int | None) -> bool:
    sql, params = _safe_dynamic_update(table, ["tenant_id = ?"], [tenant_id], "id = ?", int(row_id))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


@tracks_changes("prefix", "update", id_arg="prefix_id")
async def set_prefix_tenant(prefix_id: int, tenant_id: int | None) -> bool:
    """Set (``None``: clear) the tenant of an IPAM prefix; ``False`` when missing."""
    return await _set_tenant("ipam_prefixes", prefix_id, tenant_id)


@tracks_changes("ip_address", "update", id_arg="allocation_id")
async def set_allocation_tenant(allocation_id: int, tenant_id: int | None) -> bool:
    """Set (``None``: clear) the tenant of an IPAM allocation; ``False`` when missing."""
    return await _set_tenant("ipam_allocations", allocation_id, tenant_id)


# ── Location tree ────────────────────────────────────────────────────────────


def _ids_in(column: str, ids: Iterable[int] | None) -> tuple[str, tuple[int, ...]]:
    """`` AND column IN (ids)`` and its parameters (``("", ())`` for
    ``None``; an empty set matches nothing). ``column`` is fixed."""
    if ids is None:
        return "", ()
    wanted = tuple(sorted({int(i) for i in ids}))
    if not wanted:
        return " AND 1 = 0", ()
    return f" AND {column} IN ({_marks(wanted)})", wanted


async def get_location_tree(*, site_ids: Iterable[int] | None = None, host_ids: Iterable[int] | None = None) -> dict:
    """Regions > sites > floors, with host counts.

    ``regions``: the top-level regions, each with ``children`` (regions),
    ``sites`` (its own) and ``host_count`` (hosts of its sites and its
    descendants' sites). ``unassigned_sites``: sites in no region. A site
    carries ``host_count`` (hosts whose site it is), its status, facility,
    time zone, tenant and ``floors`` (``placed_device_count`` each).

    Object scope (``None``: all): ``site_ids`` keeps those sites,
    ``host_ids`` counts (and counts as placed) only those hosts."""
    regions = await list_regions(site_ids=site_ids)
    site_sql, site_params = _ids_in("s.id", site_ids)
    host_sql, host_params = _ids_in("h.id", host_ids)
    placed_sql, _ = _ids_in("p.host_id", host_ids)
    sites = await _select(
        f"""SELECT s.id, s.name, s.region_id, s.status, s.facility, s.time_zone, s.tenant_id, t.name AS tenant_name,
                  (SELECT COUNT(*) FROM hosts h WHERE h.site_id = s.id{host_sql}) AS host_count
           FROM geo_sites s LEFT JOIN tenants t ON t.id = s.tenant_id
           WHERE 1 = 1{site_sql}
           ORDER BY lower(s.name), s.id""",  # nosec B608 - fixed clauses, placeholders only
        (*host_params, *site_params),
    )
    floors = await _select(
        f"""SELECT f.id, f.site_id, f.name, f.floor_number,
                  (SELECT COUNT(*) FROM geo_placements p WHERE p.floor_id = f.id{placed_sql}) AS placed_device_count
           FROM geo_floors f ORDER BY f.floor_number, f.name, f.id""",  # nosec B608 - fixed clauses, placeholders only
        host_params,
    )
    floors_of: dict[int, list[dict]] = {}
    for f in floors:
        floors_of.setdefault(int(f["site_id"]), []).append(
            {
                "id": int(f["id"]),
                "name": f["name"],
                "floor_number": f["floor_number"],
                "placed_device_count": int(f["placed_device_count"]),
            }
        )
    by_region: dict[int | None, list[dict]] = {}
    for s in sites:
        region = s["region_id"]
        site = {
            "id": int(s["id"]),
            "name": s["name"],
            "region_id": int(region) if region is not None else None,
            "status": s["status"] or "active",
            "facility": s["facility"] or "",
            "time_zone": s["time_zone"] or "",
            "tenant_id": int(s["tenant_id"]) if s["tenant_id"] is not None else None,
            "tenant_name": s["tenant_name"],
            "host_count": int(s["host_count"]),
            "floors": floors_of.get(int(s["id"]), []),
        }
        by_region.setdefault(site["region_id"], []).append(site)

    known = {r["id"] for r in regions}
    nodes: dict[int, dict[str, Any]] = {}
    for r in regions:
        own = by_region.get(r["id"], [])
        nodes[r["id"]] = {
            **r,
            "sites": own,
            "children": [],
            "own_host_count": sum(s["host_count"] for s in own),
        }
    roots: list[dict] = []
    for r in regions:  # tree order: a parent comes before its children
        parent = r["parent_id"]
        if parent in nodes and parent != r["id"]:
            nodes[parent]["children"].append(nodes[r["id"]])
        else:
            roots.append(nodes[r["id"]])
    flat = _with_totals(list(nodes.values()), "own_host_count", "host_count")
    for node in flat:
        node.pop("own_host_count", None)
    unassigned = [s for region, group in by_region.items() if region not in known for s in group]
    return {"regions": roots, "unassigned_sites": sorted(unassigned, key=lambda s: (s["name"].lower(), s["id"]))}


async def _must(coro) -> dict:
    record = await coro
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("organization record vanished after write")
    return record


def _chain(parents: dict[int, int | None], node_id: int) -> list[int]:
    """The ids from ``node_id`` up to its root."""
    out: list[int] = []
    current: int | None = int(node_id)
    while current is not None and current in parents and current not in out and len(out) <= _MAX_DEPTH:
        out.append(current)
        current = parents[current]
    return out


async def site_region_chains(site_ids: Iterable[int]) -> dict[int, list[int]]:
    """Site id to the ids of its region and that region's ancestors (the
    nearest first; empty for a site in no region)."""
    ids = sorted({int(s) for s in site_ids})
    if not ids:
        return {}
    parents = {int(r["id"]): r["parent_id"] for r in await _select("SELECT id, parent_id FROM regions")}
    out: dict[int, list[int]] = {}
    for start in range(0, len(ids), 1000):
        chunk = ids[start : start + 1000]
        rows = await _select(
            f"SELECT id, region_id FROM geo_sites WHERE id IN ({_marks(chunk)})",  # nosec B608 - placeholders only
            tuple(chunk),
        )
        for r in rows:
            region = r["region_id"]
            out[int(r["id"])] = _chain(parents, int(region)) if region is not None else []
    return out
