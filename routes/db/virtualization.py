"""Virtualization persistence: cluster types, cluster groups, clusters and
their member hosts, virtual machines, VM interfaces and their addresses
(migration 0100).

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Values arrive validated (``netcontrol.virtualization``); this module stores
and reads rows. A name already taken raises ``VirtualizationNameTaken`` (a
``ValueError`` whose message says so); a delete the database refuses because
rows still point at the object raises ``VirtualizationInUse``. Creates, updates and
deletes of the five tracked types (``cluster_type``, ``cluster_group``,
``cluster``, ``virtual_machine``, ``vm_interface``) emit object-change events.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import routes.database as _dbcore
from routes.database import (
    _is_foreign_key_violation,
    _is_unique_violation,
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)
from routes.db.change_events import tracks_changes
from routes.db.custom_fields import _marks, _now

__all__ = [
    "VirtualizationInUse",
    "VirtualizationNameTaken",
    "add_cluster_host",
    "create_cluster",
    "create_cluster_group",
    "create_cluster_type",
    "create_virtual_machine",
    "create_vm_interface",
    "delete_cluster",
    "delete_cluster_group",
    "delete_cluster_type",
    "delete_virtual_machine",
    "delete_vm_interface",
    "find_cluster_by_cloud_key",
    "find_cluster_type_by_name",
    "get_cloud_resource_ref",
    "get_cluster",
    "get_cluster_group",
    "get_cluster_type",
    "get_host_clusters",
    "get_virtual_machine",
    "get_vm_interface",
    "list_cloud_virtual_machines",
    "list_cluster_groups",
    "list_cluster_hosts",
    "list_cluster_types",
    "list_clusters",
    "list_virtual_machines",
    "list_vm_interfaces",
    "missing_references",
    "remove_cluster_host",
    "replace_vm_interface_addresses",
    "update_cluster",
    "update_cluster_group",
    "update_cluster_type",
    "update_virtual_machine",
    "update_vm_interface",
    "vm_name_taken",
]


class VirtualizationNameTaken(ValueError):
    """A unique name (or cloud resource link) is already used."""


class VirtualizationInUse(ValueError):
    """Rows still point at the object, so it cannot be deleted."""


# Columns a write may set, per table (fixed; never user input).
_COLUMNS: dict[str, frozenset[str]] = {
    "cluster_types": frozenset({"name", "description"}),
    "cluster_groups": frozenset({"name", "description"}),
    "clusters": frozenset(
        {
            "name",
            "cluster_type_id",
            "cluster_group_id",
            "site_id",
            "tenant_id",
            "description",
            "comments",
            "origin",
            "cloud_key",
        }
    ),
    "virtual_machines": frozenset(
        {
            "name",
            "cluster_id",
            "status",
            "role_id",
            "tenant_id",
            "platform",
            "vcpus",
            "memory_mb",
            "disk_gb",
            "primary_ip4",
            "primary_ip6",
            "cloud_resource_id",
            "cloud_account_id",
            "cloud_resource_uid",
            "origin",
            "description",
            "comments",
        }
    ),
    "vm_interfaces": frozenset(
        {"vm_id", "name", "enabled", "mac_address", "mtu", "mode", "untagged_vlan_id", "vrf_id", "description"}
    ),
}

# Reference tables a write may name (``missing_references``).
_REFERENCE_TABLES = frozenset(
    {
        "cluster_types",
        "cluster_groups",
        "clusters",
        "geo_sites",
        "tenants",
        "device_roles",
        "hosts",
        "vlans",
        "vrfs",
        "cloud_resources",
        "virtual_machines",
    }
)

_TAKEN_MESSAGES: dict[str, str] = {
    "cluster_types": "A cluster type with this name already exists.",
    "cluster_groups": "A cluster group with this name already exists.",
    "clusters": "A cluster with this name already exists.",
    "virtual_machines": "A virtual machine with this name already exists in the cluster.",
    "vm_interfaces": "The virtual machine already has an interface with this name.",
}


def _taken_error(table: str, exc: Exception) -> VirtualizationNameTaken:
    if table == "virtual_machines" and "cloud" in str(exc).lower():
        return VirtualizationNameTaken("Another virtual machine already mirrors this cloud resource.")
    return VirtualizationNameTaken(_TAKEN_MESSAGES.get(table, "The name is already used."))


def _checked(table: str, values: dict[str, Any]) -> dict[str, Any]:
    allowed = _COLUMNS[table]
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"unknown {table} columns: {sorted(unknown)}")
    return values


async def _fetch_one(sql: str, params: Iterable = ()) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, tuple(params))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def _fetch_all(sql: str, params: Iterable = ()) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, tuple(params))
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def _insert(table: str, values: dict[str, Any], user: str) -> int:
    values = _checked(table, values)
    now = _now()
    row = {**values, "created_by": user, "created_at": now, "updated_at": now, "updated_by": user}
    columns = list(row)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({_marks(columns)}) RETURNING id",  # nosec B608 - fixed tables, whitelisted columns
            tuple(row[c] for c in columns),
        )
        new_id = int(cursor.lastrowid)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _taken_error(table, exc) from exc
        raise
    finally:
        await db.close()
    return new_id


async def _update(table: str, row_id: int, values: dict[str, Any], user: str) -> bool:
    """Set ``values`` (and the update stamps); ``False`` when the row does not exist."""
    values = _checked(table, values)
    exprs = [f"{column} = ?" for column in values] + ["updated_at = ?", "updated_by = ?"]
    sql, params = _safe_dynamic_update(table, exprs, [*values.values(), _now(), user], "id = ?", int(row_id))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return bool(cursor.rowcount)
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise _taken_error(table, exc) from exc
        raise
    finally:
        await db.close()


async def _delete(table: str, row_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(f"DELETE FROM {table} WHERE id = ?", (int(row_id),))  # nosec B608 - fixed tables
        await db.commit()
        return bool(cursor.rowcount)
    except Exception as exc:
        await db.rollback()
        if _is_foreign_key_violation(exc):
            raise VirtualizationInUse("Other records still use it.") from exc
        raise
    finally:
        await db.close()


async def missing_references(refs: dict[str, tuple[str, int | None]]) -> list[str]:
    """The keys of ``refs`` (``field: (table, id)``) whose id names no row.
    ``None`` ids are skipped."""
    missing: list[str] = []
    for field, (table, row_id) in refs.items():
        if row_id is None:
            continue
        if table not in _REFERENCE_TABLES:
            raise ValueError(f"not a reference table: {table}")
        row = await _fetch_one(f"SELECT id FROM {table} WHERE id = ?", (int(row_id),))  # nosec B608 - whitelisted
        if row is None:
            missing.append(field)
    return missing


# ── Cluster types and groups ─────────────────────────────────────────────────


async def _list_catalog(table: str) -> list[dict]:
    return await _fetch_all(
        f"""SELECT x.*, (SELECT COUNT(*) FROM clusters c WHERE c.{_CATALOG_FK[table]} = x.id) AS cluster_count
            FROM {table} x ORDER BY lower(x.name), x.id"""  # nosec B608 - fixed tables
    )


async def _get_catalog(table: str, row_id: int) -> dict | None:
    return await _fetch_one(
        f"""SELECT x.*, (SELECT COUNT(*) FROM clusters c WHERE c.{_CATALOG_FK[table]} = x.id) AS cluster_count
            FROM {table} x WHERE x.id = ?""",  # nosec B608 - fixed tables
        (int(row_id),),
    )


_CATALOG_FK = {"cluster_types": "cluster_type_id", "cluster_groups": "cluster_group_id"}


async def list_cluster_types() -> list[dict]:
    """Every cluster type with its ``cluster_count``, by name."""
    return await _list_catalog("cluster_types")


async def get_cluster_type(type_id: int) -> dict | None:
    return await _get_catalog("cluster_types", type_id)


async def find_cluster_type_by_name(name: str) -> dict | None:
    return await _fetch_one("SELECT * FROM cluster_types WHERE lower(name) = lower(?)", (name,))


@tracks_changes("cluster_type", "create")
async def create_cluster_type(*, name: str, description: str = "", user: str = "") -> dict:
    new_id = await _insert("cluster_types", {"name": name, "description": description}, user)
    row = await get_cluster_type(new_id)
    assert row is not None  # nosec B101 - just inserted
    return row


@tracks_changes("cluster_type", "update", id_arg="type_id")
async def update_cluster_type(type_id: int, values: dict[str, Any], user: str = "") -> dict | None:
    if not await _update("cluster_types", type_id, values, user):
        return None
    return await get_cluster_type(type_id)


@tracks_changes("cluster_type", "delete", id_arg="type_id")
async def delete_cluster_type(type_id: int) -> bool:
    """Raises ``VirtualizationInUse`` while a cluster has the type."""
    return await _delete("cluster_types", type_id)


async def list_cluster_groups() -> list[dict]:
    """Every cluster group with its ``cluster_count``, by name."""
    return await _list_catalog("cluster_groups")


async def get_cluster_group(group_id: int) -> dict | None:
    return await _get_catalog("cluster_groups", group_id)


@tracks_changes("cluster_group", "create")
async def create_cluster_group(*, name: str, description: str = "", user: str = "") -> dict:
    new_id = await _insert("cluster_groups", {"name": name, "description": description}, user)
    row = await get_cluster_group(new_id)
    assert row is not None  # nosec B101 - just inserted
    return row


@tracks_changes("cluster_group", "update", id_arg="group_id")
async def update_cluster_group(group_id: int, values: dict[str, Any], user: str = "") -> dict | None:
    if not await _update("cluster_groups", group_id, values, user):
        return None
    return await get_cluster_group(group_id)


@tracks_changes("cluster_group", "delete", id_arg="group_id")
async def delete_cluster_group(group_id: int) -> bool:
    """Deleting a group clears it on its clusters; the routes refuse while
    clusters are in it."""
    return await _delete("cluster_groups", group_id)


# ── Clusters ─────────────────────────────────────────────────────────────────

_CLUSTER_SELECT = """
    SELECT c.*, t.name AS cluster_type_name, g.name AS cluster_group_name,
           s.name AS site_name, tn.name AS tenant_name,
           (SELECT COUNT(*) FROM cluster_hosts ch WHERE ch.cluster_id = c.id) AS host_count,
           (SELECT COUNT(*) FROM virtual_machines v WHERE v.cluster_id = c.id) AS vm_count
    FROM clusters c
    JOIN cluster_types t ON t.id = c.cluster_type_id
    LEFT JOIN cluster_groups g ON g.id = c.cluster_group_id
    LEFT JOIN geo_sites s ON s.id = c.site_id
    LEFT JOIN tenants tn ON tn.id = c.tenant_id
"""


def _like(search: str) -> str:
    escaped = search.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


async def list_clusters(
    *,
    cluster_type_id: int | None = None,
    cluster_group_id: int | None = None,
    site_id: int | None = None,
    tenant_id: int | None = None,
    search: str | None = None,
) -> list[dict]:
    """Clusters with their type, group, site and tenant names and their
    ``host_count`` and ``vm_count``, by name."""
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (
        ("c.cluster_type_id", cluster_type_id),
        ("c.cluster_group_id", cluster_group_id),
        ("c.site_id", site_id),
        ("c.tenant_id", tenant_id),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(int(value))
    if search and search.strip():
        clauses.append("(lower(c.name) LIKE ? OR lower(c.description) LIKE ?)")
        params += [_like(search)] * 2
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return await _fetch_all(f"{_CLUSTER_SELECT}{where} ORDER BY lower(c.name), c.id", params)  # nosec B608


async def get_cluster(cluster_id: int) -> dict | None:
    return await _fetch_one(f"{_CLUSTER_SELECT} WHERE c.id = ?", (int(cluster_id),))  # nosec B608


async def find_cluster_by_cloud_key(cloud_key: str) -> dict | None:
    return await _fetch_one(f"{_CLUSTER_SELECT} WHERE c.cloud_key = ?", (cloud_key,))  # nosec B608


@tracks_changes("cluster", "create")
async def create_cluster(values: dict[str, Any], user: str = "") -> dict:
    new_id = await _insert("clusters", values, user)
    row = await get_cluster(new_id)
    assert row is not None  # nosec B101 - just inserted
    return row


@tracks_changes("cluster", "update", id_arg="cluster_id")
async def update_cluster(cluster_id: int, values: dict[str, Any], user: str = "") -> dict | None:
    if not await _update("clusters", cluster_id, values, user):
        return None
    return await get_cluster(cluster_id)


@tracks_changes("cluster", "delete", id_arg="cluster_id")
async def delete_cluster(cluster_id: int) -> bool:
    """Raises ``VirtualizationInUse`` while virtual machines are in the cluster.
    Member host rows go with it."""
    return await _delete("clusters", cluster_id)


async def list_cluster_hosts(cluster_id: int) -> list[dict]:
    """The member hosts of a cluster, by hostname."""
    return await _fetch_all(
        """SELECT h.id, h.hostname, h.ip_address, h.device_type, h.status, h.group_id,
                  ch.created_at AS added_at, ch.created_by AS added_by
           FROM cluster_hosts ch JOIN hosts h ON h.id = ch.host_id
           WHERE ch.cluster_id = ? ORDER BY lower(h.hostname), h.id""",
        (int(cluster_id),),
    )


async def add_cluster_host(cluster_id: int, host_id: int, user: str = "") -> bool:
    """Add a host to a cluster; ``False`` when it is a member already."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO cluster_hosts (cluster_id, host_id, created_by, created_at)
               VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING""",
            (int(cluster_id), int(host_id), user, _now()),
        )
        await db.commit()
        return bool(cursor.rowcount)
    finally:
        await db.close()


async def remove_cluster_host(cluster_id: int, host_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM cluster_hosts WHERE cluster_id = ? AND host_id = ?", (int(cluster_id), int(host_id))
        )
        await db.commit()
        return bool(cursor.rowcount)
    finally:
        await db.close()


async def get_host_clusters(host_id: int) -> list[dict]:
    """The clusters a host is a hypervisor of, by name."""
    return await _fetch_all(
        f"""{_CLUSTER_SELECT}
            WHERE c.id IN (SELECT cluster_id FROM cluster_hosts WHERE host_id = ?)
            ORDER BY lower(c.name), c.id""",  # nosec B608
        (int(host_id),),
    )


# ── Virtual machines ─────────────────────────────────────────────────────────

_VM_SELECT = """
    SELECT v.*, c.name AS cluster_name, c.cluster_type_id, t.name AS cluster_type_name,
           c.cluster_group_id, g.name AS cluster_group_name, c.site_id, s.name AS site_name,
           r.name AS role_name, r.color AS role_color, tn.name AS tenant_name,
           cr.provider AS cloud_provider, cr.resource_type AS cloud_resource_type,
           cr.name AS cloud_resource_name, ca.name AS cloud_account_name,
           (SELECT COUNT(*) FROM vm_interfaces i WHERE i.vm_id = v.id) AS interface_count
    FROM virtual_machines v
    JOIN clusters c ON c.id = v.cluster_id
    JOIN cluster_types t ON t.id = c.cluster_type_id
    LEFT JOIN cluster_groups g ON g.id = c.cluster_group_id
    LEFT JOIN geo_sites s ON s.id = c.site_id
    LEFT JOIN device_roles r ON r.id = v.role_id
    LEFT JOIN tenants tn ON tn.id = v.tenant_id
    LEFT JOIN cloud_resources cr ON cr.id = v.cloud_resource_id
    LEFT JOIN cloud_accounts ca ON ca.id = v.cloud_account_id
"""


async def list_virtual_machines(
    *,
    cluster_id: int | None = None,
    cluster_type_id: int | None = None,
    cluster_group_id: int | None = None,
    site_id: int | None = None,
    tenant_id: int | None = None,
    role_id: int | None = None,
    status: str | None = None,
    origin: str | None = None,
    search: str | None = None,
    limit: int = 5000,
) -> list[dict]:
    """Virtual machines with their cluster, type, group, site, role, tenant
    and cloud resource names, by name. ``site_id`` is the cluster's site;
    ``search`` matches the name, description, platform and primary IPs."""
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (
        ("v.cluster_id", cluster_id),
        ("c.cluster_type_id", cluster_type_id),
        ("c.cluster_group_id", cluster_group_id),
        ("c.site_id", site_id),
        ("v.tenant_id", tenant_id),
        ("v.role_id", role_id),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(int(value))
    if status:
        clauses.append("v.status = ?")
        params.append(status)
    if origin:
        clauses.append("v.origin = ?")
        params.append(origin)
    if search and search.strip():
        columns = ("v.name", "v.description", "v.platform", "v.primary_ip4", "v.primary_ip6")
        clauses.append("(" + " OR ".join(f"lower({col}) LIKE ?" for col in columns) + ")")
        params += [_like(search)] * len(columns)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(int(limit))
    return await _fetch_all(f"{_VM_SELECT}{where} ORDER BY lower(v.name), v.id LIMIT ?", params)  # nosec B608


async def get_virtual_machine(vm_id: int) -> dict | None:
    return await _fetch_one(f"{_VM_SELECT} WHERE v.id = ?", (int(vm_id),))  # nosec B608


async def vm_name_taken(cluster_id: int, name: str, *, except_id: int | None = None) -> bool:
    row = await _fetch_one(
        "SELECT id FROM virtual_machines WHERE cluster_id = ? AND lower(name) = lower(?) AND id <> ?",
        (int(cluster_id), name, int(except_id or 0)),
    )
    return row is not None


async def list_cloud_virtual_machines(account_id: int | None) -> list[dict]:
    """The VMs that mirror a resource of a cloud account (``None``: VMs whose
    account was deleted), keyed rows of ``virtual_machines``."""
    if account_id is None:
        return await _fetch_all(
            "SELECT * FROM virtual_machines WHERE cloud_account_id IS NULL AND cloud_resource_uid <> '' ORDER BY id"
        )
    return await _fetch_all(
        "SELECT * FROM virtual_machines WHERE cloud_account_id = ? AND cloud_resource_uid <> '' ORDER BY id",
        (int(account_id),),
    )


async def get_cloud_resource_ref(resource_id: int) -> dict | None:
    """``id``, ``account_id``, ``provider``, ``resource_uid``,
    ``resource_type`` and ``name`` of a cloud resource row."""
    return await _fetch_one(
        "SELECT id, account_id, provider, resource_uid, resource_type, name FROM cloud_resources WHERE id = ?",
        (int(resource_id),),
    )


@tracks_changes("virtual_machine", "create")
async def create_virtual_machine(values: dict[str, Any], user: str = "") -> dict:
    new_id = await _insert("virtual_machines", values, user)
    row = await get_virtual_machine(new_id)
    assert row is not None  # nosec B101 - just inserted
    return row


@tracks_changes("virtual_machine", "update", id_arg="vm_id")
async def update_virtual_machine(vm_id: int, values: dict[str, Any], user: str = "") -> dict | None:
    if not await _update("virtual_machines", vm_id, values, user):
        return None
    return await get_virtual_machine(vm_id)


@tracks_changes("virtual_machine", "delete", id_arg="vm_id")
async def delete_virtual_machine(vm_id: int) -> bool:
    """Its interfaces and their addresses go with it."""
    return await _delete("virtual_machines", vm_id)


# ── VM interfaces ────────────────────────────────────────────────────────────

_INTERFACE_SELECT = """
    SELECT i.*, vl.vid AS untagged_vlan_vid, vl.name AS untagged_vlan_name, vr.name AS vrf_name
    FROM vm_interfaces i
    LEFT JOIN vlans vl ON vl.id = i.untagged_vlan_id
    LEFT JOIN vrfs vr ON vr.id = i.vrf_id
"""


async def _with_addresses(rows: list[dict]) -> list[dict]:
    if not rows:
        return rows
    ids = [int(r["id"]) for r in rows]
    found = await _fetch_all(
        f"""SELECT vm_interface_id, address FROM vm_interface_addresses
            WHERE vm_interface_id IN ({_marks(ids)}) ORDER BY id""",  # nosec B608 - placeholders only
        ids,
    )
    by_interface: dict[int, list[str]] = {}
    for row in found:
        by_interface.setdefault(int(row["vm_interface_id"]), []).append(str(row["address"]))
    for row in rows:
        row["enabled"] = bool(row.get("enabled"))
        row["addresses"] = by_interface.get(int(row["id"]), [])
    return rows


async def list_vm_interfaces(vm_id: int) -> list[dict]:
    """A VM's interfaces by name, each with its ``addresses`` (CIDR text)."""
    rows = await _fetch_all(f"{_INTERFACE_SELECT} WHERE i.vm_id = ? ORDER BY lower(i.name), i.id", (int(vm_id),))  # nosec B608
    return await _with_addresses(rows)


async def get_vm_interface(interface_id: int) -> dict | None:
    row = await _fetch_one(f"{_INTERFACE_SELECT} WHERE i.id = ?", (int(interface_id),))  # nosec B608
    if row is None:
        return None
    return (await _with_addresses([row]))[0]


async def replace_vm_interface_addresses(interface_id: int, addresses: list[str]) -> None:
    """Make ``addresses`` (distinct CIDR text) the interface's addresses,
    keeping the rows of those it had already."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, address FROM vm_interface_addresses WHERE vm_interface_id = ?", (int(interface_id),)
        )
        current = {str(r["address"]): int(r["id"]) for r in rows_to_list(await cursor.fetchall())}
        for address, row_id in current.items():
            if address not in addresses:
                await db.execute("DELETE FROM vm_interface_addresses WHERE id = ?", (row_id,))
        now = _now()
        for address in addresses:
            if address not in current:
                await db.execute(
                    """INSERT INTO vm_interface_addresses (vm_interface_id, address, created_at)
                       VALUES (?, ?, ?) ON CONFLICT DO NOTHING""",
                    (int(interface_id), address, now),
                )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


@tracks_changes("vm_interface", "create")
async def create_vm_interface(
    vm_id: int, values: dict[str, Any], addresses: list[str] | None = None, user: str = ""
) -> dict:
    """Add an interface to a VM with ``addresses`` (distinct CIDR text)."""
    new_id = await _insert("vm_interfaces", {**values, "vm_id": int(vm_id)}, user)
    if addresses:
        await replace_vm_interface_addresses(new_id, addresses)
    row = await get_vm_interface(new_id)
    assert row is not None  # nosec B101 - just inserted
    return row


@tracks_changes("vm_interface", "update", id_arg="interface_id")
async def update_vm_interface(
    interface_id: int, values: dict[str, Any], addresses: list[str] | None = None, user: str = ""
) -> dict | None:
    """Set ``values``; ``addresses`` (when given) replace the interface's."""
    if not await _update("vm_interfaces", interface_id, values, user):
        return None
    if addresses is not None:
        await replace_vm_interface_addresses(interface_id, addresses)
    return await get_vm_interface(interface_id)


@tracks_changes("vm_interface", "delete", id_arg="interface_id")
async def delete_vm_interface(interface_id: int) -> bool:
    return await _delete("vm_interfaces", interface_id)
