"""Virtualization API: cluster types, cluster groups, clusters (with their
member hypervisor hosts), virtual machines and VM interfaces, under
``/api/virtualization``; and the sync that mirrors discovered cloud compute
instances as virtual machines.

Two routers, each registered in ``app.py``:

- ``router`` (``virtualization`` to read, ``virtualization.write`` to
  change): every list, detail, create, update and delete.
- ``admin_router`` (admin): ``POST /api/virtualization/sync-cloud``.

Writes are validated with ``netcontrol.virtualization`` (422 naming the
field), audited under ``virtualization`` and tracked in the change log. A
name already used answers 409; deleting a cluster type or group that
clusters use, or a cluster that holds virtual machines, answers 409.

Cloud sync (``sync_cloud_virtual_machines``): runs after every stored cloud
discovery (``netcontrol.routes.cloud_visibility``) and on demand. For each
AWS, Azure and GCP account it upserts a ``discovered`` VM per compute
instance (``COMPUTE_RESOURCE_TYPES``) into an auto-created cluster per
provider, account and region, with its interfaces and addresses. A VM a
person edited (origin ``manual``) keeps every value; only its link to the
resource row is refreshed. A discovered VM whose instance is gone is set to
``offline``, never deleted. See ``docs/virtualization.md``.

Object scope: cluster types and groups are shared (read by every scoped
caller, changed by unrestricted callers only, their cluster counts scoped);
a scoped caller reads and changes the clusters of their tenants or sites or
with a member host of theirs, and the virtual machines of their tenants or
of such a cluster's site or hosts (VM interfaces follow their VM).
"""

from __future__ import annotations

import logging
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.custom_fields import CustomFieldError
from netcontrol.object_scope import (
    filter_rows,
    readable_host_ids,
    request_scope,
    require_host,
    require_model_write,
    require_new_row,
    require_row,
    scope_exempt,
    scoped,
)
from netcontrol.routes.custom_fields import custom_list, with_custom_data
from netcontrol.routes.shared import _audit, _corr_id, _session_user
from netcontrol.virtualization import (
    CLOUD_CLUSTER_TYPES,
    CLOUD_PROVIDER_LABELS,
    COMMENTS_MAX,
    COMPUTE_RESOURCE_TYPES,
    DESCRIPTION_MAX,
    DISK_GB_MAX,
    MEMORY_MB_MAX,
    NAME_MAX,
    ORIGINS,
    PLATFORM_MAX,
    VCPUS_MAX,
    VM_STATUSES,
    clean_comments,
    clean_count,
    clean_description,
    clean_interface_addresses,
    clean_interface_name,
    clean_mac,
    clean_mode,
    clean_mtu,
    clean_object_name,
    clean_platform,
    clean_primary_ip,
    clean_status,
    cloud_cluster_key,
    cloud_cluster_name,
    decoded_metadata,
    subnet_cidrs,
    vm_from_resource,
)

LOGGER = logging.getLogger("plexus.virtualization")

router = APIRouter()
admin_router = APIRouter()

PREFIX = "/api/virtualization"
SYNC_USER = "cloud-sync"
# Longest text a body accepts before trimming; the real limits are checked
# after trimming.
_RAW = 200


# ── Request bodies ───────────────────────────────────────────────────────────


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CatalogCreate(_Body):
    name: str = Field(max_length=_RAW)
    description: str = Field(default="", max_length=DESCRIPTION_MAX + _RAW)


class CatalogUpdate(_Body):
    name: str | None = Field(default=None, max_length=_RAW)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + _RAW)


class ClusterCreate(_Body):
    name: str = Field(max_length=_RAW)
    cluster_type_id: int
    cluster_group_id: int | None = None
    site_id: int | None = None
    tenant_id: int | None = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX + _RAW)
    comments: str = Field(default="", max_length=COMMENTS_MAX + _RAW)


class ClusterUpdate(_Body):
    """Keys left out keep their value; ``null`` clears an optional link."""

    name: str | None = Field(default=None, max_length=_RAW)
    cluster_type_id: int | None = None
    cluster_group_id: int | None = None
    site_id: int | None = None
    tenant_id: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + _RAW)
    comments: str | None = Field(default=None, max_length=COMMENTS_MAX + _RAW)


class ClusterHostAdd(_Body):
    host_id: int


class VmCreate(_Body):
    name: str = Field(max_length=_RAW)
    cluster_id: int
    status: str = Field(default="active", max_length=40)
    role_id: int | None = None
    tenant_id: int | None = None
    platform: str = Field(default="", max_length=PLATFORM_MAX + _RAW)
    vcpus: int | None = None
    memory_mb: int | None = None
    disk_gb: int | None = None
    primary_ip4: str = Field(default="", max_length=_RAW)
    primary_ip6: str = Field(default="", max_length=_RAW)
    cloud_resource_id: int | None = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX + _RAW)
    comments: str = Field(default="", max_length=COMMENTS_MAX + _RAW)


class VmUpdate(_Body):
    """Keys left out keep their value; ``null`` clears an optional one."""

    name: str | None = Field(default=None, max_length=_RAW)
    cluster_id: int | None = None
    status: str | None = Field(default=None, max_length=40)
    role_id: int | None = None
    tenant_id: int | None = None
    platform: str | None = Field(default=None, max_length=PLATFORM_MAX + _RAW)
    vcpus: int | None = None
    memory_mb: int | None = None
    disk_gb: int | None = None
    primary_ip4: str | None = Field(default=None, max_length=_RAW)
    primary_ip6: str | None = Field(default=None, max_length=_RAW)
    cloud_resource_id: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + _RAW)
    comments: str | None = Field(default=None, max_length=COMMENTS_MAX + _RAW)


class InterfaceCreate(_Body):
    name: str = Field(max_length=_RAW)
    enabled: bool = True
    mac_address: str = Field(default="", max_length=_RAW)
    mtu: int | None = None
    mode: str = Field(default="", max_length=20)
    untagged_vlan_id: int | None = None
    vrf_id: int | None = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX + _RAW)
    addresses: list[str] = Field(default_factory=list, max_length=200)


class InterfaceUpdate(_Body):
    """Keys left out keep their value; ``addresses`` given replace the set."""

    name: str | None = Field(default=None, max_length=_RAW)
    enabled: bool | None = None
    mac_address: str | None = Field(default=None, max_length=_RAW)
    mtu: int | None = None
    mode: str | None = Field(default=None, max_length=20)
    untagged_vlan_id: int | None = None
    vrf_id: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + _RAW)
    addresses: list[str] | None = Field(default=None, max_length=200)


class CloudSyncRequest(_Body):
    account_id: int | None = None


# ── Helpers ──────────────────────────────────────────────────────────────────


def _invalid(fields: dict[str, str]) -> HTTPException:
    """422 with a message and one message per field (the form shows each
    under its input)."""
    message = next(iter(fields.values()), "Invalid value.")
    return HTTPException(status_code=422, detail={"message": message, "fields": fields})


def _clean_values(body: BaseModel, cleaners: dict[str, Any]) -> dict[str, Any]:
    """The values the body sets (left-out keys skipped), each run through its
    cleaner; every failure collected into one 422."""
    values: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for key, raw in body.model_dump(exclude_unset=True).items():
        cleaner = cleaners.get(key)
        try:
            values[key] = cleaner(raw) if cleaner else raw
        except CustomFieldError as exc:
            errors[key] = str(exc)
    if errors:
        raise _invalid(errors)
    return values


_REFERENCES: dict[str, tuple[str, str]] = {
    "cluster_type_id": ("cluster_types", "No cluster type has this id."),
    "cluster_group_id": ("cluster_groups", "No cluster group has this id."),
    "cluster_id": ("clusters", "No cluster has this id."),
    "site_id": ("geo_sites", "No site has this id."),
    "tenant_id": ("tenants", "No tenant has this id."),
    "role_id": ("device_roles", "No device role has this id."),
    "untagged_vlan_id": ("vlans", "No VLAN has this id."),
    "vrf_id": ("vrfs", "No VRF has this id."),
    "host_id": ("hosts", "No host has this id."),
}


async def _check_references(values: dict[str, Any]) -> None:
    """422 naming each id field whose id names no row."""
    refs = {k: (_REFERENCES[k][0], v) for k, v in values.items() if k in _REFERENCES and v is not None}
    missing = await db.missing_references(refs)
    if missing:
        raise _invalid({k: _REFERENCES[k][1] for k in missing})


def _found(row: dict | None, what: str) -> dict:
    if row is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return row


def _conflict(exc: Exception) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("virtualization", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


_CATALOG_CLEANERS = {"name": clean_object_name, "description": clean_description}
_CLUSTER_CLEANERS = {**_CATALOG_CLEANERS, "comments": clean_comments}
_VM_CLEANERS: dict[str, Any] = {
    "name": clean_object_name,
    "status": clean_status,
    "platform": clean_platform,
    "vcpus": lambda v: clean_count(v, "vCPUs", VCPUS_MAX),
    "memory_mb": lambda v: clean_count(v, "Memory (MB)", MEMORY_MB_MAX),
    "disk_gb": lambda v: clean_count(v, "Disk (GB)", DISK_GB_MAX),
    "primary_ip4": lambda v: clean_primary_ip(v, 4),
    "primary_ip6": lambda v: clean_primary_ip(v, 6),
    "description": clean_description,
    "comments": clean_comments,
}
_INTERFACE_CLEANERS: dict[str, Any] = {
    "name": clean_interface_name,
    "mac_address": clean_mac,
    "mtu": clean_mtu,
    "mode": clean_mode,
    "description": clean_description,
    "addresses": clean_interface_addresses,
    "enabled": lambda v: None if v is None else int(bool(v)),
}


# ── Cluster types and groups ─────────────────────────────────────────────────

_CATALOGS: dict[str, dict[str, Any]] = {
    "cluster-types": {
        "what": "Cluster type",
        "audit": "cluster_type",
        "list": "list_cluster_types",
        "get": "get_cluster_type",
        "create": "create_cluster_type",
        "update": "update_cluster_type",
        "delete": "delete_cluster_type",
    },
    "cluster-groups": {
        "what": "Cluster group",
        "audit": "cluster_group",
        "list": "list_cluster_groups",
        "get": "get_cluster_group",
        "create": "create_cluster_group",
        "update": "update_cluster_group",
        "delete": "delete_cluster_group",
    },
}


# ── Object scope ─────────────────────────────────────────────────────────────


async def _member_hosts() -> dict[int, list[int]]:
    """Cluster id -> its member host ids."""
    members: dict[int, list[int]] = {}
    for link in await db.list_cluster_host_links():
        members.setdefault(int(link["cluster_id"]), []).append(int(link["host_id"]))
    return members


def _keyed_cluster(cluster: dict, members: dict[int, list[int]]) -> dict:
    """A copy of ``cluster`` with its ``cluster`` scope model keys."""
    return {**cluster, "scope_host_ids": members.get(int(cluster["id"]), [])}


def _keyed_vm(vm: dict, members: dict[int, list[int]]) -> dict:
    """A copy of ``vm`` with its ``virtual_machine`` scope model keys: its
    cluster's site (``site_id`` of the VM rows) and member hosts."""
    cluster_id = vm.get("cluster_id")
    return {
        **vm,
        "cluster_site_id": vm.get("site_id"),
        "scope_host_ids": members.get(int(cluster_id), []) if cluster_id is not None else [],
    }


async def _readable(request: Request, model: str, rows: list[dict]) -> list[dict]:
    """The ``rows`` of ``model`` (``cluster`` or ``virtual_machine``) the
    caller may read, in order."""
    if (await request_scope(request)).unrestricted:
        return rows
    members = await _member_hosts()
    keyed = _keyed_cluster if model == "cluster" else _keyed_vm
    allowed = {int(r["id"]) for r in await filter_rows(model, [keyed(r, members) for r in rows], request)}
    return [r for r in rows if int(r["id"]) in allowed]


async def _require_cluster(request: Request, cluster_id: int, *, write: bool = False) -> dict:
    """The cluster; 404 when unknown or outside the caller's read scope, 403
    on ``write`` when it is not writable."""
    row = await db.get_cluster(cluster_id)
    if row is not None and (await request_scope(request)).restricted:
        await require_row(
            request, "cluster", _keyed_cluster(row, await _member_hosts()), write=write, not_found="Cluster not found"
        )
    return _found(row, "Cluster")


async def _require_vm(request: Request, vm_id: int, *, write: bool = False) -> dict:
    """The virtual machine; 404 when unknown or outside the caller's read
    scope, 403 on ``write`` when it is not writable."""
    row = await db.get_virtual_machine(vm_id)
    if row is not None and (await request_scope(request)).restricted:
        await require_row(
            request,
            "virtual_machine",
            _keyed_vm(row, await _member_hosts()),
            write=write,
            not_found="Virtual machine not found",
        )
    return _found(row, "Virtual machine")


async def _require_new_vm(request: Request, tenant_id: Any, cluster_id: Any) -> None:
    """For a scoped caller: 403 unless a VM of ``tenant_id`` in cluster
    ``cluster_id`` is writable."""
    if (await request_scope(request)).unrestricted:
        return
    cluster = await db.get_cluster(int(cluster_id)) if cluster_id is not None else None
    members = await _member_hosts()
    await require_new_row(
        request,
        "virtual_machine",
        {
            "tenant_id": tenant_id,
            "cluster_site_id": (cluster or {}).get("site_id"),
            "scope_host_ids": members.get(int(cluster_id), []) if cluster_id is not None else [],
        },
    )


async def _vm_scope_filters(request: Request) -> dict:
    """``db.list_virtual_machines`` keywords keeping a scoped caller's VMs
    (SQL, before the limit): those of their tenants and of the clusters
    whose site or member hosts they reach. ``{}`` when unrestricted."""
    scope = await request_scope(request)
    if scope.unrestricted:
        return {}
    allowed = await scope.keys("virtual_machine")
    sites, hosts = allowed.get("site", frozenset()), allowed.get("host", frozenset())
    members = await _member_hosts()
    clusters = [
        int(c["id"])
        for c in await db.list_clusters()
        if (c.get("site_id") is not None and int(c["site_id"]) in sites)
        or any(h in hosts for h in members.get(int(c["id"]), []))
    ]
    return {"scope_tenant_ids": sorted(allowed.get("tenant", frozenset())), "scope_cluster_ids": clusters}


async def _catalog_counts(request: Request, rows: list[dict], key: str) -> list[dict]:
    """Catalogue ``rows`` with ``cluster_count`` counting only the caller's
    clusters (``key``: the cluster column naming the catalogue row);
    unchanged for an unrestricted caller."""
    if (await request_scope(request)).unrestricted:
        return rows
    counts: dict[int, int] = {}
    for cluster in await _readable(request, "cluster", await db.list_clusters()):
        if cluster.get(key) is not None:
            counts[int(cluster[key])] = counts.get(int(cluster[key]), 0) + 1
    return [{**r, "cluster_count": counts.get(int(r["id"]), 0)} for r in rows]


async def _catalog_create(kind: str, body: CatalogCreate, request: Request) -> dict:
    await require_model_write(request)
    spec = _CATALOGS[kind]
    values = _clean_values(body, _CATALOG_CLEANERS)
    try:
        row = await getattr(db, spec["create"])(
            name=values["name"], description=values.get("description", ""), user=_session_user(request)
        )
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, f"{spec['audit']}.create", f"id={row['id']} name={row['name']}")
    return row


async def _catalog_update(kind: str, row_id: int, body: CatalogUpdate, request: Request) -> dict:
    await require_model_write(request)
    spec = _CATALOGS[kind]
    _found(await getattr(db, spec["get"])(row_id), spec["what"])
    values = {k: v for k, v in _clean_values(body, _CATALOG_CLEANERS).items() if v is not None}
    try:
        row = await getattr(db, spec["update"])(row_id, values, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    row = _found(row, spec["what"])
    await _audit_write(request, f"{spec['audit']}.update", f"id={row_id} fields={','.join(sorted(values))}")
    return row


async def _catalog_delete(kind: str, row_id: int, request: Request) -> dict:
    await require_model_write(request)
    spec = _CATALOGS[kind]
    row = _found(await getattr(db, spec["get"])(row_id), spec["what"])
    count = int(row.get("cluster_count") or 0)
    if count:
        raise HTTPException(
            status_code=409,
            detail=f"{spec['what']} '{row['name']}' is used by {count} cluster{'s' if count != 1 else ''}.",
        )
    try:
        await getattr(db, spec["delete"])(row_id)
    except db.VirtualizationInUse as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, f"{spec['audit']}.delete", f"id={row_id} name={row['name']}")
    return {"ok": True}


@router.get(f"{PREFIX}/cluster-types")
@scoped("list")
async def list_cluster_types(request: Request) -> dict:
    return {"cluster_types": await _catalog_counts(request, await db.list_cluster_types(), "cluster_type_id")}


@router.post(f"{PREFIX}/cluster-types", status_code=201)
@scoped("catalog")
async def create_cluster_type(body: CatalogCreate, request: Request) -> dict:
    return await _catalog_create("cluster-types", body, request)


@router.get(f"{PREFIX}/cluster-types/{{type_id}}")
@scoped("object")
async def get_cluster_type(type_id: int, request: Request) -> dict:
    row = _found(await db.get_cluster_type(type_id), "Cluster type")
    return (await _catalog_counts(request, [row], "cluster_type_id"))[0]


@router.put(f"{PREFIX}/cluster-types/{{type_id}}")
@scoped("catalog")
async def update_cluster_type(type_id: int, body: CatalogUpdate, request: Request) -> dict:
    return await _catalog_update("cluster-types", type_id, body, request)


@router.delete(f"{PREFIX}/cluster-types/{{type_id}}")
@scoped("catalog")
async def delete_cluster_type(type_id: int, request: Request) -> dict:
    return await _catalog_delete("cluster-types", type_id, request)


@router.get(f"{PREFIX}/cluster-groups")
@scoped("list")
async def list_cluster_groups(request: Request) -> dict:
    return {"cluster_groups": await _catalog_counts(request, await db.list_cluster_groups(), "cluster_group_id")}


@router.post(f"{PREFIX}/cluster-groups", status_code=201)
@scoped("catalog")
async def create_cluster_group(body: CatalogCreate, request: Request) -> dict:
    return await _catalog_create("cluster-groups", body, request)


@router.get(f"{PREFIX}/cluster-groups/{{group_id}}")
@scope_exempt("cluster groups are shared reference data (group_id is a cluster group)")
async def get_cluster_group(group_id: int, request: Request) -> dict:
    row = _found(await db.get_cluster_group(group_id), "Cluster group")
    return (await _catalog_counts(request, [row], "cluster_group_id"))[0]


@router.put(f"{PREFIX}/cluster-groups/{{group_id}}")
@scoped("catalog")
async def update_cluster_group(group_id: int, body: CatalogUpdate, request: Request) -> dict:
    return await _catalog_update("cluster-groups", group_id, body, request)


@router.delete(f"{PREFIX}/cluster-groups/{{group_id}}")
@scoped("catalog")
async def delete_cluster_group(group_id: int, request: Request) -> dict:
    return await _catalog_delete("cluster-groups", group_id, request)


# ── Clusters ─────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/clusters")
@scoped("list")
async def list_clusters(
    request: Request,
    cluster_type_id: int | None = Query(default=None),
    cluster_group_id: int | None = Query(default=None),
    site_id: int | None = Query(default=None),
    tenant_id: int | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
) -> dict:
    rows = await db.list_clusters(
        cluster_type_id=cluster_type_id,
        cluster_group_id=cluster_group_id,
        site_id=site_id,
        tenant_id=tenant_id,
        search=search,
    )
    rows = await _readable(request, "cluster", rows)
    host_ids = await readable_host_ids(request)
    if host_ids is not None:
        members = await _member_hosts()
        rows = [{**r, "host_count": sum(h in host_ids for h in members.get(int(r["id"]), []))} for r in rows]
    return {"clusters": await custom_list("cluster", rows, request)}


@router.post(f"{PREFIX}/clusters", status_code=201)
@scoped("create")
async def create_cluster(body: ClusterCreate, request: Request) -> dict:
    values = _clean_values(body, _CLUSTER_CLEANERS)
    await _check_references(values)
    await require_new_row(
        request,
        "cluster",
        {"tenant_id": values.get("tenant_id"), "site_id": values.get("site_id"), "scope_host_ids": []},
    )
    try:
        row = await db.create_cluster({**values, "origin": "manual"}, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "cluster.create", f"id={row['id']} name={row['name']}")
    return row


@router.get(f"{PREFIX}/clusters/{{cluster_id}}")
@scoped("object")
async def get_cluster(cluster_id: int, request: Request) -> dict:
    """The cluster with its member ``hosts`` and its ``virtual_machines``."""
    row = await _require_cluster(request, cluster_id)
    scope = await request_scope(request)
    row["hosts"] = scope.filter_hosts(await db.list_cluster_hosts(cluster_id))
    row["virtual_machines"] = await _readable(
        request, "virtual_machine", await db.list_virtual_machines(cluster_id=cluster_id)
    )
    if scope.restricted:
        row["host_count"], row["vm_count"] = len(row["hosts"]), len(row["virtual_machines"])
    return await with_custom_data("cluster", row)


@router.put(f"{PREFIX}/clusters/{{cluster_id}}")
@scoped("object")
async def update_cluster(cluster_id: int, body: ClusterUpdate, request: Request) -> dict:
    current = await _require_cluster(request, cluster_id, write=True)
    values = _clean_values(body, _CLUSTER_CLEANERS)
    for required in ("name", "cluster_type_id", "description", "comments"):
        if required in values and values[required] is None:
            raise _invalid({required: "This value cannot be cleared."})
    await _check_references(values)
    if any(k in values and values[k] != current.get(k) for k in ("tenant_id", "site_id")):
        merged = {k: values.get(k, current.get(k)) for k in ("tenant_id", "site_id")}
        members = await _member_hosts()
        await require_new_row(request, "cluster", {**merged, "scope_host_ids": members.get(cluster_id, [])})
    try:
        row = await db.update_cluster(cluster_id, values, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    row = _found(row, "Cluster")
    await _audit_write(request, "cluster.update", f"id={cluster_id} fields={','.join(sorted(values))}")
    return row


@router.delete(f"{PREFIX}/clusters/{{cluster_id}}")
@scoped("object")
async def delete_cluster(cluster_id: int, request: Request) -> dict:
    row = await _require_cluster(request, cluster_id, write=True)
    count = int(row.get("vm_count") or 0)
    if count:
        raise HTTPException(
            status_code=409,
            detail=f"Cluster '{row['name']}' holds {count} virtual machine{'s' if count != 1 else ''}.",
        )
    try:
        await db.delete_cluster(cluster_id)
    except db.VirtualizationInUse as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "cluster.delete", f"id={cluster_id} name={row['name']}")
    return {"ok": True}


@router.post(f"{PREFIX}/clusters/{{cluster_id}}/hosts", status_code=201)
@scoped("object")
async def add_cluster_host(cluster_id: int, body: ClusterHostAdd, request: Request) -> dict:
    """Add a hypervisor host to the cluster; 409 when it is a member already."""
    cluster = await _require_cluster(request, cluster_id, write=True)
    await _check_references({"host_id": body.host_id})
    if (await request_scope(request)).restricted:
        # A host the caller cannot read answers like an unknown one.
        if body.host_id not in (await readable_host_ids(request) or ()):
            raise _invalid({"host_id": _REFERENCES["host_id"][1]})
        await require_host(request, body.host_id, write=True)
    if not await db.add_cluster_host(cluster_id, body.host_id, user=_session_user(request)):
        raise HTTPException(status_code=409, detail="The host is already a member of this cluster.")
    await _audit_write(request, "cluster.host_add", f"id={cluster_id} name={cluster['name']} host_id={body.host_id}")
    return {"ok": True, "hosts": await db.list_cluster_hosts(cluster_id)}


@router.delete(f"{PREFIX}/clusters/{{cluster_id}}/hosts/{{host_id}}")
@scoped("object")
async def remove_cluster_host(cluster_id: int, host_id: int, request: Request) -> dict:
    cluster = await _require_cluster(request, cluster_id, write=True)
    readable = await readable_host_ids(request)
    if readable is not None and host_id not in readable:
        raise HTTPException(status_code=404, detail="The host is not a member of this cluster.")
    if not await db.remove_cluster_host(cluster_id, host_id):
        raise HTTPException(status_code=404, detail="The host is not a member of this cluster.")
    await _audit_write(request, "cluster.host_remove", f"id={cluster_id} name={cluster['name']} host_id={host_id}")
    return {"ok": True}


@router.get(f"{PREFIX}/tenants")
@scoped("list")
async def tenant_choices(request: Request) -> dict:
    """The tenants a cluster or VM can name (id and name only), for callers
    with the virtualization feature but not the organization one; a scoped
    caller's own."""
    tenants = await filter_rows("tenant", await db.list_tenants(), request)
    return {"tenants": [{"id": t["id"], "name": t["name"]} for t in tenants]}


@router.get(f"{PREFIX}/hosts/{{host_id}}/clusters")
@scoped("host")
async def host_clusters(host_id: int, request: Request) -> dict:
    """The clusters a host is a hypervisor of."""
    if (await request_scope(request)).restricted:
        await require_host(request, host_id)
    return {"host_id": host_id, "clusters": await _readable(request, "cluster", await db.get_host_clusters(host_id))}


# ── Virtual machines ─────────────────────────────────────────────────────────


async def _cloud_link(values: dict[str, Any], current: dict | None = None) -> None:
    """Resolve ``cloud_resource_id`` into the stored link: the resource must
    be a compute instance; ``None`` unlinks."""
    if "cloud_resource_id" not in values:
        return
    resource_id = values["cloud_resource_id"]
    if resource_id is None:
        values.update(cloud_account_id=None, cloud_resource_uid="")
        return
    if current is not None and current.get("cloud_resource_id") == resource_id:
        return
    ref = await db.get_cloud_resource_ref(resource_id)
    if ref is None:
        raise _invalid({"cloud_resource_id": "No cloud resource has this id."})
    if ref["resource_type"] not in COMPUTE_RESOURCE_TYPES.get(str(ref["provider"]), ()):
        raise _invalid({"cloud_resource_id": "The cloud resource is not a compute instance."})
    values.update(cloud_account_id=int(ref["account_id"]), cloud_resource_uid=str(ref["resource_uid"]))


@router.get(f"{PREFIX}/virtual-machines")
@scoped("list")
async def list_virtual_machines(
    request: Request,
    cluster_id: int | None = Query(default=None),
    cluster_type_id: int | None = Query(default=None),
    cluster_group_id: int | None = Query(default=None),
    site_id: int | None = Query(default=None),
    tenant_id: int | None = Query(default=None),
    role_id: int | None = Query(default=None),
    status: str | None = Query(default=None, max_length=40),
    origin: str | None = Query(default=None, max_length=20),
    search: str | None = Query(default=None, max_length=200),
) -> dict:
    if status and status not in VM_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {', '.join(VM_STATUSES)}")
    if origin and origin not in ORIGINS:
        raise HTTPException(status_code=422, detail=f"origin must be one of {', '.join(ORIGINS)}")
    rows = await db.list_virtual_machines(
        cluster_id=cluster_id,
        cluster_type_id=cluster_type_id,
        cluster_group_id=cluster_group_id,
        site_id=site_id,
        tenant_id=tenant_id,
        role_id=role_id,
        status=status,
        origin=origin,
        search=search,
        **await _vm_scope_filters(request),
    )
    rows = await _readable(request, "virtual_machine", rows)
    return {"virtual_machines": await custom_list("virtual_machine", rows, request)}


@router.post(f"{PREFIX}/virtual-machines", status_code=201)
@scoped("create")
async def create_virtual_machine(body: VmCreate, request: Request) -> dict:
    values = _clean_values(body, _VM_CLEANERS)
    await _check_references(values)
    await _require_new_vm(request, values.get("tenant_id"), values.get("cluster_id"))
    await _cloud_link(values)
    try:
        row = await db.create_virtual_machine({**values, "origin": "manual"}, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "virtual_machine.create", f"id={row['id']} name={row['name']}")
    return row


@router.get(f"{PREFIX}/virtual-machines/{{vm_id}}")
@scoped("object")
async def get_virtual_machine(vm_id: int, request: Request) -> dict:
    """The VM with its ``interfaces`` (each with its ``addresses``)."""
    row = await _require_vm(request, vm_id)
    row["interfaces"] = await db.list_vm_interfaces(vm_id)
    return await with_custom_data("virtual_machine", row)


@router.put(f"{PREFIX}/virtual-machines/{{vm_id}}")
@scoped("object")
async def update_virtual_machine(vm_id: int, body: VmUpdate, request: Request) -> dict:
    """A person's edit: the VM becomes ``manual``, so the cloud sync no
    longer changes its values."""
    current = await _require_vm(request, vm_id, write=True)
    values = _clean_values(body, _VM_CLEANERS)
    for required in ("name", "cluster_id", "status", "platform", "primary_ip4", "primary_ip6"):
        if required in values and values[required] is None:
            raise _invalid({required: "This value cannot be cleared."})
    for text in ("description", "comments"):
        if text in values and values[text] is None:
            values[text] = ""
    await _check_references(values)
    if any(k in values and values[k] != current.get(k) for k in ("tenant_id", "cluster_id")):
        await _require_new_vm(
            request, values.get("tenant_id", current.get("tenant_id")), values.get("cluster_id", current["cluster_id"])
        )
    await _cloud_link(values, current)
    try:
        row = await db.update_virtual_machine(vm_id, {**values, "origin": "manual"}, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    row = _found(row, "Virtual machine")
    await _audit_write(request, "virtual_machine.update", f"id={vm_id} fields={','.join(sorted(values))}")
    return row


@router.delete(f"{PREFIX}/virtual-machines/{{vm_id}}")
@scoped("object")
async def delete_virtual_machine(vm_id: int, request: Request) -> dict:
    row = await _require_vm(request, vm_id, write=True)
    await db.delete_virtual_machine(vm_id)
    await _audit_write(request, "virtual_machine.delete", f"id={vm_id} name={row['name']}")
    return {"ok": True}


# ── VM interfaces ────────────────────────────────────────────────────────────


async def _vm_interface(vm_id: int, interface_id: int) -> dict:
    row = await db.get_vm_interface(interface_id)
    if row is None or int(row["vm_id"]) != int(vm_id):
        raise HTTPException(status_code=404, detail="VM interface not found")
    return row


async def _interface_values(body: BaseModel, current: dict | None) -> tuple[dict[str, Any], list[str] | None]:
    values = _clean_values(body, _INTERFACE_CLEANERS)
    if "name" in values and values["name"] is None:
        raise _invalid({"name": "This value cannot be cleared."})
    for key, empty in (("mac_address", ""), ("mode", ""), ("description", ""), ("enabled", 1)):
        if key in values and values[key] is None:
            values[key] = empty
    addresses = values.pop("addresses", None)
    await _check_references(values)
    mode = values.get("mode", (current or {}).get("mode", ""))
    vlan = values.get("untagged_vlan_id", (current or {}).get("untagged_vlan_id"))
    if vlan is not None and not mode:
        raise _invalid({"untagged_vlan_id": "Set the mode to access or tagged to assign an untagged VLAN."})
    return values, addresses


async def _claim(vm: dict, request: Request) -> None:
    """A person changed a discovered VM's interfaces: it becomes manual."""
    if vm.get("origin") != "manual":
        await db.update_virtual_machine(int(vm["id"]), {"origin": "manual"}, user=_session_user(request))


@router.get(f"{PREFIX}/virtual-machines/{{vm_id}}/interfaces")
@scoped("object")
async def list_vm_interfaces(vm_id: int, request: Request) -> dict:
    await _require_vm(request, vm_id)
    return {"interfaces": await db.list_vm_interfaces(vm_id)}


@router.post(f"{PREFIX}/virtual-machines/{{vm_id}}/interfaces", status_code=201)
@scoped("object")
async def create_vm_interface(vm_id: int, body: InterfaceCreate, request: Request) -> dict:
    vm = await _require_vm(request, vm_id, write=True)
    values, addresses = await _interface_values(body, None)
    try:
        row = await db.create_vm_interface(vm_id, values, addresses or [], user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    await _claim(vm, request)
    await _audit_write(request, "vm_interface.create", f"id={row['id']} vm_id={vm_id} name={row['name']}")
    return row


@router.put(f"{PREFIX}/virtual-machines/{{vm_id}}/interfaces/{{interface_id}}")
@scoped("object")
async def update_vm_interface(vm_id: int, interface_id: int, body: InterfaceUpdate, request: Request) -> dict:
    vm = await _require_vm(request, vm_id, write=True)
    current = await _vm_interface(vm_id, interface_id)
    values, addresses = await _interface_values(body, current)
    try:
        row = await db.update_vm_interface(interface_id, values, addresses, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    await _claim(vm, request)
    await _audit_write(request, "vm_interface.update", f"id={interface_id} vm_id={vm_id}")
    return _found(row, "VM interface")


@router.delete(f"{PREFIX}/virtual-machines/{{vm_id}}/interfaces/{{interface_id}}")
@scoped("object")
async def delete_vm_interface(vm_id: int, interface_id: int, request: Request) -> dict:
    vm = await _require_vm(request, vm_id, write=True)
    current = await _vm_interface(vm_id, interface_id)
    await db.delete_vm_interface(interface_id)
    await _claim(vm, request)
    await _audit_write(request, "vm_interface.delete", f"id={interface_id} vm_id={vm_id} name={current['name']}")
    return {"ok": True}


# ── Cloud sync ───────────────────────────────────────────────────────────────

_SYNCED_FIELDS = ("name", "cluster_id", "status", "platform", "primary_ip4", "primary_ip6", "description")


async def _cloud_cluster_type(provider: str) -> int:
    name = CLOUD_CLUSTER_TYPES[provider]
    found = await db.find_cluster_type_by_name(name)
    if found is not None:
        return int(found["id"])
    try:
        row = await db.create_cluster_type(
            name=name, description=f"{CLOUD_PROVIDER_LABELS[provider]} compute instances (cloud sync).", user=SYNC_USER
        )
    except db.VirtualizationNameTaken:
        found = await db.find_cluster_type_by_name(name)
        if found is None:
            raise
        return int(found["id"])
    return int(row["id"])


async def _cloud_cluster(provider: str, account: dict, region: str, cache: dict[str, int]) -> int:
    key = cloud_cluster_key(provider, int(account["id"]), region)
    if key in cache:
        return cache[key]
    found = await db.find_cluster_by_cloud_key(key)
    if found is None:
        type_id = await _cloud_cluster_type(provider)
        name = cloud_cluster_name(provider, str(account.get("name") or account["id"]), region)
        values = {
            "cluster_type_id": type_id,
            "origin": "discovered",
            "cloud_key": key,
            "description": f"{CLOUD_PROVIDER_LABELS[provider]} compute instances of one account and region.",
        }
        try:
            found = await db.create_cluster({**values, "name": name}, user=SYNC_USER)
        except db.VirtualizationNameTaken:
            # A person's cluster has the name already: tell them apart by key.
            found = await db.create_cluster({**values, "name": f"{name} ({key})"[:NAME_MAX]}, user=SYNC_USER)
    cache[key] = int(found["id"])
    return cache[key]


async def _free_name(cluster_id: int, name: str, uid: str, vm_id: int | None) -> str | None:
    """``name``, or ``name (<instance id>)`` when another VM of the cluster
    has it; ``None`` when both are taken."""
    if not await db.vm_name_taken(cluster_id, name, except_id=vm_id):
        return name
    alternative = f"{name} ({uid.rsplit(':', 1)[-1]})"[:NAME_MAX]
    if not await db.vm_name_taken(cluster_id, alternative, except_id=vm_id):
        return alternative
    return None


async def _sync_interfaces(vm_id: int, wanted: list[dict]) -> None:
    """Make a discovered VM's interfaces the discovered ones (by name),
    changing only what differs."""
    current = {str(i["name"]).lower(): i for i in await db.list_vm_interfaces(vm_id)}
    keep: set[str] = set()
    for interface in wanted:
        key = interface["name"].lower()
        keep.add(key)
        values = {k: interface[k] for k in ("name", "mac_address", "description")}
        existing = current.get(key)
        if existing is None:
            await db.create_vm_interface(vm_id, values, interface["addresses"], user=SYNC_USER)
            continue
        changed = {k: v for k, v in values.items() if existing.get(k) != v}
        if changed:
            await db.update_vm_interface(int(existing["id"]), changed, interface["addresses"], user=SYNC_USER)
        elif existing["addresses"] != interface["addresses"]:
            await db.replace_vm_interface_addresses(int(existing["id"]), interface["addresses"])
    for key, existing in current.items():
        if key not in keep:
            await db.delete_vm_interface(int(existing["id"]))


async def _sync_account(account: dict, summary: dict[str, int], cache: dict[str, int]) -> None:
    provider = str(account.get("provider") or "")
    account_id = int(account["id"])
    resources = [decoded_metadata(r) for r in await db.get_cloud_resources(account_id=account_id)]
    subnets = subnet_cidrs(provider, resources)
    instances = [r for r in resources if r.get("resource_type") in COMPUTE_RESOURCE_TYPES[provider]]
    existing = {str(v["cloud_resource_uid"]): v for v in await db.list_cloud_virtual_machines(account_id)}
    seen: set[str] = set()
    for resource in instances:
        uid = str(resource["resource_uid"])
        seen.add(uid)
        vm = existing.get(uid)
        if vm is not None and vm.get("origin") == "manual":
            # A person owns the values; only refresh the link to the row.
            if vm.get("cloud_resource_id") != resource["id"]:
                await db.update_virtual_machine(int(vm["id"]), {"cloud_resource_id": int(resource["id"])}, SYNC_USER)
            summary["kept_manual"] += 1
            continue
        spec = vm_from_resource(provider, resource, subnets)
        cluster_id = await _cloud_cluster(provider, account, str(resource.get("region") or ""), cache)
        name = await _free_name(cluster_id, spec["name"], uid, int(vm["id"]) if vm else None)
        if name is None:
            LOGGER.warning("virtualization: no free name for cloud instance %s in cluster %s", uid, cluster_id)
            summary["skipped"] += 1
            continue
        values: dict[str, Any] = {
            "name": name,
            "cluster_id": cluster_id,
            "status": spec["status"],
            "platform": spec["platform"],
            "primary_ip4": spec["primary_ip4"],
            "primary_ip6": spec["primary_ip6"],
            "description": spec["description"],
            "cloud_resource_id": int(resource["id"]),
        }
        if vm is None:
            vm = await db.create_virtual_machine(
                {**values, "origin": "discovered", "cloud_account_id": account_id, "cloud_resource_uid": uid},
                user=SYNC_USER,
            )
            summary["created"] += 1
        else:
            changed = {k: v for k, v in values.items() if vm.get(k) != v}
            if changed:
                await db.update_virtual_machine(int(vm["id"]), changed, SYNC_USER)
                summary["updated"] += 1
            else:
                summary["unchanged"] += 1
        await _sync_interfaces(int(vm["id"]), spec["interfaces"])
    for uid, vm in existing.items():
        if uid not in seen:
            await _mark_vanished(vm, summary)


async def _mark_vanished(vm: dict, summary: dict[str, int]) -> None:
    if vm.get("origin") == "discovered" and vm.get("status") != "offline":
        await db.update_virtual_machine(int(vm["id"]), {"status": "offline"}, SYNC_USER)
        summary["offline"] += 1


async def sync_cloud_virtual_machines(account_id: int | None = None) -> dict[str, int]:
    """Mirror the stored compute instances of the AWS, Azure and GCP accounts
    (``account_id``: that one only) as virtual machines; see the module
    docstring. A failing account is logged and skipped. Returns counts:
    ``accounts``, ``created``, ``updated``, ``unchanged``, ``kept_manual``,
    ``offline``, ``skipped``, ``failed``."""
    summary = dict.fromkeys(
        ("accounts", "created", "updated", "unchanged", "kept_manual", "offline", "skipped", "failed"), 0
    )
    cache: dict[str, int] = {}
    accounts = await db.list_cloud_accounts()
    if account_id is not None:
        accounts = [a for a in accounts if int(a["id"]) == int(account_id)]
    for account in accounts:
        if str(account.get("provider") or "") not in COMPUTE_RESOURCE_TYPES:
            continue
        try:
            await _sync_account(account, summary, cache)
            summary["accounts"] += 1
        except Exception:
            summary["failed"] += 1
            LOGGER.warning("virtualization: cloud sync of account %s failed", account.get("id"), exc_info=True)
    if account_id is None:
        # VMs of a deleted account: their instances are gone from Plexus.
        for vm in await db.list_cloud_virtual_machines(None):
            await _mark_vanished(vm, summary)
    LOGGER.info("virtualization: cloud sync %s", summary)
    return summary


@admin_router.post(f"{PREFIX}/sync-cloud")
async def sync_cloud(request: Request, body: CloudSyncRequest | None = None) -> dict:
    """Mirror the discovered compute instances as virtual machines now."""
    account_id = body.account_id if body else None
    if account_id is not None and await db.get_cloud_account(account_id) is None:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    summary = await sync_cloud_virtual_machines(account_id)
    await _audit_write(request, "sync_cloud", " ".join(f"{k}={v}" for k, v in summary.items()))
    return {"ok": summary["failed"] == 0, **summary}
