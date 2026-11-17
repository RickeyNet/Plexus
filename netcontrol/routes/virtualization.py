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
"""

from __future__ import annotations

import logging
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.custom_fields import CustomFieldError
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


async def _catalog_create(kind: str, body: CatalogCreate, request: Request) -> dict:
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
async def list_cluster_types() -> dict:
    return {"cluster_types": await db.list_cluster_types()}


@router.post(f"{PREFIX}/cluster-types", status_code=201)
async def create_cluster_type(body: CatalogCreate, request: Request) -> dict:
    return await _catalog_create("cluster-types", body, request)


@router.get(f"{PREFIX}/cluster-types/{{type_id}}")
async def get_cluster_type(type_id: int) -> dict:
    return _found(await db.get_cluster_type(type_id), "Cluster type")


@router.put(f"{PREFIX}/cluster-types/{{type_id}}")
async def update_cluster_type(type_id: int, body: CatalogUpdate, request: Request) -> dict:
    return await _catalog_update("cluster-types", type_id, body, request)


@router.delete(f"{PREFIX}/cluster-types/{{type_id}}")
async def delete_cluster_type(type_id: int, request: Request) -> dict:
    return await _catalog_delete("cluster-types", type_id, request)


@router.get(f"{PREFIX}/cluster-groups")
async def list_cluster_groups() -> dict:
    return {"cluster_groups": await db.list_cluster_groups()}


@router.post(f"{PREFIX}/cluster-groups", status_code=201)
async def create_cluster_group(body: CatalogCreate, request: Request) -> dict:
    return await _catalog_create("cluster-groups", body, request)


@router.get(f"{PREFIX}/cluster-groups/{{group_id}}")
async def get_cluster_group(group_id: int) -> dict:
    return _found(await db.get_cluster_group(group_id), "Cluster group")


@router.put(f"{PREFIX}/cluster-groups/{{group_id}}")
async def update_cluster_group(group_id: int, body: CatalogUpdate, request: Request) -> dict:
    return await _catalog_update("cluster-groups", group_id, body, request)


@router.delete(f"{PREFIX}/cluster-groups/{{group_id}}")
async def delete_cluster_group(group_id: int, request: Request) -> dict:
    return await _catalog_delete("cluster-groups", group_id, request)


# ── Clusters ─────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/clusters")
async def list_clusters(
    cluster_type_id: int | None = Query(default=None),
    cluster_group_id: int | None = Query(default=None),
    site_id: int | None = Query(default=None),
    tenant_id: int | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
) -> dict:
    return {
        "clusters": await db.list_clusters(
            cluster_type_id=cluster_type_id,
            cluster_group_id=cluster_group_id,
            site_id=site_id,
            tenant_id=tenant_id,
            search=search,
        )
    }


@router.post(f"{PREFIX}/clusters", status_code=201)
async def create_cluster(body: ClusterCreate, request: Request) -> dict:
    values = _clean_values(body, _CLUSTER_CLEANERS)
    await _check_references(values)
    try:
        row = await db.create_cluster({**values, "origin": "manual"}, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "cluster.create", f"id={row['id']} name={row['name']}")
    return row


@router.get(f"{PREFIX}/clusters/{{cluster_id}}")
async def get_cluster(cluster_id: int) -> dict:
    """The cluster with its member ``hosts`` and its ``virtual_machines``."""
    row = _found(await db.get_cluster(cluster_id), "Cluster")
    row["hosts"] = await db.list_cluster_hosts(cluster_id)
    row["virtual_machines"] = await db.list_virtual_machines(cluster_id=cluster_id)
    return row


@router.put(f"{PREFIX}/clusters/{{cluster_id}}")
async def update_cluster(cluster_id: int, body: ClusterUpdate, request: Request) -> dict:
    _found(await db.get_cluster(cluster_id), "Cluster")
    values = _clean_values(body, _CLUSTER_CLEANERS)
    for required in ("name", "cluster_type_id", "description", "comments"):
        if required in values and values[required] is None:
            raise _invalid({required: "This value cannot be cleared."})
    await _check_references(values)
    try:
        row = await db.update_cluster(cluster_id, values, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    row = _found(row, "Cluster")
    await _audit_write(request, "cluster.update", f"id={cluster_id} fields={','.join(sorted(values))}")
    return row


@router.delete(f"{PREFIX}/clusters/{{cluster_id}}")
async def delete_cluster(cluster_id: int, request: Request) -> dict:
    row = _found(await db.get_cluster(cluster_id), "Cluster")
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
async def add_cluster_host(cluster_id: int, body: ClusterHostAdd, request: Request) -> dict:
    """Add a hypervisor host to the cluster; 409 when it is a member already."""
    cluster = _found(await db.get_cluster(cluster_id), "Cluster")
    await _check_references({"host_id": body.host_id})
    if not await db.add_cluster_host(cluster_id, body.host_id, user=_session_user(request)):
        raise HTTPException(status_code=409, detail="The host is already a member of this cluster.")
    await _audit_write(request, "cluster.host_add", f"id={cluster_id} name={cluster['name']} host_id={body.host_id}")
    return {"ok": True, "hosts": await db.list_cluster_hosts(cluster_id)}


@router.delete(f"{PREFIX}/clusters/{{cluster_id}}/hosts/{{host_id}}")
async def remove_cluster_host(cluster_id: int, host_id: int, request: Request) -> dict:
    cluster = _found(await db.get_cluster(cluster_id), "Cluster")
    if not await db.remove_cluster_host(cluster_id, host_id):
        raise HTTPException(status_code=404, detail="The host is not a member of this cluster.")
    await _audit_write(request, "cluster.host_remove", f"id={cluster_id} name={cluster['name']} host_id={host_id}")
    return {"ok": True}


@router.get(f"{PREFIX}/tenants")
async def tenant_choices() -> dict:
    """The tenants a cluster or VM can name (id and name only), for callers
    with the virtualization feature but not the organization one."""
    return {"tenants": [{"id": t["id"], "name": t["name"]} for t in await db.list_tenants()]}


@router.get(f"{PREFIX}/hosts/{{host_id}}/clusters")
async def host_clusters(host_id: int) -> dict:
    """The clusters a host is a hypervisor of."""
    return {"host_id": host_id, "clusters": await db.get_host_clusters(host_id)}


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
async def list_virtual_machines(
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
    return {
        "virtual_machines": await db.list_virtual_machines(
            cluster_id=cluster_id,
            cluster_type_id=cluster_type_id,
            cluster_group_id=cluster_group_id,
            site_id=site_id,
            tenant_id=tenant_id,
            role_id=role_id,
            status=status,
            origin=origin,
            search=search,
        )
    }


@router.post(f"{PREFIX}/virtual-machines", status_code=201)
async def create_virtual_machine(body: VmCreate, request: Request) -> dict:
    values = _clean_values(body, _VM_CLEANERS)
    await _check_references(values)
    await _cloud_link(values)
    try:
        row = await db.create_virtual_machine({**values, "origin": "manual"}, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "virtual_machine.create", f"id={row['id']} name={row['name']}")
    return row


@router.get(f"{PREFIX}/virtual-machines/{{vm_id}}")
async def get_virtual_machine(vm_id: int) -> dict:
    """The VM with its ``interfaces`` (each with its ``addresses``)."""
    row = _found(await db.get_virtual_machine(vm_id), "Virtual machine")
    row["interfaces"] = await db.list_vm_interfaces(vm_id)
    return row


@router.put(f"{PREFIX}/virtual-machines/{{vm_id}}")
async def update_virtual_machine(vm_id: int, body: VmUpdate, request: Request) -> dict:
    """A person's edit: the VM becomes ``manual``, so the cloud sync no
    longer changes its values."""
    current = _found(await db.get_virtual_machine(vm_id), "Virtual machine")
    values = _clean_values(body, _VM_CLEANERS)
    for required in ("name", "cluster_id", "status", "platform", "primary_ip4", "primary_ip6"):
        if required in values and values[required] is None:
            raise _invalid({required: "This value cannot be cleared."})
    for text in ("description", "comments"):
        if text in values and values[text] is None:
            values[text] = ""
    await _check_references(values)
    await _cloud_link(values, current)
    try:
        row = await db.update_virtual_machine(vm_id, {**values, "origin": "manual"}, user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    row = _found(row, "Virtual machine")
    await _audit_write(request, "virtual_machine.update", f"id={vm_id} fields={','.join(sorted(values))}")
    return row


@router.delete(f"{PREFIX}/virtual-machines/{{vm_id}}")
async def delete_virtual_machine(vm_id: int, request: Request) -> dict:
    row = _found(await db.get_virtual_machine(vm_id), "Virtual machine")
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
async def list_vm_interfaces(vm_id: int) -> dict:
    _found(await db.get_virtual_machine(vm_id), "Virtual machine")
    return {"interfaces": await db.list_vm_interfaces(vm_id)}


@router.post(f"{PREFIX}/virtual-machines/{{vm_id}}/interfaces", status_code=201)
async def create_vm_interface(vm_id: int, body: InterfaceCreate, request: Request) -> dict:
    vm = _found(await db.get_virtual_machine(vm_id), "Virtual machine")
    values, addresses = await _interface_values(body, None)
    try:
        row = await db.create_vm_interface(vm_id, values, addresses or [], user=_session_user(request))
    except db.VirtualizationNameTaken as exc:
        raise _conflict(exc) from exc
    await _claim(vm, request)
    await _audit_write(request, "vm_interface.create", f"id={row['id']} vm_id={vm_id} name={row['name']}")
    return row


@router.put(f"{PREFIX}/virtual-machines/{{vm_id}}/interfaces/{{interface_id}}")
async def update_vm_interface(vm_id: int, interface_id: int, body: InterfaceUpdate, request: Request) -> dict:
    vm = _found(await db.get_virtual_machine(vm_id), "Virtual machine")
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
async def delete_vm_interface(vm_id: int, interface_id: int, request: Request) -> dict:
    vm = _found(await db.get_virtual_machine(vm_id), "Virtual machine")
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
