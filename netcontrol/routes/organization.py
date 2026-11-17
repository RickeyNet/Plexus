"""Location hierarchy and tenancy API: regions, the location tree, tenant
groups and tenants.

Two routers, each registered in ``app.py``:

- ``router`` (signed-in user with the ``organization`` feature): read the
  regions, the location tree (regions > sites > floors with host counts),
  the sites, the tenant groups and the tenants with what each owns.
- ``admin_router`` (admin): create, change and delete regions, tenant
  groups and tenants, like the other admin catalogues.

Sites are written through ``/api/geo/sites`` (``netcontrol.routes.
geolocation``), which takes the region, status, facility, time zone and
tenant too. Rules live in ``netcontrol.organization``, storage in
``routes.db.organization``. See docs/locations-and-tenancy.md.
"""

from __future__ import annotations

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.organization import (
    COMMENTS_MAX,
    DESCRIPTION_MAX,
    NAME_MAX,
    OrganizationValueError,
    clean_name,
    clean_text,
)
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()
admin_router = APIRouter()

PREFIX = "/api/organization"
# Longest text a body takes before trimming; the real limits are checked
# after trimming.
_RAW_NAME = NAME_MAX + 100


# ── Request bodies ───────────────────────────────────────────────────────────


class TreeNodeCreate(BaseModel):
    name: str = Field(max_length=_RAW_NAME)
    parent_id: int | None = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX + 100)


class TreeNodeUpdate(BaseModel):
    """A key left out keeps its value; ``parent_id`` ``null`` moves the node
    to the top level."""

    name: str | None = Field(default=None, max_length=_RAW_NAME)
    parent_id: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + 100)


class TenantCreate(BaseModel):
    name: str = Field(max_length=_RAW_NAME)
    group_id: int | None = None
    description: str = Field(default="", max_length=DESCRIPTION_MAX + 100)
    comments: str = Field(default="", max_length=COMMENTS_MAX + 100)


class TenantUpdate(BaseModel):
    """A key left out keeps its value; ``group_id`` ``null`` takes the
    tenant out of its group."""

    name: str | None = Field(default=None, max_length=_RAW_NAME)
    group_id: int | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX + 100)
    comments: str | None = Field(default=None, max_length=COMMENTS_MAX + 100)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _invalid(fields: dict[str, str]) -> HTTPException:
    return HTTPException(status_code=422, detail={"message": " ".join(fields.values()), "fields": fields})


def _found(record: dict | None, what: str) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return record


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("organization", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


def _text_values(body: BaseModel, limits: dict[str, int], *, create: bool) -> dict:
    """The cleaned text values of a body (name and free text); 422 naming
    each bad field. An update keeps only the keys it sent (``null`` too)."""
    sent = body.model_fields_set
    values: dict = {}
    errors: dict[str, str] = {}
    for key, limit in limits.items():
        if not create and (key not in sent or getattr(body, key) is None):
            continue
        try:
            raw = getattr(body, key)
            values[key] = clean_name(raw, key, limit) if key == "name" else clean_text(raw, key, limit)
        except OrganizationValueError as exc:
            errors[exc.field] = exc.message
    if errors:
        raise _invalid(errors)
    return values


async def _check_parent(nodes: list[dict], node_id: int | None, parent_id: int | None, field: str, what: str) -> None:
    """422 when ``parent_id`` names no node, or is ``node_id`` itself or one
    of its descendants (a cycle)."""
    if parent_id is None:
        return
    by_id = {n["id"]: n for n in nodes}
    if parent_id not in by_id:
        raise _invalid({field: f"No {what} with id {parent_id}."})
    if node_id is None:
        return
    current: int | None = parent_id
    seen: set[int] = set()
    while current is not None and current not in seen:
        if current == node_id:
            raise _invalid({field: f"A {what} cannot be moved under itself or one of its descendants."})
        seen.add(current)
        current = by_id[current]["parent_id"] if current in by_id else None


def _conflict(exc: ValueError) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


def _describe(usage: dict[str, int]) -> str:
    return ", ".join(f"{n} {k}" for k, n in usage.items() if n)


_NODE_TEXT = {"name": NAME_MAX, "description": DESCRIPTION_MAX}
_TENANT_TEXT = {"name": NAME_MAX, "description": DESCRIPTION_MAX, "comments": COMMENTS_MAX}


# ── Regions and the location tree ────────────────────────────────────────────


@router.get(f"{PREFIX}/regions")
async def list_regions() -> dict:
    return {"regions": await db.list_regions()}


@router.get(f"{PREFIX}/regions/{{region_id}}")
async def get_region(region_id: int) -> dict:
    return _found(await db.get_region(region_id), "Region")


@router.get(f"{PREFIX}/locations")
async def location_tree() -> dict:
    """Regions > sites > floors, with host counts (see ``get_location_tree``)."""
    return await db.get_location_tree()


@router.get(f"{PREFIX}/sites")
async def list_sites() -> dict:
    """Every site with its region, tenant, status, facility, time zone and counts."""
    return {"sites": await db.list_geo_sites()}


@admin_router.post(f"{PREFIX}/regions", status_code=201)
async def create_region(body: TreeNodeCreate, request: Request) -> dict:
    values = _text_values(body, _NODE_TEXT, create=True)
    await _check_parent(await db.list_regions(), None, body.parent_id, "parent_id", "region")
    try:
        record = await db.create_region(parent_id=body.parent_id, user=_session_user(request), **values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "region_create", f"id={record['id']} name={record['name']}")
    return record


@admin_router.put(f"{PREFIX}/regions/{{region_id}}")
async def update_region(region_id: int, body: TreeNodeUpdate, request: Request) -> dict:
    _found(await db.get_region(region_id), "Region")
    values = _text_values(body, _NODE_TEXT, create=False)
    if "parent_id" in body.model_fields_set:
        await _check_parent(await db.list_regions(), region_id, body.parent_id, "parent_id", "region")
        values["parent_id"] = body.parent_id
    try:
        record = await db.update_region(region_id, values=values, user=_session_user(request))
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Region")
    await _audit_write(request, "region_update", f"id={region_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/regions/{{region_id}}")
async def delete_region(region_id: int, request: Request) -> dict:
    record = _found(await db.get_region(region_id), "Region")
    usage = await db.region_usage(region_id)
    if any(usage.values()):
        raise HTTPException(
            status_code=409,
            detail={
                "message": f"Region {record['name']} still holds {_describe(usage)}; move or delete them first.",
                "usage": usage,
            },
        )
    await db.delete_region(region_id)
    await _audit_write(request, "region_delete", f"id={region_id} name={record['name']}")
    return {"ok": True}


# ── Tenant groups ────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/tenant-groups")
async def list_tenant_groups() -> dict:
    return {"tenant_groups": await db.list_tenant_groups()}


@router.get(f"{PREFIX}/tenant-groups/{{group_id}}")
async def get_tenant_group(group_id: int) -> dict:
    return _found(await db.get_tenant_group(group_id), "Tenant group")


@admin_router.post(f"{PREFIX}/tenant-groups", status_code=201)
async def create_tenant_group(body: TreeNodeCreate, request: Request) -> dict:
    values = _text_values(body, _NODE_TEXT, create=True)
    await _check_parent(await db.list_tenant_groups(), None, body.parent_id, "parent_id", "tenant group")
    try:
        record = await db.create_tenant_group(parent_id=body.parent_id, user=_session_user(request), **values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "tenant_group_create", f"id={record['id']} name={record['name']}")
    return record


@admin_router.put(f"{PREFIX}/tenant-groups/{{group_id}}")
async def update_tenant_group(group_id: int, body: TreeNodeUpdate, request: Request) -> dict:
    _found(await db.get_tenant_group(group_id), "Tenant group")
    values = _text_values(body, _NODE_TEXT, create=False)
    if "parent_id" in body.model_fields_set:
        await _check_parent(await db.list_tenant_groups(), group_id, body.parent_id, "parent_id", "tenant group")
        values["parent_id"] = body.parent_id
    try:
        record = await db.update_tenant_group(group_id, values=values, user=_session_user(request))
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Tenant group")
    await _audit_write(request, "tenant_group_update", f"id={group_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/tenant-groups/{{group_id}}")
async def delete_tenant_group(group_id: int, request: Request) -> dict:
    """Refused (409) while the group has child groups; its tenants are left
    in no group."""
    record = _found(await db.get_tenant_group(group_id), "Tenant group")
    usage = await db.tenant_group_usage(group_id)
    if usage["groups"]:
        raise HTTPException(
            status_code=409,
            detail={
                "message": f"Tenant group {record['name']} has {usage['groups']} child groups; "
                "move or delete them first.",
                "usage": usage,
            },
        )
    await db.delete_tenant_group(group_id)
    await _audit_write(request, "tenant_group_delete", f"id={group_id} name={record['name']}")
    return {"ok": True, "tenants": usage["tenants"]}


# ── Tenants ──────────────────────────────────────────────────────────────────


async def _check_group(group_id: int | None) -> None:
    if group_id is not None and await db.get_tenant_group(group_id) is None:
        raise _invalid({"group_id": f"No tenant group with id {group_id}."})


@router.get(f"{PREFIX}/tenants")
async def list_tenants(group_id: int | None = Query(default=None, ge=1)) -> dict:
    """Every tenant; ``group_id`` keeps those of the group and its descendants."""
    groups = await db.tenant_group_subtree_ids([group_id]) if group_id is not None else None
    return {"tenants": await db.list_tenants(group_ids=groups)}


@router.get(f"{PREFIX}/tenants/{{tenant_id}}")
async def get_tenant(tenant_id: int) -> dict:
    """The tenant with ``counts``: how many rows it owns per kind (hosts,
    prefixes, ip_addresses, vlans, vrfs, sites, and every later table with a
    ``tenant_id`` column)."""
    record = _found(await db.get_tenant(tenant_id), "Tenant")
    return {**record, "counts": await db.tenant_usage(tenant_id)}


@admin_router.post(f"{PREFIX}/tenants", status_code=201)
async def create_tenant(body: TenantCreate, request: Request) -> dict:
    values = _text_values(body, _TENANT_TEXT, create=True)
    await _check_group(body.group_id)
    try:
        record = await db.create_tenant(group_id=body.group_id, user=_session_user(request), **values)
    except ValueError as exc:
        raise _conflict(exc) from exc
    await _audit_write(request, "tenant_create", f"id={record['id']} name={record['name']}")
    return record


@admin_router.put(f"{PREFIX}/tenants/{{tenant_id}}")
async def update_tenant(tenant_id: int, body: TenantUpdate, request: Request) -> dict:
    _found(await db.get_tenant(tenant_id), "Tenant")
    values = _text_values(body, _TENANT_TEXT, create=False)
    if "group_id" in body.model_fields_set:
        await _check_group(body.group_id)
        values["group_id"] = body.group_id
    try:
        record = await db.update_tenant(tenant_id, values=values, user=_session_user(request))
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Tenant")
    await _audit_write(request, "tenant_update", f"id={tenant_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/tenants/{{tenant_id}}")
async def delete_tenant(tenant_id: int, request: Request) -> dict:
    """Delete the tenant; what it owned stays, with no tenant. ``released``:
    how many rows lost it, per kind."""
    record = _found(await db.get_tenant(tenant_id), "Tenant")
    usage = await db.tenant_usage(tenant_id)
    await db.delete_tenant(tenant_id)
    await _audit_write(request, "tenant_delete", f"id={tenant_id} name={record['name']} released={sum(usage.values())}")
    return {"ok": True, "released": usage}
