"""Dynamic groups API: saved host filters (``/api/dynamic-groups``).

Registered in ``app.py`` under the ``inventory`` feature (``inventory.write``
for changes). Validation and resolution live in ``netcontrol.dynamic_groups``.

Object scope: every member list and preview is resolved among the hosts the
caller may read, so a scoped user never sees a host outside their scope
through a dynamic group. Definitions are shared, and a scoped user may not
create, change or delete one: a dynamic group can be a job target, and a
scoped user must not be able to redirect what it targets for others.
"""

from __future__ import annotations

from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.dynamic_groups import (
    DESCRIPTION_MAX,
    NAME_MAX,
    DynamicGroupFilterError,
    member_rows,
    resolve_hosts,
    validate_filter,
)
from netcontrol.object_scope import refuse_scoped, request_scope, scoped
from netcontrol.routes.custom_fields import _invalid
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()

PREFIX = "/api/dynamic-groups"
NOT_FOUND = "Dynamic group not found"
MEMBERS_MAX = 5000


class DynamicGroupCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=NAME_MAX)
    description: str = Field(default="", max_length=DESCRIPTION_MAX)
    object_type: str = Field(default="host", max_length=20)
    filter: dict[str, Any]


class DynamicGroupUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=NAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    filter: dict[str, Any] | None = None


class DynamicGroupPreview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filter: dict[str, Any]


def _clean_name(raw: str) -> str:
    name = " ".join(raw.split())
    if not name:
        raise _invalid("Name is required.", {"name": "Name is required."})
    return name


async def _checked_filter(raw: dict, request: Request) -> dict:
    try:
        return await validate_filter(raw, await request_scope(request))
    except DynamicGroupFilterError as exc:
        raise _invalid(exc.message, exc.fields) from exc


async def _found(dynamic_group_id: int) -> dict:
    group = await db.get_dynamic_group(int(dynamic_group_id))
    if group is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return group


async def _members(filter_def: dict, request: Request, limit: int) -> dict:
    hosts = await resolve_hosts(filter_def, await request_scope(request))
    return {"count": len(hosts), "hosts": await member_rows(hosts[:limit]), "truncated": len(hosts) > limit}


def _view(group: dict, count: int | None = None) -> dict:
    out = {k: group.get(k) for k in ("id", "name", "description", "object_type", "filter", "created_by")}
    out.update(
        created_at=group.get("created_at") or "",
        updated_at=group.get("updated_at") or "",
        updated_by=group.get("updated_by") or "",
    )
    if count is not None:
        out["member_count"] = count
    return out


@router.get(PREFIX)
@scoped("list")
async def list_dynamic_groups(request: Request) -> list[dict]:
    """Every dynamic group with ``member_count``: the hosts it matches now
    among those the caller may read."""
    scope = await request_scope(request)
    groups = await db.list_dynamic_groups()
    return [_view(g, len(await resolve_hosts(g["filter"], scope))) for g in groups]


@router.post(f"{PREFIX}/preview")
@scoped("list")
async def preview_dynamic_group(body: DynamicGroupPreview, request: Request) -> dict:
    """The hosts an unsaved filter matches now (within the caller's scope)."""
    filter_def = await _checked_filter(body.filter, request)
    return {"filter": filter_def, **await _members(filter_def, request, MEMBERS_MAX)}


@router.post(PREFIX, status_code=201)
@scoped("refused")
async def create_dynamic_group(body: DynamicGroupCreate, request: Request) -> dict:
    await refuse_scoped(request)
    name = _clean_name(body.name)
    if body.object_type != "host":
        raise _invalid("Only host dynamic groups are supported.", {"object_type": "Must be 'host'."})
    filter_def = await _checked_filter(body.filter, request)
    user = _session_user(request)
    try:
        group = await db.create_dynamic_group(
            name=name, description=body.description.strip(), filter_def=filter_def, created_by=user
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit(
        "inventory",
        "dynamic_group.create",
        user=user,
        detail=f"id={group['id']} name={name}",
        correlation_id=_corr_id(request),
    )
    return _view(group)


@router.get(f"{PREFIX}/{{dynamic_group_id}}")
@scoped("list")
async def get_dynamic_group(dynamic_group_id: int, request: Request) -> dict:
    group = await _found(dynamic_group_id)
    return _view(group, len(await resolve_hosts(group["filter"], await request_scope(request))))


@router.get(f"{PREFIX}/{{dynamic_group_id}}/members")
@scoped("list")
async def list_dynamic_group_members(
    dynamic_group_id: int, request: Request, limit: int = Query(default=MEMBERS_MAX, ge=1, le=MEMBERS_MAX)
) -> dict:
    """The hosts the group matches now, among those the caller may read."""
    group = await _found(dynamic_group_id)
    return {"id": group["id"], "name": group["name"], **await _members(group["filter"], request, limit)}


@router.put(f"{PREFIX}/{{dynamic_group_id}}")
@scoped("refused")
async def update_dynamic_group(dynamic_group_id: int, body: DynamicGroupUpdate, request: Request) -> dict:
    await refuse_scoped(request)
    await _found(dynamic_group_id)
    name = _clean_name(body.name) if body.name is not None else None
    filter_def = await _checked_filter(body.filter, request) if body.filter is not None else None
    user = _session_user(request)
    try:
        group = await db.update_dynamic_group(
            dynamic_group_id,
            name=name,
            description=body.description.strip() if body.description is not None else None,
            filter_def=filter_def,
            updated_by=user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if group is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    await _audit(
        "inventory",
        "dynamic_group.update",
        user=user,
        detail=f"id={dynamic_group_id} name={group['name']}",
        correlation_id=_corr_id(request),
    )
    return _view(group)


@router.delete(f"{PREFIX}/{{dynamic_group_id}}")
@scoped("refused")
async def delete_dynamic_group(dynamic_group_id: int, request: Request) -> dict:
    await refuse_scoped(request)
    group = await _found(dynamic_group_id)
    await db.delete_dynamic_group(dynamic_group_id)
    await _audit(
        "inventory",
        "dynamic_group.delete",
        user=_session_user(request),
        detail=f"id={dynamic_group_id} name={group['name']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}
