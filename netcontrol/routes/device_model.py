"""Device model for hosts: the four catalogues (manufacturers, device types,
roles, lifecycle statuses), bulk edit of host device values, and the helpers
the inventory endpoints use to validate, carry and filter those values.

Three routers, each registered in ``app.py``:

- ``router`` (any signed-in user): read the catalogues.
- ``admin_router`` (admin): create, change and delete catalogue records.
- ``inventory_router`` (``inventory`` feature): bulk edit hosts.

Rules live in ``netcontrol.device_model``, storage in
``routes.db.device_model``. ``hosts.device_type`` (the SSH driver key) and
``hosts.status`` (reachability) are not touched here.
"""

from __future__ import annotations

from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from netcontrol.custom_fields import CustomFieldError, TagColor
from netcontrol.device_model import (
    DESCRIPTION_MAX,
    HOST_DEVICE_FIELDS,
    LOCATION_DETAIL_MAX,
    MANUFACTURER_NAME_MAX,
    MODEL_MAX,
    PART_NUMBER_MAX,
    ROLE_NAME_MAX,
    U_HEIGHT_MAX,
    clean_name,
    parse_device_filters,
)
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()
admin_router = APIRouter()
inventory_router = APIRouter()

BULK_EDIT_MAX_HOSTS = 5000
# Longest name accepted by a body before trimming; the real limits are
# checked after trimming (``clean_name``).
_RAW_NAME_MAX = 200

PREFIX = "/api/dcim"


# ── Request bodies ───────────────────────────────────────────────────────────


class HostDeviceValues(BaseModel):
    """The device values of a host write. A key that is left out leaves the
    stored value alone; ``null`` clears it (and, for a device type or role,
    lets discovery fill it again)."""

    device_type_id: int | None = None
    role_id: int | None = None
    lifecycle_status_id: int | None = None
    site_id: int | None = None
    location_detail: str | None = Field(default=None, max_length=LOCATION_DETAIL_MAX)


class ManufacturerCreate(BaseModel):
    name: str = Field(max_length=_RAW_NAME_MAX)
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class ManufacturerUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=_RAW_NAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class DeviceTypeCreate(BaseModel):
    manufacturer_id: int
    model: str = Field(max_length=_RAW_NAME_MAX)
    part_number: str = Field(default="", max_length=PART_NUMBER_MAX)
    u_height: int = Field(default=0, ge=0, le=U_HEIGHT_MAX)
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class DeviceTypeUpdate(BaseModel):
    manufacturer_id: int | None = None
    model: str | None = Field(default=None, max_length=_RAW_NAME_MAX)
    part_number: str | None = Field(default=None, max_length=PART_NUMBER_MAX)
    u_height: int | None = Field(default=None, ge=0, le=U_HEIGHT_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class RoleCreate(BaseModel):
    name: str = Field(max_length=_RAW_NAME_MAX)
    color: TagColor = "gray"
    description: str = Field(default="", max_length=DESCRIPTION_MAX)


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=_RAW_NAME_MAX)
    color: TagColor | None = None
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class StatusCreate(RoleCreate):
    is_default: bool = False


class StatusUpdate(RoleUpdate):
    is_default: bool | None = None


class BulkEdit(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host_ids: list[int] = Field(min_length=1, max_length=BULK_EDIT_MAX_HOSTS)
    values: HostDeviceValues = Field(alias="set")


# ── Helpers shared with the inventory routes ─────────────────────────────────


def _invalid(message: str, fields: dict[str, str]) -> HTTPException:
    return HTTPException(status_code=400, detail={"message": message, "fields": fields})


def sent_device_values(body: BaseModel) -> dict[str, Any]:
    """The device values a host body sent: only the keys present, with
    ``location_detail`` trimmed (``null`` as ``""``)."""
    sent = body.model_fields_set
    values = {f: getattr(body, f) for f in HOST_DEVICE_FIELDS if f in sent}
    if "location_detail" in values:
        values["location_detail"] = (values["location_detail"] or "").strip()
    return values


async def check_device_values(values: dict[str, Any]) -> None:
    """400 with one message per field when an id names no record."""
    errors = await db.check_device_refs(values)
    if errors:
        raise _invalid("Unknown id: " + ", ".join(sorted(errors)) + ".", errors)


async def audit_device_write(request: Request, action: str, detail: str) -> None:
    await _audit("device_model", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


def describe_values(values: dict[str, Any]) -> str:
    """Audit text for device values: ``key=value`` pairs, ``-`` for none."""
    return " ".join(f"{k}={'-' if v is None else v}" for k, v in values.items()) or "-"


_DISPLAY = (
    ("device_type_id", "hardware", ("id", "model", "manufacturer_id", "manufacturer")),
    ("role_id", "role", ("id", "name", "color")),
    ("lifecycle_status_id", "lifecycle_status", ("id", "name", "color")),
    ("site_id", "site", ("id", "name")),
)


async def attach_device_data(rows: list[dict]) -> None:
    """Set the display objects ``hardware``, ``role``, ``lifecycle_status``
    and ``site`` on every host row (``None`` when not set), from one lookup
    per catalogue. Rows missing the stored keys get them as unset."""
    if not rows:
        return
    for row in rows:
        for field in HOST_DEVICE_FIELDS:
            row.setdefault(field, "" if field == "location_detail" else None)
        row["location_detail"] = row["location_detail"] or ""
    lookup = await db.get_device_display_objects(rows)
    for row in rows:
        for field, name, keys in _DISPLAY:
            record = lookup[name].get(int(row[field])) if row[field] is not None else None
            row[name] = {k: record[k] for k in keys} if record else None


async def matching_host_ids(query_params) -> dict[int, int] | None:
    """The hosts matching the request's device filters (``manufacturer_id=``,
    ``device_type_id=``, ``role_id=``, ``lifecycle_status_id=``,
    ``site_id=``; each repeatable, ``none`` for no value), as host id to
    group id. ``None`` when there are none; 400 on a value that is neither an
    id nor ``none``."""
    filters, errors = parse_device_filters(query_params.multi_items())
    if errors:
        raise _invalid("Filter not valid: " + ", ".join(sorted(errors)), errors)
    if not filters:
        return None
    return await db.find_host_ids_by_device_filters(filters)


# ── Catalogue helpers ────────────────────────────────────────────────────────


def _unprocessable(message: str) -> HTTPException:
    return HTTPException(status_code=422, detail=message)


def _name(raw: str, label: str, limit: int) -> str:
    try:
        return clean_name(raw, label, limit)
    except CustomFieldError as exc:
        raise _unprocessable(str(exc)) from exc


def _conflict(exc: ValueError) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


def _found(record: dict | None, what: str) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return record


async def _delete(kind: str, record: dict, label: str, request: Request, confirm: bool) -> dict:
    """The shared delete: 409 with ``{message, affected}`` when hosts use the
    record and ``confirm`` is not set; otherwise delete and audit."""
    affected = await db.count_catalogue_hosts(kind, record["id"])
    if affected and not confirm:
        raise HTTPException(
            status_code=409,
            detail={
                "message": f"{affected} hosts use {label}; they lose it. Send confirm=true to go ahead.",
                "affected": affected,
            },
        )
    try:
        affected = await db.delete_catalogue_record(kind, record["id"])
    except ValueError as exc:
        raise _conflict(exc) from exc
    await audit_device_write(request, f"{kind}_delete", f"id={record['id']} {label} hosts={affected}")
    return {"ok": True, "affected": affected}


# ── Read (any signed-in user) ────────────────────────────────────────────────


@router.get(f"{PREFIX}/manufacturers")
async def list_manufacturers() -> list[dict]:
    return await db.list_manufacturers()


@router.get(f"{PREFIX}/device-types")
async def list_device_types(manufacturer_id: int | None = Query(default=None)) -> list[dict]:
    return await db.list_device_types(manufacturer_id)


@router.get(f"{PREFIX}/roles")
async def list_roles() -> list[dict]:
    return await db.list_device_roles()


@router.get(f"{PREFIX}/statuses")
async def list_statuses() -> list[dict]:
    return await db.list_lifecycle_statuses()


# ── Manufacturers (admin) ────────────────────────────────────────────────────


@admin_router.post(f"{PREFIX}/manufacturers", status_code=201)
async def create_manufacturer(body: ManufacturerCreate, request: Request) -> dict:
    name = _name(body.name, "Manufacturer name", MANUFACTURER_NAME_MAX)
    try:
        record = await db.create_manufacturer(name=name, description=body.description.strip())
    except ValueError as exc:
        raise _conflict(exc) from exc
    await audit_device_write(request, "manufacturer_create", f"id={record['id']} name={name}")
    return record


@admin_router.put(f"{PREFIX}/manufacturers/{{manufacturer_id}}")
async def update_manufacturer(manufacturer_id: int, body: ManufacturerUpdate, request: Request) -> dict:
    current = _found(await db.get_manufacturer(manufacturer_id), "Manufacturer")
    name = _name(body.name, "Manufacturer name", MANUFACTURER_NAME_MAX) if body.name is not None else current["name"]
    description = body.description.strip() if body.description is not None else current["description"]
    try:
        record = await db.update_manufacturer(manufacturer_id, name=name, description=description)
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Manufacturer")
    await audit_device_write(request, "manufacturer_update", f"id={manufacturer_id} name={name}")
    return record


@admin_router.delete(f"{PREFIX}/manufacturers/{{manufacturer_id}}")
async def delete_manufacturer(manufacturer_id: int, request: Request, confirm: bool = Query(default=False)) -> dict:
    record = _found(await db.get_manufacturer(manufacturer_id), "Manufacturer")
    return await _delete("manufacturer", record, f"a device type of {record['name']}", request, confirm)


# ── Device types (admin) ─────────────────────────────────────────────────────


async def _check_manufacturer(manufacturer_id: int) -> None:
    if await db.get_manufacturer(manufacturer_id) is None:
        raise _invalid("Unknown id: manufacturer_id.", {"manufacturer_id": f"No record with id {manufacturer_id}."})


@admin_router.post(f"{PREFIX}/device-types", status_code=201)
async def create_device_type(body: DeviceTypeCreate, request: Request) -> dict:
    model = _name(body.model, "Model", MODEL_MAX)
    await _check_manufacturer(body.manufacturer_id)
    try:
        record = await db.create_device_type(
            manufacturer_id=body.manufacturer_id,
            model=model,
            part_number=body.part_number.strip(),
            u_height=body.u_height,
            description=body.description.strip(),
        )
    except ValueError as exc:
        raise _conflict(exc) from exc
    await audit_device_write(request, "device_type_create", f"id={record['id']} model={model}")
    return record


@admin_router.put(f"{PREFIX}/device-types/{{device_type_id}}")
async def update_device_type(device_type_id: int, body: DeviceTypeUpdate, request: Request) -> dict:
    current = _found(await db.get_device_type(device_type_id), "Device type")
    model = _name(body.model, "Model", MODEL_MAX) if body.model is not None else current["model"]
    manufacturer_id = body.manufacturer_id if body.manufacturer_id is not None else current["manufacturer_id"]
    if manufacturer_id != current["manufacturer_id"]:
        await _check_manufacturer(manufacturer_id)
    try:
        record = await db.update_device_type(
            device_type_id,
            manufacturer_id=manufacturer_id,
            model=model,
            part_number=body.part_number.strip() if body.part_number is not None else current["part_number"],
            u_height=body.u_height if body.u_height is not None else current["u_height"],
            description=body.description.strip() if body.description is not None else current["description"],
        )
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Device type")
    await audit_device_write(request, "device_type_update", f"id={device_type_id} model={model}")
    return record


@admin_router.delete(f"{PREFIX}/device-types/{{device_type_id}}")
async def delete_device_type(device_type_id: int, request: Request, confirm: bool = Query(default=False)) -> dict:
    record = _found(await db.get_device_type(device_type_id), "Device type")
    return await _delete("device_type", record, f"device type {record['model']}", request, confirm)


# ── Roles (admin) ────────────────────────────────────────────────────────────


@admin_router.post(f"{PREFIX}/roles", status_code=201)
async def create_role(body: RoleCreate, request: Request) -> dict:
    name = _name(body.name, "Role name", ROLE_NAME_MAX)
    try:
        record = await db.create_device_role(name=name, color=body.color, description=body.description.strip())
    except ValueError as exc:
        raise _conflict(exc) from exc
    await audit_device_write(request, "role_create", f"id={record['id']} name={name}")
    return record


@admin_router.put(f"{PREFIX}/roles/{{role_id}}")
async def update_role(role_id: int, body: RoleUpdate, request: Request) -> dict:
    current = _found(await db.get_device_role(role_id), "Role")
    name = _name(body.name, "Role name", ROLE_NAME_MAX) if body.name is not None else current["name"]
    try:
        record = await db.update_device_role(
            role_id,
            name=name,
            color=body.color or current["color"],
            description=body.description.strip() if body.description is not None else current["description"],
        )
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Role")
    await audit_device_write(request, "role_update", f"id={role_id} name={name}")
    return record


@admin_router.delete(f"{PREFIX}/roles/{{role_id}}")
async def delete_role(role_id: int, request: Request, confirm: bool = Query(default=False)) -> dict:
    record = _found(await db.get_device_role(role_id), "Role")
    return await _delete("role", record, f"role {record['name']}", request, confirm)


# ── Lifecycle statuses (admin) ───────────────────────────────────────────────

_DEFAULT_RULE = "A status stops being the default only when another status is made the default."


@admin_router.post(f"{PREFIX}/statuses", status_code=201)
async def create_status(body: StatusCreate, request: Request) -> dict:
    name = _name(body.name, "Status name", ROLE_NAME_MAX)
    try:
        record = await db.create_lifecycle_status(
            name=name, color=body.color, description=body.description.strip(), is_default=body.is_default
        )
    except ValueError as exc:
        raise _conflict(exc) from exc
    await audit_device_write(request, "status_create", f"id={record['id']} name={name} default={body.is_default}")
    return record


@admin_router.put(f"{PREFIX}/statuses/{{status_id}}")
async def update_status(status_id: int, body: StatusUpdate, request: Request) -> dict:
    current = _found(await db.get_lifecycle_status(status_id), "Status")
    if body.is_default is False and current["is_default"]:
        raise HTTPException(status_code=409, detail=_DEFAULT_RULE)
    name = _name(body.name, "Status name", ROLE_NAME_MAX) if body.name is not None else current["name"]
    make_default = bool(body.is_default) and not current["is_default"]
    try:
        record = await db.update_lifecycle_status(
            status_id,
            name=name,
            color=body.color or current["color"],
            description=body.description.strip() if body.description is not None else current["description"],
            make_default=make_default,
        )
    except ValueError as exc:
        raise _conflict(exc) from exc
    record = _found(record, "Status")
    await audit_device_write(request, "status_update", f"id={status_id} name={name} made_default={make_default}")
    return record


@admin_router.delete(f"{PREFIX}/statuses/{{status_id}}")
async def delete_status(status_id: int, request: Request, confirm: bool = Query(default=False)) -> dict:
    record = _found(await db.get_lifecycle_status(status_id), "Status")
    if record["is_default"]:
        raise HTTPException(status_code=409, detail="The default status cannot be deleted. " + _DEFAULT_RULE)
    return await _delete("status", record, f"status {record['name']}", request, confirm)


# ── Bulk edit (inventory) ────────────────────────────────────────────────────


@inventory_router.post("/api/hosts/bulk-edit")
async def bulk_edit_hosts(body: BulkEdit, request: Request) -> dict:
    """Set the given device values on many hosts; unknown host ids are
    skipped. ``updated`` is the number of hosts written."""
    values = sent_device_values(body.values)
    if not values:
        raise _invalid("Choose at least one value to set.", {"set": "Choose at least one value to set."})
    await check_device_values(values)
    updated = await db.bulk_set_host_device_fields(body.host_ids, values, lock=True)
    await audit_device_write(request, "bulk_edit", f"hosts={updated} {describe_values(values)}")
    return {"ok": True, "updated": updated}
