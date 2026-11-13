"""Custom fields and tags: definitions, per-object data, and the helpers the
inventory and IPAM list endpoints use to carry that data inline.

Four routers, each registered in ``app.py`` with the access of what it sits
beside:

- ``router`` (any signed-in user): read the definitions and tags.
- ``admin_router`` (admin): manage field definitions; rename, recolor and
  delete tags.
- ``inventory_router`` (``inventory`` feature): create a tag, read and set a
  host's or group's tags and values, tag many hosts at once.
- ``ipam_router`` (``ipam`` feature, ``ipam.write`` to change): read and set a
  prefix's tags and values. Setting also needs admin, like every IPAM write.

Values are validated and canonicalised by ``netcontrol.custom_fields`` and
stored as text by ``routes.db.custom_fields``; this module converts them to
JSON types on the way out (``typed_value``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.custom_fields import (
    FIELD_KEY_RE,
    OBJECT_TYPES,
    TEXT_MAX,
    CustomFieldError,
    FieldType,
    ObjectType,
    TagColor,
    canonical_value,
    clean_tag_name,
    typed_value,
)
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()
admin_router = APIRouter()
inventory_router = APIRouter()
ipam_router = APIRouter()

_require_admin = None

BULK_TAGS_MAX_HOSTS = 5000
_MAX_CHOICES = 200
_LIST_MAX = 500

RawValue = bool | int | float | str | None


def init_custom_fields(require_admin) -> None:
    global _require_admin
    _require_admin = require_admin


async def _require_admin_dep(request: Request):
    if _require_admin is None:
        raise HTTPException(status_code=500, detail="Authorization subsystem not initialized")
    return await _require_admin(request)


# ── Request bodies ───────────────────────────────────────────────────────────


class FieldCreate(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    label: str = Field(min_length=1, max_length=100)
    field_type: FieldType
    choices: list[str] = Field(default_factory=list, max_length=_MAX_CHOICES)
    object_types: list[ObjectType] = Field(min_length=1, max_length=len(OBJECT_TYPES))
    required: bool = False
    default_value: RawValue = ""
    description: str = Field(default="", max_length=TEXT_MAX)
    sort_order: int = 0


class FieldUpdate(BaseModel):
    """Every property but ``key`` and ``field_type``, which are fixed; any
    sent are ignored. An absent property keeps its value."""

    label: str | None = Field(default=None, min_length=1, max_length=100)
    choices: list[str] | None = Field(default=None, max_length=_MAX_CHOICES)
    object_types: list[ObjectType] | None = Field(default=None, max_length=len(OBJECT_TYPES))
    required: bool | None = None
    default_value: RawValue = None
    description: str | None = Field(default=None, max_length=TEXT_MAX)
    sort_order: int | None = None


class TagCreate(BaseModel):
    name: str = Field(max_length=200)
    color: TagColor = "gray"
    description: str = Field(default="", max_length=TEXT_MAX)


class TagUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    color: TagColor | None = None
    description: str | None = Field(default=None, max_length=TEXT_MAX)


class ObjectDataPut(BaseModel):
    """A full replace: tags become exactly ``tag_ids``; a field absent,
    ``null`` or ``""`` is cleared."""

    tag_ids: list[int] = Field(default_factory=list, max_length=_LIST_MAX)
    fields: dict[str, RawValue] = Field(default_factory=dict)


class BulkTags(BaseModel):
    host_ids: list[int] = Field(min_length=1, max_length=BULK_TAGS_MAX_HOSTS)
    add_tag_ids: list[int] = Field(default_factory=list, max_length=_LIST_MAX)
    remove_tag_ids: list[int] = Field(default_factory=list, max_length=_LIST_MAX)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _unprocessable(message: str) -> HTTPException:
    return HTTPException(status_code=422, detail=message)


def _invalid(message: str, fields: dict[str, str] | None = None) -> HTTPException:
    """The Wire Contract's validation failure: 400 with a message and one
    message per field."""
    return HTTPException(status_code=400, detail={"message": message, "fields": fields or {}})


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("custom_fields", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


def _typed(fields: list[dict], stored: dict[str, str]) -> dict[str, Any]:
    types = {f["key"]: f["field_type"] for f in fields}
    return {key: typed_value(types.get(key, "text"), value) for key, value in stored.items()}


def _clean_definition(
    *, label: str, field_type: str, choices: list[str], object_types: list[str], default: RawValue
) -> dict:
    """Validated definition properties, or 422."""
    label = label.strip()
    if not label:
        raise _unprocessable("Enter a label for the field.")
    clean_choices = [c.strip() for c in choices]
    if field_type == "select":
        if not clean_choices or any(not c for c in clean_choices):
            raise _unprocessable("A select field needs at least one choice, and no empty choices.")
        if len(set(clean_choices)) != len(clean_choices):
            raise _unprocessable("Choices must be different from each other.")
        if any(len(c) > TEXT_MAX for c in clean_choices):
            raise _unprocessable(f"A choice must be at most {TEXT_MAX} characters.")
    else:
        clean_choices = []
    types = list(dict.fromkeys(object_types))
    if not types:
        raise _unprocessable("Choose at least one object type the field applies to.")
    try:
        default_value = canonical_value(
            {"label": "Default value", "field_type": field_type, "choices": clean_choices}, default
        )
    except CustomFieldError as exc:
        raise _unprocessable(str(exc)) from exc
    return {"label": label, "choices": clean_choices, "object_types": types, "default_value": default_value}


async def _field_or_404(field_id: int) -> dict:
    field = await db.get_custom_field(field_id)
    if not field:
        raise HTTPException(status_code=404, detail="Custom field not found")
    return field


async def _tag_or_404(tag_id: int) -> dict:
    tag = await db.get_tag(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    return tag


# ── Inline data for list endpoints ───────────────────────────────────────────


async def attach_custom_data(object_type: str, rows: list[dict], key_of: Callable[[dict], str]) -> None:
    """Set ``tags`` and ``custom_fields`` on every row, from one bulk read."""
    if not rows:
        return
    keys = [key_of(r) for r in rows]
    data = await db.get_object_data_bulk(object_type, keys)
    fields = await db.list_custom_fields(object_type) if data else []
    for row, key in zip(rows, keys, strict=True):
        entry = data.get(key)
        row["tags"] = list(entry["tags"]) if entry else []
        row["custom_fields"] = _typed(fields, entry["fields"]) if entry else {}


async def matching_keys(object_type: str, query_params) -> set[str] | None:
    """The object keys matching the request's ``tag=`` (repeatable, all must
    match) and ``cf.<key>=<value>`` filters; ``None`` when there are none.
    Raises 400 on an unknown ``cf.`` key or a value the field rejects."""
    tags = [t for t in query_params.getlist("tag") if t.strip()]
    wanted = [(k[3:], v) for k, v in query_params.multi_items() if k.startswith("cf.")]
    if not tags and not wanted:
        return None
    by_key = {f["key"]: f for f in await db.list_custom_fields(object_type)}
    filters: dict[int, str] = {}
    errors: dict[str, str] = {}
    for key, raw in wanted:
        field = by_key.get(key)
        if field is None:
            errors[key] = f"No custom field '{key}' applies to {object_type}s."
            continue
        try:
            value = canonical_value(field, raw)
        except CustomFieldError as exc:
            errors[key] = str(exc)
            continue
        if not value:
            errors[key] = f"{field['label']} filter needs a value."
            continue
        filters[int(field["id"])] = value
    if errors:
        raise _invalid("Filter not valid: " + ", ".join(sorted(errors)), errors)
    return await db.find_object_keys(object_type, tags, filters)


# ── Definitions (read) ───────────────────────────────────────────────────────


@router.get("/api/custom-fields")
async def list_fields(object_type: str | None = Query(default=None)) -> list[dict]:
    if object_type is not None and object_type not in OBJECT_TYPES:
        raise HTTPException(status_code=400, detail=f"object_type must be one of: {', '.join(OBJECT_TYPES)}")
    return await db.list_custom_fields(object_type, with_counts=True)


@router.get("/api/tags")
async def list_tags() -> list[dict]:
    return await db.list_tags(with_usage=True)


# ── Definitions (admin) ──────────────────────────────────────────────────────


@admin_router.post("/api/custom-fields", status_code=201)
async def create_field(body: FieldCreate, request: Request) -> dict:
    key = body.key.strip()
    if not FIELD_KEY_RE.fullmatch(key):
        raise _unprocessable("Key must start with a lowercase letter and use only a-z, 0-9 and _ (at most 50).")
    clean = _clean_definition(
        label=body.label,
        field_type=body.field_type,
        choices=body.choices,
        object_types=list(body.object_types),
        default=body.default_value,
    )
    try:
        field = await db.create_custom_field(
            key=key,
            field_type=body.field_type,
            required=body.required,
            description=body.description.strip(),
            sort_order=body.sort_order,
            created_by=_session_user(request),
            **clean,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(request, "field_create", f"key={key} type={body.field_type}")
    return field


@admin_router.put("/api/custom-fields/{field_id}")
async def update_field(field_id: int, body: FieldUpdate, request: Request, confirm: bool = Query(default=False)):
    current = await _field_or_404(field_id)
    sent = body.model_fields_set
    clean = _clean_definition(
        label=body.label if body.label is not None else current["label"],
        field_type=current["field_type"],
        choices=body.choices if body.choices is not None else current["choices"],
        object_types=list(body.object_types) if body.object_types is not None else current["object_types"],
        default=body.default_value if "default_value" in sent else current["default_value"],
    )
    removed = sorted(set(current["object_types"]) - set(clean["object_types"]))
    affected = await db.count_custom_field_values(field_id, removed) if removed else 0
    if affected and not confirm:
        raise HTTPException(
            status_code=409,
            detail={
                "message": f"{affected} objects ({', '.join(removed)}) lose their {current['label']} value. "
                "Send confirm=true to go ahead.",
                "affected": affected,
            },
        )
    updated = await db.update_custom_field(
        field_id,
        required=body.required if body.required is not None else current["required"],
        description=body.description.strip() if body.description is not None else current["description"],
        sort_order=body.sort_order if body.sort_order is not None else current["sort_order"],
        **clean,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Custom field not found")
    detail = f"key={current['key']}"
    if removed:
        detail += f" removed_types={','.join(removed)} values_removed={affected}"
    await _audit_write(request, "field_update", detail)
    return updated


@admin_router.delete("/api/custom-fields/{field_id}")
async def delete_field(field_id: int, request: Request) -> dict:
    field = await _field_or_404(field_id)
    removed = await db.delete_custom_field(field_id)
    await _audit_write(request, "field_delete", f"key={field['key']} values_removed={removed}")
    return {"ok": True, "removed": removed}


# ── Tags ─────────────────────────────────────────────────────────────────────


def _tag_name(raw: str) -> str:
    try:
        return clean_tag_name(raw)
    except CustomFieldError as exc:
        raise _unprocessable(str(exc)) from exc


@inventory_router.post("/api/tags", status_code=201)
async def create_tag(body: TagCreate, request: Request) -> dict:
    name = _tag_name(body.name)
    try:
        tag = await db.create_tag(
            name=name, color=body.color, description=body.description.strip(), created_by=_session_user(request)
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(request, "tag_create", f"name={name}")
    return tag


@admin_router.put("/api/tags/{tag_id}")
async def update_tag(tag_id: int, body: TagUpdate, request: Request) -> dict:
    current = await _tag_or_404(tag_id)
    name = _tag_name(body.name) if body.name is not None else current["name"]
    try:
        tag = await db.update_tag(
            tag_id,
            name=name,
            color=body.color or current["color"],
            description=body.description.strip() if body.description is not None else current["description"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if tag is None:
        raise HTTPException(status_code=404, detail="Tag not found")
    await _audit_write(request, "tag_update", f"id={tag_id} name={name}")
    return tag


@admin_router.delete("/api/tags/{tag_id}")
async def delete_tag(tag_id: int, request: Request) -> dict:
    tag = await _tag_or_404(tag_id)
    removed = await db.delete_tag(tag_id)
    await _audit_write(request, "tag_delete", f"name={tag['name']} assignments_removed={removed}")
    return {"ok": True, "removed": removed}


# ── Object data ──────────────────────────────────────────────────────────────


async def _read_object(object_type: str, key: str) -> dict:
    data = await db.get_object_data(object_type, key)
    fields = await db.list_custom_fields(object_type) if data["fields"] else []
    return {"tags": data["tags"], "fields": _typed(fields, data["fields"])}


async def _save_object(object_type: str, key: str, body: ObjectDataPut, request: Request) -> dict:
    """Validate the whole body, then replace the object's tags and values.
    Every problem is reported in one 400 and nothing is written."""
    all_fields = await db.list_custom_fields()
    applicable = {f["key"]: f for f in all_fields if object_type in f["object_types"]}
    known = {f["key"] for f in all_fields}
    errors: dict[str, str] = {}
    values: dict[int, str] = {}
    for field_key, raw in body.fields.items():
        field = applicable.get(field_key)
        if field is None:
            errors[field_key] = (
                f"{field_key} does not apply to {object_type}s."
                if field_key in known
                else f"{field_key} is not a custom field (it may have been deleted)."
            )
            continue
        try:
            values[int(field["id"])] = canonical_value(field, raw)
        except CustomFieldError as exc:
            errors[field_key] = str(exc)
    for field in applicable.values():
        if field["required"] and not field["default_value"] and field["key"] not in errors:
            if not values.get(int(field["id"])):
                errors[field["key"]] = f"{field['label']} is required."

    problems: list[str] = []
    tag_ids = list(dict.fromkeys(body.tag_ids))
    existing_tags = {t["id"] for t in await db.list_tags()}
    missing = [t for t in tag_ids if t not in existing_tags]
    if missing:
        problems.append("Unknown tag id: " + ", ".join(str(t) for t in missing) + ".")
    if errors:
        problems.append("Check these fields: " + ", ".join(sorted(errors)) + ".")
    if problems:
        raise _invalid(" ".join(problems), errors)

    try:
        await db.set_object_data(object_type, key, tag_ids, values)
    except ValueError as exc:  # a tag or field deleted since the checks above
        raise _invalid(str(exc)) from exc
    stored = sorted(f["key"] for f in applicable.values() if values.get(int(f["id"])))
    await _audit_write(
        request, "object_update", f"{object_type}={key} tags={len(tag_ids)} fields={','.join(stored) or '-'}"
    )
    return await _read_object(object_type, key)


async def _host_key(host_id: int) -> str:
    if not await db.get_host(host_id):
        raise HTTPException(status_code=404, detail="Host not found")
    return str(host_id)


async def _group_key(group_id: int) -> str:
    if not await db.get_group(group_id):
        raise HTTPException(status_code=404, detail="Group not found")
    return str(group_id)


def _prefix_key(subnet: str, vrf: str) -> str:
    try:
        return db.prefix_key(subnet, vrf)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet") from None


@inventory_router.get("/api/hosts/{host_id}/custom-data")
async def get_host_data(host_id: int) -> dict:
    return await _read_object("host", await _host_key(host_id))


@inventory_router.put("/api/hosts/{host_id}/custom-data")
async def put_host_data(host_id: int, body: ObjectDataPut, request: Request) -> dict:
    return await _save_object("host", await _host_key(host_id), body, request)


@inventory_router.get("/api/inventory/{group_id}/custom-data")
async def get_group_data(group_id: int) -> dict:
    return await _read_object("group", await _group_key(group_id))


@inventory_router.put("/api/inventory/{group_id}/custom-data")
async def put_group_data(group_id: int, body: ObjectDataPut, request: Request) -> dict:
    return await _save_object("group", await _group_key(group_id), body, request)


@inventory_router.post("/api/hosts/bulk-tags")
async def bulk_tag_hosts(body: BulkTags, request: Request) -> dict:
    hosts = await db.get_hosts_by_ids(list(dict.fromkeys(body.host_ids)))
    keys = [str(h["id"]) for h in hosts]
    try:
        updated = await db.bulk_update_tags("host", keys, body.add_tag_ids, body.remove_tag_ids)
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    await _audit_write(
        request,
        "bulk_tags",
        f"hosts={updated} add={','.join(map(str, body.add_tag_ids)) or '-'} "
        f"remove={','.join(map(str, body.remove_tag_ids)) or '-'}",
    )
    return {"ok": True, "updated": updated}


@ipam_router.get("/api/ipam/prefix-custom-data")
async def get_prefix_data(subnet: str = Query(max_length=64), vrf: str = Query(default="", max_length=200)) -> dict:
    return await _read_object("prefix", _prefix_key(subnet, vrf))


@ipam_router.put("/api/ipam/prefix-custom-data", dependencies=[Depends(_require_admin_dep)])
async def put_prefix_data(
    body: ObjectDataPut,
    request: Request,
    subnet: str = Query(max_length=64),
    vrf: str = Query(default="", max_length=200),
) -> dict:
    return await _save_object("prefix", _prefix_key(subnet, vrf), body, request)
