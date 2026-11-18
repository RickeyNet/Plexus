"""Custom fields, tags, computed fields and relationships: definitions,
per-object data, and the helpers the list and detail endpoints of every
object type use to carry that data inline.

Four routers, each registered in ``app.py`` with the access of what it sits
beside:

- ``router`` (any signed-in user): read the definitions and tags, and the
  generic object API ``/api/objects/{type}/{id}/...`` for every type of the
  registry (``netcontrol.custom_fields.OBJECT_TYPE_SPECS``), which checks
  the feature of each type itself (read: ``read_feature``; write:
  ``write_feature``, or admin when it is ``None``) and object scope for
  hosts and groups.
- ``admin_router`` (admin): manage field, computed field and relationship
  definitions; rename, recolor and delete tags.
- ``inventory_router`` (``inventory`` feature): create a tag, read and set a
  host's or group's tags and values, tag many hosts at once.
- ``ipam_router`` (``ipam`` feature, ``ipam.write`` to change): read and set a
  prefix's tags and values. Setting also needs admin, like every IPAM write.

Values are validated and canonicalised by ``netcontrol.custom_fields`` and
stored as text by ``routes.db.custom_fields``; this module converts them to
JSON types on the way out (``typed_value``).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Literal

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from routes.db.change_events import (
    CHANGE_OBJECT_TYPES,
    emit_object_change,
    fetch_object_snapshot,
    wants_object_type,
)

from netcontrol.custom_fields import (
    COMPUTED_OUTPUT_MAX,
    COMPUTED_TEMPLATE_MAX,
    FIELD_KEY_RE,
    GENERIC_TYPES,
    OBJECT_TYPE_SPECS,
    OBJECT_TYPES,
    TEXT_MAX,
    Cardinality,
    CustomFieldError,
    FieldType,
    ObjectTypeSpec,
    TagColor,
    canonical_value,
    check_object_values,
    clean_tag_name,
    typed_value,
    unknown_object_types,
)
from netcontrol.data_validation import (
    CUSTOM_FIELD_PREFIX,
    OBJECT_TYPES as VALIDATION_OBJECT_TYPES,
    enforce as enforce_validation_rules,
)
from netcontrol.intended_config import Renderer, check_syntax
from netcontrol.object_scope import (
    ObjectScope,
    filter_rows,
    get_model,
    request_scope,
    require_group,
    require_host,
    require_hosts,
    require_model_write,
    require_row,
    scope_exempt,
    scoped,
)
from netcontrol.routes.shared import _audit, _corr_id, _session_user, caller_features

LOGGER = logging.getLogger("plexus.custom_fields")

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
    object_types: list[str] = Field(min_length=1, max_length=len(OBJECT_TYPES))
    required: bool = False
    default_value: RawValue = ""
    description: str = Field(default="", max_length=TEXT_MAX)
    sort_order: int = 0


class FieldUpdate(BaseModel):
    """Every property but ``key`` and ``field_type``, which are fixed; any
    sent are ignored. An absent property keeps its value."""

    label: str | None = Field(default=None, min_length=1, max_length=100)
    choices: list[str] | None = Field(default=None, max_length=_MAX_CHOICES)
    object_types: list[str] | None = Field(default=None, max_length=len(OBJECT_TYPES))
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


class ComputedFieldCreate(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    label: str = Field(min_length=1, max_length=100)
    object_type: str = Field(max_length=50)
    template: str = Field(min_length=1, max_length=COMPUTED_TEMPLATE_MAX)
    description: str = Field(default="", max_length=TEXT_MAX)
    sort_order: int = 0


class ComputedFieldUpdate(BaseModel):
    """Every property but ``key`` and ``object_type``; absent keeps its value."""

    label: str | None = Field(default=None, min_length=1, max_length=100)
    template: str | None = Field(default=None, min_length=1, max_length=COMPUTED_TEMPLATE_MAX)
    description: str | None = Field(default=None, max_length=TEXT_MAX)
    sort_order: int | None = None


class ComputedPreview(BaseModel):
    object_type: str = Field(max_length=50)
    object_id: int
    template: str = Field(min_length=1, max_length=COMPUTED_TEMPLATE_MAX)


class RelationshipCreate(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    label: str = Field(min_length=1, max_length=100)
    source_type: str = Field(max_length=50)
    destination_type: str = Field(max_length=50)
    cardinality: Cardinality = "many-to-many"
    description: str = Field(default="", max_length=TEXT_MAX)


class RelationshipUpdate(BaseModel):
    """The label and description; the types and cardinality are fixed."""

    label: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=TEXT_MAX)


class LinkCreate(BaseModel):
    """Link the object of the URL to ``peer_id``. ``side``: which end of the
    relationship the URL's object is; only needed when both ends have the
    same type (the default is the source)."""

    relationship_id: int
    peer_id: int
    side: Literal["source", "destination"] | None = None


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
    unknown = unknown_object_types(types)
    if unknown:
        raise _unprocessable(f"Unknown object type: {', '.join(unknown)}. Use one of: {', '.join(OBJECT_TYPES)}.")
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
    canonical, errors = await canonical_filter_values(object_type, wanted)
    if errors:
        raise _invalid("Filter not valid: " + ", ".join(sorted(errors)), errors)
    filters = {int(field["id"]): value for field, value in canonical}
    return await db.find_object_keys(object_type, tags, filters)


async def canonical_filter_values(
    object_type: str, wanted: list[tuple[str, object]]
) -> tuple[list[tuple[dict, str]], dict[str, str]]:
    """Custom field filter values (``(field key, raw value)`` pairs) as
    ``(field, canonical text)`` pairs, plus a message per key that names no
    field of ``object_type`` or whose value the field rejects (an empty value
    is rejected too). Shared by the list filters and dynamic groups."""
    by_key = {f["key"]: f for f in await db.list_custom_fields(object_type)}
    canonical: list[tuple[dict, str]] = []
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
        canonical.append((field, value))
    return canonical, errors


# ── Definitions (read) ───────────────────────────────────────────────────────


@router.get("/api/custom-fields")
@scope_exempt("field definitions: no host or inventory group data")
async def list_fields(object_type: str | None = Query(default=None)) -> list[dict]:
    if object_type is not None and object_type not in OBJECT_TYPES:
        raise HTTPException(status_code=400, detail=f"object_type must be one of: {', '.join(OBJECT_TYPES)}")
    return await db.list_custom_fields(object_type, with_counts=True)


@router.get("/api/tags")
@scope_exempt("tag definitions and usage counts: no host or inventory group data")
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
@scope_exempt("creates a global tag definition: no host or inventory group data")
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
    values, errors = check_object_values(all_fields, object_type, body.fields)

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
    # Data validation rules on custom fields: every field of the type (a
    # cleared one as ""), and a 422 naming the field key. Only the types
    # rules can name (``data_validation.OBJECT_TYPES``).
    applicable = [f for f in all_fields if object_type in f["object_types"]]
    if object_type in VALIDATION_OBJECT_TYPES:
        await enforce_validation_rules(
            object_type,
            {CUSTOM_FIELD_PREFIX + f["key"]: values.get(int(f["id"]), "") for f in applicable},
            field_names={CUSTOM_FIELD_PREFIX + f["key"]: f["key"] for f in applicable},
        )

    before = await db.get_object_data(object_type, key)
    try:
        await db.set_object_data(object_type, key, tag_ids, values)
    except ValueError as exc:  # a tag or field deleted since the checks above
        raise _invalid(str(exc)) from exc
    stored = sorted(f["key"] for f in all_fields if values.get(int(f["id"])))
    await _audit_write(
        request, "object_update", f"{object_type}={key} tags={len(tag_ids)} fields={','.join(stored) or '-'}"
    )
    await _record_change(object_type, key, before, await db.get_object_data(object_type, key))
    return await _read_object(object_type, key)


async def _record_change(object_type: str, key: str, before: dict, after: dict) -> None:
    """Hand a custom data save to the object-change hooks (the per-object
    change log, webhooks) as an update of the object, for the tracked types:
    the row's snapshot plus ``custom_fields`` and ``tags``, so the diff names
    exactly what changed. Never fails the save."""
    if object_type not in CHANGE_OBJECT_TYPES or not wants_object_type(object_type):
        return
    try:
        snapshot = await fetch_object_snapshot(object_type, key)
        if snapshot is None:
            return

        def view(data: dict) -> dict:
            return {**snapshot, "custom_fields": data["fields"], "tags": sorted(t["name"] for t in data["tags"])}

        old, new = view(before), view(after)
        if old != new:
            await emit_object_change(object_type, "update", key, before=old, after=new)
    except Exception as exc:  # the save is committed; the log is best effort
        LOGGER.warning("custom data change not recorded for %s %s: %s", object_type, key, type(exc).__name__)


async def _host_key(request: Request, host_id: int, *, write: bool = False) -> str:
    await require_host(request, host_id, write=write)
    return str(host_id)


async def _group_key(request: Request, group_id: int, *, write: bool = False) -> str:
    await require_group(request, group_id, write=write)
    return str(group_id)


def _prefix_key(subnet: str, vrf: str) -> str:
    try:
        return db.prefix_key(subnet, vrf)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet") from None


@inventory_router.get("/api/hosts/{host_id}/custom-data")
@scoped("host")
async def get_host_data(host_id: int, request: Request) -> dict:
    return await _read_object("host", await _host_key(request, host_id))


@inventory_router.put("/api/hosts/{host_id}/custom-data")
@scoped("host")
async def put_host_data(host_id: int, body: ObjectDataPut, request: Request) -> dict:
    return await _save_object("host", await _host_key(request, host_id, write=True), body, request)


@inventory_router.get("/api/inventory/{group_id}/custom-data")
@scoped("group")
async def get_group_data(group_id: int, request: Request) -> dict:
    return await _read_object("group", await _group_key(request, group_id))


@inventory_router.put("/api/inventory/{group_id}/custom-data")
@scoped("group")
async def put_group_data(group_id: int, body: ObjectDataPut, request: Request) -> dict:
    return await _save_object("group", await _group_key(request, group_id, write=True), body, request)


@inventory_router.post("/api/hosts/bulk-tags")
@scoped("hosts")
async def bulk_tag_hosts(body: BulkTags, request: Request) -> dict:
    # Unknown ids are skipped; a scoped caller must be able to write every one.
    hosts = await require_hosts(request, body.host_ids, write=True)
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
@scoped("subnet")
async def get_prefix_data(
    request: Request, subnet: str = Query(max_length=64), vrf: str = Query(default="", max_length=200)
) -> dict:
    """A scoped caller reads the data of the subnets of their IPAM overview
    (``netcontrol.routes.ipam.subnet_scope``); any other answers like a
    subnet with no data."""
    from netcontrol.routes.ipam import subnet_scope  # imports this module at load time

    view = await subnet_scope(request)
    if view is not None and not view.has_subnet(subnet, vrf):
        return {"tags": [], "fields": {}}
    return await _read_object("prefix", _prefix_key(subnet, vrf))


@ipam_router.put("/api/ipam/prefix-custom-data", dependencies=[Depends(_require_admin_dep)])
@scoped("admin")
async def put_prefix_data(
    body: ObjectDataPut,
    request: Request,
    subnet: str = Query(max_length=64),
    vrf: str = Query(default="", max_length=200),
) -> dict:
    return await _save_object("prefix", _prefix_key(subnet, vrf), body, request)


# ── Every object type: access ────────────────────────────────────────────────

_LOOKUP_SCAN = 5000
_LOOKUP_MAX = 50


def _spec_or_404(object_type: str, *, generic: bool = True) -> ObjectTypeSpec:
    spec = OBJECT_TYPE_SPECS.get(object_type)
    if spec is None or (generic and not spec.generic):
        raise HTTPException(status_code=404, detail=f"Unknown object type '{object_type}'")
    return spec


def can_read_type(features: frozenset[str] | None, spec: ObjectTypeSpec) -> bool:
    """Whether a caller with ``features`` (``None``: every feature, an admin
    or the API token) reads ``spec``'s objects."""
    return features is None or spec.read_feature is None or spec.read_feature in features


def _can_write_type(features: frozenset[str] | None, spec: ObjectTypeSpec) -> bool:
    if features is None:
        return True
    if spec.write_feature is None:
        return False
    return can_read_type(features, spec) and spec.write_feature in features


async def _require_type(request: Request, spec: ObjectTypeSpec, *, write: bool) -> None:
    """403 unless the caller holds the type's read (and on ``write`` its
    write) feature. Which objects of the type a scoped caller reaches is
    checked per object (``require_object``)."""
    features = await caller_features(request)
    if not can_read_type(features, spec):
        raise HTTPException(status_code=403, detail=f"Access denied for feature '{spec.read_feature}'")
    if write and not _can_write_type(features, spec):
        need = f"feature '{spec.write_feature}'" if spec.write_feature else "admin"
        raise HTTPException(status_code=403, detail=f"Changing {spec.label.lower()} data needs {need}")


async def _scope_rows(access: Any, spec: ObjectTypeSpec, keys: list[str] | None) -> list[dict]:
    """Rows of ``spec`` (the given ids; ``None``: up to ``_LOOKUP_SCAN``)
    carrying the fields its object scope model reads: the derived
    ``scope_host_ids`` / ``scope_site_ids`` / ``cluster_site_id`` come from
    the helpers the circuits, virtualization and DCIM routes key their own
    rows with, and a peering's ``host_id`` from its routing instance.
    ``access``: the request (or ``ObjectScope``) of the caller."""
    ids = None if keys is None else [int(k) for k in keys]

    async def each(get: Callable[[int], Any]) -> list[dict]:
        return [r for r in [await get(i) for i in ids or []] if r]

    kind = spec.key
    if kind == "circuit":
        from netcontrol.routes.circuits import _keyed  # deferred: that module imports this one

        circuits = await db.list_circuits() if ids is None else await each(db.get_circuit)
        return [_keyed(c) for c in circuits]
    if kind in ("cluster", "virtual_machine"):
        from netcontrol.routes.virtualization import _keyed_cluster, _keyed_vm, _member_hosts

        members = await _member_hosts()
        if kind == "cluster":
            clusters = await db.list_clusters() if ids is None else await each(db.get_cluster)
            return [_keyed_cluster(c, members) for c in clusters]
        vms = await db.list_virtual_machines() if ids is None else await each(db.get_virtual_machine)
        return [_keyed_vm(v, members) for v in vms]
    if kind == "cable":
        from netcontrol.routes.dcim import _EndpointScope

        ends = _EndpointScope(access, None)
        cables = await db.list_cables() if ids is None else await each(db.get_cable)
        return [await ends.cable_keys(c) for c in cables]
    if kind == "bgp_peering":
        return await db.list_bgp_peerings() if ids is None else await each(db.get_bgp_peering)
    if ids is None:
        return await db.list_object_rows(spec.table, spec.id_column, _LOOKUP_SCAN)
    return list((await db.get_object_rows(spec.table, spec.id_column, [str(i) for i in ids])).values())


async def _readable_keys(access: Any, spec: ObjectTypeSpec, keys: list[str]) -> set[str]:
    """The ``keys`` of objects of ``spec`` that exist and the caller reads."""
    rows = await filter_rows(spec.scope_model, await _scope_rows(access, spec, keys), access)
    return {str(r["id"]) for r in rows}


async def require_object(request: Request, object_type: str, object_id: int, *, write: bool = False) -> dict:
    """The table row of an object of a generic type the caller may read (on
    ``write``: change): 404 for an unknown type, an unknown object or one
    outside the caller's object scope (``object_scope`` model
    ``spec.scope_model``), 403 without the type's feature, for a readable
    object that is not writable, and for a scoped caller's write to shared
    reference data (catalogues, regions, providers)."""
    spec = _spec_or_404(object_type)
    await _require_type(request, spec, write=write)
    if spec.key == "host":
        return await require_host(request, object_id, write=write)
    if spec.key == "group":
        return await require_group(request, object_id, write=write)
    not_found = f"{spec.label} not found"
    if (await request_scope(request)).restricted:
        keyed = await _scope_rows(request, spec, [str(object_id)])
        if write and not get_model(spec.scope_model).keys:
            await require_row(request, spec.scope_model, keyed[0] if keyed else None, not_found=not_found)
            await require_model_write(request)
        else:
            await require_row(request, spec.scope_model, keyed[0] if keyed else None, write=write, not_found=not_found)
    row = (await db.get_object_rows(spec.table, spec.id_column, [str(object_id)])).get(str(object_id))
    if row is None:
        raise HTTPException(status_code=404, detail=not_found)
    return row


def object_title(object_type: str, row: dict) -> str:
    """The display name of an object (the change log's naming), or ``#id``."""
    from netcontrol.routes.object_changes import object_label  # deferred: avoids an import cycle

    return object_label(object_type, row) or f"#{row.get('id')}"


# ── Every object type: computed fields ───────────────────────────────────────


def render_computed(fields: list[dict], context: dict, *, where: str = "") -> dict[str, str]:
    """``{key: text}`` of each computed field rendered with ``context`` in
    the intended configuration sandbox. A template that fails renders as
    ``""`` with a logged warning; a value is trimmed and cut at
    ``COMPUTED_OUTPUT_MAX`` characters."""
    if not fields:
        return {}

    renderer = Renderer({f["key"]: f["template"] for f in fields})
    out: dict[str, str] = {}
    for field in fields:
        result = renderer.render(field["key"], context)
        if result.error is not None:
            LOGGER.warning("computed field %s on %s failed: %s", field["key"], where or "?", result.error.message)
            out[field["key"]] = ""
            continue
        out[field["key"]] = result.config_text.strip()[:COMPUTED_OUTPUT_MAX]
    return out


def _computed_context(row: dict, data: dict | None, fields: list[dict]) -> dict:
    entry = data or {"tags": [], "fields": {}}
    return {
        "obj": row,
        "custom_fields": _typed(fields, entry["fields"]),
        "tags": [t["name"] for t in entry["tags"]],
    }


# ── Every object type: inline data ───────────────────────────────────────────


async def object_custom_data_bulk(
    object_type: str,
    rows: list[dict],
    *,
    relationships: bool = False,
    features: frozenset[str] | None = None,
    access: Any = None,
) -> dict[str, dict]:
    """``{id: {"tags", "custom_fields", "computed_fields"[, "relationships"]}}``
    for the given rows of ``object_type`` (each needs ``id``), in a fixed
    number of queries whatever the number of rows. ``relationships`` adds
    each object's links, keeping only peers the caller reads: ``features``
    (``None``: every feature) and ``access`` (the request or
    ``ObjectScope``; ``None``: unrestricted). Checks no access to the rows
    themselves: the caller has already. Shared by the REST list and detail
    helpers and GraphQL."""
    if not rows:
        return {}
    keys = [str(r["id"]) for r in rows]
    data = await db.get_object_data_bulk(object_type, keys)
    fields = await db.list_custom_fields(object_type) if data else []
    computed = await db.list_computed_fields(object_type)
    out: dict[str, dict] = {}
    for row, key in zip(rows, keys, strict=True):
        entry = data.get(key)
        out[key] = {
            "tags": list(entry["tags"]) if entry else [],
            "custom_fields": _typed(fields, entry["fields"]) if entry else {},
            "computed_fields": render_computed(
                computed, _computed_context(row, entry, fields), where=f"{object_type} {key}"
            ),
        }
    if relationships:
        links = await relationship_view(object_type, keys, features, access)
        for key in keys:
            out[key]["relationships"] = links.get(key, [])
    return out


async def with_custom_data(object_type: str, record: dict) -> dict:
    """A detail response with ``tags``, ``custom_fields`` and
    ``computed_fields`` added (the record itself, returned)."""
    record.update((await object_custom_data_bulk(object_type, [record]))[str(record["id"])])
    return record


async def custom_list(object_type: str, rows: list[dict], request: Request) -> list[dict]:
    """A list response's rows filtered by the request's ``tag=`` and
    ``cf.<key>=`` parameters (``matching_keys``; 400 on a bad filter), each
    carrying ``tags`` and ``custom_fields``."""
    keys = await matching_keys(object_type, request.query_params)
    if keys is not None:
        rows = [r for r in rows if str(r["id"]) in keys]
    await attach_custom_data(object_type, rows, lambda r: str(r["id"]))
    return rows


# ── Every object type: relationships ─────────────────────────────────────────


async def relationship_view(
    object_type: str, keys: list[str], features: frozenset[str] | None = None, access: Any = None
) -> dict[str, list[dict]]:
    """``{key: [{"relationship", "side", "peer_type", "links": [{"id",
    "peer_id", "peer_label"}]}]}``: for each object, every relationship its
    type takes part in (twice, one per side, when both ends have its type)
    and its links on that side. A link is left out when the caller cannot
    read its peer: the peer's type is not in ``features`` (``None``: every
    feature) or the peer is outside the object scope of ``access`` (the
    request or ``ObjectScope``; ``None``: unrestricted)."""
    rels = await db.list_relationships(object_type)
    if not rels or not keys:
        return {k: [] for k in keys}
    links = await db.list_relationship_links(object_type, keys)
    peers: dict[str, set[str]] = {}
    for link in links:
        peers.setdefault(link["source_type"], set()).add(link["source_key"])
        peers.setdefault(link["destination_type"], set()).add(link["destination_key"])
    restricted = access is not None and (
        access.restricted if isinstance(access, ObjectScope) else (await request_scope(access)).restricted
    )
    labels: dict[tuple[str, str], str] = {}
    for peer_type, peer_keys in peers.items():
        spec = OBJECT_TYPE_SPECS.get(peer_type)
        if spec is None or not can_read_type(features, spec):
            continue
        readable = await _readable_keys(access, spec, sorted(peer_keys)) if restricted else None
        for peer_key, row in (await db.get_object_rows(spec.table, spec.id_column, sorted(peer_keys))).items():
            if readable is None or peer_key in readable:
                labels[(peer_type, peer_key)] = object_title(peer_type, row)
    out: dict[str, list[dict]] = {}
    for key in keys:
        groups: list[dict] = []
        for rel in rels:
            for side in ("source", "destination"):
                if rel[f"{side}_type"] != object_type:
                    continue
                other = "destination" if side == "source" else "source"
                mine = [
                    {
                        "id": link["id"],
                        "peer_id": int(link[f"{other}_key"]),
                        "peer_label": labels.get((link[f"{other}_type"], link[f"{other}_key"]), ""),
                    }
                    for link in links
                    if link["relationship_id"] == rel["id"]
                    and link[f"{side}_type"] == object_type
                    and link[f"{side}_key"] == key
                    and (link[f"{other}_type"], link[f"{other}_key"]) in labels
                ]
                groups.append({"relationship": rel, "side": side, "peer_type": rel[f"{other}_type"], "links": mine})
        out[key] = groups
    return out


# ── Every object type: API ───────────────────────────────────────────────────


@router.get("/api/custom-object-types")
@scope_exempt("the object type catalogue: no host or inventory group data")
async def list_object_types(request: Request) -> list[dict]:
    """Every object type that carries custom data, with whether the caller
    reads and changes it."""
    features = await caller_features(request)
    return [
        {
            "key": spec.key,
            "label": spec.label,
            "generic": spec.generic,
            "readable": can_read_type(features, spec),
            "writable": _can_write_type(features, spec),
        }
        for spec in OBJECT_TYPE_SPECS.values()
    ]


async def _object_payload(request: Request, object_type: str, row: dict) -> dict:
    key = str(row["id"])
    bulk = await object_custom_data_bulk(
        object_type, [row], relationships=True, features=await caller_features(request), access=request
    )
    entry = bulk[key]
    return {
        "tags": entry["tags"],
        "fields": entry["custom_fields"],
        "computed_fields": entry["computed_fields"],
        "relationships": entry["relationships"],
    }


@router.get("/api/objects/{object_type}/{object_id}/custom-data")
@scoped("object")
async def get_object_custom_data(object_type: str, object_id: int, request: Request) -> dict:
    """``{"tags", "fields", "computed_fields", "relationships"}`` of one object."""
    row = await require_object(request, object_type, object_id)
    return await _object_payload(request, object_type, row)


@router.put("/api/objects/{object_type}/{object_id}/custom-data")
@scoped("object")
async def put_object_custom_data(object_type: str, object_id: int, body: ObjectDataPut, request: Request) -> dict:
    """Replace one object's tags and custom field values (as the host and
    group endpoints do); answers like the GET."""
    row = await require_object(request, object_type, object_id, write=True)
    await _save_object(object_type, str(row["id"]), body, request)
    return await _object_payload(request, object_type, row)


@router.get("/api/objects/{object_type}/lookup")
@scoped("list")
async def lookup_objects(object_type: str, request: Request, q: str = Query(default="", max_length=200)) -> list[dict]:
    """Up to 50 objects of a type whose name contains ``q`` (ignoring case),
    as ``{"id", "label"}``: the picker of the relationship editor. A scoped
    caller gets only the objects of their object scope."""
    spec = _spec_or_404(object_type)
    await _require_type(request, spec, write=False)
    if (await request_scope(request)).unrestricted:
        rows = await db.list_object_rows(spec.table, spec.id_column, _LOOKUP_SCAN)
    else:
        rows = await filter_rows(spec.scope_model, await _scope_rows(request, spec, None), request)
    needle = q.strip().lower()
    out: list[dict] = []
    for row in rows:
        label = object_title(object_type, row)
        if needle in label.lower():
            out.append({"id": int(row["id"]), "label": label})
            if len(out) >= _LOOKUP_MAX:
                break
    return out


@router.post("/api/objects/{object_type}/{object_id}/relationships", status_code=201)
@scoped("object")
async def add_object_link(object_type: str, object_id: int, body: LinkCreate, request: Request) -> dict:
    """Link the object to ``peer_id`` with a relationship: needs write on
    the object and read on the peer. 409 when the cardinality forbids it."""
    rel = await db.get_relationship(body.relationship_id)
    if rel is None:
        raise HTTPException(status_code=404, detail="Relationship not found")
    sides = [s for s in ("source", "destination") if rel[f"{s}_type"] == object_type]
    if not sides:
        raise _invalid(f"The relationship {rel['label']} does not link {object_type} objects.")
    side = body.side if body.side in sides else sides[0]
    other = "destination" if side == "source" else "source"
    row = await require_object(request, object_type, object_id, write=True)
    peer = await require_object(request, rel[f"{other}_type"], body.peer_id)
    source, destination = (row, peer) if side == "source" else (peer, row)
    try:
        link = await db.add_relationship_link(
            rel["id"], str(source["id"]), str(destination["id"]), created_by=_session_user(request)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Relationship not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(
        request,
        "link_create",
        f"relationship={rel['key']} {rel['source_type']}={link['source_key']} "
        f"{rel['destination_type']}={link['destination_key']}",
    )
    return link


@router.delete("/api/objects/{object_type}/{object_id}/relationships/{link_id}")
@scoped("object")
async def delete_object_link(object_type: str, object_id: int, link_id: int, request: Request) -> dict:
    """Remove a link of the object (write on the object needed)."""
    await require_object(request, object_type, object_id, write=True)
    link = await db.get_relationship_link(link_id)
    key = str(object_id)
    if link is None or not (
        (link["source_type"] == object_type and link["source_key"] == key)
        or (link["destination_type"] == object_type and link["destination_key"] == key)
    ):
        raise HTTPException(status_code=404, detail="Link not found")
    await db.delete_relationship_link(link_id)
    await _audit_write(request, "link_delete", f"id={link_id} {object_type}={key}")
    return {"ok": True}


# ── Computed field and relationship definitions ──────────────────────────────


def _definition_key(raw: str) -> str:
    key = raw.strip()
    if not FIELD_KEY_RE.fullmatch(key):
        raise _unprocessable("Key must start with a lowercase letter and use only a-z, 0-9 and _ (at most 50).")
    return key


def _label_text(raw: str) -> str:
    label = raw.strip()
    if not label:
        raise _unprocessable("Enter a label.")
    return label


def _template_text(raw: str) -> str:

    text = raw.strip()
    if not text:
        raise _unprocessable("Enter a template.")
    issue = check_syntax(text, "computed field")
    if issue is not None:
        raise _unprocessable(f"Template error on line {issue.line}: {issue.message}")
    return text


def _known_type(object_type: str, allowed: tuple[str, ...], what: str) -> str:
    if object_type not in allowed:
        raise _unprocessable(f"{what} must be one of: {', '.join(allowed)}.")
    return object_type


@router.get("/api/computed-fields")
@scope_exempt("computed field definitions: no host or inventory group data")
async def list_computed(object_type: str | None = Query(default=None, max_length=50)) -> list[dict]:
    if object_type is not None and object_type not in OBJECT_TYPES:
        raise HTTPException(status_code=400, detail=f"object_type must be one of: {', '.join(OBJECT_TYPES)}")
    return await db.list_computed_fields(object_type)


@admin_router.post("/api/computed-fields", status_code=201)
async def create_computed(body: ComputedFieldCreate, request: Request) -> dict:
    key = _definition_key(body.key)
    object_type = _known_type(body.object_type, GENERIC_TYPES, "Object type")
    try:
        created = await db.create_computed_field(
            key=key,
            label=_label_text(body.label),
            object_type=object_type,
            template=_template_text(body.template),
            description=body.description.strip(),
            sort_order=body.sort_order,
            created_by=_session_user(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(request, "computed_create", f"key={key} type={object_type}")
    return created


@admin_router.put("/api/computed-fields/{field_id}")
async def update_computed(field_id: int, body: ComputedFieldUpdate, request: Request) -> dict:
    current = await db.get_computed_field(field_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Computed field not found")
    updated = await db.update_computed_field(
        field_id,
        label=_label_text(body.label) if body.label is not None else current["label"],
        template=_template_text(body.template) if body.template is not None else current["template"],
        description=body.description.strip() if body.description is not None else current["description"],
        sort_order=body.sort_order if body.sort_order is not None else current["sort_order"],
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Computed field not found")
    await _audit_write(request, "computed_update", f"key={current['key']} type={current['object_type']}")
    return updated


@admin_router.delete("/api/computed-fields/{field_id}")
async def delete_computed(field_id: int, request: Request) -> dict:
    current = await db.get_computed_field(field_id)
    if current is None or not await db.delete_computed_field(field_id):
        raise HTTPException(status_code=404, detail="Computed field not found")
    await _audit_write(request, "computed_delete", f"key={current['key']} type={current['object_type']}")
    return {"ok": True}


@admin_router.post("/api/computed-fields/preview")
async def preview_computed(body: ComputedPreview, request: Request) -> dict:
    """Render a template against one object: ``{"value", "error"}``. A
    template error is reported, not raised."""

    row = await require_object(request, body.object_type, body.object_id)
    data = await db.get_object_data(body.object_type, str(row["id"]))
    fields = await db.list_custom_fields(body.object_type)
    result = Renderer({"preview": body.template}).render("preview", _computed_context(row, data, fields))
    if result.error is not None:
        return {"value": "", "error": result.error.message}
    return {"value": result.config_text.strip()[:COMPUTED_OUTPUT_MAX], "error": None}


@router.get("/api/relationships")
@scope_exempt("relationship definitions: no host or inventory group data")
async def list_relationship_definitions(object_type: str | None = Query(default=None, max_length=50)) -> list[dict]:
    if object_type is not None and object_type not in OBJECT_TYPES:
        raise HTTPException(status_code=400, detail=f"object_type must be one of: {', '.join(OBJECT_TYPES)}")
    return await db.list_relationships(object_type, with_counts=True)


@admin_router.post("/api/relationships", status_code=201)
async def create_relationship(body: RelationshipCreate, request: Request) -> dict:
    key = _definition_key(body.key)
    source = _known_type(body.source_type, GENERIC_TYPES, "Source type")
    destination = _known_type(body.destination_type, GENERIC_TYPES, "Destination type")
    try:
        created = await db.create_relationship(
            key=key,
            label=_label_text(body.label),
            source_type=source,
            destination_type=destination,
            cardinality=body.cardinality,
            description=body.description.strip(),
            created_by=_session_user(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(request, "relationship_create", f"key={key} {source}->{destination} {body.cardinality}")
    return created


@admin_router.put("/api/relationships/{relationship_id}")
async def update_relationship(relationship_id: int, body: RelationshipUpdate, request: Request) -> dict:
    current = await db.get_relationship(relationship_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Relationship not found")
    updated = await db.update_relationship(
        relationship_id,
        label=_label_text(body.label) if body.label is not None else current["label"],
        description=body.description.strip() if body.description is not None else current["description"],
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Relationship not found")
    await _audit_write(request, "relationship_update", f"key={current['key']}")
    return updated


@admin_router.delete("/api/relationships/{relationship_id}")
async def delete_relationship(relationship_id: int, request: Request) -> dict:
    current = await db.get_relationship(relationship_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Relationship not found")
    removed = await db.delete_relationship(relationship_id)
    await _audit_write(request, "relationship_delete", f"key={current['key']} links_removed={removed}")
    return {"ok": True, "removed": removed}
