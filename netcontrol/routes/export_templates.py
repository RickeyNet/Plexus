"""Export templates: ``/api/export-templates``.

Two routers, each registered in ``app.py``:

- ``router`` (any signed-in user): list and read the templates of the
  object types the caller reads, and render one (``GET
  /api/export-templates/{id}/render``) into a file. A render checks the
  object type's feature (``netcontrol.export_templates.OBJECT_TYPES``) and
  loads the objects through the same list endpoint or export the type's
  own pages use, so the caller's object scope and the request's filters
  apply exactly as there.
- ``admin_router`` (admin): create, change and delete templates, and
  preview unsaved text against the first objects of its type.

Rules and the sandboxed renderer live in ``netcontrol.export_templates``,
storage in ``routes.db.export_templates``. See ``docs/export-templates.md``.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from pydantic.fields import FieldInfo

from netcontrol.bulk_import import host_export_records
from netcontrol.custom_fields import CustomFieldError
from netcontrol.export_templates import (
    OBJECT_TYPES,
    PREVIEW_DEFAULT,
    PREVIEW_MAX,
    TEMPLATE_TEXT_MAX,
    check_syntax,
    clean_description,
    clean_extension,
    clean_mime_type,
    clean_name_value,
    clean_object_type,
    clean_template_text,
    render,
)
from netcontrol.object_scope import refuse_scoped, request_scope, scope_exempt, scoped
from netcontrol.routes.circuits import list_circuits
from netcontrol.routes.config_backups import _safe_filename
from netcontrol.routes.custom_fields import attach_custom_data, matching_keys
from netcontrol.routes.device_model import matching_host_ids
from netcontrol.routes.network_objects import list_vlans
from netcontrol.routes.organization import list_sites
from netcontrol.routes.shared import _audit, _corr_id, _session_user, caller_features

LOGGER = logging.getLogger("plexus.export_templates")

router = APIRouter()
admin_router = APIRouter()

PREFIX = "/api/export-templates"
_RAW_MAX = 1000
# Longest text filter value a render accepts.
_FILTER_MAX = 200
# A rendered file never runs scripts or loads anything, whatever its media
# type: the browser treats it as a sandboxed, opaque-origin document.
_RENDER_CSP = "default-src 'none'; sandbox"


# ── Request bodies ───────────────────────────────────────────────────────────


class TemplateBody(BaseModel):
    name: str = Field(max_length=_RAW_MAX)
    object_type: str = Field(max_length=40)
    description: str = Field(default="", max_length=_RAW_MAX * 4)
    template_text: str = Field(default="", max_length=TEMPLATE_TEXT_MAX * 2)
    mime_type: str = Field(default="text/plain", max_length=_RAW_MAX)
    file_extension: str = Field(default="txt", max_length=_RAW_MAX)
    as_attachment: bool = True


class PreviewBody(BaseModel):
    object_type: str = Field(max_length=40)
    template_text: str = Field(default="", max_length=TEMPLATE_TEXT_MAX * 2)
    limit: int = Field(default=PREVIEW_DEFAULT, ge=1, le=PREVIEW_MAX)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _clean(fn: Callable[[Any], Any], raw: Any) -> Any:
    """Run a ``netcontrol.export_templates`` validator; 400 with its message."""
    try:
        return fn(raw)
    except CustomFieldError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _found(record: dict | None) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail="Export template not found")
    return record


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit(
        "export_templates", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request)
    )


def _values(body: TemplateBody) -> dict:
    values = {
        "name": _clean(clean_name_value, body.name),
        "object_type": _clean(clean_object_type, body.object_type),
        "description": _clean(clean_description, body.description),
        "template_text": _clean(clean_template_text, body.template_text),
        "mime_type": _clean(clean_mime_type, body.mime_type),
        "file_extension": _clean(clean_extension, body.file_extension),
        "as_attachment": body.as_attachment,
    }
    issue = check_syntax(values["template_text"])
    if issue is not None:
        raise HTTPException(status_code=400, detail={"message": issue.message, "line": issue.line})
    return values


def _readable_types(features: frozenset[str] | None) -> list[str]:
    """The object types whose feature ``features`` holds (``None``: all)."""
    return [k for k, t in OBJECT_TYPES.items() if features is None or t.feature in features]


async def _require_type(request: Request, object_type: str) -> None:
    """403 unless the caller reads ``object_type``'s feature."""
    if object_type not in _readable_types(await caller_features(request)):
        raise HTTPException(status_code=403, detail=f"Access denied for feature '{OBJECT_TYPES[object_type].feature}'")


async def _readable_template(request: Request, template_id: int) -> dict:
    """The template when the caller reads its object type; 404 otherwise
    (no existence leak)."""
    record = _found(await db.get_export_template(template_id))
    if record["object_type"] not in _readable_types(await caller_features(request)):
        raise HTTPException(status_code=404, detail="Export template not found")
    return record


# ── Objects of each type ─────────────────────────────────────────────────────


def _text_filter(request: Request, name: str) -> str | None:
    value = request.query_params.get(name)
    if value is None:
        return None
    if len(value) > _FILTER_MAX:
        raise HTTPException(status_code=400, detail=f"{name} must be at most {_FILTER_MAX} characters.")
    return value


def _int_filter(request: Request, name: str) -> int | None:
    value = _text_filter(request, name)
    if value is None or not value.strip():
        return None
    try:
        return int(value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{name} must be a whole number.") from None


async def _call_list(handler: Callable[..., Awaitable[dict]], request: Request, key: str, object_type: str) -> list:
    """Call a list route handler directly, as its route would: the request
    (its ``tag=`` / ``cf.<key>=`` filters and the caller's scope) plus each
    of the type's filters given in the query string, parsed by the
    handler's annotation; every other parameter takes its declared default.
    Returns the handler's ``key`` list."""
    wanted = set(OBJECT_TYPES[object_type].filters)
    kwargs: dict[str, Any] = {}
    for name, param in inspect.signature(handler).parameters.items():
        if name == "request":
            kwargs[name] = request
            continue
        if name in wanted and name in request.query_params:
            is_int = "int" in str(param.annotation)
            kwargs[name] = _int_filter(request, name) if is_int else _text_filter(request, name)
            continue
        default = param.default
        kwargs[name] = default.default if isinstance(default, FieldInfo) else default
    return list((await handler(**kwargs))[key])


async def _hosts(request: Request) -> list[dict]:
    """The hosts of the inventory export (``GET /api/inventory/export/csv``)
    the caller may read, after ``group_id=``, the device filters and
    ``tag=`` / ``cf.<key>=``."""
    hosts = (await request_scope(request)).filter_hosts(await db.get_all_hosts_for_export())
    group_id = _int_filter(request, "group_id")
    if group_id is not None:
        hosts = [h for h in hosts if h.get("group_id") == group_id]
    keys = await matching_keys("host", request.query_params)
    host_ids = await matching_host_ids(request.query_params)
    hosts = [
        h for h in hosts if (keys is None or str(h["id"]) in keys) and (host_ids is None or int(h["id"]) in host_ids)
    ]
    _fields, records = await host_export_records(hosts)
    return [{"id": int(h["id"]), "group_id": h.get("group_id"), **r} for h, r in zip(hosts, records, strict=True)]


def _prefix_key(row: dict) -> str:
    try:
        return db.prefix_key(row["subnet"], row.get("vrf"))
    except ValueError:
        return ""


async def _prefixes(request: Request) -> list[dict]:
    """Every IPAM prefix (local and synced), after ``status=``, ``vrf=`` and
    ``tag=`` / ``cf.<key>=``. Not for callers limited to selected inventory
    groups (prefix records carry no tenant to scope them by)."""
    await refuse_scoped(request)
    rows = await db.list_ipam_prefix_records()
    status, vrf = _text_filter(request, "status"), _text_filter(request, "vrf")
    rows = [
        r
        for r in rows
        if (status is None or r.get("status") == status) and (vrf is None or (r.get("vrf") or "") == vrf)
    ]
    keys = await matching_keys("prefix", request.query_params)
    if keys is not None:
        rows = [r for r in rows if _prefix_key(r) in keys]
    await attach_custom_data("prefix", rows, _prefix_key)
    return rows


async def _addresses(request: Request) -> list[dict]:
    """Every IPAM IP address, after ``prefix=`` (the prefix's subnet) and
    ``status=``. Not for callers limited to selected inventory groups."""
    await refuse_scoped(request)
    prefix = _text_filter(request, "prefix")
    rows = await db.list_ipam_allocation_records(prefix_subnets=[prefix] if prefix is not None else None)
    status = _text_filter(request, "status")
    return [r for r in rows if status is None or r.get("status") == status]


async def _vlans(request: Request) -> list[dict]:
    return await _call_list(list_vlans, request, "vlans", "vlan")


async def _circuits(request: Request) -> list[dict]:
    return await _call_list(list_circuits, request, "circuits", "circuit")


async def _sites(request: Request) -> list[dict]:
    return await _call_list(list_sites, request, "sites", "site")


_LOADERS: dict[str, Callable[[Request], Awaitable[list[dict]]]] = {
    "host": _hosts,
    "prefix": _prefixes,
    "ip_address": _addresses,
    "vlan": _vlans,
    "circuit": _circuits,
    "site": _sites,
}


async def load_queryset(request: Request, object_type: str) -> list[dict]:
    """The objects of ``object_type`` the caller may read, after the
    request's filters (403 without the type's feature)."""
    await _require_type(request, object_type)
    return await _LOADERS[object_type](request)


def _filename(template: dict) -> str:
    base = _safe_filename(template["name"])
    return f"{base}.{template['file_extension']}" if template["file_extension"] else base


# ── Templates (read) ─────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/object-types")
@scope_exempt("the object type catalogue: no host or inventory group data")
async def list_object_types(request: Request) -> dict:
    """Every object type with its filters, its main fields and whether the
    caller reads it."""
    readable = set(_readable_types(await caller_features(request)))
    return {
        "object_types": [
            {
                "key": t.key,
                "label": t.label,
                "feature": t.feature,
                "filters": list(t.filters),
                "fields": list(t.fields),
                "tags": t.tags,
                "readable": t.key in readable,
            }
            for t in OBJECT_TYPES.values()
        ]
    }


@router.get(PREFIX)
@scope_exempt("template definitions: no host or inventory group data")
async def list_templates(request: Request, object_type: str | None = Query(default=None, max_length=40)) -> dict:
    """The templates of the object types the caller reads (one type's with
    ``object_type``)."""
    types = _readable_types(await caller_features(request))
    if object_type is not None:
        _clean(clean_object_type, object_type)
        types = [t for t in types if t == object_type]
    return {"templates": await db.list_export_templates(types)}


@router.get(f"{PREFIX}/{{template_id}}")
@scope_exempt("a template definition: no host or inventory group data")
async def get_template(template_id: int, request: Request) -> dict:
    return await _readable_template(request, template_id)


@router.get(f"{PREFIX}/{{template_id}}/render")
@scoped("list")
async def render_template(template_id: int, request: Request) -> Response:
    """The template rendered with the objects of its type the caller may
    read, after the query string's filters, as a file: ``Content-Type`` and
    ``Content-Disposition`` from the template. 400 with the message and
    line when the template fails."""
    template = await _readable_template(request, template_id)
    queryset = await load_queryset(request, template["object_type"])
    result = await asyncio.to_thread(render, template["template_text"], template["object_type"], queryset)
    if result.error is not None:
        raise HTTPException(
            status_code=400,
            detail={"message": f"The template did not render: {result.error.message}", "line": result.error.line},
        )
    await _audit_write(
        request, "export_template_render", f"id={template_id} name={template['name']} objects={len(queryset)}"
    )
    disposition = "attachment" if template["as_attachment"] else "inline"
    return Response(
        content=result.config_text,
        headers={
            "Content-Type": f"{template['mime_type']}; charset=utf-8",
            "Content-Disposition": f'{disposition}; filename="{_filename(template)}"',
            "Content-Security-Policy": _RENDER_CSP,
            "Cache-Control": "private, no-store",
        },
    )


# ── Templates (admin) ────────────────────────────────────────────────────────


@admin_router.post(f"{PREFIX}/preview")
async def preview(body: PreviewBody, request: Request) -> dict:
    """Render unsaved text with the first ``limit`` objects of its type;
    stores nothing. A template error is in ``error`` (``message``,
    ``line``), not an HTTP error."""
    object_type = _clean(clean_object_type, body.object_type)
    text = _clean(clean_template_text, body.template_text)
    queryset = await load_queryset(request, object_type)
    result = await asyncio.to_thread(render, text, object_type, queryset[: body.limit])
    return {
        "output": result.config_text,
        "error": result.error.as_dict() if result.error else None,
        "count": min(len(queryset), body.limit),
        "total": len(queryset),
    }


@admin_router.post(PREFIX, status_code=201)
async def create_template(body: TemplateBody, request: Request) -> dict:
    values = _values(body)
    try:
        record = await db.create_export_template(values, _session_user(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(
        request, "export_template_create", f"id={record['id']} name={record['name']} type={record['object_type']}"
    )
    return record


@admin_router.put(f"{PREFIX}/{{template_id}}")
async def update_template(template_id: int, body: TemplateBody, request: Request) -> dict:
    _found(await db.get_export_template(template_id))
    values = _values(body)
    try:
        record = _found(await db.update_export_template(template_id, values, _session_user(request)))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(request, "export_template_update", f"id={template_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/{{template_id}}")
async def delete_template(template_id: int, request: Request) -> dict:
    record = _found(await db.get_export_template(template_id))
    await db.delete_export_template(template_id)
    await _audit_write(request, "export_template_delete", f"id={template_id} name={record['name']}")
    return {"ok": True}
