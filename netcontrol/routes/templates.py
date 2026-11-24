"""
templates.py -- Template CRUD routes.

Object scope: templates are a shared catalogue (no host or group): accounts
limited to selected inventory groups read them; only unrestricted callers
change them.

A template (or a device-type variant) may reference only the secret
variables its saving user may use (``require_usable_secret_references``):
a job resolves them for whoever runs it, who may be an admin.
"""

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from routes.secret_resolver import require_usable_secret_references

from netcontrol.object_scope import require_model_write, scope_exempt, scoped
from netcontrol.routes.git_sources import reject_git_owned
from netcontrol.routes.shared import _audit, _corr_id, _get_session

router = APIRouter()


class TemplateCreate(BaseModel):
    name: str
    content: str
    description: str = ""
    # Empty = generic body (any vendor).  A Netmiko device_type string
    # (e.g. "paloalto_panos") makes this a vendor-specific variant of
    # the same name; see migration 0040 / resolve_template_for_device_type.
    device_type: str = ""


class TemplateUpdate(BaseModel):
    name: str
    content: str
    description: str = ""
    device_type: str = ""


@router.get("/api/templates")
@scope_exempt("shared template catalogue: no host or inventory group data")
async def list_templates():
    return await db.get_all_templates()


@router.post("/api/templates", status_code=201)
@scoped("catalog")
async def create_template(body: TemplateCreate, request: Request = None):
    await require_model_write(request)
    await require_usable_secret_references(request, [body.content])
    tid = await db.create_template(body.name, body.content, body.description, body.device_type)
    session = _get_session(request) if request else None
    _dt = f" [{body.device_type}]" if body.device_type else ""
    await _audit(
        "config",
        "template.create",
        user=session["user"] if session else "",
        detail=f"created template '{body.name}'{_dt}",
        correlation_id=_corr_id(request),
    )
    return {"id": tid}


@router.get("/api/templates/{template_id}")
@scope_exempt("shared template catalogue: no host or inventory group data")
async def get_template(template_id: int):
    tpl = await db.get_template(template_id)
    if not tpl:
        raise HTTPException(404, "Template not found")
    return tpl


@router.put("/api/templates/{template_id}")
@scoped("catalog")
async def update_template(template_id: int, body: TemplateUpdate, request: Request = None):
    await require_model_write(request)
    reject_git_owned(await db.get_template(template_id), "template")
    await require_usable_secret_references(request, [body.content])
    await db.update_template(template_id, body.name, body.content, body.description, body.device_type)
    session = _get_session(request) if request else None
    await _audit(
        "config",
        "template.update",
        user=session["user"] if session else "",
        detail=f"updated template {template_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/templates/{template_id}")
@scoped("catalog")
async def delete_template(template_id: int, request: Request = None):
    await require_model_write(request)
    reject_git_owned(await db.get_template(template_id), "template")
    await db.delete_template(template_id)
    session = _get_session(request) if request else None
    await _audit(
        "config",
        "template.delete",
        user=session["user"] if session else "",
        detail=f"deleted template {template_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}
