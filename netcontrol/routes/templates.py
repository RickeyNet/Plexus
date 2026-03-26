"""
templates.py -- Template CRUD routes.
"""

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from netcontrol.routes.shared import _audit, _corr_id, _get_session

router = APIRouter()


class TemplateCreate(BaseModel):
    name: str
    content: str
    description: str = ""

class TemplateUpdate(BaseModel):
    name: str
    content: str
    description: str = ""


@router.get("/api/templates")
async def list_templates():
    return await db.get_all_templates()


@router.post("/api/templates", status_code=201)
async def create_template(body: TemplateCreate, request: Request = None):
    tid = await db.create_template(body.name, body.content, body.description)
    session = _get_session(request) if request else None
    await _audit("config", "template.create", user=session["user"] if session else "", detail=f"created template '{body.name}'", correlation_id=_corr_id(request))
    return {"id": tid}


@router.get("/api/templates/{template_id}")
async def get_template(template_id: int):
    tpl = await db.get_template(template_id)
    if not tpl:
        raise HTTPException(404, "Template not found")
    return tpl


@router.put("/api/templates/{template_id}")
async def update_template(template_id: int, body: TemplateUpdate, request: Request = None):
    await db.update_template(template_id, body.name, body.content, body.description)
    session = _get_session(request) if request else None
    await _audit("config", "template.update", user=session["user"] if session else "", detail=f"updated template {template_id}", correlation_id=_corr_id(request))
    return {"ok": True}


@router.delete("/api/templates/{template_id}")
async def delete_template(template_id: int, request: Request = None):
    await db.delete_template(template_id)
    session = _get_session(request) if request else None
    await _audit("config", "template.delete", user=session["user"] if session else "", detail=f"deleted template {template_id}", correlation_id=_corr_id(request))
    return {"ok": True}
