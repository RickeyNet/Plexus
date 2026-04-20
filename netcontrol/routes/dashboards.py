"""
dashboards.py -- User-defined dashboards with configurable panels
"""
from __future__ import annotations


import logging

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.dashboards")


class DashboardCreate(BaseModel):
    name: str
    description: str = ""
    variables_json: str = "[]"
    layout_json: str = "{}"


class DashboardUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    variables_json: str | None = None
    layout_json: str | None = None


class PanelCreate(BaseModel):
    title: str = ""
    chart_type: str = "line"
    metric_query_json: str = "{}"
    grid_x: int = 0
    grid_y: int = 0
    grid_w: int = 6
    grid_h: int = 4
    options_json: str = "{}"


class PanelUpdate(BaseModel):
    title: str | None = None
    chart_type: str | None = None
    metric_query_json: str | None = None
    grid_x: int | None = None
    grid_y: int | None = None
    grid_w: int | None = None
    grid_h: int | None = None
    options_json: str | None = None


# ── Dashboard CRUD ────────────────────────────────────────────────────────────

@router.get("/api/dashboards")
async def list_dashboards_api(request: Request):
    dashboards = await db.list_dashboards()
    return {"dashboards": dashboards}


@router.post("/api/dashboards", status_code=201)
async def create_dashboard_api(payload: DashboardCreate, request: Request):
    user = getattr(request.state, "user", None) or {}
    owner = user.get("username", "") if isinstance(user, dict) else ""
    dashboard = await db.create_dashboard(
        name=payload.name,
        description=payload.description,
        owner=owner,
        layout_json=payload.layout_json,
        variables_json=payload.variables_json,
    )
    LOGGER.info("Dashboard created: %s (id=%s)", payload.name, dashboard.get("id"))
    return dashboard


@router.get("/api/dashboards/{dashboard_id}")
async def get_dashboard_api(dashboard_id: int):
    dashboard = await db.get_dashboard(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return dashboard


@router.put("/api/dashboards/{dashboard_id}")
async def update_dashboard_api(dashboard_id: int, payload: DashboardUpdate):
    existing = await db.get_dashboard(dashboard_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    updated = await db.update_dashboard(
        dashboard_id,
        name=payload.name,
        description=payload.description,
        variables_json=payload.variables_json,
        layout_json=payload.layout_json,
    )
    return updated


@router.delete("/api/dashboards/{dashboard_id}")
async def delete_dashboard_api(dashboard_id: int):
    deleted = await db.delete_dashboard(dashboard_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return {"status": "deleted"}


# ── Panel CRUD ────────────────────────────────────────────────────────────────

@router.post("/api/dashboards/{dashboard_id}/panels", status_code=201)
async def create_panel_api(dashboard_id: int, payload: PanelCreate):
    existing = await db.get_dashboard(dashboard_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    panel = await db.create_dashboard_panel(
        dashboard_id=dashboard_id,
        title=payload.title,
        chart_type=payload.chart_type,
        metric_query_json=payload.metric_query_json,
        grid_x=payload.grid_x,
        grid_y=payload.grid_y,
        grid_w=payload.grid_w,
        grid_h=payload.grid_h,
        options_json=payload.options_json,
    )
    return panel


@router.put("/api/dashboards/{dashboard_id}/panels/{panel_id}")
async def update_panel_api(dashboard_id: int, panel_id: int, payload: PanelUpdate):
    updated = await db.update_dashboard_panel(
        panel_id,
        title=payload.title,
        chart_type=payload.chart_type,
        metric_query_json=payload.metric_query_json,
        grid_x=payload.grid_x,
        grid_y=payload.grid_y,
        grid_w=payload.grid_w,
        grid_h=payload.grid_h,
        options_json=payload.options_json,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Panel not found")
    return updated


@router.delete("/api/dashboards/{dashboard_id}/panels/{panel_id}")
async def delete_panel_api(dashboard_id: int, panel_id: int):
    deleted = await db.delete_dashboard_panel(panel_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Panel not found")
    return {"status": "deleted"}


# ── Annotations ──────────────────────────────────────────────────────────────

@router.get("/api/annotations")
async def get_annotations_api(
    host_id: int | None = Query(default=None),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    categories: str = Query(default="deployment,config,alert"),
):
    cat_list = [c.strip() for c in categories.split(",") if c.strip()]
    annotations = await db.get_annotations_in_range(
        host_id=host_id,
        start=start,
        end=end,
        categories=cat_list,
    )
    return {"annotations": annotations}
