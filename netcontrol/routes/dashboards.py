"""
dashboards.py -- User-defined dashboards with configurable panels
"""
from __future__ import annotations

import logging

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from netcontrol.routes.shared import _get_session, require_owner_or_admin
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

async def _is_admin_session(session: dict | None) -> bool:
    if session is None:
        # API-token callers are admin-equivalent by design.
        return True
    user = await db.get_user_by_id(session["user_id"])
    return bool(user and user.get("role") == "admin")


@router.get("/api/dashboards")
async def list_dashboards_api(request: Request):
    session = _get_session(request)
    # Non-admin users see only their own dashboards; admins and API-token
    # callers see all. Previously this returned every user's dashboards.
    owner = None
    if not await _is_admin_session(session):
        owner = (session or {}).get("user")
    dashboards = await db.list_dashboards(owner=owner)
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
async def get_dashboard_api(dashboard_id: int, request: Request):
    dashboard = await db.get_dashboard(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    await require_owner_or_admin(request, dashboard.get("owner"))
    return dashboard


@router.put("/api/dashboards/{dashboard_id}")
async def update_dashboard_api(dashboard_id: int, payload: DashboardUpdate, request: Request):
    existing = await db.get_dashboard(dashboard_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    await require_owner_or_admin(request, existing.get("owner"))
    updated = await db.update_dashboard(
        dashboard_id,
        name=payload.name,
        description=payload.description,
        variables_json=payload.variables_json,
        layout_json=payload.layout_json,
    )
    return updated


@router.delete("/api/dashboards/{dashboard_id}")
async def delete_dashboard_api(dashboard_id: int, request: Request):
    existing = await db.get_dashboard(dashboard_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    await require_owner_or_admin(request, existing.get("owner"))
    deleted = await db.delete_dashboard(dashboard_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return {"status": "deleted"}


# ── Panel CRUD ────────────────────────────────────────────────────────────────

@router.post("/api/dashboards/{dashboard_id}/panels", status_code=201)
async def create_panel_api(dashboard_id: int, payload: PanelCreate, request: Request):
    existing = await db.get_dashboard(dashboard_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    await require_owner_or_admin(request, existing.get("owner"))
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
async def update_panel_api(dashboard_id: int, panel_id: int, payload: PanelUpdate, request: Request):
    existing = await db.get_dashboard(dashboard_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    await require_owner_or_admin(request, existing.get("owner"))
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
async def delete_panel_api(dashboard_id: int, panel_id: int, request: Request):
    existing = await db.get_dashboard(dashboard_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    await require_owner_or_admin(request, existing.get("owner"))
    deleted = await db.delete_dashboard_panel(panel_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Panel not found")
    return {"status": "deleted"}


# ── Dashboard: bandwidth trend ───────────────────────────────────────────────

_BW_RANGE_MAP = {
    "1h": ("-1 hours", 720),
    "6h": ("-6 hours", 1500),
    "24h": ("-1 days", 2000),
    "7d": ("-7 days", 3000),
}


@router.get("/api/dashboard/top-interfaces")
async def dashboard_top_interfaces_api(
    range: str = Query(default="6h"),
    limit: int = Query(default=5, ge=1, le=20),
):
    """Top-N interfaces network-wide by peak bandwidth over `range`, with
    their bandwidth time-series so the dashboard can plot one line per
    interface. Picks the busiest (host, if_index) pairs by peak in/out bps,
    then fans out per-interface to fetch the series."""
    cutoff_sql, series_limit = _BW_RANGE_MAP.get(range, _BW_RANGE_MAP["6h"])
    from datetime import UTC, datetime, timedelta

    range_to_delta = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(days=1),
        "7d": timedelta(days=7),
    }
    start_dt = datetime.now(UTC) - range_to_delta.get(range, timedelta(hours=6))
    start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")

    tops = await db.get_top_interfaces_by_bandwidth(start=start_str, limit=limit)

    interfaces = []
    for t in tops:
        series = await db.query_interface_ts(
            host_id=t["host_id"],
            if_index=t["if_index"],
            start=start_str,
            limit=series_limit,
        )
        # query_interface_ts returns DESC; flip to ascending for time-axis plotting
        series.reverse()
        interfaces.append({
            "host_id": t["host_id"],
            "hostname": t.get("hostname") or "",
            "if_index": t["if_index"],
            "if_name": t.get("if_name") or "",
            "if_speed_mbps": t.get("if_speed_mbps") or 0,
            "peak_bps": t.get("peak_bps") or 0,
            "samples": [
                {
                    "ts": s.get("sampled_at"),
                    "in_bps": s.get("in_rate_bps"),
                    "out_bps": s.get("out_rate_bps"),
                }
                for s in series
            ],
        })

    return {"range": range, "interfaces": interfaces}


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
