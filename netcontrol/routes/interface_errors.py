"""
interface_errors.py -- Interface error/discard trending with root-cause correlation.

Provides API endpoints for:
  - Per-host interface error summary with trend data
  - Per-port error time-series (for charting)
  - Error spike events with root-cause correlation details
  - Event acknowledgement and resolution
"""
from __future__ import annotations


import json

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.interface_errors")

# ── Late-binding auth (injected by app.py) ───────────────────────────────────
_require_auth = None
_require_admin = None


def init_interface_errors(require_auth, require_admin):
    global _require_auth, _require_admin
    _require_auth = require_auth
    _require_admin = require_admin


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/interfaces/{host_id}/errors")
async def interface_error_summary(
    host_id: int,
    days: int = Query(default=1, ge=1, le=365),
):
    """Per-interface error/discard summary for a host.

    Returns aggregated error rates per interface with sample counts,
    averages, and peak values.
    """
    summary = await db.get_interface_error_summary(host_id, days)

    # Group by interface
    interfaces: dict[str, dict] = {}
    for row in summary:
        labels_str = row.get("labels_json", "{}")
        try:
            labels = json.loads(labels_str)
        except (json.JSONDecodeError, TypeError):
            labels = {}
        if_key = f"{labels.get('if_index', '?')}:{labels.get('if_name', '?')}"
        if if_key not in interfaces:
            interfaces[if_key] = {
                "if_index": labels.get("if_index"),
                "if_name": labels.get("if_name", ""),
                "metrics": {},
            }
        metric = row.get("metric_name", "")
        interfaces[if_key]["metrics"][metric] = {
            "sample_count": row.get("sample_count", 0),
            "avg_value": round(row["avg_value"], 4) if row.get("avg_value") is not None else None,
            "max_value": round(row["max_value"], 4) if row.get("max_value") is not None else None,
            "min_value": round(row["min_value"], 4) if row.get("min_value") is not None else None,
        }

    # Fetch active error events for this host
    events = await db.get_interface_error_events(host_id=host_id, unresolved_only=True)

    return {
        "host_id": host_id,
        "days": days,
        "interfaces": list(interfaces.values()),
        "active_events": len(events),
    }


@router.get("/api/interfaces/{host_id}/port/{if_index}/errors")
async def interface_error_detail(
    host_id: int,
    if_index: int,
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    limit: int = Query(default=5000, ge=1, le=50000),
):
    """Detailed error/discard time-series for a single interface."""
    samples = await db.get_interface_error_trending(
        host_id, if_index=if_index, start=start, end=end, limit=limit,
    )

    # Separate by metric type for easy charting
    series: dict[str, list] = {
        "if_in_errors": [],
        "if_out_errors": [],
        "if_in_discards": [],
        "if_out_discards": [],
        "if_in_errors_rate": [],
        "if_out_errors_rate": [],
        "if_in_discards_rate": [],
        "if_out_discards_rate": [],
    }
    for s in samples:
        metric = s.get("metric_name", "")
        if metric in series:
            series[metric].append({
                "value": s.get("value"),
                "sampled_at": s.get("sampled_at"),
            })

    # Fetch error events for this interface
    events = await db.get_interface_error_events(host_id=host_id, limit=50)
    port_events = [e for e in events if e.get("if_index") == if_index]

    return {
        "host_id": host_id,
        "if_index": if_index,
        "series": series,
        "events": port_events,
        "sample_count": len(samples),
    }


@router.get("/api/interface-error-events")
async def list_error_events(
    host_id: int | None = Query(default=None),
    severity: str | None = Query(default=None),
    unresolved_only: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=10000),
):
    """List interface error spike events across all devices."""
    return await db.get_interface_error_events(
        host_id=host_id, severity=severity,
        unresolved_only=unresolved_only, limit=limit,
    )


@router.get("/api/interface-error-events/{event_id}")
async def get_error_event(event_id: int):
    """Get a single error event with full correlation details."""
    event = await db.get_interface_error_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Parse correlation_details JSON for the response
    try:
        event["correlation_details"] = json.loads(event.get("correlation_details", "{}"))
    except (json.JSONDecodeError, TypeError):
        event["correlation_details"] = {}

    return event


@router.post("/api/interface-error-events/{event_id}/acknowledge")
async def acknowledge_error_event(event_id: int, request: Request):
    """Acknowledge an interface error event."""
    session = _get_session(request)
    user = session["user"] if session else ""
    success = await db.acknowledge_interface_error_event(event_id, user)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    await _audit("interface_errors", "event.acknowledged", user=user,
                 detail=f"event_id={event_id}", correlation_id=_corr_id(request))
    return {"ok": True}


@router.post("/api/interface-error-events/{event_id}/resolve")
async def resolve_error_event(event_id: int, request: Request):
    """Mark an interface error event as resolved."""
    session = _get_session(request)
    user = session["user"] if session else ""
    success = await db.resolve_interface_error_event(event_id)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    await _audit("interface_errors", "event.resolved", user=user,
                 detail=f"event_id={event_id}", correlation_id=_corr_id(request))
    return {"ok": True}
