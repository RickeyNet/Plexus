"""
interface_errors.py -- Interface error/discard trending with root-cause correlation.

Provides API endpoints for:
  - Per-host interface error summary with trend data
  - Per-port error time-series (for charting)
  - Error spike events with root-cause correlation details
  - Event acknowledgement and resolution

Object scope: error summaries, series and events follow their host; an
event with no inventory host is visible to unrestricted callers only.
"""

from __future__ import annotations

import json

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from netcontrol.object_scope import HOST_NOT_FOUND, group_filter, require_object_host, scoped
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.interface_errors")

_EVENT_NOT_FOUND = "Event not found"


async def _require_event(request: Request, event_id: int, *, write: bool = False) -> dict | None:
    """The event (``None`` when unknown); 404 for a scoped caller when it is
    unknown or its host is unreadable, 403 on ``write`` when not writable."""
    event = await db.get_interface_error_event(event_id)
    await require_object_host(request, event.get("host_id") if event else None, write=write, not_found=_EVENT_NOT_FOUND)
    return event


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/interfaces/{host_id}/errors")
@scoped("host")
async def interface_error_summary(
    request: Request,
    host_id: int,
    days: int = Query(default=1, ge=1, le=365),
):
    """Per-interface error/discard summary for a host.

    Returns aggregated error rates per interface with sample counts,
    averages, and peak values.
    """
    await require_object_host(request, host_id, not_found=HOST_NOT_FOUND)
    summary = await db.get_interface_error_summary(host_id, days)

    # Group by interface
    interfaces: dict[str, dict] = {}
    for row in summary:
        labels_str = row.get("labels_json", "{}")
        try:
            labels = json.loads(labels_str)
        except json.JSONDecodeError, TypeError:
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
@scoped("host")
async def interface_error_detail(
    request: Request,
    host_id: int,
    if_index: int,
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    limit: int = Query(default=5000, ge=1, le=50000),
):
    """Detailed error/discard time-series for a single interface."""
    await require_object_host(request, host_id, not_found=HOST_NOT_FOUND)
    samples = await db.get_interface_error_trending(
        host_id,
        if_index=if_index,
        start=start,
        end=end,
        limit=limit,
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
            series[metric].append(
                {
                    "value": s.get("value"),
                    "sampled_at": s.get("sampled_at"),
                }
            )

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
@scoped("list")
async def list_error_events(
    request: Request,
    host_id: int | None = Query(default=None),
    severity: str | None = Query(default=None),
    unresolved_only: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=10000),
):
    """List interface error spike events across all devices."""
    return await db.get_interface_error_events(
        host_id=host_id,
        severity=severity,
        unresolved_only=unresolved_only,
        limit=limit,
        **await group_filter(request),
    )


@router.get("/api/interface-error-events/{event_id}")
@scoped("event")
async def get_error_event(event_id: int, request: Request):
    """Get a single error event with full correlation details."""
    event = await _require_event(request, event_id)
    if not event:
        raise HTTPException(status_code=404, detail=_EVENT_NOT_FOUND)

    # Parse correlation_details JSON for the response
    try:
        event["correlation_details"] = json.loads(event.get("correlation_details", "{}"))
    except json.JSONDecodeError, TypeError:
        event["correlation_details"] = {}

    return event


@router.post("/api/interface-error-events/{event_id}/acknowledge")
@scoped("event")
async def acknowledge_error_event(event_id: int, request: Request):
    """Acknowledge an interface error event."""
    await _require_event(request, event_id, write=True)
    session = _get_session(request)
    user = session["user"] if session else ""
    success = await db.acknowledge_interface_error_event(event_id, user)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    await _audit(
        "interface_errors",
        "event.acknowledged",
        user=user,
        detail=f"event_id={event_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/interface-error-events/{event_id}/resolve")
@scoped("event")
async def resolve_error_event(event_id: int, request: Request):
    """Mark an interface error event as resolved."""
    await _require_event(request, event_id, write=True)
    session = _get_session(request)
    user = session["user"] if session else ""
    success = await db.resolve_interface_error_event(event_id)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    await _audit(
        "interface_errors", "event.resolved", user=user, detail=f"event_id={event_id}", correlation_id=_corr_id(request)
    )
    return {"ok": True}
