"""Hardware components API: a host's components with serials and their
history, an on-demand SNMP read, and the fleet-wide component and change
lists with a CSV export.

One router (``router``), registered in ``app.py`` behind the ``inventory``
feature: reads need ``inventory``, the refresh ``inventory.write`` (admins
and the API token pass both). Object scope: a host route answers 404 for a
host outside the caller's groups (the refresh 403 when it is read only);
the fleet lists keep the caller's readable hosts (a history row of a
deleted host is shown to unrestricted callers only).

Rules and readers: ``netcontrol.hardware_components``; storage:
``routes.db.hardware_components``; docs: ``docs/hardware-inventory.md``.
"""

from __future__ import annotations

import csv
import io
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response

import netcontrol.routes.state as state
from netcontrol import hardware_components as hc, health_checks
from netcontrol.csv_cells import csv_text_cell
from netcontrol.managed_targets import ADDRESS_AWAITING_CONFIRMATION, address_confirmed
from netcontrol.object_scope import HOST_NOT_FOUND, readable_host_ids, require_host, scoped
from netcontrol.routes.reporting import _csv_download_response
from netcontrol.routes.shared import _audit, _corr_id, _session_user, caller_is_admin
from netcontrol.routes.snmp import PYSMNP_AVAILABLE, _snmp_get_values, _snmp_walk
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.hardware_components")

LIMIT_MAX = 500
OFFSET_MAX = 100_000
EXPORT_MAX_ROWS = 50_000
_SNMP_TIMEOUT = 5.0

_COMPONENT_KEYS = (
    "id",
    "host_id",
    "hostname",
    "category",
    "slot",
    "name",
    "description",
    "model",
    "serial",
    "hardware_rev",
    "firmware_rev",
    "software_rev",
    "status",
    "source",
    "first_seen",
    "last_seen",
    "removed_at",
)
_EVENT_KEYS = (
    "id",
    "host_id",
    "hostname",
    "occurred_at",
    "event",
    "category",
    "slot",
    "name",
    "model",
    "serial",
    "previous_serial",
    "previous_model",
    "previous_slot",
    "previous_host_id",
    "previous_hostname",
    "changes",
    "detail",
)


def _choices(raw: str | None, allowed: tuple[str, ...], name: str) -> list[str]:
    """A comma-separated filter: its values, each one of ``allowed`` (else
    422); ``[]`` for none."""
    values = [v.strip() for v in str(raw or "").split(",") if v.strip()]
    unknown = [v for v in values if v not in allowed]
    if unknown:
        raise HTTPException(status_code=422, detail=f"{name} must be one or more of {', '.join(allowed)}")
    return list(dict.fromkeys(values))


def _component(row: dict) -> dict:
    out = {key: row.get(key) for key in _COMPONENT_KEYS}
    out["removed_at"] = row.get("removed_at") or None
    for key in _COMPONENT_KEYS:
        if out[key] is None and key not in ("removed_at",):
            out[key] = ""
    return out


def _event(row: dict, readable: frozenset[int] | None) -> dict:
    """An event as the API returns it. For a scoped caller (``readable``
    not None) the host a component was last seen on is cleared unless the
    caller may read it (a deleted host: never)."""
    out = {key: row.get(key) for key in _EVENT_KEYS}
    for key in _EVENT_KEYS:
        if out[key] is None and key not in ("host_id", "previous_host_id"):
            out[key] = ""
    out["changes"] = row.get("changes") or {}
    previous = out.get("previous_host_id")
    if readable is not None and (previous is None or int(previous) not in readable):
        out["previous_host_id"] = None
        out["previous_hostname"] = ""
    return out


async def _host_hardware(host_id: int) -> dict:
    """The body of ``GET /api/hosts/{host_id}/hardware``."""
    record = await db.get_hardware_state(host_id) or {}
    collected = record.get("collected_at") or None
    if record.get("result") == hc.STATE_NOT_READ:
        status = hc.STATE_NOT_READ
    elif collected:
        status = hc.STATE_OK
    else:
        status = hc.STATE_NEVER
    message = record.get("message") or ("No hardware read yet." if status == hc.STATE_NEVER else "")
    return {
        "host_id": host_id,
        "collected_at": collected,
        "source": (record.get("source") or "") if collected else "",
        "state": status,
        "message": message,
        "components": [_component(r) for r in await db.list_host_hardware(host_id)],
    }


@router.get("/api/hosts/{host_id}/hardware")
@scoped("host")
async def host_hardware(host_id: int, request: Request) -> dict:
    """A host's components (removed ones too) and its collection state."""
    await require_host(request, host_id)
    return await _host_hardware(host_id)


@router.get("/api/hosts/{host_id}/hardware/events")
@scoped("host")
async def host_hardware_events(
    host_id: int,
    request: Request,
    event: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=LIMIT_MAX),
    offset: int = Query(default=0, ge=0, le=OFFSET_MAX),
) -> dict:
    """A host's hardware history, newest first; ``event`` one or more
    comma-separated event types."""
    await require_host(request, host_id)
    events = _choices(event, hc.EVENTS, "event")
    total, rows = await db.list_hardware_events(host_id=host_id, events=events, limit=limit, offset=offset)
    readable = await readable_host_ids(request)
    return {"total": total, "events": [_event(r, readable) for r in rows]}


def _snmp_readers(ip_address: str, snmp_cfg: dict) -> tuple[Any, Any]:
    """The GET and capped walk of an on-demand read, with the poll's
    walk-complete rule (``health_checks.walk_complete``)."""

    async def get(oids: tuple[str, ...]) -> dict:
        values, _error = await _snmp_get_values(ip_address, _SNMP_TIMEOUT, snmp_cfg, oids)
        return values

    async def walk_table(oid: str, cap: int = health_checks.WALK_MAX_ROWS) -> tuple[dict, bool]:
        rows, error = await _snmp_walk(ip_address, _SNMP_TIMEOUT, snmp_cfg, oid, max_rows=cap, return_errors=True)
        return rows, health_checks.walk_complete(rows, error, cap)

    return get, walk_table


@router.post("/api/hosts/{host_id}/hardware/refresh")
@scoped("host")
async def refresh_host_hardware(host_id: int, request: Request) -> dict:
    """Read a host's components over SNMP now, with its effective SNMP
    config (its own profile, else its group's), and store the read. The
    shared SNMP config goes only to a confirmed address unless an admin
    asks (as the SNMP test). 409 when SNMP is off for the host, its type is
    not read, or another read of it is being stored; 502 when the device
    did not answer the read completely."""
    host = await require_host(request, host_id, write=True)
    target_ip = str(host.get("ip_address") or "").strip()
    if not target_ip:
        raise HTTPException(409, "Host has no IP address")
    if not address_confirmed(host) and not await caller_is_admin(request):
        raise HTTPException(403, f"The hardware read cannot run: the host's {ADDRESS_AWAITING_CONFIRMATION}")
    if not hc.reads_hardware(host.get("device_type")):
        raise HTTPException(409, "Hardware components are not read over SNMP for this device type")
    snmp_cfg = state._resolve_host_snmp_config(host)
    if not PYSMNP_AVAILABLE or not snmp_cfg.get("enabled"):
        raise HTTPException(409, "SNMP is not enabled for this host (its own profile or its group's)")
    get, walk_table = _snmp_readers(target_ip, snmp_cfg)
    try:
        outcome = await hc.refresh_over_snmp(host, get, walk_table)
    except hc.HardwareReadBusy:
        raise HTTPException(409, "A hardware read of this host is already running. Try again when it finishes.")
    except Exception as exc:
        LOGGER.warning("hardware refresh failed for host_id=%s: %s", host_id, type(exc).__name__)
        raise HTTPException(502, "The hardware read failed - check SNMP credentials and connectivity.")
    await _audit(
        "inventory",
        "host.hardware_refresh",
        user=_session_user(request),
        detail=f"host_id={host_id} state={outcome.get('state')} events={len(outcome.get('new_events') or [])}",
        correlation_id=_corr_id(request),
    )
    if not outcome.get("answered"):
        raise HTTPException(
            502,
            "The device did not answer the hardware read over SNMP completely "
            "(no response, bad credentials, or the walk timed out); nothing was changed.",
        )
    body = await _host_hardware(host_id)
    readable = await readable_host_ids(request)
    body["new_events"] = [_event(e, readable) for e in outcome.get("new_events") or []]
    return body


async def _component_rows(
    request: Request,
    search: str | None,
    category: str | None,
    status: str | None,
    group_id: int | None,
    limit: int,
    offset: int,
) -> tuple[int, list[dict]]:
    return await db.list_hardware_components(
        search=search,
        categories=_choices(category, hc.CATEGORIES, "category"),
        statuses=_choices(status, hc.STATUSES, "status"),
        group_id=group_id,
        host_ids=await readable_host_ids(request),
        limit=limit,
        offset=offset,
    )


@router.get("/api/hardware/components")
@scoped("list")
async def list_components(
    request: Request,
    search: str | None = Query(default=None, max_length=200),
    category: str | None = Query(default=None, max_length=200),
    status: str | None = Query(default=None, max_length=200),
    group_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=LIMIT_MAX),
    offset: int = Query(default=0, ge=0, le=OFFSET_MAX),
) -> dict:
    """Every component of the caller's hosts matching the filters
    (``search``: a substring of the serial, model, name, slot or hostname)."""
    total, rows = await _component_rows(request, search, category, status, group_id, limit, offset)
    return {"total": total, "components": [_component(r) for r in rows]}


_CSV_COLUMNS: tuple[tuple[str, str], ...] = (
    ("Hostname", "hostname"),
    ("Category", "category"),
    ("Slot", "slot"),
    ("Name", "name"),
    ("Description", "description"),
    ("Model", "model"),
    ("Serial", "serial"),
    ("Hardware Rev", "hardware_rev"),
    ("Firmware Rev", "firmware_rev"),
    ("Software Rev", "software_rev"),
    ("Status", "status"),
    ("Source", "source"),
    ("First Seen", "first_seen"),
    ("Last Seen", "last_seen"),
    ("Removed At", "removed_at"),
)


@router.get("/api/hardware/components/export")
@scoped("list")
async def export_components_csv(
    request: Request,
    search: str | None = Query(default=None, max_length=200),
    category: str | None = Query(default=None, max_length=200),
    status: str | None = Query(default=None, max_length=200),
    group_id: int | None = None,
) -> Response:
    """The components of ``GET /api/hardware/components`` as CSV (up to
    ``EXPORT_MAX_ROWS``); device text is guarded against spreadsheet
    formulas."""
    _total, rows = await _component_rows(request, search, category, status, group_id, EXPORT_MAX_ROWS, 0)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([header for header, _ in _CSV_COLUMNS])
    for row in rows:
        writer.writerow([csv_text_cell(row.get(key)) for _, key in _CSV_COLUMNS])
    return _csv_download_response(output.getvalue(), "hardware_components.csv")


@router.get("/api/hardware/events")
@scoped("list")
async def list_events(
    request: Request,
    search: str | None = Query(default=None, max_length=200),
    event: str | None = Query(default=None, max_length=200),
    host_id: int | None = None,
    category: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=LIMIT_MAX),
    offset: int = Query(default=0, ge=0, le=OFFSET_MAX),
) -> dict:
    """The hardware history of the caller's hosts, newest first: ``event``
    one or more comma-separated event types, ``search`` a substring of the
    serial, previous serial, model, hostname or slot."""
    readable = await readable_host_ids(request)
    if host_id is not None and readable is not None and host_id not in readable:
        raise HTTPException(status_code=404, detail=HOST_NOT_FOUND)
    total, rows = await db.list_hardware_events(
        search=search,
        events=_choices(event, hc.EVENTS, "event"),
        categories=_choices(category, hc.CATEGORIES, "category"),
        host_id=host_id,
        host_ids=readable,
        limit=limit,
        offset=offset,
    )
    return {"total": total, "events": [_event(r, readable) for r in rows]}
