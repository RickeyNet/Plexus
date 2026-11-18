"""
maintenance_windows.py -- Maintenance window CRUD and the change-gate
predicate used by deployment / change endpoints.

Windows define when production changes are allowed. Each window has a
``policy``:

* ``allow_changes`` -- this window explicitly *permits* changes during
  the period (overrides any blocking window).
* ``block_outside_window`` -- if the window applies to the target and we
  are not inside the window, the change is blocked.
* ``warn_outside_window`` -- like block, but emits a warning instead of
  rejecting (caller decides what to do with the warning).

A window applies to a target group if its ``maintenance_window_scopes``
includes that group, or if the window has no scope rows (global).

Object scope (model ``maintenance_window``): an account limited to selected
inventory groups sees the global windows and those covering a readable
group (with only its readable groups listed), and creates, changes or
deletes a window only when every group it covers is writable; global
windows are changed by unrestricted callers only.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from netcontrol.object_scope import (
    READ_ONLY_DETAIL,
    WRITE_SCOPE_DETAIL,
    ObjectScope,
    ScopeModel,
    filter_rows,
    register_model,
    request_scope,
    require_group,
    require_row,
    scoped,
)
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.maintenance_windows")

_WINDOW_NOT_FOUND = "Maintenance window not found"
# A window is placed by the inventory groups it covers (``group_ids``); a
# window covering no group is global (shared).
register_model(
    ScopeModel(
        "maintenance_window",
        {"group": "group_ids"},
        shared=True,
        not_found=_WINDOW_NOT_FOUND,
        description="Maintenance windows (by the inventory groups they cover; none: global)",
    )
)


def _visible_groups(scope: ObjectScope, window: dict) -> dict:
    """``window`` with only the groups the caller may read listed."""
    if scope.unrestricted:
        return window
    window["group_ids"] = [g for g in window.get("group_ids") or [] if scope.can_read_group(g)]
    if "scopes" in window:
        window["scopes"] = [sc for sc in window["scopes"] or [] if scope.can_read_group(sc.get("group_id"))]
    return window


async def _require_groups_writable(request: Request, group_ids: list[int] | None, *, detail: str) -> None:
    """For a scoped caller: 403 ``detail`` unless every group is writable;
    a window covering no group is global (unrestricted callers only)."""
    scope = await request_scope(request)
    if scope.unrestricted:
        return
    if not group_ids or not all(scope.can_write_group(g) for g in group_ids):
        raise HTTPException(status_code=403, detail=detail)


# ── Models ────────────────────────────────────────────────────────────────────


class MaintenanceWindowCreate(BaseModel):
    name: str
    description: str = ""
    start_at: str  # ISO 8601, UTC recommended
    end_at: str
    recurrence: str = "none"  # 'none' | 'daily' | 'weekly'
    weekday_mask: int = 0  # bit 0 = Mon ... bit 6 = Sun (only for weekly)
    policy: str = "block_outside_window"
    enabled: bool = True
    group_ids: list[int] = Field(default_factory=list)


class MaintenanceWindowUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    start_at: str | None = None
    end_at: str | None = None
    recurrence: str | None = None
    weekday_mask: int | None = None
    policy: str | None = None
    enabled: bool | None = None
    group_ids: list[int] | None = None


# ── Time logic (pure, no DB) ──────────────────────────────────────────────────


def _parse_iso(value: str) -> datetime:
    """Parse an ISO 8601 timestamp. Naive values are treated as UTC."""
    if not value:
        raise ValueError("empty timestamp")
    # Python's fromisoformat accepts 'Z' only from 3.11+; normalize.
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def window_is_active(window: dict, now: datetime | None = None) -> bool:
    """True if `window` is currently in effect.

    For ``recurrence='none'``: exact start_at..end_at.
    For ``daily``: every day between start_at date and end_at date the
    time-of-day band repeats. (end_at < start_at means the band crosses
    midnight; we wrap.)
    For ``weekly``: same as daily but only on weekdays whose bit in
    ``weekday_mask`` is set.

    Disabled windows always return False.
    """
    # A NULL enabled column means enabled; dict-default alone would treat
    # None as disabled (the default only applies when the key is missing).
    enabled = window.get("enabled")
    if enabled is not None and not enabled:
        return False
    now = now or datetime.now(UTC)
    start = _parse_iso(window["start_at"])
    end = _parse_iso(window["end_at"])
    recurrence = (window.get("recurrence") or "none").lower()

    if recurrence == "none":
        return start <= now <= end

    if now < start:
        # Recurrence hasn't begun yet.
        return False

    # Daily/weekly: derive today's band based on start_at's time-of-day
    # and the duration end-start.
    duration = end - start
    if duration <= timedelta(0):
        # Crosses midnight: e.g. start=22:00, end=02:00 next day on the
        # same calendar marker. Treat duration as (end + 1d) - start.
        duration = duration + timedelta(days=1)

    today_band_start = now.replace(
        hour=start.hour,
        minute=start.minute,
        second=start.second,
        microsecond=start.microsecond,
    )
    yday_band_start = today_band_start - timedelta(days=1)

    candidates: list[datetime] = []
    if recurrence == "daily":
        candidates = [yday_band_start, today_band_start]
    elif recurrence == "weekly":
        mask = int(window.get("weekday_mask") or 0)
        if mask == 0:
            return False
        if _weekday_bit_set(mask, yday_band_start.weekday()):
            candidates.append(yday_band_start)
        if _weekday_bit_set(mask, today_band_start.weekday()):
            candidates.append(today_band_start)
    else:
        return False

    for band_start in candidates:
        if band_start <= now <= band_start + duration:
            return True
    return False


def _weekday_bit_set(mask: int, weekday: int) -> bool:
    """weekday is Python's Mon=0..Sun=6 - same as our bit layout."""
    return bool(mask & (1 << weekday))


# ── Gate predicate ────────────────────────────────────────────────────────────


async def evaluate_change_gate(group_ids: list[int]) -> dict:
    """Look at all enabled windows that cover the given group ids and
    return a verdict::

        {
            "allowed": bool,
            "reason": "",                 # human-readable when not allowed
            "policy": "...",              # the deciding window's policy
            "window": {...} | None,       # the deciding window
            "warning": "" | "...",        # set when policy=warn_outside_window
        }

    Decision precedence:

    1. If any *active* window with policy ``allow_changes`` applies,
       allow.
    2. Else if any *active* window with policy ``block_outside_window``
       applies, allow. (We are inside a maintenance window - the right
       time to change.)
    3. Else if any *inactive-but-relevant* window with policy
       ``block_outside_window`` applies, **block**.
    4. Else if any inactive window with policy ``warn_outside_window``
       applies, allow with a warning.
    5. Else allow with no warning.
    """
    windows = await db.get_windows_for_groups(group_ids)
    if not windows:
        return {"allowed": True, "reason": "", "policy": "", "window": None, "warning": ""}

    now = datetime.now(UTC)
    active_allow = []
    active_block = []
    inactive_block = []
    inactive_warn = []
    for w in windows:
        active = window_is_active(w, now)
        policy = w.get("policy") or "block_outside_window"
        if active and policy == "allow_changes":
            active_allow.append(w)
        elif active and policy == "block_outside_window":
            active_block.append(w)
        elif not active and policy == "block_outside_window":
            inactive_block.append(w)
        elif not active and policy == "warn_outside_window":
            inactive_warn.append(w)

    if active_allow:
        return {"allowed": True, "reason": "", "policy": "allow_changes", "window": active_allow[0], "warning": ""}
    if active_block:
        return {
            "allowed": True,
            "reason": "",
            "policy": "block_outside_window",
            "window": active_block[0],
            "warning": "",
        }
    if inactive_block:
        w = inactive_block[0]
        return {
            "allowed": False,
            "reason": f"Blocked by maintenance window '{w['name']}' (next opens {w['start_at']})",
            "policy": "block_outside_window",
            "window": w,
            "warning": "",
        }
    if inactive_warn:
        w = inactive_warn[0]
        return {
            "allowed": True,
            "reason": "",
            "policy": "warn_outside_window",
            "window": w,
            "warning": f"Change is outside maintenance window '{w['name']}'",
        }
    return {"allowed": True, "reason": "", "policy": "", "window": None, "warning": ""}


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/api/maintenance-windows")
@scoped("list")
async def list_windows(request: Request):
    scope = await request_scope(request)
    windows = [
        _visible_groups(scope, w)
        for w in await filter_rows("maintenance_window", await db.list_maintenance_windows(), scope)
    ]
    now = datetime.now(UTC)
    for w in windows:
        try:
            w["is_active"] = window_is_active(w, now)
        except Exception:
            w["is_active"] = False
    return windows


@router.get("/api/maintenance-windows/{window_id}")
@scoped("maintenance_window")
async def get_window(window_id: int, request: Request):
    window = await require_row(request, "maintenance_window", await db.get_maintenance_window(window_id))
    _visible_groups(await request_scope(request), window)
    try:
        window["is_active"] = window_is_active(window)
    except Exception:
        window["is_active"] = False
    return window


@router.post("/api/maintenance-windows", status_code=201)
@scoped("create")
async def create_window(body: MaintenanceWindowCreate, request: Request):
    await _require_groups_writable(request, body.group_ids, detail=WRITE_SCOPE_DETAIL)
    # Validate timestamps and policy up front so we surface 400 not 500.
    try:
        start = _parse_iso(body.start_at)
        end = _parse_iso(body.end_at)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid timestamp: {exc}") from exc
    if body.recurrence == "none" and end <= start:
        raise HTTPException(status_code=400, detail="end_at must be after start_at")
    if body.policy not in db.VALID_WINDOW_POLICY:
        raise HTTPException(status_code=400, detail=f"invalid policy '{body.policy}'")
    if body.recurrence not in db.VALID_RECURRENCE:
        raise HTTPException(status_code=400, detail=f"invalid recurrence '{body.recurrence}'")
    if body.recurrence == "weekly" and (body.weekday_mask & 0x7F) == 0:
        raise HTTPException(status_code=400, detail="weekly recurrence requires weekday_mask != 0")

    session = _get_session(request)
    user = session["user"] if session else ""
    window_id = await db.create_maintenance_window(
        name=body.name,
        description=body.description,
        start_at=body.start_at,
        end_at=body.end_at,
        recurrence=body.recurrence,
        weekday_mask=body.weekday_mask,
        policy=body.policy,
        enabled=body.enabled,
        created_by=user,
        group_ids=body.group_ids,
    )
    await _audit(
        "maintenance-windows",
        "window.created",
        user=user,
        detail=f"id={window_id} name={body.name} policy={body.policy}",
        correlation_id=_corr_id(request),
    )
    return {"id": window_id}


@router.put("/api/maintenance-windows/{window_id}")
@scoped("maintenance_window")
async def update_window(window_id: int, body: MaintenanceWindowUpdate, request: Request):
    existing = await require_row(request, "maintenance_window", await db.get_maintenance_window(window_id))
    await _require_groups_writable(request, existing.get("group_ids"), detail=READ_ONLY_DETAIL)
    if body.group_ids is not None:
        await _require_groups_writable(request, body.group_ids, detail=WRITE_SCOPE_DETAIL)
    try:
        await db.update_maintenance_window(
            window_id,
            name=body.name,
            description=body.description,
            start_at=body.start_at,
            end_at=body.end_at,
            recurrence=body.recurrence,
            weekday_mask=body.weekday_mask,
            policy=body.policy,
            enabled=body.enabled,
            group_ids=body.group_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    session = _get_session(request)
    await _audit(
        "maintenance-windows",
        "window.updated",
        user=session["user"] if session else "",
        detail=f"id={window_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/maintenance-windows/{window_id}")
@scoped("maintenance_window")
async def delete_window(window_id: int, request: Request):
    existing = await require_row(request, "maintenance_window", await db.get_maintenance_window(window_id))
    await _require_groups_writable(request, existing.get("group_ids"), detail=READ_ONLY_DETAIL)
    await db.delete_maintenance_window(window_id)
    session = _get_session(request)
    await _audit(
        "maintenance-windows",
        "window.deleted",
        user=session["user"] if session else "",
        detail=f"id={window_id} name={existing.get('name', '')}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/maintenance-windows/check")
@scoped("groups")
async def check_window_gate(payload: dict, request: Request):
    """Frontend preview: given group_ids, what's the current verdict? (A
    scoped caller: every group must be readable.)"""
    group_ids = payload.get("group_ids") or []
    if not isinstance(group_ids, list):
        raise HTTPException(status_code=400, detail="group_ids must be a list")
    if (await request_scope(request)).restricted:
        for gid in group_ids:
            await require_group(request, int(gid))
    verdict = await evaluate_change_gate([int(g) for g in group_ids])
    return verdict
