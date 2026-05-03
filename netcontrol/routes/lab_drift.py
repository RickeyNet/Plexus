"""
lab_drift.py — Phase B-3a: drift-from-twin checks.

The unique closed-loop value of a digital twin is that operators validate
changes against a known-good baseline before pushing to production. That
guarantee silently breaks when the production device's running config
drifts away from the snapshot the twin holds — emergency CLI changes,
vendor support tweaks, another team's automation. This module compares
each twin's snapshot to the latest production config snapshot of the host
it was cloned from, on demand and on a configurable schedule.

We deliberately do NOT capture live config from the production device
here. The existing config_backups / config_snapshots subsystem already
handles capture; we just diff against whatever it stored most recently.
That keeps drift checking cheap (no SSH per tick), respects the existing
backup cadence, and avoids hammering devices that already get polled.

Status values written to lab_drift_runs:
  - in_sync         — twin matches production snapshot byte-for-byte
                      (after volatile-line normalization)
  - drifted         — diff is non-empty
  - missing_source  — lab device has no source_host_id, or no production
                      snapshot exists yet for that host
  - error           — diff/eval blew up; never raised, only persisted
"""
from __future__ import annotations

import asyncio
import os

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from netcontrol.routes.lab import (
    _resolve_session_user,
    _user_can_access_env,
)
from netcontrol.routes.shared import (
    _audit,
    _compute_config_diff,
    _corr_id,
)
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.lab_drift")

# Default scheduler cadence: every hour. Operators tune via env vars.
DEFAULT_DRIFT_INTERVAL_SECONDS = 60 * 60


def _drift_enabled() -> bool:
    raw = os.getenv("PLEXUS_LAB_DRIFT_ENABLED", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    return True


def _drift_interval_seconds() -> int:
    raw = os.getenv("PLEXUS_LAB_DRIFT_INTERVAL_SECONDS")
    if not raw:
        return DEFAULT_DRIFT_INTERVAL_SECONDS
    try:
        return max(60, int(raw))
    except ValueError:
        return DEFAULT_DRIFT_INTERVAL_SECONDS


# ── Models ──────────────────────────────────────────────────────────────────


class DriftCheckRequest(BaseModel):
    pass  # body is currently empty; reserved for future per-check overrides


# ── Core check (also used by the scheduler) ─────────────────────────────────


async def run_drift_check_for_device(
    device: dict,
    *,
    actor: str = "",
) -> dict:
    """Compare a twin's snapshot to its source host's most recent prod
    config snapshot. Persist a lab_drift_runs row and return a summary.

    Errors are caught and persisted as status='error' so the scheduler
    can keep walking the rest of the eligible devices.
    """
    source_host_id = device.get("source_host_id")
    twin_config = device.get("running_config", "") or ""
    if not source_host_id:
        run_id = await db.create_lab_drift_run(
            lab_device_id=device["id"],
            source_host_id=None,
            status="missing_source",
            twin_bytes=len(twin_config),
            actor=actor,
            error="Twin has no source_host_id; nothing to compare against.",
        )
        return {
            "id": run_id,
            "status": "missing_source",
            "diff_added": 0,
            "diff_removed": 0,
        }

    try:
        snapshot = await db.get_latest_config_snapshot(int(source_host_id))
    except Exception as exc:  # db error
        run_id = await db.create_lab_drift_run(
            lab_device_id=device["id"],
            source_host_id=int(source_host_id),
            status="error",
            twin_bytes=len(twin_config),
            actor=actor,
            error=f"Failed to fetch source snapshot: {exc}",
        )
        return {"id": run_id, "status": "error", "diff_added": 0, "diff_removed": 0}

    if not snapshot or not snapshot.get("config_text"):
        run_id = await db.create_lab_drift_run(
            lab_device_id=device["id"],
            source_host_id=int(source_host_id),
            status="missing_source",
            twin_bytes=len(twin_config),
            actor=actor,
            error="Source host has no captured config snapshot yet.",
        )
        return {
            "id": run_id,
            "status": "missing_source",
            "diff_added": 0,
            "diff_removed": 0,
        }

    prod_config = snapshot["config_text"] or ""
    try:
        diff_text, diff_added, diff_removed = _compute_config_diff(
            twin_config, prod_config,
            baseline_label="twin", actual_label="production",
        )
    except Exception as exc:
        run_id = await db.create_lab_drift_run(
            lab_device_id=device["id"],
            source_host_id=int(source_host_id),
            status="error",
            twin_bytes=len(twin_config),
            prod_bytes=len(prod_config),
            actor=actor,
            error=f"diff failed: {exc}",
        )
        return {"id": run_id, "status": "error", "diff_added": 0, "diff_removed": 0}

    status = "drifted" if (diff_added or diff_removed) else "in_sync"
    run_id = await db.create_lab_drift_run(
        lab_device_id=device["id"],
        source_host_id=int(source_host_id),
        status=status,
        diff_text=diff_text[:50_000],  # cap to avoid runaway storage
        diff_added=diff_added,
        diff_removed=diff_removed,
        twin_bytes=len(twin_config),
        prod_bytes=len(prod_config),
        actor=actor,
    )
    return {
        "id": run_id,
        "status": status,
        "diff_added": diff_added,
        "diff_removed": diff_removed,
    }


async def run_drift_check_all(*, actor: str = "system-scheduler") -> dict:
    """Walk every drift-eligible lab device and run a check on each."""
    summary = {"checked": 0, "drifted": 0, "in_sync": 0, "missing_source": 0, "errors": 0}
    try:
        rows = await db.list_drift_eligible_devices()
    except Exception as exc:
        LOGGER.warning("drift sweep: failed to query devices: %s", exc)
        return summary
    for row in rows:
        device = await db.get_lab_device(row["id"])
        if not device:
            continue
        summary["checked"] += 1
        try:
            result = await run_drift_check_for_device(device, actor=actor)
        except Exception as exc:
            summary["errors"] += 1
            LOGGER.warning("drift check failed for device %s: %s", row["id"], exc)
            continue
        st = result.get("status")
        if st == "drifted":
            summary["drifted"] += 1
        elif st == "in_sync":
            summary["in_sync"] += 1
        elif st == "missing_source":
            summary["missing_source"] += 1
        elif st == "error":
            summary["errors"] += 1
    return summary


async def lab_drift_scheduler_loop() -> None:
    """Background loop driven by PLEXUS_LAB_DRIFT_INTERVAL_SECONDS.

    Skips a tick when PLEXUS_LAB_DRIFT_ENABLED is falsy. Cadence is
    re-read each iteration so an operator can change the interval at
    runtime without restarting Plexus.
    """
    while True:
        interval = _drift_interval_seconds()
        await asyncio.sleep(interval)
        if not _drift_enabled():
            continue
        try:
            summary = await run_drift_check_all()
            if summary.get("checked"):
                LOGGER.info(
                    "drift sweep: checked=%d in_sync=%d drifted=%d missing=%d errors=%d",
                    summary.get("checked", 0),
                    summary.get("in_sync", 0),
                    summary.get("drifted", 0),
                    summary.get("missing_source", 0),
                    summary.get("errors", 0),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("drift scheduler iteration failed: %s", exc)


# ── HTTP API ────────────────────────────────────────────────────────────────


async def _get_device_or_403(device_id: int, request: Request) -> tuple[dict, dict | None]:
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return device, session


@router.post("/api/lab/devices/{device_id}/drift/check")
async def drift_check_endpoint(device_id: int, request: Request):
    """Run an on-demand drift check against the source host's latest snapshot."""
    device, session = await _get_device_or_403(device_id, request)
    actor = session["user"] if session else ""
    result = await run_drift_check_for_device(device, actor=actor)
    await _audit(
        "lab", "drift.check",
        user=actor,
        detail=f"device={device_id} status={result['status']} +{result['diff_added']}/-{result['diff_removed']}",
        correlation_id=_corr_id(request),
    )
    return result


@router.get("/api/lab/devices/{device_id}/drift/runs")
async def list_drift_runs_endpoint(device_id: int, request: Request, limit: int = 50):
    device, _ = await _get_device_or_403(device_id, request)
    return await db.list_lab_drift_runs(device["id"], limit=max(1, min(500, limit)))


@router.get("/api/lab/devices/{device_id}/drift/latest")
async def latest_drift_run_endpoint(device_id: int, request: Request):
    device, _ = await _get_device_or_403(device_id, request)
    latest = await db.get_latest_lab_drift_run(device["id"])
    return latest or {"status": "never_checked"}


@router.get("/api/lab/drift/runs/{run_id}")
async def get_drift_run_endpoint(run_id: int, request: Request):
    run = await db.get_lab_drift_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Drift run not found")
    # Authorize via the lab device → environment chain.
    device = await db.get_lab_device(run["lab_device_id"])
    env = await db.get_lab_environment(device["environment_id"]) if device else None
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return run
