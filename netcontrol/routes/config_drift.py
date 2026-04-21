"""
config_drift.py -- Config drift detection routes: baselines, snapshots, drift events, revert, analysis.
"""
from __future__ import annotations


import asyncio
import uuid
from datetime import UTC, datetime

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.routes.shared import (
    _audit,
    _capture_running_config,
    _compute_config_diff,
    _corr_id,
    _get_session,
    _push_config_to_device,
)
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.config_drift")

router = APIRouter()
ws_router = APIRouter()  # WebSocket routes — registered without HTTP auth dependency

# ── Late-binding auth dependencies ────────────────────────────────────────────

_require_auth = None
_require_feature = None
_require_admin = None
_verify_session_token = None
_get_user_features = None


def init_config_drift(require_auth_fn, require_feature_fn, require_admin_fn,
                      verify_session_token_fn, get_user_features_fn):
    global _require_auth, _require_feature, _require_admin
    global _verify_session_token, _get_user_features
    _require_auth = require_auth_fn
    _require_feature = require_feature_fn
    _require_admin = require_admin_fn
    _verify_session_token = verify_session_token_fn
    _get_user_features = get_user_features_fn


# ── Pydantic Models ──────────────────────────────────────────────────────────

class ConfigBaselineCreate(BaseModel):
    host_id: int
    name: str = ""
    config_text: str
    source: str = "manual"


class ConfigBaselineUpdate(BaseModel):
    name: str | None = None
    config_text: str | None = None
    source: str | None = None


class ConfigDriftStatusUpdate(BaseModel):
    status: str  # "resolved" or "accepted"


class ConfigSnapshotCaptureRequest(BaseModel):
    host_id: int
    credential_id: int


class ConfigGroupCaptureRequest(BaseModel):
    group_id: int
    credential_id: int


class ConfigDriftAnalyzeRequest(BaseModel):
    host_id: int


class ConfigDriftAnalyzeGroupRequest(BaseModel):
    group_id: int


class ConfigDriftCheckRequest(BaseModel):
    host_id: int
    credential_id: int


class ConfigDriftBulkAcceptRequest(BaseModel):
    event_ids: list[int]


class ConfigDriftRevertRequest(BaseModel):
    event_id: int
    credential_id: int


# ── Module-level state ────────────────────────────────────────────────────────

# Config capture job state (in-memory)
# capture_job_id -> {job_id, status, started_at, finished_at, output_lines}
_capture_jobs: dict[str, dict] = {}
_capture_job_sockets: dict[str, list] = {}

_revert_jobs: dict[str, dict] = {}
_revert_job_sockets: dict[str, list] = {}

_capture_jobs_lock = asyncio.Lock()
_revert_jobs_lock = asyncio.Lock()

_capture_sockets_lock = asyncio.Lock()
_revert_sockets_lock = asyncio.Lock()


# ── Helpers ──────────────────────────────────────────────────────────────────

_MAX_OUTPUT_LINES = 10_000
_MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # 10 MB cap on revert output string


async def _broadcast_capture_line(job_id: str, text: str) -> None:
    """Send a text line to all WebSocket subscribers of a capture job."""
    job = _capture_jobs.get(job_id)
    if job:
        if len(job["output_lines"]) < _MAX_OUTPUT_LINES:
            job["output_lines"].append(text)
        elif len(job["output_lines"]) == _MAX_OUTPUT_LINES:
            job["output_lines"].append("[output truncated at 10k lines]\n")
    async with _capture_sockets_lock:
        sockets = list(_capture_job_sockets.get(job_id, []))
    dead = []
    for ws in sockets:
        try:
            await asyncio.wait_for(ws.send_json({"type": "line", "text": text}), timeout=5)
        except Exception:
            LOGGER.debug("capture broadcast: dropping dead WS for job %s", job_id)
            dead.append(ws)
    if dead:
        async with _capture_sockets_lock:
            for ws in dead:
                try:
                    _capture_job_sockets[job_id].remove(ws)
                except (ValueError, KeyError):
                    pass


async def _finish_capture_job(job_id: str, status: str) -> None:
    """Mark a capture job done, notify all WebSocket subscribers."""
    job = _capture_jobs.get(job_id)
    if job:
        job["status"] = status
        job["finished_at"] = datetime.now(UTC).isoformat()
    done_msg = {"type": "job_complete", "job_id": job_id, "status": status}
    async with _capture_sockets_lock:
        sockets = _capture_job_sockets.pop(job_id, [])
    for ws in sockets:
        try:
            await asyncio.wait_for(ws.send_json(done_msg), timeout=5)
        except Exception:
            LOGGER.debug("capture finish: dropping dead WS for job %s", job_id)
    # Schedule cleanup of in-memory job state after 5 minutes
    async def _deferred_capture_cleanup() -> None:
        await asyncio.sleep(300)
        async with _capture_jobs_lock:
            _capture_jobs.pop(job_id, None)
    asyncio.ensure_future(_deferred_capture_cleanup())


async def _run_config_capture_job(
    job_id: str,
    hosts: list[dict],
    credentials: dict,
    user: str,
) -> None:
    """Background task: capture running-config from hosts, streaming progress."""
    total = len(hosts)
    ok_count = 0
    fail_count = 0

    await _broadcast_capture_line(job_id,
        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Starting config capture for {total} host(s)...\n")

    sem = asyncio.Semaphore(4)

    captured_host_ids = []

    async def _capture_one(idx: int, h: dict):
        nonlocal ok_count, fail_count
        hostname = h.get("hostname", h.get("ip_address", "unknown"))
        ip = h.get("ip_address", "")
        async with sem:
            await _broadcast_capture_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ({idx}/{total}) Connecting to {hostname} ({ip})...\n")
            try:
                config_text = await _capture_running_config(h, credentials)
                sid = await db.create_config_snapshot(
                    host_id=h["id"], config_text=config_text, capture_method="manual",
                )
                ok_count += 1
                captured_host_ids.append(h["id"])
                # Auto-set baseline if none exists for this host
                baseline = await db.get_config_baseline_for_host(h["id"])
                if not baseline:
                    await db.create_config_baseline(
                        host_id=h["id"],
                        name=f"{hostname} baseline",
                        config_text=config_text,
                        source="auto-capture",
                        created_by=user,
                    )
                    await _broadcast_capture_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ({idx}/{total}) \u2713 {hostname} \u2014 captured ({len(config_text)} chars, snapshot #{sid}) [baseline set]\n")
                else:
                    await _broadcast_capture_line(job_id,
                        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ({idx}/{total}) \u2713 {hostname} \u2014 captured ({len(config_text)} chars, snapshot #{sid})\n")
            except Exception as exc:
                fail_count += 1
                await _broadcast_capture_line(job_id,
                    f"[{datetime.now(UTC).strftime('%H:%M:%S')}] ({idx}/{total}) \u2717 {hostname} \u2014 FAILED: {exc}\n")

    tasks = [asyncio.create_task(_capture_one(i + 1, h)) for i, h in enumerate(hosts)]
    await asyncio.gather(*tasks)

    await _broadcast_capture_line(job_id,
        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Capture complete: {ok_count} succeeded, {fail_count} failed out of {total} host(s).\n")

    # Run drift analysis for each successfully captured host
    if captured_host_ids:
        await _broadcast_capture_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Running drift analysis...\n")
        drift_count = 0
        compliant_count = 0
        skip_count = 0
        for hid in captured_host_ids:
            try:
                result = await _analyze_drift_for_host(hid)
                if result.get("diff_summary") == "No baseline set":
                    skip_count += 1
                elif result.get("drifted"):
                    drift_count += 1
                else:
                    compliant_count += 1
            except Exception as exc:
                LOGGER.error("config-drift: analysis failed for host %s: %s", hid, exc)
        await _broadcast_capture_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Analysis complete: {compliant_count} compliant, {drift_count} drifted, {skip_count} skipped (no baseline).\n")

    status = "completed" if fail_count == 0 else ("partial" if ok_count > 0 else "failed")
    await _finish_capture_job(job_id, status)


async def _analyze_drift_for_host(host_id: int) -> dict:
    """Compare latest snapshot vs baseline for a single host.

    Returns {drifted: bool, event_id: int|None, diff_summary: str}.
    """
    baseline = await db.get_config_baseline_for_host(host_id)
    if not baseline:
        return {"drifted": False, "event_id": None, "diff_summary": "No baseline set"}
    snapshot = await db.get_latest_config_snapshot(host_id)
    if not snapshot:
        return {"drifted": False, "event_id": None, "diff_summary": "No snapshot available"}

    diff_text, added, removed = _compute_config_diff(
        baseline["config_text"], snapshot["config_text"],
        baseline_label="baseline", actual_label="running-config",
    )
    if not diff_text:
        return {"drifted": False, "event_id": None, "diff_summary": "In compliance"}

    event_id = await db.create_config_drift_event(
        host_id=host_id,
        snapshot_id=snapshot["id"],
        baseline_id=baseline["id"],
        diff_text=diff_text,
        diff_lines_added=added,
        diff_lines_removed=removed,
    )
    await db.create_config_drift_event_history(
        event_id=event_id,
        host_id=host_id,
        action="detected",
        from_status="",
        to_status="open",
        actor="system",
        details=f"+{added} -{removed} lines changed",
    )
    return {
        "drifted": True,
        "event_id": event_id,
        "diff_summary": f"+{added} -{removed} lines changed",
    }


async def _broadcast_revert_line(job_id: str, line: str):
    job = _revert_jobs[job_id]
    if len(job["output"]) < _MAX_OUTPUT_SIZE:
        job["output"] += line
    elif not job["output"].endswith("[output truncated]\n"):
        job["output"] += "[output truncated]\n"
    async with _revert_sockets_lock:
        sockets = list(_revert_job_sockets.get(job_id, []))
    dead = []
    for ws in sockets:
        try:
            await asyncio.wait_for(ws.send_json({"type": "line", "data": line}), timeout=5)
        except Exception:
            LOGGER.debug("revert broadcast: dropping dead WS for job %s", job_id)
            dead.append(ws)
    if dead:
        async with _revert_sockets_lock:
            for ws in dead:
                try:
                    _revert_job_sockets[job_id].remove(ws)
                except (ValueError, KeyError):
                    pass


async def _finish_revert_job(job_id: str, status: str = "completed"):
    _revert_jobs[job_id]["status"] = status
    async with _revert_sockets_lock:
        sockets = _revert_job_sockets.pop(job_id, [])
    for ws in sockets:
        try:
            await asyncio.wait_for(ws.send_json({"type": "job_complete", "status": status}), timeout=5)
        except Exception:
            LOGGER.debug("revert finish: dropping dead WS for job %s", job_id)
    # Schedule cleanup of in-memory job state after 5 minutes
    async def _deferred_revert_cleanup() -> None:
        await asyncio.sleep(300)
        async with _revert_jobs_lock:
            _revert_jobs.pop(job_id, None)
    asyncio.ensure_future(_deferred_revert_cleanup())


def _build_revert_commands(diff_text: str, baseline_text: str = "") -> list[str]:
    """Parse a unified diff and build the minimal set of config commands to revert drift.

    In the diff (baseline -> running-config):
      - Lines starting with '-' (not '---') = in baseline but missing from device -> re-add them
      - Lines starting with '+' (not '+++') = on device but not in baseline -> negate with 'no' prefix

    Context lines (unchanged, starting with ' ') are tracked so that indented
    sub-commands are emitted inside their correct config section (e.g.
    'interface GigabitEthernet0/1').  The optional *baseline_text* provides a
    fallback section lookup when the diff context window is too small.
    """
    # Build a section map from baseline text: indented line -> parent section header
    _section_map: dict[str, str] = {}
    if baseline_text:
        _cur = None
        for bline in baseline_text.splitlines():
            s = bline.strip()
            if not s or s.startswith("!") or s == "end":
                continue
            if not bline[0:1].isspace():
                _cur = bline.rstrip()
            elif _cur:
                _section_map[s] = _cur

    commands: list[str] = []
    current_section: str | None = None
    section_emitted = False

    def _ensure_section(cmd: str) -> None:
        """Emit the section header before an indented sub-command if needed."""
        nonlocal current_section, section_emitted
        if not (cmd and cmd[0].isspace()):
            return
        section = current_section or _section_map.get(cmd.strip())
        if section and not section_emitted:
            commands.append(section)
            section_emitted = True
            if not current_section:
                current_section = section

    for line in diff_text.splitlines():
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            current_section = None
            section_emitted = False
            continue

        # Context line -- track section headers for proper config hierarchy
        if line.startswith(" "):
            ctx = line[1:]  # strip the leading diff space
            if ctx and not ctx[0].isspace():
                current_section = ctx.rstrip()
                section_emitted = False
            continue

        if line.startswith("-"):
            # Missing from device -- re-add the baseline line
            cmd = line[1:]  # strip the leading '-'
            stripped = cmd.strip()
            if not stripped or stripped.startswith("!") or stripped == "end":
                continue
            if stripped.startswith("Building configuration") or stripped.startswith("Current configuration"):
                continue
            # A non-indented command is itself a section header
            if not cmd[0:1].isspace():
                current_section = cmd.rstrip()
                section_emitted = True  # the command itself enters the section
            else:
                _ensure_section(cmd)
            commands.append(cmd.rstrip())
        elif line.startswith("+"):
            # Present on device but not in baseline -- negate it
            cmd = line[1:]  # strip the leading '+'
            stripped = cmd.strip()
            if not stripped or stripped.startswith("!") or stripped == "end":
                continue
            if stripped.startswith("Building configuration") or stripped.startswith("Current configuration"):
                continue
            _ensure_section(cmd)
            # Add 'no' prefix to remove the line, preserving indentation
            indent = cmd[: len(cmd) - len(cmd.lstrip())]
            if stripped.startswith("no "):
                # "no ..." line was added -- removing it means re-adding without "no"
                commands.append(indent + stripped[3:])
            else:
                commands.append(indent + "no " + stripped)
    return commands


async def _run_revert_job(job_id: str, event: dict, host: dict, baseline: dict, credentials: dict, user: str):
    """Background task: push only the changed lines back to the device, then re-capture and re-analyze."""
    hostname = host.get("hostname", host["ip_address"])
    try:
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Analyzing diff for {hostname}...\n")

        diff_text = event.get("diff_text", "")
        config_lines = _build_revert_commands(diff_text, baseline.get("config_text", ""))

        if not config_lines:
            await _broadcast_revert_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] No config changes to revert.\n")
            await _finish_revert_job(job_id, "completed")
            return

        # Log what will be pushed
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {len(config_lines)} lines to revert (only changed lines, not full config):\n")
        for cmd in config_lines:
            await _broadcast_revert_line(job_id, f"  {cmd}\n")

        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Connecting to {hostname} ({host['ip_address']})...\n")

        output = await _push_config_to_device(host, credentials, config_lines)
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Config pushed successfully.\n")

        # Re-capture the running config to verify
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Re-capturing running config to verify...\n")
        new_config = await _capture_running_config(host, credentials)
        sid = await db.create_config_snapshot(
            host_id=host["id"],
            config_text=new_config,
            capture_method="post-revert",
        )
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Snapshot #{sid} captured ({len(new_config)} chars).\n")

        # Re-analyze drift
        result = await _analyze_drift_for_host(host["id"])
        if result.get("drifted"):
            await _broadcast_revert_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Warning: device still shows drift after revert.\n")
        else:
            await _broadcast_revert_line(job_id,
                f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Device is now compliant with baseline.\n")

        # Mark original event as resolved
        prev_status = event.get("status", "open")
        await db.update_config_drift_event_status(event["id"], "resolved", resolved_by=user)
        await db.create_config_drift_event_history(
            event_id=event["id"],
            host_id=event["host_id"],
            action="status_change",
            from_status=prev_status,
            to_status="resolved",
            actor=user,
            details="resolved after revert job completion",
        )
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Drift event marked as resolved.\n")

        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Revert complete.\n")
        await _finish_revert_job(job_id, "completed")
    except Exception as exc:
        LOGGER.error("config-drift revert failed for %s: %s", hostname, exc)
        try:
            await db.create_config_drift_event_history(
                event_id=event["id"],
                host_id=event["host_id"],
                action="revert_failed",
                from_status=event.get("status", ""),
                to_status=event.get("status", ""),
                actor=user,
                details="revert job failed; see server logs",
            )
        except Exception:
            pass
        await _broadcast_revert_line(job_id,
            f"[{datetime.now(UTC).strftime('%H:%M:%S')}] FAILED: {exc}\n")
        await _finish_revert_job(job_id, "failed")


# ── Background loops ─────────────────────────────────────────────────────────

async def _run_config_drift_check_once() -> dict:
    """Run drift analysis on all hosts that have baselines."""
    if not state.CONFIG_DRIFT_CHECK_CONFIG.get("enabled"):
        return {"enabled": False, "hosts_checked": 0, "drifted": 0, "errors": 0}

    baselines = await db.get_config_baselines()
    hosts_checked = 0
    drifted = 0
    errors = 0

    for bl in baselines:
        try:
            result = await _analyze_drift_for_host(bl["host_id"])
            hosts_checked += 1
            if result.get("drifted"):
                drifted += 1
        except Exception as exc:
            errors += 1
            LOGGER.warning("config drift check failed for host_id=%s: %s", bl["host_id"], exc)

    # Retention cleanup
    retention_days = int(state.CONFIG_DRIFT_CHECK_CONFIG.get(
        "snapshot_retention_days", state.CONFIG_DRIFT_CHECK_DEFAULTS["snapshot_retention_days"]))
    try:
        await db.delete_old_config_snapshots(retention_days)
        await db.delete_old_config_drift_events(retention_days)
    except Exception:
        pass

    if hosts_checked > 0:
        LOGGER.info("config drift check: checked %d hosts, %d drifted, %d errors",
                     hosts_checked, drifted, errors)
        increment_metric("config_drift.check.scheduled.success")

    return {
        "enabled": True,
        "hosts_checked": hosts_checked,
        "drifted": drifted,
        "errors": errors,
    }


async def _config_drift_check_loop() -> None:
    """Infinite loop that runs drift checks at configurable intervals."""
    while True:
        try:
            await asyncio.sleep(int(state.CONFIG_DRIFT_CHECK_CONFIG.get(
                "interval_seconds", state.CONFIG_DRIFT_CHECK_DEFAULTS["interval_seconds"])))
            await _run_config_drift_check_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("config drift check loop failure: %s", redact_value(str(exc)))
            increment_metric("config_drift.check.scheduled.failed")
            await asyncio.sleep(state.CONFIG_DRIFT_CHECK_DEFAULTS["interval_seconds"])


# ── Routes: Baselines ────────────────────────────────────────────────────────

def _drift_deps():
    return [Depends(_require_auth), Depends(_require_feature("config-drift"))]


@router.get("/api/config-drift/baselines")
async def list_config_baselines(host_id: int | None = Query(default=None)):
    """List config baselines, optionally filtered by host."""
    try:
        return await db.get_config_baselines(host_id=host_id)
    except Exception as exc:
        LOGGER.error("config-drift: list baselines error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/api/config-drift/baselines/{baseline_id}")
async def get_config_baseline(baseline_id: int):
    """Get a single config baseline."""
    baseline = await db.get_config_baseline(baseline_id)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")
    return baseline


@router.post("/api/config-drift/baselines", status_code=201)
async def create_config_baseline(body: ConfigBaselineCreate, request: Request):
    """Create or replace a config baseline for a host."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    session = _get_session(request)
    user = session["user"] if session else ""
    baseline_id = await db.create_config_baseline(
        host_id=body.host_id,
        name=body.name,
        config_text=body.config_text,
        source=body.source,
        created_by=user,
    )
    await _audit(
        "config-drift", "baseline.created",
        user=user,
        detail=f"host_id={body.host_id} name={body.name!r}",
        correlation_id=_corr_id(request),
    )
    return {"id": baseline_id}


@router.put("/api/config-drift/baselines/{baseline_id}")
async def update_config_baseline_endpoint(baseline_id: int, body: ConfigBaselineUpdate, request: Request):
    """Update a config baseline."""
    existing = await db.get_config_baseline(baseline_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Baseline not found")
    await db.update_config_baseline(
        baseline_id,
        name=body.name,
        config_text=body.config_text,
        source=body.source,
    )
    session = _get_session(request)
    await _audit(
        "config-drift", "baseline.updated",
        user=session["user"] if session else "",
        detail=f"baseline_id={baseline_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/config-drift/baselines/{baseline_id}")
async def delete_config_baseline_endpoint(baseline_id: int, request: Request):
    """Delete a config baseline."""
    existing = await db.get_config_baseline(baseline_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Baseline not found")
    await db.delete_config_baseline(baseline_id)
    session = _get_session(request)
    await _audit(
        "config-drift", "baseline.deleted",
        user=session["user"] if session else "",
        detail=f"baseline_id={baseline_id} host_id={existing.get('host_id')}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Routes: Snapshots ────────────────────────────────────────────────────────

@router.get("/api/config-drift/snapshots")
async def list_config_snapshots(host_id: int = Query(), limit: int = Query(default=50, ge=1, le=10000)):
    """List config snapshots for a host."""
    return await db.get_config_snapshots_for_host(host_id, limit=limit)


@router.get("/api/config-drift/snapshots/{snapshot_id}")
async def get_config_snapshot(snapshot_id: int):
    """Get a single snapshot with full config text."""
    snapshot = await db.get_config_snapshot(snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snapshot


@router.post("/api/config-drift/snapshots/capture")
async def capture_config_snapshot(body: ConfigSnapshotCaptureRequest, request: Request):
    """SSH to a device and capture its running-config."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    try:
        config_text = await _capture_running_config(host, cred)
    except Exception as exc:
        LOGGER.error("config-drift: capture failed for host %s: %s", host["ip_address"], exc)
        raise HTTPException(status_code=502, detail=f"SSH capture failed: {exc}")
    snapshot_id = await db.create_config_snapshot(
        host_id=body.host_id,
        config_text=config_text,
        capture_method="manual",
    )
    session = _get_session(request)
    await _audit(
        "config-drift", "snapshot.captured",
        user=session["user"] if session else "",
        detail=f"host_id={body.host_id} snapshot_id={snapshot_id}",
        correlation_id=_corr_id(request),
    )
    return {"snapshot_id": snapshot_id, "config_length": len(config_text)}


@router.post("/api/config-drift/snapshots/capture-group")
async def capture_group_config_snapshots(body: ConfigGroupCaptureRequest, request: Request):
    """Capture running-config for all hosts in a group."""
    hosts = await db.get_hosts_for_group(body.group_id)
    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found in group")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    results = []
    sem = asyncio.Semaphore(4)

    async def _capture_one(h):
        async with sem:
            try:
                config_text = await _capture_running_config(h, cred)
                sid = await db.create_config_snapshot(
                    host_id=h["id"], config_text=config_text, capture_method="manual",
                )
                return {"host_id": h["id"], "hostname": h["hostname"], "ok": True, "snapshot_id": sid}
            except Exception as exc:
                return {"host_id": h["id"], "hostname": h["hostname"], "ok": False, "error": str(exc)}

    tasks = [asyncio.create_task(_capture_one(h)) for h in hosts]
    results = await asyncio.gather(*tasks)
    session = _get_session(request)
    await _audit(
        "config-drift", "snapshot.captured_group",
        user=session["user"] if session else "",
        detail=f"group_id={body.group_id} hosts={len(hosts)}",
        correlation_id=_corr_id(request),
    )
    return {"results": list(results)}


# ── Routes: Capture Jobs (background with WebSocket streaming) ───────────────

@router.post("/api/config-drift/snapshots/capture-job")
async def capture_config_job(body: ConfigGroupCaptureRequest, request: Request):
    """Start a background config capture job for a group, returning a job_id for WebSocket streaming."""
    hosts = await db.get_hosts_for_group(body.group_id)
    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found in group")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    job_id = str(uuid.uuid4())
    _capture_jobs[job_id] = {
        "job_id": job_id,
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "output_lines": [],
    }

    session = _get_session(request)
    launched_by = session["user"] if session else "admin"
    asyncio.create_task(_run_config_capture_job(job_id, hosts, cred, launched_by))

    await _audit(
        "config-drift", "snapshot.capture_job",
        user=launched_by,
        detail=f"group_id={body.group_id} hosts={len(hosts)} job_id={job_id}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id, "host_count": len(hosts)}


@router.post("/api/config-drift/snapshots/capture-single-job")
async def capture_config_single_job(body: ConfigSnapshotCaptureRequest, request: Request):
    """Start a background config capture job for a single host, returning a job_id for WebSocket streaming."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    job_id = str(uuid.uuid4())
    _capture_jobs[job_id] = {
        "job_id": job_id,
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "output_lines": [],
    }

    session = _get_session(request)
    launched_by = session["user"] if session else "admin"
    asyncio.create_task(_run_config_capture_job(job_id, [host], cred, launched_by))

    await _audit(
        "config-drift", "snapshot.capture_job",
        user=launched_by,
        detail=f"host_id={body.host_id} job_id={job_id}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id, "host_count": 1}


@router.get("/api/config-drift/capture-job/{job_id}")
async def get_capture_job(job_id: str):
    """Return status and output for a config capture job."""
    job = _capture_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Capture job not found")
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
        "output": "".join(job["output_lines"]),
    }


@ws_router.websocket("/ws/config-capture/{job_id}")
async def websocket_config_capture(websocket: WebSocket, job_id: str):
    """Stream config capture job output in real-time."""
    token = websocket.cookies.get("session")
    session = _verify_session_token(token) if token else None
    if not session:
        await websocket.close(code=1008)
        return

    user = await db.get_user_by_id(session["user_id"])
    if not user:
        await websocket.close(code=1008)
        return

    features = await _get_user_features(user)
    if user.get("role") != "admin" and "config-drift" not in features:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    job = _capture_jobs.get(job_id)
    if not job:
        await websocket.send_json({"type": "error", "message": "Job not found"})
        await websocket.close()
        return

    # Replay accumulated output
    for line in list(job.get("output_lines", [])):
        await websocket.send_json({"type": "line", "text": line})

    # If already done, notify and close
    if job["status"] not in ("running", "pending"):
        await websocket.send_json({"type": "job_complete", "job_id": job_id, "status": job["status"]})
        await websocket.close()
        return

    # Subscribe to live events
    async with _capture_sockets_lock:
        if job_id not in _capture_job_sockets:
            _capture_job_sockets[job_id] = []
        _capture_job_sockets[job_id].append(websocket)

    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=120)
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        async with _capture_sockets_lock:
            if job_id in _capture_job_sockets and websocket in _capture_job_sockets[job_id]:
                _capture_job_sockets[job_id].remove(websocket)


@router.delete("/api/config-drift/snapshots/{snapshot_id}")
async def delete_config_snapshot_endpoint(snapshot_id: int, request: Request):
    """Delete a config snapshot."""
    existing = await db.get_config_snapshot(snapshot_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    await db.delete_config_snapshot(snapshot_id)
    session = _get_session(request)
    user = session["user"] if session else ""
    await _audit("config_drift", "snapshot.deleted", user=user,
                 detail=f"snapshot_id={snapshot_id} host_id={existing.get('host_id', '')}",
                 correlation_id=_corr_id(request))
    return {"ok": True}


# ── Routes: Drift Events ─────────────────────────────────────────────────────

@router.get("/api/config-drift/events")
async def list_config_drift_events(
    status: str | None = Query(default=None),
    host_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=10000),
):
    """List drift events with optional filters."""
    return await db.get_config_drift_events(status=status, host_id=host_id, limit=limit)


@router.post("/api/config-drift/events/bulk-accept")
async def bulk_accept_drift_events(body: ConfigDriftBulkAcceptRequest, request: Request):
    """Accept multiple drift events at once, updating baselines for each."""
    if not body.event_ids:
        raise HTTPException(status_code=400, detail="event_ids required")
    session = _get_session(request)
    user = session["user"] if session else ""
    accepted = 0
    for event_id in body.event_ids:
        event = await db.get_config_drift_event(event_id)
        if not event or event.get("status") != "open":
            continue
        from_status = event.get("status", "")
        await db.update_config_drift_event_status(event_id, "accepted", resolved_by=user)
        if event.get("snapshot_id"):
            snapshot = await db.get_config_snapshot(event["snapshot_id"])
            if snapshot and snapshot.get("config_text"):
                host = await db.get_host(event["host_id"])
                hostname = host["hostname"] if host else f"host-{event['host_id']}"
                await db.create_config_baseline(
                    host_id=event["host_id"],
                    name=f"{hostname} baseline",
                    config_text=snapshot["config_text"],
                    source="accepted-drift",
                    created_by=user,
                )
        await db.create_config_drift_event_history(
            event_id=event_id,
            host_id=event["host_id"],
            action="status_change",
            from_status=from_status,
            to_status="accepted",
            actor=user,
            details="bulk accept",
        )
        accepted += 1
    await _audit(
        "config-drift", "drift.bulk_accepted",
        user=user,
        detail=f"count={accepted} ids={body.event_ids[:20]}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "accepted": accepted}


@router.get("/api/config-drift/events/{event_id}")
async def get_config_drift_event(event_id: int):
    """Get a single drift event with diff text."""
    event = await db.get_config_drift_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Drift event not found")
    return event


@router.get("/api/config-drift/events/{event_id}/history")
async def get_config_drift_event_history(event_id: int, limit: int = Query(default=200, ge=1, le=2000)):
    """Return lifecycle history entries for a single drift event."""
    event = await db.get_config_drift_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Drift event not found")
    return await db.get_config_drift_event_history(event_id, limit=limit)


@router.put("/api/config-drift/events/{event_id}/status")
async def update_config_drift_event_status(event_id: int, body: ConfigDriftStatusUpdate, request: Request):
    """Update drift event status to resolved or accepted."""
    if body.status not in ("resolved", "accepted", "open"):
        raise HTTPException(status_code=400, detail="Status must be 'open', 'resolved', or 'accepted'")
    event = await db.get_config_drift_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Drift event not found")
    session = _get_session(request)
    user = session["user"] if session else ""
    from_status = event.get("status", "")
    await db.update_config_drift_event_status(event_id, body.status, resolved_by=user)

    # When accepting, update the baseline to match the snapshot (the new config is now the standard)
    if body.status == "accepted" and event.get("snapshot_id"):
        snapshot = await db.get_config_snapshot(event["snapshot_id"])
        if snapshot and snapshot.get("config_text"):
            host = await db.get_host(event["host_id"])
            hostname = host["hostname"] if host else f"host-{event['host_id']}"
            await db.create_config_baseline(
                host_id=event["host_id"],
                name=f"{hostname} baseline",
                config_text=snapshot["config_text"],
                source="accepted-drift",
                created_by=user,
            )
            LOGGER.info("config-drift: baseline updated for host %s after accepting event %s", event["host_id"], event_id)

    await db.create_config_drift_event_history(
        event_id=event_id,
        host_id=event["host_id"],
        action="status_change",
        from_status=from_status,
        to_status=body.status,
        actor=user,
        details="single status update",
    )

    await _audit(
        "config-drift", f"drift.{body.status}",
        user=user,
        detail=f"event_id={event_id} host_id={event.get('host_id')}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Routes: Revert ───────────────────────────────────────────────────────────

@router.post("/api/config-drift/events/revert")
async def revert_drift_event(body: ConfigDriftRevertRequest, request: Request):
    """Revert a device to its baseline config by pushing the baseline via SSH."""
    event = await db.get_config_drift_event(body.event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Drift event not found")

    host = await db.get_host(event["host_id"])
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    baseline = await db.get_config_baseline_for_host(event["host_id"])
    if not baseline or not baseline.get("config_text"):
        raise HTTPException(status_code=400, detail="No baseline config found for this host")

    credentials = await db.get_credential_raw(body.credential_id)
    if not credentials:
        raise HTTPException(status_code=404, detail="Credential not found")

    session = _get_session(request)
    user = session["user"] if session else ""

    job_id = str(uuid.uuid4())
    _revert_jobs[job_id] = {"status": "running", "output": "", "event_id": body.event_id, "host_id": event["host_id"]}
    _revert_job_sockets[job_id] = []

    asyncio.create_task(_run_revert_job(job_id, event, host, baseline, credentials, user))
    await db.create_config_drift_event_history(
        event_id=body.event_id,
        host_id=event["host_id"],
        action="revert_started",
        from_status=event.get("status", ""),
        to_status=event.get("status", ""),
        actor=user,
        details=f"revert job started id={job_id}",
    )

    await _audit(
        "config-drift", "drift.revert",
        user=user,
        detail=f"event_id={body.event_id} host_id={event['host_id']} job_id={job_id}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id}


@ws_router.websocket("/ws/config-revert/{job_id}")
async def ws_config_revert(websocket: WebSocket, job_id: str):
    """WebSocket for streaming revert job output."""
    token = websocket.cookies.get("session")
    session = _verify_session_token(token) if token else None
    if not session:
        await websocket.close(code=1008)
        return

    user = await db.get_user_by_id(session["user_id"])
    if not user:
        await websocket.close(code=1008)
        return

    features = await _get_user_features(user)
    if user.get("role") != "admin" and "config-drift" not in features:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    job = _revert_jobs.get(job_id)
    if not job:
        await websocket.send_json({"type": "error", "data": "Job not found"})
        await websocket.close()
        return

    # Replay history
    if job["output"]:
        for line in job["output"].splitlines(keepends=True):
            await websocket.send_json({"type": "line", "data": line})

    if job["status"] != "running":
        await websocket.send_json({"type": "job_complete", "status": job["status"]})
        await websocket.close()
        return

    async with _revert_sockets_lock:
        _revert_job_sockets.setdefault(job_id, []).append(websocket)
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=120)
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        async with _revert_sockets_lock:
            if websocket in _revert_job_sockets.get(job_id, []):
                _revert_job_sockets[job_id].remove(websocket)


# ── Routes: Analysis ─────────────────────────────────────────────────────────

@router.post("/api/config-drift/analyze")
async def analyze_config_drift(body: ConfigDriftAnalyzeRequest, request: Request):
    """Run drift analysis for a single host."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    result = await _analyze_drift_for_host(body.host_id)
    session = _get_session(request)
    await _audit(
        "config-drift", "drift.analyzed",
        user=session["user"] if session else "",
        detail=f"host_id={body.host_id} drifted={result['drifted']}",
        correlation_id=_corr_id(request),
    )
    result["host_id"] = body.host_id
    result["hostname"] = host["hostname"]
    return result


@router.post("/api/config-drift/analyze-group")
async def analyze_group_config_drift(body: ConfigDriftAnalyzeGroupRequest, request: Request):
    """Run drift analysis for all hosts in a group."""
    hosts = await db.get_hosts_for_group(body.group_id)
    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found in group")
    results = []
    for h in hosts:
        r = await _analyze_drift_for_host(h["id"])
        r["host_id"] = h["id"]
        r["hostname"] = h["hostname"]
        results.append(r)
    session = _get_session(request)
    drifted_count = sum(1 for r in results if r["drifted"])
    await _audit(
        "config-drift", "drift.analyzed_group",
        user=session["user"] if session else "",
        detail=f"group_id={body.group_id} hosts={len(results)} drifted={drifted_count}",
        correlation_id=_corr_id(request),
    )
    return {"results": results}


@router.post("/api/config-drift/check")
async def full_config_drift_check(body: ConfigDriftCheckRequest, request: Request):
    """Full cycle: capture running-config then analyze drift for one host."""
    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    cred = await db.get_credential_raw(body.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    try:
        config_text = await _capture_running_config(host, cred)
    except Exception as exc:
        LOGGER.error("config-drift: capture failed for host %s: %s", host["ip_address"], exc)
        raise HTTPException(status_code=502, detail=f"SSH capture failed: {exc}")
    snapshot_id = await db.create_config_snapshot(
        host_id=body.host_id, config_text=config_text, capture_method="manual",
    )
    result = await _analyze_drift_for_host(body.host_id)
    result["snapshot_id"] = snapshot_id
    result["host_id"] = body.host_id
    result["hostname"] = host["hostname"]
    session = _get_session(request)
    await _audit(
        "config-drift", "drift.check",
        user=session["user"] if session else "",
        detail=f"host_id={body.host_id} drifted={result['drifted']}",
        correlation_id=_corr_id(request),
    )
    return result


# ── Routes: Summary ──────────────────────────────────────────────────────────

@router.get("/api/config-drift/summary")
async def get_config_drift_summary():
    """Return drift detection summary stats."""
    return await db.get_config_drift_summary()


# ── Routes: Admin Config Drift Schedule ──────────────────────────────────────

@router.get("/api/admin/config-drift")
async def admin_get_config_drift_config():
    """Get the scheduled drift check configuration."""
    return state.CONFIG_DRIFT_CHECK_CONFIG


@router.put("/api/admin/config-drift")
async def admin_update_config_drift_config(body: dict, request: Request):
    """Update drift check schedule settings."""
    state.CONFIG_DRIFT_CHECK_CONFIG = state._sanitize_config_drift_check_config(body)
    await db.set_auth_setting("config_drift_check", state.CONFIG_DRIFT_CHECK_CONFIG)
    session = _get_session(request)
    await _audit(
        "config-drift", "config.updated",
        user=session["user"] if session else "",
        detail=f"enabled={state.CONFIG_DRIFT_CHECK_CONFIG['enabled']} interval={state.CONFIG_DRIFT_CHECK_CONFIG['interval_seconds']}s",
        correlation_id=_corr_id(request),
    )
    return state.CONFIG_DRIFT_CHECK_CONFIG


@router.post("/api/admin/config-drift/run-now")
async def admin_run_config_drift_check_now(request: Request):
    """Trigger an immediate scheduled drift check."""
    result = await _run_config_drift_check_once()
    session = _get_session(request)
    await _audit(
        "config-drift", "check.manual",
        user=session["user"] if session else "",
        detail=f"hosts_checked={result.get('hosts_checked', 0)} drifted={result.get('drifted', 0)}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "result": result}
