"""
jobs.py -- Job orchestration routes: launch, cancel, retry, priority, queue, WebSocket streaming.
"""

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict

import routes.database as db
from routes.crypto import decrypt
from routes.runner import LogEvent, execute_playbook, get_playbook_class
import netcontrol.routes.state as state
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

try:
    from routes.ansible_runner_backend import execute_ansible_playbook
    ANSIBLE_RUNNER_AVAILABLE = True
except ImportError:
    ANSIBLE_RUNNER_AVAILABLE = False

LOGGER = configure_logging("plexus.jobs")

router = APIRouter()
ws_router = APIRouter()  # WebSocket routes — registered without HTTP auth dependency

# ── Late-binding auth dependencies ────────────────────────────────────────────

_require_auth = None
_require_feature = None
_verify_session_token = None
_get_user_features = None


def init_jobs(require_auth_fn, require_feature_fn, verify_session_token_fn, get_user_features_fn):
    global _require_auth, _require_feature, _verify_session_token, _get_user_features
    _require_auth = require_auth_fn
    _require_feature = require_feature_fn
    _verify_session_token = verify_session_token_fn
    _get_user_features = get_user_features_fn


# ── Module-level state ────────────────────────────────────────────────────────

_MAX_CONCURRENT_JOBS = int(__import__("os").getenv("APP_MAX_CONCURRENT_JOBS", "4"))
_job_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_JOBS)

# Active WebSocket connections keyed by job_id
_job_sockets: dict[int, list[WebSocket]] = {}
_running_job_tasks: dict[int, asyncio.Task] = {}  # job_id -> asyncio.Task for cancellation

_PRIORITY_LABELS = {0: "low", 1: "below-normal", 2: "normal", 3: "high", 4: "critical"}


# ── Pydantic Models ──────────────────────────────────────────────────────────

class JobLaunch(BaseModel):
    playbook_id: int
    inventory_group_id: int | None = None  # Optional for backward compatibility
    host_ids: list[int] | None = None  # List of specific host IDs to target
    credential_id: int | None = None
    template_id: int | None = None
    dry_run: bool = True
    priority: int = 2  # 0=low, 1=below-normal, 2=normal, 3=high, 4=critical
    depends_on: list[int] | None = None  # Job IDs that must complete before this runs

    # Forbid unknown fields for strict payload validation.
    model_config = ConfigDict(extra="forbid")


# ── Background job processor ─────────────────────────────────────────────────

async def _process_job_queue():
    """Dequeue and run the next eligible job if concurrency allows."""
    running = await db.get_running_job_count()
    if running >= _MAX_CONCURRENT_JOBS:
        return

    next_job = await db.get_next_queued_job()
    if not next_job:
        return

    # Check dependencies
    deps_met = await db.check_job_dependencies_met(next_job["id"])
    if not deps_met:
        return

    job_id = next_job["id"]

    # Fetch all the info needed to run this job
    playbook = await db.get_playbook(next_job["playbook_id"])
    if not playbook:
        await db.finish_job(job_id, status="failed")
        await db.add_job_event(job_id, "error", "Playbook not found")
        return

    # Get hosts — use stored host_ids (specific selection) or fall back to full group
    stored_host_ids = None
    if next_job.get("host_ids"):
        try:
            stored_host_ids = json.loads(next_job["host_ids"])
        except (json.JSONDecodeError, TypeError):
            pass

    if stored_host_ids:
        hosts = await db.get_hosts_by_ids(stored_host_ids)
    else:
        hosts = await db.get_hosts_for_group(next_job["inventory_group_id"])
    if not hosts:
        await db.finish_job(job_id, status="failed")
        await db.add_job_event(job_id, "error", "No hosts found for this job")
        return

    # Get credentials — use job-specific, then app-wide default
    credentials = None
    cred_id = next_job.get("credential_id") or state.AUTH_CONFIG.get("default_credential_id")
    if cred_id:
        cred = await db.get_credential_raw(cred_id)
        if cred:
            credentials = {
                "username": cred["username"],
                "password": decrypt(cred["password"]),
                "secret": decrypt(cred["secret"]) if cred["secret"] else "",
            }
    if not credentials:
        await db.update_job_status(job_id, "failed")
        await db.add_job_event(job_id, "error", "No credential configured — set a default credential in Settings or select one when launching the job")
        return

    # Get template commands
    template_commands = []
    if next_job.get("template_id"):
        tpl = await db.get_template(next_job["template_id"])
        if tpl:
            template_commands = [
                line.rstrip() for line in tpl["content"].splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

    dry_run = bool(next_job.get("dry_run", 1))
    pb_type = playbook.get("type", "python")

    if pb_type == "ansible":
        # ── Ansible playbook path ──
        if not ANSIBLE_RUNNER_AVAILABLE:
            await db.finish_job(job_id, status="failed")
            await db.add_job_event(job_id, "error", "ansible-runner is not installed on the server")
            return
        if not playbook.get("content", "").strip():
            await db.finish_job(job_id, status="failed")
            await db.add_job_event(job_id, "error", "Ansible playbook has no YAML content")
            return
        group = await db.get_group(next_job["inventory_group_id"])
        group_name = group["name"] if group else "plexus_targets"
        await db.start_job(job_id)
        task = asyncio.create_task(
            _run_ansible_job(job_id, playbook["content"], hosts, credentials, group_name, dry_run)
        )
    else:
        # ── Python playbook path ──
        pb_class = get_playbook_class(playbook["filename"])
        if not pb_class:
            await db.finish_job(job_id, status="failed")
            await db.add_job_event(job_id, "error", f"No runner for '{playbook['filename']}'")
            return
        await db.start_job(job_id)
        task = asyncio.create_task(_run_job(job_id, pb_class, hosts, credentials, template_commands, dry_run))
    _running_job_tasks[job_id] = task

    def _on_done(t):
        _running_job_tasks.pop(job_id, None)
        # After a job finishes, try to dequeue the next one
        asyncio.ensure_future(_process_job_queue())

    task.add_done_callback(_on_done)


# ── Job runners ──────────────────────────────────────────────────────────────

async def _run_ansible_job(
    job_id: int,
    playbook_content: str,
    hosts: list[dict],
    credentials: dict,
    group_name: str,
    dry_run: bool,
):
    """Background task: execute Ansible playbook, store events, broadcast via WebSocket."""

    async def on_event(event: LogEvent):
        await db.add_job_event(job_id, event.level, event.message, event.host)
        sockets = _job_sockets.get(job_id, [])
        dead = []
        for ws in sockets:
            try:
                await ws.send_json(event.to_dict())
            except Exception:
                dead.append(ws)
        for ws in dead:
            sockets.remove(ws)

    try:
        result = await execute_ansible_playbook(
            playbook_content=playbook_content,
            hosts=hosts,
            credentials=credentials,
            group_name=group_name,
            dry_run=dry_run,
            event_callback=on_event,
        )
        await db.finish_job(
            job_id,
            status=result.status,
            hosts_ok=result.hosts_ok,
            hosts_failed=result.hosts_failed,
            hosts_skipped=result.hosts_skipped,
        )
    except asyncio.CancelledError:
        await db.add_job_event(job_id, "warning", "Job cancelled by user")
        await db.cancel_job(job_id, "system")
    except Exception as e:
        await db.finish_job(job_id, status="failed", hosts_failed=len(hosts))
        await on_event(LogEvent(level="error", message=f"Fatal error: {e}"))

    # Notify WebSocket clients that job is done
    done_msg = {"type": "job_complete", "job_id": job_id, "status": "done"}
    sockets = _job_sockets.pop(job_id, [])
    for ws in sockets:
        try:
            await ws.send_json(done_msg)
        except Exception:
            pass


async def _run_job(
    job_id: int,
    pb_class: type,
    hosts: list[dict],
    credentials: dict,
    template_commands: list[str],
    dry_run: bool,
):
    """Background task: execute playbook, store events, broadcast via WebSocket."""
    hosts_ok = 0
    hosts_failed = 0

    async def on_event(event: LogEvent):
        nonlocal hosts_ok, hosts_failed

        # Persist event
        await db.add_job_event(job_id, event.level, event.message, event.host)

        # Track host results
        if event.level == "success" and "Finished processing" in event.message:
            hosts_ok += 1
        elif event.level == "error" and event.host:
            hosts_failed += 1

        # Broadcast to WebSocket subscribers
        sockets = _job_sockets.get(job_id, [])
        dead = []
        for ws in sockets:
            try:
                await ws.send_json(event.to_dict())
            except Exception:
                dead.append(ws)
        for ws in dead:
            sockets.remove(ws)

    try:
        result = await execute_playbook(
            pb_class, hosts, credentials, template_commands, dry_run, on_event
        )
        await db.finish_job(
            job_id,
            status=result.status,
            hosts_ok=hosts_ok,
            hosts_failed=hosts_failed,
            hosts_skipped=result.hosts_skipped,
        )
    except asyncio.CancelledError:
        await db.add_job_event(job_id, "warning", "Job cancelled by user")
        await db.cancel_job(job_id, "system")
    except Exception as e:
        await db.finish_job(job_id, status="failed", hosts_failed=len(hosts))
        await on_event(LogEvent(level="error", message=f"Fatal error: {e}"))

    # Notify WebSocket clients that job is done
    done_msg = {"type": "job_complete", "job_id": job_id, "status": "done"}
    sockets = _job_sockets.pop(job_id, [])
    for ws in sockets:
        try:
            await ws.send_json(done_msg)
        except Exception:
            pass


# ── Job REST routes ──────────────────────────────────────────────────────────

def _jobs_deps():
    return [Depends(_require_auth), Depends(_require_feature("jobs"))]


@router.get("/api/jobs")
async def list_jobs(limit: int = Query(50, ge=1, le=200)):
    return await db.get_all_jobs(limit=limit)


@router.get("/api/jobs/queue")
async def get_job_queue():
    """Get all queued and running jobs with queue positions."""
    queue = await db.get_job_queue()
    running_count = sum(1 for j in queue if j["status"] == "running")
    queued_count = sum(1 for j in queue if j["status"] == "queued")
    return {
        "max_concurrent": _MAX_CONCURRENT_JOBS,
        "running": running_count,
        "queued": queued_count,
        "jobs": queue,
    }


@router.get("/api/jobs/{job_id}")
async def get_job(job_id: int):
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.get("/api/jobs/{job_id}/events")
async def get_job_events(job_id: int):
    return await db.get_job_events(job_id)


@router.post("/api/jobs/launch", status_code=201)
async def launch_job(body: JobLaunch, request: Request):
    """
    Launch a playbook execution as a background task.
    Returns the job ID immediately. Connect to the WebSocket
    at /ws/jobs/{job_id} to stream real-time output.
    """
    session = _get_session(request)
    LOGGER.debug("JobLaunch request: playbook_id=%s host_ids=%s inventory_group_id=%s", body.playbook_id, body.host_ids, body.inventory_group_id)

    # Validate playbook exists
    playbook = await db.get_playbook(body.playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    # Get hosts - either from selected host_ids or from inventory_group_id
    hosts = []
    inventory_group_id = None

    if body.host_ids and len(body.host_ids) > 0:
        hosts = await db.get_hosts_by_ids(body.host_ids)
        if not hosts:
            raise HTTPException(400, "No valid hosts selected")
        if hosts:
            inventory_group_id = hosts[0].get("group_id")
    elif body.inventory_group_id:
        group = await db.get_group(body.inventory_group_id)
        if not group:
            raise HTTPException(404, "Inventory group not found")
        hosts = await db.get_hosts_for_group(body.inventory_group_id)
        if not hosts:
            raise HTTPException(400, "No hosts in inventory group")
        inventory_group_id = body.inventory_group_id
    else:
        raise HTTPException(400, "Must specify either host_ids or inventory_group_id")

    # Get credentials — use job-specific, then app-wide default
    credentials = None
    cred_id = body.credential_id or state.AUTH_CONFIG.get("default_credential_id")
    if cred_id:
        cred = await db.get_credential_raw(cred_id)
        if not cred:
            raise HTTPException(404, "Credential not found")
        if body.credential_id and cred.get("owner_id") and session and cred["owner_id"] != session["user_id"]:
            raise HTTPException(403, "You can only use your own credentials")
        credentials = {
            "username": cred["username"],
            "password": decrypt(cred["password"]),
            "secret": decrypt(cred["secret"]) if cred["secret"] else "",
        }
    if not credentials:
        raise HTTPException(400, "No credential configured — set a default credential in Settings or select one when launching the job")

    # Get template commands
    template_commands = []
    if body.template_id:
        tpl = await db.get_template(body.template_id)
        if tpl:
            template_commands = [
                line.rstrip() for line in tpl["content"].splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

    # Validate the playbook can be executed
    pb_type = playbook.get("type", "python")
    if pb_type == "ansible":
        if not ANSIBLE_RUNNER_AVAILABLE:
            raise HTTPException(400, "Ansible runner is not installed on the server")
        if not playbook.get("content", "").strip():
            raise HTTPException(400, "Ansible playbook has no YAML content")
    else:
        pb_class = get_playbook_class(playbook["filename"])
        if not pb_class:
            raise HTTPException(400, f"No runner registered for '{playbook['filename']}'")

    launched_by = session["user"] if session else "admin"
    priority = max(0, min(4, body.priority))
    # Store specific host_ids so the queue processor targets only selected hosts
    selected_host_ids = [h["id"] for h in hosts] if body.host_ids else None
    job_id = await db.create_job(
        body.playbook_id, inventory_group_id,
        body.credential_id, body.template_id,
        body.dry_run, launched_by=launched_by,
        priority=priority, depends_on=body.depends_on,
        host_ids=selected_host_ids,
    )

    # Trigger queue processor to potentially start this job immediately
    asyncio.ensure_future(_process_job_queue())

    await _audit("jobs", "job.launch", user=launched_by,
                 detail=f"queued job {job_id} playbook='{playbook['name']}' hosts={len(hosts)} dry_run={body.dry_run} priority={priority}",
                 correlation_id=_corr_id(request))
    return {"job_id": job_id, "status": "queued"}


@router.post("/api/jobs/{job_id}/cancel")
async def cancel_job_endpoint(job_id: int, request: Request):
    """Cancel a queued or running job."""
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] not in ("queued", "running"):
        raise HTTPException(400, f"Cannot cancel job with status '{job['status']}'")

    session = _get_session(request)
    user = session["user"] if session else ""

    # Cancel running asyncio task if applicable
    task = _running_job_tasks.pop(job_id, None)
    if task and not task.done():
        task.cancel()

    ok = await db.cancel_job(job_id, user)
    if not ok:
        raise HTTPException(400, "Job could not be cancelled")

    # Notify WebSocket clients
    done_msg = {"type": "job_complete", "job_id": job_id, "status": "cancelled"}
    sockets = _job_sockets.pop(job_id, [])
    for ws in sockets:
        try:
            await ws.send_json(done_msg)
        except Exception:
            pass

    await _audit("jobs", "job.cancelled", user=user,
                 detail=f"cancelled job {job_id}", correlation_id=_corr_id(request))

    # Try to start the next queued job
    asyncio.ensure_future(_process_job_queue())
    return {"ok": True}


@router.post("/api/jobs/{job_id}/retry", status_code=201)
async def retry_job_endpoint(job_id: int, request: Request):
    """Retry a failed or cancelled job by creating a new job with the same parameters."""
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] not in ("failed", "cancelled"):
        raise HTTPException(400, f"Can only retry failed or cancelled jobs, current status: '{job['status']}'")

    session = _get_session(request)
    user = session["user"] if session else "admin"

    new_job_id = await db.create_job(
        job["playbook_id"], job["inventory_group_id"],
        job.get("credential_id"), job.get("template_id"),
        bool(job.get("dry_run", 1)), launched_by=user,
        priority=job.get("priority", 2),
    )

    asyncio.ensure_future(_process_job_queue())

    await _audit("jobs", "job.retry", user=user,
                 detail=f"retried job {job_id} as new job {new_job_id}",
                 correlation_id=_corr_id(request))
    return {"job_id": new_job_id, "status": "queued", "retried_from": job_id}


@router.patch("/api/jobs/{job_id}/priority")
async def update_job_priority_endpoint(job_id: int, body: dict, request: Request):
    """Change the priority of a queued job."""
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != "queued":
        raise HTTPException(400, "Can only change priority of queued jobs")
    new_priority = body.get("priority")
    if new_priority is None or not isinstance(new_priority, int):
        raise HTTPException(400, "priority (int 0-4) required")

    ok = await db.update_job_priority(job_id, new_priority)
    if not ok:
        raise HTTPException(400, "Failed to update priority")

    session = _get_session(request)
    await _audit("jobs", "job.priority_changed", user=session["user"] if session else "",
                 detail=f"job {job_id} priority={new_priority}",
                 correlation_id=_corr_id(request))
    return {"ok": True, "priority": max(0, min(4, new_priority))}


# ── WebSocket for live job streaming ─────────────────────────────────────────

@ws_router.websocket("/ws/jobs/{job_id}")
async def websocket_job(websocket: WebSocket, job_id: int):
    """
    Stream job events in real-time.

    1. Client connects to /ws/jobs/{job_id}
    2. Server immediately sends all existing events for the job
    3. Server streams new events as they arrive
    4. Server sends {"type": "job_complete"} when done
    """
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
    if user.get("role") != "admin" and "jobs" not in features:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # Send historical events first
    events = await db.get_job_events(job_id)
    for event in events:
        await websocket.send_json({
            "level": event["level"],
            "message": event["message"],
            "host": event["host"],
            "timestamp": event["timestamp"],
        })

    # Check if job is already done
    job = await db.get_job(job_id)
    if job and job["status"] not in ("running", "pending"):
        await websocket.send_json({
            "type": "job_complete", "job_id": job_id, "status": job["status"]
        })
        await websocket.close()
        return

    # Subscribe to live events
    if job_id not in _job_sockets:
        _job_sockets[job_id] = []
    _job_sockets[job_id].append(websocket)

    try:
        # Keep connection alive until client disconnects
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if job_id in _job_sockets and websocket in _job_sockets[job_id]:
            _job_sockets[job_id].remove(websocket)
