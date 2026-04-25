"""
jobs.py -- Job orchestration routes: launch, cancel, retry, priority, queue, WebSocket streaming.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict
from routes.crypto import decrypt
from routes.runner import LogEvent, execute_playbook, get_playbook_class
from routes.secret_resolver import (
    SecretResolutionError,
    build_redaction_set,
    extract_secret_names,
    has_secret_references,
    redact_secrets_in_text,
    redact_values,
    resolve_secrets,
)

import netcontrol.routes.state as state
from netcontrol.routes.shared import _audit, _corr_id, _get_session, require_credential_access
from netcontrol.telemetry import configure_logging

# Grace period (seconds) after a live job before re-probing SNMP on affected
# hosts.  Some devices briefly restart their SNMP agent when config changes
# are written, so polling too early would produce transient failures.
_POST_JOB_REPROBE_DELAY = 15

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
_require_admin = None
_verify_session_token = None
_get_user_features = None


def init_jobs(require_auth_fn, require_feature_fn, verify_session_token_fn, get_user_features_fn, require_admin_fn=None):
    global _require_auth, _require_feature, _require_admin, _verify_session_token, _get_user_features
    _require_auth = require_auth_fn
    _require_feature = require_feature_fn
    _require_admin = require_admin_fn
    _verify_session_token = verify_session_token_fn
    _get_user_features = get_user_features_fn


# ── Module-level state ────────────────────────────────────────────────────────

_MAX_CONCURRENT_JOBS = int(__import__("os").getenv("APP_MAX_CONCURRENT_JOBS", "4"))
_job_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_JOBS)

# Active WebSocket connections keyed by job_id
_job_sockets: dict[int, list[WebSocket]] = {}
_job_sockets_lock = asyncio.Lock()
_running_job_tasks: dict[int, asyncio.Task] = {}  # job_id -> asyncio.Task for cancellation
_running_tasks_lock = asyncio.Lock()

_PRIORITY_LABELS = {0: "low", 1: "below-normal", 2: "normal", 3: "high", 4: "critical"}

# Reserved IP ranges that should not be targeted by ad-hoc jobs
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),         # "this" network
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
]


def _validate_ad_hoc_ip(ip_str: str) -> str:
    """Validate that an ad-hoc IP is a valid unicast address not in reserved ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip_str}")
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            raise HTTPException(400, f"IP address {ip_str} is in a reserved range and cannot be targeted")
    return ip_str


# ── Pydantic Models ──────────────────────────────────────────────────────────

class JobLaunch(BaseModel):
    playbook_id: int
    inventory_group_id: int | None = None  # Optional for backward compatibility
    host_ids: list[int] | None = None  # List of specific host IDs to target
    ad_hoc_ips: list[str] | None = None  # Free-form IP addresses not in inventory
    credential_id: int | None = None
    template_id: int | None = None
    dry_run: bool = True
    priority: int = 2  # 0=low, 1=below-normal, 2=normal, 3=high, 4=critical
    depends_on: list[int] | None = None  # Job IDs that must complete before this runs

    # Forbid unknown fields for strict payload validation.
    model_config = ConfigDict(extra="forbid")


# ── Post-job SNMP re-probe ──────────────────────────────────────────────────


async def _reprobe_hosts_after_job(hosts: list[dict], credentials: dict, dry_run: bool):
    """After a live job, wait briefly then re-probe affected hosts via SNMP.

    Devices may briefly restart their SNMP agent when configuration is
    written (e.g. adding snmp-server host lines), which can cause the
    next scheduled discovery or monitoring poll to see the device as
    unreachable.  A short grace period followed by a targeted re-probe
    refreshes the SNMP engine-ID cache and keeps inventory in sync.
    """
    if dry_run:
        return
    # Only re-probe inventory hosts (skip ad-hoc IPs with id=None)
    real_hosts = [h for h in hosts if h.get("id") is not None and h.get("group_id") is not None]
    if not real_hosts:
        return

    await asyncio.sleep(_POST_JOB_REPROBE_DELAY)

    try:
        from netcontrol.routes.inventory import _sync_group_hosts
        from netcontrol.routes.snmp import _probe_discovery_target_snmp

        # Group hosts by their inventory group for efficient sync
        groups: dict[int, list[dict]] = {}
        for h in real_hosts:
            gid = h["group_id"]
            groups.setdefault(gid, []).append(h)

        for group_id, group_hosts in groups.items():
            snmp_cfg = state._resolve_snmp_discovery_config(group_id)
            if not snmp_cfg.get("enabled"):
                continue
            discovered = []
            for h in group_hosts:
                ip = h.get("ip_address")
                if not ip:
                    continue
                result = await _probe_discovery_target_snmp(ip, 5.0, snmp_cfg)
                if result is not None:
                    discovered.append(result)
            if discovered:
                await _sync_group_hosts(group_id, discovered, remove_absent=False)
                LOGGER.info("post-job reprobe: group %s — %d/%d hosts re-synced via SNMP",
                            group_id, len(discovered), len(group_hosts))
    except Exception as exc:
        LOGGER.warning("post-job SNMP reprobe failed: %s", exc)


# ── Background job processor ─────────────────────────────────────────────────

async def _process_job_queue():
    """Dequeue and run the next eligible job if concurrency allows."""
    try:
        await _process_job_queue_inner()
    except Exception as exc:
        LOGGER.exception("Queue processor error: %s", exc)


async def _process_job_queue_inner():
    running = await db.get_running_job_count()
    if running >= _MAX_CONCURRENT_JOBS:
        LOGGER.debug("Queue: max concurrency reached (%d/%d)", running, _MAX_CONCURRENT_JOBS)
        return

    next_job = await db.get_next_queued_job()
    if not next_job:
        LOGGER.debug("Queue: no queued jobs found")
        return

    # Check dependencies
    deps_met = await db.check_job_dependencies_met(next_job["id"])
    if not deps_met:
        return

    job_id = next_job["id"]
    LOGGER.info("Queue: processing job %d (playbook_id=%s, group_id=%s, host_ids=%s, ad_hoc_ips=%s)",
                job_id, next_job.get("playbook_id"), next_job.get("inventory_group_id"),
                next_job.get("host_ids"), next_job.get("ad_hoc_ips"))

    # Fetch all the info needed to run this job
    playbook = await db.get_playbook(next_job["playbook_id"])
    if not playbook:
        await db.finish_job(job_id, status="failed")
        await db.add_job_event(job_id, "error", "Playbook not found")
        return

    # Get hosts — use stored host_ids (specific selection) or fall back to full group
    hosts = []
    stored_host_ids = None
    if next_job.get("host_ids"):
        try:
            stored_host_ids = json.loads(next_job["host_ids"])
        except (json.JSONDecodeError, TypeError):
            pass

    if stored_host_ids:
        hosts = await db.get_hosts_by_ids(stored_host_ids)
    elif next_job.get("inventory_group_id"):
        hosts = await db.get_hosts_for_group(next_job["inventory_group_id"])

    # Reconstruct ad-hoc host dicts from stored IPs
    if next_job.get("ad_hoc_ips"):
        try:
            ad_hoc_list = json.loads(next_job["ad_hoc_ips"])
            for ip in ad_hoc_list:
                hosts.append({
                    "id": None,
                    "hostname": ip,
                    "ip_address": ip,
                    "device_type": "cisco_ios",
                    "group_id": None,
                })
        except (json.JSONDecodeError, TypeError):
            pass

    if not hosts:
        await db.finish_job(job_id, status="failed")
        await db.add_job_event(job_id, "error", "No hosts found for this job")
        return

    # Get credentials — use job-specific, then app-wide default.  Revalidate
    # ownership against the job's original submitter (launched_by) so a queued
    # job can never execute with a credential the submitter doesn't own.
    credentials = None
    cred_id = next_job.get("credential_id") or state.AUTH_CONFIG.get("default_credential_id")
    if cred_id:
        try:
            cred = await require_credential_access(
                cred_id,
                submitter_username=next_job.get("launched_by") or None,
            )
            credentials = {
                "username": cred["username"],
                "password": decrypt(cred["password"]),
                "secret": decrypt(cred["secret"]) if cred["secret"] else "",
            }
        except HTTPException as exc:
            await db.update_job_status(job_id, "failed")
            await db.add_job_event(job_id, "error", f"Credential check failed: {exc.detail}")
            return
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

    # Resolve {{secret.NAME}} placeholders in template commands
    _secret_redact_values: set[str] = set()
    if template_commands and has_secret_references("\n".join(template_commands)):
        try:
            _secret_redact_values = await build_redaction_set(template_commands)
            template_commands = await resolve_secrets(template_commands)
            await db.add_job_event(job_id, "info", "Secret variables resolved successfully")
        except SecretResolutionError as exc:
            await db.finish_job(job_id, status="failed")
            await db.add_job_event(
                job_id, "error",
                f"Template references undefined secret variable(s): {', '.join(exc.missing)}. "
                "Create them in Credentials → Secret Variables before running this job.",
            )
            return

    # Resolve dry_run: the DB stores 1/0; treat NULL or missing as dry-run (safe default)
    raw_dry_run = next_job.get("dry_run")
    dry_run = raw_dry_run != 0  # Only False when explicitly stored as 0
    LOGGER.info("job %s: dry_run raw=%r resolved=%s playbook=%s hosts=%d",
                job_id, raw_dry_run, dry_run, playbook.get("name", "?"), len(hosts))

    # Record the mode as the first job event so it's always visible in output
    mode_label = "DRY-RUN (simulation only — no changes will be made)" if dry_run else "LIVE MODE — changes WILL be applied"
    await db.add_job_event(job_id, "info", f"Job mode: {mode_label}")

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
        task = asyncio.create_task(_run_job(job_id, pb_class, hosts, credentials, template_commands, dry_run, _secret_redact_values))
    async with _running_tasks_lock:
        _running_job_tasks[job_id] = task

    def _on_done(t):
        async def _cleanup():
            async with _running_tasks_lock:
                _running_job_tasks.pop(job_id, None)
            await _process_job_queue()
        asyncio.ensure_future(_cleanup())

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
        async with _job_sockets_lock:
            sockets = list(_job_sockets.get(job_id, []))
        dead = []
        for ws in sockets:
            try:
                await asyncio.wait_for(ws.send_json(event.to_dict()), timeout=5)
            except Exception:
                dead.append(ws)
        if dead:
            async with _job_sockets_lock:
                for ws in dead:
                    try:
                        _job_sockets[job_id].remove(ws)
                    except (ValueError, KeyError):
                        pass

    job_succeeded = False
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
        job_succeeded = result.status == "success"
    except asyncio.CancelledError:
        await db.add_job_event(job_id, "warning", "Job cancelled by user")
        await db.cancel_job(job_id, "system")
    except Exception as e:
        await db.finish_job(job_id, status="failed", hosts_failed=len(hosts))
        await on_event(LogEvent(level="error", message=f"Fatal error: {e}"))

    # Notify WebSocket clients that job is done
    done_msg = {"type": "job_complete", "job_id": job_id, "status": "done"}
    async with _job_sockets_lock:
        sockets = _job_sockets.pop(job_id, [])
    for ws in sockets:
        try:
            await asyncio.wait_for(ws.send_json(done_msg), timeout=5)
        except Exception:
            LOGGER.debug("job broadcast: dropping dead WS for job %s", job_id)

    # Re-probe affected hosts via SNMP after a successful live job.
    if job_succeeded:
        asyncio.ensure_future(_reprobe_hosts_after_job(hosts, credentials, dry_run))


async def _run_job(
    job_id: int,
    pb_class: type,
    hosts: list[dict],
    credentials: dict,
    template_commands: list[str],
    dry_run: bool,
    secret_redact_values: set[str] | None = None,
):
    """Background task: execute playbook, store events, broadcast via WebSocket."""
    hosts_ok = 0
    hosts_failed = 0
    _redact = secret_redact_values or set()

    async def on_event(event: LogEvent):
        nonlocal hosts_ok, hosts_failed

        # Scrub any secret values from the log message before persisting
        if _redact:
            event = LogEvent(
                level=event.level,
                message=redact_values(event.message, _redact),
                host=event.host,
                timestamp=event.timestamp,
            )

        # Persist event
        await db.add_job_event(job_id, event.level, event.message, event.host)

        # Track host results
        if event.level == "success" and "Finished processing" in event.message:
            hosts_ok += 1
        elif event.level == "error" and event.host:
            hosts_failed += 1

        # Broadcast to WebSocket subscribers
        async with _job_sockets_lock:
            sockets = list(_job_sockets.get(job_id, []))
        dead = []
        for ws in sockets:
            try:
                await asyncio.wait_for(ws.send_json(event.to_dict()), timeout=5)
            except Exception:
                dead.append(ws)
        if dead:
            async with _job_sockets_lock:
                for ws in dead:
                    try:
                        _job_sockets[job_id].remove(ws)
                    except (ValueError, KeyError):
                        pass

    job_succeeded = False
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
        job_succeeded = result.status == "success"
    except asyncio.CancelledError:
        await db.add_job_event(job_id, "warning", "Job cancelled by user")
        await db.cancel_job(job_id, "system")
    except Exception as e:
        await db.finish_job(job_id, status="failed", hosts_failed=len(hosts))
        await on_event(LogEvent(level="error", message=f"Fatal error: {e}"))

    # Notify WebSocket clients that job is done
    done_msg = {"type": "job_complete", "job_id": job_id, "status": "done"}
    async with _job_sockets_lock:
        sockets = _job_sockets.pop(job_id, [])
    for ws in sockets:
        try:
            await ws.send_json(done_msg)
        except Exception:
            pass

    # Re-probe affected hosts via SNMP after a successful live job so that
    # any transient SNMP agent restart doesn't leave inventory stale.
    if job_succeeded:
        asyncio.ensure_future(_reprobe_hosts_after_job(hosts, credentials, dry_run))


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

    # Ansible playbooks can execute arbitrary code — restrict to admin only
    if playbook.get("type") == "ansible" and _require_admin:
        await _require_admin(request)

    # Get hosts - from selected host_ids, ad-hoc IPs, or inventory_group_id
    hosts = []
    ad_hoc_hosts = []
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

    # Build synthetic host dicts for ad-hoc IPs
    if body.ad_hoc_ips:
        for ip in body.ad_hoc_ips:
            ip = ip.strip()
            if ip:
                _validate_ad_hoc_ip(ip)
                ad_hoc_hosts.append({
                    "id": None,
                    "hostname": ip,
                    "ip_address": ip,
                    "device_type": "cisco_ios",
                    "group_id": None,
                })
        hosts = hosts + ad_hoc_hosts

    if not hosts:
        raise HTTPException(400, "Must specify host_ids, ad_hoc_ips, or inventory_group_id")

    # Get credentials — use job-specific, then app-wide default.  The default
    # credential is only usable by callers who actually own it (or are admin);
    # it does not grant regular users implicit access to another user's creds.
    cred_id = body.credential_id or state.AUTH_CONFIG.get("default_credential_id")
    if not cred_id:
        raise HTTPException(400, "No credential configured — set a default credential in Settings or select one when launching the job")
    cred = await require_credential_access(cred_id, session=session)
    credentials = {
        "username": cred["username"],
        "password": decrypt(cred["password"]),
        "secret": decrypt(cred["secret"]) if cred["secret"] else "",
    }

    # Get template commands
    template_commands = []
    if body.template_id:
        tpl = await db.get_template(body.template_id)
        if tpl:
            template_commands = [
                line.rstrip() for line in tpl["content"].splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

    # Validate that all {{secret.NAME}} references can be resolved
    if template_commands and has_secret_references("\n".join(template_commands)):
        try:
            # Dry-resolve (redacted) to verify all secrets exist without
            # decrypting yet — actual decryption happens at execution time.
            await resolve_secrets(template_commands, redact=True)
        except SecretResolutionError as exc:
            raise HTTPException(
                400,
                f"Template references undefined secret variable(s): {', '.join(exc.missing)}. "
                "Create them in Credentials \u2192 Secret Variables before launching.",
            )

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
    selected_host_ids = [h["id"] for h in hosts if h.get("id") is not None] or None
    # Store ad-hoc IPs separately so the queue processor can reconstruct them
    stored_ad_hoc = [ip.strip() for ip in body.ad_hoc_ips if ip.strip()] if body.ad_hoc_ips else None
    job_id = await db.create_job(
        body.playbook_id, inventory_group_id,
        body.credential_id, body.template_id,
        body.dry_run, launched_by=launched_by,
        priority=priority, depends_on=body.depends_on,
        host_ids=selected_host_ids,
        ad_hoc_ips=stored_ad_hoc,
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
    async with _running_tasks_lock:
        task = _running_job_tasks.pop(job_id, None)
    if task and not task.done():
        task.cancel()

    ok = await db.cancel_job(job_id, user)
    if not ok:
        raise HTTPException(400, "Job could not be cancelled")

    # Notify WebSocket clients
    done_msg = {"type": "job_complete", "job_id": job_id, "status": "cancelled"}
    async with _job_sockets_lock:
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

    # Carry forward host_ids and ad_hoc_ips from the original job
    retry_host_ids = None
    if job.get("host_ids"):
        try:
            retry_host_ids = json.loads(job["host_ids"])
        except (json.JSONDecodeError, TypeError):
            pass
    retry_ad_hoc = None
    if job.get("ad_hoc_ips"):
        try:
            retry_ad_hoc = json.loads(job["ad_hoc_ips"])
        except (json.JSONDecodeError, TypeError):
            pass

    new_job_id = await db.create_job(
        job["playbook_id"], job.get("inventory_group_id"),
        job.get("credential_id"), job.get("template_id"),
        bool(job.get("dry_run", 1)), launched_by=user,
        priority=job.get("priority", 2),
        host_ids=retry_host_ids,
        ad_hoc_ips=retry_ad_hoc,
    )

    asyncio.ensure_future(_process_job_queue())

    await _audit("jobs", "job.retry", user=user,
                 detail=f"retried job {job_id} as new job {new_job_id}",
                 correlation_id=_corr_id(request))
    return {"job_id": new_job_id, "status": "queued", "retried_from": job_id}


@router.post("/api/jobs/{job_id}/rerun", status_code=201)
async def rerun_job_endpoint(job_id: int, request: Request):
    """Re-run a completed job with dry_run disabled (live mode).

    Works on any finished job (completed, failed, cancelled).  Clones the
    original parameters but forces ``dry_run=False``.
    """
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] in ("queued", "running"):
        raise HTTPException(400, f"Job is still {job['status']} — wait for it to finish first")

    session = _get_session(request)
    user = session["user"] if session else "admin"

    rerun_host_ids = None
    if job.get("host_ids"):
        try:
            rerun_host_ids = json.loads(job["host_ids"])
        except (json.JSONDecodeError, TypeError):
            pass
    rerun_ad_hoc = None
    if job.get("ad_hoc_ips"):
        try:
            rerun_ad_hoc = json.loads(job["ad_hoc_ips"])
        except (json.JSONDecodeError, TypeError):
            pass

    new_job_id = await db.create_job(
        job["playbook_id"], job.get("inventory_group_id"),
        job.get("credential_id"), job.get("template_id"),
        False,  # dry_run = False (live mode)
        launched_by=user,
        priority=job.get("priority", 2),
        host_ids=rerun_host_ids,
        ad_hoc_ips=rerun_ad_hoc,
    )

    asyncio.ensure_future(_process_job_queue())

    await _audit("jobs", "job.rerun_live", user=user,
                 detail=f"re-ran job {job_id} as live job {new_job_id}",
                 correlation_id=_corr_id(request))
    return {"job_id": new_job_id, "status": "queued", "rerun_from": job_id}


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
    async with _job_sockets_lock:
        if job_id not in _job_sockets:
            _job_sockets[job_id] = []
        _job_sockets[job_id].append(websocket)

    try:
        # Keep connection alive until client disconnects (120s idle timeout)
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=120)
            except TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        async with _job_sockets_lock:
            if job_id in _job_sockets and websocket in _job_sockets[job_id]:
                _job_sockets[job_id].remove(websocket)
