"""
jobs.py -- Job orchestration routes: launch, cancel, retry, priority, queue, WebSocket streaming.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os

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
from netcontrol import job_inputs
from netcontrol.dynamic_groups import resolve_group, scope_for_launcher
from netcontrol.object_scope import request_scope
from netcontrol.routes.host_identity import host_ip_problem
from netcontrol.routes.playbooks import effective_input_schema, playbook_permissions, playbook_supports_dry_run
from netcontrol.routes.shared import (
    _audit,
    _corr_id,
    _get_session,
    require_credential_access,
    require_owner_or_admin,
    verify_ws_session,
)
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
ws_router = APIRouter()  # WebSocket routes - registered without HTTP auth dependency

# ── Late-binding auth dependencies ────────────────────────────────────────────

_require_auth = None
_require_feature = None
_require_admin = None
_verify_session_token = None
_get_user_features = None


def init_jobs(
    require_auth_fn, require_feature_fn, verify_session_token_fn, get_user_features_fn, require_admin_fn=None
):
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

# Cap for the history replay a WS client gets on connect; the full log is
# available via GET /api/jobs/{id}/events (limit up to 100k).
_WS_HISTORY_REPLAY_LIMIT = 2000

# A job in one of these states has not finished: it is waiting for a worker
# slot (queued) or executing (running). Anything else is terminal.
_ACTIVE_JOB_STATUSES = ("queued", "running")


async def _broadcast_to_job_sockets(job_id: int, payload: dict) -> None:
    """Send one payload to every subscriber of a job, concurrently.

    The payload is serialized once (N viewers used to cost N identical
    json encodes) and sends run in parallel, so a slow client only delays
    itself - bounded by the per-socket timeout - instead of holding up the
    other subscribers and the job's event loop. Dead sockets are pruned.
    """
    async with _job_sockets_lock:
        sockets = list(_job_sockets.get(job_id, []))
    if not sockets:
        return
    text = json.dumps(payload)

    async def _send(ws: WebSocket) -> WebSocket | None:
        try:
            await asyncio.wait_for(ws.send_text(text), timeout=5)
            return None
        except Exception:
            return ws

    results = await asyncio.gather(*(_send(ws) for ws in sockets))
    dead = [ws for ws in results if ws is not None]
    if dead:
        async with _job_sockets_lock:
            for ws in dead:
                try:
                    _job_sockets[job_id].remove(ws)
                except (ValueError, KeyError) as exc:
                    LOGGER.debug("job %s: dead WS already removed: %s", job_id, exc)
_running_job_tasks: dict[int, asyncio.Task] = {}  # job_id -> asyncio.Task for cancellation
_running_tasks_lock = asyncio.Lock()

# Set at shutdown so the queue processor stops launching new jobs while
# in-flight ones drain (see drain_running_jobs).
_shutting_down = False

_PRIORITY_LABELS = {0: "low", 1: "below-normal", 2: "normal", 3: "high", 4: "critical"}
_JOB_EVENT_BATCH_SIZE = max(1, int(os.getenv("APP_JOB_EVENT_BATCH_SIZE", "50")))
_JOB_EVENT_FLUSH_SECONDS = max(0.01, float(os.getenv("APP_JOB_EVENT_FLUSH_SECONDS", "0.1")))

def _validate_ad_hoc_ip(ip_str: str) -> str:
    """Validate that an ad-hoc IP is a valid unicast address not in reserved ranges."""
    problem = host_ip_problem(ip_str)
    if problem == "invalid":
        raise HTTPException(400, f"Invalid IP address: {ip_str}")
    if problem:
        raise HTTPException(400, f"IP address {ip_str} is in a reserved range and cannot be targeted")
    return ip_str


def _template_lines(content: str) -> list[str]:
    """Parse a template body into runnable command lines.

    Strips blank lines and ``#`` comments.  Factored out so the flat
    body and every per-device_type variant are parsed identically (the
    three former copies of this comprehension could drift).
    """
    return [line.rstrip() for line in (content or "").splitlines() if line.strip() and not line.strip().startswith("#")]


class _JobEventWriter:
    """Persist job events asynchronously in ordered batches."""

    _STOP = object()

    def __init__(
        self,
        job_id: int,
        *,
        batch_size: int = _JOB_EVENT_BATCH_SIZE,
        flush_seconds: float = _JOB_EVENT_FLUSH_SECONDS,
    ):
        self.job_id = job_id
        self.batch_size = max(1, batch_size)
        self.flush_seconds = max(0.01, flush_seconds)
        self.queue: asyncio.Queue = asyncio.Queue()
        self.closed = False
        self.task = asyncio.create_task(self._run())

    def enqueue(self, event: LogEvent) -> None:
        if self.closed:
            raise RuntimeError("job event writer is closed")
        if self.task.done():
            self.task.result()
        self.queue.put_nowait((event.level, event.message, event.host))

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.queue.put_nowait(self._STOP)
        await self.task

    async def _run(self) -> None:
        batch: list[tuple[str, str, str]] = []
        stopping = False
        while not stopping:
            item = await self.queue.get()
            if item is self._STOP:
                stopping = True
            else:
                batch.append(item)

            while not stopping and len(batch) < self.batch_size:
                try:
                    item = await asyncio.wait_for(self.queue.get(), timeout=self.flush_seconds)
                except TimeoutError:
                    break
                if item is self._STOP:
                    stopping = True
                else:
                    batch.append(item)

            if batch:
                try:
                    await db.add_job_events(self.job_id, batch)
                except Exception as exc:
                    # A transient write failure must not kill this task:
                    # enqueue() re-raises a dead writer's exception inside the
                    # playbook's event callback, aborting the live device job.
                    # Retry once, then drop the batch and keep the job alive.
                    LOGGER.warning(
                        "job %s: event batch write failed (%s); retrying once", self.job_id, type(exc).__name__
                    )
                    try:
                        await asyncio.sleep(0.5)
                        await db.add_job_events(self.job_id, batch)
                    except Exception as exc2:
                        LOGGER.error(
                            "job %s: dropping %d job event(s) after retry failed: %s",
                            self.job_id,
                            len(batch),
                            type(exc2).__name__,
                        )
                batch = []


# ── Pydantic Models ──────────────────────────────────────────────────────────


class JobLaunch(BaseModel):
    playbook_id: int
    inventory_group_id: int | None = None  # Optional for backward compatibility
    host_ids: list[int] | None = None  # List of specific host IDs to target
    # A dynamic group (saved host filter): its hosts are resolved when the
    # queue starts the job, within the launcher's object scope.
    dynamic_group_id: int | None = None
    ad_hoc_ips: list[str] | None = None  # Free-form IP addresses not in inventory
    credential_id: int | None = None
    template_id: int | None = None
    dry_run: bool = True
    priority: int = 2  # 0=low, 1=below-normal, 2=normal, 3=high, 4=critical
    depends_on: list[int] | None = None  # Job IDs that must complete before this runs
    parameters: dict | None = None  # Legacy name for ``inputs``
    # Values for the playbook's typed input schema (netcontrol/job_inputs.py).
    inputs: dict | None = None
    # True runs live (Ansible without --check). Wins over ``dry_run`` when
    # given; when neither says otherwise the job is a dry run.
    commit: bool | None = None

    # Forbid unknown fields for strict payload validation.
    model_config = ConfigDict(extra="forbid")


# ── Typed inputs and per-job permissions ────────────────────────────────────


def _input_error(exc: job_inputs.JobInputError) -> HTTPException:
    """422 with one message per field (the custom-fields wire contract)."""
    return HTTPException(status_code=422, detail={"message": exc.message, "fields": exc.fields})


def _coerce_parameters(schema: list[dict], raw: dict) -> dict:
    """Validate + coerce launch-time inputs against the playbook's schema.

    Returns the coerced dict (only keys declared in schema, properly typed).
    Raises HTTPException(422) with per-field messages so the operator sees
    every error before the job is queued.
    """
    if not schema:
        return {}
    try:
        return job_inputs.validate_inputs(job_inputs.normalize_schema(schema), raw)
    except job_inputs.JobInputError as exc:
        raise _input_error(exc)


async def _require_job_permission(request: Request, playbook: dict, *, commit: bool) -> None:
    """Refuse (403) a caller the playbook's run - or, for a live run, commit -
    rule does not allow. Admins and API token callers always pass."""
    role, group_ids = await job_inputs.user_permissions(_get_session(request))
    permissions = playbook_permissions(playbook)
    if not job_inputs.is_allowed(permissions, "run", role=role, group_ids=group_ids):
        raise HTTPException(403, f"You are not allowed to run '{playbook['name']}'")
    if commit and not job_inputs.is_allowed(permissions, "commit", role=role, group_ids=group_ids):
        raise HTTPException(
            403, f"You may run '{playbook['name']}' as a dry run only; committing changes is not allowed"
        )


def _stored_params(raw: object) -> dict:
    """A job row's ``parameters`` JSON as a dict (``{}`` if absent or bad)."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            value = json.loads(raw)
        except TypeError, ValueError:
            return {}
        return value if isinstance(value, dict) else {}
    return {}


def _stored_list(job: dict, column: str) -> list | None:
    """A job row's JSON list column (``host_ids``, ``ad_hoc_ips``) or ``None``."""
    raw = job.get(column)
    if not raw:
        return None
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError) as exc:
        LOGGER.warning("job %s: failed to parse %s: %s", job.get("id"), column, exc)
        return None
    return value if isinstance(value, list) else None


def job_clone_spec(job: dict) -> dict:
    """What a new job needs to run ``job`` again: playbook, targets,
    credential, template, priority and inputs (no mode, no launcher).
    Used by retry, rerun and the ChatOps job presets."""
    return {
        "playbook_id": job["playbook_id"],
        "inventory_group_id": job.get("inventory_group_id"),
        "credential_id": job.get("credential_id"),
        "template_id": job.get("template_id"),
        "priority": job.get("priority", 2),
        "host_ids": _stored_list(job, "host_ids"),
        "ad_hoc_ips": _stored_list(job, "ad_hoc_ips"),
        "parameters": _stored_params(job.get("parameters")) or None,
        "dynamic_group_id": job.get("dynamic_group_id"),
    }


async def queue_job_from_spec(spec: dict, *, dry_run: bool, launched_by: str) -> int:
    """Queue a job from a ``job_clone_spec`` and kick the queue. The caller
    has already checked the launcher may run it."""
    new_job_id = await db.create_job(
        spec["playbook_id"],
        spec.get("inventory_group_id"),
        spec.get("credential_id"),
        spec.get("template_id"),
        dry_run,
        launched_by=launched_by,
        priority=spec.get("priority", 2),
        host_ids=spec.get("host_ids"),
        ad_hoc_ips=spec.get("ad_hoc_ips"),
        parameters=spec.get("parameters"),
        dynamic_group_id=spec.get("dynamic_group_id"),
    )
    asyncio.ensure_future(_process_job_queue())
    return new_job_id


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
            discovered = []
            for h, snmp_cfg in state._hosts_with_snmp_config(group_hosts, group_id):
                ip = h.get("ip_address")
                if not ip:
                    continue
                result = await _probe_discovery_target_snmp(ip, 5.0, snmp_cfg)
                if result is not None:
                    discovered.append(result)
            if discovered:
                await _sync_group_hosts(group_id, discovered, remove_absent=False)
                LOGGER.info(
                    "post-job reprobe: group %s - %d/%d hosts re-synced via SNMP",
                    group_id,
                    len(discovered),
                    len(group_hosts),
                )
    except Exception as exc:
        LOGGER.warning("post-job SNMP reprobe failed: %s", exc)


# ── Background job processor ─────────────────────────────────────────────────

# Serializes the dequeue→launch critical section. Queue kicks fire from many
# places (launch endpoints, done-callbacks, boot reconciliation); without this
# two concurrent kicks can both read the same 'queued' row during the long
# await chain before start_job() and both launch it against live devices.
_queue_dispatch_lock = asyncio.Lock()


async def _resolve_job_hosts(job: dict) -> list[dict]:
    """The inventory hosts a queued job targets, read when it starts: the
    stored host selection, else its dynamic group (resolved now, within the
    object scope of the user who launched it), else its inventory group.
    Ad-hoc addresses are added by the caller."""
    stored_host_ids = None
    if job.get("host_ids"):
        try:
            stored_host_ids = json.loads(job["host_ids"])
        except (json.JSONDecodeError, TypeError) as exc:
            LOGGER.warning("job %s: failed to parse stored host_ids: %s", job.get("id"), exc)
    if stored_host_ids:
        return await db.get_hosts_by_ids(stored_host_ids)
    if job.get("dynamic_group_id"):
        scope = await scope_for_launcher(job.get("launched_by"))
        hosts = await resolve_group(int(job["dynamic_group_id"]), scope) or []
        LOGGER.info("job %s: dynamic group %s resolved to %d hosts", job.get("id"), job["dynamic_group_id"], len(hosts))
        return hosts
    if job.get("inventory_group_id"):
        return await db.get_hosts_for_group(job["inventory_group_id"])
    return []


async def _process_job_queue():
    """Dequeue and run the next eligible job if concurrency allows."""
    try:
        async with _queue_dispatch_lock:
            await _process_job_queue_inner()
    except Exception as exc:
        LOGGER.exception("Queue processor error: %s", exc)


async def reap_and_resume_jobs() -> None:
    """Boot-time job-queue reconciliation. Call once from the app lifespan.

    1. Fail any job orphaned in 'running' by a prior crash - otherwise it
       counts against the concurrency gate forever and wedges the queue.
    2. Prime the queue so 'queued' jobs left from before the restart drain
       (the processor is otherwise only kicked reactively by API actions).
    """
    try:
        orphaned = await db.reap_orphaned_running_jobs()
    except Exception as exc:
        LOGGER.warning("job reaper: failed to reset orphaned running jobs: %s", exc)
        orphaned = []
    for job_id in orphaned:
        try:
            await db.add_job_event(
                job_id,
                "error",
                "Job was interrupted by a server restart and marked failed. Re-run it if the change did not complete.",
            )
        except Exception as exc:
            LOGGER.debug("job reaper: could not add event to job %s: %s", job_id, exc)
    if orphaned:
        LOGGER.warning(
            "job reaper: marked %d orphaned running job(s) as failed: %s",
            len(orphaned),
            orphaned,
        )
    await _process_job_queue()


async def drain_running_jobs(grace_seconds: float | None = None) -> None:
    """Wait for in-flight job tasks to finish on shutdown (SIGTERM).

    Gives a firmware push / config deploy a brief grace window to complete
    rather than being severed mid-device-write when the event loop tears
    down. Jobs still running after the window are left as-is; the next-boot
    reaper (reap_and_resume_jobs) reconciles them. We do NOT cancel them -
    cancelling mid-write is worse than a clean process exit + restart reap.
    """
    global _shutting_down
    _shutting_down = True  # stop the done-callback from launching new jobs
    if grace_seconds is None:
        grace_seconds = float(os.getenv("APP_SHUTDOWN_JOB_GRACE_SECONDS", "15"))
    async with _running_tasks_lock:
        tasks = list(_running_job_tasks.values())
    if not tasks:
        return
    LOGGER.info(
        "shutdown: waiting up to %.0fs for %d in-flight job(s) to finish",
        grace_seconds,
        len(tasks),
    )
    _, pending = await asyncio.wait(tasks, timeout=grace_seconds)
    if pending:
        LOGGER.warning(
            "shutdown: %d job(s) still running after the grace window; "
            "they will be reconciled by the reaper on next boot",
            len(pending),
        )


async def _process_job_queue_inner():
    if _shutting_down:
        # Don't start new work while the process is draining for shutdown.
        return
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
    LOGGER.info(
        "Queue: processing job %d (playbook_id=%s, group_id=%s, host_ids=%s, ad_hoc_ips=%s)",
        job_id,
        next_job.get("playbook_id"),
        next_job.get("inventory_group_id"),
        next_job.get("host_ids"),
        next_job.get("ad_hoc_ips"),
    )

    # Fetch all the info needed to run this job
    playbook = await db.get_playbook(next_job["playbook_id"])
    if not playbook:
        await db.finish_job(job_id, status="failed")
        await db.add_job_event(job_id, "error", "Playbook not found")
        return

    hosts = await _resolve_job_hosts(next_job)

    # Reconstruct ad-hoc host dicts from stored IPs
    if next_job.get("ad_hoc_ips"):
        try:
            ad_hoc_list = json.loads(next_job["ad_hoc_ips"])
            for ip in ad_hoc_list:
                hosts.append(
                    {
                        "id": None,
                        "hostname": ip,
                        "ip_address": ip,
                        "device_type": "cisco_ios",
                        "group_id": None,
                    }
                )
        except (json.JSONDecodeError, TypeError) as exc:
            LOGGER.warning("job %s: failed to parse stored ad_hoc_ips: %s", job_id, exc)

    if not hosts:
        await db.finish_job(job_id, status="failed")
        await db.add_job_event(job_id, "error", "No hosts found for this job")
        return

    # Get credentials - use job-specific, then app-wide default.  Revalidate
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
        await db.add_job_event(
            job_id,
            "error",
            "No credential configured - set a default credential in Settings or select one when launching the job",
        )
        return

    # Get template commands.  ``template_commands`` is the flat generic
    # body used by every legacy playbook.  ``template_by_device_type``
    # maps each distinct host device_type in this job to the body that
    # resolve_template_for_device_type() picked for it (vendor-specific
    # variant, else the generic sibling) - so a mixed-vendor group runs
    # the right SNMPv3 syntax per host from one selected template.
    template_commands = []
    template_by_device_type: dict[str, list[str]] = {}
    if next_job.get("template_id"):
        tpl = await db.get_template(next_job["template_id"])
        if tpl:
            template_commands = _template_lines(tpl["content"])
            # Resolve the per-device_type bodies.  This runs on the
            # queued→running critical path, so do it off exactly two
            # queries: the selected row (above) plus every row sharing
            # its name, then resolve each device_type in memory with
            # the same rule as resolve_template_for_device_type().
            # (Looping that DB call once per device_type instead would
            # cost ~3 database round-trips each - the launch
            # latency the operator reported.)
            variants = await db.get_template_variants(tpl["name"])
            seen_dts = {h.get("device_type") or "" for h in hosts}
            for dt in seen_dts:
                resolved = db.resolve_variant_in_memory(tpl, variants, dt)
                template_by_device_type[dt] = _template_lines(resolved["content"])

    # Resolve {{secret.NAME}} placeholders in every command body (the
    # flat one and each per-device_type variant).  Secrets are resolved
    # before any device is touched; a single missing secret fails the
    # whole job rather than silently shipping an unresolved placeholder
    # to a subset of hosts.
    _secret_redact_values: set[str] = set()
    _all_bodies = [template_commands, *template_by_device_type.values()]
    _needs_secrets = any(b and has_secret_references("\n".join(b)) for b in _all_bodies)
    if _needs_secrets:
        try:
            for body in _all_bodies:
                if body and has_secret_references("\n".join(body)):
                    _secret_redact_values |= await build_redaction_set(body)
            if template_commands:
                template_commands = await resolve_secrets(template_commands)
            for dt, body in list(template_by_device_type.items()):
                if body:
                    template_by_device_type[dt] = await resolve_secrets(body)
            await db.add_job_event(job_id, "info", "Secret variables resolved successfully")
        except SecretResolutionError as exc:
            await db.finish_job(job_id, status="failed")
            await db.add_job_event(
                job_id,
                "error",
                f"Template references undefined secret variable(s): {', '.join(exc.missing)}. "
                "Create them in Credentials → Secret Variables before running this job.",
            )
            return

    # Resolve dry_run: the DB stores 1/0; treat NULL or missing as dry-run (safe default)
    raw_dry_run = next_job.get("dry_run")
    dry_run = raw_dry_run != 0  # Only False when explicitly stored as 0
    LOGGER.info(
        "job %s: dry_run raw=%r resolved=%s playbook=%s hosts=%d",
        job_id,
        raw_dry_run,
        dry_run,
        playbook.get("name", "?"),
        len(hosts),
    )

    # Record the mode as the first job event so it's always visible in output
    mode_label = (
        "DRY-RUN (simulation only - no changes will be made)" if dry_run else "LIVE MODE - changes WILL be applied"
    )
    await db.add_job_event(job_id, "info", f"Job mode: {mode_label}")

    pb_type = playbook.get("type", "python")

    # Typed inputs are stored with secret fields as {{secret.NAME}}
    # references; decrypt them only now, and scrub the values from the log.
    try:
        job_parameters, input_redact = await job_inputs.resolve_secret_inputs(
            _stored_params(next_job.get("parameters"))
        )
    except SecretResolutionError as exc:
        await db.finish_job(job_id, status="failed")
        await db.add_job_event(
            job_id,
            "error",
            f"Job input references undefined secret variable(s): {', '.join(exc.missing)}.",
        )
        return
    _secret_redact_values |= input_redact

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
        if not await db.start_job(job_id):
            # Lost the queued→running transition (concurrent kick or cancel):
            # someone else owns this job now — do not launch a second runner.
            LOGGER.warning("Queue: job %d was no longer queued at start; skipping launch", job_id)
            return
        task = asyncio.create_task(
            _run_ansible_job(
                job_id,
                playbook["content"],
                hosts,
                credentials,
                group_name,
                dry_run,
                extra_vars=job_parameters,
                secret_redact_values=_secret_redact_values,
            )
        )
    else:
        # ── Python playbook path ──
        pb_class = get_playbook_class(playbook["filename"])
        if not pb_class:
            await db.finish_job(job_id, status="failed")
            await db.add_job_event(job_id, "error", f"No runner for '{playbook['filename']}'")
            return
        if not await db.start_job(job_id):
            LOGGER.warning("Queue: job %d was no longer queued at start; skipping launch", job_id)
            return
        task = asyncio.create_task(
            _run_job(
                job_id,
                pb_class,
                hosts,
                credentials,
                template_commands,
                dry_run,
                _secret_redact_values,
                job_parameters,
                template_by_device_type,
            )
        )
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
    extra_vars: dict | None = None,
    secret_redact_values: set[str] | None = None,
):
    """Background task: execute Ansible playbook, store events, broadcast via WebSocket."""
    event_writer = _JobEventWriter(job_id)
    _redact = secret_redact_values or set()

    async def on_event(event: LogEvent):
        if _redact:
            event = LogEvent(
                level=event.level,
                message=redact_values(event.message, _redact),
                host=event.host,
                timestamp=event.timestamp,
            )
        event_writer.enqueue(event)
        await _broadcast_to_job_sockets(job_id, event.to_dict())

    job_succeeded = False
    try:
        result = await execute_ansible_playbook(
            playbook_content=playbook_content,
            hosts=hosts,
            credentials=credentials,
            group_name=group_name,
            dry_run=dry_run,
            extra_vars=extra_vars or None,
            event_callback=on_event,
        )
        await event_writer.close()
        await db.finish_job(
            job_id,
            status=result.status,
            hosts_ok=result.hosts_ok,
            hosts_failed=result.hosts_failed,
            hosts_skipped=result.hosts_skipped,
        )
        job_succeeded = result.status == "success"
    except asyncio.CancelledError:
        try:
            event = LogEvent(level="warning", message="Job cancelled by user")
            if event_writer.closed:
                await db.add_job_event(job_id, event.level, event.message, event.host)
            else:
                await on_event(event)
            await event_writer.close()
        except Exception:
            LOGGER.exception("job %s: failed to persist Ansible cancellation event", job_id)
        await db.cancel_job(job_id, "system")
    except Exception as e:
        try:
            await on_event(LogEvent(level="error", message=f"Fatal error: {e}"))
            await event_writer.close()
        except Exception:
            LOGGER.exception("job %s: failed to persist final Ansible event batch", job_id)
        await db.finish_job(job_id, status="failed", hosts_failed=len(hosts))
    finally:
        try:
            await event_writer.close()
        except Exception:
            LOGGER.exception("job %s: failed to close Ansible event writer", job_id)

    # Notify WebSocket clients that job is done
    await _broadcast_to_job_sockets(job_id, {"type": "job_complete", "job_id": job_id, "status": "done"})
    async with _job_sockets_lock:
        _job_sockets.pop(job_id, None)

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
    parameters: dict | None = None,
    template_by_device_type: dict[str, list[str]] | None = None,
):
    """Background task: execute playbook, store events, broadcast via WebSocket."""
    hosts_ok = 0
    hosts_failed = 0
    _redact = secret_redact_values or set()
    event_writer = _JobEventWriter(job_id)

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

        # Queue persistence without blocking playbook execution on a commit.
        event_writer.enqueue(event)

        # Track host results
        if event.level == "success" and "Finished processing" in event.message:
            hosts_ok += 1
        elif event.level == "error" and event.host:
            hosts_failed += 1

        # Broadcast to WebSocket subscribers
        await _broadcast_to_job_sockets(job_id, event.to_dict())

    job_succeeded = False
    try:
        result = await execute_playbook(
            pb_class,
            hosts,
            credentials,
            template_commands,
            dry_run,
            on_event,
            parameters=parameters,
            template_by_device_type=template_by_device_type,
        )
        await event_writer.close()
        await db.finish_job(
            job_id,
            status=result.status,
            hosts_ok=hosts_ok,
            hosts_failed=hosts_failed,
            hosts_skipped=result.hosts_skipped,
        )
        job_succeeded = result.status == "success"
    except asyncio.CancelledError:
        try:
            event = LogEvent(level="warning", message="Job cancelled by user")
            if event_writer.closed:
                await db.add_job_event(job_id, event.level, event.message, event.host)
            else:
                await on_event(event)
            await event_writer.close()
        except Exception:
            LOGGER.exception("job %s: failed to persist cancellation event", job_id)
        await db.cancel_job(job_id, "system")
    except Exception as e:
        try:
            await on_event(LogEvent(level="error", message=f"Fatal error: {e}"))
            await event_writer.close()
        except Exception:
            LOGGER.exception("job %s: failed to persist final event batch", job_id)
        await db.finish_job(job_id, status="failed", hosts_failed=len(hosts))
    finally:
        try:
            await event_writer.close()
        except Exception:
            LOGGER.exception("job %s: failed to close event writer", job_id)

    # Notify WebSocket clients that job is done
    await _broadcast_to_job_sockets(job_id, {"type": "job_complete", "job_id": job_id, "status": "done"})
    async with _job_sockets_lock:
        _job_sockets.pop(job_id, None)

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
async def get_job(job_id: int, request: Request):
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    await require_owner_or_admin(request, job.get("launched_by"))
    return job


@router.get("/api/jobs/{job_id}/events")
async def get_job_events(job_id: int, request: Request, limit: int = Query(default=10000, ge=1, le=100000)):
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    await require_owner_or_admin(request, job.get("launched_by"))
    return await db.get_job_events(job_id, limit)


@router.post("/api/jobs/launch", status_code=201)
async def launch_job(body: JobLaunch, request: Request):
    """
    Launch a playbook execution as a background task.
    Returns the job ID immediately. Connect to the WebSocket
    at /ws/jobs/{job_id} to stream real-time output.
    """
    session = _get_session(request)
    LOGGER.debug(
        "JobLaunch request: playbook_id=%s host_ids=%s inventory_group_id=%s",
        body.playbook_id,
        body.host_ids,
        body.inventory_group_id,
    )

    # Validate playbook exists
    playbook = await db.get_playbook(body.playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    # Ansible playbooks can execute arbitrary code - restrict to admin only
    if playbook.get("type") == "ansible" and _require_admin:
        await _require_admin(request)

    # ``commit`` wins over the legacy ``dry_run`` flag; a dry run is the default.
    dry_run = (not body.commit) if body.commit is not None else body.dry_run
    if dry_run and not playbook_supports_dry_run(playbook):
        raise HTTPException(
            422,
            detail={
                "message": f"'{playbook['name']}' has no dry-run mode; run it with commit after confirming.",
                "fields": {"commit": "This job cannot preview changes; it must be run with commit."},
            },
        )
    await _require_job_permission(request, playbook, commit=not dry_run)

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
    elif body.dynamic_group_id:
        # Checked now so the caller hears about an unknown or empty group;
        # the hosts are resolved again when the job starts.
        resolved = await resolve_group(body.dynamic_group_id, await request_scope(request))
        if resolved is None:
            raise HTTPException(404, "Dynamic group not found")
        if not resolved:
            raise HTTPException(400, "The dynamic group matches no hosts")
        hosts = resolved

    # Build synthetic host dicts for ad-hoc IPs
    if body.ad_hoc_ips:
        for ip in body.ad_hoc_ips:
            ip = ip.strip()
            if ip:
                _validate_ad_hoc_ip(ip)
                ad_hoc_hosts.append(
                    {
                        "id": None,
                        "hostname": ip,
                        "ip_address": ip,
                        "device_type": "cisco_ios",
                        "group_id": None,
                    }
                )
        hosts = hosts + ad_hoc_hosts

    if not hosts:
        raise HTTPException(400, "Must specify host_ids, ad_hoc_ips, inventory_group_id or dynamic_group_id")

    # Get credentials - use job-specific, then app-wide default.  The default
    # credential is only usable by callers who actually own it (or are admin);
    # it does not grant regular users implicit access to another user's creds.
    cred_id = body.credential_id or state.AUTH_CONFIG.get("default_credential_id")
    if not cred_id:
        raise HTTPException(
            400, "No credential configured - set a default credential in Settings or select one when launching the job"
        )
    cred = await require_credential_access(cred_id, session=session)
    credentials = {
        "username": cred["username"],
        "password": decrypt(cred["password"]),
        "secret": decrypt(cred["secret"]) if cred["secret"] else "",
    }

    # Get template commands.  This is the pre-launch validation path:
    # it only checks that secret references resolve before the job is
    # queued.  Per-device_type variants are resolved at execution time
    # in _run_job, but a vendor-specific body can reference its own
    # secrets, so validate across every variant of the selected
    # template (by name) - not just the row the operator clicked.
    template_commands = []
    if body.template_id:
        tpl = await db.get_template(body.template_id)
        if tpl:
            template_commands = _template_lines(tpl["content"])
            for variant in await db.get_template_variants(tpl["name"]):
                template_commands += _template_lines(variant["content"])

    # Validate that all {{secret.NAME}} references can be resolved
    if template_commands and has_secret_references("\n".join(template_commands)):
        try:
            # Dry-resolve (redacted) to verify all secrets exist without
            # decrypting yet - actual decryption happens at execution time.
            await resolve_secrets(template_commands, redact=True)
        except SecretResolutionError as exc:
            raise HTTPException(
                400,
                f"Template references undefined secret variable(s): {', '.join(exc.missing)}. "
                "Create them in Credentials \u2192 Secret Variables before launching.",
            )

    # Validate the playbook can be executed
    pb_type = playbook.get("type", "python")
    pb_class = None
    if pb_type == "ansible":
        if not ANSIBLE_RUNNER_AVAILABLE:
            raise HTTPException(400, "Ansible runner is not installed on the server")
        if not playbook.get("content", "").strip():
            raise HTTPException(400, "Ansible playbook has no YAML content")
    else:
        pb_class = get_playbook_class(playbook["filename"])
        if not pb_class:
            raise HTTPException(400, f"No runner registered for '{playbook['filename']}'")

    # Validate the typed inputs against the playbook's schema (stored on the
    # row, else declared on the Python class) at launch, so the user sees
    # every error at once instead of mid-run in the job log. Host, group and
    # secret inputs must exist; secrets are stored as references only.
    schema, _source = effective_input_schema(playbook)
    raw_inputs = body.inputs if body.inputs is not None else (body.parameters or {})
    coerced_params = _coerce_parameters(schema, raw_inputs)
    try:
        coerced_params = await job_inputs.resolve_references(schema, coerced_params)
    except job_inputs.JobInputError as exc:
        raise _input_error(exc)

    launched_by = session["user"] if session else "admin"
    priority = max(0, min(4, body.priority))
    # Store specific host_ids so the queue processor targets only selected
    # hosts; a dynamic group stores the group instead (resolved at run time).
    dynamic_group_id = body.dynamic_group_id if not body.host_ids and not body.inventory_group_id else None
    selected_host_ids = None if dynamic_group_id else [h["id"] for h in hosts if h.get("id") is not None] or None
    # Store ad-hoc IPs separately so the queue processor can reconstruct them
    stored_ad_hoc = [ip.strip() for ip in body.ad_hoc_ips if ip.strip()] if body.ad_hoc_ips else None
    job_id = await db.create_job(
        body.playbook_id,
        inventory_group_id,
        body.credential_id,
        body.template_id,
        dry_run,
        launched_by=launched_by,
        priority=priority,
        depends_on=body.depends_on,
        host_ids=selected_host_ids,
        ad_hoc_ips=stored_ad_hoc,
        parameters=coerced_params,
        dynamic_group_id=dynamic_group_id,
    )

    # Trigger queue processor to potentially start this job immediately
    asyncio.ensure_future(_process_job_queue())

    await _audit(
        "jobs",
        "job.launch",
        user=launched_by,
        detail=(
            f"queued job {job_id} playbook='{playbook['name']}' hosts={len(hosts)} "
            f"mode={'dry-run' if dry_run else 'commit'} dry_run={dry_run} priority={priority} "
            f"inputs={sorted(coerced_params)}"
        ),
        correlation_id=_corr_id(request),
    )
    return {"job_id": job_id, "status": "queued"}


@router.post("/api/jobs/{job_id}/cancel")
async def cancel_job_endpoint(job_id: int, request: Request):
    """Cancel a queued or running job."""
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] not in _ACTIVE_JOB_STATUSES:
        raise HTTPException(400, f"Cannot cancel job with status '{job['status']}'")

    await require_owner_or_admin(request, job.get("launched_by"))
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
            # Timeout so one wedged client socket can't stall job teardown.
            await asyncio.wait_for(ws.send_json(done_msg), timeout=5)
        except Exception as exc:
            LOGGER.debug("job %s: failed to send job_complete to WS client: %s", job_id, exc)

    await _audit("jobs", "job.cancelled", user=user, detail=f"cancelled job {job_id}", correlation_id=_corr_id(request))

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

    await require_owner_or_admin(request, job.get("launched_by"))
    playbook = await db.get_playbook(job["playbook_id"])
    if playbook:
        await _require_job_permission(request, playbook, commit=not bool(job.get("dry_run", 1)))
    session = _get_session(request)
    user = session["user"] if session else "admin"

    new_job_id = await queue_job_from_spec(job_clone_spec(job), dry_run=bool(job.get("dry_run", 1)), launched_by=user)

    await _audit(
        "jobs",
        "job.retry",
        user=user,
        detail=f"retried job {job_id} as new job {new_job_id}",
        correlation_id=_corr_id(request),
    )
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
    if job["status"] in _ACTIVE_JOB_STATUSES:
        raise HTTPException(400, f"Job is still {job['status']} - wait for it to finish first")

    await require_owner_or_admin(request, job.get("launched_by"))
    playbook = await db.get_playbook(job["playbook_id"])
    if playbook:
        await _require_job_permission(request, playbook, commit=True)
    session = _get_session(request)
    user = session["user"] if session else "admin"

    new_job_id = await queue_job_from_spec(job_clone_spec(job), dry_run=False, launched_by=user)

    await _audit(
        "jobs",
        "job.rerun_live",
        user=user,
        detail=f"re-ran job {job_id} as live job {new_job_id}",
        correlation_id=_corr_id(request),
    )
    return {"job_id": new_job_id, "status": "queued", "rerun_from": job_id}


@router.patch("/api/jobs/{job_id}/priority")
async def update_job_priority_endpoint(job_id: int, body: dict, request: Request):
    """Change the priority of a queued job."""
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != "queued":
        raise HTTPException(400, "Can only change priority of queued jobs")
    await require_owner_or_admin(request, job.get("launched_by"))
    new_priority = body.get("priority")
    if new_priority is None or not isinstance(new_priority, int):
        raise HTTPException(400, "priority (int 0-4) required")

    ok = await db.update_job_priority(job_id, new_priority)
    if not ok:
        raise HTTPException(400, "Failed to update priority")

    session = _get_session(request)
    await _audit(
        "jobs",
        "job.priority_changed",
        user=session["user"] if session else "",
        detail=f"job {job_id} priority={new_priority}",
        correlation_id=_corr_id(request),
    )
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
    session = await verify_ws_session(token)
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

    # Object-level authorization: only the job's owner (or an admin) may
    # stream its output, which routinely contains device configs/output.
    job = await db.get_job(job_id)
    if not job:
        await websocket.close(code=1008)
        return
    if user.get("role") != "admin" and job.get("launched_by") != session.get("user"):
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # Send historical events first. Replay is capped to the most recent
    # lines - a verbose multi-host job can log tens of thousands, and
    # replaying them one frame at a time stalled the event loop on every
    # page open. Full history: GET /api/jobs/{id}/events.
    events = await db.get_job_events(job_id, limit=_WS_HISTORY_REPLAY_LIMIT)
    for event in events:
        await websocket.send_text(
            json.dumps(
                {
                    "level": event["level"],
                    "message": event["message"],
                    "host": event["host"],
                    "timestamp": event["timestamp"],
                }
            )
        )

    # Already finished: say so and close. A queued job is not finished - it
    # is waiting for a worker slot - so it subscribes like a running one
    # (treating it as done closed the stream before the job even started).
    if job["status"] not in _ACTIVE_JOB_STATUSES:
        await websocket.send_json({"type": "job_complete", "job_id": job_id, "status": job["status"]})
        await websocket.close()
        return

    # Subscribe to live events
    async with _job_sockets_lock:
        if job_id not in _job_sockets:
            _job_sockets[job_id] = []
        _job_sockets[job_id].append(websocket)

    # A short job can finish between the status read above and this
    # subscription, so its final lines and job_complete broadcast went to
    # nobody. Re-check now: send what was logged after the replay, then
    # job_complete, instead of leaving the viewer waiting on a dead stream.
    latest = await db.get_job(job_id)
    if latest and latest["status"] not in _ACTIVE_JOB_STATUSES:
        last_id = max((int(e["id"]) for e in events if e.get("id") is not None), default=0)
        missed = [
            e
            for e in await db.get_job_events(job_id, limit=_WS_HISTORY_REPLAY_LIMIT)
            if e.get("id") is not None and int(e["id"]) > last_id
        ]
        try:
            for event in missed:
                await websocket.send_text(
                    json.dumps(
                        {
                            "level": event["level"],
                            "message": event["message"],
                            "host": event["host"],
                            "timestamp": event["timestamp"],
                        }
                    )
                )
            await websocket.send_json({"type": "job_complete", "job_id": job_id, "status": latest["status"]})
            await websocket.close()
        except Exception as exc:
            LOGGER.debug("job %s: WS client gone before late completion was sent: %s", job_id, exc)
        finally:
            async with _job_sockets_lock:
                if job_id in _job_sockets and websocket in _job_sockets[job_id]:
                    _job_sockets[job_id].remove(websocket)
        return

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
    except WebSocketDisconnect as exc:
        LOGGER.debug("job %s: WS client disconnected: %s", job_id, exc)
    finally:
        async with _job_sockets_lock:
            if job_id in _job_sockets and websocket in _job_sockets[job_id]:
                _job_sockets[job_id].remove(websocket)
