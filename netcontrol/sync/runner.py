"""Run a stored sync job, test a connection, and the scheduler loop.

``run_job`` opens the job's connection (the token, password or OAuth client
secret is read from the connection's service credential and decrypted only
here), then per object type of the job, in dependency order: loads both
sides, diffs them (``engine.diff_records``), plans the entries for the job's
direction and conflict policy, and - unless it is a dry run - applies them
(Plexus first, then the remote system). The run row records the summary per
object type and every entry with its outcome; the job keeps its last run.
One run of a job at a time.

``sync_jobs_loop`` is registered with the other background loops in
``netcontrol.app``: every ``CHECK_INTERVAL_SECONDS`` it runs each enabled job
whose ``interval_minutes`` has passed since its last scheduled attempt.

``transport_for`` and ``guard_for`` exist so tests can put an
``httpx.MockTransport`` and a no-op SSRF guard under the adapters.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
import routes.database as db
import routes.db.sync as sync_db
from routes.crypto import decrypt
from routes.db.change_events import current_actor

from netcontrol.routes.outbound_http import tls_verify
from netcontrol.routes.shared import _audit
from netcontrol.sync.adapters.base import RestAdapter
from netcontrol.sync.adapters.netbox import NautobotAdapter, NetBoxAdapter
from netcontrol.sync.adapters.plexus import DEFAULT_HOST_GROUP, PlexusAdapter
from netcontrol.sync.adapters.servicenow import ServiceNowAdapter
from netcontrol.sync.engine import Entry, diff_records, plan_entries, summarise
from netcontrol.sync.models import OBJECT_TYPES, MappingError
from netcontrol.sync.transport import Guard, HttpJsonClient, SyncError
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.sync")

CHECK_INTERVAL_SECONDS = 60
FIRST_RUN_DELAY_SECONDS = 90
_TIMESTAMP = "%Y-%m-%d %H:%M:%S"

_locks: dict[int, asyncio.Lock] = {}


class JobBusy(RuntimeError):
    """The job is already running."""


def transport_for(connection: dict) -> httpx.AsyncBaseTransport | None:
    """The transport under a connection's client (``None``: the network)."""
    return None


def guard_for(connection: dict) -> Guard | None:
    """The SSRF guard of a connection's client (``None``: the default)."""
    return None


# ── Connections ──────────────────────────────────────────────────────────────


async def connection_secret(connection: dict) -> tuple[str, str]:
    """``(username, secret)`` of the connection's service credential."""
    cred_id = connection.get("credential_id")
    if cred_id is None:
        raise SyncError("The connection has no credential; pick a service credential.")
    cred = await db.get_credential_raw(int(cred_id))
    if not cred or not cred.get("is_service"):
        raise SyncError("The connection's credential is gone or is not a service credential.")
    try:
        secret = decrypt(cred["password"]) if cred.get("password") else ""
    except RuntimeError as exc:
        raise SyncError("The connection's credential cannot be decrypted.") from exc
    return str(cred.get("username") or ""), secret


def build_remote(
    connection: dict, username: str, secret: str, mappings: dict[str, dict[str, Any]] | None = None
) -> RestAdapter:
    """The adapter of a connection (not yet opened)."""
    kind = connection["kind"]
    auth_type = connection["auth_type"]
    headers: dict[str, str] = {}
    auth: Any = None
    oauth: tuple[str, str] | None = None
    if auth_type == "token":
        if not secret:
            raise SyncError("The credential has no token (store the API token as its password).")
        headers["Authorization"] = f"Token {secret}"
    elif auth_type == "basic":
        auth = (username, secret)
    elif auth_type == "oauth":
        oauth = (username, secret)
    else:
        raise SyncError(f"Unknown auth type {auth_type!r}.")
    try:
        verify = tls_verify(bool(connection.get("verify_tls", True)), connection.get("ca_pem", ""))
    except Exception as exc:  # ssl.SSLError for a bundle that does not parse
        raise SyncError("The connection's CA bundle is not valid PEM.") from exc
    label = {"netbox": "NetBox", "nautobot": "Nautobot", "servicenow": "ServiceNow"}.get(kind, kind)
    client = HttpJsonClient(
        connection["base_url"],
        headers=headers,
        auth=auth,
        verify=verify,
        timeout=float(connection.get("timeout_seconds") or 30),
        transport=transport_for(connection),
        guard=guard_for(connection),
        label=label,
    )
    if kind == "netbox":
        return NetBoxAdapter(client, mappings)
    if kind == "nautobot":
        return NautobotAdapter(client, mappings)
    if kind == "servicenow":
        return ServiceNowAdapter(client, mappings, oauth=oauth)
    raise SyncError(f"Unknown connection kind {kind!r}.")


ADAPTER_CLASSES: dict[str, type[RestAdapter]] = {
    "netbox": NetBoxAdapter,
    "nautobot": NautobotAdapter,
    "servicenow": ServiceNowAdapter,
}


def check_job_mapping(kind: str, object_types: list[str], mappings: dict[str, dict[str, Any]]) -> None:
    """``MappingError`` when the job's mapping does not resolve against the
    connection kind's defaults, or a type has no endpoint."""
    # Mapping resolution never touches the client: a probe without one.
    probe = ADAPTER_CLASSES[kind](cast(HttpJsonClient, None), mappings)
    for object_type in object_types:
        if not probe.supports(object_type):
            raise MappingError(f"{probe.label} has no default table for {object_type}; set _endpoint in the mapping.")
        probe.mapping(object_type)
        probe.endpoint(object_type)


def default_mappings() -> dict[str, dict[str, dict[str, Any]]]:
    """Per connection kind and object type: the endpoint, the default
    paths, the read-only fields and the optional fields (for the UI)."""
    from netcontrol.sync.models import OBJECT_SPECS

    out: dict[str, dict[str, dict[str, Any]]] = {}
    for kind, cls in ADAPTER_CLASSES.items():
        out[kind] = {}
        for object_type, spec in OBJECT_SPECS.items():
            defaults = cls.DEFAULTS.get(object_type, {})
            out[kind][object_type] = {
                "endpoint": defaults.get("endpoint", ""),
                "paths": dict(defaults.get("paths", {})),
                "read_only": sorted(defaults.get("read_only", ())),
                "optional": sorted(spec.optional),
            }
    return out


_PING: dict[str, tuple[str, dict[str, Any]]] = {
    "netbox": ("api/dcim/manufacturers/", {"limit": 1}),
    "nautobot": ("api/dcim/manufacturers/", {"limit": 1}),
    "servicenow": ("api/now/table/cmdb_ci_netgear", {"sysparm_limit": 1, "sysparm_fields": "sys_id"}),
}


async def test_connection(connection_id: int) -> dict:
    """Sign in and read one record; stores and returns ``{ok, message}``."""
    connection = await sync_db.get_connection(connection_id, with_ca=True)
    if connection is None:
        raise LookupError("connection")
    try:
        username, secret = await connection_secret(connection)
        adapter = build_remote(connection, username, secret)
        async with adapter:
            path, params = _PING[connection["kind"]]
            await adapter.client.get(path, params)
        ok, message = True, f"Signed in to {adapter.label} and read the API."
    except SyncError as exc:
        ok, message = False, str(exc)
    except Exception as exc:
        LOGGER.warning("sync connection %s test failed: %s", connection_id, type(exc).__name__)
        ok, message = False, f"The test failed ({type(exc).__name__})."
    await sync_db.set_connection_test(connection_id, ok=ok, message=message)
    return {"ok": ok, "message": message}


# ── Runs ─────────────────────────────────────────────────────────────────────


def is_running(job_id: int) -> bool:
    lock = _locks.get(int(job_id))
    return lock is not None and lock.locked()


async def start_run(job: dict, *, dry_run: bool, trigger: str, user: str) -> dict:
    """Create the run row (``running``); ``JobBusy`` when one is running."""
    if is_running(job["id"]):
        raise JobBusy(f"The job '{job['name']}' is already running.")
    return await sync_db.create_run(job["id"], dry_run=dry_run, trigger=trigger, user=user)


async def _sync_type(
    object_type: str,
    remote: RestAdapter,
    plexus: PlexusAdapter,
    job: dict,
    dry_run: bool,
) -> tuple[list[Entry], dict[str, Any]]:
    remote_records = await remote.load(object_type)
    plexus_records = await plexus.load(object_type)
    fields = remote.fields(object_type)
    diff = diff_records(object_type, remote_records, plexus_records, fields)
    entries = plan_entries(
        diff,
        direction=job["direction"],
        policy=job["conflict_policy"],
        delete_missing=bool(job["delete_missing"]) and job["direction"] != "bidirectional",
        writable_plexus=plexus.writable(object_type) & set(fields),
        writable_remote=remote.writable(object_type),
    )
    to_plexus = [e for e in entries if e.target == "plexus" and e.outcome == "planned" and e.action != "conflict"]
    to_remote = [e for e in entries if e.target == "remote" and e.outcome == "planned"]
    await plexus.apply(object_type, to_plexus)
    if not dry_run:
        await remote.apply(object_type, to_remote)
    summary: dict[str, Any] = summarise(entries, diff)
    summary["fields"] = list(fields)
    if diff.duplicates:
        summary["warnings"] = diff.duplicates[:20]
    return entries, summary


async def execute_run(job_id: int, run_id: int, *, dry_run: bool, user: str) -> dict | None:
    """Run the job into the existing run row and finish it."""
    lock = _locks.setdefault(int(job_id), asyncio.Lock())
    async with lock:
        job = await sync_db.get_job(job_id)
        entries: list[Entry] = []
        summary: dict[str, Any] = {}
        status, message = "success", ""
        token = current_actor.set(user if user and user != "system" else f"sync:{job['name'] if job else job_id}")
        try:
            if job is None:
                raise SyncError("The job no longer exists.")
            connection = await sync_db.get_connection(job["connection_id"], with_ca=True)
            if connection is None:
                raise SyncError("The job's connection no longer exists.")
            username, secret = await connection_secret(connection)
            remote = build_remote(connection, username, secret, job["mappings"])
            plexus = PlexusAdapter(
                user=user or "system",
                dry_run=dry_run,
                host_group=str(job["options"].get("host_group") or DEFAULT_HOST_GROUP),
            )
            async with remote:
                for object_type in OBJECT_TYPES:
                    if object_type not in job["object_types"]:
                        continue
                    if not remote.supports(object_type):
                        summary[object_type] = {"error": f"{remote.label} has no {object_type} table; set _endpoint."}
                        status = "partial"
                        continue
                    try:
                        type_entries, type_summary = await _sync_type(object_type, remote, plexus, job, dry_run)
                    except (SyncError, MappingError) as exc:
                        summary[object_type] = {"error": str(exc)}
                        status = "partial"
                        continue
                    entries.extend(type_entries)
                    summary[object_type] = type_summary
            if any(e.outcome == "failed" for e in entries):
                status = "partial"
            if summary and all("error" in s for s in summary.values()):
                status = "failed"
        except (SyncError, MappingError) as exc:
            status, message = "failed", str(exc)
        except Exception as exc:
            LOGGER.exception("sync job %s run %s failed", job_id, run_id)
            status, message = "failed", f"The run failed ({type(exc).__name__})."
        finally:
            current_actor.reset(token)
        if not message:
            message = _message(entries, dry_run, status)
        run = await sync_db.finish_run(
            run_id, status=status, summary=summary, message=message, entries=(e.as_dict() for e in entries)
        )
        await sync_db.prune_runs(job_id)
    totals = {k: sum(int(s.get(k, 0)) for s in summary.values()) for k in ("create", "update", "delete", "failed")}
    await _audit(
        "sync",
        "dry_run" if dry_run else "run",
        user=user or "system",
        detail=f"job_id={job_id} run_id={run_id} status={status} " + " ".join(f"{k}={v}" for k, v in totals.items()),
    )
    return run


def _message(entries: list[Entry], dry_run: bool, status: str) -> str:
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.outcome] = counts.get(entry.outcome, 0) + 1
    if not entries:
        return "Both sides already match." if status != "failed" else "The run failed."
    if dry_run:
        return f"Dry run: {len(entries)} change(s) planned; nothing was written."
    parts = [f"{counts.get(k, 0)} {k}" for k in ("applied", "failed", "skipped") if counts.get(k)]
    return "Run finished: " + ", ".join(parts) + "."


async def run_job(job_id: int, *, dry_run: bool, trigger: str = "manual", user: str = "") -> dict | None:
    """Start and finish a run of the job (the scheduler's and the tests'
    entry point; the API starts the run then executes it after answering)."""
    job = await sync_db.get_job(job_id)
    if job is None:
        raise LookupError("job")
    run = await start_run(job, dry_run=dry_run, trigger=trigger, user=user)
    return await execute_run(job_id, run["id"], dry_run=dry_run, user=user)


# ── Scheduler ────────────────────────────────────────────────────────────────


def is_due(job: dict, now: datetime) -> bool:
    interval = int(job.get("interval_minutes") or 0)
    if not job.get("enabled") or interval <= 0:
        return False
    last = job.get("last_attempt_at") or ""
    if not last:
        return True
    try:
        at = datetime.strptime(last, _TIMESTAMP).replace(tzinfo=UTC)
    except ValueError:
        return True
    return now - at >= timedelta(minutes=interval)


async def run_due_jobs(now: datetime | None = None) -> list[int]:
    """Run every due job (one after another); the ids run."""
    now = now or datetime.now(UTC)
    ran: list[int] = []
    for job in await sync_db.list_jobs():
        if not is_due(job, now) or is_running(job["id"]):
            continue
        await sync_db.claim_job_attempt(job["id"])
        try:
            await run_job(job["id"], dry_run=False, trigger="schedule", user="")
            ran.append(job["id"])
        except LookupError, JobBusy:
            continue
    return ran


async def sync_jobs_loop() -> None:
    """Fail runs a stopped server left running, then check for due jobs
    every ``CHECK_INTERVAL_SECONDS``."""
    try:
        await sync_db.fail_stale_runs()
    except Exception as exc:
        LOGGER.warning("sync: could not close interrupted runs: %s", type(exc).__name__)
    await asyncio.sleep(FIRST_RUN_DELAY_SECONDS)
    while True:
        try:
            await run_due_jobs()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("sync scheduler loop failed: %s", type(exc).__name__)
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
