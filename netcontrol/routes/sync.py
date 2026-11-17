"""Sync framework API: connections, jobs, runs (with per-object entries),
dry runs and runs now.

``router`` is registered in ``app.py`` behind ``require_auth`` and
``require_feature_method("sync")``: read with ``sync``; ``sync.write`` adds,
edits and deletes jobs and runs them. ``admin_router`` (connections: add,
edit, delete, test) is admin only, because a connection binds a Plexus
service credential. A job that writes into Plexus (direction ``import`` or
``bidirectional``) also needs the rights of the records it writes: admin
for sites, manufacturers, device types, VRFs, VLANs, prefixes and IP
addresses (admin-managed catalogues and IPAM), ``inventory.write`` for
devices. That is checked when such a job is saved and when it is run for
real; a dry run writes nothing and needs ``sync.write`` only. Scheduled runs
act for the job (``sync:<job name>`` in the change log).

Sync is not enrolled in object scope (``netcontrol.object_scope``): accounts
limited to selected inventory groups never reach it. Every write and every
run is audited (category ``sync``). Errors: 404 unknown record, 409 a taken
name, a connection still used by jobs or a job already running, 422 bad
input (``{"message", "fields"}``). Logic: ``netcontrol.sync``; storage:
``routes.db.sync``; docs: ``docs/sync-framework.md``.
"""

from __future__ import annotations

import ssl
from typing import Any, Literal

import routes.database as db
import routes.db.sync as sync_db
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.custom_fields import TEXT_MAX
from netcontrol.routes.outbound_http import tls_verify
from netcontrol.routes.shared import _audit, _corr_id, _session_user, caller_features
from netcontrol.sync import runner
from netcontrol.sync.models import (
    AUTH_TYPES,
    CONFLICT_POLICIES,
    CONNECTION_KINDS,
    DIRECTIONS,
    OBJECT_SPECS,
    OBJECT_TYPES,
    MappingError,
    check_mappings,
)
from netcontrol.sync.transport import clean_base_url

router = APIRouter()
admin_router = APIRouter()

PREFIX = "/api/sync"
NAME_MAX = 100
GROUP_PATH_MAX = 200
INTERVAL_MIN = 5
INTERVAL_MAX = 7 * 24 * 60
PEM_MAX = 64 * 1024

Kind = Literal["netbox", "nautobot", "servicenow"]
AuthType = Literal["token", "basic", "oauth"]
Direction = Literal["import", "export", "bidirectional"]
Policy = Literal["source_wins", "plexus_wins", "skip_conflicts"]
ObjectType = Literal["sites", "manufacturers", "device_types", "vrfs", "vlans", "prefixes", "ip_addresses", "devices"]

_KIND_INFO = {
    "netbox": {"label": "NetBox", "notes": "REST API under /api/; an API token (stored as a service credential)."},
    "nautobot": {
        "label": "Nautobot",
        "notes": "REST API under /api/ (Nautobot 2.x); an API token (stored as a service credential).",
    },
    "servicenow": {
        "label": "ServiceNow CMDB",
        "notes": "Table API; basic auth (username and password) or OAuth client credentials (client id and secret).",
    },
}


# ── Bodies ───────────────────────────────────────────────────────────────────


class ConnectionBody(BaseModel):
    name: str = Field(min_length=1, max_length=NAME_MAX)
    kind: Kind
    base_url: str = Field(min_length=1, max_length=500)
    auth_type: AuthType = "token"
    credential_id: int | None = None
    verify_tls: bool = True
    # ``None`` keeps the stored bundle on an edit; ``""`` removes it.
    ca_pem: str | None = Field(default=None, max_length=PEM_MAX)
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    description: str = Field(default="", max_length=TEXT_MAX)


class JobBody(BaseModel):
    name: str = Field(min_length=1, max_length=NAME_MAX)
    connection_id: int
    object_types: list[ObjectType] = Field(min_length=1)
    direction: Direction = "import"
    conflict_policy: Policy = "skip_conflicts"
    delete_missing: bool = False
    mappings: dict[str, dict[str, Any]] = Field(default_factory=dict)
    host_group: str = Field(default="Synced", max_length=GROUP_PATH_MAX)
    interval_minutes: int = Field(default=0, ge=0, le=INTERVAL_MAX)
    enabled: bool = True
    description: str = Field(default="", max_length=TEXT_MAX)


class RunBody(BaseModel):
    dry_run: bool = True


# ── Helpers ──────────────────────────────────────────────────────────────────


def _invalid(message: str, fields: dict[str, str] | None = None) -> HTTPException:
    return HTTPException(status_code=422, detail={"message": message, "fields": fields or {}})


def _found(record: dict | None, what: str) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return record


async def _audit_write(request: Request, action: str, detail: str) -> None:
    await _audit("sync", action, user=_session_user(request), detail=detail, correlation_id=_corr_id(request))


def _writes_plexus(job: dict) -> list[str]:
    return list(job["object_types"]) if job["direction"] in ("import", "bidirectional") else []


async def _check_plexus_rights(request: Request, job: dict) -> None:
    """403 unless the caller may write every type the job writes into Plexus."""
    types = _writes_plexus(job)
    if not types:
        return
    features = await caller_features(request)
    if features is None:
        return
    admin_only = [t for t in types if t != "devices"]
    if admin_only:
        raise HTTPException(
            status_code=403,
            detail=f"Writing {', '.join(admin_only)} into Plexus needs admin rights; use the export direction "
            "or ask an admin to set up the job.",
        )
    if "devices" in types and "inventory.write" not in features:
        raise HTTPException(status_code=403, detail="Writing devices into Plexus needs inventory.write.")


# ── Catalogue ────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/catalog")
async def get_catalog() -> dict:
    """Connection kinds, object types with their fields, directions, conflict
    policies and the default mapping of every kind."""
    return {
        "kinds": [{"id": kind, "auth_types": list(AUTH_TYPES[kind]), **_KIND_INFO[kind]} for kind in CONNECTION_KINDS],
        "object_types": [
            {
                "id": spec.name,
                "label": spec.label,
                "key": list(spec.key),
                "fields": list(spec.fields),
                "optional": sorted(spec.optional),
            }
            for spec in OBJECT_SPECS.values()
        ],
        "directions": list(DIRECTIONS),
        "conflict_policies": list(CONFLICT_POLICIES),
        "default_mappings": runner.default_mappings(),
        "interval_min": INTERVAL_MIN,
        "interval_max": INTERVAL_MAX,
    }


# ── Connections ──────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/connections")
async def list_connections() -> dict:
    return {"connections": await sync_db.list_connections()}


@router.get(f"{PREFIX}/connections/{{connection_id}}")
async def get_connection(connection_id: int) -> dict:
    return _found(await sync_db.get_connection(connection_id), "Connection")


async def _connection_values(body: ConnectionBody, *, create: bool) -> dict:
    values = body.model_dump()
    values["name"] = body.name.strip()
    if not values["name"]:
        raise _invalid("Name must not be empty.", {"name": "Required."})
    try:
        values["base_url"] = clean_base_url(body.base_url, "Connection")
    except ValueError as exc:
        raise _invalid(str(exc), {"base_url": str(exc)}) from exc
    if body.auth_type not in AUTH_TYPES[body.kind]:
        allowed = ", ".join(AUTH_TYPES[body.kind])
        raise _invalid(f"{body.kind} connections use: {allowed}.", {"auth_type": f"One of: {allowed}."})
    if body.credential_id is None:
        raise _invalid("Pick the service credential holding the secret.", {"credential_id": "Required."})
    cred = await db.get_credential_raw(body.credential_id)
    if not cred or not cred.get("is_service"):
        raise _invalid(
            f"Unknown service credential id {body.credential_id}.", {"credential_id": "Not a service credential."}
        )
    if body.ca_pem is None:
        values.pop("ca_pem")
        if create:
            values["ca_pem"] = ""
    elif body.ca_pem.strip():
        try:
            tls_verify(True, body.ca_pem)
        except (ssl.SSLError, ValueError) as exc:
            raise _invalid("The CA bundle is not valid PEM.", {"ca_pem": "Not valid PEM."}) from exc
    return values


@admin_router.post(f"{PREFIX}/connections", status_code=201)
async def create_connection(body: ConnectionBody, request: Request) -> dict:
    values = await _connection_values(body, create=True)
    try:
        record = await sync_db.create_connection(values, _session_user(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(request, "connection_create", f"id={record['id']} name={record['name']} kind={record['kind']}")
    return record


@admin_router.put(f"{PREFIX}/connections/{{connection_id}}")
async def update_connection(connection_id: int, body: ConnectionBody, request: Request) -> dict:
    current = _found(await sync_db.get_connection(connection_id), "Connection")
    if current["kind"] != body.kind and current["job_count"]:
        raise _invalid("The kind of a connection used by jobs cannot change.", {"kind": "Used by jobs."})
    values = await _connection_values(body, create=False)
    try:
        record = await sync_db.update_connection(connection_id, values, _session_user(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record = _found(record, "Connection")
    await _audit_write(request, "connection_update", f"id={connection_id} name={record['name']}")
    return record


@admin_router.delete(f"{PREFIX}/connections/{{connection_id}}")
async def delete_connection(connection_id: int, request: Request) -> dict:
    current = _found(await sync_db.get_connection(connection_id), "Connection")
    try:
        deleted = await sync_db.delete_connection(connection_id)
    except sync_db.ConnectionInUse as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not deleted:
        raise HTTPException(status_code=404, detail="Connection not found")
    await _audit_write(request, "connection_delete", f"id={connection_id} name={current['name']}")
    return {"ok": True}


@admin_router.post(f"{PREFIX}/connections/{{connection_id}}/test")
async def test_connection(connection_id: int, request: Request) -> dict:
    _found(await sync_db.get_connection(connection_id), "Connection")
    result = await runner.test_connection(connection_id)
    await _audit_write(request, "connection_test", f"id={connection_id} ok={int(result['ok'])}")
    return result


# ── Jobs ─────────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/jobs")
async def list_jobs(connection_id: int | None = None) -> dict:
    jobs = await sync_db.list_jobs(connection_id)
    for job in jobs:
        job["running"] = runner.is_running(job["id"])
    return {"jobs": jobs}


@router.get(f"{PREFIX}/jobs/{{job_id}}")
async def get_job(job_id: int) -> dict:
    job = _found(await sync_db.get_job(job_id), "Job")
    job["running"] = runner.is_running(job_id)
    return job


async def _job_values(body: JobBody) -> dict:
    name = body.name.strip()
    if not name:
        raise _invalid("Name must not be empty.", {"name": "Required."})
    connection = await sync_db.get_connection(body.connection_id)
    if connection is None:
        raise _invalid(f"Unknown connection id {body.connection_id}.", {"connection_id": "Unknown connection."})
    if body.interval_minutes and body.interval_minutes < INTERVAL_MIN:
        raise _invalid(
            f"Schedule every {INTERVAL_MIN} minutes or more (0: manual only).",
            {"interval_minutes": f"0 or at least {INTERVAL_MIN}."},
        )
    wanted: set[str] = set(body.object_types)
    types: list[str] = [t for t in OBJECT_TYPES if t in wanted]
    try:
        mappings = check_mappings(body.mappings)
        runner.check_job_mapping(connection["kind"], types, mappings)
    except MappingError as exc:
        raise _invalid(str(exc), {"mappings": str(exc)}) from exc
    host_group = " / ".join(p.strip() for p in body.host_group.split("/") if p.strip()) or "Synced"
    return {
        "name": name,
        "connection_id": body.connection_id,
        "object_types": types,
        "direction": body.direction,
        "conflict_policy": body.conflict_policy,
        "delete_missing": body.delete_missing and body.direction != "bidirectional",
        "mappings": mappings,
        "options": {"host_group": host_group},
        "interval_minutes": body.interval_minutes,
        "enabled": body.enabled,
        "description": body.description.strip(),
    }


@router.post(f"{PREFIX}/jobs", status_code=201)
async def create_job(body: JobBody, request: Request) -> dict:
    values = await _job_values(body)
    await _check_plexus_rights(request, values)
    try:
        record = await sync_db.create_job(values, _session_user(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit_write(
        request,
        "job_create",
        f"id={record['id']} name={record['name']} direction={record['direction']} types={','.join(record['object_types'])}",
    )
    return record


@router.put(f"{PREFIX}/jobs/{{job_id}}")
async def update_job(job_id: int, body: JobBody, request: Request) -> dict:
    current = _found(await sync_db.get_job(job_id), "Job")
    await _check_plexus_rights(request, current)
    values = await _job_values(body)
    await _check_plexus_rights(request, values)
    try:
        record = await sync_db.update_job(job_id, values, _session_user(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record = _found(record, "Job")
    await _audit_write(request, "job_update", f"id={job_id} name={record['name']} direction={record['direction']}")
    return record


@router.delete(f"{PREFIX}/jobs/{{job_id}}")
async def delete_job(job_id: int, request: Request) -> dict:
    current = _found(await sync_db.get_job(job_id), "Job")
    await _check_plexus_rights(request, current)
    if runner.is_running(job_id):
        raise HTTPException(status_code=409, detail="The job is running; delete it when the run has finished.")
    await sync_db.delete_job(job_id)
    await _audit_write(request, "job_delete", f"id={job_id} name={current['name']}")
    return {"ok": True}


@router.post(f"{PREFIX}/jobs/{{job_id}}/run", status_code=202)
async def run_job(job_id: int, body: RunBody, request: Request, background: BackgroundTasks) -> dict:
    """Start a run (``dry_run`` true by default) and answer with the
    ``running`` run; poll ``GET /api/sync/runs/{id}`` for its outcome."""
    job = _found(await sync_db.get_job(job_id), "Job")
    if not body.dry_run:
        await _check_plexus_rights(request, job)
    user = _session_user(request)
    try:
        run = await runner.start_run(job, dry_run=body.dry_run, trigger="manual", user=user)
    except runner.JobBusy as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    background.add_task(runner.execute_run, job_id, run["id"], dry_run=body.dry_run, user=user)
    return run


# ── Runs ─────────────────────────────────────────────────────────────────────


@router.get(f"{PREFIX}/runs")
async def list_runs(job_id: int | None = None, limit: int = Query(default=100, ge=1, le=500)) -> dict:
    return {"runs": await sync_db.list_runs(job_id, limit)}


@router.get(f"{PREFIX}/runs/{{run_id}}")
async def get_run(run_id: int) -> dict:
    return _found(await sync_db.get_run(run_id), "Run")


@router.get(f"{PREFIX}/runs/{{run_id}}/entries")
async def list_run_entries(
    run_id: int,
    object_type: str | None = Query(default=None, max_length=40),
    outcome: str | None = Query(default=None, max_length=20),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict:
    _found(await sync_db.get_run(run_id), "Run")
    entries, total = await sync_db.list_run_entries(
        run_id, object_type=object_type, outcome=outcome, limit=limit, offset=offset
    )
    return {"entries": entries, "total": total, "limit": limit, "offset": offset}
