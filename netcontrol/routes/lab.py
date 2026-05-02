"""
lab.py -- Digital twin / lab mode for safe pre-production change testing.

Phase A is a config-plane simulator: lab devices hold a snapshot of running
config text (cloned from a production host's latest config snapshot, or
authored manually). Operators apply proposed commands or templates to the
twin, see the resulting unified diff, get a risk score from the existing
risk-analysis engine, and can promote a successful run to a real Deployment
record without auto-executing.

Endpoints:
    GET    /api/lab/environments
    POST   /api/lab/environments
    GET    /api/lab/environments/{id}
    PATCH  /api/lab/environments/{id}
    DELETE /api/lab/environments/{id}
    GET    /api/lab/environments/{id}/devices
    POST   /api/lab/environments/{id}/devices
    POST   /api/lab/environments/{id}/clone-host
    GET    /api/lab/devices/{id}
    PATCH  /api/lab/devices/{id}
    DELETE /api/lab/devices/{id}
    POST   /api/lab/devices/{id}/simulate
    GET    /api/lab/devices/{id}/runs
    GET    /api/lab/runs/{id}
    POST   /api/lab/runs/{id}/apply-to-device
    POST   /api/lab/runs/{id}/promote
"""
from __future__ import annotations

import json

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from netcontrol.routes.shared import (
    _audit,
    _compute_config_diff,
    _corr_id,
    _get_session,
)
from netcontrol.routes.risk_analysis import (
    _classify_change_areas,
    _compute_risk_score,
    _simulate_config_change,
)
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.lab")

# ── Late-binding auth dependencies (injected by app.py) ──────────────────────

_require_auth = None
_require_feature = None


def init_lab(require_auth, require_feature):
    global _require_auth, _require_feature
    _require_auth = require_auth
    _require_feature = require_feature


# ── Models ────────────────────────────────────────────────────────────────────


class EnvironmentCreate(BaseModel):
    name: str
    description: str = ""
    shared: bool = False


class EnvironmentUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    shared: bool | None = None
    active: bool | None = None


class DeviceCreate(BaseModel):
    hostname: str
    ip_address: str = ""
    device_type: str = "cisco_ios"
    model: str = ""
    running_config: str = ""
    notes: str = ""


class DeviceUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    device_type: str | None = None
    model: str | None = None
    running_config: str | None = None
    notes: str | None = None


class CloneHostRequest(BaseModel):
    host_id: int
    hostname_override: str | None = None


class SimulateRequest(BaseModel):
    proposed_commands: list[str] = []
    template_id: int | None = None
    apply_to_device: bool = False  # if true, persist post_config back to lab device


class PromoteRequest(BaseModel):
    name: str
    description: str = ""
    credential_id: int
    target_host_ids: list[int] = []
    target_group_id: int | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _user_can_access_env(env: dict, session: dict | None, user_role: str | None) -> bool:
    """Visibility rules: admin or token sees all, owner sees own, shared visible to all."""
    if session is None:
        return False
    if session.get("auth_mode") == "token" or user_role == "admin":
        return True
    if env.get("shared"):
        return True
    if env.get("owner_id") is None:
        # Unowned environments are admin-only.
        return False
    return env.get("owner_id") == session.get("user_id")


async def _resolve_session_user(request: Request) -> tuple[dict | None, dict | None, str]:
    """Return (session, user_row, role). Tokens get role='admin'."""
    session = _get_session(request)
    if session is None:
        return None, None, ""
    if session.get("auth_mode") == "token":
        return session, None, "admin"
    user = await db.get_user_by_id(session.get("user_id"))
    role = user.get("role", "") if user else ""
    return session, user, role


async def _resolve_commands(
    proposed_commands: list[str],
    template_id: int | None,
) -> list[str]:
    commands = [c for c in (proposed_commands or []) if c is not None]
    if template_id and not commands:
        tpl = await db.get_template(template_id)
        if not tpl:
            raise HTTPException(status_code=404, detail="Template not found")
        commands = [
            line.rstrip() for line in tpl["content"].splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    if not commands:
        raise HTTPException(status_code=400, detail="No proposed commands provided")
    return commands


# ── Environment routes ───────────────────────────────────────────────────────


@router.get("/api/lab/environments")
async def list_environments(request: Request):
    session, user, role = await _resolve_session_user(request)
    is_admin = role == "admin" or (session and session.get("auth_mode") == "token")
    user_id = session.get("user_id") if session else None
    return await db.list_lab_environments(user_id=user_id, is_admin=is_admin)


@router.post("/api/lab/environments")
async def create_environment(body: EnvironmentCreate, request: Request):
    session, _, _ = await _resolve_session_user(request)
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="name is required")
    owner_id = session.get("user_id") if session else None
    try:
        env_id = await db.create_lab_environment(
            name=body.name.strip(),
            description=body.description,
            owner_id=owner_id,
            shared=body.shared,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to create: {exc}") from exc
    await _audit(
        "lab", "environment.created",
        user=session["user"] if session else "",
        detail=f"id={env_id} name={body.name}",
        correlation_id=_corr_id(request),
    )
    return {"id": env_id}


@router.get("/api/lab/environments/{env_id}")
async def get_environment(env_id: int, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    devices = await db.list_lab_devices(env_id)
    env["devices"] = devices
    return env


@router.patch("/api/lab/environments/{env_id}")
async def update_environment(env_id: int, body: EnvironmentUpdate, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    await db.update_lab_environment(
        env_id,
        name=body.name,
        description=body.description,
        shared=body.shared,
        active=body.active,
    )
    await _audit(
        "lab", "environment.updated",
        user=session["user"] if session else "",
        detail=f"id={env_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/lab/environments/{env_id}")
async def delete_environment(env_id: int, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    await db.delete_lab_environment(env_id)
    await _audit(
        "lab", "environment.deleted",
        user=session["user"] if session else "",
        detail=f"id={env_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Device routes ─────────────────────────────────────────────────────────────


@router.get("/api/lab/environments/{env_id}/devices")
async def list_devices(env_id: int, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return await db.list_lab_devices(env_id)


@router.post("/api/lab/environments/{env_id}/devices")
async def create_device(env_id: int, body: DeviceCreate, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    if not body.hostname.strip():
        raise HTTPException(status_code=400, detail="hostname is required")
    device_id = await db.create_lab_device(
        environment_id=env_id,
        hostname=body.hostname.strip(),
        ip_address=body.ip_address,
        device_type=body.device_type or "cisco_ios",
        model=body.model,
        running_config=body.running_config,
        notes=body.notes,
    )
    await _audit(
        "lab", "device.created",
        user=session["user"] if session else "",
        detail=f"env={env_id} device={device_id} hostname={body.hostname}",
        correlation_id=_corr_id(request),
    )
    return {"id": device_id}


@router.post("/api/lab/environments/{env_id}/clone-host")
async def clone_host(env_id: int, body: CloneHostRequest, request: Request):
    """Clone a production host into the lab using its latest config snapshot."""
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")

    host = await db.get_host(body.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Source host not found")

    snapshot = await db.get_latest_config_snapshot(body.host_id)
    config_text = (snapshot or {}).get("config_text", "") if snapshot else ""

    device_id = await db.create_lab_device(
        environment_id=env_id,
        hostname=(body.hostname_override or host.get("hostname") or "twin").strip(),
        ip_address=host.get("ip_address", ""),
        device_type=host.get("device_type", "cisco_ios") or "cisco_ios",
        model=host.get("model", "") or "",
        source_host_id=body.host_id,
        running_config=config_text,
        notes=(
            "Cloned from inventory host." if config_text
            else "Cloned from inventory host (no config snapshot available — config is empty)."
        ),
    )
    await _audit(
        "lab", "device.cloned",
        user=session["user"] if session else "",
        detail=f"env={env_id} device={device_id} src_host={body.host_id} bytes={len(config_text)}",
        correlation_id=_corr_id(request),
    )
    return {
        "id": device_id,
        "config_bytes": len(config_text),
        "snapshot_id": (snapshot or {}).get("id"),
    }


@router.get("/api/lab/devices/{device_id}")
async def get_device(device_id: int, request: Request):
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return device


@router.patch("/api/lab/devices/{device_id}")
async def update_device(device_id: int, body: DeviceUpdate, request: Request):
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    await db.update_lab_device(
        device_id,
        hostname=body.hostname,
        ip_address=body.ip_address,
        device_type=body.device_type,
        model=body.model,
        running_config=body.running_config,
        notes=body.notes,
    )
    await _audit(
        "lab", "device.updated",
        user=session["user"] if session else "",
        detail=f"id={device_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/lab/devices/{device_id}")
async def delete_device(device_id: int, request: Request):
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    await db.delete_lab_device(device_id)
    await _audit(
        "lab", "device.deleted",
        user=session["user"] if session else "",
        detail=f"id={device_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Simulation + run history ─────────────────────────────────────────────────


@router.post("/api/lab/devices/{device_id}/simulate")
async def simulate(device_id: int, body: SimulateRequest, request: Request):
    """Apply commands to the lab device's snapshot, score risk, save a run."""
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")

    commands = await _resolve_commands(body.proposed_commands, body.template_id)
    pre_config = device.get("running_config", "") or ""

    affected_areas = _classify_change_areas(commands)
    post_config = _simulate_config_change(pre_config, commands)
    diff_text, diff_added, diff_removed = _compute_config_diff(
        pre_config, post_config,
        baseline_label="lab-pre", actual_label="lab-post",
    )
    risk_score, risk_level = _compute_risk_score(
        commands, affected_areas, diff_added, diff_removed, 0,
    )
    risk_detail = {
        "change_volume": {
            "total_commands": len(commands),
            "diff_lines_added": diff_added,
            "diff_lines_removed": diff_removed,
        },
        "affected_areas": affected_areas,
        "risk_factors": [],
    }
    if affected_areas:
        risk_detail["risk_factors"].append(
            f"Touches critical areas: {', '.join(a['label'] for a in affected_areas)}"
        )
    if diff_removed > 0:
        risk_detail["risk_factors"].append(f"Removes {diff_removed} line(s) from config")
    if len(commands) > 20:
        risk_detail["risk_factors"].append(f"Large change set ({len(commands)} commands)")

    status = "applied" if body.apply_to_device else "simulated"
    if body.apply_to_device:
        await db.update_lab_device(device_id, running_config=post_config)

    run_id = await db.create_lab_run(
        lab_device_id=device_id,
        submitted_by=session["user"] if session else "",
        commands=commands,
        pre_config=pre_config,
        post_config=post_config,
        diff_text=diff_text,
        diff_added=diff_added,
        diff_removed=diff_removed,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_detail=risk_detail,
        status=status,
    )
    await _audit(
        "lab", "device.simulated",
        user=session["user"] if session else "",
        detail=f"device={device_id} run={run_id} risk={risk_level} score={risk_score} applied={body.apply_to_device}",
        correlation_id=_corr_id(request),
    )

    return {
        "run_id": run_id,
        "status": status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "diff_text": diff_text,
        "diff_added": diff_added,
        "diff_removed": diff_removed,
        "affected_areas": [a["label"] for a in affected_areas],
        "post_config": post_config,
        "risk_detail": risk_detail,
    }


@router.get("/api/lab/devices/{device_id}/runs")
async def list_runs(device_id: int, request: Request, limit: int = 50):
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return await db.list_lab_runs(device_id, limit=max(1, min(500, limit)))


@router.get("/api/lab/runs/{run_id}")
async def get_run(run_id: int, request: Request):
    run = await db.get_lab_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Lab run not found")
    device = await db.get_lab_device(run["lab_device_id"])
    env = await db.get_lab_environment(device["environment_id"]) if device else None
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    # Decode JSON columns for convenience.
    try:
        run["commands"] = json.loads(run.get("commands") or "[]")
    except Exception:
        run["commands"] = []
    try:
        run["risk_detail"] = json.loads(run.get("risk_detail") or "{}")
    except Exception:
        run["risk_detail"] = {}
    return run


@router.post("/api/lab/runs/{run_id}/apply-to-device")
async def apply_run_to_device(run_id: int, request: Request):
    """Promote a simulated run's post_config to the lab device's snapshot."""
    run = await db.get_lab_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Lab run not found")
    device = await db.get_lab_device(run["lab_device_id"])
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    await db.update_lab_device(device["id"], running_config=run.get("post_config", ""))
    await db.update_lab_run_status(run_id, "applied")
    await _audit(
        "lab", "run.applied",
        user=session["user"] if session else "",
        detail=f"run={run_id} device={device['id']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/lab/runs/{run_id}/promote")
async def promote_run(run_id: int, body: PromoteRequest, request: Request):
    """Create a Deployment record from a successful lab run.

    The deployment is created in 'planned' state. It does NOT auto-execute —
    the operator must explicitly execute it through the deployments router.
    """
    run = await db.get_lab_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Lab run not found")
    device = await db.get_lab_device(run["lab_device_id"])
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")

    # Resolve target group: explicit, or fall back to the source host's group.
    group_id = body.target_group_id
    target_host_ids = list(body.target_host_ids or [])
    if not group_id and device.get("source_host_id"):
        src = await db.get_host(device["source_host_id"])
        if src:
            group_id = src.get("group_id")
            if not target_host_ids:
                target_host_ids = [src["id"]]
    if not group_id:
        raise HTTPException(
            status_code=400,
            detail="target_group_id is required (or clone from a production host)",
        )

    try:
        commands = json.loads(run.get("commands") or "[]")
    except Exception:
        commands = []

    deployment_id = await db.create_deployment(
        name=body.name.strip(),
        description=body.description or f"Promoted from lab run {run_id}",
        group_id=group_id,
        credential_id=body.credential_id,
        change_type="lab-promote",
        proposed_commands="\n".join(commands),
        host_ids=json.dumps(target_host_ids),
        created_by=session["user"] if session else "",
    )
    await db.update_lab_run_status(run_id, "promoted", promoted_deployment_id=deployment_id)
    await _audit(
        "lab", "run.promoted",
        user=session["user"] if session else "",
        detail=f"run={run_id} deployment={deployment_id} group={group_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True, "deployment_id": deployment_id}
