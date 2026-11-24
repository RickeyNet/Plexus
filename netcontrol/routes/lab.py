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

Object scope: environments keep their owner/shared rules; a twin cloned
from an inventory host (``source_host_id``) follows that host, so a caller
limited to selected inventory groups sees and uses only the twins of hosts
they may read (model ``lab_device``; twins with no source host follow the
environment rules only). Cloning needs read access to the source host;
promoting to a deployment needs write access to the target group and hosts.

Features: cloning copies the host's running config, so it also needs
``config-drift`` or ``config-backups``; promoting creates a deployment, so it
also needs ``deployments`` + ``deployments.write`` and is planned by
``deployments.plan_deployment`` (the production approval rule).

Device secrets: a twin's config is the source host's configuration, read
under the rule of ``netcontrol.routes.config_visibility``. A caller who may
not read that host's configuration as captured gets a twin cloned from the
masked text, and reads every twin of that host (its config, the runs and
diffs made on it) with the secrets masked, whoever cloned it.
"""

from __future__ import annotations

import json

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from netcontrol.object_scope import (
    READ_ONLY_DETAIL,
    ScopeModel,
    filter_rows,
    register_model,
    request_scope,
    require_group,
    require_host,
    require_host_ids,
    require_row,
    scoped,
)
from netcontrol.routes.config_visibility import mask_config_text, mask_fields, sees_raw_config
from netcontrol.routes.deployments import plan_deployment
from netcontrol.routes.risk_analysis import (
    _classify_change_areas,
    _compute_risk_score,
    _simulate_config_change,
)
from netcontrol.routes.shared import (
    _audit,
    _compute_config_diff,
    _corr_id,
    _get_session,
    require_any_feature,
    require_credential_access,
)
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.lab")

# A lab twin follows the inventory host it was cloned from; a twin with no
# source host is visible under the environment's owner/shared rules alone.
register_model(
    ScopeModel(
        "lab_device",
        {"host": "source_host_id"},
        shared=True,
        not_found="Lab device not found",
        description="Lab twins (by the inventory host they were cloned from)",
    )
)


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
    user_id = session.get("user_id")
    if user_id is None:
        return session, None, ""
    user = await db.get_user_by_id(user_id)
    role = user.get("role", "") if user else ""
    return session, user, role


async def _evaluate_compliance_impact(
    device: dict,
    pre_config: str,
    post_config: str,
) -> tuple[int, list[dict]]:
    """Score compliance regressions/improvements for a lab change.

    Lab devices don't carry a group_id directly, so we resolve compliance
    assignments via the source production host when one is set. Returns
    (new_violation_count, per_profile_impact). Failures are swallowed so a
    misconfigured profile can't block a simulation.
    """
    source_host_id = device.get("source_host_id")
    if not source_host_id:
        return 0, []
    try:
        from netcontrol.routes.compliance import _evaluate_rule

        host_obj = await db.get_host(int(source_host_id))
        if not host_obj or not host_obj.get("group_id"):
            return 0, []
        assignments = await db.get_compliance_assignments(group_id=host_obj["group_id"])
        violations = 0
        impact: list[dict] = []
        for assignment in assignments:
            if not assignment.get("enabled"):
                continue
            profile = await db.get_compliance_profile(assignment["profile_id"])
            if not profile:
                continue
            rules_json = profile.get("rules") or "[]"
            rules = json.loads(rules_json) if isinstance(rules_json, str) else rules_json
            findings_before = [_evaluate_rule(r, pre_config) for r in rules]
            findings_after = [_evaluate_rule(r, post_config) for r in rules]
            before_failures = sum(1 for f in findings_before if not f["passed"])
            after_failures = sum(1 for f in findings_after if not f["passed"])
            new_violations = max(0, after_failures - before_failures)
            violations += new_violations

            changed: list[dict] = []
            for i, rule in enumerate(rules):
                before = findings_before[i]["passed"]
                after = findings_after[i]["passed"]
                if before != after:
                    changed.append(
                        {
                            "name": rule.get("name", rule.get("pattern", "?")),
                            "before": "pass" if before else "fail",
                            "after": "pass" if after else "fail",
                            "impact": "regression" if before and not after else "improvement",
                        }
                    )
            if changed:
                impact.append(
                    {
                        "profile_name": profile["name"],
                        "profile_id": profile["id"],
                        "before_failures": before_failures,
                        "after_failures": after_failures,
                        "new_violations": new_violations,
                        "improvements": sum(1 for c in changed if c["impact"] == "improvement"),
                        "changed_rules": changed,
                    }
                )
        return violations, impact
    except Exception as exc:
        # Don't fail the simulation just because compliance evaluation broke.
        return 0, []


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
            line.rstrip() for line in tpl["content"].splitlines() if line.strip() and not line.strip().startswith("#")
        ]
    if not commands:
        raise HTTPException(status_code=400, detail="No proposed commands provided")
    return commands


async def require_lab_device(request: Request, device: dict | None, *, not_found: str = "Lab device not found") -> None:
    """404 ``not_found`` when ``device`` is a twin of a host outside the
    caller's read scope. Nothing is checked for an unrestricted caller or a
    missing device (the route answers that itself)."""
    if device is None or (await request_scope(request)).unrestricted:
        return
    await require_row(request, "lab_device", device, not_found=not_found)


async def visible_lab_devices(request: Request, devices: list[dict]) -> list[dict]:
    """The twins of ``devices`` the caller may see (all for an unrestricted caller)."""
    return await filter_rows("lab_device", devices, request)


async def twin_config_masked(request: Request, device: dict | None) -> bool:
    """Whether the caller reads ``device``'s configuration with its secrets
    masked: a twin cloned from an inventory host, for a caller who may not
    read that host's configuration as captured. A twin with no source host
    holds text its authors typed and is shown as it is."""
    source_host_id = (device or {}).get("source_host_id")
    if source_host_id is None:
        return False
    return not await sees_raw_config(request, int(source_host_id))


async def mask_twin_record(request: Request, device: dict | None, record: dict, *fields: str) -> dict:
    """``record`` (the twin itself, or a run or drift run made on it) with
    its configuration ``fields`` masked when ``twin_config_masked``."""
    if not await twin_config_masked(request, device):
        return record
    return mask_fields(record, *fields, keep_lines=True)


# ── Environment routes ───────────────────────────────────────────────────────


@router.get("/api/lab/environments")
@scoped("lab_environment")
async def list_environments(request: Request):
    session, user, role = await _resolve_session_user(request)
    is_admin = role == "admin" or bool(session and session.get("auth_mode") == "token")
    user_id = session.get("user_id") if session else None
    envs = await db.list_lab_environments(user_id=user_id, is_admin=is_admin)
    if (await request_scope(request)).restricted:
        for env in envs:
            env["device_count"] = len(await visible_lab_devices(request, await db.list_lab_devices(env["id"])))
    return envs


@router.post("/api/lab/environments")
@scoped("lab_environment")
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
    except ValueError as exc:
        # Validation errors carry a user-facing message; surface it.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.error("lab: create environment failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=400, detail="Failed to create lab environment") from exc
    await _audit(
        "lab",
        "environment.created",
        user=session["user"] if session else "",
        detail=f"id={env_id} name={body.name}",
        correlation_id=_corr_id(request),
    )
    return {"id": env_id}


@router.get("/api/lab/environments/{env_id}")
@scoped("lab_environment")
async def get_environment(env_id: int, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    env["devices"] = await visible_lab_devices(request, await db.list_lab_devices(env_id))
    return env


@router.patch("/api/lab/environments/{env_id}")
@scoped("lab_environment")
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
        "lab",
        "environment.updated",
        user=session["user"] if session else "",
        detail=f"id={env_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/lab/environments/{env_id}")
@scoped("lab_environment")
async def delete_environment(env_id: int, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    if (await request_scope(request)).restricted:
        devices = await db.list_lab_devices(env_id)
        if len(await visible_lab_devices(request, devices)) != len(devices):
            # Deleting would remove twins of hosts outside the caller's scope.
            raise HTTPException(status_code=403, detail=READ_ONLY_DETAIL)
    await db.delete_lab_environment(env_id)
    await _audit(
        "lab",
        "environment.deleted",
        user=session["user"] if session else "",
        detail=f"id={env_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Device routes ─────────────────────────────────────────────────────────────


@router.get("/api/lab/environments/{env_id}/devices")
@scoped("lab_environment")
async def list_devices(env_id: int, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return await visible_lab_devices(request, await db.list_lab_devices(env_id))


@router.post("/api/lab/environments/{env_id}/devices")
@scoped("lab_environment")
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
        "lab",
        "device.created",
        user=session["user"] if session else "",
        detail=f"env={env_id} device={device_id} hostname={body.hostname}",
        correlation_id=_corr_id(request),
    )
    return {"id": device_id}


@router.post("/api/lab/environments/{env_id}/clone-host")
@scoped("host")
async def clone_host(env_id: int, body: CloneHostRequest, request: Request):
    """Clone a production host into the lab using its latest config snapshot."""
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    # The twin holds the host's full running config (passwords, keys,
    # communities): the same access the config pages need.
    await require_any_feature(request, "config-drift", "config-backups")

    host = await require_host(request, body.host_id, not_found="Source host not found")

    snapshot = await db.get_latest_config_snapshot(body.host_id)
    config_text = (snapshot or {}).get("config_text", "") if snapshot else ""
    # A caller who reads this host's configuration masked gets a twin of the
    # masked text: the twin is theirs to read and change in full.
    secrets_masked = bool(config_text) and not await sees_raw_config(request, body.host_id)
    if secrets_masked:
        config_text = mask_config_text(config_text, keep_lines=True)

    device_id = await db.create_lab_device(
        environment_id=env_id,
        hostname=(body.hostname_override or host.get("hostname") or "twin").strip(),
        ip_address=host.get("ip_address", ""),
        device_type=host.get("device_type", "cisco_ios") or "cisco_ios",
        model=host.get("model", "") or "",
        source_host_id=body.host_id,
        running_config=config_text,
        notes=(
            ("Cloned from inventory host (device secrets masked)." if secrets_masked else "Cloned from inventory host.")
            if config_text
            else "Cloned from inventory host (no config snapshot available - config is empty)."
        ),
    )
    await _audit(
        "lab",
        "device.cloned",
        user=session["user"] if session else "",
        detail=f"env={env_id} device={device_id} src_host={body.host_id} bytes={len(config_text)}",
        correlation_id=_corr_id(request),
    )
    return {
        "id": device_id,
        "config_bytes": len(config_text),
        "snapshot_id": (snapshot or {}).get("id"),
        "secrets_masked": secrets_masked,
    }


@router.get("/api/lab/devices/{device_id}")
@scoped("lab_device")
async def get_device(device_id: int, request: Request):
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    await require_lab_device(request, device)
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return await mask_twin_record(request, device, device, "running_config")


@router.patch("/api/lab/devices/{device_id}")
@scoped("lab_device")
async def update_device(device_id: int, body: DeviceUpdate, request: Request):
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    await require_lab_device(request, device)
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
        "lab",
        "device.updated",
        user=session["user"] if session else "",
        detail=f"id={device_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/lab/devices/{device_id}")
@scoped("lab_device")
async def delete_device(device_id: int, request: Request):
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    await require_lab_device(request, device)
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    await db.delete_lab_device(device_id)
    await _audit(
        "lab",
        "device.deleted",
        user=session["user"] if session else "",
        detail=f"id={device_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


# ── Simulation + run history ─────────────────────────────────────────────────


@router.post("/api/lab/devices/{device_id}/simulate")
@scoped("lab_device")
async def simulate(device_id: int, body: SimulateRequest, request: Request):
    """Apply commands to the lab device's snapshot, score risk, save a run."""
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    await require_lab_device(request, device)
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")

    commands = await _resolve_commands(body.proposed_commands, body.template_id)
    pre_config = device.get("running_config", "") or ""

    affected_areas = _classify_change_areas(commands)
    post_config = _simulate_config_change(pre_config, commands)
    diff_text, diff_added, diff_removed = _compute_config_diff(
        pre_config,
        post_config,
        baseline_label="lab-pre",
        actual_label="lab-post",
    )
    compliance_violations, compliance_impact = await _evaluate_compliance_impact(
        device,
        pre_config,
        post_config,
    )
    risk_score, risk_level = _compute_risk_score(
        commands,
        affected_areas,
        diff_added,
        diff_removed,
        compliance_violations,
    )
    risk_factors: list[str] = []
    if affected_areas:
        risk_factors.append(f"Touches critical areas: {', '.join(a['label'] for a in affected_areas)}")
    if diff_removed > 0:
        risk_factors.append(f"Removes {diff_removed} line(s) from config")
    if compliance_violations > 0:
        risk_factors.append(f"Introduces {compliance_violations} new compliance violation(s)")
    if len(commands) > 20:
        risk_factors.append(f"Large change set ({len(commands)} commands)")
    risk_detail = {
        "change_volume": {
            "total_commands": len(commands),
            "diff_lines_added": diff_added,
            "diff_lines_removed": diff_removed,
        },
        "affected_areas": affected_areas,
        "compliance_impact": compliance_impact,
        "compliance_violations_introduced": compliance_violations,
        "risk_factors": risk_factors,
    }

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
        "lab",
        "device.simulated",
        user=session["user"] if session else "",
        detail=f"device={device_id} run={run_id} risk={risk_level} score={risk_score} applied={body.apply_to_device}",
        correlation_id=_corr_id(request),
    )

    return await mask_twin_record(
        request,
        device,
        {
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
        },
        "diff_text",
        "post_config",
    )


@router.get("/api/lab/devices/{device_id}/runs")
@scoped("lab_device")
async def list_runs(device_id: int, request: Request, limit: int = 50):
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    await require_lab_device(request, device)
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return await db.list_lab_runs(device_id, limit=max(1, min(500, limit)))


@router.get("/api/lab/runs/{run_id}")
@scoped("lab_device")
async def get_run(run_id: int, request: Request):
    run = await db.get_lab_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Lab run not found")
    device = await db.get_lab_device(run["lab_device_id"])
    await require_lab_device(request, device, not_found="Lab run not found")
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
    return await mask_twin_record(request, device, run, "pre_config", "post_config", "diff_text")


@router.post("/api/lab/runs/{run_id}/apply-to-device")
@scoped("lab_device")
async def apply_run_to_device(run_id: int, request: Request):
    """Promote a simulated run's post_config to the lab device's snapshot."""
    run = await db.get_lab_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Lab run not found")
    device = await db.get_lab_device(run["lab_device_id"])
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    await require_lab_device(request, device, not_found="Lab run not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    await db.update_lab_device(device["id"], running_config=run.get("post_config", ""))
    await db.update_lab_run_status(run_id, "applied")
    await _audit(
        "lab",
        "run.applied",
        user=session["user"] if session else "",
        detail=f"run={run_id} device={device['id']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/lab/runs/{run_id}/promote")
@scoped("group")
async def promote_run(run_id: int, body: PromoteRequest, request: Request):
    """Create a Deployment record from a successful lab run.

    The deployment is created in 'planned' state. It does NOT auto-execute -
    the operator must explicitly execute it through the deployments router.
    """
    run = await db.get_lab_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Lab run not found")
    device = await db.get_lab_device(run["lab_device_id"])
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    await require_lab_device(request, device, not_found="Lab run not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    # Creating a deployment is a deployments write, whichever page starts it.
    await require_any_feature(request, "deployments")
    await require_any_feature(request, "deployments.write")

    # Enforce credential ownership before binding it to a production deployment —
    # otherwise a user could promote a lab run with another user's credential id
    # and have it run against production hosts. Mirrors the deployments create path.
    if body.credential_id:
        await require_credential_access(body.credential_id, session=session, allow_service=True)

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
    if (await request_scope(request)).restricted:
        await require_group(request, int(group_id), write=True)
        await require_host_ids(request, target_host_ids, write=True)

    try:
        commands = json.loads(run.get("commands") or "[]")
    except Exception:
        commands = []

    # The deployments API's own path, so the production approval rule (by
    # the groups of the hosts targeted) applies to a promoted run too.
    plan = await plan_deployment(
        request,
        name=body.name.strip(),
        description=body.description or f"Promoted from lab run {run_id}",
        group_id=int(group_id),
        credential_id=body.credential_id,
        change_type="lab-promote",
        commands=commands,
        host_ids=target_host_ids,
        user=session["user"] if session else "",
    )
    deployment_id = plan["id"]
    await db.update_lab_run_status(run_id, "promoted", promoted_deployment_id=deployment_id)
    await _audit(
        "lab",
        "run.promoted",
        user=session["user"] if session else "",
        detail=f"run={run_id} deployment={deployment_id} group={group_id}",
        correlation_id=_corr_id(request),
    )
    return {
        "ok": True,
        "deployment_id": deployment_id,
        "requires_approval": plan["requires_approval"],
        "approval_status": plan["approval_status"],
    }
