"""
lab_runtime.py — Phase B-1: containerlab single-node runtime for lab mode.

Drives the `containerlab` CLI to deploy a single virtual network device per
twin. The driver is intentionally narrow: one container per lab device, no
multi-node topology yet (deferred to Phase B-2). When `containerlab` (or its
required Docker engine) is unavailable, runtime endpoints fall back to a
clear `unavailable` status rather than failing the entire feature.

Design choices:
  - All shell-out calls use `asyncio.create_subprocess_exec` with explicit
    argv lists. Operator-supplied values (node kind, image, lab/node names)
    are validated against allowlists/regexes before reaching the subprocess
    layer so we never invoke a shell.
  - Topology YAMLs and any container artifacts live under
    ``$PLEXUS_LAB_WORKDIR`` (default ``~/.plexus-labs``). A workdir per
    (env_id, device_id) keeps deploys isolated.
  - Live config push reuses the existing Netmiko helpers (`_push_config_to_device`,
    `_capture_running_config`). The lab device's mgmt IP becomes the
    Netmiko target.

Endpoints exposed (registered by app.py):
    GET  /api/lab/runtime
    POST /api/lab/devices/{id}/runtime/deploy
    POST /api/lab/devices/{id}/runtime/destroy
    POST /api/lab/devices/{id}/runtime/refresh
    GET  /api/lab/devices/{id}/runtime/events
    POST /api/lab/devices/{id}/simulate-live
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from netcontrol.routes.lab import (
    _evaluate_compliance_impact,
    _resolve_commands,
    _resolve_session_user,
    _user_can_access_env,
)
from netcontrol.routes.shared import (
    _audit,
    _capture_running_config,
    _compute_config_diff,
    _corr_id,
    _push_config_to_device,
)
from netcontrol.routes.risk_analysis import (
    _classify_change_areas,
    _compute_risk_score,
)
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.lab_runtime")

# ── Allowlists / validation ──────────────────────────────────────────────────

# containerlab `kind` field — restricted to popular OSS/free images we expect
# operators to use. Extending this list is intentional: every entry must be a
# known containerlab kind so the generated topology validates without shelling
# out additional syntax.
ALLOWED_NODE_KINDS = frozenset({
    "linux",
    "ceos",            # Arista cEOS-Lab (free with Arista account)
    "srl",             # Nokia SR Linux
    "nokia_srlinux",   # alias accepted by containerlab
    "arista_ceos",     # alias accepted by containerlab
    "cvx",             # Cumulus VX
    "frr",             # FRRouting
    "sonic-vs",        # SONiC virtual switch
    "vr-veos",         # vrnetlab Arista vEOS
    "vr-csr",          # vrnetlab Cisco CSR
    "vr-xrv9k",        # vrnetlab Cisco XRv9k
    "vr-vmx",          # vrnetlab Juniper vMX
    "vr-sros",         # vrnetlab Nokia SR OS
})

# Container image references: registry/path[:tag][@digest] limited to a safe
# subset (no spaces, shell metacharacters, or relative path tricks).
_IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,255}(:[a-zA-Z0-9._-]+)?$")

# Lab and node names go directly into containerlab CLI args and the topology
# YAML, so keep them strict. Containerlab itself only accepts [a-z0-9_-]+.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


def _default_workdir_root() -> Path:
    explicit = os.getenv("PLEXUS_LAB_WORKDIR")
    if explicit:
        return Path(explicit).expanduser().resolve()
    return Path.home() / ".plexus-labs"


def _device_workdir(device: dict) -> Path:
    """Return the per-device runtime workdir, creating the parent on demand."""
    if device.get("runtime_workdir"):
        return Path(device["runtime_workdir"])
    root = _default_workdir_root()
    return root / f"env-{device['environment_id']}" / f"dev-{device['id']}"


def _slug(value: str, fallback: str) -> str:
    """Coerce a hostname into the [a-z0-9_-]+ subset containerlab accepts."""
    cleaned = re.sub(r"[^a-zA-Z0-9_-]", "-", value or "").strip("-").lower()
    if not cleaned:
        cleaned = fallback
    if not _NAME_RE.match(cleaned):
        # Prefix the fallback if the cleaned value still doesn't match.
        cleaned = f"{fallback}-{abs(hash(cleaned)) % 10_000}"
    return cleaned[:48]


# ── containerlab CLI plumbing ────────────────────────────────────────────────


async def _run_containerlab(args: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run `containerlab <args>` and return (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        "containerlab", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def get_runtime_status() -> dict:
    """Discover whether containerlab is usable on this host."""
    binary = shutil.which("containerlab")
    if binary is None:
        return {
            "available": False,
            "binary": None,
            "version": None,
            "reason": "containerlab binary not found in PATH",
            "allowed_node_kinds": sorted(ALLOWED_NODE_KINDS),
        }
    try:
        rc, stdout, stderr = await _run_containerlab(["version"])
    except Exception as exc:  # subprocess startup failure
        return {
            "available": False,
            "binary": binary,
            "version": None,
            "reason": f"failed to invoke containerlab: {exc}",
            "allowed_node_kinds": sorted(ALLOWED_NODE_KINDS),
        }
    version_line = ""
    for line in (stdout + "\n" + stderr).splitlines():
        if "version" in line.lower():
            version_line = line.strip()
            break
    return {
        "available": rc == 0,
        "binary": binary,
        "version": version_line or None,
        "reason": "" if rc == 0 else (stderr or stdout).strip()[:300],
        "allowed_node_kinds": sorted(ALLOWED_NODE_KINDS),
    }


def _build_topology_yaml(*, lab_name: str, node_name: str, kind: str, image: str) -> str:
    """Render a minimal single-node containerlab topology file."""
    # Nothing here is operator-controlled in a way that escapes YAML syntax —
    # all four fields have already been validated against strict regex/allowlist.
    return (
        f"name: {lab_name}\n"
        "topology:\n"
        "  nodes:\n"
        f"    {node_name}:\n"
        f"      kind: {kind}\n"
        f"      image: {image}\n"
    )


async def _inspect_lab(workdir: Path) -> dict | None:
    """Return parsed `containerlab inspect --format json` output, or None."""
    topo = workdir / "topology.clab.yml"
    if not topo.is_file():
        return None
    rc, stdout, stderr = await _run_containerlab(
        ["inspect", "-t", str(topo), "--format", "json"], cwd=workdir,
    )
    if rc != 0:
        LOGGER.debug("inspect failed (rc=%s): %s", rc, stderr.strip())
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def _extract_mgmt_ipv4(inspect_doc: dict, node_name: str) -> str:
    """Pull the IPv4 mgmt address for the named node out of the inspect doc."""
    if not isinstance(inspect_doc, dict):
        return ""
    # containerlab 0.45+ shape: {"containers": [{"name": "...", "ipv4_address": "..."}]}
    containers = inspect_doc.get("containers")
    if isinstance(containers, list):
        for c in containers:
            if not isinstance(c, dict):
                continue
            name = str(c.get("name") or c.get("lab-name") or "")
            if name.endswith(node_name) or node_name in name:
                addr = c.get("ipv4_address") or c.get("ipv4-address") or ""
                if isinstance(addr, str) and "/" in addr:
                    return addr.split("/", 1)[0]
                if isinstance(addr, str):
                    return addr
    # Older shape: {"<lab>": [{"name": "...", "ipv4-address": "..."}]}
    for value in inspect_doc.values():
        if not isinstance(value, list):
            continue
        for c in value:
            if not isinstance(c, dict):
                continue
            name = str(c.get("name") or "")
            if node_name in name:
                addr = c.get("ipv4_address") or c.get("ipv4-address") or ""
                if isinstance(addr, str):
                    return addr.split("/", 1)[0]
    return ""


# ── Driver operations ───────────────────────────────────────────────────────


async def deploy_lab_device(
    device: dict,
    *,
    node_kind: str,
    image: str,
    credential_id: int | None,
    actor: str = "",
) -> dict:
    """Deploy a single-node containerlab topology for the given lab device."""
    if node_kind not in ALLOWED_NODE_KINDS:
        raise HTTPException(status_code=400, detail=f"Unsupported node kind '{node_kind}'")
    if not _IMAGE_RE.match(image or ""):
        raise HTTPException(status_code=400, detail="Image reference contains unsafe characters")

    runtime_status = await get_runtime_status()
    if not runtime_status["available"]:
        raise HTTPException(
            status_code=503,
            detail=f"containerlab runtime unavailable: {runtime_status.get('reason') or 'unknown'}",
        )

    lab_name = _slug(f"plx-env{device['environment_id']}-dev{device['id']}", "plx-lab")
    node_name = _slug(device.get("hostname") or "node", "node")

    workdir = _device_workdir(device)
    workdir.mkdir(parents=True, exist_ok=True)
    topo = workdir / "topology.clab.yml"
    topo.write_text(_build_topology_yaml(
        lab_name=lab_name, node_name=node_name, kind=node_kind, image=image,
    ))

    await db.update_lab_device_runtime(
        device["id"],
        runtime_kind="containerlab",
        runtime_node_kind=node_kind,
        runtime_image=image,
        runtime_status="provisioning",
        runtime_lab_name=lab_name,
        runtime_node_name=node_name,
        runtime_workdir=str(workdir),
        runtime_credential_id=credential_id,
        runtime_error="",
    )

    rc, stdout, stderr = await _run_containerlab(
        ["deploy", "-t", str(topo), "--reconfigure"],
        cwd=workdir,
    )
    if rc != 0:
        msg = (stderr or stdout).strip()[:500] or f"containerlab deploy exited rc={rc}"
        await db.update_lab_device_runtime(
            device["id"], runtime_status="error", runtime_error=msg,
        )
        await db.add_lab_runtime_event(
            device["id"], action="deploy", status="error", actor=actor, detail=msg,
        )
        raise HTTPException(status_code=500, detail=msg)

    inspect_doc = await _inspect_lab(workdir) or {}
    mgmt_ipv4 = _extract_mgmt_ipv4(inspect_doc, node_name)
    started_at = datetime.now(UTC).isoformat()
    await db.update_lab_device_runtime(
        device["id"],
        runtime_status="running",
        runtime_mgmt_address=mgmt_ipv4,
        runtime_started_at=started_at,
        runtime_error="",
    )
    await db.add_lab_runtime_event(
        device["id"], action="deploy", status="ok", actor=actor,
        detail=f"node={node_name} mgmt={mgmt_ipv4 or 'unknown'}",
    )
    return {
        "status": "running",
        "lab_name": lab_name,
        "node_name": node_name,
        "mgmt_ipv4": mgmt_ipv4,
        "workdir": str(workdir),
    }


async def _remove_workdir(workdir: Path) -> bool:
    """Best-effort removal of a per-device workdir. Never raises."""
    try:
        if workdir.exists():
            shutil.rmtree(workdir, ignore_errors=True)
            return True
    except Exception as exc:
        LOGGER.warning("workdir cleanup failed for %s: %s", workdir, exc)
    return False


async def destroy_lab_device(device: dict, *, actor: str = "") -> dict:
    """Tear down a previously deployed single-node lab."""
    workdir = _device_workdir(device)
    topo = workdir / "topology.clab.yml"

    if not topo.is_file():
        # Nothing on disk to destroy. Just clear status.
        await db.update_lab_device_runtime(
            device["id"], runtime_status="destroyed", runtime_mgmt_address="",
        )
        await db.add_lab_runtime_event(
            device["id"], action="destroy", status="ok", actor=actor,
            detail="no topology on disk; cleared runtime state",
        )
        return {"status": "destroyed", "reason": "no_topology"}

    runtime_status = await get_runtime_status()
    if not runtime_status["available"]:
        # Mark as destroyed locally even if we can't reach the binary, so the
        # operator can manually clean up. Surface a warning event.
        await db.update_lab_device_runtime(
            device["id"], runtime_status="destroyed", runtime_mgmt_address="",
        )
        await db.add_lab_runtime_event(
            device["id"], action="destroy", status="error", actor=actor,
            detail=f"containerlab unavailable; manual cleanup required: {runtime_status.get('reason')}",
        )
        return {"status": "destroyed", "reason": "containerlab_unavailable"}

    rc, stdout, stderr = await _run_containerlab(
        ["destroy", "-t", str(topo), "--cleanup"],
        cwd=workdir,
    )
    if rc != 0:
        msg = (stderr or stdout).strip()[:500] or f"containerlab destroy exited rc={rc}"
        await db.update_lab_device_runtime(
            device["id"], runtime_status="error", runtime_error=msg,
        )
        await db.add_lab_runtime_event(
            device["id"], action="destroy", status="error", actor=actor, detail=msg,
        )
        raise HTTPException(status_code=500, detail=msg)

    await db.update_lab_device_runtime(
        device["id"],
        runtime_status="destroyed",
        runtime_mgmt_address="",
        runtime_error="",
        runtime_workdir="",
    )
    removed = await _remove_workdir(workdir)
    await db.add_lab_runtime_event(
        device["id"], action="destroy", status="ok", actor=actor,
        detail="destroyed; workdir removed" if removed else "destroyed",
    )
    return {"status": "destroyed", "workdir_removed": removed}


async def refresh_lab_device(device: dict, *, actor: str = "") -> dict:
    """Re-inspect an existing lab and update mgmt IP / status."""
    workdir = _device_workdir(device)
    topo = workdir / "topology.clab.yml"
    if not topo.is_file():
        await db.update_lab_device_runtime(
            device["id"], runtime_status="destroyed", runtime_mgmt_address="",
        )
        return {"status": "destroyed", "reason": "no_topology"}

    runtime_status = await get_runtime_status()
    if not runtime_status["available"]:
        await db.add_lab_runtime_event(
            device["id"], action="refresh", status="error", actor=actor,
            detail=f"containerlab unavailable: {runtime_status.get('reason')}",
        )
        return {"status": device.get("runtime_status") or "unknown", "reason": "containerlab_unavailable"}

    inspect_doc = await _inspect_lab(workdir)
    if not inspect_doc:
        await db.update_lab_device_runtime(
            device["id"], runtime_status="stopped", runtime_mgmt_address="",
        )
        await db.add_lab_runtime_event(
            device["id"], action="refresh", status="ok", actor=actor,
            detail="no containers running for this topology",
        )
        return {"status": "stopped"}

    node_name = device.get("runtime_node_name") or _slug(device.get("hostname") or "node", "node")
    mgmt_ipv4 = _extract_mgmt_ipv4(inspect_doc, node_name)
    await db.update_lab_device_runtime(
        device["id"], runtime_status="running", runtime_mgmt_address=mgmt_ipv4,
    )
    await db.add_lab_runtime_event(
        device["id"], action="refresh", status="ok", actor=actor,
        detail=f"mgmt={mgmt_ipv4 or 'unknown'}",
    )
    return {"status": "running", "mgmt_ipv4": mgmt_ipv4}


async def push_commands_live(
    device: dict,
    commands: list[str],
    credentials: dict,
) -> tuple[str, str]:
    """SSH into the running container, push commands, return (push_output, post_config)."""
    if device.get("runtime_status") != "running":
        raise HTTPException(status_code=400, detail="Lab device runtime is not running")
    mgmt_ipv4 = device.get("runtime_mgmt_address") or ""
    if not mgmt_ipv4:
        raise HTTPException(status_code=400, detail="Runtime has no management IP — refresh first")

    # Build the netmiko 'host' shape from the lab device + mgmt IP.
    target = {
        "id": device["id"],
        "hostname": device.get("hostname"),
        "ip_address": mgmt_ipv4,
        "device_type": device.get("device_type") or "cisco_ios",
    }
    push_output = await _push_config_to_device(target, credentials, commands)
    post_config = await _capture_running_config(target, credentials)
    return push_output, post_config


# ── HTTP API ────────────────────────────────────────────────────────────────


class DeployRequest(BaseModel):
    node_kind: str
    image: str
    credential_id: int | None = None


class SimulateLiveRequest(BaseModel):
    proposed_commands: list[str] = []
    template_id: int | None = None


async def _get_device_or_403(device_id: int, request: Request) -> tuple[dict, dict | None]:
    device = await db.get_lab_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    env = await db.get_lab_environment(device["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return device, session


@router.get("/api/lab/runtime")
async def runtime_status_endpoint():
    return await get_runtime_status()


@router.post("/api/lab/devices/{device_id}/runtime/deploy")
async def deploy_endpoint(device_id: int, body: DeployRequest, request: Request):
    device, session = await _get_device_or_403(device_id, request)
    actor = session["user"] if session else ""
    result = await deploy_lab_device(
        device,
        node_kind=body.node_kind,
        image=body.image,
        credential_id=body.credential_id,
        actor=actor,
    )
    await _audit(
        "lab", "runtime.deploy",
        user=actor,
        detail=f"device={device_id} kind={body.node_kind} image={body.image}",
        correlation_id=_corr_id(request),
    )
    return result


@router.post("/api/lab/devices/{device_id}/runtime/destroy")
async def destroy_endpoint(device_id: int, request: Request):
    device, session = await _get_device_or_403(device_id, request)
    actor = session["user"] if session else ""
    result = await destroy_lab_device(device, actor=actor)
    await _audit(
        "lab", "runtime.destroy",
        user=actor, detail=f"device={device_id}",
        correlation_id=_corr_id(request),
    )
    return result


@router.post("/api/lab/devices/{device_id}/runtime/refresh")
async def refresh_endpoint(device_id: int, request: Request):
    device, session = await _get_device_or_403(device_id, request)
    actor = session["user"] if session else ""
    return await refresh_lab_device(device, actor=actor)


@router.get("/api/lab/devices/{device_id}/runtime/events")
async def events_endpoint(device_id: int, request: Request, limit: int = 50):
    device, _ = await _get_device_or_403(device_id, request)
    return await db.list_lab_runtime_events(device["id"], limit=max(1, min(500, limit)))


@router.post("/api/lab/devices/{device_id}/simulate-live")
async def simulate_live_endpoint(
    device_id: int, body: SimulateLiveRequest, request: Request,
):
    """Push commands to a running containerlab device, capture real running-config back.

    The pre/post configs come from the live device, so the diff and risk score
    reflect what the NOS actually accepted (vs. Phase A's text-append simulator).
    """
    device, session = await _get_device_or_403(device_id, request)
    actor = session["user"] if session else ""
    if device.get("runtime_kind") != "containerlab":
        raise HTTPException(status_code=400, detail="Lab device has no containerlab runtime")

    cred_id = device.get("runtime_credential_id")
    if not cred_id:
        raise HTTPException(status_code=400, detail="Lab device has no associated credential")
    cred = await db.get_credential_raw(int(cred_id))
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    credentials = {
        "username": cred["username"],
        "password": cred["password"],
        "secret": cred.get("secret", ""),
    }

    commands = await _resolve_commands(body.proposed_commands, body.template_id)

    pre_config = await _capture_running_config(
        {
            "id": device["id"],
            "hostname": device.get("hostname"),
            "ip_address": device.get("runtime_mgmt_address") or "",
            "device_type": device.get("device_type") or "cisco_ios",
        },
        credentials,
    )

    push_output, post_config = await push_commands_live(device, commands, credentials)

    diff_text, diff_added, diff_removed = _compute_config_diff(
        pre_config, post_config,
        baseline_label="lab-pre", actual_label="lab-post-live",
    )
    affected_areas = _classify_change_areas(commands)
    compliance_violations, compliance_impact = await _evaluate_compliance_impact(
        device, pre_config, post_config,
    )
    risk_score, risk_level = _compute_risk_score(
        commands, affected_areas, diff_added, diff_removed, compliance_violations,
    )
    risk_detail = {
        "change_volume": {
            "total_commands": len(commands),
            "diff_lines_added": diff_added,
            "diff_lines_removed": diff_removed,
        },
        "affected_areas": affected_areas,
        "compliance_impact": compliance_impact,
        "compliance_violations_introduced": compliance_violations,
        "risk_factors": [],
        "live": True,
    }
    if compliance_violations > 0:
        risk_detail["risk_factors"].append(
            f"Introduces {compliance_violations} new compliance violation(s)"
        )

    # Persist the new running-config back to the twin's snapshot so subsequent
    # Phase A simulations operate against the real post-state.
    await db.update_lab_device(device["id"], running_config=post_config)

    run_id = await db.create_lab_run(
        lab_device_id=device["id"],
        submitted_by=actor,
        commands=commands,
        pre_config=pre_config,
        post_config=post_config,
        diff_text=diff_text,
        diff_added=diff_added,
        diff_removed=diff_removed,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_detail=risk_detail,
        status="applied-live",
    )
    await db.add_lab_runtime_event(
        device["id"], action="simulate-live", status="ok", actor=actor,
        detail=f"run={run_id} +{diff_added}/-{diff_removed}",
    )
    await _audit(
        "lab", "runtime.simulate_live",
        user=actor,
        detail=f"device={device_id} run={run_id} risk={risk_level}",
        correlation_id=_corr_id(request),
    )
    return {
        "run_id": run_id,
        "status": "applied-live",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "diff_text": diff_text,
        "diff_added": diff_added,
        "diff_removed": diff_removed,
        "affected_areas": [a["label"] for a in affected_areas],
        "post_config": post_config,
        "push_output": push_output[-2000:],
    }


# ── Operational hardening ───────────────────────────────────────────────────


# Default idle TTL: 24h. Operators can override or disable (0 = disabled).
DEFAULT_RUNTIME_TTL_SECONDS = 24 * 60 * 60
DEFAULT_RUNTIME_TTL_CHECK_INTERVAL = 15 * 60  # check every 15 minutes


def _runtime_ttl_seconds() -> int:
    raw = os.getenv("PLEXUS_LAB_RUNTIME_TTL_SECONDS")
    if not raw:
        return DEFAULT_RUNTIME_TTL_SECONDS
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_RUNTIME_TTL_SECONDS


def _runtime_ttl_interval() -> int:
    raw = os.getenv("PLEXUS_LAB_RUNTIME_TTL_INTERVAL_SECONDS")
    if not raw:
        return DEFAULT_RUNTIME_TTL_CHECK_INTERVAL
    try:
        return max(60, int(raw))
    except ValueError:
        return DEFAULT_RUNTIME_TTL_CHECK_INTERVAL


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # Both sqlite "datetime('now')" and our isoformat strings are accepted.
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        ts = datetime.fromisoformat(value)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts
    except ValueError:
        return None


async def reconcile_running_labs() -> dict:
    """At startup, mark stale 'running' rows accurately against containerlab.

    If containerlab isn't installed we don't touch anything — the status badge
    will show whatever the DB last saw, and the operator can refresh manually.
    If it is installed, walk each row in (provisioning, running) and reinspect.
    Rows whose topology workdir is gone or whose containers no longer exist
    flip to 'stopped' so the UI doesn't lie.
    """
    summary = {"checked": 0, "still_running": 0, "marked_stopped": 0, "skipped": 0}
    try:
        rows = await db.list_running_lab_devices()
    except Exception as exc:
        LOGGER.warning("reconcile: failed to query running lab devices: %s", exc)
        return summary
    if not rows:
        return summary

    status = await get_runtime_status()
    if not status["available"]:
        summary["skipped"] = len(rows)
        LOGGER.info(
            "reconcile: containerlab unavailable on host; skipping %d row(s)",
            len(rows),
        )
        return summary

    for row in rows:
        summary["checked"] += 1
        workdir = _device_workdir(row)
        topo = workdir / "topology.clab.yml"
        if not topo.is_file():
            await db.update_lab_device_runtime(
                row["id"], runtime_status="stopped", runtime_mgmt_address="",
            )
            await db.add_lab_runtime_event(
                row["id"], action="reconcile", status="ok", actor="system",
                detail="topology workdir missing; marked stopped",
            )
            summary["marked_stopped"] += 1
            continue
        inspect_doc = await _inspect_lab(workdir)
        node_name = row.get("runtime_node_name") or _slug(row.get("hostname") or "node", "node")
        mgmt_ipv4 = _extract_mgmt_ipv4(inspect_doc or {}, node_name)
        if inspect_doc and mgmt_ipv4:
            await db.update_lab_device_runtime(
                row["id"], runtime_status="running", runtime_mgmt_address=mgmt_ipv4,
            )
            summary["still_running"] += 1
        else:
            await db.update_lab_device_runtime(
                row["id"], runtime_status="stopped", runtime_mgmt_address="",
            )
            await db.add_lab_runtime_event(
                row["id"], action="reconcile", status="ok", actor="system",
                detail="containerlab no longer reports the node",
            )
            summary["marked_stopped"] += 1
    return summary


async def reap_idle_runtimes(now: datetime | None = None) -> dict:
    """Destroy any running lab whose `runtime_started_at` exceeds the TTL.

    Returns a summary of what was reaped. Errors are recorded as runtime
    events but never raised — the caller is a background loop.
    """
    ttl = _runtime_ttl_seconds()
    summary = {"checked": 0, "reaped": 0, "errors": 0, "ttl_seconds": ttl}
    if ttl <= 0:
        return summary
    cutoff = (now or datetime.now(UTC)) - timedelta(seconds=ttl)
    try:
        rows = await db.list_running_lab_devices()
    except Exception as exc:
        LOGGER.warning("ttl reaper: failed to query running labs: %s", exc)
        return summary
    for row in rows:
        summary["checked"] += 1
        started = _parse_iso_timestamp(row.get("runtime_started_at"))
        if started is None or started > cutoff:
            continue
        try:
            await destroy_lab_device(dict(row), actor="system-ttl")
            summary["reaped"] += 1
        except HTTPException as exc:
            summary["errors"] += 1
            await db.add_lab_runtime_event(
                row["id"], action="ttl-destroy", status="error",
                actor="system-ttl",
                detail=str(exc.detail)[:300] if hasattr(exc, "detail") else str(exc),
            )
        except Exception as exc:
            summary["errors"] += 1
            await db.add_lab_runtime_event(
                row["id"], action="ttl-destroy", status="error",
                actor="system-ttl", detail=str(exc)[:300],
            )
    return summary


async def lab_runtime_ttl_loop() -> None:
    """Background loop that reaps idle labs at PLEXUS_LAB_RUNTIME_TTL_SECONDS."""
    while True:
        interval = _runtime_ttl_interval()
        await asyncio.sleep(interval)
        if _runtime_ttl_seconds() <= 0:
            continue
        try:
            await reap_idle_runtimes()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("ttl reaper iteration failed: %s", exc)
