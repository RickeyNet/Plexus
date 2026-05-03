"""
lab_topology.py — Phase B-2: multi-device lab topologies.

Phase B-1 deployed each twin as its own single-node containerlab lab.
Phase B-2 lets operators link N twins into one topology so routing/STP/LACP
behaviors can be tested end-to-end against real NOS images.

The driver reuses Phase B-1's containerlab plumbing — same allowlists,
same workdir layout, same `lab_runtime._run_containerlab` helper. The difference is
that one `containerlab deploy` covers all member devices and emits the
linked endpoints into the topology YAML's `links:` section.

Mode contract: a lab device is either free-standing (Phase B-1, deployed
via /api/lab/devices/{id}/runtime/deploy) or a topology member (Phase B-2,
deployed via /api/lab/topologies/{id}/deploy). Mixing is rejected at
deploy time.
"""
from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import routes.database as db
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from netcontrol.routes.lab import (
    _resolve_session_user,
    _user_can_access_env,
)
from netcontrol.routes import lab_runtime
from netcontrol.routes.lab_runtime import (
    ALLOWED_NODE_KINDS,
    _IMAGE_RE,
    _NAME_RE,
    _default_workdir_root,
    _slug,
)
from netcontrol.routes.shared import _audit, _corr_id
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.lab_topology")

# Loose endpoint-name regex — allows interface names like eth1,
# GigabitEthernet0/0/1, and Ethernet1/2 while rejecting shell metacharacters.
_ENDPOINT_RE = __import__("re").compile(r"^[a-zA-Z][a-zA-Z0-9._/-]{0,47}$")


# ── Models ──────────────────────────────────────────────────────────────────


class TopologyCreate(BaseModel):
    name: str
    description: str = ""
    mgmt_subnet: str = ""


class TopologyMembershipRequest(BaseModel):
    device_id: int


class TopologyLinkCreate(BaseModel):
    a_device_id: int
    a_endpoint: str
    b_device_id: int
    b_endpoint: str


# ── Helpers ─────────────────────────────────────────────────────────────────


def _topology_workdir(topology: dict) -> Path:
    if topology.get("workdir"):
        return Path(topology["workdir"])
    root = _default_workdir_root()
    return root / f"env-{topology['environment_id']}" / f"topo-{topology['id']}"


async def _resolve_topology_or_403(topology_id: int, request: Request) -> tuple[dict, dict | None]:
    topo = await db.get_lab_topology(topology_id)
    if not topo:
        raise HTTPException(status_code=404, detail="Topology not found")
    env = await db.get_lab_environment(topo["environment_id"])
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env or {}, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return topo, session


def _validate_endpoint(name: str) -> None:
    if not _ENDPOINT_RE.match(name or ""):
        raise HTTPException(
            status_code=400,
            detail=f"Endpoint name '{name}' contains unsafe characters",
        )


def build_topology_yaml(topology: dict, devices: list[dict], links: list[dict]) -> str:
    """Render a multi-node containerlab YAML from devices + links.

    Caller is responsible for validating each device has a usable
    runtime_node_kind / runtime_image and a slug-able hostname.
    """
    lab_name = topology["lab_name"] or _slug(
        f"plx-env{topology['environment_id']}-topo{topology['id']}", "plx-topo",
    )
    lines: list[str] = [f"name: {lab_name}", "topology:"]

    if topology.get("mgmt_subnet"):
        lines.append("  mgmt:")
        lines.append("    network: clab-mgmt")
        lines.append(f"    ipv4-subnet: {topology['mgmt_subnet']}")

    lines.append("  nodes:")
    for d in devices:
        node_name = _slug(d.get("hostname") or f"node-{d['id']}", f"node-{d['id']}")
        kind = d.get("runtime_node_kind") or "linux"
        image = d.get("runtime_image") or ""
        lines.append(f"    {node_name}:")
        lines.append(f"      kind: {kind}")
        if image:
            lines.append(f"      image: {image}")

    if links:
        # Resolve device id → node name once.
        name_by_id: dict[int, str] = {}
        for d in devices:
            name_by_id[d["id"]] = _slug(d.get("hostname") or f"node-{d['id']}", f"node-{d['id']}")
        lines.append("  links:")
        for link in links:
            a_name = name_by_id.get(link["a_device_id"])
            b_name = name_by_id.get(link["b_device_id"])
            if not a_name or not b_name:
                continue  # link references a device that's no longer a member
            lines.append(
                f"    - endpoints: [\"{a_name}:{link['a_endpoint']}\", "
                f"\"{b_name}:{link['b_endpoint']}\"]"
            )

    return "\n".join(lines) + "\n"


def _validate_member_for_deploy(device: dict) -> None:
    if not device.get("runtime_node_kind"):
        raise HTTPException(
            status_code=400,
            detail=f"Device '{device.get('hostname')}' has no runtime_node_kind set",
        )
    if device["runtime_node_kind"] not in ALLOWED_NODE_KINDS:
        raise HTTPException(
            status_code=400,
            detail=f"Device '{device.get('hostname')}' uses disallowed kind '{device['runtime_node_kind']}'",
        )
    image = device.get("runtime_image") or ""
    if not image:
        raise HTTPException(
            status_code=400,
            detail=f"Device '{device.get('hostname')}' has no runtime_image set",
        )
    if not _IMAGE_RE.match(image):
        raise HTTPException(
            status_code=400,
            detail=f"Device '{device.get('hostname')}' image contains unsafe characters",
        )


# ── Driver operations ───────────────────────────────────────────────────────


async def deploy_topology(topology: dict, *, actor: str = "") -> dict:
    devices = await db.list_topology_devices(topology["id"])
    if not devices:
        raise HTTPException(status_code=400, detail="Topology has no member devices")
    for d in devices:
        _validate_member_for_deploy(d)

    # Reject if any member has a free-standing Phase B-1 runtime still running.
    busy = [d for d in devices if d.get("runtime_kind") == "containerlab"
            and d.get("runtime_status") in ("provisioning", "running")
            and not d.get("topology_id")]
    if busy:
        names = ", ".join(b["hostname"] for b in busy)
        raise HTTPException(
            status_code=409,
            detail=f"Free-standing runtime is active on: {names}. Destroy or detach first.",
        )

    rt = await lab_runtime.get_runtime_status()
    if not rt["available"]:
        raise HTTPException(
            status_code=503,
            detail=f"containerlab runtime unavailable: {rt.get('reason') or 'unknown'}",
        )

    links = await db.list_topology_links(topology["id"])

    lab_name = _slug(
        f"plx-env{topology['environment_id']}-topo{topology['id']}", "plx-topo",
    )
    workdir = _topology_workdir(topology)
    workdir.mkdir(parents=True, exist_ok=True)
    topo_path = workdir / "topology.clab.yml"

    topology_for_yaml = {**topology, "lab_name": lab_name}
    topo_path.write_text(build_topology_yaml(topology_for_yaml, devices, links))

    await db.update_lab_topology_status(
        topology["id"],
        status="provisioning",
        lab_name=lab_name,
        workdir=str(workdir),
        error="",
    )
    for d in devices:
        await db.update_lab_device_runtime(
            d["id"],
            runtime_kind="containerlab",
            runtime_status="provisioning",
            runtime_lab_name=lab_name,
            runtime_workdir=str(workdir),
            runtime_error="",
        )

    rc, stdout, stderr = await lab_runtime._run_containerlab(
        ["deploy", "-t", str(topo_path), "--reconfigure"], cwd=workdir,
    )
    if rc != 0:
        msg = (stderr or stdout).strip()[:500] or f"containerlab deploy exited rc={rc}"
        await db.update_lab_topology_status(
            topology["id"], status="error", error=msg,
        )
        for d in devices:
            await db.update_lab_device_runtime(
                d["id"], runtime_status="error", runtime_error=msg,
            )
            await db.add_lab_runtime_event(
                d["id"], action="topology-deploy", status="error",
                actor=actor, detail=msg,
            )
        raise HTTPException(status_code=500, detail=msg)

    inspect_doc = await lab_runtime._inspect_lab(workdir) or {}
    started_at = datetime.now(UTC).isoformat()
    await db.update_lab_topology_status(
        topology["id"], status="running", error="", started_at=started_at,
    )

    member_results = []
    for d in devices:
        node_name = _slug(d.get("hostname") or f"node-{d['id']}", f"node-{d['id']}")
        mgmt_ipv4 = lab_runtime._extract_mgmt_ipv4(inspect_doc, node_name)
        await db.update_lab_device_runtime(
            d["id"],
            runtime_status="running",
            runtime_node_name=node_name,
            runtime_mgmt_address=mgmt_ipv4,
            runtime_started_at=started_at,
            runtime_error="",
        )
        await db.add_lab_runtime_event(
            d["id"], action="topology-deploy", status="ok", actor=actor,
            detail=f"topology={topology['id']} mgmt={mgmt_ipv4 or 'unknown'}",
        )
        member_results.append({
            "device_id": d["id"],
            "node_name": node_name,
            "mgmt_ipv4": mgmt_ipv4,
        })

    return {
        "status": "running",
        "lab_name": lab_name,
        "workdir": str(workdir),
        "members": member_results,
    }


async def destroy_topology(topology: dict, *, actor: str = "") -> dict:
    devices = await db.list_topology_devices(topology["id"])
    workdir = _topology_workdir(topology)
    topo_path = workdir / "topology.clab.yml"

    if not topo_path.is_file():
        await db.update_lab_topology_status(
            topology["id"], status="destroyed",
        )
        for d in devices:
            await db.update_lab_device_runtime(
                d["id"], runtime_status="destroyed", runtime_mgmt_address="",
            )
        return {"status": "destroyed", "reason": "no_topology"}

    rt = await lab_runtime.get_runtime_status()
    if not rt["available"]:
        await db.update_lab_topology_status(
            topology["id"], status="destroyed",
            error=f"containerlab unavailable: {rt.get('reason')}",
        )
        for d in devices:
            await db.update_lab_device_runtime(
                d["id"], runtime_status="destroyed", runtime_mgmt_address="",
            )
            await db.add_lab_runtime_event(
                d["id"], action="topology-destroy", status="error",
                actor=actor,
                detail=f"containerlab unavailable; manual cleanup required",
            )
        return {"status": "destroyed", "reason": "containerlab_unavailable"}

    rc, stdout, stderr = await lab_runtime._run_containerlab(
        ["destroy", "-t", str(topo_path), "--cleanup"], cwd=workdir,
    )
    if rc != 0:
        msg = (stderr or stdout).strip()[:500] or f"containerlab destroy exited rc={rc}"
        await db.update_lab_topology_status(
            topology["id"], status="error", error=msg,
        )
        for d in devices:
            await db.add_lab_runtime_event(
                d["id"], action="topology-destroy", status="error",
                actor=actor, detail=msg,
            )
        raise HTTPException(status_code=500, detail=msg)

    await db.update_lab_topology_status(
        topology["id"], status="destroyed", workdir="", error="",
    )
    for d in devices:
        await db.update_lab_device_runtime(
            d["id"],
            runtime_status="destroyed",
            runtime_mgmt_address="",
            runtime_workdir="",
            runtime_error="",
        )
        await db.add_lab_runtime_event(
            d["id"], action="topology-destroy", status="ok", actor=actor,
            detail=f"topology={topology['id']} destroyed",
        )
    removed = await lab_runtime._remove_workdir(workdir)
    return {"status": "destroyed", "workdir_removed": removed}


async def refresh_topology(topology: dict, *, actor: str = "") -> dict:
    workdir = _topology_workdir(topology)
    topo_path = workdir / "topology.clab.yml"
    if not topo_path.is_file():
        await db.update_lab_topology_status(topology["id"], status="destroyed")
        return {"status": "destroyed", "reason": "no_topology"}

    rt = await lab_runtime.get_runtime_status()
    if not rt["available"]:
        return {"status": topology.get("status") or "unknown", "reason": "containerlab_unavailable"}

    inspect_doc = await lab_runtime._inspect_lab(workdir)
    devices = await db.list_topology_devices(topology["id"])
    if not inspect_doc:
        await db.update_lab_topology_status(topology["id"], status="stopped")
        for d in devices:
            await db.update_lab_device_runtime(
                d["id"], runtime_status="stopped", runtime_mgmt_address="",
            )
        return {"status": "stopped"}

    await db.update_lab_topology_status(topology["id"], status="running")
    members = []
    for d in devices:
        node_name = d.get("runtime_node_name") or _slug(
            d.get("hostname") or f"node-{d['id']}", f"node-{d['id']}",
        )
        mgmt_ipv4 = lab_runtime._extract_mgmt_ipv4(inspect_doc, node_name)
        await db.update_lab_device_runtime(
            d["id"], runtime_status="running", runtime_mgmt_address=mgmt_ipv4,
        )
        members.append({"device_id": d["id"], "mgmt_ipv4": mgmt_ipv4})
    return {"status": "running", "members": members}


# ── HTTP API ────────────────────────────────────────────────────────────────


@router.get("/api/lab/environments/{env_id}/topologies")
async def list_topologies_endpoint(env_id: int, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    return await db.list_lab_topologies(env_id)


@router.post("/api/lab/environments/{env_id}/topologies")
async def create_topology_endpoint(env_id: int, body: TopologyCreate, request: Request):
    env = await db.get_lab_environment(env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")
    session, _, role = await _resolve_session_user(request)
    if not _user_can_access_env(env, session, role):
        raise HTTPException(status_code=403, detail="Not allowed")
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="name is required")
    topo_id = await db.create_lab_topology(
        environment_id=env_id,
        name=body.name.strip(),
        description=body.description,
        mgmt_subnet=body.mgmt_subnet,
    )
    await _audit(
        "lab", "topology.created",
        user=session["user"] if session else "",
        detail=f"env={env_id} topology={topo_id} name={body.name}",
        correlation_id=_corr_id(request),
    )
    return {"id": topo_id}


@router.get("/api/lab/topologies/{topology_id}")
async def get_topology_endpoint(topology_id: int, request: Request):
    topo, _ = await _resolve_topology_or_403(topology_id, request)
    devices = await db.list_topology_devices(topology_id)
    links = await db.list_topology_links(topology_id)
    topo["devices"] = devices
    topo["links"] = links
    return topo


@router.delete("/api/lab/topologies/{topology_id}")
async def delete_topology_endpoint(topology_id: int, request: Request):
    topo, session = await _resolve_topology_or_403(topology_id, request)
    if topo.get("status") == "running":
        raise HTTPException(
            status_code=409,
            detail="Topology is running; destroy it before deleting.",
        )
    await db.delete_lab_topology(topology_id)
    await _audit(
        "lab", "topology.deleted",
        user=session["user"] if session else "",
        detail=f"topology={topology_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/lab/topologies/{topology_id}/devices")
async def add_member_endpoint(
    topology_id: int, body: TopologyMembershipRequest, request: Request,
):
    topo, session = await _resolve_topology_or_403(topology_id, request)
    device = await db.get_lab_device(body.device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Lab device not found")
    if device["environment_id"] != topo["environment_id"]:
        raise HTTPException(
            status_code=400,
            detail="Lab device belongs to a different environment",
        )
    if device.get("topology_id") and device["topology_id"] != topology_id:
        raise HTTPException(
            status_code=409,
            detail=f"Device is already a member of topology {device['topology_id']}",
        )
    if (
        device.get("runtime_kind") == "containerlab"
        and device.get("runtime_status") in ("provisioning", "running")
    ):
        raise HTTPException(
            status_code=409,
            detail="Device has a free-standing runtime; destroy it before joining a topology",
        )
    await db.set_lab_device_topology(device["id"], topology_id)
    await _audit(
        "lab", "topology.device.added",
        user=session["user"] if session else "",
        detail=f"topology={topology_id} device={device['id']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.delete("/api/lab/topologies/{topology_id}/devices/{device_id}")
async def remove_member_endpoint(topology_id: int, device_id: int, request: Request):
    topo, session = await _resolve_topology_or_403(topology_id, request)
    if topo.get("status") == "running":
        raise HTTPException(
            status_code=409,
            detail="Topology is running; destroy it before changing membership.",
        )
    device = await db.get_lab_device(device_id)
    if not device or device.get("topology_id") != topology_id:
        raise HTTPException(status_code=404, detail="Device is not a member")
    await db.set_lab_device_topology(device["id"], None)
    await _audit(
        "lab", "topology.device.removed",
        user=session["user"] if session else "",
        detail=f"topology={topology_id} device={device_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/lab/topologies/{topology_id}/links")
async def add_link_endpoint(
    topology_id: int, body: TopologyLinkCreate, request: Request,
):
    topo, session = await _resolve_topology_or_403(topology_id, request)
    if topo.get("status") == "running":
        raise HTTPException(
            status_code=409,
            detail="Topology is running; destroy it before changing links.",
        )
    if body.a_device_id == body.b_device_id:
        raise HTTPException(status_code=400, detail="Link endpoints must be different devices")
    _validate_endpoint(body.a_endpoint)
    _validate_endpoint(body.b_endpoint)
    members = {d["id"] for d in await db.list_topology_devices(topology_id)}
    if body.a_device_id not in members or body.b_device_id not in members:
        raise HTTPException(
            status_code=400,
            detail="Both endpoints must be members of the topology",
        )
    link_id = await db.create_lab_topology_link(
        topology_id=topology_id,
        a_device_id=body.a_device_id,
        a_endpoint=body.a_endpoint,
        b_device_id=body.b_device_id,
        b_endpoint=body.b_endpoint,
    )
    await _audit(
        "lab", "topology.link.added",
        user=session["user"] if session else "",
        detail=f"topology={topology_id} link={link_id}",
        correlation_id=_corr_id(request),
    )
    return {"id": link_id}


@router.delete("/api/lab/topologies/{topology_id}/links/{link_id}")
async def remove_link_endpoint(topology_id: int, link_id: int, request: Request):
    topo, session = await _resolve_topology_or_403(topology_id, request)
    if topo.get("status") == "running":
        raise HTTPException(
            status_code=409,
            detail="Topology is running; destroy it before changing links.",
        )
    await db.delete_lab_topology_link(link_id)
    await _audit(
        "lab", "topology.link.removed",
        user=session["user"] if session else "",
        detail=f"topology={topology_id} link={link_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/lab/topologies/{topology_id}/deploy")
async def deploy_topology_endpoint(topology_id: int, request: Request):
    topo, session = await _resolve_topology_or_403(topology_id, request)
    actor = session["user"] if session else ""
    result = await deploy_topology(topo, actor=actor)
    await _audit(
        "lab", "topology.deploy",
        user=actor, detail=f"topology={topology_id}",
        correlation_id=_corr_id(request),
    )
    return result


@router.post("/api/lab/topologies/{topology_id}/destroy")
async def destroy_topology_endpoint(topology_id: int, request: Request):
    topo, session = await _resolve_topology_or_403(topology_id, request)
    actor = session["user"] if session else ""
    result = await destroy_topology(topo, actor=actor)
    await _audit(
        "lab", "topology.destroy",
        user=actor, detail=f"topology={topology_id}",
        correlation_id=_corr_id(request),
    )
    return result


@router.post("/api/lab/topologies/{topology_id}/refresh")
async def refresh_topology_endpoint(topology_id: int, request: Request):
    topo, session = await _resolve_topology_or_403(topology_id, request)
    return await refresh_topology(topo, actor=session["user"] if session else "")
