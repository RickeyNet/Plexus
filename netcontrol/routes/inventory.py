"""
inventory.py -- Inventory group/host CRUD, discovery, and SNMP profile routes.
"""

import asyncio
import csv
import io
import ipaddress
import json
import socket
import uuid

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

import netcontrol.routes.state as state
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.routes.snmp import (
    PYSMNP_AVAILABLE,  # noqa: F401
    _discover_neighbors,  # noqa: F401
    _probe_discovery_target_snmp,
    _snmp_get,
    _snmp_walk,  # noqa: F401
)
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.inventory")

# Two routers: one for inventory-feature routes, one for admin routes
router = APIRouter()
admin_router = APIRouter()


# ── Pydantic Models ──────────────────────────────────────────────────────────


class GroupCreate(BaseModel):
    name: str
    description: str = ""


class GroupUpdate(BaseModel):
    name: str
    description: str = ""

class HostCreate(BaseModel):
    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"

class HostUpdate(BaseModel):
    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"


class DiscoveryScanRequest(BaseModel):
    cidrs: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=state.DISCOVERY_DEFAULT_TIMEOUT_SECONDS, ge=0.05, le=5.0)
    max_hosts: int = Field(default=state.DISCOVERY_DEFAULT_MAX_HOSTS, ge=1, le=4096)
    device_type: str = "unknown"
    hostname_prefix: str = "discovered"
    use_snmp: bool = True

    model_config = ConfigDict(extra="forbid")


class DiscoverySyncRequest(DiscoveryScanRequest):
    remove_absent: bool = False


class DiscoveryOnboardRequest(BaseModel):
    discovered_hosts: list[dict] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


# ── Discovery helpers ────────────────────────────────────────────────────────


def _expand_scan_targets(cidrs: list[str], max_hosts: int) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        for host in network.hosts():
            ip_str = str(host)
            if ip_str in seen:
                continue
            seen.add(ip_str)
            targets.append(ip_str)
            if len(targets) >= max_hosts:
                return targets
    return targets


async def _probe_discovery_target(
    ip_address: str,
    timeout_seconds: float,
    device_type: str,
    hostname_prefix: str,
    use_snmp: bool,
    snmp_config: dict,
) -> dict | None:
    if use_snmp:
        snmp_hit = await _probe_discovery_target_snmp(ip_address, timeout_seconds, snmp_config)
        if snmp_hit is not None:
            return snmp_hit

    detected_port = 0
    detected_protocol = ""
    banner_sample = ""
    for port in state.DISCOVERY_PROBE_PORTS:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_address, port), timeout=timeout_seconds)
            if port == 22:
                try:
                    banner = await asyncio.wait_for(reader.read(256), timeout=timeout_seconds)
                    banner_sample = banner.decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner_sample = ""
            writer.close()
            await writer.wait_closed()
            _ = reader
            detected_port = port
            detected_protocol = "ssh" if port == 22 else "https"
            break
        except Exception:
            continue
    if not detected_port:
        return None

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except Exception:
        hostname = f"{hostname_prefix}-{ip_address.replace('.', '-')}"

    inferred_device_type = device_type
    inferred_os = "unknown"
    inferred_vendor = "unknown"
    if banner_sample:
        lower_banner = banner_sample.lower()
        if "cisco" in lower_banner:
            inferred_vendor = "cisco"
            inferred_device_type = "cisco_ios"
        elif "juniper" in lower_banner or "junos" in lower_banner:
            inferred_vendor = "juniper"
            inferred_device_type = "juniper_junos"
        elif "arista" in lower_banner:
            inferred_vendor = "arista"
            inferred_device_type = "arista_eos"
        elif "forti" in lower_banner:
            inferred_vendor = "fortinet"
            inferred_device_type = "fortinet"

        if "ios" in lower_banner:
            inferred_os = "ios"
        elif "nx-os" in lower_banner or "nxos" in lower_banner:
            inferred_os = "nx-os"
        elif "junos" in lower_banner:
            inferred_os = "junos"
        elif "eos" in lower_banner:
            inferred_os = "eos"
        elif "fortios" in lower_banner:
            inferred_os = "fortios"

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "device_type": inferred_device_type,
        "status": "online",
        "discovery": {
            "protocol": detected_protocol,
            "port": detected_port,
            "banner": banner_sample,
            "vendor": inferred_vendor,
            "os": inferred_os,
        },
    }


async def _discover_hosts(request: DiscoveryScanRequest, group_id: int | None = None) -> tuple[int, list[dict]]:
    targets = _expand_scan_targets(request.cidrs, request.max_hosts)
    semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)

    async def _scan_one(ip_address: str) -> dict | None:
        async with semaphore:
            return await _probe_discovery_target(
                ip_address=ip_address,
                timeout_seconds=request.timeout_seconds,
                device_type=request.device_type,
                hostname_prefix=request.hostname_prefix,
                use_snmp=request.use_snmp,
                snmp_config=snmp_cfg,
            )

    discovered_raw = await asyncio.gather(*[_scan_one(ip) for ip in targets])
    discovered = [item for item in discovered_raw if item is not None]
    discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
    return len(targets), discovered


async def _sync_group_hosts(
    group_id: int,
    discovered_hosts: list[dict],
    remove_absent: bool = False,
) -> dict:
    existing_hosts = await db.get_hosts_for_group(group_id)
    existing_by_ip = {str(host["ip_address"]): host for host in existing_hosts}

    normalized_discovered: dict[str, dict] = {}
    for host in discovered_hosts:
        ip = str(host.get("ip_address", "")).strip()
        if not ip:
            continue
        normalized_discovered[ip] = {
            "hostname": str(host.get("hostname") or "").strip() or f"host-{ip.replace('.', '-')}",
            "ip_address": ip,
            "device_type": str(host.get("device_type") or "unknown").strip() or "unknown",
            "status": str(host.get("status") or "online").strip() or "online",
        }

    added = 0
    updated = 0
    removed = 0

    for ip, discovered in normalized_discovered.items():
        existing = existing_by_ip.get(ip)
        model = discovered.get("model", "")
        sw_version = discovered.get("software_version", "")
        if existing is None:
            new_id = await db.add_host(group_id, discovered["hostname"], discovered["ip_address"], discovered["device_type"])
            await db.update_host_status(new_id, discovered["status"])
            if model or sw_version:
                await db.update_host_device_info(new_id, model, sw_version)
            added += 1
            continue

        if (
            existing.get("hostname") != discovered["hostname"]
            or existing.get("device_type") != discovered["device_type"]
        ):
            await db.update_host(existing["id"], discovered["hostname"], discovered["ip_address"], discovered["device_type"])
            updated += 1
        if model or sw_version:
            await db.update_host_device_info(existing["id"], model, sw_version)
        await db.update_host_status(existing["id"], discovered["status"])

    if remove_absent:
        discovered_ips = set(normalized_discovered)
        for ip, existing in existing_by_ip.items():
            if ip in discovered_ips:
                continue
            await db.remove_host(existing["id"])
            removed += 1

    return {
        "added": added,
        "updated": updated,
        "removed": removed,
        "matched": len(normalized_discovered),
        "existing_before": len(existing_hosts),
        "existing_after": len(existing_hosts) + added - removed,
    }


# ── Background loops ─────────────────────────────────────────────────────────


async def _run_discovery_sync_once() -> dict:
    DISCOVERY_SYNC_CONFIG = state.DISCOVERY_SYNC_CONFIG
    if not DISCOVERY_SYNC_CONFIG.get("enabled"):
        return {"enabled": False, "profiles": 0, "synced_groups": 0, "errors": 0}

    profiles = DISCOVERY_SYNC_CONFIG.get("profiles", [])
    synced_groups = 0
    errors = 0
    for profile in profiles:
        group_id = int(profile.get("group_id", 0))
        if group_id <= 0:
            continue
        group = await db.get_group(group_id)
        if not group:
            errors += 1
            LOGGER.warning("discovery sync: skipped missing group_id=%s", group_id)
            continue
        try:
            body = DiscoverySyncRequest.model_validate({
                "cidrs": profile.get("cidrs", []),
                "timeout_seconds": profile.get("timeout_seconds", state.DISCOVERY_DEFAULT_TIMEOUT_SECONDS),
                "max_hosts": profile.get("max_hosts", state.DISCOVERY_DEFAULT_MAX_HOSTS),
                "device_type": profile.get("device_type", "unknown"),
                "hostname_prefix": profile.get("hostname_prefix", "discovered"),
                "use_snmp": profile.get("use_snmp", True),
                "remove_absent": profile.get("remove_absent", False),
            })
            _, discovered = await _discover_hosts(body, group_id=group_id)
            result = await _sync_group_hosts(group_id, discovered, remove_absent=body.remove_absent)
            synced_groups += 1
            LOGGER.info(
                "discovery sync: group_id=%s discovered=%s added=%s updated=%s removed=%s",
                group_id,
                len(discovered),
                result["added"],
                result["updated"],
                result["removed"],
            )
            increment_metric("inventory.discovery.sync.success")
        except Exception as exc:
            errors += 1
            LOGGER.warning("discovery sync failed for group_id=%s: %s", group_id, redact_value(str(exc)))
            increment_metric("inventory.discovery.sync.failed")

    return {
        "enabled": True,
        "profiles": len(profiles),
        "synced_groups": synced_groups,
        "errors": errors,
    }


async def _discovery_sync_loop() -> None:
    while True:
        try:
            await _run_discovery_sync_once()
            await asyncio.sleep(int(state.DISCOVERY_SYNC_CONFIG.get("interval_seconds", state.DISCOVERY_SYNC_DEFAULTS["interval_seconds"])))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("discovery sync loop failure: %s", redact_value(str(exc)))
            increment_metric("inventory.discovery.sync.loop.failed")
            await asyncio.sleep(state.DISCOVERY_SYNC_DEFAULTS["interval_seconds"])


# ══════════════════════════════════════════════════════════════════════════════
# Admin routes (admin_router — registered with require_admin dependency)
# ══════════════════════════════════════════════════════════════════════════════


@admin_router.get("/api/admin/discovery-sync")
async def admin_get_discovery_sync_config():
    return state.DISCOVERY_SYNC_CONFIG


@admin_router.put("/api/admin/discovery-sync")
async def admin_update_discovery_sync_config(body: dict):
    state.DISCOVERY_SYNC_CONFIG = state._sanitize_discovery_sync_config(body)
    await db.set_auth_setting("discovery_sync", state.DISCOVERY_SYNC_CONFIG)
    return state.DISCOVERY_SYNC_CONFIG


@admin_router.post("/api/admin/discovery-sync/run-now")
async def admin_run_discovery_sync_now():
    result = await _run_discovery_sync_once()
    return {"ok": True, "result": result}


@admin_router.get("/api/admin/snmp-discovery")
async def admin_get_snmp_discovery_config():
    return state.SNMP_DISCOVERY_CONFIG


@admin_router.put("/api/admin/snmp-discovery")
async def admin_update_snmp_discovery_config(body: dict):
    state.SNMP_DISCOVERY_CONFIG = state._sanitize_snmp_discovery_config(body)
    await db.set_auth_setting("snmp_discovery", state.SNMP_DISCOVERY_CONFIG)
    return state.SNMP_DISCOVERY_CONFIG


@admin_router.get("/api/admin/snmp-discovery-profiles")
async def admin_get_snmp_discovery_profiles():
    return state.SNMP_DISCOVERY_PROFILES


# ── Named SNMP Profiles CRUD ─────────────────────────────────────────────────
# NOTE: GET /api/admin/snmp-profiles uses require_auth (not admin) in the original.
# It is placed on the main `router` so app.py can register it with inventory deps.


@router.get("/api/admin/snmp-profiles")
async def admin_list_snmp_profiles():
    return list(state.SNMP_PROFILES.values())


@admin_router.post("/api/admin/snmp-profiles")
async def admin_create_snmp_profile(body: dict):
    profile_id = str(uuid.uuid4())
    profile = state._sanitize_snmp_profile(profile_id, body)
    if not profile["name"]:
        raise HTTPException(400, "Profile name is required")
    state.SNMP_PROFILES[profile_id] = profile
    await db.set_auth_setting("snmp_profiles", state.SNMP_PROFILES)
    return profile


@admin_router.put("/api/admin/snmp-profiles/{profile_id}")
async def admin_update_snmp_profile(profile_id: str, body: dict):
    if profile_id not in state.SNMP_PROFILES:
        raise HTTPException(404, "Profile not found")
    profile = state._sanitize_snmp_profile(profile_id, body)
    if not profile["name"]:
        raise HTTPException(400, "Profile name is required")
    state.SNMP_PROFILES[profile_id] = profile
    await db.set_auth_setting("snmp_profiles", state.SNMP_PROFILES)
    return profile


@admin_router.delete("/api/admin/snmp-profiles/{profile_id}")
async def admin_delete_snmp_profile(profile_id: str):
    if profile_id not in state.SNMP_PROFILES:
        raise HTTPException(404, "Profile not found")
    del state.SNMP_PROFILES[profile_id]
    # Unassign any groups using this profile
    changed = False
    for gid in list(state.GROUP_SNMP_ASSIGNMENTS):
        if state.GROUP_SNMP_ASSIGNMENTS[gid] == profile_id:
            del state.GROUP_SNMP_ASSIGNMENTS[gid]
            changed = True
    await db.set_auth_setting("snmp_profiles", state.SNMP_PROFILES)
    if changed:
        await db.set_auth_setting("group_snmp_assignments", state.GROUP_SNMP_ASSIGNMENTS)
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Inventory-feature routes (router — registered with require_auth + require_feature("inventory"))
# ══════════════════════════════════════════════════════════════════════════════


# ── Group SNMP Profile Assignment ────────────────────────────────────────────


@router.get("/api/inventory/{group_id}/snmp-profile-assignment")
async def get_group_snmp_profile_assignment(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile_id = state.GROUP_SNMP_ASSIGNMENTS.get(group_id, "")
    profile = state.SNMP_PROFILES.get(profile_id) if profile_id else None
    return {"group_id": group_id, "snmp_profile_id": profile_id, "profile_name": profile["name"] if profile else ""}


@router.put("/api/inventory/{group_id}/snmp-profile-assignment")
async def update_group_snmp_profile_assignment(group_id: int, body: dict):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile_id = str(body.get("snmp_profile_id", "")).strip()
    if profile_id and profile_id not in state.SNMP_PROFILES:
        raise HTTPException(400, "SNMP profile not found")
    if profile_id:
        state.GROUP_SNMP_ASSIGNMENTS[group_id] = profile_id
    else:
        state.GROUP_SNMP_ASSIGNMENTS.pop(group_id, None)
    await db.set_auth_setting("group_snmp_assignments", state.GROUP_SNMP_ASSIGNMENTS)
    profile = state.SNMP_PROFILES.get(profile_id) if profile_id else None
    return {"group_id": group_id, "snmp_profile_id": profile_id, "profile_name": profile["name"] if profile else ""}


# ── Inventory Group CRUD ─────────────────────────────────────────────────────


@router.get("/api/inventory")
async def list_groups(include_hosts: bool = Query(default=False)):
    if include_hosts:
        return await db.get_all_groups_with_hosts()
    return await db.get_all_groups()


@router.get("/api/inventory/export/csv")
async def export_inventory_csv():
    """Export all inventory hosts as a CSV file."""
    rows = await db.get_all_hosts_for_export()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Hostname", "IP Address", "Model", "Software Version", "Device Type", "Status", "Group"])
    for r in rows:
        writer.writerow([
            r.get("hostname", ""),
            r.get("ip_address", ""),
            r.get("model", ""),
            r.get("software_version", ""),
            r.get("device_type", ""),
            r.get("status", ""),
            r.get("group_name", ""),
        ])
    return StreamingResponse(
        io.StringIO(output.getvalue()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inventory_export.csv"},
    )


@router.post("/api/inventory", status_code=201)
async def create_group(body: GroupCreate):
    gid = await db.create_group(body.name, body.description)
    return {"id": gid, "name": body.name}


@router.put("/api/inventory/{group_id}")
async def update_group(group_id: int, body: GroupUpdate):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    await db.update_group(group_id, body.name, body.description)
    return {"ok": True}


@router.get("/api/inventory/{group_id}")
async def get_group(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    hosts = await db.get_hosts_for_group(group_id)
    return {**group, "hosts": hosts}


@router.delete("/api/inventory/{group_id}")
async def delete_group(group_id: int):
    await db.delete_group(group_id)
    return {"ok": True}


# ── Hosts ────────────────────────────────────────────────────────────────────


@router.get("/api/inventory/{group_id}/hosts")
async def list_hosts(group_id: int):
    return await db.get_hosts_for_group(group_id)


@router.post("/api/inventory/{group_id}/hosts", status_code=201)
async def add_host(group_id: int, body: HostCreate):
    hid = await db.add_host(group_id, body.hostname, body.ip_address, body.device_type)
    return {"id": hid}


@router.put("/api/hosts/{host_id}")
async def update_host(host_id: int, body: HostUpdate):
    await db.update_host(host_id, body.hostname, body.ip_address, body.device_type)
    return {"ok": True}


@router.delete("/api/hosts/{host_id}")
async def remove_host(host_id: int):
    await db.remove_host(host_id)
    return {"ok": True}


@router.post("/api/hosts/bulk-delete")
async def bulk_delete_hosts(body: dict):
    host_ids = body.get("host_ids", [])
    if not host_ids or not isinstance(host_ids, list):
        raise HTTPException(400, "host_ids must be a non-empty list")
    host_ids = [int(h) for h in host_ids]
    deleted = await db.bulk_delete_hosts(host_ids)
    return {"deleted": deleted}


@router.post("/api/hosts/move")
async def move_hosts(body: dict):
    host_ids = body.get("host_ids", [])
    target_group_id = body.get("target_group_id")
    if not host_ids or not isinstance(host_ids, list):
        raise HTTPException(400, "host_ids must be a non-empty list")
    if not target_group_id:
        raise HTTPException(400, "target_group_id is required")
    target_group_id = int(target_group_id)
    group = await db.get_group(target_group_id)
    if not group:
        raise HTTPException(404, "Target group not found")
    host_ids = [int(h) for h in host_ids]
    moved = await db.move_hosts(host_ids, target_group_id)
    return {"moved": moved}


# ── Discovery routes ─────────────────────────────────────────────────────────


@router.post("/api/inventory/{group_id}/discovery/scan")
async def discovery_scan(group_id: int, body: DiscoveryScanRequest):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    scanned_count, discovered = await _discover_hosts(body, group_id=group_id)
    return {
        "group_id": group_id,
        "scanned_hosts": scanned_count,
        "discovered_count": len(discovered),
        "discovered_hosts": discovered,
    }


@router.post("/api/inventory/{group_id}/discovery/scan/stream")
async def discovery_scan_stream(group_id: int, body: DiscoveryScanRequest):
    """SSE streaming scan -- yields per-host results as they complete."""
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")

    targets = _expand_scan_targets(body.cidrs, body.max_hosts)
    total = len(targets)
    semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)

    async def _scan_one(ip_address: str) -> tuple[str, dict | None]:
        async with semaphore:
            result = await _probe_discovery_target(
                ip_address=ip_address,
                timeout_seconds=body.timeout_seconds,
                device_type=body.device_type,
                hostname_prefix=body.hostname_prefix,
                use_snmp=body.use_snmp,
                snmp_config=snmp_cfg,
            )
            return ip_address, result

    async def event_generator():
        # Send initial metadata
        yield f"data: {json.dumps({'type': 'start', 'total': total})}\n\n"

        scanned = 0
        discovered = []
        tasks = [asyncio.create_task(_scan_one(ip)) for ip in targets]

        for coro in asyncio.as_completed(tasks):
            ip_address, result = await coro
            scanned += 1
            if result is not None:
                discovered.append(result)
            yield f"data: {json.dumps({'type': 'progress', 'scanned': scanned, 'total': total, 'ip': ip_address, 'found': result is not None, 'host': result})}\n\n"

        discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
        yield f"data: {json.dumps({'type': 'done', 'scanned_hosts': total, 'discovered_count': len(discovered), 'discovered_hosts': discovered})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/api/inventory/{group_id}/snmp-discovery-profile")
async def get_group_snmp_discovery_profile(group_id: int):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile = state.SNMP_DISCOVERY_PROFILES.get(group_id)
    if profile:
        return profile
    return state._sanitize_snmp_discovery_profile(group_id, {})


@router.put("/api/inventory/{group_id}/snmp-discovery-profile")
async def update_group_snmp_discovery_profile(group_id: int, body: dict):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    profile = state._sanitize_snmp_discovery_profile(group_id, body)
    state.SNMP_DISCOVERY_PROFILES[group_id] = profile
    await db.set_auth_setting("snmp_discovery_profiles", state.SNMP_DISCOVERY_PROFILES)
    return profile


@router.post("/api/inventory/{group_id}/snmp-discovery-profile/test")
async def test_group_snmp_profile(group_id: int, body: dict):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    target_ip = str(body.get("target_ip", "")).strip()
    if not target_ip:
        raise HTTPException(400, "target_ip is required")
    snmp_config = state._resolve_snmp_discovery_config(group_id)
    if not snmp_config.get("enabled"):
        raise HTTPException(400, "SNMP is not enabled for this group")
    timeout = float(snmp_config.get("timeout_seconds", 1.2))
    try:
        result = await _snmp_get(target_ip, timeout, snmp_config)
    except Exception as exc:
        return {"success": False, "target_ip": target_ip, "error": str(exc)}
    if result is None:
        return {"success": False, "target_ip": target_ip, "error": "SNMP query failed -- no response or bad credentials"}
    return {"success": True, "target_ip": target_ip, "result": result}


@router.post("/api/inventory/{group_id}/discovery/sync")
async def discovery_sync(group_id: int, body: DiscoverySyncRequest, request: Request):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")

    # If no CIDRs provided, auto-populate from the group's existing host IPs
    if not body.cidrs:
        existing_hosts = await db.get_hosts_for_group(group_id)
        host_ips = [str(h["ip_address"]) for h in existing_hosts if h.get("ip_address")]
        if not host_ips:
            raise HTTPException(400, "Group has no hosts to sync. Add hosts first or provide CIDR targets.")
        body.cidrs = host_ips

    scanned_count, discovered = await _discover_hosts(body, group_id=group_id)
    sync_result = await _sync_group_hosts(group_id, discovered, remove_absent=body.remove_absent)
    session = _get_session(request)
    audit_user = session["user"] if session else "api-token"

    await _audit(
        "inventory",
        "discovery.sync",
        user=audit_user,
        detail=(
            f"group_id={group_id} scanned={scanned_count} discovered={len(discovered)} "
            f"added={sync_result['added']} updated={sync_result['updated']} removed={sync_result['removed']}"
        ),
        correlation_id=_corr_id(request),
    )

    return {
        "group_id": group_id,
        "scanned_hosts": scanned_count,
        "discovered_count": len(discovered),
        "sync": sync_result,
    }


@router.post("/api/inventory/{group_id}/discovery/onboard")
async def discovery_onboard(group_id: int, body: DiscoveryOnboardRequest, request: Request):
    group = await db.get_group(group_id)
    if not group:
        raise HTTPException(404, "Group not found")
    if not body.discovered_hosts:
        raise HTTPException(400, "No discovered hosts provided")

    sync_result = await _sync_group_hosts(group_id, body.discovered_hosts, remove_absent=False)
    session = _get_session(request)
    audit_user = session["user"] if session else "api-token"
    await _audit(
        "inventory",
        "discovery.onboard",
        user=audit_user,
        detail=(
            f"group_id={group_id} provided={len(body.discovered_hosts)} "
            f"added={sync_result['added']} updated={sync_result['updated']}"
        ),
        correlation_id=_corr_id(request),
    )
    return {
        "group_id": group_id,
        "provided_count": len(body.discovered_hosts),
        "sync": sync_result,
    }
