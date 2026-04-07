"""
upgrades.py -- IOS-XE Staged Upgrade Tool

Campaign-based upgrade manager with per-device phase tracking,
image management, and real-time WebSocket streaming.

Ported from standalone iosxe_upgrade.py into the Plexus platform.
"""

import asyncio
import hashlib
import json
import os
import re
import socket
import time
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel

import routes.database as db
from routes.crypto import decrypt

from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

try:
    from netmiko import ConnectHandler, file_transfer
    from netmiko.exceptions import NetmikoTimeoutException
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False

router = APIRouter()
ws_router = APIRouter()
LOGGER = configure_logging("plexus.upgrades")

SOFTWARE_IMAGES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "software_images",
)

BACKUPS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "backups", "upgrades",
)

# Validation patterns for values interpolated into device CLI commands
_SAFE_IMAGE_NAME_RE = re.compile(r'^[A-Za-z0-9._\-]+$')
_SAFE_DEST_PATH_RE = re.compile(r'^[a-z]+[0-9]*:/?$')   # flash: bootflash:/ slot0: etc.


def _validate_cli_inputs(image_name: str, dest_path: str) -> str | None:
    """Return an error message if image_name or dest_path contain unsafe characters.

    These values are interpolated into device CLI commands (dir, verify /md5,
    install add) so they must be restricted to safe characters to prevent
    command injection via Netmiko.
    """
    if not _SAFE_IMAGE_NAME_RE.match(image_name):
        return f"Image name contains invalid characters: {image_name!r}"
    if not _SAFE_DEST_PATH_RE.match(dest_path):
        return f"Destination path contains invalid characters: {dest_path!r}"
    return None


# ── Late-binding auth dependencies (injected by app.py) ──────────────────────

_require_auth = None
_require_feature = None
_verify_session_token = None
_get_user_features = None


def init_upgrades(require_auth, require_feature, verify_session_token=None, get_user_features=None):
    global _require_auth, _require_feature, _verify_session_token, _get_user_features
    _require_auth = require_auth
    _require_feature = require_feature
    _verify_session_token = verify_session_token
    _get_user_features = get_user_features


# ── Pydantic Models ──────────────────────────────────────────────────────────


class ImageUpdate(BaseModel):
    model_pattern: str = ""
    version: str = ""
    platform: str = "iosxe"
    notes: str = ""


class CampaignCreate(BaseModel):
    name: str
    description: str = ""
    image_map: dict = {}
    options: dict = {}
    host_ids: list[int] = []
    ad_hoc_ips: list[str] = []
    credential_id: int


class CampaignUpdate(BaseModel):
    name: str
    description: str = ""
    image_map: dict = {}
    options: dict = {}
    host_ids: list[int] = []
    ad_hoc_ips: list[str] = []
    credential_id: int


class CampaignPhaseRequest(BaseModel):
    phase: str  # "prestage", "transfer", "activate"
    device_ids: list[int] = []  # empty = all devices in campaign


# ── Module-level state ───────────────────────────────────────────────────────

_campaign_sockets: dict[int, list[WebSocket]] = {}
_running_campaigns: dict[int, asyncio.Task] = {}


# ── Helper: broadcast event to WebSocket subscribers ─────────────────────────


async def _broadcast_upgrade_event(campaign_id: int, event: dict):
    """Send event to all connected WebSocket clients for a campaign."""
    sockets = _campaign_sockets.get(campaign_id, [])
    dead = []
    for ws in sockets:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        sockets.remove(ws)


async def _emit(campaign_id: int, device_id: int | None, level: str, message: str, host: str = ""):
    """Persist event to DB and broadcast to WebSocket clients."""
    event_id = await db.add_upgrade_event(campaign_id, device_id, level, message, host=host)
    event = {
        "type": "upgrade_event",
        "campaign_id": campaign_id,
        "device_id": device_id,
        "level": level,
        "message": message,
        "host": host,
        "timestamp": datetime.now(UTC).isoformat(),
        "event_id": event_id,
    }
    await _broadcast_upgrade_event(campaign_id, event)


async def _emit_device_status(campaign_id: int, device_id: int, **statuses):
    """Broadcast a device status change so the UI can update checkmarks live."""
    event = {
        "type": "device_status",
        "campaign_id": campaign_id,
        "device_id": device_id,
        **statuses,
    }
    await _broadcast_upgrade_event(campaign_id, event)


# ═════════════════════════════════════════════════════════════════════════════
# IMAGE MANAGEMENT API
# ═════════════════════════════════════════════════════════════════════════════


# Maximum upload size: 2 GiB (IOS-XE images are typically 400-900 MB)
_MAX_IMAGE_UPLOAD_BYTES = int(os.getenv("PLEXUS_MAX_IMAGE_UPLOAD_MB", "2048")) * 1024 * 1024


@router.post("/api/upgrades/images")
async def upload_image(request: Request, file: UploadFile = File(...)):
    """Upload a software image file."""
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    os.makedirs(SOFTWARE_IMAGES_DIR, exist_ok=True)

    filename = os.path.basename(file.filename or "unknown.bin")
    # Validate filename: only allow safe characters
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}', filename):
        raise HTTPException(400, "Invalid image filename — use only alphanumeric, dot, hyphen, underscore")
    dest = os.path.join(SOFTWARE_IMAGES_DIR, filename)

    # Stream to disk and compute MD5, enforcing size limit
    md5 = hashlib.md5()
    size = 0
    try:
        with open(dest, "wb") as f:
            while True:
                chunk = await file.read(8 * 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > _MAX_IMAGE_UPLOAD_BYTES:
                    raise HTTPException(
                        413, f"Image exceeds maximum upload size of {_MAX_IMAGE_UPLOAD_BYTES // (1024*1024)} MB"
                    )
                f.write(chunk)
                md5.update(chunk)
    except HTTPException:
        # Clean up partial file on size limit exceeded
        if os.path.isfile(dest):
            os.remove(dest)
        raise

    md5_hash = md5.hexdigest()

    # Auto-detect version from filename
    ver_match = re.search(r'(\d+\.\d+\.\d+)', filename)
    version = ver_match.group(1) if ver_match else ""

    # Auto-detect model pattern from filename
    model_pattern = ""
    if "lite" in filename.lower():
        model_pattern = "9200"
    elif "cat9k" in filename.lower():
        model_pattern = "9300"

    image_id = await db.create_upgrade_image(
        filename=filename,
        original_name=filename,
        file_size=size,
        md5_hash=md5_hash,
        model_pattern=model_pattern,
        version=version,
        platform="iosxe",
        notes="",
        uploaded_by=user,
    )

    await _audit("upgrades", "image_upload", user=user, detail=f"Uploaded {filename} ({size} bytes, md5={md5_hash})")
    LOGGER.info("Image uploaded: %s (%s bytes) by %s", filename, size, user)

    return {"id": image_id, "filename": filename, "file_size": size, "md5_hash": md5_hash, "version": version, "model_pattern": model_pattern}


@router.get("/api/upgrades/images")
async def list_images():
    return await db.get_all_upgrade_images()


@router.get("/api/upgrades/images/{image_id}")
async def get_image(image_id: int):
    img = await db.get_upgrade_image(image_id)
    if not img:
        raise HTTPException(404, "Image not found")
    return img


@router.patch("/api/upgrades/images/{image_id}")
async def update_image(image_id: int, body: ImageUpdate, request: Request):
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    updated = await db.update_upgrade_image(
        image_id,
        model_pattern=body.model_pattern,
        version=body.version,
        platform=body.platform,
        notes=body.notes,
    )
    if not updated:
        raise HTTPException(404, "Image not found")

    await _audit("upgrades", "image_update", user=user, detail=f"Updated image {image_id}")
    return {"ok": True}


@router.delete("/api/upgrades/images/{image_id}")
async def delete_image(image_id: int, request: Request):
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    img = await db.get_upgrade_image(image_id)
    if not img:
        raise HTTPException(404, "Image not found")

    # Remove file from disk (sanitize filename to prevent path traversal)
    safe_name = os.path.basename(img["filename"])
    fpath = os.path.realpath(os.path.join(SOFTWARE_IMAGES_DIR, safe_name))
    if not fpath.startswith(os.path.realpath(SOFTWARE_IMAGES_DIR)):
        raise HTTPException(400, "Invalid image filename")
    if os.path.isfile(fpath):
        os.remove(fpath)

    await db.delete_upgrade_image(image_id)
    await _audit("upgrades", "image_delete", user=user, detail=f"Deleted image {img['filename']}")
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# CAMPAIGN MANAGEMENT API
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/api/upgrades/campaigns")
async def create_campaign(body: CampaignCreate, request: Request):
    """Create a new upgrade campaign with target devices."""
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    campaign_id = await db.create_upgrade_campaign(
        name=body.name,
        description=body.description,
        image_map=body.image_map,
        options={**body.options, "credential_id": body.credential_id},
        created_by=user,
    )

    # Add devices from host_ids (inventory)
    added = 0
    for hid in body.host_ids:
        host = await db.get_host(hid)
        if host:
            try:
                await db.add_upgrade_device(
                    campaign_id, hid, host["ip_address"], host.get("hostname", ""),
                )
                added += 1
            except Exception:
                pass  # duplicate

    # Add ad-hoc IPs
    for ip in body.ad_hoc_ips:
        ip = ip.strip()
        if ip:
            try:
                await db.add_upgrade_device(campaign_id, None, ip, "")
                added += 1
            except Exception:
                pass

    await _audit("upgrades", "campaign_create", user=user,
                 detail=f"Created campaign '{body.name}' with {added} devices")
    LOGGER.info("Campaign created: %s (%d devices) by %s", body.name, added, user)

    return {"id": campaign_id, "devices_added": added}


@router.get("/api/upgrades/campaigns")
async def list_campaigns():
    campaigns = await db.get_all_upgrade_campaigns()
    # Enrich with device counts
    for c in campaigns:
        devices = await db.get_upgrade_devices(c["id"])
        c["device_count"] = len(devices)
        c["devices_completed"] = sum(1 for d in devices if d["phase"] == "completed")
        c["devices_failed"] = sum(1 for d in devices if d["phase"] == "failed")
    return campaigns


@router.get("/api/upgrades/campaigns/{campaign_id}")
async def get_campaign(campaign_id: int):
    campaign = await db.get_upgrade_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    campaign["devices"] = await db.get_upgrade_devices(campaign_id)
    return campaign


@router.patch("/api/upgrades/campaigns/{campaign_id}")
async def update_campaign(campaign_id: int, body: CampaignUpdate, request: Request):
    """Update an existing campaign's settings and device list."""
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    campaign = await db.get_upgrade_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    if campaign_id in _running_campaigns:
        raise HTTPException(409, "Cannot edit a running campaign")

    # Update campaign metadata
    await db.update_upgrade_campaign(
        campaign_id,
        name=body.name,
        description=body.description,
        image_map=body.image_map,
        options={**body.options, "credential_id": body.credential_id},
    )

    # Rebuild device list: remove pending devices, re-add from new selections
    await db.delete_upgrade_devices_by_campaign(campaign_id)

    # Collect existing IPs that weren't deleted (already have progress)
    remaining = await db.get_upgrade_devices(campaign_id)
    existing_ips = {d["ip_address"] for d in remaining}

    added = 0
    for hid in body.host_ids:
        host = await db.get_host(hid)
        if host and host["ip_address"] not in existing_ips:
            try:
                await db.add_upgrade_device(
                    campaign_id, hid, host["ip_address"], host.get("hostname", ""),
                )
                added += 1
            except Exception:
                pass

    for ip in body.ad_hoc_ips:
        ip = ip.strip()
        if ip and ip not in existing_ips:
            try:
                await db.add_upgrade_device(campaign_id, None, ip, "")
                added += 1
            except Exception:
                pass

    total_devices = len(await db.get_upgrade_devices(campaign_id))
    await _audit("upgrades", "campaign_update", user=user,
                 detail=f"Updated campaign '{body.name}' — {total_devices} devices ({added} new)")
    LOGGER.info("Campaign updated: %s (%d total devices, %d new) by %s", body.name, total_devices, added, user)

    return {"ok": True, "total_devices": total_devices, "devices_added": added}


@router.delete("/api/upgrades/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: int, request: Request):
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    campaign = await db.get_upgrade_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    # Don't delete running campaigns
    if campaign_id in _running_campaigns:
        raise HTTPException(409, "Campaign is currently running")

    await db.delete_upgrade_campaign(campaign_id)
    await _audit("upgrades", "campaign_delete", user=user, detail=f"Deleted campaign {campaign_id}")
    return {"ok": True}


@router.get("/api/upgrades/campaigns/{campaign_id}/events")
async def get_campaign_events(campaign_id: int, device_id: int = None, limit: int = 10000):
    return await db.get_upgrade_events(campaign_id, device_id=device_id, limit=limit)


# ═════════════════════════════════════════════════════════════════════════════
# BACKUP MANAGEMENT API
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/upgrades/backups")
async def list_backups():
    """List all config backup files from upgrade prestage."""
    if not os.path.isdir(BACKUPS_DIR):
        return []

    backups = []
    for fname in sorted(os.listdir(BACKUPS_DIR), reverse=True):
        fpath = os.path.join(BACKUPS_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        stat = os.stat(fpath)
        backups.append({
            "filename": fname,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        })
    return backups


@router.get("/api/upgrades/backups/{filename}")
async def download_backup(filename: str):
    """Download a specific backup file."""
    # Prevent path traversal (CWE-22)
    safe = os.path.basename(filename)
    fpath = os.path.realpath(os.path.join(BACKUPS_DIR, safe))
    if not fpath.startswith(os.path.realpath(BACKUPS_DIR) + os.sep):
        raise HTTPException(400, "Invalid filename")

    if not os.path.isfile(fpath):
        raise HTTPException(404, "Backup file not found")

    return FileResponse(fpath, filename=safe, media_type="text/plain")


@router.delete("/api/upgrades/backups/{filename}")
async def delete_backup(filename: str, request: Request):
    """Delete a specific backup file."""
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    safe = os.path.basename(filename)
    fpath = os.path.realpath(os.path.join(BACKUPS_DIR, safe))
    if not fpath.startswith(os.path.realpath(BACKUPS_DIR) + os.sep):
        raise HTTPException(400, "Invalid filename")

    if not os.path.isfile(fpath):
        raise HTTPException(404, "Backup file not found")

    os.remove(fpath)
    await _audit("upgrades", "backup_delete", user=user, detail=f"Deleted backup {safe}")
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# PHASE EXECUTION API
# ═════════════════════════════════════════════════════════════════════════════


@router.post("/api/upgrades/campaigns/{campaign_id}/execute")
async def execute_phase(campaign_id: int, body: CampaignPhaseRequest, request: Request):
    """Execute a specific phase (prestage/transfer/activate) for a campaign."""
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    if not NETMIKO_AVAILABLE:
        raise HTTPException(500, "netmiko is not installed")

    campaign = await db.get_upgrade_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    if body.phase not in ("prestage", "transfer", "activate", "verify"):
        raise HTTPException(400, f"Invalid phase: {body.phase}")

    if campaign_id in _running_campaigns:
        raise HTTPException(409, "Campaign is already running a phase")

    # Get credential
    options = json.loads(campaign["options"]) if isinstance(campaign["options"], str) else campaign["options"]
    cred_id = options.get("credential_id")
    if not cred_id:
        raise HTTPException(400, "No credential_id in campaign options")

    cred = await db.get_credential_raw(cred_id)
    if not cred:
        raise HTTPException(400, f"Credential {cred_id} not found")

    credentials = {
        "username": cred["username"],
        "password": decrypt(cred["password"]),
        "secret": decrypt(cred["secret"]) if cred.get("secret") else "",
    }

    # Get devices
    all_devices = await db.get_upgrade_devices(campaign_id)
    if body.device_ids:
        devices = [d for d in all_devices if d["id"] in body.device_ids]
    else:
        devices = all_devices

    if not devices:
        raise HTTPException(400, "No devices to process")

    # Parse image map
    image_map_raw = json.loads(campaign["image_map"]) if isinstance(campaign["image_map"], str) else campaign["image_map"]
    # image_map: {"pattern": "image_filename", ...}
    # Sort by pattern length descending for specificity matching
    image_map = sorted(image_map_raw.items(), key=lambda x: len(x[0]), reverse=True)

    await db.update_upgrade_campaign(campaign_id, status=f"running_{body.phase}")
    await _audit("upgrades", "phase_execute", user=user,
                 detail=f"Executing {body.phase} on campaign {campaign_id} ({len(devices)} devices)")

    # Launch async task
    task = asyncio.create_task(
        _run_phase(campaign_id, body.phase, devices, credentials, image_map, options)
    )
    _running_campaigns[campaign_id] = task

    def _on_done(t):
        _running_campaigns.pop(campaign_id, None)

    task.add_done_callback(_on_done)

    return {"ok": True, "phase": body.phase, "device_count": len(devices)}


@router.post("/api/upgrades/campaigns/{campaign_id}/cancel")
async def cancel_campaign(campaign_id: int, request: Request):
    """Cancel a running campaign phase."""
    task = _running_campaigns.get(campaign_id)
    if not task:
        raise HTTPException(404, "No running phase for this campaign")

    task.cancel()
    _running_campaigns.pop(campaign_id, None)
    await db.update_upgrade_campaign(campaign_id, status="cancelled")
    await _emit(campaign_id, None, "warn", "Campaign phase cancelled by user")

    # Notify WebSocket
    await _broadcast_upgrade_event(campaign_id, {
        "type": "campaign_complete",
        "campaign_id": campaign_id,
        "status": "cancelled",
    })

    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# WEBSOCKET — Real-time upgrade streaming
# ═════════════════════════════════════════════════════════════════════════════


@ws_router.websocket("/ws/upgrades/{campaign_id}")
async def upgrade_websocket(ws: WebSocket, campaign_id: int):
    """Stream upgrade events to the browser in real-time."""
    await ws.accept()

    # Verify auth via query param or cookie
    if _verify_session_token:
        token = ws.cookies.get("session") or ws.query_params.get("token", "")
        session = _verify_session_token(token) if token else None
        if not session:
            await ws.close(code=4001, reason="Unauthorized")
            return

    # Send full historical events as a single batch to avoid keepalive timeouts
    events = await db.get_upgrade_events(campaign_id, limit=10000)
    last_id = events[-1]["id"] if events else 0
    try:
        await ws.send_json({
            "type": "replay_batch",
            "campaign_id": campaign_id,
            "last_event_id": last_id,
            "events": [
                {
                    "type": "upgrade_event",
                    "campaign_id": campaign_id,
                    "device_id": ev.get("device_id"),
                    "level": ev["level"],
                    "message": ev["message"],
                    "host": ev.get("host", ""),
                    "timestamp": ev["timestamp"],
                    "event_id": ev["id"],
                }
                for ev in events
            ],
        })
    except Exception:
        return

    # Subscribe to live events
    if campaign_id not in _campaign_sockets:
        _campaign_sockets[campaign_id] = []
    _campaign_sockets[campaign_id].append(ws)

    try:
        while True:
            await ws.receive_text()  # Keep alive
    except WebSocketDisconnect:
        pass
    finally:
        sockets = _campaign_sockets.get(campaign_id, [])
        if ws in sockets:
            sockets.remove(ws)


# ═════════════════════════════════════════════════════════════════════════════
# UPGRADE ENGINE — Core Netmiko logic ported from iosxe_upgrade.py
# ═════════════════════════════════════════════════════════════════════════════


async def _run_phase(campaign_id, phase, devices, credentials, image_map, options):
    """Orchestrate a phase across all devices with concurrency control."""
    max_workers = min(options.get("parallel", 4), 8)

    await _emit(campaign_id, None, "info",
                f"Starting {phase} phase for {len(devices)} device(s) (max {max_workers} concurrent)")

    semaphore = asyncio.Semaphore(max_workers)

    async def _process_device(dev):
        async with semaphore:
            try:
                if phase == "prestage":
                    await _device_prestage(campaign_id, dev, credentials, image_map, options)
                elif phase == "transfer":
                    await _device_transfer(campaign_id, dev, credentials, image_map, options)
                elif phase == "activate":
                    await _device_activate(campaign_id, dev, credentials, image_map, options)
                elif phase == "verify":
                    await _device_verify(campaign_id, dev, credentials, image_map, options)
            except asyncio.CancelledError:
                await db.update_upgrade_device(dev["id"], **{f"{phase}_status": "cancelled", "phase": "cancelled"})
                raise
            except Exception as e:
                LOGGER.error("Unhandled error on device %s: %s", dev["ip_address"], e, exc_info=True)
                await db.update_upgrade_device(dev["id"], **{
                    f"{phase}_status": "failed",
                    "phase": "failed",
                    "error_message": str(e),
                })
                await _emit(campaign_id, dev["id"], "error", f"Unhandled error: {e}", host=dev["ip_address"])

    tasks = [asyncio.create_task(_process_device(d)) for d in devices]

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        raise

    # Update campaign status
    all_devs = await db.get_upgrade_devices(campaign_id)
    failed = sum(1 for d in all_devs if d.get(f"{phase}_status") == "failed")
    total = len(all_devs)

    if failed == total:
        final_status = f"{phase}_failed"
    elif failed > 0:
        final_status = f"{phase}_partial"
    else:
        final_status = f"{phase}_complete"

    await db.update_upgrade_campaign(campaign_id, status=final_status)
    await _emit(campaign_id, None, "success" if failed == 0 else "warn",
                f"{phase.title()} phase complete: {total - failed}/{total} succeeded, {failed} failed")

    # Small delay to ensure all _emit() DB writes are flushed before the
    # frontend reloads and replays history
    await asyncio.sleep(0.5)

    # Notify WebSocket clients
    await _broadcast_upgrade_event(campaign_id, {
        "type": "campaign_complete",
        "campaign_id": campaign_id,
        "status": final_status,
        "phase": phase,
    })


def _build_device_params(ip, credentials, options):
    """Build Netmiko device parameters."""
    return {
        "device_type": "cisco_xe",
        "host": ip,
        "username": credentials["username"],
        "password": credentials["password"],
        "secret": credentials.get("secret", credentials["password"]),
        "port": options.get("port", 22),
        "timeout": options.get("timeout", 120),
        "session_timeout": options.get("timeout", 120),
        "auth_timeout": 30,
    }


async def _connect_device(ip, credentials, options, retries=1):
    """Connect to a device via SSH with retry support."""
    device = _build_device_params(ip, credentials, options)
    last_err = None

    for attempt in range(1, retries + 1):
        try:
            conn = await asyncio.to_thread(ConnectHandler, **device)
            await asyncio.to_thread(conn.enable)
            return conn
        except Exception as e:
            last_err = e
            if attempt < retries:
                await asyncio.sleep(min(15 * (2 ** (attempt - 1)), 120))

    raise ConnectionError(f"Failed to connect to {ip} after {retries} attempts: {last_err}")


def _resolve_image(model, image_map):
    """Match a model string against the image map patterns."""
    if not model:
        return None
    model_upper = model.upper()
    for pattern, image_file in image_map:
        if pattern.upper() in model_upper:
            return image_file
    return None


async def _detect_model(conn, ip):
    """Detect switch model from show version output."""
    output = await asyncio.to_thread(conn.send_command, "show version", read_timeout=60)
    if not output:
        return None, None

    model = None
    version = None

    for line in output.splitlines():
        if not model:
            match = re.search(r'cisco\s+(C\S+)\s+\(', line, re.IGNORECASE)
            if match:
                model = match.group(1).upper()
            else:
                match = re.search(r'Model\s+Number\s*:\s*(\S+)', line, re.IGNORECASE)
                if match:
                    model = match.group(1).upper()
        if not version:
            match = re.search(r'Version\s+(\d+\.\d+\.\d+\S*)', line)
            if match:
                version = match.group(1)

    return model, version


# ── PRESTAGE ─────────────────────────────────────────────────────────────────


async def _device_prestage(campaign_id, dev, credentials, image_map, options):
    """Prestage: health check, backup config, write memory, remove inactive packages."""
    ip = dev["ip_address"]
    dev_id = dev["id"]

    await db.update_upgrade_device(dev_id, prestage_status="running", phase="prestage",
                                   started_at=datetime.now(UTC).isoformat())
    await _emit_device_status(campaign_id, dev_id, prestage_status="running")
    await _emit(campaign_id, dev_id, "info", f"Connecting to {ip}...", host=ip)

    try:
        conn = await _connect_device(ip, credentials, options, retries=options.get("retries", 2))
    except Exception as e:
        await db.update_upgrade_device(dev_id, prestage_status="failed", phase="failed",
                                       error_message=f"Connection failed: {e}")
        await _emit_device_status(campaign_id, dev_id, prestage_status="failed", error_message=f"Connection failed: {e}")
        await _emit(campaign_id, dev_id, "error", f"Connection failed: {e}", host=ip)
        return

    try:
        await _emit(campaign_id, dev_id, "success", "Connected", host=ip)

        # Detect model and current version
        model, current_version = await _detect_model(conn, ip)
        if model:
            await db.update_upgrade_device(dev_id, model=model or "", current_version=current_version or "")
            await _emit(campaign_id, dev_id, "info", f"Model: {model}, Version: {current_version}", host=ip)

            # Resolve target image from image map
            target_image = _resolve_image(model, image_map)
            if target_image:
                await db.update_upgrade_device(dev_id, target_image=target_image)
                await _emit(campaign_id, dev_id, "info", f"Target image: {target_image}", host=ip)
            else:
                await _emit(campaign_id, dev_id, "warn", f"No image map match for model {model}", host=ip)

        # Health check
        if not options.get("skip_health_check"):
            await _emit(campaign_id, dev_id, "info", "Running pre-flight health check...", host=ip)
            passed, warnings = await _health_check(conn, ip)
            health = "passed" if passed else "failed"
            await db.update_upgrade_device(dev_id, health_status=health)

            if not passed:
                await _emit(campaign_id, dev_id, "error",
                            f"Health check FAILED: {'; '.join(warnings)}", host=ip)
                await db.update_upgrade_device(dev_id, prestage_status="failed", phase="failed",
                                               error_message="Health check failed")
                await _emit_device_status(campaign_id, dev_id, prestage_status="failed", error_message="Health check failed")
                await asyncio.to_thread(conn.disconnect)
                return
            else:
                status_msg = "Health check passed"
                if warnings:
                    status_msg += f" (warnings: {'; '.join(warnings)})"
                await _emit(campaign_id, dev_id, "success", status_msg, host=ip)

        # Backup config
        if not options.get("skip_backup"):
            await _emit(campaign_id, dev_id, "info", "Backing up running-config...", host=ip)
            try:
                config = await asyncio.to_thread(conn.send_command, "show running-config", read_timeout=120)
                os.makedirs(BACKUPS_DIR, exist_ok=True)
                hostname = dev.get("hostname") or ip
                clean = re.sub(r'[^\w\-.]', '_', hostname)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = os.path.join(BACKUPS_DIR, f"backup_{clean}_{ts}.txt")
                with open(backup_file, "w") as f:
                    f.write(config)
                await _emit(campaign_id, dev_id, "success", f"Config backed up to {backup_file}", host=ip)
            except Exception as e:
                await _emit(campaign_id, dev_id, "warn", f"Backup failed: {e}", host=ip)

        # Write memory
        await _emit(campaign_id, dev_id, "info", "Running 'write memory'...", host=ip)
        try:
            output = await asyncio.to_thread(conn.send_command, "write memory", read_timeout=60)
            await _emit(campaign_id, dev_id, "success", "Configuration saved", host=ip)
        except Exception as e:
            await _emit(campaign_id, dev_id, "warn", f"Write memory failed: {e}", host=ip)

        # Remove inactive packages
        await _emit(campaign_id, dev_id, "info", "Removing inactive packages...", host=ip)
        try:
            output = await asyncio.to_thread(
                conn.send_command, "install remove inactive",
                expect_string=r"#|proceed|y/n|\[yes/no\]|\[y/n\]",
                read_timeout=300,
            )
            if any(x in output.lower() for x in ["proceed", "y/n", "yes/no"]):
                output += await asyncio.to_thread(
                    conn.send_command, "y", expect_string=r"#", read_timeout=600,
                )
            await _emit(campaign_id, dev_id, "success", "Inactive packages removed", host=ip)
        except Exception as e:
            await _emit(campaign_id, dev_id, "warn", f"Install remove inactive: {e}", host=ip)

        await db.update_upgrade_device(dev_id, prestage_status="completed", phase="prestage_done",
                                       phase_detail="Prestage completed successfully")
        await _emit_device_status(campaign_id, dev_id, prestage_status="completed")
        await _emit(campaign_id, dev_id, "success", "Prestage complete", host=ip)

    except Exception as e:
        await db.update_upgrade_device(dev_id, prestage_status="failed", phase="failed",
                                       error_message=str(e))
        await _emit_device_status(campaign_id, dev_id, prestage_status="failed", error_message=str(e))
        await _emit(campaign_id, dev_id, "error", f"Prestage failed: {e}", host=ip)
    finally:
        try:
            await asyncio.to_thread(conn.disconnect)
        except Exception:
            pass


# ── TRANSFER ─────────────────────────────────────────────────────────────────


async def _device_transfer(campaign_id, dev, credentials, image_map, options):
    """Transfer: check space, SCP image, verify MD5."""
    ip = dev["ip_address"]
    dev_id = dev["id"]
    dest_path = options.get("dest_path", "flash:")

    await db.update_upgrade_device(dev_id, transfer_status="running", phase="transfer",
                                   started_at=datetime.now(UTC).isoformat())
    await _emit_device_status(campaign_id, dev_id, transfer_status="running")
    await _emit(campaign_id, dev_id, "info", f"Connecting to {ip}...", host=ip)

    try:
        conn = await _connect_device(ip, credentials, options, retries=options.get("retries", 2))
    except Exception as e:
        await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                       error_message=f"Connection failed: {e}")
        await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=f"Connection failed: {e}")
        await _emit(campaign_id, dev_id, "error", f"Connection failed: {e}", host=ip)
        return

    try:
        await _emit(campaign_id, dev_id, "success", "Connected", host=ip)

        # Resolve target image
        target_image = dev.get("target_image", "")
        if not target_image:
            model, _ = await _detect_model(conn, ip)
            if model:
                target_image = _resolve_image(model, image_map)
                if target_image:
                    await db.update_upgrade_device(dev_id, model=model, target_image=target_image)
            if not target_image:
                await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                               error_message="No target image resolved")
                await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message="No target image resolved")
                await _emit(campaign_id, dev_id, "error", "Cannot determine target image", host=ip)
                return

        image_name = os.path.basename(target_image)

        # Check if device is already running the target version — skip transfer
        expected_version = _extract_version(image_name)
        if expected_version:
            det_model, running_version = await _detect_model(conn, ip)
            if det_model:
                await db.update_upgrade_device(dev_id, model=det_model, current_version=running_version or "")
            if running_version and expected_version in running_version:
                await _emit(campaign_id, dev_id, "success",
                            f"Already running target version {running_version} — skipping transfer", host=ip)
                await db.update_upgrade_device(dev_id,
                                               prestage_status="completed",
                                               transfer_status="completed",
                                               activate_status="completed",
                                               verify_status="completed",
                                               phase="verified",
                                               current_version=running_version,
                                               error_message="",
                                               completed_at=datetime.now(UTC).isoformat())
                await _emit_device_status(campaign_id, dev_id,
                                          prestage_status="completed",
                                          transfer_status="completed",
                                          activate_status="completed",
                                          verify_status="completed",
                                          error_message="")
                return

        image_path = os.path.realpath(os.path.join(SOFTWARE_IMAGES_DIR, image_name))
        if not image_path.startswith(os.path.realpath(SOFTWARE_IMAGES_DIR)):
            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                           error_message="Invalid image path")
            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message="Invalid image path")
            await _emit(campaign_id, dev_id, "error", "Invalid image path — possible path traversal", host=ip)
            return

        # Validate image_name and dest_path before using in device CLI commands
        cli_err = _validate_cli_inputs(image_name, dest_path)
        if cli_err:
            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                           error_message=cli_err)
            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=cli_err)
            await _emit(campaign_id, dev_id, "error", cli_err, host=ip)
            return

        if not os.path.isfile(image_path):
            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                           error_message=f"Image file not found: {image_path}")
            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=f"Image file not found: {image_path}")
            await _emit(campaign_id, dev_id, "error", f"Image file not found on server: {target_image}", host=ip)
            return

        # Compute local MD5
        local_md5 = None
        if not options.get("skip_md5"):
            await _emit(campaign_id, dev_id, "info", "Computing local MD5 hash...", host=ip)
            local_md5 = await asyncio.to_thread(_compute_md5, image_path)
            await _emit(campaign_id, dev_id, "info", f"Local MD5: {local_md5}", host=ip)

        # Check flash space
        await _emit(campaign_id, dev_id, "info", "Checking flash space...", host=ip)
        has_space, free_bytes = await _check_flash_space(conn, image_path, dest_path)
        if not has_space:
            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                           error_message="Insufficient flash space")
            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message="Insufficient flash space")
            await _emit(campaign_id, dev_id, "error", "Insufficient flash space", host=ip)
            return
        await _emit(campaign_id, dev_id, "info", f"Flash space OK ({(free_bytes or 0) / 1024 / 1024:.0f} MB free)", host=ip)

        # Check if image already exists
        exists = await asyncio.to_thread(_check_image_exists, conn, image_name, dest_path)
        if exists:
            await _emit(campaign_id, dev_id, "info", f"Image {image_name} already on flash", host=ip)
            if local_md5 and not options.get("skip_md5"):
                await _emit(campaign_id, dev_id, "info", "Verifying existing image integrity...", host=ip)
                md5_ok = await _verify_md5_on_switch(conn, image_name, dest_path, local_md5)
                if md5_ok:
                    await _emit(campaign_id, dev_id, "success", "Existing image matches - no transfer needed", host=ip)
                    await db.update_upgrade_device(dev_id, transfer_status="completed", phase="transfer_done")
                    await _emit_device_status(campaign_id, dev_id, transfer_status="completed")
                    return
                else:
                    await _emit(campaign_id, dev_id, "warn", "Existing image does NOT match - will re-transfer", host=ip)
            else:
                await _emit(campaign_id, dev_id, "success", "Image already on flash - skipping transfer", host=ip)
                await db.update_upgrade_device(dev_id, transfer_status="completed", phase="transfer_done")
                await _emit_device_status(campaign_id, dev_id, transfer_status="completed")
                return

        # Transfer via SCP
        await _emit(campaign_id, dev_id, "info", f"Starting SCP transfer of {image_name}...", host=ip)
        await _emit(campaign_id, dev_id, "info", "This may take 10-30 minutes for large images", host=ip)

        start_time = time.time()
        transfer_ok, transfer_err = await _transfer_image(conn, image_path, image_name, dest_path, options)
        elapsed = time.time() - start_time

        if transfer_ok:
            await _emit(campaign_id, dev_id, "success", f"Transfer completed in {elapsed/60:.1f} minutes", host=ip)

            # Post-transfer MD5 verification
            if local_md5 and not options.get("skip_md5"):
                await _emit(campaign_id, dev_id, "info", "Verifying MD5 on switch...", host=ip)
                md5_ok = await _verify_md5_on_switch(conn, image_name, dest_path, local_md5)
                if md5_ok:
                    await _emit(campaign_id, dev_id, "success", "MD5 verified - image integrity confirmed", host=ip)
                else:
                    await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                                   error_message="MD5 mismatch after transfer")
                    await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message="MD5 mismatch after transfer")
                    await _emit(campaign_id, dev_id, "error", "MD5 mismatch after transfer!", host=ip)
                    return

            # Write memory after transfer
            try:
                await asyncio.to_thread(conn.send_command, "write memory", read_timeout=60)
            except Exception:
                pass

            # Pre-stage: unpack and add image so activate only needs activate+commit
            full_path = f"{dest_path}{image_name}"
            install_add_cmd = f"install add file {full_path}"
            await _emit(campaign_id, dev_id, "info", f"Pre-staging image: {install_add_cmd}", host=ip)
            await _emit(campaign_id, dev_id, "info", "This may take several minutes...", host=ip)
            try:
                install_output = await asyncio.to_thread(
                    conn.send_command, install_add_cmd, read_timeout=900,
                )
                await _emit(campaign_id, dev_id, "success", "Image pre-staged successfully", host=ip)
                if install_output:
                    await _emit(campaign_id, dev_id, "info", install_output[-500:], host=ip)
            except Exception as e:
                await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                               error_message=f"install add failed: {e}")
                await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=f"install add failed: {e}")
                await _emit(campaign_id, dev_id, "error", f"Pre-stage (install add) failed: {e}", host=ip)
                return

            await db.update_upgrade_device(dev_id, transfer_status="completed", phase="transfer_done")
            await _emit_device_status(campaign_id, dev_id, transfer_status="completed")
            await _emit(campaign_id, dev_id, "success", "Transfer phase complete", host=ip)
        else:
            # SCP reported failure, but file may have transferred before connection dropped.
            # Reconnect and check flash before marking as failed.
            await _emit(campaign_id, dev_id, "warn",
                        f"SCP error after {elapsed/60:.1f} minutes: {transfer_err or 'unknown'} — verifying flash...", host=ip)
            try:
                verify_conn = await _connect_device(ip, credentials, options, retries=1)
                exists = await asyncio.to_thread(_check_image_exists, verify_conn, image_name, dest_path)
                if exists:
                    await _emit(campaign_id, dev_id, "success",
                                "Image found on flash despite SCP error — transfer actually succeeded", host=ip)
                    # Run MD5 verification if enabled
                    md5_passed = True
                    if local_md5 and not options.get("skip_md5"):
                        await _emit(campaign_id, dev_id, "info", "Verifying MD5 on switch...", host=ip)
                        md5_ok = await _verify_md5_on_switch(verify_conn, image_name, dest_path, local_md5)
                        if md5_ok:
                            await _emit(campaign_id, dev_id, "success", "MD5 verified - image integrity confirmed", host=ip)
                        else:
                            md5_passed = False
                            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                                           error_message="MD5 mismatch after transfer")
                            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message="MD5 mismatch after transfer")
                            await _emit(campaign_id, dev_id, "error", "MD5 mismatch after transfer!", host=ip)
                    if md5_passed:
                        try:
                            await asyncio.to_thread(verify_conn.send_command, "write memory", read_timeout=60)
                        except Exception:
                            pass
                        # Pre-stage: unpack and add image so activate only needs activate+commit
                        full_path = f"{dest_path}{image_name}"
                        install_add_cmd = f"install add file {full_path}"
                        await _emit(campaign_id, dev_id, "info", f"Pre-staging image: {install_add_cmd}", host=ip)
                        await _emit(campaign_id, dev_id, "info", "This may take several minutes...", host=ip)
                        try:
                            install_output = await asyncio.to_thread(
                                verify_conn.send_command, install_add_cmd, read_timeout=900,
                            )
                            await _emit(campaign_id, dev_id, "success", "Image pre-staged successfully", host=ip)
                            if install_output:
                                await _emit(campaign_id, dev_id, "info", install_output[-500:], host=ip)
                        except Exception as e:
                            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                                           error_message=f"install add failed: {e}")
                            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=f"install add failed: {e}")
                            await _emit(campaign_id, dev_id, "error", f"Pre-stage (install add) failed: {e}", host=ip)
                            try:
                                await asyncio.to_thread(verify_conn.disconnect)
                            except Exception:
                                pass
                            return
                        await db.update_upgrade_device(dev_id, transfer_status="completed", phase="transfer_done")
                        await _emit_device_status(campaign_id, dev_id, transfer_status="completed")
                        await _emit(campaign_id, dev_id, "success", "Transfer phase complete", host=ip)
                    try:
                        await asyncio.to_thread(verify_conn.disconnect)
                    except Exception:
                        pass
                    return
                try:
                    await asyncio.to_thread(verify_conn.disconnect)
                except Exception:
                    pass
            except Exception:
                await _emit(campaign_id, dev_id, "warn", "Could not reconnect to verify flash", host=ip)

            err_detail = f"SCP transfer failed: {transfer_err}" if transfer_err else "SCP transfer failed"
            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                           error_message=err_detail)
            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=err_detail)
            await _emit(campaign_id, dev_id, "error", f"Transfer failed after {elapsed/60:.1f} minutes — {transfer_err or 'unknown error'}", host=ip)

    except Exception as e:
        await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                       error_message=str(e))
        await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=str(e))
        await _emit(campaign_id, dev_id, "error", f"Transfer failed: {e}", host=ip)
    finally:
        try:
            await asyncio.to_thread(conn.disconnect)
        except Exception:
            pass


# ── ACTIVATE ─────────────────────────────────────────────────────────────────


async def _device_activate(campaign_id, dev, credentials, image_map, options):
    """Activate: install activate commit (image already pre-staged during transfer), wait for reboot, verify."""
    ip = dev["ip_address"]
    dev_id = dev["id"]
    dest_path = options.get("dest_path", "flash:")

    await db.update_upgrade_device(dev_id, activate_status="running", phase="activate",
                                   started_at=datetime.now(UTC).isoformat())
    await _emit_device_status(campaign_id, dev_id, activate_status="running")
    await _emit(campaign_id, dev_id, "info", f"Connecting to {ip}...", host=ip)

    try:
        conn = await _connect_device(ip, credentials, options, retries=options.get("retries", 2))
    except Exception as e:
        await db.update_upgrade_device(dev_id, activate_status="failed", phase="failed",
                                       error_message=f"Connection failed: {e}")
        await _emit_device_status(campaign_id, dev_id, activate_status="failed", error_message=f"Connection failed: {e}")
        await _emit(campaign_id, dev_id, "error", f"Connection failed: {e}", host=ip)
        return

    try:
        await _emit(campaign_id, dev_id, "success", "Connected", host=ip)

        # Resolve image name
        target_image = dev.get("target_image", "")
        if not target_image:
            model, _ = await _detect_model(conn, ip)
            if model:
                target_image = _resolve_image(model, image_map)
                if target_image:
                    await db.update_upgrade_device(dev_id, target_image=target_image)
            if not target_image:
                await db.update_upgrade_device(dev_id, activate_status="failed", phase="failed",
                                               error_message="No target image resolved")
                await _emit_device_status(campaign_id, dev_id, activate_status="failed", error_message="No target image resolved")
                await _emit(campaign_id, dev_id, "error", "Cannot determine target image", host=ip)
                return

        image_name = os.path.basename(target_image)

        # Check if device is already running the target version — skip activate
        expected_version = _extract_version(image_name)
        if expected_version:
            det_model, running_version = await _detect_model(conn, ip)
            if det_model:
                await db.update_upgrade_device(dev_id, model=det_model, current_version=running_version or "")
            if running_version and expected_version in running_version:
                await _emit(campaign_id, dev_id, "success",
                            f"Already running target version {running_version} — skipping activate", host=ip)
                await db.update_upgrade_device(dev_id,
                                               prestage_status="completed",
                                               transfer_status="completed",
                                               activate_status="completed",
                                               verify_status="completed",
                                               phase="verified",
                                               current_version=running_version,
                                               error_message="",
                                               completed_at=datetime.now(UTC).isoformat())
                await _emit_device_status(campaign_id, dev_id,
                                          prestage_status="completed",
                                          transfer_status="completed",
                                          activate_status="completed",
                                          verify_status="completed",
                                          error_message="")
                return

        # Validate inputs before using in device CLI commands
        cli_err = _validate_cli_inputs(image_name, dest_path)
        if cli_err:
            await db.update_upgrade_device(dev_id, activate_status="failed", phase="failed",
                                           error_message=cli_err)
            await _emit_device_status(campaign_id, dev_id, activate_status="failed", error_message=cli_err)
            await _emit(campaign_id, dev_id, "error", cli_err, host=ip)
            return

        # Verify image exists on flash
        exists = await asyncio.to_thread(_check_image_exists, conn, image_name, dest_path)
        if not exists:
            await db.update_upgrade_device(dev_id, activate_status="failed", phase="failed",
                                           error_message=f"Image {image_name} not found on flash")
            await _emit_device_status(campaign_id, dev_id, activate_status="failed", error_message=f"Image {image_name} not found on flash")
            await _emit(campaign_id, dev_id, "error", f"Image {image_name} not on flash. Run transfer first.", host=ip)
            return

        await _emit(campaign_id, dev_id, "info", f"Image verified on flash: {dest_path}{image_name}", host=ip)

        # Image already pre-staged during transfer (install add), just activate
        command = "install activate prompt-level none"
        await _emit(campaign_id, dev_id, "cmd", f"Executing: {command}", host=ip)
        await _emit(campaign_id, dev_id, "info", "This will trigger a reload (5-15 minutes)...", host=ip)

        try:
            await asyncio.to_thread(
                conn.send_command, command, read_timeout=120,
            )
        except Exception as e:
            # Expected — switch reboots and drops the SSH session
            await _emit(campaign_id, dev_id, "info", f"Connection closed (expected during reload): {e}", host=ip)

        await _emit(campaign_id, dev_id, "success", "Activate sent - switch is rebooting", host=ip)

        # Wait for switch to come back
        if options.get("verify_upgrade", True):
            verify_wait = options.get("verify_wait", 1200)
            check_interval = options.get("check_interval", 30)

            await _emit(campaign_id, dev_id, "info",
                        f"Waiting for switch to reboot (up to {verify_wait // 60} minutes)...", host=ip)

            # First: wait for switch to go DOWN (confirm reboot started)
            await _emit(campaign_id, dev_id, "info", "Waiting for switch to go offline...", host=ip)
            went_down = await _wait_for_down(ip, timeout=300, check_interval=10, campaign_id=campaign_id, dev_id=dev_id)
            if went_down:
                await _emit(campaign_id, dev_id, "info", "Switch is offline — reboot in progress", host=ip)
            else:
                await _emit(campaign_id, dev_id, "warn",
                            "Switch never went offline — it may not have reloaded. Checking version anyway...", host=ip)

            # Then: wait for switch to come BACK online
            new_conn = await _wait_for_reboot(ip, credentials, options, verify_wait, check_interval, campaign_id, dev_id)

            if new_conn:
                await _emit(campaign_id, dev_id, "success", "Switch is back online!", host=ip)

                # Verify version
                expected_version = _extract_version(image_name)
                if expected_version:
                    _, running_version = await _detect_model(new_conn, ip)
                    if running_version and expected_version in running_version:
                        await _emit(campaign_id, dev_id, "success",
                                    f"Version verified: {running_version} (expected {expected_version})", host=ip)

                        # Commit the install to make the new version permanent
                        await _emit(campaign_id, dev_id, "info", "Running install commit to lock in new version...", host=ip)
                        try:
                            commit_output = await asyncio.to_thread(
                                new_conn.send_command, "install commit", read_timeout=300,
                            )
                            await _emit(campaign_id, dev_id, "success", "Install committed — new version is permanent", host=ip)
                            if commit_output:
                                await _emit(campaign_id, dev_id, "info", commit_output[-500:], host=ip)
                        except Exception as e:
                            await _emit(campaign_id, dev_id, "warn", f"install commit failed: {e} — switch may rollback on next reload!", host=ip)

                        await db.update_upgrade_device(dev_id, verify_status="completed",
                                                       current_version=running_version)
                        await _emit_device_status(campaign_id, dev_id, verify_status="completed")
                    else:
                        await _emit(campaign_id, dev_id, "error",
                                    f"Version mismatch! Running: {running_version}, Expected: {expected_version}", host=ip)
                        await db.update_upgrade_device(dev_id, verify_status="failed",
                                                       error_message=f"Version mismatch: {running_version}")
                        await _emit_device_status(campaign_id, dev_id, verify_status="failed", error_message=f"Version mismatch: {running_version}")

                try:
                    await asyncio.to_thread(new_conn.disconnect)
                except Exception:
                    pass
            else:
                await _emit(campaign_id, dev_id, "error",
                            f"Switch did not come back within {verify_wait // 60} minutes", host=ip)
                await db.update_upgrade_device(dev_id, verify_status="failed",
                                               error_message="Switch unreachable after reboot")
                await _emit_device_status(campaign_id, dev_id, verify_status="failed", error_message="Switch unreachable after reboot")

        await db.update_upgrade_device(dev_id, activate_status="completed", phase="completed",
                                       completed_at=datetime.now(UTC).isoformat())
        await _emit_device_status(campaign_id, dev_id, activate_status="completed")
        await _emit(campaign_id, dev_id, "success", "Activate phase complete", host=ip)

    except Exception as e:
        await db.update_upgrade_device(dev_id, activate_status="failed", phase="failed",
                                       error_message=str(e))
        await _emit_device_status(campaign_id, dev_id, activate_status="failed", error_message=str(e))
        await _emit(campaign_id, dev_id, "error", f"Activate failed: {e}", host=ip)
    finally:
        try:
            await asyncio.to_thread(conn.disconnect)
        except Exception:
            pass


# ── VERIFY ──────────────────────────────────────────────────────────────────


async def _device_verify(campaign_id, dev, credentials, image_map, options):
    """Verify: connect to switch and check running version against target image."""
    ip = dev["ip_address"]
    dev_id = dev["id"]

    await db.update_upgrade_device(dev_id, verify_status="running", phase="verify")
    await _emit_device_status(campaign_id, dev_id, verify_status="running")
    await _emit(campaign_id, dev_id, "info", f"Connecting to {ip}...", host=ip)

    try:
        conn = await _connect_device(ip, credentials, options, retries=options.get("retries", 2))
    except Exception as e:
        await db.update_upgrade_device(dev_id, verify_status="failed", phase="failed",
                                       error_message=f"Connection failed: {e}")
        await _emit_device_status(campaign_id, dev_id, verify_status="failed", error_message=f"Connection failed: {e}")
        await _emit(campaign_id, dev_id, "error", f"Connection failed: {e}", host=ip)
        return

    try:
        await _emit(campaign_id, dev_id, "success", "Connected", host=ip)

        # Detect current running version
        model, running_version = await _detect_model(conn, ip)
        if model:
            await db.update_upgrade_device(dev_id, model=model, current_version=running_version or "")

        if not running_version:
            await db.update_upgrade_device(dev_id, verify_status="failed", phase="failed",
                                           error_message="Could not detect running version")
            await _emit_device_status(campaign_id, dev_id, verify_status="failed", error_message="Could not detect running version")
            await _emit(campaign_id, dev_id, "error", "Could not detect running version", host=ip)
            return

        await _emit(campaign_id, dev_id, "info", f"Running version: {running_version}", host=ip)

        # Resolve expected version from target image
        target_image = dev.get("target_image", "")
        if not target_image and model:
            image_map_items = image_map if isinstance(image_map, list) else sorted(image_map.items(), key=lambda x: len(x[0]), reverse=True)
            target_image = _resolve_image(model, image_map_items)
            if target_image:
                await db.update_upgrade_device(dev_id, target_image=target_image)

        if not target_image:
            await db.update_upgrade_device(dev_id, verify_status="failed", phase="failed",
                                           error_message="No target image to verify against")
            await _emit_device_status(campaign_id, dev_id, verify_status="failed", error_message="No target image to verify against")
            await _emit(campaign_id, dev_id, "error", "No target image to verify against", host=ip)
            return

        image_name = os.path.basename(target_image)
        expected_version = _extract_version(image_name)

        if not expected_version:
            await db.update_upgrade_device(dev_id, verify_status="failed", phase="failed",
                                           error_message=f"Cannot extract version from {image_name}")
            await _emit_device_status(campaign_id, dev_id, verify_status="failed", error_message=f"Cannot extract version from {image_name}")
            await _emit(campaign_id, dev_id, "error", f"Cannot extract version from image name: {image_name}", host=ip)
            return

        await _emit(campaign_id, dev_id, "info", f"Expected version: {expected_version}", host=ip)

        # Compare versions
        if expected_version in running_version:
            # Device is fully upgraded — mark all steps completed
            await db.update_upgrade_device(dev_id, verify_status="completed", phase="verified",
                                           prestage_status="completed",
                                           transfer_status="completed",
                                           activate_status="completed",
                                           current_version=running_version,
                                           error_message="",
                                           completed_at=datetime.now(UTC).isoformat())
            await _emit_device_status(campaign_id, dev_id,
                                      prestage_status="completed",
                                      transfer_status="completed",
                                      activate_status="completed",
                                      verify_status="completed",
                                      error_message="")
            await _emit(campaign_id, dev_id, "success",
                        f"Upgrade verified — running {running_version} (matches {expected_version})", host=ip)
        else:
            await db.update_upgrade_device(dev_id, verify_status="failed",
                                           error_message=f"Version mismatch: running {running_version}, expected {expected_version}",
                                           current_version=running_version)
            await _emit_device_status(campaign_id, dev_id, verify_status="failed",
                                      error_message=f"Version mismatch: running {running_version}, expected {expected_version}")
            await _emit(campaign_id, dev_id, "error",
                        f"Version mismatch — running {running_version}, expected {expected_version}", host=ip)

    except Exception as e:
        await db.update_upgrade_device(dev_id, verify_status="failed", phase="failed",
                                       error_message=str(e))
        await _emit_device_status(campaign_id, dev_id, verify_status="failed", error_message=str(e))
        await _emit(campaign_id, dev_id, "error", f"Verify failed: {e}", host=ip)
    finally:
        try:
            await asyncio.to_thread(conn.disconnect)
        except Exception:
            pass


# ═════════════════════════════════════════════════════════════════════════════
# Low-level helpers (sync, run via asyncio.to_thread)
# ═════════════════════════════════════════════════════════════════════════════


async def _health_check(conn, hostname):
    """Run CPU, memory, and stack health checks. Returns (passed, warnings)."""
    warnings = []
    critical = False

    # CPU
    try:
        cpu_output = await asyncio.to_thread(conn.send_command,
                                             "show processes cpu | include CPU", read_timeout=30)
        cpu_match = re.search(r'five minutes:\s*(\d+)%', cpu_output)
        if cpu_match:
            cpu_5min = int(cpu_match.group(1))
            if cpu_5min > 80:
                warnings.append(f"CPU {cpu_5min}% (critical)")
                critical = True
            elif cpu_5min > 60:
                warnings.append(f"CPU {cpu_5min}% (elevated)")
    except Exception as e:
        warnings.append(f"CPU check failed: {e}")

    # Memory
    try:
        mem_output = await asyncio.to_thread(conn.send_command,
                                             "show platform resources", read_timeout=30)
        mem_match = re.search(r'Used:\s*\d+\s*kB\s*\((\d+)%\)', mem_output)
        if mem_match:
            mem_pct = int(mem_match.group(1))
            if mem_pct > 90:
                warnings.append(f"Memory {mem_pct}% (critical)")
                critical = True
            elif mem_pct > 80:
                warnings.append(f"Memory {mem_pct}% (elevated)")
    except Exception as e:
        warnings.append(f"Memory check failed: {e}")

    # Stack health
    try:
        stack_output = await asyncio.to_thread(conn.send_command, "show switch", read_timeout=30)
        if re.search(r'^\s*\d+\s+', stack_output, re.MULTILINE):
            for line in stack_output.splitlines():
                match = re.match(
                    r'\s*(\d+)\s+\S+\s+.*?(Ready|Removed|Progressing|Provisioned|Invalid|Added|Syncing|Version Mismatch)',
                    line,
                )
                if match and match.group(2) != "Ready":
                    warnings.append(f"Stack member {match.group(1)}: {match.group(2)}")
                    critical = True
    except Exception:
        pass  # Not a stack

    return not critical, warnings


def _compute_md5(filepath):
    """Compute MD5 of a local file in chunks."""
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
    return md5.hexdigest()


async def _check_flash_space(conn, image_path, dest_path):
    """Check if flash has enough space for the image."""
    image_size = os.path.getsize(image_path)
    output = await asyncio.to_thread(
        conn.send_command, f"dir {dest_path} | include bytes",
    )
    match = re.search(r'(\d+)\s+bytes\s+free', output)
    if match:
        free = int(match.group(1))
        return free > image_size * 1.1, free
    return True, None  # Can't determine — proceed with warning


def _check_image_exists(conn, image_name, dest_path):
    """Check if image file already exists on flash."""
    output = conn.send_command(f"dir {dest_path}{image_name}")
    lower = output.lower()
    if "no such file" in lower or "not found" in lower or "%error" in lower or "invalid" in lower:
        return False
    return image_name in output


async def _verify_md5_on_switch(conn, image_name, dest_path, expected_md5):
    """Verify MD5 hash on the switch matches local."""
    try:
        output = await asyncio.to_thread(
            conn.send_command, f"verify /md5 {dest_path}{image_name}", read_timeout=900,
        )
        md5_match = re.search(r'=\s*([a-fA-F0-9]{32})', output)
        if not md5_match:
            md5_match = re.search(r'\b([a-fA-F0-9]{32})\b', output)
        if md5_match:
            return md5_match.group(1).lower() == expected_md5.lower()
        return False
    except Exception:
        return False


async def _transfer_image(conn, image_path, image_name, dest_path, options):
    """Transfer image via SCP with retry support.

    Returns (True, None) on success, or (False, error_message) on failure.
    """
    retries = options.get("retries", 0)
    max_attempts = 1 + retries
    last_error = None

    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            backoff = min(30 * (2 ** (attempt - 2)), 300)
            await asyncio.sleep(backoff)

        try:
            await asyncio.to_thread(
                file_transfer,
                conn,
                source_file=str(image_path),
                dest_file=image_name,
                file_system=dest_path.rstrip(":") + ":",
                direction="put",
                overwrite_file=True,
            )
        except Exception as e:
            last_error = str(e)

        # Always verify file exists on flash — SCP can throw exceptions
        # (timeout, socket close) even when the file transferred successfully
        try:
            exists = await asyncio.to_thread(_check_image_exists, conn, image_name, dest_path)
            if exists:
                return True, None
        except Exception:
            pass  # Connection may be dead; will retry or fail

        if last_error and attempt >= max_attempts:
            return False, last_error

    return False, last_error or "File not found on flash after transfer"


async def _wait_for_down(ip, timeout=300, check_interval=10, campaign_id=None, dev_id=None):
    """Wait for switch to become unreachable, confirming reboot has started."""
    start = time.time()
    while (time.time() - start) < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = await asyncio.to_thread(sock.connect_ex, (ip, 22))
            sock.close()
            if result != 0:
                return True  # Port closed — switch is down
        except Exception:
            return True  # Connection error — switch is down

        elapsed = int(time.time() - start)
        if campaign_id is not None and elapsed % 30 < check_interval:
            await _emit(campaign_id, dev_id, "dim",
                        f"Switch still up... ({elapsed}s elapsed)", host=ip)
        await asyncio.sleep(check_interval)

    return False  # Never went down within timeout


async def _wait_for_reboot(ip, credentials, options, max_wait, check_interval, campaign_id, dev_id):
    """Wait for switch to come back online after reboot."""
    start = time.time()

    while (time.time() - start) < max_wait:
        elapsed = int(time.time() - start)
        if elapsed % 60 < check_interval:
            await _emit(campaign_id, dev_id, "dim",
                        f"Waiting for reboot... ({elapsed}s elapsed)", host=ip)

        try:
            conn = await _connect_device(ip, credentials, options, retries=1)
            return conn
        except Exception:
            await asyncio.sleep(check_interval)

    return None


def _extract_version(image_name):
    """Extract version from image filename. e.g. cat9k_iosxe.17.15.05.SPA.bin -> 17.15.05"""
    match = re.search(r'(\d+\.\d+\.\d+)', image_name)
    return match.group(1) if match else None
