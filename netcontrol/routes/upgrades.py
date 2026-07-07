"""
upgrades.py -- IOS-XE Staged Upgrade Tool

Campaign-based upgrade manager with per-device phase tracking,
image management, and real-time WebSocket streaming.

Ported from standalone iosxe_upgrade.py into the Plexus platform.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import routes.database as db
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from routes.crypto import decrypt

import netcontrol.routes.state as state
from netcontrol.drivers import DriverCapabilityError, get_driver
from netcontrol.routes.shared import (
    _audit,
    _corr_id,
    _get_session,
    require_credential_access,
    require_owner_or_admin,
    verify_ws_session,
)
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


async def _resolve_campaign_credential(
    cred_id, created_by, session: dict | None = None,
) -> dict:
    """Resolve the credential a campaign should run with.

    If the campaign has an explicit ``credential_id`` it's validated against
    the campaign's creator (with a live-session fallback for legacy campaigns,
    and ``allow_service`` since scheduled upgrades are unattended work). When
    no credential was set, fall back to the configured service/default
    credential — the system account used for unattended work, same as
    monitoring and MAC collection — with no per-user check, because it isn't a
    user-selected credential.

    Raises HTTPException(400/403/404) on any failure.
    """
    if cred_id:
        created_by = (created_by or "").strip()
        if created_by and created_by.lower() != "unknown":
            return await require_credential_access(
                cred_id, submitter_username=created_by, allow_service=True,
            )
        return await require_credential_access(
            cred_id, session=session, allow_service=True,
        )

    fallback_id = (
        state.AUTH_CONFIG.get("service_credential_id")
        or state.AUTH_CONFIG.get("default_credential_id")
    )
    if not fallback_id:
        raise HTTPException(
            400,
            "No credential set on the campaign and no service/default "
            "credential configured. Select a credential, or set a service "
            "credential in Settings to use as the default.",
        )
    cred = await db.get_credential_raw(fallback_id)
    if not cred:
        raise HTTPException(
            400, f"Configured default credential {fallback_id} no longer exists"
        )
    return cred

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _resolve_state_root() -> str | None:
    explicit = os.getenv("PLEXUS_STATE_DIR", "").strip()
    if explicit:
        return explicit
    key_file = os.getenv("APP_SESSION_KEY_FILE", "").strip()
    if key_file:
        return os.path.dirname(key_file)
    return None


def _resolve_software_images_dir() -> str:
    override = os.getenv("PLEXUS_SOFTWARE_IMAGES_DIR", "").strip()
    if override:
        return override
    state_root = _resolve_state_root()
    if state_root:
        return os.path.join(state_root, "software_images")
    return os.path.join(_REPO_ROOT, "software_images")


SOFTWARE_IMAGES_DIR = _resolve_software_images_dir()

BACKUPS_DIR = os.path.join(
    _REPO_ROOT,
    "backups", "upgrades",
)

# Stored filenames must stay safe for IOS-XE CLI interpolation (_SAFE_IMAGE_NAME_RE).
_UPLOAD_FILENAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$')


def _software_images_root() -> str:
    return os.path.realpath(SOFTWARE_IMAGES_DIR)


def _image_file_path(filename: str) -> str:
    """Resolve a stored image filename to an absolute path under SOFTWARE_IMAGES_DIR."""
    safe_name = os.path.basename(filename)
    root = _software_images_root()
    fpath = os.path.realpath(os.path.join(SOFTWARE_IMAGES_DIR, safe_name))
    prefix = root if root.endswith(os.sep) else root + os.sep
    if fpath != root and not fpath.startswith(prefix):
        raise HTTPException(400, "Invalid image filename")
    return fpath


def _candidate_image_dirs() -> list[str]:
    """Directories that may hold stored images, primary (SOFTWARE_IMAGES_DIR) first.

    The image directory resolution gained an env-driven state-root location
    (PLEXUS_STATE_DIR / APP_SESSION_KEY_FILE), so deployments that set a state
    dir now read from <state>/software_images while images uploaded under the
    older scheme still live in <repo_root>/software_images. Reads search every
    candidate so a file in the legacy location is still found.
    """
    dirs = [SOFTWARE_IMAGES_DIR, os.path.join(_REPO_ROOT, "software_images")]
    seen: set[str] = set()
    ordered: list[str] = []
    for d in dirs:
        key = os.path.realpath(d)
        if key not in seen:
            seen.add(key)
            ordered.append(d)
    return ordered


def _safe_image_path_in(directory: str, filename: str) -> str | None:
    """Resolve filename under directory, or None if it would escape that root."""
    safe_name = os.path.basename(filename)
    root = os.path.realpath(directory)
    fpath = os.path.realpath(os.path.join(directory, safe_name))
    prefix = root if root.endswith(os.sep) else root + os.sep
    if fpath != root and not fpath.startswith(prefix):
        return None
    return fpath


def _find_existing_image_path(filename: str) -> str | None:
    """Return the first candidate directory that actually holds filename, else None."""
    for directory in _candidate_image_dirs():
        fpath = _safe_image_path_in(directory, filename)
        if fpath and os.path.isfile(fpath):
            return fpath
    return None


def _ensure_software_images_dir() -> None:
    os.makedirs(SOFTWARE_IMAGES_DIR, exist_ok=True)


def _storage_unavailable_detail(action: str = "store") -> str:
    return (
        f"Unable to {action} image files at {SOFTWARE_IMAGES_DIR}. "
        "Check disk space and directory permissions. "
        "On Docker deployments, run: sudo chown -R 1000:1000 ./software_images "
        "then restart the plexus container."
    )


def _verify_software_images_writable() -> None:
    """Raise OSError when the image directory cannot be written."""
    _ensure_software_images_dir()
    probe = os.path.join(SOFTWARE_IMAGES_DIR, ".write_probe")
    with open(probe, "wb") as f:
        f.write(b"")
    os.remove(probe)

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
# Route-level auth comes from app.py's include_router dependencies; only the
# WebSocket session check needs a late-bound callable here.

_verify_session_token = None
_get_user_features = None


def init_upgrades(verify_session_token=None, get_user_features_fn=None):
    global _verify_session_token, _get_user_features
    _verify_session_token = verify_session_token
    _get_user_features = get_user_features_fn
    try:
        _ensure_software_images_dir()
    except OSError:
        LOGGER.warning(
            "Software images directory is not available: %s",
            SOFTWARE_IMAGES_DIR,
            exc_info=True,
        )


async def rehydrate_scheduled_upgrades():
    """Re-create asyncio tasks for scheduled campaigns after a server restart.

    Queries for any campaign with status='scheduled_activate' and a persisted
    scheduled_at time.  If scheduled_at is still in the future the task sleeps
    until that time; if it has already passed the campaign is marked missed so
    the operator can reschedule instead of triggering an out-of-window reload.
    """
    try:
        campaigns = await db.get_all_upgrade_campaigns()
    except Exception:
        LOGGER.exception("rehydrate_scheduled_upgrades: failed to query campaigns")
        return

    for campaign in campaigns:
        if campaign.get("status") != "scheduled_activate":
            continue
        scheduled_at_raw = campaign.get("scheduled_at")
        if not scheduled_at_raw:
            # No persisted time - mark failed so operator knows to reschedule
            LOGGER.warning(
                "Campaign %s is scheduled_activate but has no scheduled_at; marking failed",
                campaign["id"],
            )
            try:
                await db.update_upgrade_campaign(campaign["id"], status="activate_failed")
                op = await db.get_latest_upgrade_operation(
                    campaign["id"], phase="activate", statuses=("scheduled", "running")
                )
                if op:
                    await db.update_upgrade_operation(
                        op["id"],
                        status="activate_failed",
                        completed_at=_utc_now_iso(),
                        error_message="Scheduled activate had no persisted run time; reschedule required.",
                    )
            except Exception as exc:
                LOGGER.warning("Failed to record activate_failed for campaign %s: %s", campaign["id"], exc)
            continue

        try:
            scheduled_at_utc = datetime.fromisoformat(scheduled_at_raw)
            if scheduled_at_utc.tzinfo is None:
                scheduled_at_utc = scheduled_at_utc.replace(tzinfo=UTC)
            else:
                scheduled_at_utc = scheduled_at_utc.astimezone(UTC)
        except ValueError:
            LOGGER.warning(
                "Campaign %s has unparseable scheduled_at %r; marking failed",
                campaign["id"],
                scheduled_at_raw,
            )
            try:
                await db.update_upgrade_campaign(campaign["id"], status="activate_failed")
            except Exception as exc:
                LOGGER.warning("Failed to record activate_failed for campaign %s: %s", campaign["id"], exc)
            continue

        campaign_id = campaign["id"]
        if campaign_id in _running_campaigns:
            continue  # already running (shouldn't happen on startup)

        # Resolve credentials
        try:
            options = (
                json.loads(campaign["options"])
                if isinstance(campaign["options"], str)
                else campaign["options"]
            )
            # Rehydrating a scheduled activate after restart: resolve against
            # the campaign creator (no live session here), falling back to the
            # configured service credential when the campaign has none set.
            cred = await _resolve_campaign_credential(
                options.get("credential_id"), campaign.get("created_by"),
            )
            credentials = {
                "username": cred["username"],
                "password": decrypt(cred["password"]),
                "secret": decrypt(cred["secret"]) if cred.get("secret") else "",
            }
            devices = await db.get_upgrade_devices(campaign_id)
            image_map_raw = (
                json.loads(campaign["image_map"])
                if isinstance(campaign["image_map"], str)
                else campaign["image_map"]
            )
            image_map = sorted(image_map_raw.items(), key=lambda x: len(x[0]), reverse=True)
        except Exception:
            LOGGER.exception("Campaign %s rehydration failed resolving credentials/devices", campaign_id)
            try:
                await db.update_upgrade_campaign(campaign_id, status="activate_failed")
                op = await db.get_latest_upgrade_operation(
                    campaign_id, phase="activate", statuses=("scheduled", "running")
                )
                if op:
                    await db.update_upgrade_operation(
                        op["id"],
                        status="activate_failed",
                        completed_at=_utc_now_iso(),
                        error_message=(
                            "Scheduled activate could not be rehydrated; "
                            "check credentials/devices and reschedule."
                        ),
                    )
            except Exception as exc:
                LOGGER.warning("Failed to record rehydration failure for campaign %s: %s", campaign_id, exc)
            continue

        # If the scheduled window has already passed, do not run automatically -
        # require the operator to reschedule to avoid an unintended out-of-window reload.
        if scheduled_at_utc <= datetime.now(UTC):
            LOGGER.warning(
                "Campaign %s scheduled_at %s has already passed; marking missed so operator can reschedule",
                campaign_id,
                scheduled_at_utc.isoformat(),
            )
            try:
                await db.update_upgrade_campaign(
                    campaign_id,
                    status="activate_missed",
                    scheduled_at=None,
                )
                op = await db.get_latest_upgrade_operation(
                    campaign_id, phase="activate", statuses=("scheduled", "running")
                )
                if op:
                    await db.update_upgrade_operation(
                        op["id"],
                        status="activate_missed",
                        scheduled_at=scheduled_at_utc.isoformat(),
                        completed_at=_utc_now_iso(),
                        error_message=(
                            "Scheduled activate window was missed due to a server restart; "
                            "reschedule required."
                        ),
                    )
                await _emit(
                    campaign_id,
                    None,
                    "warn",
                    f"Scheduled activate window ({scheduled_at_utc.isoformat()}) was missed due to a server restart. "
                    "Please reschedule the activate phase.",
                )
            except Exception as exc:
                LOGGER.warning("Failed to record missed activate window for campaign %s: %s", campaign_id, exc)
            continue

        LOGGER.info(
            "Rehydrating scheduled activate for campaign %s (scheduled_at=%s)",
            campaign_id,
            scheduled_at_utc.isoformat(),
        )
        op = await db.get_latest_upgrade_operation(
            campaign_id, phase="activate", statuses=("scheduled", "running")
        )
        if op:
            operation_id = op["id"]
        else:
            operation_id = await db.create_upgrade_operation(
                campaign_id,
                "activate",
                "scheduled",
                device_count=len(devices),
                scheduled_at=scheduled_at_utc.isoformat(),
            )

        async def _run_rehydrated(
            _cid=campaign_id,
            _sat=scheduled_at_utc,
            _devs=devices,
            _creds=credentials,
            _imap=image_map,
            _opts=options,
            _opid=operation_id,
        ):
            try:
                delay_seconds = (_sat - datetime.now(UTC)).total_seconds()
                if delay_seconds > 0:
                    await _emit(_cid, None, "info", f"Resuming scheduled activate (rehydrated after restart); fires at {_sat.isoformat()}")
                    await asyncio.sleep(delay_seconds)
                await db.update_upgrade_campaign(_cid, status="running_activate", scheduled_at=None)
                await db.update_upgrade_operation(
                    _opid,
                    status="running",
                    started_at=_utc_now_iso(),
                )
                await _emit(_cid, None, "info", "Starting activate phase now")
                await _run_phase(_cid, "activate", _devs, _creds, _imap, _opts, operation_id=_opid)
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("Scheduled activate failed for campaign %s", _cid)
                await _mark_upgrade_operation_failed(
                    _cid,
                    _opid,
                    "activate",
                    "Scheduled activate failed before completion; check backend logs.",
                )

        task = asyncio.create_task(_run_rehydrated())
        _running_campaigns[campaign_id] = task
        _running_campaign_operations[campaign_id] = operation_id

        def _on_done(t, _cid=campaign_id):
            _running_campaigns.pop(_cid, None)
            _running_campaign_operations.pop(_cid, None)
            if not t.cancelled():
                exc = t.exception()
                if exc is not None:
                    LOGGER.error("Scheduled activate task crashed for campaign %s", _cid, exc_info=exc)

        task.add_done_callback(_on_done)




class ImageUpdate(BaseModel):
    model_pattern: str = ""
    version: str = ""
    platform: str = "iosxe"
    notes: str = ""


class CampaignCreate(BaseModel):
    name: str = Field(max_length=200)
    description: str = Field(default="", max_length=2000)
    # image_map keys are model/version patterns and values are image filenames;
    # bound the entry count so a create call can't carry an unbounded dict.
    image_map: dict = Field(default_factory=dict, max_length=1000)
    options: dict = Field(default_factory=dict, max_length=200)
    host_ids: list[int] = Field(default_factory=list, max_length=100000)
    ad_hoc_ips: list[Annotated[str, Field(max_length=64)]] = Field(
        default_factory=list, max_length=100000)
    # Optional: when omitted the campaign runs with the configured service
    # credential (the system account used for unattended work).
    credential_id: int | None = None


class CampaignUpdate(BaseModel):
    name: str = Field(max_length=200)
    description: str = Field(default="", max_length=2000)
    image_map: dict = Field(default_factory=dict, max_length=1000)
    options: dict = Field(default_factory=dict, max_length=200)
    host_ids: list[int] = Field(default_factory=list, max_length=100000)
    ad_hoc_ips: list[Annotated[str, Field(max_length=64)]] = Field(
        default_factory=list, max_length=100000)
    credential_id: int | None = None


class CampaignPhaseRequest(BaseModel):
    phase: str  # "prestage", "transfer", "activate", "verify", "verify_prestage"
    device_ids: list[int] = []  # empty = all devices in campaign
    scheduled_at: datetime | None = None  # optional future UTC/offset datetime (activate only)


class CampaignDeviceCancelRequest(BaseModel):
    device_ids: list[int]
    phase: str | None = None


# ── Module-level state ───────────────────────────────────────────────────────

_campaign_sockets: dict[int, list[WebSocket]] = {}
_campaign_sockets_lock = asyncio.Lock()
_running_campaigns: dict[int, asyncio.Task] = {}
_running_campaign_operations: dict[int, int] = {}

_SUPPORTED_PHASES = ("prestage", "transfer", "activate", "verify", "verify_prestage")
_PHASE_STATUS_KEY = {
    "prestage": "prestage_status",
    "transfer": "transfer_status",
    "activate": "activate_status",
    "verify": "verify_status",
    # Re-verify prestage acts as transfer-readiness verification.
    "verify_prestage": "transfer_status",
}
_PHASE_LABEL = {
    "prestage": "Prestage",
    "transfer": "Transfer",
    "activate": "Activate",
    "verify": "Verify",
    "verify_prestage": "Prestage Verify",
}


def _phase_status_key(phase: str) -> str:
    return _PHASE_STATUS_KEY.get(phase, f"{phase}_status")


def _phase_label(phase: str) -> str:
    return _PHASE_LABEL.get(phase, phase.replace("_", " ").title())


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _install_commit_output_failed(output: str | None) -> bool:
    if not output:
        return False
    text = output.lower()
    failure_markers = (
        "not responding or is otherwise unavailable",
        "failed",
        "failure",
        "error",
        "rollback",
        "aborted",
    )
    return any(marker in text for marker in failure_markers)


async def _mark_upgrade_operation_failed(
    campaign_id: int,
    operation_id: int | None,
    phase: str,
    message: str,
) -> None:
    await db.update_upgrade_campaign(
        campaign_id,
        status=f"{phase}_failed",
        scheduled_at=None,
    )
    if operation_id is not None:
        await db.update_upgrade_operation(
            operation_id,
            status=f"{phase}_failed",
            completed_at=_utc_now_iso(),
            error_message=message,
        )
    await _emit(campaign_id, None, "error", message)


# ── Helper: broadcast event to WebSocket subscribers ─────────────────────────


async def _broadcast_upgrade_event(campaign_id: int, event: dict):
    """Send event to all connected WebSocket clients for a campaign."""
    async with _campaign_sockets_lock:
        sockets = list(_campaign_sockets.get(campaign_id, []))
    dead = []
    for ws in sockets:
        try:
            await asyncio.wait_for(ws.send_json(event), timeout=5)
        except Exception:
            LOGGER.debug("upgrade broadcast: dropping dead WS for campaign %s", campaign_id)
            dead.append(ws)
    if dead:
        async with _campaign_sockets_lock:
            for ws in dead:
                try:
                    _campaign_sockets[campaign_id].remove(ws)
                except (ValueError, KeyError) as exc:
                    LOGGER.debug("upgrade broadcast: dead WS already removed for campaign %s: %s", campaign_id, exc)


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


def _derive_stale_phase_status(phase: str, devices: list[dict]) -> str:
    """Derive a terminal campaign status for a stale running phase."""
    key = _phase_status_key(phase)
    total = len(devices)
    if total == 0:
        return f"{phase}_failed"

    completed = sum(1 for d in devices if d.get(key) == "completed")
    failed = sum(1 for d in devices if d.get(key) == "failed")
    cancelled = sum(1 for d in devices if d.get(key) == "cancelled")

    if completed == total:
        return f"{phase}_complete"
    if failed == total:
        return f"{phase}_failed"
    if cancelled == total:
        return "cancelled"
    if completed + failed + cancelled == total and (completed > 0 or failed > 0):
        return f"{phase}_partial"
    return f"{phase}_partial"


async def _repair_stale_running_campaign(campaign: dict) -> dict:
    """Normalize stale running_* DB state when no in-memory task is active."""
    status = campaign.get("status") or ""
    campaign_id = campaign.get("id")
    if not isinstance(campaign_id, int):
        return campaign
    if campaign_id in _running_campaigns:
        return campaign
    if not status.startswith("running_"):
        return campaign

    phase = status.split("running_", 1)[1].strip()
    if phase not in _SUPPORTED_PHASES:
        return campaign

    devices = await db.get_upgrade_devices(campaign_id)
    recovered_status = _derive_stale_phase_status(phase, devices)
    await db.update_upgrade_campaign(campaign_id, status=recovered_status)
    campaign["status"] = recovered_status
    return campaign


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

    try:
        _verify_software_images_writable()
    except OSError:
        LOGGER.exception("Software images directory is not writable: %s", SOFTWARE_IMAGES_DIR)
        raise HTTPException(503, _storage_unavailable_detail("store"))

    filename = os.path.basename(file.filename or "unknown.bin")
    if not _UPLOAD_FILENAME_RE.fullmatch(filename):
        raise HTTPException(
            400,
            "Invalid image filename - use only letters, numbers, dot, hyphen, and underscore",
        )

    existing = await db.get_upgrade_image_by_filename(filename)
    if existing:
        raise HTTPException(
            409,
            f'An image named "{filename}" already exists. Delete it first or rename the file.',
        )

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
                        413,
                        f"Image exceeds maximum upload size of {_MAX_IMAGE_UPLOAD_BYTES // (1024 * 1024)} MB",
                    )
                f.write(chunk)
                md5.update(chunk)
    except HTTPException:
        if os.path.isfile(dest):
            try:
                os.remove(dest)
            except OSError:
                LOGGER.warning("Failed to remove partial upload %s", dest, exc_info=True)
        raise
    except OSError:
        if os.path.isfile(dest):
            try:
                os.remove(dest)
            except OSError as exc:
                LOGGER.debug("Failed to remove partial upload %s: %s", dest, exc)
        LOGGER.exception("Failed to write image file %s", filename)
        raise HTTPException(503, _storage_unavailable_detail("store"))

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

    try:
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
    except Exception as exc:
        if os.path.isfile(dest):
            try:
                os.remove(dest)
            except OSError as rm_err:
                LOGGER.debug("Failed to remove partial upload %s: %s", dest, rm_err)
        if db._is_unique_violation(exc):
            raise HTTPException(
                409,
                f'An image named "{filename}" already exists. Delete it first or rename the file.',
            )
        LOGGER.exception("Failed to record uploaded image %s", filename)
        raise HTTPException(500, "Image upload failed")

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

    # Remove the on-disk file from wherever it actually lives (primary or a
    # legacy directory), not just the primary location, to avoid orphaned files.
    fpath = _find_existing_image_path(img["filename"]) or _image_file_path(img["filename"])
    if os.path.isfile(fpath):
        try:
            os.remove(fpath)
        except OSError:
            LOGGER.exception("Failed to delete image file %s", fpath)
            raise HTTPException(503, _storage_unavailable_detail("delete"))

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

    # Bind-time IDOR gate: if a credential is specified, the creator must own
    # it (or be an admin for a service credential). When omitted, the campaign
    # runs with the configured service credential at execution time.
    if body.credential_id is not None:
        await require_credential_access(body.credential_id, session=session, allow_service=True)

    campaign_id = await db.create_upgrade_campaign(
        name=body.name,
        description=body.description,
        image_map=body.image_map,
        options={**body.options, "credential_id": body.credential_id},
        created_by=user,
    )

    # Add devices from host_ids (inventory). Track what could not be added so
    # the caller isn't silently handed a smaller campaign than they asked for
    # (an unknown host id or a duplicate previously vanished with only a debug
    # log).
    added = 0
    not_found_host_ids: list[int] = []
    skipped_host_ids: list[int] = []
    for hid in body.host_ids:
        host = await db.get_host(hid)
        if not host:
            not_found_host_ids.append(hid)
            continue
        try:
            await db.add_upgrade_device(
                campaign_id, hid, host["ip_address"], host.get("hostname", ""),
            )
            added += 1
        except Exception as exc:
            skipped_host_ids.append(hid)
            LOGGER.debug("create_campaign: skipping duplicate device %s: %s", host["ip_address"], exc)

    # Add ad-hoc IPs
    skipped_ips: list[str] = []
    for ip in body.ad_hoc_ips:
        ip = ip.strip()
        if ip:
            try:
                await db.add_upgrade_device(campaign_id, None, ip, "")
                added += 1
            except Exception as exc:
                skipped_ips.append(ip)
                LOGGER.debug("create_campaign: skipping ad-hoc device %s: %s", ip, exc)

    if not_found_host_ids or skipped_host_ids or skipped_ips:
        LOGGER.warning(
            "Campaign '%s': %d devices added; not-found host ids=%s, "
            "duplicate/skipped host ids=%s, skipped ips=%s",
            body.name, added, not_found_host_ids, skipped_host_ids, skipped_ips,
        )

    await _audit("upgrades", "campaign_create", user=user,
                 detail=f"Created campaign '{body.name}' with {added} devices")
    LOGGER.info("Campaign created: %s (%d devices) by %s", body.name, added, user)

    return {
        "id": campaign_id,
        "devices_added": added,
        "requested": len(body.host_ids) + len([i for i in body.ad_hoc_ips if i.strip()]),
        "not_found_host_ids": not_found_host_ids,
        "skipped_host_ids": skipped_host_ids,
        "skipped_ips": skipped_ips,
    }


@router.get("/api/upgrades/campaigns")
async def list_campaigns():
    campaigns = await db.get_all_upgrade_campaigns()
    # Enrich with device counts. One grouped query for all campaigns instead of
    # one get_upgrade_devices() per campaign (the old N+1).
    counts = await db.get_upgrade_device_counts()
    for c in campaigns:
        c = await _repair_stale_running_campaign(c)
        c["is_actively_running"] = c["id"] in _running_campaigns
        tally = counts.get(c["id"])
        c["device_count"] = tally["device_count"] if tally else 0
        c["devices_completed"] = tally["devices_completed"] if tally else 0
        c["devices_failed"] = tally["devices_failed"] if tally else 0
    return campaigns


@router.get("/api/upgrades/campaigns/{campaign_id}")
async def get_campaign(campaign_id: int, request: Request):
    campaign = await db.get_upgrade_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    # Object-level authz: a campaign's events/operations carry device output
    # and config captures, so only its creator (or an admin) may read it -
    # holding the `upgrades` feature is not enough (matches the jobs WS).
    await require_owner_or_admin(request, campaign.get("created_by"))
    campaign = await _repair_stale_running_campaign(campaign)
    campaign["is_actively_running"] = campaign_id in _running_campaigns
    campaign["devices"] = await db.get_upgrade_devices(campaign_id)
    campaign["operations"] = await db.get_upgrade_operations(campaign_id)
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

    # Bind-time IDOR gate (see create_campaign). Omitting the credential keeps
    # the campaign on the configured service-credential default.
    if body.credential_id is not None:
        await require_credential_access(body.credential_id, session=session, allow_service=True)

    # Update campaign metadata
    await db.update_upgrade_campaign(
        campaign_id,
        name=body.name,
        description=body.description,
        image_map=body.image_map,
        options={**body.options, "credential_id": body.credential_id},
    )

    # Rebuild device list: remove non-running devices, then re-add from new selections
    await db.delete_upgrade_devices_by_campaign(campaign_id)

    # Collect existing IPs that are still running and were intentionally preserved
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
            except Exception as exc:
                LOGGER.debug("update_campaign: skipping duplicate device %s: %s", host["ip_address"], exc)

    for ip in body.ad_hoc_ips:
        ip = ip.strip()
        if ip and ip not in existing_ips:
            try:
                await db.add_upgrade_device(campaign_id, None, ip, "")
                added += 1
            except Exception as exc:
                LOGGER.debug("update_campaign: skipping ad-hoc device %s: %s", ip, exc)

    total_devices = len(await db.get_upgrade_devices(campaign_id))
    await _audit("upgrades", "campaign_update", user=user,
                 detail=f"Updated campaign '{body.name}' - {total_devices} devices ({added} new)")
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
async def get_campaign_events(campaign_id: int, request: Request, device_id: int = None, limit: int = Query(default=1000, ge=1, le=10000)):
    campaign = await db.get_upgrade_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    # Same object-level authz as get_campaign - the events are device output.
    await require_owner_or_admin(request, campaign.get("created_by"))
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
            "modified": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
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
    """Execute a specific phase for a campaign."""
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    if not NETMIKO_AVAILABLE:
        raise HTTPException(500, "netmiko is not installed")

    campaign = await db.get_upgrade_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    if body.phase not in _SUPPORTED_PHASES:
        raise HTTPException(400, f"Invalid phase: {body.phase}")

    if campaign_id in _running_campaigns:
        raise HTTPException(409, "Campaign is already running a phase")

    scheduled_at_utc: datetime | None = None
    if body.scheduled_at is not None:
        if body.phase != "activate":
            raise HTTPException(400, "Scheduling is only supported for activate phase")
        scheduled_at_utc = body.scheduled_at
        if scheduled_at_utc.tzinfo is None:
            scheduled_at_utc = scheduled_at_utc.replace(tzinfo=UTC)
        scheduled_at_utc = scheduled_at_utc.astimezone(UTC)
        if scheduled_at_utc <= datetime.now(UTC):
            raise HTTPException(400, "scheduled_at must be in the future")

    # Resolve the credential. An explicit campaign credential is validated
    # against the creator (see helper); when none is set the configured service
    # credential is used as the default for this unattended work.
    options = json.loads(campaign["options"]) if isinstance(campaign["options"], str) else campaign["options"]
    cred = await _resolve_campaign_credential(
        options.get("credential_id"), campaign.get("created_by"), session=session,
    )

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

    # A device cancelled in a prior attempt keeps its per-phase status pinned to
    # "cancelled", which _run_phase treats as a permanent skip. Re-executing the
    # phase for a device is an explicit operator request to run it again, so clear
    # that stale "cancelled" status (on the selected devices only) before the run.
    # Update both the DB and the in-memory snapshot the scheduled task closes over,
    # since _process_device checks the snapshot before re-reading the DB.
    phase_status_key = _phase_status_key(body.phase)
    for dev in devices:
        if dev.get(phase_status_key) == "cancelled":
            await db.update_upgrade_device(
                dev["id"], **{phase_status_key: "pending", "error_message": ""}
            )
            dev[phase_status_key] = "pending"
            dev["error_message"] = ""

    # Parse image map
    image_map_raw = json.loads(campaign["image_map"]) if isinstance(campaign["image_map"], str) else campaign["image_map"]
    # image_map: {"pattern": "image_filename", ...}
    # Sort by pattern length descending for specificity matching
    image_map = sorted(image_map_raw.items(), key=lambda x: len(x[0]), reverse=True)
    operation_id = await db.create_upgrade_operation(
        campaign_id,
        body.phase,
        "scheduled" if scheduled_at_utc is not None else "running",
        requested_by=user,
        device_count=len(devices),
        scheduled_at=(
            scheduled_at_utc.isoformat() if scheduled_at_utc is not None else None
        ),
        started_at=None if scheduled_at_utc is not None else _utc_now_iso(),
    )

    if scheduled_at_utc is not None:
        await db.update_upgrade_campaign(
            campaign_id,
            status=f"scheduled_{body.phase}",
            scheduled_at=scheduled_at_utc.isoformat(),
        )
        await _audit(
            "upgrades",
            "phase_execute",
            user=user,
            detail=(
                f"Scheduled {body.phase} on campaign {campaign_id} "
                f"for {scheduled_at_utc.isoformat()} ({len(devices)} devices)"
            ),
        )

        async def _run_scheduled_phase():
            try:
                await _emit(
                    campaign_id,
                    None,
                    "info",
                    f"{body.phase.title()} phase scheduled for {scheduled_at_utc.isoformat()} ({len(devices)} devices)",
                )
                delay_seconds = (scheduled_at_utc - datetime.now(UTC)).total_seconds()
                if delay_seconds > 0:
                    await asyncio.sleep(delay_seconds)
                await db.update_upgrade_campaign(
                    campaign_id,
                    status=f"running_{body.phase}",
                    scheduled_at=None,
                )
                await db.update_upgrade_operation(
                    operation_id,
                    status="running",
                    started_at=_utc_now_iso(),
                )
                await _emit(campaign_id, None, "info", f"Starting scheduled {body.phase} phase now")
                await _run_phase(
                    campaign_id,
                    body.phase,
                    devices,
                    credentials,
                    image_map,
                    options,
                    operation_id=operation_id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("Scheduled %s failed for campaign %s", body.phase, campaign_id)
                await _mark_upgrade_operation_failed(
                    campaign_id,
                    operation_id,
                    body.phase,
                    f"Scheduled {body.phase} failed before completion; check backend logs.",
                )

        task = asyncio.create_task(_run_scheduled_phase())
    else:
        await db.update_upgrade_campaign(campaign_id, status=f"running_{body.phase}")
        await _audit("upgrades", "phase_execute", user=user,
                     detail=f"Executing {body.phase} on campaign {campaign_id} ({len(devices)} devices)")
        task = asyncio.create_task(
            _run_phase(
                campaign_id,
                body.phase,
                devices,
                credentials,
                image_map,
                options,
                operation_id=operation_id,
            )
        )
    _running_campaigns[campaign_id] = task
    _running_campaign_operations[campaign_id] = operation_id

    def _on_done(t):
        _running_campaigns.pop(campaign_id, None)
        _running_campaign_operations.pop(campaign_id, None)
        if not t.cancelled():
            exc = t.exception()
            if exc is not None:
                LOGGER.error("Upgrade task crashed for campaign %s", campaign_id, exc_info=exc)

    task.add_done_callback(_on_done)

    return {
        "ok": True,
        "phase": body.phase,
        "device_count": len(devices),
        "scheduled": scheduled_at_utc is not None,
        "scheduled_at": scheduled_at_utc.isoformat() if scheduled_at_utc is not None else None,
    }


@router.post("/api/upgrades/campaigns/{campaign_id}/cancel")
async def cancel_campaign(campaign_id: int, request: Request):
    """Cancel a running campaign phase."""
    task = _running_campaigns.get(campaign_id)
    if not task:
        raise HTTPException(404, "No running phase for this campaign")

    task.cancel()
    _running_campaigns.pop(campaign_id, None)
    operation_id = _running_campaign_operations.pop(campaign_id, None)
    await db.update_upgrade_campaign(campaign_id, status="cancelled")
    if operation_id is not None:
        await db.update_upgrade_operation(
            operation_id,
            status="cancelled",
            completed_at=_utc_now_iso(),
            error_message="Campaign phase cancelled by user",
        )
    await _emit(campaign_id, None, "warn", "Campaign phase cancelled by user")

    # Notify WebSocket
    await _broadcast_upgrade_event(campaign_id, {
        "type": "campaign_complete",
        "campaign_id": campaign_id,
        "status": "cancelled",
    })

    return {"ok": True}


@router.post("/api/upgrades/campaigns/{campaign_id}/devices/cancel")
async def cancel_campaign_devices(
    campaign_id: int,
    body: CampaignDeviceCancelRequest,
    request: Request,
):
    """Mark selected campaign devices cancelled for the active/stale phase."""
    session = _get_session(request)
    user = session.get("user", "unknown") if session else "unknown"

    campaign = await db.get_upgrade_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    requested_ids = {int(did) for did in body.device_ids}
    if not requested_ids:
        raise HTTPException(400, "No devices selected")

    phase = body.phase
    if phase is None:
        status = campaign.get("status") or ""
        if status.startswith("running_"):
            phase = status.split("running_", 1)[1].strip()
        elif status.startswith("scheduled_"):
            phase = status.split("scheduled_", 1)[1].strip()
    if phase not in _SUPPORTED_PHASES:
        raise HTTPException(400, "Cannot determine phase to cancel")

    status_key = _phase_status_key(phase)
    devices = await db.get_upgrade_devices(campaign_id)
    by_id = {d["id"]: d for d in devices}
    missing = sorted(requested_ids - set(by_id))
    if missing:
        raise HTTPException(404, "One or more devices were not found in this campaign")

    cancelled = 0
    skipped_completed = 0
    for device_id in sorted(requested_ids):
        dev = by_id[device_id]
        if dev.get(status_key) == "completed":
            skipped_completed += 1
            continue
        await db.update_upgrade_device(
            device_id,
            **{
                status_key: "cancelled",
                "phase": "cancelled",
                "error_message": f"Cancelled by {user} during {phase} phase",
            },
        )
        await _emit_device_status(
            campaign_id,
            device_id,
            **{
                status_key: "cancelled",
                "error_message": f"Cancelled by {user} during {phase} phase",
            },
        )
        await _emit(
            campaign_id,
            device_id,
            "warn",
            f"Device cancelled during {phase} phase by user",
            host=dev.get("ip_address", ""),
        )
        cancelled += 1

    if cancelled == 0:
        raise HTTPException(400, "Selected devices are already completed")

    updated_devices = await db.get_upgrade_devices(campaign_id)
    current_status = campaign.get("status") or ""
    current_phase = None
    if current_status.startswith("running_"):
        current_phase = current_status.split("running_", 1)[1].strip()
    elif current_status.startswith(f"{phase}_"):
        current_phase = phase
    same_phase_status = current_phase == phase or current_status == "cancelled"
    if campaign_id not in _running_campaigns and same_phase_status:
        await db.update_upgrade_campaign(
            campaign_id,
            status=_derive_stale_phase_status(phase, updated_devices),
        )

    await _audit(
        "upgrades",
        "devices_cancel",
        user=user,
        detail=(
            f"Cancelled {cancelled} device(s) in {phase} phase for campaign {campaign_id}"
        ),
        correlation_id=_corr_id(request),
    )

    return {
        "ok": True,
        "phase": phase,
        "cancelled": cancelled,
        "skipped_completed": skipped_completed,
    }


# ═════════════════════════════════════════════════════════════════════════════
# WEBSOCKET - Real-time upgrade streaming
# ═════════════════════════════════════════════════════════════════════════════


@ws_router.websocket("/ws/upgrades/{campaign_id}")
async def upgrade_websocket(ws: WebSocket, campaign_id: int):
    """Stream upgrade events to the browser in real-time."""
    # Verify auth before accepting the connection. The token comes from the
    # session cookie only - never a query-string param, which would leak the
    # token into proxy/access logs and browser history. Enforce the same
    # idle/absolute-lifetime, user-existence, and feature checks the other WS
    # endpoints use (fail closed rather than fail open).
    token = ws.cookies.get("session")
    session = await verify_ws_session(token)
    if not session:
        await ws.close(code=4001, reason="Unauthorized")
        return
    user = await db.get_user_by_id(session["user_id"])
    if not user:
        await ws.close(code=4001, reason="Unauthorized")
        return
    features = await _get_user_features(user) if _get_user_features else []
    if user.get("role") != "admin" and "upgrades" not in features:
        await ws.close(code=4001, reason="Unauthorized")
        return

    # Object-level authz: only the campaign's creator (or an admin) may stream
    # its output. Mirrors the REST get_campaign check and the jobs WS.
    campaign = await db.get_upgrade_campaign(campaign_id)
    if not campaign:
        await ws.close(code=4001, reason="Unauthorized")
        return
    if user.get("role") != "admin" and campaign.get("created_by") != session.get("user"):
        await ws.close(code=4001, reason="Unauthorized")
        return

    await ws.accept()

    # Send recent historical events as a single batch to avoid keepalive
    # timeouts. The tail is capped (newest-first internally, returned oldest-
    # first); live events stream in afterward, so this is just catch-up context.
    events = await db.get_upgrade_events(campaign_id, limit=1000)
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
    async with _campaign_sockets_lock:
        if campaign_id not in _campaign_sockets:
            _campaign_sockets[campaign_id] = []
        _campaign_sockets[campaign_id].append(ws)

    try:
        while True:
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=120)
            except TimeoutError:
                # Send ping to detect dead connections
                try:
                    await ws.send_json({"type": "ping"})
                except Exception:
                    break
    except WebSocketDisconnect as exc:
        LOGGER.debug("upgrade WS disconnected for campaign %s: %s", campaign_id, exc)
    finally:
        async with _campaign_sockets_lock:
            sockets = _campaign_sockets.get(campaign_id, [])
            if ws in sockets:
                sockets.remove(ws)


# ═════════════════════════════════════════════════════════════════════════════
# UPGRADE ENGINE - Core Netmiko logic ported from iosxe_upgrade.py
# ═════════════════════════════════════════════════════════════════════════════


async def _run_phase(
    campaign_id,
    phase,
    devices,
    credentials,
    image_map,
    options,
    operation_id=None,
):
    """Orchestrate a phase across all devices with concurrency control."""
    max_workers = min(options.get("parallel", 4), 8)
    status_key = _phase_status_key(phase)
    phase_name = _phase_label(phase)

    await _emit(campaign_id, None, "info",
                f"Starting {phase_name} phase for {len(devices)} device(s) (max {max_workers} concurrent)")

    semaphore = asyncio.Semaphore(max_workers)

    async def _process_device(dev):
        if dev.get(status_key) == "cancelled":
            await _emit(
                campaign_id,
                dev["id"],
                "warn",
                f"Skipping {phase_name} phase; device was cancelled",
                host=dev["ip_address"],
            )
            return
        async with semaphore:
            try:
                latest = await db.get_upgrade_device(dev["id"])
                if latest and latest.get(status_key) == "cancelled":
                    await _emit(
                        campaign_id,
                        dev["id"],
                        "warn",
                        f"Skipping {phase_name} phase; device was cancelled",
                        host=dev["ip_address"],
                    )
                    return
                if phase == "prestage":
                    await _device_prestage(campaign_id, dev, credentials, image_map, options)
                elif phase == "transfer":
                    await _device_transfer(campaign_id, dev, credentials, image_map, options)
                elif phase == "activate":
                    await _device_activate(campaign_id, dev, credentials, image_map, options)
                elif phase == "verify":
                    await _device_verify(campaign_id, dev, credentials, image_map, options)
                elif phase == "verify_prestage":
                    await _device_verify_prestage(campaign_id, dev, credentials, image_map, options)
            except asyncio.CancelledError:
                await db.update_upgrade_device(dev["id"], **{status_key: "cancelled", "phase": "cancelled"})
                raise
            except Exception as e:
                LOGGER.error("Unhandled error on device %s: %s", dev["ip_address"], e, exc_info=True)
                await db.update_upgrade_device(dev["id"], **{
                    status_key: "failed",
                    "phase": "failed",
                    "error_message": str(e)[:1000],
                })
                await _emit(campaign_id, dev["id"], "error", f"Unhandled error: {str(e)[:500]}", host=dev["ip_address"])

    tasks = [asyncio.create_task(_process_device(d)) for d in devices]

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        if operation_id is not None:
            await db.update_upgrade_operation(
                operation_id,
                status="cancelled",
                completed_at=_utc_now_iso(),
                error_message=f"{phase_name} phase cancelled",
            )
        raise

    # Update campaign status
    all_devs = await db.get_upgrade_devices(campaign_id)
    final_status = _derive_stale_phase_status(phase, all_devs)
    failed = sum(1 for d in all_devs if d.get(status_key) == "failed")
    cancelled = sum(1 for d in all_devs if d.get(status_key) == "cancelled")
    completed = sum(1 for d in all_devs if d.get(status_key) == "completed")
    total = len(all_devs)

    await db.update_upgrade_campaign(campaign_id, status=final_status)
    if operation_id is not None:
        error_message = ""
        if failed or cancelled:
            error_message = (
                f"{phase_name} phase completed with {failed} failed and "
                f"{cancelled} cancelled device(s)."
            )
        await db.update_upgrade_operation(
            operation_id,
            status=final_status,
            device_count=total,
            succeeded=completed,
            failed=failed,
            cancelled=cancelled,
            completed_at=_utc_now_iso(),
            error_message=error_message,
        )
    level = "success" if failed == 0 and cancelled == 0 else "warn"
    await _emit(campaign_id, None, level,
                f"{phase_name} phase complete: {completed}/{total} succeeded, {failed} failed, {cancelled} cancelled")

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


async def _resolve_device_type(dev) -> str:
    """Look up the host's stored device_type, falling back to ``cisco_xe``.

    ``upgrade_devices`` rows can be ad-hoc IPs (host_id is NULL) for
    campaigns that target unmanaged hardware, so the fallback keeps
    those flows working.  When ``host_id`` is set we read the device
    type off the ``hosts`` row, which is also the value Netmiko needs
    to open the session with the right CLI handler.
    """
    host_id = dev.get("host_id")
    if not host_id:
        return "cisco_xe"
    try:
        host = await db.get_host(host_id)
    except Exception:
        return "cisco_xe"
    if not host:
        return "cisco_xe"
    return host.get("device_type") or "cisco_xe"


def _build_device_params(ip, credentials, options, device_type="cisco_xe"):
    """Build Netmiko device parameters.

    ``device_type`` defaults to ``cisco_xe`` for backwards compatibility
    with ad-hoc IP campaigns (no host record, no known device_type) but
    callers that resolve the host's real device_type should pass it
    through so non-Cisco-XE platforms (when their drivers gain upgrade
    capabilities) open the SSH session with the right Netmiko handler.
    """
    return {
        "device_type": device_type or "cisco_xe",
        "host": ip,
        "username": credentials["username"],
        "password": credentials["password"],
        "secret": credentials.get("secret", credentials["password"]),
        "port": options.get("port", 22),
        "timeout": options.get("timeout", 120),
        "session_timeout": options.get("timeout", 120),
        "auth_timeout": 30,
    }


async def _connect_device(ip, credentials, options, retries=1, device_type="cisco_xe"):
    """Connect to a device via SSH with retry support."""
    device = _build_device_params(ip, credentials, options, device_type=device_type)
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


async def _run_install_add_prestage(
    conn, campaign_id, dev_id, ip, image_name, dest_path, device_type="cisco_xe"
):
    """Pre-stage packages so activate can run without a new add.

    Delegates the actual install-add verb to the driver so non-Cisco-XE
    platforms (when their drivers gain ``upgrade_install_add_command``)
    surface the right syntax.  Platforms whose driver reports
    ``upgrade_has_discrete_prestage() == False`` (Junos, NX-OS, classic
    IOS) bypass the install-add entirely - their upgrade model
    combines staging and activation into a single later step, so
    running an install-add at this point would either error
    out (Junos has no equivalent command) or pre-stage redundantly.
    The function returns ``(True, None)`` in that case so the transfer
    phase can complete and the activate phase can do both halves of
    the operation at once.
    """
    driver = get_driver(device_type)
    if not driver.upgrade_has_discrete_prestage():
        await _emit(
            campaign_id,
            dev_id,
            "info",
            "Platform combines add+activate; deferring stage until activate phase",
            host=ip,
        )
        return True, None
    full_path = f"{dest_path}{image_name}"
    try:
        install_add_cmd = driver.upgrade_install_add_command(full_path)
    except DriverCapabilityError as e:
        await _emit(campaign_id, dev_id, "error",
                    f"Pre-stage not supported on this platform: {e}", host=ip)
        return False, str(e)
    await _emit(campaign_id, dev_id, "info", f"Pre-staging image: {install_add_cmd}", host=ip)
    await _emit(campaign_id, dev_id, "info", "This may take several minutes...", host=ip)

    install_output = ""
    try:
        install_output = await asyncio.to_thread(
            conn.send_command,
            install_add_cmd,
            expect_string=r"#|>|proceed|y/n|\[yes/no\]|\[y/n\]",
            read_timeout=1200,
        )
        if any(x in install_output.lower() for x in ["proceed", "y/n", "yes/no"]):
            install_output += await asyncio.to_thread(
                conn.send_command,
                "y",
                expect_string=r"#|>",
                read_timeout=1200,
            )
    except Exception as e:
        err_text = str(e).lower()
        if any(x in err_text for x in ["pattern not detected", "timed out", "read_timeout"]):
            await _emit(
                campaign_id,
                dev_id,
                "warn",
                "Prompt detection failed during install add, retrying with timing mode...",
                host=ip,
            )
            try:
                install_output = await asyncio.to_thread(
                    conn.send_command_timing,
                    install_add_cmd,
                    read_timeout=1200,
                    strip_prompt=False,
                    strip_command=False,
                )
                if any(x in install_output.lower() for x in ["proceed", "y/n", "yes/no"]):
                    install_output += await asyncio.to_thread(
                        conn.send_command_timing,
                        "y",
                        read_timeout=1200,
                        strip_prompt=False,
                        strip_command=False,
                    )
            except Exception as timing_err:
                timing_text = str(timing_err).lower()
                if any(tok in timing_text for tok in ("already added", "already present", "already installed")):
                    await _emit(campaign_id, dev_id, "info", "Image already pre-staged", host=ip)
                    verify_ok, verify_err = await _verify_install_add_unpacked_files(
                        conn, campaign_id, dev_id, ip, image_name, dest_path
                    )
                    if not verify_ok:
                        return False, verify_err
                    return True, None
                return False, str(timing_err)

        # Some platforms report an already-added state via an exception string.
        if any(tok in err_text for tok in ("already added", "already present", "already installed")):
            await _emit(campaign_id, dev_id, "info", "Image already pre-staged", host=ip)
            verify_ok, verify_err = await _verify_install_add_unpacked_files(
                conn, campaign_id, dev_id, ip, image_name, dest_path
            )
            if not verify_ok:
                return False, verify_err
            return True, None
        if not install_output:
            return False, str(e)

    output_text = (install_output or "").lower()
    if any(tok in output_text for tok in ("already added", "already present", "already installed")):
        await _emit(campaign_id, dev_id, "info", "Image already pre-staged", host=ip)
    else:
        await _emit(campaign_id, dev_id, "success", "Image pre-staged successfully", host=ip)

    if install_output:
        await _emit(campaign_id, dev_id, "info", install_output[-500:], host=ip)

    verify_ok, verify_err = await _verify_install_add_unpacked_files(
        conn, campaign_id, dev_id, ip, image_name, dest_path
    )
    if not verify_ok:
        return False, verify_err

    return True, None


async def _verify_install_add_unpacked_files(conn, campaign_id, dev_id, ip, image_name, dest_path):
    """Verify install-add unpackaging by checking for non-.bin artifacts of target version."""
    expected_version = _extract_version(image_name)
    if not expected_version:
        return False, f"Cannot extract version from image filename: {image_name}"

    if not re.fullmatch(r"[0-9.]+", expected_version):
        return False, f"Extracted version is invalid for verification: {expected_version!r}"

    # Use plain "dir" for compatibility across platforms that return empty
    # output when a filesystem prefix is provided.
    verify_cmd = f"dir | include {expected_version}"
    await _emit(campaign_id, dev_id, "info", f"Verifying install-add artifacts: {verify_cmd}", host=ip)

    try:
        output = await asyncio.to_thread(conn.send_command, verify_cmd, read_timeout=180)
    except Exception as e:
        return False, f"Install add verification command failed: {e}"

    version_lines = []
    unpacked_lines = []
    bin_lines = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        lower = line.lower()
        if not line:
            continue
        # Ignore echoed command and directory summary noise.
        if lower.startswith("dir ") or "| include" in lower or "directory of" in lower:
            continue
        if "bytes free" in lower or "bytes total" in lower:
            continue
        if expected_version not in line:
            continue
        version_lines.append(line)
        if ".bin" in lower:
            bin_lines.append(line)
            continue
        unpacked_lines.append(line)

    if unpacked_lines:
        await _emit(
            campaign_id,
            dev_id,
            "success",
            f"Install add verified - found {len(unpacked_lines)} unpackaged entries for {expected_version}",
            host=ip,
        )
        preview_lines = unpacked_lines[:10]
        for pkg_line in preview_lines:
            await _emit(campaign_id, dev_id, "info", pkg_line[:500], host=ip)
        omitted = len(unpacked_lines) - len(preview_lines)
        if omitted > 0:
            await _emit(
                campaign_id,
                dev_id,
                "info",
                f"... {omitted} additional unpackaged entries omitted",
                host=ip,
            )
        return True, None

    if bin_lines and version_lines:
        return (
            False,
            f"Install add verification failed for {expected_version}: only .bin entries found (no unpackaged artifacts)",
        )

    return False, f"Install add verification failed for {expected_version}: no matching unpackaged files found"


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
    device_type = await _resolve_device_type(dev)

    await db.update_upgrade_device(dev_id, prestage_status="running", phase="prestage",
                                   started_at=datetime.now(UTC).isoformat())
    await _emit_device_status(campaign_id, dev_id, prestage_status="running")
    await _emit(campaign_id, dev_id, "info", f"Connecting to {ip}...", host=ip)

    try:
        conn = await _connect_device(ip, credentials, options,
                                     retries=options.get("retries", 2),
                                     device_type=device_type)
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
        except Exception as exc:
            LOGGER.debug("Disconnect failed for %s: %s", ip, exc)


# ── TRANSFER ─────────────────────────────────────────────────────────────────


async def _device_transfer(campaign_id, dev, credentials, image_map, options):
    """Transfer: check space, SCP image, verify MD5, install add, and verify unpackaging."""
    ip = dev["ip_address"]
    dev_id = dev["id"]
    dest_path = options.get("dest_path", "flash:")
    device_type = await _resolve_device_type(dev)

    await db.update_upgrade_device(dev_id, transfer_status="running", phase="transfer",
                                   started_at=datetime.now(UTC).isoformat())
    await _emit_device_status(campaign_id, dev_id, transfer_status="running")
    await _emit(campaign_id, dev_id, "info", f"Connecting to {ip}...", host=ip)

    try:
        conn = await _connect_device(ip, credentials, options,
                                     retries=options.get("retries", 2),
                                     device_type=device_type)
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

        # Check if device is already running the target version - skip transfer
        expected_version = _extract_version(image_name)
        if expected_version:
            det_model, running_version = await _detect_model(conn, ip)
            if det_model:
                await db.update_upgrade_device(dev_id, model=det_model, current_version=running_version or "")
            if running_version and expected_version in running_version:
                await _emit(campaign_id, dev_id, "success",
                            f"Already running target version {running_version} - skipping transfer", host=ip)
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

        try:
            image_path = _image_file_path(image_name)
        except HTTPException:
            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                           error_message="Invalid image path")
            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message="Invalid image path")
            await _emit(campaign_id, dev_id, "error", "Invalid image path - possible path traversal", host=ip)
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
            # The primary location may be empty if the image was stored under an
            # older directory scheme; search the other candidate locations before
            # failing so a legacy-located file is still picked up.
            fallback = _find_existing_image_path(image_name)
            if fallback:
                image_path = fallback
            else:
                searched = ", ".join(_candidate_image_dirs())
                await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                               error_message=f"Image file not found in: {searched}")
                await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=f"Image file not found in: {searched}")
                await _emit(campaign_id, dev_id, "error",
                            f"Image file not found on server: {target_image} (searched: {searched})", host=ip)
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
            should_prestage = False
            if local_md5 and not options.get("skip_md5"):
                await _emit(campaign_id, dev_id, "info", "Verifying existing image integrity...", host=ip)
                md5_ok = await _verify_md5_on_switch(conn, image_name, dest_path, local_md5)
                if md5_ok:
                    await _emit(campaign_id, dev_id, "success", "Existing image matches - no transfer needed", host=ip)
                    should_prestage = True
                else:
                    await _emit(campaign_id, dev_id, "warn", "Existing image does NOT match - will re-transfer", host=ip)
            else:
                await _emit(campaign_id, dev_id, "success", "Image already on flash - skipping transfer", host=ip)
                should_prestage = True

            if should_prestage:
                prestage_ok, prestage_err = await _run_install_add_prestage(
                    conn, campaign_id, dev_id, ip, image_name, dest_path,
                    device_type=device_type,
                )
                if not prestage_ok:
                    await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                                   error_message=prestage_err)
                    await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=prestage_err)
                    await _emit(campaign_id, dev_id, "error", f"Pre-stage (install add) failed: {prestage_err}", host=ip)
                    return

                await db.update_upgrade_device(dev_id, transfer_status="completed", phase="transfer_done")
                await _emit_device_status(campaign_id, dev_id, transfer_status="completed")
                await _emit(campaign_id, dev_id, "success", "Transfer phase complete", host=ip)
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
            except Exception as exc:
                LOGGER.debug("write memory failed after transfer for %s: %s", ip, exc)

            prestage_ok, prestage_err = await _run_install_add_prestage(
                conn, campaign_id, dev_id, ip, image_name, dest_path,
                device_type=device_type,
            )
            if not prestage_ok:
                await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                               error_message=prestage_err)
                await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=prestage_err)
                await _emit(campaign_id, dev_id, "error", f"Pre-stage (install add) failed: {prestage_err}", host=ip)
                return

            await db.update_upgrade_device(dev_id, transfer_status="completed", phase="transfer_done")
            await _emit_device_status(campaign_id, dev_id, transfer_status="completed")
            await _emit(campaign_id, dev_id, "success", "Transfer phase complete", host=ip)
        else:
            # SCP reported failure, but file may have transferred before connection dropped.
            # Reconnect and check flash before marking as failed.
            await _emit(campaign_id, dev_id, "warn",
                        f"SCP error after {elapsed/60:.1f} minutes: {transfer_err or 'unknown'} - verifying flash...", host=ip)
            try:
                verify_conn = await _connect_device(ip, credentials, options, retries=1,
                                                    device_type=device_type)
                exists = await asyncio.to_thread(_check_image_exists, verify_conn, image_name, dest_path)
                if exists:
                    await _emit(campaign_id, dev_id, "success",
                                "Image found on flash despite SCP error - transfer actually succeeded", host=ip)
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
                        except Exception as exc:
                            LOGGER.debug("write memory failed after transfer for %s: %s", ip, exc)
                        prestage_ok, prestage_err = await _run_install_add_prestage(
                            verify_conn, campaign_id, dev_id, ip, image_name, dest_path,
                            device_type=device_type,
                        )
                        if not prestage_ok:
                            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                                           error_message=prestage_err)
                            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=prestage_err)
                            await _emit(campaign_id, dev_id, "error", f"Pre-stage (install add) failed: {prestage_err}", host=ip)
                            try:
                                await asyncio.to_thread(verify_conn.disconnect)
                            except Exception as exc:
                                LOGGER.debug("Disconnect failed for %s: %s", ip, exc)
                            return
                        await db.update_upgrade_device(dev_id, transfer_status="completed", phase="transfer_done")
                        await _emit_device_status(campaign_id, dev_id, transfer_status="completed")
                        await _emit(campaign_id, dev_id, "success", "Transfer phase complete", host=ip)
                    try:
                        await asyncio.to_thread(verify_conn.disconnect)
                    except Exception as exc:
                        LOGGER.debug("Disconnect failed for %s: %s", ip, exc)
                    return
                try:
                    await asyncio.to_thread(verify_conn.disconnect)
                except Exception as exc:
                    LOGGER.debug("Disconnect failed for %s: %s", ip, exc)
            except Exception:
                await _emit(campaign_id, dev_id, "warn", "Could not reconnect to verify flash", host=ip)

            err_detail = f"SCP transfer failed: {transfer_err}" if transfer_err else "SCP transfer failed"
            await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                           error_message=err_detail)
            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=err_detail)
            await _emit(campaign_id, dev_id, "error", f"Transfer failed after {elapsed/60:.1f} minutes - {transfer_err or 'unknown error'}", host=ip)

    except Exception as e:
        await db.update_upgrade_device(dev_id, transfer_status="failed", phase="failed",
                                       error_message=str(e))
        await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=str(e))
        await _emit(campaign_id, dev_id, "error", f"Transfer failed: {e}", host=ip)
    finally:
        try:
            await asyncio.to_thread(conn.disconnect)
        except Exception as exc:
            LOGGER.debug("Disconnect failed for %s: %s", ip, exc)


# ── ACTIVATE ─────────────────────────────────────────────────────────────────


async def _device_activate(campaign_id, dev, credentials, image_map, options):
    """Activate: install activate commit (image already pre-staged during transfer), wait for reboot, verify."""
    ip = dev["ip_address"]
    dev_id = dev["id"]
    dest_path = options.get("dest_path", "flash:")
    device_type = await _resolve_device_type(dev)

    await db.update_upgrade_device(dev_id, activate_status="running", phase="activate",
                                   started_at=datetime.now(UTC).isoformat())
    await _emit_device_status(campaign_id, dev_id, activate_status="running")
    await _emit(campaign_id, dev_id, "info", f"Connecting to {ip}...", host=ip)

    try:
        conn = await _connect_device(ip, credentials, options,
                                     retries=options.get("retries", 2),
                                     device_type=device_type)
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

        # Check if device is already running the target version - skip activate
        expected_version = _extract_version(image_name)
        if expected_version:
            det_model, running_version = await _detect_model(conn, ip)
            if det_model:
                await db.update_upgrade_device(dev_id, model=det_model, current_version=running_version or "")
            if running_version and expected_version in running_version:
                await _emit(campaign_id, dev_id, "success",
                            f"Already running target version {running_version} - skipping activate", host=ip)
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

        # Image already pre-staged during transfer (install add), just activate.
        # The driver supplies the platform-specific activate verb(s); for
        # IOS-XE that's a single "install activate prompt-level none" line,
        # but multi-command sequences (e.g. Junos: software-add + reboot)
        # are also supported - they're sent one at a time and the last one
        # is expected to drop the SSH session.
        full_path = f"{dest_path}{image_name}"
        try:
            activate_commands = get_driver(device_type).upgrade_activate_commands(full_path)
        except DriverCapabilityError as e:
            await db.update_upgrade_device(dev_id, activate_status="failed", phase="failed",
                                           error_message=str(e))
            await _emit_device_status(campaign_id, dev_id, activate_status="failed", error_message=str(e))
            await _emit(campaign_id, dev_id, "error",
                        f"Activate not supported on this platform: {e}", host=ip)
            return
        for command in activate_commands:
            await _emit(campaign_id, dev_id, "cmd", f"Executing: {command}", host=ip)
            await _emit(campaign_id, dev_id, "info", "This will trigger a reload (5-15 minutes)...", host=ip)

            try:
                await asyncio.to_thread(
                    conn.send_command, command, read_timeout=120,
                )
            except Exception as e:
                # Expected on the final command - the switch reboots and drops
                # the SSH session.  We don't try to distinguish "reboot drop"
                # from a real error here; if the switch comes back at the
                # right version the upgrade was a success.
                await _emit(campaign_id, dev_id, "info", f"Connection closed (expected during reload): {e}", host=ip)
                break

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
                await _emit(campaign_id, dev_id, "info", "Switch is offline - reboot in progress", host=ip)
            else:
                await _emit(campaign_id, dev_id, "warn",
                            "Switch never went offline - it may not have reloaded. Checking version anyway...", host=ip)

            # Then: wait for switch to come BACK online
            new_conn = await _wait_for_reboot(ip, credentials, options, verify_wait, check_interval, campaign_id, dev_id, device_type=device_type)

            if new_conn:
                await _emit(campaign_id, dev_id, "success", "Switch is back online!", host=ip)

                # Verify version
                expected_version = _extract_version(image_name)
                if expected_version:
                    _, running_version = await _detect_model(new_conn, ip)
                    if running_version and expected_version in running_version:
                        await _emit(campaign_id, dev_id, "success",
                                    f"Version verified: {running_version} (expected {expected_version})", host=ip)

                        # Commit the install to make the new version permanent.
                        # Driver returns an empty string for platforms that
                        # don't need an explicit commit step (NX-OS auto-
                        # commits, Junos persists on the activate's commit).
                        try:
                            commit_cmd = get_driver(device_type).upgrade_commit_command()
                        except DriverCapabilityError as e:
                            await _emit(campaign_id, dev_id, "warn",
                                        f"Skipping commit: {e}", host=ip)
                            commit_cmd = ""
                        if commit_cmd:
                            await _emit(campaign_id, dev_id, "info",
                                        f"Running {commit_cmd} to lock in new version...", host=ip)
                            try:
                                commit_output = await asyncio.to_thread(
                                    new_conn.send_command, commit_cmd, read_timeout=300,
                                )
                                if _install_commit_output_failed(commit_output):
                                    raise RuntimeError(commit_output.strip()[:500])
                                await _emit(campaign_id, dev_id, "success", "Install committed", host=ip)
                                if commit_output:
                                    await _emit(campaign_id, dev_id, "info", commit_output[-500:], host=ip)
                            except Exception as e:
                                # A failed commit means the activated image is
                                # uncommitted and the device's auto-rollback
                                # timer will revert it to the old version. This
                                # is a hard failure, not a warning - do NOT mark
                                # the device verified.
                                msg = f"Commit failed: {e} - device will roll back to the old version"
                                await _emit(campaign_id, dev_id, "error",
                                            f"{commit_cmd} failed: {e} - switch will roll back!", host=ip)
                                await db.update_upgrade_device(
                                    dev_id, activate_status="failed",
                                    verify_status="failed",
                                    phase="failed",
                                    current_version=running_version,
                                    error_message=msg)
                                await _emit_device_status(
                                    campaign_id, dev_id,
                                    activate_status="failed",
                                    verify_status="failed",
                                    error_message=msg)
                                try:
                                    await asyncio.to_thread(new_conn.disconnect)
                                except Exception as exc:
                                    LOGGER.debug("Disconnect failed for %s: %s", ip, exc)
                                return

                            # Re-verify AFTER commit: a "successful" commit
                            # command can still leave the device on the old
                            # version (rollback already fired, partial commit).
                            # Trust nothing - re-read the running version.
                            await _emit(campaign_id, dev_id, "info",
                                        "Confirming version after commit...", host=ip)
                            _, post_commit_version = await _detect_model(new_conn, ip)
                            if not (post_commit_version
                                    and expected_version in post_commit_version):
                                msg = (f"Post-commit version mismatch: running "
                                       f"{post_commit_version}, expected {expected_version}")
                                await _emit(campaign_id, dev_id, "error", msg, host=ip)
                                await db.update_upgrade_device(
                                    dev_id, activate_status="failed",
                                    verify_status="failed",
                                    phase="failed",
                                    current_version=post_commit_version or running_version,
                                    error_message=msg)
                                await _emit_device_status(
                                    campaign_id, dev_id,
                                    activate_status="failed",
                                    verify_status="failed",
                                    error_message=msg)
                                try:
                                    await asyncio.to_thread(new_conn.disconnect)
                                except Exception as exc:
                                    LOGGER.debug("Disconnect failed for %s: %s", ip, exc)
                                return
                            running_version = post_commit_version

                        await _emit(campaign_id, dev_id, "success",
                                    f"Upgrade verified and committed - running {running_version}", host=ip)
                        await db.update_upgrade_device(dev_id, verify_status="completed",
                                                       phase="verified",
                                                       current_version=running_version,
                                                       error_message="")
                        await _emit_device_status(campaign_id, dev_id,
                                                  verify_status="completed",
                                                  error_message="")
                    else:
                        await _emit(campaign_id, dev_id, "error",
                                    f"Version mismatch! Running: {running_version}, Expected: {expected_version}", host=ip)
                        await db.update_upgrade_device(dev_id, activate_status="failed",
                                                       verify_status="failed",
                                                       phase="failed",
                                                       current_version=running_version or "",
                                                       error_message=f"Version mismatch: {running_version}")
                        await _emit_device_status(campaign_id, dev_id,
                                                  activate_status="failed",
                                                  verify_status="failed",
                                                  error_message=f"Version mismatch: {running_version}")
                        try:
                            await asyncio.to_thread(new_conn.disconnect)
                        except Exception as exc:
                            LOGGER.debug("Disconnect failed for %s: %s", ip, exc)
                        return

                try:
                    await asyncio.to_thread(new_conn.disconnect)
                except Exception as exc:
                    LOGGER.debug("Disconnect failed for %s: %s", ip, exc)
            else:
                await _emit(campaign_id, dev_id, "error",
                            f"Switch did not come back within {verify_wait // 60} minutes", host=ip)
                await db.update_upgrade_device(dev_id, activate_status="failed",
                                               verify_status="failed",
                                               phase="failed",
                                               error_message="Switch unreachable after reboot")
                await _emit_device_status(campaign_id, dev_id,
                                          activate_status="failed",
                                          verify_status="failed",
                                          error_message="Switch unreachable after reboot")
                return

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
        except Exception as exc:
            LOGGER.debug("Disconnect failed for %s: %s", ip, exc)


# ── VERIFY ──────────────────────────────────────────────────────────────────


async def _device_verify(campaign_id, dev, credentials, image_map, options):
    """Verify: connect to switch and check running version against target image."""
    ip = dev["ip_address"]
    dev_id = dev["id"]
    device_type = await _resolve_device_type(dev)

    await db.update_upgrade_device(dev_id, verify_status="running", phase="verify")
    await _emit_device_status(campaign_id, dev_id, verify_status="running")
    await _emit(campaign_id, dev_id, "info", f"Connecting to {ip}...", host=ip)

    try:
        conn = await _connect_device(ip, credentials, options,
                                     retries=options.get("retries", 2),
                                     device_type=device_type)
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
            # Device is fully upgraded - mark all steps completed
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
                        f"Upgrade verified - running {running_version} (matches {expected_version})", host=ip)
        else:
            await db.update_upgrade_device(dev_id, activate_status="failed",
                                           verify_status="failed",
                                           phase="failed",
                                           error_message=f"Version mismatch: running {running_version}, expected {expected_version}",
                                           current_version=running_version)
            await _emit_device_status(campaign_id, dev_id,
                                      activate_status="failed",
                                      verify_status="failed",
                                      error_message=f"Version mismatch: running {running_version}, expected {expected_version}")
            await _emit(campaign_id, dev_id, "error",
                        f"Version mismatch - running {running_version}, expected {expected_version}", host=ip)

    except Exception as e:
        await db.update_upgrade_device(dev_id, verify_status="failed", phase="failed",
                                       error_message=str(e))
        await _emit_device_status(campaign_id, dev_id, verify_status="failed", error_message=str(e))
        await _emit(campaign_id, dev_id, "error", f"Verify failed: {e}", host=ip)
    finally:
        try:
            await asyncio.to_thread(conn.disconnect)
        except Exception as exc:
            LOGGER.debug("Disconnect failed for %s: %s", ip, exc)


async def _device_verify_prestage(campaign_id, dev, credentials, image_map, options):
    """Re-verify install-add unpackaging using campaign target version artifacts on flash."""
    ip = dev["ip_address"]
    dev_id = dev["id"]
    dest_path = options.get("dest_path", "flash:")
    device_type = await _resolve_device_type(dev)

    await db.update_upgrade_device(
        dev_id,
        transfer_status="running",
        phase_detail="Verifying install-add unpackaged artifacts",
        started_at=datetime.now(UTC).isoformat(),
    )
    await _emit_device_status(campaign_id, dev_id, transfer_status="running")
    await _emit(campaign_id, dev_id, "info", f"Connecting to {ip} for prestage verification...", host=ip)

    try:
        conn = await _connect_device(ip, credentials, options,
                                     retries=options.get("retries", 2),
                                     device_type=device_type)
    except Exception as e:
        err_msg = f"Connection failed: {e}"
        await db.update_upgrade_device(
            dev_id,
            transfer_status="failed",
            phase_detail="Prestage verification failed (connection)",
            error_message=err_msg,
        )
        await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=err_msg)
        await _emit(campaign_id, dev_id, "error", err_msg, host=ip)
        return

    try:
        await _emit(campaign_id, dev_id, "success", "Connected", host=ip)

        model = dev.get("model")
        target_image = dev.get("target_image", "")
        if not target_image:
            det_model, _ = await _detect_model(conn, ip)
            if det_model:
                model = det_model
                await db.update_upgrade_device(dev_id, model=det_model)

        if not target_image and model:
            image_map_items = image_map if isinstance(image_map, list) else sorted(image_map.items(), key=lambda x: len(x[0]), reverse=True)
            target_image = _resolve_image(model, image_map_items)
            if target_image:
                await db.update_upgrade_device(dev_id, target_image=target_image)

        if not target_image:
            err_msg = "No target image to verify against"
            await db.update_upgrade_device(
                dev_id,
                transfer_status="failed",
                phase_detail="Prestage verification failed",
                error_message=err_msg,
            )
            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=err_msg)
            await _emit(campaign_id, dev_id, "error", err_msg, host=ip)
            return

        image_name = os.path.basename(target_image)
        verify_ok, verify_err = await _verify_install_add_unpacked_files(
            conn, campaign_id, dev_id, ip, image_name, dest_path
        )
        if not verify_ok:
            err_msg = verify_err or "Install add verification failed"
            await db.update_upgrade_device(
                dev_id,
                transfer_status="failed",
                phase_detail="Prestage verification failed",
                error_message=err_msg,
            )
            await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=err_msg)
            await _emit(campaign_id, dev_id, "error", f"Prestage verification failed: {err_msg}", host=ip)
            return

        expected_version = _extract_version(image_name)
        detail = (
            f"Prestage artifacts verified for {expected_version}"
            if expected_version
            else "Prestage artifacts verified"
        )
        await db.update_upgrade_device(
            dev_id,
            transfer_status="completed",
            phase_detail=detail,
            error_message="",
            completed_at=datetime.now(UTC).isoformat(),
        )
        await _emit_device_status(campaign_id, dev_id, transfer_status="completed", error_message="")
        await _emit(campaign_id, dev_id, "success", "Prestage verification complete", host=ip)

    except Exception as e:
        err_msg = str(e)
        await db.update_upgrade_device(
            dev_id,
            transfer_status="failed",
            phase_detail="Prestage verification failed",
            error_message=err_msg,
        )
        await _emit_device_status(campaign_id, dev_id, transfer_status="failed", error_message=err_msg)
        await _emit(campaign_id, dev_id, "error", f"Prestage verification failed: {e}", host=ip)
    finally:
        try:
            await asyncio.to_thread(conn.disconnect)
        except Exception as exc:
            LOGGER.debug("Disconnect failed for %s: %s", ip, exc)


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
    except Exception as exc:
        LOGGER.debug("Stack check skipped on %s (not a stack?): %s", hostname, exc)

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
    return True, None  # Can't determine - proceed with warning


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

        # Always verify file exists on flash - SCP can throw exceptions
        # (timeout, socket close) even when the file transferred successfully
        try:
            exists = await asyncio.to_thread(_check_image_exists, conn, image_name, dest_path)
            if exists:
                return True, None
        except Exception as exc:
            LOGGER.debug("Flash check failed after transfer attempt %d of %s: %s", attempt, image_name, exc)

        if last_error and attempt >= max_attempts:
            return False, last_error

    return False, last_error or "File not found on flash after transfer"


async def _wait_for_down(ip, timeout=300, check_interval=10, campaign_id=None, dev_id=None):  # noqa: ASYNC109 - polling-loop deadline, not a wait-for budget
    """Wait for switch to become unreachable, confirming reboot has started."""
    start = time.time()
    while (time.time() - start) < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = await asyncio.to_thread(sock.connect_ex, (ip, 22))
            sock.close()
            if result != 0:
                return True  # Port closed - switch is down
        except Exception:
            return True  # Connection error - switch is down

        elapsed = int(time.time() - start)
        if campaign_id is not None and elapsed % 30 < check_interval:
            await _emit(campaign_id, dev_id, "dim",
                        f"Switch still up... ({elapsed}s elapsed)", host=ip)
        await asyncio.sleep(check_interval)

    return False  # Never went down within timeout


async def _wait_for_reboot(ip, credentials, options, max_wait, check_interval, campaign_id, dev_id, device_type="cisco_xe"):
    """Wait for switch to come back online after reboot."""
    start = time.time()

    while (time.time() - start) < max_wait:
        elapsed = int(time.time() - start)
        if elapsed % 60 < check_interval:
            await _emit(campaign_id, dev_id, "dim",
                        f"Waiting for reboot... ({elapsed}s elapsed)", host=ip)

        try:
            conn = await _connect_device(ip, credentials, options, retries=1,
                                         device_type=device_type)
            return conn
        except Exception:
            await asyncio.sleep(check_interval)

    return None


def _extract_version(image_name):
    """Extract version from image filename. e.g. cat9k_iosxe.17.15.05.SPA.bin -> 17.15.05"""
    match = re.search(r'(\d+\.\d+\.\d+)', image_name)
    return match.group(1) if match else None
