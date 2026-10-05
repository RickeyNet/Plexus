"""software.py -- Software version tracker and vulnerability alerts.

What runs what:

* :func:`refresh_software` gathers the software version of every device
  Plexus knows - inventory hosts (what SNMP or SSH stored on the host) and
  the devices of the latest topology collection of every Meraki
  organization, Cato account and AnyConnect FMC (firmware, Socket version,
  FTD software, FMC version) - stores them as the tracked set, records
  version changes, then matches every device against the advisories and
  opens, reopens or resolves alerts. It runs on a schedule, after each
  topology collection, and on **Refresh**.
* Advisories come from three places: entered by hand, imported as JSON, or
  synced from Cisco PSIRT (openVuln), which asks Cisco about every distinct
  version of every Cisco platform in the tracked set.
* A new or reopened alert at or above the configured severity floor is
  handed to the notification channels like a monitoring alert.

Permissions: the ``software`` feature to read, ``software.write`` to
refresh, acknowledge and manage advisories, admin for the settings and the
PSIRT credentials (stored encrypted, write-only).
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netcontrol.integrations.software.psirt import OS_TYPES, PsirtApiError, PsirtClient
from netcontrol.integrations.software.versions import (
    PLATFORMS,
    SEVERITIES,
    classify_host,
    find_advisory_matches,
    normalize_severity,
    severity_at_least,
    snapshot_devices,
    validate_version_spec,
    version_spread,
)
from netcontrol.routes import background_jobs, notification_channels
from netcontrol.routes.meraki_topology import latest_snapshots
from netcontrol.routes.shared import _audit, _corr_id, _get_session, supervise_task
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.software")

_require_admin = None
_JOB_KIND = "software-psirt-sync"
_refresh_lock = asyncio.Lock()
_psirt_running = False
# Injectable for tests (httpx.MockTransport).
_PSIRT_TRANSPORT: Any = None

DEFAULT_REFRESH_INTERVAL = 6 * 60 * 60
MIN_REFRESH_INTERVAL = 5 * 60
MAX_REFRESH_INTERVAL = 7 * 24 * 60 * 60
DEFAULT_PSIRT_INTERVAL = 24 * 60 * 60
MIN_PSIRT_INTERVAL = 60 * 60
INITIAL_REFRESH_DELAY = 120

SETTING_DEFAULTS = {
    "refresh_interval_seconds": str(DEFAULT_REFRESH_INTERVAL),
    "notify_enabled": "true",
    "notify_min_severity": "high",
    "psirt_enabled": "false",
    "psirt_client_id": "",
    "psirt_interval_seconds": str(DEFAULT_PSIRT_INTERVAL),
}
_PSIRT_PLATFORMS = {key: entry["psirt"] for key, entry in PLATFORMS.items() if entry.get("psirt")}
_PLATFORM_OF_OS_TYPE = {os_type: key for key, os_type in _PSIRT_PLATFORMS.items()}
_ADVISORY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,119}$")
# Alert severities the notification channels know.
_NOTIFY_SEVERITY = {"critical": "critical", "high": "critical", "medium": "warning", "low": "info", "info": "info"}
_MAX_IMPORT = 1000


def init_software(require_admin):
    global _require_admin
    _require_admin = require_admin


async def _require_admin_dep(request: Request):
    if _require_admin is None:
        raise HTTPException(status_code=500, detail="Software routes not initialised")
    return await _require_admin(request)


def _session_user(request: Request) -> str:
    return (_get_session(request) or {}).get("user", "")


def _true(value: Any) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _clamp(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except TypeError, ValueError:
        number = default
    return max(low, min(high, number))


# ── Models ───────────────────────────────────────────────────────────────────


class AdvisoryBody(BaseModel):
    advisory_id: str = Field(min_length=1, max_length=120)
    title: str = Field(default="", max_length=300)
    severity: str = Field(default="medium", max_length=20)
    cvss: float | None = Field(default=None, ge=0, le=10)
    platform: str = Field(default="", max_length=40)
    product_match: str = Field(default="", max_length=120)
    affected_versions: list[str] = Field(default_factory=list, max_length=200)
    fixed_versions: list[str] = Field(default_factory=list, max_length=200)
    cves: list[str] = Field(default_factory=list, max_length=200)
    url: str = Field(default="", max_length=500)
    published: str = Field(default="", max_length=40)
    summary: str = Field(default="", max_length=4000)
    enabled: bool = True


class AdvisoryImportBody(BaseModel):
    advisories: list[AdvisoryBody] = Field(max_length=_MAX_IMPORT)


class SettingsBody(BaseModel):
    refresh_interval_seconds: int | None = None
    notify_enabled: bool | None = None
    notify_min_severity: str | None = Field(default=None, max_length=20)
    psirt_enabled: bool | None = None
    psirt_client_id: str | None = Field(default=None, max_length=200)
    # Write-only: omitted keeps the stored secret, "" clears it.
    psirt_client_secret: str | None = Field(default=None, max_length=400)
    psirt_interval_seconds: int | None = None


def _clean_advisory(body: AdvisoryBody) -> dict[str, Any]:
    advisory_id = body.advisory_id.strip()
    if not _ADVISORY_ID_RE.match(advisory_id):
        raise HTTPException(
            status_code=400, detail="advisory_id may only contain letters, digits, '.', '_', ':' and '-'"
        )
    platform = body.platform.strip().lower()
    if platform and platform not in PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unknown platform {platform!r}")
    specs = [spec.strip() for spec in body.affected_versions if spec and spec.strip()]
    if not specs:
        raise HTTPException(status_code=400, detail="At least one affected version is required")
    for spec in specs:
        problem = validate_version_spec(spec)
        if problem:
            raise HTTPException(status_code=400, detail=f"Affected version {spec!r}: {problem}")
    url = body.url.strip()
    if url and not url.lower().startswith(("https://", "http://")):
        raise HTTPException(status_code=400, detail="url must start with https:// or http://")
    return {
        "advisory_id": advisory_id,
        "source": "manual",
        "title": body.title.strip() or advisory_id,
        "severity": normalize_severity(body.severity),
        "cvss": body.cvss,
        "platform": platform,
        "product_match": body.product_match.strip(),
        "affected_versions": specs,
        "fixed_versions": [v.strip() for v in body.fixed_versions if v and v.strip()],
        "cves": [c.strip().upper() for c in body.cves if c and c.strip()],
        "url": url,
        "published": body.published.strip(),
        "summary": body.summary.strip(),
        "enabled": body.enabled,
    }


# ── Settings ─────────────────────────────────────────────────────────────────


async def _settings() -> dict[str, str]:
    raw = {**SETTING_DEFAULTS, **await db.get_software_settings()}
    return raw


def _public_settings(raw: dict[str, str]) -> dict[str, Any]:
    return {
        "refresh_interval_seconds": _clamp(
            raw.get("refresh_interval_seconds"), DEFAULT_REFRESH_INTERVAL, MIN_REFRESH_INTERVAL, MAX_REFRESH_INTERVAL
        ),
        "notify_enabled": _true(raw.get("notify_enabled")),
        "notify_min_severity": normalize_severity(raw.get("notify_min_severity"), "high"),
        "psirt_enabled": _true(raw.get("psirt_enabled")),
        "psirt_client_id": raw.get("psirt_client_id") or "",
        "has_psirt_secret": bool(raw.get("psirt_client_secret_enc")),
        "psirt_interval_seconds": _clamp(
            raw.get("psirt_interval_seconds"), DEFAULT_PSIRT_INTERVAL, MIN_PSIRT_INTERVAL, MAX_REFRESH_INTERVAL * 4
        ),
        "psirt_last_sync_at": raw.get("psirt_last_sync_at") or "",
        "psirt_last_sync_status": raw.get("psirt_last_sync_status") or "",
        "psirt_last_sync_message": raw.get("psirt_last_sync_message") or "",
        "psirt_platforms": sorted(_PSIRT_PLATFORMS),
        "last_refresh_at": raw.get("last_refresh_at") or "",
    }


# ── Collection ───────────────────────────────────────────────────────────────


async def collect_software_entries() -> list[dict[str, Any]]:
    """The tracked set: one entry per device with a known version.

    A topology device that is also an inventory host is listed once, under
    the collection (the controller knows the exact firmware) with the host
    attached; the host's own row is skipped.
    """
    entries: list[dict[str, Any]] = []
    claimed_hosts: set[int] = set()
    for org_ref, snapshot in await latest_snapshots():
        provider = str(snapshot.get("provider") or "meraki")
        org_name = str((snapshot.get("org") or {}).get("name") or "")
        for device in snapshot_devices(snapshot, provider):
            host_id = device.get("host_id")
            if host_id:
                claimed_hosts.add(int(host_id))
            entries.append(
                {
                    "device_key": f"{provider}:{org_ref}:{device['serial'] or device['node_id']}",
                    "source": provider,
                    "org_ref": org_ref,
                    "host_id": int(host_id) if host_id else None,
                    "name": device["name"],
                    "model": device["model"],
                    "serial": device["serial"],
                    "site": device["site"],
                    "org_name": org_name,
                    "platform": device["platform"],
                    "version": device["version"],
                    "raw_version": device["raw_version"],
                }
            )
    for host in await db.list_hosts_for_software():
        if host["id"] in claimed_hosts:
            continue
        platform, version = classify_host(host.get("device_type"), host.get("model"), host.get("software_version"))
        if not version:
            continue
        entries.append(
            {
                "device_key": f"host:{host['id']}",
                "source": "inventory",
                "org_ref": 0,
                "host_id": host["id"],
                "name": host.get("hostname") or host.get("ip_address") or f"host {host['id']}",
                "model": host.get("model") or "",
                "serial": host.get("serial_number") or "",
                "site": host.get("group_name") or "",
                "org_name": "",
                "platform": platform,
                "version": version,
                "raw_version": host.get("software_version") or "",
            }
        )
    return entries


async def _notify(alerts: list[dict], raw_settings: dict[str, str]) -> int:
    """Hand new alerts to the notification channels. Never raises."""
    if not alerts or not _true(raw_settings.get("notify_enabled")):
        return 0
    floor = normalize_severity(raw_settings.get("notify_min_severity"), "high")
    devices = {d["device_key"]: d for d in await db.list_software_versions()}
    advisories = {a["advisory_id"]: a for a in await db.list_software_advisories()}
    sent = 0
    for alert in alerts:
        if not severity_at_least(alert["severity"], floor):
            continue
        device = devices.get(alert["device_key"]) or {}
        advisory = advisories.get(alert["advisory_id"]) or {}
        label = PLATFORMS.get(device.get("platform") or "", PLATFORMS["other"])["label"]
        fixed = advisory.get("fixed_versions") or []
        message = (
            f"{device.get('name') or alert['device_key']} ({device.get('model') or 'unknown model'}) runs "
            f"{label} {device.get('version') or '?'}, affected by {alert['advisory_id']}: "
            f"{advisory.get('title') or alert['advisory_id']} [{alert['severity']}]"
        )
        if fixed:
            message += f" - fixed in {', '.join(fixed[:3])}"
        event = {
            "alert_id": f"software-{alert['id']}",
            "host_id": device.get("host_id"),
            "hostname": device.get("name") or "",
            "poll_id": None,
            "rule_id": None,
            "alert_type": "software_vulnerability",
            "metric": f"software: {alert['advisory_id']}",
            "message": message,
            "severity": _NOTIFY_SEVERITY.get(alert["severity"], "warning"),
            "value": advisory.get("cvss"),
            "threshold": None,
            "dedup_key": f"software:{alert['device_key']}:{alert['advisory_id']}",
            "channel_ids": "",
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        try:
            await notification_channels.on_alert_created(event)
            sent += 1
        except Exception as exc:  # noqa: BLE001 - delivery must never break the refresh
            LOGGER.warning("software: notification failed for alert %s: %s", alert["id"], type(exc).__name__)
    return sent


async def evaluate_software_alerts(*, notify: bool = True) -> dict[str, Any]:
    """Match every tracked device against the enabled advisories and bring
    the alerts up to date."""
    devices = await db.list_software_versions()
    advisories = await db.list_software_advisories(enabled_only=True)
    matches = find_advisory_matches(devices, advisories)
    result = await db.sync_software_alerts(matches)
    notified = 0
    if notify and (result["new"] or result["reopened"]):
        notified = await _notify([*result["new"], *result["reopened"]], await _settings())
    return {
        "open": result["open"],
        "new": len(result["new"]),
        "reopened": len(result["reopened"]),
        "resolved": result["resolved"],
        "notified": notified,
    }


async def refresh_software(*, notify: bool = True) -> dict[str, Any]:
    """Collect, store, match, alert. One at a time."""
    async with _refresh_lock:
        entries = await collect_software_entries()
        result = await db.replace_software_versions(entries)
        result["alerts"] = await evaluate_software_alerts(notify=notify)
        await db.set_software_settings(
            {
                "last_refresh_at": result["refreshed_at"],
                "last_refresh_summary": json.dumps(
                    {key: result[key] for key in ("devices", "added", "changed", "removed")}
                ),
            }
        )
        return result


async def refresh_after_collection() -> None:
    """Called when a topology collection was stored. Never raises."""
    try:
        result = await refresh_software(notify=True)
        LOGGER.info(
            "software: refreshed after collection - %d devices, %d changed, %d open alerts",
            result["devices"],
            result["changed"],
            result["alerts"]["open"],
        )
    except Exception as exc:  # noqa: BLE001 - the collection is already stored
        LOGGER.warning("software: refresh after collection failed: %s", type(exc).__name__, exc_info=True)


# ── Cisco PSIRT sync ─────────────────────────────────────────────────────────


def _psirt_error_message(exc: PsirtApiError) -> str:
    # ``detail`` is the message Cisco answered with.
    detail = f": {exc.detail}" if exc.detail else ""
    if exc.status_code in (401, 403):
        return f"Cisco PSIRT rejected the client ID or secret (HTTP {exc.status_code}){detail}"
    if exc.status_code == 0:
        return f"{exc}{detail}"
    return f"Cisco PSIRT API error (HTTP {exc.status_code}){detail}"


def _psirt_client(client_id: str, secret: str) -> PsirtClient:
    return PsirtClient(client_id, secret, transport=_PSIRT_TRANSPORT)


async def _psirt_credentials() -> tuple[str, str]:
    raw = await db.get_software_settings()
    client_id = (raw.get("psirt_client_id") or "").strip()
    secret_enc = raw.get("psirt_client_secret_enc") or ""
    if not client_id or not secret_enc:
        raise HTTPException(status_code=400, detail="Store a Cisco PSIRT client ID and secret first")
    from routes.crypto import decrypt

    return client_id, decrypt(secret_enc)


def _psirt_targets(devices: list[dict]) -> list[tuple[str, str]]:
    """Distinct ``(os_type, version)`` pairs Cisco can be asked about."""
    targets = {
        (_PSIRT_PLATFORMS[d["platform"]], d["version"])
        for d in devices
        if d.get("platform") in _PSIRT_PLATFORMS and d.get("version")
    }
    return sorted(targets)


async def run_psirt_sync(job_id: str, user: str) -> dict[str, Any]:
    """Ask Cisco PSIRT about every tracked Cisco version and store the
    advisories it answers with, then re-evaluate the alerts."""
    global _psirt_running
    _psirt_running = True
    started = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    errors: list[str] = []
    found = 0
    targets: list[tuple[str, str]] = []
    status = "completed"
    try:
        client_id, secret = await _psirt_credentials()
        targets = _psirt_targets(await db.list_software_versions())
        background_jobs.update_progress(job_id, phase="querying", done=0, total=len(targets))
        async with _psirt_client(client_id, secret) as client:
            # A refused login fails the whole sync; a failed query only skips its version.
            await client.authenticate()
            for index, (os_type, version) in enumerate(targets):
                background_jobs.update_progress(job_id, done=index, current=f"{os_type} {version}")
                try:
                    advisories = await client.advisories_by_version(os_type, version)
                except PsirtApiError as exc:
                    errors.append(f"{os_type} {version}: {_psirt_error_message(exc)}")
                    if exc.status_code in (401, 403):
                        break
                    continue
                platform = _PLATFORM_OF_OS_TYPE[os_type]
                for advisory in advisories:
                    existing = await db.get_software_advisory(advisory["advisory_id"])
                    if existing and existing.get("platform") not in ("", platform):
                        platform = ""  # affects more than one platform: match on version only
                    await db.upsert_software_advisory(
                        {**advisory, "source": "cisco-psirt", "platform": platform, "affected_versions": [version]},
                        merge_lists=True,
                    )
                    found += 1
        background_jobs.update_progress(job_id, phase="matching", done=len(targets))
        alerts = await evaluate_software_alerts(notify=True)
        if errors:
            status = "partial"
        message = f"{len(targets)} version(s) checked, {found} advisory match(es)"
        if errors:
            message += f", {len(errors)} query failure(s)"
        result = {
            "versions_checked": len(targets),
            "advisories": found,
            "errors": errors[:20],
            "alerts": alerts,
            "message": message,
        }
        background_jobs.finish_job(job_id, status, result=result)
    except HTTPException as exc:
        status, message = "failed", str(exc.detail)
        result = {"message": message, "errors": [message]}
        background_jobs.finish_job(job_id, "failed", error=message)
    except PsirtApiError as exc:
        status, message = "failed", _psirt_error_message(exc)
        result = {"message": message, "errors": [message]}
        background_jobs.finish_job(job_id, "failed", error=message)
    except Exception as exc:  # noqa: BLE001 - the job must reach a terminal state
        status, message = "failed", "Cisco PSIRT sync failed; see the server log for details"
        result = {"message": message, "errors": [message]}
        LOGGER.exception("software: PSIRT sync crashed: %s", type(exc).__name__)
        background_jobs.finish_job(job_id, "failed", error=message)
    finally:
        _psirt_running = False
    await db.set_software_settings(
        {"psirt_last_sync_at": started, "psirt_last_sync_status": status, "psirt_last_sync_message": message}
    )
    await _audit("software", "psirt_sync", user=user, detail=f"status={status} {message}")
    return result


def _start_psirt_sync(user: str) -> dict:
    if _psirt_running:
        raise HTTPException(status_code=409, detail="A Cisco PSIRT sync is already running")
    job = background_jobs.create_job(_JOB_KIND, {"phase": "starting"})
    supervise_task(asyncio.create_task(run_psirt_sync(job["job_id"], user)), "software-psirt-sync")
    return job


# ── Background loop ──────────────────────────────────────────────────────────


async def _software_refresh_loop() -> None:
    """Refresh the tracked set on the configured interval, and sync Cisco
    PSIRT when enabled and due."""
    await asyncio.sleep(INITIAL_REFRESH_DELAY)
    while True:
        interval = DEFAULT_REFRESH_INTERVAL
        try:
            raw = await _settings()
            interval = _clamp(
                raw.get("refresh_interval_seconds"),
                DEFAULT_REFRESH_INTERVAL,
                MIN_REFRESH_INTERVAL,
                MAX_REFRESH_INTERVAL,
            )
            await refresh_software(notify=True)
            if _true(raw.get("psirt_enabled")) and raw.get("psirt_client_id") and not _psirt_running:
                due_after = _clamp(
                    raw.get("psirt_interval_seconds"),
                    DEFAULT_PSIRT_INTERVAL,
                    MIN_PSIRT_INTERVAL,
                    MAX_REFRESH_INTERVAL * 4,
                )
                last = raw.get("psirt_last_sync_at") or ""
                try:
                    last_at = datetime.strptime(last, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC) if last else None
                except ValueError:
                    last_at = None
                if last_at is None or (datetime.now(UTC) - last_at).total_seconds() >= due_after:
                    job = background_jobs.create_job(_JOB_KIND, {"phase": "starting", "scheduled": True})
                    await run_psirt_sync(job["job_id"], "scheduler")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - the loop must survive
            LOGGER.warning("software: scheduled refresh failed: %s", type(exc).__name__, exc_info=True)
        await asyncio.sleep(interval)


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/api/software/overview")
async def software_overview_api(
    platform: str = Query(default="", max_length=40),
    search: str = Query(default="", max_length=200),
    source: str = Query(default="", max_length=20),
):
    raw = await _settings()
    if not raw.get("last_refresh_at"):
        # First visit: build the tracked set from what is already stored.
        await refresh_software(notify=False)
        raw = await _settings()
    every = await db.list_software_versions()
    filtered = (
        every
        if not (platform or search or source)
        else await db.list_software_versions(platform=platform, source=source, search=search)
    )
    spread = version_spread(every)
    newest = {entry["platform"]: entry["newest_version"] for entry in spread}
    alerts_by_device = await db.count_open_alerts_by_device()
    for device in filtered:
        counts = alerts_by_device.get(device["device_key"]) or {}
        device["behind_newest"] = bool(device["version"]) and device["version"] != newest.get(device["platform"])
        device["platform_label"] = PLATFORMS.get(device["platform"], PLATFORMS["other"])["label"]
        device["alert_count"] = counts.get("count", 0)
        device["unacknowledged_alerts"] = counts.get("unacknowledged", 0)
        device["worst_severity"] = counts.get("worst", "")
    alert_summary = await db.software_alert_summary()
    advisories = await db.list_software_advisories()
    sources: dict[str, int] = {}
    for device in every:
        sources[device["source"]] = sources.get(device["source"], 0) + 1
    by_severity = alert_summary["by_severity"]
    return {
        "summary": {
            "devices": len(every),
            "platforms": len(spread),
            "versions": sum(entry["version_count"] for entry in spread),
            "behind_newest": sum(entry["behind_newest"] for entry in spread),
            "open_alerts": alert_summary["open"],
            "unacknowledged_alerts": alert_summary["unacknowledged"],
            "critical_alerts": by_severity.get("critical", 0) + by_severity.get("high", 0),
            "alerts_by_severity": by_severity,
            "advisories": len(advisories),
            "enabled_advisories": sum(1 for a in advisories if a["enabled"]),
            "sources": sources,
            "last_refresh_at": raw.get("last_refresh_at") or "",
        },
        "platforms": spread,
        "platform_catalog": [
            {"key": key, "label": entry["label"], "psirt": bool(entry.get("psirt"))} for key, entry in PLATFORMS.items()
        ],
        "severities": list(SEVERITIES),
        "devices": filtered,
        "alerts": await db.list_software_alerts(include_resolved=False),
        "advisories": advisories,
        "changes": await db.list_recent_version_changes(50),
        "settings": _public_settings(raw),
    }


@router.post("/api/software/refresh")
async def software_refresh_api(request: Request):
    result = await refresh_software(notify=True)
    await _audit(
        "software",
        "refresh",
        user=_session_user(request),
        detail=f"devices={result['devices']} changed={result['changed']} open_alerts={result['alerts']['open']}",
        correlation_id=_corr_id(request),
    )
    return result


@router.get("/api/software/history")
async def software_history_api(
    device_key: str = Query(min_length=1, max_length=300), limit: int = Query(default=100, ge=1, le=1000)
):
    return {"device_key": device_key, "history": await db.get_software_history(device_key, limit=limit)}


@router.get("/api/software/advisories")
async def list_advisories_api():
    return {"advisories": await db.list_software_advisories()}


@router.post("/api/software/advisories", status_code=201)
async def create_advisory_api(body: AdvisoryBody, request: Request):
    advisory = _clean_advisory(body)
    existing = await db.get_software_advisory(advisory["advisory_id"])
    if existing:
        raise HTTPException(status_code=409, detail="An advisory with this ID already exists")
    stored = await db.upsert_software_advisory(advisory)
    alerts = await evaluate_software_alerts(notify=True)
    await _audit(
        "software",
        "advisory_create",
        user=_session_user(request),
        detail=f"advisory={advisory['advisory_id']} severity={advisory['severity']}",
        correlation_id=_corr_id(request),
    )
    return {"advisory": stored, "alerts": alerts}


@router.put("/api/software/advisories/{advisory_id}")
async def update_advisory_api(advisory_id: str, body: AdvisoryBody, request: Request):
    existing = await db.get_software_advisory(advisory_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Advisory not found")
    advisory = _clean_advisory(body)
    if advisory["advisory_id"] != advisory_id:
        raise HTTPException(status_code=400, detail="advisory_id cannot be changed")
    advisory["source"] = existing.get("source") or "manual"
    stored = await db.upsert_software_advisory(advisory)
    alerts = await evaluate_software_alerts(notify=True)
    await _audit(
        "software",
        "advisory_update",
        user=_session_user(request),
        detail=f"advisory={advisory_id}",
        correlation_id=_corr_id(request),
    )
    return {"advisory": stored, "alerts": alerts}


@router.delete("/api/software/advisories/{advisory_id}")
async def delete_advisory_api(advisory_id: str, request: Request):
    if not await db.delete_software_advisory(advisory_id):
        raise HTTPException(status_code=404, detail="Advisory not found")
    await _audit(
        "software",
        "advisory_delete",
        user=_session_user(request),
        detail=f"advisory={advisory_id}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/software/advisories/import")
async def import_advisories_api(body: AdvisoryImportBody, request: Request):
    if not body.advisories:
        raise HTTPException(status_code=400, detail="No advisories to import")
    cleaned = [_clean_advisory(item) for item in body.advisories]
    for advisory in cleaned:
        advisory["source"] = "import"
        await db.upsert_software_advisory(advisory)
    alerts = await evaluate_software_alerts(notify=True)
    await _audit(
        "software",
        "advisory_import",
        user=_session_user(request),
        detail=f"count={len(cleaned)}",
        correlation_id=_corr_id(request),
    )
    return {"imported": len(cleaned), "alerts": alerts}


@router.get("/api/software/alerts")
async def list_alerts_api(
    include_resolved: bool = Query(default=False), limit: int = Query(default=500, ge=1, le=5000)
):
    return {"alerts": await db.list_software_alerts(include_resolved=include_resolved, limit=limit)}


@router.post("/api/software/alerts/{alert_id}/acknowledge")
async def acknowledge_alert_api(alert_id: int, request: Request):
    user = _session_user(request)
    if not await db.acknowledge_software_alert(alert_id, user):
        raise HTTPException(status_code=404, detail="Open alert not found")
    await _audit(
        "software", "alert_acknowledge", user=user, detail=f"alert_id={alert_id}", correlation_id=_corr_id(request)
    )
    return {"ok": True}


@router.get("/api/software/settings", dependencies=[Depends(_require_admin_dep)])
async def get_settings_api():
    return {"settings": _public_settings(await _settings())}


@router.put("/api/software/settings", dependencies=[Depends(_require_admin_dep)])
async def update_settings_api(body: SettingsBody, request: Request):
    values: dict[str, str] = {}
    if body.refresh_interval_seconds is not None:
        if not MIN_REFRESH_INTERVAL <= body.refresh_interval_seconds <= MAX_REFRESH_INTERVAL:
            raise HTTPException(
                status_code=400,
                detail=f"refresh_interval_seconds must be between {MIN_REFRESH_INTERVAL} and {MAX_REFRESH_INTERVAL}",
            )
        values["refresh_interval_seconds"] = str(body.refresh_interval_seconds)
    if body.notify_enabled is not None:
        values["notify_enabled"] = "true" if body.notify_enabled else "false"
    if body.notify_min_severity is not None:
        severity = body.notify_min_severity.strip().lower()
        if severity not in SEVERITIES:
            raise HTTPException(status_code=400, detail=f"notify_min_severity must be one of {', '.join(SEVERITIES)}")
        values["notify_min_severity"] = severity
    if body.psirt_enabled is not None:
        values["psirt_enabled"] = "true" if body.psirt_enabled else "false"
    if body.psirt_client_id is not None:
        values["psirt_client_id"] = body.psirt_client_id.strip()
    if body.psirt_client_secret is not None:
        if body.psirt_client_secret:
            from routes.crypto import encrypt

            values["psirt_client_secret_enc"] = encrypt(body.psirt_client_secret)
        else:
            values["psirt_client_secret_enc"] = ""
    if body.psirt_interval_seconds is not None:
        if not MIN_PSIRT_INTERVAL <= body.psirt_interval_seconds <= MAX_REFRESH_INTERVAL * 4:
            raise HTTPException(
                status_code=400,
                detail=f"psirt_interval_seconds must be between {MIN_PSIRT_INTERVAL} and {MAX_REFRESH_INTERVAL * 4}",
            )
        values["psirt_interval_seconds"] = str(body.psirt_interval_seconds)
    await db.set_software_settings(values)
    changed = sorted(key.replace("_enc", "") for key in values)
    await _audit(
        "software",
        "settings_update",
        user=_session_user(request),
        detail=f"fields={','.join(changed)}",
        correlation_id=_corr_id(request),
    )
    return {"settings": _public_settings(await _settings())}


@router.post("/api/software/psirt/test", dependencies=[Depends(_require_admin_dep)])
async def test_psirt_api():
    client_id, secret = await _psirt_credentials()
    try:
        async with _psirt_client(client_id, secret) as client:
            await client.authenticate()
    except PsirtApiError as exc:
        raise HTTPException(status_code=400, detail=_psirt_error_message(exc)) from exc
    return {"ok": True, "message": "Signed in to Cisco PSIRT", "os_types": list(OS_TYPES)}


@router.post("/api/software/psirt/sync", status_code=202, dependencies=[Depends(_require_admin_dep)])
async def start_psirt_sync_api(request: Request):
    await _psirt_credentials()
    job = _start_psirt_sync(_session_user(request))
    return {"job_id": job["job_id"], "status": "running"}


@router.get("/api/software/psirt/jobs/{job_id}")
async def get_psirt_job_api(job_id: str):
    job = background_jobs.get_job(job_id, kind=_JOB_KIND)
    if job is None:
        raise HTTPException(status_code=404, detail="Sync job not found (it may have expired)")
    return job
