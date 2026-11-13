"""Near-real-time Meraki alerts: a short poll and an optional webhook receiver.

Two ingest paths share one normaliser
(``netcontrol.integrations.meraki.alerts``) and one pipeline (:func:`ingest`):

  - **Poll** (outbound only, works in every deployment). ``_meraki_alert_
    poll_loop`` in ``netcontrol.app`` calls :func:`run_alert_poll_cycle`
    every ``interval_seconds`` (default 60, at least 30). Each enabled
    Meraki source costs one paginated ``GET /organizations/{organizationId}/
    assurance/alerts`` (the active alerts). An alert the poll reported
    before and no longer does is resolved. A source that fails (401, 403,
    404, timeout) is backed off exponentially and never stops the others.
  - **Webhook** (``POST /api/webhooks/meraki``, off by default). Answers
    404 until an administrator sets a shared secret and turns it on. No
    session, no CSRF (``netcontrol.app.WEBHOOK_PATHS``); the body is size
    bounded, must be JSON, and its ``sharedSecret`` is compared in constant
    time. The work runs after the response, which Meraki wants in under
    two seconds.

:func:`ingest` stores the events (``routes.db.meraki_alerts``) and raises
each new warning or critical alert once, server-side, like the Cato egress
check and the topology availability tracker: on the inventory host the
Meraki device matches (``create_monitoring_alert``, alert type
``meraki_alert``), otherwise straight to the notification channels. A
device-down alert whose device the topology availability tracker has already
alerted on is recorded without a second notification, and the tracker skips
a device a Meraki alert already covers. When an alert resolves, its
monitoring alert is acknowledged as ``auto-resolved``. Best-effort
throughout: a failure is logged (exception type only) and never breaks the
loop or the webhook response.

Plexus stays a read-only observer: the receiver is registered by hand in the
Meraki dashboard, never through the API (see ``docs/meraki-alerts.md``).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import routes.database as db
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import netcontrol.routes.state as state
from netcontrol.integrations.meraki import alerts as meraki_alerts
from netcontrol.integrations.meraki.client import DEFAULT_BASE_URL, MerakiApiError, MerakiClient
from netcontrol.integrations.meraki.enrich import load_inventory_index
from netcontrol.integrations.meraki.normalize import InventoryIndex
from netcontrol.routes import notification_channels
from netcontrol.routes.meraki_topology import PROVIDER_MERAKI, _is_demo, _require_admin_dep, _session_user
from netcontrol.routes.shared import _audit, _corr_id
from netcontrol.routes.topology_availability import _mute_index, finish_removal
from netcontrol.telemetry import configure_logging

router = APIRouter()
admin_router = APIRouter()
webhook_router = APIRouter()
LOGGER = configure_logging("plexus.meraki_alerts")

ALERT_TYPE = "meraki_alert"
WEBHOOK_PATH = "/api/webhooks/meraki"
STATUS_SETTING = "meraki_alerts_status"
CONFIG_SETTING = "meraki_alerts"
# Meraki webhook bodies are a few KB; anything this large is not one.
MAX_WEBHOOK_BODY_BYTES = 256 * 1024
_SECRET_MIN, _SECRET_MAX = 16, 256
_POLL_CONCURRENCY = 4
_POLL_TIMEOUT_SECONDS = 20.0
_PER_PAGE = 300
# Serials per confirmation call (``GET /organizations/{organizationId}/devices``).
_CONFIRM_CHUNK = 100
# Back-off caps: a key without access (401/403) or an org the key cannot
# see (404) is retried at most hourly, anything else every ten minutes.
_MAX_BACKOFF_AUTH = 3600
_MAX_BACKOFF_OTHER = 600
_ORG_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_FMT = "%Y-%m-%d %H:%M:%S"

# Injectable for tests (``httpx.MockTransport``).
_TRANSPORT: httpx.AsyncBaseTransport | None = None
# One poll cycle at a time; one writer of the alert rows at a time.
_POLL_LOCK = asyncio.Lock()
_APPLY_LOCK = asyncio.Lock()
# org_ref -> {"failures", "next_at" (monotonic)}
_BACKOFF: dict[int, dict[str, float]] = {}

STATUS_DEFAULTS: dict[str, Any] = {
    "last_poll_at": "",
    "last_poll_ok": None,
    "last_poll_error": "",
    "sources": {},
    "last_webhook_at": "",
    "last_test_at": "",
    "last_webhook_error": "",
    "webhooks_accepted": 0,
    "webhooks_rejected": 0,
    "unknown_org_events": 0,
}
_STATUS: dict[str, Any] = json.loads(json.dumps(STATUS_DEFAULTS))


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def dedup_key(alert_key: str) -> str:
    return f"meraki_alert:{alert_key}"


# ── Settings and status ──────────────────────────────────────────────────────


def _config() -> dict:
    return state.MERAKI_ALERTS_CONFIG


def webhook_secret() -> str:
    """The decrypted shared secret, or ``""``. Never logged or returned."""
    stored = str(_config().get("webhook_secret_enc") or "")
    if not stored:
        return ""
    from routes.crypto import decrypt

    try:
        return decrypt(stored) or ""
    except Exception:  # noqa: BLE001 - a key change makes the secret unreadable
        LOGGER.warning("meraki alerts: the stored webhook secret could not be decrypted")
        return ""


def webhook_active() -> bool:
    """The receiver answers only when it is on and has a secret."""
    cfg = _config()
    return bool(cfg.get("webhook_enabled")) and bool(cfg.get("webhook_secret_enc"))


async def load_status() -> None:
    """Load the persisted status (last poll, last webhook) at startup."""
    stored = await db.get_auth_setting(STATUS_SETTING)
    _STATUS.clear()
    _STATUS.update(json.loads(json.dumps(STATUS_DEFAULTS)))
    if isinstance(stored, dict):
        for key, default in STATUS_DEFAULTS.items():
            value = stored.get(key, default)
            if isinstance(default, int) and not isinstance(default, bool):
                try:
                    value = int(value)
                except TypeError, ValueError:
                    value = default
            _STATUS[key] = value if value is not None or default is None else default
        if not isinstance(_STATUS.get("sources"), dict):
            _STATUS["sources"] = {}


async def _save_status() -> None:
    try:
        await db.set_auth_setting(STATUS_SETTING, dict(_STATUS))
    except Exception as exc:  # noqa: BLE001 - status is informational
        LOGGER.debug("meraki alerts: status not saved: %s", type(exc).__name__)


async def meraki_sources() -> list[dict]:
    """The Meraki organizations that can be polled or receive webhooks:
    provider ``meraki``, an organization ID, not a demo entry."""
    return [
        org
        for org in await db.list_meraki_orgs()
        if org.get("provider") == PROVIDER_MERAKI and str(org.get("org_id") or "").strip() and not _is_demo(org)
    ]


def _excluded() -> set[int]:
    return {int(ref) for ref in _config().get("excluded_sources") or []}


# ── Pipeline ─────────────────────────────────────────────────────────────────


def _message(row: dict) -> str:
    where = f"Meraki {row.get('org_name')}" if row.get("org_name") else "Meraki"
    device = row.get("device_name") or row.get("device_serial") or ""
    text = f"{where}: {row.get('title') or row.get('alert_type')}"
    if device:
        text += f" on {device}"
    if row.get("network_name"):
        text += f" ({row['network_name']})"
    return text


async def _topology_device(org_ref: int, serial: str) -> dict | None:
    """The topology availability row of a Meraki device, if tracked."""
    if not serial:
        return None
    rows = await db.list_topology_entity_states(PROVIDER_MERAKI, int(org_ref), "device", entity_id=f"d:{serial}")
    return rows[0] if rows else None


def _muted(row: dict, index: db.TopologyMuteIndex) -> dict | None:
    """The topology mute covering an alert row: a mute of its device
    (entity ``d:<serial>``, which a mute of the device's site covers too) or
    of its network (a site mute named like ``network_name``)."""
    org_ref = int(row.get("org_ref") or 0)
    serial = str(row.get("device_serial") or "")
    network = str(row.get("network_name") or "")
    if serial:
        device = {
            "provider": PROVIDER_MERAKI,
            "org_ref": org_ref,
            "entity_type": "device",
            "entity_id": f"d:{serial}",
            "site": network,
            "meta": {},
        }
        hit = index.match(device)
        if hit:
            return hit
    return index.match_site(PROVIDER_MERAKI, org_ref, network)


async def _host_for(row: dict, index: InventoryIndex, tracked: dict | None) -> dict | None:
    """The inventory host of the alert's device: by serial or name (the
    matching the topology build does), else the host the topology map
    matched it to (which can also match by management IP)."""
    serial = str(row.get("device_serial") or "")
    name = str(row.get("device_name") or "")
    if serial or name:
        host = index.match(serial=serial, name=name)
        if host:
            return host
    host_id = int((tracked or {}).get("host_id") or 0)
    if host_id:
        return await db.get_host(host_id)
    return None


async def _raise_alert(row: dict, index: InventoryIndex) -> tuple[str, int | None]:
    """Raise one alert. Returns how (``monitoring``, ``notification`` or
    ``topology``) and the host it was raised on."""
    key = str(row["alert_key"])
    severity = str(row.get("severity") or "warning")
    serial = str(row.get("device_serial") or "")
    tracked = await _topology_device(int(row.get("org_ref") or 0), serial)
    if (
        row.get("condition") == meraki_alerts.DEVICE_DOWN
        and tracked
        and tracked.get("state") == "down"
        and tracked.get("alert_state")
    ):
        # The hourly topology availability tracker already notified it.
        return "topology", None
    host = await _host_for(row, index, tracked)
    message = _message(row)
    metric = f"meraki {row.get('category') or 'alert'}"
    name = str(row.get("device_name") or serial or row.get("network_name") or row.get("org_name") or "")
    if host:
        await db.create_monitoring_alert(
            host_id=int(host["id"]),
            poll_id=None,
            alert_type=ALERT_TYPE,
            metric=metric,
            message=message,
            severity=severity,
            dedup_key=dedup_key(key),
            hostname=str(host.get("hostname") or name),
        )
        return "monitoring", int(host["id"])
    await notification_channels.on_alert_created(
        {
            "alert_id": dedup_key(key),
            "host_id": None,
            "hostname": name,
            "poll_id": None,
            "rule_id": None,
            "alert_type": ALERT_TYPE,
            "metric": metric,
            "message": message,
            "severity": severity,
            "value": None,
            "threshold": None,
            "dedup_key": dedup_key(key),
            "channel_ids": "",
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    return "notification", None


async def _clear(rows: list[dict]) -> int:
    cleared = 0
    for row in rows:
        try:
            cleared += await db.resolve_monitoring_alerts(dedup_key(str(row["alert_key"])))
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("meraki alerts: clearing an alert failed: %s", type(exc).__name__)
    return cleared


async def ingest(events: list[dict], *, poll_scope: tuple[int, set[str]] | None = None) -> dict[str, Any]:
    """Store normalised events from either path and raise / clear alerts.

    ``poll_scope`` (source id, keys of its active alerts) comes with a
    successful poll: that source's alerts the poll reported before and not
    now are resolved."""
    async with _APPLY_LOCK:
        result = await db.apply_meraki_alert_events(events)
        clears = list(result["clears"])
        vanished: list[str] = []
        if poll_scope is not None:
            missing = await db.resolve_missing_meraki_alerts(poll_scope[0], poll_scope[1])
            result["resolved"] += len(missing)
            clears.extend(r for r in missing if r.get("alert_state"))
            vanished = sorted({str(r["device_serial"]) for r in missing if r.get("device_serial")})
        raised = 0
        index: InventoryIndex | None = None
        mutes = await _mute_index(PROVIDER_MERAKI) if result["alerts"] else None
        for row in result["alerts"]:
            try:
                if mutes and _muted(row, mutes):
                    # Stored and counted as raised, so unmuting does not notify it.
                    await db.set_meraki_alert_raised(
                        str(row["alert_key"]), str(row.get("severity") or ""), "muted", row.get("host_id")
                    )
                    continue
                if index is None:
                    index = await load_inventory_index()
                via, host_id = await _raise_alert(row, index)
                await db.set_meraki_alert_raised(str(row["alert_key"]), str(row.get("severity") or ""), via, host_id)
                raised += 1
            except Exception as exc:  # noqa: BLE001 - delivery must never break ingestion
                LOGGER.warning("meraki alerts: raising an alert failed: %s", type(exc).__name__)
        cleared = await _clear(clears)
    return {
        "new": result["new"],
        "updated": result["updated"],
        "reopened": result["reopened"],
        "resolved": result["resolved"],
        "alerted": raised,
        "alerts_cleared": cleared,
        "vanished": vanished,
    }


async def expire_webhook_alerts() -> int:
    """Close webhook-only alerts that never got a recovery event."""
    async with _APPLY_LOCK:
        rows = await db.expire_meraki_webhook_alerts(int(_config().get("webhook_open_ttl_hours") or 24))
        await _clear([r for r in rows if r.get("alert_state")])
    return len(rows)


# ── Poll ─────────────────────────────────────────────────────────────────────


async def _poll_client(org: dict) -> tuple[MerakiClient, str]:
    """A Dashboard API client for one source with the poll's settings (short
    timeout, one request at a time, one retry, the client's own rate
    limiting), and its organization ID. Raises ``MerakiApiError`` when the
    source has no valid organization ID or no API key."""
    org_id = str(org.get("org_id") or "").strip()
    if not _ORG_ID_RE.match(org_id):
        raise MerakiApiError("invalid organization ID")
    api_key = await db.get_meraki_org_api_key(int(org["id"]))
    if not api_key:
        raise MerakiApiError("no API key")
    client = MerakiClient(
        api_key,
        base_url=str(org.get("base_url") or "") or DEFAULT_BASE_URL,
        timeout=_POLL_TIMEOUT_SECONDS,
        max_concurrency=1,
        max_retries=1,
        transport=_TRANSPORT,
    )
    return client, org_id


async def poll_source(org: dict) -> list[dict]:
    """The active assurance alerts of one source, normalised. Raises
    ``MerakiApiError`` when the organization cannot be read."""
    client, org_id = await _poll_client(org)
    async with client:
        rows = await client.get_all(
            f"organizations/{org_id}/assurance/alerts",
            params={"active": "true", "dismissed": "false", "resolved": "false"},
            per_page=_PER_PAGE,
        )
    events = [meraki_alerts.from_assurance_alert(r, org_ref=int(org["id"]), org=org) for r in rows]
    return [e for e in events if e]


async def remove_vanished_devices(org: dict, serials: list[str]) -> int:
    """After a poll resolved alerts Meraki no longer reports: remove from
    availability tracking the devices among ``serials`` that are no longer
    in the organization (with their uplinks, tunnels, links and mutes).

    Only serials with a tracked device entity are checked, with one
    ``GET /organizations/{organizationId}/devices`` (devices assigned to a
    network) filtered to them, per chunk of serials. A serial the call does
    not return is gone; a device that recovered is still returned and kept.
    Any error removes nothing. Returns the number of devices removed."""
    if not serials:
        return 0
    org_ref = int(org["id"])
    try:
        tracked = {
            str(r["entity_id"]) for r in await db.list_topology_entity_states(PROVIDER_MERAKI, org_ref, "device")
        }
        wanted = sorted({s for s in serials if f"d:{s}" in tracked})
        if not wanted:
            return 0
        found: set[str] = set()
        client, org_id = await _poll_client(org)
        async with client:
            for start in range(0, len(wanted), _CONFIRM_CHUNK):
                rows = await client.get_all(
                    f"organizations/{org_id}/devices",
                    params={"serials[]": wanted[start : start + _CONFIRM_CHUNK]},
                )
                found.update(str(r.get("serial") or "").upper() for r in rows if isinstance(r, dict))
        gone = [s for s in wanted if s.upper() not in found]
        if not gone:
            return 0
        rows = await db.remove_topology_entities(PROVIDER_MERAKI, org_ref, [f"d:{s}" for s in gone])
        await finish_removal(rows)
        return sum(1 for r in rows if r.get("entity_type") == "device")
    except Exception as exc:  # noqa: BLE001 - the poll stays best effort
        LOGGER.warning("meraki alerts: checking vanished devices of source %s failed: %s", org_ref, type(exc).__name__)
        return 0


def _error_text(exc: Exception) -> str:
    if isinstance(exc, MerakiApiError):
        if exc.status_code:
            return f"HTTP {exc.status_code}"
        text = str(exc)
        return text if text in ("no API key", "invalid organization ID") else "Meraki API unreachable"
    return type(exc).__name__


def _back_off(org_ref: int, exc: Exception) -> float:
    entry = _BACKOFF.setdefault(org_ref, {"failures": 0.0, "next_at": 0.0})
    entry["failures"] += 1
    status = getattr(exc, "status_code", None)
    cap = _MAX_BACKOFF_AUTH if status in (401, 403, 404) or str(exc) == "no API key" else _MAX_BACKOFF_OTHER
    interval = int(_config().get("interval_seconds") or 60)
    delay = float(min(cap, interval * 2 ** int(min(entry["failures"], 10))))
    entry["next_at"] = time.monotonic() + delay
    return delay


async def _poll_one(org: dict) -> dict[str, Any]:
    org_ref = int(org["id"])
    status = _STATUS["sources"].setdefault(str(org_ref), {})
    status.update({"name": str(org.get("name") or ""), "last_poll_at": _now()})
    try:
        events = await poll_source(org)
        active = {str(e["key"]) for e in events if e.get("state") == "open"}
        result = await ingest(events, poll_scope=(org_ref, active))
    except Exception as exc:  # noqa: BLE001 - one source never stops the others
        delay = _back_off(org_ref, exc)
        status.update({"last_error": _error_text(exc), "backoff_seconds": int(delay)})
        LOGGER.warning(
            "meraki alerts: polling source %s failed (%s); next try in %ss", org_ref, _error_text(exc), int(delay)
        )
        return {"org_ref": org_ref, "ok": False, "error": _error_text(exc)}
    _BACKOFF.pop(org_ref, None)
    status.update({"last_ok_at": status["last_poll_at"], "last_error": "", "backoff_seconds": 0, "open": len(active)})
    # Outside _APPLY_LOCK: one more API call, only when an alert vanished.
    removed = await remove_vanished_devices(org, result["vanished"])
    return {"org_ref": org_ref, "ok": True, "active": len(active), **result, "removed": removed}


async def run_alert_poll_cycle(trigger: str = "scheduled", *, force: bool = False) -> dict[str, Any]:
    """Poll every enabled Meraki source once and expire stale webhook
    alerts. ``force`` (Poll Now) polls even when polling is off and ignores
    back-off. Never raises."""
    async with _POLL_LOCK:
        try:
            expired = await expire_webhook_alerts()
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("meraki alerts: expiring webhook alerts failed: %s", type(exc).__name__)
            expired = 0
        if not _config().get("poll_enabled") and not force:
            return {"ok": True, "trigger": trigger, "polled": 0, "skipped": "polling is off", "expired": expired}
        try:
            sources = [s for s in await meraki_sources() if int(s["id"]) not in _excluded()]
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("meraki alerts: listing sources failed: %s", type(exc).__name__)
            return {"ok": False, "trigger": trigger, "polled": 0, "error": type(exc).__name__}
        now = time.monotonic()
        due = [
            s
            for s in sources
            if s.get("has_api_key") and (force or _BACKOFF.get(int(s["id"]), {}).get("next_at", 0.0) <= now)
        ]
        gate = asyncio.Semaphore(_POLL_CONCURRENCY)

        async def one(org: dict) -> dict[str, Any]:
            async with gate:
                return await _poll_one(org)

        results = list(await asyncio.gather(*(one(s) for s in due)))
        failed = [r for r in results if not r["ok"]]
        known = {str(s["id"]) for s in sources}
        _STATUS["sources"] = {k: v for k, v in _STATUS["sources"].items() if k in known}
        _STATUS["last_poll_at"] = _now()
        _STATUS["last_poll_ok"] = not failed
        _STATUS["last_poll_error"] = f"{len(failed)} of {len(results)} source(s) failed" if failed else ""
        await _save_status()
        new = sum(int(r.get("new") or 0) for r in results)
        alerted = sum(int(r.get("alerted") or 0) for r in results)
        resolved = sum(int(r.get("resolved") or 0) for r in results)
        removed = sum(int(r.get("removed") or 0) for r in results)
        if new or resolved or failed or removed:
            LOGGER.info(
                "meraki alerts (%s): %s source(s) polled, %s failed, %s new, %s resolved, %s alert(s), "
                "%s removed device(s)",
                trigger,
                len(results),
                len(failed),
                new,
                resolved,
                alerted,
                removed,
            )
        return {
            "ok": not failed,
            "trigger": trigger,
            "polled": len(results),
            "failed": len(failed),
            "skipped_backoff": len([s for s in sources if s.get("has_api_key")]) - len(due),
            "new": new,
            "resolved": resolved,
            "alerted": alerted,
            "removed": removed,
            "expired": expired,
            "sources": results,
        }


# ── Webhook ──────────────────────────────────────────────────────────────────


def _not_found() -> JSONResponse:
    # The same body as a route that does not exist.
    return JSONResponse(status_code=404, content={"detail": "Not Found"})


async def _read_bounded(request: Request) -> bytes | None:
    """The body, or ``None`` once it passes ``MAX_WEBHOOK_BODY_BYTES``."""
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        return None
    if declared > MAX_WEBHOOK_BODY_BYTES:
        return None
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_WEBHOOK_BODY_BYTES:
            return None
    return bytes(body)


async def process_webhook(payload: dict) -> dict[str, Any]:
    """Turn one accepted webhook into an alert event. Never raises."""
    try:
        if meraki_alerts.is_test_webhook(payload):
            _STATUS["last_test_at"] = _now()
            return {"test": True}
        org_id = str(payload.get("organizationId") or "").strip()
        org = next(
            (
                o
                for o in sorted(await meraki_sources(), key=lambda o: int(o["id"]))
                if str(o.get("org_id") or "").strip() == org_id
            ),
            None,
        )
        if org is None:
            _STATUS["unknown_org_events"] = int(_STATUS.get("unknown_org_events") or 0) + 1
            LOGGER.debug("meraki webhook: event for an organization with no enabled source ignored")
            return {"ignored": "unknown organization"}
        event = meraki_alerts.from_webhook(payload, org_ref=int(org["id"]), org=org)
        if event is None:
            return {"ignored": "no alert type"}
        return await ingest([event])
    except Exception as exc:  # noqa: BLE001 - the delivery was already acknowledged
        _STATUS["last_webhook_error"] = type(exc).__name__
        LOGGER.warning("meraki webhook: processing failed: %s", type(exc).__name__)
        return {"error": type(exc).__name__}
    finally:
        await _save_status()


@webhook_router.post(WEBHOOK_PATH, include_in_schema=False)
async def meraki_webhook(request: Request, background: BackgroundTasks):
    """Meraki's webhook receiver. No session or CSRF; the shared secret in
    the body authenticates it. Responds before the alert work runs."""
    if not webhook_active():
        return _not_found()
    body = await _read_bounded(request)
    if body is None:
        return JSONResponse(status_code=413, content={"detail": "Payload Too Large"})
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return JSONResponse(status_code=415, content={"detail": "Unsupported Media Type"})
    try:
        payload = json.loads(body)
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"detail": "Bad Request"})
    expected = webhook_secret()
    provided = payload.pop("sharedSecret", None)
    if (
        not expected
        or not isinstance(provided, str)
        or not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
    ):
        _STATUS["webhooks_rejected"] = int(_STATUS.get("webhooks_rejected") or 0) + 1
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    _STATUS["last_webhook_at"] = _now()
    _STATUS["webhooks_accepted"] = int(_STATUS.get("webhooks_accepted") or 0) + 1
    background.add_task(process_webhook, payload)
    return {"ok": True}


# ── API ──────────────────────────────────────────────────────────────────────


class MerakiAlertSettingsUpdate(BaseModel):
    poll_enabled: bool | None = None
    interval_seconds: int | None = None
    webhook_enabled: bool | None = None
    # Write-only. Validated by hand so a rejected value is never echoed in a
    # validation error or its log line.
    webhook_secret: str | None = None
    clear_webhook_secret: bool = False
    excluded_sources: list[int] | None = None
    webhook_open_ttl_hours: int | None = None


async def _settings_payload() -> dict[str, Any]:
    cfg = _config()
    excluded = _excluded()
    try:
        sources = await meraki_sources()
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("meraki alerts: listing sources failed: %s", type(exc).__name__)
        sources = []
    status = {k: v for k, v in _STATUS.items() if k != "sources"}
    return {
        "config": {
            "poll_enabled": bool(cfg.get("poll_enabled")),
            "interval_seconds": int(cfg.get("interval_seconds") or 60),
            "webhook_enabled": bool(cfg.get("webhook_enabled")),
            "webhook_secret_configured": bool(cfg.get("webhook_secret_enc")),
            "excluded_sources": sorted(excluded),
            "webhook_open_ttl_hours": int(cfg.get("webhook_open_ttl_hours") or 24),
        },
        "webhook_active": webhook_active(),
        "webhook_path": WEBHOOK_PATH,
        "min_interval_seconds": state.MERAKI_ALERTS_MIN_INTERVAL,
        "max_interval_seconds": state.MERAKI_ALERTS_MAX_INTERVAL,
        "status": status,
        "sources": [
            {
                "id": int(s["id"]),
                "name": str(s.get("name") or ""),
                "has_api_key": bool(s.get("has_api_key")),
                "excluded": int(s["id"]) in excluded,
                "last_poll_at": str((_STATUS["sources"].get(str(s["id"])) or {}).get("last_poll_at") or ""),
                "last_ok_at": str((_STATUS["sources"].get(str(s["id"])) or {}).get("last_ok_at") or ""),
                "last_error": str((_STATUS["sources"].get(str(s["id"])) or {}).get("last_error") or ""),
            }
            for s in sources
        ],
    }


@router.get("/api/monitoring/meraki-alerts")
async def list_meraki_alerts_api(
    include_resolved: bool = Query(default=False),
    org_ref: int | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
):
    """The Meraki alerts from the poll and the webhook receiver; ``muted``
    marks the alerts of a muted device or network."""
    rows = await db.list_meraki_alerts(include_resolved=include_resolved, org_ref=org_ref, limit=limit)
    mutes = await _mute_index(PROVIDER_MERAKI, org_ref) if rows else None
    for row in rows:
        row["muted"] = bool(mutes and _muted(row, mutes))
    return {"alerts": rows}


@admin_router.get("/api/monitoring/meraki-alerts/settings", dependencies=[Depends(_require_admin_dep)])
async def get_meraki_alert_settings_api():
    """The settings and status of both paths. The secret is never returned."""
    return await _settings_payload()


@admin_router.put("/api/monitoring/meraki-alerts/settings", dependencies=[Depends(_require_admin_dep)])
async def update_meraki_alert_settings_api(body: MerakiAlertSettingsUpdate, request: Request):
    current = dict(_config())
    secret_change = "unchanged"
    if body.webhook_secret is not None:
        secret = body.webhook_secret
        if secret != secret.strip() or not (_SECRET_MIN <= len(secret) <= _SECRET_MAX) or not secret.isprintable():
            raise HTTPException(
                status_code=400,
                detail=f"The shared secret must be {_SECRET_MIN} to {_SECRET_MAX} printable characters "
                "with no leading or trailing spaces",
            )
        from routes.crypto import encrypt

        secret_change = "rotated" if current.get("webhook_secret_enc") else "set"
        current["webhook_secret_enc"] = encrypt(secret)
        if body.webhook_enabled is None:
            current["webhook_enabled"] = True
    if body.clear_webhook_secret:
        secret_change = "cleared"
        current["webhook_secret_enc"] = ""
        current["webhook_enabled"] = False
    for field in ("poll_enabled", "interval_seconds", "excluded_sources", "webhook_open_ttl_hours"):
        value = getattr(body, field)
        if value is not None:
            current[field] = value
    if body.webhook_enabled is not None and not body.clear_webhook_secret:
        current["webhook_enabled"] = body.webhook_enabled
    sanitized = state._sanitize_meraki_alerts_config(current)
    state.MERAKI_ALERTS_CONFIG = sanitized
    await db.set_auth_setting(CONFIG_SETTING, sanitized)
    await _audit(
        "monitoring",
        "meraki_alerts.settings_updated",
        user=_session_user(request),
        detail=(
            f"poll={sanitized['poll_enabled']} interval={sanitized['interval_seconds']}s "
            f"webhook={sanitized['webhook_enabled']} secret={secret_change} "
            f"excluded={len(sanitized['excluded_sources'])}"
        ),
        correlation_id=_corr_id(request),
    )
    return await _settings_payload()


@admin_router.post("/api/monitoring/meraki-alerts/poll", dependencies=[Depends(_require_admin_dep)])
async def poll_meraki_alerts_now_api(request: Request):
    """Poll every enabled Meraki source now, ignoring back-off."""
    result = await run_alert_poll_cycle("manual", force=True)
    await _audit(
        "monitoring",
        "meraki_alerts.polled",
        user=_session_user(request),
        detail=f"polled={result.get('polled')} failed={result.get('failed')} new={result.get('new')}",
        correlation_id=_corr_id(request),
    )
    return result
