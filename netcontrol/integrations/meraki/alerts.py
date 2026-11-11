"""Normalise Meraki alerts from both ingest paths into one shape.

Plexus receives Meraki alerts two ways (``netcontrol.routes.meraki_alerts``):

  - **poll**: rows of ``GET /organizations/{organizationId}/assurance/alerts``
    (``id``, ``categoryType``, ``network{id,name}``, ``startedAt``,
    ``resolvedAt``, ``dismissedAt``, ``deviceType``, ``type``, ``title``,
    ``description``, ``severity``, ``scope{devices[{serial,name,...}]}``);
  - **webhook**: the JSON body Meraki POSTs to a configured HTTP server
    (``organizationId``, ``networkId``, ``networkName``, ``deviceSerial``,
    ``deviceName``, ``deviceModel``, ``alertId``, ``alertType``,
    ``alertTypeId``, ``alertLevel``, ``occurredAt``, ``alertData``, ...).

Both become the same dict (:func:`from_assurance_alert`,
:func:`from_webhook`). Its ``key`` is what deduplicates: the Plexus source,
the subject (the device serial, else the network, else the organization)
and the *condition*. The condition is the alert type with any trailing
"went down" / "came up" style token removed, then mapped through
:data:`CONDITION_ALIASES`, so a webhook "APs went down" (``stopped_reporting``)
and a polled assurance ``unreachable`` alert for the same device share one
key, and a recovery event ("... came up") carries the key of the alert it
clears. Types with no known equivalent keep their own condition, so the same
problem reported under two unrelated type names by the two paths stays two
alerts (documented in ``docs/meraki-alerts.md``).

Pure: no I/O, no database, so the tests run from the samples in
``netcontrol.integrations.meraki.alerts_sample``.
"""

from __future__ import annotations

import json
import re
from datetime import UTC
from typing import Any

from netcontrol.integrations.meraki.compliance import _parse_iso

SOURCE_POLL = "poll"
SOURCE_WEBHOOK = "webhook"

CRITICAL = "critical"
WARNING = "warning"
INFO = "info"
# Severities that raise a monitoring alert / notification; ``info`` is
# stored and listed only.
ALERTING_SEVERITIES = (WARNING, CRITICAL)
SEVERITY_RANK = {"": 0, INFO: 1, WARNING: 2, CRITICAL: 3}

# The device itself is unreachable / offline. Merging these lets the two
# paths (and the topology availability tracker, see
# ``netcontrol.routes.meraki_alerts``) recognise the same device-down
# condition. ``unreachable`` is an assurance alert type and
# ``stopped_reporting`` the webhook "APs went down" type (both from the
# Dashboard API v1 reference); the plural device words are what is left of
# the "<devices> went down" / "<devices> came up" webhook types once the
# state token is removed.
DEVICE_DOWN = "device_down"
CONDITION_ALIASES: dict[str, str] = {
    "unreachable": DEVICE_DOWN,
    "stopped_reporting": DEVICE_DOWN,
    "device": DEVICE_DOWN,
    "aps": DEVICE_DOWN,
    "appliances": DEVICE_DOWN,
    "switches": DEVICE_DOWN,
    "cameras": DEVICE_DOWN,
    "gateways": DEVICE_DOWN,
    "cellular_gateways": DEVICE_DOWN,
    "sensors": DEVICE_DOWN,
    "devices": DEVICE_DOWN,
}

# Trailing state tokens: a "down" one opens, an "up" one is a recovery.
_DOWN_TOKENS = ("went_down", "is_down", "down", "offline")
_UP_TOKENS = ("came_back_up", "came_up", "back_up", "back_online", "is_up", "up", "online", "recovered",
              "restored", "cleared", "resolved")  # fmt: skip
_TOKEN_RE = re.compile(r"_(?:" + "|".join(sorted((*_DOWN_TOKENS, *_UP_TOKENS), key=len, reverse=True)) + r")$")
_UP_RE = re.compile(r"_(?:" + "|".join(sorted(_UP_TOKENS, key=len, reverse=True)) + r")$")
_SLUG_RE = re.compile(r"[^a-z0-9]+")
# alertData copied into ``detail`` only up to this size (JSON characters).
_MAX_DETAIL_CHARS = 4000
# Payload fields never copied anywhere (the webhook's shared secret).
_SECRET_FIELDS = frozenset({"sharedSecret", "shared_secret"})


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def slug(value: Any) -> str:
    """``"APs went down"`` -> ``"aps_went_down"``."""
    return _SLUG_RE.sub("_", _text(value).lower()).strip("_")


def stamp(value: Any) -> str:
    """An ISO 8601 time as UTC ``YYYY-MM-DD HH:MM:SS`` text, or ``""``.

    A time without a zone is taken as UTC (Meraki sends UTC)."""
    moment = _parse_iso(value)
    if moment is None:
        return ""
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def severity_of(level: Any) -> str:
    """Plexus severity of a Meraki ``alertLevel`` (``critical``,
    ``warning``, ``informational``) or assurance ``severity``. An unknown
    value is a warning, so nothing new goes unnoticed."""
    text = _text(level).lower()
    if text in ("critical", "error", "high", "emergency", "alert"):
        return CRITICAL
    if text in ("informational", "info", "information", "low", "notice", "debug"):
        return INFO
    return WARNING


def is_recovery(type_id: Any) -> bool:
    """A type that reports a problem has cleared (``..._came_up``)."""
    return bool(_UP_RE.search("_" + slug(type_id)))


def condition_of(type_id: Any) -> str:
    """The condition a type reports, with the state token removed and known
    equivalents merged: ``aps_went_down`` and ``aps_came_up`` are both
    ``device_down``, as are ``stopped_reporting`` and ``unreachable``."""
    base = slug(type_id)
    stripped = _TOKEN_RE.sub("", "_" + base).lstrip("_") or base
    return CONDITION_ALIASES.get(stripped) or CONDITION_ALIASES.get(base) or stripped or "unknown"


def alert_key(org_ref: int, condition: str, *, serial: str = "", network_id: str = "") -> str:
    """The dedupe key: one Plexus alert per (source, subject, condition)."""
    if serial:
        subject = f"d:{serial.upper()}"
    elif network_id:
        subject = f"n:{network_id}"
    else:
        subject = "o"
    return f"meraki:{int(org_ref)}:{subject}:{condition}"


def _bounded(value: Any) -> Any:
    """``value`` if its JSON is small enough to keep, else a marker."""
    try:
        text = json.dumps(value, sort_keys=True, default=str)
    except TypeError, ValueError:
        return None
    if len(text) > _MAX_DETAIL_CHARS:
        return {"truncated": True, "size": len(text)}
    return value


def _event(
    *,
    org_ref: int,
    org: dict,
    network_id: str,
    network_name: str,
    serial: str,
    device_name: str,
    device_model: str,
    product_type: str,
    alert_type: str,
    category: str,
    title: str,
    message: str,
    severity: str,
    state: str,
    started_at: str,
    resolved_at: str,
    source: str,
    meraki_alert_id: str,
    detail: dict,
) -> dict[str, Any]:
    condition = condition_of(alert_type)
    return {
        "key": alert_key(org_ref, condition, serial=serial, network_id=network_id),
        "org_ref": int(org_ref),
        "org_id": _text(org.get("org_id")),
        "org_name": _text(org.get("name")),
        "network_id": network_id,
        "network_name": network_name,
        "device_serial": serial.upper(),
        "device_name": device_name,
        "device_model": device_model,
        "product_type": product_type,
        "alert_type": alert_type,
        "condition": condition,
        "category": category,
        "title": title,
        "message": message,
        "severity": severity,
        "state": state,
        "started_at": started_at,
        "resolved_at": resolved_at,
        "source": source,
        "meraki_alert_id": meraki_alert_id,
        "detail": detail,
    }


def _primary_device(scope: Any) -> dict:
    """The first device in an assurance alert's scope (lowest ``order``)."""
    devices = (
        [d for d in ((scope or {}).get("devices") or []) if isinstance(d, dict)] if isinstance(scope, dict) else []
    )
    if not devices:
        return {}
    return sorted(devices, key=lambda d: (d.get("order") is None, d.get("order") or 0))[0]


def from_assurance_alert(row: dict, *, org_ref: int, org: dict | None = None) -> dict[str, Any] | None:
    """One assurance alert row as a normalised alert, or ``None`` when the
    row is not an alert object. A row with ``resolvedAt`` or ``dismissedAt``
    set is a resolved event."""
    if not isinstance(row, dict) or not (row.get("type") or row.get("title")):
        return None
    org = org or {}
    network: dict = row["network"] if isinstance(row.get("network"), dict) else {}
    device = _primary_device(row.get("scope"))
    devices = ((row.get("scope") or {}).get("devices") or []) if isinstance(row.get("scope"), dict) else []
    alert_type = _text(row.get("type")) or slug(row.get("title"))
    resolved = stamp(row.get("resolvedAt")) or stamp(row.get("dismissedAt"))
    title = _text(row.get("title")) or alert_type
    return _event(
        org_ref=org_ref,
        org=org,
        network_id=_text(network.get("id")),
        network_name=_text(network.get("name")),
        serial=_text(device.get("serial")),
        device_name=_text(device.get("name")),
        device_model=_text(device.get("model")),
        product_type=_text(device.get("productType")) or _text(row.get("deviceType")),
        alert_type=alert_type,
        category=_text(row.get("categoryType")),
        title=title,
        message=_text(row.get("description")) or title,
        severity=severity_of(row.get("severity")),
        state="resolved" if resolved else "open",
        started_at=stamp(row.get("startedAt")),
        resolved_at=resolved,
        source=SOURCE_POLL,
        meraki_alert_id=_text(row.get("id")),
        detail={
            "device_count": len(devices) if isinstance(devices, list) else 0,
            "dismissed": bool(row.get("dismissedAt")),
            "url": _text(network.get("url")),
        },
    )


def is_test_webhook(payload: dict) -> bool:
    """A delivery from the Dashboard's "Send test webhook" button.

    The test payload is not specified in Meraki's documentation, so this is
    a heuristic: an ``alertId`` of zeros, an explicit ``test`` flag in
    ``alertData``, or a type or name that says "test". Every accepted
    delivery updates "last webhook received" whatever this returns."""
    alert_id = _text(payload.get("alertId"))
    if alert_id and set(alert_id) == {"0"}:
        return True
    data = payload.get("alertData")
    if isinstance(data, dict) and data.get("test") is True:
        return True
    for field in ("alertTypeId", "alertType"):
        if "test" in slug(payload.get(field)).split("_"):
            return True
    return False


def from_webhook(payload: dict, *, org_ref: int, org: dict | None = None) -> dict[str, Any] | None:
    """One webhook body as a normalised alert, or ``None`` when it carries
    no alert type. A recovery type ("... came up") is a resolved event with
    the key of the alert it clears. ``sharedSecret`` is never copied."""
    if not isinstance(payload, dict):
        return None
    alert_type = _text(payload.get("alertTypeId")) or slug(payload.get("alertType"))
    if not alert_type:
        return None
    org = org or {}
    title = _text(payload.get("alertType")) or alert_type
    occurred = stamp(payload.get("occurredAt")) or stamp(payload.get("sentAt"))
    recovery = is_recovery(alert_type) or is_recovery(payload.get("alertType"))
    data = payload.get("alertData")
    detail: dict[str, Any] = {
        "alert_data": _bounded({k: v for k, v in data.items() if k not in _SECRET_FIELDS})
        if isinstance(data, dict)
        else None,
        "url": _text(payload.get("deviceUrl")) or _text(payload.get("networkUrl")),
    }
    where = _text(payload.get("deviceName")) or _text(payload.get("deviceSerial"))
    message = f"{title} ({where})" if where else title
    return _event(
        org_ref=org_ref,
        org=org,
        network_id=_text(payload.get("networkId")),
        network_name=_text(payload.get("networkName")),
        serial=_text(payload.get("deviceSerial")),
        device_name=_text(payload.get("deviceName")),
        device_model=_text(payload.get("deviceModel")),
        product_type="",
        alert_type=alert_type,
        category="",
        title=title,
        message=message,
        severity=INFO if recovery else severity_of(payload.get("alertLevel")),
        state="resolved" if recovery else "open",
        started_at="" if recovery else occurred,
        resolved_at=occurred if recovery else "",
        source=SOURCE_WEBHOOK,
        meraki_alert_id=_text(payload.get("alertId")),
        detail=detail,
    )
