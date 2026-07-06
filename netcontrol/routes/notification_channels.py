"""
notification_channels.py -- Outbound alert notification channels.

Monitoring alerts are persisted to `monitoring_alerts` and surfaced in the SPA,
but a toast in a browser tab nobody is watching does not wake the on-call
engineer at 3 AM. This module owns the engine that turns each NEWLY created
monitoring alert into one or more outbound notifications: email (SMTP),
PagerDuty Events API v2, a generic JSON webhook, and Microsoft Teams incoming
webhooks.

Architecture (mirrors ``siem_forwarder``)
-----------------------------------------
- Configuration is a JSON list of "channels" persisted in `auth_settings`
  under the key `notification_channels`, alongside a list of default channel
  ids used for alerts that aren't tied to a user rule (built-in thresholds,
  baseline deviations, route churn).
- The dispatcher is a set of per-channel async tasks started in the FastAPI
  lifespan. Each channel has a bounded `asyncio.Queue`; an enqueued alert is
  rendered by the channel-type formatter and delivered by the channel driver.
- Delivery failures retry with exponential backoff up to a configurable cap.
  When a queue is full and a new alert arrives, the OLDEST queued alert is
  dropped and counted; alert *creation* (the DB insert) must never block on a
  wedged notification endpoint.
- Per-channel runtime stats (`delivered`, `dropped`, `last_error`, ...) are
  exposed via the admin API so operators can see at a glance whether
  notifications are healthy.

Dedup / suppression
-------------------
The engine is fed only when ``create_monitoring_alert`` performs a *new*
insert -- repeated occurrences of the same condition bump the existing alert's
occurrence count and do NOT re-fire the hook, so a flapping interface does not
generate a notification storm. Suppression windows are enforced upstream in
the alert evaluator (``is_alert_suppressed``), so a suppressed condition never
reaches this module.

Failure model
-------------
Best effort. The `monitoring_alerts` row is the source of truth; if a process
crash or an indefinite endpoint outage drops a notification, the alert is still
in the database and visible in the UI. We deliberately do not gate alert
inserts on notification delivery.
"""

from __future__ import annotations

import asyncio
import json
import smtplib
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import formatdate
from typing import Any

import httpx

from netcontrol.routes.net_guard import OutboundRequestError, validate_outbound_url
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.notify")

# ── Constants ────────────────────────────────────────────────────────────────

SUPPORTED_TYPES = ("email", "pagerduty", "webhook", "teams")
# Alerts only ever carry these three severities (see monitoring evaluator),
# but we accept "info" as a floor so a channel can opt in to everything.
SUPPORTED_SEVERITIES = ("info", "warning", "critical")
_SEVERITY_ORDER = {name: i for i, name in enumerate(SUPPORTED_SEVERITIES)}

REDACTION_MASK = "••••••••"

DEFAULT_QUEUE_SIZE = 1000
DEFAULT_MAX_RETRIES = 4
DEFAULT_BACKOFF_BASE = 1.0  # seconds
DEFAULT_BACKOFF_CAP = 60.0  # seconds
DEFAULT_HTTP_TIMEOUT = 10.0  # seconds
DEFAULT_SMTP_TIMEOUT = 15.0  # seconds

PAGERDUTY_ENQUEUE_URL = "https://events.pagerduty.com/v2/enqueue"

# Map our alert severity to the PagerDuty Events API v2 severity vocabulary.
_PAGERDUTY_SEVERITY = {"critical": "critical", "warning": "warning", "info": "info"}
# Teams MessageCard theme colour per severity (hex, no leading #).
_TEAMS_COLOR = {"critical": "D13438", "warning": "F7A700", "info": "0078D4"}


# ── Channel config + runtime stats ───────────────────────────────────────────

@dataclass
class ChannelConfig:
    """Validated, in-memory representation of one notification channel."""

    id: str
    name: str
    enabled: bool
    type: str               # email | pagerduty | webhook | teams
    severity_floor: str     # info | warning | critical
    queue_size: int
    max_retries: int
    backoff_base: float
    backoff_cap: float

    # email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_use_tls: bool = True   # STARTTLS
    smtp_use_ssl: bool = False  # implicit TLS (SMTPS)
    smtp_username: str = ""
    smtp_password: str = ""
    mail_from: str = ""
    mail_to: str = ""           # comma/space separated recipient list

    # pagerduty
    routing_key: str = ""       # Events API v2 integration key (secret)

    # webhook
    webhook_url: str = ""
    webhook_auth_header: str = ""   # header name, e.g. "Authorization"
    webhook_auth_value: str = ""    # header value (secret)
    verify_tls: bool = True

    # teams
    teams_webhook_url: str = ""


@dataclass
class ChannelRuntime:
    """Per-channel runtime state - counters, last error, in-flight task."""

    config: ChannelConfig
    queue: asyncio.Queue
    task: asyncio.Task | None = None
    delivered: int = 0
    dropped_queue_full: int = 0
    dropped_below_severity: int = 0
    delivery_failures: int = 0
    last_error: str = ""
    last_delivery_at: str = ""
    last_failure_at: str = ""
    _stop_event: asyncio.Event = field(default_factory=asyncio.Event)


# ── Validation / sanitization ────────────────────────────────────────────────

def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return default


def _coerce_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        ival = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, ival))


def _coerce_float(value: Any, default: float, low: float, high: float) -> float:
    try:
        fval = float(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, fval))


def sanitize_channel(raw: dict | None) -> ChannelConfig | None:
    """Validate a single channel dict; return a ChannelConfig or None.

    Invalid channels are dropped silently here - the admin API surfaces a 400
    on create/update, this is the safety net on load.
    """
    if not isinstance(raw, dict):
        return None
    channel_id = str(raw.get("id") or "").strip()
    if not channel_id:
        return None
    ctype = str(raw.get("type") or "").strip().lower()
    if ctype not in SUPPORTED_TYPES:
        return None
    name = str(raw.get("name") or "").strip() or channel_id
    severity = str(raw.get("severity_floor") or "warning").strip().lower()
    if severity not in SUPPORTED_SEVERITIES:
        severity = "warning"

    cfg = ChannelConfig(
        id=channel_id,
        name=name,
        enabled=_coerce_bool(raw.get("enabled"), True),
        type=ctype,
        severity_floor=severity,
        queue_size=_coerce_int(raw.get("queue_size"), DEFAULT_QUEUE_SIZE, 10, 100_000),
        max_retries=_coerce_int(raw.get("max_retries"), DEFAULT_MAX_RETRIES, 0, 20),
        backoff_base=_coerce_float(raw.get("backoff_base"), DEFAULT_BACKOFF_BASE, 0.1, 30.0),
        backoff_cap=_coerce_float(raw.get("backoff_cap"), DEFAULT_BACKOFF_CAP, 1.0, 600.0),
        smtp_host=str(raw.get("smtp_host") or "").strip(),
        smtp_port=_coerce_int(raw.get("smtp_port"), 587, 1, 65535),
        smtp_use_tls=_coerce_bool(raw.get("smtp_use_tls"), True),
        smtp_use_ssl=_coerce_bool(raw.get("smtp_use_ssl"), False),
        smtp_username=str(raw.get("smtp_username") or "").strip(),
        smtp_password=str(raw.get("smtp_password") or ""),
        mail_from=str(raw.get("mail_from") or "").strip(),
        mail_to=str(raw.get("mail_to") or "").strip(),
        routing_key=str(raw.get("routing_key") or "").strip(),
        webhook_url=str(raw.get("webhook_url") or "").strip(),
        webhook_auth_header=str(raw.get("webhook_auth_header") or "").strip(),
        webhook_auth_value=str(raw.get("webhook_auth_value") or ""),
        verify_tls=_coerce_bool(raw.get("verify_tls"), True),
        teams_webhook_url=str(raw.get("teams_webhook_url") or "").strip(),
    )

    # Type-specific required fields. A channel that can't possibly deliver is
    # rejected so it never silently swallows alerts.
    if ctype == "email":
        if not cfg.smtp_host or not cfg.mail_from or not _parse_recipients(cfg.mail_to):
            return None
    elif ctype == "pagerduty":
        if not cfg.routing_key:
            return None
    elif ctype == "webhook":
        if not cfg.webhook_url.lower().startswith(("http://", "https://")):
            return None
    elif ctype == "teams":
        if not cfg.teams_webhook_url.lower().startswith(("http://", "https://")):
            return None
    return cfg


def sanitize_channels(raw: Any) -> list[ChannelConfig]:
    """Sanitize the persisted list of channels. Skips invalid / duplicate rows."""
    if not isinstance(raw, list):
        return []
    out: list[ChannelConfig] = []
    seen: set[str] = set()
    for entry in raw:
        cfg = sanitize_channel(entry)
        if cfg is None or cfg.id in seen:
            continue
        seen.add(cfg.id)
        out.append(cfg)
    return out


def channel_config_to_dict(cfg: ChannelConfig, *, redact_secrets: bool = True) -> dict:
    """Serialize a ChannelConfig to a JSON-able dict. Optionally redacts the
    secret fields (SMTP password, PagerDuty routing key, webhook auth value)
    for API responses."""
    def secret(value: str) -> str:
        return REDACTION_MASK if (redact_secrets and value) else value

    return {
        "id": cfg.id,
        "name": cfg.name,
        "enabled": cfg.enabled,
        "type": cfg.type,
        "severity_floor": cfg.severity_floor,
        "queue_size": cfg.queue_size,
        "max_retries": cfg.max_retries,
        "backoff_base": cfg.backoff_base,
        "backoff_cap": cfg.backoff_cap,
        "smtp_host": cfg.smtp_host,
        "smtp_port": cfg.smtp_port,
        "smtp_use_tls": cfg.smtp_use_tls,
        "smtp_use_ssl": cfg.smtp_use_ssl,
        "smtp_username": cfg.smtp_username,
        "smtp_password": secret(cfg.smtp_password),
        "mail_from": cfg.mail_from,
        "mail_to": cfg.mail_to,
        "routing_key": secret(cfg.routing_key),
        "webhook_url": cfg.webhook_url,
        "webhook_auth_header": cfg.webhook_auth_header,
        "webhook_auth_value": secret(cfg.webhook_auth_value),
        "verify_tls": cfg.verify_tls,
        "teams_webhook_url": cfg.teams_webhook_url,
    }


_SECRET_FIELDS = ("smtp_password", "routing_key", "webhook_auth_value")


def merge_secrets(new: dict, existing: ChannelConfig | None) -> dict:
    """If the client posts the redaction sentinel for a secret field, keep the
    previously stored value instead of overwriting it with the mask."""
    if existing is None:
        return new
    for fname in _SECRET_FIELDS:
        if new.get(fname) == REDACTION_MASK:
            new[fname] = getattr(existing, fname)
    return new


def _parse_recipients(raw: str) -> list[str]:
    """Split a comma/whitespace/semicolon separated recipient string."""
    if not raw:
        return []
    parts = raw.replace(";", ",").replace("\n", ",").split(",")
    out = []
    for p in parts:
        for tok in p.split():
            tok = tok.strip()
            if tok:
                out.append(tok)
    return out


def parse_channel_ids(raw: Any) -> list[str]:
    """Normalize a channel-id assignment into a list of strings.

    Accepts a JSON list, a JSON-encoded list string, or a comma-separated
    string (the alert_rules column is TEXT).
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return []
        if s.startswith("["):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
            except (ValueError, TypeError) as exc:
                LOGGER.warning("notify: channel_ids JSON parse failed, falling back to comma split: %s", exc)
        return [t.strip() for t in s.split(",") if t.strip()]
    return []


# ── Formatters ───────────────────────────────────────────────────────────────

def _severity_label(severity: str) -> str:
    s = (severity or "warning").lower()
    return s if s in SUPPORTED_SEVERITIES else "warning"


def _alert_summary(alert: dict) -> str:
    """One-line human summary used as the notification title."""
    host = alert.get("hostname") or f"host {alert.get('host_id', '?')}"
    sev = _severity_label(alert.get("severity", "warning")).upper()
    metric = alert.get("metric", "alert")
    return f"[Plexus][{sev}] {host}: {metric}"


def format_pagerduty(alert: dict, cfg: ChannelConfig) -> dict:
    """PagerDuty Events API v2 ``trigger`` payload.

    The alert's dedup_key is reused as PagerDuty's dedup_key so repeated
    Plexus alerts collapse onto the same PagerDuty incident.
    """
    sev = _PAGERDUTY_SEVERITY.get(_severity_label(alert.get("severity", "warning")), "warning")
    host = alert.get("hostname") or f"host {alert.get('host_id', '?')}"
    custom: dict[str, Any] = {
        "alert_id": alert.get("alert_id"),
        "host_id": alert.get("host_id"),
        "metric": alert.get("metric"),
        "alert_type": alert.get("alert_type"),
        "message": alert.get("message"),
    }
    if alert.get("value") is not None:
        custom["value"] = alert.get("value")
    if alert.get("threshold") is not None:
        custom["threshold"] = alert.get("threshold")
    if alert.get("rule_id") is not None:
        custom["rule_id"] = alert.get("rule_id")

    payload: dict[str, Any] = {
        "routing_key": cfg.routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": (alert.get("message") or _alert_summary(alert))[:1024],
            "source": host,
            "severity": sev,
            "component": alert.get("metric", ""),
            "group": "plexus-monitoring",
            "custom_details": custom,
        },
    }
    dedup = alert.get("dedup_key") or ""
    if dedup:
        payload["dedup_key"] = dedup
    if alert.get("timestamp"):
        payload["payload"]["timestamp"] = alert.get("timestamp")
    return payload


def format_webhook(alert: dict) -> dict:
    """Generic webhook JSON body. Stable, source-tagged shape."""
    return {
        "source": "plexus",
        "event": "monitoring.alert",
        "alert_id": alert.get("alert_id"),
        "host_id": alert.get("host_id"),
        "hostname": alert.get("hostname", ""),
        "severity": _severity_label(alert.get("severity", "warning")),
        "metric": alert.get("metric", ""),
        "alert_type": alert.get("alert_type", ""),
        "message": alert.get("message", ""),
        "value": alert.get("value"),
        "threshold": alert.get("threshold"),
        "rule_id": alert.get("rule_id"),
        "dedup_key": alert.get("dedup_key", ""),
        "timestamp": alert.get("timestamp", ""),
    }


def format_teams(alert: dict) -> dict:
    """Microsoft Teams legacy MessageCard (Office 365 connector) payload.

    MessageCard is what incoming-webhook connectors render; the newer Adaptive
    Card flow requires Workflows/Power Automate and is out of scope for v1.
    """
    sev = _severity_label(alert.get("severity", "warning"))
    host = alert.get("hostname") or f"host {alert.get('host_id', '?')}"
    facts = [
        {"name": "Host", "value": str(host)},
        {"name": "Severity", "value": sev.upper()},
        {"name": "Metric", "value": str(alert.get("metric", ""))},
    ]
    if alert.get("value") is not None:
        facts.append({"name": "Value", "value": str(alert.get("value"))})
    if alert.get("threshold") is not None:
        facts.append({"name": "Threshold", "value": str(alert.get("threshold"))})
    if alert.get("timestamp"):
        facts.append({"name": "Time", "value": str(alert.get("timestamp"))})
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": _TEAMS_COLOR.get(sev, "F7A700"),
        "summary": _alert_summary(alert),
        "title": _alert_summary(alert),
        "sections": [
            {
                "activityTitle": "Plexus Network Monitoring Alert",
                "facts": facts,
                "text": str(alert.get("message", "")),
            }
        ],
    }


def build_email(alert: dict, cfg: ChannelConfig) -> EmailMessage:
    """Build the MIME message for an email channel."""
    msg = EmailMessage()
    msg["Subject"] = _alert_summary(alert)
    msg["From"] = cfg.mail_from
    msg["To"] = ", ".join(_parse_recipients(cfg.mail_to))
    msg["Date"] = formatdate(localtime=True)
    sev = _severity_label(alert.get("severity", "warning")).upper()
    host = alert.get("hostname") or f"host {alert.get('host_id', '?')}"
    lines = [
        f"Severity:  {sev}",
        f"Host:      {host} (id {alert.get('host_id', '?')})",
        f"Metric:    {alert.get('metric', '')}",
        f"Type:      {alert.get('alert_type', '')}",
    ]
    if alert.get("value") is not None:
        lines.append(f"Value:     {alert.get('value')}")
    if alert.get("threshold") is not None:
        lines.append(f"Threshold: {alert.get('threshold')}")
    if alert.get("timestamp"):
        lines.append(f"Time:      {alert.get('timestamp')}")
    lines.append("")
    lines.append(alert.get("message", ""))
    lines.append("")
    lines.append("-- Plexus Network Management Platform")
    msg.set_content("\n".join(lines))
    return msg


# ── Channel drivers ──────────────────────────────────────────────────────────

def _httpx_verify(cfg: ChannelConfig) -> Any:
    return True if cfg.verify_tls else False


async def _deliver_pagerduty(cfg: ChannelConfig, alert: dict) -> None:
    body = format_pagerduty(alert, cfg)
    async with httpx.AsyncClient(timeout=DEFAULT_HTTP_TIMEOUT) as client:
        resp = await client.post(PAGERDUTY_ENQUEUE_URL, json=body)
        if resp.status_code >= 400:
            raise RuntimeError(f"pagerduty HTTP {resp.status_code}: {resp.text[:200]}")


async def _guard_url(url: str) -> None:
    """SSRF pre-check for admin-configured webhook targets."""
    try:
        await asyncio.to_thread(validate_outbound_url, url)
    except OutboundRequestError as exc:
        raise RuntimeError(f"webhook target rejected: {exc}") from exc


async def _deliver_webhook(cfg: ChannelConfig, alert: dict) -> None:
    body = format_webhook(alert)
    headers = {"Content-Type": "application/json"}
    if cfg.webhook_auth_header and cfg.webhook_auth_value:
        headers[cfg.webhook_auth_header] = cfg.webhook_auth_value
    await _guard_url(cfg.webhook_url)
    async with httpx.AsyncClient(timeout=DEFAULT_HTTP_TIMEOUT, verify=_httpx_verify(cfg)) as client:
        resp = await client.post(cfg.webhook_url, json=body, headers=headers)
        if resp.status_code >= 400:
            raise RuntimeError(f"webhook HTTP {resp.status_code}: {resp.text[:200]}")


async def _deliver_teams(cfg: ChannelConfig, alert: dict) -> None:
    body = format_teams(alert)
    await _guard_url(cfg.teams_webhook_url)
    async with httpx.AsyncClient(timeout=DEFAULT_HTTP_TIMEOUT, verify=_httpx_verify(cfg)) as client:
        resp = await client.post(cfg.teams_webhook_url, json=body)
        # Teams connectors return 200 with body "1" on success.
        if resp.status_code >= 400:
            raise RuntimeError(f"teams HTTP {resp.status_code}: {resp.text[:200]}")


def _send_email_blocking(cfg: ChannelConfig, msg: EmailMessage) -> None:
    """Synchronous SMTP send. Runs in a thread executor (smtplib is blocking).

    Honours implicit TLS (SMTPS) vs STARTTLS, optional auth.
    """
    recipients = _parse_recipients(cfg.mail_to)
    if cfg.smtp_use_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port,
                              timeout=DEFAULT_SMTP_TIMEOUT, context=context) as server:
            if cfg.smtp_username:
                server.login(cfg.smtp_username, cfg.smtp_password)
            server.send_message(msg, from_addr=cfg.mail_from, to_addrs=recipients)
    else:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=DEFAULT_SMTP_TIMEOUT) as server:
            server.ehlo()
            if cfg.smtp_use_tls:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            if cfg.smtp_username:
                server.login(cfg.smtp_username, cfg.smtp_password)
            server.send_message(msg, from_addr=cfg.mail_from, to_addrs=recipients)


async def _deliver_email(cfg: ChannelConfig, alert: dict) -> None:
    msg = build_email(alert, cfg)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _send_email_blocking, cfg, msg)


async def deliver(cfg: ChannelConfig, alert: dict) -> None:
    """Format and send one alert through one channel. Raises on failure."""
    if cfg.type == "email":
        await _deliver_email(cfg, alert)
    elif cfg.type == "pagerduty":
        await _deliver_pagerduty(cfg, alert)
    elif cfg.type == "webhook":
        await _deliver_webhook(cfg, alert)
    elif cfg.type == "teams":
        await _deliver_teams(cfg, alert)
    else:
        raise ValueError(f"unsupported channel type: {cfg.type}")


# ── Dispatcher ───────────────────────────────────────────────────────────────

_runtime_lock = asyncio.Lock()
_channels: dict[str, ChannelRuntime] = {}
_default_channel_ids: list[str] = []
_started = False


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _channel_loop(rt: ChannelRuntime) -> None:
    """One asyncio task per channel. Pulls alerts from the queue, formats,
    sends, and retries with exponential backoff bounded by max_retries."""
    cfg = rt.config
    LOGGER.info("notify channel %s: started (type=%s, floor=%s)",
                cfg.id, cfg.type, cfg.severity_floor)
    try:
        while True:
            alert = await rt.queue.get()
            try:
                attempt = 0
                while True:
                    try:
                        await deliver(cfg, alert)
                        rt.delivered += 1
                        rt.last_delivery_at = _utc_now_iso()
                        break
                    except Exception as exc:
                        attempt += 1
                        rt.delivery_failures += 1
                        rt.last_error = f"{type(exc).__name__}: {exc}"
                        rt.last_failure_at = _utc_now_iso()
                        if attempt > cfg.max_retries:
                            LOGGER.warning(
                                "notify channel %s: giving up on alert id=%s after %d attempts: %s",
                                cfg.id, alert.get("alert_id"), attempt, rt.last_error,
                            )
                            break
                        delay = min(cfg.backoff_cap, cfg.backoff_base * (2 ** (attempt - 1)))
                        await asyncio.sleep(delay)
            finally:
                rt.queue.task_done()
    except asyncio.CancelledError:
        LOGGER.info("notify channel %s: stopping", cfg.id)
        raise


def _passes_floor(rt: ChannelRuntime, severity: str) -> bool:
    sev = _severity_label(severity)
    return _SEVERITY_ORDER.get(sev, 1) >= _SEVERITY_ORDER.get(rt.config.severity_floor, 1)


def _enqueue_one(rt: ChannelRuntime, alert: dict) -> None:
    """Enqueue with drop-oldest backpressure policy. Never raises."""
    try:
        rt.queue.put_nowait(alert)
    except asyncio.QueueFull:
        try:
            rt.queue.get_nowait()
            rt.queue.task_done()
            rt.dropped_queue_full += 1
        except asyncio.QueueEmpty as exc:
            LOGGER.warning("notify channel %s: queue full, drop-oldest raced empty: %s",
                           rt.config.id, exc)
        try:
            rt.queue.put_nowait(alert)
        except asyncio.QueueFull:
            rt.dropped_queue_full += 1


async def on_alert_created(alert: dict) -> None:
    """Hook target registered with ``db.set_alert_created_hook``.

    Resolves the set of target channels for this alert, applies the per-channel
    severity floor, and enqueues. Never raises - alert inserts must not break.

    Channel resolution:
      - ``alert["channel_ids"]`` (the rule's assignment, if any) wins.
      - Otherwise the global default channel set is used (built-in thresholds,
        baseline deviations, route churn -- alerts with no rule).
    """
    try:
        targets = parse_channel_ids(alert.get("channel_ids"))
        async with _runtime_lock:
            if not targets:
                targets = list(_default_channel_ids)
            # Resolve to runtimes, de-duplicating ids.
            seen: set[str] = set()
            runtimes: list[ChannelRuntime] = []
            for cid in targets:
                if cid in seen:
                    continue
                seen.add(cid)
                rt = _channels.get(cid)
                if rt is not None:
                    runtimes.append(rt)
        severity = alert.get("severity", "warning")
        for rt in runtimes:
            if not rt.config.enabled:
                continue
            if not _passes_floor(rt, severity):
                rt.dropped_below_severity += 1
                continue
            _enqueue_one(rt, alert)
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.warning("notify: on_alert_created failed: %s", type(exc).__name__)


def _config_changed(old: ChannelConfig, new: ChannelConfig) -> bool:
    """Field-by-field compare to decide whether to recreate the channel task."""
    for fname in (
        "enabled", "type", "severity_floor", "queue_size", "max_retries",
        "backoff_base", "backoff_cap", "smtp_host", "smtp_port", "smtp_use_tls",
        "smtp_use_ssl", "smtp_username", "smtp_password", "mail_from", "mail_to",
        "routing_key", "webhook_url", "webhook_auth_header", "webhook_auth_value",
        "verify_tls", "teams_webhook_url",
    ):
        if getattr(old, fname) != getattr(new, fname):
            return True
    return False


async def apply_channels(configs: list[ChannelConfig],
                         default_channel_ids: list[str] | None = None) -> None:
    """Reconcile the running channel set against a new desired config list.

    New channels get a queue + task; removed/changed channels are cancelled
    (changed ones are recreated). The default-channel-id list is updated too.
    """
    global _default_channel_ids
    async with _runtime_lock:
        if default_channel_ids is not None:
            _default_channel_ids = [str(c).strip() for c in default_channel_ids if str(c).strip()]
        desired = {c.id: c for c in configs}
        to_remove = [
            cid for cid, rt in _channels.items()
            if cid not in desired or _config_changed(rt.config, desired[cid])
        ]
        for cid in to_remove:
            rt = _channels.pop(cid)
            if rt.task and not rt.task.done():
                rt.task.cancel()
                try:
                    await rt.task
                except (asyncio.CancelledError, Exception) as exc:
                    LOGGER.debug("notify channel %s: task cancel: %s", cid, exc)
        for cid, cfg in desired.items():
            if cid in _channels:
                continue
            rt = ChannelRuntime(config=cfg, queue=asyncio.Queue(maxsize=cfg.queue_size))
            rt.task = asyncio.create_task(_channel_loop(rt))
            _channels[cid] = rt


async def start_dispatcher(configs: list[ChannelConfig],
                           default_channel_ids: list[str] | None = None) -> None:
    """Lifespan entry point. Idempotent."""
    global _started
    await apply_channels(configs, default_channel_ids or [])
    _started = True


async def stop_dispatcher() -> None:
    """Cancel every channel task. Used by lifespan shutdown and tests."""
    global _started
    async with _runtime_lock:
        runtimes = list(_channels.values())
        _channels.clear()
    for rt in runtimes:
        if rt.task and not rt.task.done():
            rt.task.cancel()
            try:
                await rt.task
            except (asyncio.CancelledError, Exception) as exc:
                LOGGER.debug("notify channel %s: task cancel: %s", rt.config.id, exc)
    _started = False


def get_stats() -> list[dict]:
    """Snapshot of per-channel runtime stats for the admin API."""
    out = []
    for rt in _channels.values():
        out.append({
            "id": rt.config.id,
            "name": rt.config.name,
            "enabled": rt.config.enabled,
            "type": rt.config.type,
            "queue_depth": rt.queue.qsize(),
            "queue_size": rt.config.queue_size,
            "delivered": rt.delivered,
            "delivery_failures": rt.delivery_failures,
            "dropped_queue_full": rt.dropped_queue_full,
            "dropped_below_severity": rt.dropped_below_severity,
            "last_error": rt.last_error,
            "last_delivery_at": rt.last_delivery_at,
            "last_failure_at": rt.last_failure_at,
        })
    return out


def _probe_alert() -> dict:
    return {
        "alert_id": 0,
        "host_id": 0,
        "hostname": "plexus-test",
        "severity": "warning",
        "metric": "notification.test",
        "alert_type": "test",
        "message": "Plexus notification channel test - if you received this, "
                   "the channel is configured correctly.",
        "value": None,
        "threshold": None,
        "rule_id": None,
        "dedup_key": "plexus:notification:test",
        "timestamp": _utc_now_iso(),
    }


async def send_test_event(channel_id: str) -> dict:
    """Deliver a synthetic probe alert directly (no queue, no retry) so the
    operator gets an immediate pass/fail. Returns {ok, error}."""
    async with _runtime_lock:
        rt = _channels.get(channel_id)
    if rt is None:
        return {"ok": False, "error": f"channel {channel_id} not running"}
    try:
        await deliver(rt.config, _probe_alert())
        return {"ok": True, "error": ""}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
