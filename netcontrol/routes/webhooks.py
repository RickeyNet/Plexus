"""
webhooks.py -- Outbound event webhooks: POST to a URL when an object changes.

The DB facade emits a structured object-change event for every create, update
and delete of the tracked object types (``routes.db.change_events``). This
module subscribes to those events, matches each against the enabled webhooks
(object type, action, optional field filters) and delivers one HTTP request
per matching webhook.

Delivery
--------
- Each webhook has its own bounded queue and ``concurrency`` worker tasks, so
  a slow receiver never holds up another webhook. A full queue drops the
  oldest pending delivery (counted in the stats); the object write that
  caused the event never waits on a receiver.
- A delivery is one request with ``X-Plexus-Event``, ``X-Plexus-Delivery``
  (a UUID shared by every attempt and redelivery of the same event, so a
  receiver can de-duplicate) and, when the webhook has a secret,
  ``X-Plexus-Signature-256: sha256=<hex HMAC-SHA256 of the body>``.
- A transport error, a timeout, HTTP 408 / 429 or a 5xx response is retried
  with exponential backoff up to ``max_retries``; another 4xx, a template
  error or a target the SSRF guard rejects is not.
- Every attempt is written to ``webhook_deliveries``; rows older than
  ``APP_WEBHOOK_DELIVERY_RETENTION_DAYS`` (default 30) are pruned hourly.

Safety
------
- The target goes through the shared SSRF guard (``outbound_http``) when it
  is saved and again before every request; redirects are never followed.
- The payload is built only from the event: credential secrets, config text
  and job parameters never enter an event, and the payload is passed through
  the shared redaction (``netcontrol.mcp.redact.redact_value``) as well.
- The signing secret and the custom headers are stored encrypted
  (``routes.crypto``) and come back from the API masked.
- Webhook configuration is not a tracked object type and deliveries write no
  audit events, so changing a webhook (which is audit-logged) or delivering
  one can never cause another delivery.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import ssl
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from routes.crypto import decrypt, encrypt
from routes.db.change_events import (
    CHANGE_ACTIONS,
    CHANGE_OBJECT_TYPES,
    add_object_change_hook,
    remove_object_change_hook,
)

from netcontrol.intended_config import Renderer, check_syntax
from netcontrol.mcp.redact import redact_value
from netcontrol.routes.outbound_http import (
    DELIVERY_RESPONSE_MAX_BYTES,
    OutboundRequestError,
    guard_url,
    send_request,
    tls_verify,
)
from netcontrol.routes.shared import _audit, _corr_id, _session_user
from netcontrol.secret_fields import (
    SECRET_MASK as REDACTION_MASK,
    compared_tls_verify,
    refuse_secret_reuse,
    url_origin,
)
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.webhooks")

router = APIRouter()

# ── Constants ────────────────────────────────────────────────────────────────

SUPPORTED_METHODS = ("POST", "PUT", "PATCH")
DEFAULT_CONTENT_TYPE = "application/json"
QUEUE_SIZE = 1000
BACKOFF_BASE = 2.0  # seconds before the first retry; doubles per retry
BACKOFF_CAP = 300.0
RESPONSE_KEEP = 2000  # characters of the response body kept in the log
ERROR_KEEP = 500
REQUEST_BODY_KEEP = 262_144  # bodies larger than this are not kept for redelivery
PRUNE_INTERVAL = 3600.0
REFRESH_INTERVAL = 30.0
DEFAULT_RETENTION_DAYS = 30
USER_AGENT = "Plexus-Webhooks/1"
TEST_EVENT = "webhook.test"

_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
_FILTER_KEY = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
_CONTENT_TYPE = re.compile(
    r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(\s*;\s*[A-Za-z0-9_.+-]+=[A-Za-z0-9_.+\"-]+)*$"
)
# Headers Plexus sets itself; a custom header may not replace them.
_RESERVED_HEADERS = frozenset(
    {"content-type", "content-length", "host", "user-agent", "transfer-encoding", "connection"}
)


def retention_days() -> int:
    try:
        return max(1, int(os.getenv("APP_WEBHOOK_DELIVERY_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS))))
    except ValueError:
        return DEFAULT_RETENTION_DAYS


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Config ───────────────────────────────────────────────────────────────────


@dataclass
class WebhookConfig:
    """A stored webhook with its secret and headers decrypted."""

    id: int
    name: str
    enabled: bool
    url: str
    http_method: str
    content_type: str
    object_types: tuple[str, ...]
    actions: tuple[str, ...]
    filters: dict[str, list[str]]
    headers: dict[str, str]
    body_template: str
    secret: str
    verify_tls: bool
    ca_bundle: str
    timeout_seconds: float
    max_retries: int
    concurrency: int


def _json_list(raw: Any) -> list:
    try:
        value = json.loads(raw or "[]")
    except TypeError, ValueError:
        return []
    return value if isinstance(value, list) else []


def _json_dict(raw: Any) -> dict:
    try:
        value = json.loads(raw or "{}")
    except TypeError, ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _decrypt_or_empty(value: str, what: str, webhook_id: Any) -> str:
    if not value:
        return ""
    try:
        return decrypt(value)
    except RuntimeError:
        LOGGER.warning("webhook %s: stored %s does not decrypt; treating it as unset", webhook_id, what)
        return ""


def _decrypt_headers(row: dict) -> dict[str, str]:
    raw = _decrypt_or_empty(row.get("headers_enc") or "", "headers", row.get("id"))
    return {str(k): str(v) for k, v in _json_dict(raw).items()}


def config_from_row(row: dict) -> WebhookConfig:
    return WebhookConfig(
        id=int(row["id"]),
        name=str(row.get("name") or ""),
        enabled=bool(row.get("enabled")),
        url=str(row.get("url") or ""),
        http_method=str(row.get("http_method") or "POST").upper(),
        content_type=str(row.get("content_type") or DEFAULT_CONTENT_TYPE),
        object_types=tuple(str(t) for t in _json_list(row.get("object_types_json"))),
        actions=tuple(str(a) for a in _json_list(row.get("actions_json"))),
        filters={
            str(k): [str(x) for x in v] for k, v in _json_dict(row.get("filters_json")).items() if isinstance(v, list)
        },
        headers=_decrypt_headers(row),
        body_template=str(row.get("body_template") or ""),
        secret=_decrypt_or_empty(row.get("secret_enc") or "", "secret", row.get("id")),
        verify_tls=bool(row.get("verify_tls")),
        ca_bundle=str(row.get("ca_bundle") or ""),
        timeout_seconds=float(row.get("timeout_seconds") or 10.0),
        max_retries=int(row.get("max_retries") or 0),
        concurrency=max(1, int(row.get("concurrency") or 1)),
    )


def public_view(row: dict) -> dict:
    """A stored webhook as the API returns it: the secret and header values
    masked, never decrypted."""
    headers = _decrypt_headers(row)
    return {
        "id": int(row["id"]),
        "name": row.get("name") or "",
        "enabled": bool(row.get("enabled")),
        "url": row.get("url") or "",
        "http_method": row.get("http_method") or "POST",
        "content_type": row.get("content_type") or DEFAULT_CONTENT_TYPE,
        "object_types": _json_list(row.get("object_types_json")),
        "actions": _json_list(row.get("actions_json")),
        "filters": _json_dict(row.get("filters_json")),
        "headers": {name: REDACTION_MASK for name in headers},
        "has_secret": bool(row.get("secret_enc")),
        "secret": REDACTION_MASK if row.get("secret_enc") else "",
        "body_template": row.get("body_template") or "",
        "verify_tls": bool(row.get("verify_tls")),
        "ca_bundle": row.get("ca_bundle") or "",
        "timeout_seconds": float(row.get("timeout_seconds") or 10.0),
        "max_retries": int(row.get("max_retries") or 0),
        "concurrency": int(row.get("concurrency") or 1),
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at") or "",
        "updated_at": row.get("updated_at") or "",
    }


class WebhookRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    enabled: bool = True
    url: str = Field(min_length=1, max_length=2000)
    http_method: str = "POST"
    content_type: str = Field(default=DEFAULT_CONTENT_TYPE, max_length=200)
    object_types: list[str] = Field(default_factory=list, max_length=len(CHANGE_OBJECT_TYPES))
    actions: list[str] = Field(default_factory=lambda: list(CHANGE_ACTIONS), max_length=len(CHANGE_ACTIONS))
    filters: dict[str, list[str | int]] = Field(default_factory=dict, max_length=20)
    headers: dict[str, str] = Field(default_factory=dict, max_length=30)
    body_template: str = Field(default="", max_length=20000)
    # None or the mask keeps the stored secret; "" clears it.
    secret: str | None = Field(default=None, max_length=500)
    verify_tls: bool = True
    ca_bundle: str = Field(default="", max_length=100_000)
    timeout_seconds: float = Field(default=10.0, ge=1, le=60)
    max_retries: int = Field(default=3, ge=0, le=10)
    concurrency: int = Field(default=2, ge=1, le=10)


async def build_columns(body: WebhookRequest, existing: dict | None) -> dict:
    """Validate a request and turn it into ``webhooks`` columns. Raises
    ``ValueError`` with a message for the client."""
    url = body.url.strip()
    try:
        await guard_url(url)
    except OutboundRequestError as exc:
        raise ValueError(f"Target URL rejected: {exc}") from exc
    method = body.http_method.strip().upper()
    if method not in SUPPORTED_METHODS:
        raise ValueError(f"HTTP method must be one of {', '.join(SUPPORTED_METHODS)}.")
    content_type = body.content_type.strip() or DEFAULT_CONTENT_TYPE
    if not _CONTENT_TYPE.match(content_type):
        raise ValueError("Content type must look like 'application/json'.")
    object_types = sorted({t.strip() for t in body.object_types if t.strip()})
    unknown = [t for t in object_types if t not in CHANGE_OBJECT_TYPES]
    if unknown or not object_types:
        raise ValueError(f"Choose at least one object type from: {', '.join(CHANGE_OBJECT_TYPES)}.")
    actions = [a for a in CHANGE_ACTIONS if a in {x.strip() for x in body.actions}]
    if not actions or len(actions) != len({x.strip() for x in body.actions}):
        raise ValueError(f"Choose at least one action from: {', '.join(CHANGE_ACTIONS)}.")
    filters: dict[str, list[str]] = {}
    for key, values in body.filters.items():
        if not _FILTER_KEY.match(key):
            raise ValueError(f"Filter field '{key}' must be a lower-case field name such as group_id.")
        cleaned = [str(v).strip() for v in values if str(v).strip()][:100]
        if cleaned:
            filters[key] = cleaned
    old_headers = _decrypt_headers(existing) if existing else {}
    kept: list[str] = []  # stored secrets this request keeps without sending them
    headers: dict[str, str] = {}
    for name, value in body.headers.items():
        name = name.strip()
        if not _HEADER_NAME.match(name):
            raise ValueError(f"Header name '{name}' is not valid.")
        if name.lower() in _RESERVED_HEADERS or name.lower().startswith("x-plexus-"):
            raise ValueError(f"Header '{name}' is set by Plexus and cannot be overridden.")
        if value == REDACTION_MASK:
            if name not in old_headers:
                raise ValueError(f"Header '{name}' has no stored value to keep; enter one.")
            value = old_headers[name]
            kept.append(f"header {name}")
        if any(c in value for c in "\r\n\x00") or len(value) > 4000:
            raise ValueError(f"Header '{name}' has a value that is too long or contains a line break.")
        headers[name] = value
    template = body.body_template
    if template.strip():
        issue = check_syntax(template, "body")
        if issue is not None:
            raise ValueError(f"Body template: {issue.as_text()}")
    ca_bundle = body.ca_bundle.strip()
    if ca_bundle:
        try:
            tls_verify(True, ca_bundle)
        except (ssl.SSLError, ValueError) as exc:
            raise ValueError("CA bundle is not a valid PEM certificate bundle.") from exc
    if body.secret is None or body.secret == REDACTION_MASK:
        secret_enc = (existing or {}).get("secret_enc") or ""
        if secret_enc:
            kept.append("signing secret")
    else:
        secret_enc = encrypt(body.secret) if body.secret else ""
    if existing is not None:
        # The stored header values and secret go to the target URL: one that
        # changes where they go must send them again.
        old_verify = bool(existing.get("verify_tls"))
        refuse_secret_reuse(
            {
                "url": url_origin(existing.get("url")),
                "verify_tls": old_verify,
                "ca_bundle": str(existing.get("ca_bundle") or "").strip(),
            },
            {
                "url": url_origin(url),
                "verify_tls": compared_tls_verify(old_verify, body.verify_tls),
                "ca_bundle": ca_bundle,
            },
            ("url", "verify_tls", "ca_bundle"),
            stored=kept,
            resent=[],
        )
    return {
        "name": body.name.strip(),
        "enabled": 1 if body.enabled else 0,
        "url": url,
        "http_method": method,
        "content_type": content_type,
        "object_types_json": json.dumps(object_types),
        "actions_json": json.dumps(actions),
        "filters_json": json.dumps(filters, sort_keys=True),
        "headers_enc": encrypt(json.dumps(headers, sort_keys=True)) if headers else "",
        "body_template": template if template.strip() else "",
        "secret_enc": secret_enc,
        "verify_tls": 1 if body.verify_tls else 0,
        "ca_bundle": ca_bundle,
        "timeout_seconds": float(body.timeout_seconds),
        "max_retries": int(body.max_retries),
        "concurrency": int(body.concurrency),
    }


# ── Matching and payload ─────────────────────────────────────────────────────


def _filter_value(event: dict, snapshot: dict, key: str) -> Any:
    # A group's own id answers a group filter.
    if key == "group_id" and event.get("object_type") == "group":
        return snapshot.get("id")
    return snapshot.get(key)


def matches(cfg: WebhookConfig, event: dict) -> bool:
    """Whether the webhook takes the event: enabled, the object type and
    action subscribed, and every filter field of the object (before or after
    the change) one of the allowed values."""
    if not cfg.enabled:
        return False
    if event.get("object_type") not in cfg.object_types or event.get("action") not in cfg.actions:
        return False
    if not cfg.filters:
        return True
    for snapshot in (event.get("after"), event.get("before")):
        if not isinstance(snapshot, dict):
            continue
        if all(str(_filter_value(event, snapshot, k)) in allowed for k, allowed in cfg.filters.items()):
            return True
    return False


def build_payload(event: dict, delivery_id: str) -> dict:
    """The JSON document a webhook receives (see docs/webhooks.md)."""
    payload = {
        "event": event.get("event", ""),
        "delivery_id": delivery_id,
        "timestamp": event.get("timestamp", ""),
        "object_type": event.get("object_type", ""),
        "object_id": event.get("object_id", ""),
        "action": event.get("action", ""),
        "user": event.get("user", ""),
        "data": event.get("after") if event.get("after") is not None else event.get("before"),
        "snapshots": {"before": event.get("before"), "after": event.get("after")},
        "changes": event.get("changes") or {},
    }
    return redact_value(payload)


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


class TemplateRenderError(ValueError):
    pass


def render_body(cfg: WebhookConfig, payload: dict) -> str:
    if not cfg.body_template:
        return json.dumps(payload, separators=(",", ":"), default=str)
    result = Renderer({"body": cfg.body_template}).render("body", {**payload, "payload": payload})
    if not result.ok:
        assert result.error is not None  # nosec B101 - not ok means an error
        raise TemplateRenderError(f"body template: {result.error.as_text()}")
    return result.config_text


def build_headers(cfg: WebhookConfig, event_name: str, delivery_id: str, body: bytes) -> dict[str, str]:
    headers = dict(cfg.headers)
    headers["Content-Type"] = cfg.content_type
    headers["User-Agent"] = USER_AGENT
    headers["X-Plexus-Event"] = event_name
    headers["X-Plexus-Delivery"] = delivery_id
    if cfg.secret:
        headers["X-Plexus-Signature-256"] = sign(cfg.secret, body)
    return headers


# ── Delivery ─────────────────────────────────────────────────────────────────


@dataclass
class DeliveryJob:
    webhook_id: int
    delivery_id: str
    event: str
    object_type: str
    object_id: str
    action: str
    payload: dict | None = None
    body: str | None = None  # set once rendered, so retries resend it unchanged
    attempt: int = 1


@dataclass
class DeliveryOutcome:
    ok: bool
    retry: bool
    status: str
    status_code: int | None = None
    latency_ms: float | None = None
    error: str = ""


def _retryable(code: int) -> bool:
    return code >= 500 or code in (408, 429)


async def deliver_once(cfg: WebhookConfig, job: DeliveryJob, *, allow_retry: bool = True) -> DeliveryOutcome:
    """Send one attempt and log it. Never raises."""
    outcome: DeliveryOutcome
    response_text = ""
    try:
        if job.body is None:
            job.body = await asyncio.to_thread(render_body, cfg, job.payload or {})
    except Exception as exc:
        outcome = DeliveryOutcome(False, False, "failed", error=str(exc)[:ERROR_KEEP])
    else:
        body = job.body.encode("utf-8")
        headers = build_headers(cfg, job.event, job.delivery_id, body)
        started = time.monotonic()
        try:
            resp = await send_request(
                cfg.http_method,
                cfg.url,
                content=body,
                headers=headers,
                verify=tls_verify(cfg.verify_tls, cfg.ca_bundle),
                timeout_s=cfg.timeout_seconds,
                max_bytes=DELIVERY_RESPONSE_MAX_BYTES,
                truncate=True,
            )
        except OutboundRequestError as exc:
            outcome = DeliveryOutcome(False, False, "blocked", error=f"target rejected: {exc}"[:ERROR_KEEP])
        except Exception as exc:
            latency = round((time.monotonic() - started) * 1000, 1)
            outcome = DeliveryOutcome(
                False, True, "retrying", None, latency, f"{type(exc).__name__}: {exc}"[:ERROR_KEEP]
            )
        else:
            latency = round((time.monotonic() - started) * 1000, 1)
            response_text = resp.text[:RESPONSE_KEEP]
            code = resp.status_code
            if 200 <= code < 300:
                outcome = DeliveryOutcome(True, False, "success", code, latency)
            else:
                outcome = DeliveryOutcome(False, _retryable(code), "retrying", code, latency, f"HTTP {code}")
    if outcome.retry and (not allow_retry or job.attempt > cfg.max_retries):
        outcome.retry = False
    if not outcome.ok and not outcome.retry and outcome.status == "retrying":
        outcome.status = "failed"
    stored_body = job.body if job.body is not None and len(job.body) <= REQUEST_BODY_KEEP else ""
    try:
        await db.add_webhook_delivery(
            webhook_id=cfg.id,
            delivery_id=job.delivery_id,
            event=job.event,
            object_type=job.object_type,
            object_id=job.object_id,
            action=job.action,
            attempt=job.attempt,
            status=outcome.status,
            status_code=outcome.status_code,
            latency_ms=outcome.latency_ms,
            request_body=stored_body,
            response_body=response_text,
            error=outcome.error,
        )
    except Exception as exc:
        LOGGER.warning("webhook %s: could not log delivery %s: %s", cfg.id, job.delivery_id, type(exc).__name__)
    return outcome


@dataclass
class WebhookRuntime:
    config: WebhookConfig
    queue: asyncio.Queue
    workers: list[asyncio.Task] = field(default_factory=list)
    delivered: int = 0
    failed: int = 0
    dropped_queue_full: int = 0
    last_error: str = ""
    last_delivery_at: str = ""
    last_failure_at: str = ""


_runtimes: dict[int, WebhookRuntime] = {}
_retry_handles: set[asyncio.TimerHandle] = set()
_prune_task: asyncio.Task | None = None
_started = False
_lock = asyncio.Lock()


def _enqueue(rt: WebhookRuntime, job: DeliveryJob) -> None:
    """Drop-oldest backpressure. Never raises."""
    try:
        rt.queue.put_nowait(job)
        return
    except asyncio.QueueFull:
        pass
    try:
        rt.queue.get_nowait()
        rt.queue.task_done()
    except asyncio.QueueEmpty:
        pass
    rt.dropped_queue_full += 1
    try:
        rt.queue.put_nowait(job)
    except asyncio.QueueFull:
        rt.dropped_queue_full += 1


def _schedule_retry(job: DeliveryJob) -> None:
    delay = min(BACKOFF_CAP, BACKOFF_BASE * (2 ** max(0, job.attempt - 2)))
    loop = asyncio.get_running_loop()

    def fire() -> None:
        _retry_handles.discard(handle)
        rt = _runtimes.get(job.webhook_id)
        if rt is not None:
            _enqueue(rt, job)

    handle = loop.call_later(delay, fire)
    _retry_handles.add(handle)


async def _worker(rt: WebhookRuntime) -> None:
    while True:
        job = await rt.queue.get()
        try:
            cfg = rt.config
            outcome = await deliver_once(cfg, job)
            if outcome.ok:
                rt.delivered += 1
                rt.last_delivery_at = _utc_now_iso()
            else:
                rt.last_error = outcome.error
                rt.last_failure_at = _utc_now_iso()
                if outcome.retry:
                    job.attempt += 1
                    _schedule_retry(job)
                else:
                    rt.failed += 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("webhook %s: worker error: %s", rt.config.id, type(exc).__name__)
        finally:
            rt.queue.task_done()


def _resize_workers(rt: WebhookRuntime) -> None:
    want = rt.config.concurrency
    rt.workers = [t for t in rt.workers if not t.done()]
    while len(rt.workers) < want:
        rt.workers.append(asyncio.create_task(_worker(rt), name=f"webhook-{rt.config.id}"))
    while len(rt.workers) > want:
        rt.workers.pop().cancel()


async def _stop_runtime(rt: WebhookRuntime) -> None:
    for task in rt.workers:
        task.cancel()
    await asyncio.gather(*rt.workers, return_exceptions=True)
    rt.workers = []


def wants(object_type: str) -> bool:
    return any(rt.config.enabled and object_type in rt.config.object_types for rt in _runtimes.values())


async def on_object_change(event: dict) -> None:
    """The object-change hook: enqueue a delivery for each matching webhook."""
    for rt in list(_runtimes.values()):
        if not matches(rt.config, event):
            continue
        delivery_id = str(uuid.uuid4())
        _enqueue(
            rt,
            DeliveryJob(
                webhook_id=rt.config.id,
                delivery_id=delivery_id,
                event=str(event.get("event", "")),
                object_type=str(event.get("object_type", "")),
                object_id=str(event.get("object_id", "")),
                action=str(event.get("action", "")),
                payload=build_payload(event, delivery_id),
            ),
        )


async def reload_webhooks() -> None:
    """Re-read the webhooks from the database and apply them: new ones start,
    deleted ones stop, changed ones take effect on their next delivery."""
    if not _started:
        return
    rows = await db.list_webhooks()
    async with _lock:
        configs = {int(r["id"]): config_from_row(r) for r in rows}
        for wid in list(_runtimes):
            if wid not in configs:
                await _stop_runtime(_runtimes.pop(wid))
        for wid, cfg in configs.items():
            rt = _runtimes.get(wid)
            if rt is None:
                rt = WebhookRuntime(config=cfg, queue=asyncio.Queue(maxsize=QUEUE_SIZE))
                _runtimes[wid] = rt
            else:
                rt.config = cfg
            _resize_workers(rt)


async def _prune_loop() -> None:
    """Prune the delivery log hourly, and re-read the webhooks every
    ``REFRESH_INTERVAL`` so a change saved through another worker process
    reaches this one too (the saving process reloads at once)."""
    last_prune = 0.0
    while True:
        try:
            if time.monotonic() - last_prune >= PRUNE_INTERVAL:
                last_prune = time.monotonic()
                removed = await db.prune_webhook_deliveries(retention_days())
                if removed:
                    LOGGER.info("webhooks: pruned %d delivery log rows", removed)
            await reload_webhooks()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("webhooks: maintenance pass failed: %s", type(exc).__name__)
        await asyncio.sleep(REFRESH_INTERVAL)


async def start_dispatcher() -> None:
    global _started, _prune_task
    if _started:
        return
    _started = True
    await reload_webhooks()
    add_object_change_hook(on_object_change, wants)
    _prune_task = asyncio.create_task(_prune_loop(), name="webhook-prune")


async def stop_dispatcher() -> None:
    global _started, _prune_task
    remove_object_change_hook(on_object_change)
    _started = False
    for handle in list(_retry_handles):
        handle.cancel()
    _retry_handles.clear()
    if _prune_task is not None:
        _prune_task.cancel()
        await asyncio.gather(_prune_task, return_exceptions=True)
        _prune_task = None
    async with _lock:
        for rt in list(_runtimes.values()):
            await _stop_runtime(rt)
        _runtimes.clear()


def get_stats() -> list[dict]:
    return [
        {
            "id": wid,
            "queue_depth": rt.queue.qsize(),
            "queue_size": QUEUE_SIZE,
            "delivered": rt.delivered,
            "failed": rt.failed,
            "dropped_queue_full": rt.dropped_queue_full,
            "last_error": rt.last_error,
            "last_delivery_at": rt.last_delivery_at,
            "last_failure_at": rt.last_failure_at,
        }
        for wid, rt in _runtimes.items()
    ]


def _outcome_dict(outcome: DeliveryOutcome, delivery_id: str) -> dict:
    return {
        "ok": outcome.ok,
        "status": outcome.status,
        "status_code": outcome.status_code,
        "latency_ms": outcome.latency_ms,
        "error": outcome.error,
        "delivery_id": delivery_id,
    }


async def send_test(row: dict, user: str) -> dict:
    """Deliver one synthetic ``webhook.test`` event now (no retries)."""
    cfg = config_from_row(row)
    delivery_id = str(uuid.uuid4())
    event = {
        "event": TEST_EVENT,
        "object_type": "webhook",
        "object_id": str(cfg.id),
        "action": "test",
        "timestamp": _utc_now_iso(),
        "user": user or "system",
        "before": None,
        "after": {"id": cfg.id, "name": cfg.name},
        "changes": {},
    }
    job = DeliveryJob(
        cfg.id, delivery_id, TEST_EVENT, "webhook", str(cfg.id), "test", build_payload(event, delivery_id)
    )
    return _outcome_dict(await deliver_once(cfg, job, allow_retry=False), delivery_id)


async def redeliver(row: dict, delivery: dict) -> dict:
    """Send a logged delivery again with the same delivery id and body."""
    if not delivery.get("request_body"):
        raise ValueError("This delivery's body was not kept, so it cannot be sent again.")
    cfg = config_from_row(row)
    attempt = (
        max(int(delivery.get("attempt") or 1), await db.last_webhook_delivery_attempt(delivery["delivery_id"])) + 1
    )
    job = DeliveryJob(
        cfg.id,
        str(delivery["delivery_id"]),
        str(delivery.get("event") or ""),
        str(delivery.get("object_type") or ""),
        str(delivery.get("object_id") or ""),
        str(delivery.get("action") or ""),
        body=str(delivery["request_body"]),
        attempt=attempt,
    )
    return _outcome_dict(await deliver_once(cfg, job, allow_retry=False), job.delivery_id)


# ── API (admin only; registered with require_admin in app.py) ────────────────


async def _must_get(webhook_id: int) -> dict:
    row = await db.get_webhook(webhook_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return row


@router.get("/api/admin/webhooks")
async def list_webhooks_api():
    rows = await db.list_webhooks()
    return {
        "webhooks": [public_view(r) for r in rows],
        "stats": get_stats(),
        "object_types": list(CHANGE_OBJECT_TYPES),
        "actions": list(CHANGE_ACTIONS),
    }


@router.get("/api/admin/webhooks/{webhook_id}")
async def get_webhook_api(webhook_id: int):
    return public_view(await _must_get(webhook_id))


@router.post("/api/admin/webhooks", status_code=201)
async def create_webhook_api(body: WebhookRequest, request: Request):
    try:
        values = await build_columns(body, None)
        row = await db.create_webhook(values, created_by=_session_user(request))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await reload_webhooks()
    await _audit(
        "system",
        "webhook.create",
        user=_session_user(request),
        detail=f"webhook={row['id']} name={row['name']} types={','.join(_json_list(row['object_types_json']))}",
        correlation_id=_corr_id(request),
    )
    return public_view(row)


@router.put("/api/admin/webhooks/{webhook_id}")
async def update_webhook_api(webhook_id: int, body: WebhookRequest, request: Request):
    existing = await _must_get(webhook_id)
    try:
        values = await build_columns(body, existing)
        row = await db.update_webhook(webhook_id, values)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await reload_webhooks()
    await _audit(
        "system",
        "webhook.update",
        user=_session_user(request),
        detail=f"webhook={webhook_id} name={row['name']} enabled={bool(row['enabled'])}",
        correlation_id=_corr_id(request),
    )
    return public_view(row)


@router.delete("/api/admin/webhooks/{webhook_id}")
async def delete_webhook_api(webhook_id: int, request: Request):
    existing = await _must_get(webhook_id)
    await db.delete_webhook(webhook_id)
    await reload_webhooks()
    await _audit(
        "system",
        "webhook.delete",
        user=_session_user(request),
        detail=f"webhook={webhook_id} name={existing['name']}",
        correlation_id=_corr_id(request),
    )
    return {"ok": True}


@router.post("/api/admin/webhooks/{webhook_id}/test")
async def test_webhook_api(webhook_id: int, request: Request):
    row = await _must_get(webhook_id)
    result = await send_test(row, _session_user(request))
    await _audit(
        "system",
        "webhook.test",
        user=_session_user(request),
        detail=f"webhook={webhook_id} ok={result['ok']} status={result['status_code']}",
        correlation_id=_corr_id(request),
    )
    return result


@router.get("/api/admin/webhooks/{webhook_id}/deliveries")
async def list_deliveries_api(webhook_id: int, limit: int = Query(default=100, ge=1, le=1000)):
    await _must_get(webhook_id)
    return {"deliveries": await db.list_webhook_deliveries(webhook_id, limit)}


@router.post("/api/admin/webhooks/{webhook_id}/deliveries/{row_id}/redeliver")
async def redeliver_api(webhook_id: int, row_id: int, request: Request):
    row = await _must_get(webhook_id)
    delivery = await db.get_webhook_delivery(row_id)
    if delivery is None or int(delivery["webhook_id"]) != webhook_id:
        raise HTTPException(status_code=404, detail="Delivery not found")
    try:
        result = await redeliver(row, delivery)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await _audit(
        "system",
        "webhook.redeliver",
        user=_session_user(request),
        detail=f"webhook={webhook_id} delivery={delivery['delivery_id']} ok={result['ok']}",
        correlation_id=_corr_id(request),
    )
    return result
