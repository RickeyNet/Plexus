"""
siem_forwarder.py -- Audit-event forwarding to external SIEM systems.

Plexus audit events are tamper-evident at the database layer (migration 0037),
but auditors and SOC teams still need the events to land in their SIEM. This
module owns the engine that turns each `audit_events` row into one or more
outbound deliveries.

Architecture
------------
- Configuration is a JSON list of "sinks" persisted in `auth_settings` under
  the key `siem_sinks`. Each sink declares a protocol (udp / tcp / tls /
  https), a format (cef / json), a destination, and optional knobs
  (TLS bundle, bearer token, severity floor, etc.).
- The dispatcher is a single async task started in the FastAPI lifespan. It
  watches a per-sink bounded `asyncio.Queue`. Each enqueued event is rendered
  by the appropriate formatter and delivered by the appropriate sink driver.
- Delivery failures are retried with exponential backoff up to a configurable
  cap. When a queue is full and a new event arrives, the OLDEST queued event
  is dropped and counted; live audit inserts must never block on a wedged
  SIEM.
- Per-sink runtime stats (`delivered`, `dropped`, `last_error`, etc.) are
  exposed via the admin API so operators can see whether forwarding is
  healthy at a glance.

Failure model
-------------
This is "best effort with a memory of failure," not a durable outbox. The
SQLite hash chain remains the source of truth: if an event was inserted but
never reached the SIEM (process crash, indefinite SIEM outage), the chain
is intact and the events can be replayed manually from the database. We
deliberately do not gate audit inserts on SIEM delivery - losing the
database-side audit trail is worse than losing SIEM forwarding.
"""

from __future__ import annotations

import asyncio
import json
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.siem")

# ── Constants ────────────────────────────────────────────────────────────────

SUPPORTED_PROTOCOLS = ("udp", "tcp", "tls", "https")
SUPPORTED_FORMATS = ("cef", "json")
SUPPORTED_SEVERITIES = ("debug", "info", "notice", "warning", "error", "critical")

DEFAULT_QUEUE_SIZE = 1000
DEFAULT_MAX_RETRIES = 5
DEFAULT_BACKOFF_BASE = 1.0  # seconds
DEFAULT_BACKOFF_CAP = 60.0  # seconds
DEFAULT_HTTPS_TIMEOUT = 10.0  # seconds
DEFAULT_TCP_TIMEOUT = 10.0
DEFAULT_TLS_TIMEOUT = 10.0

# Category → severity floor used when a sink declares `severity: "info"`.
# Anything below the floor is dropped before enqueue.
_SEVERITY_ORDER = {name: i for i, name in enumerate(SUPPORTED_SEVERITIES)}
_DEFAULT_EVENT_SEVERITY = "info"

# RFC 5424 facility/severity numerics for syslog PRI computation.
# We pin facility = local0 (16) and severity = informational (6) by default.
SYSLOG_FACILITY_LOCAL0 = 16
SYSLOG_SEVERITY_BY_NAME = {
    "emerg": 0, "alert": 1, "critical": 2, "error": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}


# ── Sink config + runtime stats ──────────────────────────────────────────────

@dataclass
class SinkConfig:
    """Validated, in-memory representation of one sink row."""

    id: str
    name: str
    enabled: bool
    protocol: str          # udp | tcp | tls | https
    format: str            # cef | json
    host: str
    port: int
    url: str               # https only
    bearer_token: str      # https only
    tls_verify: bool       # tls + https
    tls_ca_pem: str        # tls + https (optional)
    tls_client_cert_pem: str  # tls (optional)
    tls_client_key_pem: str   # tls (optional)
    severity_floor: str    # debug | info | notice | warning | error | critical
    queue_size: int
    max_retries: int
    backoff_base: float
    backoff_cap: float


@dataclass
class SinkRuntime:
    """Per-sink runtime state - counters, last error, in-flight task."""

    config: SinkConfig
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
    if ival < low:
        return low
    if ival > high:
        return high
    return ival


def _coerce_float(value: Any, default: float, low: float, high: float) -> float:
    try:
        fval = float(value)
    except (TypeError, ValueError):
        return default
    if fval < low:
        return low
    if fval > high:
        return high
    return fval


def sanitize_sink(raw: dict | None) -> SinkConfig | None:
    """Validate a single sink dict; return a SinkConfig or None if invalid.

    Invalid sinks are dropped silently here - the admin API surfaces a 400 on
    create/update, this function is the safety net on load.
    """
    if not isinstance(raw, dict):
        return None
    sink_id = str(raw.get("id") or "").strip()
    if not sink_id:
        return None
    name = str(raw.get("name") or "").strip() or sink_id
    protocol = str(raw.get("protocol") or "").strip().lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        return None
    fmt = str(raw.get("format") or "json").strip().lower()
    if fmt not in SUPPORTED_FORMATS:
        return None
    severity = str(raw.get("severity_floor") or _DEFAULT_EVENT_SEVERITY).strip().lower()
    if severity not in SUPPORTED_SEVERITIES:
        severity = _DEFAULT_EVENT_SEVERITY

    host = str(raw.get("host") or "").strip()
    url = str(raw.get("url") or "").strip()
    port = _coerce_int(raw.get("port"), 514, 1, 65535)
    if protocol == "https":
        if not url.lower().startswith(("http://", "https://")):
            return None
    else:
        if not host:
            return None

    return SinkConfig(
        id=sink_id,
        name=name,
        enabled=_coerce_bool(raw.get("enabled"), True),
        protocol=protocol,
        format=fmt,
        host=host,
        port=port,
        url=url,
        bearer_token=str(raw.get("bearer_token") or ""),
        tls_verify=_coerce_bool(raw.get("tls_verify"), True),
        tls_ca_pem=str(raw.get("tls_ca_pem") or ""),
        tls_client_cert_pem=str(raw.get("tls_client_cert_pem") or ""),
        tls_client_key_pem=str(raw.get("tls_client_key_pem") or ""),
        severity_floor=severity,
        queue_size=_coerce_int(raw.get("queue_size"), DEFAULT_QUEUE_SIZE, 10, 100_000),
        max_retries=_coerce_int(raw.get("max_retries"), DEFAULT_MAX_RETRIES, 0, 20),
        backoff_base=_coerce_float(raw.get("backoff_base"), DEFAULT_BACKOFF_BASE, 0.1, 30.0),
        backoff_cap=_coerce_float(raw.get("backoff_cap"), DEFAULT_BACKOFF_CAP, 1.0, 600.0),
    )


def sanitize_sinks(raw: Any) -> list[SinkConfig]:
    """Sanitize the persisted list of sinks. Skips invalid rows."""
    if not isinstance(raw, list):
        return []
    out: list[SinkConfig] = []
    seen_ids: set[str] = set()
    for entry in raw:
        sc = sanitize_sink(entry)
        if sc is None:
            continue
        if sc.id in seen_ids:
            continue
        seen_ids.add(sc.id)
        out.append(sc)
    return out


def sink_config_to_dict(sc: SinkConfig, *, redact_secrets: bool = True) -> dict:
    """Serialize a SinkConfig back to JSON-able dict. Optionally redacts
    secrets (bearer tokens and private keys) for API responses."""
    payload = {
        "id": sc.id,
        "name": sc.name,
        "enabled": sc.enabled,
        "protocol": sc.protocol,
        "format": sc.format,
        "host": sc.host,
        "port": sc.port,
        "url": sc.url,
        "bearer_token": "••••••••" if redact_secrets and sc.bearer_token else sc.bearer_token,
        "tls_verify": sc.tls_verify,
        "tls_ca_pem": sc.tls_ca_pem,
        "tls_client_cert_pem": sc.tls_client_cert_pem,
        "tls_client_key_pem": "••••••••" if redact_secrets and sc.tls_client_key_pem else sc.tls_client_key_pem,
        "severity_floor": sc.severity_floor,
        "queue_size": sc.queue_size,
        "max_retries": sc.max_retries,
        "backoff_base": sc.backoff_base,
        "backoff_cap": sc.backoff_cap,
    }
    return payload


# ── Formatters ───────────────────────────────────────────────────────────────

def _category_to_severity(category: str, action: str) -> str:
    """Map an audit category/action to a SIEM severity name.

    The chain itself doesn't carry severity; we derive one for SIEM filtering.
    Authentication failures and security-relevant events get warning/error,
    everything else gets info. This is a pragmatic default - operators can
    bump or lower the per-sink floor to control noise.
    """
    cat = (category or "").lower()
    act = (action or "").lower()
    if cat == "auth":
        if "fail" in act or "lock" in act or "denied" in act:
            return "warning"
        return "info"
    if cat == "security" or "tamper" in act:
        return "critical"
    if "delete" in act or "destroy" in act:
        return "notice"
    return "info"


def _cef_escape(value: str) -> str:
    """CEF escapes backslashes and pipes; also escape newlines."""
    return (
        (value or "")
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _cef_extension_escape(value: str) -> str:
    """CEF extension fields escape backslash, equals, and newline."""
    return (
        (value or "")
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _cef_severity(name: str) -> int:
    """Map our severity name to CEF severity 0-10."""
    table = {
        "debug": 1, "info": 3, "notice": 4, "warning": 6, "error": 8, "critical": 10,
    }
    return table.get(name, 3)


def format_cef(event: dict) -> str:
    """Render an audit event as a CEF 1.0 line.

    Layout: ``CEF:0|Plexus|NMS|1.0|<category.action>|<action>|<sev>|<exts>``
    """
    category = event.get("category", "")
    action = event.get("action", "")
    severity_name = event.get("severity") or _category_to_severity(category, action)
    sev = _cef_severity(severity_name)

    header = "|".join([
        "CEF:0",
        _cef_escape("Plexus"),
        _cef_escape("NMS"),
        _cef_escape("1.0"),
        _cef_escape(f"{category}.{action}" or "audit.event"),
        _cef_escape(action or "event"),
        str(sev),
    ])

    extensions = {
        "rt": event.get("timestamp", ""),
        "suser": event.get("user", ""),
        "act": action,
        "cs1": event.get("correlation_id", ""),
        "cs1Label": "correlationId",
        "cs2": event.get("row_hash", ""),
        "cs2Label": "rowHash",
        "msg": event.get("detail", ""),
        "cat": category,
        "externalId": str(event.get("id", "")),
    }
    ext_parts = []
    for key, value in extensions.items():
        ext_parts.append(f"{key}={_cef_extension_escape(str(value))}")
    return f"{header}|{' '.join(ext_parts)}"


def format_json(event: dict) -> str:
    """Render an audit event as ECS-shaped JSON (one line, no trailing newline).

    Field naming follows Elastic Common Schema where reasonable. SIEM platforms
    (Splunk, Sentinel, Elastic) all accept ECS shape natively.
    """
    category = event.get("category", "")
    action = event.get("action", "")
    severity_name = event.get("severity") or _category_to_severity(category, action)
    payload = {
        "@timestamp": event.get("timestamp", ""),
        "event": {
            "kind": "event",
            "category": [category] if category else [],
            "action": action,
            "outcome": "success",
            "severity": _cef_severity(severity_name),
            "module": "plexus",
            "dataset": "plexus.audit",
            "id": event.get("id"),
        },
        "user": {"name": event.get("user", "")},
        "trace": {"id": event.get("correlation_id", "")},
        "message": event.get("detail", ""),
        "plexus": {
            "row_hash": event.get("row_hash", ""),
            "prev_hash": event.get("prev_hash", ""),
        },
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def render_event(event: dict, fmt: str) -> str:
    if fmt == "cef":
        return format_cef(event)
    return format_json(event)


# ── Syslog framing ───────────────────────────────────────────────────────────

def _syslog_pri(severity_name: str) -> int:
    sev = SYSLOG_SEVERITY_BY_NAME.get(severity_name, 6)
    return SYSLOG_FACILITY_LOCAL0 * 8 + sev


def _syslog_header(severity_name: str, timestamp: str) -> str:
    """RFC 5424 header. Note: timestamp string is forwarded as-is; SIEMs are
    generally tolerant of either RFC 3339 or the legacy syslog date.
    """
    pri = _syslog_pri(severity_name)
    iso = timestamp or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = "-"
    app_name = "plexus"
    procid = "-"
    msgid = "audit"
    return f"<{pri}>1 {iso} {hostname} {app_name} {procid} {msgid} -"


def wrap_syslog(event: dict, payload: str) -> str:
    severity_name = event.get("severity") or _category_to_severity(
        event.get("category", ""), event.get("action", "")
    )
    return f"{_syslog_header(severity_name, event.get('timestamp', ''))} {payload}"


def frame_octet_counting(message: str) -> bytes:
    """RFC 6587 §3.4.1: ``<len> SP <message>`` for TCP/TLS framing."""
    encoded = message.encode("utf-8")
    return f"{len(encoded)} ".encode("ascii") + encoded


# ── Sink drivers ─────────────────────────────────────────────────────────────

async def _deliver_udp(sink: SinkConfig, message: str) -> None:
    """Best-effort UDP send. We don't open a long-lived socket because UDP is
    connectionless and per-event create/close is cheap relative to the SIEM
    latency itself."""
    loop = asyncio.get_running_loop()
    transport, _proto = await loop.create_datagram_endpoint(
        lambda: asyncio.DatagramProtocol(),
        remote_addr=(sink.host, sink.port),
    )
    try:
        transport.sendto(message.encode("utf-8"))
    finally:
        transport.close()


async def _deliver_tcp(sink: SinkConfig, message: str) -> None:
    """TCP with RFC 6587 octet-counting framing. Reconnects per event."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(sink.host, sink.port),
        timeout=DEFAULT_TCP_TIMEOUT,
    )
    try:
        writer.write(frame_octet_counting(message))
        await asyncio.wait_for(writer.drain(), timeout=DEFAULT_TCP_TIMEOUT)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _build_tls_context(sink: SinkConfig) -> ssl.SSLContext:
    """Build an SSLContext from the sink's TLS bundle.

    - tls_verify=False disables certificate verification entirely (DEV ONLY).
    - tls_ca_pem, when set, is used as the only trust anchor.
    - Client cert/key, when both set, are loaded for mutual TLS.
    """
    ctx = ssl.create_default_context()
    if not sink.tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if sink.tls_ca_pem.strip():
        ctx.load_verify_locations(cadata=sink.tls_ca_pem)
    if sink.tls_client_cert_pem.strip() and sink.tls_client_key_pem.strip():
        import tempfile, os as _os
        # SSLContext.load_cert_chain demands paths. Materialize PEMs into
        # temp files for the duration of context construction, then unlink.
        cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
        key_fd, key_path = tempfile.mkstemp(suffix=".pem")
        try:
            with _os.fdopen(cert_fd, "w") as f:
                f.write(sink.tls_client_cert_pem)
            with _os.fdopen(key_fd, "w") as f:
                f.write(sink.tls_client_key_pem)
            ctx.load_cert_chain(cert_path, key_path)
        finally:
            try: _os.unlink(cert_path)
            except OSError: pass
            try: _os.unlink(key_path)
            except OSError: pass
    return ctx


async def _deliver_tls(sink: SinkConfig, message: str) -> None:
    """RFC 5425: syslog over TLS with octet-counting framing."""
    ctx = _build_tls_context(sink)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(sink.host, sink.port, ssl=ctx),
        timeout=DEFAULT_TLS_TIMEOUT,
    )
    try:
        writer.write(frame_octet_counting(message))
        await asyncio.wait_for(writer.drain(), timeout=DEFAULT_TLS_TIMEOUT)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _deliver_https(sink: SinkConfig, message: str) -> None:
    """POST JSON body to the configured URL. CEF is sent as text/plain.

    Splunk HEC, Sentinel custom log ingestion, Datadog, and Elastic all accept
    a single JSON body per request. Bulk batching is intentionally out of
    scope for v1 - audit volume is low.
    """
    headers = {}
    if sink.bearer_token:
        headers["Authorization"] = f"Bearer {sink.bearer_token}"
    if sink.format == "cef":
        headers["Content-Type"] = "text/plain; charset=utf-8"
    else:
        headers["Content-Type"] = "application/json"

    verify: Any = True
    if not sink.tls_verify:
        verify = False
    elif sink.tls_ca_pem.strip():
        verify = ssl.create_default_context(cadata=sink.tls_ca_pem)

    async with httpx.AsyncClient(timeout=DEFAULT_HTTPS_TIMEOUT, verify=verify) as client:
        resp = await client.post(sink.url, content=message.encode("utf-8"), headers=headers)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"https sink {sink.id}: HTTP {resp.status_code} {resp.text[:200]}"
            )


async def deliver(sink: SinkConfig, event: dict) -> None:
    """Format and send one event. Raises on failure."""
    rendered = render_event(event, sink.format)
    # For syslog-family sinks we wrap with a header; HTTPS sends the raw payload.
    if sink.protocol in ("udp", "tcp", "tls"):
        message = wrap_syslog(event, rendered)
    else:
        message = rendered

    if sink.protocol == "udp":
        await _deliver_udp(sink, message)
    elif sink.protocol == "tcp":
        await _deliver_tcp(sink, message)
    elif sink.protocol == "tls":
        await _deliver_tls(sink, message)
    elif sink.protocol == "https":
        await _deliver_https(sink, message)
    else:
        raise ValueError(f"unsupported protocol: {sink.protocol}")


# ── Dispatcher ───────────────────────────────────────────────────────────────

_runtime_lock = asyncio.Lock()
_sinks: dict[str, SinkRuntime] = {}
_started = False


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _sink_loop(rt: SinkRuntime) -> None:
    """One asyncio task per sink. Pulls events from the queue, formats,
    sends, and retries with exponential backoff. Bounded by max_retries."""
    sink = rt.config
    LOGGER.info("siem sink %s: started (%s %s:%s, fmt=%s)",
                sink.id, sink.protocol, sink.host or sink.url, sink.port, sink.format)
    try:
        while True:
            event = await rt.queue.get()
            try:
                attempt = 0
                while True:
                    try:
                        await deliver(sink, event)
                        rt.delivered += 1
                        rt.last_delivery_at = _utc_now_iso()
                        break
                    except Exception as exc:
                        attempt += 1
                        rt.delivery_failures += 1
                        rt.last_error = f"{type(exc).__name__}: {exc}"
                        rt.last_failure_at = _utc_now_iso()
                        if attempt > sink.max_retries:
                            LOGGER.warning(
                                "siem sink %s: giving up on event id=%s after %d attempts: %s",
                                sink.id, event.get("id"), attempt, rt.last_error,
                            )
                            break
                        delay = min(sink.backoff_cap, sink.backoff_base * (2 ** (attempt - 1)))
                        await asyncio.sleep(delay)
            finally:
                rt.queue.task_done()
    except asyncio.CancelledError:
        LOGGER.info("siem sink %s: stopping", sink.id)
        raise


async def enqueue_event(event: dict) -> None:
    """Fan the event out to every enabled sink. Never raises."""
    async with _runtime_lock:
        sinks = list(_sinks.values())
    for rt in sinks:
        if not rt.config.enabled:
            continue
        # Severity floor - drop events below the per-sink threshold.
        sev = event.get("severity") or _category_to_severity(
            event.get("category", ""), event.get("action", "")
        )
        if _SEVERITY_ORDER.get(sev, 1) < _SEVERITY_ORDER.get(rt.config.severity_floor, 1):
            rt.dropped_below_severity += 1
            continue
        try:
            rt.queue.put_nowait(event)
        except asyncio.QueueFull:
            # Drop oldest to make room. This is the documented bounded-queue
            # policy - protect the audit insert path from SIEM backpressure.
            try:
                rt.queue.get_nowait()
                rt.queue.task_done()
                rt.dropped_queue_full += 1
            except asyncio.QueueEmpty:
                pass
            try:
                rt.queue.put_nowait(event)
            except asyncio.QueueFull:
                rt.dropped_queue_full += 1


async def apply_sinks(configs: list[SinkConfig]) -> None:
    """Reconcile the running sink set against a new desired config list.

    - New sinks: create queue + task.
    - Removed sinks: cancel task, drain queue.
    - Changed sinks: cancel-and-recreate. Cheap because the queues are
      small. (We could be smarter, but reconfigures are rare.)
    """
    async with _runtime_lock:
        desired: dict[str, SinkConfig] = {sc.id: sc for sc in configs}
        # Cancel removed or changed.
        to_remove: list[str] = []
        for sink_id, rt in _sinks.items():
            new_cfg = desired.get(sink_id)
            if new_cfg is None or _config_changed(rt.config, new_cfg):
                to_remove.append(sink_id)
        for sink_id in to_remove:
            rt = _sinks.pop(sink_id)
            if rt.task and not rt.task.done():
                rt.task.cancel()
                try:
                    await rt.task
                except (asyncio.CancelledError, Exception):
                    pass

        # Start fresh ones.
        for sink_id, cfg in desired.items():
            if sink_id in _sinks:
                continue
            rt = SinkRuntime(
                config=cfg,
                queue=asyncio.Queue(maxsize=cfg.queue_size),
            )
            rt.task = asyncio.create_task(_sink_loop(rt))
            _sinks[sink_id] = rt


def _config_changed(old: SinkConfig, new: SinkConfig) -> bool:
    """Cheap field-by-field compare. dataclass __eq__ would also work, but
    being explicit guards against forgetting to refresh the loop on a new
    field."""
    for f in (
        "enabled", "protocol", "format", "host", "port", "url",
        "bearer_token", "tls_verify", "tls_ca_pem",
        "tls_client_cert_pem", "tls_client_key_pem", "severity_floor",
        "queue_size", "max_retries", "backoff_base", "backoff_cap",
    ):
        if getattr(old, f) != getattr(new, f):
            return True
    return False


async def start_dispatcher(configs: list[SinkConfig]) -> None:
    """Lifespan entry point. Idempotent - safe to call twice."""
    global _started
    await apply_sinks(configs)
    _started = True


async def stop_dispatcher() -> None:
    """Cancel every sink task. Used by lifespan shutdown and by tests."""
    global _started
    async with _runtime_lock:
        runtimes = list(_sinks.values())
        _sinks.clear()
    for rt in runtimes:
        if rt.task and not rt.task.done():
            rt.task.cancel()
            try:
                await rt.task
            except (asyncio.CancelledError, Exception):
                pass
    _started = False


def get_stats() -> list[dict]:
    """Snapshot of per-sink runtime stats for the admin API."""
    out = []
    for rt in _sinks.values():
        out.append({
            "id": rt.config.id,
            "name": rt.config.name,
            "enabled": rt.config.enabled,
            "protocol": rt.config.protocol,
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


async def send_test_event(sink_id: str) -> dict:
    """Synthesize a probe event and deliver it directly (no queue, no retry)
    so the operator gets an immediate pass/fail. Returns {ok, error}."""
    async with _runtime_lock:
        rt = _sinks.get(sink_id)
    if rt is None:
        return {"ok": False, "error": f"sink {sink_id} not running"}
    probe = {
        "id": 0,
        "timestamp": _utc_now_iso(),
        "category": "system",
        "action": "siem.test",
        "user": "system",
        "detail": f"Plexus SIEM probe to sink {sink_id}",
        "correlation_id": "",
        "prev_hash": "",
        "row_hash": "",
        "severity": "info",
    }
    try:
        await deliver(rt.config, probe)
        return {"ok": True, "error": ""}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
