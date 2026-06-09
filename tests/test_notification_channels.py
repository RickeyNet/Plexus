"""Tests for the alert notification channel engine
(netcontrol.routes.notification_channels).

Covers:
  * sanitize_channel rejects incomplete configs and accepts valid ones
  * secret redaction + merge_secrets keep-on-mask behaviour
  * parse_channel_ids accepts JSON lists, comma strings, and real lists
  * formatters (pagerduty / webhook / teams / email) produce stable output
  * severity floor filters alerts below the per-channel threshold
  * dispatcher fans out to assigned channels and falls back to defaults
  * per-rule channel assignment overrides the default set
  * bounded queue drops the oldest alert on overflow
  * retry/backoff stops after max_retries
  * webhook/teams deliver real JSON to a local HTTP listener
  * email delivery builds a MIME message and calls the SMTP path
  * send_test_event delivers a synthetic probe
"""
from __future__ import annotations

import asyncio
import json

import pytest
from netcontrol.routes import notification_channels as nc


@pytest.fixture(autouse=True)
async def _clean_dispatcher():
    """Ensure no channels leak between tests."""
    await nc.stop_dispatcher()
    yield
    await nc.stop_dispatcher()


# ── Local HTTP capture listener ──────────────────────────────────────────────

class _HttpCapture:
    """Minimal HTTP/1.1 server that captures one JSON body per request and
    replies 200 (or a configurable status). Avoids an aiohttp dependency."""

    def __init__(self, status: int = 200):
        self.status = status
        self.bodies: list[dict] = []
        self.server: asyncio.AbstractServer | None = None
        self.port = 0

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/hook"

    async def _handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            clen = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    clen = int(line.split(b":", 1)[1].strip())
            body = await reader.readexactly(clen) if clen else b""
            try:
                self.bodies.append(json.loads(body.decode() or "{}"))
            except ValueError:
                self.bodies.append({"_raw": body.decode(errors="replace")})
        except Exception as exc:  # pragma: no cover - defensive
            self.bodies.append({"_err": str(exc)})
        finally:
            writer.write(
                f"HTTP/1.1 {self.status} OK\r\nContent-Length: 1\r\n"
                f"Connection: close\r\n\r\n1".encode()
            )
            try:
                await writer.drain()
            except Exception:
                pass
            writer.close()


_ALERT = {
    "alert_id": 7,
    "host_id": 3,
    "hostname": "core-sw1",
    "severity": "critical",
    "metric": "cpu",
    "alert_type": "threshold",
    "message": "CPU utilization at 99% (threshold: 90%)",
    "value": 99.0,
    "threshold": 90.0,
    "rule_id": 2,
    "dedup_key": "3:cpu:threshold",
    "timestamp": "2026-06-08T00:00:00Z",
}


async def _wait(predicate, timeout_s: float = 3.0) -> bool:
    for _ in range(int(timeout_s / 0.02)):
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


# ── Validation / sanitization ────────────────────────────────────────────────

def test_sanitize_rejects_unknown_type():
    assert nc.sanitize_channel({"id": "x", "type": "carrier-pigeon"}) is None


def test_sanitize_rejects_webhook_without_url():
    assert nc.sanitize_channel({"id": "x", "type": "webhook"}) is None


def test_sanitize_rejects_pagerduty_without_key():
    assert nc.sanitize_channel({"id": "x", "type": "pagerduty", "routing_key": ""}) is None


def test_sanitize_rejects_email_without_recipients():
    assert nc.sanitize_channel(
        {"id": "x", "type": "email", "smtp_host": "h", "mail_from": "a@b.c", "mail_to": ""}
    ) is None


def test_sanitize_rejects_teams_without_url():
    assert nc.sanitize_channel({"id": "x", "type": "teams", "teams_webhook_url": "notaurl"}) is None


def test_sanitize_accepts_each_type():
    assert nc.sanitize_channel({"id": "w", "type": "webhook", "webhook_url": "https://x/h"})
    assert nc.sanitize_channel({"id": "p", "type": "pagerduty", "routing_key": "k"})
    assert nc.sanitize_channel({"id": "t", "type": "teams", "teams_webhook_url": "https://t/h"})
    assert nc.sanitize_channel(
        {"id": "e", "type": "email", "smtp_host": "h", "mail_from": "a@b.c", "mail_to": "x@y.z"}
    )


def test_sanitize_clamps_numeric_ranges():
    cfg = nc.sanitize_channel({
        "id": "w", "type": "webhook", "webhook_url": "https://x/h",
        "queue_size": 1, "max_retries": 999, "backoff_base": 0.001,
    })
    assert cfg.queue_size == 10
    assert cfg.max_retries == 20
    assert cfg.backoff_base == 0.1


def test_sanitize_falls_back_on_bad_severity():
    cfg = nc.sanitize_channel({"id": "w", "type": "webhook", "webhook_url": "https://x/h",
                               "severity_floor": "ALARMING"})
    assert cfg.severity_floor == "warning"


def test_sanitize_channels_dedupes_ids():
    out = nc.sanitize_channels([
        {"id": "w", "type": "webhook", "webhook_url": "https://x/h"},
        {"id": "w", "type": "webhook", "webhook_url": "https://y/h"},
        {"id": "bad", "type": "webhook"},
    ])
    assert [c.id for c in out] == ["w"]


# ── Secret handling ──────────────────────────────────────────────────────────

def test_redaction_masks_secrets():
    cfg = nc.sanitize_channel({"id": "p", "type": "pagerduty", "routing_key": "supersecret"})
    redacted = nc.channel_config_to_dict(cfg)
    assert redacted["routing_key"] == nc.REDACTION_MASK
    clear = nc.channel_config_to_dict(cfg, redact_secrets=False)
    assert clear["routing_key"] == "supersecret"


def test_merge_secrets_keeps_existing_on_mask():
    existing = nc.sanitize_channel({"id": "p", "type": "pagerduty", "routing_key": "keepme"})
    incoming = {"id": "p", "type": "pagerduty", "routing_key": nc.REDACTION_MASK}
    merged = nc.merge_secrets(incoming, existing)
    assert merged["routing_key"] == "keepme"


def test_merge_secrets_overwrites_when_provided():
    existing = nc.sanitize_channel({"id": "p", "type": "pagerduty", "routing_key": "old"})
    merged = nc.merge_secrets({"id": "p", "type": "pagerduty", "routing_key": "new"}, existing)
    assert merged["routing_key"] == "new"


# ── parse_channel_ids ────────────────────────────────────────────────────────

def test_parse_channel_ids_variants():
    assert nc.parse_channel_ids('["a","b"]') == ["a", "b"]
    assert nc.parse_channel_ids("a, b ,c") == ["a", "b", "c"]
    assert nc.parse_channel_ids(["a", "b"]) == ["a", "b"]
    assert nc.parse_channel_ids("") == []
    assert nc.parse_channel_ids(None) == []


# ── Formatters ───────────────────────────────────────────────────────────────

def test_format_pagerduty_shape():
    cfg = nc.sanitize_channel({"id": "p", "type": "pagerduty", "routing_key": "rk"})
    body = nc.format_pagerduty(_ALERT, cfg)
    assert body["routing_key"] == "rk"
    assert body["event_action"] == "trigger"
    assert body["dedup_key"] == "3:cpu:threshold"
    assert body["payload"]["severity"] == "critical"
    assert body["payload"]["source"] == "core-sw1"
    assert body["payload"]["custom_details"]["value"] == 99.0


def test_format_pagerduty_maps_warning():
    cfg = nc.sanitize_channel({"id": "p", "type": "pagerduty", "routing_key": "rk"})
    body = nc.format_pagerduty({**_ALERT, "severity": "warning"}, cfg)
    assert body["payload"]["severity"] == "warning"


def test_format_webhook_shape():
    body = nc.format_webhook(_ALERT)
    assert body["source"] == "plexus"
    assert body["event"] == "monitoring.alert"
    assert body["hostname"] == "core-sw1"
    assert body["severity"] == "critical"
    assert body["value"] == 99.0


def test_format_teams_shape():
    body = nc.format_teams(_ALERT)
    assert body["@type"] == "MessageCard"
    assert body["themeColor"] == nc._TEAMS_COLOR["critical"]
    facts = {f["name"]: f["value"] for f in body["sections"][0]["facts"]}
    assert facts["Host"] == "core-sw1"
    assert facts["Severity"] == "CRITICAL"


def test_build_email_headers_and_body():
    cfg = nc.sanitize_channel({
        "id": "e", "type": "email", "smtp_host": "h",
        "mail_from": "alerts@x.com", "mail_to": "a@y.com, b@y.com",
    })
    msg = nc.build_email(_ALERT, cfg)
    assert "CRITICAL" in msg["Subject"]
    assert "core-sw1" in msg["Subject"]
    assert msg["From"] == "alerts@x.com"
    assert msg["To"] == "a@y.com, b@y.com"
    assert "CPU utilization at 99%" in msg.get_content()


# ── Severity floor ───────────────────────────────────────────────────────────

async def test_severity_floor_drops_below_threshold():
    async with _HttpCapture() as cap:
        cfg = nc.sanitize_channel({
            "id": "w", "type": "webhook", "webhook_url": cap.url, "severity_floor": "critical",
        })
        await nc.start_dispatcher([cfg], default_channel_ids=["w"])
        # warning < critical floor -> dropped, never enqueued
        await nc.on_alert_created({**_ALERT, "severity": "warning", "channel_ids": ""})
        await asyncio.sleep(0.2)
        stats = {s["id"]: s for s in nc.get_stats()}
        assert stats["w"]["dropped_below_severity"] == 1
        assert stats["w"]["delivered"] == 0


# ── Dispatcher fan-out + defaults + per-rule selection ───────────────────────

async def test_default_channels_used_when_no_rule_assignment():
    async with _HttpCapture() as cap:
        w = nc.sanitize_channel({"id": "w", "type": "webhook", "webhook_url": cap.url})
        await nc.start_dispatcher([w], default_channel_ids=["w"])
        await nc.on_alert_created({**_ALERT, "channel_ids": ""})
        assert await _wait(lambda: len(cap.bodies) >= 1)
        assert cap.bodies[0]["source"] == "plexus"


async def test_per_rule_assignment_overrides_defaults():
    async with _HttpCapture() as cap_a, _HttpCapture() as cap_b:
        a = nc.sanitize_channel({"id": "a", "type": "webhook", "webhook_url": cap_a.url})
        b = nc.sanitize_channel({"id": "b", "type": "webhook", "webhook_url": cap_b.url})
        # default is channel b, but the alert's rule assigns only channel a
        await nc.start_dispatcher([a, b], default_channel_ids=["b"])
        await nc.on_alert_created({**_ALERT, "channel_ids": '["a"]'})
        assert await _wait(lambda: len(cap_a.bodies) >= 1)
        await asyncio.sleep(0.2)
        assert len(cap_a.bodies) == 1
        assert len(cap_b.bodies) == 0


async def test_disabled_channel_not_delivered():
    async with _HttpCapture() as cap:
        w = nc.sanitize_channel({"id": "w", "type": "webhook", "webhook_url": cap.url,
                                 "enabled": False})
        await nc.start_dispatcher([w], default_channel_ids=["w"])
        await nc.on_alert_created({**_ALERT, "channel_ids": ""})
        await asyncio.sleep(0.2)
        assert len(cap.bodies) == 0


async def test_teams_delivers_messagecard():
    async with _HttpCapture() as cap:
        t = nc.sanitize_channel({"id": "t", "type": "teams", "teams_webhook_url": cap.url})
        await nc.start_dispatcher([t], default_channel_ids=["t"])
        await nc.on_alert_created({**_ALERT, "channel_ids": ""})
        assert await _wait(lambda: len(cap.bodies) >= 1)
        assert cap.bodies[0]["@type"] == "MessageCard"


# ── Bounded queue (drop oldest) ──────────────────────────────────────────────

async def test_bounded_queue_drops_oldest():
    # No listener: deliveries hang/fail, so the queue fills. queue_size floor=10.
    cfg = nc.sanitize_channel({
        "id": "w", "type": "webhook", "webhook_url": "http://127.0.0.1:1/never",
        "queue_size": 10, "max_retries": 0,
    })
    # Don't start the loop task draining; manipulate the runtime directly.
    rt = nc.ChannelRuntime(config=cfg, queue=asyncio.Queue(maxsize=10))
    for i in range(15):
        nc._enqueue_one(rt, {**_ALERT, "alert_id": i})
    assert rt.queue.qsize() == 10
    assert rt.dropped_queue_full == 5
    # The 5 oldest were dropped; the newest survive.
    remaining = []
    while not rt.queue.empty():
        remaining.append(rt.queue.get_nowait()["alert_id"])
    assert remaining == list(range(5, 15))


# ── Retry / backoff exhaustion ───────────────────────────────────────────────

async def test_retry_gives_up_after_max_retries(monkeypatch):
    attempts = {"n": 0}

    async def always_fail(cfg, alert):
        attempts["n"] += 1
        raise RuntimeError("boom")

    monkeypatch.setattr(nc, "deliver", always_fail)
    cfg = nc.sanitize_channel({
        "id": "w", "type": "webhook", "webhook_url": "http://127.0.0.1:1/x",
        "max_retries": 2, "backoff_base": 0.1, "backoff_cap": 0.1,
    })
    await nc.start_dispatcher([cfg], default_channel_ids=["w"])
    await nc.on_alert_created({**_ALERT, "channel_ids": ""})
    # 1 initial attempt + 2 retries = 3 total
    assert await _wait(lambda: attempts["n"] >= 3, timeout_s=3.0)
    await asyncio.sleep(0.2)
    assert attempts["n"] == 3
    stats = {s["id"]: s for s in nc.get_stats()}
    assert stats["w"]["delivered"] == 0
    assert stats["w"]["delivery_failures"] >= 3


# ── Email delivery path ──────────────────────────────────────────────────────

async def test_email_delivery_calls_smtp(monkeypatch):
    sent: list = []

    def fake_send(cfg, msg):
        sent.append((cfg.id, msg["To"], msg["Subject"]))

    monkeypatch.setattr(nc, "_send_email_blocking", fake_send)
    cfg = nc.sanitize_channel({
        "id": "e", "type": "email", "smtp_host": "mail", "mail_from": "a@b.c",
        "mail_to": "oncall@x.com",
    })
    await nc.start_dispatcher([cfg], default_channel_ids=["e"])
    await nc.on_alert_created({**_ALERT, "channel_ids": ""})
    assert await _wait(lambda: len(sent) >= 1)
    assert sent[0][0] == "e"
    assert sent[0][1] == "oncall@x.com"
    assert "CRITICAL" in sent[0][2]


# ── Reconcile + test event ───────────────────────────────────────────────────

async def test_apply_channels_reconciles():
    async with _HttpCapture() as cap:
        a = nc.sanitize_channel({"id": "a", "type": "webhook", "webhook_url": cap.url})
        b = nc.sanitize_channel({"id": "b", "type": "webhook", "webhook_url": cap.url})
        await nc.start_dispatcher([a, b])
        assert set(nc._channels.keys()) == {"a", "b"}
        await nc.apply_channels([a])  # drop b
        assert set(nc._channels.keys()) == {"a"}


async def test_send_test_event_delivers_probe():
    async with _HttpCapture() as cap:
        w = nc.sanitize_channel({"id": "w", "type": "webhook", "webhook_url": cap.url})
        await nc.start_dispatcher([w])
        res = await nc.send_test_event("w")
        assert res["ok"] is True
        assert len(cap.bodies) == 1
        assert cap.bodies[0]["metric"] == "notification.test"


async def test_send_test_event_unknown_channel():
    res = await nc.send_test_event("nope")
    assert res["ok"] is False
