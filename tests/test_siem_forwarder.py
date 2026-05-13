"""Tests for the SIEM audit-event forwarder (netcontrol.routes.siem_forwarder).

Covers:
  * sanitize_sink rejects invalid configs and accepts valid ones
  * CEF and ECS-JSON formatters produce stable, well-formed output
  * Syslog framing (PRI + RFC 5424 header + octet-counting)
  * UDP and TCP sinks deliver real bytes to a local listener
  * Dispatcher fans out events to multiple sinks
  * Bounded queue drops the oldest event on overflow
  * Retry/backoff stops after max_retries
  * Severity floor filters events below the threshold
  * add_audit_event hook fires successfully after insert
"""
from __future__ import annotations

import asyncio
import json
import socket

import pytest

import routes.database as db_module
from netcontrol.routes import siem_forwarder as sf


# ── Validation ───────────────────────────────────────────────────────────────

def test_sanitize_rejects_unknown_protocol():
    assert sf.sanitize_sink({"id": "x", "protocol": "carrier-pigeon", "host": "h"}) is None


def test_sanitize_rejects_https_without_url():
    assert sf.sanitize_sink({"id": "x", "protocol": "https", "url": ""}) is None


def test_sanitize_rejects_syslog_without_host():
    assert sf.sanitize_sink({"id": "x", "protocol": "udp", "host": ""}) is None


def test_sanitize_clamps_numeric_ranges():
    sc = sf.sanitize_sink({
        "id": "x", "protocol": "udp", "host": "h",
        "queue_size": 5,            # below floor
        "max_retries": 999,         # above ceiling
        "backoff_base": 0.01,       # below floor
    })
    assert sc.queue_size == 10
    assert sc.max_retries == 20
    assert sc.backoff_base == 0.1


def test_sanitize_default_format_is_json():
    sc = sf.sanitize_sink({"id": "x", "protocol": "udp", "host": "h"})
    assert sc.format == "json"


def test_sanitize_falls_back_on_bad_severity():
    sc = sf.sanitize_sink({"id": "x", "protocol": "udp", "host": "h", "severity_floor": "ALARMING"})
    assert sc.severity_floor == "info"


# ── Formatters ───────────────────────────────────────────────────────────────

_EVENT = {
    "id": 42,
    "timestamp": "2026-05-12T10:00:00Z",
    "category": "auth",
    "action": "login.success",
    "user": "alice",
    "detail": "from 10.0.0.1",
    "correlation_id": "cid-abc",
    "prev_hash": "p" * 64,
    "row_hash": "r" * 64,
}


def test_format_cef_header_and_extensions():
    line = sf.format_cef(_EVENT)
    assert line.startswith("CEF:0|Plexus|NMS|1.0|auth.login.success|login.success|")
    # Extensions must be present
    assert "suser=alice" in line
    assert "cs1=cid-abc" in line
    assert "cs1Label=correlationId" in line
    assert f"cs2={'r'*64}" in line
    assert "externalId=42" in line


def test_format_cef_escapes_pipes_and_equals():
    event = dict(_EVENT)
    event["detail"] = "weird=value | with bars"
    line = sf.format_cef(event)
    # The extension value must escape '=' (otherwise it'd parse as a new key)
    assert "msg=weird\\=value " in line


def test_format_json_is_ecs_shaped():
    payload = json.loads(sf.format_json(_EVENT))
    assert payload["@timestamp"] == _EVENT["timestamp"]
    assert payload["event"]["action"] == "login.success"
    assert payload["event"]["category"] == ["auth"]
    assert payload["event"]["module"] == "plexus"
    assert payload["event"]["dataset"] == "plexus.audit"
    assert payload["user"]["name"] == "alice"
    assert payload["plexus"]["row_hash"] == "r" * 64


# ── Syslog framing ───────────────────────────────────────────────────────────

def test_syslog_pri_is_local0_info():
    # local0 (16) * 8 + info (6) = 134
    assert sf._syslog_pri("info") == 134


def test_wrap_syslog_includes_header_and_payload():
    payload = "hello"
    wrapped = sf.wrap_syslog(_EVENT, payload)
    assert wrapped.startswith("<134>1 ")
    assert wrapped.endswith(" hello")
    assert " plexus " in wrapped


def test_frame_octet_counting():
    framed = sf.frame_octet_counting("abcdef")
    assert framed == b"6 abcdef"


# ── UDP sink delivery (real socket) ──────────────────────────────────────────

async def test_udp_sink_delivers_to_local_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    port = sock.getsockname()[1]
    try:
        sink = sf.sanitize_sink({
            "id": "udp1", "name": "udp1", "protocol": "udp",
            "format": "json", "host": "127.0.0.1", "port": port,
        })
        await sf.deliver(sink, _EVENT)
        # Receive what we sent.
        loop = asyncio.get_running_loop()
        for _ in range(50):
            try:
                data, _addr = sock.recvfrom(8192)
                break
            except BlockingIOError:
                await asyncio.sleep(0.02)
        else:
            pytest.fail("UDP listener never received the datagram")
        text = data.decode("utf-8")
        assert text.startswith("<134>1 ")
        # RFC 5424 header: <PRI>VER TS HOST APP PROCID MSGID STRUCTURED-DATA MSG
        # That's 7 space-separated tokens before the JSON body.
        body = text.split(" ", 7)[7]
        parsed = json.loads(body)
        assert parsed["event"]["action"] == "login.success"
    finally:
        sock.close()


# ── TCP sink delivery (real listener) ────────────────────────────────────────

async def test_tcp_sink_uses_octet_counting_frame():
    received: list[bytes] = []
    ready = asyncio.Event()

    async def handle(reader, writer):
        data = await reader.read(8192)
        received.append(data)
        ready.set()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        sink = sf.sanitize_sink({
            "id": "tcp1", "protocol": "tcp", "format": "cef",
            "host": "127.0.0.1", "port": port,
        })
        await sf.deliver(sink, _EVENT)
        try:
            await asyncio.wait_for(ready.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pytest.fail("TCP server did not receive frame in time")
        raw = received[0].decode("utf-8")
        # RFC 6587 octet-counting frame: "<len> <message>"
        sep = raw.index(" ")
        length = int(raw[:sep])
        body = raw[sep + 1:]
        assert len(body.encode("utf-8")) == length
        assert "CEF:0|Plexus|NMS|1.0|" in body
    finally:
        server.close()
        await server.wait_closed()


# ── Dispatcher fan-out + bounded queue ───────────────────────────────────────

async def test_dispatcher_fans_out_to_multiple_sinks():
    # Two UDP sinks listening on different ports.
    socks = []
    sinks = []
    try:
        for i in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0))
            s.setblocking(False)
            socks.append(s)
            sinks.append(sf.sanitize_sink({
                "id": f"udp{i}", "protocol": "udp", "format": "json",
                "host": "127.0.0.1", "port": s.getsockname()[1],
                "max_retries": 0,
            }))

        await sf.start_dispatcher(sinks)
        try:
            await sf.enqueue_event(_EVENT)
            # Wait for both queues to drain.
            for _ in range(50):
                drained = all(
                    rt.queue.empty() and rt.delivered >= 1
                    for rt in sf._sinks.values()
                )
                if drained:
                    break
                await asyncio.sleep(0.02)
            assert len(sf._sinks) == 2
            for rt in sf._sinks.values():
                assert rt.delivered == 1, f"sink {rt.config.id} did not deliver"
        finally:
            await sf.stop_dispatcher()
    finally:
        for s in socks:
            s.close()


async def test_bounded_queue_drops_oldest_on_overflow():
    """When queue is full, the OLDEST event is dropped to make room for the
    newest. Simulate by pointing the sink at a black hole TCP port so the
    sink loop blocks long enough for the queue to fill."""
    # Reserve a port and never accept - the connect itself will eventually
    # fail and retry, leaving items piled up in the queue.
    sink = sf.SinkConfig(
        id="slow", name="slow", enabled=True, protocol="udp", format="json",
        host="127.0.0.1", port=1,  # port 1 - anything sent here is dropped
        url="", bearer_token="", tls_verify=True,
        tls_ca_pem="", tls_client_cert_pem="", tls_client_key_pem="",
        severity_floor="info",
        queue_size=2, max_retries=0,
        backoff_base=0.1, backoff_cap=1.0,
    )
    # Build the runtime by hand so we don't have to start the loop.
    rt = sf.SinkRuntime(config=sink, queue=asyncio.Queue(maxsize=2))
    async with sf._runtime_lock:
        sf._sinks[sink.id] = rt
    try:
        for i in range(4):
            await sf.enqueue_event({**_EVENT, "id": i, "severity": "info"})
        # Queue capacity is 2 and we sent 4 -> exactly 2 dropped.
        assert rt.dropped_queue_full == 2
        assert rt.queue.qsize() == 2
        # The two newest IDs (2, 3) should remain.
        remaining = []
        while not rt.queue.empty():
            remaining.append(rt.queue.get_nowait()["id"])
            rt.queue.task_done()
        assert remaining == [2, 3]
    finally:
        async with sf._runtime_lock:
            sf._sinks.pop(sink.id, None)


# ── Retry + backoff ──────────────────────────────────────────────────────────

async def test_sink_loop_gives_up_after_max_retries(monkeypatch):
    """Patch deliver() to always raise. Confirm delivery_failures grows
    monotonically, never exceeds max_retries + 1 per event, and the loop
    keeps consuming."""
    sink = sf.SinkConfig(
        id="fail", name="fail", enabled=True, protocol="udp", format="json",
        host="127.0.0.1", port=1, url="", bearer_token="", tls_verify=True,
        tls_ca_pem="", tls_client_cert_pem="", tls_client_key_pem="",
        severity_floor="info",
        queue_size=10, max_retries=2,
        backoff_base=0.01, backoff_cap=0.02,  # near-zero so the test is fast
    )

    async def boom(*_a, **_kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(sf, "deliver", boom)

    rt = sf.SinkRuntime(config=sink, queue=asyncio.Queue(maxsize=10))
    rt.task = asyncio.create_task(sf._sink_loop(rt))
    try:
        await rt.queue.put({**_EVENT, "id": 1})
        # Wait until either failures reach 3 (1 + 2 retries) or timeout.
        for _ in range(200):
            if rt.delivery_failures >= 3:
                break
            await asyncio.sleep(0.01)
        assert rt.delivered == 0
        # 1 initial attempt + 2 retries = exactly 3 failures, then give up
        assert rt.delivery_failures == 3
        assert "boom" in rt.last_error
    finally:
        rt.task.cancel()
        try:
            await rt.task
        except asyncio.CancelledError:
            pass


# ── Severity floor ───────────────────────────────────────────────────────────

async def test_severity_floor_drops_lower_priority_events():
    """A sink with floor=warning must drop info-level events."""
    sink = sf.sanitize_sink({
        "id": "warn-only", "protocol": "udp", "host": "127.0.0.1", "port": 1,
        "format": "json", "severity_floor": "warning",
    })
    rt = sf.SinkRuntime(config=sink, queue=asyncio.Queue(maxsize=10))
    async with sf._runtime_lock:
        sf._sinks[sink.id] = rt
    try:
        # category=auth + action=login.success is "info" - should be dropped.
        await sf.enqueue_event({**_EVENT, "severity": None})
        # category=security maps to "critical" - should pass.
        await sf.enqueue_event({**_EVENT, "id": 99, "category": "security", "action": "tamper"})
        assert rt.dropped_below_severity == 1
        assert rt.queue.qsize() == 1
    finally:
        async with sf._runtime_lock:
            sf._sinks.pop(sink.id, None)


# ── add_audit_event hook ─────────────────────────────────────────────────────

async def test_audit_event_hook_fires(tmp_path, monkeypatch):
    """Registering a hook with set_audit_event_hook causes it to receive
    every newly inserted audit row."""
    db_path = str(tmp_path / "siem-hook.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()

    captured: list[dict] = []

    async def hook(event):
        captured.append(event)

    db_module.set_audit_event_hook(hook)
    try:
        await db_module.add_audit_event("auth", "login.success", "alice", "from x")
        assert len(captured) == 1
        event = captured[0]
        assert event["category"] == "auth"
        assert event["action"] == "login.success"
        assert event["user"] == "alice"
        assert event["row_hash"]  # populated
        assert event["prev_hash"] == ""  # first row
        assert event["id"]
    finally:
        db_module.set_audit_event_hook(None)


async def test_audit_event_hook_failure_does_not_break_insert(tmp_path, monkeypatch):
    """A raising hook must not propagate or prevent the audit insert."""
    db_path = str(tmp_path / "siem-hook-fail.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()

    async def boom(_event):
        raise RuntimeError("hook explosion")

    db_module.set_audit_event_hook(boom)
    try:
        new_id = await db_module.add_audit_event("auth", "login.success", "bob")
        assert new_id  # returned despite hook failure
        # Verify the row is still in the DB
        events = await db_module.get_audit_events(limit=10)
        assert any(e["id"] == new_id for e in events)
    finally:
        db_module.set_audit_event_hook(None)
