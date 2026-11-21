"""Syslog / SNMP trap event receivers: persisted settings, start/stop/rebind,
auto-start with Plexus, counters, and the admin config API.

Every receiver here binds to a free high port on loopback (the module's bind
host is patched), never to a privileged or fixed port.
"""

from __future__ import annotations

import asyncio
import socket

import netcontrol.routes.metrics_engine as me
import netcontrol.routes.state as state
import pytest
import routes.database as db

from mcp_helpers import admin_client, user_client

CONFIG = "/api/admin/metrics/receivers/config"


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _send(port: int, payload: bytes = b"<13>test message") -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, ("127.0.0.1", port))


def _reset_receivers() -> None:
    for kind, transport in list(me._receiver_transports.items()):
        if transport is not None:
            try:
                transport.close()
            except RuntimeError:
                pass  # its event loop is already closed
        me._receiver_transports[kind] = None
        me._receiver_ports[kind] = 0


@pytest.fixture(autouse=True)
def _loopback_receivers(monkeypatch):
    from netcontrol import listener_sources

    monkeypatch.setattr(me, "_RECEIVER_BIND_HOST", "127.0.0.1")
    # Loopback is not an inventory host: admit every source here (the
    # listener allowlist is tested in test_listener_sources.py).
    monkeypatch.setitem(listener_sources.CONFIG, "policy", "any")
    state.EVENT_RECEIVER_CONFIG.update(state.EVENT_RECEIVER_DEFAULTS)
    yield
    _reset_receivers()
    state.EVENT_RECEIVER_CONFIG.update(state.EVENT_RECEIVER_DEFAULTS)


def _cfg(**over) -> dict:
    return state._sanitize_event_receiver_config(over)


async def _wait_for(predicate) -> bool:
    """Poll ``predicate`` for up to 3 seconds (a loopback datagram arrives fast)."""
    for _ in range(150):
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


# ── Sanitize ────────────────────────────────────────────────────────────────


def test_sanitize_defaults():
    assert state._sanitize_event_receiver_config(None) == state.EVENT_RECEIVER_DEFAULTS
    assert state._sanitize_event_receiver_config("bad") == state.EVENT_RECEIVER_DEFAULTS  # type: ignore[arg-type]
    assert state.EVENT_RECEIVER_DEFAULTS["syslog_port"] == 1514
    assert state.EVENT_RECEIVER_DEFAULTS["trap_port"] == 10162


def test_sanitize_clamps_ports_and_coerces_bools():
    cfg = state._sanitize_event_receiver_config(
        {
            "syslog_enabled": 1,
            "syslog_port": 70000,
            "trap_enabled": "yes",
            "trap_port": 0,
            "syslog_alerts": 0,
            "config_change_trigger": "",
            "repoll_trigger": None,
            "unknown": "dropped",
        }
    )
    assert cfg == {
        "syslog_enabled": True,
        "syslog_port": 65535,
        "trap_enabled": True,
        "trap_port": 1,
        "syslog_alerts": False,
        "config_change_trigger": False,
        "repoll_trigger": False,
        # Left out: on.
        "recollect_trigger": True,
        "filterlog_evidence": True,
    }


def test_sanitize_keeps_default_for_unparseable_port():
    cfg = state._sanitize_event_receiver_config({"syslog_port": "abc", "trap_port": "20162"})
    assert cfg["syslog_port"] == 1514
    assert cfg["trap_port"] == 20162


# ── Apply: start / stop / rebind ────────────────────────────────────────────


async def test_apply_starts_stops_and_rebinds_each_receiver_on_its_own():
    p1, p2, trap_port = _free_udp_port(), _free_udp_port(), _free_udp_port()
    try:
        snap = await me.apply_event_receiver_config(_cfg(syslog_enabled=True, syslog_port=p1, trap_port=trap_port))
        assert snap["syslog_running"] is True and snap["syslog_listening_port"] == p1
        assert snap["trap_running"] is False and snap["trap_listening_port"] is None
        first = me._receiver_transports["syslog"]

        # Same settings: nothing is rebound.
        await me.apply_event_receiver_config(_cfg(syslog_enabled=True, syslog_port=p1, trap_port=trap_port))
        assert me._receiver_transports["syslog"] is first

        # Trap on: the syslog listener is left alone.
        snap = await me.apply_event_receiver_config(
            _cfg(syslog_enabled=True, syslog_port=p1, trap_enabled=True, trap_port=trap_port)
        )
        assert snap["trap_running"] is True and snap["trap_listening_port"] == trap_port
        assert me._receiver_transports["syslog"] is first
        trap_transport = me._receiver_transports["trap"]

        # Syslog port change: syslog rebinds, trap does not.
        snap = await me.apply_event_receiver_config(
            _cfg(syslog_enabled=True, syslog_port=p2, trap_enabled=True, trap_port=trap_port)
        )
        assert snap["syslog_listening_port"] == p2
        assert me._receiver_transports["syslog"] is not first
        assert me._receiver_transports["trap"] is trap_transport
        assert state.EVENT_RECEIVER_CONFIG["syslog_port"] == p2

        # Syslog off.
        snap = await me.apply_event_receiver_config(
            _cfg(syslog_enabled=False, syslog_port=p2, trap_enabled=True, trap_port=trap_port)
        )
        assert snap["syslog_running"] is False and snap["trap_running"] is True

        # stop_receivers still stops everything.
        me.stop_receivers()
        assert not me.receiver_running("syslog") and not me.receiver_running("trap")
    finally:
        me.stop_receivers()


async def test_per_receiver_stop():
    syslog_port, trap_port = _free_udp_port(), _free_udp_port()
    try:
        assert await me.start_syslog_receiver(syslog_port) is True
        assert await me.start_trap_receiver(trap_port) is True
        assert me.stop_trap_receiver() is True
        assert me.stop_trap_receiver() is False
        assert me.receiver_running("syslog") and not me.receiver_running("trap")
        assert me.stop_syslog_receiver() is True
    finally:
        me.stop_receivers()


async def test_failed_bind_is_logged_and_left_stopped():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
        busy.bind(("127.0.0.1", 0))
        port = busy.getsockname()[1]
        snap = await me.apply_event_receiver_config(_cfg(syslog_enabled=True, syslog_port=port))
    assert snap["syslog_running"] is False
    assert snap["syslog_enabled"] is True  # the saved intent is kept


# ── Counters ────────────────────────────────────────────────────────────────


async def test_counters_track_messages_and_parse_errors(monkeypatch):
    handled: list[bytes] = []
    monkeypatch.setattr(me._TrapSyslogProtocol, "_handle_syslog", lambda self, data, ip: handled.append(data))
    port = _free_udp_port()
    try:
        await me.apply_event_receiver_config(_cfg(syslog_enabled=True, syslog_port=port))
        snap = me.event_receiver_snapshot()
        assert snap["syslog_received"] == 0 and snap["syslog_last_message_at"] == ""
        assert snap["syslog_started_at"]

        _send(port)
        _send(port)
        assert await _wait_for(lambda: me._RECEIVER_STATS["syslog"].received == 2)
        snap = me.event_receiver_snapshot()
        assert snap["syslog_received"] == 2 and snap["syslog_errors"] == 0
        assert snap["syslog_last_message_at"]
        assert len(handled) == 2

        def _boom(self, data, ip):
            raise ValueError("bad message")

        monkeypatch.setattr(me._TrapSyslogProtocol, "_handle_syslog", _boom)
        _send(port)
        assert await _wait_for(lambda: me._RECEIVER_STATS["syslog"].errors == 1)
        assert me.event_receiver_snapshot()["syslog_received"] == 3

        # A restart (port change) starts the counters again.
        await me.apply_event_receiver_config(_cfg(syslog_enabled=True, syslog_port=_free_udp_port()))
        assert me.event_receiver_snapshot()["syslog_received"] == 0
    finally:
        me.stop_receivers()


def test_dropped_events_are_counted_since_start(monkeypatch):
    monkeypatch.setattr(me, "_TRAP_EVENT_BUFFER_MAX", 0)
    before = me.event_receiver_snapshot()["events_dropped"]
    me._queue_trap_syslog_event("192.0.2.10", "syslog", "", "info", "", "dropped", "dropped")
    assert me.event_receiver_snapshot()["events_dropped"] == before + 1


# ── Admin API ───────────────────────────────────────────────────────────────


def _system_audit_actions() -> list[str]:
    return [e["action"] for e in asyncio.run(db.get_audit_events(500, "system"))]


def test_config_api_is_admin_only(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    plain = user_client(admin, "recv-user", features=["monitoring"])
    assert plain.get(CONFIG).status_code == 403
    assert plain.put(CONFIG, json={"syslog_enabled": True}).status_code == 403
    assert plain.post("/api/admin/metrics/receivers/start").status_code == 403
    assert plain.post("/api/admin/metrics/receivers/stop").status_code == 403


def test_config_api_get_put_persists_applies_and_audits(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    resp = admin.get(CONFIG)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["syslog_enabled"] is False and body["syslog_running"] is False
    assert body["syslog_port"] == 1514 and body["trap_port"] == 10162
    for key in ("syslog_received", "trap_received", "events_dropped", "syslog_last_message_at"):
        assert key in body

    port = _free_udp_port()
    resp = admin.put(CONFIG, json={"syslog_enabled": True, "syslog_port": port, "repoll_trigger": False})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["syslog_running"] is True and body["syslog_listening_port"] == port
    assert body["repoll_trigger"] is False
    # Fields left out keep their saved value.
    assert body["trap_port"] == 10162 and body["syslog_alerts"] is True

    saved = asyncio.run(db.get_auth_setting("event_receivers"))
    assert saved == state._sanitize_event_receiver_config(saved)
    assert saved["syslog_enabled"] is True and saved["syslog_port"] == port and saved["repoll_trigger"] is False
    assert "event_receivers.config.updated" in _system_audit_actions()

    assert admin.put(CONFIG, json={"syslog_port": 70000}).status_code == 422
    # Both receivers enabled on one port: refused, nothing saved or rebound.
    clash = admin.put(CONFIG, json={"trap_enabled": True, "trap_port": port})
    assert clash.status_code == 400
    after = admin.get(CONFIG).json()
    assert after["trap_enabled"] is False and after["trap_running"] is False and after["syslog_port"] == port
    assert admin.put(CONFIG, json={"trap_port": 0}).status_code == 422
    assert admin.put(CONFIG, json={"syslog_enabled": False}).json()["syslog_running"] is False


def test_start_and_stop_endpoints_save_the_settings(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    syslog_port, trap_port = _free_udp_port(), _free_udp_port()
    resp = admin.post("/api/admin/metrics/receivers/start", json={"syslog_port": syslog_port, "trap_port": trap_port})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["syslog_started"] is True and body["trap_started"] is True
    saved = asyncio.run(db.get_auth_setting("event_receivers"))
    assert saved["syslog_enabled"] and saved["trap_enabled"]
    assert (saved["syslog_port"], saved["trap_port"]) == (syslog_port, trap_port)

    assert admin.post("/api/admin/metrics/receivers/start", json={"trap_port": 99999}).status_code == 422

    resp = admin.post("/api/admin/metrics/receivers/stop")
    assert resp.status_code == 200 and resp.json() == {"ok": True}
    saved = asyncio.run(db.get_auth_setting("event_receivers"))
    assert not saved["syslog_enabled"] and not saved["trap_enabled"]
    status = admin.get(CONFIG).json()
    assert status["syslog_running"] is False and status["trap_running"] is False
    actions = _system_audit_actions()
    assert "event_receivers.started" in actions and "event_receivers.stopped" in actions


def test_start_endpoint_without_a_body_uses_the_saved_ports(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    syslog_port, trap_port = _free_udp_port(), _free_udp_port()
    admin.put(CONFIG, json={"syslog_port": syslog_port, "trap_port": trap_port})
    body = admin.post("/api/admin/metrics/receivers/start").json()
    assert body["syslog_listening_port"] == syslog_port and body["trap_listening_port"] == trap_port


def test_saved_receivers_start_with_plexus(monkeypatch, request):
    syslog_port = _free_udp_port()
    asyncio.run(
        db.set_auth_setting(
            "event_receivers",
            {"syslog_enabled": True, "syslog_port": syslog_port, "trap_enabled": False},
        )
    )
    admin = admin_client(monkeypatch, request)
    body = admin.get(CONFIG).json()
    assert body["syslog_enabled"] is True
    assert body["syslog_running"] is True and body["syslog_listening_port"] == syslog_port
    assert body["trap_running"] is False


def test_startup_survives_a_port_that_will_not_bind(monkeypatch, request):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
        busy.bind(("127.0.0.1", 0))
        port = busy.getsockname()[1]
        asyncio.run(db.set_auth_setting("event_receivers", {"trap_enabled": True, "trap_port": port}))
        admin = admin_client(monkeypatch, request)
        body = admin.get(CONFIG).json()
    assert body["trap_enabled"] is True and body["trap_running"] is False
