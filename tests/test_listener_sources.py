"""Source allowlist, per-source rate limit and drop counters shared by the
SNMP trap, syslog and flow listeners (``netcontrol.listener_sources``), and
the admin API that sets them.

Addresses are from the documentation ranges; loopback receivers bind to a
free high port.
"""

from __future__ import annotations

import asyncio
import logging
import socket

import netcontrol.routes.metrics_engine as me
import pytest
import routes.database as db
from netcontrol import listener_sources as ls
from netcontrol.routes import flow_collector

from mcp_helpers import admin_client, user_client

HOST_IP = "192.0.2.40"
ALIAS_IP = "198.51.100.40"
STRANGER = "203.0.113.40"
API = "/api/admin/listener-sources"


class _Clock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """Default settings, an inventory of one host (primary and interface
    address), fresh counters, and no background refresh."""
    ls.apply_config(ls.sanitize_config(None))
    saved = dict(ls.INVENTORY_ADDRESSES)
    ls.INVENTORY_ADDRESSES.clear()
    ls.INVENTORY_ADDRESSES.update({HOST_IP: 7, ALIAS_IP: 7})
    monkeypatch.setattr(ls, "_inventory_loaded_at", float("inf"))
    for g in ls.GUARDS.values():
        g.reset()
    yield
    ls.apply_config(ls.sanitize_config(None))
    ls.INVENTORY_ADDRESSES.clear()
    ls.INVENTORY_ADDRESSES.update(saved)
    for g in ls.GUARDS.values():
        g.reset()


# ── Settings ─────────────────────────────────────────────────────────────────


def test_defaults_are_inventory_only_with_rate_limits():
    cfg = ls.sanitize_config(None)
    assert cfg == {
        "policy": "inventory",
        "extra_cidrs": [],
        "trap_rate_limit": 100,
        "syslog_rate_limit": 1000,
        "flow_rate_limit": 5000,
    }


def test_sanitize_normalises_and_drops_bad_values_when_lenient():
    cfg = ls.sanitize_config(
        {
            "policy": "ANY",
            "extra_cidrs": ["192.0.2.7/24", "2001:db8::1", "not-a-net", "192.0.2.0/24", ""],
            "syslog_rate_limit": "50",
            "flow_rate_limit": -3,
            "trap_rate_limit": True,
        }
    )
    assert cfg["policy"] == "any"
    assert cfg["extra_cidrs"] == ["192.0.2.0/24", "2001:db8::1/128"]
    assert (cfg["syslog_rate_limit"], cfg["flow_rate_limit"], cfg["trap_rate_limit"]) == (50, 0, 100)
    assert ls.sanitize_config({"policy": "nobody"})["policy"] == "inventory"


@pytest.mark.parametrize(
    "body",
    [
        {"policy": "nobody"},
        {"extra_cidrs": ["192.0.2.300/24"]},
        {"extra_cidrs": "192.0.2.0/24"},
        {"syslog_rate_limit": -1},
        {"flow_rate_limit": "fast"},
        {"extra_cidrs": [f"10.{i // 256}.{i % 256}.0/24" for i in range(ls.MAX_EXTRA_CIDRS + 1)]},
    ],
)
def test_strict_sanitize_refuses_invalid_values(body):
    with pytest.raises(ValueError):
        ls.sanitize_config(body, strict=True)


# ── Allowlist ────────────────────────────────────────────────────────────────


def test_only_inventory_addresses_pass_by_default():
    syslog = ls.guard("syslog")
    assert syslog.admit(HOST_IP) and syslog.admit(ALIAS_IP)
    assert syslog.admit(f"::ffff:{HOST_IP}")  # IPv4-mapped source
    assert not syslog.admit(STRANGER)
    assert not syslog.admit("not-an-address")
    assert syslog.stats()["dropped_source"] == 2
    # Counted per listener.
    assert ls.guard("flow").stats()["dropped_source"] == 0


def test_extra_networks_and_the_any_policy():
    flow = ls.guard("flow")
    ls.apply_config(ls.sanitize_config({"extra_cidrs": ["203.0.113.0/28", "2001:db8::/32"]}))
    assert flow.admit("203.0.113.5") and flow.admit("2001:db8::9")
    assert not flow.admit("203.0.113.99")
    ls.apply_config(ls.sanitize_config({"policy": "any"}))
    assert flow.admit("203.0.113.99")
    assert flow.stats()["dropped_source"] == 1


# ── Rate limit ───────────────────────────────────────────────────────────────


def test_each_source_is_rate_limited_with_a_burst(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(ls, "_clock", clock)
    ls.apply_config(ls.sanitize_config({"trap_rate_limit": 10}))
    trap = ls.SourceGuard("trap")
    burst = int(10 * ls.BURST_SECONDS)
    assert all(trap.admit(HOST_IP) for _ in range(burst))
    assert not trap.admit(HOST_IP)
    # Another source has its own bucket.
    assert trap.admit(ALIAS_IP)
    # Half a second refills five packets.
    clock.now += 0.5
    assert sum(trap.admit(HOST_IP) for _ in range(10)) == 5
    assert trap.stats()["dropped_rate"] == 6
    # 0 turns the limit off.
    ls.apply_config(ls.sanitize_config({"trap_rate_limit": 0}))
    assert all(trap.admit(HOST_IP) for _ in range(500))


def test_rate_buckets_are_bounded(monkeypatch):
    monkeypatch.setattr(ls, "MAX_TRACKED_SOURCES", 8)
    ls.apply_config(ls.sanitize_config({"policy": "any"}))
    guard = ls.SourceGuard("syslog")
    for i in range(100):
        assert guard.admit(f"203.0.113.{i}")
    assert guard.stats()["tracked_sources"] == 8


def test_drops_are_logged_at_most_once_per_interval(monkeypatch, caplog):
    clock = _Clock()
    monkeypatch.setattr(ls, "_clock", clock)
    guard = ls.SourceGuard("syslog")
    with caplog.at_level(logging.WARNING, logger="plexus.listener_sources"):
        for _ in range(50):
            guard.admit(STRANGER)
        assert len(caplog.records) == 1
        clock.now += ls.DROP_LOG_INTERVAL_SECONDS
        guard.admit(STRANGER)
    assert len(caplog.records) == 2
    assert "dropped 50 datagram(s)" in caplog.records[1].getMessage()
    assert guard.stats()["dropped_source"] == 51


# ── Inventory address set ────────────────────────────────────────────────────


async def test_the_set_is_loaded_from_inventory_and_shared_with_the_flow_collector():
    await db.init_db()
    group_id = await db.create_group("grp-listener-src")
    host_id = await db.add_host(group_id, "sw-ls1", "192.0.2.41", "cisco_ios")
    await db.set_host_ip_aliases(host_id, "192.0.2.41", ["198.51.100.41"])
    assert flow_collector._exporter_cache is ls.INVENTORY_ADDRESSES
    await flow_collector.refresh_exporter_cache()
    assert ls.INVENTORY_ADDRESSES["192.0.2.41"] == host_id
    assert ls.INVENTORY_ADDRESSES["198.51.100.41"] == host_id
    assert HOST_IP not in ls.INVENTORY_ADDRESSES  # reloaded, not merged
    assert ls.guard("syslog").admit("198.51.100.41")


async def test_a_stale_set_refreshes_in_the_background_never_per_packet(monkeypatch):
    calls: list[int] = []

    async def fake_map(hostnames: dict[int, str] | None = None) -> dict[str, int]:
        calls.append(1)
        await asyncio.sleep(0)
        return {STRANGER: 9}

    clock = _Clock()
    monkeypatch.setattr(ls, "_clock", clock)
    monkeypatch.setattr(db, "get_exporter_host_map", fake_map)
    monkeypatch.setattr(ls, "_inventory_loaded_at", clock.now)
    guard = ls.guard("trap")
    for _ in range(100):
        guard.admit(HOST_IP)
    assert calls == []  # fresh: no query
    clock.now += ls.INVENTORY_REFRESH_SECONDS
    # Stale: the packet is judged on the current set, one refresh starts.
    for _ in range(100):
        assert not guard.admit(STRANGER)
    await asyncio.gather(ls._refresh_task)
    assert calls == [1]
    assert guard.admit(STRANGER)


# ── The listeners ────────────────────────────────────────────────────────────


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _wait_for(predicate) -> bool:
    for _ in range(150):
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


async def test_the_syslog_receiver_drops_unknown_sources_and_shows_the_count(monkeypatch):
    handled: list[str] = []
    monkeypatch.setattr(me, "_RECEIVER_BIND_HOST", "127.0.0.1")
    monkeypatch.setattr(me._TrapSyslogProtocol, "_handle_syslog", lambda self, data, ip: handled.append(ip))

    async def no_refresh() -> int:
        return len(ls.INVENTORY_ADDRESSES)

    monkeypatch.setattr(ls, "refresh_inventory", no_refresh)
    port = _free_udp_port()
    try:
        assert await me.start_syslog_receiver(port)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"<13>from a stranger", ("127.0.0.1", port))
        assert await _wait_for(lambda: ls.guard("syslog").stats()["dropped_source"] == 1)
        snap = me.event_receiver_snapshot()
        assert snap["syslog_dropped_source"] == 1 and snap["syslog_received"] == 0
        assert handled == []
        # Loopback added as an extra network: processed.
        ls.apply_config(ls.sanitize_config({"extra_cidrs": ["127.0.0.0/8"]}))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"<13>now allowed", ("127.0.0.1", port))
        assert await _wait_for(lambda: handled == ["127.0.0.1"])
        assert me.event_receiver_snapshot()["syslog_received"] == 1
    finally:
        me.stop_receivers()


def test_the_trap_receiver_drops_unknown_sources(monkeypatch):
    queued: list[tuple] = []
    monkeypatch.setattr(me, "_queue_trap_syslog_event", lambda *args: queued.append(args))
    me._TrapSyslogProtocol("trap").datagram_received(b"\x30\x03junk", (STRANGER, 50162))
    assert queued == []
    assert me.event_receiver_snapshot()["trap_dropped_source"] == 1
    me._TrapSyslogProtocol("trap").datagram_received(b"\x30\x03junk", (HOST_IP, 50162))
    assert len(queued) == 1


async def test_the_flow_collector_drops_unknown_exporters_and_shows_the_count(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(flow_collector, "parse_netflow_v5", lambda data, addr: seen.append(addr[0]) or [])
    proto = flow_collector._FlowCollectorProtocol(mode="netflow")
    packet = b"\x00\x05" + bytes(22)
    proto.datagram_received(packet, (STRANGER, 2055))
    assert seen == []
    proto.datagram_received(packet, (HOST_IP, 2055))
    assert seen == [HOST_IP]
    assert flow_collector._config_snapshot()["dropped_source"] == 1
    assert (await flow_collector.api_flow_status())["dropped_source"] == 1
    # An exporter that is not (yet) an inventory host: allowed by an extra network.
    ls.apply_config(ls.sanitize_config({"extra_cidrs": ["203.0.113.0/24"]}))
    proto.datagram_received(packet, (STRANGER, 2055))
    assert seen == [HOST_IP, STRANGER]


def test_pending_exporter_stats_are_bounded(monkeypatch):
    flow_collector._pending_exporter_stats.clear()
    for i in range(flow_collector._pending_exporter_stats.max_entries + 50):
        flow_collector._note_exporter_packet(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", "netflow_v5", None, None)
    assert len(flow_collector._pending_exporter_stats) == flow_collector._pending_exporter_stats.max_entries
    flow_collector._pending_exporter_stats.clear()


def test_the_trap_and_syslog_host_cache_is_bounded():
    assert isinstance(me._host_ip_cache, dict)
    assert me._host_ip_cache.max_entries <= 4096


# ── Admin API ────────────────────────────────────────────────────────────────


def test_the_api_is_admin_only(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    plain = user_client(admin, "src-user", features=["monitoring"])
    assert plain.get(API).status_code == 403
    assert plain.put(API, json={"policy": "any"}).status_code == 403


def test_the_api_reads_saves_applies_and_audits(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    body = admin.get(API).json()
    assert body["policy"] == "inventory" and body["extra_cidrs"] == []
    assert set(body["listeners"]) == {"trap", "syslog", "flow"}
    assert "inventory_addresses" in body

    resp = admin.put(API, json={"extra_cidrs": ["203.0.113.0/24"], "flow_rate_limit": 20000})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["extra_cidrs"] == ["203.0.113.0/24"] and body["flow_rate_limit"] == 20000
    assert body["policy"] == "inventory"  # left out: kept
    assert ls.source_allowed("203.0.113.9")
    saved = asyncio.run(db.get_auth_setting("listener_sources"))
    assert saved == ls.sanitize_config(saved) and saved["extra_cidrs"] == ["203.0.113.0/24"]
    actions = [e["action"] for e in asyncio.run(db.get_audit_events(500, "system"))]
    assert "listener_sources.updated" in actions

    assert admin.put(API, json={"extra_cidrs": ["192.0.2.999/24"]}).status_code == 422
    assert admin.put(API, json={"policy": "everyone"}).status_code == 422
    assert admin.put(API, json={"syslog_rate_limit": -1}).status_code == 422
    assert admin.get(API).json()["extra_cidrs"] == ["203.0.113.0/24"]  # refused: unchanged
    assert admin.put(API, json={"policy": "any"}).json()["policy"] == "any"


def test_saved_settings_apply_at_startup(monkeypatch, request):
    asyncio.run(db.set_auth_setting("listener_sources", {"policy": "inventory", "extra_cidrs": ["198.51.100.0/24"]}))
    ls.apply_config(ls.sanitize_config(None))
    admin_client(monkeypatch, request)
    assert ls.CONFIG["extra_cidrs"] == ["198.51.100.0/24"]
