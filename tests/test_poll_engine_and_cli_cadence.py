"""One SNMP engine per device job, and the CLI (SSH) part of the monitoring
poll on its own cadence (``cli_poll_interval_seconds``).

Building a pysnmp engine costs about 90 ms of CPU on the event loop, so the
poll, the MAC collection and the interface inventory build one per device
and pass it to every request; it is closed when that device's job ends, and
never shared with another device. The CLI part (VPN and routes over SSH)
runs every ``cli_poll_interval_seconds``; the polls between carry its last
result. Invented hosts, documentation addresses only.
"""

from __future__ import annotations

import asyncio

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol.routes import mac_tracking, monitoring, snmp as snmp_module

IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
SYS_UPTIME = "1.3.6.1.2.1.1.3"


class _Engine:
    closed = False

    def close_dispatcher(self) -> None:
        self.closed = True


class _Engines:
    """Stands in for ``SnmpEngine``: records every engine built."""

    def __init__(self) -> None:
        self.built: list[_Engine] = []

    def __call__(self) -> _Engine:
        self.built.append(_Engine())
        return self.built[-1]


# ── snmp.py: the transport target is built once per engine ───────────────────


@pytest.fixture
def fake_pysnmp(monkeypatch):
    """pysnmp's walk, GET and UDP transport replaced; returns the transports
    built (by address) and the engines."""
    built: list[str] = []
    engines = _Engines()

    class _Transport:
        @staticmethod
        async def create(address, **_kwargs):
            await asyncio.sleep(0)  # requests sent together wait on one build
            built.append(address[0])
            return object()

    async def walker(*_args, **_kwargs):
        yield None, 0, 0, [("1.3.6.1.2.1.1.1.0", "value")]

    async def get_cmd(_engine, _auth, _transport, _context, *oids):
        return None, 0, 0, [(oid, "value") for oid in oids]

    monkeypatch.setattr(snmp_module, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(snmp_module, "SnmpEngine", engines)
    monkeypatch.setattr(snmp_module, "UdpTransportTarget", _Transport)
    monkeypatch.setattr(snmp_module, "ObjectIdentity", lambda oid: oid)
    monkeypatch.setattr(snmp_module, "ObjectType", lambda identity: identity)
    monkeypatch.setattr(snmp_module, "bulk_walk_cmd", walker)
    monkeypatch.setattr(snmp_module, "get_cmd", get_cmd)
    return built, engines


_V2C = {"enabled": True, "version": "2c", "community": "example"}


async def test_requests_through_one_engine_build_one_transport(fake_pysnmp):
    built, engines = fake_pysnmp
    async with snmp_module.device_snmp_engine() as engine:
        await asyncio.gather(
            *(snmp_module._snmp_walk("192.0.2.1", 1.0, _V2C, f"1.3.6.1.2.1.{n}", engine=engine) for n in range(20))
        )
        await snmp_module._snmp_get_values("192.0.2.1", 1.0, _V2C, ("1.3.6.1.2.1.1.5.0",), engine=engine)
        assert not engine.closed  # the caller's engine stays open for its next request
    assert built == ["192.0.2.1"]
    assert len(engines.built) == 1 and engines.built[0].closed


async def test_two_devices_get_two_engines_and_two_transports(fake_pysnmp):
    built, engines = fake_pysnmp
    for address in ("192.0.2.1", "192.0.2.2"):
        async with snmp_module.device_snmp_engine() as engine:
            await snmp_module._snmp_walk(address, 1.0, _V2C, "1.3.6.1.2.1.1", engine=engine)
            await snmp_module._snmp_walk(address, 1.0, _V2C, "1.3.6.1.2.1.2", engine=engine)
    assert built == ["192.0.2.1", "192.0.2.2"]
    assert len(engines.built) == 2 and all(engine.closed for engine in engines.built)


async def test_a_request_without_an_engine_still_builds_and_closes_its_own(fake_pysnmp):
    built, engines = fake_pysnmp
    await snmp_module._snmp_walk("192.0.2.3", 1.0, _V2C, "1.3.6.1.2.1.1")
    await snmp_module._snmp_walk("192.0.2.3", 1.0, _V2C, "1.3.6.1.2.1.1")
    assert built == ["192.0.2.3", "192.0.2.3"]
    assert len(engines.built) == 2 and all(engine.closed for engine in engines.built)


async def test_a_failed_transport_build_is_not_kept(fake_pysnmp):
    """A scoped IPv6 address cannot be reached: each request says so again
    instead of a failure being cached for the engine."""
    async with snmp_module.device_snmp_engine() as engine:
        for _ in range(2):
            with pytest.raises(ValueError):
                await snmp_module._snmp_walk("fe80::1%3", 1.0, _V2C, "1.3.6.1.2.1.1", engine=engine)
    assert snmp_module._ENGINE_TRANSPORTS.get(engine) == {}


async def test_the_engine_is_closed_on_error_and_on_cancellation(fake_pysnmp):
    _built, engines = fake_pysnmp
    with pytest.raises(RuntimeError):
        async with snmp_module.device_snmp_engine():
            raise RuntimeError("walk failed")

    async def hang() -> None:
        async with snmp_module.device_snmp_engine():
            await asyncio.sleep(60)

    task = asyncio.create_task(hang())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(engines.built) == 2 and all(engine.closed for engine in engines.built)


# ── The monitoring poll: one engine per host ─────────────────────────────────


def _snmp_device(monkeypatch, *, answers: bool = True, fail_oid: str | None = None) -> tuple[_Engines, list[object]]:
    """A device answering the poll's walks (one interface up) through the
    poll's request functions; the engines built and the engine of each
    request."""
    engines = _Engines()
    used: list[object] = []

    async def walk(_ip, _timeout, _cfg, oid, *_args, return_errors=False, engine=None, **_kwargs):
        used.append(engine)
        await asyncio.sleep(0)
        if oid == fail_oid:
            raise RuntimeError("agent went away")
        rows = {f"{IF_OPER_STATUS}.1": 1} if answers and oid == IF_OPER_STATUS else {}
        return (rows, None) if return_errors else rows

    async def get(_ip, _timeout, _cfg, oids, *, engine=None):
        used.append(engine)
        return {}, None

    monkeypatch.setattr(monitoring, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(monitoring, "SnmpEngine", engines)
    monkeypatch.setattr(monitoring, "_snmp_walk", walk)
    monkeypatch.setattr(monitoring, "_snmp_get_values", get)
    monkeypatch.setitem(state.MONITORING_CONFIG, "icmp_enabled", False)
    return engines, used


def _host(host_id: int, address: str, device_type: str = "cisco_ios") -> dict:
    return {"id": host_id, "hostname": f"sw-{host_id}", "ip_address": address, "device_type": device_type}


async def test_a_poll_sends_every_request_through_one_engine(monkeypatch):
    await db.init_db()
    engines, used = _snmp_device(monkeypatch)
    result = await monitoring._poll_host_monitoring(_host(1, "192.0.2.21"), None, {"enabled": True})
    assert result["if_up_count"] == 1
    assert len(engines.built) == 1 and engines.built[0].closed
    assert len(used) > 15 and set(used) == {engines.built[0]}


async def test_two_hosts_get_two_engines(monkeypatch):
    await db.init_db()
    engines, used = _snmp_device(monkeypatch)
    await asyncio.gather(
        monitoring._poll_host_monitoring(_host(1, "192.0.2.21"), None, {"enabled": True}),
        monitoring._poll_host_monitoring(_host(2, "192.0.2.22"), None, {"enabled": True}),
    )
    assert len(engines.built) == 2 and all(engine.closed for engine in engines.built)
    assert set(used) == set(engines.built)


async def test_the_poll_engine_is_closed_when_a_walk_fails(monkeypatch):
    await db.init_db()
    engines, _used = _snmp_device(monkeypatch, fail_oid=IF_OPER_STATUS)
    result = await monitoring._poll_host_monitoring(_host(1, "192.0.2.21"), None, {"enabled": True})
    assert result["if_up_count"] == 0
    assert len(engines.built) == 1 and engines.built[0].closed


async def test_the_poll_engine_is_closed_when_the_poll_times_out(monkeypatch):
    await db.init_db()
    engines, _used = _snmp_device(monkeypatch)

    async def stalled(*_args, **_kwargs):
        await asyncio.sleep(60)

    monkeypatch.setattr(monitoring, "_snmp_walk", stalled)
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            monitoring._poll_host_monitoring(_host(1, "192.0.2.21"), None, {"enabled": True}), timeout=0.05
        )
    assert len(engines.built) == 1 and engines.built[0].closed


async def test_the_poll_resolves_the_snmp_secrets_once(monkeypatch):
    await db.init_db()
    _snmp_device(monkeypatch)
    resolved: list[dict] = []

    async def resolve(cfg: dict) -> dict:
        resolved.append(cfg)
        return cfg

    monkeypatch.setattr(monitoring, "_resolve_snmp_secrets", resolve)
    await monitoring._poll_host_monitoring(_host(1, "192.0.2.21"), None, {"enabled": True})
    assert len(resolved) == 1


# ── MAC collection and interface inventory: one engine per host ─────────────


def _mac_device(monkeypatch) -> tuple[_Engines, list[object]]:
    engines = _Engines()
    used: list[object] = []

    async def walk(_ip, _timeout, _cfg, _oid, *_args, return_errors=False, engine=None, **_kwargs):
        used.append(engine)
        return ({}, None) if return_errors else {}

    monkeypatch.setattr(snmp_module, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(snmp_module, "SnmpEngine", engines)
    monkeypatch.setattr(mac_tracking, "_snmp_walk", walk)
    return engines, used


async def test_a_mac_collection_walks_through_one_engine_per_host(monkeypatch):
    await db.init_db()
    engines, used = _mac_device(monkeypatch)
    for host_id, address in ((990001, "198.51.100.1"), (990002, "198.51.100.2")):
        await mac_tracking.collect_mac_arp_tables(host_id, address, dict(_V2C), device_type="cisco_ios")
    assert len(engines.built) == 2 and all(engine.closed for engine in engines.built)
    assert len(used) == 26 and set(used[:13]) == {engines.built[0]} and set(used[13:]) == {engines.built[1]}


async def test_an_interface_inventory_walks_through_one_engine(monkeypatch):
    await db.init_db()
    engines, used = _mac_device(monkeypatch)
    await mac_tracking.collect_interface_inventory(990003, "198.51.100.3", dict(_V2C))
    assert len(engines.built) == 1 and engines.built[0].closed
    assert len(used) == 18 and set(used) == {engines.built[0]}


async def test_the_mac_collection_engine_is_closed_on_error(monkeypatch):
    await db.init_db()
    engines, _used = _mac_device(monkeypatch)

    async def broken(*_args, **_kwargs):
        raise RuntimeError("database down")

    monkeypatch.setattr(mac_tracking.db, "get_host", broken)
    with pytest.raises(RuntimeError):
        await mac_tracking.collect_mac_arp_tables(990004, "198.51.100.4", dict(_V2C), device_type="cisco_ios")
    assert len(engines.built) == 1 and engines.built[0].closed


# ── The CLI part on its own cadence ──────────────────────────────────────────

_VPN = """\
dst             src             state          conn-id status
203.0.113.1     192.0.2.30      QM_IDLE           1001 ACTIVE
203.0.113.2     192.0.2.30      MM_NO_STATE       1002 ACTIVE
"""
_SUMMARY = "Route Source    Networks    Subnets\nTotal           5           7\n"


class _Ssh:
    """netmiko's ``ConnectHandler``: counts the sessions opened."""

    def __init__(self, outputs: dict[str, str], *, fail: bool = False) -> None:
        self.outputs = outputs
        self.fail = fail
        self.sessions = 0
        self.sent: list[str] = []

    def __call__(self, **_kwargs):
        self.sessions += 1
        if self.fail:
            raise OSError("connection refused")
        return self

    def enable(self) -> None:
        pass

    def send_command(self, command: str, read_timeout: float | None = None) -> str:
        self.sent.append(command)
        return self.outputs.get(command, "")

    def disconnect(self) -> None:
        pass


_CRED = {"username": "svc", "password": "x", "secret": ""}


@pytest.fixture
def ssh(monkeypatch):
    netmiko = pytest.importorskip("netmiko")
    import routes.crypto

    fake = _Ssh({"show crypto isakmp sa": _VPN, "show ip route summary": _SUMMARY})
    monkeypatch.setattr(netmiko, "ConnectHandler", fake)
    monkeypatch.setattr(routes.crypto, "decrypt", lambda value: value)
    monkeypatch.setitem(state.MONITORING_CONFIG, "collect_vpn", True)
    monkeypatch.setitem(state.MONITORING_CONFIG, "collect_routes", True)
    monkeypatch.setitem(state.MONITORING_CONFIG, "interval_seconds", 300)
    monkeypatch.setitem(state.MONITORING_CONFIG, "cli_poll_interval_seconds", 900)
    monkeypatch.setattr(monitoring, "_CLI_POLL_STATE", {})
    monkeypatch.setattr(monitoring, "_ROUTE_POLL_STATE", {})
    return fake


async def _poll_cli(monkeypatch, host_id: int = 31, *, snmp_answers: bool = True) -> dict:
    _snmp_device(monkeypatch, answers=snmp_answers)
    return await monitoring._poll_host_monitoring(_host(host_id, "192.0.2.31"), _CRED, {"enabled": True})


async def test_a_poll_inside_the_cli_interval_opens_no_ssh_session_and_carries_the_last_read(monkeypatch, ssh):
    await db.init_db()
    first = await _poll_cli(monkeypatch)
    assert ssh.sessions == 1
    assert (first["vpn_tunnels_up"], first["vpn_tunnels_down"], first["route_count"]) == (1, 1, 12)

    second = await _poll_cli(monkeypatch)
    assert ssh.sessions == 1
    for key in ("vpn_tunnels_up", "vpn_tunnels_down", "vpn_details", "route_count"):
        assert second[key] == first[key]
    assert second["route_snapshot"] == ""
    # A tunnel neither vanishes nor reappears for the alert rules.
    for metric in ("vpn_down", "route_count"):
        assert monitoring._metric_value_from_poll(second, metric) == monitoring._metric_value_from_poll(first, metric)


async def test_a_poll_after_the_cli_interval_reads_it_again(monkeypatch, ssh):
    await db.init_db()
    await _poll_cli(monkeypatch)
    taken, fields = monitoring._CLI_POLL_STATE[31]
    monitoring._CLI_POLL_STATE[31] = (taken - 760, fields)  # 900 s, half a 300 s poll early
    await _poll_cli(monkeypatch)
    assert ssh.sessions == 2


async def test_a_switched_off_part_is_not_carried(monkeypatch, ssh):
    await db.init_db()
    await _poll_cli(monkeypatch)
    monkeypatch.setitem(state.MONITORING_CONFIG, "collect_vpn", False)
    carried = await _poll_cli(monkeypatch)
    assert ssh.sessions == 1
    assert (carried["vpn_tunnels_up"], carried["vpn_details"], carried["route_count"]) == (0, [], 12)


async def test_a_host_whose_snmp_did_not_answer_is_read_every_poll(monkeypatch, ssh):
    """The SSH session is then all that tells whether the host is up."""
    await db.init_db()
    await _poll_cli(monkeypatch, snmp_answers=False)
    await _poll_cli(monkeypatch, snmp_answers=False)
    assert ssh.sessions == 2


async def test_a_failed_cli_read_is_tried_again_at_the_next_poll(monkeypatch, ssh):
    await db.init_db()
    ssh.fail = True
    failed = await _poll_cli(monkeypatch)
    assert failed["vpn_details"] == [] and 31 not in monitoring._CLI_POLL_STATE
    ssh.fail = False
    await _poll_cli(monkeypatch)
    assert ssh.sessions == 2 and 31 in monitoring._CLI_POLL_STATE


async def test_a_manual_poll_reads_the_cli_part(monkeypatch, ssh):
    await db.init_db()
    _snmp_device(monkeypatch)
    host = _host(31, "192.0.2.31")

    async def targets():
        return [(host, _CRED, {"enabled": True})]

    async def store(*_args, **_kwargs):
        return 0

    async def nothing(*_args, **_kwargs):
        return None

    async def empty(*_args, **_kwargs):
        return []

    monkeypatch.setattr(monitoring, "_HOST_POLLS_RUNNING", {})
    monkeypatch.setattr(monitoring, "_build_poll_targets", targets)
    monkeypatch.setattr(monitoring, "_awaiting_confirmation_hosts", empty)
    monkeypatch.setattr(monitoring, "_process_poll_result", store)
    monkeypatch.setattr(monitoring, "_run_retention_cleanup_throttled", nothing)
    monkeypatch.setattr(monitoring, "_resolve_expired_poll_events", nothing)
    monkeypatch.setattr(monitoring.db, "get_alert_rules", empty)
    monkeypatch.setattr(monitoring.db, "get_active_alert_suppressions", empty)
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)

    await monitoring._run_monitoring_poll_once()
    await monitoring._run_monitoring_poll_once()
    assert ssh.sessions == 1  # the scheduled poll inside the interval skipped it
    await monitoring._run_monitoring_poll_once(force=True)
    assert ssh.sessions == 2


@pytest.mark.parametrize(
    ("cli_interval", "elapsed", "due"),
    [(900, 700, False), (900, 750, True), (100, 140, False), (100, 150, True), (0, 150, True)],
)
def test_the_cli_interval_is_never_shorter_than_the_poll_interval(monkeypatch, cli_interval, elapsed, due):
    monkeypatch.setitem(state.MONITORING_CONFIG, "interval_seconds", 300)
    monkeypatch.setitem(state.MONITORING_CONFIG, "cli_poll_interval_seconds", cli_interval)
    monkeypatch.setattr(monitoring, "_CLI_POLL_STATE", {7: (1000.0, {})})
    assert monitoring._cli_poll_due(7, 1000.0 + elapsed) is due
    assert monitoring._cli_poll_due(8, 1000.0) is True  # never read


def test_the_setting_is_kept_between_the_poll_interval_and_a_day():
    sanitize = state._sanitize_monitoring_config
    assert sanitize(None)["cli_poll_interval_seconds"] == 900
    assert sanitize({})["cli_poll_interval_seconds"] == 900
    assert sanitize({"interval_seconds": 600, "cli_poll_interval_seconds": 60})["cli_poll_interval_seconds"] == 600
    assert sanitize({"cli_poll_interval_seconds": 0})["cli_poll_interval_seconds"] == 300
    assert sanitize({"cli_poll_interval_seconds": 10**9})["cli_poll_interval_seconds"] == 86400
    assert sanitize({"cli_poll_interval_seconds": 1800})["cli_poll_interval_seconds"] == 1800
