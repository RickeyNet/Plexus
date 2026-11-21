"""SNMP traps are believed only from the host they claim to come from: the
community must be the one stored for that inventory host, the agent address
inside the packet counts only when the datagram's own source is an
inventory host, and APC traps reach the alert handler through the trap
receiver's bounded queue.

Trap datagrams are built with pysnmp (``tests/test_apc_ups_traps.py``);
addresses are from the documentation ranges.
"""

from __future__ import annotations

import netcontrol.routes.metrics_engine as me
import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import listener_sources as ls, monitoring_repoll as repoll
from netcontrol.integrations.apc import traps as apc_traps
from netcontrol.routes.snmp import decode_snmp_trap, trap_community_matches

from test_apc_ups_traps import v1_trap, v2c_trap

COMMUNITY = "trap-community"  # what v1_trap / v2c_trap send


@pytest.fixture
def monitored(monkeypatch):
    """Monitoring on, the group default community set to the traps', re-polls
    recorded, an empty trap buffer and fresh counters."""
    import netcontrol.routes.monitoring as monitoring

    polled: list[int] = []

    async def fake_poll(host_id: int) -> dict:
        polled.append(host_id)
        return {}

    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    monkeypatch.setitem(state.SNMP_DISCOVERY_CONFIG, "community", COMMUNITY)
    monkeypatch.setattr(monitoring, "poll_host_now", fake_poll)
    monkeypatch.setattr(apc_traps, "REPOLL_DELAY_SECONDS", 0.0)
    repoll._repoll_waiting.clear()
    me._trap_event_buffer.clear()
    me._host_ip_cache.clear()
    ls.guard("trap").reset()
    yield polled
    me._trap_event_buffer.clear()
    ls.guard("trap").reset()


async def _host(name: str, ip: str, device_type: str = "apc_ups") -> int:
    await db.init_db()
    group_id = await db.create_group(f"grp-{name}")
    return await db.add_host(group_id, name, ip, device_type)


async def _open(host_id: int) -> dict[str, dict]:
    return {a["metric"]: a for a in await db.get_monitoring_alerts(host_id, acknowledged=False)}


async def _stored(source_ip: str) -> list[dict]:
    rows = await db.get_trap_syslog_events(limit=50, event_type="trap")
    return [r for r in rows if r["source_ip"] == source_ip]


def _queue(source: str, data: bytes) -> None:
    """What the receiver queues for an accepted datagram."""
    trap = decode_snmp_trap(data)
    apc = apc_traps.parse_apc_trap(trap)
    me._queue_trap_syslog_event(source, "trap", "", apc.severity, apc.trap_oid, apc.message, data.hex(), trap)


# ── The community ────────────────────────────────────────────────────────────


def test_the_community_is_the_hosts_stored_one(monkeypatch):
    trap = decode_snmp_trap(v1_trap(5))
    host = {"id": 1, "group_id": None, "snmp_profile_id": ""}
    monkeypatch.setitem(state.SNMP_DISCOVERY_CONFIG, "community", COMMUNITY)
    assert trap_community_matches(trap, host)
    monkeypatch.setitem(state.SNMP_DISCOVERY_CONFIG, "community", "other-community")
    assert not trap_community_matches(trap, host)
    # The host's own SNMP profile wins over its group's config.
    monkeypatch.setitem(state.SNMP_PROFILES, "ups-profile", {"community": COMMUNITY, "enabled": True})
    assert trap_community_matches(trap, {**host, "snmp_profile_id": "ups-profile"})
    # A host with no community stored accepts none, an empty one included.
    monkeypatch.setitem(state.SNMP_DISCOVERY_CONFIG, "community", "")
    assert not trap_community_matches(trap, host)
    assert not trap_community_matches({**trap, "community": ""}, host)
    assert not trap_community_matches(None, host)


async def test_a_trap_with_the_wrong_community_raises_nothing(monitored, monkeypatch):
    host_id = await _host("ups-a1", "192.0.2.90")
    monkeypatch.setitem(state.SNMP_DISCOVERY_CONFIG, "community", "the-real-one")
    outcome = await apc_traps.handle_apc_trap("192.0.2.90", apc_traps.parse_apc_trap(decode_snmp_trap(v1_trap(5))))
    assert outcome["host_id"] is None
    assert await _open(host_id) == {}
    assert monitored == []


async def test_the_writer_drops_a_wrong_community_and_acts_on_the_right_one(monitored, monkeypatch):
    host_id = await _host("ups-a2", "192.0.2.91")
    monkeypatch.setitem(state.SNMP_DISCOVERY_CONFIG, "community", "the-real-one")
    _queue("192.0.2.91", v1_trap(5))
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert await _stored("192.0.2.91") == []
    assert await _open(host_id) == {}
    assert ls.guard("trap").stats()["dropped_community"] == 1
    assert me.event_receiver_snapshot()["trap_dropped_community"] == 1

    monkeypatch.setitem(state.SNMP_DISCOVERY_CONFIG, "community", COMMUNITY)
    _queue("192.0.2.91", v1_trap(5))
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert len(await _stored("192.0.2.91")) == 1
    assert "ups_on_battery" in await _open(host_id)
    # The resolve comes the same way.
    _queue("192.0.2.91", v2c_trap("1.3.6.1.4.1.318.0.9"))
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert await _open(host_id) == {}


async def test_a_trap_from_an_allowed_network_is_stored_but_never_acted_on(monitored):
    await _host("ups-a3", "192.0.2.92")
    # Not an inventory address (admitted through an extra network): no host,
    # no community to check, so the agent address is not believed either.
    _queue("203.0.113.92", v1_trap(5, agent="192.0.2.92"))
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert len(await _stored("203.0.113.92")) == 1
    assert monitored == []


# ── The agent address ────────────────────────────────────────────────────────


async def test_the_agent_address_counts_only_from_an_inventory_source(monitored):
    ups_id = await _host("ups-a4", "192.0.2.93")
    relay_id = await _host("relay-a4", "198.51.100.93", device_type="cisco_ios")
    # Source unknown: the agent address names the UPS, but is not believed.
    assert await apc_traps.find_ups_host("203.0.113.93", "192.0.2.93") is None
    # Source an inventory host (not the UPS): the agent address picks the UPS.
    found = await apc_traps.find_ups_host("198.51.100.93", "192.0.2.93")
    assert found is not None and found["id"] == ups_id
    # Source the UPS itself.
    assert (await apc_traps.find_ups_host("192.0.2.93", "0.0.0.0"))["id"] == ups_id
    # Source an inventory host that is not a UPS and no agent address.
    assert await apc_traps.find_ups_host("198.51.100.93", "0.0.0.0") is None
    assert relay_id != ups_id


# ── The bounded queue ────────────────────────────────────────────────────────


class _BusyWriter:
    """Stands in for a running writer task, so queueing starts none."""

    def done(self) -> bool:
        return False


def test_apc_traps_go_through_the_bounded_queue(monitored, monkeypatch):
    monkeypatch.setattr(ls, "_inventory_loaded_at", float("inf"))
    monkeypatch.setitem(ls.INVENTORY_ADDRESSES, "192.0.2.94", 1)
    assert not hasattr(apc_traps, "dispatch_apc_trap")
    monkeypatch.setattr(me, "_TRAP_EVENT_BUFFER_MAX", 1)
    monkeypatch.setattr(me, "_trap_event_writer_task", _BusyWriter())  # nothing drains
    monkeypatch.setattr(me, "_trap_events_dropped_total", 0)
    receiver = me._TrapSyslogProtocol("trap")
    receiver.datagram_received(v1_trap(5), ("192.0.2.94", 50162))
    receiver.datagram_received(v1_trap(7), ("192.0.2.94", 50162))
    assert len(me._trap_event_buffer) == 1
    assert me._trap_event_buffer[0][7]["trap_oid"] == "1.3.6.1.4.1.318.0.5"
    assert me.event_receiver_snapshot()["events_dropped"] == 1


async def test_a_failing_apc_handler_is_logged_not_raised(monitored, monkeypatch, caplog):
    await _host("ups-a5", "192.0.2.95")

    async def broken(_source, _trap):
        raise RuntimeError("handler failed")

    monkeypatch.setattr(me, "handle_apc_trap", broken)
    _queue("192.0.2.95", v1_trap(5))
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert len(await _stored("192.0.2.95")) == 1
    assert "handling an APC trap from 192.0.2.95 failed" in caplog.text


async def test_an_snmpv3_trap_is_stored_and_never_acted_on(monitored):
    host_id = await _host("ups-a6", "192.0.2.96")
    v3 = bytes.fromhex("3006020103040100")
    assert decode_snmp_trap(v3) is None
    me._queue_trap_syslog_event("192.0.2.96", "trap", "", "info", "", "SNMP trap", v3.hex(), None)
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert len(await _stored("192.0.2.96")) == 1
    assert await _open(host_id) == {} and monitored == []
