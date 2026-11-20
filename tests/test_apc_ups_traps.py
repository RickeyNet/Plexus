"""APC Smart-UPS SNMP traps: decoding (pysnmp's BER codec, the same library
the poll uses), matching the source to an ``apc_ups`` host, raising and
resolving the built-in UPS alerts under the poll's keys, and the immediate
re-poll.

The trap datagrams are invented, built with pysnmp the way a card builds
them; addresses are from the documentation ranges.
"""

from __future__ import annotations

import asyncio

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import monitoring_repoll as repoll
from netcontrol.integrations.apc import snmp as apc_snmp, traps as apc_traps
from netcontrol.routes.snmp import SNMP_TRAP_OID, decode_snmp_trap
from pyasn1.codec.ber import encoder
from pysnmp.proto import api

UPS_IP = "192.0.2.80"
OTHER_IP = "198.51.100.9"
CARD_TEXT = "UPS: On battery power in response to an input power problem."


def v1_trap(specific: int, enterprise: str = "1.3.6.1.4.1.318", generic: int = 6, agent: str = UPS_IP) -> bytes:
    proto = api.PROTOCOL_MODULES[api.SNMP_VERSION_1]
    pdu = proto.TrapPDU()
    proto.apiTrapPDU.set_defaults(pdu)
    proto.apiTrapPDU.set_enterprise(pdu, enterprise)
    proto.apiTrapPDU.set_agent_address(pdu, agent)
    proto.apiTrapPDU.set_generic_trap(pdu, generic)
    proto.apiTrapPDU.set_specific_trap(pdu, specific)
    proto.apiTrapPDU.set_varbinds(pdu, [(apc_traps.MTRAPARGS_STRING, proto.OctetString(CARD_TEXT))])
    message = proto.Message()
    proto.apiMessage.set_defaults(message)
    proto.apiMessage.set_community(message, "trap-community")
    proto.apiMessage.set_pdu(message, pdu)
    return encoder.encode(message)


def v2c_trap(trap_oid: str) -> bytes:
    proto = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]
    pdu = proto.SNMPv2TrapPDU()
    proto.apiTrapPDU.set_defaults(pdu)
    proto.apiTrapPDU.set_varbinds(
        pdu,
        [
            ("1.3.6.1.2.1.1.3.0", proto.TimeTicks(12345)),
            (SNMP_TRAP_OID, proto.ObjectIdentifier(trap_oid)),
            (apc_traps.MTRAPARGS_STRING, proto.OctetString("UPS: Returned from battery backup power.")),
        ],
    )
    message = proto.Message()
    proto.apiMessage.set_defaults(message)
    proto.apiMessage.set_community(message, "trap-community")
    proto.apiMessage.set_pdu(message, pdu)
    return encoder.encode(message)


def v2c_get_request() -> bytes:
    proto = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]
    pdu = proto.GetRequestPDU()
    proto.apiPDU.set_defaults(pdu)
    proto.apiPDU.set_varbinds(pdu, [("1.3.6.1.2.1.1.1.0", proto.Null(""))])
    message = proto.Message()
    proto.apiMessage.set_defaults(message)
    proto.apiMessage.set_community(message, "trap-community")
    proto.apiMessage.set_pdu(message, pdu)
    return encoder.encode(message)


def _apc(data: bytes) -> apc_traps.ApcTrap:
    trap = apc_traps.parse_apc_trap(decode_snmp_trap(data))
    assert trap is not None
    return trap


# ── Decoding ─────────────────────────────────────────────────────────────────


def test_a_v1_trap_is_decoded():
    trap = decode_snmp_trap(v1_trap(5))
    assert trap is not None
    assert (trap["version"], trap["community"], trap["trap_oid"], trap["agent_address"]) == (
        "v1",
        "trap-community",
        "1.3.6.1.4.1.318.0.5",
        UPS_IP,
    )
    assert trap["varbinds"] == [(apc_traps.MTRAPARGS_STRING, CARD_TEXT)]
    # A generic v1 trap (coldStart) maps to snmpTraps.1 (RFC 3584).
    assert decode_snmp_trap(v1_trap(0, generic=0))["trap_oid"] == "1.3.6.1.6.3.1.1.5.1"


def test_a_v2c_trap_is_decoded():
    trap = decode_snmp_trap(v2c_trap("1.3.6.1.4.1.318.0.9"))
    assert trap is not None
    assert (trap["version"], trap["trap_oid"], trap["agent_address"]) == ("v2c", "1.3.6.1.4.1.318.0.9", "")


def test_what_is_not_a_v1_or_v2c_trap_is_not_decoded():
    assert decode_snmp_trap(b"") is None
    assert decode_snmp_trap(b"\x30\x03garbage") is None
    assert decode_snmp_trap(b"<134>syslog line, not SNMP") is None
    assert decode_snmp_trap(v2c_get_request()) is None
    # An SNMPv3 header (version 3): its PDU needs the user's keys.
    assert decode_snmp_trap(bytes.fromhex("3006020103040100")) is None


def test_the_apc_trap_is_recognised():
    on_battery = _apc(v1_trap(5))
    assert (on_battery.number, on_battery.kind.name, on_battery.severity) == (5, "upsOnBattery", "warning")
    assert on_battery.message == f"APC upsOnBattery: UPS on battery ({CARD_TEXT})"
    assert on_battery.agent_address == UPS_IP
    restored = _apc(v2c_trap("1.3.6.1.4.1.318.0.9"))
    assert (restored.kind.name, restored.kind.alert, restored.kind.action) == (
        "powerRestored",
        "ups_on_battery",
        "resolve",
    )
    # An APC trap that is not a UPS trap Plexus knows: still APC, no kind.
    outlet = _apc(v1_trap(41))
    assert (outlet.kind, outlet.severity, outlet.message.split(" (")[0]) == (None, "info", "APC trap 41")
    # Not APC.
    assert apc_traps.parse_apc_trap(decode_snmp_trap(v1_trap(5, enterprise="1.3.6.1.4.1.9"))) is None
    assert apc_traps.parse_apc_trap({"trap_oid": "1.3.6.1.4.1.318.0.x"}) is None
    assert apc_traps.parse_apc_trap(None) is None


def test_the_trap_table_names_the_poll_alerts():
    alerts = {kind.alert for kind in apc_traps.APC_UPS_TRAPS.values() if kind.alert}
    assert alerts == {*apc_snmp.ALERT_METRICS, apc_snmp.ALERT_COMMUNICATION} - {apc_snmp.ALERT_TEMPERATURE}
    for number, name in [(1, "communicationLost"), (2, "upsOverload"), (5, "upsOnBattery"), (7, "lowBattery")]:
        assert apc_traps.APC_UPS_TRAPS[number].name == name
    for number, name in [(9, "powerRestored"), (11, "returnFromLowBattery"), (17, "upsBatteryNeedsReplacement")]:
        assert apc_traps.APC_UPS_TRAPS[number].name == name
    for number, name in [(23, "returnFromBypass"), (33, "upsOverloadCleared"), (53, "batteryOverTemperature")]:
        assert apc_traps.APC_UPS_TRAPS[number].name == name
    for kind in apc_traps.APC_UPS_TRAPS.values():
        assert kind.action in ("", "raise", "resolve") and bool(kind.alert) == bool(kind.action)


# ── Acting on a trap ─────────────────────────────────────────────────────────


@pytest.fixture
def repolls(monkeypatch):
    """Monitoring on, and re-polls recorded instead of polling."""
    import netcontrol.routes.monitoring as monitoring

    polled: list[int] = []

    async def fake_poll(host_id: int) -> dict:
        polled.append(host_id)
        return {}

    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    monkeypatch.setattr(monitoring, "poll_host_now", fake_poll)
    monkeypatch.setattr(apc_traps, "REPOLL_DELAY_SECONDS", 0.0)
    repoll._repoll_waiting.clear()
    return polled


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)
    await asyncio.gather(*list(repoll._background), return_exceptions=True)


async def _ups(name: str = "ups-t1", ip: str = UPS_IP, device_type: str = "apc_ups") -> tuple[int, int]:
    await db.init_db()
    group_id = await db.create_group(f"grp-{name}")
    return group_id, await db.add_host(group_id, name, ip, device_type)


async def _open(host_id: int) -> dict[str, dict]:
    return {a["metric"]: a for a in await db.get_monitoring_alerts(host_id, acknowledged=False)}


async def test_on_battery_then_power_restored(repolls):
    _group_id, host_id = await _ups()

    outcome = await apc_traps.handle_apc_trap(UPS_IP, _apc(v1_trap(5)))
    assert outcome == {"host_id": host_id, "alert": "ups_on_battery", "action": "raise", "repoll": True}
    alert = (await _open(host_id))["ups_on_battery"]
    assert (alert["severity"], alert["dedup_key"], alert["alert_type"]) == (
        "warning",
        f"{host_id}:ups_on_battery:status",
        "status",
    )
    assert alert["message"] == "UPS on battery (SNMP trap upsOnBattery)"
    await _settle()
    assert repolls == [host_id]

    outcome = await apc_traps.handle_apc_trap(UPS_IP, _apc(v2c_trap("1.3.6.1.4.1.318.0.9")))
    assert (outcome["alert"], outcome["action"]) == ("ups_on_battery", "resolve")
    assert await _open(host_id) == {}
    resolved = await db.get_monitoring_alerts(host_id, acknowledged=True)
    assert [(a["metric"], a["acknowledged_by"]) for a in resolved] == [("ups_on_battery", "auto-resolved")]
    await _settle()
    assert repolls == [host_id, host_id]


async def test_the_trap_and_the_poll_share_one_alert(repolls):
    from netcontrol.routes.monitoring import _evaluate_alerts_for_poll

    group_id, host_id = await _ups("ups-t2", "192.0.2.81")
    await apc_traps.handle_apc_trap("192.0.2.81", _apc(v1_trap(2)))  # upsOverload
    assert (await _open(host_id))["ups_overload"]["alert_type"] == "threshold"

    # The poll that follows still reads the overload: the same alert, bumped.
    status = apc_snmp.parse_ups_status({"output_status": 2, "battery_status": 2, "output_load": 107})
    res = {
        "host_id": host_id,
        "cpu_percent": None,
        "memory_percent": None,
        "if_down_count": 0,
        "if_details": [],
        "vpn_tunnels_down": 0,
        "vpn_details": [],
        "ups": status,
    }
    poll_id = await db.create_monitoring_poll(host_id)
    await _evaluate_alerts_for_poll(res, poll_id, group_id, [])
    alerts = await db.get_monitoring_alerts(host_id)
    assert [(a["metric"], a["occurrence_count"]) for a in alerts] == [("ups_overload", 2)]

    # The overload clears on the UPS: the trap resolves the poll's alert.
    await apc_traps.handle_apc_trap("192.0.2.81", _apc(v1_trap(33)))
    assert await _open(host_id) == {}


async def test_communication_lost_is_resolved_by_a_poll_that_reads_the_ups(repolls):
    from netcontrol.routes.monitoring import _evaluate_alerts_for_poll

    group_id, host_id = await _ups("ups-t3", "192.0.2.82")
    await apc_traps.handle_apc_trap("192.0.2.82", _apc(v1_trap(1)))
    assert (await _open(host_id))["ups_communication"]["severity"] == "critical"
    res = {
        "host_id": host_id,
        "cpu_percent": None,
        "memory_percent": None,
        "if_down_count": 0,
        "if_details": [],
        "vpn_tunnels_down": 0,
        "vpn_details": [],
        "ups": apc_snmp.parse_ups_status({"output_status": 2, "battery_status": 2}),
    }
    await _evaluate_alerts_for_poll(res, await db.create_monitoring_poll(host_id), group_id, [])
    assert await _open(host_id) == {}


async def test_a_trap_with_no_alert_only_repolls(repolls):
    _group_id, host_id = await _ups("ups-t4", "192.0.2.83")
    outcome = await apc_traps.handle_apc_trap("192.0.2.83", _apc(v1_trap(53)))  # batteryOverTemperature
    assert outcome == {"host_id": host_id, "alert": "", "action": "", "repoll": True}
    # An APC trap Plexus has no entry for re-polls too.
    await _settle()
    outcome = await apc_traps.handle_apc_trap("192.0.2.83", _apc(v1_trap(734)))
    assert outcome["repoll"] is True
    assert await _open(host_id) == {}


async def test_a_suppressed_alert_is_not_raised(repolls):
    group_id, host_id = await _ups("ups-t5", "192.0.2.84")
    await db.create_alert_suppression("maintenance", "2099-01-01 00:00:00", host_id=host_id, metric="ups_on_battery")
    outcome = await apc_traps.handle_apc_trap("192.0.2.84", _apc(v1_trap(5)))
    assert (outcome["action"], outcome["repoll"]) == ("", True)
    assert await _open(host_id) == {}


async def test_the_host_is_matched_by_an_interface_ip_or_the_agent_address(repolls):
    _group_id, host_id = await _ups("ups-t6", "192.0.2.85")
    await db.set_host_ip_aliases(host_id, "192.0.2.85", ["198.51.100.85"])
    outcome = await apc_traps.handle_apc_trap("198.51.100.85", _apc(v1_trap(5, agent="0.0.0.0")))
    assert outcome["host_id"] == host_id
    # Behind NAT: the source is unknown, the v1 agent address is the UPS.
    outcome = await apc_traps.handle_apc_trap("203.0.113.7", _apc(v1_trap(7, agent="192.0.2.85")))
    assert (outcome["host_id"], outcome["alert"]) == (host_id, "ups_battery")
    assert await apc_traps.find_ups_host("not-an-address", "0.0.0.0") is None


async def test_unmatched_sources_are_only_stored(repolls):
    await _ups("sw-t7", OTHER_IP, device_type="cisco_ios")
    # A known host that is not a UPS, and an address not in inventory.
    for source in (OTHER_IP, "203.0.113.99"):
        outcome = await apc_traps.handle_apc_trap(source, _apc(v1_trap(5, agent="0.0.0.0")))
        assert outcome == {"host_id": None, "alert": "", "action": "", "repoll": False}
    await _settle()
    assert repolls == []


async def test_nothing_happens_while_monitoring_is_off(repolls, monkeypatch):
    _group_id, host_id = await _ups("ups-t8", "192.0.2.86")
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", False)
    outcome = await apc_traps.handle_apc_trap("192.0.2.86", _apc(v1_trap(5)))
    assert outcome["host_id"] is None and await _open(host_id) == {}


async def test_a_burst_of_traps_is_one_repoll(repolls, monkeypatch):
    monkeypatch.setattr(apc_traps, "REPOLL_DELAY_SECONDS", 0.05)
    assert repoll.schedule_repoll(42, 0.05) is True
    assert repoll.schedule_repoll(42, 0.05) is False
    await asyncio.sleep(0.1)
    await _settle()
    assert repolls == [42]
    # Waiting is over: the next trap schedules a new one.
    assert repoll.schedule_repoll(42, 0.0) is True
    await _settle()
    assert repolls == [42, 42]


async def test_a_failing_repoll_is_logged(monkeypatch, caplog):
    import netcontrol.routes.monitoring as monitoring

    async def broken(_host_id: int) -> dict:
        raise RuntimeError("poll failed")

    monkeypatch.setattr(monitoring, "poll_host_now", broken)
    repoll._repoll_waiting.clear()
    assert repoll.schedule_repoll(43, 0.0)
    await _settle()
    assert "re-poll of host 43 failed" in caplog.text


async def test_poll_host_now(monkeypatch):
    import netcontrol.routes.monitoring as monitoring

    calls: list[dict] = []

    async def fake_once(**kwargs) -> dict:
        calls.append(kwargs)
        return {"hosts_polled": 1}

    monkeypatch.setattr(monitoring, "_run_monitoring_poll_once", fake_once)
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", False)
    assert (await monitoring.poll_host_now(9))["hosts_polled"] == 0 and calls == []
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    assert (await monitoring.poll_host_now(9))["hosts_polled"] == 1
    assert calls == [{"force": True, "host_ids": frozenset({9})}]


# ── The UDP receiver ─────────────────────────────────────────────────────────


def _receive(monkeypatch, data: bytes, source: str) -> tuple[list[tuple], list[tuple]]:
    from netcontrol.routes import metrics_engine

    queued: list[tuple] = []
    dispatched: list[tuple] = []
    monkeypatch.setattr(metrics_engine, "_queue_trap_syslog_event", lambda *args: queued.append(args))
    monkeypatch.setattr(metrics_engine, "dispatch_apc_trap", lambda ip, trap: dispatched.append((ip, trap)))
    metrics_engine._TrapSyslogProtocol("trap").datagram_received(data, (source, 50162))
    return queued, dispatched


def test_the_receiver_stores_and_dispatches_an_apc_trap(monkeypatch):
    queued, dispatched = _receive(monkeypatch, v1_trap(7), UPS_IP)
    ((source, event_type, _facility, severity, oid, message, raw),) = queued
    assert (source, event_type, severity, oid) == (UPS_IP, "trap", "critical", "1.3.6.1.4.1.318.0.7")
    assert message.startswith("APC lowBattery: UPS battery low")
    assert raw == v1_trap(7).hex()
    assert [(ip, trap.number) for ip, trap in dispatched] == [(UPS_IP, 7)]


def test_the_receiver_keeps_other_traps_as_before(monkeypatch):
    queued, dispatched = _receive(monkeypatch, v1_trap(5, enterprise="1.3.6.1.4.1.9"), OTHER_IP)
    assert dispatched == []
    assert queued[0][3] == "info" and queued[0][5].startswith(f"SNMP trap from {OTHER_IP}")
    queued, dispatched = _receive(monkeypatch, b"\x30\x03junk", OTHER_IP)
    assert dispatched == [] and len(queued) == 1


async def test_dispatch_runs_the_handler_in_the_background(monkeypatch):
    seen: list[tuple] = []

    async def fake_handle(ip, trap):
        seen.append((ip, trap.number))
        raise RuntimeError("boom")  # logged, not raised

    monkeypatch.setattr(apc_traps, "handle_apc_trap", fake_handle)
    apc_traps.dispatch_apc_trap(UPS_IP, _apc(v1_trap(5)))
    await _settle()
    assert seen == [(UPS_IP, 5)]
