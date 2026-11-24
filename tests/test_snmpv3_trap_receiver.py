"""SNMPv3 traps through the trap receiver: the hot path queues the datagram
whole (``PendingV3Trap``) from an inventory source, the batch writer decodes
it with the source host's SNMPv3 poll user (``netcontrol.snmpv3_traps``),
stores it named and acts on it (trap rules, the APC handler); a refused one
is dropped and counted (``trap_dropped_v3``); an inform, or one from a
source that is not an inventory host, is stored undecoded.

Datagrams are built by ``test_snmpv3_traps.message`` (framed by hand,
signed and encrypted with pysnmp's USM services). User names and
passphrases are invented; addresses are from the documentation ranges.
"""

from __future__ import annotations

import netcontrol.routes.metrics_engine as me
import netcontrol.routes.state as state
import netcontrol.snmpv3_engine as se
import netcontrol.snmpv3_traps as v3
import pytest
import routes.database as db
from netcontrol import listener_sources as ls, monitoring_repoll as repoll, syslog_rules as sr, trap_rules as tr
from netcontrol.integrations.apc import traps as apc_traps
from netcontrol.routes.snmp import SNMP_TRAP_OID
from pysnmp.proto import api

from test_snmp_traps import CEFC, cefc_module
from test_snmpv3_traps import USER, config, message

P = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]


def pdu(trap_oid: str, varbinds) -> object:
    trap = P.SNMPv2TrapPDU()
    P.apiPDU.set_defaults(trap)
    P.apiPDU.set_varbinds(
        trap,
        [("1.3.6.1.2.1.1.3.0", P.TimeTicks(4242)), (SNMP_TRAP_OID, P.ObjectIdentifier(trap_oid)), *varbinds],
    )
    return trap


def module_failed() -> object:
    """cefcModuleStatusChange: module 1001 failed (7)."""
    return pdu(f"{CEFC}.2.0.1", [(f"{CEFC}.1.2.1.1.2.1001", P.Integer(7)), (f"{CEFC}.1.2.1.1.4.1001", P.Integer(1234))])


def ups_on_battery() -> object:
    return pdu("1.3.6.1.4.1.318.0.5", [(apc_traps.MTRAPARGS_STRING, P.OctetString("UPS: On battery power."))])


@pytest.fixture
def v3_receiver(monkeypatch):
    """Monitoring and trap alerts on, the global SNMP config the v3 user
    (authPriv, SHA / AES-128), a fresh replay guard and counters, re-polls
    recorded."""
    import netcontrol.routes.monitoring as monitoring

    sr.reset_state()
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    monkeypatch.setattr(state, "SNMP_PROFILES", {})
    monkeypatch.setattr(state, "GROUP_SNMP_ASSIGNMENTS", {})
    monkeypatch.setattr(state, "SNMP_DISCOVERY_PROFILES", {})
    monkeypatch.setattr(state, "SNMP_DISCOVERY_CONFIG", config())
    monkeypatch.setattr(
        state, "EVENT_RECEIVER_CONFIG", {"trap_alerts": True, "config_change_trigger": False, "repoll_trigger": True}
    )
    repolls: list[int] = []
    monkeypatch.setattr(tr, "schedule_repoll", lambda host_id, *_a, **_k: repolls.append(host_id) or True)

    async def fake_poll(host_id: int) -> dict:
        repolls.append(host_id)
        return {}

    monkeypatch.setattr(monitoring, "poll_host_now", fake_poll)
    monkeypatch.setattr(apc_traps, "REPOLL_DELAY_SECONDS", 0.0)
    monkeypatch.setattr(me, "_V3_REPLAY_GUARD", v3.ReplayGuard())
    monkeypatch.setattr(me, "_v3_pending", 0)
    monkeypatch.setattr(me, "_v3_replies_waiting", 0)
    monkeypatch.setattr(me, "_trap_event_writer_task", _BusyWriter())
    se.reset()
    repoll._repoll_waiting.clear()
    me._trap_event_buffer.clear()
    me._host_ip_cache.clear()
    ls.guard("trap").reset()
    yield repolls
    me._trap_event_buffer.clear()
    ls.guard("trap").reset()
    sr.reset_state()
    se.reset()


class _BusyWriter:
    def done(self) -> bool:
        return False


async def _host(monkeypatch, name: str, ip: str, device_type: str = "cisco_ios") -> int:
    """An inventory host, also in the listener's inventory address set."""
    await db.init_db()
    group_id = await db.create_group(f"grp-{name}")
    host_id = await db.add_host(group_id, name, ip, device_type)
    monkeypatch.setitem(ls.INVENTORY_ADDRESSES, ip, host_id)
    return host_id


async def _receive(source: str, *datagrams: bytes) -> None:
    protocol = me._TrapSyslogProtocol("trap")
    for data in datagrams:
        protocol._handle_trap(data, source)
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())


async def _stored(source: str) -> list[dict]:
    rows = await db.get_trap_syslog_events(limit=50, event_type="trap")
    return [r for r in rows if r["source_ip"] == source]


async def _open(host_id: int) -> dict[str, dict]:
    return {a["dedup_key"]: a for a in await db.get_monitoring_alerts(host_id, acknowledged=False)}


def _v3_drops() -> int:
    return ls.guard("trap").stats()["dropped_v3"]


# ── Accepted ─────────────────────────────────────────────────────────────────


async def test_an_authpriv_trap_from_an_inventory_host_is_stored_named_and_raises_its_rule(v3_receiver, monkeypatch):
    host_id = await _host(monkeypatch, "v3-sw1", "192.0.2.150")
    await _receive("192.0.2.150", message(pdu=module_failed()))
    stored = await _stored("192.0.2.150")
    assert len(stored) == 1
    assert stored[0]["oid"] == f"{CEFC}.2.0.1"
    assert stored[0]["message"].startswith("cefcModuleStatusChange: cefcModuleOperStatus failed")
    assert stored[0]["severity"] == "critical"
    assert list(await _open(host_id)) == [f"trap:module:{host_id}:entPhysicalIndex 1001"]
    assert _v3_drops() == 0


async def test_the_decoded_v3_trap_reaches_the_rules_with_its_v3_fields(v3_receiver, monkeypatch):
    host_id = await _host(monkeypatch, "v3-sw2", "192.0.2.151")
    seen: list[tuple] = []

    async def record(batch):
        seen.extend(batch)

    monkeypatch.setattr(tr, "process_trap_batch", record)
    await _receive("192.0.2.151", message(pdu=module_failed()))
    ((rule_host, named),) = seen
    trap = named.trap
    assert rule_host == host_id
    assert (trap["version"], trap["user"], trap["security_level"], trap["pdu"]) == ("v3", USER, "authPriv", "trap")
    assert trap["community"] == "" and isinstance(trap["request_id"], int) and trap["engine_id"]


async def test_an_apc_v3_trap_raises_the_ups_alert(v3_receiver, monkeypatch):
    host_id = await _host(monkeypatch, "v3-ups1", "192.0.2.152", device_type="apc_ups")
    await _receive("192.0.2.152", message(pdu=ups_on_battery()))
    stored = await _stored("192.0.2.152")
    assert stored[0]["message"].startswith("APC upsOnBattery: UPS on battery")
    assert {a["metric"] for a in (await _open(host_id)).values()} == {"ups_on_battery"}


async def test_an_authnopriv_host_takes_authnopriv_traps(v3_receiver, monkeypatch):
    monkeypatch.setattr(state, "SNMP_DISCOVERY_CONFIG", config("sha256", None))
    host_id = await _host(monkeypatch, "v3-sw3", "192.0.2.153")
    await _receive("192.0.2.153", message(auth="sha256", priv=None, pdu=module_failed()))
    assert list(await _open(host_id)) == [f"trap:module:{host_id}:entPhysicalIndex 1001"]


async def test_a_v2c_trap_still_works(v3_receiver, monkeypatch):
    monkeypatch.setattr(state, "SNMP_DISCOVERY_CONFIG", {"enabled": True, "version": "2c", "community": "trap-community"})
    host_id = await _host(monkeypatch, "v3-sw4", "192.0.2.154")
    await _receive("192.0.2.154", cefc_module(7))
    assert list(await _open(host_id)) == [f"trap:module:{host_id}:entPhysicalIndex 1001"]


# ── Refused: dropped and counted ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "kwargs",
    [
        {"auth_pass": "not-the-auth-passphrase"},  # authentication
        {"priv_pass": "not-the-priv-passphrase"},  # decryption
        {"user": "someone-else"},  # unknown user
        {"priv": None},  # authNoPriv to an authPriv host
        {"auth": None, "priv": None},  # noAuthNoPriv
    ],
)
async def test_a_refused_v3_trap_is_dropped_and_counted(v3_receiver, monkeypatch, kwargs):
    host_id = await _host(monkeypatch, "v3-sw5", "192.0.2.155")
    await _receive("192.0.2.155", message(pdu=module_failed(), **kwargs))
    assert await _stored("192.0.2.155") == []
    assert await _open(host_id) == {}
    assert _v3_drops() == 1
    snapshot = me.event_receiver_snapshot()
    assert snapshot["trap_dropped_v3"] == 1 and snapshot["trap_dropped_community"] == 0


async def test_a_replayed_trap_is_dropped(v3_receiver, monkeypatch):
    await _host(monkeypatch, "v3-sw6", "192.0.2.156")
    data = message(pdu=module_failed())
    await _receive("192.0.2.156", data)
    await _receive("192.0.2.156", data)
    assert len(await _stored("192.0.2.156")) == 1
    assert _v3_drops() == 1


async def test_a_stale_trap_is_dropped(v3_receiver, monkeypatch):
    await _host(monkeypatch, "v3-sw7", "192.0.2.157")
    await _receive("192.0.2.157", message(pdu=module_failed(), boots=4, engine_time=5000))
    await _receive("192.0.2.157", message(pdu=module_failed(), boots=4, engine_time=1000))  # 4000 s behind
    await _receive("192.0.2.157", message(pdu=module_failed(), boots=3, engine_time=9000))  # an older boot
    assert len(await _stored("192.0.2.157")) == 1
    assert _v3_drops() == 2


async def test_a_host_with_v2c_settings_sending_v3_is_dropped(v3_receiver, monkeypatch):
    monkeypatch.setattr(state, "SNMP_DISCOVERY_CONFIG", {"enabled": True, "version": "2c", "community": "ro"})
    await _host(monkeypatch, "v3-sw8", "192.0.2.158")
    await _receive("192.0.2.158", message(pdu=module_failed()))
    assert await _stored("192.0.2.158") == []
    assert _v3_drops() == 1


async def test_credentials_that_fail_to_resolve_count_as_no_user(v3_receiver, monkeypatch):
    await _host(monkeypatch, "v3-sw9", "192.0.2.159")

    async def broken(_host):
        raise RuntimeError("secret store unavailable")

    monkeypatch.setattr(me, "resolve_trap_v3_credentials", broken)
    await _receive("192.0.2.159", message(pdu=module_failed()), message(pdu=module_failed()))
    assert _v3_drops() == 2


# ── Kept undecoded ───────────────────────────────────────────────────────────


async def test_an_inform_without_a_started_engine_is_stored_undecoded(v3_receiver, monkeypatch):
    """The receiver's SNMPv3 engine did not start (no database at start):
    an inform is stored with its size, as before informs were answered."""
    assert se.LOCAL is None
    host_id = await _host(monkeypatch, "v3-sw10", "192.0.2.160")
    await _receive("192.0.2.160", message(pdu=module_failed(), flags=0x07))
    stored = await _stored("192.0.2.160")
    assert len(stored) == 1 and stored[0]["message"].startswith("SNMP trap from 192.0.2.160 (")
    assert await _open(host_id) == {} and _v3_drops() == 0


async def test_a_v3_trap_from_a_non_inventory_source_is_stored_undecoded(v3_receiver):
    protocol = me._TrapSyslogProtocol("trap")
    protocol._handle_trap(message(pdu=module_failed()), "203.0.113.161")
    ((*_head, trap, _transport),) = me._trap_event_buffer
    assert trap is None  # never held for decoding
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert len(await _stored("203.0.113.161")) == 1 and _v3_drops() == 0


async def test_a_pending_v3_trap_whose_host_is_gone_is_stored_undecoded(v3_receiver, monkeypatch):
    """In the listener's address set but no longer in the database."""
    monkeypatch.setitem(ls.INVENTORY_ADDRESSES, "198.51.100.162", 999999)
    await _receive("198.51.100.162", message(pdu=module_failed()))
    assert len(await _stored("198.51.100.162")) == 1 and _v3_drops() == 0


async def test_the_receiver_holds_a_bounded_number_of_v3_datagrams(v3_receiver, monkeypatch):
    await _host(monkeypatch, "v3-sw11", "192.0.2.163")
    monkeypatch.setattr(me, "_V3_PENDING_MAX", 2)
    protocol = me._TrapSyslogProtocol("trap")
    for _ in range(3):
        protocol._handle_trap(message(pdu=module_failed()), "192.0.2.163")
    assert [isinstance(row[7], v3.PendingV3Trap) for row in me._trap_event_buffer] == [True, True, False]
    me._take_trap_event_batch()
    assert me._v3_pending == 0


# ── The APC handler ──────────────────────────────────────────────────────────


async def test_the_apc_handler_believes_an_authenticated_trap_only_for_its_host(v3_receiver, monkeypatch):
    host_id = await _host(monkeypatch, "v3-ups2", "192.0.2.164", device_type="apc_ups")
    trap = {"version": "v3", "community": "", "trap_oid": "1.3.6.1.4.1.318.0.5", "agent_address": "", "varbinds": []}
    apc = apc_traps.parse_apc_trap(trap)
    # No community: a v3 trap the receiver did not authenticate is ignored.
    assert (await apc_traps.handle_apc_trap("192.0.2.164", apc))["host_id"] is None
    assert (await apc_traps.handle_apc_trap("192.0.2.164", apc, host_id + 1))["host_id"] is None
    assert (await apc_traps.handle_apc_trap("192.0.2.164", apc, host_id))["host_id"] == host_id


def test_a_v3_dict_is_never_believed_on_its_own():
    """``_trap_believed`` takes an SNMPv3 trap's authentication from the
    batch writer, never from the dict."""
    trap = {"version": "v3", "community": "trap-community"}
    assert not me._trap_believed(trap, {"id": 1, "group_id": None})
    assert me._trap_believed(trap, {"id": 1, "group_id": None}, True)



# ── Informs answered by the receiver's own engine ────────────────────────────

LOCAL_ID = bytes.fromhex("80004fb805102030405060708090a0b0c0")  # invented


def as_inform(trap) -> object:
    """The same varbinds in an InformRequest."""
    inform = P.InformRequestPDU()
    P.apiPDU.set_defaults(inform)
    P.apiPDU.set_varbinds(inform, P.apiPDU.get_varbinds(trap))
    return inform


@pytest.fixture
def engine(v3_receiver, monkeypatch):
    """A started receiver engine; every answer the receiver sends recorded
    as ``(datagram, address)``."""
    sent: list[tuple[bytes, tuple]] = []
    monkeypatch.setattr(se, "LOCAL", v3.LocalEngine(LOCAL_ID, 3))
    monkeypatch.setattr(me, "_send_reply", lambda data, addr: sent.append((data, addr)))
    return sent


def inform_to_local(**kwargs) -> bytes:
    eng = se.LOCAL
    kwargs.setdefault("pdu", as_inform(module_failed()))
    kwargs.setdefault("flags", 0x07)
    return message(engine=eng.engine_id, boots=eng.boots, engine_time=eng.engine_time, **kwargs)


async def _receive_from(source: str, *datagrams: bytes) -> tuple:
    addr = (source, 50162)
    protocol = me._TrapSyslogProtocol("trap")
    for data in datagrams:
        protocol._handle_trap(data, source, addr)
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    return addr


async def test_a_discovery_probe_is_answered_at_once_and_not_stored(engine, monkeypatch):
    await _host(monkeypatch, "v3-inf1", "192.0.2.170")
    protocol = me._TrapSyslogProtocol("trap")
    protocol._handle_trap(
        message(auth=None, priv=None, engine=b"", user="", flags=0x04, pdu=trap_get()),
        "192.0.2.170",
        ("192.0.2.170", 50162),
    )
    assert me._trap_event_buffer == []
    ((report, addr),) = engine
    assert addr == ("192.0.2.170", 50162)
    assert v3.parse_snmpv3_header(report).engine_id == LOCAL_ID
    assert me.event_receiver_snapshot()["trap_usm_unknown_engine_ids"] == 1
    assert _v3_drops() == 0


def trap_get() -> object:
    get = P.GetRequestPDU()
    P.apiPDU.set_defaults(get)
    P.apiPDU.set_varbinds(get, [])
    return get


async def test_an_inform_is_answered_stored_named_and_raises_its_rule(engine, monkeypatch):
    host_id = await _host(monkeypatch, "v3-inf2", "192.0.2.171")
    data = inform_to_local()
    addr = await _receive_from("192.0.2.171", data)
    stored = await _stored("192.0.2.171")
    assert len(stored) == 1 and stored[0]["message"].startswith("cefcModuleStatusChange: cefcModuleOperStatus failed")
    assert list(await _open(host_id)) == [f"trap:module:{host_id}:entPhysicalIndex 1001"]
    ((response, to),) = engine
    assert to == addr
    header = v3.parse_snmpv3_header(response)
    assert header.msg_id == v3.parse_snmpv3_header(data).msg_id and header.security_level == "authPriv"
    snapshot = me.event_receiver_snapshot()
    assert snapshot["trap_v3_informs_answered"] == 1 and snapshot["trap_engine_id"] == LOCAL_ID.hex()
    assert _v3_drops() == 0


async def test_the_inform_reaches_the_rules_as_an_inform(engine, monkeypatch):
    await _host(monkeypatch, "v3-inf3", "192.0.2.172")
    seen: list[tuple] = []

    async def record(batch):
        seen.extend(batch)

    monkeypatch.setattr(tr, "process_trap_batch", record)
    await _receive_from("192.0.2.172", inform_to_local())
    ((_host_id, named),) = seen
    assert named.trap["pdu"] == "inform" and named.trap["version"] == "v3"


async def test_a_time_synchronization_inform_gets_its_report_and_is_not_stored(engine, monkeypatch):
    await _host(monkeypatch, "v3-inf4", "192.0.2.173")
    await _receive_from(
        "192.0.2.173", message(engine=LOCAL_ID, boots=0, engine_time=0, flags=0x07, pdu=as_inform(module_failed()))
    )
    assert await _stored("192.0.2.173") == []
    ((report, _addr),) = engine
    assert v3.parse_snmpv3_header(report).security_level == "authNoPriv"
    assert _v3_drops() == 0
    assert me.event_receiver_snapshot()["trap_usm_not_in_time_windows"] == 1


@pytest.mark.parametrize(
    "kwargs", [{"auth_pass": "not-the-auth-passphrase"}, {"user": "someone-else"}, {"priv": None, "flags": 0x05}]
)
async def test_a_refused_inform_is_dropped_counted_and_not_answered(engine, monkeypatch, kwargs):
    await _host(monkeypatch, "v3-inf5", "192.0.2.174")
    await _receive_from("192.0.2.174", inform_to_local(**kwargs))
    assert await _stored("192.0.2.174") == [] and engine == []
    assert _v3_drops() == 1


async def test_an_inform_from_a_non_inventory_source_is_stored_undecoded_and_not_answered(engine):
    await _receive_from("203.0.113.175", inform_to_local())
    await _receive_from("203.0.113.175", message(auth=None, priv=None, engine=b"", user="", flags=0x04, pdu=trap_get()))
    assert engine == []
    assert len(await _stored("203.0.113.175")) == 2 and _v3_drops() == 0


async def test_informs_past_the_pending_limit_are_stored_undecoded(engine, monkeypatch):
    await _host(monkeypatch, "v3-inf6", "192.0.2.176")
    monkeypatch.setattr(me, "_V3_PENDING_MAX", 1)
    protocol = me._TrapSyslogProtocol("trap")
    for _ in range(2):
        protocol._handle_trap(inform_to_local(), "192.0.2.176", ("192.0.2.176", 50162))
    assert [isinstance(row[7], v3.PendingV3Trap) for row in me._trap_event_buffer] == [True, False]
    assert me._v3_replies_waiting == 1
    me._take_trap_event_batch()
    assert me._v3_replies_waiting == 0


async def test_the_writer_flushes_early_for_an_inform(engine, monkeypatch):
    import asyncio

    await _host(monkeypatch, "v3-inf7", "192.0.2.177")
    monkeypatch.setattr(me, "_TRAP_EVENT_FLUSH_SECONDS", 30.0)
    monkeypatch.setattr(me, "_TRAP_EVENT_REPLY_SECONDS", 0.01)
    persisted: list[bool] = []

    async def persist(_guard, **_kwargs):
        persisted.append(True)
        return 0

    monkeypatch.setattr(se, "persist_replay", persist)
    me._TrapSyslogProtocol("trap")._handle_trap(inform_to_local(), "192.0.2.177", ("192.0.2.177", 50162))
    task = asyncio.ensure_future(me._trap_event_writer_loop())
    try:
        for _ in range(300):
            if engine and persisted:
                break
            await asyncio.sleep(0.01)
    finally:
        task.cancel()
    assert len(engine) == 1 and persisted


async def test_shutdown_writes_the_replay_record_only_with_an_engine(engine, monkeypatch):
    calls: list[dict] = []

    async def persist(_guard, **kwargs):
        calls.append(kwargs)
        return 2

    monkeypatch.setattr(se, "persist_replay", persist)
    assert await me.flush_v3_state() == 2 and calls == [{"force": True}]
    monkeypatch.setattr(se, "LOCAL", None)
    assert await me.flush_v3_state() == 0


async def test_an_ipv4_mapped_source_is_its_ipv4_host(v3_receiver, monkeypatch):
    host_id = await _host(monkeypatch, "v3-inf8", "192.0.2.178")
    monkeypatch.setattr(ls, "_inventory_loaded_at", float("inf"))
    protocol = me._TrapSyslogProtocol("trap")
    protocol.datagram_received(message(pdu=module_failed()), ("::ffff:192.0.2.178", 50162, 0, 0))
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert len(await _stored("192.0.2.178")) == 1
    assert list(await _open(host_id)) == [f"trap:module:{host_id}:entPhysicalIndex 1001"]
