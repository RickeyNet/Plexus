"""Hardware module health in the monitoring poll (netcontrol/module_health.py).

The pure parser, classification and alert logic are fed invented SNMP rows;
the wiring tests run ``_evaluate_alerts_for_poll`` (and one whole poll with
a fake SNMP agent) against the test database. No device, SDK or network.
"""

from __future__ import annotations

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import module_health as mh

CISCO_STATE = mh.CEFC_MODULE_OPER_STATUS
JNX_STATE = mh.JNX_FRU_STATE
# sysUpTime: a walk the poll makes before it asks for the module table.
SYS_UPTIME = "1.3.6.1.2.1.1.3"


def _cisco_rows(states: dict[int, int]) -> dict[str, int]:
    return {f"{CISCO_STATE}.{index}": state for index, state in states.items()}


def _cisco_details(index: int, name: str = "", model: str = "", admin: int = 1, descr: str = "") -> dict:
    return {
        f"{mh.ENT_PHYSICAL_NAME}.{index}": name,
        f"{mh.ENT_PHYSICAL_DESCR}.{index}": descr,
        f"{mh.ENT_PHYSICAL_MODEL}.{index}": model,
        f"{mh.CEFC_MODULE_ADMIN_STATUS}.{index}": admin,
    }


class _Agent:
    """Answers the module read's walk and GETs from invented rows, and
    records each request."""

    def __init__(self, rows: dict, answers: dict | None = None, *, silent_gets: bool = False):
        self.rows = rows
        self.answers = answers or {}
        self.silent_gets = silent_gets
        self.walks: list[str] = []
        self.gets: list[tuple[str, ...]] = []

    async def walk(self, oid: str) -> dict:
        self.walks.append(oid)
        return {k: v for k, v in self.rows.items() if k.startswith(oid + ".")}

    async def get(self, oids: tuple[str, ...]) -> dict:
        self.gets.append(oids)
        if self.silent_gets:
            return {}
        return {oid: self.answers.get(oid, "No Such Instance currently exists at this OID") for oid in oids}


# ── Device types ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("device_type", ["cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr", "CISCO_XE"])
def test_cisco_types_read_the_fru_control_mib(device_type):
    assert mh.source_for_device(device_type) is mh.CISCO


@pytest.mark.parametrize("device_type", ["juniper", "juniper_junos"])
def test_juniper_types_read_the_fru_table(device_type):
    assert mh.source_for_device(device_type) is mh.JUNIPER


@pytest.mark.parametrize("device_type", ["arista_eos", "aruba_aoscx", "cisco_asa", "apc_ups", "icmp_only", "", None])
def test_other_types_are_not_read(device_type):
    assert mh.source_for_device(device_type) is None


# ── Classification ───────────────────────────────────────────────────────────

CISCO_EXPECTED = {
    1: mh.TRANSITIONAL,  # unknown
    2: mh.OK,  # ok
    3: mh.ADMIN_DOWN,  # disabled
    4: mh.OK,  # okButDiagFailed
    5: mh.TRANSITIONAL,  # boot
    6: mh.TRANSITIONAL,  # selfTest
    7: mh.DOWN,  # failed
    8: mh.DOWN,  # missing
    9: mh.DOWN,  # mismatchWithParent
    10: mh.DOWN,  # mismatchConfig
    11: mh.DOWN,  # diagFailed
    12: mh.TRANSITIONAL,  # dormant
    13: mh.ADMIN_DOWN,  # outOfServiceAdmin
    14: mh.DOWN,  # outOfServiceEnvTemp
    15: mh.DOWN,  # poweredDown
    16: mh.TRANSITIONAL,  # poweredUp
    17: mh.DOWN,  # powerDenied
    18: mh.TRANSITIONAL,  # powerCycled
    19: mh.OK,  # okButPowerOverWarning
    20: mh.OK,  # okButPowerOverCritical
    21: mh.TRANSITIONAL,  # syncInProgress
    22: mh.TRANSITIONAL,  # upgrading
    23: mh.OK,  # okButAuthFailed
    24: mh.TRANSITIONAL,  # mdr
    25: mh.DOWN,  # fwMismatchFound
    26: mh.TRANSITIONAL,  # fwDownloadSuccess
    27: mh.DOWN,  # fwDownloadFailure
}


def test_every_cisco_module_oper_state_is_classified():
    assert set(mh.CISCO_OPER_STATES) == set(range(1, 28))
    for oper, expected in CISCO_EXPECTED.items():
        status = mh.parse_module_status(mh.CISCO, _cisco_rows({10: oper}), _cisco_details(10, "Slot 1"))
        assert status["modules"][0]["class"] == expected, oper


JUNIPER_EXPECTED = {
    1: mh.TRANSITIONAL,  # unknown
    3: mh.TRANSITIONAL,  # present
    4: mh.TRANSITIONAL,  # ready
    5: mh.TRANSITIONAL,  # announceOnline
    6: mh.OK,  # online
    7: mh.TRANSITIONAL,  # anounceOffline
    8: mh.DOWN,  # offline
    9: mh.TRANSITIONAL,  # diagnostic
    10: mh.OK,  # standby
}


def test_every_juniper_fru_state_is_classified():
    assert set(mh.JUNIPER_FRU_STATES) | {mh.JUNIPER_FRU_EMPTY} == set(range(1, 11))
    for oper, expected in JUNIPER_EXPECTED.items():
        rows = {f"{JNX_STATE}.7.1.0.0": oper}
        values = {f"{mh.JNX_FRU_TYPE}.7.1.0.0": 3, f"{mh.JNX_FRU_OFFLINE_REASON}.7.1.0.0": 3}
        status = mh.parse_module_status(mh.JUNIPER, rows, values)
        assert status["modules"][0]["class"] == expected, oper


def test_a_state_the_mib_does_not_list_neither_raises_nor_clears():
    status = mh.parse_module_status(mh.CISCO, _cisco_rows({10: 99}), {})
    assert status["modules"][0]["class"] == mh.TRANSITIONAL
    assert mh.module_alert_checks(1, status) == []
    assert mh.module_cleared_keys(1, status, [mh.alert_dedup_key(1, "10")]) == []


def test_a_cisco_module_powered_down_by_an_operator_is_not_down():
    for admin in (2, 4):  # disabled, outOfServiceAdmin
        status = mh.parse_module_status(mh.CISCO, _cisco_rows({10: 15}), _cisco_details(10, "Slot 1", admin=admin))
        assert status["modules"][0]["class"] == mh.ADMIN_DOWN
    status = mh.parse_module_status(mh.CISCO, _cisco_rows({10: 15}), _cisco_details(10, "Slot 1", admin=1))
    assert status["modules"][0]["class"] == mh.DOWN


def test_a_juniper_fru_taken_offline_by_an_operator_is_not_down():
    rows = {f"{JNX_STATE}.7.2.0.0": 8}
    for reason, expected in ((5, mh.ADMIN_DOWN), (7, mh.ADMIN_DOWN), (34, mh.ADMIN_DOWN), (3, mh.DOWN), (4, mh.DOWN)):
        values = {f"{mh.JNX_FRU_TYPE}.7.2.0.0": 3, f"{mh.JNX_FRU_OFFLINE_REASON}.7.2.0.0": reason}
        assert mh.parse_module_status(mh.JUNIPER, rows, values)["modules"][0]["class"] == expected, reason


# ── Parser ───────────────────────────────────────────────────────────────────


def test_the_cisco_table_is_parsed():
    rows = _cisco_rows({1000: 2, 3000: 7, 22: 2})
    values = _cisco_details(3000, "Slot 3", "LC-48X-EXAMPLE")
    status = mh.parse_module_status(mh.CISCO, rows, values)
    assert status["source"] == "cisco_entity_fru" and status["down_count"] == 1
    assert [m["index"] for m in status["modules"]] == ["22", "1000", "3000"]  # MIB order
    down = status["modules"][2]
    assert (down["name"], down["model"], down["status"], down["state"]) == ("Slot 3", "LC-48X-EXAMPLE", "failed", 7)


def test_a_module_without_a_name_is_named_by_its_descr_then_its_index():
    rows = _cisco_rows({5: 7, 6: 7})
    values = {**_cisco_details(5, "", descr="Line card example"), **_cisco_details(6)}
    names = [m["name"] for m in mh.parse_module_status(mh.CISCO, rows, values)["modules"]]
    assert names == ["Line card example", "Module 6"]


def test_juniper_empty_slots_and_non_module_frus_are_left_out():
    rows = {
        f"{JNX_STATE}.7.1.0.0": 6,  # FPC 0 online
        f"{JNX_STATE}.7.2.0.0": 2,  # FPC 1 slot empty
        f"{JNX_STATE}.2.1.0.0": 8,  # a power supply offline
        f"{JNX_STATE}.9.1.0.0": 10,  # RE 1 standby
    }
    values = {
        f"{mh.JNX_FRU_TYPE}.7.1.0.0": 3,
        f"{mh.JNX_FRU_TYPE}.2.1.0.0": 7,  # powerEntryModule
        f"{mh.JNX_FRU_TYPE}.9.1.0.0": 6,  # routingEngine
    }
    status = mh.parse_module_status(mh.JUNIPER, rows, values)
    assert [(m["index"], m["class"]) for m in status["modules"]] == [("7.1.0.0", mh.OK), ("9.1.0.0", mh.OK)]
    assert status["down_count"] == 0


def test_no_rows_is_no_state():
    assert mh.parse_module_status(mh.CISCO, {}, {}) == {}
    # Rows of another table are not this table.
    assert mh.parse_module_status(mh.CISCO, {"1.3.6.1.2.1.2.2.1.8.1": 1}, {}) == {}


def test_a_table_of_empty_slots_is_read_and_has_no_modules():
    status = mh.parse_module_status(mh.JUNIPER, {f"{JNX_STATE}.7.1.0.0": 2}, {})
    assert status["modules"] == [] and status["source"] == "juniper_fru"


# ── Reading (bounded) ────────────────────────────────────────────────────────


async def test_a_healthy_cisco_chassis_costs_one_walk_and_no_get():
    agent = _Agent(_cisco_rows({i: 2 for i in range(1, 40)}))
    status = await mh.read_module_status(mh.CISCO, agent.get, agent.walk)
    assert agent.walks == [CISCO_STATE] and agent.gets == []
    assert len(status["modules"]) == 39 and status["down_count"] == 0


async def test_names_are_read_only_for_the_modules_down():
    agent = _Agent(
        _cisco_rows({1: 2, 2: 7, 3: 2, 4: 8}),
        {**_cisco_details(2, "Slot 2", "LC-EXAMPLE-A"), **_cisco_details(4, "Slot 4")},
    )
    status = await mh.read_module_status(mh.CISCO, agent.get, agent.walk)
    asked = {oid.rsplit(".", 1)[1] for oids in agent.gets for oid in oids}
    assert asked == {"2", "4"} and len(agent.gets) == 1
    assert [(m["name"], m["status"]) for m in status["modules"] if m["class"] == mh.DOWN] == [
        ("Slot 2", "failed"),
        ("Slot 4", "missing"),
    ]


async def test_gets_are_chunked():
    down = {i: 7 for i in range(1, 11)}  # 10 modules x 4 objects = 40 instances
    agent = _Agent(_cisco_rows(down))
    await mh.read_module_status(mh.CISCO, agent.get, agent.walk)
    assert [len(oids) for oids in agent.gets] == [mh.OIDS_PER_GET, mh.OIDS_PER_GET]


async def test_an_unanswered_name_get_keeps_the_module_unnamed():
    agent = _Agent(_cisco_rows({3: 7}), silent_gets=True)
    status = await mh.read_module_status(mh.CISCO, agent.get, agent.walk)
    assert status["modules"][0]["name"] == "Module 3" and status["down_count"] == 1


async def test_no_walk_answer_is_no_state():
    agent = _Agent({})
    assert await mh.read_module_status(mh.CISCO, agent.get, agent.walk) == {}
    assert agent.gets == []


async def test_juniper_reads_types_then_names_of_the_down_modules():
    rows = {f"{JNX_STATE}.7.1.0.0": 6, f"{JNX_STATE}.7.2.0.0": 8, f"{JNX_STATE}.7.3.0.0": 2}
    answers = {
        f"{mh.JNX_FRU_TYPE}.7.1.0.0": 3,
        f"{mh.JNX_FRU_TYPE}.7.2.0.0": 3,
        f"{mh.JNX_FRU_NAME}.7.2.0.0": "FPC @ 1/*/*",
        f"{mh.JNX_FRU_OFFLINE_REASON}.7.2.0.0": 3,
    }
    agent = _Agent(rows, answers)
    status = await mh.read_module_status(mh.JUNIPER, agent.get, agent.walk)
    assert agent.gets[0] == (f"{mh.JNX_FRU_TYPE}.7.1.0.0", f"{mh.JNX_FRU_TYPE}.7.2.0.0")  # not the empty slot
    assert agent.gets[1] == (f"{mh.JNX_FRU_NAME}.7.2.0.0", f"{mh.JNX_FRU_OFFLINE_REASON}.7.2.0.0")
    assert [(m["name"], m["status"], m["class"]) for m in status["modules"]] == [
        ("Module 7.1.0.0", "online", mh.OK),
        ("FPC @ 1/*/*", "offline", mh.DOWN),
    ]


async def test_juniper_with_no_type_answer_is_no_state():
    """Without the FRU types the poll cannot tell modules from fans: it read
    nothing, rather than a table every module left."""
    agent = _Agent({f"{JNX_STATE}.7.1.0.0": 8}, silent_gets=True)
    assert await mh.read_module_status(mh.JUNIPER, agent.get, agent.walk) == {}


# ── Alert checks and clearing ────────────────────────────────────────────────


def _status(**classes: str) -> dict:
    """A parsed state with one module per ``index=class``."""
    label = {mh.OK: ("ok", 2), mh.DOWN: ("failed", 7), mh.TRANSITIONAL: ("booting", 5), mh.ADMIN_DOWN: ("disabled", 3)}
    modules = [
        {
            "index": i.lstrip("m"),
            "name": f"Slot {i.lstrip('m')}",
            "model": "LC-EXAMPLE" if k == mh.DOWN else "",
            "status": label[k][0],
            "state": label[k][1],
            "class": k,
        }
        for i, k in classes.items()
    ]
    return {
        "source": "cisco_entity_fru",
        "vendor": "Cisco",
        "modules": modules,
        "down_count": sum(1 for m in modules if m["class"] == mh.DOWN),
    }


def test_one_check_per_module_down():
    checks = mh.module_alert_checks(5, _status(m1=mh.OK, m2=mh.DOWN, m3=mh.DOWN, m4=mh.TRANSITIONAL, m6=mh.ADMIN_DOWN))
    assert [c["message"] for c in checks] == ["Slot 2 (LC-EXAMPLE) is failed", "Slot 3 (LC-EXAMPLE) is failed"]
    assert {c["dedup_key"] for c in checks} == {"5:module_down:2", "5:module_down:3"}
    assert all((c["metric"], c["alert_type"], c["severity"]) == ("module_down", "status", "critical") for c in checks)


def test_no_state_raises_and_clears_nothing():
    open_keys = [mh.alert_dedup_key(5, "2")]
    assert mh.module_alert_checks(5, {}) == []
    assert mh.module_cleared_keys(5, {}, open_keys) == []
    assert mh.module_down_count({}) is None and mh.module_down_count(None) is None


def test_clearing():
    others = ["5:module_down:rule:3", "5:module_down:status", "5:cpu:x"]
    open_keys = [mh.alert_dedup_key(5, i) for i in ("1", "2", "4", "6", "9", "7.1.0.0")] + others
    status = _status(m1=mh.OK, m2=mh.DOWN, m4=mh.TRANSITIONAL, m6=mh.ADMIN_DOWN)
    # ok clears, down and transitional keep, admin-down clears, a module no
    # longer in the table (9, 7.1.0.0) clears; keys of other alerts (a user
    # rule on the same metric) are not touched.
    assert mh.module_cleared_keys(5, status, open_keys) == [
        "5:module_down:1",
        "5:module_down:6",
        "5:module_down:9",
        "5:module_down:7.1.0.0",
    ]


def test_clearing_ignores_another_hosts_keys():
    assert mh.module_cleared_keys(5, _status(m1=mh.OK), ["15:module_down:1"]) == []


# ── Wiring: the poll's alert evaluation ──────────────────────────────────────


async def _host() -> tuple[int, int]:
    await db.init_db()
    group_id = await db.create_group("module-test")
    host_id = await db.add_host(group_id, "chassis-a", "192.0.2.80", "cisco_xe")
    return group_id, host_id


def _res(host_id: int, module_health: dict | None) -> dict:
    res = {
        "host_id": host_id,
        "cpu_percent": None,
        "memory_percent": None,
        "if_down_count": 0,
        "if_details": [],
        "vpn_tunnels_down": 0,
        "vpn_details": [],
    }
    if module_health is not None:
        res["module_health"] = module_health
    return res


async def _evaluate(host_id: int, group_id: int, status: dict | None, rules: list | None = None, **kw) -> int:
    from netcontrol.routes.monitoring import _evaluate_alerts_for_poll

    poll_id = await db.create_monitoring_poll(host_id)
    return await _evaluate_alerts_for_poll(_res(host_id, status), poll_id, group_id, rules or [], **kw)


async def _open(host_id: int) -> list[tuple[str, str]]:
    return sorted((a["dedup_key"], a["message"]) for a in await db.get_monitoring_alerts(host_id, acknowledged=False))


async def test_the_poll_raises_and_resolves_per_module():
    group_id, host_id = await _host()

    # A line card fails: one critical alert.
    assert await _evaluate(host_id, group_id, _status(m1=mh.OK, m2=mh.DOWN)) == 1
    alerts = await db.get_monitoring_alerts(host_id, acknowledged=False)
    assert [(a["metric"], a["alert_type"], a["severity"], a["message"]) for a in alerts] == [
        ("module_down", "status", "critical", "Slot 2 (LC-EXAMPLE) is failed")
    ]

    # Still failed: the same alert, bumped. A second module fails: a new alert.
    await _evaluate(host_id, group_id, _status(m1=mh.OK, m2=mh.DOWN, m3=mh.DOWN))
    assert [k for k, _m in await _open(host_id)] == [f"{host_id}:module_down:2", f"{host_id}:module_down:3"]
    alerts = {a["dedup_key"]: a for a in await db.get_monitoring_alerts(host_id, acknowledged=False)}
    assert alerts[f"{host_id}:module_down:2"]["occurrence_count"] == 2

    # Module 2 reboots (transitional): its alert stays. A poll that read no
    # module table changes nothing.
    await _evaluate(host_id, group_id, _status(m1=mh.OK, m2=mh.TRANSITIONAL, m3=mh.DOWN))
    await _evaluate(host_id, group_id, None)
    await _evaluate(host_id, group_id, {})
    assert len(await _open(host_id)) == 2

    # Module 2 is OK again and module 3 left the table: both resolve.
    await _evaluate(host_id, group_id, _status(m1=mh.OK, m2=mh.OK))
    assert await _open(host_id) == []
    resolved = await db.get_monitoring_alerts(host_id, acknowledged=True)
    assert {a["acknowledged_by"] for a in resolved} == {"auto-resolved"} and len(resolved) == 2


async def test_a_module_suppression_is_honoured():
    group_id, host_id = await _host()
    await db.create_alert_suppression(
        name="line card swap", ends_at="2099-01-01T00:00:00", host_id=host_id, metric="module_down"
    )
    assert await _evaluate(host_id, group_id, _status(m2=mh.DOWN)) == 0
    assert await _open(host_id) == []
    # Preloaded suppressions (the poll loop's path) too.
    rows = await db.get_active_alert_suppressions()
    assert await _evaluate(host_id, group_id, _status(m2=mh.DOWN), suppressions=rows) == 0


async def test_a_user_rule_can_use_the_module_down_count():
    from netcontrol.routes.monitoring import _metric_value_from_poll

    group_id, host_id = await _host()
    assert _metric_value_from_poll(_res(host_id, _status(m1=mh.DOWN, m2=mh.DOWN)), "module_down") == 2.0
    assert _metric_value_from_poll(_res(host_id, None), "module_down") is None
    rule_id = await db.create_alert_rule("two cards", "module_down", operator=">=", value=2.0)
    rule = {"id": rule_id, "name": "two cards", "metric": "module_down", "operator": ">=", "value": 2.0}
    # One built-in alert per module plus the rule's.
    assert await _evaluate(host_id, group_id, _status(m1=mh.DOWN, m2=mh.DOWN), [rule]) == 3
    # The modules recover: their alerts resolve, the rule's alert is the
    # rule's own and is not cleared by the module logic.
    await _evaluate(host_id, group_id, _status(m1=mh.OK, m2=mh.OK), [rule])
    assert [k for k, _m in await _open(host_id)] == [f"{host_id}:module_down:rule:{rule_id}"]


async def test_the_count_is_a_metric_sample():
    from netcontrol.routes.metrics_engine import emit_metric_samples_from_poll

    _group_id, host_id = await _host()
    await emit_metric_samples_from_poll(_res(host_id, _status(m1=mh.DOWN, m2=mh.OK)))
    await emit_metric_samples_from_poll(_res(host_id, None))  # not read: no sample
    samples = await db.query_metric_samples("module_down", [host_id])
    assert [s["value"] for s in samples] == [1.0]


# ── Wiring: a whole poll ─────────────────────────────────────────────────────


async def test_the_poll_reads_the_module_table(monkeypatch):
    import netcontrol.routes.monitoring as monitoring

    group_id, host_id = await _host()
    rows = {**_cisco_rows({1000: 2, 3000: 7}), f"{SYS_UPTIME}.0": 4200}
    answers = _cisco_details(3000, "Slot 3", "LC-48X-EXAMPLE")

    async def _walk(_ip, _timeout, _cfg, oid, *_args, return_errors=False, engine=None, **_kwargs):
        found = {k: v for k, v in rows.items() if k.startswith(oid + ".")}
        return (found, None) if return_errors else found

    async def _get(_ip, _timeout, _cfg, oids, *, engine=None):
        return {oid: answers.get(oid, "") for oid in oids}, None

    monkeypatch.setattr(monitoring, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(monitoring, "_snmp_walk", _walk)
    monkeypatch.setattr(monitoring, "_snmp_get_values", _get)
    monkeypatch.setitem(state.MONITORING_CONFIG, "icmp_enabled", False)

    host = {**(await db.get_host(host_id)), "group_id": group_id}
    result = await monitoring._poll_host_monitoring(host, None, {"enabled": True})
    assert result["module_health"]["down_count"] == 1
    await monitoring._process_poll_result(host, result, [])
    assert [m for _k, m in await _open(host_id)] == ["Slot 3 (LC-48X-EXAMPLE) is failed"]


async def test_a_walk_cut_short_reads_no_table(monkeypatch):
    import netcontrol.routes.monitoring as monitoring
    from netcontrol.routes.snmp import SNMP_TIMEOUT_ERROR

    group_id, host_id = await _host()

    async def _walk(_ip, _timeout, _cfg, oid, *_args, return_errors=False, engine=None, **_kwargs):
        found = {f"{oid}.1000": 2} if oid in (CISCO_STATE, SYS_UPTIME) else {}
        return (found, SNMP_TIMEOUT_ERROR) if return_errors else found

    monkeypatch.setattr(monitoring, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(monitoring, "_snmp_walk", _walk)
    monkeypatch.setitem(state.MONITORING_CONFIG, "icmp_enabled", False)

    host = {**(await db.get_host(host_id)), "group_id": group_id}
    result = await monitoring._poll_host_monitoring(host, None, {"enabled": True})
    assert result["module_health"] == {}


async def test_a_device_that_answered_nothing_is_not_asked_for_modules(monkeypatch):
    import netcontrol.routes.monitoring as monitoring

    await db.init_db()
    walked: list[str] = []

    async def _walk(_ip, _timeout, _cfg, oid, *_args, return_errors=False, engine=None, **_kwargs):
        walked.append(oid)
        return ({}, None) if return_errors else {}

    monkeypatch.setattr(monitoring, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(monitoring, "_snmp_walk", _walk)
    monkeypatch.setitem(state.MONITORING_CONFIG, "icmp_enabled", False)

    host = {"id": 1, "hostname": "sw-a", "ip_address": "192.0.2.82", "device_type": "cisco_xe"}
    result = await monitoring._poll_host_monitoring(host, None, {"enabled": True})
    assert "module_health" not in result
    assert CISCO_STATE not in walked


async def test_a_device_type_not_read_sends_no_module_request(monkeypatch):
    import netcontrol.routes.monitoring as monitoring

    await db.init_db()
    walked: list[str] = []

    async def _walk(_ip, _timeout, _cfg, oid, *_args, return_errors=False, engine=None, **_kwargs):
        walked.append(oid)
        return ({}, None) if return_errors else {}

    monkeypatch.setattr(monitoring, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(monitoring, "_snmp_walk", _walk)
    monkeypatch.setitem(state.MONITORING_CONFIG, "icmp_enabled", False)

    host = {"id": 1, "hostname": "fw-a", "ip_address": "192.0.2.81", "device_type": "fortinet"}
    result = await monitoring._poll_host_monitoring(host, None, {"enabled": True})
    assert "module_health" not in result
    assert not any(oid.startswith((CISCO_STATE, JNX_STATE)) for oid in walked)
