"""Power over Ethernet state in the monitoring poll
(netcontrol/poe_health.py on netcontrol/snmp_health.py).

Invented POWER-ETHERNET-MIB rows; the wiring test runs the poll and
``_evaluate_alerts_for_poll`` against the test database. No device, SDK or
network.
"""

from __future__ import annotations

import routes.database as db
from netcontrol import health_checks as hc, poe_health as poe, snmp_health as sh

from snmp_health_fakes import SYS_UPTIME, Agent, add_host, evaluate, open_alerts, poll

DETECTION = poe.PSE_PORT_DETECTION_STATUS
OPER = poe.MAIN_PSE_OPER_STATUS


def _classes(status: dict) -> dict[str, str]:
    return {i["index"]: i["class"] for i in status["items"]}


def test_port_detection_states_and_admin_disabled():
    rows = {f"{DETECTION}.1.{s}": s for s in range(1, 7)}
    rows[f"{DETECTION}.2.9"] = 4  # a faulty port whose PoE an operator turned off
    values = {f"{poe.PSE_PORT_ADMIN_ENABLE}.2.9": 2}
    status = sh.select(poe.PORT, sh.parse_table(poe.POE_PORTS, rows, values))
    assert _classes(status) == {
        "1.1": sh.ADMIN_DOWN,
        "1.2": sh.OK,
        "1.3": sh.OK,
        "1.4": sh.DOWN,
        "1.5": sh.TRANSITIONAL,
        "1.6": sh.DOWN,
        "2.9": sh.ADMIN_DOWN,
    }
    checks = sh.alert_checks(poe.PORT, 3, status)
    assert [(c["dedup_key"], c["message"], c["severity"]) for c in checks] == [
        ("3:poe_port_fault:1.4", "PoE port 4 (unit 1) is faulty", "warning"),
        ("3:poe_port_fault:1.6", "PoE port 6 (unit 1) is faulty (error condition)", "warning"),
    ]


def test_usage_threshold_and_budget_item():
    assert poe.usage_threshold(80) == 80
    assert poe.usage_threshold(None) == poe.DEFAULT_USAGE_THRESHOLD
    assert poe.usage_threshold(0) == poe.DEFAULT_USAGE_THRESHOLD
    assert poe.usage_threshold("No Such Instance currently exists at this OID") == poe.DEFAULT_USAGE_THRESHOLD
    item = poe.budget_item("1", 400, 372, 90)
    assert item is not None and item["class"] == sh.DOWN and item["state"] == 93
    assert item["status"] == "using 372 W of 400 W (93%, threshold 90%)"
    assert poe.budget_item("1", 400, 100, None)["class"] == sh.OK
    assert poe.budget_item("1", 0, 10, 90) is None
    assert poe.budget_item("1", 400, None, 90) is None


async def test_main_pse_supplies_and_budgets():
    rows = {f"{OPER}.1": 1, f"{OPER}.2": 3, f"{OPER}.3": 2, f"{OPER}.4": 7}
    answers = {
        f"{poe.MAIN_PSE_POWER}.1": 740,
        f"{poe.MAIN_PSE_CONSUMPTION}.1": 700,
        f"{poe.MAIN_PSE_USAGE_THRESHOLD}.1": 95,
    }
    agent = Agent(rows, answers)
    table = await poe.MAIN_PSE.read(agent.get, agent.walk, 1)
    # The power figures are asked only for the source that is on.
    assert agent.asked() == {
        f"{oid}.1" for oid in (poe.MAIN_PSE_POWER, poe.MAIN_PSE_CONSUMPTION, poe.MAIN_PSE_USAGE_THRESHOLD)
    }
    supplies = sh.select(poe.SUPPLY, table)
    assert _classes(supplies) == {"1": sh.OK, "2": sh.DOWN, "3": sh.ADMIN_DOWN, "4": sh.TRANSITIONAL}
    assert [c["message"] for c in sh.alert_checks(poe.SUPPLY, 5, supplies)] == ["PoE power source 2 is faulty"]
    budget = sh.select(poe.BUDGET, table)
    checks = sh.alert_checks(poe.BUDGET, 5, budget)
    assert [(c["dedup_key"], c["value"], c["alert_type"]) for c in checks] == [
        ("5:poe_budget_high:1", 95.0, "threshold")
    ]
    assert checks[0]["message"] == "PoE power source 1 is using 700 W of 740 W (95%, threshold 95%)"


async def test_main_pse_not_read_or_empty():
    assert sh.is_empty(await poe.MAIN_PSE.read(Agent({}).get, Agent({}).walk, 1))
    cut = Agent({}, cut={OPER})
    assert await poe.MAIN_PSE.read(cut.get, cut.walk, 1) is None
    # The power GET unanswered: nothing read (the budget items would clear).
    silent = Agent({f"{OPER}.1": 1}, silent_gets=True)
    assert await poe.MAIN_PSE.read(silent.get, silent.walk, 1) is None
    # Only faulty sources: no GET at all.
    agent = Agent({f"{OPER}.1": 3, f"{OPER}.2": "No Such Instance currently exists at this OID"})
    table = await poe.MAIN_PSE.read(agent.get, agent.walk, 1)
    assert agent.gets == [] and [i["index"] for i in table["items"]] == ["1"]


async def test_the_poll_raises_and_resolves_poe_alerts(monkeypatch):
    group_id, host_id = await add_host("cisco_xe")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    rows = {f"{SYS_UPTIME}.0": 4200, f"{DETECTION}.1.3": 3, f"{DETECTION}.1.7": 4, f"{OPER}.1": 1}
    answers = {f"{poe.MAIN_PSE_POWER}.1": 370, f"{poe.MAIN_PSE_CONSUMPTION}.1": 350}
    agent = Agent(rows, answers)
    result = await poll(monkeypatch, host, agent)
    assert result["poe_port_health"]["down_count"] == 1
    assert result["poe_budget_health"]["down_count"] == 1  # 95% of the budget, default threshold 90%
    assert await evaluate(host_id, group_id, result) == 2
    assert set(await open_alerts(host_id)) == {f"{host_id}:poe_port_fault:1.7", f"{host_id}:poe_budget_high:1"}
    assert {(c.metric, c.result_key) for c in poe.CHECKS} <= {(c.metric, c.result_key) for c in hc.CHECKS}

    # The port is delivering power again and the load dropped: both resolve.
    agent.rows[f"{DETECTION}.1.7"] = 3
    agent.answers[f"{poe.MAIN_PSE_CONSUMPTION}.1"] = 120
    await evaluate(host_id, group_id, await poll(monkeypatch, host, agent))
    assert await open_alerts(host_id) == {}
