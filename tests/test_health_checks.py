"""Which SNMP health checks the poll runs per device type, the fallback and
empty-table memory of their reads, and their metric values
(netcontrol/health_checks.py). Invented rows only."""

from __future__ import annotations

import pytest
from netcontrol import (
    environment_health as env,
    health_checks as hc,
    module_health as mh,
    routing_health as rh,
    snmp_health as sh,
)

from snmp_health_fakes import Agent

ALL_KEYS = {c.result_key for c in hc.CHECKS}


@pytest.mark.parametrize(
    ("device_type", "keys"),
    [
        ("cisco_xe", ALL_KEYS),
        ("CISCO_IOS", ALL_KEYS),
        ("cisco_asa", ALL_KEYS - {"module_health"}),
        ("juniper_junos", ALL_KEYS - {"temperature_health"}),
        ("arista_eos", ALL_KEYS - {"module_health"}),
        ("paloalto_panos", ALL_KEYS - {"module_health"}),
        ("fortinet", ALL_KEYS - {"module_health"}),
        ("aruba_osswitch", ALL_KEYS - {"module_health"}),
        ("aruba_aoscx", {"power_supply_health", "fan_health", "bgp_health", "ospf_health"}),
        ("netgear_prosafe", ALL_KEYS - {"module_health"}),
        ("aruba_instant_on", {"bgp_health", "ospf_health"}),
        ("", {"bgp_health", "ospf_health"}),
        (None, {"bgp_health", "ospf_health"}),
        ("apc_ups", set()),
    ],
)
async def test_the_checks_of_each_device_type(device_type, keys):
    agent = Agent({})
    assert set(await hc.read_health(1, device_type, agent.get, agent.walk_table)) == keys


def test_the_module_chain_is_module_healths():
    for device_type, source in mh.DEVICE_SOURCES.items():
        assert hc.plan_for_device(device_type)[0].sources == (source,)


async def test_the_first_table_with_rows_is_read():
    agent = Agent({f"{env.CEFC_FAN_TRAY_OPER}.5": 3})
    chain = hc.Chain(frozenset({env.KIND_FAN}), (env.CISCO_ENVMON_FAN, env.CISCO_FAN_TRAY))
    table = await hc._read_chain(chain, 1, agent.get, agent.walk_table)
    assert table["source"] == "cisco_entity_fru_fan"
    assert agent.walks == [env.ENVMON_FAN_STATE, env.CEFC_FAN_TRAY_OPER]


async def test_a_cut_walk_or_an_unanswered_kind_get_does_not_fall_back():
    chain = hc.Chain(frozenset({env.KIND_POWER}), (env.CISCO_ENVMON_SUPPLY, env.CISCO_FRU_POWER))
    agent = Agent({f"{env.CEFC_FRU_POWER_OPER}.5": 8}, cut={env.ENVMON_SUPPLY_STATE})
    assert await hc._read_chain(chain, 1, agent.get, agent.walk_table) is None
    assert agent.walks == [env.ENVMON_SUPPLY_STATE]
    # The FRU table answered, but not the GET that tells supplies from cards.
    chain = hc.Chain(frozenset({env.KIND_POWER}), (env.CISCO_FRU_POWER, env.CISCO_ENVMON_SUPPLY))
    agent = Agent({f"{env.CEFC_FRU_POWER_OPER}.5": 8, f"{env.ENVMON_SUPPLY_STATE}.1": 3}, silent_gets=True)
    assert await hc._read_chain(chain, 1, agent.get, agent.walk_table) is None
    assert agent.walks == [env.CEFC_FRU_POWER_OPER]


async def test_an_empty_chain_is_confirmed_at_the_third_empty_poll_and_a_cut_walk_does_not_count():
    chain = hc.Chain(frozenset({env.KIND_POWER}), (env.CISCO_ENVMON_SUPPLY, env.CISCO_FRU_POWER))
    agent = Agent({})
    assert await hc._read_chain(chain, 1, agent.get, agent.walk_table) is None
    agent.cut = {env.CEFC_FRU_POWER_OPER}
    assert await hc._read_chain(chain, 1, agent.get, agent.walk_table) is None  # cut: not counted
    agent.cut = set()
    assert await hc._read_chain(chain, 1, agent.get, agent.walk_table) is None  # 2 empty for the FRU table
    table = await hc._read_chain(chain, 1, agent.get, agent.walk_table)
    assert sh.is_empty(table)
    status = sh.select(env.POWER, table)
    assert sh.down_count(status) is None
    assert sh.cleared_keys(env.POWER, 1, status, ["1:power_supply_down:4", "1:power_supply_down:rule:2"]) == [
        "1:power_supply_down:4"
    ]


async def test_a_column_never_answered_is_skipped_after_its_third_empty_walk(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(hc.time, "monotonic", lambda: clock[0])
    chain = hc.Chain(frozenset({rh.KIND_BGP}), (rh.BGP4_PEERS,))
    agent = Agent({})
    for _ in range(3):
        await hc._read_chain(chain, 1, agent.get, agent.walk_table)
    assert agent.walks == [rh.BGP4_PEERS.state_oid] * 3
    # Skipped (and still "read, no items") for the window; another host is asked.
    assert sh.is_empty(await hc._read_chain(chain, 1, agent.get, agent.walk_table))
    await hc._read_chain(chain, 2, agent.get, agent.walk_table)
    assert len(agent.walks) == 4
    clock[0] += hc.EMPTY_TABLE_SECONDS + 1
    await hc._read_chain(chain, 1, agent.get, agent.walk_table)
    assert len(agent.walks) == 5
    hc.forget_all()
    assert hc._COLUMNS == {}


async def test_a_column_that_answered_rows_is_walked_at_every_poll():
    chain = hc.Chain(frozenset({rh.KIND_BGP}), (rh.BGP4_PEERS,))
    agent = Agent({f"{rh.BGP4_PEERS.state_oid}.192.0.2.1": 6})
    await hc._read_chain(chain, 1, agent.get, agent.walk_table)
    agent.rows = {}
    for _ in range(5):
        await hc._read_chain(chain, 1, agent.get, agent.walk_table)
    assert len(agent.walks) == 6


def test_metric_values_and_sample_rows():
    status = {"items": [], "down_count": 2}
    res = {"host_id": 4, "fan_health": status, "power_supply_health": {}}
    assert hc.metric_value(res, "fan_down") == 2.0
    assert hc.metric_value(res, "power_supply_down") is None
    assert hc.metric_value(res, "cpu") is None
    assert hc.metric_sample_rows(res) == [(4, "fan_down", "{}", 2.0)]
    assert set(hc.METRICS) == {
        "module_down",
        "power_supply_down",
        "fan_down",
        "temperature_alarm",
        "bgp_peer_down",
        "ospf_neighbor_down",
    }
    assert hc.metric_sample_rows({"host_id": 4, "fan_health": {"empty": True, "down_count": None}}) == []


def test_a_check_key_of_another_shape_is_not_cleared():
    status = sh.select(env.FAN, {"items": []})
    assert sh.cleared_keys(env.FAN, 5, status, ["5:fan_down:rule:2", "5:fan_down:", "5:fan_down:x", "6:fan_down:1"]) == []
    assert sh.down_count(None) is None and sh.select(env.FAN, {}) == {}
