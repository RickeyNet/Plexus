"""Power supply, fan, temperature and optics state in the monitoring poll
(netcontrol/environment_health.py on netcontrol/snmp_health.py).

Each vendor's table is fed invented rows shaped as its MIB defines them;
the wiring tests run the poll and ``_evaluate_alerts_for_poll`` against the
test database. No device, SDK or network.
"""

from __future__ import annotations

import pytest
import routes.database as db
from netcontrol import environment_health as env, health_checks, module_health as mh, snmp_health as sh

from snmp_health_fakes import SYS_UPTIME, Agent, add_host, evaluate, open_alerts, poll, res

ENT_NAME = sh.ENT_PHYSICAL_NAME
ENT_CLASS = sh.ENT_PHYSICAL_CLASS


def _parse(source: sh.TableSource, check: sh.HealthCheck, rows: dict, values: dict | None = None) -> dict:
    return sh.select(check, sh.parse_table(source, rows, values or {}))


def _classes(status: dict) -> dict[str, str]:
    return {i["index"]: i["class"] for i in status["items"]}


# ── Classification, per vendor table ─────────────────────────────────────────


def test_cisco_envmon_supply_and_fan_states():
    expected = {1: sh.OK, 2: sh.DOWN, 3: sh.DOWN, 4: sh.DOWN, 6: sh.DOWN}
    for source, check, oid in (
        (env.CISCO_ENVMON_SUPPLY, env.POWER, env.ENVMON_SUPPLY_STATE),
        (env.CISCO_ENVMON_FAN, env.FAN, env.ENVMON_FAN_STATE),
    ):
        rows = {f"{oid}.{state}": state for state in (1, 2, 3, 4, 5, 6)}
        status = _parse(source, check, rows)
        # notPresent(5) is an empty bay: not an item.
        assert _classes(status) == {str(k): v for k, v in expected.items()}


def test_cisco_envmon_temperature_states_and_severities():
    rows = {f"{env.ENVMON_TEMPERATURE_STATE}.{state}": state for state in (1, 2, 3, 4, 5, 6)}
    values = {f"{env.ENVMON_TEMPERATURE_DESCR}.3": "Inlet", f"{env.ENVMON_TEMPERATURE_VALUE}.3": 61}
    status = _parse(env.CISCO_ENVMON_TEMPERATURE, env.TEMPERATURE, rows, values)
    assert _classes(status) == {"1": sh.OK, "2": sh.DOWN, "3": sh.DOWN, "4": sh.DOWN, "6": sh.TRANSITIONAL}
    checks = sh.alert_checks(env.TEMPERATURE, 7, status)
    assert [(c["dedup_key"], c["severity"]) for c in checks] == [
        ("7:temperature_alarm:2", "warning"),
        ("7:temperature_alarm:3", "critical"),
        ("7:temperature_alarm:4", "critical"),
    ]
    assert checks[1]["message"] == "Inlet (61 C) is critical"


def test_every_cisco_fru_power_state_is_classified():
    assert set(env.CEFC_POWER_STATES) == set(range(1, 13))
    rows = {f"{env.CEFC_FRU_POWER_OPER}.{s}": s for s in range(1, 13)}
    values = {f"{ENT_CLASS}.{s}": 6 for s in range(1, 13)}
    classes = _classes(_parse(env.CISCO_FRU_POWER, env.POWER, rows, values))
    # on(2) is OK: its class is not read, so it is left out (clears the same).
    assert "2" not in classes and classes.pop("3") == sh.ADMIN_DOWN
    assert set(classes.values()) == {sh.DOWN}


def test_cisco_fru_power_keeps_power_supplies_only_and_honours_admin_off():
    rows = {
        f"{env.CEFC_FRU_POWER_OPER}.10": 2,  # a supply, on
        f"{env.CEFC_FRU_POWER_OPER}.20": 8,  # a supply, failed
        f"{env.CEFC_FRU_POWER_OPER}.30": 1,  # a line card powered off: not a supply
        f"{env.CEFC_FRU_POWER_OPER}.40": 5,  # a supply off, turned off by an operator
    }
    values = {
        f"{ENT_CLASS}.20": 6,
        f"{ENT_CLASS}.30": 9,
        f"{ENT_CLASS}.40": 6,
        f"{env.CEFC_FRU_POWER_ADMIN}.40": 2,
        f"{ENT_NAME}.20": "PS-2",
    }
    status = _parse(env.CISCO_FRU_POWER, env.POWER, rows, values)
    # The OK row's class is not read: it is left out, which clears the same.
    assert _classes(status) == {"20": sh.DOWN, "40": sh.ADMIN_DOWN}
    assert [c["message"] for c in sh.alert_checks(env.POWER, 1, status)] == ["PS-2 is failed"]
    assert sh.filter_instances(env.CISCO_FRU_POWER, rows) == [f"{ENT_CLASS}.{i}" for i in (20, 30, 40)]


def test_cisco_fan_tray_states():
    rows = {f"{env.CEFC_FAN_TRAY_OPER}.{s}": s for s in (1, 2, 3, 4)}
    assert _classes(_parse(env.CISCO_FAN_TRAY, env.FAN, rows)) == {
        "1": sh.TRANSITIONAL,
        "2": sh.OK,
        "3": sh.DOWN,
        "4": sh.DOWN,
    }


def test_entity_state_oper_power_and_fan():
    rows = {f"{env.ENT_STATE_OPER}.{i}": s for i, s in ((1, 3), (2, 2), (3, 2), (4, 2), (5, 4), (6, 1))}
    values = {
        f"{ENT_CLASS}.2": 6,  # supply disabled
        f"{ENT_CLASS}.3": 7,  # fan disabled
        f"{ENT_CLASS}.4": 10,  # a port disabled: neither
        f"{ENT_CLASS}.5": 7,
        f"{ENT_CLASS}.6": 6,
        f"{env.ENT_STATE_ADMIN}.3": 2,  # locked by an operator
    }
    table = sh.parse_table(env.ENTITY_STATE_POWER_FAN, rows, values)
    power, fan = sh.select(env.POWER, table), sh.select(env.FAN, table)
    assert _classes(power) == {"2": sh.DOWN, "6": sh.TRANSITIONAL}
    assert _classes(fan) == {"3": sh.ADMIN_DOWN, "5": sh.TRANSITIONAL}
    # The Arista variant takes no fans from it (aristaFanStateTable does).
    assert sh.select(env.FAN, sh.parse_table(env.ENTITY_STATE_POWER, rows, values))["items"] == []


@pytest.mark.parametrize(
    ("raw", "state"),
    [
        (b"", 1),
        (b"\x00", 1),
        (b"\x40", 1),  # underRepair only
        (b"\x20", 3),  # critical
        (b"\x10", 3),  # major
        (b"\x08", 2),  # minor
        (b"\x04", 2),  # warning
        (b"\x02", 0),  # indeterminate
        (b"\x80", 0),  # unknown
        (b"\x24", 3),  # critical and warning
        ("0x08", 2),
        ("0xzz", None),
        ("plain text", None),
        ("No Such Instance currently exists at this OID", None),
        (None, None),
    ],
)
def test_entity_alarm_bits(raw, state):
    assert env.alarm_state(raw) == state


def test_octets_of_a_pysnmp_value():
    class _Octets:
        def asOctets(self):  # noqa: N802 (pysnmp's name)
            return b"\x20"

    assert env.octets(_Octets()) == b"\x20" and env.alarm_state(_Octets()) == 3
    assert env.octets(bytearray(b"\x04")) == b"\x04"


def test_entity_state_temperature_keeps_celsius_sensors():
    rows = {f"{env.ENT_STATE_ALARM}.{i}": v for i, v in ((1, b""), (2, b"\x20"), (3, b"\x08"), (4, b"\x20"))}
    values = {
        f"{ENT_CLASS}.2": 8,
        f"{env.ENT_PHY_SENSOR_TYPE}.2": 8,
        f"{ENT_CLASS}.3": 8,
        f"{env.ENT_PHY_SENSOR_TYPE}.3": 8,
        f"{ENT_CLASS}.4": 8,
        f"{env.ENT_PHY_SENSOR_TYPE}.4": 4,  # a voltage sensor in alarm: not a temperature
        f"{ENT_NAME}.2": "Inlet sensor",
    }
    status = _parse(env.ENTITY_STATE_SENSORS, env.TEMPERATURE, rows, values)
    assert _classes(status) == {"2": sh.DOWN, "3": sh.DOWN}
    checks = sh.alert_checks(env.TEMPERATURE, 4, status)
    assert [(c["message"], c["severity"]) for c in checks] == [
        ("Inlet sensor is in a critical alarm", "critical"),
        ("Temperature sensor 3 is in a warning alarm", "warning"),
    ]


def test_arista_fan_states():
    rows = {f"{env.ARISTA_FAN_STATE}.{s}": s for s in (1, 2, 3, 4, 5)}
    assert _classes(_parse(env.ARISTA_FAN, env.FAN, rows)) == {
        "1": sh.TRANSITIONAL,
        "2": sh.DOWN,
        "3": sh.OK,
        "4": sh.TRANSITIONAL,
    }


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("PS1 Status", env.KIND_POWER),
        ("PSU 2 VIN", env.KIND_POWER),
        ("Power Supply 1", env.KIND_POWER),
        ("PS1 Fan 1", env.KIND_FAN),
        ("FAN2", env.KIND_FAN),
        ("CPU Core 0 Temp", env.KIND_TEMPERATURE),
        ("DTS CPU0", env.KIND_TEMPERATURE),
        ("+3.3V", None),
        ("", None),
    ],
)
def test_fortinet_sensor_kind_from_its_name(name, kind):
    assert env.fortinet_sensor_kind({env.FG_HW_SENSOR_NAME: name}) == kind


def test_fortinet_sensors_split_into_checks():
    rows = {f"{env.FG_HW_SENSOR_ALARM}.{i}": a for i, a in ((1, 0), (2, 1), (3, 1), (4, 1), (5, 1))}
    values = {
        f"{env.FG_HW_SENSOR_NAME}.2": "PS2 Status",
        f"{env.FG_HW_SENSOR_NAME}.3": "FAN1",
        f"{env.FG_HW_SENSOR_NAME}.4": "CPU Temp",
        f"{env.FG_HW_SENSOR_NAME}.5": "+12V",
    }
    table = sh.parse_table(env.FORTINET_SENSORS, rows, values)
    assert [c["message"] for c in sh.alert_checks(env.POWER, 1, sh.select(env.POWER, table))] == [
        "PS2 Status is in alarm"
    ]
    assert [c["severity"] for c in sh.alert_checks(env.FAN, 1, sh.select(env.FAN, table))] == ["warning"]
    # No severity in the MIB: the check's own.
    assert [c["severity"] for c in sh.alert_checks(env.TEMPERATURE, 1, sh.select(env.TEMPERATURE, table))] == [
        "warning"
    ]


def test_aos_switch_sensors_by_object_id():
    base = "1.3.6.1.4.1.11.2.3.7.8.3"
    rows = {f"{env.HP_SENSOR_STATUS}.{i}": s for i, s in ((1, 4), (2, 2), (3, 3), (4, 2), (5, 5), (6, 1))}
    values = {
        f"{env.HP_SENSOR_OBJECT_ID}.2": f"{base}.1",
        f"{env.HP_SENSOR_OBJECT_ID}.3": f"{base}.3",
        f"{env.HP_SENSOR_OBJECT_ID}.4": f".{base}.2",
        f"{env.HP_SENSOR_OBJECT_ID}.6": f"{base}.4",  # a future-slot sensor: none
        f"{env.HP_SENSOR_DESCR}.2": "Power Supply Sensor",
    }
    table = sh.parse_table(env.AOS_SWITCH_SENSORS, rows, values)
    assert _classes(sh.select(env.POWER, table)) == {"2": sh.DOWN}
    assert _classes(sh.select(env.FAN, table)) == {"4": sh.DOWN}
    temperature = sh.alert_checks(env.TEMPERATURE, 1, sh.select(env.TEMPERATURE, table))
    assert [(c["message"], c["severity"]) for c in temperature] == [("Temperature sensor 3 is warning", "warning")]


def test_aoscx_power_and_fan_states():
    assert set(env.AOSCX_PSU_STATES) | {2, 12} == set(range(1, 18))
    rows = {f"{env.AOSCX_PSU_STATE}.1.{s}": s for s in range(1, 18)}
    classes = _classes(_parse(env.AOSCX_POWER, env.POWER, rows))
    assert "1.2" not in classes and "1.12" not in classes  # faultAbsent, empty
    assert classes["1.1"] == sh.OK and classes["1.8"] == classes["1.11"] == sh.TRANSITIONAL
    assert {k for k, v in classes.items() if v == sh.DOWN} == {f"1.{s}" for s in (3, 4, 5, 6, 7, 9, 10, 13, 14, 15, 16, 17)}
    rows = {f"{env.AOSCX_FAN_STATE}.1.1.{s}": s for s in range(1, 6)}
    assert _classes(_parse(env.AOSCX_FAN, env.FAN, rows)) == {
        "1.1.1": sh.TRANSITIONAL,
        "1.1.3": sh.TRANSITIONAL,
        "1.1.4": sh.OK,
        "1.1.5": sh.DOWN,
    }


def test_netgear_box_services():
    rows = {f"{env.NETGEAR_FAN_STATE}.1.{s}": s for s in range(1, 8)}
    status = _parse(env.NETGEAR_FAN, env.FAN, rows)
    assert _classes(status) == {
        "1.2": sh.OK,
        "1.3": sh.DOWN,
        "1.4": sh.OK,
        "1.5": sh.DOWN,
        "1.6": sh.DOWN,
        "1.7": sh.DOWN,
    }
    assert status["items"][1]["name"] == "Fan 3 (unit 1)"
    temps = {f"{env.NETGEAR_TEMP_STATE}.2.{s}": s for s in range(0, 7)}
    status = _parse(env.NETGEAR_TEMPERATURE, env.TEMPERATURE, temps)
    assert [(c["dedup_key"], c["severity"]) for c in sh.alert_checks(env.TEMPERATURE, 3, status)] == [
        ("3:temperature_alarm:2.0", "warning"),
        ("3:temperature_alarm:2.2", "warning"),
        ("3:temperature_alarm:2.3", "critical"),
        ("3:temperature_alarm:2.4", "critical"),
    ]
    psu = _parse(env.NETGEAR_POWER, env.POWER, {f"{env.NETGEAR_PSU_STATE}.1": 5})
    assert psu["items"][0]["name"] == "Power supply 1"


# ── Reading (bounded) ────────────────────────────────────────────────────────


async def test_a_healthy_envmon_table_costs_one_walk_and_no_get():
    agent = Agent({f"{env.ENVMON_SUPPLY_STATE}.{i}": 1 for i in range(1, 5)})
    table = await env.CISCO_ENVMON_SUPPLY.read(agent.get, agent.walk, 1)
    assert agent.walks == [env.ENVMON_SUPPLY_STATE] and agent.gets == []
    assert sh.select(env.POWER, table)["down_count"] == 0


async def test_names_are_read_only_for_the_supplies_down():
    agent = Agent(
        {f"{env.ENVMON_SUPPLY_STATE}.1": 1, f"{env.ENVMON_SUPPLY_STATE}.2": 3},
        {f"{env.ENVMON_SUPPLY_DESCR}.2": "Power Supply 2"},
    )
    status = sh.select(env.POWER, await env.CISCO_ENVMON_SUPPLY.read(agent.get, agent.walk, 1))
    assert agent.gets == [(f"{env.ENVMON_SUPPLY_DESCR}.2",)]
    assert [c["message"] for c in sh.alert_checks(env.POWER, 1, status)] == ["Power Supply 2 is critical"]


async def test_cisco_sensor_thresholds():
    ev, sev, typ = env.ENT_SENSOR_THRESHOLD_EVALUATION, env.ENT_SENSOR_THRESHOLD_SEVERITY, env.ENT_SENSOR_TYPE
    rows = {
        f"{ev}.10.1": 2,
        f"{ev}.10.2": 2,  # sensor 10: no threshold crossed
        f"{ev}.11.1": 1,
        f"{ev}.11.2": 1,  # sensor 11: minor and major crossed
        f"{ev}.12.1": 1,  # sensor 12: a voltage sensor over a threshold
        f"{ev}.13.1": 1,  # sensor 13: severity other(1)
    }
    answers = {
        f"{typ}.11": 8,
        f"{typ}.12": 4,
        f"{typ}.13": 8,
        f"{sev}.11.1": 10,
        f"{sev}.11.2": 20,
        f"{sev}.12.1": 30,
        f"{sev}.13.1": 1,
        f"{ENT_NAME}.11": "Module 1 Inlet",
    }
    agent = Agent(rows, answers)
    status = sh.select(env.TEMPERATURE, await env.CISCO_SENSOR_THRESHOLDS.read(agent.get, agent.walk, 1))
    # Only the sensors in alarm are items (a sensor all false is OK by its absence).
    assert _classes(status) == {"11": sh.DOWN, "13": sh.DOWN}
    # Type and severities of the sensors in alarm only; names of the celsius ones.
    assert not any(oid.endswith(".10") or ".10." in oid for oid in agent.asked())
    checks = sh.alert_checks(env.TEMPERATURE, 2, status)
    assert [(c["message"], c["severity"]) for c in checks] == [
        ("Module 1 Inlet is over its major threshold", "critical"),
        ("Temperature sensor 13 is over a threshold", "warning"),
    ]


async def test_cisco_sensor_thresholds_not_read():
    # Ran to its end with no row: an empty table, not "not read".
    assert sh.is_empty(await env.CISCO_SENSOR_THRESHOLDS.read(Agent({}).get, Agent({}).walk, 1))
    cut = Agent({}, cut={env.ENT_SENSOR_THRESHOLD_EVALUATION})
    assert await env.CISCO_SENSOR_THRESHOLDS.read(cut.get, cut.walk, 1) is None
    agent = Agent({f"{env.ENT_SENSOR_THRESHOLD_EVALUATION}.11.1": 1}, silent_gets=True)
    assert await env.CISCO_SENSOR_THRESHOLDS.read(agent.get, agent.walk, 1) is None
    # All thresholds false: no GET at all.
    agent = Agent({f"{env.ENT_SENSOR_THRESHOLD_EVALUATION}.11.1": 2})
    status = sh.select(env.TEMPERATURE, await env.CISCO_SENSOR_THRESHOLDS.read(agent.get, agent.walk, 1))
    assert agent.gets == [] and _classes(status) == {} and status["down_count"] == 0


async def test_juniper_reads_its_fru_table_once_for_modules_supplies_and_fans():
    rows = {
        f"{mh.JNX_FRU_STATE}.7.1.0.0": 6,  # FPC online
        f"{mh.JNX_FRU_STATE}.2.1.0.0": 8,  # PEM 0 offline
        f"{mh.JNX_FRU_STATE}.4.1.0.0": 8,  # fan offline
        f"{mh.JNX_FRU_STATE}.2.2.0.0": 2,  # PEM 1 slot empty
        f"{mh.JNX_FRU_STATE}.9.1.0.0": 8,  # the craft panel offline: none of the checks
    }
    answers = {
        f"{mh.JNX_FRU_TYPE}.7.1.0.0": 3,
        f"{mh.JNX_FRU_TYPE}.2.1.0.0": 7,
        f"{mh.JNX_FRU_TYPE}.4.1.0.0": 13,
        f"{mh.JNX_FRU_TYPE}.9.1.0.0": 12,
        f"{mh.JNX_FRU_NAME}.2.1.0.0": "PEM 0",
        f"{mh.JNX_FRU_OFFLINE_REASON}.2.1.0.0": 3,
        f"{mh.JNX_FRU_NAME}.4.1.0.0": "Fan Tray 0",
        f"{mh.JNX_FRU_OFFLINE_REASON}.4.1.0.0": 7,  # cliCommand: an operator's
    }
    agent = Agent(rows, answers)
    result = await health_checks.read_health(1, "juniper_junos", agent.get, agent.walk_table)
    assert agent.walks.count(mh.JNX_FRU_STATE) == 1
    assert result["module_health"]["down_count"] == 0
    assert [c["message"] for c in sh.alert_checks(env.POWER, 1, result["power_supply_health"])] == ["PEM 0 is offline"]
    assert _classes(result["fan_health"]) == {"4.1.0.0": sh.ADMIN_DOWN}
    assert "temperature_health" not in result  # no Juniper temperature source


# ── Optics ───────────────────────────────────────────────────────────────────

ALIAS = env.ENT_ALIAS_MAPPING_IDENTIFIER
CONTAINED_IN = sh.ENT_PHYSICAL_CONTAINED_IN


def test_sensor_readings():
    assert env.sensor_reading(-725, 2, "dBm") == "-7.25 dBm"
    assert env.sensor_reading(-3, 0, "dBm") == "-3 dBm"
    assert env.sensor_reading(5, -1, "dBm") == "50 dBm"
    assert env.sensor_reading(None, 2, "dBm") == ""


def test_bits_of_a_value():
    assert sh.bit_set(b"\x80", 0) and sh.bit_set(b"\x00\x40", 9)
    assert not sh.bit_set(b"\x80", 1) and not sh.bit_set(b"", 3)


async def test_the_port_of_a_sensor_is_found_up_its_containers():
    answers = {
        f"{CONTAINED_IN}.1001": 1000,  # sensor -> transceiver
        f"{CONTAINED_IN}.1000": 900,  # transceiver -> port
        f"{ALIAS}.900.0": "1.3.6.1.2.1.2.2.1.1.17",
        f"{ALIAS}.2001": "x",  # not the instance asked (no logical index)
        f"{CONTAINED_IN}.2001": 0,  # a sensor on no port
    }
    agent = Agent({}, answers)
    assert await env.entity_if_indexes(agent.get, ["1001", "2001"]) == {"1001": "17"}
    assert len(agent.gets) == 3
    assert await env.entity_if_indexes(agent.get, []) == {}


async def test_cisco_optics_thresholds_reading_and_port():
    ev, sev, rel, typ = (
        env.ENT_SENSOR_THRESHOLD_EVALUATION,
        env.ENT_SENSOR_THRESHOLD_SEVERITY,
        env.ENT_SENSOR_THRESHOLD_RELATION,
        env.ENT_SENSOR_TYPE,
    )
    rows = {
        f"{ev}.20.1": 1,  # sensor 20: receive power below its low warning and low alarm
        f"{ev}.20.2": 1,
        f"{ev}.20.3": 2,
        f"{ev}.21.1": 1,  # sensor 21: transmit power on a port shut down
        f"{ev}.22.1": 1,  # sensor 22: equalTo relation, severity other
        f"{ev}.23.1": 2,  # sensor 23: no threshold crossed
    }
    answers = {
        f"{typ}.20": 14,
        f"{typ}.21": 14,
        f"{typ}.22": 14,
        f"{sev}.20.1": 10,
        f"{rel}.20.1": 1,
        f"{sev}.20.2": 20,
        f"{rel}.20.2": 2,
        f"{sev}.21.1": 30,
        f"{rel}.21.1": 4,
        f"{sev}.22.1": 1,
        f"{rel}.22.1": 5,
        f"{ENT_NAME}.20": "Te1/1/1 Receive Power Sensor",
        f"{env.ENT_SENSOR_SCALE}.20": 9,
        f"{env.ENT_SENSOR_PRECISION}.20": 1,
        f"{env.ENT_SENSOR_VALUE}.20": -312,
        f"{ENT_NAME}.21": "Te1/1/2 Transmit Power Sensor",
        f"{env.ENT_SENSOR_SCALE}.21": 8,  # milli: no reading shown
        f"{env.ENT_SENSOR_VALUE}.21": 5,
        f"{ALIAS}.20.0": "1.3.6.1.2.1.2.2.1.1.10",
        f"{ALIAS}.21.0": "1.3.6.1.2.1.2.2.1.1.11",
        f"{sh.IF_ADMIN_STATUS}.10": 1,
        f"{sh.IF_ADMIN_STATUS}.11": 2,
    }
    agent = Agent(rows, answers)
    table = await env.CISCO_SENSOR_THRESHOLDS.read(agent.get, agent.walk, 1)
    assert sh.select(env.TEMPERATURE, table)["items"] == []
    status = sh.select(env.OPTICS, table)
    assert _classes(status) == {"20": sh.DOWN, "21": sh.ADMIN_DOWN, "22": sh.DOWN}
    checks = sh.alert_checks(env.OPTICS, 6, status)
    assert [(c["dedup_key"], c["message"], c["severity"]) for c in checks] == [
        ("6:optic_level_alarm:20", "Te1/1/1 Receive Power Sensor (-31.2 dBm) is below its major threshold", "critical"),
        ("6:optic_level_alarm:22", "Optic 22 is past a threshold", "warning"),
    ]
    shut = next(i for i in status["items"] if i["index"] == "21")
    assert shut["status"] == "above its critical threshold, interface admin down"
    # The interface's name is not asked: the sensor's own name carries it.
    assert not any(oid.startswith(sh.IF_NAME) for oid in agent.asked())


async def test_entity_state_optics_by_name_and_port():
    rows = {f"{env.ENT_STATE_ALARM}.{i}": b"\x08" for i in (31, 32, 33)}
    values = {
        f"{ENT_CLASS}.31": 8,
        f"{env.ENT_PHY_SENSOR_TYPE}.31": 6,
        f"{ENT_NAME}.31": "DOM Rx Power Sensor for Ethernet5",
        f"{ENT_CLASS}.32": 8,
        f"{env.ENT_PHY_SENSOR_TYPE}.32": 4,
        f"{ENT_NAME}.32": "DOM Voltage Sensor for Ethernet5",  # not an optic's light level
        f"{ENT_CLASS}.33": 8,
        f"{env.ENT_PHY_SENSOR_TYPE}.33": 1,
        f"{sh.ENT_PHYSICAL_DESCR}.33": "DOM Tx Power Sensor for Ethernet6",
        f"{CONTAINED_IN}.31": 300,
        f"{ALIAS}.300.0": "1.3.6.1.2.1.2.2.1.1.5",
        f"{sh.IF_ADMIN_STATUS}.5": 1,
    }
    agent = Agent(rows, values)
    table = await env.ENTITY_STATE_SENSORS.read(agent.get, agent.walk, 1)
    status = sh.select(env.OPTICS, table)
    assert _classes(status) == {"31": sh.DOWN, "33": sh.DOWN}
    assert [c["message"] for c in sh.alert_checks(env.OPTICS, 1, status)] == [
        "DOM Rx Power Sensor for Ethernet5 is in a warning alarm",
        "DOM Tx Power Sensor for Ethernet6 is in a warning alarm",
    ]
    assert env.entity_sensor_kind({ENT_CLASS: 7}) is None
    assert sh.is_empty(await env.ENTITY_STATE_SENSORS.read(Agent({}).get, Agent({}).walk, 1))


async def test_juniper_dom_alarm_and_warning_bits():
    alarms, warnings = env.JNX_DOM_CURRENT_ALARMS, env.JNX_DOM_CURRENT_WARNINGS
    rows = {
        f"{alarms}.501": b"\x08\x00\x00",  # domRxLaserPowerLowAlarm(4)
        f"{alarms}.502": b"\x00\x00\x00",
        f"{alarms}.503": b"\x00\x00\x00",
        f"{alarms}.504": b"\x80\x00\x00",  # loss of signal only: not a light-level alarm
        f"{alarms}.505": b"\x00\x80\x00",  # domTxLaserOutputPowerLowAlarm(8), port shut down
        f"{alarms}.506": "No Such Instance currently exists at this OID",
        f"{alarms}.507": b"\x08\x00\x00",  # receive power low, the link down
        f"{warnings}.502": b"\x40\x00",  # domRxLaserPowerLowWarning(1)
        f"{warnings}.503": b"\x00\x00",
    }
    answers = {
        f"{sh.IF_NAME}.501": "xe-0/0/1",
        f"{sh.IF_ADMIN_STATUS}.501": 1,
        f"{sh.IF_ADMIN_STATUS}.505": 2,
        f"{sh.IF_OPER_STATUS}.501": 1,
        f"{sh.IF_ADMIN_STATUS}.507": 1,
        f"{sh.IF_OPER_STATUS}.507": 2,
    }
    agent = Agent(rows, answers)
    status = sh.select(env.OPTICS, await env.JUNIPER_DOM.read(agent.get, agent.walk, 1))
    assert _classes(status) == {
        "501": sh.DOWN,
        "502": sh.DOWN,
        "503": sh.OK,
        "504": sh.OK,
        "505": sh.ADMIN_DOWN,
        "507": sh.TRANSITIONAL,
    }
    checks = sh.alert_checks(env.OPTICS, 2, status)
    assert [(c["message"], c["severity"]) for c in checks] == [
        ("Optic on xe-0/0/1 is in a critical alarm (receive power low)", "critical"),
        ("Optic 502 is in a warning alarm (receive power low)", "warning"),
    ]
    assert sh.is_empty(await env.JUNIPER_DOM.read(Agent({}).get, Agent({}).walk, 1))
    for cut in (alarms, warnings):
        agent = Agent({f"{alarms}.501": b"\x00"}, cut={cut})
        assert await env.JUNIPER_DOM.read(agent.get, agent.walk, 1) is None


async def test_aos_switch_transceiver_alarms_count_only_with_dom():
    alarms = env.HP_XCVR_ALARMS
    rows = {
        f"{alarms}.1": b"\x00\x20\x00",  # rxPowerLowAlarm(10)
        f"{alarms}.2": b"\x20\x00\x00",  # txPowerLowWarning(2), not a DOM transceiver
        f"{alarms}.3": b"\x00\x00\x00",
    }
    answers = {f"{env.HP_XCVR_DIAGNOSTICS}.1": 1, f"{env.HP_XCVR_DIAGNOSTICS}.2": 2, f"{sh.IF_NAME}.1": "A1"}
    agent = Agent(rows, answers)
    status = sh.select(env.OPTICS, await env.AOS_SWITCH_DOM.read(agent.get, agent.walk, 1))
    assert _classes(status) == {"1": sh.DOWN, "2": sh.OK, "3": sh.OK}
    assert [c["message"] for c in sh.alert_checks(env.OPTICS, 1, status)] == [
        "Optic on A1 is in a critical alarm (receive power low)"
    ]
    silent = Agent(rows, silent_gets=True)
    assert await env.AOS_SWITCH_DOM.read(silent.get, silent.walk, 1) is None


async def test_nxos_reads_the_sensor_thresholds_once_for_temperature_and_optics():
    ev = env.ENT_SENSOR_THRESHOLD_EVALUATION
    rows = {f"{ev}.20.1": 1, f"{ev}.30.1": 1}
    answers = {
        f"{env.ENT_SENSOR_TYPE}.20": 14,
        f"{env.ENT_SENSOR_TYPE}.30": 8,
        f"{env.ENT_SENSOR_THRESHOLD_SEVERITY}.20.1": 20,
        f"{env.ENT_SENSOR_THRESHOLD_SEVERITY}.30.1": 10,
    }
    agent = Agent(rows, answers)
    result = await health_checks.read_health(1, "cisco_nxos", agent.get, agent.walk_table)
    assert agent.walks.count(ev) == 1
    assert _classes(result["optics_health"]) == {"20": sh.DOWN}
    assert _classes(result["temperature_health"]) == {"30": sh.DOWN}


async def test_the_poll_raises_and_resolves_an_optic(monkeypatch):
    group_id, host_id = await add_host("juniper_junos")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    alarms, warnings = env.JNX_DOM_CURRENT_ALARMS, env.JNX_DOM_CURRENT_WARNINGS
    agent = Agent(
        {f"{SYS_UPTIME}.0": 4200, f"{alarms}.501": b"\x08\x00", f"{warnings}.501": b"\x00"},
        {f"{sh.IF_NAME}.501": "xe-0/0/1"},
    )
    result = await poll(monkeypatch, host, agent)
    assert await evaluate(host_id, group_id, result) == 1
    alerts = await open_alerts(host_id)
    assert [(a["metric"], a["severity"]) for a in alerts.values()] == [("optic_level_alarm", "critical")]
    agent.rows[f"{alarms}.501"] = b"\x00\x00"
    await evaluate(host_id, group_id, await poll(monkeypatch, host, agent))
    assert await open_alerts(host_id) == {}


# ── Wiring: the poll's alert evaluation ──────────────────────────────────────


def _power(**classes: str) -> dict:
    label = {sh.OK: ("normal", 1), sh.DOWN: ("critical", 3), sh.TRANSITIONAL: ("unknown", 9), sh.ADMIN_DOWN: ("off", 3)}
    items = [
        {
            "index": i.lstrip("p"),
            "name": f"PS-{i.lstrip('p')}",
            "model": "",
            "status": label[k][0],
            "state": label[k][1],
            "class": k,
            "severity": None,
        }
        for i, k in classes.items()
    ]
    return {"source": "test", "vendor": "Test", "items": items, "down_count": sum(1 for i in items if i["class"] == sh.DOWN)}


async def test_the_poll_raises_and_resolves_per_supply():
    group_id, host_id = await add_host("cisco_xe")
    assert await evaluate(host_id, group_id, res(host_id, power_supply_health=_power(p1=sh.OK, p2=sh.DOWN))) == 1
    alerts = await open_alerts(host_id)
    assert [(a["metric"], a["severity"], a["message"]) for a in alerts.values()] == [
        ("power_supply_down", "critical", "PS-2 is critical")
    ]
    await evaluate(host_id, group_id, res(host_id, power_supply_health=_power(p1=sh.DOWN, p2=sh.DOWN)))
    assert set(await open_alerts(host_id)) == {f"{host_id}:power_supply_down:1", f"{host_id}:power_supply_down:2"}
    # Passing state keeps; a poll that read no table changes nothing.
    await evaluate(host_id, group_id, res(host_id, power_supply_health=_power(p1=sh.TRANSITIONAL, p2=sh.DOWN)))
    await evaluate(host_id, group_id, res(host_id, power_supply_health={}))
    await evaluate(host_id, group_id, res(host_id))
    assert len(await open_alerts(host_id)) == 2
    # Supply 1 turned off by an operator, supply 2 gone from the table.
    await evaluate(host_id, group_id, res(host_id, power_supply_health=_power(p1=sh.ADMIN_DOWN)))
    assert await open_alerts(host_id) == {}


async def test_fan_and_temperature_alerts_and_their_suppression():
    group_id, host_id = await add_host("arista_eos")
    fan = sh.select(env.FAN, sh.parse_table(env.ARISTA_FAN, {f"{env.ARISTA_FAN_STATE}.5": 2}, {}))
    temp_table = sh.parse_table(
        env.ENTITY_STATE_SENSORS,
        {f"{env.ENT_STATE_ALARM}.9": b"\x20"},
        {f"{ENT_CLASS}.9": 8, f"{env.ENT_PHY_SENSOR_TYPE}.9": 8},
    )
    temperature = sh.select(env.TEMPERATURE, temp_table)
    assert await evaluate(host_id, group_id, res(host_id, fan_health=fan, temperature_health=temperature)) == 2
    alerts = await open_alerts(host_id)
    assert alerts[f"{host_id}:fan_down:5"]["severity"] == "warning"
    assert alerts[f"{host_id}:temperature_alarm:9"]["severity"] == "critical"
    await db.create_alert_suppression(name="fan swap", ends_at="2099-01-01T00:00:00", host_id=host_id, metric="fan_down")
    rows = await db.get_active_alert_suppressions()
    fan2 = sh.select(env.FAN, sh.parse_table(env.ARISTA_FAN, {f"{env.ARISTA_FAN_STATE}.6": 2}, {}))
    assert await evaluate(host_id, group_id, res(host_id, fan_health=fan2), suppressions=rows) == 0


async def test_a_user_rule_and_the_metric_sample_use_the_counts():
    from netcontrol.routes.monitoring import _metric_value_from_poll, _process_poll_result

    group_id, host_id = await add_host("cisco_xe")
    result = res(host_id, power_supply_health=_power(p1=sh.DOWN, p2=sh.DOWN), fan_health=_power(p1=sh.OK))
    assert _metric_value_from_poll(result, "power_supply_down") == 2.0
    assert _metric_value_from_poll(result, "fan_down") == 0.0
    assert _metric_value_from_poll(result, "temperature_alarm") is None
    rule_id = await db.create_alert_rule("two supplies", "power_supply_down", operator=">=", value=2.0)
    rule = {"id": rule_id, "name": "two supplies", "metric": "power_supply_down", "operator": ">=", "value": 2.0}
    assert await evaluate(host_id, group_id, result, [rule]) == 3

    host = {**(await db.get_host(host_id)), "group_id": group_id}
    full = {
        **result,
        "memory_used_mb": None,
        "memory_total_mb": None,
        "uptime_seconds": None,
        "if_up_count": 0,
        "if_admin_down": 0,
        "vpn_tunnels_up": 0,
        "route_count": 0,
        "route_snapshot": "",
        "poll_status": "ok",
        "poll_error": "",
    }
    await _process_poll_result(host, full, [])
    assert [s["value"] for s in await db.query_metric_samples("power_supply_down", [host_id])] == [2.0]
    assert [s["value"] for s in await db.query_metric_samples("fan_down", [host_id])] == [0.0]
    assert await db.query_metric_samples("temperature_alarm", [host_id]) == []


# ── Wiring: a whole poll ─────────────────────────────────────────────────────


async def test_the_poll_reads_the_cisco_environment(monkeypatch):
    group_id, host_id = await add_host("cisco_xe")
    rows = {
        f"{SYS_UPTIME}.0": 4200,
        f"{env.ENVMON_SUPPLY_STATE}.1": 1,
        f"{env.ENVMON_SUPPLY_STATE}.2": 3,
        f"{env.ENVMON_FAN_STATE}.1": 1,
        f"{env.ENVMON_TEMPERATURE_STATE}.1": 2,
    }
    answers = {f"{env.ENVMON_SUPPLY_DESCR}.2": "Power Supply 2", f"{env.ENVMON_TEMPERATURE_DESCR}.1": "Inlet"}
    agent = Agent(rows, answers)
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    result = await poll(monkeypatch, host, agent)
    assert result["power_supply_health"]["down_count"] == 1
    assert result["fan_health"]["down_count"] == 0
    assert result["temperature_health"]["down_count"] == 1
    # ENVMON answered: the FRU tables are not asked; the sensor threshold
    # table is, once, for the optics.
    assert not {env.CEFC_FRU_POWER_OPER, env.CEFC_FAN_TRAY_OPER} & set(agent.walks)
    assert agent.walks.count(env.ENT_SENSOR_THRESHOLD_EVALUATION) == 1

    from netcontrol.routes.monitoring import _process_poll_result

    await _process_poll_result(host, result, [])
    messages = sorted(a["message"] for a in (await open_alerts(host_id)).values())
    assert messages == ["Inlet is warning", "Power Supply 2 is critical"]


async def test_nxos_falls_back_to_the_fru_and_sensor_tables_and_remembers_empty_ones(monkeypatch):
    group_id, host_id = await add_host("cisco_nxos")
    rows = {
        f"{SYS_UPTIME}.0": 4200,
        f"{env.CEFC_FRU_POWER_OPER}.470": 2,
        f"{env.CEFC_FRU_POWER_OPER}.471": 5,
        f"{env.CEFC_FAN_TRAY_OPER}.534": 3,
        f"{env.ENT_SENSOR_THRESHOLD_EVALUATION}.21590.1": 2,
    }
    answers = {f"{ENT_CLASS}.471": 6, f"{ENT_NAME}.471": "PowerSupply-2", f"{ENT_NAME}.534": "Fan Module-1"}
    agent = Agent(rows, answers)
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    result = await poll(monkeypatch, host, agent)
    assert [i["name"] for i in result["power_supply_health"]["items"]] == ["PowerSupply-2"]
    assert result["fan_health"]["items"][0]["status"] == "down"
    assert result["temperature_health"]["down_count"] == 0
    first = set(agent.walks)
    assert env.ENVMON_SUPPLY_STATE in first and env.CEFC_FRU_POWER_OPER in first

    # The tables the switch answered empty are walked until they have been
    # empty at three polls in a row, then not for the next hour.
    for _ in range(2):
        agent.walks.clear()
        await poll(monkeypatch, host, agent)
        assert env.ENVMON_SUPPLY_STATE in agent.walks
    agent.walks.clear()
    await poll(monkeypatch, host, agent)
    assert env.ENVMON_SUPPLY_STATE not in agent.walks and env.ENVMON_FAN_STATE not in agent.walks
    assert env.CEFC_FRU_POWER_OPER in agent.walks


async def test_a_table_empty_after_a_reload_is_read_again_at_the_next_poll(monkeypatch):
    """A chassis polled just after a reload answers its supply table empty:
    that is not "no supplies" (nothing resolves), and the next poll walks it
    again and raises for the supply that did not come back."""
    group_id, host_id = await add_host("cisco_xe")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    agent = Agent({f"{SYS_UPTIME}.0": 300}, {f"{env.ENVMON_SUPPLY_DESCR}.2": "Power Supply 2"})
    result = await poll(monkeypatch, host, agent)
    assert result["power_supply_health"] == {}
    agent.rows.update({f"{env.ENVMON_SUPPLY_STATE}.1": 1, f"{env.ENVMON_SUPPLY_STATE}.2": 3})
    agent.walks.clear()
    result = await poll(monkeypatch, host, agent)
    assert env.ENVMON_SUPPLY_STATE in agent.walks
    assert await evaluate(host_id, group_id, result) == 1
    assert [a["message"] for a in (await open_alerts(host_id)).values()] == ["Power Supply 2 is critical"]


async def test_an_open_alert_resolves_once_its_table_is_confirmed_empty(monkeypatch):
    group_id, host_id = await add_host("aruba_aoscx")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    agent = Agent({f"{SYS_UPTIME}.0": 300, f"{env.AOSCX_FAN_STATE}.1.1.1": 5})
    await evaluate(host_id, group_id, await poll(monkeypatch, host, agent))
    assert list(await open_alerts(host_id)) == [f"{host_id}:fan_down:1.1.1"]
    del agent.rows[f"{env.AOSCX_FAN_STATE}.1.1.1"]
    for _ in range(2):  # empty, not yet confirmed: the alert stays
        result = await poll(monkeypatch, host, agent)
        assert result["fan_health"] == {}
        await evaluate(host_id, group_id, result)
    assert len(await open_alerts(host_id)) == 1
    result = await poll(monkeypatch, host, agent)
    assert result["fan_health"]["empty"] and result["fan_health"]["down_count"] is None
    await evaluate(host_id, group_id, result)
    assert await open_alerts(host_id) == {}
    # No metric sample for an empty table.
    assert health_checks.metric_sample_rows(result) == []
    # The column answered rows before: it is still walked at every poll.
    agent.walks.clear()
    await poll(monkeypatch, host, agent)
    assert env.AOSCX_FAN_STATE in agent.walks


async def test_a_walk_that_reaches_the_row_cap_is_cut_short(monkeypatch):
    import netcontrol.routes.monitoring as monitoring

    monkeypatch.setattr(health_checks, "WALK_MAX_ROWS", 3)
    group_id, host_id = await add_host("aruba_aoscx")
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    rows = {f"{SYS_UPTIME}.0": 300, **{f"{env.AOSCX_PSU_STATE}.1.{i}": 1 for i in range(1, 4)}}
    rows[f"{env.AOSCX_FAN_STATE}.1.1.1"] = 5
    agent = Agent(rows)
    asked: dict[str, int] = {}
    result = await poll(monkeypatch, host, agent)
    assert result["power_supply_health"] == {}  # 3 rows: the cap, so not complete
    assert result["fan_health"]["down_count"] == 1
    # The health walks ask for the cap; the other walks keep their default.
    fake_walk = monitoring._snmp_walk

    async def _recording(ip, wait, cfg, oid, *args, max_rows=500, **kwargs):
        asked[oid] = max_rows
        return await fake_walk(ip, wait, cfg, oid, *args, **kwargs)

    monkeypatch.setattr(monitoring, "_snmp_walk", _recording)
    await monitoring._poll_host_monitoring(host, None, {"enabled": True})
    assert asked[env.AOSCX_PSU_STATE] == 3 and asked[SYS_UPTIME] == 500


async def test_a_walk_cut_short_reads_no_table_and_does_not_fall_back(monkeypatch):
    group_id, host_id = await add_host("cisco_xe")
    rows = {f"{SYS_UPTIME}.0": 4200, f"{env.ENVMON_SUPPLY_STATE}.1": 3, f"{env.CEFC_FRU_POWER_OPER}.9": 8}
    agent = Agent(rows, cut={env.ENVMON_SUPPLY_STATE})
    host = {**(await db.get_host(host_id)), "group_id": group_id}
    result = await poll(monkeypatch, host, agent)
    assert result["power_supply_health"] == {}
    assert env.CEFC_FRU_POWER_OPER not in agent.walks


async def test_a_device_that_answered_nothing_is_not_asked(monkeypatch):
    await add_host("fortinet")
    agent = Agent({})
    host = {"id": 1, "hostname": "fw-a", "ip_address": "192.0.2.91", "device_type": "fortinet"}
    result = await poll(monkeypatch, host, agent)
    assert not {"power_supply_health", "fan_health", "temperature_health", "bgp_health"} & set(result)
    assert env.FG_HW_SENSOR_ALARM not in agent.walks
