"""APC Smart-UPS readings beyond battery and output: input and output
voltage, input frequency, last transfer cause, battery and probe
temperature, and the overload and battery temperature alerts.

The SNMP answers are invented values in the shape a card returns (the
``.0`` instance of each walked scalar, one row per probe).
"""

from __future__ import annotations

import pytest
import routes.database as db
from netcontrol.integrations.apc import snmp as apc_snmp

NO_SUCH_OBJECT = "No Such Object currently exists at this OID"


def _values(**over) -> dict:
    """Walked PowerNet values of a healthy UPS on 230 V mains."""
    values = {
        "model": "Smart-UPS 1500",
        "firmware": "UPS 09.3 (ID18)",
        "serial": "AS0000000009",
        "battery_status": 2,
        "battery_capacity": 100,
        "runtime": 282_000,
        "battery_replace": 1,
        "output_status": 2,
        "output_load": 35,
        "input_voltage_hp": 2312,
        "input_voltage": 231,
        "input_frequency_hp": 499,
        "input_frequency": 50,
        "transfer_cause": 4,
        "output_voltage_hp": 2298,
        "output_voltage": 230,
        "battery_temp_extd": 254,
        "battery_temp_hp": 254,
        "battery_temp": 25,
    }
    values.update(over)
    return values


def _status(probe_rows: dict | None = None, **over) -> dict:
    return apc_snmp.parse_ups_status(_values(**over), "", probe_rows)


# ── Parsing ──────────────────────────────────────────────────────────────────


def test_the_high_precision_readings_are_used():
    status = _status()
    assert status["input_voltage_v"] == 231.2
    assert status["input_frequency_hz"] == 49.9
    assert status["output_voltage_v"] == 229.8
    assert (status["last_transfer_cause"], status["last_transfer_cause_label"]) == (4, "Blackout")
    assert status["battery_temperature_c"] == 25.4


def test_the_plain_readings_are_the_fallback():
    status = _status(input_voltage_hp=NO_SUCH_OBJECT, input_frequency_hp=None, output_voltage_hp=NO_SUCH_OBJECT)
    assert (status["input_voltage_v"], status["input_frequency_hz"], status["output_voltage_v"]) == (
        231.0,
        50.0,
        230.0,
    )


def test_unanswered_readings_are_empty_not_zero():
    status = _status(
        input_voltage_hp=None,
        input_voltage=NO_SUCH_OBJECT,
        input_frequency_hp=None,
        input_frequency=None,
        output_voltage_hp=None,
        output_voltage=None,
        transfer_cause=NO_SUCH_OBJECT,
        battery_temp_extd=None,
        battery_temp_hp=None,
        battery_temp=None,
    )
    for key in ("input_voltage_v", "input_frequency_hz", "output_voltage_v", "battery_temperature_c"):
        assert status[key] is None, key
    assert (status["last_transfer_cause"], status["last_transfer_cause_label"]) == (None, "")
    assert status["probe_temperature_c"] is None
    # A blackout really reads 0 V on the input: that is kept.
    assert _status(input_voltage_hp=0)["input_voltage_v"] == 0.0


@pytest.mark.parametrize(
    ("extd", "tenths", "whole", "expected"),
    [
        (-52, 2550, 255, -5.2),  # the extended object is signed and wins
        (None, 312, 31, 31.2),
        (None, None, 31, 31.0),
        (None, None, 255, None),  # 255: not present
        (None, 2550, 255, None),
        (None, 255, 255, None),  # 255 tenths with no whole reading: not present
        (None, 255, None, None),
        (None, 255, 25, 25.5),  # 25.5 °C, confirmed by the whole-degree reading
        (None, 2550, 31, 31.0),
        (NO_SUCH_OBJECT, NO_SUCH_OBJECT, 28, 28.0),
    ],
)
def test_the_battery_temperature(extd, tenths, whole, expected):
    status = _status(battery_temp_extd=extd, battery_temp_hp=tenths, battery_temp=whole)
    assert status["battery_temperature_c"] == expected


def test_the_probe_temperature_is_the_first_valid_probe():
    base = apc_snmp.PROBE_TEMPERATURE_OID
    rows = {f"{base}.10.1": 30, f"{base}.2.1": -1, f"{base}.3.1": 22}
    assert _status(rows)["probe_temperature_c"] == 22.0
    assert _status({f"{base}.1.1": -1})["probe_temperature_c"] is None
    assert _status({})["probe_temperature_c"] is None


def test_unknown_transfer_cause_code_has_no_label():
    assert _status(transfer_cause=42)["last_transfer_cause_label"] == ""


async def test_the_probe_table_is_walked():
    base = apc_snmp.PROBE_TEMPERATURE_OID
    rows = {oid: {oid + ".0": _values()[key]} for key, oid in apc_snmp.UPS_OIDS.items()}
    rows[base] = {f"{base}.1.1": 24}

    async def walk(oid: str) -> dict:
        return rows.get(oid, {})

    status = await apc_snmp.read_ups_status(walk)
    assert (status["probe_temperature_c"], status["input_voltage_v"]) == (24.0, 231.2)


# ── Metrics ──────────────────────────────────────────────────────────────────


def test_the_new_metric_samples_and_rollups():
    from netcontrol.routes.metrics_engine import _DOWNSAMPLE_METRICS

    status = _status({f"{apc_snmp.PROBE_TEMPERATURE_OID}.1.1": 23})
    rows = {metric: value for _h, metric, _l, value in apc_snmp.ups_metric_samples(7, status)}
    assert rows["ups_input_voltage_v"] == 231.2
    assert rows["ups_input_frequency_hz"] == 49.9
    assert rows["ups_output_voltage_v"] == 229.8
    assert rows["ups_battery_temperature_c"] == 25.4
    assert rows["ups_probe_temperature_c"] == 23.0
    assert set(apc_snmp.UPS_METRICS) <= set(_DOWNSAMPLE_METRICS)
    # Not answered: no sample at all (never a 0).
    empty = _status(battery_temp_extd=None, battery_temp_hp=None, battery_temp=None)
    assert "ups_battery_temperature_c" not in {m for _h, m, _l, _v in apc_snmp.ups_metric_samples(7, empty)}


# ── Built-in alerts ──────────────────────────────────────────────────────────


def _alerts(**over) -> dict[str, dict]:
    return {check["metric"]: check for check in apc_snmp.ups_alert_checks(_status(**over))}


def test_battery_temperature_thresholds():
    warning_c, critical_c = apc_snmp.BATTERY_TEMPERATURE_C
    assert (warning_c, critical_c) == (40.0, 50.0)
    assert "ups_battery_temperature" not in _alerts(battery_temp_extd=399)
    warn = _alerts(battery_temp_extd=400)["ups_battery_temperature"]
    assert (warn["severity"], warn["value"], warn["threshold"], warn["alert_type"]) == (
        "warning",
        40.0,
        40.0,
        "threshold",
    )
    assert warn["message"] == "UPS battery temperature 40 °C (threshold 40 °C)"
    crit = _alerts(battery_temp_extd=512)["ups_battery_temperature"]
    assert (crit["severity"], crit["threshold"]) == ("critical", 50.0)


def test_overload():
    assert "ups_overload" not in _alerts(output_load=99)
    check = _alerts(output_load=104)["ups_overload"]
    assert (check["severity"], check["value"], check["threshold"]) == ("critical", 104.0, 100.0)


def test_alert_keys_and_cleared_alerts():
    assert apc_snmp.alert_dedup_key(3, "ups_on_battery") == "3:ups_on_battery:status"
    assert apc_snmp.alert_dedup_key(3, "ups_battery_temperature") == "3:ups_battery_temperature:threshold"
    assert apc_snmp.alert_dedup_key(3, "ups_overload") == "3:ups_overload:threshold"
    status = _status(output_status=3)
    checks = apc_snmp.ups_alert_checks(status)
    cleared = apc_snmp.ups_cleared_alerts(status, checks)
    assert "ups_on_battery" not in cleared
    assert {"ups_battery", "ups_output", "ups_overload", "ups_battery_temperature", "ups_communication"} <= set(cleared)
    # An unknown output state does not prove the card talks to the UPS.
    unknown = _status(output_status=1)
    assert "ups_communication" not in apc_snmp.ups_cleared_alerts(unknown, [])
    assert apc_snmp.ups_cleared_alerts({}, []) == []


# ── The poll, end to end ─────────────────────────────────────────────────────


async def test_the_poll_raises_and_resolves_the_temperature_alert():
    from netcontrol.routes.monitoring import _evaluate_alerts_for_poll

    await db.init_db()
    group_id = await db.create_group("ups-readings")
    host_id = await db.add_host(group_id, "ups-r1", "192.0.2.70", "apc_ups")

    def _res(**over) -> dict:
        return {
            "host_id": host_id,
            "cpu_percent": None,
            "memory_percent": None,
            "if_down_count": 0,
            "if_details": [],
            "vpn_tunnels_down": 0,
            "vpn_details": [],
            "ups": _status(**over),
        }

    poll_id = await db.create_monitoring_poll(host_id)
    await _evaluate_alerts_for_poll(_res(battery_temp_extd=455, output_load=101), poll_id, group_id, [])
    open_alerts = {a["metric"]: a for a in await db.get_monitoring_alerts(host_id, acknowledged=False)}
    assert set(open_alerts) == {"ups_battery_temperature", "ups_overload"}
    assert open_alerts["ups_battery_temperature"]["severity"] == "warning"

    await _evaluate_alerts_for_poll(_res(), poll_id, group_id, [])
    assert await db.get_monitoring_alerts(host_id, acknowledged=False) == []


async def test_a_user_rule_can_use_the_input_voltage():
    from netcontrol.routes.monitoring import _metric_value_from_poll

    res = {"ups": _status(input_voltage_hp=1984)}
    assert _metric_value_from_poll(res, "ups_input_voltage_v") == 198.4
    assert _metric_value_from_poll(res, "ups_input_frequency_hz") == 49.9
    assert _metric_value_from_poll({"ups": {}}, "ups_battery_temperature_c") is None
