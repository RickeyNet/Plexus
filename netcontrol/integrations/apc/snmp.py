"""APC Smart-UPS state over SNMP (PowerNet-MIB, enterprise 318).

The monitoring poll reads these scalars from a host of type ``apc_ups``
(``netcontrol/routes/monitoring.py``), stores the result as the host's
vendor status (``host_vendor_status``, shown on the device page), emits the
numbers as metric samples (kept and rolled up like CPU and memory) and
raises the built-in UPS alerts below into ``monitoring_alerts``.

Object identifiers, checked against the PowerNet-MIB text (the poll GETs
the ``.0`` instance of each):

  upsBasicIdentModel             1.3.6.1.4.1.318.1.1.1.1.1.1   DisplayString
  upsAdvIdentFirmwareRevision    1.3.6.1.4.1.318.1.1.1.1.2.1   DisplayString
  upsAdvIdentSerialNumber        1.3.6.1.4.1.318.1.1.1.1.2.3   DisplayString
  upsBasicBatteryStatus          1.3.6.1.4.1.318.1.1.1.2.1.1   INTEGER (below)
  upsAdvBatteryCapacity          1.3.6.1.4.1.318.1.1.1.2.2.1   Gauge, percent
  upsAdvBatteryRunTimeRemaining  1.3.6.1.4.1.318.1.1.1.2.2.3   TimeTicks
  upsAdvBatteryReplaceIndicator  1.3.6.1.4.1.318.1.1.1.2.2.4   INTEGER 1 no / 2 yes
  upsBasicOutputStatus           1.3.6.1.4.1.318.1.1.1.4.1.1   INTEGER (below)
  upsAdvOutputLoad               1.3.6.1.4.1.318.1.1.1.4.2.3   Gauge, percent
  upsHighPrecInputLineVoltage    1.3.6.1.4.1.318.1.1.1.3.3.1   Gauge, tenths of VAC
  upsAdvInputLineVoltage         1.3.6.1.4.1.318.1.1.1.3.2.1   Gauge, VAC (fallback)
  upsHighPrecInputFrequency      1.3.6.1.4.1.318.1.1.1.3.3.4   Gauge, tenths of Hz
  upsAdvInputFrequency           1.3.6.1.4.1.318.1.1.1.3.2.4   Gauge, Hz (fallback)
  upsAdvInputLineFailCause       1.3.6.1.4.1.318.1.1.1.3.2.5   INTEGER (below)
  upsHighPrecOutputVoltage       1.3.6.1.4.1.318.1.1.1.4.3.1   Gauge, tenths of VAC
  upsAdvOutputVoltage            1.3.6.1.4.1.318.1.1.1.4.2.1   Gauge, VAC (fallback)
  upsHighPrecExtdBatteryTemperature
                                 1.3.6.1.4.1.318.1.1.1.2.3.13  INTEGER, tenths of °C, may be negative
  upsHighPrecBatteryTemperature  1.3.6.1.4.1.318.1.1.1.2.3.2   Gauge, tenths of °C (fallback)
  upsAdvBatteryTemperature       1.3.6.1.4.1.318.1.1.1.2.2.2   Gauge, °C (fallback; 255 = not present)
  uioSensorStatusTemperatureDegC 1.3.6.1.4.1.318.1.1.25.1.2.1.6 INTEGER per probe, °C (-1 = invalid)

The card's own firmware is not in PowerNet-MIB: it is the ``PF`` field of
the card's sysDescr (``parse_apc_nmc_sys_descr``), read in the same poll.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from netcontrol.integrations.apc.firmware import DEVICE_TYPE, ups_version
from netcontrol.routes.snmp import APC_UPS_MODEL_OID, APC_UPS_SERIAL_OID, _snmp_str, parse_apc_nmc_sys_descr

# The kind of the vendor status row (``host_vendor_status.kind``).
STATUS_KIND = DEVICE_TYPE

SYS_DESCR_OID = "1.3.6.1.2.1.1.1"
UPS_OIDS: dict[str, str] = {
    "model": APC_UPS_MODEL_OID,  # upsBasicIdentModel
    "firmware": "1.3.6.1.4.1.318.1.1.1.1.2.1",  # upsAdvIdentFirmwareRevision
    "serial": APC_UPS_SERIAL_OID,  # upsAdvIdentSerialNumber
    "battery_status": "1.3.6.1.4.1.318.1.1.1.2.1.1",  # upsBasicBatteryStatus
    "battery_capacity": "1.3.6.1.4.1.318.1.1.1.2.2.1",  # upsAdvBatteryCapacity
    "runtime": "1.3.6.1.4.1.318.1.1.1.2.2.3",  # upsAdvBatteryRunTimeRemaining
    "battery_replace": "1.3.6.1.4.1.318.1.1.1.2.2.4",  # upsAdvBatteryReplaceIndicator
    "output_status": "1.3.6.1.4.1.318.1.1.1.4.1.1",  # upsBasicOutputStatus
    "output_load": "1.3.6.1.4.1.318.1.1.1.4.2.3",  # upsAdvOutputLoad
    "input_voltage_hp": "1.3.6.1.4.1.318.1.1.1.3.3.1",  # upsHighPrecInputLineVoltage
    "input_voltage": "1.3.6.1.4.1.318.1.1.1.3.2.1",  # upsAdvInputLineVoltage
    "input_frequency_hp": "1.3.6.1.4.1.318.1.1.1.3.3.4",  # upsHighPrecInputFrequency
    "input_frequency": "1.3.6.1.4.1.318.1.1.1.3.2.4",  # upsAdvInputFrequency
    "transfer_cause": "1.3.6.1.4.1.318.1.1.1.3.2.5",  # upsAdvInputLineFailCause
    "output_voltage_hp": "1.3.6.1.4.1.318.1.1.1.4.3.1",  # upsHighPrecOutputVoltage
    "output_voltage": "1.3.6.1.4.1.318.1.1.1.4.2.1",  # upsAdvOutputVoltage
    "battery_temp_extd": "1.3.6.1.4.1.318.1.1.1.2.3.13",  # upsHighPrecExtdBatteryTemperature
    "battery_temp_hp": "1.3.6.1.4.1.318.1.1.1.2.3.2",  # upsHighPrecBatteryTemperature
    "battery_temp": "1.3.6.1.4.1.318.1.1.1.2.2.2",  # upsAdvBatteryTemperature
}
# Instances asked for in one GET. The card's agent is small and answers
# SNMPv3 slowly: a few modest requests, one at a time, not one per object.
# A cautious size, not a documented limit of the card.
SCALARS_PER_GET = 10
# uioSensorStatusTemperatureDegC: one row per probe on the card's universal
# I/O ports (index port.sensor); -1 when the reading is invalid.
PROBE_TEMPERATURE_OID = "1.3.6.1.4.1.318.1.1.25.1.2.1.6"
_PROBE_INVALID = -1

# upsAdvInputLineFailCause: why the UPS last went to battery.
TRANSFER_CAUSE_LABELS: dict[int, str] = {
    1: "No transfer yet",
    2: "High line voltage",
    3: "Brownout",
    4: "Blackout",
    5: "Small momentary sag",
    6: "Deep momentary sag",
    7: "Small momentary spike",
    8: "Large momentary spike",
    9: "Self-test",
    10: "Rate of voltage change",
}

# upsHighPrecBatteryTemperature / upsAdvBatteryTemperature report their
# maximum (255) when the UPS has no reading.
_TEMPERATURE_NOT_PRESENT = 255

# upsBasicOutputStatus.
OUTPUT_STATUS_LABELS: dict[int, str] = {
    1: "Unknown",
    2: "On line",
    3: "On battery",
    4: "On smart boost",
    5: "Timed sleeping",
    6: "Software bypass",
    7: "Off",
    8: "Rebooting",
    9: "Switched bypass",
    10: "Hardware failure bypass",
    11: "Sleeping until power returns",
    12: "On smart trim",
    13: "Eco mode",
    14: "Hot standby",
    15: "On battery test",
    16: "Emergency static bypass",
    17: "Static bypass standby",
    18: "Power saving mode",
    19: "Spot mode",
    20: "eConversion",
    21: "Charger spot mode",
    22: "Inverter spot mode",
    23: "Active load",
    24: "Battery discharge spot mode",
    25: "Inverter standby",
    26: "Charger only",
    27: "Distributed energy reserve",
    28: "Self test",
}
OUTPUT_ON_BATTERY = frozenset({3})
# The load is not protected: on bypass, or not powered at all.
OUTPUT_BYPASS = frozenset({6, 9, 10, 16})
OUTPUT_BYPASS_CRITICAL = frozenset({10, 16})
OUTPUT_OFF = frozenset({5, 7, 11})

# upsBasicBatteryStatus.
BATTERY_STATUS_LABELS: dict[int, str] = {
    1: "Unknown",
    2: "Normal",
    3: "Low",
    4: "Fault",
    5: "No battery present",
}
BATTERY_LOW = 3
BATTERY_PROBLEMS = frozenset({3, 4, 5})

# upsAdvBatteryReplaceIndicator: 2 = batteryNeedsReplacing.
BATTERY_NEEDS_REPLACING = 2

# upsAdvBatteryRunTimeRemaining reports its maximum when there is no value.
_RUNTIME_NOT_PRESENT = 4_294_967_295

# The metric samples the poll emits for a UPS (and that user alert rules
# may name), with the status key each one is read from.
UPS_METRICS: dict[str, str] = {
    "ups_battery_capacity_pct": "battery_capacity_pct",
    "ups_runtime_minutes": "runtime_minutes",
    "ups_output_load_pct": "output_load_pct",
    "ups_output_status": "output_status",
    "ups_battery_status": "battery_status",
    "ups_input_voltage_v": "input_voltage_v",
    "ups_input_frequency_hz": "input_frequency_hz",
    "ups_output_voltage_v": "output_voltage_v",
    "ups_battery_temperature_c": "battery_temperature_c",
    "ups_probe_temperature_c": "probe_temperature_c",
}

# Built-in alerts: one metric per condition, deduplicated per host like the
# other built-in checks and resolved when the condition clears. The poll and
# the UPS's SNMP traps (``traps.py``) raise and resolve the same keys.
ALERT_ON_BATTERY = "ups_on_battery"
ALERT_BATTERY = "ups_battery"
ALERT_OUTPUT = "ups_output"
ALERT_OVERLOAD = "ups_overload"
ALERT_TEMPERATURE = "ups_battery_temperature"
# Raised and resolved only by the card's communicationLost /
# communicationEstablished traps; a poll that reads a known output state
# (the card is talking to the UPS) also resolves it.
ALERT_COMMUNICATION = "ups_communication"
# The alerts the poll evaluates (and resolves when the UPS no longer reports
# the condition).
ALERT_METRICS = (ALERT_ON_BATTERY, ALERT_BATTERY, ALERT_OUTPUT, ALERT_OVERLOAD, ALERT_TEMPERATURE)
_THRESHOLD_ALERTS = frozenset({ALERT_OVERLOAD, ALERT_TEMPERATURE})

# Battery temperature alert thresholds, °C: (warning at or above, critical
# at or above). Lead-acid batteries are rated at 20-25 °C and lose about
# half their life for every 8-10 °C above that.
BATTERY_TEMPERATURE_C = (40.0, 50.0)
# upsOverload: the load is above the UPS's rated capacity.
OUTPUT_OVERLOAD_PCT = 100


def alert_type(metric: str) -> str:
    """The ``alert_type`` of a built-in UPS alert."""
    return "threshold" if metric in _THRESHOLD_ALERTS else "status"


def alert_dedup_key(host_id: int, metric: str) -> str:
    """The dedup key of a built-in UPS alert, the same one the poll's
    built-in checks use (``host:metric:alert_type``)."""
    return f"{host_id}:{metric}:{alert_type(metric)}"


def _int(raw: Any) -> int | None:
    text = _snmp_str(raw) if raw is not None else ""
    try:
        return int(text)
    except TypeError, ValueError:
        return None


def _precise(tenths: Any, whole: Any) -> float | None:
    """A reading from its high-precision object (tenths), else its plain one."""
    value = _int(tenths)
    if value is not None:
        return round(value / 10, 1)
    value = _int(whole)
    return float(value) if value is not None else None


def _battery_temperature(values: dict[str, Any]) -> float | None:
    """The battery temperature in °C: the extended object (signed tenths),
    else the high-precision one (tenths), else the whole-degree one. The
    older two read 255 when the UPS has no reading; on the high-precision
    object that is ambiguous (25.5 °C), so it counts as missing only when
    the whole-degree object is missing too."""
    extd = _int(values.get("battery_temp_extd"))
    if extd is not None:
        return round(extd / 10, 1)
    whole = _int(values.get("battery_temp"))
    whole_missing = whole is None or whole == _TEMPERATURE_NOT_PRESENT
    tenths = _int(values.get("battery_temp_hp"))
    if tenths is not None and tenths < _TEMPERATURE_NOT_PRESENT * 10:
        if not (tenths == _TEMPERATURE_NOT_PRESENT and whole_missing):
            return round(tenths / 10, 1)
    if whole is None or whole == _TEMPERATURE_NOT_PRESENT:
        return None
    return float(whole)


def _oid_key(oid: str) -> tuple[int, ...]:
    return tuple(int(part) for part in oid.split(".") if part.isdigit())


def _probe_temperature(rows: dict | None) -> float | None:
    """The first valid reading of the card's temperature probes, °C."""
    for oid in sorted(rows or {}, key=_oid_key):
        value = _int(rows[oid]) if rows else None
        if value is not None and value != _PROBE_INVALID:
            return float(value)
    return None


def parse_ups_status(values: dict[str, Any], sys_descr: str = "", probe_rows: dict | None = None) -> dict[str, Any]:
    """The UPS state from the walked objects (``UPS_OIDS`` key -> raw value),
    the card's sysDescr and its probe temperature rows. ``{}`` when the
    device answered none of the PowerNet objects (not an APC UPS card, or
    SNMP did not answer). A reading the UPS did not answer is None, never 0."""
    if not any(values.get(key) is not None and _snmp_str(values[key]) for key in UPS_OIDS):
        return {}
    output = _int(values.get("output_status"))
    battery = _int(values.get("battery_status"))
    ticks = _int(values.get("runtime"))
    cause = _int(values.get("transfer_cause"))
    firmware = _snmp_str(values.get("firmware")) if values.get("firmware") is not None else ""
    status: dict[str, Any] = {
        "model": _snmp_str(values.get("model")) if values.get("model") is not None else "",
        "firmware": firmware,
        "firmware_version": ups_version(firmware),
        "serial": _snmp_str(values.get("serial")) if values.get("serial") is not None else "",
        "output_status": output,
        "output_status_label": OUTPUT_STATUS_LABELS.get(output or 0, "Unknown"),
        "battery_status": battery,
        "battery_status_label": BATTERY_STATUS_LABELS.get(battery or 0, "Unknown"),
        "battery_capacity_pct": _int(values.get("battery_capacity")),
        "runtime_minutes": (
            round(ticks / 6000, 1) if ticks is not None and 0 <= ticks < _RUNTIME_NOT_PRESENT else None
        ),
        "output_load_pct": _int(values.get("output_load")),
        "battery_needs_replacing": _int(values.get("battery_replace")) == BATTERY_NEEDS_REPLACING,
        "input_voltage_v": _precise(values.get("input_voltage_hp"), values.get("input_voltage")),
        "input_frequency_hz": _precise(values.get("input_frequency_hp"), values.get("input_frequency")),
        "output_voltage_v": _precise(values.get("output_voltage_hp"), values.get("output_voltage")),
        "last_transfer_cause": cause,
        "last_transfer_cause_label": TRANSFER_CAUSE_LABELS.get(cause, "") if cause is not None else "",
        "battery_temperature_c": _battery_temperature(values),
        "probe_temperature_c": _probe_temperature(probe_rows),
    }
    status.update(parse_apc_nmc_sys_descr(sys_descr))
    return status


async def read_ups_status(
    get: Callable[[tuple[str, ...]], Awaitable[dict]], walk: Callable[[str], Awaitable[dict]]
) -> dict[str, Any]:
    """Read and parse the UPS state with the monitoring poll's SNMP requests:
    ``get(instance oids) -> {oid: value}`` for the scalars, in requests of
    ``SCALARS_PER_GET`` sent one after the other, and ``walk(oid) -> {oid:
    value}`` for the probe table. ``{}`` when nothing answered: a card that
    does not answer the first GET is not asked again."""
    keys = list(UPS_OIDS)
    sys_descr_oid = f"{SYS_DESCR_OID}.0"
    oids = [*(f"{UPS_OIDS[key]}.0" for key in keys), sys_descr_oid]
    answers: dict = {}
    for start in range(0, len(oids), SCALARS_PER_GET):
        answer = await get(tuple(oids[start : start + SCALARS_PER_GET]))
        if not answer and not answers:
            return {}
        answers.update(answer)
    values = {key: answers.get(f"{UPS_OIDS[key]}.0") for key in keys}
    sys_descr_raw = answers.get(sys_descr_oid)
    return parse_ups_status(
        values,
        _snmp_str(sys_descr_raw) if sys_descr_raw is not None else "",
        await walk(PROBE_TEMPERATURE_OID) or None,
    )


def ups_metric_samples(host_id: int, status: dict[str, Any]) -> list[tuple]:
    """The ``metric_samples`` rows of one UPS poll (host, metric, labels, value)."""
    rows: list[tuple] = []
    for metric, key in UPS_METRICS.items():
        value = status.get(key)
        if value is not None:
            rows.append((host_id, metric, "{}", float(value)))
    return rows


def ups_metric_value(status: dict[str, Any] | None, metric: str) -> float | None:
    """The value of one ``UPS_METRICS`` metric in a poll's UPS state."""
    key = UPS_METRICS.get(metric)
    value = (status or {}).get(key) if key else None
    return float(value) if value is not None else None


def _runtime_text(status: dict[str, Any]) -> str:
    parts = []
    if status.get("battery_capacity_pct") is not None:
        parts.append(f"battery {status['battery_capacity_pct']}%")
    if status.get("runtime_minutes") is not None:
        parts.append(f"{status['runtime_minutes']:g} min runtime left")
    return f" ({', '.join(parts)})" if parts else ""


def ups_alert_checks(status: dict[str, Any]) -> list[dict[str, Any]]:
    """The built-in alerts a UPS state raises, in the shape of the poll's
    built-in checks (``metric``, ``alert_type``, ``message``, ``severity``,
    ``value``, ``threshold``). An empty state raises none."""
    if not status:
        return []
    checks: list[dict[str, Any]] = []
    output = status.get("output_status")
    battery = status.get("battery_status")

    if output in OUTPUT_ON_BATTERY:
        checks.append(
            {
                "metric": ALERT_ON_BATTERY,
                "alert_type": "status",
                "message": f"UPS on battery{_runtime_text(status)}",
                "severity": "critical" if battery == BATTERY_LOW else "warning",
                "value": float(output),
                "threshold": None,
            }
        )

    battery_problems = []
    severity = "warning"
    if battery in BATTERY_PROBLEMS:
        battery_problems.append(f"battery {BATTERY_STATUS_LABELS[battery].lower()}")
        severity = "critical"
    if status.get("battery_needs_replacing"):
        battery_problems.append("battery needs replacing")
    if battery_problems:
        checks.append(
            {
                "metric": ALERT_BATTERY,
                "alert_type": "status",
                "message": "UPS " + ", ".join(battery_problems) + _runtime_text(status),
                "severity": severity,
                "value": float(battery or 0),
                "threshold": None,
            }
        )

    if output in OUTPUT_OFF or output in OUTPUT_BYPASS:
        label = OUTPUT_STATUS_LABELS.get(output, "Unknown")
        off = output in OUTPUT_OFF
        checks.append(
            {
                "metric": ALERT_OUTPUT,
                "alert_type": "status",
                "message": f"UPS output {'off' if off else 'on bypass'}: {label}",
                "severity": "critical" if off or output in OUTPUT_BYPASS_CRITICAL else "warning",
                "value": float(output),
                "threshold": None,
            }
        )

    load = status.get("output_load_pct")
    if load is not None and load >= OUTPUT_OVERLOAD_PCT:
        checks.append(
            {
                "metric": ALERT_OVERLOAD,
                "alert_type": alert_type(ALERT_OVERLOAD),
                "message": f"UPS overloaded: output load {load}% (rated capacity {OUTPUT_OVERLOAD_PCT}%)",
                "severity": "critical",
                "value": float(load),
                "threshold": float(OUTPUT_OVERLOAD_PCT),
            }
        )

    temperature = status.get("battery_temperature_c")
    warning_c, critical_c = BATTERY_TEMPERATURE_C
    if temperature is not None and temperature >= warning_c:
        critical = temperature >= critical_c
        threshold = critical_c if critical else warning_c
        checks.append(
            {
                "metric": ALERT_TEMPERATURE,
                "alert_type": alert_type(ALERT_TEMPERATURE),
                "message": f"UPS battery temperature {temperature:g} °C (threshold {threshold:g} °C)",
                "severity": "critical" if critical else "warning",
                "value": float(temperature),
                "threshold": threshold,
            }
        )
    return checks


def ups_cleared_alerts(status: dict[str, Any], checks: list[dict[str, Any]]) -> list[str]:
    """The built-in UPS alerts a poll's state clears: every poll-evaluated
    alert it did not raise, and the communication alert once the card
    reports a known output state (it is talking to the UPS again). None for
    an empty state (the poll read nothing)."""
    if not status:
        return []
    raised = {check["metric"] for check in checks}
    cleared = [metric for metric in ALERT_METRICS if metric not in raised]
    if status.get("output_status") not in (None, 1):
        cleared.append(ALERT_COMMUNICATION)
    return cleared
