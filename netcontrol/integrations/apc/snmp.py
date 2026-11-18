"""APC Smart-UPS state over SNMP (PowerNet-MIB, enterprise 318).

The monitoring poll reads these scalars from a host of type ``apc_ups``
(``netcontrol/routes/monitoring.py``), stores the result as the host's
vendor status (``host_vendor_status``, shown on the device page), emits the
numbers as metric samples (kept and rolled up like CPU and memory) and
raises the built-in UPS alerts below into ``monitoring_alerts``.

Object identifiers, checked against the PowerNet-MIB text (the ``.0``
instance is returned by walking the object):

  upsBasicIdentModel             1.3.6.1.4.1.318.1.1.1.1.1.1   DisplayString
  upsAdvIdentFirmwareRevision    1.3.6.1.4.1.318.1.1.1.1.2.1   DisplayString
  upsAdvIdentSerialNumber        1.3.6.1.4.1.318.1.1.1.1.2.3   DisplayString
  upsBasicBatteryStatus          1.3.6.1.4.1.318.1.1.1.2.1.1   INTEGER (below)
  upsAdvBatteryCapacity          1.3.6.1.4.1.318.1.1.1.2.2.1   Gauge, percent
  upsAdvBatteryRunTimeRemaining  1.3.6.1.4.1.318.1.1.1.2.2.3   TimeTicks
  upsAdvBatteryReplaceIndicator  1.3.6.1.4.1.318.1.1.1.2.2.4   INTEGER 1 no / 2 yes
  upsBasicOutputStatus           1.3.6.1.4.1.318.1.1.1.4.1.1   INTEGER (below)
  upsAdvOutputLoad               1.3.6.1.4.1.318.1.1.1.4.2.3   Gauge, percent

The card's own firmware is not in PowerNet-MIB: it is the ``PF`` field of
the card's sysDescr (``parse_apc_nmc_sys_descr``), read in the same poll.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from netcontrol.integrations.apc.firmware import DEVICE_TYPE, ups_version
from netcontrol.routes.snmp import _snmp_str, parse_apc_nmc_sys_descr

# The kind of the vendor status row (``host_vendor_status.kind``).
STATUS_KIND = DEVICE_TYPE

SYS_DESCR_OID = "1.3.6.1.2.1.1.1"
UPS_OIDS: dict[str, str] = {
    "model": "1.3.6.1.4.1.318.1.1.1.1.1.1",  # upsBasicIdentModel
    "firmware": "1.3.6.1.4.1.318.1.1.1.1.2.1",  # upsAdvIdentFirmwareRevision
    "serial": "1.3.6.1.4.1.318.1.1.1.1.2.3",  # upsAdvIdentSerialNumber
    "battery_status": "1.3.6.1.4.1.318.1.1.1.2.1.1",  # upsBasicBatteryStatus
    "battery_capacity": "1.3.6.1.4.1.318.1.1.1.2.2.1",  # upsAdvBatteryCapacity
    "runtime": "1.3.6.1.4.1.318.1.1.1.2.2.3",  # upsAdvBatteryRunTimeRemaining
    "battery_replace": "1.3.6.1.4.1.318.1.1.1.2.2.4",  # upsAdvBatteryReplaceIndicator
    "output_status": "1.3.6.1.4.1.318.1.1.1.4.1.1",  # upsBasicOutputStatus
    "output_load": "1.3.6.1.4.1.318.1.1.1.4.2.3",  # upsAdvOutputLoad
}

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
}

# Built-in alerts: one metric per condition, deduplicated per host like the
# other built-in checks and resolved when the condition clears.
ALERT_ON_BATTERY = "ups_on_battery"
ALERT_BATTERY = "ups_battery"
ALERT_OUTPUT = "ups_output"
ALERT_METRICS = (ALERT_ON_BATTERY, ALERT_BATTERY, ALERT_OUTPUT)


def _int(raw: Any) -> int | None:
    text = _snmp_str(raw) if raw is not None else ""
    try:
        return int(text)
    except TypeError, ValueError:
        return None


def _first(rows: dict | None) -> Any:
    """The value of a walked scalar (its one ``.0`` row), None when absent."""
    return next(iter(rows.values()), None) if rows else None


def parse_ups_status(values: dict[str, Any], sys_descr: str = "") -> dict[str, Any]:
    """The UPS state from the walked objects (``UPS_OIDS`` key -> raw value)
    and the card's sysDescr. ``{}`` when the device answered none of the
    PowerNet objects (not an APC UPS card, or SNMP did not answer)."""
    if not any(values.get(key) is not None and _snmp_str(values[key]) for key in UPS_OIDS):
        return {}
    output = _int(values.get("output_status"))
    battery = _int(values.get("battery_status"))
    ticks = _int(values.get("runtime"))
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
    }
    status.update(parse_apc_nmc_sys_descr(sys_descr))
    return status


async def read_ups_status(walk: Callable[[str], Awaitable[dict]]) -> dict[str, Any]:
    """Read and parse the UPS state with ``walk(oid) -> {oid: value}`` (the
    monitoring poll's SNMP walk). ``{}`` when nothing answered."""
    keys = list(UPS_OIDS)
    results = await asyncio.gather(*(walk(UPS_OIDS[key]) for key in keys), walk(SYS_DESCR_OID))
    values = {key: _first(rows) for key, rows in zip(keys, results[:-1])}
    sys_descr_raw = _first(results[-1])
    return parse_ups_status(values, _snmp_str(sys_descr_raw) if sys_descr_raw is not None else "")


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
    return checks
