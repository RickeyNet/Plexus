"""OPNsense health in the monitoring poll: metric samples and built-in alerts.

The monitoring poll of an inventory host that is an OPNsense firewall
collected as a topology source reads the firewall's health over its API
(``netcontrol.routes.opnsense_health``) and keeps it in the poll result as
``opnsense_health`` (``normalize.health_summary``). This module turns that
into what the poll stores and evaluates, the way ``apc.snmp`` does for a
UPS: the metric samples (``FIREWALL_METRICS``, which user alert rules may
also name), and the built-in alerts for a nearly full file system and a
state table near its limit (``DISK_FULL_PCT``, ``STATE_TABLE_FULL_PCT``),
resolved when the condition clears. CPU, memory and uptime go into the
poll's own fields, so the built-in CPU and memory thresholds and the
device charts work as for an SNMP host. Pure: no database, no network.
"""

from __future__ import annotations

from typing import Any

from netcontrol.integrations.opnsense.normalize import DISK_FULL_PCT, STATE_TABLE_FULL_PCT

# The metric samples the poll emits for a firewall (and that user alert rules
# may name), with the ``health_summary`` key each one is read from.
FIREWALL_METRICS: dict[str, str] = {
    "fw_disk_used_pct": "disk_percent",
    "fw_temperature_c": "temperature_c",
    "fw_pf_states": "pf_states",
    "fw_pf_states_pct": "pf_states_percent",
    "fw_load_avg_1m": "load_1",
}

# Built-in alerts: one metric per condition, deduplicated per host like the
# poll's other built-in checks and resolved when the condition clears.
ALERT_DISK_FULL = "fw_disk_full"
ALERT_STATE_TABLE = "fw_state_table"
ALERT_METRICS = (ALERT_DISK_FULL, ALERT_STATE_TABLE)


def alert_dedup_key(host_id: int, metric: str) -> str:
    """The dedup key of a built-in firewall alert, the one the poll's
    built-in checks use (``host:metric:alert_type``)."""
    return f"{host_id}:{metric}:threshold"


def _values(health: dict[str, Any]) -> dict[str, Any]:
    load = health.get("load_avg") or []
    return {**health, "load_1": load[0] if load else None}


def firewall_metric_samples(host_id: int, health: dict[str, Any]) -> list[tuple]:
    """The ``metric_samples`` rows of one poll's firewall health (host,
    metric, labels, value)."""
    values = _values(health or {})
    return [
        (host_id, metric, "{}", float(values[key]))
        for metric, key in FIREWALL_METRICS.items()
        if values.get(key) is not None
    ]


def firewall_metric_value(health: dict[str, Any] | None, metric: str) -> float | None:
    """The value of one ``FIREWALL_METRICS`` metric in a poll's firewall health."""
    key = FIREWALL_METRICS.get(metric)
    value = _values(health or {}).get(key) if key else None
    return float(value) if value is not None else None


def _check(metric: str, message: str, value: float, levels: tuple[float, float]) -> dict[str, Any]:
    warning, critical = levels
    return {
        "metric": metric,
        "alert_type": "threshold",
        "message": message,
        "severity": "critical" if value >= critical else "warning",
        "value": float(value),
        "threshold": critical if value >= critical else warning,
    }


def firewall_alert_checks(health: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The built-in alerts a firewall's health raises, in the shape of the
    poll's built-in checks (``metric``, ``alert_type``, ``message``,
    ``severity``, ``value``, ``threshold``). An empty health raises none."""
    if not health:
        return []
    checks: list[dict[str, Any]] = []
    disk = health.get("disk_percent")
    if disk is not None and disk >= DISK_FULL_PCT[0]:
        full = [
            f"{d.get('mountpoint')} {d.get('used_pct'):g}%"
            for d in health.get("disks") or []
            if isinstance(d, dict) and d.get("used_pct") is not None and d["used_pct"] >= DISK_FULL_PCT[0]
        ]
        checks.append(
            _check(
                ALERT_DISK_FULL,
                f"File system nearly full: {', '.join(full) or f'{disk:g}%'} (threshold {DISK_FULL_PCT[0]:g}%)",
                disk,
                DISK_FULL_PCT,
            )
        )
    states = health.get("pf_states_percent")
    if states is not None and states >= STATE_TABLE_FULL_PCT[0]:
        checks.append(
            _check(
                ALERT_STATE_TABLE,
                f"State table near its limit: {health.get('pf_states') or 0:.0f} of "
                f"{health.get('pf_states_limit') or 0:.0f} states ({states:g}%, threshold "
                f"{STATE_TABLE_FULL_PCT[0]:g}%)",
                states,
                STATE_TABLE_FULL_PCT,
            )
        )
    return checks


def firewall_cleared_alerts(health: dict[str, Any] | None, checks: list[dict[str, Any]]) -> list[str]:
    """The built-in firewall alerts a poll clears: each one whose value was
    read and is below its threshold now. None when the value was not read
    (a failed call says nothing about the disk)."""
    if not health:
        return []
    raised = {check["metric"] for check in checks}
    read = {ALERT_DISK_FULL: health.get("disk_percent"), ALERT_STATE_TABLE: health.get("pf_states_percent")}
    return [metric for metric in ALERT_METRICS if metric not in raised and read[metric] is not None]
