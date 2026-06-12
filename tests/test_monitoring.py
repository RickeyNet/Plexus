"""Tests for the monitoring alert pipeline.

Covers the logic layer that runs on every poll cycle:
  * _check_threshold / _metric_value_from_poll / _normalize_channel_ids
    (pure helpers)
  * create_monitoring_alert dedup semantics (bump vs new row, ack resets)
  * is_alert_suppressed scoping (host / group / metric / global / expiry)
  * _evaluate_alerts_for_poll built-in thresholds, rule scoping, suppression
  * _track_availability_from_poll transition recording
  * _run_alert_escalation timeout + per-rule overrides

Endpoint-level tests (auth, HTTP shapes) are a follow-up; this file targets
the background machinery that previously had zero coverage.
"""
from __future__ import annotations

import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from netcontrol.routes.monitoring import (
    _check_threshold,
    _evaluate_alerts_for_poll,
    _metric_value_from_poll,
    _normalize_channel_ids,
    _run_alert_escalation,
    _track_availability_from_poll,
)

# ── Pure helpers (no DB) ─────────────────────────────────────────────────────


@pytest.mark.parametrize("value,op,threshold,expected", [
    (90.0, ">=", 90.0, True),
    (89.9, ">=", 90.0, False),
    (91.0, ">", 90.0, True),
    (90.0, ">", 90.0, False),
    (10.0, "<=", 10.0, True),
    (9.0, "<", 10.0, True),
    (10.0, "<", 10.0, False),
    (5.0, "==", 5.0, True),
    (5.0, "!=", 5.0, False),
    (6.0, "!=", 5.0, True),
])
def test_check_threshold_operators(value, op, threshold, expected):
    assert _check_threshold(value, op, threshold) is expected


def test_check_threshold_none_value_never_triggers():
    assert _check_threshold(None, ">=", 0.0) is False


def test_check_threshold_unknown_operator_never_triggers():
    assert _check_threshold(100.0, "~=", 1.0) is False


def test_metric_value_from_poll_mapping():
    res = {
        "cpu_percent": 42.5,
        "memory_percent": None,
        "if_down_count": 3,
        "vpn_tunnels_down": 1,
        "route_count": 200,
        "if_up_count": 24,
        "uptime_seconds": None,
    }
    assert _metric_value_from_poll(res, "cpu") == 42.5
    assert _metric_value_from_poll(res, "memory") is None
    assert _metric_value_from_poll(res, "interface_down") == 3.0
    assert _metric_value_from_poll(res, "vpn_down") == 1.0
    assert _metric_value_from_poll(res, "route_count") == 200.0
    assert _metric_value_from_poll(res, "if_up") == 24.0
    # uptime None coerces to 0.0 rather than None
    assert _metric_value_from_poll(res, "uptime") == 0.0
    assert _metric_value_from_poll(res, "no_such_metric") is None


@pytest.mark.parametrize("raw,expected", [
    (None, "[]"),
    ("", "[]"),
    ("1,2, 3", '["1", "2", "3"]'),
    ([1, 2], '["1", "2"]'),
    ({"not": "a list"}, "[]"),
    (["  7  ", ""], '["7"]'),
])
def test_normalize_channel_ids(raw, expected):
    assert _normalize_channel_ids(raw) == expected


# ── Shared DB fixture ────────────────────────────────────────────────────────


async def _init_clean_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "monitoring.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    group_id = await db_module.create_group("monitoring-test")
    host_id = await db_module.add_host(group_id, "sw1", "10.0.0.1")
    return group_id, host_id


async def _make_poll(host_id: int) -> int:
    """Insert a real monitoring_polls row; poll_id columns are FK-enforced."""
    return await db_module.create_monitoring_poll(host_id)


def _poll_result(host_id: int, **overrides) -> dict:
    base = {
        "host_id": host_id,
        "poll_status": "ok",
        "cpu_percent": 10.0,
        "memory_percent": 20.0,
        "if_up_count": 2,
        "if_down_count": 0,
        "if_details": [],
        "vpn_tunnels_down": 0,
        "vpn_details": [],
        "route_count": 0,
        "uptime_seconds": 1000,
    }
    base.update(overrides)
    return base


async def _backdate_alert(alert_id: int, minutes: int) -> None:
    conn = await db_module.get_db()
    try:
        await conn.execute(
            "UPDATE monitoring_alerts SET created_at = datetime('now', ?) WHERE id = ?",
            (f"-{minutes} minutes", alert_id),
        )
        await conn.commit()
    finally:
        await conn.close()


# ── Alert dedup ──────────────────────────────────────────────────────────────


async def test_alert_dedup_bumps_existing_unacked(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    first = await db_module.create_monitoring_alert(
        host_id=host_id, poll_id=None, alert_type="threshold", metric="cpu",
        message="cpu 91%", dedup_key=f"{host_id}:cpu:threshold",
    )
    second = await db_module.create_monitoring_alert(
        host_id=host_id, poll_id=None, alert_type="threshold", metric="cpu",
        message="cpu 93%", dedup_key=f"{host_id}:cpu:threshold",
    )
    assert second == first
    alerts = await db_module.get_monitoring_alerts(host_id=host_id)
    assert len(alerts) == 1
    assert alerts[0]["occurrence_count"] == 2
    # Dedup bump carries the newest message forward.
    assert alerts[0]["message"] == "cpu 93%"


async def test_alert_dedup_resets_after_acknowledge(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    key = f"{host_id}:cpu:threshold"
    first = await db_module.create_monitoring_alert(
        host_id=host_id, poll_id=None, alert_type="threshold", metric="cpu",
        message="cpu 91%", dedup_key=key,
    )
    await db_module.acknowledge_monitoring_alert(first, "operator")
    second = await db_module.create_monitoring_alert(
        host_id=host_id, poll_id=None, alert_type="threshold", metric="cpu",
        message="cpu 92%", dedup_key=key,
    )
    assert second != first
    alerts = await db_module.get_monitoring_alerts(host_id=host_id)
    assert len(alerts) == 2


# ── Suppression scoping ──────────────────────────────────────────────────────


async def test_suppression_host_scoped(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    other_host = await db_module.add_host(group_id, "sw2", "10.0.0.2")
    await db_module.create_alert_suppression(
        name="quiet sw1", ends_at="2099-01-01T00:00:00", host_id=host_id,
    )
    assert await db_module.is_alert_suppressed(host_id, "cpu") is True
    assert await db_module.is_alert_suppressed(other_host, "cpu") is False


async def test_suppression_metric_scoped(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    await db_module.create_alert_suppression(
        name="quiet cpu only", ends_at="2099-01-01T00:00:00",
        host_id=host_id, metric="cpu",
    )
    assert await db_module.is_alert_suppressed(host_id, "cpu") is True
    assert await db_module.is_alert_suppressed(host_id, "memory") is False


async def test_suppression_group_scoped(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    await db_module.create_alert_suppression(
        name="quiet group", ends_at="2099-01-01T00:00:00", group_id=group_id,
    )
    assert await db_module.is_alert_suppressed(host_id, "cpu", group_id) is True
    # Without group context the group-scoped suppression does not apply.
    assert await db_module.is_alert_suppressed(host_id, "cpu") is False


async def test_suppression_global_blankets_everything(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    await db_module.create_alert_suppression(
        name="maintenance", ends_at="2099-01-01T00:00:00",
    )
    assert await db_module.is_alert_suppressed(host_id, "cpu", group_id) is True
    assert await db_module.is_alert_suppressed(9999, "anything") is True


async def test_suppression_expired_does_not_apply(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    await db_module.create_alert_suppression(
        name="ended yesterday", ends_at="2000-01-01T00:00:00", host_id=host_id,
    )
    assert await db_module.is_alert_suppressed(host_id, "cpu") is False


async def test_suppression_future_start_does_not_apply(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    await db_module.create_alert_suppression(
        name="next week", ends_at="2099-01-02T00:00:00",
        starts_at="2099-01-01T00:00:00", host_id=host_id,
    )
    assert await db_module.is_alert_suppressed(host_id, "cpu") is False


# ── _evaluate_alerts_for_poll ────────────────────────────────────────────────


async def test_builtin_cpu_threshold_creates_alert(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    monkeypatch.setitem(state.MONITORING_CONFIG, "cpu_threshold", 90)
    res = _poll_result(host_id, cpu_percent=92.0)
    created = await _evaluate_alerts_for_poll(res, poll_id=await _make_poll(host_id), group_id=group_id, rules=[])
    assert created == 1
    alerts = await db_module.get_monitoring_alerts(host_id=host_id)
    assert len(alerts) == 1
    assert alerts[0]["metric"] == "cpu"
    assert alerts[0]["severity"] == "warning"


async def test_builtin_cpu_95_is_critical(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    monkeypatch.setitem(state.MONITORING_CONFIG, "cpu_threshold", 90)
    res = _poll_result(host_id, cpu_percent=97.0)
    await _evaluate_alerts_for_poll(res, poll_id=await _make_poll(host_id), group_id=group_id, rules=[])
    alerts = await db_module.get_monitoring_alerts(host_id=host_id)
    assert alerts[0]["severity"] == "critical"


async def test_builtin_below_threshold_creates_nothing(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    monkeypatch.setitem(state.MONITORING_CONFIG, "cpu_threshold", 90)
    monkeypatch.setitem(state.MONITORING_CONFIG, "memory_threshold", 90)
    res = _poll_result(host_id, cpu_percent=50.0, memory_percent=50.0)
    created = await _evaluate_alerts_for_poll(res, poll_id=await _make_poll(host_id), group_id=group_id, rules=[])
    assert created == 0
    assert await db_module.get_monitoring_alerts(host_id=host_id) == []


async def test_builtin_alert_respects_suppression(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    monkeypatch.setitem(state.MONITORING_CONFIG, "cpu_threshold", 90)
    await db_module.create_alert_suppression(
        name="quiet", ends_at="2099-01-01T00:00:00", host_id=host_id,
    )
    res = _poll_result(host_id, cpu_percent=99.0)
    created = await _evaluate_alerts_for_poll(res, poll_id=await _make_poll(host_id), group_id=group_id, rules=[])
    assert created == 0
    assert await db_module.get_monitoring_alerts(host_id=host_id) == []


async def test_interface_down_builtin_alert(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    res = _poll_result(
        host_id, if_down_count=1,
        if_details=[{"if_index": 1, "name": "Gi0/1", "status": "down"}],
    )
    created = await _evaluate_alerts_for_poll(res, poll_id=await _make_poll(host_id), group_id=group_id, rules=[])
    assert created == 1
    alerts = await db_module.get_monitoring_alerts(host_id=host_id)
    assert alerts[0]["metric"] == "interface_down"
    assert "Gi0/1" in alerts[0]["message"]


def _rule(host_id=None, group_id=None, **overrides) -> dict:
    base = {
        "id": 1, "name": "high route count", "metric": "route_count",
        "operator": ">=", "value": 100.0, "severity": "warning",
        "rule_type": "threshold", "host_id": host_id, "group_id": group_id,
        "channel_ids": "",
    }
    base.update(overrides)
    return base


async def test_user_rule_fires_when_triggered(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    # The alert row FK-references alert_rules, so the rule must really exist.
    rule_id = await db_module.create_alert_rule(
        name="high route count", metric="route_count", operator=">=", value=100.0,
    )
    res = _poll_result(host_id, route_count=150)
    created = await _evaluate_alerts_for_poll(
        res, poll_id=await _make_poll(host_id), group_id=group_id,
        rules=[_rule(id=rule_id)],
    )
    assert created == 1
    alerts = await db_module.get_monitoring_alerts(host_id=host_id)
    assert alerts[0]["rule_id"] == rule_id
    assert alerts[0]["metric"] == "route_count"


async def test_user_rule_scoped_to_other_host_is_skipped(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    res = _poll_result(host_id, route_count=150)
    created = await _evaluate_alerts_for_poll(
        res, poll_id=await _make_poll(host_id), group_id=group_id, rules=[_rule(host_id=host_id + 1)],
    )
    assert created == 0


async def test_user_rule_scoped_to_other_group_is_skipped(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    res = _poll_result(host_id, route_count=150)
    created = await _evaluate_alerts_for_poll(
        res, poll_id=await _make_poll(host_id), group_id=group_id, rules=[_rule(group_id=group_id + 1)],
    )
    assert created == 0


async def test_user_rule_not_triggered_below_threshold(tmp_path, monkeypatch):
    group_id, host_id = await _init_clean_db(tmp_path, monkeypatch)
    res = _poll_result(host_id, route_count=50)
    created = await _evaluate_alerts_for_poll(
        res, poll_id=await _make_poll(host_id), group_id=group_id, rules=[_rule()],
    )
    assert created == 0


# ── Availability transitions ─────────────────────────────────────────────────


async def test_first_poll_records_unknown_to_up(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    await _track_availability_from_poll(_poll_result(host_id), poll_id=await _make_poll(host_id))
    transitions = await db_module.get_availability_transitions(host_id=host_id)
    assert len(transitions) == 1
    assert transitions[0]["old_state"] == "unknown"
    assert transitions[0]["new_state"] == "up"


async def test_steady_state_records_no_transition(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    await _track_availability_from_poll(_poll_result(host_id), poll_id=await _make_poll(host_id))
    await _track_availability_from_poll(_poll_result(host_id), poll_id=await _make_poll(host_id))
    transitions = await db_module.get_availability_transitions(host_id=host_id)
    assert len(transitions) == 1


async def test_host_down_records_up_to_down(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    await _track_availability_from_poll(_poll_result(host_id), poll_id=await _make_poll(host_id))
    await _track_availability_from_poll(
        _poll_result(host_id, poll_status="error"), poll_id=await _make_poll(host_id),
    )
    transitions = await db_module.get_availability_transitions(host_id=host_id)
    states = [(t["old_state"], t["new_state"]) for t in transitions]
    assert ("up", "down") in states


async def test_interface_flap_records_transitions(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    up = _poll_result(host_id, if_details=[{"if_index": 1, "name": "Gi0/1", "status": "up"}])
    down = _poll_result(host_id, if_details=[{"if_index": 1, "name": "Gi0/1", "status": "down"}])
    await _track_availability_from_poll(up, poll_id=await _make_poll(host_id))
    await _track_availability_from_poll(down, poll_id=await _make_poll(host_id))
    transitions = await db_module.get_availability_transitions(
        host_id=host_id, entity_type="interface",
    )
    states = [(t["old_state"], t["new_state"]) for t in transitions]
    assert ("unknown", "up") in states
    assert ("up", "down") in states


# ── Escalation ───────────────────────────────────────────────────────────────


async def test_stale_warning_escalates_to_critical(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    monkeypatch.setitem(state.MONITORING_CONFIG, "escalation_enabled", True)
    monkeypatch.setitem(state.MONITORING_CONFIG, "escalation_after_minutes", 30)
    alert_id = await db_module.create_monitoring_alert(
        host_id=host_id, poll_id=None, alert_type="threshold", metric="cpu",
        message="cpu 91%", severity="warning",
    )
    await _backdate_alert(alert_id, minutes=60)
    escalated = await _run_alert_escalation()
    assert escalated == 1
    alerts = await db_module.get_monitoring_alerts(host_id=host_id)
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["escalated"] == 1


async def test_fresh_warning_is_not_escalated(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    monkeypatch.setitem(state.MONITORING_CONFIG, "escalation_enabled", True)
    monkeypatch.setitem(state.MONITORING_CONFIG, "escalation_after_minutes", 30)
    await db_module.create_monitoring_alert(
        host_id=host_id, poll_id=None, alert_type="threshold", metric="cpu",
        message="cpu 91%", severity="warning",
    )
    assert await _run_alert_escalation() == 0


async def test_acknowledged_alert_is_not_escalated(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    monkeypatch.setitem(state.MONITORING_CONFIG, "escalation_enabled", True)
    monkeypatch.setitem(state.MONITORING_CONFIG, "escalation_after_minutes", 30)
    alert_id = await db_module.create_monitoring_alert(
        host_id=host_id, poll_id=None, alert_type="threshold", metric="cpu",
        message="cpu 91%", severity="warning",
    )
    await _backdate_alert(alert_id, minutes=60)
    await db_module.acknowledge_monitoring_alert(alert_id, "operator")
    assert await _run_alert_escalation() == 0


async def test_escalation_disabled_does_nothing(tmp_path, monkeypatch):
    _, host_id = await _init_clean_db(tmp_path, monkeypatch)
    monkeypatch.setitem(state.MONITORING_CONFIG, "escalation_enabled", False)
    alert_id = await db_module.create_monitoring_alert(
        host_id=host_id, poll_id=None, alert_type="threshold", metric="cpu",
        message="cpu 91%", severity="warning",
    )
    await _backdate_alert(alert_id, minutes=600)
    assert await _run_alert_escalation() == 0
