"""What a forged syslog message can still do once its source passed the
allowlist: a clear message resolves only an alert syslog itself raised for
the same host (never one raised by polling), and configuration-change
messages start at most one backup session per host per cooldown and cannot
postpone it forever.

Addresses are from the documentation ranges.
"""

from __future__ import annotations

import asyncio
import time

import netcontrol.routes.state as state
import pytest
import routes.database as db
from netcontrol import syslog_rules as sr

DOWN = "%OSPF-5-ADJCHG: Process 1, Nbr 198.51.100.2 on Gi0/1 from FULL to DOWN, Neighbor Down: Dead timer expired"
UP = "%OSPF-5-ADJCHG: Process 1, Nbr 198.51.100.2 on Gi0/1 from LOADING to FULL, Loading Done"


@pytest.fixture
def engine(monkeypatch):
    sr.reset_state()
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    monkeypatch.setattr(
        state,
        "EVENT_RECEIVER_CONFIG",
        {"syslog_alerts": True, "config_change_trigger": False, "repoll_trigger": False},
    )
    yield
    sr.reset_state()


async def _host(name: str, ip: str) -> int:
    await db.init_db()
    group_id = await db.create_group(f"grp-{name}")
    return await db.add_host(group_id, name, ip, "cisco_ios")


async def _open_keys(host_id: int) -> dict[str, str]:
    return {a["dedup_key"]: a["alert_type"] for a in await db.get_monitoring_alerts(host_id, acknowledged=False)}


async def test_a_clear_message_resolves_only_the_syslog_alert_of_its_host(engine):
    host_id = await _host("sw-sp1", "192.0.2.60")
    other_id = await _host("sw-sp2", "192.0.2.61")
    key = sr.dedup_key("ospf_neighbor", host_id, "198.51.100.2")
    # An alert under the same key that polling raised: it stays.
    await db.create_monitoring_alert(
        host_id=host_id,
        poll_id=None,
        alert_type="threshold",
        metric="syslog_ospf_neighbor",
        message="poll",
        dedup_key=key,
    )
    out = await sr.process_syslog_batch([(host_id, UP)])
    assert out["resolved"] == 0
    assert await _open_keys(host_id) == {key: "threshold"}
    await db.resolve_monitoring_alerts(key)
    # A syslog alert under that key on another host: it stays too.
    await db.create_monitoring_alert(
        host_id=other_id, poll_id=None, alert_type="syslog", metric="syslog_ospf_neighbor", message="x", dedup_key=key
    )
    out = await sr.process_syslog_batch([(host_id, UP)])
    assert out["resolved"] == 0
    assert await _open_keys(other_id) == {key: "syslog"}


async def test_a_clear_message_resolves_the_alert_syslog_raised(engine):
    host_id = await _host("sw-sp3", "192.0.2.62")
    assert (await sr.process_syslog_batch([(host_id, DOWN)]))["raised"] == 1
    assert (await sr.process_syslog_batch([(host_id, UP)]))["resolved"] == 1
    assert await _open_keys(host_id) == {}


async def test_resolve_by_key_can_be_limited_to_a_type_and_host():
    host_id = await _host("sw-sp4", "192.0.2.63")
    await db.create_monitoring_alert(
        host_id=host_id, poll_id=None, alert_type="status", metric="m", message="x", dedup_key="k-sp4"
    )
    assert await db.resolve_monitoring_alerts("k-sp4", alert_type="syslog", host_id=host_id) == 0
    assert await db.resolve_monitoring_alerts("k-sp4", alert_type="status", host_id=host_id + 1000) == 0
    assert await db.resolve_monitoring_alerts("k-sp4", alert_type="status", host_id=host_id) == 1
    with pytest.raises(ValueError):
        await db.resolve_monitoring_alerts("k-sp4", alert_type="status")


# ── Configuration-change sessions ────────────────────────────────────────────


@pytest.fixture
def config_runs(monkeypatch):
    sr.reset_state()
    runs: list[tuple[int, float]] = []

    async def fake_run(host_id: int) -> dict:
        runs.append((host_id, time.monotonic()))
        return {}

    monkeypatch.setattr(sr, "run_config_change", fake_run)
    monkeypatch.setattr(sr, "CONFIG_DEBOUNCE_SECONDS", 0.05)
    monkeypatch.setattr(sr, "CONFIG_COOLDOWN_SECONDS", 0.2)
    monkeypatch.setattr(sr, "CONFIG_MAX_DEFER_SECONDS", 0.15)
    yield runs
    for task in list(sr._config_tasks.values()):
        task.cancel()
    sr.reset_state()


async def test_a_message_stream_cannot_postpone_the_backup_forever(config_runs):
    start = time.monotonic()
    # A message every 20 ms would keep moving a 50 ms debounce for ever.
    while time.monotonic() - start < 0.5 and not config_runs:
        sr.note_config_change(71)
        await asyncio.sleep(0.02)
    assert config_runs, "the run never started"
    assert config_runs[0][1] - start < 0.15 + 0.1


async def test_a_flood_of_config_messages_is_one_session_per_cooldown(config_runs):
    start = time.monotonic()
    while time.monotonic() - start < 0.5:
        sr.note_config_change(72)
        await asyncio.sleep(0.01)
    for task in list(sr._config_tasks.values()):
        task.cancel()
    times = [t for h, t in config_runs if h == 72]
    assert 1 <= len(times) <= 3
    assert all(b - a >= sr.CONFIG_COOLDOWN_SECONDS - 0.01 for a, b in zip(times, times[1:], strict=False))


def test_the_per_host_config_state_is_bounded():
    assert sr._config_due.max_entries == sr.COUNTERS_MAX
    assert sr._config_last_run.max_entries == sr.COUNTERS_MAX
