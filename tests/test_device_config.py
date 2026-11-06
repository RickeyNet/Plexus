"""The shared device configuration capture (``netcontrol.routes.device_config``):
reuse of a recent backup, one stored row per configuration, and one capture
per host at a time."""

from __future__ import annotations

import asyncio

import netcontrol.routes.device_config as device_config
import pytest


class _Store:
    """In-memory stand-in for the config_backups queries the module uses."""

    def __init__(self):
        self.rows: list[dict] = []
        self.checked: list[int] = []
        self.fresh = True  # whether the newest row is within any age limit

    async def get_newest_host_config_backup(self, host_id, max_age_seconds=None):
        rows = [r for r in self.rows if r["host_id"] == host_id]
        if not rows or (max_age_seconds is not None and not self.fresh):
            return None
        return dict(rows[-1])

    async def get_config_backup(self, backup_id):
        return next((dict(r) for r in self.rows if r["id"] == backup_id), None)

    async def mark_config_backup_checked(self, backup_id):
        self.checked.append(backup_id)

    async def create_config_backup(self, *, policy_id, host_id, config_text, config_text_full, **kwargs):
        row = {
            "id": len(self.rows) + 1,
            "host_id": host_id,
            "policy_id": policy_id,
            "config_text": config_text,
            "config_text_full": config_text_full,
            "status": "success",
            **kwargs,
        }
        self.rows.append(row)
        return row["id"]


@pytest.fixture
def store(monkeypatch):
    s = _Store()
    for name in (
        "get_newest_host_config_backup",
        "get_config_backup",
        "mark_config_backup_checked",
        "create_config_backup",
    ):
        monkeypatch.setattr(device_config.db, name, getattr(s, name))
    monkeypatch.setattr(device_config, "_host_locks", {})
    monkeypatch.setattr(device_config, "_last_capture", {})
    return s


def _capture_returning(monkeypatch, configs: list[tuple[str, str]], gate: asyncio.Event | None = None):
    calls: list[int] = []
    started = asyncio.Event()

    async def _capture(host, _credentials):
        calls.append(host["id"])
        started.set()
        if gate is not None:
            await gate.wait()
        return configs[min(len(calls), len(configs)) - 1]

    monkeypatch.setattr(device_config, "_capture_device_configs", _capture)
    return calls, started


_HOST = {"id": 7, "ip_address": "192.0.2.7", "device_type": "cisco_xe"}


@pytest.mark.asyncio
async def test_capture_stores_both_forms_in_one_row(store, monkeypatch):
    calls, _ = _capture_returning(monkeypatch, [("hostname a", "hostname a\nip ssh window-size 8192")])
    got = await device_config.get_device_config(_HOST, {}, capture_method="drift")
    assert calls == [7] and got.created and not got.reused
    assert store.rows[0]["config_text"] == "hostname a"
    assert store.rows[0]["config_text_full"] == "hostname a\nip ssh window-size 8192"
    assert store.rows[0]["capture_method"] == "drift"


@pytest.mark.asyncio
async def test_unchanged_config_marks_the_newest_row_checked(store, monkeypatch):
    _capture_returning(monkeypatch, [("hostname a", "full a")])
    first = await device_config.get_device_config(_HOST, {}, capture_method="scheduled")
    second = await device_config.get_device_config(_HOST, {}, capture_method="scheduled")
    assert len(store.rows) == 1 and store.checked == [first.backup_id]
    assert second.backup_id == first.backup_id and not second.created


@pytest.mark.asyncio
async def test_on_demand_reuses_a_recent_backup_without_a_session(store, monkeypatch):
    calls, _ = _capture_returning(monkeypatch, [("hostname a", "")])
    await device_config.get_device_config(_HOST, {}, capture_method="scheduled")
    got = await device_config.get_device_config(
        _HOST, {}, capture_method="compliance", max_age_seconds=device_config.ON_DEMAND_MAX_AGE_SECONDS
    )
    assert calls == [7] and got.reused and got.config_text == "hostname a"


@pytest.mark.asyncio
async def test_on_demand_reads_the_device_when_the_backup_is_too_old(store, monkeypatch):
    calls, _ = _capture_returning(monkeypatch, [("hostname a", ""), ("hostname b", "")])
    await device_config.get_device_config(_HOST, {}, capture_method="scheduled")
    store.fresh = False
    got = await device_config.get_device_config(_HOST, {}, capture_method="compliance", max_age_seconds=900)
    assert calls == [7, 7] and not got.reused and got.config_text == "hostname b"


@pytest.mark.asyncio
async def test_waiting_callers_share_a_capture_that_started_after_they_asked(store, monkeypatch):
    # A is reading the device when B and C ask. A's read began before they
    # asked, so it may predate a change they care about: B reads again, and
    # C, still waiting, takes B's result instead of a third read.
    gate = asyncio.Event()
    calls, started = _capture_returning(monkeypatch, [("one", ""), ("two", "")], gate)
    a = asyncio.create_task(device_config.get_device_config(_HOST, {}, capture_method="deployment"))
    await started.wait()
    b = asyncio.create_task(device_config.get_device_config(_HOST, {}, capture_method="deployment"))
    c = asyncio.create_task(device_config.get_device_config(_HOST, {}, capture_method="deployment"))
    await asyncio.sleep(0)
    gate.set()
    got_a, got_b, got_c = await asyncio.gather(a, b, c)
    assert calls == [7, 7]
    assert got_a.config_text == "one" and got_b.config_text == "two"
    assert got_c.backup_id == got_b.backup_id and got_c.reused


@pytest.mark.asyncio
async def test_store_device_config_from_an_own_session(store):
    first = await device_config.store_device_config(7, "hostname a", "", capture_method="topology")
    again = await device_config.store_device_config(7, "hostname a", "", capture_method="upgrade")
    changed = await device_config.store_device_config(7, "hostname b", "", capture_method="upgrade")
    assert first.created and not again.created and changed.created
    assert [r["capture_method"] for r in store.rows] == ["topology", "upgrade"]
