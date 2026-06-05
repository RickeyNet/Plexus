from __future__ import annotations

import pytest
import routes.database as db_module
from netcontrol.routes import upgrades


class _FakeCursor:
    lastrowid = 123

    async def fetchone(self):
        return None

    async def fetchall(self):
        return []


class _FakeDb:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple]] = []
        self.commits = 0
        self.closed = False

    async def execute(self, sql, params=()):
        self.executed.append((sql, tuple(params)))
        return _FakeCursor()

    async def commit(self):
        self.commits += 1

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_update_upgrade_campaign_persists_scheduled_at(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeDb()

    async def fake_get_db():
        return fake

    monkeypatch.setattr(db_module, "get_db", fake_get_db)

    ok = await db_module.update_upgrade_campaign(
        7,
        status="scheduled_activate",
        scheduled_at="2026-06-06T01:00:00+00:00",
    )

    assert ok is True
    sql, params = fake.executed[0]
    assert "scheduled_at = ?" in sql
    assert params == (
        "scheduled_activate",
        "2026-06-06T01:00:00+00:00",
        7,
    )
    assert fake.commits == 1
    assert fake.closed is True


@pytest.mark.asyncio
async def test_run_phase_updates_operation_with_terminal_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    devices = [{"id": 10, "ip_address": "10.0.0.10", "activate_status": "pending"}]
    final_devices = [
        {"id": 10, "activate_status": "completed"},
        {"id": 11, "activate_status": "failed"},
        {"id": 12, "activate_status": "cancelled"},
    ]
    operation_updates: list[dict] = []
    campaign_updates: list[dict] = []

    async def fake_emit(*_args, **_kwargs):
        return None

    async def fake_broadcast(*_args, **_kwargs):
        return None

    async def fake_get_upgrade_device(_device_id):
        return {"id": 10, "activate_status": "pending"}

    async def fake_get_upgrade_devices(_campaign_id):
        return final_devices

    async def fake_update_upgrade_campaign(_campaign_id, **kwargs):
        campaign_updates.append(kwargs)

    async def fake_update_upgrade_operation(_operation_id, **kwargs):
        operation_updates.append(kwargs)

    async def fake_device_activate(*_args, **_kwargs):
        return None

    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    monkeypatch.setattr(upgrades, "_broadcast_upgrade_event", fake_broadcast)
    monkeypatch.setattr(upgrades, "_device_activate", fake_device_activate)
    monkeypatch.setattr(upgrades.db, "get_upgrade_device", fake_get_upgrade_device)
    monkeypatch.setattr(upgrades.db, "get_upgrade_devices", fake_get_upgrade_devices)
    monkeypatch.setattr(upgrades.db, "update_upgrade_campaign", fake_update_upgrade_campaign)
    monkeypatch.setattr(upgrades.db, "update_upgrade_operation", fake_update_upgrade_operation)

    await upgrades._run_phase(
        campaign_id=1,
        phase="activate",
        devices=devices,
        credentials={},
        image_map=[],
        options={"parallel": 1},
        operation_id=99,
    )

    assert campaign_updates == [{"status": "activate_partial"}]
    assert operation_updates == [
        {
            "status": "activate_partial",
            "device_count": 3,
            "succeeded": 1,
            "failed": 1,
            "cancelled": 1,
            "completed_at": operation_updates[0]["completed_at"],
            "error_message": (
                "Activate phase completed with 1 failed and 1 cancelled device(s)."
            ),
        }
    ]


@pytest.mark.asyncio
async def test_cancel_campaign_marks_running_operation_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeTask:
        def __init__(self) -> None:
            self.cancelled = False

        def cancel(self):
            self.cancelled = True

    task = FakeTask()
    operation_updates: list[dict] = []

    async def fake_update_upgrade_campaign(_campaign_id, **_kwargs):
        return True

    async def fake_update_upgrade_operation(_operation_id, **kwargs):
        operation_updates.append(kwargs)
        return True

    async def fake_emit(*_args, **_kwargs):
        return None

    async def fake_broadcast(*_args, **_kwargs):
        return None

    monkeypatch.setattr(upgrades, "_running_campaigns", {5: task})
    monkeypatch.setattr(upgrades, "_running_campaign_operations", {5: 44})
    monkeypatch.setattr(upgrades.db, "update_upgrade_campaign", fake_update_upgrade_campaign)
    monkeypatch.setattr(upgrades.db, "update_upgrade_operation", fake_update_upgrade_operation)
    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    monkeypatch.setattr(upgrades, "_broadcast_upgrade_event", fake_broadcast)

    result = await upgrades.cancel_campaign(5, request=None)

    assert result == {"ok": True}
    assert task.cancelled is True
    assert operation_updates == [
        {
            "status": "cancelled",
            "completed_at": operation_updates[0]["completed_at"],
            "error_message": "Campaign phase cancelled by user",
        }
    ]
