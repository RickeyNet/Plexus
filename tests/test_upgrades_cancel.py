from __future__ import annotations

from starlette.requests import Request
import pytest

from netcontrol.routes import upgrades


def test_all_cancelled_phase_derives_cancelled_campaign_status() -> None:
    devices = [
        {"activate_status": "cancelled"},
        {"activate_status": "cancelled"},
    ]

    assert upgrades._derive_stale_phase_status("activate", devices) == "cancelled"


def test_all_failed_phase_derives_failed_campaign_status() -> None:
    devices = [
        {"activate_status": "failed"},
        {"activate_status": "failed"},
    ]

    assert upgrades._derive_stale_phase_status("activate", devices) == "activate_failed"


@pytest.mark.asyncio
async def test_run_phase_skips_devices_cancelled_before_worker_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    dev = {
        "id": 10,
        "ip_address": "10.0.0.10",
        "activate_status": "cancelled",
    }
    campaign_updates: list[str] = []

    async def fake_emit(*_args, **_kwargs):
        return None

    async def fake_broadcast(*_args, **_kwargs):
        return None

    async def fake_get_upgrade_device(_device_id):
        return dev

    async def fake_get_upgrade_devices(_campaign_id):
        return [dev]

    async def fake_update_upgrade_campaign(_campaign_id, **kwargs):
        campaign_updates.append(kwargs["status"])

    async def fake_device_activate(*_args, **_kwargs):
        raise AssertionError("cancelled device should not activate")

    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    monkeypatch.setattr(upgrades, "_broadcast_upgrade_event", fake_broadcast)
    monkeypatch.setattr(upgrades.db, "get_upgrade_device", fake_get_upgrade_device)
    monkeypatch.setattr(upgrades.db, "get_upgrade_devices", fake_get_upgrade_devices)
    monkeypatch.setattr(upgrades.db, "update_upgrade_campaign", fake_update_upgrade_campaign)
    monkeypatch.setattr(upgrades, "_device_activate", fake_device_activate)

    await upgrades._run_phase(
        campaign_id=1,
        phase="activate",
        devices=[dev],
        credentials={},
        image_map=[],
        options={"parallel": 1},
    )

    assert campaign_updates == ["cancelled"]


@pytest.mark.asyncio
async def test_cancel_campaign_devices_marks_selected_activate_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    devices = [
        {
            "id": 10,
            "campaign_id": 1,
            "ip_address": "10.0.0.10",
            "activate_status": "running",
        },
        {
            "id": 11,
            "campaign_id": 1,
            "ip_address": "10.0.0.11",
            "activate_status": "completed",
        },
    ]
    device_updates: list[tuple[int, dict]] = []
    campaign_updates: list[str] = []

    monkeypatch.setattr(upgrades, "_get_session", lambda _request: {"user": "alice"})

    async def fake_get_upgrade_campaign(_campaign_id):
        return {"id": 1, "status": "running_activate"}

    async def fake_get_upgrade_devices(_campaign_id):
        current = [dict(d) for d in devices]
        for device_id, update in device_updates:
            for dev in current:
                if dev["id"] == device_id:
                    dev.update(update)
        return current

    async def fake_update_upgrade_device(device_id, **kwargs):
        device_updates.append((device_id, kwargs))
        return True

    async def fake_update_upgrade_campaign(_campaign_id, **kwargs):
        campaign_updates.append(kwargs["status"])
        return True

    async def fake_emit(*_args, **_kwargs):
        return None

    async def fake_emit_device_status(*_args, **_kwargs):
        return None

    async def fake_audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(upgrades.db, "get_upgrade_campaign", fake_get_upgrade_campaign)
    monkeypatch.setattr(upgrades.db, "get_upgrade_devices", fake_get_upgrade_devices)
    monkeypatch.setattr(upgrades.db, "update_upgrade_device", fake_update_upgrade_device)
    monkeypatch.setattr(upgrades.db, "update_upgrade_campaign", fake_update_upgrade_campaign)
    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    monkeypatch.setattr(upgrades, "_emit_device_status", fake_emit_device_status)
    monkeypatch.setattr(upgrades, "_audit", fake_audit)
    monkeypatch.setattr(upgrades, "_running_campaigns", {})

    request = Request({"type": "http", "headers": []})
    result = await upgrades.cancel_campaign_devices(
        1,
        upgrades.CampaignDeviceCancelRequest(device_ids=[10], phase="activate"),
        request,
    )

    assert result["cancelled"] == 1
    assert device_updates == [
        (
            10,
            {
                "activate_status": "cancelled",
                "phase": "cancelled",
                "error_message": "Cancelled by alice during activate phase",
            },
        )
    ]
    assert campaign_updates == ["activate_partial"]
