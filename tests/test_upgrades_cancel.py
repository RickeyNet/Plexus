from __future__ import annotations

import asyncio

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


@pytest.mark.asyncio
async def test_execute_phase_resets_cancelled_devices_before_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-running a phase clears a stale 'cancelled' status so the device runs again."""
    device_updates: list[tuple[int, dict]] = []
    run_phase_devices: list[list[dict]] = []

    async def fake_get_upgrade_campaign(_campaign_id):
        return {
            "id": 1,
            "image_map": {"C9200": "cat9k_iosxe.17.15.05.SPA.bin"},
            "options": {"credential_id": 9},
        }

    async def fake_get_credential_raw(_credential_id):
        return {"username": "u", "password": "p", "secret": ""}

    async def fake_get_upgrade_devices(_campaign_id):
        return [
            {"id": 10, "ip_address": "10.0.0.10", "activate_status": "cancelled"},
            {"id": 11, "ip_address": "10.0.0.11", "activate_status": "completed"},
        ]

    async def fake_create_upgrade_operation(*_args, **_kwargs):
        return 77

    async def fake_update_upgrade_device(device_id, **kwargs):
        device_updates.append((device_id, kwargs))
        return True

    async def fake_update_upgrade_campaign(_campaign_id, **_kwargs):
        return None

    async def fake_run_phase(_campaign_id, _phase, devices, *_args, **_kwargs):
        run_phase_devices.append(devices)

    async def fake_emit(*_args, **_kwargs):
        return None

    async def fake_audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(upgrades, "NETMIKO_AVAILABLE", True)
    monkeypatch.setattr(upgrades, "_get_session", lambda _request: {"user": "alice"})
    monkeypatch.setattr(upgrades, "decrypt", lambda value: value)
    monkeypatch.setattr(upgrades.db, "get_upgrade_campaign", fake_get_upgrade_campaign)
    monkeypatch.setattr(upgrades.db, "get_credential_raw", fake_get_credential_raw)
    monkeypatch.setattr(upgrades.db, "get_upgrade_devices", fake_get_upgrade_devices)
    monkeypatch.setattr(upgrades.db, "create_upgrade_operation", fake_create_upgrade_operation)
    monkeypatch.setattr(upgrades.db, "update_upgrade_device", fake_update_upgrade_device)
    monkeypatch.setattr(upgrades.db, "update_upgrade_campaign", fake_update_upgrade_campaign)
    monkeypatch.setattr(upgrades, "_run_phase", fake_run_phase)
    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    monkeypatch.setattr(upgrades, "_audit", fake_audit)
    monkeypatch.setattr(upgrades, "_running_campaigns", {})
    monkeypatch.setattr(upgrades, "_running_campaign_operations", {})

    await upgrades.execute_phase(
        1,
        upgrades.CampaignPhaseRequest(phase="activate"),
        request=None,
    )
    await asyncio.sleep(0)

    # The cancelled device (10) is reset to pending; the completed device (11) is untouched.
    assert (10, {"activate_status": "pending", "error_message": ""}) in device_updates
    assert all(device_id != 11 for device_id, _ in device_updates)

    # The snapshot handed to _run_phase reflects the reset, so the worker won't skip it.
    assert run_phase_devices
    dev10 = next(d for d in run_phase_devices[0] if d["id"] == 10)
    assert dev10["activate_status"] == "pending"
