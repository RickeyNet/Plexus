"""A device that passed its upgrade shares the version it now runs.

The upgrade tool keeps the running version on its own campaign row, but the
record the Inventory page, the software tracker and its alerts read is the
inventory host. These tests pin the hand-over: a verified device writes its
host (an APC UPS is polled instead, its UPS firmware lives in the monitoring
state), viewers of the campaign are told so they refetch, an ad-hoc address
is left alone, and a failure of the hand-over never fails the upgrade.
"""

from __future__ import annotations

import netcontrol.routes.monitoring as monitoring_routes
import netcontrol.routes.software as software_routes
import pytest
from netcontrol.routes import upgrades


class _Shared:
    def __init__(self) -> None:
        self.device: dict | None = {"id": 7, "campaign_id": 1, "host_id": 3, "ip_address": "192.0.2.10"}
        self.device_type = "cisco_xe"
        self.host_changed = True
        self.poll_result: dict = {"enabled": True, "hosts_polled": 1}
        self.record_error: Exception | None = None
        self.recorded: list[tuple[int, str]] = []
        self.polled: list[int] = []
        self.refreshes = 0
        self.broadcasts: list[dict] = []
        self.messages: list[tuple[str, str]] = []


@pytest.fixture
def shared(monkeypatch: pytest.MonkeyPatch) -> _Shared:
    s = _Shared()

    async def fake_get_device(device_id):
        return dict(s.device) if s.device else None

    async def fake_resolve_device_type(_dev):
        return s.device_type

    async def fake_record(host_id, version):
        if s.record_error:
            raise s.record_error
        s.recorded.append((host_id, version))
        return s.host_changed

    async def fake_poll(host_id):
        s.polled.append(host_id)
        return s.poll_result

    async def fake_refresh():
        s.refreshes += 1

    async def fake_broadcast(campaign_id, event):
        s.broadcasts.append(event)

    async def fake_emit(campaign_id, device_id, level, message, host=""):
        s.messages.append((level, message))

    monkeypatch.setattr(upgrades.db, "get_upgrade_device", fake_get_device)
    monkeypatch.setattr(upgrades, "_resolve_device_type", fake_resolve_device_type)
    monkeypatch.setattr(software_routes, "record_host_version", fake_record)
    monkeypatch.setattr(software_routes, "refresh_after_collection", fake_refresh)
    monkeypatch.setattr(monitoring_routes, "poll_host_now", fake_poll)
    monkeypatch.setattr(upgrades, "_broadcast_upgrade_event", fake_broadcast)
    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    return s


@pytest.mark.asyncio
async def test_a_verified_switch_writes_its_inventory_host_and_tells_the_viewers(shared: _Shared) -> None:
    await upgrades._share_running_version(1, 7, "17.12.3")

    assert shared.recorded == [(3, "17.12.3")]
    assert shared.polled == []
    assert shared.broadcasts == [{"type": "inventory_updated", "campaign_id": 1, "device_id": 7, "host_id": 3}]
    assert any(level == "info" and "17.12.3" in message for level, message in shared.messages)


@pytest.mark.asyncio
async def test_a_host_already_on_that_version_is_not_announced(shared: _Shared) -> None:
    shared.host_changed = False

    await upgrades._share_running_version(1, 7, "17.12.3")

    assert shared.recorded == [(3, "17.12.3")]
    assert shared.broadcasts == [] and shared.messages == []


@pytest.mark.asyncio
async def test_an_ad_hoc_address_has_no_host_to_update(shared: _Shared) -> None:
    assert shared.device is not None
    shared.device["host_id"] = None

    await upgrades._share_running_version(1, 7, "17.12.3")

    assert shared.recorded == [] and shared.polled == [] and shared.broadcasts == []


@pytest.mark.asyncio
async def test_a_ups_is_polled_because_its_host_version_is_the_card_firmware(shared: _Shared) -> None:
    shared.device_type = "apc_ups"

    await upgrades._share_running_version(1, 7, "15.0")

    assert shared.polled == [3]
    assert shared.recorded == [], "the UPS firmware must not overwrite the card firmware on the host"
    assert shared.refreshes == 1
    assert [event["type"] for event in shared.broadcasts] == ["inventory_updated"]


@pytest.mark.asyncio
async def test_a_ups_with_monitoring_off_changes_nothing(shared: _Shared) -> None:
    shared.device_type = "apc_ups"
    shared.poll_result = {"enabled": False, "hosts_polled": 0}

    await upgrades._share_running_version(1, 7, "15.0")

    assert shared.polled == [3]
    assert shared.refreshes == 0 and shared.broadcasts == []


@pytest.mark.asyncio
async def test_a_failed_hand_over_does_not_fail_the_upgrade(shared: _Shared) -> None:
    shared.record_error = RuntimeError("database is away")

    await upgrades._share_running_version(1, 7, "17.12.3")

    assert shared.broadcasts == [] and shared.messages == []


@pytest.mark.asyncio
async def test_marking_a_device_on_target_shares_its_version(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    shared_versions: list[tuple[int, int, str]] = []

    async def fake_update(device_id, **fields):
        order.append("stored")

    async def fake_status(campaign_id, device_id, **statuses):
        order.append("status")

    async def fake_share(campaign_id, device_id, running_version):
        order.append("shared")
        shared_versions.append((campaign_id, device_id, running_version))

    monkeypatch.setattr(upgrades.db, "update_upgrade_device", fake_update)
    monkeypatch.setattr(upgrades, "_emit_device_status", fake_status)
    monkeypatch.setattr(upgrades, "_share_running_version", fake_share)

    await upgrades._mark_device_on_target_version(1, 7, "17.12.3")

    assert shared_versions == [(1, 7, "17.12.3")]
    # The campaign row and its checkmarks first: sharing is the slower step.
    assert order == ["stored", "status", "shared"]
