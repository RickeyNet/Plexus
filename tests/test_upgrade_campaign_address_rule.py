"""An upgrade campaign that runs later, or for someone other than its
credential's owner, sends a personal credential only to an address an admin
confirmed or that the owner set.

A campaign records each device's address when it is added, copied from the
inventory host. A phase the credential's owner starts now signs in to every
device, as before. A scheduled phase (including one resumed after a
restart), or a phase someone else starts (an admin, the API token), is
deferred use of the credential (``netcontrol.managed_targets``): a device
whose host address another user wrote is skipped with the reason and the
other devices carry on. An address typed into the campaign is not checked.

Invented data only.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import routes.database as db
from netcontrol.managed_targets import ADDRESS_NOT_SET_BY_OWNER, recorded_address_refusal
from netcontrol.routes import state, upgrades
from routes.crypto import encrypt

from mcp_helpers import admin_client

CONFIRMED_IP = "192.0.2.71"
OWNER_IP = "198.51.100.72"
RETARGETED_IP = "203.0.113.73"
AD_HOC_IP = "203.0.113.74"
IMAGE_MAP = {"C9200": "cat9k_iosxe.17.15.05.SPA.bin"}


# ── The per-device gate in _run_phase ────────────────────────────────────────


@pytest.fixture
def phase_env(monkeypatch):
    """Real hosts rows; the campaign device store and the device phases are
    fakes that record who would have been signed in to."""
    signed_in: list[str] = []
    device_updates: dict[int, dict] = {}

    async def noop(*_a, **_k):
        return None

    async def fake_get_upgrade_device(device_id):
        return {"id": device_id}

    async def fake_get_upgrade_devices(_campaign_id):
        return [{"id": i, **u} for i, u in device_updates.items()]

    async def fake_update_upgrade_device(device_id, **fields):
        device_updates.setdefault(device_id, {}).update(fields)
        return True

    async def fake_prestage(_cid, dev, _credentials, _imap, _opts):
        signed_in.append(dev["ip_address"])

    async def not_ups(_dev):
        return False

    monkeypatch.setattr(upgrades, "_emit", noop)
    monkeypatch.setattr(upgrades, "_emit_device_status", noop)
    monkeypatch.setattr(upgrades, "_broadcast_upgrade_event", noop)
    monkeypatch.setattr(upgrades.db, "get_upgrade_device", fake_get_upgrade_device)
    monkeypatch.setattr(upgrades.db, "get_upgrade_devices", fake_get_upgrade_devices)
    monkeypatch.setattr(upgrades.db, "update_upgrade_device", fake_update_upgrade_device)
    monkeypatch.setattr(upgrades.db, "update_upgrade_campaign", noop)
    monkeypatch.setattr(upgrades.apc_upgrade, "is_ups_device", not_ups)
    monkeypatch.setattr(upgrades, "_device_prestage", fake_prestage)
    monkeypatch.setattr(state, "AUTH_CONFIG", {})
    return SimpleNamespace(signed_in=signed_in, device_updates=device_updates)


async def _seed() -> SimpleNamespace:
    """An owner's personal credential and three inventory hosts: one an
    admin added, one whose address the owner wrote, one whose address
    another user wrote."""
    await db.init_db()
    await db.create_user("camp-owner", "x" * 64, "s" * 16, role="user")
    await db.create_user("camp-other", "x" * 64, "s" * 16, role="user")
    owner = await db.get_user_by_username("camp-owner")
    other = await db.get_user_by_username("camp-other")
    assert owner and other
    cred_id = await db.create_credential("owner-device", "owner-login", encrypt("Owner-Pw-1"), owner_id=owner["id"])
    gid = await db.create_group("campaign-personal")
    confirmed = await db.add_host(gid, "core-a", CONFIRMED_IP, address_confirmed=True)
    owner_set = await db.add_host(gid, "dist-b", OWNER_IP, address_set_by=owner["id"])
    retargeted = await db.add_host(gid, "edge-c", RETARGETED_IP, address_set_by=other["id"])
    return SimpleNamespace(
        cred=await db.get_credential_raw(cred_id),
        devices=[
            {"id": 1, "host_id": confirmed, "ip_address": CONFIRMED_IP},
            {"id": 2, "host_id": owner_set, "ip_address": OWNER_IP},
            {"id": 3, "host_id": retargeted, "ip_address": RETARGETED_IP},
            # Typed into the campaign by its creator or an admin: no host row.
            {"id": 4, "host_id": None, "ip_address": AD_HOC_IP},
        ],
        retargeted=retargeted,
    )


async def _run(devices: list[dict], credential_row: dict, *, deferred: bool) -> None:
    await upgrades._run_phase(
        1, "prestage", devices, {}, [], {"parallel": 2}, credential_row=credential_row, deferred=deferred
    )


async def test_deferred_run_skips_an_address_another_user_wrote(phase_env):
    env = await _seed()
    await _run(env.devices, env.cred, deferred=True)

    assert sorted(phase_env.signed_in) == sorted([CONFIRMED_IP, OWNER_IP, AD_HOC_IP])
    skipped = phase_env.device_updates[3]
    assert skipped["prestage_status"] == "failed"
    assert "personal credential" in skipped["error_message"]
    assert ADDRESS_NOT_SET_BY_OWNER in skipped["error_message"]
    assert "Inventory page" in skipped["error_message"]
    assert set(phase_env.device_updates) == {3}


async def test_owner_run_now_signs_in_everywhere(phase_env):
    env = await _seed()
    await _run(env.devices, env.cred, deferred=False)
    assert sorted(phase_env.signed_in) == sorted([CONFIRMED_IP, OWNER_IP, RETARGETED_IP, AD_HOC_IP])
    assert phase_env.device_updates == {}


async def test_deferred_run_is_decided_on_the_host_row_at_run_time(phase_env):
    env = await _seed()
    # An admin confirms the address: signed in on the next run.
    await db.confirm_host_addresses([env.retargeted])
    await _run([env.devices[2]], env.cred, deferred=True)
    assert phase_env.signed_in == [RETARGETED_IP]


async def test_recorded_address_refusal_for_a_personal_credential():
    env = await _seed()
    assert await recorded_address_refusal(env.retargeted, RETARGETED_IP, env.cred) is None
    assert await recorded_address_refusal(env.retargeted, RETARGETED_IP, env.cred, deferred=True) == (
        ADDRESS_NOT_SET_BY_OWNER
    )
    owner_set = env.devices[1]["host_id"]
    assert await recorded_address_refusal(owner_set, OWNER_IP, env.cred, deferred=True) is None
    # The device's recorded address is no longer the host's.
    assert "differs" in (await recorded_address_refusal(owner_set, "198.51.100.99", env.cred, deferred=True) or "")
    assert "no longer exists" in (await recorded_address_refusal(None, OWNER_IP, env.cred, deferred=True) or "")


# ── Every run path says whether the run is deferred ─────────────────────────


@pytest.fixture
def api(monkeypatch, request):
    return admin_client(monkeypatch, request)


@pytest.fixture
def seen_runs(api, monkeypatch):
    seen: list[bool | None] = []

    async def fake_run_phase(*_a, deferred=None, **_k):
        seen.append(deferred)

    async def noop(*_a, **_k):
        return None

    monkeypatch.setattr(upgrades, "NETMIKO_AVAILABLE", True)
    monkeypatch.setattr(upgrades, "_run_phase", fake_run_phase)
    monkeypatch.setattr(upgrades, "_emit", noop)
    return seen


def _wait_for(seen: list, count: int) -> None:
    for _ in range(200):
        if len(seen) >= count:
            return
        time.sleep(0.02)


def _campaign(created_by: str, cred_id: int) -> int:
    async def make() -> int:
        cid = await db.create_upgrade_campaign("c-deferred", "", IMAGE_MAP, {"credential_id": cred_id}, created_by)
        await db.add_upgrade_device(cid, None, AD_HOC_IP, "")
        return cid

    return asyncio.run(make())


def test_the_owner_running_now_is_not_deferred_but_scheduling_is(api, seen_runs):
    async def seed() -> int:
        admin = await db.get_user_by_username("admin")
        assert admin
        return await db.create_credential("admin-own", "admin-login", encrypt("Admin-Pw-1"), owner_id=admin["id"])

    cid = _campaign("admin", asyncio.run(seed()))

    r = api.post(f"/api/upgrades/campaigns/{cid}/execute", json={"phase": "prestage"})
    assert r.status_code == 200, r.text
    _wait_for(seen_runs, 1)
    assert seen_runs == [False]
    upgrades._running_campaigns.pop(cid, None)

    soon = (datetime.now(UTC) + timedelta(milliseconds=200)).isoformat()
    r = api.post(f"/api/upgrades/campaigns/{cid}/execute", json={"phase": "activate", "scheduled_at": soon})
    assert r.status_code == 200, r.text
    _wait_for(seen_runs, 2)
    assert seen_runs == [False, True]
    upgrades._running_campaigns.pop(cid, None)

    # A scheduled activate resumed after a restart.
    later = (datetime.now(UTC) + timedelta(seconds=2)).isoformat()

    async def rehydrate():
        await db.update_upgrade_campaign(cid, status="scheduled_activate", scheduled_at=later)
        await upgrades.rehydrate_scheduled_upgrades()
        await upgrades._running_campaigns[cid]

    asyncio.run(rehydrate())
    assert seen_runs == [False, True, True]


def test_an_admin_running_a_users_campaign_is_deferred(api, seen_runs):
    async def seed() -> int:
        await db.create_user("camp-owner", "x" * 64, "s" * 16, role="user")
        owner = await db.get_user_by_username("camp-owner")
        assert owner
        return await db.create_credential("owner-device", "owner-login", encrypt("Owner-Pw-1"), owner_id=owner["id"])

    cid = _campaign("camp-owner", asyncio.run(seed()))
    r = api.post(f"/api/upgrades/campaigns/{cid}/execute", json={"phase": "prestage"})
    assert r.status_code == 200, r.text
    _wait_for(seen_runs, 1)
    assert seen_runs == [True]
