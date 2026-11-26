"""A scheduled upgrade phase resolves its credential again when its time comes.

A phase scheduled for later is checked against the campaign's credential in
the request that schedules it. Between then and the scheduled time the
account the campaign runs for can be disabled or deleted, lose the admin
role a service credential needs, or lose the credential. The run therefore
resolves the credential a second time as it starts
(``upgrades._start_scheduled_phase``), for the phase scheduled through the
API and for the one resumed after a restart: a refusal records the phase as
failed with the reason and no device is contacted, and a run that goes ahead
signs in with the credential's values as they are then.

Invented data only.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import routes.database as db
from netcontrol.routes import state, upgrades
from routes.crypto import encrypt

from mcp_helpers import admin_client

AD_HOC_IP = "203.0.113.84"
IMAGE_MAP = {"C9200": "cat9k_iosxe.17.15.05.SPA.bin"}
OWNER = "sched-owner"


@pytest.fixture
def runs(monkeypatch):
    """The phase runs that were started, in place of the device work."""
    seen: list[SimpleNamespace] = []

    async def fake_run_phase(
        _cid, phase, _devices, credentials, _imap, _opts, *, operation_id=None, credential_row=None, deferred=False
    ):
        seen.append(SimpleNamespace(phase=phase, login=credentials, row=credential_row, deferred=deferred))

    async def noop(*_a, **_k):
        return None

    monkeypatch.setattr(upgrades, "NETMIKO_AVAILABLE", True)
    monkeypatch.setattr(upgrades, "_run_phase", fake_run_phase)
    monkeypatch.setattr(upgrades, "_emit", noop)
    return seen


async def _seed(*, role: str = "user", own_credential: bool = True) -> SimpleNamespace:
    """A campaign of ``OWNER`` with one device and a scheduled activate.
    ``own_credential``: the campaign names the owner's personal credential;
    otherwise it names none and runs with the service credential."""
    await db.create_user(OWNER, "x" * 64, "s" * 16, role=role)
    owner = await db.get_user_by_username(OWNER)
    assert owner
    if own_credential:
        cred_id = await db.create_credential("owner-device", "owner-login", encrypt("Owner-Pw-1"), owner_id=owner["id"])
        options: dict = {"credential_id": cred_id}
    else:
        cred_id = await db.create_credential("svc-sched", "svc-login", encrypt("Svc-Pw-1"), is_service=True)
        options = {"credential_id": None}
    cid = await db.create_upgrade_campaign("c-sched", "", IMAGE_MAP, options, OWNER)
    await db.add_upgrade_device(cid, None, AD_HOC_IP, "")
    return SimpleNamespace(owner=owner, cred_id=cred_id, cid=cid, options=options)


async def _scheduled_operation(cid: int) -> int:
    return await db.create_upgrade_operation(cid, "activate", "scheduled", requested_by=OWNER, device_count=1)


async def _fire(env: SimpleNamespace, operation_id: int) -> None:
    await upgrades._start_scheduled_phase(
        env.cid,
        "activate",
        await db.get_upgrade_devices(env.cid),
        [],
        env.options,
        operation_id,
        created_by=OWNER,
        started_message="Starting scheduled activate phase now",
    )


async def _state(cid: int) -> tuple[dict, dict]:
    campaign = await db.get_upgrade_campaign(cid)
    operation = await db.get_latest_upgrade_operation(cid, phase="activate")
    assert campaign and operation
    return campaign, operation


def _assert_refused(campaign: dict, operation: dict, reason: str) -> None:
    assert campaign["status"] == "activate_failed"
    assert not campaign.get("scheduled_at")
    assert operation["status"] == "activate_failed"
    assert operation["completed_at"]
    message = operation["error_message"]
    assert "did not run" in message and "No device was contacted" in message
    assert reason in message


# ── The check as the scheduled time comes ───────────────────────────────────


async def test_run_signs_in_with_the_credential_as_it_is_at_run_time(runs, monkeypatch):
    monkeypatch.setattr(state, "AUTH_CONFIG", {})
    await db.init_db()
    env = await _seed()
    operation_id = await _scheduled_operation(env.cid)
    # The password is changed after the phase was scheduled.
    await db.update_credential(env.cred_id, enc_password=encrypt("Rotated-Pw-2"))

    await _fire(env, operation_id)

    assert len(runs) == 1
    assert runs[0].phase == "activate" and runs[0].deferred is True
    assert runs[0].login == {"username": "owner-login", "password": "Rotated-Pw-2", "secret": ""}
    assert int(runs[0].row["id"]) == env.cred_id
    campaign, operation = await _state(env.cid)
    assert campaign["status"] == "running_activate"
    assert operation["status"] == "running" and operation["started_at"]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("disable", "disabled"),
        ("delete_account", "Credential not found"),
        ("delete_credential", "Credential not found"),
    ],
)
async def test_run_is_refused_when_the_owner_can_no_longer_use_the_credential(runs, monkeypatch, change, reason):
    monkeypatch.setattr(state, "AUTH_CONFIG", {})
    await db.init_db()
    env = await _seed()
    operation_id = await _scheduled_operation(env.cid)
    if change == "disable":
        await db.update_user_admin(env.owner["id"], disabled=True)
    elif change == "delete_account":
        await db.delete_user(env.owner["id"])
    else:
        await db.delete_credential(env.cred_id)

    await _fire(env, operation_id)

    assert runs == []
    _assert_refused(*await _state(env.cid), reason)


async def test_service_credential_run_is_refused_once_the_creator_is_no_admin(runs, monkeypatch):
    monkeypatch.setattr(state, "AUTH_CONFIG", {})
    await db.init_db()
    env = await _seed(role="admin", own_credential=False)
    first = await _scheduled_operation(env.cid)
    await _fire(env, first)
    assert len(runs) == 1 and int(runs[0].row["id"]) == env.cred_id

    await db.update_user_admin(env.owner["id"], role="user")
    second = await _scheduled_operation(env.cid)
    await _fire(env, second)

    assert len(runs) == 1
    _assert_refused(*await _state(env.cid), "service credential")


# ── Both scheduled paths go through the check ───────────────────────────────


async def test_activate_resumed_after_a_restart_is_refused_when_the_owner_was_disabled(runs, monkeypatch):
    monkeypatch.setattr(state, "AUTH_CONFIG", {})
    await db.init_db()
    env = await _seed()
    await _scheduled_operation(env.cid)
    soon = (datetime.now(UTC) + timedelta(milliseconds=400)).isoformat()
    await db.update_upgrade_campaign(env.cid, status="scheduled_activate", scheduled_at=soon)

    await upgrades.rehydrate_scheduled_upgrades()
    task = upgrades._running_campaigns[env.cid]
    # Enabled when the server came back up, disabled before the time came.
    await db.update_user_admin(env.owner["id"], disabled=True)
    await task

    assert runs == []
    _assert_refused(*await _state(env.cid), "disabled")


@pytest.fixture
def api(monkeypatch, request):
    return admin_client(monkeypatch, request)


def test_phase_scheduled_through_the_api_is_refused_when_the_owner_was_disabled(api, runs):
    env = asyncio.run(_seed())
    try:
        at = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
        r = api.post(f"/api/upgrades/campaigns/{env.cid}/execute", json={"phase": "activate", "scheduled_at": at})
        assert r.status_code == 200, r.text
        assert r.json()["scheduled"] is True
        asyncio.run(db.update_user_admin(env.owner["id"], disabled=True))

        campaign: dict = {}
        operation: dict = {}
        for _ in range(250):
            campaign, operation = asyncio.run(_state(env.cid))
            if operation["status"] != "scheduled":
                break
            time.sleep(0.02)
        assert runs == []
        _assert_refused(campaign, operation, "disabled")
    finally:
        upgrades._running_campaigns.pop(env.cid, None)
