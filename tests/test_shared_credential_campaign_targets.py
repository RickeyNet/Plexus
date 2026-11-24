"""Upgrade campaigns and deployments send a shared credential only to a
confirmed address.

A campaign or deployment that runs with the Plexus service credential or
the app-wide default credential signs in to an inventory host only when its
stored row, read at the time of the run, holds the address as confirmed
(``netcontrol.managed_targets``), whoever runs it. A user's own credential
run by its owner is unaffected (run by someone else, see
``test_personal_credential_deferred_targets.py``). Deployment execute refuses the whole run (409) before any
device is touched; rollback and campaign phases skip the host with the
reason and carry on with the others.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import routes.database as db
from netcontrol.managed_targets import ADDRESS_AWAITING_CONFIRMATION
from netcontrol.routes import deployments, state, upgrades
from routes.crypto import encrypt

import pg_raw
from mcp_helpers import admin_client

CONFIRMED_IP = "192.0.2.51"
UNCONFIRMED_IP = "198.51.100.52"
AD_HOC_IP = "203.0.113.53"
IMAGE_MAP = {"C9200": "cat9k_iosxe.17.15.05.SPA.bin"}


# ── Upgrade campaigns: the per-device gate in _run_phase ─────────────────────


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

    async def fake_prestage(_cid, dev, credentials, _imap, _opts):
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


async def _hosts() -> tuple[int, int]:
    await db.init_db()
    gid = await db.create_group("campaign-targets")
    confirmed = await db.add_host(gid, "core-a", CONFIRMED_IP, address_confirmed=True)
    unconfirmed = await db.add_host(gid, "edge-b", UNCONFIRMED_IP)
    return confirmed, unconfirmed


def _devices(confirmed: int, unconfirmed: int) -> list[dict]:
    return [
        {"id": 1, "host_id": confirmed, "ip_address": CONFIRMED_IP},
        {"id": 2, "host_id": unconfirmed, "ip_address": UNCONFIRMED_IP},
        # Typed into the campaign by its creator or an admin: no host row.
        {"id": 3, "host_id": None, "ip_address": AD_HOC_IP},
    ]


async def _run(devices: list[dict], credential_row: dict | None) -> None:
    await upgrades._run_phase(1, "prestage", devices, {}, [], {"parallel": 2}, credential_row=credential_row)


async def test_shared_credential_skips_an_unconfirmed_host(phase_env):
    confirmed, unconfirmed = await _hosts()
    service = {"id": 900, "is_service": 1}
    await _run(_devices(confirmed, unconfirmed), service)

    assert sorted(phase_env.signed_in) == sorted([CONFIRMED_IP, AD_HOC_IP])
    failed = phase_env.device_updates[2]
    assert failed["prestage_status"] == "failed"
    assert ADDRESS_AWAITING_CONFIRMATION in failed["error_message"]
    assert "Inventory page" in failed["error_message"]
    assert "unreachable" not in failed["error_message"].lower()
    assert 1 not in phase_env.device_updates and 3 not in phase_env.device_updates


async def test_default_credential_counts_as_shared(phase_env, monkeypatch):
    confirmed, unconfirmed = await _hosts()
    monkeypatch.setattr(state, "AUTH_CONFIG", {"default_credential_id": 901})
    await _run(_devices(confirmed, unconfirmed), {"id": 901, "is_service": 0})
    assert UNCONFIRMED_IP not in phase_env.signed_in
    assert ADDRESS_AWAITING_CONFIRMATION in phase_env.device_updates[2]["error_message"]


async def test_users_own_credential_signs_in_everywhere(phase_env):
    confirmed, unconfirmed = await _hosts()
    await _run(_devices(confirmed, unconfirmed), {"id": 902, "is_service": 0})
    assert sorted(phase_env.signed_in) == sorted([CONFIRMED_IP, UNCONFIRMED_IP, AD_HOC_IP])
    assert phase_env.device_updates == {}


async def test_decided_on_the_host_row_at_run_time(phase_env):
    confirmed, unconfirmed = await _hosts()
    service = {"id": 900, "is_service": 1}
    # Confirmed when the campaign was built, re-addressed since: the device
    # still holds the old address, which is no longer the host's.
    await db.update_host(confirmed, "core-a", "192.0.2.99", "cisco_ios", address_confirmed=True)
    await _run([{"id": 1, "host_id": confirmed, "ip_address": CONFIRMED_IP}], service)
    assert phase_env.signed_in == []
    assert "differs" in phase_env.device_updates[1]["error_message"]

    # An admin confirms the unconfirmed host's address: signed in next run.
    await db.confirm_host_addresses([unconfirmed])
    await _run([{"id": 2, "host_id": unconfirmed, "ip_address": UNCONFIRMED_IP}], service)
    assert phase_env.signed_in == [UNCONFIRMED_IP]


async def test_a_device_from_inventory_stays_one_when_its_host_is_deleted(phase_env):
    confirmed, _unconfirmed = await _hosts()
    campaign = await db.create_upgrade_campaign("c-removed", "", {}, {}, "admin")
    await db.add_upgrade_device(campaign, confirmed, CONFIRMED_IP, "core-a")
    await db.add_upgrade_device(campaign, None, AD_HOC_IP, "")
    await db.remove_host(confirmed)

    rows = {r["ip_address"]: dict(r) for r in await pg_raw.fetch("SELECT * FROM upgrade_devices")}
    assert rows[CONFIRMED_IP]["host_id"] is None and rows[CONFIRMED_IP]["from_inventory"] == 1
    assert rows[AD_HOC_IP]["host_id"] is None and rows[AD_HOC_IP]["from_inventory"] == 0

    # With a shared credential the device whose host is gone is not signed
    # in to; the address typed into the campaign is.
    devices = list(rows.values())
    await _run(devices, {"id": 900, "is_service": 1})
    assert phase_env.signed_in == [AD_HOC_IP]
    failed = phase_env.device_updates[rows[CONFIRMED_IP]["id"]]
    assert "no longer exists" in failed["error_message"]

    # A user's own credential reaches both.
    phase_env.signed_in.clear()
    await _run(devices, {"id": 902, "is_service": 0})
    assert sorted(phase_env.signed_in) == sorted([CONFIRMED_IP, AD_HOC_IP])


def test_migration_0135_matches_a_fresh_database():
    migration = importlib.import_module("routes.migrations.0135_add_upgrade_device_from_inventory")

    async def _run_migration() -> tuple[set, set, dict]:
        await db.init_db()
        fresh = set(await pg_raw.table_columns("upgrade_devices"))
        confirmed, _unconfirmed = await _hosts()
        campaign = await db.create_upgrade_campaign("c-migrate", "", {}, {}, "admin")
        await db.add_upgrade_device(campaign, confirmed, CONFIRMED_IP, "core-a")
        await db.add_upgrade_device(campaign, None, AD_HOC_IP, "")
        await pg_raw.execute("ALTER TABLE upgrade_devices DROP COLUMN from_inventory")
        conn = await db.get_db()
        try:
            await migration.up(conn)
            await migration.up(conn)  # re-running is a no-op
        finally:
            await conn.close()
        rows = await pg_raw.fetch("SELECT ip_address, from_inventory FROM upgrade_devices")
        return fresh, set(await pg_raw.table_columns("upgrade_devices")), {r[0]: r[1] for r in rows}

    fresh, migrated, flags = asyncio.run(_run_migration())
    assert fresh == migrated
    # A stored device with a host is from inventory; one without is not.
    assert flags == {CONFIRMED_IP: 1, AD_HOC_IP: 0}


# ── Upgrade campaigns: every run path hands the credential row down ─────────


@pytest.fixture
def api(monkeypatch, request):
    return admin_client(monkeypatch, request)


def test_execute_and_rehydrate_pass_the_credential_row(api, monkeypatch):
    seen: list[dict | None] = []

    async def fake_run_phase(*_a, credential_row=None, **_k):
        seen.append(credential_row)

    async def noop(*_a, **_k):
        return None

    monkeypatch.setattr(upgrades, "NETMIKO_AVAILABLE", True)
    monkeypatch.setattr(upgrades, "_run_phase", fake_run_phase)
    monkeypatch.setattr(upgrades, "_emit", noop)
    service = asyncio.run(db.create_credential("svc-camp", "svc-user", encrypt("pw"), is_service=True))

    r = api.post("/api/upgrades/campaigns", json={"name": "c1", "ad_hoc_ips": [AD_HOC_IP], "image_map": IMAGE_MAP})
    assert r.status_code == 200, r.text
    cid = int(r.json()["id"])
    r = api.post(f"/api/upgrades/campaigns/{cid}/execute", json={"phase": "prestage"})
    assert r.status_code == 200, r.text
    for _ in range(100):
        if seen:
            break
        time.sleep(0.02)
    assert seen and int(seen[0]["id"]) == service

    # A scheduled activate rehydrated after a restart.
    upgrades._running_campaigns.pop(cid, None)
    soon = (datetime.now(UTC) + timedelta(milliseconds=200)).isoformat()

    async def rehydrate():
        await db.update_upgrade_campaign(cid, status="scheduled_activate", scheduled_at=soon)
        await upgrades.rehydrate_scheduled_upgrades()
        await upgrades._running_campaigns[cid]

    asyncio.run(rehydrate())
    assert len(seen) == 2 and int(seen[1]["id"]) == service


# ── Deployments ──────────────────────────────────────────────────────────────


@pytest.fixture
def dep_env(api, monkeypatch):
    started: list[list[str]] = []
    read: list[str] = []

    async def fake_deploy_job(_job_id, _dep_id, hosts, *_a, **_k):
        started.append([h["ip_address"] for h in hosts])

    async def fake_get_device_config(host, _credentials, **_k):
        read.append(host["ip_address"])
        return SimpleNamespace(config_text="hostname example\n")

    monkeypatch.setattr(deployments, "_run_deployment_job", fake_deploy_job)
    monkeypatch.setattr(deployments, "get_device_config", fake_get_device_config)

    async def seed():
        admin = await db.get_user_by_username("admin")
        gid = await db.create_group("deploy-targets")
        confirmed = await db.add_host(gid, "core-a", CONFIRMED_IP, address_confirmed=True)
        unconfirmed = await db.add_host(gid, "edge-b", UNCONFIRMED_IP)
        service = await db.create_credential("svc-dep", "svc", encrypt("pw"), is_service=True)
        own = await db.create_credential("own-dep", "me", encrypt("pw"), owner_id=admin["id"])
        return gid, confirmed, unconfirmed, service, own

    gid, confirmed, unconfirmed, service, own = asyncio.run(seed())

    def deployment(credential: int, host_ids: list[int], status: str = "planning") -> int:
        async def make():
            dep = await db.create_deployment(
                name="d",
                group_id=gid,
                credential_id=credential,
                proposed_commands="ntp server 192.0.2.1",
                host_ids=json.dumps(host_ids),
                created_by="admin",
            )
            if status != "planning":
                await db.update_deployment_status(dep, status)
            for host in host_ids:
                await db.create_deployment_snapshot(dep, host, "pre", "hostname example\n")
            return dep

        return asyncio.run(make())

    return SimpleNamespace(
        api=api,
        started=started,
        read=read,
        deployment=deployment,
        confirmed=confirmed,
        unconfirmed=unconfirmed,
        service=service,
        own=own,
    )


def test_execute_refuses_a_shared_credential_run_with_an_unconfirmed_host(dep_env):
    dep = dep_env.deployment(dep_env.service, [dep_env.confirmed, dep_env.unconfirmed])
    r = dep_env.api.post(f"/api/deployments/{dep}/execute")
    assert r.status_code == 409, r.text
    message = r.json()["error"]["message"]
    assert ADDRESS_AWAITING_CONFIRMATION in message
    assert "edge-b" in message and "core-a" not in message
    assert "Inventory page" in message
    assert dep_env.started == [] and dep_env.read == []
    assert asyncio.run(db.get_deployment(dep))["status"] == "planning"


def test_execute_runs_on_confirmed_hosts_or_with_an_own_credential(dep_env):
    dep = dep_env.deployment(dep_env.service, [dep_env.confirmed])
    assert dep_env.api.post(f"/api/deployments/{dep}/execute").status_code == 200
    dep = dep_env.deployment(dep_env.own, [dep_env.confirmed, dep_env.unconfirmed])
    assert dep_env.api.post(f"/api/deployments/{dep}/execute").status_code == 200
    for _ in range(100):
        if len(dep_env.started) == 2:
            break
        time.sleep(0.02)
    assert sorted(map(sorted, dep_env.started)) == [[CONFIRMED_IP], sorted([CONFIRMED_IP, UNCONFIRMED_IP])]


def _rollback(dep_env, dep: int) -> list[dict]:
    r = dep_env.api.post(f"/api/deployments/{dep}/rollback")
    assert r.status_code == 200, r.text
    job_id = r.json()["job_id"]
    for _ in range(200):
        if deployments._deployment_jobs[job_id]["status"] != "running":
            break
        time.sleep(0.02)
    checkpoints = asyncio.run(db.get_deployment_checkpoints(dep))
    return [c for c in checkpoints if c["phase"] == "rollback"]


def test_rollback_skips_an_unconfirmed_host_and_rolls_back_the_others(dep_env):
    dep = dep_env.deployment(dep_env.service, [dep_env.confirmed, dep_env.unconfirmed], status="completed")
    by_host = {c["host_id"]: c for c in _rollback(dep_env, dep)}
    assert dep_env.read == [CONFIRMED_IP]
    assert by_host[dep_env.confirmed]["status"] == "passed"
    skipped = by_host[dep_env.unconfirmed]
    assert skipped["status"] == "failed"
    assert ADDRESS_AWAITING_CONFIRMATION in json.loads(skipped["result"])["error"]
    assert asyncio.run(db.get_deployment(dep))["rollback_status"] == "failed"


def test_rollback_with_an_own_credential_reaches_every_host(dep_env):
    dep = dep_env.deployment(dep_env.own, [dep_env.confirmed, dep_env.unconfirmed], status="completed")
    statuses = {c["host_id"]: c["status"] for c in _rollback(dep_env, dep)}
    assert sorted(dep_env.read) == sorted([CONFIRMED_IP, UNCONFIRMED_IP])
    assert statuses == {dep_env.confirmed: "passed", dep_env.unconfirmed: "passed"}
