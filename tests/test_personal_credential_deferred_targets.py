"""A personal credential used for its stored owner goes only to an address
an admin confirmed or that its owner set.

A backup policy, a compliance assignment, a queued job and a deployment
bind the credential of the user who created them and read their targets
from the inventory when they run. When that run is not the owner's own
request (the schedule, a syslog trigger, the job queue, someone else
executing a deployment), the owner did not choose the address the
credential is sent to: a host another user added to the group, or an
address another user wrote, is skipped and reported with the reason, and
the run carries on with the other hosts. ``hosts.address_set_by`` records
the user who last wrote a host's address (``netcontrol.managed_targets``).
"""

from __future__ import annotations

import asyncio
import importlib
import json
import time
from types import SimpleNamespace

import pytest
import routes.database as db
from netcontrol import managed_targets
from netcontrol.managed_targets import ADDRESS_AWAITING_CONFIRMATION, ADDRESS_NOT_SET_BY_OWNER
from netcontrol.routes import compliance, config_backups, deployments, device_config, state
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, register_playbook

import pg_raw
from mcp_helpers import CsrfClient, admin_client, user_client

# The address an admin added (confirmed), one another user wrote later, and
# one the credential's owner wrote.
CONFIRMED_IP = "192.0.2.61"
RETARGETED_IP = "203.0.113.66"
OWNER_IP = "198.51.100.67"
WRITER_FEATURES = ["inventory", "inventory.write"]


@register_playbook
class _DeferredTargetsRecorder(BasePlaybook):
    filename = "deferred_targets_recorder_test.py"
    display_name = "Deferred targets recorder (test)"
    description = "test only"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield LogEvent(level="info", message="ran")


async def _make_user(username: str, role: str = "user") -> dict:
    await db.create_user(username, "x" * 64, "s" * 16, role=role)
    user = await db.get_user_by_username(username)
    assert user is not None
    return user


async def _own_credential(owner: dict, name: str, login: str) -> int:
    return await db.create_credential(name, login, encrypt("Owner-Only-Pw-1"), owner_id=owner["id"])


def _record_device_logins(monkeypatch) -> list[tuple[str, str]]:
    """Stub the SSH capture behind ``device_config.get_device_config`` (the
    address rule in front of it stays real). Returns the ``(address, login)``
    pairs a session would have been opened with."""
    seen: list[tuple[str, str]] = []

    async def fake_capture(host, credentials):
        seen.append((str(host.get("ip_address")), str(credentials.get("username"))))
        return "hostname example\n", "hostname example\n"

    monkeypatch.setattr(device_config, "_capture_device_configs", fake_capture)
    return seen


async def _owner_group() -> tuple[dict, int, int, int]:
    """alice (non-admin) owns a credential; her group holds one host an
    admin added (confirmed). Returns (alice, credential id, group id, host id)."""
    await db.init_db()
    alice = await _make_user("dt-alice")
    cred = await _own_credential(alice, "alice-ssh", "alice-login")
    gid = await db.create_group("dt-branch")
    host = await db.add_host(gid, "dt-sw1", CONFIRMED_IP, address_confirmed=True)
    return alice, cred, gid, host


async def _other_user_adds_host(gid: int) -> int:
    """What an ``inventory.write`` holder who is not an admin stores: an
    address that is not confirmed and was not set by the owner."""
    other = await _make_user("dt-other")
    return await db.add_host(gid, "dt-planted", RETARGETED_IP, address_set_by=other["id"])


async def _error_rows(host_id: int) -> list[str]:
    rows = await pg_raw.fetch("SELECT host_id, status, error_message FROM config_backups")
    return [str(r[2]) for r in rows if int(r[0]) == host_id and r[1] == "error"]


# ── The rule ─────────────────────────────────────────────────────────────────


def test_rule_matrix(monkeypatch):
    monkeypatch.setattr(state, "AUTH_CONFIG", {})
    personal = {"id": 7, "owner_id": 5, "is_service": 0}
    shared = {"id": 8, "owner_id": None, "is_service": 1}
    confirmed = {"address_confirmed": 1, "address_set_by": None}
    by_owner = {"address_confirmed": 0, "address_set_by": 5}
    by_other = {"address_confirmed": 0, "address_set_by": 6}
    by_nobody = {"address_confirmed": 0, "address_set_by": None}

    may = managed_targets.may_send_credential
    # Interactive use by the owner: their credential goes anywhere.
    assert all(may(h, personal) for h in (confirmed, by_owner, by_other, by_nobody))
    # Deferred use: only a confirmed address or one the owner set.
    assert may(confirmed, personal, deferred=True) and may(by_owner, personal, deferred=True)
    assert not may(by_other, personal, deferred=True) and not may(by_nobody, personal, deferred=True)
    # A shared credential: a confirmed address only, either way.
    for deferred in (False, True):
        assert may(confirmed, shared, deferred=deferred)
        assert not may(by_owner, shared, deferred=deferred)
    # Fail closed: an unowned credential or an unknown host.
    assert not may(by_owner, {"id": 9, "owner_id": None}, deferred=True)
    assert not may(None, personal, deferred=True)

    assert managed_targets.send_refusal(by_other, personal, deferred=True).endswith(ADDRESS_NOT_SET_BY_OWNER)
    assert ADDRESS_AWAITING_CONFIRMATION in managed_targets.send_refusal(by_owner, shared)
    assert managed_targets.send_refusal(by_owner, personal, deferred=True) is None

    assert managed_targets.session_owns_credential({"user_id": 5}, personal)
    assert not managed_targets.session_owns_credential({"user_id": 6}, personal)
    assert not managed_targets.session_owns_credential({"user_id": 5, "auth_mode": "token"}, personal)
    assert not managed_targets.session_owns_credential(None, personal)


# ── Scheduled and triggered backups, compliance scans, queued jobs ──────────


async def test_backup_policy_skips_a_host_someone_else_added(monkeypatch):
    seen = _record_device_logins(monkeypatch)
    alice, cred, gid, _host = await _owner_group()
    await db.create_config_backup_policy("dt-nightly", gid, cred, created_by=alice["username"])
    planted = await _other_user_adds_host(gid)

    result = await config_backups._run_config_backups_once()

    assert (CONFIRMED_IP, "alice-login") in seen  # the policy did run
    assert (RETARGETED_IP, "alice-login") not in seen
    assert result["errors"] == 1
    # The skipped host's error row says why.
    assert any(ADDRESS_NOT_SET_BY_OWNER in reason for reason in await _error_rows(planted))


async def test_backup_policy_does_not_follow_an_address_change_by_someone_else(monkeypatch):
    seen = _record_device_logins(monkeypatch)
    alice, cred, gid, host = await _owner_group()
    await db.create_config_backup_policy("dt-nightly", gid, cred, created_by=alice["username"])
    other = await _make_user("dt-other")
    await db.update_host(host, "dt-sw1", RETARGETED_IP, "cisco_ios", address_set_by=other["id"])

    await config_backups._run_config_backups_once()

    assert (RETARGETED_IP, "alice-login") not in seen


async def test_backup_policy_follows_the_owners_own_address_change(monkeypatch):
    seen = _record_device_logins(monkeypatch)
    alice, cred, gid, host = await _owner_group()
    await db.create_config_backup_policy("dt-nightly", gid, cred, created_by=alice["username"])
    # alice re-addresses the host herself (not an admin: not confirmed).
    await db.update_host(host, "dt-sw1", OWNER_IP, "cisco_ios", address_set_by=alice["id"])
    stored = await db.get_host(host)
    assert stored is not None and int(stored["address_confirmed"]) == 0

    await config_backups._run_config_backups_once()

    assert seen == [(OWNER_IP, "alice-login")]


async def test_an_admins_confirmation_clears_the_hold(monkeypatch):
    seen = _record_device_logins(monkeypatch)
    alice, cred, gid, _host = await _owner_group()
    await db.create_config_backup_policy("dt-nightly", gid, cred, created_by=alice["username"])
    planted = await _other_user_adds_host(gid)
    await db.confirm_host_addresses([planted])

    await config_backups._run_config_backups_once()

    assert (RETARGETED_IP, "alice-login") in seen


async def test_run_now_by_the_owner_keeps_reaching_every_host(monkeypatch):
    """The policy's Run Now in the owner's own request is not deferred."""
    seen = _record_device_logins(monkeypatch)
    alice, cred, gid, _host = await _owner_group()
    policy = await db.create_config_backup_policy("dt-nightly", gid, cred, created_by=alice["username"])
    planted = await _other_user_adds_host(gid)
    credential = await db.get_credential_raw(cred)
    host = await db.get_host(planted)
    assert credential is not None and host is not None

    result = await config_backups.backup_host(host, credential, policy_id=policy, capture_method="manual")

    assert result is True and seen == [(RETARGETED_IP, "alice-login")]


async def test_syslog_triggered_backup_skips_a_host_someone_else_added(monkeypatch):
    from netcontrol import syslog_rules

    seen = _record_device_logins(monkeypatch)
    monkeypatch.setattr(state, "CONFIG_DRIFT_CHECK_CONFIG", {"enabled": False})
    alice, cred, gid, _host = await _owner_group()
    await db.create_config_backup_policy("dt-nightly", gid, cred, created_by=alice["username"])
    planted = await _other_user_adds_host(gid)
    own = await db.add_host(gid, "dt-own", OWNER_IP, address_set_by=alice["id"])

    refused = await syslog_rules.run_config_change(planted)
    served = await syslog_rules.run_config_change(own)

    assert refused["backup"] == "failed" and served["backup"] == "stored"
    assert seen == [(OWNER_IP, "alice-login")]
    assert any(ADDRESS_NOT_SET_BY_OWNER in reason for reason in await _error_rows(planted))


async def test_compliance_assignment_skips_a_host_someone_else_added(monkeypatch):
    seen = _record_device_logins(monkeypatch)
    alice, cred, gid, _host = await _owner_group()
    profile = await db.create_compliance_profile("dt-profile", rules=json.dumps([]), created_by="admin")
    await db.create_compliance_assignment(profile, gid, cred, assigned_by=alice["username"])
    planted = await _other_user_adds_host(gid)

    await compliance._run_compliance_check_once(force=True)

    assert (CONFIRMED_IP, "alice-login") in seen
    assert (RETARGETED_IP, "alice-login") not in seen
    rows = await pg_raw.fetch("SELECT host_id, status, findings FROM compliance_scan_results")
    planted_rows = [r for r in rows if int(r[0]) == planted]
    assert planted_rows and planted_rows[0][1] == "error"
    assert ADDRESS_NOT_SET_BY_OWNER in str(planted_rows[0][2])


async def test_queued_job_skips_an_address_written_after_launch(monkeypatch):
    from netcontrol.routes import jobs as jobs_module

    started: list[tuple[list[str], str]] = []

    async def fake_run_job(_job_id, _cls, hosts, credentials, *_a, **_k):
        started.append(([h["ip_address"] for h in hosts], credentials["username"]))

    monkeypatch.setattr(jobs_module, "_run_job", fake_run_job)
    monkeypatch.setattr(jobs_module, "_shutting_down", False)
    monkeypatch.setattr(state, "AUTH_CONFIG", {})

    alice, cred, gid, host = await _owner_group()
    own = await db.add_host(gid, "dt-own", OWNER_IP, address_set_by=alice["id"])
    playbook = await db.create_playbook("dt-recorder", _DeferredTargetsRecorder.filename)
    job = await db.create_job(playbook, gid, cred, None, False, launched_by=alice["username"], host_ids=[host, own])
    # Between launch and the queue starting the job, another user re-addresses a host.
    other = await _make_user("dt-other")
    await db.update_host(host, "dt-sw1", RETARGETED_IP, "cisco_ios", address_set_by=other["id"])

    await jobs_module._process_job_queue_inner()
    for _ in range(50):
        if started:
            break
        await asyncio.sleep(0.01)

    assert started, "the job did not start"
    addresses, login = started[0]
    assert login == "alice-login"
    assert addresses == [OWNER_IP]
    events = await db.get_job_events(job)
    assert any(ADDRESS_NOT_SET_BY_OWNER in str(e.get("message")) and "dt-sw1" in str(e.get("message")) for e in events)


# ── Deployments run by someone other than the credential's owner ────────────


@pytest.fixture
def dep_env(monkeypatch, request):
    api = admin_client(monkeypatch, request)
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
        alice = await _make_user("dt-alice")
        cred = await _own_credential(alice, "alice-dep", "alice-login")
        gid = await db.create_group("dt-deploy")
        confirmed = await db.add_host(gid, "core-a", CONFIRMED_IP, address_confirmed=True)
        return alice, cred, gid, confirmed

    alice, cred, gid, confirmed = asyncio.run(seed())

    def deployment(host_ids: list[int], status: str = "planning") -> int:
        async def make():
            dep = await db.create_deployment(
                name="d",
                group_id=gid,
                credential_id=cred,
                proposed_commands="ntp server 192.0.2.1",
                host_ids=json.dumps(host_ids),
                created_by=alice["username"],
            )
            if status != "planning":
                await db.update_deployment_status(dep, status)
            for host in await db.get_hosts_for_group(gid):
                await db.create_deployment_snapshot(dep, host["id"], "pre", "hostname example\n")
            return dep

        return asyncio.run(make())

    def planted() -> int:
        return asyncio.run(_other_user_adds_host(gid))

    return SimpleNamespace(
        api=api, started=started, read=read, deployment=deployment, planted=planted, confirmed=confirmed
    )


def test_group_targeted_deployment_run_by_someone_else_refuses_a_host_added_later(dep_env):
    dep = dep_env.deployment([])  # the whole group, resolved at execute
    dep_env.planted()
    r = dep_env.api.post(f"/api/deployments/{dep}/execute")
    assert r.status_code == 409, r.text
    message = r.json()["error"]["message"]
    assert ADDRESS_NOT_SET_BY_OWNER in message
    assert "dt-planted" in message and "core-a" not in message
    assert dep_env.started == [] and dep_env.read == []


def test_group_targeted_deployment_run_by_someone_else_reaches_confirmed_hosts(dep_env):
    dep = dep_env.deployment([])
    assert dep_env.api.post(f"/api/deployments/{dep}/execute").status_code == 200
    for _ in range(100):
        if dep_env.started:
            break
        time.sleep(0.02)
    assert dep_env.started == [[CONFIRMED_IP]]


def test_rollback_run_by_someone_else_skips_a_host_added_later(dep_env):
    planted = dep_env.planted()
    dep = dep_env.deployment([], status="completed")
    r = dep_env.api.post(f"/api/deployments/{dep}/rollback")
    assert r.status_code == 200, r.text
    job_id = r.json()["job_id"]
    for _ in range(200):
        if deployments._deployment_jobs[job_id]["status"] != "running":
            break
        time.sleep(0.02)
    checkpoints = [c for c in asyncio.run(db.get_deployment_checkpoints(dep)) if c["phase"] == "rollback"]
    by_host = {c["host_id"]: c for c in checkpoints}
    assert dep_env.read == [CONFIRMED_IP]
    assert by_host[dep_env.confirmed]["status"] == "passed"
    assert by_host[planted]["status"] == "failed"
    assert ADDRESS_NOT_SET_BY_OWNER in json.loads(by_host[planted]["result"])["error"]


# ── Who set the address ──────────────────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _set_by(host_id: int) -> int | None:
    host = asyncio.run(db.get_host(host_id))
    assert host is not None
    return None if host.get("address_set_by") is None else int(host["address_set_by"])


def _user_id(username: str) -> int:
    user = asyncio.run(db.get_user_by_username(username))
    assert user is not None
    return int(user["id"])


def test_host_writes_record_the_user_who_set_the_address(admin):
    r = admin.post("/api/inventory", json={"name": "dt-writers", "description": ""})
    assert r.status_code == 201, r.text
    group = int(r.json()["id"])
    writer = user_client(admin, "dt-writer", features=WRITER_FEATURES)
    other = user_client(admin, "dt-other-writer", features=WRITER_FEATURES)
    writer_id, admin_user_id = _user_id("dt-writer"), _user_id("admin")

    r = writer.post(f"/api/inventory/{group}/hosts", json={"hostname": "edge-a", "ip_address": RETARGETED_IP})
    assert r.status_code == 201, r.text
    host = int(r.json()["id"])
    assert _set_by(host) == writer_id

    r = writer.post(
        f"/api/inventory/{group}/hosts/bulk", json={"hosts": [{"hostname": "edge-b", "ip_address": OWNER_IP}]}
    )
    assert r.status_code == 200, r.text
    assert _set_by(int(r.json()["added"][0]["id"])) == writer_id

    # Another user's edit that keeps the address leaves the writer as it is.
    r = other.put(f"/api/hosts/{host}", json={"hostname": "edge-a2", "ip_address": RETARGETED_IP})
    assert r.status_code == 200, r.text
    assert _set_by(host) == writer_id

    # An admin's new address: confirmed, and recorded as the admin's.
    r = admin.put(f"/api/hosts/{host}", json={"hostname": "edge-a2", "ip_address": CONFIRMED_IP})
    assert r.status_code == 200, r.text
    assert _set_by(host) == admin_user_id

    # A background write with no acting user records nobody.
    async def background_add() -> int:
        return await db.add_host(group, "edge-c", "192.0.2.99")

    assert _set_by(asyncio.run(background_add())) is None


def test_migration_0141_matches_a_fresh_database():
    migration = importlib.import_module("routes.migrations.0141_add_host_address_set_by")

    async def _run() -> tuple[set, set, object]:
        await db.init_db()
        fresh = set(await pg_raw.table_columns("hosts"))
        gid = await db.create_group("dt-migration")
        hid = await db.add_host(gid, "old", CONFIRMED_IP)
        await pg_raw.execute("ALTER TABLE hosts DROP COLUMN address_set_by")
        conn = await db.get_db()
        try:
            await migration.up(conn)
            await migration.up(conn)  # re-running is a no-op
        finally:
            await conn.close()
        host = await db.get_host(hid)
        assert host is not None
        return fresh, set(await pg_raw.table_columns("hosts")), host["address_set_by"]

    fresh, migrated, existing = asyncio.run(_run())
    assert fresh == migrated
    # A host stored before the migration has no recorded writer.
    assert existing is None
