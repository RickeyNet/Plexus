"""A disabled account runs nothing outside its sessions either.

Disabling an account ends its sessions and refuses its tokens
(test_account_disabled.py). The same holds for work that never touches a
session: a ChatOps identity mapped to the account is treated as unmapped,
and work the account queued or scheduled earlier is refused its credential
when it starts, including an admin's use of the service credential.

Invented data only: documentation address ranges, made-up names.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db
from fastapi import HTTPException
from netcontrol.chatops import commands, dispatcher
from netcontrol.routes import config_backups, device_config, jobs as jobs_module, state
from netcontrol.routes.shared import require_credential_access
from routes.crypto import encrypt
from routes.runner import BasePlaybook, LogEvent, register_playbook

HOST_IP = "192.0.2.61"
ALL_COMMANDS = frozenset(c.name for c in commands.catalogue())


@register_playbook
class _DisabledAccountRecorder(BasePlaybook):
    filename = "disabled_account_recorder_test.py"
    display_name = "Disabled account recorder (test)"
    description = "test only"
    tags: list[str] = []

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield LogEvent(level="info", message="ran")


async def _user(username: str, role: str = "user") -> dict:
    await db.create_user(username, "x" * 64, "s" * 16, role=role)
    return await db.get_user_by_username(username)


async def _own_credential(owner: dict, name: str, login: str) -> int:
    return await db.create_credential(name, login, encrypt("Owner-Only-Pw-1"), owner_id=owner["id"])


@pytest.fixture
def device_logins(monkeypatch) -> list[tuple[str, str]]:
    """The ``(address, login)`` pairs a device session would be opened with."""
    seen: list[tuple[str, str]] = []

    async def fake_capture(host, credentials):
        seen.append((str(host.get("ip_address")), str(credentials.get("username"))))
        return "hostname example\n", "hostname example\n"

    monkeypatch.setattr(device_config, "_capture_device_configs", fake_capture)
    return seen


async def test_submitter_check_refuses_a_disabled_account():
    await db.init_db()
    bob = await _user("dis-bob")
    cred = await _own_credential(bob, "bob-ssh", "bob-login")
    assert (await require_credential_access(cred, submitter_username="dis-bob"))["id"] == cred

    assert await db.update_user_admin(bob["id"], disabled=True)
    with pytest.raises(HTTPException) as exc:
        await require_credential_access(cred, submitter_username="dis-bob")
    assert exc.value.status_code == 403

    # Enabled again, the account's work runs again.
    assert await db.update_user_admin(bob["id"], disabled=False)
    assert (await require_credential_access(cred, submitter_username="dis-bob"))["id"] == cred


async def test_disabled_admins_policy_stops_using_the_service_credential(device_logins):
    await db.init_db()
    ops = await _user("dis-ops", role="admin")
    service = await db.create_credential("dis-svc", "svc-login", encrypt("Svc-Pw-1"), is_service=True)
    gid = await db.create_group("dis-core")
    await db.add_host(gid, "dis-core1", HOST_IP, address_confirmed=True)
    await db.create_config_backup_policy("dis-svc-policy", gid, service, created_by=ops["username"])
    assert await db.update_user_admin(ops["id"], disabled=True)

    await config_backups._run_config_backups_once()

    assert device_logins == []


async def test_disabled_users_queued_job_does_not_start(monkeypatch):
    started: list[str] = []

    async def fake_run_job(_job_id, _cls, hosts, credentials, *_a, **_k):
        started.append(credentials["username"])

    monkeypatch.setattr(jobs_module, "_run_job", fake_run_job)
    monkeypatch.setattr(jobs_module, "_shutting_down", False)
    monkeypatch.setattr(state, "AUTH_CONFIG", {})

    await db.init_db()
    bob = await _user("dis-bob")
    cred = await _own_credential(bob, "bob-ssh", "bob-login")
    gid = await db.create_group("dis-edge")
    host = await db.add_host(gid, "dis-edge1", HOST_IP, address_confirmed=True)
    playbook = await db.create_playbook("dis-recorder", _DisabledAccountRecorder.filename)
    job = await db.create_job(playbook, gid, cred, None, False, launched_by="dis-bob", host_ids=[host])
    assert await db.update_user_admin(bob["id"], disabled=True)

    await jobs_module._process_job_queue_inner()
    for _ in range(50):
        if started:
            break
        await asyncio.sleep(0.01)

    assert started == []
    assert (await db.get_job(job))["status"] == "failed"
    events = [e["message"] for e in await db.get_job_events(job)]
    assert any("Submitter account is disabled" in message for message in events), events


async def test_launcher_is_admin_ignores_a_disabled_admin():
    await db.init_db()
    ops = await _user("dis-ops", role="admin")
    assert await jobs_module._launcher_is_admin("dis-ops") is True
    assert await db.update_user_admin(ops["id"], disabled=True)
    assert await jobs_module._launcher_is_admin("dis-ops") is False


async def _chat_preset_owner() -> int:
    """A non-admin with the ChatOps and job features, mapped to a chat
    identity, owning the credential an approved job preset uses."""
    user_id = await db.create_user("dis-operator", "hash", "salt", role="user")
    group = await db.create_access_group("dis-operator access", "", ["chatops", "jobs", "jobs.write"])
    await db.set_user_groups(user_id, [group])
    await db.create_chatops_user_mapping(
        platform="slack", chat_user_id="U0EXAMPLE9", chat_label="", user_id=user_id, created_by="admin"
    )
    cred_id = await db.create_credential("dis-op-cred", "netops", "x", owner_id=user_id)
    inv_group = await db.create_group("Lab", "")
    host = await db.add_host(inv_group, "lab-sw-01", "192.0.2.50", "cisco_ios", address_confirmed=True)
    playbook = await db.create_playbook("Backup configs", "backup_configs.py")
    job_id = await db.create_job(playbook, None, cred_id, None, True, launched_by="admin", host_ids=[host])
    await db.create_chatops_job_preset(
        name="nightly backup",
        description="",
        spec=jobs_module.job_clone_spec(await db.get_job(job_id)),
        source_job_id=job_id,
        playbook_name="Backup configs",
        commit=False,
        enabled=True,
        user="admin",
    )
    return user_id


async def _jobs_launched_by(username: str) -> int:
    return len([j for j in await db.get_all_jobs() if j.get("launched_by") == username])


@pytest.mark.parametrize("change", [{"disabled": True}, {"must_change_password": True}])
async def test_chat_identity_of_an_account_that_may_not_sign_in_is_unmapped(monkeypatch, change):
    async def _idle():
        return None

    # Queued jobs stay queued: the test checks the row, not a run.
    monkeypatch.setattr(jobs_module, "_process_job_queue", _idle)
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})
    monkeypatch.setattr(state, "AUTH_CONFIG", {**state.AUTH_CONFIG, "default_credential_id": None})
    user_id = await _chat_preset_owner()

    chat = await dispatcher.resolve_user("slack", ["U0EXAMPLE9"])
    assert chat.user is not None
    assert (await dispatcher.handle(chat, "run nightly backup", ALL_COMMANDS)).ok
    assert await _jobs_launched_by("dis-operator") == 1

    if "disabled" in change:
        assert await db.update_user_admin(user_id, disabled=True)
    else:
        await db.update_user_password(user_id, "hash", "salt", must_change_password=True)
    chat = await dispatcher.resolve_user("slack", ["U0EXAMPLE9"])
    assert chat.user is None
    reply = await dispatcher.handle(chat, "run nightly backup", ALL_COMMANDS)

    assert "not linked to a Plexus user" in reply.text
    assert await _jobs_launched_by("dis-operator") == 1
