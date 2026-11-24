"""Deployment execute and rollback, and risk analysis, sign in to the device
with the stored credential's password.

The routes hand the SSH helpers (``get_device_config``,
``_push_config_to_device``) the stored credential row, which the helpers
decrypt once when they open the session. Netmiko is stubbed: the test
drives the real routes and checks the password the login is attempted with.
"""

from __future__ import annotations

import asyncio
import json
import time

import netmiko
import pytest
import routes.database as db
from netcontrol.routes import deployments
from routes.crypto import encrypt

from mcp_helpers import admin_client

PASSWORD = "deploy-device-password-0001"
SECRET = "deploy-enable-secret-0001"
HOST_IP = "192.0.2.60"
BEFORE = "hostname lab-sw-01\n"
AFTER = "hostname lab-sw-01\nntp server 192.0.2.1\n"


class _FakeConnection:
    """A Netmiko session that records the login and serves ``config``."""

    logins: list[dict] = []
    config = BEFORE

    def __init__(self, **kwargs):
        type(self).logins.append(kwargs)

    def enable(self):
        return ""

    def send_command(self, _command, **_kwargs):
        return type(self).config

    def send_config_set(self, lines):
        type(self).config = AFTER if any("ntp" in line for line in lines) else BEFORE
        return "ok"

    def save_config(self):
        return "saved"

    def disconnect(self):
        return None


@pytest.fixture
def env(monkeypatch, request):
    api = admin_client(monkeypatch, request)
    _FakeConnection.logins = []
    _FakeConnection.config = BEFORE
    monkeypatch.setattr(netmiko, "ConnectHandler", _FakeConnection)

    async def no_verification(*_a, **_k):
        return None

    monkeypatch.setattr(deployments, "_run_post_deployment_verification", no_verification)

    async def seed() -> tuple[int, int, int]:
        admin = await db.get_user_by_username("admin")
        assert admin is not None
        gid = await db.create_group("deploy-login")
        host = await db.add_host(gid, "lab-sw-01", HOST_IP, "cisco_xe", address_confirmed=True)
        cred = await db.create_credential(
            "own-deploy", "netops", encrypt(PASSWORD), encrypt(SECRET), owner_id=admin["id"]
        )
        return gid, host, cred

    gid, host, cred = asyncio.run(seed())
    return api, gid, host, cred


def _deployment(gid: int, host: int, cred: int, status: str = "planning") -> int:
    async def make() -> int:
        dep = await db.create_deployment(
            name="ntp",
            group_id=gid,
            credential_id=cred,
            proposed_commands="ntp server 192.0.2.1",
            host_ids=json.dumps([host]),
            created_by="admin",
        )
        if status != "planning":
            await db.update_deployment_status(dep, status)
            await db.create_deployment_snapshot(dep, host, "pre", BEFORE)
        return dep

    return asyncio.run(make())


def _wait(job_id: str) -> str:
    for _ in range(250):
        status = deployments._deployment_jobs[job_id]["status"]
        if status != "running":
            return status
        time.sleep(0.02)
    return "running"


def _assert_logins_used_the_stored_password() -> None:
    assert _FakeConnection.logins, "no device login was attempted"
    for login in _FakeConnection.logins:
        assert login["username"] == "netops"
        assert login["password"] == PASSWORD
        assert login["secret"] == SECRET


def test_execute_signs_in_with_the_stored_password(env):
    api, gid, host, cred = env
    dep = _deployment(gid, host, cred)

    r = api.post(f"/api/deployments/{dep}/execute")
    assert r.status_code == 200, r.text
    assert _wait(r.json()["job_id"]) == "completed"

    _assert_logins_used_the_stored_password()
    # Pre-check capture, push, post-check capture.
    assert len(_FakeConnection.logins) == 3
    assert asyncio.run(db.get_deployment(dep))["status"] == "completed"


def test_rollback_signs_in_with_the_stored_password(env):
    api, gid, host, cred = env
    dep = _deployment(gid, host, cred, status="completed")
    _FakeConnection.config = AFTER  # the deployed change is on the device

    r = api.post(f"/api/deployments/{dep}/rollback")
    assert r.status_code == 200, r.text
    assert _wait(r.json()["job_id"]) == "completed"

    _assert_logins_used_the_stored_password()
    checkpoints = [c for c in asyncio.run(db.get_deployment_checkpoints(dep)) if c["phase"] == "rollback"]
    assert [c["status"] for c in checkpoints] == ["passed"]


def test_risk_analysis_signs_in_with_the_stored_password(env):
    api, _gid, host, cred = env

    r = api.post(
        "/api/risk-analysis/analyze",
        json={"credential_id": cred, "host_id": host, "proposed_commands": ["ntp server 192.0.2.1"]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["host_results"][0]["status"] == "analyzed"
    _assert_logins_used_the_stored_password()
