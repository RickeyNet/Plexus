"""A deployment's commands and snapshots are read under the raw-config rule.

A deployment's proposed commands can carry device secrets (an enable
secret, an SNMP community, a TACACS+ key), and its pre/post snapshots are
the device's running configuration. They follow the rule of
``netcontrol.routes.config_visibility``: an admin, the API token, or a user
holding ``config-backups.write`` who may change every target reads them as
written; every other reader gets the secrets masked. Executing a deployment
pushes the stored commands as written; its job log lists them masked.

Every secret and address below is invented.
"""

from __future__ import annotations

import functools
import json
from types import SimpleNamespace

import pytest
import routes.database as db_module
from routes.crypto import encrypt

from mcp_helpers import admin_client, user_client

ENABLE_SECRET = "example-deploy-secret-0001"
COMMUNITY = "example-deploy-secret-0002"
TACACS_KEY = "example-deploy-secret-0003"
SECRETS = (ENABLE_SECRET, COMMUNITY, TACACS_KEY)
COMMANDS = [
    "hostname edge-sw1",
    f"enable secret 0 {ENABLE_SECRET}",
    f"snmp-server community {COMMUNITY} RO",
    "tacacs server tac-a",
    f" key 0 {TACACS_KEY}",
]
SNAPSHOT = "hostname edge-sw1\n" + f"snmp-server community {COMMUNITY} RO\n"
RAW_FEATURES = ["config-backups", "config-backups.write"]


def _leaked(text: str) -> list[str]:
    return [s for s in SECRETS if s in text]


@pytest.fixture
def env(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    call = admin.raw.portal.call
    gid = call(functools.partial(db_module.create_group, "deploy-masking"))
    host_id = call(functools.partial(db_module.add_host, gid, "edge-sw1", "192.0.2.31"))
    cred_id = call(functools.partial(db_module.create_credential, "deploy-masking-cred", "dev", encrypt("pw")))
    return {"admin": admin, "call": call, "gid": gid, "host_id": host_id, "cred_id": cred_id}


def _deployment(env, created_by: str) -> int:
    call = env["call"]
    dep_id = call(
        functools.partial(
            db_module.create_deployment,
            name="masking-change",
            group_id=env["gid"],
            credential_id=env["cred_id"],
            proposed_commands="\n".join(COMMANDS),
            host_ids=json.dumps([env["host_id"]]),
            created_by=created_by,
        )
    )
    call(functools.partial(db_module.create_deployment_snapshot, dep_id, env["host_id"], "pre", SNAPSHOT))
    return dep_id


def test_deployment_list_masks_commands_for_users_without_the_raw_right(env):
    dep_id = _deployment(env, "admin")
    reader = user_client(env["admin"], "deploy-reader", features=["deployments"])

    resp = reader.get("/api/deployments")
    assert resp.status_code == 200, resp.text
    assert _leaked(resp.text) == [], "deployment list returned device secrets to a deployments-only user"
    row = next(d for d in resp.json() if d["id"] == dep_id)
    assert row["secrets_masked"] is True
    # One masked command per command; the structure stays readable.
    masked = row["proposed_commands"].split("\n")
    assert len(masked) == len(COMMANDS)
    assert masked[0] == "hostname edge-sw1" and masked[2].startswith("snmp-server community ")


def test_deployment_detail_masks_commands_and_snapshots_for_its_creator_without_the_raw_right(env):
    dep_id = _deployment(env, "deploy-author")
    author = user_client(env["admin"], "deploy-author", features=["deployments", "deployments.write"])

    for path in (f"/api/deployments/{dep_id}", f"/api/deployments/{dep_id}/correlation"):
        resp = author.get(path)
        assert resp.status_code == 200, (path, resp.text)
        assert _leaked(resp.text) == [], path
    detail = author.get(f"/api/deployments/{dep_id}").json()
    assert detail["secrets_masked"] is True
    assert detail["snapshots"][0]["secrets_masked"] is True
    assert detail["snapshots"][0]["config_text"].startswith("hostname edge-sw1\n")


def test_deployment_reads_are_raw_for_callers_with_the_raw_right(env):
    dep_id = _deployment(env, "deploy-raw")
    writer = user_client(env["admin"], "deploy-raw", features=["deployments", "deployments.write", *RAW_FEATURES])

    for client in (env["admin"], writer):
        detail = client.get(f"/api/deployments/{dep_id}").json()
        assert detail["proposed_commands"] == "\n".join(COMMANDS)
        assert detail["snapshots"][0]["config_text"] == SNAPSHOT
        assert not detail.get("secrets_masked")
        row = next(d for d in client.get("/api/deployments").json() if d["id"] == dep_id)
        assert row["proposed_commands"] == "\n".join(COMMANDS)
        correlation = client.get(f"/api/deployments/{dep_id}/correlation").json()
        assert correlation["deployment"]["proposed_commands"] == "\n".join(COMMANDS)


def test_execute_pushes_the_commands_as_written_and_logs_them_masked(env, monkeypatch):
    from netcontrol.routes import deployments

    dep_id = _deployment(env, "admin")
    pushed: list[list[str]] = []

    async def fake_config(*_args, **_kwargs):
        return SimpleNamespace(config_text=SNAPSHOT)

    async def fake_push(_host, _credentials, commands):
        pushed.append(list(commands))
        return ""

    async def fake_finish(job_id, status="completed"):
        deployments._deployment_jobs[job_id]["status"] = status

    monkeypatch.setattr(deployments, "get_device_config", fake_config)
    monkeypatch.setattr(deployments, "_push_config_to_device", fake_push)
    monkeypatch.setattr(deployments, "_finish_deploy_job", fake_finish)
    monkeypatch.setattr(deployments, "supervise_task", lambda task, _name: task.cancel())
    job = {"status": "running", "output": "", "deployment_id": dep_id, "action": "execute"}
    monkeypatch.setitem(deployments._deployment_jobs, "masking-job", job)
    monkeypatch.setitem(deployments._deployment_job_sockets, "masking-job", [])

    host = {"id": env["host_id"], "hostname": "edge-sw1", "ip_address": "192.0.2.31"}
    env["call"](deployments._run_deployment_job, "masking-job", dep_id, [host], list(COMMANDS), {}, "admin")

    assert pushed == [COMMANDS]
    assert job["status"] == "completed", job["output"]
    assert "snmp-server community " in job["output"]
    assert _leaked(job["output"]) == [], "deployment log listed the commands with their secrets"
