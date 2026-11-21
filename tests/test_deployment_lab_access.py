"""Deployment approval by the hosts targeted, lab promote and lab clone
access (security audit findings 19 and 20).

- A deployment needs approval when its group or the group of any target
  host is a production group, at planning and again at execute (a host
  moved into a production group after planning).
- Lab promote plans its deployment through ``plan_deployment`` (the same
  rule) and needs ``deployments`` + ``deployments.write``.
- Lab clone-host copies a host's running config, so it needs
  ``config-drift`` or ``config-backups`` and the source host in scope.
"""

from __future__ import annotations

import asyncio
import json

import pytest
import routes.database as db_module
from routes.crypto import encrypt

LAB_FEATURES = ["lab", "lab.write"]
DEPLOY_FEATURES = ["deployments", "deployments.write"]


def _msg(r) -> str:
    """The message of an /api/ error response (``{ok, error: {code, message}}``)."""
    return r.json()["error"]["message"]


@pytest.fixture
def env(monkeypatch, request):
    import netcontrol.app as app_module
    from netcontrol.routes import state
    from starlette.testclient import TestClient

    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    state.API_RATE_LIMIT["enabled"] = False
    state.API_RATE_LIMIT_TRACKER.clear()

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    admin_csrf = resp.json().get("csrf_token", "")
    users = {
        "deployer": DEPLOY_FEATURES,
        "labber": LAB_FEATURES,
        "lab-config": [*LAB_FEATURES, "config-backups"],
        "lab-deployer": [*LAB_FEATURES, *DEPLOY_FEATURES],
    }
    for name in users:
        r = client.post(
            "/api/admin/users",
            json={"username": name, "password": "password123", "role": "user"},
            headers={"X-CSRF-Token": admin_csrf},
        )
        assert r.status_code == 201, r.text

    async def _seed():
        ids: dict = {}
        for name, features in users.items():
            user = await db_module.get_user_by_username(name)
            access = await db_module.create_access_group(f"da-{name}", "", features)
            await db_module.set_user_groups(user["id"], [access])
            ids[f"{name}_cred"] = await db_module.create_credential(
                f"da-{name}-cred", "dev", encrypt("pw"), owner_id=user["id"]
            )
        ids["lab_group"] = await db_module.create_group("da-staging")
        ids["prod_group"] = await db_module.create_group("da-prod")
        await db_module.set_group_environment(ids["prod_group"], "production")
        ids["lab_host"] = await db_module.add_host(ids["lab_group"], "da-stage-sw1", "192.0.2.51")
        ids["prod_host"] = await db_module.add_host(ids["prod_group"], "da-prod-sw1", "192.0.2.52")
        conn = await db_module.get_db()
        try:
            await conn.execute(
                "INSERT INTO config_snapshots (host_id, capture_method, config_text) VALUES (?, 'manual', ?)",
                (ids["prod_host"], "hostname da-prod-sw1\nsnmp-server community example-ro RO\n"),
            )
            await conn.commit()
        finally:
            await conn.close()
        return ids

    ctx = asyncio.run(_seed())
    ctx["client"] = client
    ctx["admin"] = {"X-CSRF-Token": admin_csrf}

    def login(user: str, password: str = "password123") -> dict:
        r = client.post("/api/auth/login", json={"username": user, "password": password})
        assert r.status_code == 200, r.text
        return {"X-CSRF-Token": r.json().get("csrf_token", "")}

    ctx["login"] = login
    return ctx


def _plan(ctx, headers, *, cred, group, hosts):
    return ctx["client"].post(
        "/api/deployments",
        json={
            "name": "da-change",
            "group_id": group,
            "host_ids": hosts,
            "credential_id": cred,
            "proposed_commands": ["hostname da-new"],
        },
        headers=headers,
    )


# ── Finding 19: approval follows the hosts targeted ─────────────────────────


def test_production_host_listed_under_another_group_requires_approval(env):
    headers = env["login"]("deployer")
    r = _plan(env, headers, cred=env["deployer_cred"], group=env["lab_group"], hosts=[env["prod_host"]])
    assert r.status_code == 200, r.text
    assert r.json()["requires_approval"] is True
    assert r.json()["approval_status"] == "pending"

    dep_id = r.json()["id"]
    r = env["client"].post(f"/api/deployments/{dep_id}/execute", headers=headers)
    assert r.status_code == 403, r.text
    assert "approval" in _msg(r)


def test_non_production_hosts_need_no_approval(env):
    headers = env["login"]("deployer")
    r = _plan(env, headers, cred=env["deployer_cred"], group=env["lab_group"], hosts=[env["lab_host"]])
    assert r.status_code == 200, r.text
    assert r.json()["requires_approval"] is False


def test_execute_rechecks_the_hosts_groups(env):
    headers = env["login"]("deployer")
    r = _plan(env, headers, cred=env["deployer_cred"], group=env["lab_group"], hosts=[env["lab_host"]])
    dep_id = r.json()["id"]
    assert r.json()["requires_approval"] is False

    # The host moves into a production group after planning.
    asyncio.run(db_module.move_hosts([env["lab_host"]], env["prod_group"]))
    r = env["client"].post(f"/api/deployments/{dep_id}/execute", headers=headers)
    assert r.status_code == 403, r.text
    dep = asyncio.run(db_module.get_deployment(dep_id))
    assert dep["requires_approval"] == 1
    assert dep["approval_status"] == "pending"
    assert dep["status"] == "planning"


# ── Object-level checks on approval requests and job status ─────────────────


def test_request_approval_is_for_the_creator_or_an_admin(env):
    owner = env["login"]("lab-deployer")
    r = _plan(env, owner, cred=env["lab-deployer_cred"], group=env["lab_group"], hosts=[env["lab_host"]])
    assert r.status_code == 200, r.text
    dep_id = r.json()["id"]

    other = env["login"]("deployer")
    r = env["client"].post(f"/api/deployments/{dep_id}/request-approval", headers=other)
    assert r.status_code == 403, r.text
    assert asyncio.run(db_module.get_deployment(dep_id))["approval_status"] == "not_required"

    owner = env["login"]("lab-deployer")
    r = env["client"].post(f"/api/deployments/{dep_id}/request-approval", headers=owner)
    assert r.status_code == 200, r.text
    assert r.json()["approval_status"] == "pending"


def test_job_status_is_for_the_creator_or_an_admin(env, monkeypatch):
    import netcontrol.routes.deployments as deployments

    owner = env["login"]("lab-deployer")
    dep_id = _plan(env, owner, cred=env["lab-deployer_cred"], group=env["lab_group"], hosts=[env["lab_host"]]).json()[
        "id"
    ]
    job = {"status": "completed", "output": "hostname da-new\n", "deployment_id": dep_id, "action": "execute"}
    monkeypatch.setitem(deployments._deployment_jobs, "da-job", job)
    client = env["client"]
    assert client.get("/api/deployments/job/da-job/status").json()["output"] == "hostname da-new\n"

    env["login"]("deployer")
    other = client.get("/api/deployments/job/da-job/status")
    unknown = client.get("/api/deployments/job/no-such-job/status")
    assert (other.status_code, _msg(other)) == (unknown.status_code, _msg(unknown)) == (404, "Deployment job not found")

    client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert client.get("/api/deployments/job/da-job/status").status_code == 200


# ── Lab promote goes through plan_deployment ────────────────────────────────


def _lab_run(ctx, headers, *, clone: bool = False) -> int:
    client = ctx["client"]
    env_id = client.post("/api/lab/environments", json={"name": "da-env"}, headers=headers).json()["id"]
    if clone:
        r = client.post(
            f"/api/lab/environments/{env_id}/clone-host", json={"host_id": ctx["prod_host"]}, headers=headers
        )
        assert r.status_code == 200, r.text
        device_id = r.json()["id"]
    else:
        r = client.post(
            f"/api/lab/environments/{env_id}/devices",
            json={"hostname": "da-twin", "running_config": "hostname da-twin\n"},
            headers=headers,
        )
        assert r.status_code == 200, r.text
        device_id = r.json()["id"]
    r = client.post(
        f"/api/lab/devices/{device_id}/simulate",
        json={"proposed_commands": ["ip domain-name example.com"]},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return r.json()["run_id"]


def test_promote_to_a_production_host_requires_approval(env):
    headers = env["login"]("lab-deployer")
    run_id = _lab_run(env, headers)
    r = env["client"].post(
        f"/api/lab/runs/{run_id}/promote",
        json={
            "name": "da-promote",
            "credential_id": env["lab-deployer_cred"],
            "target_group_id": env["lab_group"],
            "target_host_ids": [env["prod_host"]],
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["requires_approval"] is True
    dep = asyncio.run(db_module.get_deployment(r.json()["deployment_id"]))
    assert dep["requires_approval"] == 1
    assert dep["approval_status"] == "pending"
    assert dep["change_type"] == "lab-promote"
    assert json.loads(dep["host_ids"]) == [env["prod_host"]]


def test_promote_needs_the_deployments_write_feature(env):
    headers = env["login"]("labber")
    run_id = _lab_run(env, headers)
    r = env["client"].post(
        f"/api/lab/runs/{run_id}/promote",
        json={"name": "da-promote", "credential_id": env["labber_cred"], "target_group_id": env["lab_group"]},
        headers=headers,
    )
    assert r.status_code == 403, r.text
    assert "deployments" in _msg(r)


# ── Finding 20: clone-host needs a config feature ───────────────────────────


def test_clone_host_needs_a_config_feature(env):
    client = env["client"]
    headers = env["login"]("labber")
    env_id = client.post("/api/lab/environments", json={"name": "da-clone"}, headers=headers).json()["id"]
    r = client.post(f"/api/lab/environments/{env_id}/clone-host", json={"host_id": env["prod_host"]}, headers=headers)
    assert r.status_code == 403, r.text
    assert "config-drift" in _msg(r) and "config-backups" in _msg(r)
    assert asyncio.run(db_module.list_lab_devices(env_id)) == []


def test_clone_host_allowed_with_config_backups_or_as_admin(env):
    client = env["client"]
    headers = env["login"]("lab-config")
    env_id = client.post("/api/lab/environments", json={"name": "da-clone-ok"}, headers=headers).json()["id"]
    r = client.post(f"/api/lab/environments/{env_id}/clone-host", json={"host_id": env["prod_host"]}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["config_bytes"] > 0

    admin_env = client.post(
        "/api/lab/environments", json={"name": "da-admin"}, headers=env["login"]("admin", "netcontrol")
    ).json()["id"]
    r = client.post(
        f"/api/lab/environments/{admin_env}/clone-host",
        json={"host_id": env["prod_host"]},
        headers=env["login"]("admin", "netcontrol"),
    )
    assert r.status_code == 200, r.text


def test_clone_host_respects_the_object_scope(env):
    """A caller limited to one inventory group cannot clone a host of another."""
    client = env["client"]
    r = client.post(
        "/api/admin/access-groups",
        json={
            "name": "da-scoped",
            "feature_keys": [*LAB_FEATURES, "config-backups"],
            "object_scope": "groups",
            "inventory_scopes": [{"inventory_group_id": env["lab_group"], "can_write": True}],
        },
        headers=env["login"]("admin", "netcontrol"),
    )
    assert r.status_code == 201, r.text
    r = client.post(
        "/api/admin/users",
        json={"username": "lab-scoped", "password": "password123", "group_ids": [r.json()["id"]]},
        headers=env["login"]("admin", "netcontrol"),
    )
    assert r.status_code == 201, r.text
    headers = env["login"]("lab-scoped")
    env_id = client.post("/api/lab/environments", json={"name": "da-scope"}, headers=headers).json()["id"]
    r = client.post(f"/api/lab/environments/{env_id}/clone-host", json={"host_id": env["prod_host"]}, headers=headers)
    assert r.status_code == 404, r.text
    r = client.post(f"/api/lab/environments/{env_id}/clone-host", json={"host_id": env["lab_host"]}, headers=headers)
    assert r.status_code == 200, r.text
