"""Tests for digital twin / lab mode (Phase A)."""

from __future__ import annotations

import netcontrol.app as app_module
import pytest
import routes.database as db_module


class _LabClient:
    def __init__(self, client, csrf_token):
        self._client = client
        self._csrf = csrf_token

    def _merge_headers(self, kw):
        h = kw.pop("headers", {})
        h["X-CSRF-Token"] = self._csrf
        kw["headers"] = h

    def get(self, url, **kw):
        return self._client.get(url, **kw)

    def post(self, url, **kw):
        self._merge_headers(kw)
        return self._client.post(url, **kw)

    def patch(self, url, **kw):
        self._merge_headers(kw)
        return self._client.patch(url, **kw)

    def delete(self, url, **kw):
        self._merge_headers(kw)
        return self._client.delete(url, **kw)


def _auth_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "lab_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-lab")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    # Disable rate limiting and clear any leftover counts from a previous test.
    from netcontrol.routes import state as _state
    _state.API_RATE_LIMIT["enabled"] = False
    _state.API_RATE_LIMIT_TRACKER.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()

    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "netcontrol"},
    )
    csrf_token = resp.json().get("csrf_token", "")
    return _LabClient(client, csrf_token)


# ── Migration ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lab_tables_exist_after_init(tmp_path, monkeypatch):
    db_path = str(tmp_path / "lab_migrate.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()

    conn = await db_module.get_db()
    try:
        for tbl in ("lab_environments", "lab_devices", "lab_runs"):
            cur = await conn.execute(
                f"SELECT name FROM sqlite_master WHERE type='table' AND name='{tbl}'"
            )
            row = await cur.fetchone()
            assert row is not None, f"{tbl} table should exist"
    finally:
        await conn.close()


# ── Environment + device CRUD ───────────────────────────────────────────────


def test_environment_create_list_delete(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)

    resp = client.post(
        "/api/lab/environments",
        json={"name": "sandbox-1", "description": "test env", "shared": True},
    )
    assert resp.status_code == 200, resp.text
    env_id = resp.json()["id"]

    resp = client.get("/api/lab/environments")
    assert resp.status_code == 200
    names = [e["name"] for e in resp.json()]
    assert "sandbox-1" in names

    resp = client.get(f"/api/lab/environments/{env_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "sandbox-1"
    assert body["devices"] == []

    resp = client.delete(f"/api/lab/environments/{env_id}")
    assert resp.status_code == 200
    resp = client.get(f"/api/lab/environments/{env_id}")
    assert resp.status_code == 404


def test_device_create_and_simulate(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)

    env_id = client.post(
        "/api/lab/environments", json={"name": "sim-env"},
    ).json()["id"]

    initial_config = "interface Gi0/1\n shutdown\n"
    resp = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={
            "hostname": "twin-rtr-1",
            "ip_address": "10.0.0.1",
            "device_type": "cisco_ios",
            "running_config": initial_config,
        },
    )
    assert resp.status_code == 200
    device_id = resp.json()["id"]

    # Simulate a config change.
    resp = client.post(
        f"/api/lab/devices/{device_id}/simulate",
        json={
            "proposed_commands": ["interface Gi0/2", " no shutdown", " ip address 10.0.0.2 255.255.255.0"],
            "apply_to_device": False,
        },
    )
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["status"] == "simulated"
    assert result["risk_level"] in {"low", "medium", "high", "critical"}
    assert result["diff_added"] >= 1
    assert "Gi0/2" in result["diff_text"]
    run_id = result["run_id"]

    # Run history.
    resp = client.get(f"/api/lab/devices/{device_id}/runs")
    assert resp.status_code == 200
    runs = resp.json()
    assert len(runs) == 1
    assert runs[0]["id"] == run_id

    # Run detail decodes commands list.
    resp = client.get(f"/api/lab/runs/{run_id}")
    assert resp.status_code == 200
    detail = resp.json()
    assert isinstance(detail["commands"], list)
    assert detail["status"] == "simulated"

    # Apply to device persists post_config.
    resp = client.post(f"/api/lab/runs/{run_id}/apply-to-device")
    assert resp.status_code == 200
    resp = client.get(f"/api/lab/devices/{device_id}")
    assert resp.status_code == 200
    assert "Gi0/2" in resp.json()["running_config"]


def test_simulate_with_apply_persists_config(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "apply-env"}).json()["id"]
    device_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "rtr", "running_config": "hostname rtr\n"},
    ).json()["id"]

    resp = client.post(
        f"/api/lab/devices/{device_id}/simulate",
        json={"proposed_commands": ["snmp-server community public RO"], "apply_to_device": True},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "applied"

    resp = client.get(f"/api/lab/devices/{device_id}")
    assert resp.status_code == 200
    assert "snmp-server community public" in resp.json()["running_config"]


# ── Clone-from-host + promote ───────────────────────────────────────────────


def test_clone_host_uses_latest_snapshot(tmp_path, monkeypatch):
    """Cloning a production host into the lab should pull latest config snapshot."""
    client = _auth_client(tmp_path, monkeypatch)

    # Seed: create a group + host + snapshot synchronously via TestClient lifespan.
    import asyncio

    async def _seed():
        gid = await db_module.create_group(name="lab-src")
        hid = await db_module.add_host(
            group_id=gid, hostname="prod-rtr", ip_address="10.1.1.1",
        )
        # Insert a config snapshot for that host.
        conn = await db_module.get_db()
        try:
            await conn.execute(
                "INSERT INTO config_snapshots (host_id, capture_method, config_text) "
                "VALUES (?, 'manual', ?)",
                (hid, "hostname prod-rtr\ninterface Gi0/0\n ip address 10.1.1.1 255.255.255.0\n"),
            )
            await conn.commit()
        finally:
            await conn.close()
        return hid

    host_id = asyncio.run(_seed())

    env_id = client.post("/api/lab/environments", json={"name": "clone-env"}).json()["id"]

    resp = client.post(
        f"/api/lab/environments/{env_id}/clone-host",
        json={"host_id": host_id},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["config_bytes"] > 0
    cloned_device_id = body["id"]

    resp = client.get(f"/api/lab/devices/{cloned_device_id}")
    assert resp.status_code == 200
    dev = resp.json()
    assert dev["source_host_id"] == host_id
    assert "prod-rtr" in dev["running_config"]


def test_promote_run_creates_deployment(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)

    # Seed group + host + snapshot + credential so promote can target real infra.
    import asyncio

    async def _seed():
        gid = await db_module.create_group(name="prod")
        hid = await db_module.add_host(
            group_id=gid, hostname="prod-rtr-2", ip_address="10.2.2.1",
        )
        conn = await db_module.get_db()
        try:
            await conn.execute(
                "INSERT INTO config_snapshots (host_id, capture_method, config_text) "
                "VALUES (?, 'manual', ?)",
                (hid, "hostname prod-rtr-2\n"),
            )
            await conn.commit()
        finally:
            await conn.close()
        from routes.crypto import encrypt
        cred_id = await db_module.create_credential(
            name="lab-cred",
            username="netadmin",
            enc_password=encrypt("password"),
            enc_secret=encrypt(""),
        )
        return gid, hid, cred_id

    gid, hid, cred_id = asyncio.run(_seed())

    env_id = client.post("/api/lab/environments", json={"name": "promote-env"}).json()["id"]

    # Clone host into lab.
    twin_id = client.post(
        f"/api/lab/environments/{env_id}/clone-host",
        json={"host_id": hid},
    ).json()["id"]

    # Simulate a change.
    sim = client.post(
        f"/api/lab/devices/{twin_id}/simulate",
        json={"proposed_commands": ["ip domain-name lab.local"]},
    ).json()
    run_id = sim["run_id"]

    # Promote.
    resp = client.post(
        f"/api/lab/runs/{run_id}/promote",
        json={
            "name": "promote test deployment",
            "credential_id": cred_id,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["deployment_id"] >= 1

    # Run is marked promoted.
    resp = client.get(f"/api/lab/runs/{run_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "promoted"
    assert resp.json()["promoted_deployment_id"] == body["deployment_id"]
