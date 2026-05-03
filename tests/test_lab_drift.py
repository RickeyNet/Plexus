"""Tests for Phase B-3a — drift-from-twin checks."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.lab_drift as lab_drift
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


def _auth_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "lab_drift_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-drift")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

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
async def test_drift_table_exists_after_init(tmp_path, monkeypatch):
    db_path = str(tmp_path / "drift_migrate.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    conn = await db_module.get_db()
    try:
        cur = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='lab_drift_runs'"
        )
        assert await cur.fetchone() is not None
    finally:
        await conn.close()


# ── Helpers used by the HTTP tests ──────────────────────────────────────────


def _seed_host_with_snapshot(hostname: str, ip: str, config_text: str) -> int:
    """Create a group + host + config_snapshot. Returns the host id."""
    async def _do():
        gid = await db_module.create_group(name=f"grp-{hostname}")
        hid = await db_module.add_host(group_id=gid, hostname=hostname, ip_address=ip)
        conn = await db_module.get_db()
        try:
            await conn.execute(
                "INSERT INTO config_snapshots (host_id, capture_method, config_text) "
                "VALUES (?, 'manual', ?)",
                (hid, config_text),
            )
            await conn.commit()
        finally:
            await conn.close()
        return hid

    return asyncio.run(_do())


# ── On-demand check ─────────────────────────────────────────────────────────


def test_drift_check_in_sync(tmp_path, monkeypatch):
    """Twin matches the production snapshot byte-for-byte → in_sync."""
    client = _auth_client(tmp_path, monkeypatch)
    config = "hostname rtr-1\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
    host_id = _seed_host_with_snapshot("rtr-1", "10.0.0.1", config)

    env_id = client.post("/api/lab/environments", json={"name": "drift-env"}).json()["id"]
    clone = client.post(
        f"/api/lab/environments/{env_id}/clone-host",
        json={"host_id": host_id},
    ).json()
    dev_id = clone["id"]

    resp = client.post(f"/api/lab/devices/{dev_id}/drift/check")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "in_sync"
    assert body["diff_added"] == 0
    assert body["diff_removed"] == 0

    latest = client.get(f"/api/lab/devices/{dev_id}/drift/latest").json()
    assert latest["status"] == "in_sync"


def test_drift_check_detects_divergence(tmp_path, monkeypatch):
    """Modifying production after cloning should produce status='drifted'."""
    client = _auth_client(tmp_path, monkeypatch)

    initial = "hostname rtr-2\nip domain-name example.com\n"
    host_id = _seed_host_with_snapshot("rtr-2", "10.0.0.2", initial)
    env_id = client.post("/api/lab/environments", json={"name": "drift-env"}).json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/clone-host",
        json={"host_id": host_id},
    ).json()["id"]

    # Simulate prod-side cowboy change: insert a fresher snapshot for the host.
    async def _add_prod_snapshot():
        conn = await db_module.get_db()
        try:
            await conn.execute(
                "INSERT INTO config_snapshots (host_id, capture_method, config_text) "
                "VALUES (?, 'manual', ?)",
                (host_id, initial + "snmp-server community public RO\n"),
            )
            await conn.commit()
        finally:
            await conn.close()

    asyncio.run(_add_prod_snapshot())

    resp = client.post(f"/api/lab/devices/{dev_id}/drift/check")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "drifted"
    assert body["diff_added"] >= 1

    runs = client.get(f"/api/lab/devices/{dev_id}/drift/runs").json()
    assert len(runs) == 1
    assert runs[0]["status"] == "drifted"

    # Run detail surfaces the diff_text payload.
    detail = client.get(f"/api/lab/drift/runs/{runs[0]['id']}").json()
    assert "snmp-server community public" in detail["diff_text"]


def test_drift_check_missing_source_for_blank_device(tmp_path, monkeypatch):
    """A lab device authored manually (no source host) reports missing_source."""
    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "blank-env"}).json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "free-twin", "running_config": "hostname free-twin\n"},
    ).json()["id"]

    resp = client.post(f"/api/lab/devices/{dev_id}/drift/check")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "missing_source"

    latest = client.get(f"/api/lab/devices/{dev_id}/drift/latest").json()
    assert latest["status"] == "missing_source"


def test_drift_check_missing_when_no_prod_snapshot(tmp_path, monkeypatch):
    """Source host exists but has no captured snapshot yet."""
    client = _auth_client(tmp_path, monkeypatch)

    async def _seed():
        gid = await db_module.create_group(name="bare-grp")
        return await db_module.add_host(
            group_id=gid, hostname="bare-host", ip_address="10.0.0.3",
        )

    host_id = asyncio.run(_seed())
    env_id = client.post("/api/lab/environments", json={"name": "no-snap-env"}).json()["id"]
    # Manually create the device so the clone-host endpoint doesn't reject the empty config.
    async def _seed_dev():
        return await db_module.create_lab_device(
            environment_id=env_id,
            hostname="twin-bare",
            source_host_id=host_id,
            running_config="hostname twin-bare\n",
        )

    dev_id = asyncio.run(_seed_dev())

    resp = client.post(f"/api/lab/devices/{dev_id}/drift/check")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "missing_source"


# ── Scheduler iteration ──────────────────────────────────────────────────────


def test_run_drift_check_all_walks_only_eligible_devices(tmp_path, monkeypatch):
    """The sweep should walk only devices with source_host_id set."""
    client = _auth_client(tmp_path, monkeypatch)

    # Eligible: one cloned device matching prod (in_sync).
    host_id = _seed_host_with_snapshot("rtr-3", "10.0.0.4", "hostname rtr-3\n")
    env_id = client.post("/api/lab/environments", json={"name": "sweep-env"}).json()["id"]
    cloned_id = client.post(
        f"/api/lab/environments/{env_id}/clone-host",
        json={"host_id": host_id},
    ).json()["id"]

    # Ineligible: blank manual device — no source host.
    client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "manual-twin", "running_config": "hostname manual-twin\n"},
    )

    summary = asyncio.run(lab_drift.run_drift_check_all(actor="test"))
    # Only one device qualifies for a sweep.
    assert summary["checked"] == 1
    assert summary["in_sync"] == 1
    assert summary["drifted"] == 0
    assert summary["missing_source"] == 0

    # Persisted run is attached to the cloned device, not the blank one.
    runs = client.get(f"/api/lab/devices/{cloned_id}/drift/runs").json()
    assert len(runs) == 1
    assert runs[0]["actor"] == "test"


# ── Scheduler config ────────────────────────────────────────────────────────


def test_drift_scheduler_respects_disable_flag(monkeypatch):
    monkeypatch.setenv("PLEXUS_LAB_DRIFT_ENABLED", "false")
    assert lab_drift._drift_enabled() is False
    monkeypatch.setenv("PLEXUS_LAB_DRIFT_ENABLED", "true")
    assert lab_drift._drift_enabled() is True


def test_drift_scheduler_interval_clamped_minimum(monkeypatch):
    monkeypatch.setenv("PLEXUS_LAB_DRIFT_INTERVAL_SECONDS", "5")
    # Floor is 60s — anything smaller is bumped up.
    assert lab_drift._drift_interval_seconds() == 60
    monkeypatch.setenv("PLEXUS_LAB_DRIFT_INTERVAL_SECONDS", "1800")
    assert lab_drift._drift_interval_seconds() == 1800
    monkeypatch.setenv("PLEXUS_LAB_DRIFT_INTERVAL_SECONDS", "garbage")
    assert lab_drift._drift_interval_seconds() == lab_drift.DEFAULT_DRIFT_INTERVAL_SECONDS
