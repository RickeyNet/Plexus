"""Tests for Phase B-1 — containerlab runtime driver and live API."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import netcontrol.app as app_module
import netcontrol.routes.lab_runtime as lab_runtime
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
    db_path = str(tmp_path / "lab_runtime_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-runtime")
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
async def test_runtime_columns_exist_after_init(tmp_path, monkeypatch):
    db_path = str(tmp_path / "rt_migrate.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()

    conn = await db_module.get_db()
    try:
        cur = await conn.execute("PRAGMA table_info(lab_devices)")
        rows = await cur.fetchall()
        cols = {r[1] for r in rows}
        for required in (
            "runtime_kind", "runtime_node_kind", "runtime_image",
            "runtime_status", "runtime_lab_name", "runtime_node_name",
            "runtime_mgmt_address", "runtime_credential_id", "runtime_error",
            "runtime_workdir", "runtime_started_at",
        ):
            assert required in cols, f"missing lab_devices.{required}"

        cur = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='lab_runtime_events'"
        )
        assert await cur.fetchone() is not None
    finally:
        await conn.close()


# ── Driver-level unit tests ─────────────────────────────────────────────────


def test_runtime_status_unavailable_when_binary_missing(monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _name: None)

    async def _go():
        return await lab_runtime.get_runtime_status()

    res = asyncio.run(_go())
    assert res["available"] is False
    assert res["binary"] is None
    assert "not found" in res["reason"].lower()
    assert "linux" in res["allowed_node_kinds"]


def test_runtime_status_available_parses_version(monkeypatch):
    monkeypatch.setattr(
        lab_runtime.shutil, "which", lambda _name: "/usr/local/bin/containerlab",
    )

    async def _fake_run(args, cwd=None):
        return 0, "containerlab version 0.50.0\n", ""

    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)

    async def _go():
        return await lab_runtime.get_runtime_status()

    res = asyncio.run(_go())
    assert res["available"] is True
    assert res["binary"] == "/usr/local/bin/containerlab"
    assert "0.50" in (res["version"] or "")


def test_image_validation_rejects_shell_metacharacters():
    bad = ["rm -rf /", "frr;ls", "img$(whoami)", "img|cat", "img with space"]
    for image in bad:
        assert lab_runtime._IMAGE_RE.match(image) is None


def test_image_validation_accepts_common_refs():
    good = [
        "ceos:4.30.0F",
        "frrouting/frr:latest",
        "ghcr.io/nokia/srlinux:23.10.1",
        "alpine",
        "registry.example.com/team/img:1.2.3",
    ]
    for image in good:
        assert lab_runtime._IMAGE_RE.match(image) is not None


def test_topology_yaml_includes_all_fields():
    yml = lab_runtime._build_topology_yaml(
        lab_name="plx-env1-dev2",
        node_name="rtr-1",
        kind="ceos",
        image="ceos:4.30.0F",
    )
    assert "name: plx-env1-dev2" in yml
    assert "rtr-1:" in yml
    assert "kind: ceos" in yml
    assert "image: ceos:4.30.0F" in yml


def test_extract_mgmt_ipv4_modern_shape():
    doc = {
        "containers": [
            {"name": "clab-foo-rtr-1", "ipv4_address": "172.20.20.5/24"},
            {"name": "clab-bar-rtr-2", "ipv4_address": "172.20.20.6/24"},
        ],
    }
    assert lab_runtime._extract_mgmt_ipv4(doc, "rtr-1") == "172.20.20.5"


def test_extract_mgmt_ipv4_legacy_shape():
    doc = {
        "plx-env1-dev2": [
            {"name": "clab-plx-env1-dev2-rtr-1", "ipv4-address": "10.10.10.7/24"},
        ],
    }
    assert lab_runtime._extract_mgmt_ipv4(doc, "rtr-1") == "10.10.10.7"


# ── HTTP endpoints (with mocked driver) ─────────────────────────────────────


def test_runtime_status_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _name: None)
    client = _auth_client(tmp_path, monkeypatch)
    resp = client.get("/api/lab/runtime")
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is False
    assert "linux" in body["allowed_node_kinds"]


def test_deploy_rejected_when_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _name: None)
    client = _auth_client(tmp_path, monkeypatch)

    env_id = client.post("/api/lab/environments", json={"name": "rt-env"}).json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "rtr1", "running_config": "hostname rtr1\n"},
    ).json()["id"]

    resp = client.post(
        f"/api/lab/devices/{dev_id}/runtime/deploy",
        json={"node_kind": "linux", "image": "alpine"},
    )
    assert resp.status_code == 503
    assert "containerlab" in resp.text.lower()


def test_deploy_rejects_disallowed_node_kind(tmp_path, monkeypatch):
    # Pretend containerlab is available so the request hits validation.
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")
    monkeypatch.setattr(
        lab_runtime, "_run_containerlab",
        AsyncMock(return_value=(0, "version 0.50\n", "")),
    )
    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "rt-env"}).json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "rtr1"},
    ).json()["id"]

    resp = client.post(
        f"/api/lab/devices/{dev_id}/runtime/deploy",
        json={"node_kind": "exotic-fake", "image": "alpine"},
    )
    assert resp.status_code == 400
    assert "node kind" in resp.text.lower()


def test_deploy_happy_path_records_state_and_event(tmp_path, monkeypatch):
    """Successful deploy should write running state, mgmt IP, and an event row."""
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")

    # Sequence of subprocess calls during a deploy:
    #   1. version (status check)        → rc=0
    #   2. deploy ... --reconfigure       → rc=0
    #   3. inspect ... --format json      → rc=0 with mgmt IP json
    inspect_json = (
        '{"containers": [{"name": "clab-plx-rtr-1", "ipv4_address": "172.20.20.5/24"}]}'
    )

    call_log: list[list[str]] = []

    async def _fake_run(args, cwd=None):
        call_log.append(list(args))
        if args[0] == "version":
            return 0, "containerlab version 0.50.0\n", ""
        if args[0] == "deploy":
            return 0, "Deployed.\n", ""
        if args[0] == "inspect":
            return 0, inspect_json, ""
        return 1, "", "unexpected"

    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)
    monkeypatch.setenv("PLEXUS_LAB_WORKDIR", str(tmp_path / "labwd"))

    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "rt-env"}).json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "rtr-1", "running_config": "hostname rtr-1\n"},
    ).json()["id"]

    resp = client.post(
        f"/api/lab/devices/{dev_id}/runtime/deploy",
        json={"node_kind": "ceos", "image": "ceos:4.30.0F"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "running"
    assert body["mgmt_ipv4"] == "172.20.20.5"
    assert body["node_name"] == "rtr-1"

    # The driver should have asked for: version, deploy, inspect.
    seen_actions = [c[0] for c in call_log]
    assert "deploy" in seen_actions
    assert "inspect" in seen_actions

    # State persisted on the lab device.
    detail = client.get(f"/api/lab/devices/{dev_id}").json()
    assert detail["runtime_kind"] == "containerlab"
    assert detail["runtime_status"] == "running"
    assert detail["runtime_mgmt_address"] == "172.20.20.5"
    assert detail["runtime_node_kind"] == "ceos"

    events = client.get(f"/api/lab/devices/{dev_id}/runtime/events").json()
    assert any(e["action"] == "deploy" and e["status"] == "ok" for e in events)


def test_destroy_clears_state(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")
    inspect_json = (
        '{"containers": [{"name": "clab-plx-rtr-1", "ipv4_address": "172.20.20.5/24"}]}'
    )

    async def _fake_run(args, cwd=None):
        if args[0] == "version":
            return 0, "containerlab version 0.50\n", ""
        if args[0] == "deploy":
            return 0, "ok", ""
        if args[0] == "inspect":
            return 0, inspect_json, ""
        if args[0] == "destroy":
            return 0, "destroyed", ""
        return 1, "", "unknown"

    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)
    monkeypatch.setenv("PLEXUS_LAB_WORKDIR", str(tmp_path / "labwd"))

    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "rt-env"}).json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "rtr-d"},
    ).json()["id"]

    client.post(
        f"/api/lab/devices/{dev_id}/runtime/deploy",
        json={"node_kind": "linux", "image": "alpine"},
    )
    resp = client.post(f"/api/lab/devices/{dev_id}/runtime/destroy")
    assert resp.status_code == 200
    assert resp.json()["status"] == "destroyed"

    detail = client.get(f"/api/lab/devices/{dev_id}").json()
    assert detail["runtime_status"] == "destroyed"
    assert detail["runtime_mgmt_address"] in ("", None)


def test_simulate_live_runs_real_push(tmp_path, monkeypatch):
    """simulate-live should pull pre/post configs from the device via Netmiko mocks."""
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")
    inspect_json = (
        '{"containers": [{"name": "clab-plx-rtr-l", "ipv4_address": "172.20.20.5/24"}]}'
    )

    async def _fake_run(args, cwd=None):
        if args[0] == "version":
            return 0, "containerlab version 0.50\n", ""
        if args[0] == "deploy":
            return 0, "ok", ""
        if args[0] == "inspect":
            return 0, inspect_json, ""
        return 1, "", "unknown"

    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)
    monkeypatch.setenv("PLEXUS_LAB_WORKDIR", str(tmp_path / "labwd"))

    # Mock Netmiko helpers in the routes.shared module that lab_runtime imports.
    from netcontrol.routes import shared as shared_module

    capture_calls: list[tuple] = []
    push_calls: list[tuple] = []

    async def _fake_capture(host, credentials):
        capture_calls.append((host["ip_address"], list(credentials.keys())))
        # Two distinct configs so the diff has content.
        if len(capture_calls) == 1:
            return "hostname rtr-l\n"
        return "hostname rtr-l\nip domain-name lab.local\n"

    async def _fake_push(host, credentials, lines):
        push_calls.append((host["ip_address"], list(lines)))
        return "[push] ok"

    monkeypatch.setattr(shared_module, "_capture_running_config", _fake_capture)
    monkeypatch.setattr(shared_module, "_push_config_to_device", _fake_push)
    # lab_runtime imported the symbols at module load time, so patch there too.
    monkeypatch.setattr(lab_runtime, "_capture_running_config", _fake_capture)
    monkeypatch.setattr(lab_runtime, "_push_config_to_device", _fake_push)

    client = _auth_client(tmp_path, monkeypatch)

    # Seed a credential that the device will reference.
    async def _seed_cred():
        from routes.crypto import encrypt
        return await db_module.create_credential(
            name="lab-cred",
            username="admin",
            enc_password=encrypt("password"),
            enc_secret=encrypt(""),
        )

    cred_id = asyncio.run(_seed_cred())

    env_resp = client.post("/api/lab/environments", json={"name": "live-env"})
    assert env_resp.status_code == 200, env_resp.text
    env_id = env_resp.json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "rtr-l"},
    ).json()["id"]

    client.post(
        f"/api/lab/devices/{dev_id}/runtime/deploy",
        json={"node_kind": "linux", "image": "alpine", "credential_id": cred_id},
    )

    resp = client.post(
        f"/api/lab/devices/{dev_id}/simulate-live",
        json={"proposed_commands": ["ip domain-name lab.local"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "applied-live"
    assert body["diff_added"] >= 1
    assert "ip domain-name" in body["diff_text"]

    # Push helper was actually called against the mgmt IP.
    assert push_calls and push_calls[0][0] == "172.20.20.5"
    assert push_calls[0][1] == ["ip domain-name lab.local"]

    # The lab device snapshot now reflects the live post-state.
    detail = client.get(f"/api/lab/devices/{dev_id}").json()
    assert "ip domain-name lab.local" in detail["running_config"]
