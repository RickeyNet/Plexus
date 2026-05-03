"""Tests for Phase B-2 — multi-device lab topologies."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import netcontrol.app as app_module
import netcontrol.routes.lab_runtime as lab_runtime
import netcontrol.routes.lab_topology as lab_topology
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

    def delete(self, url, **kw):
        self._merge_headers(kw)
        return self._client.delete(url, **kw)


def _auth_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "lab_topology_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-topology")
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
async def test_topology_tables_exist_after_init(tmp_path, monkeypatch):
    db_path = str(tmp_path / "topo_migrate.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    conn = await db_module.get_db()
    try:
        for tbl in ("lab_topologies", "lab_topology_links"):
            cur = await conn.execute(
                f"SELECT name FROM sqlite_master WHERE type='table' AND name='{tbl}'"
            )
            assert await cur.fetchone() is not None, f"missing table {tbl}"
        # topology_id column on lab_devices
        cur = await conn.execute("PRAGMA table_info(lab_devices)")
        rows = await cur.fetchall()
        cols = {r[1] for r in rows}
        assert "topology_id" in cols
    finally:
        await conn.close()


# ── YAML generator unit tests ───────────────────────────────────────────────


def test_yaml_generator_emits_nodes_and_links():
    topology = {
        "id": 7, "environment_id": 1, "lab_name": "demo",
        "mgmt_subnet": "172.20.30.0/24",
    }
    devices = [
        {"id": 10, "hostname": "rtr-a", "runtime_node_kind": "ceos",
         "runtime_image": "ceos:4.30.0F"},
        {"id": 11, "hostname": "rtr-b", "runtime_node_kind": "frr",
         "runtime_image": "frrouting/frr:latest"},
    ]
    links = [
        {"a_device_id": 10, "a_endpoint": "eth1",
         "b_device_id": 11, "b_endpoint": "eth1"},
    ]
    yml = lab_topology.build_topology_yaml(topology, devices, links)
    assert "name: demo" in yml
    assert "rtr-a:" in yml and "kind: ceos" in yml
    assert "rtr-b:" in yml and "kind: frr" in yml
    assert "image: ceos:4.30.0F" in yml
    assert "image: frrouting/frr:latest" in yml
    assert "ipv4-subnet: 172.20.30.0/24" in yml
    assert 'endpoints: ["rtr-a:eth1", "rtr-b:eth1"]' in yml


def test_yaml_generator_handles_no_links():
    topology = {"id": 1, "environment_id": 1, "lab_name": "n", "mgmt_subnet": ""}
    devices = [{"id": 5, "hostname": "solo", "runtime_node_kind": "linux",
                "runtime_image": "alpine"}]
    yml = lab_topology.build_topology_yaml(topology, devices, [])
    assert "links:" not in yml
    assert "solo:" in yml


# ── HTTP CRUD tests ──────────────────────────────────────────────────────────


def _create_member_device(client, env_id, hostname, kind="linux", image="alpine"):
    """Create a lab device and set its runtime_kind/image so it's deployable."""
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": hostname, "running_config": f"hostname {hostname}\n"},
    ).json()["id"]

    async def _set_runtime():
        await db_module.update_lab_device_runtime(
            dev_id,
            runtime_kind="containerlab",
            runtime_node_kind=kind,
            runtime_image=image,
        )
    asyncio.run(_set_runtime())
    return dev_id


def test_topology_crud(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "topo-env"}).json()["id"]

    # Create
    resp = client.post(
        f"/api/lab/environments/{env_id}/topologies",
        json={"name": "core-pair", "description": "two routers"},
    )
    assert resp.status_code == 200
    topo_id = resp.json()["id"]

    # List
    resp = client.get(f"/api/lab/environments/{env_id}/topologies")
    assert resp.status_code == 200
    names = [t["name"] for t in resp.json()]
    assert "core-pair" in names

    # Get
    resp = client.get(f"/api/lab/topologies/{topo_id}")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["name"] == "core-pair"
    assert detail["devices"] == []
    assert detail["links"] == []

    # Delete
    resp = client.delete(f"/api/lab/topologies/{topo_id}")
    assert resp.status_code == 200


def test_membership_and_link_validation(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "topo-mem"}).json()["id"]
    topo_id = client.post(
        f"/api/lab/environments/{env_id}/topologies",
        json={"name": "mem-test"},
    ).json()["id"]

    a = _create_member_device(client, env_id, "rtr-a")
    b = _create_member_device(client, env_id, "rtr-b")

    # Add members.
    assert client.post(
        f"/api/lab/topologies/{topo_id}/devices",
        json={"device_id": a},
    ).status_code == 200
    assert client.post(
        f"/api/lab/topologies/{topo_id}/devices",
        json={"device_id": b},
    ).status_code == 200

    # Self-link rejected.
    bad = client.post(
        f"/api/lab/topologies/{topo_id}/links",
        json={
            "a_device_id": a, "a_endpoint": "eth1",
            "b_device_id": a, "b_endpoint": "eth2",
        },
    )
    assert bad.status_code == 400

    # Endpoint with shell metacharacters rejected.
    bad = client.post(
        f"/api/lab/topologies/{topo_id}/links",
        json={
            "a_device_id": a, "a_endpoint": "eth1; rm -rf /",
            "b_device_id": b, "b_endpoint": "eth1",
        },
    )
    assert bad.status_code == 400

    # Valid link succeeds.
    ok = client.post(
        f"/api/lab/topologies/{topo_id}/links",
        json={
            "a_device_id": a, "a_endpoint": "eth1",
            "b_device_id": b, "b_endpoint": "eth1",
        },
    )
    assert ok.status_code == 200, ok.text
    link_id = ok.json()["id"]

    # Topology detail surfaces the link.
    detail = client.get(f"/api/lab/topologies/{topo_id}").json()
    assert len(detail["devices"]) == 2
    assert len(detail["links"]) == 1
    assert detail["links"][0]["id"] == link_id


def test_member_must_belong_to_same_environment(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)
    env1 = client.post("/api/lab/environments", json={"name": "e1"}).json()["id"]
    env2 = client.post("/api/lab/environments", json={"name": "e2"}).json()["id"]
    topo = client.post(
        f"/api/lab/environments/{env1}/topologies",
        json={"name": "cross"},
    ).json()["id"]
    # Device in env2.
    dev = client.post(
        f"/api/lab/environments/{env2}/devices",
        json={"hostname": "stranger"},
    ).json()["id"]
    resp = client.post(
        f"/api/lab/topologies/{topo}/devices",
        json={"device_id": dev},
    )
    assert resp.status_code == 400


# ── Deploy / destroy with mocked subprocess ─────────────────────────────────


def test_deploy_topology_happy_path(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")
    inspect_json = (
        '{"containers": ['
        ' {"name": "clab-foo-rtr-a", "ipv4_address": "172.20.30.5/24"},'
        ' {"name": "clab-foo-rtr-b", "ipv4_address": "172.20.30.6/24"}'
        ']}'
    )
    call_log: list[list[str]] = []

    async def _fake_run(args, cwd=None):
        call_log.append(list(args))
        if args[0] == "version":
            return 0, "containerlab version 0.50\n", ""
        if args[0] == "deploy":
            return 0, "ok", ""
        if args[0] == "inspect":
            return 0, inspect_json, ""
        return 1, "", "?"

    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)
    monkeypatch.setenv("PLEXUS_LAB_WORKDIR", str(tmp_path / "labwd"))

    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "deploy-env"}).json()["id"]
    topo_id = client.post(
        f"/api/lab/environments/{env_id}/topologies",
        json={"name": "core-pair", "mgmt_subnet": "172.20.30.0/24"},
    ).json()["id"]

    a = _create_member_device(client, env_id, "rtr-a", kind="ceos", image="ceos:4.30")
    b = _create_member_device(client, env_id, "rtr-b", kind="frr", image="frrouting/frr:latest")
    client.post(f"/api/lab/topologies/{topo_id}/devices", json={"device_id": a})
    client.post(f"/api/lab/topologies/{topo_id}/devices", json={"device_id": b})
    client.post(
        f"/api/lab/topologies/{topo_id}/links",
        json={
            "a_device_id": a, "a_endpoint": "eth1",
            "b_device_id": b, "b_endpoint": "eth1",
        },
    )

    resp = client.post(f"/api/lab/topologies/{topo_id}/deploy")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "running"
    member_ids = {m["device_id"] for m in body["members"]}
    assert member_ids == {a, b}

    # Verify inspect was called and YAML was written.
    deploy_calls = [c for c in call_log if c[0] == "deploy"]
    assert deploy_calls, "expected at least one deploy call"
    yaml_path = deploy_calls[0][2]  # ['deploy', '-t', '<path>', '--reconfigure']
    from pathlib import Path
    assert Path(yaml_path).is_file()
    yml = Path(yaml_path).read_text()
    assert "rtr-a:" in yml and "rtr-b:" in yml
    assert 'endpoints: ["rtr-a:eth1", "rtr-b:eth1"]' in yml

    # Topology + member rows reflect running state.
    detail = client.get(f"/api/lab/topologies/{topo_id}").json()
    assert detail["status"] == "running"
    for d in detail["devices"]:
        assert d["runtime_status"] == "running"
        assert d["runtime_mgmt_address"]


def test_deploy_rejects_when_topology_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")
    monkeypatch.setattr(
        lab_runtime, "_run_containerlab",
        AsyncMock(return_value=(0, "version 0.50\n", "")),
    )
    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "empty-env"}).json()["id"]
    topo_id = client.post(
        f"/api/lab/environments/{env_id}/topologies",
        json={"name": "empty"},
    ).json()["id"]
    resp = client.post(f"/api/lab/topologies/{topo_id}/deploy")
    assert resp.status_code == 400
    assert "no member" in resp.text.lower()


def test_deploy_rejects_member_with_freestanding_runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")

    async def _fake_run(args, cwd=None):
        return 0, "version 0.50\n", ""

    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)
    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "fs-env"}).json()["id"]
    topo_id = client.post(
        f"/api/lab/environments/{env_id}/topologies",
        json={"name": "fs-topo"},
    ).json()["id"]
    dev = _create_member_device(client, env_id, "rtr-fs")

    # Force the device into "running" free-standing state.
    async def _force_running():
        await db_module.update_lab_device_runtime(
            dev,
            runtime_kind="containerlab",
            runtime_status="running",
            runtime_mgmt_address="10.0.0.1",
        )
    asyncio.run(_force_running())

    # Adding to topology must be rejected.
    resp = client.post(
        f"/api/lab/topologies/{topo_id}/devices",
        json={"device_id": dev},
    )
    assert resp.status_code == 409


def test_destroy_topology_clears_member_state(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")
    inspect_json = (
        '{"containers": [{"name": "clab-foo-rtr-d", "ipv4_address": "172.20.30.7/24"}]}'
    )

    async def _fake_run(args, cwd=None):
        if args[0] == "version":
            return 0, "version 0.50\n", ""
        if args[0] == "deploy":
            return 0, "ok", ""
        if args[0] == "inspect":
            return 0, inspect_json, ""
        if args[0] == "destroy":
            return 0, "destroyed", ""
        return 1, "", "?"

    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)
    monkeypatch.setenv("PLEXUS_LAB_WORKDIR", str(tmp_path / "labwd"))

    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "des-env"}).json()["id"]
    topo_id = client.post(
        f"/api/lab/environments/{env_id}/topologies",
        json={"name": "des-topo"},
    ).json()["id"]
    dev = _create_member_device(client, env_id, "rtr-d")
    client.post(f"/api/lab/topologies/{topo_id}/devices", json={"device_id": dev})
    deploy = client.post(f"/api/lab/topologies/{topo_id}/deploy")
    assert deploy.status_code == 200

    resp = client.post(f"/api/lab/topologies/{topo_id}/destroy")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "destroyed"
    assert body.get("workdir_removed") is True

    detail = client.get(f"/api/lab/topologies/{topo_id}").json()
    assert detail["status"] == "destroyed"
    assert all(d["runtime_status"] == "destroyed" for d in detail["devices"])
