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


# ── Operational hardening ───────────────────────────────────────────────────


def test_destroy_removes_workdir(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")
    inspect_json = (
        '{"containers": [{"name": "clab-plx-rtr-w", "ipv4_address": "172.20.20.5/24"}]}'
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

    workroot = tmp_path / "labwd"
    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)
    monkeypatch.setenv("PLEXUS_LAB_WORKDIR", str(workroot))

    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "wd-env"}).json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "rtr-w"},
    ).json()["id"]

    client.post(
        f"/api/lab/devices/{dev_id}/runtime/deploy",
        json={"node_kind": "linux", "image": "alpine"},
    )
    # Workdir should now exist with a topology file.
    device_workdir = workroot / f"env-{env_id}" / f"dev-{dev_id}"
    assert (device_workdir / "topology.clab.yml").is_file()

    resp = client.post(f"/api/lab/devices/{dev_id}/runtime/destroy")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "destroyed"
    assert body["workdir_removed"] is True
    assert not device_workdir.exists()


def test_reconcile_marks_stale_running_rows(tmp_path, monkeypatch):
    """If a row says 'running' but containerlab no longer reports it, mark stopped."""
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")

    deploy_inspect = '{"containers": [{"name": "clab-foo-rtr-r", "ipv4_address": "172.20.20.7/24"}]}'
    state = {"phase": "deploy"}

    async def _fake_run(args, cwd=None):
        if args[0] == "version":
            return 0, "containerlab version 0.50\n", ""
        if args[0] == "deploy":
            return 0, "ok", ""
        if args[0] == "inspect":
            # First inspect (during deploy) reports the container; later inspect
            # (during reconcile) returns nothing as if Docker was wiped.
            if state["phase"] == "deploy":
                return 0, deploy_inspect, ""
            return 0, "{}", ""
        return 1, "", "unknown"

    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)
    monkeypatch.setenv("PLEXUS_LAB_WORKDIR", str(tmp_path / "labwd"))

    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "rec-env"}).json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "rtr-r"},
    ).json()["id"]
    client.post(
        f"/api/lab/devices/{dev_id}/runtime/deploy",
        json={"node_kind": "linux", "image": "alpine"},
    )
    # Confirm we're running.
    detail = client.get(f"/api/lab/devices/{dev_id}").json()
    assert detail["runtime_status"] == "running"

    # Switch the fake inspector into "container is gone" mode and run reconcile.
    state["phase"] = "reconcile"
    summary = asyncio.run(lab_runtime.reconcile_running_labs())
    assert summary["checked"] == 1
    assert summary["marked_stopped"] == 1

    # The row should now report stopped.
    detail = client.get(f"/api/lab/devices/{dev_id}").json()
    assert detail["runtime_status"] == "stopped"
    assert detail["runtime_mgmt_address"] in ("", None)


def test_reconcile_skips_when_containerlab_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: None)

    # Seed a row directly so reconcile has work to do despite no client.
    db_path = str(tmp_path / "rec_skip.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)

    from datetime import UTC, datetime as _datetime

    async def _setup():
        await db_module.init_db()
        env_id = await db_module.create_lab_environment(name="rec-skip", shared=True)
        dev_id = await db_module.create_lab_device(
            environment_id=env_id, hostname="ghost", running_config="",
        )
        await db_module.update_lab_device_runtime(
            dev_id,
            runtime_kind="containerlab",
            runtime_node_kind="linux",
            runtime_image="alpine",
            runtime_status="running",
            runtime_lab_name="ghost",
            runtime_node_name="ghost",
            runtime_started_at=_datetime.now(UTC).isoformat(),
        )
        return dev_id

    asyncio.run(_setup())
    summary = asyncio.run(lab_runtime.reconcile_running_labs())
    assert summary["skipped"] == 1
    assert summary["marked_stopped"] == 0


def test_reap_idle_runtimes_destroys_old_labs(tmp_path, monkeypatch):
    """Rows older than the configured TTL should be torn down."""
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")
    inspect_json = (
        '{"containers": [{"name": "clab-plx-rtr-t", "ipv4_address": "172.20.20.9/24"}]}'
    )

    destroy_calls: list[list[str]] = []

    async def _fake_run(args, cwd=None):
        if args[0] == "version":
            return 0, "containerlab version 0.50\n", ""
        if args[0] == "deploy":
            return 0, "ok", ""
        if args[0] == "inspect":
            return 0, inspect_json, ""
        if args[0] == "destroy":
            destroy_calls.append(list(args))
            return 0, "destroyed", ""
        return 1, "", "unknown"

    monkeypatch.setattr(lab_runtime, "_run_containerlab", _fake_run)
    monkeypatch.setenv("PLEXUS_LAB_WORKDIR", str(tmp_path / "labwd"))
    # Set TTL to 1 second so anything started before "now" qualifies.
    monkeypatch.setenv("PLEXUS_LAB_RUNTIME_TTL_SECONDS", "1")

    client = _auth_client(tmp_path, monkeypatch)
    env_id = client.post("/api/lab/environments", json={"name": "ttl-env"}).json()["id"]
    dev_id = client.post(
        f"/api/lab/environments/{env_id}/devices",
        json={"hostname": "rtr-t"},
    ).json()["id"]
    client.post(
        f"/api/lab/devices/{dev_id}/runtime/deploy",
        json={"node_kind": "linux", "image": "alpine"},
    )

    # Force runtime_started_at into the past so the TTL check catches it.
    async def _backdate():
        from datetime import UTC, datetime, timedelta
        await db_module.update_lab_device_runtime(
            dev_id,
            runtime_started_at=(datetime.now(UTC) - timedelta(hours=48)).isoformat(),
        )

    asyncio.run(_backdate())

    summary = asyncio.run(lab_runtime.reap_idle_runtimes())
    assert summary["reaped"] == 1
    assert any("destroy" in args for args in destroy_calls)

    detail = client.get(f"/api/lab/devices/{dev_id}").json()
    assert detail["runtime_status"] == "destroyed"


def test_reap_idle_runtimes_disabled_when_ttl_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("PLEXUS_LAB_RUNTIME_TTL_SECONDS", "0")
    summary = asyncio.run(lab_runtime.reap_idle_runtimes())
    assert summary["ttl_seconds"] == 0
    assert summary["reaped"] == 0
    assert summary["checked"] == 0


# ── Compliance scoring on simulate paths ────────────────────────────────────


def _seed_compliance_profile_blocking_snmp_public(group_id: int):
    """Helper: create a compliance profile that fails when 'snmp-server community public' appears."""
    import json as _json
    from routes.crypto import encrypt as _encrypt

    async def _do():
        rules = [
            {
                "name": "no public SNMP community",
                "type": "must_not_contain",
                "pattern": "snmp-server community public",
            },
        ]
        prof_id = await db_module.create_compliance_profile(
            name="block-snmp-public",
            description="",
            severity="critical",
            rules=_json.dumps(rules),
        )
        cred_id = await db_module.create_credential(
            name=f"comp-cred-{group_id}",
            username="admin",
            enc_password=_encrypt("password"),
            enc_secret=_encrypt(""),
        )
        await db_module.create_compliance_assignment(
            profile_id=prof_id,
            group_id=group_id,
            credential_id=cred_id,
        )
        return prof_id

    return asyncio.run(_do())


def test_simulate_offline_includes_compliance_impact(tmp_path, monkeypatch):
    """Phase A simulate should now surface compliance regressions when the source host has profiles."""
    client = _auth_client(tmp_path, monkeypatch)

    async def _seed():
        gid = await db_module.create_group(name="comp-grp")
        hid = await db_module.add_host(
            group_id=gid, hostname="prod-rtr-c", ip_address="10.5.5.1",
        )
        return gid, hid

    gid, hid = asyncio.run(_seed())
    _seed_compliance_profile_blocking_snmp_public(gid)

    env_id = client.post("/api/lab/environments", json={"name": "comp-env"}).json()["id"]
    # Create lab device referencing source host so compliance lookup works.
    async def _seed_dev():
        return await db_module.create_lab_device(
            environment_id=env_id,
            hostname="twin-c",
            source_host_id=hid,
            running_config="hostname twin-c\n",
        )

    dev_id = asyncio.run(_seed_dev())

    resp = client.post(
        f"/api/lab/devices/{dev_id}/simulate",
        json={"proposed_commands": ["snmp-server community public RO"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    detail = body.get("risk_detail", {})
    assert detail.get("compliance_violations_introduced", 0) >= 1
    assert any(
        "compliance" in (rf or "").lower()
        for rf in detail.get("risk_factors", [])
    )
