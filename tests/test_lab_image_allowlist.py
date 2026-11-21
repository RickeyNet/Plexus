"""Lab image allowlist (SECURITY_AUDIT finding 13 / INJ-2): a user who is
not an admin may deploy only container images an admin allowed; prefix
entries match whole path segments and the exact registry host; admins may
deploy any image that passes the character check."""

from __future__ import annotations

from unittest.mock import AsyncMock

import netcontrol.routes.lab_runtime as lab_runtime
import pytest
from netcontrol import lab_images
from starlette.testclient import TestClient

from test_lab_runtime import _auth_client, _LabClient
from test_lab_topology import _create_member_device

ALLOWLIST = "/api/admin/lab-image-allowlist"


# ── Matching ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("image", "entries", "allowed"),
    [
        ("registry.example.com/team/frr:1", ["registry.example.com/team"], True),
        ("registry.example.com/team:2", ["registry.example.com/team"], True),
        ("registry.example.com/team/sub/x", ["registry.example.com/team/"], True),
        ("registry.example.com/team-evil/x:1", ["registry.example.com/team"], False),
        ("registry.example.com.attacker.example/team/x", ["registry.example.com/team"], False),
        ("registry.example.com.attacker.example/team/x", ["registry.example.com/"], False),
        ("attacker.example/registry.example.com/team/x", ["registry.example.com/team"], False),
        ("registry.example.com/team/../evil/x", ["registry.example.com/team"], False),
        ("registry.example.com/x:1", ["registry.example.com/"], True),
        ("REGISTRY.example.com/team/x", ["registry.example.com/team"], True),
        # Docker Hub normalisation: no registry is docker.io, one part is library/.
        ("ceos:4.30.0F", ["ceos"], True),
        ("docker.io/library/ceos:4.30.0F", ["ceos"], True),
        ("ceos-evil:1", ["ceos"], False),
        ("frrouting/frr", ["frrouting/frr:latest"], True),
        ("frrouting/frr:8.4", ["frrouting/frr:latest"], False),
        ("frrouting/frr:latest", ["docker.io/frrouting/"], True),
        ("evil/frr:latest", ["frrouting/"], False),
        ("alpine", [], False),
    ],
)
def test_image_allowed(image, entries, allowed):
    assert lab_images.image_allowed(image, entries) is allowed


def test_entries_are_validated():
    assert lab_images.validate_entries([" ceos ", "ceos", "registry.example.com/team/"]) == [
        "ceos",
        "registry.example.com/team/",
    ]
    for bad in (["a b"], ["x;rm"], ["reg.example.com/../x"], "ceos", [1]):
        with pytest.raises(ValueError):
            lab_images.validate_entries(bad)


# ── HTTP ─────────────────────────────────────────────────────────────────────


def _lab_user(admin: _LabClient, name: str) -> _LabClient:
    """A user who is not an admin, with the lab feature (read and write)."""
    group = admin.post("/api/admin/access-groups", json={"name": f"{name} lab", "feature_keys": ["lab", "lab.write"]})
    assert group.status_code == 201, group.text
    user = admin.post(
        "/api/admin/users",
        json={"username": name, "password": "password123", "group_ids": [group.json()["id"]]},
    )
    assert user.status_code == 201, user.text
    client = TestClient(admin._client.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": name, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return _LabClient(client, resp.json()["csrf_token"])


def _put(admin: _LabClient, entries) -> object:
    return admin._client.put(ALLOWLIST, json={"entries": entries}, headers={"X-CSRF-Token": admin._csrf})


@pytest.fixture
def lab(monkeypatch, request, tmp_path):
    """containerlab "available" with every CLI call failing after validation,
    so a deploy that passes the image checks ends in a runtime error (not
    403) without running anything."""
    monkeypatch.setattr(lab_runtime.shutil, "which", lambda _n: "/usr/bin/containerlab")

    async def fake_run(args, cwd=None):
        if args[0] == "version":
            return 0, "containerlab version 0.50\n", ""
        return 1, "", "simulated failure"

    monkeypatch.setattr(lab_runtime, "_run_containerlab", AsyncMock(side_effect=fake_run))
    monkeypatch.setenv("PLEXUS_LAB_WORKDIR", str(tmp_path / "labwd"))
    admin = _auth_client(monkeypatch, request)
    return admin, _lab_user(admin, "labuser")


def _own_device(client: _LabClient, hostname: str = "rtr1") -> tuple[int, int]:
    env = client.post("/api/lab/environments", json={"name": f"{hostname}-env"})
    assert env.status_code in (200, 201), env.text
    env_id = env.json()["id"]
    dev = client.post(
        f"/api/lab/environments/{env_id}/devices", json={"hostname": hostname, "running_config": "hostname x\n"}
    )
    assert dev.status_code in (200, 201), dev.text
    return env_id, dev.json()["id"]


def _deploy(client: _LabClient, dev_id: int, image: str):
    return client.post(f"/api/lab/devices/{dev_id}/runtime/deploy", json={"node_kind": "vr-csr", "image": image})


def test_allowlist_admin_api(lab):
    admin, user = lab
    assert admin.get(ALLOWLIST).json() == {"entries": []}
    resp = _put(admin, ["registry.example.com/team/", "ceos"])
    assert resp.status_code == 200, resp.text
    assert admin.get(ALLOWLIST).json() == {"entries": ["registry.example.com/team/", "ceos"]}
    assert _put(admin, ["bad image"]).status_code == 422
    # Not an admin: refused.
    assert user.get(ALLOWLIST).status_code == 403
    assert user._client.put(ALLOWLIST, json={"entries": ["x"]}, headers={"X-CSRF-Token": user._csrf}).status_code == 403


def test_non_admin_deploy_needs_an_allowlisted_image(lab):
    admin, user = lab
    _, dev_id = _own_device(user)

    # Empty allowlist: nothing goes.
    resp = _deploy(user, dev_id, "registry.example.com/x/rootkit:1")
    assert resp.status_code == 403, resp.text
    assert "allowlist" in resp.text

    assert _put(admin, ["registry.example.com/team"]).status_code == 200
    for image in ("registry.example.com/team-evil/x:1", "registry.example.com.attacker.example/team/x:1"):
        assert _deploy(user, dev_id, image).status_code == 403, image

    # An allowlisted image passes the checks (the fake containerlab then fails).
    resp = _deploy(user, dev_id, "registry.example.com/team/frr:1")
    assert resp.status_code != 403, resp.text


def test_admin_deploys_any_safe_image(lab):
    admin, _ = lab
    _, dev_id = _own_device(admin, "rtr-admin")
    resp = _deploy(admin, dev_id, "registry.example.com/anything/x:1")
    assert resp.status_code != 403, resp.text
    assert _deploy(admin, dev_id, "x;rm -rf /").status_code == 400


def test_non_admin_topology_deploy_checks_member_images(lab):
    admin, user = lab
    env_id, _ = _own_device(user, "seed")
    topo = user.post(f"/api/lab/environments/{env_id}/topologies", json={"name": "pair"})
    assert topo.status_code in (200, 201), topo.text
    topo_id = topo.json()["id"]
    a = _create_member_device(user, env_id, "rtr-a", kind="ceos", image="ceos:4.30")
    b = _create_member_device(user, env_id, "rtr-b", kind="frr", image="registry.example.com/x/payload:1")
    for dev in (a, b):
        assert user.post(f"/api/lab/topologies/{topo_id}/devices", json={"device_id": dev}).status_code in (200, 201)

    assert _put(admin, ["ceos"]).status_code == 200
    resp = user.post(f"/api/lab/topologies/{topo_id}/deploy")
    assert resp.status_code == 403, resp.text
    assert "rtr-b" in resp.text

    assert _put(admin, ["ceos", "registry.example.com/x/payload:1"]).status_code == 200
    assert user.post(f"/api/lab/topologies/{topo_id}/deploy").status_code != 403
