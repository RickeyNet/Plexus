"""SNMP communities and v3 keys stay with admins (internal security review finding 7).

* ``GET /api/admin/snmp-profiles``: the stored profiles for an admin, the
  public view (id, name, version, port, ``has_*``) for an inventory user.
* ``GET/PUT /api/inventory/{group}/snmp-discovery-profile``: masked on read,
  and a write that sends the mask (or leaves a secret out) keeps it.
* ``POST .../snmp-discovery-profile/test``: a non-admin may only target a
  host of the group.

Every secret below is invented test data.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import netcontrol.routes.inventory as inventory_module
import netcontrol.routes.state as state
import pytest
from netcontrol.secret_fields import SECRET_MASK

from mcp_helpers import admin_client, user_client

COMMUNITY = "invented-rw-community"
AUTH_KEY = "invented-v3-auth-key"
PRIV_KEY = "invented-v3-priv-key"
SECRETS = (COMMUNITY, AUTH_KEY, PRIV_KEY)
HOST_IP = "192.0.2.21"


@pytest.fixture(autouse=True)
def _fresh_snmp_state(monkeypatch):
    monkeypatch.setattr(state, "SNMP_PROFILES", {})
    monkeypatch.setattr(state, "GROUP_SNMP_ASSIGNMENTS", {})
    monkeypatch.setattr(state, "SNMP_DISCOVERY_PROFILES", {})


@pytest.fixture
def env(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    user = user_client(admin, "inv-user", features=["inventory"])
    group = admin.post("/api/inventory", json={"name": "Lab"})
    assert group.status_code == 201, group.text
    gid = int(group.json()["id"])
    host = admin.post(
        f"/api/inventory/{gid}/hosts", json={"hostname": "sw1", "ip_address": HOST_IP, "device_type": "cisco_ios"}
    )
    assert host.status_code == 201, host.text
    profile = {
        "name": "Core",
        "enabled": True,
        "version": "3",
        "community": COMMUNITY,
        "v3": {"username": "snmp-user", "auth_password": AUTH_KEY, "priv_password": PRIV_KEY},
    }
    created = admin.post("/api/admin/snmp-profiles", json=profile)
    assert created.status_code == 200, created.text
    group_profile = {**profile, "enabled": True}
    saved = admin.put(f"/api/inventory/{gid}/snmp-discovery-profile", json=group_profile)
    assert saved.status_code == 200, saved.text
    snmp_get = AsyncMock(return_value=None)
    monkeypatch.setattr(inventory_module, "_snmp_get", snmp_get)
    return {"admin": admin, "user": user, "gid": gid, "pid": created.json()["id"], "snmp_get": snmp_get}


def _no_secret(text: str) -> bool:
    return not any(s in text for s in SECRETS)


def test_profile_list_is_public_for_non_admins(env):
    resp = env["user"].get("/api/admin/snmp-profiles")
    assert resp.status_code == 200 and _no_secret(resp.text)
    [row] = resp.json()
    assert row == {
        "id": env["pid"],
        "name": "Core",
        "enabled": True,
        "version": "3",
        "port": 161,
        "has_community": True,
        "has_v3_auth_password": True,
        "has_v3_priv_password": True,
    }
    # The admin's profile editor still gets the stored profile.
    [full] = env["admin"].get("/api/admin/snmp-profiles").json()
    assert full["community"] == COMMUNITY and full["v3"]["auth_password"] == AUTH_KEY


def test_group_discovery_profile_is_masked_and_round_trips(env):
    admin, user, gid = env["admin"], env["user"], env["gid"]
    for client in (user, admin):
        resp = client.get(f"/api/inventory/{gid}/snmp-discovery-profile")
        assert resp.status_code == 200 and _no_secret(resp.text)
        body = resp.json()
        assert body["community"] == SECRET_MASK and body["v3"]["priv_password"] == SECRET_MASK

    # Saving the masked form back (with a setting changed) keeps the secrets.
    body["port"] = 1161
    saved = admin.put(f"/api/inventory/{gid}/snmp-discovery-profile", json=body)
    assert saved.status_code == 200 and _no_secret(saved.text)
    stored = state.SNMP_DISCOVERY_PROFILES[gid]
    assert stored["port"] == 1161
    assert (stored["community"], stored["v3"]["auth_password"], stored["v3"]["priv_password"]) == SECRETS

    # Leaving the secrets out keeps them too; an explicit "" clears one.
    assert admin.put(f"/api/inventory/{gid}/snmp-discovery-profile", json={"enabled": True}).status_code == 200
    assert state.SNMP_DISCOVERY_PROFILES[gid]["community"] == COMMUNITY
    admin.put(f"/api/inventory/{gid}/snmp-discovery-profile", json={"enabled": True, "community": ""})
    assert state.SNMP_DISCOVERY_PROFILES[gid]["community"] == ""


def test_snmp_test_targets_only_group_hosts_for_non_admins(env, monkeypatch):
    admin, gid, snmp_get = env["admin"], env["gid"], env["snmp_get"]
    writer = user_client(admin, "inv-writer", features=["inventory", "inventory.write"])
    path = f"/api/inventory/{gid}/snmp-discovery-profile/test"

    outside = writer.post(path, json={"target_ip": "203.0.113.9"})
    assert outside.status_code == 403, outside.text
    snmp_get.assert_not_called()

    inside = writer.post(path, json={"target_ip": HOST_IP})
    assert inside.status_code == 200, inside.text
    assert snmp_get.await_args.args[0] == HOST_IP

    snmp_get.reset_mock()
    assert admin.post(path, json={"target_ip": "203.0.113.9"}).status_code == 200
    assert snmp_get.await_args.args[0] == "203.0.113.9"


def test_admin_listing_of_group_discovery_profiles_is_masked(env):
    admin, gid = env["admin"], env["gid"]
    resp = admin.get("/api/admin/snmp-discovery-profiles")
    assert resp.status_code == 200 and _no_secret(resp.text)
    profile = resp.json()[str(gid)]
    assert profile["community"] == SECRET_MASK
    assert (profile["v3"]["auth_password"], profile["v3"]["priv_password"]) == (SECRET_MASK, SECRET_MASK)
    assert profile["v3"]["username"] == "snmp-user"
    # The stored profiles are untouched by the masked view.
    assert state.SNMP_DISCOVERY_PROFILES[gid]["community"] == COMMUNITY


def test_global_discovery_settings_are_masked_and_round_trip(env, monkeypatch):
    admin = env["admin"]
    monkeypatch.setattr(state, "SNMP_DISCOVERY_CONFIG", state._sanitize_snmp_discovery_config({}))
    body = {
        "enabled": True,
        "version": "3",
        "community": COMMUNITY,
        "v3": {"username": "snmp-user", "auth_password": AUTH_KEY, "priv_password": PRIV_KEY},
    }
    saved = admin.put("/api/admin/snmp-discovery", json=body)
    assert saved.status_code == 200 and _no_secret(saved.text)

    read = admin.get("/api/admin/snmp-discovery")
    assert read.status_code == 200 and _no_secret(read.text)
    masked = read.json()
    assert masked["community"] == SECRET_MASK and masked["v3"]["auth_password"] == SECRET_MASK

    def stored() -> tuple[str, str, str]:
        cfg = state.SNMP_DISCOVERY_CONFIG
        return cfg["community"], cfg["v3"]["auth_password"], cfg["v3"]["priv_password"]

    # Saving the masked form back (with a setting changed) keeps the secrets.
    masked["port"] = 1161
    assert admin.put("/api/admin/snmp-discovery", json=masked).status_code == 200
    assert state.SNMP_DISCOVERY_CONFIG["port"] == 1161 and stored() == SECRETS

    # Leaving the secrets out keeps them too; a new value replaces one and "" clears one.
    assert admin.put("/api/admin/snmp-discovery", json={"enabled": False}).status_code == 200
    assert stored() == SECRETS
    admin.put("/api/admin/snmp-discovery", json={"community": "invented-new-community", "v3": {"priv_password": ""}})
    assert stored() == ("invented-new-community", AUTH_KEY, "")
