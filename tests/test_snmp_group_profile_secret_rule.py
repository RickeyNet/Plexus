"""A group's SNMP discovery profile may name only secret variables its
saving user may use.

``PUT /api/inventory/{group_id}/snmp-discovery-profile`` needs only
``inventory.write`` on the group. The group's SNMP config is resolved with no
user whenever the group is tested, scanned or polled, so a ``{{secret.NAME}}``
written into the profile's v3 keys must pass the secret's ``usable_by`` rule
for the user who saves it (403 otherwise). A secret kept as stored is not
checked again.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db
from netcontrol.routes import snmp as snmp_module, state
from routes.crypto import encrypt

from mcp_helpers import admin_client, user_client

SECRET_VALUE = "Invented-Admin-Only-SNMP-Key-5"
HOST_IP = "192.0.2.88"


class _Stop(Exception):
    pass


@pytest.fixture
def keys_sent(monkeypatch):
    """Record the USM keys ``_snmp_get`` builds; stop before any packet."""
    sent: list[dict] = []

    def fake_usm(username, **kwargs):
        sent.append({"username": username, **kwargs})
        raise _Stop("stopped before sending")

    monkeypatch.setattr(snmp_module, "UsmUserData", fake_usm)
    monkeypatch.setattr(state, "SNMP_DISCOVERY_PROFILES", dict(state.SNMP_DISCOVERY_PROFILES))
    monkeypatch.setattr(state, "GROUP_SNMP_ASSIGNMENTS", {})
    return sent


def _profile(key_ref: str) -> dict:
    return {
        "enabled": True,
        "version": "3",
        "v3": {
            "username": "invented-monitor",
            "auth_protocol": "sha",
            "auth_password": key_ref,
            "priv_protocol": "aes128",
            "priv_password": key_ref,
        },
    }


@pytest.fixture
def env(monkeypatch, request, keys_sent):
    admin = admin_client(monkeypatch, request)
    user = user_client(admin, "snmp-group-editor", features=["inventory", "inventory.write"])

    async def _seed():
        group = await db.create_group("snmp-rule-group")
        await db.add_host(group, "snmp-rule-sw2", HOST_IP, address_confirmed=True)
        await db.create_secret_variable(
            "admin_snmp_key", encrypt(SECRET_VALUE), usable_by={"roles": ["admin"], "groups": []}
        )
        await db.create_secret_variable(
            "user_snmp_key", encrypt("Invented-User-SNMP-Key-6"), usable_by={"roles": ["user"], "groups": []}
        )
        return group

    return {"admin": admin, "user": user, "group": asyncio.run(_seed()), "sent": keys_sent}


def test_group_snmp_profile_cannot_use_an_admin_only_secret(env):
    if not snmp_module.PYSMNP_AVAILABLE:
        pytest.skip("pysnmp is not installed")
    group, user = env["group"], env["user"]
    saved = user.put(f"/api/inventory/{group}/snmp-discovery-profile", json=_profile("{{secret.admin_snmp_key}}"))
    assert saved.status_code == 403, saved.text
    user.post(f"/api/inventory/{group}/snmp-discovery-profile/test", json={"target_ip": HOST_IP})
    used = [v for k in env["sent"] for v in (k.get("authKey"), k.get("privKey"))]
    assert SECRET_VALUE not in used


def test_group_snmp_profile_accepts_an_allowed_secret_and_keeps_an_admins_reference(env):
    group, user, admin = env["group"], env["user"], env["admin"]
    ok = user.put(f"/api/inventory/{group}/snmp-discovery-profile", json=_profile("{{secret.user_snmp_key}}"))
    assert ok.status_code == 200, ok.text
    by_admin = admin.put(f"/api/inventory/{group}/snmp-discovery-profile", json=_profile("{{secret.admin_snmp_key}}"))
    assert by_admin.status_code == 200, by_admin.text
    # The user changes another field and sends the keys back masked: kept, not re-checked.
    masked = user.get(f"/api/inventory/{group}/snmp-discovery-profile").json()
    masked["v3"]["username"] = "invented-monitor-2"
    kept = user.put(f"/api/inventory/{group}/snmp-discovery-profile", json=masked)
    assert kept.status_code == 200, kept.text
    assert state.SNMP_DISCOVERY_PROFILES[group]["v3"]["auth_password"] == "{{secret.admin_snmp_key}}"
