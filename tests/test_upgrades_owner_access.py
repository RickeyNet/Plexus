"""Upgrade campaigns are owner-or-admin objects (SECURITY_AUDIT finding 6).

A campaign runs with its creator's credential, so another ``upgrades`` user
may not change, run, cancel, delete or read it, nor fetch its prestage
backups. A campaign with no credential falls back to the Plexus service
credential only when an admin created it.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module
from fastapi import HTTPException
from netcontrol.routes import upgrades
from routes.crypto import encrypt

from mcp_helpers import admin_client, user_client

AD_HOC_IP = "192.0.2.10"
IMAGE_MAP = {"C9200": "cat9k_iosxe.17.15.05.SPA.bin"}


def _campaign(client, name: str) -> int:
    resp = client.post(
        "/api/upgrades/campaigns",
        json={"name": name, "ad_hoc_ips": [AD_HOC_IP], "image_map": IMAGE_MAP},
    )
    assert resp.status_code == 200, resp.text
    return int(resp.json()["id"])


@pytest.fixture
def env(monkeypatch, request, tmp_path):
    admin = admin_client(monkeypatch, request)
    alice = user_client(admin, "alice", features=["upgrades", "upgrades.write"])
    bob = user_client(admin, "bob", features=["upgrades", "upgrades.write"])

    started: list[dict] = []

    def fake_run_phase(_cid, _phase, _devices, credentials, *_a, **_k):
        started.append(credentials)
        return asyncio.sleep(0)

    monkeypatch.setattr(upgrades, "NETMIKO_AVAILABLE", True)
    monkeypatch.setattr(upgrades, "_run_phase", fake_run_phase)
    monkeypatch.setattr(upgrades, "BACKUPS_DIR", str(tmp_path))
    asyncio.run(db_module.create_credential("svc", "svc-user", encrypt("svc-pass"), is_service=True))
    return {"admin": admin, "alice": alice, "bob": bob, "started": started, "backups": tmp_path}


def test_other_user_cannot_touch_a_campaign(env):
    alice, bob = env["alice"], env["bob"]
    cid = _campaign(alice, "alice-camp")
    device_id = int(alice.get(f"/api/upgrades/campaigns/{cid}").json()["devices"][0]["id"])
    update = {"name": "taken", "ad_hoc_ips": [AD_HOC_IP], "image_map": IMAGE_MAP}

    calls = [
        ("get", f"/api/upgrades/campaigns/{cid}", None),
        ("get", f"/api/upgrades/campaigns/{cid}/events", None),
        ("patch", f"/api/upgrades/campaigns/{cid}", update),
        ("post", f"/api/upgrades/campaigns/{cid}/execute", {"phase": "prestage"}),
        ("post", f"/api/upgrades/campaigns/{cid}/cancel", None),
        ("post", f"/api/upgrades/campaigns/{cid}/devices/cancel", {"device_ids": [device_id], "phase": "prestage"}),
        ("post", f"/api/upgrades/campaigns/{cid}/devices/{device_id}/logic-reset-confirm", None),
        ("delete", f"/api/upgrades/campaigns/{cid}", None),
    ]
    for method, path, body in calls:
        kwargs = {"json": body} if body is not None else {}
        resp = getattr(bob, method)(path, **kwargs)
        assert resp.status_code == 403, f"{method} {path}: {resp.status_code} {resp.text}"

    assert env["started"] == []
    # The campaign is untouched, and its owner still has it.
    camp = alice.get(f"/api/upgrades/campaigns/{cid}")
    assert camp.status_code == 200
    assert camp.json()["name"] == "alice-camp"
    # An admin may act on it.
    assert env["admin"].get(f"/api/upgrades/campaigns/{cid}").status_code == 200


def test_non_admin_campaign_without_credential_does_not_use_service_credential(env):
    alice = env["alice"]
    cid = _campaign(alice, "ad-hoc")
    resp = alice.post(f"/api/upgrades/campaigns/{cid}/execute", json={"phase": "prestage"})
    assert resp.status_code == 403, resp.text
    assert "service credential" in resp.text
    assert env["started"] == []


def test_admin_campaign_without_credential_uses_service_credential(env):
    admin = env["admin"]
    cid = _campaign(admin, "admin-ad-hoc")
    resp = admin.post(f"/api/upgrades/campaigns/{cid}/execute", json={"phase": "prestage"})
    assert resp.status_code == 200, resp.text
    assert env["started"] and env["started"][0]["username"] == "svc-user"


@pytest.mark.asyncio
async def test_resolve_fallback_refuses_non_admin_creator_without_request():
    """A scheduled run rehydrated with no request is checked against the
    creator, so a non-admin's campaign never gets the service credential."""
    await db_module.create_user("carol", "hash", "salt", role="user")
    await db_module.create_credential("svc", "svc-user", encrypt("p"), is_service=True)
    with pytest.raises(HTTPException) as exc:
        await upgrades._resolve_campaign_credential(None, "carol")
    assert exc.value.status_code == 403


def test_prestage_backups_are_owner_only(env):
    admin, alice, bob = env["admin"], env["alice"], env["bob"]
    cid = _campaign(alice, "with-backup")
    own = f"backup_sw1_20260101_010101_campaign{cid}.txt"
    legacy = "backup_sw2_20250101_010101.txt"
    for name in (own, legacy):
        (env["backups"] / name).write_text("hostname example\n")

    def names(client):
        resp = client.get("/api/upgrades/backups")
        assert resp.status_code == 200, resp.text
        return {b["filename"] for b in resp.json()}

    assert names(admin) == {own, legacy}
    assert names(alice) == {own}
    assert names(bob) == set()

    assert alice.get(f"/api/upgrades/backups/{own}").status_code == 200
    assert bob.get(f"/api/upgrades/backups/{own}").status_code == 403
    assert alice.get(f"/api/upgrades/backups/{legacy}").status_code == 403
    assert admin.get(f"/api/upgrades/backups/{legacy}").status_code == 200
    assert bob.delete(f"/api/upgrades/backups/{own}").status_code == 403
    assert (env["backups"] / own).exists()


def test_backup_campaign_id_is_parsed_from_the_name_only():
    assert upgrades._backup_campaign_id("backup_sw1_20260101_010101_campaign12.txt") == 12
    assert upgrades._backup_campaign_id("backup_sw1_20260101_010101.txt") is None
    # A hostname cannot smuggle an id in front of the timestamp.
    assert upgrades._backup_campaign_id("backup_x_campaign3_20260101_010101.txt") is None
