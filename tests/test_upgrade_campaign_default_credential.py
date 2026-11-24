"""An upgrade campaign with no credential of its own falls back to the
service credential, or to the default credential in Settings, under the
same per-user rule as a credential picked by hand: an admin gets the service
credential or a default credential the admin owns, and nobody gets another
user's personal credential.

Invented data only.
"""

from __future__ import annotations

import pytest
import routes.database as db
from fastapi import HTTPException
from netcontrol.routes import state, upgrades
from routes.crypto import encrypt


@pytest.fixture(autouse=True)
def _auth_config(monkeypatch):
    monkeypatch.setattr(state, "AUTH_CONFIG", {"service_credential_id": None, "default_credential_id": None})


async def _user(username: str, role: str) -> dict:
    await db.create_user(username, "x" * 64, "s" * 16, role=role)
    return await db.get_user_by_username(username)


async def _own_credential(owner: dict, name: str) -> int:
    return await db.create_credential(
        name, f"{owner['username']}-login", encrypt("Owner-Only-Pw-1"), owner_id=owner["id"]
    )


@pytest.mark.parametrize("owner_role", ["user", "admin"])
async def test_admin_campaign_does_not_borrow_another_users_default_credential(owner_role):
    await db.init_db()
    admin = await _user("camp-admin", "admin")
    owner = await _user("camp-owner", owner_role)
    theirs = await _own_credential(owner, "owner-device")
    assert await db.get_service_credentials() == []
    state.AUTH_CONFIG["default_credential_id"] = theirs

    # Picked by hand, the credential is refused; the fallback is no different.
    with pytest.raises(HTTPException) as explicit:
        await upgrades._resolve_campaign_credential(theirs, "camp-admin")
    assert explicit.value.status_code == 403

    for session in (None, {"user": "camp-admin", "user_id": admin["id"]}):
        with pytest.raises(HTTPException) as fallback:
            await upgrades._resolve_campaign_credential(None, "camp-admin", session=session)
        assert fallback.value.status_code == 403
        assert "belongs to another user" in fallback.value.detail


async def test_admin_campaign_uses_its_own_default_credential():
    await db.init_db()
    admin = await _user("camp-admin", "admin")
    mine = await _own_credential(admin, "admin-device")
    state.AUTH_CONFIG["default_credential_id"] = mine

    cred = await upgrades._resolve_campaign_credential(None, "camp-admin")
    assert int(cred["id"]) == mine


async def test_admin_campaign_uses_the_service_credential():
    await db.init_db()
    await _user("camp-admin", "admin")
    await _user("camp-user", "user")
    service = await db.create_credential("camp-svc", "svc-login", encrypt("Svc-Pw-1"), is_service=True)

    cred = await upgrades._resolve_campaign_credential(None, "camp-admin")
    assert int(cred["id"]) == service

    with pytest.raises(HTTPException) as exc:
        await upgrades._resolve_campaign_credential(None, "camp-user")
    assert exc.value.status_code == 403
    assert "only a campaign an admin created" in exc.value.detail
