"""Regression tests for admin user-management hardening.

* delete_user_guarded refuses to remove the last admin, with the check inside
  the DELETE statement so concurrent deletes can't both slip through and lock
  everyone out.
* create/update user reject an invalid role instead of silently coercing it.
* an admin sets which sign-in provider an account belongs to
  (``auth_provider`` on ``PUT /api/admin/users/{id}``).
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module


@pytest.fixture
def user_db(monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-admin-users")
    asyncio.run(db_module.init_db())


async def _mk(username: str, role: str) -> int:
    return await db_module.create_user(username, "hash", "salt", display_name=username, role=role)


def test_delete_user_guarded_blocks_last_admin(user_db):
    async def _go():
        a1 = await _mk("admin1", "admin")
        a2 = await _mk("admin2", "admin")
        u1 = await _mk("user1", "user")

        # A regular user deletes fine.
        assert await db_module.delete_user_guarded(u1) == "deleted"
        # One of two admins deletes fine.
        assert await db_module.delete_user_guarded(a1) == "deleted"
        # The last admin is protected.
        assert await db_module.delete_user_guarded(a2) == "last_admin"
        # ...and is still present.
        assert await db_module.get_user_by_id(a2) is not None

    asyncio.run(_go())


def test_delete_user_guarded_not_found(user_db):
    async def _go():
        assert await db_module.delete_user_guarded(999999) == "not_found"

    asyncio.run(_go())


# ── HTTP role validation ─────────────────────────────────────────────────────


def _auth_client(monkeypatch, request):
    import netcontrol.app as app_module

    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-admin-http")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    csrf = resp.json().get("csrf_token", "")
    return client, csrf


def test_create_user_rejects_invalid_role(monkeypatch, request):
    client, csrf = _auth_client(monkeypatch, request)
    resp = client.post(
        "/api/admin/users",
        json={"username": "bob", "password": "password123", "role": "administrator"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 400


def test_create_user_accepts_valid_role(monkeypatch, request):
    client, csrf = _auth_client(monkeypatch, request)
    resp = client.post(
        "/api/admin/users",
        json={"username": "carol", "password": "password123", "role": "user"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201


# ── Sign-in provider of an account ───────────────────────────────────────────
#
# An external sign-in never takes over an existing account on its own
# (tests/test_external_account_adoption.py); an admin hands one over by
# setting its provider here.


def _create(client, csrf, username: str) -> dict:
    resp = client.post(
        "/api/admin/users",
        json={"username": username, "password": "password123", "role": "user"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _set_provider(client, csrf, user_id: int, provider: str):
    return client.put(f"/api/admin/users/{user_id}", json={"auth_provider": provider}, headers={"X-CSRF-Token": csrf})


def test_new_and_listed_users_show_their_provider(monkeypatch, request):
    client, csrf = _auth_client(monkeypatch, request)
    created = _create(client, csrf, "dave")
    listed = {u["username"]: u for u in client.get("/api/admin/users").json()}
    assert listed["dave"]["auth_provider"] == "local"
    assert listed["dave"]["id"] == created["id"]


def test_admin_hands_a_local_account_to_an_external_provider(monkeypatch, request):
    import netcontrol.routes.auth as auth

    client, csrf = _auth_client(monkeypatch, request)
    user_id = _create(client, csrf, "erin")["id"]
    call = client.portal.call

    # Refused while the account is local...
    assert call(auth.upsert_external_user, "erin", "", "user", "ldap") is None
    epoch_before = call(db_module.get_user_by_id, user_id)["session_epoch"]

    resp = _set_provider(client, csrf, user_id, "LDAP")
    assert resp.status_code == 200, resp.text
    assert resp.json()["auth_provider"] == "ldap"

    row = call(db_module.get_user_by_username, "erin")
    assert row["auth_provider"] == "ldap"
    # Open sessions of the account end with the change.
    assert call(db_module.get_user_by_id, user_id)["session_epoch"] != epoch_before
    # ...and accepted afterwards, for that provider only.
    assert call(auth.upsert_external_user, "erin", "", "user", "ldap") is not None
    assert call(auth.upsert_external_user, "erin", "", "user", "radius") is None

    events = call(db_module.get_audit_events, 50)
    change = [e for e in events if e["action"] == "user.provider_change"]
    assert len(change) == 1
    assert "local -> ldap" in change[0]["detail"] and change[0]["user"] == "admin"


def test_changing_the_provider_forgets_the_bound_sso_subject(monkeypatch, request):
    client, csrf = _auth_client(monkeypatch, request)
    user_id = _create(client, csrf, "frank")["id"]
    call = client.portal.call
    assert _set_provider(client, csrf, user_id, "oidc").status_code == 200
    call(db_module.set_user_external_id, user_id, "subject-0001")

    # The same provider again changes nothing: the binding stays.
    assert _set_provider(client, csrf, user_id, "oidc").status_code == 200
    assert call(db_module.get_user_by_username, "frank")["external_id"] == "subject-0001"

    assert _set_provider(client, csrf, user_id, "saml").status_code == 200
    row = call(db_module.get_user_by_username, "frank")
    assert (row["auth_provider"], row["external_id"]) == ("saml", "")

    resp = _set_provider(client, csrf, user_id, "local")
    assert resp.status_code == 200 and resp.json()["auth_provider"] == "local"
    assert call(db_module.get_user_by_username, "frank")["auth_provider"] == ""


def test_an_unknown_provider_is_rejected_and_other_updates_leave_it_alone(monkeypatch, request):
    client, csrf = _auth_client(monkeypatch, request)
    user_id = _create(client, csrf, "grace")["id"]
    assert _set_provider(client, csrf, user_id, "kerberos").status_code == 400
    assert _set_provider(client, csrf, user_id, "radius").status_code == 200

    resp = client.put(f"/api/admin/users/{user_id}", json={"display_name": "Grace"}, headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    assert resp.json()["auth_provider"] == "radius"


def test_setting_the_provider_needs_an_admin(monkeypatch, request):
    client, csrf = _auth_client(monkeypatch, request)
    user_id = _create(client, csrf, "henry")["id"]
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    resp = client.post("/api/auth/login", json={"username": "henry", "password": "password123"})
    assert resp.status_code == 200, resp.text
    own_csrf = resp.json().get("csrf_token", "")
    assert _set_provider(client, own_csrf, user_id, "ldap").status_code == 403
    assert client.portal.call(db_module.get_user_by_username, "henry")["auth_provider"] == ""
