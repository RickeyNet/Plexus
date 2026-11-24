"""A local password belongs to a local account only.

An account an external provider manages (``users.auth_provider`` set) is
never signed in with a password Plexus holds: not on the local provider
path, not through local fallback, not as break-glass. An admin cannot give
it one, changing the provider clears the one it had, and the account's own
change-password form is refused. Also the change-password attempt limit,
which must hold for requests sent together. Every name is invented.
"""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.auth as auth
import pytest
import routes.database as db_module
from fastapi import HTTPException
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, create_user

LOGIN = "/api/auth/login"
CHANGE = "/api/auth/change-password"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    monkeypatch.setattr(app_module, "LOGIN_USERNAME_FAILURES", {}, raising=False)
    monkeypatch.setattr(auth, "_PASSWORD_CHANGE_ATTEMPTS", {})
    return client


def _login(username: str, password: str = "password123"):
    browser = TestClient(app_module.app, raise_server_exceptions=False)
    return browser, browser.post(LOGIN, json={"username": username, "password": password})


def _message(resp) -> str:
    return resp.json()["error"]["message"]


def _set_provider(admin: CsrfClient, user_id: int, provider: str):
    return admin.put(f"/api/admin/users/{user_id}", json={"auth_provider": provider})


def _reset(admin: CsrfClient, user_id: int, password: str):
    return admin.put(f"/api/admin/users/{user_id}/password", json={"new_password": password})


# ── sign-in ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("role", ["user", "admin"])
def test_a_managed_account_never_signs_in_with_a_local_password(admin, role):
    """The hash still matches (an account handed over by an older release):
    the provider on the account decides, also for an admin (break-glass)."""
    user_id = create_user(admin, "laura", role=role)
    assert _login("laura")[1].status_code == 200
    call = admin.raw.portal.call
    call(db_module.set_user_auth_provider, user_id, "oidc")

    resp = _login("laura")[1]
    assert resp.status_code == 401
    assert _message(resp) == "Invalid username or password"
    assert call(app_module.verify_user, "laura", "password123") is None

    # A local account of the same shape keeps signing in.
    call(db_module.set_user_auth_provider, user_id, "")
    assert _login("laura")[1].status_code == 200


def test_local_fallback_does_not_accept_a_managed_account(admin, monkeypatch):
    user_id = create_user(admin, "mike")
    admin.raw.portal.call(db_module.set_user_auth_provider, user_id, "ldap")

    async def directory_down(username, password):
        return False, "error", {}

    monkeypatch.setattr(app_module, "verify_ldap_user", directory_down)
    monkeypatch.setitem(app_module.state.AUTH_CONFIG, "provider", "ldap")
    monkeypatch.setitem(app_module.state.AUTH_CONFIG, "ldap", {"enabled": True, "fallback_to_local": True})
    create_user(admin, "olga-admin", role="admin")
    assert _login("mike")[1].status_code == 401
    # A local admin still gets in while the directory is down (break-glass).
    _, resp = _login("olga-admin")
    assert resp.status_code == 200
    assert resp.json()["auth_source"] == "local-admin-breakglass"


# ── admin actions ────────────────────────────────────────────────────────────


def test_changing_the_provider_clears_the_local_password(admin):
    user_id = create_user(admin, "nina")
    call = admin.raw.portal.call
    before = call(db_module.get_user_by_username, "nina")

    assert _set_provider(admin, user_id, "ldap").status_code == 200
    handed = call(db_module.get_user_by_username, "nina")
    assert (handed["password_hash"], handed["salt"]) != (before["password_hash"], before["salt"])
    assert _login("nina")[1].status_code == 401

    # Back to local: the old password does not come back...
    assert _set_provider(admin, user_id, "local").status_code == 200
    assert _login("nina")[1].status_code == 401
    # ...an admin sets a new one.
    assert _reset(admin, user_id, "a-new-password-1").status_code == 200
    assert _login("nina", "a-new-password-1")[1].status_code == 200

    events = call(db_module.get_audit_events, 50)
    changes = [e["detail"] for e in events if e["action"] == "user.provider_change"]
    assert len(changes) == 2 and all("local password cleared" in d for d in changes)


def test_an_update_that_keeps_the_provider_keeps_the_password(admin):
    user_id = create_user(admin, "omar")
    assert _set_provider(admin, user_id, "local").status_code == 200
    assert admin.put(f"/api/admin/users/{user_id}", json={"display_name": "Omar"}).status_code == 200
    assert _login("omar")[1].status_code == 200


def test_admin_cannot_set_a_password_on_a_managed_account(admin):
    user_id = create_user(admin, "paula")
    assert _set_provider(admin, user_id, "saml").status_code == 200
    stored = admin.raw.portal.call(db_module.get_user_by_username, "paula")

    resp = _reset(admin, user_id, "a-new-password-1")
    assert resp.status_code == 400
    assert "saml" in _message(resp) and "local" in _message(resp)
    after = admin.raw.portal.call(db_module.get_user_by_username, "paula")
    assert (after["password_hash"], after["salt"]) == (stored["password_hash"], stored["salt"])
    assert _login("paula", "a-new-password-1")[1].status_code == 401


# ── the account's own change-password form ───────────────────────────────────


def test_change_password_is_refused_for_a_managed_account(admin):
    user_id = create_user(admin, "quinn")
    browser, resp = _login("quinn")
    session = CsrfClient(browser, resp.json()["csrf_token"])
    # Set in the database only, so the open session stays valid.
    admin.raw.portal.call(db_module.set_user_auth_provider, user_id, "oidc")

    resp = session.post(CHANGE, json={"current_password": "password123", "new_password": "a-new-password-1"})
    assert resp.status_code == 400
    assert "sign-in service" in _message(resp)
    # Not counted as a wrong current password.
    assert user_id not in auth._PASSWORD_CHANGE_ATTEMPTS


def test_change_password_limit_and_reset_on_success(admin):
    create_user(admin, "rosa")
    browser, resp = _login("rosa")
    session = CsrfClient(browser, resp.json()["csrf_token"])

    def change(current: str, new: str = "a-new-password-1"):
        return session.post(CHANGE, json={"current_password": current, "new_password": new})

    for _ in range(2):
        assert change("wrong-guess").status_code == 400
    # The right password clears the count...
    ok = change("password123")
    assert ok.status_code == 200, ok.text
    for _ in range(auth._PASSWORD_CHANGE_MAX):
        assert change("wrong-guess").status_code == 400
    # ...and past the limit even the right one waits.
    assert change("a-new-password-1", "another-password-2").status_code == 429


def test_change_password_limit_holds_for_parallel_requests(monkeypatch):
    """Requests sent together must not all pass the check before the first
    slow hash comparison returns."""
    monkeypatch.setattr(auth, "_PASSWORD_CHANGE_ATTEMPTS", {})
    checked = 0

    async def slow_wrong_password(username, password):
        nonlocal checked
        checked += 1
        await asyncio.sleep(0.05)
        return None

    async def no_account(user_id):
        return None

    monkeypatch.setattr(auth, "_verify_user_fn", slow_wrong_password)
    monkeypatch.setattr(auth, "_get_session", lambda request: {"user": "sam", "user_id": 4242})
    monkeypatch.setattr(auth.db, "get_user_by_id", no_account)
    body = auth.ChangePasswordRequest(current_password="guess", new_password="a-new-password-1")

    async def attempt() -> int:
        try:
            await auth.change_password(body, None)
        except HTTPException as exc:
            return exc.status_code
        return 200

    async def burst() -> list[int]:
        return await asyncio.gather(*(attempt() for _ in range(12)))

    codes = asyncio.run(burst())
    assert codes.count(400) == auth._PASSWORD_CHANGE_MAX
    assert codes.count(429) == 12 - auth._PASSWORD_CHANGE_MAX
    assert checked == auth._PASSWORD_CHANGE_MAX
