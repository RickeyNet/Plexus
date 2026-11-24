"""An admin switches an account off without deleting it (``users.disabled``).

A disabled account cannot sign in by any method (password form, directory,
single sign-on) and gets the answer a wrong password gets, its open sessions
end at once and stay dead after it is re-enabled, and the AI-access tokens it
owns stop working. An admin cannot disable their own account or the last
enabled admin. Every name is invented.
"""

from __future__ import annotations

from functools import partial

import netcontrol.app as app_module
import netcontrol.routes.auth as auth
import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from netcontrol.mcp import auth as mcp_auth
from netcontrol.sso import SsoIdentity
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, admin_id, create_token, create_user

LOGIN = "/api/auth/login"
USERS = "/api/admin/users"
API_TOKEN = "test-token-account-disabled"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    monkeypatch.setattr(app_module, "LOGIN_USERNAME_FAILURES", {}, raising=False)
    return client


def _login(username: str, password: str = "password123"):
    browser = TestClient(app_module.app, raise_server_exceptions=False)
    return browser, browser.post(LOGIN, json={"username": username, "password": password})


def _message(resp) -> str:
    return resp.json()["error"]["message"]


def _set_disabled(admin: CsrfClient, user_id: int, disabled: bool):
    return admin.put(f"{USERS}/{user_id}", json={"disabled": disabled})


def _audit_details(admin: CsrfClient, action: str) -> list[str]:
    rows = admin.raw.portal.call(db_module.get_audit_events, 500)
    return [r.get("detail") or "" for r in rows if r.get("action") == action]


# ── password sign-in and sessions ────────────────────────────────────────────


def test_disabled_local_account_gets_the_wrong_password_answer(admin):
    """The right password is refused like a wrong one; the audit says why."""
    user_id = create_user(admin, "nadia")
    assert _set_disabled(admin, user_id, True).status_code == 200

    resp = _login("nadia")[1]
    assert resp.status_code == 401
    assert _message(resp) == _message(_login("nadia", "wrong-password")[1]) == "Invalid username or password"
    assert any("account disabled" in d for d in _audit_details(admin, "login.failure"))


def test_wrong_password_for_a_disabled_account_does_not_say_disabled(admin):
    """The password is checked first: a wrong one is audited as a plain failure."""
    user_id = create_user(admin, "oskar")
    _set_disabled(admin, user_id, True)
    before = len([d for d in _audit_details(admin, "login.failure") if "account disabled" in d])

    assert _login("oskar", "not-the-password")[1].status_code == 401
    after = len([d for d in _audit_details(admin, "login.failure") if "account disabled" in d])
    assert after == before


def test_disabling_ends_an_open_session(admin):
    user_id = create_user(admin, "petra")
    browser, resp = _login("petra")
    assert resp.status_code == 200
    assert browser.get("/api/auth/profile").status_code == 200

    _set_disabled(admin, user_id, True)
    assert browser.get("/api/auth/profile").status_code == 401
    assert browser.get("/api/auth/status").json()["authenticated"] is False


def test_re_enabling_allows_sign_in_but_not_the_old_cookie(admin):
    user_id = create_user(admin, "quentin")
    old_browser, _ = _login("quentin")
    old_cookie = old_browser.cookies.get("session")
    _set_disabled(admin, user_id, True)
    assert _set_disabled(admin, user_id, False).status_code == 200

    new_browser, resp = _login("quentin")
    assert resp.status_code == 200
    assert new_browser.get("/api/auth/profile").status_code == 200
    replay = TestClient(app_module.app, raise_server_exceptions=False)
    replay.cookies.set("session", old_cookie)
    assert replay.get("/api/auth/profile").status_code == 401


def test_admin_user_list_shows_the_flag(admin):
    user_id = create_user(admin, "rosa")
    _set_disabled(admin, user_id, True)
    users = {u["username"]: u for u in admin.get(USERS).json()}
    assert users["rosa"]["disabled"] is True
    assert users["admin"]["disabled"] is False


def test_update_audit_records_the_change(admin):
    user_id = create_user(admin, "sven")
    _set_disabled(admin, user_id, True)
    _set_disabled(admin, user_id, False)
    details = [d for d in _audit_details(admin, "user.update") if f"id={user_id}" in d]
    assert any("disabled False -> True" in d for d in details)
    assert any("disabled True -> False" in d for d in details)


# ── admin guards ─────────────────────────────────────────────────────────────


def test_an_admin_cannot_disable_their_own_account(admin):
    resp = _set_disabled(admin, admin_id(admin), True)
    assert resp.status_code == 400
    assert "your own account" in _message(resp)
    assert admin.get("/api/auth/profile").status_code == 200


def test_the_last_enabled_admin_cannot_be_disabled_or_demoted(admin, monkeypatch):
    """Through the server API token (no own account to protect): a disabled
    admin does not count as the remaining one."""
    monkeypatch.setattr(app_module, "APP_API_TOKEN", API_TOKEN)
    # A client without the admin's session cookie: the token is the caller.
    server = TestClient(app_module.app, raise_server_exceptions=False, headers={"X-API-Token": API_TOKEN})
    other = create_user(admin, "tilda", role="admin")
    assert _set_disabled(admin, other, True).status_code == 200
    main = admin_id(admin)

    resp = server.put(f"{USERS}/{main}", json={"disabled": True})
    assert resp.status_code == 400
    assert "last enabled admin" in _message(resp)
    assert server.put(f"{USERS}/{main}", json={"role": "user"}).status_code == 400
    assert server.delete(f"{USERS}/{main}").status_code == 400
    assert admin.get("/api/auth/profile").status_code == 200

    # With a second enabled admin the first may be disabled.
    assert server.put(f"{USERS}/{other}", json={"disabled": False}).status_code == 200
    assert server.put(f"{USERS}/{main}", json={"disabled": True}).status_code == 200


def test_delete_guard_ignores_disabled_admins(admin):
    other = create_user(admin, "ulla", role="admin")
    main = admin_id(admin)
    call = admin.raw.portal.call
    assert call(partial(db_module.update_user_admin, main, disabled=True)) is True
    assert call(db_module.delete_user_guarded, other) == "last_admin"
    # A disabled admin itself deletes fine.
    assert call(db_module.delete_user_guarded, main) == "deleted"


# ── AI-access (MCP) tokens ───────────────────────────────────────────────────


def test_mcp_token_of_a_disabled_owner_is_refused(admin):
    owner = create_user(admin, "viktor")
    token = create_token(admin, owner=owner, name="viktor-bot")
    call = admin.raw.portal.call
    assert call(mcp_auth.resolve_token, token) is not None

    _set_disabled(admin, owner, True)
    assert call(mcp_auth.resolve_token, token) is None
    _set_disabled(admin, owner, False)
    assert call(mcp_auth.resolve_token, token) is not None


# ── external sign-in ─────────────────────────────────────────────────────────


def test_disabled_ldap_account_is_refused_and_left_unchanged(admin, monkeypatch):
    """The directory accepts the password and maps the admin group: the
    account is refused and neither promoted nor renamed."""
    user_id = create_user(admin, "wanda")
    call = admin.raw.portal.call
    call(db_module.set_user_auth_provider, user_id, "ldap")
    _set_disabled(admin, user_id, True)

    admin_group = "CN=Plexus Admins,OU=Groups,DC=example,DC=com"
    cfg = dict(state.AUTH_CONFIG_DEFAULTS)
    cfg["provider"] = "ldap"
    cfg["ldap"] = {
        **state.AUTH_CONFIG_DEFAULTS["ldap"],
        "enabled": True,
        "server": "ldap.example.com",
        "admin_group_dn": admin_group,
        "fallback_to_local": False,
    }
    monkeypatch.setattr(app_module.state, "AUTH_CONFIG", cfg)

    async def fake_verify_ldap_user(username, password):
        return True, "accept", {"display_name": "Wanda Directory", "groups": [admin_group]}

    monkeypatch.setattr(app_module, "verify_ldap_user", fake_verify_ldap_user)

    resp = _login("wanda", "directory-password")[1]
    assert resp.status_code == 401
    assert _message(resp) == "Invalid username or password"
    row = call(db_module.get_user_by_id, user_id)
    assert row["role"] == "user" and row["disabled"]
    assert row["display_name"] != "Wanda Directory"
    assert any("account disabled" in d for d in _audit_details(admin, "login.failure"))


def test_sso_sign_in_into_a_disabled_account_is_refused(admin):
    """upsert_sso_user refuses before it re-syncs the role or binds a subject."""
    user_id = create_user(admin, "xenia")
    call = admin.raw.portal.call
    call(db_module.set_user_auth_provider, user_id, "oidc")
    _set_disabled(admin, user_id, True)

    identity = SsoIdentity(sub="subject-0042", username="xenia", display_name="Xenia Example", groups=["admins"])
    user, reason = call(auth.upsert_sso_user, identity, {"admin_groups": ["admins"]}, "oidc")
    assert user is None
    assert reason == "account disabled"
    row = call(db_module.get_user_by_username, "xenia")
    assert row["role"] == "user" and row["disabled"]
    assert (row.get("external_id") or "") == ""
