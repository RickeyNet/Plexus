"""What an anonymous caller is told when a password sign-in fails, and the
dev bootstrap shortcut's limit.

A directory server that does not answer gives a generic message (the audit
entry keeps the detail), the lockout message names the address, and the dev
bootstrap sign-in never takes over an account an external provider manages.
Every name is invented.
"""

from __future__ import annotations

import netcontrol.app as app_module
import netcontrol.routes.auth as auth
import pytest
import routes.database as db_module
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client

LOGIN = "/api/auth/login"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    monkeypatch.setattr(app_module, "LOGIN_USERNAME_FAILURES", {}, raising=False)
    return client


def _login(username: str, password: str = "password123"):
    browser = TestClient(app_module.app, raise_server_exceptions=False)
    return browser.post(LOGIN, json={"username": username, "password": password})


def _message(resp) -> str:
    return resp.json()["error"]["message"]


@pytest.mark.parametrize(
    ("provider", "verifier", "answer", "fallback", "audited"),
    [
        ("ldap", "verify_ldap_user", (False, "error", {}), False, "LDAP authentication service unavailable"),
        ("ldap", "verify_ldap_user", (False, "error", {}), True, "LDAP server is unavailable and local fallback"),
        ("radius", "verify_radius_user", (False, "error"), False, "RADIUS authentication service unavailable"),
        ("tacacs", "verify_tacacs_user", (False, "error", {}), False, "TACACS+ authentication service unavailable"),
    ],
)
def test_a_backend_outage_is_not_described_to_the_caller(
    admin, monkeypatch, provider, verifier, answer, fallback, audited
):
    async def down(username, password):
        return answer

    monkeypatch.setattr(app_module, verifier, down)
    monkeypatch.setitem(app_module.state.AUTH_CONFIG, "provider", provider)
    monkeypatch.setitem(app_module.state.AUTH_CONFIG, provider, {"enabled": True, "fallback_to_local": fallback})

    resp = _login("xavier")

    assert resp.status_code == 401
    assert _message(resp) == auth._LOGIN_UNAVAILABLE
    for word in ("LDAP", "RADIUS", "TACACS", "fallback"):
        assert word not in resp.text
    events = admin.raw.portal.call(db_module.get_audit_events, 50)
    (failure,) = [e for e in events if e["action"] == "login.failure"]
    assert failure["user"] == "xavier" and audited in failure["detail"]


def test_a_wrong_password_keeps_its_own_message(admin):
    resp = _login("xavier")
    assert resp.status_code == 401 and _message(resp) == auth._INVALID_LOGIN


def test_the_lockout_message_names_the_address(admin, monkeypatch):
    monkeypatch.setitem(app_module.state.LOGIN_RULES, "max_attempts", 2)
    assert _login("yara").status_code == 401
    locking = _login("yara")
    assert locking.status_code == 429 and "this address" in _message(locking)
    refused = _login("yara")
    assert refused.status_code == 429
    assert "address is locked" in _message(refused) and "Account" not in _message(refused)


def test_dev_bootstrap_does_not_take_over_a_managed_account(admin):
    """The bootstrap name belongs to an account a provider manages: the
    shortcut neither signs it in nor resets its password or role."""
    call = admin.raw.portal.call
    account = call(db_module.get_user_by_username, "admin")
    call(db_module.update_user_admin, account["id"], None, None, "user")
    call(db_module.set_user_auth_provider, account["id"], "oidc")
    before = call(db_module.get_user_by_username, "admin")

    resp = _login("admin", "netcontrol")

    assert resp.status_code == 401 and _message(resp) == auth._INVALID_LOGIN
    after = call(db_module.get_user_by_username, "admin")
    assert after["role"] == "user" and after["auth_provider"] == "oidc"
    assert (after["password_hash"], after["salt"]) == (before["password_hash"], before["salt"])

    # Back as a local account, the shortcut works as before.
    call(db_module.set_user_auth_provider, account["id"], "")
    assert _login("admin", "netcontrol").status_code == 200
