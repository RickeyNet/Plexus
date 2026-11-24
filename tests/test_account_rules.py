"""The rules for account names and local passwords, on every path that
creates or renames an account or sets a password: no reserved name (the
server API token's ``api-token``), no name that differs from an existing one
only in case, no control characters, a bounded password that is not the
username. Every name is invented.
"""

from __future__ import annotations

import netcontrol.app as app_module
import netcontrol.routes.auth as auth
import pytest
import routes.database as db_module
from netcontrol import account_rules
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, create_user

USERS = "/api/admin/users"
REGISTER = "/api/auth/register"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    monkeypatch.setattr(app_module, "LOGIN_USERNAME_FAILURES", {}, raising=False)
    return client


def _message(resp) -> str:
    return resp.json()["error"]["message"]


def _create(admin: CsrfClient, username: str, password: str = "password123", **more):
    return admin.post(USERS, json={"username": username, "password": password, **more})


# ── the rules themselves ─────────────────────────────────────────────────────


def test_username_rules():
    assert account_rules.username_problem("zara") is None
    assert account_rules.username_problem("zara.o'neil@example.com") is None
    assert "at least 3" in account_rules.username_problem("zo")
    assert "at most" in account_rules.username_problem("z" * 151)
    assert "control characters" in account_rules.username_problem("zara\nadmin")
    for reserved in ("api-token", "API-Token"):
        assert account_rules.username_problem(reserved) == "This username is reserved"
        assert account_rules.is_reserved_username(f" {reserved} ")


def test_password_rules():
    assert account_rules.password_problem("password123", "zara") is None
    assert "at least 8" in account_rules.password_problem("short", "zara")
    assert account_rules.password_problem("p" * 256, "zara") is None
    assert "at most 256" in account_rules.password_problem("p" * 257, "zara")
    assert "differ from the username" in account_rules.password_problem("Zara-Admin", "zara-admin")


# ── admin user management ────────────────────────────────────────────────────


def test_admin_cannot_create_a_reserved_or_look_alike_account(admin):
    assert _message(_create(admin, "api-token")) == "This username is reserved"
    assert _create(admin, "Api-Token").status_code == 400
    assert _create(admin, "zara\u2028admin").status_code == 400

    assert _create(admin, "zara").status_code == 201
    look_alike = _create(admin, "ZARA")
    assert look_alike.status_code == 400 and "already exists" in _message(look_alike)
    # The bootstrap admin of this test run, in another case.
    assert _create(admin, "Admin").status_code == 400

    assert "differ from the username" in _message(_create(admin, "zeno-long-name", "Zeno-Long-Name"))
    assert "at most 256" in _message(_create(admin, "zeno", "p" * 257))
    assert admin.raw.portal.call(db_module.get_user_by_username, "zeno") is None


def test_admin_cannot_rename_an_account_to_a_reserved_or_taken_name(admin):
    create_user(admin, "zara")
    user_id = create_user(admin, "zoltan")

    def rename(to: str):
        return admin.put(f"{USERS}/{user_id}", json={"username": to})

    assert _message(rename("api-token")) == "This username is reserved"
    assert rename("Zara").status_code == 400
    assert rename("zo").status_code == 400
    # Its own name in another case, and the unchanged name, are fine.
    assert rename("Zoltan").status_code == 200
    assert rename("Zoltan").status_code == 200


def test_admin_can_require_a_password_change(admin):
    call = admin.raw.portal.call
    created = _create(admin, "zelda", must_change_password=True)
    assert created.status_code == 201, created.text
    assert call(db_module.get_user_by_username, "zelda")["must_change_password"]

    # The default stays as before: the password is usable as it is.
    user_id = create_user(admin, "zack")
    assert not call(db_module.get_user_by_username, "zack")["must_change_password"]
    reset = admin.put(
        f"{USERS}/{user_id}/password", json={"new_password": "a-new-password-1", "must_change_password": True}
    )
    assert reset.status_code == 200, reset.text
    assert call(db_module.get_user_by_username, "zack")["must_change_password"]

    other = create_user(admin, "zachary-long")
    same = admin.put(f"{USERS}/{other}/password", json={"new_password": "Zachary-Long"})
    assert same.status_code == 400 and "differ from the username" in _message(same)


# ── self-registration and external sign-in ───────────────────────────────────


def test_self_registration_follows_the_same_rules(admin, monkeypatch):
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    create_user(admin, "zara")

    def register(username: str, password: str = "password123"):
        browser = TestClient(app_module.app, raise_server_exceptions=False)
        return browser.post(REGISTER, json={"username": username, "password": password})

    assert _message(register("api-token")) == "This username is reserved"
    assert _message(register("ZARA")) == "Username already taken"
    assert register("zed\nadmin").status_code == 400
    assert "differ from the username" in _message(register("zebedee1", "ZEBEDEE1"))

    ok = register("  zed  ")
    assert ok.status_code == 200, ok.text
    assert ok.json()["username"] == "zed"
    assert admin.raw.portal.call(db_module.get_user_by_username, "zed") is not None


@pytest.mark.parametrize("provider", ["ldap", "oidc"])
def test_an_external_sign_in_never_creates_the_reserved_account(admin, provider):
    call = admin.raw.portal.call
    assert call(auth.upsert_external_user, "API-Token", "Token", "admin", provider) is None
    assert call(db_module.get_users_by_username_ci, "api-token") == []
    events = call(db_module.get_audit_events, 50)
    (refused,) = [e for e in events if e["action"] == "login.adopt_refused"]
    assert "reserved" in refused["detail"]
    # Any other name is created as before.
    assert call(auth.upsert_external_user, "zina", "Zina", "user", provider)["auth_provider"] == provider
