"""A CSRF token belongs to the session it was issued to.

The token is signed over the user and the session's id (``sid``), which the
session cookie keeps through every refresh. A token issued to another
session of the same user, or to a session that has ended, is refused; the
token of a session that goes on (a refreshed cookie, a password change)
stays valid. Every name is invented.
"""

from __future__ import annotations

import netcontrol.app as app_module
import pytest
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, create_user

LOGIN = "/api/auth/login"
PROFILE = "/api/auth/profile"
ADMIN = {"username": "admin", "password": "netcontrol"}


def _session(user: str = "dana", user_id: int = 7) -> dict:
    """A decoded session as a sign-in creates it."""
    return app_module.verify_session_token(app_module.create_session_token(user, user_id))


def _legacy_session(issued_at: int, user: str = "dana") -> dict:
    """A session signed before ``sid`` existed."""
    token = app_module._serializer.dumps(
        {"user": user, "user_id": 7, "session_epoch": 0, "originally_issued_at": issued_at, "last_activity": issued_at}
    )
    return app_module.verify_session_token(token)


# ── the token ────────────────────────────────────────────────────────────────


def test_each_sign_in_gets_its_own_session_id():
    first, second = _session(), _session()
    assert first["sid"] and second["sid"] and first["sid"] != second["sid"]


def test_token_is_refused_for_another_session_of_the_same_user():
    first, second = _session(), _session()
    token = app_module._generate_csrf_token(first)
    assert app_module._validate_csrf_token(token, first) is True
    assert app_module._validate_csrf_token(token, second) is False


def test_token_survives_the_cookie_refresh():
    session = _session()
    token = app_module._generate_csrf_token(session)
    refreshed = app_module.verify_session_token(app_module._refresh_session_token(session))
    assert refreshed["sid"] == session["sid"]
    assert app_module._validate_csrf_token(token, refreshed) is True


def test_a_reissued_session_keeps_its_token_only_with_its_id():
    session = _session()
    token = app_module._generate_csrf_token(session)
    kept = app_module.verify_session_token(app_module.create_session_token("dana", 7, 3, session["sid"]))
    assert app_module._validate_csrf_token(token, kept) is True
    fresh = app_module.verify_session_token(app_module.create_session_token("dana", 7, 3))
    assert app_module._validate_csrf_token(token, fresh) is False


def test_session_from_before_the_id_is_bound_by_its_creation_time():
    old = _legacy_session(1_800_000_000)
    token = app_module._generate_csrf_token(old)
    assert app_module._validate_csrf_token(token, old) is True
    # The refresh adds no id, so the binding does not move.
    refreshed = app_module.verify_session_token(app_module._refresh_session_token(old))
    assert "sid" not in refreshed
    assert app_module._validate_csrf_token(token, refreshed) is True
    assert app_module._validate_csrf_token(token, _legacy_session(1_800_000_060)) is False


def test_token_bound_to_the_user_alone_is_refused():
    """What a release before the binding issued: the user name and nothing
    of the session."""
    session = _session()
    old_format = app_module._csrf_serializer.dumps({"csrf_user": session["user"]})
    assert app_module._validate_csrf_token(old_format, session) is False


def test_session_with_nothing_to_bind_to_gets_no_valid_token():
    bare = {"user": "dana", "user_id": 7}
    assert app_module._validate_csrf_token(app_module._generate_csrf_token(bare), bare) is False


# ── over HTTP ────────────────────────────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    return client


def _write(browser: TestClient, csrf: str):
    return browser.put(PROFILE, json={"display_name": "Administrator"}, headers={"X-CSRF-Token": csrf})


def _is_csrf_error(resp) -> bool:
    return resp.status_code == 403 and resp.json()["error"]["code"] == "csrf_error"


def test_second_browser_of_the_same_user_cannot_use_the_first_ones_token(admin):
    other = TestClient(app_module.app, raise_server_exceptions=False)
    other_csrf = other.post(LOGIN, json=ADMIN).json()["csrf_token"]

    assert _write(admin.raw, admin._csrf).status_code == 200
    assert _write(other, other_csrf).status_code == 200
    assert _is_csrf_error(_write(other, admin._csrf))
    assert _is_csrf_error(_write(admin.raw, other_csrf))


def test_token_from_before_a_new_sign_in_is_refused(admin):
    before = admin._csrf
    after = admin.raw.post(LOGIN, json=ADMIN).json()["csrf_token"]
    assert _is_csrf_error(_write(admin.raw, before))
    assert _write(admin.raw, after).status_code == 200


def test_status_gives_the_token_of_the_session_that_asks(admin):
    other = TestClient(app_module.app, raise_server_exceptions=False)
    other.post(LOGIN, json=ADMIN)
    from_status = admin.raw.get("/api/auth/status").json()["csrf_token"]
    assert _write(admin.raw, from_status).status_code == 200
    assert _is_csrf_error(_write(other, from_status))


def test_password_change_keeps_the_token_of_the_session_that_made_it(admin):
    create_user(admin, "petra")
    browser = TestClient(app_module.app, raise_server_exceptions=False)
    csrf = browser.post(LOGIN, json={"username": "petra", "password": "password123"}).json()["csrf_token"]
    changed = browser.post(
        "/api/auth/change-password",
        json={"current_password": "password123", "new_password": "a-new-password-1"},
        headers={"X-CSRF-Token": csrf},
    )
    assert changed.status_code == 200, changed.text
    # The cookie was re-issued for the same session: the page's token works on.
    assert _write(browser, csrf).status_code == 200
