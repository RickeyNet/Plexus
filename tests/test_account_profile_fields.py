"""Display names and the never-expiring session flag.

A display name is shown to admins and other users, so whoever sets it (the
account itself, an admin, self-registration) it is bounded, kept on one line
and its change is audited. A session that never expires cannot be combined
with the admin role, and the ``user.update`` audit entry says what changed.
Every name is invented.
"""

from __future__ import annotations

from functools import partial

import netcontrol.app as app_module
import pytest
import routes.database as db_module
from netcontrol import sso
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, create_user

PROFILE = "/api/auth/profile"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    monkeypatch.setattr(app_module, "LOGIN_USERNAME_FAILURES", {}, raising=False)
    return client


def _session(username: str) -> CsrfClient:
    browser = TestClient(app_module.app, raise_server_exceptions=False)
    resp = browser.post("/api/auth/login", json={"username": username, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(browser, resp.json()["csrf_token"])


def _events(admin: CsrfClient, action: str) -> list[dict]:
    events = admin.raw.portal.call(db_module.get_audit_events, 100)
    return [e for e in events if e["action"] == action]


def _update(admin: CsrfClient, user_id: int, **fields):
    return admin.put(f"/api/admin/users/{user_id}", json=fields)


def _message(resp) -> str:
    return resp.json()["error"]["message"]


# ── display name ─────────────────────────────────────────────────────────────


def test_clean_display_name_is_one_trimmed_bounded_line():
    assert sso.clean_display_name("  Tina\r\nTurner\x00 ") == "Tina  Turner"
    assert len(sso.clean_display_name("t" * 500)) == sso.DISPLAY_NAME_MAX_LENGTH
    assert sso.clean_display_name(None) == ""


def test_own_display_name_is_cleaned_bounded_and_audited(admin):
    user_id = create_user(admin, "tina")
    stored_before = admin.raw.portal.call(db_module.get_user_by_id, user_id)["display_name"]
    session = _session("tina")

    assert session.put(PROFILE, json={"display_name": "t" * (sso.DISPLAY_NAME_MAX_LENGTH + 1)}).status_code == 422
    assert session.put(PROFILE, json={"display_name": " Tina\nT. "}).status_code == 200
    assert admin.raw.portal.call(db_module.get_user_by_id, user_id)["display_name"] == "Tina T."
    (event,) = _events(admin, "profile.update")
    assert event["user"] == "tina"
    assert event["detail"] == f"display name '{stored_before}' -> 'Tina T.'"

    # The same name again, or a request without one, changes and records nothing.
    assert session.put(PROFILE, json={"display_name": "Tina T."}).status_code == 200
    assert session.put(PROFILE, json={}).status_code == 200
    assert len(_events(admin, "profile.update")) == 1
    assert admin.raw.portal.call(db_module.get_user_by_id, user_id)["display_name"] == "Tina T."


def test_admin_set_display_names_are_cleaned_and_bounded(admin):
    too_long = "u" * (sso.DISPLAY_NAME_MAX_LENGTH + 1)
    body = {"username": "ursula", "password": "password123", "display_name": too_long}
    assert admin.post("/api/admin/users", json=body).status_code == 422
    created = admin.post("/api/admin/users", json={**body, "display_name": " Ursula\tU. "})
    assert created.status_code == 201, created.text
    assert created.json()["display_name"] == "Ursula U."

    user_id = created.json()["id"]
    assert _update(admin, user_id, display_name=too_long).status_code == 422
    assert _update(admin, user_id, display_name="Ursula\nV.").json()["display_name"] == "Ursula V."


# ── user.update audit detail and the never-expiring session flag ─────────────


def test_user_update_audit_names_what_changed(admin):
    user_id = create_user(admin, "victor")
    resp = _update(admin, user_id, username="viktor", display_name="Viktor V.", session_never_expires=True)
    assert resp.status_code == 200, resp.text
    detail = _events(admin, "user.update")[0]["detail"]
    assert "username 'victor' -> 'viktor'" in detail
    assert "-> 'Viktor V.'" in detail
    assert "session never expires False -> True" in detail
    assert "role" not in detail

    # An update that changes nothing lists nothing.
    assert _update(admin, user_id, display_name="Viktor V.").status_code == 200
    assert _events(admin, "user.update")[0]["detail"] == f"updated user id={user_id}"


def test_a_never_expiring_session_cannot_be_combined_with_the_admin_role(admin):
    kiosk = create_user(admin, "wall-screen")
    boss = create_user(admin, "wanda", role="admin")
    call = admin.raw.portal.call

    # Not on an admin...
    resp = _update(admin, boss, session_never_expires=True)
    assert resp.status_code == 400 and "never expires" in _message(resp)
    # ...not by promoting a kiosk account, in one request or two.
    assert _update(admin, kiosk, role="admin", session_never_expires=True).status_code == 400
    assert _update(admin, kiosk, session_never_expires=True).status_code == 200
    assert _update(admin, kiosk, role="admin").status_code == 400
    after = call(db_module.get_user_by_id, kiosk)
    assert after["role"] == "user" and bool(after["session_never_expires"])
    assert not call(db_module.get_user_by_id, boss)["session_never_expires"]

    # Promotion works once the flag is off, in the same request too.
    assert _update(admin, kiosk, role="admin", session_never_expires=False).status_code == 200

    # An account that already had both keeps working until one is changed.
    call(partial(db_module.update_user_admin, boss, session_never_expires=True))
    assert _update(admin, boss, display_name="Wanda W.").status_code == 200
    assert _update(admin, boss, session_never_expires=True).status_code == 200
    assert _update(admin, boss, session_never_expires=False).status_code == 200
    assert _update(admin, boss, session_never_expires=True).status_code == 400
