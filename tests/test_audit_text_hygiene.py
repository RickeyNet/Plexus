"""Text an anonymous caller chooses (the name typed into the sign-in form)
stays on one line and within a fixed length in the audit trail and the log,
and a name with a control character never reaches a sign-in backend.
Every name is invented.
"""

from __future__ import annotations

import logging

import netcontrol.app as app_module
import netcontrol.routes.shared as shared
import pytest
import routes.database as db_module
from netcontrol import sso
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client

LOGIN = "/api/auth/login"
FORGED = "audit: category=auth action=login.success user=admin"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    monkeypatch.setattr(app_module, "LOGIN_USERNAME_FAILURES", {}, raising=False)
    return client


def _failures(admin: CsrfClient) -> list[dict]:
    events = admin.raw.portal.call(db_module.get_audit_events, 100)
    return [e for e in events if e["action"] == "login.failure"]


def test_single_line_replaces_every_line_break_and_cuts():
    text = "a\nb\rc\x00d\x1be\x7ff\x85g h i\tj"
    assert sso.single_line(text) == "a b c d e f g h i j"
    assert sso.single_line("x" * 50, 10) == "x" * 10
    assert sso.single_line(None, 10) == ""
    # Ordinary non-ASCII text is kept.
    assert sso.single_line("Zoë Müller", 50) == "Zoë Müller"


@pytest.mark.parametrize("separator", ["\n", "\r\n", "\x00", " ", "\x85"])
def test_a_name_with_a_control_character_fails_before_any_backend(admin, monkeypatch, caplog, separator):
    asked: list[str] = []

    async def backend(username, password):
        asked.append(username)
        return None, None, None

    monkeypatch.setattr(app_module, "authenticate_login_identity", backend)
    browser = TestClient(app_module.app, raise_server_exceptions=False)
    with caplog.at_level(logging.INFO):
        resp = browser.post(LOGIN, json={"username": f"walter{separator}{FORGED}", "password": "password123"})

    assert resp.status_code == 401
    assert resp.json()["error"]["message"] == "Invalid username or password"
    assert asked == []
    (event,) = _failures(admin)
    assert event["user"].startswith("walter ") and FORGED in event["user"]
    assert not sso.CONTROL_CHARS.search(event["user"])
    # The log has the attempt on one line: no line of the caller's own.
    for record in caplog.records:
        assert not sso.CONTROL_CHARS.search(record.getMessage())

    # An ordinary wrong name still reaches the backend.
    assert browser.post(LOGIN, json={"username": "walter", "password": "password123"}).status_code == 401
    assert asked == ["walter"]


def test_sign_in_name_length_is_limited(admin):
    browser = TestClient(app_module.app, raise_server_exceptions=False)
    assert browser.post(LOGIN, json={"username": "w" * 257, "password": "password123"}).status_code == 422
    assert _failures(admin) == []
    assert browser.post(LOGIN, json={"username": "w" * 256, "password": "password123"}).status_code == 401
    (event,) = _failures(admin)
    assert event["user"] == "w" * 256


def test_audit_cuts_and_flattens_user_and_detail(admin):
    call = admin.raw.portal.call
    call(shared._audit, "auth", "test.entry", "u" * 1000, "first\nsecond" + "d" * 9000)
    (event,) = [e for e in call(db_module.get_audit_events, 100) if e["action"] == "test.entry"]
    assert event["user"] == "u" * shared._AUDIT_USER_MAX
    assert event["detail"].startswith("first second")
    assert len(event["detail"]) == shared._AUDIT_DETAIL_MAX


def test_the_log_points_at_the_event_without_its_user_or_detail(admin, caplog):
    call = admin.raw.portal.call
    with caplog.at_level(logging.INFO, logger=shared.LOGGER.name):
        call(shared._audit, "config", "test.pointer", "walter", "changed the widget colour", "corr-1")
    (event,) = [e for e in call(db_module.get_audit_events, 100) if e["action"] == "test.pointer"]
    assert (event["user"], event["detail"]) == ("walter", "changed the widget colour")
    (line,) = [r.getMessage() for r in caplog.records if r.getMessage().startswith("audit: ")]
    assert line == f"audit: id={event['id']} category=config action=test.pointer correlation_id=corr-1"
