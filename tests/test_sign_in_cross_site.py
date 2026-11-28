"""Sign-in and registration cannot be sent by a page of another site.

Both start a session and take no CSRF token (there is no session yet to
bind one to), so a page of another site that could send them would sign the
visitor's browser in to an account that site chose. Two things stop it: the
browser's ``Sec-Fetch-Site`` header, or without it the request's ``Origin``,
must say this site (``csrf_guard``), and the body is read only as
``application/json``, which a page cannot send to another site without a
CORS preflight. Every name is invented.
"""

from __future__ import annotations

import json

import netcontrol.app as app_module
import netcontrol.routes.state as state
import pytest
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client

LOGIN = "/api/auth/login"
REGISTER = "/api/auth/register"
ADMIN = {"username": "admin", "password": "netcontrol"}


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    monkeypatch.setattr(state, "APP_CORS_ALLOW_ORIGINS", [])
    return client


def _browser() -> TestClient:
    """A browser with no session. Its requests carry ``Host: testserver``."""
    return TestClient(app_module.app, raise_server_exceptions=False)


def _refused(resp) -> bool:
    return resp.status_code == 403 and resp.json()["error"]["code"] == "cross_site_request"


@pytest.mark.parametrize(
    "origin",
    [
        "https://attacker.example",
        "https://wiki.testserver",  # a sibling name is another origin
        "null",  # sandboxed frame, file://
    ],
)
def test_sign_in_from_another_site_is_refused_before_the_password_is_checked(admin, monkeypatch, origin):
    async def never(*args, **kwargs):
        raise AssertionError("a refused request must not reach the password check")

    monkeypatch.setattr(app_module, "authenticate_login_identity", never, raising=False)
    browser = _browser()
    resp = browser.post(LOGIN, json=ADMIN, headers={"Origin": origin})
    assert _refused(resp), resp.text
    assert "set-cookie" not in resp.headers and "session" not in browser.cookies


@pytest.mark.parametrize("origin", [None, "http://testserver", "https://TESTSERVER:8443/"])
def test_sign_in_from_this_site_or_from_no_page_works(admin, origin):
    headers = {"Origin": origin} if origin else {}
    resp = _browser().post(LOGIN, json=ADMIN, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["csrf_token"]


@pytest.mark.parametrize(
    ("fetch_site", "origin"),
    [
        # A reverse proxy rewrote Host: the browser's own word still stands.
        ("same-origin", "https://plexus.example.com"),
        ("same-origin", None),
        ("none", None),  # no page: an extension, the address bar
    ],
)
def test_sign_in_the_browser_calls_same_origin_works_whatever_host_says(admin, fetch_site, origin):
    headers = {"Sec-Fetch-Site": fetch_site} | ({"Origin": origin} if origin else {})
    resp = _browser().post(LOGIN, json=ADMIN, headers=headers)
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize(
    ("fetch_site", "origin"),
    [
        ("cross-site", "https://attacker.example"),
        ("cross-site", None),
        # The header outranks an Origin that names this host: another port
        # of the same name is another origin.
        ("same-site", "http://testserver:9000"),
        ("same-site", "https://wiki.testserver"),
        ("not-a-value", "http://testserver"),
    ],
)
def test_sign_in_the_browser_calls_cross_origin_is_refused(admin, fetch_site, origin):
    headers = {"Sec-Fetch-Site": fetch_site} | ({"Origin": origin} if origin else {})
    browser = _browser()
    assert _refused(browser.post(LOGIN, json=ADMIN, headers=headers))
    assert "session" not in browser.cookies


def test_configured_cors_origin_may_sign_in(admin, monkeypatch):
    monkeypatch.setattr(state, "APP_CORS_ALLOW_ORIGINS", ["https://portal.example.com"])
    assert _browser().post(LOGIN, json=ADMIN, headers={"Origin": "https://portal.example.com"}).status_code == 200
    assert _refused(_browser().post(LOGIN, json=ADMIN, headers={"Origin": "https://other.example.com"}))
    listed = {"Origin": "https://portal.example.com", "Sec-Fetch-Site": "cross-site"}
    assert _browser().post(LOGIN, json=ADMIN, headers=listed).status_code == 200


def test_registration_from_another_site_is_refused(admin, monkeypatch):
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    body = {"username": "mallory", "password": "a-long-password-1", "display_name": "Mallory"}
    browser = _browser()
    assert _refused(browser.post(REGISTER, json=body, headers={"Origin": "https://attacker.example"}))
    assert "session" not in browser.cookies
    users = admin.get("/api/admin/users").json()
    assert "mallory" not in json.dumps(users)


@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"],
)
def test_sign_in_body_is_read_only_as_json(admin, content_type):
    """The content types a page can send to another site without a
    preflight, and a body with no type at all, are not a sign-in."""
    headers = {"Content-Type": content_type} if content_type else {}
    browser = _browser()
    resp = browser.post(LOGIN, content=json.dumps(ADMIN).encode(), headers=headers)
    assert resp.status_code == 422, resp.text
    assert "session" not in browser.cookies


def test_session_cookie_is_same_site_strict(admin):
    resp = _browser().post(LOGIN, json=ADMIN)
    cookie = resp.headers["set-cookie"].lower()
    assert cookie.startswith("session=") and "samesite=strict" in cookie and "httponly" in cookie
