"""WebSocket handshakes from a page of another site are refused.

CORS does not apply to WebSockets and the SameSite=Strict session cookie is
still sent by a page on a sibling subdomain, so ``verify_ws_session`` checks
the ``Sec-Fetch-Site`` and ``Origin`` headers of the socket a handler passes
it.
"""

from __future__ import annotations

import re
from pathlib import Path

import netcontrol.routes.shared as shared
import netcontrol.routes.state as state
import pytest

ROUTES = Path(shared.__file__).parent


class _Socket:
    def __init__(self, host: str, origin: str | None, fetch_site: str | None = None):
        self.headers = {"host": host}
        if origin is not None:
            self.headers["origin"] = origin
        if fetch_site is not None:
            self.headers["sec-fetch-site"] = fetch_site


@pytest.mark.parametrize(
    ("host", "origin", "allowed"),
    [
        ("plexus.example.com", None, True),  # not a browser: no ambient cookie
        ("plexus.example.com", "https://plexus.example.com", True),
        ("plexus.example.com", "https://PLEXUS.example.com/", True),
        # nginx forwards $host, which carries no port.
        ("plexus.example.com", "https://plexus.example.com:8443", True),
        ("[2001:db8::10]:8080", "http://[2001:db8::10]:8080", True),
        ("plexus.example.com", "https://wiki.example.com", False),  # sibling subdomain
        ("plexus.example.com", "https://plexus.example.com.attacker.example", False),
        ("plexus.example.com", "null", False),  # sandboxed frame, file://
        ("plexus.example.com", "https://[bad", False),
    ],
)
def test_origin_must_be_this_site(monkeypatch, host, origin, allowed):
    monkeypatch.setattr(state, "APP_CORS_ALLOW_ORIGINS", [])
    assert shared.origin_allowed(_Socket(host, origin)) is allowed


# Behind a reverse proxy that rewrites Host, the request's Host is the
# upstream name and not the address the browser opened.
UPSTREAM = "plexus-backend:8080"
OPENED = "https://plexus.example.com"


@pytest.mark.parametrize(
    ("host", "origin", "fetch_site", "request_allowed", "handshake_allowed"),
    [
        # The browser's own word outranks a Host the proxy rewrote.
        (UPSTREAM, OPENED, "same-origin", True, True),
        (UPSTREAM, OPENED, "SAME-ORIGIN ", True, True),
        (UPSTREAM, None, "none", True, True),
        (UPSTREAM, "null", "same-origin", True, True),
        (UPSTREAM, OPENED, None, False, False),  # no header: Origin against Host
        (UPSTREAM, OPENED, "cross-site", False, False),
        # Another origin by the browser's word. A request is refused; a
        # handshake goes on to compare Origin with Host.
        ("plexus.example.com", "https://plexus.example.com:9000", "same-site", False, True),
        ("plexus.example.com", "https://plexus.example.com", "cross-site", False, True),
        ("plexus.example.com", None, "cross-site", False, True),
        ("plexus.example.com", "https://wiki.example.com", "same-site", False, False),
        ("plexus.example.com", "https://plexus.example.com", "not-a-value", False, True),
    ],
)
def test_the_browsers_fetch_site_is_read_before_the_origin(
    monkeypatch, host, origin, fetch_site, request_allowed, handshake_allowed
):
    monkeypatch.setattr(state, "APP_CORS_ALLOW_ORIGINS", [])
    connection = _Socket(host, origin, fetch_site)
    assert shared.origin_allowed(connection) is request_allowed
    assert shared.origin_allowed(connection, handshake=True) is handshake_allowed


def test_configured_cors_origin_is_allowed(monkeypatch):
    monkeypatch.setattr(state, "APP_CORS_ALLOW_ORIGINS", ["https://portal.example.com/"])
    assert shared.origin_allowed(_Socket("plexus.example.com", "https://portal.example.com"))
    assert not shared.origin_allowed(_Socket("plexus.example.com", "https://other.example.com"))
    assert shared.origin_allowed(_Socket("plexus.example.com", "https://portal.example.com", "cross-site"))


async def test_verify_ws_session_refuses_a_foreign_origin_before_reading_the_token(monkeypatch):
    def never(token):
        raise AssertionError("the token must not be read for a refused origin")

    monkeypatch.setattr(state, "APP_CORS_ALLOW_ORIGINS", [])
    monkeypatch.setattr(shared, "_verify_session_token_fn", never)
    foreign = _Socket("plexus.example.com", "https://wiki.example.com")
    assert await shared.verify_ws_session("token", foreign) is None


async def test_verify_ws_session_accepts_this_site(monkeypatch):
    session = {"user": "alice", "user_id": 7, "session_epoch": 0}

    async def get_user(user_id):
        return {"id": 7, "username": "alice", "session_epoch": 0, "session_never_expires": 1}

    monkeypatch.setattr(state, "APP_CORS_ALLOW_ORIGINS", [])
    monkeypatch.setattr(shared, "_verify_session_token_fn", lambda token: session)
    monkeypatch.setattr(shared.db, "get_user_by_id", get_user)
    same = _Socket("plexus.example.com", "https://plexus.example.com")
    assert await shared.verify_ws_session("token", same) == session
    # Behind a proxy that rewrote Host, and with a header value a request
    # would be refused for: a handshake still compares Origin with Host.
    assert await shared.verify_ws_session("token", _Socket(UPSTREAM, OPENED, "same-origin")) == session
    odd = _Socket("plexus.example.com", "https://plexus.example.com", "cross-site")
    assert await shared.verify_ws_session("token", odd) == session


def test_every_ws_handler_passes_its_socket():
    """A handler that calls ``verify_ws_session(token)`` alone skips the
    Origin check."""
    calls: list[str] = []
    for path in sorted(ROUTES.glob("*.py")):
        if path.name == "shared.py":
            continue
        calls += re.findall(r"await verify_ws_session\(([^)]*)\)", path.read_text(encoding="utf-8"))
    assert len(calls) >= 5
    assert all("," in call for call in calls), calls
