"""WebSocket handshakes from a page of another site are refused.

CORS does not apply to WebSockets and the SameSite=Strict session cookie is
still sent by a page on a sibling subdomain, so ``verify_ws_session`` checks
the ``Origin`` header of the socket a handler passes it.
"""

from __future__ import annotations

import re
from pathlib import Path

import netcontrol.routes.shared as shared
import netcontrol.routes.state as state
import pytest

ROUTES = Path(shared.__file__).parent


class _Socket:
    def __init__(self, host: str, origin: str | None):
        self.headers = {"host": host}
        if origin is not None:
            self.headers["origin"] = origin


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
    assert shared.ws_origin_allowed(_Socket(host, origin)) is allowed


def test_configured_cors_origin_is_allowed(monkeypatch):
    monkeypatch.setattr(state, "APP_CORS_ALLOW_ORIGINS", ["https://portal.example.com/"])
    assert shared.ws_origin_allowed(_Socket("plexus.example.com", "https://portal.example.com"))
    assert not shared.ws_origin_allowed(_Socket("plexus.example.com", "https://other.example.com"))


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
