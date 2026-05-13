"""Session idle-timeout enforcement and audit emission.

Covers:
  1. require_auth raises 401 once last_activity exceeds session_idle_timeout
     and emits an audit event with category=auth action=session.idle_timeout.
  2. Kiosk accounts (session_never_expires=1) bypass the idle check.
  3. session_idle_timeout=0 disables the check globally.
  4. Activity inside the window passes through and re-issues a refreshed
     cookie (so the SPA's idle countdown gets reset).
  5. /api/auth/status mirrors the same enforcement and emits an audit event.
  6. /api/auth/status returns the idle_timeout_seconds / session_last_activity
     / session_never_expires / server_time fields the SPA needs.
"""

from __future__ import annotations

import time
from typing import cast
from unittest.mock import patch

import netcontrol.app as app_module
import netcontrol.routes.auth as auth_module
import netcontrol.routes.state as state
import pytest
from fastapi import HTTPException, Request, Response


class DummyRequest:
    def __init__(self, cookies: dict[str, str] | None = None, path: str = "/api/inventory"):
        self.headers = {}
        self.cookies = cookies or {}
        self.url = type("U", (), {"path": path})()
        self.state = type("S", (), {"correlation_id": "test-corr"})()


def _make_expired_token(username: str, user_id: int, age_seconds: int) -> str:
    """Mint a session token with last_activity pushed `age_seconds` into the past."""
    now = int(time.time())
    return app_module._serializer.dumps({
        "user": username,
        "user_id": user_id,
        "originally_issued_at": now,
        "last_activity": now - age_seconds,
    })


# ── Audit-event capture helper ───────────────────────────────────────────────

class AuditRecorder:
    def __init__(self):
        self.events: list[dict] = []

    async def record(self, category, action, *, user="", detail="", correlation_id=""):
        self.events.append({
            "category": category,
            "action": action,
            "user": user,
            "detail": detail,
            "correlation_id": correlation_id,
        })


# ═════════════════════════════════════════════════════════════════════════════
# 1-4. require_auth path
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_require_auth_blocks_when_idle_exceeded(monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 30)

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "alice", "role": "user", "must_change_password": 0,
                "session_never_expires": 0}

    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)

    recorder = AuditRecorder()
    with patch.object(app_module.shared, "_audit", recorder.record):
        token = _make_expired_token("alice", 7, age_seconds=120)
        req = DummyRequest(cookies={"session": token})
        resp = Response()

        with pytest.raises(HTTPException) as exc:
            await app_module.require_auth(cast(Request, req), response=resp)
        assert exc.value.status_code == 401
        assert "idle" in str(exc.value.detail).lower()

    assert len(recorder.events) == 1
    event = recorder.events[0]
    assert event["category"] == "auth"
    assert event["action"] == "session.idle_timeout"
    assert event["user"] == "alice"
    assert "idle=" in event["detail"]
    assert "threshold=30s" in event["detail"]
    assert event["correlation_id"] == "test-corr"


@pytest.mark.asyncio
async def test_kiosk_account_bypasses_idle_timeout(monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 30)

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "kiosk", "role": "user", "must_change_password": 0,
                "session_never_expires": 1}

    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)

    recorder = AuditRecorder()
    with patch.object(app_module.shared, "_audit", recorder.record):
        token = _make_expired_token("kiosk", 9, age_seconds=99999)
        req = DummyRequest(cookies={"session": token})
        resp = Response()

        session = await app_module.require_auth(cast(Request, req), response=resp)

    assert session["user"] == "kiosk"
    assert recorder.events == []


@pytest.mark.asyncio
async def test_idle_timeout_zero_disables_check(monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 0)

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "bob", "role": "user", "must_change_password": 0,
                "session_never_expires": 0}

    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)

    recorder = AuditRecorder()
    with patch.object(app_module.shared, "_audit", recorder.record):
        token = _make_expired_token("bob", 3, age_seconds=99999)
        req = DummyRequest(cookies={"session": token})
        resp = Response()

        session = await app_module.require_auth(cast(Request, req), response=resp)

    assert session["user"] == "bob"
    assert recorder.events == []


@pytest.mark.asyncio
async def test_active_session_refreshes_cookie(monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 1800)

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "carol", "role": "user", "must_change_password": 0,
                "session_never_expires": 0}

    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)

    token = _make_expired_token("carol", 4, age_seconds=10)
    req = DummyRequest(cookies={"session": token})
    resp = Response()

    session = await app_module.require_auth(cast(Request, req), response=resp)

    assert session["user"] == "carol"
    # The response should have set a refreshed session cookie.
    cookies = [h for h in resp.raw_headers if h[0].decode().lower() == "set-cookie"]
    assert any(b"session=" in v for _, v in cookies), \
        f"expected refreshed session cookie, got headers: {resp.raw_headers}"


# ═════════════════════════════════════════════════════════════════════════════
# 5-6. /api/auth/status path
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_auth_status_emits_audit_on_idle_expiry(monkeypatch):
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 60)

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "dave", "role": "user", "display_name": "",
                "must_change_password": 0, "session_never_expires": 0}

    monkeypatch.setattr(auth_module.db, "get_user_by_id", fake_get_user_by_id)

    recorder = AuditRecorder()
    monkeypatch.setattr(auth_module, "_audit", recorder.record)

    token = _make_expired_token("dave", 11, age_seconds=300)
    req = DummyRequest(cookies={"session": token}, path="/api/auth/status")
    resp = Response()

    result = await auth_module.auth_status(cast(Request, req), resp)

    assert result == {"authenticated": False}
    assert len(recorder.events) == 1
    assert recorder.events[0]["category"] == "auth"
    assert recorder.events[0]["action"] == "session.idle_timeout"
    assert recorder.events[0]["user"] == "dave"


@pytest.mark.asyncio
async def test_auth_status_returns_idle_fields_when_active(monkeypatch):
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 600)

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "eve", "role": "user", "display_name": "Eve",
                "must_change_password": 0, "session_never_expires": 0}

    async def fake_get_user_features(user):
        return []

    monkeypatch.setattr(auth_module.db, "get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(auth_module, "_get_user_features", fake_get_user_features)
    # Stub the CSRF generator since init_auth() may not have been called in this
    # unit-test context.
    monkeypatch.setattr(auth_module, "_generate_csrf_token", lambda u: "csrf-stub")

    token = _make_expired_token("eve", 12, age_seconds=5)
    req = DummyRequest(cookies={"session": token}, path="/api/auth/status")
    resp = Response()

    result = await auth_module.auth_status(cast(Request, req), resp)

    assert result["authenticated"] is True
    assert result["idle_timeout_seconds"] == 600
    assert result["session_never_expires"] is False
    assert isinstance(result["session_last_activity"], int)
    assert isinstance(result["server_time"], int)
    # last_activity should be ~5s ago (give a generous window for slow CI).
    assert 0 <= result["server_time"] - result["session_last_activity"] <= 60


@pytest.mark.asyncio
async def test_auth_status_marks_kiosk_user(monkeypatch):
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 30)

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "screen", "role": "user", "display_name": "",
                "must_change_password": 0, "session_never_expires": 1}

    async def fake_get_user_features(user):
        return []

    monkeypatch.setattr(auth_module.db, "get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(auth_module, "_get_user_features", fake_get_user_features)
    monkeypatch.setattr(auth_module, "_generate_csrf_token", lambda u: "csrf-stub")

    token = _make_expired_token("screen", 13, age_seconds=99999)
    req = DummyRequest(cookies={"session": token}, path="/api/auth/status")
    resp = Response()

    result = await auth_module.auth_status(cast(Request, req), resp)

    assert result["authenticated"] is True
    assert result["session_never_expires"] is True
