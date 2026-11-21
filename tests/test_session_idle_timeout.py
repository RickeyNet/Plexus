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
    return app_module._serializer.dumps(
        {
            "user": username,
            "user_id": user_id,
            "originally_issued_at": now,
            "last_activity": now - age_seconds,
        }
    )


# ── Audit-event capture helper ───────────────────────────────────────────────


class AuditRecorder:
    def __init__(self):
        self.events: list[dict] = []

    async def record(self, category, action, *, user="", detail="", correlation_id=""):
        self.events.append(
            {
                "category": category,
                "action": action,
                "user": user,
                "detail": detail,
                "correlation_id": correlation_id,
            }
        )


# ═════════════════════════════════════════════════════════════════════════════
# 1-4. require_auth path
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_require_auth_blocks_when_idle_exceeded(monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 30)

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "alice", "role": "user", "must_change_password": 0, "session_never_expires": 0}

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
        return {"id": uid, "username": "kiosk", "role": "user", "must_change_password": 0, "session_never_expires": 1}

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
        return {"id": uid, "username": "bob", "role": "user", "must_change_password": 0, "session_never_expires": 0}

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
        return {"id": uid, "username": "carol", "role": "user", "must_change_password": 0, "session_never_expires": 0}

    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)

    token = _make_expired_token("carol", 4, age_seconds=10)
    req = DummyRequest(cookies={"session": token})
    resp = Response()

    session = await app_module.require_auth(cast(Request, req), response=resp)

    assert session["user"] == "carol"
    # The response should have set a refreshed session cookie.
    cookies = [h for h in resp.raw_headers if h[0].decode().lower() == "set-cookie"]
    assert any(b"session=" in v for _, v in cookies), (
        f"expected refreshed session cookie, got headers: {resp.raw_headers}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# 5-6. /api/auth/status path
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_auth_status_emits_audit_on_idle_expiry(monkeypatch):
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 60)

    async def fake_get_user_by_id(uid):
        return {
            "id": uid,
            "username": "dave",
            "role": "user",
            "display_name": "",
            "must_change_password": 0,
            "session_never_expires": 0,
        }

    monkeypatch.setattr(auth_module.db, "get_user_by_id", fake_get_user_by_id)

    recorder = AuditRecorder()
    monkeypatch.setattr(auth_module, "_audit", recorder.record)

    token = _make_expired_token("dave", 11, age_seconds=300)
    req = DummyRequest(cookies={"session": token}, path="/api/auth/status")
    resp = Response()

    result = await auth_module.auth_status(cast(Request, req), resp)

    assert result["authenticated"] is False
    assert len(recorder.events) == 1
    assert recorder.events[0]["category"] == "auth"
    assert recorder.events[0]["action"] == "session.idle_timeout"
    assert recorder.events[0]["user"] == "dave"


@pytest.mark.asyncio
async def test_auth_status_returns_idle_fields_when_active(monkeypatch):
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 600)

    async def fake_get_user_by_id(uid):
        return {
            "id": uid,
            "username": "eve",
            "role": "user",
            "display_name": "Eve",
            "must_change_password": 0,
            "session_never_expires": 0,
        }

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
        return {
            "id": uid,
            "username": "screen",
            "role": "user",
            "display_name": "",
            "must_change_password": 0,
            "session_never_expires": 1,
        }

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


# ═════════════════════════════════════════════════════════════════════════════
# 7. Deleted users, revoked and over-age sessions (require_auth and status)
# ═════════════════════════════════════════════════════════════════════════════


def _make_token(user_id: int, *, epoch: int = 0, issued_age: int = 0, idle_age: int = 0) -> str:
    now = int(time.time())
    return app_module._serializer.dumps(
        {
            "user": "frank",
            "user_id": user_id,
            "session_epoch": epoch,
            "originally_issued_at": now - issued_age,
            "last_activity": now - idle_age,
        }
    )


def _user_row(uid: int, **over) -> dict:
    row = {
        "id": uid,
        "username": "frank",
        "role": "user",
        "display_name": "",
        "must_change_password": 0,
        "session_never_expires": 0,
        "session_epoch": 0,
    }
    row.update(over)
    return row


def _deletes_session_cookie(resp: Response) -> bool:
    return any(
        k.decode().lower() == "set-cookie" and v.startswith(b"session=") and b"Max-Age=0" in v
        for k, v in resp.raw_headers
    )


@pytest.mark.asyncio
async def test_require_auth_rejects_a_deleted_user(monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    async def no_user(uid):
        return None

    monkeypatch.setattr(app_module.db, "get_user_by_id", no_user)
    req = DummyRequest(cookies={"session": _make_token(21)}, path="/api/help-docs")
    resp = Response()
    with pytest.raises(HTTPException) as exc:
        await app_module.require_auth(cast(Request, req), response=resp)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Session user not found"
    assert _deletes_session_cookie(resp)


@pytest.mark.asyncio
async def test_require_auth_api_token_needs_no_user_row(monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "server-token-0001")

    async def no_user(uid):
        raise AssertionError("the API token has no user row to look up")

    monkeypatch.setattr(app_module.db, "get_user_by_id", no_user)
    req = DummyRequest(path="/api/help-docs")
    req.headers = {"x-api-token": "server-token-0001"}
    session = await app_module.require_auth(cast(Request, req), response=Response())
    assert session["auth_mode"] == "token"


@pytest.mark.parametrize(
    ("row", "token_kwargs"),
    [
        (None, {}),  # deleted user
        ({"session_epoch": 3}, {"epoch": 2}),  # revoked (password change, sign-out, rename)
        ({}, {"issued_age": app_module.SESSION_MAX_AGE + 60}),  # past the 24h cap
    ],
)
@pytest.mark.asyncio
async def test_auth_status_refuses_tokens_require_auth_refuses(monkeypatch, row, token_kwargs):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 1800)

    async def fake_get_user_by_id(uid):
        return None if row is None else _user_row(uid, **row)

    monkeypatch.setattr(auth_module.db, "get_user_by_id", fake_get_user_by_id)
    token = _make_token(22, **token_kwargs)

    with pytest.raises(HTTPException) as exc:
        await app_module.require_auth(cast(Request, DummyRequest(cookies={"session": token})), response=Response())
    assert exc.value.status_code == 401

    resp = Response()
    result = await auth_module.auth_status(cast(Request, DummyRequest(cookies={"session": token})), resp)
    assert result["authenticated"] is False
    assert "csrf_token" not in result and "username" not in result
    assert _deletes_session_cookie(resp)


@pytest.mark.asyncio
async def test_auth_status_keeps_the_forced_password_change_visible(monkeypatch):
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 1800)

    async def fake_get_user_by_id(uid):
        return _user_row(uid, must_change_password=1)

    async def fake_get_user_features(user):
        return []

    monkeypatch.setattr(auth_module.db, "get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(auth_module, "_get_user_features", fake_get_user_features)
    monkeypatch.setattr(auth_module, "_generate_csrf_token", lambda u: "csrf-stub")

    req = DummyRequest(cookies={"session": _make_token(23)}, path="/api/auth/status")
    result = await auth_module.auth_status(cast(Request, req), Response())
    assert result["authenticated"] is True
    assert result["must_change_password"] is True


# ═════════════════════════════════════════════════════════════════════════════
# 8. Change-password and profile routes enforce the idle timeout
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_profile_dependency_enforces_idle_timeout(monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setitem(state.LOGIN_RULES, "session_idle_timeout", 60)
    monkeypatch.setattr(auth_module, "_require_auth", app_module.require_auth)

    async def fake_get_user_by_id(uid):
        return _user_row(uid)

    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)
    recorder = AuditRecorder()
    with patch.object(app_module.shared, "_audit", recorder.record):
        req = DummyRequest(cookies={"session": _make_token(24, idle_age=300)}, path="/api/auth/profile")
        with pytest.raises(HTTPException) as exc:
            await auth_module._require_auth_dep(cast(Request, req), Response())
    assert exc.value.status_code == 401
    assert "idle" in str(exc.value.detail).lower()
    assert [e["action"] for e in recorder.events] == ["session.idle_timeout"]

    # An active session passes and gets its cookie refreshed.
    resp = Response()
    req = DummyRequest(cookies={"session": _make_token(24, idle_age=5)}, path="/api/auth/profile")
    session = await auth_module._require_auth_dep(cast(Request, req), resp)
    assert session["user_id"] == 24
    assert any(k.decode().lower() == "set-cookie" and v.startswith(b"session=") for k, v in resp.raw_headers)
