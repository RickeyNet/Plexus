"""The API rate limiter's exemption needs a session that is still a login.

A signed cookie alone used to exempt its holder from the anonymous per-IP
limit for good, including the cookie of a deleted account and a revoked
one. Those are counted as anonymous; an idle session of a live account is
still exempt (a stale tab must not throttle its own address).
"""

from __future__ import annotations

import asyncio
import time

import netcontrol.app as app_module
import netcontrol.routes.state as state
import pytest
from starlette.requests import Request

CLIENT = "192.0.2.9"
LIMIT = 2


def _token(user_id: int, *, epoch: int = 0, idle_for: int = 0) -> str:
    now = int(time.time())
    return app_module._serializer.dumps(
        {
            "user": "alice",
            "user_id": user_id,
            "session_epoch": epoch,
            "originally_issued_at": now,
            "last_activity": now - idle_for,
        }
    )


def _request(token: str | None) -> Request:
    headers = [(b"cookie", f"session={token}".encode())] if token else []
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/inventory",
        "query_string": b"",
        "headers": headers,
        "client": (CLIENT, 40000),
        "state": {},
    }
    return Request(scope)


async def _statuses(token: str | None, count: int) -> list[int]:
    async def call_next(request):
        return type("R", (), {"status_code": 200})()

    out = []
    for _ in range(count):
        response = await app_module.api_rate_limit_middleware(_request(token), call_next)
        out.append(response.status_code)
    return out


@pytest.fixture
def limiter(monkeypatch):
    users = {
        7: {"id": 7, "username": "alice", "session_epoch": 3, "session_never_expires": 0},
    }

    async def get_user_by_id(user_id):
        return users.get(user_id)

    monkeypatch.setattr(app_module.db, "get_user_by_id", get_user_by_id)
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setattr(
        state, "API_RATE_LIMIT", {**state.API_RATE_LIMIT, "enabled": True, "max_read": LIMIT, "window": 60}
    )
    # Created at application start; the middleware counts nothing without it.
    monkeypatch.setattr(state, "API_RATE_LIMIT_LOCK", asyncio.Lock())
    state.API_RATE_LIMIT_TRACKER.clear()
    yield users
    state.API_RATE_LIMIT_TRACKER.clear()


async def test_anonymous_requests_are_limited(limiter):
    assert await _statuses(None, LIMIT + 1) == [200] * LIMIT + [429]


async def test_live_session_is_exempt(limiter):
    assert await _statuses(_token(7, epoch=3), LIMIT + 3) == [200] * (LIMIT + 3)


async def test_idle_session_of_a_live_account_is_exempt(limiter):
    stale = _token(7, epoch=3, idle_for=7 * 24 * 3600)
    assert await _statuses(stale, LIMIT + 3) == [200] * (LIMIT + 3)


async def test_revoked_session_counts_as_anonymous(limiter):
    # The account's epoch moved on (password change, admin reset, sign-out).
    assert await _statuses(_token(7, epoch=2), LIMIT + 1) == [200] * LIMIT + [429]


async def test_deleted_users_session_counts_as_anonymous(limiter):
    assert await _statuses(_token(99), LIMIT + 1) == [200] * LIMIT + [429]


async def test_forged_cookie_counts_as_anonymous_without_a_user_lookup(limiter, monkeypatch):
    async def never(user_id):
        raise AssertionError("an unsigned cookie must not reach the database")

    monkeypatch.setattr(app_module.db, "get_user_by_id", never)
    assert await _statuses("not-a-signed-token", LIMIT + 1) == [200] * LIMIT + [429]
