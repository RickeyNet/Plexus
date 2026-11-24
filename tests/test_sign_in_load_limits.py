"""Limits on how much password checking anonymous requests can cause: sign-ins
in progress per address, password checks at once on the whole server, one
local password hash per attempt, and self-registration under the anonymous
API rate limit. Every name is invented.
"""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.auth as auth
import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from fastapi import HTTPException
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, create_user

LOGIN = "/api/auth/login"
REGISTER = "/api/auth/register"
TEST_CLIENT_ADDRESS = "testclient"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    monkeypatch.setattr(app_module, "LOGIN_USERNAME_FAILURES", {}, raising=False)
    monkeypatch.setattr(auth, "_LOGIN_IN_FLIGHT", {})
    monkeypatch.setattr(auth, "_LOGIN_CHECKS", {})
    return client


def _message(resp) -> str:
    return resp.json()["error"]["message"]


def _sign_in(username: str, password: str):
    browser = TestClient(app_module.app, raise_server_exceptions=False)
    return browser.post(LOGIN, json={"username": username, "password": password})


def _failures(admin: CsrfClient) -> list[dict]:
    events = admin.raw.portal.call(db_module.get_audit_events, 100)
    return [e for e in events if e["action"] == "login.failure"]


# ── the slot counter ─────────────────────────────────────────────────────────


def test_a_slot_is_held_for_the_block_and_freed_after():
    running: dict[str, int] = {}
    with auth._sign_in_slot(running, "198.51.100.7", 2):
        with auth._sign_in_slot(running, "198.51.100.7", 2):
            assert running == {"198.51.100.7": 2}
            with pytest.raises(HTTPException) as refused:
                with auth._sign_in_slot(running, "198.51.100.7", 2):
                    pass
            assert refused.value.status_code == 429
            # Another address has its own slots.
            with auth._sign_in_slot(running, "198.51.100.8", 2):
                assert running["198.51.100.8"] == 1
        assert running == {"198.51.100.7": 1}
    assert running == {}


def test_a_slot_is_freed_when_the_block_fails():
    running: dict[str, int] = {}
    with pytest.raises(RuntimeError):
        with auth._sign_in_slot(running, "", 1):
            raise RuntimeError("the check failed")
    assert running == {}


# ── the sign-in route ────────────────────────────────────────────────────────


def test_sign_ins_in_progress_are_limited_per_address(admin, monkeypatch):
    create_user(admin, "yara")
    limit = int(state.LOGIN_RULES.get("max_attempts", 5))
    monkeypatch.setitem(auth._LOGIN_IN_FLIGHT, TEST_CLIENT_ADDRESS, limit)

    refused = _sign_in("yara", "not-the-password")
    assert refused.status_code == 429
    assert "at once" in _message(refused)
    # Refused before any password check: nothing counted, nothing audited.
    assert _failures(admin) == []
    assert auth._LOGIN_IN_FLIGHT == {TEST_CLIENT_ADDRESS: limit}

    monkeypatch.setitem(auth._LOGIN_IN_FLIGHT, TEST_CLIENT_ADDRESS, limit - 1)
    assert _sign_in("yara", "password123").status_code == 200
    assert auth._LOGIN_IN_FLIGHT == {TEST_CLIENT_ADDRESS: limit - 1}


def test_password_checks_are_limited_on_the_whole_server(admin, monkeypatch):
    create_user(admin, "yara")
    monkeypatch.setitem(auth._LOGIN_CHECKS, "", auth._LOGIN_CHECKS_MAX)

    refused = _sign_in("yara", "password123")
    assert refused.status_code == 429
    assert "at once" in _message(refused)
    assert _failures(admin) == []
    # The address's own slot was given back.
    assert auth._LOGIN_IN_FLIGHT == {}

    monkeypatch.setitem(auth._LOGIN_CHECKS, "", auth._LOGIN_CHECKS_MAX - 1)
    assert _sign_in("yara", "password123").status_code == 200
    assert auth._LOGIN_CHECKS == {"": auth._LOGIN_CHECKS_MAX - 1}


def test_slots_are_free_again_after_failed_and_successful_sign_ins(admin):
    create_user(admin, "yara")
    assert _sign_in("yara", "not-the-password").status_code == 401
    assert _sign_in("yara", "password123").status_code == 200
    assert auth._LOGIN_IN_FLIGHT == {} and auth._LOGIN_CHECKS == {}
    assert len(_failures(admin)) == 1


# ── one local password hash per attempt ──────────────────────────────────────


async def test_an_attempt_checks_the_local_password_once(monkeypatch):
    cfg = dict(state.AUTH_CONFIG_DEFAULTS)
    cfg["provider"] = "ldap"
    cfg["ldap"] = {
        **state.AUTH_CONFIG_DEFAULTS["ldap"],
        "enabled": True,
        "fallback_to_local": True,
        "fallback_on_reject": True,
    }
    monkeypatch.setattr(state, "AUTH_CONFIG", cfg)
    monkeypatch.setenv("PLEXUS_BREAKGLASS_LOCAL_ADMIN", "true")
    monkeypatch.delenv("PLEXUS_DEV_BOOTSTRAP", raising=False)
    checks: list[str] = []

    async def verify_user(username, password):
        checks.append(username)
        return None

    async def verify_ldap_user(username, password):
        return False, "error", {}

    monkeypatch.setattr(app_module, "verify_user", verify_user)
    monkeypatch.setattr(app_module, "verify_ldap_user", verify_ldap_user)

    user, _source, error = await app_module.authenticate_login_identity("yusuf", "not-the-password")
    assert user is None and error
    # Break-glass and the local fallback asked the same question once.
    assert checks == ["yusuf"]


# ── self-registration ────────────────────────────────────────────────────────


def test_self_registration_counts_against_the_anonymous_rate_limit(admin, monkeypatch):
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    monkeypatch.setattr(state, "API_RATE_LIMIT", {**state.API_RATE_LIMIT, "enabled": True, "max_write": 2})
    monkeypatch.setattr(state, "API_RATE_LIMIT_LOCK", asyncio.Lock())
    state.API_RATE_LIMIT_TRACKER.clear()

    def register(username: str):
        browser = TestClient(app_module.app, raise_server_exceptions=False)
        return browser.post(REGISTER, json={"username": username, "password": "password123"})

    try:
        assert [register(name).status_code for name in ("yves", "yoko", "yann")] == [200, 200, 429]
        assert admin.raw.portal.call(db_module.get_user_by_username, "yann") is None
        # Sign-in keeps its own limits and is not counted here.
        assert _sign_in("yves", "password123").status_code == 200
    finally:
        state.API_RATE_LIMIT_TRACKER.clear()
