"""Password sign-in: per-username progressive delay and equal-cost failures.

Per-IP limits alone let many addresses guess one account's password, and
an unknown username used to fail without hashing anything, so response
time told an attacker which usernames exist. Every failed password
sign-in now counts against the username (a growing, capped delay before
the next attempt, never a lock), and an unknown username costs the same
password hash as a known one.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import cast

import netcontrol.app as app_module
import netcontrol.routes.auth as auth
import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from fastapi import HTTPException, Request
from netcontrol.bounded_map import BoundedDict


def _fast_hash(password: str, salt: str = "") -> str:
    """The stand-in for the real password hasher: one PBKDF2 round, so the
    tests do not pay for the production work factor."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 1).hex()


class _Req:
    def __init__(self, ip: str) -> None:
        self.client = SimpleNamespace(host=ip)
        self.headers: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self.state = SimpleNamespace(correlation_id="corr-1")
        self.url = SimpleNamespace(path="/api/auth/login")


@pytest.fixture
def env(monkeypatch):
    """Local provider, fast hasher, fresh trackers, recorded sleeps."""
    calls: list[tuple[str, str]] = []

    def counting_hash(password: str, salt: str = "") -> str:
        calls.append((password, salt))
        return _fast_hash(password, salt)

    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    audits: list[tuple[str, str, str]] = []

    async def fake_audit(category, action, user="", detail="", correlation_id=""):
        audits.append((action, user, detail))

    monkeypatch.setattr(app_module, "_hash_password", counting_hash)
    monkeypatch.setattr(app_module, "AUTH_CONFIG", {"provider": "local"})
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    failures = BoundedDict(1000, state.username_failures_expired)
    monkeypatch.setattr(app_module, "LOGIN_USERNAME_FAILURES", failures, raising=False)
    monkeypatch.setattr(auth, "_login_delay_sleep", fake_sleep)
    monkeypatch.setattr(app_module, "_audit", fake_audit)

    async def no_features(user):
        return []

    monkeypatch.setattr(app_module, "_get_user_features", no_features)
    monkeypatch.setenv("PLEXUS_BREAKGLASS_LOCAL_ADMIN", "false")
    return SimpleNamespace(calls=calls, sleeps=sleeps, failures=failures, audits=audits)


async def _make_user(username: str, password: str, role: str = "user") -> None:
    await db_module.init_db()
    salt = "s-" + username
    await db_module.create_user(username, _fast_hash(password, salt), salt, role=role)


async def _login(username: str, password: str, ip: str = "192.0.2.10"):
    body = app_module.LoginRequest(username=username, password=password)
    return await app_module.login(body, cast(Request, _Req(ip)))


async def _fail(username: str, password: str = "wrong-password", ip: str = "192.0.2.10") -> HTTPException:
    with pytest.raises(HTTPException) as exc:
        await _login(username, password, ip)
    return exc.value


# ── Equal cost and equal answer for unknown usernames ───────────────────────


@pytest.mark.asyncio
async def test_unknown_username_runs_the_same_password_hash(env):
    await _make_user("alice", "correct-horse")
    env.calls.clear()
    assert await app_module.verify_user("nobody-here", "guess") is None
    assert len(env.calls) == 1
    assert env.calls[0][0] == "guess"

    env.calls.clear()
    assert await app_module.verify_user("alice", "guess") is None
    assert len(env.calls) == 1


@pytest.mark.asyncio
async def test_unknown_and_known_username_fail_the_same_way(env):
    await _make_user("alice", "correct-horse")
    env.calls.clear()
    unknown = await _fail("nobody-here", ip="192.0.2.11")
    hashes_unknown = len(env.calls)
    env.calls.clear()
    known = await _fail("alice", ip="192.0.2.12")
    assert (
        (unknown.status_code, unknown.detail)
        == (known.status_code, known.detail)
        == (
            401,
            "Invalid username or password",
        )
    )
    assert hashes_unknown == len(env.calls) >= 1


@pytest.mark.asyncio
async def test_breakglass_path_also_hashes_for_unknown_usernames(env, monkeypatch):
    monkeypatch.setenv("PLEXUS_BREAKGLASS_LOCAL_ADMIN", "true")
    await _make_user("alice", "correct-horse")
    env.calls.clear()
    await _fail("nobody-here", ip="192.0.2.11")
    unknown = len(env.calls)
    env.calls.clear()
    await _fail("alice", ip="192.0.2.12")
    assert unknown == len(env.calls) == 2


# ── Per-username progressive delay ──────────────────────────────────────────


def test_delay_schedule_grows_and_is_capped():
    free = state.USERNAME_FAILURE_FREE_ATTEMPTS
    assert [auth._username_delay_for(n) for n in range(free + 7)] == [0.0] * free + [1, 2, 4, 8, 16, 30, 30]
    assert auth._username_delay_for(10_000) == state.USERNAME_FAILURE_MAX_DELAY == 30


@pytest.mark.asyncio
async def test_failures_from_many_addresses_slow_the_next_attempt(env):
    await _make_user("alice", "correct-horse")
    # Each attempt from a different address: the per-IP limit never trips.
    for i in range(6):
        await _fail("alice", ip=f"198.51.100.{i + 1}")
    assert env.sleeps == [1, 2, 4]
    await _fail("ALICE", ip="198.51.100.50")  # same account, other case
    assert env.sleeps[-1] == 8


@pytest.mark.asyncio
async def test_the_delay_never_locks_the_real_user_out(env):
    await _make_user("alice", "correct-horse")
    for i in range(40):
        await _fail("alice", ip=f"203.0.113.{i + 1}")
    assert max(env.sleeps) == state.USERNAME_FAILURE_MAX_DELAY
    # Still allowed in with the right password, after at most the cap.
    resp = await _login("alice", "correct-horse", ip="192.0.2.99")
    assert json.loads(resp.body)["username"] == "alice"
    assert env.sleeps[-1] <= state.USERNAME_FAILURE_MAX_DELAY


@pytest.mark.asyncio
async def test_success_resets_the_username_counter(env):
    await _make_user("alice", "correct-horse")
    for i in range(5):
        await _fail("alice", ip=f"198.51.100.{i + 1}")
    assert env.failures
    await _login("alice", "correct-horse", ip="198.51.100.77")
    assert auth._username_key("alice") not in env.failures
    env.sleeps.clear()
    await _fail("alice", ip="198.51.100.78")
    assert env.sleeps == []


@pytest.mark.asyncio
async def test_unknown_usernames_are_counted_too(env):
    await db_module.init_db()
    for i in range(4):
        await _fail("ghost", ip=f"198.51.100.{i + 1}")
    assert env.sleeps == [1]


@pytest.mark.asyncio
async def test_parallel_attempts_are_spaced_not_fired_together(env):
    await _make_user("alice", "correct-horse")
    for i in range(state.USERNAME_FAILURE_FREE_ATTEMPTS + 1):
        await _fail("alice", ip=f"198.51.100.{i + 1}")
    env.sleeps.clear()
    # Reserve three slots at the same instant: each waits longer than the last.
    now = 1_000_000.0
    key = auth._username_key("alice")
    env.failures[key] = [state.USERNAME_FAILURE_FREE_ATTEMPTS + 1, now, 0.0]
    waits = [auth._reserve_username_slot(key, now) for _ in range(3)]
    assert waits == [2, 4, 6]
    many = [auth._reserve_username_slot(key, now) for _ in range(50)]
    assert max(many) == state.USERNAME_FAILURE_MAX_DELAY


def test_failure_entries_expire_after_the_reset_window():
    reset = state.USERNAME_FAILURE_RESET_SECONDS
    assert not state.username_failures_expired("k", [5, 100.0, 0.0], 100.0 + reset - 1)
    assert state.username_failures_expired("k", [5, 100.0, 0.0], 100.0 + reset + 1)
    # A reservation in the future keeps the entry.
    assert not state.username_failures_expired("k", [5, 100.0, 100.0 + reset + 50], 100.0 + reset + 1)


def test_tracker_is_bounded():
    assert isinstance(state.LOGIN_USERNAME_FAILURES, BoundedDict)
    assert state.LOGIN_USERNAME_FAILURES.max_entries == state.TRACKER_MAX_ENTRIES


@pytest.mark.asyncio
async def test_old_failures_stop_counting(env):
    await _make_user("alice", "correct-horse")
    key = auth._username_key("alice")
    import time

    env.failures[key] = [20, time.time() - state.USERNAME_FAILURE_RESET_SECONDS - 5, 0.0]
    await _fail("alice", ip="198.51.100.9")
    assert env.sleeps == []
    assert env.failures[key][0] == 1
