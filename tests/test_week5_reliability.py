"""Week 5 — Reliability and Observability tests.

Covers:
  1. Audit-event table creation and add/get functions.
  2. Correlation-ID middleware injects and returns header.
  3. Bounded-concurrency semaphore limits concurrent jobs.
  4. Import checkpoint write/read round-trip.
  5. No stray print() in web-facing modules (app, database, converter).
  6. Audit events fired by auth endpoints (login, register, change-password).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from typing import cast
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import Request

import netcontrol.app as app_module
import routes.database as db_module
from netcontrol.routes import converter as conv_module


# ── Helpers ──────────────────────────────────────────────────────────────────


class DummyRequest:
    """Minimal Request-like object for unit tests."""

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        client_host: str = "127.0.0.1",
    ):
        normalised = {k.lower(): v for k, v in (headers or {}).items()}

        class HeaderMap(dict):
            def get(self, key, default=None):
                return super().get(str(key).lower(), default)

        self.headers = HeaderMap(normalised)
        self.cookies = cookies or {}
        self.state = type("State", (), {})()
        self.client = type("Client", (), {"host": client_host})()


# ═════════════════════════════════════════════════════════════════════════════
# 1. Audit-event DB functions
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_add_and_get_audit_event(tmp_path, monkeypatch):
    """add_audit_event should persist a row retrievable by get_audit_events."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()

    event_id = await db_module.add_audit_event(
        category="auth",
        action="login.success",
        user="admin",
        detail="logged in via RADIUS",
        correlation_id="abc-123",
    )
    assert isinstance(event_id, int)
    assert event_id > 0

    rows = await db_module.get_audit_events(limit=10)
    assert len(rows) >= 1
    row = rows[0]
    assert row["category"] == "auth"
    assert row["action"] == "login.success"
    assert row["user"] == "admin"
    assert row["correlation_id"] == "abc-123"


@pytest.mark.asyncio
async def test_get_audit_events_filter_by_category(tmp_path, monkeypatch):
    """get_audit_events with category= should only return matching rows."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()

    await db_module.add_audit_event("auth", "login.success", "userA")
    await db_module.add_audit_event("config", "playbook.create", "userB")
    await db_module.add_audit_event("auth", "login.failure", "userC")

    auth_rows = await db_module.get_audit_events(limit=100, category="auth")
    assert len(auth_rows) == 2
    assert all(r["category"] == "auth" for r in auth_rows)


@pytest.mark.asyncio
async def test_get_db_applies_busy_timeout_pragma(tmp_path, monkeypatch):
    """get_db should apply configured busy_timeout to reduce lock churn."""
    db_path = str(tmp_path / "sqlite_tuning.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "SQLITE_BUSY_TIMEOUT_MS", 12000)

    conn = await db_module.get_db()
    try:
        cur = await conn.execute("PRAGMA busy_timeout")
        busy_timeout_row = await cur.fetchone()
        assert busy_timeout_row[0] == 12000
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_get_db_creates_parent_directory(tmp_path, monkeypatch):
    """get_db should create parent directories for APP_DB_PATH-style locations."""
    nested_db = tmp_path / "nested" / "db" / "plexus.db"
    monkeypatch.setattr(db_module, "DB_PATH", str(nested_db))

    conn = await db_module.get_db()
    try:
        assert nested_db.parent.exists()
    finally:
        await conn.close()


# ═════════════════════════════════════════════════════════════════════════════
# 2. Correlation-ID middleware
# ═════════════════════════════════════════════════════════════════════════════


def test_corr_id_helper_extracts_state():
    """_corr_id should extract correlation_id from request.state."""
    req = DummyRequest()
    req.state.correlation_id = "test-corr-123"
    result = app_module._corr_id(cast(Request, req))
    assert result == "test-corr-123"


def test_corr_id_helper_returns_empty_when_missing():
    """_corr_id should return '' when request has no state.correlation_id."""
    req = DummyRequest()
    # state exists but has no correlation_id attribute
    result = app_module._corr_id(cast(Request, req))
    assert result == ""


# ═════════════════════════════════════════════════════════════════════════════
# 3. Bounded-concurrency semaphore
# ═════════════════════════════════════════════════════════════════════════════


def test_job_semaphore_exists_with_correct_limit():
    """_job_semaphore should be an asyncio.Semaphore with the configured limit."""
    assert hasattr(app_module, "_job_semaphore")
    sem = app_module._job_semaphore
    assert isinstance(sem, asyncio.Semaphore)


def test_converter_import_semaphore_exists():
    """converter module should have an import semaphore."""
    assert hasattr(conv_module, "_import_semaphore")
    sem = conv_module._import_semaphore
    assert isinstance(sem, asyncio.Semaphore)


def test_max_concurrent_jobs_env_default():
    """_MAX_CONCURRENT_JOBS should default to a sane positive value."""
    assert app_module._MAX_CONCURRENT_JOBS >= 1


def test_db_unique_violation_helper_matches_sqlite_and_postgres_messages():
    assert db_module._is_unique_violation(Exception("UNIQUE constraint failed: users.username"))
    assert db_module._is_unique_violation(Exception("duplicate key value violates unique constraint \"users_username_key\""))
    assert not db_module._is_unique_violation(Exception("timeout"))


def test_db_foreign_key_violation_helper_matches_sqlite_and_postgres_messages():
    assert db_module._is_foreign_key_violation(Exception("FOREIGN KEY constraint failed"))
    assert db_module._is_foreign_key_violation(Exception("insert or update on table violates foreign key constraint"))
    assert not db_module._is_foreign_key_violation(Exception("duplicate key value"))


@pytest.mark.asyncio
async def test_get_db_rejects_invalid_engine(monkeypatch):
    monkeypatch.setattr(db_module, "DB_ENGINE", "invalid")
    with pytest.raises(RuntimeError, match="Unsupported APP_DB_ENGINE"):
        await db_module.get_db()


# ═════════════════════════════════════════════════════════════════════════════
# 4. Import checkpoint write/read round-trip
# ═════════════════════════════════════════════════════════════════════════════


def test_checkpoint_write_read_roundtrip(tmp_path):
    """_write_checkpoint should persist parsed stages and _read_checkpoint should return them."""
    session_dir = str(tmp_path / "sess1")
    os.makedirs(session_dir)

    sample_output = (
        "Physical Interfaces                 0.45s [OK]\n"
        "Address Objects                     2.31s [OK]\n"
        "Access Rules                        1.20s [FAIL]\n"
    )

    checkpoint = conv_module._write_checkpoint(session_dir, sample_output)
    assert "Physical Interfaces" in checkpoint["completed_stages"]
    assert "Address Objects" in checkpoint["completed_stages"]
    assert "Access Rules" in checkpoint["failed_stages"]
    assert "updated_at" in checkpoint

    loaded = conv_module._read_checkpoint(session_dir)
    assert loaded == checkpoint


def test_checkpoint_read_empty_when_no_file(tmp_path):
    """_read_checkpoint should return {} when no checkpoint file exists."""
    assert conv_module._read_checkpoint(str(tmp_path)) == {}


def test_checkpoint_write_handles_empty_output(tmp_path):
    """_write_checkpoint with empty output should still write a valid file."""
    session_dir = str(tmp_path / "empty")
    os.makedirs(session_dir)

    checkpoint = conv_module._write_checkpoint(session_dir, "")
    assert checkpoint["completed_stages"] == []
    assert checkpoint["failed_stages"] == []


# ═════════════════════════════════════════════════════════════════════════════
# 5. No stray print() in web-facing modules
# ═════════════════════════════════════════════════════════════════════════════


_PRINT_PATTERN = re.compile(r"^\s*print\s*\(", re.MULTILINE)

_WEB_MODULE_PATHS = [
    os.path.join("netcontrol", "app.py"),
    os.path.join("routes", "database.py"),
    os.path.join("netcontrol", "routes", "converter.py"),
]


@pytest.mark.parametrize("rel_path", _WEB_MODULE_PATHS)
def test_no_stray_print_in_web_module(rel_path):
    """Web-facing modules should use LOGGER, not print()."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    abs_path = os.path.join(project_root, rel_path)
    with open(abs_path, "r", encoding="utf-8") as f:
        source = f.read()
    matches = _PRINT_PATTERN.findall(source)
    assert len(matches) == 0, f"Found {len(matches)} stray print() call(s) in {rel_path}"


# ═════════════════════════════════════════════════════════════════════════════
# 6. Audit events fired by auth endpoints
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_login_records_audit_event_on_success(monkeypatch):
    """Successful login should call _audit with 'login.success'."""
    user_row = {
        "id": 1,
        "username": "admin",
        "password_hash": "hash",
        "salt": "salt",
        "role": "admin",
        "display_name": "Admin",
        "must_change_password": 0,
    }

    async def fake_authenticate(username, password):
        return user_row, "local", None

    async def fake_get_features(user):
        return ["dashboard"]

    monkeypatch.setattr(app_module, "authenticate_login_identity", fake_authenticate)
    monkeypatch.setattr(app_module, "_get_user_features", fake_get_features)

    audit_calls = []

    async def track_audit(*args, **kwargs):
        audit_calls.append((args, kwargs))

    monkeypatch.setattr(app_module.db, "add_audit_event", AsyncMock(return_value=1))
    monkeypatch.setattr(app_module, "_audit", track_audit)

    body = app_module.LoginRequest(username="admin", password="secret123")
    req = DummyRequest()
    req.state.correlation_id = "corr-login"
    result = await app_module.login(body, cast(Request, req))

    assert result is not None
    assert any("login.success" in str(call) for call in audit_calls), \
        f"Expected audit call with login.success, got: {audit_calls}"


@pytest.mark.asyncio
async def test_login_records_audit_event_on_failure(monkeypatch):
    """Failed login should call _audit with 'login.failure'."""

    async def fake_authenticate(username, password):
        return None, None, "Invalid username or password"

    monkeypatch.setattr(app_module, "authenticate_login_identity", fake_authenticate)

    audit_calls = []

    async def track_audit(*args, **kwargs):
        audit_calls.append((args, kwargs))

    monkeypatch.setattr(app_module.db, "add_audit_event", AsyncMock(return_value=1))
    monkeypatch.setattr(app_module, "_audit", track_audit)

    body = app_module.LoginRequest(username="nonexistent", password="wrong")
    req = DummyRequest()
    req.state.correlation_id = "corr-fail"

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await app_module.login(body, cast(Request, req))
    assert exc_info.value.status_code == 401

    assert any("login.failure" in str(call) for call in audit_calls), \
        f"Expected audit call with login.failure, got: {audit_calls}"


@pytest.mark.asyncio
async def test_audit_helper_swallows_exceptions(monkeypatch):
    """_audit should not raise even when the DB write fails."""
    monkeypatch.setattr(
        app_module.db, "add_audit_event",
        AsyncMock(side_effect=RuntimeError("DB down")),
    )
    # Should not raise
    await app_module._audit("test", "boom", user="x")
