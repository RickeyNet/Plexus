"""Regression tests for admin user-management hardening.

  * delete_user_guarded refuses to remove the last admin, with the check inside
    the DELETE statement so concurrent deletes can't both slip through and lock
    everyone out.
  * create/update user reject an invalid role instead of silently coercing it.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module


@pytest.fixture
def user_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "admin_users.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-admin-users")
    asyncio.run(db_module.init_db())
    return db_path


async def _mk(username: str, role: str) -> int:
    return await db_module.create_user(username, "hash", "salt", display_name=username, role=role)


def test_delete_user_guarded_blocks_last_admin(user_db):
    async def _go():
        a1 = await _mk("admin1", "admin")
        a2 = await _mk("admin2", "admin")
        u1 = await _mk("user1", "user")

        # A regular user deletes fine.
        assert await db_module.delete_user_guarded(u1) == "deleted"
        # One of two admins deletes fine.
        assert await db_module.delete_user_guarded(a1) == "deleted"
        # The last admin is protected.
        assert await db_module.delete_user_guarded(a2) == "last_admin"
        # ...and is still present.
        assert await db_module.get_user_by_id(a2) is not None

    asyncio.run(_go())


def test_delete_user_guarded_not_found(user_db):
    async def _go():
        assert await db_module.delete_user_guarded(999999) == "not_found"

    asyncio.run(_go())


# ── HTTP role validation ─────────────────────────────────────────────────────

def _auth_client(tmp_path, monkeypatch, request):
    import netcontrol.app as app_module

    db_path = str(tmp_path / "admin_http.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-admin-http")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    csrf = resp.json().get("csrf_token", "")
    return client, csrf


def test_create_user_rejects_invalid_role(tmp_path, monkeypatch, request):
    client, csrf = _auth_client(tmp_path, monkeypatch, request)
    resp = client.post(
        "/api/admin/users",
        json={"username": "bob", "password": "password123", "role": "administrator"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 400


def test_create_user_accepts_valid_role(tmp_path, monkeypatch, request):
    client, csrf = _auth_client(tmp_path, monkeypatch, request)
    resp = client.post(
        "/api/admin/users",
        json={"username": "carol", "password": "password123", "role": "user"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201
