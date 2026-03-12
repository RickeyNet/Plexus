from __future__ import annotations

import os

import pytest
import routes.database as db_module


def _postgres_env_ready() -> bool:
    return bool(os.getenv("APP_DATABASE_URL"))


pytestmark = pytest.mark.skipif(
    not _postgres_env_ready(),
    reason="APP_DATABASE_URL not configured for postgres backend tests",
)


@pytest.mark.asyncio
async def test_postgres_backend_init_and_user_roundtrip(monkeypatch):
    monkeypatch.setattr(db_module, "DB_ENGINE", "postgres")
    monkeypatch.setattr(db_module, "APP_DATABASE_URL", os.getenv("APP_DATABASE_URL", ""))

    await db_module.init_db()

    username = "pg_smoke_user"
    try:
        user_id = await db_module.create_user(
            username=username,
            password_hash="hash",
            salt="salt",
            display_name="PG Smoke",
            role="user",
            must_change_password=False,
        )
    except ValueError:
        # User may already exist from previous runs; fetch and reuse.
        row = await db_module.get_user_by_username(username)
        assert row is not None
        user_id = int(row["id"])

    assert user_id > 0
    user = await db_module.get_user_by_username(username)
    assert user is not None
    assert user["username"] == username


@pytest.mark.asyncio
async def test_postgres_delete_expired_jobs_path(monkeypatch):
    monkeypatch.setattr(db_module, "DB_ENGINE", "postgres")
    monkeypatch.setattr(db_module, "APP_DATABASE_URL", os.getenv("APP_DATABASE_URL", ""))

    await db_module.init_db()
    deleted = await db_module.delete_expired_jobs(30)
    assert isinstance(deleted, int)
    assert deleted >= 0
