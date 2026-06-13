from __future__ import annotations

import asyncio
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


@pytest.mark.asyncio
async def test_postgres_audit_chain_concurrent_writers(monkeypatch):
    """Concurrent audit writes must not fork the hash chain on Postgres.

    Exercises the pg_advisory_lock acquire/release path in add_audit_event
    (the SQLite suite never runs it) and proves prev_hash linkage stays
    intact under concurrency within one process.
    """
    monkeypatch.setattr(db_module, "DB_ENGINE", "postgres")
    monkeypatch.setattr(db_module, "APP_DATABASE_URL", os.getenv("APP_DATABASE_URL", ""))

    await db_module.init_db()
    ids = await asyncio.gather(*(
        db_module.add_audit_event("ci", "pg.chain_smoke", user=f"writer{i}")
        for i in range(10)
    ))
    assert len(set(ids)) == 10

    result = await db_module.verify_audit_chain()
    assert result["ok"] is True, result
    assert result["total_rows"] >= 10


@pytest.mark.asyncio
async def test_postgres_audit_events_filtered_listing(monkeypatch):
    """Category-filtered listing works on Postgres (uses the 0055 index)."""
    monkeypatch.setattr(db_module, "DB_ENGINE", "postgres")
    monkeypatch.setattr(db_module, "APP_DATABASE_URL", os.getenv("APP_DATABASE_URL", ""))

    await db_module.init_db()
    await db_module.add_audit_event("ci_filter", "pg.listing_smoke", user="lister")
    events = await db_module.get_audit_events(limit=5, category="ci_filter")
    assert events and all(e["category"] == "ci_filter" for e in events)
