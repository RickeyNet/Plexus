from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime

import pytest
import routes.database as db_module


def _postgres_env_ready() -> bool:
    return bool(os.getenv("APP_DATABASE_URL"))


pytestmark = pytest.mark.skipif(
    not _postgres_env_ready(),
    reason="APP_DATABASE_URL not configured for postgres backend tests",
)


@pytest.fixture(autouse=True)
async def _close_pg_pool_after_test():
    # Each test runs on its own event loop (function-scoped loops), but the
    # asyncpg pool is module-global. Close it after every test so the pool
    # never outlives the loop that created it.
    yield
    await db_module.close_db_pool()


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
    ids = await asyncio.gather(
        *(db_module.add_audit_event("ci", "pg.chain_smoke", user=f"writer{i}") for i in range(10))
    )
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


@pytest.mark.asyncio
async def test_postgres_cloud_discovery_snapshot_updates_sync_status(monkeypatch):
    """Discovery snapshot commits and records sync status on Postgres.

    cloud_accounts timestamps are TEXT on Postgres; a ``::timestamptz`` cast
    on the ISO string parameter made asyncpg reject it and rolled back the
    whole snapshot.
    """
    monkeypatch.setattr(db_module, "DB_ENGINE", "postgres")
    monkeypatch.setattr(db_module, "APP_DATABASE_URL", os.getenv("APP_DATABASE_URL", ""))

    await db_module.init_db()
    account = await db_module.create_cloud_account(
        provider="aws",
        name="pg_smoke_cloud_account",
        account_identifier="000000000000",
        region_scope="us-east-1",
    )
    assert account is not None
    account_id = int(account["id"])
    try:
        summary = await db_module.replace_cloud_discovery_snapshot(
            account_id,
            resources=[
                {
                    "provider": "aws",
                    "resource_uid": "aws:sg:pg-smoke",
                    "resource_type": "security_group",
                    "name": "pg-smoke-sg",
                    "region": "us-east-1",
                    "status": "active",
                    "metadata": {
                        "policy_rules": [
                            {
                                "rule_name": "allow-https",
                                "direction": "ingress",
                                "action": "allow",
                                "protocol": "tcp",
                                "source": "0.0.0.0/0",
                                "ports": "443",
                            }
                        ]
                    },
                },
                {
                    "provider": "aws",
                    "resource_uid": "aws:vpc:pg-smoke",
                    "resource_type": "vpc",
                    "name": "pg-smoke-vpc",
                    "region": "us-east-1",
                    "cidr": "10.99.0.0/16",
                    "status": "available",
                },
            ],
            connections=[
                {
                    "provider": "aws",
                    "source_resource_uid": "aws:sg:pg-smoke",
                    "target_resource_uid": "aws:vpc:pg-smoke",
                    "connection_type": "attached",
                    "state": "up",
                }
            ],
            hybrid_links=[
                {
                    "provider": "aws",
                    "host_label": "pg-smoke-edge",
                    "cloud_resource_uid": "aws:vpc:pg-smoke",
                    "connection_type": "vpn",
                    "state": "up",
                }
            ],
            sync_status="success",
            sync_message="pg smoke",
        )
        assert summary == {
            "ok": True,
            "resources": 2,
            "connections": 1,
            "hybrid_links": 1,
            "policy_rules": 1,
        }

        refreshed = await db_module.get_cloud_account(account_id)
        assert refreshed is not None
        assert refreshed["last_sync_status"] == "success"
        assert refreshed["last_sync_message"] == "pg smoke"
        for field in ("last_sync_at", "updated_at"):
            value = refreshed[field]
            assert isinstance(value, str) and value
            datetime.fromisoformat(value)
        assert refreshed["resource_count"] == 2
        assert refreshed["connection_count"] == 1
        assert refreshed["hybrid_link_count"] == 1
    finally:
        await db_module.delete_cloud_account(account_id)


@pytest.mark.asyncio
async def test_postgres_meraki_org_build_status_update(monkeypatch):
    """Recording a topology build updates the org on Postgres.

    meraki_orgs.last_build_at is TIMESTAMPTZ on Postgres; binding the ISO
    string callers pass made asyncpg reject the update after every build.
    """
    monkeypatch.setattr(db_module, "DB_ENGINE", "postgres")
    monkeypatch.setattr(db_module, "APP_DATABASE_URL", os.getenv("APP_DATABASE_URL", ""))

    await db_module.init_db()
    name = "pg_smoke_meraki_org"
    stale = await db_module.get_meraki_org_by_name(name)
    if stale is not None:
        await db_module.delete_meraki_org(int(stale["id"]))
    org = await db_module.create_meraki_org(name=name, org_id="pg-smoke")
    assert org is not None
    org_ref = int(org["id"])
    try:
        updated = await db_module.update_meraki_org(
            org_ref,
            last_build_at=datetime.now(UTC).isoformat(),
            last_build_status="success",
            last_build_message="pg smoke",
        )
        assert updated is not None
        assert updated["last_build_status"] == "success"
        for field in ("last_build_at", "created_at", "updated_at"):
            value = updated[field]
            assert isinstance(value, str) and value
            datetime.fromisoformat(value)
    finally:
        await db_module.delete_meraki_org(org_ref)
