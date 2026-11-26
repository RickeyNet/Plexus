"""Postgres backend round-trips through the real database facade.

Every test gets a fresh clone of the migrated template database (see
tests/conftest.py), and conftest keeps one asyncpg pool per event loop and
disposes them all after each test.
"""

from __future__ import annotations

import asyncio
import importlib
from datetime import UTC, datetime

import pytest
import routes.database as db_module

import pg_raw


@pytest.mark.asyncio
async def test_postgres_backend_init_and_user_roundtrip():
    await db_module.init_db()

    username = "pg_smoke_user"
    user_id = await db_module.create_user(
        username=username,
        password_hash="hash",
        salt="salt",
        display_name="PG Smoke",
        role="user",
        must_change_password=False,
    )

    assert user_id > 0
    user = await db_module.get_user_by_username(username)
    assert user is not None
    assert user["username"] == username


@pytest.mark.asyncio
async def test_postgres_delete_expired_jobs_path():
    await db_module.init_db()
    deleted = await db_module.delete_expired_jobs(30)
    assert isinstance(deleted, int)
    assert deleted >= 0


@pytest.mark.asyncio
async def test_postgres_audit_chain_concurrent_writers():
    """Concurrent audit writes must not fork the hash chain on Postgres.

    Exercises the pg_advisory_lock acquire/release path in add_audit_event
    and proves prev_hash linkage stays intact under concurrency within one
    process.
    """
    await db_module.init_db()
    ids = await asyncio.gather(
        *(db_module.add_audit_event("ci", "pg.chain_smoke", user=f"writer{i}") for i in range(10))
    )
    assert len(set(ids)) == 10

    result = await db_module.verify_audit_chain()
    assert result["ok"] is True, result
    assert result["total_rows"] >= 10


@pytest.mark.asyncio
async def test_postgres_audit_events_filtered_listing():
    """Category-filtered listing works on Postgres (uses the 0055 index)."""
    await db_module.init_db()
    await db_module.add_audit_event("ci_filter", "pg.listing_smoke", user="lister")
    events = await db_module.get_audit_events(limit=5, category="ci_filter")
    assert events and all(e["category"] == "ci_filter" for e in events)


@pytest.mark.asyncio
async def test_postgres_cloud_discovery_snapshot_updates_sync_status():
    """Discovery snapshot commits and records sync status on Postgres.

    cloud_accounts timestamps are TEXT on Postgres; a ``::timestamptz`` cast
    on the ISO string parameter made asyncpg reject it and rolled back the
    whole snapshot.
    """
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
async def test_postgres_meraki_org_build_status_update():
    """Recording a topology build updates the org on Postgres.

    meraki_orgs.last_build_at is TIMESTAMPTZ on Postgres; binding the ISO
    string callers pass made asyncpg reject the update after every build.
    """
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


@pytest.mark.asyncio
async def test_postgres_meraki_compliance_assignment_and_results():
    """Meraki compliance writes on Postgres: the create helpers return row ids
    (lastrowid was None until the tables joined _INSERT_ID_TABLES), the
    due-assignment query's datetime(col, '+' || col || ' seconds') rewrite
    runs, and the retention delete accepts an int day count (``$1::text``
    made asyncpg reject it)."""
    await db_module.init_db()
    name = "pg_smoke_meraki_compliance_org"
    stale = await db_module.get_meraki_org_by_name(name)
    if stale is not None:
        await db_module.delete_meraki_org(int(stale["id"]))
    org = await db_module.create_meraki_org(name=name, org_id="pg-smoke")
    assert org is not None
    org_ref = int(org["id"])
    profile_id = await db_module.create_compliance_profile(name="pg_smoke_meraki_profile")
    assignment_id = None
    result_ids: list[int] = []
    try:
        assignment_id = await db_module.create_meraki_compliance_assignment(profile_id, org_ref, interval_seconds=3600)
        assert isinstance(assignment_id, int) and assignment_id > 0

        due = {a["id"] for a in await db_module.get_meraki_compliance_assignments_due()}
        assert assignment_id in due  # never scanned
        await db_module.record_meraki_compliance_assignment_scan(assignment_id, "success", "pg smoke")
        due = {a["id"] for a in await db_module.get_meraki_compliance_assignments_due()}
        assert assignment_id not in due  # scanned just now, interval not elapsed

        result_ids = await db_module.store_meraki_compliance_results(
            scan_id="pg-smoke",
            assignment_id=assignment_id,
            profile_id=profile_id,
            org_ref=org_ref,
            results=[{"target_kind": "organization", "status": "non-compliant", "findings": []}],
        )
        assert len(result_ids) == 1 and isinstance(result_ids[0], int)
        assert await db_module.get_meraki_compliance_result(result_ids[0]) is not None

        deleted = await db_module.delete_old_meraki_compliance_results(90)
        assert isinstance(deleted, int)
        assert await db_module.get_meraki_compliance_result(result_ids[0]) is not None  # too new to delete
    finally:
        for result_id in result_ids:
            await db_module.delete_meraki_compliance_result(result_id)
        if assignment_id:
            await db_module.delete_meraki_compliance_assignment(assignment_id)
        await db_module.delete_meraki_org(org_ref)
        await db_module.delete_compliance_profile(profile_id)


_PERF_INDEXES = {
    "idx_avail_transitions_poll": ("availability_transitions", "(poll_id)", None),
    "idx_monitoring_alerts_open_dedup": ("monitoring_alerts", "(dedup_key)", "acknowledged = 0"),
    "idx_monitoring_alerts_open_host_metric": ("monitoring_alerts", "(host_id, metric)", "acknowledged = 0"),
    "idx_mac_history_host_mac": ("mac_tracking_history", "(host_id, mac_address, id)", None),
    "idx_mac_history_seen_at": ("mac_tracking_history", "(seen_at)", None),
    "idx_route_snapshots_host_id": ("route_snapshots", "(host_id, id)", None),
    "idx_config_backups_host_id": ("config_backups", "(host_id, id)", None),
}
_DROPPED_FLOW_INDEXES = {"idx_flow_src", "idx_flow_dst"}


async def _index_defs() -> dict[str, tuple[str, str]]:
    rows = await pg_raw.fetch(
        "SELECT indexname, tablename, indexdef FROM pg_indexes WHERE schemaname = current_schema()"
    )
    return {r["indexname"]: (r["tablename"], r["indexdef"]) for r in rows}


def _assert_perf_indexes(defs: dict[str, tuple[str, str]]) -> None:
    for name, (table, cols, predicate) in _PERF_INDEXES.items():
        assert name in defs, name
        defined_on, indexdef = defs[name]
        assert defined_on == table
        assert cols in indexdef, indexdef
        if predicate:
            assert f"WHERE ({predicate})" in indexdef, indexdef
        else:
            assert "WHERE" not in indexdef, indexdef
    assert not _DROPPED_FLOW_INDEXES & defs.keys()


@pytest.mark.asyncio
async def test_init_db_creates_hot_path_indexes_and_drops_unused_flow_ones():
    await db_module.init_db()
    _assert_perf_indexes(await _index_defs())


@pytest.mark.asyncio
async def test_migration_0142_upgrades_an_existing_database():
    migration = importlib.import_module("routes.migrations.0142_add_perf_indexes_drop_unused_flow_indexes")
    await db_module.init_db()
    # Put the indexes back the way a database from before 0142 had them.
    for name in _PERF_INDEXES:
        await pg_raw.execute(f"DROP INDEX {name}")
    await pg_raw.execute("CREATE INDEX idx_flow_src ON flow_records(src_ip, received_at)")
    await pg_raw.execute("CREATE INDEX idx_flow_dst ON flow_records(dst_ip, received_at)")
    db = await db_module.get_db()
    try:
        await migration.up(db)
        await migration.up(db)  # re-running is a no-op
    finally:
        await db.close()
    _assert_perf_indexes(await _index_defs())
    # Startup re-applies SCHEMA on every boot; it must not bring the flow indexes back.
    await db_module.init_db()
    _assert_perf_indexes(await _index_defs())
    assert migration.VERSION == 142
