"""Tests for historical IP allocation tracking (Phase I)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db_module


@pytest.fixture
def hist_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ipam_history.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-ipam-history")

    async def _prepare():
        await db_module.init_db()

    asyncio.run(_prepare())
    return db_path


async def _ensure_group(name: str) -> int:
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)", (name,)
        )
        if cur.lastrowid:
            gid = int(cur.lastrowid)
        else:
            cur2 = await db.execute(
                "SELECT id FROM inventory_groups WHERE name = ?", (name,)
            )
            row = await cur2.fetchone()
            gid = int(row[0])
        await db.commit()
        return gid
    finally:
        await db.close()


def test_add_host_records_assignment(hist_db):
    async def _go():
        gid = await _ensure_group("G1")
        host_id = await db_module.add_host(gid, "rtr1", "10.0.0.5")
        history = await db_module.get_ip_history("10.0.0.5")
        assert len(history) == 1
        assert history[0]["hostname"] == "rtr1"
        assert history[0]["source_type"] == "host"
        assert history[0]["source_ref"] == str(host_id)
        assert history[0]["ended_at"] is None

    asyncio.run(_go())


def test_remove_host_closes_history(hist_db):
    async def _go():
        gid = await _ensure_group("G1")
        host_id = await db_module.add_host(gid, "rtr2", "10.0.0.6")
        await db_module.remove_host(host_id)
        history = await db_module.get_ip_history("10.0.0.6")
        assert len(history) == 1
        assert history[0]["ended_at"] is not None

    asyncio.run(_go())


def test_update_host_changes_ip_creates_release_then_assignment(hist_db):
    async def _go():
        gid = await _ensure_group("G1")
        host_id = await db_module.add_host(gid, "rtr3", "10.0.0.7")
        await db_module.update_host(host_id, "rtr3", "10.0.0.8", "cisco_ios")

        old = await db_module.get_ip_history("10.0.0.7")
        new = await db_module.get_ip_history("10.0.0.8")
        assert len(old) == 1
        assert old[0]["ended_at"] is not None
        assert len(new) == 1
        assert new[0]["ended_at"] is None
        assert new[0]["hostname"] == "rtr3"

    asyncio.run(_go())


def test_find_ip_owner_at_returns_correct_lifespan(hist_db):
    async def _go():
        gid = await _ensure_group("G1")
        await db_module.record_ip_assignment(
            address="10.1.0.1", hostname="alpha", source_type="host", source_ref="1"
        )
        # Manually backdate started_at
        db = await db_module.get_db()
        try:
            await db.execute(
                "UPDATE ipam_ip_history SET started_at='2024-01-01T00:00:00', "
                "ended_at='2024-06-01T00:00:00' WHERE address='10.1.0.1'"
            )
            await db.execute(
                """INSERT INTO ipam_ip_history (address, hostname, started_at)
                   VALUES ('10.1.0.1', 'beta', '2024-06-01T00:00:01')"""
            )
            await db.commit()
        finally:
            await db.close()

        # Query a date in the alpha window
        owner = await db_module.find_ip_owner_at("10.1.0.1", "2024-03-15T12:00:00")
        assert owner is not None
        assert owner["hostname"] == "alpha"

        # Query in the beta window (open)
        owner2 = await db_module.find_ip_owner_at("10.1.0.1", "2025-01-01T00:00:00")
        assert owner2 is not None
        assert owner2["hostname"] == "beta"
        assert owner2["ended_at"] is None

        # Query before any assignment
        owner3 = await db_module.find_ip_owner_at("10.1.0.1", "2020-01-01T00:00:00")
        assert owner3 is None

    asyncio.run(_go())


def test_vrf_isolation_in_history(hist_db):
    async def _go():
        await db_module.record_ip_assignment(
            address="172.16.0.1", hostname="ha", vrf_name="tenant-a"
        )
        await db_module.record_ip_assignment(
            address="172.16.0.1", hostname="hb", vrf_name="tenant-b"
        )
        a = await db_module.get_ip_history("172.16.0.1", vrf_name="tenant-a")
        b = await db_module.get_ip_history("172.16.0.1", vrf_name="tenant-b")
        assert len(a) == 1
        assert a[0]["hostname"] == "ha"
        assert len(b) == 1
        assert b[0]["hostname"] == "hb"

    asyncio.run(_go())


def test_record_assignment_dedup_same_owner(hist_db):
    async def _go():
        await db_module.record_ip_assignment(
            address="10.5.0.1", hostname="x", source_type="host", source_ref="9"
        )
        await db_module.record_ip_assignment(
            address="10.5.0.1", hostname="x", source_type="host", source_ref="9"
        )
        rows = await db_module.get_ip_history("10.5.0.1")
        assert len(rows) == 1

    asyncio.run(_go())


def test_snapshot_subnet_utilization_counts_correctly(hist_db):
    async def _go():
        gid = await _ensure_group("G1")
        # /29 = 6 usable hosts. Add 2.
        await db_module.add_host(gid, "h1", "10.50.0.1")
        await db_module.add_host(gid, "h2", "10.50.0.2")
        # Add a reservation of .3
        await db_module.create_ipam_reservation(
            "10.50.0.0/29", start_ip="10.50.0.3", end_ip="10.50.0.3",
            reason="lab", created_by="t",
        )
        # Add a pending allocation (.4)
        await db_module.allocate_next_ip(subnet="10.50.0.0/29")

        snap = await db_module.snapshot_subnet_utilization("10.50.0.0/29")
        assert snap is not None
        assert snap["total"] == 6
        assert snap["used"] == 2
        assert snap["reserved"] == 1
        assert snap["pending"] == 1
        assert snap["free"] == 2
        assert 49.0 < snap["utilization_pct"] < 67.0

    asyncio.run(_go())


def test_list_subnet_utilization_filters(hist_db):
    async def _go():
        await db_module.snapshot_subnet_utilization("10.60.0.0/30")
        await db_module.snapshot_subnet_utilization("10.61.0.0/30")
        all_rows = await db_module.list_subnet_utilization()
        assert len(all_rows) >= 2

        only = await db_module.list_subnet_utilization(subnet="10.60.0.0/30")
        assert len(only) == 1
        assert only[0]["subnet"] == "10.60.0.0/30"

    asyncio.run(_go())


def test_snapshot_all_subnets_covers_inventory(hist_db):
    async def _go():
        gid = await _ensure_group("G1")
        await db_module.add_host(gid, "h1", "192.168.42.10")
        written = await db_module.snapshot_all_subnet_utilization()
        assert written >= 1
        rows = await db_module.list_subnet_utilization()
        # The /24 inferred from 192.168.42.10 should appear
        assert any(r["subnet"].startswith("192.168.42.") for r in rows)

    asyncio.run(_go())


def test_prune_history_removes_old_closed_rows(hist_db):
    async def _go():
        await db_module.record_ip_assignment(address="10.70.0.1", hostname="old")
        await db_module.record_ip_release(address="10.70.0.1")
        # Backdate ended_at far into the past
        db = await db_module.get_db()
        try:
            await db.execute(
                "UPDATE ipam_ip_history SET ended_at='2000-01-01T00:00:00' "
                "WHERE address='10.70.0.1'"
            )
            await db.commit()
        finally:
            await db.close()

        removed = await db_module.prune_ip_history(retention_days=30)
        assert removed == 1
        rows = await db_module.get_ip_history("10.70.0.1")
        assert rows == []

    asyncio.run(_go())


def test_create_local_ipam_allocation_records_history(hist_db):
    async def _go():
        builtin = await db_module.get_or_create_builtin_ipam_source()
        alloc = await db_module.create_local_ipam_allocation(
            source_id=builtin["id"],
            subnet="10.80.0.0/24",
            address="10.80.0.42",
            hostname="srv1",
            description="test",
            created_by="tester",
        )
        assert alloc is not None
        history = await db_module.get_ip_history("10.80.0.42")
        assert len(history) == 1
        assert history[0]["hostname"] == "srv1"
        assert history[0]["source_type"] == "ipam_allocation"

    asyncio.run(_go())
