"""Tests for IPAM-driven provisioning (Phase H) — allocate_next_ip + lifecycle."""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module


@pytest.fixture
def alloc_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ipam_allocate.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-ipam-allocate")

    async def _prepare():
        await db_module.init_db()

    asyncio.run(_prepare())
    return db_path


async def _seed_host(group: str, hostname: str, ip: str, vrf: str = "") -> None:
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)", (group,)
        )
        if cur.lastrowid:
            gid = int(cur.lastrowid)
        else:
            cur2 = await db.execute(
                "SELECT id FROM inventory_groups WHERE name = ?", (group,)
            )
            row = await cur2.fetchone()
            gid = int(row[0])
        await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address, vrf_name, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (gid, hostname, ip, vrf, "online"),
        )
        await db.commit()
    finally:
        await db.close()


def test_allocate_next_ip_skips_inventory_hosts(alloc_db):
    async def _go():
        await _seed_host("G1", "h1", "10.0.0.1")
        await _seed_host("G1", "h2", "10.0.0.2")
        result = await db_module.allocate_next_ip(
            subnet="10.0.0.0/29", hostname="new-device"
        )
        assert result["address"] == "10.0.0.3"
        assert result["state"] == "pending"
        assert result["subnet"] == "10.0.0.0/29"
        assert result["id"] > 0

    asyncio.run(_go())


def test_allocate_concurrent_calls_dont_collide(alloc_db):
    async def _go():
        a = await db_module.allocate_next_ip(subnet="192.168.1.0/30")
        b = await db_module.allocate_next_ip(subnet="192.168.1.0/30")
        # /30 has two usable hosts: .1 and .2
        assert a["address"] == "192.168.1.1"
        assert b["address"] == "192.168.1.2"
        # Third should fail — no addresses left
        with pytest.raises(ValueError, match="No available"):
            await db_module.allocate_next_ip(subnet="192.168.1.0/30")

    asyncio.run(_go())


def test_allocate_respects_existing_reservations(alloc_db):
    async def _go():
        # Reserve .1–.3
        await db_module.create_ipam_reservation(
            "10.10.0.0/29",
            start_ip="10.10.0.1",
            end_ip="10.10.0.3",
            reason="lab gear",
            created_by="tester",
        )
        result = await db_module.allocate_next_ip(subnet="10.10.0.0/29")
        assert result["address"] == "10.10.0.4"

    asyncio.run(_go())


def test_allocate_vrf_isolation(alloc_db):
    async def _go():
        await _seed_host("Tenant-A", "ha", "172.16.0.1", vrf="tenant-a")
        # Same address occupied in tenant-a should not block allocation in tenant-b
        result = await db_module.allocate_next_ip(
            subnet="172.16.0.0/29", vrf_name="tenant-b"
        )
        assert result["address"] == "172.16.0.1"
        assert result["vrf_name"] == "tenant-b"

    asyncio.run(_go())


def test_release_frees_ip_for_re_allocation(alloc_db):
    async def _go():
        first = await db_module.allocate_next_ip(subnet="10.20.0.0/30")
        assert first["address"] == "10.20.0.1"

        # Mark released
        await db_module.update_pending_allocation_state(first["id"], state="released")

        # Now .1 should be available again
        second = await db_module.allocate_next_ip(subnet="10.20.0.0/30")
        assert second["address"] == "10.20.0.1"
        assert second["id"] != first["id"]

    asyncio.run(_go())


def test_expire_stale_pending_allocations(alloc_db):
    async def _go():
        # Allocate with TTL of 60s (will not expire on its own)
        result = await db_module.allocate_next_ip(
            subnet="10.30.0.0/30", ttl_seconds=60
        )
        # Manually backdate expires_at to the past
        db = await db_module.get_db()
        try:
            await db.execute(
                "UPDATE ipam_pending_allocations SET expires_at = '2000-01-01T00:00:00' WHERE id = ?",
                (result["id"],),
            )
            await db.commit()
        finally:
            await db.close()

        expired = await db_module.expire_stale_pending_allocations()
        assert expired == 1

        refreshed = await db_module.get_pending_allocation(result["id"])
        assert refreshed["state"] == "released"

        # Address is free again
        new = await db_module.allocate_next_ip(subnet="10.30.0.0/30")
        assert new["address"] == "10.30.0.1"

    asyncio.run(_go())


def test_invalid_subnet_raises(alloc_db):
    async def _go():
        with pytest.raises(ValueError, match="Invalid subnet"):
            await db_module.allocate_next_ip(subnet="not-a-cidr")

    asyncio.run(_go())


def test_list_pending_allocations_filters_by_state(alloc_db):
    async def _go():
        a = await db_module.allocate_next_ip(subnet="10.40.0.0/29")
        b = await db_module.allocate_next_ip(subnet="10.40.0.0/29")
        await db_module.update_pending_allocation_state(a["id"], state="released")

        pending_only = await db_module.list_pending_allocations(state="pending")
        pending_ids = {p["id"] for p in pending_only}
        assert b["id"] in pending_ids
        assert a["id"] not in pending_ids

        released_only = await db_module.list_pending_allocations(state="released")
        released_ids = {p["id"] for p in released_only}
        assert a["id"] in released_ids

    asyncio.run(_go())
