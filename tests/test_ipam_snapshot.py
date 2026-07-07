"""Tests for snapshot_subnet_utilization address-space handling.

Regression coverage for the IPv6 OOM/hang: the old code called
``list(net.hosts())`` which materializes 2**64 addresses for an IPv6 /64,
exhausting memory. Utilization is now computed with O(1) integer membership
math, so an IPv6 subnet snapshots instantly. Also verifies /31 (RFC 3021)
reports two usable hosts instead of zero.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module


@pytest.fixture
def snap_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ipam_snapshot.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-ipam-snapshot")
    asyncio.run(db_module.init_db())
    return db_path


async def _add_host(hostname: str, ip: str) -> None:
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT OR IGNORE INTO inventory_groups (name) VALUES ('snap')"
        )
        cur2 = await db.execute("SELECT id FROM inventory_groups WHERE name='snap'")
        gid = int((await cur2.fetchone())[0])
        await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, ?)",
            (gid, hostname, ip),
        )
        await db.commit()
    finally:
        await db.close()


def test_ipv6_64_snapshot_does_not_enumerate(snap_db):
    """A /64 has 2**64 addresses; this must return quickly, not hang."""
    async def _go():
        await _add_host("v6host", "2001:db8::5")
        # Wall-clock guard: enumeration would never finish; membership math is
        # instant. asyncio.wait_for fails loudly if we regress to enumeration.
        row = await asyncio.wait_for(
            db_module.snapshot_subnet_utilization("2001:db8::/64"), timeout=10
        )
        assert row is not None
        assert row["used"] == 1
        # total is clamped to fit SQLite's signed 64-bit INTEGER column.
        assert row["total"] >= 1

    asyncio.run(_go())


def test_slash31_reports_two_usable_hosts(snap_db):
    async def _go():
        await _add_host("p2p-a", "10.10.0.0")
        await _add_host("p2p-b", "10.10.0.1")
        row = await db_module.snapshot_subnet_utilization("10.10.0.0/31")
        assert row["total"] == 2
        assert row["used"] == 2
        assert row["free"] == 0

    asyncio.run(_go())


def test_slash30_excludes_network_and_broadcast(snap_db):
    async def _go():
        # .0 network, .3 broadcast, .1/.2 usable.
        await _add_host("u1", "10.20.0.1")
        await _add_host("u2", "10.20.0.2")
        await _add_host("net", "10.20.0.0")  # network addr — not usable
        row = await db_module.snapshot_subnet_utilization("10.20.0.0/30")
        assert row["total"] == 2
        assert row["used"] == 2  # network address is not counted

    asyncio.run(_go())


def test_reservations_dedup_against_used(snap_db):
    async def _go():
        await _add_host("h", "10.30.0.5")
        db = await db_module.get_db()
        try:
            await db.execute(
                "INSERT INTO ipam_reservations (subnet, start_ip, end_ip, reason) "
                "VALUES ('10.30.0.0/24', '10.30.0.5', '10.30.0.9', 'r')"
            )
            await db.commit()
        finally:
            await db.close()
        row = await db_module.snapshot_subnet_utilization("10.30.0.0/24")
        # .5 is both used and reserved → counted once as used; .6-.9 reserved.
        assert row["used"] == 1
        assert row["reserved"] == 4

    asyncio.run(_go())
