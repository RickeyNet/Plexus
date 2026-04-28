"""Tests for VRF/VLAN-aware IPAM scoping (Phase G)."""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db_module


@pytest.fixture
def vrf_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ipam_vrf.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-ipam-vrf")

    async def _prepare():
        await db_module.init_db()

    asyncio.run(_prepare())
    return db_path


async def _seed_groups_and_hosts(rows: list[tuple[str, str, str, str]]) -> None:
    """Seed groups + hosts. rows = [(group, hostname, ip, vrf_name)]."""
    db = await db_module.get_db()
    try:
        groups: dict[str, int] = {}
        for group, hostname, ip, vrf in rows:
            if group not in groups:
                cur = await db.execute(
                    "INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)", (group,)
                )
                if cur.lastrowid:
                    groups[group] = int(cur.lastrowid)
                else:
                    cur2 = await db.execute(
                        "SELECT id FROM inventory_groups WHERE name = ?", (group,)
                    )
                    row = await cur2.fetchone()
                    groups[group] = int(row[0])
            await db.execute(
                "INSERT INTO hosts (group_id, hostname, ip_address, vrf_name, status) "
                "VALUES (?, ?, ?, ?, ?)",
                (groups[group], hostname, ip, vrf, "online"),
            )
        await db.commit()
    finally:
        await db.close()


def test_same_ip_different_vrfs_is_not_a_conflict(vrf_db):
    async def _go():
        await _seed_groups_and_hosts([
            ("Branch-A", "rtr-a", "10.0.0.1", "tenant-a"),
            ("Branch-B", "rtr-b", "10.0.0.1", "tenant-b"),
        ])
        overview = await db_module.get_ipam_overview()
        # Same IP but different VRFs — must NOT be flagged as duplicate
        dups = overview["duplicate_ips"]
        assert dups == [], f"unexpected duplicates: {dups}"
        assert overview["summary"]["duplicate_ip_count"] == 0
        # Two distinct (subnet, vrf) rows
        assert overview["summary"]["total_subnets"] == 2
        assert set(overview["summary"]["vrf_names"]) == {"tenant-a", "tenant-b"}

    asyncio.run(_go())


def test_same_ip_same_vrf_in_two_groups_is_a_conflict(vrf_db):
    async def _go():
        await _seed_groups_and_hosts([
            ("Core-DC", "core1", "10.0.0.5", "global"),
            ("Edge-DC", "edge1", "10.0.0.5", "global"),
        ])
        overview = await db_module.get_ipam_overview()
        dups = overview["duplicate_ips"]
        assert len(dups) == 1
        assert dups[0]["ip_address"] == "10.0.0.5"
        assert dups[0]["vrf_name"] == "global"
        assert sorted(dups[0]["groups"]) == ["Core-DC", "Edge-DC"]

    asyncio.run(_go())


def test_overview_subnet_rows_carry_vrf(vrf_db):
    async def _go():
        await _seed_groups_and_hosts([
            ("Tenant-A-Net", "host-a", "192.168.10.5", "tenant-a"),
            ("Tenant-B-Net", "host-b", "192.168.10.5", "tenant-b"),
        ])
        overview = await db_module.get_ipam_overview()
        subnets = {(s["subnet"], s["vrf_name"]) for s in overview["subnets"]}
        # Same /24 appears twice — once per VRF
        assert ("192.168.10.0/24", "tenant-a") in subnets
        assert ("192.168.10.0/24", "tenant-b") in subnets

    asyncio.run(_go())


def test_empty_vrf_treated_as_global_default(vrf_db):
    async def _go():
        await _seed_groups_and_hosts([
            ("Legacy-A", "host-a", "172.16.0.10", ""),
            ("Legacy-B", "host-b", "172.16.0.10", ""),
        ])
        overview = await db_module.get_ipam_overview()
        # Both have empty VRF → treated as same VRF → conflict
        dups = overview["duplicate_ips"]
        assert len(dups) == 1
        assert dups[0]["ip_address"] == "172.16.0.10"
        assert dups[0]["vrf_name"] == ""

    asyncio.run(_go())


def test_host_create_persists_vrf_and_vlan(vrf_db):
    async def _go():
        db = await db_module.get_db()
        try:
            cur = await db.execute("INSERT INTO inventory_groups (name) VALUES ('G1')")
            gid = int(cur.lastrowid)
            await db.commit()
        finally:
            await db.close()

        hid = await db_module.add_host(
            gid, "h1", "10.20.30.40", vrf_name="prod", vlan_id="100",
        )
        assert hid > 0

        db = await db_module.get_db()
        try:
            cur = await db.execute(
                "SELECT vrf_name, vlan_id FROM hosts WHERE id = ?", (hid,)
            )
            row = await cur.fetchone()
        finally:
            await db.close()
        assert row[0] == "prod"
        assert row[1] == "100"

        await db_module.update_host(
            hid, "h1", "10.20.30.40", "cisco_ios", vrf_name="dev", vlan_id="200",
        )
        db = await db_module.get_db()
        try:
            cur = await db.execute(
                "SELECT vrf_name, vlan_id FROM hosts WHERE id = ?", (hid,)
            )
            row = await cur.fetchone()
        finally:
            await db.close()
        assert row[0] == "dev"
        assert row[1] == "200"

    asyncio.run(_go())


def test_replace_ipam_snapshot_inherits_vrf_from_prefix(vrf_db):
    async def _go():
        # Create an IPAM source
        db = await db_module.get_db()
        try:
            cur = await db.execute(
                "INSERT INTO ipam_sources (provider, name, base_url, auth_type) "
                "VALUES ('netbox', 'src1', 'http://x', 'token')"
            )
            sid = int(cur.lastrowid)
            await db.commit()
        finally:
            await db.close()

        await db_module.replace_ipam_source_snapshot(
            sid,
            prefixes=[
                {"external_id": "1", "subnet": "10.50.0.0/24",
                 "vrf": "lab", "vlan": "50", "description": "lab-net"},
            ],
            allocations=[
                # Allocation has no explicit VRF — should inherit from prefix
                {"address": "10.50.0.1", "prefix_subnet": "10.50.0.0/24"},
            ],
        )

        db = await db_module.get_db()
        try:
            cur = await db.execute(
                "SELECT vrf_name, vlan_id FROM ipam_allocations WHERE source_id = ?",
                (sid,),
            )
            row = await cur.fetchone()
        finally:
            await db.close()
        assert row[0] == "lab"
        assert row[1] == "50"

    asyncio.run(_go())
