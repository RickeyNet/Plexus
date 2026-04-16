"""Tests for cloud visibility account and topology foundation."""

import pytest
import routes.database as db_module
from netcontrol.routes.cloud_visibility import _build_sample_discovery_snapshot


async def _init(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_cloud_visibility.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


async def _add_host(group_name="core", hostname="core-sw1", ip="10.0.0.10"):
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)",
            (group_name,),
        )
        if cur.lastrowid:
            group_id = cur.lastrowid
        else:
            q = await db.execute("SELECT id FROM inventory_groups WHERE name = ?", (group_name,))
            group_id = (await q.fetchone())[0]

        cur = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, ?)",
            (group_id, hostname, ip),
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_cloud_account_crud(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)

    created = await db_module.create_cloud_account(
        provider="aws",
        name="AWS Prod",
        account_identifier="123456789012",
        region_scope="us-east-1",
        auth_type="api_keys",
        auth_config_json={"secret_ref": "aws-prod-readonly"},
        notes="Primary production account",
        enabled=1,
        created_by="admin",
    )
    assert created is not None
    assert created["provider"] == "aws"
    assert created["name"] == "AWS Prod"

    listed = await db_module.list_cloud_accounts(provider="aws")
    assert len(listed) == 1
    assert listed[0]["account_identifier"] == "123456789012"

    updated = await db_module.update_cloud_account(
        int(created["id"]),
        notes="Updated note",
        enabled=0,
        auth_config_json={"secret_ref": "aws-prod-updated"},
    )
    assert updated is not None
    assert updated["notes"] == "Updated note"
    assert updated["enabled"] == 0

    deleted = await db_module.delete_cloud_account(int(created["id"]))
    assert deleted
    assert await db_module.get_cloud_account(int(created["id"])) is None


@pytest.mark.asyncio
async def test_replace_cloud_snapshot_and_read_topology(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()
    account = await db_module.create_cloud_account(provider="azure", name="Azure Core")
    assert account is not None

    summary = await db_module.replace_cloud_discovery_snapshot(
        int(account["id"]),
        resources=[
            {
                "provider": "azure",
                "resource_uid": "azure:vnet:core",
                "resource_type": "vnet",
                "name": "core-vnet",
                "region": "centralus",
                "cidr": "10.50.0.0/16",
                "status": "connected",
            },
            {
                "provider": "azure",
                "resource_uid": "azure:er:primary",
                "resource_type": "expressroute",
                "name": "er-primary",
                "region": "centralus",
                "status": "up",
            },
        ],
        connections=[
            {
                "provider": "azure",
                "source_resource_uid": "azure:vnet:core",
                "target_resource_uid": "azure:er:primary",
                "connection_type": "expressroute_gateway",
                "state": "up",
            }
        ],
        hybrid_links=[
            {
                "provider": "azure",
                "host_id": host_id,
                "host_label": "core-sw1",
                "cloud_resource_uid": "azure:er:primary",
                "connection_type": "expressroute",
                "state": "up",
            }
        ],
    )
    assert summary["ok"]
    assert summary["resources"] == 2
    assert summary["connections"] == 1
    assert summary["hybrid_links"] == 1

    snapshot = await db_module.get_cloud_topology_snapshot(account_id=int(account["id"]))
    assert snapshot["summary"]["resource_count"] == 2
    assert snapshot["summary"]["connection_count"] == 1
    assert snapshot["summary"]["hybrid_link_count"] == 1

    resource_uids = {r["resource_uid"] for r in snapshot["resources"]}
    assert "azure:vnet:core" in resource_uids
    assert "azure:er:primary" in resource_uids


@pytest.mark.asyncio
async def test_sample_discovery_snapshot_builds_hybrid_links(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host(hostname="edge-rtr1", ip="10.0.0.20")
    account = await db_module.create_cloud_account(provider="gcp", name="GCP Shared")
    assert account is not None

    resources, connections, hybrid_links = await _build_sample_discovery_snapshot(
        account,
        connect_host_ids=[host_id],
        include_hybrid_links=True,
    )

    assert resources
    assert connections
    assert hybrid_links
    assert any(r["resource_type"] == "cloud_router" for r in resources)
    assert any(c["connection_type"] == "vpn_tunnel" for c in connections)
    assert any(int(link.get("host_id") or 0) == host_id for link in hybrid_links)
