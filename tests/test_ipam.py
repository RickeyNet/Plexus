"""Tests for lightweight IPAM overview API."""

from __future__ import annotations

import netcontrol.app as app_module
import netcontrol.routes.ipam as ipam_routes
import pytest
import routes.database as db_module


class _AuthClient:
    def __init__(self, client, csrf_token: str):
        self._client = client
        self._csrf = csrf_token

    def _merge_headers(self, kw):
        headers = kw.pop("headers", {})
        headers["X-CSRF-Token"] = self._csrf
        kw["headers"] = headers

    def get(self, url, **kw):
        return self._client.get(url, **kw)

    def post(self, url, **kw):
        self._merge_headers(kw)
        return self._client.post(url, **kw)


def _auth_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ipam_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-ipam")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "0")
    monkeypatch.setenv("PLEXUS_INITIAL_ADMIN_PASSWORD", "netcontrol")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    import asyncio

    async def _prepare_db():
        await db_module.init_db()
        db = await db_module.get_db()
        try:
            await db.execute(
                "INSERT INTO inventory_groups (name) VALUES ('bootstrap-sentinel')"
            )
            await db.commit()
        finally:
            await db.close()

    asyncio.run(_prepare_db())

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "netcontrol"},
    )
    data = response.json()
    csrf_token = data.get("csrf_token", "")
    if data.get("must_change_password"):
        client.post(
            "/api/auth/change-password",
            json={
                "current_password": "netcontrol",
                "new_password": "netcontrol-updated",
            },
            headers={"X-CSRF-Token": csrf_token},
        )
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "netcontrol-updated"},
        )
        csrf_token = response.json().get("csrf_token", "")
    return _AuthClient(client, csrf_token)


def _seed_ipam_data():
    async def _seed():
        db = await db_module.get_db()
        try:
            core_cursor = await db.execute(
                "INSERT INTO inventory_groups (name) VALUES ('IPAM Core')"
            )
            access_cursor = await db.execute(
                "INSERT INTO inventory_groups (name) VALUES ('IPAM Access')"
            )
            remote_cursor = await db.execute(
                "INSERT INTO inventory_groups (name) VALUES ('IPAM Remote')"
            )
            core_group_id = int(core_cursor.lastrowid)
            access_group_id = int(access_cursor.lastrowid)
            remote_group_id = int(remote_cursor.lastrowid)

            await db.execute(
                "INSERT INTO hosts (id, group_id, hostname, ip_address, status) VALUES (101, ?, 'core-sw-01', '10.0.0.1', 'online')",
                (core_group_id,),
            )
            await db.execute(
                "INSERT INTO hosts (id, group_id, hostname, ip_address, status) VALUES (201, ?, 'access-sw-01', '10.0.0.20', 'online')",
                (access_group_id,),
            )
            await db.execute(
                "INSERT INTO hosts (id, group_id, hostname, ip_address, status) VALUES (301, ?, 'remote-rtr-01', '10.0.0.20', 'warning')",
                (remote_group_id,),
            )
            await db.execute(
                "INSERT INTO hosts (id, group_id, hostname, ip_address, status) VALUES (302, ?, 'remote-rtr-02', '10.0.1.5/24', 'online')",
                (remote_group_id,),
            )

            await db.execute(
                "INSERT INTO cloud_accounts (id, provider, name, account_identifier, enabled) VALUES (1, 'aws', 'Prod AWS', '123456789012', 1)"
            )
            await db.execute(
                """INSERT INTO cloud_resources
                   (account_id, provider, resource_uid, resource_type, name, region, cidr, metadata_json)
                   VALUES (1, 'aws', 'vpc-1', 'vpc', 'prod-vpc', 'us-east-1', '10.0.0.0/24', '{}')"""
            )
            await db.execute(
                """INSERT INTO cloud_resources
                   (account_id, provider, resource_uid, resource_type, name, region, cidr, metadata_json)
                   VALUES (1, 'aws', 'subnet-1', 'subnet', 'app-subnet', 'us-east-1', '10.0.2.0/24', '{}')"""
            )
            await db.commit()
            return {
                "core_group_id": core_group_id,
                "access_group_id": access_group_id,
                "remote_group_id": remote_group_id,
            }
        finally:
            await db.close()

    return _seed()


def _seed_external_ipam_snapshot():
    async def _seed():
        source = await db_module.create_ipam_source(
            provider="netbox",
            name="NetBox Lab",
            base_url="https://netbox.example/api",
            auth_type="token",
            auth_config={"token": "token-value"},
            enabled=1,
            verify_tls=0,
            created_by="admin",
        )
        assert source is not None
        await db_module.replace_ipam_source_snapshot(
            int(source["id"]),
            prefixes=[
                {
                    "external_id": "prefix-100",
                    "subnet": "10.0.0.0/24",
                    "description": "Campus users",
                    "status": "active",
                }
            ],
            allocations=[
                {
                    "address": "10.0.0.30",
                    "dns_name": "user-vip.example",
                    "status": "active",
                    "description": "VIP",
                    "prefix_subnet": "10.0.0.0/24",
                }
            ],
        )
        return source

    return _seed()


def test_ipam_overview_returns_subnets_and_duplicates(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)
    try:
        import asyncio

        asyncio.run(_seed_ipam_data())

        response = client.get("/api/ipam/overview")
        assert response.status_code == 200
        body = response.json()

        summary = body["summary"]
        assert summary["inventory_host_count"] == 4
        assert summary["total_subnets"] == 3
        assert summary["inventory_subnets"] == 2
        assert summary["cloud_subnets"] == 2
        assert summary["duplicate_ip_count"] == 1
        assert summary["exact_source_overlap_count"] == 1

        subnet_map = {item["subnet"]: item for item in body["subnets"]}
        assert subnet_map["10.0.0.0/24"]["inventory_host_count"] == 3
        assert subnet_map["10.0.0.0/24"]["cloud_resource_count"] == 1
        assert subnet_map["10.0.0.0/24"]["group_names"] == ["IPAM Access", "IPAM Core", "IPAM Remote"]
        assert subnet_map["10.0.2.0/24"]["inventory_host_count"] == 0
        assert subnet_map["10.0.2.0/24"]["cloud_resource_count"] == 1

        duplicates = body["duplicate_ips"]
        assert len(duplicates) == 1
        assert duplicates[0]["ip_address"] == "10.0.0.20"
        assert duplicates[0]["host_count"] == 2
        assert duplicates[0]["groups"] == ["IPAM Access", "IPAM Remote"]
    finally:
        client._client.__exit__(None, None, None)


def test_ipam_overview_group_filter_scopes_inventory_only(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)
    try:
        import asyncio

        seeded = asyncio.run(_seed_ipam_data())

        response = client.get(f"/api/ipam/overview?group_id={seeded['core_group_id']}")
        assert response.status_code == 200
        body = response.json()

        assert body["summary"]["group_id"] == seeded["core_group_id"]
        assert body["summary"]["inventory_host_count"] == 1

        subnet_map = {item["subnet"]: item for item in body["subnets"]}
        assert subnet_map["10.0.0.0/24"]["inventory_host_count"] == 1
        assert subnet_map["10.0.0.0/24"]["group_names"] == ["IPAM Core"]
        assert body["duplicate_ips"] == []
    finally:
        client._client.__exit__(None, None, None)


def test_ipam_subnet_detail_reports_available_capacity_and_allocations(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)
    try:
        import asyncio

        asyncio.run(_seed_ipam_data())
        asyncio.run(_seed_external_ipam_snapshot())

        reservation_response = client.post(
            "/api/ipam/subnets/10.0.0.0%2F24/reservations",
            json={
                "start_ip": "10.0.0.1",
                "end_ip": "10.0.0.10",
                "reason": "Gateway and DHCP reserve",
            },
        )
        assert reservation_response.status_code == 200

        response = client.get("/api/ipam/subnets/10.0.0.0%2F24")
        assert response.status_code == 200
        body = response.json()

        summary = body["summary"]
        assert summary["inventory_host_count"] == 3
        assert summary["external_allocation_count"] == 1
        assert summary["usable_address_count"] == 254
        assert summary["reserved_address_count"] == 10
        assert summary["allocated_address_count"] == 2
        assert summary["available_address_count"] == 242

        allocations = body["allocations"]
        assert any(item["source_type"] == "inventory" and item["ip_address"] == "10.0.0.20" for item in allocations)
        assert any(item["source_type"] == "external" and item["ip_address"] == "10.0.0.30" for item in allocations)
        assert any(item["is_reserved"] for item in allocations if item["ip_address"] == "10.0.0.1")

        reservations = body["reservations"]
        assert any(item["kind"] == "custom" and item["address_count"] == 10 for item in reservations)
        assert body["available_preview"][0] == "10.0.0.11"
    finally:
        client._client.__exit__(None, None, None)


def test_ipam_source_sync_updates_overview_contract(tmp_path, monkeypatch):
    client = _auth_client(tmp_path, monkeypatch)
    try:
        async def _fake_collect_ipam_snapshot(source, auth_config):
            assert source["provider"] == "netbox"
            assert auth_config["token"] == "netbox-token"
            return {
                "prefixes": [
                    {
                        "external_id": "netbox-prefix-1",
                        "subnet": "10.20.0.0/24",
                        "description": "WAN pool",
                        "status": "active",
                    }
                ],
                "allocations": [
                    {
                        "address": "10.20.0.5",
                        "dns_name": "wan-edge-1.example",
                        "status": "active",
                        "description": "WAN edge",
                        "prefix_subnet": "10.20.0.0/24",
                    }
                ],
                "summary": {"provider": "netbox", "prefix_count": 1, "allocation_count": 1},
            }

        monkeypatch.setattr(ipam_routes, "collect_ipam_snapshot", _fake_collect_ipam_snapshot)

        create_response = client.post(
            "/api/ipam/sources",
            json={
                "provider": "netbox",
                "name": "NetBox Prod",
                "base_url": "https://netbox.example",
                "auth_type": "token",
                "auth_config": {"token": "netbox-token"},
                "enabled": True,
                "verify_tls": False,
            },
        )
        assert create_response.status_code == 201
        source_id = create_response.json()["source"]["id"]

        sync_response = client.post(f"/api/ipam/sources/{source_id}/sync")
        assert sync_response.status_code == 200
        sync_body = sync_response.json()
        assert sync_body["summary"]["prefix_count"] == 1
        assert sync_body["sync"]["prefixes"] == 1
        assert sync_body["sync"]["allocations"] == 1

        overview_response = client.get("/api/ipam/overview")
        assert overview_response.status_code == 200
        overview = overview_response.json()
        assert overview["summary"]["external_subnets"] == 1

        subnet_map = {item["subnet"]: item for item in overview["subnets"]}
        assert subnet_map["10.20.0.0/24"]["external_prefix_count"] == 1
        assert subnet_map["10.20.0.0/24"]["external_allocation_count"] == 1
        assert "external" in subnet_map["10.20.0.0/24"]["source_types"]
    finally:
        client._client.__exit__(None, None, None)