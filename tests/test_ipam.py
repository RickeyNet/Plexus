"""Tests for lightweight IPAM overview API."""

from __future__ import annotations

import netcontrol.app as app_module
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