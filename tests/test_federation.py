"""Tests for multi-instance federation feature.

Covers:
  1. Migration creates federation_peers and federation_snapshots tables.
  2. Federation peer CRUD operations.
  3. Peer connectivity test endpoint.
  4. Manual sync endpoint.
  5. Federated overview aggregation.
  6. API token encryption round-trip for peer credentials.
"""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import netcontrol.app as app_module
import pytest
import routes.database as db_module


# ── Helpers ──────────────────────────────────────────────────────────────────


class _FederationClient:
    """Wraps TestClient to auto-include CSRF token on mutating requests."""

    def __init__(self, client, csrf_token):
        self._client = client
        self._csrf = csrf_token

    def _merge_headers(self, kw):
        h = kw.pop("headers", {})
        h["X-CSRF-Token"] = self._csrf
        kw["headers"] = h

    def get(self, url, **kw):
        return self._client.get(url, **kw)

    def post(self, url, **kw):
        self._merge_headers(kw)
        return self._client.post(url, **kw)

    def put(self, url, **kw):
        self._merge_headers(kw)
        return self._client.put(url, **kw)

    def delete(self, url, **kw):
        self._merge_headers(kw)
        return self._client.delete(url, **kw)


def _auth_client(tmp_path, monkeypatch):
    """Create a TestClient with auth bootstrapped and federation tables."""
    db_path = str(tmp_path / "fed_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-federation")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient
    client = TestClient(app_module.app, raise_server_exceptions=False)

    # Trigger lifespan (init_db + _ensure_default_admin)
    client.__enter__()

    # Login as the bootstrap admin created by _ensure_default_admin()
    resp = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "netcontrol",
    })
    csrf_token = resp.json().get("csrf_token", "")
    return _FederationClient(client, csrf_token)


# ═════════════════════════════════════════════════════════════════════════════
# 1. Migration creates tables
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_federation_tables_exist_after_init(tmp_path, monkeypatch):
    """init_db should create federation_peers and federation_snapshots tables."""
    db_path = str(tmp_path / "fed_migrate.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()

    conn = await db_module.get_db()
    try:
        # Check federation_peers exists
        cur = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='federation_peers'"
        )
        row = await cur.fetchone()
        assert row is not None, "federation_peers table should exist"

        # Check federation_snapshots exists
        cur = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='federation_snapshots'"
        )
        row = await cur.fetchone()
        assert row is not None, "federation_snapshots table should exist"
    finally:
        await conn.close()


# ═════════════════════════════════════════════════════════════════════════════
# 2. Federation peer CRUD
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_create_and_list_peers(tmp_path, monkeypatch):
    """CRUD: create a peer, list peers, verify it appears."""
    client = _auth_client(tmp_path, monkeypatch)

    # Create peer
    resp = client.post("/api/federation/peers", json={
        "name": "Site-B",
        "url": "https://plexus-b.example.com",
        "api_token": "secret-token-123",
        "description": "Remote site B",
        "enabled": True,
    })
    assert resp.status_code == 201, resp.text
    peer = resp.json()
    assert peer["name"] == "Site-B"
    assert peer["url"] == "https://plexus-b.example.com"
    assert "api_token_enc" not in peer  # Encrypted token not exposed
    assert peer["has_token"] is True

    # List peers
    resp = client.get("/api/federation/peers")
    assert resp.status_code == 200
    peers = resp.json()
    assert len(peers) >= 1
    assert any(p["name"] == "Site-B" for p in peers)


@pytest.mark.asyncio
async def test_get_single_peer(tmp_path, monkeypatch):
    """GET /api/federation/peers/{id} returns the peer."""
    client = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/federation/peers", json={
        "name": "Site-C",
        "url": "https://plexus-c.example.com",
    })
    peer_id = resp.json()["id"]

    resp = client.get(f"/api/federation/peers/{peer_id}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "Site-C"


@pytest.mark.asyncio
async def test_update_peer(tmp_path, monkeypatch):
    """PUT /api/federation/peers/{id} updates fields."""
    client = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/federation/peers", json={
        "name": "OldName",
        "url": "https://old.example.com",
    })
    peer_id = resp.json()["id"]

    resp = client.put(f"/api/federation/peers/{peer_id}", json={
        "name": "NewName",
        "url": "https://new.example.com",
        "enabled": False,
    })
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["name"] == "NewName"
    assert updated["url"] == "https://new.example.com"


@pytest.mark.asyncio
async def test_delete_peer(tmp_path, monkeypatch):
    """DELETE /api/federation/peers/{id} removes the peer."""
    client = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/federation/peers", json={
        "name": "ToDelete",
        "url": "https://delete.example.com",
    })
    peer_id = resp.json()["id"]

    resp = client.delete(f"/api/federation/peers/{peer_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"

    # Verify gone
    resp = client.get(f"/api/federation/peers/{peer_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_peer_not_found(tmp_path, monkeypatch):
    """GET/PUT/DELETE for nonexistent peer returns 404."""
    client = _auth_client(tmp_path, monkeypatch)
    assert client.get("/api/federation/peers/9999").status_code == 404
    assert client.put("/api/federation/peers/9999", json={"name": "x"}).status_code == 404
    assert client.delete("/api/federation/peers/9999").status_code == 404


@pytest.mark.asyncio
async def test_peer_url_validation(tmp_path, monkeypatch):
    """Creating a peer with invalid URL scheme returns 422."""
    client = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/federation/peers", json={
        "name": "BadURL",
        "url": "ftp://bad.example.com",
    })
    assert resp.status_code == 422


# ═════════════════════════════════════════════════════════════════════════════
# 3. Peer connectivity test
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_test_peer_connectivity(tmp_path, monkeypatch):
    """POST /api/federation/peers/{id}/test returns connectivity result."""
    client = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/federation/peers", json={
        "name": "TestTarget",
        "url": "https://unreachable.example.com",
    })
    peer_id = resp.json()["id"]

    # This will fail to connect (unreachable host) but should not 500
    resp = client.post(f"/api/federation/peers/{peer_id}/test")
    assert resp.status_code == 200
    result = resp.json()
    assert result["status"] == "error"
    assert "message" in result


# ═════════════════════════════════════════════════════════════════════════════
# 4. Federated overview
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_overview_empty(tmp_path, monkeypatch):
    """GET /api/federation/overview with no peers returns empty totals."""
    client = _auth_client(tmp_path, monkeypatch)
    resp = client.get("/api/federation/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert "totals" in data
    assert "peers" in data
    assert data["totals"]["total_peers"] == 0


@pytest.mark.asyncio
async def test_overview_with_cached_snapshots(tmp_path, monkeypatch):
    """Overview aggregates data from cached federation_snapshots."""
    client = _auth_client(tmp_path, monkeypatch)

    # Create a peer
    resp = client.post("/api/federation/peers", json={
        "name": "Site-X",
        "url": "https://sitex.example.com",
        "enabled": True,
    })
    peer_id = resp.json()["id"]

    # Manually insert snapshot data (simulating a completed sync)
    db_path = str(tmp_path / "fed_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    conn = await db_module.get_db()
    try:
        await conn.execute(
            "INSERT INTO federation_snapshots (peer_id, category, data_json) VALUES (?, ?, ?)",
            (peer_id, "devices", json.dumps({"total": 10, "up": 8, "down": 2, "groups": 3})),
        )
        await conn.execute(
            "INSERT INTO federation_snapshots (peer_id, category, data_json) VALUES (?, ?, ?)",
            (peer_id, "alerts", json.dumps({"active": 5, "critical": 2, "warning": 3})),
        )
        await conn.execute(
            "UPDATE federation_peers SET last_sync_status = 'ok', enabled = 1 WHERE id = ?",
            (peer_id,),
        )
        await conn.commit()
    finally:
        await conn.close()

    resp = client.get("/api/federation/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert data["totals"]["total_peers"] == 1
    assert data["totals"]["healthy_peers"] == 1
    assert data["totals"]["total_devices"] == 10
    assert data["totals"]["devices_up"] == 8
    assert data["totals"]["total_alerts"] == 5
    assert data["totals"]["critical_alerts"] == 2
    assert len(data["peers"]) == 1
    assert data["peers"][0]["name"] == "Site-X"


# ═════════════════════════════════════════════════════════════════════════════
# 5. API token encryption
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_peer_token_encrypted_at_rest(tmp_path, monkeypatch):
    """The api_token should be stored encrypted, not in plaintext."""
    client = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/federation/peers", json={
        "name": "SecureToken",
        "url": "https://secure.example.com",
        "api_token": "my-super-secret",
    })
    peer_id = resp.json()["id"]

    # Read raw DB row
    db_path = str(tmp_path / "fed_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    conn = await db_module.get_db()
    try:
        cur = await conn.execute(
            "SELECT api_token_enc FROM federation_peers WHERE id = ?", (peer_id,)
        )
        row = await cur.fetchone()
    finally:
        await conn.close()

    assert row is not None
    enc_value = row["api_token_enc"] if isinstance(row, dict) else row[0]
    # Token should not be stored as plaintext
    assert enc_value != "my-super-secret"
    assert len(enc_value) > 0

    # Verify it decrypts back
    from routes.crypto import decrypt
    assert decrypt(enc_value) == "my-super-secret"


# ═════════════════════════════════════════════════════════════════════════════
# 6. Sync endpoint (mocked remote)
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_sync_peer_with_mocked_remote(tmp_path, monkeypatch):
    """POST /api/federation/peers/{id}/sync stores snapshot data."""
    client = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/federation/peers", json={
        "name": "MockRemote",
        "url": "https://mock.example.com",
    })
    peer_id = resp.json()["id"]

    # Mock _fetch_peer_data to return fake aggregated data
    fake_data = {
        "devices": {"total": 25, "up": 20, "down": 5, "groups": 4},
        "alerts": {"active": 3, "critical": 1, "warning": 2},
        "compliance": {"total_profiles": 2, "compliant_pct": 95},
        "version": "0.2.0",
    }
    with patch("netcontrol.routes.federation._fetch_peer_data", new_callable=AsyncMock, return_value=fake_data):
        resp = client.post(f"/api/federation/peers/{peer_id}/sync")

    assert resp.status_code == 200
    result = resp.json()
    assert result["status"] == "ok"
    assert result["data"]["devices"]["total"] == 25

    # Verify snapshots persisted
    db_path = str(tmp_path / "fed_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    conn = await db_module.get_db()
    try:
        cur = await conn.execute(
            "SELECT category, data_json FROM federation_snapshots WHERE peer_id = ?",
            (peer_id,),
        )
        rows = await cur.fetchall()
    finally:
        await conn.close()

    cats = {r["category"] if isinstance(r, dict) else r[0] for r in rows}
    assert "devices" in cats
    assert "alerts" in cats
    assert "compliance" in cats
    assert "metadata" in cats

    # Verify peer sync status updated
    resp = client.get(f"/api/federation/peers/{peer_id}")
    peer = resp.json()
    assert peer["last_sync_status"] == "ok"


# ═════════════════════════════════════════════════════════════════════════════
# 7. Module import smoke test
# ═════════════════════════════════════════════════════════════════════════════


def test_federation_module_imports():
    """The federation module should import without errors."""
    from netcontrol.routes.federation import (
        init_federation,
        federation_sync_loop,
        router,
    )
    assert router is not None
    assert callable(init_federation)
    assert callable(federation_sync_loop)
