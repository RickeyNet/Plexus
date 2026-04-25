"""Tests for the inventory serial number fetch feature."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.inventory as inventory_routes
import pytest
import routes.database as db_module


# ── Shared auth-client helper (mirrors test_ipam.py pattern) ─────────────────


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

    def put(self, url, **kw):
        self._merge_headers(kw)
        return self._client.put(url, **kw)

    def delete(self, url, **kw):
        self._merge_headers(kw)
        return self._client.delete(url, **kw)


def _make_auth_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "serial_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-serial")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "0")
    monkeypatch.setenv("PLEXUS_INITIAL_ADMIN_PASSWORD", "netcontrol")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    async def _init():
        await db_module.init_db()
        db = await db_module.get_db()
        try:
            await db.execute(
                "INSERT INTO inventory_groups (name) VALUES ('bootstrap-sentinel')"
            )
            await db.commit()
        finally:
            await db.close()

    asyncio.run(_init())

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "netcontrol"},
    )
    data = resp.json()
    csrf = data.get("csrf_token", "")
    if data.get("must_change_password"):
        client.post(
            "/api/auth/change-password",
            json={"current_password": "netcontrol", "new_password": "netcontrol-upd"},
            headers={"X-CSRF-Token": csrf},
        )
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "netcontrol-upd"},
        )
        csrf = resp.json().get("csrf_token", "")
    return _AuthClient(client, csrf)


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _seed_host(group_id: int, hostname: str = "sw-01", ip: str = "10.0.0.1") -> int:
    """Insert a host and return its id."""

    async def _do():
        db = await db_module.get_db()
        try:
            cursor = await db.execute(
                "INSERT INTO hosts (group_id, hostname, ip_address, device_type, status)"
                " VALUES (?, ?, ?, 'cisco_ios', 'online')",
                (group_id, hostname, ip),
            )
            await db.commit()
            return int(cursor.lastrowid)
        finally:
            await db.close()

    return asyncio.run(_do())


def _seed_credential() -> int:
    """Insert a dummy credential (plaintext-ish, OK for mocked tests) and return its id."""

    async def _do():
        # Encrypt a dummy password so the column format is valid
        from routes.crypto import encrypt
        enc_pw = encrypt("secret123")
        db = await db_module.get_db()
        try:
            cursor = await db.execute(
                "INSERT INTO credentials (name, username, password, secret) VALUES (?,?,?,?)",
                ("test-cred", "admin", enc_pw, ""),
            )
            await db.commit()
            return int(cursor.lastrowid)
        finally:
            await db.close()

    return asyncio.run(_do())


def _get_host_serial(host_id: int) -> str:
    async def _do():
        db = await db_module.get_db()
        try:
            cursor = await db.execute(
                "SELECT serial_number FROM hosts WHERE id = ?", (host_id,)
            )
            row = await cursor.fetchone()
            return row[0] if row else ""
        finally:
            await db.close()

    return asyncio.run(_do())


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_fetch_serial_success(tmp_path, monkeypatch):
    """Happy path: SSH returns a valid serial number line; it is stored and returned."""
    client = _make_auth_client(tmp_path, monkeypatch)

    # Seed group, host, credential
    resp = client.post("/api/inventory", json={"name": "Core", "description": ""})
    assert resp.status_code == 201
    group_id = resp.json()["id"]
    host_id = _seed_host(group_id)
    cred_id = _seed_credential()

    # Mock SSH helper to return show version output
    sample_output = "System Serial Number: FCW2346L0AJ"
    async def _mock_run_show(host, credentials, command):
        assert "System Serial Number" in command
        return sample_output

    monkeypatch.setattr(inventory_routes, "_run_show_command", _mock_run_show)

    resp = client.post(
        f"/api/hosts/{host_id}/fetch-serial",
        json={"credential_id": cred_id},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["serial_number"] == "FCW2346L0AJ"
    assert data["host_id"] == host_id

    # Verify stored in DB
    assert _get_host_serial(host_id) == "FCW2346L0AJ"


def test_fetch_serial_multiline_output(tmp_path, monkeypatch):
    """Parser finds the Serial Number line even when there is surrounding output."""
    client = _make_auth_client(tmp_path, monkeypatch)

    resp = client.post("/api/inventory", json={"name": "Access", "description": ""})
    group_id = resp.json()["id"]
    host_id = _seed_host(group_id, ip="10.0.0.2")
    cred_id = _seed_credential()

    multiline = (
        "Cisco IOS XE Software, Version 17.09.04\n"
        "System Serial Number              : ABC1234WXYZ\n"
        "Processor board ID ABC1234WXYZ\n"
    )

    async def _mock_run_show(host, credentials, command):
        return multiline

    monkeypatch.setattr(inventory_routes, "_run_show_command", _mock_run_show)

    resp = client.post(
        f"/api/hosts/{host_id}/fetch-serial",
        json={"credential_id": cred_id},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["serial_number"] == "ABC1234WXYZ"


def test_fetch_serial_missing_host(tmp_path, monkeypatch):
    """Returns 404 when host does not exist."""
    client = _make_auth_client(tmp_path, monkeypatch)
    cred_id = _seed_credential()
    resp = client.post(
        "/api/hosts/99999/fetch-serial",
        json={"credential_id": cred_id},
    )
    assert resp.status_code == 404


def test_fetch_serial_missing_credential(tmp_path, monkeypatch):
    """Returns 404 when credential does not exist."""
    client = _make_auth_client(tmp_path, monkeypatch)

    resp = client.post("/api/inventory", json={"name": "Dist", "description": ""})
    group_id = resp.json()["id"]
    host_id = _seed_host(group_id, ip="10.0.0.3")

    resp = client.post(
        f"/api/hosts/{host_id}/fetch-serial",
        json={"credential_id": 99999},
    )
    assert resp.status_code == 404


def test_fetch_serial_ssh_failure(tmp_path, monkeypatch):
    """Returns 502 when SSH connection fails."""
    client = _make_auth_client(tmp_path, monkeypatch)

    resp = client.post("/api/inventory", json={"name": "Edge", "description": ""})
    group_id = resp.json()["id"]
    host_id = _seed_host(group_id, ip="10.0.0.4")
    cred_id = _seed_credential()

    async def _failing_run(host, credentials, command):
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr(inventory_routes, "_run_show_command", _failing_run)

    resp = client.post(
        f"/api/hosts/{host_id}/fetch-serial",
        json={"credential_id": cred_id},
    )
    assert resp.status_code == 502


def test_fetch_serial_no_serial_in_output(tmp_path, monkeypatch):
    """Returns 422 when the command output contains no serial number line."""
    client = _make_auth_client(tmp_path, monkeypatch)

    resp = client.post("/api/inventory", json={"name": "WAN", "description": ""})
    group_id = resp.json()["id"]
    host_id = _seed_host(group_id, ip="10.0.0.5")
    cred_id = _seed_credential()

    async def _empty_run(host, credentials, command):
        return "Cisco IOS Software, no serial info here."

    monkeypatch.setattr(inventory_routes, "_run_show_command", _empty_run)

    resp = client.post(
        f"/api/hosts/{host_id}/fetch-serial",
        json={"credential_id": cred_id},
    )
    assert resp.status_code == 422


def test_serial_number_column_exists(tmp_path, monkeypatch):
    """Verify that the serial_number column is present after DB init (migration applied)."""
    db_path = str(tmp_path / "migration_check.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)

    async def _check():
        await db_module.init_db()
        db = await db_module.get_db()
        try:
            cursor = await db.execute("PRAGMA table_info(hosts)")
            cols = [row[1] for row in await cursor.fetchall()]
            return cols
        finally:
            await db.close()

    cols = asyncio.run(_check())
    assert "serial_number" in cols
