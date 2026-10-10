"""HTTP-level regression tests for the API-hardening pass.

Covers:
  * request-body field bounds on deployments / campaigns (422 on oversized
    payloads that would otherwise reach device commands)
  * campaign create reporting devices it could not add instead of silently
    dropping them
  * SVG stub escaping of a template name (stored-XSS guard)
"""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module

import pg_raw


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._csrf = client, csrf

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        h = kw.pop("headers", {})
        h["X-CSRF-Token"] = self._csrf
        kw["headers"] = h
        return self._c.post(url, **kw)


def _auth_client(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-hardening")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    csrf = resp.json().get("csrf_token", "")
    return _CsrfClient(client, csrf)


# ── Field bounds ─────────────────────────────────────────────────────────────


def test_deployment_rejects_too_many_commands(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    body = {
        "name": "d",
        "group_id": 1,
        "credential_id": 1,
        "proposed_commands": ["show ver"] * 10001,  # cap is 10000
    }
    assert client.post("/api/deployments", json=body).status_code == 422


def test_deployment_rejects_overlong_command(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    body = {
        "name": "d",
        "group_id": 1,
        "credential_id": 1,
        "proposed_commands": ["x" * 4001],  # per-item cap is 4000
    }
    assert client.post("/api/deployments", json=body).status_code == 422


def test_deployment_rejects_overlong_name(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    body = {"name": "n" * 201, "group_id": 1, "credential_id": 1}
    assert client.post("/api/deployments", json=body).status_code == 422


def test_campaign_rejects_huge_image_map(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    body = {"name": "c", "image_map": {str(i): "img.bin" for i in range(1001)}}
    assert client.post("/api/upgrades/campaigns", json=body).status_code == 422


# ── Campaign create device-drop reporting ────────────────────────────────────


def test_campaign_reports_unknown_host_ids(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    body = {"name": "c", "host_ids": [999999]}  # no such host
    resp = client.post("/api/upgrades/campaigns", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["devices_added"] == 0
    assert data["not_found_host_ids"] == [999999]
    assert data["requested"] == 1


# ── SVG stub escaping ────────────────────────────────────────────────────────


def test_svg_stub_escapes_template_name(monkeypatch, request):
    client = _auth_client(monkeypatch, request)

    # Seed host + malicious-named template + host_graph via a raw connection
    # (autocommit, so the app sees the rows immediately).
    async def _seed() -> int:
        conn = await pg_raw.connect()
        try:
            gid = await conn.fetchval("INSERT INTO inventory_groups (name) VALUES ('g') RETURNING id")
            hid = await conn.fetchval(
                "INSERT INTO hosts (group_id, hostname, ip_address) VALUES ($1, 'h', '10.0.0.1') RETURNING id",
                gid,
            )
            tid = await conn.fetchval(
                "INSERT INTO graph_templates (name) VALUES ('<script>alert(1)</script>') RETURNING id"
            )
            return await conn.fetchval(
                "INSERT INTO host_graphs (host_id, graph_template_id) VALUES ($1, $2) RETURNING id",
                hid,
                tid,
            )
        finally:
            await conn.close()

    hgid = asyncio.run(_seed())

    resp = client.get(f"/api/graph-image/{hgid}.svg")
    assert resp.status_code == 200
    text = resp.text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
