"""HTTP-level regression tests for the API-hardening pass.

Covers:
  * request-body field bounds on deployments / campaigns (422 on oversized
    payloads that would otherwise reach device commands)
  * campaign create reporting devices it could not add instead of silently
    dropping them
  * SVG stub escaping of a template name (stored-XSS guard)
"""

from __future__ import annotations

import sqlite3

import netcontrol.app as app_module
import routes.database as db_module


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


def _auth_client(tmp_path, monkeypatch, request):
    db_path = str(tmp_path / "hardening.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
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
    return _CsrfClient(client, csrf), db_path


# ── Field bounds ─────────────────────────────────────────────────────────────


def test_deployment_rejects_too_many_commands(tmp_path, monkeypatch, request):
    client, _ = _auth_client(tmp_path, monkeypatch, request)
    body = {
        "name": "d", "group_id": 1, "credential_id": 1,
        "proposed_commands": ["show ver"] * 10001,  # cap is 10000
    }
    assert client.post("/api/deployments", json=body).status_code == 422


def test_deployment_rejects_overlong_command(tmp_path, monkeypatch, request):
    client, _ = _auth_client(tmp_path, monkeypatch, request)
    body = {
        "name": "d", "group_id": 1, "credential_id": 1,
        "proposed_commands": ["x" * 4001],  # per-item cap is 4000
    }
    assert client.post("/api/deployments", json=body).status_code == 422


def test_deployment_rejects_overlong_name(tmp_path, monkeypatch, request):
    client, _ = _auth_client(tmp_path, monkeypatch, request)
    body = {"name": "n" * 201, "group_id": 1, "credential_id": 1}
    assert client.post("/api/deployments", json=body).status_code == 422


def test_campaign_rejects_huge_image_map(tmp_path, monkeypatch, request):
    client, _ = _auth_client(tmp_path, monkeypatch, request)
    body = {"name": "c", "image_map": {str(i): "img.bin" for i in range(1001)}}
    assert client.post("/api/upgrades/campaigns", json=body).status_code == 422


# ── Campaign create device-drop reporting ────────────────────────────────────


def test_campaign_reports_unknown_host_ids(tmp_path, monkeypatch, request):
    client, _ = _auth_client(tmp_path, monkeypatch, request)
    body = {"name": "c", "host_ids": [999999]}  # no such host
    resp = client.post("/api/upgrades/campaigns", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["devices_added"] == 0
    assert data["not_found_host_ids"] == [999999]
    assert data["requested"] == 1


# ── SVG stub escaping ────────────────────────────────────────────────────────


def test_svg_stub_escapes_template_name(tmp_path, monkeypatch, request):
    client, db_path = _auth_client(tmp_path, monkeypatch, request)
    # Seed host + malicious-named template + host_graph via a plain sqlite conn
    # (avoids fighting the app's loop-bound aiosqlite singleton).
    conn = sqlite3.connect(db_path)
    try:
        gid = conn.execute("INSERT INTO inventory_groups (name) VALUES ('g')").lastrowid
        hid = conn.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, 'h', '10.0.0.1')",
            (gid,),
        ).lastrowid
        tid = conn.execute(
            "INSERT INTO graph_templates (name) VALUES ('<script>alert(1)</script>')"
        ).lastrowid
        hgid = conn.execute(
            "INSERT INTO host_graphs (host_id, graph_template_id) VALUES (?, ?)",
            (hid, tid),
        ).lastrowid
        conn.commit()
    finally:
        conn.close()

    resp = client.get(f"/api/graph-image/{hgid}.svg")
    assert resp.status_code == 200
    text = resp.text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
