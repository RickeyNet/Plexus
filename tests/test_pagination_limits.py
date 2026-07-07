"""Negative-limit rejection on capped list endpoints.

SQLite treats ``LIMIT -1`` as *unlimited*, so a ``?limit=-1`` on a capped
endpoint whose Query param declared ``le=N`` but no ``ge=1`` dumped the whole
table. Every such param now carries ``ge=1``; FastAPI returns 422 for a
non-positive limit. This test spot-checks a representative set.
"""

from __future__ import annotations

import netcontrol.app as app_module
import routes.database as db_module


def _auth_client(tmp_path, monkeypatch, request):
    db_path = str(tmp_path / "pagination.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-pagination")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return client


# Endpoints that previously accepted limit=-1 (le= without ge=).
NEGATIVE_LIMIT_ENDPOINTS = [
    "/api/mac-tracking/search?limit=-1",
    "/api/deployments?limit=-1",
    "/api/risk-analysis?limit=-1",
    "/api/flows/top-talkers?limit=-1",
]


def test_negative_limit_rejected(tmp_path, monkeypatch, request):
    client = _auth_client(tmp_path, monkeypatch, request)
    for url in NEGATIVE_LIMIT_ENDPOINTS:
        resp = client.get(url)
        assert resp.status_code == 422, f"{url} accepted a negative limit: {resp.status_code}"


def test_zero_limit_rejected(tmp_path, monkeypatch, request):
    client = _auth_client(tmp_path, monkeypatch, request)
    resp = client.get("/api/mac-tracking/search?limit=0")
    assert resp.status_code == 422


def test_valid_limit_accepted(tmp_path, monkeypatch, request):
    client = _auth_client(tmp_path, monkeypatch, request)
    resp = client.get("/api/mac-tracking/search?limit=10")
    assert resp.status_code == 200
