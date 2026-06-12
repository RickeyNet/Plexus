"""HTTP-level tests for the monitoring routes.

Covers:
  * alert rules CRUD + validation (name/metric required, operator allowlist)
  * alert suppressions CRUD + active_only filtering
  * alert acknowledge / bulk-acknowledge
  * auth gate on the router

Complements tests/test_monitoring.py, which exercises the poll-cycle logic
directly; this file goes through the FastAPI app with a real session.
"""

from __future__ import annotations

import sqlite3

import netcontrol.app as app_module
import routes.database as db_module

# ── Helpers ──────────────────────────────────────────────────────────────────


class _CsrfClient:
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
    """TestClient with lifespan run, logged in as the bootstrap admin."""
    db_path = str(tmp_path / "monitoring_api.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-monitoring")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()

    resp = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "netcontrol",
    })
    csrf_token = resp.json().get("csrf_token", "")
    return _CsrfClient(client, csrf_token), db_path


def _seed_alert(db_path: str, severity: str = "warning") -> int:
    """Insert group → host → alert directly; there is no create-alert API.

    Uses a plain sqlite3 connection against the same file so we don't fight
    the app's loop-bound aiosqlite singleton from the test thread.
    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO inventory_groups (name) VALUES ('api-test')"
        )
        group_id = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, 'sw1', '10.9.9.1')",
            (group_id,),
        )
        host_id = cur.lastrowid
        cur = conn.execute(
            """INSERT INTO monitoring_alerts
               (host_id, alert_type, metric, message, severity, original_severity, dedup_key)
               VALUES (?, 'threshold', 'cpu', 'cpu high', ?, ?, ?)""",
            (host_id, severity, severity, f"{host_id}:cpu:threshold"),
        )
        alert_id = cur.lastrowid
        conn.commit()
        return alert_id
    finally:
        conn.close()


# ── Auth gate ────────────────────────────────────────────────────────────────


def test_monitoring_routes_require_auth(tmp_path, monkeypatch):
    db_path = str(tmp_path / "noauth.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-noauth")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    resp = client.get("/api/monitoring/rules")
    assert resp.status_code == 401


# ── Alert rules CRUD ─────────────────────────────────────────────────────────


def test_rule_create_list_get(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/monitoring/rules", json={
        "name": "high cpu", "metric": "cpu", "operator": ">=", "value": 85,
    })
    assert resp.status_code == 201
    rule_id = resp.json()["id"]

    listed = client.get("/api/monitoring/rules").json()
    assert any(r["id"] == rule_id for r in listed)

    fetched = client.get(f"/api/monitoring/rules/{rule_id}")
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "high cpu"
    assert fetched.json()["metric"] == "cpu"


def test_rule_create_requires_name_and_metric(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    assert client.post("/api/monitoring/rules", json={
        "metric": "cpu", "value": 85,
    }).status_code == 400
    assert client.post("/api/monitoring/rules", json={
        "name": "no metric", "value": 85,
    }).status_code == 400


def test_rule_create_rejects_unknown_operator(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/monitoring/rules", json={
        "name": "bad op", "metric": "cpu", "operator": "~=", "value": 1,
    })
    assert resp.status_code == 400


def test_rule_create_rejects_non_numeric_value(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/monitoring/rules", json={
        "name": "bad value", "metric": "cpu", "value": "not-a-number",
    })
    assert resp.status_code == 400


def test_rule_update_and_delete(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    rule_id = client.post("/api/monitoring/rules", json={
        "name": "to update", "metric": "cpu", "value": 85,
    }).json()["id"]

    updated = client.put(f"/api/monitoring/rules/{rule_id}", json={"value": 95})
    assert updated.status_code == 200
    assert updated.json()["value"] == 95

    assert client.delete(f"/api/monitoring/rules/{rule_id}").status_code == 200
    assert client.get(f"/api/monitoring/rules/{rule_id}").status_code == 404


def test_rule_update_missing_returns_404(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    assert client.put("/api/monitoring/rules/99999", json={"value": 1}).status_code == 404
    assert client.delete("/api/monitoring/rules/99999").status_code == 404


# ── Suppressions CRUD ────────────────────────────────────────────────────────


def test_suppression_create_list_delete(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/monitoring/suppressions", json={
        "name": "maintenance", "ends_at": "2099-01-01T00:00:00", "metric": "cpu",
    })
    assert resp.status_code == 201
    sup_id = resp.json()["id"]

    listed = client.get("/api/monitoring/suppressions").json()
    assert any(s["id"] == sup_id for s in listed)

    assert client.delete(f"/api/monitoring/suppressions/{sup_id}").status_code == 200
    listed = client.get("/api/monitoring/suppressions").json()
    assert not any(s["id"] == sup_id for s in listed)


def test_suppression_requires_ends_at(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/monitoring/suppressions", json={"name": "no end"})
    assert resp.status_code == 400


def test_suppression_active_only_filter(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    active = client.post("/api/monitoring/suppressions", json={
        "name": "active", "ends_at": "2099-01-01T00:00:00",
    }).json()["id"]
    expired = client.post("/api/monitoring/suppressions", json={
        "name": "expired", "ends_at": "2000-01-01T00:00:00",
    }).json()["id"]

    everything = {s["id"] for s in client.get("/api/monitoring/suppressions").json()}
    assert {active, expired} <= everything

    active_only = {
        s["id"]
        for s in client.get("/api/monitoring/suppressions?active_only=true").json()
    }
    assert active in active_only
    assert expired not in active_only


# ── Alert acknowledge ────────────────────────────────────────────────────────


def test_acknowledge_alert(tmp_path, monkeypatch):
    client, db_path = _auth_client(tmp_path, monkeypatch)
    alert_id = _seed_alert(db_path)

    open_alerts = client.get("/api/monitoring/alerts?acknowledged=false").json()
    assert any(a["id"] == alert_id for a in open_alerts)

    resp = client.post(f"/api/monitoring/alerts/{alert_id}/acknowledge")
    assert resp.status_code == 200

    open_alerts = client.get("/api/monitoring/alerts?acknowledged=false").json()
    assert not any(a["id"] == alert_id for a in open_alerts)
    acked = client.get("/api/monitoring/alerts?acknowledged=true").json()
    assert any(a["id"] == alert_id for a in acked)


def test_bulk_acknowledge(tmp_path, monkeypatch):
    client, db_path = _auth_client(tmp_path, monkeypatch)
    a1 = _seed_alert(db_path)

    resp = client.post("/api/monitoring/alerts/bulk-acknowledge", json={
        "alert_ids": [a1],
    })
    assert resp.status_code == 200
    assert resp.json()["acknowledged"] == 1


def test_bulk_acknowledge_requires_ids(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    resp = client.post("/api/monitoring/alerts/bulk-acknowledge", json={"alert_ids": []})
    assert resp.status_code == 400


def test_monitoring_summary_shape(tmp_path, monkeypatch):
    client, _ = _auth_client(tmp_path, monkeypatch)
    resp = client.get("/api/monitoring/summary")
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)
