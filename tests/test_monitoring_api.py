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

import asyncio

import netcontrol.app as app_module

import pg_raw

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


def _auth_client(monkeypatch, request):
    """TestClient with lifespan run, logged in as the bootstrap admin."""
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-monitoring")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))

    resp = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "netcontrol",
        },
    )
    csrf_token = resp.json().get("csrf_token", "")
    return _CsrfClient(client, csrf_token)


def _seed_alert(severity: str = "warning") -> int:
    """Insert group → host → alert directly; there is no create-alert API.

    Uses a raw autocommit connection on a private loop so the rows are
    committed before the app (running on the TestClient's loop) reads them.
    """

    async def _seed() -> int:
        conn = await pg_raw.connect()
        try:
            group_id = await conn.fetchval("INSERT INTO inventory_groups (name) VALUES ('api-test') RETURNING id")
            host_id = await conn.fetchval(
                "INSERT INTO hosts (group_id, hostname, ip_address) VALUES ($1, 'sw1', '10.9.9.1') RETURNING id",
                group_id,
            )
            return await conn.fetchval(
                """INSERT INTO monitoring_alerts
                   (host_id, alert_type, metric, message, severity, original_severity, dedup_key)
                   VALUES ($1, 'threshold', 'cpu', 'cpu high', $2, $3, $4) RETURNING id""",
                host_id,
                severity,
                severity,
                f"{host_id}:cpu:threshold",
            )
        finally:
            await conn.close()

    return asyncio.run(_seed())


# ── Auth gate ────────────────────────────────────────────────────────────────


def test_monitoring_routes_require_auth(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-noauth")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.get("/api/monitoring/rules")
    assert resp.status_code == 401


# ── Alert rules CRUD ─────────────────────────────────────────────────────────


def test_rule_create_list_get(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    resp = client.post(
        "/api/monitoring/rules",
        json={
            "name": "high cpu",
            "metric": "cpu",
            "operator": ">=",
            "value": 85,
        },
    )
    assert resp.status_code == 201
    rule_id = resp.json()["id"]

    listed = client.get("/api/monitoring/rules").json()
    assert any(r["id"] == rule_id for r in listed)

    fetched = client.get(f"/api/monitoring/rules/{rule_id}")
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "high cpu"
    assert fetched.json()["metric"] == "cpu"


def test_rule_create_requires_name_and_metric(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    assert (
        client.post(
            "/api/monitoring/rules",
            json={
                "metric": "cpu",
                "value": 85,
            },
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/monitoring/rules",
            json={
                "name": "no metric",
                "value": 85,
            },
        ).status_code
        == 400
    )


def test_rule_create_rejects_unknown_operator(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    resp = client.post(
        "/api/monitoring/rules",
        json={
            "name": "bad op",
            "metric": "cpu",
            "operator": "~=",
            "value": 1,
        },
    )
    assert resp.status_code == 400


def test_rule_create_rejects_non_numeric_value(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    resp = client.post(
        "/api/monitoring/rules",
        json={
            "name": "bad value",
            "metric": "cpu",
            "value": "not-a-number",
        },
    )
    assert resp.status_code == 400


def test_rule_update_and_delete(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    rule_id = client.post(
        "/api/monitoring/rules",
        json={
            "name": "to update",
            "metric": "cpu",
            "value": 85,
        },
    ).json()["id"]

    updated = client.put(f"/api/monitoring/rules/{rule_id}", json={"value": 95})
    assert updated.status_code == 200
    assert updated.json()["value"] == 95

    assert client.delete(f"/api/monitoring/rules/{rule_id}").status_code == 200
    assert client.get(f"/api/monitoring/rules/{rule_id}").status_code == 404


def test_rule_update_edits_fields_and_clears_scope(monkeypatch, request):
    client = _auth_client(monkeypatch, request)

    async def _seed_host() -> int:
        conn = await pg_raw.connect()
        try:
            group_id = await conn.fetchval("INSERT INTO inventory_groups (name) VALUES ('rule-scope') RETURNING id")
            return await conn.fetchval(
                "INSERT INTO hosts (group_id, hostname, ip_address) VALUES ($1, 'rule-host', '192.0.2.21') RETURNING id",
                group_id,
            )
        finally:
            await conn.close()

    host_id = asyncio.run(_seed_host())
    rule_id = client.post(
        "/api/monitoring/rules",
        json={"name": "scoped", "metric": "cpu", "value": 85, "host_id": host_id, "channel_ids": ["ops"]},
    ).json()["id"]
    assert client.get(f"/api/monitoring/rules/{rule_id}").json()["host_id"] == host_id

    updated = client.put(
        f"/api/monitoring/rules/{rule_id}",
        json={
            "name": "renamed",
            "metric": "memory",
            "operator": ">",
            "value": 70,
            "severity": "critical",
            "cooldown_minutes": 30,
            "host_id": None,
            "group_id": None,
            "channel_ids": [],
        },
    )
    assert updated.status_code == 200
    rule = updated.json()
    assert (rule["name"], rule["metric"], rule["operator"], rule["value"]) == ("renamed", "memory", ">", 70)
    assert (rule["severity"], rule["cooldown_minutes"]) == ("critical", 30)
    assert rule["host_id"] is None and rule["group_id"] is None
    assert rule["channel_ids"] == "[]"


def test_rule_update_rejects_bad_fields(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    rule_id = client.post("/api/monitoring/rules", json={"name": "strict", "metric": "cpu", "value": 85}).json()["id"]
    for body in ({"name": "  "}, {"metric": ""}, {"operator": "~="}, {"value": "not-a-number"}):
        assert client.put(f"/api/monitoring/rules/{rule_id}", json=body).status_code == 400
    assert client.get(f"/api/monitoring/rules/{rule_id}").json()["name"] == "strict"


def test_rule_update_missing_returns_404(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    assert client.put("/api/monitoring/rules/99999", json={"value": 1}).status_code == 404
    assert client.delete("/api/monitoring/rules/99999").status_code == 404


# ── Suppressions CRUD ────────────────────────────────────────────────────────


def test_suppression_create_list_delete(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    resp = client.post(
        "/api/monitoring/suppressions",
        json={
            "name": "maintenance",
            "ends_at": "2099-01-01T00:00:00",
            "metric": "cpu",
        },
    )
    assert resp.status_code == 201
    sup_id = resp.json()["id"]

    listed = client.get("/api/monitoring/suppressions").json()
    assert any(s["id"] == sup_id for s in listed)

    assert client.delete(f"/api/monitoring/suppressions/{sup_id}").status_code == 200
    listed = client.get("/api/monitoring/suppressions").json()
    assert not any(s["id"] == sup_id for s in listed)


def test_suppression_requires_ends_at(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    resp = client.post("/api/monitoring/suppressions", json={"name": "no end"})
    assert resp.status_code == 400


def test_suppression_rejects_end_not_after_start(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    for ends_at in ("2099-01-01 00:00:00", "2099-01-02 00:00:00"):
        resp = client.post(
            "/api/monitoring/suppressions",
            json={"name": "backwards", "starts_at": "2099-01-02 00:00:00", "ends_at": ends_at},
        )
        assert resp.status_code == 400
        assert "after starts_at" in resp.json()["detail"]

    resp = client.post(
        "/api/monitoring/suppressions",
        json={"name": "garbled", "starts_at": "not-a-date", "ends_at": "2099-01-02 00:00:00"},
    )
    assert resp.status_code == 400

    resp = client.post(
        "/api/monitoring/suppressions",
        json={"name": "forwards", "starts_at": "2099-01-01 00:00:00", "ends_at": "2099-01-02 00:00:00"},
    )
    assert resp.status_code == 201


def test_availability_transitions_filter_by_group_and_days(monkeypatch, request):
    client = _auth_client(monkeypatch, request)

    async def _seed() -> tuple[int, int]:
        conn = await pg_raw.connect()
        try:
            ids = []
            for name, ip in (("avail-a", "192.0.2.11"), ("avail-b", "192.0.2.12")):
                group_id = await conn.fetchval("INSERT INTO inventory_groups (name) VALUES ($1) RETURNING id", name)
                host_id = await conn.fetchval(
                    "INSERT INTO hosts (group_id, hostname, ip_address) VALUES ($1, $2, $3) RETURNING id",
                    group_id,
                    name,
                    ip,
                )
                await conn.execute(
                    """INSERT INTO availability_transitions (host_id, entity_type, old_state, new_state)
                       VALUES ($1, 'host', 'up', 'down')""",
                    host_id,
                )
                ids.append(group_id)
            # An old transition in the first group, outside a 7 day window.
            await conn.execute(
                """INSERT INTO availability_transitions (host_id, entity_type, old_state, new_state, transition_at)
                   SELECT id, 'host', 'unknown', 'up', '2000-01-01 00:00:00' FROM hosts WHERE group_id = $1""",
                ids[0],
            )
            return ids[0], ids[1]
        finally:
            await conn.close()

    group_a, group_b = asyncio.run(_seed())

    everything = client.get("/api/availability/transitions").json()["transitions"]
    assert {t["hostname"] for t in everything} >= {"avail-a", "avail-b"}

    in_a = client.get(f"/api/availability/transitions?group_id={group_a}").json()["transitions"]
    assert [t["hostname"] for t in in_a] == ["avail-a", "avail-a"]

    recent_a = client.get(f"/api/availability/transitions?group_id={group_a}&days=7").json()["transitions"]
    assert [(t["old_state"], t["new_state"]) for t in recent_a] == [("up", "down")]
    assert recent_a[0]["transition_at"]

    in_b = client.get(f"/api/availability/transitions?group_id={group_b}&days=7").json()["transitions"]
    assert [t["hostname"] for t in in_b] == ["avail-b"]


def test_suppression_active_only_filter(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    active = client.post(
        "/api/monitoring/suppressions",
        json={
            "name": "active",
            "ends_at": "2099-01-01T00:00:00",
        },
    ).json()["id"]
    expired = client.post(
        "/api/monitoring/suppressions",
        json={
            "name": "expired",
            "ends_at": "2000-01-01T00:00:00",
        },
    ).json()["id"]

    everything = {s["id"] for s in client.get("/api/monitoring/suppressions").json()}
    assert {active, expired} <= everything

    active_only = {s["id"] for s in client.get("/api/monitoring/suppressions?active_only=true").json()}
    assert active in active_only
    assert expired not in active_only


# ── Alert acknowledge ────────────────────────────────────────────────────────


def test_acknowledge_alert(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    alert_id = _seed_alert()

    open_alerts = client.get("/api/monitoring/alerts?acknowledged=false").json()
    assert any(a["id"] == alert_id for a in open_alerts)

    resp = client.post(f"/api/monitoring/alerts/{alert_id}/acknowledge")
    assert resp.status_code == 200

    open_alerts = client.get("/api/monitoring/alerts?acknowledged=false").json()
    assert not any(a["id"] == alert_id for a in open_alerts)
    acked = client.get("/api/monitoring/alerts?acknowledged=true").json()
    assert any(a["id"] == alert_id for a in acked)


def test_bulk_acknowledge(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    a1 = _seed_alert()

    resp = client.post(
        "/api/monitoring/alerts/bulk-acknowledge",
        json={
            "alert_ids": [a1],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["acknowledged"] == 1


def test_bulk_acknowledge_requires_ids(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    resp = client.post("/api/monitoring/alerts/bulk-acknowledge", json={"alert_ids": []})
    assert resp.status_code == 400


def test_monitoring_summary_shape(monkeypatch, request):
    client = _auth_client(monkeypatch, request)
    resp = client.get("/api/monitoring/summary")
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)
