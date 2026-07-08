"""Regression tests for the Batch B security/DoS cluster.

Covers:
  * capacity-planning ``projection_days`` bound (unbounded value freezes the
    event loop building ~1e8 projection dicts and can overflow timedelta)
  * vendor-OID registry mutations are admin-gated (custom entries override
    built-ins fleet-wide, so a non-admin could redirect SNMP polling)
  * dashboard GET enforces object ownership (IDOR)
  * lab promote_run routes the supplied credential through
    require_credential_access before binding it to a production deployment
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException


# ── capacity-planning projection bound (HTTP) ────────────────────────────────

def _auth_client(tmp_path, monkeypatch, request):
    import netcontrol.app as app_module
    import routes.database as db_module

    db_path = str(tmp_path / "batchb.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-batchb")
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


def test_capacity_planning_rejects_huge_projection(tmp_path, monkeypatch, request):
    client = _auth_client(tmp_path, monkeypatch, request)
    resp = client.get("/api/metrics/capacity-planning?metric=cpu_percent&projection_days=100000000")
    assert resp.status_code == 422


def test_capacity_planning_accepts_default(tmp_path, monkeypatch, request):
    client = _auth_client(tmp_path, monkeypatch, request)
    resp = client.get("/api/metrics/capacity-planning?metric=cpu_percent")
    # Empty dataset is fine; the point is it must not 422/500.
    assert resp.status_code == 200


# ── vendor-OID admin gate (structural) ───────────────────────────────────────

def _routes(router):
    out = set()
    for r in router.routes:
        for m in getattr(r, "methods", set()) or set():
            out.add((m, r.path))
    return out


def test_vendor_oid_mutations_are_admin_gated():
    import netcontrol.routes.metrics_engine as me

    admin = _routes(me.admin_router)
    public = _routes(me.router)
    assert ("POST", "/api/metrics/vendor-oids") in admin
    assert ("DELETE", "/api/metrics/vendor-oids/{entry_id}") in admin
    # Must NOT remain on the non-admin (auth + monitoring-feature) router.
    assert ("POST", "/api/metrics/vendor-oids") not in public
    assert ("DELETE", "/api/metrics/vendor-oids/{entry_id}") not in public
    # The read-only list stays available to monitoring users.
    assert ("GET", "/api/metrics/vendor-oids") in public


# ── dashboard GET ownership (wiring) ─────────────────────────────────────────

class _Stop(Exception):
    pass


@pytest.mark.asyncio
async def test_dashboard_get_enforces_owner(monkeypatch):
    import netcontrol.routes.dashboards as dash

    async def fake_get_dashboard(_id):
        return {"id": _id, "owner": "alice", "panels": []}

    captured = {}

    async def fake_owner_check(_request, owner):
        captured["owner"] = owner
        raise _Stop()

    monkeypatch.setattr(dash.db, "get_dashboard", fake_get_dashboard)
    monkeypatch.setattr(dash, "require_owner_or_admin", fake_owner_check)

    with pytest.raises(_Stop):
        await dash.get_dashboard_api(dashboard_id=5, request=None)
    assert captured["owner"] == "alice"


@pytest.mark.asyncio
async def test_dashboard_missing_is_404_before_owner_check(monkeypatch):
    import netcontrol.routes.dashboards as dash

    async def fake_get_dashboard(_id):
        return None

    monkeypatch.setattr(dash.db, "get_dashboard", fake_get_dashboard)

    with pytest.raises(HTTPException) as exc:
        await dash.get_dashboard_api(dashboard_id=999, request=None)
    assert exc.value.status_code == 404


# ── lab promote_run credential wiring ────────────────────────────────────────

@pytest.mark.asyncio
async def test_lab_promote_validates_credential(monkeypatch):
    import netcontrol.routes.lab as lab

    async def fake_run(_rid):
        return {"id": _rid, "lab_device_id": 1, "commands": "[]"}

    async def fake_device(_did):
        return {"id": 1, "environment_id": 1, "source_host_id": None}

    async def fake_env(_eid):
        return {"id": 1, "shared": 1}

    async def fake_resolve(_request):
        return ({"user_id": 10, "user": "alice"}, None, "user")

    monkeypatch.setattr(lab.db, "get_lab_run", fake_run)
    monkeypatch.setattr(lab.db, "get_lab_device", fake_device)
    monkeypatch.setattr(lab.db, "get_lab_environment", fake_env)
    monkeypatch.setattr(lab, "_resolve_session_user", fake_resolve)
    monkeypatch.setattr(lab, "_user_can_access_env", lambda *a, **k: True)

    captured = {}

    async def fake_require(credential_id, **kwargs):
        captured["credential_id"] = credential_id
        captured.update(kwargs)
        raise _Stop()

    monkeypatch.setattr(lab, "require_credential_access", fake_require)

    body = lab.PromoteRequest(name="p", credential_id=7, target_group_id=3)
    with pytest.raises(_Stop):
        await lab.promote_run(run_id=1, body=body, request=None)
    assert captured["credential_id"] == 7
    assert captured["session"] == {"user_id": 10, "user": "alice"}
