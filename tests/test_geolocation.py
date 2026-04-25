"""Tests for the Geolocation and Floor Plan Mapping API."""

from __future__ import annotations

import asyncio

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

    def put(self, url, **kw):
        self._merge_headers(kw)
        return self._client.put(url, **kw)

    def delete(self, url, **kw):
        self._merge_headers(kw)
        return self._client.delete(url, **kw)


def _make_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "geo_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-geo")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "0")
    monkeypatch.setenv("PLEXUS_INITIAL_ADMIN_PASSWORD", "netcontrol")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

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


@pytest.fixture
def geo_client(tmp_path, monkeypatch):
    return _make_client(tmp_path, monkeypatch)


# ── Site CRUD ─────────────────────────────────────────────────────────────────

def test_create_site(geo_client):
    resp = geo_client.post("/api/geo/sites", json={"name": "Melbourne HQ", "address": "123 Main St"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Melbourne HQ"
    assert data["address"] == "123 Main St"
    assert "id" in data


def test_list_sites(geo_client):
    geo_client.post("/api/geo/sites", json={"name": "Site Alpha"})
    geo_client.post("/api/geo/sites", json={"name": "Site Beta"})
    resp = geo_client.get("/api/geo/sites")
    assert resp.status_code == 200
    names = [s["name"] for s in resp.json()]
    assert "Site Alpha" in names
    assert "Site Beta" in names


def test_get_site_with_floors(geo_client):
    create = geo_client.post("/api/geo/sites", json={"name": "Site Detail"})
    site_id = create.json()["id"]
    geo_client.post(f"/api/geo/sites/{site_id}/floors", json={"name": "Floor 1", "floor_number": 1})
    resp = geo_client.get(f"/api/geo/sites/{site_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Site Detail"
    assert isinstance(data.get("floors"), list)
    assert any(f["name"] == "Floor 1" for f in data["floors"])


def test_update_site(geo_client):
    create = geo_client.post("/api/geo/sites", json={"name": "Original Name"})
    site_id = create.json()["id"]
    resp = geo_client.put(f"/api/geo/sites/{site_id}", json={"name": "Updated Name"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "Updated Name"


def test_delete_site(geo_client):
    create = geo_client.post("/api/geo/sites", json={"name": "To Delete"})
    site_id = create.json()["id"]
    resp = geo_client.delete(f"/api/geo/sites/{site_id}")
    assert resp.status_code == 200
    get_resp = geo_client.get(f"/api/geo/sites/{site_id}")
    assert get_resp.status_code == 404


def test_duplicate_site_name_returns_409(geo_client):
    geo_client.post("/api/geo/sites", json={"name": "Unique Site"})
    resp = geo_client.post("/api/geo/sites", json={"name": "Unique Site"})
    assert resp.status_code == 409


def test_invalid_lat_returns_400(geo_client):
    resp = geo_client.post("/api/geo/sites", json={"name": "Bad Lat", "lat": 999.0, "lng": 0.0})
    assert resp.status_code == 422


def test_invalid_lng_returns_400(geo_client):
    resp = geo_client.post("/api/geo/sites", json={"name": "Bad Lng", "lat": 0.0, "lng": -999.0})
    assert resp.status_code == 422


def test_missing_site_name_returns_422(geo_client):
    resp = geo_client.post("/api/geo/sites", json={"address": "No name"})
    assert resp.status_code == 422


# ── Floor CRUD ────────────────────────────────────────────────────────────────

def test_create_floor(geo_client):
    site = geo_client.post("/api/geo/sites", json={"name": "Floor Test Site"}).json()
    resp = geo_client.post(f"/api/geo/sites/{site['id']}/floors", json={"name": "Ground Floor", "floor_number": 0})
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Ground Floor"
    assert data["floor_number"] == 0


def test_get_floor(geo_client):
    site = geo_client.post("/api/geo/sites", json={"name": "Get Floor Site"}).json()
    floor = geo_client.post(f"/api/geo/sites/{site['id']}/floors", json={"name": "Level 2"}).json()
    resp = geo_client.get(f"/api/geo/floors/{floor['id']}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "Level 2"


def test_duplicate_floor_name_returns_409(geo_client):
    site = geo_client.post("/api/geo/sites", json={"name": "Dup Floor Site"}).json()
    geo_client.post(f"/api/geo/sites/{site['id']}/floors", json={"name": "Mezzanine"})
    resp = geo_client.post(f"/api/geo/sites/{site['id']}/floors", json={"name": "Mezzanine"})
    assert resp.status_code == 409


def test_delete_floor(geo_client):
    site = geo_client.post("/api/geo/sites", json={"name": "Del Floor Site"}).json()
    floor = geo_client.post(f"/api/geo/sites/{site['id']}/floors", json={"name": "To Remove"}).json()
    resp = geo_client.delete(f"/api/geo/floors/{floor['id']}")
    assert resp.status_code == 200
    assert geo_client.get(f"/api/geo/floors/{floor['id']}").status_code == 404


# ── Placements ────────────────────────────────────────────────────────────────

def _setup_site_floor_host(geo_client):
    """Helper: create a site, floor, and a host; return (site_id, floor_id, host_id)."""
    site = geo_client.post("/api/geo/sites", json={"name": "Placement Site"}).json()
    floor = geo_client.post(f"/api/geo/sites/{site['id']}/floors", json={"name": "P Floor"}).json()

    async def _create_host():
        db = await db_module.get_db()
        try:
            cur = await db.execute(
                "INSERT INTO inventory_groups (name) VALUES ('placement-group')"
            )
            gid = cur.lastrowid
            cur2 = await db.execute(
                "INSERT INTO hosts (group_id, hostname, ip_address, status) VALUES (?, 'sw-01', '10.1.1.1', 'up')",
                (gid,),
            )
            host_id = cur2.lastrowid
            await db.commit()
            return int(host_id)
        finally:
            await db.close()

    host_id = asyncio.run(_create_host())
    return site["id"], floor["id"], host_id


def test_upsert_placement(geo_client):
    _, floor_id, host_id = _setup_site_floor_host(geo_client)
    resp = geo_client.put(
        f"/api/geo/floors/{floor_id}/placements/{host_id}",
        json={"x_pct": 0.25, "y_pct": 0.5},
    )
    assert resp.status_code == 200


def test_get_placements(geo_client):
    _, floor_id, host_id = _setup_site_floor_host(geo_client)
    geo_client.put(
        f"/api/geo/floors/{floor_id}/placements/{host_id}",
        json={"x_pct": 0.1, "y_pct": 0.9},
    )
    resp = geo_client.get(f"/api/geo/floors/{floor_id}/placements")
    assert resp.status_code == 200
    pins = resp.json()
    assert any(p["host_id"] == host_id for p in pins)


def test_delete_placement(geo_client):
    _, floor_id, host_id = _setup_site_floor_host(geo_client)
    geo_client.put(
        f"/api/geo/floors/{floor_id}/placements/{host_id}",
        json={"x_pct": 0.5, "y_pct": 0.5},
    )
    resp = geo_client.delete(f"/api/geo/floors/{floor_id}/placements/{host_id}")
    assert resp.status_code == 200
    pins = geo_client.get(f"/api/geo/floors/{floor_id}/placements").json()
    assert not any(p["host_id"] == host_id for p in pins)


def test_placement_out_of_range_returns_422(geo_client):
    _, floor_id, host_id = _setup_site_floor_host(geo_client)
    resp = geo_client.put(
        f"/api/geo/floors/{floor_id}/placements/{host_id}",
        json={"x_pct": 1.5, "y_pct": 0.5},  # x > 1
    )
    assert resp.status_code == 422


# ── Overview ──────────────────────────────────────────────────────────────────

def test_geo_overview(geo_client):
    geo_client.post("/api/geo/sites", json={"name": "Overview Site"})
    resp = geo_client.get("/api/geo/overview")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
