from __future__ import annotations

import netcontrol.app as app_module
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def token_protected_client(monkeypatch):
    """Create a real FastAPI test client with API token requirement enabled."""

    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "true")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "week6-secret-token")

    with TestClient(app_module.app) as client:
        yield client


def test_protected_endpoint_rejects_missing_token(token_protected_client):
    response = token_protected_client.get("/api/admin/capabilities")
    assert response.status_code == 401
    payload = response.json()
    assert payload["ok"] is False
    assert payload["error"]["code"] == "http_error"
    assert "invalid API token" in payload["error"]["message"]


def test_protected_endpoint_rejects_invalid_token(token_protected_client):
    response = token_protected_client.get(
        "/api/admin/capabilities",
        headers={"X-API-Token": "wrong-token"},
    )
    assert response.status_code == 401
    payload = response.json()
    assert payload["ok"] is False
    assert payload["error"]["code"] == "http_error"


def test_protected_endpoint_accepts_x_api_token(token_protected_client):
    response = token_protected_client.get(
        "/api/admin/capabilities",
        headers={"X-API-Token": "week6-secret-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "feature_flags" in payload
    assert "auth_providers" in payload


def test_protected_endpoint_accepts_bearer_token(token_protected_client):
    response = token_protected_client.get(
        "/api/admin/capabilities",
        headers={"Authorization": "Bearer week6-secret-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "feature_flags" in payload


def test_token_requirement_overrides_valid_session_cookie(token_protected_client):
    session_token = app_module.create_session_token("admin", 1)
    response = token_protected_client.get(
        "/api/admin/capabilities",
        cookies={"session": session_token},
    )
    assert response.status_code == 401
    assert "invalid API token" in response.json()["error"]["message"]


def test_public_health_endpoint_remains_accessible_without_token(token_protected_client):
    response = token_protected_client.get("/api/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["status"] == "healthy"


def test_health_details_need_the_api_token(token_protected_client):
    anonymous = token_protected_client.get("/api/health")
    assert anonymous.status_code == 200
    assert anonymous.json() == {"ok": True, "status": "healthy"}
    assert token_protected_client.get("/api/health?probe=live").json() == {"ok": True, "status": "healthy"}
    full = token_protected_client.get("/api/health", headers={"X-API-Token": "week6-secret-token"}).json()
    assert full["ok"] is True and full["db"] == "ok"
    assert "metrics" in full and "uptime_seconds" in full
    # With the token required, a session cookie alone does not unlock them.
    cookie = {"session": app_module.create_session_token("admin", 1)}
    assert set(token_protected_client.get("/api/health", cookies=cookie).json()) == {"ok", "status"}


def test_version_sha_needs_the_api_token(token_protected_client):
    from netcontrol.version import APP_VERSION

    assert token_protected_client.get("/api/version").json() == {"version": APP_VERSION}
    wrong = token_protected_client.get("/api/version", headers={"X-API-Token": "wrong-token"})
    assert wrong.json() == {"version": APP_VERSION}
    full = token_protected_client.get("/api/version", headers={"Authorization": "Bearer week6-secret-token"})
    assert set(full.json()) == {"version", "git_sha"}


def test_degraded_health_keeps_503_without_the_details(token_protected_client, monkeypatch):
    async def _down(*args, **kwargs):
        raise ConnectionRefusedError("database down")

    monkeypatch.setattr(app_module.db, "get_db", _down)
    anonymous = token_protected_client.get("/api/health")
    assert anonymous.status_code == 503
    assert anonymous.json() == {"ok": False, "status": "degraded"}
    full = token_protected_client.get("/api/health", headers={"X-API-Token": "week6-secret-token"})
    assert full.status_code == 503
    assert full.json()["db"] == "error: ConnectionRefusedError"


@pytest.fixture
def session_client(monkeypatch, request):
    """A client of the app in its usual mode (sessions, no token required)."""
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    return client


def test_health_and_version_details_need_a_session(session_client):
    assert session_client.get("/api/health").json() == {"ok": True, "status": "healthy"}
    assert set(session_client.get("/api/version").json()) == {"version"}
    # A forged or stale cookie is not a session.
    session_client.cookies.set("session", "not-a-valid-session")
    assert set(session_client.get("/api/health").json()) == {"ok", "status"}
    session_client.cookies.clear()

    resp = session_client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert resp.status_code == 200, resp.text
    health = session_client.get("/api/health").json()
    assert {"metrics", "uptime_seconds", "db"} <= set(health)
    assert set(session_client.get("/api/version").json()) == {"version", "git_sha"}


def test_startup_validation_fails_when_required_token_missing(monkeypatch):
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "true")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    with pytest.raises(RuntimeError, match="APP_REQUIRE_API_TOKEN"):
        app_module._validate_startup_config()


def test_startup_validation_passes_when_required_token_present(monkeypatch):
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "true")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "configured-token")

    app_module._validate_startup_config()


@pytest.fixture(autouse=True)
def clear_require_api_token_env(monkeypatch):
    """Prevent env leakage between token tests and the rest of the suite."""
    yield
    monkeypatch.delenv("APP_REQUIRE_API_TOKEN", raising=False)
