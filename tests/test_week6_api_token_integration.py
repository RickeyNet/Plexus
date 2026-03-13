from __future__ import annotations

import netcontrol.app as app_module
import pytest
import routes.database as db_module
from fastapi.testclient import TestClient


@pytest.fixture
def token_protected_client(monkeypatch, tmp_path):
    """Create a real FastAPI test client with API token requirement enabled."""
    db_path = tmp_path / "week6-token.db"
    monkeypatch.setattr(db_module, "DB_PATH", str(db_path))

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
