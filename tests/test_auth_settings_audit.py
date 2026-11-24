"""Changes to the settings that decide who may sign in, and how, are audited
(``auth`` / ``auth_config.update`` and ``login_rules.update``) with what
changed, secrets named only as changed. Also: a saved auth configuration is
the one the next password sign-in uses. Every name and address is invented.
"""

from __future__ import annotations

import copy

import netcontrol.app as app_module
import netcontrol.routes.admin as admin_module
import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client

AUTH_CONFIG = "/api/admin/auth-config"
LOGIN_RULES = "/api/admin/login-rules"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    # The routes rebind these; put the originals back afterwards.
    monkeypatch.setattr(state, "AUTH_CONFIG", copy.deepcopy(state.AUTH_CONFIG))
    monkeypatch.setattr(state, "LOGIN_RULES", dict(state.LOGIN_RULES))
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    return client


def _events(admin: CsrfClient, action: str) -> list[dict]:
    events = admin.raw.portal.call(db_module.get_audit_events, 100)
    return [e for e in events if e["action"] == action]


# ── what the audit entry says ────────────────────────────────────────────────


def test_settings_changes_names_nested_settings_and_hides_secrets():
    old = {
        "provider": "local",
        "radius": {"enabled": False, "server": "", "secret": "old-shared-secret"},
        "ldap": {"bind_password": ""},
        "oidc": {"admin_groups": []},
    }
    new = {
        "provider": "radius",
        "radius": {"enabled": True, "server": "radius.example.com", "secret": "new-shared-secret"},
        "ldap": {"bind_password": ""},
        "oidc": {"admin_groups": ["netops"], "client_secret_enc": "ciphertext"},
    }
    changes = admin_module._settings_changes(old, new)
    assert changes == [
        'oidc.admin_groups: [] -> ["netops"]',
        "oidc.client_secret_enc: changed",
        "provider: local -> radius",
        "radius.enabled: False -> True",
        "radius.secret: changed",
        "radius.server:  -> radius.example.com",
    ]
    assert admin_module._settings_changes(new, new) == []
    long_value = admin_module._audit_setting_value("user_filter", "x" * 500)
    assert len(long_value) == admin_module._AUDIT_VALUE_MAX + 3 and long_value.endswith("...")


def test_login_rules_update_is_audited(admin):
    rules = admin.get(LOGIN_RULES).json()
    resp = admin.put(LOGIN_RULES, json={**rules, "max_attempts": 50, "lockout_time": 1})
    assert resp.status_code == 200, resp.text
    (event,) = _events(admin, "login_rules.update")
    assert event["category"] == "auth" and event["user"] == "admin"
    assert f"max_attempts: {rules['max_attempts']} -> 50" in event["detail"]
    assert f"lockout_time: {rules['lockout_time']} -> 1" in event["detail"]
    assert "rate_limit_max" not in event["detail"]

    # A save that changes nothing is still on record.
    assert admin.put(LOGIN_RULES, json=resp.json()).status_code == 200
    assert [e["detail"] for e in _events(admin, "login_rules.update")][0] == "no changes"


def test_auth_config_update_is_audited_without_secrets(admin):
    cfg = admin.get(AUTH_CONFIG).json()
    cfg["radius"] = {**cfg["radius"], "secret": "a-new-shared-secret", "fallback_on_reject": True}
    cfg["ldap"] = {**cfg["ldap"], "default_role": "admin"}
    resp = admin.put(AUTH_CONFIG, json=cfg)
    assert resp.status_code == 200, resp.text
    (event,) = _events(admin, "auth_config.update")
    assert event["category"] == "auth" and event["user"] == "admin"
    detail = event["detail"]
    assert "radius.fallback_on_reject: False -> True" in detail
    assert "radius.secret: changed" in detail
    assert "ldap.default_role: user -> admin" in detail
    assert "a-new-shared-secret" not in detail


# ── a saved configuration is the one sign-in uses ────────────────────────────


def test_a_saved_provider_is_used_by_the_next_password_sign_in(admin, monkeypatch):
    asked: list[str] = []

    async def directory(username, password):
        asked.append(username)
        return False, "reject"

    monkeypatch.setattr(app_module, "verify_radius_user", directory)
    cfg = admin.get(AUTH_CONFIG).json()
    cfg["provider"] = "radius"
    cfg["radius"] = {**cfg["radius"], "enabled": True, "server": "192.0.2.10", "secret": "a-new-shared-secret"}
    resp = admin.put(AUTH_CONFIG, json=cfg)
    assert resp.status_code == 200, resp.text

    browser = TestClient(app_module.app, raise_server_exceptions=False)
    assert browser.post("/api/auth/login", json={"username": "walter", "password": "password123"}).status_code == 401
    assert asked == ["walter"]
