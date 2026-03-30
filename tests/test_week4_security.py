"""Week 4 — Security Hardening tests.

Covers:
  1. First-login password reset enforcement for default admin.
  2. APP_ALLOW_SELF_REGISTER gate on /api/auth/register.
  3. Playbook filename hardening (allowlist, path-traversal prevention).
  4. CSRF protection for cookie-authenticated state-changing requests.
"""

from __future__ import annotations

from typing import cast
from unittest.mock import patch

import netcontrol.app as app_module
import netcontrol.routes.playbooks as playbooks_module
import pytest
from fastapi import Request

# ── Helpers ──────────────────────────────────────────────────────────────────


class DummyRequest:
    """Minimal Request-like object for unit tests."""

    def __init__(self, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None):
        normalized = {k.lower(): v for k, v in (headers or {}).items()}

        class HeaderMap(dict):
            def get(self, key, default=None):
                return super().get(str(key).lower(), default)

        self.headers = HeaderMap(normalized)
        self.cookies = cookies or {}


# ═════════════════════════════════════════════════════════════════════════════
# 1. First-login password reset enforcement
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_default_admin_creation_sets_must_change_password():
    """_ensure_default_admin must set must_change_password=True."""
    created = {}

    async def fake_get_all_users():
        return []

    async def fake_create_user(username, pw_hash, salt, *, display_name="", role="user", must_change_password=False):
        created["must_change_password"] = must_change_password
        return 1

    with patch.object(app_module.db, "get_all_users", fake_get_all_users), \
         patch.object(app_module.db, "create_user", fake_create_user):
        await app_module._ensure_default_admin()

    assert created.get("must_change_password") is True


@pytest.mark.asyncio
async def test_require_auth_blocks_when_must_change_password(monkeypatch):
    """Protected paths should return 403 when must_change_password is set."""

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "admin", "role": "admin", "must_change_password": 1}

    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    token = app_module.create_session_token("admin", 1)
    req = DummyRequest(cookies={"session": token})
    req.url = type("U", (), {"path": "/api/inventory"})()

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await app_module.require_auth(cast(Request, req))
    assert exc_info.value.status_code == 403
    assert "Password change required" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_require_auth_allows_change_password_when_must_change(monkeypatch):
    """The change-password endpoint must remain accessible even when flag is set."""

    async def fake_get_user_by_id(uid):
        return {"id": uid, "username": "admin", "role": "admin", "must_change_password": 1}

    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    token = app_module.create_session_token("admin", 1)
    req = DummyRequest(cookies={"session": token})
    req.url = type("U", (), {"path": "/api/auth/change-password"})()

    session = await app_module.require_auth(cast(Request, req))
    assert session is not None
    assert session["user"] == "admin"


# ═════════════════════════════════════════════════════════════════════════════
# 2. APP_ALLOW_SELF_REGISTER gate
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_register_blocked_by_default(monkeypatch):
    """Self-registration should be rejected when APP_ALLOW_SELF_REGISTER is unset."""
    monkeypatch.delenv("APP_ALLOW_SELF_REGISTER", raising=False)

    body = app_module.RegisterRequest(username="newuser", password="secret123")

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await app_module.register(body)
    assert exc_info.value.status_code == 403
    assert "disabled" in str(exc_info.value.detail).lower()


@pytest.mark.asyncio
async def test_register_allowed_when_opted_in(monkeypatch):
    """Self-registration should proceed when APP_ALLOW_SELF_REGISTER=true."""
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")

    user_row = {"id": 99, "username": "newuser", "display_name": "Newuser", "role": "user", "must_change_password": 0}

    async def fake_get_user_by_username(u):
        return None

    async def fake_create_user(u, h, s, *, display_name="", role="user", must_change_password=False):
        return 99

    async def fake_get_user_by_id(uid):
        return user_row

    async def fake_get_features(user):
        return ["dashboard"]

    monkeypatch.setattr(app_module.db, "get_user_by_username", fake_get_user_by_username)
    monkeypatch.setattr(app_module.db, "create_user", fake_create_user)
    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(app_module, "_get_user_features", fake_get_features)

    body = app_module.RegisterRequest(username="newuser", password="secret123")
    resp = await app_module.register(body)
    assert resp.status_code == 200
    import json
    data = json.loads(resp.body.decode())
    assert data["ok"] is True
    assert "csrf_token" in data


# ═════════════════════════════════════════════════════════════════════════════
# 3. Playbook filename hardening
# ═════════════════════════════════════════════════════════════════════════════


class TestSanitizePlaybookFilename:
    """Unit tests for _sanitize_playbook_filename."""

    def test_simple_name(self):
        assert app_module._sanitize_playbook_filename("my_playbook") == "my_playbook.py"

    def test_with_extension(self):
        assert app_module._sanitize_playbook_filename("my_playbook.py") == "my_playbook.py"

    def test_hyphens_allowed(self):
        assert app_module._sanitize_playbook_filename("my-playbook") == "my-playbook.py"

    def test_alphanumeric_start(self):
        assert app_module._sanitize_playbook_filename("A1_test") == "A1_test.py"

    def test_rejects_path_traversal_unix(self):
        with pytest.raises(ValueError, match="path separators"):
            app_module._sanitize_playbook_filename("../../etc/passwd")

    def test_rejects_path_traversal_windows(self):
        with pytest.raises(ValueError, match="path separators"):
            app_module._sanitize_playbook_filename("..\\..\\evil")

    def test_rejects_dotdot(self):
        with pytest.raises(ValueError, match="path separators"):
            app_module._sanitize_playbook_filename("..evil")

    def test_rejects_slash(self):
        with pytest.raises(ValueError, match="path separators"):
            app_module._sanitize_playbook_filename("sub/evil")

    def test_rejects_special_characters(self):
        with pytest.raises(ValueError, match="only letters"):
            app_module._sanitize_playbook_filename("play book")

    def test_rejects_leading_underscore(self):
        with pytest.raises(ValueError, match="only letters"):
            app_module._sanitize_playbook_filename("_hidden")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="only letters"):
            app_module._sanitize_playbook_filename("")

    def test_rejects_double_extension(self):
        with pytest.raises(ValueError, match="only letters"):
            app_module._sanitize_playbook_filename("evil.txt.py")

    def test_strips_whitespace(self):
        assert app_module._sanitize_playbook_filename("  hello  ") == "hello.py"

    @pytest.mark.parametrize(
        "bad_name",
        [
            "%2e%2e%2fetc%2fpasswd",
            "..%2F..%2Fwindows",
            "playbook.py/../evil",
            "playbook\\..\\evil",
            "con\x00fig",
            "evil\nname",
            "evil\tname",
            "evil.",
            ".hidden",
            "C:/Windows/System32",
            "C:\\Windows\\System32",
        ],
    )
    def test_rejects_malicious_or_pathlike_names(self, bad_name):
        with pytest.raises(ValueError):
            app_module._sanitize_playbook_filename(bad_name)

    def test_keeps_single_extension_after_whitespace_trim(self):
        assert app_module._sanitize_playbook_filename("  valid_name.py  ") == "valid_name.py"


def test_write_playbook_file_prevents_escape(tmp_path, monkeypatch):
    """write_playbook_file must reject filenames that would escape the playbooks dir."""
    monkeypatch.setattr(app_module, "project_root", str(tmp_path))
    monkeypatch.setattr(playbooks_module, "project_root", str(tmp_path))
    playbooks_dir = tmp_path / "templates" / "playbooks"
    playbooks_dir.mkdir(parents=True)

    with pytest.raises(ValueError):
        app_module.write_playbook_file("../../etc/passwd", "pwned")

    # Verify nothing was written outside playbooks dir
    assert not (tmp_path / "etc").exists()


def test_write_playbook_file_succeeds_for_valid_name(tmp_path, monkeypatch):
    """write_playbook_file should write to the correct location for valid filenames."""
    monkeypatch.setattr(app_module, "project_root", str(tmp_path))
    monkeypatch.setattr(playbooks_module, "project_root", str(tmp_path))
    playbooks_dir = tmp_path / "templates" / "playbooks"
    playbooks_dir.mkdir(parents=True)

    path = app_module.write_playbook_file("my_test_playbook", "# test content")
    assert path.endswith("my_test_playbook.py")
    assert (playbooks_dir / "my_test_playbook.py").read_text() == "# test content"


# ═════════════════════════════════════════════════════════════════════════════
# 4. CSRF protection
# ═════════════════════════════════════════════════════════════════════════════


def test_csrf_token_roundtrip():
    """A generated CSRF token should validate for the same user."""
    token = app_module._generate_csrf_token("testuser")
    assert app_module._validate_csrf_token(token, "testuser") is True


def test_csrf_token_rejects_wrong_user():
    """A CSRF token generated for user A must not validate for user B."""
    token = app_module._generate_csrf_token("userA")
    assert app_module._validate_csrf_token(token, "userB") is False


def test_csrf_token_rejects_garbage():
    """Garbage strings must not validate."""
    assert app_module._validate_csrf_token("not-a-real-token", "any") is False


@pytest.mark.asyncio
async def test_login_response_includes_csrf_token(monkeypatch):
    """The login endpoint must return a csrf_token in the response body."""
    user_row = {
        "id": 1, "username": "admin", "password_hash": "", "salt": "",
        "display_name": "Admin", "role": "admin", "must_change_password": 0,
    }

    async def fake_authenticate(u, p):
        return user_row, "local", None

    async def fake_features(user):
        return ["dashboard"]

    monkeypatch.setattr(app_module, "authenticate_login_identity", fake_authenticate)
    monkeypatch.setattr(app_module, "_get_user_features", fake_features)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})

    class FakeClient:
        host = "127.0.0.1"

    req = DummyRequest()
    req.client = FakeClient()
    req.url = type("U", (), {"path": "/api/auth/login"})()

    body = app_module.LoginRequest(username="admin", password="netcontrol")
    resp = await app_module.login(body, cast(Request, req))

    import json
    data = json.loads(resp.body.decode())
    assert data["ok"] is True
    assert "csrf_token" in data
    assert len(data["csrf_token"]) > 10


@pytest.mark.asyncio
async def test_login_response_includes_must_change_password(monkeypatch):
    """Login response must surface must_change_password flag."""
    user_row = {
        "id": 1, "username": "admin", "password_hash": "", "salt": "",
        "display_name": "Admin", "role": "admin", "must_change_password": 1,
    }

    async def fake_authenticate(u, p):
        return user_row, "local", None

    async def fake_features(user):
        return ["dashboard"]

    monkeypatch.setattr(app_module, "authenticate_login_identity", fake_authenticate)
    monkeypatch.setattr(app_module, "_get_user_features", fake_features)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})

    class FakeClient:
        host = "127.0.0.1"

    req = DummyRequest()
    req.client = FakeClient()
    req.url = type("U", (), {"path": "/api/auth/login"})()

    body = app_module.LoginRequest(username="admin", password="netcontrol")
    resp = await app_module.login(body, cast(Request, req))

    import json
    data = json.loads(resp.body.decode())
    assert data["must_change_password"] is True


@pytest.mark.asyncio
async def test_auth_status_includes_csrf_token_for_authenticated_session(monkeypatch):
    """Session restore response must include csrf_token for subsequent POST requests."""
    user_row = {
        "id": 7,
        "username": "alice",
        "display_name": "Alice",
        "role": "admin",
        "must_change_password": 0,
    }

    async def fake_get_user_by_id(uid):
        assert uid == 7
        return user_row

    async def fake_features(user):
        return ["dashboard", "inventory"]

    monkeypatch.setattr(app_module.db, "get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(app_module, "_get_user_features", fake_features)

    token = app_module.create_session_token("alice", 7)
    req = DummyRequest(cookies={"session": token})

    data = await app_module.auth_status(cast(Request, req))
    assert data["authenticated"] is True
    assert data["username"] == "alice"
    assert "csrf_token" in data
    assert len(data["csrf_token"]) > 10


def test_parse_cors_origins_defaults_when_unset(monkeypatch):
    monkeypatch.delenv("APP_CORS_ORIGINS", raising=False)
    origins = app_module._parse_cors_origins()
    assert "http://localhost:8080" in origins
    assert "http://127.0.0.1:8080" in origins


def test_parse_cors_origins_from_env(monkeypatch):
    monkeypatch.setenv("APP_CORS_ORIGINS", "https://plexus.example.com, https://admin.example.com")
    origins = app_module._parse_cors_origins()
    assert origins == ["https://plexus.example.com", "https://admin.example.com"]


@pytest.mark.asyncio
async def test_login_cookie_uses_secure_flag_when_https_enabled(monkeypatch):
    user_row = {
        "id": 1,
        "username": "admin",
        "password_hash": "",
        "salt": "",
        "display_name": "Admin",
        "role": "admin",
        "must_change_password": 0,
    }

    async def fake_authenticate(_u, _p):
        return user_row, "local", None

    async def fake_features(_user):
        return ["dashboard"]

    monkeypatch.setattr(app_module, "authenticate_login_identity", fake_authenticate)
    monkeypatch.setattr(app_module, "_get_user_features", fake_features)
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    monkeypatch.setattr(app_module, "APP_HTTPS_ENABLED", True)

    class FakeClient:
        host = "127.0.0.1"

    req = DummyRequest()
    req.client = FakeClient()
    req.url = type("U", (), {"path": "/api/auth/login"})()

    body = app_module.LoginRequest(username="admin", password="netcontrol")
    resp = await app_module.login(body, cast(Request, req))

    set_cookie_header = resp.headers.get("set-cookie", "")
    assert "Secure" in set_cookie_header


def test_security_check_payload_reflects_runtime_flags(monkeypatch):
    monkeypatch.setattr(app_module, "APP_HTTPS_ENABLED", True)
    monkeypatch.setattr(app_module, "APP_HSTS_ENABLED", True)
    monkeypatch.setattr(app_module, "APP_HSTS_MAX_AGE", 31536000)
    monkeypatch.setattr(app_module, "APP_CORS_ALLOW_ORIGINS", ["https://plexus.example.com"])
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "secret-token")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "true")

    payload = app_module._security_check_payload()

    assert payload["ok"] is True
    assert payload["transport"]["https_enabled"] is True
    assert payload["transport"]["hsts_enabled"] is True
    assert payload["cookies"]["session_cookie_secure"] is True
    assert payload["cors"]["allow_origins"] == ["https://plexus.example.com"]
    assert payload["auth"]["api_token_required"] is True
    assert payload["auth"]["api_token_configured"] is True
    assert payload["warnings"] == []


def test_security_check_payload_warns_when_hardening_disabled(monkeypatch):
    monkeypatch.setattr(app_module, "APP_HTTPS_ENABLED", False)
    monkeypatch.setattr(app_module, "APP_HSTS_ENABLED", False)
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")

    payload = app_module._security_check_payload()
    warnings = "\n".join(payload["warnings"])

    assert "APP_HTTPS is false" in warnings
    assert "APP_HSTS is false" in warnings
    assert "APP_REQUIRE_API_TOKEN is false" in warnings
    assert "APP_API_TOKEN is not set" in warnings
