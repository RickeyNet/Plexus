"""Week 4 - Security Hardening tests.

Covers:
  1. First-login password reset enforcement for default admin.
  2. APP_ALLOW_SELF_REGISTER gate on /api/auth/register.
  3. Playbook filename hardening (allowlist, path-traversal prevention).
  4. CSRF protection for cookie-authenticated state-changing requests.
"""

from __future__ import annotations

from types import SimpleNamespace
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
        # Real Starlette requests always expose .state; require_auth uses it
        # as a per-request cache for the resolved session/user.
        self.state = SimpleNamespace()


# ═════════════════════════════════════════════════════════════════════════════
# 1. First-login password reset enforcement
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_default_admin_creation_sets_must_change_password(monkeypatch):
    """_ensure_default_admin must set must_change_password=True."""
    created = {}

    # Force the non-dev, first-boot path: no dev bootstrap, no preset
    # password, and no pre-existing user to promote.
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("PLEXUS_DEV_BOOTSTRAP", raising=False)
    monkeypatch.delenv("PLEXUS_INITIAL_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PLEXUS_FORCE_ADMIN_PASSWORD_RESET", raising=False)

    async def fake_get_all_users():
        return []

    async def fake_get_user_by_username(username):
        return None

    monkeypatch.delenv("PLEXUS_DEFAULT_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PLEXUS_INITIAL_ADMIN_USERNAME", raising=False)

    async def fake_create_user(username, pw_hash, salt, *, display_name="", role="user", must_change_password=False):
        created.update(username=username, pw_hash=pw_hash, salt=salt, must_change_password=must_change_password)
        return 1

    with (
        patch.object(app_module.db, "get_all_users", fake_get_all_users),
        patch.object(app_module.db, "get_user_by_username", fake_get_user_by_username),
        patch.object(app_module.db, "create_user", fake_create_user),
        patch.object(app_module, "_emit_bootstrap_admin_credentials", lambda *a, **k: None),
    ):
        await app_module._ensure_default_admin()

    assert created.get("must_change_password") is True
    # The first-boot password is the documented default, netcontrol.
    assert created["username"] == "admin"
    assert created["pw_hash"] == app_module._hash_password("netcontrol", created["salt"])


@pytest.mark.asyncio
async def test_force_admin_password_reset_is_one_shot(monkeypatch):
    """PLEXUS_FORCE_ADMIN_PASSWORD_RESET fires once per arming.

    A flag left in .env must not reset the admin (and re-flag must-change)
    on every restart; a boot without the flag re-arms it.
    """
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("PLEXUS_DEV_BOOTSTRAP", raising=False)
    monkeypatch.delenv("PLEXUS_INITIAL_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("PLEXUS_INITIAL_ADMIN_USERNAME", "admin")

    settings: dict[str, dict] = {}
    resets: list[bool] = []
    revoked: list[int] = []
    admin_row = {"id": 1, "username": "admin", "role": "admin"}

    async def fake_get_all_users():
        return [admin_row]

    async def fake_get_user_by_username(username):
        return admin_row if username == "admin" else None

    async def fake_update_user_admin(user_id, **kwargs):
        return None

    async def fake_update_user_password(user_id, pw_hash, salt, must_change_password=False):
        resets.append(must_change_password)

    async def fake_bump_user_session_epoch(user_id):
        revoked.append(user_id)
        return len(revoked)

    async def fake_get_auth_setting(key):
        return settings.get(key)

    async def fake_set_auth_setting(key, value):
        settings[key] = value

    async def boot(flag: str | None):
        if flag is None:
            monkeypatch.delenv("PLEXUS_FORCE_ADMIN_PASSWORD_RESET", raising=False)
        else:
            monkeypatch.setenv("PLEXUS_FORCE_ADMIN_PASSWORD_RESET", flag)
        with (
            patch.object(app_module.db, "get_all_users", fake_get_all_users),
            patch.object(app_module.db, "get_user_by_username", fake_get_user_by_username),
            patch.object(app_module.db, "update_user_admin", fake_update_user_admin),
            patch.object(app_module.db, "update_user_password", fake_update_user_password),
            patch.object(app_module.db, "bump_user_session_epoch", fake_bump_user_session_epoch),
            patch.object(app_module.db, "get_auth_setting", fake_get_auth_setting),
            patch.object(app_module.db, "set_auth_setting", fake_set_auth_setting),
            patch.object(app_module, "_emit_bootstrap_admin_credentials", lambda *a, **k: None),
        ):
            await app_module._ensure_default_admin()

    await boot("true")
    assert resets == [True], "first boot with the flag resets the admin (must-change)"
    assert revoked == [1], "the reset ends the sessions signed in with the old password"
    assert settings[app_module._FORCE_RESET_MARKER_KEY]["applied"] is True

    await boot("true")
    assert resets == [True], "flag left set: no second reset on restart"

    await boot(None)
    assert settings[app_module._FORCE_RESET_MARKER_KEY]["applied"] is False, "boot without flag re-arms"
    assert resets == [True]

    await boot("true")
    assert resets == [True, True], "re-set flag fires again after re-arming"
    assert revoked == [1, 1]


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
@pytest.mark.parametrize(("env", "expected"), [(None, False), ("true", True)])
async def test_logged_out_status_reports_self_register_flag(monkeypatch, env, expected):
    """The login screen reads allow_self_register to show or hide Register."""
    if env is None:
        monkeypatch.delenv("APP_ALLOW_SELF_REGISTER", raising=False)
    else:
        monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", env)

    from fastapi import Response
    from netcontrol.routes import auth as auth_module

    result = await auth_module.auth_status(cast(Request, DummyRequest()), Response())

    assert result["authenticated"] is False
    assert result["allow_self_register"] == expected
    # The signed-out status also tells the login screen about single sign-on.
    assert set(result["sso"]["oidc"]) == {"enabled", "label", "primary"}


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


def _decoded_session(username: str, user_id: int = 1) -> dict:
    return app_module.verify_session_token(app_module.create_session_token(username, user_id))


def test_csrf_token_roundtrip():
    """A generated CSRF token should validate for the session it was made for."""
    session = _decoded_session("testuser")
    token = app_module._generate_csrf_token(session)
    assert app_module._validate_csrf_token(token, session) is True


def test_csrf_token_rejects_wrong_user():
    """A CSRF token generated for user A must not validate for user B, even
    for a session that carries the same id."""
    session = _decoded_session("userA")
    token = app_module._generate_csrf_token(session)
    assert app_module._validate_csrf_token(token, {**session, "user": "userB"}) is False


def test_csrf_token_rejects_garbage():
    """Garbage strings must not validate."""
    assert app_module._validate_csrf_token("not-a-real-token", _decoded_session("any")) is False


@pytest.mark.asyncio
async def test_login_response_includes_csrf_token(monkeypatch):
    """The login endpoint must return a csrf_token in the response body."""
    user_row = {
        "id": 1,
        "username": "admin",
        "password_hash": "",
        "salt": "",
        "display_name": "Admin",
        "role": "admin",
        "must_change_password": 0,
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
        "id": 1,
        "username": "admin",
        "password_hash": "",
        "salt": "",
        "display_name": "Admin",
        "role": "admin",
        "must_change_password": 1,
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

    from fastapi import Response

    data = await app_module.auth_status(cast(Request, req), Response())
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
@pytest.mark.parametrize(
    ("https_enabled", "cookie_secure", "expect_secure"),
    [
        (True, True, True),
        # TLS ends at the reverse proxy: APP_HTTPS is false, APP_COOKIE_SECURE true.
        (False, True, True),
        (False, False, False),
    ],
)
async def test_login_cookie_secure_flag_follows_settings(monkeypatch, https_enabled, cookie_secure, expect_secure):
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
    monkeypatch.setattr(app_module, "APP_HTTPS_ENABLED", https_enabled)
    monkeypatch.setattr(app_module, "APP_COOKIE_SECURE", cookie_secure)

    class FakeClient:
        host = "127.0.0.1"

    req = DummyRequest()
    req.client = FakeClient()
    req.url = type("U", (), {"path": "/api/auth/login"})()

    body = app_module.LoginRequest(username="admin", password="netcontrol")
    resp = await app_module.login(body, cast(Request, req))

    set_cookie_header = resp.headers.get("set-cookie", "")
    assert ("Secure" in set_cookie_header) is expect_secure


def test_security_check_payload_reflects_runtime_flags(monkeypatch):
    monkeypatch.setattr(app_module, "APP_HTTPS_ENABLED", True)
    monkeypatch.setattr(app_module, "APP_HSTS_ENABLED", True)
    monkeypatch.setattr(app_module, "APP_HSTS_MAX_AGE", 31536000)
    monkeypatch.setattr(app_module, "APP_HTTPS_REDIRECT", True)
    monkeypatch.setattr(app_module, "APP_CORS_ALLOW_ORIGINS", ["https://plexus.example.com"])
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "secret-token")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "true")

    payload = app_module._security_check_payload()

    assert payload["ok"] is True
    assert payload["transport"]["https_enabled"] is True
    assert payload["transport"]["https_redirect"] is True
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


@pytest.mark.parametrize(
    ("https_enabled", "cookie_secure", "expect_secure"),
    [(True, False, True), (False, True, True), (False, False, False)],
)
def test_security_check_reports_the_flag_the_cookie_carries(monkeypatch, https_enabled, cookie_secure, expect_secure):
    monkeypatch.setattr(app_module, "APP_HTTPS_ENABLED", https_enabled)
    monkeypatch.setattr(app_module, "APP_COOKIE_SECURE", cookie_secure)

    payload = app_module._security_check_payload()

    assert payload["cookies"]["session_cookie_secure"] is expect_secure
    assert any("without Secure" in w for w in payload["warnings"]) is not expect_secure


def test_session_refresh_keeps_the_secure_flag_of_sign_in(monkeypatch, request):
    """APP_HTTPS on with APP_COOKIE_SECURE off: sign-in issues a Secure
    cookie, so the refresh on the next request must too."""
    from mcp_helpers import admin_client

    admin = admin_client(monkeypatch, request)
    monkeypatch.setattr(app_module, "APP_HTTPS_ENABLED", True)
    monkeypatch.setattr(app_module, "APP_COOKIE_SECURE", False)
    # A cookie this fresh is not due for a refresh otherwise.
    monkeypatch.setattr(app_module, "SESSION_REFRESH_MAX_LAG_SECONDS", 0)

    resp = admin.get("/api/admin/login-rules")

    assert resp.status_code == 200
    refreshed =[h for h in resp.headers.get_list("set-cookie") if h.startswith("session=")]
    assert refreshed and all("Secure" in h for h in refreshed)


def test_security_check_warns_about_unprotected_sign_in_providers(monkeypatch):
    def warnings_for(**blocks) -> str:
        monkeypatch.setattr(app_module.state, "AUTH_CONFIG", {"provider": "local", **blocks})
        return "\n".join(app_module._security_check_payload()["warnings"])

    # A provider that is off raises nothing, whatever its settings.
    assert "RADIUS" not in warnings_for(radius={"enabled": False, "enforce_message_authenticator": False})
    assert "LDAP" not in warnings_for(ldap={"enabled": False, "default_role": "admin"})

    assert "CVE-2024-3596" in warnings_for(radius={"enabled": True, "enforce_message_authenticator": False})
    assert "RADIUS" not in warnings_for(radius={"enabled": True, "enforce_message_authenticator": True})

    assert "LDAP is enabled without TLS" in warnings_for(ldap={"enabled": True, "tls_verify": "demand"})
    weak = warnings_for(ldap={"enabled": True, "use_starttls": True, "tls_verify": "allow"})
    assert "below 'demand'" in weak and "without TLS" not in weak
    assert "LDAP" not in warnings_for(ldap={"enabled": True, "use_ssl": True, "tls_verify": "demand"})

    everyone_admin = warnings_for(
        ldap={"enabled": True, "use_ssl": True, "default_role": "admin"},
        oidc={"enabled": True, "default_role": "admin"},
        saml={"enabled": True, "default_role": "user"},
    )
    assert "LDAP default role is admin" in everyone_admin and "OIDC default role is admin" in everyone_admin
    assert "SAML" not in everyone_admin


# ── Session signing key file ─────────────────────────────────────────────────


@pytest.mark.parametrize("stored", ["", "\n", "short-key"])
def test_secret_key_file_with_unusable_key_is_replaced(monkeypatch, tmp_path, stored):
    # An empty or truncated key file must never become the signing key.
    key_file = tmp_path / "session.key"
    key_file.write_text(stored, encoding="utf-8")
    monkeypatch.setattr(app_module, "SECRET_KEY_FILE", str(key_file))

    key = app_module._load_or_create_secret_key()

    assert len(key) == 64
    assert key_file.read_text(encoding="utf-8") == key
    assert not (tmp_path / "session.key.new").exists()
    # The replacement is stable: the next start reads the same key.
    assert app_module._load_or_create_secret_key() == key


def test_secret_key_file_with_valid_key_is_kept(monkeypatch, tmp_path):
    key_file = tmp_path / "session.key"
    stored = "k" * 64
    key_file.write_text(stored + "\n", encoding="utf-8")
    monkeypatch.setattr(app_module, "SECRET_KEY_FILE", str(key_file))

    assert app_module._load_or_create_secret_key() == stored
    assert key_file.read_text(encoding="utf-8") == stored + "\n"


def test_secret_key_file_is_created_when_missing(monkeypatch, tmp_path):
    key_file = tmp_path / "keys" / "session.key"
    monkeypatch.setattr(app_module, "SECRET_KEY_FILE", str(key_file))

    key = app_module._load_or_create_secret_key()

    assert len(key) == 64
    assert key_file.read_text(encoding="utf-8") == key
