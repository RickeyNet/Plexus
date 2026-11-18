"""OIDC single sign-on through the app: /api/auth/oidc/login and /callback,
the signed-out status ``sso`` block, the admin config and test endpoints.

The provider is faked (tests/oidc_fake.py) and swapped in as
``netcontrol.oidc.CLIENT``. Every name, host and value is invented.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlsplit

import netcontrol.app as app_module
import netcontrol.routes.admin as admin_module
import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from netcontrol import oidc
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client
from oidc_fake import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeIdP

LOGIN = "/api/auth/oidc/login"
CALLBACK = "/api/auth/oidc/callback"
AUTH_CONFIG = "/api/admin/auth-config"
OIDC_TEST = "/api/admin/auth-config/oidc/test"


def _oidc_cfg(**over) -> dict:
    from routes.crypto import encrypt

    cfg = {
        "enabled": True,
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "client_secret_enc": encrypt(CLIENT_SECRET),
        "admin_groups": ["plexus-admins"],
        "button_label": "Sign in with Example ID",
    }
    cfg.update(over)
    return state._sanitize_oidc_config(cfg)


@pytest.fixture
def env(monkeypatch, request):
    """An admin session, a fake provider, OIDC configured and a clean lockout."""
    admin = admin_client(monkeypatch, request)
    idp = FakeIdP()
    monkeypatch.setattr(oidc, "CLIENT", oidc.OidcClient(transport=idp.transport()))
    monkeypatch.setitem(state.AUTH_CONFIG, "oidc", _oidc_cfg())
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    return admin, idp


def _browser() -> TestClient:
    return TestClient(app_module.app, raise_server_exceptions=False, follow_redirects=False)


def _start(browser: TestClient, idp: FakeIdP, next_path: str | None = None, code: str = "code-1") -> dict:
    url = LOGIN + (f"?next={next_path}" if next_path is not None else "")
    resp = browser.get(url)
    assert resp.status_code == 302, resp.text
    return idp.authorize(resp.headers["location"], code)


def _sign_in(browser: TestClient, idp: FakeIdP, next_path: str | None = None):
    params = _start(browser, idp, next_path)
    return browser.get(CALLBACK, params={"code": "code-1", "state": params["state"]})


def _error_code(resp) -> str:
    assert resp.status_code == 303, resp.text
    location = resp.headers["location"]
    assert location.startswith("/login?sso_error=")
    return parse_qs(urlsplit(location).query)["sso_error"][0]


def _user(username: str) -> dict | None:
    return asyncio.run(db_module.get_user_by_username(username))


def _group(admin: CsrfClient, name: str) -> int:
    resp = admin.post("/api/admin/access-groups", json={"name": name, "feature_keys": ["inventory"]})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _audit_details(action: str) -> list[str]:
    async def fetch():
        rows = await db_module.get_audit_events(limit=200)
        return [r.get("detail") or "" for r in rows if r.get("action") == action]

    return asyncio.run(fetch())


# ── happy path ───────────────────────────────────────────────────────────────


def test_full_sign_in(env):
    admin, idp = env
    browser = _browser()
    start = browser.get(LOGIN + "?next=/devices/7")
    assert start.status_code == 302
    tx_cookie = start.headers["set-cookie"]
    assert "oidc_tx=" in tx_cookie and "HttpOnly" in tx_cookie and "Path=/api/auth/oidc" in tx_cookie
    assert "samesite=lax" in tx_cookie.lower() and "Max-Age=600" in tx_cookie
    params = idp.authorize(start.headers["location"])
    assert start.headers["location"].startswith(f"{ISSUER}/authorize?")
    assert params["client_id"] == CLIENT_ID and params["code_challenge_method"] == "S256"
    assert params["state"] and params["nonce"] and params["code_challenge"]
    assert params["redirect_uri"] == "http://testserver/api/auth/oidc/callback"
    assert params["scope"] == "openid profile email"

    resp = browser.get(CALLBACK, params={"code": "code-1", "state": params["state"]})
    assert resp.status_code == 303, resp.text
    assert resp.headers["location"] == "/devices/7"
    cookies = resp.headers.get_list("set-cookie")
    assert any(c.startswith("session=") for c in cookies)
    assert any(c.startswith("oidc_tx=") and "Max-Age=0" in c for c in cookies)
    # The token request authenticated with the stored (decrypted) secret.
    assert "Basic " in idp.token_requests[0].headers["Authorization"]

    status = browser.get("/api/auth/status").json()
    assert status["authenticated"] is True
    assert status["username"] == "alice" and status["display_name"] == "Alice Example"
    assert status["role"] == "user"
    user = _user("alice")
    assert user["auth_provider"] == "oidc" and user["external_id"] == "subject-0001"
    assert any("source=oidc" in d for d in _audit_details("login.success"))


def test_next_is_sanitised(env):
    _, idp = env
    browser = _browser()
    resp = _sign_in(browser, idp, "//evil.example.com/x")
    assert resp.headers["location"] == "/"


def test_login_when_disabled_or_provider_down(env, monkeypatch):
    _, idp = env
    browser = _browser()
    idp.discovery["issuer"] = "https://other.example.com"
    assert _error_code(browser.get(LOGIN)) == "provider"
    monkeypatch.setitem(state.AUTH_CONFIG, "oidc", _oidc_cfg(enabled=False))
    assert _error_code(browser.get(LOGIN)) == "disabled"


# ── callback failures ────────────────────────────────────────────────────────


def test_state_mismatch(env):
    _, idp = env
    browser = _browser()
    _start(browser, idp)
    resp = browser.get(CALLBACK, params={"code": "code-1", "state": "forged"})
    assert _error_code(resp) == "state"
    assert any(c.startswith("oidc_tx=") and "Max-Age=0" in c for c in resp.headers.get_list("set-cookie"))
    assert browser.get("/api/auth/status").json()["authenticated"] is False
    assert idp.calls["token"] == 0
    detail = [d for d in _audit_details("login.failure") if "source=oidc" in d]
    assert detail and "state" in detail[0] and "code-1" not in detail[0]


def test_missing_tx_cookie(env):
    _, idp = env
    params = _start(_browser(), idp)
    resp = _browser().get(CALLBACK, params={"code": "code-1", "state": params["state"]})
    assert _error_code(resp) == "state"


def test_callback_when_disabled(env, monkeypatch):
    _, idp = env
    browser = _browser()
    params = _start(browser, idp)
    monkeypatch.setitem(state.AUTH_CONFIG, "oidc", _oidc_cfg(enabled=False))
    assert _error_code(browser.get(CALLBACK, params={"code": "code-1", "state": params["state"]})) == "disabled"


def test_provider_error_is_mapped_not_echoed(env):
    _, idp = env
    browser = _browser()
    params = _start(browser, idp)
    resp = browser.get(
        CALLBACK, params={"error": "access_denied", "error_description": "<b>nope</b>", "state": params["state"]}
    )
    assert _error_code(resp) == "denied"
    assert "nope" not in resp.headers["location"]
    params = _start(browser, idp)
    resp = browser.get(CALLBACK, params={"error": "server_error", "state": params["state"]})
    assert _error_code(resp) == "provider"
    params = _start(browser, idp)
    assert _error_code(browser.get(CALLBACK, params={"state": params["state"]})) == "provider"


def test_bad_id_token_is_a_token_error(env):
    _, idp = env
    idp.claims = {"aud": "someone-else"}
    assert _error_code(_sign_in(_browser(), idp)) == "token"
    assert _user("alice") is None


def test_failures_count_toward_lockout(env, monkeypatch):
    _, idp = env
    monkeypatch.setitem(state.LOGIN_RULES, "max_attempts", 3)
    monkeypatch.setitem(state.LOGIN_RULES, "rate_limit_max", 10)
    browser = _browser()
    for _ in range(3):
        _start(browser, idp)
        assert _error_code(browser.get(CALLBACK, params={"code": "code-1", "state": "forged"})) == "state"
    assert "testclient" in app_module.LOCKED_OUT
    # Even a valid sign-in is refused while locked out, and not counted again.
    resp = _sign_in(browser, idp)
    assert _error_code(resp) == "denied"
    assert idp.calls["token"] == 0
    assert len(app_module.LOGIN_ATTEMPTS["testclient"]) == 3
    # Password login shares the same lockout.
    pw = _browser().post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert pw.status_code == 429


def test_success_resets_failures(env):
    _, idp = env
    browser = _browser()
    _start(browser, idp)
    browser.get(CALLBACK, params={"code": "code-1", "state": "forged"})
    assert app_module.LOGIN_ATTEMPTS.get("testclient")
    assert _sign_in(browser, idp).status_code == 303
    assert "testclient" not in app_module.LOGIN_ATTEMPTS


# ── accounts ─────────────────────────────────────────────────────────────────


def test_new_user_gets_default_groups(env, monkeypatch):
    admin, idp = env
    gid = _group(admin, "SSO default")
    monkeypatch.setitem(state.AUTH_CONFIG, "oidc", _oidc_cfg(default_group_ids=[gid, 9999]))
    assert _sign_in(_browser(), idp).status_code == 303
    user = _user("alice")
    assert asyncio.run(db_module.get_user_group_ids(int(user["id"]))) == [gid]


def test_admin_group_mapping_and_demotion(env):
    _, idp = env
    idp.claims = {"groups": ["netops", "plexus-admins"]}
    browser = _browser()
    assert _sign_in(browser, idp).status_code == 303
    assert browser.get("/api/auth/status").json()["role"] == "admin"
    # Removed from the admin group at the provider: demoted on next login.
    idp.claims = {"groups": "netops"}
    browser = _browser()
    assert _sign_in(browser, idp).status_code == 303
    assert browser.get("/api/auth/status").json()["role"] == "user"


def test_sync_groups(env, monkeypatch):
    admin, idp = env
    default = _group(admin, "SSO all")
    netops = _group(admin, "SSO netops")
    noc = _group(admin, "SSO noc")
    mappings = [{"group": "netops", "access_group_id": netops}, {"group": "noc", "access_group_id": noc}]
    monkeypatch.setitem(
        state.AUTH_CONFIG, "oidc", _oidc_cfg(default_group_ids=[default], sync_groups=True, group_mappings=mappings)
    )
    assert _sign_in(_browser(), idp).status_code == 303
    uid = int(_user("alice")["id"])
    assert asyncio.run(db_module.get_user_group_ids(uid)) == sorted([default, netops])
    idp.claims = {"groups": ["noc"]}
    assert _sign_in(_browser(), idp).status_code == 303
    assert asyncio.run(db_module.get_user_group_ids(uid)) == sorted([default, noc])
    # Overage: the groups are unknown, so membership and role stay.
    idp.claims = {"groups": None, "_claim_names": {"groups": "src1"}}
    del idp.discovery["userinfo_endpoint"]
    monkeypatch.setattr(oidc, "CLIENT", oidc.OidcClient(transport=idp.transport()))
    assert _sign_in(_browser(), idp).status_code == 303
    assert asyncio.run(db_module.get_user_group_ids(uid)) == sorted([default, noc])
    assert any("overage" in d for d in _audit_details("login.success"))


def test_without_sync_groups_existing_membership_is_kept(env, monkeypatch):
    admin, idp = env
    default = _group(admin, "SSO first")
    monkeypatch.setitem(state.AUTH_CONFIG, "oidc", _oidc_cfg(default_group_ids=[default]))
    assert _sign_in(_browser(), idp).status_code == 303
    uid = int(_user("alice")["id"])
    other = _group(admin, "SSO later")
    monkeypatch.setitem(state.AUTH_CONFIG, "oidc", _oidc_cfg(default_group_ids=[other]))
    assert _sign_in(_browser(), idp).status_code == 303
    assert asyncio.run(db_module.get_user_group_ids(uid)) == [default]


def test_overage_keeps_role_of_existing_user(env):
    _, idp = env
    idp.claims = {"groups": ["plexus-admins"]}
    assert _sign_in(_browser(), idp).status_code == 303
    idp.claims = {"groups": None, "hasgroups": True}
    idp.userinfo = {"sub": "subject-0001"}
    browser = _browser()
    assert _sign_in(browser, idp).status_code == 303
    assert browser.get("/api/auth/status").json()["role"] == "admin"


def test_sub_mismatch_is_refused(env):
    _, idp = env
    assert _sign_in(_browser(), idp).status_code == 303
    idp.claims = {"sub": "subject-9999"}
    browser = _browser()
    assert _error_code(_sign_in(browser, idp)) == "account"
    assert browser.get("/api/auth/status").json()["authenticated"] is False
    assert _user("alice")["external_id"] == "subject-0001"


def test_local_admin_name_collision_is_refused(env):
    _, idp = env
    idp.claims = {"preferred_username": "admin", "groups": ["netops"]}
    assert _error_code(_sign_in(_browser(), idp)) == "account"
    assert (_user("admin")["auth_provider"] or "") == ""
    # Overage cannot be used to slip past the guard either.
    idp.claims = {"preferred_username": "admin", "groups": None, "hasgroups": True}
    idp.userinfo = {"sub": "subject-0001"}
    assert _error_code(_sign_in(_browser(), idp)) == "account"


def test_bad_username_claim(env):
    _, idp = env
    idp.claims = {"preferred_username": "x" * 151}
    assert _error_code(_sign_in(_browser(), idp)) == "claims"


# ── status and admin config ──────────────────────────────────────────────────


def test_signed_out_status_offers_sso(env, monkeypatch):
    status = _browser().get("/api/auth/status").json()
    assert status["sso"]["oidc"] == {"enabled": True, "label": "Sign in with Example ID", "primary": False}
    monkeypatch.setitem(state.AUTH_CONFIG, "oidc", _oidc_cfg(enabled=False, primary=True))
    status = _browser().get("/api/auth/status").json()
    assert status["sso"]["oidc"]["enabled"] is False and status["sso"]["oidc"]["primary"] is True


def _config_body(admin: CsrfClient, **oidc_over) -> dict:
    body = admin.get(AUTH_CONFIG).json()
    body["oidc"].update(oidc_over)
    return body


def test_auth_config_secret_masking_round_trip(env):
    admin, _ = env
    shown = admin.get(AUTH_CONFIG).json()
    assert shown["oidc"]["client_secret"] == admin_module._SECRET_MASK
    assert "client_secret_enc" not in shown["oidc"]
    # Sending the mask back keeps the stored secret.
    resp = admin.put(AUTH_CONFIG, json=_config_body(admin, button_label="Corporate SSO"))
    assert resp.status_code == 200, resp.text
    assert resp.json()["oidc"]["client_secret"] == admin_module._SECRET_MASK
    from routes.crypto import decrypt

    assert decrypt(state.AUTH_CONFIG["oidc"]["client_secret_enc"]) == CLIENT_SECRET
    # A new secret is stored encrypted, never in clear.
    resp = admin.put(AUTH_CONFIG, json=_config_body(admin, client_secret="rotated-value"))
    assert resp.status_code == 200
    stored = asyncio.run(db_module.get_auth_setting("auth_config"))
    assert "rotated-value" not in str(stored)
    assert decrypt(stored["oidc"]["client_secret_enc"]) == "rotated-value"
    # Empty = public client.
    resp = admin.put(AUTH_CONFIG, json=_config_body(admin, client_secret=""))
    assert resp.json()["oidc"]["client_secret"] == ""
    assert state.AUTH_CONFIG["oidc"]["client_secret_enc"] == ""


def test_auth_config_without_oidc_keeps_it(env):
    admin, _ = env
    body = admin.get(AUTH_CONFIG).json()
    del body["oidc"]
    assert admin.put(AUTH_CONFIG, json=body).status_code == 200
    assert state.AUTH_CONFIG["oidc"]["issuer"] == ISSUER
    assert state.AUTH_CONFIG["oidc"]["client_secret_enc"]


@pytest.mark.parametrize(
    "over",
    [
        {"issuer": ""},
        {"issuer": "http://idp.example.com"},
        {"client_id": " "},
        {"redirect_uri": "http://plexus.example.com/cb"},
        {"button_label": "x" * 61},
        {"group_mappings": [{"group": f"g{i}", "access_group_id": 1} for i in range(201)]},
    ],
)
def test_auth_config_validation(env, over):
    admin, _ = env
    resp = admin.put(AUTH_CONFIG, json=_config_body(admin, enabled=True, **over))
    assert resp.status_code == 400, resp.text


def test_auth_config_saves_fields(env):
    admin, _ = env
    body = _config_body(
        admin,
        scopes="profile email groups",
        admin_groups=["plexus-admins", "plexus-admins", " ops "],
        default_role="bogus",
        token_auth_method="client_secret_post",
        sync_groups=True,
        group_mappings=[{"group": "netops", "access_group_id": 3}],
        primary=True,
        redirect_uri="https://plexus.example.com/api/auth/oidc/callback",
    )
    saved = admin.put(AUTH_CONFIG, json=body).json()["oidc"]
    assert saved["admin_groups"] == ["plexus-admins", "ops"]
    assert saved["default_role"] == "user"
    assert saved["token_auth_method"] == "client_secret_post"
    assert saved["group_mappings"] == [{"group": "netops", "access_group_id": 3}]
    assert saved["primary"] is True


def test_oidc_test_endpoint(env):
    admin, idp = env
    resp = admin.post(OIDC_TEST, json={})
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["ok"] is True and out["error"] == ""
    assert out["issuer"] == ISSUER and out["key_count"] == 2
    assert out["token_endpoint"] == f"{ISSUER}/token"
    assert out["algorithms"] == ["RS256", "PS256", "ES256"]
    assert out["redirect_uri"] == "http://testserver/api/auth/oidc/callback"
    # A different issuer given in the body is tried instead.
    out = admin.post(OIDC_TEST, json={"issuer": "https://other.example.com"}).json()
    assert out["ok"] is False and out["error"]
    idp.jwks = {"keys": []}
    out = admin.post(OIDC_TEST).json()
    assert out["ok"] is False and out["key_count"] == 0


def test_forwarded_proto_drives_the_redirect_uri(env):
    admin, _ = env
    out = admin.post(OIDC_TEST, json={}, headers={"X-Forwarded-Proto": "https"}).json()
    assert out["redirect_uri"] == "https://testserver/api/auth/oidc/callback"


def test_non_admin_cannot_reach_admin_endpoints(env):
    admin, idp = env
    plain = user_client(admin, "sso-plain-user")
    assert plain.get(AUTH_CONFIG).status_code == 403
    assert plain.put(AUTH_CONFIG, json={"provider": "local"}).status_code == 403
    assert plain.post(OIDC_TEST, json={}).status_code == 403
    # Nor can an SSO-provisioned non-admin.
    browser = _browser()
    assert _sign_in(browser, idp).status_code == 303
    csrf = browser.get("/api/auth/status").json()["csrf_token"]
    assert browser.post(OIDC_TEST, json={}, headers={"X-CSRF-Token": csrf}).status_code == 403
    assert idp.calls["discovery"] == 1
