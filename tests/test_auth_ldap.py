"""LDAP provider tests: fallback matrix, role re-sync, and bind-flow guards.

Mirrors the RADIUS matrix in test_auth_radius.py, plus regression coverage for
the deep-review findings: directory role changes now re-sync on every login
(promotion AND demotion), ambiguous user searches fail closed, an empty
service-account password is refused (RFC 4513 unauthenticated bind), and the
custom group search merges with memberOf instead of being skipped by it.
"""

from __future__ import annotations

import netcontrol.app as app_module
import netcontrol.routes.auth as auth
import pytest
import routes.database as db_module

# ── authenticate_login_identity fallback matrix ──────────────────────────────


def _ldap_auth_config(**overrides):
    ldap = {
        "enabled": True,
        "fallback_to_local": True,
        "fallback_on_reject": False,
    }
    ldap.update(overrides)
    return {"provider": "ldap", "ldap": ldap, "radius": {"enabled": False}}


@pytest.mark.asyncio
async def test_ldap_accept(monkeypatch):
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _ldap_auth_config())

    async def fake_verify_ldap_user(username, password):
        return True, "accept", {"display_name": "LDAP User", "groups": []}

    async def fake_upsert_ldap_user(username, ldap_attrs):
        return {"id": 2, "username": username, "display_name": "LDAP User", "role": "user"}

    async def fake_verify_user(username, password):
        return None

    monkeypatch.setattr(app_module, "verify_ldap_user", fake_verify_ldap_user)
    monkeypatch.setattr(app_module, "upsert_ldap_user", fake_upsert_ldap_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("ldap-user", "pass")

    assert user is not None
    assert source == "ldap"
    assert error is None


@pytest.mark.asyncio
async def test_ldap_reject_no_fallback(monkeypatch):
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _ldap_auth_config())

    async def fake_verify_ldap_user(username, password):
        return False, "reject", {}

    async def fake_verify_user(username, password):
        return {"id": 3, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_ldap_user", fake_verify_ldap_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("user", "bad")

    assert user is None
    assert source is None
    assert error == "Invalid username or password"


@pytest.mark.asyncio
async def test_ldap_error_with_local_fallback(monkeypatch):
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _ldap_auth_config())

    async def fake_verify_ldap_user(username, password):
        return False, "error", {}

    async def fake_verify_user(username, password):
        return {"id": 4, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_ldap_user", fake_verify_ldap_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("fallback-user", "good")

    assert user is not None
    assert source == "local-fallback"
    assert error is None


@pytest.mark.asyncio
async def test_ldap_reject_with_override_fallback(monkeypatch):
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _ldap_auth_config(fallback_on_reject=True))

    async def fake_verify_ldap_user(username, password):
        return False, "reject", {}

    async def fake_verify_user(username, password):
        return {"id": 5, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_ldap_user", fake_verify_ldap_user)
    monkeypatch.setattr(app_module, "verify_user", fake_verify_user)

    user, source, error = await app_module.authenticate_login_identity("fallback-reject", "good")

    assert user is not None
    assert source == "local-fallback"
    assert error is None


# ── Role re-sync / provenance ────────────────────────────────────────────────


async def _fresh_db(tmp_path, monkeypatch, name):
    db_file = tmp_path / name
    monkeypatch.setattr(db_module, "DB_PATH", str(db_file))
    await db_module.init_db()


def _ldap_state_config(monkeypatch, **overrides):
    ldap = {
        "enabled": True,
        "server": "ldap.local",
        "admin_group_dn": "CN=Plexus Admins,OU=Groups,DC=corp,DC=local",
        "default_role": "user",
        "default_group_ids": [],
    }
    ldap.update(overrides)
    cfg = dict(app_module.state.AUTH_CONFIG_DEFAULTS)
    cfg["ldap"] = {**app_module.state.AUTH_CONFIG_DEFAULTS["ldap"], **ldap}
    monkeypatch.setattr(app_module.state, "AUTH_CONFIG", cfg)
    return cfg


_ADMIN_GROUPS = {"groups": ["CN=Plexus Admins,OU=Groups,DC=corp,DC=local"]}
_NO_GROUPS = {"groups": []}


@pytest.mark.asyncio
async def test_ldap_role_resyncs_on_every_login(tmp_path, monkeypatch):
    await _fresh_db(tmp_path, monkeypatch, "ldap_resync.db")
    _ldap_state_config(monkeypatch)

    user = await app_module.upsert_ldap_user("jdoe", _ADMIN_GROUPS)
    assert user["role"] == "admin"

    # Removed from the directory admin group -> demoted on next login.
    user = await app_module.upsert_ldap_user("jdoe", _NO_GROUPS)
    assert user["role"] == "user"

    # Re-added -> promoted again.
    user = await app_module.upsert_ldap_user("jdoe", _ADMIN_GROUPS)
    assert user["role"] == "admin"


@pytest.mark.asyncio
async def test_ldap_admin_group_dn_matches_spacing_and_case_variants(tmp_path, monkeypatch):
    await _fresh_db(tmp_path, monkeypatch, "ldap_dnnorm.db")
    _ldap_state_config(monkeypatch)

    attrs = {"groups": ["cn=plexus admins, ou=groups, dc=corp, dc=local"]}
    user = await app_module.upsert_ldap_user("jdoe", attrs)
    assert user["role"] == "admin"


@pytest.mark.asyncio
async def test_ldap_refuses_local_admin_collision(tmp_path, monkeypatch):
    await _fresh_db(tmp_path, monkeypatch, "ldap_collision.db")
    _ldap_state_config(monkeypatch)

    await db_module.create_user("admin", "hash", "salt", role="admin")

    # Directory account named like the local admin, without admin mapping.
    user = await app_module.upsert_ldap_user("admin", _NO_GROUPS)
    assert user is None
    # The local account is untouched.
    local = await db_module.get_user_by_username("admin")
    assert local["role"] == "admin"
    assert (local.get("auth_provider") or "") == ""


@pytest.mark.asyncio
async def test_ldap_claims_preexisting_shadow_user_then_resyncs(tmp_path, monkeypatch):
    await _fresh_db(tmp_path, monkeypatch, "ldap_claim.db")
    _ldap_state_config(monkeypatch)

    # Pre-provenance shadow account (created before the auth_provider column).
    await db_module.create_user("legacy", "hash", "salt", role="user")

    user = await app_module.upsert_ldap_user("legacy", _ADMIN_GROUPS)
    assert user["role"] == "admin"
    assert (await db_module.get_user_by_username("legacy"))["auth_provider"] == "ldap"


@pytest.mark.asyncio
async def test_ldap_display_name_refreshes(tmp_path, monkeypatch):
    await _fresh_db(tmp_path, monkeypatch, "ldap_dn_refresh.db")
    _ldap_state_config(monkeypatch)

    user = await app_module.upsert_ldap_user("jdoe", {"display_name": "Jo Doe", "groups": []})
    assert user["display_name"] == "Jo Doe"
    user = await app_module.upsert_ldap_user("jdoe", {"display_name": "Jo Doe-Smith", "groups": []})
    assert user["display_name"] == "Jo Doe-Smith"


@pytest.mark.asyncio
async def test_ldap_shadow_user_gets_default_access_groups(tmp_path, monkeypatch):
    await _fresh_db(tmp_path, monkeypatch, "ldap_groups.db")
    group_id = await db_module.create_access_group("LDAP Operators", "Default LDAP access", ["dashboard"])
    _ldap_state_config(monkeypatch, default_group_ids=[group_id])

    user = await app_module.upsert_ldap_user("ldap-user", _NO_GROUPS)

    assert user is not None
    assert await db_module.get_user_group_ids(user["id"]) == [group_id]


@pytest.mark.asyncio
async def test_radius_never_resyncs_role(tmp_path, monkeypatch):
    # RADIUS asserts no role, so a manual promotion in the Plexus UI must
    # survive subsequent RADIUS logins.
    await _fresh_db(tmp_path, monkeypatch, "radius_no_resync.db")
    cfg = app_module._sanitize_auth_config(
        {"provider": "radius", "radius": {"enabled": True, "server": "r.local", "secret": "s"}}
    )
    monkeypatch.setattr(app_module.state, "AUTH_CONFIG", cfg)

    user = await app_module.upsert_radius_user("ops")
    assert user["role"] == "user"
    await db_module.update_user_admin(int(user["id"]), role="admin")

    user = await app_module.upsert_radius_user("ops")
    assert user["role"] == "admin"


# ── Sanitizer ────────────────────────────────────────────────────────────────


def test_sanitize_ldap_tls_and_role_fields():
    cfg = app_module._sanitize_auth_config(
        {
            "provider": "ldap",
            "ldap": {
                "use_starttls": 1,
                "tls_verify": "Allow",
                "ca_cert_file": " /etc/ssl/corp-ca.pem ",
                "default_role": "Admin",
                "default_group_ids": [3, "4", -1, "bad"],
            },
        }
    )["ldap"]
    assert cfg["use_starttls"] is True
    assert cfg["tls_verify"] == "allow"
    assert cfg["ca_cert_file"] == "/etc/ssl/corp-ca.pem"
    assert cfg["default_role"] == "admin"
    assert cfg["default_group_ids"] == [3, 4]


def test_sanitize_ldap_rejects_bogus_tls_and_role_values():
    cfg = app_module._sanitize_auth_config(
        {"provider": "ldap", "ldap": {"tls_verify": "yolo", "default_role": "operator"}}
    )["ldap"]
    assert cfg["tls_verify"] == "demand"
    assert cfg["default_role"] == "user"


# ── DN / UPN helpers ─────────────────────────────────────────────────────────


def test_normalize_dn_spacing_case_and_escaped_commas():
    assert auth._normalize_dn("CN=Admins, OU=IT, DC=Corp, DC=Local") == "cn=admins,ou=it,dc=corp,dc=local"
    # An escaped comma inside a CN is not a component separator.
    assert auth._normalize_dn(r"CN=Doe\, Jane,OU=Users") == r"cn=doe\, jane,ou=users"


def test_upn_domain_from_base_dn():
    assert auth._upn_domain_from_base_dn("DC=corp,DC=local") == "corp.local"
    assert auth._upn_domain_from_base_dn("OU=Users, DC=corp, DC=example, DC=com") == "corp.example.com"
    assert auth._upn_domain_from_base_dn("OU=Users") == ""
    assert auth._upn_domain_from_base_dn("") == ""


# ── Sync bind flow (fake python_ldap) ────────────────────────────────────────


class FakeConn:
    def __init__(self, uri, module):
        self.uri = uri
        self.module = module
        self.options: dict = {}
        self.binds: list[tuple[str, str]] = []
        self.started_tls = False
        self.unbound = False
        self.protocol_version = None

    def set_option(self, key, value):
        self.options[key] = value

    def start_tls_s(self):
        self.started_tls = True

    def simple_bind_s(self, dn, password):
        self.binds.append((dn, password))
        if self.module.bind_hook:
            self.module.bind_hook(dn, password)

    def search_s(self, base, scope, flt, attrs=None):
        return self.module.search_hook(base, flt)

    def unbind_s(self):
        self.unbound = True


class FakeLdapModule:
    OPT_NETWORK_TIMEOUT = "network_timeout"
    OPT_TIMEOUT = "timeout"
    OPT_REFERRALS = "referrals"
    VERSION3 = 3
    OPT_X_TLS_NEVER = "tls_never"
    OPT_X_TLS_ALLOW = "tls_allow"
    OPT_X_TLS_TRY = "tls_try"
    OPT_X_TLS_DEMAND = "tls_demand"
    OPT_X_TLS_HARD = "tls_hard"
    OPT_X_TLS_REQUIRE_CERT = "tls_require_cert"
    OPT_X_TLS_CACERTFILE = "tls_cacertfile"
    OPT_X_TLS_NEWCTX = "tls_newctx"
    SCOPE_SUBTREE = 2

    class INVALID_CREDENTIALS(Exception):
        pass

    class SERVER_DOWN(Exception):
        pass

    class NO_SUCH_OBJECT(Exception):
        pass

    def __init__(self, search_hook=None, bind_hook=None):
        self.search_hook = search_hook or (lambda base, flt: [])
        self.bind_hook = bind_hook
        self.connections: list[FakeConn] = []

    def initialize(self, uri):
        conn = FakeConn(uri, self)
        self.connections.append(conn)
        return conn


def _install_fake_ldap(monkeypatch, fake):
    monkeypatch.setattr(auth, "LDAP_AVAILABLE", True)
    monkeypatch.setattr(auth, "python_ldap", fake)
    monkeypatch.setattr(auth, "_escape_filter_chars", lambda s: s)
    monkeypatch.setattr(auth, "_escape_dn_chars", lambda s: s)


_SEARCH_CFG = {
    "server": "dc1.corp.local",
    "port": 389,
    "bind_dn": "CN=svc,DC=corp,DC=local",
    "bind_password": "svc-pass",
    "base_dn": "DC=corp,DC=local",
    "user_search_filter": "(sAMAccountName={username})",
}


def _user_entry(dn="CN=jdoe,OU=Users,DC=corp,DC=local", groups=(b"CN=Team,DC=corp,DC=local",)):
    return (dn, {"displayName": [b"J Doe"], "mail": [b"jdoe@corp.local"], "memberOf": list(groups)})


def test_ambiguous_user_search_fails_closed(monkeypatch):
    fake = FakeLdapModule(search_hook=lambda base, flt: [_user_entry(), _user_entry("CN=jdoe2,OU=X,DC=corp,DC=local")])
    _install_fake_ldap(monkeypatch, fake)

    ok, status, attrs = auth._ldap_authenticate_sync("jdoe", "pw", dict(_SEARCH_CFG))

    assert (ok, status, attrs) == (False, "reject", {})
    # Only the service bind happened - the user's password never left Plexus.
    assert all(dn == _SEARCH_CFG["bind_dn"] for conn in fake.connections for dn, _ in conn.binds)


def test_empty_service_bind_password_is_refused(monkeypatch):
    fake = FakeLdapModule(search_hook=lambda base, flt: [_user_entry()])
    _install_fake_ldap(monkeypatch, fake)

    cfg = {**_SEARCH_CFG, "bind_password": ""}
    ok, status, attrs = auth._ldap_authenticate_sync("jdoe", "pw", cfg)

    assert (ok, status) == (False, "error")
    # No connection was even opened.
    assert fake.connections == []


def test_search_bind_happy_path_and_connection_cleanup(monkeypatch):
    fake = FakeLdapModule(search_hook=lambda base, flt: [_user_entry()])
    _install_fake_ldap(monkeypatch, fake)

    ok, status, attrs = auth._ldap_authenticate_sync("jdoe", "user-pass", dict(_SEARCH_CFG))

    assert (ok, status) == (True, "accept")
    assert attrs["display_name"] == "J Doe"
    assert attrs["groups"] == ["CN=Team,DC=corp,DC=local"]
    # Service conn + user conn, both released.
    assert len(fake.connections) == 2
    assert all(conn.unbound for conn in fake.connections)
    assert fake.connections[1].binds == [("CN=jdoe,OU=Users,DC=corp,DC=local", "user-pass")]


def test_group_search_merges_with_memberof(monkeypatch):
    def search_hook(base, flt):
        if base == "OU=Groups,DC=corp,DC=local":
            return [("CN=Nested Admins,OU=Groups,DC=corp,DC=local", {})]
        return [_user_entry()]

    fake = FakeLdapModule(search_hook=search_hook)
    _install_fake_ldap(monkeypatch, fake)

    cfg = {
        **_SEARCH_CFG,
        "group_search_base": "OU=Groups,DC=corp,DC=local",
        "group_search_filter": "(member:1.2.840.113556.1.4.1941:={user_dn})",
    }
    ok, status, attrs = auth._ldap_authenticate_sync("jdoe", "pw", cfg)

    assert (ok, status) == (True, "accept")
    # Direct memberOf groups AND the chased nested group are both present.
    assert attrs["groups"] == [
        "CN=Team,DC=corp,DC=local",
        "CN=Nested Admins,OU=Groups,DC=corp,DC=local",
    ]


def test_starttls_and_tls_options_applied(monkeypatch):
    fake = FakeLdapModule()
    _install_fake_ldap(monkeypatch, fake)

    cfg = {
        "server": "dc1.corp.local",
        "port": 389,
        "use_starttls": True,
        "tls_verify": "demand",
        "ca_cert_file": "/etc/ssl/corp-ca.pem",
        "user_dn_template": "CN={username},OU=Users,DC=corp,DC=local",
        "base_dn": "",
    }
    ok, status, _ = auth._ldap_authenticate_sync("jdoe", "pw", cfg)

    assert (ok, status) == (True, "accept")
    (conn,) = fake.connections
    assert conn.started_tls is True
    assert conn.uri == "ldap://dc1.corp.local:389"
    assert conn.options[FakeLdapModule.OPT_X_TLS_REQUIRE_CERT] == FakeLdapModule.OPT_X_TLS_DEMAND
    assert conn.options[FakeLdapModule.OPT_X_TLS_CACERTFILE] == "/etc/ssl/corp-ca.pem"
    assert FakeLdapModule.OPT_X_TLS_NEWCTX in conn.options


def test_upn_fallback_uses_dc_derived_domain(monkeypatch):
    fake = FakeLdapModule(search_hook=lambda base, flt: [])
    _install_fake_ldap(monkeypatch, fake)

    cfg = {"server": "dc1.corp.local", "port": 389, "base_dn": "OU=Users,DC=corp,DC=local"}
    ok, status, _ = auth._ldap_authenticate_sync("jdoe", "pw", cfg)

    assert (ok, status) == (True, "accept")
    assert fake.connections[0].binds[0][0] == "jdoe@corp.local"


def test_invalid_user_credentials_reject(monkeypatch):
    def bind_hook(dn, password):
        if dn != _SEARCH_CFG["bind_dn"]:
            raise FakeLdapModule.INVALID_CREDENTIALS()

    fake = FakeLdapModule(search_hook=lambda base, flt: [_user_entry()], bind_hook=bind_hook)
    _install_fake_ldap(monkeypatch, fake)

    ok, status, _ = auth._ldap_authenticate_sync("jdoe", "wrong", dict(_SEARCH_CFG))
    assert (ok, status) == (False, "reject")
