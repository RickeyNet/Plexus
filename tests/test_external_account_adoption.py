"""External sign-ins may only sign in to accounts of their own provider.

An LDAP, RADIUS, TACACS+, OIDC or SAML identity used to adopt any existing
non-admin account with the same username: a local account, or one another
provider manages. Now an existing account is used only when its
``auth_provider`` is the signing-in provider (and, for OIDC/SAML, its bound
``external_id`` matches the subject). Anything else is refused with the
generic sign-in error and an ``auth`` / ``login.adopt_refused`` audit event.
"""

from __future__ import annotations

import netcontrol.app as app_module
import netcontrol.routes.auth as auth
import pytest
import routes.database as db_module
from netcontrol.sso import SsoIdentity

_SSO_CFG = {"admin_groups": [], "default_role": "user", "default_group_ids": [], "sync_groups": False}


@pytest.fixture
def audits(monkeypatch):
    events: list[tuple[str, str, str, str]] = []

    async def fake_audit(category, action, user="", detail="", correlation_id=""):
        events.append((category, action, user, detail))

    monkeypatch.setattr(auth, "_audit", fake_audit)
    return events


def _auth_config(monkeypatch, provider: str = "local"):
    cfg = app_module._sanitize_auth_config(
        {
            "provider": provider,
            "radius": {"enabled": True, "server": "radius.example.com", "secret": "s"},
            "tacacs": {"enabled": True, "server": "tacacs.example.com", "secret": "s", "authorize": False},
            "ldap": {"enabled": True, "server": "ldap.example.com"},
        }
    )
    monkeypatch.setattr(app_module.state, "AUTH_CONFIG", cfg)


async def _account(username: str, provider: str = "", external_id: str = "", role: str = "user") -> dict:
    await db_module.init_db()
    await db_module.create_user(username, "hash", "salt", role=role, auth_provider=provider)
    user = await db_module.get_user_by_username(username)
    if external_id:
        await db_module.set_user_external_id(int(user["id"]), external_id)
        user = await db_module.get_user_by_username(username)
    return user


async def _sign_in(provider: str, username: str, sub: str = "subject-0001") -> dict | None:
    if provider == "ldap":
        return await auth.upsert_ldap_user(username, {"display_name": username, "groups": []})
    if provider == "radius":
        return await auth.upsert_radius_user(username)
    if provider == "tacacs":
        return await auth.upsert_tacacs_user(username, {})
    user, _reason = await auth.upsert_sso_user(SsoIdentity(sub=sub, username=username), _SSO_CFG, provider)
    return user


_PROVIDERS = ["ldap", "radius", "tacacs", "oidc", "saml"]


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", _PROVIDERS)
async def test_a_local_account_is_never_adopted(monkeypatch, audits, provider):
    _auth_config(monkeypatch)
    before = await _account("bob")
    assert await _sign_in(provider, "bob") is None
    after = await db_module.get_user_by_username("bob")
    assert (after["auth_provider"] or "") == ""
    assert (after["external_id"] or "") == ""
    assert after["role"] == before["role"]
    assert ("auth", "login.adopt_refused") in [(c, a) for c, a, _u, _d in audits]
    detail = next(d for _c, a, _u, d in audits if a == "login.adopt_refused")
    assert f"source={provider}" in detail and "account=local" in detail


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", _PROVIDERS)
@pytest.mark.parametrize("owner", _PROVIDERS)
async def test_an_account_of_another_provider_is_never_adopted(monkeypatch, audits, provider, owner):
    if provider == owner:
        pytest.skip("same provider")
    _auth_config(monkeypatch)
    await _account("carol", provider=owner)
    assert await _sign_in(provider, "carol") is None
    assert (await db_module.get_user_by_username("carol"))["auth_provider"] == owner
    assert any(a == "login.adopt_refused" and f"account={owner}" in d for _c, a, _u, d in audits)


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", _PROVIDERS)
async def test_an_account_of_the_same_provider_signs_in(monkeypatch, audits, provider):
    _auth_config(monkeypatch)
    await _account("dave", provider=provider)
    user = await _sign_in(provider, "dave")
    assert user is not None and user["username"] == "dave"
    assert audits == []


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", _PROVIDERS)
async def test_a_new_username_is_provisioned(monkeypatch, audits, provider):
    _auth_config(monkeypatch)
    await db_module.init_db()
    assert await _sign_in(provider, "erin") is not None
    assert (await db_module.get_user_by_username("erin"))["auth_provider"] == provider


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["oidc", "saml"])
async def test_sso_account_bound_to_another_subject_is_refused(monkeypatch, audits, provider):
    _auth_config(monkeypatch)
    await _account("frank", provider=provider, external_id="subject-0001")
    assert await _sign_in(provider, "frank", sub="subject-0002") is None
    assert any(a == "login.adopt_refused" for _c, a, _u, _d in audits)
    assert await _sign_in(provider, "frank", sub="subject-0001") is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["oidc", "saml"])
async def test_sso_account_from_before_subject_binding_binds_on_first_sign_in(monkeypatch, audits, provider):
    # Rows created before users.external_id was filled keep working for
    # their own provider: the first sign-in binds the subject.
    _auth_config(monkeypatch)
    await _account("grace", provider=provider)
    assert await _sign_in(provider, "grace", sub="subject-0003") is not None
    assert (await db_module.get_user_by_username("grace"))["external_id"] == "subject-0003"


@pytest.mark.asyncio
async def test_an_admin_mapped_identity_cannot_adopt_a_local_admin(monkeypatch, audits):
    _auth_config(monkeypatch)
    await _account("root-admin", role="admin")
    attrs = {"groups": ["cn=plexus admins,ou=groups,dc=example,dc=com"]}
    monkeypatch.setitem(app_module.state.AUTH_CONFIG, "ldap", {"enabled": True, "admin_group_dn": attrs["groups"][0]})
    assert await auth.upsert_ldap_user("root-admin", attrs) is None
    assert (await db_module.get_user_by_username("root-admin"))["auth_provider"] == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["ldap", "radius", "tacacs"])
async def test_password_login_refusal_uses_the_generic_message(monkeypatch, audits, provider):
    _auth_config(monkeypatch, provider)
    monkeypatch.setattr(app_module, "AUTH_CONFIG", app_module.state.AUTH_CONFIG)
    monkeypatch.setenv("PLEXUS_BREAKGLASS_LOCAL_ADMIN", "false")
    await _account("henry")

    async def accept(username, password):
        return True, "accept"

    async def accept_attrs(username, password):
        return True, "accept", {}

    monkeypatch.setattr(app_module, "verify_radius_user", accept)
    monkeypatch.setattr(app_module, "verify_ldap_user", accept_attrs)
    monkeypatch.setattr(app_module, "verify_tacacs_user", accept_attrs)

    user, source, error = await auth.authenticate_login_identity("henry", "directory-password")
    assert user is None and source is None
    assert error == "Invalid username or password"
