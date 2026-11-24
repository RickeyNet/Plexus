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


# ── One directory identity is one account, whatever the case typed ───────────

_PASSWORD_PROVIDERS = ["ldap", "radius", "tacacs"]


async def _usernames() -> list[str]:
    return sorted(u["username"] for u in await db_module.get_users_by_username_ci("heidi"))


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", _PASSWORD_PROVIDERS)
async def test_another_spelling_signs_into_the_same_account(monkeypatch, audits, provider):
    """Directories match a name without case; ``HEIDI`` used to become a
    second account next to ``heidi`` (default groups again, and a second
    name for four-eyes approval)."""
    _auth_config(monkeypatch)
    first = await _account("heidi", provider=provider)
    for spelling in ("HEIDI", "Heidi", " heidi "):
        user = await _sign_in(provider, spelling)
        assert user is not None and user["id"] == first["id"] and user["username"] == "heidi"
    assert await _usernames() == ["heidi"]
    assert audits == []


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", _PASSWORD_PROVIDERS)
async def test_another_spelling_gets_no_default_groups_again(monkeypatch, audits, provider):
    _auth_config(monkeypatch)
    await _account("heidi", provider=provider)
    assigned: list[int] = []

    async def record(user, group_ids, source):
        assigned.append(int(user["id"]))
        return user

    monkeypatch.setattr(auth, "_assign_default_groups", record)
    monkeypatch.setitem(app_module.state.AUTH_CONFIG[provider], "default_group_ids", [1])
    assert await _sign_in(provider, "HEIDI") is not None
    assert assigned == []


@pytest.mark.asyncio
async def test_exact_name_wins_when_spellings_already_exist(monkeypatch, audits):
    _auth_config(monkeypatch)
    lower = await _account("heidi", provider="ldap")
    upper = await _account("HEIDI", provider="ldap")
    assert (await _sign_in("ldap", "heidi"))["id"] == lower["id"]
    assert (await _sign_in("ldap", "HEIDI"))["id"] == upper["id"]
    # A third spelling cannot be tied to one of them: refused, not guessed.
    assert await _sign_in("ldap", "Heidi") is None
    assert any("several accounts differ only in case" in d for _c, _a, _u, d in audits)
    assert await _usernames() == ["HEIDI", "heidi"]


@pytest.mark.asyncio
async def test_another_providers_account_is_not_matched_by_case(monkeypatch, audits):
    """Only this provider's account is matched without case: a local
    ``heidi`` is not adopted by an LDAP ``HEIDI`` (it gets its own account,
    as an exact new name does)."""
    _auth_config(monkeypatch)
    local = await _account("heidi")
    user = await _sign_in("ldap", "HEIDI")
    assert user is not None and user["id"] != local["id"] and user["auth_provider"] == "ldap"
    assert ((await db_module.get_user_by_username("heidi"))["auth_provider"] or "") == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["oidc", "saml"])
async def test_sso_names_stay_exact(monkeypatch, audits, provider):
    # SSO accounts are bound to the IdP subject, not to a spelling.
    _auth_config(monkeypatch)
    first = await _account("heidi", provider=provider, external_id="subject-0001")
    user = await _sign_in(provider, "HEIDI", sub="subject-0002")
    assert user is not None and user["id"] != first["id"]
