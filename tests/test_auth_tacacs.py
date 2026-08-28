"""TACACS+ auth provider: wire adapter, role mapping, login flow, config plumbing.

The wire layer (``tacacs_plus``) is replaced with a scripted fake so the
tests pin Plexus' contract - what is sent, how PASS/FAIL/ERROR on each of
the two exchanges maps to accept/reject/error, and how ISE shell-profile
attributes become a Plexus role - without a live TACACS+ daemon.
"""

from __future__ import annotations

from types import SimpleNamespace

import netcontrol.app as app_module
import netcontrol.routes.admin as admin_module
import netcontrol.routes.auth as auth_module
import pytest
import routes.database as db_module

# ── Fake tacacs_plus client ──────────────────────────────────────────────────

_AUTHOR_PASS_ADD = 0x01
_AUTHOR_FAIL = 0x10
_AUTHOR_ERROR = 0x11


def _authen(valid=True, error=False):
    return SimpleNamespace(valid=valid, error=error, status=1 if valid else 2, arguments=[])


def _authz(status=_AUTHOR_PASS_ADD, arguments=None):
    return SimpleNamespace(
        valid=status in (0x01, 0x02),
        status=status,
        arguments=list(arguments or []),
    )


def _install_fake_client(monkeypatch, *, authen=None, authz=None, raise_on=None):
    """Patch ``auth_module.TACACSClient`` with a scripted stand-in.

    ``raise_on`` is ``"authenticate"`` / ``"authorize"`` to make that call
    raise ``OSError`` (socket-level failure).  Returns a recorder dict.
    """
    rec: dict = {"ctor": [], "authenticate": [], "authorize": []}

    class _FakeClient:
        def __init__(self, host, port, secret, timeout=10):
            rec["ctor"].append((host, port, secret, timeout))

        def authenticate(self, username, password, authen_type=None, **_):
            rec["authenticate"].append((username, password, authen_type))
            if raise_on == "authenticate":
                raise OSError("connection refused")
            return authen if authen is not None else _authen()

        def authorize(self, username, arguments=None, authen_type=None, **_):
            rec["authorize"].append((username, list(arguments or []), authen_type))
            if raise_on == "authorize":
                raise OSError("connection reset")
            return authz if authz is not None else _authz()

    monkeypatch.setattr(auth_module, "TACACSClient", _FakeClient)
    monkeypatch.setattr(auth_module, "TACACS_AVAILABLE", True)
    return rec


def _cfg(**overrides) -> dict:
    base = dict(app_module.state.AUTH_CONFIG_DEFAULTS["tacacs"])
    base.update({"enabled": True, "server": "ise.corp.local", "secret": "s3cret"})
    base.update(overrides)
    return base


# ── AV-pair parsing + role mapping (pure) ───────────────────────────────────


def test_parse_av_pairs_handles_mandatory_optional_bytes_and_junk() -> None:
    attrs = auth_module._parse_tacacs_av_pairs(
        [b"priv-lvl=15", b"plexus-role*admin", "Plexus-Role=user", b"noequals", b"=novalue", b""]
    )
    # Later duplicate (case-folded name) wins; junk is ignored.
    assert attrs == {"priv-lvl": "15", "plexus-role": "user"}


def test_role_attribute_beats_priv_lvl() -> None:
    role, priv = auth_module._tacacs_role_from_attrs({"priv-lvl": "15", "plexus-role": "user"}, _cfg())
    assert (role, priv) == ("user", 15)
    role, priv = auth_module._tacacs_role_from_attrs({"priv-lvl": "1", "plexus-role": "ADMIN"}, _cfg())
    assert (role, priv) == ("admin", 1)


def test_priv_lvl_threshold_maps_admin() -> None:
    assert auth_module._tacacs_role_from_attrs({"priv-lvl": "15"}, _cfg())[0] == "admin"
    assert auth_module._tacacs_role_from_attrs({"priv-lvl": "7"}, _cfg())[0] == "user"
    assert auth_module._tacacs_role_from_attrs({"priv-lvl": "7"}, _cfg(admin_priv_lvl=7))[0] == "admin"
    # 0 disables the priv-lvl rule entirely.
    assert auth_module._tacacs_role_from_attrs({"priv-lvl": "15"}, _cfg(admin_priv_lvl=0))[0] == "user"


def test_role_falls_back_to_default_and_tolerates_bad_priv() -> None:
    assert auth_module._tacacs_role_from_attrs({}, _cfg())[0] == "user"
    assert auth_module._tacacs_role_from_attrs({}, _cfg(default_role="admin"))[0] == "admin"
    assert auth_module._tacacs_role_from_attrs({"priv-lvl": "high"}, _cfg()) == ("user", None)
    # Unknown role value in the attribute is ignored, not trusted.
    assert auth_module._tacacs_role_from_attrs({"plexus-role": "superuser"}, _cfg())[0] == "user"


def test_custom_role_attribute_name() -> None:
    cfg = _cfg(role_attribute="Cisco-Plexus")
    assert auth_module._tacacs_role_from_attrs({"cisco-plexus": "admin"}, cfg)[0] == "admin"


# ── Wire adapter ─────────────────────────────────────────────────────────────


def test_authenticate_pass_then_authorize_pass_maps_role(monkeypatch) -> None:
    rec = _install_fake_client(monkeypatch, authz=_authz(arguments=[b"priv-lvl=15", b"plexus-role=admin"]))
    ok, status, attrs = auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg())
    assert (ok, status) == (True, "accept")
    assert attrs["role"] == "admin" and attrs["priv_lvl"] == 15
    assert attrs["attributes"] == {"priv-lvl": "15", "plexus-role": "admin"}
    # Exec authorization request every Cisco device sends at login, so an
    # unmodified ISE shell profile applies.
    assert rec["authorize"][0][1] == [b"service=shell", b"cmd="]
    # Default authen type is ASCII (interactive login flow).
    assert rec["authenticate"][0][2] == auth_module.TAC_PLUS_AUTHEN_TYPE_ASCII
    assert rec["ctor"][0] == ("ise.corp.local", 49, "s3cret", 5)


def test_pap_authen_type_and_custom_service(monkeypatch) -> None:
    rec = _install_fake_client(monkeypatch)
    ok, _, _ = auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg(authen_type="pap", service="plexus"))
    assert ok is True
    assert rec["authenticate"][0][2] == auth_module.TAC_PLUS_AUTHEN_TYPE_PAP
    assert rec["authorize"][0][1] == [b"service=plexus", b"cmd="]


def test_authentication_fail_is_reject_and_skips_authorize(monkeypatch) -> None:
    rec = _install_fake_client(monkeypatch, authen=_authen(valid=False))
    assert auth_module._tacacs_authenticate_sync("jdoe", "bad", _cfg()) == (False, "reject", {})
    assert rec["authorize"] == []


def test_authentication_error_status_is_error(monkeypatch) -> None:
    _install_fake_client(monkeypatch, authen=_authen(valid=False, error=True))
    assert auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg()) == (False, "error", {})


def test_authorization_fail_is_reject_not_default_role(monkeypatch) -> None:
    # Authenticated but ISE policy grants no shell profile -> reject.
    _install_fake_client(monkeypatch, authz=_authz(status=_AUTHOR_FAIL))
    assert auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg()) == (False, "reject", {})


def test_authorization_error_is_error(monkeypatch) -> None:
    _install_fake_client(monkeypatch, authz=_authz(status=_AUTHOR_ERROR))
    assert auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg()) == (False, "error", {})


def test_socket_errors_are_error(monkeypatch) -> None:
    _install_fake_client(monkeypatch, raise_on="authenticate")
    assert auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg()) == (False, "error", {})
    _install_fake_client(monkeypatch, raise_on="authorize")
    assert auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg()) == (False, "error", {})


def test_authorize_disabled_authenticates_only(monkeypatch) -> None:
    rec = _install_fake_client(monkeypatch)
    ok, status, attrs = auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg(authorize=False))
    assert (ok, status) == (True, "accept")
    assert attrs["role"] is None
    assert rec["authorize"] == []


def test_empty_password_never_hits_the_wire(monkeypatch) -> None:
    rec = _install_fake_client(monkeypatch)
    assert auth_module._tacacs_authenticate_sync("jdoe", "", _cfg()) == (False, "reject", {})
    assert rec["ctor"] == []


def test_missing_secret_or_server_is_error_not_cleartext(monkeypatch) -> None:
    rec = _install_fake_client(monkeypatch)
    assert auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg(secret=""))[1] == "error"
    assert auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg(server=""))[1] == "error"
    assert rec["ctor"] == [], "must not open a TACACS+ session without a secret"


def test_library_missing_is_error(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "TACACS_AVAILABLE", False)
    assert auth_module._tacacs_authenticate_sync("jdoe", "pw", _cfg()) == (False, "error", {})


# ── Login flow (provider branch + fallbacks) ─────────────────────────────────


def _login_cfg(**tacacs):
    t = {"enabled": True, "fallback_to_local": True, "fallback_on_reject": False}
    t.update(tacacs)
    return {"provider": "tacacs", "tacacs": t}


@pytest.mark.asyncio
async def test_login_identity_tacacs_accept(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _login_cfg())
    seen: dict = {}

    async def fake_verify(username, password):
        return True, "accept", {"role": "admin", "priv_lvl": 15, "attributes": {}}

    async def fake_upsert(username, attrs):
        seen["attrs"] = attrs
        return {"id": 2, "username": username, "display_name": username, "role": "admin"}

    async def fake_local(username, password):
        return None

    monkeypatch.setattr(app_module, "verify_tacacs_user", fake_verify)
    monkeypatch.setattr(app_module, "upsert_tacacs_user", fake_upsert)
    monkeypatch.setattr(app_module, "verify_user", fake_local)

    user, source, error = await app_module.authenticate_login_identity("jdoe", "pw")
    assert user is not None and user["username"] == "jdoe"
    assert (source, error) == ("tacacs", None)
    assert seen["attrs"]["role"] == "admin"


@pytest.mark.asyncio
async def test_login_identity_tacacs_reject_no_fallback(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _login_cfg())

    async def fake_verify(username, password):
        return False, "reject", {}

    async def fake_local(username, password):
        return {"id": 3, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_tacacs_user", fake_verify)
    monkeypatch.setattr(app_module, "verify_user", fake_local)

    assert await app_module.authenticate_login_identity("u", "bad") == (None, None, "Invalid username or password")


@pytest.mark.asyncio
async def test_login_identity_tacacs_error_with_local_fallback(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _login_cfg())

    async def fake_verify(username, password):
        return False, "error", {}

    async def fake_local(username, password):
        return {"id": 4, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_tacacs_user", fake_verify)
    monkeypatch.setattr(app_module, "verify_user", fake_local)

    user, source, error = await app_module.authenticate_login_identity("fb", "good")
    assert user is not None and (source, error) == ("local-fallback", None)


@pytest.mark.asyncio
async def test_login_identity_tacacs_error_without_fallback(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _login_cfg(fallback_to_local=False))

    async def fake_verify(username, password):
        return False, "error", {}

    async def fake_local(username, password):
        return {"id": 4, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_tacacs_user", fake_verify)
    monkeypatch.setattr(app_module, "verify_user", fake_local)

    user, source, error = await app_module.authenticate_login_identity("fb", "good")
    assert user is None and error == "TACACS+ authentication service unavailable"


@pytest.mark.asyncio
async def test_login_identity_tacacs_reject_with_override_fallback(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _login_cfg(fallback_on_reject=True))

    async def fake_verify(username, password):
        return False, "reject", {}

    async def fake_local(username, password):
        return {"id": 5, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_tacacs_user", fake_verify)
    monkeypatch.setattr(app_module, "verify_user", fake_local)

    user, source, _ = await app_module.authenticate_login_identity("fb", "good")
    assert user is not None and source == "local-fallback"


@pytest.mark.asyncio
async def test_login_identity_tacacs_disabled_falls_to_local(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "AUTH_CONFIG", _login_cfg(enabled=False))
    called = {"tacacs": False}

    async def fake_verify(username, password):
        called["tacacs"] = True
        return True, "accept", {}

    async def fake_local(username, password):
        return {"id": 6, "username": username, "display_name": username, "role": "user"}

    monkeypatch.setattr(app_module, "verify_tacacs_user", fake_verify)
    monkeypatch.setattr(app_module, "verify_user", fake_local)

    user, source, _ = await app_module.authenticate_login_identity("u", "pw")
    assert user is not None and source == "local"
    assert called["tacacs"] is False


# ── Shadow user + role sync ──────────────────────────────────────────────────


async def _fresh_db(tmp_path, monkeypatch, name):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / name))
    await db_module.init_db()


def _state_cfg(monkeypatch, **overrides):
    cfg = app_module._sanitize_auth_config({"provider": "tacacs", "tacacs": _cfg(**overrides)})
    monkeypatch.setattr(app_module.state, "AUTH_CONFIG", cfg)
    return cfg


@pytest.mark.asyncio
async def test_upsert_tacacs_role_resyncs_when_authorizing(tmp_path, monkeypatch) -> None:
    await _fresh_db(tmp_path, monkeypatch, "tacacs_resync.db")
    _state_cfg(monkeypatch)

    user = await app_module.upsert_tacacs_user("jdoe", {"role": "admin"})
    assert user["role"] == "admin"
    # Dropped from the ISE admin shell profile -> demoted on next login.
    user = await app_module.upsert_tacacs_user("jdoe", {"role": "user"})
    assert user["role"] == "user"
    user = await app_module.upsert_tacacs_user("jdoe", {"role": "admin"})
    assert user["role"] == "admin"


@pytest.mark.asyncio
async def test_upsert_tacacs_without_authorize_never_resyncs(tmp_path, monkeypatch) -> None:
    # Authenticate-only mode asserts no role: a local promotion sticks.
    await _fresh_db(tmp_path, monkeypatch, "tacacs_no_resync.db")
    _state_cfg(monkeypatch, authorize=False)

    user = await app_module.upsert_tacacs_user("ops", {"role": None})
    assert user["role"] == "user"
    await db_module.update_user_admin(int(user["id"]), role="admin")
    user = await app_module.upsert_tacacs_user("ops", {"role": None})
    assert user["role"] == "admin"


@pytest.mark.asyncio
async def test_upsert_tacacs_bogus_role_falls_back_to_default(tmp_path, monkeypatch) -> None:
    await _fresh_db(tmp_path, monkeypatch, "tacacs_default_role.db")
    _state_cfg(monkeypatch, default_role="user")
    user = await app_module.upsert_tacacs_user("x", {"role": "root"})
    assert user["role"] == "user"


@pytest.mark.asyncio
async def test_tacacs_shadow_user_gets_default_access_groups(tmp_path, monkeypatch) -> None:
    await _fresh_db(tmp_path, monkeypatch, "tacacs_groups.db")
    group_id = await db_module.create_access_group("TACACS Operators", "Default TACACS+ access", ["dashboard"])
    _state_cfg(monkeypatch, default_group_ids=[group_id])

    user = await app_module.upsert_tacacs_user("tac-user", {"role": "user"})
    assert user is not None
    assert await db_module.get_user_group_ids(user["id"]) == [group_id]


# ── Config sanitizer / admin API plumbing ────────────────────────────────────


def test_sanitize_tacacs_defaults_and_provider() -> None:
    cfg = app_module._sanitize_auth_config({"provider": "tacacs"})
    assert cfg["provider"] == "tacacs"
    t = cfg["tacacs"]
    assert t["port"] == 49 and t["authen_type"] == "ascii" and t["authorize"] is True
    assert t["service"] == "shell" and t["role_attribute"] == "plexus-role" and t["admin_priv_lvl"] == 15


def test_sanitize_tacacs_clamps_and_normalizes() -> None:
    cfg = app_module._sanitize_auth_config(
        {
            "provider": "tacacs",
            "tacacs": {
                "port": 70000,
                "timeout": 0,
                "authen_type": "CHAP",
                "service": "  ",
                "role_attribute": " Plexus-Role ",
                "admin_priv_lvl": 99,
                "default_role": "root",
                "default_group_ids": [2, "3", 0, "bad"],
            },
        }
    )
    t = cfg["tacacs"]
    assert t["port"] == 65535 and t["timeout"] == 1
    assert t["authen_type"] == "ascii"
    assert t["service"] == "shell"
    assert t["role_attribute"] == "plexus-role"
    assert t["admin_priv_lvl"] == 15
    assert t["default_role"] == "user"
    assert t["default_group_ids"] == [2, 3]
    assert (
        app_module._sanitize_auth_config({"provider": "tacacs", "tacacs": {"authen_type": "PAP"}})["tacacs"][
            "authen_type"
        ]
        == "pap"
    )


def test_admin_redacts_tacacs_secret() -> None:
    cfg = app_module._sanitize_auth_config({"provider": "tacacs", "tacacs": {"secret": "hunter2"}})
    red = admin_module._redact_auth_config(cfg)
    assert red["tacacs"]["secret"] == admin_module._SECRET_MASK
    assert cfg["tacacs"]["secret"] == "hunter2", "redaction must not mutate live config"


@pytest.mark.asyncio
async def test_admin_update_preserves_tacacs_secret_behind_mask(monkeypatch) -> None:
    live = app_module._sanitize_auth_config({"provider": "tacacs", "tacacs": {"secret": "hunter2"}})
    monkeypatch.setattr(admin_module.state, "AUTH_CONFIG", live)
    saved: dict = {}

    async def fake_set(key, value):
        saved[key] = value

    monkeypatch.setattr(admin_module.db, "set_auth_setting", fake_set)

    body = admin_module.AuthConfigRequest(
        provider="tacacs",
        tacacs=admin_module.TacacsConfigRequest(
            enabled=True, server="ise.corp.local", secret=admin_module._SECRET_MASK
        ),
    )
    out = await admin_module.admin_update_auth_config(body)
    assert saved["auth_config"]["tacacs"]["secret"] == "hunter2"
    assert out["tacacs"]["secret"] == admin_module._SECRET_MASK
    assert out["provider"] == "tacacs"


@pytest.mark.asyncio
async def test_admin_capabilities_advertise_tacacs() -> None:
    caps = await admin_module.admin_capabilities()
    assert "tacacs" in caps["auth_providers"]
