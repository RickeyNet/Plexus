"""Transport defaults of the directory sign-in providers.

A new install requires the RADIUS Message-Authenticator and connects to LDAP
over LDAPS; a server that was set up before those defaults keeps what it had
across the upgrade. LDAP without TLS needs an explicit opt-in at save time.
Settings a client leaves out of a save keep their saved value, and the newer
LDAP, OIDC and SAML sign-in options reach the stored configuration. Every
name and address is invented.
"""

from __future__ import annotations

import copy

import netcontrol.routes.admin as admin_module
import netcontrol.routes.state as state
import pytest

from mcp_helpers import CsrfClient, admin_client

AUTH_CONFIG = "/api/admin/auth-config"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    client = admin_client(monkeypatch, request)
    # The route rebinds it; put the original back afterwards.
    monkeypatch.setattr(state, "AUTH_CONFIG", copy.deepcopy(state.AUTH_CONFIG))
    return client


def _loaded(stored: dict | None) -> dict:
    """What startup makes of a stored auth config."""
    return state._sanitize_auth_config(state._stored_auth_config(stored))


def _save(admin: CsrfClient, cfg: dict, **blocks):
    return admin.put(AUTH_CONFIG, json={**cfg, **blocks})


# ── defaults ─────────────────────────────────────────────────────────────────


def test_a_new_install_requires_message_authenticator_and_ldaps():
    cfg = _loaded(None)
    assert cfg["radius"]["enforce_message_authenticator"] is True
    ldap = cfg["ldap"]
    assert (ldap["use_ssl"], ldap["port"], ldap["allow_cleartext"]) == (True, 636, False)
    assert admin_module._sign_in_provider_warnings(cfg) == []


# ── a stored configuration across the upgrade ────────────────────────────────


def test_a_radius_server_set_up_earlier_keeps_its_setting():
    server = {"enabled": True, "server": "192.0.2.10", "secret": "invented-shared-secret"}
    # Saved before the setting existed: it was off.
    before = _loaded({"provider": "radius", "radius": server})
    assert before["radius"]["enforce_message_authenticator"] is False
    assert any("CVE-2024-3596" in w for w in admin_module._sign_in_provider_warnings(before))
    for chosen in (True, False):
        cfg = _loaded({"radius": {**server, "enforce_message_authenticator": chosen}})
        assert cfg["radius"]["enforce_message_authenticator"] is chosen


def test_a_radius_block_without_a_server_takes_the_new_default():
    never_used = {"enabled": False, "server": "", "enforce_message_authenticator": False}
    assert _loaded({"radius": never_used})["radius"]["enforce_message_authenticator"] is True


def test_an_ldap_server_saved_in_clear_text_keeps_working():
    plain = {"enabled": True, "server": "ldap.example.com", "port": 389, "use_ssl": False}
    cfg = _loaded({"provider": "ldap", "ldap": plain})
    ldap = cfg["ldap"]
    assert (ldap["use_ssl"], ldap["port"], ldap["allow_cleartext"]) == (False, 389, True)
    assert any("LDAP is enabled without TLS" in w for w in admin_module._sign_in_provider_warnings(cfg))
    # A block older than the SSL switch itself was clear text on 389.
    oldest = _loaded({"ldap": {"enabled": True, "server": "ldap.example.com"}})["ldap"]
    assert (oldest["use_ssl"], oldest["port"], oldest["allow_cleartext"]) == (False, 389, True)


def test_an_ldap_server_saved_with_tls_gets_no_clear_text_opt_in():
    for tls in ({"use_ssl": True, "port": 636}, {"use_ssl": False, "use_starttls": True, "port": 389}):
        ldap = _loaded({"ldap": {"enabled": True, "server": "ldap.example.com", **tls}})["ldap"]
        assert ldap["allow_cleartext"] is False
        assert (ldap["use_ssl"], ldap["port"]) == (tls["use_ssl"], tls["port"])
    # A refusal saved by this release stays a refusal.
    refused = {"enabled": False, "server": "ldap.example.com", "port": 389, "use_ssl": False, "allow_cleartext": False}
    assert _loaded({"ldap": refused})["ldap"]["allow_cleartext"] is False


def test_an_ldap_block_without_a_server_takes_the_new_defaults():
    never_used = {"enabled": False, "server": "", "port": 389, "use_ssl": False, "use_starttls": False}
    ldap = _loaded({"ldap": never_used})["ldap"]
    assert (ldap["use_ssl"], ldap["port"], ldap["allow_cleartext"]) == (True, 636, False)


def test_the_clear_text_opt_in_is_dropped_while_tls_is_on():
    for tls in ("use_ssl", "use_starttls"):
        ldap = state._sanitize_auth_config({"ldap": {"use_ssl": False, tls: True, "allow_cleartext": True}})["ldap"]
        assert ldap["allow_cleartext"] is False
    plain = state._sanitize_auth_config({"ldap": {"use_ssl": False, "allow_cleartext": True}})["ldap"]
    assert plain["allow_cleartext"] is True


# ── saving ───────────────────────────────────────────────────────────────────


def test_enabling_ldap_without_tls_needs_the_clear_text_opt_in(admin):
    cfg = admin.get(AUTH_CONFIG).json()
    plain = {
        **cfg["ldap"],
        "enabled": True,
        "server": "192.0.2.20",
        "port": 389,
        "use_ssl": False,
        "use_starttls": False,
        "allow_cleartext": False,
    }
    refused = _save(admin, cfg, ldap=plain)
    assert refused.status_code == 400 and "Allow clear text" in refused.text
    assert state.AUTH_CONFIG["ldap"]["enabled"] is False

    accepted = _save(admin, cfg, ldap={**plain, "allow_cleartext": True})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["ldap"]["allow_cleartext"] is True

    # Turning TLS on drops the opt-in, so turning it off again asks anew.
    with_tls = _save(admin, cfg, ldap={**accepted.json()["ldap"], "use_starttls": True})
    assert with_tls.status_code == 200, with_tls.text
    assert with_tls.json()["ldap"]["allow_cleartext"] is False
    assert _save(admin, cfg, ldap={**with_tls.json()["ldap"], "use_starttls": False}).status_code == 400

    # A disabled block is not refused: nothing connects with it.
    assert _save(admin, cfg, ldap={**plain, "enabled": False}).status_code == 200


def test_settings_a_client_leaves_out_keep_their_saved_value(admin):
    cfg = admin.get(AUTH_CONFIG).json()
    cfg["radius"] = {**cfg["radius"], "enforce_message_authenticator": False}
    cfg["ldap"] = {**cfg["ldap"], "port": 3269, "use_ssl": True, "username_attribute": "uid"}
    assert _save(admin, cfg).status_code == 200

    older = admin.get(AUTH_CONFIG).json()
    del older["radius"]["enforce_message_authenticator"]
    for key in ("port", "use_ssl", "allow_cleartext", "username_attribute"):
        del older["ldap"][key]
    saved = _save(admin, older)
    assert saved.status_code == 200, saved.text
    assert saved.json()["radius"]["enforce_message_authenticator"] is False
    ldap = saved.json()["ldap"]
    assert (ldap["port"], ldap["use_ssl"], ldap["username_attribute"]) == (3269, True, "uid")


def test_ldap_oidc_and_saml_sign_in_options_are_saved(admin):
    cfg = admin.get(AUTH_CONFIG).json()
    cfg["ldap"] = {**cfg["ldap"], "username_attribute": "sAMAccountName"}
    cfg["oidc"] = {**cfg["oidc"], "allow_unverified_email": True}
    cfg["saml"] = {**cfg["saml"], "subject_attribute": "employeeNumber", "required_authn_context": ["urn:example:mfa"]}
    saved = _save(admin, cfg)
    assert saved.status_code == 200, saved.text

    def options(body: dict) -> tuple:
        return (
            body["ldap"]["username_attribute"],
            body["oidc"]["allow_unverified_email"],
            body["saml"]["subject_attribute"],
            body["saml"]["required_authn_context"],
        )

    expected = ("sAMAccountName", True, "employeeNumber", ["urn:example:mfa"])
    assert options(saved.json()) == expected
    assert options(state.AUTH_CONFIG) == expected

    # A client that does not know them leaves them as they are.
    older = saved.json()
    del older["oidc"]["allow_unverified_email"]
    del older["saml"]["subject_attribute"], older["saml"]["required_authn_context"]
    again = _save(admin, older)
    assert again.status_code == 200, again.text
    assert options(again.json()) == expected

    # Sent empty, they are cleared.
    cleared = again.json()
    cleared["ldap"]["username_attribute"] = ""
    cleared["oidc"]["allow_unverified_email"] = False
    cleared["saml"].update({"subject_attribute": "", "required_authn_context": []})
    assert options(_save(admin, cleared).json()) == ("", False, "", [])


# ── RADIUS request ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(("setting", "enforced"), [({}, True), ({"enforce_message_authenticator": False}, False)])
def test_radius_request_enforces_message_authenticator_unless_turned_off(monkeypatch, setting, enforced):
    import netcontrol.routes.auth as auth

    seen: dict = {}

    def client(**kwargs):
        seen.update(kwargs)
        raise OSError("stop before any packet is built")

    monkeypatch.setattr(auth, "PYRAD_AVAILABLE", True)
    monkeypatch.setattr(auth, "RadiusClient", client)
    monkeypatch.setattr(auth, "RadiusDictionary", lambda path: path)
    monkeypatch.setattr(auth, "radius_packet", object())
    monkeypatch.setattr(auth, "_ensure_radius_dictionary_file", lambda: "dictionary")
    cfg = {"server": "192.0.2.10", "secret": "invented-shared-secret", **setting}

    assert auth._radius_authenticate_sync("jdoe", "pw", cfg) == (False, "error")
    assert seen["enforce_ma"] is enforced
