"""An SNMPv3 secret reference that cannot be resolved sends nothing.

``{{secret.NAME}}`` in an SNMPv3 authentication or privacy password is
resolved when a request is built. When that fails (the secret was deleted or
renamed, its provider did not answer, the name is not a valid one) the text
of the reference must not become the passphrase: no request is built, a
failed privacy reference does not turn the request into one without
privacy, and the caller reads why.

Every name and value below is invented test data.
"""

from __future__ import annotations

import netcontrol.routes.snmp as snmp_module
import pytest
import routes.secret_resolver as secret_resolver
from netcontrol.snmpv3_traps import trap_v3_credentials
from routes.secret_resolver import SecretResolutionError

HOST_IP = "192.0.2.61"
AUTH_REF = "{{secret.SNMP_AUTH}}"
PRIV_REF = "{{secret.SNMP_PRIV}}"
PLAIN = "invented-plain-passphrase"
REASON = "SNMPv3 secret reference not resolved"


def _config(auth: str, priv: str) -> dict:
    return {
        "enabled": True,
        "version": "3",
        "community": "invented-community",
        "v3": {"username": "snmp-user", "auth_password": auth, "priv_password": priv},
    }


@pytest.fixture
def missing_secrets(monkeypatch):
    """Every secret variable is missing."""

    async def resolve(lines, **_kwargs):
        raise SecretResolutionError(sorted(secret_resolver.extract_secret_names(lines)))

    monkeypatch.setattr(secret_resolver, "resolve_secrets", resolve)


@pytest.fixture
def no_requests(monkeypatch):
    """A request that reaches the transport fails the test."""

    async def refuse(*_args, **_kwargs):
        raise AssertionError("an SNMP request was built")

    monkeypatch.setattr(snmp_module, "snmp_transport_target", refuse)
    monkeypatch.setattr(snmp_module, "_engine_transport_target", refuse)


@pytest.mark.parametrize(
    ("auth", "priv"),
    [(AUTH_REF, PRIV_REF), (AUTH_REF, PLAIN), (PLAIN, PRIV_REF), (AUTH_REF, "")],
    ids=["both", "auth-only", "priv-only", "auth-no-priv"],
)
async def test_a_reference_that_fails_leaves_no_passphrase(missing_secrets, auth, priv):
    given = _config(auth, priv)

    resolved = await snmp_module._resolve_snmp_secrets(given)

    # Both are emptied: a plain authentication password with a failed privacy
    # reference would otherwise be sent without privacy.
    assert resolved["v3"]["auth_password"] == "" and resolved["v3"]["priv_password"] == ""
    assert resolved[snmp_module.SECRET_ERROR_KEY] == REASON
    assert resolved["v3"]["username"] == "snmp-user"
    # The stored configuration is not changed.
    assert given == _config(auth, priv)
    assert snmp_module._build_snmp_auth(resolved) is None
    assert trap_v3_credentials(resolved) is None


async def test_a_reference_the_resolver_leaves_in_place_is_not_a_passphrase():
    # Read as a reference, but not a name the resolver substitutes: it comes
    # back as written, with no error.
    odd = "{{secret.9starts-with-a-digit}}"
    assert secret_resolver.has_secret_references(odd)
    assert await secret_resolver.resolve_secrets([odd]) == [odd]

    resolved = await snmp_module._resolve_snmp_secrets(_config(odd, PLAIN))

    assert resolved["v3"]["auth_password"] == "" and resolved["v3"]["priv_password"] == ""
    assert resolved[snmp_module.SECRET_ERROR_KEY] == REASON


async def test_no_request_is_sent_and_the_caller_reads_why(missing_secrets, no_requests):
    cfg = _config(AUTH_REF, PRIV_REF)

    assert await snmp_module._snmp_walk(HOST_IP, 1.0, cfg, "1.3.6.1.2.1.1", return_errors=True) == ({}, REASON)
    assert await snmp_module._snmp_walk(HOST_IP, 1.0, cfg, "1.3.6.1.2.1.1") == {}
    assert await snmp_module._snmp_get_values(HOST_IP, 1.0, cfg, ("1.3.6.1.2.1.1.1.0",)) == ({}, REASON)
    # The identity probe does not fall back to the community either.
    assert await snmp_module._snmp_get(HOST_IP, 1.0, cfg) is None


async def test_a_config_resolved_once_keeps_the_reason(missing_secrets, no_requests):
    # The monitoring poll resolves once and passes the result to every walk.
    resolved = await snmp_module._resolve_snmp_secrets(_config(AUTH_REF, PRIV_REF))

    assert await snmp_module._snmp_walk(HOST_IP, 1.0, resolved, "1.3.6.1.2.1.1", return_errors=True) == ({}, REASON)


async def test_references_that_resolve_are_substituted(monkeypatch):
    values = {AUTH_REF: " invented-auth-value ", PRIV_REF: "invented-priv-value"}

    async def resolve(lines, **_kwargs):
        return [values[line] for line in lines]

    monkeypatch.setattr(secret_resolver, "resolve_secrets", resolve)

    resolved = await snmp_module._resolve_snmp_secrets(_config(AUTH_REF, PRIV_REF))

    assert resolved["v3"]["auth_password"] == "invented-auth-value"
    assert resolved["v3"]["priv_password"] == "invented-priv-value"
    assert snmp_module.SECRET_ERROR_KEY not in resolved
    assert snmp_module._build_snmp_auth(resolved) is not None


async def test_a_config_without_references_is_returned_as_given():
    plain = _config(PLAIN, "")
    assert await snmp_module._resolve_snmp_secrets(plain) is plain
    disabled = {"enabled": False, "version": "2c", "community": "invented-community"}
    assert await snmp_module._snmp_walk(HOST_IP, 1.0, disabled, "1.3.6.1.2.1.1", return_errors=True) == (
        {},
        "SNMP not configured",
    )
