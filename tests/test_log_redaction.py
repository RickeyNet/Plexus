"""Log redaction (``netcontrol.telemetry``): the secret shapes it masks in
log lines, change log diffs and the syslog forwarder, the names that only
reference a secret and stay readable, and the shared definition of a secret
key name (``netcontrol.secret_keys``) it has with the MCP masking."""

from __future__ import annotations

import logging
import time

import pytest
from netcontrol import secret_keys
from netcontrol.mcp import redact as mcp_redact
from netcontrol.telemetry import RedactingFilter, redact_value


@pytest.mark.parametrize(
    ("line", "secret"),
    [
        ("login with password=hunter2 ok", "hunter2"),
        ("password: hunter2", "hunter2"),
        ('{"password": "hunter 2", "user": "bob"}', "hunter 2"),
        ("{'api_key': 'k-123'}", "k-123"),
        ("db_password = 'p@ss'", "p@ss"),
        ("password hunter2", "hunter2"),
        ("enable secret 5 $1$abcd$xyz", "$1$abcd$xyz"),
        ("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi"),
        ("sent header Basic dXNlcjpwYXNz to the proxy", "dXNlcjpwYXNz"),
        ("snmp-server community c0mmVal RO", "c0mmVal"),
        ("community: c0mmVal", "c0mmVal"),
        ("psk=pskVal1", "pskVal1"),
        ("passphrase: phraseVal", "phraseVal"),
        ("private_key: AAAAB3NzaC1", "AAAAB3NzaC1"),
        ("routing-key=rkVal", "rkVal"),
        ("credentials: credVal", "credVal"),
        ("GET /x?access_token=tokVal&page=2", "tokVal"),
        ('db_password="never closed', "never"),
    ],
)
def test_secret_shapes_are_masked(line, secret):
    out = redact_value(line)
    assert secret not in out
    assert "***" in out


@pytest.mark.parametrize(
    "line",
    [
        "token_count=5 credential_id: 7 community_list=CL1 secret_variables: 3",
        "has_password: true",
        "Login failed: password incorrect for bob",
        "password reset required",
        "secret variables are listed",
        "basic authentication failed",
        "missing bearer token",
        "no keyword at all in this line",
    ],
)
def test_words_that_only_name_a_secret_stay_readable(line):
    assert redact_value(line) == line


def test_quotes_are_kept_around_a_masked_value():
    assert redact_value('{"password": "x y"}') == '{"password": "***"}'
    assert redact_value("password='x'") == "password='***'"


def test_structured_values_mask_secrets_and_keep_references():
    value = {
        "community": "c0mm",
        "private_key": "k",
        "routing_key": "r",
        "psk": "p",
        "passphrase": "pp",
        "credentials": [{"user": "a", "pw": "b"}],
        "Authorization": "Bearer abc123",
        "credential_id": 7,
        "credentialId": 8,
        "token_count": 2,
        "community_list": "CL1",
        "secret_variables": 3,
        "credential_name": "lab-admin",
        "credential_source": "group",
        "secret_id": "approle-secret",
        "vaultSecretId": "approle-secret",
        "community_name": "c0mm",
        "community_lists": ["c0mm", "c1mm"],
        "secretVariables": {"db": "x"},
        "token_ids": {"before": 1, "after": 2},
        "has_password": True,
        "secret": None,
        "nested": [{"api-key": "x", "name": "n"}],
    }
    out = redact_value(value)
    for key in ("community", "private_key", "routing_key", "psk", "passphrase", "credentials", "Authorization"):
        assert out[key] == "***", key
    assert out["credential_id"] == 7 and out["credentialId"] == 8 and out["token_count"] == 2
    assert out["community_list"] == "CL1" and out["secret_variables"] == 3
    assert out["credential_name"] == "lab-admin" and out["credential_source"] == "group"
    # The Vault AppRole secret_id is a secret although it ends in "id", and
    # only a credential's name is a reference.
    for key in ("secret_id", "vaultSecretId", "community_name"):
        assert out[key] == "***", key
    # A list or mapping under a collection word is masked whole; a pair of
    # ids (an object change) still reads.
    assert out["community_lists"] == "***" and out["secretVariables"] == "***"
    assert out["token_ids"] == {"before": 1, "after": 2}
    assert out["has_password"] is True and out["secret"] is None
    assert out["nested"] == [{"api-key": "***", "name": "n"}]


def test_filter_redacts_a_secret_split_between_format_and_argument():
    record = logging.LogRecord(
        "plexus.test", logging.INFO, __file__, 1, "login password=%s user=%s", ("pw1", "bob"), None
    )
    assert RedactingFilter().filter(record) is True
    assert record.getMessage() == "login password=*** user=bob"
    structured = logging.LogRecord("plexus.test", logging.INFO, __file__, 1, "cfg %s", ({"psk": "p1"},), None)
    RedactingFilter().filter(structured)
    assert "p1" not in structured.getMessage()
    # A record that passes a second handler's filter is unchanged by it.
    RedactingFilter().filter(record)
    assert record.getMessage() == "login password=*** user=bob"


def test_long_lines_do_not_backtrack():
    lines = [
        'password="' * 50_000,
        "password " * 100_000,
        "a" * 1_000_000 + "password",
        "Bearer " + "a" * 1_000_000,
        'password="' + "x" * 1_000_000,
        ("password " + " " * 1000) * 1000,
        "basic " * 200_000,
        "community:" * 100_000,
    ]
    for line in lines:
        started = time.perf_counter()
        redact_value(line)
        assert time.perf_counter() - started < 5, line[:40]


def test_one_definition_of_a_secret_key_name():
    # The MCP masking uses the same names (plus the Meraki collector's).
    assert set(secret_keys.SECRET_KEY_FRAGMENTS) <= set(mcp_redact._DENY_KEY_FRAGMENTS)
    for key in (
        "community",
        "psk",
        "passphrase",
        "private_key",
        "routing_key",
        "credentials",
        "apiKey",
        "secret_id",
        "secretId",
        "community_name",
        "token_name",
    ):
        assert secret_keys.is_secret_key(key), key
    for key in (
        "credential_id",
        "token_count",
        "community_list",
        "secret_variables",
        "password_enabled",
        "credential_name",
        "credential_source",
    ):
        assert not secret_keys.is_secret_key(key), key
    assert secret_keys.should_mask("secret_variables", {"db": "x"})
    assert not secret_keys.should_mask("secret_variables", 2)
    assert not secret_keys.should_mask("password", True)
    assert not secret_keys.should_mask("password", "")
    assert mcp_redact.redact_value({"routing_key": "r", "credential_id": 4}) == {
        "routing_key": mcp_redact.MASK,
        "credential_id": 4,
    }
