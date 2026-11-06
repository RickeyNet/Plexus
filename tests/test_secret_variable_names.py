"""Secret variable name normalization and validation."""

import pytest
from fastapi import HTTPException
from netcontrol.routes.secret_variables import _validate_name
from routes.secret_resolver import normalize_secret_name


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("snmp_v3_auth_key", "snmp_v3_auth_key"),
        ("  snmp_v3_auth_key  ", "snmp_v3_auth_key"),
        ("{{secret.snmp_v3_auth_key}}", "snmp_v3_auth_key"),
        ("{{ secret.snmp_v3_auth_key }}", "snmp_v3_auth_key"),
        ("secret.snmp_v3_priv_key", "snmp_v3_priv_key"),
        ("my-secret", "my-secret"),
        ("", ""),
    ],
)
def test_normalize_secret_name(raw, expected):
    assert normalize_secret_name(raw) == expected


@pytest.mark.parametrize("raw", ["{{secret.snmp_v3_auth_key}}", "secret.snmp_v3_auth_key", "snmp_v3_auth_key"])
def test_validate_name_accepts_pasted_reference(raw):
    assert _validate_name(raw) == "snmp_v3_auth_key"


@pytest.mark.parametrize("raw", ["", "1abc", "my secret", "snmp.ro", "{{secret.}}", "a" * 65])
def test_validate_name_rejects_invalid(raw):
    with pytest.raises(HTTPException) as exc:
        _validate_name(raw)
    assert exc.value.status_code == 400
