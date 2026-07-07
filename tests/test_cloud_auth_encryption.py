"""Regression tests for cloud account credential handling.

Two defects: (1) cloud account secrets (AWS secret keys, Azure client secrets,
GCP key material) were returned in full by GET /api/cloud/accounts, and
(2) they were stored as plaintext JSON at rest. The serializer now exposes only
``has_auth_config``; the DB layer encrypts at rest with the shared AES-256-GCM
key and transparently decrypts legacy plaintext rows.
"""

from __future__ import annotations

from netcontrol.routes.cloud_visibility import _serialize_account
from routes.db.cloud import (
    _cloud_auth_decrypt,
    _cloud_auth_encrypt,
    _looks_encrypted,
)


def test_serialize_account_hides_secrets():
    account = {
        "id": 1,
        "provider": "aws",
        "name": "prod",
        "auth_config_json": '{"secret_access_key": "AKIA-SUPER-SECRET"}',
    }
    out = _serialize_account(account)
    assert "auth_config" not in out
    assert "auth_config_json" not in out
    assert out["has_auth_config"] is True
    # The secret string must not appear anywhere in the serialized output.
    assert "AKIA-SUPER-SECRET" not in str(out)


def test_serialize_account_empty_config():
    out = _serialize_account({"id": 2, "provider": "gcp", "auth_config_json": "{}"})
    assert out["has_auth_config"] is False


def test_encrypt_roundtrip():
    cipher = _cloud_auth_encrypt({"secret_access_key": "s3cr3t"})
    assert cipher
    assert "s3cr3t" not in cipher  # not stored in the clear
    assert _looks_encrypted(cipher)
    assert '"secret_access_key":"s3cr3t"' in _cloud_auth_decrypt(cipher)


def test_empty_config_encrypts_to_empty():
    assert _cloud_auth_encrypt({}) == ""
    assert _cloud_auth_encrypt(None) == ""
    assert _cloud_auth_decrypt("") == "{}"


def test_legacy_plaintext_passes_through():
    """A row written before at-rest encryption stores plaintext JSON; it must
    still decode rather than raising, so existing accounts keep working."""
    legacy = '{"secret_access_key":"old-plaintext"}'
    assert not _looks_encrypted(legacy)
    assert _cloud_auth_decrypt(legacy) == legacy


def test_looks_encrypted_classification():
    assert not _looks_encrypted("")
    assert not _looks_encrypted("{}")
    assert not _looks_encrypted('{"a": 1}')
    assert not _looks_encrypted("[1,2,3]")
    assert _looks_encrypted(_cloud_auth_encrypt({"k": "v"}))
