"""The shared write-only secret helpers (``netcontrol.secret_fields``)."""

from __future__ import annotations

import pytest
from netcontrol.secret_fields import (
    SECRET_MASK,
    destination_changes,
    mask_secret_fields,
    merge_secret_fields,
    refuse_secret_reuse,
)

PATHS = ("community", "v3.auth_password", "v3.priv_password")


def test_mask_and_merge_round_trip():
    stored = {"community": "c1", "port": 161, "v3": {"username": "u", "auth_password": "a1", "priv_password": ""}}
    masked = mask_secret_fields(stored, PATHS)
    assert masked["community"] == SECRET_MASK and masked["v3"]["auth_password"] == SECRET_MASK
    assert masked["v3"]["priv_password"] == "" and masked["v3"]["username"] == "u"
    assert stored["community"] == "c1"  # the input is not changed

    assert merge_secret_fields(masked, stored, PATHS) == stored
    # Left out: kept. Explicit "": cleared. A new value: taken.
    merged = merge_secret_fields({"port": 162, "community": ""}, stored, PATHS)
    assert merged["community"] == "" and merged["v3"]["auth_password"] == "a1"
    assert merge_secret_fields({"community": "c2"}, stored, PATHS)["community"] == "c2"
    assert merge_secret_fields({"community": SECRET_MASK}, None, PATHS)["community"] == ""


def test_secret_reuse_needs_the_same_destination():
    old = {"url": "https://a.example.com", "verify_tls": True, "mount": "kv"}
    fields = ("url", "verify_tls")
    assert destination_changes(None, old, fields) == []
    assert destination_changes(old, {**old, "mount": "other"}, fields) == []
    assert destination_changes(old, {**old, "verify_tls": False}, fields) == ["verify_tls"]

    refuse_secret_reuse(old, {**old, "mount": "other"}, fields, stored=["token"], resent=[])
    refuse_secret_reuse(old, {**old, "url": "https://b.example.com"}, fields, stored=["token"], resent=["token"])
    refuse_secret_reuse(old, {**old, "url": "https://b.example.com"}, fields, stored=[], resent=[])
    with pytest.raises(ValueError, match="url changed, so the stored token cannot be reused"):
        refuse_secret_reuse(old, {**old, "url": "https://b.example.com"}, fields, stored=["token"], resent=[])
