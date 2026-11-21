"""Secrets inside ``auth_settings`` rows (SNMP communities and v3 keys,
SIEM tokens, notification secrets, RADIUS / TACACS+ / LDAP secrets) are
stored encrypted with routes.crypto and read back in plain text; rows saved
before that keep working and are re-saved encrypted once at startup."""

from __future__ import annotations

import json

import pytest
import routes.database as db
from netcontrol.secret_fields import (
    SEALED_KEY,
    has_plain_secret,
    map_secret_paths,
    open_secret_paths,
    seal_secret_paths,
)

SNMP = {
    "core": {"name": "core", "community": "comm-value-1", "v3": {"auth_password": "auth-value-1", "priv_password": ""}},
    "edge": {"name": "edge", "community": "", "v3": {"auth_password": "", "priv_password": "priv-value-2"}},
}
CHANNELS = {
    "channels": [
        {
            "id": "a",
            "type": "webhook",
            "webhook_url": "https://hooks.example.com/in",
            "webhook_auth_value": "hook-value",
        },
        {"id": "b", "type": "pagerduty", "routing_key": "routing-value"},
    ],
    "default_channel_ids": ["a"],
}
AUTH = {
    "provider": "radius",
    "radius": {"server": "192.0.2.50", "secret": "radius-value"},
    "tacacs": {"server": "", "secret": ""},
    "ldap": {"server": "ldap.example.com", "bind_password": "ldap-value"},
    "oidc": {"client_secret_enc": "already-ciphertext"},
}
PLAIN_VALUES = (
    "comm-value-1",
    "auth-value-1",
    "priv-value-2",
    "hook-value",
    "routing-value",
    "radius-value",
    "ldap-value",
)


async def _raw(key: str) -> str:
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute("SELECT value FROM auth_settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        return row[0] if row else ""
    finally:
        await conn.close()


async def _write_raw(key: str, value: dict) -> None:
    """A row as a release before the encryption stored it: plain JSON."""
    conn = await db.get_db()
    try:
        await conn.execute(
            "INSERT INTO auth_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )
        await conn.commit()
    finally:
        await conn.close()


def test_seal_and_open_round_trip_with_wildcards():
    paths = ("*.community", "*.v3.auth_password", "*.v3.priv_password", "*.missing.path")
    sealed = seal_secret_paths(SNMP, paths, lambda s: f"enc({s})")
    assert sealed["core"]["community"] == {SEALED_KEY: "enc(comm-value-1)"}
    assert sealed["core"]["v3"]["priv_password"] == ""  # empty stays empty
    assert sealed["core"]["name"] == "core" and SNMP["core"]["community"] == "comm-value-1"  # input untouched
    assert not has_plain_secret(sealed, paths) and has_plain_secret(SNMP, paths)
    assert open_secret_paths(sealed, paths, lambda s: s[4:-1]) == SNMP
    # Sealing twice does not wrap twice; a legacy plain value opens as itself.
    assert seal_secret_paths(sealed, paths, lambda s: "x") == sealed
    assert open_secret_paths(SNMP, paths, lambda s: "never") == SNMP
    # A value that no longer decrypts (key changed) is unusable, never the ciphertext.
    assert open_secret_paths(sealed, paths, lambda s: 1 / 0)["core"]["community"] == ""
    # Lists, and paths into values that are not objects, are walked safely.
    listed = map_secret_paths({"sinks": [{"bearer_token": "t"}, "junk"]}, ("sinks.*.bearer_token",), str.upper)
    assert listed == {"sinks": [{"bearer_token": "T"}, "junk"]}


@pytest.mark.asyncio
async def test_secrets_are_stored_encrypted_and_read_back_plain():
    await db.set_auth_setting("snmp_profiles", SNMP)
    await db.set_auth_setting("notification_channels", CHANNELS)
    await db.set_auth_setting("auth_config", AUTH)
    await db.set_auth_setting("siem_sinks", {"sinks": [{"id": "s", "bearer_token": "hec-value"}]})

    for key in ("snmp_profiles", "notification_channels", "auth_config", "siem_sinks"):
        raw = await _raw(key)
        assert SEALED_KEY in raw, key
        for value in (*PLAIN_VALUES, "hec-value"):
            assert value not in raw, (key, value)

    assert await db.get_auth_setting("snmp_profiles") == SNMP
    assert await db.get_auth_setting("notification_channels") == CHANNELS
    assert await db.get_auth_setting("auth_config") == AUTH
    assert (await db.get_auth_setting("siem_sinks"))["sinks"][0]["bearer_token"] == "hec-value"
    # A key without secrets is stored as it is.
    await db.set_auth_setting("login_rules", {"max_attempts": 5})
    assert json.loads(await _raw("login_rules")) == {"max_attempts": 5}


@pytest.mark.asyncio
async def test_legacy_plain_rows_are_read_then_stored_encrypted():
    await _write_raw("snmp_profiles", SNMP)
    await _write_raw("notification_channels", CHANNELS)
    await _write_raw("auth_config", AUTH)
    assert "comm-value-1" in await _raw("snmp_profiles")

    # Read as they are before the startup pass.
    assert await db.get_auth_setting("snmp_profiles") == SNMP
    assert await db.get_auth_setting("auth_config") == AUTH

    resaved = await db.encrypt_legacy_auth_settings()
    assert sorted(resaved) == ["auth_config", "notification_channels", "snmp_profiles"]
    for key in resaved:
        raw = await _raw(key)
        assert SEALED_KEY in raw and not any(value in raw for value in PLAIN_VALUES), key
    assert await db.get_auth_setting("snmp_profiles") == SNMP
    assert await db.get_auth_setting("notification_channels") == CHANNELS
    assert await db.get_auth_setting("auth_config") == AUTH

    # Nothing left to do on the next start.
    assert await db.encrypt_legacy_auth_settings() == []


@pytest.mark.asyncio
async def test_startup_encrypts_legacy_rows_and_the_api_stays_masked(monkeypatch, request):
    await _write_raw("notification_channels", CHANNELS)
    await _write_raw("auth_config", {**AUTH, "provider": "local"})

    from mcp_helpers import admin_client

    admin = admin_client(monkeypatch, request)  # runs the app lifespan
    assert "hook-value" not in await _raw("notification_channels")
    assert "radius-value" not in await _raw("auth_config")

    channels = admin.get("/api/admin/notification-channels").json()["channels"]
    assert {c["id"]: c.get("webhook_auth_value") or c.get("routing_key") for c in channels} == {
        "a": "••••••••",
        "b": "••••••••",
    }
    auth = admin.get("/api/admin/auth-config").json()
    assert auth["radius"]["secret"] == "••••••••" and auth["ldap"]["bind_password"] == "••••••••"
    assert "radius-value" not in json.dumps(auth)
