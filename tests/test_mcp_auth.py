"""MCP token authentication and settings (``netcontrol.mcp.auth`` / ``settings``)."""

from __future__ import annotations

import pytest
import routes.database as db
from netcontrol.mcp import auth, settings


async def _user(username: str = "ai-reader", role: str = "user") -> int:
    return await db.create_user(username, "hash", "salt", role=role)


async def _issue(
    owner: int, *, categories=("inventory", "configs"), expires_at: str = "", name: str = "bot"
) -> tuple[str, int]:
    plaintext, token_hash, prefix = auth.generate_token()
    token_id = await db.create_mcp_token(
        name=name,
        token_hash=token_hash,
        token_prefix=prefix,
        owner_user_id=owner,
        categories=list(categories),
        expires_at=expires_at,
        created_by="admin",
    )
    return plaintext, token_id


def test_generate_token_shape():
    plaintext, token_hash, prefix = auth.generate_token()
    other, _, _ = auth.generate_token()
    assert plaintext.startswith("plx_mcp_")
    assert auth.hash_token(plaintext) == token_hash
    assert len(token_hash) == 64
    assert prefix == plaintext[:12]
    assert plaintext != other


def test_extract_bearer_variants():
    assert auth.extract_bearer("Bearer x") == "x"
    assert auth.extract_bearer("bearer x") == "x"
    assert auth.extract_bearer("  Bearer   x  ") == "x"
    assert auth.extract_bearer("") == ""
    assert auth.extract_bearer("Basic x") == ""
    assert auth.extract_bearer("Bearer") == ""


async def test_resolve_valid_token():
    owner = await _user("net-admin", role="admin")
    plaintext, token_id = await _issue(owner)
    ctx = await auth.resolve_token(plaintext)
    assert ctx is not None
    assert ctx.token_id == token_id and ctx.token_name == "bot"
    assert ctx.owner_id == owner and ctx.owner_username == "net-admin"
    assert ctx.owner_is_admin is True
    assert ctx.categories == frozenset({"inventory", "configs"})
    assert "inventory" in ctx.features


@pytest.mark.parametrize("case", ["unknown", "wrong_prefix", "revoked", "expired", "owner_deleted", "empty"])
async def test_resolve_rejects(case):
    owner = await _user()
    expires = "2020-01-01" if case == "expired" else ""
    plaintext, token_id = await _issue(owner, expires_at=expires)
    if case == "unknown":
        plaintext = "plx_mcp_" + "z" * 43
    elif case == "wrong_prefix":
        plaintext = plaintext.removeprefix("plx_mcp_")
    elif case == "revoked":
        await db.revoke_mcp_token(token_id)
    elif case == "owner_deleted":
        await db.delete_user(owner)
    elif case == "empty":
        plaintext = ""
    assert await auth.resolve_token(plaintext) is None


async def test_future_expiry_is_accepted():
    owner = await _user()
    plaintext, _ = await _issue(owner, expires_at="2999-01-01")
    assert await auth.resolve_token(plaintext) is not None


async def test_feature_removed_narrows_immediately():
    owner = await _user()
    group = await db.create_access_group("readers", "", ["inventory"])
    await db.set_user_groups(owner, [group])
    plaintext, _ = await _issue(owner)
    ctx = await auth.resolve_token(plaintext)
    assert ctx is not None and ctx.owner_is_admin is False
    assert "inventory" in ctx.features
    await db.set_user_groups(owner, [])
    ctx = await auth.resolve_token(plaintext)
    assert ctx is not None
    assert "inventory" not in ctx.features


async def test_settings_defaults_and_bounds():
    assert await settings.load_settings() == settings.DEFAULTS
    assert settings.DEFAULTS == {
        "enabled": False,
        "max_result_bytes": 100_000,
        "max_rows": 200,
        "calls_per_minute": 120,
    }
    with pytest.raises(ValueError):
        await settings.save_settings({"max_rows": 5})
    with pytest.raises(ValueError):
        await settings.save_settings({"calls_per_minute": "fast"})
    with pytest.raises(ValueError):
        await settings.save_settings({"no_such_key": 1})
    merged = await settings.save_settings({"enabled": True, "max_rows": 50})
    assert merged == {**settings.DEFAULTS, "enabled": True, "max_rows": 50}
    assert await settings.load_settings() == merged
