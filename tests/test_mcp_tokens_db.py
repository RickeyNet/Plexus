"""MCP access tokens: the ``mcp_tokens`` table functions (``routes.db.mcp_tokens``)."""

from __future__ import annotations

import pytest
import routes.database as db


async def _owner(username: str = "ai-reader") -> int:
    return await db.create_user(username, "hash", "salt", role="user")


async def _token(owner: int, name: str = "report-bot", token_hash: str = "a" * 64) -> int:
    return await db.create_mcp_token(
        name=name,
        token_hash=token_hash,
        token_prefix="plx_mcp_abcd",
        owner_user_id=owner,
        categories=["inventory", "configs"],
        expires_at="",
        created_by="admin",
    )


async def test_create_and_lookup_by_hash():
    owner = await _owner()
    token_id = await _token(owner)
    row = await db.get_mcp_token_by_hash("a" * 64)
    assert row and row["id"] == token_id
    assert row["categories"] == ["inventory", "configs"]
    assert row["owner_user_id"] == owner
    assert row["revoked_at"] == "" and row["call_count"] == 0
    assert (await db.get_mcp_token(token_id))["name"] == "report-bot"
    assert await db.get_mcp_token_by_hash("b" * 64) is None


async def test_list_omits_hash():
    owner = await _owner()
    await _token(owner)
    rows = await db.list_mcp_tokens()
    assert len(rows) == 1
    assert "token_hash" not in rows[0]
    assert rows[0]["owner_username"] == "ai-reader"
    assert rows[0]["categories"] == ["inventory", "configs"]


async def test_duplicate_name_rejected():
    owner = await _owner()
    await _token(owner)
    with pytest.raises(ValueError):
        await _token(owner, token_hash="c" * 64)


async def test_revoke_sets_revoked_at_once():
    owner = await _owner()
    token_id = await _token(owner)
    assert await db.revoke_mcp_token(token_id) is True
    assert await db.revoke_mcp_token(token_id) is False
    assert await db.revoke_mcp_token(token_id + 100) is False
    rows = await db.list_mcp_tokens()
    assert len(rows) == 1 and rows[0]["revoked_at"] != ""


async def test_touch_increments():
    owner = await _owner()
    token_id = await _token(owner)
    await db.touch_mcp_token(token_id)
    await db.touch_mcp_token(token_id)
    row = await db.get_mcp_token(token_id)
    assert row["call_count"] == 2
    assert row["last_used_at"] != ""
