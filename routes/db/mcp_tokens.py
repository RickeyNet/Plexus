"""MCP access tokens for the read-only AI endpoint (``netcontrol.mcp``).

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table (migration 0082): ``mcp_tokens``. Only the SHA-256 of a token is
stored; ``list_mcp_tokens`` never returns it. A revoked token keeps its row
(``revoked_at`` set) so audit history still resolves its name.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import routes.database as _dbcore
from routes.database import _is_unique_violation, row_to_dict, rows_to_list

__all__ = [
    "create_mcp_token",
    "get_mcp_token",
    "get_mcp_token_by_hash",
    "list_mcp_tokens",
    "revoke_mcp_token",
    "touch_mcp_token",
]

_FMT = "%Y-%m-%d %H:%M:%S"


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def _row(row: dict | None) -> dict | None:
    if row is None:
        return None
    item = dict(row)
    try:
        categories = json.loads(item.get("categories") or "[]")
    except TypeError, ValueError:
        categories = []
    item["categories"] = [str(c) for c in categories] if isinstance(categories, list) else []
    return item


async def create_mcp_token(
    *,
    name: str,
    token_hash: str,
    token_prefix: str,
    owner_user_id: int,
    categories: list[str],
    expires_at: str,
    created_by: str,
) -> int:
    """Store a new token. Raises ``ValueError`` when the name is taken."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO mcp_tokens
                   (name, token_hash, token_prefix, owner_user_id, categories, expires_at, created_at, created_by)
               VALUES (?,?,?,?,?,?,?,?) RETURNING id""",
            (
                name,
                token_hash,
                token_prefix,
                int(owner_user_id),
                json.dumps(list(categories)),
                expires_at or "",
                _now(),
                created_by,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(f"A token named '{name}' already exists.") from exc
        raise
    finally:
        await db.close()


async def list_mcp_tokens() -> list[dict]:
    """Every token, newest first, with the owner's username and no hash."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT t.id, t.name, t.token_prefix, t.owner_user_id, t.categories, t.expires_at,
                      t.created_at, t.created_by, t.last_used_at, t.call_count, t.revoked_at,
                      COALESCE(u.username, '') AS owner_username,
                      COALESCE(u.role, '') AS owner_role
               FROM mcp_tokens t LEFT JOIN users u ON u.id = t.owner_user_id
               ORDER BY t.id DESC"""
        )
        return [r for r in (_row(r) for r in rows_to_list(await cursor.fetchall())) if r]
    finally:
        await db.close()


async def _get_one(where: str, value: object) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(f"SELECT * FROM mcp_tokens WHERE {where} = ?", (value,))  # nosec B608 - fixed column names
        return _row(row_to_dict(await cursor.fetchone()))
    finally:
        await db.close()


async def get_mcp_token_by_hash(token_hash: str) -> dict | None:
    return await _get_one("token_hash", token_hash)


async def get_mcp_token(token_id: int) -> dict | None:
    return await _get_one("id", int(token_id))


async def revoke_mcp_token(token_id: int) -> bool:
    """Revoke a token. ``False`` when it is missing or already revoked."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE mcp_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = ''",
            (_now(), int(token_id)),
        )
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def touch_mcp_token(token_id: int) -> None:
    """Record one use: ``last_used_at`` now, ``call_count`` plus one."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE mcp_tokens SET last_used_at = ?, call_count = call_count + 1 WHERE id = ?",
            (_now(), int(token_id)),
        )
        await db.commit()
    finally:
        await db.close()
