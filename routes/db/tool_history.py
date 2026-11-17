"""Tool history persistence (migration 0107).

``tool_history`` holds the last runs each user made of a tool (Path Mode,
the Reachability sweep, Summarize), by ``kind``. A run is identified by its
``signature`` (built by the route); recording one that is already there
moves it to the top. Only the newest ``TOOL_HISTORY_LIMIT`` rows of a user
and kind are kept.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import routes.database as _dbcore
from routes.database import rows_to_list

__all__ = [
    "TOOL_HISTORY_LIMIT",
    "list_tool_history",
    "record_tool_history",
    "delete_tool_history",
    "clear_tool_history",
]

TOOL_HISTORY_LIMIT = 30


def _decode(row: dict) -> dict:
    data = row.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            data = {}
    return {
        "id": int(row["id"]),
        "data": data if isinstance(data, dict) else {},
        "used_at": row.get("used_at") or "",
    }


async def list_tool_history(user_id: int, kind: str) -> list[dict]:
    """The user's runs of ``kind``, newest first."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT id, data, used_at FROM tool_history WHERE user_id = ? AND kind = ? ORDER BY id DESC LIMIT ?",
            (int(user_id), kind, TOOL_HISTORY_LIMIT),
        )
        return [_decode(row) for row in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def record_tool_history(user_id: int, kind: str, signature: str, data: dict) -> dict:
    """Put a run at the top of the user's history of ``kind`` (replacing the
    same run further down) and drop what falls past the limit."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "DELETE FROM tool_history WHERE user_id = ? AND kind = ? AND signature = ?",
            (int(user_id), kind, signature),
        )
        cursor = await db.execute(
            "INSERT INTO tool_history (user_id, kind, signature, data, used_at) VALUES (?, ?, ?, ?, ?) RETURNING id",
            (int(user_id), kind, signature, json.dumps(data), now),
        )
        new_id = int(cursor.lastrowid)
        await db.execute(
            """DELETE FROM tool_history WHERE user_id = ? AND kind = ? AND id NOT IN (
                   SELECT id FROM tool_history WHERE user_id = ? AND kind = ? ORDER BY id DESC LIMIT ?)""",
            (int(user_id), kind, int(user_id), kind, TOOL_HISTORY_LIMIT),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
    return {"id": new_id, "data": data, "used_at": now}


async def delete_tool_history(user_id: int, kind: str, entry_id: int) -> bool:
    """Remove one of the user's runs; False when the user has no such entry."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM tool_history WHERE user_id = ? AND kind = ? AND id = ?",
            (int(user_id), kind, int(entry_id)),
        )
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def clear_tool_history(user_id: int, kind: str) -> int:
    """Remove every run of ``kind`` of the user; the number removed."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM tool_history WHERE user_id = ? AND kind = ?", (int(user_id), kind))
        await db.commit()
        return int(cursor.rowcount or 0)
    finally:
        await db.close()
