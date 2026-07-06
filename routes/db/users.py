"""Users persistence helpers.

Split out of routes/database.py; star re-exported there so the
``routes.database`` facade keeps its full public surface.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
from datetime import UTC, datetime, timedelta

import aiosqlite

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_foreign_key_violation,
    _is_unique_violation,
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "get_user_by_username",
    "get_user_by_id",
    "create_user",
    "update_user_password",
    "bump_user_session_epoch",
    "update_user_profile",
    "update_user_admin",
    "get_all_users",
    "delete_user",
    "get_user_group_ids",
    "set_user_groups",
    "get_all_access_groups",
    "get_access_group",
    "create_access_group",
    "update_access_group",
    "delete_access_group",
    "get_user_effective_features",
    "set_auth_setting",
    "get_auth_setting",
]

# ═════════════════════════════════════════════════════════════════════════════
# Users
# ═════════════════════════════════════════════════════════════════════════════

async def get_user_by_username(username: str) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM users WHERE username = ?", (username,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_user_by_id(user_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, username, display_name, role, must_change_password, session_never_expires, session_epoch, created_at FROM users WHERE id = ?",
            (user_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_user(username: str, password_hash: str, salt: str,
                      display_name: str = "", role: str = "user",
                      must_change_password: bool = False) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO users (username, password_hash, salt, display_name, role, must_change_password) VALUES (?,?,?,?,?,?)",
            (username, password_hash, salt, display_name, role, int(must_change_password)),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as e:
        await db.rollback()
        if _is_unique_violation(e):
            raise ValueError(f"Username '{username}' already exists.")
        raise
    finally:
        await db.close()


async def update_user_password(
    user_id: int,
    password_hash: str,
    salt: str,
    must_change_password: bool = False,
):
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE users SET password_hash = ?, salt = ?, must_change_password = ? WHERE id = ?",
            (password_hash, salt, int(bool(must_change_password)), user_id),
        )
        await db.commit()
    finally:
        await db.close()


async def bump_user_session_epoch(user_id: int) -> int:
    """Increment a user's session_epoch, invalidating all previously-issued
    session tokens for that user. Returns the new epoch (0 on failure)."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?",
            (user_id,),
        )
        await db.commit()
        cursor = await db.execute("SELECT session_epoch FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        return int(row[0]) if row else 0
    finally:
        await db.close()


async def update_user_profile(user_id: int, display_name: str = None):
    db = await _dbcore.get_db()
    try:
        if display_name is not None:
            await db.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id))
            await db.commit()
    finally:
        await db.close()


async def update_user_admin(user_id: int, username: str = None, display_name: str = None, role: str = None, session_never_expires: bool | None = None):
    db = await _dbcore.get_db()
    try:
        fields = []
        values = []
        if username is not None:
            fields.append("username = ?")
            values.append(username)
        if display_name is not None:
            fields.append("display_name = ?")
            values.append(display_name)
        if role is not None:
            fields.append("role = ?")
            values.append(role)
        if session_never_expires is not None:
            fields.append("session_never_expires = ?")
            values.append(int(bool(session_never_expires)))
        if not fields:
            return
        sql, params = _safe_dynamic_update("users", fields, values, "id = ?", user_id)
        await db.execute(sql, params)
        await db.commit()
    except Exception as e:
        await db.rollback()
        if _is_unique_violation(e):
            raise ValueError("Username already exists")
        raise
    finally:
        await db.close()


async def get_all_users() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, username, display_name, role, must_change_password, created_at FROM users ORDER BY username"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_user(user_id: int):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM credentials WHERE owner_id = ?", (user_id,))
        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def get_user_group_ids(user_id: int) -> list[int]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT group_id FROM user_group_memberships WHERE user_id = ? ORDER BY group_id",
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [int(r[0]) for r in rows]
    finally:
        await db.close()


async def set_user_groups(user_id: int, group_ids: list[int]):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM user_group_memberships WHERE user_id = ?", (user_id,))
        for gid in sorted(set(group_ids)):
            await db.execute(
                "INSERT INTO user_group_memberships (user_id, group_id) VALUES (?, ?)",
                (user_id, gid),
            )
        await db.commit()
    except Exception as e:
        await db.rollback()
        if _is_foreign_key_violation(e):
            raise ValueError("One or more selected groups do not exist")
        raise
    finally:
        await db.close()


async def get_all_access_groups() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """
            SELECT g.id, g.name, g.description, g.created_at, COUNT(m.user_id) AS member_count
            FROM access_groups g
            LEFT JOIN user_group_memberships m ON m.group_id = g.id
            GROUP BY g.id
            ORDER BY g.name
            """
        )
        groups = rows_to_list(await cursor.fetchall())

        for group in groups:
            fcur = await db.execute(
                "SELECT feature_key FROM access_group_features WHERE group_id = ? ORDER BY feature_key",
                (group["id"],),
            )
            group["feature_keys"] = [r[0] for r in await fcur.fetchall()]
        return groups
    finally:
        await db.close()


async def get_access_group(group_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, name, description, created_at FROM access_groups WHERE id = ?",
            (group_id,),
        )
        group = row_to_dict(await cursor.fetchone())
        if not group:
            return None

        fcur = await db.execute(
            "SELECT feature_key FROM access_group_features WHERE group_id = ? ORDER BY feature_key",
            (group_id,),
        )
        mcur = await db.execute(
            "SELECT COUNT(*) FROM user_group_memberships WHERE group_id = ?",
            (group_id,),
        )
        group["feature_keys"] = [r[0] for r in await fcur.fetchall()]
        group["member_count"] = int((await mcur.fetchone())[0])
        return group
    finally:
        await db.close()


async def create_access_group(name: str, description: str, feature_keys: list[str]) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO access_groups (name, description) VALUES (?, ?)",
            (name, description),
        )
        group_id = cursor.lastrowid
        for feature in sorted(set(feature_keys)):
            await db.execute(
                "INSERT INTO access_group_features (group_id, feature_key) VALUES (?, ?)",
                (group_id, feature),
            )
        await db.commit()
        return int(group_id)
    except Exception as e:
        await db.rollback()
        if _is_unique_violation(e):
            raise ValueError("Access group name already exists")
        raise
    finally:
        await db.close()


async def update_access_group(group_id: int, name: str, description: str, feature_keys: list[str]):
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE access_groups SET name = ?, description = ? WHERE id = ?",
            (name, description, group_id),
        )
        await db.execute("DELETE FROM access_group_features WHERE group_id = ?", (group_id,))
        for feature in sorted(set(feature_keys)):
            await db.execute(
                "INSERT INTO access_group_features (group_id, feature_key) VALUES (?, ?)",
                (group_id, feature),
            )
        await db.commit()
    except Exception as e:
        await db.rollback()
        if _is_unique_violation(e):
            raise ValueError("Access group name already exists")
        raise
    finally:
        await db.close()


async def delete_access_group(group_id: int):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM access_groups WHERE id = ?", (group_id,))
        await db.commit()
    finally:
        await db.close()


async def get_user_effective_features(user_id: int) -> list[str] | None:
    """Return the set of feature keys the user has via group memberships.

    Returns ``None`` if the user has **no** group memberships at all (so the
    caller can distinguish "unassigned" from "assigned but zero features").
    """
    db = await _dbcore.get_db()
    try:
        # First check whether the user has any group membership rows
        cursor = await db.execute(
            "SELECT COUNT(*) FROM user_group_memberships WHERE user_id = ?",
            (user_id,),
        )
        count = (await cursor.fetchone())[0]
        if count == 0:
            return None  # No memberships - caller decides default

        cursor = await db.execute(
            """
            SELECT DISTINCT f.feature_key
            FROM access_group_features f
            INNER JOIN user_group_memberships m ON m.group_id = f.group_id
            WHERE m.user_id = ?
            ORDER BY f.feature_key
            """,
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [r[0] for r in rows]
    finally:
        await db.close()


async def set_auth_setting(key: str, value: dict):
    db = await _dbcore.get_db()
    try:
        payload = json.dumps(value)
        await db.execute(
            """
            INSERT INTO auth_settings (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = datetime('now')
            """,
            (key, payload),
        )
        await db.commit()
    finally:
        await db.close()


async def get_auth_setting(key: str) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT value FROM auth_settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        if not row:
            return None
        return json.loads(row[0])
    finally:
        await db.close()


