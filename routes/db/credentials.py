"""Credentials persistence helpers.

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
    _is_unique_violation,
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "get_all_secret_variables",
    "get_secret_variable",
    "get_secret_variable_by_name",
    "create_secret_variable",
    "update_secret_variable",
    "delete_secret_variable",
    "get_all_credentials",
    "get_service_credentials",
    "get_credential_raw",
    "create_credential",
    "delete_credential",
    "update_credential",
]

# ═════════════════════════════════════════════════════════════════════════════
# Secret Variables (encrypted key-value store for template substitution)
# ═════════════════════════════════════════════════════════════════════════════


async def get_all_secret_variables() -> list[dict]:
    """Return all secret variables (without decrypted values)."""
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, name, description, created_by, created_at, updated_at FROM secret_variables ORDER BY name"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()


async def get_secret_variable(var_id: int) -> dict | None:
    """Return a single secret variable metadata (no decrypted value)."""
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, name, description, created_by, created_at, updated_at FROM secret_variables WHERE id = ?",
            (var_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await conn.close()


async def get_secret_variable_by_name(name: str) -> dict | None:
    """Return a secret variable including its encrypted value, looked up by name."""
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, name, enc_value, description, created_by FROM secret_variables WHERE name = ?",
            (name,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await conn.close()


async def create_secret_variable(
    name: str, enc_value: str, description: str = "", created_by: str = ""
) -> int:
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            "INSERT INTO secret_variables (name, enc_value, description, created_by) VALUES (?,?,?,?)",
            (name, enc_value, description, created_by),
        )
        await conn.commit()
        return cursor.lastrowid
    finally:
        await conn.close()


async def update_secret_variable(
    var_id: int,
    *,
    enc_value: str | None = None,
    description: str | None = None,
) -> bool:
    updates = []
    args = []
    if enc_value is not None:
        updates.append("enc_value = ?")
        args.append(enc_value)
    if description is not None:
        updates.append("description = ?")
        args.append(description)
    if not updates:
        return True
    if _dbcore.DB_ENGINE == "postgres":
        updates.append("updated_at = NOW()::text")
    else:
        updates.append("updated_at = datetime('now')")
    args.append(var_id)
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            f"UPDATE secret_variables SET {', '.join(updates)} WHERE id = ?",
            tuple(args),
        )
        await conn.commit()
        return cursor.rowcount > 0
    finally:
        await conn.close()


async def delete_secret_variable(var_id: int) -> bool:
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute("DELETE FROM secret_variables WHERE id = ?", (var_id,))
        await conn.commit()
        return cursor.rowcount > 0
    finally:
        await conn.close()


# ═════════════════════════════════════════════════════════════════════════════
# Credentials (encrypted externally before storage)
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_credentials(owner_id: int | None = None) -> list[dict]:
    """Return user credentials with passwords masked, excluding service creds.

    Service credentials (is_service=1) are administered separately via
    get_service_credentials() and are never returned by this function so
    they don't pollute the per-user credential picker.
    """
    db = await _dbcore.get_db()
    try:
        if owner_id is not None:
            cursor = await db.execute(
                "SELECT id, name, username, owner_id, is_service, created_at "
                "FROM credentials WHERE owner_id = ? AND is_service = 0 "
                "ORDER BY name",
                (owner_id,))
        else:
            cursor = await db.execute(
                "SELECT id, name, username, owner_id, is_service, created_at "
                "FROM credentials WHERE is_service = 0 ORDER BY name"
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_service_credentials() -> list[dict]:
    """Return service credentials with passwords masked.

    Service credentials are admin-administered and used by background work
    (monitoring polls, scheduled discovery) where there is no interactive
    user. owner_id is typically NULL but not enforced at the DB level.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, name, username, owner_id, is_service, created_at "
            "FROM credentials WHERE is_service = 1 ORDER BY name"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_credential_raw(cred_id: int) -> dict | None:
    """Return full credential including encrypted password/secret."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM credentials WHERE id = ?", (cred_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_credential(name: str, username: str, enc_password: str,
                            enc_secret: str = "", owner_id: int | None = None,
                            is_service: bool = False) -> int:
    """Insert a credential. Service credentials always have owner_id NULL."""
    if is_service:
        owner_id = None
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO credentials (name, username, password, secret, owner_id, is_service) "
            "VALUES (?,?,?,?,?,?)",
            (name, username, enc_password, enc_secret, owner_id, 1 if is_service else 0),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def delete_credential(cred_id: int):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        await db.commit()
    finally:
        await db.close()


async def update_credential(
    cred_id: int,
    *,
    name: str | None = None,
    username: str | None = None,
    enc_password: str | None = None,
    enc_secret: str | None = None,
):
    """Update credential fields. Omit or None means leave unchanged."""
    updates = []
    args = []
    if name is not None:
        updates.append("name = ?")
        args.append(name)
    if username is not None:
        updates.append("username = ?")
        args.append(username)
    if enc_password is not None:
        updates.append("password = ?")
        args.append(enc_password)
    if enc_secret is not None:
        updates.append("secret = ?")
        args.append(enc_secret)
    if not updates:
        return
    db = await _dbcore.get_db()
    try:
        sql, sql_params = _safe_dynamic_update("credentials", updates, args, "id = ?", cred_id)
        await db.execute(sql, sql_params)
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


