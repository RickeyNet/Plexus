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

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)
from routes.db.change_events import tracks_changes

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


# The external reference of a credential or secret variable (migration
# 0106) with the provider's name; never a value.
_SECRET_VARIABLE_COLUMNS = (
    "v.id, v.name, v.description, v.created_by, v.created_at, v.updated_at, "
    "v.ext_provider_id, v.ext_path, v.ext_key, p.name AS ext_provider_name"
)
_SECRET_VARIABLE_FROM = "secret_variables v LEFT JOIN secrets_providers p ON p.id = v.ext_provider_id"


async def get_all_secret_variables() -> list[dict]:
    """Return all secret variables (without decrypted values)."""
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            f"SELECT {_SECRET_VARIABLE_COLUMNS} FROM {_SECRET_VARIABLE_FROM} ORDER BY v.name"  # nosec B608 - fixed column lists
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await conn.close()


async def get_secret_variable(var_id: int) -> dict | None:
    """Return a single secret variable metadata (no decrypted value)."""
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            f"SELECT {_SECRET_VARIABLE_COLUMNS} FROM {_SECRET_VARIABLE_FROM} WHERE v.id = ?",  # nosec B608 - fixed column lists
            (var_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await conn.close()


async def get_secret_variable_by_name(name: str) -> dict | None:
    """Return a secret variable including its encrypted value (or external
    reference), looked up by name. Read its value with
    ``netcontrol.secrets_providers.service.secret_variable_plaintext``."""
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            "SELECT id, name, enc_value, description, created_by, ext_provider_id, ext_path, ext_key "
            "FROM secret_variables WHERE name = ?",
            (name,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await conn.close()


async def create_secret_variable(
    name: str,
    enc_value: str,
    description: str = "",
    created_by: str = "",
    *,
    external: dict | None = None,
) -> int:
    """Insert a secret variable. ``external`` (``provider_id``, ``path``,
    ``key``) stores a reference instead of ``enc_value`` (then ``''``)."""
    ext = _external_columns(external)
    conn = await _dbcore.get_db()
    try:
        cursor = await conn.execute(
            "INSERT INTO secret_variables (name, enc_value, description, created_by, ext_provider_id, ext_path, "
            "ext_key) VALUES (?,?,?,?,?,?,?)",
            (name, "" if external else enc_value, description, created_by, *ext[:3]),
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
    external: dict | None = None,
) -> bool:
    """Update a secret variable. ``external`` sets a reference (and clears
    the stored value); a new ``enc_value`` clears the reference."""
    updates = []
    args: list = []
    if external is not None:
        updates += ["enc_value = ?", "ext_provider_id = ?", "ext_path = ?", "ext_key = ?"]
        args += ["", *_external_columns(external)[:3]]
    elif enc_value is not None:
        updates += ["enc_value = ?", "ext_provider_id = ?", "ext_path = ?", "ext_key = ?"]
        args += [enc_value, None, "", ""]
    if description is not None:
        updates.append("description = ?")
        args.append(description)
    if not updates:
        return True
    updates.append("updated_at = NOW()::text")
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


_CREDENTIAL_COLUMNS = (
    "c.id, c.name, c.username, c.owner_id, c.is_service, c.created_at, "
    "c.ext_provider_id, c.ext_path, c.ext_key, c.ext_secret_key, p.name AS ext_provider_name"
)
_CREDENTIAL_FROM = "credentials c LEFT JOIN secrets_providers p ON p.id = c.ext_provider_id"


def _external_columns(external: dict | None) -> tuple:
    """``(ext_provider_id, ext_path, ext_key, ext_secret_key)`` for a
    reference, or the empty columns for none."""
    if not external:
        return (None, "", "", "")
    return (
        int(external["provider_id"]),
        str(external.get("path") or ""),
        str(external.get("key") or ""),
        str(external.get("secret_key") or ""),
    )


async def get_all_credentials(owner_id: int | None = None) -> list[dict]:
    """Return user credentials with passwords masked, excluding service creds.

    Service credentials (is_service=1) are administered separately via
    get_service_credentials() and are never returned by this function so
    they don't pollute the per-user credential picker.
    """
    db = await _dbcore.get_db(read_only=True)
    try:
        if owner_id is not None:
            cursor = await db.execute(
                f"SELECT {_CREDENTIAL_COLUMNS} FROM {_CREDENTIAL_FROM} "  # nosec B608 - fixed column lists
                "WHERE c.owner_id = ? AND c.is_service = 0 ORDER BY c.name",
                (owner_id,),
            )
        else:
            cursor = await db.execute(
                f"SELECT {_CREDENTIAL_COLUMNS} FROM {_CREDENTIAL_FROM} WHERE c.is_service = 0 ORDER BY c.name"  # nosec B608 - fixed column lists
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
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT {_CREDENTIAL_COLUMNS} FROM {_CREDENTIAL_FROM} WHERE c.is_service = 1 ORDER BY c.name"  # nosec B608 - fixed column lists
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_credential_raw(cred_id: int, *, resolve_external: bool = True) -> dict | None:
    """Return full credential including encrypted password/secret.

    A credential with an external reference (migration 0106) comes back
    with ``password``/``secret`` encrypted from the provider's values, so
    every consumer that decrypts them gets the external secret
    (``netcontrol.secrets_providers.service.materialize_credential``).
    ``resolve_external=False`` returns the stored row untouched, for
    callers that only check ownership or edit the record."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM credentials WHERE id = ?", (cred_id,))
        row = row_to_dict(await cursor.fetchone())
    finally:
        await db.close()
    if row and resolve_external and row.get("ext_provider_id"):
        from netcontrol.secrets_providers.service import materialize_credential

        row = await materialize_credential(row)
    return row


@tracks_changes("credential", "create")
async def create_credential(
    name: str,
    username: str,
    enc_password: str,
    enc_secret: str = "",
    owner_id: int | None = None,
    is_service: bool = False,
    external: dict | None = None,
) -> int:
    """Insert a credential. Service credentials always have owner_id NULL.
    ``external`` (``provider_id``, ``path``, ``key``, ``secret_key``) stores
    a reference instead of the password and secret (then ``''``)."""
    if is_service:
        owner_id = None
    if external:
        enc_password = enc_secret = ""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO credentials (name, username, password, secret, owner_id, is_service, ext_provider_id, "
            "ext_path, ext_key, ext_secret_key) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                name,
                username,
                enc_password,
                enc_secret,
                owner_id,
                1 if is_service else 0,
                *_external_columns(external),
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


@tracks_changes("credential", "delete", id_arg="cred_id")
async def delete_credential(cred_id: int):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        await db.commit()
    finally:
        await db.close()


@tracks_changes("credential", "update", id_arg="cred_id")
async def update_credential(
    cred_id: int,
    *,
    name: str | None = None,
    username: str | None = None,
    enc_password: str | None = None,
    enc_secret: str | None = None,
    external: dict | None = None,
    clear_external: bool = False,
):
    """Update credential fields. Omit or None means leave unchanged.

    ``external`` sets a reference and empties the stored password and
    secret; ``clear_external`` drops the reference (the caller then passes
    the new stored values)."""
    updates = []
    args: list = []
    if external is not None:
        enc_password = enc_secret = ""
        updates += ["ext_provider_id = ?", "ext_path = ?", "ext_key = ?", "ext_secret_key = ?"]
        args += list(_external_columns(external))
    elif clear_external:
        updates += ["ext_provider_id = ?", "ext_path = ?", "ext_key = ?", "ext_secret_key = ?"]
        args += list(_external_columns(None))
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
