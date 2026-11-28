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

from netcontrol.authz_cache import invalidates
from netcontrol.secret_fields import (
    NOTIFICATION_CHANNEL_SECRET_FIELDS,
    SIEM_SINK_SECRET_FIELDS,
    SNMP_SECRET_FIELDS,
    SYSLOG_TLS_SECRET_FIELDS,
    has_plain_secret,
    open_secret_paths,
    seal_secret_paths,
)

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_foreign_key_violation,
    _is_unique_violation,
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)
from routes.db.inventory import group_subtrees_sql

__all__ = [
    "get_user_by_username",
    "get_users_by_username_ci",
    "get_user_by_id",
    "create_user",
    "update_user_password",
    "bump_user_session_epoch",
    "update_user_profile",
    "update_user_admin",
    "set_user_auth_provider",
    "set_user_external_id",
    "get_users_by_external_id",
    "get_all_users",
    "delete_user",
    "delete_user_guarded",
    "get_user_group_ids",
    "set_user_groups",
    "get_all_access_groups",
    "get_access_group",
    "create_access_group",
    "update_access_group",
    "delete_access_group",
    "OBJECT_SCOPES",
    "get_user_object_scope",
    "get_user_effective_features",
    "set_auth_setting",
    "get_auth_setting",
    "AUTH_SETTING_SECRET_PATHS",
    "encrypt_legacy_auth_settings",
]

# ═════════════════════════════════════════════════════════════════════════════
# Users
# ═════════════════════════════════════════════════════════════════════════════


async def get_user_by_username(username: str) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM users WHERE username = ?", (username,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_users_by_username_ci(username: str) -> list[dict]:
    """Every account whose username equals ``username`` when case is
    ignored. Usernames are unique by exact text only, so there can be
    more than one."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?) ORDER BY id", (username,))
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_user_by_id(user_id: int) -> dict | None:
    # Runs on every authenticated request (auth dependencies); read-only.
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT id, username, display_name, role, must_change_password, session_never_expires, session_epoch, created_at, auth_provider, disabled FROM users WHERE id = ?",
            (user_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


# Every writer of users, user_group_memberships and the access_group* tables
# carries @invalidates: the auth path caches what they change
# (netcontrol.authz_cache).
@invalidates
async def create_user(
    username: str,
    password_hash: str,
    salt: str,
    display_name: str = "",
    role: str = "user",
    must_change_password: bool = False,
    auth_provider: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO users (username, password_hash, salt, display_name, role, must_change_password, auth_provider) VALUES (?,?,?,?,?,?,?)",
            (username, password_hash, salt, display_name, role, int(must_change_password), auth_provider),
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


@invalidates
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


@invalidates
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


@invalidates
async def set_user_auth_provider(user_id: int, provider: str, *, clear_external_id: bool = False):
    """Mark an account as managed by an external auth provider ('ldap',
    'radius', 'tacacs', 'oidc', 'saml'; '' = a local account).

    Managed accounts have their role/display_name re-synced from the provider
    on every successful login (see auth.upsert_external_user).
    ``clear_external_id`` also forgets the SSO subject bound to the account
    (an admin moving it to another provider), in the same transaction."""
    db = await _dbcore.get_db()
    try:
        if clear_external_id:
            await db.execute("UPDATE users SET auth_provider = ?, external_id = '' WHERE id = ?", (provider, user_id))
        else:
            await db.execute("UPDATE users SET auth_provider = ? WHERE id = ?", (provider, user_id))
        await db.commit()
    finally:
        await db.close()


@invalidates
async def set_user_external_id(user_id: int, external_id: str):
    """Bind an account to its OIDC subject (``sub``); see migration 0088."""
    db = await _dbcore.get_db()
    try:
        await db.execute("UPDATE users SET external_id = ? WHERE id = ?", (external_id, user_id))
        await db.commit()
    finally:
        await db.close()


async def get_users_by_external_id(provider: str, external_id: str) -> list[dict]:
    """The accounts of ``provider`` bound to the subject ``external_id``
    (normally one; none for an empty subject)."""
    if not provider or not external_id:
        return []
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT * FROM users WHERE auth_provider = ? AND external_id = ? ORDER BY id",
            (provider, external_id),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


@invalidates
async def update_user_profile(user_id: int, display_name: str = None):
    db = await _dbcore.get_db()
    try:
        if display_name is not None:
            await db.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id))
            await db.commit()
    finally:
        await db.close()


@invalidates
async def update_user_admin(
    user_id: int,
    username: str = None,
    display_name: str = None,
    role: str = None,
    session_never_expires: bool | None = None,
    disabled: bool | None = None,
    keep_enabled_admin: bool = False,
) -> bool:
    """Apply the given account changes; False when nothing was changed
    because ``keep_enabled_admin`` refused the update.

    ``keep_enabled_admin``: refuse a demotion or a disable that would leave
    no enabled admin. As in ``delete_user_guarded``, the count is part of
    the UPDATE statement itself rather than a separate check before it."""
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
        if disabled is not None:
            fields.append("disabled = ?")
            values.append(int(bool(disabled)))
        if not fields:
            return True
        guarded = keep_enabled_admin and (role == "user" or bool(disabled))
        where = "id = ?"
        if guarded:
            # The row may change only when it is not an enabled admin now,
            # or another enabled admin remains.
            where = (
                "id = ? AND (role != 'admin' OR disabled != 0 OR "
                "(SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?) > 0)"
            )
        sql, params = _safe_dynamic_update("users", fields, values, where, user_id)
        if guarded:
            params = (*params, user_id)
        cursor = await db.execute(sql, params)
        if guarded and (cursor.rowcount or 0) < 1:
            await db.rollback()
            return False
        await db.commit()
        return True
    except Exception as e:
        await db.rollback()
        if _is_unique_violation(e):
            raise ValueError("Username already exists")
        raise
    finally:
        await db.close()


async def get_all_users() -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT id, username, display_name, role, must_change_password, session_never_expires, created_at, auth_provider, disabled "
            "FROM users ORDER BY username"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


@invalidates
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


@invalidates
async def delete_user_guarded(user_id: int) -> str:
    """Delete a user, refusing to remove the last remaining enabled admin
    (a disabled admin cannot sign in, so it does not count).

    The last-admin check lives *inside* the DELETE statement — its COUNT
    subquery is evaluated atomically at execution — so two concurrent deletes
    of the final two admins can't both pass a separate check and leave zero
    admins (the check-then-act TOCTOU the route-level guard had). Credentials
    are removed first for the FK, and rolled back if the user delete is blocked.

    Returns "deleted", "not_found", or "last_admin".
    """
    db = await _dbcore.get_db()
    try:
        cur = await db.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if await cur.fetchone() is None:
            return "not_found"
        await db.execute("DELETE FROM credentials WHERE owner_id = ?", (user_id,))
        cur2 = await db.execute(
            """DELETE FROM users
               WHERE id = ?
                 AND (role != 'admin' OR disabled != 0
                      OR (SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?) > 0)""",
            (user_id, user_id),
        )
        if (cur2.rowcount or 0) < 1:
            # Blocked as the last admin — undo the credentials delete too.
            await db.rollback()
            return "last_admin"
        await db.commit()
        return "deleted"
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def get_user_group_ids(user_id: int) -> list[int]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT group_id FROM user_group_memberships WHERE user_id = ? ORDER BY group_id",
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [int(r[0]) for r in rows]
    finally:
        await db.close()


@invalidates
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


# ``access_groups.object_scope``: ``all`` (every device) or ``groups`` (the
# inventory groups in ``access_group_inventory_scopes`` and their sub-groups).
OBJECT_SCOPES = ("all", "groups")


async def _attach_inventory_scopes(db, groups: list[dict]) -> None:
    """Set each access group's ``inventory_scopes`` (``[{inventory_group_id,
    can_write}]`` by inventory group id; empty for ``object_scope='all'``)."""
    for group in groups:
        group["object_scope"] = group.get("object_scope") or "all"
        cursor = await db.execute(
            "SELECT inventory_group_id, can_write FROM access_group_inventory_scopes "
            "WHERE access_group_id = ? ORDER BY inventory_group_id",
            (group["id"],),
        )
        group["inventory_scopes"] = [
            {"inventory_group_id": int(r[0]), "can_write": bool(r[1])} for r in await cursor.fetchall()
        ]


async def _replace_inventory_scopes(db, group_id: int, object_scope: str, inventory_scopes: list[dict]) -> None:
    """Set an access group's scope and replace its grants (in the caller's
    transaction). Grants are kept only for ``object_scope='groups'``. An
    unknown inventory group id fails the foreign key."""
    await db.execute("UPDATE access_groups SET object_scope = ? WHERE id = ?", (object_scope, group_id))
    await db.execute("DELETE FROM access_group_inventory_scopes WHERE access_group_id = ?", (group_id,))
    if object_scope != "groups":
        return
    grants: dict[int, bool] = {}
    for grant in inventory_scopes:
        gid = int(grant["inventory_group_id"])
        grants[gid] = grants.get(gid, False) or bool(grant.get("can_write"))
    for gid, can_write in sorted(grants.items()):
        await db.execute(
            "INSERT INTO access_group_inventory_scopes (access_group_id, inventory_group_id, can_write) VALUES (?, ?, ?)",
            (group_id, gid, int(can_write)),
        )


def _access_group_write_error(e: Exception) -> ValueError | None:
    if _is_unique_violation(e):
        return ValueError("Access group name already exists")
    if _is_foreign_key_violation(e):
        return ValueError("One or more selected inventory groups do not exist")
    return None


async def get_all_access_groups() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """
            SELECT g.id, g.name, g.description, g.object_scope, g.created_at, COUNT(m.user_id) AS member_count
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
        await _attach_inventory_scopes(db, groups)
        return groups
    finally:
        await db.close()


async def get_access_group(group_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, name, description, object_scope, created_at FROM access_groups WHERE id = ?",
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
        await _attach_inventory_scopes(db, [group])
        return group
    finally:
        await db.close()


@invalidates
async def create_access_group(
    name: str,
    description: str,
    feature_keys: list[str],
    object_scope: str = "all",
    inventory_scopes: list[dict] | None = None,
) -> int:
    """Create an access group. ``inventory_scopes`` (``[{inventory_group_id,
    can_write}]``) apply only when ``object_scope`` is ``groups``. Raises
    ``ValueError`` for a taken name or an unknown inventory group."""
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
        await _replace_inventory_scopes(db, int(group_id), object_scope, inventory_scopes or [])
        await db.commit()
        return int(group_id)
    except Exception as e:
        await db.rollback()
        error = _access_group_write_error(e)
        if error is not None:
            raise error
        raise
    finally:
        await db.close()


@invalidates
async def update_access_group(
    group_id: int,
    name: str,
    description: str,
    feature_keys: list[str],
    object_scope: str | None = None,
    inventory_scopes: list[dict] | None = None,
):
    """Update an access group. ``object_scope=None`` leaves the scope and its
    grants as they are; otherwise both are replaced (see ``create_access_group``)."""
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
        if object_scope is not None:
            await _replace_inventory_scopes(db, group_id, object_scope, inventory_scopes or [])
        await db.commit()
    except Exception as e:
        await db.rollback()
        error = _access_group_write_error(e)
        if error is not None:
            raise error
        raise
    finally:
        await db.close()


@invalidates
async def delete_access_group(group_id: int):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM access_groups WHERE id = ?", (group_id,))
        await db.commit()
    finally:
        await db.close()


async def get_user_object_scope(user_id: int) -> dict:
    """The inventory groups a (non-admin) user may see and change, from the
    access groups the user belongs to.

    ``{"unrestricted": True, ...}`` when any of the user's access groups has
    ``object_scope='all'``. Otherwise the user is scoped: ``read_group_ids``
    and ``write_group_ids`` are the granted inventory groups expanded with
    all of their sub-groups (writable when any covering grant has
    ``can_write``). A user with no access group, or with no grants, is
    scoped and sees nothing.
    """
    # Hot path: runs once per request of a non-admin user on scoped routes.
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """
            SELECT g.object_scope
            FROM access_groups g
            INNER JOIN user_group_memberships m ON m.group_id = g.id
            WHERE m.user_id = ?
            """,
            (user_id,),
        )
        scopes = [r[0] for r in await cursor.fetchall()]
        if any(s == "all" for s in scopes):
            return {"unrestricted": True, "read_group_ids": [], "write_group_ids": []}

        cursor = await db.execute(
            """
            SELECT s.inventory_group_id, MAX(s.can_write) AS can_write
            FROM access_group_inventory_scopes s
            INNER JOIN access_groups g ON g.id = s.access_group_id
            INNER JOIN user_group_memberships m ON m.group_id = s.access_group_id
            WHERE m.user_id = ? AND g.object_scope = 'groups'
            GROUP BY s.inventory_group_id
            """,
            (user_id,),
        )
        grants = [(int(r[0]), bool(r[1])) for r in await cursor.fetchall()]
        read: set[int] = set()
        write: set[int] = set()
        if grants:
            # Every grant's subtree in one query; ``root_id`` names the grant
            # that reached each group, so write follows the covering grants.
            writable_roots = {group_id for group_id, can_write in grants if can_write}
            sub = await db.execute(
                group_subtrees_sql(len(grants)),
                tuple(group_id for group_id, _ in grants),
            )
            for root_id, group_id in ((int(r[0]), int(r[1])) for r in await sub.fetchall()):
                read.add(group_id)
                if root_id in writable_roots:
                    write.add(group_id)
    finally:
        await db.close()
    return {"unrestricted": False, "read_group_ids": sorted(read), "write_group_ids": sorted(write)}


async def get_user_effective_features(user_id: int) -> list[str] | None:
    """Return the set of feature keys the user has via group memberships.

    Returns ``None`` if the user has **no** group memberships at all (so the
    caller can distinguish "unassigned" from "assigned but zero features").
    """
    # Hot path: called from feature-gate dependencies on most requests.
    db = await _dbcore.get_db(read_only=True)
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


# Secrets inside ``auth_settings`` rows, by key, as dotted paths (``*`` =
# every list item / dict value). They are encrypted with routes.crypto before
# the row is written and decrypted when it is read, as the OIDC client secret
# (``auth_config.oidc.client_secret_enc``, encrypted by the admin route) and
# the Meraki alert webhook secret (``meraki_alerts.webhook_secret_enc``)
# already are. Callers see plain values; the API masks them as before.
# The field names are the API modules' own (``netcontrol.secret_fields``).
AUTH_SETTING_SECRET_PATHS: dict[str, tuple[str, ...]] = {
    "auth_config": ("radius.secret", "tacacs.secret", "ldap.bind_password"),
    "snmp_discovery": SNMP_SECRET_FIELDS,
    "snmp_discovery_profiles": tuple(f"*.{p}" for p in SNMP_SECRET_FIELDS),
    "snmp_profiles": tuple(f"*.{p}" for p in SNMP_SECRET_FIELDS),
    "siem_sinks": tuple(f"sinks.*.{p}" for p in SIEM_SINK_SECRET_FIELDS),
    "notification_channels": tuple(f"channels.*.{p}" for p in NOTIFICATION_CHANNEL_SECRET_FIELDS),
    "syslog_tls": SYSLOG_TLS_SECRET_FIELDS,
}


def _seal_setting(key: str, value):
    paths = AUTH_SETTING_SECRET_PATHS.get(key)
    if not paths:
        return value
    from routes.crypto import encrypt

    return seal_secret_paths(value, paths, encrypt)


def _open_setting(key: str, value):
    paths = AUTH_SETTING_SECRET_PATHS.get(key)
    if not paths:
        return value
    from routes.crypto import decrypt

    return open_secret_paths(value, paths, decrypt)


async def set_auth_setting(key: str, value: dict):
    db = await _dbcore.get_db()
    try:
        payload = json.dumps(_seal_setting(key, value))
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
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT value FROM auth_settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        if not row:
            return None
        return _open_setting(key, json.loads(row[0]))
    finally:
        await db.close()


async def encrypt_legacy_auth_settings() -> list[str]:
    """Re-save each ``auth_settings`` row that still holds a secret in plain
    text (written before the secrets were encrypted), so it is stored
    encrypted. Runs at startup; a row already encrypted is left alone, so
    it does nothing after the first run. Returns the keys re-saved."""
    db = await _dbcore.get_db(read_only=True)
    try:
        keys = list(AUTH_SETTING_SECRET_PATHS)
        placeholders = ", ".join("?" for _ in keys)
        cursor = await db.execute(
            f"SELECT key, value FROM auth_settings WHERE key IN ({placeholders})",  # noqa: S608  # nosec B608 - fixed SQL
            tuple(keys),
        )
        rows = [(r[0], r[1]) for r in await cursor.fetchall()]
    finally:
        await db.close()
    resaved = []
    for key, raw in rows:
        try:
            stored = json.loads(raw)
        except TypeError, ValueError:
            continue
        if has_plain_secret(stored, AUTH_SETTING_SECRET_PATHS[key]):
            await set_auth_setting(key, _open_setting(key, stored))
            resaved.append(key)
    if resaved:
        _LOGGER.info("auth_settings: encrypted the stored secrets of %s", ", ".join(sorted(resaved)))
    return resaved
