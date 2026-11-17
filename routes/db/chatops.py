"""ChatOps bots, user mappings, job presets and the command log
(``netcontrol.chatops``).

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables (migration 0105): ``chatops_bots``, ``chatops_user_mappings``,
``chatops_job_presets`` and ``chatops_command_log``. Secrets are stored
encrypted by the caller (``routes.crypto``); nothing here decrypts them.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import routes.database as _dbcore
from routes.database import _is_unique_violation, row_to_dict, rows_to_list

__all__ = [
    "add_chatops_command_log",
    "create_chatops_job_preset",
    "create_chatops_user_mapping",
    "delete_chatops_bot",
    "delete_chatops_job_preset",
    "delete_chatops_user_mapping",
    "find_chatops_user_mapping",
    "get_chatops_bot",
    "get_chatops_job_preset",
    "get_chatops_job_preset_by_name",
    "list_chatops_bots",
    "list_chatops_command_log",
    "list_chatops_job_presets",
    "list_chatops_user_mappings",
    "prune_chatops_command_log",
    "update_chatops_job_preset",
    "upsert_chatops_bot",
]

_FMT = "%Y-%m-%d %H:%M:%S"


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def _json_list(raw: object) -> list[str]:
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except TypeError, ValueError:
        return []
    return [str(v) for v in value] if isinstance(value, list) else []


def _bot(row: dict | None) -> dict | None:
    if row is None:
        return None
    item = dict(row)
    item["enabled"] = bool(item.get("enabled"))
    item["allowed_commands"] = _json_list(item.get("allowed_commands"))
    return item


def _preset(row: dict | None) -> dict | None:
    if row is None:
        return None
    item = dict(row)
    try:
        spec = json.loads(item.get("spec") or "{}")
    except TypeError, ValueError:
        spec = {}
    item["spec"] = spec if isinstance(spec, dict) else {}
    item["commit"] = bool(item.pop("commit_mode", 0))
    item["enabled"] = bool(item.get("enabled"))
    return item


# ── Bots ─────────────────────────────────────────────────────────────────────


async def list_chatops_bots() -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM chatops_bots ORDER BY platform")
        return [b for b in (_bot(r) for r in rows_to_list(await cursor.fetchall())) if b]
    finally:
        await db.close()


async def get_chatops_bot(platform: str) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM chatops_bots WHERE platform = ?", (platform,))
        return _bot(row_to_dict(await cursor.fetchone()))
    finally:
        await db.close()


async def upsert_chatops_bot(
    platform: str,
    *,
    name: str,
    enabled: bool,
    allowed_commands: list[str],
    signing_secret_enc: str | None,
    bot_token_enc: str | None,
    user: str,
) -> dict:
    """Create or update the bot of ``platform``. A secret passed as ``None``
    keeps the stored value; ``""`` clears it."""
    now = _now()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT id FROM chatops_bots WHERE platform = ?", (platform,))
        existing = await cursor.fetchone()
        commands = json.dumps(list(allowed_commands))
        if existing is None:
            await db.execute(
                """INSERT INTO chatops_bots
                       (platform, name, enabled, signing_secret_enc, bot_token_enc, allowed_commands,
                        created_by, created_at, updated_by, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    platform,
                    name,
                    1 if enabled else 0,
                    signing_secret_enc or "",
                    bot_token_enc or "",
                    commands,
                    user,
                    now,
                    user,
                    now,
                ),
            )
        else:
            sets = ["name = ?", "enabled = ?", "allowed_commands = ?", "updated_by = ?", "updated_at = ?"]
            params: list = [name, 1 if enabled else 0, commands, user, now]
            if signing_secret_enc is not None:
                sets.append("signing_secret_enc = ?")
                params.append(signing_secret_enc)
            if bot_token_enc is not None:
                sets.append("bot_token_enc = ?")
                params.append(bot_token_enc)
            params.append(platform)
            await db.execute(
                f"UPDATE chatops_bots SET {', '.join(sets)} WHERE platform = ?",  # nosec B608 - fixed column names
                tuple(params),
            )
        await db.commit()
    finally:
        await db.close()
    bot = await get_chatops_bot(platform)
    assert bot is not None  # nosec B101 - written above
    return bot


async def delete_chatops_bot(platform: str) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM chatops_bots WHERE platform = ?", (platform,))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


# ── User mappings ────────────────────────────────────────────────────────────


async def list_chatops_user_mappings() -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT m.*, COALESCE(u.username, '') AS username, COALESCE(u.role, '') AS role
               FROM chatops_user_mappings m LEFT JOIN users u ON u.id = m.user_id
               ORDER BY m.platform, lower(m.chat_user_id)"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def find_chatops_user_mapping(platform: str, identities: list[str]) -> dict | None:
    """The mapping of the first of ``identities`` (user id, e-mail) that has
    one on ``platform``, compared ignoring case."""
    wanted = [i.strip().lower() for i in identities if i and i.strip()]
    if not wanted:
        return None
    db = await _dbcore.get_db(read_only=True)
    try:
        for identity in wanted:
            cursor = await db.execute(
                "SELECT * FROM chatops_user_mappings WHERE platform = ? AND lower(chat_user_id) = ?",
                (platform, identity),
            )
            row = row_to_dict(await cursor.fetchone())
            if row:
                return row
        return None
    finally:
        await db.close()


async def create_chatops_user_mapping(
    *, platform: str, chat_user_id: str, chat_label: str, user_id: int, created_by: str
) -> int:
    """Raises ``ValueError`` when the chat identity is already mapped."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO chatops_user_mappings (platform, chat_user_id, chat_label, user_id, created_by, created_at)
               VALUES (?,?,?,?,?,?) RETURNING id""",
            (platform, chat_user_id, chat_label, int(user_id), created_by, _now()),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError("That chat user is already mapped.") from exc
        raise
    finally:
        await db.close()


async def delete_chatops_user_mapping(mapping_id: int) -> dict | None:
    """Delete a mapping; returns the deleted row or ``None``."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM chatops_user_mappings WHERE id = ?", (int(mapping_id),))
        row = row_to_dict(await cursor.fetchone())
        if row is None:
            return None
        await db.execute("DELETE FROM chatops_user_mappings WHERE id = ?", (int(mapping_id),))
        await db.commit()
        return row
    finally:
        await db.close()


# ── Job presets ──────────────────────────────────────────────────────────────


async def list_chatops_job_presets(enabled_only: bool = False) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        where = "WHERE enabled = 1" if enabled_only else ""
        cursor = await db.execute(f"SELECT * FROM chatops_job_presets {where} ORDER BY lower(name)")  # nosec B608
        return [p for p in (_preset(r) for r in rows_to_list(await cursor.fetchall())) if p]
    finally:
        await db.close()


async def _preset_where(where: str, value: object) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(f"SELECT * FROM chatops_job_presets WHERE {where}", (value,))  # nosec B608
        return _preset(row_to_dict(await cursor.fetchone()))
    finally:
        await db.close()


async def get_chatops_job_preset(preset_id: int) -> dict | None:
    return await _preset_where("id = ?", int(preset_id))


async def get_chatops_job_preset_by_name(name: str) -> dict | None:
    return await _preset_where("lower(name) = ?", (name or "").strip().lower())


async def create_chatops_job_preset(
    *,
    name: str,
    description: str,
    spec: dict,
    source_job_id: int | None,
    playbook_name: str,
    commit: bool,
    enabled: bool,
    user: str,
) -> int:
    """Raises ``ValueError`` when the name is taken."""
    now = _now()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO chatops_job_presets
                   (name, description, spec, source_job_id, playbook_name, commit_mode, enabled,
                    created_by, created_at, updated_by, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING id""",
            (
                name,
                description,
                json.dumps(spec),
                source_job_id,
                playbook_name,
                1 if commit else 0,
                1 if enabled else 0,
                user,
                now,
                user,
                now,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as exc:
        await db.rollback()
        if _is_unique_violation(exc):
            raise ValueError(f"A preset named '{name}' already exists.") from exc
        raise
    finally:
        await db.close()


async def update_chatops_job_preset(
    preset_id: int, *, description: str, commit: bool, enabled: bool, user: str
) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """UPDATE chatops_job_presets
               SET description = ?, commit_mode = ?, enabled = ?, updated_by = ?, updated_at = ?
               WHERE id = ?""",
            (description, 1 if commit else 0, 1 if enabled else 0, user, _now(), int(preset_id)),
        )
        await db.commit()
        if not (cursor.rowcount or 0):
            return None
    finally:
        await db.close()
    return await get_chatops_job_preset(preset_id)


async def delete_chatops_job_preset(preset_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM chatops_job_presets WHERE id = ?", (int(preset_id),))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


# ── Command log ──────────────────────────────────────────────────────────────


async def add_chatops_command_log(
    *,
    platform: str,
    chat_user_id: str,
    chat_user_name: str,
    username: str,
    command: str,
    arguments: str,
    outcome: str,
    detail: str,
    duration_ms: int,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO chatops_command_log
                   (created_at, platform, chat_user_id, chat_user_name, username, command, arguments,
                    outcome, detail, duration_ms)
               VALUES (?,?,?,?,?,?,?,?,?,?) RETURNING id""",
            (
                _now(),
                platform,
                chat_user_id[:200],
                chat_user_name[:200],
                username,
                command[:60],
                arguments[:500],
                outcome,
                detail[:500],
                int(duration_ms),
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def list_chatops_command_log(limit: int = 200, platform: str = "", outcome: str = "") -> list[dict]:
    """Newest first."""
    clauses: list[str] = []
    params: list = []
    if platform:
        clauses.append("platform = ?")
        params.append(platform)
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(int(limit), 1000)))
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT * FROM chatops_command_log {where} ORDER BY id DESC LIMIT ?",  # nosec B608 - fixed clauses
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def prune_chatops_command_log(retention_days: int = 90) -> int:
    """Delete log rows older than ``retention_days``; returns how many."""
    cutoff = (datetime.now(UTC) - timedelta(days=max(1, int(retention_days)))).strftime(_FMT)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM chatops_command_log WHERE created_at < ?", (cutoff,))
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()
