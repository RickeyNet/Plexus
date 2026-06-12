"""Playbooks persistence helpers.

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
    "get_all_playbooks",
    "get_playbook",
    "create_playbook",
    "sync_playbook_filename",
    "update_playbook",
    "delete_playbook",
    "get_all_templates",
    "get_template",
    "create_template",
    "update_template",
    "get_template_variants",
    "resolve_template_for_device_type",
    "resolve_variant_in_memory",
    "delete_template",
]

# ═════════════════════════════════════════════════════════════════════════════
# Playbooks
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_playbooks() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("""
            SELECT p.*,
                   (SELECT j.status FROM jobs j WHERE j.playbook_id = p.id
                    ORDER BY j.id DESC LIMIT 1) AS last_status,
                   (SELECT j.started_at FROM jobs j WHERE j.playbook_id = p.id
                    ORDER BY j.id DESC LIMIT 1) AS last_run
            FROM playbooks p ORDER BY p.name
        """)
        rows = rows_to_list(await cursor.fetchall())
        for r in rows:
            r["tags"] = json.loads(r.get("tags") or "[]")
        return rows
    finally:
        await db.close()


async def get_playbook(playbook_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM playbooks WHERE id = ?", (playbook_id,))
        row = row_to_dict(await cursor.fetchone())
        if row:
            row["tags"] = json.loads(row.get("tags") or "[]")
        return row
    finally:
        await db.close()


async def create_playbook(name: str, filename: str, description: str = "",
                          tags: list[str] | None = None, content: str = "",
                          type: str = "python") -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO playbooks (name, filename, description, tags, content, type) VALUES (?,?,?,?,?,?)",
            (name, filename, description, json.dumps(tags or []), content, type),
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as e:
        await db.rollback()
        # If it's a unique constraint error, re-raise it
        if _is_unique_violation(e):
            raise
        raise
    finally:
        await db.close()


async def sync_playbook_filename(name: str, filename: str):
    """Update the filename for an existing playbook by name."""
    db = await _dbcore.get_db()
    try:
        if _dbcore.DB_ENGINE == "postgres":
            await db.execute(
                "UPDATE playbooks SET filename = ?, updated_at = NOW()::text WHERE name = ?",
                (filename, name),
            )
        else:
            await db.execute(
                "UPDATE playbooks SET filename = ?, updated_at = datetime('now') WHERE name = ?",
                (filename, name),
            )
        await db.commit()
    finally:
        await db.close()


async def update_playbook(playbook_id: int, name: str = None, filename: str = None,
                          description: str = None, tags: list[str] | None = None,
                          content: str = None, type: str = None):
    """Update playbook fields. None values are not updated."""
    db = await _dbcore.get_db()
    try:
        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if filename is not None:
            updates.append("filename = ?")
            params.append(filename)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(tags))
        if content is not None:
            updates.append("content = ?")
            params.append(content)
        if type is not None:
            updates.append("type = ?")
            params.append(type)
        
        if updates:
            updates.append("updated_at = NOW()::text" if _dbcore.DB_ENGINE == "postgres" else "updated_at = datetime('now')")
            sql, sql_params = _safe_dynamic_update("playbooks", updates, params, "id = ?", playbook_id)
            await db.execute(sql, sql_params)
            await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def delete_playbook(playbook_id: int):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,))
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Templates
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_templates() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM templates ORDER BY name")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_template(template_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM templates WHERE id = ?", (template_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_template(name: str, content: str, description: str = "",
                          device_type: str = "") -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO templates (name, device_type, content, description) "
            "VALUES (?,?,?,?)",
            (name, device_type, content, description),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_template(template_id: int, name: str, content: str,
                          description: str = "", device_type: str = ""):
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE templates SET name=?, device_type=?, content=?,
               description=?, updated_at=datetime('now') WHERE id=?""",
            (name, device_type, content, description, template_id),
        )
        await db.commit()
    finally:
        await db.close()


async def get_template_variants(name: str) -> list[dict]:
    """Return every template row sharing ``name`` (all device_type variants).

    Used by the job pre-launch validation path so a secret referenced
    only by a vendor-specific variant is still caught before the job is
    queued, not mid-run.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM templates WHERE name = ? ORDER BY device_type", (name,)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def resolve_template_for_device_type(
    template_id: int, device_type: str
) -> dict | None:
    """Resolve the right template body for a host's device_type.

    Phase 12 lets one logical template (keyed by ``name``) carry
    vendor-specific command bodies (keyed by ``device_type``).  A job
    binds a single ``template_id``; at run time each host needs the
    variant matching *its* platform.

    Resolution order, given the job's selected template:

      1. the ``(name, device_type)`` row whose device_type exactly
         matches this host - the vendor-specific body, or
      2. the ``(name, '')`` generic row - the default body, or
      3. the originally-selected row itself (covers the case where the
         operator picked a vendor-specific template directly and there
         is no generic sibling).

    Returns ``None`` only if ``template_id`` doesn't exist at all, so
    the caller can surface a clean "template not found" error.
    """
    base = await get_template(template_id)
    if base is None:
        return None
    name = base["name"]
    db = await _dbcore.get_db()
    try:
        # Exact vendor match wins.
        cursor = await db.execute(
            "SELECT * FROM templates WHERE name = ? AND device_type = ?",
            (name, device_type or ""),
        )
        row = row_to_dict(await cursor.fetchone())
        if row is not None:
            return row
        # Fall back to the generic ('' device_type) sibling.
        cursor = await db.execute(
            "SELECT * FROM templates WHERE name = ? AND device_type = ''",
            (name,),
        )
        row = row_to_dict(await cursor.fetchone())
        if row is not None:
            return row
    finally:
        await db.close()
    # No generic sibling and no vendor match - the operator picked a
    # vendor-specific template directly; use it as-is.
    return base


def resolve_variant_in_memory(
    base: dict, variants: list[dict], device_type: str
) -> dict:
    """Pure, no-I/O twin of ``resolve_template_for_device_type``'s rule.

    Given the already-fetched selected row (``base``) and every row
    sharing its ``name`` (``variants`` from :func:`get_template_variants`),
    pick the body for ``device_type`` using the identical order:

      1. exact ``(name, device_type)`` vendor row, else
      2. the ``(name, '')`` generic sibling, else
      3. the originally-selected row itself.

    The job-launch path resolves many device_types against one template;
    doing it in memory off two queries (``get_template`` +
    ``get_template_variants``) avoids the ~3 fresh aiosqlite connections
    per device_type that calling ``resolve_template_for_device_type`` in
    a loop would otherwise open on the queued→running critical path.
    """
    want = device_type or ""
    exact = next((r for r in variants if (r["device_type"] or "") == want), None)
    if exact is not None:
        return exact
    generic = next((r for r in variants if (r["device_type"] or "") == ""), None)
    if generic is not None:
        return generic
    return base


async def delete_template(template_id: int):
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM templates WHERE id = ?", (template_id,))
        await db.commit()
    finally:
        await db.close()


