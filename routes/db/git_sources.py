"""Git data sources and the templates, playbooks and config contexts they own.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables: migration 0093. ``git_sources`` holds one row per repository;
``templates``, ``playbooks`` and ``config_contexts`` carry ``git_source_id``,
``git_path`` and ``git_commit`` on the records a source owns. The sync
itself (clone, checkout, file parsing) lives in ``netcontrol.git_sources``
and ``netcontrol.routes.git_sources``; this module only reads and writes
rows. Names of sources are unique ignoring case.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json

import routes.database as _dbcore
from routes.database import _is_foreign_key_violation
from routes.db.custom_fields import _now
from routes.db.device_model import _insert, _select, _update

__all__ = [
    "GIT_OWNED_KINDS",
    "GitOwnedConflict",
    "claim_git_source_attempt",
    "create_git_source",
    "delete_git_owned",
    "delete_git_source",
    "get_git_source",
    "list_git_owned",
    "list_git_sources",
    "set_git_source_result",
    "update_git_source",
    "upsert_git_owned",
]

# Content type -> its table, the columns that identify a record (a context
# name is unique ignoring case), and the columns a sync writes.
GIT_OWNED_KINDS: dict[str, dict] = {
    "templates": {
        "table": "templates",
        "key": ("name", "device_type"),
        "lower": False,
        "columns": ("name", "device_type", "content", "description"),
        "label": "template",
    },
    "playbooks": {
        "table": "playbooks",
        "key": ("name",),
        "lower": False,
        "columns": ("name", "filename", "type", "description", "tags", "content"),
        "label": "playbook",
    },
    "config_contexts": {
        "table": "config_contexts",
        "key": ("name",),
        "lower": True,
        "columns": (
            "name",
            "weight",
            "data",
            "description",
            "enabled",
            "device_type",
            "role_id",
            "site_id",
            "group_id",
            "host_id",
        ),
        "label": "config context",
    },
}

_SOURCE_SELECT = """
    SELECT s.*, c.name AS credential_name,
           (SELECT COUNT(*) FROM templates t WHERE t.git_source_id = s.id) AS template_count,
           (SELECT COUNT(*) FROM playbooks p WHERE p.git_source_id = s.id) AS playbook_count,
           (SELECT COUNT(*) FROM config_contexts x WHERE x.git_source_id = s.id) AS context_count
    FROM git_sources s
    LEFT JOIN credentials c ON c.id = s.credential_id
"""


def git_source_name_sql(table: str) -> str:
    """A select-list column ``git_source_name``: the name of the source that
    owns the row of ``table`` (a fixed table name or alias), or NULL."""
    return f"(SELECT gs.name FROM git_sources gs WHERE gs.id = {table}.git_source_id) AS git_source_name"


class GitOwnedConflict(ValueError):
    """A record with the same identity exists and is not owned by the
    syncing source (written in Plexus, or owned by another source)."""


def _json(text: str | None, default):
    try:
        value = json.loads(text or "")
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default


def _source(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "remote_url": row["remote_url"],
        "branch": row["branch"],
        "credential_id": int(row["credential_id"]) if row["credential_id"] is not None else None,
        "credential_name": row["credential_name"] or "",
        "provides": _json(row["provides"], []),
        "sync_interval_minutes": int(row["sync_interval_minutes"]),
        "enabled": bool(row["enabled"]),
        "status": row["status"],
        "error": row["error"] or "",
        "last_commit": row["last_commit"] or "",
        "last_attempt_at": row["last_attempt_at"] or "",
        "last_synced_at": row["last_synced_at"] or "",
        "summary": _json(row["summary"], {}),
        "object_counts": {
            "templates": int(row["template_count"]),
            "playbooks": int(row["playbook_count"]),
            "config_contexts": int(row["context_count"]),
        },
        "created_at": row["created_at"] or "",
        "updated_at": row["updated_at"] or "",
        "updated_by": row["updated_by"] or "",
    }


def _taken(name: str) -> ValueError:
    return ValueError(f"A Git source named '{name}' already exists.")


def _written(values: dict, user: str) -> dict:
    out = dict(values)
    if "provides" in out:
        out["provides"] = json.dumps(list(out["provides"]))
    if "enabled" in out:
        out["enabled"] = 1 if out["enabled"] else 0
    out["updated_at"] = _now()
    out["updated_by"] = user or ""
    return out


async def _name_taken(name: str, source_id: int | None) -> bool:
    rows = await _select("SELECT id FROM git_sources WHERE lower(name) = lower(?)", (name,))
    return any(int(r["id"]) != source_id for r in rows)


# ── Sources ──────────────────────────────────────────────────────────────────


async def list_git_sources() -> list[dict]:
    """Every source by name, with its credential's name and the number of
    records it owns of each content type."""
    return [_source(r) for r in await _select(_SOURCE_SELECT + " ORDER BY lower(s.name), s.id")]


async def get_git_source(source_id: int) -> dict | None:
    rows = await _select(_SOURCE_SELECT + " WHERE s.id = ?", (int(source_id),))
    return _source(rows[0]) if rows else None


async def create_git_source(values: dict, user: str = "") -> dict:
    """``values``: the writable fields, already validated (``provides`` a
    list). ``ValueError`` when a source has the name, ignoring case."""
    if await _name_taken(values["name"], None):
        raise _taken(values["name"])
    new_id = await _insert("git_sources", _written(values, user), _taken(values["name"]))
    record = await get_git_source(new_id)
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record


async def update_git_source(source_id: int, values: dict, user: str = "") -> dict | None:
    """Replace the writable fields. ``None`` when the source does not exist;
    ``ValueError`` when another source has the name."""
    if await _name_taken(values["name"], int(source_id)):
        raise _taken(values["name"])
    if not await _update("git_sources", int(source_id), _written(values, user), _taken(values["name"])):
        return None
    return await get_git_source(source_id)


async def delete_git_source(source_id: int) -> bool:
    """Delete the source row. Remove its records first (``delete_git_owned``);
    any left are detached by the foreign key."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM git_sources WHERE id = ?", (int(source_id),))
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def claim_git_source_attempt(source_id: int) -> None:
    """Mark a sync as started: ``status`` ``syncing`` and ``last_attempt_at``
    now. The outcome is written by ``set_git_source_result``."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE git_sources SET status = 'syncing', last_attempt_at = ? WHERE id = ?",
            (_now(), int(source_id)),
        )
        await db.commit()
    finally:
        await db.close()


async def set_git_source_result(
    source_id: int, *, status: str, error: str = "", commit: str | None = None, summary: dict | None = None
) -> None:
    """Record the outcome of a sync. ``commit`` (the imported HEAD) also sets
    ``last_synced_at``; on a failed sync it is ``None`` and the previous
    commit and summary stay."""
    sets = ["status = ?", "error = ?"]
    params: list = [status, error or ""]
    if commit is not None:
        sets += ["last_commit = ?", "last_synced_at = ?"]
        params += [commit, _now()]
    if summary is not None:
        sets.append("summary = ?")
        params.append(json.dumps(summary))
    db = await _dbcore.get_db()
    try:
        await db.execute(
            f"UPDATE git_sources SET {', '.join(sets)} WHERE id = ?",  # nosec B608 - fixed clauses
            (*params, int(source_id)),
        )
        await db.commit()
    finally:
        await db.close()


# ── Owned records ────────────────────────────────────────────────────────────


def _kind(kind: str) -> dict:
    spec = GIT_OWNED_KINDS.get(kind)
    if spec is None:
        raise ValueError(f"unknown Git content type {kind!r}")
    return spec


async def list_git_owned(source_id: int, kind: str | None = None) -> dict[str, list[dict]]:
    """``content type -> [{id, name, git_path, git_commit, ...key}]``: the
    records the source owns (only ``kind`` when given), by path."""
    out: dict[str, list[dict]] = {}
    for name, spec in GIT_OWNED_KINDS.items():
        if kind is not None and name != kind:
            continue
        cols = ", ".join(dict.fromkeys(("id", *spec["key"], "git_path", "git_commit")))
        rows = await _select(
            f"SELECT {cols} FROM {spec['table']} WHERE git_source_id = ? ORDER BY git_path, id",  # nosec B608 - fixed table names
            (int(source_id),),
        )
        out[name] = rows
    return out


async def upsert_git_owned(kind: str, source_id: int, values: dict, path: str, commit: str) -> tuple[str, int]:
    """Create or update the ``kind`` record ``values`` identify, owned by the
    source. Returns ``(outcome, id)`` with outcome ``created``, ``updated``
    or ``unchanged`` (only the path and commit moved). Raises
    ``GitOwnedConflict`` when a record with that identity is not the
    source's."""
    spec = _kind(kind)
    table = spec["table"]
    key = spec["key"]
    where = " AND ".join(f"lower({k}) = lower(?)" if spec["lower"] else f"{k} = ?" for k in key)
    columns = spec["columns"]
    rows = await _select(
        f"SELECT id, git_source_id, {', '.join(columns)} FROM {table} WHERE {where}",  # nosec B608 - fixed names
        tuple(values[k] for k in key),
    )
    owned = {"git_source_id": int(source_id), "git_path": path, "git_commit": commit}
    if kind == "config_contexts":
        stamps = {"updated_at": _now(), "updated_by": values.get("updated_by", "")}
    else:
        stamps = {"updated_at": _now()}
    written = {c: values[c] for c in columns}
    label = f"{spec['label']} '{values['name']}'"
    if not rows:
        new_id = await _insert(table, {**written, **owned, **stamps}, GitOwnedConflict(f"A {label} already exists."))
        return "created", new_id
    row = rows[0]
    if row["git_source_id"] is None or int(row["git_source_id"]) != int(source_id):
        owner = "written in Plexus" if row["git_source_id"] is None else "owned by another Git source"
        raise GitOwnedConflict(f"A {label} {owner} already exists; it was left unchanged.")
    changed = any(row[c] != written[c] for c in columns)
    update = {**owned, **(written if changed else {}), **(stamps if changed else {})}
    await _update(table, int(row["id"]), update, GitOwnedConflict(f"A {label} already exists."))
    return ("updated" if changed else "unchanged"), int(row["id"])


async def delete_git_owned(kind: str, record_id: int) -> str:
    """Remove a record the source no longer provides. Returns ``deleted``, or
    ``detached`` when other rows (job history) still reference it: it then
    stays as an ordinary record written in Plexus."""
    table = _kind(kind)["table"]
    db = await _dbcore.get_db()
    try:
        await db.execute(f"DELETE FROM {table} WHERE id = ?", (int(record_id),))  # nosec B608 - fixed table names
        await db.commit()
        return "deleted"
    except Exception as exc:
        await db.rollback()
        if not _is_foreign_key_violation(exc):
            raise
    finally:
        await db.close()
    db = await _dbcore.get_db()
    try:
        await db.execute(
            f"UPDATE {table} SET git_source_id = NULL, git_path = '', git_commit = '' WHERE id = ?",  # nosec B608 - fixed table names
            (int(record_id),),
        )
        await db.commit()
        return "detached"
    finally:
        await db.close()
