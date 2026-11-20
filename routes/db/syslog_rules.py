"""Syslog alert rules: storage only.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table: migration 0119 (``syslog_alert_rules``). The rule logic (the
built-in rules, matching, validation, the in-memory cache and the engine)
lives in ``netcontrol.syslog_rules``; the API in
``netcontrol.routes.syslog_rules``. A row with an empty ``builtin_key`` is
a custom rule; a row with one only overrides ``enabled`` and ``severity``
of that built-in rule. ``list_syslog_messages_since`` reads the stored
syslog messages (``trap_syslog_events``) for the restart restore and the
activity analysis (``netcontrol.syslog_activity``).

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

from collections.abc import Iterable

import routes.database as _dbcore
from routes.db.custom_fields import _now
from routes.db.device_model import _insert, _select, _update
from routes.db.inventory import group_ids_condition

__all__ = [
    "create_syslog_alert_rule",
    "delete_syslog_alert_rule",
    "get_syslog_alert_rule",
    "list_syslog_alert_rules",
    "list_syslog_messages_since",
    "set_syslog_builtin_override",
    "update_syslog_alert_rule",
]

_SELECT = "SELECT * FROM syslog_alert_rules"
# The columns a custom rule's create and update write.
_CUSTOM_FIELDS = (
    "name",
    "enabled",
    "match_type",
    "pattern",
    "clear_pattern",
    "severity",
    "threshold_count",
    "threshold_window_seconds",
    "auto_resolve_minutes",
)


def _rule(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"] or "",
        "enabled": bool(row["enabled"]),
        "builtin_key": row["builtin_key"] or "",
        "match_type": row["match_type"] or "",
        "pattern": row["pattern"] or "",
        "clear_pattern": row["clear_pattern"] or "",
        "severity": row["severity"] or "warning",
        "threshold_count": int(row["threshold_count"] or 1),
        "threshold_window_seconds": int(row["threshold_window_seconds"] or 0),
        "auto_resolve_minutes": int(row["auto_resolve_minutes"] or 0),
        "created_by": row["created_by"] or "",
        "created_at": row["created_at"] or "",
        "updated_at": row["updated_at"] or "",
    }


def _written(values: dict) -> dict:
    out = {k: values[k] for k in _CUSTOM_FIELDS if k in values}
    if "enabled" in out:
        out["enabled"] = 1 if out["enabled"] else 0
    out["updated_at"] = _now()
    return out


async def list_syslog_alert_rules() -> list[dict]:
    """Every row: the custom rules and the built-in overrides, by id."""
    return [_rule(r) for r in await _select(_SELECT + " ORDER BY id")]


async def get_syslog_alert_rule(rule_id: int) -> dict | None:
    rows = await _select(_SELECT + " WHERE id = ?", (int(rule_id),))
    return _rule(rows[0]) if rows else None


async def create_syslog_alert_rule(values: dict, user: str = "") -> dict:
    """A new custom rule from validated ``values`` (``_CUSTOM_FIELDS``)."""
    written = _written(values)
    written["builtin_key"] = ""
    written["created_by"] = user or ""
    new_id = await _insert("syslog_alert_rules", written, ValueError("The rule could not be saved."))
    record = await get_syslog_alert_rule(new_id)
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record


async def update_syslog_alert_rule(rule_id: int, values: dict) -> dict | None:
    """Replace the writable fields of a custom rule. None when no custom
    rule has the id (a built-in override row is changed through
    ``set_syslog_builtin_override``)."""
    existing = await get_syslog_alert_rule(rule_id)
    if existing is None or existing["builtin_key"]:
        return None
    await _update("syslog_alert_rules", int(rule_id), _written(values), ValueError("The rule could not be saved."))
    return await get_syslog_alert_rule(rule_id)


async def delete_syslog_alert_rule(rule_id: int) -> dict | None:
    """Delete a custom rule; returns the deleted row, None when no custom
    rule has the id."""
    existing = await get_syslog_alert_rule(rule_id)
    if existing is None or existing["builtin_key"]:
        return None
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM syslog_alert_rules WHERE id = ?", (int(rule_id),))
        await db.commit()
    finally:
        await db.close()
    return existing


async def set_syslog_builtin_override(builtin_key: str, enabled: bool, severity: str, user: str = "") -> dict:
    """Store the ``enabled`` / ``severity`` override of a built-in rule
    (one row per built-in, created on its first change)."""
    rows = await _select(_SELECT + " WHERE builtin_key = ?", (builtin_key,))
    values = {"enabled": 1 if enabled else 0, "severity": severity, "updated_at": _now()}
    if rows:
        await _update("syslog_alert_rules", int(rows[0]["id"]), values, ValueError("The rule could not be saved."))
        rule_id = int(rows[0]["id"])
    else:
        rule_id = await _insert(
            "syslog_alert_rules",
            {**values, "builtin_key": builtin_key, "name": builtin_key, "created_by": user or ""},
            ValueError("The rule could not be saved."),
        )
    record = await get_syslog_alert_rule(rule_id)
    if record is None:  # pragma: no cover - the row was just written
        raise RuntimeError("record vanished after write")
    return record


async def list_syslog_messages_since(
    seconds: int,
    *,
    before_id: int | None = None,
    limit: int = 5000,
    hosts_only: bool = False,
    group_ids: Iterable[int] | None = None,
) -> list[dict]:
    """One page of the syslog messages in ``trap_syslog_events`` received
    within the last ``seconds``, newest first (by id): ``id``, ``host_id``,
    ``source_ip``, ``message``, ``received_at`` and the host's
    ``device_type`` and ``hostname`` (empty for an unknown source).
    ``before_id``: the next page after the row with that id. ``hosts_only``:
    only the messages of inventory hosts. ``group_ids`` keeps the messages of
    hosts in those inventory groups (object scope: a message from an unknown
    source is left out), as ``get_trap_syslog_events`` does."""
    clauses = ["e.event_type = 'syslog'", "e.received_at >= datetime('now', ?)"]
    params: list = [f"-{int(seconds)} seconds"]
    if before_id is not None:
        clauses.append("e.id < ?")
        params.append(int(before_id))
    if hosts_only:
        clauses.append("e.host_id IS NOT NULL")
    scope_sql, scope_params = group_ids_condition("h.group_id", group_ids)
    if scope_sql:
        clauses.append(scope_sql)
        params.extend(scope_params)
    params.append(int(limit))
    return await _select(
        f"""SELECT e.id, e.host_id, e.source_ip, e.message, e.received_at,
                   COALESCE(h.device_type, '') AS device_type, COALESCE(h.hostname, '') AS hostname
            FROM trap_syslog_events e
            LEFT JOIN hosts h ON h.id = e.host_id
            WHERE {" AND ".join(clauses)}
            ORDER BY e.id DESC LIMIT ?""",  # nosec B608 - fixed clauses, placeholders only
        tuple(params),
    )
