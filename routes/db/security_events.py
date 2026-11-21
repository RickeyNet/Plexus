"""Security events: storage only.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table: migration 0126 (``security_events``). Vendor-neutral: a row names
its source (``provider``, ``org_ref``), the optional inventory host and the
kind of event; the OPNsense IDS alerts are the first producer
(``netcontrol.routes.opnsense_ids``). The alerting and the API live in
``netcontrol.routes.security_events``.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text, so they compare as text.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import routes.database as _dbcore
from routes.db.device_model import _select
from routes.db.inventory import group_ids_condition
from routes.db.opnsense_filterlog import _marks
from routes.db.routing import _like

__all__ = [
    "count_security_events",
    "insert_security_events",
    "latest_alerting_security_events",
    "list_security_events",
    "purge_security_events",
    "resolve_security_event_alerts",
    "security_event_categories",
    "security_event_watermark",
    "trim_security_events",
]

_COLUMNS = (
    "provider",
    "org_ref",
    "source_name",
    "host_id",
    "kind",
    "event_key",
    "occurred_at",
    "received_at",
    "severity",
    "priority",
    "signature_id",
    "signature",
    "category",
    "action",
    "protocol",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "interface",
    "flow_id",
    "app_proto",
)
_INSERT = (
    f"INSERT INTO security_events ({', '.join(_COLUMNS)}) VALUES ({', '.join('?' for _ in _COLUMNS)})"
    " ON CONFLICT (provider, org_ref, kind, event_key) DO NOTHING"
)
# Keys looked up per query.
_KEY_CHUNK = 500
# The severities a list can be filtered by.
SEVERITIES = ("critical", "warning", "info", "unknown")
ALERTING_SEVERITIES = ("critical", "warning")


async def _existing_keys(provider: str, org_ref: int, kind: str, keys: list[str]) -> set[str]:
    found: set[str] = set()
    for start in range(0, len(keys), _KEY_CHUNK):
        chunk = keys[start : start + _KEY_CHUNK]
        rows = await _select(
            "SELECT event_key FROM security_events WHERE provider = ? AND org_ref = ? AND kind = ?"
            f" AND event_key IN ({_marks(len(chunk))})",  # nosec B608 - placeholders only
            (provider, int(org_ref), kind, *chunk),
        )
        found.update(str(r["event_key"]) for r in rows)
    return found


async def insert_security_events(
    provider: str,
    org_ref: int,
    events: list[dict[str, Any]],
    *,
    host_id: int | None,
    source_name: str,
    received_at: str,
) -> list[dict[str, Any]]:
    """Store the events of one read of source ``(provider, org_ref)`` (each
    with ``kind``, ``event_key``, ``occurred_at`` and the event fields, see
    ``netcontrol.integrations.opnsense.ids.alert_event``). An event whose key
    is already stored is skipped. Returns the events that are new."""
    if not events:
        return []
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_kind.setdefault(str(event["kind"]), []).append(event)
    new: list[dict[str, Any]] = []
    for kind, found in by_kind.items():
        stored = await _existing_keys(provider, org_ref, kind, [str(e["event_key"]) for e in found])
        new.extend(e for e in found if str(e["event_key"]) not in stored)
    if not new:
        return []
    rows = [
        tuple(
            {
                **event,
                "provider": provider,
                "org_ref": int(org_ref),
                "source_name": source_name,
                "host_id": host_id,
                "received_at": received_at,
            }.get(column)
            for column in _COLUMNS
        )
        for event in new
    ]
    db = await _dbcore.get_db()
    try:
        await db.executemany(_INSERT, rows)
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
    return new


async def trim_security_events(provider: str, org_ref: int, keep: int) -> int:
    """Delete the events of a source beyond its newest ``keep``."""
    return await _dbcore.chunked_delete(
        "security_events",
        "provider = ? AND org_ref = ? AND id IN (SELECT id FROM security_events WHERE provider = ? AND org_ref = ?"
        " ORDER BY occurred_at DESC, id DESC OFFSET ?)",
        (provider, int(org_ref), provider, int(org_ref), int(keep)),
    )


async def security_event_watermark(provider: str, org_ref: int, kind: str) -> str | None:
    """When the newest stored event of a source and kind happened, or ``None``."""
    rows = await _select(
        "SELECT MAX(occurred_at) AS newest FROM security_events WHERE provider = ? AND org_ref = ? AND kind = ?",
        (provider, int(org_ref), kind),
    )
    newest = (rows[0] if rows else {}).get("newest")
    return str(newest) if newest else None


async def security_event_categories(provider: str, org_ref: int, kind: str, limit: int = 5000) -> dict[int, str]:
    """signature id -> the category stored for it, for the signatures of a
    source (the newest ``limit``)."""
    rows = await _select(
        "SELECT signature_id, MAX(category) AS category FROM security_events"
        " WHERE provider = ? AND org_ref = ? AND kind = ? AND category <> '' AND signature_id IS NOT NULL"
        " GROUP BY signature_id ORDER BY MAX(occurred_at) DESC LIMIT ?",
        (provider, int(org_ref), kind, int(limit)),
    )
    return {int(r["signature_id"]): str(r["category"]) for r in rows}


async def latest_alerting_security_events(
    provider: str, org_ref: int, kind: str, signature_ids: Iterable[int]
) -> dict[int, str]:
    """signature id -> when its newest stored critical or warning event
    happened, for the given signatures of a source."""
    wanted = sorted({int(s) for s in signature_ids})
    if not wanted:
        return {}
    rows = await _select(
        "SELECT signature_id, MAX(occurred_at) AS newest FROM security_events"
        " WHERE provider = ? AND org_ref = ? AND kind = ? AND severity IN (?, ?)"
        f" AND signature_id IN ({_marks(len(wanted))}) GROUP BY signature_id",  # nosec B608 - placeholders only
        (provider, int(org_ref), kind, *ALERTING_SEVERITIES, *wanted),
    )
    return {int(r["signature_id"]): str(r["newest"]) for r in rows}


def _filters(
    *,
    provider: str | None,
    org_ref: int | None,
    host_id: int | None,
    kind: str | None,
    severity: str | None,
    action: str | None,
    since: str | None,
    search: str | None,
    host_ids: Iterable[int] | None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (
        ("e.provider", provider),
        ("e.kind", kind),
        ("e.severity", severity),
        ("e.action", action),
    ):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    if org_ref is not None:
        clauses.append("e.org_ref = ?")
        params.append(int(org_ref))
    if host_id is not None:
        clauses.append("e.host_id = ?")
        params.append(int(host_id))
    if since:
        clauses.append("e.occurred_at >= ?")
        params.append(since)
    if search and search.strip():
        clauses.append(
            "(lower(e.signature) LIKE ? OR lower(e.category) LIKE ? OR e.src_ip LIKE ? OR e.dest_ip LIKE ?"
            " OR CAST(e.signature_id AS TEXT) LIKE ?)"
        )
        params += [_like(search)] * 5
    scope_sql, scope_params = group_ids_condition("e.host_id", host_ids)
    if scope_sql:
        clauses.append(scope_sql)
        params.extend(scope_params)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


async def list_security_events(
    *,
    provider: str | None = None,
    org_ref: int | None = None,
    host_id: int | None = None,
    kind: str | None = None,
    severity: str | None = None,
    action: str | None = None,
    since: str | None = None,
    search: str | None = None,
    host_ids: Iterable[int] | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """The events matching the filters, newest first (``events``), how many
    match (``total``) and how many of each severity and action
    (``counts``). ``host_ids`` keeps the events of those inventory hosts
    (object scope: an event with no host is left out); ``search`` matches
    the signature, its id, the category and the addresses."""
    where, params = _filters(
        provider=provider,
        org_ref=org_ref,
        host_id=host_id,
        kind=kind,
        severity=severity,
        action=action,
        since=since,
        search=search,
        host_ids=host_ids,
    )
    rows = await _select(
        "SELECT e.id, e.provider, e.org_ref, e.source_name, e.host_id, h.hostname, e.kind, e.occurred_at,"
        " e.received_at, e.severity, e.priority, e.signature_id, e.signature, e.category, e.action, e.protocol,"
        " e.src_ip, e.src_port, e.dest_ip, e.dest_port, e.interface, e.flow_id, e.app_proto"
        " FROM security_events e LEFT JOIN hosts h ON h.id = e.host_id"
        + where  # nosec B608 - fixed clauses, placeholders only
        + " ORDER BY e.occurred_at DESC, e.id DESC LIMIT ? OFFSET ?",
        (*params, int(limit), int(offset)),
    )
    counted = await _select(
        "SELECT e.severity, e.action, COUNT(*) AS n FROM security_events e"
        + where  # nosec B608 - fixed clauses, placeholders only
        + " GROUP BY e.severity, e.action",
        tuple(params),
    )
    counts: dict[str, int] = {**dict.fromkeys(SEVERITIES, 0), "blocked": 0}
    total = 0
    for row in counted:
        n = int(row["n"] or 0)
        total += n
        counts[str(row["severity"] or "unknown")] = counts.get(str(row["severity"] or "unknown"), 0) + n
        if row["action"] == "blocked":
            counts["blocked"] += n
    return {"events": rows, "total": total, "counts": counts}


async def count_security_events(provider: str, org_ref: int, kind: str, since: str) -> dict[str, int]:
    """How many events of a source and kind happened since ``since``, by
    severity, and how many of them were blocked."""
    found = await list_security_events(provider=provider, org_ref=org_ref, kind=kind, since=since, limit=1)
    return {**found["counts"], "total": found["total"]}


async def purge_security_events(retention_days: int) -> int:
    """Remove the events older than ``retention_days``."""
    return await _dbcore.chunked_delete(
        "security_events", "occurred_at < datetime('now', '-' || ? || ' days')", (int(retention_days),)
    )


async def resolve_security_event_alerts(alert_type: str, dedup_prefix: str, resolved_by: str) -> int:
    """Acknowledge as ``resolved_by`` the open monitoring alerts of
    ``alert_type`` whose dedup key starts with ``dedup_prefix`` (the
    security event alerts of one source). Returns how many were open."""
    if not dedup_prefix:
        return 0
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """UPDATE monitoring_alerts
               SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = datetime('now')
               WHERE alert_type = ? AND acknowledged = 0 AND substr(dedup_key, 1, ?) = ?""",
            (resolved_by, alert_type, len(dedup_prefix), dedup_prefix),
        )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()
