"""Meraki compliance persistence helpers.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables (migration 0068): ``meraki_compliance_assignments`` (a compliance
profile bound to a Meraki organization on a schedule) and
``meraki_compliance_results`` (one row per scanned target - organization,
network or switch - with the findings as JSON; ``scan_id`` groups the rows
of one scan).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import routes.database as _dbcore
from routes.database import _is_unique_violation, _safe_dynamic_update, row_to_dict, rows_to_list

__all__ = [
    "create_meraki_compliance_assignment",
    "get_meraki_compliance_assignment",
    "list_meraki_compliance_assignments",
    "update_meraki_compliance_assignment",
    "delete_meraki_compliance_assignment",
    "get_meraki_compliance_assignments_due",
    "record_meraki_compliance_assignment_scan",
    "store_meraki_compliance_results",
    "list_meraki_compliance_results",
    "get_meraki_compliance_result",
    "delete_meraki_compliance_result",
    "delete_old_meraki_compliance_results",
    "get_meraki_compliance_status",
    "get_meraki_compliance_summary",
]

_ASSIGNMENT_COLUMNS = (
    "a.id, a.profile_id, a.org_ref, a.enabled, a.interval_seconds, a.last_scan_at, a.last_scan_status, "
    "a.last_scan_message, a.assigned_at, a.assigned_by, p.name AS profile_name, p.severity AS profile_severity, "
    "o.name AS org_name, o.provider AS org_provider, (o.api_key_enc <> '') AS org_has_api_key, o.org_id AS org_identifier"
)
_ASSIGNMENT_JOINS = (
    "FROM meraki_compliance_assignments a "
    "LEFT JOIN compliance_profiles p ON p.id = a.profile_id "
    "LEFT JOIN meraki_orgs o ON o.id = a.org_ref"
)
_RESULT_COLUMNS = (
    "r.id, r.scan_id, r.assignment_id, r.profile_id, r.org_ref, r.target_kind, r.target_id, r.target_name, "
    "r.network_id, r.network_name, r.model, r.serial, r.status, r.total_rules, r.passed_rules, r.failed_rules, "
    "r.unreadable_rules, r.scanned_at, p.name AS profile_name, o.name AS org_name"
)
_RESULT_JOINS = (
    "FROM meraki_compliance_results r "
    "LEFT JOIN compliance_profiles p ON p.id = r.profile_id "
    "LEFT JOIN meraki_orgs o ON o.id = r.org_ref"
)
_UPDATABLE_ASSIGNMENT_FIELDS = {"enabled", "interval_seconds"}


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def _assignment_row(row) -> dict | None:
    item = row_to_dict(row)
    if item is None:
        return None
    item["enabled"] = bool(item.get("enabled"))
    item["org_has_api_key"] = bool(item.get("org_has_api_key"))
    return item


# ── Assignments ──────────────────────────────────────────────────────────────


async def create_meraki_compliance_assignment(
    profile_id: int,
    org_ref: int,
    *,
    interval_seconds: int = 86400,
    assigned_by: str = "",
) -> int | None:
    """Bind a profile to a Meraki organization. ``None`` if already bound."""
    db = await _dbcore.get_db()
    try:
        try:
            cursor = await db.execute(
                """INSERT INTO meraki_compliance_assignments
                   (profile_id, org_ref, enabled, interval_seconds, assigned_at, assigned_by)
                   VALUES (?, ?, 1, ?, ?, ?)""",
                (profile_id, org_ref, int(interval_seconds), _now(), assigned_by),
            )
        except Exception as exc:
            if _is_unique_violation(exc):
                return None
            raise
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_meraki_compliance_assignment(assignment_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT {_ASSIGNMENT_COLUMNS} {_ASSIGNMENT_JOINS} WHERE a.id = ?",
            (assignment_id,),
        )
        return _assignment_row(await cursor.fetchone())
    finally:
        await db.close()


async def list_meraki_compliance_assignments(
    profile_id: int | None = None,
    org_ref: int | None = None,
) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        where: list[str] = []
        params: list = []
        if profile_id is not None:
            where.append("a.profile_id = ?")
            params.append(profile_id)
        if org_ref is not None:
            where.append("a.org_ref = ?")
            params.append(org_ref)
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        cursor = await db.execute(
            f"SELECT {_ASSIGNMENT_COLUMNS} {_ASSIGNMENT_JOINS} {where_sql} ORDER BY o.name, p.name",
            tuple(params),
        )
        return [a for a in (_assignment_row(r) for r in await cursor.fetchall()) if a]
    finally:
        await db.close()


async def update_meraki_compliance_assignment(assignment_id: int, **kwargs) -> None:
    fields = [f"{k} = ?" for k in kwargs if k in _UPDATABLE_ASSIGNMENT_FIELDS]
    values = [kwargs[k] for k in kwargs if k in _UPDATABLE_ASSIGNMENT_FIELDS]
    if not fields:
        return
    query, params = _safe_dynamic_update("meraki_compliance_assignments", fields, values, "id = ?", assignment_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(query, params)
        await db.commit()
    finally:
        await db.close()


async def delete_meraki_compliance_assignment(assignment_id: int) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM meraki_compliance_assignments WHERE id = ?", (assignment_id,))
        await db.commit()
    finally:
        await db.close()


async def get_meraki_compliance_assignments_due() -> list[dict]:
    """Enabled assignments whose interval has elapsed since their last scan."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT {_ASSIGNMENT_COLUMNS} {_ASSIGNMENT_JOINS}
                WHERE a.enabled = 1
                  AND (a.last_scan_at IS NULL OR a.last_scan_at = ''
                       OR datetime(a.last_scan_at, '+' || a.interval_seconds || ' seconds') <= datetime('now'))
                ORDER BY a.last_scan_at"""
        )
        return [a for a in (_assignment_row(r) for r in await cursor.fetchall()) if a]
    finally:
        await db.close()


async def record_meraki_compliance_assignment_scan(assignment_id: int, status: str, message: str = "") -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE meraki_compliance_assignments SET last_scan_at = ?, last_scan_status = ?, last_scan_message = ? "
            "WHERE id = ?",
            (_now(), status, message[:500], assignment_id),
        )
        await db.commit()
    finally:
        await db.close()


# ── Results ──────────────────────────────────────────────────────────────────


async def store_meraki_compliance_results(
    *,
    scan_id: str,
    assignment_id: int | None,
    profile_id: int,
    org_ref: int,
    results: list[dict],
) -> list[int]:
    """Insert the targets of one scan in a single transaction. Returns the row ids."""
    now = _now()
    ids: list[int] = []
    db = await _dbcore.get_db()
    try:
        for r in results:
            cursor = await db.execute(
                """INSERT INTO meraki_compliance_results
                   (scan_id, assignment_id, profile_id, org_ref, target_kind, target_id, target_name,
                    network_id, network_name, model, serial, status, total_rules, passed_rules,
                    failed_rules, unreadable_rules, findings, scanned_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    assignment_id,
                    profile_id,
                    org_ref,
                    str(r.get("target_kind") or "network"),
                    str(r.get("target_id") or ""),
                    str(r.get("target_name") or ""),
                    str(r.get("network_id") or ""),
                    str(r.get("network_name") or ""),
                    str(r.get("model") or ""),
                    str(r.get("serial") or ""),
                    str(r.get("status") or "compliant"),
                    int(r.get("total_rules") or 0),
                    int(r.get("passed_rules") or 0),
                    int(r.get("failed_rules") or 0),
                    int(r.get("unreadable_rules") or 0),
                    json.dumps(r.get("findings") or []),
                    now,
                ),
            )
            ids.append(cursor.lastrowid)
        await db.commit()
        return ids
    finally:
        await db.close()


async def list_meraki_compliance_results(
    *,
    org_ref: int | None = None,
    profile_id: int | None = None,
    assignment_id: int | None = None,
    scan_id: str | None = None,
    status: str | None = None,
    target_kind: str | None = None,
    limit: int = 200,
) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        where: list[str] = []
        params: list = []
        for column, value in (
            ("r.org_ref", org_ref),
            ("r.profile_id", profile_id),
            ("r.assignment_id", assignment_id),
            ("r.scan_id", scan_id),
            ("r.status", status),
            ("r.target_kind", target_kind),
        ):
            if value is not None:
                where.append(f"{column} = ?")
                params.append(value)
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        params.append(int(limit))
        cursor = await db.execute(
            f"SELECT {_RESULT_COLUMNS} {_RESULT_JOINS} {where_sql} ORDER BY r.id DESC LIMIT ?",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_meraki_compliance_result(result_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT {_RESULT_COLUMNS}, r.findings {_RESULT_JOINS} WHERE r.id = ?",
            (result_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def delete_meraki_compliance_result(result_id: int) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM meraki_compliance_results WHERE id = ?", (result_id,))
        await db.commit()
    finally:
        await db.close()


async def delete_old_meraki_compliance_results(days: int = 90) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM meraki_compliance_results WHERE scanned_at < datetime('now', '-' || ? || ' days')",
            (int(days),),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_meraki_compliance_status(
    profile_id: int | None = None,
    org_ref: int | None = None,
) -> list[dict]:
    """Latest result per (target, profile)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        where: list[str] = []
        params: list = []
        if profile_id is not None:
            where.append("r.profile_id = ?")
            params.append(profile_id)
        if org_ref is not None:
            where.append("r.org_ref = ?")
            params.append(org_ref)
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        cursor = await db.execute(
            f"""SELECT {_RESULT_COLUMNS} {_RESULT_JOINS}
                INNER JOIN (
                    SELECT org_ref, target_kind, target_id, profile_id, MAX(id) AS max_id
                    FROM meraki_compliance_results
                    GROUP BY org_ref, target_kind, target_id, profile_id
                ) latest ON r.id = latest.max_id
                {where_sql}
                ORDER BY CASE r.status WHEN 'non-compliant' THEN 0 WHEN 'error' THEN 1 ELSE 2 END,
                         o.name, r.target_kind, r.target_name""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_meraki_compliance_summary() -> dict:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM meraki_compliance_assignments WHERE enabled = 1")
        row = await cursor.fetchone()
        active_assignments = row[0] if row else 0

        cursor = await db.execute(
            """SELECT r.status, COUNT(*) FROM meraki_compliance_results r
               INNER JOIN (
                   SELECT MAX(id) AS max_id FROM meraki_compliance_results
                   GROUP BY org_ref, target_kind, target_id, profile_id
               ) latest ON r.id = latest.max_id
               GROUP BY r.status"""
        )
        by_status = {str(r[0]): int(r[1]) for r in await cursor.fetchall()}

        cursor = await db.execute("SELECT MAX(scanned_at) FROM meraki_compliance_results")
        row = await cursor.fetchone()
        last_scan_at = row[0] if row else None
        targets = sum(by_status.values())
        return {
            "active_assignments": active_assignments,
            "targets_scanned": targets,
            "targets_non_compliant": by_status.get("non-compliant", 0),
            "targets_error": by_status.get("error", 0),
            "last_scan_at": last_scan_at or None,
        }
    finally:
        await db.close()
