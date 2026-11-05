"""Findings of the Cato egress vs cloud allow-list check.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table (migration 0078): ``cato_egress_findings``, one row per finding key
(``netcontrol.integrations.cato.egress_check``). A run replaces the open set:
a finding seen again is updated, one no longer reported is resolved, and a
resolved one that comes back is reopened. ``alert_state`` is the severity an
alert was raised at (``warning``) or ``""``, so a finding alerts once while
it stays open and its alert is cleared when it resolves or turns
informational.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import routes.database as _dbcore
from routes.database import rows_to_list

__all__ = [
    "apply_cato_egress_findings",
    "list_cato_egress_findings",
    "set_cato_egress_alert_via",
]

_FIELDS = (
    "cato_org_ref",
    "cato_org_name",
    "provider",
    "resource_id",
    "resource_name",
    "public_ip",
    "private_ip",
    "protocol",
    "ports",
    "filter_name",
    "rule_name",
    "rule_id",
    "kind",
    "severity",
    "message",
)
_ALERTING = "warning"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def _values(finding: dict) -> tuple:
    renamed = {**finding, "filter_name": finding.get("filter", ""), "rule_name": finding.get("rule", "")}
    return tuple(int(renamed.get(f) or 0) if f == "cato_org_ref" else str(renamed.get(f) or "") for f in _FIELDS) + (
        json.dumps(finding.get("detail") or {}, sort_keys=True, default=str),
    )


def _row(row: dict) -> dict:
    item = dict(row)
    try:
        item["detail"] = json.loads(item.pop("detail_json", None) or "{}")
    except TypeError, ValueError:
        item["detail"] = {}
    return item


async def list_cato_egress_findings(include_resolved: bool = False, limit: int = 1000) -> list[dict]:
    """The findings, warnings first, then by Cato account and resource."""
    where = "" if include_resolved else "WHERE status = 'open'"
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT * FROM cato_egress_findings {where}
                ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END,
                         CASE severity WHEN 'warning' THEN 0 ELSE 1 END,
                         cato_org_ref, provider, resource_name, public_ip, ports, finding_key
                LIMIT ?""",
            (max(1, int(limit)),),
        )
        return [_row(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def apply_cato_egress_findings(
    findings: list[dict],
    *,
    keep_providers: set[str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Bring the stored findings up to date with one run of the check.

    An open finding missing from ``findings`` is resolved, unless its cloud
    provider is in ``keep_providers`` (that cloud could not be read this
    run). Returns ``{"open", "new", "resolved", "alerts", "clears"}``:
    ``alerts`` the warning findings that need an alert (new, reopened, or
    turned into a warning), ``clears`` the stored rows whose alert is to be
    cleared (resolved, or no longer a warning)."""
    now = now or _now()
    keep = keep_providers or set()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM cato_egress_findings")
        stored = {str(r["finding_key"]): r for r in rows_to_list(await cursor.fetchall())}
        inserts: list[tuple] = []
        updates: list[tuple] = []
        resolves: list[tuple] = []
        alerts: list[dict] = []
        clears: list[dict] = []
        seen: set[str] = set()
        for finding in findings:
            key = str(finding["key"])
            if key in seen:
                continue
            seen.add(key)
            row = stored.get(key)
            warning = finding.get("severity") == _ALERTING
            alert_state = str((row or {}).get("alert_state") or "") if row and row["status"] == "open" else ""
            if row is not None and row["status"] == "open" and row.get("alert_state") and not warning:
                clears.append(row)
            if warning and alert_state != _ALERTING:
                alerts.append(finding)
            new_state = _ALERTING if warning else ""
            if row is None:
                inserts.append((key, *_values(finding), "open", now, now, "", new_state))
            else:
                first_seen = row["first_seen"] if row["status"] == "open" else now
                updates.append((*_values(finding), "open", first_seen, now, "", new_state, key))
        for key, row in stored.items():
            if key in seen or row["status"] != "open" or str(row.get("provider") or "") in keep:
                continue
            resolves.append((now, key))
            if row.get("alert_state"):
                clears.append(row)
        columns = ", ".join(_FIELDS)
        if inserts:
            await db.executemany(
                f"""INSERT INTO cato_egress_findings
                    (finding_key, {columns}, detail_json, status, first_seen, last_seen, resolved_at, alert_state)
                    VALUES ({", ".join("?" for _ in range(len(_FIELDS) + 7))})""",
                inserts,
            )
        if updates:
            assignments = ", ".join(f"{f} = ?" for f in _FIELDS)
            await db.executemany(
                f"""UPDATE cato_egress_findings
                    SET {assignments}, detail_json = ?, status = ?, first_seen = ?, last_seen = ?,
                        resolved_at = ?, alert_state = ?
                    WHERE finding_key = ?""",
                updates,
            )
        if resolves:
            await db.executemany(
                """UPDATE cato_egress_findings
                   SET status = 'resolved', resolved_at = ?, alert_state = ''
                   WHERE finding_key = ?""",
                resolves,
            )
        await db.commit()
    finally:
        await db.close()
    return {
        "open": len(seen),
        "new": len(inserts),
        "resolved": len(resolves),
        "alerts": alerts,
        "clears": clears,
    }


async def set_cato_egress_alert_via(finding_key: str, via: str) -> None:
    """Record how a finding's alert was raised: ``monitoring`` (an alert on
    an inventory host) or ``notification`` (the notification channels)."""
    db = await _dbcore.get_db()
    try:
        await db.execute("UPDATE cato_egress_findings SET alert_via = ? WHERE finding_key = ?", (via, finding_key))
        await db.commit()
    finally:
        await db.close()
