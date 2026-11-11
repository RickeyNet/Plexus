"""Near-real-time Meraki alerts (polled assurance alerts and webhooks).

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Table (migration 0081): ``meraki_alerts``, one row per alert key
(``netcontrol.integrations.meraki.alerts.alert_key``). An open event for a
key opens or refreshes its row; a resolved event closes it; a closed row is
reopened only by an event that started after it was resolved, so a late or
retried delivery of an old alert does not reopen it. ``alert_state`` is the
severity an alert was raised at (``""`` when none), so a row alerts once
while it stays open, again only if it gets worse, and its alert is cleared
when the row resolves.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as _dbcore
from routes.database import rows_to_list

__all__ = [
    "apply_meraki_alert_events",
    "expire_meraki_webhook_alerts",
    "list_meraki_alerts",
    "meraki_device_down_alerted",
    "purge_meraki_alerts",
    "resolve_missing_meraki_alerts",
    "set_meraki_alert_raised",
]

_FMT = "%Y-%m-%d %H:%M:%S"
# Copied from an event onto its row on every update.
_FIELDS = (
    "org_ref",
    "org_id",
    "org_name",
    "network_id",
    "network_name",
    "device_serial",
    "device_name",
    "device_model",
    "product_type",
    "alert_type",
    "condition",
    "category",
    "title",
    "message",
    "severity",
    "meraki_alert_id",
)
_ALERTING = ("warning", "critical")
_RANK = {"": 0, "info": 1, "warning": 2, "critical": 3}


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def _values(event: dict) -> tuple:
    return tuple(int(event.get(f) or 0) if f == "org_ref" else str(event.get(f) or "") for f in _FIELDS)


def _row(row: dict) -> dict:
    item = dict(row)
    try:
        item["detail"] = json.loads(item.pop("detail_json", None) or "{}")
    except TypeError, ValueError:
        item["detail"] = {}
    item["seen_via"] = [v for v in str(item.get("seen_via") or "").split(",") if v]
    return item


def _merge_via(stored: str, source: str) -> str:
    vias = [v for v in str(stored or "").split(",") if v]
    if source and source not in vias:
        vias.append(source)
    return ",".join(sorted(vias))


def _worse(a: str, b: str) -> str:
    return a if _RANK.get(a, 0) >= _RANK.get(b, 0) else b


def _merge_events(events: list[dict]) -> list[dict]:
    """One event per key and state, the worst severity kept: two assurance
    alerts of one condition on one device are one Plexus alert."""
    merged: dict[tuple[str, str], dict] = {}
    for event in events:
        slot = (str(event["key"]), str(event.get("state") or "open"))
        if slot in merged:
            kept = merged[slot]
            kept["severity"] = _worse(str(event.get("severity") or ""), str(kept.get("severity") or ""))
        else:
            merged[slot] = dict(event)
    return list(merged.values())


async def list_meraki_alerts(
    *, include_resolved: bool = False, org_ref: int | None = None, limit: int = 500
) -> list[dict]:
    """The alerts, open first, then the worst and the most recent first."""
    clauses: list[str] = []
    params: list[Any] = []
    if not include_resolved:
        clauses.append("status = 'open'")
    if org_ref is not None:
        clauses.append("org_ref = ?")
        params.append(int(org_ref))
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, int(limit)))
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT * FROM meraki_alerts {where}
                ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END,
                         CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
                         last_seen DESC, alert_key
                LIMIT ?""",
            tuple(params),
        )
        return [_row(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def apply_meraki_alert_events(events: list[dict], *, now: str | None = None) -> dict[str, Any]:
    """Record normalised alert events from either path.

    Returns ``{"new", "updated", "reopened", "resolved", "alerts",
    "clears"}``: ``alerts`` the open rows that need an alert raised (new,
    reopened, or worse than the alert already raised), ``clears`` the rows
    that were resolved with an alert raised (to be cleared)."""
    now = now or _now()
    events = _merge_events([e for e in events if e and e.get("key")])
    if not events:
        return {"new": 0, "updated": 0, "reopened": 0, "resolved": 0, "alerts": [], "clears": []}
    keys = sorted({str(e["key"]) for e in events})
    counts = {"new": 0, "updated": 0, "reopened": 0, "resolved": 0}
    alerts: list[dict] = []
    clears: list[dict] = []
    columns = ", ".join(_FIELDS)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"SELECT * FROM meraki_alerts WHERE alert_key IN ({', '.join('?' for _ in keys)})",
            tuple(keys),
        )
        stored = {str(r["alert_key"]): r for r in rows_to_list(await cursor.fetchall())}
        # Open events first, so a batch holding both ends of one alert closes it.
        for event in sorted(events, key=lambda e: 0 if e.get("state") != "resolved" else 1):
            key = str(event["key"])
            row = stored.get(key)
            source = str(event.get("source") or "")
            detail = json.dumps(event.get("detail") or {}, sort_keys=True, default=str)
            if event.get("state") == "resolved":
                if row is None or row["status"] != "open":
                    continue
                resolved_at = str(event.get("resolved_at") or now)
                await db.execute(
                    """UPDATE meraki_alerts
                       SET status = 'resolved', resolved_at = ?, last_seen = ?, last_source = ?,
                           seen_via = ?, alert_state = ''
                       WHERE alert_key = ?""",
                    (resolved_at, now, source, _merge_via(row["seen_via"], source), key),
                )
                counts["resolved"] += 1
                if row.get("alert_state"):
                    clears.append(dict(row))
                stored[key] = {**row, "status": "resolved", "resolved_at": resolved_at, "alert_state": ""}
                continue
            started = str(event.get("started_at") or "")
            if row is None:
                await db.execute(
                    f"""INSERT INTO meraki_alerts
                        (alert_key, {columns}, status, started_at, resolved_at, first_seen, last_seen,
                         seen_via, last_source, occurrences, detail_json, alert_state, alert_via)
                        VALUES (?, {", ".join("?" for _ in _FIELDS)}, 'open', ?, '', ?, ?, ?, ?, 1, ?, '', '')""",
                    (key, *_values(event), started or now, now, now, source, source, detail),
                )
                counts["new"] += 1
                fresh = {**event, "alert_key": key, "status": "open", "alert_state": ""}
                stored[key] = fresh
                if event.get("severity") in _ALERTING:
                    alerts.append(fresh)
                continue
            if row["status"] != "open":
                # Reopen only for an occurrence that began after the close.
                if not started or started <= str(row.get("resolved_at") or ""):
                    continue
                await db.execute(
                    f"""UPDATE meraki_alerts
                        SET {", ".join(f"{f} = ?" for f in _FIELDS)}, status = 'open', started_at = ?,
                            resolved_at = '', first_seen = ?, last_seen = ?, seen_via = ?, last_source = ?,
                            occurrences = occurrences + 1, detail_json = ?, alert_state = '', alert_via = ''
                        WHERE alert_key = ?""",
                    (*_values(event), started, now, now, source, source, detail, key),
                )
                counts["reopened"] += 1
                fresh = {**event, "alert_key": key, "status": "open", "alert_state": ""}
                stored[key] = fresh
                if event.get("severity") in _ALERTING:
                    alerts.append(fresh)
                continue
            # Still open: refresh it, keeping what the other path knew.
            severity = str(event.get("severity") or row["severity"])
            merged = {k: (str(event.get(k) or "") or str(row.get(k) or "")) for k in _FIELDS if k != "org_ref"}
            merged["severity"] = severity
            await db.execute(
                f"""UPDATE meraki_alerts
                    SET {", ".join(f"{f} = ?" for f in _FIELDS if f != "org_ref")},
                        started_at = ?, last_seen = ?, seen_via = ?, last_source = ?,
                        occurrences = occurrences + ?, detail_json = ?
                    WHERE alert_key = ?""",
                (
                    *(merged[f] for f in _FIELDS if f != "org_ref"),
                    min(filter(None, (started, str(row.get("started_at") or ""))), default=now),
                    now,
                    _merge_via(row["seen_via"], source),
                    source,
                    # A poll re-reading the same alert is not a new occurrence.
                    0 if source == "poll" and "poll" in str(row["seen_via"]).split(",") else 1,
                    detail if detail != "{}" else str(row.get("detail_json") or "{}"),
                    key,
                ),
            )
            counts["updated"] += 1
            alerted = str(row.get("alert_state") or "")
            if severity in _ALERTING and _RANK.get(severity, 0) > _RANK.get(alerted, 0):
                alerts.append({**row, **merged, "alert_key": key, "org_ref": row["org_ref"], "status": "open"})
        await db.commit()
    finally:
        await db.close()
    return {**counts, "alerts": alerts, "clears": clears}


async def _resolve_where(where: str, params: tuple, now: str) -> list[dict]:
    """Resolve the open rows matching ``where``; returns them as they were."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(f"SELECT * FROM meraki_alerts WHERE status = 'open' AND {where}", params)
        rows = rows_to_list(await cursor.fetchall())
        if rows:
            await db.executemany(
                """UPDATE meraki_alerts SET status = 'resolved', resolved_at = ?, alert_state = ''
                   WHERE alert_key = ?""",
                [(now, r["alert_key"]) for r in rows],
            )
            await db.commit()
        return rows
    finally:
        await db.close()


async def resolve_missing_meraki_alerts(org_ref: int, active_keys: set[str], *, now: str | None = None) -> list[dict]:
    """After a successful poll of one source: resolve its open alerts that
    the poll reported before and no longer does (the assurance alert was
    resolved or dismissed). Alerts only a webhook reported are left alone."""
    now = now or _now()
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT alert_key, seen_via FROM meraki_alerts WHERE status = 'open' AND org_ref = ?",
            (int(org_ref),),
        )
        candidates = [
            str(r["alert_key"])
            for r in rows_to_list(await cursor.fetchall())
            if "poll" in str(r["seen_via"]).split(",") and str(r["alert_key"]) not in active_keys
        ]
    finally:
        await db.close()
    if not candidates:
        return []
    return await _resolve_where(
        f"alert_key IN ({', '.join('?' for _ in candidates)})",
        tuple(candidates),
        now,
    )


async def expire_meraki_webhook_alerts(ttl_hours: int, *, now: str | None = None) -> list[dict]:
    """Resolve the open alerts only a webhook reported whose last event is
    older than ``ttl_hours``: many webhook types have no recovery event."""
    now = now or _now()
    cutoff = (datetime.strptime(now, _FMT) - timedelta(hours=max(1, int(ttl_hours)))).strftime(_FMT)
    return await _resolve_where("seen_via = 'webhook' AND last_seen < ?", (cutoff,), now)


async def set_meraki_alert_raised(alert_key: str, severity: str, via: str, host_id: int | None = None) -> None:
    """Record that an alert was raised for a row at ``severity``: ``via`` is
    ``monitoring`` (on an inventory host), ``notification`` (the channels)
    or ``topology`` (already notified by the topology availability tracker)."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE meraki_alerts SET alert_state = ?, alert_via = ?, host_id = ? WHERE alert_key = ?",
            (severity, via, host_id, alert_key),
        )
        await db.commit()
    finally:
        await db.close()


async def meraki_device_down_alerted(org_ref: int, serial: str) -> bool:
    """Whether an open device-down Meraki alert for this device has already
    been raised, so the topology availability tracker need not raise the
    same condition again."""
    if not serial:
        return False
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT 1 FROM meraki_alerts
               WHERE org_ref = ? AND device_serial = ? AND condition = 'device_down'
                 AND status = 'open' AND alert_state <> ''
               LIMIT 1""",
            (int(org_ref), serial.upper()),
        )
        return (await cursor.fetchone()) is not None
    finally:
        await db.close()


async def purge_meraki_alerts(retention_days: int) -> int:
    """Delete the alerts resolved more than ``retention_days`` ago."""
    cutoff = (datetime.now(UTC) - timedelta(days=max(1, int(retention_days)))).strftime(_FMT)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM meraki_alerts WHERE status = 'resolved' AND resolved_at <> '' AND resolved_at < ?",
            (cutoff,),
        )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()
