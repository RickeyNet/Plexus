"""Vendor alert feeds: storage only (the Cato events feed first).

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables (migration 0132):

  - ``vendor_alerts``: one row per ``(provider, alert_key)``. The provider
    builds the key from the source, the entity and the condition (see
    ``netcontrol.routes.vendor_alerts``). Events are applied in the order
    they happened: an open event opens or refreshes its row, a resolved
    event (a recovery) closes it, and a closed row is reopened only by an
    event that started after it was resolved, so a replayed or late event
    never reopens it. ``alert_state`` is the severity an alert was raised
    at (``""`` when none): a row alerts once while it stays open, again
    only if it gets worse, and its alert is cleared when the row resolves.
  - ``vendor_alert_feeds``: per source and feed, the vendor's cursor, the
    poll lease (one app worker polls a source at a time), the back-off and
    the status of the last poll.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text, so they compare as text.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as _dbcore
from routes.database import rows_to_list
from routes.db.inventory import group_ids_condition

__all__ = [
    "SEVERITY_RANK",
    "apply_vendor_alert_events",
    "claim_vendor_alert_feed",
    "expire_vendor_alerts",
    "list_open_vendor_alert_keys",
    "list_vendor_alert_feeds",
    "list_vendor_alerts",
    "merge_alert_events",
    "purge_vendor_alerts",
    "record_vendor_alert_feed_poll",
    "release_vendor_alert_feed",
    "resolve_vendor_alerts",
    "save_vendor_alert_feed_cursor",
    "set_vendor_alert_raised",
    "vendor_alert_covers_entity",
    "worse_severity",
]

_FMT = "%Y-%m-%d %H:%M:%S"
# Copied from an event onto its row when it opens or reopens.
_FIELDS = (
    "org_ref",
    "org_name",
    "entity_type",
    "entity_id",
    "entity_name",
    "site",
    "serial",
    "condition",
    "event_type",
    "event_sub_type",
    "title",
    "message",
    "severity",
    "tracker_scope",
    "vendor_event_id",
)
_INT_FIELDS = ("org_ref",)
ALERTING = ("warning", "critical")
SEVERITY_RANK = {"": 0, "info": 1, "warning": 2, "critical": 3}
# Entity types a ``site_links`` alert covers in the availability tracker.
LINK_ENTITY_TYPES = ("uplink", "tunnel", "link")
# Bound on the detail kept per row (JSON characters).
MAX_DETAIL_CHARS = 4000


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def worse_severity(a: str, b: str) -> str:
    """The worse of two severities (``critical`` > ``warning`` > ``info``)."""
    return a if SEVERITY_RANK.get(a, 0) >= SEVERITY_RANK.get(b, 0) else b


def merge_alert_events(events: list[dict]) -> list[dict]:
    """One event per key and state, the worst severity kept (used by the
    Meraki feed, whose two paths report the same alert)."""
    merged: dict[tuple[str, str], dict] = {}
    for event in events:
        slot = (str(event["key"]), str(event.get("state") or "open"))
        if slot in merged:
            kept = merged[slot]
            kept["severity"] = worse_severity(str(event.get("severity") or ""), str(kept.get("severity") or ""))
        else:
            merged[slot] = dict(event)
    return list(merged.values())


def _values(event: dict) -> tuple:
    return tuple(int(event.get(f) or 0) if f in _INT_FIELDS else str(event.get(f) or "") for f in _FIELDS)


def _detail(event: dict) -> str:
    text = json.dumps(event.get("detail") or {}, sort_keys=True, default=str)
    return text if len(text) <= MAX_DETAIL_CHARS else json.dumps({"truncated": True, "size": len(text)})


def _when(event: dict) -> str:
    return str(event.get("started_at") or event.get("resolved_at") or "")


def _row(row: dict) -> dict:
    item = dict(row)
    try:
        item["detail"] = json.loads(item.pop("detail_json", None) or "{}")
    except TypeError, ValueError:
        item["detail"] = {}
    item["auto_expire"] = bool(item.get("auto_expire"))
    return item


async def list_vendor_alerts(
    *,
    provider: str | None = None,
    include_resolved: bool = False,
    org_ref: int | None = None,
    limit: int = 500,
    host_ids: Iterable[int] | None = None,
) -> list[dict]:
    """The alerts, open first, then the worst and the most recent first.
    ``host_ids`` keeps the alerts raised on those inventory hosts (object
    scope: an alert with no inventory host is left out)."""
    clauses: list[str] = []
    params: list[Any] = []
    if provider:
        clauses.append("provider = ?")
        params.append(provider)
    if not include_resolved:
        clauses.append("status = 'open'")
    if org_ref is not None:
        clauses.append("org_ref = ?")
        params.append(int(org_ref))
    scope_sql, scope_params = group_ids_condition("host_id", host_ids)
    if scope_sql:
        clauses.append(scope_sql)
        params.extend(scope_params)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, int(limit)))
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT * FROM vendor_alerts {where}
                ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END,
                         CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
                         last_seen DESC, alert_key
                LIMIT ?""",  # nosec B608 - fixed clauses, placeholders only
            tuple(params),
        )
        return [_row(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def apply_vendor_alert_events(provider: str, events: list[dict], *, now: str | None = None) -> dict[str, Any]:
    """Record normalised alert events of one provider, in the order they
    happened (a feed reports a down and its recovery in sequence).

    Each event: ``key``, ``state`` (``open`` / ``resolved``), the fields of
    ``_FIELDS``, ``started_at`` (open) or ``resolved_at`` (resolved),
    ``auto_expire`` and ``detail``. Returns ``{"new", "updated",
    "reopened", "resolved", "alerts", "clears"}``: ``alerts`` the rows left
    open that need an alert raised (new, reopened or worse than the alert
    already raised), ``clears`` the rows resolved with an alert raised."""
    now = now or _now()
    events = sorted((e for e in events if e and e.get("key")), key=_when)
    if not events:
        return {"new": 0, "updated": 0, "reopened": 0, "resolved": 0, "alerts": [], "clears": []}
    keys = sorted({str(e["key"]) for e in events})
    counts = {"new": 0, "updated": 0, "reopened": 0, "resolved": 0}
    alerts: dict[str, dict] = {}
    clears: list[dict] = []
    columns = ", ".join(_FIELDS)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"SELECT * FROM vendor_alerts WHERE provider = ? AND alert_key IN ({', '.join('?' for _ in keys)})",  # nosec B608 - placeholders only
            (provider, *keys),
        )
        stored = {str(r["alert_key"]): r for r in rows_to_list(await cursor.fetchall())}
        for event in events:
            key = str(event["key"])
            row = stored.get(key)
            if event.get("state") == "resolved":
                if row is None or row["status"] != "open":
                    continue
                resolved_at = str(event.get("resolved_at") or now)
                if resolved_at < str(row.get("started_at") or ""):
                    continue  # a recovery older than the outage it would close
                await db.execute(
                    """UPDATE vendor_alerts SET status = 'resolved', resolved_at = ?, last_seen = ?, alert_state = ''
                       WHERE provider = ? AND alert_key = ?""",
                    (resolved_at, now, provider, key),
                )
                counts["resolved"] += 1
                alerts.pop(key, None)
                if row.get("alert_state"):
                    clears.append(dict(row))
                stored[key] = {**row, "status": "resolved", "resolved_at": resolved_at, "alert_state": ""}
                continue
            started = str(event.get("started_at") or now)
            detail = _detail(event)
            expire = 1 if event.get("auto_expire") else 0
            if row is None:
                await db.execute(
                    f"""INSERT INTO vendor_alerts
                        (provider, alert_key, {columns}, status, auto_expire, started_at, resolved_at, first_seen,
                         last_seen, occurrences, detail_json, alert_state, alert_via)
                        VALUES (?, ?, {", ".join("?" for _ in _FIELDS)}, 'open', ?, ?, '', ?, ?, 1, ?, '', '')""",  # nosec B608 - fixed columns
                    (provider, key, *_values(event), expire, started, now, now, detail),
                )
                counts["new"] += 1
                fresh = {**event, "provider": provider, "alert_key": key, "status": "open", "alert_state": ""}
                stored[key] = {**fresh, "started_at": started, "resolved_at": ""}
                if event.get("severity") in ALERTING:
                    alerts[key] = fresh
                continue
            if row["status"] != "open":
                # Reopen only for an occurrence that began after the close. A
                # current-state read (``observed``) says what is open now,
                # whenever it began: an alarm that stayed in alarm while its
                # part was switched off, or that fired again within the
                # clock difference to the vendor, opens again.
                if started <= str(row.get("resolved_at") or "") and not event.get("observed"):
                    continue
                await db.execute(
                    f"""UPDATE vendor_alerts
                        SET {", ".join(f"{f} = ?" for f in _FIELDS)}, status = 'open', auto_expire = ?,
                            started_at = ?, resolved_at = '', last_seen = ?, occurrences = occurrences + 1,
                            detail_json = ?, alert_state = '', alert_via = ''
                        WHERE provider = ? AND alert_key = ?""",  # nosec B608 - fixed columns
                    (*_values(event), expire, started, now, detail, provider, key),
                )
                counts["reopened"] += 1
                fresh = {**event, "provider": provider, "alert_key": key, "status": "open", "alert_state": ""}
                stored[key] = {**fresh, "started_at": started, "resolved_at": "", "occurrences": 0}
                if event.get("severity") in ALERTING:
                    alerts[key] = fresh
                continue
            # Still open: one more occurrence; the severity only gets worse.
            severity = worse_severity(str(event.get("severity") or ""), str(row.get("severity") or ""))
            await db.execute(
                """UPDATE vendor_alerts
                   SET severity = ?, message = ?, last_seen = ?, occurrences = occurrences + 1, detail_json = ?,
                       vendor_event_id = ?
                   WHERE provider = ? AND alert_key = ?""",
                (
                    severity,
                    str(event.get("message") or row.get("message") or ""),
                    now,
                    detail,
                    str(event.get("vendor_event_id") or row.get("vendor_event_id") or ""),
                    provider,
                    key,
                ),
            )
            counts["updated"] += 1
            stored[key] = {**row, "severity": severity}
            alerted = str(row.get("alert_state") or "")
            if severity in ALERTING and SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(alerted, 0):
                alerts[key] = {**row, "severity": severity, "alert_key": key, "status": "open"}
        await db.commit()
    finally:
        await db.close()
    return {**counts, "alerts": list(alerts.values()), "clears": clears}


async def _resolve_where(provider: str, where: str, params: tuple, now: str) -> list[dict]:
    """Resolve the open rows matching ``where``; returns them as they were."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"SELECT * FROM vendor_alerts WHERE provider = ? AND status = 'open' AND {where}",  # nosec B608 - fixed clauses
            (provider, *params),
        )
        rows = rows_to_list(await cursor.fetchall())
        if rows:
            await db.executemany(
                """UPDATE vendor_alerts SET status = 'resolved', resolved_at = ?, alert_state = ''
                   WHERE provider = ? AND alert_key = ?""",
                [(now, provider, r["alert_key"]) for r in rows],
            )
            await db.commit()
        return rows
    finally:
        await db.close()


async def resolve_vendor_alerts(provider: str, keys: Iterable[str], *, now: str | None = None) -> list[dict]:
    """Resolve the open alerts with these keys (their condition cleared)."""
    wanted = sorted({str(k) for k in keys})
    if not wanted:
        return []
    return await _resolve_where(
        provider, f"alert_key IN ({', '.join('?' for _ in wanted)})", tuple(wanted), now or _now()
    )


async def list_open_vendor_alert_keys(provider: str, prefix: str) -> list[str]:
    """The keys of a provider's open alerts that start with ``prefix`` (one
    scope of a current-state feed: an account's region, a subscription)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT alert_key FROM vendor_alerts
               WHERE provider = ? AND status = 'open' AND substr(alert_key, 1, ?) = ?""",
            (provider, len(prefix), prefix),
        )
        return [str(r["alert_key"]) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def expire_vendor_alerts(provider: str, ttl_hours: int, *, now: str | None = None) -> list[dict]:
    """Resolve the open one-shot alerts (``auto_expire``: no recovery event
    exists for them) whose last event is older than ``ttl_hours``."""
    now = now or _now()
    cutoff = (datetime.strptime(now, _FMT) - timedelta(hours=max(1, int(ttl_hours)))).strftime(_FMT)
    return await _resolve_where(provider, "auto_expire = 1 AND last_seen < ?", (cutoff,), now)


async def set_vendor_alert_raised(
    provider: str, alert_key: str, severity: str, via: str, host_id: int | None = None
) -> None:
    """Record that an alert was raised for a row at ``severity``: ``via`` is
    ``monitoring`` (on an inventory host), ``notification`` (the channels),
    ``topology`` (the topology availability tracker already notified it) or
    ``muted`` (its entity or site is muted: recorded, not raised)."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE vendor_alerts SET alert_state = ?, alert_via = ?, host_id = ? WHERE provider = ? AND alert_key = ?",
            (severity, via, host_id, provider, alert_key),
        )
        await db.commit()
    finally:
        await db.close()


async def vendor_alert_covers_entity(provider: str, org_ref: int, entity_type: str, entity_id: str, site: str) -> bool:
    """Whether an open vendor alert already raised a notification for a
    topology entity, so the availability tracker need not raise the same
    condition again: an ``entity`` alert of that very entity, or, for an
    uplink, tunnel or link, a ``site_links`` alert of its site."""
    clauses = ["(tracker_scope = 'entity' AND entity_type = ? AND entity_id = ?)"]
    params: list[Any] = [entity_type, entity_id]
    if entity_type in LINK_ENTITY_TYPES and site:
        clauses.append("(tracker_scope = 'site_links' AND site = ?)")
        params.append(site)
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT 1 FROM vendor_alerts
                WHERE provider = ? AND org_ref = ? AND status = 'open' AND alert_via IN ('monitoring', 'notification')
                  AND ({" OR ".join(clauses)})
                LIMIT 1""",  # nosec B608 - fixed clauses, placeholders only
            (provider, int(org_ref), *params),
        )
        return (await cursor.fetchone()) is not None
    finally:
        await db.close()


async def purge_vendor_alerts(retention_days: int) -> int:
    """Delete the alerts resolved more than ``retention_days`` ago."""
    cutoff = (datetime.now(UTC) - timedelta(days=max(1, int(retention_days)))).strftime(_FMT)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM vendor_alerts WHERE status = 'resolved' AND resolved_at <> '' AND resolved_at < ?",
            (cutoff,),
        )
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()


# ── Feeds: cursor, lease, back-off, status ───────────────────────────────────


async def list_vendor_alert_feeds(provider: str, feed: str) -> list[dict]:
    """The feed rows of a provider (one per source polled at least once)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            "SELECT * FROM vendor_alert_feeds WHERE provider = ? AND feed = ? ORDER BY org_ref", (provider, feed)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def claim_vendor_alert_feed(
    provider: str, org_ref: int, feed: str, owner: str, lease_seconds: int, *, now: str | None = None
) -> dict | None:
    """Take the poll lease of a source's feed for ``owner`` (one app
    process) for ``lease_seconds``: granted when no one holds it, the owner
    already does, or the last lease ran out (a worker that died). Returns
    the feed row (cursor, back-off) when granted, else ``None``."""
    now = now or _now()
    until = (datetime.strptime(now, _FMT) + timedelta(seconds=max(1, int(lease_seconds)))).strftime(_FMT)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO vendor_alert_feeds (provider, org_ref, feed, lease_owner, lease_until)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (provider, org_ref, feed) DO UPDATE
                 SET lease_owner = excluded.lease_owner, lease_until = excluded.lease_until
                 WHERE vendor_alert_feeds.lease_owner = '' OR vendor_alert_feeds.lease_owner = excluded.lease_owner
                    OR vendor_alert_feeds.lease_until < ?
               RETURNING *""",
            (provider, int(org_ref), feed, owner, until, now),
        )
        rows = rows_to_list(await cursor.fetchall())
        await db.commit()
        return rows[0] if rows else None
    finally:
        await db.close()


async def release_vendor_alert_feed(provider: str, org_ref: int, feed: str, owner: str) -> None:
    """Give the lease back (only when ``owner`` still holds it)."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE vendor_alert_feeds SET lease_owner = '', lease_until = ''
               WHERE provider = ? AND org_ref = ? AND feed = ? AND lease_owner = ?""",
            (provider, int(org_ref), feed, owner),
        )
        await db.commit()
    finally:
        await db.close()


async def save_vendor_alert_feed_cursor(
    provider: str,
    org_ref: int,
    feed: str,
    owner: str,
    cursor_value: str,
    *,
    events: int = 0,
    last_event_at: str = "",
    now: str | None = None,
) -> bool:
    """Store the cursor a read ended at, after its events were stored, only
    while ``owner`` holds the lease (a worker whose lease ran out never
    moves the cursor back). Returns whether it was stored."""
    now = now or _now()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """UPDATE vendor_alert_feeds
               SET feed_cursor = ?, cursor_at = ?, events_read = events_read + ?,
                   last_event_at = CASE WHEN ? > last_event_at THEN ? ELSE last_event_at END
               WHERE provider = ? AND org_ref = ? AND feed = ? AND lease_owner = ?""",
            (str(cursor_value), now, int(events), last_event_at, last_event_at, provider, int(org_ref), feed, owner),
        )
        await db.commit()
        return bool(cursor.rowcount)
    finally:
        await db.close()


async def record_vendor_alert_feed_poll(
    provider: str,
    org_ref: int,
    feed: str,
    *,
    ok: bool,
    error: str = "",
    feed_status: str = "",
    failures: int = 0,
    next_poll_at: str = "",
    now: str | None = None,
) -> None:
    """Store the outcome of one poll of a source: its status, the error
    text (bounded), the failure count and when it may be polled again."""
    now = now or _now()
    db = await _dbcore.get_db()
    try:
        await db.execute(
            f"""UPDATE vendor_alert_feeds
               SET last_poll_at = ?, {"last_ok_at = ?," if ok else ""} last_error = ?, feed_status = ?,
                   failures = ?, next_poll_at = ?
               WHERE provider = ? AND org_ref = ? AND feed = ?""",  # nosec B608 - fixed clauses
            (
                now,
                *((now,) if ok else ()),
                str(error)[:500],
                str(feed_status)[:40],
                int(failures),
                next_poll_at,
                provider,
                int(org_ref),
                feed,
            ),
        )
        await db.commit()
    finally:
        await db.close()
