"""Availability tracking of topology (API-collected) entities.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables (migration 0075): ``topology_entity_state`` (the current state of
every device, site, uplink, tunnel, VPN connection, circuit, peering and HA
link an integration's collection reported) and
``topology_availability_transitions`` (every state change).

Collections are sparse (an hourly cloud discovery, an on-demand Meraki build),
so uptime is time-weighted from the transitions, never counted per sample.
Time in ``unknown`` (not collected, pending, not in the last collection) is
left out of the uptime ratio; ``degraded`` counts as available.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as _dbcore
from routes.database import rows_to_list

__all__ = [
    "apply_topology_entity_states",
    "list_topology_entity_states",
    "get_topology_availability_summary",
    "get_topology_outages",
    "get_topology_transitions",
    "purge_topology_availability",
    "topology_uptime",
]

_FMT = "%Y-%m-%d %H:%M:%S"
# Alert severity of a state: an alert is raised when an entity gets worse
# than the alert already open for it.
_ALERT_RANK = {"degraded": 1, "down": 2}
_STATE_FIELDS = ("name", "site", "model", "host_id", "raw_status")


def _now() -> str:
    return datetime.now(UTC).strftime(_FMT)


def _parse(stamp: str | None) -> datetime | None:
    if not stamp:
        return None
    try:
        return datetime.strptime(str(stamp)[:19].replace("T", " "), _FMT)
    except ValueError:
        return None


def _fmt(moment: datetime) -> str:
    return moment.strftime(_FMT)


def _filters(
    alias: str,
    provider: str | None,
    org_ref: int | None,
    entity_type: str | None,
    entity_id: str | None = None,
) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (
        ("provider", provider),
        ("org_ref", org_ref),
        ("entity_type", entity_type),
        ("entity_id", entity_id),
    ):
        if value is not None and value != "":
            clauses.append(f"{alias}.{column} = ?")
            params.append(value)
    return clauses, params


def _key(row: dict) -> tuple[str, int, str, str]:
    return (str(row["provider"]), int(row["org_ref"]), str(row["entity_type"]), str(row["entity_id"]))


def _state_row(row: dict) -> dict:
    item = dict(row)
    try:
        item["meta"] = json.loads(item.pop("meta_json", None) or "{}")
    except TypeError, ValueError:
        item["meta"] = {}
    item["missing"] = bool(item.get("missing"))
    return item


# ── Recording ────────────────────────────────────────────────────────────────


async def list_topology_entity_states(
    provider: str | None = None,
    org_ref: int | None = None,
    entity_type: str | None = None,
) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        clauses, params = _filters("s", provider, org_ref, entity_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"SELECT s.* FROM topology_entity_state s {where} ORDER BY s.provider, s.org_ref, s.entity_type, s.name",
            tuple(params),
        )
        return [_state_row(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def apply_topology_entity_states(
    provider: str,
    org_ref: int,
    entities: list[dict],
    *,
    org_name: str = "",
    snapshot_ref: str = "",
    now: str | None = None,
) -> dict[str, Any]:
    """Bring the stored state of one organization / account up to date with
    the entities of its latest collection.

    ``entities`` are ``EntityState.as_dict()`` rows. A new entity is recorded
    with a transition from ``unknown`` (its baseline: it raises no alert). A
    stored entity absent from the collection turns ``unknown`` and is flagged
    ``missing``. Returns ``{"tracked", "new", "missing", "transitions",
    "alerts", "recoveries"}``: ``alerts`` are the transitions that need an
    alert (to ``degraded`` or ``down``, worse than the alert already open),
    ``recoveries`` the transitions back to ``up`` of an entity with one open.
    """
    now = now or _now()
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM topology_entity_state WHERE provider = ? AND org_ref = ?",
            (provider, org_ref),
        )
        stored = {_key(r): r for r in rows_to_list(await cursor.fetchall())}
        inserts: list[tuple] = []
        updates: list[tuple] = []
        transitions: list[dict] = []
        alerts: list[dict] = []
        recoveries: list[dict] = []
        seen: set[tuple[str, int, str, str]] = set()

        def transition(entity: dict, old: str, new: str, alert_state: str, *, baseline: bool) -> str:
            item = {
                "provider": provider,
                "org_ref": org_ref,
                "org_name": org_name,
                "entity_type": entity["entity_type"],
                "entity_id": entity["entity_id"],
                "name": entity.get("name") or "",
                "site": entity.get("site") or "",
                "model": entity.get("model") or "",
                "host_id": entity.get("host_id"),
                "old_state": old,
                "new_state": new,
                "transition_at": now,
                "snapshot_ref": snapshot_ref,
                "baseline": baseline,
            }
            transitions.append(item)
            rank = _ALERT_RANK.get(new, 0)
            if rank:
                if not baseline and rank > _ALERT_RANK.get(alert_state, 0):
                    alerts.append(item)
                return new if rank > _ALERT_RANK.get(alert_state, 0) else alert_state
            if new == "up":
                if alert_state:
                    recoveries.append({**item, "alert_state": alert_state})
                return ""
            return alert_state  # unknown: neither raised nor cleared

        for entity in entities:
            key = (provider, org_ref, str(entity["entity_type"]), str(entity["entity_id"]))
            if key in seen:
                continue
            seen.add(key)
            state = str(entity.get("state") or "unknown")
            meta = json.dumps(entity.get("meta") or {}, sort_keys=True, default=str)
            row = stored.get(key)
            if row is None:
                alert_state = transition(entity, "unknown", state, "", baseline=True) if state != "unknown" else ""
                inserts.append(
                    (
                        provider,
                        org_ref,
                        org_name,
                        key[2],
                        key[3],
                        *(entity.get(f) if f == "host_id" else str(entity.get(f) or "") for f in _STATE_FIELDS),
                        state,
                        now,
                        now,
                        now,
                        alert_state,
                        meta,
                    )
                )
                continue
            alert_state = str(row.get("alert_state") or "")
            since = row.get("state_since") or now
            if state != row["state"]:
                alert_state = transition(entity, str(row["state"]), state, alert_state, baseline=False)
                since = now
            updates.append(
                (
                    org_name,
                    *(entity.get(f) if f == "host_id" else str(entity.get(f) or "") for f in _STATE_FIELDS),
                    state,
                    since,
                    now,
                    alert_state,
                    meta,
                    row["id"],
                )
            )

        missing: list[tuple] = []
        for key, row in stored.items():
            if key in seen or row.get("missing"):
                continue
            since = row.get("state_since") or now
            alert_state = str(row.get("alert_state") or "")
            if row["state"] != "unknown":
                alert_state = transition(row, str(row["state"]), "unknown", alert_state, baseline=False)
                since = now
            missing.append((since, alert_state, row["id"]))

        if inserts:
            await db.executemany(
                """INSERT INTO topology_entity_state
                   (provider, org_ref, org_name, entity_type, entity_id, name, site, model, host_id,
                    raw_status, state, state_since, first_seen, last_seen, alert_state, meta_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                inserts,
            )
        if updates:
            await db.executemany(
                """UPDATE topology_entity_state
                   SET org_name = ?, name = ?, site = ?, model = ?, host_id = ?, raw_status = ?,
                       state = ?, state_since = ?, last_seen = ?, missing = 0, alert_state = ?, meta_json = ?
                   WHERE id = ?""",
                updates,
            )
        if missing:
            await db.executemany(
                """UPDATE topology_entity_state
                   SET state = 'unknown', raw_status = '', state_since = ?, missing = 1, alert_state = ?
                   WHERE id = ?""",
                missing,
            )
        if transitions:
            await db.executemany(
                """INSERT INTO topology_availability_transitions
                   (provider, org_ref, entity_type, entity_id, name, site, host_id,
                    old_state, new_state, transition_at, snapshot_ref)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        t["provider"],
                        t["org_ref"],
                        t["entity_type"],
                        t["entity_id"],
                        t["name"],
                        t["site"],
                        t["host_id"],
                        t["old_state"],
                        t["new_state"],
                        t["transition_at"],
                        t["snapshot_ref"],
                    )
                    for t in transitions
                ],
            )
        await db.commit()
    finally:
        await db.close()
    return {
        "tracked": len(seen),
        "new": len(inserts),
        "missing": len(missing),
        "transitions": transitions,
        "alerts": alerts,
        "recoveries": recoveries,
    }


async def purge_topology_availability(retention_days: int) -> int:
    """Delete transitions older than ``retention_days`` and the state of
    entities no collection has reported for that long (a deleted
    organization or account, a decommissioned device). Returns the number
    of rows deleted."""
    cutoff = _fmt(datetime.now(UTC).replace(tzinfo=None) - timedelta(days=max(1, int(retention_days))))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM topology_availability_transitions WHERE transition_at < ?", (cutoff,))
        deleted = cursor.rowcount or 0
        cursor = await db.execute("DELETE FROM topology_entity_state WHERE last_seen < ?", (cutoff,))
        deleted += cursor.rowcount or 0
        await db.commit()
        return deleted
    finally:
        await db.close()


# ── Uptime ───────────────────────────────────────────────────────────────────


def topology_uptime(
    initial_state: str,
    transitions: list[tuple[str, str]],
    *,
    window_start: str,
    now: str,
) -> dict[str, Any]:
    """Time-weighted availability of one entity over ``[window_start, now]``.

    ``initial_state`` is the state at ``window_start`` (``unknown`` when it
    was not tracked yet); ``transitions`` are ``(transition_at, new_state)``
    in time order, inside the window. Returns the seconds spent in each
    state, ``uptime_pct`` ((up + degraded) / (up + degraded + down), ``None``
    when no state was known in the window) and the down ``outages`` as
    ``(started_at, ended_at | None)`` (an outage under way at the window
    start begins at the window start)."""
    start, end = _parse(window_start), _parse(now)
    if start is None or end is None:
        raise ValueError("window_start and now must be timestamps")
    seconds = {"up": 0.0, "degraded": 0.0, "down": 0.0, "unknown": 0.0}
    outages: list[list[str | None]] = []
    state, since = initial_state if initial_state in seconds else "unknown", start
    if state == "down":
        outages.append([_fmt(start), None])
    for stamp, new_state in transitions:
        moment = _parse(stamp)
        if moment is None:
            continue
        moment = min(max(moment, start), end)
        seconds[state] += max(0.0, (moment - since).total_seconds())
        new_state = new_state if new_state in seconds else "unknown"
        if new_state == "down" and state != "down":
            outages.append([_fmt(moment), None])
        elif state == "down" and new_state != "down" and outages:
            outages[-1][1] = _fmt(moment)
        state, since = new_state, moment
    seconds[state] += max(0.0, (end - since).total_seconds())
    known = seconds["up"] + seconds["degraded"] + seconds["down"]
    return {
        "uptime_pct": round((seconds["up"] + seconds["degraded"]) / known * 100, 3) if known else None,
        "up_seconds": round(seconds["up"]),
        "degraded_seconds": round(seconds["degraded"]),
        "down_seconds": round(seconds["down"]),
        "unknown_seconds": round(seconds["unknown"]),
        "outages": [(o[0], o[1]) for o in outages],
    }


async def _window_history(
    db,
    clauses: list[str],
    params: list[Any],
    window_start: str,
) -> tuple[dict[tuple, str], dict[tuple, list[tuple[str, str]]]]:
    """For the entities the filter keeps: the state each was in at the window
    start (its last transition before it) and its transitions inside it."""
    where = " AND ".join(["t.transition_at < ?", *clauses])
    cursor = await db.execute(
        f"""SELECT t.provider, t.org_ref, t.entity_type, t.entity_id, t.new_state
            FROM topology_availability_transitions t
            INNER JOIN (
                SELECT MAX(t.id) AS max_id
                FROM topology_availability_transitions t
                WHERE {where}
                GROUP BY t.provider, t.org_ref, t.entity_type, t.entity_id
            ) latest ON t.id = latest.max_id""",
        (window_start, *params),
    )
    before = {_key(r): str(r["new_state"]) for r in rows_to_list(await cursor.fetchall())}
    where = " AND ".join(["t.transition_at >= ?", *clauses])
    cursor = await db.execute(
        f"""SELECT t.provider, t.org_ref, t.entity_type, t.entity_id, t.transition_at, t.new_state
            FROM topology_availability_transitions t
            WHERE {where}
            ORDER BY t.transition_at, t.id""",
        (window_start, *params),
    )
    inside: dict[tuple, list[tuple[str, str]]] = {}
    for r in rows_to_list(await cursor.fetchall()):
        inside.setdefault(_key(r), []).append((str(r["transition_at"]), str(r["new_state"])))
    return before, inside


def _window(days: int, now: str | None) -> tuple[str, str]:
    now = now or _now()
    end = _parse(now) or datetime.now(UTC).replace(tzinfo=None)
    return _fmt(end - timedelta(days=max(1, int(days)))), _fmt(end)


# ── Reading ──────────────────────────────────────────────────────────────────


async def get_topology_availability_summary(
    provider: str | None = None,
    org_ref: int | None = None,
    entity_type: str | None = None,
    days: int = 30,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """Per-entity uptime over the last ``days``, with current state, last
    change and outage count, plus the totals and the organizations /
    accounts tracked (unfiltered, for the filter)."""
    window_start, now = _window(days, now)
    db = await _dbcore.get_db(read_only=True)
    try:
        clauses, params = _filters("s", provider, org_ref, entity_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT s.* FROM topology_entity_state s {where}
                ORDER BY s.provider, s.org_ref, s.entity_type, s.name""",
            tuple(params),
        )
        states = [_state_row(r) for r in rows_to_list(await cursor.fetchall())]
        t_clauses, t_params = _filters("t", provider, org_ref, entity_type)
        before, inside = await _window_history(db, t_clauses, t_params, window_start)
        cursor = await db.execute(
            """SELECT provider, org_ref, MAX(org_name) AS org_name, COUNT(*) AS entity_count
               FROM topology_entity_state GROUP BY provider, org_ref ORDER BY provider, org_ref"""
        )
        orgs = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()

    entities: list[dict] = []
    counts = {"up": 0, "degraded": 0, "down": 0, "unknown": 0}
    for row in states:
        key = _key(row)
        stats = topology_uptime(before.get(key, "unknown"), inside.get(key, []), window_start=window_start, now=now)
        outages = stats.pop("outages")
        counts[row["state"] if row["state"] in counts else "unknown"] += 1
        entities.append(
            {
                **{k: row.get(k) for k in ("provider", "org_ref", "org_name", "entity_type", "entity_id")},
                **{k: row.get(k) for k in ("name", "site", "model", "host_id", "raw_status", "missing")},
                "current_state": row["state"],
                "last_change": row.get("state_since") or None,
                "first_seen": row.get("first_seen") or None,
                "last_seen": row.get("last_seen") or None,
                "outage_count": len(outages),
                **stats,
            }
        )
    rated = [e["uptime_pct"] for e in entities if e["uptime_pct"] is not None]
    return {
        "period_days": int(days),
        "window_start": window_start,
        "window_end": now,
        "entity_count": len(entities),
        "up": counts["up"],
        "degraded": counts["degraded"],
        "down": counts["down"],
        "unknown": counts["unknown"],
        "avg_uptime_pct": round(sum(rated) / len(rated), 3) if rated else None,
        "total_outages": sum(e["outage_count"] for e in entities),
        "orgs": orgs,
        "entities": entities,
    }


async def get_topology_outages(
    provider: str | None = None,
    org_ref: int | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    days: int = 30,
    limit: int = 200,
    *,
    now: str | None = None,
) -> list[dict]:
    """The down intervals inside the last ``days``, newest first. An outage
    still under way has no ``ended_at``."""
    window_start, now = _window(days, now)
    db = await _dbcore.get_db(read_only=True)
    try:
        clauses, params = _filters("s", provider, org_ref, entity_type, entity_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(f"SELECT s.* FROM topology_entity_state s {where}", tuple(params))
        states = {_key(r): r for r in rows_to_list(await cursor.fetchall())}
        t_clauses, t_params = _filters("t", provider, org_ref, entity_type, entity_id)
        before, inside = await _window_history(db, t_clauses, t_params, window_start)
    finally:
        await db.close()
    end = _parse(now)
    outages: list[dict] = []
    for key, row in states.items():
        stats = topology_uptime(before.get(key, "unknown"), inside.get(key, []), window_start=window_start, now=now)
        for started, ended in stats["outages"]:
            began = _parse(started)
            stop = _parse(ended) if ended else end
            outages.append(
                {
                    **{k: row.get(k) for k in ("provider", "org_ref", "org_name", "entity_type", "entity_id")},
                    **{k: row.get(k) for k in ("name", "site", "host_id")},
                    "started_at": started,
                    "ended_at": ended,
                    "ongoing": ended is None,
                    "duration_seconds": round((stop - began).total_seconds()) if began and stop else None,
                }
            )
    outages.sort(key=lambda o: o["started_at"], reverse=True)
    return outages[: max(1, int(limit))]


async def get_topology_transitions(
    provider: str | None = None,
    org_ref: int | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    days: int = 30,
    limit: int = 500,
) -> list[dict]:
    """State changes inside the last ``days``, newest first."""
    window_start, _now_text = _window(days, None)
    clauses, params = _filters("t", provider, org_ref, entity_type, entity_id)
    where = " AND ".join(["t.transition_at >= ?", *clauses])
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""SELECT t.* FROM topology_availability_transitions t
                WHERE {where}
                ORDER BY t.transition_at DESC, t.id DESC LIMIT ?""",
            (window_start, *params, max(1, int(limit))),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
