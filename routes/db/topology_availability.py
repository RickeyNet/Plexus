"""Availability tracking of topology (API-collected) entities.

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables (migration 0075): ``topology_entity_state`` (the current state of
every device, site, uplink, tunnel, VPN connection, circuit, peering and HA
link an integration's collection reported) and
``topology_availability_transitions`` (every state change). Migration 0084:
``topology_mutes`` (an entity or a whole site an operator muted; matched to
the state rows by ``TopologyMuteIndex``).

Collections are sparse (an hourly cloud discovery, an on-demand Meraki build),
so uptime is time-weighted from the transitions, never counted per sample.
Time in ``unknown`` (not collected, pending, not in the last collection) is
left out of the uptime ratio; ``degraded`` counts as available.

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import routes.database as _dbcore
from routes.database import rows_to_list

__all__ = [
    "MUTE_SCOPES",
    "TopologyMuteIndex",
    "apply_topology_entity_states",
    "count_topology_entity_states",
    "create_topology_mute",
    "delete_topology_mute",
    "get_topology_mute",
    "list_topology_entity_states",
    "list_topology_mutes",
    "load_topology_mute_index",
    "remove_topology_entities",
    "delete_topology_site_mutes_except",
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
_STATES = ("up", "degraded", "down", "unknown")


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


# ── Mutes ────────────────────────────────────────────────────────────────────

MUTE_SCOPES = ("entity", "site")
# Edge entities: muting the device at either end (meta ``a`` / ``b``) mutes
# them, as removing that device removes them.
_EDGE_TYPES = ("uplink", "tunnel", "link")
# What an entity of the availability summary carries of the mute covering it.
_ENTITY_MUTE_FIELDS = ("id", "scope", "site", "reason", "created_by", "created_at")
_MUTE_COLUMNS = "id, provider, org_ref, scope, entity_type, entity_id, site, reason, created_by, created_at"


def _mute_row(row: dict) -> dict:
    item = {k: row.get(k) for k in _MUTE_COLUMNS.split(", ")}
    item["id"], item["org_ref"] = int(item["id"]), int(item["org_ref"])
    return item


def _meta(entity: dict) -> dict:
    """The meta of an entity dict or of a state row read with ``meta_json``."""
    meta = entity.get("meta")
    if isinstance(meta, dict):
        return meta
    return _state_row({"meta_json": entity.get("meta_json")})["meta"]


async def create_topology_mute(
    provider: str,
    org_ref: int,
    scope: str,
    *,
    entity_type: str = "",
    entity_id: str = "",
    site: str = "",
    reason: str,
    created_by: str,
) -> dict:
    """Mute one entity (``entity`` scope) or every entity at one site
    (``site`` scope) of one source. A mute of the same target already there
    keeps its id and ``created_at`` and takes the new reason and author."""
    if scope not in MUTE_SCOPES:
        raise ValueError(f"scope must be one of {MUTE_SCOPES}")
    if scope == "entity":
        site = ""
    else:
        entity_type = entity_id = ""
    key = (str(provider), int(org_ref), scope, str(entity_type), str(entity_id), str(site))
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """INSERT INTO topology_mutes
               (provider, org_ref, scope, entity_type, entity_id, site, reason, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (provider, org_ref, scope, entity_type, entity_id, site)
               DO UPDATE SET reason = excluded.reason, created_by = excluded.created_by""",
            (*key, str(reason), str(created_by), _now()),
        )
        await db.commit()
        cursor = await db.execute(
            f"""SELECT {_MUTE_COLUMNS} FROM topology_mutes
                WHERE provider = ? AND org_ref = ? AND scope = ? AND entity_type = ? AND entity_id = ? AND site = ?""",
            key,
        )
        return _mute_row(rows_to_list(await cursor.fetchall())[0])
    finally:
        await db.close()


async def list_topology_mutes(provider: str | None = None, org_ref: int | None = None) -> list[dict]:
    """The mutes, of one source or provider when given, oldest first."""
    clauses, params = _filters("m", provider, org_ref, None)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT {_MUTE_COLUMNS} FROM topology_mutes m {where} ORDER BY m.id",
            tuple(params),
        )
        return [_mute_row(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def get_topology_mute(mute_id: int) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(f"SELECT {_MUTE_COLUMNS} FROM topology_mutes WHERE id = ?", (int(mute_id),))
        rows = rows_to_list(await cursor.fetchall())
        return _mute_row(rows[0]) if rows else None
    finally:
        await db.close()


async def delete_topology_mute(mute_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM topology_mutes WHERE id = ?", (int(mute_id),))
        await db.commit()
        return bool(cursor.rowcount)
    finally:
        await db.close()


class TopologyMuteIndex:
    """Which mute, if any, covers an entity. First hit wins:

    1. an ``entity`` mute of the entity itself;
    2. for an uplink, tunnel or link: an ``entity`` mute of the device at
       either end (meta ``a`` / ``b``);
    3. a ``site`` mute of the entity's site;
    4. for an uplink, tunnel or link: a ``site`` mute of the site of the
       device at either end (a hub-to-branch tunnel is stored under the hub's
       site and is still covered by muting the branch).

    ``states`` are ``topology_entity_state`` rows; only their devices' sites
    are used (rule 4)."""

    def __init__(self, mutes: list[dict], states: list[dict]) -> None:
        self._entity: dict[tuple[str, int, str, str], dict] = {}
        self._site: dict[tuple[str, int, str], dict] = {}
        for mute in mutes:
            source = (str(mute["provider"]), int(mute["org_ref"]))
            if mute["scope"] == "entity":
                self._entity[(*source, str(mute["entity_type"]), str(mute["entity_id"]))] = mute
            elif mute["scope"] == "site" and mute.get("site"):
                self._site[(*source, str(mute["site"]))] = mute
        self._device_site: dict[tuple[str, int, str], str] = {
            (str(s["provider"]), int(s["org_ref"]), str(s["entity_id"])): str(s.get("site") or "")
            for s in states
            if s.get("entity_type") == "device"
        }

    def __bool__(self) -> bool:
        return bool(self._entity or self._site)

    def match_site(self, provider: str, org_ref: int, site: str) -> dict | None:
        if not site:
            return None
        return self._site.get((str(provider), int(org_ref), str(site)))

    def match(self, entity: dict) -> dict | None:
        if not self:
            return None
        provider, org_ref = str(entity["provider"]), int(entity["org_ref"])
        hit = self._entity.get(_key(entity))
        if hit:
            return hit
        ends: list[str] = []
        if entity.get("entity_type") in _EDGE_TYPES:
            meta = _meta(entity)
            ends = [str(meta[end]) for end in ("a", "b") if meta.get(end)]
        for end in ends:
            hit = self._entity.get((provider, org_ref, "device", end))
            if hit:
                return hit
        hit = self.match_site(provider, org_ref, str(entity.get("site") or ""))
        if hit:
            return hit
        for end in ends:
            hit = self.match_site(provider, org_ref, self._device_site.get((provider, org_ref, end), ""))
            if hit:
                return hit
        return None


async def load_topology_mute_index(provider: str | None = None, org_ref: int | None = None) -> TopologyMuteIndex:
    """The mutes of every source (or of one), ready to match state rows.
    Without mutes, no second query is made."""
    mutes = await list_topology_mutes(provider, org_ref)
    if not mutes:
        return TopologyMuteIndex([], [])
    states: list[dict] = []
    if any(m["scope"] == "site" for m in mutes):
        states = await list_topology_entity_states(provider, org_ref, "device")
    return TopologyMuteIndex(mutes, states)


# ── Recording ────────────────────────────────────────────────────────────────


async def list_topology_entity_states(
    provider: str | None = None,
    org_ref: int | None = None,
    entity_type: str | None = None,
    *,
    entity_id: str | None = None,
    states: Sequence[str] | None = None,
    worst_first: bool = False,
    limit: int | None = None,
) -> list[dict]:
    """The stored state of the tracked entities. ``entity_id`` keeps one
    entity; ``states`` keeps only the entities currently in one of those
    states; ``worst_first`` orders down, then degraded, then the rest, the
    most recent change first within each; ``limit`` caps the rows returned."""
    clauses, params = _filters("s", provider, org_ref, entity_type, entity_id)
    if states is not None:
        wanted = list(dict.fromkeys(str(state) for state in states))
        if not wanted:
            return []
        clauses.append(f"s.state IN ({', '.join('?' for _ in wanted)})")
        params.extend(wanted)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order = "s.provider, s.org_ref, s.entity_type, s.name"
    if worst_first:
        order = f"CASE s.state WHEN 'down' THEN 0 WHEN 'degraded' THEN 1 ELSE 2 END, s.state_since DESC, {order}"
    tail = ""
    if limit is not None:
        tail = " LIMIT ?"
        params.append(max(0, int(limit)))
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT s.* FROM topology_entity_state s {where} ORDER BY {order}{tail}",
            tuple(params),
        )
        return [_state_row(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def count_topology_entity_states() -> list[dict]:
    """How many tracked entities of each type each source (provider and
    org_ref) has in each state, as ``[{"provider", "org_ref", "entity_type",
    "state", "count"}]`` rows."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT provider, org_ref, entity_type, state, COUNT(*) AS count
               FROM topology_entity_state
               GROUP BY provider, org_ref, entity_type, state
               ORDER BY provider, org_ref, entity_type, state"""
        )
        return [
            {
                "provider": str(r["provider"]),
                "org_ref": int(r["org_ref"]),
                "entity_type": str(r["entity_type"]),
                "state": str(r["state"]),
                "count": int(r["count"]),
            }
            for r in rows_to_list(await cursor.fetchall())
        ]
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
    clean_types: Collection[str] = (),
) -> dict[str, Any]:
    """Bring the stored state of one organization / account up to date with
    the entities of its latest collection.

    ``entities`` are ``EntityState.as_dict()`` rows. A new entity is recorded
    with a transition from ``unknown`` (its baseline: it raises no alert). A
    stored entity absent from the collection is deleted, with its
    entity-scope mute and no transition, when its type is in ``clean_types``
    (the collection proves it is gone; see ``clean_entity_types``); otherwise
    it turns ``unknown`` and is flagged ``missing``. Returns ``{"tracked",
    "new", "missing", "removed", "transitions", "alerts", "recoveries"}``:
    ``removed`` are the deleted state rows as they were, ``alerts`` the
    transitions that need an alert (to ``degraded`` or ``down``, worse than
    the alert already open), ``recoveries`` the transitions back to ``up`` of
    an entity with one open.
    """
    clean = frozenset(str(t) for t in clean_types)
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
        removed: list[dict] = []
        for key, row in stored.items():
            if key in seen:
                continue
            if row["entity_type"] in clean:
                removed.append(row)
                continue
            if row.get("missing"):
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
        await _delete_state_rows(db, removed)
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
        "removed": [_state_row(r) for r in removed],
        "transitions": transitions,
        "alerts": alerts,
        "recoveries": recoveries,
    }


async def _delete_state_rows(db, rows: list[dict]) -> None:
    """Delete state rows and their entity-scope mutes (in ``db``'s
    transaction; the caller commits). Their transitions stay until the
    retention purge."""
    if not rows:
        return
    await db.executemany("DELETE FROM topology_entity_state WHERE id = ?", [(r["id"],) for r in rows])
    await db.executemany(
        """DELETE FROM topology_mutes
           WHERE scope = 'entity' AND provider = ? AND org_ref = ? AND entity_type = ? AND entity_id = ?""",
        [_key(r) for r in rows],
    )


async def remove_topology_entities(provider: str, org_ref: int, device_ids: Collection[str]) -> list[dict]:
    """Delete devices the vendor no longer has (``device_ids``: their entity
    ids), the uplinks, tunnels and links ending at one of them, and their
    entity-scope mutes. Returns the deleted state rows as they were."""
    ids = {str(i) for i in device_ids if i}
    if not ids:
        return []
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM topology_entity_state WHERE provider = ? AND org_ref = ?",
            (provider, int(org_ref)),
        )
        rows = [
            r
            for r in rows_to_list(await cursor.fetchall())
            if (r["entity_type"] == "device" and str(r["entity_id"]) in ids)
            or (r["entity_type"] in _EDGE_TYPES and ids & {str(_meta(r).get(end) or "") for end in ("a", "b")})
        ]
        await _delete_state_rows(db, rows)
        await db.commit()
    finally:
        await db.close()
    return [_state_row(r) for r in rows]


async def delete_topology_site_mutes_except(provider: str, org_ref: int, site_names: Collection[str]) -> int:
    """Delete the site-scope mutes of one source whose site is not in
    ``site_names`` (the site itself is gone; a site with no devices left
    keeps its mute). Returns how many were deleted."""
    keep = {str(n) for n in site_names}
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, site FROM topology_mutes WHERE scope = 'site' AND provider = ? AND org_ref = ?",
            (provider, int(org_ref)),
        )
        gone = [(r["id"],) for r in rows_to_list(await cursor.fetchall()) if str(r["site"]) not in keep]
        if gone:
            await db.executemany("DELETE FROM topology_mutes WHERE id = ?", gone)
            await db.commit()
        return len(gone)
    finally:
        await db.close()


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
    accounts tracked (unfiltered, for the filter). A muted entity carries
    its ``mute`` and is left out of the state counts, the average uptime
    and the outage total (``muted`` counts it; ``entity_count`` still does)."""
    window_start, now = _window(days, now)
    index = await load_topology_mute_index(provider, org_ref)
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
    counts = {"up": 0, "degraded": 0, "down": 0, "unknown": 0, "muted": 0}
    for row in states:
        key = _key(row)
        stats = topology_uptime(before.get(key, "unknown"), inside.get(key, []), window_start=window_start, now=now)
        outages = stats.pop("outages")
        mute = index.match(row)
        if mute:
            counts["muted"] += 1
        else:
            counts[row["state"] if row["state"] in _STATES else "unknown"] += 1
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
                "muted": mute is not None,
                "mute": {k: mute[k] for k in _ENTITY_MUTE_FIELDS} if mute else None,
            }
        )
    counted = [e for e in entities if not e["muted"]]
    rated = [e["uptime_pct"] for e in counted if e["uptime_pct"] is not None]
    return {
        "period_days": int(days),
        "window_start": window_start,
        "window_end": now,
        "entity_count": len(entities),
        "up": counts["up"],
        "degraded": counts["degraded"],
        "down": counts["down"],
        "unknown": counts["unknown"],
        "muted": counts["muted"],
        "avg_uptime_pct": round(sum(rated) / len(rated), 3) if rated else None,
        "total_outages": sum(e["outage_count"] for e in counted),
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
