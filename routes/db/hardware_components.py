"""Hardware components with a serial, their history and the per-host
collection state: storage only (the rules are ``netcontrol.hardware_components``).

Star re-exported by routes/database.py so the ``routes.database`` facade
keeps its full public surface.

Tables (migration 0136): ``hardware_components`` (current rows, removed
ones kept, deleted with their host), ``hardware_component_events`` (the
append-only history, kept when the host is deleted: ``host_id`` NULL,
``hostname`` kept) and ``hardware_collection_state`` (per host).

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text, so they compare as text.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

import routes.database as _dbcore
from routes.database import rows_to_list
from routes.db.inventory import group_ids_condition

__all__ = [
    "get_hardware_state",
    "hardware_seen_elsewhere",
    "list_hardware_components",
    "list_hardware_events",
    "list_host_hardware",
    "record_hardware_attempt",
    "save_hardware_read",
]

_COMPONENT_FIELDS = (
    "category",
    "slot",
    "name",
    "description",
    "model",
    "serial",
    "hardware_rev",
    "firmware_rev",
    "software_rev",
)
_EVENT_FIELDS = (
    "event",
    "category",
    "slot",
    "name",
    "model",
    "serial",
    "previous_serial",
    "previous_model",
    "previous_slot",
    "previous_host_id",
    "previous_hostname",
    "detail",
)
_COMPONENT_SELECT = (
    "SELECT c.id, c.host_id, h.hostname, c.category, c.slot, c.name, c.description, c.model, c.serial,"
    " c.hardware_rev, c.firmware_rev, c.software_rev, c.status, c.source, c.first_seen, c.last_seen,"
    " c.removed_at, c.missing_since FROM hardware_components c JOIN hosts h ON h.id = c.host_id"
)
_EVENT_COLUMNS = (
    "id, host_id, hostname, occurred_at, event, category, slot, name, model, serial, previous_serial,"
    " previous_model, previous_slot, previous_host_id, previous_hostname, changes_json, detail"
)
# Most rows one list call returns.
MAX_LIST_ROWS = 50000


def _event_row(row: dict) -> dict:
    out = dict(row)
    try:
        changes = json.loads(out.pop("changes_json", "") or "{}")
    except ValueError:
        changes = {}
    out["changes"] = changes if isinstance(changes, dict) else {}
    return out


async def get_hardware_state(host_id: int) -> dict | None:
    """A host's collection state row, or None before its first attempt."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM hardware_collection_state WHERE host_id = ?", (int(host_id),))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def record_hardware_attempt(
    host_id: int, *, now: str, source: str, message: str, empty_reads: int | None = None
) -> None:
    """A read that is taken as not read: the attempt and its message; the
    last complete read stays. ``empty_reads``: the count of complete reads
    with no component, in a row (kept when None). An empty read waiting for
    confirmation asks the next poll to read again (``recheck``)."""
    recheck = 1 if empty_reads else 0
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """INSERT INTO hardware_collection_state (host_id, attempted_at, result, message, empty_reads, recheck)
               VALUES (?, ?, 'not_read', ?, ?, ?)
               ON CONFLICT (host_id) DO UPDATE SET attempted_at = excluded.attempted_at,
                   result = 'not_read', message = excluded.message,
                   empty_reads = CASE WHEN ? THEN excluded.empty_reads ELSE hardware_collection_state.empty_reads END,
                   recheck = CASE WHEN ? THEN excluded.recheck ELSE hardware_collection_state.recheck END""",
            (
                int(host_id),
                now,
                message,
                int(empty_reads or 0),
                recheck,
                empty_reads is not None,
                empty_reads is not None,
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def list_host_hardware(host_id: int) -> list[dict]:
    """Every component row of a host (removed ones too), chassis first, then
    by slot."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""{_COMPONENT_SELECT} WHERE c.host_id = ?
                ORDER BY CASE c.status WHEN 'removed' THEN 1 ELSE 0 END,
                         CASE c.category WHEN 'chassis' THEN 0 WHEN 'module' THEN 1 WHEN 'power_supply' THEN 2
                              WHEN 'fan' THEN 3 WHEN 'transceiver' THEN 4 ELSE 5 END,
                         c.slot, c.serial, c.id""",  # nosec B608 - fixed text
            (int(host_id),),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def hardware_seen_elsewhere(host_id: int, serials: Iterable[str]) -> dict[str, dict]:
    """``{UPPER(serial): {host_id, hostname, slot}}``: where each serial was
    last seen on another host (present or removed), the latest first."""
    keys = sorted({str(s).strip().upper() for s in serials if str(s).strip()})
    if not keys:
        return {}
    out: dict[str, dict] = {}
    db = await _dbcore.get_db(read_only=True)
    try:
        for start in range(0, len(keys), 500):
            chunk = keys[start : start + 500]
            cursor = await db.execute(
                f"""SELECT UPPER(c.serial) AS skey, c.host_id, h.hostname, c.slot, c.last_seen
                    FROM hardware_components c JOIN hosts h ON h.id = c.host_id
                    WHERE c.host_id <> ? AND UPPER(c.serial) IN ({",".join("?" * len(chunk))})
                    ORDER BY c.last_seen DESC, c.id DESC""",  # nosec B608 - placeholders only
                (int(host_id), *chunk),
            )
            for row in rows_to_list(await cursor.fetchall()):
                out.setdefault(
                    row["skey"], {"host_id": row["host_id"], "hostname": row["hostname"], "slot": row["slot"]}
                )
    finally:
        await db.close()
    return out


async def save_hardware_read(
    host_id: int,
    hostname: str,
    source: str,
    plan: Any,
    *,
    now: str,
    message: str,
    empty_reads: int = 0,
    chassis_serial: str = "",
) -> list[dict]:
    """Store a complete read in one transaction: the plan's new and changed
    rows and its events, the collection state, and the host's serial from
    the chassis component when the host has none (never overwritten:
    discovery matches hosts by it). Returns the new events as stored."""
    db = await _dbcore.get_db()
    try:
        for values in plan.inserts:
            await db.execute(
                f"""INSERT INTO hardware_components
                    (host_id, {", ".join(_COMPONENT_FIELDS)}, status, source, first_seen, last_seen)
                    VALUES (?, {", ".join("?" * len(_COMPONENT_FIELDS))}, 'present', ?, ?, ?)
                    RETURNING id""",  # nosec B608 - fixed column names
                (int(host_id), *(values[f] for f in _COMPONENT_FIELDS), source, now, now),
            )
        for values in plan.updates:
            removed_at = now if values.get("removed") else None
            if values.get("status") == "removed" and not values.get("removed"):
                removed_at = values.get("removed_at")
            await db.execute(
                f"""UPDATE hardware_components SET {", ".join(f"{f} = ?" for f in _COMPONENT_FIELDS)},
                        status = ?, source = ?, removed_at = ?, missing_since = ?,
                        last_seen = CASE WHEN ? THEN ? ELSE last_seen END
                    WHERE id = ? AND host_id = ?""",  # nosec B608 - fixed column names
                (
                    *(str(values.get(f) or "") for f in _COMPONENT_FIELDS),
                    values["status"],
                    str(values.get("source") or source),
                    removed_at,
                    values.get("missing_since"),
                    bool(values.get("seen")),
                    now,
                    int(values["id"]),
                    int(host_id),
                ),
            )
        stored: list[dict] = []
        for event in plan.events:
            cursor = await db.execute(
                f"""INSERT INTO hardware_component_events
                    (host_id, hostname, occurred_at, {", ".join(_EVENT_FIELDS)}, changes_json, source)
                    VALUES (?, ?, ?, {", ".join("?" * len(_EVENT_FIELDS))}, ?, ?)
                    RETURNING id""",  # nosec B608 - fixed column names
                (
                    int(host_id),
                    hostname,
                    now,
                    *(event.get(f) if f == "previous_host_id" else str(event.get(f) or "") for f in _EVENT_FIELDS),
                    json.dumps(event.get("changes") or {}, sort_keys=True),
                    source,
                ),
            )
            row = await cursor.fetchone()
            stored.append(
                {
                    "id": int(row["id"]),
                    "host_id": int(host_id),
                    "hostname": hostname,
                    "occurred_at": now,
                    **{f: event.get(f) for f in _EVENT_FIELDS},
                    "changes": event.get("changes") or {},
                }
            )
        cursor = await db.execute(
            "SELECT COUNT(*) AS n, SUM(CASE WHEN status = 'missing' THEN 1 ELSE 0 END) AS missing"
            " FROM hardware_components WHERE host_id = ? AND status <> 'removed'",
            (int(host_id),),
        )
        counts = dict(await cursor.fetchone())
        recheck = 1 if int(counts.get("missing") or 0) or empty_reads else 0
        await db.execute(
            """INSERT INTO hardware_collection_state
                   (host_id, collected_at, attempted_at, source, result, message, empty_reads, recheck, component_count)
               VALUES (?, ?, ?, ?, 'ok', ?, ?, ?, ?)
               ON CONFLICT (host_id) DO UPDATE SET collected_at = excluded.collected_at,
                   attempted_at = excluded.attempted_at, source = excluded.source, result = 'ok',
                   message = excluded.message, empty_reads = excluded.empty_reads,
                   recheck = excluded.recheck, component_count = excluded.component_count""",
            (int(host_id), now, now, source, message, int(empty_reads), recheck, int(counts.get("n") or 0)),
        )
        if chassis_serial:
            await db.execute(
                "UPDATE hosts SET serial_number = ? WHERE id = ? AND COALESCE(serial_number, '') = ''",
                (chassis_serial, int(host_id)),
            )
        await db.commit()
        return stored
    finally:
        await db.close()


def _like(value: str) -> str:
    escaped = value.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _search_clause(columns: Iterable[str], search: str | None, params: list[Any]) -> str:
    """Case-insensitive substring match of ``search`` on any column."""
    text = str(search or "").strip()
    if not text:
        return ""
    pattern = _like(text)
    parts = []
    for column in columns:
        parts.append(f"LOWER(COALESCE({column}, '')) LIKE ? ESCAPE '\\'")
        params.append(pattern)
    return "(" + " OR ".join(parts) + ")"


def _in_clause(column: str, values: Iterable[str] | None, params: list[Any]) -> str:
    chosen = [v for v in (values or ()) if v]
    if not chosen:
        return ""
    params.extend(chosen)
    return f"{column} IN ({','.join('?' * len(chosen))})"


async def list_hardware_components(
    *,
    search: str | None = None,
    categories: Iterable[str] | None = None,
    statuses: Iterable[str] | None = None,
    group_id: int | None = None,
    host_id: int | None = None,
    host_ids: Iterable[int] | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    """``(total, rows)`` of the components matching the filters: ``search``
    a case-insensitive substring of the serial, model, name, slot or
    hostname; ``host_ids`` the caller's readable hosts (None: every host)."""
    params: list[Any] = []
    clauses = [
        _search_clause(("c.serial", "c.model", "c.name", "c.slot", "h.hostname"), search, params),
        _in_clause("c.category", categories, params),
        _in_clause("c.status", statuses, params),
    ]
    if group_id is not None:
        clauses.append("h.group_id = ?")
        params.append(int(group_id))
    if host_id is not None:
        clauses.append("c.host_id = ?")
        params.append(int(host_id))
    scope_sql, scope_params = group_ids_condition("c.host_id", host_ids)
    if scope_sql:
        clauses.append(scope_sql)
        params.extend(scope_params)
    where = " AND ".join(c for c in clauses if c)
    where = f"WHERE {where}" if where else ""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT COUNT(*) AS n FROM hardware_components c JOIN hosts h ON h.id = c.host_id {where}",  # nosec B608
            tuple(params),
        )
        total = int(dict(await cursor.fetchone())["n"] or 0)
        cursor = await db.execute(
            f"""{_COMPONENT_SELECT} {where}
                ORDER BY h.hostname, c.host_id, CASE c.status WHEN 'removed' THEN 1 ELSE 0 END, c.slot, c.serial, c.id
                LIMIT ? OFFSET ?""",  # nosec B608 - fixed clauses, placeholders only
            (*params, max(1, min(int(limit), MAX_LIST_ROWS)), max(0, int(offset))),
        )
        return total, rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def list_hardware_events(
    *,
    search: str | None = None,
    events: Iterable[str] | None = None,
    categories: Iterable[str] | None = None,
    host_id: int | None = None,
    host_ids: Iterable[int] | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    """``(total, rows)`` of the history, newest first: ``search`` a
    case-insensitive substring of the serial, previous serial, model,
    hostname or slot; ``events`` any of these event types; ``host_ids``
    the caller's readable hosts (None: every host; an event of a deleted
    host is then left out)."""
    params: list[Any] = []
    clauses = [
        _search_clause(("serial", "previous_serial", "model", "hostname", "slot"), search, params),
        _in_clause("event", events, params),
        _in_clause("category", categories, params),
    ]
    if host_id is not None:
        clauses.append("host_id = ?")
        params.append(int(host_id))
    scope_sql, scope_params = group_ids_condition("host_id", host_ids)
    if scope_sql:
        clauses.append(scope_sql)
        params.extend(scope_params)
    where = " AND ".join(c for c in clauses if c)
    where = f"WHERE {where}" if where else ""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT COUNT(*) AS n FROM hardware_component_events {where}",  # nosec B608 - fixed clauses
            tuple(params),
        )
        total = int(dict(await cursor.fetchone())["n"] or 0)
        cursor = await db.execute(
            f"""SELECT {_EVENT_COLUMNS} FROM hardware_component_events {where}
                ORDER BY occurred_at DESC, id DESC LIMIT ? OFFSET ?""",  # nosec B608 - fixed clauses
            (*params, max(1, min(int(limit), MAX_LIST_ROWS)), max(0, int(offset))),
        )
        return total, [_event_row(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()
