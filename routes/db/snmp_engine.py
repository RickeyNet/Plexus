"""The SNMP trap receiver's own SNMPv3 engine (engine ID, engine boots) and
its SNMPv3 replay record: storage only (the protocol is
``netcontrol.snmpv3_engine``).

Tables (migration 0139): ``snmp_local_engine`` (one row) and
``snmpv3_replay_state`` (per source address and sender engine ID, bounded
by the caller with ``keep``).

Timestamps are UTC ``YYYY-MM-DD HH:MM:SS`` text, so they compare as text.
"""

from __future__ import annotations

from collections.abc import Iterable

import routes.database as _dbcore
from routes.database import rows_to_list

__all__ = [
    "load_snmpv3_replay_state",
    "save_snmpv3_replay_state",
    "start_snmp_local_engine",
]

# RFC 3414 section 2.2.2: snmpEngineBoots latches at 2^31-1.
_MAX_BOOTS = 2147483647


async def start_snmp_local_engine(new_engine_id: str) -> tuple[str, int]:
    """Increment the stored snmpEngineBoots in one statement and return
    ``(engine_id, boots)``. The first call stores ``new_engine_id`` (hex)
    with boots 1; every later call keeps the stored engine ID. Boots stops
    at 2^31-1 (RFC 3414 section 2.2.2)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO snmp_local_engine (id, engine_id, boots, updated_at)
               VALUES (1, ?, 1, datetime('now'))
               ON CONFLICT(id) DO UPDATE SET
                   boots = CASE WHEN snmp_local_engine.boots >= ? THEN ?
                                ELSE snmp_local_engine.boots + 1 END,
                   updated_at = datetime('now')
               RETURNING engine_id, boots""",
            (new_engine_id, _MAX_BOOTS, _MAX_BOOTS),
        )
        row = await cursor.fetchone()
        await db.commit()
    finally:
        await db.close()
    return str(row[0]), int(row[1])


async def load_snmpv3_replay_state(limit: int) -> list[dict]:
    """The ``limit`` most recently recorded replay rows: ``source``,
    ``engine_id`` (hex), ``boots``, ``engine_time``, ``seen_at``."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """SELECT source, engine_id, boots, engine_time, seen_at FROM snmpv3_replay_state
               ORDER BY seen_at DESC, source, engine_id LIMIT ?""",
            (max(0, int(limit)),),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def save_snmpv3_replay_state(rows: Iterable[tuple[str, str, int, int, str]], keep: int) -> int:
    """Upsert ``(source, engine_id, boots, engine_time, seen_at)`` rows in
    one transaction (a stored row moves forward only: a process writing an
    older timeline never moves it back), then delete all but the ``keep``
    newest. Returns the number of rows given."""
    rows = list(rows)
    db = await _dbcore.get_db()
    try:
        if rows:
            await db.executemany(
                """INSERT INTO snmpv3_replay_state (source, engine_id, boots, engine_time, seen_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(source, engine_id) DO UPDATE SET
                       boots = excluded.boots,
                       engine_time = excluded.engine_time,
                       seen_at = excluded.seen_at
                   WHERE excluded.boots > snmpv3_replay_state.boots
                      OR (excluded.boots = snmpv3_replay_state.boots
                          AND excluded.engine_time >= snmpv3_replay_state.engine_time)""",
                rows,
            )
        await db.execute(
            """DELETE FROM snmpv3_replay_state WHERE (source, engine_id) NOT IN (
                   SELECT source, engine_id FROM snmpv3_replay_state
                   ORDER BY seen_at DESC, source, engine_id LIMIT ?)""",
            (max(0, int(keep)),),
        )
        await db.commit()
    finally:
        await db.close()
    return len(rows)
