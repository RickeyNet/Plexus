"""The SNMP trap receiver's stored SNMPv3 state: its own engine (for
informs) and the replay record of the engines that send it traps.

* ``start`` -- called when the trap receiver starts listening (only the
  process that bound the port, so only one process at a time): reads the
  stored engine ID (generated once, ``snmpv3_traps.new_engine_id``),
  increments the stored snmpEngineBoots in one statement and makes
  ``LOCAL`` the engine informs are answered with. snmpEngineTime counts
  from this start. A start that cannot reach the database leaves ``LOCAL``
  None: informs are then stored undecoded, as before.
* ``restore_replay`` / ``persist_replay`` -- the trap path's per (source,
  engine ID) timelines (``snmpv3_traps.ReplayGuard``) are loaded at start
  and written back, only the ones that moved, at most once per
  ``REPLAY_PERSIST_SECONDS`` and at shutdown, so a trap storm does not
  become a write storm. The table keeps the newest rows only (the guard's
  bound). What a crash loses is the movement since the last write.

Storage: ``routes.db.snmp_engine`` (migration 0139).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from routes.db import snmp_engine as engine_db

from netcontrol.snmpv3_traps import LocalEngine, ReplayGuard, new_engine_id

LOGGER = logging.getLogger("plexus.snmpv3_engine")

# At most one replay-record write per interval (plus one at shutdown).
REPLAY_PERSIST_SECONDS = 60.0

# The engine informs are authenticated against; None until ``start``.
LOCAL: LocalEngine | None = None
# Exact copies of accepted informs, per source (the authoritative time
# window allows a copy within 150 seconds). In memory only: a restart
# increments boots, so no earlier inform is timely after it.
INFORM_REPLAY_GUARD = ReplayGuard()

_clock: Callable[[], float] = time.monotonic
_last_persist = float("-inf")


async def start() -> LocalEngine | None:
    """Increment the stored boots and make ``LOCAL`` the started engine
    (see the module doc). Returns it, or None when the database failed."""
    global LOCAL, INFORM_REPLAY_GUARD
    try:
        engine_id, boots = await engine_db.start_snmp_local_engine(new_engine_id().hex())
        engine = LocalEngine(bytes.fromhex(engine_id), boots)
    except Exception as exc:  # noqa: BLE001 - the receiver runs on without informs
        LOGGER.warning("SNMPv3 engine: not started, informs stay unanswered: %s", type(exc).__name__)
        LOCAL = None
        return None
    if engine.latched:
        LOGGER.warning("SNMPv3 engine: snmpEngineBoots is at its maximum; no inform is accepted (RFC 3414 2.2.2)")
    LOCAL = engine
    INFORM_REPLAY_GUARD = ReplayGuard()
    LOGGER.info("SNMPv3 engine: engine ID %s, boots %d", engine.engine_id.hex(), engine.boots)
    return engine


async def restore_replay(guard: ReplayGuard) -> int:
    """Load the stored trap replay record into ``guard`` (its newest
    ``max_engines`` rows). Returns how many timelines were loaded; 0 when
    the database failed (logged)."""
    try:
        rows = await engine_db.load_snmpv3_replay_state(guard.max_engines)
    except Exception as exc:  # noqa: BLE001 - start without the record, as before
        LOGGER.warning("SNMPv3 replay record: not loaded: %s", type(exc).__name__)
        return 0
    return guard.restore(rows)


async def persist_replay(guard: ReplayGuard, *, force: bool = False) -> int:
    """Write the timelines of ``guard`` that moved since the last write, at
    most once per ``REPLAY_PERSIST_SECONDS`` unless ``force`` (shutdown).
    Returns the number of rows written. A failed write is logged and its
    rows are lost (they are written again when they next move)."""
    global _last_persist
    now = _clock()
    if not force and now - _last_persist < REPLAY_PERSIST_SECONDS:
        return 0
    _last_persist = now
    rows = guard.take_changed()
    if not rows:
        return 0
    try:
        return await engine_db.save_snmpv3_replay_state(rows, guard.max_engines)
    except Exception as exc:  # noqa: BLE001 - never stops the trap writer
        LOGGER.warning("SNMPv3 replay record: %d rows not written: %s", len(rows), type(exc).__name__)
        return 0


def snapshot() -> dict:
    """The engine's identity and counters for the receiver settings: empty
    values while no engine is started."""
    engine = LOCAL
    if engine is None:
        return {
            "trap_engine_id": "",
            "trap_engine_boots": None,
            "trap_v3_informs_answered": 0,
            "trap_v3_reports_sent": 0,
            "trap_usm_unknown_engine_ids": 0,
            "trap_usm_not_in_time_windows": 0,
        }
    return {
        "trap_engine_id": engine.engine_id.hex(),
        "trap_engine_boots": engine.boots,
        "trap_v3_informs_answered": engine.responses,
        "trap_v3_reports_sent": engine.reports,
        "trap_usm_unknown_engine_ids": engine.stats["unknown_engine_ids"],
        "trap_usm_not_in_time_windows": engine.stats["not_in_time_windows"],
    }


def reset() -> None:
    """Forget the engine and the write timer (tests)."""
    global LOCAL, INFORM_REPLAY_GUARD, _last_persist
    LOCAL = None
    INFORM_REPLAY_GUARD = ReplayGuard()
    _last_persist = float("-inf")
