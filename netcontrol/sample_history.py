"""Move the rows migration 0144 left behind into the new sample tables.

Migration 0144 swapped ``metric_samples``, ``interface_ts`` and
``flow_records`` for new tables (BIGINT keys, native ``sampled_at``) without
copying a row, so the upgrade starts at once. After startup
``move_sample_history`` moves each old table (``<table>_pre0144``) into the
new one in batches, newest first by id, the three tables in turn, so every
view gets its most recent history back within seconds. A row past its
table's retention, or whose time is no timestamp, is deleted, not moved.
An old table is dropped once it is empty. The move resumes after a restart
(each batch is one statement that deletes what it moves) and two processes
running it skip each other's rows.

While a table's history is still moving, its readers see what has arrived;
jobs that derive stored rows from the raw history ask ``history_complete``
first and defer a window that starts before the swap (see
``netcontrol.routes.metrics_engine``, ``baseline_alerting``, ``billing`` and
the report scheduler).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import datetime

import routes.database as db

from netcontrol.integrations.traffic import parse_time
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.sample_history")

# Rows per batch statement, and the pause after each, so pollers and
# readers are not starved while the move runs.
BATCH_ROWS = 5000
BATCH_PAUSE_SECONDS = 0.2
PROGRESS_LOG_SECONDS = 60.0
# Wait before retrying a failed batch, or an old table another process is
# still emptying.
RETRY_SECONDS = 30.0


def _metric_samples_retention() -> int:
    from netcontrol.routes.metrics_engine import RAW_SAMPLE_RETENTION_HOURS

    return RAW_SAMPLE_RETENTION_HOURS * 3600


def _interface_ts_retention() -> int:
    from netcontrol.routes.metrics_engine import INTERFACE_TS_RETENTION_DAYS

    return INTERFACE_TS_RETENTION_DAYS * 86400


def _flow_records_retention() -> int:
    from netcontrol.routes.flow_collector import flow_retention_hours

    return flow_retention_hours() * 3600


# One entry per swapped table (the columns, time column and cast are
# ``routes.db.metrics.SAMPLE_TABLE_MOVES``): the retention, in seconds, that
# the table's own cleanup enforces.
MOVES: tuple[tuple[str, Callable[[], int]], ...] = (
    ("metric_samples", _metric_samples_retention),
    ("interface_ts", _interface_ts_retention),
    ("flow_records", _flow_records_retention),
)

_complete: set[str] = set()


async def history_complete(table: str, since: str | datetime | None = None) -> bool:
    """Whether every stored row of ``table`` at or after ``since`` is in the
    table: its old table is gone, or ``since`` is not before the swap (rows
    written since then never were in the old table). ``since`` is ``None``
    for "all of it"."""
    if table in _complete:
        return True
    swapped = await db.get_sample_move_swapped_at(table)
    if swapped is None:
        _complete.add(table)
        return True
    if since is None:
        return False
    at = parse_time(since.isoformat() if isinstance(since, datetime) else since)
    cut = parse_time(swapped)
    return at is not None and cut is not None and at >= cut


async def _after_move(table: str, swapped: str) -> None:
    """Work a table's derived data waited for, run once its old table is
    empty and before it is dropped (so a crash in between repeats it)."""
    if table == "metric_samples":
        from netcontrol.routes.metrics_engine import roll_up_windows_around

        await roll_up_windows_around(swapped)


async def move_sample_history() -> dict[str, dict[str, int]]:
    """Move every old table into its new one; returns, per table moved,
    the rows ``moved`` and ``dropped`` (past retention, no timestamp, or
    already there)."""
    pending: dict[str, dict] = {}
    for table, retention in MOVES:
        swapped = await db.get_sample_move_swapped_at(table)
        if swapped is not None:
            pending[table] = {"swapped": swapped, "retention": retention, "below": None, "taken": 0, "moved": 0}
    if not pending:
        return {}
    LOGGER.info(
        "sample history: moving the rows of %s written before the upgrade into the new tables, newest first",
        ", ".join(pending),
    )
    totals: dict[str, dict[str, int]] = {}
    last_log = time.monotonic()
    while pending:
        for table in list(pending):
            entry = pending[table]
            result = await db.move_sample_batch(
                table,
                below_id=entry["below"],
                retention_seconds=entry["retention"](),
                limit=BATCH_ROWS,
            )
            if result is not None and result["taken"]:
                entry["taken"] += result["taken"]
                entry["moved"] += result["moved"]
                entry["below"] = result["low_id"]
            elif result is not None and entry["below"] is not None:
                # Nothing left below: start over from the top for rows
                # another mover held when this one passed them.
                entry["below"] = None
            else:
                if result is not None:
                    await _after_move(table, entry["swapped"])
                if not await db.drop_sample_move_table(table):
                    # Another process still holds rows of it.
                    await asyncio.sleep(RETRY_SECONDS)
                    continue
                _complete.add(table)
                del pending[table]
                totals[table] = {"moved": entry["moved"], "dropped": entry["taken"] - entry["moved"]}
                LOGGER.info(
                    "sample history: %s done: %d rows moved, %d past retention or unreadable dropped; "
                    "old table removed",
                    table,
                    entry["moved"],
                    entry["taken"] - entry["moved"],
                )
            await asyncio.sleep(BATCH_PAUSE_SECONDS)
        if pending and time.monotonic() - last_log >= PROGRESS_LOG_SECONDS:
            last_log = time.monotonic()
            LOGGER.info(
                "sample history: still moving: %s",
                "; ".join(
                    f"{t} {e['moved']} rows moved, {e['taken'] - e['moved']} dropped" for t, e in pending.items()
                ),
            )
    return totals


async def sample_history_move_loop() -> None:
    """Background task started at every boot: moves what is left of the old
    sample tables, then returns; a failed batch is retried."""
    while True:
        try:
            await move_sample_history()
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("sample history: move failed (%s); retrying", type(exc).__name__)
            await asyncio.sleep(RETRY_SECONDS)
