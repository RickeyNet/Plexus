"""
Migration 0074: SLA rollups and server-side SLA target evaluation.

Adds:
  - ``sla_metrics.sum_value`` and ``sla_metrics.sum_sq``: the sum and the
    sum of squares behind each rollup, so windows longer than the raw poll
    retention can be recombined exactly (uptime: polls and ok polls;
    latency and jitter: response-time samples, their sum and sum of
    squares; packet loss: samples and their sum).
  - a unique index on ``sla_metrics (host_id, metric, time_window,
    period_start)`` so a rollup pass never writes a period twice, and an
    index on ``(time_window, period_end)`` for the rollup watermark.
  - ``sla_targets.window_days`` (default 30): the window a target is
    evaluated over.
  - ``sla_target_status``: the latest evaluation of every enabled target
    for every host it applies to (one row per target and host).
  - ``sla_target_status_history``: append-only, one row each time a
    target's status for a host changes (and for its first evaluation).

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 74
DESCRIPTION = "Add SLA rollup sums, sla_targets.window_days and SLA target status tables"


async def up(db) -> None:
    await db.execute("ALTER TABLE sla_metrics ADD COLUMN IF NOT EXISTS sum_value REAL NOT NULL DEFAULT 0")
    await db.execute("ALTER TABLE sla_metrics ADD COLUMN IF NOT EXISTS sum_sq REAL NOT NULL DEFAULT 0")
    # Nothing wrote sla_metrics before this migration, but drop any duplicate
    # period so the unique index can be built on every database.
    await db.execute(
        """DELETE FROM sla_metrics a
           USING sla_metrics b
           WHERE a.id > b.id
             AND a.host_id = b.host_id
             AND a.metric = b.metric
             AND a.time_window = b.time_window
             AND a.period_start = b.period_start"""
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_sla_metrics_period "
        "ON sla_metrics (host_id, metric, time_window, period_start)"
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_sla_metrics_window_end ON sla_metrics (time_window, period_end)")
    await db.execute("ALTER TABLE sla_targets ADD COLUMN IF NOT EXISTS window_days INTEGER NOT NULL DEFAULT 30")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS sla_target_status (
            id             SERIAL PRIMARY KEY,
            target_id      INTEGER NOT NULL REFERENCES sla_targets(id) ON DELETE CASCADE,
            host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            metric         TEXT    NOT NULL DEFAULT '',
            value          REAL,
            target_value   REAL    NOT NULL DEFAULT 0,
            warning_value  REAL    NOT NULL DEFAULT 0,
            status         TEXT    NOT NULL DEFAULT 'no_data',
            sample_count   INTEGER NOT NULL DEFAULT 0,
            window_days    INTEGER NOT NULL DEFAULT 30,
            window_start   TEXT    NOT NULL DEFAULT '',
            window_end     TEXT    NOT NULL DEFAULT '',
            evaluated_at   TEXT    NOT NULL DEFAULT '',
            status_since   TEXT    NOT NULL DEFAULT '',
            UNIQUE(target_id, host_id)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_sla_target_status_host ON sla_target_status (host_id)")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS sla_target_status_history (
            id              SERIAL PRIMARY KEY,
            target_id       INTEGER NOT NULL REFERENCES sla_targets(id) ON DELETE CASCADE,
            host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            metric          TEXT    NOT NULL DEFAULT '',
            value           REAL,
            status          TEXT    NOT NULL DEFAULT 'no_data',
            previous_status TEXT    NOT NULL DEFAULT '',
            window_start    TEXT    NOT NULL DEFAULT '',
            window_end      TEXT    NOT NULL DEFAULT '',
            evaluated_at    TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_sla_target_status_history_pair "
        "ON sla_target_status_history (target_id, host_id, id)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_sla_target_status_history_host ON sla_target_status_history (host_id, id)"
    )
    await db.commit()
