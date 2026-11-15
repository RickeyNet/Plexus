"""
Migration 0091: latency / jitter / loss history and SLA targets of topology
(API-collected) entities, and device-scoped software advisories.

Adds:

  - topology_entity_metrics - one raw sample per tracked entity and
    collection that reported a metric (an OPNsense gateway's dpinger loss,
    RTT and RTT deviation): ``latency_ms``, ``jitter_ms``, ``loss_pct``
    (each nullable). Purged with the monitoring retention.
  - topology_entity_metric_daily - one row per entity, UTC day and metric
    (``latency``, ``jitter``, ``packet_loss``) with the sample count, sum
    and sum of squares, added to as each sample is recorded. Purged with the
    SLA retention, so a window longer than the raw retention is exact to
    the day.
  - sla_targets.provider / org_ref / entity_type / entity_id - a target with
    a ``provider`` applies to tracked topology entities (that provider; the
    other three narrow it when set) instead of inventory hosts.
  - topology_sla_target_status - the latest evaluation of every enabled
    topology target for every entity it applies to (one row per target and
    entity), and topology_sla_target_status_history - one row each time
    that status changes (and for its first evaluation).
  - software_advisories.device_keys_json - the tracked devices an advisory
    is limited to (``[]``: every device its platform, product and versions
    match, as before). The OPNsense audit fills it with the firewall whose
    audit reported the finding.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 91
DESCRIPTION = "Add topology entity metrics, topology SLA targets and device-scoped advisories"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS topology_entity_metrics (
            id           SERIAL PRIMARY KEY,
            provider     TEXT    NOT NULL,
            org_ref      INTEGER NOT NULL DEFAULT 0,
            entity_type  TEXT    NOT NULL,
            entity_id    TEXT    NOT NULL,
            sampled_at   TEXT    NOT NULL DEFAULT '',
            latency_ms   REAL,
            jitter_ms    REAL,
            loss_pct     REAL
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_topo_entity_metrics_entity "
        "ON topology_entity_metrics (provider, org_ref, entity_type, entity_id, sampled_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_topo_entity_metrics_at ON topology_entity_metrics (sampled_at)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS topology_entity_metric_daily (
            id           SERIAL PRIMARY KEY,
            provider     TEXT    NOT NULL,
            org_ref      INTEGER NOT NULL DEFAULT 0,
            entity_type  TEXT    NOT NULL,
            entity_id    TEXT    NOT NULL,
            day          TEXT    NOT NULL,
            metric       TEXT    NOT NULL,
            sample_count INTEGER NOT NULL DEFAULT 0,
            sum_value    REAL    NOT NULL DEFAULT 0,
            sum_sq       REAL    NOT NULL DEFAULT 0,
            min_value    REAL,
            max_value    REAL,
            UNIQUE (provider, org_ref, entity_type, entity_id, day, metric)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_topo_entity_metric_daily_day ON topology_entity_metric_daily (day)")
    for column, decl in (
        ("provider", "TEXT NOT NULL DEFAULT ''"),
        ("org_ref", "INTEGER"),
        ("entity_type", "TEXT NOT NULL DEFAULT ''"),
        ("entity_id", "TEXT NOT NULL DEFAULT ''"),
    ):
        await db.execute(f"ALTER TABLE sla_targets ADD COLUMN IF NOT EXISTS {column} {decl}")
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS topology_sla_target_status (
            id             SERIAL PRIMARY KEY,
            target_id      INTEGER NOT NULL REFERENCES sla_targets(id) ON DELETE CASCADE,
            provider       TEXT    NOT NULL,
            org_ref        INTEGER NOT NULL DEFAULT 0,
            entity_type    TEXT    NOT NULL,
            entity_id      TEXT    NOT NULL,
            name           TEXT    NOT NULL DEFAULT '',
            site           TEXT    NOT NULL DEFAULT '',
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
            UNIQUE (target_id, provider, org_ref, entity_type, entity_id)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_topo_sla_status_entity "
        "ON topology_sla_target_status (provider, org_ref, entity_type, entity_id)"
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS topology_sla_target_status_history (
            id              SERIAL PRIMARY KEY,
            target_id       INTEGER NOT NULL REFERENCES sla_targets(id) ON DELETE CASCADE,
            provider        TEXT    NOT NULL,
            org_ref         INTEGER NOT NULL DEFAULT 0,
            entity_type     TEXT    NOT NULL,
            entity_id       TEXT    NOT NULL,
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
        "CREATE INDEX IF NOT EXISTS idx_topo_sla_history_target ON topology_sla_target_status_history (target_id, id)"
    )
    await db.execute(
        "ALTER TABLE software_advisories ADD COLUMN IF NOT EXISTS device_keys_json TEXT NOT NULL DEFAULT '[]'"
    )
    await db.commit()
