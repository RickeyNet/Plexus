"""
Migration 0142: Indexes for unindexed hot paths; drop two unused flow indexes.

Adds:
  - ``availability_transitions(poll_id)``: the FK is ``ON DELETE SET NULL``,
    so every poll retention delete scanned the whole table per batch.
  - ``monitoring_alerts(dedup_key) WHERE acknowledged = 0``: the dedup check
    on every alert insert and ``resolve_monitoring_alerts``.
  - ``monitoring_alerts(host_id, metric) WHERE acknowledged = 0``:
    ``list_open_monitoring_alert_keys``. Both partial indexes cover only the
    open alerts, which stay few while acknowledged ones pile up until
    retention.
  - ``mac_tracking_history(host_id, mac_address, id)``: the per-host
    latest-location query in ``record_mac_sightings_batch`` and the
    per-MAC-per-host lookup in ``record_mac_history``.
  - ``mac_tracking_history(seen_at)``: the retention delete.
  - ``route_snapshots(host_id, id)``: newest snapshot per host and the
    per-host listing.
  - ``config_backups(host_id, id)``: newest backup per host and the
    retention delete that keeps each host's newest successful backup.

Drops ``idx_flow_src`` and ``idx_flow_dst``: no query filters flow_records
by src_ip or dst_ip, so they only cost write amplification on the busiest
insert path.

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 142
DESCRIPTION = "Add hot-path indexes; drop unused flow_records src/dst indexes"


async def up(db) -> None:
    await db.execute("CREATE INDEX IF NOT EXISTS idx_avail_transitions_poll ON availability_transitions(poll_id)")
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_monitoring_alerts_open_dedup "
        "ON monitoring_alerts(dedup_key) WHERE acknowledged = 0"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_monitoring_alerts_open_host_metric "
        "ON monitoring_alerts(host_id, metric) WHERE acknowledged = 0"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_mac_history_host_mac ON mac_tracking_history(host_id, mac_address, id)"
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_mac_history_seen_at ON mac_tracking_history(seen_at)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_route_snapshots_host_id ON route_snapshots(host_id, id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_config_backups_host_id ON config_backups(host_id, id)")
    await db.execute("DROP INDEX IF EXISTS idx_flow_src")
    await db.execute("DROP INDEX IF EXISTS idx_flow_dst")
    await db.commit()
