# Plexus - Data Retention

How long Plexus keeps each class of operational data, where the setting
lives, and how cleanup is triggered.

Background loops on startup and on a periodic schedule prune anything past
its retention window - operators don't need to run cleanup commands
manually. All retention values can be tuned at runtime via the Settings UI
or the corresponding API endpoint without a restart.

## Retention table

| Data class                       | Default retention | Configurable via                                              |
|----------------------------------|-------------------|---------------------------------------------------------------|
| Job history (completed jobs)     | 30 days           | `Settings > Authentication Provider > Job History Retention`  |
| **Raw flow records**             | **48 hours**      | `Settings > NetFlow > Retention (hours)` / `retention_hours`  |
| Flow summaries (no longer written; older rows drain) | 30 days | `Settings > NetFlow > Summary retention (days)` / `summary_retention_days` |
| Config backups                   | 90 days           | `Settings > Config Backup`                                    |
| Monitoring poll history          | 30 days           | `Settings > Monitoring`. A poll's interface, VPN and route details are stored only on the newest poll and where they changed (`docs/monitoring.md`, "Rules worth knowing") |
| Monitoring alerts                | 90 days           | `Settings > Monitoring`                                       |
| Interface error/discard events   | 90 days           | `Settings > Monitoring`                                       |
| Interface time-series counters   | 30 days           | `Settings > Monitoring`                                       |
| SLA / latency probe metrics      | 90 days           | `Settings > Monitoring`                                       |
| Route snapshots                  | 30 days           | `Settings > Monitoring`                                       |
| Meraki alerts (resolved)         | 30 days           | `Settings > Monitoring` (`retention_days`); open alerts are kept |
| SNMP trap / syslog events        | 30 days           | `Settings > Monitoring`                                       |
| Availability transitions (`availability_transitions`) | 400 days | `Settings > Monitoring` (`sla_retention_days`, the SLA rollup retention, 30 to 3650); pruned by the monitoring retention pass. The newest transition of each host/entity is kept however old: it holds the current state |
| IP history (IPAM, closed rows)   | 365 days          | Fixed; pruned by the monitoring retention pass (`routes.database.prune_ip_history`). Open rows (current assignments) are kept |
| **Cloud flow records**           | **48 hours**      | Shares `flow_records` + NetFlow `retention_hours`; pruned by the cloud flow sync loop even when the NetFlow collector is disabled |
| **Cloud traffic metrics**        | **7 days (168h)** | `PUT /api/cloud/traffic-sync/config` `retention_hours`; pruned by the cloud traffic sync loop |
| Webhook delivery log (`webhook_deliveries`) | 30 days | `APP_WEBHOOK_DELIVERY_RETENTION_DAYS` (env, minimum 1); pruned hourly by the webhook dispatcher. Deleting a webhook deletes its log. See `docs/webhooks.md` |
| Per-object change log (`object_changes`) | 90 days | `Settings > System > Change log` / `change_log_retention_days` (1 to 3650); pruned hourly. See `docs/change-log.md` |
| ChatOps command log (`chatops_command_log`) | 90 days | Fixed; rows older than that are deleted as new commands are logged. See `docs/chatops.md` |
| SNMP trap receiver engine and SNMPv3 replay record (`snmp_local_engine`, `snmpv3_replay_state`) | Engine: one row, kept. Replay record: the 4096 most recently seen sender engines | None. The engine ID and boots counter must survive restarts (SNMPv3 informs). The replay record (per source address and sender engine ID: boots, engine time, when seen; no message content) is written at most once a minute and at shutdown, and older rows are deleted beyond the newest 4096. See `docs/snmp-traps.md` |
| Hardware components and their history (`hardware_components`, `hardware_component_events`, `hardware_collection_state`) | Kept; not pruned automatically | None. A host's components (present, missing and removed) and its collection state are deleted with the host; its history events are kept after the host is deleted (host link cleared, hostname kept) so a serial can still be traced. See `docs/hardware-inventory.md` |

Minimums are enforced at the API layer (e.g. job history can't go below
30 days). Increase a value freely; the next cleanup pass will simply
keep more rows.

## NetFlow / sFlow / IPFIX

The flow collector writes two tables:

- **`flow_records`** - one row per decoded flow record (NetFlow v5/v9,
  IPFIX, or sFlow sample). High write volume. Default retention is
  **48 hours**.
- **`flow_summaries`** - hourly global top-50 lists an older release
  wrote. Nothing writes or reads them now: they had no host dimension (so
  the object scope could not apply), no interfaces or timeline, and a top
  50 per hour does not add up to the top N of a longer window. The table
  stays; old rows are deleted at `summary_retention_days` (**30 days**).

The upkeep loop runs hourly while the collector is enabled. Each cycle it:

1. Re-reads the exporter cache.
2. Deletes `flow_records` older than `retention_hours`.
3. Deletes `flow_summaries` written more than `summary_retention_days`
   ago.

The flow views (Traffic Analysis, a device's Flow tab, the cloud flow tab)
aggregate `flow_records` directly, one pass per view, so they cover at most
`retention_hours`.

If you need longer raw-flow retention (e.g. for security forensics) you
can bump `retention_hours` - flow record rows are small but volume scales
linearly with traffic and exporter sampling rate, so size the underlying
DB volume (`plexus-postgres`) accordingly.

### Tuning at runtime

UI: `Settings > NetFlow`. The page exposes `Retention (hours)` and
`Summary retention (days)` alongside the enable toggle. Saving rebinds
the listeners only if `enabled` / `netflow_port` / `sflow_port` changed -
retention adjustments take effect on the next cleanup pass without
disrupting collection.

API:

```bash
curl -X PUT http://localhost:8080/api/admin/flows/config \
  -H "Content-Type: application/json" \
  -d '{
        "enabled": true,
        "retention_hours": 168,
        "summary_retention_days": 90
      }'
```

The persisted config lives in `auth_settings("flow_collector")`. On first
boot only, that row is seeded from the legacy `APP_NETFLOW_*` env vars;
after that the database row is authoritative and env-var changes are
ignored.

## Cloud visibility data

Cloud flow-log pulls (AWS CloudWatch Logs, Azure NSG blobs, GCP Cloud
Logging) land in the shared **`flow_records`** table and follow the same
NetFlow `retention_hours` value. The cloud flow sync loop runs the cleanup
itself each cycle, so retention applies even on cloud-only deployments
where the NetFlow collector is disabled.

Cloud traffic metrics (CloudWatch / Azure Monitor / Cloud Monitoring
samples) live in **`cloud_traffic_metrics`** with a default retention of
**168 hours (7 days)**, tunable 1-8760 via `retention_hours` on
`PUT /api/cloud/traffic-sync/config`. Ingestion is idempotent (unique
sample-identity index), so overlapping pull windows don't inflate storage.

Topology snapshots (`cloud_resources`, `cloud_connections`,
`cloud_policy_rules`, `cloud_hybrid_links`) are replaced wholesale on each
successful discovery and are small; they have no time-based retention.

## Job history

Completed jobs (`success` or `failed`) older than the configured retention
are deleted automatically. Running jobs are never touched. Cleanup runs
at startup and on a periodic timer.

Minimum retention: **30 days**. The Settings UI clamps anything lower to
30 before saving.

## Backups, monitoring, IPAM history

These follow the same shape: a background cleanup task runs periodically
and deletes rows older than the retention window. Defaults are listed in
the table above. All are tunable from the Settings UI under the relevant
section (Monitoring, Config Backup, etc.).

## Encryption-at-rest considerations

Retention controls how long data lives in the database. Some of that data
is sensitive - credentials are AES-256-GCM encrypted in the `credentials`
table, but other tables (config backups, syslog events) may contain
hostnames, interface names, neighbor IPs, and free-text command output.
Disk-level encryption (LUKS, BitLocker, cloud-volume KMS) is recommended
for production deployments; Plexus itself doesn't encrypt the PostgreSQL
volume.
