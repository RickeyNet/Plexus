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
| **Aggregated flow summaries**    | **30 days**       | `Settings > NetFlow > Summary retention (days)` / `summary_retention_days` |
| Config backups                   | 90 days           | `Settings > Config Backup`                                    |
| Monitoring poll history          | 30 days           | `Settings > Monitoring`                                       |
| Monitoring alerts                | 90 days           | `Settings > Monitoring`                                       |
| Interface error/discard events   | 90 days           | `Settings > Monitoring`                                       |
| Interface time-series counters   | 30 days           | `Settings > Monitoring`                                       |
| SLA / latency probe metrics      | 90 days           | `Settings > Monitoring`                                       |
| Route snapshots                  | 30 days           | `Settings > Monitoring`                                       |
| SNMP trap / syslog events        | 30 days           | `Settings > Monitoring`                                       |
| IP history (IPAM)                | 365 days          | API-only - `routes.database.prune_ip_history(retention_days)` |
| **Cloud flow records**           | **48 hours**      | Shares `flow_records` + NetFlow `retention_hours`; pruned by the cloud flow sync loop even when the NetFlow collector is disabled |
| **Cloud traffic metrics**        | **7 days (168h)** | `PUT /api/cloud/traffic-sync/config` `retention_hours`; pruned by the cloud traffic sync loop |

Minimums are enforced at the API layer (e.g. job history can't go below
30 days). Increase a value freely; the next cleanup pass will simply
keep more rows.

## NetFlow / sFlow / IPFIX

The flow collector writes two tables:

- **`flow_records`** - one row per decoded flow record (NetFlow v5/v9,
  IPFIX, or sFlow sample). High write volume. Default retention is
  **48 hours**.
- **`flow_summaries`** - hourly rollups produced by the aggregation loop:
  top-talkers (src + dst), top applications, top conversations. Cheap to
  store. Default retention is **30 days**.

The aggregation loop runs hourly while the collector is enabled. Each
cycle it:

1. Computes the previous hour's top-talkers / top-applications /
   top-conversations from `flow_records` and inserts them into
   `flow_summaries`.
2. Deletes `flow_records` older than `retention_hours`.

The split is intentional: detailed per-flow data is expensive to keep and
loses utility after a couple of days, but the aggregated views are small
and useful for week-over-week or month-over-month trend questions in the
Traffic Analysis page.

If you need longer raw-flow retention (e.g. for security forensics) you
can bump `retention_hours` - flow record rows are small but volume scales
linearly with traffic and exporter sampling rate, so size the underlying
DB volume accordingly. PostgreSQL backends handle the larger row counts
more gracefully than SQLite.

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
is sensitive - credentials are Fernet-encrypted in the `credentials`
table, but other tables (config backups, syslog events) may contain
hostnames, interface names, neighbor IPs, and free-text command output.
Disk-level encryption (LUKS, BitLocker, cloud-volume KMS) is recommended
for production deployments; Plexus itself doesn't encrypt the SQLite /
PostgreSQL volume.
