# API Reference

### Dashboard
| Method | Endpoint         | Description                                          |
|--------|------------------|------------------------------------------------------|
| GET    | `/api/dashboard` | Stats, recent jobs, inventory overview, device health, open alerts; with the `monitoring` feature also `topology`: entity counts by state (total and per provider) and the down / degraded integration entities, down first, newest first, at most 50 |
| GET    | `/api/health`    | Service health + lightweight counters/timing metrics |

### Inventory
| Method | Endpoint                      | Description                                      |
|--------|-------------------------------|--------------------------------------------------|
| GET    | `/api/inventory`              | List all groups (with host counts)               |
| POST   | `/api/inventory`              | Create group `{name, description}`               |
| GET    | `/api/inventory/{id}`         | Group detail with hosts                          |
| DELETE | `/api/inventory/{id}`         | Delete group and its hosts                       |
| GET    | `/api/inventory/{id}/hosts`   | List hosts in group                              |
| POST   | `/api/inventory/{id}/hosts`   | Add host `{hostname, ip_address, device_type}`   |
| DELETE | `/api/hosts/{id}`             | Remove a host                                    |

### Source device import
Admin only (and the `topology` and `inventory` features). See [After adding a source](meraki-topology.md#after-adding-a-source).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/sources/{org_ref}/importable-devices` | The devices of the source's latest collection that have a usable management address: `devices` (each `key` (node id), `name`, `ip`, `model`, `serial`, `kind`, `site`, `platform`, `device_type` it would get, `capabilities` `{snmp_polling, config_backup}`, `existing` (the inventory host it already is, by address or by the collection's match, or null)), `reason` (why the list is empty, else `""`), `provider`, `provider_note`, `snapshot_id`, `collected_at`, `suggested_group_name`, `max_devices`, `monitoring_enabled`. One device per address, sorted by name |
| POST   | `/api/sources/{org_ref}/import-devices` | `{device_keys, group_id \| new_group_name, snmp_profile_id?, backup_credential_id?}`. Everything is validated before anything is written (keys of the latest collection, an existing group or a new top-level name not taken (409), an existing SNMP profile, a credential the caller may use, and a backup only for devices Config Backups can read). Adds the devices not in the inventory (never changes an existing host; those are reported under `skipped`), assigns the SNMP profile to the group unless it already has another (`kept`), and creates a daily backup policy for the group unless it has one (`exists`). Returns `group {id, name, created}`, `added`, `skipped`, `errors`, `counts`, `snmp_profile {status, profile_id, profile_name}`, `backup_policy {status, policy_id, name, interval_seconds, retention_days}`, `monitoring_enabled`. Audited. 409 when the source has never been collected |

### Playbooks
| Method | Endpoint              | Description                                      |
|--------|-----------------------|--------------------------------------------------|
| GET    | `/api/playbooks`      | List all (with last run status)                  |
| POST   | `/api/playbooks`      | Register `{name, filename, description, tags}`   |
| DELETE | `/api/playbooks/{id}` | Unregister                                       |

### Templates
| Method | Endpoint              | Description                             |
|--------|-----------------------|-----------------------------------------|
| GET    | `/api/templates`      | List all                                |
| POST   | `/api/templates`      | Create `{name, content, description}`   |
| GET    | `/api/templates/{id}` | Get one                                 |
| PUT    | `/api/templates/{id}` | Update `{name, content, description}`   |
| DELETE | `/api/templates/{id}` | Delete                                  |

### Credentials
| Method | Endpoint                | Description                                   |
|--------|-------------------------|-----------------------------------------------|
| GET    | `/api/credentials`      | List all (passwords masked)                   |
| POST   | `/api/credentials`      | Create `{name, username, password, secret}`   |
| DELETE | `/api/credentials/{id}` | Delete                                        |

### Jobs
| Method | Endpoint                | Description                |
|--------|-------------------------|----------------------------|
| GET    | `/api/jobs`             | List job history           |
| GET    | `/api/jobs/{id}`        | Job detail                 |
| GET    | `/api/jobs/{id}/events` | All log events for a job   |
| POST   | `/api/jobs/launch`      | Launch a job (see below)   |
| WS     | `/ws/jobs/{id}`         | Real-time event stream     |

**Launch payload:**
```json
{
  "playbook_id": 3,
  "inventory_group_id": 1,
  "credential_id": 1,
  "template_id": 1,
  "dry_run": true
}
```

### Meraki alerts
Near-real-time Meraki alerts from the assurance-alert poll and the webhook receiver. See [meraki-alerts.md](meraki-alerts.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/monitoring/meraki-alerts` | `monitoring` feature. The alerts, open first then worst and newest; `include_resolved` (default false), `org_ref` (one source), `limit` (1 to 5000, default 500). Each row has `alert_key`, organization, network and device, `alert_type`, `condition`, `title`, `message`, `severity` (`critical`, `warning`, `info`), `status` (`open`, `resolved`), `started_at`, `resolved_at`, `last_seen` (UTC), `seen_via` (`poll`, `webhook`) and `alert_via` (how Plexus alerted: `monitoring`, `notification`, `topology`, or empty) |
| GET    | `/api/monitoring/meraki-alerts/settings` | Admin. `config` (`poll_enabled`, `interval_seconds`, `webhook_enabled`, `webhook_secret_configured`, `excluded_sources`, `webhook_open_ttl_hours`), `webhook_active`, `webhook_path`, the interval bounds, `status` (last poll, last webhook, last test webhook, accepted / rejected / unknown-organization counts) and `sources` (each Meraki source with its last poll, last success and last error). The secret is never returned |
| PUT    | `/api/monitoring/meraki-alerts/settings` | Admin, audited. Any of `poll_enabled`, `interval_seconds` (30 to 3600), `webhook_enabled`, `webhook_secret` (16 to 256 printable characters; sets or rotates the secret and turns the receiver on unless `webhook_enabled` is false), `clear_webhook_secret`, `excluded_sources` (source ids not polled; their webhooks are still accepted), `webhook_open_ttl_hours`. Returns the same body as GET |
| POST   | `/api/monitoring/meraki-alerts/poll` | Admin, audited. Poll every enabled Meraki source now, ignoring back-off and the poll switch; returns per-source results |
| POST   | `/api/webhooks/meraki` | Meraki's webhook receiver (no session, no CSRF). JSON only, at most 256 KiB; `sharedSecret` in the body must match. `200 {"ok": true}` when accepted (the alert work runs after the response), `401` on a wrong or missing secret, `404` while the receiver is off, `400` / `413` / `415` on a malformed, oversized or non-JSON body, `429` when the source IP passes its rate limit |
