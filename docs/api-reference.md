# API Reference

### Dashboard
| Method | Endpoint         | Description                                          |
|--------|------------------|------------------------------------------------------|
| GET    | `/api/dashboard` | Stats, recent jobs, inventory overview, device health, open alerts; with the `monitoring` feature also `topology`: entity counts by state (total, per provider, and `by_source`: one `{provider, org_ref, entity_type, up, degraded, down, unknown}` row per entity type of each source; the AWS, Azure and GCP accounts of one cloud share one `org_ref`) and the down / degraded integration entities, down first, newest first, at most 50 |
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
| PUT    | `/api/hosts/{id}`             | Update a host `{hostname, ip_address, device_type, vrf_name?, vlan_id?, ...}`; `vrf_name` and `vlan_id` are each left alone when absent or null and set (`""` clears) when sent |
| DELETE | `/api/hosts/{id}`             | Remove a host                                    |

### VRFs, VLANs and interface addresses
Reads need the `ipam` feature, writes are admin only and audited (`network_objects`). See [vrfs-and-vlans.md](vrfs-and-vlans.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/ipam/vrfs` | `{"vrfs": [Vrf]}` by name. A Vrf: `id`, `name`, `rd`, `description`, `origin` (`manual`, `discovered`), `created_at`, `host_count`, `device_count`, `prefix_count`, `address_count` |
| POST   | `/api/ipam/vrfs` | `{name, rd?, description?}`. `201` with the Vrf; `409` when a VRF has the name ignoring case |
| GET    | `/api/ipam/vrfs/{id}` | The Vrf plus `devices` (`host_id`, `hostname`, `interface_count`), `interfaces` (at most 2000 interface addresses), `truncated`, `prefixes` (`subnet`, `source`: the IPAM source's provider or `interface`) |
| PUT    | `/api/ipam/vrfs/{id}` | `{rd?, description?}`; a `name` key gives `422` |
| DELETE | `/api/ipam/vrfs/{id}` | `{"ok": true}`; `409` with `detail = {message, affected}` while hosts, IPAM prefixes or allocations, interface addresses or devices use the name (`message` names them, `affected` is the total) |
| GET    | `/api/ipam/vlans` | `{"vlans": [Vlan]}` by site name then VLAN id; `site_id=<id>` or `site_id=none`, `vid=<n>`. A Vlan: `id`, `vid`, `name`, `site_id`, `site` (`{id, name}` or null), `description`, `origin`, `created_at`, `device_count`, `interface_count`, `prefix_count`, `name_mismatch` |
| POST   | `/api/ipam/vlans` | `{vid, name?, site_id?, description?}`. `201` with the Vlan; `409` when the site (or no site) has the VLAN id; `400` with `detail.fields.site_id` for an unknown site |
| GET    | `/api/ipam/vlans/{id}` | The Vlan plus `devices` (`host_id`, `hostname`, `name`, `state`, `name_matches`), `interfaces` (`host_id`, `hostname`, `interface`, `mode`: `access` or `trunk`; at most 2000), `truncated`, `prefixes` (`network`, `vrf_name`, `host_id`, `hostname`, `interface`, `address`) |
| PUT    | `/api/ipam/vlans/{id}` | `{name?, site_id?, description?}` (`site_id` null: no site); `409` when the move collides; a `vid` key gives `422` |
| DELETE | `/api/ipam/vlans/{id}` | `{"ok": true}` |
| POST   | `/api/ipam/interface-addresses/rebuild` | Admin. Reads the newest stored configuration of every host again: `{"ok": true, "hosts": <read>, "addresses": <stored>}` |
| GET    | `/api/hosts/{host_id}/interface-addresses` | `reports` feature, like `/api/hosts/{host_id}/interface-inventory`. `{host_id, addresses, vrfs}`: each address `host_id`, `hostname`, `interface`, `address`, `prefix_length`, `network`, `vrf_name`, `role` (`primary`, `secondary`, `virtual`), `protocol` (`HSRP`, `VRRP`, `GLBP` or `""`), `svi_vid`, `collected_at`, `vrf_id`, `vlan_id`; each VRF `name`, `vrf_id`, `interface_count` |

`GET /api/ipam/address/{ip}` adds `interfaces`: the interface addresses equal to the address (only those of `vrf` when it is given). `GET /api/ipam/subnets/{subnet}` adds `interfaces`: the interface addresses inside the subnet, at most 1024; with `vrf` empty or absent they come from every VRF (each row carries its `vrf_name`), with `vrf` only from that VRF.

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

### Integration availability mutes
Mutes of the entities the integrations collect (Meraki, Cato, FMC, Panorama, Appgate, AWS, Azure, GCP). A muted entity is left off the Dashboard and raises no alert. See [meraki-topology.md](meraki-topology.md#muting).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/availability/topology/mutes` | `monitoring` feature. `mutes`: each with `id`, `provider`, `org_ref`, `scope` (`entity`, `site`), `entity_type`, `entity_id`, `site`, `reason`, `created_by`, `created_at` (UTC) |
| POST   | `/api/availability/topology/mutes` | `monitoring` feature, audited. `provider`, `org_ref`, `scope`, `reason` (1 to 500 characters) and, for `entity`, `entity_type` and `entity_id`, or for `site`, `site`. `404` when no tracked entity matches. Muting the same target again updates the reason. Returns `201` with `mute` and `acknowledged` (open host alerts acknowledged as `muted`) |
| DELETE | `/api/availability/topology/mutes/{id}` | `monitoring` feature, audited. `404` when absent |

`GET /api/availability/topology/summary` marks each entity with `muted` and `mute` (`id`, `scope`, `site`, `reason`, `created_by`, `created_at`, or null) and returns a `muted` total; its `up`, `degraded`, `down`, `unknown`, `avg_uptime_pct` and `total_outages` leave muted entities out. In `GET /api/dashboard`, `topology.entity_counts`, `by_provider` and `by_source` count a muted down or degraded entity under `muted`, and `problems` and `problem_count` leave it out.

### Meraki alerts
Near-real-time Meraki alerts from the assurance-alert poll and the webhook receiver. See [meraki-alerts.md](meraki-alerts.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/monitoring/meraki-alerts` | `monitoring` feature. The alerts, open first then worst and newest; `include_resolved` (default false), `org_ref` (one source), `limit` (1 to 5000, default 500). Each row has `alert_key`, organization, network and device, `alert_type`, `condition`, `title`, `message`, `severity` (`critical`, `warning`, `info`), `status` (`open`, `resolved`), `started_at`, `resolved_at`, `last_seen` (UTC), `seen_via` (`poll`, `webhook`) and `alert_via` (how Plexus alerted: `monitoring`, `notification`, `topology`, `muted`, or empty) and `muted` (its device or network is muted) |
| GET    | `/api/monitoring/meraki-alerts/settings` | Admin. `config` (`poll_enabled`, `interval_seconds`, `webhook_enabled`, `webhook_secret_configured`, `excluded_sources`, `webhook_open_ttl_hours`), `webhook_active`, `webhook_path`, the interval bounds, `status` (last poll, last webhook, last test webhook, accepted / rejected / unknown-organization counts) and `sources` (each Meraki source with its last poll, last success and last error). The secret is never returned |
| PUT    | `/api/monitoring/meraki-alerts/settings` | Admin, audited. Any of `poll_enabled`, `interval_seconds` (30 to 3600), `webhook_enabled`, `webhook_secret` (16 to 256 printable characters; sets or rotates the secret and turns the receiver on unless `webhook_enabled` is false), `clear_webhook_secret`, `excluded_sources` (source ids not polled; their webhooks are still accepted), `webhook_open_ttl_hours`. Returns the same body as GET |
| POST   | `/api/monitoring/meraki-alerts/poll` | Admin, audited. Poll every enabled Meraki source now, ignoring back-off and the poll switch; returns per-source results |
| POST   | `/api/webhooks/meraki` | Meraki's webhook receiver (no session, no CSRF). JSON only, at most 256 KiB; `sharedSecret` in the body must match. `200 {"ok": true}` when accepted (the alert work runs after the response), `401` on a wrong or missing secret, `404` while the receiver is off, `400` / `413` / `415` on a malformed, oversized or non-JSON body, `429` when the source IP passes its rate limit |

### AI access (MCP)
A read-only Model Context Protocol endpoint for AI clients, and the admin routes that manage it. See [ai-access.md](ai-access.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST   | `/mcp` | The MCP endpoint (Streamable HTTP, JSON responses, stateless; `/mcp/` is the same). Authenticated only by `Authorization: Bearer <MCP token>`: no session cookie, no CSRF token, and `APP_API_TOKEN` is refused. `404` while AI access is off, `401 {"error": "unauthorized"}` with `WWW-Authenticate: Bearer` on a missing, unknown, revoked or expired token, `429` after 20 failed attempts from one address in a minute, `405` for any method but POST. Serves `initialize`, `ping`, `tools/list` (only the tools the token may use) and `tools/call`; tool failures are returned as MCP tool errors, never as HTTP 500 |
| GET    | `/api/admin/mcp/settings` | Admin. `enabled`, `max_result_bytes`, `max_rows`, `calls_per_minute` |
| PUT    | `/api/admin/mcp/settings` | Admin, audited. Any of `enabled` (boolean), `max_result_bytes` (10000 to 1000000), `max_rows` (10 to 1000), `calls_per_minute` (1 to 600). Returns the merged settings; `422` on an unknown key or a value out of bounds |
| GET    | `/api/admin/mcp/tokens` | Admin. `tokens` (each with `id`, `name`, `token_prefix`, `owner_user_id`, `owner_username`, `owner_role`, `categories`, `expires_at`, `created_at`, `created_by`, `last_used_at`, `call_count`, `revoked_at`; never the token or its hash) and `categories` (every category a token can be given) |
| POST   | `/api/admin/mcp/tokens` | Admin, audited. `name` (1 to 80 characters, unique), `owner_user_id`, `categories` (non-empty subset of the known categories), `expires_at` (`""` or `YYYY-MM-DD`). Returns `{"token", "record"}`; `token` is the only time the plaintext is returned. `422` on invalid input (including the `audit` category with a non-admin owner), `409` when the name is taken |
| DELETE | `/api/admin/mcp/tokens/{id}` | Admin, audited. Revokes the token: `{"revoked": true}`; `404` when it does not exist or is already revoked |
