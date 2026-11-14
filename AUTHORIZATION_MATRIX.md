# Authorization Matrix

All API endpoints and their required authentication/authorization levels.

## Legend

| Guard | Meaning |
|-------|---------|
| **public** | No authentication required |
| **auth** | Valid session cookie or API token |
| **feature(X)** | Authenticated + user has access to feature X |
| **admin** | Authenticated + `role == "admin"` |
| **ws-auth** | WebSocket with session cookie validated before `accept()` |
| **mcp-token** | `Authorization: Bearer` MCP token created by an admin (hashed at rest); never a session cookie or `APP_API_TOKEN` |

## Endpoints

### Public (no auth)

| Method | Path | Notes |
|--------|------|-------|
| GET | `/` | Frontend SPA |
| POST | `/api/auth/login` | Rate-limited (brute-force protection) |
| POST | `/api/auth/register` | Gated by `APP_ALLOW_SELF_REGISTER` env flag |
| GET | `/api/auth/status` | Returns current session info |
| GET | `/api/health` | Health check (uptime, metrics) |
| GET | `/favicon.ico` | Static |
| GET | `/static/*` | Static files |
| POST | `/api/webhooks/meraki` | Meraki webhook receiver. No session or CSRF; authenticated by the shared secret in the body (constant-time compare). Answers 404 until an admin sets a secret and turns it on; 401 on a wrong secret. Rate limited per source IP on its own budget (600 per window). See `docs/meraki-alerts.md` |

### Auth-only (any authenticated user)

| Method | Path | Router |
|--------|------|--------|
| POST | `/api/auth/logout` | auth |
| PUT | `/api/auth/change-password` | auth |
| GET/PUT | `/api/auth/profile` | auth |
| GET | `/api/dashboard` | + feature("dashboard") |
| CRUD | `/api/graphs/*` | graph_export |
| CRUD | `/api/dashboards/*` | dashboards |
| CRUD | `/api/graph-templates/*` | graph_templates |
| CRUD | `/api/reporting/*` | reporting |
| CRUD | `/api/cdef/*` | cdef |
| CRUD | `/api/mac-tracking/*` | mac_tracking |
| CRUD | `/api/flow-collector/*` | flow_collector |
| CRUD | `/api/baseline-alerting/*` | baseline_alerting |
| GET | `/api/custom-fields` (`?object_type=`), `/api/tags` (with usage counts) | custom_fields |
| GET | `/api/dcim/manufacturers`, `/api/dcim/device-types` (`?manufacturer_id=`), `/api/dcim/roles`, `/api/dcim/statuses` (with host counts) | device_model |

### Feature-gated (auth + feature flag)

| Feature | Paths | Router |
|---------|-------|--------|
| `inventory` | `/api/inventory/*` | inventory |
| `topology` | `/api/topology/*` | topology |
| `topology` | `/api/sources/*`, `/api/topology/search/deep`, `/api/topology/export.html` (collections/deletes need `topology.write`; source and credential management `POST/PUT/DELETE /api/sources*` is admin-only in the handlers) | meraki_topology |
| `jobs` | `/api/jobs/*` | jobs |
| `templates` | `/api/templates/*` | templates |
| `credentials` | `/api/credentials/*` | credentials |
| `playbooks` | `/api/playbooks/*` | playbooks |
| `config-drift` | `/api/config-drift/*` | config_drift |
| `config-backups` | `/api/config-backups/*` | config_backups |
| `compliance` | `/api/compliance/*` | compliance |
| `compliance` | `/api/compliance/meraki/*` (scans use the organization's stored Dashboard API key, read-only; organizations themselves are managed under `/api/sources*`, admin-only) | meraki_compliance |
| `risk-analysis` | `/api/risk-analysis/*` | risk_analysis |
| `deployments` | `/api/deployments/*` | deployments |
| `monitoring` | `/api/monitoring/*`, `/api/sla/*` | monitoring |
| `monitoring` | `GET/POST /api/availability/topology/mutes`, `DELETE /api/availability/topology/mutes/{mute_id}` (mute and unmute an integration entity or site; the writes need `monitoring.write`, like acknowledging an alert; audited as `topology.muted` / `topology.unmuted`) | monitoring |
| `monitoring` | `/api/metrics/*` | metrics_engine |
| `monitoring` | `GET /api/monitoring/meraki-alerts` (the Meraki alert list) | meraki_alerts |
| `upgrades` | `/api/upgrades/*` | upgrades |
| `inventory` | `POST /api/tags`, `GET/PUT /api/hosts/{host_id}/custom-data`, `GET/PUT /api/inventory/{group_id}/custom-data`, `POST /api/hosts/bulk-tags` | custom_fields (inventory_router) |
| `inventory` | `POST /api/hosts/bulk-edit` (set device type, role, lifecycle status, site, location detail on many hosts; audited as `device_model` / `bulk_edit`) | device_model (inventory_router) |
| `ipam` | `GET /api/ipam/prefix-custom-data?subnet=&vrf=`; `PUT` needs `ipam.write` and admin (an admin dependency on the route, like every IPAM write) | custom_fields (ipam_router) |
| `ipam` | `GET /api/ipam/vrfs`, `GET /api/ipam/vrfs/{vrf_id}`, `GET /api/ipam/vlans`, `GET /api/ipam/vlans/{vlan_id}` (registered before the IPAM router) | network_objects (router) |
| `reports` | `GET /api/hosts/{host_id}/interface-addresses` (gated like `GET /api/hosts/{host_id}/interface-inventory`) | network_objects (host_router) |

### Admin-only

| Paths | Router |
|-------|--------|
| `/api/admin/*` | admin |
| `/api/admin/mcp/settings`, `/api/admin/mcp/tokens*` | mcp_tokens (AI access settings and MCP token create, list, revoke) |
| `POST /api/custom-fields`, `PUT/DELETE /api/custom-fields/{field_id}`, `PUT/DELETE /api/tags/{tag_id}` | custom_fields (admin_router) |
| `POST /api/dcim/{manufacturers,device-types,roles,statuses}`, `PUT/DELETE /api/dcim/{manufacturers,device-types,roles,statuses}/{id}` (`?confirm=true` to delete a record hosts use) | device_model (admin_router) |
| `POST /api/ipam/vrfs`, `PUT/DELETE /api/ipam/vrfs/{vrf_id}`, `POST /api/ipam/vlans`, `PUT/DELETE /api/ipam/vlans/{vlan_id}`, `POST /api/ipam/interface-addresses/rebuild` (audited as `network_objects`) | network_objects (admin_router) |
| `/api/secret-variables/*` | (admin enforced in handlers; reads and writes both) |
| `/api/inventory/admin/*` | inventory_admin |
| `/api/topology/admin/*` | topology_admin |
| `/api/compliance/admin/*` | compliance_admin |
| `/api/monitoring/admin/*` | monitoring_admin |
| `/api/metrics/admin/*` | metrics_engine_admin |
| `/api/monitoring/meraki-alerts/settings` (GET/PUT; the webhook secret is write-only), `POST /api/monitoring/meraki-alerts/poll` | meraki_alerts_admin |

### WebSocket (self-authenticated)

| Path | Auth check | Feature check |
|------|-----------|---------------|
| `/ws/jobs/{job_id}` | session cookie | `jobs` feature |
| `/ws/config-capture/{job_id}` | session cookie | `config-drift` feature |
| `/ws/config-revert/{job_id}` | session cookie | `config-drift` feature |
| `/ws/deployment/{job_id}` | session cookie | `deployments` feature |
| `/ws/upgrades/{campaign_id}` | session cookie | `upgrades` feature |

### CSRF Protection

All `POST/PUT/PATCH/DELETE` requests to `/api/*` require a valid `X-CSRF-Token`
header when authenticated via session cookie. API-token authenticated requests
are exempt (not susceptible to CSRF). The webhook receivers in
`WEBHOOK_PATHS` (`netcontrol/app.py`, only `/api/webhooks/meraki` today)
are exempt by exact path: the sender cannot carry a session or a CSRF
token, and the shared secret in the body authenticates each delivery.

### Credential Access (IDOR protection)

| Operation | Own credential | Unowned (NULL owner) | Other user's credential |
|-----------|---------------|---------------------|------------------------|
| List | ✅ | ❌ (admin only) | ❌ (admin only) |
| Create | ✅ (auto-owned) | - | - |
| Update | ✅ | ❌ (admin only) | ❌ |
| Delete | ✅ | ❌ (admin only) | ❌ |

Operational endpoints (job launch, deployments, config backups/drift,
compliance, upgrades, risk analysis, inventory discovery) enforce the same
ownership rules at credential-*use* time via
`require_credential_access()` in `netcontrol/routes/shared.py`. Background
workers (job queue, backup/compliance schedulers) re-validate against the
task's original submitter. Every allow/deny decision emits a `credential`
audit event; non-ownership grants carry an `override=` marker.

### API-token callers

The server API token (`X-API-Token`) is **admin-equivalent by design**: it
bypasses role checks (`require_admin` short-circuits on `auth_mode ==
"token"`) and credential-ownership checks (including unowned and other
users' credentials). It exists for CI/CD and machine-to-machine use
(federation peers authenticate with it). Consequences:

- Treat the API token like a root credential: store it in a secrets
  manager, rotate it, and never send it over plaintext HTTP (federation
  peer URLs require HTTPS unless `PLEXUS_FEDERATION_ALLOW_HTTP=true`).
- Per-token scoping is not implemented; if finer-grained machine access is
  needed, that requires a token-scopes design first.

### MCP endpoint (mcp-token)

| Method | Path | Notes |
|--------|------|-------|
| POST | `/mcp`, `/mcp/` | Read-only AI access. `404` until an admin enables it. Not in `PUBLIC_PATHS`; it has its own token check and is exempt from CSRF because it never reads a cookie. An MCP token is refused on `/api/*`, and `APP_API_TOKEN` is refused here |

What a token may call is decided per request, from the token row and its owner as they are now:

| Rule | Detail |
|------|--------|
| Token state | Refused when revoked, expired, or when its owner no longer exists |
| Category | A tool is listed and callable only if its category is on the token |
| Owner feature | The owner must hold the category's feature: `inventory`, `config-backups` (configs; `config-drift` as well for `list_config_drift`), `compliance`, `monitoring`, `topology`, `software`, `mac-tracking` (`search_mac_or_ip`), `traffic-analysis` (`get_top_talkers`). An admin owner passes every feature check |
| Audit category | `search_audit_log` needs an admin owner; a token cannot be given `audit` for a non-admin owner |
| Hidden tools | A tool the token may not use answers "Unknown tool", the same as one that does not exist |
| Always available | `plexus_overview`, which reports only on the categories the token can use: device counts need `inventory`, the data source list needs `inventory`, `monitoring` or `topology` |

## Notes

- OpenAPI docs (`/docs`, `/redoc`, `/openapi.json`) disabled by default; enable with `APP_ENABLE_DOCS=true`
- `must_change_password` flag blocks all non-password-change API access
- Rate limiting: login has brute-force protection; all API endpoints have per-IP sliding window limits when `API_RATE_LIMIT.enabled=true`
