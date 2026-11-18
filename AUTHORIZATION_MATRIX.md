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
| GET | `/api/auth/status` | Returns current session info; signed out it also carries `sso.oidc` (`enabled`, `label`, `primary`) for the login page |
| GET | `/api/auth/oidc/login` | Starts an OIDC sign-in (`?next=<same-site path>`): sets the signed `oidc_tx` cookie and redirects to the identity provider. Under the anonymous API rate limit. See `docs/sso-oidc.md` |
| GET | `/api/auth/oidc/callback` | OIDC redirect target: checks state, exchanges the code, validates the ID token, provisions the account and sets the session cookie; on failure redirects to `/login?sso_error=<code>`. Failures count toward the login lockout |
| GET | `/api/health` | Health check (uptime, metrics) |
| GET | `/favicon.ico` | Static |
| GET | `/static/*` | Static files |
| POST | `/api/chatops/slack/commands`, `/api/chatops/slack/interactivity`, `/api/chatops/webex`, `/api/chatops/teams` | ChatOps bots. No session or CSRF; each request is checked against the platform's HMAC signature (Slack with a five-minute timestamp window and repeated signatures refused; Webex and Teams de-duplicated by message id). Answers 404 until an admin sets up the platform's bot; 401 on a bad signature. At most 64 KiB of body. Rate limited per source IP on the webhook budget. Commands run as the Plexus user the chat user is mapped to and need `chatops` plus each command's own feature (`ack` needs `monitoring.write`, `run` needs `jobs.write` and an admin-approved preset); unmapped users get only help. See `docs/chatops.md` |
| POST | `/api/webhooks/meraki` | Meraki webhook receiver. No session or CSRF; authenticated by the shared secret in the body (constant-time compare). Answers 404 until an admin sets a secret and turns it on; 401 on a wrong secret. Rate limited per source IP on its own budget (600 per window). See `docs/meraki-alerts.md` |

### Auth-only (any authenticated user)

| Method | Path | Router |
|--------|------|--------|
| GET | `/api/help`, `/api/help/search?q=`, `/api/help/pages/{name}` (the user guides, rendered) | help_docs |
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
| GET | `/api/export-templates` (`?object_type=`), `/api/export-templates/object-types`, `/api/export-templates/{id}`, `/api/export-templates/{id}/render`: only templates of object types whose feature the caller holds (`inventory`, `ipam`, `circuits`, `organization`; others answer `404`); a render loads the objects through the type's own list or export, so object scope applies, and refuses scoped callers for IPAM prefixes and IP addresses (`403`). Renders audited as `export_templates` / `export_template_render` | export_templates (router) |
| GET | `/api/plugins` (the plugin manifest: users see only active plugins whose `plugin:<name>` feature they hold; admins and the API token see every plugin with status, source and errors) | plugins |

### Feature-gated (auth + feature flag)

| Feature | Paths | Router |
|---------|-------|--------|
| `inventory` | `/api/inventory/*` | inventory |
| `topology` | `/api/topology/*` | topology |
| `topology` | `GET/POST/DELETE /api/topology/history/{kind}`, `DELETE /api/topology/history/{kind}/{entry_id}` (the caller's own last 30 Path Mode traces, reachability sweeps or summaries; the writes need only `topology`, not `topology.write`, since each user changes only their own history) | tool_history |
| `topology` | `/api/sources/*`, `/api/topology/search/deep`, `/api/topology/export.html` (collections/deletes need `topology.write`; source and credential management `POST/PUT/DELETE /api/sources*` is admin-only in the handlers) | meraki_topology |
| `jobs` | `/api/jobs/*` (launch, retry and rerun also check the task's run permission and, for a live run, its commit permission: `403` when refused; admins and API token callers always pass. See `docs/jobs.md#run-and-commit-permissions`) | jobs |
| `templates` | `/api/templates/*` | templates |
| `credentials` | `/api/credentials/*` | credentials |
| `playbooks` | `/api/playbooks/*` (`PUT /api/playbooks/{id}/permissions`, and `permissions` in a playbook create or update, need admin in the handler; `GET/PUT /api/playbooks/{id}/input-schema` need only the feature) | playbooks |
| `config-drift` | `/api/config-drift/*` | config_drift |
| `config-drift` | `GET /api/intended-config/templates`, `GET /api/intended-config/templates/{id}`, `GET /api/intended-config/contexts`, `GET /api/intended-config/contexts/{id}`, `GET /api/intended-config/hosts`, `GET /api/intended-config/hosts/{host_id}`, `GET /api/intended-config/hosts/{host_id}/variables`, `POST /api/intended-config/generate` (renders and compares stored data only, no device session; audited as `config` / `intended_generate`) | intended_config (router) |
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
| `upgrades` | `POST /api/upgrades/campaigns/{campaign_id}/devices/{device_id}/logic-reset-confirm` (record that the manual Logic Reset of an APC Smart-UPS Ultra was done; write scope on the campaign like the device cancel, `409` while a step runs; audited as `upgrades` / `logic_reset_confirm`) | upgrades |
| `inventory` | `POST /api/tags`, `GET/PUT /api/hosts/{host_id}/custom-data`, `GET/PUT /api/inventory/{group_id}/custom-data`, `POST /api/hosts/bulk-tags` | custom_fields (inventory_router) |
| `inventory` | `POST /api/hosts/bulk-edit` (set device type, role, lifecycle status, site, location detail on many hosts; audited as `device_model` / `bulk_edit`) | device_model (inventory_router) |
| `ipam` | `GET /api/ipam/prefix-custom-data?subnet=&vrf=`; `PUT` needs `ipam.write` and admin (an admin dependency on the route, like every IPAM write) | custom_fields (ipam_router) |
| `ipam` | `GET /api/ipam/vrfs`, `GET /api/ipam/vrfs/{vrf_id}`, `GET /api/ipam/vlans`, `GET /api/ipam/vlans/{vlan_id}` (registered before the IPAM router) | network_objects (router) |
| `reports` | `GET /api/hosts/{host_id}/interface-addresses` (gated like `GET /api/hosts/{host_id}/interface-inventory`) | network_objects (host_router) |
| `virtualization` | `/api/virtualization/*` (cluster types, cluster groups, clusters and their hosts, virtual machines and VM interfaces; writes need `virtualization.write`, audited as `virtualization`). Not scope-enforced: members of access groups limited to selected inventory groups do not get it. See `docs/virtualization.md` | virtualization (router) |
| `sync` | `/api/sync/catalog`, `/api/sync/connections` (GET), `/api/sync/jobs*`, `/api/sync/runs*` (job writes and `POST /api/sync/jobs/{id}/run` need `sync.write`; a job that writes into Plexus also needs admin, or `inventory.write` for devices only, when saved and when run for real; a dry run needs `sync.write` only; audited as `sync`). Not scope-enforced, so users limited to selected inventory groups are refused | sync |
| `lifecycle` | `/api/lifecycle/*` (end-of-life notices, support contracts, device lifecycle status and CSV report, alert settings, `POST /api/lifecycle/check`; writes need `lifecycle.write`, audited as `lifecycle`). Not scope-enforced: members of access groups limited to selected inventory groups do not get it. See `docs/hardware-lifecycle.md` | hardware_lifecycle (router) |
| `secrets-providers` | `/api/secrets-providers/*` (HashiCorp Vault, AWS Secrets Manager and Azure Key Vault providers; writes and `POST /api/secrets-providers/{id}/test` need `secrets-providers.write`, audited as `secrets_providers`; provider secrets are write-only and no route returns a resolved value). Not scope-enforced: members of access groups limited to selected inventory groups do not get it. See `docs/secrets-providers.md` | secrets_providers (router) |
| `credentials` | `GET /api/credentials/secrets-providers` (the providers the caller may reference: admins all, others those allowing personal credentials; names and types only). An `external` reference on a user credential needs the provider to allow personal credentials unless the caller is an admin | credentials |
| `chatops` | No HTTP route of its own: lets the user's mapped chat identity run ChatOps commands, each also needing its own feature (see the ChatOps public paths above and `docs/chatops.md`). Not scope-enforced, so users limited to selected inventory groups are refused | chatops (inbound_router) |
| `graphql` | `POST /api/graphql` (read-only queries; CSRF applies to session callers), `GET /api/graphql` (GraphiQL, `404` unless the admin setting `graphiql` is on). Each field also needs the feature of its REST counterpart (`inventory`; `reports` for interfaces, interface addresses and device VLANs; `ipam` for prefixes, addresses, VLAN and VRF records; `config-backups` for backup metadata) and leaves out hosts and groups outside the caller's object scope. `graphql` is scope-enforced, so scoped users see only their groups' hosts. See `docs/graphql-api.md` | graphql (router) |
| `plugin:<name>` | `/api/plugins/<name>/*`, every route of an enabled plugin (writes need `plugin:<name>.write`; CSRF applies; `503` while the plugin is not active). The keys exist only while the plugin is loaded. Members of access groups limited to selected inventory groups do not get plugin features (fail closed), since plugins do not enforce device scope. See `docs/plugin-development.md` | plugin router (mounted by `netcontrol/routes/plugins.py`) |

### Admin-only

| Paths | Router |
|-------|--------|
| `/api/admin/*` | admin |
| `GET/PUT /api/admin/auth-config` (now with `oidc`; the client secret is write-only), `POST /api/admin/auth-config/oidc/test` | admin (OIDC single sign-on settings and connection test) |
| `/api/admin/mcp/settings`, `/api/admin/mcp/tokens*` | mcp_tokens (AI access settings and MCP token create, list, revoke) |
| `GET /api/admin/chatops`, `PUT/DELETE /api/admin/chatops/bots/{platform}`, `GET/POST /api/admin/chatops/mappings`, `DELETE /api/admin/chatops/mappings/{id}`, `GET/POST /api/admin/chatops/presets`, `PUT/DELETE /api/admin/chatops/presets/{id}`, `GET /api/admin/chatops/log` (writes audited as `chatops` / `bot.*`, `mapping.*`, `preset.*`; signing secrets and bot tokens are write-only) | chatops (admin_router, `require_admin` in `app.py`) |
| `GET/PUT /api/admin/graphql/settings` (GraphiQL, introspection and query limits; writes audited as `graphql` / `settings_update`) | graphql (admin_router) |
| `GET/POST /api/admin/webhooks`, `GET/PUT/DELETE /api/admin/webhooks/{id}`, `POST /api/admin/webhooks/{id}/test`, `GET /api/admin/webhooks/{id}/deliveries`, `POST /api/admin/webhooks/{id}/deliveries/{delivery_row_id}/redeliver` (writes, tests and redeliveries audited as `system` / `webhook.*`; the signing secret and header values are write-only) | webhooks (router, `require_admin` in `app.py`) |
| `POST /api/custom-fields`, `PUT/DELETE /api/custom-fields/{field_id}`, `PUT/DELETE /api/tags/{tag_id}` | custom_fields (admin_router) |
| `POST /api/dcim/{manufacturers,device-types,roles,statuses}`, `PUT/DELETE /api/dcim/{manufacturers,device-types,roles,statuses}/{id}` (`?confirm=true` to delete a record hosts use) | device_model (admin_router) |
| `POST /api/ipam/vrfs`, `PUT/DELETE /api/ipam/vrfs/{vrf_id}`, `POST /api/ipam/vlans`, `PUT/DELETE /api/ipam/vlans/{vlan_id}`, `POST /api/ipam/interface-addresses/rebuild` (audited as `network_objects`) | network_objects (admin_router) |
| `POST /api/virtualization/sync-cloud` (mirror the discovered AWS, Azure and GCP instances as virtual machines; audited as `virtualization` / `sync_cloud`) | virtualization (admin_router) |
| `POST /api/intended-config/templates`, `PUT/DELETE /api/intended-config/templates/{id}`, `POST /api/intended-config/contexts`, `PUT/DELETE /api/intended-config/contexts/{id}`, `POST /api/intended-config/preview` (writes audited as `config`; the preview stores nothing) | intended_config (admin_router) |
| `POST /api/export-templates`, `PUT/DELETE /api/export-templates/{id}`, `POST /api/export-templates/preview` (writes audited as `export_templates`; the preview stores nothing) | export_templates (admin_router) |
| `GET/POST /api/git-sources`, `GET/PUT/DELETE /api/git-sources/{id}`, `GET /api/git-sources/{id}/objects`, `POST /api/git-sources/{id}/sync` (writes and syncs audited as `config` / `git_source_*`; credentials are service credentials, never returned). Templates, playbooks and intended configuration contexts a Git source owns answer `409` to `PUT` and `DELETE` on their own routes | git_sources (router, `require_admin` in `app.py`) |
| `POST /api/sync/connections`, `PUT/DELETE /api/sync/connections/{id}`, `POST /api/sync/connections/{id}/test` (a connection binds a service credential; audited as `sync` / `connection_*`) | sync (admin_router) |
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
`WEBHOOK_PATHS` (`netcontrol/app.py`: `/api/webhooks/meraki` and the four
ChatOps paths) are exempt by exact path: the sender cannot carry a session
or a CSRF token, and the shared secret in the body (Meraki) or the request
signature (ChatOps) authenticates each delivery.

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
| Object scope | Refused (`403`, `{"error": "forbidden", "message": ...}`) when its owner is limited to selected inventory groups (see Object-level permissions) |
| Category | A tool is listed and callable only if its category is on the token |
| Owner feature | The owner must hold the category's feature: `inventory`, `config-backups` (configs; `config-drift` as well for `list_config_drift`), `compliance`, `monitoring`, `topology`, `software`, `mac-tracking` (`search_mac_or_ip`), `traffic-analysis` (`get_top_talkers`). An admin owner passes every feature check |
| Audit category | `search_audit_log` needs an admin owner; a token cannot be given `audit` for a non-admin owner |
| Hidden tools | A tool the token may not use answers "Unknown tool", the same as one that does not exist |
| Always available | `plexus_overview`, which reports only on the categories the token can use: device counts need `inventory`, the data source list needs `inventory`, `monitoring` or `topology` |

### Object-level permissions (scoped users)

An access group with `object_scope = 'groups'` limits its members to the
inventory groups it grants (and their sub-groups), read only or read and
write. Admins, `APP_API_TOKEN` and members of any access group with `all`
are unrestricted. See [docs/object-permissions.md](docs/object-permissions.md).

| Layer | Rule for a scoped user |
|-------|------------------------|
| Feature gates | Effective features keep only `SCOPE_ENFORCED_FEATURES` (`inventory`, `config-backups`, `config-drift`, `credentials` and their `.write` keys; credentials are per owner and need no filtering): every other `feature(X)` route, WebSocket and the dashboard answer `403` (fail closed) |
| Enforced routers | `inventory`, `custom_fields.inventory_router`, `device_model.inventory_router`, `ansible_inventory`, `config_backups`, `config_drift` (HTTP and the `ws_router` WebSockets), `intended_config` (`router`): every HTTP and WebSocket route is marked `@scoped` or `@scope_exempt` (checked by a test). Admin routers are unchanged |
| Out of read scope | `404` with the body an unknown id gets, also for records addressed by their own id (backup, policy, baseline, snapshot, drift event, intended configuration, template, context, capture job) |
| Read only | Writes answer `403 Read-only access to this inventory group`: in the configuration modules also captures, checks, analyses, restores, reverts, accepting or resolving drift, baselines, deletes, policy changes and runs, and generating intended configurations |
| Top level | Creating a top-level group or moving a group to the top level: `403` |
| Lists and exports | Readable rows only, filtered before limits and counts (`/api/inventory`, CSV export, Ansible inventory, SNMP assignments, backup lists, summary, latest per host, search and ZIP download, drift events, baselines, snapshots and summary, intended configuration rows and counts, template `host_count`) |
| Bulk and "all hosts" actions | Every host or drift event id checked; nothing changes when one fails. Generating intended configurations with no ids acts on writable hosts only |
| Global records | Backup policies, intended configuration templates and contexts: a scoped user sees one only when the inventory group (and, for a context, the host) it targets is readable, and changes or runs a policy only when its group is writable |
| WebSockets | `/ws/config-capture/{job_id}` and `/ws/config-revert/{job_id}` answer "Job not found" for a job touching a host outside the read scope |
| MCP | Tokens owned by a scoped user are refused (`403`) |

## Notes

- OpenAPI docs (`/docs`, `/redoc`, `/openapi.json`) disabled by default; enable with `APP_ENABLE_DOCS=true`
- `must_change_password` flag blocks all non-password-change API access
- Rate limiting: login has brute-force protection; all API endpoints have per-IP sliding window limits when `API_RATE_LIMIT.enabled=true`
