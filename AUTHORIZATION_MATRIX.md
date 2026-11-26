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
| GET | `/api/auth/status` | Returns current session info; signed out it also carries `sso.oidc` and `sso.saml` (`enabled`, `label`, `primary`) for the login page |
| GET | `/api/auth/oidc/login` | Starts an OIDC sign-in (`?next=<same-site path>`): sets the signed `oidc_tx` cookie and redirects to the identity provider. Under the anonymous API rate limit. See `docs/sso-oidc.md` |
| GET | `/api/auth/oidc/callback` | OIDC redirect target: checks state, exchanges the code, validates the ID token, provisions the account and sets the session cookie; on failure redirects to `/login?sso_error=<code>`. Failures after the state check count toward the login lockout; requests any site can cause (no transaction cookie, OIDC off, a wrong state) do not |
| GET | `/api/auth/saml/metadata` | SAML SP metadata (entity ID, ACS URL) to register at the IdP. See `docs/sso-saml.md` |
| GET | `/api/auth/saml/login` | Starts a SAML sign-in (`?next=<same-site path>`): sets the signed `saml_tx` cookie with the request ID and redirects to the IdP with an `AuthnRequest`. Under the anonymous API rate limit |
| POST | `/api/auth/saml/acs` | SAML assertion consumer service. No session and no CSRF token (the IdP's cross-site POST); authenticated by the signed assertion, bound to the `saml_tx` cookie's request ID, replayed assertion IDs refused. `RelayState` kept only as a same-site path. Sets the session cookie or redirects to `/login?sso_error=<code>`; a replayed assertion or a refused account counts toward the login lockout, a response that does not validate (which any site can post) does not |
| GET | `/api/health` | Health check. Without a session or the API token it answers only `{ok, status}` (200 healthy, 503 degraded, the same status codes as before); with a valid session (when `APP_REQUIRE_API_TOKEN` is off) or the `APP_API_TOKEN` it adds uptime, metrics and the database probe result |
| GET | `/api/version` | Release number (`version`). The exact build (`git_sha`) only with a valid session (when `APP_REQUIRE_API_TOKEN` is off) or the `APP_API_TOKEN` |
| GET | `/favicon.ico` | Static |
| GET | `/static/*` | Static files |
| POST | `/api/chatops/slack/commands`, `/api/chatops/slack/interactivity`, `/api/chatops/webex`, `/api/chatops/teams` | ChatOps bots. No session or CSRF; each request is checked against the platform's HMAC signature (Slack with a five-minute timestamp window and repeated signatures refused; Webex and Teams refused with `400` when the signed time in the body, Webex `data.created` or the Teams activity `timestamp`, is missing, unreadable, more than five minutes old or more than one minute ahead of the server clock, or when the delivery has no message or activity id, and de-duplicated by that id). Answers 404 until an admin sets up the platform's bot; 401 on a bad signature. At most 64 KiB of body. Rate limited per source IP on the webhook budget. Commands run as the Plexus user the chat user is mapped to and need `chatops` plus each command's own feature (`ack` needs `monitoring.write`, `run` needs `jobs.write` and an admin-approved preset); unmapped users get only help. See `docs/chatops.md` |
| POST | `/api/webhooks/meraki` | Meraki webhook receiver. No session or CSRF; authenticated by the shared secret in the body (constant-time compare). Answers 404 until an admin sets a secret and turns it on; 401 on a wrong secret. Rate limited per source IP on its own budget (600 per window). See `docs/meraki-alerts.md` |

### Auth-only (any authenticated user)

| Method | Path | Router |
|--------|------|--------|
| GET | `/api/help`, `/api/help/search?q=`, `/api/help/pages/{name}` (the user guides, rendered) | help_docs |
| POST | `/api/auth/logout` | auth |
| POST | `/api/auth/change-password` | auth |
| POST | `/api/auth/heartbeat` | auth (keeps the caller's own session alive) |
| GET/PUT | `/api/auth/profile` | auth |
| GET | `/api/changes`, `/api/changes/{object_type}/{object_id}` | object_changes (the change log. The handler keeps the object types whose feature the caller holds and answers `403` when none is left or the requested type is not one of them; a caller limited to selected inventory groups reads the changes of those groups only) |
| GET | `/api/custom-fields` (`?object_type=`), `/api/tags` (with usage counts) | custom_fields |
| GET | `/api/custom-object-types` (each type with `readable`/`writable` for the caller), `/api/computed-fields` (`?object_type=`), `/api/relationships` (`?object_type=`, with link counts) | custom_fields (router) |
| GET/PUT, POST/DELETE | `/api/objects/{type}/{id}/custom-data` (tags, values, computed fields, relationships), `GET /api/objects/{type}/lookup?q=`, `POST /api/objects/{type}/{id}/relationships`, `DELETE /api/objects/{type}/{id}/relationships/{link_id}`: the route itself checks the type's feature (`OBJECT_TYPE_SPECS`: read with its read feature, any signed-in user for the device model catalogues; change and link with its write feature, or admin for VRFs, VLANs, organization and device model types; linking also needs read on the peer), then each object by object scope with the type's `object_scope` model (`spec.scope_model`: `require_row`, `require_model_write` for shared rows with no tenant/site key, `filter_rows` for lookup): `404` outside the caller's scope, `403` read-only or shared; relationship lists drop peers the caller cannot read. Writes audited as `custom_fields` | custom_fields (router) |
| GET | `/api/dcim/manufacturers`, `/api/dcim/device-types` (`?manufacturer_id=`), `/api/dcim/roles`, `/api/dcim/statuses` (with host counts) | device_model |
| GET | `/api/dcim/device-types/{device_type_id}/components` (the device type's component templates) | device_model |
| GET | `/api/export-templates` (`?object_type=`), `/api/export-templates/object-types`, `/api/export-templates/{id}`, `/api/export-templates/{id}/render`: only templates of object types whose feature the caller holds (`inventory`, `ipam`, `circuits`, `organization`; others answer `404`); a render loads the objects through the type's own list or export, so object scope applies, and refuses scoped callers for IPAM prefixes and IP addresses (`403`). Renders audited as `export_templates` / `export_template_render` | export_templates (router) |
| GET | `/api/plugins` (the plugin manifest: users see only active plugins whose `plugin:<name>` feature they hold; admins and the API token see every plugin with status, source and errors) | plugins |

### Feature-gated (auth + feature flag)

Every feature router of a writable feature (one with a Modify column in the
access-group editor) is mounted with `require_feature_method`: reads need the
feature key, and `POST`/`PUT`/`PATCH`/`DELETE` need `<feature>.write` too
(`403` "Read-only access"). The exceptions are routers mounted with plain
`require_feature` for POST routes that only read, or that a separate key
gates: `POST /api/intended-config/remediation` (`config-drift`),
`POST /api/cdefs/evaluate` (`graph-templates`), `POST /api/jobs/{id}/approve`
and `/deny` (`jobs` plus `jobs.approve`), and the topology history routes
below.

`dashboard`, `mac-tracking`, `traffic-analysis`, `organization` and
`graphql` have no Modify column and no `.write` key. A write on one of
their routers needs the feature alone, unless its row names an admin check
or another key.

`reports` has a Modify column, but only the audit and billing routers check
`reports.write`. The other `reports` routers are mounted with
`require_feature`: generating a report and saving or deleting a report
definition need `reports` alone.

Admins and the API token pass every feature check. A row marked admin, here
or under Admin-only, is refused to every other caller whatever features
they hold.

| Feature | Paths | Router |
|---------|-------|--------|
| `inventory` | `/api/inventory/*` | inventory |
| `inventory` | `GET /api/admin/snmp-profiles` (the SNMP profile picker, the one route under `/api/admin/` that is not admin only: a non-admin gets each profile's id, name, version, port and `has_*` flags and no secret) | inventory |
| `inventory` | `POST /api/hosts/bulk-delete`, `POST /api/hosts/move`, `POST /api/hosts/snmp-profile`, `PUT/DELETE /api/hosts/{host_id}`, `PATCH /api/hosts/{host_id}/category`, `POST /api/hosts/{host_id}/fetch-serial`, `POST /api/hosts/{host_id}/snmp-profile/test`, `POST /api/groups/{group_id}/fetch-serials` (all need `inventory.write`) | inventory |
| `inventory` | `GET /api/ansible/inventory`, `GET /api/ansible/inventory/host/{hostname}` (the Ansible dynamic inventory) | ansible_inventory |
| `inventory` | `/api/dynamic-groups/*` (writes and `POST /api/dynamic-groups/preview` need `inventory.write`) | dynamic_groups |
| `inventory` | `GET /api/import/inventory/{object_type}/template`, `POST /api/import/inventory/{object_type}/preview`, `POST /api/import/inventory/{object_type}/commit` (CSV bulk import; the two POSTs need `inventory.write`) | bulk_import |
| `topology` | `/api/topology/*` | topology |
| `topology` | `GET/POST/DELETE /api/topology/history/{kind}`, `DELETE /api/topology/history/{kind}/{entry_id}` (the caller's own last 30 Path Mode traces, reachability sweeps or summaries; the writes need only `topology`, not `topology.write`, since each user changes only their own history) | tool_history |
| `topology` | `/api/sources/*`, `/api/topology/search/deep`, `/api/topology/export.html` (collections/deletes need `topology.write`; source management, the collection schedule and device import are admin only, see Admin-only; a `PUT` that changes the source's address or turns TLS verification off must send the API key again, else `400`) | meraki_topology |
| `jobs` | `/api/jobs/*` (writes need `jobs.write`, except approve and deny. Launch, retry and rerun of an Ansible task need admin, and the queue fails a queued Ansible job whose launcher is not an admin. Launch, retry and rerun also check the task's run permission and, for a live run, its commit permission: `403` when refused; admins and API token callers always pass. See `docs/jobs.md#run-and-commit-permissions`. `GET /api/jobs/approvals`, `POST /api/jobs/{id}/approve` and `POST /api/jobs/{id}/deny` also need `jobs.approve` (admins and the API token always have it) and every job target writable; the job's own requester is refused with `403`, admins included (four-eyes, like deployment approval). Changing a task's `approval_required` needs admin in the handler. See `docs/jobs.md#approvals`. A task whose template (any variant) or inputs use secret variables may target an ad-hoc address only for an admin or the API token, unless the address is the IP of an inventory host the caller may change whose address an admin confirmed (an inventory host awaiting confirmation fails the job at the queue for a non-admin launcher): launch, retry and rerun answer `403` before any secret is looked up, and the queue fails such a job whose launcher is not an admin. A secret that does not exist answers one generic message that names no secret. A secret variable's `usable_by` rule (roles and access groups) must include the caller at launch, retry and rerun (`400`, or `422` for a secret input, with the same message as a secret that does not exist) and the launcher when the queue starts the job (the job fails, no secret named in its log); admins and API token callers always pass. See `docs/jobs.md#secret-variables-and-ad-hoc-targets` and `docs/jobs.md#who-may-use-a-secret-variable`) | jobs |
| `templates` | `/api/templates/*` | templates |
| `credentials` | `/api/credentials/*` (service credentials, `/api/credentials/service*`, are admin only in the handlers) | credentials |
| `playbooks` | `GET /api/playbooks`, `GET /api/playbooks/{id}`, `GET /api/playbooks/{id}/input-schema`; `PUT /api/playbooks/{id}` and `PUT /api/playbooks/{id}/input-schema` need `playbooks.write`. Changing a playbook's code (`content`, `type` or `filename` different from the stored value) needs admin in the handler (`403`), as do `PUT /api/playbooks/{id}/permissions` and `permissions` / `approval_required` in an update. A module write never replaces a built-in playbook's module or another playbook's (`409`) | playbooks (router) |
| admin | `POST /api/playbooks`, `DELETE /api/playbooks/{id}` (a Python playbook is imported into the server process, an Ansible playbook runs on the controller) | playbooks (admin_router) |
| `config-drift` | `/api/config-drift/*` (`GET /api/config-drift/capture-job/{job_id}` needs the job's launcher or an admin, like `/ws/config-capture/{job_id}`; another user's job answers `404` like an unknown one) | config_drift |
| `config-drift` | `GET /api/intended-config/templates`, `GET /api/intended-config/templates/{id}`, `GET /api/intended-config/contexts`, `GET /api/intended-config/contexts/{id}`, `GET /api/intended-config/hosts`, `GET /api/intended-config/hosts/{host_id}`, `GET /api/intended-config/hosts/{host_id}/variables`, `POST /api/intended-config/generate` (renders and compares stored data only, no device session; needs `config-drift.write`; audited as `config` / `intended_generate`) | intended_config (router) |
| `config-drift` | `GET /api/intended-config/hosts/{host_id}/remediation` (router), `POST /api/intended-config/remediation` (read_router: no `config-drift.write` needed) (remediation commands from stored data, read scope on every host; stores and pushes nothing) | intended_config |
| `deployments` + `config-drift` | `POST /api/deployments/intended-remediation` (plans one deployment per host from its remediation; `config-drift` checked in the handler, write scope on every host, credential ownership as for `POST /api/deployments`; audited as `deployments` / `deployment.intended_remediation`) | deployments |
| `config-backups` | `/api/config-backups/*` (writes need `config-backups.write`). Backup text holds device secrets: `GET /api/config-backups/{id}`, `/{id}/diff` and `/search` return it masked (`netcontrol/mcp/redact.py`, `secrets_masked: true`) unless the caller is an admin, the API token, or holds `config-backups.write` with write scope on the device's group; `GET /api/config-backups/{id}/download` and `GET /api/config-backups/download` (raw text) need the same, else `403` (the ZIP holds only devices of groups the caller may change). Restore uses the stored text server-side. The same rule (`netcontrol/routes/config_visibility.py`) covers every other copy of device configuration: config drift snapshots, baselines, diffs and the revert command echo, intended-config extra lines and remediation, lab twins cloned from a host and their runs and drift runs, risk analyses of a host, and drift events in alert and deployment correlations. A lab clone by a caller without the right holds the masked text; an intended-remediation deployment that would remove secret lines is skipped for them. Compliance scan snippets and audit drift evidence are stored and returned masked for everyone | config_backups |
| `config-backups` | `GET /api/opnsense/hosts/{host_id}/rules`, `GET /api/opnsense/hosts/{host_id}/rules/diff` (firewall rules parsed from a host's stored backups) | opnsense_rules |
| `compliance` | `/api/compliance/*` | compliance |
| `compliance` | `/api/compliance/meraki/*` (scans use the organization's stored Dashboard API key, read-only; organizations themselves are managed under `/api/sources*`, admin-only) | meraki_compliance |
| `risk-analysis` | `/api/risk-analysis/*` | risk_analysis |
| `deployments` | `/api/deployments/*` (a plan needs approval when its group or the group of any target host is a production group, or its risk is high or critical; execute re-checks the target hosts' groups and, when one has become production, flags the plan for approval and answers `403`; the maintenance window check covers the same groups). `POST /api/deployments/{id}/request-approval` needs the plan's creator or an admin (`403`). `GET /api/deployments/job/{job_id}/status` needs the deployment's creator or an admin (like `/ws/deployment/{job_id}`); another user's job answers `404` like an unknown one. List, detail and correlation return `proposed_commands` and pre/post snapshots with secrets masked (`secrets_masked: true`) unless the caller holds the raw-config feature and may change every target (`config_visibility`); the job log lists commands masked for everyone; execute pushes the stored commands | deployments |
| `deployments` | `/api/maintenance-windows/*` (maintenance windows and `POST /api/maintenance-windows/check`; writes and the check need `deployments.write`) | maintenance_windows |
| `lab` | `/api/lab/*` (writes need `lab.write`). `POST /api/lab/environments/{id}/clone-host` also needs `config-drift` or `config-backups` (checked in the handler, `403`; it copies the host's running config) and read scope on the source host. `POST /api/lab/runs/{id}/promote` also needs `deployments` and `deployments.write` and is planned by the deployments rule above (production approval by the hosts' groups) | lab |
| `monitoring` | `/api/monitoring/*`, `/api/sla/*` (`POST /api/sla/evaluate` is admin only, see Admin-only. One manual fleet poll runs at a time: `POST /api/monitoring/poll-now`, `POST /api/monitoring/poll-now/stream` and `POST /api/admin/monitoring/run-now` answer `409` "A manual monitoring poll is already running" while another of them runs; the scheduled cycle is not affected) | monitoring |
| `monitoring` | `GET/POST /api/availability/topology/mutes`, `DELETE /api/availability/topology/mutes/{mute_id}` (mute and unmute an integration entity or site; the writes need `monitoring.write`, like acknowledging an alert; audited as `topology.muted` / `topology.unmuted`) | monitoring |
| `monitoring` | `/api/metrics/*` (`POST /api/metrics/vendor-oids` and `DELETE /api/metrics/vendor-oids/{entry_id}` are admin only, see Admin-only) | metrics_engine |
| `monitoring` | `GET /api/availability/*`, `GET /api/interfaces/*` (availability summaries, outages and transitions for hosts and integration topology; per-interface summaries, port detail and error counters) | monitoring, interface_errors |
| `monitoring` | `/api/interface-error-events/*` (acknowledge and resolve need `monitoring.write`) | interface_errors |
| `monitoring` | `/api/baseline-rules/*`, `/api/baselines/*` (baseline deviation rules, computed baselines and their chart; rule writes and `POST /api/baselines/compute` need `monitoring.write`) | baseline_alerting |
| `monitoring` | `/api/oid-profiles/*` (custom SNMP OID profiles, poller configuration; writes need `monitoring.write`) | reporting (oid_profiles_router) |
| `monitoring` | `/api/monitoring/syslog-rules*`, `/api/monitoring/trap-rules*` (syslog and SNMP trap alert rules: reads need `monitoring`; creating, updating, deleting a custom rule, a built-in override and the test routes need `monitoring.write`; audited as `syslog_rule.*` / `trap_rule.*`; object scope: a scoped caller reads the rules but cannot change them, and `POST /api/monitoring/trap-rules/test` reads a stored trap only of a host it can read) | syslog_rules |
| `monitoring` | `GET /api/monitoring/meraki-alerts` (the Meraki alert list) | meraki_alerts |
| `monitoring` | `GET /api/monitoring/vendor-alerts` (the vendor alert feed list: Cato events feed, AWS and Azure alerts; read only; object scope: a scoped caller sees the alerts raised on its readable hosts only) | vendor_alerts |
| `monitoring` | `GET /api/monitoring/security-events` (the security event list: OPNsense IDS alerts and Cato IPS events; read only, bounded: `hours` 1 to 8760, `limit` 1 to 500, `offset` up to 100,000, `q` up to 200 characters; object scope: a scoped caller sees the events of its readable hosts only, never a host-less device's, and `host_id` out of scope answers `404`) | security_events |
| `upgrades` | `/api/upgrades/*` (a campaign's list entry, detail, events and live stream are read by every holder of the feature who may read all of its devices; only its creator or an admin edits, runs, cancels or deletes it or reads its prestage backups; the list and the detail carry `can_manage` for the caller) | upgrades |
| `upgrades` | `POST /api/upgrades/campaigns/{campaign_id}/devices/{device_id}/logic-reset-confirm` (record that the manual Logic Reset of an APC Smart-UPS Ultra was done; write scope on the campaign like the device cancel, `409` while a step runs; audited as `upgrades` / `logic_reset_confirm`) | upgrades |
| `inventory` | `POST /api/tags`, `GET/PUT /api/hosts/{host_id}/custom-data`, `GET/PUT /api/inventory/{group_id}/custom-data`, `POST /api/hosts/bulk-tags` | custom_fields (inventory_router) |
| `inventory` | `POST /api/hosts/bulk-edit` (set device type, role, lifecycle status, site, location detail on many hosts; audited as `device_model` / `bulk_edit`) | device_model (inventory_router) |
| `inventory` | `POST /api/hosts/{host_id}/components/instantiate` (create the DCIM components the host's device type lists and the host lacks; write scope on the host: `404` outside the caller's groups, `403` read only; audited as `device_model` / `components_instantiate`) | device_model (inventory_router) |
| `ipam` | `GET /api/ipam/prefix-custom-data?subnet=&vrf=`; `PUT` needs `ipam.write` and admin (an admin dependency on the route, like every IPAM write) | custom_fields (ipam_router) |
| `ipam` | `GET /api/ipam/vrfs`, `GET /api/ipam/vrfs/{vrf_id}`, `GET /api/ipam/vlans`, `GET /api/ipam/vlans/{vlan_id}` (registered before the IPAM router) | network_objects (router) |
| `ipam` | `GET /api/ipam/namespaces`, `/namespaces/{id}`, `/route-targets`, `/route-targets/{id}`, `/vrfs/{vrf_id}/route-targets`, `/vlan-groups`, `/vlan-groups/{id}`, `/vlan-groups/{id}/next-vid`, `/rirs`, `/rirs/{id}`, `/aggregates`, `/aggregates/containing`, `/aggregates/{id}` (registered before the IPAM router; object scope: namespaces and RIRs are shared, route targets and aggregates are read by tenant, VLAN groups by site or their region's sites, rows with no key are shared; details list only readable VRFs, prefixes and VLANs, others `404`) | ipam_model (router) |
| `ipam` | `GET /api/ipam/*` (overview, providers and sources, subnets and their reservations, addresses, address history, reconciliation runs and diffs, utilization, pending allocations and the sync settings. Every write under `/api/ipam` is admin only, see Admin-only) | ipam |
| `ipam` | `GET /api/import/ipam/{object_type}/template` (the preview and commit are admin only, see Admin-only) | bulk_import |
| `ipam` | `GET /api/dhcp/*` (DHCP providers, servers, scopes, leases, exhaustion and lease correlation; server create, update, delete and sync are admin only, see Admin-only) | dhcp |
| `circuits` | `/api/circuits/*` (providers, provider networks, circuit types, circuits and their terminations; writes need `circuits.write`) | circuits |
| `dcim` | `/api/dcim/*` (racks, rack roles and reservations, power panels, feeds, ports and outlets, console, front and rear ports, modules, cables, host placement and cable trace; writes need `dcim.write`. The device model catalogues under `/api/dcim` have their own rows under Auth-only and Admin-only) | dcim |
| `routing` | `/api/routing/*` (autonomous systems, routing instances, peer groups, peerings, suggestions and compliance; writes need `routing.write`) | routing |
| `cloud-visibility` | `GET /api/cloud/*` (providers, accounts, resources, connections, hybrid links, topology, policies, flow log and traffic metric views, and the three sync settings. Every write under `/api/cloud`, the discovery progress and the two sync cursor lists are admin only, see Admin-only) | cloud_visibility |
| `floor-plan` | `/api/geo/*` (sites, floors, floor images and device placements; writes need `floor-plan.write`) | geolocation |
| `software` | `/api/software/*` (overview, history, advisories, end-of-life entries, alerts and job status; writes need `software.write`. The settings, the PSIRT sync and test and the CVE enrichment run are admin only, see Admin-only) | software, software_eol |
| `reports` | `GET /api/hosts/{host_id}/interface-addresses` (gated like `GET /api/hosts/{host_id}/interface-inventory`) | network_objects (host_router) |
| `reports` | `/api/reports/*` (saved reports, runs, artifacts and the CSV, PDF, SVG and draw.io exports. `POST /api/reports`, `POST /api/reports/generate` and `DELETE /api/reports/{report_id}` need `reports` alone, no `reports.write`: the router is mounted with `require_feature`) | reporting |
| `reports` | `/api/audit/*`, `GET /api/hosts/{host_id}/audit-findings`, `GET /api/hosts/{host_id}/interface-inventory`, `GET /api/hosts/{host_id}/vlans` (audit runs, schedules, findings and overrides. Starting a run and creating, changing, deleting or running a schedule or an override need `reports.write`; a caller limited to selected inventory groups cannot start runs or change schedules, `403`. The `created_by` of a schedule and of an override is the caller; a value in the request is ignored) | audit |
| `reports` | `/api/graphs/*`, `GET /api/graph-image/{host_graph_id}.svg` (graph configuration, embed and image export) | graph_export |
| `reports` | `/api/billing/*` (billing circuits, customers, periods, usage and summary. Creating, changing or deleting a billing circuit or a period and generating a period need `reports.write`) | billing |
| `dashboard` | `GET /api/dashboard` (each section needs its own feature too: `recent_jobs` needs `jobs` and shows a non-admin only the jobs they launched; `groups` needs `inventory`; `monitoring`, `device_health`, `open_alerts` and `topology` need `monitoring`. A section the caller may not see is left out of the response. A caller limited to selected inventory groups gets every section computed over those groups only) | app |
| `dashboard` | `/api/dashboards/*`, `GET /api/annotations`, `GET /api/dashboard/top-interfaces` (dashboards, their panels, annotations and the top interfaces widget; writes need `dashboard` alone; a new dashboard belongs to the signed-in user who created it; non-admins list and open only their own; a dashboard created with the API token has no owner and is admin-only) | dashboards |
| `graph-templates` | `/api/graph-templates/*`, `/api/host-templates/*`, `/api/host-graphs/*`, `/api/graph-trees/*`, `/api/data-source-profiles/*`, `POST /api/hosts/{host_id}/apply-graph-templates` (writes need `graph-templates.write`) | graph_templates |
| `graph-templates` | `/api/cdefs/*`, `PUT/DELETE /api/data-sources/{ds_id}`, `GET /api/hosts/{host_id}/data-sources`, `POST /api/hosts/{host_id}/data-sources/discover` (calculated data sources; writes need `graph-templates.write`, except `POST /api/cdefs/evaluate`, which only reads) | cdef_engine |
| `mac-tracking` | `/api/mac-tracking/*` (acknowledging moves needs `mac-tracking` alone. `POST /api/mac-tracking/collect` also needs `inventory.write`: it signs in to switches with the service credential. `POST /api/mac-tracking/cleanup` is admin only, see Admin-only) | mac_tracking |
| `traffic-analysis` | `GET /api/flows/*` (flow exporters, status, timeline and the top talkers, conversations, applications and interfaces; the collector settings are under `/api/admin/flows*`, admin only) | flow_collector |
| `organization` | `GET /api/organization/*` (regions, sites, locations, tenant groups and tenants; their writes are admin only, see Admin-only) | organization |
| `virtualization` | `/api/virtualization/*` (cluster types, cluster groups, clusters and their hosts, virtual machines and VM interfaces; writes need `virtualization.write`, audited as `virtualization`). Scope-enforced: clusters by tenant, site or member host, VMs by tenant or their cluster's site and hosts; types and groups are read-only shared catalogues for scoped users. See `docs/virtualization.md` | virtualization (router) |
| `sync` | `/api/sync/catalog`, `/api/sync/connections` (GET), `GET /api/sync/connections/{connection_id}`, `/api/sync/jobs*`, `/api/sync/runs*` (job writes and `POST /api/sync/jobs/{id}/run` need `sync.write`; a job that writes into Plexus also needs admin, or `inventory.write` for devices only, when saved and when run for real; a dry run needs `sync.write` only; audited as `sync`). Scope-enforced: scoped users read jobs and runs (run entries of their own devices only) and are refused every job write and run (`403`) | sync |
| `inventory` | `GET /api/hosts/{host_id}/hardware`, `GET /api/hosts/{host_id}/hardware/events`, `GET /api/hardware/components`, `GET /api/hardware/components/export`, `GET /api/hardware/events` (hardware components with serials and their history); `POST /api/hosts/{host_id}/hardware/refresh` needs `inventory.write` and write scope on the host, and an admin when the host's address awaits confirmation (`403`); audited as `inventory` / `host.hardware_refresh`. Scope-enforced: host routes answer `404` outside the caller's groups, the fleet lists keep readable hosts, history of a deleted host is for unrestricted callers only. See `docs/hardware-inventory.md` | hardware_components (router) |
| `lifecycle` | `/api/lifecycle/*` (end-of-life notices, support contracts, device lifecycle status and CSV report, alert settings, `POST /api/lifecycle/check`; writes need `lifecycle.write`, audited as `lifecycle`). Scope-enforced: notices are a read-only shared catalogue for scoped users, contracts and status follow their hosts, settings and `check` are refused. See `docs/hardware-lifecycle.md` | hardware_lifecycle (router) |
| `secrets-providers` | `/api/secrets-providers/*` (HashiCorp Vault, AWS Secrets Manager and Azure Key Vault providers; the feature reads them; create, update, delete and `POST /api/secrets-providers/{id}/test` are admin only (admin session or server API token, else `403`; no `.write` key), audited as `secrets_providers`; provider secrets are write-only and no route returns a resolved value). Scope-enforced: scoped users read the providers; only admins, who are never scoped, change or test them. See `docs/secrets-providers.md` | secrets_providers (router) |
| `credentials` | `GET /api/credentials/secrets-providers` (the providers the caller may reference: admins all, others those allowing personal credentials; names and types only). An `external` reference on a user credential needs the provider to allow personal credentials unless the caller is an admin | credentials |
| `chatops` | No HTTP route of its own: lets the user's mapped chat identity run ChatOps commands, each also needing its own feature (see the ChatOps public paths above and `docs/chatops.md`). Commands are refused for users limited to selected inventory groups | chatops (inbound_router) |
| `graphql` | `POST /api/graphql` (read-only queries; CSRF applies to session callers), `GET /api/graphql` (GraphiQL, `404` unless the admin setting `graphiql` is on). Each field also needs the feature of its REST counterpart (`inventory`; `reports` for interfaces, interface addresses and device VLANs; `ipam` for prefixes, addresses, VLAN and VRF records; `config-backups` for backup metadata) and leaves out hosts and groups outside the caller's object scope. `graphql` is scope-enforced, so scoped users see only their groups' hosts. See `docs/graphql-api.md` | graphql (router) |
| `plugin:<name>` | `/api/plugins/<name>/*`, every route of an enabled plugin (writes need `plugin:<name>.write`; CSRF applies; `503` while the plugin is not active). The keys exist only while the plugin is loaded. Members of access groups limited to selected inventory groups do not get plugin features (fail closed), since plugins do not enforce device scope. See `docs/plugin-development.md` | plugin router (mounted by `netcontrol/routes/plugins.py`) |

### Admin-only

| Paths | Router |
|-------|--------|
| `/api/admin/*` (except `GET /api/admin/snmp-profiles`, which the `inventory` feature reads, see Feature-gated) | admin, and the admin routers of inventory, topology, compliance, monitoring, the metrics engine, the flow collector and the other modules, whose routes all live under `/api/admin/` |
| `GET/PUT /api/admin/auth-config` (now with `oidc`; the client secret is write-only), `POST /api/admin/auth-config/oidc/test` | admin (OIDC single sign-on settings and connection test). Stored secrets (RADIUS/TACACS+ secret, LDAP bind password, OIDC client secret) are kept by sending the mask only while the server, port and TLS settings (OIDC: issuer origin and CA file) are unchanged; otherwise `400` until the secret is sent again |
| `GET/PUT /api/admin/auth-config` (`saml` block), `GET /api/admin/auth-config/saml/sp`, `POST /api/admin/auth-config/saml/metadata` | admin (SAML single sign-on settings, the SP values to register, IdP metadata import; the import saves nothing) |
| `/api/admin/mcp/settings`, `/api/admin/mcp/tokens*` | mcp_tokens (AI access settings and MCP token create, list, revoke) |
| `GET /api/admin/chatops`, `PUT/DELETE /api/admin/chatops/bots/{platform}`, `GET/POST /api/admin/chatops/mappings`, `DELETE /api/admin/chatops/mappings/{id}`, `GET/POST /api/admin/chatops/presets`, `PUT/DELETE /api/admin/chatops/presets/{id}`, `GET /api/admin/chatops/log` (writes audited as `chatops` / `bot.*`, `mapping.*`, `preset.*`; signing secrets and bot tokens are write-only) | chatops (admin_router, `require_admin` in `app.py`) |
| `GET/PUT /api/admin/graphql/settings` (GraphiQL, introspection and query limits; writes audited as `graphql` / `settings_update`) | graphql (admin_router) |
| `GET/POST /api/admin/webhooks`, `GET/PUT/DELETE /api/admin/webhooks/{id}`, `POST /api/admin/webhooks/{id}/test`, `GET /api/admin/webhooks/{id}/deliveries`, `POST /api/admin/webhooks/{id}/deliveries/{delivery_row_id}/redeliver` (writes, tests and redeliveries audited as `system` / `webhook.*`; the signing secret and header values are write-only, and a save that changes the URL's scheme, host or port, turns TLS verification off or changes the CA bundle must send them again, else `400`) | webhooks (router, `require_admin` in `app.py`) |
| `POST /api/custom-fields`, `PUT/DELETE /api/custom-fields/{field_id}`, `PUT/DELETE /api/tags/{tag_id}` | custom_fields (admin_router) |
| `POST /api/computed-fields`, `PUT/DELETE /api/computed-fields/{field_id}`, `POST /api/computed-fields/preview`, `POST /api/relationships`, `PUT/DELETE /api/relationships/{relationship_id}` (audited as `custom_fields`) | custom_fields (admin_router) |
| `POST /api/dcim/{manufacturers,device-types,roles,statuses}`, `PUT/DELETE /api/dcim/{manufacturers,device-types,roles,statuses}/{id}` (`?confirm=true` to delete a record hosts use) | device_model (admin_router) |
| `POST /api/ipam/vrfs`, `PUT/DELETE /api/ipam/vrfs/{vrf_id}`, `POST /api/ipam/vlans`, `PUT/DELETE /api/ipam/vlans/{vlan_id}`, `POST /api/ipam/interface-addresses/rebuild` (audited as `network_objects`) | network_objects (admin_router) |
| `POST /api/ipam/{namespaces,route-targets,vlan-groups,rirs,aggregates}`, `PUT/DELETE /api/ipam/{namespaces,route-targets,vlan-groups,rirs,aggregates}/{id}`, `PUT /api/ipam/vrfs/{vrf_id}/route-targets`, `PUT /api/ipam/prefixes/{prefix_id}/namespace` (audited as `ipam_model`) | ipam_model (admin_router) |
| `POST /api/dcim/component-templates`, `PUT/DELETE /api/dcim/component-templates/{id}` (audited as `device_model`) | device_model (admin_router) |
| `POST /api/virtualization/sync-cloud` (mirror the discovered AWS, Azure and GCP instances as virtual machines; audited as `virtualization` / `sync_cloud`) | virtualization (admin_router) |
| `POST /api/intended-config/templates`, `PUT/DELETE /api/intended-config/templates/{id}`, `POST /api/intended-config/contexts`, `PUT/DELETE /api/intended-config/contexts/{id}`, `POST /api/intended-config/preview` (writes audited as `config`; the preview stores nothing) | intended_config (admin_router) |
| `POST /api/export-templates`, `PUT/DELETE /api/export-templates/{id}`, `POST /api/export-templates/preview` (writes audited as `export_templates`; the preview stores nothing) | export_templates (admin_router) |
| `GET/POST /api/intended-config/remediation-ignores`, `PUT/DELETE /api/intended-config/remediation-ignores/{id}` (remediation ignore rules; writes audited as `config` / `intended_ignore_*`) | intended_config (admin_router) |
| `GET/POST /api/git-sources`, `GET/PUT/DELETE /api/git-sources/{id}`, `GET /api/git-sources/{id}/objects`, `POST /api/git-sources/{id}/sync` (writes and syncs audited as `config` / `git_source_*`; credentials are service credentials, never returned). Templates, playbooks and intended configuration contexts a Git source owns answer `409` to `PUT` and `DELETE` on their own routes | git_sources (router, `require_admin` in `app.py`) |
| `POST /api/sync/connections`, `PUT/DELETE /api/sync/connections/{id}`, `POST /api/sync/connections/{id}/test` (a connection binds a service credential; audited as `sync` / `connection_*`) | sync (admin_router) |
| `/api/secret-variables/*` | (admin enforced in handlers; reads and writes both, including each secret's `usable_by` rule. Saving a template, a playbook input schema or a group SNMP profile that references `{{secret.NAME}}` needs the saver to be allowed by that secret's rule, else `403`; a name that does not exist reads the same) |
| `POST /api/sources`, `GET/PUT /api/sources/schedule`, `PUT/DELETE /api/sources/{org_ref}`, `POST /api/sources/{org_ref}/validate` (integration sources, their credentials and the collection schedule) | meraki_topology (an admin dependency on each route) |
| `GET /api/sources/{org_ref}/importable-devices`, `POST /api/sources/{org_ref}/import-devices` (importing a source's devices into the inventory) | source_import (`require_admin` in `app.py`) |
| `POST /api/metrics/vendor-oids`, `DELETE /api/metrics/vendor-oids/{entry_id}` | metrics_engine (an admin dependency on each route) |
| `POST /api/sla/evaluate` | monitoring (an admin dependency on the route) |
| `POST /api/mac-tracking/cleanup` (deletes the MAC and client entries of every host not seen for `days`) | mac_tracking (an admin dependency on the route) |
| `POST/PUT/PATCH/DELETE /api/ipam/*` (every IPAM write: prefixes, allocations, reservations, sources and their sync, reconcile and validate, the sync settings, utilization snapshots, resolving a reconciliation diff and prefix custom data) | ipam, custom_fields (an admin dependency on each route) |
| `POST /api/import/ipam/{object_type}/preview`, `POST /api/import/ipam/{object_type}/commit` (CSV bulk import into IPAM) | bulk_import |
| `POST /api/dhcp/servers`, `PATCH/DELETE /api/dhcp/servers/{server_id}`, `POST /api/dhcp/servers/{server_id}/sync` | dhcp (an admin dependency on each route) |
| `POST/PUT/DELETE /api/cloud/*`, `GET /api/cloud/accounts/{account_id}/discover/progress`, `GET /api/cloud/flow-sync/cursors`, `GET /api/cloud/traffic-sync/cursors` (cloud accounts, validation and discovery, flow log and traffic metric ingest and pulls, and the three sync settings) | cloud_visibility (an admin dependency on each route) |
| `POST /api/software/cve-enrichment/run`, `POST /api/software/psirt/sync`, `POST /api/software/psirt/test`, `GET/PUT /api/software/settings` | software (an admin dependency on each route) |
| `POST /api/organization/{regions,tenant-groups,tenants}`, `PUT/DELETE /api/organization/{regions,tenant-groups,tenants}/{id}` | organization (admin_router) |
| `/api/federation/*` (peers, their test and sync, and the overview. The `federation` feature shows the page; every route also needs an admin) | federation |
| `/api/validation-rules/*` (data validation rules, their test, fields and violations) | validation_rules (`require_admin` in `app.py`) |
| `GET/PUT /api/admin/metrics/receivers/config`, `POST /api/admin/metrics/receivers/start`, `POST /api/admin/metrics/receivers/stop`, `GET/PUT/DELETE /api/admin/metrics/receivers/tls`, `POST /api/admin/metrics/receivers/tls/generate` (syslog / trap receiver settings and the syslog TLS server certificate and client CA; writes audited as `system` / `event_receivers.*`, `syslog_tls.*`; the TLS private key is write-only and encrypted at rest) | metrics_engine_admin |
| `/api/monitoring/meraki-alerts/settings` (GET/PUT; the webhook secret is write-only), `POST /api/monitoring/meraki-alerts/poll` | meraki_alerts_admin |
| `/api/monitoring/vendor-alerts/{provider}/settings` (GET/PUT; the Cato events feed, AWS and Azure alert feed settings and per-account status; PUT audited as `vendor_alerts.settings_updated`), `POST /api/monitoring/vendor-alerts/{provider}/poll` (audited as `vendor_alerts.polled`) | vendor_alerts_admin |

### WebSocket (self-authenticated)

| Path | Auth check | Feature check |
|------|-----------|---------------|
| `/ws/jobs/{job_id}` | session cookie | `jobs` feature |
| `/ws/config-capture/{job_id}` | session cookie | `config-drift` feature |
| `/ws/config-revert/{job_id}` | session cookie | `config-drift` feature |
| `/ws/deployment/{job_id}` | session cookie | `deployments` feature |
| `/ws/upgrades/{campaign_id}` | session cookie | `upgrades` feature; read-only, for every holder who may read all of the campaign's devices |

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
| List | ✅ | ❌ (API token only) | ❌ (API token only) |
| Create | ✅ (auto-owned) | - | - |
| Update | ✅ | ❌ (API token only) | ❌ (API token only) |
| Delete | ✅ | ❌ (API token only) | ❌ (API token only) |

The admin role gives no access to another user's credential. A credential
created with the API token has no owner.

Operational endpoints (job launch, deployments, config backups/drift,
compliance, upgrades, risk analysis, inventory discovery) enforce the same
ownership rules at credential-*use* time via
`require_credential_access()` in `netcontrol/routes/shared.py`. Background
workers (job queue, backup/compliance schedulers) re-validate against the
task's original submitter. Every allow/deny decision emits a `credential`
audit event; non-ownership grants carry an `override=` marker.

Inventory discovery remembers the SSH credential of each group's last
explicit scan or sync (`inventory_groups.discovery_credential_id`). A scan
or sync without a credential uses it only after the same
`require_credential_access(..., allow_service=True)` check as an explicit
pick; when the caller may not use it the service credential is used and
the result says so (no `403`). The scheduled discovery sync uses it only
when it is a service credential. The Plexus service credential signs in to
a scan's or sync's addresses only for an admin or the API token, or when
every address is the IP of an inventory host the caller may change whose
address an admin confirmed; otherwise the scan, sync and their stream
variants answer `403` and the caller picks their own credential or turns
SSH off. Inventory collection (`POST /api/topology/inventory/collect`)
reads only inventory hosts the caller may change, and skips (saying so) a
host whose address awaits confirmation when it signs in with the service
credential.

**Confirmed host addresses** (`netcontrol/managed_targets.py`). Shared
secrets (the Plexus service credential, the default credential, the
shared SNMP profiles) go only to a host address an admin set or
confirmed. `hosts.address_confirmed` is set when an admin or the API token
creates a host or changes its `ip_address` (single, bulk, bulk import,
discovery sync and onboard), and cleared when anyone else does; other
host fields leave it alone. Hosts stored before migration 0134 count as
confirmed. A host awaiting confirmation is not polled by monitoring or the
FDM collector (never recorded as down, no availability or SLA alert),
gets no MAC/ARP collection, topology SNMP walk, post-job SNMP re-probe,
backup or compliance capture with a shared credential, no live SSH
enrichment, is skipped by a job that runs with the default or a service
credential, and is not a valid secret-variable job target for a
non-admin launcher. An upgrade campaign or deployment that runs with the
default or a service credential decides on the host's stored row read at
the time of the run, whoever runs it (running it as an admin confirms
nothing): deployment execute is refused with `409` before any device is
touched, naming up to 5 such hosts; a rollback skips the host (a failed
rollback checkpoint with the reason) and rolls back the others; a campaign
phase (prestage, transfer, activate, verify, check status, a scheduled or
rehydrated activate, UPS phases) fails the device with the reason and
carries on with the others, as it does for a campaign device whose
address is no longer its inventory host's or whose host was deleted
since it was added (`upgrade_devices.from_inventory`, migration 0135). A user's own credential is
unaffected when its owner uses it in their own request. Work that runs
later for a stored owner (a scheduled backup or compliance scan, a
syslog-triggered backup, a queued or approved job, a deployment executed or
rolled back by someone other than the credential's owner) sends that
owner's personal credential only to a confirmed address or one the owner
set (`hosts.address_set_by`, migration 0141; written with the address by
host create, update, bulk add, bulk import and discovery sync, left alone
by an edit that keeps the address). Other hosts are skipped and reported
with the reason; a deployment execute is refused with `409`. An upgrade
campaign phase that is scheduled, resumed after a restart, or started by
someone other than the credential's owner applies the same rule per device
(`managed_targets.recorded_address_refusal(..., deferred=True)`): a refused
device fails with the reason and the others carry on. A scheduled phase
(and one resumed after a restart) resolves the campaign's credential again
when its time comes, for the campaign's creator as the account is then
(`upgrades._start_scheduled_phase`): a creator who was disabled or deleted,
no longer owns the credential, or lost the admin role a service credential
needs gets no run; the operation is recorded as failed with the reason and
audited as `upgrades` / `phase_execute_refused`. Hosts stored
before migration 0141 have no recorded writer: an unconfirmed one needs an
admin's confirmation first. Discovery scans and syncs by a non-admin send the group's SNMP
settings only to the IP of a confirmed inventory host the caller may
change and probe the other addresses without SNMP, reported as
`snmp_withheld` (`count`, `reason`) in the scan job result, the stream
`start` / `done` events and the sync response; an admin, the API token and
the scheduled sync are not limited. A sync or onboard decides whether the
hosts it writes are confirmed from the request's caller. `unmanaged_addresses`
treats the address of a host awaiting confirmation as unmanaged. The monitoring and MAC tracking fallback to
`default_credential_id` applies only when that credential is a service
credential. Admin only (admin router): `POST
/api/admin/hosts/{host_id}/confirm-address` and `POST
/api/admin/hosts/confirm-address` (`host_ids` and/or `group_id`), audited
`inventory` / `host.address_confirmed`.
Routes (inventory feature, `@scoped("group")`):

| Route | Group access | Effect |
|-------|--------------|--------|
| `GET /api/inventory/{group_id}/discovery/ssh-defaults` | read | Service defaults plus `group_credential_id` |
| `DELETE /api/inventory/{group_id}/discovery/credential` | write | Forget the remembered credential (audited `inventory` / `group.discovery_credential`) |

### API-token callers

The server API token (`X-API-Token`) is **admin-equivalent by design**: it
bypasses role checks (`require_admin` short-circuits on `auth_mode ==
"token"`) and credential-ownership checks (including unowned and other
users' credentials). It exists for CI/CD and machine-to-machine use
(federation peers authenticate with it). On `/api/credentials*` and
`/api/secret-variables*` it lists every user credential, acts as an admin
for service credentials and secret variables, and what it creates has no
owner. Routes that act on the caller's own account or history (password
change, profile, tool history, group order) answer `401`: the token is not
a user. Consequences:

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
| Feature gates | Effective features keep only `SCOPE_ENFORCED_FEATURES`: every feature of the catalog (and its `.write` key) is enrolled, so a scoped user keeps the whole application, filtered. A feature outside it (a plugin's) still answers `403` (fail closed). GraphQL keeps only the fields whose resolvers filter by scope (`GRAPHQL_SCOPED_FEATURES`) |
| Records beyond hosts | Through the model registry (`object_scope.MODELS`): a record is readable when its inventory group, host, tenant or site is in scope (tenants of in-scope hosts, sites holding them, or a per-model scope rule of the access group, `/api/admin/access-groups/{id}/scope-rules`), writable when one of them is writable (sites only through a writable rule). Shared catalogues (providers, circuit and cluster types, rack roles, templates, playbooks, compliance profiles, notices, untenanted VRFs, VLANs and ASes) are read only; global actions (sync runs, software refresh, lifecycle settings, Meraki and cloud data) are refused or empty |
| Enforced routers | Every router in `SCOPE_ENFORCED_ROUTERS` (all non-admin routers of the enrolled features, WebSocket routers included): every HTTP and WebSocket route is marked `@scoped` or `@scope_exempt` (checked by a test). Admin routers are unchanged |
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
