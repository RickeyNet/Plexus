# Done

Completed items moved out of `TODO.md`, under their original headings.
Open work stays in `TODO.md`.

# Company-Readiness Plan (3 Weeks)

## Week 1: Baseline Quality & Installability
- [x] Dependencies: add pinned requirements (`requirements.txt`, `requirements-lock.txt`); choose pip; add `.env.example` with config keys.
- [x] Tooling: add `ruff` (lint/format), `mypy`, and `pre-commit` hooks (ruff, mypy, trailing whitespace).
- [x] CI: GitHub Actions pipeline running lint + type check + tests on push/PR.
- [x] Docs: expand README with quickstart and how to run dev server/CLI + Docker.

## Week 2: Reliability, Security, and UX
- [x] Error handling/logging: standardize logging with redaction; normalize API/CLI error responses and exit codes.
- [x] Config validation: startup checks for required env vars/credentials; fail fast with clear messages.
- [x] UX: add dry-run and diff view for conversions; ensure downloadable artifacts and timestamped backups.
- [x] Security: dependency scanning (Dependabot/Snyk/OWASP dep-check); secrets never logged; add basic auth/RBAC for UI/API (at least token protection).
- [x] Observability: emit counters for conversion success/failure and timings; add health endpoint for web app.

## Week 3: Deployability, Docs, and Governance
- [x] Packaging: add Dockerfile and docker-compose (app + backing services) with healthcheck; env-based config.
- [x] Versioning/release: adopt semantic versioning; add `--version` flag; start CHANGELOG; tag first internal release.
- [x] Operator docs: runbook (upload config, review diff, apply), rollback steps, FAQ for mismatch causes.
- [x] Performance/scale: test large configs; document limits; add timeouts/retries on device/API calls.
- [x] Compliance: pick a license; document data handling/retention for configs (storage location and duration).

## Week 4: Security Hardening
- [x] Enforce first-login password reset for default admin account; block privileged operations until password is rotated.
- [x] Add `APP_ALLOW_SELF_REGISTER` (default `false` in production) and gate `/api/auth/register` behind explicit opt-in.
- [x] Harden playbook file writes with filename allowlist, path normalization, and extension enforcement.
- [x] Add CSRF protection for cookie-authenticated API calls; keep token-auth workflows compatible.

## Week 5: Reliability and Observability
- [x] Add bounded concurrency controls for jobs.
- [x] Replace remaining `print()` statements with structured logger events and consistent redaction.
- [x] Add request/job correlation IDs in logs and API responses for traceability.
- [x] Add audit events for auth changes, playbook CRUD actions, and import/deploy operations.

## Week 6: Test Depth, CI/CD, and Ops Readiness
- [x] Add integration tests for protected API behavior when `APP_REQUIRE_API_TOKEN=true`.
- [x] Add tests for playbook filename/path sanitization edge cases and malicious input attempts.
- [x] Add end-to-end smoke tests for convert -> diff -> import workflow with artifact validation.
- [x] Enforce minimum test coverage threshold in CI and fail on critical-module regression.
- [x] Add CI security gates (`pip-audit`, `bandit`, optional CodeQL) and publish SBOM artifacts for releases.
- [x] Add release automation to validate changelog/version consistency and publish container images.
- [x] Refine README setup steps (`.venv` consistency, run commands) and add incident-response runbook scenarios.

## UI/UX Modernization
- [x] Sidebar navigation: collapsible icon+label sidebar replacing top navbar.
- [x] Glassmorphism cards: translucent backdrop-blur on cards, modals, and panels.
- [x] Animated gradient background: floating orbs using theme colors on app and login screens.
- [x] Neon glow accents & gradient borders: glowing hover states, active indicators, and button halos.
- [x] Modern typography: Inter for body text, JetBrains Mono for code blocks.
- [x] Micro-interactions & motion: skeleton loaders, animated stat counters, staggered card entrances.
- [x] 3D perspective card tilt: CSS perspective hover effect on cards.
- [x] Dashboard visual upgrades: ring charts, pulse dots on running status, activity timeline.
- [x] Spacing & visual hierarchy: gradient text headings, better rhythm, section dividers.
- [x] Animated login screen: particle background, card slide-in, logo pulse.
- [x] Toast notifications: slide-in toasts replacing inline error/success banners.
- [x] Keyboard shortcuts: Ctrl+K page switcher, Esc modal close, / to focus search.
- [x] Breadcrumb / page title bar: top bar with current page name and breadcrumb trail.
- [x] Custom scrollbar styling: thin themed scrollbars matching color palette.
- [x] Empty state illustrations: SVG illustrations with call-to-action on empty pages.
- [x] Responsive sidebar overlay: mobile hamburger toggle with slide-in overlay + backdrop.

## UI/UX Improvement Backlog (Post-Modernization)
- [x] Optimize Inventory load path: remove N+1 group->hosts requests by using a single inventory payload with embedded hosts.
- [x] Add page-level data cache + stale-while-revalidate behavior so nav switches feel instant and avoid full refetch every time.
- [x] Add page-level search/filter/sort controls for Inventory, Playbooks, Jobs, Templates, and Credentials.
- [x] Reduce visual weight on Templates list (snippet/preview by default, full content on expand/edit).
- [x] Improve Jobs scanability with sticky filters (status/date/dry-run) and denser list/table view.
- [x] Add reduced-motion/performance mode for blur-heavy and infinite animations.
- [x] Improve modal accessibility (dialog semantics, focus trap, focus return, keyboard-only flow).
- [x] Add URL/deep-link support for internal pages (hash or pushState) so refresh/back keeps context.
- [x] Improve first paint by reducing remote font dependency (self-host or robust fallback stack).

## Week 7: PostgreSQL Optional Deployment (VM/Prod Focus)
- [x] Add dual-backend database abstraction (`sqlite` + `postgres`) while preserving existing `routes.database` API surface.
- [x] Add PostgreSQL schema bootstrap + migration-safe startup path (remove SQLite-specific assumptions for Postgres mode).
- [x] Add Docker Compose PostgreSQL service and env-based backend selection.
- [x] Add SQLite -> PostgreSQL migration utility with dry-run and parity verification.
- [x] Add CI matrix coverage for SQLite and PostgreSQL backends on critical API/database tests.
- [x] Update README and operator runbook for PostgreSQL deployment and backup/restore procedures.

## Week 8-10: Network Management Platform Maturity

### Now (Core Platform)
- [x] Add device discovery + continuous inventory sync (TCP reachability + SSH banner enrichment, inventory reconcile API, scheduled profile-based sync loop, and Inventory UI scan/sync controls; deeper SNMP/API enrichment pending).
- [x] Build topology visualization (L2/L3 neighbors, routing relationships, path view).
- [x] Add config drift detection against intended state with historical diffs.
- [x] Add scheduled configuration backup policies with restore validation checks.
- [x] Add golden templates/compliance profiles with continuous compliance scans.
- [x] Add pre-change risk analysis and impact simulation for policy/route/NAT changes.
- [x] Add maintenance windows and approval gates for production changes.
- [x] Add rollback orchestration with pre/post deployment checkpoints.

### Next (Operations and Observability)
- [x] Add real-time monitoring (interfaces, CPU/memory, VPN health, route churn).
- [x] Add alerting engine with threshold/anomaly rules, dedup, suppression, escalation.
- [x] Add SLA dashboards (uptime, latency, jitter, packet loss, MTTR, MTTD).
- [x] Improve job orchestration UX (queue visibility, priority, dependencies, resume/cancel).

### Metrics Engine (Prometheus Parity) -- Phase 1 Complete
- [x] Add multi-vendor OID registry with HOST-RESOURCES-MIB fallback (Cisco, Juniper, Arista, Fortinet, Palo Alto, generic).
- [x] Add per-interface time-series storage with rate calculation and counter-wrap handling.
- [x] Add flexible metric_samples table (Prometheus-style gauge model with labels).
- [x] Add 3-tier data downsampling engine (raw 48h → hourly 30d → daily 365d with min/avg/max/p95).
- [x] Add structured metrics query API with auto-resolution (`/api/metrics/query`).
- [x] Add SNMP trap and syslog UDP receivers with host correlation.

### Dashboarding & Visualization (Grafana Parity)
- [x] Adopt a charting library (ECharts or Chart.js) for line, bar, gauge, heatmap, and table panels.
- [x] Add per-device detail page with CPU/memory graphs, interface utilization, alert history, compliance status.
- [x] Add global time range selector (1h / 6h / 24h / 7d / 30d / custom) for all metric views.
- [x] Add user-defined dashboards with configurable panels (metric query + chart type + grid position).
- [x] Add dashboard template variables ($group, $host) with dropdown selectors for filtering all panels.
- [x] Add annotation support to overlay deployment/config change events on metric charts.

### Network Monitoring Breadth (LibreNMS Parity)
- [x] Add per-port utilization graphs with historical in/out bps time-series.
- [x] Add availability tracking with up/down state transitions and uptime % calculation.
- [x] Add topology weathermap (color edges green → yellow → red by utilization %).
- [x] Add custom SNMP OID profiles (user-defined OID → metric mappings with vendor defaults).
- [x] Add syslog integration (correlate syslog source IP → device, display in device detail page).
- [x] Add reporting and export (availability, compliance reports with CSV export).

### Closed-Loop Differentiation (Unique to Plexus)
- [x] Add correlation views linking config changes → metric anomalies → alerts → rollbacks.
- [x] Add deployment annotations on metric charts (auto-annotate when deployments execute).
- [x] Add post-change automated verification with success criteria and health checks.
- [x] Add capacity planning trends (bandwidth, policy scale, route table growth).

### Cacti Parity (Graphing & Data Collection Engine)
- [x] Add graph template system (reusable chart definitions that auto-apply to devices by type/metric).
- [x] Add auto-graph creation on device add/discovery (auto-create graphs for all interfaces and standard metrics).
- [x] Add host templates mapping device types to sets of graph templates for automatic provisioning.
- [x] Add per-device and per-data-source configurable poll intervals (30s, 1m, 5m per OID group).
- [x] Add SNMP table walking with auto-discovery of interfaces as independent data sources.
- [x] Add calculated data sources / CDEFs (95th percentile billing, in+out totals, averages, custom expressions).
- [x] Add graph tree hierarchical navigation (Site → Device → Interface with user-scoped permissions).
- [x] Add live bandwidth utilization overlay on topology weathermap links.
- [x] Add graph image export (PNG/SVG direct URLs for embedding in wikis, emails, NOC screens).
- [x] Add MacTrack-style MAC/ARP/port tracking for endpoint location.
- [x] Add NetFlow/sFlow/IPFIX collection and traffic analysis.
  - [x] Initial foundation: `netcontrol/routes/flow_collector.py` with NetFlow v5 + v9/IPFIX template-based parsers, UDP listener, batched buffer flush, hourly aggregation, REST endpoints (`/api/flows/top-talkers|top-applications|top-conversations|timeline|status`, `/api/admin/flows/{start,stop}`), `flow_records` + `flow_summaries` tables (`routes/database.py:1164`), DB helpers, and router mounted in `app.py`.
  - [x] Phase A - wire collector lifecycle: gated by `APP_NETFLOW_ENABLED` (default `false`), `start_flow_collector()` called from `lifespan()` on `APP_NETFLOW_PORT` (default 2055) with retention/aggregation interval from `APP_FLOW_RETENTION_HOURS` + `APP_FLOW_AGGREGATION_INTERVAL_SECONDS`; new `flow_aggregation_loop()` helper in `flow_collector.py` runs `flow_aggregation_cycle()` on the configured cadence (floor 60s) and is created/cancelled alongside the other scheduler tasks; `stop_flow_collector()` runs in shutdown finally. `.env.example` updated with NetFlow keys. Docker UDP/2055 + UDP/6343 ports and UFW/DOCKER-USER rules were already in place in `docker-compose.yml` and `deploy/DEPLOYMENT.md`.
  - [x] Phase B - exporter→host resolution: in-memory `_exporter_cache: dict[str, int]` in `flow_collector.py` populated from `hosts.ip_address` via `db.get_exporter_host_map()` at `start_flow_collector()` and refreshed from `inventory.py` add/update/remove/bulk-delete and discovery sync via `_notify_flow_collector_host_changed()` → `flow_collector.on_host_changed()`; `datagram_received` now resolves `host_id` from the cache so per-device flow queries actually return rows. New `flow_exporters` table (migration 0036 + canonical SCHEMA) with `(exporter_ip, flow_type)` unique key, upserted on every packet by `_record_exporter_packet()` → `db.upsert_flow_exporter()` (atomic `ON CONFLICT … DO UPDATE` increments `packets_received`, refreshes `last_seen`/`last_record_at`, and resyncs `host_id` so freshly-added inventory hosts get linked without a restart). New `GET /api/flows/exporters` returns the joined exporter list with hostname, packet counters, sampling rate, first/last seen, plus the live cache size.
  - [x] Phase C - sFlow v5 parser: `parse_sflow(data, addr)` in `flow_collector.py` decodes the v5 datagram header (IPv4/IPv6 agent address, sub-agent, sequence, num_samples), iterates samples, and for `flow_sample`/`expanded_flow_sample` walks each `flow_record`; `flow_data_format=raw_packet_header` (the common case) routes into `_decode_raw_packet_header()` which strips 802.1Q/QinQ tags, validates IPv4, and pulls src/dst IP+port+protocol off TCP/UDP into the same dict shape used by NetFlow. Counter samples are accepted (not parsed into flow_records) so devices that send mixed sample types don't error out. `_FlowCollectorProtocol` now takes a `mode="netflow"|"sflow"` flag and `start_flow_collector(port, sflow_port=...)` opens a second `create_datagram_endpoint` on the sFlow port; sFlow bind failure is logged but doesn't abort NetFlow startup. `bytes`/`packets` are scaled by the observed sampling_rate (frame_length × rate) so top-talker math is consistent with NetFlow. Sampling rate is captured per `(exporter_ip, source_id)` and surfaced into `flow_exporters.sampling_rate` via `_record_exporter_packet()` so the UI can show "this device is sampling 1:1024". `/api/flows/status` now returns `sflow_port`/`sflow_running`; `/api/admin/flows/start` accepts an optional `sflow_port` query param. `app.py` reads `APP_SFLOW_PORT` (set to `0` to disable) and passes it into `start_flow_collector()`.
  - [x] Phase D - config surface: NetFlow toggle/ports/retention now persist in the `auth_settings` table under the key `flow_collector` (sanitized by `state._sanitize_flow_collector_config`). `_load_persisted_security_settings()` reads the row at boot and, on first boot only, seeds it from the legacy `APP_NETFLOW_*` env vars via `_flow_collector_seed_from_env()` so existing deployments keep working without UI clicks. Lifespan no longer reads env vars directly - it consults the persisted `FLOW_COLLECTOR_CONFIG`. New `GET/PUT /api/admin/flows/config` round-trips `{enabled, netflow_port, sflow_port, retention_hours, summary_retention_days, aggregation_interval_seconds}` plus read-only `netflow_running`/`sflow_running` status. `apply_flow_collector_config()` diffs old vs new and only rebinds UDP listeners when `enabled`/`netflow_port`/`sflow_port` actually changed (start→stop sequence avoids EADDRINUSE on rebind), and `_ensure_aggregation_task()`/`_cancel_aggregation_task()` manage the aggregation loop so disabling the collector stops both the listener and the periodic rollup. React Settings page gains a NetFlow tab (`NetFlowTab.tsx`) with enable toggle, port inputs, retention/aggregation inputs, live running-status badges, and inline page help; wired through `useFlowCollectorConfig`/`useUpdateFlowCollectorConfig` hooks in `api/settings.ts`. Changes apply immediately - no restart required.
  - [x] Phase E - frontend Traffic Analysis page: `TrafficAnalysis.tsx` now renders five tabs (Top Talkers / Top Applications / Conversations / Timeline / Exporters) inside the standard card+pill-tab layout, with a global host filter (dropdown built from `useInventoryGroupsFull` flattened to a single host list) and time-range selector (1h/6h/24h/7d) in the page header. All `useFlowTop*`/`useFlowTimeline` hooks now accept an optional `hostId` and append `&host_id=N` to the underlying `/api/flows/*` calls. Charts use the existing echarts wrapper (`BarChart` for talkers/apps, `TimeSeriesChart` with `bps` axis for the timeline - normalised from per-bucket totals using the same bucket-minutes logic the hook computes). Exporters tab shows `flow_exporters` rows from `/api/flows/exporters` with hostname (linked to device detail when resolved), flow type, packet counter, sampling rate (`1:N`), and first/last seen. `useFlowStatus` was widened to surface `enabled`/`netflow_port`/`sflow_port`/`sflow_running` so the page header can show separate NetFlow and sFlow status badges. Routing (`/traffic-analysis`) and sidebar nav entry were already in place from the earlier stub.
  - [x] Phase F - device-detail integration: new `FlowTab.tsx` under `DeviceDetail/` adds a "Flow" tab to the device detail page. Top of the tab is an exporter-status card (one tile per `flow_exporters` row matching `host_id` - flow type, exporter IP, total packets received, sampling rate as `1:N`, last record time) so an operator can see at a glance whether the device is actually exporting and how it's sampling. Below that is a pill-button sub-tab row (Top Talkers / Applications / Conversations / Timeline) - each view reuses the existing `useFlowTop*` / `useFlowTimeline` hooks with `hostId` set to the detail page's host so all flow queries are pre-scoped to this device. The DeviceDetail range selector (`1h`/`6h`/`24h`/`7d`/`30d`) is mapped to the hours param the flow APIs expect, so changing the range at the top of the page filters this tab too. The Flow tab is hidden when the `traffic-analysis` feature is in `feature_visibility_hidden` (matches how the sidebar entry is suppressed), and an effect bounces back to Overview if the feature is hidden while the user is on the Flow tab.
  - [x] Phase G - playbook to configure exporters: new `templates/playbooks/netflow_enable.py` registers as `NetflowEnabler` and pushes platform-specific NetFlow v9 config to selected hosts. `_platform_builder()` dispatches on `device_type` to one of three command builders: `_build_ios_commands` (classic `ip flow-export destination` + per-interface `ip flow ingress/egress`), `_build_xe_commands` (Flexible NetFlow with `flow record` / `flow exporter` / `flow monitor` and optional `sampler` for IOS-XE), and `_build_nxos_commands` (same Flex shape with NX-OS syntax differences and a leading `feature netflow`). Collector destination resolves in priority order from job parameters (`collector_ip` / `collector_port`), then `PLEXUS_COLLECTOR_IP` + `APP_NETFLOW_PORT` env vars; without an IP the playbook fails fast with a clear error before touching any device. Per-host `netflow_interfaces` override beats the global default. Dry-run prints the exact config lines that would be applied (banner + per-host preview) so an operator can paste them into change control; live mode runs `show running-config | include flow|ip flow-export` first to capture state, applies via `send_config_set`, verifies with `show ip flow export` (IOS) or `show flow exporter PLEXUS-EXPORT` (XE/NX-OS), and `save_config`s on success. Sampling rate is plumbed end-to-end (1:1 default, configurable per job) and wired into the `sampler` block so the collector's `sampling_rate` field gets populated correctly. Simulation mode mirrors the real path when Netmiko isn't installed.
  - [x] Phase H - tests: new `tests/test_flow_collector.py` (12 tests, all passing). Hand-builds a NetFlow v5 datagram from `struct.pack` and asserts the parser round-trips every flow record field (src/dst IP+port, protocol, bytes, packets, exporter_ip) and rejects wrong-version / truncated packets. NetFlow v9 coverage builds a real `Template flowset (id=0)` followed by a matching `Data flowset (id=256)` with seven fields (src_ip/dst_ip/src_port/dst_port/protocol/in_bytes/in_pkts), verifies template caching + decoding, and confirms a data flowset without its template is dropped silently (the common case right after a collector restart). sFlow v5 coverage builds a full datagram from scratch - `v5 header → flow_sample → raw_packet_header → Ethernet/IPv4/UDP frame` - asserts the inner 5-tuple is extracted, that `bytes` is computed as `frame_length × sampling_rate` (de-sampling math) and that `_latest_sflow_sampling_rate()` captures the rate for the API surface. DB coverage seeds a sqlite DB via `init_db()`, inserts a batch with `create_flow_records_batch`, and validates `get_flow_top_talkers` ordering for both `src` and `dst` directions plus the empty-batch no-op path. Lifecycle test grabs two free UDP ports (via `bind(("127.0.0.1", 0))`), confirms `start_flow_collector` toggles `_flow_transport`/`_sflow_transport`/`FLOW_COLLECTOR_CONFIG['enabled']`, that a second `start_*` while already running returns `False` instead of crashing on EADDRINUSE, and that `stop_flow_collector` is similarly idempotent. Exporter cache tests verify `refresh_exporter_cache()` loads `ip → host_id` from inventory, and that `on_host_changed()` propagates both directions: when a new host is added for an existing exporter IP, the cache and any matching `flow_exporters` rows pick up the `host_id` without a collector restart; when the host is removed, both are cleared.
  - [x] Phase I - docs: new `NetFlow / sFlow / IPFIX` section in `README.md` (ports table for UDP 2055 / 6343, enable-via-`.env`-or-Settings flow, `GET`/`PUT /api/admin/flows/config` examples, exporter playbook usage across IOS / IOS-XE / NX-OS, Docker host-vs-container IP note, retention summary). New `DEPLOYMENT.md` with the firewall stanza Phase I called for - UFW rules for UDP 2055 / 6343 scoped to a management subnet (not the open internet), `DOCKER-USER` iptables rules (insert ACCEPT for the mgmt subnet before the DROP-everything-else rules so order is correct), the `2055:2055/udp` + `6343:6343/udp` compose `ports:` block (the `/udp` suffix is mandatory or only TCP gets published and the collector silently sees nothing), and verification steps (`ss -lunp`, device-side `show flow exporter PLEXUS-EXPORT statistics`, `GET /api/flows/exporters`). Also covers persistent state volumes and a `systemd` unit for non-Docker installs. New `DATA_RETENTION.md` lists every retention surface in one table (job history 30d, raw flow records 48h, flow summaries 30d, config backups 90d, monitoring polls/alerts/interface counters/SLA metrics/route snapshots/trap+syslog events, IPAM IP history 365d) and dedicates a section to the NetFlow split - why raw flows are short-retention (high write volume, low long-term value) and summaries are long-retention (cheap rollups, week-over-week trending in the Traffic Analysis page), how to tune `retention_hours` / `summary_retention_days` at runtime, and why the persisted `auth_settings("flow_collector")` row is authoritative over env vars after first boot.
- [x] Add baseline deviation alerting (statistical learning, not just static thresholds).

### Later (Enterprise and Ecosystem)

- [x] Add enterprise auth (LDAP/AD with auto-provisioning, group-to-role mapping, and local fallback).

## Hospital / Healthcare Network Readiness

### P0 - HIPAA Compliance & Security (Must-Have Before Deployment)

- [x] **Enforce TLS everywhere** - disable HTTP listener in production mode; redirect all plaintext to HTTPS; add HSTS header with long max-age. *Why: HIPAA §164.312(e)(1) requires encryption of ePHI in transit. The NMS carries device credentials and may display config snippets containing sensitive data.*
- [x] **Configurable session idle timeout** - add server-side idle timeout (default 15 min, configurable per policy); auto-terminate sessions and force re-auth on expiry; show countdown warning toast. *Why: HIPAA §164.312(a)(2)(iii) requires automatic logoff. Shared workstations in nurse stations and NOCs make this critical.* - Implementation: server-side enforcement lives in `require_auth` (`netcontrol/app.py`) and is mirrored in `auth_status` (`netcontrol/routes/auth.py`) so a stale cookie cannot make the SPA think it is still logged in. Timeout is configured via the existing `state.LOGIN_RULES.session_idle_timeout` admin policy (Settings → Authentication → Login Rules); `0` disables enforcement and per-user `session_never_expires=1` accounts (kiosks) bypass the check. Every expiry path emits a `category=auth action=session.idle_timeout` audit event with `idle=<elapsed>s threshold=<limit>s path=<endpoint>` and the request's correlation id. `/api/auth/status` now returns `idle_timeout_seconds`, `session_last_activity`, `session_never_expires`, and `server_time` so the SPA can drive a clock-skew-tolerant countdown. New `POST /api/auth/heartbeat` (calls `require_auth` directly so the cookie's `last_activity` is refreshed) lets a "Stay signed in" button reset the timer without waiting for the next status poll. React `IdleTimeoutWatcher` (mounted in `App.tsx`) renders a fixed-position warning toast when fewer than 60s remain, auto-calls `/api/auth/logout` on expiry, and re-anchors its countdown whenever `session_last_activity` advances. Tests in `tests/test_session_idle_timeout.py` cover the require_auth expiry path, kiosk bypass, `session_idle_timeout=0` disable, cookie refresh on active sessions, the `auth_status` mirror path with audit emission, and the new SPA-facing idle fields.
- [x] **Immutable audit log with tamper protection** - make audit_events append-only at the database level (no UPDATE/DELETE on audit tables); add cryptographic chaining (hash of previous entry) or write-once export; ensure admins cannot delete their own audit trail. *Why: auditors will ask "can a privileged user cover their tracks?" The answer must be no.* - Implementation: migration 0037 adds `prev_hash` + `row_hash` columns (sha256 chain over timestamp, category, action, user, detail, correlation_id, prev_hash) and `BEFORE UPDATE`/`BEFORE DELETE` triggers (`audit_events_no_update`, `audit_events_no_delete`) that abort with `audit immutable` on SQLite (`RAISE(ABORT)`) and Postgres (`RAISE EXCEPTION` via `audit_events_block_mutation()`). Existing rows are backfilled in a single transaction. `add_audit_event` computes the hash inside an `asyncio.Lock` so concurrent inserts can't fork the chain. New `routes.database.verify_audit_chain()` walks the log and reports the first break (`row_hash_mismatch` or `prev_hash_mismatch`); exposed at `GET /api/admin/audit-events/verify`. Tests in `tests/test_audit_chain.py` cover clean chains, tamper detection (mutation + deletion), trigger blocking, backfill correctness, and the canonical-hash formula.
- [x] **SIEM log forwarding** - add configurable syslog/webhook forwarding of audit events, auth events, and alert triggers to external SIEM (Splunk, Sentinel, QRadar); support CEF or JSON format. *Why: hospital security teams centralize all logs for correlation and incident response. Plexus events must feed the same pipeline.* - Implementation: `netcontrol/routes/siem_forwarder.py` runs a per-sink async dispatcher fed by an `add_audit_event` hook (`db.set_audit_event_hook`). Sinks support syslog UDP, TCP (RFC 6587 octet-counting), TLS (RFC 5425, optional mTLS + CA pin), and HTTPS POST (bearer token, optional CA pin). Formatters: CEF 1.0 with proper pipe/equals escaping, and ECS-shaped JSON (`@timestamp`, `event.action`, `user.name`, `plexus.row_hash`). Each sink has an `asyncio.Queue` bounded by `queue_size`; on overflow the oldest event is dropped and counted. Failures retry with exponential backoff capped at `backoff_cap`, giving up after `max_retries`. Per-sink config is persisted under the `siem_sinks` `auth_settings` key, reconciled at startup and on every CRUD via `apply_sinks`. Admin API: `GET/POST/PUT/DELETE /api/admin/siem-sinks` plus `/api/admin/siem-sinks/{id}/test` for live probe; runtime stats (`delivered`, `dropped_*`, `last_error`) returned alongside config. Bearer tokens and TLS private keys are masked as `••••••••` in API responses and only overwritten when the client sends a non-mask value. React `SiemTab` in Settings provides full CRUD with live stats refresh every 10s, severity-floor selector, and inline test button. Tests in `tests/test_siem_forwarder.py` cover validation, formatter shape, UDP/TCP delivery against real local listeners, dispatcher fan-out, bounded-queue drop-oldest policy, retry exhaustion, severity-floor filtering, and the audit-event hook (including hook-failure isolation from the insert path).

### P1 - Operational Readiness (Required for Production Use)

- [x] **Alert notification channels (email, PagerDuty, webhook)** - add outbound integrations for alert rules; support email (SMTP), PagerDuty Events API v2, generic webhook (POST JSON), and Microsoft Teams incoming webhook; allow per-rule channel assignment. *Why: critical alerts at 3 AM must reach the on-call engineer's phone, not just a toast notification in a browser tab nobody is watching.* - Implementation: new `netcontrol/routes/notification_channels.py` engine (mirrors `siem_forwarder`) with per-channel async dispatcher tasks, bounded drop-oldest queues, exponential-backoff retry, per-type formatters/drivers (email via stdlib `smtplib` in a thread executor; PagerDuty/webhook/Teams via `httpx`), secret redaction, and `send_test_event`. Channels persist under the `notification_channels` `auth_settings` key (`{channels, default_channel_ids}`), loaded/started in `app.py` lifespan. New alerts fan out via a `db.set_alert_created_hook` registered hook fired by `create_monitoring_alert` ONLY on genuinely new inserts (dedup bumps do not re-notify); the hook resolves the owning rule's `channel_ids` (new `alert_rules` column, migration 0050) or falls back to the default set, then applies each channel's severity floor. Admin CRUD + test + defaults endpoints in `admin.py`; rule create/update endpoints accept `channel_ids`. React `NotificationsTab` (Settings) provides full CRUD, live stats, per-channel test, and default-channel toggles; `RulesTab` gains a per-rule channel multi-select and shows assigned channels. Tests in `tests/test_notification_channels.py` (29 passing) cover validation, redaction/merge-secrets, formatters, severity floor, fan-out/defaults/per-rule override, bounded-queue drop-oldest, retry exhaustion, email + webhook/teams delivery against local listeners, reconcile, and test-event. README "Alert Notification Channels" section added.

## Network Operations & Visibility Enhancements

### Now - Core Operations Gaps

- [x] **Configuration full-text search** - add full-text search across all backed-up device configurations; support regex and substring matching; return results with device name, match context, and link to full config diff view; index on backup ingest for fast queries. *Why: "which devices still have SNMP community string `public`?" or "which routers have this ACL entry?" are daily questions during audits, incident response, and security hardening. Without cross-device config search, operators resort to SSH-ing into devices one by one.*
- [x] **STP topology visualization** - display spanning-tree topology per VLAN showing root bridge, designated/blocked/forwarding port states, and topology change events; alert on unexpected root bridge elections or topology change storms; overlay STP state on physical topology map. *Why: spanning-tree misconfigurations cause broadcast storms and outages that are notoriously difficult to diagnose. Visualizing STP state per-VLAN makes root bridge placement and blocked port logic immediately obvious.*
- [x] **Interface error/discard trending with root-cause correlation** - track CRC errors, input errors, giants, runts, output drops, and discards per interface over time as dedicated metrics; correlate error spikes with config changes, topology events, and cable/optic replacements; surface "likely cause" hints (e.g., CRC spike + no config change → suspect physical layer). *Why: raw error counters exist in SNMP but operators need trends and correlation, not point-in-time numbers. Reduces MTTR by surfacing physical-layer problems before they cascade.*

### Later - Advanced Analytics

- [x] **Bandwidth billing and 95th percentile reports** - calculate burstable 95th-percentile bandwidth per interface, per customer, or per circuit over configurable billing periods; generate exportable invoices with usage graphs; support commit-rate tracking and overage alerting. *Why: ISPs and shared-services IT departments bill by 95th percentile. This is a direct revenue/chargeback feature that currently requires a separate tool (MRTG, Cacti, or manual calculation).*
- [x] **Automated network documentation generation** - auto-generate network diagrams, IP address plans, VLAN maps, and device inventories as exportable PDF, SVG, or draw.io from discovered topology, inventory, and SNMP data; refresh on schedule or on-demand; include cable/circuit info when available. *Why: network documentation is always out of date. Auto-generating it from live discovery data means the documentation is as current as the last poll cycle. Saves hours of manual Visio work per quarter.*
  - [x] Initial on-demand foundation: added `network_documentation` report generation plus CSV export and SVG topology diagram export from live inventory/topology/VLAN data.
  - [x] Next slice (phase A): scheduled generation loop + persisted run artifacts (CSV/SVG) with downloadable artifact history.
  - [x] Next slice (phase B): PDF packaging and cable/circuit enrichment from billing circuit metadata (`circuit_map` + topology link enrichment).
  - [x] Next slice (phase C): draw.io topology export endpoint plus persisted `.drawio` artifacts and report UI export actions.

## Automation & Workflow Enhancements

### Now - High-Impact Automation

- [x] Add feature visibility toggle for hiding un used UI features

## Integration & Extensibility

### Now - Ecosystem Connectors

- [x] **Ansible dynamic inventory provider** - expose Plexus device inventory as an Ansible dynamic inventory source via CLI script or HTTP endpoint; support group mapping (Plexus inventory groups → Ansible groups), host variables (IP, credentials, device type, model), and filtering by group, tag, or device type. *Why: teams already using Ansible for network automation need their inventory source to be authoritative and current. Plexus as the single source of truth for device inventory eliminates stale static inventory files and manual synchronization.*

## Code Review Backlog (June 2026 Audit)

### Batch 1 - Quick Wins (low risk, do first)

- [x] **Fix the 13 pre-existing failing tests** - `test_week4_security` (3), `test_audit_overrides` (3), `test_geolocation` (4), `test_upgrades_images` (2), `test_cloud_visibility` (1). *Why: they fail on clean main and mask real regressions - every review session has needed stash-and-diff baselining just to tell new failures from the noise.* Root causes: 12 of 13 were stale tests asserting pre-change contracts (admin bootstrap promote-existing path + random-password first boot, `auth_status` new `Response` param, new HTTPS-redirect warning, FK enforcement on `audit_rule_overrides.host_id`, 201-on-create + Pydantic-422 convention, standardized `{ok, error:{code,message}}` error envelope, hardcoded April-2026 fixture timestamps aging out of the 24h window). 1 real production bug fixed: cloud-metric window cutoff compared Python-isoformat `interval_end` (T separator) lexically against SQLite `datetime('now')` (space separator), over-including the boundary day by up to ~24h — replaced with a Python-computed cutoff in `routes/database.py` (`_cloud_metric_window_cutoff`), engine-agnostic.
- [x] **Repo hygiene** - gitignore and untrack `coverage.json`, `_pytest_one.txt`, `.pytest_after.txt`, `netcontrol.db.migrate.lock`; CI should regenerate coverage artifacts, not version them.
- [x] **Add `pytest-xdist` to `requirements-dev.txt`** and document `-n auto` (already proven locally: full suite drops from ~18 min serial to ~4 min with 6 workers). Consider markers/timeout config in `pytest.ini` while in there.
- [x] **Fix blocking `time.sleep(1)` in `netcontrol/routes/cloud_flow_pullers.py:216`** - stale finding: the sleep is inside `_run()`, which executes via `await asyncio.to_thread(_run)` (line 256) — it sleeps a worker thread, not the event loop. No change needed.
- [x] **Fix `_audit(request, ...)` misuse in `geolocation.py` (9 calls) and `billing.py` (5 calls)** - already fixed: both files now route through `_geo_audit`/`_billing_audit` wrappers that call `_audit` with the correct `(category, action, user=, detail=, correlation_id=)` signature; repo-wide grep finds no remaining `_audit(request, ...)` calls.
- [x] **Migrate remaining `resp.json()["detail"]` asserts** - verified stale 2026-06-12: no test asserts the legacy FastAPI error shape anymore (`test_session_idle_timeout.py:88` reads `HTTPException.detail` in-process, which is correct; `test_siem_forwarder.py` has no response-shape asserts).

### Batch 2 - Background Long-Running Endpoints

- [x] **Inventory discovery scan** (`netcontrol/routes/inventory.py:1002`) - full CIDR probe (up to 4096 hosts) runs inline in the HTTP handler; move to a job record + WebSocket/polling pattern like config-drift capture jobs. Done via new shared in-memory registry `netcontrol/routes/background_jobs.py` (create/progress/finish + TTL cleanup, polling instead of WebSockets): POST `.../discovery/scan` now returns 202 `{job_id}`, poll `GET /api/inventory/discovery/jobs/{job_id}` for progress (`scanned/total/found`) and the same result payload the inline response had. The SSE `/scan/stream` endpoint (what the React DiscoveryModal actually uses) is unchanged. Tests: `tests/test_discovery_scan_job.py`.
- [x] **MAC fleet collection** (`/api/mac-tracking/collect` all-hosts mode) - now has a 409 overlap guard and per-host diagnostics, but still runs inline; reuse the same job pattern once it exists. Frontend needs a job-polling hook to keep the results display. Done: all-hosts mode returns `{job_id}`, runner aggregates per-host results with live `hosts_done/macs_found/arps_found` progress, poll `GET /api/mac-tracking/collect/jobs/{job_id}` (result carries the old inline payload). 409 guard kept. Frontend: `useStartFleetMacCollection` + `useMacCollectionJob` (2s `refetchInterval`) in `networkTools.ts`; MacTracking page shows live progress and the same results card; single-host collect unchanged.
- [x] **Batch MAC upserts** - each MAC costs two awaited DB round-trips (upsert + history), each opening/closing a connection; tens of thousands of connection cycles per collection. Done: `record_mac_sightings_batch` + `upsert_arp_entries_batch` in `routes/database.py` — one connection/transaction per host (executemany upserts, one latest-location query per batch, per-event inserts only for actual moves). Move semantics match `record_mac_history` exactly, including sequential in-batch comparison for repeated MACs; ARP enrichment keeps `enrich_mac_ip`'s only-fill-empty, cross-host behavior. Note: write-failure granularity is now per host-batch, not per MAC (a batch failure surfaces in the host's `errors` diagnostics instead of silently dropping one row).

### Batch 4 - Test & Tooling Structure

- [x] **Run Postgres smoke tests on all PRs** - verified 2026-06-12: ci.yml already has a `postgres-smoke` job (postgres:16 service container) on every PR; what was thin is the coverage. Expanded `tests/test_postgres_backend.py` from 2 to 4 tests: concurrent audit-chain writers (exercises the pg_advisory_lock path that SQLite runs never touch) and category-filtered audit listing (0055 index). Full API-test matrix on Postgres remains future work - most app tests are DB_PATH/SQLite-bound by design. Superseded 2026-10-09: the SQLite engine was removed and the whole suite now runs on Postgres (`PLEXUS_TEST_PG_URL`).

### Batch 5 - Security Follow-Ups

- [x] **Credential-isolation regression tests** - done 2026-07-07:
  `tests/test_credential_isolation_http.py` drives one representative endpoint
  per IDOR-swept module over real HTTP (risk-analysis, inventory fetch-serial,
  config-drift capture, config-backups restore, compliance scan, deployments
  create, upgrades campaign create, jobs launch) and asserts a non-owner gets
  403 "You can only use your own credentials" and a bogus id gets 404 - both
  fire before any device I/O. Both accounts are admins so the request clears the
  feature gate and reaches the credential check, which proves the stronger
  property that even an admin can't use another user's personal credential.
  lab_runtime is excluded by design (its credential is device-bound and gated by
  `_get_device_or_403`; covered by `test_lab_runtime.py` + the helper policy in
  `test_credential_isolation.py`).
- [x] **FDM collector credential model** (`netcontrol/integrations/cisco_fdm/collector.py:87`) - done 2026-06-12: `collect_host` rejects non-service credentials (same policy as monitoring/MAC pollers) with a regression test. Bind-time gate still needed when the endpoint that sets `hosts.fdm_credential_id` ships.
- [x] **Air-gap README** (`deploy/airgap/README.md`) - done 2026-07-07: "Step 4 - First login" already documents retrieving the random one-time bootstrap password from the container logs and the `PLEXUS_INITIAL_ADMIN_PASSWORD` override; the stale `admin/netcontrol` copy is gone.
- [x] **Pre-existing backend cleanups** - done 2026-06-12: audit-hook drops now logged (routes/db/audit.py); migration 0055 adds `monitoring_polls(host_id, polled_at)` + `audit_events(category)` (column is `polled_at`, not `sampled_at`); 14 hardcoded semaphores route through `state.device_op_semaphore()` / `APP_DEVICE_OP_CONCURRENCY`. `SELECT *` audit found most uses are narrow tables or fetch-one-by-id where the blob is the payload; the one real waste (deployments annotation query pulling proposed_commands blobs) is trimmed.
- [x] **Late-binding `init_*()` boilerplate** - resolved 2026-06-12 by deletion, not a helper: 11 modules bound auth callables that were never used (route auth comes from app.py's include_router dependencies) - dead init functions/globals removed; config_drift/deployments/upgrades trimmed to the WebSocket session-check callables they actually use; app.py wiring updated. Remaining init_* functions all bind callables that are genuinely consumed.

### Frontend Post-Migration Follow-Ups

- [x] **Remove `script-src 'unsafe-inline'` from the CSP** in
  `netcontrol/app.py` - done 2026-07-07: global `script-src` is now `'self'`
  only (no `'unsafe-inline'`, no CDN); the React bundle ships as external hashed
  modules. The security-headers middleware uses `setdefault` so the one page
  that needs a looser policy - the graph-export embed page (inline bootstrap
  `<script>` + CDN ECharts, data-only) - sets its own scoped CSP without being
  clobbered. `style-src 'unsafe-inline'` is retained for dynamic `style=` attrs.
  Regression test: `tests/test_csp_headers.py`.

### Deferred hardening (from the 2026-07-06 multi-dimension sweep)

- [x] **Consistent-snapshot backup for SQLite installs** - `deploy/backup.sh`
  tars the live `/app/state` volume; with WAL mode a sqlite install can capture
  a torn DB. Use `sqlite3 netcontrol.db ".backup"` or `VACUUM INTO` for the
  sqlite path (Postgres already uses `pg_dump`). Low priority: the documented
  compose deployment is Postgres. Dropped: SQLite is no longer a supported
  runtime (Postgres only); legacy installs migrate with
  `tools/migrate_sqlite_to_postgres.py`.

### Deferred hardening (from the 2026-07-07 five-agent audit)

- [x] **admin secret-sink / notification-channel create TOCTOU** - done
  2026-07-07: the read-modify-write of the shared `state.SIEM_SINKS` /
  `state.NOTIFICATION_CHANNELS` (+ default-channel) globals now runs under a
  per-resource `asyncio.Lock` (`_sink_mutation_lock` / `_channel_mutation_lock`)
  spanning the id-uniqueness check through the `set_auth_setting` persist, so
  concurrent create/update/delete calls can no longer duplicate an id or lose an
  update via a stale payload winning the last write.

### Performance audit (2026-07-08 four-agent sweep)

Most findings were implemented the same day (see `RELEASE_NOTES.md` Performance:
SNMP GETBULK; topology graph + utilization-map caches; dashboard bandwidth N+1;
suppression + vendor-OID caches; discovery-fan-out semaphore; chart `setOption`
reuse; device-scoped query-key decouple; federation concurrent fetch; geolocation
off-loop write; compliance regex cache; `get_baselined_host_ids`; monitoring
`include_details` cap; `compliance_scan_results` index (migration 0058)). Tests:
`tests/test_interface_ts_multi.py`, `tests/test_perf_batch.py`, plus the topology
suite's new cache-clearing fixture. The six deferred behavioral / architectural
items were implemented 2026-07-08 in a follow-up pass:

- [x] **SQLite global-access-lock read pool** — `get_db(read_only=True)` borrows
  a `PRAGMA query_only=ON` connection from a bounded pool (`APP_SQLITE_READ_POOL`,
  default 4; 0 disables) so read helpers overlap each other and the writer under
  WAL. Writes keep the single connection + exclusive lock. Nested acquisition
  reuses the held connection (a read helper inside a write transaction sees its
  uncommitted rows); requesting write access while holding a read-only
  connection raises immediately. Hot read helpers converted (monitoring polls/
  alerts/summary/rules/suppressions, inventory groups/hosts, topology links/
  interface stats, `query_interface_ts_multi`); the rest can migrate
  incrementally. Tests: `tests/test_sqlite_read_pool.py`. Removed 2026-10-09
  with the SQLite engine (`APP_SQLITE_READ_POOL` and its test are gone).
- [x] **Route-table poll cadence** — `_ssh_poll` now parses `show ip route
  summary` (IOS + NX-OS formats) every tick and only pulls the full
  `show ip route` when the summary count changes or
  `route_full_interval_seconds` (default 900; 0 = legacy every-tick) elapses.
  `route_count` prefers the summary total; churn hashing/snapshots happen on
  full ticks only. Equal-count table changes are caught at most one full
  interval late — accepted tradeoff.
- [x] **Adaptive backoff/jitter for dead hosts** — polls that raise/time out
  (which never produced a poll row or availability transition anyway) back off
  exponentially: retry next cycle after the 1st failure, then skip 1/2/4/8
  (capped) cycles; any success or a manual `force` poll resets. The poll-loop
  sleep gained 0–5% positive jitter to de-phase the background loops.
- [x] **Batch the bulk drift-accept reads** — `bulk_accept_drift_events` now
  loads all events (`get_config_drift_events_by_ids`) and snapshots
  (`get_config_snapshots_by_ids`) in two `IN (...)` queries and drops the
  per-event `get_host` (the event join already carries hostname); per-event
  baseline/status/history writes unchanged.
- [x] **Regex config-backup search pre-filter** — `_regex_required_literal()`
  derives a literal every match must contain; the SQLite regex branch
  pre-filters with `instr()` (Postgres additionally with `POSITION`) instead of
  loading every blob. Patterns with no ≥3-char required literal are rejected
  with a 400 (`regex_needs_literal`) pointing at substring/fulltext mode.
- [x] **`get_monitoring_poll_history` blob gate** — lean column list by default
  with an opt-in `include_details` flag (capped at 500 rows), plumbed through
  `/api/monitoring/polls/{host_id}/history`; the device-detail page opts in for
  the latest poll's `if_details`, history tables stay lean.

### Batch 6 - The Big One

- [x] **Split `routes/database.py` (16,795 lines) into domain modules** (hosts, credentials, monitoring, audit, mac-tracking, lab, etc.) while preserving the `routes.database` API surface. *Prerequisite: batches 1 and 4 - the suite must be green and fast before a refactor this wide.* Done 2026-06: core (connection singleton, pragmas, schema, init_db) stays in `routes/database.py` (~2,800 lines); 20 domain modules live in `routes/db/*` and are star re-exported through the facade, so all `import routes.database as db` callsites and test monkeypatches (`DB_PATH`, `DB_ENGINE`, `get_db`) work unchanged — moved code reads those names late-bound via the facade. Public API surface verified byte-identical (606 names) against a pre-split snapshot.

## UI Spacing & UX Audit (2026-11-09)

### Batch 1 - Missing or broken CSS (fix once, affects every page)

- [x] **H: Define the classes the TSX uses but `style.css` never declares** — `text-muted` (~580 uses), `input`, `table` / `table-sm`, `glass-card` (44), `card-body` (17), `skeleton-loader` (8), `badge-sm`, `btn-xs`, `badge-muted`, `text-danger`, `spinner`, `form-help`, `btn-link`, `drift-summary-card*`, `status-completed`, `.btn.active`, and a global `form-select-sm`. Today muted text renders at full colour, some inputs and tables are raw browser controls, loading skeletons are blank gaps, and the "Completed" job badge has no colour. Either define each class or switch the callers to the existing one (`form-input`, `data-table`, `btn-sm`, `badge-secondary`, `skeleton`).
- [x] **H: Add a disabled style for controls** — no `:disabled` rule exists for `.btn`, `.form-input`, `.form-select` or `.page-tab-btn`; 249 `disabled=` props look enabled and disabled primary buttons still lift and glow on hover. Remove the 17 inline opacity patches afterwards.
- [x] **H: Stop freezing progress indicators** — `lib/appearance.ts:93` always adds `reduced-motion` to `body`, and `style.css:3854` then freezes every spinner, skeleton shimmer and running-status pulse, so loading looks hung. Exempt progress indicators or apply the class only on user/OS request.
- [x] **M: Opaque cards under `reduced-motion`** — the same class strips card blur (`style.css:3884`) while cards keep 25-55% alpha, so the Astral image and Matrix rain show sharply through cards and tables.
- [x] **M: Add `button, input, select, textarea { font: inherit }`** — `.btn` renders in the system font while the rest of the UI uses JetBrains Mono (visible in TimeRangeBar, ExportMenu, Login "Register").
- [x] **H: Template cards render browser-default button text** — `pages/GraphTemplates/GraphTemplatesTab.tsx:62` uses `<button className="card">` with no colour/font reset and `border: none`; dark text on dark cards.
- [x] **M: Declare `color-scheme` per theme** — native date/time pickers and select popups stay light on dark themes.
- [x] **M: Fix themed rules that never apply** — sidebar active-link glows (`style.css:345,432,592,751,1009` lose to `:1572`), Voyager nav pills (`:741`), Voyager/Sandstone sidebar and login backgrounds (wiped by `:3870`), Voyager/Matrix title colours (`:793`, `:1016`).
- [x] **L: Remove dead and duplicate CSS** — about 150 of 425 classes are unreferenced by React (command palette, toast, stepper, `sla-*`, `credential-card`, `confirm-modal`, `#job-output-modal`); `@keyframes pulse-dot` is defined twice (`style.css:2653`, `:3416`); 68 `!important`. *Done 2026-11: 255 dead rules (177 class and id names, ~1,450 lines) and the duplicate keyframes removed; `!important` only dropped 68 to 64, the rest sit in the performance-mode and print blocks. `glass-card` and `card-body` stay as unstyled hooks.*

### Batch 2 - Spacing system

- [x] **M: Introduce spacing, radius and font-size tokens** — only colour tokens exist. `style.css` has 55 distinct paddings, 27 radii and 34 font sizes; the TSX has 2,925 inline styles with 69 distinct paddings. Card padding varies 0.75 / 1 / 1.25 / 1.5 / 2rem for the same surface. Move the primitives onto the tokens first. *Done 2026-11: `--space-*`, `--radius-*`, `--text-*`, `--control-h*` and `--card-pad*` on `:root`; every on-scale literal in `style.css` and the primitives (card, button, form, tabs, page header, time range) use them, and near-scale font sizes were snapped. Card padding is 1rem (`card-sm` 0.75rem). Off-scale literals in `style.css` and the inline styles on lines this batch did not touch remain.*
- [x] **M: One page-title and page-header pattern** — `.page h2` (`style.css:1872`, 2rem gradient) only applies on Monitoring, Jobs, NetworkTools, Software and CloudVisibility, where the title margin plus `.page-header` margin leave about 4rem. Other pages use a plain h2 with an inline 0.75rem gap; DeviceDetail and DashboardViewer use 1.25rem. *Done 2026-11: shared `<PageHeader>` renders `.page-header` + `h2.page-title` (1.5rem gradient, 1rem gap below) on every page; headings inside tabs are `h3`. Change Management gained a title.*
- [x] **M: Remove `margin-bottom` from `.card`** — `style.css:1960` stacks on grid/flex `gap`, so rows sit 1.5-2rem apart while columns sit 0.5-1rem. Drop the 29 inline `marginBottom: 0` patches afterwards. *Done 2026-11: parents set the rhythm with `.stack` / `.stack-sm` or a grid gap; the inline patches are gone.*
- [x] **M: Remove cards nested in cards** — double border, padding and hover glow on Settings, Configuration, Compliance, Upgrades, Reports, DeviceDetail, Traffic Analysis and Monitoring Configure. *Done 2026-11: outer wrappers became plain stacks or inner blocks became `.card-inset`.*
- [x] **M: Hover glow only on clickable cards** — `.card:hover` / `.stat-card:hover` (`style.css:1967`, `:1915`) make static panels look clickable; `.card-clickable` exists and is unused. *Done 2026-11: the glow lives on `.card-clickable`, set on cards that are links, buttons or have a click handler.*
- [x] **M: Standard control heights with small variants** — inputs/selects ~36px, tabs ~34px, `btn-sm` ~31px, time-range ~28px. Add `.form-input-sm` / `.form-select-sm` and use them in the Topology, Configuration, Inventory, Compliance and Software toolbars. *Done 2026-11: 36px for buttons, inputs, selects and page tabs; 30px for `btn-sm`, `form-input-sm`, `form-select-sm`, small tabs and time-range buttons.*
- [x] **H: Selects take a full row in wrapping toolbars** *(verify in browser)* — `.form-select { width: 100% }` (`style.css:2233`) inside flex-wrap toolbars: `pages/Jobs/JobsTab.tsx:76`, `pages/Monitoring/AlertsTab.tsx:73`, `AvailabilityTab.tsx:44`, `CapacityTab.tsx:28`, `SlaTab.tsx:32`, `TopologyAvailabilityPanel.tsx:80`. Add a toolbar select variant or use `.list-controls`. *Done 2026-11: `.toolbar` rows size inputs and selects to their content (also in `.page-header` and the TabBar trailing slot). Not yet checked in a browser.*

### Batch 3 - Shared primitives built several ways

- [x] **M: One stat tile component** — five or more designs across Monitoring (four of them), Dashboard, Software, Billing, the summary strip copied in Compliance / Deployments / RiskAnalysis, and the unstyled CloudVisibility cards. *Partly done 2026-11: `StatTile` / `StatGrid` (`components/StatTile.tsx`) now render the Monitoring, CloudVisibility, Billing, IPAM drilldown and MAC tracking tiles and the summary strip. Still on their own markup: Dashboard (`HealthSection`, `ResponseTimePanel`, `StatRings`) and the Software, Federation and IPAM overview tiles.*
- [x] **M: One table style** — `.data-table`, `.chart-table`, `.device-health-table`, about 20 unclassed tables with inline `4px 8px` cells, and a div-grid table in `pages/Monitoring/SlaTab.tsx:176`. Row height ranges 29-37px. Standardise on `.data-table` plus a compact modifier. *Done 2026-11: every table is `.data-table` (`.table-sm` dense, `.table-sticky`), inline cell padding and row borders removed, the SLA grid is a real table, `.chart-table` / `.device-health-table` deleted.*
- [x] **M: One badge style** — `.badge`, `.status-badge`, `.alert-severity-badge`, `.tab-bar-badge`, `.topology-change-badge`, plus solid inline badges in Deployments, Monitoring Alerts/Rules and the NetFlow tab. *Partly done 2026-11: `Badge` / `SeverityBadge` / `StatusBadge` (`components/Badge.tsx`) replace `.status-badge`, `.alert-severity-badge`, `.badge-error` and the solid inline badges. `.tab-bar-badge` and `.topology-change-badge` (count bubbles) are untouched.*
- [x] **H: One severity colour map** — Compliance profiles show medium and low as green (`pages/Compliance/Compliance.tsx:349`); RiskAnalysis maps medium and high both to amber (`pages/RiskAnalysis/helpers.ts:3`); Monitoring maps info to primary while Dashboard uses info (`pages/Monitoring/helpers.ts:26`). *Done 2026-11: `lib/severity.ts` is the only map (critical solid red, high red, medium amber, low info, info neutral); page-local maps removed.*
- [x] **M: Compliance status colours reversed between scanners** — host scans show non-compliant amber and error red (`pages/Compliance/Compliance.tsx:651`); Meraki scans show the opposite (`merakiHelpers.ts:12`). *Done 2026-11: both use `complianceStatusTone` (compliant green, non-compliant red, error amber).*
- [x] **M: One delete button style and label** — plain button with red text, ghost, `btn-danger` and `btn-xs` are all in use; label is "Del" in Inventory, Federation and Topology Sources. *Done 2026-11: `DeleteButton` everywhere a button deletes; label is always "Delete".*
- [x] **M: One callout, loading and empty-state component** — five banner styles; loading is a spinner, `.loading`, skeletons or one of 86 bare "Loading…" strings; empty is `.empty-state` (42) or one of 21 bare lines. *Partly done 2026-11: `Callout`, `LoadingState` and `EmptyState` replace the `.error` banners, red paragraphs, bare "Loading…" lines and bare "No …" lines. Still to do: skeleton placeholders, and field-level red `div`/`span` messages.*
- [x] **M: One date/time formatter** — at least five formats and several local helpers. Some parse zone-less timestamps as local and others as UTC, so the same event can show different times (Jobs, Federation, Maintenance, Monitoring Events; Reports History needs the backend format checked). Use `lib/datetime.ts` everywhere; also consolidate the uptime formatters. *Partly done 2026-11: all page-local date formatters removed in favour of `lib/datetime.ts`; backend format checked (UTC everywhere). Still to do: the uptime/duration formatters.*
- [x] **L: One progress bar component** — four hand-written styles (`pages/Upgrades/CampaignsTab.tsx:260`, `NewImageModal.tsx:72`, `CampaignViewerModal.tsx:96`, `pages/RiskAnalysis/RiskAnalysis.tsx:317`).

### Batch 4 - Modals and dialogs

- [x] **M: Sticky modal header and footer** — `.modal` is the scroll container (`style.css:2425`), so the title and × scroll away; footers are 98 hand-built inline rows at the end of the body. Make `.modal-body` scroll and add a `footer` slot to `components/Modal.tsx`. *Done 2026-11: `.modal` is a flex column, `.modal-body` scrolls, and `Modal` has a `footer` prop (`.modal-footer`); every modal's closing action row moved into it (submit buttons use `form={id}`). Audit's two hand-rolled overlays now use `Modal`.*
- [x] **M: One button order** — Cancel then primary, right-aligned; today the order and the Cancel style (`btn-secondary`, `btn-ghost`, plain) vary per modal. *Done 2026-11: every modal footer is Cancel/Close (`btn-secondary`), secondary actions, primary last; the three local `ModalActions` copies became `components/ModalActions.tsx`. Rule recorded in `FRONTEND_STYLE.md`.*
- [x] **M: Add medium and small modal sizes** — `size="large"` is 1600px and used for simple forms; the 700px default is used for wide tables and one-line confirms. *Done 2026-11: `small` 480px and `medium` 1000px added; every `size` re-evaluated (`large` uses 39 → 14, all wide tables, diffs or log viewers).*
- [x] **M: Backdrop close and focus handling** — `components/Modal.tsx:67` closes when a text-selection drag ends on the backdrop; no focus trap, initial focus or focus restore. *Done 2026-11: backdrop closes only when press and release both land on it; focus moves in on open, Tab is trapped in the topmost modal, focus returns on close (`components/modalFocus.ts`, unit tested).*
- [x] **M: Specific confirmations** — callers rely on the "Please confirm" / "Confirm" defaults (`components/DialogProvider.tsx:71`) and never name the object; cancel dialogs pair "Cancel" with "Cancel reload" (`pages/Upgrades/CampaignViewerModal.tsx:1185`). *Done 2026-11: `confirm()` no longer takes a bare string and `title` / `confirmLabel` are required, so the "Please confirm" / "Confirm" defaults are gone; all 63 calls name the action and object. Cancel confirmations use "Keep running" / "Keep reload" style labels.*
- [x] **M: Inline validation instead of `alert()`** — Inventory, Jobs, Deployments, RiskAnalysis, GraphTemplates, Backup policy. Multi-line messages lose their line breaks in `AlertDialog` / `ConfirmDialog`. *Done 2026-11: `FieldError` + `aria-invalid` for field problems and `Callout` for failed saves across the form modals (all the listed pages plus Ipam, Monitoring, Reports, Software, Upgrades, Topology, Audit); `alert()` remains for row and background action results. Alert/confirm messages keep line breaks (`.dialog-message`).*
- [x] **M: Hide the × on the forced password-change modal** — `components/ChangePasswordModal.tsx:59` makes close a no-op but the × still renders. *Done 2026-11: `Modal` has `dismissible`; the forced modal passes `dismissible={false}` (no ×, Escape or backdrop close).*

### Batch 5 - States

- [x] **H: Failed requests shown as empty or endless loading** — Settings forms check `isLoading || !draft` before `isError` (seven places, e.g. `pages/Settings/AuthTab.tsx:73`); also Monitoring Availability/SLA, Compliance tabs, Configuration Backups, IPAM overview and drilldown, FloorPlan sites, Software overview, Billing summary. *Done 2026-11: `QueryError` (`components/QueryError.tsx`, with Retry) is checked before loading and empty states on every listed page and the rest of Settings, Monitoring, Network Tools, Jobs, Topology, Compliance, Configuration, Audit, Risk Analysis, Deployments, IPAM, Inventory, Floor Plans, Software, Reports and Cloud Visibility; it replaces content only when nothing is cached. Edit forms and sync-settings forms whose load failed are no longer rendered with blanks or defaults. Not swept: Dashboard, DeviceDetail, Upgrades, GraphTemplates, Federation, MaintenanceWindows, Lab; the Topology side panels (`NodeDetails` and siblings) keep their compact red line.*
- [x] **M: Busy state on async buttons** — double-click fires twice on Jobs Retry/Cancel, IPAM Push/Accept, Compliance Assign, Alerts Acknowledge, Notification/SIEM Test. A shared pending flag disables every row at once on Compliance Scan, IPAM Sync, Cloud Discover and Audit Run now. *Done 2026-11: `BusyButton` (`components/BusyButton.tsx`) and per-row state from `usePendingKeys` (`lib/usePendingKeys.ts`) on all of the above and the other row actions on the swept pages; `ModalActions` takes `primaryBusy`.*
- [x] **M: Confirm destructive and bulk actions** — Drift Accept All / Resolve All, Monitoring Acknowledge All, MAC Acknowledge all, Discovery "remove hosts not found", IPAM Push to IPAM, Jobs live Launch, Topology Reset Positions, RiskAnalysis and Deployment Approve. *Done 2026-11: all listed, each with a count where one exists; also Drift Accept Group, Topology changes / STP Acknowledge All, Topology Collect All and advisory import.*

### Batch 6 - Accessibility

- [x] **M: Link labels to inputs** — about 300 `form-label` elements have no `htmlFor`; toolbar search and filter inputs have no label. *Done 2026-11: every `form-label` is linked with `useId` ids or titles a `role="group"`; toolbar searches, filters and row checkboxes carry an `aria-label`.*
- [x] **M: Keyboard access for clickable rows** — Inventory group headers, Audit rows and categories, SLA host rows, FloorPlan site/floor rows, Campaign viewer rows. *Done 2026-11: all listed plus Lab rows, through `clickableProps` in `lib/clickable.ts`.*
- [x] **M: `aria-label` on icon-only buttons and 28px minimum targets** — help toggle 18×22, kebab 23, `segmented-xs` 24, DeviceDetail Ack/Resolve ~20, IPAM ✕ ~20. *Done 2026-11: `--target-min` on `btn-xs`, `segmented-xs`, kebab and help toggle. Still under 28px: clickable `.badge` chips (Audit filters, Topology warnings) and FloorPlan floor rows (~25px).*
- [x] **M: Visible focus** — menu keyboard focus contrast is about 1.1 (`style.css:5573`); add a shared `:focus-visible` ring.
- [x] **M: Remove `aria-live` from `<main>`** — `App.tsx:192` re-announces every poll.
- [x] **M: User-menu role chip contrast** — 1.2-3.4 in every theme (`components/UserMenu.tsx:62`).

### Shell

- [x] **H: Collapsed sidebar hides all grouped pages** — only Dashboard and Settings stay reachable (`style.css:1648`); icons have no tooltip and the state is not persisted (`components/Sidebar.tsx:279`, `:347`).
- [x] **H: Add `min-width: 0` to `.main-content`** — any wide table makes the whole page scroll sideways (`style.css:1722`). 99 tables, about 26 overflow wrappers; add a shared `.table-scroll`.
- [x] **H: Login form width** *(verify in browser)* — `.login-card` uses `align-items: center` (`style.css:1295`), so the form in `pages/Login/Login.tsx:83` shrinks to its content.
- [x] **H: Mobile drawer closes when a nav group is tapped** — `components/Sidebar.tsx:379`.
- [x] **M: Breadcrumb bar repeats the page title** — single unlinked label (`App.tsx:85`); with the time-range bar the Dashboard opens with three header bands.
- [x] **L: Breakpoints at 1024/1280** — auto-collapse the sidebar and reduce page padding at ≤1100px.
- [x] **L: Sidebar labels clip without ellipsis or tooltip** (`style.css:1590`).
- [x] **L: Theme flash on load and missing favicon** — theme is set after first paint (`main.tsx:12`).
- [x] **L: Login shows "Register" regardless of the server setting** (`pages/Login/Login.tsx:22`).

### Dashboard

- [x] **H: "Overall Health" sits alone in a two-column grid** — `pages/Dashboard/OverviewPanels.tsx:19`, `style.css:5043`.
- [x] **H: Custom panel "Height (rows)" has almost no effect** — charts are fixed at 240px (`pages/Dashboard/Panel.tsx:70`, `lib/echart.tsx:35`).
- [x] **M: Panels jump height** between skeleton (80px), empty and loaded states (`Dashboard.tsx:40`, `BandwidthTrendPanel.tsx:47`, `TopTalkersPanel.tsx:50`, `BackupStatusPanel.tsx:63`).
- [x] **M: One health label map** — Good/Bad, Healthy/Critical, warn/down and "?" are all in use (`OverviewPanels.tsx:9`, `DevicesGridPanel.tsx:9`, `HealthSection.tsx:91`, `GroupHealthPanel.tsx:169`).
- [x] **M: Same device-health counts shown four times**; rings sit far down the page (`Dashboard.tsx:110`).
- [x] **M: Two section-heading styles on one page** (`HealthSection.tsx:32`, `AlertsSection.tsx:23`).
- [x] **M: Busiest Interfaces tooltip shows raw bps; legend wraps over the plot** (`lib/echart.tsx:111`).
- [x] **M: Empty custom panels draw blank axes; error is muted text** (`Panel.tsx:126`).
- [x] **M: Viewer toolbar mixes button sizes and duplicates Refresh** (`DashboardViewer.tsx:135`).
- [x] **L: Charts resize only on window resize** — use a `ResizeObserver` (`lib/echart.tsx:73`).
- [x] **L: Hosts/Playbooks/Jobs rings are scaled against each other** (`StatRings.tsx:100`).

### Monitoring

- [x] **M: Availability tab is two stacked dashboards** with different table styles; host Transitions ignore the filters; "Currently Down" is red at 0 (`pages/Monitoring/AvailabilityTab.tsx:31`).
- [x] **M: Capacity chart** — threshold always "80%" even for count metrics; no tooltip or units (`CapacityTab.tsx:21`).
- [x] **M: Move the Capacity and SLA SVG charts onto the shared chart component** (`CapacityTab.tsx:113`, `SlaTab.tsx:254`).
- [x] **M: Alert Rules cannot be edited**; disabled rules fade the Enable button too (`RulesTab.tsx:66`).
- [x] **M: OID Profiles vendor dropdown collapses to the selected vendor** (`OidProfilesTab.tsx:22`).
- [x] **M: Events tab** — empty state says "syslog" when SNMP Trap is selected; truncated messages have no tooltip; no overflow wrapper (`EventsTab.tsx:83`).

### DeviceDetail

- [x] **H: Interfaces tab fixed two-column tables overflow at 1280 and 1024** (`pages/DeviceDetail/InterfaceTab.tsx:162`).
- [x] **M: Overview charts have no loading or empty state** (`DeviceDetail.tsx:403`).
- [x] **M: Flow charts show raw bytes; rotated labels squash the Top Interfaces chart** (`FlowTab.tsx:195`, `InterfaceTab.tsx:151`).
- [x] **M: Help text promises an interface drill-down that does not exist; two help banners stacked** (`DeviceDetail.tsx:46`).

### GraphTemplates

- [x] **M: Templates, tree nodes and host-template assignments can be created but not edited or completed** (`pages/GraphTemplates/GraphTemplateDetailModal.tsx:69`, `GraphTreeDetailModal.tsx:62`, `HostTemplateModal.tsx:81`). *Done 2026-11: graph templates have an edit form and add/edit/delete for data series (built-ins stay read-only); host templates assign graph templates from a checklist; tree nodes can be edited, deleted, nested and pointed at a host or host graph. The item and node routes now check the parent template/tree, refuse built-in templates and reject parent cycles.*

### Topology

- [x] **H: MAC/IP/VLAN result tables are unstyled** — five columns in a 380px panel (`pages/Topology/TopologySearchPanel.tsx:245`, `:281`).
- [x] **H: Floating panels overlap and cover the map at 1024** *(verify in browser)* — search 380px, node details 380-460px, edge details fixed 480px (`TopologySearchPanel.tsx:131`, `NodeDetails.tsx:204`, `EdgeDetails.tsx:36`).
- [x] **M: Map height ignores what is stacked above it** — `calc(100vh - 280px)` (`Topology.tsx:2332`); the Path card is unbounded and pushes the map off screen; flash messages shift the toolbar.
- [x] **M: Toolbar overloaded** — 12 controls in one wrapping row, primary button mid-row, two search entry points, toggle labels change width (`Topology.tsx:1924`).
- [x] **M: Search dropdown likely painted under the map panels** *(verify in browser)* (`Topology.tsx:1973`).
- [x] **M: Add on-canvas zoom/fit controls** (`Topology.tsx:929`).
- [x] **M: Legend reuses colours for different meanings and draws link types as dots** (`Topology.tsx:2391`).
- [x] **M: NodeDetails uses its own ~22px tab bar instead of the shared `TabBar`** (`NodeDetails.tsx:358`).
- [x] **M: STP chip is always green, even when blocking** (`NodeDetails.tsx:593`).
- [x] **M: Reachability verdict filter shows no active state** (`Reachability.tsx:466`).
- [x] **M: Reachability renders up to 20,000 rows unpaginated** (`Reachability.tsx:659`).
- [x] **M: Reachability form has ~25 always-visible controls and 170-word help**; Sources multi-select needs Ctrl+click (`Reachability.tsx:176`, `SweepFilterFields.tsx:43`).

### CloudVisibility

- [x] **H: Summary stat cards are unstyled on the Topology, Flow and Traffic tabs** (`pages/CloudVisibility/TopologyTab.tsx:484`, `FlowTab.tsx:222`, `TrafficTab.tsx:214`). *Done 2026-11: all three use `StatGrid` / `StatTile`.*
- [x] **M: Half a screen of header before content**; the account filter shows on tabs that ignore it (`CloudVisibility.tsx:89`). *Done 2026-11: header is title, banner, tab bar and one help line; the provider/account filters sit in the TabBar trailing slot and the account filter is hidden on Accounts; provider capability cards became a badge row on the Accounts tab.*
- [x] **M: Form labels touch their inputs; Title Case labels with units in the name** (`SyncControls.tsx:56`, `FlowTab.tsx:72`, `AccountsTab.tsx:488`). *Done 2026-11: `form-group` / `form-label` with `useId` ids and sentence case on the Flow, Traffic, Policy and Topology filters, the sync settings and the account form; units are a suffix ("Interval (seconds)").*
- [x] **M: Flow/Traffic sync panel sits between the filters and the data; timelines render up to 10,080 table rows** (`FlowTab.tsx:102`, `:198`). *Done 2026-11: order is filters, summary, timeline, top list, sync section; timelines are a `TimeSeriesChart` (flow bytes, traffic total); the two tabs share `analytics.ts` / `AnalyticsParts.tsx` and `lib/useFlashMessage.ts`.*
- [x] **M: Policy tab shows Loading and empty together** (`PolicyTab.tsx:111`). *Done 2026-11: error, loading and empty are separate states with accurate messages; filters and drilldown no longer reload the views table.*
- [x] **M: Policy tables squeezed side by side; rules silently capped at 200; route-path tables overflow 320px cards** (`PolicyTab.tsx:38`, `:108`, `TopologyTab.tsx:344`). *Done 2026-11: tables stacked full width; rules load up to the API maximum of 2,000, render 200 at a time and show a callout when truncated (the API returns no total); route-path cards are full width with a scroll wrapper.*
- [x] **L: Accounts tab** — three primary "Add" buttons; nine-column table scrolls at 1280 (`AccountsTab.tsx:154`, `:199`). *Done 2026-11: one "Add cloud account" button; six columns. Not yet checked in a browser.*

### Settings

- [x] **M: Unsaved changes are lost silently on tab switch; the save model is mixed without signalling** (`pages/Settings/Settings.tsx:212`).
- [x] **M: 12-tab bar wraps to two rows at 1280** (`Settings.tsx:86`).
- [x] **M: Tab help describes features that do not exist** — density, SAML, password policy, log level (`Settings.tsx:35`).
- [x] **M: Same introduction shown up to four times per tab** (`Settings.tsx:201`, `NotificationsTab.tsx:295`, `SiemTab.tsx:150`).
- [x] **M: Auth and Discovery field alignment** — checkbox rows touch the next label or sit ~1rem above inputs; Notifications/SIEM patch with `marginTop: 1.4rem` (`AuthTab.tsx:731`, `DiscoveryTab.tsx:79`, `NotificationsTab.tsx:490`).
- [x] **M: Notifications, SIEM and Service Credentials tables** — unstyled tables, full-size row buttons, editors open below the table out of view, Test gives no feedback (`AuthTab.tsx:909`, `NotificationsTab.tsx:309`, `:409`, `SiemTab.tsx:160`, `:236`).

### Federation, Maintenance Windows, Network Tools

- [x] **H: Maintenance modal fields are unstyled** (`pages/MaintenanceWindows/MaintenanceWindowModal.tsx:164`). *Done 2026-11: fields use `.form-group` / `.form-label` / `.form-row` / `.form-check` / `.form-help` with linked labels, in a real `<form>` submitted from the footer.*
- [x] **M: Maintenance edit modal shows stale or blank data while loading, with Save enabled** (`MaintenanceWindowModal.tsx:70`). *Done 2026-11: the form mounts only after its window has loaded (spinner or `QueryError` until then, Save disabled), is seeded once per open, and the single-window query is not cached between opens.*
- [x] **M: Maintenance table is hand-built; state shown as lowercase text; own h2 under the tab bar** (`MaintenanceWindows.tsx:75`, `:117`). *Done 2026-11: heading removed (`.toolbar` with the New Window button), state and policy are `Badge`s, list load failure uses `QueryError`.*
- [x] **L: Nested scrollbars in the MAC history modals** (`MacTracking.tsx:906`, `:1046`). *Done 2026-11: the move-event log and MAC history bodies dropped their own height caps; the modal body is the only vertical scroller.*
- [x] **L: Traffic Analysis** — own range select instead of the shared time bar; sub-tab not in the URL (`TrafficAnalysis.tsx:68`, `:103`). *Done 2026-11: the view is in the path (`/network-tools/traffic/<view>`) through a nested `usePathTab`; the range select is gone, the shell's time bar shows on the tab and the window is clamped to 7d with `ClampedRangeHint` (`FLOW_RANGES` now shared from `api/networkTools.ts`).*

### Configuration

- [x] **M: Drift bulk actions fire n separate mutations with no error handling; two primary buttons in the toolbar** (`DriftTab.tsx:118`). *Done 2026-11: Resolve All is one `POST /api/config-drift/events/bulk-resolve` (shares `_bulk_close_drift_events` with bulk-accept); failures show an error dialog; Set Baseline is the only primary button in the toolbar.*
- [x] **M: "View Diff" expands inline in one view and opens a modal in the other**; ghost buttons with zero padding (`DriftTab.tsx:330`, `:502`). *Done 2026-11: every drift card expands its diff in place through one `DiffToggle` (`btn-secondary`); `DriftDiffModal` removed, its actions were already in the card menu.*
- [x] **M: Config viewers sized 480 / 400 / 220px**; a 400px diff inside a 1600px modal; search snippet margin bug (`BackupModal.tsx:70`, `UnifiedDiff.tsx:14`, `SearchTab.tsx:265`). *Done 2026-11: the config view, diffs and search snippets all take their size from `.drift-diff-viewer` (60vh on a page, the space left in the dialog in a modal); the snippet top margin applies.*
- [x] **M: Silent no-op submits** (`BackupPolicyModal.tsx:113`, `SetBaselineModal.tsx:62`, `CaptureSnapshotModal.tsx:39`). *Done 2026-11: each early return now sets a `FieldError` (group, credential, host, configuration); an empty latest snapshot is reported too.*
- [x] **L: Backups and drift events render as unbounded card lists** (`BackupsTab.tsx:350`, `DriftTab.tsx:159`). *Done 2026-11: both lists render 50 cards and grow through `useShowMore`; the five copies of the "Show more" button became `components/ShowMoreButton.tsx`.*

### IPAM

- [x] **M: Drilldown stat values overflow on large subnets; no thousands separators** (`SubnetDrilldown.tsx:53`). *Done 2026-11: every address count on the page goes through `lib/formatCount.ts` (thousands separators; scientific notation from 1e15, so an IPv6 /64 fits a tile). CloudVisibility uses the same helper.*
- [x] **M: Selected subnet is nearly invisible; the drilldown panel is not scrolled into view** (`Ipam.tsx:299`, `:416`). *Done 2026-11: the selected row uses the new `.data-table tr.row-selected` (primary tint and a left bar) with `aria-current`; its button reads "Selected"; the drilldown card scrolls into view when its top is off screen.*
- [x] **M: Inline button sizes instead of `btn-sm`; four primary buttons on the page** (`Ipam.tsx:917`, `:1101`). *Done 2026-11: every card and row button is `btn-sm` (drift row buttons sit in `.table-actions`); "+ Define Subnet" is the only primary button outside a form.*
- [x] **L: Inline drilldown forms reverse the button order** (`SubnetDrilldown.tsx:306`). *Done 2026-11: Cancel, then the primary action, right-aligned like a modal footer.*

### Upgrades and Software

- [x] **H: Software two-column grid has no breakpoint** *(verify in browser)* — the devices table gets ~350px at 1024 (`pages/Software/Software.tsx:330`).
- [x] **M: Software toolbar is crowded**; labels sit on the select bottom edge; full-size buttons (`Software.tsx:204`).
- [x] **M: Campaign viewer ordering** — history before actions, selection controls after the buttons they affect (`pages/Upgrades/CampaignViewerModal.tsx:833`, `:963`).

### Compliance, Deployments, RiskAnalysis, Reports

- [x] **M: Compliance scans run synchronously with only "Scanning…"; Fix All shows no progress** (`pages/Compliance/RunScanModal.tsx:187`, `FindingsModal.tsx:128`). *Done 2026-11: `POST /api/compliance/scan-bulk` and an assignment's `scan-now` return `202 {job_id}` and run on the shared `background_jobs` registry (one runner for both); `GET /api/compliance/scans/{job_id}` reports hosts done of total, violations and errors. `HostScanProgress` shows that with a `ProgressBar` in the Run Scan dialog and above the Assignments list (the job poll hook is shared with Meraki scans). Fix All shows "Fixing i of N: rule" with a bar and a running tally; Fix buttons are busy per rule. The single-host scan stays synchronous.*
- [x] **M: Up to 500 rows rendered as stacked cards with no sorting** (`Compliance.tsx:650`, `MerakiTab.tsx:339`). *Done 2026-11: host Scan Results / Host Status and Meraki Target Status / Scan Results are compact sticky-header `DataTable`s with click-to-sort headers (new shared `lib/useTableSort.ts` and `components/SortableTh.tsx`, `aria-sort` on the cell) and `useShowMore`. Results default to newest first, status lists to worst status first.*
- [x] **L: Two findings tables styled differently; second tab bar inside the Meraki tab; rules line not clamped; kind labels duplicated** (`FindingsModal.tsx:214`, `MerakiFindingsModal.tsx:43`, `MerakiTab.tsx:22`, `:62`). *Done 2026-11: both findings modals use `DataTable`, the shared `FindingResultCell`, the same sizes and a Close footer; the Meraki views are a `SegmentedControl` in a `.toolbar`; the profile rules line clamps to two lines (`.line-clamp-2`, full list in `title`); kind labels live in `merakiHelpers.ts`; `formatInterval` has one copy in `lib/datetime.ts`.*
