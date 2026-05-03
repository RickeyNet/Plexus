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
- [ ] Add maintenance windows and approval gates for production changes.
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
- [x] Add baseline deviation alerting (statistical learning, not just static thresholds).

### Later (Enterprise and Ecosystem)
- [ ] Add firmware/OS lifecycle management with staged upgrade workflows.
- [ ] Add multi-vendor adapter framework with pluggable device drivers.
- [x] Add enterprise auth (LDAP/AD with auto-provisioning, group-to-role mapping, and local fallback).
- [ ] Add secrets vault integrations (Vault/Azure Key Vault/AWS Secrets Manager) with rotation.
- [ ] Add multi-tenant boundaries (tenant isolation, quotas, delegated admin).
- [ ] Add ITSM integrations (ServiceNow/Jira) for change ticket linkage.
- [ ] Add outbound/inbound event integrations (Slack/Teams/PagerDuty/webhooks).
- [ ] Add scheduled report builder (operator + executive reports in PDF/CSV/email).
- [ ] Version and publish API contracts (OpenAPI, deprecation policy, compatibility tests).
- [ ] Create a plugin SDK for custom validators and integrations.
- [x] Add digital twin/lab mode for safe pre-production change testing.
  - [x] Phase A — config-plane simulator: lab environments + cloned-from-host devices, simulate proposed commands against snapshot, diff + risk score, persist run history, promote successful run to a Deployment record. Migration 0029. React UI at `/frontend/lab`. 6-test coverage (`tests/test_lab.py`).
  - [x] Phase B-1 — containerlab single-node runtime: per-twin Docker-backed virtual device (Arista cEOS, Nokia SR Linux, FRR, Linux, etc.), `/api/lab/runtime` availability probe, deploy/destroy/refresh endpoints, live-mode `simulate-live` that pushes commands via Netmiko and captures the real running-config back into the twin's snapshot. Append-only `lab_runtime_events` audit log. Migration 0030. Strict allowlist for node kinds and image regex; subprocess invoked with explicit argv (no shell). React UI gains a Runtime card with deploy form, status badge, refresh/destroy buttons, runtime event log, and a live-mode toggle on the simulate form. 14-test coverage (`tests/test_lab_runtime.py`).
  - [x] Phase B-1 hardening: compliance impact scoring on both Phase A and live simulate paths (when the lab device is cloned from a host with assigned profiles); startup reconciliation against `containerlab inspect` so stale "running" rows after a Plexus restart flip to "stopped"; idle TTL reaper background loop (`PLEXUS_LAB_RUNTIME_TTL_SECONDS`, default 24h, set to 0 to disable) with `PLEXUS_LAB_RUNTIME_TTL_INTERVAL_SECONDS` for check cadence; per-device topology workdir removed on successful destroy. 6 additional tests covering compliance, reconcile (active + skipped), TTL reap (active + disabled), and workdir cleanup.
  - [x] Phase B-2 — multi-device topology: new `lab_topologies` and `lab_topology_links` tables (migration 0031) plus a `lab_devices.topology_id` FK so a twin is either free-standing or a topology member (mutually exclusive at deploy time). New `netcontrol/routes/lab_topology.py` adds CRUD for topologies/members/links, a multi-node containerlab YAML generator (handles `mgmt_subnet`, `nodes`, `links`), and topology-level `deploy`/`destroy`/`refresh` endpoints that drive every member through one `containerlab deploy`. Endpoint names validated against an allowlisted regex; image/kind validation reuses Phase B-1 rules. React Lab page gains a "Topologies (multi-device)" card with create/list/delete, a per-topology editor for adding members from the existing devices list, link CRUD with both endpoint sides, and deploy/destroy/refresh buttons; deploy/destroy gated on status to prevent foot-guns. 10-test coverage (`tests/test_lab_topology.py`): migration, YAML gen with/without links, full CRUD, cross-environment rejection, endpoint metacharacter rejection, free-standing-runtime conflict, and a deploy → destroy round trip with mocked subprocess.
  - [x] Phase B-3a — drift-from-twin checks: new `lab_drift_runs` table (migration 0032) backs scheduled and on-demand comparisons of a twin's snapshot against its source host's most recent config snapshot. `netcontrol/routes/lab_drift.py` exposes `POST /api/lab/devices/{id}/drift/check`, `GET /api/lab/devices/{id}/drift/{runs,latest}`, and `GET /api/lab/drift/runs/{id}`; runs persist with status `in_sync` / `drifted` / `missing_source` / `error`. Background sweep `lab_drift_scheduler_loop` walks every twin with a `source_host_id` on a configurable cadence (`PLEXUS_LAB_DRIFT_INTERVAL_SECONDS`, default 1h, floor 60s; `PLEXUS_LAB_DRIFT_ENABLED=false` disables). React Lab page gains a Drift card on the device panel showing latest status, run-on-demand button, and history table. Reuses the existing `_compute_config_diff` so volatile-line normalization is identical to config-drift. 8-test coverage (`tests/test_lab_drift.py`).
  - [ ] Phase B-2 follow-on: drag-and-drop topology canvas (vis-network is already vendored). Current editor is list-based.
  - [ ] Phase B-3b — traffic generation: optional traffic-gen sidecar (iperf/scapy container) for exercising live topologies. Lower priority than drift-from-twin since the latter is the unique closed-loop value of having Plexus + the twin.
  - [ ] Phase B-3 — traffic generation and drift-from-twin checks: optional traffic-gen sidecar, scheduled comparison of real device config against the twin to flag unintended divergence.

---

## Hospital / Healthcare Network Readiness

Plexus manages the network infrastructure that carries PHI (Protected Health Information),
placing it under HIPAA's Security Rule. The items below harden Plexus for deployment in
hospital, clinic, and health-system environments where uptime is life-safety-critical,
auditors review every tool with credentials, and medical devices have unique network behavior.

### P0 — HIPAA Compliance & Security (Must-Have Before Deployment)

- [x] **Enforce TLS everywhere** — disable HTTP listener in production mode; redirect all plaintext to HTTPS; add HSTS header with long max-age. *Why: HIPAA §164.312(e)(1) requires encryption of ePHI in transit. The NMS carries device credentials and may display config snippets containing sensitive data.*
- [ ] **Add multi-factor authentication (TOTP)** — implement RFC 6238 TOTP enrollment, QR code provisioning, and per-login verification; allow admin policy to require MFA for all users or admin-only. *Why: username/password alone will not pass a healthcare security review. MFA is a HIPAA addressable safeguard that every hospital CISO will treat as required.*
- [ ] **Configurable session idle timeout** — add server-side idle timeout (default 15 min, configurable per policy); auto-terminate sessions and force re-auth on expiry; show countdown warning toast. *Why: HIPAA §164.312(a)(2)(iii) requires automatic logoff. Shared workstations in nurse stations and NOCs make this critical.*
- [ ] **Immutable audit log with tamper protection** — make audit_events append-only at the database level (no UPDATE/DELETE on audit tables); add cryptographic chaining (hash of previous entry) or write-once export; ensure admins cannot delete their own audit trail. *Why: auditors will ask "can a privileged user cover their tracks?" The answer must be no.*
- [ ] **SIEM log forwarding** — add configurable syslog/webhook forwarding of audit events, auth events, and alert triggers to external SIEM (Splunk, Sentinel, QRadar); support CEF or JSON format. *Why: hospital security teams centralize all logs for correlation and incident response. Plexus events must feed the same pipeline.*
- [ ] **Password policy enforcement** — add configurable minimum length, complexity requirements (upper/lower/digit/special), password history (prevent reuse of last N), and maximum age with forced rotation; enforce at registration, reset, and change endpoints. *Why: HIPAA §164.312(d) requires authentication controls. Joint Commission and CMS auditors check password policy configuration.*
- [ ] **Account lockout after failed attempts** — lock account after N consecutive failures (configurable, default 5); require admin unlock or time-based auto-unlock; log lockout events to audit trail. *Why: brute-force protection is expected by every healthcare security framework (HIPAA, HITRUST, NIST 800-66).*
- [ ] **User access review reporting** — add API/UI to generate reports showing all users, their roles, last login date, and feature access; flag dormant accounts (no login in N days). *Why: HIPAA requires periodic access reviews. IT directors need a one-click report for quarterly compliance cycles.*

### P1 — Operational Readiness (Required for Production Use)

- [ ] **Alert notification channels (email, PagerDuty, webhook)** — add outbound integrations for alert rules; support email (SMTP), PagerDuty Events API v2, generic webhook (POST JSON), and Microsoft Teams incoming webhook; allow per-rule channel assignment. *Why: critical alerts at 3 AM must reach the on-call engineer's phone, not just a toast notification in a browser tab nobody is watching.*
- [ ] **Per-device and per-group polling interval controls** — add configurable SNMP polling interval overrides at group and host level (e.g., biomedical devices at 5 min, core switches at 30 sec); enforce minimum floor to prevent accidental aggressive polling. *Why: medical devices (infusion pumps, MRI controllers, patient monitors) can crash, reboot, or drop clinical sessions if polled too aggressively. This is a patient-safety concern.*
- [ ] **Scheduled report delivery (email)** — add report scheduling (daily/weekly/monthly) with email delivery of PDF or CSV attachments; support distribution lists. *Why: hospital IT leadership and compliance officers need recurring reports without logging into the tool. Joint Commission auditors expect documented evidence delivered on schedule.*
- [ ] **ServiceNow / ITSM integration** — add API integration to create/update change requests in ServiceNow (or generic ITSM via REST); link Plexus deployments to change ticket numbers; enforce ticket-required policy before production changes. *Why: hospitals require formal Change Advisory Board (CAB) approval before any network change. Plexus deployments must link to an approved ticket for audit trail.*
- [ ] **Maintenance windows and change freeze enforcement** — add maintenance window definitions (recurring or one-time) per group; block or warn on job/deployment execution outside approved windows; integrate with change ticket approval status. *Why: hospital networks support life-safety systems. Unscheduled changes during peak clinical hours risk patient care. CAB processes require proof that changes occurred within approved windows.*
- [ ] **High availability documentation and Redis-backed job queue** — move background workers, job queue, and polling coordination from in-memory state to Redis (or PostgreSQL advisory locks); document active-passive and active-active HA deployment patterns with load balancer configuration. *Why: hospital networks are 24/7/365. An NMS outage creates blind spots during patient care. The CISO will ask "what happens when your monitoring server goes down?"*
- [ ] **Clinical VLAN segmentation visibility** — add VLAN/subnet tagging with clinical purpose labels (clinical, biomedical, guest, building management, IoT); display segment membership in topology and inventory views; allow compliance profiles scoped to specific segments. *Why: hospitals heavily segment networks per HIPAA and IEC 80001. Operators need to see "this is the biomedical VLAN" at a glance, not just "VLAN 42."*

### P2 — Scale, Depth, and Enterprise Hardening

- [ ] **Distributed polling agents** — add lightweight remote poller component that can be deployed at each hospital campus/building; pollers collect SNMP/flow/syslog locally and forward metrics to the central Plexus instance via authenticated API; central instance aggregates and presents unified view. *Why: hospital campuses span multiple buildings, sometimes across a city. A single central poller can't reach devices behind WAN links reliably, and bandwidth for SNMP across WAN is wasteful.*
- [ ] **HashiCorp Vault / external secrets integration** — add pluggable credential backend supporting HashiCorp Vault (KV v2), Azure Key Vault, and AWS Secrets Manager; rotate credentials on schedule; remove local Fernet-encrypted storage as default for production deployments. *Why: auditors will scrutinize how network device credentials (enable secrets, SNMP community strings) are stored. An external vault with rotation and access logging is the expected answer in regulated environments.*
- [ ] **Service-level SLA dashboards** — add ability to define logical services (e.g., "Epic EHR network path," "PACS imaging backbone," "nurse call system") composed of multiple devices/interfaces; calculate and display service-level availability, latency, and packet loss; alert on service degradation, not just individual device failure. *Why: hospital leadership doesn't think in devices — they think in clinical services. "Is Epic reachable?" matters more than "is switch 3 in building B up?"*
- [ ] **Biomedical device profiles and safe polling defaults** — add device classification tags (IT infrastructure, biomedical, IoT, building management); ship default profiles for common medical device vendors (GE Healthcare, Philips, Siemens Healthineers, Baxter) with conservative polling intervals and limited OID sets; warn when adding biomedical devices to aggressive polling groups. *Why: biomedical devices run safety-critical firmware. Aggressive SNMP walks can cause IV pump communication drops or imaging system reboots. This is a patient-safety issue, not just an IT concern.*
- [ ] **Compliance posture trending over time** — add historical compliance score tracking per profile, per group, and per host; display trend charts showing improvement or regression over weeks/months; support compliance SLA targets (e.g., "95% of devices compliant within 7 days of new rule"). *Why: auditors want to see trajectory, not just a point-in-time snapshot. "We're 87% compliant and improving" is a very different story than "we're 87% compliant and declining."*
- [ ] **NAC posture integration (Cisco ISE / Aruba ClearPass)** — add API integration to pull NAC posture status per endpoint; display compliant/non-compliant/unknown status alongside device inventory; alert on NAC policy violations. *Why: Network Access Control is heavily used in healthcare to protect clinical networks from rogue devices. Seeing NAC status alongside network status gives operators a complete security picture.*

### P3 — Enterprise Authentication and Long-Term Maturity

- [ ] **SAML / SSO integration** — add SAML 2.0 SP (Service Provider) support for single sign-on via hospital identity providers (Azure AD, Okta, PingFederate); support IdP-initiated and SP-initiated flows; map IdP groups to Plexus roles. *Why: hospitals standardize on SSO for all tools. If Plexus requires a separate login, adoption will be low and the security team will flag it as an exception that needs a waiver.*
- [ ] **Change history and approval audit reports** — add exportable reports showing every network change in a date range with who requested it, who approved it (ITSM ticket), what changed (diff), and outcome (success/rollback); support PDF export for compliance submissions. *Why: Joint Commission, CMS, and HIPAA auditors require documented proof that all infrastructure changes followed an approved process. This report is the primary artifact they review.*
- [ ] **Network uptime reports by clinical segment** — add segment-level availability reports (e.g., "Clinical VLAN uptime: 99.97% this quarter") with drill-down to device-level contributors; include MTTR and incident count per segment. *Why: hospital IT leadership reports network performance to clinical leadership quarterly. They need segment-level metrics, not raw device lists.*
- [ ] **Deployment and security hardening guide** — author comprehensive deployment documentation covering: recommended network placement (management VLAN, firewall rules), TLS certificate provisioning, database backup strategy, HA architecture diagrams, and security checklist for hospital CISO review. *Why: the hardest part of hospital adoption isn't the code — it's organizational trust. A CISO will ask "where does this sit on the network, who can reach it, and what happens if your engineer leaves?" The deployment guide must answer all of these.*
- [ ] **HIPAA compliance documentation package** — create formal documentation mapping Plexus capabilities to HIPAA Security Rule safeguards (§164.312 technical safeguards); include risk assessment template, data flow diagrams showing what Plexus stores/transmits, and BAA (Business Associate Agreement) template if offering as a service. *Why: compliance isn't just features — it's documented proof that features exist and are configured correctly. This package is what the compliance officer hands to the auditor.*

---

## Network Operations & Visibility Enhancements

### Now — Core Operations Gaps

- [x] **Configuration full-text search** — add full-text search across all backed-up device configurations; support regex and substring matching; return results with device name, match context, and link to full config diff view; index on backup ingest for fast queries. *Why: "which devices still have SNMP community string `public`?" or "which routers have this ACL entry?" are daily questions during audits, incident response, and security hardening. Without cross-device config search, operators resort to SSH-ing into devices one by one.*
- [ ] **Cross-device configuration diff** — add side-by-side config comparison between any two devices (or any two snapshots of the same device); highlight differences with context lines; support filtering by section (interfaces, routing, ACLs). *Why: validating that redundant pairs (HSRP, stacked switches, HA firewalls) have matching configs is a common task. Manual comparison is error-prone and tedious. A built-in cross-device diff eliminates the need for external diff tools.*
- [x] **STP topology visualization** — display spanning-tree topology per VLAN showing root bridge, designated/blocked/forwarding port states, and topology change events; alert on unexpected root bridge elections or topology change storms; overlay STP state on physical topology map. *Why: spanning-tree misconfigurations cause broadcast storms and outages that are notoriously difficult to diagnose. Visualizing STP state per-VLAN makes root bridge placement and blocked port logic immediately obvious.*
- [ ] **BGP/OSPF/EIGRP route table monitoring** — collect and diff routing tables over time; store route history with timestamps; alert on unexpected route withdrawals, prefix hijacks, next-hop changes, or AS-path anomalies; display route table diffs in device detail page. *Why: most NMS tools monitor L2/L3 data plane but ignore the control plane. A silent BGP withdrawal can black-hole traffic for minutes before interface counters show anything wrong. Route-level visibility catches these fast.*
- [x] **Interface error/discard trending with root-cause correlation** — track CRC errors, input errors, giants, runts, output drops, and discards per interface over time as dedicated metrics; correlate error spikes with config changes, topology events, and cable/optic replacements; surface "likely cause" hints (e.g., CRC spike + no config change → suspect physical layer). *Why: raw error counters exist in SNMP but operators need trends and correlation, not point-in-time numbers. Reduces MTTR by surfacing physical-layer problems before they cascade.*
- [ ] **QoS policy monitoring and visualization** — collect DSCP/queue statistics per interface via SNMP (cbQos MIB for Cisco, equivalent for other vendors); display queue depth, drop counts, and policer conformance over time; alert when priority queues show sustained drops. *Why: networks carrying voice, video, and clinical telemetry (telemedicine, nurse call, patient monitoring) depend on QoS working correctly. A misconfigured policy is invisible until call quality degrades or a monitor alarm is delayed.*
- [ ] **Failover and redundancy state validation** — periodically verify HSRP/VRRP active/standby state, spanning-tree root bridge placement, LACP port-channel membership, and BGP primary/backup path preferences match intended design; alert on unexpected state changes (e.g., backup router became active without a maintenance window). *Why: redundancy failures are silent — everything works until the primary fails and the backup isn't actually ready. Proactive validation catches misconfigured standby states before an outage reveals them.*

### Next — Expanded Visibility

- [ ] **Device lifecycle tracking (EoL/EoS/warranty)** — track end-of-life, end-of-sale, end-of-support, and warranty expiry dates per device model and software version; import lifecycle data from vendor APIs (Cisco EoX API, Juniper EOL notices) or CSV; alert N days before milestones; generate lifecycle risk reports showing devices past or approaching end-of-support. *Why: running unsupported hardware or software is a compliance violation in regulated environments and a security risk everywhere. Proactive lifecycle tracking turns a reactive "we found out during an outage" into a planned refresh cycle.*
- [ ] **TLS/SSL certificate expiry monitoring** — discover and track certificates on network device management interfaces (HTTPS, VPN PKI, RADIUS server certs); alert N days before expiry; display certificate chain details, issuer, and key strength; support manual certificate inventory entries for non-SNMP-discoverable certs. *Why: expired certificates cause VPN outages, management access failures, and 802.1X authentication breakdowns. Certificate expiry is one of the most common preventable outage causes in enterprise networks.*
- [ ] **Power and environmental monitoring** — poll UPS status (battery charge, load, time remaining), PDU per-outlet power draw, and environmental sensors (temperature, humidity) via SNMP (RFC 3433 Entity Sensor MIB, APC PowerNet MIB, Liebert/Vertiv MIBs); alert on battery low, over-temperature, or humidity threshold violations; display environmental data in device detail and facility overview dashboards. *Why: network outages caused by power failures, overheating IDFs, or humidity damage are preventable with proactive environmental monitoring. Especially critical in data centers and remote sites without on-site staff.*
- [ ] **Wireless controller and AP monitoring** — poll wireless LAN controllers (Cisco WLC, Aruba, Meraki API) for AP status, client counts, channel utilization, interference levels, and rogue AP detection; display AP map overlay on topology; alert on AP down, high client density, or rogue detection. *Why: campus and hospital networks run heavy wireless. Wireless problems are the #1 helpdesk complaint category. Having wired and wireless visibility in one tool eliminates swivel-chair monitoring between platforms.*
- [ ] **DNS/DHCP scope monitoring** — track DHCP pool utilization, lease counts, and lease churn via SNMP or API (ISC DHCP, Windows DHCP, Infoblox); monitor DNS resolution latency and failure rates via synthetic queries; alert when pools approach exhaustion or DNS latency spikes. *Why: DHCP exhaustion causes mysterious "can't connect" tickets. DNS failures cascade into application outages. Both are critical infrastructure that most NMS tools ignore.*
- [ ] **Network path testing (traceroute/MTR as a service)** — run scheduled or on-demand traceroute/MTR between monitored endpoints; store hop-by-hop results over time; alert on path changes, new asymmetric routing, or latency increases at specific hops; display path overlay on topology map. *Why: "the network is slow" is the hardest complaint to troubleshoot. Stored traceroute history shows exactly when and where a path changed, turning a 2-hour investigation into a 2-minute lookup.*
- [ ] **Synthetic monitoring probes** — schedule HTTP, ICMP, DNS, and TCP port checks from Plexus to critical endpoints (EHR portals, imaging servers, cloud services, VPN concentrators); measure reachability, latency, and certificate expiry from the network's perspective; integrate results into SLA dashboards. *Why: SNMP tells you the switch is up. Synthetic probes tell you the service behind the switch is actually reachable and responding. The distinction matters when troubleshooting application complaints.*

### Later — Advanced Analytics

- [ ] **Network path failure simulation (what-if analysis)** — model the impact of link, device, or circuit failures using discovered topology and routing data; answer "what happens if this link goes down?" by computing alternate paths and identifying single points of failure; display affected services and expected failover paths; support batch simulation for resilience audits. *Why: resilience testing today means pulling cables in maintenance windows. Simulation using live topology data lets operators validate redundancy designs without risking production traffic.*
- [x] **Bandwidth billing and 95th percentile reports** — calculate burstable 95th-percentile bandwidth per interface, per customer, or per circuit over configurable billing periods; generate exportable invoices with usage graphs; support commit-rate tracking and overage alerting. *Why: ISPs and shared-services IT departments bill by 95th percentile. This is a direct revenue/chargeback feature that currently requires a separate tool (MRTG, Cacti, or manual calculation).*
- [ ] **User-defined alert correlation rules** — allow operators to define correlation rules (e.g., "if interface X goes down AND BGP peer Y drops within 5 minutes, create single incident instead of two alerts"); support suppression (child alerts suppressed when parent device is down) and deduplication windows. *Why: alert fatigue kills operational effectiveness. A single link failure can generate 50+ alerts across dependent devices. Correlation reduces noise so operators focus on root cause, not symptoms.*
- [x] **Automated network documentation generation** — auto-generate network diagrams, IP address plans, VLAN maps, and device inventories as exportable PDF, SVG, or draw.io from discovered topology, inventory, and SNMP data; refresh on schedule or on-demand; include cable/circuit info when available. *Why: network documentation is always out of date. Auto-generating it from live discovery data means the documentation is as current as the last poll cycle. Saves hours of manual Visio work per quarter.*
  - [x] Initial on-demand foundation: added `network_documentation` report generation plus CSV export and SVG topology diagram export from live inventory/topology/VLAN data.
  - [x] Next slice (phase A): scheduled generation loop + persisted run artifacts (CSV/SVG) with downloadable artifact history.
  - [x] Next slice (phase B): PDF packaging and cable/circuit enrichment from billing circuit metadata (`circuit_map` + topology link enrichment).
  - [x] Next slice (phase C): draw.io topology export endpoint plus persisted `.drawio` artifacts and report UI export actions.

---

## Automation & Workflow Enhancements

### Now — High-Impact Automation

- [ ] **Alert-triggered auto-remediation** — allow operators to attach playbooks to alert rules as automated response actions; when an alert fires, auto-execute the linked playbook against the affected device(s) with configurable options: fully automatic, or require human approval before execution; log all auto-remediation actions to audit trail with alert-to-action linkage. *Why: common problems have known fixes (interface down → bounce port, high CPU from process → restart process, config drift detected → push compliant config). Automating the response reduces MTTR from "wait for human to notice and act" to seconds. The approval gate option maintains safety for higher-risk actions.*
- [ ] **Backup restore verification** — periodically restore a configuration backup to a lab/sandbox device (or validate via config parse/syntax check) and verify it applies cleanly; mark backup as "verified" or "verification failed" in the backup inventory; alert when backups have never been verified or verification has lapsed beyond a configurable threshold. *Why: a backup that can't be restored is not a backup. Automated restore testing proves recoverability — the difference between "we have backups" and "we can actually recover" matters when an outage hits.*
- [ ] **Bulk device onboarding wizard** — add CSV/Excel import for devices with column mapping, validation, credential assignment, group placement, and auto-discovery kick-off; support dry-run preview showing what will be created/modified before committing; display progress and per-row error reporting. *Why: initial deployment of Plexus into a network with 500+ devices shouldn't require clicking "Add Device" 500 times. Bulk import reduces onboarding from days to minutes and is expected by every network team evaluating an NMS.*
- [ ] **Configuration template compliance diffing with remediation** — beyond golden config match/mismatch, show exactly which lines differ with context; generate remediation commands to bring non-compliant devices into alignment; support one-click "push fix" for non-compliant lines with approval gate and dry-run. *Why: knowing a device is non-compliant is step one. Knowing what to do about it — and being able to do it safely from the same tool — closes the loop and reduces remediation time from hours to minutes.*
- [ ] **Scheduled config diff reports** — daily or weekly email showing all configuration changes across the network in a unified diff view; group by device, group, or change author; include before/after snippets and link to full diff in Plexus UI. *Why: compliance teams and network managers need a periodic "what changed" summary without logging into the tool. This is the most-requested report in every NMS deployment.*
- [ ] Enable the ability edit devices in the cli within the topo view to make it similar to something like CML or cisco packet tracer.
- [x] Add feature visibility toggle for hiding un used UI features

### Next — Workflow Maturity

- [ ] **Staggered rollout with per-batch health checks** — add deployment mode that pushes config changes to devices in configurable batches (e.g., 5 at a time, one site at a time, or by percentage); run automated health checks between each batch (reachability, CPU, interface errors, routing table stability); auto-pause on failure with option to rollback completed batches or continue; support time-of-day constraints per site for timezone-aware rollouts. *Why: pushing a change to 200 devices simultaneously is high-risk. Staggered rollout with health gates between batches catches problems early when only a small subset is affected, limiting blast radius and making rollback manageable.*
- [ ] **Change calendar with conflict detection** — visual calendar showing scheduled maintenance windows, pending deployments, and active change freezes; detect and warn on overlapping changes to the same device/group; integrate with ITSM ticket status. *Why: two engineers scheduling overlapping changes to the same core switch is a recipe for an outage. A shared change calendar with conflict detection prevents this coordination failure.*
- [ ] **Runbook automation (multi-step playbook chains)** — allow operators to define multi-step runbooks that chain playbook executions with conditional logic (e.g., "run pre-check, if pass run change, then run post-check, if fail run rollback"); support approval gates between steps and parallel execution across device groups. *Why: complex changes (OS upgrades, security remediations, circuit migrations) require multiple coordinated steps. Manual execution of each step introduces human error and delays. Runbook automation ensures consistent execution every time.*
- [ ] **ChatOps / natural language query interface** — add LLM-powered query layer over existing APIs; support queries like "show me all devices with >80% CPU in building A" or "what changed on the core switches this week?"; return structured results with links to relevant Plexus pages; support Slack/Teams integration for query responses. *Why: operators spend significant time navigating UIs to answer simple questions. Natural language queries reduce time-to-answer from minutes of clicking to seconds of typing. Especially valuable during incidents when speed matters.*

---

## User Experience & Collaboration

### Now — Operations Team Essentials

- [ ] **Topology export (Visio/draw.io/SVG)** — export discovered network topology as editable diagrams in Visio (vsdx), draw.io (XML), and SVG formats; include device metadata (model, IP, role), link labels (speed, utilization), and VLAN annotations; support filtered exports (single group, single site, L2-only, L3-only). *Why: network teams live in Visio diagrams for documentation, presentations, and change planning. Auto-generated editable diagrams from live discovery data save hours of manual drawing and stay current with the actual network state.*
- [ ] **NOC wall dashboard mode** — add full-screen, auto-rotating dashboard view optimized for large displays; show critical alerts, topology status, top talkers, and SLA summary; auto-refresh with configurable rotation interval; no interaction needed; support multiple display profiles (network ops, security, executive). *Why: every NOC has wall-mounted displays. If Plexus can't fill them, operators will keep their old tool running alongside Plexus just for the wall view. First-class NOC display support drives adoption.*
- [ ] **Device and interface annotation notes** — let operators attach timestamped notes, ticket references, or "known issue" tags to devices and interfaces; display notes in inventory, topology, and device detail views; support filtering by annotation (e.g., "show all devices tagged 'pending-RMA'"). *Why: institutional knowledge lives in operators' heads and sticky notes. Structured annotations in the NMS make that knowledge searchable and persistent across shifts and staff turnover.*
- [ ] **Shift handoff / operations log** — add structured log where NOC operators record events, actions taken, escalations, and pending items per shift; timestamped and searchable; link entries to devices, alerts, and jobs; support shift templates and handoff acknowledgment. *Why: shift handoff is where information gets lost. A structured ops log ensures the next shift knows what happened, what's in progress, and what needs attention. Reduces repeat troubleshooting and missed follow-ups.*

### Next — Collaboration & Usability

- [ ] **Geolocation and floor plan mapping** — assign devices to physical locations (building, floor, room, rack); upload site floor plans or campus maps as background images; place device icons on maps with drag-and-drop positioning; display device status (up/down/warning) as color-coded icons on the map; support drill-down from campus → building → floor → rack. *Why: during a physical-layer incident (power outage in a building, water leak in an IDF), operators need to instantly see which devices are in the affected area. Geographic context turns "switch-3-bldg-a-fl2 is down" into a visual that anyone — including facilities staff — can understand.*
- [ ] **Cable and circuit inventory management** — track physical circuits with carrier name, circuit ID, contract dates, SLA terms, monthly cost, and A/Z endpoints; link logical interfaces to physical circuits; alert on contract expiry; display circuit info in device detail and topology views. *Why: circuit information lives in spreadsheets and contract PDFs across most organizations. Linking physical circuits to logical interfaces in the NMS gives operators instant context during troubleshooting ("this interface is on a CenturyLink circuit, here's the ticket number to call").*
- [ ] **IP address management (IPAM) integration** — add lightweight IPAM with subnet tracking, utilization visualization, and conflict detection; or integrate with external IPAM (Infoblox, NetBox, phpIPAM) via API to pull/push address assignments; display IP utilization in inventory and topology views. *Why: IP conflicts and exhaustion cause hard-to-diagnose connectivity issues. Having address management visibility alongside network monitoring eliminates the need to cross-reference a separate IPAM tool during troubleshooting.*
  - [x] Initial foundation: added `/api/ipam/overview` plus an IPAM UI page with inferred inventory subnet tracking, utilization summaries, cloud CIDR visibility, and duplicate IP conflict detection.
  - [x] Phase A — External IPAM source integration: full CRUD for external sources (NetBox, phpIPAM, Infoblox) with encrypted auth storage, adapters that normalize prefixes and allocations, background auto-sync loop (~30 min), manual sync/validate endpoints, subnet drilldown with reservation CRUD, and sync-config API. DB migration `0018_add_ipam_sync_tables`. 6-test coverage.
  - [x] Phase B — IPAM context in device detail: added `/api/ipam/address/{ip}` endpoint (best-match subnet lookup + conflict detection); added all missing IPAM API client functions to `api.js` (fixing broken IPAM page); IPAM context panel now shows subnet CIDR, utilization bar, and conflict badge directly on the device detail page.
  - [x] Next slice (phase C): push-back sync — when Plexus discovers or updates a device IP, write the allocation back to external IPAM sources (NetBox/phpIPAM/Infoblox write adapters); add per-source push toggle.
  - [x] Next slice (phase D): IPAM utilization overlay in topology view — surface subnet utilization % as color-coded overlays on topology links/nodes.
  - [x] Next slice (phase E): bi-directional reconciliation — drift detection between Plexus inventory and external IPAM allocations (missing-in-IPAM, missing-in-Plexus, hostname/status mismatches), persisted run history with `ipam_reconciliation_runs` + `ipam_reconciliation_diffs` (migration 0023), API endpoints (`POST /api/ipam/sources/{id}/reconcile`, `GET /api/ipam/reconciliation/{runs,diffs}`, `POST /api/ipam/reconciliation/diffs/{id}/resolve`), Reconciliation UI panel on the IPAM page with per-source Reconcile button and accept-Plexus/accept-IPAM/ignore actions, and 15-test coverage.
  - [x] Next slice (phase F): DHCP scope and lease integration — pull scope utilization and active leases from Kea (ISC), Windows DHCP, and Infoblox via normalized provider adapters; persist `dhcp_servers`/`dhcp_scopes`/`dhcp_leases` (migration 0024) with encrypted auth; background `_dhcp_sync_loop` (~30 min) plus on-demand `POST /api/dhcp/servers/{id}/sync`; API endpoints for server CRUD, scope/lease listing, scope-exhaustion alerting (`/api/dhcp/exhaustion`), and lease-vs-inventory correlation (`/api/dhcp/correlation`); DHCP card on the IPAM page with server table, exhaustion alerts, unknown-lease list, and add/edit/sync/delete actions; 14-test coverage.
  - [x] Next slice (phase G): VLAN/VRF-aware subnet scoping — added `vrf_name`/`vlan_id` columns to `hosts` and `ipam_allocations` (migration 0025); `replace_ipam_source_snapshot` now persists VLAN on prefixes and inherits VRF/VLAN from prefix into allocations; `get_ipam_overview` keys subnets by `(subnet, vrf)` and conflict detection by `(vrf, ip)` so overlapping RFC1918 ranges in different VRFs no longer false-positive; subnet rows now expose `vrf_name`/`vlan_ids` and summary returns `vrf_names`/`vrf_count`; `/api/ipam/address/{ip}?vrf=` prefers same-VRF subnet match and same-VRF conflict; `HostCreate`/`HostUpdate` accept VRF/VLAN; IPAM subnet table and duplicate panel show VRF/VLAN badges; device detail IPAM context surfaces VRF context. 6-test coverage (`test_ipam_vrf.py`).
  - [x] Next slice (phase H): IPAM-driven provisioning — added `ipam_pending_allocations` table (migration 0026) tracking pending → committed/released lifecycle with TTL expiry; new `db.allocate_next_ip` picks the first free IP considering inventory hosts, IPAM allocations, reservations, and active pending rows (VRF-isolated so two tenants can hold the same IP); `POST /api/ipam/allocate` returns a pending reservation with optional push to enabled external IPAM sources; `POST /api/ipam/allocate/{id}/commit` promotes to a permanent allocation in the built-in (or originating) IPAM source; `POST /api/ipam/allocate/{id}/release` rolls back a pending reservation; `GET /api/ipam/allocate/pending` lists pending/expired/released history; `db.expire_stale_pending_allocations` reaps expired rows. 8-test coverage (`test_ipam_allocate.py`).
  - [x] Next slice (phase I): historical IP allocation tracking — added `ipam_ip_history` (append-only per-IP assignment timeline) and `ipam_subnet_utilization` (time-series snapshots) tables (migration 0027); `record_ip_assignment` closes prior open rows and starts new lifespans, `record_ip_release` closes them; `find_ip_owner_at` answers "who had this IP on date X" via started_at/ended_at range matching; host CRUD (`add_host`/`update_host`/`remove_host`/`bulk_delete_hosts`) and `create_local_ipam_allocation`/`delete_ipam_allocation` auto-record history; `snapshot_subnet_utilization` computes total/used/reserved/pending/free and persists per-snapshot rows, `snapshot_all_subnet_utilization` scans all known prefixes and inventory-inferred subnets; new endpoints `GET /api/ipam/history/{address}`, `GET /api/ipam/history/{address}/at?when=`, `GET /api/ipam/history/host/{hostname}`, `GET /api/ipam/utilization`, `POST /api/ipam/utilization/snapshot`; VRF-isolated throughout; retention via `prune_ip_history`/`prune_subnet_utilization`. 11-test coverage (`test_ipam_history.py`).
  - [x] Next slice (phase J): IPAM reporting and exports — added three IPAM report types to the existing reporting pipeline: `ipam_utilization` (latest snapshot per subnet, threshold filter, sorted by utilization%), `ipam_forecast` (least-squares linear fit over per-subnet snapshot history projecting days-until-target with status critical/warning/ok/stable/exhausted/insufficient_data), and `ipam_history` (per-IP assignment timeline filterable by address/hostname/vrf/days with computed duration_hours); CSV exports at `/api/reports/export/ipam_utilization|ipam_forecast|ipam_history` plus tabular PDF exports at `/api/reports/export/ipam_utilization.pdf` and `/api/reports/export/ipam_forecast.pdf`; new `_render_tabular_pdf` helper for capacity-planning audiences; scheduled-report dispatch (existing `_report_scheduler_loop`) now persists CSV+PDF artifacts for IPAM reports automatically when `report_definitions` rows of type `ipam_utilization`/`ipam_forecast` reach their schedule. 10-test coverage (`test_ipam_reporting.py`).
- [ ] **Multi-user change awareness** — show which users are currently viewing or modifying the same device, editing the same playbook, or running changes against the same group; display presence indicators and optional lock-on-edit for playbooks and templates. *Why: two operators simultaneously pushing conflicting changes to the same device is a preventable outage. Presence awareness and optional locking prevent coordination failures without requiring formal change management overhead for every minor edit.*
- [ ] **Customizable alert notification sounds and browser notifications** — add per-severity browser notification support (desktop push notifications with permission prompt); configurable alert sounds for critical/warning/info; support "quiet hours" per user to suppress non-critical notifications during off-shift. *Why: a browser tab running Plexus should be able to wake up an operator who's looking at another screen. Browser notifications and alert sounds are table-stakes for any monitoring tool used in a NOC environment.*

---

## Integration & Extensibility

### Now — Ecosystem Connectors

- [x] **Ansible dynamic inventory provider** — expose Plexus device inventory as an Ansible dynamic inventory source via CLI script or HTTP endpoint; support group mapping (Plexus inventory groups → Ansible groups), host variables (IP, credentials, device type, model), and filtering by group, tag, or device type. *Why: teams already using Ansible for network automation need their inventory source to be authoritative and current. Plexus as the single source of truth for device inventory eliminates stale static inventory files and manual synchronization.*
- [ ] **Inbound webhook API for external triggers** — add authenticated webhook receiver endpoints that allow external systems to trigger Plexus actions (run playbook, start discovery scan, create alert, initiate backup); support ServiceNow, Jira, and generic JSON payloads with configurable field mapping; log all inbound triggers to audit trail. *Why: automation is bidirectional. Plexus needs to react to external events (approved change ticket → auto-deploy, security scanner finding → quarantine playbook, cloud autoscale event → update inventory) not just push notifications outward.*


### Next — Developer Platform

- [ ] **Terraform provider for Plexus resources** — publish a Terraform provider that manages Plexus inventory groups, devices, credentials, compliance profiles, alert rules, and dashboard configurations as infrastructure-as-code; support import of existing resources and plan/apply lifecycle. *Why: infrastructure-as-code teams manage everything through Terraform. If Plexus configuration requires manual UI clicks, it becomes the exception that doesn't fit into GitOps workflows and CI/CD pipelines.*
- [ ] **Multi-instance federation** — support multiple Plexus instances (per-region, per-site, or per-customer) with a federated overview layer; aggregate device counts, alert summaries, compliance scores, and SLA metrics across instances; support drill-down from federated view to individual instance; authenticate cross-instance communication via mutual TLS or API tokens. *Why: MSPs managing multiple customer networks and enterprises with regional NOCs need a single pane of glass without putting all devices in one database. Federation scales Plexus beyond single-site deployments while maintaining data isolation.*
  - [x] Initial foundation: federation peer CRUD API (register/edit/remove remote instances), peer connectivity testing, manual and background sync of aggregate data (devices, alerts, compliance, version), federated overview endpoint with cross-instance totals, encrypted API token storage, Federation UI page with overview cards and peer management table, DB migration (0014), and 13-test coverage.
- [ ] **Cloud network visibility (AWS/Azure/GCP)** — monitor cloud networking constructs (AWS VPC flow logs, Transit Gateway, Azure VNet peering, GCP Cloud Router) alongside on-premises infrastructure; pull cloud topology, security group rules, and traffic metrics via provider APIs; display hybrid topology showing on-prem ↔ cloud connectivity paths (VPN, Direct Connect, ExpressRoute). *Why: most enterprise networks are hybrid. Monitoring on-prem and cloud in separate tools creates visibility gaps at the boundary — exactly where problems occur during cloud migrations and hybrid application deployments.*
  - [x] Initial foundation: cloud account CRUD API + persisted cloud resource/connection/hybrid-link tables + sample discovery endpoint + new Cloud Visibility UI page with provider/account filters and hybrid topology snapshot tables.
  - [x] Next slice (phase A): provider SDK live collectors (AWS/Azure/GCP) with `auto` discovery fallback to sample mode, provider dependency capability hints in UI, and account validation endpoint/UI action before discovery.
  - [x] Next slice (phase B): add cloud flow-log and traffic-metric ingestion (AWS VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Flow Logs) into Plexus metrics/events.
    - [x] Phase B slice 1: add cloud flow-log ingestion API (`/api/cloud/accounts/{id}/flow-logs/ingest`) with normalized/AWS/Azure/GCP payload support, cloud flow analytics endpoints (summary/top-talkers/timeline), and cloud_flow event emission.
    - [x] Phase B slice 2: add scheduled flow-log pullers (AWS CloudWatch Logs Insights, Azure Blob Storage NSG logs, GCP Cloud Logging) with per-account watermark cursors, configurable sync interval, background loop in app lifespan, and API endpoints for config/trigger/status.
    - [x] Phase B slice 3: complete Cloud Visibility frontend for flow telemetry with flow analytics cards/tables (summary/top-talkers/timeline), flow-sync configuration controls, manual pull actions, and per-account watermark cursor visibility.
    - [x] Phase B slice 4: add explicit cloud traffic-metric ingestion/storage (`/api/cloud/accounts/{id}/traffic-metrics/ingest`) with normalized/AWS/Azure/GCP payload support, cloud traffic metric analytics endpoints (summary/top-resources/timeline), persisted metric samples table, and cloud_traffic_metric event emission.
  - [ ] Next slice (phase C): add rule-level security visibility for cloud policies (AWS security group rules, Azure NSG rules, GCP firewall rules) with effective-policy views.
  - [ ] Next slice (phase D): expand topology coverage for route tables, gateways, interconnects, and peering/attachment relationships per provider.
  - [ ] Next slice (phase E): implement hybrid path modeling for on-prem ↔ cloud connectivity (VPN/Direct Connect/ExpressRoute) with inferred path hops.
  - [ ] Next slice (phase F): add scheduled cloud sync orchestration with rate-limit aware retries/backoff, stale-data detection, and sync health SLAs.
  - [ ] Next slice (phase G): harden cloud credential handling to enforce secret references, support rotation-safe auth patterns, and plug into external vault providers.
  - [ ] Next slice (phase H): add cloud-specific alerting and dashboards (tunnel/down events, route instability, denied-traffic spikes, cloud-edge health).
  - [ ] Next slice (phase I): production hardening for scale and operations (provider pagination robustness, large-account performance tests, and operator runbooks).