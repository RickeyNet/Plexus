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
- [ ] Add digital twin/lab mode for safe pre-production change testing.

---

## Hospital / Healthcare Network Readiness

Plexus manages the network infrastructure that carries PHI (Protected Health Information),
placing it under HIPAA's Security Rule. The items below harden Plexus for deployment in
hospital, clinic, and health-system environments where uptime is life-safety-critical,
auditors review every tool with credentials, and medical devices have unique network behavior.

### P0 — HIPAA Compliance & Security (Must-Have Before Deployment)

- [ ] **Enforce TLS everywhere** — disable HTTP listener in production mode; redirect all plaintext to HTTPS; add HSTS header with long max-age. *Why: HIPAA §164.312(e)(1) requires encryption of ePHI in transit. The NMS carries device credentials and may display config snippets containing sensitive data.*
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
