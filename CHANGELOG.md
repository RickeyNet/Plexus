# Changelog

## Unreleased

## 1.0.0 — 2026-05-06

First public release on GitHub. Earlier `0.x` versions in this changelog
are pre-release development snapshots that were not published as GitHub
releases.

### Air-gapped deployment
- Add `deploy/airgap/` toolchain for offline VM deploys: `bundle.sh` builds a self-contained `plexus-airgap.tar.gz` (Plexus image + postgres/nginx images + Docker Engine `.deb`s + XFCE/xrdp/AD-join `.deb`s + repo files); `install.sh` runs on the offline VM to install Docker from local debs, `docker load` the images, pin compose to the loaded image, and bring up the stack.
- Add `deploy/airgap/VM_SETUP.md` walkthrough for fresh Ubuntu 26.04 VMs: static-IP netplan template, hostname, chrony NTP, SSH key auth, XFCE+xrdp for RDP-with-desktop, AD domain join (realmd/sssd/adcli) with sudo-via-AD-group, ufw firewall, and Plexus-app AD provider config.

### Database
- Add PostgreSQL backend alongside the default SQLite via `APP_DB_ENGINE=postgres` and `APP_DATABASE_URL`; `requirements-postgres.txt` captures the additional `asyncpg` dependency for production deploys.
- Add `tools/migrate_sqlite_to_postgres.py` migration utility with `--dry-run`, row-count parity verification, and optional per-table checksum verification (`--with-checksums`).
- Add CI smoke job that exercises the Postgres backend end-to-end.

### Security & auth
- Add LDAPS / Active Directory authentication provider for the Plexus web UI (Settings → Authentication Provider), with admin-group DN mapping and configurable user-search filter.
- Add RADIUS authentication provider with access-group mapping and outbound syslog of auth events.
- Centralize credential ownership enforcement; close a default-credential bypass that allowed cross-tenant credential reuse.
- Replace ReDoS-prone shape-check regex with an O(n) scanner (CVE-class fix) and harden config-backup regex compilation against ReDoS.
- Drop SNMPv3 debug log that leaked secret-tainted data.
- Bound query parameters, sanitize error responses, and address CodeQL alerts across legacy frontend and Python routes.
- Tighten template handling for secrets; bump credential encryption.

### IPAM, DHCP, and provisioning
- Add IPAM bi-directional reconciliation between Plexus and external IPAM systems (migration 0023).
- Add VLAN/VRF-aware subnet scoping (Phase G, migration 0025).
- Add IPAM-driven provisioning with pending allocation lifecycle (Phase H, migration 0026).
- Add historical IP allocation tracking and subnet utilization snapshots (Phase I, migration 0027).
- Add DHCP scope/lease integration with Kea, Windows DHCP, and Infoblox (migration 0024).
- Add `APP_IPAM_PUSH_TOGGLE` and per-adapter push controls (migration 0019).

### Digital twin / lab mode
- Add digital twin / lab mode (Phase A): lab environments and cloned-from-host devices for offline config-plane simulation. Apply proposed commands or templates against a snapshot, see unified diff plus risk score, persist run history, and promote successful runs into the Deployments pipeline. Migration 0029 adds `lab_environments`, `lab_devices`, `lab_runs`. New `lab` feature flag and React page at `/frontend/lab`.
- Add containerlab single-node runtime for lab mode (Phase B-1): a twin can now back its snapshot with a real virtual NOS (Arista cEOS, Nokia SR Linux, FRR, Linux) deployed via the host's containerlab CLI. New endpoints `GET /api/lab/runtime`, `POST /api/lab/devices/{id}/runtime/{deploy,destroy,refresh}`, `GET /api/lab/devices/{id}/runtime/events`, and `POST /api/lab/devices/{id}/simulate-live` (pushes commands via Netmiko, captures the real running-config back). Strict allowlist for node kinds and image references; subprocess invoked with explicit argv. Migration 0030 adds runtime fields to `lab_devices` and a `lab_runtime_events` audit log. React Lab page gains a Runtime card and live-mode simulate toggle.
- Operationally harden Phase B-1: simulate-live and Phase A simulate now feed compliance regressions from the source host's profiles into the risk score; startup reconciles in-flight `running` rows against `containerlab inspect` so a Plexus restart no longer leaves stale state; new background TTL reaper destroys idle labs (`PLEXUS_LAB_RUNTIME_TTL_SECONDS`, default 24h, `0` to disable; `PLEXUS_LAB_RUNTIME_TTL_INTERVAL_SECONDS` controls cadence); per-device topology workdir is removed after a successful destroy.
- Add multi-device lab topologies (Phase B-2): operators can now link N twins into a single containerlab deployment so routing/STP/LACP behaviors run end-to-end against real NOS images. Migration 0031 adds `lab_topologies`, `lab_topology_links`, and `lab_devices.topology_id`. New endpoints `GET|POST /api/lab/environments/{id}/topologies`, `GET|DELETE /api/lab/topologies/{id}`, `POST|DELETE /api/lab/topologies/{id}/devices[/{device_id}]`, `POST|DELETE /api/lab/topologies/{id}/links[/{link_id}]`, `POST /api/lab/topologies/{id}/{deploy,destroy,refresh}`. The YAML generator emits a `mgmt` subnet block when set, validates each member's kind/image, and rejects deploy when a member still has a free-standing runtime running. React Lab page gains a "Topologies (multi-device)" card with a list-based editor for members and links and runtime controls. Drag-and-drop canvas deferred to a follow-on.
- Add drift-from-twin checks (Phase B-3a): a scheduled and on-demand comparison of each twin's snapshot against the most recent production config snapshot for the host it was cloned from, so prod-side cowboy changes that silently invalidate a validated twin become visible. Migration 0032 adds `lab_drift_runs`. New endpoints `POST /api/lab/devices/{id}/drift/check`, `GET /api/lab/devices/{id}/drift/runs`, `GET /api/lab/devices/{id}/drift/latest`, `GET /api/lab/drift/runs/{id}`. Background scheduler `lab_drift_scheduler_loop` runs every `PLEXUS_LAB_DRIFT_INTERVAL_SECONDS` (default 3600, floor 60); `PLEXUS_LAB_DRIFT_ENABLED=false` disables. Reuses `_compute_config_diff` so volatile-line filtering matches the config-drift module. React Lab page adds a Drift card on each device panel.
- Add visual topology canvas to the lab UI (Phase B-2 follow-on): new `TopologyCanvas` component in the React frontend renders multi-device topologies as a SVG diagram with circular auto-layout, status-coloured nodes, hover tooltips, and click-two-nodes-to-link with an inline endpoint prompt. Editor exposes a List / Canvas view toggle; both share the same data so changes round-trip. Pure SVG keeps the bundle small (no vis-network or reactflow dep added).

### Topology, monitoring & compliance
- Add SNMP-driven device discovery and polling.
- Add topology builder with CDP/LLDP and FDB+ARP fallback inference for environments where neighbor discovery is disabled.
- Add STP multi-VLAN topology visualization, anomaly detection, and alerts.
- Add layout customization, drag-and-drop, and export options to the topology canvas.
- Add config drift detection with revertable history and event timeline.
- Add config backup search and drift event history.
- Add scheduled backup policies and retention.
- Add risk analysis for proposed config changes.
- Add observability tab with availability and capacity dashboards.
- Add compliance scans with on-demand scan buttons, scan timeouts, regex guard, and admin run-now bypass fix.
- Add data analysis tools and dashboard visualizations.

### Device upgrades
- Add device upgrade orchestration with persisted scheduled-at and task rehydration after restart.
- Various reliability and UX fixes to the upgrade flow.

### Playbooks & jobs
- Refactor netmiko helpers into shared module; replace the `config_backup` playbook with first-class in-app config-backup downloads.
- Add job orchestration with dry-run support.
- Fix scheduled-job execution and polling reliability.

### Frontend
- Begin React migration: ports of Settings, Compliance, Device Detail, Federation, Floor Plan, Network Tools, and Lab pages.
- Rebuild React shell to mirror the legacy SPA chrome for a seamless cutover.
- Drop PatternFly in favor of legacy CSS for visual consistency during migration.
- Upgrade React, Vite, and tooling to current majors.
- Break the legacy `app.js` into per-feature modules to reduce coupling and improve load time.
- Improve theme system: smoother theme switching, fixed lag, removed redundant themes.

### Inventory & UX
- Add per-user inventory group ordering, density toggle, and collapsible groups (migration 0028).
- Collapse the Network tab into a smaller set of consolidated tabs while preserving every feature.
- Add admin-controlled feature visibility for nav entries (Settings → Feature visibility).
- Smoother scrolling and corrected gutter rendering in code-editor modals.
- Align password minimum length between UI and backend.

### Documentation
- Add SQLite-to-Postgres migration runbook.
- Linux deploy hardening: backup procedures, path cleanup, and bootstrap fix.

## 0.2.0 — 2026-03-05
- Add shared semantic version constant and `python templates/run.py --version` CLI output.
- Wire API metadata version to shared app version.
- Improve deployability docs and compose persistence (named volumes, restart policy, health endpoint).
- Add operator runbook with apply flow, rollback steps, and mismatch FAQ.
- Add performance/scale limits and data retention documentation.
- Add configurable API timeout/retry/backoff for FTD importer and cleanup scripts.
- Add MIT `LICENSE`.

## 0.1.0 — 2026-03-04
- Add CI workflow (lint, type-check, tests) and pinned dependency files.
- Add Ruff, mypy, pytest, and pre-commit configs.
- Add unit tests for converter routes with fixtures.
- Add Dockerfile and docker-compose for containerized runs.
- Add .env.example for configuration and starter operator docs footprint.
