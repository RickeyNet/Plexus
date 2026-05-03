# Changelog

## Unreleased
- Add digital twin / lab mode (Phase A): lab environments and cloned-from-host devices for offline config-plane simulation. Apply proposed commands or templates against a snapshot, see unified diff plus risk score, persist run history, and promote successful runs into the Deployments pipeline. Migration 0029 adds `lab_environments`, `lab_devices`, `lab_runs`. New `lab` feature flag and React page at `/frontend/lab`.
- Add containerlab single-node runtime for lab mode (Phase B-1): a twin can now back its snapshot with a real virtual NOS (Arista cEOS, Nokia SR Linux, FRR, Linux) deployed via the host's containerlab CLI. New endpoints `GET /api/lab/runtime`, `POST /api/lab/devices/{id}/runtime/{deploy,destroy,refresh}`, `GET /api/lab/devices/{id}/runtime/events`, and `POST /api/lab/devices/{id}/simulate-live` (pushes commands via Netmiko, captures the real running-config back). Strict allowlist for node kinds and image references; subprocess invoked with explicit argv. Migration 0030 adds runtime fields to `lab_devices` and a `lab_runtime_events` audit log. React Lab page gains a Runtime card and live-mode simulate toggle.
- Operationally harden Phase B-1: simulate-live and Phase A simulate now feed compliance regressions from the source host's profiles into the risk score; startup reconciles in-flight `running` rows against `containerlab inspect` so a Plexus restart no longer leaves stale state; new background TTL reaper destroys idle labs (`PLEXUS_LAB_RUNTIME_TTL_SECONDS`, default 24h, `0` to disable; `PLEXUS_LAB_RUNTIME_TTL_INTERVAL_SECONDS` controls cadence); per-device topology workdir is removed after a successful destroy.
- Add multi-device lab topologies (Phase B-2): operators can now link N twins into a single containerlab deployment so routing/STP/LACP behaviors run end-to-end against real NOS images. Migration 0031 adds `lab_topologies`, `lab_topology_links`, and `lab_devices.topology_id`. New endpoints `GET|POST /api/lab/environments/{id}/topologies`, `GET|DELETE /api/lab/topologies/{id}`, `POST|DELETE /api/lab/topologies/{id}/devices[/{device_id}]`, `POST|DELETE /api/lab/topologies/{id}/links[/{link_id}]`, `POST /api/lab/topologies/{id}/{deploy,destroy,refresh}`. The YAML generator emits a `mgmt` subnet block when set, validates each member's kind/image, and rejects deploy when a member still has a free-standing runtime running. React Lab page gains a "Topologies (multi-device)" card with a list-based editor for members and links and runtime controls. Drag-and-drop canvas deferred to a follow-on.

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
