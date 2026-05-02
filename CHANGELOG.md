# Changelog

## Unreleased
- Add digital twin / lab mode (Phase A): lab environments and cloned-from-host devices for offline config-plane simulation. Apply proposed commands or templates against a snapshot, see unified diff plus risk score, persist run history, and promote successful runs into the Deployments pipeline. Migration 0029 adds `lab_environments`, `lab_devices`, `lab_runs`. New `lab` feature flag and React page at `/frontend/lab`.

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
