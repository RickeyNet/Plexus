# PostgreSQL Optional Deployment Plan

This plan adds PostgreSQL as the primary Docker deployment target while keeping SQLite as a local/dev fallback.

## Goals

- Keep existing SQLite workflow working for local development.
- Add PostgreSQL-backed runtime for VM/production deployments.
- Preserve current API behavior and schema semantics.
- Keep Docker as the default deployment method.

## Target Architecture

- App container: `plexus`
- Database container: `postgres`
- App database mode selected by env var.

Suggested env:

- `APP_DB_ENGINE=sqlite|postgres` (default: `sqlite`)
- `APP_DATABASE_URL=postgresql://<user>:<pass>@postgres:5432/<db>`
- Existing SQLite vars remain valid for `sqlite` mode.

## Scope Summary

The current data layer in `routes/database.py` is SQLite-coupled (`aiosqlite`, `PRAGMA`, `datetime('now')`, `lastrowid`, and migration logic using `PRAGMA table_info`).

Migration work must add a backend abstraction and normalize SQL and ID-return behavior.

## Phase 1: Backend Abstraction (Foundation)

Deliverables:

- Introduce DB backend selector (`sqlite` or `postgres`).
- Add DB adapter layer with common async methods:
  - `execute`
  - `fetchone`
  - `fetchall`
  - `commit`
  - `close`
  - insert helpers returning inserted IDs
- Keep `routes/database.py` public function signatures unchanged.

Acceptance:

- Existing tests continue passing in SQLite mode.

Estimate:

- 2-3 dev days.

## Phase 2: PostgreSQL Schema and Migrations

Deliverables:

- Add PostgreSQL schema bootstrap and idempotent migration path.
- Remove SQLite-only assumptions for PostgreSQL path:
  - `PRAGMA`-based introspection
  - `AUTOINCREMENT`
  - `datetime('now')`
  - retention query pieces using `julianday`
- Normalize all insert paths currently using `lastrowid`.

Acceptance:

- Clean DB init succeeds on fresh Postgres container.
- Existing API smoke tests pass in Postgres mode.

Estimate:

- 3-5 dev days.

## Phase 3: Docker and Runtime Wiring

Deliverables:

- Update `docker-compose.yml`:
  - add `postgres` service with persistent volume
  - add app dependency health check for postgres mode
- Keep SQLite-only compose path available for simple local use.
- Add `.env.example` entries for Postgres config.

Acceptance:

- `docker compose up --build` works in both:
  - SQLite mode
  - PostgreSQL mode

Estimate:

- 1-2 dev days.

## Phase 4: Data Migration Tool (SQLite -> PostgreSQL)

Deliverables:

- Add one-shot migration script to transfer existing data:
  - users, auth settings, inventory, hosts, playbooks, templates, credentials, jobs, job_events, audit_events
- Include dry-run and verification output.

Acceptance:

- Migration verification report shows row count parity per table.

Estimate:

- 2-3 dev days.

## Phase 5: Test Matrix and Docs

Deliverables:

- Expand CI to run critical tests against both backends.
- Add docs for:
  - local SQLite
  - Docker + PostgreSQL
  - migration playbook and rollback.

Acceptance:

- CI green for both backend modes.
- Runbook updated with Postgres operations and backup/restore notes.

Estimate:

- 2-3 dev days.

## Total Estimate

- Basic optional support: 5-8 dev days.
- Production-hardened dual-backend support: 2-4 weeks.

## Risks and Mitigations

- Risk: hidden SQLite-specific SQL behavior.
  - Mitigation: compatibility tests for each DB function cluster.
- Risk: migration mistakes in production data cutover.
  - Mitigation: dry-run checks plus row-count and checksum validation.
- Risk: performance regressions from generic abstraction.
  - Mitigation: backend-specific query tuning where needed.

## Initial Execution Order

1. Phase 1 foundation in `routes/database.py`.
2. Phase 3 docker/env wiring (safe to parallelize after foundation shape is decided).
3. Phase 2 SQL normalization and schema bootstrap.
4. Phase 4 migration tooling.
5. Phase 5 CI/docs hardening.
