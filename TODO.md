# Company-Readiness Plan (3 Weeks)

## Week 1: Baseline Quality & Installability
- [x] Dependencies: add pinned requirements (`requirements.txt`, `requirements-lock.txt`); choose pip; add `.env.example` with config keys.
- [x] Tooling: add `ruff` (lint/format), `mypy`, and `pre-commit` hooks (ruff, mypy, trailing whitespace).
- [x] Tests: create converter tests (happy-path conversion stub + import args) with fixtures in `tests/`.
- [x] CI: GitHub Actions pipeline running lint + type check + tests on push/PR.
- [x] Docs: expand README with quickstart, scope (FortiGate → FTD), and how to run dev server/CLI + Docker.

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
- [x] Add scheduled disk cleanup for `netcontrol/converter_sessions` backups and stale session directories based on retention settings.
- [x] Add import idempotency/checkpoint markers so failed staged imports can resume safely.
- [x] Add bounded concurrency controls for convert/import jobs to avoid FTD API saturation.
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
- [x] Converter stepper UI: visual progress bar for the 3-step convert/import/cleanup flow.
- [x] Keyboard shortcuts: Ctrl+K page switcher, Esc modal close, / to focus search.
- [x] Breadcrumb / page title bar: top bar with current page name and breadcrumb trail.
- [x] Custom scrollbar styling: thin themed scrollbars matching color palette.
- [x] Empty state illustrations: SVG illustrations with call-to-action on empty pages.
- [x] Responsive sidebar overlay: mobile hamburger toggle with slide-in overlay + backdrop.

## UI/UX Improvement Backlog (Post-Modernization)
- [x] Optimize Inventory load path: remove N+1 group->hosts requests by using a single inventory payload with embedded hosts.
- [x] Add page-level data cache + stale-while-revalidate behavior so nav switches feel instant and avoid full refetch every time.
- [x] Align converter stepper state with visible content: hide Cleanup until Step 3 and keep reset state consistent.
- [x] Add page-level search/filter/sort controls for Inventory, Playbooks, Jobs, Templates, and Credentials.
- [x] Reduce visual weight on Templates list (snippet/preview by default, full content on expand/edit).
- [x] Improve Jobs scanability with sticky filters (status/date/dry-run) and denser list/table view.
- [x] Add reduced-motion/performance mode for blur-heavy and infinite animations.
- [x] Improve modal accessibility (dialog semantics, focus trap, focus return, keyboard-only flow).
- [x] Add URL/deep-link support for internal pages (hash or pushState) so refresh/back keeps context.
- [x] Improve first paint by reducing remote font dependency (self-host or robust fallback stack).

## Week 7: PostgreSQL Optional Deployment (VM/Prod Focus)
- [ ] Add dual-backend database abstraction (`sqlite` + `postgres`) while preserving existing `routes.database` API surface.
- [ ] Add PostgreSQL schema bootstrap + migration-safe startup path (remove SQLite-specific assumptions for Postgres mode).
- [ ] Add Docker Compose PostgreSQL service and env-based backend selection.
- [ ] Add SQLite -> PostgreSQL migration utility with dry-run and parity verification.
- [ ] Add CI matrix coverage for SQLite and PostgreSQL backends on critical API/database tests.
- [ ] Update README and operator runbook for PostgreSQL deployment and backup/restore procedures.
