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
- [ ] Add integration tests for protected API behavior when `APP_REQUIRE_API_TOKEN=true`.
- [ ] Add tests for playbook filename/path sanitization edge cases and malicious input attempts.
- [ ] Add end-to-end smoke tests for convert -> diff -> import workflow with artifact validation.
- [ ] Enforce minimum test coverage threshold in CI and fail on critical-module regression.
- [ ] Add CI security gates (`pip-audit`, `bandit`, optional CodeQL) and publish SBOM artifacts for releases.
- [ ] Add release automation to validate changelog/version consistency and publish container images.
- [ ] Refine README setup steps (`.venv` consistency, run commands) and add incident-response runbook scenarios.
