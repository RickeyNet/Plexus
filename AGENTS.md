# Plexus - Agent Context

## Project Overview
Plexus is a network automation platform built with FastAPI (Python) + a React/TypeScript SPA.
It manages network device inventory, topology discovery, config management, monitoring,
and IOS-XE upgrades via SNMP, Netmiko, and Ansible.

## Architecture
- **Backend**: FastAPI app in `netcontrol/app.py`, routes split across `netcontrol/routes/`
- **Database**: PostgreSQL (`APP_DB_ENGINE=postgres`, the only backend; the SQLite engine was removed). Queries and migrations use a portable SQLite-style dialect (`?`, `datetime('now', ...)`, `INSERT OR IGNORE`) that `routes/database.py` translates for Postgres. Tests run on Postgres and require `PLEXUS_TEST_PG_URL` (see `DEVSETUP.md`); legacy SQLite installs migrate with `tools/migrate_sqlite_to_postgres.py`
- **Frontend**: React 19 + TypeScript + Vite SPA in `netcontrol/static/frontend/`, built to `frontend/dist/` and served at `/frontend` (the legacy vanilla-JS SPA was removed after the migration - history in `docs/FRONTEND_MIGRATION.md`, conventions in `FRONTEND_STYLE.md`)
- **Encryption**: Fernet (AES-128-CBC + HMAC-SHA256) via `routes/crypto.py`, key in `netcontrol.key` at the repo root (override via `APP_ENCRYPTION_KEY_FILE`)
- **Auth**: Session cookies (itsdangerous signed tokens), CSRF protection, PBKDF2-SHA256 passwords
- **Playbooks**: Python classes in `templates/playbooks/` registered via `@register_playbook` decorator
- **Migrations**: Versioned files in `routes/migrations/`, run by `routes/migrations/runner.py`

## Key Patterns
- All SQL uses parameterized queries (`?` placeholders, auto-converted to `$N` for Postgres)
- Route modules use late-binding init functions (`init_jobs()`, `init_auth()`, etc.) to avoid circular imports
- Frontend renders user data through React (JSX auto-escapes); avoid `dangerouslySetInnerHTML`
- `{{secret.NAME}}` syntax in config templates resolves encrypted variables at job execution time
- Secret values are redacted from job logs via `redact_values()` in `routes/secret_resolver.py`

## Code Reuse
- Search for an existing helper before writing a new one; reuse or extend it instead of adding a duplicate
- Logic needed in more than one module goes in one shared place (utility module, base class, shared hook/component) and is imported from both
- Consolidate duplicated code you touch when it is small and safe; otherwise flag it in the summary
- Delegated worker prompts carry this rule and name the shared modules in scope

## CI Compliance
- `.github/workflows/ci.yml` is the contract: read the jobs covering the files in scope before changing them, and run those steps locally with the same commands and flags CI uses (the `pytest` console script, `ruff check`, `mypy netcontrol templates`, `bandit`, `pip-audit`, the frontend lint/typecheck/test/build)
- A change is not done until the CI steps that cover it pass locally; if a step cannot be reproduced, say so explicitly
- A new feature that adds a dependency, test requirement (service, env var, system package, SDK), tool, or new code area updates `ci.yml` and the requirements/lock/coverage-gate files in the same change
- Tests must not depend on anything CI does not install: `importorskip` the optional package or add it to the CI install
- On a CI failure, find the exact failing step (jobs API or annotations), reproduce it, and fix the root cause; never loosen a gate or skip a check to go green without being asked
- Delegated worker prompts name the CI steps covering their scope and the commands to run before reporting

## Security Rules
- Never put `str(exc)` in HTTP error responses - use generic messages, log details server-side
- Never use `dangerouslySetInnerHTML` with user/API data; let JSX escape it
- Path operations must use `os.path.basename()` + `os.path.realpath()` confinement checks
- Credential mutations require owner-or-admin check via `_can_modify()`
- Secret variable mutations require admin role
- WebSocket endpoints must validate session cookie before `websocket.accept()`

## Vendor Monitoring Parity Standard
Every vendor Plexus supports must meet the same monitoring bar. "Supported" means an
SSH/SNMP driver (`netcontrol/drivers/`: Cisco IOS/IOS XE/IOS XR/NX-OS/ASA/FTD, Juniper,
Arista, Fortinet, PAN-OS), an API integration (`netcontrol/integrations/`: Meraki, Cato,
Cisco FDM, Cisco FMC, Panorama, Appgate, AWS, Azure, GCP), or a cloud collector. Priority
vendors are Cisco, Cato, AWS and Azure; a gap there is a bug, not a backlog item.

- **Availability and SLA.** Every device, site, link, tunnel or cloud connection the
  vendor reports a state for feeds one availability pipeline: a persisted up/down/degraded
  state with transitions and outage history, a time-weighted uptime % over any window,
  latency/jitter/packet loss where the vendor exposes them, and SLA targets that are
  evaluated server-side on a schedule (never only in the browser) into `monitoring_alerts`
  and the notification channels. Inventory hosts use the poll pipeline
  (`netcontrol/routes/monitoring.py`); API-collected entities use the topology
  availability tracker fed from every stored snapshot. Rollups must outlive raw-poll
  retention so a 365-day SLA window is real.
- **Software and CVE.** Every device whose vendor exposes a software/firmware version is
  in the software tracker (`netcontrol/integrations/software/versions.py`, one platform
  key per OS). Every platform has an advisory source: a vendor vulnerability API where one
  exists (Cisco PSIRT openVuln today), otherwise an import/scrape of the vendor's security
  notices, and cloud providers use their native findings feeds (AWS Inspector/Security Hub,
  Azure Defender for Cloud). "Manual entry only" is an accepted gap only when documented in
  the coverage matrix with the reason.
- **Adding or changing a vendor** means updating, in the same change: the extractor that
  maps the vendor's status vocabulary to up/down/degraded/unknown, the version classifier,
  the advisory source (or the documented gap), tests built from the vendor's `sample.py`
  so they run without SDKs or network, the per-vendor doc, and the coverage matrix in
  `docs/vendor-monitoring-coverage.md`. A vendor row in that matrix must never claim
  coverage the code does not have.
- **Review check.** A worker or reviewer touching monitoring, SLA, software or an
  integration asks: does this vendor's data reach availability, SLA evaluation, version
  tracking and advisories the same way Cisco's does? If not, say so in the summary.

## Development
- Windows dev machine, Linux deployment target
- No bash available - use `cmd` or PowerShell for shell commands
- Tests: `pytest` with `pytest-asyncio`, coverage gate at 30%
- Full suite is slow serially (~18 min); use `pytest -n auto` (pytest-xdist) for ~4 min runs
- Linting: `ruff`, type checking: `mypy`, security: `bandit` + `pip-audit`
- CI: GitHub Actions with CodeQL scanning

## File Size Warning
- `routes/database.py` is ~8,700 lines - use offset/limit when reading
