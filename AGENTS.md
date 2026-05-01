# Plexus — Agent Context

## Project Overview
Plexus is a network automation platform built with FastAPI (Python) + vanilla JS SPA.
It manages network device inventory, topology discovery, config management, monitoring,
and IOS-XE upgrades via SNMP, Netmiko, and Ansible.

## Architecture
- **Backend**: FastAPI app in `netcontrol/app.py`, routes split across `netcontrol/routes/`
- **Database**: SQLite (default) or Postgres (`APP_DB_ENGINE=postgres`), abstracted in `routes/database.py`
- **Frontend**: Single-page app in `netcontrol/static/` — `index.html`, `js/app.js`, `js/api.js`
- **Encryption**: Fernet (AES-128-CBC + HMAC-SHA256) via `routes/crypto.py`, key in `netcontrol.key` at the repo root (override via `APP_ENCRYPTION_KEY_FILE`)
- **Auth**: Session cookies (itsdangerous signed tokens), CSRF protection, PBKDF2-SHA256 passwords
- **Playbooks**: Python classes in `templates/playbooks/` registered via `@register_playbook` decorator
- **Migrations**: Versioned files in `routes/migrations/`, run by `routes/migrations/runner.py`

## Key Patterns
- All SQL uses parameterized queries (`?` placeholders, auto-converted to `$N` for Postgres)
- Route modules use late-binding init functions (`init_jobs()`, `init_auth()`, etc.) to avoid circular imports
- Frontend uses `escapeHtml()` (defined at ~line 6396 of app.js) for all user data in innerHTML
- `{{secret.NAME}}` syntax in config templates resolves encrypted variables at job execution time
- Secret values are redacted from job logs via `redact_values()` in `routes/secret_resolver.py`

## Security Rules
- Never put `str(exc)` in HTTP error responses — use generic messages, log details server-side
- Always use `escapeHtml()` for user/API data in innerHTML contexts
- Path operations must use `os.path.basename()` + `os.path.realpath()` confinement checks
- Credential mutations require owner-or-admin check via `_can_modify()`
- Secret variable mutations require admin role
- WebSocket endpoints must validate session cookie before `websocket.accept()`

## Development
- Windows dev machine, Linux deployment target
- No bash available — use `cmd` or PowerShell for shell commands
- Tests: `pytest` with `pytest-asyncio`, coverage gate at 30%
- Linting: `ruff`, type checking: `mypy`, security: `bandit` + `pip-audit`
- CI: GitHub Actions with CodeQL scanning

## File Size Warning
- `netcontrol/static/js/app.js` is ~13,000 lines — use offset/limit when reading
- `routes/database.py` is ~8,700 lines — same approach
