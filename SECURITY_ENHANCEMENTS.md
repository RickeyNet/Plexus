# Security Enhancements

## Critical

- [x] **XSS in topology node details panel** — User-controlled data (`node.label`, `node.ip`) is interpolated directly into an `onclick` handler and raw HTML without escaping (`netcontrol/static/js/app.js:2375-2422`). Apply `escapeHtml()` to all user-controlled fields and replace inline `onclick` with event delegation using data attributes.
- [x] **Path traversal in playbook file reader** — `os.path.join(playbooks_dir, filename)` used without verifying the resolved path stays within `playbooks_dir` (`netcontrol/routes/playbooks.py:142-161`). The upload path (line 87) has this check but the read path does not. Add `os.path.normpath()` containment validation.
- [x] **Hardcoded default admin credentials** — Default `admin/netcontrol` created on first startup (`netcontrol/app.py:343-349`) and demo credentials `netadmin/cisco123` seeded (`routes/seed.py:128-133`). Generate a random initial password or require input at first startup.
- [x] **Assertions used for security checks** — `assert _csrf_serializer is not None` guards CSRF validation (`netcontrol/app.py:267,273`). Python's `-O` flag strips assertions. Replace with explicit `if ... is None: raise RuntimeError(...)`.

## High

- [x] **Docker container runs as root** — No `USER` directive in `Dockerfile`. Add a non-root user (`RUN useradd -m -u 1000 plexus` / `USER plexus`).
- [x] **Swallowed exceptions in LDAP auth** — Bare `except Exception: pass` blocks silently discard authentication errors (`netcontrol/routes/auth.py:336-348`). Add `LOGGER.warning()` calls so failures are visible for security monitoring.
- [x] **Permissive CORS configuration** — `allow_methods=["*"]` and `allow_headers=["*"]` with `allow_credentials=True` (`netcontrol/app.py:731-737`). Restrict to specific methods (`GET, POST, PUT, DELETE, OPTIONS`) and headers (`Content-Type, X-CSRF-Token, X-API-Token, Authorization`).
- [x] **No API rate limiting beyond login** — Only the login endpoint has rate limiting. All other endpoints (job launch, discovery, inventory) have no throttling, enabling resource exhaustion.
- [x] **Missing `.dockerignore`** — Docker build context includes `.venv/`, `.git/`, `*.db`, `*.key`, and other sensitive files. Create a `.dockerignore` excluding secrets, databases, caches, and dev artifacts.
- [x] **Insecure LDAP TLS settings** — LDAP connections use `OPT_X_TLS_ALLOW` permitting invalid certificates (`netcontrol/routes/auth.py:240-242`), enabling MITM attacks. Require certificate validation for production LDAP servers.
- [x] **Plaintext credentials in CI/CD** — Hardcoded `POSTGRES_USER: plexus` / `POSTGRES_PASSWORD: plexus` in GitHub Actions workflow (`.github/workflows/ci.yml:65-70`). Use GitHub secrets or document that these are test-only values.

- [ ] **LDAP injection in authentication** — User-supplied `username` from the login form is inserted into LDAP filter expressions and DN templates via `.replace("{username}", username)` without calling `ldap.filter.escape_filter_chars()` (`netcontrol/routes/auth.py:261,270,327,354`). No input validation exists on the username field. An attacker can submit `*` to match every directory account or inject filter operators to bypass authentication. Escape all user input with `escape_filter_chars()` before LDAP interpolation.
- [ ] **Stored XSS via SVG graph export** — The SVG export endpoint embeds the graph template `name` field directly into an SVG `<text>` element via f-string interpolation with no XML escaping (`netcontrol/routes/graph_export.py:248`). Any authenticated user can create templates with arbitrary names. The SVG is served with `image/svg+xml` content type, so browsers execute inline scripts. Escape the title with `xml.sax.saxutils.escape()` before interpolation.

## Medium

- [x] **Missing database indexes** — Only 7 indexes across 30+ tables (`routes/database.py:643-656`). Add indexes on `jobs(created_at, status)`, `hosts(group_id)`, `users(username)`, `audit_events(created_at)`, and other commonly queried foreign keys.
- [ ] **No schema migration framework** — Schema changes use manual `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` at startup (`routes/database.py:1162-1179`). No version tracking, no rollback, concurrent startup race risk. Consider adopting Alembic.
- [x] **SQL injection in migration tool** — Table and column names interpolated directly into SQL via f-strings (`tools/migrate_sqlite_to_postgres.py:75-139`). Validate names against a whitelist of known tables.
- [x] **Console logging of sensitive data** — Multiple `console.log()` calls expose host IPs, user profiles, and playbook details in browser DevTools (`netcontrol/static/js/app.js:5572,5930,5998,6599`). Remove or gate behind a debug flag.
- [x] **Frontend memory leaks** — `setInterval` instances for elapsed time displays not always cleared on abnormal modal closure (`netcontrol/static/js/app.js:2483-2489`). Event listeners for device detail time ranges accumulate without cleanup (line 523).
- [x] **Unvalidated ad-hoc IPs in job execution** — Ad-hoc IP addresses passed to jobs aren't validated against reserved ranges like localhost or link-local (`netcontrol/routes/jobs.py:130-137`), enabling internal network scanning.
- [x] **Cookie `secure` flag conditional on config** — Session cookies only set `secure=True` when `APP_HTTPS=true` (`netcontrol/routes/auth.py:568,610`). If a reverse proxy handles TLS termination, cookies may be sent over HTTP.
- [x] **Missing CSRF token on CSV export** — The CSV export `fetch()` call sends credentials but no CSRF token header (`netcontrol/static/js/app.js:3340`).

## Low

- [x] **Bare exception handlers in database layer** — Multiple `except Exception:` blocks silently swallow errors in host info updates and topology changes (`routes/database.py:6089,6228,6410,6423`). Add logging to all exception handlers.
- [x] **HSTS disabled by default** — `APP_HSTS=false` in `.env.example` even when HTTPS is enabled. Should default to `true` when `APP_HTTPS=true`.
- [x] **Dependabot monthly schedule** — Monthly update schedule in `.github/dependabot.yml` means security patches could be delayed up to 30 days. Change to weekly.
- [x] **Loose dependency version ranges** — `python-ldap>=3.4,<4`, `pysnmp>=7.1,<8`, `ansible-runner>=2.4,<3` in `requirements.txt` allow potentially breaking minor version updates. Pin to patch-level versions.
