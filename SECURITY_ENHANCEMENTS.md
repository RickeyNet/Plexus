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

- [x] **LDAP injection in authentication** — User-supplied `username` from the login form is inserted into LDAP filter expressions and DN templates via `.replace("{username}", username)` without calling `ldap.filter.escape_filter_chars()` (`netcontrol/routes/auth.py:261,270,327,354`). No input validation exists on the username field. An attacker can submit `*` to match every directory account or inject filter operators to bypass authentication. Fixed: added `escape_dn_chars()` for DN templates and `escape_filter_chars()` for search filters at all 4 injection points.
- [x] **Stored XSS via SVG graph export** — The SVG export endpoint embeds the graph template `name` field directly into an SVG `<text>` element via f-string interpolation with no XML escaping (`netcontrol/routes/graph_export.py:248`). Any authenticated user can create templates with arbitrary names. The SVG is served with `image/svg+xml` content type, so browsers execute inline scripts. Fixed: applied `xml.sax.saxutils.escape()` to the title in both the SVG stub and the embed HTML template.
- [x] **Stored XSS via WebSocket device status updates** — The live WebSocket handler for device status inserts `data.error_message` into the DOM via `innerHTML` without `escapeHtml()` (`netcontrol/static/js/app.js:13071`), while the initial render path correctly escapes. User-controlled data from `image_map` flows into error messages and executes in other users' browsers. Fixed: added `escapeHtml()` to both the `title` attribute and inner content.
- [x] **Path traversal via image_map in transfer phase** — `os.path.join(SOFTWARE_IMAGES_DIR, target_image)` used raw user-supplied `target_image` from campaign `image_map` without sanitization (`netcontrol/routes/upgrades.py:925`). An attacker could exfiltrate arbitrary server files via SCP to a device they control. Fixed: apply `os.path.basename()` before path construction with `realpath` confinement check.
- [x] **Path traversal via upload filename** — `file.filename` from multipart upload used directly in `os.path.join()` without `os.path.basename()` (`netcontrol/routes/upgrades.py:164`), enabling arbitrary file write. Fixed: added `os.path.basename()` sanitization.
- [x] **Path traversal in delete_image()** — `img["filename"]` from database used in `os.path.join(SOFTWARE_IMAGES_DIR, img["filename"])` without `os.path.basename()` (`netcontrol/routes/upgrades.py:252`). If a malicious filename was stored prior to upload sanitization fix, it could delete arbitrary files. Fixed: added `os.path.basename()` and `os.path.realpath()` confinement check.
- [x] **Unauthenticated WebSocket: deployment streaming** — `/ws/deployment/{job_id}` accepts connections without any session validation (`netcontrol/routes/deployments.py:831`), unlike other WebSocket endpoints (jobs, upgrades, config-capture) which properly check session tokens. Any unauthenticated user can observe deployment output. Fixed: added session/user/feature validation matching the pattern used by jobs and config-capture WebSocket handlers.
- [x] **Unauthenticated WebSocket: config revert streaming** — `/ws/config-revert/{job_id}` has no authentication check (`netcontrol/routes/config_drift.py:898`). The config-capture WebSocket in the same file properly validates sessions. Fixed: added matching session/user/feature verification before `websocket.accept()`.
- [x] **Netmiko command injection via image names** — User-supplied `image_name` and `dest_path` from campaign data are interpolated directly into device CLI commands via f-strings: `dir {dest_path}{image_name}` (`netcontrol/routes/upgrades.py:1405`), `verify /md5 {dest_path}{image_name}` (line 1416), and `install add file {full_path} activate commit` (line 1130). Fixed: added `_validate_cli_inputs()` with regex allowlists — image names must be `[A-Za-z0-9._-]+` and dest_path must match `[a-z]+[0-9]*:/?`. Validation is called in both `_device_transfer` and `_device_activate` before any CLI commands.

## Medium

- [x] **Missing database indexes** — Only 7 indexes across 30+ tables (`routes/database.py:643-656`). Add indexes on `jobs(created_at, status)`, `hosts(group_id)`, `users(username)`, `audit_events(created_at)`, and other commonly queried foreign keys.
- [x] **No schema migration framework** — Schema changes use manual `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` at startup (`routes/database.py:1162-1179`). No version tracking, no rollback, concurrent startup race risk. Fixed: implemented `routes/migrations/` framework with versioned migration files, a `schema_migrations` tracking table, advisory/file locking for concurrent startup safety, and automatic bootstrapping for existing databases. All inline migrations consolidated into `0001_baseline.py`.
- [x] **SQL injection in migration tool** — Table and column names interpolated directly into SQL via f-strings (`tools/migrate_sqlite_to_postgres.py:75-139`). Validate names against a whitelist of known tables.
- [x] **Console logging of sensitive data** — Multiple `console.log()` calls expose host IPs, user profiles, and playbook details in browser DevTools (`netcontrol/static/js/app.js:5572,5930,5998,6599`). Remove or gate behind a debug flag.
- [x] **Frontend memory leaks** — `setInterval` instances for elapsed time displays not always cleared on abnormal modal closure (`netcontrol/static/js/app.js:2483-2489`). Event listeners for device detail time ranges accumulate without cleanup (line 523).
- [x] **Unvalidated ad-hoc IPs in job execution** — Ad-hoc IP addresses passed to jobs aren't validated against reserved ranges like localhost or link-local (`netcontrol/routes/jobs.py:130-137`), enabling internal network scanning.
- [x] **Cookie `secure` flag conditional on config** — Session cookies only set `secure=True` when `APP_HTTPS=true` (`netcontrol/routes/auth.py:568,610`). If a reverse proxy handles TLS termination, cookies may be sent over HTTP.
- [x] **Missing CSRF token on CSV export** — The CSV export `fetch()` call sends credentials but no CSRF token header (`netcontrol/static/js/app.js:3340`).
- [x] **Multiple innerHTML XSS in app.js** — Several locations insert API/user data into `innerHTML` without `escapeHtml()`: credential names in `<option>` tags (line 4757), topology change hostnames/interfaces (lines 3002-3007), search query reflection (line 12044), topology search results (lines 2848-2850), and ~8 error message displays using `${error.message}`. Fixed: applied `escapeHtml()` to all 25+ unescaped interpolation sites across credential dropdowns, topology changes, topology search (escape-then-highlight), MAC tracking results/history, traffic analysis tables, upgrade campaign lists/details, and all 5 page-load error handlers.
- [x] **IDOR in credentials update/delete** — Ownership check in credentials endpoints skips validation when `owner_id` is NULL (`netcontrol/routes/credentials.py:50-90`). Any authenticated user can modify or delete shared credentials with no owner. Fixed: added `_can_modify()` helper enforcing owner-or-admin policy — unowned credentials (NULL `owner_id`) now require admin role. List endpoint also restricted so non-admins only see their own credentials. All endpoints now require authentication explicitly.

## Low

- [x] **Bare exception handlers in database layer** — Multiple `except Exception:` blocks silently swallow errors in host info updates and topology changes (`routes/database.py:6089,6228,6410,6423`). Add logging to all exception handlers.
- [x] **HSTS disabled by default** — `APP_HSTS=false` in `.env.example` even when HTTPS is enabled. Should default to `true` when `APP_HTTPS=true`.
- [x] **Dependabot monthly schedule** — Monthly update schedule in `.github/dependabot.yml` means security patches could be delayed up to 30 days. Change to weekly.
- [x] **Loose dependency version ranges** — `python-ldap>=3.4,<4`, `pysnmp>=7.1,<8`, `ansible-runner>=2.4,<3` in `requirements.txt` allow potentially breaking minor version updates. Pin to patch-level versions.

## Post-audit hardening (security review pass 2)

- [x] **Missing security headers** — Only HSTS was set. Added `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and `Content-Security-Policy` (script-src 'self' + CDN, no unsafe-inline for scripts, frame-ancestors 'none').
- [x] **OpenAPI docs exposed unauthenticated** — `/docs`, `/redoc`, `/openapi.json` were in PUBLIC_PATHS, leaking the full API schema. Removed from public paths; docs endpoints now disabled by default (`APP_ENABLE_DOCS=true` to re-enable).
- [x] **Encryption key file hardening** — `routes/crypto.py` had no key validation, no atomic write, no permission warning, and decrypt errors leaked `InvalidToken` tracebacks. Rewrote: validates key length/encoding on load, warns on loose file permissions, uses atomic write (tmp+rename) for key creation, catches `InvalidToken` with a safe error message, handles empty strings gracefully.
- [x] **No upload size limit** — Image upload (`/api/upgrades/images`) had no size cap, enabling disk exhaustion. Added streaming size check with 2 GiB default limit (`PLEXUS_MAX_IMAGE_UPLOAD_MB` env var), plus filename character validation.
- [x] **Remaining `str(exc)` in topology HTTP responses** — Three endpoints in `topology.py` still leaked exception details: build-graph, group-discovery, and full-discovery. Replaced with generic messages.
- [x] **Authorization matrix documented** — Created `AUTHORIZATION_MATRIX.md` mapping every endpoint to its auth/feature/admin requirement.

### Verified secure (no action needed)

- [x] **Encryption** — AES-256-GCM (`AESGCM`) with random 96-bit nonce per message (`routes/crypto.py:118-131`). Legacy Fernet-encrypted values (AES-128-CBC + HMAC-SHA256) are transparently decrypted on read for backward compatibility.
- [x] **Session tokens** — `itsdangerous.URLSafeTimedSerializer` uses HMAC-SHA1 with `hmac.compare_digest()` internally (timing-safe). 24h expiry enforced.
- [x] **API token comparison** — Uses `secrets.compare_digest()` (constant-time).
- [x] **CSRF protection** — Signed, time-limited, user-bound tokens on all state-changing cookie-auth requests.
- [x] **Password hashing** — PBKDF2-SHA256 with 600k iterations and random salt.
- [x] **SQL queries** — All *values* use parameterized `?` placeholders. Column/table names in dynamic `UPDATE SET` clauses are hardcoded Python strings (not user-controlled). Verified across `database.py`.
- [ ] **Playbook execution** — Python playbooks require server-side registered classes (cannot inject arbitrary code via API). Ansible playbooks run user YAML by design — currently gated by `jobs` feature which non-admins may have; should be restricted to admin role only.

### Remaining risks (accepted or deferred)

- [ ] **SSRF via SNMP/Netmiko** — Authenticated users can target arbitrary IPs for discovery/jobs/upgrades. Ad-hoc IPs are validated against reserved ranges, but inventory hosts are not restricted. Mitigation: feature-gated access, audit logging. Full fix would require an IP allowlist.
- [ ] **Ansible playbook RCE** — Admin users can execute arbitrary Ansible YAML. This is by design but should be restricted to admin role only (currently gated by `jobs` feature which non-admins may have).
- [ ] **Dependency CVEs** — `pip-audit` and `bandit` are in CI (`requirements-dev.txt`). Consider adding `safety` or Snyk for broader CVE coverage. Run `pip-audit` locally before releases.
