# Developer Setup (WSL2 + Docker + Postgres)

How to run Plexus locally so that what you test matches what the VM runs.

## Why this exists

The deployed stack (`docker-compose.yml`) is PostgreSQL 16 + nginx (TLS, HSTS,
Secure cookies, `FORWARDED_ALLOW_IPS=*`) + the hashed `requirements-lock.txt` +
the cloud SDKs (`INSTALL_CLOUD_SDKS=true`). A bare `python templates/run.py` on
Windows with SQLite differs from it in ways that hide real bugs:

- **Framework versions.** A local `pip install` can lag the lock (for example
  starlette 0.52 locally vs 1.6.0 pinned).
- **SQLite vs Postgres.** Postgres goes through the SQL translation layer in
  `routes/database.py`: `lastrowid` only works for tables listed in
  `_INSERT_ID_TABLES`, `LIKE` is case-sensitive, and datetime math is
  engine-specific.
- **Missing cloud SDKs.** Cloud Visibility Discover and pulls take the
  "SDK not installed" branch.
- **No reverse proxy.** No HTTPS/HSTS/CSP, and the client IP is always
  `127.0.0.1`, so rate limits and lockouts behave differently.
- **Vite dev server is not the built bundle.** `tsc` errors fail the Docker
  build but not `npm run dev`.

So develop inside WSL2 (Ubuntu 24.04) against the same pieces, using two loops:
Loop A (the full stack) and Loop B (Postgres in Docker, app from source).

## Prerequisites (WSL2 Ubuntu 24.04)

1. **Clone into the WSL filesystem** (`~/code/plexus`), not `/mnt/c/...`. Bind
   mounts and file watching across the Windows boundary are slow, and you risk
   picking up Windows-built `node_modules`.
2. **Docker Engine + compose plugin** from Docker's apt repository; follow
   `deploy/DEPLOYMENT.md`, "Step 1: Install Docker" (Ubuntu's `docker.io`
   package lacks compose). Then add yourself to the `docker` group and re-login
   (or run `newgrp docker`):
   ```bash
   sudo usermod -aG docker $USER
   ```
   Docker Engine inside WSL needs systemd. Add this to `/etc/wsl.conf`:
   ```ini
   [boot]
   systemd=true
   ```
   then run `wsl --shutdown` from Windows, reopen the shell and check with
   `systemctl is-system-running`. Alternative: Docker Desktop with WSL
   integration enabled for your distro.
3. **Python 3.14** (Ubuntu 24.04 ships 3.12; the code uses 3.14-only syntax):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   uv python install 3.14
   ```
4. **Node 24 via nvm inside WSL.** Never run `npm ci` with the Windows `node`
   from `/mnt/c` (it is first on PATH in a default WSL shell):
   ```bash
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
   exec bash
   nvm install 24
   ```

## Loop A: full stack (what the VM runs)

1. Generate `.env` (random secrets) and self-signed certs in `certs/`, point
   CORS at localhost, then build and start:
   ```bash
   bash deploy/setup.sh
   sed -i 's|^APP_CORS_ORIGINS=.*|APP_CORS_ORIGINS=https://localhost|' .env
   docker compose up --build -d
   docker compose logs -f plexus
   ```
2. Open `https://localhost`, accept the certificate warning, log in as
   `admin` / `netcontrol` and change the password (forced).
3. Rebuild after code changes, or reset everything including the database:
   ```bash
   docker compose up --build -d plexus
   docker compose down -v
   ```

Notes:

- `.env` sets `APP_COOKIE_SECURE=true`, so logging in over plain
  `http://127.0.0.1:8080` silently fails (the browser drops the Secure
  cookie). Use `https://localhost`, or set `APP_COOKIE_SECURE=false`.
- Compose always runs on Postgres: its `environment:` block overrides `.env`.
  For a SQLite container, build and run the image directly:
  ```bash
  docker build -t plexus-app:local .
  docker run -e APP_DB_PATH=/app/state/netcontrol.db \
    -e APP_SESSION_KEY_FILE=/app/state/session.key \
    -e APP_ENCRYPTION_KEY_FILE=/app/state/netcontrol.key \
    -v plexus-sqlite:/app/state -p 127.0.0.1:8080:8080 \
    -e APP_ENV=dev plexus-app:local
  ```

## Loop B: fast loop (Postgres in Docker, app from source)

1. Run `bash deploy/setup.sh` once so `.env` exists (it holds
   `POSTGRES_PASSWORD`).
2. Start Postgres, create the venv, install dependencies and run the app:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres
   uv venv --python 3.14 .venv && source .venv/bin/activate
   uv pip install --require-hashes -r requirements-lock.txt
   uv pip install -r requirements-dev.txt -r requirements-cloud.txt
   export APP_DB_ENGINE=postgres
   export APP_DATABASE_URL="postgresql://plexus:$(grep ^POSTGRES_PASSWORD= .env | cut -d= -f2)@127.0.0.1:5432/plexus"
   export APP_ENV=dev
   python templates/run.py
   ```
3. In a second shell, start the Vite dev server:
   ```bash
   cd netcontrol/static/frontend && npm ci && npm run dev
   ```
   Open `http://localhost:5173/frontend/`; `/api`, `/static` and `/ws` are
   proxied to the backend on 8080. Without Vite, run `npm run build` and open
   `http://127.0.0.1:8080/frontend/`.

Why it looks like this:

- `templates/run.py` does not read `.env`; the variables must be exported.
- The hashed lock goes in its own install: `--require-hashes` cannot be mixed
  with the unhashed dev/cloud requirement files.
- `APP_ENV=dev` bootstraps `admin` / `netcontrol` without a forced password
  change.
- `docker-compose.dev.yml` only publishes Postgres on `127.0.0.1:5432` and is
  never auto-loaded; pass it explicitly with `-f`.

To avoid retyping the exports, keep them in a shell function in `~/.bashrc`
(run it from the repo root):

```bash
plexus-dev() {
  source .venv/bin/activate
  export APP_DB_ENGINE=postgres APP_ENV=dev
  export APP_DATABASE_URL="postgresql://plexus:$(grep ^POSTGRES_PASSWORD= .env | cut -d= -f2)@127.0.0.1:5432/plexus"
}
```

Loop B skips nginx and HTTPS, so run Loop A before shipping.

## Tests and checks

These mirror `.github/workflows/ci.yml`.

Python (repo root, venv active):

```bash
ruff check .
mypy netcontrol templates
pytest -n auto        # main suite, SQLite

# Postgres smoke test against the Loop B database
APP_DB_ENGINE=postgres APP_DATABASE_URL="$APP_DATABASE_URL" pytest tests/test_postgres_backend.py -q
```

The main suite is SQLite-only, so check new SQL by hand on Postgres (Loop B).

Frontend (`netcontrol/static/frontend`):

```bash
npm run lint
npm run typecheck
npm test
npm run build         # tsc + vite + viewer bundle, exactly what the Docker build runs
```

Run `npm run build` before Loop A to catch type errors early instead of in the
image build.

## Before calling a change done

Re-verify in Loop A:

- WebSocket streams (job output, deployments, upgrades) through nginx over `wss`.
- Login, CSRF and cookies over HTTPS with the dev bootstrap off.
- Any new `INSERT` / `LIKE` / datetime SQL on Postgres.
- Cloud Visibility with the real SDKs.
- A clean `npm run build`.

## Troubleshooting

- `docker: permission denied` → not in the `docker` group yet; run
  `sudo usermod -aG docker $USER` and re-login (or `newgrp docker`).
- `Cannot connect to the Docker daemon` → systemd not enabled in WSL, or Docker
  Desktop WSL integration is off.
- Port 8080, 5432 or 443 already in use (a Windows-side Plexus or Postgres) →
  stop it, or change the published port in the compose override.
- `POSTGRES_PASSWORD must be set` → `.env` is missing; run
  `bash deploy/setup.sh`.
- Login works, then you are logged out immediately → Secure cookie over plain
  HTTP; use `https://localhost` or set `APP_COOKIE_SECURE=false`.
- `npm run build` fails with native-module errors → Windows `node_modules`
  copied in; `rm -rf node_modules && npm ci` with the WSL node.
- `SyntaxError` on `except A, B:` → Python older than 3.14; use the uv venv.
