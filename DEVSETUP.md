# Developer Setup (Docker + Postgres)

How to run Plexus locally so that what you test matches what the VM runs.
PostgreSQL in Docker is the only supported way to run or develop Plexus, on
Windows (Docker Desktop) or in WSL2.

## Why this exists

The deployed stack (`docker-compose.yml`) is PostgreSQL 16 + nginx (TLS, HSTS,
Secure cookies, `FORWARDED_ALLOW_IPS=*`) + the hashed `requirements-lock.txt` +
the cloud SDKs (`INSTALL_CLOUD_SDKS=true`). A bare `python templates/run.py`
without that setup differs from it in ways that hide real bugs:

- **Framework versions.** A local `pip install` can lag the lock (for example
  starlette 0.52 locally vs 1.6.0 pinned).
- **SQLite vs Postgres.** Postgres goes through the SQL translation layer in
  `routes/database.py`: `lastrowid` only works for tables listed in
  `_INSERT_ID_TABLES`, `LIKE` is case-sensitive, and datetime math is
  engine-specific. This is why SQLite is not a supported way to run the app;
  its engine is kept only for the in-process test suite and the legacy
  migration tool.
- **Missing cloud SDKs.** Cloud Visibility Discover and pulls take the
  "SDK not installed" branch.
- **No reverse proxy.** No HTTPS/HSTS/CSP, and the client IP is always
  `127.0.0.1`, so rate limits and lockouts behave differently.
- **Vite dev server is not the built bundle.** `tsc` errors fail the Docker
  build but not `npm run dev`.

So develop against the same pieces, using two loops: Loop A (the full stack)
and Loop B (Postgres in Docker, app from source). On Windows use Docker Desktop
with a Windows venv (next section); WSL2 (Ubuntu 24.04) is the alternative.

**Pick one path per checkout:**

- **Windows path:** Docker Desktop + a Windows venv + PowerShell. The repo,
  venv, Node and editor all live on the Windows side. No Ubuntu distro needed.
- **WSL2 path:** clone again inside Ubuntu and use the Linux toolchain there
  (Python, Node, Docker all inside WSL).

Don't mix them for one checkout (for example a Windows venv plus WSL Node on
the same `node_modules`).

## Windows: Docker Desktop + Windows venv

Everything here runs on the Windows side. Ubuntu (or any other WSL distro) is
not needed: Docker Desktop runs its engine in its own hidden WSL2 distro,
`docker-desktop`, which is what `wsl -l -v` lists. The
`wsl --install --no-distribution` step below only installs the WSL2 kernel for
that backend. Installing Ubuntu is only for the separate WSL2 path.

### One-time prerequisites

In PowerShell **as Administrator**:

```powershell
wsl --install --no-distribution     # WSL2 kernel for Docker Desktop's backend
winget install -e --id Docker.DockerDesktop
```

Reboot, start Docker Desktop, then check from a normal PowerShell:

```powershell
docker compose version
```

Docker Desktop needs a paid subscription at larger companies; Podman Desktop is
the free alternative.

Install Python 3.14 and Node 24 if they are missing. Node is only needed for
the frontend (Vite, `npm run build`). After `winget install`, open a new
terminal so `python` and `node` are on PATH.

```powershell
winget install -e --id Python.Python.3.14
winget install -e --id OpenJS.NodeJS.LTS
```

You also need Git for Windows (it provides Git Bash for `deploy/setup.sh`).

Create the venv (skip the first line if `.venv` already exists) and install
the dependencies with pip. `uv` is not needed on Windows; `requirements-dev.txt`
installs it into the venv for regenerating the lock.

```powershell
python3.14 -m venv .venv     # classic installer with the py launcher: py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements-lock.txt
python -m pip install -r requirements-dev.txt -r requirements-cloud.txt
```

The lock is compiled with `--universal`, so it installs on Windows as is
(`python-ldap` and `uvloop` carry Linux-only markers and are skipped).

### Loop (Postgres in Docker, app from source)

1. Run `deploy/setup.sh` once to create `.env` (it holds `POSTGRES_PASSWORD`)
   and `certs/`. Run it from **Git Bash** (Start menu "Git Bash", or
   right-click the repo folder > "Open Git Bash here"):
   ```bash
   bash deploy/setup.sh
   ```
   Do not type `bash` in PowerShell: there it resolves to
   `C:\Windows\System32\bash.exe`, the WSL launcher, which tries to start a
   WSL distro instead. To run it from PowerShell, call Git's bash by full path
   (per-user Git install; a machine-wide install is under
   `C:\Program Files\Git` instead):
   ```powershell
   & "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe" deploy/setup.sh
   ```
   If Git Bash fails with `Permission denied` / `Exit 126` or "Access is
   denied", endpoint policy is blocking `bash.exe`; see Troubleshooting.
   The script is idempotent: it skips `.env` and `certs/` if they already
   exist, so rerunning is harmless. If Docker is not installed yet it stops at
   its Docker check, but `.env` and `certs/` are already created.
2. Start Postgres, load the dev environment and run the app (PowerShell, repo
   root):
   ```powershell
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres
   . .\scripts\dev-env.ps1
   python templates/run.py
   ```
   Use `scripts\dev-env.ps1`; `scripts/dev-env.sh` is for Linux shells. It
   reads `POSTGRES_PASSWORD` (and `POSTGRES_USER` / `POSTGRES_DB`) from
   `.env`, sets `APP_DB_ENGINE=postgres`, `APP_ENV=dev` and
   `APP_DATABASE_URL` (host `127.0.0.1`), and activates `.venv`. Dot-source it
   (the leading `. `) so the variables stay in your session. If PowerShell
   refuses to run scripts, run
   `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

   If port 8080 is taken (other Windows software can hold it; Adobe Connect
   is one example), run the backend on another port:
   ```powershell
   python templates/run.py --port 8081
   ```
3. In a second PowerShell, start the Vite dev server (repo root):
   ```powershell
   cd netcontrol\static\frontend
   $env:PLEXUS_BACKEND_URL = 'http://127.0.0.1:8081'   # only if backend is not on 8080
   npm ci
   npm run dev
   ```
   Open `http://localhost:5173/frontend/` and log in as `admin` /
   `netcontrol` (no forced password change under `APP_ENV=dev`). Vite proxies
   `/api`, `/static` and `/ws` to `PLEXUS_BACKEND_URL` (default
   `http://127.0.0.1:8080`).

### Full stack on Windows

`docker compose up --build -d` works the same as in WSL2 or on a VM; follow
Loop A. Run `setup.sh` from Git Bash as in step 1 above. The other Loop A
commands are plain `docker compose` and run from PowerShell too. Instead of
the `sed` line, edit `.env` by hand and set
`APP_CORS_ORIGINS=https://localhost`.

## WSL2 prerequisites (Ubuntu 24.04)

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

## Loop B: fast loop (Postgres in Docker, app from source)

1. Run `bash deploy/setup.sh` once so `.env` exists (it holds
   `POSTGRES_PASSWORD`).
2. Start Postgres, create the venv, install dependencies and run the app:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres
   uv venv --python 3.14 .venv && source .venv/bin/activate
   uv pip install --require-hashes -r requirements-lock.txt
   uv pip install -r requirements-dev.txt -r requirements-cloud.txt
   source scripts/dev-env.sh
   python templates/run.py
   ```
   `scripts/dev-env.sh` exports `APP_DB_ENGINE=postgres`, `APP_ENV=dev` and
   `APP_DATABASE_URL` (built from `.env`, host `127.0.0.1`) and activates
   `.venv`. `scripts/dev-env.ps1` is the PowerShell equivalent.
3. In a second shell, start the Vite dev server:
   ```bash
   cd netcontrol/static/frontend && npm ci && npm run dev
   ```
   Open `http://localhost:5173/frontend/`; `/api`, `/static` and `/ws` are
   proxied to the backend on 8080. Without Vite, run `npm run build` and open
   `http://127.0.0.1:8080/frontend/`.

Why it looks like this:

- `templates/run.py` does not read `.env`; the variables must be exported,
  which is what `scripts/dev-env.sh` and `scripts/dev-env.ps1` do.
- `.env` sets `APP_DATABASE_URL` with host `postgres` (the compose network
  name); from the host the database is at `127.0.0.1`.
- The hashed lock goes in its own install: `--require-hashes` cannot be mixed
  with the unhashed dev/cloud requirement files.
- `APP_ENV=dev` bootstraps `admin` / `netcontrol` without a forced password
  change.
- `docker-compose.dev.yml` only publishes Postgres on `127.0.0.1:5432` and is
  never auto-loaded; pass it explicitly with `-f`.

Optionally, keep a shortcut in `~/.bashrc` (run it from the repo root):

```bash
plexus-dev() { source scripts/dev-env.sh; }
```

Loop B skips nginx and HTTPS, so run Loop A before shipping.

## Updating dependencies

Regenerate `requirements-lock.txt` after changing `requirements.txt` (needs `uv`,
included in `requirements-dev.txt`; `--universal` keeps Linux-only markers such as
`python-ldap` and `uvloop` so the lock is valid on every platform):

```bash
uv pip compile requirements.txt --universal --generate-hashes --python-version 3.14 -o requirements-lock.txt
```

The Docker image and the SBOM are built from this lock, so a changed
`requirements.txt` without a regenerated lock does not reach the deployment.

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
- `Cannot connect to the Docker daemon` → Docker Desktop is not running, or in
  WSL2 systemd is not enabled or Docker Desktop WSL integration is off.
- Port 8080, 5432 or 443 already in use (a Windows-side Plexus or Postgres,
  or other Windows software such as Adobe Connect on 8080) → stop it, or
  change the published port in the compose override. Find the owner in
  PowerShell:
  ```powershell
  Get-NetTCPConnection -LocalPort 8080 -State Listen | Select-Object OwningProcess
  Get-Process -Id <pid>
  ```
  For Loop B, run the backend on another port and point Vite at it (set the
  variable in the Vite shell before `npm run dev`):
  ```powershell
  python templates/run.py --port 8081
  $env:PLEXUS_BACKEND_URL = 'http://127.0.0.1:8081'
  ```
- `Failed to run '/usr/bin/bash': Permission denied` / `Exit 126` when
  opening Git Bash, or "Access is denied" running `bash.exe` from PowerShell,
  while `git.exe` works → an application-control / EDR rule on the machine
  blocks `bash.exe`; it is not a Git problem. Git's `usr\bin\sh.exe` is the
  same program under another name and is usually not blocked, and
  `deploy/setup.sh` uses no bash-only syntax. Put Git's `usr\bin` on PATH
  first (it holds `dirname`, `cat` and `openssl`; without it the script
  cannot find the repo root and tries to write `.env` into the Git install
  folder), then run it from PowerShell at the repo root:
  ```powershell
  $env:PATH = "$env:LOCALAPPDATA\Programs\Git\usr\bin;$env:PATH"
  sh deploy/setup.sh
  ```
  (machine-wide Git: `C:\Program Files\Git\usr\bin`). Long term, ask IT for
  an exception for Git's `bash.exe`.
- `bash` in PowerShell starts (or complains about) a WSL distro → that is
  `C:\Windows\System32\bash.exe`, the WSL launcher, not Git Bash. Use Git
  Bash, or call Git's `bash.exe` by full path (Windows Loop, step 1).
- `POSTGRES_PASSWORD must be set` → `.env` is missing; run
  `bash deploy/setup.sh`.
- Login works, then you are logged out immediately → Secure cookie over plain
  HTTP; use `https://localhost` or set `APP_COOKIE_SECURE=false`.
- `npm run build` fails with native-module errors → Windows `node_modules`
  copied in; `rm -rf node_modules && npm ci` with the WSL node.
- `SyntaxError` on `except A, B:` → Python older than 3.14; use the uv venv.
