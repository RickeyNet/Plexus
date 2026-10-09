# Database Backends

PostgreSQL 16 is the only supported runtime backend for Plexus. The compose
stack (`docker-compose.yml`) runs it as the `postgres` service with its data in
the `plexus-postgres` volume, and the development loops in
[DEVSETUP.md](../DEVSETUP.md) (Windows with Docker Desktop, and WSL2) run the
same container with the app from source.

Environment variables:

- `APP_DB_ENGINE=postgres`
- `APP_DATABASE_URL=postgresql://<user>:<pass>@<host>:5432/<db>`. Compose uses
  the host `postgres` (the compose network name) and sets both variables
  itself; when running from source against the dev container the host is
  `127.0.0.1` (`scripts/dev-env.ps1` and `scripts/dev-env.sh` build the URL
  from `.env`).

The `asyncpg` driver is part of `requirements.txt` and the hashed
`requirements-lock.txt`, and installs from prebuilt wheels on Linux and
Windows.

## SQLite

The SQLite engine remains in `routes/database.py` for two reasons: the pytest
suite runs in-process on SQLite files, and `tools/migrate_sqlite_to_postgres.py`
reads legacy SQLite databases. It is not a supported way to run the app, and
its `.env` options are no longer documented. `APP_DB_ENGINE` defaults to
`postgres`, and the app refuses to start with any other engine unless
`PLEXUS_ALLOW_SQLITE_ENGINE=1` is set, an escape hatch meant for the test
suite only.

## Migrating a legacy SQLite install

Installs that still have a SQLite database (`netcontrol.db`) can move their
data to PostgreSQL with the migration utility, which verifies row counts and
optionally per-table checksums. Without `--sqlite-path` it reads `APP_DB_PATH`,
falling back to `netcontrol.db`. Older compose installs kept the file in the
`plexus-db` volume at `/app/state/netcontrol.db`; compose no longer sets
`APP_DB_PATH`, so pass that path explicitly. Back up that file before
upgrading: the new `deploy/upgrade.sh` stops when `.env` still sets
`APP_DB_ENGINE=sqlite`.

```bash
# verify source and show source row counts only
python tools/migrate_sqlite_to_postgres.py --dry-run

# migrate and verify row-count parity
python tools/migrate_sqlite_to_postgres.py \
  --sqlite-path netcontrol.db \
  --postgres-url postgresql://plexus:plexus@localhost:5432/plexus

# migrate and verify row counts + per-table checksums
python tools/migrate_sqlite_to_postgres.py \
  --sqlite-path netcontrol.db \
  --postgres-url postgresql://plexus:plexus@localhost:5432/plexus \
  --with-checksums
```
