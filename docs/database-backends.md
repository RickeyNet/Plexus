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

`APP_DB_ENGINE` defaults to `postgres`, and the app refuses to start with any
other value; the error points at the migration tool below. Queries and
migrations are still written in a portable SQLite-style dialect (`?`
placeholders, `datetime('now', ...)`, `INSERT OR IGNORE`), which the Postgres
connection layer in `routes/database.py` translates at execution time.

## Migrating a legacy SQLite install

The SQLite engine has been removed from the app, but installs that still have
a SQLite database (`netcontrol.db`) can move their data to PostgreSQL with the
migration utility, which reads the file with Python's built-in `sqlite3`
module and verifies row counts and optionally per-table checksums. Without
`--sqlite-path` it reads `APP_DB_PATH` (the app itself no longer reads this
variable), falling back to `netcontrol.db`. Older compose installs kept the
file in the `plexus-db` volume at `/app/state/netcontrol.db`; compose no
longer sets `APP_DB_PATH`, so pass that path explicitly. Back up that file
before upgrading: `deploy/upgrade.sh` stops when `.env` still sets
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
