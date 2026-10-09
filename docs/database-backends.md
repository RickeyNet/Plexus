# Database Backends

Plexus supports two database backends: **SQLite** (default) and **PostgreSQL** (production).

| Backend    | Requirements file            | Use case                    |
|------------|------------------------------|-----------------------------|
| SQLite     | `requirements.txt`           | Local dev, Windows, demos   |
| PostgreSQL | `requirements-postgres.txt`  | Linux production, VM deploy |

`requirements-postgres.txt` includes `asyncpg`, which requires a C compiler to build on Windows. On Linux, prebuilt wheels are available so it installs without issues.

Environment variables:

- `APP_DB_ENGINE=sqlite|postgres`
- `APP_DATABASE_URL=postgresql://<user>:<pass>@postgres:5432/<db>` (required when engine is `postgres`)
- `APP_DB_PATH` (SQLite file path; compose pins this to `/app/state/netcontrol.db`)

SQLite to PostgreSQL migration utility:

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
