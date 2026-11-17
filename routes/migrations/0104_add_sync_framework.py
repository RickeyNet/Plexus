"""
Migration 0104: the sync framework - connections to NetBox, Nautobot and
ServiceNow, sync jobs, their runs and the per-object outcome of each run.

Adds:

  - sync_connections - one remote system: name (unique ignoring case),
    kind (``netbox``, ``nautobot``, ``servicenow``), base URL (https),
    auth type (``token``; ``basic`` or ``oauth`` for ServiceNow), the
    service credential holding the token / password / client secret
    (``credentials``, cleared when it goes; never a plaintext secret here),
    TLS verification and an optional CA bundle (PEM), request timeout,
    description, the outcome of the last connection test and the stamps.
  - sync_jobs - what to sync over a connection (deleted with it is refused:
    the API answers 409 while jobs use it): name (unique ignoring case),
    the object types (a JSON list), direction (``import``, ``export``,
    ``bidirectional``), conflict policy (``source_wins``, ``plexus_wins``,
    ``skip_conflicts``), ``delete_missing``, the per-object-type field
    mappings (JSON object), options (JSON object: the host group of synced
    devices), schedule (``interval_minutes``, 0: manual only), enabled,
    the last run's id, status and time, the last scheduled attempt and the
    stamps.
  - sync_runs - one run of a job (deleted with it): dry run or real,
    trigger_kind (``manual``, ``schedule``), status (``running``, ``success``,
    ``partial``, ``failed``), who started it, start and finish times, the
    summary (JSON: counts per object type) and a message.
  - sync_run_entries - one planned change of a run (deleted with it):
    object type, the object's natural key as text, action (``create``,
    ``update``, ``delete``, ``conflict``), target (``plexus``, ``remote``),
    the per-field changes (JSON), outcome (``planned``, ``applied``,
    ``failed``, ``skipped``) and a message.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 104
DESCRIPTION = "Add the sync framework: connections, jobs, runs and run entries"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT '',
            updated_by  TEXT NOT NULL DEFAULT ''
"""

_TABLES: tuple[tuple[str, str], ...] = (
    (
        "sync_connections",
        f"""
            id               SERIAL PRIMARY KEY,
            name             TEXT NOT NULL,
            kind             TEXT NOT NULL,
            base_url         TEXT NOT NULL,
            auth_type        TEXT NOT NULL DEFAULT 'token',
            credential_id    INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
            verify_tls       INTEGER NOT NULL DEFAULT 1,
            ca_pem           TEXT NOT NULL DEFAULT '',
            timeout_seconds  INTEGER NOT NULL DEFAULT 30,
            description      TEXT NOT NULL DEFAULT '',
            last_test_at     TEXT NOT NULL DEFAULT '',
            last_test_ok     INTEGER,
            last_test_message TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "sync_jobs",
        f"""
            id               SERIAL PRIMARY KEY,
            name             TEXT NOT NULL,
            connection_id    INTEGER NOT NULL REFERENCES sync_connections(id) ON DELETE RESTRICT,
            object_types     TEXT NOT NULL DEFAULT '[]',
            direction        TEXT NOT NULL DEFAULT 'import',
            conflict_policy  TEXT NOT NULL DEFAULT 'skip_conflicts',
            delete_missing   INTEGER NOT NULL DEFAULT 0,
            mappings         TEXT NOT NULL DEFAULT '{{}}',
            options          TEXT NOT NULL DEFAULT '{{}}',
            interval_minutes INTEGER NOT NULL DEFAULT 0,
            enabled          INTEGER NOT NULL DEFAULT 1,
            description      TEXT NOT NULL DEFAULT '',
            last_run_id      INTEGER,
            last_run_status  TEXT NOT NULL DEFAULT '',
            last_run_at      TEXT NOT NULL DEFAULT '',
            last_attempt_at  TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        """,
    ),
    (
        "sync_runs",
        """
            id           SERIAL PRIMARY KEY,
            job_id       INTEGER NOT NULL REFERENCES sync_jobs(id) ON DELETE CASCADE,
            dry_run      INTEGER NOT NULL DEFAULT 0,
            trigger_kind TEXT NOT NULL DEFAULT 'manual',
            status       TEXT NOT NULL DEFAULT 'running',
            started_by   TEXT NOT NULL DEFAULT '',
            started_at   TEXT NOT NULL DEFAULT '',
            finished_at  TEXT NOT NULL DEFAULT '',
            summary      TEXT NOT NULL DEFAULT '{}',
            message      TEXT NOT NULL DEFAULT ''
        """,
    ),
    (
        "sync_run_entries",
        """
            id           SERIAL PRIMARY KEY,
            run_id       INTEGER NOT NULL REFERENCES sync_runs(id) ON DELETE CASCADE,
            object_type  TEXT NOT NULL,
            object_key   TEXT NOT NULL DEFAULT '',
            action       TEXT NOT NULL,
            target       TEXT NOT NULL,
            changes      TEXT NOT NULL DEFAULT '{}',
            outcome      TEXT NOT NULL DEFAULT 'planned',
            message      TEXT NOT NULL DEFAULT ''
        """,
    ),
)

_INDEXES: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_connections_name ON sync_connections (lower(name))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_jobs_name ON sync_jobs (lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_sync_jobs_connection ON sync_jobs (connection_id)",
    "CREATE INDEX IF NOT EXISTS idx_sync_runs_job ON sync_runs (job_id, id)",
    "CREATE INDEX IF NOT EXISTS idx_sync_run_entries_run ON sync_run_entries (run_id, object_type)",
)


async def up(db) -> None:
    for table, columns in _TABLES:
        await db.execute(f"CREATE TABLE IF NOT EXISTS {table} ({columns})")  # nosec B608 - fixed DDL
    for statement in _INDEXES:
        await db.execute(statement)
    await db.commit()
