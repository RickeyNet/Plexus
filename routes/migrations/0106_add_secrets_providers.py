"""
Migration 0106: external secrets providers (HashiCorp Vault, AWS Secrets
Manager, Azure Key Vault) and external references on credentials and secret
variables.

Adds:

  - secrets_providers - name (unique ignoring case), ``provider_type``
    (``vault``, ``aws``, ``azure``), description, ``enabled`` (0/1),
    ``allow_user_credentials`` (0/1: a non-admin may point their own
    credential at this provider; admins always may), ``cache_ttl`` (seconds
    a resolved value is kept in memory, 0 to 3600, default 300),
    ``config_json`` (the non-secret settings: URL, mount, region, tenant,
    client id...), ``secret_enc`` (the provider's own auth secrets - Vault
    token or AppRole secret id, AWS secret access key, Azure client secret -
    as a JSON object encrypted with ``routes.crypto``) and the stamps.
  - credentials gain ``ext_provider_id`` (a provider; a provider in use
    cannot be deleted), ``ext_path`` (the secret's path, id or name in the
    provider), ``ext_key`` (the key of the password inside the secret, ``''``
    for the whole value) and ``ext_secret_key`` (the key of the enable
    secret, ``''``: the password). With a provider set the stored
    ``password`` and ``secret`` are empty.
  - secret_variables gain ``ext_provider_id``, ``ext_path`` and
    ``ext_key`` with the same meaning; the stored ``enc_value`` is empty.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 106
DESCRIPTION = "Add external secrets providers and references on credentials and secret variables"

_TABLE = """
    id                     SERIAL PRIMARY KEY,
    name                   TEXT NOT NULL,
    provider_type          TEXT NOT NULL,
    description            TEXT NOT NULL DEFAULT '',
    enabled                INTEGER NOT NULL DEFAULT 1,
    allow_user_credentials INTEGER NOT NULL DEFAULT 0,
    cache_ttl              INTEGER NOT NULL DEFAULT 300,
    config_json            TEXT NOT NULL DEFAULT '{}',
    secret_enc             TEXT NOT NULL DEFAULT '',
    created_by             TEXT NOT NULL DEFAULT '',
    created_at             TEXT NOT NULL DEFAULT '',
    updated_at             TEXT NOT NULL DEFAULT '',
    updated_by             TEXT NOT NULL DEFAULT ''
"""

_REFERENCE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("ext_provider_id", "INTEGER REFERENCES secrets_providers(id) ON DELETE RESTRICT"),
    ("ext_path", "TEXT NOT NULL DEFAULT ''"),
    ("ext_key", "TEXT NOT NULL DEFAULT ''"),
)

_INDEXES: tuple[str, ...] = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_providers_name ON secrets_providers (lower(name))",
    "CREATE INDEX IF NOT EXISTS idx_credentials_ext_provider ON credentials (ext_provider_id)",
    "CREATE INDEX IF NOT EXISTS idx_secret_variables_ext_provider ON secret_variables (ext_provider_id)",
)


async def up(db) -> None:
    await db.execute(f"CREATE TABLE IF NOT EXISTS secrets_providers ({_TABLE})")  # nosec B608 - fixed DDL
    for table in ("credentials", "secret_variables"):
        for column, definition in _REFERENCE_COLUMNS:
            await db.execute(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}"  # nosec B608 - fixed DDL
            )
    await db.execute("ALTER TABLE credentials ADD COLUMN IF NOT EXISTS ext_secret_key TEXT NOT NULL DEFAULT ''")
    for statement in _INDEXES:
        await db.execute(statement)
    await db.commit()
