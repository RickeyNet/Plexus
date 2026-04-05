"""
Migration 0003: Add secret_variables table.

Encrypted key-value store for template variable substitution.
Templates reference secrets via {{secret.NAME}} syntax; values are
Fernet-encrypted at rest and only decrypted at job execution time.
"""

VERSION = 3
DESCRIPTION = "Add secret_variables table"


async def up(db):
    await db.execute("""
        CREATE TABLE IF NOT EXISTS secret_variables (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            enc_value   TEXT    NOT NULL,
            description TEXT    DEFAULT '',
            created_by  TEXT    NOT NULL DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_secret_variables_name ON secret_variables(name)"
    )
    await db.commit()
