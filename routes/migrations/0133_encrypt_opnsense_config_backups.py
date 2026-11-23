"""
Migration 0133: OPNsense config backups are encrypted at rest.

Adds:

  - config_backups.config_text_enc - the raw ``config.xml`` of an OPNsense
    backup, encrypted with the install's key (``routes.crypto.encrypt``,
    AES-256-GCM). ``config_text`` then holds the same file with every
    secret replaced by its fingerprint marker. '' for every other backup.
  - config_backups.config_text_digest - a keyed digest (HMAC-SHA256 under
    a key derived from the install's key) of the raw ``config.xml``, which
    tells whether a newly collected file equals the stored one, a changed
    secret included. '' for every other backup.

Converting the OPNsense backups stored before this release needs the
encryption key, which a migration does not use: the server does it at
startup (``netcontrol.routes.opnsense_backup_encryption.encrypt_legacy_backups``),
in batches, on every start until none is left.

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 133
DESCRIPTION = "Encrypt OPNsense config backups at rest"


async def up(db) -> None:
    await db.execute("ALTER TABLE config_backups ADD COLUMN IF NOT EXISTS config_text_enc TEXT NOT NULL DEFAULT ''")
    await db.execute("ALTER TABLE config_backups ADD COLUMN IF NOT EXISTS config_text_digest TEXT NOT NULL DEFAULT ''")
    await db.commit()
