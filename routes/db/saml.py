"""SAML assertion replay cache (migration 0111).

``saml_assertion_ids`` holds the (hashed issuer + ID) key of every SAML
assertion Plexus accepted until the assertion expires. Recording one that
is already there means the same assertion was posted twice: a replay.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import routes.database as _dbcore

__all__ = ["remember_saml_assertion", "prune_saml_assertions"]


async def remember_saml_assertion(assertion_key: str, expires_at: int) -> bool:
    """Record an accepted assertion. False when it was already recorded
    (a replay); expired rows are pruned on the way."""
    now = int(time.time())
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM saml_assertion_ids WHERE expires_at < ?", (now,))
        cursor = await db.execute(
            "INSERT INTO saml_assertion_ids (assertion_id, expires_at, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT (assertion_id) DO NOTHING",
            (assertion_key, int(expires_at), datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")),
        )
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def prune_saml_assertions() -> int:
    """Delete expired rows; the number deleted."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM saml_assertion_ids WHERE expires_at < ?", (int(time.time()),))
        await db.commit()
        return cursor.rowcount or 0
    finally:
        await db.close()
