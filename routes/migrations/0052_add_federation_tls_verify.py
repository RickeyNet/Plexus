"""
Migration 0052: Add tls_verify flag to federation peers.

Federation requests previously disabled TLS certificate verification
unconditionally (verify=False), allowing an on-path attacker to capture the
peer API token. Peers now verify certificates by default; operators using
self-signed certificates between instances can opt out per peer.

Existing rows default to tls_verify = 1 (verify). Deployments whose peers
use self-signed certs must either install trusted certs or explicitly
disable verification on that peer after upgrading.
"""

from __future__ import annotations

VERSION = 52
DESCRIPTION = "Add federation_peers.tls_verify flag (verify TLS by default)"


async def up(db) -> None:
    await db.execute("ALTER TABLE federation_peers ADD COLUMN IF NOT EXISTS tls_verify INTEGER NOT NULL DEFAULT 1")
    await db.commit()
