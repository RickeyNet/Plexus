"""
Migration 0118: the check a Cato finding belongs to.

The Cato shared hosts vs Azure check
(``netcontrol.integrations.cato.shared_host_check``) stores its findings in
``cato_egress_findings`` (migration 0078) next to the egress check's. Adds:

  - cato_egress_findings.check_name - ``egress`` (the default, so existing
    rows stay the egress check's) or ``shared_host``. A run lists, updates
    and resolves only the rows of its own check (``routes.db.cato_egress``).
  - idx_cato_egress_findings_check - on (check_name, status, severity), for
    the per-check listing.

Every step is idempotent.
"""

from __future__ import annotations

VERSION = 118
DESCRIPTION = "Add check_name to cato_egress_findings"


async def up(db) -> None:
    await db.execute(
        "ALTER TABLE cato_egress_findings ADD COLUMN IF NOT EXISTS check_name TEXT NOT NULL DEFAULT 'egress'"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_cato_egress_findings_check "
        "ON cato_egress_findings (check_name, status, severity)"
    )
    await db.commit()
