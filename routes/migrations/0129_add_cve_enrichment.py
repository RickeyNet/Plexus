"""
Migration 0129: NVD and CISA KEV enrichment of software advisories.

Adds:

  - cve_enrichment - one row per CVE id an advisory names: what NVD
    answered (``lookup_state``: ``pending`` until NVD answered, ``scored``,
    ``unscored`` when NVD has no CVSS metric yet, ``not_found``; the
    ``vulnStatus`` as ``nvd_status``; the CVSS base score, severity, vector
    and version used) and when (``nvd_checked_at``), the last lookup error,
    and whether the CVE is in the CISA Known Exploited Vulnerabilities
    catalogue (``known_exploited``, ``kev_date_added``, ``kev_due_date``,
    ``kev_ransomware``, ``kev_checked_at``). Written by
    ``netcontrol.routes.software_cve``.
  - software_advisories.severity_source - where the severity comes from:
    ``default`` (the source gave none; enrichment may set it), ``enriched``
    (set from the CVSS score and the KEV flag), ``vendor`` (the vendor's
    rating, kept) or ``admin`` (set by an administrator, kept). Existing
    rows: Cisco PSIRT advisories are ``vendor``, manual and imported ones
    ``admin``, OPNsense audit advisories still at the audit's ``medium``
    ``default`` (any other severity there was an administrator's edit), and
    any other source ``vendor``.
  - software_advisories.cvss_source - ``nvd`` when the CVSS score was
    filled in by enrichment ('' when it is the advisory's own).
  - software_advisories.known_exploited, kev_date_added, kev_due_date,
    kev_ransomware, enriched_at - the KEV flag of the advisory's CVEs and
    when enrichment last looked at it.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 129
DESCRIPTION = "Add CVE enrichment cache and advisory severity source"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cve_enrichment (
            cve_id          TEXT    PRIMARY KEY,
            lookup_state    TEXT    NOT NULL DEFAULT 'pending',
            nvd_status      TEXT    NOT NULL DEFAULT '',
            cvss            REAL,
            cvss_severity   TEXT    NOT NULL DEFAULT '',
            cvss_vector     TEXT    NOT NULL DEFAULT '',
            cvss_version    TEXT    NOT NULL DEFAULT '',
            nvd_checked_at  TEXT    NOT NULL DEFAULT '',
            last_error      TEXT    NOT NULL DEFAULT '',
            known_exploited INTEGER NOT NULL DEFAULT 0,
            kev_date_added  TEXT    NOT NULL DEFAULT '',
            kev_due_date    TEXT    NOT NULL DEFAULT '',
            kev_ransomware  TEXT    NOT NULL DEFAULT '',
            kev_checked_at  TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    cursor = await db.execute(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = 'software_advisories' AND column_name = 'severity_source'"
    )
    backfill = await cursor.fetchone() is None
    for column, decl in (
        ("severity_source", "TEXT NOT NULL DEFAULT 'default'"),
        ("cvss_source", "TEXT NOT NULL DEFAULT ''"),
        ("known_exploited", "INTEGER NOT NULL DEFAULT 0"),
        ("kev_date_added", "TEXT NOT NULL DEFAULT ''"),
        ("kev_due_date", "TEXT NOT NULL DEFAULT ''"),
        ("kev_ransomware", "TEXT NOT NULL DEFAULT ''"),
        ("enriched_at", "TEXT NOT NULL DEFAULT ''"),
    ):
        await db.execute(f"ALTER TABLE software_advisories ADD COLUMN IF NOT EXISTS {column} {decl}")
    if backfill:
        await db.execute(
            "UPDATE software_advisories SET severity_source = 'admin' WHERE source IN ('manual', 'import')"
        )
        await db.execute(
            "UPDATE software_advisories SET severity_source = 'admin' "
            "WHERE source = 'opnsense-audit' AND severity <> 'medium'"
        )
        await db.execute(
            "UPDATE software_advisories SET severity_source = 'vendor' "
            "WHERE source NOT IN ('manual', 'import', 'opnsense-audit')"
        )
    await db.commit()
