"""
Migration 0130: software end of life per release series.

Adds:

  - software_eol_entries - the end-of-life date of one release series of
    one software platform (``platform``: a key of
    ``netcontrol.integrations.software.versions.PLATFORMS``; ``series``:
    ``25.1``, ``17.9``), entered by an administrator or imported:
    ``eol_date`` (the day security fixes stop, ``YYYY-MM-DD``), optional
    ``release_date``, ``url`` and ``notes``, ``source`` (``manual`` or
    ``import``) and ``enabled``. One row per platform and series. The
    software tracker evaluates every tracked device against them
    (``netcontrol.integrations.software.lifecycle``); for OPNsense an entry
    overrides the built-in estimate.
  - software_versions.major_upgrade - a newer major release the device
    itself reports as available (an OPNsense firewall's
    ``upgrade_major_version``), '' when none: evidence that the series it
    runs is superseded.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text. Every
step is idempotent.
"""

from __future__ import annotations

VERSION = 130
DESCRIPTION = "Add software end-of-life entries per release series"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS software_eol_entries (
            id            SERIAL PRIMARY KEY,
            platform      TEXT    NOT NULL,
            series        TEXT    NOT NULL,
            eol_date      TEXT    NOT NULL,
            release_date  TEXT    NOT NULL DEFAULT '',
            url           TEXT    NOT NULL DEFAULT '',
            notes         TEXT    NOT NULL DEFAULT '',
            source        TEXT    NOT NULL DEFAULT 'manual',
            enabled       INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT    NOT NULL DEFAULT '',
            created_by    TEXT    NOT NULL DEFAULT '',
            updated_at    TEXT    NOT NULL DEFAULT '',
            updated_by    TEXT    NOT NULL DEFAULT '',
            UNIQUE(platform, series)
        )
        """
    )
    await db.execute("ALTER TABLE software_versions ADD COLUMN IF NOT EXISTS major_upgrade TEXT NOT NULL DEFAULT ''")
    await db.commit()
