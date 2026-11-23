"""
opnsense_masking.py -- OPNsense config.xml in config drift and config backups.

The pure rules live in ``netcontrol.integrations.opnsense.secrets``; this
module binds them to the install and the database:

  - ``mask_text`` / ``drift_form``: the masking (and, for drift, the
    normalization) keyed with a key derived from this install's encryption
    key (``routes.crypto.derive_key``), so a fingerprint cannot be
    reproduced elsewhere to confirm a guessed secret.
  - ``is_opnsense_host`` / ``is_opnsense_text``: whether a host or a stored
    text is an OPNsense firewall's configuration.
  - ``mask_record``: masks the text fields of a backup, baseline, snapshot
    or drift event read from the database before an endpoint returns it.
  - ``drift_snapshot_text``: what a drift capture of an OPNsense host
    stores. Plexus never opens a session to the firewall for drift: the
    snapshot is the host's newest config backup (written by the OPNsense
    collection), normalized and masked.

A stored OPNsense backup holds this masked text, with the raw file kept
only encrypted for the raw download (``opnsense_backup_encryption``); every
form that config drift stores (snapshots, baselines, drift events) is
masked, and every endpoint that shows a backup's text masks it on the way
out as well (masking is idempotent), which also covers a backup stored in
plain text by an older release and not converted yet.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import routes.database as db

from netcontrol.integrations.inventory_import import SNMP_DEVICE_TYPES
from netcontrol.integrations.opnsense.secrets import (
    config_revision,
    drift_text,
    looks_like_config_xml,
    mask_config_xml,
)

OPNSENSE_DEVICE_TYPE = SNMP_DEVICE_TYPES["opnsense"]
# The capture method of the backups the OPNsense collection stores.
BACKUP_CAPTURE_METHOD = "opnsense-api"
_KEY_PURPOSE = "opnsense-config-secret-fingerprint"

NO_BACKUP_MESSAGE = (
    "No config.xml backup of this OPNsense firewall yet: collect its OPNsense source "
    "(with configuration backups enabled) first. Plexus does not read the firewall over SSH."
)
REVERT_REFUSED_MESSAGE = (
    "Revert is not available for OPNsense firewalls: Plexus does not write to them. "
    "Change the firewall in its web interface, or accept the drift as the new baseline."
)
RESTORE_REFUSED_MESSAGE = (
    "Restore is not available for OPNsense firewalls: Plexus does not write to them. "
    "Download the backup and restore it in the firewall's web interface (System, Configuration, Backups)."
)


class OpnsenseBackupMissing(LookupError):
    """The OPNsense host has no stored config.xml backup to take a drift
    snapshot from."""


@lru_cache(maxsize=1)
def fingerprint_key() -> bytes:
    from routes.crypto import derive_key

    return derive_key(_KEY_PURPOSE)


def is_opnsense_host(host: dict | None) -> bool:
    return str((host or {}).get("device_type") or "").strip().lower() == OPNSENSE_DEVICE_TYPE


def is_opnsense_text(text: str | None, *, device_type: str | None = None, capture_method: str | None = None) -> bool:
    """Whether a stored text is (a diff of) an OPNsense configuration: by
    the host's device type, the backup's capture method or the content."""
    return (
        str(device_type or "").strip().lower() == OPNSENSE_DEVICE_TYPE
        or capture_method == BACKUP_CAPTURE_METHOD
        or looks_like_config_xml(text)
    )


def mask_text(text: str) -> str:
    """``config.xml`` text (raw, normalized or a diff) with its secrets
    masked by fingerprint."""
    return mask_config_xml(text, key=fingerprint_key())


def drift_form(text: str) -> str:
    """Normalized and masked: what drift stores and compares."""
    return drift_text(text, key=fingerprint_key())


def mask_record(
    record: dict[str, Any] | None,
    *fields: str,
    device_type: str | None = None,
) -> dict[str, Any] | None:
    """Mask ``fields`` of a record read from the database when it belongs
    to an OPNsense firewall (``device_type``, else the record's own
    ``device_type`` / ``capture_method`` / content), and flag it
    ``secrets_masked``. Other records are returned unchanged."""
    if not record:
        return record
    kind = device_type if device_type is not None else record.get("device_type")
    method = record.get("capture_method")
    masked = False
    for field in fields:
        value = record.get(field)
        if isinstance(value, str) and value and is_opnsense_text(value, device_type=kind, capture_method=method):
            record[field] = mask_text(value)
            masked = True
    if masked:
        record["secrets_masked"] = True
    return record


def revision_of(text: str) -> dict[str, str]:
    """The ``<revision>`` (time, username, description) of a config.xml,
    shown next to a view or diff that leaves it out."""
    return config_revision(text)


async def drift_snapshot_text(host: dict) -> str:
    """The drift snapshot of an OPNsense host: its newest config backup in
    drift form. Raises ``OpnsenseBackupMissing`` when it has none."""
    row = await db.get_newest_host_config_backup(int(host["id"]))
    text = str((row or {}).get("config_text") or "")
    if not text:
        raise OpnsenseBackupMissing(NO_BACKUP_MESSAGE)
    return drift_form(text)
