"""
opnsense_backup_encryption.py -- OPNsense config.xml backups encrypted at rest.

An OPNsense ``config.xml`` holds password hashes, API key secrets, private
keys and pre-shared keys. A config backup of one is stored in three
columns of ``config_backups`` (``seal``):

  - ``config_text``: the file with every secret replaced by its
    fingerprint marker (``opnsense_masking.mask_text``). It is still the
    same XML, so everything that reads stored backups (the backup view,
    diff and search, the rules view and rule change alerts, the filter log
    labels, config drift, path tracing, AI access) works on it without the
    secrets ever being read.
  - ``config_text_enc``: the raw file, encrypted with the install's key
    (``routes.crypto.encrypt``, AES-256-GCM). Only the raw download
    decrypts it (``raw_backup_text``).
  - ``config_text_digest``: HMAC-SHA256 of the raw file under a key
    derived from the install's key, so the store can tell an unchanged
    file from one where only a secret changed without decrypting anything.

``netcontrol.routes.device_config.store_device_config`` seals every
OPNsense configuration it stores. ``encrypt_legacy_backups`` converts the
ones stored in plain text by an older release: it runs at startup, in
batches, and leaves a row another process converted first alone.

Other devices' backups (read over SSH) are stored as captured.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from dataclasses import dataclass
from functools import lru_cache

import routes.database as db
from routes.crypto import decrypt, derive_key, encrypt

from netcontrol.integrations.opnsense.secrets import CONFIG_XML_ROOTS
from netcontrol.routes.opnsense_masking import (
    BACKUP_CAPTURE_METHOD,
    OPNSENSE_DEVICE_TYPE,
    is_opnsense_text,
    mask_text,
)

_DIGEST_PURPOSE = "opnsense-config-backup-digest"
# Rows converted per query at startup.
BATCH_SIZE = 50

KEY_MISMATCH_MESSAGE = (
    "The raw config.xml of the backup cannot be decrypted: it was encrypted with a different "
    "encryption key (netcontrol.key) than this server has. Restore the original key file to "
    "download it. The backup view still shows it with the secrets masked."
)


class RawBackupUnavailable(RuntimeError):
    """The encrypted raw copy of a backup cannot be decrypted (the
    install's encryption key changed)."""


@dataclass(frozen=True)
class SealedBackup:
    """What an OPNsense backup stores: masked text, encrypted raw text and
    the raw text's keyed digest."""

    config_text: str
    config_text_full: str
    config_text_enc: str
    config_text_digest: str


@lru_cache(maxsize=1)
def _digest_key() -> bytes:
    return derive_key(_DIGEST_PURPOSE)


def backup_digest(raw: str) -> str:
    """HMAC-SHA256 (hex) of a raw config.xml under this install's digest
    key: equal for equal files, different when any byte (a secret
    included) differs, and not reproducible without the key."""
    return hmac.new(_digest_key(), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def same_digest(stored: str | None, digest: str) -> bool:
    """Whether a stored digest is this one. A row without one (stored
    before backups were encrypted) never matches."""
    return bool(stored) and hmac.compare_digest(str(stored), digest)


def is_opnsense_backup(text: str | None, *, device_type: str | None = None, capture_method: str | None = None) -> bool:
    """Whether a configuration about to be stored is sealed: the rule
    ``opnsense_masking.is_opnsense_text`` applies to stored texts."""
    return bool(text) and is_opnsense_text(text, device_type=device_type, capture_method=capture_method)


def seal(raw: str, raw_full: str = "") -> SealedBackup:
    """The stored form of an OPNsense backup. ``raw_full`` (the form with
    defaults, ``''`` for OPNsense) is stored masked; only ``raw`` is kept
    encrypted. CPU work on a large file: call it off the event loop."""
    return SealedBackup(
        config_text=mask_text(raw),
        config_text_full=mask_text(raw_full) if raw_full else "",
        config_text_enc=encrypt(raw),
        config_text_digest=backup_digest(raw),
    )


async def raw_backup_text(backup: dict) -> str:
    """The file a raw download of ``backup`` (a row of ``get_config_backup``)
    returns: the decrypted config.xml of an OPNsense backup, the stored
    text of any other. Raises ``RawBackupUnavailable`` when the encrypted
    copy cannot be decrypted; never returns part of it."""
    return raw_text_of(backup, await db.get_config_backup_encrypted_text(int(backup["id"])))


def raw_text_of(backup: dict, sealed: str) -> str:
    """``raw_backup_text`` for a caller that already read the backup's
    encrypted copy ``sealed`` (``''`` when it has none): no query, so it
    also runs in a worker thread (the bulk download)."""
    if not sealed:
        return str(backup.get("config_text") or "")
    try:
        return decrypt(sealed)
    except Exception:
        raise RawBackupUnavailable(KEY_MISMATCH_MESSAGE) from None


async def encrypt_legacy_backups(batch_size: int = BATCH_SIZE) -> dict[str, int]:
    """Seal every OPNsense backup still stored in plain text (written by a
    release before backups were encrypted), ``batch_size`` rows per query,
    oldest first. Safe on every start and in several processes at once: a
    sealed row is never selected or changed again. Returns counts only:
    ``sealed`` (rows this call converted) and ``skipped`` (candidates that
    are not an OPNsense configuration)."""
    counts = {"sealed": 0, "skipped": 0}
    after_id = 0
    while True:
        rows = await db.get_unsealed_config_backups(
            after_id=after_id,
            limit=batch_size,
            device_type=OPNSENSE_DEVICE_TYPE,
            capture_method=BACKUP_CAPTURE_METHOD,
            sniff_roots=[f"<{root}" for root in CONFIG_XML_ROOTS],
        )
        for row in rows:
            after_id = max(after_id, int(row["id"]))
            raw = str(row.get("config_text") or "")
            if not is_opnsense_backup(
                raw, device_type=row.get("device_type"), capture_method=row.get("capture_method")
            ):
                counts["skipped"] += 1
                continue
            sealed = await asyncio.to_thread(seal, raw, str(row.get("config_text_full") or ""))
            if await db.seal_config_backup(
                int(row["id"]),
                config_text=sealed.config_text,
                config_text_full=sealed.config_text_full,
                config_text_enc=sealed.config_text_enc,
                config_text_digest=sealed.config_text_digest,
            ):
                counts["sealed"] += 1
        if len(rows) < batch_size:
            return counts
