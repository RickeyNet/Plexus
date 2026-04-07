"""
crypto.py — AES-256-GCM encryption for stored credentials.

On first run, generates a 32-byte key file at ./netcontrol.key.
Keep this file safe — losing it means stored credentials are unrecoverable.

Uses AES-256-GCM which provides:
  - 256-bit key (vs Fernet's 128-bit)
  - Authenticated encryption (integrity + confidentiality in one pass)
  - Random 96-bit nonce per message (no nonce reuse)

Backward-compatible: transparently decrypts legacy Fernet-encrypted values
(detected by the "gAAAAA" base64 prefix) so existing credentials survive
the upgrade without a migration step.
"""

import base64
import logging
import os
import stat

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOGGER = logging.getLogger("plexus.crypto")

KEY_FILE = os.path.join(os.path.dirname(__file__), "netcontrol.key")

# AES-256-GCM nonce size (96 bits per NIST recommendation)
_NONCE_SIZE = 12

# Prefix byte to identify AES-256-GCM ciphertext vs legacy Fernet
_V2_PREFIX = b"\x02"


def _load_or_create_key() -> bytes:
    """Load the 32-byte AES-256 key from disk, or create one atomically.

    Accepts both legacy 44-byte Fernet keys (for backward compat during
    decryption) and new 44-byte base64-encoded 32-byte keys.  On first
    run after upgrade, the old Fernet key is preserved — legacy values
    are decrypted with it and re-encrypted with AES-256-GCM on next write.

    New installations generate a 32-byte key directly.
    """
    if os.path.isfile(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            raw = f.read().strip()

        # Validate: must be 44 bytes of url-safe base64
        if len(raw) != 44:
            raise RuntimeError(
                f"Encryption key file {KEY_FILE} is corrupt (expected 44 bytes, got {len(raw)}). "
                "Restore from backup or delete the file to generate a new key (existing credentials will be lost)."
            )
        try:
            base64.urlsafe_b64decode(raw)
        except Exception:
            raise RuntimeError(f"Encryption key file {KEY_FILE} contains invalid base64 data.")

        # Warn if file permissions are too open (Unix only)
        try:
            mode = os.stat(KEY_FILE).st_mode
            if mode & (stat.S_IRGRP | stat.S_IROTH):
                LOGGER.warning(
                    "Encryption key file %s is readable by group/other (mode %o). "
                    "Run: chmod 600 %s",
                    KEY_FILE, stat.S_IMODE(mode), KEY_FILE,
                )
        except (OSError, AttributeError):
            pass  # Windows or stat unavailable
        return raw

    # Generate new 32-byte AES-256 key, base64-encoded to 44 bytes
    key_bytes = AESGCM.generate_key(bit_length=256)  # 32 raw bytes
    key_b64 = base64.urlsafe_b64encode(key_bytes)  # 44 bytes on disk
    tmp_path = KEY_FILE + ".tmp"
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key_b64)
        finally:
            os.close(fd)
        os.replace(tmp_path, KEY_FILE)  # atomic on POSIX
    except FileExistsError:
        # Another process beat us — read their key instead
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return _load_or_create_key()
    except OSError:
        # Fallback for Windows where O_EXCL may behave differently
        with open(KEY_FILE, "wb") as f:
            f.write(key_b64)
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass
    LOGGER.info("Generated new AES-256 encryption key at %s", KEY_FILE)
    return key_b64


_key_b64 = _load_or_create_key()
_key_raw = base64.urlsafe_b64decode(_key_b64)

# Fernet keys are 32 bytes decoded (16-byte signing + 16-byte encryption).
# AES-256 keys are 32 bytes decoded.  Both encode to 44 bytes base64.
# We determine which type the key is by trying to construct a Fernet instance.
_legacy_fernet = None
try:
    _legacy_fernet = Fernet(_key_b64)
except (ValueError, Exception):
    pass

# For AES-256-GCM: if this is a legacy Fernet key (32 bytes = 16 sign + 16 enc),
# we use the full 32 bytes as the AES-256 key.  New keys are already 32 bytes.
_aesgcm = AESGCM(_key_raw)


def encrypt(plaintext: str) -> str:
    """Encrypt a string with AES-256-GCM, return base64-encoded ciphertext.

    Each call generates a unique random 96-bit nonce.  Output format:
    base64( 0x02 || nonce(12) || ciphertext+tag )
    """
    if not plaintext:
        return ""
    nonce = os.urandom(_NONCE_SIZE)
    ct = _aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(_V2_PREFIX + nonce + ct).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext back to plaintext.

    Transparently handles both:
      - New AES-256-GCM tokens (prefix byte 0x02)
      - Legacy Fernet tokens (prefix byte 0x80, base64 starts with 'gAAAAA')

    Raises RuntimeError with a safe message if decryption fails.
    """
    if not ciphertext:
        return ""

    try:
        raw = base64.urlsafe_b64decode(ciphertext.encode())
    except Exception:
        raise RuntimeError(
            "Failed to decrypt credential — ciphertext is not valid base64."
        )

    # New AES-256-GCM format: prefix 0x02 + 12-byte nonce + ciphertext+tag
    if raw[:1] == _V2_PREFIX:
        if len(raw) < 1 + _NONCE_SIZE + 16:  # prefix + nonce + min GCM tag
            raise RuntimeError("Failed to decrypt credential — ciphertext is too short.")
        nonce = raw[1:1 + _NONCE_SIZE]
        ct = raw[1 + _NONCE_SIZE:]
        try:
            return _aesgcm.decrypt(nonce, ct, None).decode()
        except Exception:
            raise RuntimeError(
                "Failed to decrypt credential — the encryption key may have changed. "
                "Re-enter the credential or restore the original netcontrol.key file."
            )

    # Legacy Fernet format (first byte 0x80, base64 starts with 'gAAAAA')
    if _legacy_fernet is not None:
        try:
            return _legacy_fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            pass

    raise RuntimeError(
        "Failed to decrypt credential — the encryption key may have changed. "
        "Re-enter the credential or restore the original netcontrol.key file."
    )
