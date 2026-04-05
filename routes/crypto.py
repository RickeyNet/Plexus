"""
crypto.py — Fernet-based encryption for stored credentials.

On first run, generates a key file at ./netcontrol.key.
Keep this file safe — losing it means stored credentials are unrecoverable.

Fernet uses AES-128-CBC with HMAC-SHA256 (encrypt-then-MAC), random IVs
per message, and includes a timestamp — no IV-reuse or ECB concerns.
"""

import base64
import logging
import os
import stat

from cryptography.fernet import Fernet, InvalidToken

LOGGER = logging.getLogger("plexus.crypto")

KEY_FILE = os.path.join(os.path.dirname(__file__), "netcontrol.key")


def _load_or_create_key() -> bytes:
    """Load the Fernet key from disk, or create one atomically.

    Validates that loaded key material is well-formed before use.
    Uses atomic write (write-to-temp + rename) to avoid partial-key
    files from a crash or concurrent startup.
    """
    if os.path.isfile(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read().strip()
        # Validate key material — Fernet keys are 44 bytes of url-safe base64
        if len(key) != 44:
            raise RuntimeError(
                f"Encryption key file {KEY_FILE} is corrupt (expected 44 bytes, got {len(key)}). "
                "Restore from backup or delete the file to generate a new key (existing credentials will be lost)."
            )
        try:
            base64.urlsafe_b64decode(key)  # validate encoding
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
        return key

    # Generate new key atomically
    key = Fernet.generate_key()
    tmp_path = KEY_FILE + ".tmp"
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
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
            f.write(key)
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass
    LOGGER.info("Generated new encryption key at %s", KEY_FILE)
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> str:
    """Encrypt a string, return base64-encoded ciphertext.

    Fernet generates a unique random IV per call, so identical plaintext
    produces different ciphertext each time.
    """
    if not plaintext:
        return ""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext back to plaintext.

    Raises RuntimeError with a safe message if decryption fails,
    rather than leaking cryptographic details.
    """
    if not ciphertext:
        return ""
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        raise RuntimeError(
            "Failed to decrypt credential — the encryption key may have changed. "
            "Re-enter the credential or restore the original netcontrol.key file."
        )
