"""
crypto.py — Fernet-based encryption for stored credentials.

On first run, generates a key file at ./netcontrol.key.
Keep this file safe — losing it means stored credentials are unrecoverable.
"""

import os
from cryptography.fernet import Fernet

KEY_FILE = os.path.join(os.path.dirname(__file__), "netcontrol.key")


def _load_or_create_key() -> bytes:
    if os.path.isfile(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(KEY_FILE, 0o600)
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> str:
    """Encrypt a string, return base64-encoded ciphertext."""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext back to plaintext."""
    return _fernet.decrypt(ciphertext.encode()).decode()
