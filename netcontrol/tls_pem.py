"""Load a certificate chain and private key held as PEM text into an
``ssl.SSLContext``.

``SSLContext.load_cert_chain`` reads files only. The PEM text is written to
private temporary files (``mkstemp``: mode 0600) for the call and removed
right after, also when loading fails. Used by the SIEM forwarder (client
certificate) and the syslog TLS receiver (server certificate).
"""

from __future__ import annotations

import logging
import os
import ssl
import tempfile

LOGGER = logging.getLogger("plexus.tls_pem")


def load_cert_chain_pem(ctx: ssl.SSLContext, cert_pem: str, key_pem: str) -> None:
    """``ctx.load_cert_chain`` from PEM text. Raises ``ssl.SSLError`` when
    the certificate or key cannot be loaded or do not match."""
    cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
    key_fd, key_path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(cert_fd, "w") as f:
            f.write(cert_pem)
        with os.fdopen(key_fd, "w") as f:
            f.write(key_pem)
        ctx.load_cert_chain(cert_path, key_path)
    finally:
        for path in (cert_path, key_path):
            try:
                os.unlink(path)
            except OSError as exc:
                LOGGER.debug("tls: temporary PEM file cleanup failed: %s", exc)
