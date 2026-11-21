"""Content-Security-Policy helpers shared by the pages that set their own CSP."""

from __future__ import annotations

import base64
import hashlib


def script_hash_source(script: str) -> str:
    """The CSP source expression (``'sha256-...'``) that allows exactly this
    inline ``<script>`` body. ``script`` must be the text between the tags,
    byte for byte, or the browser blocks it."""
    digest = hashlib.sha256(script.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode('ascii')}'"
