"""Inbound request signatures, one check per platform.

- Slack signs ``v0:<timestamp>:<raw body>`` with HMAC-SHA256 and the app's
  signing secret (``X-Slack-Signature: v0=<hex>``, ``X-Slack-Request-Timestamp``).
  A timestamp more than ``SLACK_REPLAY_WINDOW_SECONDS`` from now is refused,
  so a captured request cannot be replayed later.
- Webex signs the raw body with HMAC-SHA1 and the webhook's secret
  (``X-Spark-Signature: <hex>``).
- A Teams outgoing webhook signs the raw body with HMAC-SHA256 keyed by the
  base64-decoded security token (``Authorization: HMAC <base64>``).

Webex and Teams sign no timestamp, so their deliveries are de-duplicated by
message / activity id in ``ReplayGuard`` instead.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import time
from collections import OrderedDict

SLACK_REPLAY_WINDOW_SECONDS = 300


def verify_slack(secret: str, timestamp: str, body: bytes, signature: str, now: float | None = None) -> bool:
    if not secret or not timestamp or not signature:
        return False
    try:
        stamp = int(timestamp)
    except ValueError:
        return False
    current = time.time() if now is None else now
    if abs(current - stamp) > SLACK_REPLAY_WINDOW_SECONDS:
        return False
    base = b"v0:" + str(stamp).encode() + b":" + body
    expected = "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.encode(), signature.strip().encode())


def verify_webex(secret: str, body: bytes, signature: str) -> bool:
    if not secret or not signature:
        return False
    # Webex's documented signature is HMAC-SHA1; not used for anything but this check.
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha1).hexdigest()
    return hmac.compare_digest(expected.encode(), signature.strip().lower().encode())


def verify_teams(security_token: str, body: bytes, authorization: str) -> bool:
    if not security_token or not authorization:
        return False
    scheme, _, provided = authorization.strip().partition(" ")
    if scheme.upper() != "HMAC" or not provided:
        return False
    try:
        key = base64.b64decode(security_token, validate=True)
    except binascii.Error, ValueError:
        return False
    expected = base64.b64encode(hmac.new(key, body, hashlib.sha256).digest()).decode()
    return hmac.compare_digest(expected.encode(), provided.strip().encode())


class ReplayGuard:
    """Remembers ids seen in the last ``ttl`` seconds (at most ``size``):
    ``seen(id)`` is ``True`` for a repeat. Platforms retry deliveries they
    think failed, and an attacker can resend a captured signed body."""

    def __init__(self, ttl: float = 600.0, size: int = 5000) -> None:
        self._ttl, self._size = ttl, size
        self._ids: OrderedDict[str, float] = OrderedDict()

    def seen(self, key: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        while self._ids:
            oldest, stamp = next(iter(self._ids.items()))
            if current - stamp <= self._ttl and len(self._ids) < self._size:
                break
            self._ids.pop(oldest)
        if not key:
            return False
        if key in self._ids:
            return True
        self._ids[key] = current
        return False

    def clear(self) -> None:
        self._ids.clear()
