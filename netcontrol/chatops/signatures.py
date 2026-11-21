"""Inbound request signatures, one check per platform.

- Slack signs ``v0:<timestamp>:<raw body>`` with HMAC-SHA256 and the app's
  signing secret (``X-Slack-Signature: v0=<hex>``, ``X-Slack-Request-Timestamp``).
  A timestamp more than ``SLACK_REPLAY_WINDOW_SECONDS`` from now is refused,
  so a captured request cannot be replayed later.
- Webex signs the raw body with HMAC-SHA1 and the webhook's secret
  (``X-Spark-Signature: <hex>``).
- A Teams outgoing webhook signs the raw body with HMAC-SHA256 keyed by the
  base64-decoded security token (``Authorization: HMAC <base64>``).

Webex and Teams sign no timestamp header, but the signed body carries one
(Webex ``data.created``, the Teams activity ``timestamp``):
``fresh_delivery_time`` refuses a delivery whose time is more than
``DELIVERY_MAX_AGE_SECONDS`` old (or missing or unparseable), and
``ReplayGuard`` de-duplicates by message / activity id within that window.
A delivery with no id cannot be de-duplicated, so it is refused.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import time
from collections import OrderedDict

from netcontrol.routes.maintenance_windows import _parse_iso

SLACK_REPLAY_WINDOW_SECONDS = 300
# Webex and Teams: how old a delivery's signed time may be, and how far ahead
# of this server's clock it may run (clock skew).
DELIVERY_MAX_AGE_SECONDS = 300
DELIVERY_MAX_SKEW_SECONDS = 60


def within_replay_window(stamp: float, max_age: float, max_skew: float, now: float | None = None) -> bool:
    """Whether a signed time ``stamp`` (epoch seconds) is at most ``max_age``
    seconds old and at most ``max_skew`` seconds in the future."""
    current = time.time() if now is None else now
    return -max_skew <= current - stamp <= max_age


def fresh_delivery_time(value: object, now: float | None = None) -> bool:
    """Whether a Webex or Teams delivery's signed ISO 8601 time (naive: UTC)
    is recent (``DELIVERY_MAX_AGE_SECONDS``, ``DELIVERY_MAX_SKEW_SECONDS``).
    Missing or unparseable: ``False``."""
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        stamp = _parse_iso(value).timestamp()
    except ValueError:
        return False
    return within_replay_window(stamp, DELIVERY_MAX_AGE_SECONDS, DELIVERY_MAX_SKEW_SECONDS, now)


def verify_slack(secret: str, timestamp: str, body: bytes, signature: str, now: float | None = None) -> bool:
    if not secret or not timestamp or not signature:
        return False
    try:
        stamp = int(timestamp)
    except ValueError:
        return False
    if not within_replay_window(stamp, SLACK_REPLAY_WINDOW_SECONDS, SLACK_REPLAY_WINDOW_SECONDS, now):
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
    ``seen(id)`` is ``True`` for a repeat, and for an empty id (a delivery
    that cannot be de-duplicated is refused like a repeat). Platforms retry
    deliveries they think failed, and an attacker can resend a captured
    signed body; ``fresh_delivery_time`` refuses one older than the ttl."""

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
            return True
        if key in self._ids:
            return True
        self._ids[key] = current
        return False

    def clear(self) -> None:
        self._ids.clear()
