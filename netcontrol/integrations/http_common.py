"""Small helpers shared by the HTTP API clients of the integrations.

- ``validate_https_host``: the address a client sends its credentials to,
  reduced to ``https://host[:port]`` and checked (no other path, no query,
  no embedded user, never plain ``http``).
- ``RequestPacer``: spaces the requests of one client so a collection
  never loads the device or controller it reads.
- ``retry_delay``: how long to wait before retrying a failed call, with
  exponential backoff and an honoured ``Retry-After`` on HTTP 429.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlsplit

MAX_RETRY_AFTER_SECONDS = 60.0
MAX_BACKOFF_SECONDS = 30.0


def validate_https_host(url: str, label: str, *, ignored_paths: tuple[str, ...] = ()) -> str:
    """Normalise and validate the address of an API host.

    Accepts ``https://host[:port]`` (a bare host is taken as https, a
    trailing ``/`` is dropped, and so is one of ``ignored_paths``, compared
    without case) and returns just that: the URL decides where the
    credentials are sent, so no other path, no query and no embedded user is
    allowed, and ``http`` is refused. Raises ``ValueError`` with a message
    naming ``label`` otherwise.
    """
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError(f"{label} address is required")
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    parts = urlsplit(cleaned)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"{label} address must be an https URL")
    path = parts.path.rstrip("/")
    if path.lower() in {p.lower() for p in ignored_paths}:
        path = ""
    if parts.username or parts.password or parts.query or parts.fragment or path.strip("/"):
        raise ValueError(f"{label} address must be the host only")
    try:
        port = parts.port
    except ValueError:
        raise ValueError(f"{label} address has an invalid port") from None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port else "")


class RequestPacer:
    """At most ``requests_per_second`` requests, evenly spaced. Not
    reentrant-safe on its own: callers hold their own lock around a call."""

    def __init__(self, requests_per_second: float) -> None:
        self._min_interval = 1.0 / max(0.1, float(requests_per_second))
        self._next_slot = 0.0

    async def wait(self) -> None:
        now = time.monotonic()
        start = max(now, self._next_slot)
        self._next_slot = start + self._min_interval
        if start > now:
            await asyncio.sleep(start - now)


def retry_delay(attempt: int, *, rate_limited: bool = False, retry_after: str | None = None) -> float:
    """Seconds to wait before retry number ``attempt`` (1 for the first):
    ``2**attempt`` up to ``MAX_BACKOFF_SECONDS``; on HTTP 429 the
    ``Retry-After`` the server sent instead, between 1 second and
    ``MAX_RETRY_AFTER_SECONDS``."""
    delay = min(2.0**attempt, MAX_BACKOFF_SECONDS)
    if rate_limited:
        try:
            delay = float(retry_after) if retry_after is not None else delay
        except ValueError:
            pass
        delay = min(max(delay, 1.0), MAX_RETRY_AFTER_SECONDS)
    return delay
