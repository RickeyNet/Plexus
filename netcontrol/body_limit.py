"""Request body size limit, enforced before any route, auth or form code runs.

FastAPI reads (and for multipart, spools) a request body before router
dependencies such as ``require_auth`` run, so without a limit here an
unauthenticated client could make the app buffer an arbitrarily large body.
:class:`BodyLimitMiddleware` is a pure ASGI middleware registered outermost in
``netcontrol/app.py``. It answers 413 when the declared ``Content-Length`` is
over the limit for the path, and when a body without one (chunked) passes the
limit while it streams in.

Most paths get the default limit (``APP_MAX_REQUEST_BODY_MB``, 10 MB). The
upload routes in :func:`default_path_limits` get their own, larger limit,
derived from the size cap each route already enforces on the file itself.

``deploy/nginx.conf`` mirrors this: a small server-wide
``client_max_body_size`` and ``location`` blocks with large limits for the
same upload paths. Keep the two path lists in agreement.

Route-level limits stay where they are and may be tighter (the webhook
receivers bound their bodies with ``shared.read_bounded_body``).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from typing import Any

from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.body_limit")

MIB = 1024 * 1024
DEFAULT_MAX_BODY_MB = 10
# Multipart framing around an uploaded file (boundaries, part headers and
# small form fields) on top of the route's own file-size cap.
UPLOAD_ALLOWANCE_BYTES = MIB

PathLimits = list[tuple[re.Pattern[str], int]]


def max_body_bytes_from_env(name: str = "APP_MAX_REQUEST_BODY_MB", default_mb: int = DEFAULT_MAX_BODY_MB) -> int:
    """A limit in bytes from an environment variable holding megabytes. A
    missing, malformed or non-positive value falls back to ``default_mb``."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return default_mb * MIB
    try:
        value = int(raw)
    except ValueError:
        LOGGER.warning("%s=%r is not a whole number of MB; using %d", name, raw, default_mb)
        return default_mb * MIB
    if value < 1:
        LOGGER.warning("%s must be at least 1 MB; using %d", name, default_mb)
        return default_mb * MIB
    return value * MIB


def default_path_limits() -> PathLimits:
    """The upload routes allowed a body larger than the default, each with
    its route's own file cap plus the multipart allowance. Mirrored by the
    ``location`` blocks in ``deploy/nginx.conf``.

    A route listed here must not let FastAPI read its body (no ``File``,
    ``Form`` or body parameter): it checks the caller first and then reads
    the upload itself (``shared.uploaded_file``)."""
    # Imported here: the route modules are heavy, and app.py has loaded them
    # by the time the middleware is built.
    from netcontrol.routes.geolocation import _MAX_IMAGE_BYTES as floor_image_bytes
    from netcontrol.routes.upgrades import _MAX_IMAGE_UPLOAD_BYTES as software_image_bytes

    return [
        # Software (firmware) image upload: PLEXUS_MAX_IMAGE_UPLOAD_MB, 2 GB.
        (re.compile(r"/api/upgrades/images"), software_image_bytes + UPLOAD_ALLOWANCE_BYTES),
        # Floor-plan image upload: 20 MB.
        (re.compile(r"/api/geo/floors/[0-9]+/image"), floor_image_bytes + UPLOAD_ALLOWANCE_BYTES),
    ]


def declared_length(raw: bytes | str | None) -> int | None:
    """A ``Content-Length`` value as an int; ``None`` when absent. Raises
    ``ValueError`` when malformed or negative."""
    if raw is None:
        return None
    text = raw.decode("latin-1") if isinstance(raw, bytes) else raw
    value = int(text.strip())
    if value < 0:
        raise ValueError("negative Content-Length")
    return value


class BodyTooLarge(Exception):
    """Raised into the app when a streamed body passes its limit."""


async def _reply(send: Any, status: int, code: str, message: str) -> None:
    body = json.dumps({"ok": False, "error": {"code": code, "message": message}}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _too_large_message(limit: int) -> str:
    return f"Request body is larger than the {limit // MIB} MB this endpoint accepts."


class BodyLimitMiddleware:
    """Refuse request bodies over a per-path limit with 413 (see module doc)."""

    def __init__(
        self,
        app: Any,
        default_limit: int | None = None,
        path_limits: Iterable[tuple[re.Pattern[str], int]] | None = None,
    ) -> None:
        self.app = app
        self.default_limit = default_limit if default_limit is not None else max_body_bytes_from_env()
        self.path_limits: PathLimits = list(path_limits) if path_limits is not None else default_path_limits()

    def limit_for(self, path: str) -> int:
        for pattern, limit in self.path_limits:
            if pattern.fullmatch(path):
                return max(limit, self.default_limit)
        return self.default_limit

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self.limit_for(scope.get("path", ""))
        raw_length = next((value for name, value in scope.get("headers") or [] if name == b"content-length"), None)
        try:
            declared = declared_length(raw_length)
        except ValueError:
            await _reply(send, 400, "bad_request", "Invalid Content-Length header.")
            return
        if declared is not None and declared > limit:
            await _reply(send, 413, "payload_too_large", _too_large_message(limit))
            return

        received = 0
        response_started = False
        rejected = False

        async def counting_receive() -> Any:
            nonlocal received, rejected
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    if not response_started and not rejected:
                        rejected = True
                        await _reply(send, 413, "payload_too_large", _too_large_message(limit))
                    raise BodyTooLarge
            return message

        async def guarded_send(message: Any) -> None:
            nonlocal response_started
            if rejected:
                return  # the 413 has been sent; drop whatever the app answers
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except BodyTooLarge:
            return
        except Exception:
            if rejected:
                # An inner layer turned BodyTooLarge into its own error.
                return
            raise
