"""One pure ASGI middleware for every HTTP request the app serves.

:class:`PlexusHTTPMiddleware` is registered outermost in ``netcontrol/app.py``
and does, in this order:

1. Correlation id: a supplied ``X-Correlation-ID`` (letters, digits and
   ``. _ : -``, at most 128 characters) or a new one, set before anything
   else on ``scope["state"]`` (``request.state.correlation_id``) and on
   ``routes.db.change_events.current_correlation_id`` (reset when the request
   ends), and sent back on every response.
2. Response headers: the security headers (HSTS when enabled,
   ``X-Content-Type-Options``, ``X-Frame-Options``, ``Referrer-Policy``,
   ``Permissions-Policy``, a default ``Content-Security-Policy`` a route may
   replace) and ``X-Accel-Buffering: no`` on event streams, applied to the
   ``http.response.start`` message of every response: normal, error,
   streamed, file and short-circuit responses alike.
3. Request metrics (``api.requests.total``, ``api.requests.failed``,
   ``api.request.duration_ms`` up to the response start) and a log line for
   a request whose handler raised.
4. The request body limit (:class:`netcontrol.body_limit.BodyLimitMiddleware`).
5. The guards, in order, each a small function that answers the request
   itself (a redirect, a 429, a 403) or lets it through.

Unlike ``BaseHTTPMiddleware`` it runs the app in the request's own task (no
extra task or stream pair per layer), so context variables set by a handler
or dependency stay visible and streamed responses pass straight through.
WebSocket and lifespan scopes go to the app untouched.
"""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Awaitable, Callable, Sequence

from routes.db.change_events import current_correlation_id
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from netcontrol.body_limit import BodyLimitMiddleware
from netcontrol.telemetry import configure_logging, increment_metric, observe_timing

LOGGER = configure_logging("plexus.app")

# A guard answers the request (returns a response) or lets it through (None).
Guard = Callable[[Request], Awaitable[Response | None]]

CORRELATION_HEADER = "X-Correlation-ID"
_CORRELATION_HEADER_KEY = b"x-correlation-id"
# What a caller may send as its own correlation id; anything else gets a new
# one. Covers hex ids, UUIDs and W3C trace ids.
_SUPPLIED_CORRELATION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")

# Response types that are streams read event by event (SSE; NDJSON is
# accepted by the SPA's stream readers too): sent with X-Accel-Buffering: no.
UNBUFFERED_STREAM_TYPES = frozenset({"text/event-stream", "application/x-ndjson"})

# script-src is 'self' only: the React bundle ships as external hashed
# modules from /assets, so no inline <script> or CDN is needed. 'unsafe-inline'
# is kept for style-src alone (dynamic style= attrs from the React app and
# ECharts). Set with setdefault: a single-purpose endpoint that needs a looser
# policy (the graph-export embed page) sets its own.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self'; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

_FIXED_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
)


def correlation_id_for(scope: Scope) -> str:
    """The request's correlation id: the caller's ``X-Correlation-ID`` when
    it is a plain token (see ``_SUPPLIED_CORRELATION_ID``), else a new one."""
    for name, value in scope.get("headers") or ():
        if name == _CORRELATION_HEADER_KEY:
            supplied = value.decode("latin-1").strip()
            if _SUPPLIED_CORRELATION_ID.fullmatch(supplied):
                return supplied
            break
    return secrets.token_hex(8)


def apply_security_headers(headers: MutableHeaders, *, hsts: str | None) -> None:
    """Set the security headers on a response's ``headers`` (and
    ``X-Accel-Buffering: no`` on an event stream, so nginx passes each event
    straight on). ``hsts`` is the ``Strict-Transport-Security`` value, or
    ``None`` when HSTS is off."""
    if hsts:
        headers["Strict-Transport-Security"] = hsts
    for name, value in _FIXED_SECURITY_HEADERS:
        headers[name] = value
    headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type in UNBUFFERED_STREAM_TYPES:
        headers.setdefault("X-Accel-Buffering", "no")


def _record_request(status: int | None, started_at: float) -> float:
    """Count one request (failed when it raised, ``status`` None, or
    answered 4xx/5xx) and its time to the response start."""
    duration_ms = (time.perf_counter() - started_at) * 1000
    increment_metric("api.requests.total")
    if status is None or status >= 400:
        increment_metric("api.requests.failed")
    observe_timing("api.request.duration_ms", duration_ms)
    return duration_ms


class PlexusHTTPMiddleware:
    """The app's HTTP middleware (see the module docstring).

    ``guards`` run in order after the body limit; ``hsts_header`` returns the
    HSTS value per request (``None`` when off); ``internal_error`` builds the
    500 response for a request whose handler raised, so that response gets the
    headers too (the exception is still re-raised for the server's error
    handling and logging)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        guards: Sequence[Guard] = (),
        hsts_header: Callable[[], str | None] = lambda: None,
        internal_error: Callable[[Request], Response] | None = None,
    ) -> None:
        self.app = app
        self.guards = tuple(guards)
        self.hsts_header = hsts_header
        self.internal_error = internal_error
        # The body limit answers before any guard reads the request.
        self.body_limit = BodyLimitMiddleware(self._guarded)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        corr_id = correlation_id_for(scope)
        scope.setdefault("state", {})["correlation_id"] = corr_id
        context_token = current_correlation_id.set(corr_id)
        started_at = time.perf_counter()
        hsts = self.hsts_header()
        response_started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = MutableHeaders(raw=list(message.get("headers") or ()))
                apply_security_headers(headers, hsts=hsts)
                headers[CORRELATION_HEADER] = corr_id
                message = {**message, "headers": headers.raw}
                _record_request(int(message["status"]), started_at)
            await send(message)

        try:
            await self.body_limit(scope, receive, send_with_headers)
        except Exception:
            if not response_started:
                path = scope.get("path", "")
                if self.internal_error is not None and not getattr(scope.get("app"), "debug", False):
                    # The server's error handler still runs and logs; it
                    # sends nothing once this response has started.
                    response = self.internal_error(Request(scope))
                    await response(scope, receive, send_with_headers)
                    duration_ms = (time.perf_counter() - started_at) * 1000
                else:
                    duration_ms = _record_request(None, started_at)
                LOGGER.warning(
                    "request error path=%s correlation_id=%s duration_ms=%.1f", path, corr_id, duration_ms
                )
            raise
        finally:
            current_correlation_id.reset(context_token)

    async def _guarded(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.guards:
            request = Request(scope, receive)
            for guard in self.guards:
                response = await guard(request)
                if response is not None:
                    await response(scope, receive, send)
                    return
        await self.app(scope, receive, send)
