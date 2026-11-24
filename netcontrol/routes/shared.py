"""
shared.py -- Cross-domain helper functions used by multiple route modules.

Provides audit logging, config capture/push/diff, and session helpers.
"""

from __future__ import annotations

import asyncio
import contextlib
import difflib
import functools
import os
import re
import time
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Iterable, Iterator
from typing import Any
from urllib.parse import urlsplit

import routes.database as db
from fastapi import HTTPException, Request
from starlette.datastructures import UploadFile
from starlette.responses import StreamingResponse
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocket

import netcontrol.routes.state as state
from netcontrol.account_rules import API_TOKEN_USER
from netcontrol.sso import single_line
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.shared")

# Mirrors app.SESSION_MAX_AGE (absolute session lifetime cap, 24h). Kept as a
# local constant so WS auth can enforce the same cap require_auth does without
# importing app (which would create a cycle).
_WS_SESSION_MAX_AGE = 86400


# ── Audit helper ─────────────────────────────────────────────────────────────

_AUDIT_USER_MAX = 256
_AUDIT_DETAIL_MAX = 4000


async def _audit(
    category: str,
    action: str,
    user: str = "",
    detail: str = "",
    correlation_id: str = "",
) -> None:
    """Fire-and-forget audit record.  Never raises to the caller.

    ``user`` and ``detail`` may hold text an anonymous caller chose (the
    name typed into the sign-in form), so both are stored and logged on one
    line and cut to a fixed length: such text can then neither start a log
    line of its own nor fill the audit table.
    """
    user = single_line(user, _AUDIT_USER_MAX)
    detail = single_line(detail, _AUDIT_DETAIL_MAX)
    try:
        await db.add_audit_event(category, action, user=user, detail=detail, correlation_id=correlation_id)
        LOGGER.info(
            "audit: category=%s action=%s user=%s correlation_id=%s detail=%s",
            category,
            action,
            user,
            correlation_id,
            detail,
        )
    except Exception:
        LOGGER.warning("Failed to write audit event category=%s action=%s", category, action)


# Strong references to supervised fire-and-forget tasks. asyncio holds only a
# weak reference to a pending task, so without this a task can be garbage-
# collected before it runs. Tasks remove themselves on completion.
_supervised_tasks: set[asyncio.Task] = set()


def supervise_task(task: asyncio.Task, label: str) -> None:
    """Log an exception escaping a fire-and-forget task rather than letting
    asyncio swallow it silently, and retain a strong reference so the task
    can't be GC'd mid-flight. Attach to any create_task whose result nobody
    awaits, so a crash surfaces in logs instead of vanishing."""
    _supervised_tasks.add(task)

    def _cb(t: asyncio.Task) -> None:
        _supervised_tasks.discard(t)
        if t.cancelled():
            return
        exc = t.exception()
        if exc is not None:
            LOGGER.error("%s crashed: %s", label, exc, exc_info=exc)

    task.add_done_callback(_cb)


# ── Fan-out and long-lived work limits ───────────────────────────────────────


@contextlib.asynccontextmanager
async def fan_out[T](aws: Iterable[Awaitable[T]]) -> AsyncIterator[Iterator[Awaitable[T]]]:
    """Start every awaitable as a task and give ``asyncio.as_completed`` over
    them: ``await`` each item for the next result to finish (it raises what
    that task raised).

    Leaving the block, at the end, by an exception, by cancellation or
    because the consumer went away (the client of a streaming response
    disconnects: GeneratorExit or CancelledError in the generator), cancels
    every task still pending, so no probe or device sign-in keeps running
    for a result nobody will read."""
    tasks = [asyncio.ensure_future(aw) for aw in aws]
    try:
        yield asyncio.as_completed(tasks)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
            elif not task.cancelled():
                # Mark a finished, unread failure as retrieved: no "Task
                # exception was never retrieved" warning for it.
                task.exception()


def session_identity(session: dict | None) -> str | None:
    """Who a session is, for per-caller limits: ``user:<id>``, ``api-token``
    for the server API token (one identity, however many clients use it),
    ``None`` without a session."""
    if not session:
        return None
    if session.get("auth_mode") == "token":
        return API_TOKEN_USER
    return f"user:{session.get('user_id')}"


class ActiveSlot:
    """One unit of an ``ActiveLimit`` held by one caller. ``release`` is
    idempotent. Used as a context manager it is released when the block
    ends, unless ownership passed to a response (``stream``) or a task
    (``release_when_done``), which then release it when they end."""

    def __init__(self, limit: ActiveLimit, identity: str) -> None:
        self._limit = limit
        self._identity = identity
        self._held = True
        self._handed_off = False

    @property
    def held(self) -> bool:
        return self._held

    def release(self) -> None:
        if self._held:
            self._held = False
            self._limit._release(self._identity)

    def __enter__(self) -> ActiveSlot:
        return self

    def __exit__(self, *exc_info: object) -> None:
        if not self._handed_off:
            self.release()

    def stream(self, content: AsyncGenerator[str], media_type: str = "text/event-stream") -> StreamingResponse:
        """A streaming response of ``content`` that holds this slot until
        the response ends, however it ends (finished, failed, client gone),
        and closes ``content`` then so its own cleanup runs at once."""
        self._handed_off = True
        return _SlotStreamingResponse(_SlotBody(content, self), media_type=media_type)

    def release_when_done(self, task: asyncio.Future[Any]) -> None:
        """Hold this slot until ``task`` is done (also when it is cancelled
        before it starts)."""
        self._handed_off = True
        task.add_done_callback(lambda _task: self.release())


class _SlotBody:
    """The body of a slot's streaming response: ``content``, releasing the
    slot and closing ``content`` when it ends, fails, is cancelled or is
    closed (also when it is closed before it ever started)."""

    def __init__(self, content: AsyncGenerator[str], slot: ActiveSlot) -> None:
        self._content = content
        self._slot = slot

    def __aiter__(self) -> _SlotBody:
        return self

    async def __anext__(self) -> str:
        try:
            return await self._content.__anext__()
        except BaseException:
            # StopAsyncIteration, a failure, or CancelledError (the client
            # went away while the stream waited for its next event).
            await self.aclose()
            raise

    async def aclose(self) -> None:
        self._slot.release()
        # Closing a finished generator does nothing; one still open (the
        # client went away between two events) runs its cleanup now, which
        # cancels its fan_out tasks.
        with contextlib.suppress(RuntimeError):
            await self._content.aclose()


class _SlotStreamingResponse(StreamingResponse):
    """A ``StreamingResponse`` that closes its ``_SlotBody`` when it is done
    with, whatever ended it."""

    def __init__(self, content: _SlotBody, *, media_type: str) -> None:
        super().__init__(content, media_type=media_type)
        self._body = content

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self._body.aclose()


class ActiveLimit:
    """At most ``per_identity`` long-lived things (streams, jobs, sockets)
    open per caller and ``total`` overall.

    The app is one process and one event loop, so plain counters suffice: a
    claim and a release never interleave. Every caller gets the same
    numbers, an admin included; the server API token is one identity."""

    def __init__(self, what: str, per_identity: int, total: int) -> None:
        self.what = what
        self.per_identity = max(1, per_identity)
        self.total = max(1, total)
        self._open: dict[str, int] = {}

    def active(self, identity: str | None = None) -> int:
        """How many are open: for ``identity``, or overall."""
        if identity is None:
            return sum(self._open.values())
        return self._open.get(identity, 0)

    def refusal(self, identity: str) -> str | None:
        """Why one more for ``identity`` is refused, ``None`` when it is not."""
        if self._open.get(identity, 0) >= self.per_identity:
            return (
                f"You already have {self.per_identity} {self.what} open, the most one user may run at once. "
                "Wait for one to finish or close it, then try again."
            )
        if self.active() >= self.total:
            return f"The server is already running its limit of {self.total} {self.what}. Try again shortly."
        return None

    def try_claim(self, identity: str | None) -> ActiveSlot | None:
        """A slot for ``identity`` (``None``: ``anonymous``), or ``None``
        when the caller or the server is at the limit."""
        key = identity or "anonymous"
        if self.refusal(key) is not None:
            return None
        return self._take(key)

    def claim(self, request: Any) -> ActiveSlot:
        """A slot for the caller of an HTTP request; 429 with the reason
        when the caller or the server is at the limit."""
        identity = session_identity(request_session(request)) or "anonymous"
        reason = self.refusal(identity)
        if reason is not None:
            raise HTTPException(status_code=429, detail=reason, headers={"Retry-After": "10"})
        return self._take(identity)

    def _take(self, identity: str) -> ActiveSlot:
        self._open[identity] = self._open.get(identity, 0) + 1
        return ActiveSlot(self, identity)

    def _release(self, identity: str) -> None:
        left = self._open.get(identity, 0) - 1
        if left > 0:
            self._open[identity] = left
        else:
            self._open.pop(identity, None)

    def reset(self) -> None:
        """Forget every open slot (tests)."""
        self._open.clear()


# Heavy: inventory discovery scans and syncs (streamed, inline or as a
# background job) and topology neighbor discovery.
DISCOVERY_RUNS = ActiveLimit("discovery runs", state.DISCOVERY_RUNS_PER_USER, state.DISCOVERY_RUNS_TOTAL)
# Cheap: the topology utilization stream and the /ws/* job output sockets.
LIVE_STREAMS = ActiveLimit("live streams", state.LIVE_STREAMS_PER_USER, state.LIVE_STREAMS_TOTAL)

# Close code of a WebSocket refused for the limit: 1013 "Try Again Later".
WS_CLOSE_TRY_AGAIN_LATER = 1013


def limit_websocket(limit: ActiveLimit) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Wrap a ``/ws/*`` handler so each signed-in caller holds one slot of
    ``limit`` while its socket is open; past the limit the handshake is
    closed with 1013. A handshake without a validly signed session cookie
    takes no slot: the handler itself refuses it."""

    def wrap(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(fn)
        async def handler(*args: Any, **kwargs: Any) -> Any:
            websocket = next((v for v in (*args, *kwargs.values()) if isinstance(v, WebSocket)), None)
            token = websocket.cookies.get("session") if websocket is not None else None
            session = _verify_session_token_fn(token) if token and _verify_session_token_fn else None
            identity = session_identity(session)
            if identity is None or websocket is None:
                return await fn(*args, **kwargs)
            slot = limit.try_claim(identity)
            if slot is None:
                LOGGER.warning("websocket refused: %s at the %s limit", identity, limit.what)
                await websocket.close(code=WS_CLOSE_TRY_AGAIN_LATER, reason=f"Too many {limit.what} open")
                return None
            with slot:
                return await fn(*args, **kwargs)

        return handler

    return wrap


def resolve_state_root() -> str | None:
    """The directory Plexus keeps persistent on-disk state in:
    ``PLEXUS_STATE_DIR``, else the folder of ``APP_SESSION_KEY_FILE`` (the
    ``/app/state`` volume in the container), else ``None`` (a developer
    checkout; callers fall back to a folder of the repository)."""
    explicit = os.getenv("PLEXUS_STATE_DIR", "").strip()
    if explicit:
        return explicit
    key_file = os.getenv("APP_SESSION_KEY_FILE", "").strip()
    if key_file:
        return os.path.dirname(key_file)
    return None


def _corr_id(request) -> str:
    """Extract the correlation ID attached by correlation_id_middleware."""
    return getattr(request.state, "correlation_id", "") if hasattr(request, "state") else ""


async def read_bounded_body(request, max_bytes: int) -> bytes | None:
    """The request body, or ``None`` once it passes ``max_bytes`` (declared
    or streamed). Inbound webhook receivers read unauthenticated bodies
    before checking their signature, so they never buffer more than this."""
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        return None
    if declared > max_bytes:
        return None
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > max_bytes:
            return None
    return bytes(body)


# The OpenAPI request body of a route that takes its file through
# ``uploaded_file`` (pass as ``openapi_extra``): such a route declares no
# ``File`` parameter for FastAPI to describe.
FILE_UPLOAD_OPENAPI = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {"file": {"type": "string", "format": "binary"}},
                }
            }
        },
    }
}
# Form parts an upload request may carry besides its one file.
_UPLOAD_FORM_MAX_FIELDS = 16


@contextlib.asynccontextmanager
async def uploaded_file(request: Request, field: str = "file") -> AsyncIterator[UploadFile]:
    """The file part ``field`` of a multipart request, read when this is
    entered and closed (its spooled copy deleted) on exit; 422 without one,
    400 for a body that does not parse (as FastAPI answers for a ``File``
    parameter).

    FastAPI reads the body of a route that declares a ``File`` parameter
    before any dependency or handler code runs, so such a route spools a
    whole upload for a caller it then refuses. A route with a large body
    limit declares no ``File`` parameter and calls this after its own
    checks: a refused caller is answered before a byte is read."""
    try:
        form = await request.form(max_files=1, max_fields=_UPLOAD_FORM_MAX_FIELDS)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="There was an error parsing the body") from exc
    try:
        upload = form.get(field)
        if not isinstance(upload, UploadFile):
            raise HTTPException(status_code=422, detail=f"Send the file in the form field '{field}'")
        yield upload
    finally:
        await form.close()


def _request_scheme(request) -> str:
    """The scheme the browser used: ``X-Forwarded-Proto`` from a reverse
    proxy, else the request's own scheme (direct TLS termination)."""
    return request.headers.get("x-forwarded-proto", request.url.scheme).strip().lower()


# ── Session helper (initialized by app.py) ───────────────────────────────────

_verify_session_token_fn = None


def init_shared(verify_session_token_fn):
    """Called by app.py at module load time to inject the session verifier."""
    global _verify_session_token_fn
    _verify_session_token_fn = verify_session_token_fn


def _get_session(request) -> dict | None:
    """Extract session data from the request cookie without raising (None for
    an object with no cookies, e.g. a route function called directly)."""
    token = (getattr(request, "cookies", None) or {}).get("session")
    if not token:
        return None
    if _verify_session_token_fn is None:
        return None
    return _verify_session_token_fn(token)


def _session_user_id(request) -> int:
    """The user id of the session making the request; 401 when there is none."""
    user_id = (_get_session(request) or {}).get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return int(user_id)


def _session_user(request) -> str:
    """The username of the session making the request, or ``""``."""
    return (_get_session(request) or {}).get("user", "")


def request_session(request) -> dict | None:
    """The session of an authenticated request, the server API token
    included. ``require_auth`` gives a token caller the session
    ``{"user": "api-token", "user_id": 0, "auth_mode": "token"}``, which the
    cookie-only ``_get_session`` never returns. For a handler that serves
    token callers and tells them apart by ``auth_mode``."""
    session = getattr(getattr(request, "state", None), "auth_session", None)
    if isinstance(session, dict) and session.get("auth_mode") == "token":
        return session
    return _get_session(request)


async def admin_session(request: Request) -> dict:
    """The session of an admin caller (an admin user or the server API
    token): 401 without a session, 403 for anyone else. Called by a handler
    or used as the dependency of an admin-only route of a router mounted
    behind ``require_auth``, which has checked the session itself."""
    session = request_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if session.get("auth_mode") != "token":
        user = await db.get_user_by_id(session["user_id"])
        if not user or user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
    return session


async def caller_features(request) -> frozenset[str] | None:
    """The feature keys of the caller of an HTTP request, ``None`` for an
    admin or the server API token (every feature). Reads what the feature
    gate resolved for this request (``request.state``); resolves it the same
    way when it is not there. No session: no features."""
    session = getattr(request.state, "auth_session", None)
    if not isinstance(session, dict):
        return frozenset()
    if session.get("auth_mode") == "token":
        return None
    user = getattr(request.state, "auth_user", None)
    if not isinstance(user, dict):
        user = await db.get_user_by_id(int(session.get("user_id") or 0))
    if not user:
        return frozenset()
    if user.get("role") == "admin":
        return None
    features = getattr(request.state, "auth_features", None)
    if not isinstance(features, list):
        from netcontrol.routes.auth import _get_user_features

        features = await _get_user_features(user)
    return frozenset(features)


async def require_any_feature(request, *feature_keys: str) -> None:
    """403 unless the caller of an HTTP request holds at least one of
    ``feature_keys`` (an admin and the server API token hold every one).
    For a route that, past its own router's feature gate, also exposes the
    data of another feature."""
    features = await caller_features(request)
    if features is None or any(key in features for key in feature_keys):
        return
    names = " or ".join(f"'{key}'" for key in feature_keys)
    raise HTTPException(status_code=403, detail=f"Access denied: this needs the {names} feature")


def ws_origin_allowed(websocket) -> bool:
    """Whether a WebSocket handshake comes from a page of this site.

    CORS does not cover WebSockets, and the SameSite=Strict session cookie
    is still sent by a page on a sibling subdomain (same site), so without
    this check such a page could read the signed-in user's streams.

    Allowed: no ``Origin`` (a non-browser client; a browser always sends
    one), an ``Origin`` whose host is the request's ``Host``, and the
    origins of ``APP_CORS_ORIGINS``. Ports are not compared, because the
    shipped nginx forwards ``$host``, which carries none.
    """
    origin = (websocket.headers.get("origin") or "").strip().rstrip("/").lower()
    if not origin:
        return True
    if origin in {str(allowed).strip().rstrip("/").lower() for allowed in state.APP_CORS_ALLOW_ORIGINS}:
        return True
    try:
        origin_host = urlsplit(origin).hostname
        request_host = urlsplit("//" + (websocket.headers.get("host") or "")).hostname
    except ValueError:
        return False
    return bool(origin_host) and origin_host == request_host


async def verify_ws_session(token: str | None, websocket=None) -> dict | None:
    """Validate a WebSocket session token the same way require_auth does.

    The raw ``verify_session_token`` only checks the signature; the idle
    timeout and absolute-lifetime cap are enforced by ``require_auth`` for
    HTTP requests. WebSocket handlers bypass ``require_auth``, so without
    this an arbitrarily old (but validly signed) cookie could open a stream.
    This mirrors require_auth's time checks, honoring the
    ``session_never_expires`` kiosk opt-out.

    A handler passes its ``websocket`` so a handshake from a page of
    another site is refused too (``ws_origin_allowed``).

    Returns the session dict on success, or None (caller should close the
    socket with code 1008).
    """
    if not token or _verify_session_token_fn is None:
        return None
    if websocket is not None and not ws_origin_allowed(websocket):
        return None
    session = _verify_session_token_fn(token)
    if not session or "user_id" not in session:
        return None
    user = await db.get_user_by_id(session["user_id"])
    if not user:
        return None
    # Forced-password-change gate (mirrors the HTTP middleware, which blocks
    # every route except the password-change endpoints). A user who must
    # rotate their password may not open device-output streams first.
    if user.get("must_change_password"):
        return None
    if session_rejection(session, user) is not None:
        return None
    return session


def session_rejection(session: dict, user: dict | None) -> str | None:
    """Why ``require_auth`` would refuse a validly signed ``session`` whose
    user record is ``user``, or ``None`` when it would accept it.

    Reasons: ``"user_missing"`` (deleted account), ``"disabled"`` (an admin
    switched the account off; callers treat it like ``"revoked"``),
    ``"revoked"`` (the user's session epoch moved on: password change,
    admin reset, privilege change, rename, sign-out), ``"expired"`` (24h absolute cap) and
    ``"idle"`` (idle timeout). Kiosk accounts (``session_never_expires``)
    skip the two time checks. The forced password change is not a reason
    here: each caller decides what that user may still reach.
    """
    if not user:
        return "user_missing"
    if user.get("disabled"):
        return "disabled"
    if int(session.get("session_epoch") or 0) != int(user.get("session_epoch") or 0):
        return "revoked"
    if bool(user.get("session_never_expires")):
        return None
    now = int(time.time())
    originally_issued = int(session.get("originally_issued_at") or 0)
    if originally_issued > 0 and now - originally_issued > _WS_SESSION_MAX_AGE:
        return "expired"
    idle_timeout = int(state.LOGIN_RULES.get("session_idle_timeout", 1800))
    last_activity = int(session.get("last_activity") or 0)
    if idle_timeout > 0 and last_activity > 0 and now - last_activity > idle_timeout:
        return "idle"
    return None


# ── Object-level authorization (ownership) ───────────────────────────────────


async def require_owner_or_admin(request, owner_username: str | None) -> dict | None:
    """Enforce that the caller owns an object (by username) or is an admin.

    Router-level ``require_auth``/``require_feature`` has already
    authenticated the request before any handler runs, so if no session
    cookie is present the request was authenticated via the server API
    token (``auth_mode == "token"``), which is admin-equivalent by design -
    such callers are allowed through.

    For cookie-authenticated requests the caller must either be the object's
    owner (``owner_username`` matches the session user) or hold the admin
    role. Raises HTTPException(403) otherwise. Returns the session dict (or
    None for API-token callers).

    This is object-level authorization layered on top of the feature-level
    gate; it prevents a user who merely holds a feature (e.g. ``jobs``) from
    reading or controlling objects created by other users.
    """
    session = _get_session(request)
    if session is not None and owner_username and session.get("user") == owner_username:
        return session
    if await caller_is_admin(request):
        return session
    raise HTTPException(status_code=403, detail="You do not have access to this resource")


async def is_owner_or_admin(request, owner_username: str | None) -> bool:
    """``require_owner_or_admin`` as a test: for a route that answers another
    user's object like an unknown one (404) instead of 403."""
    try:
        await require_owner_or_admin(request, owner_username)
    except HTTPException:
        return False
    return True


async def caller_is_admin(request) -> bool:
    """Whether the caller of an authenticated request is an admin: an admin
    session, or no session cookie (the server API token, admin-equivalent,
    as in ``require_owner_or_admin``)."""
    session = _get_session(request)
    if session is None:
        return True
    user = await db.get_user_by_id(session["user_id"])
    return bool(user and user.get("role") == "admin")


# ── Credential ownership enforcement ─────────────────────────────────────────


async def require_credential_access(
    credential_id,
    *,
    session: dict | None = None,
    submitter_username: str | None = None,
    allow_service: bool = False,
) -> dict:
    """Fetch a credential and enforce that the caller is allowed to use it.

    Pass either a live `session` dict (HTTP request context) or a
    `submitter_username` (background worker / scheduler running a task that
    was originally queued by a user).  At least one must be provided.

    Rules for **user credentials** (is_service=0):
      - Strictly per-owner: ``owner_id`` must match the caller's user id.
      - Admin role does NOT grant access to another user's credential.
      - API-token callers bypass the owner check.
      - Unowned (``owner_id`` is NULL) creds are usable only by API tokens.

    Rules for **service credentials** (is_service=1):
      - Reserved for Plexus-internal background work (monitoring, scheduled
        discovery). Callers must opt in by passing ``allow_service=True``;
        this prevents user-driven endpoints (job launch, etc.) from picking
        up a service cred via misconfiguration.
      - When opted in, admins, API-token callers, and admin submitters may
        use them. Non-admin users cannot use a service cred even with the
        opt-in flag.

    Raises HTTPException(400/401/403/404) on any failure so callers that
    already propagate HTTPException don't need extra handling.

    Every decision (allow or deny) emits a ``credential`` audit event so the
    trail records who used which credential. Grants that don't rest on plain
    ownership (API-token bypass, admin use of a service credential) are
    flagged with an ``override`` marker so legitimate admin use is
    distinguishable from a future authorization regression.
    """
    caller = (
        API_TOKEN_USER
        if session is not None and session.get("auth_mode") == "token"
        else (session or {}).get("user") or submitter_username or "(unauthenticated)"
    )

    async def _deny(status: int, detail: str, cred: dict | None = None) -> HTTPException:
        await _audit(
            "credential",
            "use_denied",
            user=str(caller),
            detail=f"credential_id={credential_id} owner_id={cred.get('owner_id') if cred else '?'} reason={detail}",
        )
        return HTTPException(status_code=status, detail=detail)

    async def _allow(cred: dict, override: str | None = None) -> dict:
        await _audit(
            "credential",
            "use",
            user=str(caller),
            detail=f"credential_id={credential_id} owner_id={cred.get('owner_id')} "
            f"service={int(bool(cred.get('is_service')))}" + (f" override={override}" if override else ""),
        )
        # An external reference is resolved only once access is granted
        # (netcontrol/secrets_providers/service.py); a failure is a 502
        # naming the provider, never a value.
        from netcontrol.secrets_providers.service import SecretsProviderError, materialize_credential

        try:
            return await materialize_credential(cred, strict=True, actor=str(caller)) or cred
        except SecretsProviderError as exc:
            raise HTTPException(
                status_code=502, detail=f"The credential's external secret could not be resolved: {exc.message}"
            ) from exc

    if credential_id is None:
        raise await _deny(400, "credential_id is required")

    cred = await db.get_credential_raw(credential_id, resolve_external=False)
    if not cred:
        raise await _deny(404, "Credential not found")

    is_service_cred = bool(cred.get("is_service"))

    if is_service_cred and not allow_service:
        # Service creds are only available to call sites that explicitly
        # opt in; this protects user-facing flows from accidentally pulling
        # a Plexus-internal cred just because it was configured as a default.
        raise await _deny(403, "This credential is reserved for Plexus internal use", cred)

    if session is not None:
        if session.get("auth_mode") == "token":
            return await _allow(cred, override=API_TOKEN_USER)
        user_id = session.get("user_id")
        if user_id is None:
            raise await _deny(401, "Not authenticated", cred)
        if is_service_cred:
            user = await db.get_user_by_id(int(user_id))
            if user and user.get("role") == "admin":
                return await _allow(cred, override="admin-service-cred")
            raise await _deny(403, "Service credentials require admin access", cred)
        if cred.get("owner_id") == int(user_id):
            return await _allow(cred)
        raise await _deny(403, "You can only use your own credentials", cred)

    if submitter_username:
        user = await db.get_user_by_username(submitter_username)
        if not user:
            # Submitter no longer exists (deleted account). Fail closed.
            raise await _deny(403, "Submitter account is no longer valid", cred)
        if user.get("disabled"):
            # A disabled account runs nothing: its sessions and tokens are
            # refused, and so is work it queued or scheduled earlier.
            raise await _deny(403, "Submitter account is disabled", cred)
        if is_service_cred:
            if user.get("role") == "admin":
                return await _allow(cred, override="admin-service-cred")
            raise await _deny(403, "Service credentials require admin submitter", cred)
        if cred.get("owner_id") == int(user["id"]):
            return await _allow(cred)
        raise await _deny(403, "Credential is not owned by the task submitter", cred)

    raise await _deny(401, "Not authenticated", cred)


async def service_credential() -> dict | None:
    """The Plexus service credential (``AUTH_CONFIG.service_credential_id``),
    or ``None`` when none is configured or the id no longer points at one.

    When no id is configured in Settings but exactly one service credential
    exists, that one is used: there is nothing to choose between, and an
    admin who created a service credential expects unattended work to pick
    it up. With several and none selected, the choice stays explicit.

    Unattended work may only use a Plexus-owned service credential, never a
    user's personal stored credential."""
    cred_id = state.AUTH_CONFIG.get("service_credential_id")
    if not isinstance(cred_id, int):
        candidates = await db.get_service_credentials()
        if len(candidates) != 1:
            return None
        cred_id = int(candidates[0]["id"])
    cred = await db.get_credential_raw(cred_id)
    if not cred or not cred.get("is_service"):
        return None
    return cred


# ── Config capture/push/diff ────────────────────────────────────────────────

# Patterns matching volatile IOS/NX-OS metadata lines that change between
# captures but do not represent actual configuration drift.
_VOLATILE_LINE_RES = [
    re.compile(r"^Current configuration\s*:\s*\d+\s*bytes", re.IGNORECASE),
    re.compile(r"^Building configuration\.\.\.", re.IGNORECASE),
    re.compile(r"^! Last configuration change at\b"),
    re.compile(r"^! NVRAM config last updated at\b"),
    re.compile(r"^! No configuration change since last restart", re.IGNORECASE),
    re.compile(r"^ntp clock-period\s+\d+"),
]


def _normalize_config(text: str) -> str:
    """Strip volatile metadata lines so they don't appear as drift."""
    lines = text.splitlines(keepends=True)
    return "".join(line for line in lines if not any(pat.search(line.strip()) for pat in _VOLATILE_LINE_RES))


def _compute_config_diff(
    baseline_text: str,
    actual_text: str,
    baseline_label: str = "baseline",
    actual_label: str = "actual",
) -> tuple[str, int, int]:
    """Compute unified diff between baseline and actual config.

    Volatile metadata lines (byte counts, timestamps, ntp clock-period) are
    stripped before comparison so they never show up as false drift.

    Returns (diff_text, lines_added, lines_removed).
    """
    baseline_lines = _normalize_config(baseline_text).splitlines(keepends=True)
    actual_lines = _normalize_config(actual_text).splitlines(keepends=True)
    diff = list(
        difflib.unified_diff(
            baseline_lines,
            actual_lines,
            fromfile=baseline_label,
            tofile=actual_label,
        )
    )
    diff_text = "".join(diff)
    added = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
    return diff_text, added, removed


def _open_netmiko_session(
    host: dict, credentials: dict, *, autodetect: bool = True, enable_optional: bool = False, **connect_options
):
    """Open a Netmiko session, autodetecting device_type when generic.

    ``autodetect=False`` opens one session with the given type and skips the
    SSHDetect login (discovery reads ``show version`` itself and classifies
    the OS from it). ``connect_options`` (``conn_timeout``, ``auth_timeout``
    ...) go to Netmiko's ``ConnectHandler``.

    With an enable secret the session enters enable mode; a failure there
    closes the session and raises, unless ``enable_optional`` (a read-only
    caller that does not know the platform yet, such as discovery), which
    keeps the session in user mode instead.

    Returns ``(connection, resolved_device_type)``.  The caller is
    responsible for ``disconnect()``.

    When the stored device_type is the generic 'cisco_ios' default
    (or 'unknown'), Netmiko's SSHDetect is used first to autodetect the
    real platform (e.g. cisco_xe for IOS-XE devices like Catalyst
    9200/9300).  Returning the resolved type lets callers look up the
    matching ``Driver`` after the autodetect, so per-vendor command
    syntax is correct even when inventory has the wrong type stored.
    """
    import netmiko
    from netmiko import SSHDetect
    from routes.crypto import decrypt

    from netcontrol.drivers import DriverCapabilityError, get_driver, session_platform

    # A platform with no command line (an Instant On switch) has no SSH
    # server: say so instead of timing out on the connection.
    if not get_driver(host.get("device_type")).cli:
        raise DriverCapabilityError(
            f"{host.get('device_type')} devices have no command line (SNMP only): no SSH session is opened"
        )

    device = {
        "device_type": host.get("device_type", "cisco_ios"),
        "host": host["ip_address"],
        "username": credentials["username"],
        "password": decrypt(credentials["password"]),
        "secret": decrypt(credentials.get("secret", "")),
    }

    # Autodetect when the stored type is a generic Cisco default
    # that may be wrong (e.g. IOS-XE devices mis-classified as IOS).
    if autodetect and device["device_type"] in ("cisco_ios", "unknown"):
        guesser = None
        try:
            detect_device = {**device, "device_type": "autodetect"}
            guesser = SSHDetect(**detect_device)
            best = guesser.autodetect()
            if best:
                LOGGER.info("Autodetected device_type %s for %s (was %s)", best, device["host"], device["device_type"])
                device["device_type"] = best
        except Exception:
            LOGGER.debug("SSHDetect failed for %s, using %s", device["host"], device["device_type"])
        finally:
            # Disconnect even when autodetect() raised, or the probe session
            # (socket + paramiko transport thread) leaks until GC.
            if guesser is not None:
                try:
                    guesser.connection.disconnect()
                except Exception:
                    LOGGER.debug("SSHDetect disconnect failed for %s", device["host"])

    # The session may be opened under another Netmiko name of the same
    # platform (the one ntc-templates has its templates under); the type
    # returned is still the host's, which the drivers are registered by.
    session_device = {**device, "device_type": session_platform(device["device_type"])}
    net_connect = netmiko.ConnectHandler(**session_device, **connect_options)
    if device["secret"]:
        try:
            net_connect.enable()
        except Exception as exc:
            if not enable_optional:
                # Close the session before raising, or it leaks until GC.
                try:
                    net_connect.disconnect()
                except Exception:
                    LOGGER.debug("disconnect after failed enable failed for %s", device["host"])
                raise
            LOGGER.info("No enable mode on %s (%s); continuing in user mode", device["host"], type(exc).__name__)
    return net_connect, device["device_type"]


def _send_parsed(conn, command: str, driver=None, **send_options):
    """Blocking: one show command parsed by ntc-templates. Returns the
    parsed rows, or the raw text when no template parsed it (what Netmiko's
    ``use_textfsm`` returns). The templates are those of the session's
    platform, or of the driver's ``template_platform`` when it names one."""
    from netmiko.utilities import get_structured_data

    platform = driver.template_platform if driver is not None else None
    if not platform:
        return conn.send_command(command, use_textfsm=True, **send_options)
    output = conn.send_command(command, **send_options)
    return get_structured_data(str(output or ""), platform=platform, command=command)


# Netmiko's default read timeout (10 s) is too short for a chassis to print
# its configuration, and far too short with every default included.
_CONFIG_READ_TIMEOUT_SECONDS = 120
_FULL_CONFIG_READ_TIMEOUT_SECONDS = 180

# What a device type without a capture command (no driver) is sent.
_FALLBACK_CONFIG_COMMAND = "show running-config"


def _config_capture_commands(device_type: str) -> tuple[str, str | None]:
    """``(plain command, defaults-included command or None)`` for a device
    type. The commands come from its driver, so Junos gets ``show
    configuration | display set``; a type without a driver gets ``show
    running-config``. The second is None when the platform has no separate
    form that prints default settings."""
    from netcontrol.drivers import DriverCapabilityError, get_driver

    driver = get_driver(device_type)
    try:
        plain = driver.capture_running_config_command()
    except DriverCapabilityError:
        return _FALLBACK_CONFIG_COMMAND, None
    full = driver.capture_full_config_command()
    return plain, (full if full != plain else None)


def _read_device_configs(conn, device_type: str) -> tuple[str, str]:
    """Blocking: read ``(plain config, config with defaults)`` over an open
    session. The second is ``""`` when the platform has no such form or the
    device did not print it in time; the plain config is what callers diff,
    push and parse, so its failure raises and the other's does not."""
    plain_cmd, full_cmd = _config_capture_commands(device_type)
    plain = str(conn.send_command(plain_cmd, read_timeout=_CONFIG_READ_TIMEOUT_SECONDS) or "")
    full = ""
    if full_cmd:
        try:
            full = str(conn.send_command(full_cmd, read_timeout=_FULL_CONFIG_READ_TIMEOUT_SECONDS) or "")
        except Exception as exc:  # noqa: BLE001 - the plain config is still usable
            LOGGER.warning("config capture: %r not read: %s", full_cmd, exc)
    return plain, full


async def _capture_device_configs(host: dict, credentials: dict) -> tuple[str, str]:
    """SSH to a device once and read ``(plain config, config with
    defaults)`` (see ``_read_device_configs``)."""

    def _do_capture():
        conn, resolved_type = _open_netmiko_session(host, credentials)
        try:
            return _read_device_configs(conn, resolved_type)
        finally:
            conn.disconnect()

    return await asyncio.to_thread(_do_capture)


async def _capture_running_config(host: dict, credentials: dict) -> str:
    """SSH to a device and read its plain running configuration only.

    Inventory devices go through ``netcontrol.routes.device_config``, which
    stores what it reads in Config Backups; this is for targets that are
    not inventory hosts (lab runtime nodes).
    """

    def _do_capture():
        conn, resolved_type = _open_netmiko_session(host, credentials)
        try:
            plain_cmd, _ = _config_capture_commands(resolved_type)
            return conn.send_command(plain_cmd, read_timeout=_CONFIG_READ_TIMEOUT_SECONDS)
        finally:
            conn.disconnect()

    return await asyncio.to_thread(_do_capture)


async def _run_show_command(
    host: dict,
    credentials: dict,
    command: str,
    *,
    autodetect: bool = True,
    enable_optional: bool = False,
    **connect_options,
) -> str:
    """SSH to a device and run a single show command via Netmiko.

    The command is supplied by the caller verbatim - this helper only
    handles the SSH session lifecycle and autodetect.  Returns the raw
    command output string. ``autodetect``, ``enable_optional`` and
    ``connect_options`` are passed to :func:`_open_netmiko_session`.
    """

    def _do_run():
        conn, _ = _open_netmiko_session(
            host, credentials, autodetect=autodetect, enable_optional=enable_optional, **connect_options
        )
        try:
            return conn.send_command(command)
        finally:
            conn.disconnect()

    return await asyncio.to_thread(_do_run)


def _run_show_commands(
    host: dict,
    credentials: dict,
    commands: tuple[str, ...],
    *,
    read_timeout: float = 30,
    **session_options,
) -> dict[str, str]:
    """Blocking: one SSH session, every show command, best-effort per
    command. Returns ``{command: output}``; a command that fails gives
    ``(command failed: <error type>)`` as its output, so one bad command
    does not lose the rest. A failed login raises. ``session_options``
    (``autodetect``, ``enable_optional``, ``conn_timeout`` ...) go to
    :func:`_open_netmiko_session`. Run it with ``asyncio.to_thread``."""
    conn, _resolved = _open_netmiko_session(host, credentials, **session_options)
    outputs: dict[str, str] = {}
    try:
        for command in commands:
            try:
                outputs[command] = str(conn.send_command(command, read_timeout=read_timeout))
            except Exception as exc:  # noqa: BLE001 - one bad command must not lose the rest
                outputs[command] = f"(command failed: {type(exc).__name__})"
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001 - best-effort teardown
            LOGGER.debug("disconnect after show commands failed for %s", host.get("ip_address"))
    return outputs


async def _collect_mac_table_via_cli(host: dict, credentials: dict) -> list[dict]:
    """SSH to a device and pull the MAC address-table via Netmiko + ntc-templates.

    Returns a normalised list of ``{"mac", "vlan", "port", "type"}`` rows.

    The mac_tracking collector uses this in preference to the SNMP
    bridge/Q-BRIDGE MIB walks because the CLI returns every VLAN's FDB
    in one round-trip - on Cisco, SNMP only exposes VLAN 1's bridge MIB
    in the default context and needs a per-VLAN SNMPv3 context dance to
    see anything else, which is unreliable in the wild.

    Raises ``DriverCapabilityError`` when the resolved driver doesn't
    implement ``mac_table_show_command()`` (firewalls, routers without
    L2 forwarding, etc.) - the caller is expected to fall back to SNMP
    in that case.
    """
    from netcontrol.drivers import get_driver

    def _do_collect() -> list[dict]:
        conn, resolved_type = _open_netmiko_session(host, credentials)
        try:
            driver = get_driver(resolved_type)
            # mac_table_show_command() may raise DriverCapabilityError for
            # platforms with no L2 table; let it propagate so the caller
            # knows to fall back rather than silently returning an empty
            # list (which would look the same as "device has no MACs").
            cmd = driver.mac_table_show_command()
            # use_textfsm pulls ntc-templates' parsed output (a list of
            # dicts).  When no template matches, Netmiko returns the raw
            # string instead - guard against that so we don't crash with
            # AttributeError downstream.
            parsed = _send_parsed(conn, cmd, driver)
            if not isinstance(parsed, list):
                return []
            return driver.parse_mac_table(parsed)
        finally:
            conn.disconnect()

    return await asyncio.to_thread(_do_collect)


async def _push_config_to_device(host: dict, credentials: dict, config_lines: list[str]) -> str:
    """SSH to a device and push config lines via Netmiko, then save."""

    def _do_push():
        conn, _ = _open_netmiko_session(host, credentials)
        try:
            output = conn.send_config_set(config_lines)
            # save_config() is Netmiko's vendor-aware persist call - it
            # already knows ``write memory`` vs ``copy running-config
            # startup-config`` per platform, so the driver's
            # save_config_commands() is only used by routes that bypass
            # Netmiko's high-level helper.
            save_output = conn.save_config()
            return output + "\n" + save_output
        finally:
            conn.disconnect()

    return await asyncio.to_thread(_do_push)
