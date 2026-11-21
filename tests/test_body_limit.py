"""Request body limit middleware (netcontrol/body_limit.py)."""

from __future__ import annotations

import json
import re

import netcontrol.app as app_module
import pytest
from netcontrol import body_limit
from netcontrol.body_limit import MIB, BodyLimitMiddleware
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

# ── A small app behind the middleware ────────────────────────────────────────


async def _echo(request: Request) -> JSONResponse:
    body = await request.body()
    return JSONResponse({"size": len(body)})


async def _protected(request: Request) -> JSONResponse:
    # Stands in for require_auth: it would only run after the body is read.
    await request.body()
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)


def _client(default_limit: int = 100, path_limits=None) -> TestClient:
    inner = Starlette(
        routes=[
            Route("/echo", _echo, methods=["POST"]),
            Route("/protected", _protected, methods=["POST"]),
            Route("/upload/{n}", _echo, methods=["POST"]),
        ]
    )
    limits = path_limits if path_limits is not None else [(re.compile(r"/upload/[0-9]+"), 1000)]
    app = BodyLimitMiddleware(inner, default_limit=default_limit, path_limits=limits)
    return TestClient(app)


def _chunks(total: int, size: int = 10):
    sent = 0
    while sent < total:
        n = min(size, total - sent)
        sent += n
        yield b"x" * n


def test_small_body_passes():
    resp = _client().post("/echo", content=b"x" * 100)
    assert resp.status_code == 200
    assert resp.json() == {"size": 100}


def test_no_body_passes():
    resp = _client().post("/echo")
    assert resp.status_code == 200
    assert resp.json() == {"size": 0}


def test_declared_length_over_limit_is_413_before_the_app_runs():
    resp = _client().post("/protected", content=b"x" * 101)
    assert resp.status_code == 413
    body = resp.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "payload_too_large"


def test_chunked_body_over_limit_is_413():
    # A generator body is sent without Content-Length (chunked).
    resp = _client().post("/protected", content=_chunks(500))
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "payload_too_large"


def test_chunked_body_under_limit_passes():
    resp = _client().post("/echo", content=_chunks(90))
    assert resp.status_code == 200
    assert resp.json() == {"size": 90}


def test_allowlisted_path_accepts_a_larger_body():
    client = _client()
    assert client.post("/upload/7", content=b"x" * 900).json() == {"size": 900}
    assert client.post("/upload/7", content=b"x" * 1001).status_code == 413
    # Only the listed path shape is allowlisted.
    assert client.post("/upload/abc", content=b"x" * 900).status_code == 413


def test_malformed_content_length_is_400():
    resp = _client().post("/echo", content=b"x", headers={"Content-Length": "abc"})
    assert resp.status_code == 400


# ── Raw ASGI: streamed chunks and an app that answers after the limit ────────


async def _run(app, path: str, chunks: list[bytes], headers=None):
    messages = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]
    sent: list[dict] = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": path, "headers": headers or []}
    await app(scope, receive, send)
    return sent


@pytest.mark.asyncio
async def test_streamed_chunks_counted_and_late_app_response_dropped():
    reads: list[int] = []

    async def inner(scope, receive, send):
        total = 0
        try:
            while True:
                message = await receive()
                total += len(message.get("body", b""))
                reads.append(total)
                if not message.get("more_body"):
                    break
        except Exception:
            # An app that swallows the error and answers anyway.
            await send({"type": "http.response.start", "status": 500, "headers": []})
            await send({"type": "http.response.body", "body": b"oops"})
            return
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = BodyLimitMiddleware(inner, default_limit=25, path_limits=[])
    sent = await _run(app, "/x", [b"a" * 10, b"b" * 10, b"c" * 10, b"d" * 10])
    starts = [m for m in sent if m["type"] == "http.response.start"]
    assert [m["status"] for m in starts] == [413]
    assert reads == [10, 20]  # stopped at the chunk that crossed the limit
    payload = json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))
    assert payload["error"]["code"] == "payload_too_large"


@pytest.mark.asyncio
async def test_non_http_scopes_pass_through():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])

    app = BodyLimitMiddleware(inner, default_limit=1, path_limits=[])
    await app({"type": "lifespan"}, None, None)
    await app({"type": "websocket", "path": "/ws/x", "headers": []}, None, None)
    assert seen == ["lifespan", "websocket"]


# ── Configuration ────────────────────────────────────────────────────────────


def test_default_limit_from_env(monkeypatch):
    monkeypatch.setenv("APP_MAX_REQUEST_BODY_MB", "3")
    assert body_limit.max_body_bytes_from_env() == 3 * MIB
    for bad in ("", "abc", "0", "-5"):
        monkeypatch.setenv("APP_MAX_REQUEST_BODY_MB", bad)
        assert body_limit.max_body_bytes_from_env() == body_limit.DEFAULT_MAX_BODY_MB * MIB


def test_upload_paths_get_their_route_caps():
    from netcontrol.routes import geolocation, upgrades

    mw = BodyLimitMiddleware(None, default_limit=10 * MIB)
    allowance = body_limit.UPLOAD_ALLOWANCE_BYTES
    assert mw.limit_for("/api/upgrades/images") == upgrades._MAX_IMAGE_UPLOAD_BYTES + allowance
    assert mw.limit_for("/api/geo/floors/12/image") == geolocation._MAX_IMAGE_BYTES + allowance
    assert mw.limit_for("/api/upgrades/images/5") == 10 * MIB
    assert mw.limit_for("/api/auth/login") == 10 * MIB
    # An allowlist entry never lowers a path below the default.
    small = BodyLimitMiddleware(None, default_limit=50 * MIB)
    assert small.limit_for("/api/geo/floors/1/image") == 50 * MIB


# ── The real app ─────────────────────────────────────────────────────────────


def test_registered_outermost_in_the_app():
    assert app_module.app.user_middleware[0].cls is BodyLimitMiddleware


def test_app_refuses_oversized_unauthenticated_body_before_auth(monkeypatch):
    client = TestClient(app_module.app, raise_server_exceptions=False)
    limit = BodyLimitMiddleware(None).limit_for("/api/auth/login")
    over = b"{" + b" " * limit + b"}"

    resp = client.post("/api/auth/login", content=over, headers={"Content-Type": "application/json"})
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "payload_too_large"

    # Chunked, on a route that needs a session: still 413, not 401.
    def stream():
        for _ in range(limit // MIB + 2):
            yield b"x" * MIB

    resp = client.post("/api/inventory", content=stream(), headers={"Content-Type": "application/json"})
    assert resp.status_code == 413

    # A normal unauthenticated request is unaffected.
    resp = client.post("/api/inventory", json={"name": "x"})
    assert resp.status_code in (401, 403)
