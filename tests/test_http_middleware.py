"""The app's HTTP middleware (netcontrol/http_middleware.py).

Pins what every HTTP response gets and the order requests are refused in:
the body limit (413), then the HTTPS redirect (301), then the API rate limit
(429), then the CSRF check (403). Every response, refused or not, streamed,
static, failed or not found, carries the security headers and the request's
correlation id; the session cookie is verified once per request; GZip, CORS
and WebSockets work as before. Every name and address is invented.
"""

from __future__ import annotations

import asyncio
import json

import netcontrol.app as app_module
import netcontrol.routes.state as state
import pytest
from fastapi import Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from netcontrol import http_middleware
from netcontrol.http_middleware import PlexusHTTPMiddleware
from routes.db.change_events import current_correlation_id
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, PlainTextResponse, StreamingResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient

from mcp_helpers import admin_client

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "content-security-policy": http_middleware.CONTENT_SECURITY_POLICY,
}


def _assert_headers(resp) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert resp.headers.get(name) == value, (name, resp.status_code, dict(resp.headers))
    assert resp.headers.get("x-correlation-id"), dict(resp.headers)


def _error_code(resp) -> str:
    return resp.json()["error"]["code"]


# ── Probe routes on the real app ─────────────────────────────────────────────


async def _probe_auth(request: Request) -> dict:
    return {
        "correlation_id": request.state.correlation_id,
        "context_correlation_id": current_correlation_id.get(),
        "precheck_user": (getattr(request.state, "session_precheck", None) or {}).get("user"),
    }


async def _probe_boom() -> dict:
    raise RuntimeError("probe failure")


async def _probe_stream():
    async def events():
        yield "data: 1\n\n"
        yield "data: 2\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


@pytest.fixture
def probes():
    routes = app_module.app.router.routes
    added = [
        APIRoute(
            "/api/mw-probe/auth",
            _probe_auth,
            methods=["GET", "POST"],
            dependencies=[Depends(app_module.require_auth)],
        ),
        APIRoute("/api/mw-probe/boom", _probe_boom, methods=["GET"]),
        APIRoute("/api/mw-probe/stream", _probe_stream, methods=["GET"]),
    ]
    for route in reversed(added):
        routes.insert(0, route)
    yield
    for route in added:
        routes.remove(route)


@pytest.fixture
def admin(monkeypatch, request):
    monkeypatch.setattr(app_module, "LOGIN_ATTEMPTS", {})
    monkeypatch.setattr(app_module, "LOCKED_OUT", {})
    return admin_client(monkeypatch, request)


@pytest.fixture
def rate_limit(monkeypatch):
    """Rate limiting on, with a fresh tracker; returns the config to adjust."""
    cfg = {**state.API_RATE_LIMIT, "enabled": True, "window": 60, "max_read": 120, "max_write": 40}
    monkeypatch.setattr(state, "API_RATE_LIMIT", cfg)
    monkeypatch.setattr(state, "API_RATE_LIMIT_LOCK", asyncio.Lock())
    state.API_RATE_LIMIT_TRACKER.clear()
    yield cfg
    state.API_RATE_LIMIT_TRACKER.clear()


def _revoked_cookie() -> str:
    """A validly signed session cookie of the admin whose epoch has moved on."""
    return app_module.create_session_token("admin", 1, session_epoch=987654)


# ── Short-circuits and their order ───────────────────────────────────────────


def test_body_limit_answers_before_the_https_redirect(admin, monkeypatch):
    monkeypatch.setattr(app_module, "APP_HTTPS_REDIRECT", True)
    limit = PlexusHTTPMiddleware(None).body_limit.limit_for("/api/auth/login")
    resp = admin.raw.post(
        "/api/auth/login",
        content=b"{" + b" " * limit + b"}",
        headers={"Content-Type": "application/json"},
        follow_redirects=False,
    )
    assert resp.status_code == 413
    assert _error_code(resp) == "payload_too_large"
    _assert_headers(resp)


def test_https_redirect_answers_before_the_rate_limit(admin, monkeypatch, rate_limit):
    monkeypatch.setattr(app_module, "APP_HTTPS_REDIRECT", True)
    rate_limit["max_read"] = 0
    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.get("/api/inventory?x=1", follow_redirects=False)
    assert resp.status_code == 301
    assert resp.headers["location"] == "https://testserver/api/inventory?x=1"
    _assert_headers(resp)
    # The health probe is exempt and reaches the app over plain HTTP.
    assert client.get("/api/health", follow_redirects=False).status_code != 301
    # Behind a TLS proxy the request goes on to the rate limit.
    resp = client.get("/api/inventory", headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
    assert resp.status_code == 429


def test_rate_limit_answers_before_the_csrf_check(admin, rate_limit):
    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.cookies.set("session", _revoked_cookie())
    rate_limit["max_write"] = 0
    resp = client.post("/api/mw-probe/auth", json={})
    assert resp.status_code == 429
    assert resp.json() == {
        "ok": False,
        "error": {"code": "rate_limit_exceeded", "message": resp.json()["error"]["message"]},
    }
    assert resp.json()["error"]["message"].startswith("Too many requests. Try again in ")
    _assert_headers(resp)
    rate_limit["enabled"] = False
    resp = client.post("/api/mw-probe/auth", json={})
    assert resp.status_code == 403
    assert resp.json() == {"ok": False, "error": {"code": "csrf_error", "message": "Missing or invalid CSRF token"}}
    _assert_headers(resp)


def test_csrf_check_then_the_route(admin, probes, rate_limit):
    resp = admin.raw.post("/api/mw-probe/auth", json={})
    assert resp.status_code == 403
    assert _error_code(resp) == "csrf_error"
    _assert_headers(resp)
    resp = admin.raw.post("/api/mw-probe/auth", json={}, headers={"X-CSRF-Token": "forged"})
    assert resp.status_code == 403
    resp = admin.post("/api/mw-probe/auth", json={})
    assert resp.status_code == 200
    _assert_headers(resp)


def test_api_token_and_exempt_paths_skip_the_csrf_check(admin, probes, monkeypatch):
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "probe-api-token")
    resp = admin.raw.post("/api/mw-probe/auth", json={}, headers={"X-API-Token": "probe-api-token"})
    assert resp.status_code == 200
    # A public path is not CSRF checked (the login answers for itself).
    resp = admin.raw.post("/api/auth/login", json={"username": "nobody", "password": "wrong-password"})
    assert "csrf_error" not in resp.text


# ── Headers on every kind of response ────────────────────────────────────────


def test_headers_on_normal_missing_streamed_static_and_failed_responses(admin, probes, monkeypatch):
    monkeypatch.setattr(app_module, "APP_HSTS_ENABLED", True)
    monkeypatch.setattr(app_module, "APP_HSTS_MAX_AGE", 3600)
    client = admin.raw
    normal = client.get("/api/health")
    missing = client.get("/api/mw-probe/no-such-route")
    static = client.get("/static/css/style.css")
    with client.stream("GET", "/api/mw-probe/stream") as stream:
        body = "".join(stream.iter_text())
        stream_headers = stream.headers
    for resp in (normal, missing, static):
        _assert_headers(resp)
        assert resp.headers["strict-transport-security"] == "max-age=3600; includeSubDomains"
    assert missing.status_code == 404
    assert static.headers["cache-control"] == "no-cache"
    assert body == "data: 1\n\ndata: 2\n\n"
    assert stream_headers["x-accel-buffering"] == "no"
    assert stream_headers["x-content-type-options"] == "nosniff"
    assert stream_headers["x-correlation-id"]
    assert "x-accel-buffering" not in normal.headers


def test_unhandled_error_reaches_the_handler_once_and_gets_the_headers(admin, probes, monkeypatch):
    logged = []
    monkeypatch.setattr(app_module.LOGGER, "error", lambda *args, **kw: logged.append(args[0]))
    resp = admin.raw.get("/api/mw-probe/boom", headers={"X-Correlation-ID": "probe-corr-500"})
    assert resp.status_code == 500
    assert resp.json() == {"ok": False, "error": {"code": "internal_error", "message": "Internal server error"}}
    _assert_headers(resp)
    assert resp.headers["x-correlation-id"] == "probe-corr-500"
    assert logged == ["Unhandled error on %s: %s"]
    # The exception still propagates to the server (and a raising TestClient).
    with pytest.raises(RuntimeError):
        TestClient(app_module.app).get("/api/mw-probe/boom")


def test_route_csp_is_kept_and_security_headers_are_enforced():
    from starlette.datastructures import MutableHeaders

    headers = MutableHeaders(
        raw=[(b"content-security-policy", b"default-src 'none'"), (b"x-frame-options", b"SAMEORIGIN")]
    )
    http_middleware.apply_security_headers(headers, hsts=None)
    assert headers["content-security-policy"] == "default-src 'none'"
    assert headers.getlist("x-frame-options") == ["DENY"]
    assert "strict-transport-security" not in headers


# ── Correlation id ───────────────────────────────────────────────────────────


def test_correlation_id_is_echoed_set_on_the_request_and_generated(admin, probes):
    resp = admin.raw.get("/api/mw-probe/auth", headers={"X-Correlation-ID": "  req-0042.a:b_c  "})
    assert resp.headers["x-correlation-id"] == "req-0042.a:b_c"
    assert resp.json()["correlation_id"] == "req-0042.a:b_c"
    assert resp.json()["context_correlation_id"] == "req-0042.a:b_c"

    generated = admin.raw.get("/api/mw-probe/auth")
    corr = generated.headers["x-correlation-id"]
    assert len(corr) == 16 and int(corr, 16) >= 0
    assert generated.json()["correlation_id"] == corr


@pytest.mark.parametrize("supplied", ["has spaces in it", "x" * 129, "semi;colon", "quote\"d"])
def test_unusable_correlation_id_is_replaced(supplied):
    scope = {"type": "http", "headers": [(b"x-correlation-id", supplied.encode())]}
    corr = http_middleware.correlation_id_for(scope)
    assert corr != supplied.strip()
    assert len(corr) == 16


def test_short_circuit_responses_carry_the_supplied_correlation_id(admin, rate_limit):
    client = TestClient(app_module.app, raise_server_exceptions=False)
    rate_limit["max_read"] = 0
    resp = client.get("/api/inventory", headers={"X-Correlation-ID": "probe-corr-429"})
    assert resp.status_code == 429
    assert resp.headers["x-correlation-id"] == "probe-corr-429"


# ── One session verification per request ─────────────────────────────────────


@pytest.mark.parametrize("limiting", [True, False])
def test_session_cookie_is_verified_once_per_request(admin, probes, rate_limit, monkeypatch, limiting):
    rate_limit["enabled"] = limiting
    calls = []
    real = app_module.verify_session_token

    def counting(token):
        calls.append(token)
        return real(token)

    monkeypatch.setattr(app_module, "verify_session_token", counting)
    resp = admin.raw.get("/api/mw-probe/auth")
    assert resp.status_code == 200
    assert resp.json()["precheck_user"] == ("admin" if limiting else None)
    assert len(calls) == 1
    calls.clear()
    resp = admin.post("/api/mw-probe/auth", json={})
    assert resp.status_code == 200
    assert resp.json()["precheck_user"] == "admin"
    assert len(calls) == 1


# ── GZip and CORS ────────────────────────────────────────────────────────────


def test_gzip_still_compresses(admin):
    resp = admin.raw.get("/static/css/style.css", headers={"Accept-Encoding": "gzip"})
    assert resp.status_code == 200
    assert resp.headers["content-encoding"] == "gzip"
    _assert_headers(resp)


def test_cors_allows_only_the_configured_origins(admin):
    cors = next(m for m in app_module.app.user_middleware if m.cls is CORSMiddleware)
    allowed = cors.kwargs["allow_origins"][0]
    ok = admin.raw.get("/api/health", headers={"Origin": allowed})
    assert ok.headers["access-control-allow-origin"] == allowed
    assert ok.headers["access-control-allow-credentials"] == "true"
    other = admin.raw.get("/api/health", headers={"Origin": "https://other.example.com"})
    assert "access-control-allow-origin" not in other.headers
    preflight = admin.raw.options(
        "/api/inventory",
        headers={"Origin": allowed, "Access-Control-Request-Method": "POST"},
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == allowed
    _assert_headers(preflight)


# ── The middleware on its own ────────────────────────────────────────────────


def _standalone(guards=()):
    async def plain(request):
        return JSONResponse({"corr": request.state.correlation_id, "ctx": current_correlation_id.get()})

    async def boom(request):
        raise ValueError("probe")

    async def echo(websocket):
        await websocket.accept()
        await websocket.send_text(await websocket.receive_text())
        await websocket.close()

    def internal_error(request):
        return PlainTextResponse("internal", status_code=500)

    return Starlette(
        routes=[Route("/plain", plain, methods=["GET", "POST"]), Route("/boom", boom), WebSocketRoute("/ws", echo)],
        middleware=[
            Middleware(
                PlexusHTTPMiddleware,
                guards=guards,
                hsts_header=lambda: "max-age=60; includeSubDomains",
                internal_error=internal_error,
            )
        ],
    )


def test_guards_run_in_order_and_stop_at_the_first_answer():
    seen = []

    async def first(request):
        seen.append("first")

    async def second(request):
        seen.append("second")
        return PlainTextResponse("refused", status_code=418)

    async def third(request):
        seen.append("third")

    client = TestClient(_standalone([first, second, third]))
    resp = client.get("/plain", headers={"X-Correlation-ID": "probe-guard"})
    assert resp.status_code == 418
    assert seen == ["first", "second"]
    assert resp.headers["x-correlation-id"] == "probe-guard"
    assert resp.headers["strict-transport-security"] == "max-age=60; includeSubDomains"
    _assert_headers(resp)


def test_body_limit_runs_before_the_guards(monkeypatch):
    monkeypatch.setenv("APP_MAX_REQUEST_BODY_MB", "1")
    seen = []

    async def guard(request):
        seen.append(request.url.path)

    client = TestClient(_standalone([guard]))
    resp = client.post("/plain", content=b"x" * (1024 * 1024 + 1))
    assert resp.status_code == 413
    assert seen == []
    _assert_headers(resp)


def test_standalone_context_and_error_path():
    client = TestClient(_standalone(), raise_server_exceptions=False)
    body = client.get("/plain", headers={"X-Correlation-ID": "probe-ctx"}).json()
    assert body == {"corr": "probe-ctx", "ctx": "probe-ctx"}
    failed = client.get("/boom")
    assert failed.status_code == 500
    assert failed.text == "internal"
    _assert_headers(failed)


def test_websocket_passes_through_untouched():
    seen = []

    async def guard(request):
        seen.append("guard")
        return PlainTextResponse("refused", status_code=403)

    client = TestClient(_standalone([guard]))
    with client.websocket_connect("/ws") as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "ping"
    assert seen == []


async def test_correlation_context_is_reset_after_the_request():
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/plain",
        "raw_path": b"/plain",
        "root_path": "",
        "query_string": b"",
        "scheme": "http",
        "http_version": "1.1",
        "server": ("testserver", 80),
        "client": ("192.0.2.10", 40000),
        "headers": [(b"x-correlation-id", b"probe-reset")],
    }
    await _standalone()(scope, receive, send)
    assert json.loads(sent[-1]["body"]) == {"corr": "probe-reset", "ctx": "probe-reset"}
    assert current_correlation_id.get() == ""
