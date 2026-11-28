"""How the app serves: compression level, cache headers of static files,
unbuffered event streams behind nginx, and a startup that does not wait for
a discovery scan."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.inventory as inventory_module
from fastapi.middleware.gzip import GZipMiddleware
from netcontrol import http_middleware
from starlette.applications import Starlette
from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Mount
from starlette.testclient import TestClient


def test_gzip_runs_at_level_five():
    gzip = [m for m in app_module.app.user_middleware if m.cls is GZipMiddleware]
    assert len(gzip) == 1
    assert gzip[0].kwargs.get("compresslevel") == 5


def test_static_files_revalidate():
    client = TestClient(app_module.app)
    resp = client.get("/static/css/style.css")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-cache"
    etag = resp.headers["etag"]
    again = client.get("/static/css/style.css", headers={"if-none-match": etag})
    assert again.status_code == 304
    assert again.headers["cache-control"] == "no-cache"


def test_cached_static_files_send_their_policy(tmp_path):
    (tmp_path / "index-abc123.js").write_text("console.log(1)\n", encoding="utf-8")
    site = Starlette(
        routes=[
            Mount(
                "/assets",
                app_module._CachedStaticFiles(directory=tmp_path, cache_control=app_module._IMMUTABLE_CACHE_CONTROL),
            )
        ]
    )
    resp = TestClient(site).get("/assets/index-abc123.js")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "public, max-age=31536000, immutable"


async def _headers_for(response) -> dict:
    headers = MutableHeaders(raw=list(response.raw_headers))
    http_middleware.apply_security_headers(headers, hsts=None)
    return dict(headers)


async def test_event_streams_are_marked_unbuffered_for_nginx():
    async def events():
        yield "data: 1\n\n"

    sse = await _headers_for(StreamingResponse(events(), media_type="text/event-stream"))
    assert sse["x-accel-buffering"] == "no"
    ndjson = await _headers_for(StreamingResponse(events(), media_type="application/x-ndjson"))
    assert ndjson["x-accel-buffering"] == "no"
    plain = await _headers_for(JSONResponse({"ok": True}))
    assert "x-accel-buffering" not in plain
    # The security headers are still set on a stream.
    assert sse["x-content-type-options"] == "nosniff"


async def test_startup_does_not_wait_for_the_discovery_scan(monkeypatch):
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    scanning = asyncio.Event()
    release = asyncio.Event()

    async def slow_scan() -> dict:
        scanning.set()
        await release.wait()
        return {"enabled": False}

    monkeypatch.setattr(inventory_module, "_run_discovery_sync_once", slow_scan)
    monkeypatch.setattr(app_module, "_run_discovery_sync_once", slow_scan)
    lifespan = app_module.lifespan(app_module.app)
    # A scan that never ends must not hold startup.
    await asyncio.wait_for(lifespan.__aenter__(), timeout=120)
    try:
        # The background loop runs the first scan itself.
        await asyncio.wait_for(scanning.wait(), timeout=30)
    finally:
        release.set()
        await lifespan.__aexit__(None, None, None)
