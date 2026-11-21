"""Regression tests for the Content-Security-Policy tightening.

The global security-headers middleware now sets ``script-src 'self'`` (no
``'unsafe-inline'`` and no CDN) for the whole app: the React bundle ships as
external hashed modules, so nothing in the SPA needs an inline script. The
graph-export embed page has an inline bootstrap <script> and sets its own CSP
(script-src 'self' plus that script's hash, ECharts served by the app), and the
middleware must not clobber it (it uses setdefault).
"""

from __future__ import annotations

import asyncio
from html.parser import HTMLParser

import pytest

import pg_raw


class _Scripts(HTMLParser):
    """The scripts of a page as a browser reads them: ``srcs`` of the
    external ones, ``inline`` the text of each executable one without a
    ``src``. A data block (``type="application/json"``) is not executed and
    is left out."""

    def __init__(self) -> None:
        super().__init__()
        self.srcs: list[str] = []
        self.inline: list[str] = []
        self._open = False

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        found = dict(attrs)
        if found.get("src") is not None:
            self.srcs.append(found["src"])
        elif (found.get("type") or "text/javascript") in ("text/javascript", "module"):
            self._open = True
            self.inline.append("")

    def handle_data(self, data):
        if self._open:
            self.inline[-1] += data

    def handle_endtag(self, tag):
        if tag == "script":
            self._open = False


@pytest.fixture
def client(monkeypatch, request):
    import netcontrol.app as app_module

    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-csp")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient

    c = TestClient(app_module.app, raise_server_exceptions=False)
    c.__enter__()
    request.addfinalizer(lambda: c.__exit__(None, None, None))
    return c


def test_global_csp_has_no_inline_script(client):
    resp = client.get("/api/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert csp, "expected a CSP header on every response"

    # Isolate the script-src directive.
    directives = {d.strip().split(" ", 1)[0]: d.strip() for d in csp.split(";") if d.strip()}
    script_src = directives.get("script-src", "")
    assert script_src == "script-src 'self'", script_src
    assert "'unsafe-inline'" not in script_src
    assert "cdn.jsdelivr.net" not in script_src

    # style-src intentionally keeps 'unsafe-inline' for dynamic style= attrs.
    assert "'unsafe-inline'" in directives.get("style-src", "")


def test_middleware_does_not_clobber_endpoint_csp(monkeypatch, client):
    """A route that sets its own CSP (the graph-export embed page) keeps it;
    the middleware only fills in a default when none is present."""
    import netcontrol.app as app_module
    from starlette.responses import HTMLResponse

    scoped = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' "
        "https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'"
    )

    @app_module.app.get("/api/_csp_probe")
    async def _probe():  # pragma: no cover - registered for the test only
        return HTMLResponse("<b>ok</b>", headers={"Content-Security-Policy": scoped})

    resp = client.get("/api/_csp_probe")
    assert resp.headers.get("Content-Security-Policy") == scoped


# ── Graph embed page (internal security review CFG-8) ───────────────────────────────


def test_embed_csp_allows_only_self_and_the_bootstrap_hash():
    from netcontrol.csp import script_hash_source
    from netcontrol.routes import graph_export

    directives = {d.strip().split(" ", 1)[0]: d.strip() for d in graph_export.EMBED_CSP.split(";") if d.strip()}
    expected = f"script-src 'self' {script_hash_source(graph_export.EMBED_BOOTSTRAP_SCRIPT)}"
    assert directives["script-src"] == expected
    assert "'unsafe-inline'" not in directives["script-src"]
    assert "http" not in graph_export.EMBED_CSP
    assert directives["frame-ancestors"] == "frame-ancestors 'none'"


def test_script_hash_source_matches_the_csp_spec_example():
    from netcontrol.csp import script_hash_source

    # CSP Level 3: sha256 of "alert('Hello, world.');".
    assert script_hash_source("alert('Hello, world.');") == "'sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng='"


def _seed_host_graph() -> int:
    async def _seed() -> int:
        conn = await pg_raw.connect()
        try:
            gid = await conn.fetchval("INSERT INTO inventory_groups (name) VALUES ('csp-g') RETURNING id")
            hid = await conn.fetchval(
                "INSERT INTO hosts (group_id, hostname, ip_address) VALUES ($1, 'csp-h', '192.0.2.10') RETURNING id",
                gid,
            )
            tid = await conn.fetchval("INSERT INTO graph_templates (name) VALUES ('CPU') RETURNING id")
            return await conn.fetchval(
                "INSERT INTO host_graphs (host_id, graph_template_id) VALUES ($1, $2) RETURNING id", hid, tid
            )
        finally:
            await conn.close()

    return asyncio.run(_seed())


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_embed_page_loads_echarts_from_the_app_under_its_csp(client, theme):
    from netcontrol.csp import script_hash_source
    from netcontrol.routes import graph_export

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert resp.status_code == 200
    hgid = _seed_host_graph()

    resp = client.get(f"/api/graphs/{hgid}/embed", params={"theme": theme})
    assert resp.status_code == 200
    assert resp.headers["Content-Security-Policy"] == graph_export.EMBED_CSP
    html = resp.text
    scripts = _Scripts()
    scripts.feed(html)
    assert scripts.srcs == [graph_export.ECHARTS_SCRIPT_SRC] == ["/vendor/echarts.min.js"]
    assert "cdn.jsdelivr.net" not in html
    # Every inline executable script is the one the CSP hash allows, whatever the theme.
    inline = scripts.inline
    assert inline == [graph_export.EMBED_BOOTSTRAP_SCRIPT]
    assert script_hash_source(inline[0]) in resp.headers["Content-Security-Policy"]
    assert f'data-theme="{"dark" if theme == "dark" else ""}"' in html
