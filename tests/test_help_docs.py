"""Help: the user guides inside Plexus (``netcontrol.routes.help_docs``)
and the page list it shares with the wiki (``netcontrol.docs_catalog``)."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

import netcontrol.app as app_module
import pytest
from netcontrol import docs_catalog
from netcontrol.routes import help_docs
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


# ── Rendering ───────────────────────────────────────────────────────────────


def test_html_in_a_guide_is_escaped_and_unsafe_links_dropped() -> None:
    page = help_docs.render("# T\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1))\n", "T")
    assert "<script>" not in page.html
    assert "&lt;script&gt;" in page.html
    assert 'href="javascript' not in page.html


def test_outside_links_open_in_a_new_tab_and_help_links_do_not() -> None:
    page = help_docs.render("[out](https://example.com/a) [in](/help/IPAM) [here](#top)\n", "T")
    assert '<a href="https://example.com/a" target="_blank" rel="noopener noreferrer">' in page.html
    assert '<a href="/help/IPAM">' in page.html
    assert '<a href="#top">' in page.html


def test_headings_get_github_anchors_and_the_first_h1_is_the_title() -> None:
    page = help_docs.render("# Guide `one`\n\n## Set up: step 1\n\n## Set up: step 1\n\n### A/B\n", "Fallback")
    assert page.title == "Guide one"
    assert [h["id"] for h in page.headings] == ["set-up-step-1", "set-up-step-1-1", "ab"]
    assert '<h2 id="set-up-step-1">' in page.html
    assert help_docs.render("no heading\n", "Fallback").title == "Fallback"


def test_links_between_guides_point_at_help_and_other_files_at_github(tmp_path: Path) -> None:
    pages = {"docs/a.md": "Page-A"}
    errors: list[str] = []
    out = docs_catalog.rewrite_links(
        "[A](a.md#x) [script](../deploy/setup.sh)",
        "docs/a.md",
        pages,
        tmp_path,
        errors,
        page_link=help_docs.help_link,
        strict=False,
    )
    assert out == f"[A](/help/Page-A#x) [script]({docs_catalog.REPO_URL}/blob/main/deploy/setup.sh)"
    assert errors == []


def test_every_link_and_anchor_between_the_shipped_guides_resolves() -> None:
    ids: dict[str, set[str]] = {}
    html: dict[str, str] = {}
    for name in help_docs._sources():
        page = help_docs.load(name)
        assert page is not None, name
        html[name] = page.html
        ids[name] = set(re.findall(r' id="([^"]+)"', page.html))
    broken = []
    for name, body in html.items():
        for href in re.findall(r'href="([^"]+)"', body):
            if href.startswith("#"):
                target, anchor = name, href[1:]
            elif href.startswith("/help/"):
                target, _, anchor = href[len("/help/") :].partition("#")
            else:
                continue
            if target not in ids or (anchor and anchor not in ids[target]):
                broken.append(f"{name}: {href}")
    assert broken == []


def test_search_needs_every_word_and_ranks_title_hits_first() -> None:
    results = help_docs.search("path trace")
    assert results[0]["name"] == "Path-Trace"
    assert all("snippet" in r for r in results)
    assert help_docs.search("") == []
    assert help_docs.search("zzqx-no-guide-says-this") == []


def test_the_docker_image_ships_every_guide() -> None:
    """Each page source survives .dockerignore (last matching pattern wins;
    a pattern that matches a parent directory excludes what is under it)."""
    patterns = []
    for line in (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append((line.startswith("!"), line.lstrip("!").rstrip("/")))

    def excluded(path: str) -> bool:
        target = PurePosixPath(path)
        candidates = [target, *target.parents[:-1]]
        state = False
        for negated, pattern in patterns:
            if any(c.full_match(pattern) for c in candidates):
                state = not negated
        return state

    sources = [*docs_catalog.page_index(), help_docs.HOME_SOURCE]
    assert [s for s in sources if excluded(s)] == []
    assert excluded("deploy/setup.sh")


def test_every_page_help_banner_names_a_guide_that_exists() -> None:
    """``<PageHelp guide="Page#heading">`` links resolve to a page and heading."""
    src = REPO_ROOT / "netcontrol" / "static" / "frontend" / "src"
    named = [
        (path.relative_to(src).as_posix(), guide)
        for path in src.rglob("*.tsx")
        for guide in re.findall(r'\sguide="([^"]+)"', path.read_text(encoding="utf-8"))
    ]
    assert named
    broken = []
    for where, guide in named:
        name, _, anchor = guide.partition("#")
        page = help_docs.load(name)
        if page is None or (anchor and f' id="{anchor}"' not in page.html):
            broken.append(f"{where}: {guide}")
    assert broken == []


# ── API ─────────────────────────────────────────────────────────────────────


def test_anonymous_is_rejected(admin) -> None:
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    assert anon.get("/api/help").status_code == 401
    assert anon.get("/api/help/pages/Home").status_code == 401


def test_any_user_reads_the_guides(admin) -> None:
    user = user_client(admin, features=[])
    index = user.get("/api/help")
    assert index.status_code == 200, index.text
    body = index.json()
    assert body["home"] == "Home"
    assert [s["title"] for s in body["sections"]] == [title for title, _ in docs_catalog.PAGES]
    assert {"name": "Path-Trace", "title": "Path Trace"} in body["sections"][4]["pages"]

    home = user.get("/api/help/pages/Home").json()
    assert 'href="/help/Deployment-Guide"' in home["html"]

    page = user.get("/api/help/pages/Path-Trace").json()
    assert page["section"] == "Topology"
    assert page["source"] == "docs/path-trace.md"
    assert page["source_url"].endswith("/blob/main/docs/path-trace.md")
    assert page["headings"] and page["html"].startswith("<h1")

    found = user.get("/api/help/search", params={"q": "path trace"}).json()
    assert found["results"][0]["name"] == "Path-Trace"


def test_unknown_page_is_404(admin) -> None:
    assert admin.get("/api/help/pages/No-Such-Page").status_code == 404
    assert admin.get("/api/help/pages/..%2F..%2Fetc%2Fpasswd").status_code == 404
