"""Help: the user guides, read inside Plexus.

The guides are the repository documents listed in
``netcontrol.docs_catalog.PAGES`` (the same pages the GitHub wiki
publishes) plus ``wiki/Home.md`` as the front page. Each is rendered from
markdown to HTML on first read and kept until its file changes.

Rendering escapes any HTML in a document (``html`` off) and drops links
whose scheme is not safe, so the page can insert the result as is. Links
between guides become ``/help/<page>`` addresses, links to other
repository files go to the file on GitHub, and outside links open in a new
tab.

Endpoints (any signed-in user):

- ``GET /api/help``: the sections and their pages.
- ``GET /api/help/search?q=``: pages whose text holds every word of ``q``,
  with a line of context.
- ``GET /api/help/pages/{name}``: one page as HTML, with its headings.

The handlers are plain functions so FastAPI runs their file reads in its
thread pool, off the event loop.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from markdown_it import MarkdownIt
from markdown_it.renderer import RendererHTML
from markdown_it.token import Token
from markdown_it.utils import OptionsDict

from netcontrol.docs_catalog import (
    DEFAULT_BRANCH,
    LINK,
    PAGES,
    REPO_ROOT,
    REPO_URL,
    WIKI_SOURCE_DIR,
    map_links,
    page_index,
    page_title,
    rewrite_links,
)

router = APIRouter(prefix="/api/help")

HOME = "Home"
HOME_SOURCE = f"{WIKI_SOURCE_DIR}/Home.md"
SEARCH_LIMIT = 25
_SNIPPET = 160


def help_link(name: str) -> str:
    """The in-app address of a page."""
    return f"/help/{name}"


def _sources() -> dict[str, tuple[str, str]]:
    """Page name -> (source document, section), Home first."""
    found = {HOME: (HOME_SOURCE, "")}
    for section, pages in PAGES:
        for name, source in pages:
            found[name] = (source, section)
    return found


# ── Rendering ───────────────────────────────────────────────────────────────


def _markdown() -> MarkdownIt:
    md = MarkdownIt("commonmark", {"html": False}).enable("table").enable("strikethrough")

    # Bound to the renderer, so the first argument is the renderer itself.
    def link_open(renderer: RendererHTML, tokens: list[Token], idx: int, options: OptionsDict, env: dict) -> str:
        href = str(tokens[idx].attrGet("href") or "")
        if href.startswith(("http://", "https://")):
            tokens[idx].attrSet("target", "_blank")
            tokens[idx].attrSet("rel", "noopener noreferrer")
        return renderer.renderToken(tokens, idx, options, env)

    # Each table sits in a scroll box, so a wide table scrolls on its own on a
    # narrow window while the table itself can still stretch to full width.
    def table_open(renderer: RendererHTML, tokens: list[Token], idx: int, options: OptionsDict, env: dict) -> str:
        return '<div class="help-table">' + renderer.renderToken(tokens, idx, options, env)

    def table_close(renderer: RendererHTML, tokens: list[Token], idx: int, options: OptionsDict, env: dict) -> str:
        return renderer.renderToken(tokens, idx, options, env) + "</div>\n"

    md.add_render_rule("link_open", link_open)
    md.add_render_rule("table_open", table_open)
    md.add_render_rule("table_close", table_close)
    return md


_MD = _markdown()
_NOT_SLUG = re.compile(r"[^\w\- ]", re.UNICODE)


def slugify(text: str) -> str:
    """A heading's anchor, the way GitHub makes it, so ``#anchor`` links
    written for GitHub land on the same heading."""
    return _NOT_SLUG.sub("", text.strip().lower()).replace(" ", "-")


def _inline_text(token: Token) -> str:
    return "".join(child.content for child in token.children or [] if child.type in ("text", "code_inline"))


@dataclass(frozen=True)
class Rendered:
    title: str
    html: str
    headings: list[dict]
    text: str


def render(markdown: str, fallback_title: str) -> Rendered:
    """Markdown to HTML, with an id on every heading and the title (the
    first level-one heading, else ``fallback_title``)."""
    tokens = _MD.parse(markdown)
    seen: dict[str, int] = {}
    headings: list[dict] = []
    title = ""
    for i, token in enumerate(tokens):
        if token.type != "heading_open":
            continue
        text = _inline_text(tokens[i + 1])
        base = slugify(text) or "section"
        count = seen.get(base, 0)
        seen[base] = count + 1
        anchor = base if count == 0 else f"{base}-{count}"
        token.attrSet("id", anchor)
        level = int(token.tag[1])
        if level == 1 and not title:
            title = text
        elif level in (2, 3):
            headings.append({"id": anchor, "text": text, "level": level})
    html = _MD.renderer.render(tokens, _MD.options, {})
    return Rendered(title=title or fallback_title, html=html, headings=headings, text=markdown)


def _link_home(text: str, names: set[str]) -> str:
    """Point the front page's wiki-style links (``Page-Name``) at Help."""

    def swap(match: re.Match[str]) -> str:
        target, title = match.group(1), match.group(2) or ""
        page, _, anchor = target.partition("#")
        if page not in names:
            return match.group(0)
        return f"]({help_link(page)}{'#' + anchor if anchor else ''}{title})"

    return map_links(text, swap)[0]


# Rendered pages by name, with the file's modification time they were read at.
_CACHE: dict[str, tuple[int, Rendered]] = {}
_CACHE_LOCK = threading.Lock()


def load(name: str, root: Path = REPO_ROOT) -> Rendered | None:
    """One page, rendered; None when the name is unknown or its file is not
    in this install."""
    sources = _sources()
    if name not in sources:
        return None
    source, _ = sources[name]
    path = root / source
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        return None
    key = f"{root}::{name}"
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
    if cached and cached[0] == stamp:
        return cached[1]
    raw = path.read_text(encoding="utf-8")
    if name == HOME:
        body = _link_home(raw, set(sources))
    else:
        body = rewrite_links(raw, source, page_index(), root, [], page_link=help_link, strict=False)
    rendered = render(body, page_title(name))
    with _CACHE_LOCK:
        _CACHE[key] = (stamp, rendered)
    return rendered


# ── Search ──────────────────────────────────────────────────────────────────

_MARKUP = re.compile(r"[`*_>#|]+")


def _plain(line: str) -> str:
    """A markdown line as plain words: link targets and markup dropped."""
    line = LINK.sub("]", line).replace("[", "").replace("]", "")
    return " ".join(_MARKUP.sub(" ", line).split())


def search(query: str, root: Path = REPO_ROOT, limit: int = SEARCH_LIMIT) -> list[dict]:
    """Pages holding every word of ``query`` (case-insensitive), title hits
    first, then by how often the words occur."""
    words = [w for w in query.lower().split() if w]
    if not words:
        return []
    hits: list[tuple[int, int, str, dict]] = []
    for name, (_, section) in _sources().items():
        page = load(name, root)
        if page is None:
            continue
        lower = page.text.lower()
        if not all(w in lower for w in words):
            continue
        title_hit = all(w in page.title.lower() for w in words)
        count = sum(lower.count(w) for w in words)
        snippet = ""
        for line in page.text.splitlines():
            plain = _plain(line)
            low = plain.lower()
            at = low.find(words[0])
            if at < 0:
                continue
            start = max(0, at - _SNIPPET // 3)
            snippet = ("…" if start else "") + plain[start : start + _SNIPPET]
            if start + _SNIPPET < len(plain):
                snippet += "…"
            break
        hits.append(
            (
                0 if title_hit else 1,
                -count,
                name,
                {"name": name, "title": page.title, "section": section, "snippet": snippet},
            )
        )
    hits.sort(key=lambda h: (h[0], h[1], h[2]))
    return [h[3] for h in hits[:limit]]


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.get("")
def help_index() -> dict:
    """The sections and their pages, leaving out any whose file this install
    does not ship."""
    sections = []
    for section, pages in PAGES:
        listed = [{"name": name, "title": page_title(name)} for name, source in pages if (REPO_ROOT / source).is_file()]
        if listed:
            sections.append({"title": section, "pages": listed})
    return {"home": HOME, "sections": sections}


@router.get("/search")
def help_search(q: str = Query("", max_length=200)) -> dict:
    return {"query": q, "results": search(q)}


@router.get("/pages/{name}")
def help_page(name: str) -> dict:
    page = load(name)
    if page is None:
        raise HTTPException(status_code=404, detail=f"No help page named {name!r}")
    source, section = _sources()[name]
    return {
        "name": name,
        "title": page.title,
        "section": section,
        "source": source,
        "source_url": f"{REPO_URL}/blob/{DEFAULT_BRANCH}/{source}",
        "headings": page.headings,
        "html": page.html,
    }
