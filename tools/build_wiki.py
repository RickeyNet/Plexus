#!/usr/bin/env python3
"""Build the GitHub wiki from the documentation in this repository.

The repository is the only place documentation is written. This tool turns
it into the flat set of pages a GitHub wiki wants:

- every document in ``PAGES`` becomes one wiki page, with its links
  rewritten (a link to another document becomes a link to that wiki page, a
  link to any other repository file becomes a link to the file on GitHub);
- the hand-written pages in ``wiki/`` (``Home.md``, ``_Footer.md``) are
  copied as they are;
- ``_Sidebar.md`` is generated from the sections in ``PAGES``.

Usage:
    python tools/build_wiki.py --out build/wiki   # write the pages
    python tools/build_wiki.py --check            # validate only (CI)

The tool fails when a document under ``docs/`` is neither a page nor listed
in ``NOT_PUBLISHED``, when a source file is missing, when a link points at
a file that does not exist, or when a document leaves a code fence open.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# The page list and link rewriting are shared with the in-app Help pages.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netcontrol.docs_catalog import (  # noqa: E402
    DEFAULT_BRANCH,
    EXTERNAL,
    FENCE,
    LINK,
    NOT_PUBLISHED,
    PAGES,
    REPO_ROOT,
    REPO_URL,
    WIKI_SOURCE_DIR,
    page_index,
    rewrite_links,
)

__all__ = [
    "DEFAULT_BRANCH",
    "NOT_PUBLISHED",
    "PAGES",
    "REPO_ROOT",
    "REPO_URL",
    "build",
    "build_sidebar",
    "check_wiki_links",
    "main",
    "page_index",
    "rewrite_links",
    "write",
]


def check_wiki_links(text: str, source: str, names: set[str], errors: list[str]) -> None:
    """Report links in a hand-written wiki page that name no wiki page."""
    in_fence = False
    for line in text.splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
        if in_fence:
            continue
        for match in LINK.finditer(line):
            target = match.group(1)
            if EXTERNAL.match(target) or target.startswith("#"):
                continue
            page = target.partition("#")[0]
            if page not in names:
                errors.append(f"{source}: link to unknown wiki page {target!r}")


def build_sidebar() -> str:
    """The wiki sidebar: Home, then every page under its section."""
    lines = ["**[Home](Home)**", ""]
    for section, pages in PAGES:
        lines.append(f"**{section}**")
        lines.append("")
        lines.extend(f"- [{name.replace('-', ' ')}]({name})" for name, _ in pages)
        lines.append("")
    return "\n".join(lines)


def build(root: Path = REPO_ROOT) -> tuple[dict[str, str], list[str]]:
    """Return the wiki files (file name -> content) and the problems found."""
    files: dict[str, str] = {}
    errors: list[str] = []
    pages = page_index()

    names = [name for _, section in PAGES for name, _ in section]
    for name in sorted({n for n in names if names.count(n) > 1}):
        errors.append(f"wiki page name used twice: {name}")

    docs_dir = root / "docs"
    if docs_dir.is_dir():
        for doc in sorted(docs_dir.glob("*.md")):
            rel = f"docs/{doc.name}"
            if rel not in pages and rel not in NOT_PUBLISHED:
                errors.append(f"{rel}: add it to PAGES or NOT_PUBLISHED in netcontrol/docs_catalog.py")

    for source, name in pages.items():
        path = root / source
        if not path.is_file():
            errors.append(f"{source}: source of wiki page {name} is missing")
            continue
        body = rewrite_links(path.read_text(encoding="utf-8"), source, pages, root, errors)
        note = f"<!-- Generated from {source} by tools/build_wiki.py. Edit that file, not this page. -->\n\n"
        files[f"{name}.md"] = note + body

    known = set(pages.values()) | {"Home"}
    wiki_dir = root / WIKI_SOURCE_DIR
    for page in sorted(wiki_dir.glob("*.md")) if wiki_dir.is_dir() else []:
        if page.name in files or page.name == "_Sidebar.md":
            errors.append(f"{WIKI_SOURCE_DIR}/{page.name}: name is taken by a generated page")
            continue
        text = page.read_text(encoding="utf-8")
        check_wiki_links(text, f"{WIKI_SOURCE_DIR}/{page.name}", known | {page.stem}, errors)
        files[page.name] = text
    if "Home.md" not in files:
        errors.append(f"{WIKI_SOURCE_DIR}/Home.md is missing")

    files["_Sidebar.md"] = build_sidebar()
    return files, errors


def write(files: dict[str, str], out_dir: Path) -> None:
    """Replace the markdown files in ``out_dir`` with ``files``.

    Only ``*.md`` files are removed, so the ``.git`` directory of a wiki
    clone, and any images uploaded through the wiki, are kept.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*.md"):
        old.unlink()
    for name, content in files.items():
        (out_dir / name).write_text(content, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the GitHub wiki from the repository docs.")
    parser.add_argument("--out", type=Path, help="Directory to write the wiki pages into.")
    parser.add_argument("--check", action="store_true", help="Validate only; write nothing.")
    args = parser.parse_args(argv)
    if not args.check and args.out is None:
        parser.error("give --out DIR or --check")

    files, errors = build()
    if errors:
        print("WIKI BUILD FAILED")
        for line in errors:
            print(f" - {line}")
        return 1
    if args.check:
        print(f"WIKI CHECK PASSED ({len(files)} pages)")
        return 0
    write(files, args.out)
    print(f"Wrote {len(files)} wiki pages to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
