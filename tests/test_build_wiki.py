"""Tests for tools/build_wiki.py, the GitHub wiki generator."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("build_wiki", REPO_ROOT / "tools" / "build_wiki.py")
assert _spec is not None and _spec.loader is not None
build_wiki = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_wiki)

PAGES = {"docs/a.md": "Page-A", "docs/b.md": "Page-B", "GUIDE.md": "Guide"}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "docs").mkdir()
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "setup.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    return tmp_path


def _rewrite(text: str, repo: Path, source: str = "docs/a.md") -> tuple[str, list[str]]:
    errors: list[str] = []
    return build_wiki.rewrite_links(text, source, PAGES, repo, errors), errors


def test_link_to_sibling_document_becomes_wiki_link(repo: Path) -> None:
    out, errors = _rewrite("See [B](b.md) and [the guide](../GUIDE.md).", repo)
    assert out == "See [B](Page-B) and [the guide](Guide)."
    assert errors == []


def test_link_from_repo_root_resolves_into_docs(repo: Path) -> None:
    out, _ = _rewrite("[A](docs/a.md)", repo, source="GUIDE.md")
    assert out == "[A](Page-A)"


def test_anchor_and_title_are_kept(repo: Path) -> None:
    out, _ = _rewrite('[B](b.md#api-reference "API")', repo)
    assert out == '[B](Page-B#api-reference "API")'


def test_other_repository_file_becomes_github_link(repo: Path) -> None:
    out, errors = _rewrite("[setup](../deploy/setup.sh) [dir](../deploy)", repo)
    base = f"{build_wiki.REPO_URL}/"
    assert out == f"[setup]({base}blob/main/deploy/setup.sh) [dir]({base}tree/main/deploy)"
    assert errors == []


def test_external_and_in_page_links_are_kept(repo: Path) -> None:
    text = "[x](https://example.com/a.md) [y](#section) [z](mailto:ops@example.com)"
    out, errors = _rewrite(text, repo)
    assert out == text
    assert errors == []


def test_missing_target_is_reported_and_left_alone(repo: Path) -> None:
    out, errors = _rewrite("[gone](missing.md) [out](../../etc/passwd)", repo)
    assert out == "[gone](missing.md) [out](../../etc/passwd)"
    assert len(errors) == 2
    assert "missing.md" in errors[0]


def test_code_fences_are_not_rewritten(repo: Path) -> None:
    text = "```\n[B](b.md)\n```\n[B](b.md)\n"
    out, _ = _rewrite(text, repo)
    assert out == "```\n[B](b.md)\n```\n[B](Page-B)\n"


def test_unclosed_code_fence_is_reported(repo: Path) -> None:
    _, errors = _rewrite("text\n```bash\necho hi\n", repo)
    assert errors == ["docs/a.md: a code fence is opened and never closed"]


def test_hand_written_page_links_must_name_wiki_pages() -> None:
    errors: list[str] = []
    text = "[ok](Page-A#top) [web](https://example.com) [bad](Nope)\n```\n[skip](Nope)\n```\n"
    build_wiki.check_wiki_links(text, "wiki/Home.md", {"Page-A"}, errors)
    assert errors == ["wiki/Home.md: link to unknown wiki page 'Nope'"]


def test_sidebar_lists_every_page_once() -> None:
    sidebar = build_wiki.build_sidebar()
    for name in build_wiki.page_index().values():
        assert sidebar.count(f"]({name})") == 1


def test_build_reports_unlisted_doc_and_missing_home(repo: Path) -> None:
    (repo / "docs" / "new-feature.md").write_text("# New\n", encoding="utf-8")
    _, errors = build_wiki.build(repo)
    assert "docs/new-feature.md: add it to PAGES or NOT_PUBLISHED in netcontrol/docs_catalog.py" in errors
    assert "wiki/Home.md is missing" in errors


def test_write_replaces_markdown_and_keeps_other_files(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "Old-Page.md").write_text("old", encoding="utf-8")
    (tmp_path / "diagram.png").write_bytes(b"png")
    build_wiki.write({"Home.md": "home\n"}, tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == [".git", "Home.md", "diagram.png"]


def test_repository_wiki_builds_clean() -> None:
    files, errors = build_wiki.build()
    assert errors == []
    assert {"Home.md", "_Sidebar.md", "_Footer.md", "Device-Model.md"} <= set(files)
    assert "](Deployment-Guide)" in files["Home.md"]
    assert build_wiki.main(["--check"]) == 0
