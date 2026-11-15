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
import posixpath
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WIKI_SOURCE_DIR = "wiki"
REPO_URL = "https://github.com/RickeyNet/Plexus"
DEFAULT_BRANCH = "main"

# (sidebar section, [(wiki page name, source document), ...]) in sidebar
# order. A page name is the wiki file name without ".md"; GitHub shows the
# hyphens as spaces.
PAGES: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Install and operate",
        [
            ("Deployment-Guide", "deploy/DEPLOYMENT.md"),
            ("Firewall-Rules", "deploy/FIREWALL.md"),
            ("Air-Gapped-Deployment", "deploy/airgap/README.md"),
            ("Air-Gapped-VM-Setup", "deploy/airgap/VM_SETUP.md"),
            ("Database-Backends", "docs/database-backends.md"),
            ("Data-Retention", "DATA_RETENTION.md"),
            ("Administration", "docs/administration.md"),
            ("Federation", "docs/federation.md"),
        ],
    ),
    (
        "Sign-in and access",
        [
            ("Single-Sign-On-OIDC", "docs/sso-oidc.md"),
            ("RADIUS-Login", "RADIUS_CONFIGURATION_GUIDE.md"),
            ("TACACS-Login", "TACACS_CONFIGURATION_GUIDE.md"),
            ("Object-Permissions", "docs/object-permissions.md"),
            ("Authorization-Matrix", "AUTHORIZATION_MATRIX.md"),
            ("Audit-Log", "docs/audit-log.md"),
        ],
    ),
    (
        "Inventory and addressing",
        [
            ("Core-Concepts", "docs/core-concepts.md"),
            ("Discovery", "docs/discovery.md"),
            ("Device-Model", "docs/device-model.md"),
            ("Custom-Fields-and-Tags", "docs/custom-fields-and-tags.md"),
            ("VRFs-and-VLANs", "docs/vrfs-and-vlans.md"),
            ("IPAM", "docs/ipam.md"),
            ("Floor-Plan", "docs/floor-plan.md"),
            ("Network-Tools", "docs/network-tools.md"),
        ],
    ),
    (
        "Configuration and change",
        [
            ("Running-Jobs", "docs/jobs.md"),
            ("Writing-Playbooks", "docs/writing-playbooks.md"),
            ("Config-Backups-and-Drift", "docs/config-backups-and-drift.md"),
            ("Intended-Configuration", "docs/intended-config.md"),
            ("Compliance", "docs/compliance.md"),
            ("Change-Management", "docs/change-management.md"),
            ("Risk-Analysis", "docs/risk-analysis.md"),
            ("Deployments", "docs/deployments.md"),
            ("Maintenance-Windows", "docs/maintenance-windows.md"),
            ("Lab-Mode", "docs/lab-mode.md"),
            ("IOS-XE-Upgrade-Tool", "docs/upgrade-tool-guide.md"),
        ],
    ),
    (
        "Topology",
        [
            ("Path-Trace", "docs/path-trace.md"),
            ("AWS-Topology", "docs/aws-topology.md"),
            ("Azure-Topology", "docs/azure-topology.md"),
            ("GCP-Topology", "docs/gcp-topology.md"),
            ("Meraki-Topology", "docs/meraki-topology.md"),
            ("Cato-Topology", "docs/cato-topology.md"),
            ("Cisco-FMC-Topology", "docs/fmc-topology.md"),
            ("Panorama-Topology", "docs/panorama-topology.md"),
            ("Appgate-SDP-Topology", "docs/appgate-topology.md"),
            ("Cloud-Visibility", "docs/cloud-visibility.md"),
        ],
    ),
    (
        "Monitoring and reports",
        [
            ("Dashboard", "docs/dashboard.md"),
            ("Monitoring", "docs/monitoring.md"),
            ("Graph-Templates", "docs/graph-templates.md"),
            ("SLA-Monitoring", "docs/sla-monitoring.md"),
            ("Software-Versions-and-Vulnerabilities", "docs/software-versions.md"),
            ("Alert-Notification-Channels", "docs/alert-notification-channels.md"),
            ("Meraki-Alerts", "docs/meraki-alerts.md"),
            ("Meraki-Compliance", "docs/meraki-compliance.md"),
            ("Flow-Collector", "docs/flow-collector.md"),
            ("Vendor-Monitoring-Coverage", "docs/vendor-monitoring-coverage.md"),
            ("Reports", "docs/reports.md"),
            ("Network-Documentation-Reports", "docs/network-documentation-usage.md"),
        ],
    ),
    (
        "API and AI access",
        [
            ("API-Reference", "docs/api-reference.md"),
            ("WebSocket-Usage", "docs/websocket-usage.md"),
            ("AI-Access-MCP", "docs/ai-access.md"),
        ],
    ),
    (
        "Developers",
        [
            ("Developer-Setup", "DEVSETUP.md"),
            ("Architecture-and-Conventions", "AGENTS.md"),
            ("Frontend-Style-Guide", "FRONTEND_STYLE.md"),
            ("Versioning-and-Release", "docs/versioning-and-release.md"),
            ("Changelog", "CHANGELOG.md"),
        ],
    ),
]

# Documents under docs/ that are deliberately not wiki pages. Every other
# file in docs/ must be in PAGES, so a new document cannot be forgotten.
NOT_PUBLISHED = {
    "docs/FRONTEND_MIGRATION.md",  # archived migration plan
}

# Inline markdown link or image: "](target)" or "](target "title")".
_LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(\s+\"[^\"]*\")?\s*\)")
_FENCE = re.compile(r"^\s*(```|~~~)")
_EXTERNAL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)")


def page_index() -> dict[str, str]:
    """Map each source document to its wiki page name."""
    return {source: name for _, pages in PAGES for name, source in pages}


def _resolve(target: str, source: str) -> str:
    """Repo-relative path a link in ``source`` points at ("" if outside)."""
    if target.startswith("/"):
        path = posixpath.normpath(target.lstrip("/"))
    else:
        path = posixpath.normpath(posixpath.join(posixpath.dirname(source), target))
    return "" if path.startswith("..") else path


def rewrite_links(text: str, source: str, pages: dict[str, str], root: Path, errors: list[str]) -> str:
    """Rewrite the relative links of one repository document for the wiki.

    Links to another published document become wiki page links, links to any
    other repository file become GitHub links, and links that were already
    absolute or in-page are kept. Code fences are left alone.
    """

    def swap(match: re.Match[str]) -> str:
        target, title = match.group(1), match.group(2) or ""
        if _EXTERNAL.match(target) or target.startswith("#"):
            return match.group(0)
        path_part, _, anchor = target.partition("#")
        path = _resolve(path_part, source)
        suffix = f"#{anchor}" if anchor else ""
        if path in pages:
            return f"]({pages[path]}{suffix}{title})"
        on_disk = root / path if path else None
        if on_disk is None or not on_disk.exists():
            errors.append(f"{source}: link to missing file {target!r}")
            return match.group(0)
        kind = "tree" if on_disk.is_dir() else "blob"
        return f"]({REPO_URL}/{kind}/{DEFAULT_BRANCH}/{path}{suffix}{title})"

    out: list[str] = []
    in_fence = False
    for line in text.splitlines(keepends=True):
        if _FENCE.match(line):
            in_fence = not in_fence
        out.append(line if in_fence else _LINK.sub(swap, line))
    if in_fence:
        errors.append(f"{source}: a code fence is opened and never closed")
    return "".join(out)


def check_wiki_links(text: str, source: str, names: set[str], errors: list[str]) -> None:
    """Report links in a hand-written wiki page that name no wiki page."""
    in_fence = False
    for line in text.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
        if in_fence:
            continue
        for match in _LINK.finditer(line):
            target = match.group(1)
            if _EXTERNAL.match(target) or target.startswith("#"):
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
                errors.append(f"{rel}: add it to PAGES or NOT_PUBLISHED in tools/build_wiki.py")

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
