#!/usr/bin/env python3
"""Validate release consistency between version constant, changelog, and tag.

Checks:
- netcontrol/version.py APP_VERSION matches latest CHANGELOG entry version.
- Optional tag (for example v0.2.0) matches APP_VERSION.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

VERSION_FILE = Path("netcontrol/version.py")
CHANGELOG_FILE = Path("CHANGELOG.md")

VERSION_RE = re.compile(r'APP_VERSION\s*=\s*"(?P<version>\d+\.\d+\.\d+)"')
CHANGELOG_RE = re.compile(r"^##\s+(?P<version>\d+\.\d+\.\d+)\b", re.MULTILINE)


def _read_app_version() -> str:
    text = VERSION_FILE.read_text(encoding="utf-8")
    match = VERSION_RE.search(text)
    if not match:
        raise ValueError("Could not find APP_VERSION in netcontrol/version.py")
    return match.group("version")


def _read_latest_changelog_version() -> str:
    text = CHANGELOG_FILE.read_text(encoding="utf-8")
    match = CHANGELOG_RE.search(text)
    if not match:
        raise ValueError("Could not find a changelog version header in CHANGELOG.md")
    return match.group("version")


def _normalize_tag(tag: str) -> str:
    raw = tag.strip()
    if raw.startswith("refs/tags/"):
        raw = raw.split("/", 2)[-1]
    if raw.lower().startswith("v"):
        raw = raw[1:]
    return raw


def main() -> int:
    tag = sys.argv[1] if len(sys.argv) > 1 else ""

    app_version = _read_app_version()
    changelog_version = _read_latest_changelog_version()

    if app_version != changelog_version:
        print(
            "Release consistency check failed: "
            f"APP_VERSION={app_version} but latest CHANGELOG version={changelog_version}"
        )
        return 1

    if tag:
        normalized_tag = _normalize_tag(tag)
        if normalized_tag != app_version:
            print(
                "Release consistency check failed: "
                f"tag={normalized_tag} but APP_VERSION={app_version}"
            )
            return 1

    print(
        "Release consistency check passed: "
        f"version={app_version}, changelog={changelog_version}, tag={_normalize_tag(tag) if tag else 'n/a'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
