"""Project version metadata.

The version is sourced in priority order:
  1. PLEXUS_VERSION environment variable — set by Docker builds via
     ARG/ENV so release images self-identify without source edits.
  2. A VERSION file at the repo root — written by the release pipeline.
  3. The hardcoded fallback below — used in development checkouts.

The git SHA (when available) is captured separately so the upgrade UI
can distinguish "v1.2.3 release build" from "v1.2.3 + 4 local commits".
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_FALLBACK_VERSION = "1.0.0"


def _read_version() -> str:
    env_version = os.environ.get("PLEXUS_VERSION", "").strip()
    if env_version:
        return env_version
    version_file = Path(__file__).resolve().parent.parent / "VERSION"
    if version_file.is_file():
        text = version_file.read_text(encoding="utf-8").strip()
        if text:
            return text
    return _FALLBACK_VERSION


def _read_git_sha() -> str:
    # Image builds bake the SHA in via PLEXUS_GIT_SHA so the running
    # container can report it without needing git on PATH.
    env_sha = os.environ.get("PLEXUS_GIT_SHA", "").strip()
    if env_sha:
        return env_sha[:12]
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=Path(__file__).resolve().parent.parent,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return out.decode().strip()
    except Exception:
        return ""


APP_VERSION = _read_version()
APP_GIT_SHA = _read_git_sha()
