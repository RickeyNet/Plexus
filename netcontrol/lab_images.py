"""The container images lab users may deploy through containerlab.

containerlab starts several node kinds (``ceos``, the vrnetlab ``vr-*``
kinds) as privileged containers, so the image a lab user picks runs as root
on the lab host. Admins keep an allowlist (the ``lab_image_allowlist`` auth
setting, edited at ``/api/admin/lab-image-allowlist``); a caller who is not
an admin may deploy only an image it allows. Admins may deploy any image
that passes the character check (``lab_runtime._IMAGE_RE``). The lab module
has no built-in image per node kind, so the default (empty) allowlist lets
non-admins deploy nothing until an admin adds entries.

An entry is an image reference, matched after Docker's normalisation (no
registry is ``docker.io``, a one-part name is ``library/<name>``, no tag is
``latest``):

* with a tag (``ghcr.io/nokia/srlinux:23.10.1``): that image only;
* without one (``ghcr.io/nokia/srlinux``, ``registry.example.com/team/``):
  that repository with any tag, and every repository below it by whole
  path segments (``registry.example.com/team`` allows
  ``registry.example.com/team/frr:1`` but not
  ``registry.example.com/team-evil/x``);
* a registry host alone with a trailing slash (``registry.example.com/``):
  every image of that registry.

The registry host is compared exactly (ignoring case), so
``registry.example.com.attacker.example/team/x`` matches no entry for
``registry.example.com``.
"""

from __future__ import annotations

import re
from typing import NamedTuple

import routes.database as db

SETTING_KEY = "lab_image_allowlist"
MAX_ENTRIES = 200

# The same character set lab_runtime._IMAGE_RE accepts for an image, with an
# optional trailing "/" (a registry or namespace prefix).
_ENTRY_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,255}(:[a-zA-Z0-9._-]+)?/?$")
_DEFAULT_REGISTRY = "docker.io"
_REGISTRY_ALIASES = {"index.docker.io": _DEFAULT_REGISTRY, "registry-1.docker.io": _DEFAULT_REGISTRY}


class ImageRef(NamedTuple):
    registry: str
    path: tuple[str, ...]  # repository path segments (may be empty for a registry entry)
    tag: str | None


def parse_reference(ref: str, *, entry: bool = False) -> ImageRef:
    """``ref`` split into registry, repository path and tag, normalised as
    Docker does. ``entry``: an allowlist entry, where a trailing ``/`` marks
    the first part as a registry even without a path after it."""
    text = ref.strip()
    prefix = entry and text.endswith("/")
    text = text.rstrip("/")
    tag: str | None = None
    last_slash = text.rfind("/")
    colon = text.rfind(":")
    if colon > last_slash:
        text, tag = text[:colon], text[colon + 1 :]
    parts = [p for p in text.split("/") if p]
    registry = _DEFAULT_REGISTRY
    first = parts[0] if parts else ""
    if (len(parts) > 1 or prefix) and ("." in first or ":" in first or first == "localhost"):
        registry = first.lower()
        parts = parts[1:]
    registry = _REGISTRY_ALIASES.get(registry, registry)
    if registry == _DEFAULT_REGISTRY and len(parts) == 1 and not prefix:
        parts = ["library", parts[0]]
    return ImageRef(registry, tuple(parts), tag)


def image_allowed(image: str, entries: list[str]) -> bool:
    """Whether ``image`` matches an allowlist entry (see the module doc)."""
    if ".." in image or "//" in image or image.strip().endswith("/"):
        return False  # not a valid reference; never let it match a prefix
    ref = parse_reference(image)
    tag = ref.tag or "latest"
    for raw in entries:
        allowed = parse_reference(raw, entry=True)
        if allowed.registry != ref.registry:
            continue
        if allowed.tag is not None:
            if allowed.path == ref.path and allowed.tag == tag:
                return True
            continue
        if ref.path[: len(allowed.path)] == allowed.path and (allowed.path or raw.strip().endswith("/")):
            return True
    return False


def validate_entries(entries: object) -> list[str]:
    """The cleaned entry list (trimmed, duplicates dropped, order kept).
    Raises ``ValueError`` naming the first invalid entry."""
    if not isinstance(entries, list):
        raise ValueError("entries must be a list of image references")
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"At most {MAX_ENTRIES} entries")
    out: list[str] = []
    for value in entries:
        if not isinstance(value, str):
            raise ValueError("Each entry must be a string")
        text = value.strip()
        if not _ENTRY_RE.match(text) or ".." in text or "//" in text:
            raise ValueError(f"Invalid image reference or prefix: {value!r}")
        if text not in out:
            out.append(text)
    return out


async def load_allowlist() -> list[str]:
    """The stored allowlist; entries that no longer validate are ignored."""
    stored = await db.get_auth_setting(SETTING_KEY)
    raw = stored.get("entries") if isinstance(stored, dict) else None
    out: list[str] = []
    for value in raw if isinstance(raw, list) else []:
        try:
            out.extend(e for e in validate_entries([value]) if e not in out)
        except ValueError:
            continue
    return out


async def save_allowlist(entries: object) -> list[str]:
    """Validate and store ``entries``; returns the stored list."""
    clean = validate_entries(entries)
    await db.set_auth_setting(SETTING_KEY, {"entries": clean})
    return clean


async def check_image_allowed(image: str, *, is_admin: bool, what: str = "Image") -> str | None:
    """None when the caller may deploy ``image``, else the refusal message."""
    if is_admin:
        return None
    if image_allowed(image, await load_allowlist()):
        return None
    return (
        f"{what} '{image}' is not in the lab image allowlist. Ask an admin to add it "
        "(Admin API: /api/admin/lab-image-allowlist)."
    )
