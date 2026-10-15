"""Fetch the Pyodide runtime the Topology HTML export embeds.

The export can carry the path tracer itself: Pyodide (CPython compiled to
WebAssembly) runs the engine in the browser, offline. This script downloads
the pinned Pyodide core release over HTTPS, checks its SHA-256, and extracts
only the files the export needs into ``netcontrol/static/vendor/pyodide``
(or the directory given with ``--dest`` / ``PLEXUS_PYODIDE_DIR``), with the
Pyodide license (MPL-2.0) next to them. The directory is not committed.

Idempotent: when the directory already holds every file of the pinned
version (its ``VERSION`` marker), nothing is downloaded. Standard library
only, so it runs before any dependency is installed. On an air-gapped host,
run it on a connected machine and copy the directory over.

    python scripts/fetch_pyodide.py [--dest DIR] [--force]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

PYODIDE_VERSION = "314.0.7"
ARCHIVE_URL = (
    f"https://github.com/pyodide/pyodide/releases/download/{PYODIDE_VERSION}/pyodide-core-{PYODIDE_VERSION}.tar.bz2"
)
ARCHIVE_SHA256 = "2abdcc2e35208af406e07724cffa85bc582ced97e9028383ecf5462541393f95"
# The core archive carries no license file; this is the one of the release tag.
LICENSE_URL = f"https://raw.githubusercontent.com/pyodide/pyodide/{PYODIDE_VERSION}/LICENSE"
LICENSE_SHA256 = "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5"
# Archive members the export embeds (see netcontrol/integrations/meraki/html_export.py).
FILES = (
    "pyodide.mjs",
    "pyodide.asm.mjs",
    "pyodide.asm.wasm",
    "python_stdlib.zip",
    "pyodide-lock.json",
    "package.json",
)
_MEMBER_PREFIX = "pyodide/"
_DEFAULT_DEST = Path(__file__).resolve().parents[1] / "netcontrol" / "static" / "vendor" / "pyodide"
_TIMEOUT = 120


class FetchError(Exception):
    pass


def _download(url: str, target: Path, sha256: str) -> None:
    if not url.startswith("https://"):
        raise FetchError(f"refusing a non-HTTPS URL: {url}")
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as response, target.open("wb") as out:  # noqa: S310
            while chunk := response.read(1 << 20):
                digest.update(chunk)
                out.write(chunk)
    except OSError as exc:
        raise FetchError(f"download of {url} failed: {exc}") from exc
    if digest.hexdigest() != sha256:
        raise FetchError(f"{url}: SHA-256 {digest.hexdigest()} does not match the pinned {sha256}")


def is_current(dest: Path) -> bool:
    """Whether ``dest`` already holds every file of the pinned version."""
    try:
        version = (dest / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return False
    return version == PYODIDE_VERSION and all((dest / name).is_file() for name in (*FILES, "LICENSE"))


def fetch(dest: Path) -> None:
    """Download, verify and extract the pinned runtime into ``dest``."""
    with tempfile.TemporaryDirectory(prefix="pyodide-") as scratch:
        work = Path(scratch)
        archive = work / "pyodide-core.tar.bz2"
        _download(ARCHIVE_URL, archive, ARCHIVE_SHA256)
        staged = work / "staged"
        staged.mkdir()
        _download(LICENSE_URL, staged / "LICENSE", LICENSE_SHA256)
        wanted = {_MEMBER_PREFIX + name: name for name in FILES}
        with tarfile.open(archive, "r:bz2") as tar:
            for member in tar.getmembers():
                name = wanted.pop(member.name, None)
                if name is None:
                    continue
                if not member.isfile():
                    raise FetchError(f"{member.name} in the archive is not a regular file")
                member.name = name
                tar.extract(member, staged, filter="data")
        if wanted:
            raise FetchError(f"the archive lacks {', '.join(sorted(wanted))}")
        dest.mkdir(parents=True, exist_ok=True)
        # The marker goes last: an interrupted copy leaves no current-looking directory.
        (dest / "VERSION").unlink(missing_ok=True)
        for item in staged.iterdir():
            shutil.copyfile(item, dest / item.name)
        (dest / "VERSION").write_text(PYODIDE_VERSION + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, help="target directory (default: PLEXUS_PYODIDE_DIR or the vendor dir)")
    parser.add_argument("--force", action="store_true", help="download even when the files are present")
    args = parser.parse_args(argv)
    configured = os.environ.get("PLEXUS_PYODIDE_DIR", "").strip()
    dest = args.dest or (Path(configured) if configured else _DEFAULT_DEST)
    if not args.force and is_current(dest):
        print(f"Pyodide {PYODIDE_VERSION} already in {dest}")
        return 0
    try:
        fetch(dest)
    except (FetchError, OSError, tarfile.TarError) as exc:
        print(f"fetch_pyodide: {exc}", file=sys.stderr)
        return 1
    print(f"Pyodide {PYODIDE_VERSION} extracted to {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
