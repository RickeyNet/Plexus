"""Check that requirements-lock.txt covers every entry of requirements.txt.

The Docker image installs Python packages from requirements-lock.txt only
(``pip install --require-hashes -r requirements-lock.txt``), while CI's test
job installs requirements.txt through requirements-dev.txt. A package added to
requirements.txt without regenerating the lock therefore passes CI and is then
missing from the image, so the in-app updater's new container fails to import
and never turns healthy. This check fails the build instead.

For every requirement in requirements.txt (and any ``-r`` file it includes)
the lock must pin the same package, and at least one pinned version must
satisfy the requirement's version specifier. Packages the lock pins only
under environment markers count as pinned.

Usage: python tools/check_requirements_lock.py [requirements.txt] [requirements-lock.txt]
Regenerate the lock with the command in its header, e.g.
``uv pip compile requirements.txt --universal --generate-hashes --python-version 3.14 -o requirements-lock.txt``.
"""

from __future__ import annotations

import sys
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

REPO_ROOT = Path(__file__).resolve().parent.parent


def _logical_lines(path: Path) -> list[str]:
    """Lines of a requirements file with comments stripped and ``\\``
    continuations joined."""
    out: list[str] = []
    pending = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line = (pending + line).strip()
        pending = ""
        if line:
            out.append(line)
    if pending.strip():
        out.append(pending.strip())
    return out


def read_requirements(path: Path, _seen: set[Path] | None = None) -> list[Requirement]:
    """The requirements of ``path``, following ``-r``/``--requirement``
    includes and skipping other pip options."""
    seen = _seen if _seen is not None else set()
    path = path.resolve()
    if path in seen:
        return []
    seen.add(path)
    reqs: list[Requirement] = []
    for line in _logical_lines(path):
        if line.startswith(("-r ", "--requirement ")):
            include = line.split(None, 1)[1].strip()
            reqs.extend(read_requirements(path.parent / include, seen))
            continue
        if line.startswith("-"):
            continue
        try:
            reqs.append(Requirement(line))
        except InvalidRequirement as exc:
            raise SystemExit(f"{path.name}: cannot parse requirement {line!r}: {exc}") from exc
    return reqs


def read_lock(path: Path) -> dict[str, list[Version]]:
    """Package name -> pinned versions (a universal lock may pin a package
    more than once under different markers)."""
    pins: dict[str, list[Version]] = {}
    for line in _logical_lines(path):
        if line.startswith("-"):
            continue
        spec = line.split(";", 1)[0].split(" --hash", 1)[0].strip()
        if "==" not in spec:
            continue
        name, _, version = spec.partition("==")
        name = name.split("[", 1)[0].strip()
        try:
            pins.setdefault(canonicalize_name(name), []).append(Version(version.strip()))
        except InvalidVersion as exc:
            raise SystemExit(f"{path.name}: bad pinned version in {line!r}: {exc}") from exc
    return pins


def check(requirements: Path, lock: Path) -> list[str]:
    """Problems found; empty when the lock covers every requirement."""
    pins = read_lock(lock)
    problems: list[str] = []
    for req in read_requirements(requirements):
        name = canonicalize_name(req.name)
        versions = pins.get(name)
        if not versions:
            problems.append(f"{req.name}: in {requirements.name} but not pinned in {lock.name}")
            continue
        if req.specifier and not any(req.specifier.contains(v, prereleases=True) for v in versions):
            pinned = ", ".join(str(v) for v in versions)
            problems.append(f"{req.name}: {lock.name} pins {pinned}, which does not satisfy '{req.specifier}'")
    return problems


def main(argv: list[str]) -> int:
    requirements = Path(argv[0]) if argv else REPO_ROOT / "requirements.txt"
    lock = Path(argv[1]) if len(argv) > 1 else REPO_ROOT / "requirements-lock.txt"
    problems = check(requirements, lock)
    if problems:
        print(f"{lock.name} is out of date with {requirements.name}:")
        for problem in problems:
            print(f"  - {problem}")
        print("Regenerate it with the command in its header (uv pip compile ... --generate-hashes).")
        return 1
    print(f"{lock.name} covers every requirement in {requirements.name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
