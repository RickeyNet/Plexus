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

The image built with the cloud SDKs (INSTALL_CLOUD_SDKS=true) installs
requirements-cloud-lock.txt instead: one hashed lock of requirements.txt plus
requirements-cloud.txt. With no arguments this script checks both locks, and
that every package the two locks share is pinned to the same version (except
CLOUD_LOCK_DIVERGENT, where a cloud SDK cannot use the base pin), so the two
image variants differ only by the SDKs.

Usage:
  python tools/check_requirements_lock.py                 # both locks
  python tools/check_requirements_lock.py REQS LOCK       # one pair
  python tools/check_requirements_lock.py --constraints LOCK [--exclude NAME]...
      print LOCK's pins without hashes (the constraints the cloud lock is
      compiled with; see DEVSETUP.md)

Regenerate a lock with the command in its header, e.g.
``uv pip compile requirements.txt --universal --generate-hashes --python-version 3.14 -o requirements-lock.txt``.
"""

from __future__ import annotations

import sys
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

REPO_ROOT = Path(__file__).resolve().parent.parent

# Packages requirements-cloud-lock.txt may pin differently from
# requirements-lock.txt: botocore requires python-dateutil<3, while the base
# lock (strawberry-graphql) pins 4.x.
CLOUD_LOCK_DIVERGENT = frozenset({"python-dateutil"})


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


def _lock_specs(path: Path) -> list[str]:
    """``name==version[ ; marker]`` of every pin in a lock, hashes dropped."""
    specs: list[str] = []
    for line in _logical_lines(path):
        if line.startswith("-"):
            continue
        spec = line.split(" --hash", 1)[0].strip()
        if "==" in spec.split(";", 1)[0]:
            specs.append(spec)
    return specs


def read_lock(path: Path) -> dict[str, list[Version]]:
    """Package name -> pinned versions (a universal lock may pin a package
    more than once under different markers)."""
    pins: dict[str, list[Version]] = {}
    for line in _lock_specs(path):
        spec = line.split(";", 1)[0].strip()
        name, _, version = spec.partition("==")
        name = name.split("[", 1)[0].strip()
        try:
            pins.setdefault(canonicalize_name(name), []).append(Version(version.strip()))
        except InvalidVersion as exc:
            raise SystemExit(f"{path.name}: bad pinned version in {line!r}: {exc}") from exc
    return pins


def check(requirements: Path | list[Path], lock: Path) -> list[str]:
    """Problems found; empty when the lock covers every requirement of the
    requirements file(s)."""
    files = requirements if isinstance(requirements, list) else [requirements]
    pins = read_lock(lock)
    problems: list[str] = []
    for req in [r for path in files for r in read_requirements(path)]:
        name = canonicalize_name(req.name)
        versions = pins.get(name)
        if not versions:
            problems.append(f"{req.name}: required but not pinned in {lock.name}")
            continue
        if req.specifier and not any(req.specifier.contains(v, prereleases=True) for v in versions):
            pinned = ", ".join(str(v) for v in versions)
            problems.append(f"{req.name}: {lock.name} pins {pinned}, which does not satisfy '{req.specifier}'")
    return problems


def check_consistent(base_lock: Path, other_lock: Path, allowed: frozenset[str] | set[str] = frozenset()) -> list[str]:
    """Packages both locks pin, but to different versions (``allowed`` names
    excepted)."""
    base, other = read_lock(base_lock), read_lock(other_lock)
    skip = {canonicalize_name(name) for name in allowed}
    problems: list[str] = []
    for name in sorted(set(base) & set(other) - skip):
        if sorted(base[name]) != sorted(other[name]):
            problems.append(
                f"{name}: {other_lock.name} pins {', '.join(map(str, other[name]))}, "
                f"{base_lock.name} pins {', '.join(map(str, base[name]))}"
            )
    return problems


def constraints(lock: Path, exclude: set[str] | frozenset[str] = frozenset()) -> list[str]:
    """The pins of ``lock`` without hashes, minus the ``exclude`` packages."""
    skip = {canonicalize_name(name) for name in exclude}
    out: list[str] = []
    for spec in _lock_specs(lock):
        name = spec.split("==", 1)[0].split("[", 1)[0].strip()
        if canonicalize_name(name) not in skip:
            out.append(spec)
    return out


def _report(label: str, lock: Path, problems: list[str]) -> int:
    if problems:
        print(f"{lock.name} is out of date with {label}:")
        for problem in problems:
            print(f"  - {problem}")
        print("Regenerate it with the command in its header (uv pip compile ... --generate-hashes).")
        return 1
    print(f"{lock.name} covers every requirement in {label}.")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--constraints":
        lock = Path(argv[1])
        exclude = {argv[i + 1] for i, arg in enumerate(argv[2:-1], start=2) if arg == "--exclude"}
        for spec in constraints(lock, exclude):
            print(spec)
        return 0
    if argv:
        requirements = Path(argv[0])
        lock = Path(argv[1]) if len(argv) > 1 else REPO_ROOT / "requirements-lock.txt"
        return _report(requirements.name, lock, check(requirements, lock))

    base_reqs, cloud_reqs = REPO_ROOT / "requirements.txt", REPO_ROOT / "requirements-cloud.txt"
    base_lock, cloud_lock = REPO_ROOT / "requirements-lock.txt", REPO_ROOT / "requirements-cloud-lock.txt"
    rc = _report(base_reqs.name, base_lock, check(base_reqs, base_lock))
    rc |= _report(f"{base_reqs.name} + {cloud_reqs.name}", cloud_lock, check([base_reqs, cloud_reqs], cloud_lock))
    drift = check_consistent(base_lock, cloud_lock, CLOUD_LOCK_DIVERGENT)
    if drift:
        print(f"{cloud_lock.name} pins shared packages differently from {base_lock.name}:")
        for problem in drift:
            print(f"  - {problem}")
        print("Recompile it with the command in its header (constraints from the base lock).")
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
