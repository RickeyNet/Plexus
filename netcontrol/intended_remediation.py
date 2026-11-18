"""Remediation of intended configuration: the commands that close the gap
between a host's intended configuration and its running configuration
(newest backup), with no I/O.

The comparison is ``netcontrol.intended_config.compare_configs`` (indentation
trees), so the commands match the diff the Intended view shows:

- a *missing* intended line is added under its parent lines;
- an *extra* backup line (inside a block the intended text writes with
  children; top-level backup lines are never extra) is negated, which
  removes its whole block;
- removals in a block come before additions in it, and parents come before
  their children.

Only platforms with an indented, ``no``-negated CLI are supported (see
``PLATFORMS``); any other driver gets a ``supported=False`` result instead of
commands that could be wrong. Admin-defined ignore rules (``exact``,
``prefix`` or ``regex``, RE2 through ``routes.user_regex``) drop matching
lines, and their blocks, from both sides before comparing. Banner blocks are
never remediated: they are dropped and noted when they differ.

Storage of ignore rules lives in ``routes.db.intended_config``, the API in
``netcontrol.routes.intended_config`` (preview, ignore rules) and
``netcontrol.routes.deployments`` (deployment creation). See
``docs/intended-config.md``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from routes.user_regex import compile_user_regex

from netcontrol.custom_fields import CustomFieldError, clean_name, clean_text
from netcontrol.intended_config import compare_configs, config_lines

__all__ = [
    "IGNORE_DESCRIPTION_MAX",
    "IGNORE_KINDS",
    "IGNORE_PATTERN_MAX",
    "PLATFORMS",
    "Platform",
    "Remediation",
    "clean_ignore_description",
    "clean_ignore_kind",
    "clean_ignore_pattern",
    "compile_ignore_rules",
    "generate_remediation",
    "negate",
    "platform_for",
]

IGNORE_KINDS: tuple[str, ...] = ("exact", "prefix", "regex")
IGNORE_PATTERN_MAX = 500
IGNORE_DESCRIPTION_MAX = 500

# Lines a configuration dump prints that are not commands (checked at the top
# level only, on both sides, with their blocks).
_COMMON_SKIP = (
    r"^Building configuration",
    r"^Current configuration",
    r"^Last configuration change",
    r"^NVRAM config last updated",
    r"^end$",
)


@dataclass(frozen=True)
class Platform:
    """How one CLI family takes remediation commands.

    ``negation``: the prefix that removes a line (a line that already starts
    with it is removed by dropping it). ``skip``: patterns of top-level lines
    that are not configuration commands, in addition to the common ones."""

    name: str
    negation: str = "no "
    skip: tuple[str, ...] = ()
    _skip_re: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Fixed patterns from this module, never user input.
        object.__setattr__(self, "_skip_re", re.compile("|".join((*_COMMON_SKIP, *self.skip))))

    def skips(self, stripped: str) -> bool:
        return self._skip_re.search(stripped) is not None


_IOS = Platform("Cisco IOS", skip=(r"^version \d",))
# Driver key (``hosts.device_type``) -> rules. Every other driver is not supported.
PLATFORMS: dict[str, Platform] = {
    "cisco_ios": _IOS,
    "cisco_xe": Platform("Cisco IOS-XE", skip=(r"^version \d",)),
    "cisco_nxos": Platform("Cisco NX-OS", skip=(r"^version \d", r"^boot nxos ")),
    "cisco_nxos_ssh": Platform("Cisco NX-OS", skip=(r"^version \d", r"^boot nxos ")),
    "arista_eos": Platform("Arista EOS"),
    "aruba_aoscx": Platform("Aruba AOS-CX"),
    "cisco_asa": Platform("Cisco ASA", skip=(r"^:", r"^ASA Version ", r"^Cryptochecksum:")),
}


def platform_for(device_type: str | None) -> Platform | None:
    """The rules of a driver key, or ``None`` when remediation does not support it."""
    return PLATFORMS.get(str(device_type or ""))


def negate(stripped: str, platform: Platform = _IOS) -> str:
    """The command that removes a (stripped) line: ``no X`` for ``X``, ``X`` for ``no X``."""
    prefix = platform.negation
    if stripped.startswith(prefix) and len(stripped) > len(prefix):
        return stripped[len(prefix) :].lstrip()
    return prefix + stripped


# ── Ignore rules ─────────────────────────────────────────────────────────────


def clean_ignore_description(raw: object) -> str:
    return clean_text(raw, "Description", IGNORE_DESCRIPTION_MAX)


def clean_ignore_kind(raw: object) -> str:
    if raw not in IGNORE_KINDS:
        raise CustomFieldError(f"Kind must be one of: {', '.join(IGNORE_KINDS)}.")
    return str(raw)


def clean_ignore_pattern(raw: object, kind: str) -> str:
    """A pattern trimmed, 1 to ``IGNORE_PATTERN_MAX`` characters; a ``regex``
    must compile with RE2 (no lookarounds or backreferences)."""
    pattern = clean_name(raw, "Pattern", IGNORE_PATTERN_MAX)
    if kind == "regex":
        try:
            compile_user_regex(pattern, ignore_case=False)
        except ValueError as exc:
            raise CustomFieldError(
                f"Pattern is not a valid regular expression ({exc}). Lookarounds and backreferences are not supported."
            ) from exc
    return pattern


def compile_ignore_rules(rules: Iterable[dict], device_type: str | None) -> Callable[[str], bool]:
    """A test of a stripped line against the enabled rules that apply to the
    driver (``device_type`` ``''`` on a rule: every driver). A regex is
    searched, case sensitively, with RE2; one that no longer compiles is
    skipped."""
    exact: set[str] = set()
    prefixes: list[str] = []
    regexes = []
    driver = str(device_type or "")
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if rule.get("device_type") and rule["device_type"] != driver:
            continue
        pattern = str(rule.get("pattern") or "")
        if not pattern:
            continue
        kind = rule.get("kind")
        if kind == "exact":
            exact.add(pattern)
        elif kind == "prefix":
            prefixes.append(pattern)
        elif kind == "regex":
            try:
                regexes.append(compile_user_regex(pattern, ignore_case=False))
            except ValueError:
                continue
    prefix_tuple = tuple(prefixes)

    def matches(stripped: str) -> bool:
        if stripped in exact or (prefix_tuple and stripped.startswith(prefix_tuple)):
            return True
        return any(r.search(stripped) for r in regexes)

    return matches


# ── Generation ───────────────────────────────────────────────────────────────


@dataclass
class Remediation:
    """The commands for one host and what they do. ``supported`` is
    ``False`` (with ``reason``) for a driver ``PLATFORMS`` does not cover."""

    supported: bool
    platform: str = ""
    commands: list[str] = field(default_factory=list)
    added: int = 0
    removed: int = 0
    ignored: int = 0
    notes: list[str] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "supported": self.supported,
            "platform": self.platform,
            "commands": list(self.commands),
            "added": self.added,
            "removed": self.removed,
            "ignored": self.ignored,
            "notes": list(self.notes),
            "reason": self.reason,
        }


_BANNER = re.compile(r"^banner\s+\S+\s*(.*)$")


def _split_lines(text: str) -> list[str]:
    return str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _strip_banners(lines: list[str]) -> tuple[list[str], list[str]]:
    """The lines without banner blocks, and the banner blocks' text."""
    kept: list[str] = []
    banners: list[str] = []
    i = 0
    while i < len(lines):
        match = _BANNER.match(lines[i])
        if not match:
            kept.append(lines[i])
            i += 1
            continue
        rest = match.group(1)
        # The delimiter: ``^C`` (as printed) or the first character after the type.
        delim = "^C" if rest.startswith("^C") else rest[:1]
        block = [lines[i]]
        closed = not delim or rest[len(delim) :].find(delim) >= 0
        i += 1
        while not closed and i < len(lines):
            block.append(lines[i])
            closed = delim in lines[i]
            i += 1
        banners.append("\n".join(line.rstrip() for line in block))
    return kept, banners


def _filtered(text: str, platform: Platform, ignore: Callable[[str], bool]) -> tuple[str, int, list[str]]:
    """The text without banners, non-command top-level lines and ignored
    lines (each with its block); the number of ignored lines; the banners."""
    lines, banners = _strip_banners(_split_lines(text))
    kept: list[str] = []
    ignored = 0
    verdicts: dict[tuple[str, ...], tuple[bool, bool]] = {}
    for line, path in config_lines("\n".join(lines)):
        if path is None:
            kept.append(line)
            continue
        parent = verdicts.get(path[:-1], (False, False)) if len(path) > 1 else (False, False)
        own_ignored = parent[1] or ignore(path[-1])
        dropped = parent[0] or own_ignored or (len(path) == 1 and platform.skips(path[0]))
        verdicts[path] = (dropped, own_ignored)
        if own_ignored:
            ignored += 1
        if not dropped:
            kept.append(line)
    return "\n".join(kept), ignored, banners


class _Writer:
    """Emits commands under their parent lines, indented one space per
    level. Entering a context emits only the parent lines past the part it
    shares with the current context: these CLIs fall back to the parent
    mode for a parent-level command."""

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.current: tuple[str, ...] = ()

    def emit(self, context: tuple[str, ...], text: str, *, enters: bool) -> None:
        common = 0
        while common < min(len(context), len(self.current)) and context[common] == self.current[common]:
            common += 1
        for depth in range(common, len(context)):
            self.commands.append(" " * depth + context[depth])
        self.commands.append(" " * len(context) + text)
        # An added line may open a mode its children follow; a removal does not.
        self.current = (*context, text) if enters else context


def generate_remediation(
    intended: str,
    running: str,
    device_type: str | None,
    ignore_rules: Iterable[dict] = (),
) -> Remediation:
    """The commands that make ``running`` match ``intended`` for a host of
    driver ``device_type`` (see the module docstring)."""
    platform = platform_for(device_type)
    if platform is None:
        return Remediation(
            supported=False,
            reason=(
                f"Remediation is not supported for driver '{device_type or 'unknown'}'. "
                f"Supported drivers: {', '.join(sorted(PLATFORMS))}."
            ),
        )
    ignore = compile_ignore_rules(ignore_rules, device_type)
    intended_text, ignored_intended, intended_banners = _filtered(intended, platform, ignore)
    running_text, ignored_running, running_banners = _filtered(running, platform, ignore)
    result = Remediation(supported=True, platform=platform.name, ignored=ignored_intended + ignored_running)
    if intended_banners and sorted(intended_banners) != sorted(running_banners):
        result.notes.append("Banner lines differ; banners are not remediated, change them by hand.")

    comparison = compare_configs(intended_text, running_text)
    entries = [
        (path, line["missing"])
        for (_text, path), line in zip(config_lines(intended_text), comparison.lines, strict=True)
        if path is not None
    ]
    removals: dict[tuple[str, ...], list[str]] = {}
    for extra in comparison.extra:
        removals.setdefault(tuple(extra["path"]), []).append(extra["text"].strip())
    additions: dict[tuple[str, ...], set[str]] = {}
    for path, missing in entries:
        if missing:
            additions.setdefault(path[:-1], set()).add(path[-1])

    writer = _Writer()
    done: set[tuple[str, ...]] = set()

    def remove_under(parent: tuple[str, ...]) -> None:
        if parent in done:
            return
        done.add(parent)
        for text in removals.get(parent, []):
            command = negate(text, platform)
            # ``no shutdown`` on the device and ``shutdown`` intended: the addition does it.
            if command in additions.get(parent, set()):
                continue
            writer.emit(parent, command, enters=False)
            result.removed += 1

    for path, missing in entries:
        parent = path[:-1]
        remove_under(parent)
        if missing:
            writer.emit(parent, path[-1], enters=True)
            result.added += 1
        remove_under(path)
    result.commands = writer.commands
    return result
