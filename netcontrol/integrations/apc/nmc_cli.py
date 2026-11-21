"""APC Network Management Card command line: commands and output parsing.

The NMC CLI (``apc>`` prompt, NMC2 and NMC3) prints ``Key: value`` lines
and ends a command with a status line such as ``E000: Success``. The exact
layout of ``upsabout``, ``about``, ``alarmcount`` and ``upsfwupdate`` output
has not been checked against every card firmware, so the parsers here are
tolerant: keys are matched case-insensitively, unknown lines are ignored,
and the status line is used when present but never required. When a field
cannot be read the caller blocks the device with a reason instead of
guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from netcontrol.integrations.apc.firmware import (
    NMC2_APP,
    NMC3_APP,
    normalize_ups_id,
    parse_firmware_filename,
    ups_version,
)

# ── Commands ─────────────────────────────────────────────────────────────────

UPSABOUT = "upsabout"
ABOUT = "about"
ALARMCOUNT = "alarmcount"
UPDATE_STATUS = "upsfwupdate -status"
# Where the vendor procedure puts the firmware file: a directory on the
# NMC, never opened on this server (hence the B108 exemption).
REMOTE_DIR = "/tmp"  # nosec B108
CD_REMOTE_DIR = f"cd {REMOTE_DIR}"
DIR = "dir"

# Netmiko session type for the NMC CLI (``apc>`` prompt, no enable mode).
NETMIKO_DEVICE_TYPE = "apc_aos"


def remote_path(filename: str) -> str:
    """Where a firmware file goes on the card. Only a well-formed UPS
    firmware file name is accepted, so the path is safe to put in a CLI
    command."""
    parsed = parse_firmware_filename(filename)
    if parsed is None:
        raise ValueError(f"Not a UPS firmware file name: {filename!r}")
    return f"{REMOTE_DIR}/{parsed.filename}"


def install_command(filename: str) -> str:
    return f'upsfwupdate -install -file "{remote_path(filename)}"'


# ── Generic output parsing ───────────────────────────────────────────────────

_STATUS_LINE_RE = re.compile(r"^\s*(E\d{3})\s*:\s*(.*?)\s*$", re.MULTILINE)
SUCCESS_CODES = frozenset({"E000", "E001"})
_DASHES_RE = re.compile(r"^\s*[-=_]{3,}\s*$")


def status_line(output: str | None) -> tuple[str, str] | None:
    """The first ``Exxx: message`` status line, as ``(code, message)``."""
    match = _STATUS_LINE_RE.search(output or "")
    return (match.group(1).upper(), match.group(2)) if match else None


def command_error(output: str | None) -> str | None:
    """``"E102: Parameter Error"`` when the command reported a failure code;
    None for E000/E001 or when there is no status line."""
    status = status_line(output)
    if status and status[0] not in SUCCESS_CODES:
        return f"{status[0]}: {status[1]}".rstrip(": ")
    return None


def _split_key_value(line: str) -> tuple[str, str] | None:
    if ":" not in line or _STATUS_LINE_RE.match(line):
        return None
    key, _, value = line.partition(":")
    key = " ".join(key.split()).lower()
    if not key or ">" in key:
        return None
    return key, value.strip()


def parse_key_values(output: str | None) -> dict[str, str]:
    """``Key: value`` lines as a dict with lower-case keys (first one wins)."""
    values: dict[str, str] = {}
    for line in (output or "").splitlines():
        pair = _split_key_value(line)
        if pair and pair[0] not in values:
            values[pair[0]] = pair[1]
    return values


def parse_sections(output: str | None) -> list[tuple[str, dict[str, str]]]:
    """``about``-style output: a title line (no colon), an optional rule of
    dashes, then ``Key: value`` lines. Lines before the first title land in
    a section titled ``""``."""
    sections: list[tuple[str, dict[str, str]]] = [("", {})]
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or _DASHES_RE.match(line) or _STATUS_LINE_RE.match(line):
            continue
        pair = _split_key_value(line)
        if pair is None:
            if ">" in line:  # the echoed prompt and command
                continue
            sections.append((line, {}))
            continue
        current = sections[-1][1]
        current.setdefault(pair[0], pair[1])
    return [s for s in sections if s[1]]


def _first(values: dict[str, str], *keys: str) -> str:
    for key in keys:
        if values.get(key):
            return values[key]
    return ""


# ── upsabout ─────────────────────────────────────────────────────────────────

_REVISION_ID_RE = re.compile(r"\bID\s*[:#]?\s*(\d{2,5})\b", re.IGNORECASE)


@dataclass(frozen=True)
class UpsAbout:
    model: str
    sku: str
    serial: str
    firmware_revision: str
    ups_id: str
    version: str


def parse_upsabout(output: str | None) -> UpsAbout:
    values = parse_key_values(output)
    revision = _first(
        values,
        "firmware revision",
        "firmware version",
        "ups firmware revision",
        "main firmware revision",
        "firmware",
    )
    raw_id = _first(values, "id", "ups id", "firmware id", "ups firmware id")
    if not raw_id:
        match = _REVISION_ID_RE.search(revision)
        raw_id = match.group(1) if match else ""
    revision_for_version = _REVISION_ID_RE.sub("", revision)
    return UpsAbout(
        model=_first(values, "model", "model name", "ups model"),
        sku=_first(values, "sku", "model number"),
        serial=_first(values, "serial number", "serial", "ups serial number"),
        firmware_revision=revision,
        ups_id=normalize_ups_id(raw_id),
        version=ups_version(revision_for_version),
    )


# ── about ────────────────────────────────────────────────────────────────────

_NMC2_MODELS = re.compile(r"^AP963\d", re.IGNORECASE)
_NMC3_MODELS = re.compile(r"^AP964\d", re.IGNORECASE)
# The card's operating system section: named ``aos``, titled "APC OS(AOS)".
_AOS_NAME = "aos"
_AOS_TITLE_RE = re.compile(r"\baos\b|\bapc os\b", re.IGNORECASE)


def _version_number(text: str) -> str:
    return text.strip().lstrip("vV")


@dataclass(frozen=True)
class NmcAbout:
    generation: str  # "nmc2", "nmc3" or "" when unknown
    app_name: str
    app_version: str
    model_number: str
    aos_version: str = ""  # the card's operating system (AOS) release

    @property
    def firmware(self) -> str:
        """The card's firmware, the version of an ``apc_ups`` host (the
        ``PF`` field of its sysDescr over SNMP): the AOS release, else the
        application module's when the output has no AOS section (an NMC3
        runs one image, so the two are the same there)."""
        return self.aos_version or self.app_version


def parse_about(output: str | None) -> NmcAbout:
    sections = parse_sections(output)
    model_number = ""
    app_name = ""
    app_version = ""
    aos_version = ""
    for title, values in sections:
        model_number = model_number or _first(values, "model number", "model")
        name = values.get("name", "").strip().lower()
        if name in (NMC2_APP, NMC3_APP) and not app_name:
            app_name, app_version = name, values.get("version", "")
        elif (name == _AOS_NAME or (not name and _AOS_TITLE_RE.search(title))) and not aos_version:
            aos_version = _version_number(values.get("version", ""))
    if not app_name:
        for title, values in sections:
            if "application" in title.lower():
                app_name = values.get("name", "").strip().lower()
                app_version = values.get("version", "")
                break
    if app_name == NMC2_APP:
        generation = "nmc2"
    elif app_name == NMC3_APP:
        generation = "nmc3"
    elif _NMC2_MODELS.match(model_number):
        generation = "nmc2"
    elif _NMC3_MODELS.match(model_number):
        generation = "nmc3"
    else:
        generation = ""
    return NmcAbout(
        generation=generation,
        app_name=app_name,
        app_version=_version_number(app_version),
        model_number=model_number,
        aos_version=aos_version,
    )


# ── alarmcount ───────────────────────────────────────────────────────────────

_BARE_NUMBER_RE = re.compile(r"^\s*(\d+)\s*$", re.MULTILINE)


def parse_alarm_count(output: str | None) -> int | None:
    """Active alarms, or None when the output does not say."""
    if command_error(output):
        return None
    for key, value in parse_key_values(output).items():
        if "alarm" in key:
            match = re.match(r"\d+", value)
            if match:
                return int(match.group(0))
    match = _BARE_NUMBER_RE.search(output or "")
    return int(match.group(1)) if match else None


# ── upsfwupdate ──────────────────────────────────────────────────────────────

# Nothing running. Wording differs by card firmware: the Schneider FAQ shows
# "No firmware update is in progress", an NMC3 (su v2.0) answers "No firmware
# update in progress".
_IDLE_RE = re.compile(r"\bno\s+(?:firmware\s+)?update\s+(?:is\s+)?in\s+progress\b", re.IGNORECASE)
_FAILURE_WORDS = ("fail", "error", "abort", "invalid", "refused", "reject", "mismatch", "incompatible", "not valid")


def output_off_required(text: str | None) -> bool:
    """Whether the card said the UPS output must be off (matched loosely:
    the words ``output`` and ``off`` both appear)."""
    low = (text or "").lower()
    return "output" in low and re.search(r"\boff\b", low) is not None


@dataclass(frozen=True)
class UpdateStatus:
    state: str  # "idle", "in_progress", "failed" or "error" (the command failed)
    text: str


def parse_update_status(output: str | None) -> UpdateStatus:
    """``upsfwupdate -status``: ``Status: No firmware update in progress``
    (or ``... is in progress``) means nothing is running (a finished update
    looks the same)."""
    error = command_error(output)
    if error:
        return UpdateStatus("error", error)
    values = parse_key_values(output)
    status = values.get("status", "")
    text = status or " ".join(line.strip() for line in (output or "").splitlines() if line.strip() and ">" not in line)
    low = text.lower()
    if _IDLE_RE.search(text) or _IDLE_RE.search(output or ""):
        return UpdateStatus("idle", status or "No firmware update in progress")
    if any(word in low for word in _FAILURE_WORDS):
        return UpdateStatus("failed", text)
    return UpdateStatus("in_progress", text)


@dataclass(frozen=True)
class InstallResult:
    outcome: str  # "started", "output_off" or "refused"
    message: str


def parse_install_output(output: str | None) -> InstallResult:
    """What ``upsfwupdate -install`` answered.

    A success status (E000/E001) means the update started. Otherwise a
    message about the output having to be off is a manual case; an error
    code or failure wording (e.g. the card refusing a file for another UPS
    ID) is a refusal.
    """
    text = " ".join(line.strip() for line in (output or "").splitlines() if line.strip() and ">" not in line)
    status = status_line(output)
    if status and status[0] in SUCCESS_CODES:
        return InstallResult("started", text)
    if output_off_required(text):
        return InstallResult("output_off", text)
    error = command_error(output)
    if error:
        return InstallResult("refused", text or error)
    if any(word in text.lower() for word in _FAILURE_WORDS):
        return InstallResult("refused", text)
    return InstallResult("started", text)


# ── dir ──────────────────────────────────────────────────────────────────────


def file_listed(output: str | None, filename: str) -> bool:
    """Whether ``dir`` output lists ``filename`` as a whole word."""
    pattern = rf"(?<![\w.\-]){re.escape(filename)}(?![\w.\-])"
    return re.search(pattern, output or "", re.IGNORECASE) is not None
