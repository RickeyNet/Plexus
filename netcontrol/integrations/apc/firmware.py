"""APC Smart-UPS firmware files and the rules for updating them.

The procedure follows Schneider Electric FAQ000242942 / FA170679 (update
Smart-UPS firmware through the Network Management Card): the ``.enc`` file
for the UPS's ID is copied to the card and installed with ``upsfwupdate``.

Firmware files are named ``<prefix><ID>UPS_<major>-<minor>.enc``, for
example ``SRT1025UPS_15-0.enc`` (prefix ``SRT``, UPS ID ``1025``, version
``15.0``). The UPS ID is what the card reports in ``upsabout``; a file for
another ID is refused by the card, so Plexus checks it before sending.

This module is pure: it parses names and decides what may run. The SSH/SCP
side lives in ``netcontrol.integrations.apc.upgrade``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from netcontrol.integrations.software.versions import compare_versions

# Inventory device type of a Smart-UPS managed through its NMC.
DEVICE_TYPE = "apc_ups"

# Image library ``platform`` value for UPS firmware files.
IMAGE_PLATFORM = "apc_ups"

_FILENAME_RE = re.compile(
    r"^(?P<prefix>[A-Za-z]{2,8})(?P<ups_id>\d{4})UPS_(?P<major>\d{1,3})-(?P<minor>\d{1,3})\.enc$",
    re.IGNORECASE,
)
_REVISION_VERSION_RE = re.compile(r"(\d{1,3})[.\-_](\d{1,3})")

# ── Prerequisites (FAQ000242942) ─────────────────────────────────────────────

# NMC2 runs the ``sumx`` application module, NMC3 the ``su`` module.
NMC2_APP = "sumx"
NMC3_APP = "su"
MIN_NMC2_APP_VERSION = "6.4.0"
MIN_NMC3_APP_VERSION = "1.0"

# Smart-UPS Ultra (SRTL): the card needs firmware 2.5.4.4 or later and the
# UPS needs a manual Logic Reset ("brain dead" reset) before the update.
LOGIC_RESET_IDS = frozenset({"1226", "1227"})
LOGIC_RESET_MIN_NMC_VERSION = "2.5.4.4"

# UPS IDs that Plexus leaves to a person, with the reason shown on the device.
MANUAL_UPDATE_IDS: dict[str, str] = {
    "1225": (
        "UPS ID 1225 (Smart-UPS Modular Ultra) needs the additional steps in Schneider FAQ000261838; update it by hand"
    ),
}

# UPS IDs whose update needs the UPS output turned off. Schneider publishes
# the list of models; it is filled in here from that table as it becomes
# available. Plexus never turns the output off, so these are manual updates.
OUTPUT_OFF_REQUIRED_IDS: dict[str, str] = {}

# UPS ID 1001 updates in two steps: the first file changes the UPS ID to
# 1013, then the newest UPS ID 1013 file is installed.
TWO_STEP_UPDATES: dict[str, tuple[str, str]] = {
    "1001": ("SRT1001UPS_02-9.enc", "1013"),
}
TWO_STEP_EXAMPLE_FINAL = {"1013": "SRT1013UPS_15-0.enc"}

# ── Install timing ────────────────────────────────────────────────────────────

INSTALL_TIMEOUT_SECONDS = 30 * 60
# Smart-UPS Modular Ultra (SRYL) can take more than 20 minutes.
SRYL_INSTALL_TIMEOUT_SECONDS = 45 * 60
POLL_INTERVAL_SECONDS = 20

# A ``.enc`` file is a few megabytes; anything near this is not one.
MAX_FIRMWARE_FILE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class UpsFirmwareFile:
    """One UPS firmware file, parsed from its name."""

    filename: str
    prefix: str
    ups_id: str
    version: str

    @property
    def is_modular_ultra(self) -> bool:
        return self.prefix.upper() == "SRYL"


def parse_firmware_filename(name: str | None) -> UpsFirmwareFile | None:
    """``SRT1025UPS_15-0.enc`` -> prefix ``SRT``, UPS ID ``1025``, version
    ``15.0``; ``None`` for any other name (including paths)."""
    match = _FILENAME_RE.match(str(name or ""))
    if not match:
        return None
    return UpsFirmwareFile(
        filename=match.group(0),
        prefix=match.group("prefix").upper(),
        ups_id=match.group("ups_id"),
        version=f"{int(match.group('major'))}.{int(match.group('minor'))}",
    )


def is_firmware_filename(name: str | None) -> bool:
    return parse_firmware_filename(name) is not None


def normalize_ups_id(raw: object) -> str:
    """The UPS ID as digits without leading zeros (``"01025"`` -> ``"1025"``)."""
    digits = re.sub(r"\D", "", str(raw or ""))
    return str(int(digits)) if digits else ""


def ups_version(revision: object) -> str:
    """The ``major.minor`` UPS firmware version in a revision string:
    ``"UPS 09.3 (ID18)"`` -> ``"9.3"``, ``"15-0"`` -> ``"15.0"``."""
    match = _REVISION_VERSION_RE.search(str(revision or ""))
    if not match:
        return ""
    return f"{int(match.group(1))}.{int(match.group(2))}"


def install_timeout_seconds(image: UpsFirmwareFile | None, model: str = "") -> int:
    """How long to wait for ``upsfwupdate`` to finish on one UPS."""
    if (image is not None and image.is_modular_ultra) or "SRYL" in (model or "").upper():
        return SRYL_INSTALL_TIMEOUT_SECONDS
    return INSTALL_TIMEOUT_SECONDS


def _newest(files: Iterable[UpsFirmwareFile]) -> UpsFirmwareFile | None:
    newest: UpsFirmwareFile | None = None
    for item in files:
        if newest is None or compare_versions(item.version, newest.version) > 0:
            newest = item
    return newest


# ── Update plan ──────────────────────────────────────────────────────────────

READY = "ready"
UP_TO_DATE = "up_to_date"
BLOCKED = "blocked"
MANUAL = "manual"
WAITING_LOGIC_RESET = "waiting_logic_reset"


@dataclass(frozen=True)
class UpdatePlan:
    """What to install on one UPS, or why nothing will be installed.

    ``outcome`` is one of ``ready`` (install ``steps`` in order),
    ``up_to_date`` (already on ``target``), ``blocked`` / ``manual`` /
    ``waiting_logic_reset`` (``reason`` says why).
    """

    outcome: str
    reason: str = ""
    steps: tuple[UpsFirmwareFile, ...] = field(default_factory=tuple)
    target: UpsFirmwareFile | None = None


def plan_update(
    ups_id: object,
    running_version: str,
    campaign_files: Iterable[UpsFirmwareFile],
    library_files: Iterable[UpsFirmwareFile] = (),
) -> UpdatePlan:
    """Pick the file(s) to install on a UPS from the campaign's images.

    The campaign image whose UPS ID equals the UPS's ID is used (the newest
    one when there are several). UPS ID 1001 takes its two-step path from
    the whole image library. Never a downgrade or a reinstall: an image at
    the running version means the UPS is already up to date.
    """
    uid = normalize_ups_id(ups_id)
    campaign = list(campaign_files)
    library = list(library_files)
    if not uid:
        return UpdatePlan(BLOCKED, "Could not read the UPS ID from upsabout")
    if uid in MANUAL_UPDATE_IDS:
        return UpdatePlan(MANUAL, MANUAL_UPDATE_IDS[uid])
    if uid in OUTPUT_OFF_REQUIRED_IDS:
        return UpdatePlan(
            MANUAL,
            f"UPS ID {uid} must have its output turned off for a firmware update "
            f"({OUTPUT_OFF_REQUIRED_IDS[uid] or 'Schneider model table'}); Plexus never turns UPS output off",
        )
    if not running_version:
        return UpdatePlan(BLOCKED, "Could not read the running UPS firmware version from upsabout")

    if uid in TWO_STEP_UPDATES:
        return _plan_two_step(uid, running_version, campaign + library)

    candidates = [f for f in campaign if f.ups_id == uid]
    if not candidates and uid in {next_id for _first, next_id in TWO_STEP_UPDATES.values()}:
        # A UPS part-way through a two-step update: its second file came
        # from the library, so look there again.
        candidates = [f for f in library if f.ups_id == uid]
    target = _newest(candidates)
    if target is None:
        others = sorted({f.ups_id for f in campaign})
        detail = f" (campaign images are for UPS ID {', '.join(others)})" if others else ""
        return UpdatePlan(BLOCKED, f"No image in this campaign is for UPS ID {uid}{detail}")
    order = compare_versions(target.version, running_version)
    if order == 0:
        return UpdatePlan(UP_TO_DATE, f"Already running {running_version}", target=target)
    if order < 0:
        return UpdatePlan(
            BLOCKED,
            f"{target.filename} (version {target.version}) is older than the running version "
            f"{running_version}; Plexus never downgrades UPS firmware",
            target=target,
        )
    return UpdatePlan(READY, steps=(target,), target=target)


def _plan_two_step(uid: str, running_version: str, files: list[UpsFirmwareFile]) -> UpdatePlan:
    first_name, next_id = TWO_STEP_UPDATES[uid]
    first = next((f for f in files if f.filename.lower() == first_name.lower()), None)
    final = _newest(f for f in files if f.ups_id == next_id)
    missing = []
    if first is None:
        missing.append(first_name)
    if final is None:
        missing.append(f"a UPS ID {next_id} image such as {TWO_STEP_EXAMPLE_FINAL.get(next_id, '')}".rstrip())
    if first is None or final is None:
        return UpdatePlan(
            BLOCKED,
            f"UPS ID {uid} updates in two steps ({first_name}, which changes the ID to {next_id}, then the "
            f"UPS ID {next_id} firmware); missing from the image library: {' and '.join(missing)}",
        )
    if compare_versions(first.version, running_version) <= 0:
        return UpdatePlan(
            BLOCKED,
            f"{first.filename} (version {first.version}) is not newer than the running version "
            f"{running_version}; Plexus never downgrades UPS firmware",
            target=final,
        )
    return UpdatePlan(READY, steps=(first, final), target=final)


# ── Device pre-checks ────────────────────────────────────────────────────────


def alarm_problem(active_alarms: int | None) -> str | None:
    if active_alarms is None:
        return "Could not read the active alarm count (alarmcount)"
    if active_alarms > 0:
        return f"{active_alarms} active alarm(s) on the UPS/NMC; clear them before updating firmware"
    return None


def nmc_problem(generation: str, app_version: str, ups_id: object) -> str | None:
    """Why the card's firmware is not good enough to update this UPS, or None."""
    uid = normalize_ups_id(ups_id)
    if generation not in ("nmc2", "nmc3"):
        return "Could not identify the NMC (expected application module sumx on NMC2 or su on NMC3 in the about output)"
    if not app_version:
        return "Could not read the NMC application firmware version from the about output"
    if generation == "nmc2" and compare_versions(app_version, MIN_NMC2_APP_VERSION) < 0:
        return (
            f"NMC2 application (sumx) firmware {app_version} is older than v{MIN_NMC2_APP_VERSION}, the "
            "minimum for UPS firmware updates; update the NMC first"
        )
    if generation == "nmc3" and compare_versions(app_version, MIN_NMC3_APP_VERSION) < 0:
        return (
            f"NMC3 application (su) firmware {app_version} is older than v{MIN_NMC3_APP_VERSION}, the "
            "minimum for UPS firmware updates; update the NMC first"
        )
    if uid in LOGIC_RESET_IDS and (
        generation != "nmc3" or compare_versions(app_version, LOGIC_RESET_MIN_NMC_VERSION) < 0
    ):
        return (
            f"UPS ID {uid} (Smart-UPS Ultra) needs NMC firmware {LOGIC_RESET_MIN_NMC_VERSION} or later "
            f"(the card runs {generation.upper()} {app_version}); update the NMC first"
        )
    return None


def needs_logic_reset(ups_id: object) -> bool:
    return normalize_ups_id(ups_id) in LOGIC_RESET_IDS


@dataclass(frozen=True)
class PrecheckResult:
    outcome: str
    reason: str
    plan: UpdatePlan


def evaluate_prechecks(
    *,
    ups_id: object,
    running_version: str,
    nmc_generation: str,
    nmc_app_version: str,
    active_alarms: int | None,
    campaign_files: Iterable[UpsFirmwareFile],
    library_files: Iterable[UpsFirmwareFile] = (),
    logic_reset_confirmed: bool = False,
) -> PrecheckResult:
    """Every pre-check for one UPS, in order: the plan (manual IDs, image
    and version), then the alarms and the NMC firmware, then the Logic
    Reset confirmation for the Smart-UPS Ultra IDs."""
    plan = plan_update(ups_id, running_version, campaign_files, library_files)
    if plan.outcome in (MANUAL, UP_TO_DATE, BLOCKED):
        return PrecheckResult(plan.outcome, plan.reason, plan)
    problems = [p for p in (alarm_problem(active_alarms), nmc_problem(nmc_generation, nmc_app_version, ups_id)) if p]
    if problems:
        return PrecheckResult(BLOCKED, "; ".join(problems), plan)
    if needs_logic_reset(ups_id) and not logic_reset_confirmed:
        return PrecheckResult(
            WAITING_LOGIC_RESET,
            f"UPS ID {normalize_ups_id(ups_id)} (Smart-UPS Ultra) needs a manual Logic Reset before the update. "
            "Do the reset, then confirm it on this device in the campaign",
            plan,
        )
    return PrecheckResult(READY, "", plan)
