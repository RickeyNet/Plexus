"""Upgrades tool phases for APC Smart-UPS devices, run through the NMC.

A UPS (inventory device type ``apc_ups``) goes through the same campaign
phases as a switch, with the steps of Schneider FAQ000242942 behind them:

  prestage        pre-checks only (``upsabout``, ``about``, ``alarmcount``):
                  UPS ID and running version, NMC firmware minimum, no
                  active alarms, an image for this UPS ID that is newer than
                  the running firmware, manual and Logic Reset cases
  transfer        SCP the ``.enc`` file to ``/tmp`` on the card, then
                  ``cd /tmp`` + ``dir`` to confirm it is there
  activate        ``upsfwupdate -install``, poll ``upsfwupdate -status``
                  until the card reports no update in progress, re-read
                  ``upsabout`` and require the new version (UPS ID 1001 runs
                  its two files back to back here)
  verify          re-read ``upsabout`` and compare with the target
  verify_prestage the read-only "Check status"

There is no separate commit step. Plexus never turns the UPS output off:
an update that needs it is left to a person (``manual``). The session is
the NMC command line over SSH with the campaign's credential (Netmiko
``apc_aos``); the copy uses the legacy SCP protocol (Netmiko/``scp``), the
equivalent of ``scp -O``.

Per-device statuses used besides the shared ones: ``manual`` (a person has
to do the update; the reason is in ``error_message``) and ``waiting`` (the
Smart-UPS Ultra Logic Reset has not been confirmed yet).
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import md5 as _md5
from types import ModuleType
from typing import Any

import routes.database as db

from netcontrol.integrations.apc import nmc_cli
from netcontrol.integrations.apc.firmware import (
    BLOCKED,
    DEVICE_TYPE,
    IMAGE_PLATFORM,
    MANUAL,
    MAX_FIRMWARE_FILE_BYTES,
    POLL_INTERVAL_SECONDS,
    READY,
    TWO_STEP_UPDATES,
    UP_TO_DATE,
    WAITING_LOGIC_RESET,
    PrecheckResult,
    UpsFirmwareFile,
    evaluate_prechecks,
    install_timeout_seconds,
    needs_logic_reset,
    parse_firmware_filename,
)
from netcontrol.integrations.software.versions import compare_versions
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.upgrades.apc")

MANUAL_STATUS = "manual"
WAITING_STATUS = "waiting"
LOGIC_RESET_PHASE = "awaiting_logic_reset"
_SCP_RETRY_BACKOFF_SECONDS = 15
# Consecutive ``upsfwupdate -status`` reads that may fail (session drop,
# error code) before the install is reported as lost.
_MAX_STATUS_READ_FAILURES = 3


def _up() -> ModuleType:
    """The Upgrades route module (imported late: it imports this module)."""
    from netcontrol.routes import upgrades

    return upgrades


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ═════════════════════════════════════════════════════════════════════════════
# Campaign membership and images
# ═════════════════════════════════════════════════════════════════════════════


async def is_ups_device(dev: dict) -> bool:
    return await _up()._resolve_device_type(dev) == DEVICE_TYPE


async def campaign_mix_error(host_ids: list[int], ad_hoc_ips: list[str]) -> str | None:
    """A campaign holds either UPS devices or other devices, not both.

    The phases mean different things for each (Activate installs UPS
    firmware without a reload; it reboots a switch) and a UPS takes its
    image by UPS ID rather than by model pattern, so one campaign is one
    kind. Ad-hoc addresses have no device type and count as switches.
    """
    if not host_ids:
        return None
    hosts = await db.get_hosts_by_ids(list(host_ids))
    ups = [h for h in hosts if (h.get("device_type") or "") == DEVICE_TYPE]
    if not ups:
        return None
    others = len(hosts) - len(ups) + len([ip for ip in ad_hoc_ips if ip.strip()])
    if others:
        return (
            "A campaign holds either APC Smart-UPS devices or other devices, not both: "
            f"{len(ups)} UPS device(s) and {others} other device(s) selected. Create a separate campaign "
            "for the UPS devices."
        )
    return None


def _campaign_files(image_map: Any) -> list[UpsFirmwareFile]:
    """The UPS firmware files a campaign's image map names (keys ignored:
    a UPS takes the image whose UPS ID matches its own)."""
    if isinstance(image_map, dict):
        names = list(image_map.values())
    else:
        names = [item[1] for item in (image_map or []) if isinstance(item, (list, tuple)) and len(item) == 2]
    files = []
    for name in names:
        parsed = parse_firmware_filename(os.path.basename(str(name or "")))
        if parsed is not None:
            files.append(parsed)
    return files


async def _library_files() -> list[UpsFirmwareFile]:
    files = []
    for image in await db.get_all_upgrade_images():
        parsed = parse_firmware_filename(image.get("filename"))
        if parsed is not None:
            files.append(parsed)
    return files


# ═════════════════════════════════════════════════════════════════════════════
# Image upload (.enc, or a vendor .zip holding one .enc)
# ═════════════════════════════════════════════════════════════════════════════


@dataclass
class UploadedFirmware:
    """A UPS firmware upload ready to record in the image library.

    For a ``.zip`` upload the ``.enc`` was extracted to ``staged_path``;
    ``commit`` moves it to ``final_path`` and removes the zip.
    """

    image: UpsFirmwareFile
    final_path: str
    size: int
    md5_hash: str
    staged_path: str | None = None
    archive_path: str | None = None

    @property
    def filename(self) -> str:
        return self.image.filename

    @property
    def notes(self) -> str:
        return f"APC Smart-UPS firmware for UPS ID {self.image.ups_id} ({self.image.prefix})"

    def commit(self) -> None:
        if self.staged_path:
            os.replace(self.staged_path, self.final_path)
            self.staged_path = None
        if self.archive_path and os.path.isfile(self.archive_path):
            os.remove(self.archive_path)
            self.archive_path = None

    def discard(self) -> None:
        for path in (self.staged_path, self.archive_path):
            if path and os.path.isfile(path):
                try:
                    os.remove(path)
                except OSError as exc:
                    LOGGER.debug("Failed to remove %s: %s", path, exc)


def _file_md5(path: str) -> str:
    # MD5 matches the checksum the image library records for every image;
    # it is an integrity check, not a security primitive.
    digest = _md5(usedforsecurity=False)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_uploaded_image(path: str, filename: str, images_dir: str) -> UploadedFirmware | None:
    """Recognise a UPS firmware upload already written to ``path``.

    * ``<prefix><ID>UPS_<major>-<minor>.enc``: returned as is.
    * a ``.zip`` holding exactly one such ``.enc``: the ``.enc`` is
      extracted (by its base name only, never a path from the archive) to a
      staging file in ``images_dir``; ``commit`` puts it in place.
    * anything else (including a zip without an ``.enc``): None, the caller
      keeps its usual handling.

    Raises ValueError for a UPS upload that cannot be accepted: an ``.enc``
    with a name that is not a UPS firmware name, a zip with several
    ``.enc`` files, an unsafe member path or an oversize member.
    """
    lower = filename.lower()
    if lower.endswith(".enc"):
        image = parse_firmware_filename(filename)
        if image is None:
            raise ValueError(
                "An .enc upload must keep the vendor file name <prefix><UPS ID>UPS_<major>-<minor>.enc "
                "(for example SRT1025UPS_15-0.enc) so the UPS ID and version can be read from it"
            )
        size = os.path.getsize(path)
        if size > MAX_FIRMWARE_FILE_BYTES:
            raise ValueError("The .enc file is larger than any UPS firmware file")
        return UploadedFirmware(image=image, final_path=path, size=size, md5_hash=_file_md5(path))
    if not lower.endswith(".zip"):
        return None
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ValueError("The .zip upload is not a readable zip archive") from exc
    with archive:
        members = [m for m in archive.infolist() if not m.is_dir() and m.filename.lower().endswith(".enc")]
        if not members:
            return None
        if len(members) > 1:
            names = ", ".join(sorted(os.path.basename(m.filename) for m in members))
            raise ValueError(f"The zip holds more than one .enc file ({names}); upload the one you need")
        member = members[0]
        member_name = member.filename.replace("\\", "/")
        if member_name.startswith("/") or ".." in member_name.split("/") or ":" in member_name:
            raise ValueError("The zip has an unsafe path for its .enc file")
        image = parse_firmware_filename(os.path.basename(member_name))
        if image is None:
            raise ValueError(
                f"The .enc file in the zip ({os.path.basename(member_name)}) is not named like UPS firmware "
                "(<prefix><UPS ID>UPS_<major>-<minor>.enc)"
            )
        if member.file_size > MAX_FIRMWARE_FILE_BYTES:
            raise ValueError("The .enc file in the zip is larger than any UPS firmware file")
        handle, staged = tempfile.mkstemp(prefix=".ups-", suffix=".partial", dir=images_dir)
        written = 0
        try:
            with os.fdopen(handle, "wb") as out, archive.open(member) as src:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_FIRMWARE_FILE_BYTES:
                        raise ValueError("The .enc file in the zip is larger than any UPS firmware file")
                    out.write(chunk)
        except BaseException:
            os.remove(staged)
            raise
    return UploadedFirmware(
        image=image,
        final_path=os.path.join(images_dir, image.filename),
        size=written,
        md5_hash=_file_md5(staged),
        staged_path=staged,
        archive_path=path,
    )


# ═════════════════════════════════════════════════════════════════════════════
# Device session helpers
# ═════════════════════════════════════════════════════════════════════════════


@dataclass
class _UpsState:
    about: nmc_cli.UpsAbout
    nmc: nmc_cli.NmcAbout
    alarms: int | None


class _Run:
    """One device in one phase: the session, events and status writes."""

    def __init__(self, campaign_id: int, dev: dict, credentials: dict, options: dict, status_key: str) -> None:
        self.campaign_id = campaign_id
        self.dev = dev
        self.dev_id: int = dev["id"]
        self.ip: str = dev["ip_address"]
        self.credentials = credentials
        self.options = options
        self.status_key = status_key
        self.conn: Any = None

    async def emit(self, level: str, message: str) -> None:
        await _up()._emit(self.campaign_id, self.dev_id, level, message, host=self.ip)

    async def set_status(self, status: str, error: str = "", **fields: Any) -> None:
        if status == "failed":
            fields.setdefault("phase", "failed")
        await db.update_upgrade_device(self.dev_id, **{self.status_key: status}, error_message=error, **fields)
        await _up()._emit_device_status(self.campaign_id, self.dev_id, **{self.status_key: status}, error_message=error)

    async def fail(self, message: str) -> None:
        await self.set_status("failed", message)
        await self.emit("error", message)

    async def connect(self) -> bool:
        await self.emit("info", f"Connecting to the NMC at {self.ip} (SSH)...")
        try:
            self.conn = await _up()._connect_device(
                self.ip,
                self.credentials,
                self.options,
                retries=self.options.get("retries", 2),
                device_type=nmc_cli.NETMIKO_DEVICE_TYPE,
            )
        except Exception as exc:
            await self.fail(f"Connection failed: {exc}")
            return False
        await self.emit("success", "Connected")
        return True

    async def reconnect(self) -> None:
        await self.disconnect()
        self.conn = await _up()._connect_device(
            self.ip, self.credentials, self.options, retries=2, device_type=nmc_cli.NETMIKO_DEVICE_TYPE
        )

    async def disconnect(self) -> None:
        if self.conn is None:
            return
        try:
            await asyncio.to_thread(self.conn.disconnect)
        except Exception as exc:
            LOGGER.debug("Disconnect failed for %s: %s", self.ip, exc)
        self.conn = None

    async def cli(self, command: str, read_timeout: int = 60) -> str:
        output = await asyncio.to_thread(self.conn.send_command, command, read_timeout=read_timeout)
        return str(output or "")

    async def read_about(self) -> nmc_cli.UpsAbout:
        about = nmc_cli.parse_upsabout(await self.cli(nmc_cli.UPSABOUT))
        fields: dict[str, Any] = {}
        if about.model or about.sku:
            fields["model"] = about.sku or about.model
        if about.version:
            fields["current_version"] = about.version
        if about.ups_id:
            fields["ups_id"] = about.ups_id
        if fields:
            await db.update_upgrade_device(self.dev_id, **fields)
        return about

    async def read_state(self) -> _UpsState:
        about = await self.read_about()
        nmc = nmc_cli.parse_about(await self.cli(nmc_cli.ABOUT))
        alarms = nmc_cli.parse_alarm_count(await self.cli(nmc_cli.ALARMCOUNT))
        await self.emit(
            "info",
            f"UPS {about.model or about.sku or 'model unknown'}, UPS ID {about.ups_id or 'unknown'}, "
            f"firmware {about.firmware_revision or 'unknown'}; NMC {nmc.generation.upper() or 'unknown'} "
            f"{nmc.app_name or '?'} {nmc.app_version or '?'}; active alarms: "
            f"{'unknown' if alarms is None else alarms}",
        )
        return _UpsState(about=about, nmc=nmc, alarms=alarms)

    async def is_cancelled(self) -> bool:
        latest = await db.get_upgrade_device(self.dev_id)
        return bool(latest and latest.get(self.status_key) == "cancelled")


async def _prechecks(run: _Run, image_map: Any) -> tuple[PrecheckResult, _UpsState]:
    state = await run.read_state()
    latest = await db.get_upgrade_device(run.dev_id) or {}
    result = evaluate_prechecks(
        ups_id=state.about.ups_id,
        running_version=state.about.version,
        nmc_generation=state.nmc.generation,
        nmc_app_version=state.nmc.app_version,
        active_alarms=state.alarms,
        campaign_files=_campaign_files(image_map),
        library_files=await _library_files(),
        logic_reset_confirmed=bool(latest.get("logic_reset_confirmed_at")),
    )
    if result.plan.target is not None:
        await db.update_upgrade_device(run.dev_id, target_image=result.plan.target.filename)
    return result, state


async def _apply_gate(run: _Run, result: PrecheckResult, running_version: str) -> bool:
    """Record a pre-check outcome that stops this phase; True when ready."""
    if result.outcome == READY:
        return True
    if result.outcome == UP_TO_DATE:
        await _up()._mark_device_on_target_version(run.campaign_id, run.dev_id, running_version)
        await run.emit("success", f"Already running the target firmware {running_version}; nothing to install")
    elif result.outcome == MANUAL:
        message = f"Manual update required: {result.reason}"
        await run.set_status(MANUAL_STATUS, message, phase="manual")
        await run.emit("warn", message)
    elif result.outcome == WAITING_LOGIC_RESET:
        message = f"Waiting for Logic Reset: {result.reason}"
        await run.set_status(WAITING_STATUS, message, phase=LOGIC_RESET_PHASE)
        await run.emit("warn", message)
    else:
        await run.fail(f"Blocked: {result.reason}")
    return False


# ═════════════════════════════════════════════════════════════════════════════
# Transfer
# ═════════════════════════════════════════════════════════════════════════════


def _scp_put(conn: Any, local_path: str, remote_path: str, progress: Any, timeout: float) -> None:
    from netmiko.scp_handler import SCPConn

    scp_conn = SCPConn(conn, socket_timeout=timeout, progress4=progress)
    try:
        scp_conn.scp_transfer_file(local_path, remote_path)
    finally:
        scp_conn.close()


async def _file_on_card(run: _Run, filename: str) -> bool:
    await run.cli(nmc_cli.CD_REMOTE_DIR)
    return nmc_cli.file_listed(await run.cli(nmc_cli.DIR), filename)


async def _send_to_card(run: _Run, image: UpsFirmwareFile) -> str | None:
    """SCP ``image`` to ``/tmp`` on the card and confirm it with ``dir``.
    Returns an error message, or None when the file is on the card."""
    up = _up()
    try:
        local_path = up._local_image_path(image.filename)
    except Exception:
        local_path = None
    if not local_path:
        return f"Image {image.filename} is not stored on the Plexus server; upload it to the image library"
    remote = nmc_cli.remote_path(image.filename)
    attempts = 1 + max(0, min(int(run.options.get("retries", 0) or 0), 3))
    last_error = ""
    for attempt in range(1, attempts + 1):
        if attempt > 1:
            await asyncio.sleep(_SCP_RETRY_BACKOFF_SECONDS)
        await run.emit("info", f"Copying {image.filename} to {remote} on the NMC (SCP, attempt {attempt}/{attempts})")
        progress = up._TransferProgressReporter(asyncio.get_running_loop(), run.campaign_id, run.dev_id, attempt)
        try:
            await asyncio.to_thread(
                _scp_put, run.conn, local_path, remote, progress, float(run.options.get("scp_timeout", 60))
            )
        except Exception as exc:
            last_error = f"SCP failed: {exc}"
            await run.emit("warn", last_error)
        try:
            if await _file_on_card(run, image.filename):
                await run.emit("success", f"{image.filename} is in {nmc_cli.REMOTE_DIR} on the NMC")
                return None
        except Exception as exc:
            last_error = f"Could not list {nmc_cli.REMOTE_DIR} on the NMC: {exc}"
        if not last_error:
            last_error = f"{image.filename} is not listed in {nmc_cli.REMOTE_DIR} on the NMC after the copy"
    return (
        f"{last_error}. Check that SCP is enabled on the NMC (Configuration > Network > Console > Access) "
        "and that the credential may log in over SSH"
    )


async def device_transfer(campaign_id: int, dev: dict, credentials: dict, image_map: Any, options: dict) -> None:
    run = _Run(campaign_id, dev, credentials, options, "transfer_status")
    await _up()._start_device_phase(campaign_id, run.dev_id, "transfer_status", phase="transfer", started_at=_now())
    if not await run.connect():
        return
    try:
        result, state = await _prechecks(run, image_map)
        if not await _apply_gate(run, result, state.about.version):
            return
        image = result.plan.steps[0]
        error = await _send_to_card(run, image)
        if error:
            await run.fail(error)
            return
        await run.set_status("completed", phase="transfer_done", phase_detail=f"{image.filename} on the NMC")
        await run.emit("success", "Transfer complete; Activate installs the firmware")
    except Exception as exc:
        LOGGER.debug("UPS transfer failed for %s", run.ip, exc_info=True)
        await run.fail(f"Transfer failed: {exc}")
    finally:
        await run.disconnect()


# ═════════════════════════════════════════════════════════════════════════════
# Activate (install, wait, verify)
# ═════════════════════════════════════════════════════════════════════════════


@dataclass
class _StepOutcome:
    outcome: str  # "ok", "failed", "manual" or "cancelled"
    message: str = ""


async def _read_update_status(run: _Run) -> nmc_cli.UpdateStatus:
    return nmc_cli.parse_update_status(await run.cli(nmc_cli.UPDATE_STATUS))


async def _wait_for_install(run: _Run, image: UpsFirmwareFile, model: str) -> _StepOutcome:
    """Poll ``upsfwupdate -status`` until no update is in progress."""
    timeout = install_timeout_seconds(image, model)
    start = time.monotonic()
    failures = 0
    last_text = ""
    while True:
        try:
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            await run.emit(
                "warn",
                "Campaign cancelled: Plexus stopped watching the install. The firmware install already "
                "started on the UPS cannot be aborted and continues on its own; check the UPS with "
                "Check status later",
            )
            raise
        if await run.is_cancelled():
            return _StepOutcome(
                "cancelled",
                "Cancelled by user while the install was running. The install already started on the UPS "
                "cannot be aborted and continues on its own; check the UPS with Check status later",
            )
        elapsed = int(time.monotonic() - start)
        try:
            status = await _read_update_status(run)
        except Exception as exc:
            failures += 1
            await run.emit("dim", f"Status read failed ({exc}); reconnecting ({elapsed}s elapsed)")
            if failures >= _MAX_STATUS_READ_FAILURES:
                return _StepOutcome("failed", f"Lost contact with the NMC while the install was running: {exc}")
            try:
                await run.reconnect()
            except Exception as reconnect_exc:
                LOGGER.debug("Reconnect to %s failed: %s", run.ip, reconnect_exc)
            continue
        if status.state == "idle":
            return _StepOutcome("ok")
        if status.state == "failed":
            if nmc_cli.output_off_required(status.text):
                return _StepOutcome("manual", f"The NMC says the UPS output must be off: {status.text}")
            return _StepOutcome("failed", f"The NMC reported the update failed: {status.text}")
        if status.state == "error":
            failures += 1
            if failures >= _MAX_STATUS_READ_FAILURES:
                return _StepOutcome("failed", f"upsfwupdate -status keeps failing: {status.text}")
        else:
            failures = 0
            if status.text and status.text != last_text:
                await run.emit("dim", f"Install: {status.text} ({elapsed}s elapsed)")
                last_text = status.text
        if elapsed >= timeout:
            return _StepOutcome(
                "failed",
                f"The install did not finish within {timeout // 60} minutes; check the UPS and the NMC event log",
            )


async def _install_step(run: _Run, image: UpsFirmwareFile, model: str) -> _StepOutcome:
    """Install one firmware file and confirm the UPS runs its version."""
    before = await _read_update_status(run)
    if before.state == "in_progress":
        return _StepOutcome("failed", f"A firmware update is already running on this UPS ({before.text})")
    if not await _file_on_card(run, image.filename):
        await run.emit("info", f"{image.filename} is not in {nmc_cli.REMOTE_DIR} on the NMC; copying it now")
        error = await _send_to_card(run, image)
        if error:
            return _StepOutcome("failed", error)

    command = nmc_cli.install_command(image.filename)
    await run.emit("info", f"Installing: {command}")
    result = nmc_cli.parse_install_output(await run.cli(command, read_timeout=180))
    if result.outcome == "output_off":
        return _StepOutcome(
            "manual",
            f"The NMC refused the update because the UPS output must be off ({result.message}). "
            "Plexus never turns UPS output off; update this UPS by hand",
        )
    if result.outcome == "refused":
        return _StepOutcome("failed", f"The NMC refused {image.filename}: {result.message or 'no detail'}")
    timeout = install_timeout_seconds(image, model)
    await run.emit(
        "info",
        f"Install started; polling every {POLL_INTERVAL_SECONDS}s for up to {timeout // 60} minutes. "
        "The UPS output stays on",
    )
    waited = await _wait_for_install(run, image, model)
    if waited.outcome != "ok":
        return waited

    about = await run.read_about()
    if compare_versions(about.version, image.version) != 0 or (
        about.ups_id and about.ups_id != image.ups_id and not _changes_id(image)
    ):
        return _StepOutcome(
            "failed",
            f"Firmware file was transferred but not installed: the UPS reports {about.firmware_revision or 'no version'} "
            f"(UPS ID {about.ups_id or 'unknown'}), expected version {image.version}. See Schneider FAQ000258690",
        )
    await run.emit("success", f"UPS now runs {about.version} (UPS ID {about.ups_id or 'unknown'})")
    return _StepOutcome("ok")


def _changes_id(image: UpsFirmwareFile) -> bool:
    """The first file of a two-step update changes the UPS ID."""
    step = TWO_STEP_UPDATES.get(image.ups_id)
    return bool(step and step[0].lower() == image.filename.lower())


async def device_activate(campaign_id: int, dev: dict, credentials: dict, image_map: Any, options: dict) -> None:
    run = _Run(campaign_id, dev, credentials, options, "activate_status")
    await _up()._start_device_phase(campaign_id, run.dev_id, "activate_status", phase="activate", started_at=_now())
    if not await run.connect():
        return
    try:
        result, state = await _prechecks(run, image_map)
        if not await _apply_gate(run, result, state.about.version):
            return
        model = state.about.sku or state.about.model
        steps = result.plan.steps
        if len(steps) > 1:
            await run.emit(
                "info",
                f"UPS ID {state.about.ups_id} updates in {len(steps)} steps: "
                + ", then ".join(step.filename for step in steps),
            )
        for index, image in enumerate(steps, start=1):
            if len(steps) > 1:
                await run.emit("info", f"Step {index}/{len(steps)}: {image.filename}")
            outcome = await _install_step(run, image, model)
            if outcome.outcome == "manual":
                await run.set_status(MANUAL_STATUS, f"Manual update required: {outcome.message}", phase="manual")
                await run.emit("warn", outcome.message)
                return
            if outcome.outcome == "cancelled":
                await run.emit("warn", outcome.message)
                return
            if outcome.outcome != "ok":
                await run.fail(outcome.message)
                return
        final = steps[-1]
        await _up()._mark_device_on_target_version(campaign_id, run.dev_id, final.version)
        await run.emit("success", f"Firmware update complete: {final.filename} installed and verified")
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        LOGGER.debug("UPS activate failed for %s", run.ip, exc_info=True)
        await run.fail(f"Activate failed: {exc}")
    finally:
        await run.disconnect()


# ═════════════════════════════════════════════════════════════════════════════
# Prestage, verify, check status
# ═════════════════════════════════════════════════════════════════════════════


async def device_prestage(campaign_id: int, dev: dict, credentials: dict, image_map: Any, options: dict) -> None:
    run = _Run(campaign_id, dev, credentials, options, "prestage_status")
    await _up()._start_device_phase(campaign_id, run.dev_id, "prestage_status", phase="prestage", started_at=_now())
    if not await run.connect():
        return
    try:
        result, state = await _prechecks(run, image_map)
        if not await _apply_gate(run, result, state.about.version):
            return
        steps = ", then ".join(step.filename for step in result.plan.steps)
        await run.set_status(
            "completed", phase="prestage_done", phase_detail=f"Pre-checks passed; will install {steps}"
        )
        await run.emit("success", f"Pre-checks passed; will install {steps}")
    except Exception as exc:
        LOGGER.debug("UPS prestage failed for %s", run.ip, exc_info=True)
        await run.fail(f"Pre-checks failed: {exc}")
    finally:
        await run.disconnect()


async def device_verify(campaign_id: int, dev: dict, credentials: dict, image_map: Any, options: dict) -> None:
    run = _Run(campaign_id, dev, credentials, options, "verify_status")
    await _up()._start_device_phase(campaign_id, run.dev_id, "verify_status", phase="verify")
    if not await run.connect():
        return
    try:
        about = await run.read_about()
        latest = await db.get_upgrade_device(run.dev_id) or {}
        target = parse_firmware_filename(latest.get("target_image") or dev.get("target_image"))
        if target is None:
            await run.fail("No target firmware to verify against; run Prestage first")
            return
        if not about.version:
            await run.fail("Could not read the running UPS firmware version from upsabout")
            return
        if compare_versions(about.version, target.version) == 0 and (not about.ups_id or about.ups_id == target.ups_id):
            await _up()._mark_device_on_target_version(campaign_id, run.dev_id, about.version)
            await run.emit("success", f"Upgrade verified: running {about.version} ({target.filename})")
            return
        message = (
            f"Version mismatch: the UPS runs {about.version} (UPS ID {about.ups_id or 'unknown'}), "
            f"expected {target.version} from {target.filename}"
        )
        await db.update_upgrade_device(run.dev_id, activate_status="failed")
        await _up()._emit_device_status(campaign_id, run.dev_id, activate_status="failed")
        await run.fail(message)
    except Exception as exc:
        await run.fail(f"Verify failed: {exc}")
    finally:
        await run.disconnect()


async def device_check_status(campaign_id: int, dev: dict, credentials: dict, image_map: Any, options: dict) -> None:
    """Read-only: running firmware, an update in progress, the file in /tmp.

    The verdict lands in the transfer column (completed when the file for
    the next step is on the card, pending when not), or in every column
    when the UPS already runs the target. A check that cannot connect keeps
    the previous transfer status.
    """
    run = _Run(campaign_id, dev, credentials, options, "transfer_status")
    previous = dev.get("transfer_status") or "pending"
    await _up()._start_device_phase(
        campaign_id, run.dev_id, "transfer_status", phase_detail="Checking UPS firmware", started_at=_now()
    )
    try:
        run.conn = await _up()._connect_device(
            run.ip, credentials, options, retries=options.get("retries", 2), device_type=nmc_cli.NETMIKO_DEVICE_TYPE
        )
    except Exception as exc:
        await run.set_status(previous, f"Status check could not complete: Connection failed: {exc}")
        await run.emit("error", f"Status check could not complete: Connection failed: {exc}")
        return
    try:
        result, state = await _prechecks(run, image_map)
        plan = result.plan
        if plan.outcome == UP_TO_DATE:
            await _apply_gate(run, result, state.about.version)
            return
        if plan.outcome == MANUAL:
            await _apply_gate(run, PrecheckResult(MANUAL, plan.reason, plan), state.about.version)
            return
        if plan.outcome == BLOCKED or not plan.steps:
            await run.set_status(previous, f"Blocked: {plan.reason}")
            await run.emit("warn", f"Blocked: {plan.reason}")
            return
        update = await _read_update_status(run)
        if update.state == "in_progress":
            await run.set_status(previous, phase_detail="Firmware update in progress on the UPS")
            await run.emit("info", f"A firmware update is in progress on the UPS: {update.text}")
            return
        image = plan.steps[0]
        if await _file_on_card(run, image.filename):
            await run.set_status("completed", phase_detail=f"{image.filename} on the NMC")
            await run.emit("success", f"{image.filename} is on the NMC; ready to activate")
        else:
            await run.set_status("pending", phase_detail="Firmware not on the NMC")
            await run.emit("warn", f"{image.filename} is not in {nmc_cli.REMOTE_DIR} on the NMC; run Transfer")
        if result.outcome != READY:
            await run.emit("warn", f"Pre-checks would stop this UPS: {result.reason}")
    except Exception as exc:
        await run.set_status(previous, f"Status check could not complete: {exc}")
        await run.emit("error", f"Status check could not complete: {exc}")
    finally:
        await run.disconnect()


_PHASE_HANDLERS = {
    "prestage": device_prestage,
    "transfer": device_transfer,
    "activate": device_activate,
    "verify": device_verify,
    "verify_prestage": device_check_status,
}


async def run_device_phase(
    phase: str, campaign_id: int, dev: dict, credentials: dict, image_map: Any, options: dict
) -> None:
    handler = _PHASE_HANDLERS.get(phase)
    if handler is None:
        raise ValueError(f"Unsupported phase for a UPS: {phase}")
    await handler(campaign_id, dev, credentials, image_map, options)


# ═════════════════════════════════════════════════════════════════════════════
# Logic Reset confirmation
# ═════════════════════════════════════════════════════════════════════════════


async def confirm_logic_reset(campaign_id: int, device: dict, user: str) -> dict:
    """Record that a person did the Logic Reset on a Smart-UPS Ultra.

    Raises ValueError when the device is not waiting for one.
    """
    waiting = device.get("prestage_status") == WAITING_STATUS or device.get("phase") == LOGIC_RESET_PHASE
    if not waiting and not needs_logic_reset(device.get("ups_id")):
        raise ValueError("This device does not need a Logic Reset confirmation")
    confirmed_at = _now()
    fields: dict[str, Any] = {
        "logic_reset_confirmed_by": user,
        "logic_reset_confirmed_at": confirmed_at,
        "phase": "logic_reset_confirmed",
        "phase_detail": f"Logic Reset confirmed by {user}",
    }
    statuses: dict[str, str] = {}
    for key in ("prestage_status", "transfer_status", "activate_status"):
        if device.get(key) == WAITING_STATUS:
            statuses[key] = "completed" if key == "prestage_status" else "pending"
    await db.update_upgrade_device(device["id"], **fields, **statuses, error_message="")
    await _up()._emit_device_status(campaign_id, device["id"], **statuses, error_message="")
    await _up()._emit(
        campaign_id,
        device["id"],
        "info",
        f"Logic Reset confirmed by {user}; Transfer and Activate may run",
        host=device.get("ip_address", ""),
    )
    return {"confirmed_by": user, "confirmed_at": confirmed_at, **statuses}


__all__ = [
    "IMAGE_PLATFORM",
    "MANUAL_STATUS",
    "WAITING_STATUS",
    "UploadedFirmware",
    "campaign_mix_error",
    "confirm_logic_reset",
    "is_ups_device",
    "prepare_uploaded_image",
    "run_device_phase",
]
