"""APC Smart-UPS firmware rules and NMC CLI parsing.

The CLI outputs below are invented. They are modelled on the documented
NMC command line format (``Key: value`` lines, an ``E000: Success`` status
line, ``about`` sections with a dashed rule), not captured from a device.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from netcontrol.integrations.apc import firmware, nmc_cli
from netcontrol.integrations.apc.firmware import (
    BLOCKED,
    MANUAL,
    READY,
    UP_TO_DATE,
    WAITING_LOGIC_RESET,
    UpsFirmwareFile,
    evaluate_prechecks,
    parse_firmware_filename,
    plan_update,
)
from netcontrol.integrations.apc.upgrade import prepare_uploaded_image


def _f(name: str) -> UpsFirmwareFile:
    parsed = parse_firmware_filename(name)
    assert parsed is not None, name
    return parsed


# ── File names ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "prefix", "ups_id", "version"),
    [
        ("SRT1025UPS_15-0.enc", "SRT", "1025", "15.0"),
        ("SRTL1227UPS_01-2.enc", "SRTL", "1227", "1.2"),
        ("SRYL1225UPS_18-0.enc", "SRYL", "1225", "18.0"),
        ("smt1018ups_09-3.ENC", "SMT", "1018", "9.3"),
        ("SCL1040UPS_02-1.enc", "SCL", "1040", "2.1"),
    ],
)
def test_parse_firmware_filename(name, prefix, ups_id, version):
    parsed = parse_firmware_filename(name)
    assert parsed is not None
    assert (parsed.prefix, parsed.ups_id, parsed.version) == (prefix, ups_id, version)


@pytest.mark.parametrize(
    "name",
    ["", None, "cat9k_iosxe.17.09.04a.SPA.bin", "SRT125UPS_15-0.enc", "../SRT1025UPS_15-0.enc", "SRT1025UPS_15.enc"],
)
def test_parse_firmware_filename_rejects_other_names(name):
    assert parse_firmware_filename(name) is None
    assert not firmware.is_firmware_filename(name)


def test_versions_and_ids():
    assert firmware.ups_version("UPS 09.3 (ID18)") == "9.3"
    assert firmware.ups_version("15-0") == "15.0"
    assert firmware.ups_version("unknown") == ""
    assert firmware.normalize_ups_id("01025") == "1025"
    assert firmware.normalize_ups_id(None) == ""


def test_install_timeout_is_longer_for_modular_ultra():
    assert firmware.install_timeout_seconds(_f("SRT1025UPS_15-0.enc")) == 30 * 60
    assert firmware.install_timeout_seconds(_f("SRYL1230UPS_18-0.enc")) == 45 * 60
    assert firmware.install_timeout_seconds(None, model="SRYL20KIMB") == 45 * 60


# ── Plan ─────────────────────────────────────────────────────────────────────


def test_plan_picks_the_newest_image_for_the_ups_id():
    files = [_f("SRT1025UPS_14-1.enc"), _f("SRT1025UPS_15-0.enc"), _f("SRT1030UPS_16-0.enc")]
    plan = plan_update("1025", "12.4", files)
    assert plan.outcome == READY
    assert [s.filename for s in plan.steps] == ["SRT1025UPS_15-0.enc"]


def test_plan_blocks_when_no_image_matches_the_ups_id():
    plan = plan_update("1025", "12.4", [_f("SRT1030UPS_16-0.enc")])
    assert plan.outcome == BLOCKED
    assert "UPS ID 1025" in plan.reason and "1030" in plan.reason


def test_plan_never_downgrades_or_reinstalls():
    older = plan_update("1025", "15.0", [_f("SRT1025UPS_14-1.enc")])
    assert older.outcome == BLOCKED and "never downgrades" in older.reason
    same = plan_update("1025", "15.0", [_f("SRT1025UPS_15-0.enc")])
    assert same.outcome == UP_TO_DATE
    assert same.target is not None and same.target.filename == "SRT1025UPS_15-0.enc"


def test_plan_blocks_without_id_or_version():
    assert plan_update("", "15.0", []).outcome == BLOCKED
    assert plan_update("1025", "", [_f("SRT1025UPS_15-0.enc")]).outcome == BLOCKED


def test_plan_1225_is_manual():
    plan = plan_update("1225", "17.0", [_f("SRYL1225UPS_18-0.enc")])
    assert plan.outcome == MANUAL
    assert "FAQ000261838" in plan.reason


def test_plan_output_off_ids_are_manual(monkeypatch):
    monkeypatch.setitem(firmware.OUTPUT_OFF_REQUIRED_IDS, "1025", "")
    plan = plan_update("1025", "12.4", [_f("SRT1025UPS_15-0.enc")])
    assert plan.outcome == MANUAL
    assert "never turns UPS output off" in plan.reason


def test_plan_1001_two_steps_from_the_library():
    library = [_f("SRT1001UPS_02-9.enc"), _f("SRT1013UPS_15-0.enc")]
    plan = plan_update("1001", "1.0", [], library)
    assert plan.outcome == READY
    assert [s.filename for s in plan.steps] == ["SRT1001UPS_02-9.enc", "SRT1013UPS_15-0.enc"]
    assert plan.target is not None and plan.target.ups_id == "1013"


def test_plan_1001_names_the_missing_file():
    plan = plan_update("1001", "1.0", [], [_f("SRT1013UPS_15-0.enc")])
    assert plan.outcome == BLOCKED
    assert "SRT1001UPS_02-9.enc" in plan.reason
    plan = plan_update("1001", "1.0", [], [_f("SRT1001UPS_02-9.enc")])
    assert plan.outcome == BLOCKED
    assert "SRT1013UPS_15-0.enc" in plan.reason


def test_plan_1013_after_the_first_step_finds_the_library_image():
    plan = plan_update("1013", "2.9", [], [_f("SRT1001UPS_02-9.enc"), _f("SRT1013UPS_15-0.enc")])
    assert plan.outcome == READY
    assert [s.filename for s in plan.steps] == ["SRT1013UPS_15-0.enc"]


# ── Pre-checks ───────────────────────────────────────────────────────────────


def _pre(**overrides):
    kwargs = {
        "ups_id": "1025",
        "running_version": "12.4",
        "nmc_generation": "nmc2",
        "nmc_app_version": "6.9.6",
        "active_alarms": 0,
        "campaign_files": [_f("SRT1025UPS_15-0.enc")],
    }
    kwargs.update(overrides)
    return evaluate_prechecks(**kwargs)


def test_prechecks_pass():
    result = _pre()
    assert result.outcome == READY
    assert result.reason == ""


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"active_alarms": 2}, "2 active alarm(s)"),
        ({"active_alarms": None}, "active alarm count"),
        ({"nmc_app_version": "6.3.2"}, "older than v6.4.0"),
        ({"nmc_generation": "nmc3", "nmc_app_version": "0.9"}, "older than v1.0"),
        ({"nmc_generation": ""}, "Could not identify the NMC"),
        ({"nmc_app_version": ""}, "application firmware version"),
    ],
)
def test_prechecks_block(overrides, fragment):
    result = _pre(**overrides)
    assert result.outcome == BLOCKED
    assert fragment in result.reason


def test_prechecks_smart_ups_ultra_needs_nmc_2_5_4_4_and_a_logic_reset():
    files = [_f("SRTL1227UPS_01-2.enc")]
    base = {"ups_id": "1227", "running_version": "1.1", "campaign_files": files}
    assert _pre(**base, nmc_generation="nmc2", nmc_app_version="6.9.6").outcome == BLOCKED
    blocked = _pre(**base, nmc_generation="nmc3", nmc_app_version="2.5.4.3")
    assert blocked.outcome == BLOCKED and "2.5.4.4" in blocked.reason
    waiting = _pre(**base, nmc_generation="nmc3", nmc_app_version="2.5.4.4")
    assert waiting.outcome == WAITING_LOGIC_RESET
    assert "Logic Reset" in waiting.reason
    ready = _pre(**base, nmc_generation="nmc3", nmc_app_version="2.6.0.1", logic_reset_confirmed=True)
    assert ready.outcome == READY


def test_prechecks_report_plan_outcomes_first():
    assert _pre(ups_id="1225", active_alarms=3).outcome == MANUAL
    assert _pre(running_version="15.0", active_alarms=3).outcome == UP_TO_DATE


# ── NMC CLI parsing ──────────────────────────────────────────────────────────

UPSABOUT = """apc>upsabout
E000: Success
Model: Smart-UPS SRT 3000
SKU: SRT3KXLI
Serial Number: TEST0000001
Manufacture Date: 01/02/2020
Firmware Revision: UPS 12.4 (ID1025)
ID: 1025
Apparent Power Rating: 3000 VA
"""

UPSABOUT_ID_IN_REVISION = """E000: Success
Model: Smart-UPS 1500
SKU: SMT1500I
Firmware Revision: UPS 09.3 (ID18)
"""

# The layout a user confirmed on an SRT card (values invented): the status
# line first, no ID line, the UPS ID only inside the firmware revision, and
# empty fields left blank.
UPSABOUT_SRT_CONFIRMED = """E000: Success
Model: Smart-UPS SRT 6000
Serial Number:
Firmware Revision: UPS 11.7 (ID1022)
Manufacture Date:
Apparent Power Rating: 6000 VA
"""

ABOUT_NMC2 = """apc>about
E000: Success
Hardware Factory
---------------
Model Number:           AP9631
Serial Number:          TEST0000002
Hardware Revision:      05

Application Module
---------------
Name:                   sumx
Version:                v6.9.6
Date:                   01/01/2022

APC OS(AOS)
---------------
Name:                   aos
Version:                v6.9.6
"""

ABOUT_NMC3 = """E000: Success
Hardware Factory
---------------
Model Number: AP9641
Application Module
---------------
Name: su
Version: v2.5.4.4
"""


def test_parse_upsabout():
    about = nmc_cli.parse_upsabout(UPSABOUT)
    assert about.ups_id == "1025"
    assert about.version == "12.4"
    assert about.sku == "SRT3KXLI"
    assert about.model == "Smart-UPS SRT 3000"
    fallback = nmc_cli.parse_upsabout(UPSABOUT_ID_IN_REVISION)
    assert (fallback.ups_id, fallback.version) == ("18", "9.3")


def test_parse_upsabout_confirmed_srt_layout():
    about = nmc_cli.parse_upsabout(UPSABOUT_SRT_CONFIRMED)
    assert (about.ups_id, about.version) == ("1022", "11.7")
    assert about.model == "Smart-UPS SRT 6000"
    assert about.serial == ""
    assert nmc_cli.command_error(UPSABOUT_SRT_CONFIRMED) is None


def test_parse_about():
    nmc2 = nmc_cli.parse_about(ABOUT_NMC2)
    assert (nmc2.generation, nmc2.app_name, nmc2.app_version, nmc2.model_number) == (
        "nmc2",
        "sumx",
        "6.9.6",
        "AP9631",
    )
    nmc3 = nmc_cli.parse_about(ABOUT_NMC3)
    assert (nmc3.generation, nmc3.app_version) == ("nmc3", "2.5.4.4")
    by_model = nmc_cli.parse_about("Model Number: AP9641\nSomething: else\n")
    assert by_model.generation == "nmc3"
    assert nmc_cli.parse_about("").generation == ""


def test_parse_about_card_firmware():
    # The card's firmware is its AOS release; the application module's when
    # the output has no AOS section (one image on an NMC3).
    nmc2 = nmc_cli.parse_about(ABOUT_NMC2)
    assert (nmc2.aos_version, nmc2.firmware) == ("6.9.6", "6.9.6")
    differing = nmc_cli.parse_about(
        "Application Module\n---\nName: sumx\nVersion: v6.9.6\n\nAPC OS(AOS)\n---\nName: aos\nVersion: v6.9.8\n"
    )
    assert (differing.app_version, differing.aos_version, differing.firmware) == ("6.9.6", "6.9.8", "6.9.8")
    by_title = nmc_cli.parse_about("APC OS(AOS)\n---\nVersion: v7.0.4\n")
    assert by_title.firmware == "7.0.4"
    nmc3 = nmc_cli.parse_about(ABOUT_NMC3)
    assert (nmc3.aos_version, nmc3.firmware) == ("", "2.5.4.4")
    assert nmc_cli.parse_about("E101: Command Not Found\n").firmware == ""


@pytest.mark.parametrize(
    ("output", "count"),
    [
        ("E000: Success\nAlarmCount: 0\n", 0),
        ("E000: Success\nActive Alarms: 3\n", 3),
        ("E000: Success\n2\n", 2),
        ("E102: Parameter Error\n", None),
        ("nothing useful", None),
    ],
)
def test_parse_alarm_count(output, count):
    assert nmc_cli.parse_alarm_count(output) == count


def test_parse_about_confirmed_embedded_nmc3():
    # The layout a user confirmed on an embedded NMC3 (values invented): no
    # AP964x model number, blank fields, the application module named "su".
    about = nmc_cli.parse_about(
        "Hardware Factory\n---------------\nModel Number: 0N-0000\nSerial Number: \nHardware Revision: 3\n"
        "Manufacture Date: \nMAC Address: \nManagement Uptime: \n\n"
        "Application Module\n---------------\nName: su\nVersion: v2.0.0.5\nDate: Jan 01 2021\nTime: 10:00:00\n"
    )
    assert (about.generation, about.app_name, about.app_version) == ("nmc3", "su", "2.0.0.5")


@pytest.mark.parametrize(
    "idle_text",
    [
        "No firmware update is in progress",  # the Schneider FAQ wording
        "No firmware update in progress",  # confirmed on an NMC3 (su v2.0)
    ],
)
def test_parse_update_status_idle_wordings(idle_text):
    assert nmc_cli.parse_update_status(f"E000: Success\nStatus: {idle_text}\n").state == "idle"


def test_parse_update_status():
    idle = nmc_cli.parse_update_status("E000: Success\nStatus: No firmware update is in progress\n")
    assert idle.state == "idle"
    running = nmc_cli.parse_update_status("E000: Success\nStatus: Updating UPS (45%)\n")
    assert running.state == "in_progress" and "45%" in running.text
    failed = nmc_cli.parse_update_status("E000: Success\nStatus: Update failed\n")
    assert failed.state == "failed"
    error = nmc_cli.parse_update_status("E101: Command Not Found\n")
    assert error.state == "error" and error.text.startswith("E101")


def test_parse_install_output():
    assert nmc_cli.parse_install_output("E000: Success\nFirmware update started\n").outcome == "started"
    off = nmc_cli.parse_install_output("E100: Command Failed\nUPS output must be turned off before updating\n")
    assert off.outcome == "output_off"
    refused = nmc_cli.parse_install_output("E100: Command Failed\nFirmware file does not match UPS ID\n")
    assert refused.outcome == "refused" and "UPS ID" in refused.message
    assert nmc_cli.parse_install_output("Error: invalid file").outcome == "refused"
    assert nmc_cli.parse_install_output("").outcome == "started"


def test_commands_and_status_lines():
    assert nmc_cli.install_command("SRT1025UPS_15-0.enc") == 'upsfwupdate -install -file "/tmp/SRT1025UPS_15-0.enc"'
    with pytest.raises(ValueError):
        nmc_cli.install_command('x"; reboot; "')
    assert nmc_cli.command_error("E000: Success") is None
    assert nmc_cli.command_error("E001: Successfully Issued") is None
    assert nmc_cli.command_error("E102: Parameter Error") == "E102: Parameter Error"
    assert nmc_cli.command_error("no status line") is None
    listing = "E000: Success\n-rw-  1 apc apc 3145728 Jan 01 2024 SRT1025UPS_15-0.enc\n"
    assert nmc_cli.file_listed(listing, "SRT1025UPS_15-0.enc")
    assert not nmc_cli.file_listed(listing, "SRT1025UPS_15-0.en")
    assert nmc_cli.output_off_required("Turn the UPS output OFF first")
    assert not nmc_cli.output_off_required("output voltage normal")


# ── Upload (.enc / .zip) ─────────────────────────────────────────────────────


def _zip(path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)


def test_prepare_enc_upload(tmp_path):
    path = tmp_path / "SRT1025UPS_15-0.enc"
    path.write_bytes(b"enc-bytes")
    upload = prepare_uploaded_image(str(path), path.name, str(tmp_path))
    assert upload is not None
    assert (upload.filename, upload.size, upload.image.ups_id) == ("SRT1025UPS_15-0.enc", 9, "1025")
    upload.commit()
    assert path.is_file()


def test_prepare_rejects_a_renamed_enc(tmp_path):
    path = tmp_path / "firmware.enc"
    path.write_bytes(b"x")
    with pytest.raises(ValueError, match="vendor file name"):
        prepare_uploaded_image(str(path), path.name, str(tmp_path))


def test_prepare_ignores_other_files(tmp_path):
    path = tmp_path / "cat9k_iosxe.17.09.04a.SPA.bin"
    path.write_bytes(b"x")
    assert prepare_uploaded_image(str(path), path.name, str(tmp_path)) is None
    archive = tmp_path / "other.zip"
    _zip(archive, {"readme.txt": b"hello"})
    assert prepare_uploaded_image(str(archive), archive.name, str(tmp_path)) is None


def test_prepare_extracts_the_enc_from_a_zip(tmp_path):
    archive = tmp_path / "upload.zip"
    _zip(archive, {"SRT1025UPS_15-0/SRT1025UPS_15-0.enc": b"enc-bytes", "SRT1025UPS_15-0/notes.txt": b"n"})
    upload = prepare_uploaded_image(str(archive), archive.name, str(tmp_path))
    assert upload is not None and upload.staged_path
    assert not (tmp_path / "SRT1025UPS_15-0.enc").exists()
    upload.commit()
    assert (tmp_path / "SRT1025UPS_15-0.enc").read_bytes() == b"enc-bytes"
    assert not archive.exists()
    assert upload.size == 9


def test_prepare_discard_removes_the_staged_file(tmp_path):
    archive = tmp_path / "upload.zip"
    _zip(archive, {"SRT1025UPS_15-0.enc": b"enc"})
    upload = prepare_uploaded_image(str(archive), archive.name, str(tmp_path))
    assert upload is not None
    upload.discard()
    assert sorted(p.name for p in tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("members", "fragment"),
    [
        ({"SRT1025UPS_15-0.enc": b"a", "SRT1030UPS_16-0.enc": b"b"}, "more than one .enc"),
        ({"../SRT1025UPS_15-0.enc": b"a"}, "unsafe path"),
        ({"/abs/SRT1025UPS_15-0.enc": b"a"}, "unsafe path"),
        ({"firmware.enc": b"a"}, "not named like UPS firmware"),
    ],
)
def test_prepare_rejects_bad_zips(tmp_path, members, fragment):
    archive = tmp_path / "upload.zip"
    _zip(archive, members)
    with pytest.raises(ValueError, match=fragment):
        prepare_uploaded_image(str(archive), archive.name, str(tmp_path))
    assert [p.name for p in tmp_path.iterdir()] == ["upload.zip"]


def test_prepare_rejects_oversize_and_broken_zips(tmp_path, monkeypatch):
    from netcontrol.integrations.apc import upgrade

    monkeypatch.setattr(upgrade, "MAX_FIRMWARE_FILE_BYTES", 4)
    archive = tmp_path / "upload.zip"
    _zip(archive, {"SRT1025UPS_15-0.enc": b"too-large"})
    with pytest.raises(ValueError, match="larger"):
        prepare_uploaded_image(str(archive), archive.name, str(tmp_path))
    broken = tmp_path / "broken.zip"
    broken.write_bytes(io.BytesIO(b"not a zip").getvalue())
    with pytest.raises(ValueError, match="not a readable zip"):
        prepare_uploaded_image(str(broken), broken.name, str(tmp_path))
