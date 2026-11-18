"""APC Smart-UPS phases of the Upgrades tool (netcontrol.integrations.apc.upgrade).

The NMC session is a fake: each CLI command returns invented output in the
documented ``Key: value`` / ``E000: Success`` shape (modelled on the NMC
CLI documentation, not captured from a device). The upgrade_devices rows
live in a dict, so these tests need no database.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest
from netcontrol.integrations.apc import upgrade as apc
from netcontrol.routes import upgrades

IDLE = "E000: Success\nStatus: No firmware update in progress\n"  # as an NMC3 answers
RUNNING = "E000: Success\nStatus: Updating UPS firmware (40%)\n"
INSTALL_OK = "E000: Success\nFirmware update started\n"
NO_ALARMS = "E000: Success\nAlarmCount: 0\n"
ABOUT_NMC2 = "E000: Success\nApplication Module\n---\nName: sumx\nVersion: v6.9.6\n"
ABOUT_NMC3 = "E000: Success\nApplication Module\n---\nName: su\nVersion: v2.6.0.1\n"


def upsabout(version: str, ups_id: str = "1025", prefix: str = "SRT") -> str:
    return (
        "E000: Success\n"
        f"Model: Smart-UPS {prefix} 3000\nSKU: {prefix}3KXLI\nSerial Number: TEST0000001\n"
        f"Firmware Revision: UPS {version} (ID{ups_id})\nID: {ups_id}\n"
    )


class FakeNmc:
    """Stand-in for the Netmiko apc_aos session.

    ``responses`` maps a command to its output, or to a list consumed in
    order (the last entry repeats). ``tmp_files`` is what ``dir`` lists.
    """

    def __init__(self, responses: dict[str, object], tmp_files: set[str] | None = None) -> None:
        self.responses = responses
        self.tmp_files = set(tmp_files or ())
        self.commands: list[str] = []
        self.disconnected = False

    def send_command(self, command: str, **_: object) -> str:
        self.commands.append(command)
        if command == "dir":
            return "E000: Success\n" + "\n".join(f"-rw- 1 apc apc 3145728 {name}" for name in sorted(self.tmp_files))
        if command == "cd /tmp":
            return "E000: Success\n"
        value = self.responses.get(command, "E000: Success\n")
        if isinstance(value, list):
            value = value.pop(0) if len(value) > 1 else value[0]
        if callable(value):
            return value()
        return str(value)

    def disconnect(self) -> None:
        self.disconnected = True


class Harness:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path, device: dict, library: list[str]) -> None:
        self.device = device
        self.events: list[tuple[str, str]] = []
        self.statuses: list[dict] = []
        self.on_target: list[str] = []
        self.scp: list[str] = []
        self.conn: FakeNmc | None = None
        self.connect_error: Exception | None = None
        self.library = [{"filename": name} for name in library]
        for name in library:
            (tmp_path / name).write_bytes(b"enc")

        async def fake_connect(ip, credentials, options, retries=1, device_type="cisco_xe"):
            assert device_type == "apc_aos"
            if self.connect_error:
                raise self.connect_error
            return self.conn

        async def fake_emit(campaign_id, device_id, level, message, host=""):
            self.events.append((level, message))

        async def fake_status(campaign_id, device_id, **statuses):
            self.statuses.append(statuses)

        async def fake_start(campaign_id, device_id, status_key, **fields):
            self.device.update({status_key: "running", "error_message": "", **fields})

        async def fake_on_target(campaign_id, device_id, running_version):
            self.on_target.append(running_version)
            for key in ("prestage_status", "transfer_status", "activate_status", "verify_status"):
                self.device[key] = "completed"

        async def fake_update(device_id, **fields):
            self.device.update(fields)
            return True

        async def fake_get_device(device_id):
            return dict(self.device)

        async def fake_images():
            return self.library

        def fake_scp(conn, local_path, remote_path, progress, timeout):
            self.scp.append(remote_path)
            conn.tmp_files.add(remote_path.rsplit("/", 1)[1])

        monkeypatch.setattr(upgrades, "_connect_device", fake_connect)
        monkeypatch.setattr(upgrades, "_emit", fake_emit)
        monkeypatch.setattr(upgrades, "_emit_device_status", fake_status)
        monkeypatch.setattr(upgrades, "_start_device_phase", fake_start)
        monkeypatch.setattr(upgrades, "_mark_device_on_target_version", fake_on_target)
        monkeypatch.setattr(upgrades, "_local_image_path", lambda name: str(tmp_path / name))
        monkeypatch.setattr(apc.db, "update_upgrade_device", fake_update)
        monkeypatch.setattr(apc.db, "get_upgrade_device", fake_get_device)
        monkeypatch.setattr(apc.db, "get_all_upgrade_images", fake_images)
        monkeypatch.setattr(apc, "_scp_put", fake_scp)
        monkeypatch.setattr(apc, "POLL_INTERVAL_SECONDS", 0)

    def messages(self, level: str | None = None) -> str:
        return "\n".join(m for lvl, m in self.events if level is None or lvl == level)

    async def run(self, phase: str, image_map: dict | None = None) -> None:
        await apc.run_device_phase(
            phase,
            1,
            self.device,
            {"username": "nmc-user", "password": "pw", "secret": ""},
            image_map if image_map is not None else {"1025": "SRT1025UPS_15-0.enc"},
            {"retries": 0},
        )


@pytest.fixture
def device() -> dict:
    return {
        "id": 7,
        "campaign_id": 1,
        "host_id": 3,
        "ip_address": "192.0.2.10",
        "prestage_status": "pending",
        "transfer_status": "pending",
        "activate_status": "pending",
        "verify_status": "pending",
        "target_image": "",
        "error_message": "",
    }


@pytest.fixture
def harness_factory(monkeypatch, tmp_path, device) -> Callable[..., Harness]:
    def make(responses: dict[str, object], *, tmp_files=(), library=("SRT1025UPS_15-0.enc",)) -> Harness:
        harness = Harness(monkeypatch, tmp_path, device, list(library))
        harness.conn = FakeNmc(responses, set(tmp_files))
        return harness

    return make


def base_responses(**extra: object) -> dict[str, object]:
    responses: dict[str, object] = {
        "upsabout": upsabout("12.4"),
        "about": ABOUT_NMC2,
        "alarmcount": NO_ALARMS,
        "upsfwupdate -status": IDLE,
    }
    responses.update(extra)
    return responses


# ── Prestage ─────────────────────────────────────────────────────────────────


async def test_prestage_passes_and_records_the_ups(harness_factory, device):
    h = harness_factory(base_responses())
    await h.run("prestage")
    assert device["prestage_status"] == "completed"
    assert device["ups_id"] == "1025"
    assert device["current_version"] == "12.4"
    assert device["model"] == "SRT3KXLI"
    assert device["target_image"] == "SRT1025UPS_15-0.enc"
    assert "Pre-checks passed; will install SRT1025UPS_15-0.enc" in h.messages("success")
    assert h.conn is not None and h.conn.disconnected
    # Pre-checks never change anything on the card.
    assert not any(c.startswith("upsfwupdate -install") for c in h.conn.commands)


async def test_prestage_blocks_on_active_alarms(harness_factory, device):
    h = harness_factory(base_responses(alarmcount="E000: Success\nAlarmCount: 2\n"))
    await h.run("prestage")
    assert device["prestage_status"] == "failed"
    assert device["error_message"].startswith("Blocked: 2 active alarm(s)")


async def test_prestage_blocks_when_no_image_matches(harness_factory, device):
    h = harness_factory(base_responses())
    await h.run("prestage", {"1030": "SRT1030UPS_16-0.enc"})
    assert device["prestage_status"] == "failed"
    assert "No image in this campaign is for UPS ID 1025" in device["error_message"]


async def test_prestage_1225_is_manual(harness_factory, device):
    h = harness_factory(base_responses(upsabout=upsabout("17.0", "1225", "SRYL")))
    await h.run("prestage", {"1225": "SRYL1225UPS_18-0.enc"})
    assert device["prestage_status"] == "manual"
    assert device["error_message"].startswith("Manual update required")


async def test_prestage_already_on_target_marks_every_step_done(harness_factory, device):
    h = harness_factory(base_responses(upsabout=upsabout("15.0")))
    await h.run("prestage")
    assert h.on_target == ["15.0"]
    assert device["verify_status"] == "completed"


async def test_connection_failure_fails_the_phase(harness_factory, device):
    h = harness_factory(base_responses())
    h.connect_error = ConnectionError("no route")
    await h.run("prestage")
    assert device["prestage_status"] == "failed"
    assert "Connection failed: no route" in device["error_message"]


async def test_logic_reset_waits_then_confirmation_releases_the_device(harness_factory, device):
    responses = base_responses(upsabout=upsabout("1.1", "1227", "SRTL"), about=ABOUT_NMC3)
    image_map = {"1227": "SRTL1227UPS_01-2.enc"}
    h = harness_factory(responses, library=["SRTL1227UPS_01-2.enc"])
    await h.run("prestage", image_map)
    assert device["prestage_status"] == "waiting"
    assert device["phase"] == "awaiting_logic_reset"

    # Transfer refuses to copy until the reset is confirmed.
    await h.run("transfer", image_map)
    assert device["transfer_status"] == "waiting"
    assert h.scp == []

    result = await apc.confirm_logic_reset(1, dict(device), "operator1")
    assert result["confirmed_by"] == "operator1"
    assert device["logic_reset_confirmed_by"] == "operator1"
    assert device["prestage_status"] == "completed"
    assert device["transfer_status"] == "pending"
    assert "Logic Reset confirmed by operator1" in h.messages("info")

    await h.run("transfer", image_map)
    assert device["transfer_status"] == "completed"
    assert h.scp == ["/tmp/SRTL1227UPS_01-2.enc"]


async def test_logic_reset_confirmation_is_refused_for_other_devices(device):
    device["ups_id"] = "1025"
    with pytest.raises(ValueError):
        await apc.confirm_logic_reset(1, device, "operator1")


# ── Transfer ─────────────────────────────────────────────────────────────────


async def test_transfer_copies_to_tmp_and_confirms_with_dir(harness_factory, device):
    h = harness_factory(base_responses())
    await h.run("transfer")
    assert h.scp == ["/tmp/SRT1025UPS_15-0.enc"]
    assert device["transfer_status"] == "completed"
    assert h.conn is not None
    assert h.conn.commands.index("cd /tmp") < h.conn.commands.index("dir")


async def test_transfer_fails_when_the_file_never_appears(harness_factory, device, monkeypatch):
    h = harness_factory(base_responses())

    def broken_scp(conn, local_path, remote_path, progress, timeout):
        raise OSError("scp: protocol error")

    monkeypatch.setattr(apc, "_scp_put", broken_scp)
    await h.run("transfer")
    assert device["transfer_status"] == "failed"
    assert "SCP failed: scp: protocol error" in device["error_message"]
    assert "SCP is enabled on the NMC" in device["error_message"]


# ── Activate ─────────────────────────────────────────────────────────────────


async def test_activate_installs_waits_and_verifies(harness_factory, device):
    responses = base_responses(
        upsabout=[upsabout("12.4"), upsabout("15.0")],
        **{
            "upsfwupdate -status": [IDLE, RUNNING, RUNNING, IDLE],
            'upsfwupdate -install -file "/tmp/SRT1025UPS_15-0.enc"': INSTALL_OK,
        },
    )
    h = harness_factory(responses, tmp_files={"SRT1025UPS_15-0.enc"})
    await h.run("activate")
    assert h.on_target == ["15.0"]
    assert h.scp == []  # already on the card
    assert "Firmware update complete" in h.messages("success")
    assert "The UPS output stays on" in h.messages("info")


async def test_activate_copies_the_file_when_it_is_missing(harness_factory, device):
    responses = base_responses(
        upsabout=[upsabout("12.4"), upsabout("15.0")],
        **{'upsfwupdate -install -file "/tmp/SRT1025UPS_15-0.enc"': INSTALL_OK},
    )
    h = harness_factory(responses)
    await h.run("activate")
    assert h.scp == ["/tmp/SRT1025UPS_15-0.enc"]
    assert h.on_target == ["15.0"]


async def test_activate_unchanged_version_is_transferred_but_not_installed(harness_factory, device):
    responses = base_responses(**{'upsfwupdate -install -file "/tmp/SRT1025UPS_15-0.enc"': INSTALL_OK})
    h = harness_factory(responses, tmp_files={"SRT1025UPS_15-0.enc"})
    await h.run("activate")
    assert device["activate_status"] == "failed"
    assert "transferred but not installed" in device["error_message"]
    assert "FAQ000258690" in device["error_message"]
    assert h.on_target == []


async def test_activate_output_off_refusal_is_manual(harness_factory, device):
    responses = base_responses(
        **{
            'upsfwupdate -install -file "/tmp/SRT1025UPS_15-0.enc"': (
                "E100: Command Failed\nUPS output must be OFF to update this model\n"
            )
        }
    )
    h = harness_factory(responses, tmp_files={"SRT1025UPS_15-0.enc"})
    await h.run("activate")
    assert device["activate_status"] == "manual"
    assert "never turns UPS output off" in device["error_message"]


async def test_activate_refused_file(harness_factory, device):
    responses = base_responses(
        **{'upsfwupdate -install -file "/tmp/SRT1025UPS_15-0.enc"': "E100: Command Failed\nWrong UPS ID\n"}
    )
    h = harness_factory(responses, tmp_files={"SRT1025UPS_15-0.enc"})
    await h.run("activate")
    assert device["activate_status"] == "failed"
    assert "The NMC refused SRT1025UPS_15-0.enc" in device["error_message"]


async def test_activate_refuses_while_another_update_runs(harness_factory, device):
    h = harness_factory(base_responses(**{"upsfwupdate -status": RUNNING}), tmp_files={"SRT1025UPS_15-0.enc"})
    await h.run("activate")
    assert device["activate_status"] == "failed"
    assert "already running" in device["error_message"]


async def test_activate_times_out(harness_factory, device, monkeypatch):
    responses = base_responses(
        **{
            "upsfwupdate -status": [IDLE, RUNNING],
            'upsfwupdate -install -file "/tmp/SRT1025UPS_15-0.enc"': INSTALL_OK,
        }
    )
    h = harness_factory(responses, tmp_files={"SRT1025UPS_15-0.enc"})
    monkeypatch.setattr(apc, "install_timeout_seconds", lambda image, model="": 0)
    await h.run("activate")
    assert device["activate_status"] == "failed"
    assert "did not finish within" in device["error_message"]


async def test_activate_device_cancel_stops_watching(harness_factory, device):
    def running_then_cancelled() -> str:
        # The operator cancels the device (devices/cancel) while the install runs.
        device["activate_status"] = "cancelled"
        return RUNNING

    responses = base_responses(
        **{
            "upsfwupdate -status": [IDLE, running_then_cancelled],
            'upsfwupdate -install -file "/tmp/SRT1025UPS_15-0.enc"': INSTALL_OK,
        }
    )
    h = harness_factory(responses, tmp_files={"SRT1025UPS_15-0.enc"})
    await h.run("activate")
    assert device["activate_status"] == "cancelled"
    assert "cannot be aborted" in h.messages("warn")
    assert h.on_target == []


async def test_activate_task_cancel_reports_the_install_cannot_be_aborted(harness_factory, device, monkeypatch):
    responses = base_responses(
        **{
            "upsfwupdate -status": [IDLE, RUNNING],
            'upsfwupdate -install -file "/tmp/SRT1025UPS_15-0.enc"': INSTALL_OK,
        }
    )
    h = harness_factory(responses, tmp_files={"SRT1025UPS_15-0.enc"})
    monkeypatch.setattr(apc, "POLL_INTERVAL_SECONDS", 30)
    task = asyncio.create_task(h.run("activate"))
    for _ in range(200):
        await asyncio.sleep(0.01)
        if "Install started" in h.messages("info"):
            break
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert "cannot be aborted" in h.messages("warn")
    assert h.conn is not None and h.conn.disconnected


async def test_activate_1001_runs_both_steps(harness_factory, device):
    responses = base_responses(
        upsabout=[upsabout("1.0", "1001"), upsabout("2.9", "1013"), upsabout("15.0", "1013")],
        **{
            'upsfwupdate -install -file "/tmp/SRT1001UPS_02-9.enc"': INSTALL_OK,
            'upsfwupdate -install -file "/tmp/SRT1013UPS_15-0.enc"': INSTALL_OK,
        },
    )
    h = harness_factory(responses, library=["SRT1001UPS_02-9.enc", "SRT1013UPS_15-0.enc"])
    await h.run("activate", {"1001": "SRT1001UPS_02-9.enc"})
    assert h.scp == ["/tmp/SRT1001UPS_02-9.enc", "/tmp/SRT1013UPS_15-0.enc"]
    assert h.on_target == ["15.0"]
    assert "Step 2/2: SRT1013UPS_15-0.enc" in h.messages("info")


async def test_activate_1001_blocks_without_the_second_file(harness_factory, device):
    h = harness_factory(base_responses(upsabout=upsabout("1.0", "1001")), library=["SRT1001UPS_02-9.enc"])
    await h.run("activate", {"1001": "SRT1001UPS_02-9.enc"})
    assert device["activate_status"] == "failed"
    assert "SRT1013UPS_15-0.enc" in device["error_message"]


# ── Verify and Check status ──────────────────────────────────────────────────


async def test_verify(harness_factory, device):
    device["target_image"] = "SRT1025UPS_15-0.enc"
    h = harness_factory(base_responses(upsabout=upsabout("15.0")))
    await h.run("verify")
    assert h.on_target == ["15.0"]

    device["verify_status"] = "pending"
    h2 = harness_factory(base_responses())
    await h2.run("verify")
    assert device["verify_status"] == "failed"
    assert device["activate_status"] == "failed"
    assert "Version mismatch" in device["error_message"]


async def test_verify_without_target(harness_factory, device):
    h = harness_factory(base_responses())
    await h.run("verify")
    assert device["verify_status"] == "failed"
    assert "run Prestage first" in device["error_message"]


async def test_check_status(harness_factory, device):
    h = harness_factory(base_responses(), tmp_files={"SRT1025UPS_15-0.enc"})
    await h.run("verify_prestage")
    assert device["transfer_status"] == "completed"
    assert h.conn is not None
    assert not any(c.startswith("upsfwupdate -install") for c in h.conn.commands)

    h2 = harness_factory(base_responses())
    await h2.run("verify_prestage")
    assert device["transfer_status"] == "pending"

    h3 = harness_factory(base_responses(upsabout=upsabout("15.0")))
    await h3.run("verify_prestage")
    assert h3.on_target == ["15.0"]


async def test_check_status_keeps_previous_status_when_unreachable(harness_factory, device):
    device["transfer_status"] = "completed"
    h = harness_factory(base_responses())
    h.connect_error = ConnectionError("timeout")
    await h.run("verify_prestage")
    assert device["transfer_status"] == "completed"
    assert "could not complete" in device["error_message"]


async def test_unknown_phase_is_rejected(device):
    with pytest.raises(ValueError):
        await apc.run_device_phase("commit", 1, device, {}, {}, {})


# ── Campaign wiring ──────────────────────────────────────────────────────────


async def test_campaign_mix_error(monkeypatch):
    hosts = {1: {"id": 1, "device_type": "apc_ups"}, 2: {"id": 2, "device_type": "cisco_xe"}}

    async def fake_hosts(ids):
        return [hosts[i] for i in ids if i in hosts]

    monkeypatch.setattr(apc.db, "get_hosts_by_ids", fake_hosts)
    assert await apc.campaign_mix_error([], []) is None
    assert await apc.campaign_mix_error([1], []) is None
    assert await apc.campaign_mix_error([2], ["198.51.100.4"]) is None
    assert "not both" in (await apc.campaign_mix_error([1, 2], []) or "")
    assert "not both" in (await apc.campaign_mix_error([1], ["198.51.100.4"]) or "")


async def test_run_phase_dispatches_ups_devices(monkeypatch):
    ups = {"id": 1, "host_id": 11, "ip_address": "192.0.2.11", "prestage_status": "pending"}
    switch = {"id": 2, "host_id": 12, "ip_address": "192.0.2.12", "prestage_status": "pending"}
    calls: list[tuple[str, int]] = []

    async def fake_device_type(dev):
        return "apc_ups" if dev["id"] == 1 else "cisco_xe"

    async def fake_ups_phase(phase, campaign_id, dev, credentials, image_map, options):
        calls.append(("ups", dev["id"]))

    async def fake_prestage(campaign_id, dev, credentials, image_map, options):
        calls.append(("cisco", dev["id"]))

    async def noop(*_args, **_kwargs):
        return None

    async def fake_get_device(device_id):
        return {"id": device_id}

    async def fake_get_devices(campaign_id):
        return [ups, switch]

    monkeypatch.setattr(upgrades, "_resolve_device_type", fake_device_type)
    monkeypatch.setattr(apc, "run_device_phase", fake_ups_phase)
    monkeypatch.setattr(upgrades, "_device_prestage", fake_prestage)
    monkeypatch.setattr(upgrades, "_emit", noop)
    monkeypatch.setattr(upgrades, "_broadcast_upgrade_event", noop)
    monkeypatch.setattr(upgrades.db, "get_upgrade_device", fake_get_device)
    monkeypatch.setattr(upgrades.db, "get_upgrade_devices", fake_get_devices)
    monkeypatch.setattr(upgrades.db, "update_upgrade_campaign", noop)

    await upgrades._run_phase(1, "prestage", [ups, switch], {}, [], {})
    assert sorted(calls) == [("cisco", 2), ("ups", 1)]
