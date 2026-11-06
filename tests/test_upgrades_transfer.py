"""Campaign transfer: live SCP progress, preserving progress on edit, check status."""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db
from netcontrol.routes import upgrades

_TARGET = "cat9k_iosxe.17.15.05.SPA.bin"


def _mode_line(mode: str) -> str:
    """The ``show version | include INSTALL|BUNDLE`` line a Cat9k prints."""
    return f"*    1 41    C9300-48P          17.12.04          CAT9K_IOSXE           {mode}\n"


class _FakeConn:
    """Answers only the boot-mode command; other device I/O is stubbed."""

    def __init__(self, boot_mode: str = "INSTALL") -> None:
        self.boot_mode = boot_mode
        self.commands: list[str] = []

    def send_command(self, cmd: str, **kwargs) -> str:
        self.commands.append(cmd)
        return _mode_line(self.boot_mode) if "INSTALL|BUNDLE" in cmd else ""

    def disconnect(self) -> None:
        return None


def _patch_check(
    monkeypatch: pytest.MonkeyPatch,
    *,
    boot_mode: str = "INSTALL",
    running: str = "17.12.04",
    on_flash: bool = True,
    md5_ok: bool = True,
    expanded: bool = True,
    connect_error: Exception | None = None,
    local_image: str | None = "/images/x.bin",
) -> dict:
    """Stub device I/O for _device_verify_prestage; return the recorded device updates."""
    rec: dict = {"updates": {}, "md5_checked": False}

    async def update_upgrade_device(dev_id, **fields):
        rec["updates"].update(fields)

    async def noop(*args, **kwargs):
        return None

    async def connect(*args, **kwargs):
        if connect_error:
            raise connect_error
        return _FakeConn(boot_mode)

    async def detect_model(conn, ip):
        return "C9300-48P", running

    async def verify_md5(conn, name, dest, expected):
        rec["md5_checked"] = True
        return md5_ok

    async def unpacked(*args, **kwargs):
        return (True, None) if expanded else (False, "no .pkg files for 17.15.05")

    async def device_type(dev):
        return "cisco_xe"

    monkeypatch.setattr(db, "update_upgrade_device", update_upgrade_device)
    monkeypatch.setattr(upgrades, "_emit", noop)
    monkeypatch.setattr(upgrades, "_emit_device_status", noop)
    monkeypatch.setattr(upgrades, "_resolve_device_type", device_type)
    monkeypatch.setattr(upgrades, "_connect_device", connect)
    monkeypatch.setattr(upgrades, "_detect_model", detect_model)
    monkeypatch.setattr(upgrades, "_check_image_exists", lambda conn, name, dest: on_flash)
    monkeypatch.setattr(upgrades, "_local_image_path", lambda name: local_image)
    monkeypatch.setattr(upgrades, "_compute_md5", lambda path: "a" * 32)
    monkeypatch.setattr(upgrades, "_verify_md5_on_switch", verify_md5)
    monkeypatch.setattr(upgrades, "_verify_install_add_unpacked_files", unpacked)
    return rec


async def _run_check(transfer_status: str = "completed", options: dict | None = None) -> None:
    dev = {"id": 5, "ip_address": "10.9.0.1", "target_image": _TARGET, "transfer_status": transfer_status}
    await upgrades._device_verify_prestage(1, dev, {}, [], options or {})


@pytest.mark.asyncio
async def test_check_status_records_install_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch_check(monkeypatch)
    await _run_check(transfer_status="pending")
    assert rec["updates"]["boot_mode"] == "install"
    assert rec["updates"]["transfer_status"] == "completed"


@pytest.mark.asyncio
async def test_check_status_bundle_mode_fails_transfer_before_image_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch_check(monkeypatch, boot_mode="BUNDLE")
    await _run_check(transfer_status="completed")
    assert rec["updates"]["boot_mode"] == "bundle"
    assert rec["updates"]["transfer_status"] == "failed"
    assert "BUNDLE" in rec["updates"]["error_message"]
    assert rec["md5_checked"] is False


@pytest.mark.asyncio
async def test_check_status_bundle_mode_on_target_version_is_done(monkeypatch: pytest.MonkeyPatch) -> None:
    """Already upgraded (e.g. by hand in bundle mode): nothing left to block."""
    rec = _patch_check(monkeypatch, boot_mode="BUNDLE", running="17.15.05")
    await _run_check(transfer_status="pending")
    assert rec["updates"]["boot_mode"] == "bundle"
    assert rec["updates"]["transfer_status"] == "completed"
    assert rec["updates"]["verify_status"] == "completed"


@pytest.mark.asyncio
@pytest.mark.parametrize(("mode", "recorded", "blocked"), [("INSTALL", "install", False), ("BUNDLE", "bundle", True)])
async def test_boot_mode_gate_records_mode(
    monkeypatch: pytest.MonkeyPatch, mode: str, recorded: str, blocked: bool
) -> None:
    rec = _patch_check(monkeypatch)
    statuses: list[dict] = []

    async def emit_status(campaign_id, dev_id, **fields):
        statuses.append(fields)

    monkeypatch.setattr(upgrades, "_emit_device_status", emit_status)
    err = await upgrades._boot_mode_gate(_FakeConn(mode), 1, 5, "10.9.0.1", "cisco_xe")
    assert rec["updates"]["boot_mode"] == recorded
    assert statuses == [{"boot_mode": recorded}]
    assert bool(err) is blocked


@pytest.mark.asyncio
async def test_boot_mode_gate_skips_platforms_without_boot_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch_check(monkeypatch)
    conn = _FakeConn("BUNDLE")
    assert await upgrades._boot_mode_gate(conn, 1, 5, "10.9.0.1", "cisco_nxos") is None
    assert conn.commands == []
    assert "boot_mode" not in rec["updates"]


@pytest.mark.asyncio
async def test_prestage_stops_on_bundle_mode_before_health_check(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch_check(monkeypatch, boot_mode="BUNDLE")

    async def health_check(*args, **kwargs):
        raise AssertionError("health check must not run on a BUNDLE-mode switch")

    async def passthrough(conn, device_type, *args):
        return device_type

    monkeypatch.setattr(upgrades, "_health_check", health_check)
    monkeypatch.setattr(upgrades, "_upgrade_device_type", passthrough)
    dev = {"id": 5, "ip_address": "10.9.0.1", "hostname": "sw1"}
    await upgrades._device_prestage(1, dev, {}, [("C9300", _TARGET)], {})
    assert rec["updates"]["prestage_status"] == "failed"
    assert rec["updates"]["boot_mode"] == "bundle"
    assert "BUNDLE" in rec["updates"]["error_message"]


@pytest.mark.asyncio
async def test_check_status_on_target_version_marks_every_step(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch_check(monkeypatch, running="17.15.05")
    await _run_check(transfer_status="pending")
    u = rec["updates"]
    assert [u[k] for k in ("prestage_status", "transfer_status", "activate_status", "verify_status")] == [
        "completed"
    ] * 4
    assert rec["md5_checked"] is False


@pytest.mark.asyncio
async def test_check_status_complete_and_expanded_image_marks_transfer(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch_check(monkeypatch)
    await _run_check(transfer_status="pending")
    assert rec["updates"]["transfer_status"] == "completed"
    assert rec["updates"]["error_message"] == ""
    assert rec["md5_checked"] is True
    assert "activate_status" not in rec["updates"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "status", "error_fragment"),
    [
        ({"md5_ok": False}, "failed", "does not match"),
        ({"expanded": False}, "failed", "not expanded"),
        ({"on_flash": False}, "pending", ""),
    ],
)
async def test_check_status_image_outcomes(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict, status: str, error_fragment: str
) -> None:
    rec = _patch_check(monkeypatch, **kwargs)
    await _run_check()
    assert rec["updates"]["transfer_status"] == status
    assert error_fragment in rec["updates"]["error_message"]


@pytest.mark.asyncio
async def test_check_status_skip_md5_option_skips_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _patch_check(monkeypatch, local_image=None)
    await _run_check(transfer_status="pending", options={"skip_md5": True})
    assert rec["updates"]["transfer_status"] == "completed"
    assert rec["md5_checked"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [{"connect_error": OSError("timed out")}, {"local_image": None}],
)
async def test_check_status_inconclusive_keeps_previous_status(monkeypatch: pytest.MonkeyPatch, kwargs: dict) -> None:
    rec = _patch_check(monkeypatch, **kwargs)
    await _run_check(transfer_status="completed")
    assert rec["updates"]["transfer_status"] == "completed"
    assert rec["updates"]["error_message"]


class _VersionConn:
    def __init__(self, output: str) -> None:
        self.output = output
        self.commands: list[str] = []

    def send_command(self, cmd: str, **kwargs) -> str:
        self.commands.append(cmd)
        return self.output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("inventory_type", "show_version", "expected", "queried"),
    [
        ("cisco_ios", "Cisco IOS XE Software, Version 17.03.04", "cisco_xe", True),
        (
            "cisco_ios",
            "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E",
            "cisco_ios",
            True,
        ),
        ("cisco_xe", "Cisco IOS XE Software", "cisco_xe", False),
        ("juniper_junos", "JUNOS 21.4R3", "juniper_junos", False),
    ],
)
async def test_upgrade_device_type_uses_reported_os(
    monkeypatch: pytest.MonkeyPatch, inventory_type: str, show_version: str, expected: str, queried: bool
) -> None:
    async def noop(*args, **kwargs):
        return None

    monkeypatch.setattr(upgrades, "_emit", noop)
    conn = _VersionConn(show_version)
    result = await upgrades._upgrade_device_type(conn, inventory_type, 1, 2, "10.9.0.1")
    assert result == expected
    assert bool(conn.commands) is queried


@pytest.mark.asyncio
async def test_campaign_edit_keeps_progress_of_still_selected_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upgrades, "_get_session", lambda request: {"user": "tester"})

    async def no_audit(*args, **kwargs) -> None:
        return None

    monkeypatch.setattr(upgrades, "_audit", no_audit)

    campaign_id = await db.create_upgrade_campaign(
        name="c1", description="", image_map={}, options={}, created_by="tester"
    )
    kept_id = await db.add_upgrade_device(campaign_id, None, "10.9.0.1", "")
    await db.add_upgrade_device(campaign_id, None, "10.9.0.2", "")
    await db.update_upgrade_device(
        kept_id, prestage_status="completed", transfer_status="completed", phase="transfer_done"
    )
    await db.add_upgrade_events([(campaign_id, kept_id, "success", "Transfer phase complete", "10.9.0.1")])

    body = upgrades.CampaignUpdate(name="c1", ad_hoc_ips=["10.9.0.1", "10.9.0.3"])
    result = await upgrades.update_campaign(campaign_id, body, request=None)  # type: ignore[arg-type]

    assert result == {"ok": True, "total_devices": 2, "devices_added": 1}
    devices = {d["ip_address"]: d for d in await db.get_upgrade_devices(campaign_id)}
    assert set(devices) == {"10.9.0.1", "10.9.0.3"}
    kept = devices["10.9.0.1"]
    assert kept["id"] == kept_id
    assert kept["prestage_status"] == "completed"
    assert kept["transfer_status"] == "completed"
    assert devices["10.9.0.3"]["transfer_status"] in (None, "pending")
    events = await db.get_upgrade_events(campaign_id)
    assert any(e["device_id"] == kept_id for e in events)


def test_progress_event_reports_percent_rate_and_eta() -> None:
    loop = asyncio.new_event_loop()
    try:
        reporter = upgrades._TransferProgressReporter(loop, campaign_id=7, device_id=3, attempt=2)
        start = reporter._start
        event = reporter.build_event(size=1000, sent=250, now=start + 5)
    finally:
        loop.close()

    assert event == {
        "type": "transfer_progress",
        "campaign_id": 7,
        "device_id": 3,
        "sent": 250,
        "total": 1000,
        "percent": 25.0,
        "rate_bps": 50,
        "eta_seconds": 15,
        "elapsed_seconds": 5,
        "attempt": 2,
    }


def test_progress_event_handles_zero_size_and_no_bytes() -> None:
    loop = asyncio.new_event_loop()
    try:
        reporter = upgrades._TransferProgressReporter(loop, 1, 1)
        event = reporter.build_event(size=0, sent=0, now=reporter._start + 1)
    finally:
        loop.close()

    assert event["percent"] == 0.0
    assert event["eta_seconds"] is None


@pytest.mark.asyncio
async def test_transfer_image_broadcasts_throttled_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    sent_events: list[dict] = []

    async def fake_broadcast(campaign_id: int, event: dict) -> None:
        sent_events.append(event)

    def fake_file_transfer(conn, **kwargs):
        progress4 = kwargs["progress4"]
        assert progress4 is not None
        # Rapid chunks: only the first (throttle window opens) and the final
        # chunk are broadcast.
        for sent in (100, 200, 300, 400):
            progress4(b"img.bin", 400, sent, ("10.0.0.1", 22))

    monkeypatch.setattr(upgrades, "_broadcast_upgrade_event", fake_broadcast)
    monkeypatch.setattr(upgrades, "file_transfer", fake_file_transfer)
    monkeypatch.setattr(upgrades, "_check_image_exists", lambda conn, name, dest: True)

    ok, err = await upgrades._transfer_image(
        object(), "/images/img.bin", "img.bin", "flash:", {}, campaign_id=9, dev_id=4
    )
    # Let the thread-scheduled broadcasts run on this loop.
    for _ in range(5):
        await asyncio.sleep(0)

    assert (ok, err) == (True, None)
    assert [e["sent"] for e in sent_events] == [100, 400]
    assert all(e["type"] == "transfer_progress" and e["device_id"] == 4 for e in sent_events)
    assert sent_events[-1]["percent"] == 100.0


@pytest.mark.asyncio
async def test_transfer_image_without_campaign_skips_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    def fake_file_transfer(conn, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(upgrades, "file_transfer", fake_file_transfer)
    monkeypatch.setattr(upgrades, "_check_image_exists", lambda conn, name, dest: True)

    ok, _ = await upgrades._transfer_image(object(), "/images/img.bin", "img.bin", "flash:", {})

    assert ok is True
    assert seen["progress4"] is None
    # _device_transfer verifies the MD5 itself; netmiko must not hash the
    # image on the switch a second time.
    assert seen["verify_file"] is False


_WINDOW_CMD = "show running-config all | include ^ip tcp window-size|^ip ssh window-size|^ip ssh bulk-mode"


async def _window_check(monkeypatch: pytest.MonkeyPatch, conn, device_type: str = "cisco_xe") -> list[tuple]:
    events: list[tuple] = []

    async def fake_emit(campaign_id, device_id, level, message, host=""):
        events.append((level, message))

    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    await upgrades._transfer_window_check(conn, 1, 5, "10.9.0.1", device_type)
    return events


@pytest.mark.asyncio
async def test_transfer_window_check_warns_with_fix_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _VersionConn("")
    events = await _window_check(monkeypatch, conn)
    assert conn.commands == [_WINDOW_CMD]
    [(level, message)] = events
    assert level == "warn"
    assert "TCP window 4128 bytes (default)" in message
    assert "SSH window at its default" in message
    assert "ip tcp window-size 65536; ip ssh bulk-mode (or ip ssh window-size 65536" in message


@pytest.mark.asyncio
async def test_transfer_window_check_reports_tuned_device(monkeypatch: pytest.MonkeyPatch) -> None:
    events = await _window_check(monkeypatch, _VersionConn("ip tcp window-size 65535\nip ssh bulk-mode\n"))
    assert events == [("info", "Transfer windows OK (TCP window 65535 bytes, SSH bulk mode on)")]


@pytest.mark.asyncio
async def test_transfer_window_check_accepts_ssh_window_size(monkeypatch: pytest.MonkeyPatch) -> None:
    """Releases without bulk mode are tuned through ``ip ssh window-size``."""
    events = await _window_check(monkeypatch, _VersionConn("ip tcp window-size 65536\nip ssh window-size 65536\n"))
    assert events == [("info", "Transfer windows OK (TCP window 65536 bytes, SSH window 65536 bytes)")]


@pytest.mark.asyncio
async def test_transfer_window_check_skips_platforms_without_the_knobs(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _VersionConn("")
    assert await _window_check(monkeypatch, conn, device_type="cisco_nxos") == []
    assert conn.commands == []


@pytest.mark.asyncio
async def test_transfer_window_check_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom:
        def send_command(self, *_a, **_k):
            raise OSError("socket closed")

    [(level, message)] = await _window_check(monkeypatch, _Boom())
    assert level == "warn"
    assert "continuing" in message


@pytest.mark.asyncio
@pytest.mark.parametrize(("on_flash", "checked"), [(False, True), (True, False)])
async def test_transfer_checks_windows_only_before_a_real_copy(
    monkeypatch: pytest.MonkeyPatch, on_flash: bool, checked: bool
) -> None:
    rec = _patch_check(monkeypatch, on_flash=on_flash)
    conn = _FakeConn()

    async def connect(*args, **kwargs):
        return conn

    async def flash_space(*args, **kwargs):
        return True, 10**10

    async def transfer_image(conn, *args, **kwargs):
        conn.commands.append("SCP")
        return True, None

    async def prestage(*args, **kwargs):
        return True, None

    monkeypatch.setattr(upgrades, "_connect_device", connect)
    monkeypatch.setattr(upgrades, "_check_flash_space", flash_space)
    monkeypatch.setattr(upgrades, "_transfer_image", transfer_image)
    monkeypatch.setattr(upgrades, "_run_install_add_prestage", prestage)

    dev = {"id": 5, "ip_address": "10.9.0.1", "target_image": _TARGET}
    await upgrades._device_transfer(1, dev, {}, [], {})

    assert rec["updates"]["transfer_status"] == "completed"
    assert (_WINDOW_CMD in conn.commands) is checked
    if checked:
        assert conn.commands.index(_WINDOW_CMD) < conn.commands.index("SCP")


@pytest.mark.asyncio
async def test_successful_transfer_clears_the_previous_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A retry that succeeds must not keep the earlier failure's text.

    Check status marks a present-but-unexpanded image failed with a reason;
    the Transfer that then finishes install add ends completed, so the
    stored and broadcast error both have to be emptied.
    """
    rec = _patch_check(monkeypatch, on_flash=True)
    rec["updates"]["error_message"] = "Image is on flash but not expanded (install add)"
    statuses: list[dict] = []

    async def connect(*args, **kwargs):
        return _FakeConn()

    async def prestage(*args, **kwargs):
        return True, None

    async def emit_status(campaign_id, dev_id, **fields):
        statuses.append(fields)

    async def flash_space(*args, **kwargs):
        return True, 10**10

    monkeypatch.setattr(upgrades, "_connect_device", connect)
    monkeypatch.setattr(upgrades, "_check_flash_space", flash_space)
    monkeypatch.setattr(upgrades, "_run_install_add_prestage", prestage)
    monkeypatch.setattr(upgrades, "_emit_device_status", emit_status)

    dev = {"id": 5, "ip_address": "10.9.0.1", "target_image": _TARGET}
    await upgrades._device_transfer(1, dev, {}, [], {})

    assert rec["updates"]["transfer_status"] == "completed"
    assert rec["updates"]["error_message"] == ""
    assert statuses[0] == {"transfer_status": "running", "error_message": ""}
    assert statuses[-1]["transfer_status"] == "completed"
