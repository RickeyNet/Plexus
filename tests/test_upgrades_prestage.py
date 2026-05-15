"""Tests for the multi-vendor short-circuit in `_run_install_add_prestage`.

The upgrade route's pre-stage helper used to assume every host
spoke IOS-XE install-mode.  Phase 7 of the driver framework makes
the helper consult the driver's ``upgrade_has_discrete_prestage()``
and skip the install-add entirely when the platform combines add +
activate (Junos, NX-OS, classic IOS).  These tests are the regression
guard so a future refactor can't silently re-introduce the assumption
that every vendor has an IOS-XE-shaped two-phase upgrade flow.

The tests stub the device connection (`conn`) and `_emit` so they
don't need Netmiko or the upgrade-events DB - the only contract
under test is the platform-shape branch at the top of the helper.
"""
from __future__ import annotations

import pytest
from netcontrol.routes import upgrades


class _RecordingConn:
    """Minimal stand-in for the Netmiko ConnectHandler.

    The test confirms that when the driver advertises single-phase
    upgrade flow, no commands are ever sent to the device - so this
    records `send_command` calls and exposes them for assertion.
    """

    def __init__(self) -> None:
        self.commands: list[str] = []

    def send_command(self, command: str, **_: object) -> str:
        self.commands.append(command)
        return ""


@pytest.fixture(autouse=True)
def _stub_emit(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Replace `_emit` with a recorder so we don't touch the DB."""
    events: list[tuple] = []

    async def fake_emit(campaign_id, device_id, level, message, host=""):
        events.append((level, message, host))

    monkeypatch.setattr(upgrades, "_emit", fake_emit)
    return events


@pytest.mark.asyncio
async def test_run_install_add_prestage_short_circuits_for_single_phase_driver(
    _stub_emit: list[tuple],
) -> None:
    """Junos / NX-OS / classic IOS skip install-add and report success."""
    conn = _RecordingConn()
    ok, err = await upgrades._run_install_add_prestage(
        conn,
        campaign_id=1,
        dev_id=42,
        ip="10.0.0.1",
        image_name="jinstall-22.4R3.tgz",
        dest_path="/var/tmp/",
        device_type="juniper_junos",
    )
    assert ok is True
    assert err is None
    # No commands must hit the device - the route would otherwise be
    # sending IOS-XE "install add file ..." syntax at a Junos session.
    assert conn.commands == []
    # The operator should see the deferral, not "pre-stage not
    # supported" (which would mislead them into thinking the platform
    # is unsupported when it just doesn't need a separate stage).
    levels_and_messages = [(lvl, msg) for (lvl, msg, _h) in _stub_emit]
    assert any(
        lvl == "info" and "defer" in msg.lower() for (lvl, msg) in levels_and_messages
    )


@pytest.mark.asyncio
async def test_run_install_add_prestage_short_circuits_for_cisco_nxos(
    _stub_emit: list[tuple],
) -> None:
    """NX-OS combines add+activate via ``install all nxos`` - prestage skips."""
    conn = _RecordingConn()
    ok, err = await upgrades._run_install_add_prestage(
        conn,
        campaign_id=1,
        dev_id=42,
        ip="10.0.0.1",
        image_name="nxos.10.3.4a.M.bin",
        dest_path="bootflash:",
        device_type="cisco_nxos",
    )
    assert ok is True
    assert err is None
    # No commands hit the device - the route would otherwise be sending
    # IOS-XE ``install add file ...`` syntax at an NX-OS session, which
    # NX-OS parses as a different command and would silently misbehave.
    assert conn.commands == []
    # The operator log must explain the skip as "deferral", not
    # "platform unsupported" - NX-OS is supported, it just doesn't have
    # a discrete prestage phase.
    levels_and_messages = [(lvl, msg) for (lvl, msg, _h) in _stub_emit]
    assert any(
        lvl == "info" and "defer" in msg.lower() for (lvl, msg) in levels_and_messages
    )


@pytest.mark.asyncio
async def test_run_install_add_prestage_runs_for_cisco_xe(
    monkeypatch: pytest.MonkeyPatch,
    _stub_emit: list[tuple],
) -> None:
    """IOS-XE: the install-add command really fires."""

    class _SuccessConn:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def send_command(self, command: str, **_: object) -> str:
            self.commands.append(command)
            # The first call is `install add file ...` - return a
            # clean output (no "proceed" / "y/n" prompts) so the
            # helper takes the success path.  The second call is the
            # `dir | include <version>` verification.
            if command.startswith("install add file"):
                return "Image added successfully"
            if command.startswith("dir"):
                # Return a verification line so `_verify_install_add_unpacked_files`
                # accepts the result.
                return "  -rw- 12345 Jan 1 2024 cat9k_iosxe.17.09.04a.pkg\n"
            return ""

    # `asyncio.to_thread(conn.send_command, ...)` runs the lambda in
    # a thread; for the test we don't need real threading, but the
    # default behaviour is fine - the conn is just synchronous.
    conn = _SuccessConn()
    ok, err = await upgrades._run_install_add_prestage(
        conn,
        campaign_id=1,
        dev_id=42,
        ip="10.0.0.1",
        image_name="cat9k_iosxe.17.09.04a.SPA.bin",
        dest_path="flash:",
        device_type="cisco_xe",
    )
    assert ok is True
    assert err is None
    # The install-add command must include the full device path so
    # IOS-XE finds the staged .bin.
    assert any(
        c.startswith("install add file flash:cat9k_iosxe.17.09.04a.SPA.bin")
        for c in conn.commands
    )
