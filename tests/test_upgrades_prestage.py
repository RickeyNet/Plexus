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
async def test_run_install_add_prestage_short_circuits_for_arista_eos(
    _stub_emit: list[tuple],
) -> None:
    """Arista EOS uses ``install source`` + ``reload now`` - prestage skips."""
    conn = _RecordingConn()
    ok, err = await upgrades._run_install_add_prestage(
        conn,
        campaign_id=1,
        dev_id=42,
        ip="10.0.0.1",
        image_name="EOS-4.30.5M.swi",
        dest_path="flash:",
        device_type="arista_eos",
    )
    assert ok is True
    assert err is None
    # No commands hit the device - the route would otherwise be sending
    # IOS-XE ``install add file ...`` syntax at an Arista EOS session,
    # which EOS parses as a wholly different ``install`` subcommand and
    # would either error out or (worse) attempt the wrong operation.
    assert conn.commands == []
    # The operator must see the deferral as "info", not "pre-stage not
    # supported" - EOS is supported, it just doesn't have a discrete
    # prestage phase (same single-phase shape as Junos / NX-OS).
    levels_and_messages = [(lvl, msg) for (lvl, msg, _h) in _stub_emit]
    assert any(
        lvl == "info" and "defer" in msg.lower() for (lvl, msg) in levels_and_messages
    )


@pytest.mark.asyncio
async def test_run_install_add_prestage_runs_for_cisco_xr(
    monkeypatch: pytest.MonkeyPatch,
    _stub_emit: list[tuple],
) -> None:
    """IOS-XR: the install-add command really fires (uses ``source``).

    XR is the second driver (after IOS-XE) to expose a discrete
    prestage step, so this test mirrors the XE happy-path but asserts
    the XR-specific ``install add source <path>`` verb instead of
    XE's ``install add file <path>``.  Without this guard, a future
    refactor could silently downgrade XR back to single-phase or send
    the XE wording at an XR session - the latter parse-errors because
    XR uses ``source``, not ``file``.
    """

    class _XRSuccessConn:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def send_command(self, command: str, **_: object) -> str:
            self.commands.append(command)
            if command.startswith("install add source"):
                # XR prints a packaging operation ID on success; the
                # route doesn't parse the ID (bare ``install activate``
                # picks up all newly-added packages later), but the
                # success-path tokens must not contain ``proceed`` /
                # ``y/n`` or the helper would think the device is
                # asking for confirmation.
                return "Install operation 1 succeeded"
            if command.startswith("dir"):
                # ``_verify_install_add_unpacked_files`` calls
                # ``dir | include <version>`` - return a line that
                # contains the extracted version so the verify path
                # accepts it.
                return "  -rw- 12345 Jan 1 2024 asr9k-mini-x64-7.5.2.iso\n"
            return ""

    conn = _XRSuccessConn()
    ok, err = await upgrades._run_install_add_prestage(
        conn,
        campaign_id=1,
        dev_id=42,
        ip="10.0.0.1",
        image_name="asr9k-mini-x64-7.5.2.iso",
        dest_path="harddisk:",
        device_type="cisco_xr",
    )
    assert ok is True
    assert err is None
    # The install-add command must be XR's ``install add source ...``,
    # not XE's ``install add file ...`` - the latter parse-errors on XR.
    assert any(
        c.startswith("install add source harddisk:asr9k-mini-x64-7.5.2.iso")
        for c in conn.commands
    )
    # And the XE wording must NOT appear - a regression where the
    # route fell back to XE syntax would silently break every XR
    # upgrade.
    assert not any(c.startswith("install add file") for c in conn.commands)


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
