"""Tests for the Netmiko session helpers in ``netcontrol.routes.shared``.

These exercise the driver-backed config-capture path added in Phase 2
of the multi-vendor driver framework.  The intent is to assert:

  - ``_open_netmiko_session`` returns the autodetected device_type so
    callers can resolve the right driver after SSHDetect upgrades a
    generic ``cisco_ios`` to ``cisco_xe``.
  - ``_capture_running_config`` consults the driver registry, not a
    hardcoded ``"show running-config"``.  When the resolved driver
    doesn't implement the capability the helper falls back to the
    legacy command so existing backups keep working.
  - SSHDetect only runs for generic Cisco defaults (``cisco_ios`` /
    ``unknown``); a stored ``cisco_xe`` skips autodetect.
  - The ``secret`` field triggers ``conn.enable()`` exactly once.
"""

from __future__ import annotations

import asyncio
import sys
import types

import pytest

# ── Fake netmiko module ─────────────────────────────────────────────────────


class _FakeNetConnect:
    """Stand-in for a Netmiko BaseConnection."""

    def __init__(self, **kwargs):
        self.device_type = kwargs.get("device_type")
        self.host = kwargs.get("host")
        self.username = kwargs.get("username")
        self.password = kwargs.get("password")
        self.secret = kwargs.get("secret", "")
        self.commands_run: list[str] = []
        self.config_sets: list[list[str]] = []
        self.enable_called = 0
        self.disconnect_called = 0
        self.save_calls = 0

    def enable(self):
        self.enable_called += 1

    def send_command(self, cmd, *args, **kwargs):
        self.commands_run.append(cmd)
        return f"<output of {cmd}>"

    def send_config_set(self, cmds, *args, **kwargs):
        self.config_sets.append(list(cmds))
        return f"<config output {len(cmds)} lines>"

    def save_config(self):
        self.save_calls += 1
        return "[OK] saved"

    def disconnect(self):
        self.disconnect_called += 1


class _FakeSSHDetect:
    """Stand-in for netmiko.SSHDetect.

    The constructor records the device_type it was called with so tests
    can confirm autodetect was (or was not) attempted.  ``autodetect``
    returns a class-level ``best`` value so individual tests can change
    the verdict without subclassing.
    """

    instances: list[_FakeSSHDetect] = []
    best: str | None = "cisco_xe"

    def __init__(self, **kwargs):
        self.device_type = kwargs.get("device_type")
        # Mirror Netmiko's public ``connection`` attribute - our shared
        # helper calls ``guesser.connection.disconnect()`` for cleanup.
        self.connection = _FakeNetConnect(**kwargs)
        type(self).instances.append(self)

    def autodetect(self):
        return type(self).best


@pytest.fixture(autouse=True)
def fake_netmiko(monkeypatch):
    """Install a minimal fake ``netmiko`` package for the duration of a test.

    Also resets the shared SSHDetect call-log so each test starts clean.
    Yields the ``_FakeNetConnect`` instance the next ``ConnectHandler``
    call will return so tests can assert against it.
    """
    holder: dict[str, _FakeNetConnect | None] = {"conn": None}

    def _connect_handler(**kwargs):
        conn = _FakeNetConnect(**kwargs)
        holder["conn"] = conn
        return conn

    fake = types.ModuleType("netmiko")
    fake.ConnectHandler = _connect_handler
    fake.SSHDetect = _FakeSSHDetect

    monkeypatch.setitem(sys.modules, "netmiko", fake)
    # ``from netmiko import SSHDetect`` resolves through the same module
    # entry, but stash a submodule binding too in case any caller imports
    # it as ``netmiko.SSHDetect``.
    _FakeSSHDetect.instances = []
    _FakeSSHDetect.best = "cisco_xe"
    yield holder


@pytest.fixture(autouse=True)
def stub_crypto(monkeypatch):
    """Make ``routes.crypto.decrypt`` a no-op identity function.

    The real decrypt() pulls keys from disk; tests just need the value
    to round-trip through.
    """
    crypto = types.ModuleType("routes.crypto")
    crypto.decrypt = lambda v: v
    crypto.encrypt = lambda v: v
    monkeypatch.setitem(sys.modules, "routes.crypto", crypto)
    yield


# ── _open_netmiko_session ──────────────────────────────────────────────────


def test_open_session_autodetects_generic_cisco_ios(fake_netmiko):
    from netcontrol.routes.shared import _open_netmiko_session

    host = {"ip_address": "10.0.0.1", "device_type": "cisco_ios"}
    creds = {"username": "u", "password": "p", "secret": ""}

    conn, resolved = _open_netmiko_session(host, creds)

    # SSHDetect should have been instantiated once with device_type="autodetect"
    assert len(_FakeSSHDetect.instances) == 1
    assert _FakeSSHDetect.instances[0].device_type == "autodetect"
    # The autodetect verdict (cisco_xe) is what we connect with.
    assert conn.device_type == "cisco_xe"
    assert resolved == "cisco_xe"


def test_open_session_skips_autodetect_for_specific_type(fake_netmiko):
    # When inventory already has the right specific type, we shouldn't
    # waste an extra SSH session on autodetect.
    from netcontrol.routes.shared import _open_netmiko_session

    host = {"ip_address": "10.0.0.1", "device_type": "cisco_xe"}
    creds = {"username": "u", "password": "p", "secret": ""}

    conn, resolved = _open_netmiko_session(host, creds)

    assert _FakeSSHDetect.instances == []
    assert resolved == "cisco_xe"
    assert conn.device_type == "cisco_xe"


def test_open_session_autodetects_when_type_is_unknown(fake_netmiko):
    from netcontrol.routes.shared import _open_netmiko_session

    host = {"ip_address": "10.0.0.1", "device_type": "unknown"}
    creds = {"username": "u", "password": "p", "secret": ""}

    _, resolved = _open_netmiko_session(host, creds)
    assert len(_FakeSSHDetect.instances) == 1
    assert resolved == "cisco_xe"


def test_open_session_falls_back_when_autodetect_returns_none(fake_netmiko):
    # SSHDetect can return None when it can't classify the banner.  In
    # that case we keep the original device_type rather than blowing up.
    from netcontrol.routes.shared import _open_netmiko_session

    _FakeSSHDetect.best = None
    host = {"ip_address": "10.0.0.1", "device_type": "cisco_ios"}
    _, resolved = _open_netmiko_session(host, {"username": "u", "password": "p", "secret": ""})
    assert resolved == "cisco_ios"


def test_open_session_calls_enable_when_secret_present(fake_netmiko):
    from netcontrol.routes.shared import _open_netmiko_session

    host = {"ip_address": "10.0.0.1", "device_type": "cisco_xe"}
    creds = {"username": "u", "password": "p", "secret": "enable_password"}

    conn, _ = _open_netmiko_session(host, creds)
    assert conn.enable_called == 1


def test_open_session_skips_enable_when_no_secret(fake_netmiko):
    from netcontrol.routes.shared import _open_netmiko_session

    host = {"ip_address": "10.0.0.1", "device_type": "cisco_xe"}
    conn, _ = _open_netmiko_session(host, {"username": "u", "password": "p", "secret": ""})
    assert conn.enable_called == 0


# ── _capture_running_config ────────────────────────────────────────────────


def test_capture_running_config_uses_driver_command(fake_netmiko):
    # After autodetect upgrades cisco_ios → cisco_xe, the driver lookup
    # should resolve to CiscoXEDriver, whose capture command is
    # "show running-config".  This indirectly proves the
    # driver-resolves-from-the-autodetected-type path works.
    from netcontrol.routes.shared import _capture_running_config

    host = {"ip_address": "10.0.0.1", "device_type": "cisco_ios"}
    creds = {"username": "u", "password": "p", "secret": ""}

    output = asyncio.run(_capture_running_config(host, creds))

    conn = fake_netmiko["conn"]
    assert conn.commands_run == ["show running-config"]
    assert "show running-config" in output
    assert conn.disconnect_called == 1


def test_capture_running_config_falls_back_for_unknown_vendor(fake_netmiko):
    # An unknown device_type yields GenericDriver which raises
    # DriverCapabilityError - the helper must catch and use the legacy
    # default rather than propagating an error that would break backups
    # for an otherwise-reachable device.
    from netcontrol.routes.shared import _capture_running_config

    # Stop SSHDetect from upgrading to cisco_xe so the driver lookup
    # really does hit the unknown path.
    _FakeSSHDetect.best = None

    host = {"ip_address": "10.0.0.1", "device_type": "frobozz_os"}
    creds = {"username": "u", "password": "p", "secret": ""}

    asyncio.run(_capture_running_config(host, creds))

    conn = fake_netmiko["conn"]
    # Legacy default - the helper falls back rather than crashing.
    assert conn.commands_run == ["show running-config"]


def test_capture_running_config_disconnects_on_command_error(fake_netmiko):
    # send_command exceptions must not leak the SSH session - the helper
    # uses try/finally so disconnect runs either way.  Without that
    # contract, a flaky device would slowly exhaust the worker's file
    # descriptors.
    from netcontrol.routes.shared import _capture_running_config

    def _boom(cmd, *args, **kwargs):
        raise RuntimeError("network glitch")

    host = {"ip_address": "10.0.0.1", "device_type": "cisco_xe"}
    creds = {"username": "u", "password": "p", "secret": ""}

    # Patch send_command on the next ConnectHandler result.  Easiest
    # path: install a custom ConnectHandler for this test.
    captured: dict[str, _FakeNetConnect] = {}

    def _connect(**kwargs):
        conn = _FakeNetConnect(**kwargs)
        conn.send_command = _boom  # type: ignore[assignment]
        captured["conn"] = conn
        return conn

    sys.modules["netmiko"].ConnectHandler = _connect

    with pytest.raises(RuntimeError, match="network glitch"):
        asyncio.run(_capture_running_config(host, creds))

    assert captured["conn"].disconnect_called == 1


# ── _run_show_command ──────────────────────────────────────────────────────


def test_run_show_command_uses_caller_supplied_command(fake_netmiko):
    from netcontrol.routes.shared import _run_show_command

    host = {"ip_address": "10.0.0.1", "device_type": "cisco_xe"}
    creds = {"username": "u", "password": "p", "secret": ""}

    output = asyncio.run(_run_show_command(host, creds, "show version"))

    conn = fake_netmiko["conn"]
    assert conn.commands_run == ["show version"]
    assert "show version" in output
    assert conn.disconnect_called == 1


# ── _push_config_to_device ─────────────────────────────────────────────────


def test_push_config_runs_config_set_and_save(fake_netmiko):
    from netcontrol.routes.shared import _push_config_to_device

    host = {"ip_address": "10.0.0.1", "device_type": "cisco_xe"}
    creds = {"username": "u", "password": "p", "secret": ""}
    cmds = ["interface Gi0/0", "description plexus-managed"]

    output = asyncio.run(_push_config_to_device(host, creds, cmds))

    conn = fake_netmiko["conn"]
    assert conn.config_sets == [cmds]
    assert conn.save_calls == 1
    # The combined return value includes both send_config_set output and
    # the save_config output, joined by a newline.  Callers use this to
    # display "what happened" in the UI.
    assert "config output" in output
    assert "saved" in output
    assert conn.disconnect_called == 1
