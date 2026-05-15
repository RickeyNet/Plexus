"""Tests for the vendor-neutral SNMPv3 configurator playbook.

The playbook in ``templates/playbooks/snmpv3_configurator.py`` was
refactored in Phase 3 of the multi-vendor driver framework to resolve
its vendor-specific commands through the driver registry instead of
hard-coding Cisco syntax.  These tests assert:

  - Hosts whose ``device_type`` has no registered driver are skipped
    with a clear error event and never get an SSH session (otherwise we
    would push Cisco syntax at e.g. a Junos device).
  - The driver's ``snmpv3_show_existing_command()`` is what actually
    runs in the "show existing" step, not a hardcoded literal.
  - NX-OS hosts skip the engine-ID pin entirely because the driver
    reports the engine ID as platform-managed; the playbook must not
    error out and must not try to send ``snmp-server engineID local``.
  - On a successful live push, the driver's
    ``snmpv3_verify_users_command()`` is used for the verify step and
    Netmiko's ``save_config()`` is called once.
"""

from __future__ import annotations

import sys
import types

import pytest

# ── Fake netmiko module + ConnectHandler ───────────────────────────────────


class _FakeConn:
    """Stand-in for a Netmiko BaseConnection.

    Records every command sent so the test can assert which driver
    commands were actually used.  ``send_command_returns`` is keyed by
    the exact command string and lets a test customise per-command
    output (e.g. return a realistic ``show snmp engineID`` line).
    """

    send_command_returns: dict[str, str] = {}

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.send_commands: list[str] = []
        self.config_sets: list[list[str]] = []
        self.save_calls = 0
        self.disconnect_calls = 0
        self.enable_calls = 0
        self.in_enable = False

    # Netmiko surface used by connect_device:
    def check_enable_mode(self) -> bool:
        return self.in_enable

    def enable(self) -> None:
        self.enable_calls += 1
        self.in_enable = True

    def find_prompt(self) -> str:
        return "fake-sw#"

    def send_command(self, cmd, *args, **kwargs):
        self.send_commands.append(cmd)
        return type(self).send_command_returns.get(cmd, f"<output of {cmd}>")

    def send_config_set(self, cmds, *args, **kwargs):
        self.config_sets.append(list(cmds))
        return f"<applied {len(cmds)} lines>"

    def save_config(self) -> str:
        self.save_calls += 1
        return "[OK] saved"

    def disconnect(self) -> None:
        self.disconnect_calls += 1


@pytest.fixture
def fake_netmiko(monkeypatch):
    """Install a fake ``netmiko`` module and force NETMIKO_AVAILABLE=True.

    Yields the holder dict so tests can grab the conn that the next
    ``ConnectHandler(...)`` call returns.  Each test starts with a
    clean ``send_command_returns`` table.
    """
    _FakeConn.send_command_returns = {}
    holder: dict[str, _FakeConn | None] = {"conn": None}

    def _connect_handler(**kwargs):
        c = _FakeConn(**kwargs)
        holder["conn"] = c
        return c

    fake = types.ModuleType("netmiko")
    fake.ConnectHandler = _connect_handler
    # Netmiko also exports an exceptions submodule; the playbook's
    # _common.py imports the two classes directly.  We don't expect them
    # to be raised here, so plain Exception subclasses are enough.
    fake_exc_mod = types.ModuleType("netmiko.exceptions")

    class _Timeout(Exception):
        pass

    class _Auth(Exception):
        pass

    fake_exc_mod.NetmikoTimeoutException = _Timeout
    fake_exc_mod.NetmikoAuthenticationException = _Auth
    fake.NetmikoTimeoutException = _Timeout
    fake.NetmikoAuthenticationException = _Auth

    monkeypatch.setitem(sys.modules, "netmiko", fake)
    monkeypatch.setitem(sys.modules, "netmiko.exceptions", fake_exc_mod)

    # Flip the cached flags inside _common.py so it takes the live path.
    import templates.playbooks._common as common
    monkeypatch.setattr(common, "NETMIKO_AVAILABLE", True)
    monkeypatch.setattr(common, "ConnectHandler", _connect_handler)
    monkeypatch.setattr(common, "NetmikoTimeoutException", _Timeout)
    monkeypatch.setattr(common, "NetmikoAuthenticationException", _Auth)

    # The playbook module captures NETMIKO_AVAILABLE at import time, so
    # patch the bound name too.
    import templates.playbooks.snmpv3_configurator as pb
    monkeypatch.setattr(pb, "NETMIKO_AVAILABLE", True)

    yield holder


async def _drain(agen):
    """Collect every event yielded by the async generator into a list."""
    return [ev async for ev in agen]


# ── Driver-resolution gating ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_vendor_is_skipped_before_ssh(fake_netmiko):
    """A device_type without a driver must not get an SSH session.

    The whole point of routing through the registry is to refuse to
    push Cisco syntax at an unrecognised vendor.  This test catches a
    regression where the playbook would fall through to the legacy
    'cisco_ios' default and silently send the wrong commands.
    """
    from templates.playbooks.snmpv3_configurator import Snmpv3Configurator

    pb = Snmpv3Configurator()
    events = await _drain(pb.run(
        hosts=[{"ip_address": "10.0.0.1", "hostname": "weird-box",
                "device_type": "frobozz_os"}],
        credentials={"username": "u", "password": "p", "secret": ""},
        template_commands=["snmp-server group SECURE v3 priv"],
        dry_run=False,
    ))

    # No SSH session was ever opened.
    assert fake_netmiko["conn"] is None
    # And the operator got a clear, actionable error.
    errors = [e for e in events if e.level == "error"]
    assert any("No SNMPv3 driver registered" in e.message for e in errors)
    assert any("frobozz_os" in e.message for e in errors)


# ── Show-existing routes through the driver ────────────────────────────────


@pytest.mark.asyncio
async def test_show_existing_uses_driver_command_dry_run(fake_netmiko):
    """The 'show existing' step must use the driver's command verbatim.

    Dry-run is the simplest path that still exercises step 1 - it
    connects, runs show-existing, prints the would-apply preview, and
    does not push config.  The assertion that send_commands contains
    *exactly* the driver-supplied command (not a hardcoded literal)
    catches a regression where someone re-inlines ``show running-config
    | include snmp-server``.
    """
    from netcontrol.drivers import get_driver
    from templates.playbooks.snmpv3_configurator import Snmpv3Configurator

    pb = Snmpv3Configurator()
    events = await _drain(pb.run(
        hosts=[{"ip_address": "10.0.0.1", "hostname": "sw1",
                "device_type": "cisco_xe"}],
        credentials={"username": "u", "password": "p", "secret": ""},
        template_commands=["snmp-server user netops SECURE v3 auth sha s priv aes 256 p"],
        dry_run=True,
    ))

    conn = fake_netmiko["conn"]
    assert conn is not None
    expected = get_driver("cisco_xe").snmpv3_show_existing_command()
    assert expected in conn.send_commands
    # Dry-run: no config_sets pushed, no save.
    assert conn.config_sets == []
    assert conn.save_calls == 0
    assert conn.disconnect_calls == 1
    # And the operator saw the would-apply preview.
    assert any(e.level == "info" and "[DRY-RUN] Would apply" in e.message
               for e in events)


# ── NX-OS skips the engine-ID pin ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_nxos_skips_engine_id_pin(fake_netmiko):
    """NX-OS persists the engine ID; the playbook must not try to pin it.

    The driver returns an empty string for both the show and the pin
    command.  ``pin_snmp_engine_id`` should short-circuit and emit an
    info-level event explaining why, and crucially never send
    ``snmp-server engineID local ...`` (which doesn't exist on NX-OS).
    """
    from templates.playbooks.snmpv3_configurator import Snmpv3Configurator

    pb = Snmpv3Configurator()
    events = await _drain(pb.run(
        hosts=[{"ip_address": "10.0.0.2", "hostname": "nx1",
                "device_type": "cisco_nxos"}],
        credentials={"username": "u", "password": "p", "secret": ""},
        template_commands=["snmp-server user netops SECURE v3 auth sha s priv aes 256 p"],
        dry_run=False,
    ))

    conn = fake_netmiko["conn"]
    assert conn is not None
    # The template was pushed exactly once - we got past step 3.
    assert len(conn.config_sets) == 1
    # And no engine-ID pin command sneaked in - the only config_set is
    # the template itself.
    pinned = [c for batch in conn.config_sets for c in batch
              if "snmp-server engineID local" in c]
    assert pinned == []
    # 'show snmp engineID' was never run because the driver returned "".
    assert "show snmp engineID" not in conn.send_commands
    # The info event explains why pin was skipped.
    assert any("engine ID is platform-managed" in e.message for e in events)


# ── Full live path uses driver verify command + saves ──────────────────────


@pytest.mark.asyncio
async def test_live_push_uses_driver_verify_and_saves(fake_netmiko):
    """End-to-end live push on an IOS-XE host.

    Validates the four driver consults that matter on the live path:
      1. show-existing command  → driver-supplied
      2. engine-ID show command → driver-supplied + matched by regex
      3. engine-ID pin command  → driver-supplied + sent in config mode
      4. verify-users command   → driver-supplied
    Plus the side effect that ``conn.save_config()`` is called once at
    the end so the running-config survives a reload.
    """
    from templates.playbooks.snmpv3_configurator import Snmpv3Configurator

    # Realistic engine-ID output so the regex in pin_snmp_engine_id
    # matches and produces an actual pin command.
    _FakeConn.send_command_returns = {
        "show snmp engineID": "Local SNMP engineID: 80000009030050568D9CDFC0",
    }

    pb = Snmpv3Configurator()
    events = await _drain(pb.run(
        hosts=[{"ip_address": "10.0.0.3", "hostname": "xe1",
                "device_type": "cisco_xe"}],
        credentials={"username": "u", "password": "p", "secret": ""},
        template_commands=["snmp-server user netops SECURE v3 auth sha s priv aes 256 p"],
        dry_run=False,
    ))

    conn = fake_netmiko["conn"]
    assert conn is not None
    # Step 1 + 4 send_commands.
    assert "show running-config | include snmp-server" in conn.send_commands
    assert "show snmp engineID" in conn.send_commands
    assert "show snmp user" in conn.send_commands
    # Step 2 - pin command came from the driver with the captured ID.
    pin_batches = [b for b in conn.config_sets
                   if any("snmp-server engineID local 80000009030050568D9CDFC0" in c
                          for c in b)]
    assert len(pin_batches) == 1
    # Step 3 - the user template itself was pushed.
    template_batches = [b for b in conn.config_sets
                        if any(c.startswith("snmp-server user netops") for c in b)]
    assert len(template_batches) == 1
    # Persisted to startup exactly once.
    assert conn.save_calls == 1
    # Disconnect ran cleanly.
    assert conn.disconnect_calls == 1
    # And the run finished successfully.
    assert any(e.level == "success" and "Finished processing" in e.message
               for e in events)
