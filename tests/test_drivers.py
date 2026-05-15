"""Tests for the multi-vendor driver framework.

Covers:
  - Registry lookup for the three Cisco device_types ships out of the box.
  - Unknown / None device_type falls back to GenericDriver and any
    capability call raises DriverCapabilityError (so the playbook can
    skip the host instead of guessing at Cisco syntax).
  - cisco_nxos and cisco_nxos_ssh both resolve to the same driver class.
  - Each Cisco driver's build_netflow_config output is well-formed:
    starts with the expected anchor lines, embeds the collector IP/port
    and the interfaces, and only emits sampler stanzas when sampling > 1.
  - register_driver rejects duplicate registrations (would otherwise
    silently shadow an existing driver depending on import order).
"""

from __future__ import annotations

import pytest
from netcontrol.drivers import (
    Driver,
    DriverCapabilityError,
    GenericDriver,
    NetflowConfig,
    get_driver,
    register_driver,
    registered_device_types,
)
from netcontrol.drivers.arista_eos import AristaEOSDriver
from netcontrol.drivers.cisco_ios import CiscoIOSDriver
from netcontrol.drivers.cisco_nxos import CiscoNXOSDriver
from netcontrol.drivers.cisco_xe import CiscoXEDriver
from netcontrol.drivers.cisco_xr import CiscoXRDriver
from netcontrol.drivers.juniper_junos import JuniperJunosDriver


def _cfg(sampling_rate: int = 1, interfaces: list[str] | None = None) -> NetflowConfig:
    return NetflowConfig(
        collector_ip="10.0.0.5",
        collector_port=2055,
        interfaces=interfaces or ["GigabitEthernet0/0", "GigabitEthernet0/1"],
        sampling_rate=sampling_rate,
    )


# ── registry ────────────────────────────────────────────────────────────────


def test_registry_resolves_each_cisco_device_type() -> None:
    assert isinstance(get_driver("cisco_ios"), CiscoIOSDriver)
    assert isinstance(get_driver("cisco_xe"), CiscoXEDriver)
    assert isinstance(get_driver("cisco_nxos"), CiscoNXOSDriver)
    # Both NX-OS transports share one driver class.
    assert isinstance(get_driver("cisco_nxos_ssh"), CiscoNXOSDriver)


def test_registry_resolves_juniper_junos() -> None:
    # First non-Cisco driver: the Netmiko device_type string for Juniper
    # is "juniper_junos" and the routes/inventory.py + routes/snmp.py
    # vendor inference already emits that exact value, so the driver
    # must register under it (no aliasing needed).
    assert isinstance(get_driver("juniper_junos"), JuniperJunosDriver)
    assert get_driver("juniper_junos").vendor == "juniper"


def test_registered_device_types_includes_cisco_set() -> None:
    types = registered_device_types()
    assert "cisco_ios" in types
    assert "cisco_xe" in types
    assert "cisco_nxos" in types
    assert "cisco_nxos_ssh" in types
    assert "cisco_xr" in types
    assert "juniper_junos" in types
    assert "arista_eos" in types


def test_registry_resolves_cisco_xr() -> None:
    # Third Cisco driver after IOS / IOS-XE / NX-OS.  The Netmiko
    # device_type string for IOS-XR is ``cisco_xr``, which is what
    # routes/inventory.py and routes/snmp.py infer from XR device
    # banners + sysDescr.  Vendor tag stays ``cisco`` (XR is a Cisco
    # NOS), which groups XR with the other Cisco platforms when
    # filtering by vendor.
    assert isinstance(get_driver("cisco_xr"), CiscoXRDriver)
    assert get_driver("cisco_xr").vendor == "cisco"


def test_registry_resolves_arista_eos() -> None:
    # Second non-Cisco driver: the Netmiko device_type string for Arista
    # EOS is "arista_eos", which is what routes/inventory.py and
    # routes/snmp.py infer from EOS device banners + sysDescr.  The
    # vendor tag must be "arista" so filtering by vendor groups EOS
    # devices separately from Cisco / Juniper hosts.
    assert isinstance(get_driver("arista_eos"), AristaEOSDriver)
    assert get_driver("arista_eos").vendor == "arista"


def test_unknown_device_type_falls_back_to_generic() -> None:
    drv = get_driver("frobozz_os")
    assert isinstance(drv, GenericDriver)


def test_none_device_type_falls_back_to_generic() -> None:
    drv = get_driver(None)
    assert isinstance(drv, GenericDriver)


def test_generic_driver_raises_on_netflow_capabilities() -> None:
    drv = get_driver("frobozz_os")
    with pytest.raises(DriverCapabilityError):
        drv.build_netflow_config(_cfg())
    with pytest.raises(DriverCapabilityError):
        drv.netflow_verify_command()


def test_generic_driver_raises_on_config_capabilities() -> None:
    # The shared.py refactor depends on this: unknown vendors must raise
    # so the caller can fall back to a safe default instead of getting an
    # empty string and silently doing nothing.
    drv = get_driver("frobozz_os")
    with pytest.raises(DriverCapabilityError):
        drv.capture_running_config_command()
    with pytest.raises(DriverCapabilityError):
        drv.save_config_commands()


def test_generic_driver_raises_on_snmpv3_capabilities() -> None:
    # Mirrors the netflow + config-capture contract: a host whose
    # device_type isn't registered must produce a loud capability error
    # so the SNMPv3 playbook can refuse to push Cisco syntax at an
    # unknown vendor.
    drv = get_driver("frobozz_os")
    with pytest.raises(DriverCapabilityError):
        drv.snmpv3_show_existing_command()
    with pytest.raises(DriverCapabilityError):
        drv.snmpv3_engine_id_show_command()
    with pytest.raises(DriverCapabilityError):
        drv.snmpv3_engine_id_pin_command("ABC123")
    with pytest.raises(DriverCapabilityError):
        drv.snmpv3_verify_users_command()


def test_generic_driver_raises_on_health_check_capabilities() -> None:
    # Inventory's fetch-serial endpoint depends on this: an unknown
    # device_type must not silently fall through to a Cisco-style
    # ``show version | include System Serial Number`` and then return
    # an empty serial because the parser didn't match.  The driver
    # gap has to be obvious.
    drv = get_driver("frobozz_os")
    with pytest.raises(DriverCapabilityError):
        drv.show_version_command()
    with pytest.raises(DriverCapabilityError):
        drv.serial_number_show_command()
    with pytest.raises(DriverCapabilityError):
        drv.parse_serial_number("System Serial Number: ABC123")


def test_register_driver_rejects_duplicate_device_type() -> None:
    # Define a competing driver for an already-registered type; the
    # decorator should refuse to shadow CiscoIOSDriver.
    with pytest.raises(ValueError, match="already registered"):

        @register_driver
        class _Bogus(Driver):
            device_types = ("cisco_ios",)


def test_register_driver_requires_device_types() -> None:
    with pytest.raises(ValueError, match="device_types"):

        @register_driver
        class _Empty(Driver):
            device_types = ()


# ── cisco_ios output ────────────────────────────────────────────────────────


def test_cisco_ios_build_netflow_config_classic_shape() -> None:
    drv = get_driver("cisco_ios")
    cmds = drv.build_netflow_config(_cfg())
    # Anchors that prove this is the classic-IOS shape, not Flexible NetFlow.
    assert "ip flow-export destination 10.0.0.5 2055" in cmds
    assert "ip flow-export version 9" in cmds
    # Per-interface enablement is emitted for every interface in the input.
    assert cmds.count("ip flow ingress") == 2
    assert cmds.count("ip flow egress") == 2
    # Classic IOS has no record/exporter/monitor/sampler constructs.
    assert not any(c.startswith("flow record") for c in cmds)
    assert not any(c.startswith("flow exporter") for c in cmds)
    assert not any(c.startswith("flow monitor") for c in cmds)
    assert not any(c.startswith("sampler ") for c in cmds)


def test_cisco_ios_verify_command() -> None:
    assert get_driver("cisco_ios").netflow_verify_command() == "show ip flow export"


def test_cisco_ios_config_capture_and_save() -> None:
    drv = get_driver("cisco_ios")
    assert drv.capture_running_config_command() == "show running-config"
    assert drv.save_config_commands() == ["write memory"]


def test_cisco_ios_snmpv3_capability_surface() -> None:
    drv = get_driver("cisco_ios")
    assert drv.snmpv3_show_existing_command() == "show running-config | include snmp-server"
    assert drv.snmpv3_engine_id_show_command() == "show snmp engineID"
    assert (
        drv.snmpv3_engine_id_pin_command("80000009030050568D9CDFC0")
        == "snmp-server engineID local 80000009030050568D9CDFC0"
    )
    assert drv.snmpv3_verify_users_command() == "show snmp user"


def test_cisco_ios_health_check_capability_surface() -> None:
    drv = get_driver("cisco_ios")
    assert drv.show_version_command() == "show version"
    assert (
        drv.serial_number_show_command()
        == "show version | include System Serial Number"
    )
    # Full-line shape from a real device.
    assert (
        drv.parse_serial_number("System Serial Number              : FCW2346L0AJ")
        == "FCW2346L0AJ"
    )
    # Multi-line input with surrounding noise still resolves the right field.
    multi = (
        "Cisco IOS Software, ...\n"
        "Processor board ID FCW2346L0AJ\n"
        "System Serial Number : FCW2346L0AJ\n"
        "Switch uptime is 47 weeks, 3 days\n"
    )
    assert drv.parse_serial_number(multi) == "FCW2346L0AJ"
    # No serial line in output -> None (callers turn this into a 422).
    assert drv.parse_serial_number("Cisco IOS, no serial info.") is None


def test_cisco_ios_ignores_sampling_rate() -> None:
    # Classic IOS doesn't expose a sampler under this config style, so a
    # high sampling_rate shouldn't grow the command list.
    drv = get_driver("cisco_ios")
    base = drv.build_netflow_config(_cfg(sampling_rate=1))
    sampled = drv.build_netflow_config(_cfg(sampling_rate=1024))
    assert base == sampled


# ── cisco_xe output ─────────────────────────────────────────────────────────


def test_cisco_xe_build_netflow_config_flexible_shape() -> None:
    drv = get_driver("cisco_xe")
    cmds = drv.build_netflow_config(_cfg())
    # Flexible NetFlow anchors.
    assert "flow record PLEXUS-RECORD" in cmds
    assert "flow exporter PLEXUS-EXPORT" in cmds
    assert "flow monitor PLEXUS-MON" in cmds
    assert " destination 10.0.0.5" in cmds
    assert " transport udp 2055" in cmds
    # Per-interface monitor binding for every interface.
    assert cmds.count(" ip flow monitor PLEXUS-MON input") == 2
    # No sampler stanza without sampling.
    assert not any(c.startswith("sampler ") for c in cmds)


def test_cisco_xe_emits_sampler_when_sampling_gt_1() -> None:
    drv = get_driver("cisco_xe")
    cmds = drv.build_netflow_config(_cfg(sampling_rate=1024))
    assert "sampler PLEXUS-SAMPLER" in cmds
    assert " mode random 1 out-of 1024" in cmds
    # Sampler is also wired into each interface monitor binding.
    assert any("sampler PLEXUS-SAMPLER input" in c for c in cmds)


def test_cisco_xe_verify_command() -> None:
    assert (
        get_driver("cisco_xe").netflow_verify_command()
        == "show flow exporter PLEXUS-EXPORT"
    )


def test_cisco_xe_config_capture_and_save() -> None:
    drv = get_driver("cisco_xe")
    assert drv.capture_running_config_command() == "show running-config"
    assert drv.save_config_commands() == ["write memory"]


def test_cisco_xe_snmpv3_capability_surface() -> None:
    # IOS-XE shares the SNMPv3 command vocabulary with classic IOS;
    # the test exists as a regression guard so a future XE-specific
    # tweak doesn't silently drift away from IOS.
    drv = get_driver("cisco_xe")
    assert drv.snmpv3_show_existing_command() == "show running-config | include snmp-server"
    assert drv.snmpv3_engine_id_show_command() == "show snmp engineID"
    assert drv.snmpv3_engine_id_pin_command("AB12") == "snmp-server engineID local AB12"
    assert drv.snmpv3_verify_users_command() == "show snmp user"


def test_cisco_xe_health_check_capability_surface() -> None:
    # XE prints "System Serial Number" the same way IOS does, so the
    # capability surface is identical.  Test exists as a regression
    # guard against XE drifting away from IOS.
    drv = get_driver("cisco_xe")
    assert drv.show_version_command() == "show version"
    assert (
        drv.serial_number_show_command()
        == "show version | include System Serial Number"
    )
    assert (
        drv.parse_serial_number("System Serial Number : ABC1234WXYZ")
        == "ABC1234WXYZ"
    )


# ── cisco_nxos output ───────────────────────────────────────────────────────


def test_cisco_nxos_build_netflow_config_starts_with_feature_enable() -> None:
    drv = get_driver("cisco_nxos")
    cmds = drv.build_netflow_config(_cfg())
    # NX-OS requires the feature toggle before any flow config.
    assert cmds[0] == "feature netflow"
    assert "flow record PLEXUS-RECORD" in cmds
    assert "flow exporter PLEXUS-EXPORT" in cmds
    assert "flow monitor PLEXUS-MON" in cmds
    # NX-OS uses 'match ip protocol', not 'match ipv4 protocol' (XE).
    assert " match ip protocol" in cmds


def test_cisco_nxos_emits_sampler_when_sampling_gt_1() -> None:
    drv = get_driver("cisco_nxos")
    cmds = drv.build_netflow_config(_cfg(sampling_rate=512))
    assert "sampler PLEXUS-SAMPLER" in cmds
    # NX-OS sampler syntax is 'mode 1 out-of N' (no 'random' keyword).
    assert " mode 1 out-of 512" in cmds


def test_cisco_nxos_ssh_uses_same_driver_class() -> None:
    a = get_driver("cisco_nxos")
    b = get_driver("cisco_nxos_ssh")
    assert type(a) is type(b)


def test_cisco_nxos_verify_command() -> None:
    assert (
        get_driver("cisco_nxos").netflow_verify_command()
        == "show flow exporter PLEXUS-EXPORT"
    )


def test_cisco_nxos_config_capture_and_save() -> None:
    # NX-OS does not accept ``write memory`` - the driver must emit the
    # explicit copy command instead.  Regression-guards against someone
    # copy-pasting the IOS save in here.
    drv = get_driver("cisco_nxos")
    assert drv.capture_running_config_command() == "show running-config"
    assert drv.save_config_commands() == ["copy running-config startup-config"]


def test_cisco_nxos_snmpv3_engine_id_is_platform_managed() -> None:
    # NX-OS persists the SNMP engine ID across reloads automatically
    # and does not expose ``snmp-server engineID local`` as a knob.  Both
    # the show command and the pin command must return empty strings so
    # the playbook's pin step short-circuits.  Returning a Cisco-IOS
    # style command here would error out on the device.
    drv = get_driver("cisco_nxos")
    assert drv.snmpv3_engine_id_show_command() == ""
    assert drv.snmpv3_engine_id_pin_command("ABC") == ""
    # The show-existing and verify-users commands are still valid on
    # NX-OS, so they're populated even though the pin step isn't.
    assert drv.snmpv3_show_existing_command() == "show running-config | include snmp-server"
    assert drv.snmpv3_verify_users_command() == "show snmp user"


def test_cisco_nxos_health_check_uses_processor_board_id() -> None:
    # The meaningful divergence vs IOS/XE: NX-OS labels the chassis
    # serial "Processor Board ID" (no colon, space-separated) and the
    # include filter needs the quoted multi-word phrase to match.
    # Routing the IOS command at NX-OS would return zero rows and the
    # parser would never find a serial - this test guards that gap.
    drv = get_driver("cisco_nxos")
    assert drv.show_version_command() == "show version"
    assert (
        drv.serial_number_show_command()
        == 'show version | include "Processor Board ID"'
    )
    # Real-world NX-OS output uses a space, not a colon, after the label.
    assert (
        drv.parse_serial_number("Processor Board ID FOX1234ABCD")
        == "FOX1234ABCD"
    )
    # Some NX-OS releases print a colon variant; both shapes parse.
    assert (
        drv.parse_serial_number("Processor Board ID: FOX9999ZZZZ")
        == "FOX9999ZZZZ"
    )
    # And the "System Serial Number" wording from IOS must NOT match
    # the NX-OS parser - mixing parsers across vendors is the bug we're
    # guarding against.
    assert drv.parse_serial_number("System Serial Number : FCW2346L0AJ") is None


# ── parity with the existing netflow_enable playbook ─────────────────────────


def test_drivers_produce_identical_lines_to_existing_playbook_format() -> None:
    """Regression check: the refactor must not change the wire output.

    Phase 1's promise is "interface change only, no behavioural change."
    The simplest way to enforce that is to assert the new driver output
    matches the old per-platform builders line-for-line on a known input.
    The expected lists below were captured from the original
    ``_build_ios_commands`` / ``_build_xe_commands`` / ``_build_nxos_commands``
    helpers before they were removed.
    """
    cfg = NetflowConfig(
        collector_ip="192.0.2.10",
        collector_port=2055,
        interfaces=["GigabitEthernet0/0"],
        sampling_rate=1,
    )

    expected_ios = [
        "ip flow-export destination 192.0.2.10 2055",
        "ip flow-export version 9",
        "ip flow-export source Loopback0",
        "interface GigabitEthernet0/0",
        "ip flow ingress",
        "ip flow egress",
        "exit",
    ]
    assert get_driver("cisco_ios").build_netflow_config(cfg) == expected_ios

    expected_xe = [
        "flow record PLEXUS-RECORD",
        " match ipv4 source address",
        " match ipv4 destination address",
        " match transport source-port",
        " match transport destination-port",
        " match ipv4 protocol",
        " collect counter bytes",
        " collect counter packets",
        " collect timestamp sys-uptime first",
        " collect timestamp sys-uptime last",
        "exit",
        "flow exporter PLEXUS-EXPORT",
        " destination 192.0.2.10",
        " transport udp 2055",
        " export-protocol netflow-v9",
        " source Loopback0",
        "exit",
        "flow monitor PLEXUS-MON",
        " record PLEXUS-RECORD",
        " exporter PLEXUS-EXPORT",
        " cache timeout active 60",
        "exit",
        "interface GigabitEthernet0/0",
        " ip flow monitor PLEXUS-MON input",
        "exit",
    ]
    assert get_driver("cisco_xe").build_netflow_config(cfg) == expected_xe

    expected_nxos = [
        "feature netflow",
        "flow record PLEXUS-RECORD",
        " match ipv4 source address",
        " match ipv4 destination address",
        " match transport source-port",
        " match transport destination-port",
        " match ip protocol",
        " collect counter bytes",
        " collect counter packets",
        " collect timestamp sys-uptime first",
        " collect timestamp sys-uptime last",
        "exit",
        "flow exporter PLEXUS-EXPORT",
        " destination 192.0.2.10",
        " transport udp 2055",
        " version 9",
        " source loopback0",
        "exit",
        "flow monitor PLEXUS-MON",
        " record PLEXUS-RECORD",
        " exporter PLEXUS-EXPORT",
        "exit",
        "interface GigabitEthernet0/0",
        " ip flow monitor PLEXUS-MON input",
        "exit",
    ]
    assert get_driver("cisco_nxos").build_netflow_config(cfg) == expected_nxos


# ── juniper_junos output ────────────────────────────────────────────────────


def test_juniper_junos_build_netflow_config_uses_set_syntax() -> None:
    # The whole point of the Junos driver is to prove the framework
    # accommodates non-Cisco config syntax.  Junos NetFlow lives under
    # ``forwarding-options sampling`` + ``services flow-monitoring`` and
    # is configured as "set ..." statements, not config-mode stanzas.
    drv = get_driver("juniper_junos")
    cmds = drv.build_netflow_config(_cfg())
    # Every line should start with "set " — no Cisco-style stanza lines
    # (those start with bare keywords like "flow record" or "interface").
    assert all(c.startswith("set ") for c in cmds), cmds
    # Collector + port are baked into the flow-server line.
    assert any("flow-server 10.0.0.5 port 2055" in c for c in cmds)
    # version9 template wiring is present.
    assert any("version9 template PLEXUS-RECORD" in c for c in cmds)
    # Per-interface family-inet sampling is enabled for every interface
    # in the input (both directions).
    assert sum("family inet sampling input" in c for c in cmds) == 2
    assert sum("family inet sampling output" in c for c in cmds) == 2


def test_juniper_junos_netflow_respects_sampling_rate() -> None:
    # Unlike classic IOS, Junos exposes a native sampling rate knob, so
    # the driver must honour cfg.sampling_rate (passing rate=1 means
    # "sample every packet"; rate=1024 means "1 in 1024").
    drv = get_driver("juniper_junos")
    base = drv.build_netflow_config(_cfg(sampling_rate=1))
    sampled = drv.build_netflow_config(_cfg(sampling_rate=1024))
    assert any("input rate 1" in c for c in base)
    assert any("input rate 1024" in c for c in sampled)
    # No-sampling and high-sampling configs differ only in the rate line
    # — the rest of the surface area is identical, which guards against
    # accidentally tying other knobs (template, instance) to the rate.
    base_norm = [c for c in base if "input rate" not in c]
    sampled_norm = [c for c in sampled if "input rate" not in c]
    assert base_norm == sampled_norm


def test_juniper_junos_verify_command() -> None:
    # Junos has no direct analogue of "show flow exporter X"; the
    # closest "is my sampling configured and accepted?" check is
    # show forwarding-options sampling.
    assert (
        get_driver("juniper_junos").netflow_verify_command()
        == "show forwarding-options sampling"
    )


def test_juniper_junos_config_capture_and_save() -> None:
    drv = get_driver("juniper_junos")
    # `| display set` produces the discrete-set-statements form, which
    # is what Plexus's diff/backup code consumes (line-oriented text,
    # not the curly-brace tree).
    assert drv.capture_running_config_command() == "show configuration | display set"
    # Junos persists via ``commit`` (handled by Netmiko's save_config()),
    # so there is no extra save step here.  Empty list — not None —
    # because the playbook's iter-over-save-commands loop must work.
    assert drv.save_config_commands() == []


def test_juniper_junos_snmpv3_capability_surface() -> None:
    drv = get_driver("juniper_junos")
    # Existing-config dump uses the Junos config form (set lines under
    # the snmp stanza), not the Cisco include-snmp-server filter.
    assert (
        drv.snmpv3_show_existing_command()
        == "show configuration snmp | display set"
    )
    # Engine ID is platform-managed on Junos (same model as NX-OS): both
    # show and pin return empty strings so pin_snmp_engine_id() emits its
    # short-circuit info event instead of running a Cisco-shaped command
    # against the Junos device.
    assert drv.snmpv3_engine_id_show_command() == ""
    assert drv.snmpv3_engine_id_pin_command("ABC123") == ""
    # Verify-users uses the Junos-flavoured "show snmp v3 user", which
    # is meaningfully different from Cisco's "show snmp user".  Routing
    # the Cisco command at Junos returns a parse error, so this is a
    # regression guard against someone copy-pasting from cisco_ios.py.
    assert drv.snmpv3_verify_users_command() == "show snmp v3 user"


def test_juniper_junos_health_check_capability_surface() -> None:
    drv = get_driver("juniper_junos")
    # show version is unmodified on Junos.
    assert drv.show_version_command() == "show version"
    # Serial filter anchors on the "Chassis" row of ``show chassis
    # hardware`` — that's the row that carries the chassis-level serial.
    assert drv.serial_number_show_command() == "show chassis hardware | match Chassis"

    # Real Junos ``show chassis hardware`` rows are whitespace-aligned.
    # The Chassis row carries empty Version + Part-number columns, so
    # the serial is the first alphanumeric token of length >= 6.
    junos_output = (
        "Hardware inventory:\n"
        "Item             Version  Part number  Serial number     Description\n"
        "Chassis                                JN12345AB         EX4300-48T\n"
        "Routing Engine 0 REV 06   750-054855   AB1234567890      RE-EX4300-48T\n"
    )
    assert drv.parse_serial_number(junos_output) == "JN12345AB"

    # Cisco's "System Serial Number" wording must NOT match the Junos
    # parser - cross-vendor parser mixups are exactly the bug class the
    # driver framework exists to prevent.
    assert drv.parse_serial_number("System Serial Number : FCW2346L0AJ") is None

    # No Chassis row at all -> None (route handler converts to 422).
    assert drv.parse_serial_number("Hardware inventory:\nItem ... Description\n") is None


def test_juniper_junos_parse_serial_ignores_engine_chassis_lines() -> None:
    # Sub-component rows like "Routing Engine 0" or "FPC 0" can include
    # the word "chassis" inside their description text.  The parser
    # only accepts lines that *start* with "Chassis " (the literal
    # top-of-table label), not lines that merely contain it - otherwise
    # we'd return an FPC's serial as the chassis serial.
    drv = get_driver("juniper_junos")
    misleading = (
        "Routing Engine 0  REV 06  750-054855  RE9999  chassis controller\n"
        "FPC 0             REV 32  750-054850  AAAAAA  Chassis FPC\n"
    )
    assert drv.parse_serial_number(misleading) is None


# ── software upgrade capability surface ─────────────────────────────────────


def test_cisco_xe_install_add_command_uses_full_path() -> None:
    # IOS-XE install-mode add takes the device-side full path; the
    # driver shouldn't second-guess the caller's path format (flash:
    # vs bootflash:/ vs slot0:) — it just stitches it into the command.
    drv = get_driver("cisco_xe")
    assert (
        drv.upgrade_install_add_command("flash:cat9k_iosxe.17.09.04a.SPA.bin")
        == "install add file flash:cat9k_iosxe.17.09.04a.SPA.bin"
    )


def test_cisco_xe_activate_returns_prompt_level_none() -> None:
    # The "prompt-level none" suffix is what suppresses the interactive
    # y/n confirmation so the command can be sent non-interactively
    # before the reload drops the SSH session.  A driver that drops
    # this suffix would hang every upgrade.
    drv = get_driver("cisco_xe")
    cmds = drv.upgrade_activate_commands("flash:cat9k_iosxe.17.09.04a.SPA.bin")
    assert cmds == ["install activate prompt-level none"]


def test_cisco_xe_commit_command() -> None:
    # Without "install commit" IOS-XE auto-rolls-back on the next reload,
    # silently undoing the upgrade.  Regression guard against returning
    # an empty string here.
    assert get_driver("cisco_xe").upgrade_commit_command() == "install commit"


def test_cisco_ios_does_not_implement_install_mode() -> None:
    # Classic IOS uses copy + boot-system + reload, not install mode.
    # The Plexus upgrade route only knows the install-mode flow, so the
    # IOS driver intentionally leaves these unimplemented - a classic-IOS
    # host attempting upgrade should fail loudly, not silently send
    # IOS-XE syntax that classic IOS doesn't parse.
    drv = get_driver("cisco_ios")
    with pytest.raises(DriverCapabilityError):
        drv.upgrade_install_add_command("flash:image.bin")
    with pytest.raises(DriverCapabilityError):
        drv.upgrade_activate_commands("flash:image.bin")
    with pytest.raises(DriverCapabilityError):
        drv.upgrade_commit_command()


def test_cisco_nxos_upgrade_is_single_phase() -> None:
    # NX-OS collapses add+activate+commit into a single ``install all
    # nxos <image>`` operation; there is no "staged but not yet
    # activated" state to land in.  ``upgrade_has_discrete_prestage()``
    # must return False so the upgrade route skips the install-add
    # prestage call (same shape as Junos - sending IOS-XE's ``install
    # add file`` at an NX-OS session would parse-error).
    drv = get_driver("cisco_nxos")
    assert drv.upgrade_has_discrete_prestage() is False
    # No discrete prestage means upgrade_install_add_command should
    # still raise - the route never calls it for a single-phase
    # platform but the contract is "raise unless you implement it".
    with pytest.raises(DriverCapabilityError):
        drv.upgrade_install_add_command("bootflash:image.bin")


def test_cisco_nxos_activate_uses_install_all_nxos() -> None:
    # ``install all nxos <path>`` is the canonical single-command
    # upgrade verb for NX-OS.  Regression guard against accidentally
    # swapping in IOS-XE's ``install activate`` (which NX-OS parses
    # as "install all" + garbage) or dropping the ``nxos`` keyword
    # (which selects a target image set; without it the platform
    # prompts interactively and the SSH session hangs before reload).
    drv = get_driver("cisco_nxos")
    cmds = drv.upgrade_activate_commands("bootflash:nxos.10.3.4a.M.bin")
    assert cmds == ["install all nxos bootflash:nxos.10.3.4a.M.bin"]


def test_cisco_nxos_activate_preserves_caller_path_format() -> None:
    # NX-OS accepts a couple of device-side path prefixes (bootflash:,
    # bootflash:/, volatile:) and the driver shouldn't second-guess
    # which one the caller picked - it just stitches the path into
    # the command verbatim.  Regression guard against the driver
    # silently rewriting the path prefix.
    drv = get_driver("cisco_nxos")
    cmds = drv.upgrade_activate_commands("bootflash:/nxos.10.3.4a.M.bin")
    assert cmds == ["install all nxos bootflash:/nxos.10.3.4a.M.bin"]


def test_cisco_nxos_commit_is_no_op() -> None:
    # NX-OS auto-commits the new boot variable when the device boots
    # successfully into the new image; there is no analogue to
    # IOS-XE's ``install commit``.  An empty string signals "skip
    # commit" to the route (same pattern Junos uses).
    assert get_driver("cisco_nxos").upgrade_commit_command() == ""


def test_cisco_nxos_ssh_alias_shares_upgrade_methods() -> None:
    # cisco_nxos and cisco_nxos_ssh resolve to the same driver class,
    # so the upgrade methods must produce identical output regardless
    # of which alias Netmiko's autodetect happens to pick.  Without
    # this guarantee an autodetect that returned cisco_nxos_ssh
    # instead of cisco_nxos could silently change the upgrade flow.
    a = get_driver("cisco_nxos")
    b = get_driver("cisco_nxos_ssh")
    assert a.upgrade_activate_commands("bootflash:image.bin") == \
        b.upgrade_activate_commands("bootflash:image.bin")
    assert a.upgrade_commit_command() == b.upgrade_commit_command()
    assert a.upgrade_has_discrete_prestage() == b.upgrade_has_discrete_prestage()


def test_juniper_junos_upgrade_is_single_phase() -> None:
    # Junos has no "stage now, activate later" workflow: ``request
    # system software add`` validates + lays down + reboots in one
    # operation.  ``upgrade_has_discrete_prestage()`` must return
    # False so the upgrade route skips the install-add prestage call
    # (otherwise the route would try to run install-add against a
    # Junos session, the driver would raise DriverCapabilityError,
    # and the operator would see a misleading "pre-stage not
    # supported" error for a platform that simply doesn't need it).
    drv = get_driver("juniper_junos")
    assert drv.upgrade_has_discrete_prestage() is False
    # No discrete prestage means upgrade_install_add_command should
    # still raise - the route never calls it for a single-phase
    # platform but the contract is "raise unless you implement it".
    with pytest.raises(DriverCapabilityError):
        drv.upgrade_install_add_command("/var/tmp/jinstall.tgz")


def test_juniper_junos_activate_uses_single_combined_command() -> None:
    # The Junos activate is a single command that validates, adds, and
    # reboots in one shot.  ``no-validate`` is critical for non-
    # interactive execution (without it Junos prompts for cross-platform
    # validation confirmation and blocks the SSH session); the inline
    # ``reboot`` keyword skips a second "reboot the system?" prompt.
    # Both keywords being present is a regression guard - drop either
    # and every Junos upgrade hangs at a prompt.
    drv = get_driver("juniper_junos")
    cmds = drv.upgrade_activate_commands("/var/tmp/jinstall-host-arm-22.4R3.tgz")
    assert cmds == [
        "request system software add /var/tmp/jinstall-host-arm-22.4R3.tgz "
        "no-validate reboot"
    ]


def test_juniper_junos_commit_is_no_op() -> None:
    # Junos persists the new image automatically on reboot - there is
    # no operator-visible commit knob analogous to IOS-XE's ``install
    # commit``.  An empty string signals "skip commit" to the route.
    assert get_driver("juniper_junos").upgrade_commit_command() == ""


def test_cisco_xe_has_discrete_prestage() -> None:
    # IOS-XE install mode has a real two-phase workflow that the route
    # exploits to let the operator approve activate-and-reboot in a
    # maintenance window after the slow upload finishes.  Flipping this
    # to False would collapse the two phases into one and remove the
    # approval gate from the upgrade flow.
    assert get_driver("cisco_xe").upgrade_has_discrete_prestage() is True


def test_single_phase_default_for_drivers_without_install_mode() -> None:
    # Drivers that don't override ``upgrade_has_discrete_prestage``
    # inherit the base False default - that's the right behaviour for
    # any platform whose vendor verbs collapse add+activate (classic
    # IOS, NX-OS, Junos).  Inverting this default would force every
    # new vendor driver to implement a prestage step even when its
    # vendor model doesn't have one.
    assert get_driver("cisco_ios").upgrade_has_discrete_prestage() is False
    assert get_driver("cisco_nxos").upgrade_has_discrete_prestage() is False
    assert get_driver("arista_eos").upgrade_has_discrete_prestage() is False
    assert get_driver("frobozz_os").upgrade_has_discrete_prestage() is False


def test_generic_driver_upgrade_methods_raise() -> None:
    # Unknown vendor: every upgrade entry point must raise so the route
    # handler reports "no driver" rather than silently sending Cisco
    # syntax over the SSH session.
    drv = get_driver("frobozz_os")
    with pytest.raises(DriverCapabilityError):
        drv.upgrade_install_add_command("flash:image")
    with pytest.raises(DriverCapabilityError):
        drv.upgrade_activate_commands("flash:image")
    with pytest.raises(DriverCapabilityError):
        drv.upgrade_commit_command()


# ── arista_eos output ───────────────────────────────────────────────────────


def test_arista_eos_build_netflow_config_uses_flow_tracking() -> None:
    # EOS uses ``flow tracking hardware`` / ``tracker`` / ``exporter``
    # nested stanzas rather than Cisco's flat ``flow record`` + ``flow
    # exporter`` + ``flow monitor`` triad.  Emitting Cisco Flexible
    # NetFlow lines at an EOS session would parse-error on the very
    # first ``flow record`` line, so the regression guard is that the
    # output starts with the EOS top-level anchor and never contains
    # the Cisco ``flow record`` or ``flow monitor`` keywords.
    drv = get_driver("arista_eos")
    cmds = drv.build_netflow_config(_cfg())
    assert cmds[0] == "flow tracking hardware"
    # Tracker, exporter, and collector wiring all present.
    joined = "\n".join(cmds)
    assert "tracker PLEXUS-MON" in joined
    assert "exporter PLEXUS-EXPORT" in joined
    assert "collector 10.0.0.5 port 2055" in joined
    # Cisco's Flexible NetFlow shapes must not leak in.
    assert "flow record" not in joined
    assert "flow monitor" not in joined
    # Per-interface attachment uses the EOS ``flow tracker hardware``
    # noun, not Cisco's ``ip flow monitor``.
    assert "flow tracker hardware PLEXUS-MON" in joined
    assert "ip flow monitor" not in joined


def test_arista_eos_netflow_includes_each_interface() -> None:
    # Each requested interface must get its own per-interface stanza.
    # A regression where only the first interface is bound would
    # silently lose visibility on every other monitored port.
    drv = get_driver("arista_eos")
    cmds = drv.build_netflow_config(
        _cfg(interfaces=["Ethernet1", "Ethernet2", "Ethernet48"])
    )
    joined = "\n".join(cmds)
    assert "interface Ethernet1" in joined
    assert "interface Ethernet2" in joined
    assert "interface Ethernet48" in joined


def test_arista_eos_netflow_respects_sampling_rate() -> None:
    # The sample rate must flow through to a ``sample N`` line; the
    # rest of the output must be otherwise identical.  This is a
    # regression guard against accidentally coupling other knobs
    # (timeouts, template interval) to the sample-rate field.
    drv = get_driver("arista_eos")
    low = drv.build_netflow_config(_cfg(sampling_rate=1))
    high = drv.build_netflow_config(_cfg(sampling_rate=1024))
    # Both runs include a sample line, only the integer differs.
    assert "  sample 1" in low
    assert "  sample 1024" in high
    # All other lines are identical.
    diff = [a for a, b in zip(low, high) if a != b]
    assert diff == ["  sample 1"]


def test_arista_eos_verify_command() -> None:
    # ``show flow tracking hardware`` is EOS's analogue to Cisco's
    # ``show flow exporter`` - the latter does not exist on EOS and
    # would parse-error.
    assert (
        get_driver("arista_eos").netflow_verify_command()
        == "show flow tracking hardware"
    )


def test_arista_eos_config_capture_and_save() -> None:
    drv = get_driver("arista_eos")
    # EOS uses Cisco-style ``show running-config`` verbatim.
    assert drv.capture_running_config_command() == "show running-config"
    # ``copy running-config startup-config`` is Arista's documented
    # save form and matches the NX-OS driver - both datacenter
    # platforms use the explicit-copy save surface.
    assert drv.save_config_commands() == ["copy running-config startup-config"]


def test_arista_eos_snmpv3_capability_surface() -> None:
    # EOS mirrors IOS-XE's ``snmp-server`` config noun and supports
    # ``snmp-server engineID local`` pinning - unlike NX-OS and Junos,
    # which return empty strings because their engine ID is platform-
    # managed.  This test locks in that EOS gets the real pin command,
    # not the empty-string short-circuit.
    drv = get_driver("arista_eos")
    assert drv.snmpv3_show_existing_command() == "show running-config | include snmp-server"
    assert drv.snmpv3_engine_id_show_command() == "show snmp engineID"
    assert (
        drv.snmpv3_engine_id_pin_command("80000009030011AABBCCDDEE")
        == "snmp-server engineID local 80000009030011AABBCCDDEE"
    )
    assert drv.snmpv3_verify_users_command() == "show snmp user"


def test_arista_eos_health_check_capability_surface() -> None:
    drv = get_driver("arista_eos")
    assert drv.show_version_command() == "show version"
    # EOS uses lowercase-n "Serial number" with a colon, not IOS-XE's
    # "System Serial Number".  Sending the IOS filter at EOS returns
    # zero rows; sending the EOS filter at IOS returns zero rows.
    assert drv.serial_number_show_command() == "show version | include Serial number"
    # Typical EOS show-version line:
    #   "Serial number:                          JPE19450ABC"
    # Variable whitespace between the colon and the value is normal
    # across EOS releases; the parser must not assume a fixed column.
    sample = (
        "Arista DCS-7280SR-48C6-F\n"
        "Hardware version:    11.00\n"
        "Serial number:                          JPE19450ABC\n"
        "System MAC address:  001c.7300.0001\n"
    )
    assert drv.parse_serial_number(sample) == "JPE19450ABC"


def test_arista_eos_parse_serial_handles_tight_whitespace() -> None:
    # Older / minimal EOS outputs may print "Serial number: VALUE" with
    # a single space.  The parser must work regardless of how many
    # spaces follow the colon - splitting on ``:`` and stripping is
    # the right shape; anchoring on a fixed column would silently fail.
    drv = get_driver("arista_eos")
    assert drv.parse_serial_number("Serial number: ABC123XYZ\n") == "ABC123XYZ"


def test_arista_eos_parse_serial_rejects_unrelated_lines() -> None:
    # ``show version`` includes lines like "Hardware version:" that
    # share the "<label>: <value>" shape but are not the serial.  The
    # parser anchors on the leading "Serial number" phrase so those
    # lines must not match.
    drv = get_driver("arista_eos")
    noise = (
        "Hardware version:    01.00\n"
        "Software image version: 4.30.5M\n"
        "Internal build version: 4.30.5M-12345\n"
    )
    assert drv.parse_serial_number(noise) is None


def test_arista_eos_upgrade_is_single_phase() -> None:
    # EOS has no "stage now, activate later" workflow: ``install
    # source`` validates + sets the boot image, then ``reload now``
    # reboots.  ``upgrade_has_discrete_prestage()`` must return False
    # so the upgrade route's prestage helper short-circuits without
    # trying to install-add against an EOS session.
    drv = get_driver("arista_eos")
    assert drv.upgrade_has_discrete_prestage() is False
    # No discrete prestage means upgrade_install_add_command should
    # still raise - the route never calls it for a single-phase
    # platform, but the raise is defense-in-depth against a future
    # caller bypassing the gate.
    with pytest.raises(DriverCapabilityError):
        drv.upgrade_install_add_command("flash:EOS-4.30.5M.swi")


def test_arista_eos_activate_uses_install_source_then_reload_now() -> None:
    # The EOS activate is two commands: ``install source`` (validates +
    # sets boot image, synchronous) and ``reload now`` (drops the SSH
    # session).  ``reload now`` instead of bare ``reload`` skips the
    # "Save current configuration?" / "Proceed with reload?" prompts -
    # dropping the ``now`` qualifier would hang the route forever
    # waiting on those prompts.  Order matters: the route iterates the
    # list and the final command is the one expected to drop the SSH
    # session, so reload must come last.
    drv = get_driver("arista_eos")
    cmds = drv.upgrade_activate_commands("flash:EOS-4.30.5M.swi")
    assert cmds == [
        "install source flash:EOS-4.30.5M.swi",
        "reload now",
    ]


def test_arista_eos_activate_preserves_caller_path_format() -> None:
    # EOS accepts paths in several forms (``flash:``, ``flash:/``,
    # ``file:/mnt/flash/...``).  The driver passes whatever the caller
    # supplied through verbatim instead of rewriting it - a regression
    # where the driver normalized the prefix would silently change the
    # boot path on platforms where the path matters.
    drv = get_driver("arista_eos")
    cmds = drv.upgrade_activate_commands("file:/mnt/flash/EOS-4.30.5M.swi")
    assert cmds[0] == "install source file:/mnt/flash/EOS-4.30.5M.swi"


def test_arista_eos_commit_is_no_op() -> None:
    # EOS auto-persists the boot image selection once the device
    # successfully boots into the new version - no operator-visible
    # commit knob analogous to IOS-XE's ``install commit``.  Empty
    # string signals "skip commit" to the route.
    assert get_driver("arista_eos").upgrade_commit_command() == ""


# ── cisco_xr output ─────────────────────────────────────────────────────────


def test_cisco_xr_build_netflow_config_uses_xr_nouns() -> None:
    # XR NetFlow uses ``flow exporter-map`` / ``flow monitor-map`` /
    # ``sampler-map`` nouns, not IOS-XE's ``flow exporter`` / ``flow
    # monitor`` / ``sampler``.  Feeding XE Flexible NetFlow config at
    # an XR session would parse-error on the very first ``flow record``
    # line - XR has no such command.  The regression guard is that the
    # output uses the XR ``-map`` suffixes and never contains XE's
    # path-less keywords.
    drv = get_driver("cisco_xr")
    cmds = drv.build_netflow_config(_cfg())
    joined = "\n".join(cmds)
    assert "flow exporter-map PLEXUS-EXPORT" in joined
    assert "flow monitor-map PLEXUS-MON" in joined
    # XR's exporter destination + transport are inside the exporter-map
    # stanza, same shape as XE but the parent keyword differs.
    assert " destination 10.0.0.5" in cmds
    assert " transport udp 2055" in cmds
    # XE's flat noun set must not leak in.
    assert "\nflow exporter PLEXUS-EXPORT" not in "\n" + joined
    assert "\nflow monitor PLEXUS-MON" not in "\n" + joined
    assert "flow record" not in joined
    # Per-interface attachment uses ``flow ipv4 monitor ... ingress``,
    # not XE's ``ip flow monitor ... input``.
    assert " flow ipv4 monitor PLEXUS-MON ingress" in cmds
    assert "ip flow monitor" not in joined


def test_cisco_xr_netflow_includes_each_interface() -> None:
    # Each requested interface must get its own per-interface stanza.
    # A regression where only the first interface is bound would
    # silently lose visibility on every other monitored port.
    drv = get_driver("cisco_xr")
    cmds = drv.build_netflow_config(
        _cfg(interfaces=["GigabitEthernet0/0/0/0", "GigabitEthernet0/0/0/1"])
    )
    joined = "\n".join(cmds)
    assert "interface GigabitEthernet0/0/0/0" in joined
    assert "interface GigabitEthernet0/0/0/1" in joined


def test_cisco_xr_emits_sampler_when_sampling_gt_1() -> None:
    # XR's sampler-map is only emitted when sampling > 1, mirroring the
    # XE driver's pattern.  Sampling rate of 1 means "every packet" and
    # would produce a no-op sampler stanza, so the driver skips it.
    drv = get_driver("cisco_xr")
    low = drv.build_netflow_config(_cfg(sampling_rate=1))
    high = drv.build_netflow_config(_cfg(sampling_rate=1024))
    assert "sampler-map PLEXUS-SAMPLER" not in low
    assert "sampler-map PLEXUS-SAMPLER" in high
    # When sampling fires, the rate flows into ``random 1 out-of N``.
    assert " random 1 out-of 1024" in high
    # And the per-interface attachment picks up the sampler reference.
    assert any("sampler PLEXUS-SAMPLER ingress" in c for c in high)


def test_cisco_xr_verify_command() -> None:
    # ``show flow exporter-map`` is the XR analogue to XE's ``show
    # flow exporter``.  The XE wording (no ``-map`` suffix) does not
    # exist on XR and parse-errors.
    assert (
        get_driver("cisco_xr").netflow_verify_command()
        == "show flow exporter-map PLEXUS-EXPORT"
    )


def test_cisco_xr_config_capture_and_save() -> None:
    # XR is commit-based: ``show running-config`` dumps the active
    # committed config, but pushing config requires ``commit`` for it
    # to take effect.  Without commit, candidate edits sit pending
    # forever - an empty save_config_commands list would silently
    # leave SNMPv3 / NetFlow changes uncommitted.
    drv = get_driver("cisco_xr")
    assert drv.capture_running_config_command() == "show running-config"
    assert drv.save_config_commands() == ["commit"]
    # Regression guard: XR must not emit IOS / IOS-XE's ``write memory``
    # or NX-OS's ``copy running-config startup-config`` - those are not
    # XR commands and would parse-error.
    assert drv.save_config_commands() != ["write memory"]
    assert drv.save_config_commands() != ["copy running-config startup-config"]


def test_cisco_xr_snmpv3_capability_surface() -> None:
    # XR mirrors IOS-XE's ``snmp-server`` config noun and supports
    # ``snmp-server engineID local`` pinning - unlike NX-OS / Junos,
    # which return empty strings because their engine ID is platform-
    # managed.  This test locks in that XR gets the real pin command
    # (matching IOS / IOS-XE / EOS).  Without pinning, an engine-ID
    # regen on XR would localize-invalidate every existing SNMPv3
    # user, same risk as on IOS-XE.
    drv = get_driver("cisco_xr")
    assert drv.snmpv3_show_existing_command() == "show running-config | include snmp-server"
    # XR's show form uses lowercase ``engineid`` (XR's CLI completion
    # shows the lowercase form), different from XE's ``engineID``.
    assert drv.snmpv3_engine_id_show_command() == "show snmp engineid"
    assert (
        drv.snmpv3_engine_id_pin_command("80000009030022FFEE11AABB")
        == "snmp-server engineID local 80000009030022FFEE11AABB"
    )
    assert drv.snmpv3_verify_users_command() == "show snmp user"


def test_cisco_xr_health_check_capability_surface() -> None:
    drv = get_driver("cisco_xr")
    assert drv.show_version_command() == "show version"
    # XR labels the serial ``Serial Number`` (capital N) with a colon -
    # different from EOS's lowercase-n ``Serial number:`` and from
    # IOS / IOS-XE's ``System Serial Number``.  The quoted phrase
    # matters because XR's include filter is case-sensitive by default.
    assert drv.serial_number_show_command() == 'show version | include "Serial Number"'
    # Typical XR show-version line:
    #   ``Serial Number   : FOX2436A0XX``
    # (label + variable whitespace + colon + variable whitespace +
    # value, same general shape as IOS-XE but with the different label
    # casing).
    sample = (
        "Cisco IOS XR Software, Version 7.5.2\n"
        "ROM: System Bootstrap, Version 1.10\n"
        "Serial Number   : FOX2436A0XX\n"
        "Chassis : ASR-9006-AC-V2\n"
    )
    assert drv.parse_serial_number(sample) == "FOX2436A0XX"


def test_cisco_xr_parse_serial_is_case_sensitive_vs_eos() -> None:
    # The case-sensitivity is the explicit boundary between the XR
    # parser and the EOS parser - both platforms label the same field
    # but differ only in the capitalisation of "Number" / "number".
    # A future refactor that switches to ``.lower()`` would silently
    # start accepting EOS-shaped lines, and cross-vendor parser mixups
    # are exactly the bug class the driver framework exists to prevent.
    drv = get_driver("cisco_xr")
    # EOS-shaped line (lowercase ``number``) must NOT match the XR
    # parser even though the value looks valid - if it matched, an
    # XR fetch-serial against a mis-classified EOS device would return
    # bogus data instead of None.
    assert drv.parse_serial_number("Serial number: ABC123XYZ\n") is None
    # IOS / IOS-XE wording must also not match XR.
    assert drv.parse_serial_number("System Serial Number : FCW2346L0AJ") is None


def test_cisco_xr_parse_serial_rejects_unrelated_lines() -> None:
    # XR's ``show version`` includes lines like ``System image file is``
    # and ``Cisco IOS XR Software, Version`` that do not contain the
    # ``Serial Number`` phrase.  The parser must anchor on the leading
    # phrase so those lines don't accidentally produce a serial.
    drv = get_driver("cisco_xr")
    noise = (
        "Cisco IOS XR Software, Version 7.5.2\n"
        "System image file is harddisk:asr9k-mini-x64-7.5.2.iso\n"
        "Configuration register is 0x2102\n"
    )
    assert drv.parse_serial_number(noise) is None


def test_cisco_xr_upgrade_has_discrete_prestage() -> None:
    # XR install mode has a real two-phase workflow: ``install add
    # source`` pre-stages packages into the install repository, then
    # ``install activate`` later flips to them and reboots.  The route
    # uses this to keep transfer / add distinct from activate-and-reboot
    # so the operator can approve activate in a maintenance window
    # after the slow upload finishes (same shape as IOS-XE install
    # mode).  Flipping this to False would collapse the two phases
    # into one and remove the approval gate from the XR upgrade flow.
    assert get_driver("cisco_xr").upgrade_has_discrete_prestage() is True


def test_cisco_xr_install_add_command_uses_source_keyword() -> None:
    # The ``source`` keyword is required - without it XR interprets
    # the command as ``install add`` with a missing argument and
    # prompts interactively.  Regression guard against dropping the
    # keyword and hanging every XR upgrade at a prompt.  ``image_path``
    # is the device-side full path (e.g. ``harddisk:asr9k-...iso``);
    # the driver doesn't second-guess the caller's path format.
    drv = get_driver("cisco_xr")
    assert (
        drv.upgrade_install_add_command("harddisk:asr9k-mini-x64-7.5.2.iso")
        == "install add source harddisk:asr9k-mini-x64-7.5.2.iso"
    )


def test_cisco_xr_install_add_preserves_caller_path_format() -> None:
    # XR's filesystem is ``harddisk:`` or ``disk0:`` rather than
    # IOS-XE's ``flash:``, but the driver does not normalize the
    # caller's prefix.  Regression guard against silently rewriting
    # the path - if the caller picked ``disk0:`` for a reason (e.g.
    # the active boot disk on this chassis differs from the default),
    # the driver must not change it to ``harddisk:``.
    drv = get_driver("cisco_xr")
    assert (
        drv.upgrade_install_add_command("disk0:asr9k-mini-x64-7.5.2.iso")
        == "install add source disk0:asr9k-mini-x64-7.5.2.iso"
    )


def test_cisco_xr_activate_uses_synchronous_keyword() -> None:
    # Bare ``install activate`` activates all newly-added inactive
    # packages - no op-ID argument needed when stage and activate run
    # back-to-back in the route.  ``synchronous`` makes the command
    # block until activate completes (or the reload drops the SSH
    # session), which is the XR equivalent of XE's ``prompt-level
    # none`` - both suppress the interactive prompt that would
    # otherwise hang the route.  Image path is not interpolated
    # because the activate operates on whatever was just added.
    drv = get_driver("cisco_xr")
    cmds = drv.upgrade_activate_commands("harddisk:asr9k-mini-x64-7.5.2.iso")
    assert cmds == ["install activate synchronous"]
    # XE's ``prompt-level none`` noun must not leak into XR - it's
    # not a valid XR keyword and would parse-error.
    assert "prompt-level" not in cmds[0]


def test_cisco_xr_commit_command() -> None:
    # Without ``install commit`` an XR box auto-rolls-back to the
    # prior image on the *next* reload, silently undoing the upgrade.
    # Same risk and same fix as IOS-XE install mode.  Regression guard
    # against returning an empty string here (which would short-circuit
    # the commit step in the route and leave XR pending auto-rollback).
    assert get_driver("cisco_xr").upgrade_commit_command() == "install commit"
