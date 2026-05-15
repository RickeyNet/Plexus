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
from netcontrol.drivers.cisco_ios import CiscoIOSDriver
from netcontrol.drivers.cisco_nxos import CiscoNXOSDriver
from netcontrol.drivers.cisco_xe import CiscoXEDriver


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


def test_registered_device_types_includes_cisco_set() -> None:
    types = registered_device_types()
    assert "cisco_ios" in types
    assert "cisco_xe" in types
    assert "cisco_nxos" in types
    assert "cisco_nxos_ssh" in types


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
