"""Netgear support: the managed switch driver (SSH) and the SNMP-only smart
switch and access point types.

The table samples are invented switch output in the form the managed
switches print (the Broadcom ICOS tables), parsed by the ntc-templates the
driver names, so the driver is checked against the rows it really receives.
"""

from __future__ import annotations

import pytest
from netcontrol.drivers import (
    DriverCapabilityError,
    get_driver,
    registered_device_types,
    session_platform,
    supports_cli,
    supports_config_capture,
)
from netcontrol.drivers.netgear import NetgearAccessPointDriver, NetgearManagedDriver, NetgearSmartSwitchDriver
from netcontrol.drivers.show_version import parse_show_version
from netcontrol.integrations.inventory_import import capabilities
from netcontrol.integrations.software.versions import PLATFORMS, classify_host
from netcontrol.routes.snmp import _infer_device_category, _infer_vendor_os_from_text, _parse_model_and_version
from ntc_templates.parse import parse_output

VLANS = """
VLAN ID VLAN Name                        VLAN Type
------- -------------------------------- -------------------
1       default                          Default
10      USERS                            Static
30      PRINTERS                         Static
"""

MACS = """
VLAN ID  MAC Address         Interface  IfIndex  Status
-------  ------------------  ---------  -------  ------------
1        00:00:5E:00:53:01   0/5/1      1601     Management
10       00:00:5E:00:53:A1   1/0/1      1        Learned
30       00:00:5E:00:53:A2   1/0/2      2        Static
"""

LLDP = """
LLDP Remote Device Summary

Local
Interface  RemID   Chassis ID            Port ID             System Name
---------  ------  --------------------  ------------------  ------------------
1/0/1      3       00:00:5E:00:53:10     Gi1/0/24            core-sw-01
1/0/2
1/0/3      5       00:00:5E:00:53:20     00:00:5E:00:53:21
"""

ISDP = """
Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge,
                  S - Switch, H - Host, I - IGMP, r - Repeater

Device ID                Intf      Holdtime  Capability Platform         Port ID
------------------------ --------- --------- ---------- ---------------- ---------
core-sw-01.example.com   1/0/1     150       S I        cisco WS-C3750X  GigabitEthernet1/0/24
"""

SHOW_VERSION = """
Switch: 1

System Description............................. M4300-28G ProSAFE 24-port 1G and 2-port 10GBASE-T and 2-port 10G SFP+, 12.0.17.6, B1.0.0.17
Machine Type................................... M4300-28G ProSAFE 24-port 1G and 2-port 10GBASE-T and 2-port 10G SFP+
Machine Model.................................. M4300-28G
Serial Number.................................. EXAMPLE0SERIAL
Burned In MAC Address.......................... 00:00:5E:00:53:01
Software Version............................... 12.0.17.6
Bootcode Version............................... B1.0.0.17
"""

MANAGED_DESCR = "M4300-28G ProSAFE 24-port 1G and 2-port 10GBASE-T and 2-port 10G SFP+, 12.0.17.6, B1.0.0.17"
M4250_DESCR = "M4250-10G2F-PoE+ 8x1G PoE+ 125W and 2x1G and 2xSFP Managed Switch, 13.0.4.26, 1.0.0.11"
SMART_DESCR = "GS724Tv4 ProSafe 24-port Gigabit Ethernet Smart Switch, 6.3.1.33, B1.0.0.4"


class _FakeConn:
    """A session that prints ``outputs[command]`` and records how it was asked."""

    def __init__(self, outputs: dict[str, str]) -> None:
        self.outputs = outputs
        self.calls: list[tuple[str, dict]] = []

    def send_command(self, command: str, **kwargs):
        self.calls.append((command, kwargs))
        return self.outputs.get(command, "")


def _rows(command: str, text: str) -> list[dict]:
    rows = parse_output(platform="broadcom_icos", command=command, data=text)
    assert rows, f"no template parsed {command!r}"
    return rows


# ── Registry and session ─────────────────────────────────────────────────────


def test_registry_resolves_the_netgear_types():
    assert isinstance(get_driver("netgear_prosafe"), NetgearManagedDriver)
    assert isinstance(get_driver("netgear_smart"), NetgearSmartSwitchDriver)
    assert isinstance(get_driver("netgear_ap"), NetgearAccessPointDriver)
    assert {"netgear_prosafe", "netgear_smart", "netgear_ap"} <= set(registered_device_types())
    assert {get_driver(t).vendor for t in ("netgear_prosafe", "netgear_smart", "netgear_ap")} == {"netgear"}


def test_a_managed_switch_keeps_its_netmiko_class_and_borrows_the_icos_templates():
    assert session_platform("netgear_prosafe") == "netgear_prosafe"
    assert get_driver("netgear_prosafe").template_platform == "broadcom_icos"
    assert get_driver("cisco_xe").template_platform is None


def test_send_parsed_reads_the_templates_of_the_driver_platform():
    pytest.importorskip("netmiko")
    from netcontrol.routes.shared import _send_parsed

    driver = get_driver("netgear_prosafe")
    conn = _FakeConn({"show vlan brief": VLANS, "show clock": "12:00:00"})
    rows = _send_parsed(conn, "show vlan brief", driver, read_timeout=30)
    assert [row["vlan_id"] for row in rows] == ["1", "10", "30"]
    # The raw output is asked for: Netmiko would look under "netgear_prosafe".
    assert conn.calls == [("show vlan brief", {"read_timeout": 30})]
    # No template: the raw text, as Netmiko's own use_textfsm returns.
    assert _send_parsed(conn, "show clock", driver) == "12:00:00"
    # A driver without a template platform is parsed by Netmiko.
    _send_parsed(conn, "show vlan brief", get_driver("cisco_xe"))
    assert conn.calls[-1] == ("show vlan brief", {"use_textfsm": True})


# ── Managed switch ───────────────────────────────────────────────────────────


def test_managed_commands():
    driver = get_driver("netgear_prosafe")
    routes = driver.route_table_commands()
    assert (routes.summary, routes.table, routes.all_vrfs) == (None, "show ip route", None)
    assert driver.capture_running_config_command() == "show running-config"
    assert driver.capture_full_config_command() == "show running-config all"
    assert driver.save_config_commands() == ["write memory confirm"]
    assert driver.vlan_show_command() == "show vlan brief"
    assert driver.mac_table_show_command() == "show mac-addr-table"
    assert driver.neighbor_show_commands() == [
        ("cdp", "show isdp neighbors"),
        ("lldp", "show lldp remote-device all"),
    ]
    assert supports_cli("netgear_prosafe") and supports_config_capture("netgear_prosafe")
    # Not implemented: reported, not sent as another vendor's commands.
    for capability in (driver.interface_status_show_command, driver.snmpv3_show_existing_command):
        with pytest.raises(DriverCapabilityError):
            capability()


def test_managed_vlans():
    vlans = get_driver("netgear_prosafe").parse_vlans(_rows("show vlan brief", VLANS))
    assert vlans == [
        {"vlan_id": 1, "name": "default", "state": "active"},
        {"vlan_id": 10, "name": "USERS", "state": "active"},
        {"vlan_id": 30, "name": "PRINTERS", "state": "active"},
    ]


def test_managed_mac_table_leaves_out_the_switch_itself():
    macs = get_driver("netgear_prosafe").parse_mac_table(_rows("show mac-addr-table", MACS))
    assert macs == [
        {"mac": "00:00:5e:00:53:a1", "vlan": 10, "port": "1/0/1", "type": "dynamic"},
        {"mac": "00:00:5e:00:53:a2", "vlan": 30, "port": "1/0/2", "type": "static"},
    ]


def test_managed_neighbors():
    driver = get_driver("netgear_prosafe")
    lldp = driver.parse_neighbors("lldp", _rows("show lldp remote-device all", LLDP))
    # A port without a neighbor and a neighbor without a name are left out.
    assert [(n["local_interface"], n["remote_device_name"], n["remote_interface"]) for n in lldp] == [
        ("1/0/1", "core-sw-01", "Gi1/0/24")
    ]
    assert lldp[0]["protocol"] == "lldp" and lldp[0]["remote_ip"] == ""
    isdp = driver.parse_neighbors("cdp", _rows("show isdp neighbors", ISDP))
    assert len(isdp) == 1
    assert isdp[0]["local_interface"] == "1/0/1" and isdp[0]["remote_device_name"] == "core-sw-01.example.com"
    assert isdp[0]["remote_interface"] == "GigabitEthernet1/0/24" and isdp[0]["protocol"] == "cdp"
    assert isdp[0]["remote_platform"] == "cisco WS-C3750X"


def test_managed_serial_and_show_version():
    driver = get_driver("netgear_prosafe")
    assert driver.show_version_command() == driver.serial_number_show_command() == "show version"
    assert driver.parse_serial_number(SHOW_VERSION) == "EXAMPLE0SERIAL"
    assert driver.parse_serial_number("") is None
    facts = parse_show_version(SHOW_VERSION)
    assert facts.os_device_type == "netgear_prosafe"
    assert (facts.model, facts.software_version, facts.serial_number) == ("M4300-28G", "12.0.17.6", "EXAMPLE0SERIAL")
    # Another vendor's ICOS switch prints the same fields and is not taken for Netgear.
    other = SHOW_VERSION.replace("M4300-28G", "AS4610-54P").replace("ProSAFE", "Example")
    assert parse_show_version(other).os_device_type is None


def test_inventory_collection_reads_the_tables_with_the_icos_templates():
    pytest.importorskip("netmiko")
    from netcontrol.routes import inventory_collection

    driver = inventory_collection._table_driver("netgear_prosafe")
    conn = _FakeConn({"show vlan brief": VLANS, "show mac-addr-table": MACS, "show lldp remote-device all": LLDP})
    assert [v["vlan_id"] for v in inventory_collection._read_vlans(conn, driver, None)] == [1, 10, 30]
    assert [m["port"] for m in inventory_collection._read_macs(conn, driver)] == ["1/0/1", "1/0/2"]
    # ISDP printed nothing (off, or no Cisco neighbor): the LLDP neighbors are still read.
    assert [n["remote_device_name"] for n in inventory_collection._read_neighbors(conn, driver)] == ["core-sw-01"]
    # The port table has no command: skipped without an error entry.
    outcome: dict = {"errors": []}
    inventory_collection._read_part(
        outcome, "interfaces", "Port table", lambda: inventory_collection._read_interfaces(conn, driver)
    )
    assert outcome == {"errors": []}


# ── Smart switches and access points: SNMP only ──────────────────────────────


@pytest.mark.parametrize("device_type", ["netgear_smart", "netgear_ap"])
def test_smart_switches_and_access_points_have_no_command_line(device_type, monkeypatch):
    netmiko = pytest.importorskip("netmiko")
    from netcontrol.routes import inventory_collection
    from netcontrol.routes.shared import _open_netmiko_session

    assert not supports_cli(device_type) and not supports_config_capture(device_type)
    assert capabilities(device_type) == {"snmp_polling": True, "config_backup": False}
    assert not inventory_collection._collectable({"device_type": device_type})
    driver = get_driver(device_type)
    for capability in (driver.mac_table_show_command, driver.show_version_command, driver.route_table_commands):
        with pytest.raises(DriverCapabilityError):
            capability()

    def _never(**_kw):
        raise AssertionError("an SSH session was opened")

    monkeypatch.setattr(netmiko, "ConnectHandler", _never)
    host = {"ip_address": "192.0.2.40", "device_type": device_type}
    with pytest.raises(DriverCapabilityError, match="no command line"):
        _open_netmiko_session(host, {"username": "plexus", "password": "x", "secret": ""})


# ── SNMP detection and software platforms ────────────────────────────────────


@pytest.mark.parametrize(
    ("sys_descr", "device_type", "os_name", "model", "version", "category"),
    [
        (MANAGED_DESCR, "netgear_prosafe", "netgear-managed", "M4300-28G", "12.0.17.6", "switch"),
        (M4250_DESCR, "netgear_prosafe", "netgear-managed", "M4250-10G2F-PoE+", "13.0.4.26", "switch"),
        (
            "NETGEAR XSM4348CS 48-Port 10G Managed Switch",
            "netgear_prosafe",
            "netgear-managed",
            "XSM4348CS",
            "",
            "switch",
        ),
        (SMART_DESCR, "netgear_smart", "netgear-smart", "GS724Tv4", "6.3.1.33", "switch"),
        (
            "NETGEAR MS510TXPP Smart Managed Pro Switch, 1.0.4.9",
            "netgear_smart",
            "netgear-smart",
            "MS510TXPP",
            "1.0.4.9",
            "switch",
        ),
        ("WAX620", "netgear_ap", "netgear-ap", "WAX620", "", "wireless"),
        ("NETGEAR Insight Managed WiFi 6 Access Point", "netgear_ap", "netgear-ap", "", "", "wireless"),
    ],
)
def test_snmp_sys_descr_names_the_netgear_line(sys_descr, device_type, os_name, model, version, category):
    assert _infer_vendor_os_from_text(sys_descr) == ("netgear", device_type, os_name)
    assert _parse_model_and_version(sys_descr) == (model, version)
    assert _infer_device_category(model, sys_descr, device_type) == category


def test_a_netgear_device_of_an_unknown_line_keeps_an_unknown_type():
    assert _infer_vendor_os_from_text("NETGEAR ReadyNAS 4.2") == ("netgear", "unknown", "unknown")


def test_other_vendors_are_not_taken_for_netgear():
    # Zyxel's access points are WAX too; a model in the middle of another vendor's text is not a Netgear switch.
    assert _infer_vendor_os_from_text("Zyxel WAX650S")[0] == "unknown"
    assert _infer_vendor_os_from_text("HP LaserJet M4555 MFP")[0] == "unknown"
    assert _infer_vendor_os_from_text("Linux host1 5.15.0 #1 SMP x86_64") == ("unknown", "unknown", "unknown")
    cisco = "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE"
    assert _infer_vendor_os_from_text(cisco)[:2] == ("cisco", "cisco_xe")
    assert _parse_model_and_version(cisco) == ("CAT9K_IOSXE", "17.9.4a")


def test_software_platforms():
    assert {"netgear-managed", "netgear-smart", "netgear-ap"} <= set(PLATFORMS)
    assert classify_host("netgear_prosafe", "M4300-28G", "12.0.17.6") == ("netgear-managed", "12.0.17.6")
    assert classify_host("netgear_smart", "GS724Tv4", "6.3.1.33") == ("netgear-smart", "6.3.1.33")
    assert classify_host("netgear_ap", "WAX620", "10.8.11.4") == ("netgear-ap", "10.8.11.4")
