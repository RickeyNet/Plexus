"""HPE Aruba switch support: the AOS-CX and AOS-Switch (HP ProCurve) drivers
and the SNMP-only Instant On type.

The table samples are invented switch output in the form each platform
prints, parsed by the ntc-templates Netmiko uses, so a driver is checked
against the rows it really receives.
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
from netcontrol.drivers.aruba import ArubaAOSCXDriver, ArubaInstantOnDriver, ArubaOSSwitchDriver
from netcontrol.drivers.show_version import parse_show_version
from netcontrol.integrations.inventory_import import capabilities
from netcontrol.integrations.software.versions import PLATFORMS, classify_host
from netcontrol.routes.ansible_inventory import _map_network_os
from netcontrol.routes.metrics_engine import _resolve_oids_uncached
from netcontrol.routes.snmp import _infer_device_category, _infer_vendor_os_from_text, _parse_model_and_version
from ntc_templates.parse import parse_output

# ── AOS-CX ───────────────────────────────────────────────────────────────────

CX_INTERFACES = """
Interface 1/1/1 is up
 Admin state is up
 Link state: up for 3 days (since Mon Nov 09 08:00:00 UTC 2026)
 Link transitions: 1
 Description: uplink to core-sw-01
 Persona:
 Hardware: Ethernet, MAC Address: 00:00:5e:00:53:01
 MTU 1500
 Type 1GbT
 Full-duplex
 qos trust none
 Speed 1000 Mb/s
 Auto-negotiation is on
 Flow-control: off
 Error-control: off
 MDI mode: MDIX
 VLAN Mode: native-untagged
 Native VLAN: 1
 Allowed VLAN List: 10,20-22
 Rx
              100 total packets              6400 total bytes
               90   unicast packets
                5   multicast packets
                5   broadcast packets
                0 errors                        0 dropped
                0 CRC/FCS
 Tx
              200 total packets             12800 total bytes
              190   unicast packets
                5   multicast packets
                5   broadcast packets
                0 errors                        0 dropped
                0 CRC/FCS
                0 collision

Interface 1/1/2 is down
 Admin state is down
 State information: Administratively down
 Link transitions: 0
 Description: printer
 Hardware: Ethernet, MAC Address: 00:00:5e:00:53:02
 MTU 1500
 Type 1GbT
 Full-duplex
 qos trust none
 Speed 0 Mb/s
 Auto-negotiation is off
 Flow-control: off
 Error-control: off
 VLAN Mode: access
 Access VLAN: 30
 Rx
                0 total packets                 0 total bytes
                0   unicast packets
                0   multicast packets
                0   broadcast packets
                0 errors                        0 dropped
                0 CRC/FCS
 Tx
                0 total packets                 0 total bytes
                0   unicast packets
                0   multicast packets
                0   broadcast packets
                0 errors                        0 dropped
                0 CRC/FCS
                0 collision
"""

CX_VLANS = """
------------------------------------------------------------------------------------------------
VLAN  Name                              Status  Reason                  Type      Interfaces
------------------------------------------------------------------------------------------------
1     DEFAULT_VLAN_1                    up      ok                      default   1/1/1
10    USERS                             up      ok                      static    1/1/1
30    PRINTERS                          down    no_member_port          static    1/1/2
40    QUARANTINE                        down    admin_down              static
"""

CX_MACS = """
MAC age-time            : 300 seconds
Number of MAC addresses : 2

MAC Address          VLAN     Type                      Port
--------------------------------------------------------------
00:00:5e:00:53:a1    10       dynamic                   1/1/1
00:00:5e:00:53:a2    30       dynamic                   1/1/2
"""

CX_LLDP = """
Port                           : 1/1/1
Neighbor Entries               : 1
Neighbor Entries Deleted       : 0
Neighbor Entries Dropped       : 0
Neighbor Entries Aged-Out      : 0
Neighbor System-Name           : core-sw-01
Neighbor System-Description    : Aruba JL668A FL.10.10.1020
Neighbor Chassis-Name          : core-sw-01
Neighbor Chassis-Description   : Aruba JL668A FL.10.10.1020
Neighbor Chassis-ID            : 00:00:5e:00:53:10
Neighbor Management-Address    : 192.0.2.1
Chassis Capabilities Available : Bridge, Router
Chassis Capabilities Enabled   : Bridge, Router
Neighbor Port-ID               : 1/1/24
Neighbor Port-Desc             : 1/1/24
Neighbor Port VLAN ID          : 1
TTL                            : 120
"""

CX_VERSION = """
-----------------------------------------------------------------------------
ArubaOS-CX
(c) Copyright 2017-2026 Hewlett Packard Enterprise Development LP
-----------------------------------------------------------------------------
Version      : FL.10.10.1020
Build Date   : 2026-01-15 10:00:00 UTC
Build ID     : ArubaOS-CX:FL.10.10.1020:0123456789ab:202601151000
Active Image : primary

Service OS Version : FL.01.11.0003
BIOS Version       : FL.01.0003
"""

# ── AOS-Switch / ProCurve ────────────────────────────────────────────────────

OS_BRIEF = """
 Status and Counters - Port Status

                          | Intrusion                           MDI  Flow Bcast
  Port         Type       | Alert     Enabled Status Mode       Mode Ctrl Limit
  ------------ ---------- + --------- ------- ------ ---------- ---- ---- -----
  1            100/1000T  | No        Yes     Up     1000FDx    MDIX off  0
  2            100/1000T  | No        Yes     Down   1000FDx    Auto off  0
  3            100/1000T  | No        No      Down   100HDx     Auto off  0
  25           SFP+SR     | No        Yes     Up     10GigFD    NA   off  0
"""

OS_STATUS = """
  Port     Name       Status  Config-mode   Speed    Type       Tagged Untagged
  -------- ---------- ------- ------------- -------- ---------- ------ --------
  1        desk-101   Up      Auto          1000FDx  100/1000T  No     10
  2        desk-102   Down    Auto          1000FDx  100/1000T  No     10
  3        spare      Down    Auto          100HDx   100/1000T  No     1
  25       uplink     Up      Auto          10GigFD  SFP+SR     multi  1
"""

OS_VLANS = """
 Status and Counters - VLAN Information

  Maximum VLANs to support : 256
  Primary VLAN : DEFAULT_VLAN
  Management VLAN :

  VLAN ID Name                             | Status     Voice Jumbo
  ------- -------------------------------- + ---------- ----- -----
  1       DEFAULT_VLAN                     | Port-based No    No
  10      USERS                            | Port-based No    No
  20      VOICE                            | Port-based Yes   No
"""

OS_MACS = """
 Status and Counters - Port Address Table

  MAC Address   Port  VLAN
  ------------- ----- ----
  00005e-0053b1 1     10
  00005e-0053b2 25    1
"""

OS_LLDP = """
 LLDP Remote Devices Information

  LocalPort | ChassisId                 PortId PortDescr SysName
  --------- + ------------------------- ------ --------- ----------------------
  25        | 00005e-005310             24     24        core-sw-01
"""

OS_CDP = """
 CDP neighbors information

  Port : 1
  Device ID : phone-101.example.com
  Address Type : IP
  Address      : 192.0.2.50
  Platform     : Cisco IP Phone 8841
  Capability   : Host Phone
  Device Port  : Port 1
  Version      : sip88xx.14-2-1

------------------------------------------------------------------------------

  Port : 25
  Device ID : 00 00 5e 00 53 10
  Address Type : IP
  Address      : 192.0.2.1
  Platform     : Aruba JL668A FL.10.10.1020
  Capability   : Switch
  Device Port  : 24
  Version      : Aruba JL668A FL.10.10.1020
"""

OS_VERSION = """
Image stamp:    /ws/swbuildm/rel_example_qaoff/code/build/lvm(swbuildm_rel_example_qaoff)
                Jan 15 2026 10:00:00
                WC.16.10.0003
                123
Boot Image:     Primary

Boot ROM Version:    WC.16.01.0006
Active Boot ROM:     Primary
"""

OS_CONFIG = """
hostname "access-sw-01"
vlan 1
   name "DEFAULT_VLAN"
   untagged 3,25
   exit
vlan 10
   name "USERS"
   untagged 1-2
   tagged 25
   exit
"""

# (ntc-templates platform, command the driver sends, sample): every command
# a driver names must have a template that parses that platform's output.
SAMPLES = [
    ("aruba_aoscx", "show interface", CX_INTERFACES),
    ("aruba_aoscx", "show vlan", CX_VLANS),
    ("aruba_aoscx", "show mac-address-table", CX_MACS),
    ("aruba_aoscx", "show lldp neighbor-info detail", CX_LLDP),
    ("hp_procurve", "show interfaces brief", OS_BRIEF),
    ("hp_procurve", "show interfaces status", OS_STATUS),
    ("hp_procurve", "show vlans", OS_VLANS),
    ("hp_procurve", "show mac-address", OS_MACS),
    ("hp_procurve", "show lldp info remote-device", OS_LLDP),
    ("hp_procurve", "show cdp neighbors detail", OS_CDP),
]


def _rows(platform: str, command: str, text: str) -> list[dict]:
    rows = parse_output(platform=platform, command=command, data=text)
    assert rows, f"no template parsed {command!r} for {platform}"
    return rows


# ── Registry ─────────────────────────────────────────────────────────────────


def test_registry_resolves_the_aruba_types():
    assert isinstance(get_driver("aruba_aoscx"), ArubaAOSCXDriver)
    for device_type in ("aruba_osswitch", "aruba_procurve", "hp_procurve"):
        assert isinstance(get_driver(device_type), ArubaOSSwitchDriver)
    assert isinstance(get_driver("aruba_instant_on"), ArubaInstantOnDriver)
    assert {"aruba_aoscx", "aruba_osswitch", "hp_procurve", "aruba_instant_on"} <= set(registered_device_types())
    assert {get_driver(t).vendor for t in ("aruba_aoscx", "aruba_osswitch", "aruba_instant_on")} == {"aruba"}


def test_an_aos_switch_session_opens_under_the_name_its_templates_are_filed_by():
    # ntc-templates has no "aruba_osswitch" platform; the same Netmiko class serves all three names.
    for device_type in ("aruba_osswitch", "aruba_procurve", "hp_procurve"):
        assert session_platform(device_type) == "hp_procurve"
    assert session_platform("aruba_aoscx") == "aruba_aoscx"
    assert session_platform("cisco_xe") == "cisco_xe"
    assert session_platform("no_such_type") == "no_such_type"


def test_open_session_uses_the_session_platform_and_returns_the_host_type(monkeypatch):
    netmiko = pytest.importorskip("netmiko")
    import routes.crypto
    from netcontrol.routes.shared import _open_netmiko_session

    opened: list[dict] = []
    monkeypatch.setattr(netmiko, "ConnectHandler", lambda **kw: opened.append(kw) or object())
    monkeypatch.setattr(routes.crypto, "decrypt", lambda value: value)
    host = {"ip_address": "192.0.2.20", "device_type": "aruba_osswitch"}
    _conn, resolved = _open_netmiko_session(host, {"username": "plexus", "password": "x", "secret": ""})
    assert opened[0]["device_type"] == "hp_procurve" and opened[0]["host"] == "192.0.2.20"
    assert resolved == "aruba_osswitch"


# ── AOS-CX ───────────────────────────────────────────────────────────────────


def test_aoscx_commands():
    driver = get_driver("aruba_aoscx")
    routes = driver.route_table_commands()
    assert (routes.summary, routes.table, routes.all_vrfs) == (None, "show ip route", "show ip route all-vrfs")
    assert driver.capture_running_config_command() == "show running-config"
    assert driver.capture_full_config_command() == "show running-config all"
    assert driver.save_config_commands() == ["write memory"]
    assert driver.neighbor_show_commands() == [("lldp", "show lldp neighbor-info detail")]
    assert driver.snmpv3_verify_users_command() == "show snmpv3 users"
    # The engine ID is kept by the switch: nothing to pin.
    assert driver.snmpv3_engine_id_show_command() == "" and driver.snmpv3_engine_id_pin_command("80001") == ""
    # One table has the VLAN membership: no switchport command.
    with pytest.raises(DriverCapabilityError):
        driver.interface_switchport_show_command()


def test_aoscx_interfaces():
    driver = get_driver("aruba_aoscx")
    rows = _rows("aruba_aoscx", driver.interface_status_show_command(), CX_INTERFACES)
    ports = {p["name"]: p for p in driver.parse_interfaces(rows, [])}
    assert ports["1/1/1"] == {
        "name": "1/1/1",
        "description": "uplink to core-sw-01",
        "admin_state": "up",
        "oper_state": "up",
        "speed_mbps": 1000,
        "duplex": "full",
        "access_vlan": 0,
        "trunk_vlans": "10,20,21,22",
    }
    assert ports["1/1/2"]["admin_state"] == "down" and ports["1/1/2"]["oper_state"] == "down"
    assert ports["1/1/2"]["access_vlan"] == 30 and ports["1/1/2"]["trunk_vlans"] == ""


def test_aoscx_trunk_allowing_every_vlan():
    row = {"interface": "lag1", "link_status": "up", "link_admin": "up", "vlan_mode": "native-tagged", "vlan_trunk": ["all"]}
    assert get_driver("aruba_aoscx").parse_interfaces([row], [])[0]["trunk_vlans"] == "1-4094"


def test_aoscx_vlans():
    driver = get_driver("aruba_aoscx")
    vlans = driver.parse_vlans(_rows("aruba_aoscx", driver.vlan_show_command(), CX_VLANS))
    assert [(v["vlan_id"], v["name"], v["state"]) for v in vlans] == [
        (1, "DEFAULT_VLAN_1", "active"),
        (10, "USERS", "active"),
        # No port up, but defined: active. Shut down by the configuration: suspended.
        (30, "PRINTERS", "active"),
        (40, "QUARANTINE", "suspended"),
    ]


def test_aoscx_mac_table():
    driver = get_driver("aruba_aoscx")
    macs = driver.parse_mac_table(_rows("aruba_aoscx", driver.mac_table_show_command(), CX_MACS))
    assert macs == [
        {"mac": "00:00:5e:00:53:a1", "vlan": 10, "port": "1/1/1", "type": "dynamic"},
        {"mac": "00:00:5e:00:53:a2", "vlan": 30, "port": "1/1/2", "type": "dynamic"},
    ]


def test_aoscx_lldp_neighbors():
    driver = get_driver("aruba_aoscx")
    ((protocol, command),) = driver.neighbor_show_commands()
    (neighbor,) = driver.parse_neighbors(protocol, _rows("aruba_aoscx", command, CX_LLDP))
    assert neighbor["local_interface"] == "1/1/1" and neighbor["remote_device_name"] == "core-sw-01"
    assert neighbor["remote_interface"] == "1/1/24" and neighbor["remote_ip"] == "192.0.2.1"
    assert neighbor["protocol"] == "lldp" and neighbor["remote_platform"] == "Aruba JL668A FL.10.10.1020"


def test_aoscx_serial_and_show_version():
    driver = get_driver("aruba_aoscx")
    assert driver.serial_number_show_command() == "show system | include Serial"
    assert driver.parse_serial_number("Chassis Serial Nbr      : SG00EXAMPLE1\n") == "SG00EXAMPLE1"
    assert driver.parse_serial_number("Hostname : sw1\n") is None
    facts = parse_show_version(CX_VERSION)
    assert facts.os_device_type == "aruba_aoscx" and facts.software_version == "FL.10.10.1020"


# ── AOS-Switch / ProCurve ────────────────────────────────────────────────────


def test_aos_switch_commands():
    driver = get_driver("aruba_osswitch")
    routes = driver.route_table_commands()
    assert (routes.summary, routes.table, routes.all_vrfs) == (None, "show ip route", None)
    assert driver.capture_running_config_command() == "show running-config"
    # No form with the defaults included.
    assert driver.capture_full_config_command() == "show running-config"
    assert driver.save_config_commands() == ["write memory"]
    assert driver.neighbor_show_commands() == [
        ("cdp", "show cdp neighbors detail"),
        ("lldp", "show lldp info remote-device"),
    ]
    assert driver.snmpv3_verify_users_command() == "show snmpv3 user"


def test_aos_switch_interfaces_merge_the_brief_and_status_tables():
    driver = get_driver("hp_procurve")
    brief = _rows("hp_procurve", driver.interface_status_show_command(), OS_BRIEF)
    status = _rows("hp_procurve", driver.interface_switchport_show_command(), OS_STATUS)
    ports = {p["name"]: p for p in driver.parse_interfaces(brief, status)}
    assert ports["1"] == {
        "name": "1",
        "description": "desk-101",
        "admin_state": "up",
        "oper_state": "up",
        "speed_mbps": 1000,
        "duplex": "full",
        "access_vlan": 10,
        "trunk_vlans": "",
    }
    assert ports["3"]["admin_state"] == "down" and ports["3"]["duplex"] == "half" and ports["3"]["speed_mbps"] == 100
    # Tagged VLANs make it a trunk; "multi" does not say which, so they stay unknown.
    assert ports["25"]["speed_mbps"] == 10000 and ports["25"]["access_vlan"] == 0 and ports["25"]["trunk_vlans"] == ""


def test_aos_switch_interfaces_without_the_status_table():
    # A release before 16.x rejects "show interfaces status": the ports are stored without names or VLANs.
    driver = get_driver("hp_procurve")
    ports = driver.parse_interfaces(_rows("hp_procurve", "show interfaces brief", OS_BRIEF), [])
    assert [p["name"] for p in ports] == ["1", "2", "3", "25"]
    assert all(p["description"] == "" and p["access_vlan"] == 0 and p["trunk_vlans"] == "" for p in ports)


def test_aos_switch_vlans_and_the_configuration_fallback():
    driver = get_driver("aruba_osswitch")
    vlans = driver.parse_vlans(_rows("hp_procurve", driver.vlan_show_command(), OS_VLANS))
    assert vlans == [
        {"vlan_id": 1, "name": "DEFAULT_VLAN", "state": "active"},
        {"vlan_id": 10, "name": "USERS", "state": "active"},
        {"vlan_id": 20, "name": "VOICE", "state": "active"},
    ]
    # The configuration quotes its names.
    assert driver.parse_config_vlans(OS_CONFIG) == [
        {"vlan_id": 1, "name": "DEFAULT_VLAN", "state": "active"},
        {"vlan_id": 10, "name": "USERS", "state": "active"},
    ]
    assert driver.parse_config_hostname(OS_CONFIG) == "access-sw-01"


def test_aos_switch_mac_table():
    driver = get_driver("aruba_osswitch")
    macs = driver.parse_mac_table(_rows("hp_procurve", driver.mac_table_show_command(), OS_MACS))
    assert macs == [
        {"mac": "00:00:5e:00:53:b1", "vlan": 10, "port": "1", "type": "dynamic"},
        {"mac": "00:00:5e:00:53:b2", "vlan": 1, "port": "25", "type": "dynamic"},
    ]


def test_aos_switch_neighbors():
    driver = get_driver("aruba_osswitch")
    commands = dict(driver.neighbor_show_commands())
    (lldp,) = driver.parse_neighbors("lldp", _rows("hp_procurve", commands["lldp"], OS_LLDP))
    assert lldp["local_interface"] == "25" and lldp["remote_device_name"] == "core-sw-01"
    # The summary table's description column is the neighbor's port, not its platform.
    assert lldp["remote_interface"] == "24" and lldp["remote_platform"] == ""
    # The CDP table repeats the LLDP neighbor by MAC address: only the CDP speaker is kept.
    (cdp,) = driver.parse_neighbors("cdp", _rows("hp_procurve", commands["cdp"], OS_CDP))
    assert cdp["local_interface"] == "1" and cdp["remote_device_name"] == "phone-101.example.com"
    assert cdp["remote_ip"] == "192.0.2.50" and cdp["remote_platform"] == "Cisco IP Phone 8841"


def test_aos_switch_serial_and_show_version():
    driver = get_driver("aruba_osswitch")
    assert driver.serial_number_show_command() == "show system information"
    assert driver.parse_serial_number("  ROM Version        : WC.16.01.0006\n  Serial Number      : SG00EXAMPLE2\n") == (
        "SG00EXAMPLE2"
    )
    facts = parse_show_version(OS_VERSION)
    assert facts.os_device_type == "aruba_osswitch" and facts.software_version == "WC.16.10.0003"


# ── Instant On: SNMP only ────────────────────────────────────────────────────


def test_instant_on_has_no_command_line():
    assert not supports_cli("aruba_instant_on") and not supports_cli("icmp_only")
    for device_type in ("aruba_aoscx", "aruba_osswitch", "cisco_xe", "hp_comware", "", None):
        assert supports_cli(device_type)
    assert not supports_config_capture("aruba_instant_on")
    assert capabilities("aruba_instant_on") == {"snmp_polling": True, "config_backup": False}
    driver = get_driver("aruba_instant_on")
    for capability in (driver.mac_table_show_command, driver.show_version_command, driver.route_table_commands):
        with pytest.raises(DriverCapabilityError):
            capability()


def test_no_ssh_session_is_opened_to_an_instant_on_switch(monkeypatch):
    netmiko = pytest.importorskip("netmiko")
    from netcontrol.routes.shared import _open_netmiko_session

    def _never(**_kw):
        raise AssertionError("an SSH session was opened")

    monkeypatch.setattr(netmiko, "ConnectHandler", _never)
    host = {"ip_address": "192.0.2.30", "device_type": "aruba_instant_on"}
    with pytest.raises(DriverCapabilityError, match="no command line"):
        _open_netmiko_session(host, {"username": "plexus", "password": "x", "secret": ""})


def test_inventory_collection_skips_an_instant_on_switch():
    from netcontrol.routes import inventory_collection

    assert not inventory_collection._collectable({"device_type": "aruba_instant_on"})
    assert inventory_collection._collectable({"device_type": "aruba_aoscx"})


# ── SNMP detection, versions, OIDs, Ansible ──────────────────────────────────

INSTANT_ON_DESCR = "Aruba Instant On 1830 24G 2SFP Switch JL812A, InstantOn_1830_2.9.1.17 (20), Linux 4.4.120"
AOS_SWITCH_DESCR = (
    "Aruba JL253A 2930F-24G-4SFP+ Switch, revision WC.16.10.0003, ROM WC.16.01.0006 "
    "(/ws/swbuildm/rel_example_qaoff/code/build/lvm(swbuildm_rel_example_qaoff))"
)
PROCURVE_DESCR = "ProCurve J9019B Switch 2510B-24, revision Q.11.57, ROM Q.10.02 (/sw/code/build/harp(bh2))"
AOSCX_DESCR = "Aruba JL668A FL.10.10.1020"


@pytest.mark.parametrize(
    ("sys_descr", "device_type", "os_name", "model", "version"),
    [
        (INSTANT_ON_DESCR, "aruba_instant_on", "instant-on", "JL812A", "2.9.1.17"),
        ("HPE Networking Instant On Switch 1830 8G JL810A", "aruba_instant_on", "instant-on", "JL810A", ""),
        (AOS_SWITCH_DESCR, "aruba_osswitch", "aos-switch", "2930F-24G-4SFP+", "WC.16.10.0003"),
        (PROCURVE_DESCR, "aruba_osswitch", "aos-switch", "2510B-24", "Q.11.57"),
        (AOSCX_DESCR, "aruba_aoscx", "aos-cx", "JL668A", "FL.10.10.1020"),
    ],
)
def test_snmp_sys_descr_names_the_aruba_platform(sys_descr, device_type, os_name, model, version):
    assert _infer_vendor_os_from_text(sys_descr) == ("aruba", device_type, os_name)
    assert _parse_model_and_version(sys_descr) == (model, version)
    assert _infer_device_category(model, sys_descr, device_type) == "switch"


def test_other_vendors_are_not_taken_for_aruba():
    cisco = "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE"
    assert _infer_vendor_os_from_text(cisco)[:2] == ("cisco", "cisco_xe")
    assert _parse_model_and_version(cisco) == ("CAT9K_IOSXE", "17.9.4a")
    assert _infer_vendor_os_from_text("Linux host1 5.15.0 #1 SMP x86_64") == ("unknown", "unknown", "unknown")


def test_software_platforms():
    assert {"aos-cx", "aos-switch", "instant-on"} <= set(PLATFORMS)
    assert classify_host("aruba_aoscx", "JL668A", "FL.10.10.1020") == ("aos-cx", "10.10.1020")
    assert classify_host("aruba_osswitch", "2930F-24G-4SFP+", "WC.16.10.0003") == ("aos-switch", "16.10.0003")
    assert classify_host("hp_procurve", "", "Q.11.57") == ("aos-switch", "11.57")
    assert classify_host("aruba_instant_on", "JL812A", "2.9.1.17") == ("instant-on", "2.9.1.17")
    # A map node known only by its model text.
    assert classify_host(None, "Aruba Instant On 1830 24G", "")[0] == "instant-on"


async def test_monitoring_oids(monkeypatch):
    import routes.database as db

    async def _no_override(_device_type):
        return None

    monkeypatch.setattr(db, "get_vendor_oid_for_host", _no_override)
    for device_type in ("aruba_osswitch", "hp_procurve", "aruba_procurve"):
        oids = await _resolve_oids_uncached(device_type)
        assert oids["vendor"] == "Aruba" and oids["cpu_oid"].startswith("1.3.6.1.4.1.11.2.14.11.5.1.9.6")
        assert oids["mem_used_oid"] and oids["mem_free_oid"] and not oids["mem_total_oid"]
    # AOS-CX and Instant On are polled with the HOST-RESOURCES fallback.
    for device_type in ("aruba_aoscx", "aruba_instant_on"):
        assert (await _resolve_oids_uncached(device_type))["vendor"] == "Generic"


def test_ansible_network_os():
    assert _map_network_os("aruba_aoscx") == "arubanetworks.aoscx.aoscx"
    assert _map_network_os("aruba_osswitch") == _map_network_os("hp_procurve") == "community.network.procurve"
