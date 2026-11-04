"""The shared ``show version`` parser and OS classifier
(netcontrol/drivers/show_version.py), from sample device output."""

from __future__ import annotations

import asyncio

import pytest
from netcontrol.drivers.show_version import ShowVersionFacts, classify_show_version_os, parse_show_version

# Catalyst 9300 stack member, IOS XE 17.9 (install mode).
IOS_XE_C9300 = """\
Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Fri 20-Oct-23 10:44 by mcpre


Cisco IOS-XE software, Copyright (c) 2005-2023 by cisco Systems, Inc.
All rights reserved.  Certain components of Cisco IOS-XE software are
licensed under the GNU General Public License ("GPL") Version 2.0.

ROM: IOS-XE ROMMON
BOOTLDR: System Bootstrap, Version 17.11.1r, RELEASE SOFTWARE (P)

HQ-CORE-SW1 uptime is 12 weeks, 3 days, 4 hours, 10 minutes
Uptime for this control processor is 12 weeks, 3 days, 4 hours, 12 minutes
System returned to ROM by Reload Command
System image file is "flash:packages.conf"
Last reload reason: Reload Command

cisco C9300-48P (X86) processor with 1338934K/6147K bytes of memory.
Processor board ID FOC2345X0AB
2048K bytes of non-volatile configuration memory.

Base Ethernet MAC Address          : 00:11:22:33:44:55
Motherboard Assembly Number        : 73-17956-06
Motherboard Serial Number          : FOC23451ABC
Model Revision Number              : A0
Motherboard Revision Number        : A0
Model Number                       : C9300-48P
System Serial Number               : FOC2345X0AB

Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 65    C9300-48P          17.09.04a         CAT9K_IOSXE           INSTALL
"""

# Catalyst 2960-X, classic IOS 15.2.
IOS_C2960X = """\
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Tue 28-Feb-23 06:30 by mcpre

ROM: Bootstrap program is C2960X boot loader
BOOTLDR: C2960X Boot Loader (C2960X-HBOOT-M) Version 15.2(3r)E1, RELEASE SOFTWARE (fc1)

BR-ACC-SW2 uptime is 1 year, 2 weeks, 6 hours, 3 minutes
System returned to ROM by power-on
System image file is "flash:/c2960x-universalk9-mz.152-7.E8/c2960x-universalk9-mz.152-7.E8.bin"
Last reload reason: power-on

cisco WS-C2960X-48FPD-L (APM86XXX) processor (revision B0) with 524288K bytes of memory.
Processor board ID FOC1234X5YZ
Last reset from power-on

Model revision number           : B0
Motherboard revision number     : A0
Model number                    : WS-C2960X-48FPD-L
Daughterboard assembly number   : 73-14200-02
Daughterboard serial number     : FOC12345678
System serial number            : FOC1234X5YZ
"""

# Nexus 93180YC-EX, NX-OS 9.3.
NXOS_N9K = """\
Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Copyright (C) 2002-2022, Cisco and/or its affiliates.
All rights reserved.

Software
  BIOS: version 05.45
 NXOS: version 9.3(10)
  BIOS compile time:  10/26/2020
  NXOS image file is: bootflash:///nxos.9.3.10.bin
  NXOS compile time:  6/28/2022 14:00:00 [06/28/2022 23:39:44]

Hardware
  cisco Nexus9000 C93180YC-EX chassis
  Intel(R) Xeon(R) CPU  @ 1.80GHz with 24569316 kB of memory.
  Processor Board ID FDO21120U8N

  Device name: DC1-LEAF-01
  bootflash:   53298520 kB
Kernel uptime is 120 day(s), 3 hour(s), 2 minute(s), 10 second(s)
"""

JUNOS_EX = """\
fpc0:
--------------------------------------------------------------------------
Hostname: br-ex-01
Model: ex4300-48t
Junos: 21.4R3-S1.5
JUNOS OS Kernel 64-bit  [20221005.8dc4b4a_builder_stable_12]
"""

UNRECOGNIZED = """\
                ^
% Invalid input detected at '^' marker.
"""


def test_ios_xe_c9300():
    facts = parse_show_version(IOS_XE_C9300)
    assert facts == ShowVersionFacts(
        os_device_type="cisco_xe",
        model="C9300-48P",
        software_version="17.09.04a",
        serial_number="FOC2345X0AB",
        hostname="HQ-CORE-SW1",
    )


def test_classic_ios_c2960x():
    facts = parse_show_version(IOS_C2960X)
    assert facts.os_device_type == "cisco_ios"
    assert facts.model == "WS-C2960X-48FPD-L"
    assert facts.software_version == "15.2(7)E8"
    # Classic Catalyst spells it "System serial number" (lower case).
    assert facts.serial_number == "FOC1234X5YZ"
    assert facts.hostname == "BR-ACC-SW2"


def test_nxos_n9k():
    facts = parse_show_version(NXOS_N9K)
    assert facts.os_device_type == "cisco_nxos"
    assert facts.model == "C93180YC-EX"
    assert facts.software_version == "9.3(10)"
    assert facts.serial_number == "FDO21120U8N"
    # "Kernel uptime is" is not a hostname; NX-OS names it "Device name".
    assert facts.hostname == "DC1-LEAF-01"


def test_junos_ex():
    facts = parse_show_version(JUNOS_EX)
    assert facts.os_device_type == "juniper_junos"
    assert facts.model == "ex4300-48t"
    assert facts.software_version == "21.4R3-S1.5"
    assert facts.hostname == "br-ex-01"
    # Junos show version carries no chassis serial: never guessed.
    assert facts.serial_number is None


@pytest.mark.parametrize("output", [UNRECOGNIZED, "", None, "   \n"])
def test_unrecognized_output_yields_no_facts(output):
    facts = parse_show_version(output)
    assert facts.empty
    assert facts.to_dict() == {
        "os_device_type": None,
        "model": None,
        "software_version": None,
        "serial_number": None,
        "hostname": None,
    }


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("Cisco IOS XE Software, Version 17.03.04", "cisco_xe"),
        ("Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M)", "cisco_xe"),
        ("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E", "cisco_ios"),
        ("Cisco IOS XR Software, Version 7.3.2", "cisco_xr"),
        ("Cisco Adaptive Security Appliance Software Version 9.16(3)", "cisco_asa"),
        ("Model : Cisco Firepower 2120 Threat Defense (77) Version 7.0.1 (Build 84)", "cisco_ftd"),
        ("Arista DCS-7050TX-64-R\nSoftware image version: 4.28.3M", "arista_eos"),
        ("JUNOS 21.4R3", None),
        ("Linux 5.15", None),
    ],
)
def test_classify_show_version_os(output, expected):
    assert classify_show_version_os(output) == expected


class _Conn:
    def __init__(self, output: str) -> None:
        self.output = output

    def send_command(self, cmd: str, **kwargs) -> str:
        return self.output


def test_upgrade_detect_model_keeps_its_contract():
    """The upgrade workflow reads model/version through the shared parser
    but keeps its contract: model upper-cased, only a dotted release."""
    from netcontrol.routes import upgrades

    assert asyncio.run(upgrades._detect_model(_Conn(IOS_XE_C9300), "10.0.0.1")) == ("C9300-48P", "17.09.04a")
    # A classic IOS train is not a dotted release: version stays unknown.
    assert asyncio.run(upgrades._detect_model(_Conn(IOS_C2960X), "10.0.0.2")) == ("WS-C2960X-48FPD-L", None)
    assert asyncio.run(upgrades._detect_model(_Conn(""), "10.0.0.3")) == (None, None)
