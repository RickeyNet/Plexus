"""IOS-XE chassis parsers used by the upgrade safety gates.

``show boot``, ``show module`` and the environment commands, each in the
modular chassis (9400/9600) and stackable (9200/9300) layouts, plus
unrecognised replies.  Serial numbers and MAC addresses are invented.
"""

from __future__ import annotations

import pytest
from netcontrol.drivers import DriverCapabilityError, get_driver

XE = get_driver("cisco_xe")

# ── show boot ───────────────────────────────────────────────────────────────

BOOT_MODULAR_DUAL = """\
BOOT variable = bootflash:packages.conf;
Configuration Register is 0x102 (will be 0x2102 at next reload)
MANUAL_BOOT variable = no
BAUD variable = 9600
ENABLE_BREAK variable does not exist
CONFIG_FILE variable does not exist

Standby BOOT variable = bootflash:packages.conf;
Standby Configuration Register is 0x2102
Standby MANUAL_BOOT variable = no
Standby BAUD variable = 9600
"""

BOOT_MODULAR_BIN_STANDBY = """\
BOOT variable = bootflash:packages.conf;
Configuration Register is 0x2102
MANUAL_BOOT variable = no
Standby BOOT variable = bootflash:cat9k_iosxe.17.12.04.SPA.bin;bootflash:packages.conf;
Standby Configuration Register is 0x2142
Standby MANUAL_BOOT variable = yes
"""

BOOT_STACK = """\
---------------------------
Switch 1
---------------------------
Current Boot Variables:
BOOT variable = flash:packages.conf;

Boot Variables on next reload:
BOOT variable = flash:packages.conf;
Manual Boot = no
Enable Break = no
Boot Mode = DEVICE
iPXE Timeout = 0

---------------------------
Switch 2
---------------------------
Current Boot Variables:
BOOT variable = flash:packages.conf;

Boot Variables on next reload:
BOOT variable does not exist
Manual Boot = yes
Enable Break = no
"""


def test_boot_vars_command() -> None:
    assert XE.upgrade_boot_vars_show_command() == "show boot"


def test_boot_vars_modular_dual_supervisor() -> None:
    entries = XE.parse_boot_vars(BOOT_MODULAR_DUAL)["entries"]
    assert entries == [
        {"scope": "active", "boot": "bootflash:packages.conf", "manual_boot": False, "config_register": "0x2102"},
        {"scope": "standby", "boot": "bootflash:packages.conf", "manual_boot": False, "config_register": "0x2102"},
    ]


def test_boot_vars_modular_first_entry_wins() -> None:
    entries = {e["scope"]: e for e in XE.parse_boot_vars(BOOT_MODULAR_BIN_STANDBY)["entries"]}
    assert entries["standby"]["boot"] == "bootflash:cat9k_iosxe.17.12.04.SPA.bin"
    assert entries["standby"]["manual_boot"] is True
    assert entries["standby"]["config_register"] == "0x2142"


def test_boot_vars_stack_next_reload_wins() -> None:
    entries = {e["scope"]: e for e in XE.parse_boot_vars(BOOT_STACK)["entries"]}
    assert entries["switch 1"] == {
        "scope": "switch 1",
        "boot": "flash:packages.conf",
        "manual_boot": False,
        "config_register": None,
    }
    # "does not exist" on next reload overrides a current value.
    assert entries["switch 2"]["boot"] == ""
    assert entries["switch 2"]["manual_boot"] is True


@pytest.mark.parametrize("text", ["", "% Invalid input detected at '^' marker.\n", "garbage\n"])
def test_boot_vars_unrecognised(text: str) -> None:
    assert XE.parse_boot_vars(text) == {}


# ── show module ─────────────────────────────────────────────────────────────

MODULE_9400 = """\
Chassis Type: C9407R

Mod Ports Card Type                                   Model          Serial No.
---+-----+--------------------------------------------+--------------+--------------
1   48   48-Port UPOE 10/100/1000 (RJ-45)             C9400-LC-48U   JAE00000001
2   48   48-Port UPOE 10/100/1000 (RJ-45)             C9400-LC-48U   JAE00000002
3   10   Supervisor 1 Module                          C9400-SUP-1    JAE00000003
4   10   Supervisor 1 Module                          C9400-SUP-1    JAE00000004
5   48   48-Port UPOE 10/100/1000 (RJ-45)             C9400-LC-48U   JAE00000005

Mod MAC addresses                    Hw   Fw           Sw                 Status
---+--------------------------------+----+------------+------------------+--------
1   0000.5E00.5301 to 0000.5E00.532F 1.0  17.15.1r     17.15.05           ok
2   0000.5E00.5330 to 0000.5E00.535F 1.0  17.15.1r     17.15.05           out of service
3   0000.5E00.5360 to 0000.5E00.5369 1.0  17.15.1r     17.15.05           ok
4   0000.5E00.536A to 0000.5E00.5373 1.0  17.15.1r     17.15.05           ok
5   0000.5E00.5374 to 0000.5E00.53A3 1.0  17.15.1r     17.12.04           ok

Mod Redundancy Role     Operating Redundancy Mode Configured Redundancy Mode
---+-------------------+-------------------------+---------------------------
3   Active              sso                       sso
4   Standby             sso                       sso

Chassis MAC address range: 64 addresses from 0000.5e00.5300 to 0000.5e00.533f
"""

MODULE_SVL_QUAD = """\
Chassis Type: C9606R

Switch Number 1

Mod Ports Card Type                                   Model          Serial No.
---+-----+--------------------------------------------+--------------+--------------
1   24   24-Port 40GE/12-Port 100GE                   C9600-LC-24C   CAT00000011
3   0    Supervisor 1 Module                          C9600-SUP-1    CAT00000013
4   0    Supervisor 1 Module                          C9600-SUP-1    CAT00000014

Mod MAC addresses                    Hw   Fw           Sw                 Status
---+--------------------------------+----+------------+------------------+--------
1   0000.5E00.5301 to 0000.5E00.532F 1.0  17.3.1r[FC2] 17.15.05           ok
3   0000.5E00.5330 to 0000.5E00.535F 1.0  17.3.1r[FC2] 17.15.05           ok
4   --                               --   N/A          --                 Provisioned

Mod Redundancy Role     Operating Redundancy Mode Configured Redundancy Mode
---+-------------------+-------------------------+---------------------------
3   Active              sso                       sso
4   InChassis-Standby   rpr                       rpr

Switch Number 2

Mod Ports Card Type                                   Model          Serial No.
---+-----+--------------------------------------------+--------------+--------------
1   24   24-Port 40GE/12-Port 100GE                   C9600-LC-24C   CAT00000021
3   0    Supervisor 1 Module                          C9600-SUP-1    CAT00000023

Mod MAC addresses                    Hw   Fw           Sw                 Status
---+--------------------------------+----+------------+------------------+--------
1   0000.5E00.5360 to 0000.5E00.538F 1.0  17.3.1r[FC2] 17.15.05           ok
3   0000.5E00.5390 to 0000.5E00.53BF 1.0  17.3.1r[FC2] 17.15.05           booting

Mod Redundancy Role     Operating Redundancy Mode Configured Redundancy Mode
---+-------------------+-------------------------+---------------------------
3   Standby             sso                       sso
"""

MODULE_STACK = """\
Switch  Ports    Model                Serial No.   MAC address     Hw Ver.       Sw Ver.
------  -----   ---------             -----------  --------------  -------       --------
 1       41     C9300-48P             FOC0000X001  0000.5e00.5344  V02           17.15.05
 2       41     C9300-48P             FOC0000X002  0000.5e00.5345  V02           17.12.04
"""


def test_module_command() -> None:
    assert XE.upgrade_module_show_command() == "show module"


def test_module_modular_chassis() -> None:
    state = XE.parse_module_state(MODULE_9400)
    assert state["modular"] is True
    assert state["chassis_type"] == "C9407R"
    mods = {m["slot"]: m for m in state["modules"]}
    assert sorted(mods) == [1, 2, 3, 4, 5]
    assert mods[1]["card_type"] == "48-Port UPOE 10/100/1000 (RJ-45)"
    assert mods[1]["model"] == "C9400-LC-48U"
    assert mods[2]["status"] == "out of service"
    assert mods[5]["sw"] == "17.12.04"
    assert mods[3]["supervisor"] and mods[4]["supervisor"] and not mods[1]["supervisor"]
    assert (mods[3]["role"], mods[4]["role"], mods[1]["role"]) == ("active", "standby", None)
    assert all(m["chassis"] is None for m in state["modules"])


def test_module_svl_pair_keys_by_chassis_and_slot() -> None:
    state = XE.parse_module_state(MODULE_SVL_QUAD)
    mods = {(m["chassis"], m["slot"]): m for m in state["modules"]}
    assert set(mods) == {(1, 1), (1, 3), (1, 4), (2, 1), (2, 3)}
    assert mods[(1, 4)]["status"] == "Provisioned"
    assert mods[(1, 4)]["sw"] is None
    assert mods[(1, 4)]["role"] == "inchassis-standby"
    assert mods[(2, 3)]["status"] == "booting"
    assert mods[(2, 3)]["role"] == "standby"


def test_module_stackable() -> None:
    state = XE.parse_module_state(MODULE_STACK)
    assert state["modular"] is False
    assert [(m["slot"], m["model"], m["sw"], m["status"]) for m in state["modules"]] == [
        (1, "C9300-48P", "17.15.05", None),
        (2, "C9300-48P", "17.12.04", None),
    ]


@pytest.mark.parametrize("text", ["", "% Invalid input detected at '^' marker.\n", "Chassis Type: C9407R\n"])
def test_module_unrecognised(text: str) -> None:
    assert XE.parse_module_state(text) == {}


# ── environment ─────────────────────────────────────────────────────────────

ENV_9400 = """\
Power                                                       Fan States
Supply  Model No              Type  Capacity  Status        0     1
------  --------------------  ----  --------  ------------  -----------
PS1     C9400-PWR-3200AC      ac    3200 W    active        good  good
PS2     C9400-PWR-3200AC      ac    3200 W    faulty        bad   good
PS3     C9400-PWR-3200AC      ac    3200 W    standby       good  good
PS4     n.a.                  n.a.  n.a.      n.a.          n.a.  n.a.

PS Current Configuration Mode : Combined
PS Current Operating State    : Combined

Fan Tray Status
---------------
Slot  Fan Status
FM1   ok
"""

ENV_9300 = """\
Switch 1 FAN 1 is OK
Switch 1 FAN 2 is FAILED
FAN PS-1 is OK
FAN PS-2 is NOT PRESENT
Switch 1: SYSTEM TEMPERATURE is OK
SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
--  ------------------  ----------  ---------------  -------  -------  -----
1A  PWR-C1-715WAC       DCB0000X01  OK               Good     Good     715
1B  PWR-C1-715WAC       DCB0000X02  No Input Power   Bad      Bad      715
2A  Not Present
"""

ENV_HEALTHY = """\
Switch 1 FAN 1 is OK
FAN PS-1 is OK
FAN PS-2 is NOT PRESENT
1A  PWR-C1-715WAC       DCB0000X01  OK               Good     Good     715
1B  Not Present
"""


def test_environment_commands() -> None:
    assert XE.upgrade_environment_show_commands() == ["show environment status", "show environment all"]


def test_environment_modular_flags_faulty_supply() -> None:
    problems = XE.parse_environment_state({"show environment status": ENV_9400})["problems"]
    assert len(problems) == 1
    assert problems[0].startswith("PS2 C9400-PWR-3200AC")


def test_environment_stackable_flags_fan_and_supply() -> None:
    problems = XE.parse_environment_state({"show environment all": ENV_9300})["problems"]
    assert "Switch 1 FAN 2 is FAILED" in problems
    assert any(p.startswith("1B PWR-C1-715WAC") and "No Input Power" in p for p in problems)
    assert len(problems) == 2


def test_environment_healthy_and_unrecognised() -> None:
    assert XE.parse_environment_state({"show environment all": ENV_HEALTHY}) == {"problems": []}
    assert XE.parse_environment_state({"show environment status": "% Invalid input detected\n"}) == {"problems": []}
    assert XE.parse_environment_state({}) == {"problems": []}


def test_standby_flash_filesystems() -> None:
    assert XE.upgrade_standby_flash_filesystems() == ["stby-bootflash:", "stby-flash:"]


def test_generic_driver_has_no_chassis_capabilities() -> None:
    drv = get_driver("frobozz_os")
    for call in (
        drv.upgrade_boot_vars_show_command,
        drv.upgrade_module_show_command,
        drv.upgrade_environment_show_commands,
        drv.upgrade_standby_flash_filesystems,
    ):
        with pytest.raises(DriverCapabilityError):
            call()
