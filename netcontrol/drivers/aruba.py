"""HPE Aruba switch drivers: AOS-CX, AOS-Switch (HP ProCurve) and Instant On.

Three product lines that share a vendor and little else:

  - **AOS-CX** (6000 to 10000 series). An IOS-like command line with its own
    table commands (``show mac-address-table``, ``show lldp neighbor-info
    detail``) and one ``show interface`` that prints state, speed and VLAN
    membership per port, so there is no separate switchport table.
  - **AOS-Switch** (2530, 2930, 3810, 5400R and the HP ProCurve switches
    before them). ``show interfaces brief`` gives the port state and ``show
    interfaces status`` the port names and VLANs; MAC addresses print as
    ``aabbcc-ddeeff``; names in the configuration are quoted. It hears CDP
    as well as LLDP. Netmiko reaches it as ``aruba_osswitch``,
    ``aruba_procurve`` or ``hp_procurve``, and ntc-templates files its
    templates under the last two, so the session is opened as
    ``hp_procurve`` whichever of them the host has.
  - **Instant On** (1830, 1930, 1960). No command line at all: the switch
    is managed from its web page or the Instant On cloud portal and answers
    SNMP read requests. Plexus polls it over SNMP and never opens an SSH
    session to it (``cli = False``).

Not implemented, so the callers report it instead of sending another
vendor's syntax: NetFlow export (these switches export sFlow, and AOS-CX
IPFIX only on some models) and the software upgrade workflow (their
images are copied by the switch itself, ``copy tftp|sftp flash``, not
pushed to it).
"""

from __future__ import annotations

import re

from netcontrol.drivers.base import (
    CiscoStyleTables,
    Driver,
    RouteTableCommands,
    _duplex_word,
    _row_value,
    _speed_mbps,
    register_driver,
    vlan_csv,
)

# "Chassis Serial Nbr : X" (AOS-CX ``show system``), "Serial Number : X"
# (AOS-Switch ``show system information``).
_SERIAL = re.compile(r"Serial\s+(?:Number|Nbr)\s*:\s*(\S+)", re.IGNORECASE)
# The device id of a ``show cdp neighbors detail`` entry that AOS-Switch
# learned over LLDP: the neighbor's MAC address, not a name.
_MAC_DEVICE_ID = re.compile(r"^(?:[0-9a-f]{2}[ :-]?){5}[0-9a-f]{2}$|^[0-9a-f]{6}-[0-9a-f]{6}$", re.IGNORECASE)
# The Mode column of ``show interfaces brief``: 1000FDx, 100HDx, 10GigFD.
_MODE_SPEED = re.compile(r"^(\d+)(gig)?", re.IGNORECASE)


def _parse_serial(output: str) -> str | None:
    match = _SERIAL.search(output or "")
    return match.group(1) if match else None


@register_driver
class ArubaAOSCXDriver(CiscoStyleTables, Driver):
    device_types = ("aruba_aoscx",)
    vendor = "aruba"
    display_name = "Aruba AOS-CX"

    def route_table_commands(self) -> RouteTableCommands:
        # ``all-vrfs`` prints every VRF's table under a "VRF: NAME" header.
        return RouteTableCommands(None, "show ip route", "show ip route all-vrfs")

    def capture_running_config_command(self) -> str:
        return "show running-config"

    def capture_full_config_command(self) -> str:
        return "show running-config all"

    def save_config_commands(self) -> list[str]:
        return ["write memory"]

    def mac_table_show_command(self) -> str:
        return "show mac-address-table"

    def parse_mac_table(self, parsed_rows: list[dict]) -> list[dict]:
        return self._parse_cisco_style_mac_rows(parsed_rows)

    def vlan_show_command(self) -> str:
        return "show vlan"

    def parse_vlans(self, rows: list[dict]) -> list[dict]:
        # The Status column says whether a port of the VLAN is up, not
        # whether the VLAN exists; only one shut down by the configuration
        # ("admin_down") is not active.
        reasons = {_row_value(row, "vlan_id"): _row_value(row, "reason").lower() for row in rows or []}
        return [
            {**vlan, "state": "suspended" if reasons.get(str(vlan["vlan_id"])) == "admin_down" else "active"}
            for vlan in self._parse_cisco_style_vlan_rows(rows)
        ]

    def interface_status_show_command(self) -> str:
        return "show interface"

    def parse_interfaces(self, status_rows: list[dict], switchport_rows: list[dict]) -> list[dict]:
        # ``show interface`` carries the VLAN membership too; AOS-CX has no
        # switchport table, so ``switchport_rows`` is always empty.
        out: list[dict] = []
        for row in status_rows or []:
            name = _row_value(row, "interface")
            if not name:
                continue
            mode = _row_value(row, "vlan_mode").lower()
            # "native-untagged" / "native-tagged" are the two trunk modes.
            trunk = mode.startswith("native") or "trunk" in mode
            access = _row_value(row, "vlan_access")
            out.append(
                {
                    "name": name,
                    "description": _row_value(row, "interface_desc"),
                    "admin_state": _row_value(row, "link_admin").lower(),
                    "oper_state": _row_value(row, "link_status").lower(),
                    "speed_mbps": _speed_mbps(_row_value(row, "speed")),
                    "duplex": _duplex_word(_row_value(row, "duplex")),
                    "access_vlan": int(access) if not trunk and access.isdigit() else 0,
                    "trunk_vlans": vlan_csv(_row_value(row, "vlan_trunk")) if trunk else "",
                }
            )
        return out

    def neighbor_show_commands(self) -> list[tuple[str, str]]:
        return [("lldp", "show lldp neighbor-info detail")]

    def snmpv3_show_existing_command(self) -> str:
        return "show running-config | include snmp"

    def snmpv3_engine_id_show_command(self) -> str:
        # The engine ID is kept across reloads and configuration changes, so
        # there is nothing to pin (as on NX-OS and Junos).
        return ""

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        return ""

    def snmpv3_verify_users_command(self) -> str:
        return "show snmpv3 users"

    def show_version_command(self) -> str:
        return "show version"

    def serial_number_show_command(self) -> str:
        # ``show version`` prints no serial; ``show system`` does.
        return "show system | include Serial"

    def parse_serial_number(self, output: str) -> str | None:
        return _parse_serial(output)


@register_driver
class ArubaOSSwitchDriver(Driver):
    device_types = ("aruba_osswitch", "aruba_procurve", "hp_procurve")
    vendor = "aruba"
    display_name = "Aruba AOS-Switch / HP ProCurve"
    session_type = "hp_procurve"

    def route_table_commands(self) -> RouteTableCommands:
        # One routing table: no summary command and no VRFs.
        return RouteTableCommands(None, "show ip route", None)

    def capture_running_config_command(self) -> str:
        return "show running-config"

    def save_config_commands(self) -> list[str]:
        return ["write memory"]

    def mac_table_show_command(self) -> str:
        return "show mac-address"

    def parse_mac_table(self, parsed_rows: list[dict]) -> list[dict]:
        return self._parse_cisco_style_mac_rows(parsed_rows)

    def vlan_show_command(self) -> str:
        return "show vlans"

    def parse_vlans(self, rows: list[dict]) -> list[dict]:
        # The Status column is how the VLAN was made (Port-based, Dynamic),
        # not a state: every VLAN listed is active.
        return [{**vlan, "state": "active"} for vlan in self._parse_cisco_style_vlan_rows(rows)]

    def parse_config_vlans(self, config_text: str) -> list[dict]:
        return self._parse_cisco_style_config_vlans(config_text)

    def interface_status_show_command(self) -> str:
        # Every release has this table; it has the state, speed and duplex.
        return "show interfaces brief"

    def interface_switchport_show_command(self) -> str:
        # The port names and VLANs. Releases before 16.x reject it, and the
        # ports are then stored without them.
        return "show interfaces status"

    def parse_interfaces(self, status_rows: list[dict], switchport_rows: list[dict]) -> list[dict]:
        vlans = {_row_value(row, "port").lower(): row for row in switchport_rows or [] if _row_value(row, "port")}
        out: list[dict] = []
        for row in status_rows or []:
            port = _row_value(row, "port")
            if not port:
                continue
            status = _row_value(row, "status").lower()
            enabled = _row_value(row, "enabled").lower()
            mode = _row_value(row, "mode")
            speed = _MODE_SPEED.match(mode)
            membership = vlans.get(port.lower(), {})
            tagged = _row_value(membership, "vlan_tagged").lower()
            untagged = _row_value(membership, "vlan_untagged")
            # A port that carries a tagged VLAN is a trunk in the Cisco
            # sense. "multi" says several are tagged without naming them.
            trunk = tagged not in ("", "no")
            out.append(
                {
                    "name": port,
                    "description": _row_value(membership, "name"),
                    "admin_state": {"yes": "up", "no": "down"}.get(enabled, ""),
                    "oper_state": status if status in ("up", "down") else "",
                    "speed_mbps": int(speed.group(1)) * (1000 if speed.group(2) else 1) if speed else 0,
                    "duplex": "full" if "fd" in mode.lower() else ("half" if "hd" in mode.lower() else ""),
                    "access_vlan": int(untagged) if not trunk and untagged.isdigit() else 0,
                    "trunk_vlans": vlan_csv(tagged) if trunk else "",
                }
            )
        return out

    def neighbor_show_commands(self) -> list[tuple[str, str]]:
        # The LLDP summary table: every release prints it for all ports at
        # once (the detail form takes a port list). It has no management
        # address, so a neighbor is matched by its name.
        return [("cdp", "show cdp neighbors detail"), ("lldp", "show lldp info remote-device")]

    def parse_neighbors(self, protocol: str, rows: list[dict]) -> list[dict]:
        if protocol == "cdp":
            # The CDP table also lists LLDP neighbors, by MAC address; the
            # LLDP table names them.
            rows = [row for row in rows or [] if not _MAC_DEVICE_ID.match(_row_value(row, "chassis_id"))]
        else:
            # In the summary table this column is the neighbor's port
            # description, not its platform.
            rows = [{k: v for k, v in row.items() if k != "neighbor_description"} for row in rows or []]
        return self._parse_neighbor_rows(protocol, rows)

    def snmpv3_show_existing_command(self) -> str:
        return "show running-config | include snmp"

    def snmpv3_engine_id_show_command(self) -> str:
        # Derived from the switch's MAC address and kept: nothing to pin.
        return ""

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        return ""

    def snmpv3_verify_users_command(self) -> str:
        return "show snmpv3 user"

    def show_version_command(self) -> str:
        return "show version"

    def serial_number_show_command(self) -> str:
        # ``show version`` prints no serial. Not filtered with ``| include``:
        # older ProCurve releases have no output filters, and the output is short.
        return "show system information"

    def parse_serial_number(self, output: str) -> str | None:
        return _parse_serial(output)


@register_driver
class ArubaInstantOnDriver(Driver):
    """An Instant On switch: SNMP and ICMP only (see the module docstring).
    Every command capability keeps the raising default."""

    device_types = ("aruba_instant_on",)
    vendor = "aruba"
    display_name = "Aruba Instant On"
    cli = False
