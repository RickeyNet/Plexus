"""Netgear drivers: fully managed switches, smart switches and access points.

Three product lines, told apart by what they can be managed with:

  - **Fully managed switches** (M4250, M4300, M4350, M4500, and the M4100,
    M5300, M6100, M7100 and GSM72xx before them). An SSH command line
    derived from Broadcom's ICOS (FASTPATH): ``show mac-addr-table``,
    ``show vlan brief``, ``show lldp remote-device all``, and ISDP in place
    of CDP. Netmiko reaches it as ``netgear_prosafe``; ntc-templates has no
    Netgear templates and files the ones for this command set under
    ``broadcom_icos``, so the tables are parsed with those
    (``template_platform``).
  - **Smart switches** (GS1xxT, GS3xxT, GS7xxT, XS7xxT, MS5xxT: the Smart,
    Smart Managed Pro and S350 lines). No command line: managed from their
    web page or the Insight cloud, they answer SNMP. Plexus polls them over
    SNMP and never opens an SSH session (``cli = False``).
  - **Access points** (WAX, WBE and WAC series). The same: a web page or
    Insight, and SNMP when it is enabled on a standalone access point.

Plus switches (GS105E, GS308E) have neither SNMP nor a command line and
are ICMP-only hosts.

Not implemented on the managed switches, so the callers report it instead
of sending another vendor's syntax: the port table over SSH (ntc-templates
has no template for ``show port all``; ports come from SNMP IF-MIB), the
SNMPv3 setup playbook, NetFlow export (these switches export sFlow) and
the software upgrade workflow.
"""

from __future__ import annotations

import re

from netcontrol.drivers.base import Driver, RouteTableCommands, _row_value, register_driver

# "Serial Number........ X" of ``show version``.
_SERIAL = re.compile(r"^\s*Serial\s+Number\s*\.+\s*(\S+)", re.IGNORECASE | re.MULTILINE)
# Statuses of ``show mac-addr-table`` that are not a station behind a port:
# the switch's own addresses.
_OWN_MAC_STATUSES = frozenset({"management", "self"})


@register_driver
class NetgearManagedDriver(Driver):
    device_types = ("netgear_prosafe",)
    vendor = "netgear"
    display_name = "Netgear managed switch"
    template_platform = "broadcom_icos"

    def route_table_commands(self) -> RouteTableCommands:
        # No summary command is read: the table is read at each collection.
        # The M4250 / M4300 have one routing table; a VRF of an M4500 is not read.
        return RouteTableCommands(None, "show ip route", None)

    def capture_running_config_command(self) -> str:
        return "show running-config"

    def capture_full_config_command(self) -> str:
        return "show running-config all"

    def save_config_commands(self) -> list[str]:
        # Without ``confirm`` the switch asks "Are you sure you want to save? (y/n)".
        return ["write memory confirm"]

    def mac_table_show_command(self) -> str:
        return "show mac-addr-table"

    def parse_mac_table(self, parsed_rows: list[dict]) -> list[dict]:
        rows = []
        for row in parsed_rows or []:
            status = _row_value(row, "status").lower()
            if status in _OWN_MAC_STATUSES:
                continue
            rows.append(
                {**row, "port": _row_value(row, "interface"), "type": "static" if status == "static" else "dynamic"}
            )
        return self._parse_cisco_style_mac_rows(rows)

    def vlan_show_command(self) -> str:
        return "show vlan brief"

    def parse_vlans(self, rows: list[dict]) -> list[dict]:
        # The third column is how the VLAN was made (Default, Static), not a state.
        return [{**vlan, "state": "active"} for vlan in self._parse_cisco_style_vlan_rows(rows)]

    def neighbor_show_commands(self) -> list[tuple[str, str]]:
        # ISDP is the switch's CDP: it hears Cisco devices and is stored as CDP.
        # The LLDP summary has no management address, so a neighbor is matched by its name.
        return [("cdp", "show isdp neighbors"), ("lldp", "show lldp remote-device all")]

    def parse_neighbors(self, protocol: str, rows: list[dict]) -> list[dict]:
        if protocol == "lldp":
            # A port without a neighbor is printed too, as its name alone;
            # the chassis id is not a name to fall back to.
            rows = [
                {k: v for k, v in row.items() if k != "chassis_id"}
                for row in rows or []
                if _row_value(row, "neighbor_name")
            ]
        return self._parse_neighbor_rows(protocol, rows)

    def show_version_command(self) -> str:
        return "show version"

    def serial_number_show_command(self) -> str:
        # Not filtered with ``| include``: older releases have no output filters.
        return "show version"

    def parse_serial_number(self, output: str) -> str | None:
        match = _SERIAL.search(output or "")
        return match.group(1) if match else None


@register_driver
class NetgearSmartSwitchDriver(Driver):
    """A Netgear smart switch: SNMP and ICMP only (see the module docstring).
    Every command capability keeps the raising default."""

    device_types = ("netgear_smart",)
    vendor = "netgear"
    display_name = "Netgear smart switch"
    cli = False


@register_driver
class NetgearAccessPointDriver(Driver):
    """A Netgear access point: SNMP and ICMP only."""

    device_types = ("netgear_ap",)
    vendor = "netgear"
    display_name = "Netgear access point"
    cli = False
