"""Driver ABC, registry, and shared dataclasses.

A ``Driver`` is stateless: methods take parameters and return data
(command lists, show-command strings).  Network I/O stays in the
caller (the playbook or route handler) so drivers remain trivially
unit-testable without Netmiko or a real device.

Registration is by Plexus ``device_type`` string (the same value stored
on ``hosts.device_type`` and accepted by Netmiko).  A single driver
class can register itself for several device_types via the
``device_types`` class variable; ``cisco_nxos`` and ``cisco_nxos_ssh``
share one driver, for example.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import ClassVar


class DriverCapabilityError(NotImplementedError):
    """Raised when a driver is asked for a capability it does not implement.

    Subclasses ``NotImplementedError`` so callers can catch the standard
    type, but the dedicated subclass makes it obvious in logs/tracebacks
    that the failure is a driver gap (add the method to the vendor's
    driver) versus a generic abstract-method bug.
    """


def _normalise_mac(raw: str) -> str:
    """Convert any common MAC representation to lower-case colon-separated hex.

    Cisco show output uses Cisco-style ``aabb.ccdd.eeff``; Arista / Junos
    print ``aa:bb:cc:dd:ee:ff``; some platforms print hyphen-separated.
    The downstream sqlite/postgres rows store the colon form, so we
    canonicalise here once.
    """
    hex_only = "".join(c for c in raw.lower() if c in "0123456789abcdef")
    if len(hex_only) != 12:
        return raw.strip().lower()
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


# Every VLAN a trunk can carry, stored literally instead of 4094 ids.
ALL_VLANS = "1-4094"
_VLAN_RANGE = re.compile(r"^(\d+)\s*-\s*(\d+)$")


def parse_vlan_ranges(text: str) -> set[int]:
    """The VLAN ids of a list such as ``"1-5,10,20-22"`` (``"ALL"``: every
    VLAN, ``"NONE"`` or an unreadable item: none). Ids outside 1-4094 are dropped."""
    out: set[int] = set()
    for part in str(text or "").split(","):
        part = part.strip()
        if part.upper() == "ALL":
            return set(range(1, 4095))
        match = _VLAN_RANGE.match(part)
        if match:
            first, last = int(match.group(1)), int(match.group(2))
            out.update(range(max(first, 1), min(last, 4094) + 1))
        elif part.isdigit() and 1 <= int(part) <= 4094:
            out.add(int(part))
    return out


def vlan_csv(text: str) -> str:
    """The comma-separated sorted VLAN ids of a trunk's allowed list (the
    ``interface_inventory.trunk_vlans`` form), or ``ALL_VLANS`` for every VLAN."""
    vlans = parse_vlan_ranges(text)
    if len(vlans) == 4094:
        return ALL_VLANS
    return ",".join(str(v) for v in sorted(vlans))


def _row_value(row: dict, *keys: str) -> str:
    """The first non-empty of ``keys`` in an ntc-templates row, as text (a
    List value is joined with commas). The names differ between templates
    and between ntc-templates versions, so callers name every candidate."""
    for key in keys:
        value = row.get(key)
        if isinstance(value, list):
            value = ",".join(str(v).strip() for v in value if str(v).strip())
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _ip_or_blank(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return ""


def _speed_mbps(text: str) -> int:
    """Mbps of a status table's speed column (``a-1000``, ``10G``, ``2.5G``, ``100``; ``auto``: 0)."""
    value = text.strip().lower().removeprefix("a-")
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([gm]?)", value)
    if not match:
        return 0
    number = float(match.group(1))
    return int(number * 1000) if match.group(2) == "g" else int(number)


def _duplex_word(text: str) -> str:
    value = text.strip().lower()
    if not value:
        return ""
    if "full" in value:
        return "full"
    if "half" in value:
        return "half"
    return "unknown"


# Status-table words of a port whose link is up, and of one shut down by its configuration.
_OPER_UP = frozenset({"connected", "up", "monitoring"})
_ADMIN_DOWN = frozenset({"disabled"})
_CONFIG_VLAN = re.compile(r"^vlan\s+([\d,\s-]+)$", re.IGNORECASE)
_CONFIG_NAME = re.compile(r"^\s+name\s+(.+?)\s*$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class NetflowConfig:
    """Inputs to ``Driver.build_netflow_config``.

    Kept as a dataclass (rather than positional args) so future fields
    - export protocol version, source interface override, IPFIX vs v9
    selection - can be added without changing every driver signature.
    """

    collector_ip: str
    collector_port: int
    interfaces: list[str]
    sampling_rate: int = 1
    exporter_name: str = "PLEXUS-EXPORT"
    monitor_name: str = "PLEXUS-MON"
    record_name: str = "PLEXUS-RECORD"
    sampler_name: str = "PLEXUS-SAMPLER"


@dataclass(frozen=True, slots=True)
class RouteTableCommands:
    """The show commands that read a device's route table.

    ``summary`` is the cheap command the monitoring poll runs every tick to
    see whether the table moved (``None``: the platform has none, so the
    full table is read every tick); ``table`` prints the full table of the
    global routing instance; ``all_vrfs`` prints every VRF's table
    (``None``: ``table`` already does, or the platform has no VRFs). The
    path trace reads the stored output (``netcontrol.integrations.pathtrace``).
    """

    summary: str | None
    table: str
    all_vrfs: str | None = None


# What the monitoring poll sent to every device before the drivers knew the
# commands: the fallback for a device_type without a driver.
IOS_ROUTE_TABLE_COMMANDS = RouteTableCommands("show ip route summary", "show ip route", "show ip route vrf *")


class Driver:
    """Vendor-neutral capability surface for a network device.

    Concrete drivers override ``device_types`` (the set of Plexus
    device_type strings they handle) and whichever capability methods
    they support.  Anything left as the base implementation raises
    ``DriverCapabilityError`` so callers fail loudly rather than
    silently doing the wrong thing.
    """

    device_types: ClassVar[tuple[str, ...]] = ()
    vendor: ClassVar[str] = "generic"
    display_name: ClassVar[str] = "Generic"

    def build_netflow_config(self, cfg: NetflowConfig) -> list[str]:
        """Return the config-mode command lines that enable NetFlow export."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement build_netflow_config()")

    def netflow_verify_command(self) -> str:
        """Return a ``show`` command that confirms the exporter is up."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement netflow_verify_command()")

    def capture_running_config_command(self) -> str:
        """Return the show command that dumps the device's running config.

        The result is consumed by config-backup and lab snapshot code that
        SSHes to the device, runs the command, and stores the raw text.
        Vendor-specific because e.g. Juniper Junos uses
        ``show configuration | display set`` while Cisco uses
        ``show running-config``.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement capture_running_config_command()")

    def route_table_commands(self) -> RouteTableCommands:
        """Return the show commands that read the device's route table.

        Consumed by the monitoring poll, which stores the output for the
        path trace. Vendor-specific because an ASA or Junos prints its
        table with ``show route`` and a FortiGate with ``get router info
        routing-table all``, and because the all-VRFs form differs
        (``vrf *`` on IOS, ``vrf all`` on NX-OS and EOS).
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement route_table_commands()")

    def save_config_commands(self) -> list[str]:
        """Return the command(s) that persist running-config to startup.

        Returned as a list because some platforms (NX-OS) want a single
        ``copy running-config startup-config`` while others may need
        multiple steps.  An empty list means "no save step required"
        (e.g. Junos commit semantics, where ``commit`` already persists).

        Most callers will prefer Netmiko's ``conn.save_config()`` which
        handles vendor quirks automatically; this exists for routes that
        push config without Netmiko's high-level helper.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement save_config_commands()")

    # ── MAC address-table capability surface ───────────────────────────────
    #
    # The mac_tracking collector historically polled the bridge / Q-BRIDGE
    # MIB over SNMP, which on Cisco needs a per-VLAN SNMPv3 context dance
    # to see anything beyond VLAN 1.  CLI scraping with ntc-templates
    # parses the same data from one ``show mac address-table`` command
    # without any of that ceremony.  The driver owns the command and the
    # row-normalisation so the collector stays vendor-neutral.
    #
    # The default implementation here covers every CLI that ships
    # Cisco-style output (``show mac address-table`` returning a vlan /
    # mac / type / port-name table parseable by the bundled ntc-template
    # ``cisco_ios_show_mac_address-table``).  That's IOS, IOS-XE, NX-OS,
    # and Arista EOS — all four can rely on the base implementation.
    # Junos, Palo Alto, Fortinet, Cisco XR all need overrides if/when MAC
    # tracking is wanted there.

    def mac_table_show_command(self) -> str:
        """Return the show command that dumps the device's MAC address table.

        Raises ``DriverCapabilityError`` by default so a firewall driver
        (which has no L2 forwarding table) doesn't accidentally get a
        switch-only command shipped to its SSH session.  Switch / bridge
        drivers override.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement mac_table_show_command()")

    def parse_mac_table(self, parsed_rows: list[dict]) -> list[dict]:
        """Normalise textfsm-parsed rows into the collector's schema.

        Input is what Netmiko returns from ``send_command(...,
        use_textfsm=True)`` — a list of dicts whose keys come from the
        ntc-template column names (vendor-specific).  Output is a list of
        ``{"mac", "vlan", "port", "type"}`` dicts the collector can hand
        straight to ``upsert_mac_entry``.

        Default raises ``DriverCapabilityError`` to match the show-command
        contract above; switch drivers override with vendor-appropriate
        column names.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement parse_mac_table()")

    @staticmethod
    def _parse_cisco_style_mac_rows(parsed_rows: list[dict]) -> list[dict]:
        """Shared helper for drivers whose textfsm template matches the
        cisco_ios ``show mac address-table`` schema (vlan / destination_address
        / type / destination_port).  IOS, IOS-XE, NX-OS and Arista EOS all
        use this layout, so they call into this helper rather than duplicating
        the row-normalisation logic.
        """
        out: list[dict] = []
        for row in parsed_rows or []:
            mac_raw = (row.get("destination_address") or row.get("mac") or row.get("mac_address") or "").strip()
            if not mac_raw:
                continue
            # ntc-templates 9 names the column vlan_id and prints the ports as a list.
            vlan_raw = _row_value(row, "vlan_id", "vlan")
            try:
                vlan = int(vlan_raw)
            except ValueError, TypeError:
                # Cisco prints "All" for system / multicast entries — skip
                # them, they're not learnt MACs.
                continue
            port = _row_value(row, "destination_port", "ports", "port").split(",")[0].strip()
            if not port or port.lower() in ("cpu", "router", "switch"):
                continue
            type_raw = str(row.get("type", "dynamic")).strip().lower()
            out.append(
                {
                    "mac": _normalise_mac(mac_raw),
                    "vlan": vlan,
                    "port": port,
                    "type": type_raw if type_raw in ("dynamic", "static") else "dynamic",
                }
            )
        return out

    # ── VLAN, port and neighbor tables (CLI) ──────────────────────────────
    #
    # The topology inventory collection reads these over the SSH session it
    # already holds, so a switch without SNMP still gets its VLANs, ports and
    # CDP/LLDP neighbors. Each show command is parsed by ntc-templates
    # (Netmiko ``use_textfsm=True``) and the driver turns those rows into the
    # Plexus rows: ``parse_vlans`` -> ``{"vlan_id", "name", "state"}``,
    # ``parse_interfaces`` -> the ``interface_inventory`` fields,
    # ``parse_neighbors`` -> ``{"local_interface", "remote_device_name",
    # "remote_ip", "remote_interface", "protocol", "remote_platform"}`` (the
    # SNMP neighbor discovery's keys) plus ``"remote_capabilities"``. A
    # firewall keeps the raising defaults.

    def vlan_show_command(self) -> str:
        """Return the show command that lists the VLANs defined on the device."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement vlan_show_command()")

    def interface_status_show_command(self) -> str:
        """Return the show command that prints one status line per port."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement interface_status_show_command()")

    def interface_switchport_show_command(self) -> str:
        """Return the show command that prints each port's access VLAN and trunk VLANs."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement interface_switchport_show_command()")

    def neighbor_show_commands(self) -> list[tuple[str, str]]:
        """Return ``(protocol, command)`` pairs that print the CDP / LLDP neighbors, CDP first."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement neighbor_show_commands()")

    def parse_vlans(self, rows: list[dict]) -> list[dict]:
        """Normalise the parsed ``vlan_show_command()`` rows into ``{"vlan_id", "name", "state"}``."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement parse_vlans()")

    def parse_config_vlans(self, config_text: str) -> list[dict]:
        """The VLANs a running configuration declares, for a device whose
        VLAN command was rejected or not parsed (same row shape as ``parse_vlans``)."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement parse_config_vlans()")

    def parse_interfaces(self, status_rows: list[dict], switchport_rows: list[dict]) -> list[dict]:
        """Merge the parsed status and switchport rows into ``interface_inventory`` rows."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement parse_interfaces()")

    def parse_neighbors(self, protocol: str, rows: list[dict]) -> list[dict]:
        """Normalise the parsed rows of one ``neighbor_show_commands()`` command."""
        raise DriverCapabilityError(f"{type(self).__name__} does not implement parse_neighbors()")

    @staticmethod
    def _parse_cisco_style_vlan_rows(rows: list[dict]) -> list[dict]:
        """Shared helper for the ``show vlan`` templates of IOS, NX-OS and EOS
        (vlan_id / vlan_name / status)."""
        out: dict[int, dict] = {}
        for row in rows or []:
            raw = _row_value(row, "vlan_id", "vlan", "tag")
            if not raw.isdigit() or not 1 <= int(raw) <= 4094:
                continue
            state = _row_value(row, "status", "state").lower() or "active"
            out[int(raw)] = {"vlan_id": int(raw), "name": _row_value(row, "vlan_name", "name"), "state": state}
        return [out[vid] for vid in sorted(out)]

    @staticmethod
    def _parse_cisco_style_config_vlans(config_text: str) -> list[dict]:
        """Shared helper: the ``vlan N`` / `` name X`` blocks of an IOS, NX-OS
        or EOS configuration (``vlan 10,20-22`` declares several, unnamed)."""
        found: dict[int, str] = {}
        current: int | None = None
        for line in str(config_text or "").splitlines():
            match = _CONFIG_VLAN.match(line.rstrip())
            if match:
                ids = parse_vlan_ranges(match.group(1).replace(" ", ""))
                for vid in ids:
                    found.setdefault(vid, "")
                current = next(iter(ids)) if len(ids) == 1 else None
                continue
            name = _CONFIG_NAME.match(line)
            if current is not None and name:
                found[current] = name.group(1)
            elif line.strip() and not line.startswith((" ", "\t")):
                current = None
        return [{"vlan_id": vid, "name": found[vid], "state": "active"} for vid in sorted(found)]

    @staticmethod
    def _parse_cisco_style_interface_rows(status_rows: list[dict], switchport_rows: list[dict]) -> list[dict]:
        """Shared helper for the ``show interface(s) status`` and ``show
        interface(s) switchport`` templates of IOS, NX-OS and EOS. Rows are
        matched by interface name across the abbreviations; the status
        table's spelling is stored. Value conventions follow the SNMP
        collector: up/down words, Mbps, access VLAN 0 when none, trunk VLANs
        as ``vlan_csv``."""
        from netcontrol.integrations.pathtrace.route_tables import interface_key

        switchports = {
            interface_key(_row_value(row, "interface", "name", "port")): row
            for row in switchport_rows or []
            if _row_value(row, "interface", "name", "port")
        }
        out: list[dict] = []
        for row in status_rows or []:
            port = _row_value(row, "port", "interface")
            if not port:
                continue
            status = _row_value(row, "status").lower()
            status_vlan = _row_value(row, "vlan_id", "vlan").lower()
            switchport = switchports.get(interface_key(port), {})
            mode = _row_value(switchport, "mode", "operational_mode").lower()
            admin_mode = _row_value(switchport, "admin_mode", "administrative_mode").lower()
            trunk = "trunk" in mode or ("trunk" in admin_mode and mode in ("", "down")) or status_vlan == "trunk"
            access = _row_value(switchport, "access_vlan") or status_vlan.split(",")[0]
            description = _row_value(row, "name", "description")
            out.append(
                {
                    "name": port,
                    # NX-OS prints "--" for a port without a description.
                    "description": "" if description == "--" else description,
                    "admin_state": "down" if status in _ADMIN_DOWN else ("up" if status else ""),
                    "oper_state": "up" if status in _OPER_UP else ("down" if status else ""),
                    "speed_mbps": _speed_mbps(_row_value(row, "speed")),
                    "duplex": _duplex_word(_row_value(row, "duplex")),
                    "access_vlan": 0 if trunk or not access.isdigit() else int(access),
                    # A trunk whose allowed list was not printed (no switchport row) stays unknown.
                    "trunk_vlans": vlan_csv(_row_value(switchport, "trunking_vlans", "trunk_vlans", "allowed_vlans"))
                    if trunk
                    else "",
                }
            )
        return out

    @staticmethod
    def _parse_neighbor_rows(protocol: str, rows: list[dict]) -> list[dict]:
        """Shared helper for every CDP / LLDP neighbor template (IOS, NX-OS,
        EOS, Junos, IOS-XR name the same things differently)."""
        out: list[dict] = []
        for row in rows or []:
            local = _row_value(row, "local_interface", "local_port")
            name = _row_value(row, "neighbor_name", "neighbor", "destination_host", "system_name", "chassis_id")
            if not local or not name:
                continue
            if protocol == "cdp":
                # NX-OS prints "name(SERIAL)" as the Device ID; the SNMP discovery keeps the name.
                name = name.split("(")[0].strip() or name
                remote = _row_value(row, "neighbor_interface", "remote_port", "port_id")
                platform = _row_value(row, "platform")
            else:
                remote = _row_value(row, "neighbor_port_id", "neighbor_interface", "neighbor_port_description")
                platform = _row_value(row, "neighbor_description", "system_description", "platform")
            out.append(
                {
                    "local_interface": local,
                    "remote_device_name": name,
                    "remote_ip": _ip_or_blank(
                        _row_value(row, "mgmt_address", "management_ip", "management_address", "interface_ip")
                    ),
                    "remote_interface": remote,
                    "protocol": protocol,
                    "remote_platform": platform[:200],
                    # As printed: CDP words ("Router Switch IGMP", "Host Phone"),
                    # LLDP letters ("B,R", "B,T"). The map tells end devices by them.
                    "remote_capabilities": _row_value(row, "capabilities")[:100],
                }
            )
        return out

    # ── SNMPv3 capability surface ──────────────────────────────────────────
    #
    # SNMPv3 provisioning happens in a single playbook
    # (``templates/playbooks/snmpv3_configurator.py``).  The playbook owns
    # the high-level flow (show existing → pin engine ID → push user
    # template → verify); each step's vendor-specific command comes from
    # the driver so the playbook itself can be vendor-neutral.

    def snmpv3_show_existing_command(self) -> str:
        """Return a show command that prints the device's current SNMP config.

        Used by the SNMPv3 playbook as the "before" snapshot so the
        operator can see what was already there.  Cisco platforms use
        ``show running-config | include snmp-server``; Junos would be
        ``show configuration snmp | display set``.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement snmpv3_show_existing_command()")

    def snmpv3_engine_id_show_command(self) -> str:
        """Return the show command that prints the local SNMP engine ID.

        Returns an empty string when the platform doesn't expose engine
        ID pinning as a config knob (NX-OS persists the engine ID by
        default, so pinning is unnecessary and ``snmp-server engineID
        local`` is not a valid command).
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement snmpv3_engine_id_show_command()")

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        """Return the config line that pins the SNMP engine ID.

        Cisco IOS / IOS-XE regenerate the engine ID when certain
        ``snmp-server`` lines are added or removed.  Because SNMPv3 keys
        are *localized* to the engine ID, regeneration silently
        invalidates every existing user - monitoring then breaks until
        the keys are re-cut.  Pinning the current ID before any change
        keeps the keys valid.

        Returns an empty string when the platform doesn't support
        pinning (see ``snmpv3_engine_id_show_command``).
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement snmpv3_engine_id_pin_command()")

    def snmpv3_verify_users_command(self) -> str:
        """Return the show command that lists configured SNMPv3 users.

        Used as the "after" verification step in the SNMPv3 playbook.
        ``show snmp user`` is the de-facto common command across IOS,
        IOS-XE, and NX-OS; Junos uses ``show snmp v3 user``.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement snmpv3_verify_users_command()")

    # ── Health-check / fingerprint capability surface ──────────────────────
    #
    # Inventory's "fetch serial" feature and the upgrade pre-stage health
    # check both need to read the device's chassis identity (serial,
    # model, software version).  Each platform spells these differently:
    # IOS / IOS-XE expose "System Serial Number" via ``show version``,
    # NX-OS calls the same field "Processor Board ID" in its ``show
    # version`` output, Junos uses ``show chassis hardware`` and prints
    # "Serial number" lines.  The driver owns both the command to run
    # and the parser that pulls the serial out so callers don't have to
    # branch on device_type.

    def show_version_command(self) -> str:
        """Return the full ``show version`` command for this platform.

        Used by the upgrade pre-stage code that needs the unfiltered
        version output to extract both software version and chassis
        model.  Most platforms accept ``show version`` verbatim; Junos
        would override with ``show version detail``.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement show_version_command()")

    def serial_number_show_command(self) -> str:
        """Return an include-filtered show command for the serial line only.

        The inventory fetch-serial UI fires this against many hosts in
        parallel; filtering at the device (rather than pulling the
        whole ``show version`` over SSH) keeps the round-trip small.
        IOS / IOS-XE use ``show version | include System Serial Number``;
        NX-OS uses ``show version | include "Processor Board"`` because
        the NX-OS chassis serial is printed as "Processor Board ID" not
        "System Serial Number".
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement serial_number_show_command()")

    def parse_serial_number(self, output: str) -> str | None:
        """Extract the chassis serial from ``show version`` output.

        Accepts either the full ``show version`` output or the
        filtered output from ``serial_number_show_command()`` - the
        parser scans line-by-line for the platform's serial label.
        Returns ``None`` when no serial line is found (the caller
        decides whether that is a 422 or a "try again later").
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement parse_serial_number()")

    # ── Software upgrade capability surface ────────────────────────────────
    #
    # The upgrades route (``netcontrol/routes/upgrades.py``) historically
    # hard-coded Cisco IOS-XE "install mode" verbs: ``install add file``
    # to pre-stage, ``install activate prompt-level none`` to activate +
    # reload, ``install commit`` to make the new image permanent.  Junos
    # uses ``request system software add`` + ``request system reboot``
    # in a single phase (no separate add/activate split); NX-OS uses
    # ``install all nxos``; classic IOS uses ``copy tftp:`` + ``boot
    # system flash:`` + ``reload``.  These methods give the driver a
    # place to surface the right verb so the route doesn't have to
    # branch on device_type.  Routes that have only implemented the
    # IOS-XE flow can still call ``upgrade_install_add_command`` on a
    # Junos host and get a clear ``DriverCapabilityError`` instead of
    # silently shipping Cisco syntax to a Juniper SSH session.

    def upgrade_has_discrete_prestage(self) -> bool:
        """Return True if the platform has a separate "stage image" step.

        IOS-XE install mode splits the workflow in two: ``install add
        file`` pre-stages the package, then a later ``install activate``
        flips to it and reloads.  The upgrade route runs both as
        distinct phases (``transfer`` ends with the install-add;
        ``activate`` runs after operator approval).

        Junos collapses the two into a single ``request system software
        add ... reboot`` operation - there is no "staged but not yet
        activated" state to land in - so the route must skip the
        prestage call and let the activate phase do both at once.

        Default is False so drivers that don't override (Junos, NX-OS,
        classic IOS) get the single-phase shape, which matches the
        majority of non-IOS-XE vendors.  IOS-XE returns True.
        """
        return False

    def upgrade_install_add_command(self, image_path: str) -> str:
        """Return the command that pre-stages a software image.

        ``image_path`` is the full device-side path (e.g.
        ``flash:cat9k_iosxe.17.09.04a.SPA.bin``).  IOS-XE: ``install
        add file <path>``.  Platforms that don't have a discrete
        pre-stage step (Junos performs add+activate as one operation)
        should raise ``DriverCapabilityError`` so the caller routes
        through ``upgrade_activate_commands`` instead.

        Callers should consult ``upgrade_has_discrete_prestage()`` and
        skip this call entirely when it returns False - otherwise the
        ``DriverCapabilityError`` raised here will surface as a "pre-
        stage not supported" error in the operator log, which is
        misleading for platforms that simply don't need pre-staging.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement upgrade_install_add_command()")

    def upgrade_activate_commands(self, image_path: str, *, issu: bool = False) -> list[str]:
        """Return the command(s) that activate the staged image and reboot.

        Returns a list because some platforms need multiple steps
        (e.g. Junos: ``request system software add ... no-validate``
        then ``request system reboot``).  The final command in the
        list is expected to trigger the reload - the caller treats a
        dropped SSH session after the last command as success.

        ``issu=True`` requests an in-service upgrade (standby reloads
        first, switchover, then the old active reloads) so a dual-sup
        chassis or StackWise Virtual pair never fully leaves the
        network.  Callers must check ``upgrade_supports_issu()`` first;
        drivers that don't override this default ignore the flag, so
        passing it blindly would silently run a disruptive reload.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement upgrade_activate_commands()")

    def upgrade_supports_issu(self) -> bool:
        """Return True if ``upgrade_activate_commands(issu=True)`` is meaningful.

        Default False.  IOS-XE install mode supports ``install activate
        issu`` on redundant platforms (Catalyst 9400/9600 dual-sup,
        9500 StackWise Virtual).  The route refuses an ISSU campaign
        on any driver that returns False rather than downgrading to a
        disruptive reload behind the operator's back.
        """
        return False

    def upgrade_redundancy_show_command(self) -> str:
        """Return the command that reports supervisor/SVL redundancy state.

        IOS-XE: ``show redundancy``.  Used by the upgrade pre-flight
        health check (standby must be STANDBY HOT before an activate
        on a redundant chassis) and as a hard gate before an ISSU
        activate (which additionally requires SSO).  Platforms with no
        redundancy concept should leave this unimplemented - the route
        treats ``DriverCapabilityError`` as "standalone, skip check".
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement upgrade_redundancy_show_command()")

    def parse_redundancy_state(self, output: str) -> dict:
        """Parse ``upgrade_redundancy_show_command()`` output.

        Returns a dict with at least:

        - ``redundant`` (bool): a peer supervisor / SVL member exists
        - ``standby_hot`` (bool): peer is fully synced (STANDBY HOT)
        - ``hardware_mode`` / ``operating_mode`` / ``peer_state``
          (str | None): raw fields for the operator log
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement parse_redundancy_state()")

    def upgrade_boot_mode_show_command(self) -> str:
        """Return the command that reports the software boot mode.

        IOS-XE Catalyst 9k boots either in INSTALL mode (packages.conf
        + unpacked .pkg files - the only mode ``install add`` /
        ``install activate`` work in) or BUNDLE mode (boots the .bin
        directly; ``install add`` errors out).  The route runs this
        before the first install verb so a BUNDLE-mode chassis fails
        fast with a clear message instead of a cryptic CLI error.
        Platforms without the concept leave this unimplemented - the
        route treats ``DriverCapabilityError`` as "no gate".
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement upgrade_boot_mode_show_command()")

    def parse_boot_mode(self, output: str) -> str | None:
        """Parse ``upgrade_boot_mode_show_command()`` output.

        Returns ``"install"``, ``"bundle"``, or ``None`` when the mode
        can't be determined (the route only *blocks* on ``"bundle"``;
        unknown is logged as a warning and allowed through).
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement parse_boot_mode()")

    def upgrade_commit_command(self) -> str:
        """Return the command that makes the new image permanent.

        Cisco IOS-XE install mode rolls back automatically on the
        next reload unless ``install commit`` runs after the activate
        completes.  NX-OS auto-commits.  Junos persists on commit.
        Platforms with no separate commit step should return an empty
        string so the caller can short-circuit.
        """
        raise DriverCapabilityError(f"{type(self).__name__} does not implement upgrade_commit_command()")


class CiscoStyleTables:
    """Mixin: the ``parse_*`` methods of the VLAN, port and neighbor tables
    for a platform whose ntc-templates follow the Cisco layout (IOS,
    IOS-XE, NX-OS, EOS). The driver still names its own show commands."""

    def parse_vlans(self, rows: list[dict]) -> list[dict]:
        return Driver._parse_cisco_style_vlan_rows(rows)

    def parse_config_vlans(self, config_text: str) -> list[dict]:
        return Driver._parse_cisco_style_config_vlans(config_text)

    def parse_interfaces(self, status_rows: list[dict], switchport_rows: list[dict]) -> list[dict]:
        return Driver._parse_cisco_style_interface_rows(status_rows, switchport_rows)

    def parse_neighbors(self, protocol: str, rows: list[dict]) -> list[dict]:
        return Driver._parse_neighbor_rows(protocol, rows)


class GenericDriver(Driver):
    """Fallback used when no driver is registered for a device_type.

    All capability methods raise ``DriverCapabilityError`` so an
    unknown vendor never silently falls through to a Cisco code path -
    the operator gets a clear "no driver for foo_os" error instead.
    """

    vendor = "unknown"
    display_name = "Unknown"


_REGISTRY: dict[str, type[Driver]] = {}


def register_driver(cls: type[Driver]) -> type[Driver]:
    """Class decorator that registers ``cls`` for each of its device_types.

    Re-registering an existing device_type is a programming error and
    raises ``ValueError`` - silently shadowing a driver would make
    "which driver am I getting?" depend on import order.
    """
    if not cls.device_types:
        raise ValueError(f"{cls.__name__} must declare a non-empty device_types tuple before it can be registered.")
    for dt in cls.device_types:
        existing = _REGISTRY.get(dt)
        if existing is not None and existing is not cls:
            raise ValueError(
                f"device_type {dt!r} already registered to {existing.__name__}; cannot re-register to {cls.__name__}"
            )
        _REGISTRY[dt] = cls
    return cls


def get_driver(device_type: str | None) -> Driver:
    """Return a driver instance for ``device_type``, or ``GenericDriver``.

    ``None`` and unknown strings both yield the generic driver - callers
    that care about the distinction should check ``isinstance(drv,
    GenericDriver)`` or inspect ``drv.vendor``.
    """
    if not device_type:
        return GenericDriver()
    cls = _REGISTRY.get(device_type, GenericDriver)
    return cls()


def registered_device_types() -> tuple[str, ...]:
    """Sorted tuple of every device_type that currently has a driver.

    Useful for surfacing supported platforms in the UI or for
    diagnostics endpoints.
    """
    return tuple(sorted(_REGISTRY.keys()))
