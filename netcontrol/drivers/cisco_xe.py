"""Cisco IOS-XE driver (Flexible NetFlow)."""

from __future__ import annotations

import re

from netcontrol.drivers.base import CiscoStyleTables, Driver, NetflowConfig, RouteTableCommands, register_driver

# Receive windows in bytes.  ``_DEFAULT_TCP_WINDOW`` is the IOS default
# when ``ip tcp window-size`` is unset.  A TCP or SSH window below
# ``_MIN_FAST_WINDOW`` leaves an SCP image copy over a high-latency path
# window-bound; ``_RECOMMENDED_WINDOW`` is the value Cisco documents for
# both knobs (larger SSH windows cost CPU on low-end switches).
_DEFAULT_TCP_WINDOW = 4128
_MIN_FAST_WINDOW = 65535
_RECOMMENDED_WINDOW = 65536


@register_driver
class CiscoXEDriver(CiscoStyleTables, Driver):
    device_types = ("cisco_xe",)
    vendor = "cisco"
    display_name = "Cisco IOS-XE"

    def route_table_commands(self) -> RouteTableCommands:
        return RouteTableCommands("show ip route summary", "show ip route", "show ip route vrf *")

    def build_netflow_config(self, cfg: NetflowConfig) -> list[str]:
        cmds = [
            f"flow record {cfg.record_name}",
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
            f"flow exporter {cfg.exporter_name}",
            f" destination {cfg.collector_ip}",
            f" transport udp {cfg.collector_port}",
            " export-protocol netflow-v9",
            " source Loopback0",
            "exit",
            f"flow monitor {cfg.monitor_name}",
            f" record {cfg.record_name}",
            f" exporter {cfg.exporter_name}",
            " cache timeout active 60",
            "exit",
        ]
        if cfg.sampling_rate > 1:
            cmds += [
                f"sampler {cfg.sampler_name}",
                f" mode random 1 out-of {cfg.sampling_rate}",
                "exit",
            ]
        for intf in cfg.interfaces:
            cmds.append(f"interface {intf}")
            cmds.append(f" ip flow monitor {cfg.monitor_name} input")
            if cfg.sampling_rate > 1:
                cmds.append(f" ip flow monitor {cfg.monitor_name} sampler {cfg.sampler_name} input")
            cmds.append("exit")
        return cmds

    def netflow_verify_command(self) -> str:
        # The exporter name is interpolated into the command, so the driver
        # uses the same default the builder uses.  Callers that override
        # ``exporter_name`` on NetflowConfig should construct the verify
        # command themselves; for now Plexus always uses PLEXUS-EXPORT.
        return "show flow exporter PLEXUS-EXPORT"

    def capture_running_config_command(self) -> str:
        return "show running-config"

    def capture_full_config_command(self) -> str:
        return "show running-config all"

    def save_config_commands(self) -> list[str]:
        return ["write memory"]

    def mac_table_show_command(self) -> str:
        return "show mac address-table"

    def parse_mac_table(self, parsed_rows: list[dict]) -> list[dict]:
        return self._parse_cisco_style_mac_rows(parsed_rows)

    def vlan_show_command(self) -> str:
        return "show vlan brief"

    def interface_status_show_command(self) -> str:
        return "show interfaces status"

    def interface_switchport_show_command(self) -> str:
        return "show interfaces switchport"

    def neighbor_show_commands(self) -> list[tuple[str, str]]:
        return [("cdp", "show cdp neighbors detail"), ("lldp", "show lldp neighbors detail")]

    def snmpv3_show_existing_command(self) -> str:
        return "show running-config | include snmp-server"

    def snmpv3_engine_id_show_command(self) -> str:
        return "show snmp engineID"

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        return f"snmp-server engineID local {engine_id}"

    def snmpv3_verify_users_command(self) -> str:
        return "show snmp user"

    def show_version_command(self) -> str:
        return "show version"

    def serial_number_show_command(self) -> str:
        return "show version | include System Serial Number"

    def parse_serial_number(self, output: str) -> str | None:
        # IOS-XE prints the same "System Serial Number" line as IOS.
        for line in output.splitlines():
            if "System Serial Number" in line:
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
        return None

    def upgrade_has_discrete_prestage(self) -> bool:
        # IOS-XE install mode has a real two-phase workflow: ``install
        # add file`` lands the package in the install-mode unpacked
        # layout and ``install activate`` later flips to it.  The route
        # uses this to keep the transfer phase distinct from the
        # activate-and-reboot phase so an operator can approve activate
        # in a maintenance window after the long upload finishes.
        return True

    def upgrade_install_add_command(self, image_path: str) -> str:
        # IOS-XE install-mode pre-stage: copies the package out of the
        # .bin into the install-mode unpacked layout.  ``image_path``
        # is the device-side full path (e.g. ``flash:cat9k.bin``).
        return f"install add file {image_path}"

    def upgrade_activate_commands(self, image_path: str, *, issu: bool = False) -> list[str]:
        # ``prompt-level none`` suppresses the interactive y/n prompt so
        # the command can be sent non-interactively before the reload
        # drops the SSH session.  ``image_path`` isn't interpolated
        # because in install mode the activate operates on whatever
        # was just added, not a path argument.
        #
        # ``issu`` inserts the in-service keyword: on a dual-sup
        # chassis (9400/9600) or StackWise Virtual pair (9500) the
        # standby reloads onto the new image first, an SSO switchover
        # follows, then the old active reloads - the chassis stays
        # forwarding throughout.  Requires SSO + STANDBY HOT; the
        # route gates on ``show redundancy`` before sending this.
        if issu:
            return ["install activate issu prompt-level none"]
        return ["install activate prompt-level none"]

    def upgrade_supports_issu(self) -> bool:
        return True

    def upgrade_redundancy_show_command(self) -> str:
        return "show redundancy"

    def parse_redundancy_state(self, output: str) -> dict:
        # Representative IOS-XE output (dual-sup / SVL):
        #
        #                  Hardware Mode = Duplex
        #     Configured Redundancy Mode = sso
        #      Operating Redundancy Mode = sso
        #   ...
        #   Peer Processor Information :
        #   ----------------------------
        #                 Standby Location = slot 2
        #           Current Software state = STANDBY HOT
        #
        # Standalone box prints ``Hardware Mode = Simplex`` and, instead
        # of a Peer block, "Peer (slot: 2) information is not available
        # because it is in 'DISABLED' state".  The active's own block
        # also has a ``Current Software state = ACTIVE`` line, so the
        # peer state is only read from text *after* the Peer header.
        text = output or ""

        def _field(label: str, src: str) -> str | None:
            m = re.search(rf"{label}\s*=\s*(.+)", src)
            return m.group(1).strip() if m else None

        hardware_mode = _field("Hardware Mode", text)
        operating_mode = _field("Operating Redundancy Mode", text)

        peer_state: str | None = None
        _, sep, peer_block = text.partition("Peer Processor Information")
        if sep:
            peer_state = _field("Current Software state", peer_block)
        if peer_state is None:
            m = re.search(r"Peer .*?information is not available because it is in '([^']+)' state", text)
            if m:
                peer_state = m.group(1).strip()

        redundant = (hardware_mode or "").lower() == "duplex" or "STANDBY" in (peer_state or "").upper()
        standby_hot = (peer_state or "").upper() == "STANDBY HOT"
        return {
            "redundant": redundant,
            "standby_hot": standby_hot,
            "hardware_mode": hardware_mode,
            "operating_mode": (operating_mode or "").lower() or None,
            "peer_state": peer_state,
        }

    def upgrade_boot_mode_show_command(self) -> str:
        # ``show version`` on a stackable Catalyst 9k ends with a
        # per-switch table whose last column is ``Mode`` (INSTALL /
        # BUNDLE).  A modular chassis (9400, 9600) prints no such table,
        # so the filter also keeps the ``System image file`` line, which
        # every platform prints.  ``include`` takes a regex on IOS-XE so
        # one filter catches all three.
        return "show version | include INSTALL|BUNDLE|System image file"

    def parse_boot_mode(self, output: str) -> str | None:
        # Representative filtered lines:
        #
        #   System image file is "bootflash:packages.conf"
        #   *    1 41    C9300-48P       17.12.04          CAT9K_IOSXE           INSTALL
        #   *    1 41    C9300-48P       17.12.04          CAT9K_IOSXE           BUNDLE
        #
        # Case-sensitive whole-word match so the header row (``Mode``)
        # and prose like "installed" never register.  BUNDLE wins if
        # both somehow appear - it's the blocking state.
        text = output or ""
        if re.search(r"\bBUNDLE\b", text):
            return "bundle"
        if re.search(r"\bINSTALL\b", text):
            return "install"
        # No mode table: the boot file tells the mode.  A provisioning
        # file (packages.conf) is install mode, a monolithic .bin is
        # bundle mode.
        m = re.search(r'System image file is "([^"]+)"', text)
        if m:
            image = m.group(1).strip().lower()
            if image.endswith(".conf"):
                return "install"
            if image.endswith(".bin"):
                return "bundle"
        return None

    def upgrade_transfer_window_show_command(self) -> str:
        # The SSH window has two forms depending on release: bulk mode
        # (on by default from 17.10, and not every release accepts a
        # size argument) and the older ``ip ssh window-size``.  ``all``
        # makes a default-on bulk mode visible, and the line-start
        # anchor filters out a negated ``no ip ssh bulk-mode`` so it
        # reads as "off".
        return "show running-config all | include ^ip tcp window-size|^ip ssh window-size|^ip ssh bulk-mode"

    def parse_transfer_window(self, output: str) -> dict:
        # Representative filtered lines (any may be absent):
        #
        #   ip tcp window-size 65536
        #   ip ssh window-size 65536
        #   ip ssh bulk-mode 131072
        #
        # No TCP line means the IOS default window is in effect.  The
        # SSH side is fine with either bulk mode or a large window-size.
        text = output or ""

        def _size(command: str) -> int | None:
            m = re.search(rf"^{command} (\d+)", text, re.MULTILINE)
            return int(m.group(1)) if m else None

        tcp_window = _size("ip tcp window-size")
        ssh_window = _size("ip ssh window-size")
        ssh_bulk_mode = bool(re.search(r"^ip ssh bulk-mode\b", text, re.MULTILINE))

        problems: list[str] = []
        recommended: list[str] = []
        if (tcp_window or _DEFAULT_TCP_WINDOW) < _MIN_FAST_WINDOW:
            shown = f"{tcp_window} bytes" if tcp_window else f"{_DEFAULT_TCP_WINDOW} bytes (default)"
            problems.append(f"TCP window {shown}")
            recommended.append(f"ip tcp window-size {_RECOMMENDED_WINDOW}")
        if not ssh_bulk_mode and (ssh_window or 0) < _MIN_FAST_WINDOW:
            problems.append(f"SSH window {ssh_window} bytes" if ssh_window else "SSH window at its default")
            recommended.append(
                f"ip ssh bulk-mode (or ip ssh window-size {_RECOMMENDED_WINDOW} on releases without bulk mode)"
            )
        return {
            "tcp_window": tcp_window,
            "ssh_window": ssh_window,
            "ssh_bulk_mode": ssh_bulk_mode,
            "problems": problems,
            "recommended": recommended,
        }

    def upgrade_commit_command(self) -> str:
        # Without ``install commit`` an IOS-XE box auto-rolls-back to
        # the prior image on the *next* reload.  This finalizes it.
        return "install commit"

    def upgrade_install_state_show_command(self) -> str:
        return "show install summary"

    def parse_install_state(self, output: str) -> dict:
        # Representative output (Cisco Catalyst 9000 upgrade guide; the
        # header names the members: ``[ Switch 1 2 ]``, ``[ R0 R1 ]``):
        #
        #   [ Switch 1 2 ] Installed Package(s) Information:
        #   State (St): I - Inactive, U - Activated & Uncommitted,
        #               C - Activated & Committed, D - Deactivated & Uncommitted
        #   --------------------------------------------------------------
        #   Type  St   Filename/Version
        #   --------------------------------------------------------------
        #   IMG   I    17.12.03.0.3740
        #   IMG   C    17.09.04a.0.6
        #   --------------------------------------------------------------
        #   Auto abort timer: inactive
        #
        # An open activate shows ``Auto abort timer: active on
        # install_activate, time before rollback - 01:52:08`` (later
        # releases drop "on install_activate").  Some releases print one
        # block per member; identical package lines are merged.
        text = output or ""
        packages: list[dict] = []
        seen: set[tuple[str, str, str]] = set()
        for line in text.splitlines():
            m = _INSTALL_PACKAGE_LINE.match(line)
            if not m:
                continue
            key = (m.group(1), m.group(2), m.group(3))
            if key in seen:
                continue
            seen.add(key)
            packages.append({"type": key[0], "state": key[1], "version": key[2]})
        if not packages:
            return {}

        def _versions(state: str) -> list[str]:
            return list(dict.fromkeys(p["version"] for p in packages if p["state"] == state))

        timer: str | None = None
        m = re.search(r"Auto abort timer\s*:\s*(inactive|active)\b", text, re.IGNORECASE)
        if m:
            timer = m.group(1).lower()
        rollback = re.search(r"time before rollback\s*[-:]\s*(\d+:\d{2}:\d{2})", text, re.IGNORECASE)
        return {
            "packages": packages,
            "committed": _versions("C"),
            "uncommitted": _versions("U"),
            "inactive": _versions("I"),
            "deactivated": _versions("D"),
            "auto_abort_timer": timer,
            "rollback_in": rollback.group(1) if rollback else None,
        }

    def upgrade_install_log_show_command(self) -> str:
        return "show install log"

    def parse_install_log(self, output: str) -> dict:
        # Operations start with ``[2|install_activate]: START <date>`` in
        # the log, or ``install_activate: START <date>`` when echoed by
        # the command itself, and end with ``END SUCCESS`` / ``END
        # FAILED ...`` or ``SUCCESS: install_activate`` / ``FAILED:
        # install_activate : <reason>``.  Only the last operation that
        # started is summarised.
        lines = (output or "").splitlines()
        start_idx = None
        operation = ""
        for idx, line in enumerate(lines):
            m = _INSTALL_LOG_START.search(line)
            if m:
                start_idx, operation = idx, m.group(1)
        if start_idx is None:
            return {}
        result: str | None = None
        reasons: list[str] = []
        for line in lines[start_idx + 1 :]:
            stripped = line.strip()
            if not stripped:
                continue
            outcome = _INSTALL_LOG_RESULT.search(stripped)
            if outcome:
                result = (outcome.group(1) or outcome.group(2)).upper()
            if _INSTALL_LOG_REASON.search(stripped):
                reasons.append(stripped[:200])
        return {"operation": operation, "result": result, "reasons": list(dict.fromkeys(reasons))[-5:]}

    def upgrade_boot_vars_show_command(self) -> str:
        return "show boot"

    def parse_boot_vars(self, output: str) -> dict:
        # Representative output, modular chassis (9400/9600, and the
        # 9500 high-performance models); the standby's lines repeat with
        # a ``Standby`` prefix when a second supervisor is up:
        #
        #   BOOT variable = bootflash:packages.conf;
        #   Configuration Register is 0x102 (will be 0x2102 at next reload)
        #   MANUAL_BOOT variable = no
        #   BAUD variable = 9600
        #   Standby BOOT variable = bootflash:packages.conf;
        #   Standby Configuration Register is 0x2102
        #   Standby MANUAL_BOOT variable = no
        #
        # Stackable (9200/9300), one block per member:
        #
        #   ---------------------------
        #   Switch 1
        #   ---------------------------
        #   Current Boot Variables:
        #   BOOT variable = flash:packages.conf;
        #
        #   Boot Variables on next reload:
        #   BOOT variable = flash:packages.conf;
        #   Manual Boot = no
        #   Enable Break = no
        #
        # The next-reload value is the one the reload uses, so it wins
        # over the current one.  ``BOOT variable does not exist`` reads as
        # an empty BOOT variable.
        entries: dict[str, dict] = {}
        member: str | None = None
        section: str | None = None

        def _entry(scope: str) -> dict:
            if scope not in entries:
                entries[scope] = {"current": None, "next": None, "manual_boot": None, "config_register": None}
            return entries[scope]

        for raw in (output or "").splitlines():
            line = raw.strip()
            m = re.match(r"^Switch\s+(\d+)$", line)
            if m:
                member, section = f"switch {m.group(1)}", None
                continue
            if re.match(r"^Current Boot Variables\s*:", line, re.IGNORECASE):
                section = "current"
                continue
            if re.match(r"^Boot Variables on next reload\s*:", line, re.IGNORECASE):
                section = "next"
                continue
            standby = line.startswith("Standby ")
            body = line[len("Standby ") :] if standby else line
            scope = "standby" if standby else (member or "active")
            m = re.match(r"^BOOT variable\s*(?:=\s*(.*)|does not exist)", body)
            if m:
                value = (m.group(1) or "").strip()
                first = value.split(";")[0].strip()
                # Older releases append ``,<n>`` (boot attempts) to an entry.
                first = re.sub(r",\d+$", "", first)
                _entry(scope)["next" if section == "next" else "current"] = first
                continue
            m = re.match(
                r"^Configuration Register is\s+(0x[0-9a-fA-F]+)(?:\s*\(will be\s+(0x[0-9a-fA-F]+)\s+at next reload\))?",
                body,
            )
            if m:
                _entry(scope)["config_register"] = (m.group(2) or m.group(1)).lower()
                continue
            m = re.match(r"^(?:MANUAL_BOOT variable|Manual Boot)\s*=\s*(\w+)", body, re.IGNORECASE)
            if m:
                _entry(scope)["manual_boot"] = m.group(1).lower() in ("yes", "1", "true")
        if not entries:
            return {}
        result = []
        for scope, e in entries.items():
            boot = e["next"] if e["next"] is not None else e["current"]
            result.append(
                {
                    "scope": scope,
                    "boot": boot if boot is not None else "",
                    "manual_boot": e["manual_boot"],
                    "config_register": e["config_register"],
                }
            )
        return {"entries": result}

    def upgrade_module_show_command(self) -> str:
        return "show module"

    def parse_module_state(self, output: str) -> dict:
        # Representative output, modular chassis (Cisco's Catalyst 9400
        # dual supervisor upgrade note; columns abbreviated):
        #
        #   Chassis Type: C9407R
        #
        #   Mod Ports Card Type                              Model          Serial No.
        #   ---+-----+--------------------------------------+--------------+--------------
        #   1   48   48-Port 10/100/1000 (RJ-45)             C9400-LC-48T   JAE00000001
        #   3   10   Supervisor 1 Module                     C9400-SUP-1    JAE00000003
        #   4   10   Supervisor 1 Module                     C9400-SUP-1    JAE00000004
        #
        #   Mod MAC addresses                    Hw   Fw           Sw                 Status
        #   ---+--------------------------------+----+------------+------------------+--------
        #   1   0000.5e00.5301 to 0000.5e00.532f 1.0  17.15.1r     17.15.05           ok
        #   3   0000.5e00.5330 to 0000.5e00.5339 1.0  17.15.1r     17.15.05           ok
        #   4   0000.5e00.533a to 0000.5e00.5343 1.0  17.15.1r     17.15.05           ok
        #
        #   Mod Redundancy Role     Operating Redundancy Mode Configured Redundancy Mode
        #   ---+-------------------+-------------------------+---------------------------
        #   3   Active              sso                       sso
        #   4   Standby             sso                       sso
        #
        # A StackWise Virtual pair repeats the three tables under
        # ``Switch Number 1`` / ``Switch Number 2``; a quad-supervisor
        # pair shows the in-chassis standby with ``--`` columns, status
        # ``Provisioned`` and role ``InChassis-Standby``.  Status values
        # include ``ok``, ``booting``, ``out of service``, ``offline``,
        # ``faulty`` and ``disabled``.
        #
        # Stackable (9200/9300), one row per member and no status column:
        #
        #   Switch  Ports    Model                Serial No.   MAC address     Hw Ver.       Sw Ver.
        #   ------  -----   ---------             -----------  --------------  -------       --------
        #    1       41     C9300-48P             FOC0000X001  0000.5e00.5344  V02           17.15.05
        #    2       41     C9300-48P             FOC0000X002  0000.5e00.5345  V02           17.15.05
        text = output or ""
        modules: dict[tuple[int | None, int], dict] = {}
        chassis: int | None = None
        table: str | None = None
        chassis_type: str | None = None
        modular = False

        def _module(slot: int) -> dict:
            key = (chassis, slot)
            if key not in modules:
                modules[key] = {
                    "chassis": chassis,
                    "slot": slot,
                    "model": None,
                    "card_type": None,
                    "sw": None,
                    "status": None,
                    "supervisor": False,
                    "role": None,
                }
            return modules[key]

        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^Chassis Type\s*:\s*(\S+)", line)
            if m:
                chassis_type, modular = m.group(1), True
                continue
            m = re.match(r"^Switch Number\s+(\d+)", line)
            if m:
                chassis, table = int(m.group(1)), None
                continue
            if re.match(r"^Mod\s+Ports\s+Card Type", line):
                table, modular = "cards", True
                continue
            if re.match(r"^Mod\s+MAC addresses", line):
                table, modular = "status", True
                continue
            if re.match(r"^Mod\s+Redundancy Role", line):
                table = "redundancy"
                continue
            if re.match(r"^Switch\s+Ports\s+Model", line):
                table = "stack"
                continue
            tokens = line.split()
            if not tokens[0].isdigit() or table is None:
                continue
            slot = int(tokens[0])
            if table == "cards" and len(tokens) >= 4:
                mod = _module(slot)
                mod["model"], mod["card_type"] = tokens[-2], " ".join(tokens[2:-2]) or None
            elif table == "status":
                rest = tokens[4:] if len(tokens) > 3 and tokens[2] == "to" else tokens[2:]
                if len(rest) >= 4:
                    mod = _module(slot)
                    sw = rest[2]
                    mod["sw"] = None if sw in ("--", "N/A") else sw
                    mod["status"] = " ".join(rest[3:])
            elif table == "redundancy" and len(tokens) >= 2:
                _module(slot)["role"] = tokens[1].lower()
            elif table == "stack" and len(tokens) >= 7:
                mod = _module(slot)
                mod["model"], mod["sw"] = tokens[2], tokens[-1]
        if not modules:
            return {}
        for mod in modules.values():
            card = (mod["card_type"] or "").lower()
            mod["supervisor"] = "supervisor" in card or "-SUP" in (mod["model"] or "").upper()
        return {"modular": modular, "chassis_type": chassis_type, "modules": list(modules.values())}

    def upgrade_environment_show_commands(self) -> list[str]:
        # A modular chassis lists power supplies and fan trays in ``show
        # environment status``; a stackable reports both in ``show
        # environment all``.  Each platform rejects the other's command,
        # and a rejected command simply yields no readings.
        return ["show environment status", "show environment all"]

    def parse_environment_state(self, outputs: dict[str, str]) -> dict:
        # Representative output, modular chassis (``show environment status``):
        #
        #   Power                                                       Fan States
        #   Supply  Model No              Type  Capacity  Status        0     1
        #   ------  --------------------  ----  --------  ------------  -----------
        #   PS1     C9400-PWR-3200AC      ac    3200 W    active        good  good
        #   PS2     C9400-PWR-3200AC      ac    3200 W    faulty        bad   good
        #   PS3     n.a.                  n.a.  n.a.      n.a.          n.a.  n.a.
        #
        #   Fan Tray Status
        #   ---------------
        #   Slot  Fan Status
        #   FM1   ok
        #
        # Stackable (``show environment all``):
        #
        #   Switch 1 FAN 1 is OK
        #   FAN PS-1 is OK
        #   FAN PS-2 is NOT PRESENT
        #   SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
        #   --  ------------------  ----------  ---------------  -------  -------  -----
        #   1A  PWR-C1-715WAC       DCB0000X01  OK               Good     Good     715
        #   1B  PWR-C1-715WAC       DCB0000X02  No Input Power   Bad      Bad      715
        #
        # Only power supply and fan lines are read, and only a positively
        # bad word flags one: ``Not Present``, ``standby`` and unknown text
        # are not problems.
        problems: list[str] = []
        for output in outputs.values():
            for raw in (output or "").splitlines():
                line = " ".join(raw.split())
                if not line or not _ENV_SUBJECT.search(line):
                    continue
                if _ENV_BAD.search(line):
                    problems.append(line[:160])
        return {"problems": list(dict.fromkeys(problems))}

    def upgrade_standby_flash_filesystems(self) -> list[str]:
        # 9400/9600 name the standby's flash ``stby-bootflash:``; some
        # StackWise Virtual pairs use ``stby-flash:``.
        return ["stby-bootflash:", "stby-flash:"]


# A power supply or fan reading: ``PS1``, ``FAN PS-1``, ``Switch 1 FAN 1``,
# a fan tray (``FM1``), or a stackable supply row (``1A  PWR-C1-...``).
_ENV_SUBJECT = re.compile(r"\bPS-?\d|\bFAN\b|\bFM\d|\bPWR-|^\d+[A-Z]\s", re.IGNORECASE)
_ENV_BAD = re.compile(
    r"\b(?:bad|fail|failed|failure|faulty|fault|no input power|critical|shutdown|not functioning)\b", re.IGNORECASE
)


# ``IMG   C    17.09.04a.0.6`` - package type, one-letter state, version
# or package file name.  The legend and header rows never match: their
# second column is not a single state letter.
_INSTALL_PACKAGE_LINE = re.compile(r"^\s*([A-Z]{2,8})\s+([IUCD])\s+(\S+)")
_INSTALL_LOG_START = re.compile(r"\b(install_\w+)(?:\([^)]*\))?\]?\s*:\s*START\b")
_INSTALL_LOG_RESULT = re.compile(r"\bEND\s+(SUCCESS|FAILED)\b|^(SUCCESS|FAILED)\s*:", re.IGNORECASE)
_INSTALL_LOG_REASON = re.compile(r"\bFAILED\b|\bERROR\b|^%\s|not allowed", re.IGNORECASE)
