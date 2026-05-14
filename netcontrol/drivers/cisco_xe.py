"""Cisco IOS-XE driver (Flexible NetFlow)."""

from __future__ import annotations

from netcontrol.drivers.base import Driver, NetflowConfig, register_driver


@register_driver
class CiscoXEDriver(Driver):
    device_types = ("cisco_xe",)
    vendor = "cisco"
    display_name = "Cisco IOS-XE"

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
                cmds.append(
                    f" ip flow monitor {cfg.monitor_name} sampler "
                    f"{cfg.sampler_name} input"
                )
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

    def save_config_commands(self) -> list[str]:
        return ["write memory"]

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

    def upgrade_activate_commands(self, image_path: str) -> list[str]:
        # ``prompt-level none`` suppresses the interactive y/n prompt so
        # the command can be sent non-interactively before the reload
        # drops the SSH session.  ``image_path`` isn't interpolated
        # because in install mode the activate operates on whatever
        # was just added, not a path argument.
        return ["install activate prompt-level none"]

    def upgrade_commit_command(self) -> str:
        # Without ``install commit`` an IOS-XE box auto-rolls-back to
        # the prior image on the *next* reload.  This finalizes it.
        return "install commit"
