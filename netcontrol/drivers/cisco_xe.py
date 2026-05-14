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
