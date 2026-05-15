"""Cisco NX-OS driver (Flexible NetFlow, requires ``feature netflow``)."""

from __future__ import annotations

from netcontrol.drivers.base import Driver, NetflowConfig, register_driver


@register_driver
class CiscoNXOSDriver(Driver):
    # Netmiko exposes both ssh and non-ssh transports under separate
    # device_type strings; both map to the same NX-OS syntax here.
    device_types = ("cisco_nxos", "cisco_nxos_ssh")
    vendor = "cisco"
    display_name = "Cisco NX-OS"

    def build_netflow_config(self, cfg: NetflowConfig) -> list[str]:
        cmds = [
            "feature netflow",
            f"flow record {cfg.record_name}",
            " match ipv4 source address",
            " match ipv4 destination address",
            " match transport source-port",
            " match transport destination-port",
            " match ip protocol",
            " collect counter bytes",
            " collect counter packets",
            " collect timestamp sys-uptime first",
            " collect timestamp sys-uptime last",
            "exit",
            f"flow exporter {cfg.exporter_name}",
            f" destination {cfg.collector_ip}",
            f" transport udp {cfg.collector_port}",
            " version 9",
            " source loopback0",
            "exit",
            f"flow monitor {cfg.monitor_name}",
            f" record {cfg.record_name}",
            f" exporter {cfg.exporter_name}",
            "exit",
        ]
        if cfg.sampling_rate > 1:
            cmds += [
                f"sampler {cfg.sampler_name}",
                f" mode 1 out-of {cfg.sampling_rate}",
                "exit",
            ]
        for intf in cfg.interfaces:
            cmds.append(f"interface {intf}")
            cmds.append(f" ip flow monitor {cfg.monitor_name} input")
            if cfg.sampling_rate > 1:
                cmds.append(
                    f" ip flow monitor {cfg.monitor_name} sampler {cfg.sampler_name}"
                )
            cmds.append("exit")
        return cmds

    def netflow_verify_command(self) -> str:
        return "show flow exporter PLEXUS-EXPORT"
