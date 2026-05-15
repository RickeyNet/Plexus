"""Cisco IOS driver (classic, pre-Flexible-NetFlow)."""

from __future__ import annotations

from netcontrol.drivers.base import Driver, NetflowConfig, register_driver


@register_driver
class CiscoIOSDriver(Driver):
    device_types = ("cisco_ios",)
    vendor = "cisco"
    display_name = "Cisco IOS"

    def build_netflow_config(self, cfg: NetflowConfig) -> list[str]:
        # Classic IOS NetFlow v9 - global export destination + per-interface
        # ingress/egress.  No Flexible NetFlow, so no record/exporter/monitor
        # constructs and the sampling_rate field is ignored (the platform
        # doesn't expose a sampler under this config style).
        cmds = [
            f"ip flow-export destination {cfg.collector_ip} {cfg.collector_port}",
            "ip flow-export version 9",
            "ip flow-export source Loopback0",
        ]
        for intf in cfg.interfaces:
            cmds += [
                f"interface {intf}",
                "ip flow ingress",
                "ip flow egress",
                "exit",
            ]
        return cmds

    def netflow_verify_command(self) -> str:
        return "show ip flow export"

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
