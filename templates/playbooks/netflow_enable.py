"""
netflow_enable.py - NetFlow Exporter Configuration Playbook

Pushes the right ``flow exporter`` / ``flow monitor`` / interface-binding
config onto Cisco devices so they start exporting NetFlow records to the
Plexus collector.  Three platforms are supported, each with its own
syntax:

* ``cisco_ios``  - classic NetFlow v9 via ``ip flow-export destination``
  on each monitored interface (no Flexible NetFlow).
* ``cisco_xe``   - Flexible NetFlow: ``flow record`` + ``flow exporter``
  + ``flow monitor`` + ``ip flow monitor PLEXUS-MON input`` per interface.
* ``cisco_nxos`` - NX-OS Flexible NetFlow with the same shape as IOS-XE
  but slightly different syntax (``ip flow monitor PLEXUS-MON input``
  becomes ``ip flow monitor PLEXUS-MON input`` under each L3 interface;
  v9 is the default).

The collector IP and port come from (in priority order):
  1. The job's ``parameters`` dict (``collector_ip`` / ``collector_port``)
     if the UI ever passes structured params for this playbook.
  2. The ``PLEXUS_COLLECTOR_IP`` env var + ``APP_NETFLOW_PORT`` env var.
  3. Hard fail - without a collector IP the device has nowhere to send.

Sampling rate is optional; on IOS-XE / NX-OS we wire it via a ``sampler``
construct.  Defaults to 1:1 (no sampling) since the collector handles
de-sampling automatically when ``sampling_rate`` is reported.

Dry-run prints the exact lines that *would* be applied, grouped per
device, so an operator can paste them into change control before going
live.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook

from templates.playbooks._common import (
    NETMIKO_AVAILABLE,
    connect_device,
    simulate_connect,
)


DEFAULT_EXPORTER_NAME = "PLEXUS-EXPORT"
DEFAULT_MONITOR_NAME = "PLEXUS-MON"
DEFAULT_RECORD_NAME = "PLEXUS-RECORD"
DEFAULT_SAMPLER_NAME = "PLEXUS-SAMPLER"


def _resolve_collector(parameters: dict | None) -> tuple[str | None, int]:
    """Pick the collector IP + port from job params or env, in that order."""
    params = parameters or {}
    ip = (
        params.get("collector_ip")
        or os.getenv("PLEXUS_COLLECTOR_IP", "").strip()
        or None
    )
    port_raw = (
        params.get("collector_port")
        or os.getenv("APP_NETFLOW_PORT", "").strip()
        or "2055"
    )
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        port = 2055
    return ip, port


def _build_ios_commands(
    collector_ip: str,
    collector_port: int,
    interfaces: list[str],
) -> list[str]:
    """Classic IOS NetFlow v9 - global destination + per-interface ingress/egress."""
    cmds = [
        f"ip flow-export destination {collector_ip} {collector_port}",
        "ip flow-export version 9",
        "ip flow-export source Loopback0",
    ]
    for intf in interfaces:
        cmds += [
            f"interface {intf}",
            "ip flow ingress",
            "ip flow egress",
            "exit",
        ]
    return cmds


def _build_xe_commands(
    collector_ip: str,
    collector_port: int,
    interfaces: list[str],
    sampling_rate: int,
) -> list[str]:
    """IOS-XE Flexible NetFlow - record, exporter, monitor, optional sampler."""
    cmds = [
        f"flow record {DEFAULT_RECORD_NAME}",
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
        f"flow exporter {DEFAULT_EXPORTER_NAME}",
        f" destination {collector_ip}",
        f" transport udp {collector_port}",
        " export-protocol netflow-v9",
        " source Loopback0",
        "exit",
        f"flow monitor {DEFAULT_MONITOR_NAME}",
        f" record {DEFAULT_RECORD_NAME}",
        f" exporter {DEFAULT_EXPORTER_NAME}",
        " cache timeout active 60",
        "exit",
    ]
    if sampling_rate > 1:
        cmds += [
            f"sampler {DEFAULT_SAMPLER_NAME}",
            f" mode random 1 out-of {sampling_rate}",
            "exit",
        ]
    for intf in interfaces:
        cmds.append(f"interface {intf}")
        cmds.append(f" ip flow monitor {DEFAULT_MONITOR_NAME} input")
        if sampling_rate > 1:
            cmds.append(f" ip flow monitor {DEFAULT_MONITOR_NAME} sampler {DEFAULT_SAMPLER_NAME} input")
        cmds.append("exit")
    return cmds


def _build_nxos_commands(
    collector_ip: str,
    collector_port: int,
    interfaces: list[str],
    sampling_rate: int,
) -> list[str]:
    """NX-OS Flexible NetFlow.  Note: NX-OS requires ``feature netflow`` first."""
    cmds = [
        "feature netflow",
        f"flow record {DEFAULT_RECORD_NAME}",
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
        f"flow exporter {DEFAULT_EXPORTER_NAME}",
        f" destination {collector_ip}",
        f" transport udp {collector_port}",
        " version 9",
        " source loopback0",
        "exit",
        f"flow monitor {DEFAULT_MONITOR_NAME}",
        f" record {DEFAULT_RECORD_NAME}",
        f" exporter {DEFAULT_EXPORTER_NAME}",
        "exit",
    ]
    if sampling_rate > 1:
        cmds += [
            f"sampler {DEFAULT_SAMPLER_NAME}",
            f" mode 1 out-of {sampling_rate}",
            "exit",
        ]
    for intf in interfaces:
        cmds.append(f"interface {intf}")
        cmds.append(f" ip flow monitor {DEFAULT_MONITOR_NAME} input")
        if sampling_rate > 1:
            cmds.append(f" ip flow monitor {DEFAULT_MONITOR_NAME} sampler {DEFAULT_SAMPLER_NAME}")
        cmds.append("exit")
    return cmds


def _platform_builder(device_type: str):
    """Map a Plexus device_type string to its platform-specific builder."""
    if device_type == "cisco_xe":
        return _build_xe_commands
    if device_type in ("cisco_nxos", "cisco_nxos_ssh"):
        return _build_nxos_commands
    # cisco_ios and any unknown variants fall back to classic IOS syntax.
    return _build_ios_commands


@register_playbook
class NetflowEnabler(BasePlaybook):
    filename = "netflow_enable.py"
    display_name = "Enable NetFlow Export"
    description = (
        "Configures NetFlow v9 export on Cisco IOS / IOS-XE / NX-OS so the "
        "device starts sending flow records to the Plexus collector. Honors "
        "dry-run; collector IP comes from PLEXUS_COLLECTOR_IP env or a "
        "collector_ip job parameter."
    )
    tags = ["netflow", "observability", "cisco"]
    # No template required - the playbook generates platform-specific config
    # itself based on device_type and the collector settings.
    requires_template = False

    parameters_schema = [
        {
            "name": "collector_ip",
            "type": "string",
            "label": "Collector IP",
            "required": True,
            "default": "",
            "help": "Reachable address of the Plexus NetFlow collector. Falls back to $PLEXUS_COLLECTOR_IP.",
        },
        {
            "name": "collector_port",
            "type": "int",
            "label": "Collector Port",
            "required": False,
            "default": 2055,
            "help": "UDP port the collector listens on. Defaults to 2055.",
        },
        {
            "name": "interfaces",
            "type": "list",
            "label": "Interfaces",
            "required": False,
            "default": "GigabitEthernet0/0",
            "help": "Comma-separated list of interfaces to enable flow export on. Per-host override via host_info['netflow_interfaces'] still wins.",
        },
        {
            "name": "sampling_rate",
            "type": "int",
            "label": "Sampling Rate (1:N)",
            "required": False,
            "default": 1,
            "help": "1 = sample every packet. Higher N reduces device CPU at the cost of resolution.",
        },
    ]

    async def run(
        self,
        hosts: list[dict],
        credentials: dict,
        template_commands: list[str] | None = None,
        dry_run: bool = True,
    ) -> AsyncGenerator[LogEvent, None]:
        # Parameters arrive on ``self`` for playbooks that opt into them;
        # fall back to ``None`` so _resolve_collector can default cleanly.
        parameters = getattr(self, "parameters", None)
        collector_ip, collector_port = _resolve_collector(parameters)

        # Without a collector destination the push is meaningless - fail
        # loudly before touching any device.
        if not collector_ip:
            yield self.log_error(
                "No collector IP found. Set PLEXUS_COLLECTOR_IP (the reachable "
                "address of this Plexus instance) or pass collector_ip in the "
                "job parameters."
            )
            return

        # Default interface list - operators can override per-host via
        # ``host_info['netflow_interfaces']`` if the UI surfaces it later.
        default_interfaces = (parameters or {}).get("interfaces") or ["GigabitEthernet0/0"]
        sampling_rate = int((parameters or {}).get("sampling_rate") or 1)

        yield self.log_info(
            f"NetFlow Enabler - targeting {len(hosts)} device(s), "
            f"collector {collector_ip}:{collector_port}, sampling 1:{sampling_rate}"
        )
        if dry_run:
            yield self.log_warn("*** DRY-RUN MODE - commands will not be written ***")
        else:
            yield self.log_warn("*** LIVE MODE - commands WILL be written ***")

        for host in hosts:
            ip = host.get("ip_address") or host.get("host")
            hostname = host.get("hostname", ip or "unknown")
            device_type = host.get("device_type", "cisco_ios")
            # Per-host override beats the global default; useful when only
            # some uplinks should be monitored on a given device.
            interfaces = host.get("netflow_interfaces") or default_interfaces

            yield self.log_sep()
            yield self.log_info(
                f"Connecting to {hostname} ({ip}) [{device_type}] ...",
                host=hostname,
            )

            builder = _platform_builder(device_type)
            if device_type == "cisco_ios":
                commands = builder(collector_ip, collector_port, interfaces)
            else:
                commands = builder(collector_ip, collector_port, interfaces, sampling_rate)

            if NETMIKO_AVAILABLE:
                async for event in self._process_real_device(
                    ip, hostname, device_type, credentials, commands, dry_run,
                ):
                    yield event
            else:
                async for event in self._process_simulated_device(
                    ip, hostname, commands, dry_run,
                ):
                    yield event

        yield self.log_sep()
        yield self.log_success("NetFlow enablement playbook complete.")

    async def _process_real_device(
        self,
        ip: str,
        hostname: str,
        device_type: str,
        credentials: dict,
        commands: list[str],
        dry_run: bool,
    ) -> AsyncGenerator[LogEvent, None]:
        async with connect_device(
            self, ip, hostname, device_type, credentials,
        ) as (conn, events):
            for ev in events:
                yield ev
            if conn is None:
                return

            # Show the operator what's already configured - useful when a
            # device is being re-pointed to a new collector.
            yield self.log_info("Checking existing flow configuration ...", host=hostname)
            try:
                existing = await asyncio.to_thread(
                    conn.send_command,
                    "show running-config | include flow|ip flow-export",
                )
            except Exception as exc:  # noqa: BLE001
                yield self.log_warn(
                    f"Could not read existing flow config: {exc}",
                    host=hostname,
                )
                existing = ""
            if existing.strip():
                yield self.log_info(
                    f"Current flow config:\n{existing}",
                    host=hostname,
                )
            else:
                yield self.log_info("No existing flow config found.", host=hostname)

            if dry_run:
                yield self.log_info(
                    f"[DRY-RUN] Would apply {len(commands)} line(s):",
                    host=hostname,
                )
                for cmd in commands:
                    yield self.log_info(f"  {cmd}", host=hostname)
                yield self.log_success(
                    f"Finished processing {hostname} ({ip}).",
                    host=hostname,
                )
                return

            yield self.log_info(
                f"Applying {len(commands)} line(s) of NetFlow config ...",
                host=hostname,
            )
            output = await asyncio.to_thread(conn.send_config_set, commands)
            yield self.log_info(output or "(no output)", host=hostname)

            # Verify the exporter actually came up - different show commands
            # per platform, so guard each separately.
            try:
                if device_type == "cisco_ios":
                    verify = await asyncio.to_thread(
                        conn.send_command, "show ip flow export"
                    )
                else:
                    verify = await asyncio.to_thread(
                        conn.send_command,
                        f"show flow exporter {DEFAULT_EXPORTER_NAME}",
                    )
                yield self.log_info(
                    f"Exporter verification:\n{verify}",
                    host=hostname,
                )
            except Exception as exc:  # noqa: BLE001
                yield self.log_warn(f"Verify step failed: {exc}", host=hostname)

            yield self.log_info("Saving running config to startup ...", host=hostname)
            await asyncio.to_thread(conn.save_config)
            yield self.log_success("Config saved.", host=hostname)

            yield self.log_success(
                f"Finished processing {hostname} ({ip}).",
                host=hostname,
            )

    async def _process_simulated_device(
        self,
        ip: str,
        hostname: str,
        commands: list[str],
        dry_run: bool,
    ) -> AsyncGenerator[LogEvent, None]:
        async for ev in simulate_connect(self, ip, hostname):
            yield ev
            if ev.level == "error":
                return

        yield self.log_info("Checking existing flow configuration ...", host=hostname)
        yield self.log_info("No existing flow config found.", host=hostname)

        if dry_run:
            yield self.log_info(
                f"[DRY-RUN] Would apply {len(commands)} line(s):",
                host=hostname,
            )
            for cmd in commands:
                yield self.log_info(f"  {cmd}", host=hostname)
        else:
            yield self.log_info(
                f"Applying {len(commands)} line(s) of NetFlow config ...",
                host=hostname,
            )
            yield self.log_success("Flow exporter configured.", host=hostname)
            yield self.log_info(
                f"Exporter verification:\n  {DEFAULT_EXPORTER_NAME} active, "
                f"packets sent: 0 (just configured)",
                host=hostname,
            )
            yield self.log_success("Config saved.", host=hostname)

        yield self.log_success(
            f"Finished processing {hostname} ({ip}).",
            host=hostname,
        )
