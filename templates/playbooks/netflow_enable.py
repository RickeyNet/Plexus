"""
netflow_enable.py - NetFlow Exporter Configuration Playbook

Pushes the right ``flow exporter`` / ``flow monitor`` / interface-binding
config onto a device so it starts exporting NetFlow records to the
Plexus collector.  Vendor-specific syntax lives in the
``netcontrol.drivers`` package - this playbook only orchestrates the
job (resolve collector, pick a driver per host, dry-run vs live).

The collector IP and port come from (in priority order):
  1. The job's ``parameters`` dict (``collector_ip`` / ``collector_port``)
     if the UI ever passes structured params for this playbook.
  2. The ``PLEXUS_COLLECTOR_IP`` env var + ``APP_NETFLOW_PORT`` env var.
  3. Hard fail - without a collector IP the device has nowhere to send.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator

from netcontrol.drivers import (
    DriverCapabilityError,
    NetflowConfig,
    get_driver,
)
from routes.runner import BasePlaybook, LogEvent, register_playbook

from templates.playbooks._common import (
    NETMIKO_AVAILABLE,
    connect_device,
    simulate_connect,
)


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
    ) -> AsyncGenerator[LogEvent]:
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

            driver = get_driver(device_type)
            try:
                commands = driver.build_netflow_config(
                    NetflowConfig(
                        collector_ip=collector_ip,
                        collector_port=collector_port,
                        interfaces=list(interfaces),
                        sampling_rate=sampling_rate,
                    )
                )
            except DriverCapabilityError as exc:
                # No driver for this device_type, or the driver doesn't
                # support NetFlow.  Skip this host with a clear message
                # rather than guessing at Cisco syntax.
                yield self.log_error(
                    f"Skipping {hostname}: {exc}",
                    host=hostname,
                )
                continue
            verify_cmd = driver.netflow_verify_command()

            if NETMIKO_AVAILABLE:
                async for event in self._process_real_device(
                    ip, hostname, device_type, credentials, commands, verify_cmd, dry_run,
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
        verify_cmd: str,
        dry_run: bool,
    ) -> AsyncGenerator[LogEvent]:
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

            # Verify the exporter actually came up.  The driver tells us
            # which show command to use, so the playbook stays vendor-neutral.
            try:
                verify = await asyncio.to_thread(conn.send_command, verify_cmd)
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
    ) -> AsyncGenerator[LogEvent]:
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
                "Exporter verification:\n  PLEXUS-EXPORT active, "
                "packets sent: 0 (just configured)",
                host=hostname,
            )
            yield self.log_success("Config saved.", host=hostname)

        yield self.log_success(
            f"Finished processing {hostname} ({ip}).",
            host=hostname,
        )
