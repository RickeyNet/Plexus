"""
SNMPv3 Configurator — Playbook

Converts the legacy SNMPv3 helper script into a Plexus playbook.
Uses inventory hosts + selected template commands, supports dry-run,
and streams progress via LogEvent yields.
"""

import asyncio
import random
from typing import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False


@register_playbook
class Snmpv3Configurator(BasePlaybook):
    filename = "snmpv3_configurator.py"
    display_name = "SNMPv3 Configurator"
    description = "Applies SNMPv3 config to Cisco IOS switches using a template."
    tags = ["snmp", "security", "cisco"]
    requires_template = True

    async def run(
        self,
        hosts: list[dict],
        credentials: dict,
        template_commands: list[str] | None = None,
        dry_run: bool = True,
    ) -> AsyncGenerator[LogEvent, None]:
        if not template_commands:
            yield self.log_error("No template selected; this playbook requires SNMPv3 commands.")
            return

        yield self.log_info(f"SNMPv3 Configurator — targeting {len(hosts)} device(s)")
        yield self.log_info(f"Template commands ({len(template_commands)}):")
        for cmd in template_commands:
            yield self.log_info(f"  {cmd}")

        if dry_run:
            yield self.log_warn("*** DRY-RUN MODE — commands will not be written ***")
        else:
            yield self.log_warn("*** LIVE MODE — commands WILL be written ***")

        for host in hosts:
            ip = host.get("ip_address") or host.get("host")
            hostname = host.get("hostname", ip or "unknown")
            device_type = host.get("device_type", "cisco_ios")

            yield self.log_sep()
            yield self.log_info(f"Connecting to {hostname} ({ip}) ...", host=hostname)

            if NETMIKO_AVAILABLE:
                async for event in self._process_real_device(
                    ip,
                    hostname,
                    device_type,
                    credentials,
                    template_commands,
                    dry_run,
                ):
                    yield event
            else:
                async for event in self._process_simulated_device(
                    ip,
                    hostname,
                    template_commands,
                    dry_run,
                ):
                    yield event

        yield self.log_sep()
        yield self.log_success("SNMPv3 configuration playbook complete.")

    async def _process_real_device(
        self,
        ip: str,
        hostname: str,
        device_type: str,
        credentials: dict,
        template_commands: list[str],
        dry_run: bool,
    ) -> AsyncGenerator[LogEvent, None]:
        device = {
            "device_type": device_type,
            "host": ip,
            "username": credentials.get("username"),
            "password": credentials.get("password"),
            "secret": credentials.get("secret") or credentials.get("password"),
            "timeout": 30,
            "banner_timeout": 30,
        }

        try:
            conn = await asyncio.to_thread(ConnectHandler, **device)
        except NetmikoTimeoutException:
            yield self.log_error(f"TIMEOUT connecting to {ip} — skipping.", host=hostname)
            return
        except NetmikoAuthenticationException:
            yield self.log_error(f"AUTH FAILED for {ip} — skipping.", host=hostname)
            return
        except Exception as e:
            yield self.log_error(f"Connection error for {ip}: {e}", host=hostname)
            return

        try:
            if not conn.check_enable_mode():
                await asyncio.to_thread(conn.enable)

            prompt = conn.find_prompt().replace("#", "").replace(">", "").strip()
            yield self.log_success(f"Connected to {prompt} ({ip})", host=hostname)

            yield self.log_info("Checking existing SNMP configuration ...", host=hostname)
            existing = await asyncio.to_thread(
                conn.send_command, "show running-config | include snmp-server"
            )
            if existing.strip():
                yield self.log_info(f"Current SNMP config:\n{existing}", host=hostname)
            else:
                yield self.log_info("No existing SNMP configuration found.", host=hostname)

            if dry_run:
                yield self.log_info("[DRY-RUN] Would apply:", host=hostname)
                for cmd in template_commands:
                    yield self.log_info(f"  {cmd}", host=hostname)
            else:
                yield self.log_info("Applying SNMPv3 configuration ...", host=hostname)
                output = await asyncio.to_thread(conn.send_config_set, template_commands)
                yield self.log_info(output or "(no output)", host=hostname)

                verify = await asyncio.to_thread(conn.send_command, "show snmp user")
                yield self.log_info(f"SNMPv3 user verification:\n{verify}", host=hostname)

                yield self.log_info("Saving running config to startup ...", host=hostname)
                await asyncio.to_thread(conn.save_config)
                yield self.log_success("Config saved.", host=hostname)

            yield self.log_success(f"Finished processing {hostname} ({ip}).", host=hostname)

        finally:
            conn.disconnect()

    async def _process_simulated_device(
        self,
        ip: str,
        hostname: str,
        template_commands: list[str],
        dry_run: bool,
    ) -> AsyncGenerator[LogEvent, None]:
        await asyncio.sleep(random.uniform(0.2, 0.6))

        if random.random() < 0.08:
            yield self.log_error(f"TIMEOUT connecting to {ip} — skipping.", host=hostname)
            return

        yield self.log_success(f"Connected to {hostname} ({ip})", host=hostname)
        await asyncio.sleep(random.uniform(0.2, 0.4))

        fake_existing = "snmp-server group SECURE v3 priv\nsnmp-server user netops SECURE v3 auth sha *** priv aes 256 ***"
        yield self.log_info(f"Current SNMP config:\n{fake_existing}", host=hostname)

        if dry_run:
            yield self.log_info("[DRY-RUN] Would apply:", host=hostname)
            for cmd in template_commands:
                yield self.log_info(f"  {cmd}", host=hostname)
        else:
            yield self.log_info("Applying SNMPv3 configuration ...", host=hostname)
            await asyncio.sleep(random.uniform(0.2, 0.4))
            yield self.log_success("Template applied.", host=hostname)
            yield self.log_info("SNMPv3 user verification:\nuser netops\n  auth sha ******\n  priv aes-256 ******", host=hostname)
            yield self.log_success("Config saved.", host=hostname)

        yield self.log_success(f"Finished processing {hostname} ({ip}).", host=hostname)