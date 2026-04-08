"""
Template Configurator — Generic Playbook

Connects to Cisco IOS switches and applies the selected configuration
template in config mode.  Works with any template stored in Plexus
(access-port hardening, trunk config, NTP, banners, etc.).

Supports dry-run preview and live mode with automatic config save.
"""

import asyncio
import random
from collections.abc import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )

    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False


@register_playbook
class TemplateConfigurator(BasePlaybook):
    filename = "template_configurator.py"
    display_name = "Template Configurator"
    description = (
        "Pushes any selected configuration template into Cisco IOS switches. "
        "Select a template (access port, trunk, NTP, banner, etc.) and this "
        "playbook applies it in config mode, then saves the running config."
    )
    tags = ["template", "config", "cisco", "general"]
    requires_template = True

    async def run(
        self,
        hosts: list[dict],
        credentials: dict,
        template_commands: list[str] | None = None,
        dry_run: bool = True,
    ) -> AsyncGenerator[LogEvent, None]:
        if not template_commands:
            yield self.log_error(
                "No template selected — this playbook requires a configuration template."
            )
            return

        yield self.log_info(
            f"Template Configurator — targeting {len(hosts)} device(s)"
        )
        yield self.log_info(f"Template has {len(template_commands)} command(s).")

        if dry_run:
            yield self.log_warn("*** DRY-RUN MODE — commands will NOT be written ***")
        else:
            yield self.log_warn("*** LIVE MODE — commands WILL be written ***")

        succeeded = 0
        failed = 0

        for host in hosts:
            ip = host.get("ip_address") or host.get("host")
            hostname = host.get("hostname", ip or "unknown")
            device_type = host.get("device_type", "cisco_ios")

            yield self.log_sep()
            yield self.log_info(f"Connecting to {hostname} ({ip}) ...", host=hostname)

            if NETMIKO_AVAILABLE:
                ok = True
                async for event in self._process_real_device(
                    ip, hostname, device_type, credentials,
                    template_commands, dry_run,
                ):
                    if event.level == "error":
                        ok = False
                    yield event
            else:
                ok = True
                async for event in self._process_simulated_device(
                    ip, hostname, template_commands, dry_run,
                ):
                    if event.level == "error":
                        ok = False
                    yield event

            if ok:
                succeeded += 1
            else:
                failed += 1

        yield self.log_sep()
        summary = f"Complete: {succeeded} succeeded, {failed} failed out of {len(hosts)} device(s)."
        if failed:
            yield self.log_warn(summary)
        else:
            yield self.log_success(summary)

    # ── Real device via Netmiko ───────────────────────────────────────────

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
            # Enter enable mode if needed
            if not conn.check_enable_mode():
                await asyncio.to_thread(conn.enable)

            prompt = conn.find_prompt().replace("#", "").replace(">", "").strip()
            yield self.log_success(f"Connected to {prompt} ({ip})", host=hostname)

            # If the template contains snmp-server commands, pin the SNMP
            # engine ID first.  Cisco IOS regenerates the engine ID when
            # certain snmp-server lines are added, which invalidates all
            # SNMPv3 localized keys and breaks monitoring.
            has_snmp_cmds = any(
                cmd.strip().lower().startswith("snmp-server")
                for cmd in template_commands
            )
            if has_snmp_cmds and not dry_run:
                async for ev in self._pin_snmp_engine_id(conn, hostname):
                    yield ev

            if dry_run:
                yield self.log_info("[DRY-RUN] Would apply the following commands:", host=hostname)
                for cmd in template_commands:
                    yield self.log_info(f"  {cmd}", host=hostname)
            else:
                yield self.log_info("Applying template configuration ...", host=hostname)
                output = await asyncio.to_thread(
                    conn.send_config_set, template_commands
                )
                if output.strip():
                    yield self.log_info(f"Device output:\n{output}", host=hostname)

                yield self.log_info("Saving running config to startup ...", host=hostname)
                await asyncio.to_thread(conn.save_config)
                yield self.log_success("Config saved.", host=hostname)

            yield self.log_success(
                f"Finished processing {hostname} ({ip}).", host=hostname
            )

        except Exception as e:
            yield self.log_error(
                f"Error configuring {hostname} ({ip}): {e}", host=hostname
            )
        finally:
            conn.disconnect()

    # ── SNMP engine ID preservation ─────────────────────────────────────

    async def _pin_snmp_engine_id(self, conn, hostname: str) -> AsyncGenerator[LogEvent, None]:
        """Read the current SNMP engine ID and pin it with an explicit config.

        Cisco IOS regenerates the engine ID when certain snmp-server
        commands are added/removed.  This invalidates all SNMPv3 user
        keys (they are localized to the engine ID).  By setting
        ``snmp-server engineID local <id>`` before applying SNMP
        changes, the engine ID is pinned and keys remain valid.
        """
        import re

        try:
            output = await asyncio.to_thread(
                conn.send_command, "show snmp engineID"
            )
            # Typical output: "Local SNMP engineID: 80000009030050568D9CDFC0"
            match = re.search(r"[Ll]ocal\s+.*[Ee]ngine\s*ID[:\s]+([0-9A-Fa-f]+)", output)
            if not match:
                yield self.log_info(
                    "Could not detect SNMP engine ID — skipping pin.",
                    host=hostname,
                )
                return
            engine_id = match.group(1).strip()
            yield self.log_info(
                f"Pinning SNMP engine ID ({engine_id}) to prevent SNMPv3 key invalidation.",
                host=hostname,
            )
            await asyncio.to_thread(
                conn.send_config_set,
                [f"snmp-server engineID local {engine_id}"],
            )
        except Exception as exc:
            yield self.log_warn(
                f"Could not pin SNMP engine ID: {exc}",
                host=hostname,
            )

    # ── Simulation mode for dev/testing ───────────────────────────────────

    async def _process_simulated_device(
        self,
        ip: str,
        hostname: str,
        template_commands: list[str],
        dry_run: bool,
    ) -> AsyncGenerator[LogEvent, None]:
        await asyncio.sleep(random.uniform(0.2, 0.6))

        # Simulate occasional connection failures
        if random.random() < 0.08:
            yield self.log_error(f"TIMEOUT connecting to {ip} — skipping.", host=hostname)
            return

        yield self.log_success(f"Connected to {hostname} ({ip})", host=hostname)
        await asyncio.sleep(random.uniform(0.2, 0.4))

        if dry_run:
            yield self.log_info("[DRY-RUN] Would apply the following commands:", host=hostname)
            for cmd in template_commands:
                yield self.log_info(f"  {cmd}", host=hostname)
        else:
            yield self.log_info("Applying template configuration ...", host=hostname)
            await asyncio.sleep(random.uniform(0.3, 0.6))
            yield self.log_info(
                "Device output:\n"
                + "\n".join(f"{hostname}(config)#{cmd}" for cmd in template_commands),
                host=hostname,
            )
            yield self.log_info("Saving running config to startup ...", host=hostname)
            await asyncio.sleep(random.uniform(0.1, 0.3))
            yield self.log_success("Config saved.", host=hostname)

        yield self.log_success(
            f"Finished processing {hostname} ({ip}).", host=hostname
        )
