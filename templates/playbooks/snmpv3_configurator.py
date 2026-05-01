"""
SNMPv3 Configurator — Playbook

Pushes SNMPv3 configuration onto Cisco IOS switches using a
user-selected template (groups, users, views, ACLs, etc.).

Special care is taken to pin the SNMP engine ID *before* the push.
Cisco IOS regenerates the engine ID when certain ``snmp-server``
lines are added, and because SNMPv3 user keys are localized to that
engine ID, regeneration silently invalidates every existing user.
The pin step keeps monitoring working across the change.

Streams progress as ``LogEvent`` yields so the UI can render it live,
and falls back to simulation mode when Netmiko isn't installed.
"""

import asyncio
from collections.abc import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook

# Shared helpers — see _common.py for design notes.
from templates.playbooks._common import (
    NETMIKO_AVAILABLE,
    connect_device,
    pin_snmp_engine_id,
    simulate_connect,
)


@register_playbook
class Snmpv3Configurator(BasePlaybook):
    # Metadata read by the UI.  ``requires_template`` forces the user
    # to choose an SNMPv3 command template before the run can start.
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
        # No template means nothing to push — fail fast with a clear error.
        if not template_commands:
            yield self.log_error(
                "No template selected; this playbook requires SNMPv3 commands."
            )
            return

        yield self.log_info(f"SNMPv3 Configurator — targeting {len(hosts)} device(s)")
        yield self.log_info(f"Template commands ({len(template_commands)}):")
        for cmd in template_commands:
            yield self.log_info(f"  {cmd}")

        # Loud banner so dry-run vs live can't be confused at a glance.
        if dry_run:
            yield self.log_warn("*** DRY-RUN MODE — commands will not be written ***")
        else:
            yield self.log_warn("*** LIVE MODE — commands WILL be written ***")

        for host in hosts:
            # Accept either inventory shape (``ip_address`` or ``host``).
            ip = host.get("ip_address") or host.get("host")
            hostname = host.get("hostname", ip or "unknown")
            device_type = host.get("device_type", "cisco_ios")

            yield self.log_sep()
            yield self.log_info(f"Connecting to {hostname} ({ip}) ...", host=hostname)

            # Real or simulated execution path; identical event shape either way.
            if NETMIKO_AVAILABLE:
                async for event in self._process_real_device(
                    ip, hostname, device_type, credentials,
                    template_commands, dry_run,
                ):
                    yield event
            else:
                async for event in self._process_simulated_device(
                    ip, hostname, template_commands, dry_run,
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
        # connect_device builds the device dict, opens the SSH session,
        # promotes to enable mode, and disconnects on exit.
        async with connect_device(
            self, ip, hostname, device_type, credentials
        ) as (conn, events):
            for ev in events:
                yield ev
            if conn is None:
                return

            # Step 1 — show the operator what's already there.  Useful
            # context when troubleshooting after the run.
            yield self.log_info("Checking existing SNMP configuration ...", host=hostname)
            existing = await asyncio.to_thread(
                conn.send_command, "show running-config | include snmp-server"
            )
            if existing.strip():
                yield self.log_info(f"Current SNMP config:\n{existing}", host=hostname)
            else:
                yield self.log_info("No existing SNMP configuration found.", host=hostname)

            # Step 2 — pin the SNMP engine ID before any changes.  Skip
            # for dry-runs since pinning is itself a config write.
            if not dry_run:
                async for ev in pin_snmp_engine_id(self, conn, hostname):
                    yield ev

            # Step 3 — push the template (or just preview it).
            if dry_run:
                yield self.log_info("[DRY-RUN] Would apply:", host=hostname)
                for cmd in template_commands:
                    yield self.log_info(f"  {cmd}", host=hostname)
            else:
                yield self.log_info("Applying SNMPv3 configuration ...", host=hostname)
                output = await asyncio.to_thread(conn.send_config_set, template_commands)
                yield self.log_info(output or "(no output)", host=hostname)

                # Step 4 — verify users were actually created.
                verify = await asyncio.to_thread(conn.send_command, "show snmp user")
                yield self.log_info(f"SNMPv3 user verification:\n{verify}", host=hostname)

                # Step 5 — persist running-config so it survives a reload.
                yield self.log_info("Saving running config to startup ...", host=hostname)
                await asyncio.to_thread(conn.save_config)
                yield self.log_success("Config saved.", host=hostname)

            yield self.log_success(
                f"Finished processing {hostname} ({ip}).", host=hostname
            )

    async def _process_simulated_device(
        self,
        ip: str,
        hostname: str,
        template_commands: list[str],
        dry_run: bool,
    ) -> AsyncGenerator[LogEvent, None]:
        # Fake connect — random delay + 8% chance of "timeout".
        async for ev in simulate_connect(self, ip, hostname):
            yield ev
            if ev.level == "error":
                return

        # Pretend there's already an SNMP config so the verify-style
        # output renders something realistic in the UI.
        fake_existing = (
            "snmp-server group SECURE v3 priv\n"
            "snmp-server user netops SECURE v3 auth sha *** priv aes 256 ***"
        )
        yield self.log_info(f"Current SNMP config:\n{fake_existing}", host=hostname)

        if dry_run:
            yield self.log_info("[DRY-RUN] Would apply:", host=hostname)
            for cmd in template_commands:
                yield self.log_info(f"  {cmd}", host=hostname)
        else:
            yield self.log_info("Applying SNMPv3 configuration ...", host=hostname)
            yield self.log_success("Template applied.", host=hostname)
            yield self.log_info(
                "SNMPv3 user verification:\nuser netops\n  auth sha ******\n  priv aes-256 ******",
                host=hostname,
            )
            yield self.log_success("Config saved.", host=hostname)

        yield self.log_success(
            f"Finished processing {hostname} ({ip}).", host=hostname
        )
