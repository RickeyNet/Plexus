"""
Template Configurator — Generic Playbook

Connects to Cisco IOS switches and applies the selected configuration
template in config mode.  Works with any template stored in Plexus
(access-port hardening, trunk config, NTP, banners, SNMPv3, etc.).

Supports a dry-run preview and a live mode that automatically saves
the running config when the push succeeds.
"""

import asyncio
import random
from collections.abc import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook

# Shared helpers — see _common.py.  Underscore prefix keeps the module
# out of the playbook auto-loader.
from templates.playbooks._common import (
    NETMIKO_AVAILABLE,
    connect_device,
    pin_snmp_engine_id,
    simulate_connect,
)


@register_playbook
class TemplateConfigurator(BasePlaybook):
    # Metadata read by the UI to render the playbook card.
    filename = "template_configurator.py"
    display_name = "Template Configurator"
    description = (
        "Pushes any selected configuration template into Cisco IOS switches. "
        "Select a template (access port, trunk, NTP, banner, etc.) and this "
        "playbook applies it in config mode, then saves the running config."
    )
    tags = ["template", "config", "cisco", "general"]
    requires_template = True  # No template ⇒ no work; UI gates the run.

    async def run(
        self,
        hosts: list[dict],
        credentials: dict,
        template_commands: list[str] | None = None,
        dry_run: bool = True,
    ) -> AsyncGenerator[LogEvent, None]:
        # Hard fail when no template was selected — there is nothing
        # generic to push without one.
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

        # Per-host success/failure tally for the closing summary line.
        succeeded = 0
        failed = 0

        for host in hosts:
            # Inventory entries can use either ``ip_address`` or ``host``;
            # accept either so this playbook plays nicely with both shapes.
            ip = host.get("ip_address") or host.get("host")
            hostname = host.get("hostname", ip or "unknown")
            device_type = host.get("device_type", "cisco_ios")

            yield self.log_sep()
            yield self.log_info(f"Connecting to {hostname} ({ip}) ...", host=hostname)

            # Choose the real or simulated path.  We watch each event's
            # level: any ``error`` flips this host into the "failed"
            # bucket for the summary.
            ok = True
            if NETMIKO_AVAILABLE:
                async for event in self._process_real_device(
                    ip, hostname, device_type, credentials,
                    template_commands, dry_run,
                ):
                    if event.level == "error":
                        ok = False
                    yield event
            else:
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

        # Final summary — coloured warn if anything failed, success otherwise.
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
        # connect_device manages the device dict, exception handling,
        # enable-mode promotion, and clean disconnect on exit.
        async with connect_device(
            self, ip, hostname, device_type, credentials
        ) as (conn, events):
            for ev in events:
                yield ev
            if conn is None:
                return

            try:
                # If the template touches SNMP, pin the engine ID
                # *before* the push so SNMPv3 user keys keep working
                # afterwards.  See pin_snmp_engine_id docstring for why.
                has_snmp_cmds = any(
                    cmd.strip().lower().startswith("snmp-server")
                    for cmd in template_commands
                )
                if has_snmp_cmds and not dry_run:
                    async for ev in pin_snmp_engine_id(self, conn, hostname):
                        yield ev

                if dry_run:
                    # Preview only — print exactly what would be sent.
                    yield self.log_info(
                        "[DRY-RUN] Would apply the following commands:",
                        host=hostname,
                    )
                    for cmd in template_commands:
                        yield self.log_info(f"  {cmd}", host=hostname)
                else:
                    yield self.log_info("Applying template configuration ...", host=hostname)
                    # send_config_set drops into config mode, runs each line, exits.
                    output = await asyncio.to_thread(
                        conn.send_config_set, template_commands
                    )
                    if output.strip():
                        yield self.log_info(f"Device output:\n{output}", host=hostname)

                    # Persist to startup so changes survive a reload.
                    yield self.log_info("Saving running config to startup ...", host=hostname)
                    await asyncio.to_thread(conn.save_config)
                    yield self.log_success("Config saved.", host=hostname)

                yield self.log_success(
                    f"Finished processing {hostname} ({ip}).", host=hostname
                )

            except Exception as e:
                # Any unexpected failure during the push surfaces here
                # as an ``error`` event, which flips this host's bucket.
                yield self.log_error(
                    f"Error configuring {hostname} ({ip}): {e}", host=hostname
                )

    # ── Simulation mode for dev/testing ───────────────────────────────────

    async def _process_simulated_device(
        self,
        ip: str,
        hostname: str,
        template_commands: list[str],
        dry_run: bool,
    ) -> AsyncGenerator[LogEvent, None]:
        # Fake the connect handshake (random delay + 8% fake timeout).
        async for ev in simulate_connect(self, ip, hostname):
            yield ev
            if ev.level == "error":
                return

        await asyncio.sleep(random.uniform(0.2, 0.4))

        if dry_run:
            yield self.log_info(
                "[DRY-RUN] Would apply the following commands:", host=hostname
            )
            for cmd in template_commands:
                yield self.log_info(f"  {cmd}", host=hostname)
        else:
            yield self.log_info("Applying template configuration ...", host=hostname)
            await asyncio.sleep(random.uniform(0.3, 0.6))
            # Render a believable IOS config-mode echo so the UI looks real.
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
