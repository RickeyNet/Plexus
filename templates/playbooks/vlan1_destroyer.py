"""
vlan1_destroyer.py — VLAN 1 Access Port Remediation Playbook

Connects to Cisco Catalyst switches, inventories all interfaces,
finds access ports still parked on VLAN 1 (the default VLAN), and
applies a replacement interface configuration from the selected
template — the standard fix for the "everything on VLAN 1" anti-pattern.

When Netmiko isn't installed (e.g. local dev), the playbook runs in
simulation mode with realistic fake output so the UI flow can still be
exercised end-to-end.
"""

import asyncio
import random

from routes.runner import BasePlaybook, register_playbook

# Shared connection / simulation helpers live in _common.py — see that
# file for the rationale behind each helper.  The leading underscore
# also hides the module from the playbook auto-loader.
from templates.playbooks._common import (
    NETMIKO_AVAILABLE,
    connect_device,
    simulate_connect,
)


def _parse_vlan1_access_ports(output: str) -> list[str]:
    """Parse ``show interfaces switchport`` output for VLAN 1 access ports.

    The command emits a stanza per interface.  We track three pieces of
    state per stanza — the interface name, whether it's in static
    access mode, and its access VLAN — and emit the interface when all
    three conditions match (access + VLAN 1).
    """
    vlan1_ports: list[str] = []
    current_interface: str | None = None
    is_access = False
    access_vlan: str | None = None

    for line in output.splitlines():
        # ``Name:`` marks the start of a new interface stanza.  Before
        # moving on, decide whether the *previous* stanza qualified.
        if line.startswith("Name:"):
            if current_interface and is_access and access_vlan == "1":
                vlan1_ports.append(current_interface)
            current_interface = line.split("Name:")[-1].strip()
            is_access = False
            access_vlan = None
        elif "Administrative Mode:" in line:
            # "static access" is the only mode we treat as a real access port.
            mode = line.split("Administrative Mode:")[-1].strip().lower()
            is_access = mode == "static access"
        elif "Access Mode VLAN:" in line:
            # Field can read e.g. "1 (default)"; we only care about the number.
            vlan_part = line.split("Access Mode VLAN:")[-1].strip()
            access_vlan = vlan_part.split()[0] if vlan_part else None

    # Don't forget the final stanza — it has no following ``Name:`` line.
    if current_interface and is_access and access_vlan == "1":
        vlan1_ports.append(current_interface)

    return vlan1_ports


def _simulate_vlan1_ports() -> list[str]:
    """Generate plausible fake VLAN 1 ports for simulation mode."""
    all_ports = [f"Gi1/0/{i}" for i in range(1, 49)]
    # 0–8 offending ports per device gives a realistic mix of clean and dirty switches.
    vlan1_count = random.randint(0, 8)
    return random.sample(all_ports, vlan1_count)


@register_playbook
class Vlan1Destroyer(BasePlaybook):
    # These class attributes are how the UI discovers and labels the playbook.
    filename = "vlan1_destroyer.py"
    display_name = "VLAN 1 Destroyer"
    description = (
        "Scans Cisco switches for access ports still on VLAN 1 and applies "
        "a hardening template to move them off the default VLAN. "
        "Requires a config template with the replacement port commands."
    )
    tags = ["vlan", "security", "remediation", "cisco"]
    requires_template = True  # The UI will gate the run until a template is picked.

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        # ── Header / banner output ─────────────────────────────────────
        yield self.log_info(f"VLAN 1 Destroyer — targeting {len(hosts)} device(s)")

        # If the user didn't pick a template, fall back to a sane built-in
        # so the playbook still does something useful instead of erroring.
        if not template_commands:
            yield self.log_warn(
                "No template selected. Using default: switchport access vlan 100"
            )
            template_commands = [
                "switchport mode access",
                "switchport access vlan 100",
                "spanning-tree portfast",
                "spanning-tree bpduguard enable",
            ]

        yield self.log_info(f"Template commands ({len(template_commands)}):")
        for cmd in template_commands:
            yield self.log_info(f"  {cmd}")

        # Make the run mode unmistakable — dry-run is preview-only.
        if dry_run:
            yield self.log_warn("*** DRY-RUN MODE — no changes will be made ***")
        else:
            yield self.log_warn("*** LIVE MODE — changes WILL be written ***")

        # Counters used in the final summary line.  Stored on self so
        # the per-device coroutines can update them.
        self._total_remediated = 0
        self._total_ports_found = 0

        # ── Iterate every selected host ────────────────────────────────
        for host_info in hosts:
            ip = host_info["ip_address"]
            hostname = host_info.get("hostname", ip)
            device_type = host_info.get("device_type", "cisco_ios")

            yield self.log_sep()
            yield self.log_info(f"Connecting to {hostname} ({ip}) ...", host=hostname)

            # Pick the real or simulated path based on whether Netmiko
            # is installed.  Both paths yield the same shape of events
            # so the UI can't tell the difference.
            if NETMIKO_AVAILABLE:
                async for event in self._process_real_device(
                    ip, hostname, device_type, credentials,
                    template_commands, dry_run
                ):
                    yield event
            else:
                async for event in self._process_simulated_device(
                    ip, hostname, template_commands, dry_run
                ):
                    yield event

        # ── Final summary ──────────────────────────────────────────────
        yield self.log_sep()
        yield self.log_success(
            f"Complete: found {self._total_ports_found} VLAN 1 port(s) across "
            f"{len(hosts)} device(s), remediated {self._total_remediated}."
        )

    async def _process_real_device(
        self, ip, hostname, device_type, credentials, template_commands, dry_run
    ):
        """Execute the workflow against an actual switch via Netmiko."""
        # connect_device handles the device dict, exception mapping,
        # enable-mode, and the "Connected to ..." event.  It yields
        # ``conn=None`` if anything failed; we just emit any queued
        # events and bail.
        async with connect_device(
            self, ip, hostname, device_type, credentials
        ) as (conn, events):
            for ev in events:
                yield ev
            if conn is None:
                return

            # Step 1 — pull the switchport inventory.  ``delay_factor=2``
            # gives the device extra time on big chassis where the
            # output can take a while to render.
            yield self.log_info("Gathering interface inventory ...", host=hostname)
            output = await asyncio.to_thread(
                conn.send_command, "show interfaces switchport", delay_factor=2
            )
            vlan1_ports = _parse_vlan1_access_ports(output)

            # Early-exit when there's nothing to do — saves a noisy log.
            if not vlan1_ports:
                yield self.log_success(
                    "No access ports on VLAN 1 found. Device is clean.",
                    host=hostname,
                )
                yield self.log_success(
                    f"Finished processing {hostname} ({ip}).", host=hostname
                )
                return

            yield self.log_warn(
                f"Found {len(vlan1_ports)} access port(s) on VLAN 1: "
                f"{', '.join(vlan1_ports)}",
                host=hostname,
            )
            self._total_ports_found += len(vlan1_ports)

            # Step 2 — apply the template per interface.  We prepend
            # ``interface <name>`` so each command in the template
            # lands inside that interface's config block.
            for port in vlan1_ports:
                config_set = [f"interface {port}"] + template_commands
                if dry_run:
                    yield self.log_info(f"[DRY-RUN] Would apply to {port}:", host=hostname)
                    for cmd in config_set:
                        yield self.log_info(f"  {cmd}", host=hostname)
                else:
                    yield self.log_info(f"Applying template to {port} ...", host=hostname)
                    await asyncio.to_thread(conn.send_config_set, config_set)
                    yield self.log_success(f"Applied template to {port}", host=hostname)
                self._total_remediated += 1

            # Step 3 — persist running-config to startup-config so the
            # change survives a reload.  Only on a real (non-dry) run
            # that actually changed something.
            if not dry_run and self._total_remediated > 0:
                yield self.log_info("Saving running config ...", host=hostname)
                await asyncio.to_thread(conn.save_config)
                yield self.log_success("Config saved.", host=hostname)

            yield self.log_success(
                f"Finished processing {hostname} ({ip}).", host=hostname
            )

    async def _process_simulated_device(
        self, ip, hostname, template_commands, dry_run
    ):
        """Mirror the real workflow with fake data so dev/UI work flows."""
        # simulate_connect handles the random sleep + occasional fake timeout.
        async for ev in simulate_connect(self, ip, hostname):
            yield ev
            if ev.level == "error":
                # An error from simulate_connect is the "device unreachable"
                # case — skip the rest of this host.
                return

        yield self.log_info("Gathering interface inventory ...", host=hostname)
        await asyncio.sleep(random.uniform(0.3, 0.6))

        vlan1_ports = _simulate_vlan1_ports()

        if not vlan1_ports:
            yield self.log_success(
                "No access ports on VLAN 1 found. Device is clean.",
                host=hostname,
            )
            yield self.log_success(
                f"Finished processing {hostname} ({ip}).", host=hostname
            )
            return

        yield self.log_warn(
            f"Found {len(vlan1_ports)} access port(s) on VLAN 1: "
            f"{', '.join(vlan1_ports)}",
            host=hostname,
        )
        self._total_ports_found += len(vlan1_ports)

        for port in vlan1_ports:
            await asyncio.sleep(random.uniform(0.1, 0.3))
            config_set = [f"interface {port}"] + template_commands
            if dry_run:
                yield self.log_info(f"[DRY-RUN] Would apply to {port}:", host=hostname)
                for cmd in config_set:
                    yield self.log_info(f"  {cmd}", host=hostname)
            else:
                yield self.log_info(f"Applying template to {port} ...", host=hostname)
                await asyncio.sleep(random.uniform(0.2, 0.4))
                yield self.log_success(f"Applied template to {port}", host=hostname)
            self._total_remediated += 1

        if not dry_run and self._total_remediated > 0:
            yield self.log_info("Saving running config ...", host=hostname)
            await asyncio.sleep(random.uniform(0.2, 0.4))
            yield self.log_success("Config saved.", host=hostname)

        yield self.log_success(
            f"Finished processing {hostname} ({ip}).", host=hostname
        )
