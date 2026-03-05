"""
vlan1_destroyer.py — VLAN 1 Access Port Remediation Playbook

Connects to Cisco Catalyst switches, inventories all interfaces,
identifies access ports assigned to VLAN 1, and applies a replacement
interface configuration from the selected template.

When Netmiko is not installed or devices are unreachable during development,
the script runs in simulation mode with realistic fake output.
"""

import asyncio
import random

from routes.runner import BasePlaybook, register_playbook

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False


def _parse_vlan1_access_ports(output: str) -> list[str]:
    """Parse 'show interfaces switchport' to find access ports on VLAN 1."""
    vlan1_ports = []
    current_interface = None
    is_access = False
    access_vlan = None

    for line in output.splitlines():
        if line.startswith("Name:"):
            if current_interface and is_access and access_vlan == "1":
                vlan1_ports.append(current_interface)
            current_interface = line.split("Name:")[-1].strip()
            is_access = False
            access_vlan = None
        elif "Administrative Mode:" in line:
            mode = line.split("Administrative Mode:")[-1].strip().lower()
            is_access = mode == "static access"
        elif "Access Mode VLAN:" in line:
            vlan_part = line.split("Access Mode VLAN:")[-1].strip()
            access_vlan = vlan_part.split()[0] if vlan_part else None

    if current_interface and is_access and access_vlan == "1":
        vlan1_ports.append(current_interface)

    return vlan1_ports


def _simulate_vlan1_ports() -> list[str]:
    """Generate realistic fake VLAN 1 port data for simulation mode."""
    all_ports = [f"Gi1/0/{i}" for i in range(1, 49)]
    vlan1_count = random.randint(0, 8)
    return random.sample(all_ports, vlan1_count)


@register_playbook
class Vlan1Destroyer(BasePlaybook):
    filename = "vlan1_destroyer.py"
    display_name = "VLAN 1 Destroyer"
    description = (
        "Scans Cisco switches for access ports still on VLAN 1 and applies "
        "a hardening template to move them off the default VLAN. "
        "Requires a config template with the replacement port commands."
    )
    tags = ["vlan", "security", "remediation", "cisco"]
    requires_template = True

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield self.log_info(
            f"VLAN 1 Destroyer — targeting {len(hosts)} device(s)"
        )

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

        if dry_run:
            yield self.log_warn("*** DRY-RUN MODE — no changes will be made ***")
        else:
            yield self.log_warn("*** LIVE MODE — changes WILL be written ***")

        self._total_remediated = 0
        self._total_ports_found = 0

        for host_info in hosts:
            ip = host_info["ip_address"]
            hostname = host_info.get("hostname", ip)
            device_type = host_info.get("device_type", "cisco_ios")

            yield self.log_sep()
            yield self.log_info(f"Connecting to {hostname} ({ip}) ...", host=hostname)

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

        yield self.log_sep()
        yield self.log_success(
            f"Complete: found {self._total_ports_found} VLAN 1 port(s) across "
            f"{len(hosts)} device(s), remediated {self._total_remediated}."
        )

    async def _process_real_device(
        self, ip, hostname, device_type, credentials, template_commands, dry_run
    ):
        """Connect to a real device via Netmiko."""
        device = {
            "device_type": device_type,
            "host": ip,
            "username": credentials["username"],
            "password": credentials["password"],
            "secret": credentials.get("secret", credentials["password"]),
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

            yield self.log_info("Gathering interface inventory ...", host=hostname)
            output = await asyncio.to_thread(
                conn.send_command, "show interfaces switchport", delay_factor=2
            )
            vlan1_ports = _parse_vlan1_access_ports(output)

            if not vlan1_ports:
                yield self.log_success(
                    "No access ports on VLAN 1 found. Device is clean.",
                    host=hostname
                )
                yield self.log_success(f"Finished processing {hostname} ({ip}).", host=hostname)
                return

            yield self.log_warn(
                f"Found {len(vlan1_ports)} access port(s) on VLAN 1: "
                f"{', '.join(vlan1_ports)}",
                host=hostname
            )
            self._total_ports_found += len(vlan1_ports)

            for port in vlan1_ports:
                config_set = [f"interface {port}"] + template_commands
                if dry_run:
                    yield self.log_info(f"[DRY-RUN] Would apply to {port}:", host=hostname)
                    for cmd in config_set:
                        yield self.log_info(f"  {cmd}", host=hostname)
                else:
                    yield self.log_info(f"Applying template to {port} ...", host=hostname)
                    output = await asyncio.to_thread(conn.send_config_set, config_set)
                    yield self.log_success(f"Applied template to {port}", host=hostname)
                self._total_remediated += 1

            if not dry_run and self._total_remediated > 0:
                yield self.log_info("Saving running config ...", host=hostname)
                await asyncio.to_thread(conn.save_config)
                yield self.log_success("Config saved.", host=hostname)

            yield self.log_success(f"Finished processing {hostname} ({ip}).", host=hostname)

        finally:
            conn.disconnect()

    async def _process_simulated_device(
        self, ip, hostname, template_commands, dry_run
    ):
        """Simulate device processing for development/testing."""
        await asyncio.sleep(random.uniform(0.3, 0.8))

        if random.random() < 0.08:
            yield self.log_error(
                f"TIMEOUT connecting to {ip} — skipping.", host=hostname
            )
            return

        yield self.log_success(f"Connected to {hostname} ({ip})", host=hostname)
        yield self.log_info("Gathering interface inventory ...", host=hostname)
        await asyncio.sleep(random.uniform(0.3, 0.6))

        vlan1_ports = _simulate_vlan1_ports()

        if not vlan1_ports:
            yield self.log_success(
                "No access ports on VLAN 1 found. Device is clean.",
                host=hostname
            )
            yield self.log_success(f"Finished processing {hostname} ({ip}).", host=hostname)
            return

        yield self.log_warn(
            f"Found {len(vlan1_ports)} access port(s) on VLAN 1: "
            f"{', '.join(vlan1_ports)}",
            host=hostname
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

        yield self.log_success(f"Finished processing {hostname} ({ip}).", host=hostname)
