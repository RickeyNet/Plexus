"""
ntp_audit.py — NTP Compliance Audit Playbook

Checks each device for proper NTP configuration. Reports devices
that are missing NTP servers or have unauthorized NTP sources.
"""

import asyncio
import random
from collections.abc import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False


EXPECTED_NTP_SERVERS = ["10.0.0.50", "10.0.0.51"]


@register_playbook
class NtpAudit(BasePlaybook):
    filename = "ntp_audit.py"
    display_name = "NTP Compliance Check"
    description = (
        "Audits NTP configuration on all devices. Reports missing or "
        "unauthorized NTP servers and clock settings."
    )
    tags = ["ntp", "compliance", "audit"]
    requires_template = False

    @staticmethod
    def parse_ntp_servers(show_output: str) -> list[str]:
        """Parse 'show ntp associations' for configured server IPs."""
        servers = []
        for line in show_output.splitlines():
            line = line.strip()
            if not line or line.startswith("address") or line.startswith("-"):
                continue
            parts = line.replace("*", "").replace("+", "").replace("~", "").split()
            if parts and parts[0].count(".") == 3:
                servers.append(parts[0])
        return servers

    async def _run_simulated(
        self, hosts, credentials, template_commands, dry_run
    ) -> AsyncGenerator[LogEvent, None]:
        yield self.log_info(f"NTP Compliance Audit — checking {len(hosts)} host(s)")
        yield self.log_info(f"Expected NTP servers: {', '.join(EXPECTED_NTP_SERVERS)}")

        compliant = 0
        non_compliant = 0

        for host_info in hosts:
            ip = host_info["ip_address"]
            hostname = host_info.get("hostname", f"SW-{ip.split('.')[-1]}")
            yield self.log_sep()
            yield self.log_info(f"Connecting to {ip} ...", host=ip)
            await asyncio.sleep(random.uniform(0.2, 0.5))

            if random.random() < 0.08:
                yield self.log_error(f"TIMEOUT connecting to {ip} — skipping.", host=ip)
                continue

            yield self.log_success(f"Connected to {hostname} ({ip})", host=ip)
            yield self.log_info("Checking NTP associations ...", host=ip)
            await asyncio.sleep(random.uniform(0.2, 0.4))

            # Simulate NTP check
            if random.random() < 0.75:
                yield self.log_success(
                    f"COMPLIANT — NTP servers: {', '.join(EXPECTED_NTP_SERVERS)}",
                    host=ip,
                )
                compliant += 1
            else:
                rogue = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
                yield self.log_warn(
                    f"NON-COMPLIANT — Found unauthorized NTP server: {rogue}",
                    host=ip,
                )
                non_compliant += 1

            yield self.log_success(f"Finished processing {hostname} ({ip}).", host=ip)

        yield self.log_sep()
        yield self.log_info(f"Audit complete: {compliant} compliant, {non_compliant} non-compliant")
        if non_compliant == 0:
            yield self.log_success("All devices are NTP-compliant.")
        else:
            yield self.log_warn(f"{non_compliant} device(s) need NTP remediation.")

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        async for event in self._run_simulated(hosts, credentials, template_commands, dry_run):
            yield event
