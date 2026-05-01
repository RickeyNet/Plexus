"""
ntp_audit.py — NTP Compliance Audit Playbook

Walks the inventory and reports which devices are using the expected
corporate NTP servers vs. unauthorized ones.

NOTE: this playbook is currently *simulation-only* — there is no
Netmiko code path yet.  It exists to demonstrate the audit-style
playbook shape (read-only, summary at the end) and to wire up the UI
flow.  When a real implementation is added, follow the pattern in
``snmpv3_configurator.py``: use ``connect_device`` from ``_common``,
run ``show ntp associations``, and feed the output to
``parse_ntp_servers`` below.
"""

import asyncio
import random
from collections.abc import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook


# Servers every device is expected to use.  In a real deployment this
# would come from config / a settings table rather than being hard-coded.
EXPECTED_NTP_SERVERS = ["10.0.0.50", "10.0.0.51"]


@register_playbook
class NtpAudit(BasePlaybook):
    # UI metadata.  Read-only audit, so no template required.
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
        """Pull the configured server IPs out of ``show ntp associations``.

        IOS prefixes status characters (``*``, ``+``, ``~``) before the
        address column on associated peers; we strip those, then take
        the first whitespace-delimited token that looks like an IPv4
        address (i.e. has exactly three dots).
        """
        servers = []
        for line in show_output.splitlines():
            line = line.strip()
            # Skip the header row, separator dashes, and blank lines.
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

        # Tallies for the closing summary line.
        compliant = 0
        non_compliant = 0

        for host_info in hosts:
            ip = host_info["ip_address"]
            hostname = host_info.get("hostname", f"SW-{ip.split('.')[-1]}")
            yield self.log_sep()
            yield self.log_info(f"Connecting to {ip} ...", host=ip)
            await asyncio.sleep(random.uniform(0.2, 0.5))

            # 8% fake timeout rate — same shape as ``_common.simulate_connect``.
            if random.random() < 0.08:
                yield self.log_error(f"TIMEOUT connecting to {ip} — skipping.", host=ip)
                continue

            yield self.log_success(f"Connected to {hostname} ({ip})", host=ip)
            yield self.log_info("Checking NTP associations ...", host=ip)
            await asyncio.sleep(random.uniform(0.2, 0.4))

            # Bias the simulation toward compliance (75%) to mimic a
            # mostly-clean fleet — failures stand out, which is what
            # the real-world output usually looks like.
            if random.random() < 0.75:
                yield self.log_success(
                    f"COMPLIANT — NTP servers: {', '.join(EXPECTED_NTP_SERVERS)}",
                    host=ip,
                )
                compliant += 1
            else:
                # Generate a random RFC1918 address to play the role of
                # an unauthorized NTP source the audit found.
                rogue = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                yield self.log_warn(
                    f"NON-COMPLIANT — Found unauthorized NTP server: {rogue}",
                    host=ip,
                )
                non_compliant += 1

            yield self.log_success(f"Finished processing {hostname} ({ip}).", host=ip)

        yield self.log_sep()
        yield self.log_info(
            f"Audit complete: {compliant} compliant, {non_compliant} non-compliant"
        )
        # Promote the closing line to ``success`` or ``warn`` so the UI
        # colours it appropriately at a glance.
        if non_compliant == 0:
            yield self.log_success("All devices are NTP-compliant.")
        else:
            yield self.log_warn(f"{non_compliant} device(s) need NTP remediation.")

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        # Currently always simulation; see module docstring for the
        # roadmap to a real Netmiko implementation.
        async for event in self._run_simulated(hosts, credentials, template_commands, dry_run):
            yield event
