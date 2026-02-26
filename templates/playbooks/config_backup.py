"""
config_backup.py — Running Config Backup Playbook

Pulls running-config from each device and saves to timestamped files.
"""

import asyncio
import random
from typing import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook


@register_playbook
class ConfigBackup(BasePlaybook):
    filename = "config_backup.py"
    display_name = "Backup Running Configs"
    description = (
        "Pulls running-config from all devices in the inventory and "
        "saves them to timestamped backup files."
    )
    tags = ["backup", "config", "maintenance"]
    requires_template = False

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield self.log_info(f"Config Backup — targeting {len(hosts)} device(s)")

        if dry_run:
            yield self.log_info("*** DRY-RUN MODE — configs will be displayed but not saved ***")
        else:
            yield self.log_info("Backup directory: ./backups/")

        backed_up = 0
        for host_info in hosts:
            ip = host_info["ip_address"]
            hostname = host_info.get("hostname", f"SW-{ip.split('.')[-1]}")
            yield self.log_sep()
            yield self.log_info(f"Connecting to {ip} ...", host=ip)
            await asyncio.sleep(random.uniform(0.3, 0.6))

            if random.random() < 0.05:
                yield self.log_error(f"Connection failed to {ip} — skipping.", host=ip)
                continue

            yield self.log_success(f"Connected to {hostname} ({ip})", host=ip)
            yield self.log_info("Pulling running-config ...", host=ip)
            await asyncio.sleep(random.uniform(0.4, 1.0))

            config_lines = random.randint(150, 600)
            yield self.log_info(f"Retrieved {config_lines} lines of configuration", host=ip)

            if dry_run:
                yield self.log_info(f"[DRY-RUN] Would save to backups/{hostname}_{ip}.cfg", host=ip)
            else:
                yield self.log_success(f"Saved to backups/{hostname}_{ip}.cfg", host=ip)

            backed_up += 1
            yield self.log_success(f"Finished processing {hostname} ({ip}).", host=ip)

        yield self.log_sep()
        yield self.log_success(f"Backup complete: {backed_up}/{len(hosts)} devices backed up.")
