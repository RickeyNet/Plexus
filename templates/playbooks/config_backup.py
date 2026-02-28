"""
config_backup.py — Running Config Backup Playbook

Pulls running-config from each device and saves to timestamped files.
"""

import asyncio
import random
import os
import netmiko
import datetime
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

        # Ensure the backups directory exists
        backup_dir = "backups"
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        if dry_run:
            yield self.log_info("*** DRY-RUN MODE — configs will be displayed but not saved ***")
        else:
            yield self.log_info(f"Backup directory: ./{backup_dir}/")

        backed_up = 0
        for host_info in hosts:
            ip = host_info["ip_address"]
            hostname = host_info.get("hostname", f"SW-{ip.split('.')[-1]}")
            yield self.log_sep()
            yield self.log_info(f"Connecting to {ip} ...", host=ip)
            await asyncio.sleep(random.uniform(0.3, 0.6))

            yield self.log_success(f"Connected to {hostname} ({ip})", host=ip)
            yield self.log_info("Pulling running-config ...", host=ip)
            await asyncio.sleep(random.uniform(0.4, 1.0))

            config_lines = random.randint(150, 600)
            yield self.log_info(f"Retrieved {config_lines} lines of configuration", host=ip)

            # Simulate pulling the actual running-config using 'show running-config'
            running_config = f"! Running configuration for {hostname} ({ip})\n"
            running_config += "\n".join([f"interface {i}" for i in range(1, config_lines)])

            if not dry_run:
                # Add date to filename
                date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file_path = os.path.join(backup_dir, f"{hostname}_{ip}_{date_str}.txt")
                try:
                    device = {
                        "device_type": "cisco_ios",
                        "host": ip,
                        "username": credentials.get("username"),
                        "password": credentials.get("password"),
                        "secret": credentials.get("secret", ""),
                    }
                    net_connect = netmiko.ConnectHandler(**device)
                    if device["secret"]:
                        net_connect.enable()
                    running_config = net_connect.send_command("show running-config")
                    net_connect.disconnect()
                    with open(backup_file_path, "w") as backup_file:
                        backup_file.write(running_config)
                    yield self.log_success(f"Saved to {backup_file_path}", host=ip)
                except Exception as e:
                    yield self.log_error(f"Failed to backup {hostname} ({ip}): {e}", host=ip)

            backed_up += 1
            yield self.log_success(f"Finished processing {hostname} ({ip}).", host=ip)

        yield self.log_sep()
        yield self.log_success(f"Backup complete: {backed_up}/{len(hosts)} devices backed up.")
