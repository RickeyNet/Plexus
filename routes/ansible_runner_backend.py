"""
ansible_runner_backend.py — Ansible execution backend for Plexus.

Translates Plexus inventory/credentials into ansible-runner format,
executes YAML playbooks, and streams events back as LogEvent objects
compatible with the existing job/WebSocket pipeline.
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile

import ansible_runner

from routes.runner import LogEvent, PlaybookResult

_LOGGER = logging.getLogger("plexus.ansible")

# ── Device type mapping ──────────────────────────────────────────────────────

# Maps Netmiko device_type values to Ansible ansible_network_os values
_DEVICE_TYPE_MAP = {
    "cisco_ios":        "cisco.ios.ios",
    "cisco_xe":         "cisco.ios.ios",
    "cisco_nxos":       "cisco.nxos.nxos",
    "cisco_nxos_ssh":   "cisco.nxos.nxos",
    "cisco_asa":        "cisco.asa.asa",
    "cisco_xr":         "cisco.iosxr.iosxr",
    "arista_eos":       "arista.eos.eos",
    "juniper_junos":    "junipernetworks.junos.junos",
    "paloalto_panos":   "paloaltonetworks.panos.panos",
    "linux":            "linux",
    "linux_ssh":        "linux",
    "vyos":             "vyos.vyos.vyos",
    "fortinet":         "fortinet.fortios.fortios",
    "hp_comware":       "community.network.comware",
    "hp_procurve":      "community.network.procurve",
    "dell_os10":        "dellemc.os10.os10",
}


def _map_network_os(device_type: str) -> str:
    """Map a Netmiko device_type to an Ansible network_os value."""
    return _DEVICE_TYPE_MAP.get(device_type, device_type)


def _ansible_connection(device_type: str) -> str:
    """Determine the Ansible connection type from a device type."""
    if device_type in ("linux", "linux_ssh"):
        return "ssh"
    return "ansible.netcommon.network_cli"


# ── Inventory generation ─────────────────────────────────────────────────────

def build_inventory(
    hosts: list[dict],
    credentials: dict,
    group_name: str = "plexus_targets",
) -> dict:
    """
    Build an ansible-runner compatible inventory dict from Plexus hosts.

    Args:
        hosts: list of host dicts from the DB (ip_address, hostname, device_type, etc.)
        credentials: dict with username, password, and optional secret
        group_name: Ansible group name for the hosts
    """
    host_entries = {}
    for host in hosts:
        dt = host.get("device_type", "cisco_ios")
        entry = {
            "ansible_host": host["ip_address"],
            "ansible_network_os": _map_network_os(dt),
            "ansible_connection": _ansible_connection(dt),
            "ansible_user": credentials["username"],
            "ansible_password": credentials["password"],
        }
        if credentials.get("secret"):
            entry["ansible_become"] = True
            entry["ansible_become_method"] = "enable"
            entry["ansible_become_password"] = credentials["secret"]

        # Use hostname as the inventory key, fall back to IP
        key = host.get("hostname") or host["ip_address"]
        # Deduplicate keys if multiple hosts share a hostname
        if key in host_entries:
            key = f"{key}_{host['ip_address']}"
        host_entries[key] = entry

    return {
        "all": {
            "children": {
                group_name: {
                    "hosts": host_entries,
                }
            }
        }
    }


# ── Event translation ────────────────────────────────────────────────────────

def _translate_event(event: dict) -> LogEvent | None:
    """Translate an ansible-runner event dict into a Plexus LogEvent."""
    etype = event.get("event", "")
    data = event.get("event_data", {})

    host = data.get("host", "")
    task = data.get("task", "")
    play = data.get("play", "")
    role = data.get("role", "")

    task_label = f"{role} : {task}" if role else task

    if etype == "playbook_on_play_start":
        return LogEvent(level="sep", message=f"PLAY [{play}]")

    if etype == "playbook_on_task_start":
        return LogEvent(level="info", message=f"TASK [{task_label}]")

    if etype == "runner_on_start":
        return LogEvent(level="dim", message=f"Starting: {task_label}", host=host)

    if etype == "runner_on_ok":
        result = data.get("res", {})
        changed = result.get("changed", False)
        label = "CHANGED" if changed else "OK"
        msg = f"{label}: {task_label}"
        # Include stdout if present (e.g., command output)
        stdout = result.get("stdout", "")
        if stdout:
            msg += f"\n{stdout}"
        return LogEvent(level="success", message=msg, host=host)

    if etype == "runner_on_failed":
        result = data.get("res", {})
        err_msg = result.get("msg", "") or result.get("stderr", "") or str(result)
        return LogEvent(
            level="error",
            message=f"FAILED: {task_label} — {err_msg}",
            host=host,
        )

    if etype == "runner_on_skipped":
        return LogEvent(level="dim", message=f"SKIPPED: {task_label}", host=host)

    if etype == "runner_on_unreachable":
        result = data.get("res", {})
        err_msg = result.get("msg", "unreachable")
        return LogEvent(
            level="error",
            message=f"UNREACHABLE: {err_msg}",
            host=host,
        )

    if etype == "runner_item_on_ok":
        item = data.get("res", {}).get("item", "")
        return LogEvent(level="success", message=f"OK (item={item}): {task_label}", host=host)

    if etype == "runner_item_on_failed":
        item = data.get("res", {}).get("item", "")
        err_msg = data.get("res", {}).get("msg", "")
        return LogEvent(
            level="error",
            message=f"FAILED (item={item}): {task_label} — {err_msg}",
            host=host,
        )

    if etype == "playbook_on_stats":
        return None  # Handled separately for summary extraction

    # Ignore internal/verbose events
    return None


def _extract_stats(events: list[dict]) -> tuple[int, int, int, int]:
    """
    Extract host counts from ansible-runner events.
    Returns (ok, failed, unreachable, skipped).
    """
    hosts_ok = set()
    hosts_failed = set()
    hosts_unreachable = set()
    hosts_skipped = set()

    for ev in events:
        etype = ev.get("event", "")
        host = ev.get("event_data", {}).get("host", "")
        if not host:
            continue
        if etype == "runner_on_ok":
            hosts_ok.add(host)
        elif etype == "runner_on_failed":
            hosts_failed.add(host)
        elif etype == "runner_on_unreachable":
            hosts_unreachable.add(host)
        elif etype == "runner_on_skipped":
            hosts_skipped.add(host)

    # Hosts that failed or were unreachable should not be counted as ok
    pure_ok = hosts_ok - hosts_failed - hosts_unreachable
    total_failed = len(hosts_failed | hosts_unreachable)
    return len(pure_ok), total_failed, len(hosts_skipped - pure_ok - hosts_failed - hosts_unreachable)


# ── Main executor ────────────────────────────────────────────────────────────

async def execute_ansible_playbook(
    playbook_content: str,
    hosts: list[dict],
    credentials: dict,
    group_name: str = "plexus_targets",
    dry_run: bool = False,
    extra_vars: dict | None = None,
    event_callback=None,
) -> PlaybookResult:
    """
    Execute an Ansible YAML playbook via ansible-runner.

    Args:
        playbook_content: YAML string of the playbook
        hosts: list of host dicts from Plexus inventory
        credentials: dict with username, password, secret
        group_name: inventory group name
        dry_run: if True, run in --check mode
        extra_vars: additional variables to pass
        event_callback: async callable(LogEvent) for real-time streaming

    Returns:
        PlaybookResult with host counts
    """
    tmpdir = tempfile.mkdtemp(prefix="plexus_ansible_")
    try:
        # Set up ansible-runner project structure
        project_dir = os.path.join(tmpdir, "project")
        inventory_dir = os.path.join(tmpdir, "inventory")
        os.makedirs(project_dir, exist_ok=True)
        os.makedirs(inventory_dir, exist_ok=True)

        # Write the playbook YAML
        playbook_path = os.path.join(project_dir, "playbook.yml")
        with open(playbook_path, "w", encoding="utf-8") as f:
            f.write(playbook_content)

        # Write inventory JSON
        inventory = build_inventory(hosts, credentials, group_name)
        inventory_path = os.path.join(inventory_dir, "hosts.json")
        with open(inventory_path, "w", encoding="utf-8") as f:
            json.dump(inventory, f, indent=2)

        # Write ansible.cfg to disable host key checking for lab/automation use
        cfg_path = os.path.join(project_dir, "ansible.cfg")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("[defaults]\n")
            f.write("host_key_checking = False\n")
            f.write("timeout = 30\n")
            f.write("gathering = explicit\n")
            f.write("\n[persistent_connection]\n")
            f.write("connect_timeout = 30\n")
            f.write("command_timeout = 30\n")

        # Build cmdline args
        cmdline = ""
        if dry_run:
            cmdline = "--check --diff"

        # Emit start event
        if event_callback:
            await event_callback(LogEvent(
                level="info",
                message=f"Launching Ansible playbook ({len(hosts)} host(s), "
                        f"group={group_name}, check_mode={dry_run})",
            ))

        # Run ansible-runner in a thread to not block the event loop
        runner = await asyncio.to_thread(
            ansible_runner.run,
            private_data_dir=tmpdir,
            playbook="playbook.yml",
            inventory=inventory_path,
            extravars=extra_vars or {},
            cmdline=cmdline or None,
            quiet=True,
        )

        # Process events and stream them
        all_events = list(runner.events)

        for ev in all_events:
            log_event = _translate_event(ev)
            if log_event and event_callback:
                await event_callback(log_event)

        # Extract summary stats
        ok, failed, skipped = _extract_stats(all_events)

        # Emit summary
        status = "failed" if runner.status == "failed" or failed > 0 else "success"
        if event_callback:
            await event_callback(LogEvent(
                level="sep",
                message="=" * 60,
            ))
            summary_level = "success" if status == "success" else "error"
            await event_callback(LogEvent(
                level=summary_level,
                message=f"Playbook finished: {runner.status} "
                        f"(ok={ok} failed={failed} skipped={skipped})",
            ))

        return PlaybookResult(
            status=status,
            hosts_ok=ok,
            hosts_failed=failed,
            hosts_skipped=skipped,
        )

    except Exception as e:
        _LOGGER.error("Ansible playbook execution error: %s", e, exc_info=True)
        if event_callback:
            await event_callback(LogEvent(
                level="error",
                message=f"Ansible execution failed: {e}",
            ))
        return PlaybookResult(status="failed", hosts_ok=0, hosts_failed=len(hosts), hosts_skipped=0)

    finally:
        # Clean up temp directory
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
