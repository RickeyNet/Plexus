"""
ansible_inventory.py — Ansible dynamic inventory provider for Plexus.

Exposes Plexus device inventory in Ansible dynamic inventory JSON format
via HTTP endpoints. Supports group mapping, host variables, and filtering
by group name, device type, and device category.

Ansible dynamic inventory spec:
  --list  → {"group": {"hosts": [...]}, "_meta": {"hostvars": {...}}}
  --host <name> → {host_var: value, ...}
"""

from __future__ import annotations

import logging

import routes.database as db
from fastapi import APIRouter, HTTPException, Query

_LOGGER = logging.getLogger("plexus.ansible_inventory")

router = APIRouter()

# Late-bound auth dependency
_require_auth = None


def init_ansible_inventory(require_auth):
    global _require_auth
    _require_auth = require_auth


# ── Device type mapping (mirrors routes/ansible_runner_backend.py) ───────────

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
    return _DEVICE_TYPE_MAP.get(device_type, device_type)


def _ansible_connection(device_type: str) -> str:
    if device_type in ("linux", "linux_ssh"):
        return "ssh"
    return "ansible.netcommon.network_cli"


def _sanitize_group_name(name: str) -> str:
    """Convert a Plexus group name to a valid Ansible group name.

    Ansible group names must be alphanumeric + underscore.
    """
    return "".join(c if c.isalnum() or c == "_" else "_" for c in name)


async def _fetch_inventory(
    group: str | None,
    device_type: str | None,
    device_category: str | None,
) -> dict:
    """Build the full Ansible dynamic inventory JSON payload.

    Returns the ``--list`` format with ``_meta.hostvars`` so Ansible
    does not need to make per-host callbacks.
    """
    groups_data = await db.get_all_groups_with_hosts()

    inventory: dict = {"_meta": {"hostvars": {}}}
    all_hosts: list[str] = []

    for grp in groups_data:
        grp_name = grp["name"]

        # Filter by group name if requested
        if group and grp_name != group:
            continue

        ansible_group = _sanitize_group_name(grp_name)

        group_hosts: list[str] = []
        for host in grp.get("hosts", []):
            dt = host.get("device_type", "cisco_ios")
            cat = host.get("device_category", "")

            # Filter by device_type if requested
            if device_type and dt != device_type:
                continue
            # Filter by device_category if requested
            if device_category and cat != device_category:
                continue

            # Use hostname as inventory key, fall back to IP
            key = host.get("hostname") or host["ip_address"]

            hostvars = {
                "ansible_host": host["ip_address"],
                "ansible_network_os": _map_network_os(dt),
                "ansible_connection": _ansible_connection(dt),
                "plexus_device_type": dt,
                "plexus_model": host.get("model", ""),
                "plexus_software_version": host.get("software_version", ""),
                "plexus_status": host.get("status", "unknown"),
                "plexus_group": grp_name,
                "plexus_host_id": host.get("id"),
            }
            if cat:
                hostvars["plexus_device_category"] = cat

            inventory["_meta"]["hostvars"][key] = hostvars
            group_hosts.append(key)
            all_hosts.append(key)

        if group_hosts:
            inventory[ansible_group] = {"hosts": group_hosts}

    # Ansible expects an "all" group
    inventory["all"] = {"hosts": all_hosts}

    return inventory


@router.get("/api/ansible/inventory")
async def ansible_inventory_list(
    group: str | None = Query(default=None, description="Filter by Plexus group name"),
    device_type: str | None = Query(default=None, description="Filter by device_type (e.g. cisco_ios)"),
    device_category: str | None = Query(default=None, description="Filter by device_category (e.g. router, switch)"),
):
    """Return Ansible dynamic inventory in ``--list`` format.

    This endpoint returns all groups with their hosts and a ``_meta.hostvars``
    section so Ansible does not need to issue per-host callbacks.
    """
    return await _fetch_inventory(group, device_type, device_category)


@router.get("/api/ansible/inventory/host/{hostname}")
async def ansible_inventory_host(hostname: str):
    """Return host variables for a single host (``--host`` format).

    Looks up the host by hostname across all inventory groups.
    """
    inv = await _fetch_inventory(group=None, device_type=None, device_category=None)
    hostvars = inv.get("_meta", {}).get("hostvars", {}).get(hostname)
    if hostvars is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return hostvars
