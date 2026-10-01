"""Attach Plexus inventory data to Meraki topology nodes.

Meraki hardware is cloud-managed and exposes no CLI, so "SSH" and "SNMP" can
only add value where a node is *also* a Plexus inventory host:

  - a non-Meraki LLDP/CDP neighbor (core switch, ISP router, firewall), or
  - a cloud-monitored Catalyst that Plexus manages directly as well.

``normalize.build_snapshot`` tags those nodes with ``node["inventory"]``.
This module then appends, per matched host:

  1. data Plexus already collected over SNMP/SSH (interfaces, VLANs, the
     latest route-table snapshot, CDP/LLDP links), read from the database, and
  2. optionally (``ssh_enrich``) live show-command output over SSH.

Live SSH uses the Plexus service credential only - the same rule as every
other unattended collector - and never runs configuration commands.
"""

from __future__ import annotations

import asyncio
from typing import Any

import routes.database as db

import netcontrol.routes.state as state
from netcontrol.integrations.meraki.normalize import InventoryIndex, _add, table_section, text_section
from netcontrol.telemetry import configure_logging, redact_value

LOGGER = configure_logging("plexus.meraki")

# Read-only show commands per Netmiko device_type prefix. First match wins.
_SHOW_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("cisco_asa", ("show route", "show interface ip brief", "show vpn-sessiondb summary")),
    ("cisco_ftd", ("show route", "show interface ip brief", "show vpn-sessiondb summary")),
    ("cisco_nxos", ("show ip route", "show vlan brief", "show ip interface brief", "show cdp neighbors")),
    ("cisco_xr", ("show route", "show ipv4 interface brief", "show lldp neighbors")),
    ("cisco", ("show ip route", "show vlan brief", "show ip interface brief", "show cdp neighbors")),
    ("arista", ("show ip route", "show vlan brief", "show ip interface brief", "show lldp neighbors")),
    ("juniper", ("show route terse", "show vlans", "show interfaces terse", "show lldp neighbors")),
    ("fortinet", ("get router info routing-table all", "get system interface physical")),
    ("paloalto", ("show routing route", "show interface all")),
)

_MAX_OUTPUT_CHARS = 120_000
_MAX_ROUTE_TEXT_CHARS = 200_000
_ALIAS_CHUNK = 500
_SSH_TIMEOUT_SECONDS = 90


def show_commands_for(device_type: str) -> tuple[str, ...]:
    dtype = (device_type or "").lower()
    for prefix, commands in _SHOW_COMMANDS:
        if dtype.startswith(prefix):
            return commands
    return ()


async def load_inventory_index() -> InventoryIndex:
    """Build the serial/IP/hostname lookup over every inventory host."""
    hosts = await db.get_all_hosts()
    host_ids = [h["id"] for h in hosts]
    aliases: list[dict] = []
    for start in range(0, len(host_ids), _ALIAS_CHUNK):
        aliases.extend(await db.get_ip_aliases_for_hosts(host_ids[start : start + _ALIAS_CHUNK]))
    return InventoryIndex(hosts, aliases)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... (truncated, {len(text) - limit} more characters)"


async def collected_sections(host_id: int) -> list[dict]:
    """Sections built from what Plexus has already stored for this host."""
    sections: list[dict] = []
    interfaces = await db.get_interface_inventory_for_host(host_id)
    _add(
        sections,
        table_section(
            "Interfaces (Plexus SNMP)",
            ["Interface", "Description", "Admin", "Oper", "Speed (Mb)", "Duplex", "Access VLAN", "Trunk VLANs"],
            [
                [
                    i.get("name"),
                    i.get("description"),
                    i.get("admin_state"),
                    i.get("oper_state"),
                    i.get("speed_mbps") or "",
                    i.get("duplex"),
                    i.get("access_vlan") or "",
                    i.get("trunk_vlans"),
                ]
                for i in interfaces
            ],
        ),
    )
    vlans = await db.get_vlan_definitions_for_host(host_id)
    _add(
        sections,
        table_section(
            "VLANs (Plexus SNMP)",
            ["VLAN", "Name", "State"],
            [[v.get("vlan_id"), v.get("name"), v.get("state")] for v in vlans],
        ),
    )
    links = await db.get_topology_links_for_host(host_id)
    _add(
        sections,
        table_section(
            "Neighbors (Plexus CDP/LLDP)",
            ["Local interface", "Neighbor", "Remote interface", "Neighbor IP", "Protocol"],
            [
                [
                    link.get("source_interface"),
                    link.get("target_device_name"),
                    link.get("target_interface"),
                    link.get("target_ip"),
                    link.get("protocol"),
                ]
                for link in links
            ],
        ),
    )
    route_snapshot = await db.get_latest_route_snapshot(host_id)
    if route_snapshot and route_snapshot.get("routes_text"):
        _add(
            sections,
            text_section(
                f"Route table (Plexus SSH, {route_snapshot.get('route_count') or 0} routes, "
                f"captured {route_snapshot.get('captured_at') or 'unknown'})",
                _truncate(str(route_snapshot["routes_text"]), _MAX_ROUTE_TEXT_CHARS),
            ),
        )
    return sections


def _run_show_commands(host: dict, credential: dict, commands: tuple[str, ...]) -> dict[str, str]:
    """Blocking: one SSH session, every command, best-effort per command."""
    from netcontrol.routes.shared import _open_netmiko_session

    conn, _resolved = _open_netmiko_session(host, credential)
    outputs: dict[str, str] = {}
    try:
        for command in commands:
            try:
                outputs[command] = str(conn.send_command(command, read_timeout=30))
            except Exception as exc:  # noqa: BLE001 - one bad command must not lose the rest
                outputs[command] = f"(command failed: {type(exc).__name__})"
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass
    return outputs


async def _live_ssh_sections(host: dict, credential: dict) -> tuple[list[dict], str | None]:
    commands = show_commands_for(str(host.get("device_type") or ""))
    if not commands:
        return [], None
    try:
        async with state.device_op_semaphore():
            outputs = await asyncio.wait_for(
                asyncio.to_thread(_run_show_commands, host, credential, commands),
                timeout=_SSH_TIMEOUT_SECONDS,
            )
    except Exception as exc:  # noqa: BLE001 - recorded in the collection report
        LOGGER.warning("meraki: SSH enrichment failed for %s: %s", host.get("hostname", "?"), redact_value(str(exc)))
        return [], f"SSH enrichment failed ({type(exc).__name__})"
    sections: list[dict] = []
    for command, output in outputs.items():
        _add(sections, text_section(f"CLI (live SSH): {command}", _truncate(output, _MAX_OUTPUT_CHARS)))
    return sections, None


async def _service_credential() -> dict | None:
    cred_id = state.AUTH_CONFIG.get("service_credential_id")
    if not isinstance(cred_id, int):
        return None
    cred = await db.get_credential_raw(cred_id)
    # Unattended work may only use a Plexus-owned service credential, never a
    # user's personal stored credential.
    if not cred or not cred.get("is_service"):
        return None
    return cred


async def enrich_snapshot(snapshot: dict[str, Any], *, ssh: bool = False, progress=None) -> dict[str, Any]:
    """Append inventory-derived sections to matched nodes (in place)."""
    matched = [n for n in snapshot.get("nodes") or [] if (n.get("inventory") or {}).get("host_id")]
    collection = snapshot.setdefault("collection", {})
    if not matched:
        return snapshot

    credential = await _service_credential() if ssh else None
    if ssh and credential is None:
        collection.setdefault("errors", []).append(
            {
                "scope": "ssh",
                "path": "",
                "status": None,
                "message": "Live SSH enrichment skipped: no Plexus service credential is configured",
            }
        )

    # Several nodes can map to one host (a core switch seen from many sites);
    # collect once per host and share the sections.
    cache: dict[int, list[dict]] = {}
    used_ssh = False
    for index, node in enumerate(matched, start=1):
        host_id = int(node["inventory"]["host_id"])
        if host_id not in cache:
            sections = await collected_sections(host_id)
            if credential is not None:
                host = await db.get_host(host_id)
                if host:
                    live, error = await _live_ssh_sections(host, credential)
                    sections.extend(live)
                    used_ssh = used_ssh or bool(live)
                    if error:
                        collection.setdefault("errors", []).append(
                            {"scope": f"ssh:{host.get('hostname')}", "path": "", "status": None, "message": error}
                        )
            cache[host_id] = sections
        node["sections"].extend(cache[host_id])
        if progress is not None:
            progress({"phase": "inventory", "hosts_done": index, "hosts_total": len(matched)})

    sources = collection.setdefault("sources", [])
    sources.append("Plexus inventory (SNMP/SSH-collected data)")
    if used_ssh:
        sources.append("Live SSH show commands")
    return snapshot
