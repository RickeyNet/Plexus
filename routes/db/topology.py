"""Topology persistence helpers.

Split out of routes/database.py; star re-exported there so the
``routes.database`` facade keeps its full public surface.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
from datetime import UTC, datetime, timedelta

import aiosqlite

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "upsert_topology_link",
    "get_topology_links",
    "get_topology_links_for_host",
    "delete_topology_links_for_host",
    "replace_topology_links_for_host",
    "delete_all_topology_links",
    "resolve_topology_target_host_ids",
    "upsert_interface_stat",
    "upsert_interface_stats_batch",
    "get_interface_stats_for_host",
    "get_interface_stats_by_hosts",
    "upsert_interface_inventory",
    "get_interface_inventory_for_host",
    "get_interface_inventory_by_name",
    "upsert_vlan_definition",
    "get_vlan_definitions_for_host",
    "insert_topology_change",
    "get_topology_changes",
    "get_topology_changes_count",
    "acknowledge_topology_changes",
    "delete_old_topology_changes",
    "upsert_stp_port_state",
    "delete_stp_port_states_for_host",
    "get_stp_port_states",
    "insert_stp_topology_event",
    "get_stp_topology_events",
    "get_stp_topology_events_count",
    "acknowledge_stp_topology_events",
    "count_recent_stp_topology_events",
    "upsert_stp_root_policy",
    "get_stp_root_policy",
    "get_stp_root_policies",
    "delete_stp_root_policy",
    "get_topology_positions",
    "save_topology_positions",
    "delete_topology_positions",
    "create_config_baseline",
    "get_config_baseline",
    "get_config_baseline_for_host",
    "get_config_baselines",
    "get_baselined_host_ids",
    "update_config_baseline",
    "delete_config_baseline",
    "create_config_snapshot",
    "get_config_snapshot",
    "get_config_snapshots_by_ids",
    "get_config_snapshots_for_host",
    "get_latest_config_snapshot",
    "delete_config_snapshot",
    "delete_old_config_snapshots",
    "create_config_drift_event",
    "create_config_drift_event_history",
    "get_config_drift_event_history",
    "get_config_drift_event",
    "get_config_drift_events_by_ids",
    "get_config_drift_events",
    "get_config_drift_summary",
    "update_config_drift_event_status",
    "delete_old_config_drift_events",
    "create_config_backup_policy",
    "get_config_backup_policies",
    "get_config_backup_policy",
    "update_config_backup_policy",
    "delete_config_backup_policy",
    "get_config_backup_policies_due",
    "update_config_backup_policy_last_run",
    "create_config_backup",
    "get_latest_config_backup",
    "get_config_backups",
    "get_latest_config_backups_per_host",
    "get_config_backup",
    "get_previous_successful_config_backup",
    "search_config_backups",
    "delete_config_backup",
    "delete_old_config_backups",
    "get_config_backup_summary",
    "create_compliance_profile",
    "get_compliance_profiles",
    "get_compliance_profile",
    "update_compliance_profile",
    "delete_compliance_profile",
    "create_compliance_assignment",
    "get_compliance_assignments",
    "get_compliance_assignment",
    "update_compliance_assignment",
    "delete_compliance_assignment",
    "get_compliance_assignments_due",
    "update_compliance_assignment_last_scan",
    "create_compliance_scan_result",
    "get_compliance_scan_results",
    "get_compliance_scan_result",
    "delete_compliance_scan_result",
    "delete_old_compliance_scan_results",
    "get_compliance_summary",
    "get_compliance_host_status",
    "create_risk_analysis",
    "get_risk_analyses",
    "get_risk_analysis",
    "approve_risk_analysis",
    "delete_risk_analysis",
    "get_risk_analysis_summary",
    "create_deployment",
    "get_deployments",
    "get_deployment",
    "update_deployment_status",
    "claim_deployment_for_execute",
    "delete_deployment",
    "get_deployment_summary",
    "create_deployment_checkpoint",
    "update_deployment_checkpoint",
    "get_deployment_checkpoints",
    "create_deployment_snapshot",
    "get_deployment_snapshots",
]

# ═════════════════════════════════════════════════════════════════════════════
# Topology Links
# ═════════════════════════════════════════════════════════════════════════════

async def upsert_topology_link(
    source_host_id: int,
    source_ip: str,
    source_interface: str,
    target_host_id: int | None,
    target_ip: str,
    target_device_name: str,
    target_interface: str,
    protocol: str = "cdp",
    target_platform: str = "",
) -> int:
    """Insert or replace a topology link (deduplicated by source+interfaces+target)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO topology_links
               (source_host_id, source_ip, source_interface,
                target_host_id, target_ip, target_device_name,
                target_interface, protocol, target_platform, discovered_at)
               VALUES (?,?,?,?,?,?,?,?,?, datetime('now'))
               ON CONFLICT(source_host_id, source_interface, target_device_name, target_interface)
               DO UPDATE SET
                   target_host_id = excluded.target_host_id,
                   target_ip = excluded.target_ip,
                   protocol = excluded.protocol,
                   target_platform = excluded.target_platform,
                   discovered_at = excluded.discovered_at""",
            (source_host_id, source_ip, source_interface,
             target_host_id, target_ip, target_device_name,
             target_interface, protocol, target_platform),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_topology_links(group_id: int | None = None) -> list[dict]:
    """Return topology links, optionally filtered by source host group."""
    db = await _dbcore.get_db(read_only=True)
    try:
        if group_id is not None:
            cursor = await db.execute(
                """SELECT tl.*, h.hostname AS source_hostname, h.device_type AS source_device_type,
                          h.status AS source_status, h.group_id AS source_group_id
                   FROM topology_links tl
                   JOIN hosts h ON tl.source_host_id = h.id
                   WHERE h.group_id = ?
                   ORDER BY tl.source_host_id, tl.source_interface""",
                (group_id,),
            )
        else:
            cursor = await db.execute(
                """SELECT tl.*, h.hostname AS source_hostname, h.device_type AS source_device_type,
                          h.status AS source_status, h.group_id AS source_group_id
                   FROM topology_links tl
                   JOIN hosts h ON tl.source_host_id = h.id
                   ORDER BY tl.source_host_id, tl.source_interface"""
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_topology_links_for_host(host_id: int) -> list[dict]:
    """Return all topology links where the given host is source or resolved target."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT tl.*, h.hostname AS source_hostname, h.device_type AS source_device_type,
                      h.status AS source_status, h.group_id AS source_group_id
               FROM topology_links tl
               JOIN hosts h ON tl.source_host_id = h.id
               WHERE tl.source_host_id = ? OR tl.target_host_id = ?
               ORDER BY tl.source_host_id, tl.source_interface""",
            (host_id, host_id),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_topology_links_for_host(host_id: int) -> int:
    """Delete all topology links where the given host is the source."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM topology_links WHERE source_host_id = ?", (host_id,)
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def replace_topology_links_for_host(host_id: int, links: list[dict]) -> int:
    """Replace all links sourced from a host in a single transaction.

    Batched alternative to delete_topology_links_for_host() + per-link
    upsert_topology_link(): one DELETE plus one executemany, and the old
    links never vanish without their replacements in a committed state.
    """
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "DELETE FROM topology_links WHERE source_host_id = ?", (host_id,)
        )
        if links:
            await db.executemany(
                """INSERT INTO topology_links
                   (source_host_id, source_ip, source_interface,
                    target_host_id, target_ip, target_device_name,
                    target_interface, protocol, target_platform, discovered_at)
                   VALUES (?,?,?,?,?,?,?,?,?, datetime('now'))
                   ON CONFLICT(source_host_id, source_interface, target_device_name, target_interface)
                   DO UPDATE SET
                       target_host_id = excluded.target_host_id,
                       target_ip = excluded.target_ip,
                       protocol = excluded.protocol,
                       target_platform = excluded.target_platform,
                       discovered_at = excluded.discovered_at""",
                [(link["source_host_id"], link["source_ip"], link["source_interface"],
                  link["target_host_id"], link["target_ip"], link["target_device_name"],
                  link["target_interface"], link["protocol"], link["target_platform"])
                 for link in links],
            )
        await db.commit()
        return len(links)
    finally:
        await db.close()


async def delete_all_topology_links() -> int:
    """Delete all topology links."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM topology_links")
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def resolve_topology_target_host_ids() -> int:
    """Match unresolved target_host_ids by looking up target_ip or target_device_name in hosts."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """UPDATE topology_links
               SET target_host_id = (
                   SELECT h.id FROM hosts h
                   WHERE h.ip_address = topology_links.target_ip
                      OR LOWER(h.hostname) = LOWER(topology_links.target_device_name)
                   LIMIT 1
               )
               WHERE target_host_id IS NULL
                 AND (target_ip != '' OR target_device_name != '')"""
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Interface Stats (utilization tracking)
# ═════════════════════════════════════════════════════════════════════════════

async def upsert_interface_stat(
    host_id: int,
    if_index: int,
    if_name: str,
    if_speed_mbps: int,
    in_octets: int,
    out_octets: int,
) -> int:
    """Insert or update interface counters, shifting current values to prev_*."""
    return await upsert_interface_stats_batch([
        (host_id, if_index, if_name, if_speed_mbps, in_octets, out_octets),
    ])


_UPSERT_INTERFACE_STAT_SQL = """
    INSERT INTO interface_stats
       (host_id, if_index, if_name, if_speed_mbps, in_octets, out_octets, polled_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(host_id, if_index)
       DO UPDATE SET
           if_name = excluded.if_name,
           if_speed_mbps = CASE WHEN excluded.if_speed_mbps > 0
                                THEN excluded.if_speed_mbps
                                ELSE interface_stats.if_speed_mbps END,
           prev_in_octets = interface_stats.in_octets,
           prev_out_octets = interface_stats.out_octets,
           prev_polled_at = interface_stats.polled_at,
           in_octets = excluded.in_octets,
           out_octets = excluded.out_octets,
           polled_at = excluded.polled_at
"""


async def upsert_interface_stats_batch(rows: list[tuple]) -> int:
    """Batch upsert interface counters for one or more interfaces."""
    if not rows:
        return 0
    db = await _dbcore.get_db()
    try:
        await db.executemany(_UPSERT_INTERFACE_STAT_SQL, rows)
        await db.commit()
        return len(rows)
    finally:
        await db.close()


async def get_interface_stats_for_host(host_id: int) -> list[dict]:
    """Return all interface stats for a host."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM interface_stats WHERE host_id = ? ORDER BY if_index",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_interface_stats_by_hosts(host_ids: list[int]) -> list[dict]:
    """Return interface stats for multiple hosts."""
    if not host_ids:
        return []
    db = await _dbcore.get_db(read_only=True)
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cursor = await db.execute(
            f"SELECT * FROM interface_stats WHERE host_id IN ({placeholders}) ORDER BY host_id, if_index",
            tuple(host_ids),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Interface inventory (audit: port-hygiene rule)
# ═════════════════════════════════════════════════════════════════════════════

async def upsert_interface_inventory(
    host_id: int,
    if_index: int,
    name: str,
    description: str,
    admin_state: str,
    oper_state: str,
    speed_mbps: int,
    duplex: str,
    last_change: str,
    access_vlan: int,
    trunk_vlans: str,
) -> int:
    """Insert or update one per-port inventory row. The (host_id, if_index)
    pair is unique so re-poll just refreshes the snapshot."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO interface_inventory
               (host_id, if_index, name, description, admin_state, oper_state,
                speed_mbps, duplex, last_change, access_vlan, trunk_vlans,
                collected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(host_id, if_index) DO UPDATE SET
                   name = excluded.name,
                   description = excluded.description,
                   admin_state = excluded.admin_state,
                   oper_state = excluded.oper_state,
                   speed_mbps = excluded.speed_mbps,
                   duplex = excluded.duplex,
                   last_change = excluded.last_change,
                   access_vlan = excluded.access_vlan,
                   trunk_vlans = excluded.trunk_vlans,
                   collected_at = excluded.collected_at""",
            (host_id, if_index, name, description, admin_state, oper_state,
             speed_mbps, duplex, last_change, access_vlan, trunk_vlans),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_interface_inventory_for_host(host_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM interface_inventory WHERE host_id = ? ORDER BY if_index",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_interface_inventory_by_name(host_id: int, name: str) -> dict | None:
    """Look up one port by host + interface name (used by VLAN-consistency
    and port-hygiene rules to cross-reference topology edges)."""
    if not name:
        return None
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM interface_inventory WHERE host_id = ? AND name = ? LIMIT 1",
            (host_id, name),
        )
        row = await cursor.fetchone()
        return rows_to_list([row])[0] if row else None
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# VLAN definitions (audit: vlan-consistency rule)
# ═════════════════════════════════════════════════════════════════════════════

async def upsert_vlan_definition(
    host_id: int,
    vlan_id: int,
    name: str,
    state: str,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO vlan_definitions
               (host_id, vlan_id, name, state, collected_at)
               VALUES (?, ?, ?, ?, datetime('now'))
               ON CONFLICT(host_id, vlan_id) DO UPDATE SET
                   name = excluded.name,
                   state = excluded.state,
                   collected_at = excluded.collected_at""",
            (host_id, vlan_id, name, state),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_vlan_definitions_for_host(host_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM vlan_definitions WHERE host_id = ? ORDER BY vlan_id",
            (host_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Topology Changes (diff detection)
# ═════════════════════════════════════════════════════════════════════════════

async def insert_topology_change(
    change_type: str,
    source_host_id: int | None,
    source_hostname: str = "",
    source_interface: str = "",
    target_device_name: str = "",
    target_interface: str = "",
    target_ip: str = "",
    protocol: str = "",
) -> int:
    """Record a topology change (added/removed link)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO topology_changes
               (change_type, source_host_id, source_hostname, source_interface,
                target_device_name, target_interface, target_ip, protocol, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (change_type, source_host_id, source_hostname, source_interface,
             target_device_name, target_interface, target_ip, protocol),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_topology_changes(unacknowledged_only: bool = False,
                               limit: int = 100) -> list[dict]:
    """Return recent topology changes."""
    db = await _dbcore.get_db()
    try:
        where = "WHERE acknowledged = 0" if unacknowledged_only else ""
        cursor = await db.execute(
            f"SELECT * FROM topology_changes {where} ORDER BY detected_at DESC LIMIT ?",
            (limit,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_topology_changes_count(unacknowledged_only: bool = True) -> int:
    """Return count of topology changes."""
    db = await _dbcore.get_db()
    try:
        where = "WHERE acknowledged = 0" if unacknowledged_only else ""
        cursor = await db.execute(
            f"SELECT COUNT(*) FROM topology_changes {where}"
        )
        row = await cursor.fetchone()
        return row[0] if row else 0
    finally:
        await db.close()


async def acknowledge_topology_changes() -> int:
    """Mark all unacknowledged changes as acknowledged."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE topology_changes SET acknowledged = 1 WHERE acknowledged = 0"
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def delete_old_topology_changes(days: int = 30) -> int:
    """Delete topology changes older than N days."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM topology_changes WHERE detected_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# STP Topology State + Events
# ═════════════════════════════════════════════════════════════════════════════

async def upsert_stp_port_state(
    host_id: int,
    vlan_id: int,
    bridge_port: int,
    if_index: int,
    interface_name: str,
    port_state: str,
    port_role: str,
    designated_bridge_id: str,
    root_bridge_id: str,
    root_port: int,
    topology_change_count: int,
    time_since_topology_change: int,
    is_root_bridge: bool,
) -> int:
    """Insert or update one STP port-state row for a host/VLAN/bridge-port."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO stp_port_states
               (host_id, vlan_id, bridge_port, if_index, interface_name,
                port_state, port_role, designated_bridge_id, root_bridge_id,
                root_port, topology_change_count, time_since_topology_change,
                is_root_bridge, collected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(host_id, vlan_id, bridge_port)
               DO UPDATE SET
                   if_index = excluded.if_index,
                   interface_name = excluded.interface_name,
                   port_state = excluded.port_state,
                   port_role = excluded.port_role,
                   designated_bridge_id = excluded.designated_bridge_id,
                   root_bridge_id = excluded.root_bridge_id,
                   root_port = excluded.root_port,
                   topology_change_count = excluded.topology_change_count,
                   time_since_topology_change = excluded.time_since_topology_change,
                   is_root_bridge = excluded.is_root_bridge,
                   collected_at = excluded.collected_at""",
            (
                host_id, vlan_id, bridge_port, if_index, interface_name,
                port_state, port_role, designated_bridge_id, root_bridge_id,
                root_port, topology_change_count, time_since_topology_change,
                1 if is_root_bridge else 0,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def delete_stp_port_states_for_host(host_id: int, vlan_id: int | None = None) -> int:
    """Delete STP port states for a host, optionally restricted to one VLAN."""
    db = await _dbcore.get_db()
    try:
        if vlan_id is None:
            cursor = await db.execute(
                "DELETE FROM stp_port_states WHERE host_id = ?",
                (host_id,),
            )
        else:
            cursor = await db.execute(
                "DELETE FROM stp_port_states WHERE host_id = ? AND vlan_id = ?",
                (host_id, vlan_id),
            )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_stp_port_states(
    group_id: int | None = None,
    host_id: int | None = None,
    vlan_id: int | None = None,
    limit: int = 5000,
) -> list[dict]:
    """Return latest STP port states joined with host metadata."""
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if group_id is not None:
            clauses.append("h.group_id = ?")
            params.append(group_id)
        if host_id is not None:
            clauses.append("s.host_id = ?")
            params.append(host_id)
        if vlan_id is not None:
            clauses.append("s.vlan_id = ?")
            params.append(vlan_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(int(limit), 20000)))

        cursor = await db.execute(
            f"""SELECT s.*, h.hostname, h.ip_address, h.group_id
                FROM stp_port_states s
                JOIN hosts h ON h.id = s.host_id
                {where_sql}
                ORDER BY s.collected_at DESC, s.host_id, s.vlan_id, s.bridge_port
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def insert_stp_topology_event(
    host_id: int,
    vlan_id: int,
    event_type: str,
    severity: str = "warning",
    interface_name: str = "",
    details: str = "",
    old_value: str = "",
    new_value: str = "",
) -> int:
    """Record an STP event (root change, topology change, port-state change)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO stp_topology_events
               (host_id, vlan_id, event_type, severity, interface_name,
                details, old_value, new_value, acknowledged, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, datetime('now'))""",
            (
                host_id, vlan_id, event_type, severity, interface_name,
                details, old_value, new_value,
            ),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_stp_topology_events(
    unacknowledged_only: bool = True,
    limit: int = 200,
) -> list[dict]:
    """Return STP events newest-first with host context."""
    db = await _dbcore.get_db()
    try:
        where_sql = "WHERE e.acknowledged = 0" if unacknowledged_only else ""
        cursor = await db.execute(
            f"""SELECT e.*, h.hostname, h.ip_address
                FROM stp_topology_events e
                JOIN hosts h ON h.id = e.host_id
                {where_sql}
                ORDER BY e.created_at DESC, e.id DESC
                LIMIT ?""",
            (max(1, min(int(limit), 5000)),),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_stp_topology_events_count(unacknowledged_only: bool = True) -> int:
    """Return count of STP events."""
    db = await _dbcore.get_db()
    try:
        where_sql = "WHERE acknowledged = 0" if unacknowledged_only else ""
        cursor = await db.execute(
            f"SELECT COUNT(*) FROM stp_topology_events {where_sql}"
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0
    finally:
        await db.close()


async def acknowledge_stp_topology_events() -> int:
    """Mark all unacknowledged STP events as acknowledged."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE stp_topology_events SET acknowledged = 1 WHERE acknowledged = 0"
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def count_recent_stp_topology_events(
    host_id: int,
    vlan_id: int,
    event_type: str,
    within_minutes: int = 30,
    max_rows: int = 500,
) -> int:
    """Count STP events of a type for host/VLAN inside a recent time window."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT created_at
               FROM stp_topology_events
               WHERE host_id = ?
                 AND vlan_id = ?
                 AND event_type = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (
                host_id,
                vlan_id,
                event_type,
                max(1, min(int(max_rows), 5000)),
            ),
        )
        rows = await cursor.fetchall()
        if not rows:
            return 0

        now = datetime.now(UTC)
        cutoff_seconds = max(1, int(within_minutes)) * 60
        count = 0

        for row in rows:
            created_raw = row[0] if isinstance(row, (list, tuple)) else row["created_at"]
            if not created_raw:
                continue
            created_text = str(created_raw).replace(" ", "T")
            try:
                dt = datetime.fromisoformat(created_text)
            except Exception:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            if (now - dt).total_seconds() <= cutoff_seconds:
                count += 1
            else:
                # Rows are ordered newest-first; once outside window, remaining rows will be older.
                break

        return count
    finally:
        await db.close()


# ── STP Root-Bridge Policies ─────────────────────────────────────────────────

async def upsert_stp_root_policy(
    group_id: int,
    vlan_id: int,
    expected_root_bridge_id: str,
    expected_root_hostname: str = "",
    enabled: bool = True,
) -> int:
    """Upsert expected STP root-bridge policy for one inventory group/VLAN."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """INSERT INTO stp_root_policies
               (group_id, vlan_id, expected_root_bridge_id, expected_root_hostname,
                enabled, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
               ON CONFLICT(group_id, vlan_id)
               DO UPDATE SET
                   expected_root_bridge_id = excluded.expected_root_bridge_id,
                   expected_root_hostname = excluded.expected_root_hostname,
                   enabled = excluded.enabled,
                   updated_at = datetime('now')""",
            (
                int(group_id),
                int(vlan_id),
                str(expected_root_bridge_id or "").strip(),
                str(expected_root_hostname or "").strip(),
                1 if enabled else 0,
            ),
        )
        await db.commit()

        cursor = await db.execute(
            """SELECT id
               FROM stp_root_policies
               WHERE group_id = ? AND vlan_id = ?""",
            (int(group_id), int(vlan_id)),
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0
    finally:
        await db.close()


async def get_stp_root_policy(group_id: int, vlan_id: int) -> dict | None:
    """Return one STP root policy for group/VLAN, or None when absent."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*, g.name AS group_name
               FROM stp_root_policies p
               JOIN inventory_groups g ON g.id = p.group_id
               WHERE p.group_id = ? AND p.vlan_id = ?
               LIMIT 1""",
            (int(group_id), int(vlan_id)),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        rows = rows_to_list([row])
        return rows[0] if rows else None
    finally:
        await db.close()


async def get_stp_root_policies(
    group_id: int | None = None,
    vlan_id: int | None = None,
    enabled_only: bool = False,
    limit: int = 2000,
) -> list[dict]:
    """Return STP root-bridge policies with inventory group context."""
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []

        if group_id is not None:
            clauses.append("p.group_id = ?")
            params.append(int(group_id))
        if vlan_id is not None:
            clauses.append("p.vlan_id = ?")
            params.append(int(vlan_id))
        if enabled_only:
            clauses.append("p.enabled = 1")

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(int(limit), 10000)))

        cursor = await db.execute(
            f"""SELECT p.*, g.name AS group_name
                FROM stp_root_policies p
                JOIN inventory_groups g ON g.id = p.group_id
                {where_sql}
                ORDER BY p.group_id, p.vlan_id, p.id
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_stp_root_policy(policy_id: int) -> int:
    """Delete one STP root policy by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM stp_root_policies WHERE id = ?",
            (int(policy_id),),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Topology Node Positions ──────────────────────────────────────────────────

async def get_topology_positions() -> dict:
    """Return all saved node positions as {node_id: {x, y}}."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT node_id, x, y FROM topology_node_positions")
        rows = await cursor.fetchall()
        return {row[0]: {"x": row[1], "y": row[2]} for row in rows}
    finally:
        await db.close()


async def save_topology_positions(positions: dict) -> int:
    """Upsert node positions. positions = {node_id: {x, y} | null}.
    A null value deletes that node's saved position (unpin)."""
    if not positions:
        return 0
    db = await _dbcore.get_db()
    try:
        count = 0
        for node_id, pos in positions.items():
            if pos is None:
                # Delete this node's position (unpin)
                await db.execute(
                    "DELETE FROM topology_node_positions WHERE node_id = ?",
                    (str(node_id),),
                )
            else:
                await db.execute(
                    """INSERT INTO topology_node_positions (node_id, x, y, updated_at)
                       VALUES (?, ?, ?, datetime('now'))
                       ON CONFLICT(node_id) DO UPDATE SET
                           x = excluded.x,
                           y = excluded.y,
                           updated_at = datetime('now')""",
                    (str(node_id), pos["x"], pos["y"]),
                )
            count += 1
        await db.commit()
        return count
    finally:
        await db.close()


async def delete_topology_positions() -> int:
    """Delete all saved node positions."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM topology_node_positions")
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Config Baselines ─────────────────────────────────────────────────────────


async def create_config_baseline(
    host_id: int,
    name: str = "",
    config_text: str = "",
    source: str = "manual",
    created_by: str = "",
) -> int:
    """Create or replace a config baseline for a host."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_baselines
               (host_id, name, config_text, source, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
               ON CONFLICT(host_id) DO UPDATE SET
                   name = excluded.name,
                   config_text = excluded.config_text,
                   source = excluded.source,
                   updated_at = datetime('now')""",
            (host_id, name, config_text, source, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_baseline(baseline_id: int) -> dict | None:
    """Return a single config baseline by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM config_baselines WHERE id = ?", (baseline_id,)
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def get_config_baseline_for_host(host_id: int) -> dict | None:
    """Return the config baseline for a specific host."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM config_baselines WHERE host_id = ?", (host_id,)
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def get_config_baselines(
    host_id: int | None = None,
    limit: int = 200,
) -> list[dict]:
    """Return config baselines, optionally filtered by host_id."""
    db = await _dbcore.get_db()
    try:
        if host_id is not None:
            cursor = await db.execute(
                """SELECT b.*, h.hostname, h.ip_address
                   FROM config_baselines b
                   JOIN hosts h ON h.id = b.host_id
                   WHERE b.host_id = ?
                   ORDER BY b.updated_at DESC LIMIT ?""",
                (host_id, limit),
            )
        else:
            cursor = await db.execute(
                """SELECT b.*, h.hostname, h.ip_address
                   FROM config_baselines b
                   JOIN hosts h ON h.id = b.host_id
                   ORDER BY b.updated_at DESC LIMIT ?""",
                (limit,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_baselined_host_ids(limit: int = 200) -> list[int]:
    """Return just the host_ids that have a config baseline (newest first).

    The drift-check loop only needs the ids to fan out per-host analysis;
    get_config_baselines() pulls every baseline's full config_text blob, which
    is wasted I/O when the caller discards everything but host_id.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT host_id FROM config_baselines ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        )
        return [row[0] for row in await cursor.fetchall()]
    finally:
        await db.close()


async def update_config_baseline(
    baseline_id: int,
    name: str | None = None,
    config_text: str | None = None,
    source: str | None = None,
) -> None:
    """Update fields on a config baseline."""
    db = await _dbcore.get_db()
    try:
        parts: list[str] = []
        params: list = []
        if name is not None:
            parts.append("name = ?")
            params.append(name)
        if config_text is not None:
            parts.append("config_text = ?")
            params.append(config_text)
        if source is not None:
            parts.append("source = ?")
            params.append(source)
        if not parts:
            return
        parts.append("updated_at = datetime('now')")
        params.append(baseline_id)
        await db.execute(
            f"UPDATE config_baselines SET {', '.join(parts)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_config_baseline(baseline_id: int) -> None:
    """Delete a config baseline."""
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM config_baselines WHERE id = ?", (baseline_id,))
        await db.commit()
    finally:
        await db.close()


# ── Config Snapshots ─────────────────────────────────────────────────────────


async def create_config_snapshot(
    host_id: int,
    config_text: str,
    capture_method: str = "manual",
) -> int:
    """Store a running-config snapshot for a host."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_snapshots (host_id, config_text, capture_method, captured_at)
               VALUES (?, ?, ?, datetime('now'))""",
            (host_id, config_text, capture_method),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_snapshot(snapshot_id: int) -> dict | None:
    """Return a single config snapshot by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM config_snapshots WHERE id = ?", (snapshot_id,)
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def get_config_snapshots_by_ids(snapshot_ids: list[int]) -> list[dict]:
    """Return config snapshots (including config_text) for a set of IDs in one query."""
    if not snapshot_ids:
        return []
    db = await _dbcore.get_db()
    try:
        placeholders = ",".join("?" for _ in snapshot_ids)
        cursor = await db.execute(
            f"SELECT * FROM config_snapshots WHERE id IN ({placeholders})",
            tuple(snapshot_ids),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_config_snapshots_for_host(
    host_id: int, limit: int = 50
) -> list[dict]:
    """Return config snapshots for a host, newest first."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT id, host_id, capture_method, captured_at,
                      LENGTH(config_text) as config_length
               FROM config_snapshots
               WHERE host_id = ?
               ORDER BY captured_at DESC LIMIT ?""",
            (host_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_latest_config_snapshot(host_id: int) -> dict | None:
    """Return the most recent snapshot for a host."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM config_snapshots
               WHERE host_id = ?
               ORDER BY id DESC LIMIT 1""",
            (host_id,),
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def delete_config_snapshot(snapshot_id: int) -> None:
    """Delete a config snapshot."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "DELETE FROM config_snapshots WHERE id = ?", (snapshot_id,)
        )
        await db.commit()
    finally:
        await db.close()


async def delete_old_config_snapshots(days: int = 90) -> int:
    """Delete config snapshots older than N days."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM config_snapshots WHERE captured_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Config Drift Events ──────────────────────────────────────────────────────


async def create_config_drift_event(
    host_id: int,
    snapshot_id: int,
    baseline_id: int | None,
    diff_text: str,
    diff_lines_added: int = 0,
    diff_lines_removed: int = 0,
) -> int:
    """Record a detected configuration drift event."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_drift_events
               (host_id, snapshot_id, baseline_id, diff_text,
                diff_lines_added, diff_lines_removed, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
            (host_id, snapshot_id, baseline_id, diff_text,
             diff_lines_added, diff_lines_removed),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def create_config_drift_event_history(
    event_id: int,
    host_id: int,
    action: str,
    from_status: str = "",
    to_status: str = "",
    actor: str = "",
    details: str = "",
) -> int:
    """Append a history/log entry for a drift event lifecycle action."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_drift_event_history
               (event_id, host_id, action, from_status, to_status, actor, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (event_id, host_id, action, from_status, to_status, actor, details),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_drift_event_history(event_id: int, limit: int = 200) -> list[dict]:
    """Return history entries for a drift event (newest first)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT h.id, h.event_id, h.host_id, h.action, h.from_status, h.to_status,
                      h.actor, h.details, h.created_at,
                      d.status AS current_status,
                      host.hostname, host.ip_address
               FROM config_drift_event_history h
               JOIN config_drift_events d ON d.id = h.event_id
               LEFT JOIN hosts host ON host.id = h.host_id
               WHERE h.event_id = ?
               ORDER BY h.created_at DESC, h.id DESC
               LIMIT ?""",
            (event_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_config_drift_event(event_id: int) -> dict | None:
    """Return a single drift event with host info."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT e.*, h.hostname, h.ip_address, h.device_type
               FROM config_drift_events e
               JOIN hosts h ON h.id = e.host_id
               WHERE e.id = ?""",
            (event_id,),
        )
        row = await cursor.fetchone()
        return row_to_dict(row)
    finally:
        await db.close()


async def get_config_drift_events_by_ids(event_ids: list[int]) -> list[dict]:
    """Return drift events (with host info) for a set of IDs in one query."""
    if not event_ids:
        return []
    db = await _dbcore.get_db()
    try:
        placeholders = ",".join("?" for _ in event_ids)
        cursor = await db.execute(
            f"""SELECT e.*, h.hostname, h.ip_address, h.device_type
                FROM config_drift_events e
                JOIN hosts h ON h.id = e.host_id
                WHERE e.id IN ({placeholders})""",
            tuple(event_ids),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_config_drift_events(
    status: str | None = None,
    host_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """Return drift events with optional filters."""
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if status:
            clauses.append("e.status = ?")
            params.append(status)
        if host_id is not None:
            clauses.append("e.host_id = ?")
            params.append(host_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT e.id, e.host_id, e.snapshot_id, e.baseline_id,
                       e.status, e.diff_text, e.diff_lines_added, e.diff_lines_removed,
                       e.detected_at, e.resolved_at, e.resolved_by,
                       h.hostname, h.ip_address, h.device_type
                FROM config_drift_events e
                JOIN hosts h ON h.id = e.host_id
                {where}
                ORDER BY e.detected_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_config_drift_summary() -> dict:
    """Return drift summary stats."""
    db = await _dbcore.get_db()
    try:
        # Count hosts with baselines
        cursor = await db.execute(
            "SELECT COUNT(*) FROM config_baselines"
        )
        row = await cursor.fetchone()
        total_baselined = row[0] if row else 0

        # Count hosts with open drift events
        cursor = await db.execute(
            "SELECT COUNT(DISTINCT host_id) FROM config_drift_events WHERE status = 'open'"
        )
        row = await cursor.fetchone()
        drifted = row[0] if row else 0

        # Count open events
        cursor = await db.execute(
            "SELECT COUNT(*) FROM config_drift_events WHERE status = 'open'"
        )
        row = await cursor.fetchone()
        open_events = row[0] if row else 0

        # Count accepted events
        cursor = await db.execute(
            "SELECT COUNT(*) FROM config_drift_events WHERE status = 'accepted'"
        )
        row = await cursor.fetchone()
        accepted_events = row[0] if row else 0

        return {
            "total_baselined": total_baselined,
            "compliant": max(0, total_baselined - drifted),
            "drifted": drifted,
            "open_events": open_events,
            "accepted_events": accepted_events,
        }
    finally:
        await db.close()


async def update_config_drift_event_status(
    event_id: int, status: str, resolved_by: str = ""
) -> None:
    """Update drift event status (open/resolved/accepted)."""
    db = await _dbcore.get_db()
    try:
        if status in ("resolved", "accepted"):
            await db.execute(
                """UPDATE config_drift_events
                   SET status = ?, resolved_at = datetime('now'), resolved_by = ?
                   WHERE id = ?""",
                (status, resolved_by, event_id),
            )
        else:
            await db.execute(
                "UPDATE config_drift_events SET status = ? WHERE id = ?",
                (status, event_id),
            )
        await db.commit()
    finally:
        await db.close()


async def delete_old_config_drift_events(days: int = 90) -> int:
    """Delete drift events older than N days."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM config_drift_events WHERE detected_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ── Config Backup Policies ──────────────────────────────────────────────────


async def create_config_backup_policy(
    name: str,
    group_id: int,
    credential_id: int,
    interval_seconds: int = 86400,
    retention_days: int = 30,
    created_by: str = "",
) -> int:
    """Create a new config backup policy."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_backup_policies
               (name, group_id, credential_id, interval_seconds, retention_days, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            (name, group_id, credential_id, interval_seconds, retention_days, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_config_backup_policies(group_id: int | None = None) -> list[dict]:
    """List all backup policies, optionally filtered by group."""
    db = await _dbcore.get_db()
    try:
        if group_id is not None:
            cursor = await db.execute(
                """SELECT p.*, g.name as group_name,
                          (SELECT COUNT(*) FROM hosts WHERE group_id = p.group_id) as host_count
                   FROM config_backup_policies p
                   LEFT JOIN inventory_groups g ON g.id = p.group_id
                   WHERE p.group_id = ?
                   ORDER BY p.name""",
                (group_id,),
            )
        else:
            cursor = await db.execute(
                """SELECT p.*, g.name as group_name,
                          (SELECT COUNT(*) FROM hosts WHERE group_id = p.group_id) as host_count
                   FROM config_backup_policies p
                   LEFT JOIN inventory_groups g ON g.id = p.group_id
                   ORDER BY p.name"""
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_config_backup_policy(policy_id: int) -> dict | None:
    """Get a single backup policy by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*, g.name as group_name,
                      (SELECT COUNT(*) FROM hosts WHERE group_id = p.group_id) as host_count
               FROM config_backup_policies p
               LEFT JOIN inventory_groups g ON g.id = p.group_id
               WHERE p.id = ?""",
            (policy_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_config_backup_policy(policy_id: int, **kwargs) -> None:
    """Update a backup policy. Pass only the fields to change."""
    allowed = {"name", "enabled", "credential_id", "interval_seconds", "retention_days"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return
    updates["updated_at"] = "datetime('now')"
    sets = []
    params = []
    for k, v in updates.items():
        if k == "updated_at":
            sets.append("updated_at = datetime('now')")
        else:
            sets.append(f"{k} = ?")
            params.append(v)
    sql, sql_params = _safe_dynamic_update("config_backup_policies", sets, params, "id = ?", policy_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
    finally:
        await db.close()


async def delete_config_backup_policy(policy_id: int) -> None:
    """Delete a backup policy."""
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM config_backup_policies WHERE id = ?", (policy_id,))
        await db.commit()
    finally:
        await db.close()


async def get_config_backup_policies_due() -> list[dict]:
    """Get enabled policies that are due for a backup run."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*, g.name as group_name
               FROM config_backup_policies p
               LEFT JOIN inventory_groups g ON g.id = p.group_id
               WHERE p.enabled = 1
                 AND (p.last_run_at IS NULL
                      OR datetime(p.last_run_at, '+' || p.interval_seconds || ' seconds') < datetime('now'))"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def update_config_backup_policy_last_run(policy_id: int) -> None:
    """Mark a policy as just having been run."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE config_backup_policies SET last_run_at = datetime('now') WHERE id = ?",
            (policy_id,),
        )
        await db.commit()
    finally:
        await db.close()


# ── Config Backups ───────────────────────────────────────────────────────────


_CONFIG_BACKUP_SEARCH_MODES = {"fulltext", "substring", "regex"}


def _normalize_config_backup_search_mode(mode: str) -> str:
    normalized = (mode or "fulltext").strip().lower() or "fulltext"
    if normalized not in _CONFIG_BACKUP_SEARCH_MODES:
        raise ValueError("invalid_mode")
    return normalized


_CONFIG_BACKUP_REGEX_MAX_LEN = 512


def _has_redos_shape(pattern: str) -> bool:
    """Single-pass O(n) scan that flags catastrophic-backtracking shapes.

    Detects: (1) a quantifier (+, *, {n,}) immediately following a closing
    group paren - i.e. (...)+ / (...)* - when the group itself contains a
    quantifier or top-level alternation. This covers (a+)+, (a*)*, (a|b)+,
    (a|a)*, etc. Uses no regex (would itself be ReDoS-prone) and does no
    backtracking.
    """
    depth = 0
    # Track per-depth: does this group contain an inner quantifier or '|'?
    has_quant = [False]
    has_alt = [False]
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "(":
            depth += 1
            has_quant.append(False)
            has_alt.append(False)
        elif ch == ")":
            inner_quant = has_quant.pop() if len(has_quant) > 1 else False
            inner_alt = has_alt.pop() if len(has_alt) > 1 else False
            depth = max(0, depth - 1)
            # Look ahead for an outer quantifier on this group
            j = i + 1
            outer_quant = False
            if j < n and pattern[j] in "+*":
                outer_quant = True
            elif j < n and pattern[j] == "{":
                outer_quant = True
            if outer_quant and (inner_quant or inner_alt):
                return True
        elif ch in "+*" and depth >= 0:
            has_quant[-1] = True
        elif ch == "|":
            has_alt[-1] = True
        i += 1
    return False


def _compile_config_backup_regex(pattern: str) -> re.Pattern:
    """Compile a user-supplied regex with bounds, raising ValueError('invalid_regex') on failure."""
    if pattern is None or len(pattern) > _CONFIG_BACKUP_REGEX_MAX_LEN:
        raise ValueError("invalid_regex")
    if _has_redos_shape(pattern):
        raise ValueError("invalid_regex")
    try:
        # Safe despite py/regex-injection: pattern is length-bounded, screened
        # for catastrophic-backtracking shapes, and only reachable by admins.
        # The CodeQL alert is dismissed ("won't fix") in the Security tab -
        # inline comments do not suppress GitHub code scanning alerts.
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError("invalid_regex") from exc


_CONFIG_BACKUP_REGEX_MIN_LITERAL = 3

# Escaped alphanumerics are class shorthands / anchors / backrefs, never literals.
_REGEX_NON_LITERAL_ESCAPES = frozenset(
    "dDwWsSbBAZ0123456789nrtvfaux"
)


def _regex_required_literal(pattern: str) -> str:
    """Longest literal substring every match of `pattern` must contain.

    Single-pass scanner in the style of _has_redos_shape (no regex, no
    backtracking). Conservative: group contents, classes, wildcards, and
    class-shorthand escapes break literal runs; a quantifier keeps its
    atom only when the minimum repeat is >= 1; a top-level alternation
    means nothing is required, so the result is ''. Used to derive a cheap
    substring pre-filter for regex-mode backup search.
    """
    runs: list[str] = []
    cur: list[str] = []
    depth = 0
    i = 0
    n = len(pattern)

    def _end_run() -> None:
        if cur:
            runs.append("".join(cur))
            cur.clear()

    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                _end_run()
                break
            nxt = pattern[i + 1]
            i += 2
            if depth == 0:
                if nxt in _REGEX_NON_LITERAL_ESCAPES:
                    _end_run()
                else:
                    cur.append(nxt)
            continue
        if ch == "[":
            _end_run()
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1
            continue
        if ch == "(":
            _end_run()
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            if ch == "|":
                return ""  # top-level alternation: no substring is required
            if ch in "*+?{":
                if ch == "{":
                    j = i
                    while j < n and pattern[j] != "}":
                        j += 1
                    min_part = pattern[i + 1 : j].split(",", 1)[0].strip()
                    if cur and not (min_part.isdigit() and int(min_part) >= 1):
                        cur.pop()
                    i = j
                elif ch in "*?" and cur:
                    cur.pop()
                _end_run()
            elif ch in ".^$":
                _end_run()
            else:
                cur.append(ch)
        i += 1
    _end_run()
    return max(runs, key=len, default="")


def _build_sqlite_fts_query(search_query: str) -> str:
    tokens = [tok for tok in re.findall(r"[A-Za-z0-9_.:/-]+", search_query or "") if tok]
    if not tokens:
        escaped = (search_query or "").replace('"', '""')
        return f'"{escaped}"'
    return " AND ".join(f'"{tok.replace(chr(34), chr(34) + chr(34))}"' for tok in tokens[:10])


def _extract_config_backup_match_context(
    config_text: str,
    search_query: str,
    *,
    mode: str,
    context_lines: int = 1,
    compiled_regex: re.Pattern | None = None,
) -> dict | None:
    lines = (config_text or "").splitlines()
    if not lines:
        return None

    mode = _normalize_config_backup_search_mode(mode)
    match_idx: int | None = None

    if mode == "regex":
        regex = compiled_regex
        if regex is None:
            try:
                regex = _compile_config_backup_regex(search_query)
            except ValueError:
                return None
        for idx, line in enumerate(lines):
            if regex.search(line):
                match_idx = idx
                break
    elif mode == "substring":
        needle = (search_query or "").lower()
        if not needle:
            return None
        for idx, line in enumerate(lines):
            if needle in line.lower():
                match_idx = idx
                break
    else:  # fulltext
        tokens = [tok.lower() for tok in re.findall(r"[A-Za-z0-9_.:/-]+", search_query or "") if tok]
        if not tokens:
            tokens = [(search_query or "").strip().lower()]
        tokens = [tok for tok in tokens if tok]
        if not tokens:
            return None
        for idx, line in enumerate(lines):
            lowered = line.lower()
            if any(tok in lowered for tok in tokens):
                match_idx = idx
                break

    if match_idx is None:
        return None

    radius = max(0, min(int(context_lines), 5))
    start = max(0, match_idx - radius)
    end = min(len(lines), match_idx + radius + 1)
    before_lines = lines[start:match_idx]
    match_line = lines[match_idx]
    after_lines = lines[match_idx + 1:end]
    context_text = "\n".join(before_lines + [match_line] + after_lines)
    return {
        "line_number": match_idx + 1,
        "match_line": match_line,
        "before_lines": before_lines,
        "after_lines": after_lines,
        "context_text": context_text,
    }


async def create_config_backup(
    policy_id: int | None,
    host_id: int,
    config_text: str,
    capture_method: str = "scheduled",
    status: str = "success",
    error_message: str = "",
) -> int:
    """Store a config backup record."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO config_backups
               (policy_id, host_id, config_text, capture_method, status, error_message, captured_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
            (policy_id, host_id, config_text, capture_method, status, error_message),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_latest_config_backup(policy_id: int, host_id: int) -> dict | None:
    """Get the most recent successful backup for a policy+host, including config_text."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT id, config_text FROM config_backups
               WHERE policy_id = ? AND host_id = ? AND status = 'success'
               ORDER BY captured_at DESC LIMIT 1""",
            (policy_id, host_id),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_config_backups(
    host_id: int | None = None,
    policy_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """List backups with host info, optionally filtered."""
    db = await _dbcore.get_db()
    try:
        conditions = []
        params: list = []
        if host_id is not None:
            conditions.append("b.host_id = ?")
            params.append(host_id)
        if policy_id is not None:
            conditions.append("b.policy_id = ?")
            params.append(policy_id)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT b.id, b.policy_id, b.host_id, b.capture_method, b.status,
                       b.error_message, b.captured_at, LENGTH(b.config_text) as config_length,
                       h.hostname, h.ip_address, h.device_type
                FROM config_backups b
                LEFT JOIN hosts h ON h.id = b.host_id
                {where}
                ORDER BY b.captured_at DESC LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_latest_config_backups_per_host() -> list[dict]:
    """Return the most recent backup row for each host (dashboard rollup)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT b.id, b.policy_id, b.host_id, b.capture_method, b.status,
                      b.error_message, b.captured_at, LENGTH(b.config_text) as config_length,
                      h.hostname, h.ip_address, h.device_type
               FROM config_backups b
               INNER JOIN (
                   SELECT host_id, MAX(id) AS max_id
                   FROM config_backups
                   WHERE host_id IS NOT NULL
                   GROUP BY host_id
               ) latest ON b.id = latest.max_id
               LEFT JOIN hosts h ON h.id = b.host_id
               ORDER BY h.hostname"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_config_backup(backup_id: int) -> dict | None:
    """Get a single backup record including config text."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT b.*, h.hostname, h.ip_address, h.device_type
               FROM config_backups b
               LEFT JOIN hosts h ON h.id = b.host_id
               WHERE b.id = ?""",
            (backup_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_previous_successful_config_backup(backup_id: int) -> dict | None:
    """Return the previous successful backup for the same host as backup_id."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT prev.id, prev.policy_id, prev.host_id, prev.capture_method, prev.status,
                      prev.error_message, prev.captured_at, prev.config_text,
                      h.hostname, h.ip_address, h.device_type
               FROM config_backups cur
               JOIN config_backups prev ON prev.host_id = cur.host_id
               LEFT JOIN hosts h ON h.id = prev.host_id
               WHERE cur.id = ?
                 AND cur.status = 'success'
                 AND prev.status = 'success'
                 AND (
                    prev.captured_at < cur.captured_at OR
                    (prev.captured_at = cur.captured_at AND prev.id < cur.id)
                 )
               ORDER BY prev.captured_at DESC, prev.id DESC
               LIMIT 1""",
            (backup_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def search_config_backups(
    search_query: str,
    *,
    mode: str = "fulltext",
    limit: int = 50,
    context_lines: int = 1,
) -> dict:
    """Search backed-up configurations and return contextual matches."""
    query = (search_query or "").strip()
    requested_mode = _normalize_config_backup_search_mode(mode)
    row_limit = max(1, min(int(limit), 200))

    if not query:
        return {
            "query": "",
            "requested_mode": requested_mode,
            "mode": requested_mode,
            "limit": row_limit,
            "count": 0,
            "has_more": False,
            "results": [],
        }

    effective_mode = requested_mode
    context_radius = max(0, min(int(context_lines), 5))

    compiled_regex = None
    if requested_mode == "regex":
        compiled_regex = _compile_config_backup_regex(query)

    base_select = """
        SELECT b.id, b.policy_id, b.host_id, b.capture_method, b.status,
               b.error_message, b.captured_at, b.config_text,
               h.hostname, h.ip_address, h.device_type
        FROM config_backups b
        LEFT JOIN hosts h ON h.id = b.host_id
    """
    cursor = None
    db = await _dbcore.get_db()
    try:
        if requested_mode == "fulltext":
            if _dbcore.DB_ENGINE == "postgres":
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                          AND to_tsvector('simple', COALESCE(b.config_text, ''))
                              @@ plainto_tsquery('simple', ?)
                        ORDER BY b.captured_at DESC, b.id DESC""",
                    (query,),
                )
            else:
                fts_query = _build_sqlite_fts_query(query)
                try:
                    cursor = await db.execute(
                        f"""{base_select}
                            JOIN config_backups_fts fts ON fts.rowid = b.id
                            WHERE b.status = 'success'
                              AND fts.config_backups_fts MATCH ?
                            ORDER BY b.captured_at DESC, b.id DESC""",
                        (fts_query,),
                    )
                except Exception:
                    effective_mode = "substring"

        if cursor is None and effective_mode == "substring":
            if _dbcore.DB_ENGINE == "postgres":
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                          AND POSITION(LOWER(?) IN LOWER(COALESCE(b.config_text, ''))) > 0
                        ORDER BY b.captured_at DESC, b.id DESC""",
                    (query,),
                )
            else:
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                          AND instr(LOWER(COALESCE(b.config_text, '')), LOWER(?)) > 0
                        ORDER BY b.captured_at DESC, b.id DESC""",
                    (query,),
                )

        if cursor is None and effective_mode == "regex":
            # Cheap substring pre-filter so regex search never full-scans
            # (SQLite would otherwise load every blob into Python). Patterns
            # with no required literal must use substring/fulltext instead.
            literal = _regex_required_literal(query).lower()
            if len(literal) < _CONFIG_BACKUP_REGEX_MIN_LITERAL:
                raise ValueError("regex_needs_literal")
            if _dbcore.DB_ENGINE == "postgres":
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                          AND POSITION(? IN LOWER(COALESCE(b.config_text, ''))) > 0
                          AND COALESCE(b.config_text, '') ~* ?
                        ORDER BY b.captured_at DESC, b.id DESC""",
                    (literal, query),
                )
            else:
                cursor = await db.execute(
                    f"""{base_select}
                        WHERE b.status = 'success'
                          AND instr(LOWER(COALESCE(b.config_text, '')), ?) > 0
                        ORDER BY b.captured_at DESC, b.id DESC""",
                    (literal,),
                )

        if cursor is None:
            raise ValueError("invalid_mode")

        results: list[dict] = []
        has_more = False

        while True:
            row = await cursor.fetchone()
            if row is None:
                break
            rec = dict(row)
            context = _extract_config_backup_match_context(
                rec.get("config_text") or "",
                query,
                mode=effective_mode,
                context_lines=context_radius,
                compiled_regex=compiled_regex,
            )
            if context is None:
                continue

            results.append(
                {
                    "backup_id": rec["id"],
                    "policy_id": rec.get("policy_id"),
                    "host_id": rec.get("host_id"),
                    "hostname": rec.get("hostname"),
                    "ip_address": rec.get("ip_address"),
                    "device_type": rec.get("device_type"),
                    "captured_at": rec.get("captured_at"),
                    "capture_method": rec.get("capture_method"),
                    "match_line_number": context["line_number"],
                    "match_line": context["match_line"],
                    "context_before": "\n".join(context["before_lines"]),
                    "context_before_lines": context["before_lines"],
                    "context_after": "\n".join(context["after_lines"]),
                    "context_after_lines": context["after_lines"],
                    "match_context": context["context_text"],
                    "config_length": len(rec.get("config_text") or ""),
                    "diff_view_path": f"/api/config-backups/{rec['id']}/diff",
                }
            )

            if len(results) >= row_limit:
                while True:
                    peek = await cursor.fetchone()
                    if peek is None:
                        break
                    peek_rec = dict(peek)
                    peek_context = _extract_config_backup_match_context(
                        peek_rec.get("config_text") or "",
                        query,
                        mode=effective_mode,
                        context_lines=context_radius,
                        compiled_regex=compiled_regex,
                    )
                    if peek_context is not None:
                        has_more = True
                        break
                break

        return {
            "query": query,
            "requested_mode": requested_mode,
            "mode": effective_mode,
            "limit": row_limit,
            "count": len(results),
            "has_more": has_more,
            "results": results,
        }
    finally:
        await db.close()


async def delete_config_backup(backup_id: int) -> None:
    """Delete a single backup."""
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM config_backups WHERE id = ?", (backup_id,))
        await db.commit()
    finally:
        await db.close()


async def delete_old_config_backups(days: int = 30) -> int:
    """Delete backups older than N days (retention cleanup)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM config_backups WHERE captured_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_config_backup_summary() -> dict:
    """Return summary stats for config backups."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM config_backup_policies")
        row = await cursor.fetchone()
        total_policies = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM config_backups")
        row = await cursor.fetchone()
        total_backups = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(DISTINCT host_id) FROM config_backups WHERE status = 'success'")
        row = await cursor.fetchone()
        hosts_backed_up = row[0] if row else 0

        cursor = await db.execute("SELECT MAX(captured_at) FROM config_backups")
        row = await cursor.fetchone()
        last_backup_at = row[0] if row else None

        return {
            "total_policies": total_policies,
            "total_backups": total_backups,
            "hosts_backed_up": hosts_backed_up,
            "last_backup_at": last_backup_at,
        }
    finally:
        await db.close()


# ── Compliance Profiles ─────────────────────────────────────────────────────


async def create_compliance_profile(
    name: str,
    description: str = "",
    rules: str = "[]",
    severity: str = "medium",
    created_by: str = "",
) -> int:
    """Create a new compliance profile with rules JSON."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO compliance_profiles
               (name, description, rules, severity, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            (name, description, rules, severity, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_compliance_profiles() -> list[dict]:
    """List all compliance profiles."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT p.*,
                      (SELECT COUNT(*) FROM compliance_profile_assignments WHERE profile_id = p.id) as assignment_count
               FROM compliance_profiles p
               ORDER BY p.name"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_compliance_profile(profile_id: int) -> dict | None:
    """Get a single compliance profile by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM compliance_profiles WHERE id = ?", (profile_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_compliance_profile(profile_id: int, **kwargs) -> None:
    """Update a compliance profile. Pass only the fields to change."""
    allowed = {"name", "description", "rules", "severity"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return
    sets = []
    params = []
    for k, v in updates.items():
        sets.append(f"{k} = ?")
        params.append(v)
    sets.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("compliance_profiles", sets, params, "id = ?", profile_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
    finally:
        await db.close()


async def delete_compliance_profile(profile_id: int) -> None:
    """Delete a compliance profile and its assignments/results."""
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM compliance_profiles WHERE id = ?", (profile_id,))
        await db.commit()
    finally:
        await db.close()


# ── Compliance Profile Assignments ──────────────────────────────────────────


async def create_compliance_assignment(
    profile_id: int,
    group_id: int,
    credential_id: int,
    interval_seconds: int = 86400,
    assigned_by: str = "",
) -> int:
    """Assign a compliance profile to an inventory group."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO compliance_profile_assignments
               (profile_id, group_id, credential_id, interval_seconds, assigned_by, assigned_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))""",
            (profile_id, group_id, credential_id, interval_seconds, assigned_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_compliance_assignments(profile_id: int | None = None, group_id: int | None = None) -> list[dict]:
    """List compliance assignments, optionally filtered."""
    db = await _dbcore.get_db()
    try:
        where_clauses = []
        params = []
        if profile_id is not None:
            where_clauses.append("a.profile_id = ?")
            params.append(profile_id)
        if group_id is not None:
            where_clauses.append("a.group_id = ?")
            params.append(group_id)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        cursor = await db.execute(
            f"""SELECT a.*, p.name as profile_name, p.severity as profile_severity,
                       g.name as group_name,
                       (SELECT COUNT(*) FROM hosts WHERE group_id = a.group_id) as host_count
                FROM compliance_profile_assignments a
                LEFT JOIN compliance_profiles p ON p.id = a.profile_id
                LEFT JOIN inventory_groups g ON g.id = a.group_id
                {where_sql}
                ORDER BY a.assigned_at DESC""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_compliance_assignment(assignment_id: int) -> dict | None:
    """Get a single compliance assignment by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT a.*, p.name as profile_name, g.name as group_name
               FROM compliance_profile_assignments a
               LEFT JOIN compliance_profiles p ON p.id = a.profile_id
               LEFT JOIN inventory_groups g ON g.id = a.group_id
               WHERE a.id = ?""",
            (assignment_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def update_compliance_assignment(assignment_id: int, **kwargs) -> None:
    """Update an assignment. Pass only the fields to change."""
    allowed = {"enabled", "credential_id", "interval_seconds"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return
    sets = []
    params = []
    for k, v in updates.items():
        sets.append(f"{k} = ?")
        params.append(v)
    sql, sql_params = _safe_dynamic_update("compliance_profile_assignments", sets, params, "id = ?", assignment_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
    finally:
        await db.close()


async def delete_compliance_assignment(assignment_id: int) -> None:
    """Delete a compliance assignment."""
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM compliance_profile_assignments WHERE id = ?", (assignment_id,))
        await db.commit()
    finally:
        await db.close()


async def get_compliance_assignments_due() -> list[dict]:
    """Get enabled assignments that are due for a compliance scan."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT a.*, p.name as profile_name, p.rules as profile_rules,
                      p.severity as profile_severity, g.name as group_name
               FROM compliance_profile_assignments a
               LEFT JOIN compliance_profiles p ON p.id = a.profile_id
               LEFT JOIN inventory_groups g ON g.id = a.group_id
               WHERE a.enabled = 1
                 AND (a.last_scan_at IS NULL
                      OR datetime(a.last_scan_at, '+' || a.interval_seconds || ' seconds') < datetime('now'))"""
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def update_compliance_assignment_last_scan(assignment_id: int) -> None:
    """Mark an assignment as just having been scanned."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE compliance_profile_assignments SET last_scan_at = datetime('now') WHERE id = ?",
            (assignment_id,),
        )
        await db.commit()
    finally:
        await db.close()


# ── Compliance Scan Results ─────────────────────────────────────────────────


async def create_compliance_scan_result(
    assignment_id: int | None,
    profile_id: int,
    host_id: int,
    status: str = "compliant",
    total_rules: int = 0,
    passed_rules: int = 0,
    failed_rules: int = 0,
    findings: str = "[]",
    config_snippet: str = "",
) -> int:
    """Store a compliance scan result for a host."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO compliance_scan_results
               (assignment_id, profile_id, host_id, status, total_rules, passed_rules,
                failed_rules, findings, config_snippet, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (assignment_id, profile_id, host_id, status, total_rules, passed_rules,
             failed_rules, findings, config_snippet),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_compliance_scan_results(
    host_id: int | None = None,
    profile_id: int | None = None,
    assignment_id: int | None = None,
    status: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """List compliance scan results with optional filters."""
    db = await _dbcore.get_db()
    try:
        where_clauses = []
        params: list = []
        if host_id is not None:
            where_clauses.append("r.host_id = ?")
            params.append(host_id)
        if profile_id is not None:
            where_clauses.append("r.profile_id = ?")
            params.append(profile_id)
        if assignment_id is not None:
            where_clauses.append("r.assignment_id = ?")
            params.append(assignment_id)
        if status is not None:
            where_clauses.append("r.status = ?")
            params.append(status)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT r.*, p.name as profile_name, h.hostname, h.ip_address
                FROM compliance_scan_results r
                LEFT JOIN compliance_profiles p ON p.id = r.profile_id
                LEFT JOIN hosts h ON h.id = r.host_id
                {where_sql}
                ORDER BY r.scanned_at DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_compliance_scan_result(result_id: int) -> dict | None:
    """Get a single scan result by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT r.*, p.name as profile_name, h.hostname, h.ip_address
               FROM compliance_scan_results r
               LEFT JOIN compliance_profiles p ON p.id = r.profile_id
               LEFT JOIN hosts h ON h.id = r.host_id
               WHERE r.id = ?""",
            (result_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def delete_compliance_scan_result(result_id: int) -> None:
    """Delete a single scan result."""
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM compliance_scan_results WHERE id = ?", (result_id,))
        await db.commit()
    finally:
        await db.close()


async def delete_old_compliance_scan_results(days: int = 90) -> int:
    """Delete compliance scan results older than N days."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM compliance_scan_results WHERE scanned_at < datetime('now', '-' || ? || ' days')",
            (days,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_compliance_summary() -> dict:
    """Return summary stats for compliance scanning."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM compliance_profiles")
        row = await cursor.fetchone()
        total_profiles = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM compliance_profile_assignments WHERE enabled = 1")
        row = await cursor.fetchone()
        active_assignments = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(DISTINCT host_id) FROM compliance_scan_results")
        row = await cursor.fetchone()
        hosts_scanned = row[0] if row else 0

        cursor = await db.execute(
            """SELECT COUNT(DISTINCT host_id) FROM compliance_scan_results
               WHERE status = 'non-compliant'
                 AND id IN (SELECT MAX(id) FROM compliance_scan_results GROUP BY host_id, profile_id)"""
        )
        row = await cursor.fetchone()
        hosts_non_compliant = row[0] if row else 0

        cursor = await db.execute("SELECT MAX(scanned_at) FROM compliance_scan_results")
        row = await cursor.fetchone()
        last_scan_at = row[0] if row else None

        return {
            "total_profiles": total_profiles,
            "active_assignments": active_assignments,
            "hosts_scanned": hosts_scanned,
            "hosts_non_compliant": hosts_non_compliant,
            "last_scan_at": last_scan_at,
        }
    finally:
        await db.close()


async def get_compliance_host_status(profile_id: int | None = None) -> list[dict]:
    """Get latest compliance status per host (optionally filtered by profile)."""
    db = await _dbcore.get_db()
    try:
        where_clause = "WHERE r.profile_id = ?" if profile_id is not None else ""
        params = (profile_id,) if profile_id is not None else ()
        cursor = await db.execute(
            f"""SELECT r.host_id, h.hostname, h.ip_address, r.profile_id,
                       p.name as profile_name, r.status, r.total_rules,
                       r.passed_rules, r.failed_rules, r.scanned_at
                FROM compliance_scan_results r
                INNER JOIN (
                    SELECT host_id, profile_id, MAX(id) as max_id
                    FROM compliance_scan_results
                    GROUP BY host_id, profile_id
                ) latest ON r.id = latest.max_id
                LEFT JOIN hosts h ON h.id = r.host_id
                LEFT JOIN compliance_profiles p ON p.id = r.profile_id
                {where_clause}
                ORDER BY r.status DESC, h.hostname""",
            params,
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Risk Analyses ───────────────────────────────────────────────────────────


async def create_risk_analysis(
    change_type: str = "template",
    host_id: int | None = None,
    group_id: int | None = None,
    risk_level: str = "low",
    risk_score: float = 0.0,
    proposed_commands: str = "",
    proposed_diff: str = "",
    current_config: str = "",
    simulated_config: str = "",
    analysis: str = "{}",
    compliance_impact: str = "[]",
    affected_areas: str = "[]",
    created_by: str = "",
) -> int:
    """Create a new risk analysis record."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO risk_analyses
               (change_type, host_id, group_id, risk_level, risk_score,
                proposed_commands, proposed_diff, current_config, simulated_config,
                analysis, compliance_impact, affected_areas, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (change_type, host_id, group_id, risk_level, risk_score,
             proposed_commands, proposed_diff, current_config, simulated_config,
             analysis, compliance_impact, affected_areas, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_risk_analyses(
    host_id: int | None = None,
    group_id: int | None = None,
    risk_level: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """List risk analyses with optional filters."""
    db = await _dbcore.get_db()
    try:
        where_clauses = []
        params: list = []
        if host_id is not None:
            where_clauses.append("r.host_id = ?")
            params.append(host_id)
        if group_id is not None:
            where_clauses.append("r.group_id = ?")
            params.append(group_id)
        if risk_level is not None:
            where_clauses.append("r.risk_level = ?")
            params.append(risk_level)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT r.*, h.hostname, h.ip_address, g.name as group_name
                FROM risk_analyses r
                LEFT JOIN hosts h ON h.id = r.host_id
                LEFT JOIN inventory_groups g ON g.id = r.group_id
                {where_sql}
                ORDER BY r.created_at DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_risk_analysis(analysis_id: int) -> dict | None:
    """Get a single risk analysis by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT r.*, h.hostname, h.ip_address, g.name as group_name
               FROM risk_analyses r
               LEFT JOIN hosts h ON h.id = r.host_id
               LEFT JOIN inventory_groups g ON g.id = r.group_id
               WHERE r.id = ?""",
            (analysis_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def approve_risk_analysis(analysis_id: int, approved_by: str) -> None:
    """Mark a risk analysis as approved."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE risk_analyses SET approved = 1, approved_by = ?, approved_at = datetime('now') WHERE id = ?",
            (approved_by, analysis_id),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_risk_analysis(analysis_id: int) -> None:
    """Delete a risk analysis."""
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM risk_analyses WHERE id = ?", (analysis_id,))
        await db.commit()
    finally:
        await db.close()


async def get_risk_analysis_summary() -> dict:
    """Return summary stats for risk analyses."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM risk_analyses")
        row = await cursor.fetchone()
        total = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM risk_analyses WHERE risk_level IN ('high', 'critical')")
        row = await cursor.fetchone()
        high_risk = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM risk_analyses WHERE approved = 1")
        row = await cursor.fetchone()
        approved = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM risk_analyses WHERE approved = 0")
        row = await cursor.fetchone()
        pending = row[0] if row else 0

        cursor = await db.execute("SELECT MAX(created_at) FROM risk_analyses")
        row = await cursor.fetchone()
        last_analysis_at = row[0] if row else None

        return {
            "total": total,
            "high_risk": high_risk,
            "approved": approved,
            "pending": pending,
            "last_analysis_at": last_analysis_at,
        }
    finally:
        await db.close()


# ── Deployments ──────────────────────────────────────────────────────────────


async def create_deployment(
    name: str,
    group_id: int,
    credential_id: int,
    change_type: str = "template",
    proposed_commands: str = "",
    template_id: int | None = None,
    risk_analysis_id: int | None = None,
    host_ids: str = "[]",
    description: str = "",
    created_by: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO deployments
               (name, description, group_id, credential_id, change_type,
                proposed_commands, template_id, risk_analysis_id, host_ids,
                created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (name, description, group_id, credential_id, change_type,
             proposed_commands, template_id, risk_analysis_id, host_ids,
             created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_deployments(
    status: str | None = None,
    group_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        where_clauses = []
        params: list = []
        if status:
            where_clauses.append("d.status = ?")
            params.append(status)
        if group_id is not None:
            where_clauses.append("d.group_id = ?")
            params.append(group_id)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        params.append(limit)
        cursor = await db.execute(
            f"""SELECT d.*, g.name as group_name
                FROM deployments d
                LEFT JOIN inventory_groups g ON g.id = d.group_id
                {where_sql}
                ORDER BY d.created_at DESC
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_deployment(deployment_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT d.*, g.name as group_name
               FROM deployments d
               LEFT JOIN inventory_groups g ON g.id = d.group_id
               WHERE d.id = ?""",
            (deployment_id,),
        )
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def claim_deployment_for_execute(deployment_id: int) -> bool:
    """Atomically transition a deployment from planning/failed into execution.

    Returns True if this caller won the claim, False if the deployment was
    already claimed by a concurrent request. This closes the execute TOCTOU:
    without it, two simultaneous /execute calls both read status='planning'
    and both push commands to the devices.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "UPDATE deployments SET status = 'pre-check', "
            "started_at = COALESCE(started_at, datetime('now')) "
            "WHERE id = ? AND status IN ('planning', 'failed')",
            (deployment_id,),
        )
        await db.commit()
        return (cursor.rowcount or 0) > 0
    finally:
        await db.close()


async def update_deployment_status(
    deployment_id: int, status: str,
    rollback_status: str | None = None,
) -> None:
    db = await _dbcore.get_db()
    try:
        if rollback_status is not None:
            await db.execute(
                "UPDATE deployments SET status = ?, rollback_status = ? WHERE id = ?",
                (status, rollback_status, deployment_id),
            )
        else:
            await db.execute(
                "UPDATE deployments SET status = ? WHERE id = ?",
                (status, deployment_id),
            )
        if status in ("executing",) :
            await db.execute(
                "UPDATE deployments SET started_at = datetime('now') WHERE id = ? AND started_at IS NULL",
                (deployment_id,),
            )
        if status in ("completed", "failed", "rolled-back"):
            await db.execute(
                "UPDATE deployments SET finished_at = datetime('now') WHERE id = ?",
                (deployment_id,),
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def delete_deployment(deployment_id: int) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM deployments WHERE id = ?", (deployment_id,))
        await db.commit()
    finally:
        await db.close()


async def get_deployment_summary() -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM deployments")
        total = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status = 'completed'")
        completed = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status IN ('executing', 'pre-check', 'post-check')")
        active = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status = 'rolled-back'")
        rolled_back = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status = 'failed'")
        failed = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM deployments WHERE status = 'planning'")
        planning = (await cursor.fetchone())[0]

        return {
            "total": total,
            "completed": completed,
            "active": active,
            "rolled_back": rolled_back,
            "failed": failed,
            "planning": planning,
        }
    finally:
        await db.close()


# ── Deployment Checkpoints ───────────────────────────────────────────────────


async def create_deployment_checkpoint(
    deployment_id: int,
    phase: str,
    check_name: str,
    check_type: str = "config_capture",
    host_id: int | None = None,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO deployment_checkpoints
               (deployment_id, phase, check_name, check_type, host_id, created_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))""",
            (deployment_id, phase, check_name, check_type, host_id),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_deployment_checkpoint(
    checkpoint_id: int, status: str, result: str = "{}",
) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE deployment_checkpoints
               SET status = ?, result = ?, executed_at = datetime('now')
               WHERE id = ?""",
            (status, result, checkpoint_id),
        )
        await db.commit()
    finally:
        await db.close()


async def get_deployment_checkpoints(deployment_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT c.*, h.hostname, h.ip_address
               FROM deployment_checkpoints c
               LEFT JOIN hosts h ON h.id = c.host_id
               WHERE c.deployment_id = ?
               ORDER BY c.phase, c.id""",
            (deployment_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


# ── Deployment Snapshots ─────────────────────────────────────────────────────


async def create_deployment_snapshot(
    deployment_id: int,
    host_id: int,
    phase: str,
    config_text: str,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO deployment_snapshots
               (deployment_id, host_id, phase, config_text, captured_at)
               VALUES (?, ?, ?, ?, datetime('now'))""",
            (deployment_id, host_id, phase, config_text),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_deployment_snapshots(
    deployment_id: int, phase: str | None = None,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        if phase:
            cursor = await db.execute(
                """SELECT s.*, h.hostname, h.ip_address
                   FROM deployment_snapshots s
                   LEFT JOIN hosts h ON h.id = s.host_id
                   WHERE s.deployment_id = ? AND s.phase = ?
                   ORDER BY s.id""",
                (deployment_id, phase),
            )
        else:
            cursor = await db.execute(
                """SELECT s.*, h.hostname, h.ip_address
                   FROM deployment_snapshots s
                   LEFT JOIN hosts h ON h.id = s.host_id
                   WHERE s.deployment_id = ?
                   ORDER BY s.phase, s.id""",
                (deployment_id,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


