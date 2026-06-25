"""Inventory persistence helpers.

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
from routes.db.ipam import record_ip_assignment, record_ip_release

__all__ = [
    "get_all_groups",
    "get_all_groups_with_hosts",
    "get_all_groups_for_user",
    "get_all_groups_with_hosts_for_user",
    "set_user_group_order",
    "get_group",
    "create_group",
    "update_group",
    "delete_group",
    "get_host",
    "get_hosts_for_group",
    "get_hosts_by_ids",
    "get_all_hosts",
    "find_host_by_ip",
    "get_host_ip_index",
    "set_host_ip_aliases",
    "get_ip_aliases_for_hosts",
    "get_hosts_with_identity",
    "get_fdm_hosts",
    "add_host",
    "remove_host",
    "update_host",
    "move_hosts",
    "bulk_delete_hosts",
    "update_host_status",
    "update_host_device_info",
    "update_host_serial",
    "get_all_hosts_for_export",
]

# ═════════════════════════════════════════════════════════════════════════════
# Inventory Groups
# ═════════════════════════════════════════════════════════════════════════════

async def get_all_groups() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("""
            SELECT g.*, COUNT(h.id) AS host_count
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            GROUP BY g.id ORDER BY g.name
        """)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_all_groups_with_hosts() -> list[dict]:
    """Return all groups with embedded host arrays using a single query."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("""
            SELECT
                g.id AS group_id,
                g.name AS group_name,
                g.description AS group_description,
                h.id AS host_id,
                h.group_id AS host_group_id,
                h.hostname AS host_hostname,
                h.ip_address AS host_ip_address,
                h.device_type AS host_device_type,
                h.status AS host_status,
                h.last_seen AS host_last_seen,
                h.model AS host_model,
                h.software_version AS host_software_version,
                h.device_category AS host_device_category,
                h.serial_number AS host_serial_number
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            ORDER BY g.name, h.ip_address
        """)
        rows = await cursor.fetchall()
    finally:
        await db.close()

    groups: list[dict] = []
    by_group_id: dict[int, dict] = {}
    for row in rows:
        gid = int(row["group_id"])
        group = by_group_id.get(gid)
        if group is None:
            group = {
                "id": gid,
                "name": row["group_name"],
                "description": row["group_description"] or "",
                "host_count": 0,
                "hosts": [],
            }
            by_group_id[gid] = group
            groups.append(group)

        host_id = row["host_id"]
        if host_id is None:
            continue
        group["hosts"].append({
            "id": host_id,
            "group_id": row["host_group_id"],
            "hostname": row["host_hostname"],
            "ip_address": row["host_ip_address"],
            "device_type": row["host_device_type"],
            "status": row["host_status"],
            "last_seen": row["host_last_seen"],
            "model": row["host_model"] or "",
            "software_version": row["host_software_version"] or "",
            "device_category": row["host_device_category"] or "",
            "serial_number": row["host_serial_number"] or "",
        })
        group["host_count"] += 1

    return groups


async def get_all_groups_for_user(user_id: int) -> list[dict]:
    """Like get_all_groups but ordered by the user's saved drag order.

    Groups the user has not explicitly positioned fall to the bottom
    alphabetically (COALESCE(position, large sentinel)).
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """
            SELECT g.*, COUNT(h.id) AS host_count, o.position AS _position
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            LEFT JOIN user_inventory_group_order o
                   ON o.group_id = g.id AND o.user_id = ?
            GROUP BY g.id, o.position
            ORDER BY COALESCE(o.position, 2147483647), g.name
            """,
            (user_id,),
        )
        rows = rows_to_list(await cursor.fetchall())
    finally:
        await db.close()
    for row in rows:
        row.pop("_position", None)
    return rows


async def get_all_groups_with_hosts_for_user(user_id: int) -> list[dict]:
    """Per-user-ordered variant of get_all_groups_with_hosts."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """
            SELECT
                g.id AS group_id,
                g.name AS group_name,
                g.description AS group_description,
                o.position AS _position,
                h.id AS host_id,
                h.group_id AS host_group_id,
                h.hostname AS host_hostname,
                h.ip_address AS host_ip_address,
                h.device_type AS host_device_type,
                h.status AS host_status,
                h.last_seen AS host_last_seen,
                h.model AS host_model,
                h.software_version AS host_software_version,
                h.device_category AS host_device_category,
                h.serial_number AS host_serial_number
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            LEFT JOIN user_inventory_group_order o
                   ON o.group_id = g.id AND o.user_id = ?
            ORDER BY COALESCE(o.position, 2147483647), g.name, h.ip_address
            """,
            (user_id,),
        )
        rows = await cursor.fetchall()
    finally:
        await db.close()

    groups: list[dict] = []
    by_group_id: dict[int, dict] = {}
    for row in rows:
        gid = int(row["group_id"])
        group = by_group_id.get(gid)
        if group is None:
            group = {
                "id": gid,
                "name": row["group_name"],
                "description": row["group_description"] or "",
                "host_count": 0,
                "hosts": [],
            }
            by_group_id[gid] = group
            groups.append(group)

        host_id = row["host_id"]
        if host_id is None:
            continue
        group["hosts"].append({
            "id": host_id,
            "group_id": row["host_group_id"],
            "hostname": row["host_hostname"],
            "ip_address": row["host_ip_address"],
            "device_type": row["host_device_type"],
            "status": row["host_status"],
            "last_seen": row["host_last_seen"],
            "model": row["host_model"] or "",
            "software_version": row["host_software_version"] or "",
            "device_category": row["host_device_category"] or "",
            "serial_number": row["host_serial_number"] or "",
        })
        group["host_count"] += 1

    return groups


async def set_user_group_order(user_id: int, ordered_group_ids: list[int]) -> None:
    """Replace the saved order for a user with the given list of group ids."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "DELETE FROM user_inventory_group_order WHERE user_id = ?",
            (user_id,),
        )
        for position, group_id in enumerate(ordered_group_ids):
            await db.execute(
                "INSERT INTO user_inventory_group_order (user_id, group_id, position) "
                "VALUES (?, ?, ?)",
                (user_id, int(group_id), position),
            )
        await db.commit()
    finally:
        await db.close()


async def get_group(group_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM inventory_groups WHERE id = ?", (group_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def create_group(name: str, description: str = "") -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO inventory_groups (name, description) VALUES (?, ?)",
            (name, description),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_group(group_id: int, name: str, description: str = ""):
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE inventory_groups SET name = ?, description = ? WHERE id = ?",
            (name, description, group_id),
        )
        await db.commit()
    finally:
        await db.close()


async def delete_group(group_id: int):
    db = await _dbcore.get_db()
    try:
        # Delete jobs referencing this group (job_events cascade automatically)
        await db.execute("DELETE FROM jobs WHERE inventory_group_id = ?", (group_id,))
        await db.execute("DELETE FROM inventory_groups WHERE id = ?", (group_id,))
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Hosts
# ═════════════════════════════════════════════════════════════════════════════

async def get_host(host_id: int) -> dict | None:
    """Get a single host by ID."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_hosts_for_group(group_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM hosts WHERE group_id = ? ORDER BY ip_address", (group_id,)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_hosts_by_ids(host_ids: list[int]) -> list[dict]:
    """Get multiple hosts by their IDs."""
    if not host_ids:
        return []
    db = await _dbcore.get_db()
    try:
        placeholders = ','.join('?' * len(host_ids))
        cursor = await db.execute(
            f"SELECT * FROM hosts WHERE id IN ({placeholders}) ORDER BY ip_address",
            tuple(host_ids)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_all_hosts() -> list[dict]:
    """Get every host across all groups, ordered by hostname."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM hosts ORDER BY hostname, ip_address"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def find_host_by_ip(ip_address: str) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM hosts WHERE ip_address = ? LIMIT 1", (ip_address,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


# ── Multi-interface device identity / IP aliases ─────────────────────────────
#
# A device owns one primary IP (hosts.ip_address) plus any number of secondary
# interface IPs (host_ip_aliases). Discovery uses these, together with serial
# number and sysName, to recognise that a freshly probed IP is an existing
# device rather than a new one — preventing one router with many interface IPs
# from registering as many duplicate hosts.


async def get_host_ip_index(group_id: int) -> dict[str, int]:
    """Return {ip_address: host_id} covering every host in the group across both
    its primary IP and its recorded interface-IP aliases."""
    db = await _dbcore.get_db()
    try:
        index: dict[str, int] = {}
        cursor = await db.execute(
            "SELECT id, ip_address FROM hosts WHERE group_id = ?", (group_id,)
        )
        for row in await cursor.fetchall():
            d = dict(row)
            ip = (d.get("ip_address") or "").strip()
            if ip:
                index[ip] = int(d["id"])
        cursor = await db.execute(
            """SELECT a.ip_address AS ip, a.host_id AS host_id
               FROM host_ip_aliases a
               JOIN hosts h ON h.id = a.host_id
               WHERE h.group_id = ?""",
            (group_id,),
        )
        for row in await cursor.fetchall():
            d = dict(row)
            ip = (d.get("ip") or "").strip()
            # A primary IP always wins over an alias if they ever collide.
            if ip and ip not in index:
                index[ip] = int(d["host_id"])
        return index
    finally:
        await db.close()


async def set_host_ip_aliases(host_id: int, primary_ip: str, alias_ips: list[str]) -> int:
    """Replace the recorded interface-IP aliases for a host.

    The host's own primary IP is never stored as an alias. Returns the number
    of alias rows written.
    """
    primary = (primary_ip or "").strip()
    clean = sorted({
        ip.strip() for ip in alias_ips
        if ip and ip.strip() and ip.strip() != primary
    })
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM host_ip_aliases WHERE host_id = ?", (host_id,))
        for ip in clean:
            await db.execute(
                "INSERT INTO host_ip_aliases (host_id, ip_address) VALUES (?, ?)",
                (host_id, ip),
            )
        await db.commit()
        return len(clean)
    finally:
        await db.close()


async def get_ip_aliases_for_hosts(host_ids: list[int]) -> list[dict]:
    """Return [{host_id, ip_address}] interface-IP aliases for the given hosts.

    Used by topology to resolve a neighbor reported via a device's secondary
    interface IP back to the owning inventory host.
    """
    if not host_ids:
        return []
    db = await _dbcore.get_db()
    try:
        placeholders = ",".join("?" * len(host_ids))
        cursor = await db.execute(
            f"SELECT host_id, ip_address FROM host_ip_aliases WHERE host_id IN ({placeholders})",
            tuple(host_ids),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_hosts_with_identity(group_id: int) -> list[dict]:
    """Hosts in the group with the fields discovery dedups on (id, hostname,
    ip_address, serial_number)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT id, hostname, ip_address, serial_number, device_type, "
            "model, software_version, device_category, status "
            "FROM hosts WHERE group_id = ?",
            (group_id,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_fdm_hosts() -> list[dict]:
    """Hosts opted in to Cisco FDM REST-API polling (fdm_api_enabled = 1).

    Drives the FDM metrics collector (netcontrol/integrations/cisco_fdm). Each
    row carries fdm_credential_id / fdm_port / fdm_verify_tls used to build the
    per-host FdmClient.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM hosts WHERE fdm_api_enabled = 1 ORDER BY hostname, ip_address"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def add_host(group_id: int, hostname: str, ip_address: str,
                   device_type: str = "cisco_ios",
                   vrf_name: str = "", vlan_id: str = "") -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address, device_type, vrf_name, vlan_id) "
            "VALUES (?,?,?,?,?,?)",
            (group_id, hostname, ip_address, device_type, vrf_name or "", str(vlan_id or "")),
        )
        await db.commit()
        new_id = cursor.lastrowid
    except Exception as e:
        if _is_unique_violation(e):
            raise ValueError(f"Host {ip_address} already exists in group {group_id}")
        raise
    finally:
        await db.close()
    if ip_address:
        try:
            await record_ip_assignment(
                address=ip_address, hostname=hostname or "",
                vrf_name=vrf_name or "", source_type="host",
                source_ref=str(new_id), note="host added",
            )
        except Exception as exc:
            _LOGGER.warning(
                "Failed to record IP assignment for host %s: %s",
                new_id, exc,
            )
    return new_id


async def remove_host(host_id: int):
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts WHERE id = ?", (host_id,)
        )
        row = await cur.fetchone()
        prior_ip = ""
        prior_vrf = ""
        if row:
            d = dict(row)
            prior_ip = (d.get("ip_address") or "").strip()
            prior_vrf = (d.get("vrf_name") or "").strip()
        await db.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        await db.commit()
    finally:
        await db.close()
    if prior_ip:
        try:
            await record_ip_release(
                address=prior_ip, vrf_name=prior_vrf, note="host removed"
            )
        except Exception as exc:
            _LOGGER.warning(
                "Failed to record IP release for removed host %s: %s",
                host_id, exc,
            )


async def update_host(host_id: int, hostname: str, ip_address: str,
                      device_type: str = "cisco_ios",
                      vrf_name: str | None = None, vlan_id: str | None = None):
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts WHERE id = ?", (host_id,)
        )
        prior_row = await cur.fetchone()
        prior = dict(prior_row) if prior_row else {}
        prior_ip = (prior.get("ip_address") or "").strip()
        prior_vrf = (prior.get("vrf_name") or "").strip()

        if vrf_name is None and vlan_id is None:
            await db.execute(
                "UPDATE hosts SET hostname=?, ip_address=?, device_type=? WHERE id=?",
                (hostname, ip_address, device_type, host_id),
            )
        else:
            await db.execute(
                "UPDATE hosts SET hostname=?, ip_address=?, device_type=?, vrf_name=?, vlan_id=? "
                "WHERE id=?",
                (hostname, ip_address, device_type,
                 vrf_name or "", str(vlan_id or ""), host_id),
            )
        await db.commit()
    finally:
        await db.close()

    new_vrf = (vrf_name or prior_vrf) if vrf_name is not None else prior_vrf
    new_ip = (ip_address or "").strip()
    try:
        if prior_ip and (prior_ip != new_ip or prior_vrf != new_vrf):
            await record_ip_release(
                address=prior_ip, vrf_name=prior_vrf, note="host updated"
            )
        if new_ip:
            await record_ip_assignment(
                address=new_ip, hostname=hostname or "",
                vrf_name=new_vrf or "", source_type="host",
                source_ref=str(host_id), note="host updated",
            )
    except Exception as exc:
        _LOGGER.warning(
            "Failed to record IP assignment history for updated host %s: %s",
            host_id, exc,
        )


async def move_hosts(host_ids: list[int], target_group_id: int) -> int:
    if not host_ids:
        return 0
    db = await _dbcore.get_db()
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cursor = await db.execute(
            f"UPDATE hosts SET group_id = ? WHERE id IN ({placeholders})",
            (target_group_id, *host_ids),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def bulk_delete_hosts(host_ids: list[int]) -> int:
    if not host_ids:
        return 0
    db = await _dbcore.get_db()
    try:
        placeholders = ",".join("?" for _ in host_ids)
        cur = await db.execute(
            f"SELECT ip_address, vrf_name FROM hosts WHERE id IN ({placeholders})",
            tuple(host_ids),
        )
        prior_rows = [dict(r) for r in await cur.fetchall()]
        cursor = await db.execute(
            f"DELETE FROM hosts WHERE id IN ({placeholders})",
            tuple(host_ids),
        )
        await db.commit()
        rowcount = cursor.rowcount
    finally:
        await db.close()
    for r in prior_rows:
        ip = (r.get("ip_address") or "").strip()
        vrf = (r.get("vrf_name") or "").strip()
        if ip:
            try:
                await record_ip_release(
                    address=ip, vrf_name=vrf, note="bulk host delete"
                )
            except Exception as exc:
                _LOGGER.warning(
                    "Failed to record IP release for bulk-deleted host (%s): %s",
                    ip, exc,
                )
    return rowcount


async def update_host_status(host_id: int, status: str):
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE hosts SET status = ?, last_seen = ? WHERE id = ?",
            (status, datetime.now(UTC).isoformat(), host_id),
        )
        await db.commit()
    finally:
        await db.close()


async def update_host_device_info(host_id: int, model: str, software_version: str,
                                  device_category: str = ""):
    """Update the model, software_version, and device_category fields for a host."""
    db = await _dbcore.get_db()
    try:
        if device_category:
            await db.execute(
                "UPDATE hosts SET model = ?, software_version = ?, device_category = ? WHERE id = ?",
                (model, software_version, device_category, host_id),
            )
        else:
            await db.execute(
                "UPDATE hosts SET model = ?, software_version = ? WHERE id = ?",
                (model, software_version, host_id),
            )
        await db.commit()
    finally:
        await db.close()


async def update_host_serial(host_id: int, serial_number: str) -> None:
    """Update the serial_number field for a host."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            "UPDATE hosts SET serial_number = ? WHERE id = ?",
            (serial_number, host_id),
        )
        await db.commit()
    finally:
        await db.close()


async def get_all_hosts_for_export() -> list[dict]:
    """Return all hosts with group name for CSV export."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("""
            SELECT h.hostname, h.ip_address, h.device_type, h.status,
                   h.model, h.software_version, g.name AS group_name
            FROM hosts h
            LEFT JOIN inventory_groups g ON g.id = h.group_id
            ORDER BY g.name, h.hostname
        """)
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


