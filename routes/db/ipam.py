"""Ipam persistence helpers.

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
    "get_ipam_overview",
    "get_ipam_subnet_detail",
    "list_ipam_sources",
    "create_ipam_source",
    "get_ipam_source",
    "get_ipam_source_auth_config",
    "update_ipam_source",
    "delete_ipam_source",
    "replace_ipam_source_snapshot",
    "set_ipam_source_sync_status",
    "list_ipam_reservations",
    "create_ipam_reservation",
    "delete_ipam_reservation",
    "get_or_create_builtin_ipam_source",
    "create_ipam_prefix",
    "get_ipam_prefix",
    "delete_ipam_prefix",
    "create_local_ipam_allocation",
    "delete_ipam_allocation",
    "list_ipam_allocations_for_source",
    "allocate_next_ip",
    "get_pending_allocation",
    "list_pending_allocations",
    "update_pending_allocation_state",
    "expire_stale_pending_allocations",
    "record_ip_assignment",
    "record_ip_release",
    "get_ip_history",
    "find_ip_owner_at",
    "list_ip_history_for_hostname",
    "snapshot_subnet_utilization",
    "snapshot_all_subnet_utilization",
    "list_subnet_utilization",
    "prune_ip_history",
    "prune_subnet_utilization",
    "generate_ipam_utilization_report_data",
    "generate_ipam_forecast_report_data",
    "generate_ipam_history_report_data",
    "create_reconciliation_run",
    "finalize_reconciliation_run",
    "insert_reconciliation_diff",
    "list_reconciliation_runs",
    "list_reconciliation_diffs",
    "get_reconciliation_diff",
    "mark_reconciliation_diff_resolved",
    "list_dhcp_servers",
    "get_dhcp_server",
    "create_dhcp_server",
    "update_dhcp_server",
    "delete_dhcp_server",
    "get_dhcp_server_auth_config",
    "replace_dhcp_server_snapshot",
    "set_dhcp_server_sync_status",
    "list_dhcp_scopes",
    "list_dhcp_leases",
]

# ═════════════════════════════════════════════════════════════════════════════
# IPAM - Lightweight IP Address Management
# ═════════════════════════════════════════════════════════════════════════════


def _infer_subnet(ip_str: str) -> str | None:
    """Infer network CIDR from a host IP string.

    Handles both notated (10.0.0.1/24) and plain (10.0.0.1) forms.
    Plain IPv4 defaults to /24; plain IPv6 defaults to /64.
    Returns canonical network string (e.g. "10.0.0.0/24") or None on error.
    """
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    try:
        if "/" in ip_str:
            net = ipaddress.ip_interface(ip_str).network
        else:
            addr = ipaddress.ip_address(ip_str)
            prefix = 64 if addr.version == 6 else 24
            net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
        return str(net)
    except ValueError:
        return None


def _ip_in_reservation(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, rsv: dict) -> bool:
    """Return True if *addr* falls within the reservation IP range."""
    try:
        start = ipaddress.ip_address(rsv["start_ip"])
        end = ipaddress.ip_address(rsv["end_ip"])
        return start <= addr <= end
    except (ValueError, KeyError):
        return False


async def get_ipam_overview(
    group_id: int | None = None,
    include_cloud: bool = True,
    include_external: bool = True,
) -> dict:
    """Return a merged IPAM overview across inventory, cloud, and external sources."""
    db = await _dbcore.get_db()
    try:
        # ── 1. Inventory hosts ──────────────────────────────────────────────
        if group_id is not None:
            cursor = await db.execute(
                """SELECT h.ip_address, h.vrf_name, h.vlan_id, g.name AS group_name
                   FROM hosts h
                   JOIN inventory_groups g ON h.group_id = g.id
                   WHERE h.group_id = ? AND h.ip_address != '' AND h.ip_address IS NOT NULL""",
                (group_id,),
            )
        else:
            cursor = await db.execute(
                """SELECT h.ip_address, h.vrf_name, h.vlan_id, g.name AS group_name
                   FROM hosts h
                   JOIN inventory_groups g ON h.group_id = g.id
                   WHERE h.ip_address != '' AND h.ip_address IS NOT NULL"""
            )
        host_rows = rows_to_list(await cursor.fetchall())

        # Subnets are scoped by (subnet, vrf) so the same RFC1918 range in
        # different VRFs does not collapse into one row. Empty VRF = "global".
        subnet_hosts: dict[tuple[str, str], list[dict]] = {}
        subnet_vlans: dict[tuple[str, str], set[str]] = {}
        # Conflict key is (vrf, ip): same IP in different inventory groups but
        # the same VRF is a real conflict; different VRFs are not.
        ip_groups: dict[tuple[str, str], set[str]] = {}

        for row in host_rows:
            ip = row["ip_address"].strip().split("/")[0]
            group = row["group_name"]
            vrf = (row.get("vrf_name") or "").strip()
            vlan = (row.get("vlan_id") or "").strip()
            sn = _infer_subnet(ip)
            if sn is None:
                continue
            key = (sn, vrf)
            subnet_hosts.setdefault(key, []).append({"ip": ip, "group": group, "vrf": vrf, "vlan": vlan})
            if vlan:
                subnet_vlans.setdefault(key, set()).add(vlan)
            ip_groups.setdefault((vrf, ip), set()).add(group)

        # ── 2. Cloud resources (no VRF concept - keyed with vrf="") ─────────
        cloud_keys: set[tuple[str, str]] = set()
        subnet_cloud_count: dict[tuple[str, str], int] = {}

        if include_cloud:
            cursor = await db.execute(
                """SELECT DISTINCT cr.cidr
                   FROM cloud_resources cr
                   WHERE cr.cidr != '' AND cr.cidr IS NOT NULL"""
            )
            cloud_rows = await cursor.fetchall()
            for row in cloud_rows:
                cidr = row[0].strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    sn = str(net)
                except ValueError:
                    continue
                k = (sn, "")
                cloud_keys.add(k)
                subnet_cloud_count[k] = subnet_cloud_count.get(k, 0) + 1

        # ── 3. External IPAM prefixes (carry their own VRF) ─────────────────
        external_keys: set[tuple[str, str]] = set()
        local_keys: set[tuple[str, str]] = set()
        key_vlans: dict[tuple[str, str], set[str]] = {}
        subnet_ext_prefix_count: dict[tuple[str, str], int] = {}
        subnet_ext_alloc_count: dict[tuple[str, str], int] = {}

        if include_external:
            cursor = await db.execute(
                """SELECT p.subnet, p.vrf, p.vlan, s.provider
                   FROM ipam_prefixes p
                   JOIN ipam_sources s ON s.id = p.source_id
                   WHERE p.subnet != '' AND p.subnet IS NOT NULL"""
            )
            ext_prefix_rows = rows_to_list(await cursor.fetchall())
            for row in ext_prefix_rows:
                sn = row["subnet"].strip()
                vrf = (row.get("vrf") or "").strip()
                vlan = (row.get("vlan") or "").strip()
                k = (sn, vrf)
                if vlan:
                    key_vlans.setdefault(k, set()).add(vlan)
                if row["provider"] == "plexus":
                    local_keys.add(k)
                else:
                    external_keys.add(k)
                    subnet_ext_prefix_count[k] = subnet_ext_prefix_count.get(k, 0) + 1

            cursor = await db.execute(
                """SELECT p.subnet, p.vrf, COUNT(a.id) AS cnt
                   FROM ipam_prefixes p
                   LEFT JOIN ipam_allocations a
                     ON a.source_id = p.source_id AND a.prefix_subnet = p.subnet
                   GROUP BY p.subnet, p.vrf"""
            )
            alloc_rows = rows_to_list(await cursor.fetchall())
            for row in alloc_rows:
                k = (row["subnet"], (row.get("vrf") or "").strip())
                subnet_ext_alloc_count[k] = (
                    subnet_ext_alloc_count.get(k, 0) + int(row.get("cnt") or 0)
                )

        # ── 4. Merge all (subnet, vrf) keys ─────────────────────────────────
        inventory_keys = set(subnet_hosts.keys())
        all_keys: set[tuple[str, str]] = (
            inventory_keys | cloud_keys | external_keys | local_keys
        )
        # Exact overlap is now inventory∩cloud per (subnet, vrf); cloud always vrf=""
        exact_overlaps = {sn for (sn, v) in inventory_keys if (sn, "") in cloud_keys and v == ""}

        subnets_out: list[dict] = []
        for k in sorted(all_keys):
            sn, vrf = k
            hosts_in = subnet_hosts.get(k, [])
            unique_ips = {h["ip"] for h in hosts_in}
            group_names = sorted({h["group"] for h in hosts_in})
            vlans = sorted(subnet_vlans.get(k, set()) | key_vlans.get(k, set()))
            src_types: list[str] = []
            if k in inventory_keys:
                src_types.append("inventory")
            if k in cloud_keys:
                src_types.append("cloud")
            if k in local_keys:
                src_types.append("local")
            if k in external_keys:
                src_types.append("external")
            try:
                net = ipaddress.ip_network(sn, strict=False)
                total = net.num_addresses
                usable = max(0, total - 2) if net.prefixlen < 31 else total
            except ValueError:
                total = usable = 0
            used = len(unique_ips)
            utilization_pct = round((used / usable * 100), 1) if usable else 0.0
            subnets_out.append({
                "subnet": sn,
                "vrf_name": vrf,
                "vlan_ids": vlans,
                "inventory_host_count": len(hosts_in),
                "cloud_resource_count": subnet_cloud_count.get(k, 0),
                "external_prefix_count": subnet_ext_prefix_count.get(k, 0),
                "external_allocation_count": subnet_ext_alloc_count.get(k, 0),
                "group_names": group_names,
                "source_types": src_types,
                "used_count": used,
                "total_count": usable,
                "utilization_pct": utilization_pct,
            })

        # ── 5. Duplicate IP detection (VRF-aware) ───────────────────────────
        # Same IP in different inventory groups within the same VRF = conflict.
        # Same IP in different VRFs = NOT a conflict.
        duplicates_out: list[dict] = []
        for (vrf, ip), groups in sorted(ip_groups.items()):
            if len(groups) > 1:
                host_count = sum(
                    1 for row in host_rows
                    if row["ip_address"].strip().split("/")[0] == ip
                    and (row.get("vrf_name") or "").strip() == vrf
                )
                duplicates_out.append({
                    "ip_address": ip,
                    "vrf_name": vrf,
                    "host_count": host_count,
                    "groups": sorted(groups),
                })

        # ── 6. Summary ──────────────────────────────────────────────────────
        total_ext_allocs = sum(subnet_ext_alloc_count.values())
        distinct_vrfs = sorted({vrf for (_, vrf) in all_keys if vrf})
        summary: dict = {
            "inventory_host_count": len(host_rows),
            "total_subnets": len(all_keys),
            "inventory_subnets": len(inventory_keys),
            "cloud_subnets": len(cloud_keys),
            "local_subnets": len(local_keys),
            "external_subnets": len(external_keys),
            "duplicate_ip_count": len(duplicates_out),
            "exact_source_overlap_count": len(exact_overlaps),
            "external_allocation_count": total_ext_allocs,
            "vrf_names": distinct_vrfs,
            "vrf_count": len(distinct_vrfs),
        }
        if group_id is not None:
            summary["group_id"] = group_id

        return {
            "summary": summary,
            "subnets": subnets_out,
            "duplicate_ips": duplicates_out,
        }
    finally:
        await db.close()


async def get_ipam_subnet_detail(
    subnet: str,
    group_id: int | None = None,
    include_cloud: bool = True,
    include_external: bool = True,
) -> dict:
    """Return per-subnet utilisation detail: allocations, reservations, available preview."""
    db = await _dbcore.get_db()
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        net_str = str(net)
        prefix_len = net.prefixlen

        # ── Inventory hosts in this subnet ──────────────────────────────────
        if group_id is not None:
            cursor = await db.execute(
                """SELECT h.ip_address, h.hostname, g.name AS group_name
                   FROM hosts h
                   JOIN inventory_groups g ON h.group_id = g.id
                   WHERE h.group_id = ? AND h.ip_address != '' AND h.ip_address IS NOT NULL""",
                (group_id,),
            )
        else:
            cursor = await db.execute(
                """SELECT h.ip_address, h.hostname, g.name AS group_name
                   FROM hosts h
                   JOIN inventory_groups g ON h.group_id = g.id
                   WHERE h.ip_address != '' AND h.ip_address IS NOT NULL"""
            )
        all_host_rows = rows_to_list(await cursor.fetchall())

        inv_in_subnet: list[dict] = []
        for row in all_host_rows:
            ip_s = row["ip_address"].strip().split("/")[0]
            try:
                addr = ipaddress.ip_address(ip_s)
                if addr in net:
                    inv_in_subnet.append({"ip": ip_s, "hostname": row["hostname"], "group": row["group_name"]})
            except ValueError:
                continue

        # ── Custom reservations ─────────────────────────────────────────────
        cursor = await db.execute(
            "SELECT * FROM ipam_reservations WHERE subnet = ? ORDER BY start_ip",
            (net_str,),
        )
        raw_reservations = rows_to_list(await cursor.fetchall())

        # ── External and local allocations for this prefix ─────────────────
        ext_allocs: list[dict] = []
        if include_external:
            cursor = await db.execute(
                """SELECT a.address, a.dns_name, a.description, a.metadata_json,
                          s.provider, s.name AS source_name
                   FROM ipam_allocations a
                   JOIN ipam_sources s ON s.id = a.source_id
                   WHERE a.prefix_subnet = ?""",
                (net_str,),
            )
            ext_allocs = rows_to_list(await cursor.fetchall())

        # ── Utilisation math ────────────────────────────────────────────────
        if prefix_len >= 31:
            usable = net.num_addresses
        else:
            usable = net.num_addresses - 2  # exclude network + broadcast

        # Count IPs covered by reservations
        reserved_ips: set[str] = set()
        for rsv in raw_reservations:
            try:
                start = ipaddress.ip_address(rsv["start_ip"])
                end = ipaddress.ip_address(rsv["end_ip"])
                cur_ip = start
                while cur_ip <= end:
                    reserved_ips.add(str(cur_ip))
                    cur_ip += 1
            except ValueError:
                continue

        reserved_count = len(reserved_ips)

        # Unique inventory IPs in subnet
        inv_unique_ips: set[str] = {h["ip"] for h in inv_in_subnet}
        # External allocation IPs
        ext_unique_ips: set[str] = set()
        for ea in ext_allocs:
            ip_s = (ea.get("address") or "").strip()
            try:
                if ipaddress.ip_address(ip_s) in net:
                    ext_unique_ips.add(ip_s)
            except ValueError:
                continue

        # Allocated = unique IPs from all sources NOT already counted as reserved
        allocated_ips = (inv_unique_ips | ext_unique_ips) - reserved_ips
        allocated_count = len(allocated_ips)

        available_count = max(0, usable - reserved_count - allocated_count)

        # ── Build allocations list ──────────────────────────────────────────
        allocations_out: list[dict] = []

        # Inventory entries (include even if reserved - flag them)
        for h in inv_in_subnet:
            ip_s = h["ip"]
            allocations_out.append({
                "ip_address": ip_s,
                "source_type": "inventory",
                "hostname": h["hostname"],
                "group_name": h["group"],
                "description": "",
                "is_reserved": ip_s in reserved_ips,
                "allocation_id": None,
            })

        # External allocations
        for ea in ext_allocs:
            ip_s = (ea.get("address") or "").strip()
            provider = ea.get("provider") or ""
            source_type = "local" if provider == "plexus" else "external"
            allocations_out.append({
                "ip_address": ip_s,
                "source_type": source_type,
                "hostname": ea.get("dns_name") or "",
                "group_name": ea.get("source_name") or "",
                "description": ea.get("description") or "",
                "is_reserved": ip_s in reserved_ips,
                "allocation_id": ea.get("id"),
            })

        # Sort by IP
        def _ip_sort_key(item: dict):
            try:
                return int(ipaddress.ip_address(item["ip_address"]))
            except ValueError:
                return 0

        allocations_out.sort(key=_ip_sort_key)

        # ── Reservations list with address_count ────────────────────────────
        reservations_out: list[dict] = []
        for rsv in raw_reservations:
            try:
                start = ipaddress.ip_address(rsv["start_ip"])
                end = ipaddress.ip_address(rsv["end_ip"])
                addr_count = max(0, int(end) - int(start) + 1)
            except ValueError:
                addr_count = 0
            reservations_out.append({
                "id": rsv.get("id"),
                "kind": "custom",
                "subnet": rsv.get("subnet"),
                "start_ip": rsv.get("start_ip"),
                "end_ip": rsv.get("end_ip"),
                "address_count": addr_count,
                "reason": rsv.get("reason") or "",
                "created_by": rsv.get("created_by") or "",
                "created_at": rsv.get("created_at"),
            })

        # ── Available preview (first N free IPs) ────────────────────────────
        occupied = reserved_ips | inv_unique_ips | ext_unique_ips
        available_preview: list[str] = []
        for addr in net.hosts():
            if len(available_preview) >= 20:
                break
            if str(addr) not in occupied:
                available_preview.append(str(addr))

        summary_out = {
            "subnet": net_str,
            "prefix_length": prefix_len,
            "inventory_host_count": len(inv_in_subnet),
            "external_allocation_count": len(ext_allocs),
            "usable_address_count": usable,
            "reserved_address_count": reserved_count,
            "allocated_address_count": allocated_count,
            "available_address_count": available_count,
        }

        return {
            "subnet": net_str,
            "summary": summary_out,
            "allocations": allocations_out,
            "reservations": reservations_out,
            "available_preview": available_preview,
        }
    finally:
        await db.close()


def _serialize_ipam_source(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "provider": row.get("provider"),
        "name": row.get("name"),
        "base_url": row.get("base_url") or "",
        "auth_type": row.get("auth_type") or "",
        "sync_scope": row.get("sync_scope") or "",
        "notes": row.get("notes") or "",
        "enabled": bool(row.get("enabled")),
        "push_enabled": bool(row.get("push_enabled", 0)),
        "verify_tls": bool(row.get("verify_tls", 1)),
        "last_sync_at": row.get("last_sync_at"),
        "last_sync_status": row.get("last_sync_status") or "never",
        "last_sync_message": row.get("last_sync_message") or "",
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "prefix_count": int(row.get("prefix_count") or 0),
        "allocation_count": int(row.get("allocation_count") or 0),
        "has_auth_config": bool(row.get("auth_config_enc")),
    }


async def list_ipam_sources(
    provider: str | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if provider:
            clauses.append("s.provider = ?")
            params.append(provider)
        if enabled_only:
            clauses.append("s.enabled = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT s.*,
                       (SELECT COUNT(*) FROM ipam_prefixes p WHERE p.source_id = s.id) AS prefix_count,
                       (SELECT COUNT(*) FROM ipam_allocations a WHERE a.source_id = s.id) AS allocation_count
                FROM ipam_sources s
                {where}
                ORDER BY s.provider ASC, s.name ASC""",
            tuple(params),
        )
        return [_serialize_ipam_source(dict(r)) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def create_ipam_source(
    provider: str,
    name: str,
    base_url: str = "",
    auth_type: str = "none",
    auth_config: dict | None = None,
    sync_scope: str = "",
    notes: str = "",
    enabled: bool = True,
    push_enabled: bool = False,
    verify_tls: bool = True,
    created_by: str = "",
) -> dict | None:
    from routes.crypto import encrypt as _enc

    auth_config_enc = ""
    if auth_config:
        auth_config_enc = _enc(json.dumps(auth_config, separators=(",", ":")))

    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO ipam_sources
               (provider, name, base_url, auth_type, auth_config_enc,
                sync_scope, notes, enabled, push_enabled, verify_tls, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                provider,
                name,
                base_url,
                auth_type,
                auth_config_enc,
                sync_scope,
                notes,
                int(bool(enabled)),
                int(bool(push_enabled)),
                int(bool(verify_tls)),
                created_by,
            ),
        )
        await db.commit()
        return await get_ipam_source(cursor.lastrowid)
    finally:
        await db.close()


async def get_ipam_source(source_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT s.*,
                      (SELECT COUNT(*) FROM ipam_prefixes p WHERE p.source_id = s.id) AS prefix_count,
                      (SELECT COUNT(*) FROM ipam_allocations a WHERE a.source_id = s.id) AS allocation_count
               FROM ipam_sources s
               WHERE s.id = ?""",
            (source_id,),
        )
        row = await cursor.fetchone()
        return _serialize_ipam_source(dict(row)) if row else None
    finally:
        await db.close()


async def get_ipam_source_auth_config(source_id: int) -> dict:
    """Return the decrypted auth_config dict for an IPAM source."""
    from routes.crypto import decrypt as _dec

    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT auth_config_enc FROM ipam_sources WHERE id = ?",
            (source_id,),
        )
        row = await cursor.fetchone()
        if not row or not row[0]:
            return {}
        try:
            return json.loads(_dec(row[0]))
        except Exception:
            return {}
    finally:
        await db.close()


async def update_ipam_source(source_id: int, **kwargs) -> dict | None:
    from routes.crypto import encrypt as _enc

    allowed = {
        "provider", "name", "base_url", "auth_type", "sync_scope",
        "notes", "enabled", "push_enabled", "verify_tls", "last_sync_at",
        "last_sync_status", "last_sync_message",
    }
    sets: list[str] = []
    vals: list = []

    # Handle auth_config dict separately (needs encryption)
    auth_config = kwargs.pop("auth_config", None)
    if auth_config is not None:
        enc = _enc(json.dumps(auth_config, separators=(",", ":")))
        sets.append("auth_config_enc = ?")
        vals.append(enc)

    for key, value in kwargs.items():
        if key not in allowed or value is None:
            continue
        if key in ("enabled", "push_enabled", "verify_tls"):
            value = int(bool(value))
        sets.append(f"{key} = ?")
        vals.append(value)

    if not sets:
        return await get_ipam_source(source_id)

    sets.append("updated_at = datetime('now')")
    db = await _dbcore.get_db()
    try:
        sql, sql_params = _safe_dynamic_update("ipam_sources", sets, vals, "id = ?", source_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_ipam_source(source_id)
    finally:
        await db.close()


async def delete_ipam_source(source_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM ipam_sources WHERE id = ?", (source_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def replace_ipam_source_snapshot(
    source_id: int,
    prefixes: list[dict],
    allocations: list[dict],
    sync_status: str = "success",
    sync_message: str = "",
) -> dict:
    """Replace all prefixes/allocations for a source and update sync status."""
    db = await _dbcore.get_db()
    try:
        # Clear existing snapshot data
        await db.execute("DELETE FROM ipam_prefixes WHERE source_id = ?", (source_id,))
        await db.execute("DELETE FROM ipam_allocations WHERE source_id = ?", (source_id,))

        prefix_count = 0
        for pref in prefixes:
            subnet = (pref.get("subnet") or "").strip()
            if not subnet:
                continue
            external_id = str(pref.get("external_id") or pref.get("id") or "")
            await db.execute(
                """INSERT OR IGNORE INTO ipam_prefixes
                   (source_id, external_id, subnet, description, vrf, vlan, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_id,
                    external_id,
                    subnet,
                    pref.get("description") or "",
                    pref.get("vrf") or "",
                    str(pref.get("vlan") or ""),
                    json.dumps(pref.get("metadata") or {}, separators=(",", ":")),
                ),
            )
            prefix_count += 1

        # Build a (subnet -> {vrf, vlan}) map to inherit context for allocations
        # whose source data does not carry VRF/VLAN explicitly.
        prefix_ctx: dict[str, dict[str, str]] = {}
        for pref in prefixes:
            sn = (pref.get("subnet") or "").strip()
            if not sn:
                continue
            prefix_ctx.setdefault(sn, {
                "vrf": str(pref.get("vrf") or ""),
                "vlan": str(pref.get("vlan") or ""),
            })

        alloc_count = 0
        for alloc in allocations:
            address = (alloc.get("address") or "").strip()
            if not address:
                continue
            prefix_subnet = (alloc.get("prefix_subnet") or "").strip()
            ctx = prefix_ctx.get(prefix_subnet, {})
            vrf_name = str(alloc.get("vrf") or alloc.get("vrf_name") or ctx.get("vrf") or "")
            vlan_id = str(alloc.get("vlan") or alloc.get("vlan_id") or ctx.get("vlan") or "")
            await db.execute(
                """INSERT OR IGNORE INTO ipam_allocations
                   (source_id, prefix_subnet, address, dns_name, status, description,
                    vrf_name, vlan_id, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_id,
                    prefix_subnet,
                    address,
                    alloc.get("dns_name") or "",
                    alloc.get("status") or "",
                    alloc.get("description") or "",
                    vrf_name,
                    vlan_id,
                    json.dumps(alloc.get("metadata") or {}, separators=(",", ":")),
                ),
            )
            alloc_count += 1

        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """UPDATE ipam_sources
               SET last_sync_at = ?,
                   last_sync_status = ?,
                   last_sync_message = ?,
                   updated_at = ?
               WHERE id = ?""",
            (now_iso, sync_status, sync_message, now_iso, source_id),
        )
        await db.commit()
        return {"prefixes": prefix_count, "allocations": alloc_count}
    finally:
        await db.close()


async def set_ipam_source_sync_status(
    source_id: int,
    status: str,
    message: str = "",
) -> None:
    """Update only the sync status fields of an IPAM source."""
    db = await _dbcore.get_db()
    try:
        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """UPDATE ipam_sources
               SET last_sync_status = ?,
                   last_sync_message = ?,
                   last_sync_at = ?,
                   updated_at = ?
               WHERE id = ?""",
            (status, message, now_iso, now_iso, source_id),
        )
        await db.commit()
    finally:
        await db.close()


async def list_ipam_reservations(subnet: str) -> list[dict]:
    """Return all custom reservations for a subnet."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        subnet_key = str(net)
    except ValueError:
        subnet_key = subnet

    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ipam_reservations WHERE subnet = ? ORDER BY start_ip",
            (subnet_key,),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def create_ipam_reservation(
    subnet: str,
    start_ip: str,
    end_ip: str,
    reason: str = "",
    created_by: str = "",
) -> dict | None:
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        subnet_key = str(net)
    except ValueError:
        subnet_key = subnet

    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO ipam_reservations (subnet, start_ip, end_ip, reason, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (subnet_key, start_ip, end_ip, reason, created_by),
        )
        await db.commit()
        rsv_id = cursor.lastrowid
        cursor2 = await db.execute(
            "SELECT * FROM ipam_reservations WHERE id = ?", (rsv_id,)
        )
        row = await cursor2.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_ipam_reservation(reservation_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM ipam_reservations WHERE id = ?", (reservation_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_or_create_builtin_ipam_source() -> dict:
    """Return the built-in Plexus IPAM source, creating it idempotently on first call."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ipam_sources WHERE provider = 'plexus' LIMIT 1"
        )
        row = await cursor.fetchone()
        if row:
            return _serialize_ipam_source(dict(row))
    finally:
        await db.close()
    # Create the built-in source
    return await create_ipam_source(
        provider="plexus",
        name="Plexus (Built-in)",
        base_url="",
        auth_type="none",
        auth_config={},
        sync_scope="",
        notes="Managed directly by Plexus. Subnets and allocations defined here are authoritative.",
        enabled=True,
        verify_tls=True,
        created_by="system",
    )


async def create_ipam_prefix(
    source_id: int,
    subnet: str,
    description: str = "",
    vrf: str = "",
    notes: str = "",
) -> dict | None:
    """Create a manually-defined subnet prefix under the given IPAM source."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        subnet_key = str(net)
    except ValueError:
        return None

    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT OR IGNORE INTO ipam_prefixes
               (source_id, external_id, subnet, description, vrf, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (source_id, subnet_key, subnet_key, description, vrf, json.dumps({"notes": notes})),
        )
        await db.commit()
        prefix_id = cursor.lastrowid
        if not prefix_id:
            # Already existed - fetch it
            cursor2 = await db.execute(
                "SELECT * FROM ipam_prefixes WHERE source_id = ? AND subnet = ? LIMIT 1",
                (source_id, subnet_key),
            )
            row = await cursor2.fetchone()
            return dict(row) if row else None
        cursor3 = await db.execute(
            "SELECT * FROM ipam_prefixes WHERE id = ?", (prefix_id,)
        )
        row = await cursor3.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_ipam_prefix(prefix_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ipam_prefixes WHERE id = ?", (prefix_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_ipam_prefix(prefix_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM ipam_prefixes WHERE id = ?", (prefix_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def create_local_ipam_allocation(
    source_id: int,
    subnet: str,
    address: str,
    hostname: str = "",
    description: str = "",
    created_by: str = "",
) -> dict | None:
    """Manually record an IP address allocation within a subnet."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        subnet_key = str(net)
        ipaddress.ip_address(address)  # validate
    except ValueError:
        return None

    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT OR IGNORE INTO ipam_allocations
               (source_id, prefix_subnet, address, dns_name, status, description, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                source_id,
                subnet_key,
                address,
                hostname,
                "active",
                description,
                json.dumps({"created_by": created_by}),
            ),
        )
        await db.commit()
        alloc_id = cursor.lastrowid
        if not alloc_id:
            cursor2 = await db.execute(
                "SELECT * FROM ipam_allocations WHERE source_id = ? AND address = ? LIMIT 1",
                (source_id, address),
            )
            row = await cursor2.fetchone()
            return dict(row) if row else None
        cursor3 = await db.execute(
            "SELECT * FROM ipam_allocations WHERE id = ?", (alloc_id,)
        )
        row = await cursor3.fetchone()
        result = dict(row) if row else None
    finally:
        await db.close()
    if result:
        try:
            await record_ip_assignment(
                address=address, hostname=hostname or "",
                vrf_name=(result.get("vrf_name") or "").strip(),
                source_type="ipam_allocation",
                source_ref=str(result.get("id") or ""),
                recorded_by=created_by or "",
                note=description or "",
            )
        except Exception as exc:
            _LOGGER.warning(
                "Failed to record IP assignment for IPAM allocation %s (%s): %s",
                result.get("id"), address, exc,
            )
    return result


async def delete_ipam_allocation(allocation_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            "SELECT address, vrf_name FROM ipam_allocations WHERE id = ?",
            (allocation_id,),
        )
        prior = await cur.fetchone()
        prior_d = dict(prior) if prior else {}
        cursor = await db.execute(
            "DELETE FROM ipam_allocations WHERE id = ?", (allocation_id,)
        )
        await db.commit()
        deleted = cursor.rowcount > 0
    finally:
        await db.close()
    if deleted and prior_d.get("address"):
        try:
            await record_ip_release(
                address=prior_d["address"],
                vrf_name=(prior_d.get("vrf_name") or "").strip(),
                note="ipam allocation deleted",
            )
        except Exception as exc:
            _LOGGER.warning(
                "Failed to record IP release for deleted IPAM allocation %s (%s): %s",
                allocation_id, prior_d.get("address"), exc,
            )
    return deleted


async def list_ipam_allocations_for_source(source_id: int) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT id, source_id, prefix_subnet, address, dns_name,
                      status, description, metadata_json, discovered_at
               FROM ipam_allocations
               WHERE source_id = ?
               ORDER BY address""",
            (source_id,),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


# ─────────────────────────────────────────────────────────────────────────────
# IPAM-driven provisioning (Phase H) – next-IP allocation w/ pending state
# ─────────────────────────────────────────────────────────────────────────────


def _serialize_pending_allocation(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "subnet": row.get("subnet") or "",
        "address": row.get("address") or "",
        "vrf_name": row.get("vrf_name") or "",
        "hostname": row.get("hostname") or "",
        "description": row.get("description") or "",
        "source_id": (int(row["source_id"]) if row.get("source_id") else None),
        "external_ref": row.get("external_ref") or "",
        "state": row.get("state") or "pending",
        "expires_at": row.get("expires_at"),
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at"),
        "committed_at": row.get("committed_at"),
        "released_at": row.get("released_at"),
    }


async def _occupied_ips_for_subnet(
    db, subnet: str, vrf_name: str
) -> set[str]:
    """Return the set of IPs already taken in this subnet+vrf.

    Combines:
      - inventory hosts (filtered to subnet, matching vrf if non-empty)
      - external/local IPAM allocations under this prefix (matching vrf when set)
      - reservations (start..end ranges)
      - active pending allocations that have not expired
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return set()
    occupied: set[str] = set()

    cursor = await db.execute(
        "SELECT ip_address, vrf_name FROM hosts WHERE ip_address != '' AND ip_address IS NOT NULL"
    )
    for row in rows_to_list(await cursor.fetchall()):
        ip_s = (row["ip_address"] or "").strip().split("/")[0]
        h_vrf = (row.get("vrf_name") or "").strip()
        if vrf_name and h_vrf != vrf_name:
            continue
        try:
            if ipaddress.ip_address(ip_s) in net:
                occupied.add(ip_s)
        except ValueError:
            continue

    cursor = await db.execute(
        "SELECT address, vrf_name FROM ipam_allocations WHERE prefix_subnet = ?",
        (str(net),),
    )
    for row in rows_to_list(await cursor.fetchall()):
        a_vrf = (row.get("vrf_name") or "").strip()
        if vrf_name and a_vrf and a_vrf != vrf_name:
            continue
        ip_s = (row.get("address") or "").strip()
        if ip_s:
            occupied.add(ip_s)

    cursor = await db.execute(
        "SELECT start_ip, end_ip FROM ipam_reservations WHERE subnet = ?",
        (str(net),),
    )
    for row in rows_to_list(await cursor.fetchall()):
        try:
            start = ipaddress.ip_address(row["start_ip"])
            end = ipaddress.ip_address(row["end_ip"])
            cur_ip = start
            while cur_ip <= end:
                occupied.add(str(cur_ip))
                cur_ip += 1
        except ValueError:
            continue

    cursor = await db.execute(
        """SELECT address, vrf_name, expires_at FROM ipam_pending_allocations
           WHERE state = 'pending' AND subnet = ?""",
        (str(net),),
    )
    now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()
    for row in rows_to_list(await cursor.fetchall()):
        p_vrf = (row.get("vrf_name") or "").strip()
        if vrf_name and p_vrf != vrf_name:
            continue
        exp = row.get("expires_at") or ""
        if exp and exp < now_iso:
            continue
        ip_s = (row.get("address") or "").strip()
        if ip_s:
            occupied.add(ip_s)

    return occupied


async def allocate_next_ip(
    *,
    subnet: str,
    vrf_name: str = "",
    hostname: str = "",
    description: str = "",
    source_id: int | None = None,
    ttl_seconds: int = 900,
    created_by: str = "",
) -> dict:
    """Reserve the first available IP in `subnet` and persist a pending row.

    Raises ValueError on bad subnet or when no addresses are available.
    Returns a serialized pending-allocation dict including `address` and `id`.
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {subnet}") from exc

    vrf_name = (vrf_name or "").strip()
    ttl = max(60, min(86400, int(ttl_seconds or 900)))
    expires_at = (datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=ttl)).isoformat()

    db = await _dbcore.get_db()
    try:
        occupied = await _occupied_ips_for_subnet(db, str(net), vrf_name)

        chosen: str | None = None
        if net.prefixlen == 32 or net.prefixlen == 128:
            candidate_iter = iter([net.network_address])
        else:
            candidate_iter = net.hosts()
        for addr in candidate_iter:
            s = str(addr)
            if s not in occupied:
                chosen = s
                break

        if chosen is None:
            raise ValueError(f"No available addresses in {net}")

        cursor = await db.execute(
            """INSERT INTO ipam_pending_allocations
                  (subnet, address, vrf_name, hostname, description,
                   source_id, state, expires_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (
                str(net),
                chosen,
                vrf_name,
                hostname or "",
                description or "",
                int(source_id) if source_id else None,
                expires_at,
                created_by or "",
            ),
        )
        await db.commit()
        pid = cursor.lastrowid
        cur2 = await db.execute(
            "SELECT * FROM ipam_pending_allocations WHERE id = ?", (pid,)
        )
        row = await cur2.fetchone()
        return _serialize_pending_allocation(dict(row)) if row else {
            "id": pid, "address": chosen, "subnet": str(net), "vrf_name": vrf_name,
            "state": "pending", "expires_at": expires_at,
        }
    finally:
        await db.close()


async def get_pending_allocation(allocation_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM ipam_pending_allocations WHERE id = ?", (int(allocation_id),)
        )
        row = await cur.fetchone()
        return _serialize_pending_allocation(dict(row)) if row else None
    finally:
        await db.close()


async def list_pending_allocations(
    state: str | None = None, include_expired: bool = False, limit: int = 200
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if state:
            clauses.append("state = ?")
            params.append(state)
        if state == "pending" and not include_expired:
            clauses.append("expires_at >= ?")
            params.append(datetime.now(UTC).replace(tzinfo=None).isoformat())
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(limit))
        cur = await db.execute(
            f"SELECT * FROM ipam_pending_allocations{where} "
            f"ORDER BY created_at DESC LIMIT ?",
            tuple(params),
        )
        rows = rows_to_list(await cur.fetchall())
        return [_serialize_pending_allocation(r) for r in rows]
    finally:
        await db.close()


async def update_pending_allocation_state(
    allocation_id: int,
    *,
    state: str,
    external_ref: str | None = None,
    source_id: int | None = None,
) -> dict | None:
    """Mark a pending allocation as committed or released."""
    if state not in ("committed", "released"):
        raise ValueError("state must be 'committed' or 'released'")
    ts_col = "committed_at" if state == "committed" else "released_at"
    db = await _dbcore.get_db()
    try:
        sets: list[str] = ["state = ?", f"{ts_col} = ?"]
        params: list = [state, datetime.now(UTC).replace(tzinfo=None).isoformat()]
        if external_ref is not None:
            sets.append("external_ref = ?")
            params.append(external_ref)
        if source_id is not None:
            sets.append("source_id = ?")
            params.append(int(source_id))
        params.append(int(allocation_id))
        await db.execute(
            f"UPDATE ipam_pending_allocations SET {', '.join(sets)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
        cur = await db.execute(
            "SELECT * FROM ipam_pending_allocations WHERE id = ?", (int(allocation_id),)
        )
        row = await cur.fetchone()
        return _serialize_pending_allocation(dict(row)) if row else None
    finally:
        await db.close()


async def expire_stale_pending_allocations() -> int:
    """Mark expired pending rows as released. Returns number of rows updated."""
    db = await _dbcore.get_db()
    try:
        now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()
        cur = await db.execute(
            """UPDATE ipam_pending_allocations
               SET state = 'released', released_at = ?
               WHERE state = 'pending' AND expires_at < ?""",
            (now_iso, now_iso),
        )
        await db.commit()
        return int(cur.rowcount or 0)
    finally:
        await db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Historical IP allocation tracking (Phase I)
# ─────────────────────────────────────────────────────────────────────────────


def _serialize_ip_history(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "address": row.get("address") or "",
        "vrf_name": row.get("vrf_name") or "",
        "hostname": row.get("hostname") or "",
        "source_type": row.get("source_type") or "",
        "source_ref": row.get("source_ref") or "",
        "started_at": row.get("started_at"),
        "ended_at": row.get("ended_at"),
        "recorded_by": row.get("recorded_by") or "",
        "note": row.get("note") or "",
    }


def _serialize_subnet_utilization(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "subnet": row.get("subnet") or "",
        "vrf_name": row.get("vrf_name") or "",
        "total": int(row.get("total") or 0),
        "used": int(row.get("used") or 0),
        "reserved": int(row.get("reserved") or 0),
        "pending": int(row.get("pending") or 0),
        "free": int(row.get("free") or 0),
        "utilization_pct": float(row.get("utilization_pct") or 0.0),
        "captured_at": row.get("captured_at"),
    }


async def record_ip_assignment(
    *,
    address: str,
    hostname: str = "",
    vrf_name: str = "",
    source_type: str = "",
    source_ref: str = "",
    recorded_by: str = "",
    note: str = "",
) -> dict | None:
    """Record that `address` (in optional VRF) is now assigned to `hostname`.

    Closes any existing open history row for the same (address, vrf) before
    inserting the new open row, so the timeline stays consistent. No-op if
    the address is already open with the same hostname/source.
    """
    address = (address or "").strip()
    if not address:
        return None
    try:
        ipaddress.ip_address(address.split("/")[0])
    except ValueError:
        return None
    vrf_name = (vrf_name or "").strip()
    now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()

    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            """SELECT id, hostname, source_type, source_ref FROM ipam_ip_history
               WHERE address = ? AND vrf_name = ? AND ended_at IS NULL
               ORDER BY started_at DESC LIMIT 1""",
            (address, vrf_name),
        )
        existing = await cur.fetchone()
        if existing:
            existing_d = dict(existing)
            if (
                (existing_d.get("hostname") or "") == hostname
                and (existing_d.get("source_type") or "") == source_type
                and (existing_d.get("source_ref") or "") == source_ref
            ):
                cur2 = await db.execute(
                    "SELECT * FROM ipam_ip_history WHERE id = ?", (existing_d["id"],)
                )
                row = await cur2.fetchone()
                return _serialize_ip_history(dict(row)) if row else None
            await db.execute(
                "UPDATE ipam_ip_history SET ended_at = ? WHERE id = ?",
                (now_iso, existing_d["id"]),
            )

        cur3 = await db.execute(
            """INSERT INTO ipam_ip_history
                  (address, vrf_name, hostname, source_type, source_ref,
                   started_at, recorded_by, note)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                address,
                vrf_name,
                hostname or "",
                source_type or "",
                source_ref or "",
                now_iso,
                recorded_by or "",
                note or "",
            ),
        )
        await db.commit()
        new_id = cur3.lastrowid
        cur4 = await db.execute(
            "SELECT * FROM ipam_ip_history WHERE id = ?", (new_id,)
        )
        row = await cur4.fetchone()
        return _serialize_ip_history(dict(row)) if row else None
    finally:
        await db.close()


async def record_ip_release(
    *,
    address: str,
    vrf_name: str = "",
    recorded_by: str = "",
    note: str = "",
) -> int:
    """Close the open history row for (address, vrf). Returns rows updated."""
    address = (address or "").strip()
    if not address:
        return 0
    vrf_name = (vrf_name or "").strip()
    now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            """UPDATE ipam_ip_history
               SET ended_at = ?,
                   note = CASE WHEN ? = '' THEN note ELSE ? END
               WHERE address = ? AND vrf_name = ? AND ended_at IS NULL""",
            (now_iso, note or "", note or "", address, vrf_name),
        )
        # recorded_by is intentionally not stored on release - it's an event,
        # not a new assignment. Caller can pass via note if needed.
        _ = recorded_by
        await db.commit()
        return int(cur.rowcount or 0)
    finally:
        await db.close()


async def get_ip_history(
    address: str,
    vrf_name: str = "",
    limit: int = 100,
) -> list[dict]:
    """Return assignment history for an IP, newest first."""
    address = (address or "").strip()
    if not address:
        return []
    vrf_name = (vrf_name or "").strip()
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            """SELECT * FROM ipam_ip_history
               WHERE address = ? AND vrf_name = ?
               ORDER BY started_at DESC LIMIT ?""",
            (address, vrf_name, int(limit)),
        )
        rows = rows_to_list(await cur.fetchall())
        return [_serialize_ip_history(r) for r in rows]
    finally:
        await db.close()


async def find_ip_owner_at(
    address: str,
    when_iso: str,
    vrf_name: str = "",
) -> dict | None:
    """Who held `address` at timestamp `when_iso`? Returns the matching history row or None."""
    address = (address or "").strip()
    when_iso = (when_iso or "").strip()
    if not address or not when_iso:
        return None
    vrf_name = (vrf_name or "").strip()
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            """SELECT * FROM ipam_ip_history
               WHERE address = ? AND vrf_name = ?
                 AND started_at <= ?
                 AND (ended_at IS NULL OR ended_at >= ?)
               ORDER BY started_at DESC LIMIT 1""",
            (address, vrf_name, when_iso, when_iso),
        )
        row = await cur.fetchone()
        return _serialize_ip_history(dict(row)) if row else None
    finally:
        await db.close()


async def list_ip_history_for_hostname(
    hostname: str, limit: int = 200
) -> list[dict]:
    """All IPs ever assigned to `hostname`, newest first."""
    hostname = (hostname or "").strip()
    if not hostname:
        return []
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            """SELECT * FROM ipam_ip_history
               WHERE hostname = ?
               ORDER BY started_at DESC LIMIT ?""",
            (hostname, int(limit)),
        )
        rows = rows_to_list(await cur.fetchall())
        return [_serialize_ip_history(r) for r in rows]
    finally:
        await db.close()


async def snapshot_subnet_utilization(
    subnet: str, vrf_name: str = ""
) -> dict | None:
    """Compute utilization for a subnet+vrf and persist a time-series row."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None
    vrf_name = (vrf_name or "").strip()
    sn = str(net)

    if net.prefixlen == 32 or net.prefixlen == 128:
        total = 1
        host_iter = [net.network_address]
    else:
        total = max(0, net.num_addresses - 2)
        host_iter = list(net.hosts())
    host_set = {str(h) for h in host_iter}

    db = await _dbcore.get_db()
    try:
        used_set: set[str] = set()
        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts WHERE ip_address != '' AND ip_address IS NOT NULL"
        )
        for row in rows_to_list(await cur.fetchall()):
            ip_s = (row["ip_address"] or "").strip().split("/")[0]
            h_vrf = (row.get("vrf_name") or "").strip()
            if vrf_name and h_vrf != vrf_name:
                continue
            if ip_s in host_set:
                used_set.add(ip_s)

        cur = await db.execute(
            "SELECT address, vrf_name FROM ipam_allocations WHERE prefix_subnet = ?",
            (sn,),
        )
        for row in rows_to_list(await cur.fetchall()):
            a_vrf = (row.get("vrf_name") or "").strip()
            if vrf_name and a_vrf and a_vrf != vrf_name:
                continue
            ip_s = (row.get("address") or "").strip()
            if ip_s in host_set:
                used_set.add(ip_s)

        reserved_set: set[str] = set()
        cur = await db.execute(
            "SELECT start_ip, end_ip FROM ipam_reservations WHERE subnet = ?",
            (sn,),
        )
        for row in rows_to_list(await cur.fetchall()):
            try:
                start = ipaddress.ip_address(row["start_ip"])
                end = ipaddress.ip_address(row["end_ip"])
                cur_ip = start
                while cur_ip <= end:
                    s = str(cur_ip)
                    if s in host_set:
                        reserved_set.add(s)
                    cur_ip += 1
            except ValueError:
                continue

        pending_set: set[str] = set()
        now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat()
        cur = await db.execute(
            """SELECT address, vrf_name, expires_at FROM ipam_pending_allocations
               WHERE state = 'pending' AND subnet = ?""",
            (sn,),
        )
        for row in rows_to_list(await cur.fetchall()):
            p_vrf = (row.get("vrf_name") or "").strip()
            if vrf_name and p_vrf != vrf_name:
                continue
            exp = row.get("expires_at") or ""
            if exp and exp < now_iso:
                continue
            ip_s = (row.get("address") or "").strip()
            if ip_s in host_set:
                pending_set.add(ip_s)

        # Sets may overlap; deduplicate so counts sum correctly.
        used = len(used_set)
        reserved = len(reserved_set - used_set)
        pending = len(pending_set - used_set - reserved_set)
        consumed = used + reserved + pending
        free = max(0, total - consumed)
        pct = (consumed / total * 100.0) if total > 0 else 0.0

        cur = await db.execute(
            """INSERT INTO ipam_subnet_utilization
                  (subnet, vrf_name, total, used, reserved, pending, free, utilization_pct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (sn, vrf_name, total, used, reserved, pending, free, pct),
        )
        await db.commit()
        new_id = cur.lastrowid
        cur2 = await db.execute(
            "SELECT * FROM ipam_subnet_utilization WHERE id = ?", (new_id,)
        )
        row = await cur2.fetchone()
        return _serialize_subnet_utilization(dict(row)) if row else None
    finally:
        await db.close()


async def snapshot_all_subnet_utilization() -> int:
    """Snapshot utilization for every (subnet, vrf) Plexus knows about.

    Subnet sources: external/local IPAM prefixes plus inferred-from-inventory
    subnets. Returns the number of snapshot rows written.
    """
    pairs: set[tuple[str, str]] = set()
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            "SELECT DISTINCT subnet, vrf FROM ipam_prefixes WHERE subnet IS NOT NULL AND subnet != ''"
        )
        for row in rows_to_list(await cur.fetchall()):
            sn = (row.get("subnet") or "").strip()
            vrf = (row.get("vrf") or "").strip()
            if sn:
                pairs.add((sn, vrf))

        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts WHERE ip_address != '' AND ip_address IS NOT NULL"
        )
        for row in rows_to_list(await cur.fetchall()):
            ip_s = (row["ip_address"] or "").strip().split("/")[0]
            vrf = (row.get("vrf_name") or "").strip()
            sn = _infer_subnet(ip_s)
            if sn:
                pairs.add((sn, vrf))
    finally:
        await db.close()

    written = 0
    for subnet, vrf in pairs:
        result = await snapshot_subnet_utilization(subnet, vrf)
        if result is not None:
            written += 1
    return written


async def list_subnet_utilization(
    subnet: str | None = None,
    vrf_name: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """Return time-series utilization rows, newest first."""
    clauses: list[str] = []
    params: list = []
    if subnet:
        clauses.append("subnet = ?")
        params.append(subnet)
    if vrf_name is not None:
        clauses.append("vrf_name = ?")
        params.append(vrf_name)
    if since:
        clauses.append("captured_at >= ?")
        params.append(since)
    if until:
        clauses.append("captured_at <= ?")
        params.append(until)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(int(limit))
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            f"SELECT * FROM ipam_subnet_utilization{where} "
            f"ORDER BY captured_at DESC LIMIT ?",
            tuple(params),
        )
        rows = rows_to_list(await cur.fetchall())
        return [_serialize_subnet_utilization(r) for r in rows]
    finally:
        await db.close()


async def prune_ip_history(retention_days: int = 365) -> int:
    """Delete closed history rows older than retention_days. Returns rows removed."""
    if retention_days <= 0:
        return 0
    cutoff = (
        datetime.now(UTC).replace(tzinfo=None) - timedelta(days=int(retention_days))
    ).isoformat()
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            "DELETE FROM ipam_ip_history WHERE ended_at IS NOT NULL AND ended_at < ?",
            (cutoff,),
        )
        await db.commit()
        return int(cur.rowcount or 0)
    finally:
        await db.close()


async def prune_subnet_utilization(retention_days: int = 365) -> int:
    """Delete utilization snapshots older than retention_days."""
    if retention_days <= 0:
        return 0
    cutoff = (
        datetime.now(UTC).replace(tzinfo=None) - timedelta(days=int(retention_days))
    ).isoformat()
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            "DELETE FROM ipam_subnet_utilization WHERE captured_at < ?",
            (cutoff,),
        )
        await db.commit()
        return int(cur.rowcount or 0)
    finally:
        await db.close()


# ─────────────────────────────────────────────────────────────────────────────
# IPAM Reporting (Phase J)
# ─────────────────────────────────────────────────────────────────────────────


async def generate_ipam_utilization_report_data(
    vrf_name: str | None = None,
    threshold_pct: float = 0.0,
) -> list[dict]:
    """Latest utilization snapshot per (subnet, vrf), filtered by threshold.

    Returns one row per known (subnet, vrf), using the most recent snapshot.
    Falls back to a live snapshot computation for subnets that have never been
    captured. Sorted by utilization_pct descending so capacity-planning
    audiences see the most-stressed subnets first.
    """
    pairs: set[tuple[str, str]] = set()
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            "SELECT DISTINCT subnet, vrf FROM ipam_prefixes "
            "WHERE subnet IS NOT NULL AND subnet != ''"
        )
        for row in rows_to_list(await cur.fetchall()):
            sn = (row.get("subnet") or "").strip()
            v = (row.get("vrf") or "").strip()
            if sn and (vrf_name is None or v == vrf_name):
                pairs.add((sn, v))
        cur = await db.execute(
            "SELECT DISTINCT subnet, vrf_name FROM ipam_subnet_utilization"
        )
        for row in rows_to_list(await cur.fetchall()):
            sn = (row.get("subnet") or "").strip()
            v = (row.get("vrf_name") or "").strip()
            if sn and (vrf_name is None or v == vrf_name):
                pairs.add((sn, v))
        cur = await db.execute(
            "SELECT ip_address, vrf_name FROM hosts "
            "WHERE ip_address IS NOT NULL AND ip_address != ''"
        )
        for row in rows_to_list(await cur.fetchall()):
            ip_s = (row.get("ip_address") or "").strip().split("/")[0]
            v = (row.get("vrf_name") or "").strip()
            if vrf_name is not None and v != vrf_name:
                continue
            sn = _infer_subnet(ip_s)
            if sn:
                pairs.add((sn, v))
    finally:
        await db.close()

    rows: list[dict] = []
    for subnet, vrf in pairs:
        snap = None
        existing = await list_subnet_utilization(
            subnet=subnet, vrf_name=vrf, limit=1
        )
        if existing:
            snap = existing[0]
        else:
            snap = await snapshot_subnet_utilization(subnet, vrf)
        if not snap:
            continue
        pct = float(snap.get("utilization_pct") or 0.0)
        if pct < float(threshold_pct):
            continue
        rows.append(
            {
                "subnet": snap.get("subnet"),
                "vrf_name": snap.get("vrf_name") or "",
                "total": int(snap.get("total") or 0),
                "used": int(snap.get("used") or 0),
                "reserved": int(snap.get("reserved") or 0),
                "pending": int(snap.get("pending") or 0),
                "free": int(snap.get("free") or 0),
                "utilization_pct": round(pct, 2),
                "captured_at": snap.get("captured_at"),
            }
        )
    rows.sort(key=lambda r: (-r["utilization_pct"], r["subnet"]))
    return rows


def _linear_forecast(
    points: list[tuple[float, float]], target_pct: float
) -> tuple[float | None, float | None]:
    """Least-squares linear fit over (t, util%) points.

    Returns (slope_per_day, days_to_target). Slope is utilization_pct change
    per day. days_to_target is days from the most recent point until
    util reaches `target_pct`; None if non-positive slope or already past.
    """
    if len(points) < 2:
        return (None, None)
    n = float(len(points))
    sum_x = sum(p[0] for p in points)
    sum_y = sum(p[1] for p in points)
    sum_xy = sum(p[0] * p[1] for p in points)
    sum_xx = sum(p[0] * p[0] for p in points)
    denom = n * sum_xx - sum_x * sum_x
    if denom == 0:
        return (None, None)
    slope = (n * sum_xy - sum_x * sum_y) / denom  # pct per second
    last_t, last_y = points[-1]
    slope_per_day = slope * 86400.0
    if slope <= 0 or last_y >= target_pct:
        return (slope_per_day, None)
    secs = (target_pct - last_y) / slope
    return (slope_per_day, secs / 86400.0)


async def generate_ipam_forecast_report_data(
    vrf_name: str | None = None,
    lookback_days: int = 30,
    target_pct: float = 90.0,
    min_points: int = 2,
) -> list[dict]:
    """Project subnet exhaustion using a linear fit over recent snapshots.

    Per (subnet, vrf), fit a line through utilization_pct samples in the
    lookback window and project days-until-target. Subnets with fewer than
    `min_points` samples are reported with status="insufficient_data" so the
    report always covers the full inventory.
    """
    cutoff = (
        datetime.now(UTC).replace(tzinfo=None) - timedelta(days=int(lookback_days))
    ).isoformat()
    db = await _dbcore.get_db()
    try:
        clauses = ["captured_at >= ?"]
        params: list = [cutoff]
        if vrf_name is not None:
            clauses.append("vrf_name = ?")
            params.append(vrf_name)
        where = " WHERE " + " AND ".join(clauses)
        cur = await db.execute(
            f"SELECT subnet, vrf_name, captured_at, total, used, reserved, "
            f"pending, free, utilization_pct FROM ipam_subnet_utilization{where} "
            f"ORDER BY subnet, vrf_name, captured_at ASC",
            tuple(params),
        )
        snapshot_rows = rows_to_list(await cur.fetchall())
    finally:
        await db.close()

    grouped: dict[tuple[str, str], list[dict]] = {}
    for r in snapshot_rows:
        key = ((r.get("subnet") or "").strip(), (r.get("vrf_name") or "").strip())
        grouped.setdefault(key, []).append(r)

    rows: list[dict] = []
    for (subnet, vrf), samples in grouped.items():
        if not subnet:
            continue
        latest = samples[-1]
        latest_pct = float(latest.get("utilization_pct") or 0.0)
        if len(samples) < int(min_points):
            rows.append(
                {
                    "subnet": subnet,
                    "vrf_name": vrf,
                    "samples": len(samples),
                    "current_utilization_pct": round(latest_pct, 2),
                    "slope_pct_per_day": None,
                    "days_to_target": None,
                    "projected_exhaustion_at": None,
                    "target_pct": float(target_pct),
                    "status": "insufficient_data",
                }
            )
            continue
        points: list[tuple[float, float]] = []
        for s in samples:
            ts = s.get("captured_at") or ""
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", ""))
            except ValueError:
                continue
            points.append((dt.timestamp(), float(s.get("utilization_pct") or 0.0)))
        slope, days_to_target = _linear_forecast(points, float(target_pct))
        projected_at: str | None = None
        status = "stable"
        if days_to_target is not None and days_to_target > 0:
            projected_dt = datetime.now(UTC).replace(tzinfo=None) + timedelta(
                days=days_to_target
            )
            projected_at = projected_dt.isoformat()
            if days_to_target <= 30:
                status = "critical"
            elif days_to_target <= 90:
                status = "warning"
            else:
                status = "ok"
        elif latest_pct >= float(target_pct):
            status = "exhausted"
        rows.append(
            {
                "subnet": subnet,
                "vrf_name": vrf,
                "samples": len(samples),
                "current_utilization_pct": round(latest_pct, 2),
                "slope_pct_per_day": (
                    round(slope, 4) if slope is not None else None
                ),
                "days_to_target": (
                    round(days_to_target, 1) if days_to_target is not None else None
                ),
                "projected_exhaustion_at": projected_at,
                "target_pct": float(target_pct),
                "status": status,
            }
        )
    # Sort: critical first, then by days_to_target ascending (None last).
    status_order = {
        "exhausted": 0, "critical": 1, "warning": 2, "ok": 3,
        "stable": 4, "insufficient_data": 5,
    }
    rows.sort(
        key=lambda r: (
            status_order.get(r["status"], 99),
            r["days_to_target"] if r["days_to_target"] is not None else 1e9,
            r["subnet"],
        )
    )
    return rows


async def generate_ipam_history_report_data(
    address: str | None = None,
    hostname: str | None = None,
    vrf_name: str | None = None,
    days: int = 90,
    limit: int = 1000,
) -> list[dict]:
    """Per-IP assignment history rows for forensic/audit reports."""
    cutoff = (
        datetime.now(UTC).replace(tzinfo=None) - timedelta(days=int(days))
    ).isoformat()
    clauses = ["started_at >= ?"]
    params: list = [cutoff]
    if address:
        clauses.append("address = ?")
        params.append(address)
    if hostname:
        clauses.append("hostname = ?")
        params.append(hostname)
    if vrf_name is not None:
        clauses.append("vrf_name = ?")
        params.append(vrf_name)
    where = " WHERE " + " AND ".join(clauses)
    params.append(int(limit))
    db = await _dbcore.get_db()
    try:
        cur = await db.execute(
            f"SELECT address, vrf_name, hostname, source_type, source_ref, "
            f"started_at, ended_at, recorded_by, note FROM ipam_ip_history{where} "
            f"ORDER BY started_at DESC LIMIT ?",
            tuple(params),
        )
        rows = rows_to_list(await cur.fetchall())
    finally:
        await db.close()
    out: list[dict] = []
    for r in rows:
        started = r.get("started_at")
        ended = r.get("ended_at")
        duration_s: float | None = None
        if started:
            try:
                s = datetime.fromisoformat(str(started).replace("Z", ""))
                e = (
                    datetime.fromisoformat(str(ended).replace("Z", ""))
                    if ended else datetime.now(UTC).replace(tzinfo=None)
                )
                duration_s = (e - s).total_seconds()
            except ValueError:
                duration_s = None
        out.append(
            {
                "address": r.get("address"),
                "vrf_name": r.get("vrf_name") or "",
                "hostname": r.get("hostname") or "",
                "source_type": r.get("source_type") or "",
                "source_ref": r.get("source_ref") or "",
                "started_at": started,
                "ended_at": ended,
                "duration_hours": (
                    round(duration_s / 3600.0, 2) if duration_s is not None else None
                ),
                "recorded_by": r.get("recorded_by") or "",
                "note": r.get("note") or "",
            }
        )
    return out


# ─────────────────────────────────────────────────────────────────────────────
# IPAM Reconciliation – runs and diffs
# ─────────────────────────────────────────────────────────────────────────────


def _serialize_reconciliation_run(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "source_id": int(row.get("source_id") or 0),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "status": row.get("status") or "running",
        "triggered_by": row.get("triggered_by") or "",
        "diff_count": int(row.get("diff_count") or 0),
        "resolved_count": int(row.get("resolved_count") or 0),
        "message": row.get("message") or "",
    }


def _serialize_reconciliation_diff(row: dict) -> dict:
    plexus_state = row.get("plexus_state_json") or "{}"
    ipam_state = row.get("ipam_state_json") or "{}"
    try:
        plexus_obj = json.loads(plexus_state) if isinstance(plexus_state, str) else plexus_state
    except Exception:
        plexus_obj = {}
    try:
        ipam_obj = json.loads(ipam_state) if isinstance(ipam_state, str) else ipam_state
    except Exception:
        ipam_obj = {}
    return {
        "id": int(row.get("id") or 0),
        "run_id": int(row.get("run_id") or 0),
        "source_id": int(row.get("source_id") or 0),
        "address": row.get("address") or "",
        "drift_type": row.get("drift_type") or "",
        "plexus_state": plexus_obj,
        "ipam_state": ipam_obj,
        "resolution": row.get("resolution") or "",
        "resolved_by": row.get("resolved_by") or "",
        "resolved_at": row.get("resolved_at"),
        "resolution_message": row.get("resolution_message") or "",
        "created_at": row.get("created_at"),
    }


async def create_reconciliation_run(source_id: int, triggered_by: str = "") -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO ipam_reconciliation_runs (source_id, status, triggered_by)
               VALUES (?, 'running', ?)""",
            (source_id, triggered_by),
        )
        await db.commit()
        run_id = cursor.lastrowid
        if not run_id:
            return None
        cur2 = await db.execute(
            "SELECT * FROM ipam_reconciliation_runs WHERE id = ?", (run_id,)
        )
        row = await cur2.fetchone()
        return _serialize_reconciliation_run(dict(row)) if row else None
    finally:
        await db.close()


async def finalize_reconciliation_run(
    run_id: int,
    *,
    status: str,
    diff_count: int,
    message: str = "",
) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE ipam_reconciliation_runs
               SET status = ?, diff_count = ?, message = ?,
                   finished_at = datetime('now')
               WHERE id = ?""",
            (status, int(diff_count), message, run_id),
        )
        await db.commit()
    finally:
        await db.close()


async def insert_reconciliation_diff(
    *,
    run_id: int,
    source_id: int,
    address: str,
    drift_type: str,
    plexus_state: dict | None = None,
    ipam_state: dict | None = None,
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO ipam_reconciliation_diffs
               (run_id, source_id, address, drift_type,
                plexus_state_json, ipam_state_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                source_id,
                address,
                drift_type,
                json.dumps(plexus_state or {}, separators=(",", ":")),
                json.dumps(ipam_state or {}, separators=(",", ":")),
            ),
        )
        await db.commit()
        return int(cursor.lastrowid or 0)
    finally:
        await db.close()


async def list_reconciliation_runs(
    source_id: int | None = None,
    limit: int = 50,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        if source_id is not None:
            cursor = await db.execute(
                """SELECT * FROM ipam_reconciliation_runs
                   WHERE source_id = ?
                   ORDER BY started_at DESC, id DESC
                   LIMIT ?""",
                (source_id, int(max(1, limit))),
            )
        else:
            cursor = await db.execute(
                """SELECT * FROM ipam_reconciliation_runs
                   ORDER BY started_at DESC, id DESC
                   LIMIT ?""",
                (int(max(1, limit)),),
            )
        return [_serialize_reconciliation_run(dict(r)) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def list_reconciliation_diffs(
    *,
    source_id: int | None = None,
    run_id: int | None = None,
    open_only: bool = True,
    limit: int = 500,
) -> list[dict]:
    clauses: list[str] = []
    params: list = []
    if source_id is not None:
        clauses.append("source_id = ?")
        params.append(source_id)
    if run_id is not None:
        clauses.append("run_id = ?")
        params.append(run_id)
    if open_only:
        clauses.append("(resolution IS NULL OR resolution = '')")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(int(max(1, limit)))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"""SELECT * FROM ipam_reconciliation_diffs
                {where}
                ORDER BY id DESC
                LIMIT ?""",
            tuple(params),
        )
        return [_serialize_reconciliation_diff(dict(r)) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_reconciliation_diff(diff_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ipam_reconciliation_diffs WHERE id = ?", (diff_id,)
        )
        row = await cursor.fetchone()
        return _serialize_reconciliation_diff(dict(row)) if row else None
    finally:
        await db.close()


async def mark_reconciliation_diff_resolved(
    diff_id: int,
    *,
    resolution: str,
    resolved_by: str,
    message: str = "",
) -> dict | None:
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE ipam_reconciliation_diffs
               SET resolution = ?, resolved_by = ?, resolution_message = ?,
                   resolved_at = datetime('now')
               WHERE id = ? AND (resolution IS NULL OR resolution = '')""",
            (resolution, resolved_by, message, diff_id),
        )
        await db.commit()
        cursor = await db.execute(
            "SELECT * FROM ipam_reconciliation_diffs WHERE id = ?", (diff_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        diff = _serialize_reconciliation_diff(dict(row))
        # Bump resolved counter on parent run
        await db.execute(
            """UPDATE ipam_reconciliation_runs
               SET resolved_count = resolved_count + 1
               WHERE id = ?""",
            (diff.get("run_id"),),
        )
        await db.commit()
        return diff
    finally:
        await db.close()


# ─────────────────────────────────────────────────────────────────────────────
# DHCP – Servers, Scopes, and Leases
# ─────────────────────────────────────────────────────────────────────────────


def _serialize_dhcp_server(row: dict) -> dict:
    return {
        "id": int(row.get("id") or 0),
        "provider": row.get("provider") or "",
        "name": row.get("name") or "",
        "base_url": row.get("base_url") or "",
        "auth_type": row.get("auth_type") or "",
        "notes": row.get("notes") or "",
        "enabled": bool(row.get("enabled")),
        "verify_tls": bool(row.get("verify_tls", 1)),
        "last_sync_at": row.get("last_sync_at"),
        "last_sync_status": row.get("last_sync_status") or "never",
        "last_sync_message": row.get("last_sync_message") or "",
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "scope_count": int(row.get("scope_count") or 0),
        "lease_count": int(row.get("lease_count") or 0),
        "has_auth_config": bool(row.get("auth_config_enc")),
    }


async def list_dhcp_servers(enabled_only: bool = False) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        where = " WHERE s.enabled = 1" if enabled_only else ""
        cursor = await db.execute(
            f"""SELECT s.*,
                       (SELECT COUNT(*) FROM dhcp_scopes p WHERE p.server_id = s.id) AS scope_count,
                       (SELECT COUNT(*) FROM dhcp_leases l WHERE l.server_id = s.id) AS lease_count
                FROM dhcp_servers s
                {where}
                ORDER BY s.provider ASC, s.name ASC"""
        )
        return [_serialize_dhcp_server(dict(r)) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def get_dhcp_server(server_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT s.*,
                      (SELECT COUNT(*) FROM dhcp_scopes p WHERE p.server_id = s.id) AS scope_count,
                      (SELECT COUNT(*) FROM dhcp_leases l WHERE l.server_id = s.id) AS lease_count
               FROM dhcp_servers s
               WHERE s.id = ?""",
            (server_id,),
        )
        row = await cursor.fetchone()
        return _serialize_dhcp_server(dict(row)) if row else None
    finally:
        await db.close()


async def create_dhcp_server(
    provider: str,
    name: str,
    base_url: str = "",
    auth_type: str = "none",
    auth_config: dict | None = None,
    notes: str = "",
    enabled: bool = True,
    verify_tls: bool = True,
    created_by: str = "",
) -> dict | None:
    from routes.crypto import encrypt as _enc

    auth_config_enc = ""
    if auth_config:
        auth_config_enc = _enc(json.dumps(auth_config, separators=(",", ":")))

    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO dhcp_servers
               (provider, name, base_url, auth_type, auth_config_enc,
                notes, enabled, verify_tls, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                provider,
                name,
                base_url,
                auth_type,
                auth_config_enc,
                notes,
                int(bool(enabled)),
                int(bool(verify_tls)),
                created_by,
            ),
        )
        await db.commit()
        return await get_dhcp_server(cursor.lastrowid)
    finally:
        await db.close()


async def update_dhcp_server(server_id: int, **kwargs) -> dict | None:
    from routes.crypto import encrypt as _enc

    allowed = {
        "provider", "name", "base_url", "auth_type", "notes",
        "enabled", "verify_tls", "last_sync_at", "last_sync_status",
        "last_sync_message",
    }
    sets: list[str] = []
    vals: list = []

    auth_config = kwargs.pop("auth_config", None)
    if auth_config is not None:
        enc = _enc(json.dumps(auth_config, separators=(",", ":")))
        sets.append("auth_config_enc = ?")
        vals.append(enc)

    for key, value in kwargs.items():
        if key not in allowed or value is None:
            continue
        if key in ("enabled", "verify_tls"):
            value = int(bool(value))
        sets.append(f"{key} = ?")
        vals.append(value)

    if not sets:
        return await get_dhcp_server(server_id)

    sets.append("updated_at = datetime('now')")
    db = await _dbcore.get_db()
    try:
        sql, sql_params = _safe_dynamic_update("dhcp_servers", sets, vals, "id = ?", server_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_dhcp_server(server_id)
    finally:
        await db.close()


async def delete_dhcp_server(server_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM dhcp_servers WHERE id = ?", (server_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_dhcp_server_auth_config(server_id: int) -> dict:
    from routes.crypto import decrypt as _dec

    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT auth_config_enc FROM dhcp_servers WHERE id = ?",
            (server_id,),
        )
        row = await cursor.fetchone()
        if not row or not row[0]:
            return {}
        try:
            return json.loads(_dec(row[0]))
        except Exception:
            return {}
    finally:
        await db.close()


async def replace_dhcp_server_snapshot(
    server_id: int,
    scopes: list[dict],
    leases: list[dict],
    sync_status: str = "success",
    sync_message: str = "",
) -> dict:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM dhcp_scopes WHERE server_id = ?", (server_id,))
        await db.execute("DELETE FROM dhcp_leases WHERE server_id = ?", (server_id,))

        scope_count = 0
        for sc in scopes:
            subnet = (sc.get("subnet") or "").strip()
            if not subnet:
                continue
            await db.execute(
                """INSERT OR IGNORE INTO dhcp_scopes
                   (server_id, external_id, subnet, name, range_start, range_end,
                    total_addresses, used_addresses, free_addresses, state, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    server_id,
                    str(sc.get("external_id") or ""),
                    subnet,
                    sc.get("name") or "",
                    sc.get("range_start") or "",
                    sc.get("range_end") or "",
                    int(sc.get("total_addresses") or 0),
                    int(sc.get("used_addresses") or 0),
                    int(sc.get("free_addresses") or 0),
                    sc.get("state") or "",
                    json.dumps(sc.get("metadata") or {}, separators=(",", ":")),
                ),
            )
            scope_count += 1

        lease_count = 0
        for lease in leases:
            address = (lease.get("address") or "").strip()
            if not address:
                continue
            await db.execute(
                """INSERT OR IGNORE INTO dhcp_leases
                   (server_id, scope_subnet, address, mac_address, hostname,
                    client_id, state, starts_at, ends_at, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    server_id,
                    lease.get("scope_subnet") or "",
                    address,
                    lease.get("mac_address") or "",
                    lease.get("hostname") or "",
                    lease.get("client_id") or "",
                    lease.get("state") or "",
                    lease.get("starts_at") or None,
                    lease.get("ends_at") or None,
                    json.dumps(lease.get("metadata") or {}, separators=(",", ":")),
                ),
            )
            lease_count += 1

        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """UPDATE dhcp_servers
               SET last_sync_at = ?, last_sync_status = ?,
                   last_sync_message = ?, updated_at = ?
               WHERE id = ?""",
            (now_iso, sync_status, sync_message, now_iso, server_id),
        )
        await db.commit()
        return {"scopes": scope_count, "leases": lease_count}
    finally:
        await db.close()


async def set_dhcp_server_sync_status(
    server_id: int,
    status: str,
    message: str = "",
) -> None:
    db = await _dbcore.get_db()
    try:
        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """UPDATE dhcp_servers
               SET last_sync_status = ?, last_sync_message = ?,
                   last_sync_at = ?, updated_at = ?
               WHERE id = ?""",
            (status, message, now_iso, now_iso, server_id),
        )
        await db.commit()
    finally:
        await db.close()


async def list_dhcp_scopes(server_id: int | None = None) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        if server_id is not None:
            cursor = await db.execute(
                """SELECT * FROM dhcp_scopes WHERE server_id = ?
                   ORDER BY subnet""",
                (server_id,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM dhcp_scopes ORDER BY server_id, subnet"
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def list_dhcp_leases(
    server_id: int | None = None,
    scope_subnet: str | None = None,
    limit: int = 500,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if server_id is not None:
            clauses.append("server_id = ?")
            params.append(server_id)
        if scope_subnet:
            clauses.append("scope_subnet = ?")
            params.append(scope_subnet)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(int(max(1, min(limit, 5000))))
        cursor = await db.execute(
            f"SELECT * FROM dhcp_leases{where} ORDER BY address LIMIT ?",
            tuple(params),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


