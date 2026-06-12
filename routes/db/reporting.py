"""Reporting persistence helpers.

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
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "create_report_definition",
    "get_report_definition",
    "list_report_definitions",
    "delete_report_definition",
    "update_report_definition_last_run",
    "create_report_run",
    "complete_report_run",
    "create_report_artifact",
    "get_report_artifacts",
    "get_report_artifact",
    "delete_old_report_runs",
    "get_report_runs",
    "get_report_run",
    "generate_availability_report_data",
    "generate_compliance_report_data",
    "generate_interface_report_data",
    "generate_network_documentation_report_data",
]

# ═════════════════════════════════════════════════════════════════════════════
# Reporting & Export
# ═════════════════════════════════════════════════════════════════════════════


async def create_report_definition(
    name: str, report_type: str = "availability",
    parameters_json: str = "{}", schedule: str = "",
    created_by: str = "",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO report_definitions
               (name, report_type, parameters_json, schedule, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (name, report_type, parameters_json, schedule, created_by),
        )
        await db.commit()
        rid = cursor.lastrowid
        return (await get_report_definition(rid)) or {}
    finally:
        await db.close()


async def get_report_definition(report_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM report_definitions WHERE id = ?", (report_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_report_definitions() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM report_definitions ORDER BY updated_at DESC"
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def delete_report_definition(report_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM report_definitions WHERE id = ?", (report_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def update_report_definition_last_run(report_id: int) -> None:
    """Mark a report definition as having just run."""
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE report_definitions
               SET last_run_at = datetime('now'),
                   updated_at = datetime('now')
               WHERE id = ?""",
            (report_id,),
        )
        await db.commit()
    finally:
        await db.close()


async def create_report_run(
    report_id: int | None, report_type: str,
    parameters_json: str = "{}",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO report_runs
               (report_id, report_type, parameters_json, status)
               VALUES (?, ?, ?, 'running')""",
            (report_id, report_type, parameters_json),
        )
        await db.commit()
        rid = cursor.lastrowid
        rcursor = await db.execute("SELECT * FROM report_runs WHERE id = ?", (rid,))
        row = await rcursor.fetchone()
        return dict(row) if row else {}
    finally:
        await db.close()


async def complete_report_run(
    run_id: int, result_json: str, row_count: int, status: str = "completed",
) -> None:
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """UPDATE report_runs
               SET result_json = ?, row_count = ?, status = ?,
                   completed_at = datetime('now')
               WHERE id = ?""",
            (result_json, row_count, status, run_id),
        )
        await db.commit()
    finally:
        await db.close()


async def create_report_artifact(
    run_id: int,
    report_id: int | None,
    artifact_type: str,
    file_name: str,
    media_type: str,
    content_text: str | None = None,
    content_blob: bytes | None = None,
) -> dict:
    """Persist a generated report artifact (CSV/SVG/etc.)."""
    db = await _dbcore.get_db()
    try:
        blob_payload = None
        text_payload = ""
        if content_blob is not None:
            blob_payload = bytes(content_blob)
            size_bytes = len(blob_payload)
        else:
            text_payload = content_text if isinstance(content_text, str) else str(content_text or "")
            size_bytes = len(text_payload.encode("utf-8"))
        cursor = await db.execute(
            """INSERT INTO report_artifacts
               (run_id, report_id, artifact_type, file_name, media_type, content_text, content_blob, size_bytes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, report_id, artifact_type, file_name, media_type, text_payload, blob_payload, size_bytes),
        )
        await db.commit()
        artifact_id = cursor.lastrowid
        rcursor = await db.execute(
            """SELECT id, run_id, report_id, artifact_type, file_name, media_type, size_bytes, created_at
               FROM report_artifacts WHERE id = ?""",
            (artifact_id,),
        )
        row = await rcursor.fetchone()
        return dict(row) if row else {}
    finally:
        await db.close()


async def get_report_artifacts(
    run_id: int,
    limit: int = 20,
) -> list[dict]:
    """List report artifacts for a run (without content payload)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT id, run_id, report_id, artifact_type, file_name, media_type, size_bytes, created_at
               FROM report_artifacts
               WHERE run_id = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (run_id, limit),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_report_artifact(artifact_id: int) -> dict | None:
    """Get one report artifact including content payload."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM report_artifacts WHERE id = ?",
            (artifact_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_old_report_runs(days: int = 90) -> int:
    """Delete report runs older than N days (artifacts cascade)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM report_runs WHERE started_at < datetime('now', '-' || ? || ' days')",
            (max(1, int(days)),),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def get_report_runs(report_id: int | None = None, limit: int = 50) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        if report_id is not None:
            cursor = await db.execute(
                "SELECT * FROM report_runs WHERE report_id = ? ORDER BY started_at DESC LIMIT ?",
                (report_id, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM report_runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_report_run(run_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM report_runs WHERE id = ?", (run_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def generate_availability_report_data(
    group_id: int | None = None,
    days: int = 30,
) -> list[dict]:
    """Generate availability report rows for CSV export."""
    db = await _dbcore.get_db()
    try:
        group_filter = ""
        params: list = [days]
        if group_id is not None:
            group_filter = "AND h.group_id = ?"
            params.append(group_id)

        cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.hostname, h.ip_address, h.device_type,
                       ig.name AS group_name,
                       COUNT(p.id) AS total_polls,
                       SUM(CASE WHEN p.poll_status = 'ok' THEN 1 ELSE 0 END) AS ok_polls,
                       AVG(p.response_time_ms) AS avg_latency_ms,
                       MAX(p.response_time_ms) AS max_latency_ms,
                       AVG(p.packet_loss_pct) AS avg_packet_loss_pct,
                       AVG(p.cpu_percent) AS avg_cpu,
                       AVG(p.memory_percent) AS avg_memory,
                       (SELECT COUNT(*) FROM availability_transitions t
                        WHERE t.host_id = h.id AND t.entity_type = 'host'
                          AND t.new_state = 'down'
                          AND t.transition_at >= datetime('now', '-' || ? || ' days')
                       ) AS outage_count
                FROM hosts h
                LEFT JOIN monitoring_polls p ON p.host_id = h.id
                  AND p.polled_at >= datetime('now', '-' || ? || ' days')
                LEFT JOIN inventory_groups ig ON ig.id = h.group_id
                WHERE 1=1 {group_filter}
                GROUP BY h.id
                ORDER BY h.hostname""",
            tuple(params + [days]),
        )
        rows = rows_to_list(await cursor.fetchall())
        for r in rows:
            total = r["total_polls"] or 1
            ok = r["ok_polls"] or 0
            r["uptime_pct"] = round(ok / total * 100, 3)
            for k in ("avg_latency_ms", "max_latency_ms", "avg_packet_loss_pct", "avg_cpu", "avg_memory"):
                if r.get(k) is not None:
                    r[k] = round(r[k], 2)
        return rows
    finally:
        await db.close()


async def generate_compliance_report_data(
    group_id: int | None = None,
) -> list[dict]:
    """Generate compliance report rows for CSV export."""
    db = await _dbcore.get_db()
    try:
        group_filter = ""
        params: list = []
        if group_id is not None:
            group_filter = "WHERE h.group_id = ?"
            params.append(group_id)

        cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.hostname, h.ip_address, h.device_type,
                       ig.name AS group_name,
                       csr.profile_id, cp.name AS profile_name,
                       csr.status, csr.total_rules, csr.passed_rules, csr.failed_rules,
                       csr.scanned_at
                FROM compliance_scan_results csr
                JOIN hosts h ON h.id = csr.host_id
                LEFT JOIN inventory_groups ig ON ig.id = h.group_id
                LEFT JOIN compliance_profiles cp ON cp.id = csr.profile_id
                {group_filter}
                ORDER BY csr.scanned_at DESC""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def generate_interface_report_data(
    host_id: int | None = None,
    group_id: int | None = None,
    days: int = 1,
) -> list[dict]:
    """Generate interface utilization report rows for CSV export."""
    db = await _dbcore.get_db()
    try:
        clauses = ["1=1"]
        params: list = [days]
        if host_id is not None:
            clauses.append("h.id = ?")
            params.append(host_id)
        if group_id is not None:
            clauses.append("h.group_id = ?")
            params.append(group_id)
        where = " AND ".join(clauses)

        cursor = await db.execute(
            f"""SELECT h.hostname, h.ip_address,
                       its.if_index, its.if_name, its.if_speed_mbps,
                       COUNT(*) AS samples,
                       AVG(its.in_rate_bps) AS avg_in_bps,
                       AVG(its.out_rate_bps) AS avg_out_bps,
                       MAX(its.in_rate_bps) AS peak_in_bps,
                       MAX(its.out_rate_bps) AS peak_out_bps,
                       AVG(its.utilization_pct) AS avg_util,
                       MAX(its.utilization_pct) AS peak_util
                FROM interface_ts its
                JOIN hosts h ON h.id = its.host_id
                WHERE its.sampled_at >= datetime('now', '-' || ? || ' days')
                  AND {where}
                GROUP BY its.host_id, its.if_index
                ORDER BY h.hostname, its.if_name""",
            tuple(params),
        )
        rows = rows_to_list(await cursor.fetchall())
        for r in rows:
            for k in ("avg_in_bps", "avg_out_bps", "peak_in_bps", "peak_out_bps", "avg_util", "peak_util"):
                if r.get(k) is not None:
                    r[k] = round(r[k], 2)
        return rows
    finally:
        await db.close()


def _infer_ip_network(ip_text: str) -> str:
    """Infer a network CIDR from a host address.

    If CIDR is present, use it directly. For plain host addresses, infer
    /24 for IPv4 and /64 for IPv6 so documentation can still produce an IP plan
    when explicit prefixes are not stored.
    """
    value = str(ip_text or "").strip()
    if not value:
        return ""
    try:
        if "/" in value:
            return str(ipaddress.ip_interface(value).network)
        ip_obj = ipaddress.ip_address(value)
        default_prefix = 24 if ip_obj.version == 4 else 64
        return str(ipaddress.ip_network(f"{value}/{default_prefix}", strict=False))
    except Exception:
        return ""


def _normalize_iface_for_doc(name: str) -> str:
    """Normalize interface names for loose circuit/link matching."""
    value = str(name or "").strip().lower()
    if not value:
        return ""
    value = re.sub(r"\s+", "", value)
    value = (
        value.replace("tengigabitethernet", "te")
        .replace("gigabitethernet", "gi")
        .replace("fastethernet", "fa")
        .replace("port-channel", "po")
        .replace("ethernet", "eth")
    )
    return value


async def generate_network_documentation_report_data(
    group_id: int | None = None,
) -> list[dict]:
    """Generate flattened rows for automated network documentation.

    Sections included:
      - summary
      - inventory
      - topology_link
      - ip_plan
      - vlan_map
      - circuit_map
    """
    db = await _dbcore.get_db()
    try:
        host_where = ""
        host_params: list = []
        if group_id is not None:
            host_where = "WHERE h.group_id = ?"
            host_params.append(group_id)

        host_cursor = await db.execute(
            f"""SELECT h.id AS host_id, h.group_id, h.hostname, h.ip_address,
                       h.device_type, h.status, h.model, h.software_version,
                       ig.name AS group_name
                FROM hosts h
                LEFT JOIN inventory_groups ig ON ig.id = h.group_id
                {host_where}
                ORDER BY ig.name, h.hostname, h.ip_address""",
            tuple(host_params),
        )
        hosts = rows_to_list(await host_cursor.fetchall())

        link_where = ""
        link_params: list = []
        if group_id is not None:
            link_where = "WHERE sh.group_id = ?"
            link_params.append(group_id)

        link_cursor = await db.execute(
            f"""SELECT tl.source_host_id,
                       sh.hostname AS source_hostname,
                       tl.source_interface,
                       tl.target_host_id,
                       COALESCE(th.hostname, tl.target_device_name, '') AS target_device_name,
                       COALESCE(th.ip_address, tl.target_ip, '') AS target_ip,
                       tl.target_interface,
                       tl.protocol
                FROM topology_links tl
                JOIN hosts sh ON sh.id = tl.source_host_id
                LEFT JOIN hosts th ON th.id = tl.target_host_id
                {link_where}
                ORDER BY sh.hostname, tl.source_interface, target_device_name""",
            tuple(link_params),
        )
        links = rows_to_list(await link_cursor.fetchall())

        circuit_where = ""
        circuit_params: list = []
        if group_id is not None:
            circuit_where = "WHERE h.group_id = ?"
            circuit_params.append(group_id)

        circuit_cursor = await db.execute(
            f"""SELECT bc.id AS circuit_id,
                       bc.name AS circuit_name,
                       bc.description AS circuit_description,
                       bc.customer AS circuit_customer,
                       bc.host_id AS circuit_host_id,
                       bc.if_index AS circuit_if_index,
                       bc.if_name AS circuit_if_name,
                       bc.commit_rate_bps,
                       bc.burst_limit_bps,
                       bc.enabled AS circuit_enabled,
                       h.hostname AS circuit_hostname,
                       h.ip_address AS circuit_host_ip,
                       h.group_id AS circuit_group_id,
                       ig.name AS circuit_group_name
                FROM billing_circuits bc
                LEFT JOIN hosts h ON h.id = bc.host_id
                LEFT JOIN inventory_groups ig ON ig.id = h.group_id
                {circuit_where}
                ORDER BY bc.customer, bc.name, h.hostname, bc.if_name""",
            tuple(circuit_params),
        )
        circuits = rows_to_list(await circuit_cursor.fetchall())

        vlan_where = ""
        vlan_params: list = []
        if group_id is not None:
            vlan_where = "WHERE h.group_id = ?"
            vlan_params.append(group_id)

        vlan_cursor = await db.execute(
            f"""SELECT m.vlan AS vlan_id,
                       COUNT(*) AS mac_entry_count,
                       COUNT(DISTINCT m.host_id) AS vlan_device_count
                FROM mac_address_table m
                JOIN hosts h ON h.id = m.host_id
                {vlan_where}
                GROUP BY m.vlan
                ORDER BY m.vlan""",
            tuple(vlan_params),
        )
        vlan_rows = rows_to_list(await vlan_cursor.fetchall())

        if not vlan_rows:
            stp_cursor = await db.execute(
                f"""SELECT s.vlan_id,
                           COUNT(DISTINCT s.host_id) AS vlan_device_count,
                           COUNT(*) AS port_state_count
                    FROM stp_port_states s
                    JOIN hosts h ON h.id = s.host_id
                    {vlan_where}
                    GROUP BY s.vlan_id
                    ORDER BY s.vlan_id""",
                tuple(vlan_params),
            )
            stp_rows = rows_to_list(await stp_cursor.fetchall())
            vlan_rows = [
                {
                    "vlan_id": row.get("vlan_id"),
                    "mac_entry_count": 0,
                    "vlan_device_count": row.get("vlan_device_count", 0),
                    "details": f"Derived from STP port states ({int(row.get('port_state_count', 0))} entries)",
                }
                for row in stp_rows
            ]

        group_name_by_host = {
            int(h.get("host_id")): str(h.get("group_name") or "")
            for h in hosts
            if h.get("host_id") is not None
        }

        circuits_by_host_iface: dict[tuple[int, str], dict] = {}
        for circuit in circuits:
            host_id = int(circuit.get("circuit_host_id") or 0)
            iface_key = _normalize_iface_for_doc(str(circuit.get("circuit_if_name") or ""))
            if host_id <= 0 or not iface_key:
                continue
            circuits_by_host_iface[(host_id, iface_key)] = circuit

        subnet_map: dict[str, dict[str, set[str]]] = {}
        for host in hosts:
            subnet = _infer_ip_network(str(host.get("ip_address") or ""))
            if not subnet:
                continue
            entry = subnet_map.setdefault(subnet, {"hosts": set(), "groups": set()})
            hostname = str(host.get("hostname") or f"host-{host.get('host_id')}")
            if hostname:
                entry["hosts"].add(hostname)
            group_name = str(host.get("group_name") or "").strip()
            if group_name:
                entry["groups"].add(group_name)

        def _row(section: str) -> dict:
            return {
                "section": section,
                "group_name": "",
                "host_id": "",
                "hostname": "",
                "ip_address": "",
                "device_type": "",
                "status": "",
                "model": "",
                "software_version": "",
                "source_host_id": "",
                "source_hostname": "",
                "source_interface": "",
                "target_host_id": "",
                "target_device_name": "",
                "target_ip": "",
                "target_interface": "",
                "protocol": "",
                "subnet": "",
                "subnet_host_count": "",
                "vlan_id": "",
                "vlan_device_count": "",
                "mac_entry_count": "",
                "circuit_id": "",
                "circuit_name": "",
                "circuit_customer": "",
                "circuit_if_index": "",
                "circuit_if_name": "",
                "circuit_commit_mbps": "",
                "circuit_burst_mbps": "",
                "circuit_enabled": "",
                "details": "",
            }

        rows: list[dict] = []

        for host in hosts:
            row = _row("inventory")
            row.update(
                {
                    "group_name": host.get("group_name") or "",
                    "host_id": host.get("host_id") or "",
                    "hostname": host.get("hostname") or "",
                    "ip_address": host.get("ip_address") or "",
                    "device_type": host.get("device_type") or "",
                    "status": host.get("status") or "",
                    "model": host.get("model") or "",
                    "software_version": host.get("software_version") or "",
                }
            )
            rows.append(row)

        for link in links:
            row = _row("topology_link")
            src_host_id = int(link.get("source_host_id") or 0)
            src_iface = str(link.get("source_interface") or "")
            circuit = circuits_by_host_iface.get(
                (src_host_id, _normalize_iface_for_doc(src_iface))
            )
            details = ""
            if circuit:
                commit_mbps = round(float(circuit.get("commit_rate_bps") or 0) / 1_000_000, 3)
                details = (
                    f"Circuit {circuit.get('circuit_name', '')} "
                    f"(customer={circuit.get('circuit_customer', '')}, commit={commit_mbps} Mbps)"
                )
            row.update(
                {
                    "group_name": group_name_by_host.get(src_host_id, ""),
                    "source_host_id": link.get("source_host_id") or "",
                    "source_hostname": link.get("source_hostname") or "",
                    "source_interface": src_iface,
                    "target_host_id": link.get("target_host_id") or "",
                    "target_device_name": link.get("target_device_name") or "",
                    "target_ip": link.get("target_ip") or "",
                    "target_interface": link.get("target_interface") or "",
                    "protocol": link.get("protocol") or "",
                    "circuit_id": circuit.get("circuit_id") if circuit else "",
                    "circuit_name": circuit.get("circuit_name") if circuit else "",
                    "circuit_customer": circuit.get("circuit_customer") if circuit else "",
                    "circuit_if_index": circuit.get("circuit_if_index") if circuit else "",
                    "circuit_if_name": circuit.get("circuit_if_name") if circuit else "",
                    "circuit_commit_mbps": round(float(circuit.get("commit_rate_bps") or 0) / 1_000_000, 3) if circuit else "",
                    "circuit_burst_mbps": round(float(circuit.get("burst_limit_bps") or 0) / 1_000_000, 3) if circuit else "",
                    "circuit_enabled": int(circuit.get("circuit_enabled") or 0) if circuit else "",
                    "details": details,
                }
            )
            rows.append(row)

        def _subnet_sort_key(subnet: str) -> tuple:
            try:
                net = ipaddress.ip_network(subnet, strict=False)
                return (net.version, int(net.network_address), net.prefixlen)
            except Exception:
                return (99, subnet, 0)

        for subnet in sorted(subnet_map.keys(), key=_subnet_sort_key):
            entry = subnet_map[subnet]
            host_names = sorted(entry["hosts"])
            group_names = sorted(entry["groups"])
            preview = ", ".join(host_names[:6])
            if len(host_names) > 6:
                preview = f"{preview} +{len(host_names) - 6} more"

            row = _row("ip_plan")
            row.update(
                {
                    "group_name": ", ".join(group_names),
                    "subnet": subnet,
                    "subnet_host_count": len(host_names),
                    "details": preview,
                }
            )
            rows.append(row)

        for vlan in vlan_rows:
            row = _row("vlan_map")
            row.update(
                {
                    "vlan_id": vlan.get("vlan_id") or "",
                    "vlan_device_count": vlan.get("vlan_device_count") or 0,
                    "mac_entry_count": vlan.get("mac_entry_count") or 0,
                    "details": vlan.get("details") or "",
                }
            )
            rows.append(row)

        for circuit in circuits:
            row = _row("circuit_map")
            commit_mbps = round(float(circuit.get("commit_rate_bps") or 0) / 1_000_000, 3)
            burst_mbps = round(float(circuit.get("burst_limit_bps") or 0) / 1_000_000, 3)
            row.update(
                {
                    "group_name": circuit.get("circuit_group_name") or "",
                    "host_id": circuit.get("circuit_host_id") or "",
                    "hostname": circuit.get("circuit_hostname") or "",
                    "ip_address": circuit.get("circuit_host_ip") or "",
                    "circuit_id": circuit.get("circuit_id") or "",
                    "circuit_name": circuit.get("circuit_name") or "",
                    "circuit_customer": circuit.get("circuit_customer") or "",
                    "circuit_if_index": circuit.get("circuit_if_index") or "",
                    "circuit_if_name": circuit.get("circuit_if_name") or "",
                    "circuit_commit_mbps": commit_mbps,
                    "circuit_burst_mbps": burst_mbps,
                    "circuit_enabled": int(circuit.get("circuit_enabled") or 0),
                    "details": circuit.get("circuit_description") or "",
                }
            )
            rows.append(row)

        summary = _row("summary")
        summary["details"] = (
            f"devices={len(hosts)} links={len(links)} subnets={len(subnet_map)} "
            f"vlans={len(vlan_rows)} circuits={len(circuits)}"
        )
        rows.insert(0, summary)

        return rows
    finally:
        await db.close()


