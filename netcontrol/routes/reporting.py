"""
reporting.py -- Report generation and CSV export for availability,
compliance, and interface utilization data.
"""

import asyncio
import csv
import io
import json
import logging
import math
import os
import re
from datetime import UTC, datetime
from xml.sax.saxutils import escape as _xml_escape

import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

router = APIRouter()
LOGGER = configure_logging("plexus.reporting")

REPORT_SCHEDULER_ENABLED = os.getenv("APP_REPORT_SCHEDULER_ENABLED", "true").strip().lower() not in {
    "0", "false", "no", "off",
}
REPORT_SCHEDULER_POLL_SECONDS = max(
    30, int(os.getenv("APP_REPORT_SCHEDULER_POLL_SECONDS", "60"))
)
REPORT_SCHEDULER_MAX_RUNS_PER_CYCLE = max(
    1, min(50, int(os.getenv("APP_REPORT_SCHEDULER_MAX_RUNS_PER_CYCLE", "10")))
)
REPORT_RUN_RETENTION_DAYS = max(
    7, int(os.getenv("APP_REPORT_RUN_RETENTION_DAYS", "120"))
)


class ReportDefinitionCreate(BaseModel):
    name: str
    report_type: str = "availability"
    parameters_json: str = "{}"
    schedule: str = ""


# ── Report Definitions CRUD ──────────────────────────────────────────────────


@router.get("/api/reports")
async def list_reports():
    return {"reports": await db.list_report_definitions()}


@router.post("/api/reports", status_code=201)
async def create_report(payload: ReportDefinitionCreate, request: Request):
    user = getattr(request.state, "user", None) or {}
    owner = user.get("username", "") if isinstance(user, dict) else ""
    report = await db.create_report_definition(
        name=payload.name,
        report_type=payload.report_type,
        parameters_json=payload.parameters_json,
        schedule=payload.schedule,
        created_by=owner,
    )
    LOGGER.info("Report created: %s (id=%s)", payload.name, report.get("id"))
    return report


@router.delete("/api/reports/{report_id}")
async def delete_report(report_id: int):
    deleted = await db.delete_report_definition(report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "deleted"}


@router.get("/api/reports/runs")
async def list_report_runs(
    report_id: int | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
):
    return {"runs": await db.get_report_runs(report_id, limit)}


# ── Report Generation ────────────────────────────────────────────────────────


_SCHEDULE_TOKEN_RE = re.compile(r"^\s*(?:every\s+)?(\d+)\s*([smhdw])\s*$")


def _parse_schedule_interval_seconds(schedule: str) -> int | None:
    """Parse report schedule text into an interval in seconds."""
    raw = str(schedule or "").strip().lower()
    if not raw or raw in {"off", "none", "disabled", "manual"}:
        return None

    named = {
        "@hourly": 3600,
        "hourly": 3600,
        "@daily": 86400,
        "daily": 86400,
        "@weekly": 7 * 86400,
        "weekly": 7 * 86400,
        "@monthly": 30 * 86400,
        "monthly": 30 * 86400,
    }
    if raw in named:
        return named[raw]

    match = _SCHEDULE_TOKEN_RE.match(raw)
    if not match:
        return None

    amount = max(1, int(match.group(1)))
    unit = match.group(2)
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}[unit]
    return amount * multiplier


def _parse_report_params(parameters_json: str | dict | None) -> dict:
    if isinstance(parameters_json, dict):
        return parameters_json
    if not parameters_json:
        return {}
    try:
        parsed = json.loads(parameters_json)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _parse_db_datetime_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        candidate = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(candidate)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except Exception:
        return None


def _is_report_definition_due(report_def: dict, now_utc: datetime) -> bool:
    interval = _parse_schedule_interval_seconds(str(report_def.get("schedule") or ""))
    if not interval:
        return False
    last_run = _parse_db_datetime_utc(report_def.get("last_run_at"))
    if last_run is None:
        return True
    elapsed = (now_utc - last_run).total_seconds()
    return elapsed >= interval


async def _generate_report_rows(report_type: str, params: dict) -> list[dict]:
    group_id = params.get("group_id")
    days = params.get("days", 30)
    host_id = params.get("host_id")

    if report_type == "availability":
        return await db.generate_availability_report_data(group_id, days)
    if report_type == "compliance":
        return await db.generate_compliance_report_data(group_id)
    if report_type == "interface":
        return await db.generate_interface_report_data(host_id, group_id, days)
    if report_type == "network_documentation":
        return await db.generate_network_documentation_report_data(group_id)
    raise HTTPException(status_code=400, detail=f"Unknown report type: {report_type}")


def _scheduled_filename_prefix(report_type: str) -> str:
    safe = re.sub(r"[^a-z0-9_]+", "_", str(report_type or "report").strip().lower())
    safe = safe.strip("_") or "report"
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{safe}_{stamp}"


async def _persist_report_artifacts(
    run_id: int,
    report_id: int | None,
    report_type: str,
    rows: list[dict],
    params: dict,
) -> list[dict]:
    """Persist generated artifacts for a report run."""
    artifacts: list[dict] = []
    prefix = _scheduled_filename_prefix(report_type)

    csv_data = _rows_to_csv(rows)
    artifacts.append(
        await db.create_report_artifact(
            run_id=run_id,
            report_id=report_id,
            artifact_type="csv",
            file_name=f"{prefix}.csv",
            media_type="text/csv",
            content_text=csv_data,
        )
    )

    if report_type == "network_documentation":
        group_id = params.get("group_id")
        graph = await _build_network_doc_topology(group_id)
        svg = _render_network_doc_svg(graph, group_id)
        pdf_bytes = _render_network_doc_pdf(rows, group_id=group_id)
        artifacts.append(
            await db.create_report_artifact(
                run_id=run_id,
                report_id=report_id,
                artifact_type="svg",
                file_name=f"{prefix}.svg",
                media_type="image/svg+xml",
                content_text=svg,
            )
        )
        artifacts.append(
            await db.create_report_artifact(
                run_id=run_id,
                report_id=report_id,
                artifact_type="pdf",
                file_name=f"{prefix}.pdf",
                media_type="application/pdf",
                content_blob=pdf_bytes,
            )
        )

    return artifacts


async def _execute_report_run(
    *,
    report_id: int | None,
    report_type: str,
    params: dict,
    persist_artifacts: bool = False,
    include_rows: bool = True,
) -> dict:
    """Execute one report run, persist run status/results, and optionally artifacts."""
    run = await db.create_report_run(
        report_id=report_id,
        report_type=report_type,
        parameters_json=json.dumps(params),
    )

    artifacts: list[dict] = []
    try:
        rows = await _generate_report_rows(report_type, params)

        await db.complete_report_run(
            run["id"], json.dumps(rows, default=str), len(rows), "completed"
        )

        if persist_artifacts:
            artifacts = await _persist_report_artifacts(
                run_id=run["id"],
                report_id=report_id,
                report_type=report_type,
                rows=rows,
                params=params,
            )

        response = {
            "run_id": run["id"],
            "report_type": report_type,
            "row_count": len(rows),
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
        }
        if include_rows:
            response["rows"] = rows
        return response
    except HTTPException:
        await db.complete_report_run(run["id"], "{}", 0, "error")
        raise
    except Exception as exc:
        LOGGER.error("Report generation failed (type=%s): %s", report_type, exc)
        await db.complete_report_run(run["id"], json.dumps({"error": "generation_failed"}), 0, "error")
        raise HTTPException(status_code=500, detail="Report generation failed — see server logs")


async def _run_scheduled_reports_once() -> dict:
    """Execute due scheduled report definitions exactly once."""
    if not REPORT_SCHEDULER_ENABLED:
        return {"enabled": False, "definitions_checked": 0, "due": 0, "ran": 0, "errors": 0}

    definitions = await db.list_report_definitions()
    now_utc = datetime.now(UTC)
    due_defs = [d for d in definitions if _is_report_definition_due(d, now_utc)]
    due_defs = due_defs[:REPORT_SCHEDULER_MAX_RUNS_PER_CYCLE]

    ran = 0
    errors = 0
    for report_def in due_defs:
        report_id = int(report_def.get("id") or 0)
        report_type = str(report_def.get("report_type") or "availability").strip().lower()
        params = _parse_report_params(report_def.get("parameters_json"))

        try:
            await _execute_report_run(
                report_id=report_id,
                report_type=report_type,
                params=params,
                persist_artifacts=True,
                include_rows=False,
            )
            await db.update_report_definition_last_run(report_id)
            ran += 1
        except HTTPException as exc:
            errors += 1
            LOGGER.warning(
                "report scheduler: report_id=%s type=%s failed: %s",
                report_id,
                report_type,
                exc.detail,
            )
        except Exception as exc:
            errors += 1
            LOGGER.warning(
                "report scheduler: report_id=%s type=%s failed: %s",
                report_id,
                report_type,
                exc,
            )

    if ran > 0:
        try:
            await db.delete_old_report_runs(REPORT_RUN_RETENTION_DAYS)
        except Exception as exc:
            LOGGER.warning("report scheduler: retention cleanup failed: %s", exc)

    if ran > 0:
        increment_metric("reporting.scheduler.success")
    if errors > 0:
        increment_metric("reporting.scheduler.failed")

    return {
        "enabled": True,
        "definitions_checked": len(definitions),
        "due": len(due_defs),
        "ran": ran,
        "errors": errors,
    }


async def _report_scheduler_loop() -> None:
    """Background loop that runs due scheduled reports."""
    while True:
        try:
            await asyncio.sleep(REPORT_SCHEDULER_POLL_SECONDS)
            result = await _run_scheduled_reports_once()
            if result.get("ran", 0) > 0 or result.get("errors", 0) > 0:
                LOGGER.info(
                    "report scheduler: checked=%d due=%d ran=%d errors=%d",
                    int(result.get("definitions_checked", 0)),
                    int(result.get("due", 0)),
                    int(result.get("ran", 0)),
                    int(result.get("errors", 0)),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("report scheduler loop failure: %s", redact_value(str(exc)))
            increment_metric("reporting.scheduler.failed")
            await asyncio.sleep(REPORT_SCHEDULER_POLL_SECONDS)


async def _build_network_doc_topology(group_id: int | None = None) -> dict:
    """Build lightweight topology graph data for documentation export."""
    links = await db.get_topology_links(group_id)

    nodes_by_id: dict[str | int, dict] = {}
    edges: list[dict] = []

    source_host_ids = {int(link["source_host_id"]) for link in links if link.get("source_host_id")}
    target_host_ids = {
        int(link["target_host_id"]) for link in links if link.get("target_host_id")
    }
    all_host_ids = source_host_ids | target_host_ids

    hosts = await db.get_hosts_by_ids(list(all_host_ids)) if all_host_ids else []
    host_ids = {int(h["id"]) for h in hosts}

    if group_id is not None:
        group_hosts = await db.get_hosts_for_group(group_id)
        for host in group_hosts:
            hid = int(host["id"])
            if hid not in host_ids:
                hosts.append(host)
                host_ids.add(hid)

    groups = await db.get_all_groups()
    group_name_map = {int(g["id"]): g["name"] for g in groups}

    for host in hosts:
        hid = int(host["id"])
        nodes_by_id[hid] = {
            "id": hid,
            "label": host.get("hostname") or f"host-{hid}",
            "ip": host.get("ip_address") or "",
            "device_type": host.get("device_type") or "",
            "group_name": group_name_map.get(int(host.get("group_id") or 0), ""),
            "in_inventory": True,
        }

    for link in links:
        source_id = int(link["source_host_id"])
        target_host_id = link.get("target_host_id")
        target_name = str(link.get("target_device_name") or "").strip()
        target_ip = str(link.get("target_ip") or "").strip()

        if target_host_id and int(target_host_id) in nodes_by_id:
            target_id: str | int = int(target_host_id)
        else:
            norm_name = target_name.lower().split(".")[0] if target_name else ""
            norm_ip = target_ip
            ext_key = f"ext_{norm_name}" if norm_name else f"ext_{norm_ip or 'unknown'}"
            target_id = ext_key
            if ext_key not in nodes_by_id:
                nodes_by_id[ext_key] = {
                    "id": ext_key,
                    "label": target_name or target_ip or "unknown",
                    "ip": target_ip,
                    "device_type": "unknown",
                    "group_name": "",
                    "in_inventory": False,
                }

        edges.append(
            {
                "id": int(link.get("id") or 0),
                "from": source_id,
                "to": target_id,
                "protocol": str(link.get("protocol") or "cdp").strip().lower(),
                "source_interface": str(link.get("source_interface") or "").strip(),
                "target_interface": str(link.get("target_interface") or "").strip(),
            }
        )

    return {"nodes": list(nodes_by_id.values()), "edges": edges}


def _protocol_color(protocol: str) -> str:
    if protocol == "lldp":
        return "#00a86b"
    if protocol == "ospf":
        return "#ff8f00"
    if protocol == "bgp":
        return "#6a1b9a"
    return "#0277bd"  # cdp/default


def _render_network_doc_svg(graph: dict, group_id: int | None = None) -> str:
    """Render a static SVG network diagram from topology nodes/edges."""
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    width = max(1200, min(2400, 700 + len(nodes) * 30))
    height = max(780, min(1600, 520 + len(nodes) * 22))

    title = "Plexus Network Documentation Diagram"
    subtitle = f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')}"
    if group_id is not None:
        subtitle = f"{subtitle}  |  Group ID: {group_id}"

    if not nodes:
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="#f5f8fb"/>
  <text x="{width // 2}" y="{height // 2 - 20}" text-anchor="middle" font-family="Arial, sans-serif" font-size="28" fill="#1f2937">{_xml_escape(title)}</text>
  <text x="{width // 2}" y="{height // 2 + 18}" text-anchor="middle" font-family="Arial, sans-serif" font-size="16" fill="#6b7280">No topology nodes available for export.</text>
</svg>"""

    cx = width / 2
    cy = (height / 2) + 18
    radius = max(180.0, min(width, height) * 0.34)

    ordered_nodes = sorted(nodes, key=lambda n: str(n.get("label") or n.get("id")))
    positions: dict[str | int, tuple[float, float]] = {}
    total = len(ordered_nodes)

    if total == 1:
        only = ordered_nodes[0]
        positions[only["id"]] = (cx, cy)
    else:
        for idx, node in enumerate(ordered_nodes):
            angle = (2 * math.pi * idx / total) - (math.pi / 2)
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            positions[node["id"]] = (x, y)

    edge_parts: list[str] = []
    edge_label_parts: list[str] = []
    for edge in edges:
        src = edge.get("from")
        dst = edge.get("to")
        if src not in positions or dst not in positions:
            continue
        x1, y1 = positions[src]
        x2, y2 = positions[dst]
        color = _protocol_color(str(edge.get("protocol") or ""))
        edge_parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{color}" stroke-width="2.2" stroke-opacity="0.85" />'
        )

        src_if = str(edge.get("source_interface") or "").strip()
        dst_if = str(edge.get("target_interface") or "").strip()
        iface_label = " -> ".join([part for part in (src_if, dst_if) if part])
        if iface_label:
            mx = (x1 + x2) / 2
            my = (y1 + y2) / 2
            edge_label_parts.append(
                f'<text x="{mx:.1f}" y="{my:.1f}" text-anchor="middle" '
                'font-family="Arial, sans-serif" font-size="10" fill="#334155" '
                'stroke="#ffffff" stroke-width="2" paint-order="stroke fill">'
                f'{_xml_escape(iface_label)}</text>'
            )

    node_parts: list[str] = []
    for node in ordered_nodes:
        x, y = positions[node["id"]]
        label = str(node.get("label") or node.get("id"))
        ip = str(node.get("ip") or "")
        group_name = str(node.get("group_name") or "")
        in_inventory = bool(node.get("in_inventory"))

        fill = "#2563eb" if in_inventory else "#64748b"
        stroke = "#1e40af" if in_inventory else "#334155"

        node_parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="24" fill="{fill}" stroke="{stroke}" stroke-width="2" />'
        )
        node_parts.append(
            f'<text x="{x:.1f}" y="{(y + 42):.1f}" text-anchor="middle" '
            'font-family="Arial, sans-serif" font-size="12" fill="#0f172a">'
            f'{_xml_escape(label)}</text>'
        )
        if ip:
            node_parts.append(
                f'<text x="{x:.1f}" y="{(y + 56):.1f}" text-anchor="middle" '
                'font-family="Arial, sans-serif" font-size="10" fill="#475569">'
                f'{_xml_escape(ip)}</text>'
            )
        if group_name:
            node_parts.append(
                f'<text x="{x:.1f}" y="{(y - 33):.1f}" text-anchor="middle" '
                'font-family="Arial, sans-serif" font-size="10" fill="#64748b">'
                f'{_xml_escape(group_name)}</text>'
            )

    legend = """
  <rect x="20" y="90" width="238" height="108" rx="8" fill="#ffffff" stroke="#d1d5db"/>
  <text x="32" y="112" font-family="Arial, sans-serif" font-size="12" fill="#0f172a">Protocol Legend</text>
  <line x1="32" y1="128" x2="62" y2="128" stroke="#0277bd" stroke-width="2.4"/><text x="72" y="132" font-family="Arial, sans-serif" font-size="11" fill="#334155">CDP/Default</text>
  <line x1="32" y1="146" x2="62" y2="146" stroke="#00a86b" stroke-width="2.4"/><text x="72" y="150" font-family="Arial, sans-serif" font-size="11" fill="#334155">LLDP</text>
  <line x1="32" y1="164" x2="62" y2="164" stroke="#ff8f00" stroke-width="2.4"/><text x="72" y="168" font-family="Arial, sans-serif" font-size="11" fill="#334155">OSPF</text>
  <line x1="32" y1="182" x2="62" y2="182" stroke="#6a1b9a" stroke-width="2.4"/><text x="72" y="186" font-family="Arial, sans-serif" font-size="11" fill="#334155">BGP</text>
"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="#f5f8fb"/>
  <text x="{width // 2}" y="34" text-anchor="middle" font-family="Arial, sans-serif" font-size="24" fill="#0f172a">{_xml_escape(title)}</text>
  <text x="{width // 2}" y="56" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" fill="#64748b">{_xml_escape(subtitle)}</text>
  {legend}
  <g id="edges">
    {''.join(edge_parts)}
  </g>
  <g id="edge-labels">
    {''.join(edge_label_parts)}
  </g>
  <g id="nodes">
    {''.join(node_parts)}
  </g>
</svg>"""


def _pdf_escape(text: str) -> str:
    return (
        str(text or "")
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _rows_to_network_doc_lines(rows: list[dict], group_id: int | None = None) -> list[str]:
    """Convert network documentation rows into printable text lines."""
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    lines: list[str] = [
        "Plexus Network Documentation Report",
        f"Generated: {generated}",
        f"Scope: {'All Groups' if group_id is None else f'Group ID {group_id}'}",
        "",
    ]

    summary = next((r for r in rows if str(r.get("section")) == "summary"), None)
    if summary:
        lines.append("Summary")
        lines.append(f"  {summary.get('details', '')}")
        lines.append("")

    inventory = [r for r in rows if str(r.get("section")) == "inventory"]
    lines.append(f"Inventory ({len(inventory)})")
    for r in inventory:
        lines.append(
            f"  {r.get('hostname', '')} [{r.get('ip_address', '')}] "
            f"group={r.get('group_name', '')} type={r.get('device_type', '')} "
            f"status={r.get('status', '')}"
        )
    lines.append("")

    links = [r for r in rows if str(r.get("section")) == "topology_link"]
    lines.append(f"Topology Links ({len(links)})")
    for r in links:
        details = f" | {r.get('details')}" if r.get("details") else ""
        lines.append(
            f"  {r.get('source_hostname', '')}:{r.get('source_interface', '')} -> "
            f"{r.get('target_device_name', '')}:{r.get('target_interface', '')} "
            f"proto={r.get('protocol', '')}{details}"
        )
    lines.append("")

    subnets = [r for r in rows if str(r.get("section")) == "ip_plan"]
    lines.append(f"IP Plan ({len(subnets)} subnets)")
    for r in subnets:
        lines.append(
            f"  {r.get('subnet', '')} hosts={r.get('subnet_host_count', 0)} "
            f"groups={r.get('group_name', '')}"
        )
        if r.get("details"):
            lines.append(f"    {r.get('details')}")
    lines.append("")

    vlans = [r for r in rows if str(r.get("section")) == "vlan_map"]
    lines.append(f"VLAN Map ({len(vlans)})")
    for r in vlans:
        lines.append(
            f"  VLAN {r.get('vlan_id', '')}: devices={r.get('vlan_device_count', 0)} "
            f"mac_entries={r.get('mac_entry_count', 0)}"
        )
        if r.get("details"):
            lines.append(f"    {r.get('details')}")
    lines.append("")

    circuits = [r for r in rows if str(r.get("section")) == "circuit_map"]
    if circuits:
        lines.append(f"Circuit Map ({len(circuits)})")
        for r in circuits:
            lines.append(
                f"  {r.get('circuit_name', '')} customer={r.get('circuit_customer', '')} "
                f"host={r.get('hostname', '')} if={r.get('circuit_if_name', '')} "
                f"commit={r.get('circuit_commit_mbps', '')} Mbps"
            )
            if r.get("details"):
                lines.append(f"    {r.get('details')}")
        lines.append("")

    return lines


def _render_text_pdf(title: str, lines: list[str]) -> bytes:
    """Render a minimal multi-page PDF containing monospaced text."""
    page_width = 595
    page_height = 842
    left = 40
    top = 800
    line_height = 12
    max_lines_per_page = 58

    all_lines = [title, ""] + [str(line) for line in lines]
    if not all_lines:
        all_lines = [title]

    chunks = [
        all_lines[i: i + max_lines_per_page]
        for i in range(0, len(all_lines), max_lines_per_page)
    ]

    page_count = len(chunks)
    font_obj = 3 + page_count * 2
    objects: dict[int, bytes] = {}

    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join([f"{3 + idx * 2} 0 R" for idx in range(page_count)])
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {page_count} >>".encode("ascii")

    for idx, page_lines in enumerate(chunks):
        page_obj = 3 + idx * 2
        content_obj = 4 + idx * 2

        stream_cmds = [
            "BT",
            "/F1 10 Tf",
            f"{line_height} TL",
            f"{left} {top} Td",
        ]
        for line in page_lines:
            stream_cmds.append(f"({_pdf_escape(line)}) Tj")
            stream_cmds.append("T*")
        stream_cmds.append("ET")

        stream = ("\n".join(stream_cmds) + "\n").encode("utf-8")
        objects[content_obj] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream
            + b"endstream"
        )
        objects[page_obj] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_width} {page_height}] "
            f"/Resources << /Font << /F1 {font_obj} 0 R >> >> "
            f"/Contents {content_obj} 0 R >>"
        ).encode("ascii")

    objects[font_obj] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"

    max_obj = max(objects.keys())
    out = bytearray()
    out.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (max_obj + 1)
    for obj_num in range(1, max_obj + 1):
        offsets[obj_num] = len(out)
        out.extend(f"{obj_num} 0 obj\n".encode("ascii"))
        out.extend(objects[obj_num])
        out.extend(b"\nendobj\n")

    xref_offset = len(out)
    out.extend(f"xref\n0 {max_obj + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for obj_num in range(1, max_obj + 1):
        out.extend(f"{offsets[obj_num]:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {max_obj + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(out)


def _render_network_doc_pdf(rows: list[dict], group_id: int | None = None) -> bytes:
    lines = _rows_to_network_doc_lines(rows, group_id=group_id)
    return _render_text_pdf("Plexus Network Documentation", lines)


@router.post("/api/reports/generate")
async def generate_report(body: dict, request: Request):
    """Generate a report and return results as JSON."""
    report_type = str(body.get("report_type", "availability")).strip().lower()
    params = body.get("parameters", {})
    if not isinstance(params, dict):
        params = {}
    persist_artifacts = bool(
        body.get("persist_artifacts", report_type == "network_documentation")
    )

    return await _execute_report_run(
        report_id=body.get("report_id"),
        report_type=report_type,
        params=params,
        persist_artifacts=persist_artifacts,
        include_rows=True,
    )


# ── CSV Export ───────────────────────────────────────────────────────────────


def _rows_to_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


@router.get("/api/reports/export/availability")
async def export_availability_csv(
    group_id: int | None = Query(default=None),
    days: int = Query(default=30),
):
    rows = await db.generate_availability_report_data(group_id, days)
    csv_data = _rows_to_csv(rows)
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=availability_report.csv"},
    )


@router.get("/api/reports/export/compliance")
async def export_compliance_csv(
    group_id: int | None = Query(default=None),
):
    rows = await db.generate_compliance_report_data(group_id)
    csv_data = _rows_to_csv(rows)
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=compliance_report.csv"},
    )


@router.get("/api/reports/export/interface")
async def export_interface_csv(
    host_id: int | None = Query(default=None),
    group_id: int | None = Query(default=None),
    days: int = Query(default=1),
):
    rows = await db.generate_interface_report_data(host_id, group_id, days)
    csv_data = _rows_to_csv(rows)
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=interface_report.csv"},
    )


@router.get("/api/reports/export/network_documentation")
async def export_network_documentation_csv(
    group_id: int | None = Query(default=None),
):
    rows = await db.generate_network_documentation_report_data(group_id)
    csv_data = _rows_to_csv(rows)
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=network_documentation_report.csv"},
    )


@router.get("/api/reports/export/network_documentation.svg")
async def export_network_documentation_svg(
    group_id: int | None = Query(default=None),
):
    try:
        graph = await _build_network_doc_topology(group_id)
        svg = _render_network_doc_svg(graph, group_id)
        return Response(
            content=svg,
            media_type="image/svg+xml",
            headers={"Content-Disposition": "attachment; filename=network_documentation_topology.svg"},
        )
    except Exception as exc:
        LOGGER.error("Network documentation SVG export failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to export network documentation SVG")


@router.get("/api/reports/export/network_documentation.pdf")
async def export_network_documentation_pdf(
    group_id: int | None = Query(default=None),
):
    try:
        rows = await db.generate_network_documentation_report_data(group_id)
        pdf_bytes = _render_network_doc_pdf(rows, group_id=group_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=network_documentation_report.pdf"},
        )
    except Exception as exc:
        LOGGER.error("Network documentation PDF export failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to export network documentation PDF")


@router.get("/api/reports/runs/{run_id}")
async def get_report_run_detail(run_id: int):
    run = await db.get_report_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Report run not found")
    return run


@router.get("/api/reports/runs/{run_id}/artifacts")
async def list_report_run_artifacts(
    run_id: int,
    limit: int = Query(default=20, ge=1, le=200),
):
    run = await db.get_report_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Report run not found")
    artifacts = await db.get_report_artifacts(run_id, limit=limit)
    return {"artifacts": artifacts}


@router.get("/api/reports/artifacts/{artifact_id}")
async def download_report_artifact(artifact_id: int):
    artifact = await db.get_report_artifact(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Report artifact not found")
    file_name = str(artifact.get("file_name") or f"artifact_{artifact_id}.txt").strip()
    safe_name = os.path.basename(file_name) or f"artifact_{artifact_id}.txt"
    media_type = str(artifact.get("media_type") or "application/octet-stream")
    blob = artifact.get("content_blob")
    if isinstance(blob, memoryview):
        blob = blob.tobytes()
    if isinstance(blob, (bytes, bytearray)) and len(blob) > 0:
        content: bytes | str = bytes(blob)
    else:
        content = str(artifact.get("content_text") or "")
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={safe_name}"},
    )


@router.get("/api/reports/runs/{run_id}/csv")
async def export_report_run_csv(run_id: int):
    """Export a previously-generated report run as CSV."""
    run = await db.get_report_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Report run not found")

    artifacts = await db.get_report_artifacts(run_id, limit=50)
    csv_artifact = next((a for a in artifacts if str(a.get("artifact_type")) == "csv"), None)
    if csv_artifact:
        full = await db.get_report_artifact(int(csv_artifact["id"]))
        if full:
            blob = full.get("content_blob")
            if isinstance(blob, memoryview):
                blob = blob.tobytes()
            if isinstance(blob, (bytes, bytearray)) and len(blob) > 0:
                payload: str | bytes = bytes(blob)
            else:
                payload = str(full.get("content_text") or "")
            return Response(
                content=payload,
                media_type=str(full.get("media_type") or "text/csv"),
                headers={"Content-Disposition": f"attachment; filename={os.path.basename(str(full.get('file_name') or f'report_{run_id}.csv'))}"},
            )

    try:
        rows = json.loads(run.get("result_json", "[]"))
    except Exception:
        rows = []
    if not isinstance(rows, list):
        rows = []
    csv_data = _rows_to_csv(rows)
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=report_{run_id}.csv"},
    )


# ── Custom OID Profiles Routes ──────────────────────────────────────────────


class OidProfileCreate(BaseModel):
    name: str
    vendor: str = ""
    device_type: str = ""
    description: str = ""
    oids_json: str = "[]"
    is_default: int = 0


class OidProfileUpdate(BaseModel):
    name: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    description: str | None = None
    oids_json: str | None = None
    is_default: int | None = None


@router.get("/api/oid-profiles")
async def list_oid_profiles(vendor: str | None = Query(default=None)):
    return {"profiles": await db.get_custom_oid_profiles(vendor)}


@router.get("/api/oid-profiles/{profile_id}")
async def get_oid_profile(profile_id: int):
    profile = await db.get_custom_oid_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="OID profile not found")
    return profile


@router.post("/api/oid-profiles", status_code=201)
async def create_oid_profile(payload: OidProfileCreate, request: Request):
    user = getattr(request.state, "user", None) or {}
    owner = user.get("username", "") if isinstance(user, dict) else ""
    profile = await db.create_custom_oid_profile(
        name=payload.name,
        vendor=payload.vendor,
        device_type=payload.device_type,
        description=payload.description,
        oids_json=payload.oids_json,
        is_default=payload.is_default,
        created_by=owner,
    )
    return profile


@router.put("/api/oid-profiles/{profile_id}")
async def update_oid_profile(profile_id: int, payload: OidProfileUpdate):
    updated = await db.update_custom_oid_profile(
        profile_id,
        name=payload.name,
        vendor=payload.vendor,
        device_type=payload.device_type,
        description=payload.description,
        oids_json=payload.oids_json,
        is_default=payload.is_default,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="OID profile not found")
    return updated


@router.delete("/api/oid-profiles/{profile_id}")
async def delete_oid_profile(profile_id: int):
    deleted = await db.delete_custom_oid_profile(profile_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="OID profile not found")
    return {"status": "deleted"}
