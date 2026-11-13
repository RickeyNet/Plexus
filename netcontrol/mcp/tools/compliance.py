"""Compliance tools: the latest scan result of every target, from every source.

Inventory devices are scanned against their stored configuration; Meraki
networks and devices against their dashboard settings. Both kinds of result
are returned together, each row naming its ``source``.
"""

from __future__ import annotations

import json
from typing import Any

import routes.database as db

from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.dispatch import no_data, page_args
from netcontrol.mcp.registry import Tool, register
from netcontrol.mcp.tools._common import PAGING, schema
from netcontrol.mcp.tools._hosts import HOST_ARG, resolve_host

SOURCE = "compliance scans"
MAX_FINDINGS = 50
_SCAN_ROWS = 10_000
_STATUS = {"pass": "compliant", "fail": "non-compliant"}


def _findings(raw: Any) -> list[Any]:
    try:
        parsed = json.loads(raw or "[]")
    except TypeError, ValueError:
        return []
    if not isinstance(parsed, list):
        return []
    failed = [f for f in parsed if not (isinstance(f, dict) and f.get("passed") is True)]
    return failed[:MAX_FINDINGS]


async def _latest_results() -> list[dict[str, Any]]:
    """The newest result of each target and profile, inventory and Meraki."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for result in await db.get_compliance_scan_results(limit=_SCAN_ROWS):  # newest first
        key = (result["host_id"], result["profile_id"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "host": {
                    "id": result["host_id"],
                    "hostname": result.get("hostname"),
                    "ip_address": result.get("ip_address"),
                },
                "profile": result.get("profile_name"),
                "status": result.get("status"),
                "total_rules": result.get("total_rules"),
                "passed_rules": result.get("passed_rules"),
                "failed_rules": result.get("failed_rules"),
                "findings": _findings(result.get("findings")),
                "scanned_at": result.get("scanned_at"),
                "source": "inventory",
            }
        )
    for result in await db.list_meraki_compliance_results(limit=_SCAN_ROWS):  # newest first
        target = (result["org_ref"], result["target_kind"], result["target_id"], result["profile_id"])
        if target in seen:
            continue
        seen.add(target)
        rows.append(
            {
                "target": result.get("target_name") or result.get("target_id"),
                "target_kind": result.get("target_kind"),
                "network": result.get("network_name"),
                "organization": result.get("org_name"),
                "profile": result.get("profile_name"),
                "status": result.get("status"),
                "total_rules": result.get("total_rules"),
                "passed_rules": result.get("passed_rules"),
                "failed_rules": result.get("failed_rules"),
                "unreadable_rules": result.get("unreadable_rules"),
                "scanned_at": result.get("scanned_at"),
                "source": "meraki",
            }
        )
    return rows


def _profile_matches(row: dict[str, Any], wanted: str) -> bool:
    return not wanted or wanted in str(row.get("profile") or "").lower()


async def list_compliance_results(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    rows = await _latest_results()
    if not rows:
        return no_data(SOURCE)
    profile = str(args.get("profile") or "").strip().lower()
    status = _STATUS.get(str(args.get("status") or ""))
    host_id = int((await resolve_host(args["host"]))["id"]) if args.get("host") else None
    kept = [
        row
        for row in rows
        if _profile_matches(row, profile)
        and (status is None or row["status"] == status)
        and (host_id is None or row.get("host", {}).get("id") == host_id)
    ]
    return page_args(kept, args)


async def get_compliance_summary(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    rows = await _latest_results()
    if not rows:
        return no_data(SOURCE)
    profile = str(args.get("profile") or "").strip().lower()
    profiles: dict[tuple[str, str], dict[str, Any]] = {}
    totals = {"targets": 0, "compliant": 0, "non_compliant": 0, "error": 0}
    for row in rows:
        if not _profile_matches(row, profile):
            continue
        entry = profiles.setdefault(
            (str(row["profile"]), row["source"]),
            {
                "profile": row["profile"],
                "source": row["source"],
                "compliant": 0,
                "non_compliant": 0,
                "error": 0,
                "last_scan": "",
            },
        )
        bucket = {"compliant": "compliant", "non-compliant": "non_compliant"}.get(str(row["status"]), "error")
        entry[bucket] += 1
        totals[bucket] += 1
        totals["targets"] += 1
        entry["last_scan"] = max(entry["last_scan"], str(row.get("scanned_at") or ""))
    return {"profiles": [profiles[key] for key in sorted(profiles)], "totals": totals}


register(
    Tool(
        name="list_compliance_results",
        description=(
            "Lists the latest compliance result of each device or network against each profile: status "
            "(compliant or non-compliant), rule counts, the failed rules with their detail, and when it "
            "was scanned. Covers inventory devices and Meraki networks; each row names its source. "
            "Filter by profile name, device, and status (pass or fail)."
        ),
        category="compliance",
        input_schema=schema(
            {
                "profile": {"type": "string", "maxLength": 200, "description": "Part of the profile name."},
                "host": HOST_ARG,
                "status": {"type": "string", "enum": ["pass", "fail"]},
                **PAGING,
            }
        ),
        handler=list_compliance_results,
    )
)
register(
    Tool(
        name="get_compliance_summary",
        description=(
            "Counts compliant and non-compliant targets per compliance profile and per source "
            "(inventory, Meraki), with the time of the last scan. Use it for an overall compliance "
            "posture before listing individual results."
        ),
        category="compliance",
        input_schema=schema({"profile": {"type": "string", "maxLength": 200}}),
        handler=get_compliance_summary,
    )
)
