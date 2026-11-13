"""Software tools: versions per device and the advisories that affect them.

Every tracked device is returned whatever collected it (inventory, Meraki,
Cato, cloud accounts, firewall managers); rows name their ``source``. A
platform with devices but no advisory to check them against is reported as a
gap, not left out.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import routes.database as db

from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.dispatch import no_data, page_args
from netcontrol.mcp.registry import Tool, register
from netcontrol.mcp.tools._common import PAGING, db_time, parse_time, schema

SOURCE = "software versions"
MAX_AFFECTED_HOSTS = 100


async def list_software_versions(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    if not await db.list_software_versions():
        return no_data(SOURCE)
    vendor = str(args.get("vendor") or "").strip().lower()
    version = str(args.get("version") or "").strip().lower()
    changed_since = parse_time(args.get("changed_since"), "changed_since")
    open_alerts = await db.count_open_alerts_by_device()
    rows = []
    for device in await db.list_software_versions(search=str(args.get("host") or "")):
        if vendor and vendor not in f"{device.get('platform')} {device.get('source')}".lower():
            continue
        if version and version not in str(device.get("version") or "").lower():
            continue
        if changed_since is not None:
            changed = db_time(device.get("changed_at"))
            if changed is None or changed < changed_since:
                continue
        alerts = open_alerts.get(device["device_key"], {})
        rows.append(
            {
                "name": device.get("name"),
                "platform": device.get("platform"),
                "version": device.get("version"),
                "previous_version": device.get("previous_version") or None,
                "changed_at": device.get("changed_at") or None,
                "model": device.get("model"),
                "site": device.get("site"),
                "organization": device.get("org_name"),
                "host_id": device.get("host_id"),
                "open_advisories": int(alerts.get("count", 0)),
                "worst_severity": alerts.get("worst") if alerts else None,
                "last_seen": device.get("last_seen"),
                "source": device.get("source"),
            }
        )
    return page_args(rows, args)


async def list_advisories(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    devices = await db.list_software_versions()
    advisories = await db.list_software_advisories()
    if not devices and not advisories:
        return no_data(SOURCE)
    severity = str(args.get("severity") or "").strip().lower()
    cve = str(args.get("cve") or "").strip().lower()
    host = str(args.get("host") or "").strip().lower()

    affected: dict[str, list[dict[str, Any]]] = {}
    for alert in await db.list_software_alerts(limit=10_000):
        affected.setdefault(str(alert["advisory_id"]), []).append(
            {"name": alert.get("device_name"), "version": alert.get("version"), "source": alert.get("device_source")}
        )
    rows = []
    for advisory in advisories:
        hosts = affected.get(str(advisory["advisory_id"]), [])
        if severity and str(advisory.get("severity") or "").lower() != severity:
            continue
        if cve and cve not in [str(c).lower() for c in advisory.get("cves") or []]:
            continue
        if host and not any(host in str(h.get("name") or "").lower() for h in hosts):
            continue
        rows.append(
            {
                "id": advisory["advisory_id"],
                "title": advisory.get("title"),
                "severity": advisory.get("severity"),
                "cvss": advisory.get("cvss"),
                "cves": advisory.get("cves") or [],
                "platform": advisory.get("platform"),
                "affected_versions": advisory.get("affected_versions") or [],
                "fixed_in": advisory.get("fixed_versions") or [],
                "published": advisory.get("published"),
                "url": advisory.get("url"),
                "enabled": advisory.get("enabled"),
                "affected_hosts": hosts[:MAX_AFFECTED_HOSTS],
                "affected_host_count": len(hosts),
                "source": advisory.get("source"),
            }
        )
    covered = {str(a.get("platform") or "") for a in advisories if a.get("enabled")}
    tracked = Counter(str(d.get("platform") or "unknown") for d in devices)
    result = page_args(rows, args)
    result["platforms_without_advisories"] = [
        {"platform": platform, "advisory_source": "none", "devices": count}
        for platform, count in sorted(tracked.items())
        if platform not in covered
    ]
    return result


register(
    Tool(
        name="list_software_versions",
        description=(
            "Lists the software version of every tracked device from every source (inventory, Meraki, "
            "Cato, cloud accounts, firewall managers): platform, version, the previous version and when "
            "it changed, and how many open advisories affect it. 'vendor' matches part of the platform "
            "or source, 'version' part of the version, 'host' part of the name, model, serial or site. "
            "changed_since lists only devices whose version changed after that time."
        ),
        category="software",
        input_schema=schema(
            {
                "vendor": {"type": "string", "maxLength": 60},
                "version": {"type": "string", "maxLength": 60},
                "host": {"type": "string", "maxLength": 255},
                "changed_since": {"type": "string", "maxLength": 40, "description": "ISO 8601 time."},
                **PAGING,
            }
        ),
        handler=list_software_versions,
    )
)
register(
    Tool(
        name="list_advisories",
        description=(
            "Lists security advisories and CVEs Plexus checks versions against, each with the devices it "
            "currently affects and the versions that fix it. Filter by severity, CVE id, or part of an "
            "affected device's name. platforms_without_advisories names platforms that have devices but "
            "no advisory source, so their absence from the list is not a clean bill of health."
        ),
        category="software",
        input_schema=schema(
            {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "cve": {"type": "string", "maxLength": 40},
                "host": {"type": "string", "maxLength": 255},
                **PAGING,
            }
        ),
        handler=list_advisories,
    )
)
