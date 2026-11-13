"""Config tools: search, read and compare stored configuration backups.

Everything here reads backups Plexus already holds; nothing connects to a
device. Secrets in the returned text are masked by the dispatcher;
``search_configs`` also masks before it matches.
"""

from __future__ import annotations

import asyncio
from typing import Any

import routes.database as db
from routes.db.topology import _compile_config_backup_regex

from netcontrol.integrations.pathtrace.ios_config import blocks
from netcontrol.mcp import redact
from netcontrol.mcp.auth import McpContext
from netcontrol.mcp.dispatch import no_data, page_args
from netcontrol.mcp.registry import Tool, ToolError, register
from netcontrol.mcp.tools._common import PAGING, TIME_RANGE, host_ref, in_window, schema, time_window
from netcontrol.mcp.tools._hosts import HOST_ARG, group_paths, resolve_host
from netcontrol.routes.shared import _compute_config_diff

SOURCE = "config backups"
MAX_PATTERN_CHARS = 200
MAX_MATCHES_PER_DEVICE = 20
MAX_SECTION_HEADERS = 30
MAX_DRIFT_DIFF_LINES = 200
_CHUNK = 50


def _matcher(pattern: str, mode: str):
    """A ``line -> bool`` test for the pattern."""
    if mode == "regex":
        try:
            compiled = _compile_config_backup_regex(pattern)
        except ValueError:
            raise ToolError(
                "Invalid pattern: not a regular expression Plexus accepts. Use RE2 syntax (no "
                "backreferences or lookarounds) without nested quantifiers, or use mode 'text'."
            ) from None
        return lambda line: compiled.search(line) is not None
    needle = pattern.lower()
    return lambda line: needle in line.lower()


def _matches(text: str, test, context: int) -> tuple[list[dict[str, Any]], int]:
    """The matching lines of a configuration with their context.

    The text is masked before the pattern is tried, so a hit or a miss says
    nothing about a secret value, and a context window cannot cut a key or
    certificate block into lines that are masked one at a time."""
    lines = redact.redact_config_text(text, keep_lines=True).splitlines()
    hits = [index for index, line in enumerate(lines) if test(line)]
    shown = [
        {"line_number": index + 1, "lines": lines[max(0, index - context) : index + context + 1]}
        for index in hits[:MAX_MATCHES_PER_DEVICE]
    ]
    return shown, max(0, len(hits) - MAX_MATCHES_PER_DEVICE)


async def search_configs(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    pattern = str(args["pattern"])
    if not pattern.strip():
        raise ToolError("Invalid pattern: it is empty.")
    test = _matcher(pattern, str(args.get("mode") or "text"))
    context = int(args.get("context_lines", 1))
    not_matching = bool(args.get("not_matching"))
    vendor = str(args.get("vendor") or "").strip().lower()
    group = str(args.get("group") or "").strip().lower()

    paths = await group_paths()
    hosts = [
        host
        for host in await db.get_all_hosts()
        if (not vendor or vendor in str(host.get("device_type") or "").lower())
        and (not group or group in paths.get(int(host.get("group_id") or 0), "").lower())
    ]
    rows: list[dict[str, Any]] = []
    searched = 0
    for start in range(0, len(hosts), _CHUNK):
        chunk = hosts[start : start + _CHUNK]
        backups = await db.get_latest_config_texts_for_hosts([int(h["id"]) for h in chunk])
        for host in chunk:
            backup = backups.get(int(host["id"]))
            if not backup:
                continue
            searched += 1
            # Off the event loop: masking and matching a large configuration is CPU work.
            found, more = await asyncio.to_thread(_matches, str(backup.get("config_text") or ""), test, context)
            if bool(found) == not_matching:
                continue
            row: dict[str, Any] = {
                "host": host_ref(host),
                "backup_id": backup["id"],
                "backup_time": backup.get("captured_at"),
            }
            if not not_matching:
                row["matches"] = found
                if more:
                    row["more_matches"] = more
            rows.append(row)
    if not searched and not vendor and not group:
        return no_data(SOURCE)
    result = page_args(rows, args)
    result["devices_searched"] = searched
    result["devices_without_backup"] = len(hosts) - searched
    return result


async def _backup_of(host: dict, backup_id: int) -> dict:
    backup = await db.get_config_backup(int(backup_id))
    if not backup or int(backup.get("host_id") or 0) != int(host["id"]):
        raise ToolError(f"Backup {backup_id} does not belong to {host['hostname']}.")
    if backup.get("status") != "success":
        raise ToolError(f"Backup {backup_id} did not complete, so it has no configuration.")
    return backup


def _section(text: str, wanted: str) -> str:
    found = blocks(text)
    lowered = wanted.strip().lower()
    chosen = [block for block in found if block.header.lower().startswith(lowered)]
    if not chosen:
        # One header per line, so the dispatcher's line-based masking applies.
        headers = "\n" + "\n".join(block.header for block in found[:MAX_SECTION_HEADERS])
        raise ToolError(f"No section starts with '{wanted}'. Sections in this configuration include: {headers}")
    out: list[str] = []
    for block in chosen:
        out.append(block.header)
        out.extend(" " * indent + line for indent, line in block.children)
    return "\n".join(out) + "\n"


async def get_device_config(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    host = await resolve_host(args["host"])
    backup: dict | None
    if args.get("backup_id") is not None:
        backup = await _backup_of(host, args["backup_id"])
    else:
        backup = await db.get_newest_host_config_backup(int(host["id"]))
        if not backup:
            return no_data(f"{SOURCE} of {host['hostname']}")
    text = str(backup.get("config_text") or "")
    if args.get("section"):
        text = _section(text, str(args["section"]))
    return {
        "host": host_ref(host),
        "backup_id": backup["id"],
        "backup_time": backup.get("captured_at"),
        "lines": len(text.splitlines()),
        "config": text,
    }


async def diff_device_configs(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    host = await resolve_host(args["host"])
    newer: dict | None
    older: dict | None
    if args.get("to_backup_id") is not None:
        newer = await _backup_of(host, args["to_backup_id"])
    else:
        newer = await db.get_newest_host_config_backup(int(host["id"]))
        if not newer:
            return no_data(f"{SOURCE} of {host['hostname']}")
    if args.get("from_backup_id") is not None:
        older = await _backup_of(host, args["from_backup_id"])
    else:
        older = await db.get_previous_successful_config_backup(int(newer["id"]))
        if not older:
            raise ToolError(f"Only one backup exists for {host['hostname']}, so there is nothing to compare.")
    diff, added, removed = _compute_config_diff(
        str(older.get("config_text") or ""),
        str(newer.get("config_text") or ""),
        f"backup {older['id']} ({older.get('captured_at')})",
        f"backup {newer['id']} ({newer.get('captured_at')})",
    )
    return {
        "host": host_ref(host),
        "from": {"backup_id": older["id"], "backup_time": older.get("captured_at")},
        "to": {"backup_id": newer["id"], "backup_time": newer.get("captured_at")},
        "lines_added": added,
        "lines_removed": removed,
        "diff": diff,
    }


async def list_config_drift(_ctx: McpContext, args: dict[str, Any]) -> dict[str, Any]:
    since, until = time_window(args, default_hours=None)
    host_id = int((await resolve_host(args["host"]))["id"]) if args.get("host") else None
    events = await db.get_config_drift_events(status=args.get("status") or None, host_id=host_id, limit=5000)
    rows = []
    for event in events:
        if not in_window(event.get("detected_at"), since, until):
            continue
        diff_lines = str(event.get("diff_text") or "").splitlines()
        rows.append(
            {
                "id": event["id"],
                "host": {
                    "id": event["host_id"],
                    "hostname": event.get("hostname"),
                    "ip_address": event.get("ip_address"),
                },
                "status": event.get("status"),
                "detected_at": event.get("detected_at"),
                "resolved_at": event.get("resolved_at"),
                "lines_added": event.get("diff_lines_added"),
                "lines_removed": event.get("diff_lines_removed"),
                "diff": "\n".join(diff_lines[:MAX_DRIFT_DIFF_LINES]),
                "diff_truncated": len(diff_lines) > MAX_DRIFT_DIFF_LINES,
            }
        )
    return page_args(rows, args)


register(
    Tool(
        name="search_configs",
        description=(
            "Searches the latest stored configuration of every device and returns the devices that "
            "match, with the matching lines and their line numbers. Answers 'which devices have X "
            "configured'. Set not_matching to list the devices whose configuration lacks the pattern "
            "('which devices are missing X'). mode 'text' is a case-insensitive substring; mode 'regex' "
            "is an RE2 regular expression tested against each line. Secret values are masked, so search "
            "for the command (snmp-server community), not for a secret."
        ),
        category="configs",
        input_schema=schema(
            {
                "pattern": {"type": "string", "minLength": 1, "maxLength": MAX_PATTERN_CHARS},
                "mode": {"type": "string", "enum": ["text", "regex"]},
                "not_matching": {"type": "boolean"},
                "vendor": {"type": "string", "maxLength": 60, "description": "Part of the device type, e.g. cisco."},
                "group": {"type": "string", "maxLength": 255, "description": "Part of the inventory group path."},
                "context_lines": {"type": "integer", "minimum": 0, "maximum": 5},
                **PAGING,
            },
            required=("pattern",),
        ),
        handler=search_configs,
    )
)
register(
    Tool(
        name="get_device_config",
        description=(
            "Returns a device's stored configuration: the latest backup, or the one named by backup_id. "
            "'section' returns only the top-level blocks whose first line starts with that text and "
            "their indented lines (interface GigabitEthernet1/0/1, router bgp). Prefer a section: a "
            "whole configuration may exceed the result size limit. Secret values are masked."
        ),
        category="configs",
        input_schema=schema(
            {
                "host": HOST_ARG,
                "backup_id": {"type": "integer", "minimum": 1},
                "section": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            required=("host",),
        ),
        handler=get_device_config,
    )
)
register(
    Tool(
        name="diff_device_configs",
        description=(
            "Returns a unified diff between two stored configuration backups of one device. By default "
            "it compares the latest backup with the one before it, which answers 'what changed on this "
            "device'. Backup ids come from get_device_config and search_configs."
        ),
        category="configs",
        input_schema=schema(
            {
                "host": HOST_ARG,
                "from_backup_id": {"type": "integer", "minimum": 1},
                "to_backup_id": {"type": "integer", "minimum": 1},
            },
            required=("host",),
        ),
        handler=diff_device_configs,
    )
)
register(
    Tool(
        name="list_config_drift",
        description=(
            "Lists configuration drift events: times a device's running configuration was found to "
            "differ from its approved baseline, with the diff. Filter by device, status (open, "
            "accepted, resolved) and time range. Without since, events of any age are returned."
        ),
        category="configs",
        features=("config-drift",),
        input_schema=schema({"host": HOST_ARG, "status": {"type": "string", "maxLength": 30}, **TIME_RANGE, **PAGING}),
        handler=list_config_drift,
    )
)
