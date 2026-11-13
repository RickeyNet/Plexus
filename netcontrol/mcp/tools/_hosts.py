"""Shared by every tool that takes a ``host`` argument or returns hosts.

``resolve_host`` turns what a person or a model would type (a host name, an
IP address, or the numeric id a previous result showed) into one inventory
host. It never picks between several matches: it lists them and asks for a
narrower reference.
"""

from __future__ import annotations

from typing import Any

import routes.database as db

from netcontrol.mcp.registry import ToolError

MAX_CANDIDATES = 10

HOST_ARG = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "description": "A device: host name, IP address, or the numeric id from an earlier result.",
}

# Host columns a tool may return. Credentials are not on the host row, and
# nothing outside this list is passed through.
_HOST_FIELDS = (
    "id",
    "hostname",
    "ip_address",
    "device_type",
    "model",
    "software_version",
    "device_category",
    "serial_number",
    "status",
    "last_seen",
    "vrf_name",
)


async def group_paths() -> dict[int, str]:
    """Group id to its full path (``Campus / Core``)."""
    return {int(g["id"]): str(g.get("path") or g["name"]) for g in await db.get_all_groups()}


def host_row(host: dict[str, Any], paths: dict[int, str]) -> dict[str, Any]:
    """The fields of an inventory host a tool returns."""
    row = {field: host.get(field) for field in _HOST_FIELDS}
    row["group"] = paths.get(int(host.get("group_id") or 0), "")
    row["source"] = "inventory"
    return row


async def alias_index() -> dict[int, list[str]]:
    """Host id to the secondary interface addresses the device owns."""
    hosts = await db.get_all_hosts()
    index: dict[int, list[str]] = {}
    for alias in await db.get_ip_aliases_for_hosts([int(h["id"]) for h in hosts]):
        index.setdefault(int(alias["host_id"]), []).append(str(alias["ip_address"]))
    return {host_id: sorted(addresses) for host_id, addresses in index.items()}


def _describe(host: dict[str, Any], paths: dict[int, str]) -> str:
    group = paths.get(int(host.get("group_id") or 0), "")
    return f"id {host['id']}: {host['hostname']} ({host['ip_address']}, group {group or 'none'})"


async def resolve_host(ref: str) -> dict:
    """The one inventory host ``ref`` names.

    Tried in order: numeric id, exact address (primary or alias), exact
    host name, then a partial host name. Raises ``ToolError`` listing up to
    ten candidates when more than one host matches, and
    ``ToolError("No host matches '<ref>'. Try search_hosts.")`` when none does.
    """
    ref = str(ref or "").strip()
    hosts = await db.get_all_hosts()
    matches: list[dict] = []
    if ref.isdigit():
        matches = [h for h in hosts if int(h["id"]) == int(ref)]
    if not matches and ref:
        aliases = await alias_index()
        matches = [h for h in hosts if h["ip_address"] == ref or ref in aliases.get(int(h["id"]), [])]
    if not matches and ref:
        lowered = ref.lower()
        matches = [h for h in hosts if str(h["hostname"]).lower() == lowered]
        if not matches:
            matches = [h for h in hosts if lowered in str(h["hostname"]).lower()]
    if not matches:
        raise ToolError(f"No host matches '{ref}'. Try search_hosts.")
    if len(matches) > 1:
        paths = await group_paths()
        listed = "; ".join(_describe(h, paths) for h in matches[:MAX_CANDIDATES])
        raise ToolError(f"{len(matches)} hosts match '{ref}'. Use one of these ids as the host argument: {listed}")
    return matches[0]
