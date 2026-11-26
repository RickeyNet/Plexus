"""
config_visibility.py -- who may read device configuration as captured.

A device's configuration holds its secrets: enable and user passwords,
SNMP communities and keys, TACACS+/RADIUS keys, pre-shared keys. Every copy
Plexus keeps or derives from it follows one rule, whichever page returns it
(config backups, drift snapshots, baselines and diffs, intended config,
lab twins, risk analyses, correlations):

- an admin, the API token, or a user holding ``config-backups.write`` whose
  object scope may change the device's inventory group reads it as
  captured;
- every other caller reads it with the secrets masked by
  ``netcontrol.mcp.redact.redact_config_text`` (``secrets_masked: true``);
- a server-side caller (no HTTP request: the scheduler, a background job,
  a route called directly) works on the text as captured.

An OPNsense ``config.xml`` is masked for everyone, as before
(``opnsense_masking``). Rule evaluation, drift detection and compliance
checks run on the server and keep using the stored text; only what leaves
the server goes through this module.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from fastapi import HTTPException
from starlette.requests import HTTPConnection

from netcontrol.mcp.redact import MASK, redact_config_text
from netcontrol.object_scope import request_scope, require_object_host
from netcontrol.routes import opnsense_masking
from netcontrol.routes.shared import caller_features

# The feature that reads device configuration with its secrets.
RAW_CONFIG_FEATURE = "config-backups.write"
_NOT_FOUND = "Not found"


async def has_raw_config_feature(request: Any) -> bool:
    """Whether the caller may see device secrets at all: an admin, the API
    token, or a user holding ``config-backups.write``. A call with no HTTP
    request is a server-side caller."""
    if not isinstance(request, HTTPConnection):
        return True
    features = await caller_features(request)
    return features is None or RAW_CONFIG_FEATURE in features


async def sees_raw_config(request: Any, host_id: int | None) -> bool:
    """``has_raw_config_feature`` and, for a caller limited to inventory
    groups, write access to the device's group (the right a restore
    needs). Any doubt (unknown host, lookup error) answers ``False``."""
    if not await has_raw_config_feature(request):
        return False
    try:
        await require_object_host(request, host_id, write=True, not_found=_NOT_FOUND)
    except HTTPException:
        return False
    return True


def mask_config_text(text: str, *, keep_lines: bool = False) -> str:
    """Configuration text (or a diff of it) with its secrets masked.
    ``keep_lines`` masks a key block line by line, for diffs and line
    numbered views."""
    return redact_config_text(text, keep_lines=keep_lines)


def mask_lines(lines: Iterable[str]) -> list[str]:
    """Configuration lines (commands, the lines of a section) with their
    secrets masked, one result line per line. Read as one text, so a key
    block spread over several lines is masked whole."""
    given = [str(line) for line in lines]
    if not given:
        return []
    masked = redact_config_text("\n".join(given), keep_lines=True).split("\n")
    if len(masked) == len(given):
        return masked
    return [redact_config_text(line) for line in given]


def mask_commands(commands: Iterable[str]) -> list[str]:
    """Configuration commands with their secrets masked, one per command. A
    ``no`` command is masked as the line it removes, so ``no key 0 <value>``
    hides the value as ``key 0 <value>`` would."""
    given = [str(command) for command in commands]
    stripped: list[str] = []
    negated: list[tuple[str, bool]] = []
    for command in given:
        body = command.lstrip()
        indent = command[: len(command) - len(body)]
        is_no = body.lower().startswith("no ")
        stripped.append(indent + (body[3:] if is_no else body))
        negated.append((indent, is_no))
    masked = mask_lines(stripped)
    return [
        indent + "no " + line[len(indent) :] if is_no else line
        for (indent, is_no), line in zip(negated, masked, strict=True)
    ]


def holds_mask(text: str) -> bool:
    """Whether ``text`` carries the mask a masked view puts in place of a
    secret."""
    return MASK in (text or "")


def restore_masked_lines(text: str, *sources: str) -> str:
    """``text`` with each line that is the masked form of a line of one of
    ``sources`` (the stored configuration it was read from) given back as
    that line, so a caller who reads masked text and saves it (a baseline
    taken from a masked snapshot) stores the configuration, not the mask.
    Equal masked lines are given back in the order of the source. A line
    with no source stays as it is. Nothing is returned to the caller."""
    if not holds_mask(text):
        return text
    originals: dict[str, list[str]] = {}
    for source in sources:
        if not source:
            continue
        raw = source.splitlines()
        masked = redact_config_text(source, keep_lines=True).splitlines()
        if len(raw) != len(masked):
            continue
        for masked_line, raw_line in zip(masked, raw, strict=True):
            if masked_line != raw_line:
                originals.setdefault(masked_line, []).append(raw_line)
    if not originals:
        return text
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        queue = originals.get(body)
        out.append((queue.pop(0) if queue else body) + line[len(body) :])
    return "".join(out)


def mask_fields(record: dict[str, Any], *fields: str, keep_lines: bool = False) -> dict[str, Any]:
    """Mask the configuration ``fields`` of ``record`` in place and flag it
    ``secrets_masked``, for a caller already known not to see them raw."""
    for field in fields:
        value = record.get(field)
        if isinstance(value, str) and value:
            record[field] = redact_config_text(value, keep_lines=keep_lines)
    record["secrets_masked"] = True
    return record


async def mask_config_record(
    request: Any,
    record: dict[str, Any] | None,
    *fields: str,
    host_id: int | None = None,
    keep_lines: bool = False,
    device_type: str | None = None,
) -> dict[str, Any] | None:
    """``record`` (a row read from the database) with its configuration
    ``fields`` as this caller may read them: an OPNsense configuration
    masked for everyone, any other masked unless ``sees_raw_config`` holds
    for its host (``host_id``, else the record's own ``host_id``)."""
    if not record:
        return record
    masked = opnsense_masking.mask_record(record, *fields, device_type=device_type)
    if masked is None or masked.get("secrets_masked"):
        return masked
    owner = host_id if host_id is not None else masked.get("host_id")
    if not await sees_raw_config(request, owner):
        mask_fields(masked, *fields, keep_lines=keep_lines)
    return masked


async def raw_hosts(request: Any, host_ids: Iterable[int | None]) -> dict[int | None, bool]:
    """``host_id -> sees_raw_config`` for each distinct host, read once."""
    distinct = set(host_ids)
    if not await has_raw_config_feature(request):
        return dict.fromkeys(distinct, False)
    if isinstance(request, HTTPConnection) and (await request_scope(request)).unrestricted:
        return dict.fromkeys(distinct, True)
    return {host_id: await sees_raw_config(request, host_id) for host_id in distinct}


async def mask_config_rows(
    request: Any,
    rows: list[dict[str, Any]],
    *fields: str,
    keep_lines: bool = False,
    host_field: str = "host_id",
    also: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    """``mask_config_record`` over a list, the right read once per host.
    ``also`` is called with each row of a host this caller does not read
    raw, to mask what the row holds beside ``fields`` (commands, text
    inside a JSON column)."""
    allowed = await raw_hosts(request, (row.get(host_field) for row in rows))
    for row in rows:
        opnsense_masking.mask_record(row, *fields)
        if allowed.get(row.get(host_field), False):
            continue
        if not row.get("secrets_masked"):
            mask_fields(row, *fields, keep_lines=keep_lines)
        if also is not None:
            also(row)
    return rows
