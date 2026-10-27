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
from typing import Any

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
    "get_or_create_group_path",
    "find_top_level_group",
    "GROUP_PATH_SEPARATOR",
    "get_host",
    "get_hosts_for_group",
    "get_hosts_by_ids",
    "get_all_hosts",
    "find_host_by_ip",
    "find_hosts_by_hostname",
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


# Joins a group's path: the names from the top group down.
GROUP_PATH_SEPARATOR = " / "

# Deepest group chain followed when walking parents (a guard, not a limit
# anyone reaches: the bulk add nests two levels).
_MAX_GROUP_DEPTH = 64


def _tree_ordered(groups: list[dict]) -> list[dict]:
    """Order ``groups`` depth first (each parent before its sub-groups) and
    set each one's ``path`` and ``depth``.

    ``groups`` arrive in sibling order (the per-user order, then the name);
    that order is kept among the sub-groups of each parent. A group whose
    parent is not in the list is placed at the top level.
    """
    by_id = {g["id"]: g for g in groups}
    children: dict[int | None, list[dict]] = {}
    for g in groups:
        parent = g.get("parent_id")
        children.setdefault(parent if parent in by_id else None, []).append(g)

    ordered: list[dict] = []
    seen: set[int] = set()

    def walk(roots: list[dict]) -> None:
        stack: list[tuple[dict, str, int]] = [(g, "", 0) for g in reversed(roots)]
        while stack:
            group, prefix, depth = stack.pop()
            if group["id"] in seen:
                continue
            seen.add(group["id"])
            group["path"] = f"{prefix}{GROUP_PATH_SEPARATOR}{group['name']}" if prefix else group["name"]
            group["depth"] = depth
            ordered.append(group)
            for child in reversed(children.get(group["id"], [])):
                stack.append((child, group["path"], depth + 1))

    walk(children.get(None, []))
    # Only a parent cycle (rejected on write) leaves groups unvisited.
    walk([g for g in groups if g["id"] not in seen])
    return ordered


async def get_all_groups() -> list[dict]:
    """Every group with its ``host_count`` (direct hosts), ``parent_id``,
    ``path`` and ``depth``, ordered as a tree (siblings by name)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("""
            SELECT g.*, COUNT(h.id) AS host_count
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            GROUP BY g.id ORDER BY g.name
        """)
        return _tree_ordered(rows_to_list(await cursor.fetchall()))
    finally:
        await db.close()


# Host columns of the ``include_hosts`` listing, selected as ``host_<column>``.
_GROUP_LISTING_HOST_COLUMNS = (
    "id",
    "group_id",
    "hostname",
    "ip_address",
    "device_type",
    "status",
    "last_seen",
    "model",
    "software_version",
    "device_category",
    "serial_number",
    "aws_instance_id",
)
# Host columns read back as '' when NULL.
_GROUP_LISTING_TEXT_COLUMNS = ("model", "software_version", "device_category", "serial_number", "aws_instance_id")
_GROUP_LISTING_HOST_SELECT = ",\n                ".join(f"h.{c} AS host_{c}" for c in _GROUP_LISTING_HOST_COLUMNS)


def _groups_with_hosts_from_rows(rows) -> list[dict]:
    """Fold the group-by-host rows of the ``include_hosts`` listing into
    groups with embedded host arrays, tree ordered (rows arrive in sibling
    order, then by host address)."""
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
                "parent_id": row["group_parent_id"],
                "host_count": 0,
                "hosts": [],
            }
            by_group_id[gid] = group
            groups.append(group)

        if row["host_id"] is None:
            continue
        host = {c: row[f"host_{c}"] for c in _GROUP_LISTING_HOST_COLUMNS}
        for c in _GROUP_LISTING_TEXT_COLUMNS:
            host[c] = host[c] or ""
        group["hosts"].append(host)
        group["host_count"] += 1

    return _tree_ordered(groups)


async def get_all_groups_with_hosts() -> list[dict]:
    """Return all groups with embedded host arrays using a single query
    (tree ordered, like ``get_all_groups``)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(f"""
            SELECT
                g.id AS group_id,
                g.name AS group_name,
                g.description AS group_description,
                g.parent_id AS group_parent_id,
                {_GROUP_LISTING_HOST_SELECT}
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            ORDER BY g.name, h.ip_address
        """)  # noqa: S608 - fixed column names
        rows = await cursor.fetchall()
    finally:
        await db.close()
    return _groups_with_hosts_from_rows(rows)


async def get_all_groups_for_user(user_id: int) -> list[dict]:
    """Like get_all_groups but ordered by the user's saved drag order.

    Groups the user has not explicitly positioned fall to the bottom
    alphabetically (COALESCE(position, large sentinel)). The order applies
    among siblings: the result is still a tree (parents before sub-groups).
    """
    db = await _dbcore.get_db(read_only=True)
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
    return _tree_ordered(rows)


async def get_all_groups_with_hosts_for_user(user_id: int) -> list[dict]:
    """Per-user-ordered variant of get_all_groups_with_hosts."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"""
            SELECT
                g.id AS group_id,
                g.name AS group_name,
                g.description AS group_description,
                g.parent_id AS group_parent_id,
                {_GROUP_LISTING_HOST_SELECT}
            FROM inventory_groups g
            LEFT JOIN hosts h ON h.group_id = g.id
            LEFT JOIN user_inventory_group_order o
                   ON o.group_id = g.id AND o.user_id = ?
            ORDER BY COALESCE(o.position, 2147483647), g.name, h.ip_address
            """,  # noqa: S608 - fixed column names
            (user_id,),
        )
        rows = await cursor.fetchall()
    finally:
        await db.close()
    return _groups_with_hosts_from_rows(rows)


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
                "INSERT INTO user_inventory_group_order (user_id, group_id, position) VALUES (?, ?, ?)",
                (user_id, int(group_id), position),
            )
        await db.commit()
    finally:
        await db.close()


async def _group_chain(db, group_id: int) -> list[dict]:
    """The group and its ancestors, from the top group down (``[]`` when the
    group does not exist)."""
    cursor = await db.execute(
        f"""
        WITH RECURSIVE chain (id, name, parent_id, lvl) AS (
            SELECT id, name, parent_id, 0 FROM inventory_groups WHERE id = ?
            UNION ALL
            SELECT g.id, g.name, g.parent_id, c.lvl + 1
            FROM inventory_groups g JOIN chain c ON g.id = c.parent_id
            WHERE c.lvl < {_MAX_GROUP_DEPTH}
        )
        SELECT id, name, parent_id FROM chain ORDER BY lvl DESC
        """,  # noqa: S608 - a fixed integer
        (group_id,),
    )
    return rows_to_list(await cursor.fetchall())


# SQL subquery: the ids of a group and of all of its sub-groups, bound to one
# ``?`` (the group id). Walks ``inventory_groups.parent_id`` down from the
# group (``_group_chain`` walks up), depth-guarded the same way. Shared by
# every module that scopes something to "a group and everything under it"
# (SLA targets, ...); embed it as ``... IN {GROUP_SUBTREE_SQL}``.
GROUP_SUBTREE_SQL = f"""(
    WITH RECURSIVE sub (id, lvl) AS (
        SELECT id, 0 FROM inventory_groups WHERE id = ?
        UNION ALL
        SELECT g.id, s.lvl + 1 FROM inventory_groups g JOIN sub s ON g.parent_id = s.id
        WHERE s.lvl < {_MAX_GROUP_DEPTH}
    )
    SELECT id FROM sub
)"""


async def _check_parent(db, group_id: int | None, parent_id: int | None) -> None:
    """Raise ``ValueError`` when ``parent_id`` is not a group, or is
    ``group_id`` itself or one of its sub-groups (a cycle)."""
    if parent_id is None:
        return
    chain = await _group_chain(db, parent_id)
    if not chain:
        raise ValueError("Parent group not found")
    if group_id is not None and any(g["id"] == group_id for g in chain):
        raise ValueError("A group cannot be moved under itself or one of its sub-groups")


async def get_group(group_id: int) -> dict | None:
    """One group with its ``parent_id``, ``path`` (the names from the top,
    joined with " / ") and ``depth`` (0 for a top-level group)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM inventory_groups WHERE id = ?", (group_id,))
        group = row_to_dict(await cursor.fetchone())
        if group is None:
            return None
        chain = await _group_chain(db, group_id)
    finally:
        await db.close()
    group["path"] = GROUP_PATH_SEPARATOR.join(g["name"] for g in chain) or group["name"]
    group["depth"] = max(len(chain) - 1, 0)
    return group


async def create_group(name: str, description: str = "", parent_id: int | None = None) -> int:
    """Create a group, at the top level or under ``parent_id``.

    Raises ``ValueError`` when the parent does not exist. A sibling with the
    same name fails the unique index (``_is_unique_violation``).
    """
    db = await _dbcore.get_db()
    try:
        await _check_parent(db, None, parent_id)
        cursor = await db.execute(
            "INSERT INTO inventory_groups (name, description, parent_id) VALUES (?, ?, ?)",
            (name, description, parent_id),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


# ``update_group``'s default for ``parent_id``: leave the parent as it is.
_UNCHANGED: Any = object()


async def update_group(group_id: int, name: str, description: str = "", parent_id: int | None = _UNCHANGED):
    """Rename a group and, when ``parent_id`` is given, move it (``None``
    moves it to the top level). Raises ``ValueError`` when the parent does
    not exist or is the group itself or one of its sub-groups."""
    db = await _dbcore.get_db()
    try:
        if parent_id is _UNCHANGED:
            await db.execute(
                "UPDATE inventory_groups SET name = ?, description = ? WHERE id = ?",
                (name, description, group_id),
            )
        else:
            await _check_parent(db, group_id, parent_id)
            await db.execute(
                "UPDATE inventory_groups SET name = ?, description = ?, parent_id = ? WHERE id = ?",
                (name, description, parent_id, group_id),
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def get_or_create_group_path(names: list[str], description: str = "") -> list[dict]:
    """The groups along ``names`` (from the top), creating each missing one
    under the previous one with ``description``.

    A level matches a sibling by exact name. Returns one dict per level from
    the top: ``id``, ``name``, ``parent_id``, ``path`` and ``created`` (True
    for a group this call made). A level created concurrently by someone else
    is looked up again and reused.
    """
    cleaned = [n.strip() for n in names]
    if not cleaned or any(not n for n in cleaned):
        raise ValueError("A group path needs at least one name and no empty names")
    levels: list[dict] = []
    parent_id: int | None = None
    db = await _dbcore.get_db()
    try:
        for name in cleaned:
            path = GROUP_PATH_SEPARATOR.join([*(lv["name"] for lv in levels), name])
            row = await _find_child_group(db, parent_id, name)
            created = False
            if row is None:
                try:
                    cursor = await db.execute(
                        "INSERT INTO inventory_groups (name, description, parent_id) VALUES (?, ?, ?)",
                        (name, description, parent_id),
                    )
                    await db.commit()
                    gid = cursor.lastrowid
                    created = True
                except Exception as exc:
                    await db.rollback()
                    if not _is_unique_violation(exc):
                        raise
                    row = await _find_child_group(db, parent_id, name)
                    if row is None:
                        raise
                    gid = row["id"]
            else:
                gid = row["id"]
            levels.append({"id": gid, "name": name, "parent_id": parent_id, "path": path, "created": created})
            parent_id = gid
    finally:
        await db.close()
    return levels


async def _find_child_group(db, parent_id: int | None, name: str) -> dict | None:
    """The sub-group of ``parent_id`` (a top-level group for ``None``) named ``name``."""
    if parent_id is None:
        cursor = await db.execute(
            "SELECT id, name, parent_id FROM inventory_groups WHERE parent_id IS NULL AND name = ?", (name,)
        )
    else:
        cursor = await db.execute(
            "SELECT id, name, parent_id FROM inventory_groups WHERE parent_id = ? AND name = ?", (parent_id, name)
        )
    return row_to_dict(await cursor.fetchone())


async def find_top_level_group(name: str) -> dict | None:
    """The top-level group named ``name`` (sub-groups of that name are not matched)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        return await _find_child_group(db, None, name)
    finally:
        await db.close()


async def delete_group(group_id: int):
    """Delete a group, its hosts and the jobs that targeted it. Raises
    ``ValueError`` when the group has sub-groups (delete or move them first)."""
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM inventory_groups WHERE parent_id = ?", (group_id,))
        if (await cursor.fetchone())[0]:
            raise ValueError("The group has sub-groups: delete them or move them to another parent first")
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
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
        return row_to_dict(await cursor.fetchone())
    finally:
        await db.close()


async def get_hosts_for_group(group_id: int) -> list[dict]:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM hosts WHERE group_id = ? ORDER BY ip_address", (group_id,))
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_hosts_by_ids(host_ids: list[int]) -> list[dict]:
    """Get multiple hosts by their IDs."""
    if not host_ids:
        return []
    db = await _dbcore.get_db(read_only=True)
    try:
        placeholders = ",".join("?" * len(host_ids))
        cursor = await db.execute(
            f"SELECT * FROM hosts WHERE id IN ({placeholders}) ORDER BY ip_address", tuple(host_ids)
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_all_hosts() -> list[dict]:
    """Get every host across all groups, ordered by hostname."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM hosts ORDER BY hostname, ip_address")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def find_host_by_ip(ip_address: str) -> dict | None:
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM hosts WHERE ip_address = ? LIMIT 1", (ip_address,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def find_hosts_by_hostname(hostname: str) -> list[dict]:
    """Every host, in any group, named ``hostname`` (case-insensitive)."""
    name = (hostname or "").strip()
    if not name:
        return []
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM hosts WHERE LOWER(hostname) = LOWER(?) ORDER BY id", (name,))
        return rows_to_list(await cursor.fetchall())
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
    db = await _dbcore.get_db(read_only=True)
    try:
        index: dict[str, int] = {}
        cursor = await db.execute("SELECT id, ip_address FROM hosts WHERE group_id = ?", (group_id,))
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
    clean = sorted({ip.strip() for ip in alias_ips if ip and ip.strip() and ip.strip() != primary})
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
    db = await _dbcore.get_db(read_only=True)
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
    db = await _dbcore.get_db(read_only=True)
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
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT * FROM hosts WHERE fdm_api_enabled = 1 ORDER BY hostname, ip_address")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def add_host(
    group_id: int,
    hostname: str,
    ip_address: str,
    device_type: str = "cisco_ios",
    vrf_name: str = "",
    vlan_id: str = "",
    aws_instance_id: str = "",
) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address, device_type, vrf_name, vlan_id, aws_instance_id)"
            " VALUES (?,?,?,?,?,?,?)",
            (
                group_id,
                hostname,
                ip_address,
                device_type,
                vrf_name or "",
                str(vlan_id or ""),
                (aws_instance_id or "").strip(),
            ),
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
                address=ip_address,
                hostname=hostname or "",
                vrf_name=vrf_name or "",
                source_type="host",
                source_ref=str(new_id),
                note="host added",
            )
        except Exception as exc:
            _LOGGER.warning(
                "Failed to record IP assignment for host %s: %s",
                new_id,
                exc,
            )
    return new_id


async def remove_host(host_id: int):
    db = await _dbcore.get_db()
    try:
        cur = await db.execute("SELECT ip_address, vrf_name FROM hosts WHERE id = ?", (host_id,))
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
            await record_ip_release(address=prior_ip, vrf_name=prior_vrf, note="host removed")
        except Exception as exc:
            _LOGGER.warning(
                "Failed to record IP release for removed host %s: %s",
                host_id,
                exc,
            )


async def update_host(
    host_id: int,
    hostname: str,
    ip_address: str,
    device_type: str = "cisco_ios",
    vrf_name: str | None = None,
    vlan_id: str | None = None,
    aws_instance_id: str | None = None,
):
    """``None`` leaves ``vrf_name``/``vlan_id`` (together) and ``aws_instance_id`` unchanged."""
    db = await _dbcore.get_db()
    try:
        cur = await db.execute("SELECT ip_address, vrf_name FROM hosts WHERE id = ?", (host_id,))
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
                "UPDATE hosts SET hostname=?, ip_address=?, device_type=?, vrf_name=?, vlan_id=? WHERE id=?",
                (hostname, ip_address, device_type, vrf_name or "", str(vlan_id or ""), host_id),
            )
        if aws_instance_id is not None:
            await db.execute(
                "UPDATE hosts SET aws_instance_id=? WHERE id=?",
                (aws_instance_id.strip(), host_id),
            )
        await db.commit()
    finally:
        await db.close()

    new_vrf = (vrf_name or prior_vrf) if vrf_name is not None else prior_vrf
    new_ip = (ip_address or "").strip()
    try:
        if prior_ip and (prior_ip != new_ip or prior_vrf != new_vrf):
            await record_ip_release(address=prior_ip, vrf_name=prior_vrf, note="host updated")
        if new_ip:
            await record_ip_assignment(
                address=new_ip,
                hostname=hostname or "",
                vrf_name=new_vrf or "",
                source_type="host",
                source_ref=str(host_id),
                note="host updated",
            )
    except Exception as exc:
        _LOGGER.warning(
            "Failed to record IP assignment history for updated host %s: %s",
            host_id,
            exc,
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
                await record_ip_release(address=ip, vrf_name=vrf, note="bulk host delete")
            except Exception as exc:
                _LOGGER.warning(
                    "Failed to record IP release for bulk-deleted host (%s): %s",
                    ip,
                    exc,
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


async def update_host_device_info(host_id: int, model: str, software_version: str, device_category: str = ""):
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
    db = await _dbcore.get_db(read_only=True)
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
