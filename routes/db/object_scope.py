"""Object scope storage beyond the inventory group grants (``routes.db.users``):
the per-model scope rules of access groups (migration 0111) and the host,
tenant and site ids a set of inventory groups reaches.

Rules belong to access groups whose ``object_scope`` is ``groups``; the
rules of an ``all`` access group are kept but never applied (its members are
unrestricted). See ``netcontrol.object_scope`` for how they are used.
"""

from __future__ import annotations

from collections.abc import Iterable

from netcontrol.authz_cache import invalidates

import routes.database as _dbcore
from routes.database import rows_to_list

__all__ = [
    "SCOPE_RULE_ATTRIBUTES",
    "get_user_scope_rules",
    "get_access_group_scope_rules",
    "set_access_group_scope_rules",
    "get_group_scope_keys",
]

# What a rule filters on: the tenant or the site a record belongs to.
SCOPE_RULE_ATTRIBUTES: tuple[str, ...] = ("tenant", "site")
_ATTRIBUTE_TABLES = {"tenant": "tenants", "site": "geo_sites"}


def _rule(row: dict) -> dict:
    return {
        "model": str(row["model"]),
        "attribute": str(row["attribute"]),
        "value_id": int(row["value_id"]),
        "can_write": bool(row["can_write"]),
    }


async def get_user_scope_rules(user_id: int) -> list[dict]:
    """The scope rules of the ``groups`` access groups ``user_id`` belongs to
    (``model``, ``attribute``, ``value_id``, ``can_write``; a rule present in
    several groups is writable when any of them makes it writable)."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """
            SELECT r.model, r.attribute, r.value_id, MAX(r.can_write) AS can_write
            FROM access_group_scope_rules r
            INNER JOIN access_groups g ON g.id = r.access_group_id
            INNER JOIN user_group_memberships m ON m.group_id = r.access_group_id
            WHERE m.user_id = ? AND g.object_scope = 'groups'
            GROUP BY r.model, r.attribute, r.value_id
            ORDER BY r.model, r.attribute, r.value_id
            """,
            (int(user_id),),
        )
        return [_rule(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


async def get_access_group_scope_rules(access_group_id: int) -> list[dict]:
    """The scope rules of one access group, in a stable order."""
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            """
            SELECT model, attribute, value_id, can_write FROM access_group_scope_rules
            WHERE access_group_id = ? ORDER BY model, attribute, value_id
            """,
            (int(access_group_id),),
        )
        return [_rule(r) for r in rows_to_list(await cursor.fetchall())]
    finally:
        await db.close()


@invalidates  # the auth path caches users' scope rules (netcontrol.authz_cache)
async def set_access_group_scope_rules(access_group_id: int, rules: Iterable[dict]) -> list[dict]:
    """Replace the scope rules of an access group. Each rule's ``attribute``
    must be in ``SCOPE_RULE_ATTRIBUTES`` and its ``value_id`` an existing
    tenant or site (``ValueError`` otherwise; nothing is changed). The model
    name is validated by the caller (``netcontrol.object_scope``)."""
    wanted: dict[tuple[str, str, int], bool] = {}
    for rule in rules:
        attribute = str(rule["attribute"])
        if attribute not in SCOPE_RULE_ATTRIBUTES:
            raise ValueError(f"Unknown scope rule attribute: {attribute}")
        key = (str(rule["model"]), attribute, int(rule["value_id"]))
        wanted[key] = wanted.get(key, False) or bool(rule.get("can_write"))
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT id FROM access_groups WHERE id = ?", (int(access_group_id),))
        if not await cursor.fetchone():
            raise ValueError("Access group not found")
        for attribute, table in _ATTRIBUTE_TABLES.items():
            ids = sorted({k[2] for k in wanted if k[1] == attribute})
            if not ids:
                continue
            cursor = await db.execute(
                f"SELECT id FROM {table} WHERE id IN ({','.join('?' * len(ids))})",  # noqa: S608  # nosec B608 - fixed table names
                tuple(ids),
            )
            found = {int(r[0]) for r in await cursor.fetchall()}
            missing = [i for i in ids if i not in found]
            if missing:
                raise ValueError(f"Unknown {attribute} ids in scope rules: {missing}")
        await db.execute("DELETE FROM access_group_scope_rules WHERE access_group_id = ?", (int(access_group_id),))
        for (model, attribute, value_id), can_write in sorted(wanted.items()):
            await db.execute(
                """
                INSERT INTO access_group_scope_rules (access_group_id, model, attribute, value_id, can_write)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(access_group_id), model, attribute, value_id, 1 if can_write else 0),
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
    return await get_access_group_scope_rules(access_group_id)


async def get_group_scope_keys(group_ids: Iterable[int]) -> dict[str, frozenset[int]]:
    """What the hosts of ``group_ids`` (already expanded with sub-groups)
    reach: ``host_ids``, the ``tenant_ids`` of those hosts, and the
    ``site_ids`` they stand in (their own site, their rack's or their floor
    plan placement's)."""
    ids = tuple(sorted({int(g) for g in group_ids}))
    if not ids:
        return {"host_ids": frozenset(), "tenant_ids": frozenset(), "site_ids": frozenset()}
    marks = ",".join("?" * len(ids))
    db = await _dbcore.get_db(read_only=True)
    try:
        cursor = await db.execute(
            f"SELECT id, tenant_id FROM hosts WHERE group_id IN ({marks})",  # noqa: S608  # nosec B608 - placeholders only
            ids,
        )
        rows = await cursor.fetchall()
        hosts = frozenset(int(r[0]) for r in rows)
        tenants = frozenset(int(r[1]) for r in rows if r[1] is not None)
        cursor = await db.execute(
            f"""
            SELECT h.site_id FROM hosts h WHERE h.group_id IN ({marks})
            UNION
            SELECT r.site_id FROM hosts h INNER JOIN racks r ON r.id = h.rack_id
            WHERE h.group_id IN ({marks})
            UNION
            SELECT f.site_id FROM geo_placements p
            INNER JOIN geo_floors f ON f.id = p.floor_id
            INNER JOIN hosts h ON h.id = p.host_id
            WHERE h.group_id IN ({marks})
            """,  # noqa: S608  # nosec B608 - placeholders only
            ids + ids + ids,
        )
        sites = frozenset(int(r[0]) for r in await cursor.fetchall() if r[0] is not None)
    finally:
        await db.close()
    return {"host_ids": hosts, "tenant_ids": tenants, "site_ids": sites}
