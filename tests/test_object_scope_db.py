"""Object-level permission storage (migration 0089, ``routes.db.users``):
access group scopes and grants, the sub-group expansion of a grant, the
union across a user's access groups, ``all`` winning, and the cascades."""

from __future__ import annotations

import importlib

import pytest
import routes.database as db

_migration = importlib.import_module("routes.migrations.0089_add_object_scopes")


async def _user(name: str, group_ids: list[int]) -> int:
    uid = await db.create_user(name, "hash", "salt")
    if group_ids:
        await db.set_user_groups(uid, group_ids)
    return uid


async def _tree() -> dict[str, int]:
    """site-a (with site-a/floor-1 and its floor-1/rack-1) and site-b."""
    a = await db.create_group("site-a")
    a1 = await db.create_group("floor-1", parent_id=a)
    a11 = await db.create_group("rack-1", parent_id=a1)
    b = await db.create_group("site-b")
    return {"a": a, "a1": a1, "a11": a11, "b": b}


async def test_migration_is_idempotent():
    conn = await db.get_db()
    try:
        await _migration.up(conn)
    finally:
        await conn.close()
    gid = await db.create_access_group("viewers", "", ["inventory"])
    group = await db.get_access_group(gid)
    assert group["object_scope"] == "all"
    assert group["inventory_scopes"] == []


async def test_scope_and_grants_round_trip():
    t = await _tree()
    gid = await db.create_access_group(
        "east ops",
        "",
        ["inventory"],
        object_scope="groups",
        inventory_scopes=[
            {"inventory_group_id": t["b"], "can_write": False},
            {"inventory_group_id": t["a"], "can_write": True},
            # A duplicate grant merges: write wins.
            {"inventory_group_id": t["b"], "can_write": True},
        ],
    )
    group = await db.get_access_group(gid)
    assert group["object_scope"] == "groups"
    assert group["inventory_scopes"] == [
        {"inventory_group_id": t["a"], "can_write": True},
        {"inventory_group_id": t["b"], "can_write": True},
    ]
    listed = next(g for g in await db.get_all_access_groups() if g["id"] == gid)
    assert listed["inventory_scopes"] == group["inventory_scopes"]

    # Leaving the scope out of an update keeps it.
    await db.update_access_group(gid, "east ops", "d", ["inventory"])
    assert (await db.get_access_group(gid))["inventory_scopes"] == group["inventory_scopes"]
    # Back to all: the grants are cleared.
    await db.update_access_group(
        gid, "east ops", "d", ["inventory"], object_scope="all", inventory_scopes=group["inventory_scopes"]
    )
    group = await db.get_access_group(gid)
    assert group["object_scope"] == "all"
    assert group["inventory_scopes"] == []


async def test_unknown_inventory_group_is_rejected():
    with pytest.raises(ValueError, match="inventory groups"):
        await db.create_access_group(
            "ghost", "", [], object_scope="groups", inventory_scopes=[{"inventory_group_id": 999999}]
        )
    assert all(g["name"] != "ghost" for g in await db.get_all_access_groups())
    gid = await db.create_access_group("real", "", [])
    with pytest.raises(ValueError, match="inventory groups"):
        await db.update_access_group(
            gid, "real", "", [], object_scope="groups", inventory_scopes=[{"inventory_group_id": 999999}]
        )
    assert (await db.get_access_group(gid))["object_scope"] == "all"


async def test_grant_covers_sub_groups_and_write_wins():
    t = await _tree()
    reader = await db.create_access_group(
        "readers", "", [], object_scope="groups", inventory_scopes=[{"inventory_group_id": t["a"]}]
    )
    writer = await db.create_access_group(
        "rack writers",
        "",
        [],
        object_scope="groups",
        inventory_scopes=[{"inventory_group_id": t["a1"], "can_write": True}, {"inventory_group_id": t["b"]}],
    )
    uid = await _user("op-east", [reader, writer])
    scope = await db.get_user_object_scope(uid)
    assert scope["unrestricted"] is False
    assert scope["read_group_ids"] == sorted([t["a"], t["a1"], t["a11"], t["b"]])
    assert scope["write_group_ids"] == sorted([t["a1"], t["a11"]])

    # A sub-group created later is covered at once.
    a12 = await db.create_group("rack-2", parent_id=t["a1"])
    assert a12 in (await db.get_user_object_scope(uid))["write_group_ids"]


async def test_any_all_group_makes_the_user_unrestricted():
    t = await _tree()
    scoped = await db.create_access_group(
        "scoped", "", [], object_scope="groups", inventory_scopes=[{"inventory_group_id": t["a"]}]
    )
    everything = await db.create_access_group("everything", "", [])
    uid = await _user("mixed", [scoped, everything])
    assert (await db.get_user_object_scope(uid))["unrestricted"] is True


async def test_no_groups_or_no_grants_sees_nothing():
    lonely = await _user("lonely", [])
    assert await db.get_user_object_scope(lonely) == {
        "unrestricted": False,
        "read_group_ids": [],
        "write_group_ids": [],
    }
    empty = await db.create_access_group("empty", "", [], object_scope="groups")
    uid = await _user("empty-member", [empty])
    assert (await db.get_user_object_scope(uid))["read_group_ids"] == []


async def test_cascades_on_delete():
    t = await _tree()
    gid = await db.create_access_group(
        "cascade",
        "",
        [],
        object_scope="groups",
        inventory_scopes=[{"inventory_group_id": t["b"]}, {"inventory_group_id": t["a11"], "can_write": True}],
    )
    uid = await _user("cascade-user", [gid])
    await db.delete_group(t["b"])
    assert (await db.get_access_group(gid))["inventory_scopes"] == [{"inventory_group_id": t["a11"], "can_write": True}]
    assert (await db.get_user_object_scope(uid))["read_group_ids"] == [t["a11"]]

    await db.delete_access_group(gid)
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM access_group_inventory_scopes WHERE access_group_id = ?", (gid,)
        )
        assert (await cursor.fetchone())[0] == 0
    finally:
        await conn.close()
    assert (await db.get_user_object_scope(uid))["read_group_ids"] == []
