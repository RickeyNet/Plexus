"""Tests for the mutes of topology (API-collected) entities.

Covers, with no network access: the ``topology_mutes`` CRUD (upsert on the
unique key, list, get, delete) and ``TopologyMuteIndex`` matching (an entity
mute, a device mute covering its uplinks and tunnels, a site mute covering
every entity at the site and the edges whose far end is there, scoping to
one source).

All names, serials and sites are invented.
"""

from __future__ import annotations

import routes.database as db_module

DEVICE = {
    "entity_type": "device",
    "entity_id": "d:Q2XX-AAAA-0001",
    "name": "Branch-12 MX",
    "state": "down",
    "site": "Branch-12",
}
UPLINK = {
    "entity_type": "uplink",
    "entity_id": "uplink:w1>d:Q2XX-AAAA-0001:wan1",
    "name": "Branch-12 MX wan1",
    "state": "down",
    "site": "Branch-12",
    "meta": {"kind": "uplink", "a": "w1", "b": "d:Q2XX-AAAA-0001"},
}
HUB = {"entity_type": "device", "entity_id": "d:Q2XX-AAAA-0002", "name": "Hub MX", "state": "up", "site": "Hub"}
TUNNEL = {
    "entity_type": "tunnel",
    "entity_id": "vpn:d:Q2XX-AAAA-0002>d:Q2XX-AAAA-0001",
    "name": "Hub MX - Branch-12 MX",
    "state": "down",
    "site": "Hub",
    "meta": {"kind": "vpn", "a": "d:Q2XX-AAAA-0002", "b": "d:Q2XX-AAAA-0001"},
}


def _as(entity: dict, provider: str = "meraki", org_ref: int = 7) -> dict:
    return {"provider": provider, "org_ref": org_ref, "meta": {}, **entity}


async def _seed() -> None:
    await db_module.apply_topology_entity_states("meraki", 7, [DEVICE, UPLINK, HUB, TUNNEL], org_name="Example Org")


async def _mute_device(reason: str = "not installed") -> dict:
    return await db_module.create_topology_mute(
        "meraki", 7, "entity", entity_type="device", entity_id=DEVICE["entity_id"], reason=reason, created_by="admin"
    )


async def test_entity_mute_matches_only_that_entity():
    await _seed()
    mute = await _mute_device()
    index = await db_module.load_topology_mute_index()
    assert index.match(_as(DEVICE))["id"] == mute["id"]
    assert index.match(_as(HUB)) is None


async def test_device_mute_covers_its_uplinks_and_tunnels():
    await _seed()
    mute = await _mute_device()
    index = await db_module.load_topology_mute_index("meraki", 7)
    assert index.match(_as(UPLINK))["id"] == mute["id"]
    assert index.match(_as(TUNNEL))["id"] == mute["id"]


async def test_site_mute_covers_every_entity_at_site():
    await _seed()
    mute = await db_module.create_topology_mute("meraki", 7, "site", site="Branch-12", reason="r", created_by="admin")
    index = await db_module.load_topology_mute_index()
    assert index.match(_as(DEVICE))["id"] == mute["id"]
    assert index.match(_as(UPLINK))["id"] == mute["id"]
    assert index.match(_as(HUB)) is None
    assert index.match_site("meraki", 7, "Branch-12")["id"] == mute["id"]
    assert index.match_site("meraki", 7, "Hub") is None


async def test_site_mute_covers_edge_with_far_end_at_site():
    await _seed()
    mute = await db_module.create_topology_mute("meraki", 7, "site", site="Branch-12", reason="r", created_by="admin")
    index = await db_module.load_topology_mute_index()
    # The tunnel is stored under the hub's site; its branch end is muted.
    assert TUNNEL["site"] == "Hub"
    assert index.match(_as(TUNNEL))["id"] == mute["id"]
    # A state row as read from the database (meta as JSON text) matches too.
    (row,) = [r for r in await db_module.list_topology_entity_states("meraki", 7, "tunnel")]
    stored = {**row, "meta_json": '{"a": "d:Q2XX-AAAA-0002", "b": "d:Q2XX-AAAA-0001"}'}
    stored.pop("meta")
    assert index.match(stored)["id"] == mute["id"]


async def test_mute_is_scoped_to_its_source():
    await _seed()
    await _mute_device()
    await db_module.create_topology_mute("meraki", 7, "site", site="Branch-12", reason="r", created_by="admin")
    index = await db_module.load_topology_mute_index()
    assert index.match(_as(DEVICE, org_ref=8)) is None
    assert index.match(_as(DEVICE, provider="cato")) is None
    assert index.match(_as(UPLINK, org_ref=8)) is None
    assert index.match_site("cato", 7, "Branch-12") is None


async def test_duplicate_mute_updates_reason():
    await _seed()
    first = await _mute_device("first")
    second = await db_module.create_topology_mute(
        "meraki", 7, "entity", entity_type="device", entity_id=DEVICE["entity_id"], reason="second", created_by="ops"
    )
    assert second["id"] == first["id"] and second["created_at"] == first["created_at"]
    assert second["reason"] == "second" and second["created_by"] == "ops"
    listed = await db_module.list_topology_mutes()
    assert [(m["id"], m["reason"]) for m in listed] == [(first["id"], "second")]
    assert await db_module.list_topology_mutes("meraki", 7) == listed
    assert await db_module.list_topology_mutes("cato") == []


async def test_delete_mute():
    await _seed()
    mute = await _mute_device()
    assert (await db_module.get_topology_mute(mute["id"]))["scope"] == "entity"
    assert await db_module.delete_topology_mute(mute["id"]) is True
    assert await db_module.delete_topology_mute(mute["id"]) is False
    assert await db_module.get_topology_mute(mute["id"]) is None


async def test_empty_index_is_falsy_and_matches_nothing():
    await _seed()
    index = await db_module.load_topology_mute_index()
    assert not index
    assert index.match(_as(DEVICE)) is None and index.match(_as(TUNNEL)) is None
    assert index.match_site("meraki", 7, "Branch-12") is None
    await _mute_device()
    assert await db_module.load_topology_mute_index()
