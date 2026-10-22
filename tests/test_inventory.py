"""Tests for the inventory bulk host add (the Topology page's "Add to inventory")
and the group hierarchy (parent and sub-groups, migration 0072)."""

from __future__ import annotations

import asyncio
import importlib

import netcontrol.routes.inventory as inventory_routes
import pytest
import routes.database as db_module

import pg_raw
from test_inventory_serial import _make_auth_client


@pytest.fixture
def api(monkeypatch, request):
    return _make_auth_client(monkeypatch, request)


def _group(api, name: str) -> int:
    resp = api.post("/api/inventory", json={"name": name})
    assert resp.status_code in (200, 201), resp.text
    return resp.json()["id"]


def test_bulk_add_adds_skips_existing_and_reports_errors(api):
    other = _group(api, "Existing")
    first = api.post(
        f"/api/inventory/{other}/hosts",
        json={"hostname": "core-1", "ip_address": "10.9.0.1", "device_type": "cisco_xe"},
    )
    assert first.status_code == 201, first.text
    existing_id = first.json()["id"]

    target = _group(api, "From topology")
    resp = api.post(
        f"/api/inventory/{target}/hosts/bulk",
        json={
            "hosts": [
                {"hostname": "dist-1", "ip_address": "10.9.0.2", "device_type": "cisco_xe"},
                {"hostname": "fw-1", "ip_address": "10.9.0.3", "device_type": "cisco_asa"},
                {"hostname": "core-1-again", "ip_address": "10.9.0.1", "device_type": "cisco_ios"},
                {"hostname": "bad", "ip_address": "not-an-ip"},
                {"hostname": "loop", "ip_address": "127.0.0.1"},
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert [(h["hostname"], h["ip_address"]) for h in body["added"]] == [
        ("dist-1", "10.9.0.2"),
        ("fw-1", "10.9.0.3"),
    ]
    assert all(isinstance(h["id"], int) for h in body["added"])

    assert len(body["skipped"]) == 1
    skipped = body["skipped"][0]
    assert skipped["ip_address"] == "10.9.0.1"
    assert skipped["host_id"] == existing_id
    assert skipped["group_id"] == other
    assert skipped["reason"]

    assert [e["hostname"] for e in body["errors"]] == ["bad", "loop"]
    assert "Invalid IP address" in body["errors"][0]["error"]
    assert "reserved range" in body["errors"][1]["error"]

    hosts = api.get(f"/api/inventory/{target}/hosts").json()
    assert {(h["hostname"], h["device_type"]) for h in hosts} == {("dist-1", "cisco_xe"), ("fw-1", "cisco_asa")}


def test_bulk_add_skips_a_repeated_ip_in_the_same_request(api):
    target = _group(api, "Dupes")
    resp = api.post(
        f"/api/inventory/{target}/hosts/bulk",
        json={
            "hosts": [
                {"hostname": "a", "ip_address": "10.9.1.1"},
                {"hostname": "b", "ip_address": "10.9.1.1"},
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [h["hostname"] for h in body["added"]] == ["a"]
    assert [(s["hostname"], s["group_id"]) for s in body["skipped"]] == [("b", target)]


def test_bulk_add_caps_the_batch(api):
    target = _group(api, "Too many")
    hosts = [
        {"hostname": f"h{i}", "ip_address": f"10.20.{i // 250}.{i % 250 + 1}"}
        for i in range(inventory_routes.BULK_ADD_MAX_HOSTS + 1)
    ]
    resp = api.post(f"/api/inventory/{target}/hosts/bulk", json={"hosts": hosts})
    assert resp.status_code == 400
    assert api.get(f"/api/inventory/{target}/hosts").json() == []


def test_bulk_add_unknown_group_is_404(api):
    resp = api.post("/api/inventory/999999/hosts/bulk", json={"hosts": []})
    assert resp.status_code == 404


def test_bulk_add_per_group_route_reports_the_group(api):
    target = _group(api, "Per group")
    resp = api.post(
        f"/api/inventory/{target}/hosts/bulk",
        json={"hosts": [{"hostname": "edge-1", "ip_address": "10.9.2.1"}]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"added", "skipped", "errors"}
    assert [(h["hostname"], h["group_id"], h["group_name"]) for h in body["added"]] == [("edge-1", target, "Per group")]


def _names_by_id(api) -> dict[int, str]:
    return {g["id"]: g["name"] for g in api.get("/api/inventory").json()}


def test_grouped_bulk_add_creates_named_groups_once(api):
    existing = _group(api, "Meraki - HQ")
    resp = api.post(
        "/api/inventory/hosts/bulk",
        json={
            "hosts": [
                {"hostname": "sw-1", "ip_address": "10.9.3.1", "group_name": "Meraki - HQ"},
                {"hostname": "vm-1", "ip_address": "10.9.3.2", "group_name": "AWS - prod-vpc"},
                {"hostname": "vm-2", "ip_address": "10.9.3.3", "group_name": " AWS - prod-vpc "},
                {"hostname": "nb-1", "ip_address": "10.9.3.4", "group_name": "core - neighbors"},
                {"hostname": "orphan", "ip_address": "10.9.3.5"},
                {"hostname": "both", "ip_address": "10.9.3.6", "group_id": existing, "group_name": "x"},
                {"hostname": "bad", "ip_address": "not-an-ip", "group_name": "Never created"},
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    created = {g["name"]: g["id"] for g in body["groups_created"]}
    assert set(created) == {"AWS - prod-vpc", "core - neighbors"}
    assert [(h["hostname"], h["group_name"]) for h in body["added"]] == [
        ("sw-1", "Meraki - HQ"),
        ("vm-1", "AWS - prod-vpc"),
        ("vm-2", "AWS - prod-vpc"),
        ("nb-1", "core - neighbors"),
    ]
    assert body["added"][0]["group_id"] == existing
    assert body["added"][1]["group_id"] == body["added"][2]["group_id"] == created["AWS - prod-vpc"]
    assert [e["hostname"] for e in body["errors"]] == ["orphan", "both", "bad"]

    names = list(_names_by_id(api).values())
    assert names.count("AWS - prod-vpc") == 1
    assert "Never created" not in names
    groups = {g["name"]: g for g in api.get("/api/inventory").json()}
    assert groups["AWS - prod-vpc"]["description"] == inventory_routes.BULK_ADD_GROUP_DESCRIPTION
    vpc_hosts = api.get(f"/api/inventory/{created['AWS - prod-vpc']}/hosts").json()
    assert {h["hostname"] for h in vpc_hosts} == {"vm-1", "vm-2"}

    # A second request reuses the group the first one created.
    again = api.post(
        "/api/inventory/hosts/bulk",
        json={"hosts": [{"hostname": "vm-3", "ip_address": "10.9.3.7", "group_name": "AWS - prod-vpc"}]},
    )
    assert again.status_code == 200, again.text
    assert again.json()["groups_created"] == []
    assert again.json()["added"][0]["group_id"] == created["AWS - prod-vpc"]


def test_grouped_bulk_add_uses_the_body_default_group(api):
    default = _group(api, "Default target")
    other = _group(api, "Other target")
    resp = api.post(
        "/api/inventory/hosts/bulk",
        json={
            "group_id": default,
            "hosts": [
                {"hostname": "d-1", "ip_address": "10.9.4.1"},
                {"hostname": "o-1", "ip_address": "10.9.4.2", "group_id": other},
                {"hostname": "missing", "ip_address": "10.9.4.3", "group_id": 999999},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [(h["hostname"], h["group_id"]) for h in body["added"]] == [("d-1", default), ("o-1", other)]
    assert [(e["hostname"], e["error"]) for e in body["errors"]] == [("missing", "Group not found")]
    assert body["groups_created"] == []


def test_grouped_bulk_add_unknown_default_group_is_404(api):
    resp = api.post("/api/inventory/hosts/bulk", json={"group_id": 999999, "hosts": []})
    assert resp.status_code == 404


# ── Group hierarchy ──────────────────────────────────────────────────────────


def _sub(api, name: str, parent_id: int):
    return api.post("/api/inventory", json={"name": name, "parent_id": parent_id})


def _listing(api, ids: set[int], include_hosts: bool = False) -> list[tuple[str, int, int | None]]:
    url = "/api/inventory?include_hosts=true" if include_hosts else "/api/inventory"
    resp = api.get(url)
    assert resp.status_code == 200, resp.text
    return [(g["path"], g["depth"], g["parent_id"]) for g in resp.json() if g["id"] in ids]


def test_sub_groups_list_as_a_tree_with_path_and_depth(api):
    zeta = _group(api, "Zeta")
    alpha = _group(api, "Alpha")
    beta = _sub(api, "Beta", zeta).json()["id"]
    aardvark = _sub(api, "Aardvark", zeta).json()["id"]
    deep = _sub(api, "Deep", beta).json()["id"]
    ids = {zeta, alpha, beta, aardvark, deep}

    expected = [
        ("Alpha", 0, None),
        ("Zeta", 0, None),
        ("Zeta / Aardvark", 1, zeta),
        ("Zeta / Beta", 1, zeta),
        ("Zeta / Beta / Deep", 2, beta),
    ]
    assert _listing(api, ids) == expected
    assert _listing(api, ids, include_hosts=True) == expected

    one = api.get(f"/api/inventory/{deep}").json()
    assert (one["path"], one["depth"], one["parent_id"]) == ("Zeta / Beta / Deep", 2, beta)

    # The per-user order applies among siblings; sub-groups stay under their parent.
    resp = api.post("/api/inventory/groups/reorder", json={"ordered_ids": [zeta, beta, aardvark, alpha]})
    assert resp.status_code == 200, resp.text
    assert _listing(api, ids) == [
        ("Zeta", 0, None),
        ("Zeta / Beta", 1, zeta),
        ("Zeta / Beta / Deep", 2, beta),
        ("Zeta / Aardvark", 1, zeta),
        ("Alpha", 0, None),
    ]


def test_a_group_cannot_move_under_itself_or_a_sub_group(api):
    top = _group(api, "Top")
    mid = _sub(api, "Mid", top).json()["id"]
    leaf = _sub(api, "Leaf", mid).json()["id"]

    for parent in (top, leaf):
        resp = api.put(f"/api/inventory/{top}", json={"name": "Top", "parent_id": parent})
        assert resp.status_code == 400, resp.text
    assert "sub-groups" in resp.json()["error"]["message"]
    assert _sub(api, "Orphan", 999999).status_code == 400
    assert api.put(f"/api/inventory/{mid}", json={"name": "Mid", "parent_id": 999999}).status_code == 400

    # Omitting parent_id keeps the parent; null moves the group to the top level.
    assert api.put(f"/api/inventory/{leaf}", json={"name": "Leaf renamed"}).status_code == 200
    assert api.get(f"/api/inventory/{leaf}").json()["path"] == "Top / Mid / Leaf renamed"
    assert api.put(f"/api/inventory/{mid}", json={"name": "Mid", "parent_id": None}).status_code == 200
    assert api.get(f"/api/inventory/{leaf}").json()["path"] == "Mid / Leaf renamed"
    # A move under another branch is allowed.
    assert api.put(f"/api/inventory/{mid}", json={"name": "Mid", "parent_id": top}).status_code == 200
    assert api.get(f"/api/inventory/{mid}").json()["depth"] == 1


def test_a_group_with_sub_groups_cannot_be_deleted(api):
    parent = _group(api, "Parent")
    child = _sub(api, "Child", parent).json()["id"]

    resp = api.delete(f"/api/inventory/{parent}")
    assert resp.status_code == 409
    assert "sub-groups" in resp.json()["error"]["message"]
    assert api.get(f"/api/inventory/{parent}").status_code == 200

    assert api.delete(f"/api/inventory/{child}").status_code == 200
    assert api.delete(f"/api/inventory/{parent}").status_code == 200
    assert api.get(f"/api/inventory/{parent}").status_code == 404


def test_group_names_are_unique_among_siblings(api):
    first = _group(api, "Region A")
    second = _group(api, "Region B")
    assert _sub(api, "Site", first).status_code == 201
    assert _sub(api, "Site", second).status_code == 201
    # A top-level group may share a sub-group's name.
    assert api.post("/api/inventory", json={"name": "Site"}).status_code == 201

    again = _sub(api, "Site", first)
    assert again.status_code == 409
    assert "already exists" in again.json()["error"]["message"]
    assert api.post("/api/inventory", json={"name": "Region A"}).status_code == 409

    other = _sub(api, "Other", first).json()["id"]
    assert api.put(f"/api/inventory/{other}", json={"name": "Site"}).status_code == 409


def test_grouped_bulk_add_creates_the_group_path(api):
    aws = _group(api, "AWS")
    resp = api.post(
        "/api/inventory/hosts/bulk",
        json={
            "hosts": [
                {"hostname": "hq-sw", "ip_address": "10.9.5.1", "group_path": ["Meraki", "1000 - HQ"]},
                {"hostname": "br-sw", "ip_address": "10.9.5.2", "group_path": ["Meraki", "Branch"]},
                {"hostname": "hq-ap", "ip_address": "10.9.5.3", "group_path": [" Meraki ", "1000 - HQ"]},
                {"hostname": "vm-1", "ip_address": "10.9.5.4", "group_path": ["AWS", "vpc-1"]},
                {"hostname": "blank", "ip_address": "10.9.5.5", "group_path": ["Meraki", " "]},
                {"hostname": "two", "ip_address": "10.9.5.6", "group_path": ["Meraki"], "group_id": aws},
                {"hostname": "bad", "ip_address": "not-an-ip", "group_path": ["Never", "Created"]},
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    created = {g["path"]: g for g in body["groups_created"]}
    assert list(created) == ["Meraki", "Meraki / 1000 - HQ", "Meraki / Branch", "AWS / vpc-1"]
    meraki = created["Meraki"]["id"]
    assert created["Meraki"]["parent_id"] is None
    assert created["Meraki / 1000 - HQ"]["parent_id"] == meraki
    assert created["Meraki / Branch"]["parent_id"] == meraki
    assert created["AWS / vpc-1"]["parent_id"] == aws
    assert created["Meraki / Branch"]["name"] == "Branch"

    assert [(h["hostname"], h["group_name"], h["group_path"]) for h in body["added"]] == [
        ("hq-sw", "1000 - HQ", "Meraki / 1000 - HQ"),
        ("br-sw", "Branch", "Meraki / Branch"),
        ("hq-ap", "1000 - HQ", "Meraki / 1000 - HQ"),
        ("vm-1", "vpc-1", "AWS / vpc-1"),
    ]
    assert body["added"][0]["group_id"] == body["added"][2]["group_id"] == created["Meraki / 1000 - HQ"]["id"]
    assert [e["hostname"] for e in body["errors"]] == ["blank", "two", "bad"]

    paths = [g["path"] for g in api.get("/api/inventory").json()]
    assert paths.count("Meraki") == 1
    assert not any(p.startswith("Never") for p in paths)
    # Hosts go into the leaf only; the parent has none of its own.
    assert api.get(f"/api/inventory/{meraki}/hosts").json() == []

    again = api.post(
        "/api/inventory/hosts/bulk",
        json={"hosts": [{"hostname": "hq-2", "ip_address": "10.9.5.7", "group_path": ["Meraki", "1000 - HQ"]}]},
    )
    assert again.status_code == 200, again.text
    assert again.json()["groups_created"] == []
    assert again.json()["added"][0]["group_id"] == created["Meraki / 1000 - HQ"]["id"]


def test_bulk_add_group_name_matches_a_top_level_group_only(api):
    parent = _group(api, "Cloud")
    nested = _sub(api, "Shared", parent).json()["id"]
    resp = api.post(
        "/api/inventory/hosts/bulk",
        json={"hosts": [{"hostname": "s-1", "ip_address": "10.9.6.1", "group_name": "Shared"}]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [(g["name"], g["parent_id"]) for g in body["groups_created"]] == [("Shared", None)]
    assert body["added"][0]["group_id"] != nested


def test_migration_0072_moves_name_uniqueness_to_siblings():
    migration = importlib.import_module("routes.migrations.0072_add_inventory_group_parent")

    async def _shape() -> dict:
        indexes = {
            r["indexname"]
            for r in await pg_raw.fetch("SELECT indexname FROM pg_indexes WHERE tablename = 'inventory_groups'")
        }
        constraints = {
            r["conname"]
            for r in await pg_raw.fetch(
                "SELECT conname FROM pg_constraint WHERE conrelid = 'inventory_groups'::regclass"
            )
        }
        return {
            "columns": await pg_raw.table_columns("inventory_groups"),
            "indexes": indexes,
            "constraints": constraints,
        }

    async def _run() -> tuple[dict, dict]:
        await db_module.init_db()
        fresh = await _shape()
        # Put the table back the way it was before 0072.
        await pg_raw.execute("DROP INDEX idx_inventory_groups_sibling_name")
        await pg_raw.execute("DROP INDEX idx_inventory_groups_parent_id")
        await pg_raw.execute("ALTER TABLE inventory_groups DROP COLUMN parent_id")
        await pg_raw.execute("ALTER TABLE inventory_groups ADD CONSTRAINT inventory_groups_name_key UNIQUE (name)")
        db = await db_module.get_db()
        try:
            await migration.up(db)
            await migration.up(db)  # re-running is a no-op
        finally:
            await db.close()
        return fresh, await _shape()

    fresh, migrated = asyncio.run(_run())
    assert fresh == migrated
    assert "parent_id" in migrated["columns"]
    assert {"idx_inventory_groups_parent_id", "idx_inventory_groups_sibling_name"} <= migrated["indexes"]
    assert "fk_inventory_groups_parent_id_inventory_groups" in migrated["constraints"]
    assert "inventory_groups_name_key" not in migrated["constraints"]
    assert migration.VERSION == 72
