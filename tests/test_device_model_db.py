"""Device model storage (``routes.db.device_model``), the hooks in the
inventory and geolocation modules, and the migration 0085 backfill."""

from __future__ import annotations

import importlib

import pytest
import routes.database as db

_migration = importlib.import_module("routes.migrations.0085_add_device_model")


async def _host(name: str = "edge-sw1", ip: str = "192.0.2.10", device_type: str = "cisco_xe", group: str = "core"):
    groups = {g["name"]: g["id"] for g in await db.get_all_groups()}
    gid = groups.get(group) or await db.create_group(group)
    return await db.add_host(gid, name, ip, device_type)


async def _role_id(name: str) -> int:
    return next(r["id"] for r in await db.list_device_roles() if r["name"] == name)


async def _status_id(name: str) -> int:
    return next(s["id"] for s in await db.list_lifecycle_statuses() if s["name"] == name)


async def _exec(sql: str, params: tuple = ()) -> None:
    conn = await db.get_db()
    try:
        await conn.execute(sql, params)
        await conn.commit()
    finally:
        await conn.close()


# ── Seeds ────────────────────────────────────────────────────────────────────


async def test_seeded_roles_and_statuses():
    roles = {r["name"]: r["color"] for r in await db.list_device_roles()}
    assert roles == {
        "Firewall": "red",
        "Phone": "gray",
        "Router": "blue",
        "Server": "orange",
        "Switch": "teal",
        "Unknown": "gray",
        "WLC": "purple",
        "Wireless": "purple",
    }
    statuses = await db.list_lifecycle_statuses()
    assert [s["name"] for s in statuses if s["is_default"]] == ["Active"]
    assert {s["name"] for s in statuses} == {
        "Active",
        "Planned",
        "Staged",
        "Maintenance",
        "Decommissioning",
        "Retired",
    }
    assert await db.get_default_host_status_id() == await _status_id("Active")


# ── Catalogue CRUD ───────────────────────────────────────────────────────────


async def test_manufacturer_round_trip_and_unique_ignoring_case():
    made = await db.create_manufacturer(name="Example Networks", description="lab gear")
    assert made == {
        "id": made["id"],
        "name": "Example Networks",
        "description": "lab gear",
        "device_type_count": 0,
        "host_count": 0,
    }
    with pytest.raises(ValueError, match="already exists"):
        await db.create_manufacturer(name="example networks")
    other = await db.create_manufacturer(name="Other")
    with pytest.raises(ValueError):
        await db.update_manufacturer(other["id"], name="EXAMPLE NETWORKS", description="")
    renamed = await db.update_manufacturer(other["id"], name="Other Co", description="x")
    assert renamed["name"] == "Other Co" and renamed["description"] == "x"
    assert await db.update_manufacturer(other["id"] + 1000, name="Ghost", description="") is None
    assert await db.get_manufacturer(other["id"] + 1000) is None
    assert [m["name"] for m in await db.list_manufacturers()] == ["Example Networks", "Other Co"]


async def test_device_type_round_trip_counts_and_uniqueness():
    maker = await db.create_manufacturer(name="Example Networks")
    other = await db.create_manufacturer(name="Other")
    dt = await db.create_device_type(
        manufacturer_id=maker["id"], model="EX-1000", part_number="EX-1000-AC", u_height=1, description="1U"
    )
    assert dt == {
        "id": dt["id"],
        "manufacturer_id": maker["id"],
        "manufacturer": "Example Networks",
        "model": "EX-1000",
        "part_number": "EX-1000-AC",
        "u_height": 1,
        "description": "1U",
        "host_count": 0,
    }
    with pytest.raises(ValueError, match="already has"):
        await db.create_device_type(manufacturer_id=maker["id"], model="ex-1000")
    # The same model under another manufacturer is a different device type.
    second = await db.create_device_type(manufacturer_id=other["id"], model="EX-1000")
    with pytest.raises(ValueError):
        await db.update_device_type(
            second["id"], manufacturer_id=maker["id"], model="EX-1000", part_number="", u_height=0, description=""
        )
    moved = await db.update_device_type(
        second["id"], manufacturer_id=maker["id"], model="EX-2000", part_number="p", u_height=2, description="d"
    )
    assert moved["manufacturer"] == "Example Networks" and moved["model"] == "EX-2000" and moved["u_height"] == 2
    assert (
        await db.update_device_type(
            second["id"] + 1000, manufacturer_id=maker["id"], model="x", part_number="", u_height=0, description=""
        )
        is None
    )
    assert [d["model"] for d in await db.list_device_types(maker["id"])] == ["EX-1000", "EX-2000"]
    assert await db.list_device_types(other["id"]) == []
    assert len(await db.list_device_types()) == 2

    host = await _host()
    assert await db.set_host_device_fields(host, {"device_type_id": dt["id"]})
    assert (await db.get_device_type(dt["id"]))["host_count"] == 1
    listed = await db.get_manufacturer(maker["id"])
    assert listed["device_type_count"] == 2 and listed["host_count"] == 1


async def test_role_round_trip():
    role = await db.create_device_role(name="Core", color="blue", description="core layer")
    assert role == {"id": role["id"], "name": "Core", "color": "blue", "description": "core layer", "host_count": 0}
    with pytest.raises(ValueError):
        await db.create_device_role(name="ROUTER")
    updated = await db.update_device_role(role["id"], name="Core layer", color="red", description="")
    assert updated["name"] == "Core layer" and updated["color"] == "red"
    with pytest.raises(ValueError):
        await db.update_device_role(role["id"], name="switch", color="red", description="")
    assert await db.update_device_role(role["id"] + 1000, name="x", color="red", description="") is None


async def test_default_status_moves_in_one_step():
    active = await _status_id("Active")
    made = await db.create_lifecycle_status(name="Spare", color="gray", is_default=True)
    assert made["is_default"] is True
    assert (await db.get_lifecycle_status(active))["is_default"] is False
    assert await db.get_default_host_status_id() == made["id"]
    back = await db.update_lifecycle_status(active, name="Active", color="green", description="", make_default=True)
    assert back["is_default"] is True
    assert (await db.get_lifecycle_status(made["id"]))["is_default"] is False
    assert [s["name"] for s in await db.list_lifecycle_statuses() if s["is_default"]] == ["Active"]
    with pytest.raises(ValueError):
        await db.create_lifecycle_status(name="active")
    with pytest.raises(ValueError):
        await db.update_lifecycle_status(made["id"], name="Retired", color="gray", description="")
    # A missing status changes nothing, not even the current default.
    assert (
        await db.update_lifecycle_status(made["id"] + 1000, name="x", color="gray", description="", make_default=True)
        is None
    )
    assert await db.get_default_host_status_id() == active


async def test_default_status_cannot_be_deleted():
    with pytest.raises(ValueError, match="default status"):
        await db.delete_catalogue_record("status", await _status_id("Active"))
    assert await db.get_lifecycle_status(await _status_id("Active")) is not None


# ── Hosts ────────────────────────────────────────────────────────────────────


async def test_new_host_gets_the_default_status():
    host = await db.get_host(await _host())
    assert host["lifecycle_status_id"] == await _status_id("Active")
    assert host["device_type_id"] is None and host["role_id"] is None and host["site_id"] is None
    assert host["location_detail"] == "" and host["hardware_locked"] == 0 and host["role_locked"] == 0


async def test_new_host_without_a_default_status_has_none():
    await _exec("UPDATE host_statuses SET is_default = 0")
    assert await db.get_default_host_status_id() is None
    host = await db.get_host(await _host())
    assert host["lifecycle_status_id"] is None


async def test_set_fields_sets_and_clears_locks():
    maker = await db.create_manufacturer(name="Example Networks")
    dt = await db.create_device_type(manufacturer_id=maker["id"], model="EX-1000")
    host = await _host()
    switch = await _role_id("Switch")
    assert await db.set_host_device_fields(
        host, {"device_type_id": dt["id"], "role_id": switch, "location_detail": "Row 4", "other": 1}
    )
    row = await db.get_host(host)
    assert (row["device_type_id"], row["role_id"], row["location_detail"]) == (dt["id"], switch, "Row 4")
    assert row["hardware_locked"] == 1 and row["role_locked"] == 1
    assert await db.set_host_device_fields(host, {"device_type_id": None, "location_detail": None})
    row = await db.get_host(host)
    assert row["device_type_id"] is None and row["hardware_locked"] == 0 and row["location_detail"] == ""
    assert row["role_id"] == switch and row["role_locked"] == 1
    # Without lock the lock flags stay as they are.
    assert await db.set_host_device_fields(host, {"role_id": None}, lock=False)
    assert (await db.get_host(host))["role_locked"] == 1
    assert await db.set_host_device_fields(host, {}) is True
    assert await db.set_host_device_fields(host + 1000, {}) is False
    assert await db.set_host_device_fields(host + 1000, {"site_id": None}) is False


async def test_bulk_set_skips_unknown_hosts():
    h1 = await _host("sw1", "192.0.2.11")
    h2 = await _host("sw2", "192.0.2.12")
    retired = await _status_id("Retired")
    assert await db.bulk_set_host_device_fields([h1, h2, h2, h2 + 1000], {"lifecycle_status_id": retired}) == 2
    assert {(await db.get_host(h))["lifecycle_status_id"] for h in (h1, h2)} == {retired}
    assert await db.bulk_set_host_device_fields([], {"lifecycle_status_id": retired}) == 0
    assert await db.bulk_set_host_device_fields([h1], {}) == 0


async def test_check_device_refs():
    site = await db.create_geo_site(name="Site A")
    assert await db.check_device_refs({"site_id": site["id"], "role_id": None, "location_detail": "x"}) == {}
    errors = await db.check_device_refs(
        {"site_id": site["id"] + 1000, "device_type_id": 0, "role_id": 2**40, "lifecycle_status_id": 999999}
    )
    assert set(errors) == {"site_id", "device_type_id", "role_id", "lifecycle_status_id"}
    assert await db.check_device_refs({}) == {}


async def test_filters():
    maker = await db.create_manufacturer(name="Example Networks")
    other = await db.create_manufacturer(name="Other")
    dt1 = await db.create_device_type(manufacturer_id=maker["id"], model="EX-1000")
    dt2 = await db.create_device_type(manufacturer_id=other["id"], model="OT-1")
    switch = await _role_id("Switch")
    h1 = await _host("sw1", "192.0.2.11")
    h2 = await _host("sw2", "192.0.2.12")
    h3 = await _host("sw3", "192.0.2.13", group="edge")
    await db.set_host_device_fields(h1, {"device_type_id": dt1["id"], "role_id": switch})
    await db.set_host_device_fields(h2, {"device_type_id": dt2["id"]})
    find = db.find_host_ids_by_device_filters
    assert set(await find({"manufacturer_id": [maker["id"]]})) == {h1}
    assert set(await find({"manufacturer_id": [maker["id"], None]})) == {h1, h3}
    assert set(await find({"device_type_id": [dt2["id"]]})) == {h2}
    assert set(await find({"role_id": [None]})) == {h2, h3}
    assert set(await find({"role_id": [None], "device_type_id": [dt1["id"], dt2["id"]]})) == {h2}
    assert set(await find({})) == {h1, h2, h3}
    by_id = await find({"device_type_id": [None]})
    assert by_id == {h3: (await db.get_host(h3))["group_id"]}


async def test_display_objects():
    maker = await db.create_manufacturer(name="Example Networks")
    dt = await db.create_device_type(manufacturer_id=maker["id"], model="EX-1000")
    site = await db.create_geo_site(name="Site A")
    host = await _host()
    await db.set_host_device_fields(host, {"device_type_id": dt["id"], "site_id": site["id"]})
    objects = await db.get_device_display_objects([await db.get_host(host), {"device_type_id": None}])
    assert objects["hardware"][dt["id"]]["manufacturer"] == "Example Networks"
    assert objects["site"][site["id"]]["name"] == "Site A"
    assert objects["role"] == {}
    assert set(objects["lifecycle_status"]) == {await _status_id("Active")}
    assert await db.get_device_display_objects([]) == {
        "hardware": {},
        "role": {},
        "lifecycle_status": {},
        "site": {},
    }


# ── Deleting catalogue records ───────────────────────────────────────────────


async def test_delete_device_type_nulls_hosts_and_clears_lock():
    maker = await db.create_manufacturer(name="Example Networks")
    dt = await db.create_device_type(manufacturer_id=maker["id"], model="EX-1000")
    host = await _host()
    await db.set_host_device_fields(host, {"device_type_id": dt["id"]})
    assert await db.count_catalogue_hosts("device_type", dt["id"]) == 1
    assert await db.delete_catalogue_record("device_type", dt["id"]) == 1
    row = await db.get_host(host)
    assert row["device_type_id"] is None and row["hardware_locked"] == 0
    assert await db.get_device_type(dt["id"]) is None


async def test_delete_manufacturer_takes_its_device_types():
    maker = await db.create_manufacturer(name="Example Networks")
    dt1 = await db.create_device_type(manufacturer_id=maker["id"], model="EX-1000")
    dt2 = await db.create_device_type(manufacturer_id=maker["id"], model="EX-2000")
    h1 = await _host("sw1", "192.0.2.11")
    h2 = await _host("sw2", "192.0.2.12")
    await db.set_host_device_fields(h1, {"device_type_id": dt1["id"]})
    await db.set_host_device_fields(h2, {"device_type_id": dt2["id"]})
    assert await db.count_catalogue_hosts("manufacturer", maker["id"]) == 2
    assert await db.delete_catalogue_record("manufacturer", maker["id"]) == 2
    assert await db.list_device_types() == []
    assert (await db.get_host(h1))["device_type_id"] is None


async def test_delete_role_and_status_null_hosts():
    role = await db.create_device_role(name="Core")
    status = await db.create_lifecycle_status(name="Spare")
    host = await _host()
    await db.set_host_device_fields(host, {"role_id": role["id"], "lifecycle_status_id": status["id"]})
    assert await db.delete_catalogue_record("role", role["id"]) == 1
    assert await db.delete_catalogue_record("status", status["id"]) == 1
    row = await db.get_host(host)
    assert row["role_id"] is None and row["role_locked"] == 0 and row["lifecycle_status_id"] is None
    assert await db.delete_catalogue_record("role", role["id"]) == 0


async def test_deleting_a_site_nulls_hosts():
    site = await db.create_geo_site(name="Site A")
    host = await _host()
    await db.set_host_device_fields(host, {"site_id": site["id"], "location_detail": "Rack 2"})
    assert await db.delete_geo_site(site["id"])
    row = await db.get_host(host)
    assert row["site_id"] is None and row["location_detail"] == "Rack 2"


# ── Discovery link ───────────────────────────────────────────────────────────


async def test_link_creates_once_and_repeat_is_a_no_op():
    host = await _host(device_type="cisco_xe")
    await db.link_host_hardware(host, "", "C9300-48P", "switch")
    row = await db.get_host(host)
    dt = await db.get_device_type(row["device_type_id"])
    assert dt["manufacturer"] == "Cisco" and dt["model"] == "C9300-48P"
    assert row["role_id"] == await _role_id("Switch")
    assert row["hardware_locked"] == 0 and row["role_locked"] == 0
    await db.link_host_hardware(host, "", "c9300-48p", "switch")
    other = await _host("sw2", "192.0.2.12", device_type="cisco_ios")
    await db.link_host_hardware(other, "", "C9300-48P ", "")
    assert len(await db.list_device_types()) == 1
    assert [m["name"] for m in await db.list_manufacturers()] == ["Cisco"]
    assert (await db.get_host(other))["device_type_id"] == dt["id"]


async def test_link_uses_vendor_then_unknown():
    host = await _host(device_type="linux")
    await db.link_host_hardware(host, "Juniper Networks", "EX4300-48T", "")
    assert (await db.get_device_type((await db.get_host(host))["device_type_id"]))["manufacturer"] == "Juniper"
    plain = await _host("srv1", "192.0.2.20", device_type="linux")
    await db.link_host_hardware(plain, "", "Example Box 9", "")
    assert (await db.get_device_type((await db.get_host(plain))["device_type_id"]))["manufacturer"] == "Unknown"


async def test_link_respects_locks_and_existing_role():
    maker = await db.create_manufacturer(name="Example Networks")
    chosen = await db.create_device_type(manufacturer_id=maker["id"], model="EX-1000")
    host = await _host()
    firewall = await _role_id("Firewall")
    await db.set_host_device_fields(host, {"device_type_id": chosen["id"], "role_id": firewall})
    await db.link_host_hardware(host, "", "C9300-48P", "switch")
    row = await db.get_host(host)
    assert row["device_type_id"] == chosen["id"] and row["role_id"] == firewall
    assert await db.list_manufacturers() == [await db.get_manufacturer(maker["id"])]
    # A role set without a lock is still never replaced.
    await db.set_host_device_fields(host, {"role_id": None})
    await db.set_host_device_fields(host, {"role_id": firewall}, lock=False)
    await db.link_host_hardware(host, "", "", "switch")
    assert (await db.get_host(host))["role_id"] == firewall


async def test_link_after_clearing_the_lock_fills_again():
    maker = await db.create_manufacturer(name="Example Networks")
    chosen = await db.create_device_type(manufacturer_id=maker["id"], model="EX-1000")
    host = await _host()
    await db.set_host_device_fields(host, {"device_type_id": chosen["id"]})
    await db.set_host_device_fields(host, {"device_type_id": None})
    await db.link_host_hardware(host, "", "C9300-48P", "")
    row = await db.get_host(host)
    assert row["device_type_id"] not in (None, chosen["id"])


async def test_link_ignores_unknown_category_missing_host_and_empty_input():
    host = await _host()
    await db.link_host_hardware(host, "", "", "toaster")
    await db.link_host_hardware(host, "", "", "")
    await db.link_host_hardware(host + 1000, "", "C9300", "switch")
    row = await db.get_host(host)
    assert row["role_id"] is None and row["device_type_id"] is None
    assert await db.list_manufacturers() == []


async def test_link_never_raises(monkeypatch):
    import routes.db.device_model as device_model

    warnings: list[str] = []

    async def broken(*_a, **_kw):
        raise RuntimeError("database is gone")

    monkeypatch.setattr(db, "get_db", broken)
    monkeypatch.setattr(device_model._LOGGER, "warning", lambda msg, *args: warnings.append(msg % args))
    await db.link_host_hardware(1, "", "C9300", "switch")
    assert warnings == ["device model: could not link host 1 to its hardware: database is gone"]


async def test_link_rolls_back_a_failed_step(monkeypatch):
    import routes.db.device_model as device_model

    host = await _host()
    monkeypatch.setattr(device_model, "manufacturer_name", lambda *_a: 1 / 0)
    await db.link_host_hardware(host, "", "C9300", "switch")
    row = await db.get_host(host)
    assert row["device_type_id"] is None and row["role_id"] is None


async def test_device_info_update_links_the_host():
    host = await _host(device_type="arista_eos")
    await db.update_host_device_info(host, "DCS-7050SX", "4.28", "switch")
    row = await db.get_host(host)
    assert row["model"] == "DCS-7050SX"
    assert (await db.get_device_type(row["device_type_id"]))["manufacturer"] == "Arista"
    assert row["role_id"] == await _role_id("Switch")


# ── Geolocation ──────────────────────────────────────────────────────────────


async def test_placement_sets_the_site_only_when_empty():
    site_a = await db.create_geo_site(name="Site A")
    site_b = await db.create_geo_site(name="Site B")
    floor_a = await db.create_geo_floor(site_a["id"], "Ground")
    floor_b = await db.create_geo_floor(site_b["id"], "Ground")
    host = await _host()
    await db.upsert_geo_placement(floor_a["id"], host, 0.5, 0.5)
    assert (await db.get_host(host))["site_id"] == site_a["id"]
    await db.upsert_geo_placement(floor_b["id"], host, 0.2, 0.2)
    assert (await db.get_host(host))["site_id"] == site_a["id"]
    counts = {s["name"]: s["host_count"] for s in await db.list_geo_sites()}
    assert counts == {"Site A": 1, "Site B": 0}


# ── Migration backfill ───────────────────────────────────────────────────────


async def test_backfill_links_existing_hosts_and_is_idempotent():
    site_a = await db.create_geo_site(name="Site A")
    site_b = await db.create_geo_site(name="Site B")
    floor_a = await db.create_geo_floor(site_a["id"], "Ground")
    floor_b = await db.create_geo_floor(site_b["id"], "Ground")
    h1 = await _host("sw1", "192.0.2.11", device_type="cisco_xe")
    h2 = await _host("sw2", "192.0.2.12", device_type="cisco_ios")
    h3 = await _host("fw1", "192.0.2.13", device_type="fortinet")
    h4 = await _host("srv1", "192.0.2.14", device_type="linux")
    h5 = await _host("bare", "192.0.2.15", device_type="cisco_ios")
    await db.upsert_geo_placement(floor_b["id"], h1, 0.5, 0.5)
    await db.upsert_geo_placement(floor_a["id"], h1, 0.5, 0.5)
    # Start from a database as it was before 0085: none of the new values set.
    await _exec("UPDATE hosts SET device_type_id = NULL, role_id = NULL, lifecycle_status_id = NULL, site_id = NULL")
    for host, model, category in (
        (h1, "C9300-48P", "switch"),
        (h2, " c9300-48p ", "Switch"),
        (h3, "FortiGate-60F", "firewall"),
        (h4, "Example Box 9", "toaster"),
        (h5, "", "router"),
    ):
        await _exec("UPDATE hosts SET model = ?, device_category = ? WHERE id = ?", (model, category, host))

    for _ in range(2):
        conn = await db.get_db()
        try:
            await _migration.backfill(conn)
            await conn.commit()
        finally:
            await conn.close()

    makers = {m["name"]: m for m in await db.list_manufacturers()}
    assert set(makers) == {"Cisco", "Fortinet", "Unknown"}
    assert makers["Cisco"]["device_type_count"] == 1 and makers["Cisco"]["host_count"] == 2
    rows = {h: await db.get_host(h) for h in (h1, h2, h3, h4, h5)}
    assert rows[h1]["device_type_id"] == rows[h2]["device_type_id"] is not None
    assert (await db.get_device_type(rows[h4]["device_type_id"]))["manufacturer"] == "Unknown"
    assert rows[h5]["device_type_id"] is None
    assert rows[h1]["role_id"] == rows[h2]["role_id"] == await _role_id("Switch")
    assert rows[h3]["role_id"] == await _role_id("Firewall")
    assert rows[h4]["role_id"] is None and rows[h5]["role_id"] == await _role_id("Router")
    active = await _status_id("Active")
    assert {r["lifecycle_status_id"] for r in rows.values()} == {active}
    assert rows[h1]["site_id"] == min(site_a["id"], site_b["id"])
    assert rows[h2]["site_id"] is None
    assert all(r["hardware_locked"] == 0 and r["role_locked"] == 0 for r in rows.values())


async def test_migration_up_runs_twice():
    conn = await db.get_db()
    try:
        await _migration.up(conn)
    finally:
        await conn.close()
    assert len(await db.list_device_roles()) == 8
    assert [s["name"] for s in await db.list_lifecycle_statuses() if s["is_default"]] == ["Active"]
