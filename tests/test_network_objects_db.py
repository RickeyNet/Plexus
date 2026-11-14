"""VRF and VLAN storage (``routes.db.network_objects``): records, counts, the
VLAN resolution rule, discovery that only creates, interface addresses, the
hooks in the inventory and IPAM writers, and the migration 0086 backfill."""

from __future__ import annotations

import importlib

import pytest
import routes.database as db

_migration = importlib.import_module("routes.migrations.0086_add_vrfs_vlans_interface_addresses")


async def _host(name: str = "edge-sw1", ip: str = "192.0.2.10", device_type: str = "cisco_ios", **kw) -> int:
    groups = {g["name"]: g["id"] for g in await db.get_all_groups()}
    gid = groups.get("core") or await db.create_group("core")
    return await db.add_host(gid, name, ip, device_type, **kw)


async def _exec(sql: str, params: tuple = ()) -> None:
    conn = await db.get_db()
    try:
        await conn.execute(sql, params)
        await conn.commit()
    finally:
        await conn.close()


async def _port(host_id: int, if_index: int, name: str, access: int = 0, trunk: str = "") -> None:
    await _exec(
        "INSERT INTO interface_inventory (host_id, if_index, name, access_vlan, trunk_vlans) VALUES (?, ?, ?, ?, ?)",
        (host_id, if_index, name, access, trunk),
    )


def _row(interface: str, address: str, network: str, vrf: str = "", role: str = "primary", svi: int = 0) -> dict:
    return {
        "interface": interface,
        "interface_key": interface.lower(),
        "address": address,
        "prefix_length": int(network.split("/")[1]),
        "network": network,
        "vrf_name": vrf,
        "role": role,
        "protocol": "HSRP" if role == "virtual" else "",
        "svi_vid": svi,
    }


async def _vrf(name: str) -> dict:
    return next(v for v in await db.list_vrfs() if v["name"] == name)


# ── VRFs ─────────────────────────────────────────────────────────────────────


async def test_vrf_round_trip_and_unique_ignoring_case():
    made = await db.create_vrf(name="BLUE", rd="65000:10", description="tenant")
    assert made == {
        "id": made["id"],
        "name": "BLUE",
        "rd": "65000:10",
        "description": "tenant",
        "origin": "manual",
        "created_at": made["created_at"],
        "host_count": 0,
        "device_count": 0,
        "prefix_count": 0,
        "address_count": 0,
    }
    assert len(made["created_at"]) == 19
    with pytest.raises(ValueError, match="already exists"):
        await db.create_vrf(name="blue")
    updated = await db.update_vrf(made["id"], rd="65000:11", description="")
    assert (updated["name"], updated["rd"], updated["description"]) == ("BLUE", "65000:11", "")
    assert await db.update_vrf(999999, rd="", description="") is None
    assert await db.get_vrf(999999) is None and await db.get_vrf_detail(999999) is None
    await db.create_vrf(name="ALPHA")
    assert [v["name"] for v in await db.list_vrfs()] == ["ALPHA", "BLUE"]
    assert await db.delete_vrf(made["id"]) is True
    assert await db.delete_vrf(made["id"]) is False


async def test_ensure_vrfs_creates_missing_only_and_never_overwrites():
    await db.create_vrf(name="BLUE", rd="65000:10", description="kept")
    assert await db.ensure_vrfs(["BLUE", " RED ", "", "x" * 65, "RED"], "discovered") == 1
    assert await db.ensure_vrfs(["BLUE", "RED"]) == 0
    assert await db.ensure_vrfs([]) == 0
    blue, red = await _vrf("BLUE"), await _vrf("RED")
    assert (blue["origin"], blue["rd"], blue["description"]) == ("manual", "65000:10", "kept")
    assert red["origin"] == "discovered"
    assert len(await db.list_vrfs()) == 2


async def test_vrf_counts_usage_and_detail():
    source = await db.get_or_create_builtin_ipam_source()
    h1 = await _host("r1", "192.0.2.10", vrf_name="BLUE")
    h2 = await _host("r2", "192.0.2.11")
    # Host writes and prefix writes create the record.
    assert (await _vrf("BLUE"))["origin"] == "manual"
    await db.create_ipam_prefix(source["id"], "198.51.100.0/24", vrf="BLUE")
    assert await db.replace_host_bindings(
        h1,
        [
            _row("Vlan10", "198.51.100.1", "198.51.100.0/24", "BLUE", svi=10),
            _row("Vlan20", "203.0.113.1", "203.0.113.0/24", "BLUE", svi=20),
            _row("Vlan20", "203.0.113.3", "203.0.113.0/24", "BLUE", role="virtual", svi=20),
        ],
        {"BLUE": 2},
    )
    assert await db.replace_host_bindings(h2, [_row("Gi0/1", "203.0.113.2", "203.0.113.0/24", "BLUE")], {"BLUE": 1})
    blue = await _vrf("BLUE")
    assert (blue["host_count"], blue["device_count"], blue["prefix_count"], blue["address_count"]) == (1, 2, 2, 4)
    assert await db.vrf_usage("BLUE") == {
        "hosts": 1,
        "prefixes": 1,
        "allocations": 0,
        "interface_addresses": 4,
        "device_vrfs": 2,
    }
    detail = await db.get_vrf_detail(blue["id"], limit=3)
    assert detail["devices"] == [
        {"host_id": h1, "hostname": "r1", "interface_count": 2},
        {"host_id": h2, "hostname": "r2", "interface_count": 1},
    ]
    assert detail["truncated"] is True and len(detail["interfaces"]) == 3
    assert detail["interfaces"][0]["hostname"] == "r1" and detail["interfaces"][0]["interface"] == "Vlan10"
    assert detail["prefixes"] == [
        {"subnet": "198.51.100.0/24", "source": "plexus"},
        {"subnet": "203.0.113.0/24", "source": "interface"},
    ]
    assert (await db.get_vrf_detail(blue["id"]))["truncated"] is False


async def test_replace_bindings_replaces_and_cascades_with_the_host():
    host = await _host()
    assert await db.replace_host_bindings(999999, [], {}) is False
    await db.replace_host_bindings(host, [_row("Gi0/1", "192.0.2.1", "192.0.2.0/24", "RED")], {"RED": 1, "GREEN": 0})
    assert (await _vrf("RED"))["origin"] == "discovered" and await _vrf("GREEN")
    await db.replace_host_bindings(host, [_row("Gi0/2", "192.0.2.5", "192.0.2.0/24")], {})
    found = await db.get_interface_addresses_for_host(host)
    assert [a["interface"] for a in found["addresses"]] == ["Gi0/2"] and found["vrfs"] == []
    # Discovery never deletes a record.
    assert {v["name"] for v in await db.list_vrfs()} == {"RED", "GREEN"}
    await db.remove_host(host)
    assert await db.get_interface_addresses_for_host(host) == {"addresses": [], "vrfs": []}
    assert (await _vrf("RED"))["address_count"] == 0


async def test_host_addresses_carry_vrf_and_vlan_record_ids():
    site = await db.create_geo_site(name="Site A")
    host = await _host()
    await db.set_host_device_fields(host, {"site_id": site["id"]})
    vrf = await db.create_vrf(name="BLUE")
    global_vlan = await db.create_vlan(vid=10)
    site_vlan = await db.create_vlan(vid=10, site_id=site["id"])
    await db.replace_host_bindings(
        host,
        [
            _row("Vlan10", "192.0.2.1", "192.0.2.0/24", "BLUE", svi=10),
            _row("Vlan30", "198.51.100.1", "198.51.100.0/24", "UNKNOWN", svi=30),
            _row("Gi0/1", "203.0.113.1", "203.0.113.0/30"),
        ],
        {"BLUE": 1, "UNKNOWN": 1},
    )
    await db.delete_vrf((await _vrf("UNKNOWN"))["id"])
    found = await db.get_interface_addresses_for_host(host)
    ids = {a["interface"]: (a["vrf_id"], a["vlan_id"]) for a in found["addresses"]}
    assert ids == {"Vlan10": (vrf["id"], site_vlan["id"]), "Vlan30": (None, None), "Gi0/1": (None, None)}
    assert found["vrfs"] == [
        {"name": "BLUE", "vrf_id": vrf["id"], "interface_count": 1},
        {"name": "UNKNOWN", "vrf_id": None, "interface_count": 1},
    ]
    await db.delete_vlan(site_vlan["id"])
    found = await db.get_interface_addresses_for_host(host)
    assert next(a for a in found["addresses"] if a["interface"] == "Vlan10")["vlan_id"] == global_vlan["id"]


async def test_find_interface_addresses():
    host = await _host("r1")
    await db.replace_host_bindings(
        host,
        [
            _row("Vlan10", "192.0.2.1", "192.0.2.0/24", "BLUE"),
            _row("Vlan11", "192.0.2.129", "192.0.2.128/25"),
            _row("Gi0/1", "2001:db8::1", "2001:db8::/64"),
        ],
        {"BLUE": 1},
    )
    assert [a["interface"] for a in await db.find_interface_addresses("192.0.2.1")] == ["Vlan10"]
    assert await db.find_interface_addresses("192.0.2.1", "") == []
    assert len(await db.find_interface_addresses("192.0.2.1", "BLUE")) == 1
    assert await db.find_interface_addresses("not-an-ip") == []
    assert [a["address"] for a in await db.find_interface_addresses("2001:DB8::0001")] == ["2001:db8::1"]
    inside = await db.find_interface_addresses_in_subnet("192.0.2.0/24")
    assert [a["address"] for a in inside] == ["192.0.2.1", "192.0.2.129"]
    assert [a["address"] for a in await db.find_interface_addresses_in_subnet("192.0.2.5/24", "BLUE")] == ["192.0.2.1"]
    assert len(await db.find_interface_addresses_in_subnet("192.0.2.0/24", limit=1)) == 1
    assert [a["address"] for a in await db.find_interface_addresses_in_subnet("2001:db8::/32")] == ["2001:db8::1"]
    assert await db.find_interface_addresses_in_subnet("bogus") == []


# ── VLANs ────────────────────────────────────────────────────────────────────


async def test_vlan_round_trip_uniqueness_and_site_cascade():
    site_a = await db.create_geo_site(name="Site A")
    site_b = await db.create_geo_site(name="Site B")
    made = await db.create_vlan(vid=10, name="users", site_id=site_a["id"], description="floor 1")
    assert made == {
        "id": made["id"],
        "vid": 10,
        "name": "users",
        "site_id": site_a["id"],
        "site": {"id": site_a["id"], "name": "Site A"},
        "description": "floor 1",
        "origin": "manual",
        "created_at": made["created_at"],
        "device_count": 0,
        "interface_count": 0,
        "prefix_count": 0,
        "name_mismatch": False,
    }
    with pytest.raises(ValueError, match="already exists"):
        await db.create_vlan(vid=10, site_id=site_a["id"])
    glob = await db.create_vlan(vid=10)
    assert glob["site"] is None and glob["site_id"] is None
    with pytest.raises(ValueError):
        await db.create_vlan(vid=10)
    other = await db.create_vlan(vid=10, site_id=site_b["id"])
    with pytest.raises(ValueError, match="VLAN 10"):
        await db.update_vlan(other["id"], name="", site_id=site_a["id"], description="")
    renamed = await db.update_vlan(made["id"], name="staff", site_id=site_a["id"], description="")
    assert (renamed["name"], renamed["description"]) == ("staff", "")
    assert await db.update_vlan(999999, name="", site_id=None, description="") is None
    assert await db.get_vlan(999999) is None and await db.get_vlan_detail(999999) is None
    await db.create_vlan(vid=5, site_id=site_b["id"])
    listed = await db.list_vlans()
    assert [(v["site"]["name"] if v["site"] else None, v["vid"]) for v in listed] == [
        (None, 10),
        ("Site A", 10),
        ("Site B", 5),
        ("Site B", 10),
    ]
    assert [v["vid"] for v in await db.list_vlans(site_id=site_b["id"])] == [5, 10]
    assert [v["id"] for v in await db.list_vlans(no_site=True)] == [glob["id"]]
    assert len(await db.list_vlans(vid=10)) == 3
    await db.delete_geo_site(site_b["id"])
    assert [v["vid"] for v in await db.list_vlans()] == [10, 10]
    assert await db.delete_vlan(glob["id"]) is True and await db.delete_vlan(glob["id"]) is False


async def test_vlan_resolution_counts_and_mismatch():
    site = await db.create_geo_site(name="Site A")
    h_site = await _host("sw-site", "192.0.2.21")
    h_none = await _host("sw-none", "192.0.2.22")
    await db.set_host_device_fields(h_site, {"site_id": site["id"]})
    for host, name in ((h_site, "users"), (h_none, "USERS ")):
        await db.upsert_vlan_definition(host_id=host, vlan_id=10, name=name, state="active")
    glob = await db.create_vlan(vid=10, name="users")
    # Without a site record both devices resolve to the global one.
    assert (await db.get_vlan(glob["id"]))["device_count"] == 2
    site_vlan = await db.create_vlan(vid=10, name="staff", site_id=site["id"])
    await _port(h_site, 1, "Gi1/0/1", access=10)
    await _port(h_site, 2, "Te1/1/1", trunk="1-4094")
    await _port(h_site, 3, "Gi1/0/2", access=10, trunk="10,20")
    await _port(h_site, 4, "Gi1/0/3", access=20)
    await _port(h_none, 1, "Gi0/1", trunk="20,30")
    await _port(h_none, 2, "Gi0/2", access=10)
    await db.replace_host_bindings(
        h_site,
        [
            _row("Vlan10", "192.0.2.1", "192.0.2.0/24", svi=10),
            _row("Vlan10", "192.0.2.3", "192.0.2.0/24", role="virtual", svi=10),
            _row("Vlan20", "198.51.100.1", "198.51.100.0/24", svi=20),
        ],
        {},
    )
    on_site = await db.get_vlan(site_vlan["id"])
    assert (on_site["device_count"], on_site["interface_count"], on_site["prefix_count"]) == (1, 3, 1)
    assert on_site["name_mismatch"] is True
    globally = await db.get_vlan(glob["id"])
    assert (globally["device_count"], globally["interface_count"], globally["prefix_count"]) == (1, 1, 0)
    # "USERS " is the record's name ignoring case and spaces.
    assert globally["name_mismatch"] is False

    detail = await db.get_vlan_detail(site_vlan["id"])
    assert detail["devices"] == [
        {"host_id": h_site, "hostname": "sw-site", "name": "users", "state": "active", "name_matches": False}
    ]
    assert [(p["interface"], p["mode"]) for p in detail["interfaces"]] == [
        ("Gi1/0/1", "access"),
        ("Gi1/0/2", "access"),
        ("Gi1/0/2", "trunk"),
        ("Te1/1/1", "trunk"),
    ]
    assert detail["truncated"] is False
    assert detail["prefixes"] == [
        {
            "network": "192.0.2.0/24",
            "vrf_name": "",
            "host_id": h_site,
            "hostname": "sw-site",
            "interface": "Vlan10",
            "address": "192.0.2.1",
        }
    ]
    assert len((await db.get_vlan_detail(site_vlan["id"], limit=2))["interfaces"]) == 2
    # A device without a name for the VLAN never mismatches.
    await db.upsert_vlan_definition(host_id=h_site, vlan_id=10, name="", state="active")
    assert (await db.get_vlan(site_vlan["id"]))["name_mismatch"] is False


async def test_list_vlan_ports_access_then_trunk():
    h1 = await _host("sw1", "192.0.2.31")
    h2 = await _host("sw2", "192.0.2.32")
    await _port(h1, 1, "Te1/1/1", trunk="1-100")
    await _port(h1, 2, "Gi1/0/1", access=50)
    await _port(h2, 1, "Gi0/1", access=50, trunk="ALL")
    await _port(h2, 2, "Gi0/2", trunk="NONE")
    ports = await db.list_vlan_ports(50)
    assert [(p["host_id"], p["interface"], p["mode"]) for p in ports] == [
        (h1, "Gi1/0/1", "access"),
        (h2, "Gi0/1", "access"),
        (h1, "Te1/1/1", "trunk"),
        (h2, "Gi0/1", "trunk"),
    ]
    assert ports[0]["hostname"] == "sw1"
    assert [p["interface"] for p in await db.list_vlan_ports(50, [h2])] == ["Gi0/1", "Gi0/1"]
    assert await db.list_vlan_ports(50, []) == []


async def test_ensure_vlans_for_host_creates_missing_only():
    site = await db.create_geo_site(name="Site A")
    on_site = await _host("sw1", "192.0.2.41")
    no_site = await _host("sw2", "192.0.2.42")
    await db.set_host_device_fields(on_site, {"site_id": site["id"]})
    await db.create_vlan(vid=30, name="kept")
    for vid, name in ((10, " users "), (20, "voice"), (30, "printers"), (4095, "bad")):
        await db.upsert_vlan_definition(host_id=on_site, vlan_id=vid, name=name, state="active")
    await db.upsert_vlan_definition(host_id=no_site, vlan_id=10, name="clients", state="active")
    assert await db.ensure_vlans_for_host(on_site) == 2
    assert await db.ensure_vlans_for_host(on_site) == 0
    made = {(v["site_id"], v["vid"]): v for v in await db.list_vlans()}
    assert made[(site["id"], 10)]["name"] == "users" and made[(site["id"], 10)]["origin"] == "discovered"
    # VLAN 30 resolves to the global record already: no site record is made.
    assert (site["id"], 30) not in made and made[(None, 30)]["name"] == "kept"
    assert await db.ensure_vlans_for_host(no_site) == 1
    assert await db.ensure_vlans_for_host(999999) == 0
    made = {(v["site_id"], v["vid"]): v["name"] for v in await db.list_vlans()}
    assert made[(None, 10)] == "clients" and made[(site["id"], 10)] == "users"


# ── Hooks in the writers ─────────────────────────────────────────────────────


async def test_writers_create_vrf_records():
    host = await _host("r1", "192.0.2.51")
    assert await db.list_vrfs() == []
    await db.update_host(host, "r1", "192.0.2.51", "cisco_ios", vrf_name="MGMT", vlan_id="")
    source = await db.get_or_create_builtin_ipam_source()
    await db.create_ipam_prefix(source["id"], "198.51.100.0/24", vrf="LAB")
    other = await db.create_ipam_source(
        provider="netbox",
        name="Example NetBox",
        base_url="https://ipam.example.com",
        auth_type="none",
        auth_config={},
        created_by="test",
    )
    await db.replace_ipam_source_snapshot(
        other["id"],
        prefixes=[{"subnet": "203.0.113.0/24", "vrf": "EXT"}],
        allocations=[{"address": "203.0.113.5", "vrf_name": "EXT2"}],
    )
    origins = {v["name"]: v["origin"] for v in await db.list_vrfs()}
    assert origins == {"MGMT": "manual", "LAB": "manual", "EXT": "discovered", "EXT2": "discovered"}


async def test_update_host_sets_vrf_and_vlan_independently():
    host = await _host("r1", "192.0.2.71", vrf_name="BLUE", vlan_id="10")
    await db.update_host(host, "r1", "192.0.2.71", "cisco_ios", vrf_name="RED")
    row = await db.get_host(host)
    assert (row["vrf_name"], row["vlan_id"]) == ("RED", "10")
    await db.update_host(host, "r1", "192.0.2.71", "cisco_ios", vlan_id="20")
    row = await db.get_host(host)
    assert (row["vrf_name"], row["vlan_id"]) == ("RED", "20")
    await db.update_host(host, "r1", "192.0.2.71", "cisco_ios")
    row = await db.get_host(host)
    assert (row["vrf_name"], row["vlan_id"]) == ("RED", "20")
    await db.update_host(host, "r1", "192.0.2.71", "cisco_ios", vrf_name="", vlan_id="")
    row = await db.get_host(host)
    assert (row["vrf_name"], row["vlan_id"]) == ("", "")
    # The address history follows the VRF the host is now in.
    for vrf in ("BLUE", "RED", ""):
        assert await db.get_ip_history("192.0.2.71", vrf), vrf


# ── Migration backfill ───────────────────────────────────────────────────────


async def test_backfill_creates_records_and_is_idempotent():
    site = await db.create_geo_site(name="Site A")
    h1 = await _host("sw1", "192.0.2.61", vrf_name=" BLUE ")
    h2 = await _host("sw2", "192.0.2.62")
    h3 = await _host("sw3", "192.0.2.63")
    await db.set_host_device_fields(h2, {"site_id": site["id"]})
    source = await db.get_or_create_builtin_ipam_source()
    await db.create_ipam_prefix(source["id"], "198.51.100.0/24", vrf="LAB")
    for host, vid, name in ((h1, 10, "users-a"), (h3, 10, "users-c"), (h2, 10, "site-users"), (h1, 4095, "x")):
        await db.upsert_vlan_definition(host_id=host, vlan_id=vid, name=name, state="active")
    # Start from a database as it was before 0086: no records.
    await _exec("DELETE FROM vrfs")
    await _exec("DELETE FROM vlans")
    await _exec("UPDATE hosts SET vrf_name = ? WHERE id = ?", ("x" * 65, h3))

    for _ in range(2):
        conn = await db.get_db()
        try:
            await _migration.backfill(conn)
            await conn.commit()
        finally:
            await conn.close()

    vrfs = {v["name"]: v["origin"] for v in await db.list_vrfs()}
    assert vrfs == {"BLUE": "discovered", "LAB": "discovered"}
    vlans = {(v["site_id"], v["vid"]): v for v in await db.list_vlans()}
    assert set(vlans) == {(None, 10), (site["id"], 10)}
    assert vlans[(None, 10)]["name"] == "users-a" and vlans[(None, 10)]["origin"] == "discovered"
    assert vlans[(site["id"], 10)]["name"] == "site-users"


async def test_migration_up_runs_twice():
    await db.create_vrf(name="BLUE")
    conn = await db.get_db()
    try:
        await _migration.up(conn)
    finally:
        await conn.close()
    assert [v["name"] for v in await db.list_vrfs()] == ["BLUE"]
