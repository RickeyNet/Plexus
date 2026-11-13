"""Custom fields and tags storage (``routes.db.custom_fields``)."""

from __future__ import annotations

import pytest
import routes.database as db


async def _owner_field(**kw) -> dict:
    args = {
        "key": "owner",
        "label": "Owner",
        "field_type": "select",
        "choices": ["net", "sec"],
        "object_types": ["host", "prefix"],
        "required": True,
        "default_value": "net",
        "description": "",
        "sort_order": 5,
        "created_by": "admin",
    }
    args.update(kw)
    return await db.create_custom_field(**args)


# ── Task 2: definitions ──────────────────────────────────────────────────────


async def test_tag_names_are_unique_ignoring_case():
    await db.create_tag(name="PCI-Scope")
    with pytest.raises(ValueError):
        await db.create_tag(name="pci-scope")


async def test_tag_round_trip_and_usage():
    tag = await db.create_tag(name="core", color="blue", description="core sites")
    assert tag == {"id": tag["id"], "name": "core", "color": "blue", "description": "core sites"}
    (listed,) = await db.list_tags(with_usage=True)
    assert listed["usage"] == {"host": 0, "group": 0, "prefix": 0}
    assert await db.get_tag(tag["id"]) == tag
    assert await db.get_tag(tag["id"] + 100) is None
    assert await db.list_tags() == [tag]


async def test_tag_update_and_delete():
    tag = await db.create_tag(name="edge")
    other = await db.create_tag(name="core")
    updated = await db.update_tag(tag["id"], name="Edge", color="red", description="edge sites")
    assert updated == {"id": tag["id"], "name": "Edge", "color": "red", "description": "edge sites"}
    with pytest.raises(ValueError):
        await db.update_tag(tag["id"], name="CORE", color="red", description="")
    assert await db.update_tag(tag["id"] + 100, name="x", color="gray", description="") is None
    assert await db.delete_tag(other["id"]) == 0
    assert await db.get_tag(other["id"]) is None


async def test_field_round_trip_and_object_type_filter():
    f = await _owner_field()
    assert f["choices"] == ["net", "sec"] and f["required"] is True
    assert f["object_types"] == ["host", "prefix"] and f["sort_order"] == 5
    assert set(f) == {
        "id",
        "key",
        "label",
        "field_type",
        "choices",
        "object_types",
        "required",
        "default_value",
        "description",
        "sort_order",
    }
    assert [x["key"] for x in await db.list_custom_fields("host")] == ["owner"]
    assert await db.list_custom_fields("group") == []
    assert await db.get_custom_field(f["id"]) == f
    assert await db.get_custom_field(f["id"] + 100) is None


async def test_fields_are_listed_in_sort_order():
    await _owner_field(key="b_second", sort_order=2)
    await _owner_field(key="a_third", sort_order=3)
    await _owner_field(key="c_first", sort_order=1)
    assert [x["key"] for x in await db.list_custom_fields()] == ["c_first", "b_second", "a_third"]


async def test_duplicate_field_key_raises():
    await _owner_field()
    with pytest.raises(ValueError):
        await _owner_field(label="Other owner")


async def test_update_field_keeps_key_and_type():
    f = await _owner_field()
    updated = await db.update_custom_field(
        f["id"],
        label="Team",
        choices=["net"],
        object_types=["host"],
        required=False,
        default_value="",
        description="who runs it",
        sort_order=1,
    )
    assert updated["key"] == "owner" and updated["field_type"] == "select"
    assert updated["label"] == "Team" and updated["choices"] == ["net"] and updated["required"] is False
    assert (
        await db.update_custom_field(
            f["id"] + 100,
            label="x",
            choices=[],
            object_types=[],
            required=False,
            default_value="",
            description="",
            sort_order=0,
        )
        is None
    )


def test_prefix_key_is_canonical():
    assert db.prefix_key("192.0.2.5/24", " blue ") == "192.0.2.0/24|blue"
    assert db.prefix_key("2001:DB8::/32") == "2001:db8::/32|"
    assert db.prefix_key("198.51.100.0/24", None) == "198.51.100.0/24|"
    with pytest.raises(ValueError):
        db.prefix_key("not-a-subnet")


# ── Task 3: object data ──────────────────────────────────────────────────────


async def _host(name: str = "edge-sw1", ip: str = "192.0.2.10", group: int | None = None) -> int:
    gid = group if group is not None else await db.create_group(f"grp-{name}")
    return await db.add_host(gid, name, ip, "cisco_ios")


async def test_set_get_replace():
    h = str(await _host())
    a = await db.create_tag(name="alpha")
    b = await db.create_tag(name="bravo")
    owner = await _owner_field()
    await db.set_object_data("host", h, [b["id"], a["id"]], {owner["id"]: "net"})
    data = await db.get_object_data("host", h)
    assert data == {
        "tags": [{"id": a["id"], "name": "alpha", "color": "gray"}, {"id": b["id"], "name": "bravo", "color": "gray"}],
        "fields": {"owner": "net"},
    }
    await db.set_object_data("host", h, [b["id"]], {owner["id"]: ""})
    data = await db.get_object_data("host", h)
    assert data == {"tags": [{"id": b["id"], "name": "bravo", "color": "gray"}], "fields": {}}


async def test_set_rejects_unknown_ids_and_writes_nothing():
    h = str(await _host())
    a = await db.create_tag(name="alpha")
    owner = await _owner_field()
    await db.set_object_data("host", h, [a["id"]], {owner["id"]: "net"})
    before = await db.get_object_data("host", h)
    with pytest.raises(ValueError, match="999999"):
        await db.set_object_data("host", h, [999999], {})
    with pytest.raises(ValueError, match="888888"):
        await db.set_object_data("host", h, [], {888888: "x"})
    assert await db.get_object_data("host", h) == before


async def test_bulk_matches_single_and_handles_2000_keys():
    h = str(await _host())
    a = await db.create_tag(name="alpha")
    owner = await _owner_field()
    await db.set_object_data("host", h, [a["id"]], {owner["id"]: "sec"})
    keys = [str(i) for i in range(1, 2001)] + [h]
    single = await db.get_object_data("host", h)
    assert await db.get_object_data_bulk("host", keys) == {h: single}
    assert await db.get_object_data_bulk("host", [h]) == {h: single}
    assert await db.get_object_data_bulk("host") == {h: single}
    assert await db.get_object_data_bulk("host", []) == {}
    assert await db.get_object_data_bulk("group", keys) == {}


async def test_bulk_update_tags_adds_and_removes():
    h1 = str(await _host("a1", "192.0.2.11"))
    h2 = str(await _host("a2", "192.0.2.12"))
    a = await db.create_tag(name="alpha")
    b = await db.create_tag(name="bravo")
    await db.set_object_data("host", h1, [b["id"]], {})
    touched = await db.bulk_update_tags("host", [h1, h2], [a["id"]], [b["id"]])
    assert touched == 2
    for key in (h1, h2):
        assert [t["name"] for t in (await db.get_object_data("host", key))["tags"]] == ["alpha"]
    # Adding a tag twice is harmless.
    assert await db.bulk_update_tags("host", [h1], [a["id"]], []) == 1
    assert await db.bulk_update_tags("host", [], [a["id"]], []) == 0
    with pytest.raises(ValueError, match="777777"):
        await db.bulk_update_tags("host", [h1], [777777], [])


async def test_find_object_keys_requires_every_tag_and_value():
    h1 = str(await _host("f1", "192.0.2.21"))
    h2 = str(await _host("f2", "192.0.2.22"))
    a = await db.create_tag(name="a")
    b = await db.create_tag(name="b")
    owner = await _owner_field()
    await db.set_object_data("host", h1, [a["id"], b["id"]], {owner["id"]: "net"})
    await db.set_object_data("host", h2, [a["id"]], {owner["id"]: "sec"})
    assert await db.find_object_keys("host", ["A", "b"], {}) == {h1}
    assert await db.find_object_keys("host", ["a"], {owner["id"]: "sec"}) == {h2}
    assert await db.find_object_keys("host", ["a"], {}) == {h1, h2}
    assert await db.find_object_keys("host", ["nope"], {}) == set()
    assert await db.find_object_keys("host", [], {}) == set()


async def test_tag_usage_counts():
    h = str(await _host())
    a = await db.create_tag(name="alpha")
    await db.set_object_data("host", h, [a["id"]], {})
    await db.set_object_data("prefix", db.prefix_key("192.0.2.0/24"), [a["id"]], {})
    (listed,) = await db.list_tags(with_usage=True)
    assert listed["usage"] == {"host": 1, "group": 0, "prefix": 1}
    assert await db.delete_tag(a["id"]) == 2
    assert await db.get_object_data("host", h) == {"tags": [], "fields": {}}


async def test_removing_object_type_from_field_deletes_those_values():
    h = str(await _host())
    owner = await _owner_field()
    key = db.prefix_key("198.51.100.0/24")
    await db.set_object_data("host", h, [], {owner["id"]: "net"})
    await db.set_object_data("prefix", key, [], {owner["id"]: "sec"})
    assert await db.count_custom_field_values(owner["id"]) == 2
    assert await db.count_custom_field_values(owner["id"], ["prefix"]) == 1
    assert await db.count_custom_field_values(owner["id"], []) == 0
    await db.update_custom_field(
        owner["id"],
        label="Owner",
        choices=["net", "sec"],
        object_types=["host"],
        required=True,
        default_value="net",
        description="",
        sort_order=5,
    )
    assert (await db.get_object_data("prefix", key))["fields"] == {}
    assert (await db.get_object_data("host", h))["fields"] == {"owner": "net"}
    assert await db.delete_custom_field(owner["id"]) == 1
    assert (await db.get_object_data("host", h))["fields"] == {}


async def _tag_host(host_id: int) -> None:
    tag = (await db.list_tags())[0] if await db.list_tags() else await db.create_tag(name="alpha")
    await db.set_object_data("host", str(host_id), [tag["id"]], {})


async def test_host_delete_purges():
    h = await _host()
    await _tag_host(h)
    await db.remove_host(h)
    assert await db.get_object_data_bulk("host", [str(h)]) == {}


async def test_bulk_host_delete_purges():
    gid = await db.create_group("bulk")
    h1 = await _host("b1", "192.0.2.31", gid)
    h2 = await _host("b2", "192.0.2.32", gid)
    keep = await _host("b3", "192.0.2.33", gid)
    for h in (h1, h2, keep):
        await _tag_host(h)
    assert await db.bulk_delete_hosts([h1, h2]) == 2
    assert set(await db.get_object_data_bulk("host")) == {str(keep)}


async def test_group_delete_purges_group_and_its_hosts():
    gid = await db.create_group("doomed")
    other = await db.create_group("kept")
    h = await _host("g1", "192.0.2.41", gid)
    survivor = await _host("g2", "192.0.2.42", other)
    tag = await db.create_tag(name="alpha")
    await db.set_object_data("group", str(gid), [tag["id"]], {})
    await db.set_object_data("group", str(other), [tag["id"]], {})
    await db.set_object_data("host", str(h), [tag["id"]], {})
    await db.set_object_data("host", str(survivor), [tag["id"]], {})
    await db.delete_group(gid)
    assert set(await db.get_object_data_bulk("group")) == {str(other)}
    assert set(await db.get_object_data_bulk("host")) == {str(survivor)}


async def test_moving_a_host_keeps_its_data():
    src = await db.create_group("src")
    dst = await db.create_group("dst")
    h = await _host("m1", "192.0.2.51", src)
    await _tag_host(h)
    before = await db.get_object_data("host", str(h))
    assert await db.move_hosts([h], dst) == 1
    assert await db.get_object_data("host", str(h)) == before


async def test_prefix_data_survives_a_source_resync():
    source = await db.create_ipam_source("netbox", "lab-ipam", base_url="https://ipam.example.com")
    prefixes = [{"subnet": "192.0.2.0/24", "external_id": "p1"}]
    await db.replace_ipam_source_snapshot(source["id"], prefixes, [])
    tag = await db.create_tag(name="lab")
    key = db.prefix_key("192.0.2.0/24")
    await db.set_object_data("prefix", key, [tag["id"]], {})
    await db.replace_ipam_source_snapshot(source["id"], prefixes, [])
    assert [t["name"] for t in (await db.get_object_data("prefix", key))["tags"]] == ["lab"]
