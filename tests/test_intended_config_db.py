"""Intended configuration storage (``routes.db.intended_config``): templates
and contexts round trip, names unique ignoring case, the bulk readers the
template variables use, and the intended configuration rows."""

from __future__ import annotations

import importlib

import pytest
import routes.database as db

_migration = importlib.import_module("routes.migrations.0087_add_intended_configs")


async def _host(name: str = "edge-r1", ip: str = "192.0.2.10", group: str = "core") -> int:
    groups = {g["name"]: g["id"] for g in await db.get_all_groups()}
    gid = groups.get(group) or await db.create_group(group)
    return await db.add_host(gid, name, ip, "cisco_ios")


async def _exec(sql: str, params: tuple = ()) -> None:
    conn = await db.get_db()
    try:
        await conn.execute(sql, params)
        await conn.commit()
    finally:
        await conn.close()


def _template_values(name: str = "base", **extra) -> dict:
    return {
        "name": name,
        "kind": "device",
        "device_type": "",
        "role_id": None,
        "site_id": None,
        "group_id": None,
        "template_text": "hostname {{ host.name }}\n",
        "description": "",
        "enabled": True,
        **extra,
    }


def _row(**extra) -> dict:
    return {
        "template_id": 1,
        "template_name": "base",
        "status": "ok",
        "error": "",
        "config_text": "hostname edge-r1\n",
        "compliance": "unknown",
        "backup_id": None,
        "missing_count": 0,
        "extra_count": 0,
        **extra,
    }


async def test_migration_is_idempotent():
    conn = await db.get_db()
    try:
        await _migration.up(conn)
    finally:
        await conn.close()
    assert await db.list_config_templates() == []


async def test_template_round_trip_and_unique_name():
    made = await db.create_config_template(_template_values(group_id=4, enabled=False), "admin")
    assert made == {
        "id": made["id"],
        "name": "base",
        "kind": "device",
        "device_type": "",
        "role_id": None,
        "site_id": None,
        "group_id": 4,
        "template_text": "hostname {{ host.name }}\n",
        "description": "",
        "enabled": False,
        "created_at": made["created_at"],
        "updated_at": made["updated_at"],
        "updated_by": "admin",
        "host_count": 0,
    }
    assert made["created_at"] and made["updated_at"]
    with pytest.raises(ValueError, match="already exists"):
        await db.create_config_template(_template_values("BASE"))
    other = await db.create_config_template(_template_values("snippet", kind="snippet"))
    with pytest.raises(ValueError):
        await db.update_config_template(other["id"], _template_values("Base"))
    renamed = await db.update_config_template(made["id"], _template_values("Base", description="d"), "ops")
    assert (renamed["name"], renamed["description"], renamed["updated_by"], renamed["enabled"]) == (
        "Base",
        "d",
        "ops",
        True,
    )
    assert await db.update_config_template(999, _template_values("x")) is None
    assert [t["name"] for t in await db.list_config_templates()] == ["Base", "snippet"]
    assert await db.delete_config_template(made["id"]) is True
    assert await db.delete_config_template(made["id"]) is False
    assert await db.get_config_template(made["id"]) is None


async def test_context_round_trip_order_and_bad_stored_data():
    values = {
        "name": "ntp",
        "weight": 10,
        "data": '{"ntp":["192.0.2.1"]}',
        "description": "",
        "enabled": True,
        "device_type": "",
        "role_id": None,
        "site_id": 2,
        "group_id": None,
        "host_id": 5,
    }
    made = await db.create_config_context(values, "admin")
    assert made["data"] == {"ntp": ["192.0.2.1"]} and (made["site_id"], made["host_id"]) == (2, 5)
    await db.create_config_context({**values, "name": "a-low", "weight": 1})
    await db.create_config_context({**values, "name": "B", "weight": 10})
    assert [c["name"] for c in await db.list_config_contexts()] == ["a-low", "B", "ntp"]
    with pytest.raises(ValueError):
        await db.create_config_context({**values, "name": "NTP"})
    updated = await db.update_config_context(made["id"], {**values, "data": "{}", "enabled": False})
    assert updated["data"] == {} and updated["enabled"] is False
    assert await db.update_config_context(999, {**values, "name": "zz"}) is None
    await _exec("UPDATE config_contexts SET data = ? WHERE id = ?", ("not json", made["id"]))
    assert (await db.get_config_context(made["id"]))["data"] == {}
    await _exec("UPDATE config_contexts SET data = ? WHERE id = ?", ("[1]", made["id"]))
    assert (await db.get_config_context(made["id"]))["data"] == {}
    assert await db.delete_config_context(made["id"]) is True


async def test_bulk_readers():
    h1 = await _host()
    h2 = await _host("edge-r2", "192.0.2.11")
    site_id = int((await db.create_geo_site(name="Site A"))["id"])
    await db.create_vlan(vid=20, name="users", site_id=site_id)
    await db.create_vlan(vid=10, name="mgmt")
    assert [(v["vid"], v["site_id"]) for v in await db.list_vlan_records()] == [(10, None), (20, site_id)]
    await db.create_vrf(name="BLUE", rd="65000:1", description="tenant")
    await db.replace_host_bindings(
        h1,
        [
            {
                "interface": "GigabitEthernet0/1",
                "interface_key": "gigabitethernet0/1",
                "address": "192.0.2.1",
                "prefix_length": 24,
                "network": "192.0.2.0/24",
                "vrf_name": "BLUE",
                "role": "primary",
                "protocol": "",
                "svi_vid": 0,
            }
        ],
        {"BLUE": 1, "RED": 0},
    )
    await _exec(
        "INSERT INTO interface_inventory (host_id, if_index, name, admin_state) VALUES (?, ?, ?, ?)",
        (h1, 1, "GigabitEthernet0/1", "up"),
    )
    vrfs = await db.get_vrfs_for_hosts([h1, h2])
    assert vrfs == {
        h1: [
            {"name": "BLUE", "rd": "65000:1", "description": "tenant"},
            {"name": "RED", "rd": "", "description": ""},
        ]
    }
    interfaces, addresses = await db.get_interfaces_for_hosts([h1, h2])
    assert [i["name"] for i in interfaces[h1]] == ["GigabitEthernet0/1"] and h2 not in interfaces
    assert addresses[h1][0]["address"] == "192.0.2.1"
    assert await db.count_hosts() == 2


async def test_intended_rows_save_compare_summary_and_delete():
    h1 = await _host()
    h2 = await _host("edge-r2", "192.0.2.11", group="edge")
    assert await db.save_intended_config(999999, _row()) is None
    assert await db.save_intended_config(h1, _row()) is True
    first = await db.get_intended_config(h1)
    assert first["config_text"] == "hostname edge-r1\n" and first["error"] is None
    assert first["changed_at"] == first["generated_at"]
    await _exec("UPDATE intended_configs SET changed_at = ? WHERE host_id = ?", ("2000-01-01 00:00:00", h1))
    assert await db.save_intended_config(h1, _row()) is False
    assert (await db.get_intended_config(h1))["changed_at"] == "2000-01-01 00:00:00"
    assert await db.save_intended_config(h1, _row(config_text="hostname other\n")) is True
    assert (await db.get_intended_config(h1))["changed_at"] != "2000-01-01 00:00:00"
    await db.save_intended_config(h2, _row(status="error", error="boom", config_text=""))

    assert await db.set_intended_comparison(
        h1, compliance="non_compliant", backup_id=None, missing_count=2, extra_count=1
    )
    assert not await db.set_intended_comparison(
        999999, compliance="compliant", backup_id=None, missing_count=0, extra_count=0
    )
    rows = await db.list_intended_configs()
    assert [r["hostname"] for r in rows] == ["edge-r1", "edge-r2"]
    assert rows[0]["group_name"] == "core" and rows[0]["missing_count"] == 2 and rows[1]["error"] == "boom"
    assert [r["host_id"] for r in await db.list_intended_configs(compliance="non_compliant")] == [h1]
    assert [r["host_id"] for r in await db.list_intended_configs(status="error")] == [h2]
    assert [r["host_id"] for r in await db.list_intended_configs(group_id=rows[1]["group_id"])] == [h2]
    await _host("edge-r3", "192.0.2.12")
    assert await db.summarize_intended_configs() == {
        "hosts": 3,
        "generated": 2,
        "errors": 1,
        "compliant": 0,
        "non_compliant": 1,
        "unknown": 1,
        "no_template": 1,
    }
    assert (await db.list_config_templates()) == []
    assert await db.delete_intended_configs([h1, h2, 999999]) == 2
    assert await db.get_intended_config(h1) is None


async def test_template_host_count_and_host_delete_cascades():
    template = await db.create_config_template(_template_values())
    host = await _host()
    await db.save_intended_config(host, _row(template_id=template["id"]))
    assert (await db.get_config_template(template["id"]))["host_count"] == 1
    await db.remove_host(host)
    assert await db.get_intended_config(host) is None
    assert (await db.get_config_template(template["id"]))["host_count"] == 0
