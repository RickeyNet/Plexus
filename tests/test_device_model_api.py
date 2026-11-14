"""Device model API (``netcontrol.routes.device_model``) and what it adds to
the inventory endpoints: host device values, inline display objects,
filters, bulk edit and CSV columns."""

from __future__ import annotations

import asyncio
import csv
import io

import netcontrol.app as app_module
import pytest
import routes.database as db
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

DCIM = "/api/dcim"
BULK = "/api/hosts/bulk-edit"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict | list:
    assert resp.status_code == status, resp.text
    return resp.json()


def _group(admin: CsrfClient, name: str = "core") -> int:
    return int(_ok(admin.post("/api/inventory", json={"name": name}), 201)["id"])


def _host(admin: CsrfClient, group_id: int, name: str = "edge-sw1", ip: str = "192.0.2.10", **extra) -> int:
    body = {"hostname": name, "ip_address": ip, **extra}
    return int(_ok(admin.post(f"/api/inventory/{group_id}/hosts", json=body), 201)["id"])


def _maker(admin: CsrfClient, name: str = "Example Networks") -> dict:
    return _ok(admin.post(f"{DCIM}/manufacturers", json={"name": name}), 201)


def _type(admin: CsrfClient, manufacturer_id: int, model: str = "EX-1000", **extra) -> dict:
    body = {"manufacturer_id": manufacturer_id, "model": model, **extra}
    return _ok(admin.post(f"{DCIM}/device-types", json=body), 201)


def _named(admin: CsrfClient, kind: str, name: str) -> dict:
    return next(r for r in _ok(admin.get(f"{DCIM}/{kind}")) if r["name"] == name)


def _site(name: str = "Site A") -> dict:
    return asyncio.run(db.create_geo_site(name=name))


def _host_row(admin: CsrfClient, group_id: int, host_id: int) -> dict:
    return next(h for h in _ok(admin.get(f"/api/inventory/{group_id}/hosts")) if h["id"] == host_id)


def _ids(rows: list[dict]) -> list[int]:
    return [r["id"] for r in rows]


# ── Access ───────────────────────────────────────────────────────────────────


def test_anonymous_is_rejected(admin):
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    for kind in ("manufacturers", "device-types", "roles", "statuses"):
        assert anon.get(f"{DCIM}/{kind}").status_code == 401
    assert anon.post(BULK, json={"host_ids": [1], "set": {"role_id": None}}).status_code in (401, 403)


def test_any_user_reads_only_admin_writes(admin):
    maker = _maker(admin)
    dtype = _type(admin, maker["id"])
    role = _named(admin, "roles", "Switch")
    status = _named(admin, "statuses", "Planned")
    user = user_client(admin)
    for kind in ("manufacturers", "device-types", "roles", "statuses"):
        assert user.get(f"{DCIM}/{kind}").status_code == 200
    assert user.post(f"{DCIM}/manufacturers", json={"name": "Other"}).status_code == 403
    assert user.put(f"{DCIM}/manufacturers/{maker['id']}", json={"name": "x"}).status_code == 403
    assert user.delete(f"{DCIM}/manufacturers/{maker['id']}").status_code == 403
    assert user.post(f"{DCIM}/device-types", json={"manufacturer_id": maker["id"], "model": "x"}).status_code == 403
    assert user.put(f"{DCIM}/device-types/{dtype['id']}", json={"model": "x"}).status_code == 403
    assert user.delete(f"{DCIM}/device-types/{dtype['id']}").status_code == 403
    assert user.post(f"{DCIM}/roles", json={"name": "Core"}).status_code == 403
    assert user.put(f"{DCIM}/roles/{role['id']}", json={"name": "x"}).status_code == 403
    assert user.delete(f"{DCIM}/roles/{role['id']}").status_code == 403
    assert user.post(f"{DCIM}/statuses", json={"name": "Spare"}).status_code == 403
    assert user.put(f"{DCIM}/statuses/{status['id']}", json={"name": "x"}).status_code == 403
    assert user.delete(f"{DCIM}/statuses/{status['id']}").status_code == 403


def test_bulk_edit_needs_inventory(admin):
    host = _host(admin, _group(admin))
    body = {"host_ids": [host], "set": {"location_detail": "Rack 1"}}
    assert user_client(admin, "no-inventory").post(BULK, json=body).status_code == 403
    operator = user_client(admin, "operator", features=["inventory"])
    assert _ok(operator.post(BULK, json=body)) == {"ok": True, "updated": 1}
    # The catalogues stay admin-only for an inventory user.
    assert operator.post(f"{DCIM}/roles", json={"name": "Core"}).status_code == 403


# ── Catalogues ───────────────────────────────────────────────────────────────


def test_manufacturer_crud(admin):
    maker = _maker(admin, "  Example Networks ")
    assert maker == {
        "id": maker["id"],
        "name": "Example Networks",
        "description": "",
        "device_type_count": 0,
        "host_count": 0,
    }
    resp = admin.post(f"{DCIM}/manufacturers", json={"name": "EXAMPLE networks"})
    assert resp.status_code == 409 and "already exists" in resp.json()["error"]["message"]
    for bad in ({"name": "  "}, {"name": "x" * 101}, {"name": "x" * 201}, {}):
        assert admin.post(f"{DCIM}/manufacturers", json=bad).status_code == 422, bad
    updated = _ok(admin.put(f"{DCIM}/manufacturers/{maker['id']}", json={"description": " lab "}))
    assert updated["name"] == "Example Networks" and updated["description"] == "lab"
    renamed = _ok(admin.put(f"{DCIM}/manufacturers/{maker['id']}", json={"name": "Example Co"}))
    assert renamed["name"] == "Example Co"
    other = _maker(admin, "Other")
    assert admin.put(f"{DCIM}/manufacturers/{other['id']}", json={"name": "example co"}).status_code == 409
    assert admin.put(f"{DCIM}/manufacturers/999999", json={"name": "Ghost"}).status_code == 404
    assert admin.delete(f"{DCIM}/manufacturers/999999").status_code == 404
    assert _ok(admin.delete(f"{DCIM}/manufacturers/{other['id']}")) == {"ok": True, "affected": 0}
    assert _ids(_ok(admin.get(f"{DCIM}/manufacturers"))) == [maker["id"]]


def test_device_type_crud(admin):
    maker = _maker(admin)
    other = _maker(admin, "Other")
    dtype = _type(admin, maker["id"], " EX-1000 ", part_number=" EX-1000-AC ", u_height=2, description="d")
    assert dtype == {
        "id": dtype["id"],
        "manufacturer_id": maker["id"],
        "manufacturer": "Example Networks",
        "model": "EX-1000",
        "part_number": "EX-1000-AC",
        "u_height": 2,
        "description": "d",
        "host_count": 0,
    }
    assert (
        admin.post(f"{DCIM}/device-types", json={"manufacturer_id": maker["id"], "model": "ex-1000"}).status_code == 409
    )
    for bad in ({"model": " "}, {"u_height": -1}, {"u_height": 101}, {"model": "m" * 101}):
        body = {"manufacturer_id": maker["id"], "model": "EX-9", **bad}
        assert admin.post(f"{DCIM}/device-types", json=body).status_code == 422, bad
    missing = admin.post(f"{DCIM}/device-types", json={"manufacturer_id": 999999, "model": "EX-9"})
    assert missing.status_code == 400 and "manufacturer_id" in missing.json()["detail"]["fields"]
    second = _type(admin, other["id"], "OT-1")
    assert [d["id"] for d in _ok(admin.get(f"{DCIM}/device-types?manufacturer_id={other['id']}"))] == [second["id"]]
    assert len(_ok(admin.get(f"{DCIM}/device-types"))) == 2
    assert admin.get(f"{DCIM}/device-types?manufacturer_id=abc").status_code == 422
    moved = _ok(admin.put(f"{DCIM}/device-types/{second['id']}", json={"manufacturer_id": maker["id"], "u_height": 1}))
    assert moved["manufacturer"] == "Example Networks" and moved["model"] == "OT-1" and moved["u_height"] == 1
    assert admin.put(f"{DCIM}/device-types/{second['id']}", json={"model": "EX-1000"}).status_code == 409
    assert admin.put(f"{DCIM}/device-types/{second['id']}", json={"manufacturer_id": 999999}).status_code == 400
    kept = _ok(admin.put(f"{DCIM}/device-types/{second['id']}", json={"model": "OT-2", "part_number": "p"}))
    assert kept["model"] == "OT-2" and kept["part_number"] == "p" and kept["description"] == ""
    assert admin.put(f"{DCIM}/device-types/999999", json={"model": "x"}).status_code == 404
    assert admin.delete(f"{DCIM}/device-types/999999").status_code == 404


def test_role_crud(admin):
    role = _ok(admin.post(f"{DCIM}/roles", json={"name": "Core", "color": "blue", "description": "core"}), 201)
    assert role == {"id": role["id"], "name": "Core", "color": "blue", "description": "core", "host_count": 0}
    assert admin.post(f"{DCIM}/roles", json={"name": "router"}).status_code == 409
    assert admin.post(f"{DCIM}/roles", json={"name": "Edge", "color": "pink"}).status_code == 422
    assert admin.post(f"{DCIM}/roles", json={"name": "x" * 51}).status_code == 422
    updated = _ok(admin.put(f"{DCIM}/roles/{role['id']}", json={"color": "red"}))
    assert updated["name"] == "Core" and updated["color"] == "red"
    assert admin.put(f"{DCIM}/roles/{role['id']}", json={"name": "Switch"}).status_code == 409
    assert admin.put(f"{DCIM}/roles/999999", json={"name": "x"}).status_code == 404
    assert admin.delete(f"{DCIM}/roles/999999").status_code == 404
    assert _ok(admin.delete(f"{DCIM}/roles/{role['id']}"))["affected"] == 0


def test_status_default_rules(admin):
    active = _named(admin, "statuses", "Active")
    assert active["is_default"] is True and active["color"] == "green"
    spare = _ok(admin.post(f"{DCIM}/statuses", json={"name": "Spare", "is_default": True}), 201)
    assert spare["is_default"] is True
    assert _named(admin, "statuses", "Active")["is_default"] is False
    # The default cannot be un-set directly or deleted.
    resp = admin.put(f"{DCIM}/statuses/{spare['id']}", json={"is_default": False})
    assert resp.status_code == 409 and "detail" not in resp.json()
    resp = admin.delete(f"{DCIM}/statuses/{spare['id']}?confirm=true")
    assert resp.status_code == 409 and "default" in resp.json()["error"]["message"]
    # Making another the default moves it.
    moved = _ok(admin.put(f"{DCIM}/statuses/{active['id']}", json={"is_default": True, "description": "in use"}))
    assert moved["is_default"] is True and moved["description"] == "in use"
    assert _named(admin, "statuses", "Spare")["is_default"] is False
    same = _ok(admin.put(f"{DCIM}/statuses/{active['id']}", json={"is_default": True, "color": "teal"}))
    assert same["is_default"] is True and same["color"] == "teal"
    assert admin.post(f"{DCIM}/statuses", json={"name": "ACTIVE"}).status_code == 409
    assert admin.put(f"{DCIM}/statuses/{spare['id']}", json={"name": "Retired"}).status_code == 409
    assert admin.put(f"{DCIM}/statuses/999999", json={"name": "x"}).status_code == 404
    assert admin.delete(f"{DCIM}/statuses/999999").status_code == 404
    assert _ok(admin.delete(f"{DCIM}/statuses/{spare['id']}"))["affected"] == 0


def test_delete_in_use_needs_confirm(admin):
    gid = _group(admin)
    maker = _maker(admin)
    dtype = _type(admin, maker["id"])
    role = _ok(admin.post(f"{DCIM}/roles", json={"name": "Core"}), 201)
    status = _ok(admin.post(f"{DCIM}/statuses", json={"name": "Spare"}), 201)
    host = _host(admin, gid, device_type_id=dtype["id"], role_id=role["id"], lifecycle_status_id=status["id"])
    for path in (
        f"manufacturers/{maker['id']}",
        f"device-types/{dtype['id']}",
        f"roles/{role['id']}",
        f"statuses/{status['id']}",
    ):
        resp = admin.delete(f"{DCIM}/{path}")
        assert resp.status_code == 409, path
        assert resp.json()["detail"]["affected"] == 1
        assert "confirm=true" in resp.json()["detail"]["message"]
    assert _named(admin, "manufacturers", "Example Networks")["host_count"] == 1
    assert _ok(admin.delete(f"{DCIM}/roles/{role['id']}?confirm=true")) == {"ok": True, "affected": 1}
    assert _ok(admin.delete(f"{DCIM}/manufacturers/{maker['id']}?confirm=true")) == {"ok": True, "affected": 1}
    assert _ok(admin.get(f"{DCIM}/device-types")) == []
    assert _ok(admin.delete(f"{DCIM}/statuses/{status['id']}?confirm=true"))["affected"] == 1
    row = _host_row(admin, gid, host)
    assert row["device_type_id"] is None and row["role_id"] is None and row["lifecycle_status_id"] is None
    assert row["hardware"] is None and row["role"] is None and row["lifecycle_status"] is None


# ── Host create and update ───────────────────────────────────────────────────


def test_host_create_with_device_values_and_locks(admin):
    gid = _group(admin)
    maker = _maker(admin)
    dtype = _type(admin, maker["id"], "C9300-48P")
    switch = _named(admin, "roles", "Switch")
    planned = _named(admin, "statuses", "Planned")
    site = _site()
    host = _host(
        admin,
        gid,
        device_type_id=dtype["id"],
        role_id=switch["id"],
        lifecycle_status_id=planned["id"],
        site_id=site["id"],
        location_detail=" Row 4, rack 12 ",
    )
    row = _host_row(admin, gid, host)
    assert {k: row[k] for k in ("device_type_id", "role_id", "lifecycle_status_id", "site_id", "location_detail")} == {
        "device_type_id": dtype["id"],
        "role_id": switch["id"],
        "lifecycle_status_id": planned["id"],
        "site_id": site["id"],
        "location_detail": "Row 4, rack 12",
    }
    assert row["hardware"] == {
        "id": dtype["id"],
        "model": "C9300-48P",
        "manufacturer_id": maker["id"],
        "manufacturer": "Example Networks",
    }
    assert row["role"] == {"id": switch["id"], "name": "Switch", "color": "teal"}
    assert row["lifecycle_status"] == {"id": planned["id"], "name": "Planned", "color": "blue"}
    assert row["site"] == {"id": site["id"], "name": "Site A"}
    stored = asyncio.run(db.get_host(host))
    assert stored["hardware_locked"] == 1 and stored["role_locked"] == 1
    # The driver key and reachability are untouched.
    assert row["device_type"] == "cisco_ios" and row["status"] == "unknown"


def test_host_create_without_values_gets_the_default_status(admin):
    gid = _group(admin)
    host = _host(admin, gid)
    row = _host_row(admin, gid, host)
    active = _named(admin, "statuses", "Active")
    assert row["lifecycle_status"] == {"id": active["id"], "name": "Active", "color": "green"}
    assert row["hardware"] is None and row["role"] is None and row["site"] is None
    assert row["location_detail"] == ""
    # An explicit null means no status.
    other = _host(admin, gid, "edge-sw2", "192.0.2.11", lifecycle_status_id=None)
    assert _host_row(admin, gid, other)["lifecycle_status"] is None


def test_host_create_with_unknown_id_is_400_and_writes_nothing(admin):
    gid = _group(admin)
    resp = admin.post(
        f"/api/inventory/{gid}/hosts",
        json={"hostname": "x", "ip_address": "192.0.2.10", "role_id": 999999, "site_id": 0},
    )
    assert resp.status_code == 400
    assert set(resp.json()["detail"]["fields"]) == {"role_id", "site_id"}
    assert _ok(admin.get(f"/api/inventory/{gid}/hosts")) == []
    long = admin.post(
        f"/api/inventory/{gid}/hosts", json={"hostname": "x", "ip_address": "192.0.2.10", "location_detail": "r" * 201}
    )
    assert long.status_code == 422


def test_host_update_keeps_left_out_values_and_null_clears_lock(admin):
    gid = _group(admin)
    maker = _maker(admin)
    dtype = _type(admin, maker["id"])
    switch = _named(admin, "roles", "Switch")
    host = _host(admin, gid, device_type_id=dtype["id"], role_id=switch["id"], location_detail="Rack 1")
    base = {"hostname": "edge-sw1", "ip_address": "192.0.2.10"}
    _ok(admin.put(f"/api/hosts/{host}", json=base))
    row = _host_row(admin, gid, host)
    assert row["device_type_id"] == dtype["id"] and row["role_id"] == switch["id"]
    assert row["location_detail"] == "Rack 1"
    _ok(admin.put(f"/api/hosts/{host}", json={**base, "device_type_id": None, "location_detail": None}))
    stored = asyncio.run(db.get_host(host))
    assert stored["device_type_id"] is None and stored["hardware_locked"] == 0
    assert stored["role_id"] == switch["id"] and stored["role_locked"] == 1 and stored["location_detail"] == ""
    bad = admin.put(f"/api/hosts/{host}", json={**base, "hostname": "renamed", "device_type_id": 999999})
    assert bad.status_code == 400 and "device_type_id" in bad.json()["detail"]["fields"]
    assert asyncio.run(db.get_host(host))["hostname"] == "edge-sw1"


def test_bulk_add_carries_device_values(admin):
    gid = _group(admin)
    retired = _named(admin, "statuses", "Retired")
    body = {
        "hosts": [
            {"hostname": "a", "ip_address": "192.0.2.21", "lifecycle_status_id": retired["id"]},
            {"hostname": "b", "ip_address": "192.0.2.22"},
            {"hostname": "c", "ip_address": "192.0.2.23", "role_id": 999999},
        ]
    }
    result = _ok(admin.post(f"/api/inventory/{gid}/hosts/bulk", json=body))
    assert len(result["added"]) == 2
    assert result["errors"][0]["hostname"] == "c" and "role_id" in result["errors"][0]["error"]
    by_name = {h["hostname"]: h for h in _ok(admin.get(f"/api/inventory/{gid}/hosts"))}
    assert by_name["a"]["lifecycle_status"]["name"] == "Retired"
    assert by_name["b"]["lifecycle_status"]["name"] == "Active"


def test_category_patch_fills_an_empty_role(admin):
    gid = _group(admin)
    host = _host(admin, gid)
    resp = admin.raw.patch(
        f"/api/hosts/{host}/category", json={"device_category": "firewall"}, headers={"X-CSRF-Token": admin._csrf}
    )
    assert resp.status_code == 200, resp.text
    assert _host_row(admin, gid, host)["role"]["name"] == "Firewall"


# ── Listing and filters ──────────────────────────────────────────────────────


def _fleet(admin: CsrfClient) -> dict:
    """Two groups, four hosts with different device values."""
    core, edge = _group(admin, "core"), _group(admin, "edge")
    maker = _maker(admin)
    other = _maker(admin, "Other")
    t1 = _type(admin, maker["id"], "EX-1000")
    t2 = _type(admin, other["id"], "OT-1")
    switch = _named(admin, "roles", "Switch")["id"]
    router = _named(admin, "roles", "Router")["id"]
    site = _site()["id"]
    h1 = _host(admin, core, "sw1", "192.0.2.11", device_type_id=t1["id"], role_id=switch, site_id=site)
    h2 = _host(admin, core, "sw2", "192.0.2.12", device_type_id=t2["id"], role_id=router)
    h3 = _host(admin, edge, "sw3", "192.0.2.13", role_id=switch)
    h4 = _host(admin, edge, "sw4", "192.0.2.14")
    return {
        "core": core,
        "edge": edge,
        "maker": maker["id"],
        "other": other["id"],
        "t1": t1["id"],
        "switch": switch,
        "site": site,
        "hosts": (h1, h2, h3, h4),
    }


def _listed(admin: CsrfClient, query: str, mine: tuple[int, ...]) -> list[int]:
    """The ids among ``mine`` that the filtered listing returns (the app
    seeds hosts of its own at startup)."""
    groups = _ok(admin.get(f"/api/inventory?include_hosts=true&{query}"))
    return sorted(h["id"] for g in groups for h in g["hosts"] if h["id"] in mine)


def _groups(admin: CsrfClient, query: str, mine: set[int]) -> set[int]:
    return {g["id"] for g in _ok(admin.get(f"/api/inventory?{query}")) if g["id"] in mine}


def test_inline_objects_on_every_listing(admin):
    f = _fleet(admin)
    h1 = f["hosts"][0]
    full = _ok(admin.get("/api/inventory?include_hosts=true"))
    row = next(h for g in full for h in g["hosts"] if h["id"] == h1)
    assert row["hardware"]["manufacturer"] == "Example Networks" and row["role"]["name"] == "Switch"
    assert row["site"] == {"id": f["site"], "name": "Site A"} and row["location_detail"] == ""
    detail = _ok(admin.get(f"/api/inventory/{f['core']}"))
    assert next(h for h in detail["hosts"] if h["id"] == h1)["hardware"]["model"] == "EX-1000"
    assert _host_row(admin, f["core"], h1)["role"]["color"] == "teal"


def test_each_filter_and_none(admin):
    f = _fleet(admin)
    h1, h2, h3, h4 = mine = f["hosts"]
    assert _listed(admin, f"manufacturer_id={f['maker']}", mine) == [h1]
    assert _listed(admin, f"manufacturer_id={f['other']}&manufacturer_id=none", mine) == [h2, h3, h4]
    assert _listed(admin, f"device_type_id={f['t1']}", mine) == [h1]
    assert _listed(admin, "device_type_id=none", mine) == [h3, h4]
    assert _listed(admin, f"role_id={f['switch']}", mine) == [h1, h3]
    assert _listed(admin, "role_id=none", mine) == [h4]
    assert _listed(admin, f"site_id={f['site']}", mine) == [h1]
    assert _listed(admin, "site_id=none", mine) == [h2, h3, h4]
    active = _named(admin, "statuses", "Active")["id"]
    assert _listed(admin, f"lifecycle_status_id={active}", mine) == [h1, h2, h3, h4]
    assert _listed(admin, "lifecycle_status_id=none", mine) == []
    # Different filters must all match.
    assert _listed(admin, f"role_id={f['switch']}&device_type_id=none", mine) == [h3]
    # Groups left with no matching host are dropped.
    groups = _ok(admin.get(f"/api/inventory?include_hosts=true&manufacturer_id={f['maker']}"))
    assert [g["id"] for g in groups] == [f["core"]]
    # Without hosts, a group matches when it has a matching host.
    ours = {f["core"], f["edge"]}
    assert _groups(admin, "role_id=none", ours) == {f["edge"]}
    assert _groups(admin, f"role_id={f['switch']}", ours) == ours
    # The group endpoints filter their hosts.
    assert _ids(_ok(admin.get(f"/api/inventory/{f['edge']}/hosts?role_id=none"))) == [h4]
    assert _ids(_ok(admin.get(f"/api/inventory/{f['core']}?device_type_id={f['t1']}"))["hosts"]) == [h1]


def test_filters_combine_with_tags(admin):
    f = _fleet(admin)
    h1, _h2, h3, _h4 = mine = f["hosts"]
    tag = _ok(admin.post("/api/tags", json={"name": "lab"}), 201)
    _ok(admin.post("/api/hosts/bulk-tags", json={"host_ids": [h3], "add_tag_ids": [tag["id"]]}))
    assert _listed(admin, f"role_id={f['switch']}&tag=lab", mine) == [h3]
    assert _listed(admin, f"role_id={f['switch']}", mine) == [h1, h3]
    assert _ids(_ok(admin.get(f"/api/inventory/{f['core']}/hosts?tag=lab&role_id={f['switch']}"))) == []
    # Without hosts: the group must carry the tag and have a matching host.
    _ok(admin.put(f"/api/inventory/{f['core']}/custom-data", json={"tag_ids": [tag["id"]], "fields": {}}))
    ours = {f["core"], f["edge"]}
    assert _groups(admin, f"tag=lab&role_id={f['switch']}", ours) == {f["core"]}
    assert _groups(admin, "tag=lab&role_id=none", ours) == set()


@pytest.mark.parametrize("value", ["abc", "0", "-3", "1.5", "99999999999"])
def test_bad_filter_value_is_400(admin, value):
    gid = _group(admin)
    for url in (
        f"/api/inventory?include_hosts=true&role_id={value}",
        f"/api/inventory?site_id={value}",
        f"/api/inventory/{gid}/hosts?device_type_id={value}",
        f"/api/inventory/{gid}?manufacturer_id={value}",
    ):
        resp = admin.get(url)
        assert resp.status_code == 400, url
        assert resp.json()["detail"]["fields"], url


def test_listing_works_when_new_columns_are_null(admin):
    gid = _group(admin)
    host = _host(admin, gid)

    async def blank() -> None:
        conn = await db.get_db()
        try:
            await conn.execute(
                "UPDATE hosts SET device_type_id = NULL, role_id = NULL, lifecycle_status_id = NULL, site_id = NULL"
            )
            await conn.commit()
        finally:
            await conn.close()

    asyncio.run(blank())
    groups = _ok(admin.get("/api/inventory?include_hosts=true"))
    row = next(h for g in groups for h in g["hosts"] if h["id"] == host)
    assert (row["hardware"], row["role"], row["lifecycle_status"], row["site"]) == (None, None, None, None)
    assert _ok(admin.get(f"/api/inventory/{gid}"))["hosts"][0]["lifecycle_status"] is None
    assert admin.get("/api/inventory/export/csv").status_code == 200


# ── Bulk edit ────────────────────────────────────────────────────────────────


def test_bulk_edit(admin):
    f = _fleet(admin)
    h1, h2, h3, h4 = f["hosts"]
    retired = _named(admin, "statuses", "Retired")["id"]
    body = {"host_ids": [h1, h2, 999999], "set": {"lifecycle_status_id": retired, "location_detail": " Cage 2 "}}
    assert _ok(admin.post(BULK, json=body)) == {"ok": True, "updated": 2}
    assert _listed(admin, f"lifecycle_status_id={retired}", f["hosts"]) == [h1, h2]
    assert _host_row(admin, f["core"], h1)["location_detail"] == "Cage 2"
    # Only the keys present are applied.
    assert _host_row(admin, f["core"], h1)["role_id"] == f["switch"]
    assert _ok(admin.post(BULK, json={"host_ids": [h3, h4], "set": {"device_type_id": f["t1"]}}))["updated"] == 2
    assert asyncio.run(db.get_host(h4))["hardware_locked"] == 1
    assert (
        _ok(admin.post(BULK, json={"host_ids": [h3], "set": {"device_type_id": None, "site_id": None}}))["updated"] == 1
    )
    assert asyncio.run(db.get_host(h3))["hardware_locked"] == 0


def test_bulk_edit_rejects_bad_bodies(admin):
    host = _host(admin, _group(admin))
    assert admin.post(BULK, json={"host_ids": [], "set": {"role_id": None}}).status_code == 422
    assert admin.post(BULK, json={"host_ids": list(range(1, 5002)), "set": {"role_id": None}}).status_code == 422
    assert admin.post(BULK, json={"host_ids": [host]}).status_code == 422
    empty = admin.post(BULK, json={"host_ids": [host], "set": {}})
    assert empty.status_code == 400 and "set" in empty.json()["detail"]["fields"]
    unknown = admin.post(BULK, json={"host_ids": [host], "set": {"role_id": 999999}})
    assert unknown.status_code == 400 and unknown.json()["detail"]["fields"] == {"role_id": "No record with id 999999."}


# ── CSV ──────────────────────────────────────────────────────────────────────


def test_csv_columns(admin):
    f = _fleet(admin)
    _ok(admin.post(BULK, json={"host_ids": [f["hosts"][0]], "set": {"location_detail": "=HYPERLINK(1)"}}))
    resp = admin.get("/api/inventory/export/csv")
    assert resp.status_code == 200
    header, *rows = list(csv.reader(io.StringIO(resp.text)))
    assert header == [
        "Hostname",
        "IP Address",
        "Model",
        "Software Version",
        "Platform",
        "Status",
        "Group",
        "Manufacturer",
        "Device Type",
        "Role",
        "Lifecycle Status",
        "Site",
        "Location Detail",
        "Tags",
    ]
    by_name = {r[0]: r for r in rows}
    assert by_name["sw1"][4] == "cisco_ios"
    assert by_name["sw1"][7:13] == ["Example Networks", "EX-1000", "Switch", "Active", "Site A", "'=HYPERLINK(1)"]
    assert by_name["sw4"][7:13] == ["", "", "", "Active", "", ""]


# ── Sites ────────────────────────────────────────────────────────────────────


def test_geo_sites_carry_host_count(admin):
    f = _fleet(admin)
    sites = {s["name"]: s for s in _ok(admin.get("/api/geo/sites"))}
    assert sites["Site A"]["host_count"] == 1 and sites["Site A"]["id"] == f["site"]


# ── Audit ────────────────────────────────────────────────────────────────────


def test_writes_are_audited(admin):
    gid = _group(admin)
    maker = _maker(admin)
    admin.put(f"{DCIM}/manufacturers/{maker['id']}", json={"name": "Example Co"})
    dtype = _type(admin, maker["id"])
    admin.put(f"{DCIM}/device-types/{dtype['id']}", json={"u_height": 1})
    role = _ok(admin.post(f"{DCIM}/roles", json={"name": "Core"}), 201)
    admin.put(f"{DCIM}/roles/{role['id']}", json={"color": "red"})
    status = _ok(admin.post(f"{DCIM}/statuses", json={"name": "Spare"}), 201)
    admin.put(f"{DCIM}/statuses/{status['id']}", json={"color": "red"})
    host = _host(admin, gid, role_id=role["id"])
    admin.put(f"/api/hosts/{host}", json={"hostname": "edge-sw1", "ip_address": "192.0.2.10", "site_id": None})
    admin.post(BULK, json={"host_ids": [host], "set": {"location_detail": "Rack 1"}})
    admin.delete(f"{DCIM}/device-types/{dtype['id']}")
    admin.delete(f"{DCIM}/manufacturers/{maker['id']}")
    admin.delete(f"{DCIM}/roles/{role['id']}?confirm=true")
    admin.delete(f"{DCIM}/statuses/{status['id']}")
    events = asyncio.run(db.get_audit_events(limit=100, category="device_model"))
    assert {e["action"] for e in events} == {
        "manufacturer_create",
        "manufacturer_update",
        "manufacturer_delete",
        "device_type_create",
        "device_type_update",
        "device_type_delete",
        "role_create",
        "role_update",
        "role_delete",
        "status_create",
        "status_update",
        "status_delete",
        "host_create",
        "host_update",
        "bulk_edit",
    }
    assert all(e["user"] == "admin" for e in events)
