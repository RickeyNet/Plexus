"""IPAM namespaces, route targets, VLAN groups, RIRs and aggregates
(migration 0110, ``netcontrol.ipam_model``, ``routes.db.ipam_model``,
``netcontrol.routes.ipam_model``): the rules, the API contracts, uniqueness
per namespace and VRF and per VLAN group, aggregate containment and
utilisation, the next free VLAN id, and access."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import pytest
import routes.database as db
from netcontrol.custom_fields import CustomFieldError
from netcontrol.ipam_model import (
    aggregate_usage,
    clean_aggregate_prefix,
    clean_route_target,
    clean_vid_range,
    containing_aggregate,
    next_free_vid,
)
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

API = "/api/ipam"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _err(resp, status: int) -> str:
    assert resp.status_code == status, resp.text
    error = resp.json()["error"]
    return str(error.get("message") or error)


# ── Rules ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("65000:100", "65000:100"),
        (" 64512:4294967295 ", "64512:4294967295"),
        ("4200000000:1", "4200000000:1"),
        ("192.0.2.1:100", "192.0.2.1:100"),
        ("065000:007", "65000:7"),
    ],
)
def test_route_target_accepts_the_three_forms(raw, clean):
    assert clean_route_target(raw) == clean


@pytest.mark.parametrize(
    "raw", ["", "65000", "65000:", ":100", "65000:100:1", "4200000000:70000", "192.0.2.1:70000", "2001:db8::1:1", "a:b"]
)
def test_route_target_refuses_bad_values(raw):
    with pytest.raises(CustomFieldError):
        clean_route_target(raw)


def test_vid_range_and_next_free_vid():
    assert clean_vid_range(100, 199) == (100, 199)
    for low, high in ((0, 10), (10, 4095), (20, 10), (True, 10)):
        with pytest.raises(CustomFieldError):
            clean_vid_range(low, high)
    assert next_free_vid(100, 103, [100, 101, 103]) == 102
    assert next_free_vid(100, 101, [100, 101]) is None


def test_aggregate_prefix_containment_and_usage():
    assert clean_aggregate_prefix(" 198.51.100.0/24 ") == "198.51.100.0/24"
    with pytest.raises(CustomFieldError, match="did you mean 198.51.100.0/24"):
        clean_aggregate_prefix("198.51.100.7/24")
    with pytest.raises(CustomFieldError):
        clean_aggregate_prefix("not-a-prefix")
    aggregates = [{"prefix": "198.51.100.0/24"}, {"prefix": "198.51.100.0/25"}, {"prefix": "2001:db8::/32"}]
    assert containing_aggregate("198.51.100.16/28", aggregates) == {"prefix": "198.51.100.0/25"}
    assert containing_aggregate("198.51.100.200/29", aggregates) == {"prefix": "198.51.100.0/24"}
    assert containing_aggregate("2001:db8:1::/48", aggregates) == {"prefix": "2001:db8::/32"}
    assert containing_aggregate("203.0.113.0/24", aggregates) is None
    assert containing_aggregate("junk", aggregates) is None
    usage = aggregate_usage(
        "198.51.100.0/24", ["198.51.100.0/25", "198.51.100.0/26", "203.0.113.0/24", "2001:db8::/64", "junk"]
    )
    # The /26 sits inside the /25: counted as a prefix, its addresses once.
    assert usage == {"prefix_count": 2, "total_addresses": 256, "used_addresses": 128, "utilization_pct": 50.0}


# ── Migration: everything existing is in Global ─────────────────────────────


def test_existing_vrfs_and_prefixes_land_in_global(admin):
    namespaces = _ok(admin.get(f"{API}/namespaces"))["namespaces"]
    assert [(n["id"], n["name"]) for n in namespaces] == [(1, "Global")]
    vrf = _ok(admin.post(f"{API}/vrfs", json={"name": "BLUE"}), 201)
    assert vrf["namespace_id"] == 1 and vrf["namespace_name"] == "Global"
    prefix = _ok(admin.post(f"{API}/prefixes", json={"subnet": "192.0.2.0/24"}), 201)["prefix"]
    assert prefix["namespace_id"] == 1
    assert _err(admin.delete(f"{API}/namespaces/1"), 409) == "The Global namespace cannot be deleted."


# ── Namespaces and prefix uniqueness ─────────────────────────────────────────


def test_prefix_is_unique_per_namespace_and_vrf(admin):
    lab = _ok(admin.post(f"{API}/namespaces", json={"name": "Lab", "description": "test bed"}), 201)
    assert _err(admin.post(f"{API}/namespaces", json={"name": "lab"}), 409) == "A namespace named 'lab' already exists."
    body = {"subnet": "198.51.100.0/24"}
    first = _ok(admin.post(f"{API}/prefixes", json=body), 201)["prefix"]
    assert "already defined" in _err(admin.post(f"{API}/prefixes", json=body), 409)
    # The same address space in another VRF, and in another namespace.
    in_vrf = _ok(admin.post(f"{API}/prefixes", json={**body, "vrf": "RED"}), 201)["prefix"]
    in_lab = _ok(admin.post(f"{API}/prefixes", json={**body, "namespace_id": lab["id"]}), 201)["prefix"]
    assert len({first["id"], in_vrf["id"], in_lab["id"]}) == 3
    assert (in_vrf["namespace_id"], in_lab["namespace_id"]) == (1, lab["id"])
    assert "already defined" in _err(admin.post(f"{API}/prefixes", json={**body, "namespace_id": lab["id"]}), 409)
    # A VRF record lives in one namespace: its prefixes follow it.
    assert _err(admin.post(f"{API}/prefixes", json={**body, "vrf": "RED", "namespace_id": lab["id"]}), 422) == (
        "VRF RED is in another namespace."
    )
    lab_vrf = _ok(
        admin.post(f"{API}/prefixes", json={"subnet": "203.0.113.0/24", "vrf": "LABNET", "namespace_id": lab["id"]}),
        201,
    )
    vrfs = {v["name"]: v for v in _ok(admin.get(f"{API}/vrfs"))["vrfs"]}
    assert vrfs["LABNET"]["namespace_id"] == lab["id"] and lab_vrf["prefix"]["namespace_id"] == lab["id"]
    unknown = admin.post(f"{API}/prefixes", json={**body, "namespace_id": 999})
    assert unknown.status_code == 400 and "namespace_id" in unknown.text

    detail = _ok(admin.get(f"{API}/namespaces/{lab['id']}"))
    assert [v["name"] for v in detail["vrfs"]] == ["LABNET"]
    assert {p["subnet"] for p in detail["prefixes"]} == {"198.51.100.0/24", "203.0.113.0/24"}
    # Moving a prefix into a namespace that has it already is refused.
    assert "already has" in _err(
        admin.put(f"{API}/prefixes/{first['id']}/namespace", json={"namespace_id": lab["id"]}), 409
    )
    spare = _ok(admin.post(f"{API}/namespaces", json={"name": "Spare"}), 201)
    moved = _ok(admin.put(f"{API}/prefixes/{in_lab['id']}/namespace", json={"namespace_id": spare["id"]}))
    assert (moved["prefix"]["id"], moved["prefix"]["namespace_id"]) == (in_lab["id"], spare["id"])
    # A prefix of a VRF record follows the VRF's namespace.
    follows = admin.put(f"{API}/prefixes/{in_vrf['id']}/namespace", json={"namespace_id": spare["id"]})
    assert follows.status_code == 422 and "move the VRF" in follows.text
    # A namespace in use cannot be deleted.
    assert "in use" in _err(admin.delete(f"{API}/namespaces/{lab['id']}"), 409)


def test_vrf_namespace_can_be_set_and_changed(admin):
    lab = _ok(admin.post(f"{API}/namespaces", json={"name": "Lab"}), 201)
    vrf = _ok(admin.post(f"{API}/vrfs", json={"name": "GREEN", "namespace_id": lab["id"]}), 201)
    assert vrf["namespace_id"] == lab["id"]
    moved = _ok(admin.put(f"{API}/vrfs/{vrf['id']}", json={"namespace_id": 1}))
    assert moved["namespace_id"] == 1
    assert admin.put(f"{API}/vrfs/{vrf['id']}", json={"namespace_id": 999}).status_code == 400
    assert admin.post(f"{API}/vrfs", json={"name": "X", "namespace_id": 999}).status_code == 400


# ── Route targets ────────────────────────────────────────────────────────────


def test_route_targets_crud_and_vrf_import_export(admin):
    a = _ok(admin.post(f"{API}/route-targets", json={"name": " 65000:100 ", "description": "hub"}), 201)
    b = _ok(admin.post(f"{API}/route-targets", json={"name": "192.0.2.1:200"}), 201)
    assert a["name"] == "65000:100"
    assert (
        _err(admin.post(f"{API}/route-targets", json={"name": "65000:100"}), 409)
        == "Route target 65000:100 already exists."
    )
    bad = admin.post(f"{API}/route-targets", json={"name": "65000"})
    assert bad.status_code == 422 and "name" in bad.json()["detail"]["fields"]
    assert admin.post(f"{API}/route-targets", json={"name": "65000:1", "tenant_id": 999}).status_code == 400

    vrf = _ok(admin.post(f"{API}/vrfs", json={"name": "BLUE"}), 201)
    path = f"{API}/vrfs/{vrf['id']}/route-targets"
    assert _ok(admin.get(path)) == {"vrf_id": vrf["id"], "import": [], "export": []}
    set_ = _ok(admin.put(path, json={"import_ids": [a["id"], b["id"]], "export_ids": [a["id"]]}))
    assert [r["name"] for r in set_["import"]] == ["192.0.2.1:200", "65000:100"]
    assert [r["name"] for r in set_["export"]] == ["65000:100"]
    assert admin.put(path, json={"import_ids": [999]}).status_code == 400
    # The VRF detail shows them; the route target lists its VRFs.
    detail = _ok(admin.get(f"{API}/vrfs/{vrf['id']}"))
    assert [r["name"] for r in detail["route_targets"]["export"]] == ["65000:100"]
    rt = _ok(admin.get(f"{API}/route-targets/{a['id']}"))
    assert (rt["import_vrf_count"], rt["export_vrf_count"]) == (1, 1)
    assert {(v["name"], v["direction"]) for v in rt["vrfs"]} == {("BLUE", "import"), ("BLUE", "export")}
    by_vrf = _ok(admin.get(f"{API}/route-targets", params={"vrf_id": vrf["id"]}))["route_targets"]
    assert {r["id"] for r in by_vrf} == {a["id"], b["id"]}
    assert len(_ok(admin.get(f"{API}/route-targets", params={"q": "hub"}))["route_targets"]) == 1
    renamed = _ok(admin.put(f"{API}/route-targets/{b['id']}", json={"name": "4200000000:5"}))
    assert renamed["name"] == "4200000000:5"
    _ok(admin.delete(f"{API}/route-targets/{a['id']}"))
    assert _ok(admin.get(path))["export"] == []
    assert admin.get(f"{API}/route-targets/{a['id']}").status_code == 404


# ── VLAN groups ──────────────────────────────────────────────────────────────


def _site(admin: CsrfClient, name: str) -> int:
    return int(_ok(admin.post("/api/geo/sites", json={"name": name}), 201)["id"])


def test_vlan_group_range_uniqueness_and_next_vid(admin):
    group = _ok(admin.post(f"{API}/vlan-groups", json={"name": "Campus", "min_vid": 100, "max_vid": 102}), 201)
    gid = group["id"]
    assert _ok(admin.get(f"{API}/vlan-groups/{gid}/next-vid")) == {"vlan_group_id": gid, "vid": 100}
    first = _ok(admin.post(f"{API}/vlans", json={"vid": 100, "vlan_group_id": gid}), 201)
    assert first["vlan_group"] == {"id": gid, "name": "Campus"}
    assert _ok(admin.get(f"{API}/vlan-groups/{gid}/next-vid"))["vid"] == 101
    # Outside the range.
    outside = admin.post(f"{API}/vlans", json={"vid": 200, "vlan_group_id": gid})
    assert outside.status_code == 422 and "100 to 102" in outside.text
    # The VLAN id once per group: a second site's VLAN 100 cannot join.
    site = _site(admin, "Branch")
    clash = admin.post(f"{API}/vlans", json={"vid": 100, "site_id": site, "vlan_group_id": gid})
    assert clash.status_code == 409 and "VLAN group" in clash.text
    # Another group may hold the same VLAN id.
    other = _ok(admin.post(f"{API}/vlan-groups", json={"name": "Lab"}), 201)
    _ok(admin.post(f"{API}/vlans", json={"vid": 100, "site_id": site, "vlan_group_id": other["id"]}), 201)
    _ok(admin.post(f"{API}/vlans", json={"vid": 101, "vlan_group_id": gid}), 201)
    second_site = _ok(admin.post(f"{API}/vlans", json={"vid": 102, "site_id": site}), 201)
    _ok(admin.put(f"{API}/vlans/{second_site['id']}", json={"vlan_group_id": gid}))
    detail = _ok(admin.get(f"{API}/vlan-groups/{gid}"))
    assert ([v["vid"] for v in detail["vlans"]], detail["available"], detail["next_vid"]) == ([100, 101, 102], 0, None)
    assert _ok(admin.get(f"{API}/vlan-groups/{gid}/next-vid"))["vid"] is None
    assert {v["vid"] for v in _ok(admin.get(f"{API}/vlans", params={"vlan_group_id": gid}))["vlans"]} == {100, 101, 102}
    # The range cannot shrink below its VLANs.
    assert "outside" in _err(admin.put(f"{API}/vlan-groups/{gid}", json={"max_vid": 101}), 422)
    assert admin.put(f"{API}/vlan-groups/{gid}", json={"min_vid": 200}).status_code == 422
    # Deleting the group keeps its VLANs, in no group.
    _ok(admin.delete(f"{API}/vlan-groups/{gid}"))
    assert _ok(admin.get(f"{API}/vlans/{first['id']}"))["vlan_group_id"] is None
    assert admin.get(f"{API}/vlan-groups/{gid}/next-vid").status_code == 404


def test_vlan_group_scope(admin):
    site_a, site_b = _site(admin, "Site A"), _site(admin, "Site B")
    assert admin.post(f"{API}/vlan-groups", json={"name": "Both", "site_id": site_a, "region_id": 1}).status_code == 422
    assert admin.post(f"{API}/vlan-groups", json={"name": "Nowhere", "site_id": 999}).status_code == 400
    assert admin.post(f"{API}/vlan-groups", json={"name": "Nowhere", "region_id": 999}).status_code == 400
    scoped = _ok(admin.post(f"{API}/vlan-groups", json={"name": "A only", "site_id": site_a}), 201)
    assert scoped["site_name"] == "Site A"
    _ok(admin.post(f"{API}/vlans", json={"vid": 10, "site_id": site_a, "vlan_group_id": scoped["id"]}), 201)
    _ok(admin.post(f"{API}/vlans", json={"vid": 11, "vlan_group_id": scoped["id"]}), 201)
    wrong = admin.post(f"{API}/vlans", json={"vid": 12, "site_id": site_b, "vlan_group_id": scoped["id"]})
    assert wrong.status_code == 422 and "scoped to one site" in wrong.text
    # The group cannot move to the other site while it holds Site A's VLAN.
    assert admin.put(f"{API}/vlan-groups/{scoped['id']}", json={"site_id": site_b}).status_code == 422
    assert [g["name"] for g in _ok(admin.get(f"{API}/vlan-groups", params={"site_id": site_a}))["vlan_groups"]] == [
        "A only"
    ]


# ── RIRs and aggregates ──────────────────────────────────────────────────────


def test_rirs_aggregates_containment_and_utilisation(admin):
    rir = _ok(admin.post(f"{API}/rirs", json={"name": "RFC 5737", "is_private": True}), 201)
    assert rir["is_private"] is True
    assert admin.post(f"{API}/rirs", json={"name": "rfc 5737"}).status_code == 409
    body = {"prefix": "198.51.100.0/24", "rir_id": rir["id"], "date_added": "2026-01-15"}
    agg = _ok(admin.post(f"{API}/aggregates", json=body), 201)
    assert (agg["rir_name"], agg["date_added"]) == ("RFC 5737", "2026-01-15")
    assert "host bits" in admin.post(f"{API}/aggregates", json={**body, "prefix": "198.51.100.9/24"}).text
    assert admin.post(f"{API}/aggregates", json={**body, "date_added": "2026-13-01"}).status_code == 422
    assert admin.post(f"{API}/aggregates", json={**body, "rir_id": 999}).status_code == 400
    assert "overlaps" in _err(admin.post(f"{API}/aggregates", json={**body, "prefix": "198.51.100.0/25"}), 422)
    v6 = _ok(admin.post(f"{API}/aggregates", json={"prefix": "2001:db8::/32", "rir_id": rir["id"]}), 201)

    for subnet in ("198.51.100.0/25", "198.51.100.128/26"):
        _ok(admin.post(f"{API}/prefixes", json={"subnet": subnet}), 201)
    _ok(admin.post(f"{API}/prefixes", json={"subnet": "203.0.113.0/24"}), 201)
    rows = {a["prefix"]: a for a in _ok(admin.get(f"{API}/aggregates"))["aggregates"]}
    assert (rows["198.51.100.0/24"]["prefix_count"], rows["198.51.100.0/24"]["utilization_pct"]) == (2, 75.0)
    assert rows["2001:db8::/32"]["prefix_count"] == 0
    detail = _ok(admin.get(f"{API}/aggregates/{agg['id']}"))
    assert {p["subnet"] for p in detail["prefixes"]} == {"198.51.100.0/25", "198.51.100.128/26"}
    assert detail["used_addresses"] == 192

    # A prefix reports the aggregate that holds it.
    found = _ok(admin.get(f"{API}/aggregates/containing", params={"subnet": "198.51.100.128/26"}))
    assert found["aggregate"]["id"] == agg["id"] and found["aggregate"]["utilization_pct"] == 75.0
    assert _ok(admin.get(f"{API}/aggregates/containing", params={"subnet": "203.0.113.0/24"}))["aggregate"] is None
    drill = _ok(admin.get(f"{API}/subnets/198.51.100.0/25"))
    assert drill["aggregate"]["prefix"] == "198.51.100.0/24"

    # A RIR with aggregates cannot be deleted.
    assert "in use" in _err(admin.delete(f"{API}/rirs/{rir['id']}"), 409)
    _ok(admin.delete(f"{API}/aggregates/{agg['id']}"))
    _ok(admin.delete(f"{API}/aggregates/{v6['id']}"))
    _ok(admin.delete(f"{API}/rirs/{rir['id']}"))
    assert _ok(admin.get(f"{API}/rirs"))["rirs"] == []


# ── Access ───────────────────────────────────────────────────────────────────


def test_reads_need_ipam_and_writes_need_admin(admin):
    rt = _ok(admin.post(f"{API}/route-targets", json={"name": "65000:1"}), 201)
    group = _ok(admin.post(f"{API}/vlan-groups", json={"name": "G"}), 201)
    reads = (
        f"{API}/namespaces",
        f"{API}/route-targets",
        f"{API}/route-targets/{rt['id']}",
        f"{API}/vlan-groups",
        f"{API}/vlan-groups/{group['id']}/next-vid",
        f"{API}/rirs",
        f"{API}/aggregates",
    )
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    assert [anon.get(p).status_code for p in reads] == [401] * len(reads)
    plain = user_client(admin, "plain-user")
    assert [plain.get(p).status_code for p in reads] == [403] * len(reads)
    reader = user_client(admin, "ipam-user", features=["ipam"])
    assert [reader.get(p).status_code for p in reads] == [200] * len(reads)
    writes = (
        reader.post(f"{API}/namespaces", json={"name": "N"}),
        reader.post(f"{API}/route-targets", json={"name": "65000:2"}),
        reader.put(f"{API}/route-targets/{rt['id']}", json={"description": "x"}),
        reader.delete(f"{API}/route-targets/{rt['id']}"),
        reader.post(f"{API}/vlan-groups", json={"name": "H"}),
        reader.post(f"{API}/rirs", json={"name": "R"}),
        reader.put(f"{API}/vrfs/1/route-targets", json={}),
        reader.put(f"{API}/prefixes/1/namespace", json={"namespace_id": 1}),
    )
    assert [r.status_code for r in writes] == [403] * len(writes)


def test_writes_are_audited_and_change_tracked(admin):
    seen: list[dict] = []

    async def hook(event: dict) -> None:
        seen.append(event)

    from routes.db.change_events import add_object_change_hook, remove_object_change_hook

    add_object_change_hook(hook)
    try:
        rir = _ok(admin.post(f"{API}/rirs", json={"name": "Private"}), 201)
        _ok(admin.put(f"{API}/rirs/{rir['id']}", json={"description": "internal"}))
    finally:
        remove_object_change_hook(hook)
    assert [(e["object_type"], e["action"]) for e in seen] == [("rir", "create"), ("rir", "update")]
    events = asyncio.run(db.get_audit_events(limit=50, category="ipam_model"))
    assert [e["action"] for e in events if e["action"].startswith("rir_")] == ["rir_update", "rir_create"]


# ── Object scope ─────────────────────────────────────────────────────────────


def _scoped_ipam_user(admin: CsrfClient, name: str, rules: list[dict]) -> CsrfClient:
    """A user limited to selected inventory groups (none granted), reading
    IPAM through per-model tenant and site rules."""
    body = {"name": f"{name} access", "feature_keys": ["ipam"], "object_scope": "groups", "inventory_scopes": []}
    group = _ok(admin.post("/api/admin/access-groups", json=body), 201)
    _ok(admin.put(f"/api/admin/access-groups/{group['id']}/scope-rules", json={"rules": rules}))
    _ok(
        admin.post("/api/admin/users", json={"username": name, "password": "password123", "group_ids": [group["id"]]}),
        201,
    )
    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": name, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json()["csrf_token"])


def test_scoped_reader_sees_only_their_tenants_and_sites(admin):
    t_a = _ok(admin.post("/api/organization/tenants", json={"name": "east-co"}), 201)["id"]
    t_b = _ok(admin.post("/api/organization/tenants", json={"name": "west-co"}), 201)["id"]
    s_a, s_b = _site(admin, "East site"), _site(admin, "West site")
    rt_a = _ok(admin.post(f"{API}/route-targets", json={"name": "65000:1", "tenant_id": t_a}), 201)
    rt_b = _ok(admin.post(f"{API}/route-targets", json={"name": "65000:2", "tenant_id": t_b}), 201)
    rt_shared = _ok(admin.post(f"{API}/route-targets", json={"name": "65000:3"}), 201)
    vrf = _ok(admin.post(f"{API}/vrfs", json={"name": "BLUE", "tenant_id": t_a}), 201)
    ids = [rt_a["id"], rt_b["id"], rt_shared["id"]]
    _ok(admin.put(f"{API}/vrfs/{vrf['id']}/route-targets", json={"import_ids": ids, "export_ids": ids}))
    g_a = _ok(admin.post(f"{API}/vlan-groups", json={"name": "East", "site_id": s_a}), 201)
    g_b = _ok(admin.post(f"{API}/vlan-groups", json={"name": "West", "site_id": s_b}), 201)
    _ok(admin.post(f"{API}/vlan-groups", json={"name": "Anywhere"}), 201)
    _ok(admin.post(f"{API}/vlans", json={"vid": 10, "site_id": s_a, "vlan_group_id": g_a["id"]}), 201)
    rir = _ok(admin.post(f"{API}/rirs", json={"name": "RFC 5737", "is_private": True}), 201)
    agg_a = _ok(
        admin.post(f"{API}/aggregates", json={"prefix": "198.51.100.0/24", "rir_id": rir["id"], "tenant_id": t_a}), 201
    )
    agg_b = _ok(
        admin.post(f"{API}/aggregates", json={"prefix": "203.0.113.0/24", "rir_id": rir["id"], "tenant_id": t_b}), 201
    )
    _ok(admin.post(f"{API}/prefixes", json={"subnet": "198.51.100.0/25", "tenant_id": t_a}), 201)
    _ok(admin.post(f"{API}/prefixes", json={"subnet": "198.51.100.128/25", "tenant_id": t_b}), 201)
    lab = _ok(admin.post(f"{API}/namespaces", json={"name": "Lab"}), 201)

    reader = _scoped_ipam_user(
        admin,
        "east-reader",
        [
            {"model": "route_target", "attribute": "tenant", "value_id": t_a},
            {"model": "aggregate", "attribute": "tenant", "value_id": t_a},
            {"model": "vrf", "attribute": "tenant", "value_id": t_a},
            {"model": "ipam_prefix", "attribute": "tenant", "value_id": t_a},
            {"model": "vlan_group", "attribute": "site", "value_id": s_a},
            {"model": "vlan", "attribute": "site", "value_id": s_a},
        ],
    )
    # Route targets: their tenant's and the shared one; the VRF shows only those.
    names = {r["name"] for r in _ok(reader.get(f"{API}/route-targets"))["route_targets"]}
    assert names == {"65000:1", "65000:3"}
    assert reader.get(f"{API}/route-targets/{rt_b['id']}").status_code == 404
    assert [v["name"] for v in _ok(reader.get(f"{API}/route-targets/{rt_a['id']}"))["vrfs"]] == ["BLUE", "BLUE"]
    detail = _ok(reader.get(f"{API}/vrfs/{vrf['id']}"))
    assert {r["name"] for r in detail["route_targets"]["import"]} == {"65000:1", "65000:3"}
    assert {r["name"] for r in _ok(reader.get(f"{API}/vrfs/{vrf['id']}/route-targets"))["export"]} == {
        "65000:1",
        "65000:3",
    }
    assert len(_ok(admin.get(f"{API}/vrfs/{vrf['id']}"))["route_targets"]["import"]) == 3
    # VLAN groups: their site's and the unscoped one.
    groups = {g["name"] for g in _ok(reader.get(f"{API}/vlan-groups"))["vlan_groups"]}
    assert groups == {"East", "Anywhere"}
    assert "scope_site_ids" not in _ok(reader.get(f"{API}/vlan-groups"))["vlan_groups"][0]
    assert [v["vid"] for v in _ok(reader.get(f"{API}/vlan-groups/{g_a['id']}"))["vlans"]] == [10]
    assert reader.get(f"{API}/vlan-groups/{g_b['id']}").status_code == 404
    assert reader.get(f"{API}/vlan-groups/{g_b['id']}/next-vid").status_code == 404
    assert _ok(reader.get(f"{API}/vlan-groups/{g_a['id']}/next-vid"))["vid"] == 1
    # Aggregates: their tenant's, with only their prefixes listed.
    assert [a["prefix"] for a in _ok(reader.get(f"{API}/aggregates"))["aggregates"]] == ["198.51.100.0/24"]
    assert reader.get(f"{API}/aggregates/{agg_b['id']}").status_code == 404
    agg = _ok(reader.get(f"{API}/aggregates/{agg_a['id']}"))
    assert [p["subnet"] for p in agg["prefixes"]] == ["198.51.100.0/25"]
    hidden = _ok(reader.get(f"{API}/aggregates/containing", params={"subnet": "203.0.113.0/25"}))
    assert hidden["aggregate"] is None
    # Namespaces and RIRs are reference data; a namespace lists only readable rows.
    assert {n["name"] for n in _ok(reader.get(f"{API}/namespaces"))["namespaces"]} == {"Global", "Lab"}
    assert _ok(reader.get(f"{API}/namespaces/{lab['id']}"))["prefixes"] == []
    global_ns = _ok(reader.get(f"{API}/namespaces/1"))
    assert [p["subnet"] for p in global_ns["prefixes"]] == ["198.51.100.0/25"]
    assert [v["name"] for v in global_ns["vrfs"]] == ["BLUE"]
    assert [r["name"] for r in _ok(reader.get(f"{API}/rirs"))["rirs"]] == ["RFC 5737"]
    assert _ok(reader.get(f"{API}/rirs/{rir['id']}"))["name"] == "RFC 5737"
    # Writes stay admin only.
    assert reader.post(f"{API}/rirs", json={"name": "X"}).status_code == 403
    assert reader.put(f"{API}/vrfs/{vrf['id']}/route-targets", json={}).status_code == 403
