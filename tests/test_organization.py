"""Location hierarchy and tenancy (``netcontrol.routes.organization`` and the
site, host, IPAM, VLAN and VRF extensions): region and tenant group trees,
cycle and delete refusals, the location tree, site fields, tenant counts,
tenant assignment, the tenant and region host filters (regions include their
descendants), dynamic groups, access and the change log."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import pytest
import routes.database as db
from netcontrol.dynamic_groups import resolve_hosts, validate_filter
from netcontrol.object_scope import UNRESTRICTED
from netcontrol.organization import OrganizationValueError, clean_name, clean_site_status, clean_text, clean_time_zone
from netcontrol.routes import state
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

ORG = "/api/organization"
REGIONS = f"{ORG}/regions"
GROUPS = f"{ORG}/tenant-groups"
TENANTS = f"{ORG}/tenants"
SITES = "/api/geo/sites"


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200):
    assert resp.status_code == status, resp.text
    return resp.json()


def _region(admin: CsrfClient, name: str, parent: int | None = None) -> int:
    return int(_ok(admin.post(REGIONS, json={"name": name, "parent_id": parent}), 201)["id"])


def _site(admin: CsrfClient, name: str, **extra) -> int:
    return int(_ok(admin.post(SITES, json={"name": name, **extra}), 201)["id"])


def _tenant(admin: CsrfClient, name: str, **extra) -> int:
    return int(_ok(admin.post(TENANTS, json={"name": name, **extra}), 201)["id"])


def _host(admin: CsrfClient, name: str, ip: str, **extra) -> int:
    gid = int(_ok(admin.post("/api/inventory", json={"name": f"group-{name}"}), 201)["id"])
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios", **extra}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


def _listed_hosts(admin: CsrfClient, query: str) -> set[str]:
    groups = _ok(admin.get(f"/api/inventory?include_hosts=true&{query}"))
    return {h["hostname"] for g in groups for h in g["hosts"]}


# ── Rules ────────────────────────────────────────────────────────────────────


def test_site_status_and_time_zone_rules():
    assert clean_site_status(" Planned ") == "planned"
    assert clean_time_zone(" Europe/Amsterdam ") == "Europe/Amsterdam"
    assert clean_time_zone("") == ""
    for bad in ("Mars/Olympus", "../etc/passwd", "x" * 80):
        with pytest.raises(OrganizationValueError) as exc:
            clean_time_zone(bad)
        assert exc.value.field == "time_zone"
    with pytest.raises(OrganizationValueError):
        clean_site_status("closed")
    with pytest.raises(OrganizationValueError):
        clean_name("x" * 101)
    with pytest.raises(OrganizationValueError):
        clean_text("x" * 101, "facility", 100)


# ── Access ───────────────────────────────────────────────────────────────────


def test_reads_need_organization_and_writes_need_admin(admin):
    rid = _region(admin, "Europe")
    tid = _tenant(admin, "Example Retail")
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    assert anon.get(REGIONS).status_code == 401
    plain = user_client(admin, "plain-user")
    reads = (REGIONS, f"{REGIONS}/{rid}", f"{ORG}/locations", f"{ORG}/sites", GROUPS, TENANTS, f"{TENANTS}/{tid}")
    for path in reads:
        assert plain.get(path).status_code == 403, path
    reader = user_client(admin, "org-reader", features=["organization"])
    for path in reads:
        assert reader.get(path).status_code == 200, path
    writes = (
        reader.post(REGIONS, json={"name": "Asia"}),
        reader.put(f"{REGIONS}/{rid}", json={"description": "x"}),
        reader.delete(f"{REGIONS}/{rid}"),
        reader.post(GROUPS, json={"name": "Retail"}),
        reader.post(TENANTS, json={"name": "Other"}),
        reader.put(f"{TENANTS}/{tid}", json={"description": "x"}),
        reader.delete(f"{TENANTS}/{tid}"),
    )
    assert [r.status_code for r in writes] == [403] * len(writes)
    assert "organization" in state.FEATURE_FLAGS and "organization.write" not in state.FEATURE_FLAGS


# ── Regions ──────────────────────────────────────────────────────────────────


def test_region_tree_with_site_counts(admin):
    europe = _region(admin, "Europe")
    west = _region(admin, "West", europe)
    nl = _region(admin, "Netherlands", west)
    _region(admin, "Asia")
    _site(admin, "AMS1", region_id=nl)
    _site(admin, "AMS2", region_id=nl)
    _site(admin, "LON1", region_id=west)
    regions = _ok(admin.get(REGIONS))["regions"]
    assert [(r["name"], r["depth"]) for r in regions] == [
        ("Asia", 0),
        ("Europe", 0),
        ("West", 1),
        ("Netherlands", 2),
    ]
    by_name = {r["name"]: r for r in regions}
    assert by_name["Netherlands"]["path"] == "Europe / West / Netherlands"
    assert (by_name["West"]["site_count"], by_name["West"]["total_site_count"]) == (1, 3)
    assert (by_name["Europe"]["site_count"], by_name["Europe"]["total_site_count"]) == (0, 3)
    assert by_name["Europe"]["child_count"] == 1


def test_region_name_unique_among_siblings(admin):
    europe = _region(admin, "Europe")
    _region(admin, "North", europe)
    _region(admin, "North")  # another parent: fine
    assert admin.post(REGIONS, json={"name": " north ", "parent_id": europe}).status_code == 409
    assert admin.post(REGIONS, json={"name": "europe"}).status_code == 409
    assert admin.post(REGIONS, json={"name": "  "}).status_code == 422
    resp = admin.post(REGIONS, json={"name": "Lost", "parent_id": 9999})
    assert resp.status_code == 422 and "parent_id" in resp.text


def test_region_cycle_is_refused(admin):
    a = _region(admin, "A")
    b = _region(admin, "B", a)
    c = _region(admin, "C", b)
    for parent in (a, c):
        resp = admin.put(f"{REGIONS}/{a}", json={"parent_id": parent})
        assert resp.status_code == 422 and "parent_id" in resp.text, resp.text
    moved = _ok(admin.put(f"{REGIONS}/{c}", json={"parent_id": None}))
    assert moved["parent_id"] is None and moved["depth"] == 0
    assert _ok(admin.put(f"{REGIONS}/{b}", json={"name": "B2"}))["parent_id"] == a


def test_region_delete_refused_while_it_holds_regions_or_sites(admin):
    parent = _region(admin, "Parent")
    child = _region(admin, "Child", parent)
    site = _site(admin, "S1", region_id=child)
    assert admin.delete(f"{REGIONS}/{parent}").status_code == 409
    assert admin.delete(f"{REGIONS}/{child}").status_code == 409
    _ok(admin.put(f"{SITES}/{site}", json={"region_id": None}))
    _ok(admin.delete(f"{REGIONS}/{child}"))
    _ok(admin.delete(f"{REGIONS}/{parent}"))
    assert admin.get(f"{REGIONS}/{parent}").status_code == 404


def test_location_tree_with_host_counts(admin):
    europe = _region(admin, "Europe")
    nl = _region(admin, "Netherlands", europe)
    ams = _site(admin, "AMS1", region_id=nl)
    lone = _site(admin, "Lone")
    _ok(admin.post(f"{SITES}/{ams}/floors", json={"name": "Ground", "floor_number": 0}), 201)
    _host(admin, "r1", "192.0.2.1", site_id=ams)
    _host(admin, "r2", "192.0.2.2", site_id=ams)
    _host(admin, "r3", "192.0.2.3", site_id=lone)
    tree = _ok(admin.get(f"{ORG}/locations"))
    [top] = tree["regions"]
    assert top["name"] == "Europe" and top["host_count"] == 2 and top["sites"] == []
    [child] = top["children"]
    assert child["host_count"] == 2
    [site] = child["sites"]
    assert (site["name"], site["host_count"], site["status"]) == ("AMS1", 2, "active")
    assert [f["name"] for f in site["floors"]] == ["Ground"]
    assert [(s["name"], s["host_count"]) for s in tree["unassigned_sites"]] == [("Lone", 1)]


# ── Sites ────────────────────────────────────────────────────────────────────


def test_site_location_and_tenancy_fields(admin):
    rid = _region(admin, "Europe")
    tid = _tenant(admin, "Example Retail")
    site = _ok(
        admin.post(
            SITES,
            json={
                "name": "AMS1",
                "region_id": rid,
                "status": "Planned",
                "facility": " Example DC 1 ",
                "time_zone": "Europe/Amsterdam",
                "tenant_id": tid,
            },
        ),
        201,
    )
    assert (site["region_id"], site["status"], site["facility"], site["time_zone"], site["tenant_id"]) == (
        rid,
        "planned",
        "Example DC 1",
        "Europe/Amsterdam",
        tid,
    )
    bad = admin.post(SITES, json={"name": "X", "status": "closed", "time_zone": "Mars/Base", "region_id": 999})
    assert bad.status_code == 422
    assert all(f in bad.text for f in ("status", "time_zone", "region_id"))
    # A key left out keeps its value; null clears a region or tenant.
    updated = _ok(admin.put(f"{SITES}/{site['id']}", json={"facility": "Example DC 2"}))
    assert (updated["region_id"], updated["tenant_id"], updated["time_zone"]) == (rid, tid, "Europe/Amsterdam")
    cleared = _ok(admin.put(f"{SITES}/{site['id']}", json={"region_id": None, "tenant_id": None}))
    assert (cleared["region_id"], cleared["tenant_id"], cleared["facility"]) == (None, None, "Example DC 2")
    listed = {s["name"]: s for s in _ok(admin.get(f"{ORG}/sites"))["sites"]}
    assert listed["AMS1"]["region_name"] is None


# ── Tenant groups and tenants ────────────────────────────────────────────────


def test_tenant_group_tree_cycle_and_delete(admin):
    top = int(_ok(admin.post(GROUPS, json={"name": "Customers"}), 201)["id"])
    sub = int(_ok(admin.post(GROUPS, json={"name": "Retail", "parent_id": top}), 201)["id"])
    assert admin.post(GROUPS, json={"name": "retail"}).status_code == 409
    assert admin.put(f"{GROUPS}/{top}", json={"parent_id": sub}).status_code == 422
    assert admin.put(f"{GROUPS}/{top}", json={"parent_id": top}).status_code == 422
    tid = _tenant(admin, "Example Retail", group_id=sub)
    groups = _ok(admin.get(GROUPS))["tenant_groups"]
    assert [(g["name"], g["depth"], g["total_tenant_count"]) for g in groups] == [
        ("Customers", 0, 1),
        ("Retail", 1, 1),
    ]
    assert [t["id"] for t in _ok(admin.get(f"{TENANTS}?group_id={top}"))["tenants"]] == [tid]
    assert admin.delete(f"{GROUPS}/{top}").status_code == 409
    assert _ok(admin.delete(f"{GROUPS}/{sub}"))["tenants"] == 1
    assert _ok(admin.get(f"{TENANTS}/{tid}"))["group_id"] is None


def test_tenant_crud_and_contracts(admin):
    tid = _tenant(admin, " Example Retail ", description="Stores")
    tenant = _ok(admin.get(f"{TENANTS}/{tid}"))
    assert (tenant["name"], tenant["description"], tenant["group_id"]) == ("Example Retail", "Stores", None)
    assert admin.post(TENANTS, json={"name": "example retail"}).status_code == 409
    assert admin.post(TENANTS, json={"name": "X", "group_id": 999}).status_code == 422
    other = _tenant(admin, "Example Bank")
    assert admin.put(f"{TENANTS}/{other}", json={"name": "EXAMPLE RETAIL"}).status_code == 409
    assert _ok(admin.put(f"{TENANTS}/{tid}", json={"comments": "note"}))["comments"] == "note"
    assert admin.get(f"{TENANTS}/9999").status_code == 404


def test_tenant_counts_and_assignment(admin):
    tid = _tenant(admin, "Example Retail")
    host = _host(admin, "edge-r1", "192.0.2.10", tenant_id=tid)
    _host(admin, "edge-r2", "192.0.2.11")
    _site(admin, "AMS1", tenant_id=tid)
    prefix = _ok(admin.post("/api/ipam/prefixes", json={"subnet": "198.51.100.0/24", "tenant_id": tid}), 201)["prefix"]
    assert prefix["tenant_id"] == tid
    alloc = _ok(
        admin.post(
            "/api/ipam/subnets/198.51.100.0/24/allocations",
            json={"address": "198.51.100.5", "tenant_id": tid},
        ),
        201,
    )["allocation"]
    vlan = _ok(admin.post("/api/ipam/vlans", json={"vid": 10, "tenant_id": tid}), 201)
    vrf = _ok(admin.post("/api/ipam/vrfs", json={"name": "BLUE", "tenant_id": tid}), 201)
    assert (vlan["tenant_id"], vlan["tenant_name"], vrf["tenant_name"]) == (tid, "Example Retail", "Example Retail")
    counts = _ok(admin.get(f"{TENANTS}/{tid}"))["counts"]
    assert {k: counts[k] for k in ("hosts", "prefixes", "ip_addresses", "vlans", "vrfs", "sites")} == {
        "hosts": 1,
        "prefixes": 1,
        "ip_addresses": 1,
        "vlans": 1,
        "vrfs": 1,
        "sites": 1,
    }
    # Host detail and list carry the tenant.
    listed = {h["hostname"]: h for g in _ok(admin.get("/api/inventory?include_hosts=true")) for h in g["hosts"]}
    assert listed["edge-r1"]["tenant"] == {"id": tid, "name": "Example Retail"}
    assert listed["edge-r2"]["tenant"] is None
    # Subnet detail lists prefix and allocation tenants.
    detail = _ok(admin.get("/api/ipam/subnets/198.51.100.0/24"))
    assert [p["tenant_name"] for p in detail["prefixes"]] == ["Example Retail"]
    [row] = [a for a in detail["allocations"] if a["ip_address"] == "198.51.100.5"]
    assert (row["allocation_id"], row["tenant_name"]) == (alloc["id"], "Example Retail")
    # Clearing and setting again.
    _ok(admin.patch(f"/api/ipam/prefixes/{prefix['id']}", json={"tenant_id": None}))
    _ok(admin.patch(f"/api/ipam/allocations/{alloc['id']}", json={"tenant_id": None}))
    assert admin.patch(f"/api/ipam/prefixes/{prefix['id']}", json={"tenant_id": 999}).status_code == 400
    assert admin.patch("/api/ipam/prefixes/99999", json={"tenant_id": None}).status_code == 404
    assert _ok(admin.put(f"/api/ipam/vlans/{vlan['id']}", json={"name": "users"}))["tenant_id"] == tid
    assert _ok(admin.put(f"/api/ipam/vlans/{vlan['id']}", json={"tenant_id": None}))["tenant_id"] is None
    assert _ok(admin.put(f"/api/ipam/vrfs/{vrf['id']}", json={"tenant_id": None}))["tenant_id"] is None
    assert admin.post("/api/ipam/vlans", json={"vid": 20, "tenant_id": 999}).status_code == 400
    _ok(admin.put(f"/api/hosts/{host}", json={"hostname": "edge-r1", "ip_address": "192.0.2.10", "tenant_id": None}))
    counts = _ok(admin.get(f"{TENANTS}/{tid}"))["counts"]
    assert sum(counts.values()) == 1  # the site
    released = _ok(admin.delete(f"{TENANTS}/{tid}"))["released"]
    assert released["sites"] == 1
    assert _ok(admin.get(f"{SITES}"))[0]["tenant_id"] is None


def test_tenant_counts_discover_new_tables(admin):
    """A table a later migration adds with a tenant_id column is counted."""

    async def make() -> None:
        conn = await db.get_db()
        try:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS org_test_widgets (id SERIAL PRIMARY KEY, "
                "tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL)"
            )
            await conn.commit()
        finally:
            await conn.close()

    async def add(tid: int) -> None:
        conn = await db.get_db()
        try:
            await conn.execute("INSERT INTO org_test_widgets (tenant_id) VALUES (?)", (tid,))
            await conn.commit()
        finally:
            await conn.close()

    asyncio.run(make())
    tid = _tenant(admin, "Example Retail")
    asyncio.run(add(tid))
    assert "org_test_widgets" in asyncio.run(db.tenant_owner_tables())
    assert _ok(admin.get(f"{TENANTS}/{tid}"))["counts"]["org_test_widgets"] == 1


# ── Host filters and dynamic groups ──────────────────────────────────────────


def test_host_filters_by_tenant_and_region_with_descendants(admin):
    europe = _region(admin, "Europe")
    nl = _region(admin, "Netherlands", europe)
    asia = _region(admin, "Asia")
    ams = _site(admin, "AMS1", region_id=nl)
    sin = _site(admin, "SIN1", region_id=asia)
    lone = _site(admin, "Lone")
    tid = _tenant(admin, "Example Retail")
    _host(admin, "ams-r1", "192.0.2.1", site_id=ams, tenant_id=tid)
    _host(admin, "sin-r1", "192.0.2.2", site_id=sin)
    _host(admin, "lone-r1", "192.0.2.3", site_id=lone)
    _host(admin, "nosite-r1", "192.0.2.4")
    assert _listed_hosts(admin, f"region_id={europe}") == {"ams-r1"}
    assert _listed_hosts(admin, f"region_id={nl}") == {"ams-r1"}
    assert _listed_hosts(admin, f"region_id={europe}&region_id={asia}") == {"ams-r1", "sin-r1"}
    mine = {"ams-r1", "sin-r1", "lone-r1", "nosite-r1"}  # the database may hold seeded hosts too
    assert _listed_hosts(admin, "region_id=none") & mine == {"lone-r1", "nosite-r1"}
    assert _listed_hosts(admin, f"tenant_id={tid}") == {"ams-r1"}
    assert _listed_hosts(admin, "tenant_id=none") & mine == {"sin-r1", "lone-r1", "nosite-r1"}
    assert admin.get("/api/inventory?include_hosts=true&region_id=abc").status_code == 400
    listed = {h["hostname"]: h for g in _ok(admin.get("/api/inventory?include_hosts=true")) for h in g["hosts"]}
    assert listed["ams-r1"]["region_ids"] == [nl, europe]
    assert listed["nosite-r1"]["region_ids"] == []

    async def resolve(raw: dict) -> set[str]:
        clean = await validate_filter(raw, UNRESTRICTED)
        return {h["hostname"] for h in await resolve_hosts(clean, UNRESTRICTED)}

    assert asyncio.run(resolve({"region_id": [europe]})) == {"ams-r1"}
    assert asyncio.run(resolve({"tenant_id": [tid]})) == {"ams-r1"}
    assert asyncio.run(resolve({"region_id": [None]})) & mine == {"lone-r1", "nosite-r1"}


def test_bulk_edit_sets_tenant(admin):
    tid = _tenant(admin, "Example Retail")
    a = _host(admin, "r1", "192.0.2.1")
    b = _host(admin, "r2", "192.0.2.2")
    _ok(admin.post("/api/hosts/bulk-edit", json={"host_ids": [a, b], "set": {"tenant_id": tid}}))
    assert _ok(admin.get(f"{TENANTS}/{tid}"))["counts"]["hosts"] == 2


# ── Change log ───────────────────────────────────────────────────────────────


def test_change_log_records_organization_objects(admin):
    rid = _region(admin, "Europe")
    _ok(admin.put(f"{REGIONS}/{rid}", json={"description": "EU"}))
    gid = int(_ok(admin.post(GROUPS, json={"name": "Customers"}), 201)["id"])
    tid = _tenant(admin, "Example Retail", group_id=gid)
    site = _site(admin, "AMS1", region_id=rid)
    _ok(admin.put(f"{SITES}/{site}", json={"status": "retired"}))
    _ok(admin.delete(f"{TENANTS}/{tid}"))

    def actions(object_type: str, object_id: int) -> list[str]:
        rows = _ok(admin.get(f"/api/changes/{object_type}/{object_id}"))["changes"]
        return sorted(r["action"] for r in rows)

    assert actions("region", rid) == ["create", "update"]
    assert actions("tenant_group", gid) == ["create"]
    assert actions("tenant", tid) == ["create", "delete"]
    assert actions("site", site) == ["create", "update"]
    [update] = [r for r in _ok(admin.get(f"/api/changes/site/{site}"))["changes"] if r["action"] == "update"]
    assert update["changes"]["status"] == {"before": "active", "after": "retired"}
    assert update["object_label"] == "AMS1"
    reader = user_client(admin, "org-reader", features=["organization"])
    assert reader.get(f"/api/changes/region/{rid}").status_code == 200
    assert reader.get(f"/api/changes/host/{rid}").status_code == 403
