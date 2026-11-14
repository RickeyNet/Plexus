"""VRF and VLAN API (``netcontrol.routes.network_objects``): access per route,
the records, the 400 / 409 / 422 contracts, audit events, a host's interface
addresses, the two extended IPAM answers, ``store_device_config`` filling
the bindings, the rebuild and the one-off backfill."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.network_objects as network_objects
import pytest
import routes.database as db
from netcontrol.routes.device_config import store_device_config
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

VRFS = "/api/ipam/vrfs"
VLANS = "/api/ipam/vlans"
REBUILD = "/api/ipam/interface-addresses/rebuild"

IOS = """hostname edge-r1
interface Vlan10
 vrf forwarding BLUE
 ip address 192.0.2.2 255.255.255.0
 standby 1 ip 192.0.2.1
!
interface GigabitEthernet0/1
 ip address 203.0.113.1 255.255.255.252
!
"""


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _host(admin: CsrfClient, name: str = "edge-r1", ip: str = "192.0.2.10", **extra) -> int:
    gid = int(_ok(admin.post("/api/inventory", json={"name": f"group-{name}"}), 201)["id"])
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios", **extra}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


def _store(host_id: int, text: str = IOS, device_type: str | None = None) -> None:
    asyncio.run(store_device_config(host_id, text, "", capture_method="topology", device_type=device_type))


# ── Access ───────────────────────────────────────────────────────────────────


def test_anonymous_is_rejected(admin):
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    for path in (VRFS, f"{VRFS}/1", VLANS, f"{VLANS}/1", "/api/hosts/1/interface-addresses"):
        assert anon.get(path).status_code == 401, path
    for path in (VRFS, VLANS, REBUILD):
        assert anon.post(path, json={}).status_code in (401, 403), path


def test_reads_need_ipam_and_writes_need_admin(admin):
    vrf = _ok(admin.post(VRFS, json={"name": "BLUE"}), 201)
    vlan = _ok(admin.post(VLANS, json={"vid": 10}), 201)
    plain = user_client(admin, "plain-user")
    for path in (VRFS, f"{VRFS}/{vrf['id']}", VLANS, f"{VLANS}/{vlan['id']}"):
        assert plain.get(path).status_code == 403, path
    reader = user_client(admin, "ipam-user", features=["ipam"])
    for path in (VRFS, f"{VRFS}/{vrf['id']}", VLANS, f"{VLANS}/{vlan['id']}"):
        assert reader.get(path).status_code == 200, path
    writes = (
        reader.post(VRFS, json={"name": "RED"}),
        reader.put(f"{VRFS}/{vrf['id']}", json={"rd": "1:1"}),
        reader.delete(f"{VRFS}/{vrf['id']}"),
        reader.post(VLANS, json={"vid": 20}),
        reader.put(f"{VLANS}/{vlan['id']}", json={"name": "x"}),
        reader.delete(f"{VLANS}/{vlan['id']}"),
        reader.post(REBUILD),
    )
    assert [r.status_code for r in writes] == [403] * len(writes)


def test_host_addresses_are_gated_like_interface_inventory(admin):
    host = _host(admin)
    assert (
        user_client(admin, "ipam-only", features=["ipam"]).get(f"/api/hosts/{host}/interface-addresses").status_code
        == 403
    )
    reports = user_client(admin, "reports-user", features=["reports"])
    assert reports.get(f"/api/hosts/{host}/interface-inventory").status_code == 200
    assert _ok(reports.get(f"/api/hosts/{host}/interface-addresses")) == {"host_id": host, "addresses": [], "vrfs": []}


def test_new_paths_resolve_to_their_handlers(admin):
    """Each path answers from this module's handler (the IPAM router's greedy
    ``/api/ipam/subnets/{subnet:path}`` and its other routes never take them)."""
    assert _ok(admin.get(VRFS)) == {"vrfs": []}
    assert _ok(admin.get(VLANS)) == {"vlans": []}
    for what, base in (("VRF", VRFS), ("VLAN", VLANS)):
        for resp in (admin.get(f"{base}/3"), admin.put(f"{base}/3", json={}), admin.delete(f"{base}/3")):
            assert resp.status_code == 404 and resp.json()["error"]["message"] == f"{what} not found"
    assert _ok(admin.post(REBUILD)) == {"ok": True, "hosts": 0, "addresses": 0}
    assert _ok(admin.get("/api/hosts/3/interface-addresses")) == {"host_id": 3, "addresses": [], "vrfs": []}


# ── VRFs ─────────────────────────────────────────────────────────────────────


def test_vrf_crud_and_contracts(admin):
    vrf = _ok(admin.post(VRFS, json={"name": " BLUE ", "rd": " 65000:10 ", "description": "tenant"}), 201)
    assert {k: vrf[k] for k in ("name", "rd", "description", "origin", "host_count", "prefix_count")} == {
        "name": "BLUE",
        "rd": "65000:10",
        "description": "tenant",
        "origin": "manual",
        "host_count": 0,
        "prefix_count": 0,
    }
    resp = admin.post(VRFS, json={"name": "blue"})
    assert resp.status_code == 409 and "already exists" in resp.json()["error"]["message"]
    for bad in ({}, {"name": " "}, {"name": "x" * 65}, {"name": "x" * 201}, {"name": "A", "rd": "1" * 65}):
        assert admin.post(VRFS, json=bad).status_code == 422, bad
    assert admin.put(f"{VRFS}/{vrf['id']}", json={"name": "RED"}).status_code == 422
    assert admin.put(f"{VRFS}/{vrf['id']}", json={"description": "d" * 501}).status_code == 422
    updated = _ok(admin.put(f"{VRFS}/{vrf['id']}", json={"rd": "65000:11"}))
    assert (updated["name"], updated["rd"], updated["description"]) == ("BLUE", "65000:11", "tenant")
    assert _ok(admin.put(f"{VRFS}/{vrf['id']}", json={"description": ""}))["rd"] == "65000:11"
    assert admin.put(f"{VRFS}/999999", json={}).status_code == 404
    assert admin.get(f"{VRFS}/999999").status_code == 404
    assert admin.delete(f"{VRFS}/999999").status_code == 404
    detail = _ok(admin.get(f"{VRFS}/{vrf['id']}"))
    assert detail["devices"] == [] and detail["interfaces"] == [] and detail["prefixes"] == []
    assert detail["truncated"] is False
    assert [v["name"] for v in _ok(admin.get(VRFS))["vrfs"]] == ["BLUE"]
    assert _ok(admin.delete(f"{VRFS}/{vrf['id']}")) == {"ok": True}
    assert _ok(admin.get(VRFS)) == {"vrfs": []}


def test_vrf_delete_refused_while_in_use(admin):
    host = _host(admin, vrf_name="MGMT")
    vrf = next(v for v in _ok(admin.get(VRFS))["vrfs"] if v["name"] == "MGMT")
    assert vrf["host_count"] == 1 and vrf["origin"] == "manual"
    resp = admin.delete(f"{VRFS}/{vrf['id']}")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["affected"] == 1 and "1 hosts" in detail["message"] and "MGMT" in detail["message"]
    admin.put(f"/api/hosts/{host}", json={"hostname": "edge-r1", "ip_address": "192.0.2.10", "vrf_name": ""})
    assert _ok(admin.delete(f"{VRFS}/{vrf['id']}")) == {"ok": True}


# ── VLANs ────────────────────────────────────────────────────────────────────


def test_vlan_crud_and_contracts(admin):
    site = asyncio.run(db.create_geo_site(name="Site A"))
    other = asyncio.run(db.create_geo_site(name="Site B"))
    vlan = _ok(admin.post(VLANS, json={"vid": 10, "name": " users ", "site_id": site["id"]}), 201)
    assert (vlan["vid"], vlan["name"], vlan["site"], vlan["name_mismatch"]) == (
        10,
        "users",
        {"id": site["id"], "name": "Site A"},
        False,
    )
    missing = admin.post(VLANS, json={"vid": 11, "site_id": 999999})
    assert missing.status_code == 400 and set(missing.json()["detail"]["fields"]) == {"site_id"}
    assert admin.post(VLANS, json={"vid": 10, "site_id": site["id"]}).status_code == 409
    for bad in ({}, {"vid": 0}, {"vid": 4095}, {"vid": "x"}, {"vid": 5, "name": "n" * 65}):
        assert admin.post(VLANS, json=bad).status_code == 422, bad
    glob = _ok(admin.post(VLANS, json={"vid": 10}), 201)
    blocked = _ok(admin.post(VLANS, json={"vid": 10, "site_id": other["id"]}), 201)
    assert admin.put(f"{VLANS}/{glob['id']}", json={"vid": 11}).status_code == 422
    assert admin.put(f"{VLANS}/{blocked['id']}", json={"site_id": site["id"]}).status_code == 409
    assert admin.put(f"{VLANS}/{blocked['id']}", json={"site_id": 999999}).status_code == 400
    assert admin.put(f"{VLANS}/{blocked['id']}", json={"site_id": None}).status_code == 409
    renamed = _ok(admin.put(f"{VLANS}/{vlan['id']}", json={"name": "staff", "description": "floor 1"}))
    assert (renamed["name"], renamed["site_id"], renamed["description"]) == ("staff", site["id"], "floor 1")
    assert admin.put(f"{VLANS}/999999", json={}).status_code == 404
    assert admin.get(f"{VLANS}/999999").status_code == 404
    assert admin.delete(f"{VLANS}/999999").status_code == 404
    assert [v["id"] for v in _ok(admin.get(f"{VLANS}?site_id=none"))["vlans"]] == [glob["id"]]
    assert [v["id"] for v in _ok(admin.get(f"{VLANS}?site_id={site['id']}"))["vlans"]] == [vlan["id"]]
    assert len(_ok(admin.get(f"{VLANS}?vid=10"))["vlans"]) == 3
    assert _ok(admin.get(f"{VLANS}?vid=11")) == {"vlans": []}
    bad = admin.get(f"{VLANS}?site_id=abc")
    assert bad.status_code == 400 and "site_id" in bad.json()["detail"]["fields"]
    detail = _ok(admin.get(f"{VLANS}/{vlan['id']}"))
    assert detail["devices"] == [] and detail["interfaces"] == [] and detail["prefixes"] == []
    assert detail["truncated"] is False
    assert _ok(admin.delete(f"{VLANS}/{glob['id']}")) == {"ok": True}


def test_writes_are_audited(admin):
    vrf = _ok(admin.post(VRFS, json={"name": "BLUE"}), 201)
    admin.put(f"{VRFS}/{vrf['id']}", json={"rd": "1:1"})
    admin.delete(f"{VRFS}/{vrf['id']}")
    vlan = _ok(admin.post(VLANS, json={"vid": 10}), 201)
    admin.put(f"{VLANS}/{vlan['id']}", json={"name": "users"})
    admin.delete(f"{VLANS}/{vlan['id']}")
    admin.post(REBUILD)
    events = asyncio.run(db.get_audit_events(limit=50, category="network_objects"))
    assert {e["action"] for e in events} == {
        "vrf_create",
        "vrf_update",
        "vrf_delete",
        "vlan_create",
        "vlan_update",
        "vlan_delete",
        "interface_addresses_rebuild",
    }
    assert all(e["user"] == "admin" for e in events)


# ── Interface addresses ──────────────────────────────────────────────────────


def test_store_device_config_fills_bindings_and_ipam_answers(admin):
    host = _host(admin)
    _store(host)
    found = _ok(admin.get(f"/api/hosts/{host}/interface-addresses"))
    assert [(a["interface"], a["address"], a["role"]) for a in found["addresses"]] == [
        ("GigabitEthernet0/1", "203.0.113.1", "primary"),
        ("Vlan10", "192.0.2.2", "primary"),
        ("Vlan10", "192.0.2.1", "virtual"),
    ]
    blue = next(v for v in _ok(admin.get(VRFS))["vrfs"] if v["name"] == "BLUE")
    assert blue["origin"] == "discovered" and blue["address_count"] == 2 and blue["device_count"] == 1
    assert found["vrfs"] == [{"name": "BLUE", "vrf_id": blue["id"], "interface_count": 1}]
    assert found["addresses"][1]["vrf_id"] == blue["id"] and found["addresses"][1]["vlan_id"] is None

    address = _ok(admin.get("/api/ipam/address/192.0.2.2"))
    assert [(i["hostname"], i["interface"]) for i in address["interfaces"]] == [("edge-r1", "Vlan10")]
    assert _ok(admin.get("/api/ipam/address/192.0.2.2?vrf=BLUE"))["interfaces"][0]["vrf_name"] == "BLUE"
    assert _ok(admin.get("/api/ipam/address/192.0.2.2?vrf=RED"))["interfaces"] == []
    # Every VRF when no vrf is given; only that VRF when it is.
    subnet = _ok(admin.get("/api/ipam/subnets/192.0.2.0/24"))
    assert [i["address"] for i in subnet["interfaces"]] == ["192.0.2.2", "192.0.2.1"]
    assert len(_ok(admin.get("/api/ipam/subnets/192.0.2.0/24?vrf=BLUE"))["interfaces"]) == 2
    assert _ok(admin.get("/api/ipam/subnets/192.0.2.0/24?vrf=RED"))["interfaces"] == []

    # A configuration of a platform that is not read leaves the rows alone.
    _store(host, "set deviceconfig system hostname fw1", device_type="paloalto_panos")
    assert len(_ok(admin.get(f"/api/hosts/{host}/interface-addresses"))["addresses"]) == 3
    # Without a device type the host's own (cisco_ios) is used.
    _store(host, "interface GigabitEthernet0/2\n ip address 198.51.100.1 255.255.255.0\n")
    assert [a["address"] for a in _ok(admin.get(f"/api/hosts/{host}/interface-addresses"))["addresses"]] == [
        "198.51.100.1"
    ]


def test_sync_is_best_effort(admin, monkeypatch):
    host = _host(admin)
    _store(host)

    class _Broken:
        @staticmethod
        def config(_text):
            raise RuntimeError("parser tripped")

    monkeypatch.setattr(network_objects, "platform_of", lambda _type: _Broken)
    assert asyncio.run(network_objects.sync_host_bindings(host, "cisco_ios", "x")) is None
    # The capture itself still succeeds and the stored rows stay.
    asyncio.run(store_device_config(host, "hostname changed", "", capture_method="topology"))
    assert len(_ok(admin.get(f"/api/hosts/{host}/interface-addresses"))["addresses"]) == 3
    assert asyncio.run(network_objects.sync_host_bindings(999999, None, IOS)) is None


def test_rebuild_and_one_off_backfill(admin):
    h1 = _host(admin)
    h2 = _host(admin, "edge-r2", "192.0.2.11")
    _host(admin, "no-config", "192.0.2.12")
    for host in (h1, h2):
        asyncio.run(
            db.create_config_backup(
                policy_id=None,
                host_id=host,
                config_text=IOS,
                config_text_full="",
                capture_method="scheduled",
                status="success",
                error_message="",
            )
        )
    assert _ok(admin.post(REBUILD)) == {"ok": True, "hosts": 2, "addresses": 6}
    asyncio.run(db.replace_host_bindings(h1, [], {}))
    first = asyncio.run(network_objects.backfill_interface_addresses())
    assert first == {"hosts": 2, "addresses": 6}
    assert asyncio.run(network_objects.backfill_interface_addresses()) is None
    assert asyncio.run(db.get_auth_setting(network_objects.BACKFILL_SETTING))["done"] is True


# ── Host values the dialog edits ─────────────────────────────────────────────


def test_host_vrf_and_vlan_are_listed_and_updated_independently(admin):
    host = _host(admin, vrf_name="BLUE", vlan_id="10")
    base = {"hostname": "edge-r1", "ip_address": "192.0.2.10"}
    _ok(admin.put(f"/api/hosts/{host}", json={**base, "vrf_name": "RED"}))
    row = asyncio.run(db.get_host(host))
    assert (row["vrf_name"], row["vlan_id"]) == ("RED", "10")
    _ok(admin.put(f"/api/hosts/{host}", json={**base, "vlan_id": "20"}))
    groups = _ok(admin.get("/api/inventory?include_hosts=true"))
    listed = next(h for g in groups for h in g.get("hosts", []) if h["id"] == host)
    assert (listed["vrf_name"], listed["vlan_id"]) == ("RED", "20")
