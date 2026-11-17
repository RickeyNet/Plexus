"""Circuits (``netcontrol.routes.circuits``, ``routes.db.circuits``,
``netcontrol.circuits``): providers, provider networks, circuit types and
circuits with their A / Z terminations; access, uniqueness, the site-xor-
provider-network rule, 409 on deleting a record in use, filters, the device
view with utilisation, change log entries, audit and the billing link."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import pytest
import routes.database as db
from netcontrol.circuits import FieldErrors, clean_date, clean_kbps, clean_status, clean_term_side, clean_url
from netcontrol.custom_fields import CustomFieldError
from netcontrol.routes import state
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

BASE = "/api/circuits"
PROVIDERS = f"{BASE}/providers"
NETWORKS = f"{BASE}/provider-networks"
TYPES = f"{BASE}/circuit-types"
CIRCUITS = f"{BASE}/circuits"


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _fields(resp) -> dict:
    assert resp.status_code == 422, resp.text
    return resp.json()["detail"]["fields"]


def _host(admin: CsrfClient, name: str = "edge-r1", ip: str = "192.0.2.10") -> int:
    gid = int(_ok(admin.post("/api/inventory", json={"name": f"group-{name}"}), 201)["id"])
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios"}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


def _site(name: str = "Site One") -> int:
    async def make() -> int:
        conn = await db.get_db()
        try:
            cursor = await conn.execute("INSERT INTO geo_sites (name) VALUES (?) RETURNING id", (name,))
            new_id = int(cursor.lastrowid)
            await conn.commit()
            return new_id
        finally:
            await conn.close()

    return asyncio.run(make())


def _tenant(name: str = "Tenant One") -> int:
    async def make() -> int:
        conn = await db.get_db()
        try:
            cursor = await conn.execute("INSERT INTO tenants (name) VALUES (?) RETURNING id", (name,))
            new_id = int(cursor.lastrowid)
            await conn.commit()
            return new_id
        finally:
            await conn.close()

    return asyncio.run(make())


def _base(admin: CsrfClient) -> tuple[int, int]:
    provider = _ok(admin.post(PROVIDERS, json={"name": "Example Carrier"}), 201)
    ctype = _ok(admin.post(TYPES, json={"name": "Internet"}), 201)
    return int(provider["id"]), int(ctype["id"])


def _circuit(admin: CsrfClient, provider: int, ctype: int, cid: str = "CKT-1001", **extra) -> dict:
    return _ok(admin.post(CIRCUITS, json={"cid": cid, "provider_id": provider, "circuit_type_id": ctype, **extra}), 201)


# ── Rules ────────────────────────────────────────────────────────────────────


def test_rules():
    assert clean_date(" 2026-02-28 ", "D") == "2026-02-28"
    assert clean_date("", "D") == ""
    for bad in ("2026-2-28", "2026-02-30", "yesterday"):
        with pytest.raises(CustomFieldError):
            clean_date(bad, "D")
    assert clean_url("https://portal.example.com/x") == "https://portal.example.com/x"
    assert clean_url("") == ""
    with pytest.raises(CustomFieldError):
        clean_url("ftp://example.com")
    assert clean_kbps(None, "R") is None and clean_kbps("", "R") is None and clean_kbps(1000, "R") == 1000
    for bad in (-1, True, "10", 10**12):
        with pytest.raises(CustomFieldError):
            clean_kbps(bad, "R")
    assert clean_status(" Active ") == "active"
    with pytest.raises(CustomFieldError):
        clean_status("gone")
    assert clean_term_side("z") == "Z"
    with pytest.raises(CustomFieldError):
        clean_term_side("B")
    errors = FieldErrors()
    assert not errors and errors.message() == "Check the fields and try again."
    errors.add("a", "first")
    errors.add("a", "second")
    assert errors and errors.fields == {"a": "first"}


# ── Access ───────────────────────────────────────────────────────────────────


def test_anonymous_is_rejected(admin):
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    for path in (PROVIDERS, NETWORKS, TYPES, CIRCUITS, f"{BASE}/hosts/1/circuits"):
        assert anon.get(path).status_code == 401, path


def test_reads_need_circuits_and_writes_need_circuits_write(admin):
    provider, ctype = _base(admin)
    plain = user_client(admin, "plain-user")
    assert plain.get(CIRCUITS).status_code == 403
    reader = user_client(admin, "circuit-reader", features=["circuits"])
    for path in (PROVIDERS, NETWORKS, TYPES, CIRCUITS, f"{PROVIDERS}/{provider}"):
        assert reader.get(path).status_code == 200, path
    assert reader.post(TYPES, json={"name": "MPLS"}).status_code == 403
    writer = user_client(admin, "circuit-writer", features=["circuits", "circuits.write"])
    assert writer.post(TYPES, json={"name": "MPLS"}).status_code == 201
    assert "circuits" in state.FEATURE_FLAGS and "circuits.write" in state.FEATURE_FLAGS


# ── Providers, networks, types ───────────────────────────────────────────────


def test_provider_crud_uniqueness_and_validation(admin):
    provider = _ok(
        admin.post(
            PROVIDERS,
            json={"name": " Example Carrier ", "account": "ACC-1", "portal_url": "https://portal.example.com"},
        ),
        201,
    )
    assert provider["name"] == "Example Carrier" and provider["circuit_count"] == 0
    assert provider["created_by"] == "admin" and provider["created_at"]
    assert admin.post(PROVIDERS, json={"name": "example carrier"}).status_code == 409
    fields = _fields(admin.post(PROVIDERS, json={"name": "", "portal_url": "portal"}))
    assert set(fields) == {"name", "portal_url"}
    updated = _ok(admin.put(f"{PROVIDERS}/{provider['id']}", json={"noc_contact": "noc@example.com"}))
    assert updated["noc_contact"] == "noc@example.com" and updated["account"] == "ACC-1"
    other = _ok(admin.post(PROVIDERS, json={"name": "Second Carrier"}), 201)
    assert admin.put(f"{PROVIDERS}/{other['id']}", json={"name": "EXAMPLE CARRIER"}).status_code == 409
    assert admin.put(f"{PROVIDERS}/9999", json={}).status_code == 404
    assert [p["name"] for p in _ok(admin.get(PROVIDERS))["providers"]] == ["Example Carrier", "Second Carrier"]
    assert _ok(admin.delete(f"{PROVIDERS}/{other['id']}")) == {"ok": True}
    assert admin.delete(f"{PROVIDERS}/{other['id']}").status_code == 404


def test_provider_networks(admin):
    provider, ctype = _base(admin)
    other = _ok(admin.post(PROVIDERS, json={"name": "Other Carrier"}), 201)["id"]
    net = _ok(admin.post(NETWORKS, json={"provider_id": provider, "name": "MPLS Cloud"}), 201)
    assert net["provider_name"] == "Example Carrier" and net["termination_count"] == 0
    assert admin.post(NETWORKS, json={"provider_id": provider, "name": "mpls cloud"}).status_code == 409
    # The same name under another provider is fine.
    _ok(admin.post(NETWORKS, json={"provider_id": other, "name": "MPLS Cloud"}), 201)
    assert _fields(admin.post(NETWORKS, json={"name": "x"})) == {"provider_id": "Choose a provider."}
    assert "provider_id" in _fields(admin.post(NETWORKS, json={"provider_id": 9999, "name": "x"}))
    assert "provider_id" in _fields(admin.put(f"{NETWORKS}/{net['id']}", json={"provider_id": other}))
    assert _ok(admin.put(f"{NETWORKS}/{net['id']}", json={"description": "core"}))["description"] == "core"
    assert len(_ok(admin.get(NETWORKS, params={"provider_id": provider}))["provider_networks"]) == 1
    detail = _ok(admin.get(f"{PROVIDERS}/{provider}"))
    assert [n["name"] for n in detail["networks"]] == ["MPLS Cloud"] and detail["network_count"] == 1
    # A network in use by a termination cannot be deleted, nor can its provider.
    other_type = ctype
    circuit = _circuit(
        admin, int(other), other_type, terminations=[{"term_side": "Z", "provider_network_id": net["id"]}]
    )
    resp = admin.delete(f"{NETWORKS}/{net['id']}")
    assert resp.status_code == 409 and resp.json()["detail"]["usage"] == {"terminations": 1}
    resp = admin.delete(f"{PROVIDERS}/{provider}")
    assert resp.status_code == 409 and resp.json()["detail"]["usage"] == {"circuits": 0, "terminations": 1}
    _ok(admin.delete(f"{CIRCUITS}/{circuit['id']}"))
    _ok(admin.delete(f"{NETWORKS}/{net['id']}"))
    assert admin.get(f"{NETWORKS}/{net['id']}").status_code == 404


def test_circuit_types_and_in_use_delete(admin):
    provider, ctype = _base(admin)
    assert admin.post(TYPES, json={"name": "INTERNET"}).status_code == 409
    assert _fields(admin.post(TYPES, json={"name": " "})) == {"name": "Name must not be empty."}
    assert _ok(admin.put(f"{TYPES}/{ctype}", json={"description": "DIA"}))["description"] == "DIA"
    _circuit(admin, provider, ctype)
    assert _ok(admin.get(f"{TYPES}/{ctype}"))["circuit_count"] == 1
    resp = admin.delete(f"{TYPES}/{ctype}")
    assert resp.status_code == 409 and resp.json()["detail"]["usage"] == {"circuits": 1}
    resp = admin.delete(f"{PROVIDERS}/{provider}")
    assert resp.status_code == 409 and resp.json()["detail"]["affected"] == 1
    spare = _ok(admin.post(TYPES, json={"name": "Spare"}), 201)
    _ok(admin.delete(f"{TYPES}/{spare['id']}"))
    assert admin.get(f"{TYPES}/{spare['id']}").status_code == 404


def test_db_delete_in_use_raises():
    """The facade turns a foreign key refusal into ``CircuitInUseError``."""

    async def run() -> None:
        provider = await db.create_circuit_provider({"name": "Example Carrier"})
        ctype = await db.create_circuit_type({"name": "Internet"})
        await db.create_circuit({"cid": "C1", "provider_id": provider["id"], "circuit_type_id": ctype["id"]})
        with pytest.raises(db.CircuitInUseError):
            await db.delete_circuit_type(ctype["id"])
        assert await db.circuit_missing_refs({"provider_id": provider["id"], "host_id": 9999, "x": 1}) == ["host_id"]

    asyncio.run(run())


# ── Circuits and terminations ────────────────────────────────────────────────


def test_circuit_crud_with_terminations(admin):
    provider, ctype = _base(admin)
    site = _site()
    host = _host(admin)
    net = _ok(admin.post(NETWORKS, json={"provider_id": provider, "name": "Backbone"}), 201)["id"]
    tenant = _tenant()
    circuit = _circuit(
        admin,
        provider,
        ctype,
        status="planned",
        tenant_id=tenant,
        install_date="2026-01-15",
        commit_rate_kbps=100_000,
        terminations=[
            {"term_side": "a", "site_id": site, "host_id": host, "interface_name": "Gi0/1", "xconnect_id": "XC-9"},
            {"term_side": "Z", "provider_network_id": net, "port_speed_kbps": 1_000_000},
        ],
    )
    assert circuit["status"] == "planned" and circuit["tenant_name"] == "Tenant One"
    assert circuit["provider_name"] == "Example Carrier" and circuit["circuit_type_name"] == "Internet"
    a, z = circuit["terminations"]
    assert (a["term_side"], a["site_name"], a["hostname"], a["interface_name"]) == ("A", "Site One", "edge-r1", "Gi0/1")
    assert (z["term_side"], z["provider_network_name"], z["port_speed_kbps"]) == ("Z", "Backbone", 1_000_000)
    detail = _ok(admin.get(f"{CIRCUITS}/{circuit['id']}"))
    assert detail["utilisation"] == []

    # The same cid under the same provider (ignoring case) is a 409.
    resp = admin.post(CIRCUITS, json={"cid": "ckt-1001", "provider_id": provider, "circuit_type_id": ctype})
    assert resp.status_code == 409

    # A PUT without terminations keeps them; with a list, replaces them.
    updated = _ok(admin.put(f"{CIRCUITS}/{circuit['id']}", json={"status": "active", "description": "Main uplink"}))
    assert updated["status"] == "active" and len(updated["terminations"]) == 2
    updated = _ok(
        admin.put(
            f"{CIRCUITS}/{circuit['id']}",
            json={"terminations": [{"term_side": "A", "site_id": site, "description": "rack 4"}]},
        )
    )
    assert [(t["term_side"], t["description"], t["host_id"]) for t in updated["terminations"]] == [
        ("A", "rack 4", None)
    ]
    assert updated["terminations"][0]["id"] == a["id"]

    # Termination endpoints.
    term = _ok(admin.put(f"{CIRCUITS}/{circuit['id']}/terminations/z", json={"provider_network_id": net}))
    assert term["term_side"] == "Z"
    term = _ok(admin.put(f"{CIRCUITS}/{circuit['id']}/terminations/Z", json={"pp_info": "PP1/3"}))
    assert term["pp_info"] == "PP1/3" and term["provider_network_id"] == net
    assert _fields(admin.put(f"{CIRCUITS}/{circuit['id']}/terminations/B", json={})) == {
        "term_side": "Termination side must be A or Z."
    }
    assert admin.put(f"{CIRCUITS}/9999/terminations/A", json={"site_id": site}).status_code == 404
    _ok(admin.delete(f"{CIRCUITS}/{circuit['id']}/terminations/Z"))
    assert admin.delete(f"{CIRCUITS}/{circuit['id']}/terminations/Z").status_code == 404

    _ok(admin.delete(f"{CIRCUITS}/{circuit['id']}"))
    assert admin.get(f"{CIRCUITS}/{circuit['id']}").status_code == 404
    assert admin.delete(f"{CIRCUITS}/{circuit['id']}").status_code == 404


def test_circuit_validation(admin):
    provider, ctype = _base(admin)
    site = _site()
    net = _ok(admin.post(NETWORKS, json={"provider_id": provider, "name": "Backbone"}), 201)["id"]
    fields = _fields(admin.post(CIRCUITS, json={"cid": ""}))
    assert set(fields) == {"cid", "provider_id", "circuit_type_id"}
    fields = _fields(
        admin.post(
            CIRCUITS,
            json={
                "cid": "C-2",
                "provider_id": 9999,
                "circuit_type_id": ctype,
                "status": "lost",
                "tenant_id": 9999,
                "billing_circuit_id": 9999,
                "install_date": "2026-03-01",
                "termination_date": "2026-02-01",
                "commit_rate_kbps": -5,
            },
        )
    )
    assert set(fields) == {
        "provider_id",
        "status",
        "tenant_id",
        "billing_circuit_id",
        "termination_date",
        "commit_rate_kbps",
    }
    assert _fields(
        admin.post(
            CIRCUITS, json={"cid": "C", "provider_id": provider, "circuit_type_id": ctype, "install_date": "2026-13-01"}
        )
    ) == {"install_date": "Install date is not a real date."}


def test_term_side_and_site_xor_network_rules(admin):
    provider, ctype = _base(admin)
    site = _site()
    net = _ok(admin.post(NETWORKS, json={"provider_id": provider, "name": "Backbone"}), 201)["id"]

    def post(terms):
        return admin.post(
            CIRCUITS, json={"cid": "C-9", "provider_id": provider, "circuit_type_id": ctype, "terminations": terms}
        )

    assert "terminations.A.term_side" in _fields(post([{"term_side": "A", "site_id": site}] * 2))
    assert _fields(post([{"term_side": "A"}])) == {
        "terminations.A.site_id": "Choose a site or a provider network for the termination."
    }
    assert _fields(post([{"term_side": "A", "site_id": site, "provider_network_id": net}])) == {
        "terminations.A.site_id": "Choose a site or a provider network, not both."
    }
    assert _fields(post([{"term_side": "Z", "site_id": site, "interface_name": "Gi0/1"}])) == {
        "terminations.Z.interface_name": "Choose the device the interface belongs to."
    }
    assert _fields(post([{"term_side": "Z", "site_id": site, "host_id": 9999}])) == {
        "terminations.Z.host_id": "The device does not exist."
    }
    assert "terminations.0.term_side" in _fields(post([{"term_side": "Q", "site_id": site}]))
    assert "terminations.A.port_speed_kbps" in _fields(
        post([{"term_side": "A", "site_id": site, "port_speed_kbps": -1}])
    )
    # Nothing was written by the refused requests.
    assert _ok(admin.get(CIRCUITS))["circuits"] == []

    # The database enforces both rules too.
    circuit = _circuit(admin, provider, ctype, terminations=[{"term_side": "A", "site_id": site}])

    async def clash() -> None:
        with pytest.raises(ValueError, match="A side already has a termination"):
            await db.create_circuit_termination(circuit["id"], "A", {"site_id": site})
        with pytest.raises(Exception):  # noqa: B017 - the CHECK constraint
            await db.create_circuit_termination(circuit["id"], "Z", {"site_id": site, "provider_network_id": net})

    asyncio.run(clash())


def test_filters(admin):
    provider, ctype = _base(admin)
    other_provider = _ok(admin.post(PROVIDERS, json={"name": "Other Carrier"}), 201)["id"]
    mpls = _ok(admin.post(TYPES, json={"name": "MPLS"}), 201)["id"]
    site_a, site_b = _site("Site A"), _site("Site B")
    host = _host(admin)
    tenant = _tenant()
    _circuit(
        admin,
        provider,
        ctype,
        "INET-1",
        description="Head office internet",
        terminations=[{"term_side": "A", "site_id": site_a, "host_id": host, "interface_name": "Gi0/0"}],
    )
    _circuit(
        admin,
        other_provider,
        mpls,
        "MPLS-7",
        status="offline",
        tenant_id=tenant,
        terminations=[{"term_side": "A", "site_id": site_b}],
    )

    def cids(**params) -> list[str]:
        return [c["cid"] for c in _ok(admin.get(CIRCUITS, params=params))["circuits"]]

    assert cids() == ["INET-1", "MPLS-7"]
    assert cids(provider_id=provider) == ["INET-1"]
    assert cids(circuit_type_id=mpls) == ["MPLS-7"]
    assert cids(status="offline") == ["MPLS-7"]
    assert cids(tenant_id=tenant) == ["MPLS-7"]
    assert cids(site_id=site_a) == ["INET-1"]
    assert cids(host_id=host) == ["INET-1"]
    assert cids(q="mpls") == ["MPLS-7"]
    assert cids(q="HEAD OFFICE") == ["INET-1"]
    assert cids(q="  ") == ["INET-1", "MPLS-7"]
    assert admin.get(CIRCUITS, params={"status": "lost"}).status_code == 400


# ── Devices and utilisation ──────────────────────────────────────────────────


def _set_stats(host_id: int, name: str) -> None:
    async def run() -> None:
        await db.upsert_interface_stats_batch([(host_id, 1, name, 1000, 0, 0)])
        conn = await db.get_db()
        try:
            await conn.execute(
                """UPDATE interface_stats SET prev_in_octets = 0, prev_out_octets = 0,
                       in_octets = 1250000, out_octets = 2500000,
                       prev_polled_at = '2026-01-01 00:00:00', polled_at = '2026-01-01 00:00:10'
                   WHERE host_id = ? AND if_index = 1""",
                (host_id,),
            )
            await conn.commit()
        finally:
            await conn.close()

    asyncio.run(run())


def test_device_view_interfaces_and_utilisation(admin):
    provider, ctype = _base(admin)
    site = _site()
    host = _host(admin)
    idle = _host(admin, "edge-r2", "192.0.2.11")
    _set_stats(host, "GigabitEthernet0/1")
    term = {"term_side": "A", "site_id": site, "host_id": host, "interface_name": "gigabitethernet0/1"}
    with_rate = _circuit(admin, provider, ctype, "C-RATE", commit_rate_kbps=10_000, terminations=[term])
    _circuit(admin, provider, ctype, "C-NORATE", terminations=[term])

    view = _ok(admin.get(f"{BASE}/hosts/{host}/circuits"))
    by_cid = {c["cid"]: c for c in view["circuits"]}
    assert set(by_cid) == {"C-RATE", "C-NORATE"}
    (util,) = by_cid["C-RATE"]["utilisation"]
    # 1,250,000 bytes in 10 s = 1 Mbps in, 2 Mbps out; 10 Mbps committed.
    assert (util["in_bps"], util["out_bps"]) == (1_000_000, 2_000_000)
    assert (util["in_pct_of_commit"], util["out_pct_of_commit"]) == (10.0, 20.0)
    assert by_cid["C-NORATE"]["utilisation"] == []
    assert _ok(admin.get(f"{CIRCUITS}/{with_rate['id']}"))["utilisation"][0]["term_side"] == "A"
    assert _ok(admin.get(f"{BASE}/hosts/{idle}/circuits"))["circuits"] == []
    assert admin.get(f"{BASE}/hosts/9999/circuits").status_code == 404

    async def inventory() -> None:
        await db.upsert_interface_inventory(host, 2, "Gi0/2", "", "up", "up", 1000, "full", "", 0, "")

    asyncio.run(inventory())
    assert _ok(admin.get(f"{BASE}/hosts/{host}/interfaces"))["interfaces"] == ["Gi0/2", "GigabitEthernet0/1"]
    assert admin.get(f"{BASE}/hosts/9999/interfaces").status_code == 404

    # Deleting the host clears the termination's device.
    _ok(admin.delete(f"/api/hosts/{host}"))
    term_after = _ok(admin.get(f"{CIRCUITS}/{with_rate['id']}"))["terminations"][0]
    assert term_after["host_id"] is None


def test_billing_link(admin):
    provider, ctype = _base(admin)
    host = _host(admin)
    billing = _ok(
        admin.post(
            "/api/billing/circuits",
            json={"name": "Uplink billing", "customer": "Example Customer", "host_id": host, "if_index": 1},
        ),
        201,
    )
    circuit = _circuit(admin, provider, ctype, billing_circuit_id=billing["id"])
    assert circuit["billing_circuit_id"] == billing["id"]
    assert circuit["billing_circuit_name"] == "Uplink billing" and circuit["billing_customer"] == "Example Customer"
    _ok(admin.delete(f"/api/billing/circuits/{billing['id']}"))
    assert _ok(admin.get(f"{CIRCUITS}/{circuit['id']}"))["billing_circuit_id"] is None


# ── Change log and audit ─────────────────────────────────────────────────────


def test_changes_are_recorded_and_audited(admin):
    provider, ctype = _base(admin)
    site = _site()
    circuit = _circuit(admin, provider, ctype, terminations=[{"term_side": "A", "site_id": site}])
    _ok(admin.put(f"{CIRCUITS}/{circuit['id']}", json={"status": "offline"}))
    net = _ok(admin.post(NETWORKS, json={"provider_id": provider, "name": "Backbone"}), 201)
    _ok(admin.delete(f"{CIRCUITS}/{circuit['id']}"))

    history = _ok(admin.get(f"/api/changes/circuit/{circuit['id']}"))["changes"]
    assert [c["action"] for c in history] == ["delete", "update", "create"]
    assert history[1]["changes"]["status"] == {"before": "active", "after": "offline"}
    assert history[2]["object_label"] == "CKT-1001" and history[2]["user"] == "admin"
    term_id = circuit["terminations"][0]["id"]
    assert [c["action"] for c in _ok(admin.get(f"/api/changes/circuit_termination/{term_id}"))["changes"]] == [
        "delete",
        "create",
    ]
    for kind, oid in (("circuit_provider", provider), ("circuit_type", ctype), ("provider_network", net["id"])):
        assert _ok(admin.get(f"/api/changes/{kind}/{oid}"))["changes"][0]["action"] == "create", kind

    reader = user_client(admin, "circuit-reader", features=["circuits"])
    assert _ok(reader.get(f"/api/changes/circuit/{circuit['id']}"))["total"] == 3
    assert (
        user_client(admin, "ipam-reader", features=["ipam"]).get(f"/api/changes/circuit/{circuit['id']}").status_code
        == 403
    )

    events = asyncio.run(db.get_audit_events(limit=50))
    actions = {e["action"] for e in events if e.get("category") == "circuits"}
    assert {"provider_create", "circuit_type_create", "circuit_create", "circuit_update", "circuit_delete"} <= actions


def test_choices_list_hosts_sites_and_tenants(admin):
    host = _host(admin)
    site = _site("Site Choice")
    tenant = _tenant("Tenant Choice")
    reader = user_client(admin, "circuit-reader", features=["circuits"])
    body = _ok(reader.get(f"{BASE}/choices"))
    assert {"id": host, "hostname": "edge-r1", "ip_address": "192.0.2.10"} in body["hosts"]
    assert {"id": site, "name": "Site Choice"} in body["sites"]
    assert {"id": tenant, "name": "Tenant Choice"} in body["tenants"]
