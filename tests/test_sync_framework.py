"""Sync framework: value normalisation and mappings, the diff engine, the
plan for every direction and conflict policy, the NetBox / Nautobot /
ServiceNow adapters against fake APIs (``httpx.MockTransport``), the shared
HTTP client, and the API end to end (dry run, real import into Plexus
through the bulk import pipeline, export, permissions, run history).

All names and addresses are invented (documentation ranges, example.com).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
import routes.database as db
from netcontrol.routes import state
from netcontrol.routes.ipam_adapters import _address_with_host_prefix, _coerce_list, _normalize_address
from netcontrol.routes.net_guard import OutboundRequestError
from netcontrol.sync import runner
from netcontrol.sync.adapters import base as adapter_base
from netcontrol.sync.adapters.netbox import NautobotAdapter, NetBoxAdapter
from netcontrol.sync.adapters.servicenow import ServiceNowAdapter
from netcontrol.sync.engine import Entry, diff_records, plan_entries, summarise
from netcontrol.sync.models import (
    MappingError,
    check_mappings,
    key_text,
    make_record,
    natural_key,
    resolve_mapping,
    spec_for,
)
from netcontrol.sync.transport import HttpJsonClient, SyncError, clean_base_url

from mcp_helpers import CsrfClient, admin_client, user_client

API = "/api/sync"
TOKEN = "tok-sync-test"  # invented


async def _no_guard(url: str) -> None:
    return None


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


# ── Fake APIs ────────────────────────────────────────────────────────────────


class FakeNetBox:
    """An in-memory NetBox/Nautobot: list (limit/offset), create, patch and
    delete under /api/<app>/<model>/. A flat ``status`` written is stored as
    NetBox returns it (``{"value", "label"}``)."""

    def __init__(self, data: dict[str, list[dict]] | None = None, token: str = TOKEN) -> None:
        self.data = {k: [dict(r) for r in v] for k, v in (data or {}).items()}
        self.token = token
        self.calls: list[tuple[str, str, str | None, dict, Any]] = []
        self.next_id = 1000

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization") != f"Token {self.token}":
            return httpx.Response(403, json={"detail": "Invalid token"})
        parts = request.url.path.strip("/").split("/")
        endpoint = "/".join(parts[1:3])
        ref = parts[3] if len(parts) > 3 else None
        body = json.loads(request.content) if request.content else None
        params = dict(request.url.params)
        self.calls.append((request.method, endpoint, ref, params, body))
        rows = self.data.setdefault(endpoint, [])
        if isinstance(body, dict) and isinstance(body.get("status"), str):
            body["status"] = {"value": body["status"], "label": body["status"].title()}
        if request.method == "GET":
            limit, offset = int(params.get("limit", 50)), int(params.get("offset", 0))
            return httpx.Response(200, json={"count": len(rows), "results": rows[offset : offset + limit]})
        if request.method == "POST":
            self.next_id += 1
            row = {"id": self.next_id, **(body or {})}
            rows.append(row)
            return httpx.Response(201, json=row)
        row = next((r for r in rows if str(r["id"]) == ref), None)
        if row is None:
            return httpx.Response(404, json={"detail": "Not found."})
        if request.method == "PATCH":
            row.update(body or {})
            return httpx.Response(200, json=row)
        if request.method == "DELETE":
            rows.remove(row)
            return httpx.Response(204)
        return httpx.Response(405)

    def writes(self) -> list[tuple[str, str, str | None, Any]]:
        return [(m, e, r, b) for m, e, r, _p, b in self.calls if m != "GET"]


def _client(handler, base: str = "https://netbox.example.com", **kw) -> HttpJsonClient:
    headers = kw.pop("headers", {"Authorization": f"Token {TOKEN}"})
    return HttpJsonClient(base, headers=headers, transport=httpx.MockTransport(handler), guard=_no_guard, **kw)


NETBOX_DATA = {
    "dcim/sites": [
        {
            "id": 1,
            "name": "Branch-1",
            "description": "First branch",
            "status": {"value": "active", "label": "Active"},
            "physical_address": "1 Example Way",
            "latitude": 51.5,
            "longitude": -0.12,
        }
    ],
    "dcim/manufacturers": [{"id": 20, "name": "Cisco", "description": ""}],
    "dcim/device-types": [
        {"id": 21, "model": "C9300-48P", "manufacturer": {"name": "Cisco"}, "part_number": "C9300-48P", "u_height": 1}
    ],
    "ipam/vrfs": [{"id": 5, "name": "blue", "rd": "65000:1", "description": "Blue VRF"}],
    "ipam/prefixes": [
        {
            "id": 7,
            "prefix": "192.0.2.0/24",
            "vrf": {"id": 5, "name": "blue"},
            "description": "Branch LAN",
            "site": {"id": 1, "name": "Branch-1"},
            "vlan": None,
        }
    ],
    "ipam/ip-addresses": [
        {
            "id": 9,
            "address": "192.0.2.10/24",
            "vrf": {"id": 5, "name": "blue"},
            "dns_name": "SW1.example.com",
            "description": "switch",
        }
    ],
    "dcim/devices": [
        {
            "id": 11,
            "name": "branch1-sw1",
            "primary_ip": {"address": "192.0.2.10/24"},
            "site": {"name": "Branch-1"},
            "device_type": {"model": "C9300-48P", "manufacturer": {"name": "Cisco"}},
            "role": {"name": "access"},
            "serial": "FOC0000X1",
        }
    ],
}


# ── Models ───────────────────────────────────────────────────────────────────


def test_normalisation_and_natural_keys():
    spec = spec_for("ip_addresses")
    record = make_record("ip_addresses", {"address": "192.0.2.10/24", "prefix": "192.0.2.10/24", "dns_name": "A.B"})
    assert record.values["address"] == "192.0.2.10"
    assert record.values["prefix"] == "192.0.2.0/24"
    assert record.values["dns_name"] == "a.b"
    assert natural_key(spec, record.values) == ("192.0.2.10",)
    site = make_record("sites", {"name": "Branch-1", "latitude": 51.50000001, "status": "Active"})
    assert site.key == ("branch-1",) and site.values["latitude"] == "51.5" and site.values["status"] == "active"
    vlan = make_record("vlans", {"vid": "10.0", "site": "HQ"})
    assert vlan.values["vid"] == "10" and key_text(spec_for("vlans"), vlan.values) == "10 @ HQ"
    prefix = make_record("prefixes", {"prefix": "198.51.100.7/24", "vrf": "blue"})
    assert prefix.label == "198.51.100.0/24 (VRF blue)"
    assert make_record("device_types", {"manufacturer": "Acme", "model": "X1"}).label == "Acme X1"


def test_mapping_resolution():
    defaults = {"name": "name", "site": "site.name", "role": "role.name", "serial": "serial", "primary_ip": "ip"}
    mapping = resolve_mapping("devices", defaults, None)
    assert "role" not in mapping.paths and "serial" not in mapping.paths  # optional: off by default
    mapping = resolve_mapping("devices", defaults, {"role": True, "serial": "asset.serial", "site": False})
    assert mapping.paths["role"] == "role.name" and mapping.paths["serial"] == "asset.serial"
    assert "site" not in mapping.paths and "role" in mapping.fields
    mapping = resolve_mapping("devices", defaults, {"_endpoint": "custom/devices"})
    assert mapping.options == {"endpoint": "custom/devices"}
    with pytest.raises(MappingError, match="key field"):
        resolve_mapping("devices", defaults, {"name": False})
    with pytest.raises(MappingError, match="no field"):
        resolve_mapping("devices", defaults, {"colour": "x"})
    with pytest.raises(MappingError, match="no default"):
        resolve_mapping("devices", defaults, {"platform": True})
    assert check_mappings(None) == {}
    with pytest.raises(MappingError, match="Unknown object type"):
        check_mappings({"widgets": {}})
    with pytest.raises(MappingError, match="must be a path"):
        check_mappings({"devices": {"role": 5}})


# ── Diff engine and plan ─────────────────────────────────────────────────────


def _sites(*rows: dict) -> list:
    return [make_record("sites", r, ref=i + 1) for i, r in enumerate(rows)]


def test_diff_pairs_by_key_and_diffs_fields():
    remote = _sites(
        {"name": "A", "description": "same"},
        {"name": "B", "description": "new text"},
        {"name": "C", "description": ""},
        {"name": "c", "description": "duplicate"},
    )
    plexus = _sites({"name": "a", "description": "same"}, {"name": "B", "description": "old"}, {"name": "D"})
    diff = diff_records("sites", remote, plexus, ["name", "description"])
    states = {item.label: item.state for item in diff.items}
    assert states == {"A": "same", "B": "changed", "C": "remote_only", "D": "plexus_only"}
    changed = next(i for i in diff.items if i.label == "B")
    assert changed.fields == {"description": ("new text", "old")}
    assert len(diff.duplicates) == 1 and "'c'" in diff.duplicates[0]
    # A field one side does not read is not compared.
    diff = diff_records(
        "sites", [make_record("sites", {"name": "B"}, fields=["name"])], plexus, ["name", "description"]
    )
    assert next(i for i in diff.items if i.label == "B").state == "same"


def _plan(remote, plexus, **kw):
    diff = diff_records("sites", remote, plexus, ["name", "description", "address"])
    kw.setdefault("writable_plexus", {"name", "description", "address"})
    kw.setdefault("writable_remote", {"name", "description", "address"})
    return plan_entries(diff, **kw), diff


def test_plan_import_export_and_deletes():
    remote = _sites({"name": "A", "description": "r"}, {"name": "B", "description": "only remote"})
    plexus = _sites({"name": "A", "description": "p"}, {"name": "C", "description": "only plexus"})
    entries, diff = _plan(remote, plexus, direction="import")
    got = {(e.key, e.action, e.target) for e in entries}
    assert got == {("A", "update", "plexus"), ("B", "create", "plexus")}
    update = next(e for e in entries if e.action == "update")
    assert update.changes == {"description": {"before": "p", "after": "r"}} and update.ref == 1
    assert update.values == {"name": "A", "description": "r"}
    entries, _ = _plan(remote, plexus, direction="import", delete_missing=True)
    assert ("C", "delete", "plexus") in {(e.key, e.action, e.target) for e in entries}
    entries, _ = _plan(remote, plexus, direction="export", delete_missing=True)
    got = {(e.key, e.action, e.target) for e in entries}
    assert got == {("A", "update", "remote"), ("C", "create", "remote"), ("B", "delete", "remote")}
    summary = summarise(entries, diff)
    assert summary["create"] == 1 and summary["delete"] == 1 and summary["planned"] == 3


def test_plan_bidirectional_conflict_policies():
    remote = _sites({"name": "A", "description": "remote", "address": ""}, {"name": "R"})
    plexus = _sites({"name": "A", "description": "plexus", "address": "1 Example Way"}, {"name": "P"})
    for policy, expected in (
        ("source_wins", {("A", "update", "plexus"), ("A", "update", "remote")}),
        ("plexus_wins", {("A", "update", "remote")}),
        ("skip_conflicts", {("A", "update", "remote"), ("A", "conflict", "plexus")}),
    ):
        entries, _ = _plan(remote, plexus, direction="bidirectional", policy=policy, delete_missing=True)
        got = {(e.key, e.action, e.target) for e in entries}
        assert expected | {("R", "create", "plexus"), ("P", "create", "remote")} == got, policy
        # Never a delete in a bidirectional run.
        assert not any(e.action == "delete" for e in entries)
    entries, _ = _plan(remote, plexus, direction="bidirectional", policy="plexus_wins")
    to_remote = next(e for e in entries if e.target == "remote" and e.key == "A")
    # The empty remote address is filled, the conflict goes Plexus's way.
    assert to_remote.changes == {
        "description": {"before": "remote", "after": "plexus"},
        "address": {"before": "", "after": "1 Example Way"},
    }
    entries, _ = _plan(remote, plexus, direction="bidirectional", policy="skip_conflicts")
    conflict = next(e for e in entries if e.action == "conflict")
    assert conflict.outcome == "skipped" and conflict.changes == {
        "description": {"plexus": "plexus", "remote": "remote"}
    }


def test_plan_respects_writable_fields_and_guards_mass_deletes():
    remote = _sites({"name": "A", "description": "r", "address": "x"})
    plexus = _sites({"name": "A", "description": "p", "address": "y"})
    entries, _ = _plan(remote, plexus, direction="export", writable_remote={"name", "description"})
    assert entries[0].changes == {"description": {"before": "r", "after": "p"}}
    entries, _ = _plan(remote, plexus, direction="export", writable_remote={"description"})
    assert entries[0].action == "update"  # an update never needs the key written
    entries, _ = _plan([], plexus, direction="export", writable_remote={"description"})
    assert entries[0].action == "create" and entries[0].outcome == "skipped"
    many = _sites(*({"name": f"s{i}"} for i in range(30)))
    entries, _ = _plan(many[:5], many, direction="import", delete_missing=True)
    deletes = [e for e in entries if e.action == "delete"]
    assert len(deletes) == 25 and all(e.outcome == "skipped" and "Held back" in e.message for e in deletes)


# ── Shared HTTP client and helpers ───────────────────────────────────────────


def test_http_client_errors_and_scope():
    async def go():
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/bad":
                return httpx.Response(400, json={"name": ["This field is required."]})
            return httpx.Response(200, text="not json")

        async with _client(handler) as client:
            with pytest.raises(SyncError, match="HTTP 400.*required"):
                await client.get("bad")
            with pytest.raises(SyncError, match="not JSON"):
                await client.get("text")
            with pytest.raises(SyncError, match="outside the connection"):
                await client.get("https://netbox.example.com.evil.example/x")

        async def reject(url: str) -> None:
            raise OutboundRequestError("loopback")

        client = HttpJsonClient("https://netbox.example.com", guard=reject, label="NetBox")
        with pytest.raises(SyncError, match="NetBox address rejected"):
            async with client:
                pass

    asyncio.run(go())


def test_clean_base_url_and_shared_ipam_helpers():
    assert clean_base_url("netbox.example.com/") == "https://netbox.example.com"
    assert clean_base_url("https://cmdb.example.com:8443/sn/") == "https://cmdb.example.com:8443/sn"
    for bad in ("http://netbox.example.com", "https://u:p@netbox.example.com", "https://x.example.com/?a=1", ""):
        with pytest.raises(ValueError):
            clean_base_url(bad)
    # The IPAM adapter helpers now sit on the shared transport.
    assert _normalize_address("2001:db8::5/64") == "2001:db8::5"
    assert _address_with_host_prefix("2001:db8::5") == "2001:db8::5/128"
    assert _coerce_list({"data": [{"a": 1}, 2]}) == [{"a": 1}]


# ── NetBox / Nautobot adapters ───────────────────────────────────────────────


def test_netbox_adapter_loads_pages_and_writes(monkeypatch):
    monkeypatch.setattr("netcontrol.sync.adapters.netbox.PAGE_SIZE", 2)
    fake = FakeNetBox(
        {
            "dcim/sites": [{"id": i, "name": f"site-{i}", "status": {"value": "planned"}} for i in range(1, 6)],
            **{k: v for k, v in NETBOX_DATA.items() if k != "dcim/sites"},
        }
    )

    async def go():
        async with NetBoxAdapter(_client(fake), {"devices": {"role": True}}) as nb:
            sites = await nb.load("sites")
            assert [s.values["name"] for s in sites] == [f"site-{i}" for i in range(1, 6)]
            assert sites[0].values["status"] == "planned" and sites[0].ref == 1
            gets = [c for c in fake.calls if c[0] == "GET" and c[1] == "dcim/sites"]
            assert [c[3]["offset"] for c in gets] == ["0", "2", "4"]
            (address,) = await nb.load("ip_addresses")
            assert address.values == {
                "address": "192.0.2.10",
                "prefix": "192.0.2.0/24",
                "vrf": "blue",
                "dns_name": "sw1.example.com",
                "description": "switch",
            }
            (device,) = await nb.load("devices")
            assert device.values["primary_ip"] == "192.0.2.10" and device.values["manufacturer"] == "Cisco"
            assert device.values["role"] == "access" and "serial" not in device.values
            assert "primary_ip" not in nb.writable("devices") and "manufacturer" not in nb.writable("devices")

            entries = [
                Entry("sites", "Branch-9", "create", "remote", values={"name": "Branch 9", "status": "active"}),
                Entry(
                    "ip_addresses",
                    "198.51.100.5",
                    "create",
                    "remote",
                    values={"address": "198.51.100.5", "prefix": "198.51.100.0/25", "dns_name": "a.example.com"},
                ),
                Entry(
                    "ip_addresses",
                    "192.0.2.10",
                    "update",
                    "remote",
                    values={"address": "192.0.2.10", "prefix": ""},
                    ref=9,
                ),
                Entry("vrfs", "blue", "delete", "remote", ref=5),
                Entry("vrfs", "gone", "delete", "remote", ref=404),
            ]
            await nb.apply("sites", entries[:1])
            await nb.apply("ip_addresses", entries[1:3])
            await nb.apply("vrfs", entries[3:])
        return entries

    entries = asyncio.run(go())
    assert [e.outcome for e in entries] == ["applied", "applied", "applied", "applied", "failed"]
    assert "HTTP 404" in entries[4].message
    writes = fake.writes()
    assert writes[0] == (
        "POST",
        "dcim/sites",
        None,
        {"name": "Branch 9", "status": {"value": "active", "label": "Active"}, "slug": "branch-9"},
    )
    assert writes[1][3] == {
        "address": "198.51.100.5/25",
        "dns_name": "a.example.com",
        "status": {"value": "active", "label": "Active"},
    }
    # Dropping the prefix rewrites the address with the host mask; the key is not re-sent.
    assert writes[2] == ("PATCH", "ipam/ip-addresses", "9", {"address": "192.0.2.10/32"})
    assert writes[3] == ("DELETE", "ipam/vrfs", "5", None)


def test_nautobot_adapter_paths_and_statuses():
    fake = FakeNetBox(
        {
            "dcim/locations": [{"id": 3, "name": "HQ", "status": {"name": "Active"}, "physical_address": ""}],
            "dcim/devices": [
                {
                    "id": 4,
                    "name": "hq-fw1",
                    "location": {"name": "HQ"},
                    "device_type": {"model": "FW-100"},
                    "primary_ip4": {"address": "203.0.113.1/24"},
                }
            ],
        }
    )

    async def go():
        async with NautobotAdapter(_client(fake, base="https://nautobot.example.com")) as nb:
            (site,) = await nb.load("sites")
            (device,) = await nb.load("devices")
            entry = Entry("sites", "Lab", "create", "remote", values={"name": "Lab", "status": "planned"})
            await nb.apply("sites", [entry])
            vrf = Entry("vrfs", "red", "create", "remote", values={"name": "red", "rd": "65000:2"})
            await nb.apply("vrfs", [vrf])
        return site, device, entry

    site, device, entry = asyncio.run(go())
    assert site.values["status"] == "active" and site.values["name"] == "HQ"
    assert device.values == {"name": "hq-fw1", "primary_ip": "203.0.113.1", "site": "HQ", "device_type": "FW-100"}
    assert entry.outcome == "applied"
    assert all(c[3].get("depth") == "1" for c in fake.calls if c[0] == "GET")
    posts = [c for c in fake.calls if c[0] == "POST"]
    assert posts[0][4] == {"location_type": {"name": "Site"}, "status": {"name": "Planned"}, "name": "Lab"}
    assert posts[1][4] == {"namespace": {"name": "Global"}, "name": "red", "rd": "65000:2"}


# ── ServiceNow adapter ───────────────────────────────────────────────────────


class FakeServiceNow:
    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.rows = {
            "cmdb_ci_netgear": [
                {
                    "sys_id": "a1b2c3",
                    "name": "dc-core1",
                    "ip_address": "198.51.100.1",
                    "location": "DC-East",
                    "manufacturer": "Juniper",
                    "model_id": "QFX5120",
                    "serial_number": "",
                }
            ],
            "core_company": [{"sys_id": "m1", "name": "Juniper"}],
        }

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path
        if path == "/oauth_token.do":
            form = dict(httpx.QueryParams(request.content.decode()))
            if form == {"grant_type": "client_credentials", "client_id": "cid", "client_secret": "csecret"}:
                return httpx.Response(200, json={"access_token": "oauth-abc", "expires_in": 1800})
            return httpx.Response(401, json={"error": "invalid_client"})
        table = path.split("/")[4]
        if request.method == "GET":
            offset = int(request.url.params.get("sysparm_offset", 0))
            return httpx.Response(200, json={"result": self.rows.get(table, [])[offset:]})
        return httpx.Response(201 if request.method == "POST" else 200, json={"result": {}})


def test_servicenow_basic_auth_reads_display_values_and_writes():
    fake = FakeServiceNow()

    async def go():
        client = _client(fake, base="https://cmdb.example.com", headers={}, auth=("svc", "pw"))
        async with ServiceNowAdapter(client, {"devices": {"serial": True}}) as sn:
            (device,) = await sn.load("devices")
            (maker,) = await sn.load("manufacturers")
            assert not sn.supports("vrfs")
            create = Entry("devices", "edge1", "create", "remote", values={"name": "edge1", "site": "DC-West"})
            update = Entry("devices", "dc-core1", "update", "remote", values={"name": "dc-core1", "serial": "SN1"})
            update.ref = device.ref
            await sn.apply("devices", [create, update])
        return device, maker, create, update

    device, maker, create, update = asyncio.run(go())
    assert device.values["site"] == "DC-East" and device.values["device_type"] == "QFX5120" and device.ref == "a1b2c3"
    assert maker.values == {"name": "Juniper"}
    first = fake.calls[0]
    assert first.headers["Authorization"].startswith("Basic ")
    assert first.url.params["sysparm_display_value"] == "true"
    assert first.url.params["sysparm_exclude_reference_link"] == "true"
    company = next(c for c in fake.calls if "core_company" in c.url.path)
    assert company.url.params["sysparm_query"] == "manufacturer=true"
    post = next(c for c in fake.calls if c.method == "POST")
    assert post.url.params["sysparm_input_display_value"] == "true"
    assert json.loads(post.content) == {"name": "edge1", "location": "DC-West"}
    patch = next(c for c in fake.calls if c.method == "PATCH")
    assert patch.url.path.endswith("/cmdb_ci_netgear/a1b2c3") and json.loads(patch.content) == {"serial_number": "SN1"}
    assert create.outcome == update.outcome == "applied"


def test_servicenow_oauth_token_flow():
    fake = FakeServiceNow()

    async def go(secret: str):
        client = _client(fake, base="https://cmdb.example.com", headers={})
        async with ServiceNowAdapter(client, oauth=("cid", secret)) as sn:
            return await sn.load("devices")

    assert len(asyncio.run(go("csecret"))) == 1
    assert fake.calls[1].headers["Authorization"] == "Bearer oauth-abc"
    with pytest.raises(SyncError, match="HTTP 401"):
        asyncio.run(go("wrong"))


def test_key_field_a_system_does_not_hold_reads_empty():
    adapter = ServiceNowAdapter(_client(FakeServiceNow()))
    assert adapter.mapping("prefixes").paths["vrf"] == "" and "vrf" not in adapter.writable("prefixes")
    plexus = [
        make_record("prefixes", {"prefix": "192.0.2.0/24", "description": "LAN"}),
        make_record("prefixes", {"prefix": "198.51.100.0/24", "vrf": "blue"}),
    ]
    diff = diff_records("prefixes", [], plexus, adapter.fields("prefixes"))
    entries = plan_entries(
        diff, direction="export", writable_plexus=set(), writable_remote=adapter.writable("prefixes")
    )
    assert {e.key: e.outcome for e in entries} == {"192.0.2.0/24": "planned", "198.51.100.0/24 (VRF blue)": "skipped"}
    body = adapter.build_body("prefixes", entries[0].values, create=True)
    assert body == {"name": "192.0.2.0/24", "short_description": "LAN", "location": ""}


def test_rest_adapter_endpoint_must_be_a_path():
    adapter = ServiceNowAdapter(_client(FakeServiceNow()), {"vrfs": {"_endpoint": "https://other.example.com/x"}})
    with pytest.raises(MappingError, match="path of the connection"):
        adapter.endpoint("vrfs")
    assert adapter_base.slugify("Branch #1 / East") == "branch-1-east"


# ── API end to end ───────────────────────────────────────────────────────────


@pytest.fixture
def netbox(monkeypatch) -> FakeNetBox:
    fake = FakeNetBox(NETBOX_DATA)
    monkeypatch.setattr(runner, "transport_for", lambda connection: httpx.MockTransport(fake))
    monkeypatch.setattr(runner, "guard_for", lambda connection: _no_guard)
    return fake


def _connection(admin: CsrfClient, **over) -> dict:
    cred = admin.post("/api/credentials/service", json={"name": "netbox-sync", "username": "sync", "password": TOKEN})
    assert cred.status_code == 201, cred.text
    body = {
        "name": "Lab NetBox",
        "kind": "netbox",
        "base_url": "https://netbox.example.com/",
        "auth_type": "token",
        "credential_id": cred.json()["id"],
        **over,
    }
    resp = admin.post(f"{API}/connections", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _job(client: CsrfClient, connection_id: int, **over) -> Any:
    body = {
        "name": "NetBox import",
        "connection_id": connection_id,
        "object_types": ["devices", "sites", "manufacturers", "device_types", "vrfs", "prefixes", "ip_addresses"],
        "direction": "import",
        **over,
    }
    return client.post(f"{API}/jobs", json=body)


def _run(client: CsrfClient, job_id: int, dry_run: bool) -> dict:
    resp = client.post(f"{API}/jobs/{job_id}/run", json={"dry_run": dry_run})
    assert resp.status_code == 202, resp.text
    run = client.get(f"{API}/runs/{resp.json()['id']}").json()
    assert run["status"] != "running"
    return run


def test_api_dry_run_then_import_into_plexus(monkeypatch, request, netbox):
    admin = admin_client(monkeypatch, request)
    connection = _connection(admin)
    assert connection["base_url"] == "https://netbox.example.com" and connection["credential_name"] == "netbox-sync"
    assert TOKEN not in json.dumps(admin.get(f"{API}/connections").json())
    test = admin.post(f"{API}/connections/{connection['id']}/test")
    assert test.json() == {"ok": True, "message": "Signed in to NetBox and read the API."}

    job = _job(admin, connection["id"], host_group="Synced / NetBox")
    assert job.status_code == 201, job.text
    job = job.json()
    assert job["object_types"] == [
        "sites",
        "manufacturers",
        "device_types",
        "vrfs",
        "prefixes",
        "ip_addresses",
        "devices",
    ]

    dry = _run(admin, job["id"], dry_run=True)
    assert dry["dry_run"] and dry["status"] == "success", dry
    assert dry["summary"]["sites"]["create"] == 1
    assert not any(s["name"] == "Branch-1" for s in asyncio.run(db.list_geo_sites()))
    entries = admin.get(f"{API}/runs/{dry['id']}/entries").json()
    assert entries["total"] == 7 and {e["outcome"] for e in entries["entries"]} == {"planned"}
    prefix_entry = next(e for e in entries["entries"] if e["object_type"] == "prefixes")
    assert "No VRF 'blue'" in prefix_entry["message"]  # would exist after the VRF step of a real run

    real = _run(admin, job["id"], dry_run=False)
    assert real["status"] == "success", [
        (e["object_type"], e["outcome"], e["message"])
        for e in admin.get(f"{API}/runs/{real['id']}/entries").json()["entries"]
    ]
    entries = admin.get(f"{API}/runs/{real['id']}/entries", params={"object_type": "devices"}).json()["entries"]
    assert entries[0]["outcome"] == "applied" and entries[0]["changes"]["primary_ip"]["after"] == "192.0.2.10"
    site = next(s for s in asyncio.run(db.list_geo_sites()) if s["name"] == "Branch-1")
    assert site["address"] == "1 Example Way" and float(site["lat"]) == 51.5
    assert any(v["name"] == "blue" and v["rd"] == "65000:1" for v in asyncio.run(db.list_vrfs()))
    prefixes = {p["subnet"]: p for p in asyncio.run(db.list_ipam_prefix_records())}
    assert prefixes["192.0.2.0/24"]["vrf"] == "blue" and prefixes["192.0.2.0/24"]["site"] == "Branch-1"
    host = next(h for h in asyncio.run(db.get_all_hosts()) if h["hostname"] == "branch1-sw1")
    assert host["ip_address"] == "192.0.2.10" and host["site_id"] == site["id"]
    group = next(g for g in asyncio.run(db.get_all_groups()) if g["id"] == host["group_id"])
    assert group["path"] == "Synced / NetBox"
    assert netbox.writes() == []  # an import never writes to NetBox

    # A second run finds both sides equal.
    again = _run(admin, job["id"], dry_run=False)
    assert again["message"] == "Both sides already match." and again["summary"]["devices"]["unchanged"] == 1
    runs = admin.get(f"{API}/runs", params={"job_id": job["id"]}).json()["runs"]
    assert [r["id"] for r in runs] == [again["id"], real["id"], dry["id"]]
    assert admin.get(f"{API}/jobs/{job['id']}").json()["last_run_status"] == "success"
    # The change log records the synced host, created by the acting user.
    changes, _total = asyncio.run(db.list_object_changes(object_types=["host"], object_id=str(host["id"])))
    assert ("create", "admin") in [(c["action"], c["user"]) for c in changes]
    assert {c["user"] for c in changes} == {"admin"}


def test_api_export_and_bidirectional(monkeypatch, request, netbox):
    admin = admin_client(monkeypatch, request)
    connection = _connection(admin)
    asyncio.run(db.create_vrf(name="green", rd="65000:3", description="Green VRF"))
    asyncio.run(db.create_vrf(name="blue", rd="65000:9", description="Blue VRF"))
    job = _job(admin, connection["id"], name="VRF export", object_types=["vrfs"], direction="export").json()
    run = _run(admin, job["id"], dry_run=False)
    assert run["status"] == "success", run
    writes = netbox.writes()
    assert ("POST", "ipam/vrfs", None, {"name": "green", "rd": "65000:3", "description": "Green VRF"}) in writes
    assert ("PATCH", "ipam/vrfs", "5", {"rd": "65000:9"}) in writes

    netbox.data["ipam/vrfs"][0]["rd"] = "65000:1"  # someone changed it in NetBox again
    edit = admin.put(
        f"{API}/jobs/{job['id']}",
        json={
            "name": "VRF both ways",
            "connection_id": connection["id"],
            "object_types": ["vrfs"],
            "direction": "bidirectional",
            "conflict_policy": "skip_conflicts",
        },
    )
    assert edit.status_code == 200, edit.text
    run = _run(admin, job["id"], dry_run=False)
    entries = admin.get(f"{API}/runs/{run['id']}/entries").json()["entries"]
    conflict = next(e for e in entries if e["action"] == "conflict")
    assert (
        conflict["changes"] == {"rd": {"plexus": "65000:9", "remote": "65000:1"}} and conflict["outcome"] == "skipped"
    )
    assert next(v for v in asyncio.run(db.list_vrfs()) if v["name"] == "blue")["rd"] == "65000:9"


def test_api_validation_and_permissions(monkeypatch, request, netbox):
    admin = admin_client(monkeypatch, request)
    connection = _connection(admin)
    bad = admin.post(
        f"{API}/connections",
        json={
            "name": "x",
            "kind": "netbox",
            "base_url": "http://n.example.com",
            "credential_id": connection["credential_id"],
        },
    )
    assert bad.status_code == 422 and "https" in bad.json()["detail"]["message"]
    bad = admin.post(
        f"{API}/connections",
        json={
            "name": "x",
            "kind": "netbox",
            "base_url": "n.example.com",
            "auth_type": "oauth",
            "credential_id": connection["credential_id"],
        },
    )
    assert bad.status_code == 422 and bad.json()["detail"]["fields"] == {"auth_type": "One of: token."}
    dup = admin.post(
        f"{API}/connections",
        json={
            "name": "LAB netbox",
            "kind": "netbox",
            "base_url": "n.example.com",
            "credential_id": connection["credential_id"],
        },
    )
    assert dup.status_code == 409
    bad = _job(admin, connection["id"], mappings={"devices": {"name": False}})
    assert bad.status_code == 422 and "key field" in bad.json()["detail"]["message"]
    bad = _job(admin, connection["id"], interval_minutes=2)
    assert bad.status_code == 422
    job = _job(admin, connection["id"]).json()
    assert admin.delete(f"{API}/connections/{connection['id']}").status_code == 409

    reader = user_client(admin, "sync-reader", features=["sync"])
    assert reader.get(f"{API}/jobs").status_code == 200
    assert reader.post(f"{API}/jobs/{job['id']}/run", json={"dry_run": True}).status_code == 403
    writer = user_client(admin, "sync-writer", features=["sync", "sync.write"])
    assert writer.post(f"{API}/connections/{connection['id']}/test").status_code == 403
    denied = _job(writer, connection["id"], name="writer import", object_types=["vrfs"])
    assert denied.status_code == 403 and "admin rights" in denied.json()["error"]["message"]
    exported = _job(writer, connection["id"], name="writer export", object_types=["vrfs"], direction="export")
    assert exported.status_code == 201, exported.text
    # A dry run of the admin's import job is fine; a real run is not.
    assert writer.post(f"{API}/jobs/{job['id']}/run", json={"dry_run": True}).status_code == 202
    assert writer.post(f"{API}/jobs/{job['id']}/run", json={"dry_run": False}).status_code == 403
    catalog = reader.get(f"{API}/catalog").json()
    assert {k["id"] for k in catalog["kinds"]} == {"netbox", "nautobot", "servicenow"}
    assert catalog["default_mappings"]["netbox"]["devices"]["read_only"] == ["manufacturer", "primary_ip"]


def test_scheduler_runs_due_jobs(monkeypatch, request, netbox):
    from datetime import UTC, datetime

    admin = admin_client(monkeypatch, request)
    connection = _connection(admin)
    job = _job(admin, connection["id"], object_types=["vrfs"], interval_minutes=15).json()
    manual = _job(admin, connection["id"], name="manual only", object_types=["vrfs"]).json()
    assert runner.is_due(job, datetime.now(UTC)) and not runner.is_due(manual, datetime.now(UTC))
    assert asyncio.run(runner.run_due_jobs()) == [job["id"]]
    runs = admin.get(f"{API}/runs", params={"job_id": job["id"]}).json()["runs"]
    assert runs[0]["trigger"] == "schedule" and runs[0]["status"] == "success"
    assert asyncio.run(runner.run_due_jobs()) == []  # not due again for 15 minutes
