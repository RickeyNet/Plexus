"""Bulk import (``netcontrol.bulk_import`` and its routes): parsing, the
round trip with the host export, create/update/upsert, reference errors,
all-or-nothing commits, limits, object scope, formula guards, safe YAML and
the object-change events."""

from __future__ import annotations

import csv
import io
import ipaddress

import pytest
import routes.database as db
import yaml
from netcontrol import bulk_import
from netcontrol.bulk_import import BulkImportError, parse_records
from routes.db.change_events import add_object_change_hook, remove_object_change_hook

from mcp_helpers import CsrfClient, admin_client, user_client
from test_object_scope_api import _scoped

INV = "/api/import/inventory"
IPAM = "/api/import/ipam"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200):
    assert resp.status_code == status, resp.text
    return resp.json()


def _group(admin: CsrfClient, name: str, parent_id: int | None = None) -> int:
    return int(_ok(admin.post("/api/inventory", json={"name": name, "parent_id": parent_id}), 201)["id"])


def _host(admin: CsrfClient, group_id: int, name: str, ip: str) -> int:
    return int(
        _ok(admin.post(f"/api/inventory/{group_id}/hosts", json={"hostname": name, "ip_address": ip}), 201)["id"]
    )


def _csv(rows: list[list[str]]) -> str:
    out = io.StringIO()
    csv.writer(out).writerows(rows)
    return out.getvalue()


def _form(text: str, fmt: str = "csv", mode: str = "create", match_key: str = "", **extra) -> dict:
    return {"text": text, "format": fmt, "mode": mode, "match_key": match_key, **{k: str(v) for k, v in extra.items()}}


def _preview(client: CsrfClient, kind: str, text: str, family: str = INV, **kw):
    return client.post(f"{family}/{kind}/preview", data=_form(text, **kw))


def _commit(client: CsrfClient, kind: str, text: str, family: str = INV, **kw):
    return client.post(f"{family}/{kind}/commit", data=_form(text, **kw))


_TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _hosts() -> dict[str, dict]:
    """The hosts these tests add (the dev bootstrap seeds others)."""
    import asyncio

    return {
        h["hostname"]: h
        for h in asyncio.run(db.get_all_hosts())
        if any(ipaddress.ip_address(h["ip_address"]) in n for n in _TEST_NETS)
    }


HOST_HEAD = ["Hostname", "IP Address", "Group"]


# ── Parsing ──────────────────────────────────────────────────────────────────


def test_csv_parse_normalises_keys_and_strips_formula_guard():
    text = _csv([["Hostname", "IP Address", "Tags"], ["'=sw1", "192.0.2.1", "'@core; edge"], ["", "", ""]])
    (rec,) = parse_records(text, "csv")
    assert rec.row == 2
    assert rec.values == {"hostname": "=sw1", "ip_address": "192.0.2.1", "tags": "@core; edge"}
    # An apostrophe that does not guard a formula stays.
    (kept,) = parse_records(_csv([["Hostname"], ["'quoted"]]), "csv")
    assert kept.values["hostname"] == "'quoted"


def test_csv_duplicate_header_and_extra_cells():
    with pytest.raises(BulkImportError, match="twice"):
        parse_records(_csv([["Hostname", "hostname"], ["a", "b"]]), "csv")
    (rec,) = parse_records(_csv([["Hostname"], ["a", "extra"]]), "csv")
    assert rec.problems and "more cells" in rec.problems[0]["message"]
    with pytest.raises(BulkImportError, match="no rows"):
        parse_records("Hostname\n", "csv")
    with pytest.raises(BulkImportError, match="empty"):
        parse_records("", "csv")


def test_yaml_and_json_parse():
    text = yaml.safe_dump(
        {"hosts": [{"Hostname": "sw1", "ip_address": "192.0.2.1", "tags": ["a", "b"], "custom_fields": {"n": 2}}]}
    )
    (rec,) = parse_records(text, "yaml")
    assert rec.values == {"hostname": "sw1", "ip_address": "192.0.2.1", "tags": ["a", "b"], "custom_fields": {"n": "2"}}
    (rec,) = parse_records('[{"hostname": "sw2", "flag": true, "when": null}]', "json")
    assert rec.values == {"hostname": "sw2", "flag": "true", "when": ""}
    (bad,) = parse_records("- [1, 2]\n", "yaml")
    assert bad.problems
    (nested,) = parse_records("- hostname: {a: 1}\n", "yaml")
    assert "single value" in nested.problems[0]["message"]
    with pytest.raises(BulkImportError, match="list of objects"):
        parse_records("hostname: sw1\n", "yaml")
    with pytest.raises(BulkImportError, match="not valid JSON"):
        parse_records("[{", "json")
    with pytest.raises(BulkImportError, match="Format"):
        parse_records("x", "xml")


def test_yaml_python_tags_are_refused():
    text = "- !!python/object/apply:os.system ['echo unsafe']\n"
    with pytest.raises(BulkImportError, match="not valid YAML"):
        parse_records(text, "yaml")


def test_limits(monkeypatch):
    monkeypatch.setattr(bulk_import, "MAX_IMPORT_ROWS", 2)
    with pytest.raises(BulkImportError, match="at most 2"):
        parse_records(_csv([["Hostname"], ["a"], ["b"], ["c"]]), "csv")
    monkeypatch.setattr(bulk_import, "MAX_IMPORT_BYTES", 10)
    with pytest.raises(BulkImportError, match="larger"):
        parse_records("x" * 11, "csv")
    with pytest.raises(BulkImportError, match="larger"):
        bulk_import.decode_upload(b"x" * 11)
    monkeypatch.setattr(bulk_import, "MAX_IMPORT_BYTES", 100)
    with pytest.raises(BulkImportError, match="UTF-8"):
        bulk_import.decode_upload(b"\xff\xfe\xfa")
    assert bulk_import.decode_upload("﻿a".encode()) == "a"


def test_csv_cells():
    assert bulk_import.csv_text_cell("=1") == "'=1"
    assert bulk_import.unguard_cell(bulk_import.csv_text_cell("-5")) == "-5"
    assert bulk_import.csv_field_cell({"field_type": "number"}, -5) == "-5"
    assert bulk_import.csv_field_cell({"field_type": "boolean"}, True) == "true"
    assert bulk_import.csv_field_cell({"field_type": "text"}, None) == ""


# ── Hosts over HTTP ──────────────────────────────────────────────────────────


def test_template_and_upload(admin):
    _ok(
        admin.post(
            "/api/custom-fields",
            json={"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["host"]},
        ),
        201,
    )
    head = next(csv.reader(io.StringIO(admin.get(f"{INV}/hosts/template").text)))
    export_head = next(csv.reader(io.StringIO(admin.get("/api/inventory/export/csv").text)))
    assert head == export_head and head[-2:] == ["Tags", "Owner"]
    assert admin.get(f"{INV}/nope/template").status_code == 404
    vrf_head = next(csv.reader(io.StringIO(admin.get(f"{IPAM}/vrfs/template").text)))
    assert vrf_head == ["Name", "RD", "Description"]
    gid = _group(admin, "core")
    files = {"file": ("hosts.csv", _csv([HOST_HEAD, ["sw1", "192.0.2.1", "core"]]).encode(), "text/csv")}
    report = _ok(admin.post(f"{INV}/hosts/preview", files=files, data={"format": "csv"}))
    assert report["summary"]["create"] == 1 and gid
    assert admin.post(f"{INV}/hosts/preview", data={"format": "csv"}).status_code == 400
    assert _preview(admin, "hosts", "x", fmt="xml").status_code == 400
    assert _preview(admin, "hosts", "x", mode="merge").status_code == 400
    assert _preview(admin, "hosts", "x", match_key="serial").status_code == 400


def test_create_update_upsert_and_skip(admin):
    gid = _group(admin, "core")
    _host(admin, gid, "sw1", "192.0.2.1")
    text = _csv([HOST_HEAD, ["sw1", "192.0.2.11", "core"], ["sw2", "192.0.2.2", "core"]])

    created = _ok(_commit(admin, "hosts", text, mode="create"))
    assert [r["action"] for r in created["rows"]] == ["skip", "create"]
    assert created["committed"] and created["applied"] == 1
    assert _hosts()["sw1"]["ip_address"] == "192.0.2.1"

    updated = _ok(_commit(admin, "hosts", text, mode="update"))
    assert [r["action"] for r in updated["rows"]] == ["update", "skip"]
    assert updated["rows"][0]["changes"] == {"IP Address": {"before": "192.0.2.1", "after": "192.0.2.11"}}
    assert _hosts()["sw1"]["ip_address"] == "192.0.2.11"

    missing = _commit(admin, "hosts", _csv([HOST_HEAD, ["sw9", "192.0.2.9", "core"]]), mode="update")
    assert missing.status_code == 422
    assert missing.json()["rows"][0]["errors"][0]["message"].startswith("No existing host")

    upsert = _ok(
        _commit(
            admin,
            "hosts",
            _csv([HOST_HEAD, ["sw2", "192.0.2.22", "core"], ["sw3", "192.0.2.3", "core"]]),
            mode="upsert",
        )
    )
    assert [r["action"] for r in upsert["rows"]] == ["update", "create"]
    by_ip = _ok(
        _preview(
            admin, "hosts", _csv([["IP Address", "Hostname"], ["192.0.2.3", "renamed"]]), mode="update", match_key="ip"
        )
    )
    assert by_ip["rows"][0]["changes"] == {"Hostname": {"before": "sw3", "after": "renamed"}}


def test_round_trip_with_csv_and_yaml_export(admin):
    _ok(
        admin.post(
            "/api/custom-fields",
            json={"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["host"]},
        ),
        201,
    )
    _ok(
        admin.post(
            "/api/custom-fields",
            json={"key": "units", "label": "Rack units", "field_type": "number", "object_types": ["host"]},
        ),
        201,
    )
    maker = _ok(admin.post("/api/dcim/manufacturers", json={"name": "Example Networks"}), 201)
    _ok(admin.post("/api/dcim/device-types", json={"manufacturer_id": maker["id"], "model": "EX-1"}), 201)
    tag = _ok(admin.post("/api/tags", json={"name": "=cmd"}), 201)
    parent = _group(admin, "east")
    child = _group(admin, "core", parent)
    _group(admin, "core")  # same name at the top level: the export gives paths
    hid = _host(admin, child, "sw1", "192.0.2.1")
    _ok(
        admin.put(
            f"/api/hosts/{hid}/custom-data", json={"tag_ids": [tag["id"]], "fields": {"owner": "@ops", "units": 2}}
        )
    )
    _ok(admin.post("/api/hosts/bulk-edit", json={"host_ids": [hid], "set": {"device_type_id": None}}))

    exported = admin.get("/api/inventory/export/csv").text
    rows = list(csv.reader(io.StringIO(exported)))
    mine = next(r for r in rows if r[0] == "sw1")
    assert mine[6] == "east / core" and "'=cmd" in mine
    # Every exported host (the dev bootstrap seeds some too) reads back unchanged.
    same = _ok(_preview(admin, "hosts", exported, mode="upsert"))
    assert same["summary"]["skip"] == len(rows) - 1 == same["summary"]["total"], same
    assert {c["column"] for c in same["ignored_columns"]} == {"model", "software_version", "status"}

    mine[rows[0].index("Role")] = "Switch"
    mine[rows[0].index("Manufacturer")] = "Example Networks"
    mine[rows[0].index("Device Type")] = "EX-1"
    mine[rows[0].index("Owner")] = "'=net"
    changed = _ok(_commit(admin, "hosts", _csv([rows[0], mine]), mode="update"))
    assert changed["rows"][0]["changes"] == {
        "Role": {"before": "", "after": "Switch"},
        "Device Type": {"before": "", "after": "Example Networks EX-1"},
        "Owner": {"before": "@ops", "after": "=net"},
    }
    data = _ok(admin.get(f"/api/hosts/{hid}/custom-data"))
    assert data["fields"] == {"owner": "=net", "units": 2}
    assert [t["name"] for t in data["tags"]] == ["=cmd"]

    exported_yaml = admin.get("/api/inventory/export/yaml")
    assert exported_yaml.status_code == 200
    record = next(r for r in yaml.safe_load(exported_yaml.text) if r["hostname"] == "sw1")
    assert record["group"] == "east / core" and record["custom_fields"] == {"owner": "=net", "units": 2}
    assert record["tags"] == ["=cmd"] and record["role"] == "Switch"
    again = _ok(_preview(admin, "hosts", exported_yaml.text, fmt="yaml", mode="update"))
    assert again["summary"]["skip"] == again["summary"]["total"], again


def test_reference_errors(admin):
    _group(admin, "core")
    _group(admin, "dup", _group(admin, "north"))
    _group(admin, "dup", _group(admin, "west"))
    head = [*HOST_HEAD, "Role", "Lifecycle Status", "Site", "Manufacturer", "Device Type", "VRF", "VLAN", "Password"]
    text = _csv(
        [
            head,
            ["a", "192.0.2.1", "nowhere", "", "", "", "", "", "", "", "pw"],
            ["b", "192.0.2.2", "core", "Wizard", "Lost", "Atlantis", "", "", "", "", ""],
            ["c", "192.0.2.3", "core", "", "", "", "Example", "", "BLUE", "77", ""],
            ["d", "192.0.2.4", "core", "", "", "", "", "Nope", "", "", ""],
            ["e", "not-an-ip", "dup", "", "", "", "", "", "", "", ""],
            ["f", "127.0.0.1", "core", "", "", "", "", "", "", "", ""],
            ["", "", "core", "", "", "", "", "", "", "", ""],
        ]
    )
    report = _commit(admin, "hosts", text)
    assert report.status_code == 422
    body = report.json()
    assert not body["committed"] and body["summary"]["error"] == 7
    fields = [{e["field"] for e in r["errors"]} for r in body["rows"]]
    assert fields[0] == {"group"}
    assert fields[1] == {"role", "lifecycle_status", "site"}
    assert fields[2] == {"device_type", "vrf", "vlan"}
    assert fields[3] == {"device_type"}
    assert fields[4] == {"ip_address", "group"}
    assert fields[5] == {"ip_address"}
    assert fields[6] == {"hostname"}
    assert {"column": "password", "reason": "Secrets cannot be imported."} in body["ignored_columns"]
    assert _hosts() == {}


def test_duplicates_in_file_and_ambiguous_match(admin):
    gid = _group(admin, "core")
    _host(admin, gid, "twin", "192.0.2.1")
    _host(admin, _group(admin, "other"), "twin", "192.0.2.2")
    text = _csv([HOST_HEAD, ["n1", "192.0.2.5", "core"], ["n1", "192.0.2.6", "core"], ["n2", "192.0.2.1", "core"]])
    rows = _ok(_preview(admin, "hosts", text))["rows"]
    assert rows[1]["errors"][0]["message"] == "Row 2 has the same hostname."
    assert "already exists in this group" in rows[2]["errors"][0]["message"]
    twin = _ok(_preview(admin, "hosts", _csv([HOST_HEAD, ["twin", "192.0.2.9", "core"]]), mode="update"))["rows"][0]
    assert twin["errors"][0]["message"].startswith("Matches 2 hosts")


def test_tags_are_created_on_commit_only(admin):
    _group(admin, "core")
    text = _csv([[*HOST_HEAD, "Tags"], ["sw1", "192.0.2.1", "core", "fresh; Fresh"]])
    preview = _ok(_preview(admin, "hosts", text))
    assert preview["new_tags"] == ["fresh"]
    assert all(t["name"] != "fresh" for t in _ok(admin.get("/api/tags")))
    _ok(_commit(admin, "hosts", text))
    assert any(t["name"] == "fresh" for t in _ok(admin.get("/api/tags")))


def test_all_or_nothing_rolls_back_a_failed_write(admin, monkeypatch):
    _group(admin, "core")
    real = db.add_host
    calls = {"n": 0}

    async def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("disk full")
        return await real(*args, **kwargs)

    monkeypatch.setattr(db, "add_host", flaky)
    text = _csv([[*HOST_HEAD, "Tags"], ["sw1", "192.0.2.1", "core", "brand-new"], ["sw2", "192.0.2.2", "core", ""]])
    resp = _commit(admin, "hosts", text)
    assert resp.status_code == 422
    body = resp.json()
    assert body["message"] == "Nothing was imported: row 3 failed and every write was rolled back."
    assert body["rows"][1]["errors"][0]["message"] == "The write failed: RuntimeError: disk full"
    assert _hosts() == {}
    assert all(t["name"] != "brand-new" for t in _ok(admin.get("/api/tags")))

    # Stop on first error: the rows before the failing one stay.
    calls["n"] = 0
    resp = _commit(admin, "hosts", text, atomic="false")
    assert resp.status_code == 200
    body = resp.json()
    assert body["applied"] == 1 and body["message"].startswith("Stopped at row 3")
    assert set(_hosts()) == {"sw1"}


def test_stop_on_first_error_row(admin):
    _group(admin, "core")
    text = _csv(
        [HOST_HEAD, ["sw1", "192.0.2.1", "core"], ["sw2", "192.0.2.2", "nowhere"], ["sw3", "192.0.2.3", "core"]]
    )
    assert _commit(admin, "hosts", text).status_code == 422
    assert _hosts() == {}
    body = _ok(_commit(admin, "hosts", text, atomic="false"))
    assert body["applied"] == 1 and body["message"].startswith("Stopped at row 3: it has errors.")
    assert set(_hosts()) == {"sw1"}


def test_object_change_events_fire(admin):
    events: list[dict] = []

    async def hook(event: dict) -> None:
        events.append(event)

    add_object_change_hook(hook)
    try:
        _group(admin, "core")
        events.clear()
        _ok(_commit(admin, "hosts", _csv([HOST_HEAD, ["sw1", "192.0.2.1", "core"], ["sw2", "192.0.2.2", "core"]])))
        _ok(_commit(admin, "groups", _csv([["Name", "Parent"], ["edge", "core"]])))
    finally:
        remove_object_change_hook(hook)
    assert [e["event"] for e in events] == ["host.create", "host.create", "group.create"]
    assert {e["after"]["hostname"] for e in events[:2]} == {"sw1", "sw2"}


def test_scoped_user_imports_only_into_writable_groups(admin):
    a = _group(admin, "site-a")
    b = _group(admin, "site-b")
    _group(admin, "hidden")
    _host(admin, b, "b-host", "198.51.100.2")
    scoped = _scoped(
        admin,
        "importer",
        [{"inventory_group_id": a, "can_write": True}, {"inventory_group_id": b, "can_write": False}],
        features=("inventory", "inventory.write"),
    )
    text = _csv(
        [
            HOST_HEAD,
            ["a-new", "198.51.100.1", "site-a"],
            ["b-new", "198.51.100.3", "site-b"],
            ["h", "198.51.100.4", "hidden"],
        ]
    )
    rows = _ok(_preview(scoped, "hosts", text))["rows"]
    assert rows[0]["action"] == "create"
    assert rows[1]["errors"] == [{"field": "group", "message": "Read-only access to this inventory group"}]
    assert rows[2]["errors"] == [{"field": "group", "message": "No group 'hidden'."}]
    update = _ok(_preview(scoped, "hosts", _csv([HOST_HEAD, ["b-host", "198.51.100.9", "site-b"]]), mode="update"))
    assert update["rows"][0]["errors"][0]["message"] == "Read-only access to this inventory group"
    groups = _ok(
        _preview(scoped, "groups", _csv([["Name", "Parent"], ["top", ""], ["rack", "site-a"], ["x", "site-b"]]))
    )
    assert [r["action"] for r in groups["rows"]] == ["error", "create", "error"]
    assert _ok(_commit(scoped, "hosts", _csv([HOST_HEAD, ["a-new", "198.51.100.1", "site-a"]])))["applied"] == 1
    reader = user_client(admin, "inv-reader", features=["inventory"])
    assert _preview(reader, "hosts", text).status_code == 403


# ── Groups ───────────────────────────────────────────────────────────────────


def test_groups_nested_in_one_file_and_update(admin):
    _ok(
        admin.post(
            "/api/custom-fields",
            json={"key": "code", "label": "Site code", "field_type": "text", "object_types": ["group"]},
        ),
        201,
    )
    text = _csv(
        [
            ["Name", "Parent", "Description", "Site code"],
            ["east", "", "East", "E1"],
            ["core", "east", "", ""],
            ["rack", "east / core", "", ""],
            ["bad / name", "", "", ""],
            ["orphan", "missing", "", ""],
        ]
    )
    preview = _ok(_preview(admin, "groups", text))
    assert [r["action"] for r in preview["rows"]] == ["create", "create", "create", "error", "error"]
    assert _ok(_commit(admin, "groups", _csv(_rows_upto(text, 4))))["applied"] == 3
    paths = {g["path"]: g for g in _ok(admin.get("/api/inventory"))}
    assert {"east", "east / core", "east / core / rack"} <= set(paths)
    assert _ok(admin.get(f"/api/inventory/{paths['east']['id']}/custom-data"))["fields"] == {"code": "E1"}
    updated = _ok(_commit(admin, "groups", _csv([["Name", "Description"], ["east", "Eastern"]]), mode="update"))
    assert updated["rows"][0]["changes"] == {"Description": {"before": "East", "after": "Eastern"}}


def _rows_upto(text: str, n: int) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))[:n]


# ── Prefixes, addresses, VLANs, VRFs ─────────────────────────────────────────


def test_ipam_imports_need_admin(admin):
    user = user_client(admin, "ipam-writer", features=["ipam", "ipam.write"])
    assert user.get(f"{IPAM}/vrfs/template").status_code == 200
    assert _preview(user, "vrfs", _csv([["Name"], ["blue"]]), family=IPAM).status_code == 403
    assert admin.get(f"{IPAM}/hosts/template").status_code == 404


def test_vrfs_vlans_prefixes_and_addresses(admin):
    import asyncio

    asyncio.run(db.create_geo_site(name="HQ"))
    vrfs = _ok(_commit(admin, "vrfs", _csv([["Name", "RD"], ["BLUE", "65000:1"], ["red", ""]]), family=IPAM))
    assert vrfs["applied"] == 2
    upd = _ok(_commit(admin, "vrfs", _csv([["Name", "Description"], ["blue", "Blue net"]]), family=IPAM, mode="upsert"))
    assert upd["rows"][0]["changes"] == {"Description": {"before": "", "after": "Blue net"}}

    vlans = _ok(
        _commit(admin, "vlans", _csv([["VLAN ID", "Name", "Site"], ["10", "users", "HQ"], ["20", "", ""]]), family=IPAM)
    )
    assert vlans["applied"] == 2
    bad = _ok(_preview(admin, "vlans", _csv([["VLAN ID", "Site"], ["5000", ""], ["30", "Mars"]]), family=IPAM))
    assert [e["field"] for r in bad["rows"] for e in r["errors"]] == ["vid", "site"]
    renamed = _ok(
        _commit(admin, "vlans", _csv([["VLAN ID", "Site", "Name"], ["10", "HQ", "staff"]]), family=IPAM, mode="update")
    )
    assert renamed["rows"][0]["changes"] == {"Name": {"before": "users", "after": "staff"}}

    _ok(
        admin.post(
            "/api/custom-fields",
            json={"key": "owner", "label": "Owner", "field_type": "text", "object_types": ["prefix"]},
        ),
        201,
    )
    prefixes = _ok(
        _commit(
            admin,
            "prefixes",
            _csv(
                [
                    ["Prefix", "VRF", "Site", "VLAN", "Owner"],
                    ["192.0.2.0/24", "blue", "HQ", "10", "net"],
                    ["198.51.100.7/24", "", "", "", ""],
                ]
            ),
            family=IPAM,
        )
    )
    assert prefixes["applied"] == 2
    assert prefixes["rows"][1]["warnings"] == ["Stored as 198.51.100.0/24."]
    records = {r["subnet"]: r for r in asyncio.run(db.list_ipam_prefix_records())}
    assert records["192.0.2.0/24"]["vrf"] == "BLUE" and records["192.0.2.0/24"]["vlan"] == "10"
    assert _ok(admin.get("/api/ipam/prefix-custom-data?subnet=192.0.2.0/24&vrf=BLUE"))["fields"] == {"owner": "net"}
    bad_prefix = _ok(
        _preview(
            admin,
            "prefixes",
            _csv([["Prefix", "VRF", "VLAN"], ["203.0.113.0/24", "green", "99"], ["nope", "", ""]]),
            family=IPAM,
        )
    )
    assert [{e["field"] for e in r["errors"]} for r in bad_prefix["rows"]] == [{"vrf", "vlan"}, {"prefix"}]
    clash = _ok(_preview(admin, "prefixes", _csv([["Prefix", "VRF"], ["198.51.100.0/24", "red"]]), family=IPAM))
    assert "defines 198.51.100.0/24 already" in clash["rows"][0]["errors"][0]["message"]
    desc = _ok(
        _commit(
            admin, "prefixes", _csv([["Prefix", "Description"], ["198.51.100.0/24", "lab"]]), family=IPAM, mode="update"
        )
    )
    assert desc["rows"][0]["changes"] == {"Description": {"before": "", "after": "lab"}}

    addresses = _ok(
        _commit(
            admin,
            "addresses",
            _csv([["Address", "VRF", "DNS Name"], ["192.0.2.10", "blue", "a.example.com"], ["198.51.100.5", "", ""]]),
            family=IPAM,
        )
    )
    assert addresses["applied"] == 2
    allocs = {a["address"]: a for a in asyncio.run(db.list_ipam_allocation_records())}
    assert allocs["192.0.2.10"]["prefix_subnet"] == "192.0.2.0/24" and allocs["192.0.2.10"]["vrf_name"] == "BLUE"
    no_prefix = _ok(
        _preview(
            admin,
            "addresses",
            _csv([["Address", "Prefix"], ["203.0.113.5", ""], ["192.0.2.11", "198.51.100.0/24"]]),
            family=IPAM,
        )
    )
    assert [e["field"] for r in no_prefix["rows"] for e in r["errors"]] == ["prefix", "prefix"]
    dns = _ok(
        _commit(
            admin,
            "addresses",
            _csv([["Address", "DNS Name"], ["198.51.100.5", "b.example.com"]]),
            family=IPAM,
            mode="update",
        )
    )
    assert dns["rows"][0]["changes"] == {"DNS Name": {"before": "", "after": "b.example.com"}}


def test_validation_rules_apply_to_imported_rows(admin):
    from netcontrol import data_validation

    data_validation.invalidate_rules_cache()
    try:
        rule = {"object_type": "host", "field": "hostname", "rule_type": "regex", "params": {"pattern": "sw-[0-9]+"}}
        _ok(admin.post("/api/validation-rules", json={"name": "hostname pattern", **rule}), 201)
        _ok(
            admin.post(
                "/api/validation-rules",
                json={"name": "address dns", "object_type": "ip_address", "field": "hostname", "rule_type": "required"},
            ),
            201,
        )
        _group(admin, "core")
        text = _csv([HOST_HEAD, ["sw-1", "192.0.2.41", "core"], ["bad_name", "192.0.2.42", "core"]])

        preview = _ok(_preview(admin, "hosts", text))
        assert [r["action"] for r in preview["rows"]] == ["create", "error"]
        assert preview["rows"][1]["errors"][0]["field"] == "hostname"

        refused = _commit(admin, "hosts", text)
        assert refused.status_code == 422
        assert "sw-1" not in _hosts() and "bad_name" not in _hosts()
        assert _ok(_commit(admin, "hosts", _csv([HOST_HEAD, ["sw-2", "192.0.2.43", "core"]])))["applied"] == 1
    finally:
        data_validation.invalidate_rules_cache()
