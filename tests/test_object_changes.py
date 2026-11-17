"""The per-object change log (``netcontrol.routes.object_changes``): every
tracked create/update/delete is recorded with its field diff, user and
correlation id; secrets never reach the table; the API filters by feature
per object type and by the caller's inventory groups; old rows are pruned
after the configurable retention; and the tracking gaps closed with it emit
events."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import netcontrol.app as app_module
import pytest
import routes.database as db
from netcontrol.routes import object_changes as oc, state
from routes.db import change_events
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

CHANGES = "/api/changes"


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _group(admin: CsrfClient, name: str) -> int:
    return int(_ok(admin.post("/api/inventory", json={"name": name}), 201)["id"])


def _host(admin: CsrfClient, gid: int, name: str, ip: str) -> int:
    body = {"hostname": name, "ip_address": ip, "device_type": "cisco_ios"}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


def _scoped_client(admin: CsrfClient, username: str, group_id: int, features: list[str]) -> CsrfClient:
    """A user limited to inventory group ``group_id`` (read only)."""
    group = _ok(
        admin.post(
            "/api/admin/access-groups",
            json={
                "name": f"{username} access",
                "feature_keys": features,
                "object_scope": "groups",
                "inventory_scopes": [{"inventory_group_id": group_id, "can_write": False}],
            },
        ),
        201,
    )
    _ok(
        admin.post(
            "/api/admin/users", json={"username": username, "password": "password123", "group_ids": [group["id"]]}
        ),
        201,
    )
    client = TestClient(app_module.app, raise_server_exceptions=False)
    resp = client.post("/api/auth/login", json={"username": username, "password": "password123"})
    assert resp.status_code == 200, resp.text
    return CsrfClient(client, resp.json()["csrf_token"])


# ── Recording and diff content ───────────────────────────────────────────────


def test_host_lifecycle_is_recorded_with_field_diff(admin):
    gid = _group(admin, "core")
    host_id = _host(admin, gid, "edge-r1", "192.0.2.10")
    resp = admin.put(
        f"/api/hosts/{host_id}",
        json={"hostname": "edge-r2", "ip_address": "192.0.2.11"},
        headers={"X-Correlation-ID": "corr-test-1"},
    )
    _ok(resp)
    _ok(admin.delete(f"/api/hosts/{host_id}"))

    body = _ok(admin.get(f"{CHANGES}/host/{host_id}"))
    assert body["total"] == 3
    delete, update, create = body["changes"]  # newest first
    assert [c["action"] for c in (create, update, delete)] == ["create", "update", "delete"]
    assert all(c["user"] == "admin" and c["object_id"] == str(host_id) for c in body["changes"])

    assert create["before"] is None and create["after"]["hostname"] == "edge-r1"
    assert create["object_label"] == "edge-r1"
    assert update["changes"]["hostname"] == {"before": "edge-r1", "after": "edge-r2"}
    assert update["changes"]["ip_address"] == {"before": "192.0.2.10", "after": "192.0.2.11"}
    assert "group_id" not in update["changes"]  # unchanged fields are not in the diff
    assert update["correlation_id"] == "corr-test-1"
    assert delete["after"] is None and delete["before"]["hostname"] == "edge-r2"
    assert delete["object_label"] == "edge-r2"  # still readable after the host is gone

    groups = _ok(admin.get(f"{CHANGES}/group/{gid}"))
    assert [c["action"] for c in groups["changes"]] == ["create"]
    assert groups["changes"][0]["object_label"] == "core"


def test_ipam_objects_are_recorded(admin):
    vlan = _ok(admin.post("/api/ipam/vlans", json={"vid": 120, "name": "users"}), 201)
    _ok(admin.put(f"/api/ipam/vlans/{vlan['id']}", json={"name": "staff"}))
    prefix = _ok(admin.post("/api/ipam/prefixes", json={"subnet": "198.51.100.0/24", "description": "lab"}), 201)[
        "prefix"
    ]

    vlan_log = _ok(admin.get(f"{CHANGES}/vlan/{vlan['id']}"))["changes"]
    assert [c["action"] for c in vlan_log] == ["update", "create"]
    assert vlan_log[0]["changes"]["name"] == {"before": "users", "after": "staff"}
    assert vlan_log[0]["object_label"] == "120 staff"

    by_label = _ok(admin.get(CHANGES, params={"object_type": "prefix", "object_label": "198.51.100.0/24"}))
    assert by_label["total"] == 1
    assert by_label["changes"][0]["object_id"] == str(prefix["id"])


def test_secrets_never_reach_the_change_log(admin):
    resp = admin.post(
        "/api/credentials",
        json={"name": "lab-cred", "username": "netops", "password": "Sup3rS3cretPW", "secret": "En4bleS3cret"},
    )
    cred = _ok(resp, 201)
    body = _ok(admin.get(f"{CHANGES}/credential/{cred['id']}"))
    assert body["total"] == 1
    after = body["changes"][0]["after"]
    assert "password" not in after and "secret" not in after
    assert after["username"] == "netops"
    text = json.dumps(body)
    assert "Sup3rS3cretPW" not in text and "En4bleS3cret" not in text


async def test_recorder_masks_secret_looking_keys():
    await oc.on_object_change(
        {
            "event": "vrf.update",
            "object_type": "vrf",
            "action": "update",
            "object_id": "7",
            "timestamp": "2026-01-02T03:04:05Z",
            "user": "alice",
            "correlation_id": "",
            "before": {"id": 7, "name": "blue", "api_key": "k-old"},
            "after": {"id": 7, "name": "blue", "api_key": "k-new"},
            "changes": {"api_key": {"before": "k-old", "after": "k-new"}},
        }
    )
    rows, total = await db.list_object_changes(object_types=["vrf"], object_id="7")
    assert total == 1
    row = rows[0]
    assert row["changed_at"] == "2026-01-02 03:04:05"
    assert row["object_label"] == "blue"
    assert "k-old" not in json.dumps(row) and "k-new" not in json.dumps(row)


# ── Access: features per type, object scope ──────────────────────────────────


def test_changes_follow_the_feature_of_each_type(admin):
    gid = _group(admin, "core")
    _host(admin, gid, "edge-r1", "192.0.2.20")
    _ok(admin.post("/api/ipam/vrfs", json={"name": "blue"}), 201)

    ipam_only = user_client(admin, "ipam-reader", features=["ipam"])
    assert ipam_only.get(f"{CHANGES}?object_type=host").status_code == 403
    body = _ok(ipam_only.get(CHANGES))
    assert {c["object_type"] for c in body["changes"]} == {"vrf"}
    assert "host" not in body["object_types"] and "credential" not in body["object_types"]

    nothing = user_client(admin, "dash-only", features=["dashboard"])
    assert nothing.get(CHANGES).status_code == 403

    # Credentials belong to their owners: admins only.
    inv = user_client(admin, "cred-user", features=["inventory", "credentials"])
    assert inv.get(f"{CHANGES}?object_type=credential").status_code == 403


def test_scoped_user_sees_only_changes_in_readable_groups(admin):
    core, edge = _group(admin, "core"), _group(admin, "edge")
    in_scope = _host(admin, core, "core-r1", "192.0.2.30")
    out_scope = _host(admin, edge, "edge-r1", "203.0.113.30")
    _ok(admin.put(f"/api/hosts/{out_scope}", json={"hostname": "edge-r9", "ip_address": "203.0.113.30"}))
    _ok(admin.post("/api/ipam/vlans", json={"vid": 300, "name": "voice"}), 201)

    scoped = _scoped_client(admin, "scoped-reader", core, ["inventory", "ipam"])
    body = _ok(scoped.get(CHANGES))
    seen = {(c["object_type"], c["object_id"]) for c in body["changes"]}
    assert seen == {("group", str(core)), ("host", str(in_scope))}
    assert set(body["object_types"]) <= set(oc.SCOPED_TYPES)

    assert _ok(scoped.get(f"{CHANGES}/host/{out_scope}"))["changes"] == []
    assert _ok(scoped.get(f"{CHANGES}/group/{edge}"))["changes"] == []
    assert _ok(scoped.get(f"{CHANGES}/host/{in_scope}"))["total"] == 1
    # IPAM is not available to accounts limited to selected groups.
    assert scoped.get(f"{CHANGES}?object_type=vlan").status_code == 403


# ── Filters and pagination ───────────────────────────────────────────────────


async def _seed(rows: list[dict]) -> None:
    for row in rows:
        await db.add_object_change(**row)


async def test_list_filters_and_pagination():
    base = {"object_type": "vrf", "object_label": "blue", "changes": {}}
    await _seed(
        [
            {**base, "object_id": "1", "action": "create", "user": "alice", "changed_at": "2026-01-01 10:00:00"},
            {**base, "object_id": "1", "action": "update", "user": "bob", "changed_at": "2026-01-02 10:00:00"},
            {**base, "object_id": "2", "action": "create", "user": "alice", "changed_at": "2026-01-03 10:00:00"},
            {**base, "object_id": "2", "action": "delete", "user": "bob", "changed_at": "2026-01-04 10:00:00"},
        ]
    )
    rows, total = await db.list_object_changes(object_types=["vrf"], user="alice")
    assert total == 2 and {r["object_id"] for r in rows} == {"1", "2"}
    rows, total = await db.list_object_changes(object_types=["vrf"], action="delete")
    assert total == 1 and rows[0]["object_id"] == "2"
    rows, total = await db.list_object_changes(
        object_types=["vrf"], since="2026-01-02 00:00:00", until="2026-01-03 23:59:59"
    )
    assert [r["changed_at"][:10] for r in rows] == ["2026-01-03", "2026-01-02"]
    rows, total = await db.list_object_changes(object_types=["vrf"], limit=1, offset=1)
    assert total == 4 and len(rows) == 1 and rows[0]["changed_at"].startswith("2026-01-03")
    assert await db.list_object_changes(object_types=[]) == ([], 0)
    rows, total = await db.list_object_changes(object_types=["host"])
    assert total == 0


def test_api_filters_and_validation(admin):
    gid = _group(admin, "core")
    host_id = _host(admin, gid, "edge-r1", "192.0.2.40")
    _ok(admin.put(f"/api/hosts/{host_id}", json={"hostname": "edge-r2", "ip_address": "192.0.2.40"}))
    today = datetime.now(UTC).strftime("%Y-%m-%d")

    assert _ok(admin.get(CHANGES, params={"object_type": "host", "action": "update"}))["total"] == 1
    assert _ok(admin.get(CHANGES, params={"user": "admin", "object_type": "host"}))["total"] == 2
    assert _ok(admin.get(CHANGES, params={"user": "nobody"}))["total"] == 0
    assert _ok(admin.get(CHANGES, params={"since": today, "until": today, "object_type": "host"}))["total"] == 2
    assert _ok(admin.get(CHANGES, params={"until": "2000-01-01"}))["total"] == 0
    page = _ok(admin.get(CHANGES, params={"limit": 1, "offset": 0}))
    assert len(page["changes"]) == 1 and page["total"] >= 3 and page["limit"] == 1

    assert admin.get(CHANGES, params={"object_type": "widget"}).status_code == 400
    assert admin.get(CHANGES, params={"action": "rename"}).status_code == 400
    assert admin.get(CHANGES, params={"since": "yesterday"}).status_code == 400
    assert admin.get(CHANGES, params={"limit": 0}).status_code == 422
    assert admin.get(f"{CHANGES}/widget/1").status_code == 400


# ── Retention ────────────────────────────────────────────────────────────────


async def test_prune_removes_rows_past_retention(monkeypatch):
    old = (datetime.now(UTC) - timedelta(days=40)).strftime(db.OBJECT_CHANGE_TIME_FORMAT)
    fresh = (datetime.now(UTC) - timedelta(days=5)).strftime(db.OBJECT_CHANGE_TIME_FORMAT)
    base = {"object_type": "vrf", "object_id": "1", "action": "update"}
    await _seed([{**base, "changed_at": old}, {**base, "changed_at": fresh}])
    monkeypatch.setitem(state.AUTH_CONFIG, "change_log_retention_days", 30)
    assert oc.retention_days() == 30
    assert await oc.prune_once() == 1
    rows, total = await db.list_object_changes(object_types=["vrf"])
    assert total == 1 and rows[0]["changed_at"] == fresh


def test_retention_setting_round_trip(admin):
    cfg = _ok(admin.get("/api/admin/auth-config"))
    assert cfg["change_log_retention_days"] == 90
    saved = _ok(admin.put("/api/admin/auth-config", json={**cfg, "change_log_retention_days": 14}))
    assert saved["change_log_retention_days"] == 14
    # A client that does not send the key keeps the saved value.
    legacy = {k: v for k, v in saved.items() if k != "change_log_retention_days"}
    assert _ok(admin.put("/api/admin/auth-config", json=legacy))["change_log_retention_days"] == 14
    assert admin.put("/api/admin/auth-config", json={**cfg, "change_log_retention_days": 0}).status_code == 422
    assert state._sanitize_auth_config({"change_log_retention_days": 99999})["change_log_retention_days"] == 3650


# ── Tracking gaps closed with the change log ─────────────────────────────────


async def test_host_attribute_setters_emit_updates():
    events: list[dict] = []

    async def hook(event: dict) -> None:
        events.append(event)

    gid = await db.create_group("core")
    host_id = await db.add_host(gid, "edge-r1", "192.0.2.50")
    change_events.add_object_change_hook(hook)
    try:
        await db.update_host_serial(host_id, "SN-0001")
        await db.update_host_device_info(host_id, "C9300", "17.9.4")
        await db.set_hosts_snmp_profile([host_id], "profile-a")
        await db.set_host_device_fields(host_id, {"serial_number": "SN-0001"})  # no field it sets changes
    finally:
        change_events.remove_object_change_hook(hook)
    changed = [sorted(e["changes"]) for e in events]
    assert [e["action"] for e in events] == ["update", "update", "update"]
    assert "serial_number" in changed[0]
    assert {"model", "software_version"} <= set(changed[1])
    assert changed[2] == ["snmp_profile_id"]
