"""HTTP tests for the topology mute routes (``/api/availability/topology/mutes``).

Covers create / list / delete, reason validation, unknown targets, the
acknowledgement of open alerts on mute, the monitoring feature gate and the
audit trail. All names, serials and addresses are invented.
"""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.topology_availability as tracking
import pytest
import routes.database as db_module

MUTES = "/api/availability/topology/mutes"
DEVICE = {
    "entity_type": "device",
    "entity_id": "d:Q2XX-AAAA-0001",
    "name": "Branch-12 MX",
    "state": "down",
    "site": "Branch-12",
    "host_id": 9411,
}


async def _seed() -> None:
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (941, 'Branches')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type) "
            "VALUES (9411, 941, 'branch-12-mx.example.com', '192.0.2.12', 'meraki')"
        )
        await db.commit()
    finally:
        await db.close()
    await db_module.apply_topology_entity_states("meraki", 7, [DEVICE], org_name="Example Org")


@pytest.fixture
def client(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-topology-mutes")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    from starlette.testclient import TestClient

    test_client = TestClient(app_module.app, raise_server_exceptions=False)
    test_client.__enter__()
    request.addfinalizer(lambda: test_client.__exit__(None, None, None))
    asyncio.run(_seed())
    resp = test_client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert resp.status_code == 200, resp.text
    return test_client, {"X-CSRF-Token": resp.json().get("csrf_token", "")}


def _body(**fields) -> dict:
    return {
        "provider": "meraki",
        "org_ref": 7,
        "scope": "entity",
        "entity_type": "device",
        "entity_id": DEVICE["entity_id"],
        "reason": "not installed yet",
        **fields,
    }


def test_create_list_delete_mute(client):
    test_client, headers = client
    resp = test_client.post(MUTES, json=_body(reason="  not installed yet  "), headers=headers)
    assert resp.status_code == 201, resp.text
    mute = resp.json()["mute"]
    assert mute["scope"] == "entity" and mute["reason"] == "not installed yet" and mute["created_by"] == "admin"
    assert resp.json()["acknowledged"] == 0
    listed = test_client.get(MUTES).json()["mutes"]
    assert [m["id"] for m in listed] == [mute["id"]]
    site = test_client.post(
        MUTES, json=_body(scope="site", entity_type="", entity_id="", site="Branch-12"), headers=headers
    )
    assert site.status_code == 201, site.text
    assert site.json()["mute"]["site"] == "Branch-12" and site.json()["mute"]["entity_id"] == ""
    assert test_client.delete(f"{MUTES}/{mute['id']}", headers=headers).json() == {"ok": True}
    assert test_client.delete(f"{MUTES}/{mute['id']}", headers=headers).status_code == 404
    assert [m["id"] for m in test_client.get(MUTES).json()["mutes"]] == [site.json()["mute"]["id"]]


def test_reason_required_and_bounded(client):
    test_client, headers = client
    for reason in ("", "   ", "x" * 501):
        assert test_client.post(MUTES, json=_body(reason=reason), headers=headers).status_code == 400
    assert test_client.post(MUTES, json=_body(reason="x" * 500), headers=headers).status_code == 201
    assert test_client.post(MUTES, json=_body(provider="bogus"), headers=headers).status_code == 422
    assert test_client.post(MUTES, json=_body(scope="org"), headers=headers).status_code == 422
    assert test_client.post(MUTES, json=_body(entity_type="vpc"), headers=headers).status_code == 422


def test_unknown_entity_or_site_is_404(client):
    test_client, headers = client
    for body in (
        _body(entity_id="d:Q2XX-AAAA-0999"),
        _body(org_ref=8),
        _body(provider="cato"),
        _body(entity_id=""),
        _body(entity_type=""),
        _body(scope="site", entity_type="", entity_id="", site="Nowhere"),
        _body(scope="site", entity_type="", entity_id="", site=""),
    ):
        assert test_client.post(MUTES, json=body, headers=headers).status_code == 404, body
    assert test_client.get(MUTES).json() == {"mutes": []}


def test_mute_acknowledges_open_host_alert(client):
    test_client, headers = client
    key = tracking.dedup_key({"provider": "meraki", "org_ref": 7, **DEVICE})
    asyncio.run(
        db_module.create_monitoring_alert(
            host_id=9411,
            poll_id=None,
            alert_type=tracking.ALERT_TYPE,
            metric="topology device",
            message="Device Branch-12 MX is down",
            severity="critical",
            dedup_key=key,
            hostname="Branch-12 MX",
        )
    )
    resp = test_client.post(MUTES, json=_body(), headers=headers)
    assert resp.status_code == 201, resp.text
    assert resp.json()["acknowledged"] == 1
    (alert,) = asyncio.run(db_module.get_monitoring_alerts(host_id=9411))
    assert alert["acknowledged"] and alert["acknowledged_by"] == "muted"


def test_mute_requires_monitoring_feature(client):
    test_client, headers = client
    group_id = asyncio.run(db_module.create_access_group("viewer group", "", ["dashboard"]))
    resp = test_client.post(
        "/api/admin/users",
        json={"username": "viewer", "password": "password123", "role": "user", "group_ids": [group_id]},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    resp = test_client.post("/api/auth/login", json={"username": "viewer", "password": "password123"})
    assert resp.status_code == 200, resp.text
    viewer = {"X-CSRF-Token": resp.json().get("csrf_token", "")}
    assert test_client.get(MUTES).status_code == 403
    assert test_client.post(MUTES, json=_body(), headers=viewer).status_code == 403
    assert test_client.delete(f"{MUTES}/1", headers=viewer).status_code == 403


def test_mute_and_unmute_are_audited(client):
    test_client, headers = client
    mute = test_client.post(MUTES, json=_body(reason="secret plan"), headers=headers).json()["mute"]
    assert test_client.delete(f"{MUTES}/{mute['id']}", headers=headers).status_code == 200
    events = asyncio.run(db_module.get_audit_events(50, "monitoring"))
    actions = {e["action"]: e for e in events if e["action"].startswith("topology.")}
    assert set(actions) == {"topology.muted", "topology.unmuted"}
    expected = f"meraki:7 entity device:{DEVICE['entity_id']}"
    assert actions["topology.muted"]["detail"] == expected and actions["topology.unmuted"]["detail"] == expected
    assert actions["topology.muted"]["user"] == "admin"
    assert all("secret plan" not in str(e.get("detail")) for e in events)
