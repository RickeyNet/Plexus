"""Discovery and the Plexus service credential (security audit finding 18).

A discovery scan or sync with no credential of the caller's own signs in
with the Plexus service credential. Its addresses come from the request, so
for a non-admin that fallback is allowed only when every address is an
inventory host the caller may change; otherwise the request is refused
(403) and the caller picks a credential, turns SSH off, or asks an admin.
"""

from __future__ import annotations

import asyncio

import netcontrol.routes.inventory as inventory
import pytest
import routes.database as db_module
from routes.crypto import encrypt

INVENTORY_IP = "192.0.2.41"
OUTSIDE_IP = "203.0.113.9"


def _msg(r) -> str:
    """The message of an /api/ error response (``{ok, error: {code, message}}``)."""
    return r.json()["error"]["message"]


@pytest.fixture
def env(monkeypatch, request):
    import netcontrol.app as app_module
    from starlette.testclient import TestClient

    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")

    probed: list[tuple[str, dict | None]] = []

    async def _no_probe(ip_address, body, snmp_cfg, semaphore, credential, **_kw):
        # No traffic: record what would have been probed, and with what.
        probed.append((ip_address, credential))
        return None

    monkeypatch.setattr(inventory, "_scan_target", _no_probe)

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    admin_csrf = resp.json().get("csrf_token", "")
    r = client.post(
        "/api/admin/users",
        json={"username": "scanner", "password": "password123", "role": "user"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert r.status_code == 201, r.text

    async def _seed():
        scanner = await db_module.get_user_by_username("scanner")
        access = await db_module.create_access_group("ds-scanners", "", ["inventory", "inventory.write"])
        await db_module.set_user_groups(scanner["id"], [access])
        service = await db_module.create_credential("ds-service", "svc", encrypt("pw"), is_service=True)
        own = await db_module.create_credential("ds-own", "me", encrypt("pw"), owner_id=scanner["id"])
        group = await db_module.create_group("ds-group")
        # An admin's host: its address is confirmed (netcontrol.managed_targets).
        await db_module.add_host(group, "ds-sw1", INVENTORY_IP, address_confirmed=True)
        return {"service": service, "own": own, "group": group}

    ctx = asyncio.run(_seed())
    ctx["client"] = client
    ctx["admin"] = {"X-CSRF-Token": admin_csrf}
    ctx["probed"] = probed

    def login(user: str, password: str = "password123") -> dict:
        r = client.post("/api/auth/login", json={"username": user, "password": password})
        assert r.status_code == 200, r.text
        return {"X-CSRF-Token": r.json().get("csrf_token", "")}

    ctx["login"] = login
    return ctx


def _scan(ctx, headers, cidrs, *, path="scan", **body):
    payload = {"cidrs": cidrs, "use_snmp": False, "use_icmp": False}
    payload.update(body)
    return ctx["client"].post(f"/api/inventory/{ctx['group']}/discovery/{path}", json=payload, headers=headers)


@pytest.mark.parametrize("path", ["scan", "scan/stream", "sync", "sync/stream"])
def test_non_admin_may_not_use_the_service_credential_on_outside_addresses(env, path):
    r = _scan(env, env["login"]("scanner"), [f"{OUTSIDE_IP}/32"], path=path)
    assert r.status_code == 403, r.text
    assert "service credential" in _msg(r)
    assert OUTSIDE_IP in _msg(r)
    assert env["probed"] == []


def test_non_admin_with_own_credential_or_without_ssh_may_scan_any_address(env):
    headers = env["login"]("scanner")
    r = _scan(env, headers, [f"{OUTSIDE_IP}/32"], credential_id=env["own"])
    assert r.status_code == 202, r.text
    r = _scan(env, headers, [f"{OUTSIDE_IP}/32"], use_ssh=False)
    assert r.status_code == 202, r.text


def test_non_admin_may_use_the_service_credential_on_inventory_hosts(env):
    headers = env["login"]("scanner")
    r = _scan(env, headers, [f"{INVENTORY_IP}/32"])
    assert r.status_code == 202, r.text
    assert r.json()["total_targets"] == 1
    # A sync with no addresses re-reads the group's own hosts.
    r = _scan(env, headers, [], path="sync")
    assert r.status_code == 200, r.text
    assert r.json()["ssh_enrichment"]["credential_source"] == "service"


def test_admin_may_use_the_service_credential_on_any_address(env):
    r = _scan(env, env["login"]("admin", "netcontrol"), [f"{OUTSIDE_IP}/32"])
    assert r.status_code == 202, r.text


async def test_service_target_rule_unit():
    """The rule itself: no request (a direct or API-token call) passes."""
    await db_module.init_db()
    await inventory._require_service_targets(None, [OUTSIDE_IP])
