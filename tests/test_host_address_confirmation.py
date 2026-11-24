"""Shared secrets go only to a host address an admin set or confirmed.

A non-admin who may add or change inventory hosts could point a host at a
device they run; unattended collection would then sign in to it with the
Plexus service credential, the default credential or a shared SNMP
profile. ``hosts.address_confirmed`` records whether an admin (or the API
token) set the address, ``netcontrol.managed_targets`` holds the one rule,
and every collection path skips a host awaiting confirmation without
recording it as down.
"""

from __future__ import annotations

import asyncio
import importlib

import pytest
import routes.database as db
from netcontrol import managed_targets
from netcontrol.object_scope import UNRESTRICTED
from netcontrol.routes import state
from routes.crypto import encrypt

import pg_raw
from mcp_helpers import CsrfClient, admin_client, user_client

ADMIN_IP = "192.0.2.21"
USER_IP = "198.51.100.22"
ATTACKER_IP = "203.0.113.10"
WRITER_FEATURES = ["inventory", "inventory.write"]


def _flag(host_id: int) -> int:
    host = asyncio.run(db.get_host(host_id))
    assert host is not None
    return int(host["address_confirmed"])


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


@pytest.fixture
def group(admin) -> int:
    r = admin.post("/api/inventory", json={"name": "addr-confirm", "description": ""})
    assert r.status_code == 201, r.text
    return int(r.json()["id"])


# ── (a) who sets the address decides the flag ────────────────────────────────


def test_admin_created_host_is_confirmed_and_non_admin_host_is_not(admin, group):
    r = admin.post(f"/api/inventory/{group}/hosts", json={"hostname": "core-a", "ip_address": ADMIN_IP})
    assert r.status_code == 201, r.text
    assert _flag(r.json()["id"]) == 1

    writer = user_client(admin, "addr-writer", features=WRITER_FEATURES)
    r = writer.post(f"/api/inventory/{group}/hosts", json={"hostname": "edge-b", "ip_address": USER_IP})
    assert r.status_code == 201, r.text
    assert _flag(r.json()["id"]) == 0

    r = writer.post(
        f"/api/inventory/{group}/hosts/bulk", json={"hosts": [{"hostname": "edge-c", "ip_address": ATTACKER_IP}]}
    )
    assert r.status_code == 200, r.text
    assert _flag(r.json()["added"][0]["id"]) == 0

    # The listing carries the flag.
    listed = {h["hostname"]: h for h in admin.get(f"/api/inventory/{group}/hosts").json()}
    assert listed["core-a"]["address_confirmed"] == 1
    assert listed["edge-b"]["address_confirmed"] == 0
    groups = admin.get("/api/inventory?include_hosts=true").json()
    rows = {h["hostname"]: h for g in groups for h in g.get("hosts", [])}
    assert rows["edge-c"]["address_confirmed"] == 0


def test_re_addressing_by_a_non_admin_clears_the_flag_other_edits_keep_it(admin, group):
    host_id = admin.post(f"/api/inventory/{group}/hosts", json={"hostname": "core-a", "ip_address": ADMIN_IP}).json()[
        "id"
    ]
    writer = user_client(admin, "addr-editor", features=WRITER_FEATURES)

    # A rename keeps the confirmed address confirmed.
    r = writer.put(f"/api/hosts/{host_id}", json={"hostname": "core-renamed", "ip_address": ADMIN_IP})
    assert r.status_code == 200, r.text
    assert _flag(host_id) == 1

    r = writer.put(f"/api/hosts/{host_id}", json={"hostname": "core-renamed", "ip_address": ATTACKER_IP})
    assert r.status_code == 200, r.text
    assert _flag(host_id) == 0

    # An admin rename alone does not confirm it; an admin re-address does.
    r = admin.put(f"/api/hosts/{host_id}", json={"hostname": "core-b", "ip_address": ATTACKER_IP})
    assert r.status_code == 200, r.text
    assert _flag(host_id) == 0
    r = admin.put(f"/api/hosts/{host_id}", json={"hostname": "core-b", "ip_address": ADMIN_IP})
    assert r.status_code == 200, r.text
    assert _flag(host_id) == 1


def test_discovery_onboard_by_a_non_admin_stores_hosts_unconfirmed(admin, group):
    writer = user_client(admin, "addr-onboarder", features=WRITER_FEATURES)
    body = {"discovered_hosts": [{"ip_address": ATTACKER_IP, "hostname": "found-1"}]}
    r = writer.post(f"/api/inventory/{group}/discovery/onboard", json=body)
    assert r.status_code == 200, r.text
    (host,) = asyncio.run(db.get_hosts_for_group(group))
    assert int(host["address_confirmed"]) == 0

    body = {"discovered_hosts": [{"ip_address": ADMIN_IP, "hostname": "found-2"}]}
    assert admin.post(f"/api/inventory/{group}/discovery/onboard", json=body).status_code == 200
    flags = {h["ip_address"]: int(h["address_confirmed"]) for h in asyncio.run(db.get_hosts_for_group(group))}
    assert flags == {ATTACKER_IP: 0, ADMIN_IP: 1}


async def test_sync_without_a_caller_stores_unconfirmed_and_admin_profiles_confirm():
    import netcontrol.routes.inventory as inventory

    await db.init_db()
    gid = await db.create_group("addr-sync")

    async def no_walk(ip):
        return []

    await inventory._sync_group_hosts(
        gid, [{"ip_address": ATTACKER_IP, "hostname": "bg-1"}], interface_ip_resolver=no_walk
    )
    await inventory._sync_group_hosts(
        gid, [{"ip_address": ADMIN_IP, "hostname": "bg-2"}], interface_ip_resolver=no_walk, address_confirmed=True
    )
    flags = {h["ip_address"]: int(h["address_confirmed"]) for h in await db.get_hosts_for_group(gid)}
    assert flags == {ATTACKER_IP: 0, ADMIN_IP: 1}


async def test_api_token_actor_confirms_and_a_user_named_like_it_does_not():
    from routes.db.change_events import current_actor

    await db.init_db()
    token = current_actor.set("api-token")
    try:
        assert await managed_targets.caller_confirms_addresses() is True
        await db.create_user("api-token", "x", "salt", role="user")
        assert await managed_targets.caller_confirms_addresses() is False
    finally:
        current_actor.reset(token)
    assert await managed_targets.caller_confirms_addresses() is False


# ── (c) the confirm action is admin only and audited ─────────────────────────


def test_confirm_is_admin_only_and_audited(admin, group):
    writer = user_client(admin, "addr-confirmer", features=WRITER_FEATURES)
    host_id = writer.post(f"/api/inventory/{group}/hosts", json={"hostname": "edge-b", "ip_address": USER_IP}).json()[
        "id"
    ]
    other = writer.post(f"/api/inventory/{group}/hosts", json={"hostname": "edge-c", "ip_address": ATTACKER_IP}).json()[
        "id"
    ]

    assert writer.post(f"/api/admin/hosts/{host_id}/confirm-address").status_code == 403
    assert writer.post("/api/admin/hosts/confirm-address", json={"group_id": group}).status_code == 403
    assert _flag(host_id) == 0

    r = admin.post(f"/api/admin/hosts/{host_id}/confirm-address")
    assert r.status_code == 200, r.text
    assert r.json()["confirmed"] == [host_id]
    assert _flag(host_id) == 1 and _flag(other) == 0

    r = admin.post("/api/admin/hosts/confirm-address", json={"group_id": group})
    assert r.status_code == 200, r.text
    assert r.json()["confirmed"] == [other]
    assert r.json()["already_confirmed"] == [host_id]
    assert _flag(other) == 1

    assert admin.post("/api/admin/hosts/999999/confirm-address").status_code == 404
    assert admin.post("/api/admin/hosts/confirm-address", json={}).status_code == 400

    events = asyncio.run(db.get_audit_events(50, "inventory"))
    confirmed = [e for e in events if e["action"] == "host.address_confirmed"]
    assert len(confirmed) == 2
    assert all(e["user"] == "admin" for e in confirmed)
    assert any(f"{host_id}={USER_IP}" in e["detail"] for e in confirmed)


# ── (d) unmanaged_addresses ──────────────────────────────────────────────────


def test_same_address_ignores_spelling_and_name_hosts_caps_the_list():
    assert managed_targets.same_address("2001:DB8::1", " 2001:db8:0::1 ")
    assert managed_targets.same_address("Core-A", "core-a ")
    assert not managed_targets.same_address("192.0.2.1", "192.0.2.10")
    assert not managed_targets.same_address("", "192.0.2.1")

    hosts = [{"hostname": f"sw-{n}", "ip_address": f"192.0.2.{n}"} for n in range(1, 8)]
    assert managed_targets.name_hosts(hosts[:2]) == "sw-1 (192.0.2.1), sw-2 (192.0.2.2)"
    assert managed_targets.name_hosts(hosts).endswith("sw-5 (192.0.2.5) and 2 more")
    assert managed_targets.name_hosts([{"ip_address": "192.0.2.9"}, {"hostname": "edge"}, {}]) == (
        "192.0.2.9, edge, unnamed host"
    )


async def test_unconfirmed_host_address_is_unmanaged():
    await db.init_db()
    gid = await db.create_group("addr-managed")
    await db.add_host(gid, "core-a", ADMIN_IP, address_confirmed=True)
    await db.add_host(gid, "edge-b", ATTACKER_IP)
    outside = await managed_targets.unmanaged_addresses([ADMIN_IP, ATTACKER_IP], UNRESTRICTED)
    assert outside == [ATTACKER_IP]


def test_discovery_refuses_the_service_credential_on_an_unconfirmed_host(admin, group, monkeypatch):
    import netcontrol.routes.inventory as inventory

    probed: list[str] = []

    async def no_probe(ip_address, body, snmp_cfg, semaphore, credential, **_kw):
        probed.append(ip_address)
        return None

    monkeypatch.setattr(inventory, "_scan_target", no_probe)
    asyncio.run(db.create_credential("addr-service", "svc", encrypt("pw"), is_service=True))
    writer = user_client(admin, "addr-scanner", features=WRITER_FEATURES)
    writer.post(f"/api/inventory/{group}/hosts", json={"hostname": "edge-b", "ip_address": ATTACKER_IP})
    r = writer.post(
        f"/api/inventory/{group}/discovery/scan",
        json={"cidrs": [f"{ATTACKER_IP}/32"], "use_snmp": False, "use_icmp": False},
    )
    assert r.status_code == 403, r.text
    assert probed == []


# ── (e) the default-credential fallback is a service credential only ─────────


async def test_default_credential_fallback_needs_a_service_credential(monkeypatch):
    await db.init_db()
    personal = await db.create_credential("addr-personal", "me", encrypt("pw"))
    monkeypatch.setattr(state, "AUTH_CONFIG", {"default_credential_id": personal})
    assert await managed_targets.unattended_credential() is None

    service = await db.create_credential("addr-svc", "svc", encrypt("pw"), is_service=True)
    second = await db.create_credential("addr-svc2", "svc2", encrypt("pw"), is_service=True)
    # Two service credentials and none chosen: only a service default is used.
    monkeypatch.setattr(state, "AUTH_CONFIG", {"default_credential_id": second})
    assert int((await managed_targets.unattended_credential())["id"]) == second
    monkeypatch.setattr(state, "AUTH_CONFIG", {"service_credential_id": service, "default_credential_id": personal})
    assert int((await managed_targets.unattended_credential())["id"]) == service


def test_migration_0134_matches_a_fresh_database():
    migration = importlib.import_module("routes.migrations.0134_add_host_address_confirmed")

    async def _run() -> tuple[set, set, int]:
        await db.init_db()
        fresh = set(await pg_raw.table_columns("hosts"))
        gid = await db.create_group("addr-migration")
        hid = await db.add_host(gid, "old", ADMIN_IP)
        await pg_raw.execute("ALTER TABLE hosts DROP COLUMN address_confirmed")
        conn = await db.get_db()
        try:
            await migration.up(conn)
            await migration.up(conn)  # re-running is a no-op
        finally:
            await conn.close()
        host = await db.get_host(hid)
        return fresh, set(await pg_raw.table_columns("hosts")), int(host["address_confirmed"])

    fresh, migrated, existing = asyncio.run(_run())
    assert fresh == migrated
    # A host stored before the migration counts as confirmed.
    assert existing == 1
