"""Each inventory group remembers the SSH credential its discovery scan or
sync was explicitly run with (``inventory_groups.discovery_credential_id``,
migration 0117), and a scan or sync with no credential uses it before the
Plexus service credential."""

from __future__ import annotations

import asyncio
import importlib

import netcontrol.routes.inventory as inventory
import netcontrol.routes.state as state
import pytest
import routes.database as db_module
from fastapi import HTTPException
from netcontrol.routes.inventory import DiscoveryScanRequest

import pg_raw
from test_inventory_serial import _make_auth_client

SERVICE = {"id": 3, "name": "plexus-svc", "username": "svc", "password": "x", "is_service": 1}
OTHER_SERVICE = {"id": 4, "name": "ups-svc", "username": "upsadmin", "password": "x", "is_service": 1}
MINE = {"id": 9, "name": "my-cred", "username": "me", "password": "x", "is_service": 0, "owner_id": 1}
SESSION = {"user": "alice", "user_id": 1}


def _body(**overrides) -> DiscoveryScanRequest:
    values = {"cidrs": ["192.0.2.0/30"], "use_snmp": False, "use_icmp": False}
    values.update(overrides)
    return DiscoveryScanRequest(**values)


@pytest.fixture
def fakes(monkeypatch):
    """Credentials 3 (service, the Settings default), 4 (another service
    credential) and 9 (alice's own); records group writes and audit rows."""
    creds = {3: SERVICE, 4: OTHER_SERVICE, 9: MINE}
    record: dict[str, list] = {"set": [], "audit": [], "access": []}

    async def access(credential_id, *, session=None, allow_service=False):
        record["access"].append(credential_id)
        cred = creds.get(int(credential_id))
        if cred is None:
            raise HTTPException(404, "Credential not found")
        if cred.get("owner_id") not in (None, (session or {}).get("user_id")):
            raise HTTPException(403, "You can only use your own credentials")
        return cred

    async def service():
        return SERVICE

    async def raw(credential_id, *, resolve_external=True):
        return creds.get(int(credential_id))

    async def set_cred(group_id, credential_id):
        record["set"].append((group_id, credential_id))

    async def audit(category, action, user="", detail="", correlation_id=""):
        record["audit"].append((category, action, user, detail))

    monkeypatch.setattr(inventory, "require_credential_access", access)
    monkeypatch.setattr(inventory, "service_credential", service)
    monkeypatch.setattr(inventory.db, "get_credential_raw", raw)
    monkeypatch.setattr(inventory.db, "set_group_discovery_credential", set_cred)
    monkeypatch.setattr(inventory, "_audit", audit)
    record["creds"] = creds  # type: ignore[assignment]
    return record


# ── Remembering an explicit pick ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_explicit_pick_is_remembered_for_the_group(fakes):
    group = {"id": 5, "discovery_credential_id": None}
    cred, summary = await inventory._resolve_discovery_ssh(_body(credential_id=9), SESSION, group=group)
    assert cred is MINE
    assert summary["credential_source"] == "explicit"
    assert fakes["set"] == [(5, 9)]
    assert group["discovery_credential_id"] == 9
    [(category, action, user, detail)] = fakes["audit"]
    assert (category, action, user) == ("inventory", "group.discovery_credential", "alice")
    assert detail == "group_id=5 credential_id=9 previous=service"
    assert "password" not in detail


@pytest.mark.asyncio
async def test_same_pick_again_writes_nothing(fakes):
    group = {"id": 5, "discovery_credential_id": 9}
    await inventory._resolve_discovery_ssh(_body(credential_id=9), SESSION, group=group)
    assert fakes["set"] == [] and fakes["audit"] == []


@pytest.mark.asyncio
async def test_picking_the_default_service_credential_forgets(fakes):
    group = {"id": 5, "discovery_credential_id": 9}
    cred, _ = await inventory._resolve_discovery_ssh(_body(credential_id=3), SESSION, group=group)
    assert cred is SERVICE
    assert fakes["set"] == [(5, None)]
    assert fakes["audit"][0][3] == "group_id=5 credential_id=service previous=9"


@pytest.mark.asyncio
async def test_another_service_credential_is_remembered(fakes):
    group = {"id": 5, "discovery_credential_id": None}
    await inventory._resolve_discovery_ssh(_body(credential_id=4), SESSION, group=group)
    assert fakes["set"] == [(5, 4)]


@pytest.mark.asyncio
async def test_use_service_credential_forgets_and_uses_the_default(fakes):
    group = {"id": 5, "discovery_credential_id": 9}
    cred, summary = await inventory._resolve_discovery_ssh(_body(use_service_credential=True), SESSION, group=group)
    assert cred is SERVICE
    assert summary["credential_source"] == "service"
    assert fakes["set"] == [(5, None)]
    assert 9 not in fakes["access"]


@pytest.mark.asyncio
async def test_denied_explicit_pick_is_not_remembered(fakes):
    group = {"id": 5, "discovery_credential_id": None}
    with pytest.raises(HTTPException) as exc:
        await inventory._resolve_discovery_ssh(_body(credential_id=9), {"user": "bob", "user_id": 2}, group=group)
    assert exc.value.status_code == 403
    assert fakes["set"] == []


# ── Using the remembered credential ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_credential_uses_the_groups(fakes):
    group = {"id": 5, "discovery_credential_id": 9}
    cred, summary = await inventory._resolve_discovery_ssh(_body(), SESSION, group=group)
    assert cred is MINE
    assert summary["credential_source"] == "group"
    assert summary["credential"] == "my-cred"
    assert summary["note"] == ""
    assert fakes["set"] == []  # using it is not a change


@pytest.mark.asyncio
async def test_remembered_credential_the_caller_may_not_use_falls_back(fakes):
    group = {"id": 5, "discovery_credential_id": 9}
    cred, summary = await inventory._resolve_discovery_ssh(_body(), {"user": "bob", "user_id": 2}, group=group)
    assert cred is SERVICE
    assert summary["credential_source"] == "service"
    assert "cannot be used" in summary["note"]
    assert "service credential" in summary["note"]
    assert fakes["set"] == []  # bob's run does not change what alice picked


@pytest.mark.asyncio
async def test_deleted_remembered_credential_is_ignored(fakes):
    group = {"id": 5, "discovery_credential_id": 77}
    cred, summary = await inventory._resolve_discovery_ssh(_body(), SESSION, group=group)
    assert cred is SERVICE
    assert summary["credential_source"] == "service"
    assert summary["note"] == ""


@pytest.mark.asyncio
async def test_unattended_uses_a_remembered_service_credential(fakes):
    group = {"id": 5, "discovery_credential_id": 4}
    cred, summary = await inventory._resolve_discovery_ssh(_body(), None, group=group, unattended=True)
    assert cred is OTHER_SERVICE
    assert summary["credential_source"] == "group"
    assert fakes["access"] == []  # no session to check: service credentials only


@pytest.mark.asyncio
async def test_unattended_never_uses_a_personal_credential(fakes):
    group = {"id": 5, "discovery_credential_id": 9}
    cred, summary = await inventory._resolve_discovery_ssh(_body(), None, group=group, unattended=True)
    assert cred is SERVICE
    assert summary["credential_source"] == "service"
    assert "personal credential" in summary["note"]


@pytest.mark.asyncio
@pytest.mark.parametrize(("remembered", "expected"), [(4, OTHER_SERVICE), (9, SERVICE)])
async def test_scheduled_sync_uses_the_group_credential_only_when_service(monkeypatch, fakes, remembered, expected):
    sync_cfg = {"enabled": True, "interval_seconds": 900, "profiles": [{"group_id": 5, "cidrs": ["192.0.2.0/30"]}]}
    monkeypatch.setattr(state, "DISCOVERY_SYNC_CONFIG", sync_cfg)
    seen = {}

    async def fake_get_group(group_id):
        return {"id": group_id, "name": "ups", "discovery_credential_id": remembered}

    async def fake_discover(_body, group_id=None, *, credential=None):
        seen["credential"] = credential
        return 0, []

    async def fake_sync(group_id, discovered, remove_absent=False):
        return {"added": 0, "updated": 0, "removed": 0}

    monkeypatch.setattr(inventory.db, "get_group", fake_get_group)
    monkeypatch.setattr(inventory, "_discover_hosts", fake_discover)
    monkeypatch.setattr(inventory, "_sync_group_hosts", fake_sync)

    result = await inventory._run_discovery_sync_once()
    assert result["synced_groups"] == 1
    assert seen["credential"] is expected
    assert fakes["set"] == []


# ── API and database ─────────────────────────────────────────────────────────


def test_migration_0117_matches_a_fresh_database():
    migration = importlib.import_module("routes.migrations.0117_add_group_discovery_credential")

    async def _shape() -> dict:
        constraints = {
            r["conname"]
            for r in await pg_raw.fetch(
                "SELECT conname FROM pg_constraint WHERE conrelid = 'inventory_groups'::regclass"
            )
        }
        # A column added later sits last: compare the set, not the order.
        return {"columns": set(await pg_raw.table_columns("inventory_groups")), "constraints": constraints}

    async def _run() -> tuple[dict, dict]:
        await db_module.init_db()
        fresh = await _shape()
        await pg_raw.execute("ALTER TABLE inventory_groups DROP COLUMN discovery_credential_id")
        db = await db_module.get_db()
        try:
            await migration.up(db)
            await migration.up(db)  # re-running is a no-op
        finally:
            await db.close()
        return fresh, await _shape()

    fresh, migrated = asyncio.run(_run())
    assert fresh == migrated
    assert "discovery_credential_id" in migrated["columns"]
    assert "fk_inventory_groups_discovery_credential_id_credentials" in migrated["constraints"]


@pytest.fixture
def api(monkeypatch, request):
    return _make_auth_client(monkeypatch, request)


def _run(coro):
    return asyncio.run(coro)


def test_api_remembers_forgets_and_survives_deletes(api, monkeypatch):
    async def no_scan(_body, group_id=None, *, credential=None):
        return 0, []

    monkeypatch.setattr(inventory, "_discover_hosts", no_scan)
    monkeypatch.setattr(state, "AUTH_CONFIG", {**state.AUTH_CONFIG, "service_credential_id": None})

    resp = api.post("/api/inventory", json={"name": "UPS cards"})
    assert resp.status_code in (200, 201), resp.text
    group_id = resp.json()["id"]
    admin = _run(db_module.get_user_by_username("admin"))
    cred_id = _run(db_module.create_credential("ups-login", "apc", "enc", owner_id=int(admin["id"])))

    resp = api.get(f"/api/inventory/{group_id}/discovery/ssh-defaults")
    assert resp.status_code == 200, resp.text
    assert resp.json()["group_credential_id"] is None

    resp = api.post(
        f"/api/inventory/{group_id}/discovery/sync",
        json={"cidrs": ["192.0.2.10/32"], "credential_id": cred_id, "use_snmp": False, "use_icmp": False},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ssh_enrichment"]["credential_source"] == "explicit"
    assert api.get(f"/api/inventory/{group_id}/discovery/ssh-defaults").json()["group_credential_id"] == cred_id

    events = _run(db_module.get_audit_events(limit=50, category="inventory"))
    assert any(
        e["action"] == "group.discovery_credential" and f"group_id={group_id} credential_id={cred_id}" in e["detail"]
        for e in events
    )

    # A sync with no credential signs in with the group's.
    resp = api.post(
        f"/api/inventory/{group_id}/discovery/sync",
        json={"cidrs": ["192.0.2.10/32"], "use_snmp": False, "use_icmp": False},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ssh_enrichment"]["credential_source"] == "group"
    assert resp.json()["ssh_enrichment"]["credential"] == "ups-login"

    resp = api.delete(f"/api/inventory/{group_id}/discovery/credential")
    assert resp.status_code == 200, resp.text
    assert api.get(f"/api/inventory/{group_id}/discovery/ssh-defaults").json()["group_credential_id"] is None

    # Deleting the credential clears the column (ON DELETE SET NULL).
    _run(db_module.set_group_discovery_credential(group_id, cred_id))
    _run(db_module.delete_credential(cred_id))
    assert _run(db_module.get_group(group_id))["discovery_credential_id"] is None

    resp = api.delete(f"/api/inventory/{group_id}")
    assert resp.status_code == 200, resp.text
