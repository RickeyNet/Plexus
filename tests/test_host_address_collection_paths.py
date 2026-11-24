"""Every collection path that sends a shared secret skips a host whose
address awaits an admin's confirmation (``netcontrol.managed_targets``),
says why, and never records it as down.

Each test pairs a confirmed host (192.0.2.0/24) with an unconfirmed one at
203.0.113.10, standing in for a listener a non-admin pointed a host at, and
fails if any shared credential or SNMP config would reach that address.
"""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db
from netcontrol import managed_targets
from netcontrol.routes import monitoring, state
from routes.crypto import encrypt

from mcp_helpers import CsrfClient, admin_client, user_client

CONFIRMED_IP = "192.0.2.31"
ATTACKER_IP = "203.0.113.10"
SNMP_CFG = {"enabled": True, "version": "2c", "community": "shared-community", "port": 161, "timeout_seconds": 1.0}


async def _fleet() -> tuple[int, int, int, int]:
    """A group with one confirmed and one unconfirmed host, and a service
    credential set in Settings: ``(group, confirmed, unconfirmed, service)``."""
    await db.init_db()
    gid = await db.create_group("addr-fleet")
    good = await db.add_host(gid, "core-a", CONFIRMED_IP, address_confirmed=True)
    bad = await db.add_host(gid, "edge-x", ATTACKER_IP)
    service = await db.create_credential("addr-fleet-svc", "svc", encrypt("pw"), is_service=True)
    return gid, good, bad, service


@pytest.fixture
def settings(monkeypatch):
    """Isolated AUTH_CONFIG / MONITORING_CONFIG; every group has SNMP on."""
    monkeypatch.setattr(state, "AUTH_CONFIG", {})
    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", lambda _gid=None: dict(SNMP_CFG))
    monkeypatch.setitem(state.MONITORING_CONFIG, "enabled", True)
    return state


# ── Monitoring ───────────────────────────────────────────────────────────────


async def test_monitoring_never_polls_an_unconfirmed_host_nor_records_it_down(monkeypatch, settings):
    gid, good, bad, service = await _fleet()
    settings.AUTH_CONFIG["service_credential_id"] = service

    targets = await monitoring._build_poll_targets()
    assert [h["id"] for h, _cred, _cfg in targets] == [good]
    assert all(int(cred["id"]) == service for _h, cred, _cfg in targets)

    polled: list[str] = []
    processed: list[int] = []

    async def poll(host, cred, snmp_cfg):
        polled.append(host["ip_address"])
        return {"host_id": host["id"], "poll_status": "ok"}

    async def store(h, res, rules, suppressions=None):
        processed.append(h["id"])
        return 0

    async def nothing(*args, **kwargs):
        return None

    monkeypatch.setattr(monitoring, "_poll_host_monitoring", poll)
    monkeypatch.setattr(monitoring, "_process_poll_result", store)
    monkeypatch.setattr(monitoring, "_run_retention_cleanup_throttled", nothing)
    monkeypatch.setattr(monitoring, "_HOST_POLLS_RUNNING", {})

    result = await monitoring._run_monitoring_poll_once(force=True)
    assert polled == [CONFIRMED_IP]
    assert processed == [good]
    assert result["awaiting_confirmation"] == 1
    assert result["skipped_reason"] == managed_targets.ADDRESS_AWAITING_CONFIRMATION
    assert result["errors"] == 0

    # A one-host poll of the unconfirmed host (an APC trap re-poll) also skips it.
    result = await monitoring.poll_host_now(bad)
    assert result["hosts_polled"] == 0 and result["awaiting_confirmation"] == 1
    assert polled == [CONFIRMED_IP]

    # Nothing was stored for it: no poll, no availability change, no alert.
    assert await db.get_monitoring_poll_history(bad) == []
    assert await db.get_monitoring_alerts(host_id=bad) == []


async def test_an_unconfirmed_host_raises_no_sla_alert(settings):
    gid, good, bad, service = await _fleet()
    await db.create_sla_target("addr-uptime", "uptime", 99.9, 99.0, group_id=gid)
    result = await monitoring.evaluate_sla_targets()
    # Never polled: no data, so no warn / breach and no alert.
    assert (result["alerts"], result["warn"], result["breach"]) == (0, 0, 0)
    assert result["no_data"] == 2
    assert await db.get_monitoring_alerts(host_id=bad) == []


async def test_default_credential_fallback_skips_a_personal_credential(settings):
    _gid, good, _bad, _service = await _fleet()
    owner = await db.create_user("addr-owner", "x", "salt")
    personal = await db.create_credential("addr-mine", "me", encrypt("pw"), owner_id=owner)
    # A second service credential: none is picked implicitly any more.
    await db.create_credential("addr-fleet-svc2", "svc2", encrypt("pw"), is_service=True)
    settings.AUTH_CONFIG["default_credential_id"] = personal
    targets = await monitoring._build_poll_targets()
    assert [(h["id"], cred) for h, cred, _cfg in targets] == [(good, None)]


# ── MAC tracking ─────────────────────────────────────────────────────────────


async def test_mac_collection_sends_nothing_to_an_unconfirmed_host(monkeypatch, settings):
    from netcontrol.routes import mac_tracking, shared

    _gid, _good, bad, service = await _fleet()
    settings.AUTH_CONFIG["service_credential_id"] = service

    def refuse(*args, **kwargs):
        raise AssertionError("a shared secret was sent to an unconfirmed address")

    async def refuse_async(*args, **kwargs):
        refuse()

    monkeypatch.setattr(mac_tracking, "_snmp_walk", refuse_async)
    monkeypatch.setattr(shared, "_collect_mac_table_via_cli", refuse_async)
    host = await db.get_host(bad)
    result = await mac_tracking.collect_mac_arp_tables(
        bad, ATTACKER_IP, dict(SNMP_CFG), device_type="cisco_ios", host=host
    )
    assert result["skipped"] is True
    assert result["skipped_reason"] == managed_targets.ADDRESS_AWAITING_CONFIRMATION
    assert result["macs_found"] == 0 and result["diag"]["cli_attempted"] is False


# ── Topology SNMP walks ──────────────────────────────────────────────────────


async def test_topology_walks_leave_out_an_unconfirmed_host(settings):
    from netcontrol.routes import topology

    gid, good, _bad, _service = await _fleet()
    hosts, cfgs = topology._snmp_hosts(await db.get_hosts_for_group(gid), gid)
    assert [h["id"] for h in hosts] == [good]
    assert set(cfgs) == {good}


# ── Config capture (backups, compliance) ─────────────────────────────────────


async def test_shared_credential_capture_refuses_an_unconfirmed_host(monkeypatch, settings):
    from netcontrol.routes import config_backups, device_config

    _gid, good, bad, service = await _fleet()
    service_cred = await db.get_credential_raw(service)
    captured: list[str] = []

    async def capture(host, credentials):
        captured.append(host["ip_address"])
        return "hostname core-a\n", ""

    monkeypatch.setattr(device_config, "_capture_device_configs", capture)

    with pytest.raises(device_config.AddressNotConfirmedError):
        await device_config.get_device_config(await db.get_host(bad), service_cred, capture_method="manual")
    assert captured == []

    # A scheduled backup records the reason as the host's error row.
    stored = await config_backups.backup_host(
        await db.get_host(bad), service_cred, policy_id=None, capture_method="scheduled"
    )
    assert stored is False
    rows = await db.get_config_backups(host_id=bad)
    assert rows and managed_targets.ADDRESS_AWAITING_CONFIRMATION in rows[0]["error_message"]
    assert captured == []

    # The confirmed host is read; so is the unconfirmed one with a user's own credential.
    await device_config.get_device_config(await db.get_host(good), service_cred, capture_method="manual")
    personal = {"id": 0, "username": "me", "password": "pw", "secret": "", "is_service": 0}
    await device_config.get_device_config(await db.get_host(bad), personal, capture_method="manual")
    assert captured == [CONFIRMED_IP, ATTACKER_IP]


# ── Inventory collection over SSH ────────────────────────────────────────────


async def test_inventory_collection_skips_an_unconfirmed_host(monkeypatch, settings):
    from netcontrol.routes import inventory_collection

    _gid, _good, bad, service = await _fleet()

    def refuse(host, credential):
        raise AssertionError("the service credential was sent to an unconfirmed address")

    monkeypatch.setattr(inventory_collection, "_capture_host", refuse)
    outcome = await inventory_collection._collect_host(
        await db.get_host(bad), await db.get_credential_raw(service), asyncio.Lock()
    )
    assert outcome["skipped"] is True
    assert managed_targets.ADDRESS_AWAITING_CONFIRMATION in outcome["error"]


# ── Cisco FDM collector ──────────────────────────────────────────────────────


async def test_fdm_collector_does_not_poll_an_unconfirmed_host(monkeypatch, settings):
    from netcontrol.integrations.cisco_fdm import collector

    _gid, good, bad, service = await _fleet()
    conn = await db.get_db()
    try:
        await conn.execute(
            "UPDATE hosts SET fdm_api_enabled = 1, fdm_credential_id = ? WHERE id IN (?, ?)", (service, good, bad)
        )
        await conn.commit()
    finally:
        await conn.close()

    polled: list[int] = []

    async def collect(host):
        polled.append(host["id"])
        return {"host_id": host["id"], "poll_status": "ok"}

    async def store(h, res, rules, suppressions=None):
        return 0

    monkeypatch.setattr(collector, "collect_host", collect)
    monkeypatch.setattr(monitoring, "_process_poll_result", store)
    result = await collector.run_fdm_poll_once(force=True)
    assert polled == [good]
    assert result["awaiting_confirmation"] == 1


# ── Live SSH enrichment of a topology snapshot ───────────────────────────────


async def test_live_ssh_enrichment_skips_an_unconfirmed_host(monkeypatch, settings):
    from netcontrol.integrations.meraki import enrich

    _gid, _good, bad, service = await _fleet()
    settings.AUTH_CONFIG["service_credential_id"] = service

    async def refuse(host, credential):
        raise AssertionError("the service credential was sent to an unconfirmed address")

    monkeypatch.setattr(enrich, "_live_ssh_sections", refuse)
    snapshot = {"nodes": [{"id": "n1", "inventory": {"host_id": bad}, "sections": []}]}
    await enrich.enrich_snapshot(snapshot, ssh=True)
    messages = [e["message"] for e in snapshot["collection"]["errors"]]
    assert any(managed_targets.ADDRESS_AWAITING_CONFIRMATION in m for m in messages)


# ── Jobs with secret variables ───────────────────────────────────────────────


async def test_secret_job_of_a_non_admin_refuses_an_unconfirmed_host():
    from netcontrol.routes import jobs

    _gid, good, bad, _service = await _fleet()
    await db.create_user("addr-launcher", "x", "salt")
    hosts = await db.get_hosts_by_ids([good, bad])
    refused = await jobs._launcher_secret_targets_refused({"launched_by": "addr-launcher"}, hosts)
    assert refused == [ATTACKER_IP]
    # An admin launcher may send secrets anywhere.
    await db.create_user("addr-admin", "x", "salt", role="admin")
    assert await jobs._launcher_secret_targets_refused({"launched_by": "addr-admin"}, hosts) == []


# ── Manual SNMP test of a host ───────────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def test_host_snmp_test_of_an_unconfirmed_host_is_admin_only(admin, monkeypatch):
    from netcontrol.routes import inventory

    sent: list[str] = []

    async def snmp_get(ip, _wait, cfg):
        sent.append(ip)
        return {"sysName": "x"}

    monkeypatch.setattr(inventory, "_snmp_get", snmp_get)
    monkeypatch.setattr(state, "_resolve_host_snmp_config", lambda host, group_id=None: dict(SNMP_CFG))
    gid = admin.post("/api/inventory", json={"name": "addr-snmp", "description": ""}).json()["id"]
    writer = user_client(admin, "addr-snmp-writer", features=["inventory", "inventory.write"])
    host_id = writer.post(f"/api/inventory/{gid}/hosts", json={"hostname": "edge-x", "ip_address": ATTACKER_IP}).json()[
        "id"
    ]
    r = writer.post(f"/api/hosts/{host_id}/snmp-profile/test")
    assert r.status_code == 403, r.text
    assert sent == []
    assert admin.post(f"/api/hosts/{host_id}/snmp-profile/test").status_code == 200
    assert sent == [ATTACKER_IP]
