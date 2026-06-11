"""MAC tracking DB-layer tests: per-switch move detection, uplink suppression,
IP-preservation on upsert, and cross-host ARP enrichment."""

from __future__ import annotations

import pytest
import routes.database as db_module


@pytest.fixture
async def mac_db(tmp_path, monkeypatch):
    """Temporary DB with two switches seeded."""
    db_path = str(tmp_path / "mac_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    await db_module.init_db()

    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'core')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (100, 1, 'sw-a', '10.0.1.1', 'cisco_ios', 'online')"
        )
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (200, 1, 'sw-b', '10.0.1.2', 'cisco_ios', 'online')"
        )
        await db.commit()
    finally:
        await db.close()
    return {"host_a": 100, "host_b": 200}


MAC = "aa:bb:cc:dd:ee:ff"


async def _open_move_count() -> int:
    summary = await db_module.get_mac_move_event_summary()
    return summary["open"]


@pytest.mark.asyncio
async def test_same_mac_on_two_switches_is_not_a_move(mac_db):
    """A MAC visible on two switches at once is normal (access + uplink),
    not a move. The old global comparison wrongly flagged this."""
    a, b = mac_db["host_a"], mac_db["host_b"]

    baseline_a = await db_module.record_mac_history(MAC, a, "Gi1/0/1", vlan=10)
    assert baseline_a is not None  # first sighting on switch A → baseline
    assert await _open_move_count() == 0

    # Re-seeing it on A unchanged is a no-op.
    assert await db_module.record_mac_history(MAC, a, "Gi1/0/1", vlan=10) is None
    assert await _open_move_count() == 0

    # Seeing the same MAC on switch B is just another vantage point — baseline
    # for B, NOT a "switch move".
    baseline_b = await db_module.record_mac_history(MAC, b, "Gi1/0/2", vlan=10)
    assert baseline_b is not None
    assert await _open_move_count() == 0


@pytest.mark.asyncio
async def test_port_change_on_same_switch_is_a_move(mac_db):
    """A port change on the same switch is a real relocation."""
    a = mac_db["host_a"]
    await db_module.record_mac_history(MAC, a, "Gi1/0/1", vlan=10)
    assert await _open_move_count() == 0

    event_id = await db_module.record_mac_history(MAC, a, "Gi1/0/5", vlan=10)
    assert event_id is not None
    assert await _open_move_count() == 1

    events = await db_module.get_mac_move_events("open", 10)
    assert len(events) == 1
    ev = events[0]
    assert "port" in ev["change_kind"]
    # Per-switch detection: both sides of the move are the same switch.
    assert ev["from_host_id"] == a
    assert ev["to_host_id"] == a
    assert ev["from_port"] == "Gi1/0/1"
    assert ev["to_port"] == "Gi1/0/5"


@pytest.mark.asyncio
async def test_vlan_change_on_same_switch_is_a_move(mac_db):
    a = mac_db["host_a"]
    await db_module.record_mac_history(MAC, a, "Gi1/0/1", vlan=10)
    event_id = await db_module.record_mac_history(MAC, a, "Gi1/0/1", vlan=20)
    assert event_id is not None
    events = await db_module.get_mac_move_events("open", 10)
    assert "vlan" in events[0]["change_kind"]


@pytest.mark.asyncio
async def test_uplink_sighting_is_skipped(mac_db):
    """is_uplink sightings record nothing — no baseline, no move."""
    a = mac_db["host_a"]
    assert await db_module.record_mac_history(MAC, a, "Po1", vlan=10, is_uplink=True) is None
    assert await _open_move_count() == 0
    # And because no baseline was written, a later real sighting on an access
    # port is treated as the first sighting (baseline, not a move).
    event_id = await db_module.record_mac_history(MAC, a, "Gi1/0/1", vlan=10)
    assert event_id is not None
    assert await _open_move_count() == 0


@pytest.mark.asyncio
async def test_upsert_preserves_ip_when_incoming_empty(mac_db):
    """FDB polls pass ip_address='' and must not wipe an enriched IP."""
    a = mac_db["host_a"]
    await db_module.upsert_mac_entry(host_id=a, mac_address=MAC, vlan=10, port_name="Gi1/0/1")
    assert await db_module.enrich_mac_ip(MAC, "10.0.0.50") == 1

    # A subsequent FDB upsert with no IP should keep the enriched value.
    await db_module.upsert_mac_entry(host_id=a, mac_address=MAC, vlan=10, port_name="Gi1/0/1")
    rows = await db_module.get_mac_table_for_host(a)
    assert len(rows) == 1
    assert rows[0]["ip_address"] == "10.0.0.50"


@pytest.mark.asyncio
async def test_enrich_mac_ip_is_cross_host_and_non_destructive(mac_db):
    """enrich_mac_ip fills empty IPs for the MAC on every host, never
    overwriting an IP that's already set."""
    a, b = mac_db["host_a"], mac_db["host_b"]
    await db_module.upsert_mac_entry(host_id=a, mac_address=MAC, vlan=10, port_name="Gi1/0/1")
    await db_module.upsert_mac_entry(host_id=b, mac_address=MAC, vlan=10, port_name="Gi1/0/2")

    # First enrichment touches both empty rows.
    assert await db_module.enrich_mac_ip(MAC, "10.0.0.50") == 2
    # Second enrichment with a different IP touches nothing (both already set).
    assert await db_module.enrich_mac_ip(MAC, "10.0.0.99") == 0

    for host in (a, b):
        rows = await db_module.get_mac_table_for_host(host)
        assert rows[0]["ip_address"] == "10.0.0.50"


@pytest.mark.asyncio
async def test_enrich_mac_ip_ignores_blank_args(mac_db):
    assert await db_module.enrich_mac_ip("", "10.0.0.1") == 0
    assert await db_module.enrich_mac_ip(MAC, "") == 0


async def _wait_for_job(job_id: str, deadline_seconds: float = 5.0) -> dict:
    """Poll the in-memory job registry until the job leaves 'running'."""
    import asyncio

    from netcontrol.routes import background_jobs

    deadline = asyncio.get_event_loop().time() + deadline_seconds
    while True:
        job = background_jobs.get_job(job_id)
        assert job is not None, "job vanished from the registry"
        if job["status"] != "running":
            return job
        assert asyncio.get_event_loop().time() < deadline, "job never finished"
        await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_full_collection_aggregates_per_host_diagnostics(mac_db, monkeypatch):
    """All-hosts collect runs as a background job whose result must surface
    each host's errors, not just exceptions."""
    import netcontrol.routes.mac_tracking as mac_tracking
    import netcontrol.routes.state as state_module

    monkeypatch.setattr(
        state_module, "_resolve_snmp_discovery_config",
        lambda _gid: {"enabled": True},
    )

    async def fake_collect(host_id, ip, cfg, **kwargs):
        # host 100 returns a diagnostic, host 200 is clean
        if host_id == 100:
            return {"macs_found": 3, "arps_found": 1,
                    "errors": ["per-VLAN walks hit 60s budget"]}
        return {"macs_found": 5, "arps_found": 2, "errors": []}

    monkeypatch.setattr(mac_tracking, "collect_mac_arp_tables", fake_collect)

    launched = await mac_tracking.trigger_mac_collection(host_id=None)
    assert launched["status"] == "running"
    assert launched["hosts_total"] == 2

    job = await _wait_for_job(launched["job_id"])
    assert job["status"] == "completed"
    total = job["result"]

    assert total["macs_found"] == 8
    assert total["arps_found"] == 3
    assert total["hosts_collected"] == 2
    # The per-host diagnostic is preserved (structured + flattened), not dropped.
    assert len(total["host_errors"]) == 1
    assert total["host_errors"][0]["host_id"] == 100
    assert any("60s budget" in e for e in total["errors"])
    # The guard flag is released once the job finishes.
    assert mac_tracking._full_collection_running is False


@pytest.mark.asyncio
async def test_full_collection_rejects_concurrent_run(mac_db, monkeypatch):
    """A second full collection while one is running returns 409."""
    import netcontrol.routes.mac_tracking as mac_tracking
    from fastapi import HTTPException

    monkeypatch.setattr(mac_tracking, "_full_collection_running", True)

    with pytest.raises(HTTPException) as exc:
        await mac_tracking.trigger_mac_collection(host_id=None)
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_collection_job_endpoint_roundtrip(mac_db, monkeypatch):
    """The job polling endpoint returns the running job and 404s unknown ids."""
    import netcontrol.routes.mac_tracking as mac_tracking
    import netcontrol.routes.state as state_module
    from fastapi import HTTPException

    monkeypatch.setattr(
        state_module, "_resolve_snmp_discovery_config",
        lambda _gid: {"enabled": True},
    )

    async def fake_collect(host_id, ip, cfg, **kwargs):
        return {"macs_found": 1, "arps_found": 0, "errors": []}

    monkeypatch.setattr(mac_tracking, "collect_mac_arp_tables", fake_collect)

    launched = await mac_tracking.trigger_mac_collection(host_id=None)
    job = await mac_tracking.get_mac_collection_job(launched["job_id"])
    assert job["kind"] == "mac-fleet-collection"

    await _wait_for_job(launched["job_id"])

    with pytest.raises(HTTPException) as exc:
        await mac_tracking.get_mac_collection_job("nope")
    assert exc.value.status_code == 404


# ── Batched write paths ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_batch_sightings_match_sequential_move_semantics(mac_db):
    """record_mac_sightings_batch must reproduce record_mac_history's
    semantics: baseline on first sight, no-op when unchanged, move event on
    port change, uplinks skipped for history."""
    a = mac_db["host_a"]

    counts = await db_module.record_mac_sightings_batch(a, [
        {"mac": MAC, "vlan": 10, "port_name": "Gi1/0/1", "port_index": 1,
         "entry_type": "dynamic", "is_uplink": False},
    ])
    assert counts == {"macs": 1, "history": 1, "moves": 0}
    assert await _open_move_count() == 0

    # Same location again - history no-op.
    counts = await db_module.record_mac_sightings_batch(a, [
        {"mac": MAC, "vlan": 10, "port_name": "Gi1/0/1", "port_index": 1,
         "entry_type": "dynamic", "is_uplink": False},
    ])
    assert counts == {"macs": 1, "history": 0, "moves": 0}

    # Port change - opens a move event.
    counts = await db_module.record_mac_sightings_batch(a, [
        {"mac": MAC, "vlan": 10, "port_name": "Gi1/0/5", "port_index": 5,
         "entry_type": "dynamic", "is_uplink": False},
    ])
    assert counts == {"macs": 1, "history": 1, "moves": 1}
    assert await _open_move_count() == 1

    # Uplink sighting - FDB row written, history/move skipped.
    counts = await db_module.record_mac_sightings_batch(a, [
        {"mac": "11:22:33:44:55:66", "vlan": 10, "port_name": "Po1",
         "port_index": 99, "entry_type": "dynamic", "is_uplink": True},
    ])
    assert counts == {"macs": 1, "history": 0, "moves": 0}
    assert await _open_move_count() == 1


@pytest.mark.asyncio
async def test_batch_sightings_same_mac_twice_in_one_batch(mac_db):
    """Two same-MAC sightings in one batch compare against each other
    sequentially, exactly as two record_mac_history calls would have."""
    a = mac_db["host_a"]

    counts = await db_module.record_mac_sightings_batch(a, [
        {"mac": MAC, "vlan": 10, "port_name": "Gi1/0/1", "port_index": 1,
         "entry_type": "dynamic", "is_uplink": False},
        {"mac": MAC, "vlan": 20, "port_name": "Gi1/0/1", "port_index": 1,
         "entry_type": "dynamic", "is_uplink": False},
    ])
    # First is the baseline; second differs in VLAN → move, same as the old
    # sequential per-sighting calls.
    assert counts["history"] == 2
    assert counts["moves"] == 1


@pytest.mark.asyncio
async def test_batch_arp_upsert_and_cross_host_enrichment(mac_db):
    """upsert_arp_entries_batch writes ARP rows and enriches empty MAC-table
    IPs cross-host without overwriting existing ones."""
    a, b = mac_db["host_a"], mac_db["host_b"]

    # FDB rows live on switch A (no IP) and switch B (already enriched).
    await db_module.record_mac_sightings_batch(a, [
        {"mac": MAC, "vlan": 10, "port_name": "Gi1/0/1", "port_index": 1,
         "entry_type": "dynamic", "is_uplink": False},
    ])
    await db_module.upsert_mac_entry(host_id=b, mac_address=MAC, vlan=10,
                                     port_name="Gi1/0/2", ip_address="10.9.9.9")

    # ARP learned on switch B (the L3 device).
    written = await db_module.upsert_arp_entries_batch(b, [
        {"ip_address": "10.0.50.5", "mac_address": MAC, "interface_name": "Vlan10"},
        {"ip_address": "", "mac_address": "ff:ee:dd:cc:bb:aa", "interface_name": ""},
    ])
    assert written == 2

    rows = await db_module.search_mac_tracking(MAC)
    by_host = {r["host_id"]: r for r in rows}
    # Switch A's empty IP was enriched cross-host; switch B's existing IP kept.
    assert by_host[a]["ip_address"] == "10.0.50.5"
    assert by_host[b]["ip_address"] == "10.9.9.9"
