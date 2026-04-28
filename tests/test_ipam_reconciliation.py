"""Tests for IPAM bi-directional reconciliation (Phase E)."""

from __future__ import annotations

import asyncio

import netcontrol.app as app_module
import netcontrol.routes.ipam_reconciliation as reconcile_mod
import pytest
import routes.database as db_module
from netcontrol.routes.ipam_reconciliation import (
    DRIFT_HOSTNAME_MISMATCH,
    DRIFT_MISSING_IN_IPAM,
    DRIFT_MISSING_IN_PLEXUS,
    DRIFT_STATUS_MISMATCH,
    compute_drifts,
)


# ─────────────────────────────────────────────────────────────────────────────
# Pure-function tests for compute_drifts
# ─────────────────────────────────────────────────────────────────────────────


def test_compute_drifts_missing_in_ipam():
    plexus = [{"id": 1, "hostname": "core-01", "ip_address": "10.0.0.1"}]
    ipam = []
    drifts = compute_drifts(plexus, ipam)
    assert len(drifts) == 1
    assert drifts[0]["drift_type"] == DRIFT_MISSING_IN_IPAM
    assert drifts[0]["address"] == "10.0.0.1"
    assert drifts[0]["plexus_state"]["hostname"] == "core-01"
    assert drifts[0]["ipam_state"] == {}


def test_compute_drifts_missing_in_plexus():
    plexus = []
    ipam = [{"address": "10.0.0.5", "dns_name": "ext.example", "status": "active"}]
    drifts = compute_drifts(plexus, ipam)
    assert len(drifts) == 1
    assert drifts[0]["drift_type"] == DRIFT_MISSING_IN_PLEXUS
    assert drifts[0]["address"] == "10.0.0.5"


def test_compute_drifts_skips_ipam_only_entries_marked_inactive():
    plexus = []
    ipam = [{"address": "10.0.0.5", "dns_name": "old.example", "status": "deprecated"}]
    drifts = compute_drifts(plexus, ipam)
    # Deprecated IPAM-only entries are not drift -- IPAM is correctly tracking
    # that nothing lives at that address.
    assert drifts == []


def test_compute_drifts_hostname_mismatch_case_insensitive():
    plexus = [{"hostname": "Core-01", "ip_address": "10.0.0.1"}]
    ipam = [{"address": "10.0.0.1", "dns_name": "core-01", "status": "active"}]
    # Same hostname after normalization -> no drift.
    assert compute_drifts(plexus, ipam) == []

    plexus = [{"hostname": "core-01", "ip_address": "10.0.0.1"}]
    ipam = [{"address": "10.0.0.1", "dns_name": "core-99", "status": "active"}]
    drifts = compute_drifts(plexus, ipam)
    assert len(drifts) == 1
    assert drifts[0]["drift_type"] == DRIFT_HOSTNAME_MISMATCH


def test_compute_drifts_status_mismatch_when_ipam_inactive_but_plexus_active():
    plexus = [{"hostname": "core-01", "ip_address": "10.0.0.1"}]
    ipam = [{"address": "10.0.0.1", "dns_name": "core-01", "status": "deprecated"}]
    drifts = compute_drifts(plexus, ipam)
    assert len(drifts) == 1
    assert drifts[0]["drift_type"] == DRIFT_STATUS_MISMATCH


def test_compute_drifts_normalizes_cidr_addresses():
    plexus = [{"hostname": "rtr-1", "ip_address": "10.0.0.7/24"}]
    ipam = [{"address": "10.0.0.7", "dns_name": "rtr-1", "status": "active"}]
    assert compute_drifts(plexus, ipam) == []


def test_compute_drifts_ignores_invalid_ip_entries():
    plexus = [
        {"hostname": "valid", "ip_address": "10.0.0.10"},
        {"hostname": "junk", "ip_address": "not-an-ip"},
    ]
    ipam = [
        {"address": "10.0.0.10", "dns_name": "valid", "status": "active"},
        {"address": "", "dns_name": "blank", "status": "active"},
    ]
    assert compute_drifts(plexus, ipam) == []


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests for run_reconciliation + resolve_diff
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def ipam_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ipam_reconcile.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-reconcile")

    async def _prepare():
        await db_module.init_db()

    asyncio.run(_prepare())
    return db_path


def _seed_source_and_inventory():
    async def _seed():
        db = await db_module.get_db()
        try:
            cursor = await db.execute(
                "INSERT INTO inventory_groups (name) VALUES ('Recon Core')"
            )
            group_id = int(cursor.lastrowid)
            await db.execute(
                "INSERT INTO hosts (group_id, hostname, ip_address, status) VALUES (?, ?, ?, ?)",
                (group_id, "core-01", "10.0.0.1", "online"),
            )
            await db.execute(
                "INSERT INTO hosts (group_id, hostname, ip_address, status) VALUES (?, ?, ?, ?)",
                (group_id, "core-02", "10.0.0.2", "online"),
            )
            await db.commit()
        finally:
            await db.close()

        source = await db_module.create_ipam_source(
            provider="netbox",
            name="Recon NetBox",
            base_url="https://netbox.example/api",
            auth_type="token",
            auth_config={"token": "t"},
            enabled=1,
            push_enabled=1,
            verify_tls=0,
            created_by="admin",
        )
        # Snapshot: IPAM knows 10.0.0.2 (with wrong hostname) and 10.0.0.99 (Plexus does not).
        await db_module.replace_ipam_source_snapshot(
            int(source["id"]),
            prefixes=[{"external_id": "p1", "subnet": "10.0.0.0/24", "status": "active"}],
            allocations=[
                {
                    "address": "10.0.0.2",
                    "dns_name": "stale-name",
                    "status": "active",
                    "prefix_subnet": "10.0.0.0/24",
                },
                {
                    "address": "10.0.0.99",
                    "dns_name": "ghost",
                    "status": "active",
                    "prefix_subnet": "10.0.0.0/24",
                },
            ],
        )
        return source

    return asyncio.run(_seed())


def test_run_reconciliation_records_all_drift_types(ipam_db):
    source = _seed_source_and_inventory()
    summary = asyncio.run(
        reconcile_mod.run_reconciliation(int(source["id"]), triggered_by="tester")
    )
    assert summary["diff_count"] == 3  # missing_in_ipam (10.0.0.1), hostname (10.0.0.2), missing_in_plexus (10.0.0.99)
    counts = summary["counts_by_type"]
    assert counts.get(DRIFT_MISSING_IN_IPAM) == 1
    assert counts.get(DRIFT_HOSTNAME_MISMATCH) == 1
    assert counts.get(DRIFT_MISSING_IN_PLEXUS) == 1

    runs = asyncio.run(db_module.list_reconciliation_runs(source_id=int(source["id"])))
    assert len(runs) == 1
    assert runs[0]["status"] == "completed"
    assert runs[0]["triggered_by"] == "tester"

    diffs = asyncio.run(db_module.list_reconciliation_diffs(source_id=int(source["id"])))
    assert len(diffs) == 3
    addresses = {d["address"] for d in diffs}
    assert addresses == {"10.0.0.1", "10.0.0.2", "10.0.0.99"}


def test_run_reconciliation_rejects_builtin_plexus_source(ipam_db):
    builtin = asyncio.run(db_module.get_or_create_builtin_ipam_source())
    with pytest.raises(ValueError):
        asyncio.run(reconcile_mod.run_reconciliation(int(builtin["id"])))


def test_resolve_diff_accept_ipam_marks_resolved_without_push(ipam_db, monkeypatch):
    source = _seed_source_and_inventory()
    asyncio.run(reconcile_mod.run_reconciliation(int(source["id"])))

    diffs = asyncio.run(db_module.list_reconciliation_diffs(source_id=int(source["id"])))
    target = next(d for d in diffs if d["drift_type"] == DRIFT_HOSTNAME_MISMATCH)

    # accept_ipam must NOT call the external push adapter.
    async def _fail_push(*args, **kwargs):
        raise AssertionError("push_allocation_to_provider should not be called for accept_ipam")

    monkeypatch.setattr(reconcile_mod, "push_allocation_to_provider", _fail_push)

    resolved = asyncio.run(
        reconcile_mod.resolve_diff(
            int(target["id"]),
            resolution="accept_ipam",
            resolved_by="alice",
        )
    )
    assert resolved["resolution"] == "accept_ipam"
    assert resolved["resolved_by"] == "alice"

    open_diffs = asyncio.run(
        db_module.list_reconciliation_diffs(source_id=int(source["id"]), open_only=True)
    )
    assert all(d["id"] != target["id"] for d in open_diffs)

    runs = asyncio.run(db_module.list_reconciliation_runs(source_id=int(source["id"])))
    assert runs[0]["resolved_count"] == 1


def test_resolve_diff_accept_plexus_invokes_push(ipam_db, monkeypatch):
    source = _seed_source_and_inventory()
    asyncio.run(reconcile_mod.run_reconciliation(int(source["id"])))
    diffs = asyncio.run(db_module.list_reconciliation_diffs(source_id=int(source["id"])))
    target = next(d for d in diffs if d["drift_type"] == DRIFT_HOSTNAME_MISMATCH)

    pushed: list[dict] = []

    async def _capture_push(src, auth_config, *, address, dns_name, description=""):
        pushed.append({"address": address, "dns_name": dns_name})

    monkeypatch.setattr(reconcile_mod, "push_allocation_to_provider", _capture_push)

    resolved = asyncio.run(
        reconcile_mod.resolve_diff(
            int(target["id"]),
            resolution="accept_plexus",
            resolved_by="bob",
        )
    )
    assert resolved["resolution"] == "accept_plexus"
    assert pushed == [{"address": "10.0.0.2", "dns_name": "core-02"}]


def test_resolve_diff_accept_plexus_invalid_for_missing_in_plexus(ipam_db, monkeypatch):
    source = _seed_source_and_inventory()
    asyncio.run(reconcile_mod.run_reconciliation(int(source["id"])))
    diffs = asyncio.run(db_module.list_reconciliation_diffs(source_id=int(source["id"])))
    target = next(d for d in diffs if d["drift_type"] == DRIFT_MISSING_IN_PLEXUS)

    async def _unreachable(*args, **kwargs):
        raise AssertionError("push must not be invoked for invalid resolution")

    monkeypatch.setattr(reconcile_mod, "push_allocation_to_provider", _unreachable)

    with pytest.raises(ValueError):
        asyncio.run(
            reconcile_mod.resolve_diff(
                int(target["id"]),
                resolution="accept_plexus",
                resolved_by="bob",
            )
        )


def test_resolve_diff_rejects_already_resolved(ipam_db):
    source = _seed_source_and_inventory()
    asyncio.run(reconcile_mod.run_reconciliation(int(source["id"])))
    diffs = asyncio.run(db_module.list_reconciliation_diffs(source_id=int(source["id"])))
    target = diffs[0]

    asyncio.run(
        reconcile_mod.resolve_diff(
            int(target["id"]),
            resolution="ignored",
            resolved_by="ops",
        )
    )
    with pytest.raises(ValueError):
        asyncio.run(
            reconcile_mod.resolve_diff(
                int(target["id"]),
                resolution="ignored",
                resolved_by="ops",
            )
        )


def test_resolve_diff_rejects_unknown_resolution(ipam_db):
    source = _seed_source_and_inventory()
    asyncio.run(reconcile_mod.run_reconciliation(int(source["id"])))
    diffs = asyncio.run(db_module.list_reconciliation_diffs(source_id=int(source["id"])))
    with pytest.raises(ValueError):
        asyncio.run(
            reconcile_mod.resolve_diff(
                int(diffs[0]["id"]),
                resolution="not-a-resolution",
                resolved_by="ops",
            )
        )


def test_resolve_diff_accept_plexus_requires_push_enabled(ipam_db, monkeypatch):
    source = _seed_source_and_inventory()
    # Disable push on this source.
    asyncio.run(db_module.update_ipam_source(int(source["id"]), push_enabled=False))

    asyncio.run(reconcile_mod.run_reconciliation(int(source["id"])))
    diffs = asyncio.run(db_module.list_reconciliation_diffs(source_id=int(source["id"])))
    target = next(d for d in diffs if d["drift_type"] == DRIFT_HOSTNAME_MISMATCH)

    with pytest.raises(ValueError, match="Push is not enabled"):
        asyncio.run(
            reconcile_mod.resolve_diff(
                int(target["id"]),
                resolution="accept_plexus",
                resolved_by="bob",
            )
        )
