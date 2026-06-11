"""Discovery-scan background job: launch, progress, result, and 404 polling."""

from __future__ import annotations

import asyncio

import netcontrol.routes.inventory as inventory
import pytest
from fastapi import HTTPException
from netcontrol.routes import background_jobs
from netcontrol.routes.inventory import DiscoveryScanRequest


async def _wait_for_job(job_id: str, deadline_seconds: float = 5.0) -> dict:
    deadline = asyncio.get_event_loop().time() + deadline_seconds
    while True:
        job = background_jobs.get_job(job_id)
        assert job is not None, "job vanished from the registry"
        if job["status"] != "running":
            return job
        assert asyncio.get_event_loop().time() < deadline, "job never finished"
        await asyncio.sleep(0.01)


def _request() -> DiscoveryScanRequest:
    return DiscoveryScanRequest(
        cidrs=["10.0.0.0/30"],  # expands to 10.0.0.1 and 10.0.0.2
        timeout_seconds=0.1,
        max_hosts=16,
        device_type="unknown",
        hostname_prefix="discovered",
        use_snmp=False,
        use_icmp=False,
    )


@pytest.mark.asyncio
async def test_discovery_scan_launches_job_and_collects_results(monkeypatch):
    async def fake_get_group(group_id):
        return {"id": group_id, "name": "lab"}

    async def fake_probe(ip_address, **kwargs):
        # Only one of the two targets is reachable.
        if ip_address == "10.0.0.2":
            return {"hostname": "discovered-10-0-0-2", "ip_address": ip_address,
                    "device_type": "unknown", "status": "discovered"}
        return None

    monkeypatch.setattr(inventory.db, "get_group", fake_get_group)
    monkeypatch.setattr(inventory, "_probe_discovery_target", fake_probe)
    monkeypatch.setattr(inventory.state, "_resolve_snmp_discovery_config",
                        lambda _gid: {"enabled": False})

    launched = await inventory.discovery_scan(1, _request())
    assert launched["status"] == "running"
    assert launched["total_targets"] == 2

    job = await _wait_for_job(launched["job_id"])
    assert job["status"] == "completed"
    assert job["progress"]["scanned"] == 2
    result = job["result"]
    assert result["scanned_hosts"] == 2
    assert result["discovered_count"] == 1
    assert result["discovered_hosts"][0]["ip_address"] == "10.0.0.2"

    # The polling endpoint returns the same record.
    polled = await inventory.get_discovery_scan_job(launched["job_id"])
    assert polled["job_id"] == launched["job_id"]


@pytest.mark.asyncio
async def test_discovery_scan_job_failure_is_reported(monkeypatch):
    async def fake_get_group(group_id):
        return {"id": group_id, "name": "lab"}

    async def exploding_probe(ip_address, **kwargs):
        raise RuntimeError("probe blew up")

    monkeypatch.setattr(inventory.db, "get_group", fake_get_group)
    monkeypatch.setattr(inventory, "_probe_discovery_target", exploding_probe)
    monkeypatch.setattr(inventory.state, "_resolve_snmp_discovery_config",
                        lambda _gid: {"enabled": False})

    launched = await inventory.discovery_scan(1, _request())
    job = await _wait_for_job(launched["job_id"])
    assert job["status"] == "failed"
    assert "probe blew up" in (job["error"] or "")


@pytest.mark.asyncio
async def test_discovery_job_poll_unknown_id_404s():
    with pytest.raises(HTTPException) as exc:
        await inventory.get_discovery_scan_job("not-a-job")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_discovery_scan_invalid_cidr_rejected_before_job(monkeypatch):
    async def fake_get_group(group_id):
        return {"id": group_id, "name": "lab"}

    monkeypatch.setattr(inventory.db, "get_group", fake_get_group)

    bad = _request()
    bad.cidrs = ["not-a-cidr"]
    with pytest.raises(HTTPException) as exc:
        await inventory.discovery_scan(1, bad)
    assert exc.value.status_code == 400
