"""Discovery sends the group's SNMP config only to confirmed addresses.

The group's SNMP settings (communities, SNMPv3 keys) are admin-only
secrets. A discovery scan or sync by an admin (or the API token) probes
every target with them; anyone else's probes with them only the address of
a confirmed inventory host they may change, and the other targets without
SNMP (TCP and ICMP). The result says how many targets were probed without
SNMP and why (``snmp_withheld``), in the scan job, the SSE ``start`` and
``done`` events and the sync response. A streamed sync stores the hosts it
adds as confirmed only for an admin.
"""

from __future__ import annotations

import asyncio
import json
import time

import netcontrol.routes.inventory as inventory
import pytest
import routes.database as db
from netcontrol.routes import state

from mcp_helpers import CsrfClient, admin_client, user_client

CONFIRMED_IP = "192.0.2.21"
UNCONFIRMED_IP = "198.51.100.22"
OUTSIDE_IP = "203.0.113.10"
WRITER_FEATURES = ["inventory", "inventory.write"]
SNMP_CFG = {"enabled": True, "version": "2c", "community": "example-community", "port": 161}


@pytest.fixture
def env(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    probed: list[tuple[str, bool]] = []
    found: dict[str, dict] = {}

    async def fake_probe(
        ip_address, timeout_seconds, device_type, hostname_prefix, use_snmp, snmp_config, use_icmp=True
    ):
        # No traffic: record whether the SNMP config would have been sent.
        probed.append((ip_address, bool(use_snmp)))
        return found.get(ip_address)

    monkeypatch.setattr(inventory, "_probe_discovery_target", fake_probe)
    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", lambda _gid=None: dict(SNMP_CFG))

    r = admin.post("/api/inventory", json={"name": "snmp-targets", "description": ""})
    assert r.status_code == 201, r.text
    group = int(r.json()["id"])
    # An admin's host: confirmed. A writer's host: awaiting confirmation.
    r = admin.post(f"/api/inventory/{group}/hosts", json={"hostname": "core-a", "ip_address": CONFIRMED_IP})
    assert r.status_code == 201, r.text
    writer = user_client(admin, "snmp-writer", features=WRITER_FEATURES)
    r = writer.post(f"/api/inventory/{group}/hosts", json={"hostname": "edge-b", "ip_address": UNCONFIRMED_IP})
    assert r.status_code == 201, r.text
    return {"admin": admin, "writer": writer, "group": group, "probed": probed, "found": found}


def _body(**extra) -> dict:
    body = {
        "cidrs": [f"{CONFIRMED_IP}/32", f"{UNCONFIRMED_IP}/32", f"{OUTSIDE_IP}/32"],
        "use_ssh": False,
        "use_icmp": False,
    }
    body.update(extra)
    return body


def _events(text: str) -> list[dict]:
    return [json.loads(line[len("data: ") :]) for line in text.splitlines() if line.startswith("data: ")]


def _job_result(client: CsrfClient, job_id: str) -> dict:
    for _ in range(200):
        job = client.get(f"/api/inventory/discovery/jobs/{job_id}").json()
        if job.get("status") == "completed":
            return job["result"]
        assert job.get("status") == "running", job
        time.sleep(0.05)
    raise AssertionError("discovery job did not finish")


def _assert_withheld(summary: dict, count: int) -> None:
    assert summary["count"] == count
    assert bool(summary["reason"]) is bool(count)


@pytest.mark.parametrize("path", ["scan", "scan/stream", "sync", "sync/stream"])
def test_non_admin_sends_snmp_only_to_confirmed_hosts(env, path):
    r = env["writer"].post(f"/api/inventory/{env['group']}/discovery/{path}", json=_body())
    assert r.status_code in (200, 202), r.text
    if path == "scan":
        _assert_withheld(_job_result(env["writer"], r.json()["job_id"])["snmp_withheld"], 2)
    elif path == "sync":
        _assert_withheld(r.json()["snmp_withheld"], 2)
    else:
        events = _events(r.text)
        _assert_withheld(events[0]["snmp_withheld"], 2)
        _assert_withheld(events[-1]["snmp_withheld"], 2)
        assert events[0]["type"] == "start" and events[-1]["type"] == "done"
    # Every target is still probed; only the confirmed host with SNMP.
    assert dict(env["probed"]) == {CONFIRMED_IP: True, UNCONFIRMED_IP: False, OUTSIDE_IP: False}


@pytest.mark.parametrize("path", ["scan", "sync/stream"])
def test_admin_sends_snmp_to_every_target(env, path):
    r = env["admin"].post(f"/api/inventory/{env['group']}/discovery/{path}", json=_body())
    assert r.status_code in (200, 202), r.text
    if path == "scan":
        _assert_withheld(_job_result(env["admin"], r.json()["job_id"])["snmp_withheld"], 0)
    else:
        _assert_withheld(_events(r.text)[-1]["snmp_withheld"], 0)
    assert dict(env["probed"]) == {CONFIRMED_IP: True, UNCONFIRMED_IP: True, OUTSIDE_IP: True}


def test_scan_without_snmp_withholds_nothing(env):
    r = env["writer"].post(f"/api/inventory/{env['group']}/discovery/sync", json=_body(use_snmp=False))
    assert r.status_code == 200, r.text
    _assert_withheld(r.json()["snmp_withheld"], 0)
    assert all(not used for _ip, used in env["probed"])


def test_streamed_sync_confirms_new_hosts_only_for_an_admin(env, monkeypatch):
    monkeypatch.setattr(state, "_resolve_snmp_discovery_config", lambda _gid=None: {"enabled": False})
    admin_new, writer_new = "192.0.2.31", "198.51.100.32"
    for ip in (admin_new, writer_new):
        env["found"][ip] = {"ip_address": ip, "hostname": f"found-{ip.rsplit('.', 1)[1]}", "device_type": "unknown"}

    for client, ip in ((env["admin"], admin_new), (env["writer"], writer_new)):
        r = client.post(
            f"/api/inventory/{env['group']}/discovery/sync/stream", json=_body(cidrs=[f"{ip}/32"], use_snmp=False)
        )
        assert r.status_code == 200, r.text
        assert _events(r.text)[-1]["sync"]["added"] == 1

    flags = {h["ip_address"]: int(h["address_confirmed"]) for h in asyncio.run(db.get_hosts_for_group(env["group"]))}
    assert flags[admin_new] == 1
    assert flags[writer_new] == 0
