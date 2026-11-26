"""Topology concurrency: the scheduled discovery follow-up runs its hosts
side by side under the shared device-op semaphore, one failing host leaving
the others alone, and the graph cache coalesces builds per cache key, so a
slow build of one group does not hold up another."""

from __future__ import annotations

import asyncio

import netcontrol.routes.mac_tracking as mac_tracking
import netcontrol.routes.snmp as snmp
import netcontrol.routes.state as state
import netcontrol.routes.topology as topology
import routes.database as db_module


def _neighbors(host_id: int, count: int) -> list[dict]:
    return [
        {
            "source_host_id": host_id,
            "local_interface": f"Gi1/0/{i}",
            "remote_device_name": f"peer-{host_id}-{i}.example.com",
            "remote_interface": "Gi0/1",
            "remote_ip": f"192.0.2.{i + 1}",
            "protocol": "lldp",
        }
        for i in range(count)
    ]


async def test_discovery_follow_up_runs_hosts_concurrently_and_isolates_failures(monkeypatch):
    hosts = [
        {"id": i, "ip_address": f"198.51.100.{i}", "hostname": f"sw-{i}", "device_type": "cisco_ios"}
        for i in range(1, 8)
    ]
    walk_fails, write_fails = 7, 3
    monkeypatch.setitem(state.TOPOLOGY_DISCOVERY_CONFIG, "enabled", True)

    async def groups():
        return [{"id": 1, "name": "campus"}]

    async def group_hosts(_group_id):
        return hosts

    async def discover(host_id, _ip, _cfg, timeout_seconds=5.0):
        if host_id == walk_fails:
            raise TimeoutError("no answer")
        return _neighbors(host_id, host_id), []

    async def passthrough(walk_results, _cfgs):
        return walk_results, 0

    async def no_links(_host_id):
        return []

    active = {"now": 0, "peak": 0}
    written: list[int] = []

    async def write(host_id, neighbors, _if_stats):
        active["now"] += 1
        active["peak"] = max(active["peak"], active["now"])
        try:
            await asyncio.sleep(0.05)
            if host_id == write_fails:
                raise RuntimeError("database went away")
            written.append(host_id)
        finally:
            active["now"] -= 1

    async def noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(db_module, "get_all_groups", groups)
    monkeypatch.setattr(db_module, "get_hosts_for_group", group_hosts)
    monkeypatch.setattr(topology, "_snmp_hosts", lambda hs, _gid: (hs, {h["id"]: {} for h in hs}))
    monkeypatch.setattr(topology, "_discover_neighbors", discover)
    monkeypatch.setattr(topology, "_apply_inferred_topology", passthrough)
    monkeypatch.setattr(db_module, "get_topology_links_for_host", no_links)
    monkeypatch.setattr(topology, "_write_links_and_stats", write)
    monkeypatch.setattr(db_module, "resolve_topology_target_host_ids", noop)
    monkeypatch.setattr(snmp, "auto_discover_data_sources", noop)
    monkeypatch.setattr(mac_tracking, "collect_mac_arp_tables", noop)
    monkeypatch.setattr(mac_tracking, "collect_interface_inventory", noop)

    result = await topology._run_topology_discovery_once()

    # Same summary shape; the walk failure and the write failure are the two errors.
    ok_hosts = [h["id"] for h in hosts if h["id"] not in (walk_fails, write_fails)]
    assert result == {
        "enabled": True,
        "groups_scanned": 1,
        "links_discovered": sum(ok_hosts),
        "errors": 2,
    }
    assert sorted(written) == ok_hosts
    # Side by side, but never past the shared cap.
    assert active["peak"] == min(state.DEVICE_OP_CONCURRENCY, 6)
    assert active["peak"] > 1 or state.DEVICE_OP_CONCURRENCY == 1


async def test_a_slow_build_does_not_block_other_groups_and_same_key_coalesces(monkeypatch):
    topology.invalidate_topology_cache()
    release = asyncio.Event()
    builds: list[int | None] = []

    async def build(group_id, links_scope=None):
        builds.append(group_id)
        if group_id == 1:
            await release.wait()
        return {"nodes": [], "edges": [], "group": group_id}

    monkeypatch.setattr(topology, "_build_topology", build)
    try:
        slow = asyncio.create_task(topology.topology_graph(1))
        slow_twin = asyncio.create_task(topology.topology_graph(1))
        await asyncio.sleep(0)
        # Group 2 builds while group 1's build is still waiting.
        other = await asyncio.wait_for(topology.topology_graph(2), timeout=2)
        assert other["group"] == 2
        release.set()
        first, second = await asyncio.gather(slow, slow_twin)
        assert first is second
        assert builds.count(1) == 1 and builds.count(2) == 1
    finally:
        release.set()
        topology.invalidate_topology_cache()
