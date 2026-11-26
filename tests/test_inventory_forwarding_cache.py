"""The per-host forwarding cache behind path trace, subnets and deep search
(``meraki_topology._inventory_forwarding``): every call reads only the ids
of the newest route capture and backup of each host; configuration and
route text are read, and parsed off the event loop, only for the hosts
whose capture, backup, group or alias tables changed."""

from __future__ import annotations

import threading
import time

import netcontrol.routes.meraki_topology as mt
import pytest
import routes.database as db_module
from netcontrol.bounded_map import BoundedDict

_CONFIG = "hostname edge-{n}\ninterface Vlan10\n ip address 192.0.2.{n} 255.255.255.0\n"


async def _hosts(count: int) -> tuple[int, list[dict]]:
    await db_module.init_db()
    group_id = await db_module.create_group("forwarding-cache")
    nodes = []
    for n in range(1, count + 1):
        host_id = await db_module.add_host(group_id, f"edge-{n}", f"198.51.100.{n}")
        await db_module.create_config_backup(None, host_id, _CONFIG.format(n=n))
        await db_module.create_route_snapshot(
            host_id, 1, f"C 192.0.2.0/24 is directly connected, Vlan10 ({n})", f"h{n}"
        )
        nodes.append(
            {
                "id": host_id,
                "ip": f"198.51.100.{n}",
                "device_type": "cisco_ios",
                "group_id": group_id,
                "group_name": "forwarding-cache",
                "in_inventory": True,
            }
        )
    return group_id, nodes


@pytest.fixture
def spies(monkeypatch):
    """Count the text reads and the hosts parsed, and where they were parsed."""
    seen: dict = {"configs": [], "routes": [], "parsed": [], "threads": set()}
    monkeypatch.setattr(mt, "_HOST_FORWARDING", BoundedDict(mt._HOST_FORWARDING_LIMIT))
    config_texts = db_module.get_latest_config_texts_for_hosts
    route_texts = db_module.get_latest_route_snapshots_for_hosts
    parse = mt.forwarding_for_host

    async def read_configs(host_ids):
        seen["configs"].append(sorted(host_ids))
        return await config_texts(host_ids)

    async def read_routes(host_ids):
        seen["routes"].append(sorted(host_ids))
        return await route_texts(host_ids)

    def parse_host(host, *args, **kwargs):
        seen["parsed"].append(host["ip_address"])
        seen["threads"].add(threading.current_thread() is threading.main_thread())
        return parse(host, *args, **kwargs)

    monkeypatch.setattr(db_module, "get_latest_config_texts_for_hosts", read_configs)
    monkeypatch.setattr(db_module, "get_latest_route_snapshots_for_hosts", read_routes)
    monkeypatch.setattr(mt, "forwarding_for_host", parse_host)
    return seen


async def test_id_reads_return_the_newest_successful_rows_only():
    _group, nodes = await _hosts(2)
    first, second = nodes[0]["id"], nodes[1]["id"]
    newest = await db_module.create_config_backup(None, first, "hostname edge-1\n")
    await db_module.create_config_backup(None, first, "", status="failed", error_message="timeout")
    newest_route = await db_module.create_route_snapshot(second, 2, "S 203.0.113.0/24 [1/0] via 192.0.2.254", "h")
    backups = await db_module.get_latest_config_backup_ids_for_hosts([first, second, 999999])
    routes = await db_module.get_latest_route_snapshot_ids_for_hosts([first, second, 999999])
    texts = await db_module.get_latest_config_texts_for_hosts([first, second])
    captures = await db_module.get_latest_route_snapshots_for_hosts([first, second])
    # The ids agree with the rows the text reads return.
    assert backups == {host_id: row["id"] for host_id, row in texts.items()}
    assert routes == {host_id: row["id"] for host_id, row in captures.items()}
    assert backups[first] == newest and routes[second] == newest_route
    assert await db_module.get_latest_config_backup_ids_for_hosts([]) == {}
    assert await db_module.get_latest_route_snapshot_ids_for_hosts([]) == {}


async def test_unchanged_hosts_read_no_text_and_parse_nothing(spies):
    _group, nodes = await _hosts(3)
    first = await mt._inventory_forwarding(nodes)
    assert set(first) == {n["id"] for n in nodes}
    assert len(spies["parsed"]) == 3 and spies["threads"] == {False}

    for seen in ("configs", "routes", "parsed"):
        spies[seen].clear()
    again = await mt._inventory_forwarding(nodes)
    assert spies == {"configs": [], "routes": [], "parsed": [], "threads": {False}}
    # The same cached entries, in the order of the graph's nodes.
    assert list(again) == [n["id"] for n in nodes]
    assert all(again[h] is first[h] for h in first)


async def test_a_changed_host_reloads_alone_and_replaces_its_entry(spies):
    _group, nodes = await _hosts(3)
    await mt._inventory_forwarding(nodes)
    changed = nodes[1]
    await db_module.create_config_backup(None, changed["id"], _CONFIG.format(n=42))
    for seen in ("configs", "routes", "parsed"):
        spies[seen].clear()

    result = await mt._inventory_forwarding(nodes)
    assert spies["configs"] == [[changed["id"]]] and spies["routes"] == [[changed["id"]]]
    assert spies["parsed"] == [changed["ip"]]
    assert set(result) == {n["id"] for n in nodes}
    # One entry per host: the new key replaced the old one.
    assert len(mt._HOST_FORWARDING) == 3

    # A new route capture or a group rename is a change too.
    await db_module.create_route_snapshot(nodes[0]["id"], 1, "C 192.0.2.0/24 is directly connected, Vlan20", "x")
    renamed = [dict(nodes[2], group_name="renamed"), *nodes[:2]]
    spies["parsed"].clear()
    await mt._inventory_forwarding(renamed)
    assert sorted(spies["parsed"]) == sorted([nodes[0]["ip"], nodes[2]["ip"]])
    assert len(mt._HOST_FORWARDING) == 3


async def test_the_cache_is_bounded_without_a_full_clear(spies, monkeypatch):
    _group, nodes = await _hosts(3)
    monkeypatch.setattr(mt, "_HOST_FORWARDING", BoundedDict(2))
    result = await mt._inventory_forwarding(nodes)
    # Every host is answered even when the cache cannot hold them all.
    assert set(result) == {n["id"] for n in nodes}
    assert list(mt._HOST_FORWARDING) == [nodes[1]["id"], nodes[2]["id"]]


async def test_second_call_cost(spies):
    """Before: every call read all config and route text; now an unchanged
    map reads only ids. Printed for the record (``-s``)."""
    _group, nodes = await _hosts(20)
    started = time.perf_counter()
    await mt._inventory_forwarding(nodes)
    cold = time.perf_counter() - started
    started = time.perf_counter()
    await mt._inventory_forwarding(nodes)
    warm = time.perf_counter() - started
    print(f"inventory forwarding, 20 hosts: cold {cold * 1000:.1f} ms, warm {warm * 1000:.1f} ms")
    assert len(spies["configs"]) == 1 and len(spies["parsed"]) == 20
