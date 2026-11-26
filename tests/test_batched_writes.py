"""Bulk writes that used to run a statement per row (performance audit,
batch 2): DHCP snapshots, interface addresses, host graphs from templates,
SNMP data sources and bulk MAC move acknowledgement.

Each test checks that a mixed batch (new rows, rows already stored,
duplicates inside the batch and, where the old code tolerated it, a bad row)
leaves the same rows and return value as the per-row code did, and that the
number of statements no longer grows with the number of rows.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

import pytest
import routes.database as db
import routes.db.graphs as graphs


@contextlib.contextmanager
def _count_statements(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Every execute/executemany sent through the compat layer, in order."""
    seen: list[str] = []
    compat = db._PostgresConnectionCompat
    real_execute, real_many = compat.execute, compat.executemany

    async def execute(self, query, params=()):
        seen.append("execute")
        return await real_execute(self, query, params)

    async def executemany(self, query, params):
        seen.append("executemany")
        return await real_many(self, query, params)

    with monkeypatch.context() as patch:
        patch.setattr(compat, "execute", execute)
        patch.setattr(compat, "executemany", executemany)
        yield seen


async def _exec(sql: str, params: tuple = ()) -> None:
    conn = await db.get_db()
    try:
        await conn.execute(sql, params)
        await conn.commit()
    finally:
        await conn.close()


async def _rows(sql: str, params: tuple = ()) -> list[dict]:
    conn = await db.get_db()
    try:
        cursor = await conn.execute(sql, params)
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await conn.close()


async def _host(name: str, ip: str, group: str = "batch-core", device_type: str = "cisco_ios") -> int:
    groups = {g["name"]: g["id"] for g in await db.get_all_groups()}
    gid = groups.get(group) or await db.create_group(group)
    return await db.add_host(gid, name, ip, device_type)


# ── DHCP snapshot ────────────────────────────────────────────────────────────


def _lease(address: str, mac: str = "", **kw) -> dict:
    return {"address": address, "mac_address": mac, "scope_subnet": "192.0.2.0/24", **kw}


async def test_dhcp_snapshot_keeps_counts_first_duplicate_and_skips_blanks(monkeypatch):
    server = await db.create_dhcp_server("kea", "dhcp-a", base_url="https://dhcp.example.com")
    assert server is not None
    sid = int(server["id"])
    # An earlier snapshot is replaced, not merged.
    await db.replace_dhcp_server_snapshot(sid, [{"subnet": "198.51.100.0/24"}], [_lease("198.51.100.9")])

    scopes = [
        {"subnet": "192.0.2.0/24", "external_id": "1", "name": "first", "total_addresses": "254"},
        {"subnet": "192.0.2.0/24", "external_id": "1", "name": "duplicate"},
        {"subnet": "  "},
    ]
    leases = [
        _lease("192.0.2.10", "00:00:5e:00:53:01", hostname="pc-1", metadata={"k": 1}),
        _lease("192.0.2.10", "00:00:5e:00:53:99"),
        _lease("192.0.2.11", "00:00:5e:00:53:02"),
        _lease(""),
    ]
    with _count_statements(monkeypatch) as seen:
        result = await db.replace_dhcp_server_snapshot(sid, scopes, leases)
    # Counts are rows offered (blank ones aside), as before.
    assert result == {"scopes": 2, "leases": 3}
    stored_scopes = await db.list_dhcp_scopes(sid)
    assert [(s["subnet"], s["name"], s["total_addresses"]) for s in stored_scopes] == [("192.0.2.0/24", "first", 254)]
    stored = await db.list_dhcp_leases(sid)
    assert [(lease["address"], lease["mac_address"], lease["hostname"]) for lease in stored] == [
        ("192.0.2.10", "00:00:5e:00:53:01", "pc-1"),
        ("192.0.2.11", "00:00:5e:00:53:02", ""),
    ]
    assert stored[0]["metadata_json"] == '{"k":1}'
    # Two deletes, one executemany per table, the server update.
    assert seen == ["execute", "execute", "executemany", "executemany", "execute"]

    many = [_lease(f"192.0.2.{i}") for i in range(20, 120)]
    with _count_statements(monkeypatch) as seen_many:
        assert (await db.replace_dhcp_server_snapshot(sid, scopes, many))["leases"] == 100
    assert seen_many == seen
    assert len(await db.list_dhcp_leases(sid)) == 100


async def test_dhcp_snapshot_bad_value_writes_nothing():
    server = await db.create_dhcp_server("kea", "dhcp-b")
    assert server is not None
    sid = int(server["id"])
    await db.replace_dhcp_server_snapshot(sid, [], [_lease("192.0.2.5")])
    with pytest.raises(ValueError):
        await db.replace_dhcp_server_snapshot(sid, [{"subnet": "192.0.2.0/24", "total_addresses": "many"}], [])
    # All or nothing, as before: the earlier snapshot is still there.
    assert [lease["address"] for lease in await db.list_dhcp_leases(sid)] == ["192.0.2.5"]


# ── Interface addresses ──────────────────────────────────────────────────────


def _addr(interface: str, address: str, vrf: str = "") -> dict:
    return {
        "interface": interface,
        "interface_key": interface.lower(),
        "address": address,
        "prefix_length": 24,
        "network": address.rsplit(".", 1)[0] + ".0/24",
        "vrf_name": vrf,
        "role": "primary",
        "protocol": "",
        "svi_vid": 0,
    }


async def test_interface_addresses_batch_keeps_order_and_skips_duplicates(monkeypatch):
    host = await _host("edge-1", "192.0.2.30")
    await db.replace_host_bindings(host, [_addr("Gi0/9", "198.51.100.9")], {"OLD": 1})
    rows = [
        _addr("Gi0/2", "192.0.2.2", "BLUE"),
        _addr("Gi0/1", "192.0.2.1"),
        _addr("Gi0/2", "192.0.2.2", "RED"),  # same (interface, address): skipped
    ]
    with _count_statements(monkeypatch) as seen:
        assert await db.replace_host_bindings(host, rows, {"BLUE": 1, "GREEN": 0}) is True
    stored = await _rows(
        "SELECT interface, address, vrf_name FROM interface_addresses WHERE host_id = ? ORDER BY id", (host,)
    )
    assert stored == [
        {"interface": "Gi0/2", "address": "192.0.2.2", "vrf_name": "BLUE"},
        {"interface": "Gi0/1", "address": "192.0.2.1", "vrf_name": ""},
    ]
    vrfs = await _rows("SELECT vrf_name, interface_count FROM host_vrfs WHERE host_id = ? ORDER BY vrf_name", (host,))
    assert vrfs == [{"vrf_name": "BLUE", "interface_count": 1}, {"vrf_name": "GREEN", "interface_count": 0}]
    assert {"BLUE", "GREEN", "RED"} <= {v["name"] for v in await db.list_vrfs()}

    # Same VRF names as above: VRF records are still made one name at a time.
    many = [_addr(f"Gi1/{i}", f"203.0.113.{i}", "RED") for i in range(1, 60)]
    with _count_statements(monkeypatch) as seen_many:
        await db.replace_host_bindings(host, many, {"BLUE": 1, "GREEN": 0})
    assert len(seen_many) == len(seen)


# ── Host graphs from templates ───────────────────────────────────────────────


async def test_device_templates_create_only_new_graphs_in_one_transaction(monkeypatch):
    host = await _host("core-1", "192.0.2.40")
    cpu = await graphs.create_graph_template(name="batch-cpu", scope="device", title_format="CPU")
    mem = await graphs.create_graph_template(name="batch-mem", scope="device")
    disk = await graphs.create_graph_template(name="batch-disk", scope="device")
    first = await graphs.create_host_template(name="batch-all", device_types="[]")
    second = await graphs.create_host_template(name="batch-ios", device_types='["CISCO_IOS"]')
    other = await graphs.create_host_template(name="batch-other", device_types='["juniper_junos"]')
    for ht, gt in ((first, cpu), (first, mem), (second, mem), (second, disk), (other, disk)):
        await graphs.link_graph_template_to_host_template(ht["id"], gt["id"])
    # Already there: not created again, not reported.
    await graphs.create_host_graph(host, mem["id"], title="kept")

    with _count_statements(monkeypatch) as seen:
        created = await graphs.apply_graph_templates_to_host(host)
    # Host templates are read in no set order, so compare as a set; the rows
    # still come back in creation (id) order.
    assert {(g["graph_template_id"], g["title"], g["instance_key"]) for g in created} == {
        (cpu["id"], "CPU", ""),
        (disk["id"], "batch-disk", ""),
    }
    assert len(created) == 2
    assert [g["id"] for g in created] == sorted(g["id"] for g in created)
    # Host, host templates, links of each matching template, then one insert.
    assert seen == ["execute"] * 5
    assert await graphs.apply_graph_templates_to_host(host) == []
    titles = {g["graph_template_id"]: g["title"] for g in await graphs.list_host_graphs(host)}
    assert titles[mem["id"]] == "kept"
    assert await graphs.apply_graph_templates_to_host(999999) == []


async def test_interface_templates_batch_returns_new_rows_in_request_order(monkeypatch):
    host = await _host("access-1", "192.0.2.41")
    traffic = await graphs.create_graph_template(
        name="batch-if", scope="interface", title_format="$interface ($ifIndex)"
    )
    errors = await graphs.create_graph_template(name="batch-err", scope="interface")
    await graphs.create_host_graph(host, errors["id"], title="kept", instance_key="2")
    ifaces = [
        {"if_index": "2", "if_name": "Gi0/2"},
        {"ifIndex": 1, "ifDescr": "Gi0/1"},
        {"if_index": "2", "if_name": "Gi0/2-again"},  # same instance: skipped
        {"if_index": "", "if_name": "no-index"},
    ]
    with _count_statements(monkeypatch) as seen:
        created = await graphs.apply_interface_graph_templates_to_host(host, ifaces)
    assert [(g["graph_template_id"], g["instance_key"], g["title"], g["instance_label"]) for g in created] == [
        (traffic["id"], "2", "Gi0/2 (2)", "Gi0/2"),
        (traffic["id"], "1", "Gi0/1 (1)", "Gi0/1"),
        (errors["id"], "1", "batch-err", "Gi0/1"),
    ]
    assert await graphs.apply_interface_graph_templates_to_host(host, ifaces) == []

    many = [{"if_index": str(i), "if_name": f"Te1/{i}"} for i in range(10, 70)]
    with _count_statements(monkeypatch) as seen_many:
        assert len(await graphs.apply_interface_graph_templates_to_host(host, many)) == 120
    # One template read and one insert, whatever the interface count.
    assert seen_many == seen == ["execute", "execute"]


# ── SNMP data sources ────────────────────────────────────────────────────────


def _source(key: str, name: str, **kw) -> dict:
    return {
        "instance_key": key,
        "name": name,
        "instance_label": name,
        "table_oid": "1.3.6.1.2.1.2.2.1",
        "oids_json": '{"if_type": "6"}',
        **kw,
    }


async def _sources(host: int) -> dict[str, dict]:
    return {s["instance_key"]: s for s in await db.list_snmp_data_sources(host, "interface")}


async def test_bulk_snmp_upsert_matches_the_single_row_upsert(monkeypatch):
    host = await _host("dist-1", "192.0.2.50")
    kept_id = await db.upsert_snmp_data_source(host, "interface", "1", name="old", poll_interval=60)
    batch = [
        _source("1", "Gi0/1"),  # existing: updated, poll interval (not passed) kept
        _source("2", "Gi0/2"),
        _source("2", "Gi0/2-renamed"),  # duplicate in the batch: the later one wins
        _source("3", "Gi0/3"),
    ]
    with _count_statements(monkeypatch) as seen:
        assert await db.upsert_snmp_data_sources(host, "interface", batch) == 4
    stored = await _sources(host)
    assert stored["1"]["id"] == kept_id and stored["1"]["name"] == "Gi0/1" and stored["1"]["poll_interval"] == 60
    assert stored["2"]["name"] == "Gi0/2-renamed" and stored["3"]["instance_label"] == "Gi0/3"
    assert stored["3"]["poll_interval"] == 300 and stored["3"]["index_oid"] == ""
    assert seen == ["executemany"]

    many = [_source(str(i), f"Te1/{i}") for i in range(10, 80)]
    with _count_statements(monkeypatch) as seen_many:
        assert await db.upsert_snmp_data_sources(host, "interface", many) == 70
    assert seen_many == ["executemany"]
    assert await db.upsert_snmp_data_sources(host, "interface", []) == 0
    # The single-row function shares the statement and still returns the id.
    assert await db.upsert_snmp_data_source(host, "interface", "3", name="again") == stored["3"]["id"]


async def test_bulk_snmp_upsert_skips_a_bad_row_and_stores_the_rest():
    host = await _host("dist-2", "192.0.2.51")
    batch = [
        _source("1", "Gi0/1", poll_interval=60),
        _source("2", "Gi0/2", poll_interval="not-a-number"),
        _source("3", "Gi0/3", poll_interval=120),
    ]
    assert await db.upsert_snmp_data_sources(host, "interface", batch) == 2
    stored = await _sources(host)
    assert sorted(stored) == ["1", "3"]
    assert (stored["1"]["poll_interval"], stored["3"]["poll_interval"]) == (60, 120)


# ── Bulk MAC move acknowledge ────────────────────────────────────────────────


async def _move(mac: str, host: int, status: str = "open") -> int:
    conn = await db.get_db()
    try:
        cursor = await conn.execute(
            "INSERT INTO mac_move_events (mac_address, status, from_host_id, to_host_id) VALUES (?, ?, ?, ?)",
            (mac, status, host, host),
        )
        await conn.commit()
        return int(cursor.lastrowid)
    finally:
        await conn.close()


async def test_bulk_mac_acknowledge_updates_and_writes_history_in_two_statements(monkeypatch):
    a = await _host("sw-a", "192.0.2.60", group="batch-east")
    b = await _host("sw-b", "192.0.2.61", group="batch-west")
    east = [await _move(f"00:00:5e:00:53:{i:02x}", a) for i in range(1, 4)]
    west = await _move("00:00:5e:00:53:aa", b)
    done = await _move("00:00:5e:00:53:bb", a, status="acknowledged")
    east_group = next(g["id"] for g in await db.get_all_groups() if g["name"] == "batch-east")

    with _count_statements(monkeypatch) as seen:
        assert await db.acknowledge_open_mac_move_events("alice", group_ids=[east_group]) == 3
    assert seen == ["execute", "executemany"]

    events = {e["id"]: e for e in await db.get_mac_move_events(limit=50)}
    assert all(events[i]["status"] == "acknowledged" and events[i]["acknowledged_by"] == "alice" for i in east)
    assert all(events[i]["acknowledged_at"] for i in east)
    assert events[west]["status"] == "open" and events[done]["acknowledged_by"] == ""
    history = await _rows(
        "SELECT event_id, mac_address, action, from_status, to_status, actor, details FROM "
        "mac_move_event_history ORDER BY id"
    )
    assert history == [
        {
            "event_id": i,
            "mac_address": f"00:00:5e:00:53:{n:02x}",
            "action": "acknowledged",
            "from_status": "open",
            "to_status": "acknowledged",
            "actor": "alice",
            "details": "bulk",
        }
        for n, i in enumerate(east, start=1)
    ]

    # Unscoped, no actor: the rest; then nothing is left.
    assert await db.acknowledge_open_mac_move_events() == 1
    last = await _rows("SELECT event_id, actor FROM mac_move_event_history WHERE event_id = ?", (west,))
    assert last == [{"event_id": west, "actor": "operator"}]
    with _count_statements(monkeypatch) as seen_none:
        assert await db.acknowledge_open_mac_move_events() == 0
    assert seen_none == ["execute"]
