"""Latest-row reads driven from the hosts table, chunked retention deletes,
and the retention of availability transitions, IPAM history and flow
summaries (performance audit items)."""

from __future__ import annotations

import json

import netcontrol.routes.flow_collector as flow_collector
import netcontrol.routes.monitoring as monitoring_routes
import pytest
import routes.database as db_module

OLD = "2000-01-01 00:00:00"
OLDER = "1999-01-01 00:00:00"
NEW = "2999-01-01 00:00:00"


@pytest.fixture(autouse=True)
def _small_chunks(monkeypatch):
    # Several chunks per sweep, so the loop in chunked_delete is exercised.
    monkeypatch.setattr(db_module, "_DELETE_CHUNK_SIZE", 2)


async def _exec(sql: str, params: tuple = ()) -> None:
    db = await db_module.get_db()
    try:
        await db.execute(sql, params)
        await db.commit()
    finally:
        await db.close()


async def _rows(sql: str, params: tuple = ()) -> list[dict]:
    db = await db_module.get_db(read_only=True)
    try:
        cursor = await db.execute(sql, params)
        return db_module.rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def _group(name: str = "perf-group") -> int:
    await _exec("INSERT INTO inventory_groups (name) VALUES (?)", (name,))
    return int((await _rows("SELECT id FROM inventory_groups WHERE name = ?", (name,)))[0]["id"])


async def _hosts(count: int, group_id: int | None = None) -> list[int]:
    gid = group_id if group_id is not None else await _group()
    return [await db_module.add_host(gid, f"perf-host-{i}.example.com", f"192.0.2.{i + 10}") for i in range(count)]


async def _poll(host_id: int, polled_at: str, cpu: float, status: str = "ok") -> None:
    await _exec(
        "INSERT INTO monitoring_polls (host_id, cpu_percent, memory_percent, if_up_count, poll_status, polled_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (host_id, cpu, cpu / 2, 3, status, polled_at),
    )


# The query the lateral reads replaced: kept here as the reference result.
_REFERENCE_LATEST = """SELECT p.id, p.host_id, p.cpu_percent, p.polled_at FROM monitoring_polls p
    INNER JOIN (SELECT host_id, MAX(id) AS max_id FROM monitoring_polls GROUP BY host_id) latest
      ON p.id = latest.max_id
    JOIN hosts h ON h.id = p.host_id
    ORDER BY h.hostname"""


# ── Item 1: latest poll per host ─────────────────────────────────────────────


async def _seed_polls() -> list[int]:
    """Host 0 has no polls, host 1 one, host 2 three (the newest by id is
    not the newest by polled_at, so last_poll_at must still be the MAX)."""
    hosts = await _hosts(3)
    await _poll(hosts[1], "2026-01-01 10:00:00", 10.0)
    await _poll(hosts[2], "2026-01-01 09:00:00", 20.0)
    await _poll(hosts[2], "2026-01-02 09:00:00", 85.0, status="error")
    await _poll(hosts[2], "2026-01-01 08:00:00", 30.0)
    return hosts


async def test_latest_monitoring_polls_match_reference_query():
    hosts = await _seed_polls()
    expected = await _rows(_REFERENCE_LATEST)
    got = await db_module.get_latest_monitoring_polls()
    assert [(r["id"], r["host_id"], r["cpu_percent"]) for r in got] == [
        (r["id"], r["host_id"], r["cpu_percent"]) for r in expected
    ]
    assert hosts[0] not in {r["host_id"] for r in got}
    assert {r["host_id"]: r["cpu_percent"] for r in got} == {hosts[1]: 10.0, hosts[2]: 30.0}
    detailed = await db_module.get_latest_monitoring_polls(include_details=True, limit=1)
    assert len(detailed) == 1 and "if_details" in detailed[0]


async def test_latest_monitoring_polls_group_filters():
    gid = await _group("perf-a")
    other = await _group("perf-b")
    (in_group,) = await _hosts(1, gid)
    out_host = await db_module.add_host(other, "perf-out.example.com", "192.0.2.99")
    await _poll(in_group, "2026-01-01 10:00:00", 10.0)
    await _poll(out_host, "2026-01-01 10:00:00", 50.0)
    assert [r["host_id"] for r in await db_module.get_latest_monitoring_polls(group_id=gid)] == [in_group]
    assert [r["host_id"] for r in await db_module.get_latest_monitoring_polls(group_ids=[other])] == [out_host]
    assert await db_module.get_latest_monitoring_polls(group_ids=[]) == []


async def test_monitoring_summary_from_one_pass():
    await _seed_polls()
    summary = await db_module.get_monitoring_summary()
    assert summary["monitored_hosts"] == 2
    # Latest polls: host 1 cpu 10, host 2 cpu 30 (highest id, not newest time).
    assert summary["avg_cpu"] == 20.0
    assert summary["high_cpu_hosts"] == 0
    assert summary["error_hosts"] == 0
    assert summary["interfaces_up"] == 6
    assert summary["last_poll_at"] == "2026-01-02 09:00:00"


async def test_monitoring_summary_without_polls():
    await _hosts(2)
    summary = await db_module.get_monitoring_summary()
    assert summary["monitored_hosts"] == 0
    assert summary["avg_cpu"] is None
    assert summary["last_poll_at"] is None


async def test_latest_config_backups_and_compliance_status():
    h1, h2, h3 = await _hosts(3)
    for host, status in ((h1, "success"), (h1, "failed"), (h2, "success")):
        await _exec(
            "INSERT INTO config_backups (host_id, config_text, status, captured_at) VALUES (?, ?, ?, ?)",
            (host, "hostname example", status, NEW),
        )
    latest = {r["host_id"]: r["status"] for r in await db_module.get_latest_config_backups_per_host()}
    assert latest == {h1: "failed", h2: "success"}
    assert h3 not in latest

    await _exec("INSERT INTO compliance_profiles (name) VALUES ('perf-profile-a')")
    await _exec("INSERT INTO compliance_profiles (name) VALUES ('perf-profile-b')")
    pa, pb = [r["id"] for r in await _rows("SELECT id FROM compliance_profiles ORDER BY name")]
    for host, profile, status in (
        (h1, pa, "non-compliant"),
        (h1, pa, "compliant"),
        (h1, pb, "non-compliant"),
        (h2, pa, "non-compliant"),
        (h2, pa, "compliant"),
    ):
        await _exec(
            "INSERT INTO compliance_scan_results (profile_id, host_id, status) VALUES (?, ?, ?)",
            (profile, host, status),
        )
    status = {(r["host_id"], r["profile_id"]): r["status"] for r in await db_module.get_compliance_host_status()}
    assert status == {(h1, pa): "compliant", (h1, pb): "non-compliant", (h2, pa): "compliant"}
    only_b = await db_module.get_compliance_host_status(pb)
    assert [(r["host_id"], r["profile_name"]) for r in only_b] == [(h1, "perf-profile-b")]
    summary = await db_module.get_compliance_summary()
    assert summary["hosts_scanned"] == 2
    assert summary["hosts_non_compliant"] == 1


# ── Item 2: chunked retention deletes ────────────────────────────────────────


async def test_poll_alert_and_route_snapshot_retention():
    h1, h2 = await _hosts(2)
    for stamp in (OLD, OLD, OLD, NEW):
        await _poll(h1, stamp, 1.0)
    assert await db_module.delete_old_monitoring_polls(30) == 3
    assert [r["polled_at"] for r in await _rows("SELECT polled_at FROM monitoring_polls")] == [NEW]

    for stamp in (OLD, OLD, OLD, NEW):
        await _exec(
            "INSERT INTO monitoring_alerts (host_id, alert_type, metric, message, created_at) VALUES (?, ?, ?, ?, ?)",
            (h1, "threshold", "cpu", "cpu high", stamp),
        )
    assert await db_module.delete_old_monitoring_alerts(30) == 3
    assert len(await _rows("SELECT id FROM monitoring_alerts")) == 1

    # h1: three old snapshots (the newest of them is kept); h2: old + new.
    for host, stamp in ((h1, OLDER), (h1, OLDER), (h1, OLD), (h2, OLD), (h2, NEW)):
        await _exec("INSERT INTO route_snapshots (host_id, captured_at) VALUES (?, ?)", (host, stamp))
    assert await db_module.delete_old_route_snapshots(30) == 3
    kept = await _rows("SELECT host_id, captured_at FROM route_snapshots ORDER BY host_id")
    assert [(r["host_id"], r["captured_at"]) for r in kept] == [(h1, OLD), (h2, NEW)]


async def test_sla_and_mac_retention():
    (host,) = await _hosts(1)
    # period_start is part of the rollup's unique key: one hour each.
    for stamp in ("2000-01-01 00:00:00", "2000-01-01 01:00:00", "2000-01-01 02:00:00", NEW):
        await _exec(
            "INSERT INTO sla_metrics (host_id, period_start, period_end) VALUES (?, ?, ?)",
            (host, stamp, stamp),
        )
    assert await db_module.delete_old_sla_metrics(30) == 3
    assert len(await _rows("SELECT id FROM sla_metrics")) == 1

    for i, stamp in enumerate((OLD, OLD, OLD, NEW)):
        mac = f"00:00:5e:00:53:{i:02x}"
        await _exec("INSERT INTO mac_move_events (mac_address, detected_at) VALUES (?, ?)", (mac, stamp))
        await _exec(
            "INSERT INTO mac_tracking_history (mac_address, host_id, seen_at) VALUES (?, ?, ?)", (mac, host, stamp)
        )
        await _exec(
            "INSERT INTO mac_address_table (host_id, mac_address, last_seen) VALUES (?, ?, ?)", (host, mac, stamp)
        )
    assert await db_module.delete_old_mac_move_events(30) == 3
    assert await db_module.delete_old_mac_history(30) == 3
    assert await db_module.cleanup_stale_mac_entries(30) == 3
    for table in ("mac_move_events", "mac_tracking_history", "mac_address_table"):
        assert len(await _rows(f"SELECT id FROM {table}")) == 1  # nosec B608 - fixed names


async def test_topology_and_compliance_retention():
    h1, h2 = await _hosts(2)
    for stamp in (OLD, OLD, OLD, NEW):
        await _exec("INSERT INTO topology_changes (change_type, detected_at) VALUES ('added', ?)", (stamp,))
    assert await db_module.delete_old_topology_changes(30) == 3

    # h1: old success, old failure, newest-success (old) kept; h2: old
    # failure only (no success to keep) and a new success.
    for host, status, stamp in (
        (h1, "success", OLDER),
        (h1, "failed", OLD),
        (h1, "success", OLD),
        (h1, "failed", OLD),
        (h2, "failed", OLD),
        (h2, "success", NEW),
    ):
        await _exec("INSERT INTO config_backups (host_id, status, captured_at) VALUES (?, ?, ?)", (host, status, stamp))
    assert await db_module.delete_old_config_backups(30) == 4
    kept = await _rows("SELECT host_id, status, captured_at FROM config_backups ORDER BY host_id")
    assert [(r["host_id"], r["status"], r["captured_at"]) for r in kept] == [
        (h1, "success", OLD),
        (h2, "success", NEW),
    ]

    await _exec("INSERT INTO compliance_profiles (name) VALUES ('perf-retention')")
    (profile,) = [r["id"] for r in await _rows("SELECT id FROM compliance_profiles")]
    for stamp in (OLD, OLD, OLD, NEW):
        await _exec(
            "INSERT INTO compliance_scan_results (profile_id, host_id, scanned_at) VALUES (?, ?, ?)",
            (profile, h1, stamp),
        )
    assert await db_module.delete_old_compliance_scan_results(30) == 3


async def test_topology_availability_and_metric_retention():
    for stamp in (OLD, OLD, OLD, NEW):
        await _exec(
            "INSERT INTO topology_availability_transitions (provider, entity_type, entity_id, transition_at)"
            " VALUES ('aws', 'instance', 'perf-entity', ?)",
            (stamp,),
        )
    for i, stamp in enumerate((OLD, NEW)):
        await _exec(
            "INSERT INTO topology_entity_state (provider, entity_type, entity_id, last_seen)"
            " VALUES ('aws', 'instance', ?, ?)",
            (f"perf-state-{i}", stamp),
        )
    assert await db_module.purge_topology_availability(30) == 4
    assert len(await _rows("SELECT id FROM topology_availability_transitions")) == 1
    assert len(await _rows("SELECT id FROM topology_entity_state")) == 1


async def test_ipam_report_and_flow_retention():
    for stamp, ended in (("1999-01-01T00:00:00", "1999-06-01T00:00:00"),) * 3 + (
        ("1999-01-01T00:00:00", None),
        ("2999-01-01T00:00:00", "2999-06-01T00:00:00"),
    ):
        await _exec(
            "INSERT INTO ipam_ip_history (address, started_at, ended_at) VALUES ('192.0.2.50', ?, ?)",
            (stamp, ended),
        )
    # Closed old rows go; the open row (a current assignment) stays.
    assert await db_module.prune_ip_history(365) == 3
    assert len(await _rows("SELECT id FROM ipam_ip_history")) == 2

    for stamp in ("1999-01-01T00:00:00",) * 3 + ("2999-01-01T00:00:00",):
        await _exec("INSERT INTO ipam_subnet_utilization (subnet, captured_at) VALUES ('192.0.2.0/24', ?)", (stamp,))
    assert await db_module.prune_subnet_utilization(365) == 3

    for stamp in (OLD, OLD, OLD, NEW):
        await _exec("INSERT INTO report_runs (report_type, started_at) VALUES ('availability', ?)", (stamp,))
    assert await db_module.delete_old_report_runs(90) == 3

    for stamp in (OLD, OLD, OLD, NEW):
        await _exec(
            "INSERT INTO flow_summaries (summary_type, period_start, period_end, created_at)"
            " VALUES ('top_src', ?, ?, ?)",
            (stamp, stamp, stamp),
        )
    assert await db_module.cleanup_old_flow_summaries(30) == 3
    assert [r["created_at"] for r in await _rows("SELECT created_at FROM flow_summaries")] == [NEW]


# ── Item 3: tables now pruned by the retention passes ────────────────────────


async def _transition(host_id: int, entity_type: str, entity_id: str, new_state: str, at: str) -> None:
    await _exec(
        "INSERT INTO availability_transitions (host_id, entity_type, entity_id, old_state, new_state, transition_at)"
        " VALUES (?, ?, ?, 'unknown', ?, ?)",
        (host_id, entity_type, entity_id, new_state, at),
    )


async def test_availability_transitions_keep_newest_per_entity():
    h1, h2 = await _hosts(2)
    # h1 host entity: all old; the newest of them carries the current state.
    await _transition(h1, "host", "", "down", OLDER)
    await _transition(h1, "host", "", "up", OLDER)
    await _transition(h1, "host", "", "down", OLD)
    # h1 interface: old rows and a new one; the newest old row stays (the
    # state a report window opening before the new row starts from).
    await _transition(h1, "interface", "Gi0/1", "down", OLD)
    await _transition(h1, "interface", "Gi0/1", "up", OLD)
    await _transition(h1, "interface", "Gi0/1", "down", NEW)
    # h2: a single old transition, which is its newest, is kept.
    await _transition(h2, "host", "", "up", OLD)

    assert await db_module.delete_old_availability_transitions(400) == 3
    rows = await _rows(
        "SELECT host_id, entity_type, entity_id, new_state, transition_at FROM availability_transitions ORDER BY id"
    )
    assert [(r["host_id"], r["entity_type"], r["new_state"], r["transition_at"]) for r in rows] == [
        (h1, "host", "down", OLD),
        (h1, "interface", "up", OLD),
        (h1, "interface", "down", NEW),
        (h2, "host", "up", OLD),
    ]
    assert await db_module.get_last_availability_states(h1, "host") == {"": "down"}
    assert await db_module.get_last_availability_states(h1, "interface") == {"Gi0/1": "down"}


async def test_monitoring_retention_pass_prunes_transitions_and_ip_history(monkeypatch):
    (host,) = await _hosts(1)
    await _transition(host, "host", "", "down", OLDER)
    await _transition(host, "host", "", "up", OLD)
    await _transition(host, "host", "", "down", NEW)
    await _exec(
        "INSERT INTO ipam_ip_history (address, started_at, ended_at)"
        " VALUES ('192.0.2.60', '1999-01-01T00:00:00', '1999-02-01T00:00:00')"
    )
    days: list[int] = []
    real = db_module.delete_old_availability_transitions

    async def _spy(retention_days: int) -> int:
        days.append(retention_days)
        return await real(retention_days)

    monkeypatch.setattr(db_module, "delete_old_availability_transitions", _spy)
    monkeypatch.setattr(monitoring_routes, "_last_retention_cleanup", 0.0)
    monkeypatch.setitem(monitoring_routes.state.MONITORING_CONFIG, "retention_interval_seconds", 0)
    monkeypatch.setitem(monitoring_routes.state.MONITORING_CONFIG, "sla_retention_days", 400)
    await monitoring_routes._run_retention_cleanup_throttled()

    assert days == [400]
    states = [r["new_state"] for r in await _rows("SELECT new_state FROM availability_transitions ORDER BY id")]
    assert states == ["up", "down"]
    assert await _rows("SELECT id FROM ipam_ip_history WHERE address = '192.0.2.60'") == []


async def test_flow_aggregation_cycle_prunes_summaries(monkeypatch):
    async def _none(*_args, **_kwargs):
        return []

    async def _sync() -> None:
        return None

    for name in ("get_flow_top_talkers", "get_flow_top_applications", "get_flow_top_conversations"):
        monkeypatch.setattr(db_module, name, _none)
    monkeypatch.setattr(flow_collector, "sync_exporter_hosts", _sync)
    monkeypatch.setitem(flow_collector.FLOW_COLLECTOR_CONFIG, "summary_retention_days", 30)
    for stamp in (OLD, NEW):
        await _exec(
            "INSERT INTO flow_summaries (summary_type, period_start, period_end, created_at)"
            " VALUES ('top_src', ?, ?, ?)",
            (stamp, stamp, stamp),
        )
    await flow_collector.flow_aggregation_cycle()
    assert [r["created_at"] for r in await _rows("SELECT created_at FROM flow_summaries")] == [NEW]


# ── Item 4: the run list leaves out result_json ──────────────────────────────


async def test_report_run_list_omits_result_json():
    definition = await db_module.create_report_definition("perf-report")
    run = await db_module.create_report_run(definition["id"], "availability", json.dumps({"group_id": 1}))
    other = await db_module.create_report_run(None, "availability")
    await db_module.complete_report_run(run["id"], json.dumps({"rows": [{"host": "perf-host"}]}), 1)

    runs = await db_module.get_report_runs()
    assert {r["id"] for r in runs} == {run["id"], other["id"]}
    for r in runs:
        assert "result_json" not in r
        assert {"id", "report_id", "report_type", "parameters_json", "status", "row_count", "started_at"} <= set(r)
    assert [r["id"] for r in await db_module.get_report_runs(definition["id"])] == [run["id"]]
    assert [r["id"] for r in await db_module.get_report_runs(run_ids={other["id"]})] == [other["id"]]
    assert [r["id"] for r in await db_module.get_report_runs(definition["id"], run_ids={other["id"]})] == []
    assert await db_module.get_report_runs(run_ids=set()) == []

    detail = await db_module.get_report_run(run["id"])
    assert detail is not None
    assert json.loads(detail["result_json"]) == {"rows": [{"host": "perf-host"}]}
