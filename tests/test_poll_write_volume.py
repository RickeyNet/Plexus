"""Per-poll write volume: what one device poll stores, and that the readers
of it still get the same answers.

A poll of a 48-port switch used to write eight metric samples per interface
(four raw error/discard counters and their four rates) and the full
``if_details`` / ``vpn_details`` / ``route_snapshot`` blobs on every poll
row. It now writes the four rates only, and keeps the blobs on the newest
poll and on the first and last poll of each run of unchanged state.

The "legacy" host in these tests is written the way the poll wrote before
that change (raw counter samples added, every poll row keeping its blobs),
from the same poll sequence at the same clock, so the aggregates of both
hosts must be equal.
"""

from __future__ import annotations

import importlib
import json
from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db
from netcontrol.routes import metrics_engine, monitoring
from netcontrol.routes.billing import calculate_95th_percentile

import pg_raw

PORTS = 48
INTERVAL = 300
T0 = datetime(2026, 1, 5, 8, 0, tzinfo=UTC)
RAW_COUNTERS = [metric for _field, metric in db.INTERFACE_ERROR_COUNTERS]
RATE_METRICS = [f"{metric}_rate" for metric in RAW_COUNTERS]
_ROUTES = "\n".join(f"O    198.51.100.{i}/32 [110/2] via 192.0.2.1, GigabitEthernet1/0/1" for i in range(60))
_ERRORS_TEMPLATE = "Interface Errors & Discards"


def _stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%d %H:%M:%S")


def _poll_result(host_id: int, k: int, *, port2_down: bool = False) -> dict:
    """Poll ``k`` of a 48-port switch: traffic on every port, a slow error
    count on two ports (below the spike threshold), port 2 down on request."""
    interfaces = []
    for i in range(1, PORTS + 1):
        status = "down" if (i == 2 and port2_down) or i > 40 else "up"
        interfaces.append(
            {
                "if_index": i,
                "name": f"GigabitEthernet1/0/{i}",
                "status": status,
                "speed_mbps": 1000,
                "in_octets": 1_000_000 * i + k * 3_000_000 * i,
                "out_octets": 2_000_000 * i + k * 1_500_000 * i,
                "in_errors": 10 + k * 60 if i in (1, 10) else 0,
                "out_errors": 0,
                "in_discards": 5 + k * 30 if i == 10 else 0,
                "out_discards": 0,
            }
        )
    up = sum(1 for iface in interfaces if iface["status"] == "up")
    return {
        "host_id": host_id,
        "cpu_percent": 10.0 + k,
        "memory_percent": 40.0,
        "memory_used_mb": None,
        "memory_total_mb": None,
        "uptime_seconds": None,
        "if_up_count": up,
        "if_down_count": PORTS - up,
        "if_admin_down": 0,
        "if_details": interfaces,
        "vpn_tunnels_up": 2,
        "vpn_tunnels_down": 0,
        "vpn_details": [
            {"peer": "203.0.113.10", "status": "up", "raw": "203.0.113.10 QM_IDLE"},
            {"peer": "203.0.113.11", "status": "up", "raw": "203.0.113.11 QM_IDLE"},
        ],
        "route_count": 60,
        "route_snapshot": _ROUTES,
        "poll_status": "ok",
        "poll_error": "",
        "response_time_ms": 3.0 + k,
        "packet_loss_pct": 0.0,
        "icmp_alive": True,
        "icmp_rtt_ms": 2.5,
    }


async def _host(name: str, address: str) -> dict:
    groups = {g["name"]: g["id"] for g in await db.get_all_groups()}
    group_id = groups.get("poll-volume") or await db.create_group("poll-volume")
    host_id = await db.add_host(group_id, name, address, "cisco_ios")
    return {**(await db.get_host(host_id)), "group_id": group_id}


class _Clock:
    """Pins ``metrics_engine``'s clock, so rates come out the same each run."""

    def __init__(self, monkeypatch):
        self.now = T0
        clock = self

        class _Pinned(datetime):
            @classmethod
            def now(cls, tz=None):  # noqa: ARG003 - same signature as datetime.now
                return clock.now

        monkeypatch.setattr(metrics_engine, "datetime", _Pinned)


async def _age_counter_state(host_id: int, k: int) -> None:
    """Put the counter state the poll just stored at poll ``k``'s time and
    the previous one at the poll before, as a real 300 s cadence leaves it."""
    now, before = _stamp(T0 + timedelta(seconds=INTERVAL * k)), _stamp(T0 + timedelta(seconds=INTERVAL * (k - 1)))
    for table in ("interface_stats", "interface_error_stats"):
        await pg_raw.execute(
            f"UPDATE {table} SET polled_at = $1, "  # noqa: S608 - fixed table names
            "prev_polled_at = CASE WHEN prev_polled_at IS NULL THEN NULL ELSE $2 END WHERE host_id = $3",
            now,
            before,
            host_id,
        )


async def _legacy_raw_counter_samples(res: dict) -> None:
    """The four raw counter samples per interface the poll wrote before."""
    rows = []
    for iface in res["if_details"]:
        labels = json.dumps({"if_index": iface["if_index"], "if_name": iface["name"]})
        for field, metric in db.INTERFACE_ERROR_COUNTERS:
            rows.append((res["host_id"], metric, labels, float(iface.get(field) or 0)))
    await db.create_metric_samples_batch(rows)


async def _row_counts(host_id: int) -> dict[str, int]:
    counts = {}
    for table in ("metric_samples", "interface_ts", "monitoring_polls"):
        counts[table] = await pg_raw.fetchval(f"SELECT COUNT(*) FROM {table} WHERE host_id = $1", host_id)  # noqa: S608
    return counts


async def _stored_bytes(host_id: int) -> dict[str, int]:
    sizes = {}
    for table in ("metric_samples", "interface_ts", "monitoring_polls"):
        sizes[table] = int(
            await pg_raw.fetchval(
                f"SELECT COALESCE(SUM(pg_column_size(t.*)), 0) FROM {table} t WHERE host_id = $1",  # noqa: S608
                host_id,
            )
        )
    return sizes


async def _run_polls(monkeypatch, polls: int = 6) -> tuple[dict, dict, list[dict]]:
    """The same poll sequence on a host polled now and on a legacy host;
    port 2 goes down at poll 3. Returns both hosts and the new host's
    per-poll row deltas."""
    await db.init_db()
    clock = _Clock(monkeypatch)
    host = await _host("sw-new", "192.0.2.21")
    legacy = await _host("sw-legacy", "192.0.2.22")
    deltas = []
    for k in range(polls):
        clock.now = T0 + timedelta(seconds=INTERVAL * k)
        before = await _row_counts(host["id"])
        await monitoring._process_poll_result(host, _poll_result(host["id"], k, port2_down=k >= 3), [])
        after = await _row_counts(host["id"])
        deltas.append({t: after[t] - before[t] for t in after})
        await _age_counter_state(host["id"], k)

        legacy_res = _poll_result(legacy["id"], k, port2_down=k >= 3)
        with monkeypatch.context() as m:
            m.setattr(monitoring, "poll_details_digest", lambda *_a: None)
            await monitoring._process_poll_result(legacy, legacy_res, [])
        await _legacy_raw_counter_samples(legacy_res)
        await _age_counter_state(legacy["id"], k)
    return host, legacy, deltas


async def _poll_rows(host_id: int) -> list[dict]:
    rows = await pg_raw.fetch(
        "SELECT id, if_details, vpn_details, route_snapshot, details_digest FROM monitoring_polls "
        "WHERE host_id = $1 ORDER BY id",
        host_id,
    )
    return [dict(r) for r in rows]


# ── Rows written per poll ────────────────────────────────────────────────────


async def test_a_48_port_poll_writes_the_rates_and_no_raw_counters(monkeypatch):
    host, legacy, deltas = await _run_polls(monkeypatch)
    # Poll 0 has no previous counters, poll 1 no previous interval; from
    # poll 2 on every interface has its four rates.
    host_metrics = 9  # cpu, memory, response time, loss, 2 interface and 2 VPN counts, route count
    assert [d["metric_samples"] for d in deltas] == [host_metrics] * 2 + [host_metrics + 4 * PORTS] * 4
    assert [d["interface_ts"] for d in deltas] == [PORTS] * 6
    assert [d["monitoring_polls"] for d in deltas] == [1] * 6
    names = {
        r["metric_name"]
        for r in await pg_raw.fetch("SELECT DISTINCT metric_name FROM metric_samples WHERE host_id = $1", host["id"])
    }
    assert set(RATE_METRICS) <= names
    assert not set(RAW_COUNTERS) & names
    # The legacy writer's eight per interface, for the record.
    legacy_raw = await pg_raw.fetchval(
        "SELECT COUNT(*) FROM metric_samples WHERE host_id = $1 AND metric_name = ANY($2::text[])",
        legacy["id"],
        RAW_COUNTERS,
    )
    assert legacy_raw == 4 * PORTS * 6


async def test_stored_rows_and_bytes_drop_against_the_legacy_writer(monkeypatch):
    host, legacy, _deltas = await _run_polls(monkeypatch)
    new_rows, old_rows = await _row_counts(host["id"]), await _row_counts(legacy["id"])
    new_bytes, old_bytes = await _stored_bytes(host["id"]), await _stored_bytes(legacy["id"])
    print(f"\nrows after 6 polls: legacy={old_rows} now={new_rows}")
    print(f"bytes after 6 polls: legacy={old_bytes} now={new_bytes}")
    assert new_rows["metric_samples"] == old_rows["metric_samples"] - 4 * PORTS * 6
    assert new_rows["interface_ts"] == old_rows["interface_ts"]
    assert new_bytes["metric_samples"] < old_bytes["metric_samples"]
    # Two of six poll rows hold no blobs.
    assert new_bytes["monitoring_polls"] < old_bytes["monitoring_polls"]


# ── Aggregates ───────────────────────────────────────────────────────────────


async def test_rollups_p95_billing_sla_and_availability_equal_the_legacy_writer(monkeypatch):
    host, legacy, _deltas = await _run_polls(monkeypatch)
    await db.rollup_metric_samples(RATE_METRICS + RAW_COUNTERS, "hourly", "2000-01-01 00:00:00", "2999-01-01 00:00:00")

    async def rollups(host_id: int) -> dict:
        rows = await pg_raw.fetch(
            "SELECT metric_name, labels_json, val_min, val_avg, val_max, val_p95, sample_count "
            "FROM metric_rollups WHERE host_id = $1",
            host_id,
        )
        return {(r["metric_name"], r["labels_json"]): tuple(r)[2:] for r in rows}

    new, old = await rollups(host["id"]), await rollups(legacy["id"])
    old_rates = {key: value for key, value in old.items() if key[0] in RATE_METRICS}
    assert old_rates and new == old_rates
    # Port 1 errs at 60 per 300 s: 0.2 errors/s on every interval.
    port1 = json.dumps({"if_index": 1, "if_name": "GigabitEthernet1/0/1"})
    assert new[("if_in_errors_rate", port1)] == pytest.approx((0.2, 0.2, 0.2, 0.2, 4))

    # 95th percentile billing and the interface series read interface_ts.
    for if_index in (1, 2, 48):
        values = []
        for host_id in (host["id"], legacy["id"]):
            samples = await db.get_billing_samples_for_period(
                host_id, if_index, "2000-01-01 00:00:00", "2999-01-01 00:00:00"
            )
            values.append(calculate_95th_percentile([s["in_rate_bps"] for s in samples]))
        assert values[0] == values[1] > 0

    # SLA and availability read the poll rows' status and timing columns.
    sla = [
        {
            k: v
            for k, v in (await db.get_sla_host_metrics(days=1, host_id=host_id))["hosts"][host_id].items()
            if k not in ("host_id", "hostname", "ip_address")
        }
        for host_id in (host["id"], legacy["id"])
    ]
    assert sla[0]["total_polls"] == 6
    assert sla[0] == sla[1]
    availability = {
        h["host_id"]: {k: v for k, v in h.items() if k not in ("host_id", "hostname", "ip_address")}
        for h in (await db.get_availability_summary(days=1))["hosts"]
    }
    assert availability[host["id"]] == availability[legacy["id"]]


async def test_the_error_summary_and_chart_read_rates_and_the_newest_counters(monkeypatch):
    host, _legacy, _deltas = await _run_polls(monkeypatch)
    # The pinned clock put the counter state in the past; the summary window
    # is the database's "now".
    await pg_raw.execute("UPDATE interface_error_stats SET polled_at = $1", _stamp(datetime.now(UTC)))
    summary = await db.get_interface_error_summary(host["id"], days=1)
    by_key = {(r["metric_name"], json.loads(r["labels_json"])["if_index"]): r for r in summary}
    # The raw counter is the newest one (poll 5: 10 + 5 * 60), not a sample.
    assert by_key[("if_in_errors", 1)]["max_value"] == 310.0
    assert by_key[("if_in_discards", 10)]["max_value"] == 155.0
    assert by_key[("if_in_errors", 3)]["max_value"] == 0.0
    assert by_key[("if_in_errors_rate", 1)]["max_value"] == pytest.approx(0.2)
    assert by_key[("if_in_errors_rate", 1)]["sample_count"] == 4
    assert {r["metric_name"] for r in summary} == set(RAW_COUNTERS) | set(RATE_METRICS)

    # The per-port chart gets the rate series (it plots only those), for
    # that port only: ifIndex 1 must not match 10 to 19.
    trend = await db.get_interface_error_trending(host["id"], if_index=1)
    assert {json.loads(r["labels_json"])["if_index"] for r in trend} == {1}
    assert sorted({r["metric_name"] for r in trend}) == sorted(RATE_METRICS)
    assert len(trend) == 4 * 4


# ── Poll detail blobs ────────────────────────────────────────────────────────


async def test_blobs_stay_on_the_newest_poll_and_where_the_state_changed(monkeypatch):
    host, legacy, _deltas = await _run_polls(monkeypatch)
    rows = await _poll_rows(host["id"])
    stored = [r["if_details"] is not None for r in rows]
    # Polls 0-2 one state, 3-5 another (port 2 down): each run keeps its
    # first and last row.
    assert stored == [True, False, True, True, False, True]
    assert all((r["vpn_details"] is None) == (r["route_snapshot"] is None) == (not s) for r, s in zip(rows, stored))
    digests = [r["details_digest"] for r in rows]
    assert digests[0] == digests[1] == digests[2] != digests[3] == digests[4] == digests[5]
    # The legacy rows (no digest) all keep theirs.
    assert all(r["if_details"] is not None for r in await _poll_rows(legacy["id"]))
    # The newest row holds the newest poll's details, counters included.
    newest = json.loads(rows[-1]["if_details"])
    assert newest[0]["in_octets"] == _poll_result(host["id"], 5)["if_details"][0]["in_octets"]


async def test_latest_poll_readers_get_the_blobs(monkeypatch):
    host, _legacy, _deltas = await _run_polls(monkeypatch)
    latest = {p["host_id"]: p for p in await db.get_latest_monitoring_polls(include_details=True)}
    newest = latest[host["id"]]
    assert json.loads(newest["if_details"])[1]["status"] == "down"
    assert json.loads(newest["vpn_details"])[0]["peer"] == "203.0.113.10"
    assert newest["route_snapshot"] == _ROUTES
    # The device page asks for one history row with the details.
    (one,) = await db.get_monitoring_poll_history(host["id"], limit=1, include_details=True)
    assert one["if_details"] == newest["if_details"] and one["details_from_poll_id"] is None
    assert "details_digest" not in one


async def test_history_fills_a_cleared_row_from_its_run(monkeypatch):
    host, _legacy, _deltas = await _run_polls(monkeypatch)
    ids = [r["id"] for r in await _poll_rows(host["id"])]
    for limit in (6, 2):  # the whole run on the page, or only the cleared row's neighbour
        history = {p["id"]: p for p in await db.get_monitoring_poll_history(host["id"], limit, include_details=True)}
        cleared = history[ids[4]]
        assert cleared["details_from_poll_id"] in (ids[3], ids[5])
        assert json.loads(cleared["if_details"])[1]["status"] == "down"
        assert cleared["route_snapshot"] == _ROUTES
    history = await db.get_monitoring_poll_history(host["id"], 6, include_details=True)
    assert all(p["if_details"] is not None for p in history)
    first_run = {p["id"]: p for p in history}[ids[1]]
    assert first_run["details_from_poll_id"] in (ids[0], ids[2])
    assert json.loads(first_run["if_details"])[1]["status"] == "up"
    # The lean history (restart check, MCP) is unchanged.
    lean = await db.get_monitoring_poll_history(host["id"], 6)
    assert "if_details" not in lean[0] and "details_from_poll_id" not in lean[0]


async def test_retention_keeps_a_cleared_rows_source(monkeypatch):
    """Retention deletes the oldest polls first; the row a cleared row is
    filled from is newer, so it outlives it."""
    host, _legacy, _deltas = await _run_polls(monkeypatch)
    ids = [r["id"] for r in await _poll_rows(host["id"])]
    await pg_raw.execute("DELETE FROM monitoring_polls WHERE id = ANY($1::int[])", ids[:1] + ids[3:4])
    history = {p["id"]: p for p in await db.get_monitoring_poll_history(host["id"], 10, include_details=True)}
    assert history[ids[1]]["details_from_poll_id"] == ids[2]
    assert history[ids[4]]["details_from_poll_id"] == ids[5]


# ── Upgrade ──────────────────────────────────────────────────────────────────


async def test_migration_0143_upgrades_a_database_with_old_poll_rows(monkeypatch):
    migration = importlib.import_module("routes.migrations.0143_poll_details_digest")
    await db.init_db()
    await db.seed_built_in_graph_templates()
    host = await _host("sw-upgrade", "192.0.2.23")
    # The schema and rows of a database from before 0143.
    await pg_raw.execute("ALTER TABLE monitoring_polls DROP COLUMN details_digest")
    for column in ("if_details", "vpn_details", "route_snapshot"):
        await pg_raw.execute(f"ALTER TABLE monitoring_polls ALTER COLUMN {column} SET NOT NULL")
    await pg_raw.execute(
        """UPDATE graph_template_items SET metric_name = replace(metric_name, '_rate', ''), transform = 'rate'
           WHERE template_id IN (SELECT id FROM graph_templates WHERE built_in = 1 AND name = $1)""",
        _ERRORS_TEMPLATE,
    )
    legacy = json.dumps(_poll_result(host["id"], 0)["if_details"])
    for _ in range(3):
        await pg_raw.execute(
            "INSERT INTO monitoring_polls (host_id, if_details, vpn_details, route_snapshot, polled_at) "
            "VALUES ($1, $2, '[]', $3, $4)",
            host["id"],
            legacy,
            _ROUTES,
            _stamp(datetime.now(UTC)),
        )

    conn = await db.get_db()
    try:
        await migration.up(conn)
        await migration.up(conn)  # re-running is a no-op
    finally:
        await conn.close()
    assert migration.VERSION == 143
    nullable = {
        r["column_name"]: r["is_nullable"]
        for r in await pg_raw.fetch(
            "SELECT column_name, is_nullable FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'monitoring_polls'"
        )
    }
    assert nullable["details_digest"] == "YES"
    assert {nullable[c] for c in ("if_details", "vpn_details", "route_snapshot")} == {"YES"}
    items = await pg_raw.fetch(
        """SELECT metric_name, transform FROM graph_template_items WHERE template_id IN
           (SELECT id FROM graph_templates WHERE built_in = 1 AND name = $1) ORDER BY sort_order""",
        _ERRORS_TEMPLATE,
    )
    assert [(r["metric_name"], r["transform"]) for r in items] == [(m, "") for m in RATE_METRICS]

    # New polls after the old rows: the old rows are never cleared.
    clock = _Clock(monkeypatch)
    for k in range(3):
        clock.now = T0 + timedelta(seconds=INTERVAL * k)
        await monitoring._process_poll_result(host, _poll_result(host["id"], k), [])
    rows = await _poll_rows(host["id"])
    assert [r["details_digest"] is None for r in rows] == [True] * 3 + [False] * 3
    assert [r["if_details"] is not None for r in rows] == [True, True, True, True, False, True]
    history = await db.get_monitoring_poll_history(host["id"], 10, include_details=True)
    assert all(p["if_details"] is not None for p in history)
    # Startup re-applies SCHEMA on every boot; that must leave all of it as is.
    await db.init_db()
    assert len(await _poll_rows(host["id"])) == 6


async def test_digest_ignores_counters_but_not_state():
    res = _poll_result(1, 0)
    later = _poll_result(1, 7)
    vpn = json.dumps(res["vpn_details"])
    same = monitoring.poll_details_digest(res["if_details"], vpn, _ROUTES)
    assert monitoring.poll_details_digest(later["if_details"], vpn, _ROUTES) == same
    down = _poll_result(1, 0, port2_down=True)
    assert monitoring.poll_details_digest(down["if_details"], vpn, _ROUTES) != same
    assert monitoring.poll_details_digest(res["if_details"], "[]", _ROUTES) != same
    assert monitoring.poll_details_digest(res["if_details"], vpn, _ROUTES + "\nC 192.0.2.0/24") != same
