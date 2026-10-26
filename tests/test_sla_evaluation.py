"""Tests for the SLA rollups and the server-side SLA target evaluation.

Covers:
  * rollups      - hourly rows from raw polls and daily rows from hourly ones,
                   with the sums that recombine them; a second pass writes
                   nothing (idempotent)
  * evaluation   - met / warn / breach for higher- and lower-is-better
                   metrics, group targets fanning out to the group's hosts and
                   sub-groups, status history, stale rows dropped
  * alerts       - one ``sla_breach`` alert per (target, host), deduplicated
                   across passes, escalated from warning to critical,
                   suppressed by an active suppression
  * HTTP API     - target window_days validation, POST /api/sla/evaluate,
                   GET /api/sla/compliance (+ history) and the summary's
                   compliance counts
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import netcontrol.app as app_module
import pytest
import routes.database as db_module
import routes.db.monitoring as db_monitoring
from netcontrol.routes.monitoring import classify_sla_value, evaluate_sla_targets, run_sla_cycle

import pg_raw


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


async def _group(name: str, parent_id: int | None = None) -> int:
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT INTO inventory_groups (name, parent_id) VALUES (?, ?)",
            (name, parent_id),
        )
        await db.commit()
        return int(cur.lastrowid)
    finally:
        await db.close()


async def _host(group_id: int, hostname: str, ip: str = "10.0.0.1") -> int:
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, ?)",
            (group_id, hostname, ip),
        )
        await db.commit()
        return int(cur.lastrowid)
    finally:
        await db.close()


async def _polls(host_id: int, rows: list[tuple[datetime, str, float | None, float | None]]) -> None:
    """Insert polls as (polled_at, poll_status, response_time_ms, packet_loss_pct)."""
    db = await db_module.get_db()
    try:
        for polled_at, status, rt, loss in rows:
            await db.execute(
                "INSERT INTO monitoring_polls (host_id, poll_status, response_time_ms, packet_loss_pct, polled_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (host_id, status, rt, loss, _ts(polled_at)),
            )
        await db.commit()
    finally:
        await db.close()


async def _fetch(sql: str, params: tuple = ()) -> list[dict]:
    db = await db_module.get_db(read_only=True)
    try:
        cur = await db.execute(sql, params)
        return db_module.rows_to_list(await cur.fetchall())
    finally:
        await db.close()


def _pop_stddev(values: list[float]) -> float:
    mean = sum(values) / len(values)
    return (sum((v - mean) ** 2 for v in values) / len(values)) ** 0.5


# ── classification ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("metric", "value", "target", "warning", "expected"),
    [
        ("uptime", 99.95, 99.9, 99.0, "met"),
        ("uptime", 99.9, 99.9, 99.0, "met"),
        ("uptime", 99.5, 99.9, 99.0, "warn"),
        ("uptime", 99.0, 99.9, 99.0, "warn"),
        ("uptime", 98.0, 99.9, 99.0, "breach"),
        ("latency", 40.0, 50.0, 100.0, "met"),
        ("latency", 50.0, 50.0, 100.0, "met"),
        ("latency", 75.0, 50.0, 100.0, "warn"),
        ("latency", 150.0, 50.0, 100.0, "breach"),
        ("jitter", 3.0, 5.0, 10.0, "met"),
        ("jitter", 12.0, 5.0, 10.0, "breach"),
        ("packet_loss", 0.5, 1.0, 5.0, "met"),
        ("packet_loss", 2.0, 1.0, 5.0, "warn"),
        ("packet_loss", 9.0, 1.0, 5.0, "breach"),
        ("uptime", None, 99.9, 99.0, "no_data"),
        ("latency", None, 50.0, 100.0, "no_data"),
    ],
)
def test_classify_sla_value(metric, value, target, warning, expected):
    assert classify_sla_value(metric, value, target, warning) == expected


# ── rollups ──────────────────────────────────────────────────────────────────


def test_rollup_writes_hourly_and_daily_rows_once():
    async def _go():
        gid = await _group("roll")
        hid = await _host(gid, "sw-roll")
        base = (datetime.now(UTC) - timedelta(days=3)).replace(hour=10, minute=0, second=0, microsecond=0)
        await _polls(
            hid,
            [
                (base + timedelta(minutes=10), "ok", 10.0, 0.0),
                (base + timedelta(minutes=20), "ok", 30.0, 0.0),
                (base + timedelta(hours=1, minutes=5), "error", None, 100.0),
                (base + timedelta(hours=1, minutes=10), "ok", 20.0, 50.0),
            ],
        )

        first = await db_module.rollup_sla_metrics()
        assert first == {"hourly_rows": 8, "daily_rows": 4}
        rows = await _fetch(
            "SELECT metric, time_window, value, sample_count, sum_value, sum_sq, period_start, period_end "
            "FROM sla_metrics WHERE host_id = ? ORDER BY time_window, period_start, metric",
            (hid,),
        )
        hourly = {(r["period_start"], r["metric"]): r for r in rows if r["time_window"] == "hourly"}
        h0, h1 = _ts(base), _ts(base + timedelta(hours=1))
        assert hourly[(h0, "uptime")]["value"] == pytest.approx(100.0)
        assert hourly[(h0, "uptime")]["period_end"] == h1
        assert hourly[(h1, "uptime")]["value"] == pytest.approx(50.0)
        assert hourly[(h1, "uptime")]["sample_count"] == 2
        assert hourly[(h1, "uptime")]["sum_value"] == pytest.approx(1.0)
        assert hourly[(h0, "latency")]["value"] == pytest.approx(20.0)
        assert hourly[(h0, "latency")]["sum_sq"] == pytest.approx(1000.0)
        assert hourly[(h0, "jitter")]["value"] == pytest.approx(10.0)
        assert hourly[(h1, "latency")]["sample_count"] == 1
        assert hourly[(h1, "packet_loss")]["value"] == pytest.approx(75.0)

        daily = {r["metric"]: r for r in rows if r["time_window"] == "daily"}
        day = base.strftime("%Y-%m-%d")
        assert daily["uptime"]["period_start"] == f"{day} 00:00:00"
        assert daily["uptime"]["period_end"] == f"{(base + timedelta(days=1)).strftime('%Y-%m-%d')} 00:00:00"
        assert daily["uptime"]["value"] == pytest.approx(75.0)
        assert daily["latency"]["value"] == pytest.approx(20.0)
        assert daily["jitter"]["value"] == pytest.approx(_pop_stddev([10.0, 30.0, 20.0]))
        assert daily["packet_loss"]["value"] == pytest.approx(37.5)

        second = await db_module.rollup_sla_metrics()
        assert second == {"hourly_rows": 0, "daily_rows": 0}
        count = await _fetch("SELECT COUNT(*) AS n FROM sla_metrics")
        assert count[0]["n"] == 12

    asyncio.run(_go())


def test_summary_spans_polls_purged_by_retention():
    async def _go():
        gid = await _group("long")
        hid = await _host(gid, "sw-long")
        now = datetime.now(UTC)
        old = (now - timedelta(days=60)).replace(hour=10, minute=0, second=0, microsecond=0)
        recent = (now - timedelta(days=2)).replace(hour=10, minute=0, second=0, microsecond=0)
        old_rows = [
            (old + timedelta(minutes=5), "ok", 10.0, 0.0),
            (old + timedelta(minutes=10), "ok", 20.0, 0.0),
            (old + timedelta(minutes=15), "error", None, 100.0),
            (old + timedelta(minutes=20), "ok", 30.0, 0.0),
        ]
        recent_rows = [
            (recent + timedelta(minutes=5), "ok", 40.0, 0.0),
            (recent + timedelta(hours=3), "ok", 50.0, 10.0),
            # Not rolled up yet (the current hour): read from the raw polls.
            (now - timedelta(seconds=30), "ok", 60.0, 0.0),
        ]
        await _polls(hid, old_rows + recent_rows)

        def _expected(rows):
            rts = [r[2] for r in rows if r[2] is not None]
            losses = [r[3] for r in rows if r[3] is not None]
            return {
                "uptime_pct": round(sum(1 for r in rows if r[1] == "ok") / len(rows) * 100, 3),
                "avg_latency_ms": round(sum(rts) / len(rts), 2),
                "jitter_ms": round(_pop_stddev(rts), 2),
                "avg_packet_loss_pct": round(sum(losses) / len(losses), 2),
                "total_polls": len(rows),
            }

        def _host_values(summary):
            host = next(h for h in summary["hosts"] if h["host_id"] == hid)
            return {
                k: host[k] for k in ("uptime_pct", "avg_latency_ms", "jitter_ms", "avg_packet_loss_pct", "total_polls")
            }

        everything = _expected(old_rows + recent_rows)
        raw_only = _host_values(await db_module.get_sla_summary(days=90))
        assert raw_only == pytest.approx(everything)

        await db_module.rollup_sla_metrics()
        assert _host_values(await db_module.get_sla_summary(days=90)) == pytest.approx(everything)

        # Raw retention (30 days) drops the old polls; the rollups keep them.
        await db_module.delete_old_monitoring_polls(30)
        remaining = await _fetch("SELECT COUNT(*) AS n FROM monitoring_polls WHERE host_id = ?", (hid,))
        assert remaining[0]["n"] == len(recent_rows)
        assert _host_values(await db_module.get_sla_summary(days=90)) == pytest.approx(everything)
        assert _host_values(await db_module.get_sla_summary(days=30)) == pytest.approx(_expected(recent_rows))

        detail = await db_module.get_sla_host_detail(hid, days=90)
        by_day = {d["day"]: d for d in detail["daily"]}
        old_day = by_day[old.strftime("%Y-%m-%d")]
        assert old_day["uptime_pct"] == pytest.approx(75.0)
        assert old_day["total_polls"] == 4
        assert old_day["avg_latency_ms"] == pytest.approx(20.0)
        assert by_day[recent.strftime("%Y-%m-%d")]["total_polls"] == 2

    asyncio.run(_go())


# ── evaluation ───────────────────────────────────────────────────────────────


def test_group_target_applies_to_group_and_sub_groups():
    async def _go():
        parent = await _group("Region")
        child = await _group("Site", parent_id=parent)
        other = await _group("Elsewhere")
        hp = await _host(parent, "sw-parent")
        hc = await _host(child, "sw-child", "10.0.0.2")
        ho = await _host(other, "sw-other", "10.0.0.3")
        recent = datetime.now(UTC) - timedelta(hours=2)
        for hid in (hp, hc, ho):
            await _polls(hid, [(recent, "ok", 5.0, 0.0)])

        group_target = await db_module.create_sla_target(
            "Region uptime", "uptime", 99.9, 99.0, group_id=parent, window_days=7
        )
        result = await evaluate_sla_targets()
        assert result["evaluated"] == 2 and result["met"] == 2

        rows = await db_module.get_sla_compliance(target_id=group_target)
        assert {r["host_id"] for r in rows} == {hp, hc}
        assert all(r["status"] == "met" and r["window_days"] == 7 for r in rows)
        assert {r["host_id"] for r in await db_module.get_sla_compliance(group_id=parent)} == {hp, hc}
        assert {r["host_id"] for r in await db_module.get_sla_compliance(group_id=child)} == {hc}

        # A global target covers every host.
        await db_module.create_sla_target("All latency", "latency", 10.0, 20.0)
        await evaluate_sla_targets()
        rows = await db_module.get_sla_compliance(host_id=ho)
        assert [r["target_name"] for r in rows] == ["All latency"]

    asyncio.run(_go())


def test_evaluation_alerts_dedup_escalate_and_record_history(monkeypatch):
    fired: list[dict] = []

    async def _hook(alert: dict) -> None:
        fired.append(alert)

    monkeypatch.setattr(db_monitoring, "_alert_created_hook", _hook)

    async def _go():
        gid = await _group("eval")
        hid = await _host(gid, "sw-eval")
        recent = datetime.now(UTC) - timedelta(hours=2)
        await _polls(hid, [(recent, "ok", 50.0, 0.0), (recent + timedelta(minutes=5), "error", 50.0, 0.0)])

        t_uptime = await db_module.create_sla_target("Core uptime", "uptime", 99.9, 99.0, host_id=hid)
        t_latency = await db_module.create_sla_target("Core latency", "latency", 10.0, 100.0, host_id=hid)
        await db_module.create_sla_target("Core loss", "packet_loss", 1.0, 5.0, host_id=hid)

        first = await evaluate_sla_targets()
        assert (first["met"], first["warn"], first["breach"], first["alerts"]) == (1, 1, 1, 2)
        alerts = {
            a["dedup_key"]: a
            for a in await _fetch("SELECT * FROM monitoring_alerts WHERE alert_type = 'sla_breach' ORDER BY id")
        }
        assert set(alerts) == {f"sla:{t_uptime}:{hid}", f"sla:{t_latency}:{hid}"}
        uptime_alert = alerts[f"sla:{t_uptime}:{hid}"]
        assert uptime_alert["severity"] == "critical"
        assert uptime_alert["metric"] == "sla_uptime"
        assert uptime_alert["value"] == pytest.approx(50.0)
        assert uptime_alert["threshold"] == pytest.approx(99.0)
        assert "Core uptime" in uptime_alert["message"] and "breached" in uptime_alert["message"]
        latency_alert = alerts[f"sla:{t_latency}:{hid}"]
        assert latency_alert["severity"] == "warning" and latency_alert["metric"] == "sla_latency"
        assert len(fired) == 2 and {a["hostname"] for a in fired} == {"sw-eval"}

        history = await db_module.get_sla_compliance_history(host_id=hid)
        assert len(history) == 3 and {h["previous_status"] for h in history} == {""}

        # A second pass bumps the open alerts instead of opening new ones and
        # records no history (nothing changed).
        await evaluate_sla_targets()
        rows = await _fetch("SELECT * FROM monitoring_alerts WHERE alert_type = 'sla_breach' ORDER BY id")
        assert len(rows) == 2 and all(r["occurrence_count"] == 2 for r in rows)
        assert len(fired) == 2
        assert len(await db_module.get_sla_compliance_history(host_id=hid)) == 3

        # warn -> breach escalates the open warning alert to critical.
        await db_module.update_sla_target(t_latency, warning_value=20.0)
        result = await evaluate_sla_targets()
        assert result["breach"] == 2
        escalated = await _fetch("SELECT * FROM monitoring_alerts WHERE id = ?", (latency_alert["id"],))
        assert escalated[0]["severity"] == "critical"
        history = await db_module.get_sla_compliance_history(target_id=t_latency, host_id=hid)
        assert [(h["status"], h["previous_status"]) for h in history] == [("breach", "warn"), ("warn", "")]
        status = await db_module.get_sla_compliance(target_id=t_latency)
        assert status[0]["status"] == "breach" and status[0]["value"] == pytest.approx(50.0)

        # A disabled target's status rows are dropped on the next pass.
        await db_module.update_sla_target(t_latency, enabled=0)
        await evaluate_sla_targets()
        assert await db_module.get_sla_compliance(target_id=t_latency) == []

    asyncio.run(_go())


def test_active_suppression_blocks_sla_alert():
    async def _go():
        gid = await _group("supp")
        hid = await _host(gid, "sw-supp")
        await _polls(hid, [(datetime.now(UTC) - timedelta(hours=1), "error", None, 100.0)])
        await db_module.create_sla_target("Supp uptime", "uptime", 99.9, 99.0, host_id=hid)
        await db_module.create_alert_suppression("maintenance", "2099-01-01 00:00:00", host_id=hid, metric="sla_uptime")
        result = await evaluate_sla_targets()
        assert result["breach"] == 1 and result["alerts"] == 0 and result["suppressed"] == 1
        assert await _fetch("SELECT id FROM monitoring_alerts WHERE alert_type = 'sla_breach'") == []
        assert (await db_module.get_sla_compliance(host_id=hid))[0]["status"] == "breach"

    asyncio.run(_go())


def test_target_without_data_is_no_data_and_raises_nothing():
    async def _go():
        gid = await _group("quiet")
        hid = await _host(gid, "sw-quiet")
        await db_module.create_sla_target("Quiet uptime", "uptime", 99.9, 99.0, host_id=hid)
        result = await run_sla_cycle()
        assert result["evaluation"]["no_data"] == 1 and result["evaluation"]["alerts"] == 0
        row = (await db_module.get_sla_compliance(host_id=hid))[0]
        assert row["status"] == "no_data" and row["value"] is None and row["sample_count"] == 0

    asyncio.run(_go())


# ── HTTP API ─────────────────────────────────────────────────────────────────


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._headers = client, {"X-CSRF-Token": csrf}

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        return self._c.post(url, headers=self._headers, **kw)

    def put(self, url, **kw):
        return self._c.put(url, headers=self._headers, **kw)


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-sla-eval")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def _seed_api_host() -> tuple[int, int]:
    async def _seed() -> tuple[int, int]:
        conn = await pg_raw.connect()
        try:
            gid = await conn.fetchval("INSERT INTO inventory_groups (name) VALUES ('sla-api') RETURNING id")
            hid = await conn.fetchval(
                "INSERT INTO hosts (group_id, hostname, ip_address) VALUES ($1, 'sw-api', '10.7.0.1') RETURNING id",
                gid,
            )
            polled = _ts(datetime.now(UTC) - timedelta(hours=1))
            for status in ("ok", "error"):
                await conn.execute(
                    "INSERT INTO monitoring_polls (host_id, poll_status, response_time_ms, packet_loss_pct, "
                    "polled_at) VALUES ($1, $2, 12.5, 0, $3)",
                    hid,
                    status,
                    polled,
                )
            return int(gid), int(hid)
        finally:
            await conn.close()

    return asyncio.run(_seed())


def test_sla_compliance_api(api):
    gid, hid = _seed_api_host()

    bad = api.post("/api/sla/targets", json={"name": "x", "metric": "uptime", "window_days": 0})
    assert bad.status_code == 400
    bad = api.post("/api/sla/targets", json={"name": "x", "metric": "cpu"})
    assert bad.status_code == 400
    created = api.post(
        "/api/sla/targets",
        json={
            "name": "API uptime",
            "metric": "uptime",
            "target_value": 99.9,
            "warning_value": 99,
            "group_id": gid,
            "window_days": 7,
        },
    )
    assert created.status_code == 201
    target_id = created.json()["id"]
    targets = api.get("/api/sla/targets").json()
    assert next(t for t in targets if t["id"] == target_id)["window_days"] == 7
    updated = api.put(f"/api/sla/targets/{target_id}", json={"window_days": 14})
    assert updated.status_code == 200 and updated.json()["window_days"] == 14
    assert api.put(f"/api/sla/targets/{target_id}", json={"window_days": 400}).status_code == 400

    evaluated = api.post("/api/sla/evaluate")
    assert evaluated.status_code == 200
    assert evaluated.json()["evaluation"]["breach"] == 1

    rows = api.get("/api/sla/compliance").json()
    assert len(rows) == 1
    row = rows[0]
    assert row["target_id"] == target_id and row["host_id"] == hid and row["hostname"] == "sw-api"
    assert row["status"] == "breach" and row["value"] == pytest.approx(50.0) and row["window_days"] == 14
    assert api.get(f"/api/sla/compliance?group_id={gid}").json()[0]["host_id"] == hid
    assert api.get(f"/api/sla/compliance?host_id={hid + 1000}").json() == []

    history = api.get(f"/api/sla/compliance/history?target_id={target_id}&host_id={hid}&limit=5").json()
    assert [h["status"] for h in history] == ["breach"]
    assert api.get("/api/sla/compliance/history?limit=0").status_code == 422

    summary = api.get("/api/sla/summary?days=30").json()
    assert summary["compliance"]["breach"] == 1 and summary["compliance"]["hosts"] == 1
    assert next(h for h in summary["hosts"] if h["host_id"] == hid)["sla_status"] == "breach"

    alerts = api.get("/api/monitoring/alerts").json()
    alert_list = alerts["alerts"] if isinstance(alerts, dict) else alerts
    assert any(a.get("dedup_key") == f"sla:{target_id}:{hid}" for a in alert_list)
