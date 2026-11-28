"""The flow views read the raw records, one scan per view.

``flow_summaries`` (hourly global top-50 lists, never read) can not answer
the views exactly: they have no host dimension for the object scope, no
interfaces or timeline buckets, and a top 50 per hour does not add up to
the top N of a longer window. So nothing writes them any more, and the
views take every aggregate from one ``GROUPING SETS`` scan instead of one
scan each. These tests check that one scan against a reference computed in
Python from the same generated records, per view and per filter.
"""

from __future__ import annotations

import random
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
import routes.database as db_module
import routes.db.flows as flows_db
from fastapi import HTTPException
from netcontrol.routes import flow_collector

NOW = datetime.now(UTC).replace(microsecond=0)
LIMIT = 10


@pytest.fixture(autouse=True)
def _records_aged_from_this_test():
    """Age the generated records from the start of each test, not from the
    import of this module: the views count back from the database's clock,
    and in a long run the two are many minutes apart."""
    global NOW
    NOW = datetime.now(UTC).replace(microsecond=0)


def _stamp(at: datetime) -> str:
    """``received_at`` as the database writes it (UTC, comparable as text
    with the ``datetime('now', ...)`` bounds)."""
    return at.strftime("%Y-%m-%d %H:%M:%S+00")


async def _execute(sql: str, params: tuple = ()) -> int | None:
    db = await db_module.get_db()
    try:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def _hosts() -> dict[str, int]:
    """Two inventory groups with one exporter host each."""
    ids: dict[str, int] = {}
    for group, host, ip in (("site-a", "edge-a", "192.0.2.1"), ("site-b", "edge-b", "192.0.2.2")):
        ids[group] = await _execute("INSERT INTO inventory_groups (name) VALUES (?)", (group,))
        ids[host] = await _execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, ?)", (ids[group], host, ip)
        )
    return ids


def _offsets(rng: random.Random, count: int) -> list[timedelta]:
    """Ages of generated records: inside the last five hours, never within
    two minutes of the one-hour bound, plus a few older than a day."""
    ages = []
    while len(ages) < count:
        minutes = rng.uniform(1, 300)
        if abs(minutes - 60) > 2:
            ages.append(timedelta(minutes=minutes))
    return ages + [timedelta(hours=30 + i) for i in range(5)]


async def _generate(ids: dict[str, int], count: int = 400, seed: int = 5) -> list[dict]:
    """Insert ``count`` records spread over five hours across both hosts and
    an unresolved exporter (no host), and return them as dicts."""
    rng = random.Random(seed)
    exporters = [("192.0.2.1", ids["edge-a"]), ("192.0.2.2", ids["edge-b"]), ("192.0.2.99", None)]
    rows = []
    for age in _offsets(rng, count):
        exporter_ip, host_id = rng.choice(exporters)
        rows.append(
            {
                "exporter_ip": exporter_ip,
                "host_id": host_id,
                "flow_type": "netflow_v9",
                "src_ip": f"198.51.100.{rng.randint(1, 30)}",
                "dst_ip": f"203.0.113.{rng.randint(1, 30)}",
                "src_port": rng.randint(1024, 65000),
                "dst_port": rng.choice([22, 53, 80, 123, 443, 8443]),
                "protocol": rng.choice([6, 17]),
                "bytes": rng.randint(1, 10**8),
                "packets": rng.randint(1, 5000),
                "input_if": rng.randint(1, 6),
                "output_if": rng.randint(1, 6),
                "received_at": NOW - age,
            }
        )
    await _insert(rows)
    return rows


async def _insert(rows: list[dict]) -> None:
    db = await db_module.get_db()
    try:
        await db.executemany(
            """INSERT INTO flow_records
               (exporter_ip, host_id, flow_type, src_ip, dst_ip, src_port, dst_port, protocol,
                bytes, packets, input_if, output_if, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    r["exporter_ip"],
                    r["host_id"],
                    r["flow_type"],
                    r["src_ip"],
                    r["dst_ip"],
                    r["src_port"],
                    r["dst_port"],
                    r["protocol"],
                    r["bytes"],
                    r["packets"],
                    r["input_if"],
                    r["output_if"],
                    _stamp(r["received_at"]),
                )
                for r in rows
            ],
        )
        await db.commit()
    finally:
        await db.close()


# ── the reference: the aggregates computed in Python ────────────────────────


def _within(rows: list[dict], hours: int) -> list[dict]:
    return [r for r in rows if r["received_at"] >= NOW - timedelta(hours=hours)]


def _ranked(rows: list[dict], key, fields: tuple[str, ...], limit: int) -> list[dict]:
    totals: dict = defaultdict(lambda: [0, 0, 0])
    for r in rows:
        entry = totals[key(r)]
        entry[0] += r["bytes"]
        entry[1] += r["packets"]
        entry[2] += 1
    ranked = sorted(totals.items(), key=lambda item: -item[1][0])[:limit]
    return [
        {
            **dict(zip(fields, k if isinstance(k, tuple) else (k,), strict=True)),
            "total_bytes": b,
            "total_packets": p,
            "flow_count": n,
        }
        for k, (b, p, n) in ranked
    ]


def _bucket(at: datetime, minutes: int) -> str:
    return at.strftime("%Y-%m-%dT%H:") + f"{at.minute // minutes * minutes:02d}:00"


def _reference(rows: list[dict], limit: int = LIMIT, bucket_minutes: int = 5) -> dict:
    timeline: dict = defaultdict(lambda: [0, 0, 0])
    sides: dict = defaultdict(lambda: {"in_bytes": 0, "out_bytes": 0, "flow_count": 0})
    for r in rows:
        point = timeline[_bucket(r["received_at"], bucket_minutes)]
        point[0] += r["bytes"]
        point[1] += r["packets"]
        point[2] += 1
        for column, side in (("input_if", "in_bytes"), ("output_if", "out_bytes")):
            entry = sides[(r["host_id"], r["exporter_ip"], r[column])]
            entry[side] += r["bytes"]
            entry["flow_count"] += 1
    interfaces = sorted(
        (
            {"host_id": h, "exporter_ip": e, "if_index": i, **v, "total_bytes": v["in_bytes"] + v["out_bytes"]}
            for (h, e, i), v in sides.items()
        ),
        key=lambda r: -r["total_bytes"],
    )[:limit]
    return {
        "top_src": _ranked(rows, lambda r: r["src_ip"], ("ip",), limit),
        "top_dst": _ranked(rows, lambda r: r["dst_ip"], ("ip",), limit),
        "top_applications": _ranked(rows, lambda r: (r["dst_port"], r["protocol"]), ("port", "protocol"), limit),
        "top_conversations": _ranked(rows, lambda r: (r["src_ip"], r["dst_ip"]), ("src_ip", "dst_ip"), limit),
        "top_interfaces": interfaces,
        "timeline": [
            {"bucket": b, "total_bytes": v[0], "total_packets": v[1], "flow_count": v[2]}
            for b, v in sorted(timeline.items())
        ],
    }


def _plain(found: dict) -> dict:
    return {name: [dict(row) for row in rows] for name, rows in found.items()}


class _CountingDb:
    """A connection that counts the statements run through it."""

    def __init__(self, db, counter: list[str]):
        self._db = db
        self._counter = counter

    async def execute(self, sql, *args, **kwargs):
        self._counter.append(sql)
        return await self._db.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._db, name)


def _count_statements(monkeypatch) -> list[str]:
    statements: list[str] = []
    real_get_db = flows_db._dbcore.get_db

    async def counting_get_db(*args, **kwargs):
        return _CountingDb(await real_get_db(*args, **kwargs), statements)

    monkeypatch.setattr(flows_db._dbcore, "get_db", counting_get_db)
    return statements


# ── tests ───────────────────────────────────────────────────────────────────


async def test_overview_matches_the_reference_and_every_single_reader():
    await db_module.init_db()
    rows = await _generate(await _hosts())
    expected = _reference(_within(rows, 6))

    overview = _plain(await db_module.get_flow_overview(hours=6, limit=LIMIT, bucket_minutes=5))
    assert overview == expected

    # The single-view readers (the per-view endpoints, the Dashboard panel)
    # return the same rows.
    assert await db_module.get_flow_top_talkers(hours=6, direction="src", limit=LIMIT) == expected["top_src"]
    assert await db_module.get_flow_top_talkers(hours=6, direction="dst", limit=LIMIT) == expected["top_dst"]
    assert await db_module.get_flow_top_applications(hours=6, limit=LIMIT) == expected["top_applications"]
    assert await db_module.get_flow_top_conversations(hours=6, limit=LIMIT) == expected["top_conversations"]
    assert await db_module.get_flow_top_interfaces(hours=6, limit=LIMIT) == expected["top_interfaces"]
    assert await db_module.get_flow_timeline(hours=6, bucket_minutes=5) == expected["timeline"]


async def test_overview_is_one_statement(monkeypatch):
    await db_module.init_db()
    await _generate(await _hosts(), count=50)
    statements = _count_statements(monkeypatch)
    await db_module.get_flow_overview(hours=6, limit=LIMIT)
    assert len(statements) == 1
    assert "GROUPING SETS" in statements[0]


async def test_overview_parts_compute_only_what_is_asked(monkeypatch):
    await db_module.init_db()
    rows = await _generate(await _hosts())
    expected = _reference(_within(rows, 6))
    statements = _count_statements(monkeypatch)

    talkers = await db_module.get_flow_overview(hours=6, limit=LIMIT, parts=["top_dst", "top_src"])
    assert talkers == {"top_src": expected["top_src"], "top_dst": expected["top_dst"]}
    assert "dst_port" not in statements[-1] and "input_if" not in statements[-1]
    assert await db_module.get_flow_overview(hours=6, limit=LIMIT, parts=["top_interfaces"]) == {
        "top_interfaces": expected["top_interfaces"]
    }
    assert len(statements) == 2
    assert await db_module.get_flow_overview(hours=6, parts=[]) == {}
    assert len(statements) == 2


async def test_overview_endpoint_rejects_unknown_parts(monkeypatch):
    monkeypatch.setattr(flow_collector, "_flow_scope", AsyncMock(return_value={}))
    with pytest.raises(HTTPException) as caught:
        await flow_collector.api_flow_overview(
            host_id=None, hours=1, limit=LIMIT, bucket_minutes=5, parts="top_src,nope"
        )
    assert caught.value.status_code == 400


async def test_scope_and_host_filters_apply_to_every_view():
    await db_module.init_db()
    ids = await _hosts()
    rows = await _generate(ids)

    scoped = _plain(await db_module.get_flow_overview(hours=6, limit=LIMIT, group_ids=[ids["site-a"]]))
    assert scoped == _reference([r for r in _within(rows, 6) if r["host_id"] == ids["edge-a"]])
    assert {r["host_id"] for r in scoped["top_interfaces"]} == {ids["edge-a"]}

    one_host = _plain(await db_module.get_flow_overview(host_id=ids["edge-b"], hours=6, limit=LIMIT))
    assert one_host == _reference([r for r in _within(rows, 6) if r["host_id"] == ids["edge-b"]])

    # A scope of no groups sees nothing.
    empty = await db_module.get_flow_overview(hours=6, limit=LIMIT, group_ids=[])
    assert all(rows == [] for rows in empty.values())


async def test_window_bounds_short_and_long():
    await db_module.init_db()
    rows = await _generate(await _hosts())
    last_hour = _plain(await db_module.get_flow_overview(hours=1, limit=LIMIT, bucket_minutes=1))
    assert last_hour == _reference(_within(rows, 1), bucket_minutes=1)
    # Records over a day old are outside a 24 h window and inside 48 h.
    day = await db_module.get_flow_overview(hours=24, limit=LIMIT, bucket_minutes=15)
    two_days = await db_module.get_flow_overview(hours=48, limit=LIMIT, bucket_minutes=15)
    assert sum(p["flow_count"] for p in day["timeline"]) == len(_within(rows, 24))
    assert sum(p["flow_count"] for p in two_days["timeline"]) == len(rows)


async def test_cloud_overview_matches_the_reference_and_its_readers():
    await db_module.init_db()
    rng = random.Random(11)
    rows = []
    for age in _offsets(rng, 200):
        account, provider = rng.choice([(1, "aws"), (2, "azure")])
        rows.append(
            {
                "exporter_ip": f"cloud-account-{account}",
                "host_id": None,
                "flow_type": f"cloud_{provider}_flow",
                "src_ip": f"198.51.100.{rng.randint(1, 20)}",
                "dst_ip": f"203.0.113.{rng.randint(1, 20)}",
                "src_port": 1024,
                "dst_port": 443,
                "protocol": 6,
                "bytes": rng.randint(1, 10**8),
                "packets": rng.randint(1, 5000),
                "input_if": 0,
                "output_if": 0,
                "received_at": NOW - age,
            }
        )
    await _insert(rows)

    for account_id, provider in ((None, None), (1, None), (None, "azure")):
        chosen = [
            r
            for r in _within(rows, 24)
            if (account_id is None or r["exporter_ip"] == f"cloud-account-{account_id}")
            and (provider is None or r["flow_type"] == f"cloud_{provider}_flow")
        ]
        expected = _reference(chosen, limit=LIMIT, bucket_minutes=15)
        found = await db_module.get_cloud_flow_overview(account_id, provider, 24, LIMIT, 15)
        summary = found["summary"]
        assert summary["flow_count"] == len(chosen)
        assert summary["total_bytes"] == sum(r["bytes"] for r in chosen)
        assert summary["total_packets"] == sum(r["packets"] for r in chosen)
        assert summary["unique_sources"] == len({r["src_ip"] for r in chosen})
        assert summary["unique_destinations"] == len({r["dst_ip"] for r in chosen})
        assert summary["first_seen"] == _stamp(min(r["received_at"] for r in chosen))
        assert summary["last_seen"] == _stamp(max(r["received_at"] for r in chosen))
        assert found["top_src"] == expected["top_src"]
        assert found["top_dst"] == expected["top_dst"]
        assert found["timeline"] == expected["timeline"]
        assert await db_module.get_cloud_flow_summary(account_id, provider, 24) == summary
        assert await db_module.get_cloud_flow_top_talkers(account_id, provider, 24, "dst", LIMIT) == found["top_dst"]
        assert await db_module.get_cloud_flow_timeline(account_id, provider, 24, 15) == found["timeline"]

    nothing = await db_module.get_cloud_flow_summary(account_id=999)
    assert nothing == {
        "flow_count": 0,
        "total_bytes": 0,
        "total_packets": 0,
        "unique_sources": 0,
        "unique_destinations": 0,
        "first_seen": None,
        "last_seen": None,
    }


async def test_overview_endpoint_enriches_and_keeps_the_scope(monkeypatch):
    await db_module.init_db()
    ids = await _hosts()
    rows = await _generate(ids, count=100)
    monkeypatch.setattr(flow_collector, "_flow_scope", AsyncMock(return_value={"group_ids": [ids["site-b"]]}))
    monkeypatch.setattr(flow_collector, "lookup_flow_asns", AsyncMock(return_value={}))

    reply = await flow_collector.api_flow_overview(host_id=None, hours=6, limit=LIMIT, bucket_minutes=5, parts="")
    expected = _reference([r for r in _within(rows, 6) if r["host_id"] == ids["edge-b"]])
    assert [r["ip"] for r in reply["top_src"]] == [r["ip"] for r in expected["top_src"]]
    assert all(r["protocol_name"] == "" for r in reply["top_src"] + reply["top_dst"])
    assert {r["service_name"] for r in reply["top_applications"]} <= {
        flow_collector.PORT_SERVICES.get(p, f"port-{p}") for p in (22, 53, 80, 123, 443, 8443)
    }
    assert all("if_name" in r for r in reply["top_interfaces"])
    assert sum(p["flow_count"] for p in reply["timeline"]) == len(
        [r for r in _within(rows, 6) if r["host_id"] == ids["edge-b"]]
    )
    flow_collector.lookup_flow_asns.assert_awaited_once()


async def test_aggregation_cycle_writes_no_summaries_and_drains_old_ones(monkeypatch):
    await db_module.init_db()
    await _generate(await _hosts(), count=50)
    old = _stamp(NOW - timedelta(days=40))
    recent = _stamp(NOW - timedelta(days=1))
    for created in (old, recent):
        await _execute(
            "INSERT INTO flow_summaries (summary_type, period_start, period_end, created_at) VALUES (?, ?, ?, ?)",
            ("top_src", created, created, created),
        )
    monkeypatch.setattr(flow_collector, "sync_exporter_hosts", AsyncMock())

    await flow_collector.flow_aggregation_cycle()
    await flow_collector.flow_aggregation_cycle()

    db = await db_module.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT created_at FROM flow_summaries")
        assert [r["created_at"] for r in await cursor.fetchall()] == [recent]
    finally:
        await db.close()
