"""Tests for IPAM reporting and exports (Phase J)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db_module


@pytest.fixture
def report_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ipam_reporting.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-ipam-reporting")

    async def _prepare():
        await db_module.init_db()

    asyncio.run(_prepare())
    return db_path


async def _ensure_group(name: str) -> int:
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)", (name,)
        )
        if cur.lastrowid:
            gid = int(cur.lastrowid)
        else:
            cur2 = await db.execute(
                "SELECT id FROM inventory_groups WHERE name = ?", (name,)
            )
            row = await cur2.fetchone()
            gid = int(row[0])
        await db.commit()
        return gid
    finally:
        await db.close()


def test_utilization_report_includes_inventory_subnet(report_db):
    async def _go():
        gid = await _ensure_group("G1")
        await db_module.add_host(gid, "h1", "10.0.0.5")
        rows = await db_module.generate_ipam_utilization_report_data()
        assert any(r["subnet"].startswith("10.0.0.") for r in rows)
        target = next(r for r in rows if r["subnet"].startswith("10.0.0."))
        assert target["used"] >= 1
        assert "utilization_pct" in target

    asyncio.run(_go())


def test_utilization_report_threshold_filters(report_db):
    async def _go():
        # /30: 2 usable. Use both → 100%.
        gid = await _ensure_group("G1")
        await db_module.add_host(gid, "a", "10.20.0.1")
        await db_module.add_host(gid, "b", "10.20.0.2")
        await db_module.snapshot_subnet_utilization("10.20.0.0/30")
        # Empty subnet → 0%.
        await db_module.snapshot_subnet_utilization("10.21.0.0/30")

        all_rows = await db_module.generate_ipam_utilization_report_data()
        full_rows = await db_module.generate_ipam_utilization_report_data(
            threshold_pct=99.0
        )
        assert any(r["subnet"] == "10.21.0.0/30" for r in all_rows)
        assert all(r["utilization_pct"] >= 99.0 for r in full_rows)
        assert any(r["subnet"] == "10.20.0.0/30" for r in full_rows)

    asyncio.run(_go())


def test_utilization_report_sorted_by_pct_desc(report_db):
    async def _go():
        await db_module.snapshot_subnet_utilization("10.30.0.0/30")  # 0%
        gid = await _ensure_group("G1")
        await db_module.add_host(gid, "a", "10.31.0.1")
        await db_module.add_host(gid, "b", "10.31.0.2")
        await db_module.snapshot_subnet_utilization("10.31.0.0/30")  # 100%
        rows = await db_module.generate_ipam_utilization_report_data()
        pcts = [r["utilization_pct"] for r in rows]
        assert pcts == sorted(pcts, reverse=True)

    asyncio.run(_go())


def test_forecast_report_insufficient_data(report_db):
    async def _go():
        await db_module.snapshot_subnet_utilization("10.40.0.0/24")
        rows = await db_module.generate_ipam_forecast_report_data(min_points=2)
        target = next(r for r in rows if r["subnet"] == "10.40.0.0/24")
        assert target["status"] == "insufficient_data"
        assert target["days_to_target"] is None

    asyncio.run(_go())


def test_forecast_report_projects_exhaustion(report_db):
    async def _go():
        # Manually insert a rising trend of utilization snapshots.
        db = await db_module.get_db()
        try:
            base = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=20)
            for i, pct in enumerate([10.0, 25.0, 40.0, 55.0, 70.0]):
                ts = (base + timedelta(days=i * 5)).isoformat()
                await db.execute(
                    """INSERT INTO ipam_subnet_utilization
                       (subnet, vrf_name, total, used, reserved, pending, free,
                        utilization_pct, captured_at)
                       VALUES ('10.50.0.0/24','',254,?,0,0,?,?,?)""",
                    (int(254 * pct / 100), int(254 * (1 - pct / 100)), pct, ts),
                )
            await db.commit()
        finally:
            await db.close()

        rows = await db_module.generate_ipam_forecast_report_data(
            lookback_days=30, target_pct=90.0
        )
        target = next(r for r in rows if r["subnet"] == "10.50.0.0/24")
        assert target["samples"] == 5
        assert target["slope_pct_per_day"] is not None
        assert target["slope_pct_per_day"] > 0
        assert target["days_to_target"] is not None
        assert target["days_to_target"] > 0
        assert target["status"] in {"critical", "warning", "ok"}
        assert target["projected_exhaustion_at"] is not None

    asyncio.run(_go())


def test_forecast_report_flat_trend_is_stable(report_db):
    async def _go():
        db = await db_module.get_db()
        try:
            base = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=20)
            for i in range(4):
                ts = (base + timedelta(days=i * 5)).isoformat()
                await db.execute(
                    """INSERT INTO ipam_subnet_utilization
                       (subnet, vrf_name, total, used, reserved, pending, free,
                        utilization_pct, captured_at)
                       VALUES ('10.51.0.0/24','',254,127,0,0,127,50.0,?)""",
                    (ts,),
                )
            await db.commit()
        finally:
            await db.close()
        rows = await db_module.generate_ipam_forecast_report_data(lookback_days=30)
        target = next(r for r in rows if r["subnet"] == "10.51.0.0/24")
        assert target["status"] == "stable"
        assert target["days_to_target"] is None

    asyncio.run(_go())


def test_history_report_filters_by_address(report_db):
    async def _go():
        gid = await _ensure_group("G1")
        h1 = await db_module.add_host(gid, "x", "10.60.0.5")
        await db_module.remove_host(h1)
        await db_module.add_host(gid, "y", "10.60.0.6")
        rows = await db_module.generate_ipam_history_report_data(address="10.60.0.5")
        assert len(rows) == 1
        assert rows[0]["address"] == "10.60.0.5"
        assert rows[0]["hostname"] == "x"
        assert rows[0]["ended_at"] is not None
        assert rows[0]["duration_hours"] is not None

    asyncio.run(_go())


def test_history_report_filters_by_hostname(report_db):
    async def _go():
        gid = await _ensure_group("G1")
        await db_module.add_host(gid, "alpha", "10.70.0.1")
        await db_module.add_host(gid, "beta", "10.70.0.2")
        rows = await db_module.generate_ipam_history_report_data(hostname="alpha")
        assert len(rows) == 1
        assert rows[0]["hostname"] == "alpha"

    asyncio.run(_go())


def test_reporting_module_dispatches_ipam_report_types(report_db):
    """The reporting module's _generate_report_rows must accept the new types."""

    from netcontrol.routes import reporting

    async def _go():
        gid = await _ensure_group("G1")
        await db_module.add_host(gid, "u1", "10.80.0.1")

        util = await reporting._generate_report_rows("ipam_utilization", {})
        assert isinstance(util, list)
        assert any(r.get("subnet", "").startswith("10.80.0.") for r in util)

        forecast = await reporting._generate_report_rows(
            "ipam_forecast", {"lookback_days": 30}
        )
        assert isinstance(forecast, list)

        hist = await reporting._generate_report_rows(
            "ipam_history", {"hostname": "u1"}
        )
        assert isinstance(hist, list)
        assert any(r["hostname"] == "u1" for r in hist)

    asyncio.run(_go())


def test_tabular_pdf_renders_for_empty_and_populated(report_db):
    from netcontrol.routes.reporting import _render_tabular_pdf

    empty = _render_tabular_pdf("X", [])
    assert empty.startswith(b"%PDF-")
    rows = [
        {"subnet": "10.0.0.0/24", "utilization_pct": 50.0, "free": 100},
        {"subnet": "10.1.0.0/24", "utilization_pct": 25.0, "free": 200},
    ]
    pdf = _render_tabular_pdf("Test", rows)
    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf
