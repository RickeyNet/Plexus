"""The availability and interface CSV exports answer with rows, with and
without their group and host filters.

Both statements select columns beside their aggregates, so every selected
column has to be grouped or aggregated, and the availability statement
takes its parameters in the order of its placeholders.

Every name and address below is invented test data.
"""

from __future__ import annotations

import asyncio
import csv
import io

import pytest
import routes.database as db

from mcp_helpers import admin_client

HOST_IP = "192.0.2.21"


def _rows(resp) -> list[dict]:
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/csv")
    return list(csv.DictReader(io.StringIO(resp.text)))


def _group_with_host(admin, group: str, hostname: str, ip_address: str) -> tuple[int, int]:
    created = admin.post("/api/inventory", json={"name": group})
    assert created.status_code == 201, created.text
    gid = int(created.json()["id"])
    host = admin.post(
        f"/api/inventory/{gid}/hosts", json={"hostname": hostname, "ip_address": ip_address, "device_type": "cisco_ios"}
    )
    assert host.status_code == 201, host.text
    return gid, int(host.json()["id"])


@pytest.fixture
def env(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    lab, sw1 = _group_with_host(admin, "Lab", "sw1", HOST_IP)
    core, sw2 = _group_with_host(admin, "Core", "sw2", "192.0.2.22")
    # (host, index, name, speed, in octets, out octets, in bps, out bps, utilization)
    samples = [
        (sw1, 1, "Gi0/1", 1000, 10, 20, 100.0, 200.0, 1.0),
        (sw1, 1, "Gi0/1", 1000, 30, 40, 300.0, 400.0, 3.0),
        (sw1, 2, "Gi0/2", 1000, 10, 20, 50.0, 60.0, 0.5),
        (sw2, 1, "Te1/1", 10000, 10, 20, 70.0, 80.0, 0.1),
    ]
    assert asyncio.run(db.create_interface_ts_batch(samples)) == 4
    return {"admin": admin, "lab": lab, "core": core, "sw1": sw1, "sw2": sw2}


def test_availability_export_lists_every_host_with_its_group(env):
    rows = _rows(env["admin"].get("/api/reports/export/availability"))
    # The seeded demo inventory is listed as well.
    assert {(r["hostname"], r["group_name"]) for r in rows} >= {("sw1", "Lab"), ("sw2", "Core")}
    assert len({r["host_id"] for r in rows}) == len(rows)


def test_availability_export_takes_the_group_filter_and_the_period(env):
    rows = _rows(env["admin"].get("/api/reports/export/availability", params={"group_id": env["core"], "days": 7}))
    assert [(r["hostname"], r["group_name"]) for r in rows] == [("sw2", "Core")]


def test_interface_export_has_one_row_per_interface(env):
    rows = _rows(env["admin"].get("/api/reports/export/interface"))
    assert [(r["hostname"], r["if_name"]) for r in rows] == [("sw1", "Gi0/1"), ("sw1", "Gi0/2"), ("sw2", "Te1/1")]
    first = rows[0]
    assert (first["ip_address"], int(first["if_index"]), int(first["if_speed_mbps"])) == (HOST_IP, 1, 1000)
    assert int(first["samples"]) == 2
    assert (float(first["avg_in_bps"]), float(first["peak_in_bps"])) == (200.0, 300.0)
    assert (float(first["avg_out_bps"]), float(first["peak_out_bps"])) == (300.0, 400.0)


def test_interface_export_takes_the_host_and_group_filters(env):
    admin = env["admin"]
    by_host = _rows(admin.get("/api/reports/export/interface", params={"host_id": env["sw1"]}))
    assert {r["hostname"] for r in by_host} == {"sw1"} and len(by_host) == 2
    by_group = _rows(admin.get("/api/reports/export/interface", params={"group_id": env["core"], "days": 2}))
    assert [(r["hostname"], r["if_name"]) for r in by_group] == [("sw2", "Te1/1")]
