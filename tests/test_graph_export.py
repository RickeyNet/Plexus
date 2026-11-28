"""Graph export: the chart option and the embed page of a host graph carry
the stored samples of its template's metrics (``netcontrol/routes/graph_export.py``).
"""

from __future__ import annotations

import asyncio
import json
import re

import pytest

import pg_raw
from mcp_helpers import admin_client


@pytest.fixture
def admin(monkeypatch, request):
    return admin_client(monkeypatch, request)


def _host_graph(admin, metric: str, instance_key: str = "") -> tuple[int, int]:
    """A host with a graph of a one-item template: ``(host id, host graph id)``."""
    group = admin.post("/api/inventory", json={"name": "graph-export"}).json()
    host = admin.post(
        f"/api/inventory/{group['id']}/hosts", json={"hostname": "edge-sw1", "ip_address": "192.0.2.21"}
    ).json()
    template = admin.post("/api/graph-templates", json={"name": "Export"}).json()
    item = admin.post(f"/api/graph-templates/{template['id']}/items", json={"metric_name": metric, "label": "Series"})
    assert item.status_code == 201, item.text
    graph = admin.post(
        "/api/host-graphs",
        json={"host_id": host["id"], "graph_template_id": template["id"], "instance_key": instance_key},
    )
    assert graph.status_code == 201, graph.text
    return host["id"], graph.json()["id"]


def _points(option: dict) -> list[float]:
    return [point[1] for point in option["series"][0]["data"]]


def test_chart_option_carries_the_samples_oldest_first(admin):
    host_id, graph_id = _host_graph(admin, "cpu_percent")
    asyncio.run(
        pg_raw.execute(
            """INSERT INTO metric_samples (host_id, metric_name, value, sampled_at) VALUES
               ($1, 'cpu_percent', 11, now() - interval '2 hours'),
               ($1, 'cpu_percent', 22, now() - interval '1 hour'),
               ($1, 'cpu_percent', 99, now() - interval '3 days'),
               ($1, 'memory_percent', 55, now() - interval '1 hour')""",
            host_id,
        )
    )

    resp = admin.get(f"/api/graphs/{graph_id}/config")
    assert resp.status_code == 200, resp.text
    assert _points(resp.json()) == [11, 22]
    assert _points(admin.get(f"/api/graphs/{graph_id}/config", params={"range": "7d"}).json()) == [99, 11, 22]


def test_embed_page_carries_the_samples(admin):
    host_id, graph_id = _host_graph(admin, "cpu_percent")
    asyncio.run(
        pg_raw.execute(
            "INSERT INTO metric_samples (host_id, metric_name, value) VALUES ($1, 'cpu_percent', 42)", host_id
        )
    )

    resp = admin.get(f"/api/graphs/{graph_id}/embed")
    assert resp.status_code == 200, resp.text
    data = re.search(r'<script id="chart-data" type="application/json">(.*?)</script>', resp.text, re.S)
    assert _points(json.loads(data.group(1))) == [42]


def test_interface_graph_falls_back_to_the_interface_series(admin):
    host_id, graph_id = _host_graph(admin, "if_in_bps", instance_key="7")
    asyncio.run(
        pg_raw.execute(
            """INSERT INTO interface_ts (host_id, if_index, in_rate_bps, out_rate_bps, sampled_at) VALUES
               ($1, 7, 1000, 9, now() - interval '2 hours'),
               ($1, 7, 2000, 9, now() - interval '1 hour'),
               ($1, 8, 5000, 9, now() - interval '1 hour')""",
            host_id,
        )
    )

    resp = admin.get(f"/api/graphs/{graph_id}/config")
    assert resp.status_code == 200, resp.text
    assert _points(resp.json()) == [1000, 2000]


def test_a_range_the_database_cannot_take_is_refused(admin):
    _, graph_id = _host_graph(admin, "cpu_percent")
    resp = admin.get(f"/api/graphs/{graph_id}/config", params={"range": "9" * 30 + "d"})
    assert resp.status_code == 422, resp.text
    assert admin.get(f"/api/graphs/{graph_id}/config", params={"range": "soon"}).status_code == 200
