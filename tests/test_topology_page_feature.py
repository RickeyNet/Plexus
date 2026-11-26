"""The topology page's VLAN search and status overlay need the topology
feature, as the rest of ``/api/topology`` does, and not the reports feature."""

from __future__ import annotations

import pytest

from mcp_helpers import admin_client, user_client

PAGE_READS = [
    ("/api/topology/search/hosts-by-vlan", {"vlan_id": 10}),
    ("/api/topology/overlay/status", None),
]


@pytest.fixture
def admin(monkeypatch, request):
    return admin_client(monkeypatch, request)


@pytest.mark.parametrize(("path", "params"), PAGE_READS)
def test_the_topology_feature_reads_the_page_data(admin, path, params):
    viewer = user_client(admin, "map-viewer", features=["topology"])
    resp = viewer.get(path, params=params)
    assert resp.status_code == 200, resp.text
    assert isinstance(resp.json()["hosts"], list)


@pytest.mark.parametrize(("path", "params"), PAGE_READS)
def test_the_reports_feature_alone_does_not(admin, path, params):
    reporter = user_client(admin, "report-reader", features=["reports"])
    assert reporter.get(path, params=params).status_code == 403
