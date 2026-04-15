"""Network documentation reporting tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import netcontrol.routes.reporting as reporting_module
import pytest
import routes.database as db_module


class DummyRequest:
    def __init__(self):
        self.state = type("S", (), {"correlation_id": "test-corr"})()


@pytest.fixture
async def docs_db(tmp_path, monkeypatch):
    """Set up a fresh SQLite DB with sample inventory/topology/VLAN data."""
    db_path = str(tmp_path / "docs_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    monkeypatch.setattr(db_module, "DB_ENGINE", "sqlite")
    await db_module.init_db()

    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'Core')")
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (2, 'Access')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status, model, software_version) "
            "VALUES (100, 1, 'core-sw-01', '10.10.1.1', 'cisco_ios', 'online', 'C9500', '17.9.4')"
        )
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status, model, software_version) "
            "VALUES (200, 2, 'access-sw-01', '10.10.1.20', 'cisco_ios', 'online', 'C9300', '17.6.5')"
        )
        await db.execute(
            """INSERT INTO mac_address_table
               (host_id, mac_address, vlan, port_name, port_index, ip_address, entry_type)
               VALUES (100, 'aa:bb:cc:dd:ee:01', 10, 'Gi1/0/1', 1, '10.10.1.101', 'dynamic')"""
        )
        await db.execute(
            """INSERT INTO mac_address_table
               (host_id, mac_address, vlan, port_name, port_index, ip_address, entry_type)
               VALUES (200, 'aa:bb:cc:dd:ee:02', 10, 'Gi1/0/2', 2, '10.10.1.102', 'dynamic')"""
        )
        await db.commit()
    finally:
        await db.close()

    await db_module.upsert_topology_link(
        source_host_id=100,
        source_ip="10.10.1.1",
        source_interface="Gi1/0/48",
        target_host_id=200,
        target_ip="10.10.1.20",
        target_device_name="access-sw-01",
        target_interface="Gi1/0/48",
        protocol="lldp",
    )
    await db_module.create_billing_circuit(
        name="WAN-Core-Access",
        host_id=100,
        if_index=48,
        if_name="Gi1/0/48",
        customer="Hospital-NOC",
        description="Core-to-access uplink circuit",
        commit_rate_bps=200_000_000,
        burst_limit_bps=500_000_000,
        created_by="tests",
    )
    return db_path


@pytest.mark.asyncio
async def test_generate_network_documentation_report_data_sections(docs_db):
    rows = await db_module.generate_network_documentation_report_data()
    assert rows

    sections = {row["section"] for row in rows}
    assert "summary" in sections
    assert "inventory" in sections
    assert "topology_link" in sections
    assert "ip_plan" in sections
    assert "vlan_map" in sections
    assert "circuit_map" in sections

    summary = rows[0]
    assert summary["section"] == "summary"
    assert "devices=2" in str(summary["details"])

    ip_plan_rows = [r for r in rows if r["section"] == "ip_plan"]
    assert any(str(r.get("subnet")) == "10.10.1.0/24" for r in ip_plan_rows)

    vlan_rows = [r for r in rows if r["section"] == "vlan_map"]
    assert any(int(r.get("vlan_id") or 0) == 10 for r in vlan_rows)

    topo_rows = [r for r in rows if r["section"] == "topology_link"]
    assert any(r.get("circuit_name") == "WAN-Core-Access" for r in topo_rows)

    circuit_rows = [r for r in rows if r["section"] == "circuit_map"]
    assert any(r.get("circuit_customer") == "Hospital-NOC" for r in circuit_rows)


@pytest.mark.asyncio
async def test_generate_network_documentation_report_data_group_filter(docs_db):
    rows = await db_module.generate_network_documentation_report_data(group_id=1)

    inventory_rows = [r for r in rows if r["section"] == "inventory"]
    assert len(inventory_rows) == 1
    assert inventory_rows[0]["hostname"] == "core-sw-01"
    assert inventory_rows[0]["group_name"] == "Core"


@pytest.mark.asyncio
async def test_generate_report_dispatches_network_documentation(monkeypatch):
    create_run_mock = AsyncMock(return_value={"id": 77})
    generate_rows_mock = AsyncMock(
        return_value=[{"section": "summary", "details": "devices=1"}]
    )
    complete_run_mock = AsyncMock(return_value=True)

    monkeypatch.setattr(reporting_module.db, "create_report_run", create_run_mock)
    monkeypatch.setattr(
        reporting_module.db,
        "generate_network_documentation_report_data",
        generate_rows_mock,
    )
    monkeypatch.setattr(reporting_module.db, "complete_report_run", complete_run_mock)

    result = await reporting_module.generate_report(
        {
            "report_type": "network_documentation",
            "parameters": {"group_id": 1},
            "persist_artifacts": False,
        },
        DummyRequest(),
    )

    assert result["run_id"] == 77
    assert result["report_type"] == "network_documentation"
    assert result["row_count"] == 1
    generate_rows_mock.assert_awaited_once_with(1)
    complete_run_mock.assert_awaited()


@pytest.mark.asyncio
async def test_export_network_documentation_svg(monkeypatch):
    fake_links = [
        {
            "id": 1,
            "source_host_id": 10,
            "source_interface": "Gi0/1",
            "target_host_id": None,
            "target_ip": "172.16.0.1",
            "target_device_name": "edge-fw",
            "target_interface": "port1",
            "protocol": "cdp",
        }
    ]
    fake_hosts = [
        {
            "id": 10,
            "group_id": 1,
            "hostname": "core-sw",
            "ip_address": "10.0.0.1",
            "device_type": "cisco_ios",
        }
    ]
    fake_groups = [{"id": 1, "name": "Core"}]

    monkeypatch.setattr(reporting_module.db, "get_topology_links", AsyncMock(return_value=fake_links))
    monkeypatch.setattr(reporting_module.db, "get_hosts_by_ids", AsyncMock(return_value=fake_hosts))
    monkeypatch.setattr(reporting_module.db, "get_all_groups", AsyncMock(return_value=fake_groups))

    response = await reporting_module.export_network_documentation_svg(group_id=None)
    body = response.body.decode("utf-8")

    assert response.media_type == "image/svg+xml"
    assert "network_documentation_topology.svg" in response.headers.get("Content-Disposition", "")
    assert "<svg" in body
    assert "Plexus Network Documentation Diagram" in body
    assert "core-sw" in body


@pytest.mark.asyncio
async def test_export_network_documentation_drawio(monkeypatch):
    fake_links = [
        {
            "id": 1,
            "source_host_id": 10,
            "source_interface": "Gi0/1",
            "target_host_id": None,
            "target_ip": "172.16.0.1",
            "target_device_name": "edge-fw",
            "target_interface": "port1",
            "protocol": "cdp",
        }
    ]
    fake_hosts = [
        {
            "id": 10,
            "group_id": 1,
            "hostname": "core-sw",
            "ip_address": "10.0.0.1",
            "device_type": "cisco_ios",
        }
    ]
    fake_groups = [{"id": 1, "name": "Core"}]

    monkeypatch.setattr(reporting_module.db, "get_topology_links", AsyncMock(return_value=fake_links))
    monkeypatch.setattr(reporting_module.db, "get_hosts_by_ids", AsyncMock(return_value=fake_hosts))
    monkeypatch.setattr(reporting_module.db, "get_all_groups", AsyncMock(return_value=fake_groups))

    response = await reporting_module.export_network_documentation_drawio(group_id=None)
    body = response.body.decode("utf-8")

    assert response.media_type == "application/vnd.jgraph.mxfile"
    assert "network_documentation_topology.drawio" in response.headers.get("Content-Disposition", "")
    assert "<mxfile" in body
    assert "Plexus Network Documentation Topology" in body
    assert "core-sw" in body


@pytest.mark.asyncio
async def test_generate_report_persists_artifacts(docs_db):
    result = await reporting_module.generate_report(
        {
            "report_type": "network_documentation",
            "parameters": {"group_id": 1},
            "persist_artifacts": True,
        },
        DummyRequest(),
    )
    run_id = int(result["run_id"])
    artifacts = await db_module.get_report_artifacts(run_id, limit=20)
    artifact_types = {a["artifact_type"] for a in artifacts}
    assert "csv" in artifact_types
    assert "svg" in artifact_types
    assert "drawio" in artifact_types
    assert "pdf" in artifact_types

    csv_artifact = next(a for a in artifacts if a["artifact_type"] == "csv")
    download = await reporting_module.download_report_artifact(int(csv_artifact["id"]))
    assert download.media_type == "text/csv"
    assert "attachment; filename=" in download.headers.get("Content-Disposition", "")

    pdf_artifact = next(a for a in artifacts if a["artifact_type"] == "pdf")
    pdf_download = await reporting_module.download_report_artifact(int(pdf_artifact["id"]))
    assert pdf_download.media_type == "application/pdf"
    assert bytes(pdf_download.body).startswith(b"%PDF-")

    listed = await reporting_module.list_report_run_artifacts(run_id, limit=20)
    listed_types = {a["artifact_type"] for a in listed["artifacts"]}
    assert "csv" in listed_types
    assert "svg" in listed_types
    assert "drawio" in listed_types
    assert "pdf" in listed_types


@pytest.mark.asyncio
async def test_export_network_documentation_pdf(docs_db):
    response = await reporting_module.export_network_documentation_pdf(group_id=None)
    assert response.media_type == "application/pdf"
    assert "network_documentation_report.pdf" in response.headers.get("Content-Disposition", "")
    assert bytes(response.body).startswith(b"%PDF-")


@pytest.mark.asyncio
async def test_run_scheduled_reports_once_runs_due_definitions(monkeypatch):
    now = datetime.now(UTC)
    due_report = {
        "id": 11,
        "name": "Daily Docs",
        "report_type": "network_documentation",
        "parameters_json": "{\"group_id\": 1}",
        "schedule": "1h",
        "last_run_at": (now - timedelta(hours=2)).isoformat(),
    }
    not_due_report = {
        "id": 12,
        "name": "Recent",
        "report_type": "availability",
        "parameters_json": "{}",
        "schedule": "1h",
        "last_run_at": (now - timedelta(minutes=15)).isoformat(),
    }

    monkeypatch.setattr(reporting_module, "REPORT_SCHEDULER_ENABLED", True)
    monkeypatch.setattr(reporting_module.db, "list_report_definitions", AsyncMock(return_value=[due_report, not_due_report]))
    execute_mock = AsyncMock(return_value={"run_id": 501, "artifact_count": 2})
    update_mock = AsyncMock(return_value=None)
    cleanup_mock = AsyncMock(return_value=0)
    monkeypatch.setattr(reporting_module, "_execute_report_run", execute_mock)
    monkeypatch.setattr(reporting_module.db, "update_report_definition_last_run", update_mock)
    monkeypatch.setattr(reporting_module.db, "delete_old_report_runs", cleanup_mock)

    result = await reporting_module._run_scheduled_reports_once()

    assert result["ran"] == 1
    assert result["errors"] == 0
    execute_mock.assert_awaited_once()
    update_mock.assert_awaited_once_with(11)
