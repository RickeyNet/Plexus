"""CPU work moved off the event loop keeps its results.

  1. Config drift: an unchanged baseline/snapshot pair is not diffed again,
     a changed one is, and the open/duplicate event handling still runs.
  2. Bulk config backup zip: the same files and bytes as one single
     download per backup, a bounded number of queries, and the caller's
     group scope applied to the bulk read.
  3. Inventory CSV/YAML export and report renders: the same bytes as the
     inline serialization they replace.

Every name and address below is invented test data.
"""

from __future__ import annotations

import asyncio
import csv
import io
import re
import zipfile

import netcontrol.routes.config_backups as config_backups
import netcontrol.routes.config_drift as drift_routes
import netcontrol.routes.reporting as reporting
import pytest
import routes.database as db_module
import yaml
from netcontrol.bulk_import import host_csv_header, host_csv_row, host_export_records
from routes.crypto import encrypt

from mcp_helpers import admin_client

# ── 1. Config drift diff reuse ───────────────────────────────────────────────


@pytest.fixture
async def drift_host(monkeypatch):
    await db_module.init_db()
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (1, 'lab')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, status) "
            "VALUES (100, 1, 'edge-lab-01', '192.0.2.11', 'cisco_ios', 'online')"
        )
        await db.commit()
    finally:
        await db.close()
    drift_routes._DRIFT_DIFF_CACHE.clear()
    calls: list[tuple[str, str]] = []
    real = drift_routes._compute_config_diff

    def _counting(baseline: str, actual: str, *args, **kwargs):
        calls.append((baseline, actual))
        return real(baseline, actual, *args, **kwargs)

    monkeypatch.setattr(drift_routes, "_compute_config_diff", _counting)
    yield calls
    drift_routes._DRIFT_DIFF_CACHE.clear()


@pytest.mark.asyncio
async def test_unchanged_pair_is_diffed_once_and_a_changed_one_again(drift_host):
    calls = drift_host
    await db_module.create_config_baseline(host_id=100, config_text="hostname edge-lab-01\n")
    await db_module.create_config_snapshot(host_id=100, config_text="hostname edge-lab-01-changed\n")

    first = await drift_routes._analyze_drift_for_host(100)
    second = await drift_routes._analyze_drift_for_host(100)
    third = await drift_routes._analyze_drift_for_host(100)
    assert len(calls) == 1
    assert first["drifted"] and second["event_id"] == first["event_id"] == third["event_id"]
    assert "already reported" in third["diff_summary"]

    # A new snapshot is a new pair.
    await db_module.create_config_snapshot(host_id=100, config_text="hostname edge-lab-01-other\n")
    fourth = await drift_routes._analyze_drift_for_host(100)
    assert len(calls) == 2
    assert fourth["event_id"] != first["event_id"]

    # A baseline edited in place keeps its id: its text still counts.
    baseline = await db_module.get_config_baseline_for_host(100)
    await db_module.update_config_baseline(baseline["id"], config_text="hostname edge-lab-01-other\n")
    fifth = await drift_routes._analyze_drift_for_host(100)
    assert len(calls) == 3
    assert fifth["drifted"] is False and "compliance" in fifth["diff_summary"].lower()


@pytest.mark.asyncio
async def test_a_reused_diff_still_runs_the_event_handling(drift_host):
    """The diff is reused, the event decisions are not: an event closed by a
    user while the drift persists is followed by a new one, as before."""
    calls = drift_host
    await db_module.create_config_baseline(host_id=100, config_text="hostname edge-lab-01\n")
    await db_module.create_config_snapshot(host_id=100, config_text="hostname edge-lab-01-changed\n")
    first = await drift_routes._analyze_drift_for_host(100)
    await db_module.update_config_drift_event_status(first["event_id"], "resolved", "operator")

    again = await drift_routes._analyze_drift_for_host(100)
    assert len(calls) == 1
    assert again["drifted"] is True and again["event_id"] != first["event_id"]
    open_events = await db_module.get_config_drift_events(status="open", host_id=100)
    assert [e["id"] for e in open_events] == [again["event_id"]]


@pytest.mark.asyncio
async def test_config_back_at_baseline_is_compliant_with_its_event_left_as_it_was(drift_host):
    """A snapshot back at the baseline is a new pair, so it is compared and
    found compliant. Drift analysis never closes events itself (a revert
    job or a user does), so the open event stays open, as before."""
    calls = drift_host
    await db_module.create_config_baseline(host_id=100, config_text="hostname edge-lab-01\n")
    await db_module.create_config_snapshot(host_id=100, config_text="hostname edge-lab-01-changed\n")
    drifted = await drift_routes._analyze_drift_for_host(100)
    await db_module.create_config_snapshot(host_id=100, config_text="hostname edge-lab-01\n")

    back = await drift_routes._analyze_drift_for_host(100)
    assert len(calls) == 2
    assert back == {"drifted": False, "event_id": None, "diff_summary": "In compliance"}
    event = await db_module.get_config_drift_event(drifted["event_id"])
    assert event["status"] == "open"


# ── 2. Bulk config backup zip ────────────────────────────────────────────────


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def backup_env(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    created = admin.post("/api/inventory", json={"name": "zip-lab"})
    assert created.status_code == 201, created.text
    group_id = int(created.json()["id"])
    host = admin.post(
        f"/api/inventory/{group_id}/hosts",
        json={"hostname": "edge-zip-01", "ip_address": "198.51.100.40", "device_type": "cisco_ios"},
    )
    assert host.status_code == 201, host.text
    host_id = int(host.json()["id"])
    ids = [
        _run(db_module.create_config_backup(None, host_id, f"hostname edge-zip-01\n! rev {n}\n", "manual"))
        for n in range(4)
    ]
    # A sealed backup: the zip holds the decrypted raw text, as its single download does.
    ids.append(
        _run(
            db_module.create_config_backup(
                None, host_id, "masked text\n", "manual", config_text_enc=encrypt("raw text é\r\n")
            )
        )
    )
    _run(db_module.create_config_backup(None, host_id, "", "manual", status="error", error_message="timeout"))
    return {"admin": admin, "group_id": group_id, "host_id": host_id, "ids": ids}


def _single_download_archive(admin, host_id: int) -> dict[str, bytes]:
    """What the bulk zip held before: one single download per successful
    backup of the list, named and disambiguated in list order."""
    rows = _run(db_module.get_config_backups(host_id=host_id, limit=500))
    files: dict[str, bytes] = {}
    for row in rows:
        if row["status"] != "success":
            continue
        single = admin.get(f"/api/config-backups/{row['id']}/download")
        assert single.status_code == 200, single.text
        name = re.search(r'filename="([^"]+)"', single.headers["content-disposition"]).group(1)
        base, ext = name.rsplit(".", 1)
        counter = 2
        while name in files:
            name = f"{base}_{counter}.{ext}"
            counter += 1
        files[name] = single.content
    return files


def test_bulk_zip_holds_the_single_downloads_with_few_queries(backup_env, monkeypatch):
    admin, host_id = backup_env["admin"], backup_env["host_id"]
    expected = _single_download_archive(admin, host_id)
    assert len(expected) == 5

    reads: list[list[int]] = []
    real_read = db_module.get_config_backup_downloads

    async def _counting_read(backup_ids, **kwargs):
        reads.append(list(backup_ids))
        return await real_read(backup_ids, **kwargs)

    async def _per_row(*_args, **_kwargs):
        raise AssertionError("the bulk zip must not read backups one at a time")

    monkeypatch.setattr(db_module, "get_config_backup_downloads", _counting_read)
    monkeypatch.setattr(db_module, "get_config_backup", _per_row)
    monkeypatch.setattr(db_module, "get_config_backup_encrypted_text", _per_row)
    monkeypatch.setattr(config_backups, "_ZIP_READ_BATCH", 2)

    archive = admin.get("/api/config-backups/download", params={"host_id": host_id})
    assert archive.status_code == 200, archive.text
    with zipfile.ZipFile(io.BytesIO(archive.content)) as zf:
        got = {name: zf.read(name) for name in zf.namelist()}
    assert got == expected
    assert "raw text é\r\n".encode() in got.values()
    # Five successful backups in batches of two: three reads.
    assert [len(batch) for batch in reads] == [2, 2, 1]


def test_bulk_read_applies_the_group_scope_and_keeps_the_order(backup_env):
    ids, group_id = backup_env["ids"], backup_env["group_id"]
    wanted = list(reversed(ids))
    rows = _run(db_module.get_config_backup_downloads(wanted, group_ids=frozenset({group_id})))
    assert [r["id"] for r in rows] == wanted
    assert rows[-1]["config_text_enc"] == "" and rows[0]["config_text_enc"]
    assert _run(db_module.get_config_backup_downloads(wanted, group_ids=frozenset({group_id + 1000}))) == []
    assert _run(db_module.get_config_backup_downloads(wanted, group_ids=frozenset())) == []
    assert _run(db_module.get_config_backup_downloads([])) == []


# ── 3. Exports and report renders ────────────────────────────────────────────


@pytest.fixture
def admin(monkeypatch, request):
    client = admin_client(monkeypatch, request)
    created = client.post("/api/inventory", json={"name": "export-lab"})
    assert created.status_code == 201, created.text
    for name, ip in (("=edge-exp-01", "203.0.113.21"), ("edge-exp-é", "203.0.113.22")):
        host = client.post(f"/api/inventory/{created.json()['id']}/hosts", json={"hostname": name, "ip_address": ip})
        assert host.status_code == 201, host.text
    return client


def _export_records():
    return _run(host_export_records(_run(db_module.get_all_hosts_for_export())))


def test_inventory_csv_and_yaml_exports_are_unchanged(admin):
    fields, records = _export_records()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(host_csv_header(fields))
    for record in records:
        writer.writerow(host_csv_row(record, fields))

    got_csv = admin.get("/api/inventory/export/csv")
    assert got_csv.status_code == 200, got_csv.text
    assert got_csv.content == output.getvalue().encode("utf-8")
    assert "'=edge-exp-01" in got_csv.text

    got_yaml = admin.get("/api/inventory/export/yaml")
    assert got_yaml.status_code == 200, got_yaml.text
    assert got_yaml.content == yaml.safe_dump(records, sort_keys=False, allow_unicode=True).encode("utf-8")


REPORT_ROWS = [
    {"hostname": "=edge-rpt-01", "ip_address": "192.0.2.31", "uptime_pct": 99.5, "note": None},
    {"hostname": "edge-rpt-é", "ip_address": "192.0.2.32", "uptime_pct": 100, "note": "a, b"},
]


def test_report_csv_and_pdf_exports_are_unchanged(admin, monkeypatch):
    async def _rows(*_args, **_kwargs):
        return [dict(r) for r in REPORT_ROWS]

    monkeypatch.setattr(db_module, "generate_availability_report_data", _rows)
    monkeypatch.setattr(db_module, "generate_ipam_utilization_report_data", _rows)

    got_csv = admin.get("/api/reports/export/availability")
    assert got_csv.status_code == 200, got_csv.text
    expected_lines = [
        "hostname,ip_address,uptime_pct,note",
        "'=edge-rpt-01,192.0.2.31,99.5,",
        'edge-rpt-é,192.0.2.32,100,"a, b"',
    ]
    assert got_csv.content == "".join(f"{line}\r\n" for line in expected_lines).encode()
    assert got_csv.content == reporting._rows_to_csv(REPORT_ROWS).encode("utf-8")

    got_pdf = admin.get("/api/reports/export/ipam_utilization.pdf")
    assert got_pdf.status_code == 200, got_pdf.text
    assert got_pdf.content == reporting._render_tabular_pdf("Plexus IPAM Subnet Utilization", REPORT_ROWS)
    assert got_pdf.content.startswith(b"%PDF-1.4")
