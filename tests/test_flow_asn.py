from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import maxminddb
import pytest
from netcontrol import flow_asn
from netcontrol.routes import flow_collector


def _entry(asn=15169, organization="Example Network"):
    return {"autonomous_system_number": asn, "autonomous_system_organization": organization}


def _reader(records, edition="GeoLite2-ASN"):
    reader = Mock(spec=maxminddb.Reader)
    reader.metadata.return_value = SimpleNamespace(database_type=edition)
    reader.get.side_effect = lambda addr: records.get(str(addr))
    return reader


def test_public_ips_only_and_missing_asn_records(tmp_path, monkeypatch):
    path = tmp_path / "GeoLite2-ASN.mmdb"
    path.touch()
    reader = _reader(
        {
            "8.8.8.8": _entry(organization=" Example Network "),
            "2606:4700::1111": _entry(13335, None),
            "1.0.0.1": _entry(True),
        }
    )
    open_database = Mock(return_value=reader)
    monkeypatch.setattr(maxminddb, "open_database", open_database)
    ips = [
        "8.8.8.8",
        "8.8.8.8",
        "::ffff:8.8.8.8",
        "2606:4700::1111",
        "1.1.1.1",
        "1.0.0.1",
        "10.0.0.1",
        "127.0.0.1",
        "100.64.0.1",
        "224.0.0.1",
        "192.0.2.1",
        "not-an-ip",
        "fe80::1",
        "2001:db8::1",
        "ff02::1",
        "2606:4700::1111%eth0",
        "::ffff:10.0.0.1",
    ]
    assert flow_asn.AsnDatabase(path).lookup(ips) == {
        "8.8.8.8": {"asn": 15169, "asn_organization": "Example Network"},
        "::ffff:8.8.8.8": {"asn": 15169, "asn_organization": "Example Network"},
        "2606:4700::1111": {"asn": 13335, "asn_organization": None},
    }
    open_database.assert_called_once_with(path, maxminddb.MODE_MEMORY)
    assert sorted(str(call.args[0]) for call in reader.get.call_args_list) == [
        "1.0.0.1",
        "1.1.1.1",
        "2606:4700::1111",
        "8.8.8.8",
        "8.8.8.8",
    ]


def test_reload_after_first_download_and_keep_last_good_reader(tmp_path, monkeypatch, caplog):
    path = tmp_path / "GeoLite2-ASN.mmdb"
    database = flow_asn.AsnDatabase(path)
    clock = Mock(return_value=100)
    monkeypatch.setattr(flow_asn, "monotonic", clock)
    original = _reader({"8.8.8.8": _entry(15169)})
    wrong_edition = _reader({}, edition="GeoLite2-City")
    updated = _reader({"8.8.8.8": _entry(13335)})
    open_database = Mock(side_effect=[original, wrong_edition, PermissionError, updated])
    monkeypatch.setattr(maxminddb, "open_database", open_database)

    assert database.lookup(["8.8.8.8"]) == {}
    path.touch()
    # No repeat stat inside the refresh interval.
    assert database.lookup(["8.8.8.8"]) == {}
    open_database.assert_not_called()

    def current_asn():
        clock.return_value += 60
        return database.lookup(["8.8.8.8"])["8.8.8.8"]["asn"]

    assert current_asn() == 15169
    assert current_asn() == 15169  # file unchanged, no reopen
    open_database.assert_called_once()

    replacement = tmp_path / "new.mmdb"
    replacement.write_bytes(b"wrong edition")
    replacement.replace(path)
    assert current_asn() == 15169
    wrong_edition.close.assert_called_once()
    assert "expected a GeoLite2-ASN database" in caplog.text
    assert current_asn() == 15169  # still the rejected file, don't reopen it
    assert open_database.call_count == 2
    original.close.assert_not_called()

    replacement.write_bytes(b"updated edition")
    replacement.replace(path)
    assert current_asn() == 15169  # temporary read error
    assert current_asn() == 13335  # retry the same file
    original.close.assert_called_once()
    path.unlink()
    assert current_asn() == 13335


def test_invalid_mmdb_without_previous_copy(tmp_path, caplog):
    path = tmp_path / "broken.mmdb"
    path.write_bytes(b"not a MaxMind database")
    assert flow_asn.AsnDatabase(path).lookup(["8.8.8.8"]) == {}
    assert "Could not load the GeoLite2 ASN database" in caplog.text


async def test_top_talkers_enrich_only_scoped_rows_and_keep_rank(tmp_path, monkeypatch):
    path = tmp_path / "GeoLite2-ASN.mmdb"
    path.touch()
    reader = _reader({"8.8.8.8": _entry()})
    monkeypatch.setattr(maxminddb, "open_database", Mock(return_value=reader))
    monkeypatch.setattr(flow_asn, "_database", flow_asn.AsnDatabase(path))
    monkeypatch.setattr(flow_collector, "_flow_scope", AsyncMock(return_value={"group_ids": [7]}))
    rows = [
        {"ip": "10.0.0.1", "total_bytes": 2500, "flow_count": 10},
        {"ip": "8.8.8.8", "total_bytes": 1500, "flow_count": 5},
    ]
    get_talkers = AsyncMock(return_value=[row.copy() for row in rows])
    monkeypatch.setattr(flow_collector.db, "get_flow_top_talkers", get_talkers)
    reply = await flow_collector.api_top_talkers(host_id=2, hours=24, direction="dst", limit=10)
    get_talkers.assert_awaited_once_with(2, 24, "dst", 10, group_ids=[7])
    assert reply == [
        {**rows[0], "protocol_name": ""},
        {**rows[1], "protocol_name": "", "asn": 15169, "asn_organization": "Example Network"},
    ]

    monkeypatch.setattr(flow_asn, "_database", None)
    get_talkers.return_value = rows
    assert await flow_collector.api_top_talkers(host_id=None, hours=1, direction="src", limit=10) == [
        {"ip": "10.0.0.1", "total_bytes": 2500, "flow_count": 10, "protocol_name": ""},
        {"ip": "8.8.8.8", "total_bytes": 1500, "flow_count": 5, "protocol_name": ""},
    ]
