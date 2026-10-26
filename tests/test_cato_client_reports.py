"""Tests for the Cato Client connection reports reader
(``netcontrol.integrations.cato.client_reports``): the ``events`` query
against a mock GraphQL endpoint, paging, the per-device reduction and the
timestamp formats Cato returns."""

from __future__ import annotations

import json

import httpx
import pytest
from netcontrol.integrations.cato import client_reports
from netcontrol.integrations.cato.client import CatoClient
from netcontrol.integrations.cato.client_reports import (
    DIMENSIONS,
    PATH,
    PHASE,
    ClientReports,
    collect_client_reports,
    parse_time,
)


def _client(handler) -> CatoClient:
    return CatoClient("test-key", transport=httpx.MockTransport(handler), requests_per_second=1000)


def _events(records: list[dict], total: int) -> httpx.Response:
    events = {
        "from": "2026-10-19T20:00:00Z",
        "to": "2026-10-26T20:00:00Z",
        "totalCount": total,
        "records": [{"fieldsMap": r} for r in records],
    }
    return httpx.Response(200, json={"data": {"events": events}})


def _fields(user: str, device: str, split: str, last_time, **extra) -> dict:
    return {
        "user_id": user,
        "user_name": f"User {user}",
        "device_name": device,
        "os_type": "OS_MAC",
        "split_tunnel_configuration": split,
        "office_mode": "Disabled",
        "trusted_networks": "Enabled",
        "src_ip": extra.pop("src_ip", "198.51.100.7"),
        "pop_name": "Chicago",
        "event_count": extra.pop("event_count", "2"),
        "last_time": last_time,
        **extra,
    }


def test_parse_time_reads_every_spelling_cato_returns_as_utc():
    assert parse_time("2026-10-26 19:51:37.014") == "2026-10-26T19:51:37Z"
    assert parse_time("2026-10-26T19:00") == "2026-10-26T19:00:00Z"
    assert parse_time("1793018342000") == "2026-10-26T12:39:02Z"
    assert parse_time("2026-10-26T14:00:00-05:00") == "2026-10-26T19:00:00Z"
    assert parse_time("") == parse_time(None) == parse_time("yesterday") == ""


@pytest.mark.asyncio
async def test_two_pages_are_read_and_reduced_to_the_newest_report_per_user_device(monkeypatch):
    monkeypatch.setattr(client_reports, "PAGE_SIZE", 2)
    pages = {
        0: [
            _fields("1000114", "CCM-J6JT6NKWX5", "Admin Defined", "2026-10-26 12:39:02.120"),
            # The same device from another address, earlier: reduced away.
            _fields("1000114", "CCM-J6JT6NKWX5", "Disabled", "2026-10-26T09:00", src_ip="203.0.113.9"),
        ],
        2: [_fields("1000114", "OLD-LAPTOP", "Disabled", "1792918342000", event_count=5)],
    }
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies.append(body)
        assert body["operationName"] == "plexusClientReports"
        return _events(pages[body["variables"]["from"]], total=3)

    progress: list[tuple[str, int, int]] = []
    errors: list[dict] = []
    async with _client(handler) as client:
        found = await collect_client_reports(
            client, "42", errors, report=lambda phase, calls=0, planned=0: progress.append((phase, calls, planned))
        )

    first = bodies[0]
    assert "events(" in first["query"] and "$timeFrame: TimeFrame!" in first["query"]
    assert "records(limit: $limit, from: $from) { fieldsMap }" in first["query"]
    assert first["variables"] == {
        "accountID": "42",
        "timeFrame": "last.P7D",
        "filters": [
            {"fieldName": "event_type", "operator": "is", "values": ["Connectivity"]},
            {"fieldName": "event_sub_type", "operator": "is", "values": ["Client Connectivity Policy"]},
        ],
        "dimensions": [{"fieldName": name} for name in DIMENSIONS],
        "measures": [
            {"fieldName": "event_count", "aggType": "sum"},
            {"fieldName": "time", "aggType": "max", "alias": "last_time"},
        ],
        "sort": [{"alias": "last_time", "order": "desc"}],
        "limit": 2,
        "from": 0,
    }
    assert [b["variables"]["from"] for b in bodies] == [0, 2]
    assert errors == []
    # One call planned up front, one added for the second page.
    assert sum(c for _p, c, _n in progress) == 2 and sum(n for _p, _c, n in progress) == 1
    assert {p for p, _c, _n in progress} == {PHASE}

    assert found is not None
    assert (found["from"], found["to"]) == ("2026-10-19T20:00:00Z", "2026-10-26T20:00:00Z")
    assert found["rows"] == [
        {
            "user_id": "1000114",
            "user_name": "User 1000114",
            "device_name": "CCM-J6JT6NKWX5",
            "os_type": "OS_MAC",
            "split_tunnel_configuration": "Admin Defined",
            "office_mode": "Disabled",
            "trusted_networks": "Enabled",
            "src_ip": "198.51.100.7",
            "pop_name": "Chicago",
            "time": "2026-10-26T12:39:02Z",
            "event_count": 2,
        },
        {
            "user_id": "1000114",
            "user_name": "User 1000114",
            "device_name": "OLD-LAPTOP",
            "os_type": "OS_MAC",
            "split_tunnel_configuration": "Disabled",
            "office_mode": "Disabled",
            "trusted_networks": "Enabled",
            "src_ip": "198.51.100.7",
            "pop_name": "Chicago",
            "time": "2026-10-25T08:52:22Z",
            "event_count": 5,
        },
    ]


@pytest.mark.asyncio
async def test_reading_stops_at_the_page_cap_with_a_note(monkeypatch):
    monkeypatch.setattr(client_reports, "PAGE_SIZE", 1)
    monkeypatch.setattr(client_reports, "MAX_PAGES", 2)
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        offset = json.loads(request.content)["variables"]["from"]
        calls.append(offset)
        return _events([_fields(str(offset), "D", "Disabled", "2026-10-26 10:00:00.000")], total=5)

    errors: list[dict] = []
    async with _client(handler) as client:
        found = await collect_client_reports(client, "42", errors)

    assert calls == [0, 1] and found is not None and len(found["rows"]) == 2
    assert errors == [
        {
            "scope": "account",
            "path": PATH,
            "status": None,
            "message": "First 2 of 5 report groups read (2 pages of 1, newest first); the rest were not read",
        }
    ]


@pytest.mark.asyncio
async def test_a_refused_query_is_an_error_and_not_collected():
    # A key without the View permission for events: best effort.
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"errors": [{"message": "Permission denied"}]})

    errors: list[dict] = []
    done: list[int] = []
    async with _client(handler) as client:
        found = await collect_client_reports(
            client, "42", errors, report=lambda _p, calls=0, planned=0: done.append(calls)
        )

    assert found is None and sum(done) == 1
    assert [(e["path"], e["status"]) for e in errors] == [(PATH, None)]
    assert "Permission denied" in errors[0]["message"]


def test_the_report_for_a_user_is_the_current_devices_else_the_newest():
    reports = ClientReports(
        {
            "rows": [
                {"user_id": "7", "device_name": "NEW", "time": "2026-10-26T10:00:00Z"},
                {"user_id": "7", "device_name": "CURRENT", "time": "2026-10-25T10:00:00Z"},
            ]
        }
    )
    assert reports.for_user("7", "current") == (
        {"user_id": "7", "device_name": "CURRENT", "time": "2026-10-25T10:00:00Z"},
        True,
    )
    assert reports.for_user("7", "GONE")[0]["device_name"] == "NEW" and reports.for_user("7", "GONE")[1] is False
    assert reports.for_user("8", "X") == (None, False) and reports.missing == "not found for this device"
    assert ClientReports(None).collected is False and ClientReports(None).missing == "not collected"
