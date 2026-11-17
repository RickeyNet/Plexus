"""Tool history: each user's last Path Mode traces, reachability sweeps and
summaries (``netcontrol.routes.tool_history``, ``routes.db.tool_history``)."""

from __future__ import annotations

import netcontrol.app as app_module
import pytest
import routes.database as db
from starlette.testclient import TestClient

from mcp_helpers import CsrfClient, admin_client, user_client

PATH = "/api/topology/history/path"
SWEEP = "/api/topology/history/reachability"
SUMMARY = "/api/topology/history/summarize"


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _trace(a: str, b: str, traffic: str = "") -> dict:
    return {"picks": [{"key": f"a:{a}", "label": a}, {"key": f"a:{b}", "label": b}], "traffic": traffic}


def test_a_run_is_kept_and_reopened_as_sent(admin) -> None:
    data = {
        "picks": [
            {"key": "n:1", "node": 1, "label": "core-sw-01"},
            {"key": "app:example.com", "label": "example.com", "app": "example.com"},
        ],
        "traffic": "tcp/443",
    }
    saved = admin.post(PATH, json={"data": data, "key": "k1"})
    assert saved.status_code == 200, saved.text
    body = admin.get(PATH).json()
    assert body["limit"] == db.TOOL_HISTORY_LIMIT
    [entry] = body["entries"]
    assert entry == {"id": saved.json()["id"], "data": data, "used_at": entry["used_at"]}
    assert entry["used_at"]


def test_running_one_again_moves_it_to_the_top(admin) -> None:
    admin.post(PATH, json={"data": _trace("192.0.2.1", "198.51.100.1"), "key": "a"})
    admin.post(PATH, json={"data": _trace("192.0.2.2", "198.51.100.2"), "key": "b"})
    # The page's key decides sameness: other data under key "a" replaces it.
    admin.post(PATH, json={"data": _trace("192.0.2.1", "198.51.100.1", "tcp/22"), "key": "a"})
    entries = admin.get(PATH).json()["entries"]
    assert [e["data"]["traffic"] for e in entries] == ["tcp/22", ""]
    # Without a key the inputs are the key, whatever their order.
    admin.post(SUMMARY, json={"data": {"addresses": "192.0.2.1", "prefix": "24"}})
    admin.post(SUMMARY, json={"data": {"prefix": "24", "addresses": "192.0.2.1"}})
    assert len(admin.get(SUMMARY).json()["entries"]) == 1


def test_only_the_newest_are_kept_per_tool(admin) -> None:
    for n in range(db.TOOL_HISTORY_LIMIT + 3):
        assert admin.post(SWEEP, json={"data": {"form": {"destination": f"192.0.2.{n}"}}}).status_code == 200
    admin.post(SUMMARY, json={"data": {"addresses": "203.0.113.0/24"}})
    entries = admin.get(SWEEP).json()["entries"]
    assert len(entries) == db.TOOL_HISTORY_LIMIT
    assert entries[0]["data"]["form"]["destination"] == f"192.0.2.{db.TOOL_HISTORY_LIMIT + 2}"
    assert entries[-1]["data"]["form"]["destination"] == "192.0.2.3"
    # Each tool has its own list.
    assert len(admin.get(SUMMARY).json()["entries"]) == 1
    assert admin.get(PATH).json()["entries"] == []


def test_each_user_sees_and_changes_only_their_own(admin) -> None:
    other = user_client(admin, "history-user", features=["topology"])
    mine = admin.post(PATH, json={"data": _trace("192.0.2.1", "198.51.100.1")}).json()
    assert other.get(PATH).json()["entries"] == []
    # Reading the map is enough to keep a history (no topology.write).
    assert other.post(PATH, json={"data": _trace("192.0.2.7", "198.51.100.7")}).status_code == 200
    assert other.delete(f"{PATH}/{mine['id']}").status_code == 404
    assert other.delete(PATH).json()["removed"] == 1
    assert len(admin.get(PATH).json()["entries"]) == 1
    # An entry is deleted under its own tool only.
    assert admin.delete(f"{SWEEP}/{mine['id']}").status_code == 404
    assert admin.delete(f"{PATH}/{mine['id']}").json() == {"ok": True}
    assert admin.get(PATH).json()["entries"] == []


def test_access_needs_a_session_and_the_topology_feature(admin) -> None:
    anon = TestClient(app_module.app, raise_server_exceptions=False)
    assert anon.get(PATH).status_code == 401
    no_map = user_client(admin, "no-map-user", features=["inventory"])
    assert no_map.get(SWEEP).status_code == 403


def test_unknown_tool_is_refused(admin) -> None:
    assert admin.get("/api/topology/history/other").status_code == 422
    assert admin.post("/api/topology/history/other", json={"data": {"a": 1}}).status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"data": {}},
        {"data": {"addresses": "x" * 64_001}},
        {"data": {"a": 1}, "key": "k" * 2001},
        {"data": ["not", "an", "object"]},
    ],
)
def test_bad_entries_are_refused(admin, body) -> None:
    assert admin.post(SUMMARY, json=body).status_code == 422
