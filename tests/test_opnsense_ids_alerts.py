"""The IDS (Suricata) alerts of an OPNsense firewall as security events
(``netcontrol.integrations.opnsense.ids``, ``collector.collect_ids_alerts``,
``netcontrol.routes.opnsense_ids``, ``netcontrol.routes.security_events``,
``routes.db.security_events``).

Covers, with no network access (a fake firewall serves the answers of
``sample.ids_api_answers`` over ``httpx.MockTransport``):
  * rows        - only the known fields kept, text bounded and cleaned,
                  classtype -> priority -> severity, the event key
  * collector   - the status first, an IDS that is off or missing, the
                  pages (POST that only reads) stopping at the newest event
                  stored or the page limit, the rule lookups and their
                  limit, a refused privilege, the collection's phase and
                  call count
  * store       - each event once, the cap per source, retention, removal
                  with the source
  * alerts      - one per firewall and signature, counted on repeat, the
                  blocked / detected wording, a backlog stored only, the
                  channels once per open period for a firewall that is no
                  inventory host, the quiet period, mutes and suppressions
  * paths       - a collection (sections), the monitoring poll, a Suricata
                  syslog line (a read, not a collection), the list API

Every name, signature and address is invented (example.com, documentation
ranges, signature ids 9,100,000+).
"""

from __future__ import annotations

import asyncio
import copy
import json
from datetime import UTC, datetime, timedelta

import httpx
import netcontrol.app as app_module  # noqa: F401 - the app the database belongs to
import netcontrol.routes.meraki_topology as topology_routes
import netcontrol.routes.opnsense_health as health_poll
import netcontrol.routes.security_events as security
import netcontrol.routes.state as state
import netcontrol.routes.topology_availability as tracking
import pytest
import routes.database as db
from netcontrol import source_recollect as rc
from netcontrol.integrations.opnsense import collector as collector_module
from netcontrol.integrations.opnsense.client import OpnsenseClient
from netcontrol.integrations.opnsense.collector import collect_ids_alerts, collect_opnsense
from netcontrol.integrations.opnsense.ids import (
    CLASSTYPE_PRIORITY,
    SIGNATURE_MAX,
    alert_event,
    alert_events,
    alert_rows,
    event_key,
    keep_row,
    priority_severity,
    rule_classtype,
)
from netcontrol.integrations.opnsense.normalize import build_snapshot
from netcontrol.integrations.opnsense.sample import (
    IDS_RULES,
    build_sample_raw,
    ids_alert_rows,
    ids_api_answers,
    sample_api_answers,
)
from netcontrol.integrations.traffic import store_time
from netcontrol.routes import opnsense_ids
from netcontrol.routes.opnsense_collection import after_collection

from test_meraki_topology import _CsrfClient, api  # noqa: F401 - the fixture is used by name
from test_opnsense_syslog import clean, scheduler  # noqa: F401 - the fixtures are used by name

BASE = "https://fw1.example.com"
KEY = "plexus-key-0003"
SECRET = "plexus-secret-0003-not-real"
FIREWALL = "d:fw-edge-1.example.com"
NOW = datetime(2026, 11, 20, 10, 20, tzinfo=UTC)
TROJAN, SCAN, AGENT = 9100001, 9100002, 9100003
ALERT_PATHS = ("ids/service/query_alerts", "ids/service/queryAlerts")


def _rows_at(now: datetime) -> list[dict]:
    """The sample's alert rows, moved so that the newest is a minute before ``now``."""
    rows = ids_alert_rows()
    shift = now - timedelta(minutes=1) - datetime(2026, 11, 20, 10, 15, 30, 512301, tzinfo=UTC)
    for row in rows:
        at = datetime.fromisoformat(row["timestamp"]) + shift
        row["timestamp"] = at.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    return rows


class _Firewall:
    """The sample's API: every answer of ``sample_api_answers`` and the IDS
    endpoints (``ids_api_answers``); the alert search pages over the POST
    body. Records every call."""

    def __init__(self, rows: list[dict] | None = None, status: str = "running") -> None:
        self.answers = {**sample_api_answers(), **ids_api_answers(status)}
        if rows is not None:
            self.answers["ids/service/query_alerts"]["rows"] = rows
        self.fail: dict[str, int] = {}
        self.calls: list[tuple[str, str]] = []
        self.bodies: list[dict] = []

    def paths(self) -> list[str]:
        return [path for _method, path in self.calls]

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/")
        self.calls.append((request.method, path))
        if path in self.fail:
            return httpx.Response(self.fail[path], json={"message": f"refused {path}"})
        if path in ALERT_PATHS:
            # A search that reads its page from the POST body; nothing else is posted.
            assert request.method == "POST"
            body = json.loads(request.content or b"{}")
            self.bodies.append(body)
            rows = self.answers["ids/service/query_alerts"]["rows"]
            count, page = int(body["rowCount"]), int(body["current"])
            found = rows[(page - 1) * count : page * count]
            return httpx.Response(200, json={"rows": copy.deepcopy(found), "total": len(found), "current": page})
        if path == "ipsec/sessions/search_phase2":
            name = json.loads(request.content or b"{}").get("id", "")
            return httpx.Response(200, json=copy.deepcopy(self.answers[path].get(name) or {"rows": []}))
        if path == "core/firmware/audit":
            return httpx.Response(200, json={"status": "ok"})
        assert request.method == "GET", (request.method, path)
        if path == "ipsec/connections/search_child":
            connection = request.url.params.get("connection", "")
            return httpx.Response(200, json=copy.deepcopy(self.answers[path].get(connection) or {"rows": []}))
        if path == "core/firmware/running":
            return httpx.Response(200, json={"status": "ready"})
        if path == "core/firmware/upgradestatus":
            log = "***GOT REQUEST TO AUDIT SECURITY***\n0 problem(s) in 0 installed package(s) found.\n***DONE***\n"
            return httpx.Response(200, json={"status": "done", "log": log})
        if path == "core/backup/download/this":
            return httpx.Response(200, text=self.answers[path])
        if path not in self.answers:
            return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
        return httpx.Response(200, json=copy.deepcopy(self.answers[path]))


def _client(fake: _Firewall) -> OpnsenseClient:
    return OpnsenseClient(BASE, KEY, SECRET, transport=httpx.MockTransport(fake.handler), requests_per_second=1000)


def _events(now: datetime = NOW, rows: list[dict] | None = None) -> list[dict]:
    return alert_events({"rows": [keep_row(r) for r in (rows or _rows_at(now))]}, dict(IDS_RULES))


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)
    return events


async def _host(name: str) -> dict:
    group = await db.create_group(f"opn-ids-{name}")
    host_id = await db.add_host(group, "fw-edge-1.example.com", "192.0.2.1", "opnsense")
    host = await db.get_host(host_id)
    assert host
    return host


async def _source(name: str = "Edge firewall", options: dict | None = None) -> int:
    org = await db.create_meraki_org(
        name, provider="opnsense", base_url=BASE, api_key=f"{KEY}:{SECRET}", options=options, created_by="test"
    )
    assert org
    return int(org["id"])


def _section(snapshot: dict, title: str) -> dict:
    firewall = next(n for n in snapshot["nodes"] if n["id"] == FIREWALL)
    return next(s for s in firewall["sections"] if s["title"] == title)


# ── Rows ─────────────────────────────────────────────────────────────────────


def test_a_row_keeps_only_the_known_fields_with_bounded_text():
    row = {**ids_alert_rows()[0], "alert": "x" * 5000, "http": {"hostname": "c2.example.com"}}
    kept = keep_row(row)
    assert set(kept) == {
        "timestamp",
        "alert",
        "alert_sid",
        "alert_action",
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port",
        "proto",
        "in_iface",
        "flow_id",
        "app_proto",
    }
    assert len(kept["alert"]) == 512 and "payload_printable" not in kept
    assert len(alert_rows(ids_api_answers()["ids/service/query_alerts"])) == 4
    assert alert_rows({"rows": "nope"}) == [] and alert_rows(None) == []


def test_a_row_becomes_an_event_with_its_classtype_severity_and_flow():
    trojan, _second, scan, agent = (alert_event(keep_row(r), IDS_RULES) for r in ids_alert_rows())
    assert trojan == {
        "kind": "ids_alert",
        "event_key": trojan["event_key"],
        "occurred_at": "2026-11-20 10:15:30",
        "signature_id": TROJAN,
        "signature": "PLEXUS SAMPLE Trojan beacon to example C2",
        "category": "trojan-activity",
        "priority": 1,
        "severity": "critical",
        "action": "blocked",
        "protocol": "TCP",
        "src_ip": "192.0.2.50",
        "src_port": 51234,
        "dest_ip": "203.0.113.66",
        "dest_port": 80,
        "interface": "vtnet0",
        "flow_id": "1500000000000001",
        "app_proto": "http",
    }
    assert (scan["severity"], scan["action"], scan["interface"]) == ("warning", "allowed", "vtnet1")
    assert (agent["severity"], agent["dest_ip"]) == ("info", "2001:db8::80")
    # The same alert has the same key; another flow another.
    assert trojan["event_key"] == event_key(keep_row(ids_alert_rows()[0])) != scan["event_key"]
    # No classtype known: the severity is unknown (stored only).
    assert alert_event(keep_row(ids_alert_rows()[0]), {})["severity"] == "unknown"
    assert priority_severity(None) == "unknown" and priority_severity(4) == "info"
    assert CLASSTYPE_PRIORITY["tcp-connection"] == 4


def test_untrusted_text_is_cleaned_and_bounded():
    row = {
        **ids_alert_rows()[0],
        "alert": "<script>\x1b[31m" + "A" * 2000,
        "src_ip": "not-an-address",
        "src_port": "70000",
        "in_iface": "^vtnet0\n",
    }
    event = alert_event(keep_row(row), IDS_RULES)
    assert event is not None
    assert "\x1b" not in event["signature"] and len(event["signature"]) == SIGNATURE_MAX
    assert (event["src_ip"], event["src_port"], event["interface"]) == ("", None, "vtnet0")
    # A record without a time or a signature id is no event.
    assert alert_event({"alert_sid": 1}, {}) is None and alert_event({"timestamp": row["timestamp"]}, {}) is None


def test_a_row_that_still_has_the_alert_object_keeps_its_own_severity():
    row = {
        "timestamp": "2026-11-20T11:15:30.000000+0100",
        "alert": {"signature": "PLEXUS SAMPLE raw", "signature_id": 9100009, "severity": 2, "category": "Recon"},
        "src_ip": "192.0.2.9",
    }
    event = alert_event(keep_row(row), {})
    assert event is not None
    assert (event["occurred_at"], event["severity"], event["category"], event["action"]) == (
        "2026-11-20 10:15:30",
        "warning",
        "Recon",
        "allowed",
    )


def test_the_rule_classtype():
    assert rule_classtype({"classtype": "Trojan-Activity"}) == "trojan-activity"
    assert rule_classtype({"classtype": "##none##"}) == "" and rule_classtype([]) == ""


# ── Collector ────────────────────────────────────────────────────────────────


async def test_the_read_takes_the_status_the_pages_and_the_rules():
    fake = _Firewall()
    errors: list[dict] = []
    async with _client(fake) as client:
        found, calls, answered = await collect_ids_alerts(client, errors)
    assert errors == [] and found is not None
    assert (found["status"], len(found["rows"]), found["truncated"], found["pages"]) == ("running", 4, False, 1)
    assert found["classtypes"] == IDS_RULES and found["lookups_skipped"] == 0
    assert fake.bodies == [{"rowCount": 200, "current": 1}]
    assert (calls, answered) == (5, 5) == (len(fake.calls), len(fake.calls))
    # Read-only: the status and the rules over GET, the search over POST; nothing else.
    assert fake.calls == [
        ("GET", "ids/service/status"),
        ("POST", "ids/service/query_alerts"),
        *[("GET", f"ids/settings/get_rule_info/{sid}") for sid in IDS_RULES],
    ]


async def test_the_read_stops_at_the_newest_event_stored_and_skips_known_rules():
    fake = _Firewall()
    async with _client(fake) as client:
        found, _calls, _answered = await collect_ids_alerts(
            client, [], since="2026-11-20 10:13:00", classtypes={TROJAN: "trojan-activity"}
        )
    assert found is not None
    assert [r["alert_sid"] for r in found["rows"]] == [TROJAN, TROJAN]
    assert found["classtypes"] == {} and "ids/settings/get_rule_info/9100001" not in fake.paths()


async def test_the_read_is_bounded_by_the_page_and_lookup_limits(monkeypatch):
    monkeypatch.setattr(collector_module, "IDS_PAGE_ROWS", 1)
    monkeypatch.setattr(collector_module, "IDS_MAX_PAGES", 2)
    monkeypatch.setattr(collector_module, "IDS_MAX_RULE_LOOKUPS", 0)
    fake = _Firewall()
    async with _client(fake) as client:
        found, calls, _answered = await collect_ids_alerts(client, [])
    assert found is not None
    assert (len(found["rows"]), found["truncated"], found["pages"]) == (2, True, 2)
    assert fake.bodies == [{"rowCount": 1, "current": 1}, {"rowCount": 1, "current": 2}]
    assert found["classtypes"] == {} and found["lookups_skipped"] == 1 and calls == 3


async def test_an_ids_that_is_off_or_missing_reads_nothing_more():
    fake = _Firewall(status="disabled")
    async with _client(fake) as client:
        found, calls, _answered = await collect_ids_alerts(client, [])
    assert found is not None and found["status"] == "disabled" and found["rows"] == [] and calls == 1
    fake = _Firewall()
    fake.fail = {"ids/service/status": 404}
    errors: list[dict] = []
    async with _client(fake) as client:
        found, calls, answered = await collect_ids_alerts(client, errors)
    assert found == {"status": "unavailable", "rows": [], "classtypes": {}} and errors == [] and answered == 0


async def test_a_refused_privilege_is_a_warning_that_names_it():
    fake = _Firewall()
    fake.fail = {"ids/service/status": 403}
    errors: list[dict] = []
    async with _client(fake) as client:
        found, _calls, _answered = await collect_ids_alerts(client, errors)
    (warning,) = errors
    assert found is None and warning["status"] == 403 and "Services: Intrusion Detection" in warning["message"]
    # A refused search keeps the status and warns once (both forms refused).
    fake = _Firewall()
    fake.fail = {path: 403 for path in ALERT_PATHS}
    errors = []
    async with _client(fake) as client:
        found, _calls, _answered = await collect_ids_alerts(client, errors)
    assert found is not None and found["rows"] == [] and len(errors) == 1 and errors[0]["scope"] == "ids"


async def test_the_collection_reads_the_alerts_in_its_own_phase_and_counts_its_calls():
    fake = _Firewall()
    progress: list[dict] = []
    options = {"include_firmware_audit": False, "config_backup": False}
    async with _client(fake) as client:
        raw = await collect_opnsense(client, options, progress.append, ids_state={"since": None, "classtypes": {}})
    assert raw["errors"] == [] and len(raw["ids_alerts"]["rows"]) == 4
    phase = [p for p in progress if p["phase"] == "opnsense ids alerts"]
    assert phase and phase[-1]["alerts"] == 4
    assert progress[-1]["calls_done"] == progress[-1]["calls_total"]

    fake.calls.clear()
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {**options, "include_ids_alerts": False})
    assert raw["ids_alerts"] is None and not any(p.startswith("ids/") for p in fake.paths())


# ── Store and alerts ─────────────────────────────────────────────────────────


async def test_events_are_stored_once_and_alert_once_per_signature(notifications):
    host = await _host("store")
    org = 8201
    first = await security.record_events("opnsense", org, _events(), host=host, source_name="Edge", now=NOW)
    assert len(first["stored"]) == 4 and first["alerted"] == 2
    alerts = {a["dedup_key"]: a for a in await db.get_monitoring_alerts(host_id=host["id"], acknowledged=False)}
    trojan = alerts[f"security:opnsense:{org}:ids_alert:{TROJAN}"]
    scan = alerts[f"security:opnsense:{org}:ids_alert:{SCAN}"]
    assert len(alerts) == 2 and (trojan["severity"], scan["severity"]) == ("critical", "warning")
    assert trojan["alert_type"] == "security_event" and trojan["metric"] == "ids_alert" and trojan["value"] == 2.0
    assert "PLEXUS SAMPLE Trojan beacon to example C2 (sid 9100001, trojan-activity, priority 1)" in trojan["message"]
    assert "2 event(s), 1 of 2 blocked" in trojan["message"]
    assert "detected only, not blocked" in scan["message"]
    assert "198.51.100.99:40000 -> 203.0.113.10:22 TCP" in scan["message"]

    # The same read again: nothing new, nothing counted.
    again = await security.record_events("opnsense", org, _events(), host=host, source_name="Edge", now=NOW)
    assert again["stored"] == [] and again["alerted"] == 0
    # A new beacon a minute later: stored, and the open alert counted.
    later = NOW + timedelta(minutes=1)
    newer = await security.record_events(
        "opnsense", org, _events(later)[-1:], host=host, source_name="Edge", now=later + timedelta(minutes=1)
    )
    assert len(newer["stored"]) == 1
    open_alerts = await db.get_monitoring_alerts(host_id=host["id"], acknowledged=False)
    bumped = next(a for a in open_alerts if a["dedup_key"].endswith(str(TROJAN)))
    assert len(open_alerts) == 2 and bumped["occurrence_count"] == 2 and "1 event(s), blocked" in bumped["message"]
    found = await db.list_security_events(provider="opnsense", org_ref=org)
    assert found["total"] == 5 and found["counts"]["critical"] == 3 and found["counts"]["blocked"] == 2
    assert all(e["host_id"] == host["id"] and e["hostname"] == "fw-edge-1.example.com" for e in found["events"])


async def test_an_alert_ends_after_the_quiet_period(notifications, monkeypatch):
    host = await _host("quiet")
    await security.record_events("opnsense", 8202, _events(), host=host, source_name="Edge", now=NOW)
    assert await security.resolve_quiet_alerts() == 0  # seen just now
    monkeypatch.setattr(security, "QUIET_MINUTES", 0)
    assert await security.resolve_quiet_alerts() == 2
    rows = await db.get_monitoring_alerts(host_id=host["id"])
    assert {a["acknowledged_by"] for a in rows} == {"auto-resolved (quiet)"}


async def test_a_backlog_is_stored_without_alerts(notifications):
    host = await _host("backlog")
    result = await security.record_events(
        "opnsense", 8203, _events(), host=host, source_name="Edge", now=NOW + timedelta(hours=3)
    )
    assert len(result["stored"]) == 4 and result["alerted"] == 0
    assert await db.get_monitoring_alerts(host_id=host["id"]) == [] and notifications == []


async def test_a_firewall_off_the_inventory_notifies_once_per_open_period(notifications):
    org = 8204
    first = await security.record_events("opnsense", org, _events(), host=None, source_name="Edge", now=NOW)
    assert first["alerted"] == 2 and len(notifications) == 2
    assert all(n["host_id"] is None and n["alert_type"] == "security_event" for n in notifications)
    assert notifications[0]["message"].startswith("IDS alert on Edge (OPNsense): PLEXUS SAMPLE Trojan beacon")
    # Another beacon ten minutes later: the alert is still open, no new notification.
    later = NOW + timedelta(minutes=10)
    repeat = await security.record_events(
        "opnsense", org, _events(later)[-1:], host=None, source_name="Edge", now=later
    )
    assert (repeat["alerted"], repeat["repeated"], len(notifications)) == (0, 1, 2)
    # After a quiet period longer than QUIET_MINUTES: notified again.
    much_later = NOW + timedelta(minutes=security.QUIET_MINUTES + 30)
    fresh = await security.record_events(
        "opnsense", org, _events(much_later)[-1:], host=None, source_name="Edge", now=much_later
    )
    assert fresh["alerted"] == 1 and len(notifications) == 3


async def test_a_mute_of_the_firewall_covers_its_ids_alerts(notifications):
    host = await _host("mute")
    org = 8205
    await tracking.record_snapshot_states(
        "opnsense", org, build_snapshot(build_sample_raw()), now="2026-11-20 09:00:00"
    )
    await security.record_events("opnsense", org, _events(), host=host, source_name="Edge", now=NOW)
    assert len(await db.get_monitoring_alerts(host_id=host["id"], acknowledged=False)) == 2
    mute = await db.create_topology_mute(
        "opnsense", org, "entity", entity_type="device", entity_id=FIREWALL, reason="pentest", created_by="admin"
    )
    # Creating the mute acknowledges the open ones; new events raise nothing.
    assert await tracking.mute_entities(mute) >= 2
    assert await db.get_monitoring_alerts(host_id=host["id"], acknowledged=False) == []
    later = NOW + timedelta(minutes=5)
    result = await security.record_events("opnsense", org, _events(later), host=host, source_name="Edge", now=later)
    assert len(result["stored"]) == 4 and (result["alerted"], result["muted"]) == (0, 2)
    assert await db.get_monitoring_alerts(host_id=host["id"], acknowledged=False) == []


async def test_a_suppression_of_the_host_covers_its_ids_alerts(notifications):
    host = await _host("suppressed")
    ends = (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    await db.create_alert_suppression("pentest", ends, host_id=int(host["id"]), metric="ids_alert")
    result = await security.record_events("opnsense", 8206, _events(), host=host, source_name="Edge", now=NOW)
    assert (result["alerted"], result["muted"]) == (0, 2)


async def test_the_cap_per_source_retention_and_removal_with_the_source(notifications, monkeypatch):
    org = await _source("Capped firewall")
    monkeypatch.setattr(security, "MAX_EVENTS_PER_SOURCE", 3)
    await security.record_events("opnsense", org, _events(), host=None, source_name="Capped", now=NOW)
    kept = (await db.list_security_events(provider="opnsense", org_ref=org))["events"]
    # The oldest (the info event) went first.
    assert [e["signature_id"] for e in kept] == [TROJAN, TROJAN, SCAN]
    # Retention: an event older than the monitoring retention goes.
    old = _events(datetime(2020, 1, 1, tzinfo=UTC))[:1]
    await security.record_events("opnsense", 8207, old, host=None, source_name="Old", now=NOW)
    assert await db.purge_security_events(30) >= 1
    assert (await db.list_security_events(org_ref=8207))["total"] == 0
    # The source deleted: its events go with it, another provider's stay.
    await security.record_events("aws", org, _events(), host=None, source_name="Other", now=NOW + timedelta(hours=5))
    assert await db.delete_meraki_org(org)
    assert (await db.list_security_events(provider="opnsense", org_ref=org))["total"] == 0
    assert (await db.list_security_events(provider="aws", org_ref=org))["total"] == 3  # the cap


async def test_the_list_filters_and_the_object_scope(notifications):
    host = await _host("list")
    await security.record_events("opnsense", 8208, _events(), host=host, source_name="Edge", now=NOW)
    await security.record_events("opnsense", 8209, _events(), host=None, source_name="Branch", now=NOW)
    found = await db.list_security_events(severity="critical", search="beacon", org_ref=8208)
    assert found["total"] == 2 and {e["signature_id"] for e in found["events"]} == {TROJAN}
    assert (await db.list_security_events(search="203.0.113.10"))["total"] == 2
    assert (await db.list_security_events(search="9100003"))["total"] == 2
    assert (await db.list_security_events(search="100%_"))["total"] == 0
    assert (await db.list_security_events(action="blocked", org_ref=8209))["total"] == 1
    # A scoped caller sees the events of its hosts only, never a host-less device's.
    assert (await db.list_security_events(host_ids={int(host["id"])}))["total"] == 4
    assert (await db.list_security_events(host_ids=set()))["total"] == 0
    page = await db.list_security_events(org_ref=8208, limit=1, offset=1)
    assert len(page["events"]) == 1 and page["total"] == 4


# ── The paths that read them ─────────────────────────────────────────────────


async def test_a_collection_stores_the_events_and_shows_them_on_the_firewall(notifications):
    org = await _source()
    now = datetime.now(UTC)
    raw = build_sample_raw()
    raw["ids_alerts"] = {"status": "running", "rows": [keep_row(r) for r in _rows_at(now)], "classtypes": IDS_RULES}
    raw["ids_state"] = {"since": None, "classtypes": {}}
    snapshot = build_snapshot(raw)
    await after_collection(raw, snapshot, org)
    assert "ids_alerts" not in raw and "ids_state" not in raw
    rows = dict(_section(snapshot, "IDS alerts")["rows"])
    assert rows["Status"] == "Running" and rows["New alerts stored"] == "4"
    assert rows["Last 24 h"] == "4: 2 critical, 1 warning, 1 info, 0 unknown; 1 blocked"
    assert rows["Alerting"].startswith("Notification channels only")
    newest = _section(snapshot, "Newest IDS alerts")
    assert newest["columns"][0] == "Time (UTC)" and len(newest["rows"]) == 4
    assert newest["rows"][0][3] == f"PLEXUS SAMPLE Trojan beacon to example C2 (sid {TROJAN})"
    assert len(notifications) == 2  # no inventory host: the channels

    # The next collection reads from the newest event stored.
    state_now = await opnsense_ids.read_state(org)
    assert state_now["since"] == store_time(now - timedelta(minutes=1))
    assert state_now["classtypes"] == {TROJAN: "trojan-activity", SCAN: "attempted-recon", AGENT: "misc-activity"}

    # An IDS that is off says so and stores nothing.
    raw = build_sample_raw()
    raw["ids_alerts"] = {"status": "disabled", "rows": [], "classtypes": {}}
    snapshot = build_snapshot(raw)
    await after_collection(raw, snapshot, org)
    assert dict(_section(snapshot, "IDS alerts")["rows"]) == {"Status": "Disabled on the firewall: no alerts read"}
    assert not opnsense_ids.poll_wanted(org)


@pytest.fixture
def firewall_source(monkeypatch):
    """An OPNsense source whose API is the fake firewall (alerts of a
    minute ago), and no SNMP or ICMP."""
    fake = _Firewall(rows=_rows_at(datetime.now(UTC)))

    def _opnsense_client(org, secret, options, **kwargs):
        key, value = secret.split(":", 1)
        kwargs["transport"] = httpx.MockTransport(fake.handler)
        return OpnsenseClient(org["base_url"], key, value, requests_per_second=1000, **kwargs)

    monkeypatch.setattr(topology_routes, "_opnsense_client", _opnsense_client)
    monkeypatch.setitem(state.MONITORING_CONFIG, "icmp_enabled", False)
    health_poll.forget_sources()
    yield fake
    health_poll.forget_sources()


async def _source_with_host(host_id: int, options: dict | None = None) -> int:
    org = await _source(options=options)
    snapshot = build_snapshot(build_sample_raw())
    snapshot["summary"][health_poll.SUMMARY_KEY] = host_id
    await db.create_meraki_snapshot(org, snapshot, built_by="test")
    return org


async def test_the_poll_reads_the_new_alerts_of_an_inventory_firewall(firewall_source, notifications):
    from netcontrol.routes.monitoring import _poll_host_monitoring

    host = await _host("poll")
    org = await _source_with_host(int(host["id"]))
    await _poll_host_monitoring(host, None, {"enabled": False})
    stored = await db.list_security_events(provider="opnsense", org_ref=org)
    assert stored["total"] == 4 and all(e["host_id"] == host["id"] for e in stored["events"])
    alerts = await db.get_monitoring_alerts(host_id=host["id"], acknowledged=False)
    assert {a["metric"] for a in alerts} == {"ids_alert"} and len(alerts) == 2
    # The next poll reads from the newest event: one page, no rule lookups, nothing new.
    firewall_source.calls.clear()
    await _poll_host_monitoring(host, None, {"enabled": False})
    ids_calls = [c for c in firewall_source.calls if c[1].startswith("ids/")]
    assert ids_calls == [("GET", "ids/service/status"), ("POST", "ids/service/query_alerts")]
    assert (await db.list_security_events(provider="opnsense", org_ref=org))["total"] == 4

    # The IDS switched off: the poll stops reading it until a collection says otherwise.
    firewall_source.answers["ids/service/status"]["status"] = "disabled"
    await _poll_host_monitoring(host, None, {"enabled": False})
    firewall_source.calls.clear()
    await _poll_host_monitoring(host, None, {"enabled": False})
    assert not any(path.startswith("ids/") for path in firewall_source.paths())


async def test_the_poll_skips_the_ids_when_the_option_is_off(firewall_source):
    from netcontrol.routes.monitoring import _poll_host_monitoring

    host = await _host("poll-off")
    await _source_with_host(int(host["id"]), {"include_ids_alerts": False})
    await _poll_host_monitoring(host, None, {"enabled": False})
    assert firewall_source.calls and not any(path.startswith("ids/") for path in firewall_source.paths())


async def test_a_suricata_syslog_line_reads_the_alerts_without_collecting(firewall_source, notifications, monkeypatch):
    host = await _host("syslog")
    org = await _source_with_host(int(host["id"]))
    collected: list[int] = []

    async def no_collection(org_row: dict, user: str) -> str:
        collected.append(int(org_row["id"]))
        return "completed"

    monkeypatch.setattr(topology_routes, "collect_source_now", no_collection)
    assert await rc.run_recollect(org, {"ids"}) == "completed"
    assert collected == [] and all(path.startswith("ids/") for path in firewall_source.paths())
    found = await db.list_security_events(provider="opnsense", org_ref=org)
    assert found["total"] == 4 and found["events"][0]["host_id"] == host["id"]
    # With another reason the source is collected as before.
    assert await rc.run_recollect(org, {"ids", "gateway"}) == "completed" and collected == [org]
    # The option off, or no such source: skipped.
    await db.update_meraki_org(org, options={"include_ids_alerts": False})
    assert await rc.run_recollect(org, {"ids"}) == "skipped"
    assert await rc.run_recollect(999999, {"ids"}) == "skipped"


async def test_ids_reads_are_not_counted_against_the_hour_of_collections(scheduler):  # noqa: F811
    clock, runs, _outcomes = scheduler
    for _ in range(rc.MAX_RUNS_PER_HOUR + 2):
        rc.note_recollect(7, "ids")
        await _settle()
        clock.t += rc.MIN_INTERVAL_SECONDS
    # About one a minute, none held back by the hourly cap, and none counted in it.
    assert len(runs) == rc.MAX_RUNS_PER_HOUR + 2 and not rc._run_times.get(7)
    assert runs[-1][1] - runs[0][1] < rc.HOUR_SECONDS / 2
    # The hour's collections used up: a collection that joins a pending read waits, the read runs.
    for _ in range(rc.MAX_RUNS_PER_HOUR):
        rc.note_recollect(8, "gateway")
        await _settle()
        clock.t += rc.MIN_INTERVAL_SECONDS
    runs.clear()
    rc.note_recollect(8, "ids")
    rc.note_recollect(8, "gateway")
    await _settle()
    assert [r[2] for r in runs] == [["ids"], ["gateway"]]
    assert runs[1][1] >= runs[0][1] and runs[1][1] == rc._run_times[8][-1]


async def _settle() -> None:
    while rc._tasks:
        await asyncio.gather(*list(rc._tasks.values()), return_exceptions=True)


def test_the_list_api_filters_and_bounds(api):  # noqa: F811
    assert api.get("/api/monitoring/security-events").status_code == 200
    body = api.get("/api/monitoring/security-events?hours=48&severity=critical&q=beacon&limit=10").json()
    assert set(body) >= {"events", "total", "counts", "since", "hours", "limit", "offset"} and body["hours"] == 48
    for bad in (
        "limit=501",
        "hours=0",
        "hours=9000",
        "severity=bad",
        "action=dropped",
        f"q={'x' * 201}",
        "provider=Bad%20Name",
        "offset=-1",
    ):
        assert api.get(f"/api/monitoring/security-events?{bad}").status_code == 422, bad
    assert api.get("/api/monitoring/security-events?host_id=999999").status_code == 404
