"""Near-real-time Meraki alerts: the normaliser
(``netcontrol.integrations.meraki.alerts``), the pipeline, the poll and the
webhook receiver (``netcontrol.routes.meraki_alerts``).

Built from the invented samples in
``netcontrol.integrations.meraki.alerts_sample``; the Dashboard API is an
``httpx.MockTransport``, so nothing touches the network.
"""

from __future__ import annotations

import json

import httpx
import netcontrol.app as app_module
import netcontrol.routes.meraki_alerts as routes
import netcontrol.routes.state as state
import netcontrol.routes.topology_availability as tracking
import pytest
import routes.database as db_module
from netcontrol.integrations.meraki import alerts, alerts_sample as sample

from test_meraki_topology import _CsrfClient, api  # noqa: F401 - the fixture is used by name

T0 = "2026-11-10 08:00:00"
T1 = "2026-11-10 09:00:00"
T2 = "2026-11-10 10:00:00"
SETTINGS = "/api/monitoring/meraki-alerts/settings"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """Default settings, no status, back-off or transport left by another test."""
    monkeypatch.setattr(state, "MERAKI_ALERTS_CONFIG", state._sanitize_meraki_alerts_config(None))
    monkeypatch.setattr(routes, "_STATUS", json.loads(json.dumps(routes.STATUS_DEFAULTS)))
    monkeypatch.setattr(routes, "_BACKOFF", {})
    monkeypatch.setattr(routes, "_TRANSPORT", None)


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(routes.notification_channels, "on_alert_created", _capture)
    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)
    return events


async def _source(name: str = "Example Retail", *, org_id: str = sample.ORG_ID, api_key: str = "k") -> dict:
    org = await db_module.create_meraki_org(name, org_id=org_id, api_key=api_key)
    assert org
    return org


def _poll_event(org_ref: int, **fields) -> dict:
    event = alerts.from_assurance_alert(sample.assurance_alert(**fields), org_ref=org_ref, org={"name": "Example"})
    assert event
    return event


def _webhook_event(org_ref: int, payload: dict | None = None) -> dict:
    event = alerts.from_webhook(payload or sample.webhook_payload(), org_ref=org_ref, org={"name": "Example"})
    assert event
    return event


# ── Normaliser ───────────────────────────────────────────────────────────────


def test_an_assurance_alert_is_normalised():
    event = alerts.from_assurance_alert(sample.assurance_alert(), org_ref=5, org={"name": "Shop", "org_id": "9"})
    assert event is not None
    assert event["key"] == f"meraki:5:d:{sample.AP_SERIAL}:device_down"
    assert event["condition"] == alerts.DEVICE_DOWN and event["alert_type"] == "unreachable"
    assert event["severity"] == "critical" and event["state"] == "open" and event["source"] == "poll"
    assert event["device_serial"] == sample.AP_SERIAL and event["device_name"] == sample.AP_NAME
    assert event["network_id"] == sample.NETWORK_ID and event["network_name"] == sample.NETWORK_NAME
    assert event["started_at"] == "2026-11-10 08:15:00" and event["resolved_at"] == ""
    assert event["org_name"] == "Shop" and event["org_id"] == "9" and event["category"] == "connectivity"
    assert event["meraki_alert_id"] == "4000000001"


def test_assurance_scope_severity_and_network_alerts():
    rows = sample.sample_assurance_alerts()
    crc, info = (alerts.from_assurance_alert(r, org_ref=5) for r in rows[1:])
    assert crc and info
    # The first device of the scope (lowest order) is the subject.
    assert crc["device_serial"] == sample.SWITCH_SERIAL and crc["severity"] == "warning"
    assert crc["key"] == f"meraki:5:d:{sample.SWITCH_SERIAL}:crc_errors_error"
    assert crc["detail"]["device_count"] == 2
    assert info["severity"] == "info" and info["key"] == f"meraki:5:n:{sample.NETWORK_ID_2}:high_channel_utilization"
    assert alerts.from_assurance_alert({"unexpected": True}, org_ref=5) is None


@pytest.mark.parametrize("field", ["resolved_at", "dismissed_at"])
def test_a_resolved_or_dismissed_assurance_alert_is_a_resolved_event(field):
    event = alerts.from_assurance_alert(sample.assurance_alert(**{field: "2026-11-10T09:30:00+01:00"}), org_ref=5)
    assert event and event["state"] == "resolved" and event["resolved_at"] == "2026-11-10 08:30:00"


def test_a_webhook_is_normalised_to_the_same_key_and_never_keeps_the_secret():
    payload = sample.webhook_payload(alert_data={"sharedSecret": "nested", "duration": 300})
    event = alerts.from_webhook(payload, org_ref=5)
    polled = alerts.from_assurance_alert(sample.assurance_alert(), org_ref=5)
    assert event and polled
    assert event["key"] == polled["key"]
    assert event["source"] == "webhook" and event["severity"] == "critical" and event["state"] == "open"
    assert event["alert_type"] == "stopped_reporting" and event["title"] == "APs went down"
    assert event["device_model"] == "MR46" and event["started_at"] == "2026-11-10 08:14:30"
    assert event["detail"]["alert_data"] == {"duration": 300}
    assert sample.SHARED_SECRET not in json.dumps(event) and "nested" not in json.dumps(event)


def test_a_recovery_webhook_resolves_the_same_key():
    down = alerts.from_webhook(sample.webhook_payload(), org_ref=5)
    up = alerts.from_webhook(sample.webhook_recovery(), org_ref=5)
    assert down and up
    assert up["key"] == down["key"] and up["state"] == "resolved"
    assert up["resolved_at"] == "2026-11-10 08:40:00" and up["started_at"] == ""
    assert alerts.from_webhook({"organizationId": "1"}, org_ref=5) is None


@pytest.mark.parametrize(
    ("type_id", "condition", "recovery"),
    [
        ("unreachable", "device_down", False),
        ("stopped_reporting", "device_down", False),
        ("appliances_went_down", "device_down", False),
        ("switches_came_up", "device_down", True),
        ("APs came back up", "device_down", True),
        ("power_supply_down", "power_supply", False),
        ("power_supply_up", "power_supply", True),
        ("settings_changed", "settings_changed", False),
        ("crc_errors_error", "crc_errors_error", False),
    ],
)
def test_conditions_merge_equivalent_types(type_id, condition, recovery):
    assert alerts.condition_of(type_id) == condition
    assert alerts.is_recovery(type_id) is recovery


def test_severity_mapping_and_test_webhooks():
    assert [alerts.severity_of(v) for v in ("critical", "warning", "informational", "", "weird")] == [
        "critical",
        "warning",
        "info",
        "warning",
        "warning",
    ]
    assert alerts.is_test_webhook(sample.webhook_test())
    assert alerts.is_test_webhook(sample.webhook_payload(alert_data={"test": True}))
    assert not alerts.is_test_webhook(sample.webhook_payload())
    assert alerts.stamp("2026-11-10T10:00:00+02:00") == "2026-11-10 08:00:00"
    assert alerts.stamp("not a time") == ""


# ── Pipeline ─────────────────────────────────────────────────────────────────


async def test_the_same_alert_by_both_paths_is_one_alert_raised_once(notifications):
    org = await _source()
    first = await routes.ingest([_poll_event(org["id"])])
    assert first["new"] == 1 and first["alerted"] == 1
    second = await routes.ingest([_webhook_event(org["id"])])
    assert second["new"] == 0 and second["updated"] == 1 and second["alerted"] == 0
    # The poll reading it again is not a new occurrence and alerts nothing.
    await routes.ingest([_poll_event(org["id"])])
    rows = await db_module.list_meraki_alerts()
    assert len(rows) == 1
    row = rows[0]
    assert row["seen_via"] == ["poll", "webhook"] and row["occurrences"] == 2
    assert row["device_model"] == "MR46" and row["alert_via"] == "notification" and row["alert_state"] == "critical"
    assert len(notifications) == 1
    event = notifications[0]
    assert event["alert_type"] == routes.ALERT_TYPE and event["severity"] == "critical"
    assert event["dedup_key"] == f"meraki_alert:{row['alert_key']}" and event["host_id"] is None
    assert sample.AP_NAME in event["message"] and sample.NETWORK_NAME in event["message"]


async def test_a_recovery_webhook_closes_the_alert_and_a_poll_absence_does_too(notifications):
    org = await _source()
    await routes.ingest([_webhook_event(org["id"])])
    result = await routes.ingest([_webhook_event(org["id"], sample.webhook_recovery())])
    assert result["resolved"] == 1
    assert await db_module.list_meraki_alerts() == []
    (closed,) = await db_module.list_meraki_alerts(include_resolved=True)
    assert closed["status"] == "resolved" and closed["resolved_at"] == "2026-11-10 08:40:00"

    crc = alerts.from_assurance_alert(sample.sample_assurance_alerts()[1], org_ref=org["id"])
    assert crc
    await routes.ingest([crc], poll_scope=(org["id"], {crc["key"]}))
    assert len(await db_module.list_meraki_alerts()) == 1
    gone = await routes.ingest([], poll_scope=(org["id"], set()))
    assert gone["resolved"] == 1 and await db_module.list_meraki_alerts() == []


async def test_a_poll_absence_leaves_webhook_only_alerts_open(notifications):
    org = await _source()
    await routes.ingest([_webhook_event(org["id"])])
    await routes.ingest([], poll_scope=(org["id"], set()))
    assert len(await db_module.list_meraki_alerts()) == 1


async def test_an_alert_on_an_inventory_device_is_a_monitoring_alert_cleared_on_resolve(notifications):
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (951, 'Branch')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, serial_number) "
            f"VALUES (9511, 951, 'ap-lobby-01.example.com', '192.0.2.10', 'meraki', '{sample.AP_SERIAL}')"
        )
        await db.commit()
    finally:
        await db.close()
    org = await _source()
    event = _poll_event(org["id"])
    await routes.ingest([event], poll_scope=(org["id"], {event["key"]}))
    alerts_on_host = await db_module.get_monitoring_alerts(host_id=9511)
    assert len(alerts_on_host) == 1
    assert alerts_on_host[0]["alert_type"] == "meraki_alert" and alerts_on_host[0]["severity"] == "critical"
    (row,) = await db_module.list_meraki_alerts()
    assert row["alert_via"] == "monitoring" and row["host_id"] == 9511
    assert notifications == []  # the monitoring alert's own hook notifies

    result = await routes.ingest([], poll_scope=(org["id"], set()))
    assert result["alerts_cleared"] == 1
    (cleared,) = await db_module.get_monitoring_alerts(host_id=9511)
    assert cleared["acknowledged"] and cleared["acknowledged_by"] == "auto-resolved"


async def test_informational_alerts_are_listed_never_raised(notifications):
    org = await _source()
    info = alerts.from_assurance_alert(sample.sample_assurance_alerts()[2], org_ref=org["id"])
    assert info
    result = await routes.ingest([info])
    assert result["new"] == 1 and result["alerted"] == 0 and notifications == []
    worse = dict(info, severity="warning")
    assert (await routes.ingest([worse]))["alerted"] == 1 and len(notifications) == 1


async def test_an_old_delivery_never_reopens_a_resolved_alert():
    event = _webhook_event(1)
    await db_module.apply_meraki_alert_events([event], now=T0)
    await db_module.apply_meraki_alert_events([dict(event, state="resolved", resolved_at=T1)], now=T1)
    late = await db_module.apply_meraki_alert_events([dict(event, started_at=T0)], now=T2)
    assert late["reopened"] == 0 and late["alerts"] == []
    again = await db_module.apply_meraki_alert_events([dict(event, started_at=T2)], now=T2)
    assert again["reopened"] == 1 and len(again["alerts"]) == 1


async def test_device_down_is_not_notified_twice_with_the_topology_tracker(notifications):
    org = await _source()
    serial = sample.AP_SERIAL
    node = {"id": f"d:{serial}", "kind": "wireless", "label": sample.AP_NAME, "serial": serial, "site": "s"}
    snapshot = {"nodes": [dict(node, status="online")], "sites": [{"id": "s", "name": "Branch"}]}
    await tracking.record_snapshot_states("meraki", org["id"], snapshot, now=T0)
    snapshot["nodes"][0]["status"] = "offline"
    await tracking.record_snapshot_states("meraki", org["id"], snapshot, now=T1)
    assert len(notifications) == 1 and notifications[0]["alert_type"] == "topology_availability"

    # The tracker already notified this device: the Meraki alert is recorded only.
    result = await routes.ingest([_webhook_event(org["id"])])
    assert result["alerted"] == 1 and len(notifications) == 1
    (row,) = await db_module.list_meraki_alerts()
    assert row["alert_via"] == "topology"


async def test_the_topology_tracker_skips_a_device_the_meraki_alert_covers(notifications):
    org = await _source()
    await routes.ingest([_webhook_event(org["id"])])
    assert len(notifications) == 1
    serial = sample.AP_SERIAL
    snapshot = {
        "nodes": [{"id": f"d:{serial}", "kind": "wireless", "label": "ap", "serial": serial, "status": "online"}],
        "sites": [],
    }
    await tracking.record_snapshot_states("meraki", org["id"], snapshot, now=T0)
    snapshot["nodes"][0]["status"] = "offline"
    result = await tracking.record_snapshot_states("meraki", org["id"], snapshot, now=T1)
    assert len(result["alerts"]) == 1 and len(notifications) == 1


async def test_webhook_only_alerts_expire_and_resolved_alerts_are_purged():
    event = _webhook_event(1)
    await db_module.apply_meraki_alert_events([event], now=T0)
    assert await db_module.expire_meraki_webhook_alerts(24, now=T1) == []
    expired = await db_module.expire_meraki_webhook_alerts(1, now="2026-11-10 10:00:01")
    assert [r["alert_key"] for r in expired] == [event["key"]]
    assert await db_module.purge_meraki_alerts(30) == 0
    db = await db_module.get_db()
    try:
        await db.execute("UPDATE meraki_alerts SET resolved_at = '2000-01-01 00:00:00'")
        await db.commit()
    finally:
        await db.close()
    assert await db_module.purge_meraki_alerts(30) == 1


async def test_the_migration_created_the_table():
    db = await db_module.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT version FROM schema_migrations WHERE version = 81")
        assert await cursor.fetchone() is not None
        cursor = await db.execute("SELECT COUNT(*) FROM meraki_alerts")
        assert (await cursor.fetchone())[0] == 0
    finally:
        await db.close()


# ── Poll ─────────────────────────────────────────────────────────────────────


def _transport(responses: dict[str, httpx.Response], calls: list[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        for org_id, response in responses.items():
            if f"/organizations/{org_id}/assurance/alerts" in request.url.path:
                assert request.url.params.get("perPage") == "300"
                assert request.method == "GET"
                return response
        return httpx.Response(404, json={"errors": ["Not found"]})

    return httpx.MockTransport(handler)


async def test_a_poll_cycle_isolates_a_failing_organization_and_backs_it_off(monkeypatch, notifications):
    good = await _source("Good", org_id="900001")
    bad = await _source("Bad", org_id="900002")
    calls: list[str] = []
    monkeypatch.setattr(
        routes,
        "_TRANSPORT",
        _transport(
            {
                "900001": httpx.Response(200, json=sample.sample_assurance_alerts()),
                "900002": httpx.Response(401, json={"errors": ["Invalid API key"]}),
            },
            calls,
        ),
    )
    result = await routes.run_alert_poll_cycle()
    assert result["polled"] == 2 and result["failed"] == 1 and result["new"] == 3
    by_ref = {r["org_ref"]: r for r in result["sources"]}
    assert by_ref[good["id"]]["ok"] and by_ref[bad["id"]] == {"org_ref": bad["id"], "ok": False, "error": "HTTP 401"}
    assert len(await db_module.list_meraki_alerts(org_ref=good["id"])) == 3
    assert len(notifications) == 2  # the critical and the warning; the info is listed only
    assert routes._STATUS["sources"][str(bad["id"])]["last_error"] == "HTTP 401"

    # The failing organization is backed off: the next cycle does not call it.
    calls.clear()
    second = await routes.run_alert_poll_cycle()
    assert second["polled"] == 1 and second["skipped_backoff"] == 1
    assert all("/900002/" not in path for path in calls)
    # Poll Now ignores back-off.
    assert (await routes.run_alert_poll_cycle("manual", force=True))["polled"] == 2


async def test_a_poll_resolves_what_meraki_no_longer_reports(monkeypatch, notifications):
    await _source()
    rows = sample.sample_assurance_alerts()
    monkeypatch.setattr(routes, "_TRANSPORT", _transport({sample.ORG_ID: httpx.Response(200, json=rows)}, []))
    await routes.run_alert_poll_cycle()
    monkeypatch.setattr(routes, "_TRANSPORT", _transport({sample.ORG_ID: httpx.Response(200, json=rows[1:])}, []))
    result = await routes.run_alert_poll_cycle()
    assert result["resolved"] == 1
    assert {r["condition"] for r in await db_module.list_meraki_alerts()} == {
        "crc_errors_error",
        "high_channel_utilization",
    }


async def test_excluded_sources_and_polling_off_are_not_polled(monkeypatch):
    org = await _source()
    calls: list[str] = []
    monkeypatch.setattr(routes, "_TRANSPORT", _transport({sample.ORG_ID: httpx.Response(200, json=[])}, calls))
    monkeypatch.setitem(state.MERAKI_ALERTS_CONFIG, "excluded_sources", [org["id"]])
    assert (await routes.run_alert_poll_cycle())["polled"] == 0
    monkeypatch.setitem(state.MERAKI_ALERTS_CONFIG, "excluded_sources", [])
    monkeypatch.setitem(state.MERAKI_ALERTS_CONFIG, "poll_enabled", False)
    off = await routes.run_alert_poll_cycle()
    assert off["polled"] == 0 and off["skipped"] == "polling is off" and calls == []
    assert (await routes.run_alert_poll_cycle("manual", force=True))["polled"] == 1 and len(calls) == 1


async def test_sources_without_a_key_or_org_id_and_demo_entries_are_skipped(monkeypatch):
    await _source("No key", api_key="")
    await _source("No org", org_id="")
    await db_module.create_meraki_org("Cato", provider="cato", org_id="1", api_key="k")
    calls: list[str] = []
    monkeypatch.setattr(routes, "_TRANSPORT", _transport({}, calls))
    assert (await routes.run_alert_poll_cycle())["polled"] == 0 and calls == []


# ── Webhook receiver and API ─────────────────────────────────────────────────


def _post(client, payload, **kw):
    """Deliver like Meraki: no session cookie, no CSRF token."""
    client._c.cookies.clear()
    body = payload if isinstance(payload, (bytes, str)) else json.dumps(payload)
    headers = kw.pop("headers", {"Content-Type": "application/json"})
    return client._c.post(routes.WEBHOOK_PATH, content=body, headers=headers)


def _enable(client, secret: str = sample.SHARED_SECRET):
    resp = client.put(SETTINGS, json={"webhook_secret": secret})
    assert resp.status_code == 200, resp.text
    return resp


def test_the_receiver_is_hidden_until_a_secret_is_set(api):  # noqa: F811
    hidden = _post(api, sample.webhook_payload())
    missing = api._c.post("/api/webhooks/does-not-exist", content=b"{}", headers={"Content-Type": "application/json"})
    assert hidden.status_code == 404 and hidden.json() == {"detail": "Not Found"}
    assert hidden.status_code == missing.status_code


def test_settings_never_return_the_secret(api):  # noqa: F811
    resp = _enable(api)
    assert sample.SHARED_SECRET not in resp.text
    config = resp.json()["config"]
    assert config["webhook_secret_configured"] is True and config["webhook_enabled"] is True
    assert resp.json()["webhook_active"] is True and resp.json()["webhook_path"] == routes.WEBHOOK_PATH
    shown = api.get(SETTINGS)
    assert sample.SHARED_SECRET not in shown.text and "webhook_secret_enc" not in shown.text
    # Stored encrypted, never in clear.
    assert sample.SHARED_SECRET not in json.dumps(state.MERAKI_ALERTS_CONFIG)
    assert routes.webhook_secret() == sample.SHARED_SECRET

    bad = api.put(SETTINGS, json={"webhook_secret": "short-secret"})
    assert bad.status_code == 400 and "short-secret" not in bad.text

    clamped = api.put(SETTINGS, json={"interval_seconds": 5, "excluded_sources": [3, 3, -1]}).json()["config"]
    assert clamped["interval_seconds"] == 30 and clamped["excluded_sources"] == [3]

    cleared = api.put(SETTINGS, json={"clear_webhook_secret": True}).json()
    assert cleared["config"]["webhook_secret_configured"] is False and cleared["webhook_active"] is False
    assert _post(api, sample.webhook_payload()).status_code == 404


def test_settings_are_admin_only(api):  # noqa: F811
    api._c.cookies.clear()
    assert api.get(SETTINGS).status_code == 401
    assert api.post("/api/monitoring/meraki-alerts/poll").status_code == 401


def test_a_wrong_or_missing_secret_is_rejected_without_detail(api):  # noqa: F811
    _enable(api)
    wrong = _post(api, sample.webhook_payload(shared_secret="wrong-secret-wrong-secret"))
    assert wrong.status_code == 401 and wrong.json() == {"detail": "Unauthorized"}
    payload = sample.webhook_payload()
    payload.pop("sharedSecret")
    assert _post(api, payload).status_code == 401
    assert routes._STATUS["webhooks_rejected"] == 2 and routes._STATUS["last_webhook_at"] == ""


def test_oversized_and_non_json_bodies_are_rejected(api):  # noqa: F811
    _enable(api)
    big = sample.webhook_payload(alert_data={"pad": "x" * (routes.MAX_WEBHOOK_BODY_BYTES + 1)})
    assert _post(api, big).status_code == 413
    assert _post(api, "not json").status_code == 400
    assert _post(api, "[1, 2]").status_code == 400
    form = _post(api, json.dumps(sample.webhook_payload()), headers={"Content-Type": "text/plain"})
    assert form.status_code == 415


def test_a_webhook_from_an_unknown_organization_is_counted_and_ignored(api):  # noqa: F811
    _enable(api)
    resp = _post(api, sample.webhook_payload(org_id="123456789"))
    assert resp.status_code == 200 and resp.json() == {"ok": True}
    assert routes._STATUS["unknown_org_events"] == 1 and routes._STATUS["last_webhook_at"]
    api._c.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert api.get("/api/monitoring/meraki-alerts").json() == {"alerts": []}


def test_the_test_webhook_is_recorded_for_the_admin(api):  # noqa: F811
    _enable(api)
    assert _post(api, sample.webhook_test()).status_code == 200
    assert routes._STATUS["last_test_at"] and routes._STATUS["webhooks_accepted"] == 1
    api._c.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    status = api.get(SETTINGS).json()["status"]
    assert status["last_test_at"] and status["last_webhook_at"]
    assert api.get("/api/monitoring/meraki-alerts").json() == {"alerts": []}


def test_a_webhook_alert_is_stored_listed_and_cleared(api, notifications):  # noqa: F811
    created = api.post("/api/sources", json={"name": "Example Retail", "org_id": sample.ORG_ID, "api_key": "k"})
    assert created.status_code == 201, created.text
    _enable(api)
    assert _post(api, sample.webhook_payload()).status_code == 200
    api._c.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    listed = api.get("/api/monitoring/meraki-alerts").json()["alerts"]
    assert len(listed) == 1 and listed[0]["seen_via"] == ["webhook"] and listed[0]["severity"] == "critical"
    assert len(notifications) == 1
    assert _post(api, sample.webhook_recovery()).status_code == 200
    api._c.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    assert api.get("/api/monitoring/meraki-alerts").json()["alerts"] == []
    assert len(api.get("/api/monitoring/meraki-alerts?include_resolved=true").json()["alerts"]) == 1


def test_webhook_deliveries_are_rate_limited_per_source_ip(api, monkeypatch):  # noqa: F811
    _enable(api)
    monkeypatch.setitem(state.API_RATE_LIMIT, "enabled", True)
    monkeypatch.setattr(app_module, "WEBHOOK_RATE_LIMIT_MAX", 2)
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})
    codes = [_post(api, sample.webhook_test()).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_poll_now_is_audited_and_reports_each_source(api, monkeypatch):  # noqa: F811
    created = api.post("/api/sources", json={"name": "Example Retail", "org_id": sample.ORG_ID, "api_key": "k"})
    assert created.status_code == 201
    monkeypatch.setattr(
        routes,
        "_TRANSPORT",
        _transport({sample.ORG_ID: httpx.Response(200, json=sample.sample_assurance_alerts())}, []),
    )
    resp = api.post("/api/monitoring/meraki-alerts/poll")
    assert resp.status_code == 200, resp.text
    assert resp.json()["polled"] == 1 and resp.json()["new"] == 3
    source = api.get(SETTINGS).json()["sources"][0]
    assert source["name"] == "Example Retail" and source["last_ok_at"] and source["last_error"] == ""


async def test_webhooks_reach_sources_that_are_not_polled(notifications):
    """A poll opt-out or a source without an API key still takes webhooks."""
    org = await _source(api_key="")
    state.MERAKI_ALERTS_CONFIG["excluded_sources"] = [org["id"]]
    result = await routes.process_webhook(sample.webhook_payload())
    assert result["new"] == 1
    (row,) = await db_module.list_meraki_alerts()
    assert row["org_ref"] == org["id"] and row["seen_via"] == ["webhook"]
