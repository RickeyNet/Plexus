"""Near-real-time Cato alerts: the events feed normaliser
(``netcontrol.integrations.cato.events_feed``), the vendor alert feed store
(``routes.db.vendor_alerts``, migration 0132), the shared pipeline and poll
(``netcontrol.routes.vendor_alerts``) and the Cato provider
(``netcontrol.routes.cato_alerts``).

Built from the invented samples in ``netcontrol.integrations.cato.sample``;
the Cato API is an ``httpx.MockTransport``, so nothing touches the network.
"""

from __future__ import annotations

import json

import httpx
import netcontrol.routes.cato_alerts as cato_routes
import netcontrol.routes.security_events as security_routes
import netcontrol.routes.topology_availability as tracking
import netcontrol.routes.vendor_alerts as feeds
import pytest
import routes.database as db_module
from netcontrol.integrations.cato import events_feed, sample

from test_meraki_topology import _CsrfClient, api  # noqa: F401 - the fixture is used by name

T0 = "2026-11-20 07:00:00"
T1 = "2026-11-20 09:00:00"
SETTINGS = "/api/monitoring/vendor-alerts/cato/settings"
DENVER_KEY_SUFFIX = ":site:1003:disconnected"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """Default settings, no transport or cycle state left by another test."""
    monkeypatch.setattr(feeds, "_CONFIG", {})
    monkeypatch.setattr(feeds, "_LAST_CYCLE", {})
    monkeypatch.setattr(cato_routes, "_TRANSPORT", None)


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)
    return events


async def _source(name: str = "Example Cato", *, account: str = sample.EVENTS_ACCOUNT_ID, api_key: str = "k") -> dict:
    org = await db_module.create_meraki_org(name, provider="cato", org_id=account, api_key=api_key)
    assert org
    return org


def _alerts(org_ref: int, *records: dict) -> list[dict]:
    page = events_feed.parse_page(sample.feed_page(list(records)))
    return events_feed.classify(page["records"], org_ref=org_ref, org_name="Example Cato")["alerts"]


def _security(*records: dict) -> list[dict]:
    page = events_feed.parse_page(sample.feed_page(list(records)))
    return events_feed.classify(page["records"], org_ref=1)["security"]


# ── Normaliser ───────────────────────────────────────────────────────────────


def test_the_request_asks_only_for_mapped_sub_types_and_fields():
    variables = events_feed.variables("4100", "")
    assert variables["accountIDs"] == ["4100"] and variables["marker"] == ""
    (flt,) = variables["filters"]
    assert flt["fieldName"] == "event_sub_type" and flt["operator"] == "in"
    assert set(flt["values"]) == set(events_feed.CONNECTIVITY) | {"IPS"}
    assert "event_sub_type" in variables["fieldNames"] and "time" in variables["fieldNames"]
    query = events_feed.EVENTS_FEED_QUERY
    for word in ("eventsFeed", "marker", "fetchedCount", "errorString", "fieldsMap", "plexusEventsFeed"):
        assert word in query
    assert "mutation" not in query


def test_a_page_is_parsed_and_classified():
    page = events_feed.parse_page(
        sample.feed_page(
            [sample.site_disconnected(), sample.link_disconnected(), sample.ips_event(), sample.user_connected()],
            marker="m-9",
        )
    )
    assert page["marker"] == "m-9" and page["fetched"] == 4 and page["errors"] == []
    found = events_feed.classify(page["records"], org_ref=7, org_name="Example Cato")
    site, link = found["alerts"]
    assert site["key"] == "cato:7:site:1003:disconnected" and site["state"] == "open"
    assert site["severity"] == "critical" and site["tracker_scope"] == "entity" and site["site"] == "Branch-Denver"
    assert site["serial"] == "X1500-0004-DDDD" and site["started_at"] == "2026-11-20 08:00:00"
    assert site["event_type"] == "Connectivity" and site["title"] == "Disconnected"
    assert link["key"] == "cato:7:uplink:1002:WAN 02:disconnected" and link["severity"] == "warning"
    assert link["tracker_scope"] == "site_links" and link["detail"]["ISP_name"] == "Example Cable"
    # The remote user's connection is no site event.
    assert found["ignored"] == 1 and len(found["security"]) == 1


def test_a_recovery_carries_the_key_of_the_alert_it_clears():
    down, up = _alerts(7, sample.site_disconnected(), sample.site_connected())
    assert up["key"] == down["key"] and up["state"] == "resolved"
    assert up["resolved_at"] == "2026-11-20 08:20:00" and up["started_at"] == ""
    reconnected = _alerts(7, sample.feed_event("Reconnected", src_site_id="1003", src_site_name="Branch-Denver"))[0]
    assert reconnected["key"] == down["key"] and reconnected["state"] == "resolved"


def test_one_shot_and_info_events():
    failover, quality, port = _alerts(
        7,
        sample.feed_event("Socket Fail-Over", event_type="Sockets Management", socket_role="Secondary"),
        sample.feed_event("Last-Mile Quality", socket_interface="WAN 01", link_health_pkt_loss="4.5"),
        sample.feed_event("LAN port disconnected", socket_interface="LAN 03"),
    )
    assert failover["auto_expire"] and failover["state"] == "open" and failover["severity"] == "warning"
    assert failover["tracker_scope"] == "" and failover["entity_type"] == "site"
    assert quality["auto_expire"] and quality["entity_id"] == "1002:WAN 01"
    assert quality["detail"]["link_health_pkt_loss"] == "4.5"
    assert port["severity"] == "info" and port["entity_type"] == "port"
    # Unmapped sub-types and records with no site are ignored.
    assert _alerts(7, sample.feed_event("BGP Session"), sample.feed_event("Disconnected", src_site_id="", src_site_name="")) == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-11-20T08:00:00Z", "2026-11-20 08:00:00"),
        ("2026-11-20T09:00:00+01:00", "2026-11-20 08:00:00"),
        ("1795161600", "2026-11-20 08:00:00"),
        ("1795161600000", "2026-11-20 08:00:00"),
        ("", ""),
        ("not a time", ""),
    ],
)
def test_event_times(value, expected):
    assert events_feed.event_time({"time": value}) == expected


def test_an_ips_event_is_a_security_event():
    (event,) = _security(sample.ips_event())
    assert event["kind"] == "ids_alert" and event["severity"] == "critical" and event["action"] == "blocked"
    assert event["signature_id"] == 1900001 and event["signature"] == "Demo exploit attempt"
    assert event["category"] == "Exploit" and event["src_port"] == 51514 and event["dest_ip"] == "203.0.113.50"
    assert event["site_name"] == "Branch-Madison" and event["serial"] == "X1500-0003-CCCC"
    assert event["event_key"].startswith("ev:IPS:")
    monitored = _security(sample.ips_event(action="Monitor", risk_level="Low", signature_id="ab-12", event_id=None))[0]
    assert monitored["action"] == "allowed" and monitored["severity"] == "info"
    # A signature that is no number still groups by a stable number.
    assert monitored["signature_id"] == events_feed.signature_number({"signature_id": "ab-12"})
    assert monitored["event_key"] == _security(sample.ips_event(action="Monitor", risk_level="Low", signature_id="ab-12", event_id=None))[0]["event_key"]
    assert _security(sample.ips_event(risk_level="", severity="Medium"))[0]["severity"] == "warning"
    assert _security(sample.ips_event(risk_level="", severity=""))[0]["severity"] == "unknown"


def test_an_account_error_is_reported():
    page = events_feed.parse_page(sample.feed_page([], error="Events integration is disabled"))
    assert page["errors"] == ["Events integration is disabled"] and page["records"] == []
    assert events_feed.parse_page(None) == {"marker": "", "fetched": 0, "records": [], "errors": []}


# ── Store and pipeline ───────────────────────────────────────────────────────


async def test_a_disconnect_alerts_once_and_its_recovery_clears_it(notifications):
    org = await _source()
    (down,) = _alerts(org["id"], sample.site_disconnected())
    first = await feeds.ingest("cato", [down])
    assert first["new"] == 1 and first["alerted"] == 1
    again = await feeds.ingest("cato", [down])
    assert again["new"] == 0 and again["updated"] == 1 and again["alerted"] == 0
    assert len(notifications) == 1
    event = notifications[0]
    assert event["alert_type"] == "vendor_alert" and event["severity"] == "critical"
    assert event["dedup_key"] == f"vendor_alert:{down['key']}" and "Branch-Denver" in event["message"]
    (row,) = await db_module.list_vendor_alerts(provider="cato")
    assert row["alert_via"] == "notification" and row["occurrences"] == 2 and row["alert_state"] == "critical"

    (up,) = _alerts(org["id"], sample.site_connected())
    result = await feeds.ingest("cato", [up])
    assert result["resolved"] == 1
    assert await db_module.list_vendor_alerts(provider="cato") == []
    (closed,) = await db_module.list_vendor_alerts(provider="cato", include_resolved=True)
    assert closed["status"] == "resolved" and closed["resolved_at"] == "2026-11-20 08:20:00"


async def test_a_replayed_page_neither_reopens_nor_renotifies(notifications):
    org = await _source()
    page = _alerts(org["id"], sample.site_disconnected(), sample.site_connected())
    first = await feeds.ingest("cato", page)
    # Down and up in one page: stored resolved, never raised.
    assert first["new"] == 1 and first["resolved"] == 1 and first["alerted"] == 0 and notifications == []
    replay = await feeds.ingest("cato", page)
    assert replay["reopened"] == 0 and replay["alerted"] == 0 and notifications == []
    # A new outage after the recovery opens it again.
    (later,) = _alerts(org["id"], sample.site_disconnected(at="2026-11-20T10:00:00Z"))
    assert (await feeds.ingest("cato", [later]))["reopened"] == 1 and len(notifications) == 1


async def test_an_alert_on_an_inventory_socket_is_a_monitoring_alert_cleared_on_recovery(notifications):
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (961, 'Branches')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, serial_number) "
            "VALUES (9611, 961, 'socket-denver.example.com', '192.0.2.40', 'cato', 'X1500-0004-DDDD')"
        )
        await db.commit()
    finally:
        await db.close()
    org = await _source()
    await feeds.ingest("cato", _alerts(org["id"], sample.site_disconnected()))
    (alert,) = await db_module.get_monitoring_alerts(host_id=9611)
    assert alert["alert_type"] == "vendor_alert" and alert["severity"] == "critical"
    (row,) = await db_module.list_vendor_alerts(provider="cato")
    assert row["alert_via"] == "monitoring" and row["host_id"] == 9611 and notifications == []
    result = await feeds.ingest("cato", _alerts(org["id"], sample.site_connected()))
    assert result["alerts_cleared"] == 1
    (cleared,) = await db_module.get_monitoring_alerts(host_id=9611)
    assert cleared["acknowledged"] and cleared["acknowledged_by"] == "auto-resolved"


async def test_info_events_are_listed_never_raised(notifications):
    org = await _source()
    result = await feeds.ingest("cato", _alerts(org["id"], sample.feed_event("LAN port disconnected", socket_interface="LAN 03")))
    assert result["new"] == 1 and result["alerted"] == 0 and notifications == []


async def test_one_shot_alerts_expire_and_resolved_alerts_are_purged(notifications):
    org = await _source()
    (failover,) = _alerts(org["id"], sample.feed_event("Socket Fail-Over"))
    await db_module.apply_vendor_alert_events("cato", [failover], now=T0)
    assert await db_module.expire_vendor_alerts("cato", 24, now=T1) == []
    expired = await db_module.expire_vendor_alerts("cato", 1, now=T1)
    assert [r["alert_key"] for r in expired] == [failover["key"]]
    assert await db_module.purge_vendor_alerts(30) == 0
    db = await db_module.get_db()
    try:
        await db.execute("UPDATE vendor_alerts SET resolved_at = '2000-01-01 00:00:00'")
        await db.commit()
    finally:
        await db.close()
    assert await db_module.purge_vendor_alerts(30) == 1


async def test_the_migration_created_the_tables():
    db = await db_module.get_db(read_only=True)
    try:
        cursor = await db.execute("SELECT version FROM schema_migrations WHERE version = 132")
        assert await cursor.fetchone() is not None
        for table in ("vendor_alerts", "vendor_alert_feeds"):
            cursor = await db.execute(f"SELECT COUNT(*) FROM {table}")  # nosec B608 - fixed names
            assert (await cursor.fetchone())[0] == 0
    finally:
        await db.close()


# ── Mutes and the availability tracker ───────────────────────────────────────


async def _mute_denver(org_ref: int) -> dict:
    return await db_module.create_topology_mute(
        "cato", org_ref, "site", site="Branch-Denver", reason="site closed", created_by="admin"
    )


async def test_a_muted_site_alert_is_stored_not_raised(notifications):
    org = await _source()
    await _mute_denver(org["id"])
    result = await feeds.ingest("cato", _alerts(org["id"], sample.site_disconnected(), sample.link_disconnected()))
    assert result["muted"] == 1 and result["alerted"] == 1 and len(notifications) == 1
    listed = (await feeds.list_vendor_alerts_api(provider="cato", include_resolved=False, org_ref=None, limit=500))["alerts"]
    flags = {r["site"]: (r["muted"], r["alert_via"]) for r in listed}
    assert flags == {"Branch-Denver": (True, "muted"), "Branch-Madison": (False, "notification")}


async def test_muting_acknowledges_the_open_alert(notifications):
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (962, 'Branches')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, serial_number) "
            "VALUES (9621, 962, 'socket-denver.example.com', '192.0.2.41', 'cato', 'X1500-0004-DDDD')"
        )
        await db.commit()
    finally:
        await db.close()
    org = await _source()
    await feeds.ingest("cato", _alerts(org["id"], sample.site_disconnected()))
    mute = await _mute_denver(org["id"])
    assert await tracking.mute_entities(mute) == 1
    (alert,) = await db_module.get_monitoring_alerts(host_id=9621)
    assert alert["acknowledged_by"] == "muted"
    (row,) = await db_module.list_vendor_alerts(provider="cato")
    assert row["alert_via"] == "muted"


def _snapshot(site_status: str, uplink_status: str = "active") -> dict:
    return {
        "nodes": [
            {"id": "w:madison", "kind": "wan", "label": "WAN", "site": "1002", "status": "online"},
            {"id": "d:5003", "kind": "appliance", "label": "Branch-Madison", "site": "1002", "status": "online"},
            {"id": "d:5004", "kind": "appliance", "label": "Branch-Denver", "site": "1003", "status": "online"},
        ],
        "edges": [{"id": "e1", "a": "w:madison", "b": "d:5003", "kind": "uplink", "label": "WAN 02", "status": uplink_status}],
        "sites": [
            {"id": "1002", "name": "Branch-Madison", "status": "online"},
            {"id": "1003", "name": "Branch-Denver", "status": site_status},
        ],
    }


async def test_a_site_down_is_not_notified_twice_with_the_tracker(notifications):
    org = await _source()
    await tracking.record_snapshot_states("cato", org["id"], _snapshot("online"), now=T0)
    await tracking.record_snapshot_states("cato", org["id"], _snapshot("offline"), now=T0)
    assert [n["alert_type"] for n in notifications] == ["topology_availability"]
    result = await feeds.ingest("cato", _alerts(org["id"], sample.site_disconnected()))
    assert result["alerted"] == 1 and len(notifications) == 1
    (row,) = await db_module.list_vendor_alerts(provider="cato")
    assert row["alert_via"] == "topology"


async def test_the_tracker_skips_what_a_feed_alert_already_notified(notifications):
    org = await _source()
    await tracking.record_snapshot_states("cato", org["id"], _snapshot("online"), now=T0)
    await feeds.ingest("cato", _alerts(org["id"], sample.site_disconnected(), sample.link_disconnected()))
    assert len(notifications) == 2
    result = await tracking.record_snapshot_states("cato", org["id"], _snapshot("offline", "failed"), now=T0)
    # The site and its uplink went down; both were notified by the feed already.
    assert len(result["alerts"]) == 2 and len(notifications) == 2


async def test_a_feed_alert_resolves_when_the_tracker_shows_it_cleared(notifications):
    org = await _source()
    await tracking.record_snapshot_states("cato", org["id"], _snapshot("online"), now=T0)
    await db_module.apply_vendor_alert_events(
        "cato", _alerts(org["id"], sample.site_disconnected(), sample.link_disconnected()), now=T0
    )
    # A collection from before the events proves nothing.
    assert await feeds.resolve_cleared("cato", org["id"]) == 0
    await tracking.record_snapshot_states("cato", org["id"], _snapshot("online"), now=T1)
    assert await feeds.resolve_cleared("cato", org["id"]) == 2
    assert await db_module.list_vendor_alerts(provider="cato") == []


def test_tracker_coverage_and_clearing_rules():
    site = {"alert_key": "a", "status": "open", "tracker_scope": "entity", "entity_type": "site", "entity_id": "1003",
            "site": "Branch-Denver", "last_seen": T0}  # fmt: skip
    link = {**site, "alert_key": "b", "tracker_scope": "site_links", "entity_type": "uplink", "entity_id": "1003:WAN 02"}
    once = {**site, "alert_key": "c", "auto_expire": True}
    down_site = {"entity_type": "site", "entity_id": "1003", "site": "Branch-Denver", "state": "down", "alert_state": "critical"}
    up_uplink = {"entity_type": "uplink", "entity_id": "x", "site": "Branch-Denver", "state": "up", "alert_state": "", "last_seen": T1}
    assert feeds.tracker_covered(site, [down_site]) and not feeds.tracker_covered(link, [down_site])
    assert feeds.tracker_covered(link, [{**up_uplink, "state": "down", "alert_state": "warning"}])
    assert not feeds.tracker_covered({**site, "tracker_scope": ""}, [down_site])
    assert feeds.cleared_keys([site, link, once], [{**down_site, "state": "up", "last_seen": T1}, up_uplink]) == ["a", "b"]
    assert feeds.cleared_keys([link], []) == []


# ── Security events ──────────────────────────────────────────────────────────


async def test_ips_events_are_security_events_per_site(notifications, monkeypatch):
    monkeypatch.setattr(security_routes, "ALERT_MAX_AGE_MINUTES", 10**8)
    org = await _source()
    await _mute_denver(org["id"])
    events = _security(sample.ips_event(), sample.ips_event(src_site_id="1003", src_site_name="Branch-Denver"))
    totals = await feeds.record_security("cato", org, events)
    assert totals == {"stored": 2, "alerted": 1, "muted": 1}
    found = await db_module.list_security_events(provider="cato", since="2000-01-01 00:00:00")
    assert found["total"] == 2
    assert {e["source_name"] for e in found["events"]} == {"Example Cato / Branch-Madison", "Example Cato / Branch-Denver"}
    assert len(notifications) == 1 and notifications[0]["alert_type"] == "security_event"
    # The same events read again are stored once.
    assert (await feeds.record_security("cato", org, events))["stored"] == 0


# ── Poll ─────────────────────────────────────────────────────────────────────


def _transport(pages: list[dict | httpx.Response], calls: list[dict]) -> httpx.MockTransport:
    answers = list(pages)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.method == "POST" and request.headers["x-api-key"] == "k"
        assert body["operationName"] == "plexusEventsFeed" and "mutation" not in body["query"]
        calls.append(body["variables"])
        answer = answers.pop(0) if answers else sample.feed_page([], marker=body["variables"]["marker"])
        return answer if isinstance(answer, httpx.Response) else httpx.Response(200, json={"data": answer})

    return httpx.MockTransport(handler)


async def _feed_row(org_ref: int) -> dict:
    (row,) = [r for r in await db_module.list_vendor_alert_feeds("cato", "events_feed") if r["org_ref"] == org_ref]
    return row


async def test_the_first_poll_positions_the_marker_and_the_next_reads_from_it(monkeypatch, notifications):
    org = await _source()
    calls: list[dict] = []
    monkeypatch.setattr(
        cato_routes,
        "_TRANSPORT",
        _transport(
            [
                sample.feed_page([], marker="m-1"),
                sample.feed_page([sample.site_disconnected(), sample.ips_event()], marker="m-2"),
                sample.feed_page([], marker="m-2"),
            ],
            calls,
        ),
    )
    first = await feeds.run_poll_cycle("cato")
    assert first["polled"] == 1 and first["failed"] == 0
    assert [c["marker"] for c in calls] == [""]
    row = await _feed_row(org["id"])
    assert row["feed_cursor"] == "m-1" and row["feed_status"] == "positioned" and row["lease_owner"] == ""

    second = await feeds.run_poll_cycle("cato", force=True)
    assert [c["marker"] for c in calls] == ["", "m-1", "m-2"]
    assert second["new"] == 1 and second["alerted"] == 1 and second["security"] == 1
    row = await _feed_row(org["id"])
    assert row["feed_cursor"] == "m-2" and row["events_read"] == 2 and row["last_event_at"] == "2026-11-20 08:00:00"
    assert row["feed_status"] == "ok" and row["last_ok_at"]


async def test_a_refused_feed_backs_off_keeps_the_cursor_and_logs_once(monkeypatch, caplog):
    org = await _source()
    await db_module.claim_vendor_alert_feed("cato", org["id"], "events_feed", "setup", 60)
    await db_module.save_vendor_alert_feed_cursor("cato", org["id"], "events_feed", "setup", "m-5")
    await db_module.release_vendor_alert_feed("cato", org["id"], "events_feed", "setup")
    calls: list[dict] = []
    refused = sample.feed_page([], marker="", error="Events feed is not enabled for this account")
    monkeypatch.setattr(cato_routes, "_TRANSPORT", _transport([refused, refused], calls))
    result = await feeds.run_poll_cycle("cato")
    assert result["failed"] == 1 and result["sources"][0]["feed_status"] == "refused"
    row = await _feed_row(org["id"])
    assert row["feed_cursor"] == "m-5" and row["failures"] == 1 and row["next_poll_at"] > row["last_poll_at"]
    assert "not enabled" in row["last_error"]
    # Backing off: the next scheduled cycle does not call Cato.
    skipped = await feeds.run_poll_cycle("cato")
    assert skipped["polled"] == 0 and skipped["skipped"] == 1 and len(calls) == 1
    # Poll Now ignores the back-off; the same error is not logged again.
    caplog.clear()
    await feeds.run_poll_cycle("cato", force=True)
    assert len(calls) == 2 and (await _feed_row(org["id"]))["failures"] == 2
    assert not [r for r in caplog.records if "not enabled" in r.getMessage()]


async def test_access_and_rate_limit_errors():
    describe = cato_routes.describe_error
    denied = describe(cato_routes.CatoApiError("x", status_code=403))
    assert denied.feed_status == "no_access" and denied.access
    refused = describe(cato_routes.CatoApiError("x", graphql=True, detail="permission denied for eventsFeed"))
    assert refused.feed_status == "refused" and refused.access and "permission denied" in refused.text
    limited = describe(cato_routes.CatoApiError("x", graphql=True, detail="Rate limit exceeded"))
    assert limited.feed_status == "rate_limited" and not limited.access
    assert describe(cato_routes.CatoApiError("x")).feed_status == "unreachable"
    assert feeds.backoff_delay(1, 60, 600) == 120 and feeds.backoff_delay(9, 60, 600) == 600


async def test_a_source_another_worker_polls_is_skipped(monkeypatch):
    org = await _source()
    assert await db_module.claim_vendor_alert_feed("cato", org["id"], "events_feed", "other-worker", 300)
    calls: list[dict] = []
    monkeypatch.setattr(cato_routes, "_TRANSPORT", _transport([], calls))
    result = await feeds.run_poll_cycle("cato", force=True)
    assert result["polled"] == 0 and result["sources"][0]["skipped"] == "polled by another worker" and calls == []
    # A lease that ran out (its worker died) is taken over.
    assert await db_module.claim_vendor_alert_feed("cato", org["id"], "events_feed", "mine", 60, now="2099-01-01 00:00:00")


async def test_excluded_sources_polling_off_and_skipped_sources(monkeypatch):
    org = await _source()
    await _source("No key", api_key="")
    await _source("Demo-less", account="")
    calls: list[dict] = []
    monkeypatch.setattr(cato_routes, "_TRANSPORT", _transport([], calls))
    feeds._CONFIG["cato"] = feeds.sanitize_config({"poll_enabled": False})
    assert (await feeds.run_poll_cycle("cato"))["skipped"] == "polling is off"
    feeds._CONFIG["cato"] = feeds.sanitize_config({"excluded_sources": [org["id"]]})
    assert (await feeds.run_poll_cycle("cato"))["polled"] == 0 and calls == []
    feeds._CONFIG["cato"] = feeds.sanitize_config({})
    assert (await feeds.run_poll_cycle("cato"))["polled"] == 1 and len(calls) == 1


# ── API ──────────────────────────────────────────────────────────────────────


def test_settings_are_admin_only_and_clamped(api):  # noqa: F811
    resp = api.get(SETTINGS)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["provider"] == "cato" and body["config"]["interval_seconds"] == 60 and body["sources"] == []
    changed = api.put(SETTINGS, json={"interval_seconds": 5, "excluded_sources": [3, 3, -1], "open_ttl_hours": 0})
    assert changed.status_code == 200
    assert changed.json()["config"] == {
        "poll_enabled": True,
        "interval_seconds": 30,
        "excluded_sources": [3],
        "open_ttl_hours": 1,
        "security_events": True,
    }
    assert api.get("/api/monitoring/vendor-alerts/nope/settings").status_code == 404
    api._c.cookies.clear()
    assert api.get(SETTINGS).status_code == 401
    assert api.post("/api/monitoring/vendor-alerts/cato/poll").status_code == 401


def test_poll_now_is_audited_and_the_alerts_are_listed(api, monkeypatch, notifications):  # noqa: F811
    created = api.post(
        "/api/sources", json={"name": "Example Cato", "provider": "cato", "org_id": sample.EVENTS_ACCOUNT_ID, "api_key": "k"}
    )
    assert created.status_code == 201, created.text
    calls: list[dict] = []
    monkeypatch.setattr(
        cato_routes,
        "_TRANSPORT",
        _transport([sample.feed_page([], marker="m-1"), sample.feed_page([sample.site_disconnected()], marker="m-2")], calls),
    )
    for _ in range(2):
        resp = api.post("/api/monitoring/vendor-alerts/cato/poll")
        assert resp.status_code == 200, resp.text
    assert resp.json()["new"] == 1
    listed = api.get("/api/monitoring/vendor-alerts?provider=cato").json()["alerts"]
    assert len(listed) == 1 and listed[0]["entity_name"] == "Branch-Denver" and listed[0]["muted"] is False
    source = api.get(SETTINGS).json()["sources"][0]
    assert source["name"] == "Example Cato" and source["cursor_set"] and source["feed_status"] == "ok"
    assert api.get("/api/monitoring/vendor-alerts?provider=BAD!").status_code == 422
