"""Tests for the OPNsense health and services (``collector.collect_health``,
``normalize.health_summary``, ``opnsense.health``, ``routes.opnsense_health``).

Covers, with no network access (a fake firewall serves the answers of
``sample.sample_api_answers`` over ``httpx.MockTransport``):
  * collector  - every health part read with GET, the process list of the
                 activity dropped, the service rows trimmed, a missing
                 endpoint (404) as one informational warning, a refused one
                 (403) naming its privilege, the option off, the call count
  * normalize  - the summary from the sample (CPU from top's CPU line,
                 memory without the ZFS ARC, the fullest file system,
                 hottest sensor, state table, uptime), the shapes of older
                 releases, the Health and Services sections, the full disk
                 and state table warnings
  * tracking   - each service a ``service`` entity of the firewall, down
                 when stopped: the alert on the firewall's inventory host,
                 recovery, a service gone at a clean collection removed and
                 its alert resolved, muting the firewall covers its services
  * poll       - the health merged into a monitoring poll (only the fields
                 SNMP left empty), stored as metric samples, the built-in
                 disk full alert raised and resolved, a user rule on a
                 firewall metric, the host noted at collection

Every name and address is invented (example.com, documentation ranges).
"""

from __future__ import annotations

import base64
import copy
import json

import httpx
import netcontrol.app as app_module  # noqa: F401 - the app the database belongs to
import netcontrol.routes.meraki_topology as topology_routes
import netcontrol.routes.opnsense_health as health_poll
import netcontrol.routes.state as state
import netcontrol.routes.topology_availability as tracking
import pytest
import routes.database as db
from netcontrol.integrations.availability import clean_entity_types, extract_entity_states
from netcontrol.integrations.opnsense.client import OpnsenseClient
from netcontrol.integrations.opnsense.collector import HEALTH_PARTS, collect_health, collect_opnsense
from netcontrol.integrations.opnsense.health import (
    ALERT_DISK_FULL,
    FIREWALL_METRICS,
    firewall_alert_checks,
    firewall_cleared_alerts,
    firewall_metric_samples,
)
from netcontrol.integrations.opnsense.normalize import build_snapshot, health_summary, uptime_seconds
from netcontrol.integrations.opnsense.sample import build_sample_raw, sample_api_answers
from netcontrol.routes.opnsense_collection import note_health_host

BASE = "https://fw1.example.com"
KEY = "plexus-key-0002"
SECRET = "plexus-secret-0002-not-real"
FIREWALL = "d:fw-edge-1.example.com"
T0 = "2026-01-01 00:00:00"
T1 = "2026-01-02 00:00:00"
T2 = "2026-01-03 00:00:00"
T3 = "2026-01-04 00:00:00"


class _Firewall:
    """The health and VPN endpoints of a firewall: the sample's answers, GET
    only but for the per-connection IPsec child SAs (POST ``{"id": ...}``)."""

    def __init__(self) -> None:
        self.answers = sample_api_answers()
        self.fail: dict[str, int] = {}
        self.calls: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        expected = "Basic " + base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()
        if request.headers.get("Authorization") != expected:
            return httpx.Response(401, json={"message": "Authentication Failed"})
        path = request.url.path.removeprefix("/api/")
        self.calls.append(path)
        assert request.method == "GET" or path == "ipsec/sessions/search_phase2", (request.method, path)
        if path in self.fail:
            return httpx.Response(self.fail[path], json={"message": f"refused {path}"})
        if path not in self.answers:
            return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
        if request.method == "POST":
            found = self.answers[path].get(json.loads(request.content)["id"])
            if found is None:
                return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
            return httpx.Response(200, json=copy.deepcopy(found))
        return httpx.Response(200, json=copy.deepcopy(self.answers[path]))


def _client(fake: _Firewall) -> OpnsenseClient:
    return OpnsenseClient(BASE, KEY, SECRET, transport=httpx.MockTransport(fake.handler), requests_per_second=1000)


def _raw(**health: object) -> dict:
    """The sample collection with some health answers replaced."""
    raw = build_sample_raw()
    raw["health"].update(health)
    return raw


def _services(running: dict[str, int] | None = None, drop: tuple[str, ...] = ()) -> list[dict]:
    rows = copy.deepcopy(build_sample_raw()["health"]["services"])
    for row in rows:
        row["running"] = (running or {}).get(row["id"], row["running"])
    return [r for r in rows if r["id"] not in drop]


def _section(snapshot: dict, title: str) -> dict:
    firewall = next(n for n in snapshot["nodes"] if n["id"] == FIREWALL)
    return next(s for s in firewall["sections"] if s["title"] == title)


# ── Collector ────────────────────────────────────────────────────────────────


async def test_collect_health_reads_every_part_and_keeps_no_process_list():
    fake = _Firewall()
    errors: list[dict] = []
    async with _client(fake) as client:
        health, answered = await collect_health(client, errors)
    assert errors == [] and answered == len(HEALTH_PARTS) == 7
    assert fake.calls == [paths[0] for _key, paths, _privilege in HEALTH_PARTS]
    assert set(health) == {key for key, _paths, _privilege in HEALTH_PARTS}
    # top's header lines only: the process list names every command line.
    assert health["activity"] == {"headers": sample_api_answers()["diagnostics/activity/get_activity"]["headers"]}
    assert "not-a-real-secret" not in str(health)
    assert health["services"][0] == {
        "id": "configd",
        "name": "configd",
        "description": "System Configuration Daemon",
        "running": 1,
        "locked": 1,
    }
    assert health == build_sample_raw()["health"]


async def test_collect_health_skips_a_missing_endpoint_quietly_and_names_a_refused_privilege():
    fake = _Firewall()
    fake.fail = {"diagnostics/system/system_temperature": 404, "core/service/search": 403}
    errors: list[dict] = []
    async with _client(fake) as client:
        health, answered = await collect_health(client, errors)
    assert answered == 5 and health["temperature"] is None and health["services"] is None
    by_scope = sorted(errors, key=lambda e: bool(e.get("info")))
    refused, missing = by_scope
    assert refused["status"] == 403 and "privilege needed: Status: Services" in refused["message"]
    assert missing["info"] and "/diagnostics/system/system_temperature" in missing["message"]
    # The camelCase form of 24.7 to 25.1 was tried before giving up.
    assert "diagnostics/system/systemTemperature" in fake.calls


async def test_collect_health_reads_only_the_parts_asked_for():
    fake = _Firewall()
    async with _client(fake) as client:
        health, answered = await collect_health(client, [], ("pf_states",))
    assert answered == 1 and fake.calls == ["diagnostics/firewall/pf_states"]
    assert health["pf_states"] == {"current": "1830", "limit": "404000"} and health["services"] is None


async def test_the_collection_reads_health_by_default_and_counts_its_calls(monkeypatch):
    import netcontrol.integrations.opnsense.collector as collector_module

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(collector_module.asyncio, "sleep", _no_sleep)
    fake = _Firewall()
    fake.answers = {**sample_api_answers()}
    progress: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        # The rest of the collection: whatever the sample has, 404 otherwise.
        path = request.url.path.removeprefix("/api/")
        if path == "core/firmware/upgradestatus":
            return httpx.Response(
                200, json={"status": "done", "log": "***GOT REQUEST TO AUDIT SECURITY***\n***DONE***"}
            )
        if path == "core/backup/download/this":
            return httpx.Response(404)
        if request.method == "POST":
            return httpx.Response(200, json={"rows": []})
        return fake.handler(request)

    options = {"include_firmware_audit": False, "config_backup": False}
    async with OpnsenseClient(
        BASE, KEY, SECRET, transport=httpx.MockTransport(handler), requests_per_second=1000
    ) as client:
        raw = await collect_opnsense(client, options, progress.append)
    assert raw["health"] == build_sample_raw()["health"]
    health_phase = [p for p in progress if p["phase"] == "opnsense health"]
    assert health_phase[-1]["services"] == 8
    assert progress[-1]["calls_done"] == progress[-1]["calls_total"]

    fake.calls.clear()
    async with OpnsenseClient(
        BASE, KEY, SECRET, transport=httpx.MockTransport(handler), requests_per_second=1000
    ) as client:
        raw = await collect_opnsense(client, {**options, "include_health": False})
    assert raw["health"] is None
    assert not {paths[0] for _key, paths, _privilege in HEALTH_PARTS} & set(fake.calls)


# ── Normalize ────────────────────────────────────────────────────────────────


def test_summary_of_the_sample():
    summary = build_snapshot(build_sample_raw())["health"]
    assert summary["cpu_percent"] == 7.0  # 100 - 93.0 % idle
    assert summary["load_avg"] == [0.31, 0.24, 0.2]
    # The ZFS ARC is not counted as used.
    assert (summary["memory_percent"], summary["memory_used_mb"], summary["memory_total_mb"]) == (32.5, 1331.2, 4096.0)
    assert summary["arc_mb"] == 512.0
    assert summary["disk_percent"] == 41.0 and [d["mountpoint"] for d in summary["disks"]] == [
        "/",
        "/var/log",
        "/boot/efi",
    ]
    assert summary["temperature_c"] == 49.0 and len(summary["temperatures"]) == 3
    assert (summary["pf_states"], summary["pf_states_limit"], summary["pf_states_percent"]) == (1830.0, 404000.0, 0.5)
    assert summary["uptime_seconds"] == 12 * 86400 + 3 * 3600 + 4 * 60 + 5


def test_summary_of_older_releases_and_odd_answers():
    activity = {"headers": ["last pid: 1;  load averages:  1.50,  1.25,  1.00  up 0+01:00:00", "CPU: 80.0% idle"]}
    summary = health_summary(
        {
            # 24.7: no load averages in system_time; the 24.7 disk rows; no ARC.
            "time": {"uptime": "01:02:03", "datetime": "x", "config": "y"},
            "activity": activity,
            "disk": {
                "devices": [
                    {
                        "device": "/dev/gpt/rootfs",
                        "type": "ufs",
                        "blocks": "9.7G",
                        "used": "2.1G",
                        "used_pct": 24,
                        "mountpoint": "/",
                    },
                    {
                        "device": "/dev/cd0",
                        "type": "cd9660",
                        "blocks": "1.0G",
                        "used": "1.0G",
                        "used_pct": 100,
                        "mountpoint": "/cdrom",
                    },
                ]
            },
            "resources": {"memory": {"total": "1073741824", "used": 536870912}},
            "pf_states": {"result": "failed"},
            "temperature": [],
        }
    )
    assert summary["cpu_percent"] == 20.0 and summary["load_avg"] == [1.5, 1.25, 1.0]
    assert summary["uptime_seconds"] == 3723
    # Read-only media are always full: not the fullest file system.
    assert summary["disk_percent"] == 24.0 and summary["disks"][0]["size"] == "9.7G"
    assert summary["memory_percent"] == 50.0 and summary["arc_mb"] is None
    assert summary["pf_states"] is None and summary["pf_states_percent"] is None and summary["temperature_c"] is None
    # Nothing read at all.
    assert health_summary(None)["cpu_percent"] is None and health_summary({})["disks"] == []
    assert health_summary({"resources": {"memory": {"used": "N/A"}}})["memory_percent"] is None
    assert uptime_seconds("3 Tage, 00:00:01") == 259201 and uptime_seconds("soon") is None


def test_health_and_services_sections():
    snapshot = build_snapshot(_raw(services=_services({"unbound": 0})))
    health = dict(_section(snapshot, "Health")["rows"])
    assert health["CPU"] == "7 %" and health["State table"] == "1830 of 404000 (0.5 %)"
    assert health["Memory"].startswith("32.5 % (1331 of 4096 MiB, ARC 512 MiB")
    assert "/var/log 41 % of 24.3G" in health["File systems"]
    assert health["Services"] == "7 of 8 running" and health["Stopped"] == "Unbound"
    services = _section(snapshot, "Services")
    rows = {r[1]: dict(zip(services["columns"], r, strict=True)) for r in services["rows"]}
    assert rows["unbound"]["Status"] == "stopped" and rows["configd"]["Locked"] == "Yes"
    assert snapshot["summary"]["services"] == 8 and snapshot["summary"]["services_stopped"] == 1


def test_health_not_read_adds_nothing():
    raw = build_sample_raw()
    raw["health"] = None
    snapshot = build_snapshot(raw)
    assert "health" not in snapshot and "services" not in snapshot
    assert snapshot["summary"]["services"] is None
    titles = [s["title"] for s in next(n for n in snapshot["nodes"] if n["id"] == FIREWALL)["sections"]]
    assert "Health" not in titles and "Services" not in titles


def test_a_full_disk_and_a_full_state_table_are_informational_warnings():
    disk = copy.deepcopy(build_sample_raw()["health"]["disk"])
    disk["devices"][1]["used_pct"] = 93
    snapshot = build_snapshot(_raw(disk=disk, pf_states={"current": "330000", "limit": "404000"}))
    warnings = [w for w in snapshot["collection"]["errors"] if w["scope"] == "health"]
    assert [w["message"] for w in warnings] == [
        "File system nearly full: /var/log (93 %)",
        "State table near its limit: 330000 of 404000 states (81.7 %)",
    ]
    assert all(w["info"] for w in warnings) and "service" in clean_entity_types("opnsense", snapshot)


# ── Entities and tracking ────────────────────────────────────────────────────


def _service_entities(snapshot: dict) -> dict:
    return {e.entity_id: e for e in extract_entity_states("opnsense", 3, snapshot) if e.entity_type == "service"}


def test_each_enabled_service_is_an_entity_of_the_firewall():
    snapshot = build_snapshot(_raw(services=_services({"suricata": 0})))
    next(n for n in snapshot["nodes"] if n["id"] == FIREWALL)["inventory"] = {"host_id": 41}
    entities = _service_entities(snapshot)
    assert sorted(entities) == [
        "svc:configd",
        "svc:dhcpd",
        "svc:dpinger",
        "svc:kea-dhcp/v6",
        "svc:ntpd",
        "svc:openvpn/1",
        "svc:suricata",
        "svc:unbound",
    ]
    unbound, ids = entities["svc:unbound"], entities["svc:suricata"]
    assert (unbound.state, unbound.raw_status, unbound.host_id) == ("up", "running", 41)
    assert unbound.name == "fw-edge-1.example.com Unbound" and unbound.site == "fw-edge-1.example.com"
    assert unbound.meta == {"type": "unbound", "kind": "OPNsense service", "a": FIREWALL}
    assert (ids.state, ids.raw_status) == ("down", "stopped")


async def _host(group_id: int) -> int:
    group = await db.create_group(f"opn-health-{group_id}")
    return await db.add_host(group, "fw-edge-1.example.com", "192.0.2.1", "opnsense")


def _on_host(snapshot: dict, host_id: int) -> dict:
    next(n for n in snapshot["nodes"] if n["id"] == FIREWALL)["inventory"] = {"host_id": host_id}
    return snapshot


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(tracking.notification_channels, "on_alert_created", _capture)
    return events


async def test_a_stopped_service_alerts_on_the_host_recovers_and_a_gone_one_is_removed(notifications):
    host_id = await _host(1)
    org = 8101

    async def collect(now: str, **kwargs) -> dict:
        snapshot = _on_host(build_snapshot(_raw(services=_services(**kwargs))), host_id)
        return await tracking.record_snapshot_states("opnsense", org, snapshot, now=now)

    first = await collect(T0)
    assert first["alerts"] == []  # baseline
    await collect(T1, running={"unbound": 0})
    key = f"topo:opnsense:{org}:service:svc:unbound"
    alerts = await db.get_monitoring_alerts(host_id=host_id)
    assert [(a["dedup_key"], a["severity"]) for a in alerts] == [(key, "critical")]
    assert alerts[0]["message"].startswith("Service fw-edge-1.example.com Unbound at fw-edge-1.example.com")
    assert "is down (was up)" in alerts[0]["message"]

    back = await collect(T2)
    assert [t["entity_id"] for t in back["recoveries"]] == ["svc:unbound"]

    # Stopped again, then disabled by the admin: core/service/search no
    # longer lists it, the clean collection removes it and resolves its alert.
    await collect(T3, running={"unbound": 0})
    assert [a["dedup_key"] for a in await db.get_monitoring_alerts(host_id=host_id, acknowledged=False)] == [key]
    gone = await collect("2026-01-05 00:00:00", drop=("unbound",))
    assert gone["removed"] == 1
    assert await db.get_monitoring_alerts(host_id=host_id, acknowledged=False) == []
    states = await db.list_topology_entity_states("opnsense", org, "service")
    assert "svc:unbound" not in {r["entity_id"] for r in states} and len(states) == 7


async def test_services_not_read_are_kept_and_raise_nothing(notifications):
    org = 8102
    await tracking.record_snapshot_states("opnsense", org, build_snapshot(build_sample_raw()), now=T0)
    raw = build_sample_raw()
    raw["health"]["services"] = None
    raw["errors"].append({"scope": "health", "path": "/core/service/search", "status": 403, "message": "refused"})
    result = await tracking.record_snapshot_states("opnsense", org, build_snapshot(raw), now=T1)
    assert result["removed"] == 0 and result["alerts"] == [] and notifications == []
    states = await db.list_topology_entity_states("opnsense", org, "service")
    assert len(states) == 8 and all(r["missing"] for r in states)


async def test_muting_the_firewall_covers_its_services(notifications):
    org = 8103
    await tracking.record_snapshot_states("opnsense", org, build_snapshot(build_sample_raw()), now=T0)
    await db.create_topology_mute(
        "opnsense", org, "entity", entity_type="device", entity_id=FIREWALL, reason="maintenance", created_by="admin"
    )
    stopped = build_snapshot(_raw(services=_services({"unbound": 0, "dhcpd": 0})))
    result = await tracking.record_snapshot_states("opnsense", org, stopped, now=T1)
    assert len(result["alerts"]) == 2 and result["muted_alerts"] == 2 and notifications == []


async def test_a_firewall_off_the_inventory_alerts_to_the_channels(notifications):
    org = 8104
    await tracking.record_snapshot_states("opnsense", org, build_snapshot(build_sample_raw()), now=T0)
    await tracking.record_snapshot_states(
        "opnsense", org, build_snapshot(_raw(services=_services({"kea-dhcp/v6": 0}))), now=T1
    )
    (event,) = notifications
    assert event["host_id"] is None and event["dedup_key"] == f"topo:opnsense:{org}:service:svc:kea-dhcp/v6"


# ── The monitoring poll ──────────────────────────────────────────────────────


def test_metric_samples_and_built_in_checks():
    summary = health_summary(build_sample_raw()["health"])
    rows = {metric: value for _host, metric, _labels, value in firewall_metric_samples(5, summary)}
    assert rows == {
        "fw_disk_used_pct": 41.0,
        "fw_temperature_c": 49.0,
        "fw_pf_states": 1830.0,
        "fw_pf_states_pct": 0.5,
        "fw_load_avg_1m": 0.31,
    }
    assert set(rows) == set(FIREWALL_METRICS)
    assert firewall_alert_checks(summary) == []
    assert firewall_cleared_alerts(summary, []) == ["fw_disk_full", "fw_state_table"]
    full = {
        **summary,
        "disk_percent": 96.0,
        "disks": [{"mountpoint": "/", "used_pct": 96.0}],
        "pf_states_percent": 85.0,
    }
    checks = {c["metric"]: c for c in firewall_alert_checks(full)}
    assert (checks["fw_disk_full"]["severity"], checks["fw_disk_full"]["threshold"]) == ("critical", 95.0)
    assert checks["fw_disk_full"]["message"] == "File system nearly full: / 96% (threshold 90%)"
    assert (checks["fw_state_table"]["severity"], checks["fw_state_table"]["threshold"]) == ("warning", 80.0)
    # A value that was not read clears nothing.
    assert firewall_cleared_alerts({**summary, "disk_percent": None}, []) == ["fw_state_table"]
    assert firewall_alert_checks(None) == [] and firewall_cleared_alerts({}, []) == []


def test_merge_fills_only_what_snmp_left_empty_and_marks_an_answering_firewall_up():
    summary = health_summary(build_sample_raw()["health"])
    result = {
        "cpu_percent": 12.0,
        "memory_percent": None,
        "uptime_seconds": None,
        "poll_status": "error",
        "poll_error": "x",
    }
    health_poll.merge_health(result, summary)
    assert result["cpu_percent"] == 12.0 and result["memory_percent"] == 32.5
    assert result["uptime_seconds"] == summary["uptime_seconds"] and result["opnsense_health"] is summary
    assert (result["poll_status"], result["poll_error"]) == ("ok", "")


@pytest.fixture
def firewall_source(monkeypatch):
    """An OPNsense source whose API is the fake firewall, and no SNMP or ICMP."""
    fake = _Firewall()

    def _opnsense_client(org, secret, options, **kwargs):
        key, value = secret.split(":", 1)
        kwargs["transport"] = httpx.MockTransport(fake.handler)
        return OpnsenseClient(org["base_url"], key, value, requests_per_second=1000, **kwargs)

    monkeypatch.setattr(topology_routes, "_opnsense_client", _opnsense_client)
    monkeypatch.setitem(state.MONITORING_CONFIG, "icmp_enabled", False)
    health_poll.forget_sources()
    yield fake
    health_poll.forget_sources()


async def _source_with_host(host_id: int) -> int:
    org = await db.create_meraki_org(
        "Edge firewall", provider="opnsense", base_url=BASE, api_key=f"{KEY}:{SECRET}", created_by="test"
    )
    snapshot = build_snapshot(build_sample_raw())
    snapshot["summary"][health_poll.SUMMARY_KEY] = host_id
    await db.create_meraki_snapshot(org["id"], snapshot, built_by="test")
    return int(org["id"])


async def test_the_poll_reads_stores_and_alerts_without_snmp(firewall_source):
    from netcontrol.routes.monitoring import _poll_host_monitoring, _process_poll_result

    host_id = await _host(2)
    await _source_with_host(host_id)
    host = await db.get_host(host_id)

    result = await _poll_host_monitoring(host, None, {"enabled": False})
    assert (result["cpu_percent"], result["memory_percent"], result["poll_status"]) == (7.0, 32.5, "ok")
    assert "core/service/search" not in firewall_source.calls  # the collection tracks services
    await _process_poll_result(host, result, [])
    polls = await db.get_monitoring_poll_history(host_id)
    assert [p["cpu_percent"] for p in polls] == [7.0]
    samples = await db.query_metric_samples("fw_disk_used_pct", [host_id])
    assert [s["value"] for s in samples] == [41.0]
    assert await db.get_monitoring_alerts(host_id, acknowledged=False) == []

    # /var/log fills up: the built-in alert; it drains: resolved.
    firewall_source.answers["diagnostics/system/system_disk"]["devices"][1]["used_pct"] = 92
    full = await _poll_host_monitoring(host, None, {"enabled": False})
    await _process_poll_result(host, full, [])
    alerts = await db.get_monitoring_alerts(host_id, acknowledged=False)
    assert [(a["metric"], a["severity"], a["dedup_key"]) for a in alerts] == [
        (ALERT_DISK_FULL, "warning", f"{host_id}:{ALERT_DISK_FULL}:threshold")
    ]
    firewall_source.answers["diagnostics/system/system_disk"]["devices"][1]["used_pct"] = 41
    drained = await _poll_host_monitoring(host, None, {"enabled": False})
    await _process_poll_result(host, drained, [])
    assert await db.get_monitoring_alerts(host_id, acknowledged=False) == []


async def test_a_user_rule_can_use_a_firewall_metric(firewall_source):
    from netcontrol.routes.monitoring import _evaluate_alerts_for_poll, _poll_host_monitoring

    host_id = await _host(3)
    await _source_with_host(host_id)
    result = await _poll_host_monitoring(await db.get_host(host_id), None, {"enabled": False})
    poll_id = await db.create_monitoring_poll(host_id)
    rule_id = await db.create_alert_rule("Hot firewall", "fw_temperature_c", operator=">=", value=45.0)
    rule = {"id": rule_id, "name": "Hot firewall", "metric": "fw_temperature_c", "operator": ">=", "value": 45.0}
    assert await _evaluate_alerts_for_poll(result, poll_id, None, [rule], suppressions=[]) == 1
    (alert,) = await db.get_monitoring_alerts(host_id, acknowledged=False)
    assert alert["metric"] == "fw_temperature_c" and alert["value"] == 49.0


async def test_a_host_of_no_source_is_left_alone(firewall_source):
    from netcontrol.routes.monitoring import _poll_host_monitoring

    host_id = await _host(4)
    result = await _poll_host_monitoring(await db.get_host(host_id), None, {"enabled": False})
    assert result["cpu_percent"] is None and "opnsense_health" not in result and firewall_source.calls == []


async def test_a_source_with_health_off_is_not_read(firewall_source):
    from netcontrol.routes.monitoring import _poll_host_monitoring

    host_id = await _host(5)
    org_ref = await _source_with_host(host_id)
    await db.update_meraki_org(org_ref, options={"include_health": False})
    result = await _poll_host_monitoring(await db.get_host(host_id), None, {"enabled": False})
    # Only the VPN counters (``include_vpn``: tunnel traffic) and the IDS
    # status (``include_ids_alerts``; this firewall has no IDS API) are read.
    assert "opnsense_health" not in result
    assert firewall_source.calls and all(
        c.startswith(("ipsec/", "wireguard/", "openvpn/", "ids/")) for c in firewall_source.calls
    )
    firewall_source.calls.clear()
    await db.update_meraki_org(
        org_ref, options={"include_health": False, "include_vpn": False, "include_ids_alerts": False}
    )
    health_poll.forget_sources()
    result = await _poll_host_monitoring(await db.get_host(host_id), None, {"enabled": False})
    assert "opnsense_health" not in result and firewall_source.calls == []


async def test_the_collection_notes_the_inventory_host(firewall_source):
    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    host = await note_health_host(raw, snapshot, 8105)
    assert host is None and snapshot["summary"][health_poll.SUMMARY_KEY] is None
    assert dict(_section(snapshot, "Health")["rows"])["History"].startswith("Shown here only")

    host_id = await _host(6)
    snapshot = build_snapshot(raw)
    host = await note_health_host(raw, snapshot, 8105)
    assert host is not None and int(host["id"]) == host_id
    assert snapshot["summary"][health_poll.SUMMARY_KEY] == host_id
    rows = _section(snapshot, "Health")["rows"]
    assert rows[-2][0] == "History" and rows[-1][0] == "Source"
    assert rows[-2][1].endswith("stored with the monitoring poll of fw-edge-1.example.com")
