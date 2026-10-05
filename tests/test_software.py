"""Tests for the software version tracker and vulnerability alerts.

Covers, with no network access:
  * versions   - parsing, ordering, specification matching, classification,
                 reading versions out of topology snapshots, matching, spread
  * psirt      - token login, version query, not-found, relogin, retry
  * HTTP API   - the tracked set from inventory hosts and the sample
                 topologies, version history, advisories (CRUD, import,
                 validation), alerts (open, acknowledge, resolve),
                 notifications, settings (write-only secret), PSIRT sync job
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import netcontrol.app as app_module
import netcontrol.routes.software as software_routes
import pytest
import routes.database as db_module
from netcontrol.integrations.anyconnect.normalize import build_snapshot as build_anyconnect_snapshot
from netcontrol.integrations.anyconnect.sample import build_sample_raw as build_anyconnect_raw
from netcontrol.integrations.meraki.normalize import build_snapshot as build_meraki_snapshot
from netcontrol.integrations.meraki.sample import build_sample_raw as build_meraki_raw
from netcontrol.integrations.software.psirt import OS_TYPES, PsirtApiError, PsirtClient, normalize_advisory
from netcontrol.integrations.software.versions import (
    PLATFORMS,
    advisory_applies,
    canonical_version,
    classify_host,
    compare_versions,
    extract_version,
    find_advisory_matches,
    newest_version,
    severity_at_least,
    snapshot_devices,
    validate_version_spec,
    version_matches,
    version_spread,
    version_tokens,
)

# ── versions ─────────────────────────────────────────────────────────────────


def test_extract_and_canonical_version_cover_every_source_format():
    assert extract_version("Version 17.9.4a, RELEASE SOFTWARE (fc3)") == "17.9.4a"
    assert extract_version("15.2(7)E8") == "15.2(7)E8"
    assert extract_version("v7.2.5,build1517,230516 (GA.F)") == "7.2.5"
    assert extract_version("7.4.1 (build 172)") == "7.4.1"
    assert extract_version("JUNOS 21.4R3-S4.9") == "21.4R3-S4.9"
    assert extract_version("") == "" and extract_version(None) == ""
    assert canonical_version("wired-18-107-2") == "18.107.2"
    assert canonical_version("switch-17-1-4") == "17.1.4"
    assert canonical_version("MX 18.107.2") == "18.107.2"
    assert canonical_version("21.4R3-S4.9") == "21.4R3-S4.9"
    assert canonical_version("15.2(7)E8") == "15.2(7)E8"


def test_versions_compare_by_parts_not_as_text():
    assert compare_versions("17.9.4a", "17.9.4") == 1
    assert compare_versions("17.10.1", "17.9.4a") == 1
    assert compare_versions("15.2(7)E10", "15.2(7)E8") == 1
    assert compare_versions("17.09.4", "17.9.4") == 0
    assert compare_versions("21.4R3", "21.4R3-S4") == -1
    assert version_tokens("wired-18-107-2") == version_tokens("18.107.2")
    assert newest_version(["17.3.4", "17.12.1", "17.9.4a"]) == "17.12.1"
    assert newest_version([]) == ""


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("17.9.4a", "17.9.4a", True),
        ("17.9.4a", "17.9.4", False),
        ("17.9.4a", "17.9.*", True),
        ("17.10.1", "17.9.*", False),
        ("17.3.4", "<17.6.5", True),
        ("17.6.5", "<17.6.5", False),
        ("17.6.5", "<=17.6.5", True),
        ("15.2(7)E8", ">=15.2(7)E8", True),
        ("17.4.1", "17.3..17.6.4", True),
        ("17.6.5", "17.3..17.6.4", False),
        ("16.12.5", "16.12..16.12.9, !=16.12.5", False),
        ("16.12.6", "16.12..16.12.9, !=16.12.5", True),
        ("17.3.4", "..17.3.4", True),
        ("18.107.2", "wired-18-107-2", True),
        ("", "17.9.4a", False),
        ("17.9.4a", "", False),
    ],
)
def test_version_matches_the_specification_grammar(version, spec, expected):
    assert version_matches(version, spec) is expected


def test_validate_version_spec_reports_what_is_wrong():
    assert validate_version_spec("<17.6.5, 17.3.*") == ""
    assert validate_version_spec("17.3..17.6") == ""
    assert "empty" in validate_version_spec("  ")
    assert "not a version" in validate_version_spec("<abc")
    assert "no bounds" in validate_version_spec("..")


def test_classify_host_tells_ios_xe_from_ios_and_knows_the_drivers():
    assert classify_host("cisco_ios", "C9300-48T", "17.9.4a") == ("ios-xe", "17.9.4a")
    assert classify_host("cisco_ios", "C3750E", "15.2(4)E10") == ("ios", "15.2(4)E10")
    assert classify_host("cisco_xe", "", "Version 17.12.1") == ("ios-xe", "17.12.1")
    assert classify_host("cisco_nxos", "n9000", "10.3(2)") == ("nx-os", "10.3(2)")
    assert classify_host("cisco_ftd", "FPR2110", "7.2.5") == ("ftd", "7.2.5")
    assert classify_host("cisco_ftd", "Cisco Adaptive Security Appliance", "9.16(4)14") == ("asa", "9.16(4)14")
    assert classify_host("juniper_junos", "ex4300", "21.4R3-S4.9") == ("junos", "21.4R3-S4.9")
    assert classify_host("fortinet", "FGT60F", "v7.2.5,build1517") == ("fortios", "7.2.5")
    assert classify_host("unknown", "Arista DCS-7050", "4.28.3M") == ("eos", "4.28.3M")
    assert classify_host("unknown", "", "3.1.0") == ("other", "3.1.0")
    assert classify_host("cisco_ios", "", "") == ("ios", "")


def test_snapshot_devices_read_firmware_from_meraki_and_software_from_anyconnect():
    meraki = build_meraki_snapshot(build_meraki_raw())
    devices = snapshot_devices(meraki, "meraki")
    assert devices and all(d["serial"] and d["version"] for d in devices)
    by_platform = {d["platform"] for d in devices}
    assert by_platform == {"meraki-mx", "meraki-ms", "meraki-mr"}
    mx = next(d for d in devices if d["platform"] == "meraki-mx")
    assert mx["raw_version"] == "wired-18-2-11" and mx["version"] == "18.2.11" and mx["site"]

    anyconnect = build_anyconnect_snapshot(build_anyconnect_raw())
    devices = snapshot_devices(anyconnect, "anyconnect")
    platforms = sorted(d["platform"] for d in devices)
    assert platforms == ["fmc", "ftd", "ftd"]
    assert {d["version"] for d in devices} == {"7.4.1"}
    # Users nodes, WAN stubs and the AWS snapshot carry no versions.
    assert snapshot_devices(anyconnect, "aws") == []


def test_advisory_matching_respects_platform_product_and_enabled():
    device = {"device_key": "host:1", "platform": "ios-xe", "model": "C9300-48T", "version": "17.9.4a"}
    base = {"advisory_id": "A", "severity": "High", "affected_versions": ["<17.12.1"], "enabled": True}
    assert advisory_applies(device, base)
    assert advisory_applies(device, {**base, "platform": "ios-xe"})
    assert not advisory_applies(device, {**base, "platform": "nx-os"})
    assert advisory_applies(device, {**base, "product_match": "c9300"})
    assert not advisory_applies(device, {**base, "product_match": "C9500"})
    assert not advisory_applies(device, {**base, "enabled": False})
    matches = find_advisory_matches(
        [device, {**device, "device_key": "host:2", "version": "17.12.3"}],
        [base, {**base, "advisory_id": "B", "severity": "critical", "affected_versions": ["17.12.*"]}],
    )
    assert [(m["device_key"], m["advisory_id"], m["severity"]) for m in matches] == [
        ("host:2", "B", "critical"),
        ("host:1", "A", "high"),
    ]
    assert severity_at_least("high", "high") and severity_at_least("critical", "medium")
    assert not severity_at_least("low", "medium")


def test_version_spread_finds_the_newest_and_most_common_versions():
    devices = [
        {"platform": "ios-xe", "version": "17.9.4a"},
        {"platform": "ios-xe", "version": "17.9.4a"},
        {"platform": "ios-xe", "version": "17.12.1"},
        {"platform": "ios-xe", "version": "16.12.4"},
        {"platform": "meraki-ms", "version": "17.1.4"},
        {"platform": "meraki-ms", "version": ""},
    ]
    spread = version_spread(devices)
    assert [p["platform"] for p in spread] == ["ios-xe", "meraki-ms"]
    xe = spread[0]
    assert xe["label"] == PLATFORMS["ios-xe"]["label"]
    assert xe["device_count"] == 4 and xe["version_count"] == 3
    assert xe["newest_version"] == "17.12.1" and xe["most_common_version"] == "17.9.4a"
    assert xe["behind_newest"] == 3
    assert [v["version"] for v in xe["versions"]] == ["17.12.1", "17.9.4a", "16.12.4"]
    assert spread[1]["device_count"] == 1


# ── Cisco PSIRT client ───────────────────────────────────────────────────────

_ADVISORY = {
    "advisoryId": "cisco-sa-iosxe-test-AbCd",
    "advisoryTitle": "Cisco IOS XE Software Test Vulnerability",
    "sir": "High",
    "cvssBaseScore": "8.6",
    "cves": ["CVE-2026-0001"],
    "firstFixed": ["17.12.1"],
    "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-test",
    "firstPublished": "2026-09-24T16:00:00",
    "lastUpdated": "2026-09-25T16:00:00",
    "summary": "<p>A vulnerability in <b>IOS XE</b> could allow&nbsp;an attacker to cause a reload.</p>",
    "productNames": ["Cisco IOS XE Software"],
    "bugIDs": ["CSCxx12345"],
}


class _FakePsirt:
    """Cisco's token and advisory endpoints, with knobs for failure cases."""

    def __init__(self) -> None:
        self.tokens = 0
        self.queries: list[tuple[str, str]] = []
        self.reject_login = False
        self.expire_first_token = False
        self.rate_limit_once = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "id.cisco.com":
            self.tokens += 1
            body = dict(httpx.QueryParams(request.content.decode()))
            if self.reject_login or body.get("client_secret") != "secret":
                return httpx.Response(401, json={"error": "invalid_client", "error_description": "bad secret"})
            assert body["grant_type"] == "client_credentials" and body["client_id"] == "client"
            return httpx.Response(200, json={"access_token": f"tok{self.tokens}", "expires_in": 3599})
        assert request.url.host == "apix.cisco.com"
        if self.expire_first_token and request.headers["Authorization"] == "Bearer tok1":
            return httpx.Response(401, json={"errorCode": "UNAUTHORIZED"})
        if self.rate_limit_once:
            self.rate_limit_once = False
            return httpx.Response(429, headers={"Retry-After": "0"})
        os_type = request.url.path.rsplit("/", 1)[-1]
        version = request.url.params.get("version", "")
        self.queries.append((os_type, version))
        if version == "17.9.4a":
            return httpx.Response(200, json={"advisories": [_ADVISORY]})
        return httpx.Response(404, json={"errorCode": "NOT_FOUND", "errorMessage": "No data found"})


def _psirt(fake: _FakePsirt, **kwargs) -> PsirtClient:
    kwargs.setdefault("requests_per_second", 1000)
    return PsirtClient("client", kwargs.pop("secret", "secret"), transport=httpx.MockTransport(fake.handler), **kwargs)


@pytest.mark.asyncio
async def test_psirt_client_logs_in_once_and_normalises_advisories():
    fake = _FakePsirt()
    async with _psirt(fake) as client:
        found = await client.advisories_by_version("iosxe", "17.9.4a")
        assert await client.advisories_by_version("iosxe", "17.12.1") == []
    assert fake.tokens == 1 and fake.queries == [("iosxe", "17.9.4a"), ("iosxe", "17.12.1")]
    assert len(found) == 1
    advisory = found[0]
    assert advisory["advisory_id"] == "cisco-sa-iosxe-test-AbCd"
    assert advisory["severity"] == "high" and advisory["cvss"] == 8.6
    assert advisory["cves"] == ["CVE-2026-0001"] and advisory["fixed_versions"] == ["17.12.1"]
    assert advisory["summary"] == "A vulnerability in IOS XE could allow an attacker to cause a reload."
    assert advisory["url"].startswith("https://sec.cloudapps.cisco.com/")


def test_normalize_advisory_tolerates_missing_fields():
    assert normalize_advisory({}) is None
    advisory = normalize_advisory({"advisoryId": "x", "cvssBaseScore": "NA", "sir": "Informational"})
    assert advisory == {
        "advisory_id": "x",
        "title": "x",
        "severity": "info",
        "cvss": None,
        "cves": [],
        "fixed_versions": [],
        "url": "",
        "published": "",
        "updated": "",
        "summary": "",
        "product_names": [],
        "bug_ids": [],
    }


@pytest.mark.asyncio
async def test_psirt_client_refuses_bad_credentials_and_unknown_os_types():
    fake = _FakePsirt()
    async with _psirt(fake, secret="wrong") as client:
        with pytest.raises(PsirtApiError) as excinfo:
            await client.authenticate()
        assert excinfo.value.status_code == 401 and excinfo.value.detail == "bad secret"
    async with _psirt(fake) as client:
        with pytest.raises(PsirtApiError):
            await client.advisories_by_version("meraki", "18.107.2")
    assert "iosxe" in OS_TYPES and "ftd" in OS_TYPES


@pytest.mark.asyncio
async def test_psirt_client_renews_an_expired_token_and_retries_a_rate_limit(monkeypatch):
    import netcontrol.integrations.software.psirt as psirt_module

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(psirt_module.asyncio, "sleep", _no_sleep)
    fake = _FakePsirt()
    fake.expire_first_token = True
    fake.rate_limit_once = True
    async with _psirt(fake) as client:
        found = await client.advisories_by_version("iosxe", "17.9.4a")
    assert len(found) == 1
    assert fake.tokens == 2 and client.stats["rate_limited"] == 1 and client.stats["logins"] == 2


# ── HTTP API ─────────────────────────────────────────────────────────────────


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._headers = client, {"X-CSRF-Token": csrf}

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        return self._c.post(url, headers=self._headers, **kw)

    def put(self, url, **kw):
        return self._c.put(url, headers=self._headers, **kw)

    def delete(self, url, **kw):
        return self._c.delete(url, headers=self._headers, **kw)


@pytest.fixture
def api(tmp_path, monkeypatch, request):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "software.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-software")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    monkeypatch.setattr(software_routes, "_psirt_running", False)
    import netcontrol.routes.meraki_topology as routes_module

    routes_module._SNAPSHOT_CACHE.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def _seed_hosts():
    async def _seed():
        db = await db_module.get_db()
        try:
            await db.execute("INSERT INTO inventory_groups (id, name) VALUES (907, 'Core')")
            await db.execute(
                "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, model, software_version, "
                "serial_number) VALUES (9001, 907, 'core-1', '10.9.0.1', 'cisco_ios', 'C9300-48T', "
                "'Version 17.9.4a, RELEASE SOFTWARE', 'FOC1')"
            )
            await db.execute(
                "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, model, software_version) "
                "VALUES (9002, 907, 'edge-1', '10.9.0.2', 'cisco_ios', 'C3750E', '15.2(4)E10')"
            )
            await db.execute(
                "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type, model, software_version) "
                "VALUES (9003, 907, 'no-version', '10.9.0.3', 'cisco_ios', '', '')"
            )
            await db.commit()
        finally:
            await db.close()

    asyncio.run(_seed())


def _set_version(host_id: int, version: str) -> None:
    async def _update():
        db = await db_module.get_db()
        try:
            await db.execute("UPDATE hosts SET software_version = ? WHERE id = ?", (version, host_id))
            await db.commit()
        finally:
            await db.close()

    asyncio.run(_update())


def _delete_host(host_id: int) -> None:
    async def _delete():
        db = await db_module.get_db()
        try:
            await db.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
            await db.commit()
        finally:
            await db.close()

    asyncio.run(_delete())


def _device(overview: dict, name: str) -> dict:
    return next(d for d in overview["devices"] if d["name"] == name)


def test_api_overview_tracks_inventory_hosts_and_topology_devices(api):
    _seed_hosts()
    assert api.post("/api/meraki/sample?provider=meraki").status_code == 201
    assert api.post("/api/meraki/sample?provider=anyconnect").status_code == 201

    overview = api.get("/api/software/overview").json()
    summary = overview["summary"]
    assert summary["sources"]["inventory"] == 2  # the host without a version is not tracked
    assert summary["sources"]["meraki"] > 0 and summary["sources"]["anyconnect"] == 3
    assert summary["devices"] == sum(summary["sources"].values())
    assert summary["open_alerts"] == 0 and summary["advisories"] == 0 and summary["last_refresh_at"]

    core = _device(overview, "core-1")
    assert core["device_key"] == "host:9001" and core["source"] == "inventory"
    assert core["platform"] == "ios-xe" and core["version"] == "17.9.4a"
    assert core["raw_version"] == "Version 17.9.4a, RELEASE SOFTWARE" and core["site"] == "Core"
    assert core["platform_label"] == "Cisco IOS XE" and core["serial"] == "FOC1"
    assert _device(overview, "edge-1")["platform"] == "ios"

    platforms = {p["platform"]: p for p in overview["platforms"]}
    assert platforms["meraki-mx"]["newest_version"] == "18.2.11"
    assert platforms["ftd"]["device_count"] == 2 and platforms["fmc"]["device_count"] == 1
    assert {p["key"] for p in overview["platform_catalog"]} == set(PLATFORMS)
    mx = next(d for d in overview["devices"] if d["platform"] == "meraki-mx")
    assert mx["device_key"].startswith("meraki:") and mx["raw_version"] == "wired-18-2-11"
    assert mx["org_name"] and mx["site"]

    # Filters narrow the device list; the spread stays fleet-wide.
    filtered = api.get("/api/software/overview?platform=ios-xe&search=core").json()
    assert [d["name"] for d in filtered["devices"]] == ["core-1"]
    assert filtered["summary"]["devices"] == summary["devices"]
    assert len(filtered["platforms"]) == len(overview["platforms"])
    by_source = api.get("/api/software/overview?source=anyconnect").json()
    assert {d["source"] for d in by_source["devices"]} == {"anyconnect"}


def test_api_refresh_records_version_changes_and_history(api):
    _seed_hosts()
    first = api.get("/api/software/overview").json()
    assert _device(first, "core-1")["changed_at"] == "" and first["changes"] == []

    _set_version(9001, "17.12.3")
    time.sleep(1.1)  # history rows are timestamped to the second
    result = api.post("/api/software/refresh").json()
    assert result["devices"] == 2 and result["changed"] == 1 and result["added"] == 0
    assert result["changes"] == [
        {
            "device_key": "host:9001",
            "name": "core-1",
            "platform": "ios-xe",
            "from_version": "17.9.4a",
            "to_version": "17.12.3",
        }
    ]
    overview = api.get("/api/software/overview").json()
    core = _device(overview, "core-1")
    assert core["version"] == "17.12.3" and core["previous_version"] == "17.9.4a" and core["changed_at"]
    assert overview["changes"][0]["name"] == "core-1" and overview["changes"][0]["version"] == "17.12.3"

    history = api.get("/api/software/history?device_key=host:9001").json()["history"]
    assert [(h["version"], bool(h["seen_until"])) for h in history] == [("17.12.3", False), ("17.9.4a", True)]

    # A host that disappears is dropped and its history closed.
    _delete_host(9001)
    result = api.post("/api/software/refresh").json()
    assert result["removed"] == 1 and result["devices"] == 1
    history = api.get("/api/software/history?device_key=host:9001").json()["history"]
    assert all(h["seen_until"] for h in history)


def test_api_advisories_open_acknowledge_and_resolve_alerts(api, monkeypatch):
    _seed_hosts()
    sent: list[dict] = []

    async def _capture(event: dict) -> None:
        sent.append(event)

    monkeypatch.setattr(software_routes.notification_channels, "on_alert_created", _capture)
    api.get("/api/software/overview")

    bad = api.post("/api/software/advisories", json={"advisory_id": "x", "affected_versions": ["<abc"]})
    assert bad.status_code == 400 and "not a version" in bad.json()["error"]["message"]
    assert (
        api.post("/api/software/advisories", json={"advisory_id": "bad id!", "affected_versions": ["1"]}).status_code
        == 400
    )
    assert api.post("/api/software/advisories", json={"advisory_id": "x", "affected_versions": []}).status_code == 400
    assert (
        api.post(
            "/api/software/advisories", json={"advisory_id": "x", "platform": "mars", "affected_versions": ["1"]}
        ).status_code
        == 400
    )

    created = api.post(
        "/api/software/advisories",
        json={
            "advisory_id": "cisco-sa-xe-1",
            "title": "IOS XE web UI",
            "severity": "Critical",
            "cvss": 10,
            "platform": "ios-xe",
            "affected_versions": ["<17.12.1"],
            "fixed_versions": ["17.12.1"],
            "cves": ["cve-2026-0001"],
            "url": "https://example.com/sa",
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["advisory"]["severity"] == "critical" and body["advisory"]["cves"] == ["CVE-2026-0001"]
    assert body["alerts"] == {"open": 1, "new": 1, "reopened": 0, "resolved": 0, "notified": 1}
    assert (
        api.post(
            "/api/software/advisories", json={"advisory_id": "cisco-sa-xe-1", "affected_versions": ["1"]}
        ).status_code
        == 409
    )

    # The notification carries the device, version, advisory and fix.
    assert len(sent) == 1
    event = sent[0]
    assert event["alert_type"] == "software_vulnerability" and event["severity"] == "critical"
    assert event["hostname"] == "core-1" and event["host_id"] == 9001 and event["value"] == 10
    assert "core-1 (C9300-48T) runs Cisco IOS XE 17.9.4a, affected by cisco-sa-xe-1" in event["message"]
    assert "fixed in 17.12.1" in event["message"]
    assert event["dedup_key"] == "software:host:9001:cisco-sa-xe-1"

    overview = api.get("/api/software/overview").json()
    assert overview["summary"]["open_alerts"] == 1 and overview["summary"]["critical_alerts"] == 1
    assert overview["summary"]["unacknowledged_alerts"] == 1
    alert = overview["alerts"][0]
    assert alert["device_name"] == "core-1" and alert["advisory_id"] == "cisco-sa-xe-1"
    assert alert["title"] == "IOS XE web UI" and alert["fixed_versions"] == ["17.12.1"] and not alert["acknowledged"]
    core = _device(overview, "core-1")
    assert core["alert_count"] == 1 and core["worst_severity"] == "critical" and core["unacknowledged_alerts"] == 1
    assert _device(overview, "edge-1")["alert_count"] == 0

    # A medium advisory on classic IOS is opened but, below the floor, not notified.
    api.post(
        "/api/software/advisories",
        json={
            "advisory_id": "cisco-sa-ios-1",
            "severity": "medium",
            "platform": "ios",
            "affected_versions": ["15.2(4)E10"],
        },
    )
    assert len(sent) == 1
    alerts = api.get("/api/software/alerts").json()["alerts"]
    assert [(a["advisory_id"], a["severity"]) for a in alerts] == [
        ("cisco-sa-xe-1", "critical"),
        ("cisco-sa-ios-1", "medium"),
    ]

    assert api.post(f"/api/software/alerts/{alert['id']}/acknowledge").status_code == 200
    assert api.post("/api/software/alerts/999999/acknowledge").status_code == 404
    acked = next(a for a in api.get("/api/software/alerts").json()["alerts"] if a["id"] == alert["id"])
    assert acked["acknowledged"] and acked["acknowledged_by"] == "admin"

    # Upgrading the host resolves the alert; downgrading reopens it unacknowledged.
    _set_version(9001, "17.12.1")
    result = api.post("/api/software/refresh").json()
    assert result["alerts"]["resolved"] == 1 and result["alerts"]["open"] == 1
    assert api.get("/api/software/alerts").json()["alerts"][0]["advisory_id"] == "cisco-sa-ios-1"
    resolved = api.get("/api/software/alerts?include_resolved=true").json()["alerts"]
    assert any(a["id"] == alert["id"] and a["resolved"] for a in resolved)
    _set_version(9001, "17.9.4a")
    result = api.post("/api/software/refresh").json()
    assert result["alerts"]["reopened"] == 1 and len(sent) == 2
    reopened = next(a for a in api.get("/api/software/alerts").json()["alerts"] if a["id"] == alert["id"])
    assert not reopened["acknowledged"] and not reopened["resolved"]

    # Editing: disabling the advisory resolves its alert; deleting removes it.
    edited = api.put(
        "/api/software/advisories/cisco-sa-xe-1",
        json={
            "advisory_id": "cisco-sa-xe-1",
            "platform": "ios-xe",
            "affected_versions": ["<17.12.1"],
            "enabled": False,
        },
    )
    assert edited.status_code == 200 and edited.json()["alerts"]["resolved"] == 1
    assert (
        api.put(
            "/api/software/advisories/missing", json={"advisory_id": "missing", "affected_versions": ["1"]}
        ).status_code
        == 404
    )
    assert api.delete("/api/software/advisories/cisco-sa-ios-1").status_code == 200
    assert api.delete("/api/software/advisories/cisco-sa-ios-1").status_code == 404
    remaining = api.get("/api/software/alerts?include_resolved=true").json()["alerts"]
    assert {a["advisory_id"] for a in remaining} == {"cisco-sa-xe-1"}
    assert api.get("/api/software/overview").json()["summary"]["open_alerts"] == 0


def test_api_import_replaces_advisories_by_id(api):
    _seed_hosts()
    api.get("/api/software/overview")
    assert api.post("/api/software/advisories/import", json={"advisories": []}).status_code == 400
    res = api.post(
        "/api/software/advisories/import",
        json={
            "advisories": [
                {"advisory_id": "imp-1", "severity": "high", "affected_versions": ["17.9.*"], "title": "first"},
                {"advisory_id": "imp-2", "severity": "low", "affected_versions": ["1.0"]},
            ]
        },
    )
    assert res.status_code == 200 and res.json()["imported"] == 2 and res.json()["alerts"]["open"] == 1
    res = api.post(
        "/api/software/advisories/import",
        json={
            "advisories": [
                {"advisory_id": "imp-1", "severity": "low", "affected_versions": ["99.*"], "title": "second"}
            ]
        },
    )
    assert res.json()["alerts"] == {"open": 0, "new": 0, "reopened": 0, "resolved": 1, "notified": 0}
    advisories = {a["advisory_id"]: a for a in api.get("/api/software/advisories").json()["advisories"]}
    assert advisories["imp-1"]["title"] == "second" and advisories["imp-1"]["source"] == "import"
    assert advisories["imp-1"]["affected_versions"] == ["99.*"] and len(advisories) == 2


def test_api_settings_keep_the_psirt_secret_write_only(api):
    settings = api.get("/api/software/settings").json()["settings"]
    assert settings["refresh_interval_seconds"] == 6 * 3600 and settings["notify_min_severity"] == "high"
    assert settings["has_psirt_secret"] is False and settings["psirt_platforms"] == sorted(
        software_routes._PSIRT_PLATFORMS
    )

    assert api.put("/api/software/settings", json={"refresh_interval_seconds": 10}).status_code == 400
    assert api.put("/api/software/settings", json={"notify_min_severity": "severe"}).status_code == 400
    assert api.post("/api/software/psirt/sync").status_code == 400  # no credentials yet

    updated = api.put(
        "/api/software/settings",
        json={
            "refresh_interval_seconds": 3600,
            "notify_enabled": False,
            "notify_min_severity": "medium",
            "psirt_enabled": True,
            "psirt_client_id": " client ",
            "psirt_client_secret": "s3cr3t-value",
            "psirt_interval_seconds": 7200,
        },
    ).json()["settings"]
    assert updated["psirt_client_id"] == "client" and updated["has_psirt_secret"] is True
    assert updated["notify_enabled"] is False and updated["psirt_interval_seconds"] == 7200
    assert "s3cr3t-value" not in json.dumps(api.get("/api/software/settings").json())
    assert "s3cr3t-value" not in json.dumps(api.get("/api/software/overview").json()["settings"])

    # Omitting the secret keeps it; an empty one clears it.
    assert api.put("/api/software/settings", json={"psirt_client_id": "client2"}).json()["settings"]["has_psirt_secret"]
    assert not api.put("/api/software/settings", json={"psirt_client_secret": ""}).json()["settings"][
        "has_psirt_secret"
    ]


def _wait(api, job_id: str) -> dict:
    for _ in range(100):
        job = api.get(f"/api/software/psirt/jobs/{job_id}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.05)
    raise AssertionError("PSIRT sync did not finish")


def test_api_psirt_sync_stores_advisories_for_the_tracked_versions(api, monkeypatch):
    _seed_hosts()
    assert api.post("/api/meraki/sample?provider=anyconnect").status_code == 201
    api.get("/api/software/overview")
    fake = _FakePsirt()
    monkeypatch.setattr(software_routes, "_PSIRT_TRANSPORT", httpx.MockTransport(fake.handler))
    original = software_routes._psirt_client

    def _fast_client(client_id: str, secret: str) -> PsirtClient:
        client = original(client_id, secret)
        client._min_interval = 0.0
        return client

    monkeypatch.setattr(software_routes, "_psirt_client", _fast_client)

    api.put("/api/software/settings", json={"psirt_client_id": "client", "psirt_client_secret": "wrong"})
    assert api.post("/api/software/psirt/test").status_code == 400
    api.put("/api/software/settings", json={"psirt_client_secret": "secret"})
    assert api.post("/api/software/psirt/test").json()["ok"] is True

    started = api.post("/api/software/psirt/sync")
    assert started.status_code == 202
    job = _wait(api, started.json()["job_id"])
    assert job["status"] == "completed", job
    result = job["result"]
    # One query per distinct (os type, version): IOS XE 17.9.4a, IOS 15.2(4)E10, FTD 7.4.1, FMC 7.4.1.
    assert sorted(fake.queries) == [("fmc", "7.4.1"), ("ftd", "7.4.1"), ("ios", "15.2(4)E10"), ("iosxe", "17.9.4a")]
    assert result["versions_checked"] == 4 and result["advisories"] == 1 and result["errors"] == []
    assert result["alerts"]["open"] == 1 and result["alerts"]["new"] == 1
    assert api.get(f"/api/software/psirt/jobs/{job['job_id']}x").status_code == 404

    advisories = api.get("/api/software/advisories").json()["advisories"]
    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory["advisory_id"] == "cisco-sa-iosxe-test-AbCd" and advisory["source"] == "cisco-psirt"
    assert advisory["platform"] == "ios-xe" and advisory["affected_versions"] == ["17.9.4a"]
    assert advisory["severity"] == "high" and advisory["cvss"] == 8.6 and advisory["fixed_versions"] == ["17.12.1"]

    overview = api.get("/api/software/overview").json()
    assert overview["alerts"][0]["device_name"] == "core-1"
    assert overview["settings"]["psirt_last_sync_status"] == "completed"
    assert "4 version(s) checked, 1 advisory match(es)" == overview["settings"]["psirt_last_sync_message"]

    # A second sync for a version Cisco already answered keeps one advisory and one alert.
    job = _wait(api, api.post("/api/software/psirt/sync").json()["job_id"])
    assert job["status"] == "completed" and job["result"]["alerts"]["new"] == 0
    assert len(api.get("/api/software/advisories").json()["advisories"]) == 1

    # Bad credentials: the sync fails and says so.
    api.put("/api/software/settings", json={"psirt_client_secret": "wrong"})
    job = _wait(api, api.post("/api/software/psirt/sync").json()["job_id"])
    assert job["status"] == "failed" and "rejected the client ID or secret" in job["error"]
    assert api.get("/api/software/settings").json()["settings"]["psirt_last_sync_status"] == "failed"


def test_api_requires_the_software_feature(tmp_path, monkeypatch, request):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "software-perm.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-software")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    assert client.get("/api/software/overview").status_code == 401
    assert "software" in app_module.FEATURE_FLAGS and "software.write" in app_module.FEATURE_FLAGS
