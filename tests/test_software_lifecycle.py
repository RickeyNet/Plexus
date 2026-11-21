"""Tests for the software end of life per release series.

Covers, with no network access:
  * series     - the series of a version per platform (OPNsense community
                 and business edition, the prefix rule of entries)
  * estimate   - the OPNsense estimate by release cadence, year rollover
  * status     - entry over estimate, the firewall's own report, the
                 warning window at its boundaries, unknown
  * advisories - the generated ``lifecycle`` advisories: created with an
                 alert, an administrator's severity kept, withdrawn after an
                 upgrade, nothing for a platform without entries
  * HTTP API   - the entries (CRUD, import, validation, permissions), the
                 overview's status per device and summary, the setting
"""

from __future__ import annotations

import asyncio
from datetime import date, timedelta

import netcontrol.routes.software_eol as eol_routes
import pytest
import routes.database as db_module
from netcontrol.integrations.software.lifecycle import (
    DEFAULT_WARN_DAYS,
    evaluate,
    fleet_statuses,
    lifecycle_advisories,
    lifecycle_advisory_id,
    opnsense_estimate,
    opnsense_successor,
    series_evidence,
    series_matches,
    series_of,
    status_counts,
    status_text,
    warn_days_setting,
)
from netcontrol.integrations.software.versions import find_advisory_matches

from mcp_helpers import user_client
from test_software import _device, _seed_hosts, _set_version, api  # noqa: F401 - the fixture is used by name

TODAY = date(2026, 11, 21)
ENTRIES = "/api/software/eol-entries"


def _entry(platform: str, series: str, eol: str, **fields) -> dict:
    return {"platform": platform, "series": series, "eol_date": eol, "enabled": True, **fields}


# ── series ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("version", "series"),
    [
        ("25.1.4_1", "25.1"),
        ("25.7.6", "25.7"),
        ("24.10.2", "24.10"),  # business edition
        ("26.4", "26.4"),
        ("26.1.r1", "26.1"),
        ("OPNsense 25.7.6-amd64", "25.7"),
        ("251.4", ""),
        ("", ""),
    ],
)
def test_opnsense_series_of_a_version(version, series):
    assert series_of("opnsense", version) == series


def test_other_platforms_take_the_longest_entry_on_a_component_boundary():
    entries = [_entry("ios-xe", "17.9", "2027-01-01"), _entry("ios-xe", "17", "2030-01-01")]
    assert series_of("ios-xe", "17.9.4a", entries) == "17.9"
    assert series_of("ios-xe", "17.90.1", entries) == "17"
    assert series_of("ios-xe", "17.90.1", entries[:1]) == ""
    assert series_of("ios-xe", "16.12.5", entries) == ""
    assert series_of("nx-os", "17.9.4a", entries) == ""  # another platform's entries
    assert series_of("ios-xe", "17.9.4a", [{**entries[0], "enabled": False}]) == ""
    assert series_of("ios", "15.2(7)E8", [_entry("ios", "15.2(7)", "2026-01-01")]) == "15.2(7)"
    assert series_matches("17.9.4a", "17.9") and not series_matches("17.90.1", "17.9")
    assert not series_matches("17.9.4a", "")


# ── estimate ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("series", "successor", "estimate"),
    [
        ("25.1", "25.7", "2025-07-31"),  # January series: ends when the July one is out
        ("25.7", "26.1", "2026-01-31"),  # July series: the year rolls over
        ("24.4", "24.10", "2024-10-31"),  # business edition
        ("24.10", "25.4", "2025-04-30"),
        ("99.7", "100.1", "2100-01-31"),
        ("25.3", "", ""),
        ("", "", ""),
    ],
)
def test_opnsense_estimate_follows_the_release_cadence(series, successor, estimate):
    assert opnsense_successor(series) == successor
    assert opnsense_estimate(series) == estimate


# ── status ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("days", "status"),
    [(-1, "end_of_life"), (0, "end_of_life"), (1, "ending"), (60, "ending"), (61, "supported")],
)
def test_entry_status_at_the_window_boundaries(days, status):
    eol = (TODAY + timedelta(days=days)).isoformat()
    result = evaluate("ios-xe", "17.9.4a", TODAY, [_entry("ios-xe", "17.9", eol, url="https://example.com/eol")])
    assert result["status"] == status and result["days"] == days and result["date"] == eol
    assert result["source"] == "entry" and result["estimate"] is False and result["series"] == "17.9"
    assert result["url"] == "https://example.com/eol" and "Administrator entry" in result["basis"]


def test_the_window_is_a_parameter():
    eol = (TODAY + timedelta(days=90)).isoformat()
    entries = [_entry("ios-xe", "17.9", eol)]
    assert evaluate("ios-xe", "17.9.4a", TODAY, entries)["status"] == "supported"
    assert evaluate("ios-xe", "17.9.4a", TODAY, entries, warn_days=90)["status"] == "ending"


def test_opnsense_estimate_status():
    supported = evaluate("opnsense", "25.7.6", date(2025, 12, 1))
    assert supported["status"] == "supported" and supported["days"] == 61 and supported["date"] == "2026-01-31"
    assert supported["source"] == "estimate" and supported["estimate"] is True and supported["successor"] == "26.1"
    assert "January 2026" in supported["basis"]
    assert evaluate("opnsense", "25.7.6", date(2025, 12, 2))["status"] == "ending"
    ended = evaluate("opnsense", "25.7.6", TODAY)
    assert ended["status"] == "end_of_life" and ended["days"] < 0
    business = evaluate("opnsense", "24.10.2", date(2025, 3, 1))
    assert business["date"] == "2025-04-30" and business["status"] == "ending"


def test_an_entry_overrides_the_opnsense_estimate_and_the_report():
    entries = [_entry("opnsense", "25.7", "2027-03-01", url="https://example.com/opnsense")]
    result = evaluate("opnsense", "25.7.6", TODAY, entries, reported="26.1")
    assert result["source"] == "entry" and result["date"] == "2027-03-01" and result["status"] == "supported"
    disabled = evaluate("opnsense", "25.7.6", TODAY, [{**entries[0], "enabled": False}])
    assert disabled["source"] == "estimate"


def test_the_firewalls_report_of_a_newer_major_release_ends_the_series_early():
    before = date(2025, 6, 1)  # the estimate for 25.1 is 2025-07-31
    reported = evaluate("opnsense", "25.1.4_1", before, reported="25.7")
    assert reported["status"] == "end_of_life" and reported["source"] == "reported"
    assert reported["successor"] == "25.7" and "reports major release 25.7" in reported["basis"]
    # The date stays the estimate (still ahead); the basis says why it ended.
    assert reported["date"] == "2025-07-31" and reported["days"] > 0 and reported["estimate"] is False
    # The same series or an older one is no evidence.
    assert evaluate("opnsense", "25.1.4_1", before, reported="25.1.5")["source"] == "estimate"
    assert evaluate("opnsense", "25.1.4_1", before, reported="24.7")["source"] == "estimate"


def test_the_newest_series_is_not_end_of_life_before_its_successor_ships():
    # 26.1 shipped on 2026-01-28: 25.7 was still the newest series on the 5th.
    early = evaluate("opnsense", "25.7.6", date(2026, 1, 5))
    assert early["status"] == "ending" and early["source"] == "estimate" and early["date"] == "2026-01-31"
    # The firewall offers 26.1 on its release day: end of life at once.
    shipped = evaluate("opnsense", "25.7.6", date(2026, 1, 28), reported="26.1")
    assert shipped["status"] == "end_of_life" and shipped["source"] == "reported"
    assert status_text(shipped).startswith("End of life: The firewall reports major release 26.1")
    # Without a report, the estimate ends it after the successor's month.
    late = evaluate("opnsense", "25.7.6", date(2026, 2, 1))
    assert late["status"] == "end_of_life" and late["source"] == "estimate" and late["days"] == -1


def test_unknown_without_entry_or_rule():
    result = evaluate("ios-xe", "17.9.4a", TODAY, [])
    assert result["status"] == "unknown" and result["series"] == "" and result["date"] is None
    assert evaluate("opnsense", "25.3.1", TODAY)["status"] == "unknown"
    assert evaluate("opnsense", "", TODAY)["status"] == "unknown"


def test_status_text_names_the_status_date_and_source():
    entry = [_entry("ios-xe", "17.9", "2026-12-01")]
    assert (
        status_text(evaluate("ios-xe", "17.9.4a", TODAY, entry))
        == "Ends on 2026-12-01, in 10 days (administrator entry)"
    )
    assert status_text(evaluate("opnsense", "25.7.6", TODAY)) == "End of life since 2026-01-31 (estimate)"
    assert status_text(evaluate("opnsense", "26.7.1", date(2026, 8, 1))) == "Supported until 2027-01-31 (estimate)"
    reported = status_text(evaluate("opnsense", "26.7.1", TODAY, reported="27.1"))
    assert reported.startswith("End of life: The firewall reports major release 27.1") and not reported.endswith(".")
    assert status_text(evaluate("ios-xe", "17.9.4a", TODAY)).startswith("Unknown: ")


def test_warn_days_setting_falls_back_to_the_default():
    assert warn_days_setting(None) == DEFAULT_WARN_DAYS == 60
    assert warn_days_setting("30") == 30
    assert warn_days_setting("0") == 60 and warn_days_setting("99999") == 60 and warn_days_setting("x") == 60


def test_one_firewalls_report_counts_for_its_whole_series():
    devices = [
        {"device_key": "a", "platform": "opnsense", "version": "26.7.1", "major_upgrade": "27.1"},
        {"device_key": "b", "platform": "opnsense", "version": "26.7.2", "major_upgrade": ""},
        {"device_key": "c", "platform": "opnsense", "version": "26.1.9", "major_upgrade": ""},
        {"device_key": "d", "platform": "ios-xe", "version": "17.9.4a", "major_upgrade": "18.1"},
    ]
    assert series_evidence(devices) == {("opnsense", "26.7"): "27.1"}
    statuses = fleet_statuses(devices, [], TODAY)
    assert statuses["a"]["source"] == statuses["b"]["source"] == "reported"
    assert statuses["c"]["status"] == "end_of_life" and statuses["c"]["source"] == "estimate"
    assert statuses["d"]["status"] == "unknown"
    assert status_counts(list(statuses.values())) == {"supported": 0, "ending": 0, "end_of_life": 3, "unknown": 1}


# ── generated advisories ─────────────────────────────────────────────────────


def test_lifecycle_advisories_cover_ending_and_ended_series_only():
    devices = [
        {"device_key": "fw1", "platform": "opnsense", "version": "25.7.6"},
        {"device_key": "fw2", "platform": "opnsense", "version": "26.7.1"},
        {"device_key": "sw1", "platform": "ios-xe", "version": "17.9.4a"},
        {"device_key": "sw2", "platform": "ios-xe", "version": "17.12.1"},
        {"device_key": "r1", "platform": "junos", "version": "21.4R3"},
    ]
    entries = [
        _entry("ios-xe", "17.9", "2026-11-15", url="https://example.com/xe"),
        _entry("ios-xe", "17.12", "2029-01-01"),
    ]
    # 26.7 is four months from its estimated end of life: still supported.
    found = {a["advisory_id"]: a for a in lifecycle_advisories(devices, entries, date(2026, 10, 1))}
    assert set(found) == {"lifecycle:opnsense:25.7", "lifecycle:ios-xe:17.9"}
    ended, ending = found["lifecycle:opnsense:25.7"], found["lifecycle:ios-xe:17.9"]
    assert ended["title"] == "OPNsense 25.7 is end of life" and ended["severity"] == "high"
    assert ended["affected_versions"] == ["25.7.*"] and ended["fixed_versions"] == ["26.1"]
    assert ended["source"] == "lifecycle" and ended["cves"] == [] and ended["status"] == "end_of_life"
    assert "No more security fixes" in ended["summary"] and ended["url"].startswith("https://docs.opnsense.org/")
    assert ending["title"] == "Cisco IOS XE 17.9 reaches end of life on 2026-11-15" and ending["severity"] == "low"
    assert ending["url"] == "https://example.com/xe" and ending["published"] == "2026-11-15"
    # The tracker's own matcher alerts the devices of the series only.
    matches = find_advisory_matches(
        [{**d, "model": ""} for d in devices], [{**a, "enabled": True} for a in found.values()]
    )
    assert sorted((m["device_key"], m["advisory_id"]) for m in matches) == [
        ("fw1", "lifecycle:opnsense:25.7"),
        ("sw1", "lifecycle:ios-xe:17.9"),
    ]
    # An estimate is marked as such in the title of an ending series.
    soon = lifecycle_advisories(devices[1:2], [], date(2026, 12, 2))
    assert soon[0]["title"] == "OPNsense 26.7 reaches end of life on 2027-01-31 (estimate)"
    assert lifecycle_advisory_id("ios", "15.2(7)") == "lifecycle:ios:15.2-7-"


# ── HTTP API ─────────────────────────────────────────────────────────────────


@pytest.fixture
def today(monkeypatch):
    monkeypatch.setattr(eol_routes, "_today", lambda: TODAY)
    return TODAY


def _advisory(client, advisory_id: str) -> dict | None:
    return next(
        (a for a in client.get("/api/software/advisories").json()["advisories"] if a["advisory_id"] == advisory_id),
        None,
    )


def _alerts(client, advisory_id: str) -> list[dict]:
    return [a for a in client.get("/api/software/alerts").json()["alerts"] if a["advisory_id"] == advisory_id]


def test_api_entries_crud_validation_and_alerts(api, today):  # noqa: F811
    _seed_hosts()  # core-1 runs IOS XE 17.9.4a
    api.get("/api/software/overview")
    bad = [
        _entry("mars", "1.0", "2027-01-01"),
        _entry("ios-xe", "17.9 x", "2027-01-01"),
        _entry("ios-xe", "17.9", "2027-13-01"),
        _entry("ios-xe", "17.9", ""),
        _entry("ios-xe", "17.9", "2027-01-01", url="ftp://example.com"),
        _entry("ios-xe", "17.9", "2027-01-01", release_date="2027-06-01"),
    ]
    for body in bad:
        assert api.post(ENTRIES, json=body).status_code == 400, body

    created = api.post(ENTRIES, json=_entry("ios-xe", "17.9", "2026-12-21", notes="Vendor notice"))
    assert created.status_code == 201, created.text
    entry = created.json()["entry"]
    assert entry["source"] == "manual" and entry["created_by"] == "admin" and entry["notes"] == "Vendor notice"
    assert created.json()["alerts"]["open"] == 1
    assert api.post(ENTRIES, json=_entry("ios-xe", "17.9", "2027-01-01")).status_code == 409
    listed = api.get(ENTRIES).json()
    assert [e["series"] for e in listed["entries"]] == ["17.9"] and listed["warn_days"] == 60

    advisory = _advisory(api, "lifecycle:ios-xe:17.9")
    assert advisory["severity"] == "low" and advisory["affected_versions"] == ["17.9.*"]
    (alert,) = _alerts(api, "lifecycle:ios-xe:17.9")
    assert alert["device_name"] == "core-1" and alert["severity"] == "low"
    assert api.post(f"/api/software/alerts/{alert['id']}/acknowledge").status_code == 200

    # End of life now: the severity becomes high.
    updated = api.put(f"{ENTRIES}/{entry['id']}", json=_entry("ios-xe", "17.9", "2026-11-01"))
    assert updated.status_code == 200 and updated.json()["entry"]["eol_date"] == "2026-11-01"
    advisory = _advisory(api, "lifecycle:ios-xe:17.9")
    assert advisory["severity"] == "high" and advisory["title"] == "Cisco IOS XE 17.9 is end of life"

    # An administrator's severity and enabled switch survive the next refresh.
    edited = api.put(
        "/api/software/advisories/lifecycle:ios-xe:17.9",
        json={
            **{k: advisory[k] for k in ("advisory_id", "title", "platform", "affected_versions")},
            "severity": "critical",
        },
    )
    assert edited.status_code == 200, edited.text
    api.post("/api/software/refresh")
    assert _advisory(api, "lifecycle:ios-xe:17.9")["severity"] == "critical"
    assert _alerts(api, "lifecycle:ios-xe:17.9")[0]["severity"] == "critical"

    # Upgraded off the series: the alert resolves and the advisory is withdrawn.
    _set_version(9001, "17.12.3")
    result = api.post("/api/software/refresh").json()
    assert result["lifecycle"]["withdrawn"] == 1
    assert _alerts(api, "lifecycle:ios-xe:17.9") == []
    withdrawn = _advisory(api, "lifecycle:ios-xe:17.9")
    assert withdrawn["affected_versions"] == [] and withdrawn["severity"] == "critical"

    other = api.post(ENTRIES, json=_entry("ios-xe", "17.12", "2029-01-01")).json()["entry"]
    assert api.put(f"{ENTRIES}/{other['id']}", json=_entry("ios-xe", "17.9", "2029-01-01")).status_code == 409
    assert api.put(f"{ENTRIES}/424242", json=_entry("ios-xe", "17.6", "2029-01-01")).status_code == 404
    assert api.delete(f"{ENTRIES}/{entry['id']}").status_code == 200
    assert api.delete(f"{ENTRIES}/{entry['id']}").status_code == 404


def test_api_import_creates_or_replaces_by_platform_and_series(api, today):  # noqa: F811
    _seed_hosts()
    api.get("/api/software/overview")
    assert api.post(f"{ENTRIES}/import", json={"entries": []}).status_code == 400
    first = api.post(
        f"{ENTRIES}/import",
        json={"entries": [_entry("ios-xe", "17.9", "2026-11-01"), _entry("ios", "15.2(4)", "2030-01-01")]},
    )
    assert first.status_code == 200 and first.json()["imported"] == 2 and first.json()["alerts"]["open"] == 1
    again = api.post(f"{ENTRIES}/import", json={"entries": [_entry("ios-xe", "17.9", "2027-06-01")]})
    assert again.status_code == 200
    entries = {e["series"]: e for e in api.get(ENTRIES).json()["entries"]}
    assert set(entries) == {"17.9", "15.2(4)"} and entries["17.9"]["eol_date"] == "2027-06-01"
    assert {e["source"] for e in entries.values()} == {"import"}
    assert again.json()["alerts"]["open"] == 0  # supported again: withdrawn


def test_api_entries_need_software_write(api, today):  # noqa: F811
    reader = user_client(api, "eol-reader", features=["software"])
    assert reader.get(ENTRIES).status_code == 200
    assert reader.post(ENTRIES, json=_entry("ios-xe", "17.9", "2027-01-01")).status_code == 403
    writer = user_client(api, "eol-writer", features=["software", "software.write"])
    created = writer.post(ENTRIES, json=_entry("ios-xe", "17.9", "2027-01-01"))
    assert created.status_code == 201, created.text
    assert created.json()["entry"]["created_by"] == "eol-writer"
    assert reader.delete(f"{ENTRIES}/{created.json()['entry']['id']}").status_code == 403
    nobody = user_client(api, "eol-nobody")
    assert nobody.get(ENTRIES).status_code == 403


def test_api_overview_carries_the_status_per_device(api, today):  # noqa: F811
    _seed_hosts()
    assert api.post("/api/sources/sample?provider=opnsense").status_code == 201
    overview = api.get("/api/software/overview").json()
    firewall = next(d for d in overview["devices"] if d["platform"] == "opnsense")
    status = firewall["lifecycle"]
    assert status["series"] == "25.7" and status["status"] == "end_of_life"
    assert status["source"] == "estimate" and status["date"] == "2026-01-31" and status["estimate"] is True
    assert _device(overview, "core-1")["lifecycle"]["status"] == "unknown"
    assert overview["summary"]["lifecycle"] == {"supported": 0, "ending": 0, "end_of_life": 1, "unknown": 2}

    # The end-of-life series raises an alert for the firewall with no page opened.
    (alert,) = _alerts(api, "lifecycle:opnsense:25.7")
    assert alert["severity"] == "high" and alert["device_key"] == firewall["device_key"]
    # Only OPNsense has a built-in rule: no advisory for the Cisco hosts.
    advisories = [a for a in api.get("/api/software/advisories").json()["advisories"] if a["source"] == "lifecycle"]
    assert [a["advisory_id"] for a in advisories] == ["lifecycle:opnsense:25.7"]

    # An administrator's entry for the series wins over the estimate.
    created = api.post(ENTRIES, json=_entry("opnsense", "25.7", "2027-06-30"))
    assert created.status_code == 201 and created.json()["alerts"]["open"] == 0
    status = next(d for d in api.get("/api/software/overview").json()["devices"] if d["platform"] == "opnsense")[
        "lifecycle"
    ]
    assert status["source"] == "entry" and status["status"] == "supported" and status["date"] == "2027-06-30"


def test_api_setting_widens_the_warning_window(api, today):  # noqa: F811
    _seed_hosts()
    api.get("/api/software/overview")
    api.post(ENTRIES, json=_entry("ios-xe", "17.9", (TODAY + timedelta(days=90)).isoformat()))
    assert _device(api.get("/api/software/overview").json(), "core-1")["lifecycle"]["status"] == "supported"
    assert api.put("/api/software/settings", json={"eol_warn_days": 0}).status_code == 400
    saved = api.put("/api/software/settings", json={"eol_warn_days": 120})
    assert saved.status_code == 200 and saved.json()["settings"]["eol_warn_days"] == 120
    assert _device(api.get("/api/software/overview").json(), "core-1")["lifecycle"]["status"] == "ending"
    assert len(_alerts(api, "lifecycle:ios-xe:17.9")) == 1


def test_sync_creates_nothing_without_devices_on_the_series(api, today):  # noqa: F811
    api.post(ENTRIES, json=_entry("junos", "21.4", "2020-01-01"))

    async def _lifecycle_advisories() -> list[dict]:
        return [a for a in await db_module.list_software_advisories() if a["source"] == "lifecycle"]

    assert asyncio.run(_lifecycle_advisories()) == []
