"""Tests for the NVD and CISA KEV enrichment of software advisories.

Covers, with no network access (samples shaped like the NVD CVE API 2.0
answers and the CISA KEV catalogue schema):
  * parsing   - CVSS 4.0 / 3.1 / 2.0 metrics, Primary before Secondary, no
                metrics yet, an unknown CVE, the KEV catalogue
  * client    - the apiKey header, HTTP 403 / 429 / 5xx / timeouts and
                retries, the KEV download
  * rules     - the severity bands, the KEV floor, a vendor's and an
                administrator's severity kept, the cache refresh rule
  * run       - advisories of every source enriched, open alerts following,
                the cache reused, the per-run cap, failures recorded and
                nothing lost, re-notification when an advisory becomes
                known exploited
  * settings  - off by default, the write-only API key, mirror URLs through
                the outbound address guard, the run-now job
  * OPNsense  - an audit advisory enriched, the audit synced again, the
                enriched values and an administrator's severity kept
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta

import httpx
import netcontrol.routes.software as software_routes
import netcontrol.routes.software_cve as software_cve
import pytest
import routes.database as db
from netcontrol.integrations.opnsense.normalize import build_snapshot
from netcontrol.integrations.opnsense.sample import build_sample_raw
from netcontrol.integrations.software import cve_enrichment
from netcontrol.integrations.software.cve_enrichment import (
    KEV_URL,
    NVD_API_URL,
    CveFeedError,
    NvdClient,
    advisory_enrichment,
    cve_ids,
    fetch_kev_catalog,
    lookup_due,
    lookup_order,
    parse_kev_catalog,
    parse_nvd_cve,
    severity_for_score,
    validate_feed_url,
)

from test_software import _seed_hosts, api as _software_api

# The software tests' logged-in API client, used by name.
api = _software_api

# ── Samples ──────────────────────────────────────────────────────────────────


def _metric(version: str, score: float, severity: str, *, kind: str = "Primary", source: str = "nvd@nist.gov"):
    vector = {
        "4.0": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "3.1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "3.0": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "2.0": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
    }[version]
    data = {"version": version, "vectorString": vector, "baseScore": score}
    metric = {"source": source, "type": kind, "cvssData": data}
    if version == "2.0":
        # CVSS 2.0 carries the severity on the metric, not in cvssData.
        metric.update(baseSeverity=severity, exploitabilityScore=8.6, impactScore=10.0)
    else:
        data["baseSeverity"] = severity
    if version in ("3.0", "3.1"):
        metric.update(exploitabilityScore=3.9, impactScore=6.0)
    return metric


def _nvd_answer(cve_id: str, metrics: dict | None, status: str = "Analyzed") -> dict:
    cve = {
        "id": cve_id,
        "sourceIdentifier": "cve@mitre.org",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2025-02-04T15:15:10.163",
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": "Sample description."}],
        "references": [],
    }
    if metrics is not None:
        cve["metrics"] = metrics
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-11-21T08:00:00.000",
        "vulnerabilities": [{"cve": cve}],
    }


NOT_FOUND = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2026-11-21T08:00:00.000",
    "vulnerabilities": [],
}

# Public CVEs: Log4Shell (3.1 and 2.0), PAN-OS GlobalProtect (4.0 from the
# CNA and 3.1), Heartbleed (2.0 only in this sample), and one NVD has not
# analysed yet.
NVD_SAMPLES = {
    "CVE-2021-44228": _nvd_answer(
        "CVE-2021-44228",
        {
            "cvssMetricV31": [_metric("3.1", 10.0, "CRITICAL")],
            "cvssMetricV2": [_metric("2.0", 9.3, "HIGH")],
        },
    ),
    "CVE-2024-3400": _nvd_answer(
        "CVE-2024-3400",
        {
            "cvssMetricV40": [_metric("4.0", 10.0, "CRITICAL", kind="Secondary", source="psirt@paloaltonetworks.com")],
            "cvssMetricV31": [
                _metric("3.1", 10.0, "CRITICAL", kind="Secondary", source="psirt@paloaltonetworks.com"),
                _metric("3.1", 9.8, "CRITICAL"),
            ],
        },
    ),
    "CVE-2014-0160": _nvd_answer("CVE-2014-0160", {"cvssMetricV2": [_metric("2.0", 5.0, "MEDIUM")]}),
    "CVE-2026-0001": _nvd_answer("CVE-2026-0001", {"cvssMetricV31": [_metric("3.1", 9.8, "CRITICAL")]}),
    "CVE-2026-0002": _nvd_answer("CVE-2026-0002", {}, status="Awaiting Analysis"),
    "CVE-2023-20198": _nvd_answer("CVE-2023-20198", {"cvssMetricV31": [_metric("3.1", 10.0, "CRITICAL")]}),
}


def _kev_entry(cve_id: str, added: str, due: str, ransomware: str = "Unknown") -> dict:
    return {
        "cveID": cve_id,
        "vendorProject": "Example vendor",
        "product": "Example product",
        "vulnerabilityName": "Example vulnerability",
        "dateAdded": added,
        "shortDescription": "Sample description.",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "dueDate": due,
        "knownRansomwareCampaignUse": ransomware,
        "notes": "https://example.com/advisory",
        "cwes": ["CWE-77"],
    }


def _kev_catalog(*entries: dict) -> dict:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.11.20",
        "dateReleased": "2026-11-20T17:00:00.0000Z",
        "count": len(entries),
        "vulnerabilities": list(entries),
    }


KEV_PAN = _kev_entry("CVE-2024-3400", "2024-04-12", "2024-04-19")
KEV_IOSXE = _kev_entry("CVE-2023-20198", "2023-10-16", "2023-10-20")
KEV_LOG4J = _kev_entry("CVE-2021-44228", "2021-12-10", "2021-12-24", "Known")
KEV_AUDIT = _kev_entry("CVE-2026-0002", "2026-11-01", "2026-11-22")


class _Feeds:
    """NVD and the KEV host behind one ``httpx.MockTransport``."""

    def __init__(self) -> None:
        self.kev = _kev_catalog(KEV_PAN, KEV_IOSXE)
        self.kev_status = 200
        self.nvd_status: int | None = None
        self.nvd_queries: list[str] = []
        self.api_keys: list[str | None] = []
        self.kev_downloads = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(KEV_URL):
            self.kev_downloads += 1
            if self.kev_status != 200:
                return httpx.Response(self.kev_status, text="unavailable")
            return httpx.Response(200, json=self.kev)
        assert request.url.path == "/rest/json/cves/2.0"
        cve = request.url.params["cveId"]
        self.nvd_queries.append(cve)
        self.api_keys.append(request.headers.get("apiKey"))
        if self.nvd_status is not None:
            return httpx.Response(self.nvd_status, headers={"message": "Request forbidden by administrative rules."})
        return httpx.Response(200, json=NVD_SAMPLES.get(cve, NOT_FOUND))


async def _no_sleep(_seconds: float) -> None:
    return None


@pytest.fixture
def feeds(monkeypatch):
    fake = _Feeds()
    monkeypatch.setattr(software_cve, "_TRANSPORT", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(software_cve, "_REQUESTS_PER_SECOND", 1000.0)
    monkeypatch.setattr(software_cve, "_running", False)
    monkeypatch.setattr(cve_enrichment, "_sleep", _no_sleep)
    return fake


# ── Parsing ──────────────────────────────────────────────────────────────────


def test_parse_nvd_cve_prefers_the_newest_version_and_the_primary_metric():
    log4j = parse_nvd_cve(NVD_SAMPLES["CVE-2021-44228"], "cve-2021-44228")
    assert log4j == {
        "cve_id": "CVE-2021-44228",
        "lookup_state": "scored",
        "nvd_status": "Analyzed",
        "cvss": 10.0,
        "cvss_severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_version": "3.1",
    }
    # 4.0 is the newest version present (a CNA's Secondary metric is used
    # when it is the only one of that version).
    pan = parse_nvd_cve(NVD_SAMPLES["CVE-2024-3400"], "CVE-2024-3400")
    assert pan["cvss_version"] == "4.0" and pan["cvss"] == 10.0 and pan["cvss_vector"].startswith("CVSS:4.0/")
    # Within one version, NVD's Primary metric wins over the CNA's Secondary.
    only_31 = {"cvssMetricV31": NVD_SAMPLES["CVE-2024-3400"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]}
    assert parse_nvd_cve(_nvd_answer("CVE-2024-3400", only_31), "CVE-2024-3400")["cvss"] == 9.8
    # CVSS 2.0 only: the severity sits on the metric.
    heartbleed = parse_nvd_cve(NVD_SAMPLES["CVE-2014-0160"], "CVE-2014-0160")
    assert (heartbleed["cvss"], heartbleed["cvss_severity"], heartbleed["cvss_version"]) == (5.0, "medium", "2.0")


def test_parse_nvd_cve_tells_no_score_yet_from_unknown():
    pending = parse_nvd_cve(NVD_SAMPLES["CVE-2026-0002"], "CVE-2026-0002")
    assert pending["lookup_state"] == "unscored" and pending["nvd_status"] == "Awaiting Analysis"
    assert pending["cvss"] is None
    no_metrics = parse_nvd_cve(_nvd_answer("CVE-2026-0003", None, status="Received"), "CVE-2026-0003")
    assert no_metrics["lookup_state"] == "unscored" and no_metrics["nvd_status"] == "Received"
    assert parse_nvd_cve(NOT_FOUND, "CVE-2026-9999")["lookup_state"] == "not_found"
    # An answer about another CVE is not taken for this one.
    assert parse_nvd_cve(NVD_SAMPLES["CVE-2021-44228"], "CVE-2014-0160")["lookup_state"] == "not_found"
    assert parse_nvd_cve(None, "CVE-2014-0160")["lookup_state"] == "not_found"


def test_parse_kev_catalog_and_cve_ids():
    catalog = parse_kev_catalog(_kev_catalog(KEV_PAN, KEV_LOG4J, {"cveID": "not-a-cve"}, "junk"))
    assert catalog == {
        "CVE-2024-3400": {"date_added": "2024-04-12", "due_date": "2024-04-19", "ransomware": "Unknown"},
        "CVE-2021-44228": {"date_added": "2021-12-10", "due_date": "2021-12-24", "ransomware": "Known"},
    }
    with pytest.raises(ValueError):
        parse_kev_catalog({"title": "something else"})
    assert cve_ids([" cve-2024-3400", "CVE-2024-3400", "CVE-24-1", "", None, "CVE-2021-44228"]) == [
        "CVE-2024-3400",
        "CVE-2021-44228",
    ]


# ── Rules ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("score", "severity"),
    [(10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"), (6.9, "medium"), (4.0, "medium")]
    + [(3.9, "low"), (0.0, "low"), (None, None)],
)
def test_severity_bands(score, severity):
    assert severity_for_score(score) == severity


def _cached(score: float | None, *, kev: bool = False, added: str = "", due: str = "", ransomware: str = "") -> dict:
    return {
        "cvss": score,
        "known_exploited": kev,
        "kev_date_added": added,
        "kev_due_date": due,
        "kev_ransomware": ransomware,
    }


def test_advisory_enrichment_derives_severity_and_applies_the_kev_floor():
    cache = {
        "CVE-2026-0001": _cached(5.3),
        "CVE-2026-0002": _cached(None, kev=True, added="2026-11-01", due="2026-11-22"),
        "CVE-2026-0003": _cached(9.8, kev=True, added="2026-10-01", due="2026-10-22", ransomware="Known"),
    }
    default = {"severity": "medium", "severity_source": "default", "cvss": None, "cves": ["CVE-2026-0001"]}
    assert advisory_enrichment(default, cache) == {
        "cvss": 5.3,
        "cvss_source": "nvd",
        "severity": "medium",
        "severity_source": "enriched",
        "known_exploited": False,
        "kev_date_added": "",
        "kev_due_date": "",
        "kev_ransomware": "",
    }
    # Known exploited: at least high, with or without a score.
    raised = advisory_enrichment({**default, "cves": ["CVE-2026-0001", "CVE-2026-0002"]}, cache)
    assert raised["severity"] == "high" and raised["cvss"] == 5.3 and raised["known_exploited"]
    assert advisory_enrichment({**default, "cves": ["CVE-2026-0002"]}, cache)["severity"] == "high"
    # The highest score of its CVEs; the earliest KEV dates; ransomware use.
    both = advisory_enrichment({**default, "cves": ["CVE-2026-0002", "CVE-2026-0003"]}, cache)
    assert both["cvss"] == 9.8 and both["severity"] == "critical"
    assert (both["kev_date_added"], both["kev_due_date"], both["kev_ransomware"]) == (
        "2026-10-01",
        "2026-10-22",
        "Known",
    )
    # Nothing known about its CVEs: unchanged.
    unknown = advisory_enrichment({**default, "cves": ["CVE-2026-0009"]}, cache)
    assert (unknown["severity"], unknown["severity_source"], unknown["cvss"]) == ("medium", "default", None)


def test_advisory_enrichment_keeps_a_vendors_and_an_administrators_severity():
    cache = {"CVE-2026-0003": _cached(9.8, kev=True, added="2026-10-01", due="2026-10-22")}
    vendor = {"severity": "medium", "severity_source": "vendor", "cvss": 5.3, "cves": ["CVE-2026-0003"]}
    fields = advisory_enrichment(vendor, cache)
    # The vendor's rating and own score stay; the KEV flag is set.
    assert (fields["severity"], fields["cvss"], fields["cvss_source"]) == ("medium", 5.3, "")
    assert fields["known_exploited"] and fields["kev_date_added"] == "2026-10-01"
    admin = {"severity": "low", "severity_source": "admin", "cvss": None, "cves": ["CVE-2026-0003"]}
    fields = advisory_enrichment(admin, cache)
    # The administrator's severity stays; a missing score is filled.
    assert (fields["severity"], fields["severity_source"], fields["cvss"]) == ("low", "admin", 9.8)
    # A score enrichment filled before is updated; an own one is not.
    refilled = advisory_enrichment({**admin, "cvss": 7.5, "cvss_source": "nvd"}, cache)
    assert refilled["cvss"] == 9.8


def test_lookup_due_refreshes_scores_weekly_and_missing_scores_daily():
    now = datetime(2026, 11, 21, 12, 0, 0)

    def ago(days: float) -> str:
        return (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    assert lookup_due(None, now) and lookup_due({"lookup_state": "pending", "nvd_checked_at": ""}, now)
    assert not lookup_due({"lookup_state": "scored", "nvd_checked_at": ago(6)}, now)
    assert lookup_due({"lookup_state": "scored", "nvd_checked_at": ago(7.1)}, now)
    for state in ("unscored", "not_found"):
        assert not lookup_due({"lookup_state": state, "nvd_checked_at": ago(0.5)}, now)
        assert lookup_due({"lookup_state": state, "nvd_checked_at": ago(1.5)}, now)
    cache = {
        "CVE-2026-0001": {"lookup_state": "scored", "nvd_checked_at": ago(9)},
        "CVE-2026-0002": {"lookup_state": "scored", "nvd_checked_at": ago(30)},
        "CVE-2026-0003": {"lookup_state": "scored", "nvd_checked_at": ago(1)},
    }
    # Never answered first, then the longest unchecked; fresh ones not at all.
    assert lookup_order(["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"], cache, now) == [
        "CVE-2026-0004",
        "CVE-2026-0002",
        "CVE-2026-0001",
    ]


def test_validate_feed_url():
    assert validate_feed_url("  ", "NVD API URL") == ""
    assert (
        validate_feed_url("https://nvd.example.com/rest/json/cves/2.0", "x")
        == "https://nvd.example.com/rest/json/cves/2.0"
    )
    for bad in ("http://nvd.example.com/x", "https://user:pw@nvd.example.com/", "https://nvd.example.com/?a=1"):
        with pytest.raises(ValueError):
            validate_feed_url(bad, "NVD API URL")
    with pytest.raises(ValueError, match="valid URL"):
        validate_feed_url("https://nvd.example.com:99999/", "NVD API URL")


# ── Client ───────────────────────────────────────────────────────────────────


def _nvd(handler, **kwargs) -> NvdClient:
    kwargs.setdefault("requests_per_second", 1000)
    return NvdClient(transport=httpx.MockTransport(handler), **kwargs)


@pytest.mark.asyncio
async def test_nvd_client_sends_the_cve_id_and_the_api_key(monkeypatch):
    feeds = _Feeds()
    async with _nvd(feeds.handler, api_key="k3y-value") as client:
        entry = await client.lookup("cve-2021-44228")
        assert (await client.lookup("CVE-2026-9999"))["lookup_state"] == "not_found"
    assert entry["cvss"] == 10.0 and feeds.nvd_queries == ["CVE-2021-44228", "CVE-2026-9999"]
    assert feeds.api_keys == ["k3y-value", "k3y-value"]
    async with _nvd(feeds.handler) as client:
        await client.lookup("CVE-2014-0160")
    assert feeds.api_keys[-1] is None
    with pytest.raises(CveFeedError):
        await NvdClient().lookup("not-a-cve")
    # Without a key, NVD's public limit: 5 requests per rolling 30 seconds.
    assert NvdClient()._pacer._min_interval == pytest.approx(6.0)
    assert NvdClient(api_key="k")._pacer._min_interval == pytest.approx(0.6)


@pytest.mark.asyncio
async def test_nvd_client_retries_and_reports_refusals(monkeypatch):
    monkeypatch.setattr(cve_enrichment, "_sleep", _no_sleep)
    answers = [httpx.Response(429, headers={"Retry-After": "1"}), httpx.Response(503)]

    def flaky(request: httpx.Request) -> httpx.Response:
        if answers:
            return answers.pop(0)
        return httpx.Response(200, json=NVD_SAMPLES["CVE-2026-0001"])

    async with _nvd(flaky) as client:
        assert (await client.lookup("CVE-2026-0001"))["cvss"] == 9.8
    assert client.stats == {"requests": 3, "retries": 2, "rate_limited": 1}

    def forbidden(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, headers={"message": "Invalid apiKey."})

    async with _nvd(forbidden, max_retries=1) as client:
        with pytest.raises(CveFeedError) as excinfo:
            await client.lookup("CVE-2026-0001")
    assert excinfo.value.rate_limited and excinfo.value.status_code == 403
    assert "Invalid apiKey." in str(excinfo.value)

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    async with _nvd(timeout) as client:
        with pytest.raises(CveFeedError) as excinfo:
            await client.lookup("CVE-2026-0001")
    assert excinfo.value.status_code == 0 and not excinfo.value.rate_limited
    assert client.stats["requests"] == 3  # the first try and two retries

    def bad_request(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"message": "bad"})

    async with _nvd(bad_request) as client:
        with pytest.raises(CveFeedError) as excinfo:
            await client.lookup("CVE-2026-0001")
    assert excinfo.value.status_code == 400 and client.stats["requests"] == 1


@pytest.mark.asyncio
async def test_fetch_kev_catalog():
    feeds = _Feeds()
    transport = httpx.MockTransport(feeds.handler)
    catalog = await fetch_kev_catalog(transport=transport)
    assert set(catalog) == {"CVE-2024-3400", "CVE-2023-20198"}
    feeds.kev_status = 500
    with pytest.raises(CveFeedError, match="HTTP 500"):
        await fetch_kev_catalog(transport=transport)

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    with pytest.raises(CveFeedError, match="unreachable"):
        await fetch_kev_catalog(KEV_URL, transport=httpx.MockTransport(timeout))
    with pytest.raises(CveFeedError, match="not the catalogue"):
        await fetch_kev_catalog(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[])))


# ── Runs through the API ─────────────────────────────────────────────────────


def _wait(api, job_id: str) -> dict:
    for _ in range(400):
        job = api.get(f"/api/software/cve-enrichment/jobs/{job_id}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.05)
    raise AssertionError("CVE enrichment did not finish")


def _run(api) -> dict:
    started = api.post("/api/software/cve-enrichment/run")
    assert started.status_code == 202, started.text
    return _wait(api, started.json()["job_id"])


def _advisories(api) -> dict[str, dict]:
    return {a["advisory_id"]: a for a in api.get("/api/software/advisories").json()["advisories"]}


def _sql(statement: str, params: tuple = ()) -> None:
    async def _go():
        conn = await db.get_db()
        try:
            await conn.execute(statement, params)
            await conn.commit()
        finally:
            await conn.close()

    asyncio.run(_go())


def _seed_advisories(api) -> None:
    # An import without a severity (default), an administrator's low one,
    # and a Cisco PSIRT one with the vendor's rating and score.
    res = api.post(
        "/api/software/advisories/import",
        json={
            "advisories": [
                {"advisory_id": "imp-log4j", "affected_versions": ["17.9.*"], "cves": ["CVE-2021-44228"]},
                {"advisory_id": "imp-unknown", "affected_versions": ["17.9.*"], "cves": ["CVE-2026-9999"]},
            ]
        },
    )
    assert res.status_code == 200, res.text
    created = api.post(
        "/api/software/advisories",
        json={
            "advisory_id": "man-pan",
            "severity": "low",
            "platform": "ios",
            "affected_versions": ["15.2(4)E10"],
            "cves": ["CVE-2024-3400", "CVE-2014-0160"],
        },
    )
    assert created.status_code == 201, created.text

    async def _psirt():
        await db.upsert_software_advisory(
            {
                "advisory_id": "cisco-sa-iosxe-webui",
                "source": "cisco-psirt",
                "severity": "medium",
                "severity_source": "vendor",
                "cvss": 5.3,
                "platform": "ios-xe",
                "affected_versions": ["17.9.4a"],
                "cves": ["CVE-2023-20198"],
            }
        )

    asyncio.run(_psirt())


def test_enrichment_is_off_by_default_and_the_api_key_is_write_only(api, feeds):
    settings = api.get("/api/software/settings").json()["settings"]
    assert settings["cve_enrichment_enabled"] is False and settings["has_nvd_api_key"] is False
    assert settings["nvd_default_url"] == NVD_API_URL and settings["kev_default_url"] == KEV_URL
    assert settings["cve_last_run_at"] == "" and settings["cve_last_run_counts"] == {}
    assert api.post("/api/software/cve-enrichment/run").status_code == 400
    assert not software_cve.scheduled_run_due({**software_cve.SETTING_DEFAULTS})

    saved = api.put(
        "/api/software/settings", json={"cve_enrichment_enabled": True, "nvd_api_key": "nvd-k3y-0001-not-real"}
    )
    assert saved.status_code == 200 and saved.json()["settings"]["has_nvd_api_key"] is True
    for text in (saved.text, api.get("/api/software/settings").text, api.get("/api/software/overview").text):
        assert "nvd-k3y-0001-not-real" not in text

    # Mirrors: https only, through the outbound address guard.
    assert api.put("/api/software/settings", json={"kev_url": "http://kev.example.com/kev.json"}).status_code == 400
    refused = api.put("/api/software/settings", json={"kev_url": "https://169.254.169.254/kev.json"})
    assert refused.status_code == 400 and "outbound address guard" in refused.json()["error"]["message"]
    mirror = api.put("/api/software/settings", json={"kev_url": "https://kev.example.com/kev.json"})
    assert mirror.status_code == 200 and mirror.json()["settings"]["kev_url"] == "https://kev.example.com/kev.json"
    # The stored key is not sent to a new NVD host unless entered again.
    moved = api.put("/api/software/settings", json={"nvd_base_url": "https://nvd.example.com/rest/json/cves/2.0"})
    assert moved.status_code == 400 and "NVD API key" in moved.json()["error"]["message"]
    moved = api.put(
        "/api/software/settings",
        json={"nvd_base_url": "https://nvd.example.com/rest/json/cves/2.0", "nvd_api_key": "other-k3y"},
    )
    assert moved.status_code == 200 and moved.json()["settings"]["nvd_base_url"].startswith("https://nvd.example.com/")
    # Omitted keeps the key, "" clears it.
    assert api.put("/api/software/settings", json={"kev_url": ""}).json()["settings"]["has_nvd_api_key"] is True
    assert api.put("/api/software/settings", json={"nvd_api_key": ""}).json()["settings"]["has_nvd_api_key"] is False


def test_run_enriches_advisories_of_every_source_and_their_alerts(api, feeds, monkeypatch):
    sent: list[dict] = []

    async def _capture(event: dict) -> None:
        sent.append(event)

    monkeypatch.setattr(software_routes.notification_channels, "on_alert_created", _capture)
    _seed_hosts()
    api.get("/api/software/overview")
    _seed_advisories(api)
    api.post("/api/software/refresh")
    before = _advisories(api)
    assert before["imp-log4j"]["severity_source"] == "default" and before["man-pan"]["severity_source"] == "admin"
    assert sent == []  # medium and low: below the notification floor

    api.put("/api/software/settings", json={"cve_enrichment_enabled": True, "nvd_api_key": "nvd-k3y-0001-not-real"})
    job = _run(api)
    assert job["status"] == "completed", job
    counts = job["result"]["counts"]
    assert counts["cves"] == 5 and counts["looked_up"] == 5 and counts["remaining"] == 0
    assert counts["known_exploited"] == 2 and counts["kev_downloaded"] is True
    assert feeds.kev_downloads == 1 and set(feeds.api_keys) == {"nvd-k3y-0001-not-real"}

    advisories = _advisories(api)
    log4j = advisories["imp-log4j"]
    assert (log4j["severity"], log4j["severity_source"], log4j["cvss"], log4j["cvss_source"]) == (
        "critical",
        "enriched",
        10.0,
        "nvd",
    )
    assert log4j["known_exploited"] is False
    # Unknown at NVD: the default stays.
    assert advisories["imp-unknown"]["severity"] == "medium" and advisories["imp-unknown"]["cvss"] is None
    # The administrator's low stays; the score is filled and the KEV flag set.
    pan = advisories["man-pan"]
    assert (pan["severity"], pan["cvss"], pan["known_exploited"]) == ("low", 10.0, True)
    assert (pan["kev_date_added"], pan["kev_due_date"], pan["kev_ransomware"]) == (
        "2024-04-12",
        "2024-04-19",
        "Unknown",
    )
    # Cisco's rating and score stay; the KEV flag is set.
    psirt = advisories["cisco-sa-iosxe-webui"]
    assert (psirt["severity"], psirt["cvss"], psirt["cvss_source"], psirt["known_exploited"]) == (
        "medium",
        5.3,
        "",
        True,
    )

    # Open alerts follow; the first run notifies nothing again.
    alerts = {a["advisory_id"]: a for a in api.get("/api/software/alerts").json()["alerts"]}
    assert alerts["imp-log4j"]["severity"] == "critical" and alerts["imp-log4j"]["cvss"] == 10.0
    assert alerts["man-pan"]["known_exploited"] is True and alerts["man-pan"]["kev_date_added"] == "2024-04-12"
    assert alerts["cisco-sa-iosxe-webui"]["known_exploited"] is True
    assert sent == []
    settings = api.get("/api/software/settings").json()["settings"]
    assert (
        settings["cve_last_run_status"] == "completed" and "5 CVE(s): 5 looked up" in settings["cve_last_run_message"]
    )

    # A second run: the cache is fresh, nothing is asked again. Log4Shell
    # has become known exploited: its open alert is notified once more.
    feeds.kev = _kev_catalog(KEV_PAN, KEV_IOSXE, KEV_LOG4J)
    job = _run(api)
    assert job["status"] == "completed" and job["result"]["counts"]["looked_up"] == 0
    assert len(feeds.nvd_queries) == 5 and feeds.kev_downloads == 2
    assert job["result"]["counts"]["became_known_exploited"] == 1
    assert len(sent) == 1 and "known exploited (CISA KEV, added 2021-12-10)" in sent[0]["message"]
    assert sent[0]["dedup_key"] == "software:host:9001:imp-log4j" and sent[0]["severity"] == "critical"

    # A score older than a week is asked again.
    _sql(
        "UPDATE cve_enrichment SET nvd_checked_at = ? WHERE cve_id = 'CVE-2021-44228'",
        ((datetime.now() - timedelta(days=8)).strftime("%Y-%m-%d %H:%M:%S"),),
    )
    job = _run(api)
    assert job["result"]["counts"]["looked_up"] == 1 and feeds.nvd_queries[-1] == "CVE-2021-44228"

    # An administrator's edit in the modal makes the severity theirs.
    edited = api.put(
        "/api/software/advisories/imp-log4j",
        json={
            "advisory_id": "imp-log4j",
            "severity": "medium",
            "cvss": 10.0,
            "affected_versions": ["17.9.*"],
            "cves": ["CVE-2021-44228"],
        },
    ).json()["advisory"]
    assert (edited["severity"], edited["severity_source"], edited["cvss_source"]) == ("medium", "admin", "nvd")
    # Handing it back to enrichment applies the cached values at once
    # (10.0: critical; the known-exploited floor only ever raises).
    edited = api.put(
        "/api/software/advisories/imp-log4j",
        json={
            "advisory_id": "imp-log4j",
            "severity": "medium",
            "severity_source": "default",
            "affected_versions": ["17.9.*"],
            "cves": ["CVE-2021-44228"],
        },
    ).json()["advisory"]
    assert (edited["severity"], edited["severity_source"], edited["cvss"]) == ("critical", "enriched", 10.0)


def test_run_caps_lookups_and_survives_feed_failures(api, feeds, monkeypatch):
    _seed_hosts()
    api.get("/api/software/overview")
    _seed_advisories(api)
    api.put("/api/software/settings", json={"cve_enrichment_enabled": True})
    monkeypatch.setattr(cve_enrichment, "MAX_LOOKUPS_PER_RUN", 2)

    job = _run(api)
    counts = job["result"]["counts"]
    assert job["status"] == "completed" and counts["looked_up"] == 2 and counts["remaining"] == 3
    assert "3 left for the next run" in job["result"]["message"]
    raw = {**software_cve.SETTING_DEFAULTS, **asyncio.run(db.get_software_settings())}
    assert software_cve.scheduled_run_due(raw)  # the rest continue on the next run

    # NVD refuses (rate limit) and the KEV host fails: the run says so, the
    # stored values stay, and a software refresh is unaffected.
    before = _advisories(api)
    feeds.nvd_status = 403
    feeds.kev_status = 503
    job = _run(api)
    assert job["status"] == "failed" and "CISA KEV" in job["error"]
    assert job["result"]["counts"]["remaining"] == 3 and len(job["result"]["errors"]) == 2
    assert "HTTP 403" in job["result"]["errors"][1] and "stopped after 1 of 2" in job["result"]["errors"][1]
    after = _advisories(api)
    for advisory_id, advisory in before.items():
        for field in ("severity", "cvss", "known_exploited"):
            assert after[advisory_id][field] == advisory[field], (advisory_id, field)
    settings = api.get("/api/software/settings").json()["settings"]
    assert settings["cve_last_run_status"] == "failed" and "CISA KEV" in settings["cve_last_run_message"]
    assert api.post("/api/software/refresh").status_code == 200

    async def _cache():
        return await db.list_cve_enrichment()

    errors = [row for row in asyncio.run(_cache()).values() if row["last_error"]]
    assert len(errors) == 1 and "HTTP 403" in errors[0]["last_error"]

    # Back up: the next run finishes the backlog.
    feeds.nvd_status, feeds.kev_status = None, 200
    monkeypatch.setattr(cve_enrichment, "MAX_LOOKUPS_PER_RUN", 100)
    job = _run(api)
    assert job["status"] == "completed" and job["result"]["counts"]["looked_up"] == 3
    assert job["result"]["counts"]["remaining"] == 0
    assert api.get("/api/software/cve-enrichment/jobs/nope").status_code == 404


def test_mcp_list_advisories_returns_the_enrichment(api, feeds):
    from netcontrol.mcp.tools.software import list_advisories

    _seed_hosts()
    api.get("/api/software/overview")
    _seed_advisories(api)
    api.put("/api/software/settings", json={"cve_enrichment_enabled": True})
    assert _run(api)["status"] == "completed"
    result = asyncio.run(list_advisories(None, {"known_exploited": True}))
    rows = {row["id"]: row for row in result["items"]}
    assert set(rows) == {"man-pan", "cisco-sa-iosxe-webui"}
    assert rows["man-pan"]["known_exploited"] is True and rows["man-pan"]["kev_due_date"] == "2024-04-19"
    assert rows["man-pan"]["severity_source"] == "admin" and rows["man-pan"]["cvss_from_nvd"] is True


# ── OPNsense audit round trip ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_opnsense_audit_advisory_keeps_its_enrichment_across_audits(monkeypatch):
    from netcontrol.routes.opnsense_collection import sync_audit_advisories

    feeds = _Feeds()
    feeds.kev = _kev_catalog(KEV_AUDIT)
    monkeypatch.setattr(software_cve, "_TRANSPORT", httpx.MockTransport(feeds.handler))
    monkeypatch.setattr(software_cve, "_REQUESTS_PER_SECOND", 1000.0)
    monkeypatch.setattr(software_cve, "_running", False)
    raw = build_sample_raw()
    snapshot = build_snapshot(raw)
    assert (await sync_audit_advisories(raw, snapshot, 901))["upserted"] == 2
    first_id = "opnsense-audit:00000000-0000-4000-8000-000000000001"  # CVE-2026-0001, -0002
    second_id = "opnsense-audit:00000000-0000-4000-8000-000000000002"
    stored = await db.get_software_advisory(first_id)
    assert (stored["severity"], stored["severity_source"], stored["cvss"]) == ("medium", "default", None)

    await db.set_software_settings({"cve_enrichment_enabled": "true"})
    result = await software_cve.run_cve_enrichment(None, "test", software_routes.evaluate_software_alerts)
    assert result["status"] == "completed", result
    enriched = await db.get_software_advisory(first_id)
    # 9.8 from NVD, and CVE-2026-0002 is known exploited: critical.
    assert (enriched["severity"], enriched["severity_source"], enriched["cvss"]) == ("critical", "enriched", 9.8)
    assert enriched["known_exploited"] and enriched["kev_date_added"] == "2026-11-01"
    other = await db.get_software_advisory(second_id)

    # The next audit reports the same findings: nothing is reset.
    assert (await sync_audit_advisories(raw, snapshot, 901))["upserted"] == 2
    again = await db.get_software_advisory(first_id)
    for field in ("severity", "severity_source", "cvss", "cvss_source", "known_exploited", "kev_date_added"):
        assert again[field] == enriched[field], field
    assert (await db.get_software_advisory(second_id))["severity"] == other["severity"]

    # An administrator's severity wins over the audit and over enrichment.
    await db.upsert_software_advisory({**again, "severity": "low", "severity_source": "admin"}, override_severity=True)
    await sync_audit_advisories(raw, snapshot, 901)
    await software_cve.run_cve_enrichment(None, "test", software_routes.evaluate_software_alerts)
    final = await db.get_software_advisory(first_id)
    assert (final["severity"], final["severity_source"], final["cvss"], final["known_exploited"]) == (
        "low",
        "admin",
        9.8,
        True,
    )
    counts = json.loads((await db.get_software_settings())["cve_last_run_counts"])
    assert counts["looked_up"] == 0  # the cache answered
