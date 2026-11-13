"""MCP compliance and software tools, across CLI devices and other sources."""

from __future__ import annotations

import json

import pytest
import routes.database as db
from netcontrol.mcp import registry

from mcp_helpers import call, db_ctx


@pytest.fixture(autouse=True)
def _tools():
    registry.load_tools()


async def _seed_compliance() -> dict[str, int]:
    group = await db.create_group("Campus", "")
    ids = {
        "sw": await db.add_host(group, "core-sw-01", "192.0.2.1"),
        "rtr": await db.add_host(group, "edge-rtr-01", "192.0.2.2"),
        "baseline": await db.create_compliance_profile("Baseline hardening"),
        "wifi": await db.create_compliance_profile("Wireless policy"),
    }
    finding = [{"rule": "no telnet", "passed": False, "detail": "line vty has transport input telnet"}]
    await db.create_compliance_scan_result(None, ids["baseline"], ids["sw"], "non-compliant", 4, 1, 3)
    await db.create_compliance_scan_result(
        None, ids["baseline"], ids["sw"], "non-compliant", 4, 3, 1, json.dumps(finding)
    )
    await db.create_compliance_scan_result(None, ids["baseline"], ids["rtr"], "compliant", 4, 4, 0)
    org = await db.create_meraki_org("Example Retail", org_id="100200", api_key="k")
    ids["org"] = org["id"]
    await db.store_meraki_compliance_results(
        scan_id="scan-1",
        assignment_id=None,
        profile_id=ids["wifi"],
        org_ref=org["id"],
        results=[
            {
                "target_kind": "network",
                "target_id": "N_1",
                "target_name": "Store 12",
                "network_name": "Store 12",
                "status": "non-compliant",
                "total_rules": 2,
                "passed_rules": 1,
                "failed_rules": 1,
            }
        ],
    )
    return ids


async def test_list_compliance_results():
    ids = await _seed_compliance()
    ctx = await db_ctx()
    data, is_error = await call(ctx, "list_compliance_results", {})
    assert is_error is False
    assert data["total"] == 3  # the latest result per target and profile
    sw = next(r for r in data["items"] if r.get("host", {}).get("id") == ids["sw"])
    assert sw["status"] == "non-compliant" and sw["failed_rules"] == 1 and sw["profile"] == "Baseline hardening"
    assert sw["findings"][0]["rule"] == "no telnet" and sw["source"] == "inventory" and sw["scanned_at"]

    data, _ = await call(ctx, "list_compliance_results", {"status": "pass"})
    assert [r["host"]["hostname"] for r in data["items"]] == ["edge-rtr-01"]
    data, _ = await call(ctx, "list_compliance_results", {"status": "fail", "profile": "baseline"})
    assert [r["host"]["hostname"] for r in data["items"]] == ["core-sw-01"]
    data, _ = await call(ctx, "list_compliance_results", {"host": "edge-rtr-01"})
    assert data["total"] == 1


async def test_results_span_vendors():
    await _seed_compliance()
    data, _ = await call(await db_ctx(), "list_compliance_results", {})
    assert {r["source"] for r in data["items"]} == {"inventory", "meraki"}
    meraki = next(r for r in data["items"] if r["source"] == "meraki")
    assert meraki["target"] == "Store 12" and meraki["organization"] == "Example Retail"
    assert meraki["profile"] == "Wireless policy" and meraki["status"] == "non-compliant"


async def test_get_compliance_summary():
    await _seed_compliance()
    ctx = await db_ctx()
    data, is_error = await call(ctx, "get_compliance_summary", {})
    assert is_error is False
    by_key = {(p["profile"], p["source"]): p for p in data["profiles"]}
    assert by_key[("Baseline hardening", "inventory")]["compliant"] == 1
    assert by_key[("Baseline hardening", "inventory")]["non_compliant"] == 1
    assert by_key[("Wireless policy", "meraki")]["non_compliant"] == 1
    assert data["totals"] == {"targets": 3, "compliant": 1, "non_compliant": 2, "error": 0}
    data, _ = await call(ctx, "get_compliance_summary", {"profile": "wireless"})
    assert [p["profile"] for p in data["profiles"]] == ["Wireless policy"]


async def test_never_scanned_is_no_data():
    ctx = await db_ctx()
    for name in ("list_compliance_results", "get_compliance_summary"):
        data, is_error = await call(ctx, name, {})
        assert is_error is False and data["no_data"] is True and "compliance" in data["message"]


def _device(key: str, name: str, source: str, platform: str, version: str, **extra) -> dict:
    return {
        "device_key": key,
        "name": name,
        "source": source,
        "platform": platform,
        "version": version,
        "raw_version": version,
        **extra,
    }


async def _seed_software() -> None:
    devices = [
        _device("host:1", "core-sw-01", "inventory", "ios-xe", "17.6.1", model="C9300-48P"),
        _device("cato:7", "branch-socket-01", "cato", "cato-socket", "22.0.1", site="Branch 7"),
        _device("aws:9", "tgw-fw-01", "aws", "aws-ami", "2026.3"),
    ]
    await db.replace_software_versions(devices)
    devices[0] = {**devices[0], "version": "17.9.4", "raw_version": "17.9.4"}
    await db.replace_software_versions(devices)
    await db.upsert_software_advisory(
        {
            "advisory_id": "example-sa-0001",
            "source": "manual",
            "title": "Web UI privilege escalation",
            "severity": "critical",
            "platform": "ios-xe",
            "affected_versions": ["17.9.4"],
            "fixed_versions": ["17.9.5"],
            "cves": ["CVE-2099-0001"],
            "enabled": True,
        }
    )
    await db.sync_software_alerts([{"device_key": "host:1", "advisory_id": "example-sa-0001", "severity": "critical"}])


async def test_list_software_versions():
    await _seed_software()
    ctx = await db_ctx()
    data, is_error = await call(ctx, "list_software_versions", {})
    assert is_error is False and data["total"] == 3
    assert {r["source"] for r in data["items"]} == {"inventory", "cato", "aws"}
    sw = next(r for r in data["items"] if r["name"] == "core-sw-01")
    assert sw["version"] == "17.9.4" and sw["previous_version"] == "17.6.1" and sw["platform"] == "ios-xe"
    assert sw["open_advisories"] == 1 and sw["worst_severity"] == "critical"
    cato = next(r for r in data["items"] if r["source"] == "cato")
    assert cato["open_advisories"] == 0

    data, _ = await call(ctx, "list_software_versions", {"vendor": "cato"})
    assert [r["name"] for r in data["items"]] == ["branch-socket-01"]
    data, _ = await call(ctx, "list_software_versions", {"version": "17.9"})
    assert [r["name"] for r in data["items"]] == ["core-sw-01"]
    data, _ = await call(ctx, "list_software_versions", {"host": "tgw"})
    assert [r["name"] for r in data["items"]] == ["tgw-fw-01"]
    data, _ = await call(ctx, "list_software_versions", {"changed_since": "2020-01-01T00:00:00Z"})
    assert [r["name"] for r in data["items"]] == ["core-sw-01"]
    data, _ = await call(ctx, "list_software_versions", {"changed_since": "2999-01-01T00:00:00Z"})
    assert data["items"] == []


async def test_list_advisories():
    await _seed_software()
    ctx = await db_ctx()
    data, is_error = await call(ctx, "list_advisories", {})
    assert is_error is False
    (advisory,) = data["items"]
    assert advisory["id"] == "example-sa-0001" and advisory["cves"] == ["CVE-2099-0001"]
    assert advisory["severity"] == "critical" and advisory["fixed_in"] == ["17.9.5"]
    assert advisory["affected_hosts"] == [{"name": "core-sw-01", "version": "17.9.4", "source": "inventory"}]
    gaps = {g["platform"]: g for g in data["platforms_without_advisories"]}
    assert set(gaps) == {"cato-socket", "aws-ami"}
    assert gaps["cato-socket"] == {"platform": "cato-socket", "advisory_source": "none", "devices": 1}

    for args, count in (
        ({"cve": "cve-2099-0001"}, 1),
        ({"cve": "CVE-2099-9999"}, 0),
        ({"severity": "critical"}, 1),
        ({"severity": "low"}, 0),
        ({"host": "core-sw"}, 1),
        ({"host": "branch-socket"}, 0),
    ):
        data, _ = await call(ctx, "list_advisories", args)
        assert len(data["items"]) == count, args


async def test_never_collected_software_is_no_data():
    ctx = await db_ctx()
    for name in ("list_software_versions", "list_advisories"):
        data, is_error = await call(ctx, name, {})
        assert is_error is False and data["no_data"] is True and "software" in data["message"]


async def test_hidden_without_category():
    compliance_only = await db_ctx(categories=["compliance"], name="c-bot")
    software_only = await db_ctx(categories=["software"], name="s-bot")
    for name in ("list_software_versions", "list_advisories"):
        assert await call(compliance_only, name, {}) == (f"Unknown tool: {name}", True)
        assert (await call(software_only, name, {}))[1] is False
    for name in ("list_compliance_results", "get_compliance_summary"):
        assert await call(software_only, name, {}) == (f"Unknown tool: {name}", True)
        assert (await call(compliance_only, name, {}))[1] is False
