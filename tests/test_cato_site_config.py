"""Tests for the Cato site and network configuration reader
(``netcontrol.integrations.cato.site_config``): the collector against a mock
GraphQL endpoint, the section builders, and the demo payload."""

from __future__ import annotations

import json
from dataclasses import replace

import httpx
import pytest
from netcontrol.integrations.cato import site_config
from netcontrol.integrations.cato.client import CatoClient
from netcontrol.integrations.cato.sample import build_sample_raw
from netcontrol.integrations.cato.site_config import (
    ACCOUNT_CALLS,
    KNOWN_HOST_COLUMNS,
    RANGE_SETTINGS_COLUMNS,
    SITE_CALLS,
    account_config_sections,
    build_sample_site_config,
    collect_site_config,
    planned_calls,
    site_config_sections,
)

# Socket sites, as the account snapshot lists them: with their devices.
SITES = [
    {"id": "1001", "info": {"name": "HQ"}, "devices": [{"id": "d1"}]},
    {"id": "1002", "info": {"name": "Branch"}, "devices": [{"id": "d2"}]},
]


def _client(handler) -> CatoClient:
    return CatoClient("test-key", transport=httpx.MockTransport(handler), requests_per_second=1000)


def _ok(data: dict) -> httpx.Response:
    return httpx.Response(200, json={"data": data})


def _refused(message: str) -> httpx.Response:
    return httpx.Response(200, json={"errors": [{"message": message}]})


def _site(field: str, value) -> dict:
    return {"site": {field: value}}


def _network(group: str, field: str, value) -> dict:
    return {"networkConfig": {group: {field: value}}}


def _site_id(body: dict) -> str:
    variables = body["variables"]
    ref = variables.get("site") or variables["input"]["site"]
    assert ref["by"] == "ID"
    return ref["input"]


def _answer(body: dict) -> httpx.Response:
    """A complete, small account: every query answered."""
    op = body["operationName"]
    if op == "plexusAccountInfo":
        return _ok({"accountManagement": {"account": {"id": "42", "name": "Acme", "plan": "COMMERCIAL"}}})
    if op == "plexusDhcpSettings":
        return _ok(_network("dhcp", "settings", {"leaseTime": 3600, "relay": {"enabled": False}}))
    if op == "plexusDhcpOptions":
        return _ok(
            _network(
                "dhcp",
                "optionList",
                {"items": [{"tag": 42, "type": "IP", "value": "10.0.0.1"}], "paging": {"total": 1}},
            )
        )
    if op == "plexusDhcpRelayGroups":
        return _ok(_network("dhcp", "relayGroupList", {"items": [], "paging": {"total": 0}}))
    if op == "plexusDnsSettings":
        return _ok(_network("dns", "settings", {"primaryServer": "10.0.0.53", "suffix": []}))
    if op == "plexusDnsForwardingRules":
        return _ok(_network("dns", "forwardingRuleList", {"items": [], "paging": {"total": 0}}))
    if op == "plexusDnsServerSets":
        return _ok(_network("dns", "serverSetList", {"items": [], "paging": {"total": 0}}))
    if op == "plexusDnsSuffixSets":
        return _ok(_network("dns", "suffixSetList", {"items": [], "paging": {"total": 0}}))
    sid = _site_id(body)
    if op == "plexusSiteNetworkRanges":
        return _ok(
            _site("networkRangeList", {"items": [{"name": f"R{sid}", "subnet": f"10.{sid[-1]}.0.0/24"}], "total": 1})
        )
    if op == "plexusSiteStaticHosts":
        return _ok(_site("staticHostList", {"items": [{"name": "h", "ip": "10.1.0.5", "psk": "x"}]}))
    if op == "plexusSiteKnownHosts":
        return _ok(_site("knownHostList", {"knownHost": [{"ip": "10.1.0.9"}], "pageInfo": {"total": 1}}))
    if op == "plexusSiteSocketConfiguration":
        config = {"serial": f"S{sid}", "socketInfo": {"isPrimary": True, "model": "X1500"}}
        return _ok(_site("siteSocketConfiguration", {"primarySocketConfiguration": config}))
    if op == "plexusSiteGeneralDetails":
        return _ok(_site("siteGeneralDetails", {"siteType": "BRANCH", "siteLocation": {"timezone": "UTC"}}))
    if op == "plexusSiteBackhauling":
        return _ok(_site("siteBackhauling", {"useAsBackhaulingGW": False}))
    if op == "plexusSiteWifiSsids":
        return _ok(_site("wifiSsidList", {"wifiSsid": [], "pageInfo": {"total": 0}}))
    if op == "plexusSiteDnsSettings":
        # null: the site uses the account default.
        return _ok(_network("dns", "siteSettings", None))
    raise AssertionError(f"unexpected operation {op}")


# ── Collection ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_collects_account_and_every_site_and_reports_progress():
    seen: list[str] = []
    progress: list[tuple[str, int]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert "mutation" not in body["query"]
        seen.append(body["operationName"])
        return _answer(body)

    errors: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_site_config(
            client, "42", SITES, errors, report=lambda phase, calls=0, **_f: progress.append((phase, calls))
        )

    assert errors == []
    assert len(seen) == planned_calls(len(SITES)) == ACCOUNT_CALLS + 2 * SITE_CALLS
    assert sum(calls for _phase, calls in progress) == len(seen)
    assert {phase for phase, _calls in progress} == {"cato site config"}
    assert raw["account"]["name"] == "Acme"
    assert raw["dhcp"]["settings"]["leaseTime"] == 3600
    assert raw["dhcp"]["options"][0]["tag"] == 42 and raw["dhcp"]["relay_groups"] == []
    assert raw["dns"]["settings"]["primaryServer"] == "10.0.0.53"
    assert set(raw["sites"]) == {"1001", "1002"}
    hq = raw["sites"]["1001"]
    assert set(hq) == set(site_config.SITE_KEYS)
    assert hq["ranges"][0]["name"] == "R1001"
    assert hq["socket_configuration"]["primarySocketConfiguration"]["serial"] == "S1001"
    # Read and null: the account default, told from not collected (None).
    assert hq["dns"] == {}
    assert hq["wifi_ssids"] == []
    # Secrets never reach the payload.
    assert "psk" not in hq["static_hosts"][0]


@pytest.mark.asyncio
async def test_refused_site_query_is_recorded_and_the_rest_is_read():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["operationName"] == "plexusSiteBackhauling" and _site_id(body) == "1002":
            return _refused("Site is not a Socket site")
        if body["operationName"] == "plexusDnsSettings":
            return httpx.Response(403)
        return _answer(body)

    errors: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_site_config(client, "42", SITES, errors)

    assert raw["sites"]["1002"]["backhauling"] is None
    assert raw["sites"]["1001"]["backhauling"] == {"useAsBackhaulingGW": False}
    assert raw["sites"]["1002"]["ranges"] and raw["dns"]["settings"] is None
    assert raw["dns"]["forwarding_rules"] == []
    paths = {(e["scope"], e["path"]) for e in errors}
    assert paths == {("site Branch", "site.siteBackhauling"), ("account", "networkConfig.dns.settings")}
    assert all(set(e) == {"scope", "path", "status", "message"} for e in errors)


@pytest.mark.asyncio
async def test_full_query_refused_falls_back_to_reduced_for_every_site():
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sent.append(body["operationName"])
        if body["operationName"] == "plexusSiteNetworkRanges":
            return _refused('Cannot query field "mdnsReflector" on type "NetworkRange".')
        if body["operationName"] == "plexusSiteNetworkRangesBasic":
            body = {**body, "operationName": "plexusSiteNetworkRanges"}
        return _answer(body)

    errors: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_site_config(client, "42", SITES, errors)

    assert raw["sites"]["1001"]["ranges"][0]["name"] == "R1001"
    assert raw["sites"]["1002"]["ranges"][0]["name"] == "R1002"
    # The full query is tried once; the second site goes straight to the reduced one.
    assert sent.count("plexusSiteNetworkRanges") == 1 and sent.count("plexusSiteNetworkRangesBasic") == 2
    assert [e["path"] for e in errors] == ["site.networkRangeList (full detail)"]
    assert "mdnsReflector" in errors[0]["message"]


@pytest.mark.asyncio
async def test_known_hosts_follow_paging_to_the_total():
    pages: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["operationName"] != "plexusSiteKnownHosts":
            return _answer(body)
        paging = body["variables"]["input"]["paging"]
        pages.append(paging)
        start = paging["from"]
        hosts = [{"ip": f"10.0.{i // 250}.{i % 250 + 1}"} for i in range(start, min(start + paging["limit"], 230))]
        return _ok(_site("knownHostList", {"knownHost": hosts, "pageInfo": {"total": 230}}))

    errors: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_site_config(client, "42", SITES[:1], errors)

    assert [p["from"] for p in pages] == [0, 100, 200]
    assert len(raw["sites"]["1001"]["known_hosts"]) == 230
    assert errors == []


@pytest.mark.asyncio
async def test_known_hosts_stop_at_the_per_site_limit(monkeypatch):
    specs = tuple(replace(s, cap=150) if s.key == "known_hosts" else s for s in site_config._SITE_SPECS)
    monkeypatch.setattr(site_config, "_SITE_SPECS", specs)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["operationName"] != "plexusSiteKnownHosts":
            return _answer(body)
        start = body["variables"]["input"]["paging"]["from"]
        hosts = [{"ip": f"10.0.{i // 250}.{i % 250 + 1}"} for i in range(start, start + 100)]
        return _ok(_site("knownHostList", {"knownHost": hosts, "pageInfo": {"total": 5000}}))

    errors: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_site_config(client, "42", SITES[:1], errors)

    assert len(raw["sites"]["1001"]["known_hosts"]) == 150
    assert [(e["path"], e["message"]) for e in errors] == [
        ("site.knownHostList", "First 150 of 5000 read (the per-site limit)")
    ]


@pytest.mark.asyncio
async def test_socket_configuration_is_not_asked_for_a_site_without_a_socket():
    """An IPsec or cloud site has no Socket (no device and no Socket info in
    the snapshot): Cato answers its Socket configuration with an error, so
    the query is not sent, the payload says not collected, and the skipped
    call still counts for the progress."""
    # Cato lists an IPsec site's tunnel as a device too: type IPSEC-IKEv2, no
    # Socket info (the shape the full sites query returns for CLE_HQ).
    tunnel = {"id": "1", "name": "", "connected": True, "haRole": "MASTER", "type": "IPSEC-IKEv2", "socketInfo": None}
    sites = [
        *SITES,
        {"id": "1004", "info": {"name": "AWS", "connType": "IPSEC_V2", "sockets": []}, "devices": []},
        {"id": "1005", "info": {"name": "HQ IPsec", "connType": "IPSEC_V2", "sockets": None}, "devices": [tunnel]},
    ]
    asked: list[str] = []
    progress: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["operationName"] == "plexusSiteSocketConfiguration":
            asked.append(_site_id(body))
        return _answer(body)

    errors: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_site_config(
            client, "42", sites, errors, report=lambda _p, calls=0, **_f: progress.append(calls)
        )

    assert asked == ["1001", "1002"]
    assert raw["sites"]["1004"]["socket_configuration"] is None
    assert raw["sites"]["1005"]["socket_configuration"] is None
    assert raw["sites"]["1004"]["ranges"][0]["name"] == "R1004"
    assert errors == []
    assert sum(progress) == planned_calls(len(sites))


@pytest.mark.asyncio
async def test_query_refused_for_the_first_sites_is_not_sent_for_the_rest():
    sites = [{"id": str(2000 + n), "info": {"name": f"S{n}"}, "devices": [{"id": f"d{n}"}]} for n in range(5)]
    wifi_calls: list[str] = []
    progress: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["operationName"].startswith("plexusSiteWifiSsids"):
            wifi_calls.append(_site_id(body))
            return _refused("Permission denied")
        return _answer(body)

    errors: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_site_config(
            client, "42", sites, errors, report=lambda _p, calls=0, **_f: progress.append(calls)
        )

    # The full and the reduced query for each of the first three sites, then none.
    assert wifi_calls == ["2000", "2000", "2001", "2001", "2002", "2002"]
    assert all(raw["sites"][s["id"]]["wifi_ssids"] is None for s in sites)
    assert all(raw["sites"][s["id"]]["ranges"] for s in sites)
    assert errors[-1]["path"] == "site.wifiSsidList" and "remaining 2" in errors[-1]["message"]
    # Skipped calls still advance the progress to the planned total.
    assert sum(progress) == planned_calls(len(sites))


@pytest.mark.asyncio
async def test_sites_beyond_the_cap_are_skipped_with_one_error(monkeypatch):
    monkeypatch.setattr(site_config, "MAX_SITES", 1)

    def handler(request: httpx.Request) -> httpx.Response:
        return _answer(json.loads(request.content))

    errors: list[dict] = []
    async with _client(handler) as client:
        raw = await collect_site_config(client, "42", SITES, errors)

    assert list(raw["sites"]) == ["1001"]
    assert len(errors) == 1 and errors[0]["path"] == "site configuration"
    assert "first 1 of 2 sites" in errors[0]["message"]
    assert planned_calls(10) == ACCOUNT_CALLS + SITE_CALLS


# ── Sections ──────────────────────────────────────────────────────────────────


def _by_title(sections: list[dict]) -> dict[str, dict]:
    titles = [s["title"] for s in sections]
    assert len(titles) == len(set(titles))
    return {s["title"]: s for s in sections}


def test_site_sections_render_ranges_hosts_and_settings():
    raw = {
        "dhcp": {"relay_groups": [{"id": "rg-1", "name": "Core-DHCP"}]},
        "sites": {
            "7": {
                "ranges": [
                    {"subnet": "10.9.0.0/24", "name": "B", "rangeType": "VLAN", "vlan": 9,
                     "dhcpSettings": {"dhcpType": "DHCP_RELAY", "relayGroupId": "rg-1"}},
                    {"subnet": "10.2.0.0/24", "name": "A", "rangeType": "Native", "internetOnly": False,
                     "dhcpSettings": {"dhcpType": "DHCP_RANGE", "ipRange": "10.2.0.10-10.2.0.99",
                                      "leaseTimeSettings": {"leaseTime": 1, "timeUnit": "DAYS"}}},
                ],
                "known_hosts": [
                    {"ip": "10.2.0.10", "macAddress": "aa:bb", "ipAllocationType": "DYNAMIC",
                     "networkRange": {"name": "A", "subnet": "10.2.0.0/24"},
                     "leaseTimeSeconds": 86400, "expiresInSeconds": 3725, "lastActivitySeconds": 59},
                ],
                "static_hosts": None,
                "general": {"siteType": "BRANCH", "disableAclForSip": False,
                            "siteLocation": {"cityName": "Madison", "countryCode": "US", "timezone": "America/Chicago"},
                            "workingHours": {"override": True, "workingDays": ["TUESDAY", "MONDAY"],
                                             "fromTimeMinuteOffset": 540, "toTimeMinuteOffset": 1080}},
                "backhauling": None,
                "dns": None,
            }
        },
    }  # fmt: skip
    sections = _by_title(site_config_sections(raw, "7"))
    assert list(sections) == ["Site settings", "Network range settings", "Known hosts"]

    ranges = sections["Network range settings"]
    assert ranges["columns"] == RANGE_SETTINGS_COLUMNS
    assert [r[0] for r in ranges["rows"]] == ["10.2.0.0/24", "10.9.0.0/24"]
    assert ranges["rows"][0][6] == "Range 10.2.0.10-10.2.0.99, lease 1 day"
    assert ranges["rows"][1][6] == "Relay to Core-DHCP"

    known = sections["Known hosts"]
    assert known["columns"] == KNOWN_HOST_COLUMNS
    assert known["rows"][0][6:] == ["A (10.2.0.0/24)", "1d (expires in 1h 2m)", "59s ago"]

    settings = dict(sections["Site settings"]["rows"])
    assert settings["Working hours"] == "Mon, Tue 09:00-18:00"
    assert settings["Location"] == "Madison, US" and settings["ACL for SIP disabled"] == "No"
    # DNS not collected: no row rather than a guess.
    assert not any(key.startswith("Site DNS") for key in settings)


def test_socket_configuration_narrows_to_the_node_serial():
    def config(serial: str, primary: bool) -> dict:
        return {
            "serial": serial,
            "managementIp": "10.0.0.2",
            "socketInfo": {"isPrimary": primary, "wifiSupported": "TRUE"},
        }

    raw = {
        "sites": {
            "1": {
                "socket_configuration": {
                    "primarySocketConfiguration": config("AAA", True),
                    "secondarySocketConfiguration": config("BBB", False),
                }
            }
        }
    }
    both = [s["title"] for s in site_config_sections(raw, "1")]
    assert both == ["Socket configuration (primary)", "Socket configuration (secondary)"]
    mine = site_config_sections(raw, "1", serial="BBB")
    assert [s["title"] for s in mine] == ["Socket configuration"]
    rows = dict(mine[0]["rows"])
    assert rows["Role"] == "Secondary" and rows["Serial"] == "BBB" and rows["Wi-Fi support"] == "Yes"


def test_nothing_collected_gives_no_sections():
    empty = dict.fromkeys(site_config.SITE_KEYS)
    assert site_config_sections({"sites": {"1": empty}}, "1") == []
    assert site_config_sections({"sites": {}}, "1") == []
    assert site_config_sections(None, "1") == []
    raw = {"account": None, "dhcp": dict.fromkeys(("settings", "options", "relay_groups")), "dns": {}}
    assert account_config_sections(raw) == []
    assert account_config_sections(None) == []


def test_account_sections_render_dhcp_and_dns():
    raw = {
        "account": {"id": "42", "name": "Acme", "plan": "COMMERCIAL"},
        "dhcp": {
            "settings": {"leaseTime": 86400, "relay": {"enabled": True, "timeout": 30, "group": {"name": "G"}}},
            "options": [{"tag": 66, "type": "ASCII", "value": "tftp"}, {"tag": 42, "type": "IP", "value": "10.0.0.1"}],
            "relay_groups": [{"name": "G", "server": ["10.0.0.5", "10.0.0.6"]}],
        },
        "dns": {
            "settings": {"primaryServer": "10.0.0.53", "suffix": ["a.example", "b.example"]},
            "forwarding_rules": [{"domain": "corp.example", "server": ["10.0.0.53"]}],
            "server_sets": [],
            "suffix_sets": None,
        },
    }
    sections = _by_title(account_config_sections(raw))
    assert list(sections) == [
        "Account",
        "DHCP settings",
        "DHCP options",
        "DHCP relay groups",
        "DNS settings",
        "DNS forwarding rules",
    ]
    assert dict(sections["DHCP settings"]["rows"]) == {
        "Lease time": "1d (86400 s)",
        "DHCP relay": "Yes",
        "Relay group": "G",
        "Relay timeout": "30 s",
    }
    assert sections["DHCP options"]["rows"] == [["42", "IP", "10.0.0.1", ""], ["66", "ASCII", "tftp", ""]]
    assert sections["DHCP relay groups"]["rows"] == [["G", "10.0.0.5, 10.0.0.6"]]
    assert dict(sections["DNS settings"]["rows"])["Search suffixes"] == "a.example, b.example"


def test_sample_config_matches_the_sample_account_and_shows_every_section():
    sample = build_sample_site_config()
    sample_sites = {s["id"]: s for s in build_sample_raw()["sites"]}
    assert set(sample["sites"]) == set(sample_sites)

    titles: set[str] = set()
    for site_id, site in sample_sites.items():
        assert set(sample["sites"][site_id]) == set(site_config.SITE_KEYS)
        for device in site["devices"] or [None]:
            serial = (device or {}).get("socketInfo", {}).get("serial", "")
            sections = site_config_sections(sample, site_id, serial=serial)
            titles |= {s["title"] for s in sections}
            if device:
                socket = next(s for s in sections if s["title"] == "Socket configuration")
                assert dict(socket["rows"])["Serial"] == serial
    assert titles == {
        "Site settings",
        "Socket configuration",
        "Network range settings",
        "Static hosts",
        "Known hosts",
        "Wi-Fi SSIDs",
    }
    account = [s["title"] for s in account_config_sections(sample)]
    assert account == [
        "Account",
        "DHCP settings",
        "DHCP options",
        "DHCP relay groups",
        "DNS settings",
        "DNS forwarding rules",
        "DNS server sets",
        "DNS suffix sets",
    ]
    # Section titles of the Socket node that already exist must not repeat.
    assert not titles & {"Device", "Interfaces", "Network ranges", "VPN", "Overview", "WAN links"}
