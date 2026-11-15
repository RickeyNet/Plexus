"""Tests for the OPNsense topology integration (``netcontrol.integrations.opnsense``)
and its source routes, config backup and audit advisories.

Covers, with no network access (a fake firewall serves the answers of
``sample.sample_api_answers`` over ``httpx.MockTransport``):
  * client      - HTTP Basic auth, no redirects, the snake_case to camelCase
                  fallback, retries, the address and credential checks
  * collector   - every part read, the progress phases, secrets scrubbed,
                  one refused or missing endpoint degrading to a warning,
                  a rejected key failing, the audit flow
  * normalize   - the sample snapshot: nodes, sections, subnet index, the
                  gateway / WireGuard / OpenVPN status vocabularies, the
                  firmware and audit warnings, no config.xml in the snapshot
  * HTTP API    - CRUD with a write-only key:secret, the sample, a build job
                  against the fake firewall: config backup skipped until the
                  firewall is an inventory host, then stored once and
                  re-checked when unchanged; audit advisories and alerts
                  created, updated, then withdrawn

Every name and address is invented (example.com, documentation ranges).
"""

from __future__ import annotations

import base64
import copy

import httpx
import netcontrol.app as app_module  # noqa: F401 - the app the fixture serves
import pytest
from netcontrol.integrations.availability import extract_entity_states
from netcontrol.integrations.inventory_import import importable_devices
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.opnsense import client as client_module, collector as collector_module
from netcontrol.integrations.opnsense.client import (
    OpnsenseApiError,
    OpnsenseClient,
    split_credentials,
    validate_base_url,
)
from netcontrol.integrations.opnsense.collector import (
    DEFAULT_OPTIONS,
    collect_opnsense,
    parse_audit_log,
    sanitize_options,
)
from netcontrol.integrations.opnsense.normalize import (
    audit_advisories,
    build_snapshot,
    gateway_status,
    openvpn_client_status,
    wireguard_status,
)
from netcontrol.integrations.opnsense.sample import (
    AUDIT_LOG,
    SAMPLE_CONFIG_XML,
    build_sample_raw,
    sample_api_answers,
)
from netcontrol.integrations.software.versions import snapshot_devices

from test_meraki_topology import _CsrfClient, api  # noqa: F401 - the fixture is used by name

BASE = "https://fw1.example.com"
KEY = "plexus-key-0001"
SECRET = "plexus-secret-0001-not-real"
FIREWALL = "d:fw-edge-1.example.com"
CLEAN_AUDIT = "***GOT REQUEST TO AUDIT SECURITY***\n0 problem(s) in 0 installed package(s) found.\n***DONE***\n"

# The camelCase form (24.7 to 25.1) of every snake_case path the collector tries first.
CAMEL = {
    "diagnostics/system/systemInformation": "diagnostics/system/system_information",
    "interfaces/overview/interfacesInfo": "interfaces/overview/interfaces_info",
    "diagnostics/interface/getRoutes": "diagnostics/interface/get_routes",
    "ipsec/sessions/searchPhase1": "ipsec/sessions/search_phase1",
    "openvpn/service/searchSessions": "openvpn/service/search_sessions",
}


class _FakeFirewall:
    """An OPNsense firewall's API serving the sample answers, with knobs for
    failure cases."""

    def __init__(self) -> None:
        self.answers = sample_api_answers()
        self.fail: dict[str, int] = {}  # path -> HTTP status
        self.snake_forbidden = False  # a 24.7 to 25.1 privilege: camelCase only
        self.running = "ready"
        self.audit_done = True
        self.audit_log = AUDIT_LOG
        self.audits = 0
        self.calls: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        expected = "Basic " + base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()
        if request.headers.get("Authorization") != expected:
            return httpx.Response(401, json={"status": 401, "message": "Authentication Failed"})
        path = request.url.path.removeprefix("/api/")
        if path in self.fail:
            return httpx.Response(self.fail[path], json={"message": f"refused {path}"})
        if self.snake_forbidden and path in CAMEL.values():
            return httpx.Response(403, json={"status": 403, "message": "Forbidden"})
        key = CAMEL.get(path, path)
        if key == "core/firmware/audit":
            assert request.method == "POST"
            self.audits += 1
            return httpx.Response(200, json=self.answers[key])
        # Read-only: nothing else is ever posted.
        assert request.method == "GET", (request.method, path)
        if key == "core/firmware/running":
            return httpx.Response(200, json={"status": self.running})
        if key == "core/firmware/upgradestatus":
            return httpx.Response(200, json={"status": "done" if self.audit_done else "running", "log": self.audit_log})
        if key == "core/backup/download/this":
            return httpx.Response(200, text=self.answers[key], headers={"Content-Type": "application/octet-stream"})
        if key not in self.answers:
            return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
        return httpx.Response(200, json=copy.deepcopy(self.answers[key]))

    def paths(self) -> list[str]:
        return [r.url.path.removeprefix("/api/") for r in self.calls]


def _client(fake: _FakeFirewall, **kwargs) -> OpnsenseClient:
    kwargs.setdefault("requests_per_second", 1000)
    return OpnsenseClient(BASE, KEY, SECRET, transport=httpx.MockTransport(fake.handler), **kwargs)


@pytest.fixture
def no_sleep(monkeypatch):
    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(client_module.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(collector_module.asyncio, "sleep", _no_sleep)


def _section(entity: dict, title: str) -> dict:
    return next(s for s in entity["sections"] if s["title"] == title)


def _titles(entity: dict) -> list[str]:
    return [s["title"] for s in entity["sections"]]


def _node(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)


def _kv(entity: dict, title: str) -> dict[str, str]:
    return dict(_section(entity, title)["rows"])


def _table(entity: dict, title: str) -> list[dict[str, str]]:
    section = _section(entity, title)
    return [dict(zip(section["columns"], row, strict=False)) for row in section["rows"]]


# ── Client ───────────────────────────────────────────────────────────────────


def test_base_url_must_be_the_https_gui_host():
    assert validate_base_url("fw1.example.com") == "https://fw1.example.com"
    assert validate_base_url("https://192.0.2.1:8443/") == "https://192.0.2.1:8443"
    assert validate_base_url("https://fw1.example.com/api") == "https://fw1.example.com"
    assert validate_base_url("https://[2001:db8::1]:4443") == "https://[2001:db8::1]:4443"
    for bad in ("", "http://fw1.example.com", "https://fw1.example.com/ui", "https://u:p@fw1.example.com"):
        with pytest.raises(ValueError):
            validate_base_url(bad)
    with pytest.raises(ValueError, match="invalid port"):
        validate_base_url("https://fw1.example.com:99999")


def test_credentials_split_on_the_first_colon():
    assert split_credentials(f"{KEY}:{SECRET}") == (KEY, SECRET)
    assert split_credentials(" key:sec:ret ") == ("key", "sec:ret")
    for bad in ("", "key-only", ":secret", "key:", "  :  "):
        with pytest.raises(ValueError, match="key:secret"):
            split_credentials(bad)


@pytest.mark.asyncio
async def test_client_sends_basic_auth_and_never_follows_redirects():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["User-Agent"].startswith("Plexus-OpnsenseTopology")
        return httpx.Response(302, headers={"Location": "https://attacker.example.com/"})

    async with OpnsenseClient(BASE, KEY, SECRET, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(OpnsenseApiError) as raised:
            await client.get("core/firmware/status")
    assert raised.value.status_code == 302 and raised.value.path == "/core/firmware/status"


@pytest.mark.asyncio
async def test_client_falls_back_to_the_camel_case_path_when_the_snake_case_one_is_refused():
    fake = _FakeFirewall()
    fake.snake_forbidden = True
    async with _client(fake) as client:
        path, body = await client.get_first(collector_module.PATH_SYSTEM)
    assert path == "diagnostics/system/systemInformation" and body["name"] == "fw-edge-1.example.com"
    assert fake.paths() == ["diagnostics/system/system_information", "diagnostics/system/systemInformation"]


@pytest.mark.asyncio
async def test_client_retries_server_errors_and_rate_limits_but_not_a_403(no_sleep):
    answers = iter([httpx.Response(503), httpx.Response(429, headers={"Retry-After": "2"}), httpx.Response(200, json={})])
    async with OpnsenseClient(BASE, KEY, SECRET, transport=httpx.MockTransport(lambda r: next(answers))) as client:
        assert await client.get("routes/gateway/status") == {}
        assert client.stats == {"requests": 3, "retries": 2, "rate_limited": 1}
    fake = _FakeFirewall()
    fake.fail = {"routes/gateway/status": 403}
    async with _client(fake) as client:
        with pytest.raises(OpnsenseApiError) as raised:
            await client.get("routes/gateway/status")
    assert raised.value.status_code == 403 and raised.value.detail == "refused routes/gateway/status"
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_client_reports_an_unreachable_firewall(no_sleep):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    async with OpnsenseClient(BASE, KEY, SECRET, max_retries=1, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(OpnsenseApiError) as raised:
            await client.get("core/firmware/status")
    assert raised.value.transport and raised.value.status_code is None


def test_sanitize_options_defaults_and_coerces():
    assert sanitize_options(None) == DEFAULT_OPTIONS
    assert set(DEFAULT_OPTIONS) == {
        "verify_tls",
        "include_gateways",
        "include_vpn",
        "include_routes",
        "include_firmware_audit",
        "config_backup",
        "inventory_enrich",
    }
    assert all(value is True for value in DEFAULT_OPTIONS.values())
    opts = sanitize_options({"verify_tls": 0, "include_vpn": "", "unknown": 1, "config_backup": "yes"})
    assert opts == {**DEFAULT_OPTIONS, "verify_tls": False, "include_vpn": False, "config_backup": True}


# ── Collector ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_collect_reads_every_part_and_reports_the_phases(no_sleep):
    fake = _FakeFirewall()
    phases: list[str] = []
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {}, lambda p: phases.append(p["phase"]))
    assert list(dict.fromkeys(phases)) == [
        "opnsense system",
        "opnsense interfaces",
        "opnsense gateways",
        "opnsense vpn",
        "opnsense routes",
        "opnsense firmware",
        "opnsense config",
        "collected",
    ]
    assert raw["errors"] == []
    assert len(raw["interfaces"]) == 6 and len(raw["gateways"]) == 4 and len(raw["routes"]) == 7
    assert len(raw["ipsec"]) == 2 and len(raw["wireguard"]) == 3 and len(raw["openvpn"]) == 4
    assert raw["firmware"]["product"]["product_version"] == "25.7.6" and len(raw["firmware"]["updates"]) == 2
    assert raw["audit"]["problems"] == 2 and fake.audits == 1
    assert raw["config_xml"] == SAMPLE_CONFIG_XML
    assert raw["firewall"] == {"name": "", "base_url": BASE, "address": "fw1.example.com"}


@pytest.mark.asyncio
async def test_collect_scrubs_every_secret(no_sleep):
    fake = _FakeFirewall()
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"config_backup": False})
    text = str({k: v for k, v in raw.items() if k != "config_xml"})
    for secret in ("not-a-real-secret", "not-a-real-licence", "SUBSCRIPTION", "mirror.example.com", SECRET):
        assert secret not in text
    assert raw["config_xml"] is None and "core/backup/download/this" not in fake.paths()
    assert raw["interfaces"][0]["config"] == {
        "descr": "WAN",
        "enable": "1",
        "ipaddr": "203.0.113.10",
        "subnet": "28",
    }


@pytest.mark.asyncio
async def test_collect_is_best_effort_past_a_refused_or_missing_endpoint(no_sleep):
    fake = _FakeFirewall()
    fake.fail = {"wireguard/service/show": 404, "routes/gateway/status": 403}
    async with _client(fake) as client:
        raw = await collect_opnsense(client)
    assert raw["gateways"] is None and raw["wireguard"] is None and raw["ipsec"]
    by_path = {e["path"]: e for e in raw["errors"]}
    assert by_path["/routes/gateway/status"]["status"] == 403 and "privilege" in by_path["/routes/gateway/status"]["message"]
    assert by_path["/wireguard/service/show"]["status"] == 404
    assert "no such endpoint" in by_path["/wireguard/service/show"]["message"]
    snapshot = build_snapshot(raw)
    assert snapshot["summary"]["wan_uplinks"] == 0 and len(snapshot["collection"]["errors"]) == 4


@pytest.mark.asyncio
async def test_collect_falls_back_on_a_release_whose_privileges_name_camel_case(no_sleep):
    fake = _FakeFirewall()
    fake.snake_forbidden = True
    async with _client(fake) as client:
        raw = await collect_opnsense(client)
    assert raw["errors"] == [] and raw["system"]["name"] == "fw-edge-1.example.com" and raw["routes"]
    assert "interfaces/overview/interfacesInfo" in fake.paths()


@pytest.mark.asyncio
async def test_collect_fails_on_a_rejected_key_or_when_nothing_answers(no_sleep):
    fake = _FakeFirewall()
    async with OpnsenseClient(BASE, KEY, "wrong", transport=httpx.MockTransport(fake.handler)) as client:
        with pytest.raises(OpnsenseApiError) as raised:
            await collect_opnsense(client)
    assert raised.value.status_code == 401 and len(fake.calls) == 1
    fake = _FakeFirewall()
    fake.fail = {path: 403 for path in [*fake.answers, *CAMEL]}
    async with _client(fake) as client:
        with pytest.raises(OpnsenseApiError) as raised:
            await collect_opnsense(client)
    assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_collect_skips_the_audit_while_another_firmware_task_runs(no_sleep):
    fake = _FakeFirewall()
    fake.running = "busy"
    async with _client(fake) as client:
        raw = await collect_opnsense(client)
    assert raw["audit"] is None and fake.audits == 0
    (warning,) = raw["errors"]
    assert warning["info"] is True and "another firmware task" in warning["message"]


@pytest.mark.asyncio
async def test_collect_stops_waiting_for_an_audit_that_does_not_finish(no_sleep):
    fake = _FakeFirewall()
    fake.audit_done = False
    async with _client(fake) as client:
        raw = await collect_opnsense(client, {"config_backup": False})
    assert raw["audit"] is None and fake.audits == 1
    assert fake.paths().count("core/firmware/upgradestatus") == collector_module.AUDIT_MAX_POLLS
    assert raw["errors"][0]["path"] == "/core/firmware/upgradestatus"


@pytest.mark.asyncio
async def test_collect_rejects_a_download_that_is_no_config_xml(no_sleep):
    fake = _FakeFirewall()
    fake.answers["core/backup/download/this"] = "<html>login</html>"
    async with _client(fake) as client:
        raw = await collect_opnsense(client)
    assert raw["config_xml"] is None and raw["errors"][0]["scope"] == "config"


def test_parse_audit_log_reads_packages_issues_and_cves():
    parsed = parse_audit_log(AUDIT_LOG)
    assert parsed["problems"] == 2
    first, second = parsed["findings"]
    assert first == {
        "package": "openssl",
        "version": "3.0.17",
        "description": "OpenSSL -- Sample out-of-bounds read",
        "cves": ["CVE-2026-0001", "CVE-2026-0002"],
        "url": "https://vuxml.FreeBSD.org/freebsd/00000000-0000-4000-8000-000000000001.html",
        "vuxml_id": "00000000-0000-4000-8000-000000000001",
    }
    assert second["package"] == "curl" and second["cves"] == ["CVE-2026-0003"]
    assert parse_audit_log(CLEAN_AUDIT) == {"findings": [], "problems": 0}
    # A package with two issues, a hyphenated name, and the recursive form.
    text = (
        "py311-cryptography-42.0.0_1 is vulnerable:\n  first issue\n  CVE: CVE-2026-1000\n"
        "  WWW: https://example.com/a\n\n  second issue\n  WWW: https://example.com/b\n\n"
        "  Packages that depend on py311-cryptography: py311-x\n\n1 problem(s) in 1 package(s) found.\n"
    )
    findings = parse_audit_log(text)["findings"]
    assert [(f["package"], f["version"], f["description"]) for f in findings] == [
        ("py311-cryptography", "42.0.0_1", "first issue"),
        ("py311-cryptography", "42.0.0_1", "second issue"),
    ]


# ── Normalize ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    return build_snapshot(build_sample_raw())


def test_snapshot_summary_and_nodes(snapshot):
    assert snapshot["provider"] == "opnsense" and snapshot["schema"] == 1
    summary = snapshot["summary"]
    assert summary["devices"] == 3 and summary["vpn_tunnels"] == 6 and summary["wan_uplinks"] == 4
    assert summary["version"] == "25.7.6" and summary["update_pending"] is True
    assert summary["vulnerable_packages"] == 2
    kinds = {n["id"]: n["kind"] for n in snapshot["nodes"]}
    assert kinds[FIREWALL] == "appliance"
    assert sorted(k for k, v in kinds.items() if v == "wan") == ["w:CORE_GW", "w:WAN2_GW", "w:WAN_GW", "w:WAN_GW6"]
    assert sum(1 for v in kinds.values() if v == "vpn_peer") == 6
    assert sorted(k for k, v in kinds.items() if v == "vpn_server") == ["ovpn:server:1", "ovpn:server:3"]
    firewall = _node(snapshot, FIREWALL)
    assert firewall["ip"] == "192.0.2.1" and firewall["model"] == "OPNsense"
    assert {s["name"] for s in snapshot["sites"]} == {"fw-edge-1.example.com", "VPN peers"}


def test_snapshot_firewall_sections(snapshot):
    firewall = _node(snapshot, FIREWALL)
    assert _titles(firewall) == [
        "Overview",
        "Interfaces",
        "Connected subnets",
        "Gateways",
        "Static routes",
        "Routing table",
        "IPsec tunnels",
        "WireGuard peers",
        "OpenVPN instances",
        "Firmware",
        "Pending updates",
        "Security audit",
        "Vulnerable packages",
    ]
    overview = _kv(firewall, "Overview")
    assert overview["Version"] == "25.7.6" and overview["Latest version"] == "25.7.7"
    assert overview["Update pending"] == "Yes"
    interfaces = {r["Interface"]: r for r in _table(firewall, "Interfaces")}
    assert interfaces["opt1"]["VLAN"] == "20" and interfaces["opt3"]["Status"] == "no carrier"
    assert interfaces["lan"]["IPv6"] == "2001:db8:10::1/64"
    gateways = {r["Gateway"]: r for r in _table(firewall, "Gateways")}
    assert gateways["WAN_GW"]["RTT"] == "4.2 ms" and gateways["WAN2_GW"]["Loss"] == "100.0 %"
    assert _kv(firewall, "Firmware")["Packages to update"] == "2"
    vulnerable = _table(firewall, "Vulnerable packages")
    assert vulnerable[0]["CVEs"] == "CVE-2026-0001, CVE-2026-0002"


def test_subnet_index_reads_connected_subnets_and_static_routes(snapshot):
    index = {(s["cidr"], s["kind"]): s for s in subnet_index(snapshot)}
    assert index[("192.0.2.0/25", "connected")]["node_id"] == FIREWALL
    assert index[("192.0.2.128/26", "connected")]["name"] == "DMZ"
    assert index[("2001:db8:10::/64", "connected")]
    assert index[("198.51.100.192/27", "static")]["node_id"] == FIREWALL
    # The disabled guest VLAN, the default route and host routes are not subnets.
    assert not any(cidr == "192.0.2.192/27" for cidr, _kind in index)
    assert not any(cidr in ("0.0.0.0/0", "192.0.2.1/32") for cidr, _kind in index)


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        ({"status": "none", "delay": "4.2 ms", "loss": "0.0 %"}, "active"),
        ({"status": "none", "delay": "~", "loss": "~"}, "unknown"),
        ({"status": "down", "loss": "100.0 %"}, "failed"),
        ({"status": "force_down"}, "failed"),
        ({"status": "delay"}, "degraded"),
        ({"status": "loss"}, "degraded"),
        ({"status": "delay+loss"}, "degraded"),
        ({"status": "pending"}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_gateway_status_vocabulary(item, expected):
    assert gateway_status(item) == expected


def test_tunnel_status_vocabularies():
    assert wireguard_status({"peer-status": "online"}) == "reachable"
    assert wireguard_status({"peer-status": "stale"}) == "degraded"
    assert wireguard_status({"peer-status": "offline"}) == "unreachable"
    # A release without peer-status: from the handshake.
    assert wireguard_status({"latest-handshake": 1000}, now=1100) == "reachable"
    assert wireguard_status({"latest-handshake": 1000}, now=5000) == "degraded"
    assert wireguard_status({"latest-handshake": 0}, now=5000) == "unreachable"
    assert openvpn_client_status({"status": "connected"}) == "reachable"
    assert openvpn_client_status({"status": "reconnecting"}) == "degraded"
    assert openvpn_client_status({"status": "failed"}) == "unreachable"
    assert openvpn_client_status({"status": None}) == "unreachable"


def test_gateways_and_tunnels_are_edges_with_their_monitor_data(snapshot):
    edges = {(e["a"], e["b"]): e for e in snapshot["edges"]}
    wan = edges[("w:WAN_GW", FIREWALL)]
    assert wan["kind"] == "uplink" and wan["status"] == "active" and wan["b_port"] == "WAN_GW"
    assert wan["detail"] == "RTT 4.2 ms, RTTsd 0.3 ms, loss 0.0 %"
    assert wan["metrics"] == {"loss_pct": 0.0, "rtt_ms": 4.2, "rttsd_ms": 0.3}
    assert edges[("w:CORE_GW", FIREWALL)]["metrics"] == {}
    tunnels = {e["b"]: (e["label"], e["status"]) for e in snapshot["edges"] if e["kind"] == "vpn3p"}
    assert tunnels == {
        "p:ipsec:198.51.100.20": ("IPsec", "reachable"),
        "p:ipsec:203.0.113.200": ("IPsec", "unreachable"),
        "p:wg:wg0:branch-2": ("WireGuard", "reachable"),
        "p:wg:wg0:branch-3": ("WireGuard", "degraded"),
        "p:ovpn:2": ("OpenVPN", "reachable"),
        "p:ovpn:4": ("OpenVPN", "degraded"),
    }
    assert _titles(_node(snapshot, "w:WAN_GW")) == ["Gateway"]
    assert _titles(_node(snapshot, "p:ipsec:198.51.100.20")) == ["IPsec peer"]
    assert _titles(_node(snapshot, "p:wg:wg0:branch-2")) == ["WireGuard peer"]
    assert _titles(_node(snapshot, "p:ovpn:2")) == ["OpenVPN peer"]
    server = _node(snapshot, "ovpn:server:1")
    assert _titles(server) == ["OpenVPN server", "Connected clients"]
    assert _table(server, "Connected clients")[0]["User"] == "ana"
    assert _node(snapshot, "ovpn:server:3")["status"] == "offline"


def test_firmware_and_audit_are_info_warnings(snapshot):
    warnings = snapshot["collection"]["errors"]
    assert [w["path"] for w in warnings] == ["/core/firmware/status", "/core/firmware/audit"]
    assert all(w["info"] for w in warnings)
    assert "25.7.6 to 25.7.7" in warnings[0]["message"] and "CVE-2026-0003" in warnings[1]["message"]


def test_config_xml_never_reaches_the_snapshot():
    raw = build_sample_raw()
    raw["config_xml"] = SAMPLE_CONFIG_XML
    built = build_snapshot(raw)
    assert "sample.hash" not in str(built) and "<opnsense>" not in str(built)


def test_availability_tracks_gateways_tunnels_and_servers(snapshot):
    entities = extract_entity_states("opnsense", 9, snapshot)
    types = {(e.entity_type, e.state) for e in entities}
    assert {("uplink", "up"), ("uplink", "down"), ("uplink", "degraded"), ("uplink", "unknown")} <= types
    assert {("tunnel", "up"), ("tunnel", "down"), ("tunnel", "degraded")} <= types
    assert ("device", "down") in types  # the OpenVPN server that does not run


def test_software_platform_and_import_device_type(snapshot):
    (device,) = snapshot_devices(snapshot, "opnsense")
    assert device["platform"] == "opnsense" and device["version"] == "25.7.6"
    (candidate,) = importable_devices(snapshot, "opnsense")["devices"]
    assert candidate["key"] == FIREWALL and candidate["ip"] == "192.0.2.1"
    assert candidate["device_type"] == "opnsense" and candidate["platform"] == "opnsense"
    assert candidate["capabilities"] == {"snmp_polling": True, "config_backup": False}


def test_audit_advisories_one_per_vuxml_entry():
    advisories = audit_advisories(build_sample_raw()["audit"], "25.7.6")
    assert [a["advisory_id"] for a in advisories] == [
        "opnsense-audit:00000000-0000-4000-8000-000000000001",
        "opnsense-audit:00000000-0000-4000-8000-000000000002",
    ]
    first = advisories[0]
    assert first["source"] == "opnsense-audit" and first["platform"] == "opnsense"
    assert first["affected_versions"] == ["25.7.6"] and first["cves"] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert first["severity"] == "medium" and "openssl-3.0.17" in first["summary"]
    assert audit_advisories(None, "25.7.6") == [] and audit_advisories({"findings": []}, "") == []


# ── HTTP API ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _forget_cached_snapshots(request):
    """The samples must not leak into the next test's map."""
    import netcontrol.routes.meraki_topology as routes_module
    from netcontrol.routes.topology import invalidate_topology_cache

    def forget() -> None:
        routes_module._SNAPSHOT_CACHE.clear()
        routes_module._HOST_FORWARDING.clear()
        invalidate_topology_cache()

    forget()
    request.addfinalizer(forget)


def _wait(client, job_id: str) -> dict:
    job: dict = {}
    for _ in range(400):
        job = client.get(f"/api/sources/builds/{job_id}").json()
        if job["status"] != "running":
            break
    return job


def _create(client, **fields):
    body = {"name": "Edge firewall", "provider": "opnsense", "org_id": "local", "base_url": BASE}
    body["api_key"] = f"{KEY}:{SECRET}"
    body.update(fields)
    return client.post("/api/sources", json=body)


def test_api_opnsense_crud_keeps_the_key_and_secret_write_only(api):  # noqa: F811
    listing = api.get("/api/sources").json()
    assert listing["opnsense_default_options"] == DEFAULT_OPTIONS and "appgate_default_options" in listing
    created = _create(api, base_url="https://192.0.2.1:8443/", org_id="", options={"include_vpn": 0})
    assert created.status_code == 201, created.text
    org = created.json()["org"]
    assert org["provider"] == "opnsense" and org["has_api_key"] is True and org["org_id"] == "local"
    assert org["base_url"] == "https://192.0.2.1:8443"
    assert org["options"] == {**DEFAULT_OPTIONS, "include_vpn": False}
    for text in (created.text, api.get("/api/sources").text):
        assert SECRET not in text and KEY not in text

    for bad_key in ("key-only", ":secret", "key:"):
        refused = _create(api, name=f"Bad {bad_key}", api_key=bad_key)
        assert refused.status_code == 400 and "key:secret" in refused.text
    assert _create(api, name="Plain http", base_url="http://fw1.example.com").status_code == 400
    assert _create(api, name="With path", base_url="https://fw1.example.com/ui").status_code == 400

    # Omitting the key keeps it; a new one must be key:secret too.
    kept = api.put(f"/api/sources/{org['id']}", json={"options": {"include_routes": False}})
    assert kept.status_code == 200 and kept.json()["org"]["has_api_key"] is True
    assert api.put(f"/api/sources/{org['id']}", json={"api_key": "no-colon"}).status_code == 400
    assert api.delete(f"/api/sources/{org['id']}").status_code == 200


def test_api_opnsense_sample_is_merged_into_the_topology(api):  # noqa: F811
    built = api.post("/api/sources/sample?provider=opnsense")
    assert built.status_code == 201, built.text
    assert built.json()["summary"]["vpn_tunnels"] == 6
    org_ref = built.json()["org_ref"]
    org = next(o for o in api.get("/api/sources").json()["orgs"] if o["id"] == org_ref)
    assert org["name"] == "Sample OPNsense firewall (demo data)" and org["provider"] == "opnsense"
    assert org["base_url"] == "https://192.0.2.1" and org["org_id"] == "local"

    graph = api.get("/api/topology").json()
    ours = [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "opnsense"]
    assert {"appliance", "wan", "vpn_peer", "vpn_server"} <= {n["meraki"]["kind"] for n in ours}
    details = api.get(f"/api/sources/nodes?org_ref={org_ref}&node_id={FIREWALL}").json()
    assert details["provider"] == "opnsense" and "Gateways" in [s["title"] for s in details["sections"]]
    subnets = api.get("/api/sources/subnets").json()["subnets"]
    dmz = next(s for s in subnets if s["cidr"] == "192.0.2.128/26")
    assert dmz["provider"] == "opnsense" and dmz["kind"] == "connected"
    source = next(s for s in api.get("/api/topology/sources").json()["sources"] if s["type"] == "opnsense")
    assert source["demo"] and not source["can_collect"]
    # The software page knows the platform.
    catalog = api.get("/api/software/overview").json()["platform_catalog"]
    assert {"key": "opnsense", "label": "OPNsense"} in [{k: p[k] for k in ("key", "label")} for p in catalog]
    # Rebuilding refreshes the same entry.
    assert api.post("/api/sources/sample?provider=opnsense").json()["org_ref"] == org_ref


def test_api_opnsense_build_stores_config_backups_and_audit_advisories(api, monkeypatch):  # noqa: F811
    import netcontrol.routes.meraki_topology as routes_module

    # Not asyncio.sleep: the app's own loops run in this process too.
    monkeypatch.setattr(collector_module, "AUDIT_POLL_SECONDS", 0)

    fake = _FakeFirewall()
    real_client = routes_module.OpnsenseClient

    def _client_factory(base_url, key, secret, **kwargs):
        assert (base_url, key, secret) == (BASE, KEY, SECRET) and kwargs["verify_tls"] is False
        kwargs.update(transport=httpx.MockTransport(fake.handler), requests_per_second=1000)
        return real_client(base_url, key, secret, **kwargs)

    monkeypatch.setattr(routes_module, "OpnsenseClient", _client_factory)
    org = _create(api, options={"verify_tls": False}).json()["org"]

    checked = api.post(f"/api/sources/{org['id']}/validate").json()
    assert checked["ok"] is True and checked["message"] == "API key OK: fw-edge-1.example.com (OPNsense 25.7.6-amd64)"

    # 1. Not yet an inventory host: nothing stored, a warning says to import it.
    job = _wait(api, api.post(f"/api/sources/{org['id']}/build").json()["job_id"])
    assert job["status"] == "partial", job
    snapshot = api.get(f"/api/sources/snapshots/{job['result']['snapshot_id']}/data")
    assert "sample.hash" not in snapshot.text and SECRET not in snapshot.text
    messages = [e["message"] for e in snapshot.json()["collection"]["errors"]]
    assert any("not an inventory host yet" in m for m in messages)
    assert _kv(_node(snapshot.json(), FIREWALL), "Config backup")["Result"].startswith("Not stored")

    # The audit findings are advisories matched to the firewall's version.
    advisories = {a["advisory_id"]: a for a in api.get("/api/software/advisories").json()["advisories"]}
    ours = {k: v for k, v in advisories.items() if v["source"] == "opnsense-audit"}
    assert len(ours) == 2 and all(a["affected_versions"] == ["25.7.6"] for a in ours.values())
    alerts = [a for a in api.get("/api/software/alerts").json()["alerts"] if a["advisory_id"] in ours]
    assert len(alerts) == 2

    # 2. Import the firewall, collect again: the backup is stored.
    imported = api.post(
        f"/api/sources/{org['id']}/import-devices", json={"device_keys": [FIREWALL], "new_group_name": "Firewalls"}
    )
    assert imported.status_code == 200 and imported.json()["counts"]["added"] == 1, imported.text
    job = _wait(api, api.post(f"/api/sources/{org['id']}/build").json()["job_id"])
    data = api.get(f"/api/sources/snapshots/{job['result']['snapshot_id']}/data").json()
    backup = _kv(_node(data, FIREWALL), "Config backup")
    assert backup["Result"] == "New backup stored"
    (host,) = api.get(f"/api/inventory/{imported.json()['group']['id']}/hosts").json()
    assert (host["ip_address"], host["device_type"]) == ("192.0.2.1", "opnsense")
    backups = api.get("/api/config-backups").json()
    ours_backups = [b for b in backups if b.get("capture_method") == "opnsense-api"]
    assert len(ours_backups) == 1 and ours_backups[0]["host_id"] == host["id"]
    assert not any("not an inventory host" in e["message"] for e in data["collection"]["errors"])

    # 3. Unchanged config.xml: no second row, the newest is re-checked.
    job = _wait(api, api.post(f"/api/sources/{org['id']}/build").json()["job_id"])
    data = api.get(f"/api/sources/snapshots/{job['result']['snapshot_id']}/data").json()
    assert _kv(_node(data, FIREWALL), "Config backup")["Result"] == "Unchanged since the newest backup"
    assert len([b for b in api.get("/api/config-backups").json() if b.get("capture_method") == "opnsense-api"]) == 1
    # Repeated collections do not duplicate the advisories.
    advisories = api.get("/api/software/advisories").json()["advisories"]
    assert sum(1 for a in advisories if a["source"] == "opnsense-audit") == 2

    # 4. The audit finds nothing any more: the version is withdrawn, the alerts resolve.
    fake.audit_log = CLEAN_AUDIT
    _wait(api, api.post(f"/api/sources/{org['id']}/build").json()["job_id"])
    advisories = [a for a in api.get("/api/software/advisories").json()["advisories"] if a["source"] == "opnsense-audit"]
    assert len(advisories) == 2 and all(a["affected_versions"] == [] for a in advisories)
    open_alerts = [a for a in api.get("/api/software/alerts").json()["alerts"] if a["advisory_id"] in ours]
    assert open_alerts == []


def test_api_opnsense_build_reports_a_rejected_key(api, monkeypatch):  # noqa: F811
    import netcontrol.routes.meraki_topology as routes_module

    fake = _FakeFirewall()
    real_client = routes_module.OpnsenseClient
    monkeypatch.setattr(
        routes_module,
        "OpnsenseClient",
        lambda base_url, key, secret, **kw: real_client(
            base_url, key, secret, **{**kw, "transport": httpx.MockTransport(fake.handler)}
        ),
    )
    org = _create(api, api_key=f"{KEY}:wrong-secret").json()["org"]
    job = _wait(api, api.post(f"/api/sources/{org['id']}/build").json()["job_id"])
    assert job["status"] == "failed" and job["error"] == "OPNsense rejected the API key and secret (HTTP 401)"
    checked = api.post(f"/api/sources/{org['id']}/validate").json()
    assert checked == {
        "ok": False,
        "message": "OPNsense rejected the API key and secret (HTTP 401)",
        "organizations": [],
    }
