"""Tests for Meraki security compliance.

* catalog      - every check is well-formed; built-in Meraki profiles name
                 real checks
* evaluation   - the sample organization produces the expected findings per
                 target (organization / network / switch), unknown checks
                 and unreadable payloads are reported, not swallowed
* collector    - fetches only what the profile's checks need; 403 marks a
                 payload unreadable, 404 skips it
* host scans   - rules of type "meraki" are ignored by the running-config
                 evaluator
* HTTP API     - checks catalog, assignment CRUD, background scan of the
                 demo organization, results, status, summary, validation
"""

from __future__ import annotations

import json

import httpx
import netcontrol.app as app_module
import pytest
import routes.database as db_module
from netcontrol.integrations.meraki.client import MerakiClient
from netcontrol.integrations.meraki.compliance import (
    CHECKS,
    ENDPOINTS,
    SCOPES,
    Unreadable,
    build_sample_compliance_raw,
    catalog,
    collect_compliance_data,
    evaluate_profile,
    required_endpoints,
    rule_template,
    summarise_results,
)
from routes.builtin_compliance_profiles import BUILTIN_PROFILES

# ── Catalog ──────────────────────────────────────────────────────────────────


def test_every_check_is_well_formed():
    assert len(CHECKS) >= 35
    for check in CHECKS.values():
        assert check.scope in SCOPES
        assert check.name and check.description and check.ios_equivalent
        for key in check.requires:
            assert key in ENDPOINTS or key in ("ports", "device", "network", "ssid"), (check.id, key)
        if check.scope == "device":
            assert "ports" in check.requires or any(
                ENDPOINTS[k][0] == "device" for k in check.requires if k in ENDPOINTS
            )
    entries = catalog()
    assert {e["id"] for e in entries} == set(CHECKS)
    assert all(e["category_label"] for e in entries)


def test_rule_template_selects_the_check_with_defaults():
    rule = rule_template("switch_port_access_policy")
    assert rule["type"] == "meraki" and rule["check"] == "switch_port_access_policy"
    assert rule["params"]["allowed_types"] == ["Sticky MAC allow list", "MAC allow list", "Custom access policy"]
    assert "params" not in rule_template("mx_amp_enabled")


def test_builtin_meraki_profiles_reference_known_checks():
    meraki_profiles = [p for p in BUILTIN_PROFILES if p[0].startswith("Meraki ")]
    assert len(meraki_profiles) == 4
    for _name, _desc, _sev, rules in meraki_profiles:
        assert rules
        for rule in rules:
            assert rule["type"] == "meraki"
            assert rule["check"] in CHECKS, rule["check"]
            # The built-in parameters are the check's defaults.
            assert rule.get("params", {}) == CHECKS[rule["check"]].params


def test_required_endpoints_follow_the_rules():
    assert required_endpoints([rule_template("switch_port_bpdu_guard")]) == {"switch_ports"}
    assert required_endpoints([rule_template("switch_port_unused_disabled")]) == {"switch_ports", "port_statuses"}
    assert required_endpoints([rule_template("switch_dhcp_rogue_alert")]) == {"dhcp_server_policy", "alerts"}
    assert required_endpoints([rule_template("ssid_pmf_enabled")]) == {"ssids"}
    assert required_endpoints([rule_template("ssid_guest_isolated")]) == {"ssids", "ssid_l3_firewall"}
    assert required_endpoints([{"type": "must_contain", "pattern": "x"}]) == set()
    assert required_endpoints([{"type": "meraki", "check": "nope"}]) == set()


# ── Evaluation ───────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def sample_results() -> list[dict]:
    rules = [rule_template(check_id) for check_id in CHECKS]
    return evaluate_profile(rules, build_sample_compliance_raw())


def _target(results: list[dict], kind: str, name: str) -> dict:
    return next(r for r in results if r["target_kind"] == kind and r["target_name"] == name)


def _failed(result: dict) -> set[str]:
    return {f["check"] for f in result["findings"] if f["passed"] is False}


def test_sample_targets_cover_org_networks_and_switches(sample_results):
    kinds = {r["target_kind"] for r in sample_results}
    assert kinds == {"org", "network", "device", "ssid"}
    assert sample_results[0]["target_kind"] == "org"
    # Only switches are device targets; access points and appliances have no port checks.
    assert all(r["model"].startswith("MS") for r in sample_results if r["target_kind"] == "device")
    counts = summarise_results(sample_results)
    assert counts["targets"] == len(sample_results) and counts["errors"] == 0
    assert counts["non_compliant"] > 0 and counts["compliant"] > 0


def test_sample_weak_branch_fails_the_switch_and_appliance_checks(sample_results):
    boston = _target(sample_results, "network", "Branch-Boston")
    assert boston["status"] == "non-compliant"
    assert {
        "switch_dhcp_server_policy",
        "switch_arp_inspection",
        "switch_storm_control",
        "mx_ip_source_guard",
        "mx_ids_prevention",
        "mx_firewalled_services",
        "mx_port_forwarding_restricted",
        "mx_l3_firewall_logging",
        "net_syslog_configured",
        "net_snmp_no_v2c",
    } <= _failed(boston)
    # The evidence names the offending object.
    pf = next(f for f in boston["findings"] if f["check"] == "mx_port_forwarding_restricted")
    assert pf["evidence"] and "Camera NVR" in pf["evidence"][0]

    atlanta = _target(sample_results, "network", "Branch-Atlanta")
    assert atlanta["status"] == "compliant", _failed(atlanta)


def test_sample_weak_switch_fails_port_checks_with_port_evidence(sample_results):
    weak = _target(sample_results, "device", "Branch-Boston-SW1")
    assert weak["status"] == "non-compliant"
    assert {
        "switch_port_access_policy",
        "switch_port_bpdu_guard",
        "switch_port_native_vlan",
        "switch_port_trunk_pruned",
        "switch_port_storm_control",
    } <= _failed(weak)
    access = next(f for f in weak["findings"] if f["check"] == "switch_port_access_policy")
    assert "3 of" in access["detail"]
    assert any("port 5" in e for e in access["evidence"])
    # The unused-ports check needs live port statuses, which the sample does
    # not carry: it is not applicable rather than failed.
    assert "switch_port_unused_disabled" not in {f["check"] for f in weak["findings"]}

    healthy = _target(sample_results, "device", "HQ-DataCenter-SW1")
    assert healthy["status"] == "compliant", _failed(healthy)


def test_sample_ssids_are_targets_with_per_ssid_findings(sample_results):
    ssids = [r for r in sample_results if r["target_kind"] == "ssid"]
    # Two enabled SSIDs per wireless network, each its own target, in its network.
    networks = {r["network_name"] for r in sample_results if r["target_kind"] == "network"}
    assert len(ssids) == 2 * len(networks)
    assert all(r["network_name"] and r["model"].startswith("SSID ") for r in ssids)

    weak_corp = next(r for r in ssids if r["network_name"] == "Branch-Boston" and r["target_name"] == "Corp")
    assert _failed(weak_corp) == {"ssid_wpa2_or_better", "ssid_radius_redundancy", "ssid_pmf_enabled"}
    # Guest-only checks leave no finding on a corporate SSID.
    corp_checks = {f["check"] for f in weak_corp["findings"]}
    assert not corp_checks & {"ssid_guest_isolated", "ssid_guest_lan_firewall", "ssid_guest_bandwidth_limit"}
    assert "ssid_splash_on_open" not in corp_checks

    weak_guest = next(r for r in ssids if r["network_name"] == "Branch-Boston" and r["target_name"] == "Guest")
    assert _failed(weak_guest) == {"ssid_guest_isolated", "ssid_guest_lan_firewall", "ssid_guest_bandwidth_limit"}
    lan = next(f for f in weak_guest["findings"] if f["check"] == "ssid_guest_lan_firewall")
    assert "allow" in lan["detail"]
    assert "ssid_enterprise_auth" not in {f["check"] for f in weak_guest["findings"]}

    good_guest = next(r for r in ssids if r["network_name"] == "Branch-Atlanta" and r["target_name"] == "Guest")
    assert good_guest["status"] == "compliant", _failed(good_guest)
    good_corp = next(r for r in ssids if r["network_name"] == "Branch-Atlanta" and r["target_name"] == "Corp")
    assert good_corp["status"] == "compliant", _failed(good_corp)


def test_ssid_checks_without_the_per_ssid_payload():
    raw = build_sample_compliance_raw()
    raw["ssids_detail"] = {}
    rules = [rule_template("ssid_guest_isolated"), rule_template("ssid_guest_lan_firewall")]
    results = evaluate_profile(rules, raw)
    guests = [r for r in results if r["target_name"] == "Guest"]
    assert guests
    for g in guests:
        checks = {f["check"] for f in g["findings"]}
        # The optional firewall payload is missing: isolation is judged on the
        # SSID alone; the firewall-only check is not applicable.
        assert checks == {"ssid_guest_isolated"}
    # An unreadable SSID list becomes one unreadable target for the network.
    raw["networks_detail"]["N_1000"]["ssids"] = Unreadable("HTTP 403")
    results = evaluate_profile(rules, raw)
    hq = next(r for r in results if r["network_id"] == "N_1000")
    assert hq["status"] == "error" and hq["target_id"] == "N_1000:*" and hq["unreadable_rules"] == 2


def test_sample_org_findings_name_the_admins(sample_results):
    org = sample_results[0]
    assert org["status"] == "non-compliant"
    failed = _failed(org)
    assert {"org_admins_2fa", "org_admins_active", "org_login_2fa_enforced"} <= failed
    assert "org_snmp_v3_only" not in failed and "org_login_lockout" not in failed
    two_fa = next(f for f in org["findings"] if f["check"] == "org_admins_2fa")
    assert two_fa["evidence"] == ["Former Contractor <contractor@example.net>"]


def test_rule_params_override_defaults():
    raw = build_sample_compliance_raw()
    strict = {"type": "meraki", "check": "org_login_lockout", "params": {"max_attempts": 3}}
    results = evaluate_profile([strict], raw)
    assert results[0]["findings"][0]["passed"] is False
    assert "5 attempts" in results[0]["findings"][0]["detail"]
    # Exempting the weak ports by name clears the access-policy finding.
    exempt = {
        "type": "meraki",
        "check": "switch_port_access_policy",
        "params": {"exempt_name_pattern": "^Access [5-7]$"},
    }
    weak = _target(evaluate_profile([exempt], raw), "device", "Branch-Boston-SW1")
    assert weak["status"] == "compliant"


def test_unknown_check_and_unreadable_payload_are_reported():
    raw = build_sample_compliance_raw()
    raw["org"]["admins"] = Unreadable("HTTP 403")
    raw["switch_ports"] = Unreadable("HTTP 403")
    rules = [
        {"name": "Typo", "type": "meraki", "check": "does_not_exist"},
        rule_template("org_admins_2fa"),
        rule_template("org_login_strong_passwords"),
        rule_template("switch_port_bpdu_guard"),
    ]
    results = evaluate_profile(rules, raw)
    org = results[0]
    by_check = {f["check"]: f for f in org["findings"]}
    assert by_check["does_not_exist"]["unreadable"] and "Unknown Meraki check" in by_check["does_not_exist"]["detail"]
    assert by_check["org_admins_2fa"]["unreadable"] and "HTTP 403" in by_check["org_admins_2fa"]["detail"]
    assert by_check["org_login_strong_passwords"]["passed"] is True
    # Unreadable is not a violation: the status says the scan could not tell.
    assert org["status"] == "error" and org["failed_rules"] == 0 and org["unreadable_rules"] == 2
    switches = [r for r in results if r["target_kind"] == "device"]
    assert switches and all(r["status"] == "error" for r in switches)


def test_non_meraki_rules_and_inapplicable_networks_are_ignored():
    raw = build_sample_compliance_raw()
    # A wireless-only network has no switch or appliance checks.
    raw["networks"][0]["productTypes"] = ["wireless"]
    rules = [{"type": "must_contain", "pattern": "ntp"}, rule_template("switch_rstp_enabled")]
    results = evaluate_profile(rules, raw)
    names = {r["target_name"] for r in results}
    assert raw["networks"][0]["name"] not in names
    assert all(r["target_kind"] == "network" for r in results)
    assert evaluate_profile([{"type": "regex_match", "pattern": "x"}], raw) == []


# ── Collector ────────────────────────────────────────────────────────────────


def _client(handler) -> MerakiClient:
    return MerakiClient("test-key", transport=httpx.MockTransport(handler), requests_per_second=50)


@pytest.mark.asyncio
async def test_collector_fetches_only_what_the_rules_need():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.split("/api/v1/", 1)[1]
        seen.append(path)
        if path == "organizations/1":
            return httpx.Response(200, json={"id": "1", "name": "Acme"})
        if path == "organizations/1/networks":
            return httpx.Response(
                200,
                json=[
                    {"id": "N1", "name": "Site A", "productTypes": ["switch", "appliance"]},
                    {"id": "N2", "name": "Site B", "productTypes": ["wireless"]},
                    {"id": "N3", "name": "Site C", "productTypes": ["wireless"]},
                ],
            )
        if path == "organizations/1/devices":
            return httpx.Response(
                200,
                json=[
                    {"serial": "S1", "name": "sw1", "model": "MS120", "networkId": "N1", "productType": "switch"},
                    {"serial": "A1", "name": "ap1", "model": "MR46", "networkId": "N2", "productType": "wireless"},
                ],
            )
        if path == "organizations/1/switch/ports/bySwitch":
            return httpx.Response(
                200,
                json=[
                    {
                        "serial": "S1",
                        "ports": [
                            {"portId": "1", "enabled": True, "type": "access", "stpGuard": "disabled", "vlan": 10},
                            {"portId": "2", "enabled": True, "type": "trunk", "stpGuard": "loop guard", "vlan": 99},
                        ],
                    }
                ],
            )
        if path == "networks/N1/switch/dhcpServerPolicy":
            return httpx.Response(403, json={"errors": ["forbidden"]})
        if path == "networks/N1/switch/stp":
            return httpx.Response(404, json={"errors": ["not found"]})
        if path == "networks/N2/wireless/ssids":
            return httpx.Response(
                200,
                json=[
                    {
                        "number": 0,
                        "name": "Guest WiFi",
                        "enabled": True,
                        "authMode": "psk",
                        "ipAssignmentMode": "Bridge mode",
                    },
                    {"number": 1, "name": "Unused", "enabled": False, "authMode": "open"},
                ],
            )
        if path == "networks/N3/wireless/ssids":
            return httpx.Response(403, json={"errors": ["forbidden"]})
        if path == "networks/N2/wireless/ssids/0/firewall/l3FirewallRules":
            return httpx.Response(
                200,
                json={
                    "rules": [{"comment": "Wireless clients accessing LAN", "policy": "deny", "destCidr": "Local LAN"}]
                },
            )
        if path.endswith("syslogServers"):
            return httpx.Response(200, json={"servers": [{"host": "10.0.0.1", "port": 514, "roles": ["Flows"]}]})
        raise AssertionError(f"unexpected call {path}")

    rules = [
        rule_template("switch_dhcp_server_policy"),
        rule_template("switch_rstp_enabled"),
        rule_template("switch_port_bpdu_guard"),
        rule_template("net_syslog_configured"),
        rule_template("ssid_guest_isolated"),
    ]
    async with _client(handler) as client:
        raw = await collect_compliance_data(client, "1", rules)

    # Switch endpoints only for the switch network; syslog for both; no
    # wireless, appliance or organization endpoints were requested.
    assert "networks/N2/switch/dhcpServerPolicy" not in seen
    assert "networks/N2/syslogServers" in seen and "networks/N1/syslogServers" in seen
    assert not any("loginSecurity" in p for p in seen)
    # The per-SSID firewall is read for the enabled SSID only, and never for the switch network.
    assert "networks/N2/wireless/ssids/0/firewall/l3FirewallRules" in seen
    assert not any("ssids/1/" in p for p in seen) and not any(p.startswith("networks/N1/wireless") for p in seen)
    assert raw["ssids_detail"]["N2"]["0"]["ssid_l3_firewall"]["rules"]
    assert isinstance(raw["networks_detail"]["N1"]["dhcp_server_policy"], Unreadable)
    assert raw["networks_detail"]["N1"]["stp"] is None
    assert raw["switch_ports"]["S1"][0]["portId"] == "1"
    assert raw["errors"] and raw["errors"][0]["status"] == 403

    results = evaluate_profile(rules, raw)
    site_a = _target(results, "network", "Site A")
    checks = {f["check"]: f for f in site_a["findings"]}
    assert checks["switch_dhcp_server_policy"]["unreadable"]
    assert "switch_rstp_enabled" not in checks  # 404: not applicable
    assert checks["net_syslog_configured"]["passed"] is True
    sw1 = _target(results, "device", "sw1")
    assert _failed(sw1) == {"switch_port_bpdu_guard"}
    assert not any(r["target_name"] == "ap1" for r in results)
    guest = _target(results, "ssid", "Guest WiFi")
    assert guest["status"] == "compliant" and "denies Local LAN" in guest["findings"][0]["detail"]
    site_c = next(r for r in results if r["target_kind"] == "ssid" and r["network_name"] == "Site C")
    assert site_c["status"] == "error"


@pytest.mark.asyncio
async def test_collector_requires_the_inventory():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"errors": ["Invalid API key"]})

    from netcontrol.integrations.meraki.client import MerakiApiError

    async with _client(handler) as client:
        with pytest.raises(MerakiApiError) as exc:
            await collect_compliance_data(client, "1", [rule_template("org_admins_2fa")])
    assert exc.value.status_code == 401


# ── Host scans ignore Meraki rules ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_host_scan_skips_meraki_rules(monkeypatch):
    import netcontrol.routes.compliance as compliance_module

    async def _fake_capture(_host, _creds):
        return "hostname sw1\nip dhcp snooping\n"

    monkeypatch.setattr(compliance_module, "_capture_running_config", _fake_capture)
    profile = {
        "rules": json.dumps(
            [
                {"name": "snooping", "type": "must_contain", "pattern": "ip dhcp snooping"},
                rule_template("switch_dhcp_server_policy"),
            ]
        )
    }
    result = await compliance_module._evaluate_host_compliance({"id": 1, "ip_address": "10.0.0.1"}, profile, {})
    assert result["status"] == "compliant"
    assert result["total_rules"] == 1 and result["passed_rules"] == 1
    assert [f["name"] for f in json.loads(result["findings"])] == ["snooping"]


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
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "meraki-compliance.db"))
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-meraki-compliance")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_compliance as routes_module
    import netcontrol.routes.meraki_topology as topology_module

    topology_module._SNAPSHOT_CACHE.clear()
    routes_module._running_scans.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def _wait_for_job(api, job_id: str) -> dict:
    job: dict = {}
    for _ in range(400):
        resp = api.get(f"/api/compliance/meraki/scans/{job_id}")
        assert resp.status_code == 200, resp.text
        job = resp.json()
        if job["status"] != "running":
            break
    return job


def _meraki_profile_id(api, name: str) -> int:
    api.post("/api/compliance/profiles/load-builtin")
    return next(p["id"] for p in api.get("/api/compliance/profiles").json() if p["name"] == name)


def test_api_checks_catalog_and_orgs(api):
    api._c.cookies.clear()
    assert api.get("/api/compliance/meraki/checks").status_code == 401


def test_api_catalog_lists_checks_with_rule_templates(api):
    body = api.get("/api/compliance/meraki/checks").json()
    ids = {c["id"] for c in body["checks"]}
    assert "switch_dhcp_server_policy" in ids and "switch_port_access_policy" in ids
    port = next(c for c in body["checks"] if c["id"] == "switch_port_access_policy")
    assert port["rule"]["type"] == "meraki" and port["scope"] == "device"
    assert body["categories"]["switching"]

    # Only Meraki organizations are offered (never their keys).
    assert api.get("/api/compliance/meraki/orgs").json() == []
    api.post("/api/meraki/sample")
    orgs = api.get("/api/compliance/meraki/orgs").json()
    assert len(orgs) == 1 and orgs[0]["is_sample"] and not orgs[0]["has_api_key"]
    assert "api_key" not in orgs[0] and "api_key_enc" not in orgs[0]


def test_api_profile_validation_rejects_unknown_meraki_check(api):
    bad = api.post(
        "/api/compliance/profiles",
        json={"name": "Bad", "rules": [{"name": "x", "type": "meraki", "check": "no_such_check"}]},
    )
    assert bad.status_code == 400 and "Unknown Meraki check" in bad.text
    ok = api.post(
        "/api/compliance/profiles",
        json={"name": "Good", "rules": [rule_template("mx_amp_enabled")]},
    )
    assert ok.status_code == 201
    worse = api.put(
        f"/api/compliance/profiles/{ok.json()['id']}",
        json={"rules": [{"type": "meraki", "check": "mx_amp_enabled", "params": "nope"}]},
    )
    assert worse.status_code == 400


def test_api_assignment_crud_and_scan_of_the_demo_organization(api):
    org_ref = api.post("/api/meraki/sample").json()["org_ref"]
    profile_id = _meraki_profile_id(api, "Meraki Switch Security Baseline")

    # A profile without Meraki rules cannot be assigned to an organization.
    ios_profile = next(p["id"] for p in api.get("/api/compliance/profiles").json() if p["name"].startswith("CIS IOS"))
    refused = api.post("/api/compliance/meraki/assignments", json={"profile_id": ios_profile, "org_ref": org_ref})
    assert refused.status_code == 400

    created = api.post(
        "/api/compliance/meraki/assignments",
        json={"profile_id": profile_id, "org_ref": org_ref, "interval_seconds": 7200},
    )
    assert created.status_code == 201, created.text
    assignment_id = created.json()["id"]
    dup = api.post("/api/compliance/meraki/assignments", json={"profile_id": profile_id, "org_ref": org_ref})
    assert dup.status_code == 409

    listed = api.get("/api/compliance/meraki/assignments").json()
    assert len(listed) == 1
    assert listed[0]["profile_name"] == "Meraki Switch Security Baseline"
    assert listed[0]["org_name"].startswith("Sample Organization") and listed[0]["enabled"] is True
    assert listed[0]["interval_seconds"] == 7200 and listed[0]["last_scan_at"] is None

    updated = api.put(f"/api/compliance/meraki/assignments/{assignment_id}", json={"enabled": False})
    assert updated.status_code == 200 and updated.json()["enabled"] is False

    started = api.post(f"/api/compliance/meraki/assignments/{assignment_id}/scan-now")
    assert started.status_code == 202, started.text
    job = _wait_for_job(api, started.json()["job_id"])
    assert job["status"] == "completed", job
    result = job["result"]
    assert result["targets"] > 0 and result["non_compliant"] >= 2 and result["errors"] == 0
    assert result["status"] == "non-compliant"

    after = api.get(f"/api/compliance/meraki/assignments?profile_id={profile_id}").json()[0]
    assert after["last_scan_at"] and after["last_scan_status"] == "non-compliant"

    rows = api.get(f"/api/compliance/meraki/results?scan_id={result['scan_id']}&limit=500").json()
    assert len(rows) == result["targets"]
    kinds = {r["target_kind"] for r in rows}
    assert kinds == {"network", "device"}  # the switch baseline has no organization checks
    assert all("findings" not in r for r in rows)
    weak = next(r for r in rows if r["target_name"] == "Branch-Boston-SW1")
    assert weak["status"] == "non-compliant" and weak["model"] == "MS120-24P"
    detail = api.get(f"/api/compliance/meraki/results/{weak['id']}").json()
    assert isinstance(detail["findings"], list)
    failed = [f for f in detail["findings"] if f["passed"] is False]
    assert failed and all(f["evidence"] for f in failed if f["check"].startswith("switch_port_"))

    status = api.get(f"/api/compliance/meraki/status?org_ref={org_ref}").json()
    assert len(status) == result["targets"]
    assert status[0]["status"] == "non-compliant"  # worst first

    summary = api.get("/api/compliance/meraki/summary").json()
    assert summary["targets_scanned"] == result["targets"]
    assert summary["targets_non_compliant"] == result["non_compliant"]
    assert summary["last_scan_at"]

    # The host summary and host status stay host-only.
    assert api.get("/api/compliance/summary").json()["hosts_scanned"] == 0

    deleted = api.delete(f"/api/compliance/meraki/results/{weak['id']}")
    assert deleted.status_code == 200
    assert api.get(f"/api/compliance/meraki/results/{weak['id']}").status_code == 404

    assert api.delete(f"/api/compliance/meraki/assignments/{assignment_id}").status_code == 200
    assert api.get("/api/compliance/meraki/assignments").json() == []
    # Results outlive their assignment.
    assert len(api.get(f"/api/compliance/meraki/results?scan_id={result['scan_id']}&limit=500").json()) == len(rows) - 1


def test_api_on_demand_scan_runs_one_per_organization(api):
    org_ref = api.post("/api/meraki/sample").json()["org_ref"]
    profile_id = _meraki_profile_id(api, "Meraki Dashboard Access Hardening")
    started = api.post("/api/compliance/meraki/scan", json={"profile_id": profile_id, "org_ref": org_ref})
    assert started.status_code == 202, started.text
    # A second scan of the same organization while one runs is refused (or
    # the first has already finished, in which case it is accepted).
    second = api.post("/api/compliance/meraki/scan", json={"profile_id": profile_id, "org_ref": org_ref})
    assert second.status_code in (202, 409)
    job = _wait_for_job(api, started.json()["job_id"])
    assert job["status"] == "completed", job
    rows = api.get(f"/api/compliance/meraki/results?scan_id={job['result']['scan_id']}").json()
    assert len(rows) == 1 and rows[0]["target_kind"] == "org"
    assert rows[0]["status"] == "non-compliant" and rows[0]["assignment_id"] is None

    missing = api.post("/api/compliance/meraki/scan", json={"profile_id": profile_id, "org_ref": 999})
    assert missing.status_code == 404
    assert api.get("/api/compliance/meraki/scans/nope").status_code == 404


def test_api_scan_requires_an_api_key_unless_sample(api, monkeypatch):
    org = api.post("/api/meraki/orgs", json={"name": "Acme", "org_id": "1"}).json()["org"]
    profile_id = _meraki_profile_id(api, "Meraki Wireless Security Baseline")
    refused = api.post("/api/compliance/meraki/scan", json={"profile_id": profile_id, "org_ref": org["id"]})
    assert refused.status_code == 400

    # With a key, the collector is called with the resolved organization id.
    import netcontrol.routes.meraki_compliance as routes_module

    async def _fake_collect(_client, org_id, rules, _options, progress):
        assert org_id == "1" and all(r["type"] == "meraki" for r in rules)
        progress({"phase": "networks"})
        raw = build_sample_compliance_raw()
        raw["organization"] = {"id": "1", "name": "Acme"}
        return raw

    monkeypatch.setattr(routes_module, "collect_compliance_data", _fake_collect)
    api.put(f"/api/meraki/orgs/{org['id']}", json={"api_key": "k"})
    started = api.post("/api/compliance/meraki/scan", json={"profile_id": profile_id, "org_ref": org["id"]})
    assert started.status_code == 202, started.text
    job = _wait_for_job(api, started.json()["job_id"])
    assert job["status"] == "completed", job
    assert job["result"]["org_name"] == "Acme"
    rows = api.get("/api/compliance/meraki/results").json()
    assert rows and all(r["target_kind"] == "ssid" for r in rows)


def test_scheduled_loop_runs_due_meraki_assignments(api):
    import asyncio

    import netcontrol.routes.compliance as compliance_module

    org_ref = api.post("/api/meraki/sample").json()["org_ref"]
    profile_id = _meraki_profile_id(api, "Meraki Security Appliance Baseline")
    created = api.post("/api/compliance/meraki/assignments", json={"profile_id": profile_id, "org_ref": org_ref})
    assert created.status_code == 201

    # Run the loop body inside the app's event loop (the TestClient portal).
    portal = api._c.portal
    assert portal is not None
    stats = portal.call(lambda: compliance_module._run_compliance_check_once(force=True))
    assert stats["meraki_assignments_run"] == 1
    assert stats["meraki_targets_scanned"] > 0 and stats["meraki_violations"] >= 1
    # Not due again straight away.
    again = portal.call(lambda: compliance_module._run_compliance_check_once(force=True))
    assert again["meraki_assignments_run"] == 0
    listed = api.get("/api/compliance/meraki/assignments").json()
    assert listed[0]["last_scan_status"] == "non-compliant"
    del asyncio
