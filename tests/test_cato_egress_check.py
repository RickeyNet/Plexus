"""The Cato egress vs cloud allow-list check
(``netcontrol.integrations.cato.egress_check``) and its server-side run
(``netcontrol.routes.cato_egress_check``), built from the bundled samples:
the Cato account (a name-only NAT rule to both allocated IPs, an address
rule that NATs Branch-Madison to 192.0.2.101 for 203.0.113.60, the
predefined rule), the AWS account (sql-public-1 on 203.0.113.60, its
security group allowing tcp 1433 from 192.0.2.101 and 192.0.2.102), the
Azure subscription and the GCP project.

Covers every finding kind, the account notes, broad source ranges, and the
persistence, alert raise / clear, and the HTTP API.
"""

from __future__ import annotations

import netcontrol.app as app_module
import netcontrol.routes.cato_egress_check as runner
import pytest
import routes.database as db_module
from netcontrol.integrations.aws.reachability import Reachability as AwsReachability
from netcontrol.integrations.aws.sample import build_sample as aws_sample
from netcontrol.integrations.azure import sample as azure_sample
from netcontrol.integrations.azure.reachability import Reachability as AzureReachability
from netcontrol.integrations.cato import egress_check
from netcontrol.integrations.cato.normalize import build_snapshot as build_cato
from netcontrol.integrations.cato.sample import (
    NAT_ASHBURN,
    NAT_NEW_YORK,
    _endpoint,
    _ref,
    build_sample_raw,
    network_rule,
)
from netcontrol.integrations.gcp.reachability import Reachability as GcpReachability
from netcontrol.integrations.gcp.sample import build_sample as gcp_sample

_SQL = "203.0.113.60"  # sql-public-1
_SQL_GROUP = "sg-0ed9e0s1"
_ORG = 3


def _raw(rule_2: dict | None = None, *, drop_rule_2: bool = False) -> dict:
    """The sample Cato account, with its name-only NAT rule (index 2)
    replaced or dropped."""
    raw = build_sample_raw()
    rules = raw["wan_network"]["rules"]
    position = next(i for i, r in enumerate(rules) if r["index"] == 2)
    if drop_rule_2:
        rules.pop(position)
    elif rule_2 is not None:
        rules[position] = rule_2
    return raw


def _by_address(*allocation: dict) -> dict:
    """Rule 2 matching the SQL server by address, NATting to ``allocation``."""
    return network_rule(
        2,
        "SQL by address",
        "NAT",
        destination=_endpoint(ip=[_SQL]),
        allocation=[dict(a) for a in allocation],
    )


def _aws(allowed: tuple[str, ...] = ("192.0.2.101/32", "192.0.2.102/32"), extra: list[str] | None = None):
    """The AWS sample with sql-public's inbound rules allowing ``allowed``
    (and ``extra`` sources) on tcp 1433."""
    resources, connections = aws_sample()
    group = next(r for r in resources if r["resource_type"] == "security_group" and r["name"] == "sql-public")
    rules = [r for r in group["metadata"]["policy_rules"] if r["direction"] != "inbound"]
    for index, source in enumerate([*allowed, *(extra or [])], start=1):
        rules.append(
            {
                "rule_uid": f"aws:sg:{_SQL_GROUP}:inbound:{index}",
                "rule_name": f"inbound-{index}",
                "direction": "inbound",
                "action": "allow",
                "protocol": "tcp",
                "source_selector": source,
                "destination_selector": "self",
                "port_expression": "1433",
                "priority": None,
            }
        )
    group["metadata"]["policy_rules"] = rules
    return AwsReachability(resources, connections)


def _azure():
    """The Azure sample with an NSG on web-vm-1's subnet that lets SQL in
    from the Ashburn allocated IP only."""
    resources, connections = azure_sample.build_sample()
    rule = azure_sample._rule("AllowSqlFromCato", 100, "inbound", "allow", "tcp", "1433", "192.0.2.101/32", "*")
    web = f"{azure_sample.WEST}/web"
    resources.append(azure_sample._nsg(f"{azure_sample.SUBSCRIPTION}:rg-west:nsg-web", [rule], [web], region="westus2"))
    return AzureReachability(resources, connections)


def _gcp():
    """The GCP sample with a firewall rule letting SQL into prod-vpc
    (app-1, external IP 203.0.113.21) from the New York allocated IP."""
    resources, connections = gcp_sample()
    resources.append(
        {
            "provider": "gcp",
            "resource_uid": "gcp:firewall_policy:sample:prod-allow-sql-from-cato",
            "resource_type": "firewall_policy",
            "name": "prod-allow-sql-from-cato",
            "region": "global",
            "cidr": "",
            "status": "active",
            "metadata": {
                "network_id": "sample:prod-vpc",
                "direction": "INGRESS",
                "priority": 900,
                "disabled": False,
                "allowed": [{"protocol": "tcp", "ports": ["1433"]}],
                "denied": [],
                "source_ranges": ["192.0.2.102/32"],
                "destination_ranges": [],
                "source_tags": [],
                "target_tags": [],
                "source_service_accounts": [],
                "target_service_accounts": [],
            },
        }
    )
    return GcpReachability(resources, connections)


def _check(raw: dict | None = None, clouds: list | None = None, snapshot: dict | None = None) -> list[dict]:
    cato = snapshot if snapshot is not None else build_cato(raw or build_sample_raw())
    return egress_check.check([(_ORG, cato)], clouds if clouds is not None else [("aws", _aws())])


def _for(findings: list[dict], public_ip: str) -> list[dict]:
    return [f for f in findings if f["public_ip"] == public_ip]


# ── Finding kinds ───────────────────────────────────────────────────────────


def test_the_bare_ip_falls_to_the_predefined_rule_while_the_nat_rule_matches_by_name():
    """The motivating case: the rule that NATs to the allowed addresses
    matches by name only, so a connection to the bare IP leaves from a PoP's
    shared address the security group does not list."""
    findings = _for(_check(), _SQL)
    assert [(f["kind"], f["severity"], f["rule"]) for f in findings] == [
        ("hostname_only", "warning", "tcp 1433 from 192.0.2.101/32"),
        ("hostname_only", "warning", "tcp 1433 from 192.0.2.102/32"),
    ]
    first = findings[0]
    assert first["provider"] == "aws" and first["resource_name"] == "sql-public-1"
    assert (first["private_ip"], first["protocol"], first["ports"]) == ("10.210.0.40", "tcp", "1433")
    assert first["filter"] == f"security group sql-public ({_SQL_GROUP})"
    assert first["key"] == f"{_ORG}:aws:i-0d8b001:{_SQL}:tcp:1433:aws:sg:{_SQL_GROUP}:inbound:1"
    message = first["message"]
    assert message.startswith("Reachable only by hostname. sql-public-1 (203.0.113.60) tcp 1433: ")
    assert "Remote user" in message or "Range of" in message
    assert "falls to Rule 4 Internet Traffic - Predefined (no special routing" in message
    assert "Rule 2 Geoblocked apps egress NATs to 192.0.2.101, 192.0.2.102 only when Cato identifies" in message
    detail = first["detail"]
    assert detail["allowed_ips"] == ["192.0.2.101"]
    assert detail["name_rules"] == ["Rule 2 Geoblocked apps egress"]
    assert detail["cato_rule"] == "Rule 4 Internet Traffic - Predefined"
    # Branch-Madison matches the address rule, which NATs to an allowed IP.
    assert detail["sources"]["ok"] == ["Range of Branch-Madison (10.60.20.0/24)"]
    assert "Remote user Dana Reyes (10.88.0.11)" in detail["sources"]["hostname_only"]


def test_an_address_rule_natting_to_the_allowed_ips_raises_nothing():
    findings = _check(_raw(_by_address(NAT_ASHBURN, NAT_NEW_YORK)))
    assert _for(findings, _SQL) == []


def test_a_rule_natting_to_an_ip_the_filters_refuse_is_a_mismatch():
    # Only New York's address gets in; the address rule NATs to Ashburn's.
    clouds = [("aws", _aws(allowed=("192.0.2.102/32",)))]
    [finding] = _for(_check(_raw(_by_address(NAT_ASHBURN)), clouds), _SQL)
    assert (finding["kind"], finding["severity"]) == ("allocated_ip_mismatch", "warning")
    assert finding["detail"]["nat_ips"] == ["192.0.2.101"]
    assert finding["detail"]["refused_ips"] == ["192.0.2.101"]
    assert "matches Rule 2 SQL by address, which NATs to 192.0.2.101" in finding["message"]
    assert "do not let 192.0.2.101 in" in finding["message"]


def test_no_rule_natting_to_the_allowed_ips_is_a_warning():
    findings = _for(_check(_raw(drop_rule_2=True)), _SQL)
    assert {f["kind"] for f in findings} == {"no_nat_rule"}
    # Branch-Madison's address rule NATs to 192.0.2.101: fine for it.
    first = findings[0]
    assert first["detail"]["sources"]["ok"] == ["Range of Branch-Madison (10.60.20.0/24)"]
    assert first["message"].startswith("No Cato rule egresses via the allowed IPs.")
    assert "falls to Rule 4 Internet Traffic - Predefined" in first["message"]


def test_a_rule_that_cannot_be_resolved_is_informational():
    rule = network_rule(
        2,
        "Unknown app egress",
        "NAT",
        allocation=[dict(NAT_ASHBURN), dict(NAT_NEW_YORK)],
        customApp=[_ref("ca-9", "Not in the list")],
    )
    findings = _for(_check(_raw(rule)), _SQL)
    assert findings and {(f["kind"], f["severity"]) for f in findings} == {("undetermined", "info")}
    assert "may apply: Rule 2 Unknown app egress (custom application Not in the list" in findings[0]["message"]


def test_azure_network_security_groups_are_checked_the_same_way():
    findings = _check(clouds=[("azure", _azure())])
    [finding] = findings
    assert (finding["provider"], finding["resource_name"], finding["public_ip"]) == (
        "azure",
        "web-vm-1",
        "203.0.113.91",
    )
    assert finding["kind"] == "hostname_only" and finding["rule"] == "rule AllowSqlFromCato (100)"
    assert finding["filter"].startswith("network security group nsg-web on subnet web")
    # The address rule is for the AWS server: Madison falls through here too.
    assert "Range of Branch-Madison (10.60.20.0/24)" in finding["detail"]["sources"]["hostname_only"]
    # An address rule for this VM that NATs to the allowed IP clears it.
    rule = network_rule(
        2, "Web by address", "NAT", destination=_endpoint(ip=["203.0.113.91"]), allocation=[dict(NAT_ASHBURN)]
    )
    assert _check(_raw(rule), clouds=[("azure", _azure())]) == []


def test_gcp_firewall_rules_are_checked_the_same_way():
    findings = _check(clouds=[("gcp", _gcp())])
    [finding] = findings
    assert (finding["provider"], finding["resource_name"], finding["public_ip"]) == ("gcp", "app-1", "203.0.113.21")
    assert finding["kind"] == "hostname_only"
    assert finding["rule"] == "rule prod-allow-sql-from-cato (priority 900)"
    assert finding["detail"]["allowed_ips"] == ["192.0.2.102"]


def test_broad_and_every_address_sources_say_nothing_about_cato():
    clouds = [("aws", _aws(allowed=(), extra=["0.0.0.0/0", "192.0.0.0/8"]))]
    assert _for(_check(clouds=clouds), _SQL) == []
    # A covering range no broader than /16 counts.
    clouds = [("aws", _aws(allowed=("192.0.2.0/24",)))]
    [finding] = _for(_check(clouds=clouds), _SQL)
    assert finding["detail"]["allowed_ips"] == ["192.0.2.101", "192.0.2.102"]


# ── Account notes ───────────────────────────────────────────────────────────


def test_a_snapshot_without_network_rules_is_an_informational_note():
    snapshot = build_cato(build_sample_raw())
    for node in snapshot["nodes"]:
        (node.get("forwarding") or {}).pop("egress_policy", None)
    [note] = _check(snapshot=snapshot)
    assert (note["kind"], note["severity"], note["key"]) == (
        "network_rules_not_collected",
        "info",
        f"{_ORG}:account:network_rules_not_collected",
    )
    assert "the network rules are not in the latest collection" in note["message"]


def test_allocated_ips_not_collected_fall_back_to_the_addresses_the_rules_name():
    raw = build_sample_raw()
    raw.pop("allocated_ips")
    findings = _check(raw)
    notes = [f for f in findings if f["kind"] == "allocated_ips_not_collected"]
    assert len(notes) == 1 and "192.0.2.101, 192.0.2.102" in notes[0]["message"]
    assert {f["kind"] for f in _for(findings, _SQL)} == {"hostname_only"}


def test_no_cloud_account_and_reduced_rules_are_notes():
    assert [f["kind"] for f in _check(clouds=[])] == ["no_cloud_accounts"]
    raw = build_sample_raw()
    raw["wan_network"]["reduced"] = True
    assert [f["kind"] for f in _check(raw)] == ["network_rules_unavailable"]


# ── Persistence, alerts and the API ─────────────────────────────────────────


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(runner.notification_channels, "on_alert_created", _capture)
    return events


def _inputs(monkeypatch, raw: dict, failed: set[str] | None = None, aws=None):
    snapshot = build_cato(raw)

    async def _fake():
        return [(_ORG, snapshot)], [("aws", aws or _aws())], set(failed or ())

    monkeypatch.setattr(runner, "_inputs", _fake)


async def _stored(include_resolved: bool = True) -> dict[str, dict]:
    return {f["finding_key"]: f for f in await db_module.list_cato_egress_findings(include_resolved=include_resolved)}


async def test_a_run_stores_findings_alerts_once_and_resolves_when_cleared(monkeypatch, notifications):
    _inputs(monkeypatch, build_sample_raw())
    first = await runner.run_egress_check("test")
    assert first["ok"] and first["warnings"] == 2 and first["alerted"] == 2
    stored = await _stored()
    assert {f["kind"] for f in stored.values()} == {"hostname_only"} and len(stored) == 2
    row = next(iter(stored.values()))
    assert row["status"] == "open" and row["alert_state"] == "warning" and row["alert_via"] == "notification"
    assert row["detail"]["allowed_ips"] and row["cato_org_ref"] == _ORG
    assert [e["alert_type"] for e in notifications] == ["cato_egress", "cato_egress"]
    assert notifications[0]["dedup_key"] == f"cato_egress:{row['finding_key']}"
    assert notifications[0]["host_id"] is None and "Reachable only by hostname" in notifications[0]["message"]

    # Same condition: no new alert.
    again = await runner.run_egress_check("test")
    assert again["alerted"] == 0 and again["new"] == 0 and len(notifications) == 2

    # Fixed in Cato: the findings resolve.
    _inputs(monkeypatch, _raw(_by_address(NAT_ASHBURN, NAT_NEW_YORK)))
    fixed = await runner.run_egress_check("test")
    assert fixed["resolved"] == 2 and fixed["findings"] == 0
    assert await db_module.list_cato_egress_findings() == []
    assert {f["status"] for f in (await _stored()).values()} == {"resolved"}

    # Broken again: reopened and alerted again.
    _inputs(monkeypatch, build_sample_raw())
    broken = await runner.run_egress_check("test")
    assert broken["alerted"] == 2 and len(notifications) == 4
    assert {f["status"] for f in (await _stored()).values()} == {"open"}


async def test_a_finding_on_an_inventory_host_raises_and_clears_a_monitoring_alert(monkeypatch, notifications):
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (941, 'Cloud')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type) "
            f"VALUES (9411, 941, 'sql-public-1', '{_SQL}', 'linux')"
        )
        await db.commit()
    finally:
        await db.close()
    _inputs(monkeypatch, build_sample_raw())
    await runner.run_egress_check("test")
    alerts = await db_module.get_monitoring_alerts(host_id=9411)
    assert len(alerts) == 2 and {a["alert_type"] for a in alerts} == {"cato_egress"}
    assert {a["severity"] for a in alerts} == {"warning"} and notifications == []
    assert {f["alert_via"] for f in (await _stored()).values()} == {"monitoring"}

    _inputs(monkeypatch, _raw(_by_address(NAT_ASHBURN, NAT_NEW_YORK)))
    cleared = await runner.run_egress_check("test")
    assert cleared["alerts_cleared"] == 2
    alerts = await db_module.get_monitoring_alerts(host_id=9411)
    assert {(a["acknowledged"], a["acknowledged_by"]) for a in alerts} == {(1, "auto-resolved")}


async def test_findings_of_a_cloud_that_could_not_be_read_are_kept(monkeypatch, notifications):
    _inputs(monkeypatch, build_sample_raw())
    await runner.run_egress_check("test")
    # AWS fails to load: its findings stay open, unchanged.
    snapshot = build_cato(build_sample_raw())

    async def _no_aws():
        return [(_ORG, snapshot)], [], {"aws"}

    monkeypatch.setattr(runner, "_inputs", _no_aws)
    result = await runner.run_egress_check("test")
    assert result["clouds_not_read"] == ["aws"] and result["resolved"] == 0
    assert {f["status"] for f in (await _stored()).values() if f["provider"] == "aws"} == {"open"}


async def test_a_warning_turning_informational_clears_its_alert(monkeypatch, notifications):
    _inputs(monkeypatch, build_sample_raw())
    await runner.run_egress_check("test")
    rule = network_rule(
        2,
        "Unknown app egress",
        "NAT",
        allocation=[dict(NAT_ASHBURN), dict(NAT_NEW_YORK)],
        customApp=[_ref("ca-9", "Not in the list")],
    )
    _inputs(monkeypatch, _raw(rule))
    await runner.run_egress_check("test")
    stored = await _stored()
    assert {(f["kind"], f["severity"], f["alert_state"]) for f in stored.values()} == {("undetermined", "info", "")}


async def test_the_run_never_raises(monkeypatch):
    async def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(runner, "_inputs", _boom)
    result = await runner.run_egress_check("test")
    assert result["ok"] is False and result["error"] == "RuntimeError"


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-cato-egress")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_topology as topology_routes

    topology_routes._SNAPSHOT_CACHE.clear()

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    csrf = resp.json().get("csrf_token", "")
    return client, {"X-CSRF-Token": csrf}


def test_the_sample_collections_run_the_check_and_the_api_lists_it(api):
    client, headers = api
    for provider in ("cato", "aws"):
        resp = client.post(f"/api/sources/sample?provider={provider}", headers=headers)
        assert resp.status_code == 201, resp.text

    # The AWS collection, after the Cato one, ran the check.
    body = client.get("/api/monitoring/cato-egress/findings").json()
    sql = [f for f in body["findings"] if f["public_ip"] == _SQL]
    assert len(sql) == 2 and {f["kind"] for f in sql} == {"hostname_only"}
    assert sql[0]["kind_label"] == "Reachable only by hostname" and sql[0]["status"] == "open"

    resp = client.post("/api/monitoring/cato-egress/run", headers=headers)
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["ok"] and result["cato_accounts"] == 1 and "aws" in result["clouds"]
    assert result["warnings"] >= 2 and result["new"] == 0

    assert client.get("/api/monitoring/cato-egress/findings?include_resolved=true").status_code == 200
    assert client.get("/api/monitoring/cato-egress/findings?limit=0").status_code == 422
