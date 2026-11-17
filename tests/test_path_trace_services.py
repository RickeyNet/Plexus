"""Managed cloud services as ends of a path trace
(``netcontrol.integrations.pathtrace.services`` and ``pathtrace.cloud``),
built from the bundled AWS, Azure and GCP samples: a private service
address places in its network and names the service and the listener or
rule that takes the flow, a collected DNS name stands for the service's
addresses, a public frontend is entered at the service, and an Azure
Firewall's public address meets its DNAT rules."""

from __future__ import annotations

from netcontrol.integrations.aws.normalize import build_snapshot as build_aws
from netcontrol.integrations.aws.reachability import Reachability as AwsReachability
from netcontrol.integrations.aws.sample import build_sample as aws_sample
from netcontrol.integrations.azure.normalize import build_snapshot as build_azure
from netcontrol.integrations.azure.reachability import Reachability as AzureReachability
from netcontrol.integrations.azure.sample import build_sample as azure_sample
from netcontrol.integrations.gcp.normalize import build_snapshot as build_gcp
from netcontrol.integrations.gcp.reachability import Reachability as GcpReachability
from netcontrol.integrations.gcp.sample import build_sample as gcp_sample
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import merge_meraki_into_graph
from netcontrol.integrations.pathtrace import offline, services
from netcontrol.integrations.pathtrace.engine import Tracer

ACCOUNT = {"id": 1, "name": "Prod", "last_sync_at": "2026-10-01T12:00:00+00:00", "last_sync_status": "success"}
_CLOUDS = {
    "aws": (-1, build_aws, aws_sample, AwsReachability),
    "azure": (-2, build_azure, azure_sample, AzureReachability),
    "gcp": (-3, build_gcp, gcp_sample, GcpReachability),
}


def _tracer(provider: str, rows: tuple[list[dict], list[dict]] | None = None) -> Tracer:
    org_ref, build, sample, engine = _CLOUDS[provider]
    resources, connections = rows or sample()
    snapshot = build([ACCOUNT], resources, connections)
    nodes: dict = {}
    edges: list = []
    merge_meraki_into_graph(
        nodes, edges, [(org_ref, snapshot)], host_node=lambda _h: None, resolve_external=lambda _n, _i: None
    )
    subnets = [{"org_ref": org_ref, "provider": provider, **row} for row in subnet_index(snapshot)]
    graph = {"nodes": list(nodes.values()), "edges": edges}
    return Tracer(graph, {org_ref: snapshot}, {org_ref: engine(resources, connections)}, {}, subnets)


def _items(direction: dict) -> list[tuple[str, str, str, str]]:
    return [(i["stage"], i["status"], i["where"], i["text"]) for h in direction["hops"] for i in h["items"]]


def _find(direction: dict, stage: str, where: str) -> tuple[str, str]:
    found = [(status, text) for s, status, w, text in _items(direction) if s == stage and w.startswith(where)]
    assert found, (stage, where, _items(direction))
    return found[0]


# ── The service record ──────────────────────────────────────────────────────


def test_listeners_rules_and_dns_names_are_read_from_the_record():
    resources, connections = azure_sample()
    index = services.index(AzureReachability(resources, connections))
    lb = index.at("sample:rg-prod:prod-vnet", "10.231.10.100")
    assert lb is not None and lb.label == "Internal load balancer lb-app"
    assert [(entry.protocol, entry.ports) for entry in lb.listeners] == [("tcp", "443"), ("tcp", "50000-50009")]
    gateway = index.frontends["203.0.113.75"]
    assert gateway.pairs == {"203.0.113.75": "10.230.4.10"}
    assert [(e.ports, e.scope) for e in gateway.listeners] == [("443", "public")]
    assert [s.name for s, _a in index.named("STSampleData.blob.example.com.")] == ["pe-sampledata-blob"]
    assert {f["name"] for f in index.firewalls} >= {"azfw-hub"}
    assert index.dnat["203.0.113.70"]["name"] == "azfw-hub"


def test_the_offline_export_carries_the_services_module():
    assert "netcontrol/integrations/pathtrace/services.py" in offline.MODULES


# ── Private addresses and DNS names ─────────────────────────────────────────


def test_an_aws_load_balancer_by_its_dns_name_checks_its_security_groups():
    name = "internal-core-api-0c0re0001.us-east-1.elb.amazonaws.com"
    result = _tracer("aws").trace("10.200.10.10", name, protocol="tcp", port=443)
    assert result["destination"]["address"] == "10.200.10.80"
    assert result["notes"][0].startswith(f"{name} is the DNS name of Application load balancer core-api")
    assert "also stands for 10.200.11.80" in result["notes"][0]
    assert result["verdict"] == "allowed"
    status, text = _find(result["request"], "security_group", "Security groups of Application load balancer core-api")
    assert status == "ok" and "core-app" in text
    status, text = _find(result["request"], "policy", "Application load balancer core-api")
    assert status == "info" and "Which ports it takes is not collected" in text


def test_an_azure_load_balancer_rule_decides_the_port():
    tracer = _tracer("azure")
    allowed = tracer.trace("10.231.10.21", "10.231.10.100", protocol="tcp", port=443)
    status, text = _find(allowed["request"], "policy", "Internal load balancer lb-app")
    assert status == "ok" and "load-balancing rule https: Tcp 443 -> 443 takes tcp/443" in text
    refused = tracer.trace("10.231.10.21", "10.231.10.100", protocol="tcp", port=8080)
    status, text = _find(refused["request"], "policy", "Internal load balancer lb-app")
    assert status == "blocked" and "No listener or rule takes tcp/8080" in text
    assert refused["verdict"] == "blocked"
    nat = tracer.trace("10.231.10.21", "10.231.10.100", protocol="tcp", port=50003)
    assert "inbound NAT rule ssh-app" in _find(nat["request"], "policy", "Internal load balancer lb-app")[1]


def test_a_private_endpoint_names_what_it_connects_to():
    result = _tracer("azure").trace("10.231.10.21", "stsampledata.blob.example.com", protocol="tcp", port=443)
    assert result["destination"]["address"] == "10.231.20.40"
    status, text = _find(result["request"], "policy", "Private endpoint pe-sampledata-blob")
    assert status == "info"
    assert "It connects to stsampledata (Microsoft.Storage/storageAccounts, blob)." in text


def test_a_gcp_internal_load_balancer_and_a_psc_endpoint():
    tracer = _tracer("gcp")
    result = tracer.trace("10.241.10.5", "db.ilb-db.il4.us-central1.lb.sample.internal", protocol="tcp", port=5432)
    assert result["destination"]["address"] == "10.241.20.100"
    status, text = _find(result["request"], "policy", "Internal passthrough Network Load Balancer ilb-db")
    assert status == "ok" and "forwarding rule TCP 5432 takes tcp/5432" in text
    psc = tracer.trace("10.240.1.10", "10.240.1.50", protocol="tcp", port=5432)
    assert "It connects to sample:us-central1:sa-db." in _find(psc["request"], "policy", "Private Service Connect")[1]


def test_an_unknown_name_is_still_an_error():
    try:
        _tracer("aws").trace("10.200.10.10", "nothing.example.com")
    except ValueError as exc:
        assert "is not an IP address or network" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


# ── Public frontends ────────────────────────────────────────────────────────


def test_a_public_frontend_delivered_to_a_private_address_continues_there():
    result = _tracer("azure").trace("198.51.100.7", "203.0.113.75", protocol="tcp", port=443)
    assert result["verdict"] == "allowed"
    status, text = _find(result["request"], "nat", "Azure public address")
    assert status == "ok" and "public address of Application gateway agw-hub (10.230.4.10)" in text
    status, text = _find(result["request"], "policy", "Application gateway agw-hub")
    assert status == "ok" and "listener app-https: HTTPS 443 (app.example.com) takes tcp/443" in text
    # The replies leave from the public address again.
    assert "leave as 203.0.113.75" in _find(result["reply"], "nat", "Azure public address")[1]


def test_a_public_frontend_with_no_private_address_ends_at_the_service():
    tracer = _tracer("gcp")
    result = tracer.trace("198.51.100.7", "203.0.113.80", protocol="tcp", port=443)
    assert result["verdict"] == "allowed"
    status, text = _find(result["request"], "route", "GCP Global external Application Load Balancer")
    assert status == "ok" and "203.0.113.80 is the public frontend of" in text
    text = _find(result["request"], "route", "Global external Application Load Balancer web-https")[1]
    assert "backend service bs-web" in text and "not collected by address" in text
    assert "from its public frontend 203.0.113.80, to the internet" in _items(result["reply"])[0][3]
    refused = tracer.trace("198.51.100.7", "203.0.113.80", protocol="tcp", port=22)
    assert refused["verdict"] == "blocked"


# ── Azure Firewall DNAT ─────────────────────────────────────────────────────


def test_an_azure_firewall_dnat_rule_translates_to_the_load_balancer_behind():
    result = _tracer("azure").trace("198.51.100.7", "203.0.113.70", protocol="tcp", port=443)
    assert result["request"]["verdict"] == "allowed"
    status, text = _find(result["request"], "nat", "Azure Firewall azfw-hub, DNAT")
    assert status == "ok"
    assert "rule https-to-app of collection inbound-dnat translates 203.0.113.70 (tcp/443) to 10.231.10.100" in text
    assert "translates the source to its own address 10.230.1.4" in text
    assert (
        "rule https: Tcp 443 -> 443 takes tcp/443"
        in _find(result["request"], "policy", "Internal load balancer lb-app")[1]
    )
    refused = _tracer("azure").trace("198.51.100.7", "203.0.113.70", protocol="tcp", port=22)
    assert refused["verdict"] == "blocked"
    assert "No DNAT rule takes tcp/22 to 203.0.113.70" in refused["summary"]


def test_a_dnat_rule_that_translates_the_port_moves_the_flow_to_it():
    resources, connections = azure_sample()
    firewall = next(r for r in resources if r["resource_type"] == "azure_firewall" and r["name"] == "azfw-hub")
    rule = firewall["metadata"]["dnat_rules"][0]
    rule["destination_ports"], rule["translated_port"] = ["8443"], "443"
    result = _tracer("azure", (resources, connections)).trace("198.51.100.7", "203.0.113.70", protocol="tcp", port=8443)
    assert result["request"]["verdict"] == "allowed"
    assert (
        "rule https: Tcp 443 -> 443 takes tcp/443"
        in _find(result["request"], "policy", "Internal load balancer lb-app")[1]
    )


def test_dnat_match_reads_sources_and_policy_gaps():
    meta = {
        "dnat_rules": [
            {
                "name": "only-partners",
                "collection": "c",
                "protocols": ["TCP"],
                "source_addresses": ["198.51.100.0/24"],
                "destination_addresses": ["203.0.113.70"],
                "destination_ports": ["443"],
                "translated_address": "10.0.0.5",
                "translated_port": "8443",
            }
        ]
    }
    rule, status, _text = services.dnat_match(meta, "203.0.113.70", "198.51.100.9", "tcp", (443, 443))
    assert rule is not None and status == "ok"
    assert services.translated_ports(rule, (443, 443)) == (8443, 8443)
    assert services.dnat_match(meta, "203.0.113.70", "192.0.2.9", "tcp", (443, 443))[:2] == (None, "blocked")
    assert services.dnat_match({"firewall_policy": "fwpol"}, "203.0.113.70", "", "tcp", None)[1] == "unknown"
    assert services.dnat_covers(meta["dnat_rules"][0], "198.51.100.9")
    assert not services.dnat_covers(meta["dnat_rules"][0], "192.0.2.9")
