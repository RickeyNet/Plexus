"""Path tracing from Cato to the public address of a cloud instance: the
network rule that routes the flow, the address it leaves Cato with, and the
security groups (AWS) or network security groups (Azure) checked against
that address, never against the private address it left the user with."""

from __future__ import annotations

from netcontrol.integrations.aws.normalize import build_snapshot as build_aws_snapshot
from netcontrol.integrations.aws.reachability import Reachability as AwsReachability
from netcontrol.integrations.aws.sample import build_sample as build_aws_sample
from netcontrol.integrations.azure import sample as azure_sample
from netcontrol.integrations.azure.normalize import build_snapshot as build_azure_snapshot
from netcontrol.integrations.azure.reachability import Reachability as AzureReachability
from netcontrol.integrations.cato.normalize import build_snapshot as build_cato_snapshot
from netcontrol.integrations.cato.sample import _ref, build_sample_raw
from netcontrol.integrations.meraki.forwarding import nat
from netcontrol.integrations.meraki.unified import merge_meraki_into_graph
from netcontrol.integrations.pathtrace.engine import Tracer

_SQL = "203.0.113.60"  # sql-public-1, the AWS sample's public SQL server (10.210.0.40)
_AZURE_VM = "203.0.113.91"  # web-vm-1, the Azure sample's VM with a public IP (10.232.1.11)
_DANA = {"source_node": "meraki:3:cato:user:9001"}  # a remote user, full tunnel, on PoP New York
_MADISON = {"source_node": "meraki:3:d:5003"}  # Branch-Madison's Socket
_SQL_PORT = {"protocol": "tcp", "port": 1433}
_ACCOUNT = {"id": 1, "name": "Sample", "account_identifier": "sample"}


def _cato_raw() -> dict:
    """The sample account without its Internet firewall rule by category,
    which Plexus cannot evaluate: the network rules and the cloud decide."""
    raw = build_sample_raw()
    raw["internet_firewall"]["rules"] = [r for r in raw["internet_firewall"]["rules"] if r["name"] == "Allow all"]
    return raw


def _azure_rows() -> tuple[list[dict], list[dict]]:
    """The Azure sample with a network security group on web-vm-1's subnet
    that lets SQL in from the Cato sample's Ashburn allocated IP only."""
    resources, connections = azure_sample.build_sample()
    rule = azure_sample._rule("AllowSqlFromCato", 100, "inbound", "allow", "tcp", "1433", "192.0.2.101/32", "*")
    web = f"{azure_sample.WEST}/web"
    resources.append(azure_sample._nsg(f"{azure_sample.SUBSCRIPTION}:rg-west:nsg-web", [rule], [web], region="westus2"))
    return resources, connections


def _tracer(raw: dict | None = None, cato: dict | None = None) -> Tracer:
    cato = cato or build_cato_snapshot(raw or _cato_raw())
    aws_resources, aws_connections = build_aws_sample()
    azure_resources, azure_connections = _azure_rows()
    snapshots = {
        3: cato,
        -1: build_aws_snapshot([_ACCOUNT], aws_resources, aws_connections, None),
        -2: build_azure_snapshot([_ACCOUNT], azure_resources, azure_connections),
    }
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(
        nodes, edges, list(snapshots.items()), host_node=lambda _id: None, resolve_external=lambda *_: None
    )
    clouds = {
        -1: AwsReachability(aws_resources, aws_connections),
        -2: AzureReachability(azure_resources, azure_connections),
    }
    return Tracer({"nodes": list(nodes.values()), "edges": edges}, snapshots, clouds, {}, [])


def _item(direction: dict, stage: str, where_starts: str) -> dict:
    return next(
        i for h in direction["hops"] for i in h["items"] if i["stage"] == stage and i["where"].startswith(where_starts)
    )


def _madison_rule(raw: dict) -> dict:
    return next(r for r in raw["wan_network"]["rules"] if r["index"] == 3)


def test_the_public_address_of_an_instance_is_its_vpc():
    tracer = _tracer()
    result = tracer.trace("10.60.20.5", _SQL, **_MADISON, **_SQL_PORT)
    assert result["destination"]["node"] == "meraki:-1:vpc:vpc-0ed9e00002"
    request = result["request"]
    crossing = _item(request, "route", "Internet")
    assert crossing["text"] == f"Crosses the internet to sql-public-1 ({_SQL}) in edge-security-vpc."
    public = _item(request, "nat", "AWS public address")
    assert (
        public["text"] == f"{_SQL} is the public address of instance sql-public-1 (10.210.0.40): AWS delivers it there."
    )


def test_an_address_rule_nats_to_an_allocated_ip_the_security_group_allows():
    result = _tracer().trace("10.60.20.5", _SQL, **_MADISON, **_SQL_PORT)
    request = result["request"]
    assert result["verdict"] == "allowed", result["summary"]
    rule = _item(request, "route", "Network rules")
    assert (rule["status"], rule["rule"]) == ("info", 2)  # by name only
    nat = _item(request, "nat", "Cato egress address")
    assert nat["text"] == "Source 10.60.20.5 becomes 192.0.2.101 (NAT IP Ashburn - 192.0.2.101, PoP Ashburn)."
    group = _item(request, "security_group", "Security groups of instance sql-public-1")
    assert (group["status"], group["text"]) == ("ok", "Allowed by sql-public: tcp 1433 from 192.0.2.101/32.")
    # The replies leave the instance's public address and come back through
    # the Cato Cloud, which translates them back to the Madison host.
    reply = result["reply"]
    assert [h["label"] for h in reply["hops"]][-4:] == ["Internet", "Cato Cloud", "PoP New York", "Branch-Madison"]
    assert _item(reply, "nat", "AWS public address")["text"] == (
        f"Replies from 10.210.0.40 leave as {_SQL}, its public address."
    )
    assert _item(reply, "nat", "Cato egress address")["text"] == (
        "Replies to 192.0.2.101 are translated back to 10.60.20.5 by the session."
    )


def test_a_bare_ip_from_a_remote_user_leaves_from_the_pops_shared_address_and_is_unknown():
    """The incident: the app connects to the bare IP, the rule that NATs to
    the allowed addresses matches only by name, so the flow takes the
    predefined rule out of the PoP's shared address, which the security
    group does not list."""
    result = _tracer().trace("10.88.0.11", _SQL, **_DANA, **_SQL_PORT)
    request = result["request"]
    caveat = next(i for h in request["hops"] for i in h["items"] if i["where"] == "Network rules" and i["rule"] == 2)
    assert caveat["status"] == "info" and "matches only if Cato identifies the traffic by name" in caveat["text"]
    assert f"the bare IP {_SQL} falls to Rule 4 Internet Traffic - Predefined" in caveat["text"]
    group = _item(request, "security_group", "Security groups of instance sql-public-1")
    assert group["status"] == "unknown"
    assert group["text"] == (
        "The flow leaves Cato from the shared address of its PoP, which Cato does not report, so whether this "
        "lets it in is not known. Only part of it is allowed: sql-public: tcp 1433 from 192.0.2.101/32; "
        "sql-public: tcp 1433 from 192.0.2.102/32."
    )
    # Never checked against the user's private address.
    assert not any("10.88.0.11" in i["text"] for h in request["hops"][3:] for i in h["items"])
    assert result["verdict"] == "unknown"
    assert result["reply"]["summary"].startswith("Not traced: the flow leaves Cato from the shared address")


def test_an_allocated_ip_the_security_group_does_not_list_is_blocked():
    raw = _cato_raw()
    _madison_rule(raw)["configuration"]["allocationIp"] = [_ref("aip-9", "NAT IP Denver - 192.0.2.109")]
    result = _tracer(raw).trace("10.60.20.5", _SQL, **_MADISON, **_SQL_PORT)
    assert result["verdict"] == "blocked"
    group = _item(result["request"], "security_group", "Security groups of instance sql-public-1")
    assert (group["status"], group["text"]) == ("blocked", "No rule of sql-public allows it.")
    assert result["summary"].startswith("Blocked at edge-security-vpc, Security groups of instance sql-public-1")


def test_several_allocated_ips_are_each_checked():
    raw = _cato_raw()
    _madison_rule(raw)["configuration"]["allocationIp"] = [
        _ref("aip-1", "NAT IP Ashburn - 192.0.2.101"),
        _ref("aip-9", "NAT IP Denver - 192.0.2.109"),
    ]
    result = _tracer(raw).trace("10.60.20.5", _SQL, **_MADISON, **_SQL_PORT)
    group = _item(result["request"], "security_group", "Security groups of instance sql-public-1")
    assert group["status"] == "partial"
    assert group["text"].startswith(
        "Allowed from 192.0.2.101 only, not from 192.0.2.109, so it depends on which address the flow leaves with."
    )
    assert result["verdict"] == "partial"
    nat = _item(result["request"], "nat", "Cato egress address")
    assert "becomes one of 192.0.2.101" in nat["text"] and "192.0.2.109" in nat["text"]


def test_network_rules_not_collected_leave_the_egress_address_unknown():
    raw = _cato_raw()
    raw["wan_network"] = None
    result = _tracer(raw).trace("10.60.20.5", _SQL, **_MADISON, **_SQL_PORT)
    request = result["request"]
    rule = _item(request, "route", "Network rules")
    assert rule["status"] == "unknown" and rule["text"].startswith("The network rules are not collected")
    group = _item(request, "security_group", "Security groups of instance sql-public-1")
    assert group["status"] == "unknown"
    assert group["text"].startswith("The address the flow leaves Cato with is not known")
    assert result["verdict"] == "unknown"


def test_azure_network_security_groups_are_checked_against_the_egress_address():
    raw = _cato_raw()
    _madison_rule(raw)["destination"]["ip"] = [_SQL, _AZURE_VM]
    tracer = _tracer(raw)
    allowed = tracer.trace("10.60.20.5", _AZURE_VM, **_MADISON, **_SQL_PORT)
    assert allowed["destination"]["node"].startswith("meraki:-2:vnet:")
    assert allowed["verdict"] == "allowed", allowed["summary"]
    request = allowed["request"]
    assert _item(request, "nat", "Azure public address")["text"].startswith(f"{_AZURE_VM} is the public address of")
    nsg = _item(request, "security_group", "Network security group nsg-web")
    assert (nsg["status"], nsg["text"]) == ("ok", "Allowed by rule AllowSqlFromCato (100).")

    # A remote user's bare-IP connection leaves from the PoP's shared address.
    unknown = tracer.trace("10.88.0.11", _AZURE_VM, **_DANA, **_SQL_PORT)
    nsg = _item(unknown["request"], "security_group", "Network security group nsg-web")
    assert nsg["status"] == "unknown"
    assert nsg["text"].startswith("The flow leaves Cato from the shared address of its PoP, which Cato does not report")

    # An allocated IP the group does not allow is denied by its default rule.
    _madison_rule(raw)["configuration"]["allocationIp"] = [_ref("aip-2", "NAT IP New York - 192.0.2.102")]
    blocked = _tracer(raw).trace("10.60.20.5", _AZURE_VM, **_MADISON, **_SQL_PORT)
    nsg = _item(blocked["request"], "security_group", "Network security group nsg-web")
    assert nsg["status"] == "blocked" and "DenyAllInBound" in nsg["text"]
    assert blocked["verdict"] == "blocked"


def test_a_gcp_external_ip_is_delivered_to_its_instance():
    from netcontrol.integrations.gcp.normalize import build_snapshot as build_gcp_snapshot
    from netcontrol.integrations.gcp.reachability import Reachability as GcpReachability
    from netcontrol.integrations.gcp.sample import build_sample as build_gcp_sample

    resources, connections = build_gcp_sample()
    snapshots = {3: build_cato_snapshot(_cato_raw()), -3: build_gcp_snapshot([_ACCOUNT], resources, connections)}
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(
        nodes, edges, list(snapshots.items()), host_node=lambda _id: None, resolve_external=lambda *_: None
    )
    graph = {"nodes": list(nodes.values()), "edges": edges}
    tracer = Tracer(graph, snapshots, {-3: GcpReachability(resources, connections)}, {}, [])
    result = tracer.trace("10.60.20.5", "203.0.113.21", **_MADISON, protocol="tcp", port=443)
    request = result["request"]
    assert _item(request, "route", "Internet")["text"] == "Crosses the internet to app-1 (203.0.113.21) in prod-vpc."
    assert _item(request, "nat", "GCP public address")["status"] == "ok"
    rules = _item(request, "security_group", "Firewall rules of VPC network prod-vpc")
    assert rules["status"] == "ok"
    assert result["verdict"] == "allowed", result["summary"]


def test_a_private_source_never_reaches_a_clouds_filters():
    """A snapshot from before the network rules (the Cloud's uplink NAT to an
    address that was not collected) leaves the private source untranslated:
    at the cloud it is an unknown public address, never the private one."""
    cato = build_cato_snapshot(_cato_raw())
    block = next(n for n in cato["nodes"] if n["id"] == "cato:cloud")["forwarding"]
    del block["egress_policy"]
    block["nat"] = [nat(1, "interface_pat", name="Cato public address", translated_src=["interface"])]
    result = _tracer(cato=cato).trace("10.88.0.11", _SQL, **_DANA, **_SQL_PORT)
    request = result["request"]
    crossing = _item(request, "nat", "Internet")
    assert crossing["status"] == "info" and "no NAT on the way translated 10.88.0.11" in crossing["text"]
    group = _item(request, "security_group", "Security groups of instance sql-public-1")
    assert group["status"] == "unknown" and "10.88.0.11, a private address, so whether" in group["text"]
