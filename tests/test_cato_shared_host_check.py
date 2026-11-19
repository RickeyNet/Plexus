"""The Cato shared hosts vs Azure check
(``netcontrol.integrations.cato.shared_host_check``), the Shared Hosts block
the Cato normalizer builds for it, its storage beside the egress check's
findings and its server-side run (``netcontrol.routes.cato_shared_host_check``).

The Azure side is an invented VNet built with the Azure sample's helpers:
vdi-vnet (10.240.0.0/16) with the subnet hosts (10.240.1.0/24, the
multi-session hosts avd-host-1 to avd-host-4) and the subnet cato-lan
(10.240.2.0/24) with the vSocket vsocket-1 at 10.240.2.4. The Cato side is a
snapshot whose Cato Cloud routes a site range covering cato-lan and whose
Shared Hosts rule names the hosts subnet.
"""

from __future__ import annotations

import netcontrol.app as app_module
import netcontrol.routes.cato_egress_check as base_runner
import netcontrol.routes.cato_shared_host_check as runner
import pytest
import routes.database as db_module
from netcontrol.integrations.azure import sample as az
from netcontrol.integrations.azure.reachability import Reachability
from netcontrol.integrations.cato import shared_host_check
from netcontrol.integrations.cato.normalize import CLOUD_NODE_ID, build_snapshot as build_cato
from netcontrol.integrations.cato.sample import _ref, _rule, build_sample_raw

_ORG = 7
_VNET = f"{az.SUBSCRIPTION}:rg-vdi:vdi-vnet"
_HOSTS = f"{_VNET}/hosts"
_LAN = f"{_VNET}/cato-lan"
_RT = f"{az.SUBSCRIPTION}:rg-vdi:rt-hosts"
_NSG_HOSTS = f"{az.SUBSCRIPTION}:rg-vdi:nsg-hosts"
_NSG_LAN = f"{az.SUBSCRIPTION}:rg-vdi:nsg-cato-lan"
_SOCKET = "10.240.2.4"
_SYSTEM = "10.254.254.0/24"
_HOST_IPS = ("10.240.1.11", "10.240.1.12", "10.240.1.13", "10.240.1.14")


def _system_route(next_hop: str = _SOCKET, prefix: str = _SYSTEM) -> dict:
    return az._route("to-cato-system", prefix, "VirtualAppliance", next_hop)


def _azure(
    *,
    routes: list[dict] | None = None,
    table: bool = True,
    forwards: bool = True,
    hosts_rules: list[dict] | None = None,
    lan_rules: list[dict] | None = None,
    same_subnet: bool = False,
    hosts: tuple[str, ...] = _HOST_IPS,
    extra: list[dict] | None = None,
) -> Reachability:
    """The invented VDI VNet. ``same_subnet`` puts the vSocket at
    10.240.1.4 in the hosts subnet (with the route to it)."""
    socket_ip = "10.240.1.4" if same_subnet else _SOCKET
    resources = [
        az._res(
            f"vnet:{_VNET}",
            "vnet",
            "vdi-vnet",
            "eastus",
            cidr="10.240.0.0/16",
            resource_group="rg-vdi",
            address_prefixes=["10.240.0.0/16"],
            dns_servers=[],
            subnet_count=3,
        ),
        az._subnet(
            _VNET,
            "hosts",
            "10.240.1.0/24",
            **({"route_table": _RT} if table else {}),
            **({"nsg": _NSG_HOSTS} if hosts_rules is not None else {}),
        ),
        az._subnet(_VNET, "cato-lan", "10.240.2.0/24", **({"nsg": _NSG_LAN} if lan_rules is not None else {})),
        az._subnet(_VNET, "spare", "10.240.3.0/24"),
        az._vm(
            f"{az.SUBSCRIPTION}:rg-vdi:vsocket-1",
            _VNET,
            [("hosts" if same_subnet else "cato-lan", socket_ip, "")],
            forwards=forwards,
        ),
    ]
    for number, address in enumerate(hosts, start=1):
        resources.append(az._vm(f"{az.SUBSCRIPTION}:rg-vdi:avd-host-{number}", _VNET, [("hosts", address, "")]))
    if table:
        resources.append(
            az._res(
                f"route_table:{_RT}",
                "route_table",
                "rt-hosts",
                "eastus",
                resource_group="rg-vdi",
                disable_bgp_route_propagation=True,
                route_count=1,
                routes=routes if routes is not None else [_system_route(socket_ip)],
                route_summaries=[],
                subnet_ids=[_HOSTS],
            )
        )
    if hosts_rules is not None:
        resources.append(az._nsg(_NSG_HOSTS, hosts_rules, [_HOSTS]))
    if lan_rules is not None:
        resources.append(az._nsg(_NSG_LAN, lan_rules, [_LAN]))
    return Reachability([*resources, *(extra or [])], [])


def _shared_rule(
    index: int = 1,
    name: str = "AVD pool",
    *,
    cidrs: tuple[str, ...] = ("10.240.1.0/24",),
    unresolved: tuple[str, ...] = (),
    enabled: bool = True,
) -> dict:
    return {
        "index": index,
        "name": name,
        "enabled": enabled,
        "hosts": [{"name": "AVD-Hosts", "cidrs": list(cidrs)}],
        "unresolved": list(unresolved),
        "excluded": [{"name": "Updates", "cidrs": ["198.51.100.0/24"]}],
    }


def _snapshot(
    rules: list[dict] | None = None, *, enabled: bool = True, ranges: tuple[str, ...] = ("10.240.2.0/24",)
) -> dict:
    routes = [{"prefix": p, "kind": "static", "source": "Range of Azure-VDI"} for p in ranges]
    routes.append({"prefix": "0.0.0.0/0", "kind": "default", "source": "Cato internet egress"})
    block = {
        "kind": "cato_shared_hosts",
        "enabled": enabled,
        "reduced": False,
        "rules": rules if rules is not None else [_shared_rule()],
    }
    return {
        "provider": "cato",
        "org": {"name": "Demo Cato account"},
        "nodes": [{"id": CLOUD_NODE_ID, "forwarding": {"routes": routes, "shared_hosts": block}}],
    }


def _check(engine: Reachability | None = None, snapshot: dict | None = None, **kwargs) -> list[dict]:
    clouds = [("azure", engine if engine is not None else _azure())]
    return shared_host_check.check([(_ORG, snapshot or _snapshot())], clouds, **kwargs)


def _kinds(findings: list[dict]) -> list[str]:
    return sorted(f["kind"] for f in findings)


def _one(findings: list[dict], kind: str) -> dict:
    [found] = [f for f in findings if f["kind"] == kind]
    return found


# ── Healthy and routing ─────────────────────────────────────────────────────


def test_a_healthy_host_pool_gets_only_the_gre_over_udp_note():
    findings = _check()
    assert _kinds(findings) == ["gre_over_udp_required"]
    note = findings[0]
    assert (note["severity"], note["provider"], note["protocol"], note["ports"]) == ("info", "azure", "udp", "4754")
    assert note["key"] == f"shared_host:{_ORG}:gre_over_udp_required:azure"
    assert "GREOverUDP = 1" in note["message"] and "4 Azure virtual machines" in note["message"]
    assert "Traffic to Updates is excluded from the tunnel" in note["message"]
    assert note["detail"]["excluded"] == [{"rule": "Rule 1 AVD pool", "name": "Updates", "cidrs": ["198.51.100.0/24"]}]
    assert [h["ip"] for h in note["detail"]["hosts"]] == list(_HOST_IPS)


def test_a_missing_route_is_one_warning_for_the_whole_subnet():
    findings = _check(_azure(table=False))
    assert _kinds(findings) == ["gre_over_udp_required", "no_route"]
    finding = _one(findings, "no_route")
    assert finding["severity"] == "warning"
    assert finding["key"] == f"shared_host:{_ORG}:no_route:{_HOSTS}"
    assert finding["resource_name"] == "subnet hosts (10.240.1.0/24)"
    # Several hosts: no single address to alert on.
    assert finding["private_ip"] == ""
    message = finding["message"]
    assert message.startswith("No route to the Cato system range. avd-host-1 (10.240.1.11), avd-host-2 (10.240.1.12)")
    assert "and 1 more in subnet hosts (10.240.1.0/24)" in message
    assert "0.0.0.0/0 via Internet, so Azure sends it to the internet" in message
    assert "The subnet has no route table" in message
    assert len(finding["detail"]["hosts"]) == 4 and finding["detail"]["rules"] == ["Rule 1 AVD pool"]


def test_a_route_table_without_the_system_range_is_named():
    routes = [az._route("to-branch", "10.60.0.0/16", "VirtualAppliance", _SOCKET)]
    finding = _one(_check(_azure(routes=routes)), "no_route")
    assert "Route table rt-hosts of the subnet has no user route for it" in finding["message"]
    assert finding["filter"] == "route table rt-hosts"


def test_a_route_with_next_hop_none_drops_the_tunnel():
    routes = [az._route("blackhole", _SYSTEM, "None")]
    finding = _one(_check(_azure(routes=routes)), "no_route")
    assert "which drops the traffic (next hop None)" in finding["message"]
    assert finding["rule"] == "route blackhole (Dropped)"


def test_a_default_route_to_the_vsocket_covers_the_system_range():
    routes = [az._route("default-to-cato", "0.0.0.0/0", "VirtualAppliance", _SOCKET)]
    assert _kinds(_check(_azure(routes=routes))) == ["gre_over_udp_required"]


def test_narrower_routes_splitting_the_system_range_are_undetermined():
    routes = [_system_route(), az._route("half", "10.254.254.128/25", "Internet")]
    finding = _one(_check(_azure(routes=routes)), "undetermined")
    assert finding["key"] == f"shared_host:{_ORG}:undetermined:route:{_HOSTS}"
    assert "is routed differently (10.254.254.128/25 via route half (Internet))" in finding["message"]


def test_a_gateway_route_is_undetermined():
    routes = [az._route("via-gateway", _SYSTEM, "VirtualNetworkGateway")]
    finding = _one(_check(_azure(routes=routes)), "undetermined")
    assert "leaves Azure through the virtual network gateway" in finding["message"]


def test_a_system_range_override_is_evaluated():
    findings = _check(system_range="10.255.0.0/24")
    finding = _one(findings, "no_route")
    assert "per-user tunnel to 10.255.0.0/24" in finding["message"]
    with pytest.raises(ValueError):
        _check(system_range="2001:db8::/64")


# ── The next hop ────────────────────────────────────────────────────────────


def test_a_next_hop_that_is_no_virtual_machine_is_undetermined():
    finding = _one(_check(_azure(routes=[_system_route("10.240.2.99")])), "undetermined")
    assert finding["key"] == f"shared_host:{_ORG}:undetermined:hop:10.240.2.99"
    assert finding["private_ip"] == "10.240.2.99"
    assert "10.240.2.99, which no collected virtual machine has" in finding["message"]


def test_ip_forwarding_off_on_the_vsocket_is_a_warning():
    finding = _one(_check(_azure(forwards=False)), "ip_forwarding_off")
    assert finding["severity"] == "warning"
    assert finding["resource_name"] == "virtual machine vsocket-1" and finding["private_ip"] == _SOCKET
    assert finding["key"] == f"shared_host:{_ORG}:ip_forwarding_off:{az.SUBSCRIPTION}:rg-vdi:vsocket-1:{_SOCKET}"
    assert "IP forwarding is off on its network interface vsocket-1-nic0" in finding["message"]
    assert "Affected hosts: avd-host-1 (10.240.1.11)" in finding["message"]


def test_a_next_hop_outside_the_cato_site_ranges_is_informational():
    finding = _one(_check(snapshot=_snapshot(ranges=("10.60.20.0/24",))), "next_hop_not_cato_site")
    assert finding["severity"] == "info"
    assert "which is in no network range of a site of Demo Cato account" in finding["message"]


# ── Network security groups ─────────────────────────────────────────────────


def _deny(name: str, direction: str, source: str = "*", destination: str = "*") -> dict:
    return az._rule(name, 100, direction, "deny", "udp", "4754", source, destination)


def test_a_host_side_deny_on_udp_4754_blocks_the_tunnel():
    findings = _check(_azure(hosts_rules=[_deny("DenyTunnelOut", "outbound", destination="10.254.254.0/24")]))
    finding = _one(findings, "nsg_blocked")
    assert (finding["protocol"], finding["ports"], finding["resource_name"]) == ("udp", "4754", "nsg-hosts")
    assert finding["rule"] == "rule DenyTunnelOut (100)"
    assert finding["key"] == f"shared_host:{_ORG}:nsg_blocked:{_NSG_HOSTS}:outbound:{_NSG_HOSTS}:DenyTunnelOut"
    assert "Network security group nsg-hosts denies udp/4754 outbound from avd-host-1" in finding["message"]
    assert finding["detail"]["direction"] == "outbound"


def test_the_default_rules_on_the_host_subnet_let_the_tunnel_out():
    # AllowVnetOutBound: Azure counts the user route's prefix in VirtualNetwork.
    assert _kinds(_check(_azure(hosts_rules=[]))) == ["gre_over_udp_required"]


def test_a_vsocket_side_deny_on_udp_4754_blocks_the_tunnel():
    allow = az._rule("AllowTunnelIn", 200, "inbound", "allow", "udp", "4754", "10.240.1.0/24", "*")
    findings = _check(_azure(lan_rules=[_deny("DenyTunnelIn", "inbound", source="10.240.1.0/24"), allow]))
    finding = _one(findings, "nsg_blocked")
    assert finding["private_ip"] == _SOCKET and finding["detail"]["direction"] == "inbound"
    assert "denies udp/4754 inbound at virtual machine vsocket-1 (10.240.2.4)" in finding["message"]
    # Only the explicit allow: the tunnel gets in.
    assert _kinds(_check(_azure(lan_rules=[allow]))) == ["gre_over_udp_required"]


def test_the_vsocket_side_judges_the_system_range_as_the_destination():
    # A rule for the vSocket's own address does not take traffic addressed to the system range.
    allow_own = az._rule("AllowToSocket", 100, "inbound", "allow", "udp", "4754", "*", f"{_SOCKET}/32")
    finding = _one(_check(_azure(lan_rules=[allow_own])), "nsg_blocked")
    assert finding["rule"] == "rule DenyAllInBound (65500)"


def test_host_and_vsocket_in_the_same_subnet():
    engine = _azure(same_subnet=True, hosts_rules=[_deny("DenyTunnelIn", "inbound", destination="10.254.254.0/24")])
    findings = _check(engine, snapshot=_snapshot(ranges=("10.240.1.0/24",)))
    finding = _one(findings, "nsg_blocked")
    assert finding["detail"]["direction"] == "inbound" and finding["private_ip"] == "10.240.1.4"
    assert "denies udp/4754 inbound at virtual machine vsocket-1 (10.240.1.4) from avd-host-1" in finding["message"]
    # The same subnet: no return route is needed, and the subnet group lets it out.
    assert _kinds(findings) == ["gre_over_udp_required", "nsg_blocked"]
    # The vSocket the rule's range also covers is no shared host.
    note = _one(findings, "gre_over_udp_required")
    assert "10.240.1.4" not in [h["ip"] for h in note["detail"]["hosts"]]


# ── Return route ────────────────────────────────────────────────────────────


def test_a_vsocket_subnet_with_no_way_back_is_a_warning():
    socket_table = f"{az.SUBSCRIPTION}:rg-vdi:rt-cato-lan"
    extra = [
        az._res(
            f"route_table:{socket_table}",
            "route_table",
            "rt-cato-lan",
            "eastus",
            resource_group="rg-vdi",
            disable_bgp_route_propagation=True,
            route_count=1,
            routes=[az._route("drop-hosts", "10.240.1.0/24", "None")],
            route_summaries=[],
            subnet_ids=[_LAN],
        )
    ]
    finding = _one(_check(_azure(extra=extra)), "no_return_route")
    assert finding["resource_name"] == "subnet cato-lan (10.240.2.0/24)"
    assert "has no route back to avd-host-1" in finding["message"]
    assert "drops the traffic (next hop None)" in finding["message"]


# ── Rule entries ────────────────────────────────────────────────────────────


def test_a_rule_range_with_no_virtual_machine_in_a_collected_subnet_is_stale():
    rule = _shared_rule(cidrs=("10.240.1.11/32", "10.240.3.0/24", "10.70.0.0/24"))
    findings = _check(snapshot=_snapshot([rule]))
    stale = _one(findings, "no_host_found")
    assert stale["key"] == f"shared_host:{_ORG}:no_host_found:Rule 1 AVD pool:10.240.3.0/24"
    assert "inside subnet spare (10.240.3.0/24) of VNet vdi-vnet" in stale["message"]
    # 10.70.0.0/24 is in no collected subnet: may be on-premises, nothing said.
    assert _kinds(findings) == ["gre_over_udp_required", "no_host_found"]
    note = _one(findings, "gre_over_udp_required")
    assert [h["ip"] for h in note["detail"]["hosts"]] == ["10.240.1.11"]
    assert note["private_ip"] == "10.240.1.11"


def test_an_unresolved_host_range_is_informational():
    findings = _check(snapshot=_snapshot([_shared_rule(unresolved=("Old-Pool",))]))
    note = _one(findings, "hosts_not_resolved")
    assert (note["severity"], note["provider"], note["key"]) == ("info", "", f"shared_host:{_ORG}:hosts_not_resolved:1")
    assert "names the global IP range Old-Pool, which did not resolve" in note["message"]


def test_no_block_a_disabled_policy_or_no_enabled_rule_says_nothing():
    snapshot = _snapshot()
    snapshot["nodes"][0]["forwarding"].pop("shared_hosts")
    assert _check(_azure(table=False), snapshot=snapshot) == []
    assert _check(_azure(table=False), snapshot=_snapshot(enabled=False)) == []
    assert _check(_azure(table=False), snapshot=_snapshot([_shared_rule(enabled=False)])) == []
    # No Azure account: nothing to evaluate.
    assert shared_host_check.check([(_ORG, _snapshot())], [("aws", object())]) == []


# ── The Cato snapshot ───────────────────────────────────────────────────────


def _cloud_forwarding(raw: dict) -> dict:
    snapshot = build_cato(raw)
    return next(n for n in snapshot["nodes"] if n["id"] == CLOUD_NODE_ID)["forwarding"]


def test_the_normalizer_builds_the_shared_hosts_block_from_the_terminal_server_policy():
    raw = build_sample_raw()
    raw["terminal_server"]["rules"] = [
        _rule(
            2,
            "AVD pool",
            allowedHostIP=[_ref("gr-1", "Lab-Pool"), _ref("gr-99", "Old-Pool")],
            excludeTraffic=[_ref("gr-3", "Corp-Networks")],
        ),
        {**_rule(1, "Citrix farm", allowedHostIP=_ref("gr-2", "Scanners"), excludeTraffic=[]), "enabled": False},
    ]
    block = _cloud_forwarding(raw)["shared_hosts"]
    assert (block["kind"], block["enabled"], block["reduced"]) == ("cato_shared_hosts", True, False)
    assert block["rules"] == [
        {
            "index": 1,
            "name": "Citrix farm",
            "enabled": False,
            "hosts": [{"name": "Scanners", "cidrs": ["10.50.10.200/30"]}],
            "unresolved": [],
            "excluded": [],
        },
        {
            "index": 2,
            "name": "AVD pool",
            "enabled": True,
            "hosts": [{"name": "Lab-Pool", "cidrs": ["10.77.128.0/22"]}],
            "unresolved": ["Old-Pool"],
            "excluded": [{"name": "Corp-Networks", "cidrs": ["10.0.0.0/8"]}],
        },
    ]
    # The egress policy is still there, next to it.
    assert _cloud_forwarding(raw)["egress_policy"]["kind"]


def test_a_policy_that_was_not_read_has_no_block():
    raw = build_sample_raw()
    raw.pop("terminal_server")
    assert "shared_hosts" not in _cloud_forwarding(raw)


# ── Storage, alerts and the API ─────────────────────────────────────────────


def _stored_finding(key: str, severity: str = "warning") -> dict:
    return {
        "key": key,
        "cato_org_ref": _ORG,
        "cato_org_name": "Demo Cato account",
        "provider": "azure",
        "kind": "no_route",
        "severity": severity,
        "message": "m",
        "detail": {},
    }


async def test_each_check_lists_updates_and_resolves_only_its_own_rows():
    await db_module.apply_cato_egress_findings([_stored_finding("shared_host:7:no_route:x")], check="shared_host")
    await db_module.apply_cato_egress_findings([_stored_finding("7:azure:vm:203.0.113.9:tcp:443:r")])
    # An egress run with nothing resolves the egress row only.
    result = await db_module.apply_cato_egress_findings([])
    assert result["resolved"] == 1
    shared = await db_module.list_cato_egress_findings(check="shared_host")
    assert [f["finding_key"] for f in shared] == ["shared_host:7:no_route:x"]
    assert shared[0]["status"] == "open" and shared[0]["check_name"] == "shared_host"
    assert await db_module.list_cato_egress_findings() == []
    assert [f["check_name"] for f in await db_module.list_cato_egress_findings(include_resolved=True)] == ["egress"]
    # And the other way round.
    await db_module.apply_cato_egress_findings([_stored_finding("7:azure:vm:203.0.113.9:tcp:443:r")])
    result = await db_module.apply_cato_egress_findings([], check="shared_host")
    assert result["resolved"] == 1
    assert [f["finding_key"] for f in await db_module.list_cato_egress_findings()] == [
        "7:azure:vm:203.0.113.9:tcp:443:r"
    ]


@pytest.fixture
def notifications(monkeypatch):
    events: list[dict] = []

    async def _capture(event: dict) -> None:
        events.append(event)

    monkeypatch.setattr(base_runner.notification_channels, "on_alert_created", _capture)
    return events


def _inputs(monkeypatch, engine: Reachability, snapshot: dict | None = None) -> None:
    async def _fake():
        return [(_ORG, snapshot or _snapshot())], [("azure", engine)], set()

    monkeypatch.setattr(runner, "_inputs", _fake)


async def test_a_run_alerts_once_and_resolves_when_the_route_is_added(monkeypatch, notifications):
    _inputs(monkeypatch, _azure(table=False))
    first = await runner.run_shared_host_check("test")
    assert first["ok"] and first["warnings"] == 1 and first["alerted"] == 1 and first["findings"] == 2
    assert first["clouds"] == ["azure"] and first["cato_accounts"] == 1
    [event] = notifications
    assert event["alert_type"] == "cato_shared_host"
    assert event["dedup_key"] == f"cato_shared_host:shared_host:{_ORG}:no_route:{_HOSTS}"
    assert event["message"].startswith("Cato shared hosts (Demo Cato account): No route to the Cato system range.")
    stored = await db_module.list_cato_egress_findings(check="shared_host")
    assert {f["kind"] for f in stored} == {"no_route", "gre_over_udp_required"}
    assert await db_module.list_cato_egress_findings() == []

    again = await runner.run_shared_host_check("test")
    assert again["alerted"] == 0 and again["new"] == 0 and len(notifications) == 1

    _inputs(monkeypatch, _azure())
    fixed = await runner.run_shared_host_check("test")
    assert fixed["resolved"] == 1 and fixed["warnings"] == 0


async def test_a_single_inventory_host_gets_a_monitoring_alert_that_auto_resolves(monkeypatch, notifications):
    db = await db_module.get_db()
    try:
        await db.execute("INSERT INTO inventory_groups (id, name) VALUES (951, 'VDI')")
        await db.execute(
            "INSERT INTO hosts (id, group_id, hostname, ip_address, device_type) "
            "VALUES (9511, 951, 'avd-host-1', '10.240.1.11', 'windows')"
        )
        await db.commit()
    finally:
        await db.close()
    _inputs(monkeypatch, _azure(table=False, hosts=("10.240.1.11",)))
    await runner.run_shared_host_check("test")
    alerts = await db_module.get_monitoring_alerts(host_id=9511)
    assert [(a["alert_type"], a["severity"]) for a in alerts] == [("cato_shared_host", "warning")]
    assert notifications == []

    _inputs(monkeypatch, _azure(hosts=("10.240.1.11",)))
    cleared = await runner.run_shared_host_check("test")
    assert cleared["alerts_cleared"] == 1
    alerts = await db_module.get_monitoring_alerts(host_id=9511)
    assert {(a["acknowledged"], a["acknowledged_by"]) for a in alerts} == {(1, "auto-resolved")}


async def test_the_run_never_raises(monkeypatch):
    async def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(runner, "_inputs", _boom)
    result = await runner.run_shared_host_check("test")
    assert result["ok"] is False and result["error"] == "RuntimeError"


def test_the_system_range_environment_variable(monkeypatch):
    monkeypatch.delenv(runner.SYSTEM_RANGE_ENV, raising=False)
    assert runner.system_range() == "10.254.254.0/24"
    monkeypatch.setenv(runner.SYSTEM_RANGE_ENV, "10.255.0.0/24")
    assert runner.system_range() == "10.255.0.0/24"
    monkeypatch.setenv(runner.SYSTEM_RANGE_ENV, "not-a-network")
    assert runner.system_range() == "10.254.254.0/24"
    monkeypatch.setenv(runner.SYSTEM_RANGE_ENV, "2001:db8::/64")
    assert runner.system_range() == "10.254.254.0/24"


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-cato-shared-hosts")
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


def test_the_sample_collections_run_the_check_and_the_api_lists_it(api, monkeypatch):
    client, headers = api
    for provider in ("cato", "azure"):
        resp = client.post(f"/api/sources/sample?provider={provider}", headers=headers)
        assert resp.status_code == 201, resp.text
    resp = client.post("/api/monitoring/cato-shared-hosts/run", headers=headers)
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["ok"] and result["cato_accounts"] == 1 and "azure" in result["clouds"]
    # The sample's Shared Hosts rule names no Azure address.
    assert result["warnings"] == 0
    assert client.get("/api/monitoring/cato-shared-hosts/findings").json() == {"findings": []}

    _inputs(monkeypatch, _azure(table=False))
    assert client.post("/api/monitoring/cato-shared-hosts/run", headers=headers).json()["warnings"] == 1
    body = client.get("/api/monitoring/cato-shared-hosts/findings").json()
    finding = next(f for f in body["findings"] if f["kind"] == "no_route")
    assert finding["kind_label"] == "No route to the Cato system range" and finding["status"] == "open"
    assert len(finding["detail"]["hosts"]) == 4
    # The egress check's list does not show them.
    egress = client.get("/api/monitoring/cato-egress/findings").json()["findings"]
    assert not any(f["finding_key"].startswith("shared_host:") for f in egress)
    assert client.get("/api/monitoring/cato-shared-hosts/findings?include_resolved=true").status_code == 200
    assert client.get("/api/monitoring/cato-shared-hosts/findings?limit=0").status_code == 422
