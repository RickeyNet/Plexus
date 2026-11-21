"""GraphQL over the object models beyond inventory and IPAM: locations and
tenancy, the device model, circuits, DCIM, virtualization, routing and
hardware lifecycle. Root queries, relations both ways, filters, feature
gates, object scope, batching and the cost limit."""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db
from graphql import parse
from netcontrol.custom_fields import OBJECT_TYPE_SPECS
from netcontrol.graphql_api import limits
from netcontrol.graphql_api.context import GraphQLContext
from netcontrol.graphql_api.schema import schema
from netcontrol.object_scope import ObjectScope
from netcontrol.routes import state

from mcp_helpers import CsrfClient, admin_client, user_client
from test_graphql_api import _gql, _group, _host, _login

FEATURES = ["organization", "circuits", "dcim", "virtualization", "routing", "lifecycle"]
ALL_FEATURES = frozenset({"graphql", "inventory", "ipam", "reports", *FEATURES})


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


async def _seed(w: dict) -> None:
    """Every model, linked to host ``ha`` (group ``a``); ``hb`` (group
    ``b``) is at another site and on the far end of a cable and a peering."""
    ha, hb = w["ha"], w["hb"]
    region = await db.create_region(name="emea")
    west = await db.create_region(name="west", parent_id=region["id"])
    customers = await db.create_tenant_group(name="customers")
    tenant = await db.create_tenant(name="acme", group_id=customers["id"])
    site = await db.create_geo_site(
        "dc-a", address="1 Example Road", region_id=west["id"], tenant_id=tenant["id"], facility="hall 1"
    )
    other = await db.create_geo_site("dc-b")
    maker = await db.create_manufacturer(name="Examplecorp")
    model = await db.create_device_type(
        manufacturer_id=maker["id"], model="EX-1000", part_number="EX-1000-AC", u_height=1
    )
    role = await db.create_device_role(name="core", color="blue")
    status = await db.create_lifecycle_status(name="in service", color="green")
    await db.set_host_device_fields(
        ha,
        {
            "device_type_id": model["id"],
            "role_id": role["id"],
            "lifecycle_status_id": status["id"],
            "site_id": site["id"],
            "tenant_id": tenant["id"],
        },
    )
    await db.set_host_device_fields(hb, {"site_id": other["id"], "device_type_id": model["id"]})

    rack_role = await db.create_dcim_record("rack_role", {"name": "network"})
    rack = await db.create_dcim_record(
        "rack", {"site_id": site["id"], "name": "r01", "tenant_id": tenant["id"], "role_id": rack_role["id"]}
    )
    assert await db.set_host_placement(ha, {"rack_id": rack["id"], "rack_position": 10, "rack_face": "front"})
    rear = await db.create_dcim_record("rear_port", {"host_id": ha, "name": "rear1", "positions": 2})
    await db.create_dcim_record(
        "front_port", {"host_id": ha, "name": "front1", "rear_port_id": rear["id"], "rear_port_position": 1}
    )
    await db.create_dcim_record("module", {"host_id": ha, "bay": "slot 1", "part_number": "MOD-1", "serial": "S1"})
    panel = await db.create_dcim_record("power_panel", {"site_id": site["id"], "name": "pp1"})
    feed = await db.create_dcim_record(
        "power_feed", {"power_panel_id": panel["id"], "rack_id": rack["id"], "name": "feed-a"}
    )
    psu = await db.create_dcim_record("power_port", {"host_id": ha, "name": "psu1", "maximum_draw": 300})
    await db.create_dcim_record("power_outlet", {"host_id": ha, "name": "out1", "power_port_id": psu["id"]})
    interface = {"type": "interface", "id": None, "name": ""}
    cable = await db.create_cable(
        {
            "a": {**interface, "host_id": ha, "name": "Gi0/1"},
            "b": {**interface, "host_id": hb, "name": "Gi0/2"},
            "label": "c-100",
            "length": 2.5,
        }
    )
    await db.create_cable(
        {
            "a": {"type": "power_feed", "id": feed["id"], "host_id": None, "name": ""},
            "b": {"type": "power_port", "id": psu["id"], "host_id": ha, "name": ""},
            "label": "pwr-1",
        }
    )

    provider = await db.create_circuit_provider({"name": "Example Carrier", "account": "ACC-1"})
    circuit_type = await db.create_circuit_type({"name": "internet"})
    circuit = await db.create_circuit(
        {
            "cid": "CID-100",
            "provider_id": provider["id"],
            "circuit_type_id": circuit_type["id"],
            "tenant_id": tenant["id"],
            "commit_rate_kbps": 100000,
        }
    )
    await db.create_circuit_termination(
        circuit["id"], "A", {"site_id": site["id"], "host_id": ha, "interface_name": "Gi0/0"}
    )

    cluster_type = await db.create_cluster_type(name="hypervisor")
    cluster = await db.create_cluster({"name": "cl-1", "cluster_type_id": cluster_type["id"], "site_id": site["id"]})
    await db.add_cluster_host(cluster["id"], ha)
    vm = await db.create_virtual_machine(
        {"name": "vm-1", "cluster_id": cluster["id"], "vcpus": 2, "role_id": role["id"], "tenant_id": tenant["id"]}
    )
    await db.create_vm_interface(vm["id"], {"name": "eth0", "mac_address": "02:00:00:00:00:01"}, ["192.0.2.50/24"])

    local = await db.create_autonomous_system(asn=64512, description="lab")
    remote = await db.create_autonomous_system(asn=64513, tenant_id=tenant["id"])
    instance = await db.create_routing_instance(
        host_id=ha, values={"name": "default", "autonomous_system_id": local["id"], "router_id": "192.0.2.1"}
    )
    peering = await db.create_bgp_peering(
        routing_instance_id=instance["id"],
        values={"remote_address": "198.51.100.1", "remote_asn_id": remote["id"], "remote_host_id": hb},
    )

    await db.create_hardware_notice({"device_type_id": model["id"], "end_of_sale": "2030-01-01"})
    await db.create_support_contract(
        {"provider": "Example Support", "contract_id": "SC-1", "cost": "100.50", "currency": "EUR"}, [ha]
    )
    w.update(
        site=site["id"],
        other_site=other["id"],
        tenant=tenant["id"],
        rack=rack["id"],
        cluster=cluster["id"],
        vm=vm["id"],
        model=model["id"],
        circuit=circuit["id"],
        region=west["id"],
        maker=maker["id"],
        role=role["id"],
        provider=provider["id"],
        asn=local["id"],
        peering=peering["id"],
        cable=cable,
    )


@pytest.fixture
def world(admin) -> dict:
    w: dict = {}
    w["a"] = _group(admin, "site-a")
    w["b"] = _group(admin, "site-b")
    w["ha"] = _host(admin, w["a"], "edge-r1", "192.0.2.10")
    w["hb"] = _host(admin, w["b"], "edge-r2", "198.51.100.20")
    asyncio.run(_seed(w))
    return w


def _run(query: str, scope: ObjectScope, features: frozenset[str] | None = None, variables: dict | None = None) -> dict:
    """Execute ``query`` on the schema with a context built directly (a
    scope and feature set the HTTP layer would give)."""

    async def go() -> dict:
        context = GraphQLContext(scope=scope, features=features, max_limit=1000)
        result = await schema.execute(query, variable_values=variables, context_value=context)
        return {"data": result.data, "errors": [e.message for e in result.errors or []]}

    return asyncio.run(go())


# ── Root queries and relations ───────────────────────────────────────────────


def test_host_relations_to_every_model(admin, world):
    query = """query($id: Int!) {
      host(id: $id) {
        hostname
        hardware { model partNumber manufacturer { name } }
        role { name color }
        lifecycleStatus { name }
        site { name region { name parent { name } } }
        tenant { name group { name } }
        rack { name } rackPosition rackFace
        frontPorts { name rearPort { name positions } }
        rearPorts { name frontPorts { name } }
        modules { bay partNumber }
        powerPorts { name maximumDraw outlets { name } cable { label a { type } } }
        powerOutlets { name powerPort { name } }
        cables { label length a { type name host { hostname } } b { type name label host { hostname } } }
        circuitTerminations { termSide interfaceName circuit { cid } site { name } }
        clusters { name virtualMachines { name } }
        routingInstances { name asn routerId autonomousSystem { asn } }
        bgpPeerings { remoteAddress remoteAsn remoteHost { hostname } remoteAutonomousSystem { asn } }
        hardwareNotices { endOfSale deviceType { model } }
        supportContracts { contractId cost currency }
      }
    }"""
    body = _gql(admin, query, {"id": world["ha"]})
    assert "errors" not in body, body
    host = body["data"]["host"]
    assert host["hardware"] == {"model": "EX-1000", "partNumber": "EX-1000-AC", "manufacturer": {"name": "Examplecorp"}}
    assert host["role"] == {"name": "core", "color": "blue"}
    assert host["lifecycleStatus"] == {"name": "in service"}
    assert host["site"] == {"name": "dc-a", "region": {"name": "west", "parent": {"name": "emea"}}}
    assert host["tenant"] == {"name": "acme", "group": {"name": "customers"}}
    assert (host["rack"], host["rackPosition"], host["rackFace"]) == ({"name": "r01"}, 10, "front")
    assert host["frontPorts"] == [{"name": "front1", "rearPort": {"name": "rear1", "positions": 2}}]
    assert host["rearPorts"] == [{"name": "rear1", "frontPorts": [{"name": "front1"}]}]
    assert host["modules"] == [{"bay": "slot 1", "partNumber": "MOD-1"}]
    assert host["powerPorts"] == [
        {
            "name": "psu1",
            "maximumDraw": 300,
            "outlets": [{"name": "out1"}],
            "cable": {"label": "pwr-1", "a": {"type": "power_feed"}},
        }
    ]
    assert host["powerOutlets"] == [{"name": "out1", "powerPort": {"name": "psu1"}}]
    cables = {c["label"]: c for c in host["cables"]}
    assert set(cables) == {"c-100", "pwr-1"}
    assert cables["c-100"]["length"] == 2.5
    assert cables["c-100"]["a"] == {"type": "interface", "name": "Gi0/1", "host": {"hostname": "edge-r1"}}
    assert cables["c-100"]["b"] == {
        "type": "interface",
        "name": "Gi0/2",
        "label": "edge-r2 / Gi0/2",
        "host": {"hostname": "edge-r2"},
    }
    assert host["circuitTerminations"] == [
        {"termSide": "A", "interfaceName": "Gi0/0", "circuit": {"cid": "CID-100"}, "site": {"name": "dc-a"}}
    ]
    assert host["clusters"] == [{"name": "cl-1", "virtualMachines": [{"name": "vm-1"}]}]
    assert host["routingInstances"] == [
        {"name": "default", "asn": 64512, "routerId": "192.0.2.1", "autonomousSystem": {"asn": 64512}}
    ]
    assert host["bgpPeerings"] == [
        {
            "remoteAddress": "198.51.100.1",
            "remoteAsn": 64513,
            "remoteHost": {"hostname": "edge-r2"},
            "remoteAutonomousSystem": {"asn": 64513},
        }
    ]
    assert host["hardwareNotices"] == [{"endOfSale": "2030-01-01", "deviceType": {"model": "EX-1000"}}]
    assert host["supportContracts"] == [{"contractId": "SC-1", "cost": "100.50", "currency": "EUR"}]


def test_root_queries_and_reverse_relations(admin, world):
    query = """{
      regions(limit: 10) { name path depth children { name } sites(limit: 20) { name } }
      sites(name: "dc-a", limit: 10) {
        name address facility status lat
        tenant { name } hosts(limit: 20) { hostname } racks(limit: 20) { name } powerPanels(limit: 20) { name powerFeeds { name } }
        circuits(limit: 20) { cid } clusters(limit: 20) { name } vlans(limit: 20) { vid }
      }
      tenantGroups(limit: 10) { name tenants(limit: 20) { name } }
      tenants(limit: 10) { name sites(limit: 20) { name } hosts(limit: 20) { hostname } circuits(limit: 20) { cid } racks(limit: 20) { name } clusters(limit: 20) { name }
                virtualMachines(limit: 20) { name } }
      manufacturers(limit: 10) { name deviceTypes(limit: 20) { model hosts(limit: 20) { hostname } hardwareNotices { endOfSale } } }
      deviceRoles(name: "core") { name hosts(limit: 20) { hostname } virtualMachines(limit: 20) { name } }
      lifecycleStatuses(name: "in service") { name isDefault hosts(limit: 20) { hostname } }
      circuitProviders(limit: 10) { name account circuits(limit: 20) { cid } networks { name } }
      circuitTypes(limit: 10) { name circuits(limit: 20) { cid provider { name } circuitType { name } tenant { name }
                     commitRateKbps terminations { termSide host { hostname } } } }
      racks(limit: 10) { name uHeight descUnits width site { name } role { name } tenant { name } hosts(limit: 20) { hostname }
              powerFeeds { name powerPanel { name } cable { label } } }
      rackRoles(limit: 10) { name racks(limit: 20) { name } }
      cables(limit: 10) { label a { type } b { type } }
      frontPorts(limit: 10) { name host { hostname } }
      rearPorts(limit: 10) { name }
      modules(limit: 10) { bay host { hostname } }
      powerPanels(limit: 10) { name site { name } }
      powerFeeds(limit: 10) { name rack { name } voltage amperage }
      powerPorts(limit: 10) { name }
      powerOutlets(limit: 10) { name }
      clusters(limit: 10) { name clusterTypeName site { name } hosts(limit: 20) { hostname }
                 virtualMachines(limit: 20) { name vcpus role { name } tenant { name } cluster { name }
                                   interfaces { name macAddress enabled addresses } } }
      autonomousSystems(limit: 10) { asn tenant { name } routingInstances { name } peerings(limit: 20) { remoteAddress } }
      routingInstances(limit: 10) { name host { hostname } peerings { remoteAddress routingInstance { name } host { hostname } } }
      bgpPeerings(limit: 10) { remoteAddress localAsn addressFamilies }
      hardwareNotices(limit: 10) { endOfSale deviceType { model } hosts(limit: 20) { hostname } }
      supportContracts(limit: 10) { provider contractId hosts(limit: 20) { hostname } }
    }"""
    body = _gql(admin, query)
    assert "errors" not in body, body
    data = body["data"]
    assert data["regions"] == [
        {"name": "emea", "path": "emea", "depth": 0, "children": [{"name": "west"}], "sites": []},
        {"name": "west", "path": "emea / west", "depth": 1, "children": [], "sites": [{"name": "dc-a"}]},
    ]
    assert data["sites"] == [
        {
            "name": "dc-a",
            "address": "1 Example Road",
            "facility": "hall 1",
            "status": "active",
            "lat": None,
            "tenant": {"name": "acme"},
            "hosts": [{"hostname": "edge-r1"}],
            "racks": [{"name": "r01"}],
            "powerPanels": [{"name": "pp1", "powerFeeds": [{"name": "feed-a"}]}],
            "circuits": [{"cid": "CID-100"}],
            "clusters": [{"name": "cl-1"}],
            "vlans": [],
        }
    ]
    assert data["tenantGroups"] == [{"name": "customers", "tenants": [{"name": "acme"}]}]
    assert data["tenants"] == [
        {
            "name": "acme",
            "sites": [{"name": "dc-a"}],
            "hosts": [{"hostname": "edge-r1"}],
            "circuits": [{"cid": "CID-100"}],
            "racks": [{"name": "r01"}],
            "clusters": [],
            "virtualMachines": [{"name": "vm-1"}],
        }
    ]
    device_type = data["manufacturers"][0]["deviceTypes"][0]
    assert {h["hostname"] for h in device_type["hosts"]} == {"edge-r1", "edge-r2"}
    assert device_type["hardwareNotices"] == [{"endOfSale": "2030-01-01"}]
    assert data["deviceRoles"] == [
        {"name": "core", "hosts": [{"hostname": "edge-r1"}], "virtualMachines": [{"name": "vm-1"}]}
    ]
    statuses = {s["name"]: s for s in data["lifecycleStatuses"]}
    assert statuses["in service"]["hosts"] == [{"hostname": "edge-r1"}]
    assert data["circuitProviders"] == [
        {"name": "Example Carrier", "account": "ACC-1", "circuits": [{"cid": "CID-100"}], "networks": []}
    ]
    assert data["circuitTypes"][0]["circuits"] == [
        {
            "cid": "CID-100",
            "provider": {"name": "Example Carrier"},
            "circuitType": {"name": "internet"},
            "tenant": {"name": "acme"},
            "commitRateKbps": 100000,
            "terminations": [{"termSide": "A", "host": {"hostname": "edge-r1"}}],
        }
    ]
    rack = data["racks"][0]
    assert rack["uHeight"] == 42 and rack["descUnits"] is False and rack["width"] == 19
    assert (
        rack["site"] == {"name": "dc-a"} and rack["role"] == {"name": "network"} and rack["tenant"] == {"name": "acme"}
    )
    assert rack["hosts"] == [{"hostname": "edge-r1"}]
    assert rack["powerFeeds"] == [{"name": "feed-a", "powerPanel": {"name": "pp1"}, "cable": {"label": "pwr-1"}}]
    assert data["rackRoles"] == [{"name": "network", "racks": [{"name": "r01"}]}]
    assert len(data["cables"]) == 2
    assert data["frontPorts"] == [{"name": "front1", "host": {"hostname": "edge-r1"}}]
    assert data["modules"] == [{"bay": "slot 1", "host": {"hostname": "edge-r1"}}]
    assert data["powerFeeds"] == [{"name": "feed-a", "rack": {"name": "r01"}, "voltage": 230, "amperage": 16}]
    cluster = data["clusters"][0]
    assert cluster["clusterTypeName"] == "hypervisor" and cluster["hosts"] == [{"hostname": "edge-r1"}]
    assert cluster["virtualMachines"] == [
        {
            "name": "vm-1",
            "vcpus": 2,
            "role": {"name": "core"},
            "tenant": {"name": "acme"},
            "cluster": {"name": "cl-1"},
            "interfaces": [
                {"name": "eth0", "macAddress": "02:00:00:00:00:01", "enabled": True, "addresses": ["192.0.2.50/24"]}
            ],
        }
    ]
    by_asn = {a["asn"]: a for a in data["autonomousSystems"]}
    assert by_asn[64512]["routingInstances"] == [{"name": "default"}] and by_asn[64512]["peerings"] == []
    assert by_asn[64513]["tenant"] == {"name": "acme"} and by_asn[64513]["peerings"] == [
        {"remoteAddress": "198.51.100.1"}
    ]
    assert data["routingInstances"][0]["peerings"] == [
        {"remoteAddress": "198.51.100.1", "routingInstance": {"name": "default"}, "host": {"hostname": "edge-r1"}}
    ]
    assert data["bgpPeerings"] == [{"remoteAddress": "198.51.100.1", "localAsn": 64512, "addressFamilies": []}]
    notice_hosts = {h["hostname"] for h in data["hardwareNotices"][0]["hosts"]}
    assert notice_hosts == {"edge-r1", "edge-r2"}
    assert data["supportContracts"] == [
        {"provider": "Example Support", "contractId": "SC-1", "hosts": [{"hostname": "edge-r1"}]}
    ]


def test_get_by_id_queries(admin, world):
    query = """query($site: Int!, $tenant: Int!, $rack: Int!, $cluster: Int!, $vm: Int!, $model: Int!, $circuit: Int!) {
      site(id: $site) { name } tenant(id: $tenant) { name } rack(id: $rack) { name }
      cluster(id: $cluster) { name } virtualMachine(id: $vm) { name } deviceType(id: $model) { model }
      circuit(id: $circuit) { cid } unknown: site(id: 999999) { name }
    }"""
    variables = {k: world[k] for k in ("site", "tenant", "rack", "cluster", "vm", "model", "circuit")}
    data = _gql(admin, query, variables)["data"]
    assert data == {
        "site": {"name": "dc-a"},
        "tenant": {"name": "acme"},
        "rack": {"name": "r01"},
        "cluster": {"name": "cl-1"},
        "virtualMachine": {"name": "vm-1"},
        "deviceType": {"model": "EX-1000"},
        "circuit": {"cid": "CID-100"},
        "unknown": None,
    }
    ids = _gql(admin, "{ regions { id } tenantGroups { id } manufacturers { id } cables { id } }")["data"]
    cable_id = ids["cables"][0]["id"]
    query = "query($r: Int!, $m: Int!, $c: Int!) { region(id: $r) { name } manufacturer(id: $m) { name } cable(id: $c) { id } }"
    data = _gql(admin, query, {"r": ids["regions"][0]["id"], "m": ids["manufacturers"][0]["id"], "c": cable_id})["data"]
    assert data == {"region": {"name": "emea"}, "manufacturer": {"name": "Examplecorp"}, "cable": {"id": cable_id}}


def test_filters(admin, world):
    query = """query($site: Int!, $other: Int!, $tenant: Int!, $ha: Int!, $hb: Int!) {
      sitesByTenant: sites(tenantId: $tenant) { name }
      sitesNone: sites(status: "retired") { name }
      racksAtOther: racks(siteId: $other) { name }
      circuitsAtSite: circuits(siteId: $site) { cid }
      circuitsOfHb: circuits(hostId: $hb) { cid }
      cablesOfHb: cables(hostId: $hb) { label }
      portsOfHb: frontPorts(hostId: $hb) { name }
      modulesByPart: modules(partNumber: "mod") { bay }
      vmsByName: virtualMachines(name: "VM-") { name }
      asByNumber: autonomousSystems(asn: 64513) { asn }
      peeringsByAsn: bgpPeerings(asn: 64512) { remoteAddress }
      instancesOfHb: routingInstances(hostId: $hb) { name }
      contractsOfHa: supportContracts(hostId: $ha) { contractId }
      typesByPart: deviceTypes(partNumber: "ex-1000") { model }
      pagedHosts: sites(limit: 1, offset: 1) { name }
    }"""
    variables = {
        "site": world["site"],
        "other": world["other_site"],
        "tenant": world["tenant"],
        "ha": world["ha"],
        "hb": world["hb"],
    }
    data = _gql(admin, query, variables)["data"]
    assert data["sitesByTenant"] == [{"name": "dc-a"}]
    assert data["sitesNone"] == [] and data["racksAtOther"] == [] and data["circuitsOfHb"] == []
    assert data["circuitsAtSite"] == [{"cid": "CID-100"}]
    assert data["cablesOfHb"] == [{"label": "c-100"}]
    assert data["portsOfHb"] == []
    assert data["modulesByPart"] == [{"bay": "slot 1"}]
    assert data["vmsByName"] == [{"name": "vm-1"}]
    assert data["asByNumber"] == [{"asn": 64513}]
    assert data["peeringsByAsn"] == [{"remoteAddress": "198.51.100.1"}]
    assert data["instancesOfHb"] == []
    assert data["contractsOfHa"] == [{"contractId": "SC-1"}]
    assert data["typesByPart"] == [{"model": "EX-1000"}]
    assert data["pagedHosts"] == [{"name": "dc-b"}]
    body = _gql(admin, "{ racks(limit: 0) { id } }")
    assert body["data"] == {"racks": None}
    assert body["errors"][0]["message"] == "limit must be between 1 and 1000"


# ── Access ───────────────────────────────────────────────────────────────────

_ROOTS_BY_FEATURE = {
    "organization": ["regions", "sites", "tenantGroups", "tenants"],
    "circuits": ["circuitProviders", "circuitTypes", "circuits"],
    "dcim": [
        "racks",
        "rackRoles",
        "cables",
        "frontPorts",
        "rearPorts",
        "modules",
        "powerPanels",
        "powerFeeds",
        "powerPorts",
        "powerOutlets",
    ],
    "virtualization": ["clusters", "virtualMachines"],
    "routing": ["autonomousSystems", "routingInstances", "bgpPeerings"],
    "lifecycle": ["hardwareNotices", "supportContracts"],
}


def test_each_root_needs_the_feature_of_its_rest_router(admin, world):
    reader = user_client(admin, "gql-models", features=["graphql", "inventory"])
    roots = [r for names in _ROOTS_BY_FEATURE.values() for r in names]
    body = _gql(reader, "{ " + " ".join(f"{r} {{ id }}" for r in roots) + " manufacturers { name } }")
    assert all(body["data"][r] is None for r in roots)
    # The device model catalogues are open to every signed-in user, as in REST.
    assert body["data"]["manufacturers"] == [{"name": "Examplecorp"}]
    assert {e["message"] for e in body["errors"]} == {f"Access denied for feature '{f}'" for f in FEATURES}

    # A relation checks the feature of the type it reaches.
    body = _gql(
        reader,
        '{ hosts(name: "edge-r1") { hostname hardware { model } site { name } rack { name } '
        "clusters { name } supportContracts { id } bgpPeerings { id } circuitTerminations { id } } }",
    )
    host = body["data"]["hosts"][0]
    assert host["hardware"] == {"model": "EX-1000"}
    assert all(
        host[k] is None for k in ("site", "rack", "clusters", "supportContracts", "bgpPeerings", "circuitTerminations")
    )
    assert {e["message"] for e in body["errors"]} == {f"Access denied for feature '{f}'" for f in FEATURES}

    # Each feature opens its own roots.
    for feature, names in _ROOTS_BY_FEATURE.items():
        one = user_client(admin, f"gql-{feature}", features=["graphql", feature])
        body = _gql(one, "{ " + " ".join(f"{r} {{ id }}" for r in names) + " }")
        assert "errors" not in body, (feature, body)
        assert all(isinstance(body["data"][r], list) for r in names)


def test_scoped_caller_reads_rows_by_the_scope_model_registry(admin, world):
    """Rows go through ``object_scope.filter_rows``: readable when any key
    (host, tenant, site) is reached by the granted groups; shared reference
    rows with no key are read by everyone."""
    scope = ObjectScope(unrestricted=False, read_groups=frozenset({world["b"]}))
    query = """{
      hosts { hostname cables { label } }
      sites { name } racks { name } cables { label } frontPorts { name } modules { bay }
      circuits { cid } clusters { name } virtualMachines { name }
      routingInstances { name } bgpPeerings { remoteAddress }
      hardwareNotices { hosts { hostname } } supportContracts { contractId }
      regions { name } tenants { name } autonomousSystems { asn } powerPanels { name } circuitProviders { name }
      manufacturers { name deviceTypes { hosts { hostname } } }
    }"""
    data = _run(query, scope, ALL_FEATURES)["data"]
    # edge-r2 (group b, no tenant, site dc-b, not in a rack) is the only
    # readable host, so its own site dc-b is readable. The cable to edge-r1 has
    # edge-r2 as a key, so it is readable; edge-r1's own records, its site,
    # tenant, rack, circuit and cluster are not.
    assert data["hosts"] == [{"hostname": "edge-r2", "cables": [{"label": "c-100"}]}]
    assert data["cables"] == [{"label": "c-100"}]
    assert data["sites"] == [{"name": "dc-b"}]
    for key in (
        "racks",
        "frontPorts",
        "modules",
        "circuits",
        "clusters",
        "virtualMachines",
        "routingInstances",
        "bgpPeerings",
        "supportContracts",
        "tenants",
        "powerPanels",
    ):
        assert data[key] == [], key
    # Shared reference data: notices (their hosts within scope), regions,
    # providers, an AS of no tenant (64513 belongs to acme: hidden).
    assert data["hardwareNotices"] == [{"hosts": [{"hostname": "edge-r2"}]}]
    assert [r["name"] for r in data["regions"]] == ["emea", "west"]
    assert data["circuitProviders"] == [{"name": "Example Carrier"}]
    assert data["autonomousSystems"] == [{"asn": 64512}]
    assert data["manufacturers"] == [{"name": "Examplecorp", "deviceTypes": [{"hosts": [{"hostname": "edge-r2"}]}]}]

    # Group a reaches edge-r1, its tenant acme and dc-a (its rack's site).
    scope_a = ObjectScope(unrestricted=False, read_groups=frozenset({world["a"]}))
    data = _run(query, scope_a, ALL_FEATURES)["data"]
    assert data["hosts"] == [{"hostname": "edge-r1", "cables": [{"label": "c-100"}, {"label": "pwr-1"}]}]
    assert data["sites"] == [{"name": "dc-a"}] and data["racks"] == [{"name": "r01"}]
    assert data["circuits"] == [{"cid": "CID-100"}] and data["clusters"] == [{"name": "cl-1"}]
    assert data["virtualMachines"] == [{"name": "vm-1"}] and data["tenants"] == [{"name": "acme"}]
    assert data["supportContracts"] == [{"contractId": "SC-1"}]
    assert data["bgpPeerings"] == [{"remoteAddress": "198.51.100.1"}]
    assert data["powerPanels"] == [{"name": "pp1"}]
    assert sorted(a["asn"] for a in data["autonomousSystems"]) == [64512, 64513]
    # A relation to a host out of scope reads null.
    assert _run(
        f"{{ host(id: {world['ha']}) {{ bgpPeerings {{ remoteHost {{ hostname }} }} }} }}", scope_a, ALL_FEATURES
    )["data"] == {"host": {"bgpPeerings": [{"remoteHost": None}]}}

    # No grant at all: only shared rows.
    data = _run("{ sites { name } regions { name } cables { id } }", ObjectScope(unrestricted=False), ALL_FEATURES)
    assert data["data"] == {"sites": [], "regions": [{"name": "emea"}, {"name": "west"}], "cables": []}


def test_scoped_user_with_site_and_tenant_scope_rules(admin, world):
    """Over HTTP: a user limited to group b, plus scope rules granting the
    racks of site dc-a and the circuits of tenant acme."""
    features = ["graphql", "inventory", *FEATURES]
    body = {
        "name": "rules access",
        "feature_keys": features,
        "object_scope": "groups",
        "inventory_scopes": [{"inventory_group_id": world["b"]}],
    }
    group = admin.post("/api/admin/access-groups", json=body)
    assert group.status_code == 201, group.text
    rules = {
        "rules": [
            {"model": "rack", "attribute": "site", "value_id": world["site"]},
            {"model": "circuit", "attribute": "tenant", "value_id": world["tenant"]},
        ]
    }
    resp = admin.put(f"/api/admin/access-groups/{group.json()['id']}/scope-rules", json=rules)
    assert resp.status_code == 200, resp.text
    user = {"username": "rules-user", "password": "password123", "group_ids": [group.json()["id"]]}
    assert admin.post("/api/admin/users", json=user).status_code == 201
    client = _login("rules-user")
    body = _gql(client, "{ hosts { hostname } racks { name } circuits { cid } sites { name } clusters { name } }")
    assert "errors" not in body, body
    assert body["data"] == {
        "hosts": [{"hostname": "edge-r2"}],
        "racks": [{"name": "r01"}],
        "circuits": [{"cid": "CID-100"}],
        # edge-r2's own site; the rack rule grants racks, not their site.
        "sites": [{"name": "dc-b"}],
        "clusters": [],
    }


# ── Tags, custom fields, computed fields ─────────────────────────────────────

# Object type -> (the root list that reaches it, the world key of its id).
_CUSTOM_ROOTS = {
    "host": ("hosts", "ha"),
    "group": ("groups", "a"),
    "prefix": ("prefixes", "prefix"),
    "vrf": ("vrfs", "vrf"),
    "vlan": ("vlans", "vlan"),
    "region": ("regions", "region"),
    "site": ("sites", "site"),
    "tenant": ("tenants", "tenant"),
    "manufacturer": ("manufacturers", "maker"),
    "device_type": ("deviceTypes", "model"),
    "device_role": ("deviceRoles", "role"),
    "circuit_provider": ("circuitProviders", "provider"),
    "circuit": ("circuits", "circuit"),
    "cluster": ("clusters", "cluster"),
    "virtual_machine": ("virtualMachines", "vm"),
    "autonomous_system": ("autonomousSystems", "asn"),
    "bgp_peering": ("bgpPeerings", "peering"),
    "rack": ("racks", "rack"),
    "cable": ("cables", "cable"),
}


def test_every_custom_data_type_has_tags_custom_and_computed_fields(admin, world):
    assert set(_CUSTOM_ROOTS) == set(OBJECT_TYPE_SPECS)

    async def seed() -> None:
        source = await db.create_ipam_source(provider="netbox", name="lab ipam", base_url="https://ipam.example.com")
        assert source is not None
        await db.replace_ipam_source_snapshot(int(source["id"]), [{"id": 1, "subnet": "192.0.2.0/24"}], [])
        world["prefix"] = next(int(p["id"]) for p in await db.list_ipam_prefix_records())
        world["vrf"] = (await db.create_vrf(name="BLUE"))["id"]
        world["vlan"] = (await db.create_vlan(vid=10, name="users"))["id"]
        tag = await db.create_tag(name="gold", color="green")
        field = await db.create_custom_field(
            key="owner",
            label="Owner",
            field_type="text",
            choices=[],
            object_types=list(OBJECT_TYPE_SPECS),
            required=False,
            default_value="",
            description="",
            sort_order=0,
            created_by="admin",
        )
        for object_type in OBJECT_TYPE_SPECS:
            await db.create_computed_field(
                key="label", label="Label", object_type=object_type, template="{{ custom_fields.owner }}!"
            )
            key = "192.0.2.0/24|" if object_type == "prefix" else str(world[_CUSTOM_ROOTS[object_type][1]])
            await db.set_object_data(object_type, key, [int(tag["id"])], {int(field["id"]): f"team-{object_type}"})

    asyncio.run(seed())
    roots = list(_CUSTOM_ROOTS.items())
    for chunk in (roots[:10], roots[10:]):
        query = (
            "{ "
            + " ".join(
                f"{t}: {root}(limit: 50) {{ id tags {{ name }} customFields {{ key value }} computedFields }}"
                for t, (root, _) in chunk
            )
            + " }"
        )
        body = _gql(admin, query)
        assert "errors" not in body, body
        for object_type, (_root, key) in chunk:
            row = next(r for r in body["data"][object_type] if r["id"] == world[key])
            assert row["tags"] == [{"name": "gold"}], object_type
            assert row["customFields"] == [{"key": "owner", "value": f"team-{object_type}"}], object_type
            assert row["computedFields"] == {"label": f"team-{object_type}!"}, object_type


def test_custom_data_is_batched_per_request(admin, world, monkeypatch):
    calls = {"n": 0}
    import netcontrol.graphql_api.context as context_module

    original = context_module.object_custom_data_bulk

    async def counting(object_type, rows, **kwargs):
        calls["n"] += 1
        return await original(object_type, rows, **kwargs)

    monkeypatch.setattr(context_module, "object_custom_data_bulk", counting)
    for i in range(4):
        _host(admin, world["a"], f"edge-c{i}", f"192.0.2.{120 + i}")
    result = _run("{ hosts { tags { name } customFields { key } computedFields } }", ObjectScope(unrestricted=True))
    assert result["errors"] == [] and len(result["data"]["hosts"]) >= 6
    assert calls["n"] == 1


# ── IPAM model (migration 0110) ──────────────────────────────────────────────


def test_ipam_model_types_and_relations(admin, world):
    async def seed() -> None:
        lab = await db.create_dcim_record("namespace", {"name": "lab"})
        world["namespace"] = lab["id"]
        rt = await db.create_dcim_record("route_target", {"name": "64512:100", "tenant_id": world["tenant"]})
        group = await db.create_dcim_record(
            "vlan_group", {"name": "dc-a vlans", "site_id": world["site"], "min_vid": 100, "max_vid": 199}
        )
        rir = await db.create_dcim_record("rir", {"name": "Documentation", "is_private": True})
        await db.create_dcim_record("aggregate", {"prefix": "192.0.2.0/24", "rir_id": rir["id"]})
        vrf = await db.create_vrf(name="BLUE", namespace_id=lab["id"])
        assert await db.set_vrf_route_targets(vrf["id"], [rt["id"]], []) == []
        await db.create_vlan(vid=150, name="servers", vlan_group_id=group["id"])
        source = await db.create_ipam_source(provider="netbox", name="lab ipam", base_url="https://ipam.example.com")
        assert source is not None
        await db.replace_ipam_source_snapshot(int(source["id"]), [{"id": 1, "subnet": "192.0.2.0/26"}], [])
        await db.create_dcim_record(
            "component_template", {"device_type_id": world["model"], "component_type": "power_port", "name": "PSU1"}
        )

    asyncio.run(seed())
    query = """{
      namespaces { name vrfCount }
      routeTargets { name importVrfCount tenant { name } }
      vlanGroups { name minVid maxVid site { name } vlans(limit: 20) { vid } }
      rirs { name isPrivate aggregates { prefix } }
      aggregates(contains: "192.0.2.5") { prefix prefixCount totalAddresses usedAddresses utilizationPct rir { name } }
      vrfs(name: "BLUE") { name namespace { name } routeTargets { import { name } export { name } } }
      prefixes { prefix namespace { name } aggregate { prefix } }
      vlans(vid: 150) { name vlanGroup { name } }
      deviceTypes { model componentTemplates { componentType name } }
    }"""
    body = _gql(admin, query)
    assert "errors" not in body, body
    data = body["data"]
    assert {n["name"] for n in data["namespaces"]} >= {"Global", "lab"}
    assert data["routeTargets"] == [{"name": "64512:100", "importVrfCount": 1, "tenant": {"name": "acme"}}]
    assert data["vlanGroups"] == [
        {"name": "dc-a vlans", "minVid": 100, "maxVid": 199, "site": {"name": "dc-a"}, "vlans": [{"vid": 150}]}
    ]
    assert data["rirs"] == [{"name": "Documentation", "isPrivate": True, "aggregates": [{"prefix": "192.0.2.0/24"}]}]
    assert data["aggregates"] == [
        {
            "prefix": "192.0.2.0/24",
            "prefixCount": 1,
            "totalAddresses": "256",
            "usedAddresses": "64",
            "utilizationPct": 25.0,
            "rir": {"name": "Documentation"},
        }
    ]
    assert data["vrfs"] == [
        {
            "name": "BLUE",
            "namespace": {"name": "lab"},
            "routeTargets": {"import": [{"name": "64512:100"}], "export": []},
        }
    ]
    assert data["prefixes"] == [
        {"prefix": "192.0.2.0/26", "namespace": {"name": "Global"}, "aggregate": {"prefix": "192.0.2.0/24"}}
    ]
    assert data["vlans"] == [{"name": "servers", "vlanGroup": {"name": "dc-a vlans"}}]
    assert data["deviceTypes"][0]["componentTemplates"] == [{"componentType": "power_port", "name": "PSU1"}]

    # The new IPAM roots need ipam; component templates follow the catalogue rule.
    reader = user_client(admin, "gql-noipam", features=["graphql", "inventory"])
    body = _gql(
        reader,
        "{ namespaces { id } routeTargets { id } vlanGroups { id } rirs { id } aggregates { id } "
        "deviceTypes { componentTemplates { name } } }",
    )
    assert all(body["data"][k] is None for k in ("namespaces", "routeTargets", "vlanGroups", "rirs", "aggregates"))
    assert body["data"]["deviceTypes"][0]["componentTemplates"] == [{"name": "PSU1"}]
    assert {e["message"] for e in body["errors"]} == {"Access denied for feature 'ipam'"}

    # A scoped caller: shared rows of no tenant are read, a route target of a
    # tenant out of reach is not; a VLAN group of a site out of reach neither.
    scope_b = ObjectScope(unrestricted=False, read_groups=frozenset({world["b"]}))
    data = _run(
        "{ rirs { name } routeTargets { name } vlanGroups { name } namespaces { name } }", scope_b, ALL_FEATURES
    )
    assert data["errors"] == []
    assert data["data"]["rirs"] == [{"name": "Documentation"}]
    assert data["data"]["routeTargets"] == [] and data["data"]["vlanGroups"] == []
    scope_a = ObjectScope(unrestricted=False, read_groups=frozenset({world["a"]}))
    data = _run("{ routeTargets { name } vlanGroups { name } }", scope_a, ALL_FEATURES)["data"]
    assert data == {"routeTargets": [{"name": "64512:100"}], "vlanGroups": [{"name": "dc-a vlans"}]}


# ── Batching and limits ──────────────────────────────────────────────────────

_NESTED = """{
  hosts { hostname hardware { model manufacturer { name } } role { name } lifecycleStatus { name }
          site { name region { name } tenant { name } } tenant { name } rack { name site { name } }
          frontPorts { name rearPort { name } cable { label } } rearPorts { name } modules { bay }
          powerPorts { name outlets { name } cable { label } } powerOutlets { name powerPort { name } }
          cables { label a { host { hostname } } }
          circuitTerminations { circuit { cid provider { name } } }
          clusters { name virtualMachines { name interfaces { name } } }
          routingInstances { name autonomousSystem { asn } peerings { remoteAddress } }
          bgpPeerings { remoteAutonomousSystem { asn } }
          hardwareNotices { endOfSale } supportContracts { contractId } }
}"""


def test_nested_queries_run_a_fixed_number_of_database_reads(admin, world, monkeypatch):
    original = db.get_db
    calls = {"n": 0}

    async def counting(*args, **kwargs):
        calls["n"] += 1
        return await original(*args, **kwargs)

    def count() -> int:
        calls["n"] = 0
        result = _run(_NESTED, ObjectScope(unrestricted=True))
        assert result["errors"] == [], result["errors"]
        return calls["n"]

    monkeypatch.setattr(db, "get_db", counting)
    few = count()
    monkeypatch.setattr(db, "get_db", original)
    for i in range(6):
        _host(admin, world["a"], f"edge-x{i}", f"192.0.2.{100 + i}")

    async def more() -> None:
        hosts = [h for h in await db.get_all_hosts() if h["hostname"].startswith("edge-x")]
        for host in hosts:
            await db.set_host_device_fields(
                int(host["id"]), {"site_id": world["site"], "device_type_id": world["model"]}
            )
            await db.create_dcim_record("module", {"host_id": int(host["id"]), "bay": "slot 1"})
            await db.add_cluster_host(world["cluster"], int(host["id"]))

    asyncio.run(more())
    monkeypatch.setattr(db, "get_db", counting)
    many = count()
    assert many == few, (few, many)


def test_cost_limit_covers_the_new_lists(admin, world):
    gql_schema = schema._schema
    doc = parse("{ sites(limit: 10) { racks(limit: 5) { hosts(limit: 2) { id } } } }")
    assert limits.estimate_cost(gql_schema, doc, None, 10**6) == (10 + 50 + 100, False)
    # Cables and circuits weigh 2 per row.
    doc = parse("{ cables(limit: 10) { id } circuits(limit: 5) { terminations { id } } }")
    assert limits.estimate_cost(gql_schema, doc, None, 10**6) == (20 + 10 + 5 * limits.UNBOUNDED_LIST_ESTIMATE, False)
    # Root lists default to 100 rows.
    doc = parse("{ virtualMachines { interfaces { id } } }")
    assert limits.estimate_cost(gql_schema, doc, None, 10**6) == (100 + 100 * limits.UNBOUNDED_LIST_ESTIMATE, False)

    costly = "{ sites(limit: 1000) { hosts(limit: 1000) { id } } }"
    assert "too complex" in _gql(admin, costly, status=400)["errors"][0]["message"]
    heavy = "{ tenants(limit: 300) { circuits(limit: 100) { id } } }"
    assert "too complex" in _gql(admin, heavy, status=400)["errors"][0]["message"]
    assert "errors" not in _gql(admin, "{ tenants(limit: 10) { circuits(limit: 10) { id } } }")
