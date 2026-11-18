"""GraphQL types of the object models beyond inventory and IPAM: locations
and tenancy, the device model, circuits, DCIM, virtualization, routing and
hardware lifecycle, with their root queries (``ModelQuery``, merged into
the schema's ``Query``).

Every type is an allow-list of columns, read through the ``routes.db``
readers of its REST routes (``GraphQLContext.table`` and the batched
loaders). Cloud resource ids and keys, billing links and change stamps are
not declared.

Each field checks the feature of the matching REST router
(``Access denied for feature 'X'``):

* regions, sites, tenant groups, tenants: ``organization``
* manufacturers, device types, device roles, lifecycle statuses: none
  beyond ``graphql`` (the catalogues are open to every signed-in user)
* circuit providers, provider networks, circuit types, circuits and their
  terminations: ``circuits``
* rack roles, racks, cables, front and rear ports, modules, power panels,
  feeds, ports and outlets: ``dcim``
* clusters, virtual machines, VM interfaces: ``virtualization``
* AS numbers, routing instances, BGP peerings: ``routing``
* hardware notices, support contracts: ``lifecycle``
* every relation to a host: ``inventory``

Object scope: see ``GraphQLContext.visible``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

import strawberry
from strawberry.types import Info

from netcontrol.graphql_api.common import DEFAULT_LIMIT, CustomData, _ctx, _text, make

if TYPE_CHECKING:
    from netcontrol.graphql_api.schema import VLAN, VRF, Host

_SCHEMA = "netcontrol.graphql_api.schema"
HostRef = Annotated["Host", strawberry.lazy(_SCHEMA)]
VLANRef = Annotated["VLAN", strawberry.lazy(_SCHEMA)]
VRFRef = Annotated["VRF", strawberry.lazy(_SCHEMA)]

ORGANIZATION = "organization"
CIRCUITS = "circuits"
DCIM = "dcim"
VIRTUALIZATION = "virtualization"
ROUTING = "routing"
LIFECYCLE = "lifecycle"
INVENTORY = "inventory"


# ── Plumbing ─────────────────────────────────────────────────────────────────


async def _row(info: Info, feature: str | None, model: str, row_id: Any) -> dict | None:
    """The readable row ``row_id`` of ``model`` (None when unknown, hidden
    or ``row_id`` is None), after checking ``feature``."""
    ctx = _ctx(info)
    if feature:
        ctx.require(feature)
    if row_id is None:
        return None
    return (await ctx.by_id(model)).get(int(row_id))


async def _rows(info: Info, feature: str | None, model: str, key: str, value: Any) -> list[dict]:
    """The readable rows of ``model`` whose ``key`` is ``value``."""
    ctx = _ctx(info)
    if feature:
        ctx.require(feature)
    return (await ctx.grouped(model, key)).get(int(value), []) if value is not None else []


async def _table(info: Info, feature: str | None, model: str) -> list[dict]:
    ctx = _ctx(info)
    if feature:
        ctx.require(feature)
    return await ctx.table(model)


def _page(info: Info, rows: list[dict], limit: int | None, offset: int, *, bounded: bool = False) -> list[dict]:
    return _ctx(info).page(rows, limit, offset, bounded=bounded)


def _named(rows: list[dict], key: str, text: str | None) -> list[dict]:
    """The rows whose ``key`` holds ``text`` ignoring case (all for none)."""
    if not text:
        return rows
    wanted = text.lower()
    return [r for r in rows if wanted in _text(r, key).lower()]


def _equal(rows: list[dict], key: str, value: Any) -> list[dict]:
    """The rows whose ``key`` is ``value`` (all when ``value`` is None)."""
    if value is None:
        return rows
    return [r for r in rows if r.get(key) is not None and str(r[key]) == str(value)]


def _hosts(rows: list[dict]) -> list[Host]:
    from netcontrol.graphql_api.schema import Host

    return [Host(row=r) for r in rows]


async def _host(info: Info, host_id: Any) -> Host | None:
    ctx = _ctx(info)
    ctx.require(INVENTORY)
    row = (await ctx.hosts_by_id()).get(int(host_id)) if host_id is not None else None
    return _hosts([row])[0] if row else None


async def _hosts_where(info: Info, key: str, value: Any, limit: int | None, offset: int) -> list[Host]:
    ctx = _ctx(info)
    ctx.require(INVENTORY)
    rows = (await ctx.hosts_where(key)).get(int(value), []) if value is not None else []
    return _hosts(ctx.page(rows, limit, offset, bounded=False))


async def _host_records(info: Info, kind: str, host_id: Any) -> list[dict]:
    ctx = _ctx(info)
    ctx.require(DCIM)
    return await ctx.host_records[kind].load(int(host_id))


def _distinct(rows: list[dict]) -> list[dict]:
    seen: set[int] = set()
    out = []
    for row in rows:
        if int(row["id"]) not in seen:
            seen.add(int(row["id"]))
            out.append(row)
    return out


# ── Locations and tenancy ────────────────────────────────────────────────────


@strawberry.type(description="A region of the location tree (Settings > Organization).")
class Region(CustomData):
    row: strawberry.Private[dict]
    custom_type = "region"
    id: int
    name: str
    description: str
    path: str = strawberry.field(description="Full path from the top region, e.g. emea / west.")
    depth: int

    @strawberry.field
    async def parent(self, info: Info) -> Region | None:
        row = await _row(info, ORGANIZATION, "region", self.row.get("parent_id"))
        return make(Region, row) if row else None

    @strawberry.field
    async def children(self, info: Info) -> list[Region]:
        return [make(Region, r) for r in await _rows(info, ORGANIZATION, "region", "parent_id", self.row["id"])]

    @strawberry.field(description="The sites directly in this region.")
    async def sites(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Site]:
        rows = await _rows(info, ORGANIZATION, "site", "region_id", self.row["id"])
        return [make(Site, r) for r in _page(info, rows, limit, offset)]


@strawberry.type(description="A tenant group (a tree).")
class TenantGroup:
    row: strawberry.Private[dict]
    id: int
    name: str
    description: str
    path: str
    depth: int

    @strawberry.field
    async def parent(self, info: Info) -> TenantGroup | None:
        row = await _row(info, ORGANIZATION, "tenant_group", self.row.get("parent_id"))
        return make(TenantGroup, row) if row else None

    @strawberry.field
    async def children(self, info: Info) -> list[TenantGroup]:
        rows = await _rows(info, ORGANIZATION, "tenant_group", "parent_id", self.row["id"])
        return [make(TenantGroup, r) for r in rows]

    @strawberry.field(description="The tenants directly in this group.")
    async def tenants(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Tenant]:
        rows = await _rows(info, ORGANIZATION, "tenant", "group_id", self.row["id"])
        return [make(Tenant, r) for r in _page(info, rows, limit, offset)]


@strawberry.type(description="A tenant: the owner of hosts, sites, circuits, racks, clusters and more.")
class Tenant(CustomData):
    row: strawberry.Private[dict]
    custom_type = "tenant"
    id: int
    name: str
    description: str
    comments: str

    @strawberry.field
    async def group(self, info: Info) -> TenantGroup | None:
        row = await _row(info, ORGANIZATION, "tenant_group", self.row.get("group_id"))
        return make(TenantGroup, row) if row else None

    @strawberry.field
    async def sites(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Site]:
        rows = await _rows(info, ORGANIZATION, "site", "tenant_id", self.row["id"])
        return [make(Site, r) for r in _page(info, rows, limit, offset)]

    @strawberry.field
    async def hosts(self, info: Info, limit: int | None = None, offset: int = 0) -> list[HostRef]:
        return await _hosts_where(info, "tenant_id", self.row["id"], limit, offset)

    @strawberry.field
    async def circuits(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Circuit]:
        rows = await _rows(info, CIRCUITS, "circuit", "tenant_id", self.row["id"])
        return [make(Circuit, r) for r in _page(info, rows, limit, offset)]

    @strawberry.field
    async def racks(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Rack]:
        rows = await _rows(info, DCIM, "rack", "tenant_id", self.row["id"])
        return [make(Rack, r) for r in _page(info, rows, limit, offset)]

    @strawberry.field
    async def clusters(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Cluster]:
        rows = await _rows(info, VIRTUALIZATION, "cluster", "tenant_id", self.row["id"])
        return [make(Cluster, r) for r in _page(info, rows, limit, offset)]

    @strawberry.field
    async def virtual_machines(self, info: Info, limit: int | None = None, offset: int = 0) -> list[VirtualMachine]:
        rows = await _rows(info, VIRTUALIZATION, "virtual_machine", "tenant_id", self.row["id"])
        return [make(VirtualMachine, r) for r in _page(info, rows, limit, offset)]


@strawberry.type(description="A site (a location with an address, in a region).")
class Site(CustomData):
    row: strawberry.Private[dict]
    custom_type = "site"
    id: int
    name: str
    description: str
    address: str
    lat: float | None
    lng: float | None
    status: str
    facility: str
    time_zone: str

    @strawberry.field
    async def region(self, info: Info) -> Region | None:
        row = await _row(info, ORGANIZATION, "region", self.row.get("region_id"))
        return make(Region, row) if row else None

    @strawberry.field
    async def tenant(self, info: Info) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return make(Tenant, row) if row else None

    @strawberry.field(description="The hosts whose site this is.")
    async def hosts(
        self, info: Info, name: str | None = None, limit: int | None = None, offset: int = 0
    ) -> list[HostRef]:
        ctx = _ctx(info)
        ctx.require(INVENTORY)
        rows = _named((await ctx.hosts_where("site_id")).get(int(self.row["id"]), []), "hostname", name)
        return _hosts(ctx.page(rows, limit, offset, bounded=False))

    @strawberry.field
    async def racks(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Rack]:
        rows = await _rows(info, DCIM, "rack", "site_id", self.row["id"])
        return [make(Rack, r) for r in _page(info, rows, limit, offset)]

    @strawberry.field
    async def power_panels(self, info: Info, limit: int | None = None, offset: int = 0) -> list[PowerPanel]:
        rows = await _rows(info, DCIM, "power_panel", "site_id", self.row["id"])
        return [make(PowerPanel, r) for r in _page(info, rows, limit, offset)]

    @strawberry.field(description="The circuits with a termination at this site.")
    async def circuits(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Circuit]:
        ctx = _ctx(info)
        ctx.require(CIRCUITS)
        circuits = await ctx.by_id("circuit")
        terms = (await ctx.circuit_terminations("site_id")).get(int(self.row["id"]), [])
        rows = _distinct([circuits[int(t["circuit_id"])] for t in terms if int(t["circuit_id"]) in circuits])
        return [make(Circuit, r) for r in ctx.page(rows, limit, offset, bounded=False)]

    @strawberry.field
    async def clusters(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Cluster]:
        rows = await _rows(info, VIRTUALIZATION, "cluster", "site_id", self.row["id"])
        return [make(Cluster, r) for r in _page(info, rows, limit, offset)]

    @strawberry.field(description="The VLAN records of this site.")
    async def vlans(self, info: Info, limit: int | None = None, offset: int = 0) -> list[VLANRef]:
        from netcontrol.graphql_api.schema import VLAN

        ctx = _ctx(info)
        ctx.require("ipam")
        rows = [v for v in await ctx.vlans() if v.get("site_id") == int(self.row["id"])]
        return [VLAN(row=r) for r in ctx.page(rows, limit, offset, bounded=False)]


# ── Device model ─────────────────────────────────────────────────────────────


@strawberry.type(description="A hardware manufacturer.")
class Manufacturer(CustomData):
    row: strawberry.Private[dict]
    custom_type = "manufacturer"
    id: int
    name: str
    description: str

    @strawberry.field
    async def device_types(self, info: Info, limit: int | None = None, offset: int = 0) -> list[DeviceType]:
        rows = await _rows(info, None, "device_type", "manufacturer_id", self.row["id"])
        return [make(DeviceType, r) for r in _page(info, rows, limit, offset)]


@strawberry.type(description="A device type (hardware model) of a manufacturer.")
class DeviceType(CustomData):
    row: strawberry.Private[dict]
    custom_type = "device_type"
    id: int
    model: str
    part_number: str
    u_height: int
    description: str

    @strawberry.field
    async def manufacturer(self, info: Info) -> Manufacturer | None:
        row = await _row(info, None, "manufacturer", self.row.get("manufacturer_id"))
        return make(Manufacturer, row) if row else None

    @strawberry.field(description="The hosts of this device type.")
    async def hosts(self, info: Info, limit: int | None = None, offset: int = 0) -> list[HostRef]:
        return await _hosts_where(info, "device_type_id", self.row["id"], limit, offset)

    @strawberry.field(description="The components a host of this type is created with.")
    async def component_templates(self, info: Info) -> list[ComponentTemplate]:
        rows = await _rows(info, None, "component_template", "device_type_id", self.row["id"])
        return [make(ComponentTemplate, r) for r in rows]

    @strawberry.field(description="The end-of-life notice of this device type.")
    async def hardware_notices(self, info: Info) -> list[HardwareNotice]:
        return [
            make(HardwareNotice, r)
            for r in await _rows(info, LIFECYCLE, "hardware_notice", "device_type_id", self.row["id"])
        ]


@strawberry.type(description="A device role (router, access switch ...).")
class DeviceRole(CustomData):
    row: strawberry.Private[dict]
    custom_type = "device_role"
    id: int
    name: str
    color: str
    description: str

    @strawberry.field
    async def hosts(self, info: Info, limit: int | None = None, offset: int = 0) -> list[HostRef]:
        return await _hosts_where(info, "role_id", self.row["id"], limit, offset)

    @strawberry.field
    async def virtual_machines(self, info: Info, limit: int | None = None, offset: int = 0) -> list[VirtualMachine]:
        rows = await _rows(info, VIRTUALIZATION, "virtual_machine", "role_id", self.row["id"])
        return [make(VirtualMachine, r) for r in _page(info, rows, limit, offset)]


@strawberry.type(description="A lifecycle status of hosts (active, planned, decommissioning ...).")
class LifecycleStatus:
    row: strawberry.Private[dict]
    id: int
    name: str
    color: str
    description: str
    is_default: bool

    @strawberry.field
    async def hosts(self, info: Info, limit: int | None = None, offset: int = 0) -> list[HostRef]:
        return await _hosts_where(info, "lifecycle_status_id", self.row["id"], limit, offset)


# ── Circuits ─────────────────────────────────────────────────────────────────


@strawberry.type(description="A circuit provider (carrier).")
class CircuitProvider(CustomData):
    row: strawberry.Private[dict]
    custom_type = "circuit_provider"
    id: int
    name: str
    account: str
    portal_url: str
    noc_contact: str
    admin_contact: str
    comments: str

    @strawberry.field
    async def circuits(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Circuit]:
        rows = await _rows(info, CIRCUITS, "circuit", "provider_id", self.row["id"])
        return [make(Circuit, r) for r in _page(info, rows, limit, offset)]

    @strawberry.field
    async def networks(self, info: Info) -> list[ProviderNetwork]:
        return [
            make(ProviderNetwork, r)
            for r in await _rows(info, CIRCUITS, "provider_network", "provider_id", self.row["id"])
        ]


@strawberry.type(description="A provider network (a cloud or MPLS network a circuit lands in).")
class ProviderNetwork:
    row: strawberry.Private[dict]
    id: int
    name: str
    description: str

    @strawberry.field
    async def provider(self, info: Info) -> CircuitProvider | None:
        row = await _row(info, CIRCUITS, "circuit_provider", self.row.get("provider_id"))
        return make(CircuitProvider, row) if row else None


@strawberry.type(description="A circuit type (internet, MPLS, dark fibre ...).")
class CircuitType:
    row: strawberry.Private[dict]
    id: int
    name: str
    description: str

    @strawberry.field
    async def circuits(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Circuit]:
        rows = await _rows(info, CIRCUITS, "circuit", "circuit_type_id", self.row["id"])
        return [make(Circuit, r) for r in _page(info, rows, limit, offset)]


@strawberry.type(description="One end (A or Z) of a circuit.")
class CircuitTermination:
    row: strawberry.Private[dict]
    id: int
    term_side: str = strawberry.field(description="A or Z.")
    interface_name: str
    port_speed_kbps: int | None
    upstream_speed_kbps: int | None
    xconnect_id: str
    pp_info: str = strawberry.field(description="Patch panel and port.")
    description: str

    @strawberry.field
    async def circuit(self, info: Info) -> Circuit | None:
        row = await _row(info, CIRCUITS, "circuit", self.row.get("circuit_id"))
        return make(Circuit, row) if row else None

    @strawberry.field
    async def site(self, info: Info) -> Site | None:
        row = await _row(info, ORGANIZATION, "site", self.row.get("site_id"))
        return make(Site, row) if row else None

    @strawberry.field
    async def host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("host_id"))

    @strawberry.field
    async def provider_network(self, info: Info) -> ProviderNetwork | None:
        row = await _row(info, CIRCUITS, "provider_network", self.row.get("provider_network_id"))
        return make(ProviderNetwork, row) if row else None


@strawberry.type(description="A circuit of a provider.")
class Circuit(CustomData):
    row: strawberry.Private[dict]
    custom_type = "circuit"
    id: int
    cid: str = strawberry.field(description="The provider's circuit id.")
    status: str
    install_date: str
    termination_date: str
    commit_rate_kbps: int | None
    description: str
    comments: str

    @strawberry.field
    async def provider(self, info: Info) -> CircuitProvider | None:
        row = await _row(info, CIRCUITS, "circuit_provider", self.row.get("provider_id"))
        return make(CircuitProvider, row) if row else None

    @strawberry.field
    async def circuit_type(self, info: Info) -> CircuitType | None:
        row = await _row(info, CIRCUITS, "circuit_type", self.row.get("circuit_type_id"))
        return make(CircuitType, row) if row else None

    @strawberry.field
    async def tenant(self, info: Info) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return make(Tenant, row) if row else None

    @strawberry.field(description="The A then Z termination (those you may read).")
    async def terminations(self, info: Info) -> list[CircuitTermination]:
        ctx = _ctx(info)
        ctx.require(CIRCUITS)
        readable = {int(t["id"]) for t in await ctx.terminations()}
        return [make(CircuitTermination, t) for t in self.row.get("terminations") or [] if int(t["id"]) in readable]


# ── DCIM ─────────────────────────────────────────────────────────────────────


@strawberry.type(description="One end of a cable.")
class CableEndpoint:
    row: strawberry.Private[dict]
    type: str = strawberry.field(
        description="interface, front_port, rear_port, power_port, power_outlet, power_feed or circuit_termination."
    )
    record_id: int | None = strawberry.field(
        description="The id of the port, outlet, feed or termination (null for an interface)."
    )
    name: str
    label: str

    @strawberry.field
    async def host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("host_id"))


@strawberry.type(description="A cable between two endpoints.")
class Cable(CustomData):
    row: strawberry.Private[dict]
    custom_type = "cable"
    id: int
    status: str
    type: str
    label: str
    color: str
    length: float | None
    length_unit: str
    description: str

    @strawberry.field
    def a(self) -> CableEndpoint:
        end = self.row.get("a") or {}
        return make(CableEndpoint, end, record_id=end.get("id"))

    @strawberry.field
    def b(self) -> CableEndpoint:
        end = self.row.get("b") or {}
        return make(CableEndpoint, end, record_id=end.get("id"))

    @strawberry.field
    async def tenant(self, info: Info) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return make(Tenant, row) if row else None


async def _host_cable(info: Info, host_id: Any, cable_id: Any) -> Cable | None:
    """The cable ``cable_id`` of a host's port (batched per host)."""
    if cable_id is None:
        return None
    ctx = _ctx(info)
    ctx.require(DCIM)
    for row in await ctx.host_cables.load(int(host_id)):
        if int(row["id"]) == int(cable_id):
            return make(Cable, row)
    return None


@strawberry.type(description="A rack role.")
class RackRole:
    row: strawberry.Private[dict]
    id: int
    name: str
    color: str
    description: str

    @strawberry.field
    async def racks(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Rack]:
        rows = await _rows(info, DCIM, "rack", "role_id", self.row["id"])
        return [make(Rack, r) for r in _page(info, rows, limit, offset)]


@strawberry.type(description="A rack of a site.")
class Rack(CustomData):
    row: strawberry.Private[dict]
    custom_type = "rack"
    id: int
    name: str
    facility_id: str
    status: str
    u_height: int
    desc_units: bool = strawberry.field(description="Units are numbered top to bottom.")
    width: int
    serial: str
    asset_tag: str
    floor_name: str | None
    description: str
    comments: str

    @strawberry.field
    async def site(self, info: Info) -> Site | None:
        row = await _row(info, ORGANIZATION, "site", self.row.get("site_id"))
        return make(Site, row) if row else None

    @strawberry.field
    async def role(self, info: Info) -> RackRole | None:
        row = await _row(info, DCIM, "rack_role", self.row.get("role_id"))
        return make(RackRole, row) if row else None

    @strawberry.field
    async def tenant(self, info: Info) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return make(Tenant, row) if row else None

    @strawberry.field(description="The hosts in this rack.")
    async def hosts(self, info: Info, limit: int | None = None, offset: int = 0) -> list[HostRef]:
        return await _hosts_where(info, "rack_id", self.row["id"], limit, offset)

    @strawberry.field
    async def power_feeds(self, info: Info) -> list[PowerFeed]:
        return [make(PowerFeed, r) for r in await _rows(info, DCIM, "power_feed", "rack_id", self.row["id"])]


@strawberry.type(description="A power panel of a site.")
class PowerPanel:
    row: strawberry.Private[dict]
    id: int
    name: str
    floor_name: str | None
    description: str

    @strawberry.field
    async def site(self, info: Info) -> Site | None:
        row = await _row(info, ORGANIZATION, "site", self.row.get("site_id"))
        return make(Site, row) if row else None

    @strawberry.field
    async def power_feeds(self, info: Info) -> list[PowerFeed]:
        return [make(PowerFeed, r) for r in await _rows(info, DCIM, "power_feed", "power_panel_id", self.row["id"])]


@strawberry.type(description="A power feed (a circuit of a panel) to a rack.")
class PowerFeed:
    row: strawberry.Private[dict]
    id: int
    name: str
    status: str
    type: str
    supply: str
    phase: str
    voltage: int
    amperage: int
    max_utilization: int
    description: str

    @strawberry.field
    async def power_panel(self, info: Info) -> PowerPanel | None:
        row = await _row(info, DCIM, "power_panel", self.row.get("power_panel_id"))
        return make(PowerPanel, row) if row else None

    @strawberry.field
    async def rack(self, info: Info) -> Rack | None:
        row = await _row(info, DCIM, "rack", self.row.get("rack_id"))
        return make(Rack, row) if row else None

    @strawberry.field
    async def cable(self, info: Info) -> Cable | None:
        ctx = _ctx(info)
        ctx.require(DCIM)
        row = (await ctx.power_feed_cables()).get(int(self.row["id"]))
        return make(Cable, row) if row else None


@strawberry.type(description="A rear port of a patch panel (a host).")
class RearPort:
    row: strawberry.Private[dict]
    id: int
    name: str
    type: str
    positions: int
    description: str

    @strawberry.field
    async def host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("host_id"))

    @strawberry.field
    async def front_ports(self, info: Info) -> list[FrontPort]:
        rows = await _host_records(info, "front_port", self.row["host_id"])
        return [make(FrontPort, r) for r in rows if r.get("rear_port_id") == self.row["id"]]

    @strawberry.field
    async def cable(self, info: Info) -> Cable | None:
        return await _host_cable(info, self.row["host_id"], self.row.get("cable_id"))


@strawberry.type(description="A front port of a patch panel, mapped to a rear port position.")
class FrontPort:
    row: strawberry.Private[dict]
    id: int
    name: str
    type: str
    rear_port_position: int
    description: str

    @strawberry.field
    async def host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("host_id"))

    @strawberry.field
    async def rear_port(self, info: Info) -> RearPort | None:
        rows = await _host_records(info, "rear_port", self.row["host_id"])
        return next((make(RearPort, r) for r in rows if r["id"] == self.row.get("rear_port_id")), None)

    @strawberry.field
    async def cable(self, info: Info) -> Cable | None:
        return await _host_cable(info, self.row["host_id"], self.row.get("cable_id"))


@strawberry.type(description="A module installed in a bay of a host.")
class Module:
    row: strawberry.Private[dict]
    id: int
    bay: str
    module_type: str
    part_number: str
    serial: str
    asset_tag: str
    status: str
    description: str

    @strawberry.field
    async def host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("host_id"))


@strawberry.type(description="A power inlet of a host.")
class PowerPort:
    row: strawberry.Private[dict]
    id: int
    name: str
    maximum_draw: int | None = strawberry.field(description="Watts.")
    allocated_draw: int | None = strawberry.field(description="Watts.")
    description: str

    @strawberry.field
    async def host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("host_id"))

    @strawberry.field(description="The outlets of the host this port feeds.")
    async def outlets(self, info: Info) -> list[PowerOutlet]:
        rows = await _host_records(info, "power_outlet", self.row["host_id"])
        return [make(PowerOutlet, r) for r in rows if r.get("power_port_id") == self.row["id"]]

    @strawberry.field
    async def cable(self, info: Info) -> Cable | None:
        return await _host_cable(info, self.row["host_id"], self.row.get("cable_id"))


@strawberry.type(description="A power outlet of a host (a PDU).")
class PowerOutlet:
    row: strawberry.Private[dict]
    id: int
    name: str
    feed_leg: str
    description: str

    @strawberry.field
    async def host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("host_id"))

    @strawberry.field
    async def power_port(self, info: Info) -> PowerPort | None:
        if self.row.get("power_port_id") is None:
            return None
        rows = await _host_records(info, "power_port", self.row["host_id"])
        return next((make(PowerPort, r) for r in rows if r["id"] == self.row["power_port_id"]), None)

    @strawberry.field
    async def cable(self, info: Info) -> Cable | None:
        return await _host_cable(info, self.row["host_id"], self.row.get("cable_id"))


# ── Virtualization ───────────────────────────────────────────────────────────


@strawberry.type(description="A virtualization cluster (hypervisor hosts and their VMs).")
class Cluster(CustomData):
    row: strawberry.Private[dict]
    custom_type = "cluster"
    id: int
    name: str
    cluster_type_name: str
    cluster_group_name: str | None
    origin: str
    description: str
    comments: str

    @strawberry.field
    async def site(self, info: Info) -> Site | None:
        row = await _row(info, ORGANIZATION, "site", self.row.get("site_id"))
        return make(Site, row) if row else None

    @strawberry.field
    async def tenant(self, info: Info) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return make(Tenant, row) if row else None

    @strawberry.field(description="The member (hypervisor) hosts.")
    async def hosts(self, info: Info, limit: int | None = None, offset: int = 0) -> list[HostRef]:
        ctx = _ctx(info)
        ctx.require(VIRTUALIZATION)
        ctx.require(INVENTORY)
        links = (await ctx.grouped("cluster_host", "cluster_id")).get(int(self.row["id"]), [])
        hosts = await ctx.hosts_by_id()
        rows = [hosts[int(link["host_id"])] for link in links if int(link["host_id"]) in hosts]
        rows.sort(key=lambda h: (_text(h, "hostname").lower(), int(h["id"])))
        return _hosts(ctx.page(rows, limit, offset, bounded=False))

    @strawberry.field
    async def virtual_machines(
        self, info: Info, name: str | None = None, limit: int | None = None, offset: int = 0
    ) -> list[VirtualMachine]:
        rows = _named(await _rows(info, VIRTUALIZATION, "virtual_machine", "cluster_id", self.row["id"]), "name", name)
        return [make(VirtualMachine, r) for r in _page(info, rows, limit, offset)]


@strawberry.type(description="An interface of a virtual machine.")
class VMInterface:
    row: strawberry.Private[dict]
    id: int
    name: str
    enabled: bool
    mac_address: str
    mtu: int | None
    mode: str
    description: str
    addresses: list[str] = strawberry.field(description="The addresses (CIDR text).")
    vrf_name: str | None

    @strawberry.field
    async def untagged_vlan(self, info: Info) -> VLANRef | None:
        from netcontrol.graphql_api.schema import _vlan_by_id

        return await _vlan_by_id(info, self.row.get("untagged_vlan_id"))

    @strawberry.field
    async def vrf(self, info: Info) -> VRFRef | None:
        from netcontrol.graphql_api.schema import _vrf_named

        return await _vrf_named(info, _text(self.row, "vrf_name"))


@strawberry.type(description="A virtual machine of a cluster.")
class VirtualMachine(CustomData):
    row: strawberry.Private[dict]
    custom_type = "virtual_machine"
    id: int
    name: str
    status: str
    platform: str
    vcpus: int | None
    memory_mb: int | None
    disk_gb: int | None
    primary_ip4: str | None
    primary_ip6: str | None
    origin: str = strawberry.field(description="manual, or the cloud sync that created it.")
    description: str
    comments: str

    @strawberry.field
    async def cluster(self, info: Info) -> Cluster | None:
        row = await _row(info, VIRTUALIZATION, "cluster", self.row.get("cluster_id"))
        return make(Cluster, row) if row else None

    @strawberry.field
    async def role(self, info: Info) -> DeviceRole | None:
        row = await _row(info, None, "device_role", self.row.get("role_id"))
        return make(DeviceRole, row) if row else None

    @strawberry.field
    async def tenant(self, info: Info) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return make(Tenant, row) if row else None

    @strawberry.field
    async def interfaces(self, info: Info) -> list[VMInterface]:
        ctx = _ctx(info)
        ctx.require(VIRTUALIZATION)
        return [make(VMInterface, r) for r in await ctx.vm_interfaces.load(int(self.row["id"]))]


# ── Routing ──────────────────────────────────────────────────────────────────


@strawberry.type(description="An autonomous system number record.")
class AutonomousSystem(CustomData):
    row: strawberry.Private[dict]
    custom_type = "autonomous_system"
    id: int
    asn: int
    description: str
    rir: str
    comments: str

    @strawberry.field
    async def tenant(self, info: Info) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return make(Tenant, row) if row else None

    @strawberry.field(description="The routing instances whose local AS this is.")
    async def routing_instances(self, info: Info) -> list[RoutingInstance]:
        rows = await _rows(info, ROUTING, "routing_instance", "autonomous_system_id", self.row["id"])
        return [make(RoutingInstance, r) for r in rows]

    @strawberry.field(description="The BGP peerings whose remote AS this is.")
    async def peerings(self, info: Info, limit: int | None = None, offset: int = 0) -> list[BgpPeering]:
        rows = await _rows(info, ROUTING, "bgp_peering", "remote_asn_id", self.row["id"])
        return [make(BgpPeering, r) for r in _page(info, rows, limit, offset)]


@strawberry.type(description="A routing instance (a BGP process) of a device.")
class RoutingInstance:
    row: strawberry.Private[dict]
    id: int
    name: str
    asn: int = strawberry.field(description="The local AS number.")
    router_id: str
    vrf_name: str
    status: str
    description: str

    @strawberry.field
    async def host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("host_id"))

    @strawberry.field
    async def autonomous_system(self, info: Info) -> AutonomousSystem | None:
        row = await _row(info, ROUTING, "autonomous_system", self.row.get("autonomous_system_id"))
        return make(AutonomousSystem, row) if row else None

    @strawberry.field
    async def peerings(self, info: Info) -> list[BgpPeering]:
        rows = await _rows(info, ROUTING, "bgp_peering", "routing_instance_id", self.row["id"])
        return [make(BgpPeering, r) for r in rows]


@strawberry.type(description="An intended BGP peering of a routing instance.")
class BgpPeering(CustomData):
    row: strawberry.Private[dict]
    custom_type = "bgp_peering"
    id: int
    local_address: str
    remote_address: str
    local_asn: int
    remote_asn: int
    peer_group_name: str
    status: str
    address_families: list[str]
    import_policy: str
    export_policy: str
    description: str

    @strawberry.field
    async def routing_instance(self, info: Info) -> RoutingInstance | None:
        row = await _row(info, ROUTING, "routing_instance", self.row.get("routing_instance_id"))
        return make(RoutingInstance, row) if row else None

    @strawberry.field
    async def remote_autonomous_system(self, info: Info) -> AutonomousSystem | None:
        row = await _row(info, ROUTING, "autonomous_system", self.row.get("remote_asn_id"))
        return make(AutonomousSystem, row) if row else None

    @strawberry.field
    async def host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("host_id"))

    @strawberry.field(description="The inventory host of the remote end, when known.")
    async def remote_host(self, info: Info) -> HostRef | None:
        return await _host(info, self.row.get("remote_host_id"))


# ── Hardware lifecycle ───────────────────────────────────────────────────────


@strawberry.type(description="An end-of-life notice of a device type or a part number.")
class HardwareNotice:
    row: strawberry.Private[dict]
    id: int
    part_number: str
    end_of_sale: str
    end_of_sw_maintenance: str
    end_of_security_fixes: str
    end_of_support: str
    documentation_url: str
    comments: str

    @strawberry.field
    async def device_type(self, info: Info) -> DeviceType | None:
        row = await _row(info, None, "device_type", self.row.get("device_type_id"))
        return make(DeviceType, row) if row else None

    @strawberry.field(description="The hosts it applies to (by device type, part number or module).")
    async def hosts(self, info: Info, limit: int | None = None, offset: int = 0) -> list[HostRef]:
        ctx = _ctx(info)
        ctx.require(INVENTORY)
        matches = await _rows(info, LIFECYCLE, "hardware_notice_match", "notice_id", self.row["id"])
        hosts = await ctx.hosts_by_id()
        rows = _distinct([hosts[int(m["host_id"])] for m in matches if int(m["host_id"]) in hosts])
        rows.sort(key=lambda h: (_text(h, "hostname").lower(), int(h["id"])))
        return _hosts(ctx.page(rows, limit, offset, bounded=False))


@strawberry.type(description="A support contract covering hosts.")
class SupportContract:
    row: strawberry.Private[dict]
    id: int
    provider: str
    contract_id: str = strawberry.field(description="The provider's contract number.")
    start_date: str
    end_date: str
    cost: str | None = strawberry.field(description="Decimal text.")
    currency: str
    support_level: str
    description: str
    comments: str

    @strawberry.field(description="The hosts it covers.")
    async def hosts(self, info: Info, limit: int | None = None, offset: int = 0) -> list[HostRef]:
        ctx = _ctx(info)
        ctx.require(INVENTORY)
        hosts = await ctx.hosts_by_id()
        rows = [hosts[int(h["id"])] for h in self.row.get("hosts") or [] if int(h["id"]) in hosts]
        return _hosts(ctx.page(rows, limit, offset, bounded=False))


# ── IPAM model (migration 0110) ──────────────────────────────────────────────

IPAM = "ipam"


@strawberry.type(description="A component a host of a device type is created with.")
class ComponentTemplate:
    row: strawberry.Private[dict]
    id: int
    component_type: str = strawberry.field(
        description="console_port, power_port, rear_port, front_port or module (bay)."
    )
    name: str
    type: str
    positions: int
    rear_port_template_name: str | None
    rear_port_position: int
    maximum_draw: int | None
    allocated_draw: int | None
    description: str


@strawberry.type(description="An IPAM namespace: VRFs and prefixes that may repeat across namespaces.")
class Namespace:
    row: strawberry.Private[dict]
    id: int
    name: str
    description: str
    vrf_count: int
    prefix_count: int


@strawberry.type(description="A route target (RFC 4364 extended community).")
class RouteTarget:
    row: strawberry.Private[dict]
    id: int
    name: str
    description: str
    import_vrf_count: int
    export_vrf_count: int

    @strawberry.field
    async def tenant(self, info: Info) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return make(Tenant, row) if row else None


@strawberry.type(description="The route targets a VRF imports and exports.")
class VrfRouteTargets:
    import_targets: list[RouteTarget] = strawberry.field(name="import")
    export_targets: list[RouteTarget] = strawberry.field(name="export")


@strawberry.type(description="A VLAN group: a VLAN id range of a site, a region or no scope.")
class VlanGroup:
    row: strawberry.Private[dict]
    id: int
    name: str
    min_vid: int
    max_vid: int
    vlan_count: int
    description: str

    @strawberry.field
    async def site(self, info: Info) -> Site | None:
        row = await _row(info, ORGANIZATION, "site", self.row.get("site_id"))
        return make(Site, row) if row else None

    @strawberry.field
    async def region(self, info: Info) -> Region | None:
        row = await _row(info, ORGANIZATION, "region", self.row.get("region_id"))
        return make(Region, row) if row else None

    @strawberry.field
    async def vlans(self, info: Info, limit: int | None = None, offset: int = 0) -> list[VLANRef]:
        from netcontrol.graphql_api.schema import VLAN

        ctx = _ctx(info)
        ctx.require(IPAM)
        rows = [v for v in await ctx.vlans() if v.get("vlan_group_id") == int(self.row["id"])]
        return [VLAN(row=r) for r in ctx.page(rows, limit, offset, bounded=False)]


@strawberry.type(name="RIR", description="A regional internet registry (or a private range authority).")
class Rir:
    row: strawberry.Private[dict]
    id: int
    name: str
    is_private: bool
    description: str
    aggregate_count: int

    @strawberry.field
    async def aggregates(self, info: Info) -> list[Aggregate]:
        return [make(Aggregate, r) for r in await _rows(info, IPAM, "aggregate", "rir_id", self.row["id"])]


@strawberry.type(description="An aggregate: a top-level block from a RIR, with how much the IPAM prefixes use.")
class Aggregate:
    row: strawberry.Private[dict]
    id: int
    prefix: str
    date_added: str
    description: str
    prefix_count: int
    total_addresses: str = strawberry.field(description="Decimal text (IPv6 counts exceed Int).")
    used_addresses: str = strawberry.field(description="Decimal text.")
    utilization_pct: float

    @strawberry.field
    async def rir(self, info: Info) -> Rir | None:
        row = await _row(info, IPAM, "rir", self.row.get("rir_id"))
        return make(Rir, row) if row else None

    @strawberry.field
    async def tenant(self, info: Info) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return make(Tenant, row) if row else None


async def namespace_of(info: Info, namespace_id: Any) -> Namespace | None:
    row = await _row(info, IPAM, "namespace", namespace_id)
    return make(Namespace, row) if row else None


async def aggregate_of(info: Info, subnet: str) -> Aggregate | None:
    """The most specific readable aggregate holding ``subnet``
    (``containing_aggregate``, over the request's aggregates)."""
    from netcontrol.ipam_model import containing_aggregate

    found = containing_aggregate(subnet, await _table(info, IPAM, "aggregate"))
    return make(Aggregate, found) if found else None


async def vrf_route_targets(info: Info, vrf_id: int) -> VrfRouteTargets:
    ctx = _ctx(info)
    ctx.require(IPAM)
    found = (await ctx.vrf_route_targets()).get(vrf_id, {})
    return VrfRouteTargets(
        import_targets=[make(RouteTarget, r) for r in found.get("import", [])],
        export_targets=[make(RouteTarget, r) for r in found.get("export", [])],
    )


# ── Host relations (resolved by ``schema.Host``) ─────────────────────────────


async def host_contracts(info: Info, host_id: int) -> list[SupportContract]:
    ctx = _ctx(info)
    ctx.require(LIFECYCLE)
    rows = [
        c for c in await ctx.table("support_contract") if any(int(h["id"]) == host_id for h in c.get("hosts") or [])
    ]
    return [make(SupportContract, r) for r in rows]


async def host_notices(info: Info, host_id: int) -> list[HardwareNotice]:
    ctx = _ctx(info)
    ctx.require(LIFECYCLE)
    notices = await ctx.by_id("hardware_notice")
    matches = (await ctx.grouped("hardware_notice_match", "host_id")).get(host_id, [])
    rows = _distinct([notices[int(m["notice_id"])] for m in matches if int(m["notice_id"]) in notices])
    return [make(HardwareNotice, r) for r in rows]


async def host_clusters(info: Info, host_id: int) -> list[Cluster]:
    ctx = _ctx(info)
    ctx.require(VIRTUALIZATION)
    clusters = await ctx.by_id("cluster")
    links = (await ctx.grouped("cluster_host", "host_id")).get(host_id, [])
    return [make(Cluster, clusters[int(link["cluster_id"])]) for link in links if int(link["cluster_id"]) in clusters]


async def host_terminations(info: Info, host_id: int) -> list[CircuitTermination]:
    ctx = _ctx(info)
    ctx.require(CIRCUITS)
    return [make(CircuitTermination, t) for t in (await ctx.circuit_terminations("host_id")).get(host_id, [])]


async def host_cables(info: Info, host_id: int) -> list[Cable]:
    ctx = _ctx(info)
    ctx.require(DCIM)
    return [make(Cable, r) for r in await ctx.host_cables.load(host_id)]


# ── Root queries ─────────────────────────────────────────────────────────────


@strawberry.type
class ModelQuery:
    # Locations and tenancy

    @strawberry.field(description="Regions in tree order (parents first), by name.")
    async def regions(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[Region] | None:
        rows = _named(await _table(info, ORGANIZATION, "region"), "name", name)
        return [make(Region, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One region by id.")
    async def region(self, info: Info, id: int) -> Region | None:
        row = await _row(info, ORGANIZATION, "region", id)
        return make(Region, row) if row else None

    @strawberry.field(description="Sites, by name. Filters combine (AND).")
    async def sites(
        self,
        info: Info,
        name: str | None = None,
        region_id: int | None = None,
        tenant_id: int | None = None,
        status: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Site] | None:
        rows = _named(await _table(info, ORGANIZATION, "site"), "name", name)
        rows = _equal(_equal(_equal(rows, "region_id", region_id), "tenant_id", tenant_id), "status", status)
        return [make(Site, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One site by id.")
    async def site(self, info: Info, id: int) -> Site | None:
        row = await _row(info, ORGANIZATION, "site", id)
        return make(Site, row) if row else None

    @strawberry.field(description="Tenant groups in tree order, by name.")
    async def tenant_groups(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[TenantGroup] | None:
        rows = _named(await _table(info, ORGANIZATION, "tenant_group"), "name", name)
        return [make(TenantGroup, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Tenants, by name.")
    async def tenants(
        self,
        info: Info,
        name: str | None = None,
        group_id: int | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Tenant] | None:
        rows = _equal(_named(await _table(info, ORGANIZATION, "tenant"), "name", name), "group_id", group_id)
        return [make(Tenant, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One tenant by id.")
    async def tenant(self, info: Info, id: int) -> Tenant | None:
        row = await _row(info, ORGANIZATION, "tenant", id)
        return make(Tenant, row) if row else None

    # Device model

    @strawberry.field(description="Manufacturers, by name.")
    async def manufacturers(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[Manufacturer] | None:
        rows = _named(await _table(info, None, "manufacturer"), "name", name)
        return [make(Manufacturer, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One manufacturer by id.")
    async def manufacturer(self, info: Info, id: int) -> Manufacturer | None:
        row = await _row(info, None, "manufacturer", id)
        return make(Manufacturer, row) if row else None

    @strawberry.field(description="Device types, by manufacturer then model.")
    async def device_types(
        self,
        info: Info,
        model: str | None = None,
        manufacturer_id: int | None = None,
        part_number: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[DeviceType] | None:
        rows = _named(await _table(info, None, "device_type"), "model", model)
        rows = _named(_equal(rows, "manufacturer_id", manufacturer_id), "part_number", part_number)
        return [make(DeviceType, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One device type by id.")
    async def device_type(self, info: Info, id: int) -> DeviceType | None:
        row = await _row(info, None, "device_type", id)
        return make(DeviceType, row) if row else None

    @strawberry.field(description="Device roles, by name.")
    async def device_roles(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[DeviceRole] | None:
        rows = _named(await _table(info, None, "device_role"), "name", name)
        return [make(DeviceRole, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Host lifecycle statuses, by name.")
    async def lifecycle_statuses(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[LifecycleStatus] | None:
        rows = _named(await _table(info, None, "lifecycle_status"), "name", name)
        return [make(LifecycleStatus, r) for r in _page(info, rows, limit, offset, bounded=True)]

    # Circuits

    @strawberry.field(description="Circuit providers, by name.")
    async def circuit_providers(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[CircuitProvider] | None:
        rows = _named(await _table(info, CIRCUITS, "circuit_provider"), "name", name)
        return [make(CircuitProvider, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Circuit types, by name.")
    async def circuit_types(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[CircuitType] | None:
        rows = _named(await _table(info, CIRCUITS, "circuit_type"), "name", name)
        return [make(CircuitType, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Circuits, by provider then circuit id. Filters combine (AND).")
    async def circuits(
        self,
        info: Info,
        cid: str | None = None,
        provider_id: int | None = None,
        circuit_type_id: int | None = None,
        status: str | None = None,
        tenant_id: int | None = None,
        site_id: int | None = None,
        host_id: int | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Circuit] | None:
        rows = _named(await _table(info, CIRCUITS, "circuit"), "cid", cid)
        rows = _equal(_equal(rows, "provider_id", provider_id), "circuit_type_id", circuit_type_id)
        rows = _equal(_equal(rows, "status", status), "tenant_id", tenant_id)
        for key, value in (("site_id", site_id), ("host_id", host_id)):
            if value is not None:
                rows = [c for c in rows if any(t.get(key) == value for t in c.get("terminations") or [])]
        return [make(Circuit, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One circuit by id.")
    async def circuit(self, info: Info, id: int) -> Circuit | None:
        row = await _row(info, CIRCUITS, "circuit", id)
        return make(Circuit, row) if row else None

    # DCIM

    @strawberry.field(description="Racks, by site then name. Filters combine (AND).")
    async def racks(
        self,
        info: Info,
        name: str | None = None,
        site_id: int | None = None,
        role_id: int | None = None,
        tenant_id: int | None = None,
        status: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Rack] | None:
        rows = _named(await _table(info, DCIM, "rack"), "name", name)
        rows = _equal(_equal(rows, "site_id", site_id), "role_id", role_id)
        rows = _equal(_equal(rows, "tenant_id", tenant_id), "status", status)
        return [make(Rack, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One rack by id.")
    async def rack(self, info: Info, id: int) -> Rack | None:
        row = await _row(info, DCIM, "rack", id)
        return make(Rack, row) if row else None

    @strawberry.field(description="Rack roles, by name.")
    async def rack_roles(self, info: Info, limit: int = DEFAULT_LIMIT, offset: int = 0) -> list[RackRole] | None:
        rows = await _table(info, DCIM, "rack_role")
        return [make(RackRole, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Cables, by id. host_id matches either end.")
    async def cables(
        self,
        info: Info,
        host_id: int | None = None,
        status: str | None = None,
        type: str | None = None,
        tenant_id: int | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Cable] | None:
        ctx = _ctx(info)
        ctx.require(DCIM)
        filters = {"host_id": host_id, "status": status, "type": type, "tenant_id": tenant_id}
        rows = await ctx.cables(filters)
        return [make(Cable, r) for r in ctx.page(rows, limit, offset)]

    @strawberry.field(description="One cable by id.")
    async def cable(self, info: Info, id: int) -> Cable | None:
        ctx = _ctx(info)
        ctx.require(DCIM)
        row = await ctx.cable(id)
        return make(Cable, row) if row else None

    @strawberry.field(description="Front ports of patch panels, by host then name.")
    async def front_ports(
        self,
        info: Info,
        host_id: int | None = None,
        name: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[FrontPort] | None:
        rows = await _dcim(info, "front_port", {"host_id": host_id}, name)
        return [make(FrontPort, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Rear ports of patch panels, by host then name.")
    async def rear_ports(
        self,
        info: Info,
        host_id: int | None = None,
        name: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[RearPort] | None:
        rows = await _dcim(info, "rear_port", {"host_id": host_id}, name)
        return [make(RearPort, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Modules, by host then bay.")
    async def modules(
        self,
        info: Info,
        host_id: int | None = None,
        status: str | None = None,
        part_number: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Module] | None:
        rows = await _dcim(info, "module", {"host_id": host_id, "status": status}, None)
        rows = _named(rows, "part_number", part_number)
        return [make(Module, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Power panels, by site then name.")
    async def power_panels(
        self, info: Info, site_id: int | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[PowerPanel] | None:
        rows = _equal(await _table(info, DCIM, "power_panel"), "site_id", site_id)
        return [make(PowerPanel, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Power feeds, by panel then name.")
    async def power_feeds(
        self,
        info: Info,
        power_panel_id: int | None = None,
        rack_id: int | None = None,
        status: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[PowerFeed] | None:
        rows = _equal(
            _equal(await _table(info, DCIM, "power_feed"), "power_panel_id", power_panel_id), "rack_id", rack_id
        )
        rows = _equal(rows, "status", status)
        return [make(PowerFeed, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Power ports (inlets) of hosts, by host then name.")
    async def power_ports(
        self, info: Info, host_id: int | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[PowerPort] | None:
        rows = await _dcim(info, "power_port", {"host_id": host_id}, None)
        return [make(PowerPort, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Power outlets of hosts, by host then name.")
    async def power_outlets(
        self, info: Info, host_id: int | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[PowerOutlet] | None:
        rows = await _dcim(info, "power_outlet", {"host_id": host_id}, None)
        return [make(PowerOutlet, r) for r in _page(info, rows, limit, offset, bounded=True)]

    # Virtualization

    @strawberry.field(description="Virtualization clusters, by name. Filters combine (AND).")
    async def clusters(
        self,
        info: Info,
        name: str | None = None,
        site_id: int | None = None,
        tenant_id: int | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Cluster] | None:
        rows = _named(await _table(info, VIRTUALIZATION, "cluster"), "name", name)
        rows = _equal(_equal(rows, "site_id", site_id), "tenant_id", tenant_id)
        return [make(Cluster, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One cluster by id.")
    async def cluster(self, info: Info, id: int) -> Cluster | None:
        row = await _row(info, VIRTUALIZATION, "cluster", id)
        return make(Cluster, row) if row else None

    @strawberry.field(description="Virtual machines, by name. Filters combine (AND).")
    async def virtual_machines(
        self,
        info: Info,
        name: str | None = None,
        cluster_id: int | None = None,
        site_id: int | None = None,
        tenant_id: int | None = None,
        role_id: int | None = None,
        status: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[VirtualMachine] | None:
        rows = _named(await _table(info, VIRTUALIZATION, "virtual_machine"), "name", name)
        rows = _equal(_equal(_equal(rows, "cluster_id", cluster_id), "site_id", site_id), "tenant_id", tenant_id)
        rows = _equal(_equal(rows, "role_id", role_id), "status", status)
        return [make(VirtualMachine, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One virtual machine by id.")
    async def virtual_machine(self, info: Info, id: int) -> VirtualMachine | None:
        row = await _row(info, VIRTUALIZATION, "virtual_machine", id)
        return make(VirtualMachine, row) if row else None

    # Routing

    @strawberry.field(description="AS number records, by number.")
    async def autonomous_systems(
        self,
        info: Info,
        asn: int | None = None,
        tenant_id: int | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[AutonomousSystem] | None:
        rows = _equal(_equal(await _table(info, ROUTING, "autonomous_system"), "asn", asn), "tenant_id", tenant_id)
        return [make(AutonomousSystem, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One AS number record by id.")
    async def autonomous_system(self, info: Info, id: int) -> AutonomousSystem | None:
        row = await _row(info, ROUTING, "autonomous_system", id)
        return make(AutonomousSystem, row) if row else None

    @strawberry.field(description="Routing instances, by device then name. asn is the local AS number.")
    async def routing_instances(
        self,
        info: Info,
        host_id: int | None = None,
        asn: int | None = None,
        status: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[RoutingInstance] | None:
        rows = _equal(_equal(await _table(info, ROUTING, "routing_instance"), "host_id", host_id), "asn", asn)
        rows = _equal(rows, "status", status)
        return [make(RoutingInstance, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One routing instance by id.")
    async def routing_instance(self, info: Info, id: int) -> RoutingInstance | None:
        row = await _row(info, ROUTING, "routing_instance", id)
        return make(RoutingInstance, row) if row else None

    @strawberry.field(description="BGP peerings, by device. asn matches the local or the remote AS number.")
    async def bgp_peerings(
        self,
        info: Info,
        host_id: int | None = None,
        routing_instance_id: int | None = None,
        asn: int | None = None,
        status: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[BgpPeering] | None:
        rows = await _table(info, ROUTING, "bgp_peering")
        rows = _equal(_equal(rows, "host_id", host_id), "routing_instance_id", routing_instance_id)
        if asn is not None:
            rows = [p for p in rows if asn in (p.get("local_asn"), p.get("remote_asn"))]
        rows = _equal(rows, "status", status)
        return [make(BgpPeering, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One BGP peering by id.")
    async def bgp_peering(self, info: Info, id: int) -> BgpPeering | None:
        row = await _row(info, ROUTING, "bgp_peering", id)
        return make(BgpPeering, row) if row else None

    # Hardware lifecycle

    @strawberry.field(description="End-of-life notices, by manufacturer then model or part number.")
    async def hardware_notices(
        self,
        info: Info,
        device_type_id: int | None = None,
        part_number: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[HardwareNotice] | None:
        rows = _equal(await _table(info, LIFECYCLE, "hardware_notice"), "device_type_id", device_type_id)
        rows = _named(rows, "part_number", part_number)
        return [make(HardwareNotice, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One end-of-life notice by id.")
    async def hardware_notice(self, info: Info, id: int) -> HardwareNotice | None:
        row = await _row(info, LIFECYCLE, "hardware_notice", id)
        return make(HardwareNotice, row) if row else None

    @strawberry.field(description="Support contracts, by provider then contract id.")
    async def support_contracts(
        self,
        info: Info,
        provider: str | None = None,
        host_id: int | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[SupportContract] | None:
        rows = _named(await _table(info, LIFECYCLE, "support_contract"), "provider", provider)
        if host_id is not None:
            rows = [c for c in rows if any(int(h["id"]) == host_id for h in c.get("hosts") or [])]
        return [make(SupportContract, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="One support contract by id.")
    async def support_contract(self, info: Info, id: int) -> SupportContract | None:
        row = await _row(info, LIFECYCLE, "support_contract", id)
        return make(SupportContract, row) if row else None


@strawberry.type
class IpamModelQuery:
    @strawberry.field(description="IPAM namespaces (Global first), by name.")
    async def namespaces(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[Namespace] | None:
        rows = _named(await _table(info, IPAM, "namespace"), "name", name)
        return [make(Namespace, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Route targets, by name.")
    async def route_targets(
        self,
        info: Info,
        name: str | None = None,
        tenant_id: int | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[RouteTarget] | None:
        rows = _equal(_named(await _table(info, IPAM, "route_target"), "name", name), "tenant_id", tenant_id)
        return [make(RouteTarget, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="VLAN groups, by name.")
    async def vlan_groups(
        self,
        info: Info,
        name: str | None = None,
        site_id: int | None = None,
        region_id: int | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[VlanGroup] | None:
        rows = _named(await _table(info, IPAM, "vlan_group"), "name", name)
        rows = _equal(_equal(rows, "site_id", site_id), "region_id", region_id)
        return [make(VlanGroup, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="RIRs, by name.")
    async def rirs(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[Rir] | None:
        rows = _named(await _table(info, IPAM, "rir"), "name", name)
        return [make(Rir, r) for r in _page(info, rows, limit, offset, bounded=True)]

    @strawberry.field(description="Aggregates with their usage, by family and network.")
    async def aggregates(
        self,
        info: Info,
        rir_id: int | None = None,
        tenant_id: int | None = None,
        contains: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Aggregate] | None:
        from netcontrol.ipam_model import containing_aggregate

        rows = _equal(_equal(await _table(info, IPAM, "aggregate"), "rir_id", rir_id), "tenant_id", tenant_id)
        if contains:
            rows = [r for r in rows if containing_aggregate(contains, [r]) is not None]
        return [make(Aggregate, r) for r in _page(info, rows, limit, offset, bounded=True)]


async def _dcim(info: Info, kind: str, filters: dict[str, Any], name: str | None) -> list[dict]:
    ctx = _ctx(info)
    ctx.require(DCIM)
    return _named(await ctx.dcim_records(kind, filters), "name", name)
