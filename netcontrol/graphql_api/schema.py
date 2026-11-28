"""The read-only GraphQL schema: inventory and IPAM objects and their relations,
and the root ``Query`` (with ``models.ModelQuery`` merged in for the other
object models; see ``netcontrol.graphql_api.models``).

Every type is an allow-list of columns: credentials, encrypted fields, SNMP
communities and profiles, API keys, cloud instance ids, configuration text
and IPAM ``metadata_json`` are never declared, so no query can reach them.

Fields check the feature the matching REST route needs (``Access denied for
feature 'X'`` in ``errors``, the rest of the query still answers):

* hosts, groups, their tags and custom fields, dynamic groups: ``inventory``
* interfaces, interface addresses, device VLANs: ``reports``
* prefixes, IP addresses, VLAN and VRF records: ``ipam``
* a host's latest configuration backup (metadata only): ``config-backups``

Hosts and inventory groups outside the caller's object scope are absent
from every list and every relation (a hidden parent group reads ``null``).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import Any

import routes.database as db
import strawberry
from graphql import GraphQLObjectType, GraphQLSchema
from strawberry.extensions import MaskErrors
from strawberry.tools import merge_types
from strawberry.types import Info

from netcontrol.graphql_api import limits, models
from netcontrol.graphql_api.common import DEFAULT_LIMIT, CustomData, _ctx, _opt_int, _text
from netcontrol.graphql_api.context import GraphQLClientError, network_of

# ── VRF and VLAN records ─────────────────────────────────────────────────────


@strawberry.type(name="VRF", description="A VRF record (Settings > IPAM > VRFs).")
class VRF(CustomData):
    row: strawberry.Private[dict]
    custom_type = "vrf"

    @strawberry.field
    def id(self) -> int:
        return int(self.row["id"])

    @strawberry.field
    def name(self) -> str:
        return _text(self.row, "name")

    @strawberry.field
    def rd(self) -> str:
        return _text(self.row, "rd")

    @strawberry.field
    def description(self) -> str:
        return _text(self.row, "description")

    @strawberry.field
    def origin(self) -> str:
        return _text(self.row, "origin")

    @strawberry.field(description="The route targets this VRF imports and exports.")
    async def route_targets(self, info: Info) -> models.VrfRouteTargets:
        return await models.vrf_route_targets(info, int(self.row["id"]))

    @strawberry.field
    async def namespace(self, info: Info) -> models.Namespace | None:
        return await models.namespace_of(info, self.row.get("namespace_id"))

    @strawberry.field(description="The IPAM prefixes of this VRF.")
    async def prefixes(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Prefix]:
        ctx = _ctx(info)
        rows = [p for p in await ctx.prefixes() if p["vrf"] == self.row["name"]]
        return [Prefix(row=r) for r in ctx.page(rows, limit, offset, bounded=False)]


@strawberry.type(name="VLAN", description="A VLAN record of a site or of no site.")
class VLAN(CustomData):
    row: strawberry.Private[dict]
    custom_type = "vlan"

    @strawberry.field
    def id(self) -> int:
        return int(self.row["id"])

    @strawberry.field
    def vid(self) -> int:
        return int(self.row["vid"])

    @strawberry.field
    def name(self) -> str:
        return _text(self.row, "name")

    @strawberry.field
    def description(self) -> str:
        return _text(self.row, "description")

    @strawberry.field
    def origin(self) -> str:
        return _text(self.row, "origin")

    @strawberry.field
    def site_id(self) -> int | None:
        return _opt_int(self.row, "site_id")

    @strawberry.field
    def site_name(self) -> str | None:
        site = self.row.get("site")
        return str(site["name"]) if site else None

    @strawberry.field
    async def vlan_group(self, info: Info) -> models.VlanGroup | None:
        row = await models._row(info, "ipam", "vlan_group", self.row.get("vlan_group_id"))
        return models.make(models.VlanGroup, row) if row else None

    @strawberry.field(description="The IPAM prefixes whose VLAN resolves to this record.")
    async def prefixes(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Prefix]:
        ctx = _ctx(info)
        mapping = await ctx.prefix_vlan_ids()
        rows = [p for p in await ctx.prefixes() if mapping.get(int(p["id"])) == int(self.row["id"])]
        return [Prefix(row=r) for r in ctx.page(rows, limit, offset, bounded=False)]


async def _vrf_named(info: Info, name: str) -> VRF | None:
    ctx = _ctx(info)
    ctx.require("ipam")
    row = (await ctx.vrfs_by_name()).get(name) if name else None
    return VRF(row=row) if row else None


async def _vlan_by_id(info: Info, vlan_id: int | None) -> VLAN | None:
    ctx = _ctx(info)
    ctx.require("ipam")
    row = (await ctx.vlans_by_id()).get(int(vlan_id)) if vlan_id is not None else None
    return VLAN(row=row) if row else None


# ── IPAM ─────────────────────────────────────────────────────────────────────


@strawberry.type(description="An IP address allocation of an IPAM source.")
class IPAddress:
    row: strawberry.Private[dict]

    @strawberry.field
    def id(self) -> int:
        return int(self.row["id"])

    @strawberry.field
    def address(self) -> str:
        return _text(self.row, "address")

    @strawberry.field
    def dns_name(self) -> str:
        return _text(self.row, "dns_name")

    @strawberry.field
    def status(self) -> str:
        return _text(self.row, "status")

    @strawberry.field
    def description(self) -> str:
        return _text(self.row, "description")

    @strawberry.field
    def vrf_name(self) -> str:
        return _text(self.row, "vrf_name")

    @strawberry.field(description="The VLAN text the source gives.")
    def vlan_name(self) -> str:
        return _text(self.row, "vlan_id")

    @strawberry.field(description="The prefix (network text) the allocation belongs to.")
    def prefix_subnet(self) -> str:
        return _text(self.row, "prefix_subnet")

    @strawberry.field(description="The IPAM source provider (plexus for local records).")
    def source(self) -> str:
        return _text(self.row, "provider")

    @strawberry.field
    def source_name(self) -> str:
        return _text(self.row, "source_name")

    @strawberry.field
    async def vrf(self, info: Info) -> VRF | None:
        return await _vrf_named(info, _text(self.row, "vrf_name").strip())


@strawberry.type(description="An IPAM prefix (local or synced from an IPAM source).")
class Prefix(CustomData):
    row: strawberry.Private[dict]
    custom_type = "prefix"

    def custom_row(self) -> dict:
        """A prefix's custom data is keyed by ``subnet|vrf``."""
        return {**self.row, "id": _prefix_key(self.row)}

    @strawberry.field
    def id(self) -> int:
        return int(self.row["id"])

    @strawberry.field(description="The network, e.g. 192.0.2.0/24.")
    def prefix(self) -> str:
        return str(self.row["_net"])

    @strawberry.field
    def family(self) -> int:
        return int(self.row["_net"].version)

    @strawberry.field
    def description(self) -> str:
        return _text(self.row, "description")

    @strawberry.field
    def status(self) -> str:
        return _text(self.row, "status")

    @strawberry.field
    def vrf_name(self) -> str:
        return _text(self.row, "vrf")

    @strawberry.field
    def tenant(self) -> str:
        return _text(self.row, "tenant")

    @strawberry.field
    def site(self) -> str:
        return _text(self.row, "site")

    @strawberry.field(description="The VLAN text the source gives (see vlan for the record).")
    def vlan_name(self) -> str:
        return _text(self.row, "vlan")

    @strawberry.field(description="The IPAM source provider (plexus for local records).")
    def source(self) -> str:
        return _text(self.row, "provider")

    @strawberry.field
    def source_name(self) -> str:
        return _text(self.row, "source_name")

    @strawberry.field
    async def vrf(self, info: Info) -> VRF | None:
        return await _vrf_named(info, self.row["vrf"])

    @strawberry.field
    async def vlan(self, info: Info) -> VLAN | None:
        return await _vlan_by_id(info, (await _ctx(info).prefix_vlan_ids()).get(int(self.row["id"])))

    @strawberry.field
    async def namespace(self, info: Info) -> models.Namespace | None:
        return await models.namespace_of(info, self.row.get("namespace_id"))

    @strawberry.field(description="The most specific aggregate that holds this prefix.")
    async def aggregate(self, info: Info) -> models.Aggregate | None:
        return await models.aggregate_of(info, str(self.row["_net"]))

    @strawberry.field(description="The most specific other prefix of the same VRF that contains this one.")
    async def parent(self, info: Info) -> Prefix | None:
        if self.row["_parent"] is None:
            return None
        row = (await _ctx(info).prefixes_by_network()).get((self.row["vrf"], self.row["_parent"]))
        return Prefix(row=row) if row else None

    @strawberry.field(description="The prefixes directly under this one in the same VRF.")
    async def children(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Prefix]:
        ctx = _ctx(info)
        rows = (await ctx.prefix_children()).get((self.row["vrf"], self.row["_net"]), [])
        return [Prefix(row=r) for r in ctx.page(rows, limit, offset, bounded=False)]

    @strawberry.field(description="The address allocations of this prefix in its IPAM source.")
    async def ip_addresses(self, info: Info, limit: int | None = None, offset: int = 0) -> list[IPAddress]:
        ctx = _ctx(info)
        rows = await ctx.allocations.load((int(self.row["source_id"]), str(self.row["subnet"])))
        return [IPAddress(row=r) for r in ctx.page(rows, limit, offset, bounded=False)]


def _prefix_key(row: dict) -> str:
    return f"{row['_net']}|{row['vrf']}"


# ── Inventory ────────────────────────────────────────────────────────────────


@strawberry.type(description="An interface address a device's stored configuration declares.")
class InterfaceAddress:
    row: strawberry.Private[dict]

    @strawberry.field
    def interface(self) -> str:
        return _text(self.row, "interface")

    @strawberry.field
    def address(self) -> str:
        return _text(self.row, "address")

    @strawberry.field
    def prefix_length(self) -> int:
        return int(self.row.get("prefix_length") or 0)

    @strawberry.field
    def network(self) -> str:
        return _text(self.row, "network")

    @strawberry.field
    def vrf_name(self) -> str:
        return _text(self.row, "vrf_name")

    @strawberry.field(description="primary, secondary or virtual.")
    def role(self) -> str:
        return _text(self.row, "role")

    @strawberry.field
    def protocol(self) -> str:
        return _text(self.row, "protocol")

    @strawberry.field(description="The VLAN id of a VLAN interface (0: none).")
    def svi_vid(self) -> int:
        return int(self.row.get("svi_vid") or 0)

    @strawberry.field
    def collected_at(self) -> str:
        return _text(self.row, "collected_at")

    @strawberry.field
    async def vrf(self, info: Info) -> VRF | None:
        return await _vrf_named(info, _text(self.row, "vrf_name"))

    @strawberry.field
    async def vlan(self, info: Info) -> VLAN | None:
        return await _vlan_by_id(info, self.row.get("vlan_id"))


@strawberry.type(description="An interface of a device (interface inventory).")
class Interface:
    row: strawberry.Private[dict]

    @strawberry.field
    def if_index(self) -> int:
        return int(self.row.get("if_index") or 0)

    @strawberry.field
    def name(self) -> str:
        return _text(self.row, "name")

    @strawberry.field
    def description(self) -> str:
        return _text(self.row, "description")

    @strawberry.field
    def admin_state(self) -> str:
        return _text(self.row, "admin_state")

    @strawberry.field
    def oper_state(self) -> str:
        return _text(self.row, "oper_state")

    @strawberry.field
    def speed_mbps(self) -> float:
        return float(self.row.get("speed_mbps") or 0)

    @strawberry.field
    def duplex(self) -> str:
        return _text(self.row, "duplex")

    @strawberry.field
    def access_vlan(self) -> int:
        return int(self.row.get("access_vlan") or 0)

    @strawberry.field
    def trunk_vlans(self) -> str:
        return _text(self.row, "trunk_vlans")

    @strawberry.field
    def collected_at(self) -> str:
        return _text(self.row, "collected_at")

    @strawberry.field(description="The addresses configured on this interface.")
    async def addresses(self, info: Info) -> list[InterfaceAddress]:
        rows = await _ctx(info).addresses.load(int(self.row["host_id"]))
        return [InterfaceAddress(row=r) for r in rows if r["interface"] == self.row.get("name")]


@strawberry.type(description="A VLAN a device defines.")
class HostVlan:
    row: strawberry.Private[dict]

    @strawberry.field
    def vid(self) -> int:
        return int(self.row["vid"])

    @strawberry.field
    def name(self) -> str:
        return _text(self.row, "name")

    @strawberry.field
    def state(self) -> str:
        return _text(self.row, "state")

    @strawberry.field(description="The VLAN record it resolves to (the device's site, else no site).")
    async def vlan(self, info: Info) -> VLAN | None:
        return await _vlan_by_id(info, self.row.get("record_id"))


@strawberry.type(description="Metadata of a configuration backup (never its text).")
class ConfigBackup:
    row: strawberry.Private[dict]

    @strawberry.field
    def id(self) -> int:
        return int(self.row["id"])

    @strawberry.field
    def captured_at(self) -> str:
        return _text(self.row, "captured_at")

    @strawberry.field
    def status(self) -> str:
        return _text(self.row, "status")

    @strawberry.field
    def capture_method(self) -> str:
        return _text(self.row, "capture_method")

    @strawberry.field
    def error_message(self) -> str:
        return _text(self.row, "error_message")

    @strawberry.field(description="Length of the stored configuration, in characters.")
    def config_length(self) -> int:
        return int(self.row.get("config_length") or 0)


@strawberry.type(description="A device in inventory.")
class Host(CustomData):
    row: strawberry.Private[dict]
    custom_type = "host"

    @strawberry.field
    def id(self) -> int:
        return int(self.row["id"])

    @strawberry.field
    def hostname(self) -> str:
        return _text(self.row, "hostname")

    @strawberry.field
    def ip_address(self) -> str:
        return _text(self.row, "ip_address")

    @strawberry.field
    def device_type(self) -> str:
        return _text(self.row, "device_type")

    @strawberry.field
    def status(self) -> str:
        return _text(self.row, "status")

    @strawberry.field
    def last_seen(self) -> str | None:
        return self.row.get("last_seen") or None

    @strawberry.field
    def model(self) -> str:
        return _text(self.row, "model")

    @strawberry.field
    def software_version(self) -> str:
        return _text(self.row, "software_version")

    @strawberry.field
    def device_category(self) -> str:
        return _text(self.row, "device_category")

    @strawberry.field
    def serial_number(self) -> str:
        return _text(self.row, "serial_number")

    @strawberry.field
    def vrf_name(self) -> str:
        return _text(self.row, "vrf_name")

    @strawberry.field(description="The VLAN text of the host's management address.")
    def vlan_name(self) -> str:
        return _text(self.row, "vlan_id")

    @strawberry.field
    def site_id(self) -> int | None:
        return _opt_int(self.row, "site_id")

    @strawberry.field
    def group_id(self) -> int:
        return int(self.row["group_id"])

    @strawberry.field
    async def group(self, info: Info) -> Group | None:
        row = (await _ctx(info).groups_by_id()).get(int(self.row["group_id"]))
        return Group(row=row) if row else None

    @strawberry.field
    async def interfaces(self, info: Info) -> list[Interface] | None:
        ctx = _ctx(info)
        ctx.require("reports")
        return [Interface(row=r) for r in await ctx.interfaces.load(int(self.row["id"]))]

    @strawberry.field
    async def interface_addresses(self, info: Info) -> list[InterfaceAddress] | None:
        ctx = _ctx(info)
        ctx.require("reports")
        return [InterfaceAddress(row=r) for r in await ctx.addresses.load(int(self.row["id"]))]

    @strawberry.field(description="The VLANs the device defines.")
    async def vlans(self, info: Info) -> list[HostVlan] | None:
        ctx = _ctx(info)
        ctx.require("reports")
        return [HostVlan(row=r) for r in await ctx.host_vlans.load(int(self.row["id"]))]

    @strawberry.field(description="The VRF record of the host's management VRF.")
    async def vrf(self, info: Info) -> VRF | None:
        return await _vrf_named(info, _text(self.row, "vrf_name").strip())

    @strawberry.field
    async def latest_config_backup(self, info: Info) -> ConfigBackup | None:
        ctx = _ctx(info)
        ctx.require("config-backups")
        row = (await ctx.latest_backups()).get(int(self.row["id"]))
        return ConfigBackup(row=row) if row else None

    # Device model, location, DCIM, circuits, virtualization, routing and
    # lifecycle (types in netcontrol.graphql_api.models).

    @strawberry.field(description="The device type record (manufacturer and model).")
    async def hardware(self, info: Info) -> models.DeviceType | None:
        row = await models._row(info, None, "device_type", self.row.get("device_type_id"))
        return models.make(models.DeviceType, row) if row else None

    @strawberry.field
    async def role(self, info: Info) -> models.DeviceRole | None:
        row = await models._row(info, None, "device_role", self.row.get("role_id"))
        return models.make(models.DeviceRole, row) if row else None

    @strawberry.field
    async def lifecycle_status(self, info: Info) -> models.LifecycleStatus | None:
        row = await models._row(info, None, "lifecycle_status", self.row.get("lifecycle_status_id"))
        return models.make(models.LifecycleStatus, row) if row else None

    @strawberry.field
    async def site(self, info: Info) -> models.Site | None:
        row = await models._row(info, models.ORGANIZATION, "site", self.row.get("site_id"))
        return models.make(models.Site, row) if row else None

    @strawberry.field
    async def tenant(self, info: Info) -> models.Tenant | None:
        row = await models._row(info, models.ORGANIZATION, "tenant", self.row.get("tenant_id"))
        return models.make(models.Tenant, row) if row else None

    @strawberry.field
    async def rack(self, info: Info) -> models.Rack | None:
        row = await models._row(info, models.DCIM, "rack", self.row.get("rack_id"))
        return models.make(models.Rack, row) if row else None

    @strawberry.field(description="The lowest rack unit the device occupies (null: not mounted).")
    def rack_position(self) -> int | None:
        return _opt_int(self.row, "rack_position")

    @strawberry.field(description="front or rear ('' when not mounted).")
    def rack_face(self) -> str:
        return _text(self.row, "rack_face")

    @strawberry.field
    async def front_ports(self, info: Info) -> list[models.FrontPort] | None:
        return [
            models.make(models.FrontPort, r) for r in await models._host_records(info, "front_port", self.row["id"])
        ]

    @strawberry.field
    async def rear_ports(self, info: Info) -> list[models.RearPort] | None:
        return [models.make(models.RearPort, r) for r in await models._host_records(info, "rear_port", self.row["id"])]

    @strawberry.field
    async def modules(self, info: Info) -> list[models.Module] | None:
        return [models.make(models.Module, r) for r in await models._host_records(info, "module", self.row["id"])]

    @strawberry.field
    async def power_ports(self, info: Info) -> list[models.PowerPort] | None:
        return [
            models.make(models.PowerPort, r) for r in await models._host_records(info, "power_port", self.row["id"])
        ]

    @strawberry.field
    async def power_outlets(self, info: Info) -> list[models.PowerOutlet] | None:
        rows = await models._host_records(info, "power_outlet", self.row["id"])
        return [models.make(models.PowerOutlet, r) for r in rows]

    @strawberry.field(description="The cables with an end on this host.")
    async def cables(self, info: Info) -> list[models.Cable] | None:
        return await models.host_cables(info, int(self.row["id"]))

    @strawberry.field(description="The circuit terminations on this host.")
    async def circuit_terminations(self, info: Info) -> list[models.CircuitTermination] | None:
        return await models.host_terminations(info, int(self.row["id"]))

    @strawberry.field(description="The clusters this host is a hypervisor of.")
    async def clusters(self, info: Info) -> list[models.Cluster] | None:
        return await models.host_clusters(info, int(self.row["id"]))

    @strawberry.field
    async def routing_instances(self, info: Info) -> list[models.RoutingInstance] | None:
        rows = await models._rows(info, models.ROUTING, "routing_instance", "host_id", self.row["id"])
        return [models.make(models.RoutingInstance, r) for r in rows]

    @strawberry.field
    async def bgp_peerings(self, info: Info) -> list[models.BgpPeering] | None:
        rows = await models._rows(info, models.ROUTING, "bgp_peering", "host_id", self.row["id"])
        return [models.make(models.BgpPeering, r) for r in rows]

    @strawberry.field(description="The end-of-life notices that apply to this host.")
    async def hardware_notices(self, info: Info) -> list[models.HardwareNotice] | None:
        return await models.host_notices(info, int(self.row["id"]))

    @strawberry.field(description="The support contracts covering this host.")
    async def support_contracts(self, info: Info) -> list[models.SupportContract] | None:
        return await models.host_contracts(info, int(self.row["id"]))


@strawberry.type(description="An inventory group.")
class Group(CustomData):
    row: strawberry.Private[dict]
    custom_type = "group"

    @strawberry.field
    def id(self) -> int:
        return int(self.row["id"])

    @strawberry.field
    def name(self) -> str:
        return _text(self.row, "name")

    @strawberry.field
    def description(self) -> str:
        return _text(self.row, "description")

    @strawberry.field
    def environment(self) -> str | None:
        return self.row.get("environment") or None

    @strawberry.field(description="Full path from the top group, e.g. site-a / floor-1.")
    def path(self) -> str:
        return _text(self.row, "path")

    @strawberry.field
    def depth(self) -> int:
        return int(self.row.get("depth") or 0)

    @strawberry.field(description="The parent group, null at the top or when it is outside your scope.")
    async def parent(self, info: Info) -> Group | None:
        parent_id = self.row.get("parent_id")
        row = (await _ctx(info).groups_by_id()).get(int(parent_id)) if parent_id is not None else None
        return Group(row=row) if row else None

    @strawberry.field
    async def children(self, info: Info) -> list[Group]:
        return [Group(row=r) for r in (await _ctx(info).group_children()).get(int(self.row["id"]), [])]

    @strawberry.field(description="The hosts directly in this group.")
    async def hosts(self, info: Info, name: str | None = None, limit: int | None = None, offset: int = 0) -> list[Host]:
        ctx = _ctx(info)
        rows = (await ctx.hosts_by_group()).get(int(self.row["id"]), [])
        if name:
            rows = [h for h in rows if name.lower() in _text(h, "hostname").lower()]
        return [Host(row=r) for r in ctx.page(rows, limit, offset, bounded=False)]


# ── Filters ──────────────────────────────────────────────────────────────────


def _ip_matcher(ip: str) -> Any:
    """A test of a host's address against ``ip``: an address (equal) or a
    network (inside)."""
    text = ip.strip()
    if "/" in text:
        net = network_of(text)
        if net is None:
            raise GraphQLClientError("ip must be an IP address or a network")

        def inside(value: str) -> bool:
            try:
                return ipaddress.ip_address(value.split("/")[0].strip()) in net
            except ValueError:
                return False

        return inside
    try:
        wanted = ipaddress.ip_address(text)
    except ValueError as exc:
        raise GraphQLClientError("ip must be an IP address or a network") from exc

    def equal(value: str) -> bool:
        try:
            return ipaddress.ip_address(value.split("/")[0].strip()) == wanted
        except ValueError:
            return False

    return equal


def _network_arg(text: str, name: str) -> Any:
    net = network_of(text)
    if net is None:
        raise GraphQLClientError(f"{name} must be an IP address or a network")
    return net


# ── Root ─────────────────────────────────────────────────────────────────────


@strawberry.type(description="A dynamic group: a saved host filter, resolved when it is read.")
class DynamicGroup:
    row: strawberry.Private[dict]

    @strawberry.field
    def id(self) -> int:
        return int(self.row["id"])

    @strawberry.field
    def name(self) -> str:
        return _text(self.row, "name")

    @strawberry.field
    def description(self) -> str:
        return _text(self.row, "description")

    @strawberry.field(description="The hosts the filter matches now, among those you may read.")
    async def members(self, info: Info, limit: int | None = None, offset: int = 0) -> list[Host]:
        ctx = _ctx(info)
        rows = await ctx.dynamic_group_hosts(self.row)
        return [Host(row=r) for r in ctx.page(rows, limit, offset, bounded=False)]


@strawberry.type
class InventoryQuery:
    @strawberry.field(description="Dynamic groups (saved host filters), by name.")
    async def dynamic_groups(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[DynamicGroup] | None:
        ctx = _ctx(info)
        ctx.require("inventory")
        rows = await db.list_dynamic_groups()
        if name:
            rows = [g for g in rows if name.lower() in _text(g, "name").lower()]
        return [DynamicGroup(row=r) for r in ctx.page(rows, limit, offset)]

    @strawberry.field(description="Hosts you may read, by hostname. Filters combine (AND).")
    async def hosts(
        self,
        info: Info,
        name: str | None = None,
        ip: str | None = None,
        group_id: int | None = None,
        group: str | None = None,
        device_type: str | None = None,
        status: str | None = None,
        tags: list[str] | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Host] | None:
        ctx = _ctx(info)
        ctx.require("inventory")
        # Scope, group, type, status and tags narrow the list in SQL; the
        # name (substring ignoring case) and address tests run on the ids,
        # names and addresses only (``GraphQLContext.host_page``).
        tests: list[Callable[[dict], bool]] = []
        if name:
            needle = name.lower()
            tests.append(lambda h: needle in _text(h, "hostname").lower())
        if ip:
            match = _ip_matcher(ip)
            tests.append(lambda h: match(_text(h, "ip_address")))
        group_ids: set[int] | None = None
        if group_id is not None:
            group_ids = {group_id}
        if group:
            groups = await ctx.groups_by_id()
            wanted = group.strip().lower()
            ids = {gid for gid, g in groups.items() if wanted in (_text(g, "name").lower(), _text(g, "path").lower())}
            group_ids = ids if group_ids is None else group_ids & ids
        equal = {k: v for k, v in (("device_type", device_type), ("status", status)) if v}
        host_ids: list[int] | None = None
        if tags:
            keys = await ctx.tagged_keys("host", tags)
            host_ids = [int(k) for k in keys if k.isascii() and k.isdigit() and str(int(k)) == k]
        rows = await ctx.host_page(
            limit,
            offset,
            group_ids=group_ids,
            host_ids=host_ids,
            equal=equal,
            keep=(lambda h: all(t(h) for t in tests)) if tests else None,
        )
        return [Host(row=r) for r in rows]

    @strawberry.field(description="One host by id (null when unknown or outside your scope).")
    async def host(self, info: Info, id: int) -> Host | None:
        ctx = _ctx(info)
        ctx.require("inventory")
        row = (await ctx.hosts_by_id()).get(id)
        return Host(row=row) if row else None

    @strawberry.field(description="Inventory groups you may read, as a tree (parents before children).")
    async def groups(
        self,
        info: Info,
        name: str | None = None,
        tags: list[str] | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Group] | None:
        ctx = _ctx(info)
        ctx.require("inventory")
        rows = await ctx.groups()
        if name:
            rows = [g for g in rows if name.lower() in _text(g, "name").lower()]
        if tags:
            keys = await ctx.tagged_keys("group", tags)
            rows = [g for g in rows if str(g["id"]) in keys]
        return [Group(row=r) for r in ctx.page(rows, limit, offset)]

    @strawberry.field(description="One inventory group by id (null when unknown or outside your scope).")
    async def group(self, info: Info, id: int) -> Group | None:
        ctx = _ctx(info)
        ctx.require("inventory")
        row = (await ctx.groups_by_id()).get(id)
        return Group(row=row) if row else None

    @strawberry.field(description="IPAM prefixes, by family and network. Filters combine (AND).")
    async def prefixes(
        self,
        info: Info,
        prefix: str | None = None,
        within: str | None = None,
        contains: str | None = None,
        vrf: str | None = None,
        tags: list[str] | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Prefix] | None:
        ctx = _ctx(info)
        ctx.require("ipam")
        rows = await ctx.prefixes()
        if prefix:
            exact = _network_arg(prefix, "prefix")
            rows = [p for p in rows if p["_net"] == exact]
        if within:
            outer = _network_arg(within, "within")
            rows = [p for p in rows if p["_net"].version == outer.version and p["_net"].subnet_of(outer)]
        if contains:
            inner = _network_arg(contains, "contains")
            rows = [p for p in rows if p["_net"].version == inner.version and p["_net"].supernet_of(inner)]
        if vrf is not None:
            rows = [p for p in rows if p["vrf"] == vrf.strip()]
        if tags:
            keys = await ctx.tagged_keys("prefix", tags)
            rows = [p for p in rows if _prefix_key(p) in keys]
        return [Prefix(row=r) for r in ctx.page(rows, limit, offset)]

    @strawberry.field(description="One IPAM prefix by id.")
    async def prefix(self, info: Info, id: int) -> Prefix | None:
        ctx = _ctx(info)
        ctx.require("ipam")
        row = (await ctx.prefixes_by_id()).get(id)
        return Prefix(row=row) if row else None

    @strawberry.field(description="IPAM address allocations, by address.")
    async def ip_addresses(
        self,
        info: Info,
        address: str | None = None,
        vrf: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[IPAddress] | None:
        ctx = _ctx(info)
        ctx.require("ipam")
        vrf_name = vrf.strip() if vrf is not None else None
        rows = await ctx.allocation_page(address.strip() if address else None, vrf_name, limit, offset)
        return [IPAddress(row=r) for r in rows]

    @strawberry.field(description="VLAN records, by site and VLAN id.")
    async def vlans(
        self,
        info: Info,
        vid: int | None = None,
        name: str | None = None,
        site_id: int | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[VLAN] | None:
        ctx = _ctx(info)
        ctx.require("ipam")
        rows = await ctx.vlans()
        if vid is not None:
            rows = [v for v in rows if int(v["vid"]) == vid]
        if name:
            rows = [v for v in rows if name.lower() in _text(v, "name").lower()]
        if site_id is not None:
            rows = [v for v in rows if v.get("site_id") == site_id]
        return [VLAN(row=r) for r in ctx.page(rows, limit, offset)]

    @strawberry.field(description="VRF records, by name.")
    async def vrfs(
        self, info: Info, name: str | None = None, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> list[VRF] | None:
        ctx = _ctx(info)
        ctx.require("ipam")
        rows = await ctx.vrfs()
        if name:
            rows = [v for v in rows if name.lower() in _text(v, "name").lower()]
        return [VRF(row=r) for r in ctx.page(rows, limit, offset)]


def _should_mask(error: Any) -> bool:
    """Mask resolver failures except the ones meant for the caller; errors
    with no original exception (syntax, validation) are kept."""
    original = getattr(error, "original_error", None)
    return original is not None and not isinstance(original, GraphQLClientError)


Query = merge_types("Query", (InventoryQuery, models.ModelQuery, models.IpamModelQuery))

schema = strawberry.Schema(
    query=Query,
    extensions=[
        lambda: MaskErrors(should_mask_error=_should_mask, error_message="Internal error"),
        limits.ResultSizeLimit,
    ],
)


def _describe_nested_limits(gql_schema: GraphQLSchema) -> None:
    """Say on every nested list's ``limit`` argument (no default) what the
    list returns without one: at most ``max_limit`` rows
    (``GraphQLContext.page``), which is also what the cost estimate
    assumes."""
    for gql_type in gql_schema.type_map.values():
        if not isinstance(gql_type, GraphQLObjectType) or gql_type.name.startswith("__"):
            continue
        for field in gql_type.fields.values():
            arg = field.args.get("limit")
            if arg is not None and arg.default_value is None and not arg.description:
                arg.description = (
                    "Most rows to return. Without it, at most the max_limit of the graphql_api "
                    "setting (1000 by default); the cost estimate counts that many."
                )


_describe_nested_limits(schema._schema)
