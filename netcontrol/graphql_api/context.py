"""The per-request context of a GraphQL query: who is asking, what they may
see, and the batched readers every resolver goes through.

Access is decided as the REST API decides it:

* ``require(feature)``: the feature the matching REST route needs (``None``
  features: an admin or the server API token, who pass every check);
* ``scope``: the caller's object scope (``netcontrol.object_scope``); hosts
  and inventory groups outside it are never listed or reachable, and the
  rows of every other model go through the scope model registry
  (``visible``: ``object_scope.filter_rows`` on rows keyed by
  ``scope_keyed``).

Every reader runs once per request (``_once``) or is a ``DataLoader`` that
batches the keys of one execution step into one query, so nested queries
cost a fixed number of database round trips whatever the number of rows.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

import routes.database as db
from strawberry.dataloader import DataLoader

from netcontrol.custom_fields import OBJECT_TYPE_SPECS, OBJECT_TYPES
from netcontrol.object_scope import ObjectScope, filter_rows
from netcontrol.routes.custom_fields import object_custom_data_bulk
from netcontrol.routes.inventory import _visible_tree

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class GraphQLClientError(Exception):
    """An error whose message is shown to the caller (all others are masked)."""


class GraphQLAccessError(GraphQLClientError):
    """The caller lacks the feature a field needs."""


def network_of(text: object) -> IPNetwork | None:
    try:
        return ipaddress.ip_network(str(text or "").strip(), strict=False)
    except ValueError:
        return None


def _supernets(net: IPNetwork) -> Iterable[IPNetwork]:
    for length in range(net.prefixlen - 1, -1, -1):
        yield net.supernet(new_prefix=length)


# Every row the virtual machine list reads (it takes a limit; the others
# answer every row).
_ALL_VMS = 1_000_000

# Model name -> the routes.db reader of every row of it. Each is read at most
# once per request (``GraphQLContext.table``).
_TABLES: dict[str, Callable[[], Awaitable[list[dict]]]] = {
    "region": db.list_regions,
    "site": db.list_geo_sites,
    "tenant_group": db.list_tenant_groups,
    "tenant": db.list_tenants,
    "manufacturer": db.list_manufacturers,
    "device_type": db.list_device_types,
    "device_role": db.list_device_roles,
    "lifecycle_status": db.list_lifecycle_statuses,
    "circuit_provider": db.list_circuit_providers,
    "provider_network": db.list_provider_networks,
    "circuit_type": db.list_circuit_types,
    "circuit": db.list_circuits,
    "rack_role": lambda: db.list_dcim_records("rack_role"),
    "rack": lambda: db.list_dcim_records("rack"),
    "power_panel": lambda: db.list_dcim_records("power_panel"),
    "power_feed": lambda: db.list_dcim_records("power_feed"),
    "cluster": db.list_clusters,
    "cluster_host": db.list_cluster_host_links,
    "virtual_machine": lambda: db.list_virtual_machines(limit=_ALL_VMS),
    "autonomous_system": db.list_autonomous_systems,
    "routing_instance": db.list_routing_instances,
    "bgp_peering": db.list_bgp_peerings,
    "hardware_notice": db.list_hardware_notices,
    "hardware_notice_match": db.hardware_notice_matches,
    "support_contract": db.list_support_contracts,
    # Migration 0110: IPAM namespaces, route targets, VLAN groups, RIRs and
    # aggregates (with their usage), and device type component templates.
    "namespace": lambda: db.list_dcim_records("namespace"),
    "route_target": lambda: db.list_dcim_records("route_target"),
    "vlan_group": lambda: db.list_dcim_records("vlan_group"),
    "rir": lambda: db.list_dcim_records("rir"),
    "aggregate": db.list_aggregates_with_usage,
    "component_template": lambda: db.list_dcim_records("component_template"),
}

# The DCIM record kinds that belong to a host (read per host in batches).
HOST_RECORD_KINDS: tuple[str, ...] = ("front_port", "rear_port", "module", "power_port", "power_outlet")

# Model name -> its ``netcontrol.object_scope.MODELS`` entry where the names
# differ: the custom data types' ``scope_model`` (``ObjectTypeSpec``; the
# device model catalogues are ``catalog``, a peering follows its routing
# instance's host), plus the models with no custom data: the other shared
# catalogues (lifecycle statuses, notices, component templates), a host's
# own records and IPAM addresses.
_SCOPE_MODELS: dict[str, str] = {
    "lifecycle_status": "catalog",
    "hardware_notice": "catalog",
    "component_template": "catalog",
    **dict.fromkeys(HOST_RECORD_KINDS, "host_record"),
    "cluster_host": "host_record",
    "hardware_notice_match": "host_record",
    "ip_address": "ipam_allocation",
    **{spec.key: spec.scope_model for spec in OBJECT_TYPE_SPECS.values()},
}


def _row_key(row: dict) -> str:
    return str(row["id"])


class GraphQLContext:
    def __init__(self, *, scope: ObjectScope, features: frozenset[str] | None, max_limit: int) -> None:
        self.scope = scope
        self.features = features
        self.max_limit = max_limit
        self._memo: dict[str, asyncio.Future[Any]] = {}
        self.interfaces = DataLoader(load_fn=self._load_interfaces)
        self.addresses = DataLoader(load_fn=self._load_addresses)
        self.host_vlans = DataLoader(load_fn=self._load_host_vlans)
        self.allocations = DataLoader(load_fn=self._load_allocations)
        # Keyed by the row (its ``id``: a prefix's is ``subnet|vrf``).
        self.custom_data: dict[str, DataLoader[dict, dict]] = {
            object_type: DataLoader(load_fn=self._custom_loader(object_type), cache_key_fn=_row_key)
            for object_type in OBJECT_TYPES
        }
        self.host_records: dict[str, DataLoader[int, list[dict]]] = {
            kind: DataLoader(load_fn=self._host_records_loader(kind)) for kind in HOST_RECORD_KINDS
        }
        self.host_cables = DataLoader(load_fn=self._load_host_cables)
        self.vm_interfaces = DataLoader(load_fn=self._load_vm_interfaces)

    # ── Access ───────────────────────────────────────────────────────────────

    def require(self, feature: str) -> None:
        if self.features is not None and feature not in self.features:
            raise GraphQLAccessError(f"Access denied for feature '{feature}'")

    def page(self, rows: list[Any], limit: int | None, offset: int, *, bounded: bool = True) -> list[Any]:
        """``rows[offset:offset + limit]``; ``limit`` None (nested lists
        only) is every row from ``offset``."""
        if offset < 0:
            raise GraphQLClientError("offset must be 0 or more")
        if limit is None:
            if bounded:
                raise GraphQLClientError("limit is required")
            return rows[offset:]
        if not 1 <= limit <= self.max_limit:
            raise GraphQLClientError(f"limit must be between 1 and {self.max_limit}")
        return rows[offset : offset + limit]

    async def _once(self, key: str, factory: Callable[[], Awaitable[Any]]) -> Any:
        future = self._memo.get(key)
        if future is None:
            future = asyncio.ensure_future(factory())
            self._memo[key] = future
        return await future

    # ── Inventory (scoped) ───────────────────────────────────────────────────

    async def groups(self) -> list[dict]:
        """The readable groups as a tree (a group under a hidden parent is
        top level), as ``GET /api/inventory`` lists them."""

        async def load() -> list[dict]:
            return _visible_tree(self.scope, await db.get_all_groups())

        return await self._once("groups", load)

    async def groups_by_id(self) -> dict[int, dict]:
        async def load() -> dict[int, dict]:
            return {int(g["id"]): g for g in await self.groups()}

        return await self._once("groups_by_id", load)

    async def group_children(self) -> dict[int | None, list[dict]]:
        async def load() -> dict[int | None, list[dict]]:
            out: dict[int | None, list[dict]] = {}
            for group in await self.groups():
                parent = group.get("parent_id")
                out.setdefault(int(parent) if parent is not None else None, []).append(group)
            return out

        return await self._once("group_children", load)

    async def hosts(self) -> list[dict]:
        """The readable hosts, by hostname."""

        async def load() -> list[dict]:
            return self.scope.filter_hosts(await db.get_all_hosts())

        return await self._once("hosts", load)

    async def hosts_by_id(self) -> dict[int, dict]:
        async def load() -> dict[int, dict]:
            return {int(h["id"]): h for h in await self.hosts()}

        return await self._once("hosts_by_id", load)

    async def hosts_by_group(self) -> dict[int, list[dict]]:
        async def load() -> dict[int, list[dict]]:
            out: dict[int, list[dict]] = {}
            for host in await self.hosts():
                out.setdefault(int(host["group_id"]), []).append(host)
            return out

        return await self._once("hosts_by_group", load)

    async def latest_backups(self) -> dict[int, dict]:
        """``host_id -> newest backup`` (metadata only) of the readable hosts."""

        async def load() -> dict[int, dict]:
            kwargs = {} if self.scope.unrestricted else {"group_ids": self.scope.read_groups}
            rows = await db.get_latest_config_backups_per_host(**kwargs)
            return {int(r["host_id"]): r for r in rows if r.get("host_id") is not None}

        return await self._once("latest_backups", load)

    async def tagged_keys(self, object_type: str, tags: list[str]) -> set[str]:
        return await db.find_object_keys(object_type, tags, {})

    # ── IPAM ─────────────────────────────────────────────────────────────────

    async def vrfs(self) -> list[dict]:
        async def load() -> list[dict]:
            return await self.visible("vrf", await db.list_vrfs())

        return await self._once("vrfs", load)

    async def vrfs_by_name(self) -> dict[str, dict]:
        async def load() -> dict[str, dict]:
            return {v["name"]: v for v in await self.vrfs()}

        return await self._once("vrfs_by_name", load)

    async def vlans(self) -> list[dict]:
        async def load() -> list[dict]:
            return await self.visible("vlan", await db.list_vlans())

        return await self._once("vlans", load)

    async def vlans_by_id(self) -> dict[int, dict]:
        async def load() -> dict[int, dict]:
            return {int(v["id"]): v for v in await self.vlans()}

        return await self._once("vlans_by_id", load)

    async def prefixes(self) -> list[dict]:
        """Every IPAM prefix with a valid network, by family, network and id,
        each with ``_net`` (its network) and ``_parent`` (the network of the
        most specific other prefix of its VRF that contains it, or None)."""

        async def load() -> list[dict]:
            rows = []
            for row in await self.visible("prefix", await db.list_ipam_prefix_records()):
                net = network_of(row.get("subnet"))
                if net is None:
                    continue
                rows.append({**row, "vrf": (row.get("vrf") or "").strip(), "_net": net})
            present = {(r["vrf"], r["_net"]) for r in rows}
            for row in rows:
                row["_parent"] = next((s for s in _supernets(row["_net"]) if (row["vrf"], s) in present), None)
            rows.sort(key=lambda r: (r["_net"].version, r["_net"], int(r["id"])))
            return rows

        return await self._once("prefixes", load)

    async def prefixes_by_id(self) -> dict[int, dict]:
        async def load() -> dict[int, dict]:
            return {int(p["id"]): p for p in await self.prefixes()}

        return await self._once("prefixes_by_id", load)

    async def prefixes_by_network(self) -> dict[tuple[str, IPNetwork], dict]:
        """``(vrf, network) -> prefix`` (the lowest id when sources repeat one)."""

        async def load() -> dict[tuple[str, IPNetwork], dict]:
            out: dict[tuple[str, IPNetwork], dict] = {}
            for row in await self.prefixes():
                out.setdefault((row["vrf"], row["_net"]), row)
            return out

        return await self._once("prefixes_by_network", load)

    async def prefix_children(self) -> dict[tuple[str, IPNetwork], list[dict]]:
        async def load() -> dict[tuple[str, IPNetwork], list[dict]]:
            out: dict[tuple[str, IPNetwork], list[dict]] = {}
            for row in await self.prefixes():
                if row["_parent"] is not None:
                    out.setdefault((row["vrf"], row["_parent"]), []).append(row)
            return out

        return await self._once("prefix_children", load)

    async def prefix_vlan_ids(self) -> dict[int, int]:
        """``prefix id -> VLAN record id`` for the prefixes whose ``vlan``
        text names one record: a VLAN id (the record at the prefix's site,
        else the one of no site, else the only one) or a VLAN name (the only
        record of that name)."""

        async def load() -> dict[int, int]:
            by_vid: dict[int, list[dict]] = {}
            by_name: dict[str, list[dict]] = {}
            for vlan in await self.vlans():
                by_vid.setdefault(int(vlan["vid"]), []).append(vlan)
                if vlan["name"]:
                    by_name.setdefault(str(vlan["name"]).lower(), []).append(vlan)
            out: dict[int, int] = {}
            for row in await self.prefixes():
                text = str(row.get("vlan") or "").strip()
                if not text:
                    continue
                if text.isdigit():
                    found = by_vid.get(int(text), [])
                    site = str(row.get("site") or "").strip().lower()
                    pick = [v for v in found if site and v["site"] and str(v["site"]["name"]).lower() == site]
                    pick = pick or [v for v in found if v["site_id"] is None] or found
                else:
                    pick = by_name.get(text.lower(), [])
                if len(pick) == 1:
                    out[int(row["id"])] = int(pick[0]["id"])
            return out

        return await self._once("prefix_vlan_ids", load)

    async def allocation_records(self, address: str | None) -> list[dict]:
        return await self.visible("ip_address", await db.list_ipam_allocation_records(address=address))

    async def vrf_route_targets(self) -> dict[int, dict[str, list[dict]]]:
        """VRF id -> its ``{"import", "export"}`` route targets (readable
        ones only)."""

        async def load() -> dict[int, dict[str, list[dict]]]:
            readable = await self.by_id("route_target")
            return {
                vrf_id: {
                    d: [readable[int(r["id"])] for r in rts if int(r["id"]) in readable] for d, rts in found.items()
                }
                for vrf_id, found in (await db.get_route_targets_by_vrf_ids()).items()
            }

        return await self._once("vrf_route_targets", load)

    # ── Models (organization, device model, circuits, DCIM, virtualization,
    #    routing, hardware lifecycle) ─────────────────────────────────────────

    async def raw(self, model: str) -> list[dict]:
        """Every row of ``model`` (``_TABLES``), unfiltered, read once per
        request: for the scope keys of other models only."""
        return await self._once(f"raw:{model}", _TABLES[model])

    async def table(self, model: str) -> list[dict]:
        """Every row of ``model`` the caller may read, read once per request."""

        async def load() -> list[dict]:
            return await self.visible(model, await self.raw(model))

        return await self._once(f"table:{model}", load)

    async def by_id(self, model: str) -> dict[int, dict]:
        async def load() -> dict[int, dict]:
            return {int(r["id"]): r for r in await self.table(model)}

        return await self._once(f"by_id:{model}", load)

    async def grouped(self, model: str, key: str) -> dict[int, list[dict]]:
        """The readable rows of ``model`` by their ``key`` column (rows
        without one are left out)."""

        async def load() -> dict[int, list[dict]]:
            out: dict[int, list[dict]] = {}
            for row in await self.table(model):
                if row.get(key) is not None:
                    out.setdefault(int(row[key]), []).append(row)
            return out

        return await self._once(f"grouped:{model}:{key}", load)

    async def hosts_where(self, key: str) -> dict[int, list[dict]]:
        """The readable hosts by their ``key`` column (``site_id``,
        ``rack_id``, ``tenant_id``, ``device_type_id`` ...)."""

        async def load() -> dict[int, list[dict]]:
            out: dict[int, list[dict]] = {}
            for host in await self.hosts():
                if host.get(key) is not None:
                    out.setdefault(int(host[key]), []).append(host)
            return out

        return await self._once(f"hosts_where:{key}", load)

    async def visible(self, model: str, rows: list[dict]) -> list[dict]:
        """``rows`` of ``model`` the caller may read, by the rules of its
        ``object_scope.MODELS`` entry (``_SCOPE_MODELS``), each keyed by
        ``scope_keyed``. An unrestricted caller keeps every row."""
        if self.scope.unrestricted or not rows:
            return rows
        keyed = await self.scope_keyed(model, rows)
        return await filter_rows(_SCOPE_MODELS.get(model, model), keyed, self.scope)

    async def scope_keyed(self, model: str, rows: list[dict]) -> list[dict]:
        """``rows`` with the derived fields their scope model reads
        (``object_scope.MODELS``): ``scope_host_ids`` / ``scope_site_ids`` of
        a circuit, cluster, VM, contract, VLAN group or cable,
        ``cluster_site_id`` of a VM and ``circuit_tenant_id`` of a
        termination. The REST routes' own keying helpers are used where they
        read no database; cables and terminations are keyed from the
        request's tables (batched, where REST reads per endpoint)."""
        if model == "circuit":
            from netcontrol.routes.circuits import _keyed  # deferred: imports this package's callers

            return [_keyed(r) for r in rows]
        if model in ("cluster", "virtual_machine"):
            from netcontrol.routes.virtualization import _keyed_cluster, _keyed_vm

            members: dict[int, list[int]] = {}
            for link in await self.raw("cluster_host"):
                members.setdefault(int(link["cluster_id"]), []).append(int(link["host_id"]))
            keyer = _keyed_cluster if model == "cluster" else _keyed_vm
            return [keyer(r, members) for r in rows]
        if model == "support_contract":
            from netcontrol.routes.hardware_lifecycle import _scoped_contract

            return [_scoped_contract(r) for r in rows]
        if model == "vlan_group":
            return await db.with_vlan_group_scope(rows)
        if model == "circuit_termination":
            tenants = {int(c["id"]): c.get("tenant_id") for c in await self.raw("circuit")}
            return [{**t, "circuit_tenant_id": tenants.get(int(t["circuit_id"]))} for t in rows]
        if model == "cable":
            sites = await self._endpoint_sites()
            out = []
            for row in rows:
                hosts = [int(h) for h in (row.get("a_host_id"), row.get("b_host_id")) if h is not None]
                ends = ((str(row.get(f"{s}_type")), row.get(f"{s}_id")) for s in ("a", "b"))
                found = [sites.get((kind, int(rid))) for kind, rid in ends if rid is not None]
                out.append({**row, "scope_host_ids": hosts, "scope_site_ids": [s for s in found if s is not None]})
            return out
        return rows

    async def _endpoint_sites(self) -> dict[tuple[str, int], int]:
        """``(endpoint type, id) -> site id`` of power feeds (their panel's
        site) and circuit terminations, the cable ends a site reaches."""

        async def load() -> dict[tuple[str, int], int]:
            out: dict[tuple[str, int], int] = {}
            for feed in await self.raw("power_feed"):
                if feed.get("site_id") is not None:
                    out[("power_feed", int(feed["id"]))] = int(feed["site_id"])
            for circuit in await self.raw("circuit"):
                for term in circuit.get("terminations") or []:
                    if term.get("site_id") is not None:
                        out[("circuit_termination", int(term["id"]))] = int(term["site_id"])
            return out

        return await self._once("endpoint_sites", load)

    async def circuit_terminations(self, key: str) -> dict[int, list[dict]]:
        """The terminations of the readable circuits by their ``key``
        column (``host_id``, ``site_id``, ``provider_network_id``)."""

        async def load() -> dict[int, list[dict]]:
            out: dict[int, list[dict]] = {}
            for term in await self.terminations():
                if term.get(key) is not None:
                    out.setdefault(int(term[key]), []).append(term)
            return out

        return await self._once(f"circuit_terminations:{key}", load)

    async def terminations(self) -> list[dict]:
        """The readable terminations of the readable circuits."""

        async def load() -> list[dict]:
            terms = [t for c in await self.table("circuit") for t in c.get("terminations") or []]
            return await self.visible("circuit_termination", terms)

        return await self._once("terminations", load)

    async def power_feed_cables(self) -> dict[int, dict]:
        """Power feed id -> its readable cable (a feed has no host)."""

        async def load() -> dict[int, dict]:
            out: dict[int, dict] = {}
            for cable in await self.cables({"endpoint_type": "power_feed"}):
                for side in ("a", "b"):
                    if cable.get(f"{side}_type") == "power_feed" and cable.get(f"{side}_id") is not None:
                        out[int(cable[f"{side}_id"])] = cable
            return out

        return await self._once("power_feed_cables", load)

    async def dcim_records(self, kind: str, filters: dict[str, Any], q: str = "") -> list[dict]:
        """A root list of DCIM records of ``kind`` (``db.list_dcim_records``
        filters), within the caller's scope."""
        return await self.visible(kind, await db.list_dcim_records(kind, filters, q))

    async def cables(self, filters: dict[str, Any]) -> list[dict]:
        return await self.visible("cable", await db.list_cables(filters))

    async def cable(self, cable_id: int) -> dict | None:
        row = await db.get_cable(int(cable_id))
        found = await self.visible("cable", [row]) if row else []
        return found[0] if found else None

    # ── Batched loaders ──────────────────────────────────────────────────────

    async def _load_interfaces(self, host_ids: list[int]) -> list[list[dict]]:
        found = await db.get_interface_inventory_for_hosts(list(host_ids))
        return [found.get(h, []) for h in host_ids]

    async def _load_addresses(self, host_ids: list[int]) -> list[list[dict]]:
        found = await db.get_interface_addresses_for_hosts(host_ids)
        return [found.get(h, []) for h in host_ids]

    async def _load_host_vlans(self, host_ids: list[int]) -> list[list[dict]]:
        found = await db.get_host_vlans_for_hosts(host_ids)
        return [found.get(h, []) for h in host_ids]

    async def _load_allocations(self, keys: list[tuple[int, str]]) -> list[list[dict]]:
        rows = await db.list_ipam_allocation_records(prefix_subnets=[subnet for _, subnet in keys])
        rows = await self.visible("ip_address", rows)
        grouped: dict[tuple[int, str], list[dict]] = {}
        for row in rows:
            grouped.setdefault((int(row["source_id"]), str(row["prefix_subnet"])), []).append(row)
        return [grouped.get(key, []) for key in keys]

    def _custom_loader(self, object_type: str) -> Callable[[list[dict]], Awaitable[list[dict]]]:
        """Tags, custom field and computed field values of rows of
        ``object_type`` (``object_custom_data_bulk``, no relationships)."""

        async def load(rows: list[dict]) -> list[dict]:
            data = await object_custom_data_bulk(
                object_type, list(rows), relationships=False, features=self.features, access=self.scope
            )
            empty: dict[str, Any] = {"tags": [], "custom_fields": {}, "computed_fields": {}}
            return [data.get(_row_key(row), empty) for row in rows]

        return load

    def _host_records_loader(self, kind: str) -> Callable[[list[int]], Awaitable[list[list[dict]]]]:
        async def load(host_ids: list[int]) -> list[list[dict]]:
            grouped: dict[int, list[dict]] = {}
            for row in await db.list_dcim_records(kind, host_ids=host_ids):
                grouped.setdefault(int(row["host_id"]), []).append(row)
            return [grouped.get(h, []) for h in host_ids]

        return load

    async def _load_host_cables(self, host_ids: list[int]) -> list[list[dict]]:
        rows = await self.visible("cable", await db.list_cables(host_ids=host_ids))
        grouped: dict[int, list[dict]] = {}
        for row in rows:
            for end in {row.get("a_host_id"), row.get("b_host_id")}:
                if end is not None:
                    grouped.setdefault(int(end), []).append(row)
        return [grouped.get(h, []) for h in host_ids]

    async def _load_vm_interfaces(self, vm_ids: list[int]) -> list[list[dict]]:
        found = await db.list_vm_interfaces_by_vm_ids(vm_ids)
        return [found.get(v, []) for v in vm_ids]
