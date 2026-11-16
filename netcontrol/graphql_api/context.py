"""The per-request context of a GraphQL query: who is asking, what they may
see, and the batched readers every resolver goes through.

Access is decided as the REST API decides it:

* ``require(feature)``: the feature the matching REST route needs (``None``
  features: an admin or the server API token, who pass every check);
* ``scope``: the caller's object scope (``netcontrol.object_scope``); hosts
  and inventory groups outside it are never listed or reachable.

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

from netcontrol.object_scope import ObjectScope
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
        self.custom_data: dict[str, DataLoader[str, dict]] = {
            object_type: DataLoader(load_fn=self._custom_loader(object_type))
            for object_type in ("host", "group", "prefix")
        }

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

    # ── IPAM (unscoped: needs the ipam feature, which a scoped user lacks) ──

    async def vrfs(self) -> list[dict]:
        return await self._once("vrfs", db.list_vrfs)

    async def vrfs_by_name(self) -> dict[str, dict]:
        async def load() -> dict[str, dict]:
            return {v["name"]: v for v in await self.vrfs()}

        return await self._once("vrfs_by_name", load)

    async def vlans(self) -> list[dict]:
        return await self._once("vlans", db.list_vlans)

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
            for row in await db.list_ipam_prefix_records():
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
        return await db.list_ipam_allocation_records(address=address)

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
        grouped: dict[tuple[int, str], list[dict]] = {}
        for row in rows:
            grouped.setdefault((int(row["source_id"]), str(row["prefix_subnet"])), []).append(row)
        return [grouped.get(key, []) for key in keys]

    def _custom_loader(self, object_type: str) -> Callable[[list[str]], Awaitable[list[dict]]]:
        async def load(keys: list[str]) -> list[dict]:
            data = await db.get_object_data_bulk(object_type, list(keys))
            return [data.get(key, {"tags": [], "fields": {}}) for key in keys]

        return load
