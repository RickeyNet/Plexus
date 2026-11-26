"""Object-level permissions: which inventory groups (and, through them,
which hosts, tenants and sites) a user may see and change.

An access group either covers every object (``object_scope='all'``, the
default) or only the inventory groups it grants (``object_scope='groups'``),
each read only or read and write; a grant covers the group and all of its
sub-groups. A user is **unrestricted** when they are an admin, call with the
server API token, or belong to any access group whose scope is ``all``;
otherwise they are **scoped** to the union of their groups' grants (no
grants: they see nothing).

Every feature is enrolled: a scoped user keeps the whole application,
filtered. Records reach the scope through the **model registry**
(``MODELS``): a model names the fields of its rows that place it
(``group`` an inventory group id, ``host`` a host id, ``tenant`` a tenant
id, ``site`` a site id). A scoped caller

- reads a row when any of its keys is readable: its inventory group or host
  is in a granted group, its tenant is the tenant of such a host, its site
  holds such a host (by rack or floor plan placement), or a **scope rule**
  of the caller's access groups grants that tenant or site for the model
  (or for every model, ``*``);
- changes a row when any of its keys is writable: a writable group or host,
  the tenant of a host in a writable group, or a writable scope rule. A site
  reached only through a host is read only (a site is often shared); write
  on a site takes a scope rule;
- of a **shared** model (reference data such as providers, circuit types,
  rack roles or a template catalogue) reads the rows with no key, and never
  changes them: only unrestricted callers change shared rows.

A module enforces scope by checking every route of its routers
(``require_group``/``require_host``/``require_hosts``, the row helpers
``require_row``/``require_new_row``/``filter_rows`` and ``group_filter``),
marking each route ``@scoped(kind)`` or ``@scope_exempt(reason)``, and
listing its routers in ``SCOPE_ENFORCED_ROUTERS``. A feature whose module
has not done so is kept from scoped users:
``netcontrol.routes.auth._get_user_features`` keeps only the keys in
``SCOPE_ENFORCED_FEATURES`` for a scoped user, so every other feature gate
answers 403 (plugins and new features stay fail closed until enrolled), and
MCP tokens owned by a scoped user are refused.

Responses: an object outside the caller's read scope answers 404 with the
body an unknown id gets (no existence leak); a write to one that is
readable but not writable answers 403 ``READ_ONLY_DETAIL``; a create or a
move to keys the caller cannot write answers 403 ``WRITE_SCOPE_DETAIL``. A
row whose group id is NULL is visible to unrestricted users only.

Other consumers (GraphQL, ChatOps, MCP) use the same rules through
``filter_rows(model, rows, scope)``, ``can_access(scope, model, row)`` and
``sql_condition(model, scope)`` with a scope from ``scope_for_user``.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import routes.database as db
import routes.db.object_scope as scope_db
from fastapi import HTTPException
from starlette.requests import HTTPConnection

from netcontrol.routes.shared import _get_session

# Feature keys a scoped user keeps: every gateable feature of the catalog
# (``netcontrol.routes.state``). Enrolling a module: enforce scope in all of
# its routes, add its feature key (and ``<key>.write`` when the catalog has
# one) here and its routers to ``SCOPE_ENFORCED_ROUTERS``. A feature that is
# not listed (a plugin's, or a new one) stays hidden from scoped users.
_ENFORCED_READ = (
    "dashboard",
    "inventory",
    "ipam",
    "dcim",
    "sync",
    "circuits",
    "routing",
    "virtualization",
    "playbooks",
    "jobs",
    "templates",
    "credentials",
    "topology",
    "cloud-visibility",
    "monitoring",
    "config-drift",
    "config-backups",
    "compliance",
    "risk-analysis",
    "reports",
    "graph-templates",
    "mac-tracking",
    "software",
    "lifecycle",
    "traffic-analysis",
    "upgrades",
    "deployments",
    "federation",
    "floor-plan",
    "lab",
    "organization",
    # GraphQL resolvers filter every type by the caller's scope.
    "graphql",
    # ChatOps commands run as the mapped user, within that user's scope.
    "chatops",
    "secrets-providers",
)
# Read-only catalog keys (no ``.write``): dashboard, mac-tracking,
# traffic-analysis, organization, graphql, chatops, secrets-providers.
_NO_WRITE = frozenset(
    {
        "dashboard",
        "mac-tracking",
        "traffic-analysis",
        "organization",
        "graphql",
        "chatops",
        "secrets-providers",
    }
)
# Further per-feature permissions whose routes enforce the scope too
# (jobs.approve: the approvals list and decisions check every job target).
_ENFORCED_EXTRA = ("jobs.approve",)
SCOPE_ENFORCED_FEATURES: frozenset[str] = frozenset(
    list(_ENFORCED_READ) + [f"{k}.write" for k in _ENFORCED_READ if k not in _NO_WRITE] + list(_ENFORCED_EXTRA)
)

# Every router registered under a feature in SCOPE_ENFORCED_FEATURES, as
# ``"module:attribute"``, plus the WebSocket routers (registered without HTTP
# dependencies; their handlers check the feature and the scope themselves).
# The completeness test (tests/test_object_scope_api.py) requires each of
# their HTTP and WebSocket routes to carry ``@scoped`` or ``@scope_exempt``.
# Admin routers are not listed: admins are unrestricted.
SCOPE_ENFORCED_ROUTERS: tuple[str, ...] = (
    "netcontrol.routes.inventory:router",
    "netcontrol.routes.hardware_components:router",
    "netcontrol.routes.bulk_import:router",
    "netcontrol.routes.custom_fields:inventory_router",
    # Definitions, tags and the generic object API: open to every signed-in
    # user; it checks each type's feature and, for hosts and groups, the scope.
    "netcontrol.routes.custom_fields:router",
    "netcontrol.routes.device_model:inventory_router",
    "netcontrol.routes.dynamic_groups:router",
    "netcontrol.routes.ansible_inventory:router",
    "netcontrol.routes.config_backups:router",
    "netcontrol.routes.opnsense_rules:router",
    "netcontrol.routes.config_drift:router",
    "netcontrol.routes.config_drift:ws_router",
    "netcontrol.routes.intended_config:router",
    "netcontrol.routes.intended_config:read_router",
    "netcontrol.routes.credentials:router",
    "netcontrol.routes.graphql:router",
    # The change log is open to every signed-in user; it filters by feature
    # per object type and by the caller's inventory groups itself.
    "netcontrol.routes.object_changes:router",
    # Export templates: open to every signed-in user; a render checks the
    # object type's feature and loads through the type's scoped list.
    "netcontrol.routes.export_templates:router",
    # Monitoring and alerting.
    "netcontrol.routes.monitoring:router",
    "netcontrol.routes.syslog_rules:router",
    "netcontrol.routes.cato_egress_check:router",
    "netcontrol.routes.cato_shared_host_check:router",
    "netcontrol.routes.meraki_alerts:router",
    "netcontrol.routes.vendor_alerts:router",
    "netcontrol.routes.security_events:router",
    "netcontrol.routes.metrics_engine:router",
    "netcontrol.routes.baseline_alerting:router",
    "netcontrol.routes.interface_errors:router",
    "netcontrol.routes.reporting:oid_profiles_router",
    "netcontrol.routes.dashboards:router",
    # Jobs, change management and compliance.
    "netcontrol.routes.jobs:router",
    "netcontrol.routes.jobs:approvals_router",
    "netcontrol.routes.jobs:ws_router",
    "netcontrol.routes.playbooks:router",
    "netcontrol.routes.templates:router",
    "netcontrol.routes.deployments:router",
    "netcontrol.routes.deployments:ws_router",
    "netcontrol.routes.maintenance_windows:router",
    "netcontrol.routes.compliance:router",
    "netcontrol.routes.meraki_compliance:router",
    "netcontrol.routes.risk_analysis:router",
    "netcontrol.routes.upgrades:router",
    "netcontrol.routes.upgrades:ws_router",
    # Topology, tracking, software and lifecycle.
    "netcontrol.routes.topology:router",
    "netcontrol.routes.meraki_topology:router",
    "netcontrol.routes.tool_history:router",
    "netcontrol.routes.inventory_collection:router",
    "netcontrol.routes.mac_tracking:router",
    "netcontrol.routes.flow_collector:router",
    "netcontrol.routes.software:router",
    "netcontrol.routes.hardware_lifecycle:router",
    "netcontrol.routes.geolocation:router",
    "netcontrol.routes.cloud_visibility:router",
    # IPAM, organization, circuits, virtualization and routing.
    "netcontrol.routes.ipam:router",
    "netcontrol.routes.dhcp:router",
    "netcontrol.routes.network_objects:router",
    "netcontrol.routes.network_objects:host_router",
    "netcontrol.routes.ipam_model:router",
    "netcontrol.routes.custom_fields:ipam_router",
    "netcontrol.routes.bulk_import:ipam_router",
    "netcontrol.routes.organization:router",
    "netcontrol.routes.circuits:router",
    "netcontrol.routes.virtualization:router",
    "netcontrol.routes.routing:router",
    # DCIM, sync, reports and the rest.
    "netcontrol.routes.dcim:router",
    "netcontrol.routes.sync:router",
    "netcontrol.routes.secrets_providers:router",
    "netcontrol.routes.reporting:router",
    "netcontrol.routes.audit:router",
    "netcontrol.routes.graph_templates:router",
    "netcontrol.routes.cdef_engine:router",
    "netcontrol.routes.cdef_engine:read_router",
    "netcontrol.routes.graph_export:router",
    "netcontrol.routes.billing:router",
    "netcontrol.routes.federation:router",
    "netcontrol.routes.lab:router",
    "netcontrol.routes.lab_runtime:router",
    "netcontrol.routes.lab_topology:router",
    "netcontrol.routes.lab_drift:router",
)

READ_ONLY_DETAIL = "Read-only access to this inventory group"
GROUP_NOT_FOUND = "Group not found"
HOST_NOT_FOUND = "Host not found"
# Why an MCP token is refused (and the 403 for routes that refuse scoped users).
MCP_SCOPED_DETAIL = (
    "AI access is not available to accounts limited to selected inventory groups: "
    "the token's owner has object-level restrictions"
)
SCOPED_REFUSED_DETAIL = "Not available to accounts limited to selected inventory groups"


@dataclass(frozen=True)
class ObjectScope:
    """The inventory groups a caller may read and write (ids expanded with
    their sub-groups); ``unrestricted`` callers may read and write all."""

    unrestricted: bool
    read_groups: frozenset[int] = field(default_factory=frozenset)
    write_groups: frozenset[int] = field(default_factory=frozenset)
    # The scope rules of the caller's access groups (per model, by tenant or site).
    rules: tuple[ScopeRule, ...] = ()
    # What the granted groups reach (hosts, tenants, sites), loaded once on
    # first use by ``reach()``.
    _reach: dict = field(default_factory=dict, compare=False, hash=False, repr=False)

    @property
    def restricted(self) -> bool:
        return not self.unrestricted

    @property
    def read_only(self) -> bool:
        """A scoped caller who may change nothing (no writable grant or rule)."""
        return self.restricted and not self.write_groups and not any(r.can_write for r in self.rules)

    async def reach(self) -> ScopeReach:
        """The hosts, tenants and sites the granted inventory groups reach
        (read and write sets); empty for an unrestricted caller, who is never
        filtered. Loaded from the database once per scope object."""
        cached = self._reach.get("reach")
        if isinstance(cached, ScopeReach):
            return cached
        if self.unrestricted or not self.read_groups:
            reach = ScopeReach()
        else:
            read = await scope_db.get_group_scope_keys(self.read_groups)
            write = (
                await scope_db.get_group_scope_keys(self.write_groups)
                if self.write_groups
                else {"host_ids": frozenset(), "tenant_ids": frozenset()}
            )
            reach = ScopeReach(
                read_hosts=read["host_ids"],
                write_hosts=write["host_ids"],
                read_tenants=read["tenant_ids"],
                write_tenants=write["tenant_ids"],
                read_sites=read["site_ids"],
            )
        self._reach["reach"] = reach
        return reach

    async def keys(self, model: str, *, write: bool = False) -> dict[str, frozenset[int]]:
        """For a scoped caller: the ids each key attribute of ``model`` must
        hold for a row to be readable (``write``: writable), from the granted
        groups and the scope rules of ``model`` (and ``*``)."""
        spec = get_model(model)
        reach = await self.reach()
        if write:
            sets = {
                "group": self.write_groups,
                "host": reach.write_hosts,
                "tenant": reach.write_tenants,
                "site": frozenset(),
            }
        else:
            sets = {
                "group": self.read_groups,
                "host": reach.read_hosts,
                "tenant": reach.read_tenants,
                "site": reach.read_sites,
            }
        for rule in self.rules:
            if rule.model not in (spec.name, "*") or (write and not rule.can_write):
                continue
            sets[rule.attribute] = sets.get(rule.attribute, frozenset()) | {rule.value_id}
        return {attr: sets.get(attr, frozenset()) for attr in spec.keys}

    def can_read_group(self, group_id: int | None) -> bool:
        if self.unrestricted:
            return True
        return group_id is not None and int(group_id) in self.read_groups

    def can_write_group(self, group_id: int | None) -> bool:
        if self.unrestricted:
            return True
        return group_id is not None and int(group_id) in self.write_groups

    def filter_groups(self, groups: list[dict], key: str = "id") -> list[dict]:
        """The groups (rows with the group id under ``key``) the caller may read."""
        if self.unrestricted:
            return groups
        return [g for g in groups if self.can_read_group(g.get(key))]

    def filter_hosts(self, hosts: list[dict], key: str = "group_id") -> list[dict]:
        """The hosts (rows with their group id under ``key``) the caller may read."""
        if self.unrestricted:
            return hosts
        return [h for h in hosts if self.can_read_group(h.get(key))]

    def status(self) -> dict:
        """The ``object_scope`` of ``/api/auth/status`` and the login response:
        ``read_only`` tells the SPA to hide every write control."""
        return {
            "restricted": self.restricted,
            "write_group_ids": [] if self.unrestricted else sorted(self.write_groups),
            "read_only": self.read_only,
        }


@dataclass(frozen=True)
class ScopeRule:
    """A per-model grant of an access group: rows of ``model`` (``*``: every
    model) whose ``attribute`` (``tenant`` or ``site``) is ``value_id``."""

    model: str
    attribute: str
    value_id: int
    can_write: bool = False


@dataclass(frozen=True)
class ScopeReach:
    """What a scoped caller's inventory groups reach: their hosts, the
    tenants of those hosts and the sites they stand in (read only)."""

    read_hosts: frozenset[int] = frozenset()
    write_hosts: frozenset[int] = frozenset()
    read_tenants: frozenset[int] = frozenset()
    write_tenants: frozenset[int] = frozenset()
    read_sites: frozenset[int] = frozenset()


UNRESTRICTED = ObjectScope(unrestricted=True)
# A scoped caller with no grants: sees nothing.
NO_ACCESS = ObjectScope(unrestricted=False)


async def scope_for_user(user: dict | None, *, token: bool = False) -> ObjectScope:
    """The scope of ``user`` (a ``users`` row). ``token``: the caller used the
    server API token (unrestricted). No user: nothing is visible."""
    if token:
        return UNRESTRICTED
    if not user:
        return NO_ACCESS
    if user.get("role") == "admin":
        return UNRESTRICTED
    data = await db.get_user_object_scope(int(user["id"]))
    if data["unrestricted"]:
        return UNRESTRICTED
    rules = await scope_db.get_user_scope_rules(int(user["id"]))
    return ObjectScope(
        unrestricted=False,
        read_groups=frozenset(int(g) for g in data["read_group_ids"]),
        write_groups=frozenset(int(g) for g in data["write_group_ids"]),
        rules=tuple(
            ScopeRule(r["model"], r["attribute"], int(r["value_id"]), bool(r["can_write"]))
            for r in rules
            if r["model"] == "*" or r["model"] in MODELS
        ),
    )


async def _session_scope(session: dict, cached_user: Any = None) -> ObjectScope:
    if session.get("auth_mode") == "token":
        return UNRESTRICTED
    user_id = session.get("user_id")
    if user_id is None:
        return NO_ACCESS
    user = cached_user
    if not isinstance(user, dict) or int(user.get("id") or -1) != int(user_id):
        user = await db.get_user_by_id(int(user_id))
    return await scope_for_user(user)


async def request_scope(request: Any) -> ObjectScope:
    """The scope of the caller of an HTTP request, resolved once per request
    and cached on ``request.state`` (next to ``auth_session``/``auth_user``).

    The identity is the session ``require_auth`` resolved for this request
    (an API token is unrestricted). A real request with no session is
    refused everything. An object that is not a request (a route function
    called directly) and carries no session cookie counts as the API token,
    as ``shared.require_owner_or_admin`` does.
    """
    if not isinstance(request, HTTPConnection):
        session = _get_session(request) if hasattr(request, "cookies") else None
        return UNRESTRICTED if session is None else await _session_scope(session)
    cached = getattr(request.state, "object_scope", None)
    if isinstance(cached, ObjectScope):
        return cached
    session = getattr(request.state, "auth_session", None) or _get_session(request)
    if not session:
        scope = NO_ACCESS
    else:
        scope = await _session_scope(session, getattr(request.state, "auth_user", None))
    request.state.object_scope = scope
    return scope


async def ws_scope(session: dict) -> ObjectScope:
    """The scope of a WebSocket caller (``session`` from ``verify_ws_session``)."""
    if not session:
        return NO_ACCESS
    return await _session_scope(session)


def _check(scope: ObjectScope, group_id: int | None, *, write: bool, not_found: str) -> None:
    if not scope.can_read_group(group_id):
        raise HTTPException(status_code=404, detail=not_found)
    if write and not scope.can_write_group(group_id):
        raise HTTPException(status_code=403, detail=READ_ONLY_DETAIL)


async def require_group(request: Any, group_id: int, *, write: bool = False, not_found: str = GROUP_NOT_FOUND) -> dict:
    """The inventory group row; 404 ``not_found`` when unknown or outside the
    caller's read scope, 403 on ``write`` when it is not writable. A route
    whose unknown group answers another message passes it as ``not_found``."""
    group = await db.get_group(int(group_id))
    if not group:
        raise HTTPException(status_code=404, detail=not_found)
    _check(await request_scope(request), group["id"], write=write, not_found=not_found)
    return group


async def require_host(request: Any, host_id: int, *, write: bool = False, not_found: str = HOST_NOT_FOUND) -> dict:
    """The host row; 404 ``not_found`` when unknown or outside the caller's
    read scope, 403 on ``write`` when its group is not writable."""
    host = await db.get_host(int(host_id))
    if not host:
        raise HTTPException(status_code=404, detail=not_found)
    _check(await request_scope(request), host.get("group_id"), write=write, not_found=not_found)
    return host


async def require_hosts(
    request: Any, host_ids: Iterable[int], *, write: bool = False, not_found: str = HOST_NOT_FOUND
) -> list[dict]:
    """The host rows of ``host_ids`` (duplicates removed). For an
    unrestricted caller unknown ids are skipped; for a scoped caller every
    id must be readable (else 404 ``not_found``, naming none) and, on
    ``write``, writable (else 403)."""
    ids = list(dict.fromkeys(int(h) for h in host_ids))
    hosts = await db.get_hosts_by_ids(ids)
    scope = await request_scope(request)
    if scope.unrestricted:
        return hosts
    if len(hosts) != len(ids):
        raise HTTPException(status_code=404, detail=not_found)
    for host in hosts:
        _check(scope, host.get("group_id"), write=write, not_found=not_found)
    return hosts


async def require_object_host(request: Any, host_id: int | None, *, not_found: str, write: bool = False) -> None:
    """For a record addressed by its own id (a backup, a baseline, a
    snapshot, a drift event) that belongs to host ``host_id``: 404
    ``not_found`` (the answer an unknown record id gets) when the host is
    unknown, ``None`` or outside the caller's read scope; 403 on ``write``
    when its group is not writable. Nothing is read for an unrestricted
    caller."""
    scope = await request_scope(request)
    if scope.unrestricted:
        return
    host = await db.get_host(int(host_id)) if host_id is not None else None
    _check(scope, host.get("group_id") if host else None, write=write, not_found=not_found)


async def group_filter(request: Any, *, write: bool = False) -> dict[str, frozenset[int]]:
    """Keyword arguments for the ``routes.db`` readers that take
    ``group_ids`` (keep only rows of hosts in those inventory groups): ``{}``
    for an unrestricted caller, so the reader runs exactly as before; else
    ``{"group_ids": <the readable (on ``write``: writable) groups>}``."""
    scope = await request_scope(request)
    if scope.unrestricted:
        return {}
    return {"group_ids": scope.write_groups if write else scope.read_groups}


async def refuse_scoped(request: Any) -> None:
    """403 for a scoped caller: for actions that cannot be confined to the
    caller's inventory groups."""
    if (await request_scope(request)).restricted:
        raise HTTPException(status_code=403, detail=SCOPED_REFUSED_DETAIL)


# ── Model registry ────────────────────────────────────────────────────────────

# The key attributes a model row can carry.
KEY_ATTRIBUTES: tuple[str, ...] = ("group", "host", "tenant", "site")


@dataclass(frozen=True)
class ScopeModel:
    """How rows of one kind of record reach the object scope.

    ``keys`` maps a key attribute (``group``, ``host``, ``tenant``,
    ``site``) to the row field holding it: an id, ``None``, or a list of
    ids (any of them counts, e.g. the sites of a circuit's terminations).
    A row is readable (writable) when any key is. ``shared``: a row with no
    key at all is reference data every scoped caller reads but only
    unrestricted callers change; otherwise such a row is for unrestricted
    callers only. ``not_found`` is the 404 detail of an unknown id."""

    name: str
    keys: dict[str, str]
    shared: bool = False
    not_found: str = "Not found"
    description: str = ""

    def __post_init__(self) -> None:
        unknown = set(self.keys) - set(KEY_ATTRIBUTES)
        if unknown:
            raise ValueError(f"unknown scope key attributes {sorted(unknown)} for {self.name}")

    def row_keys(self, row: dict) -> dict[str, list[int]]:
        """The key ids a row carries, by attribute (attributes without ids left out)."""
        out: dict[str, list[int]] = {}
        for attr, fld in self.keys.items():
            value = row.get(fld)
            if value is None or value == "":
                continue
            values = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
            ids = []
            for v in values:
                try:
                    ids.append(int(v))
                except TypeError, ValueError:
                    continue
            if ids:
                out[attr] = ids
        return out


MODELS: dict[str, ScopeModel] = {}


def register_model(model: ScopeModel) -> ScopeModel:
    """Add (or replace) a model of the registry; returns it."""
    MODELS[model.name] = model
    return model


def get_model(name: str) -> ScopeModel:
    """The registered model ``name`` (``KeyError`` when unknown)."""
    try:
        return MODELS[name]
    except KeyError:
        raise KeyError(f"object scope model {name!r} is not registered") from None


def _models(*specs: ScopeModel) -> None:
    for spec in specs:
        register_model(spec)


_HOST = {"host": "host_id"}
_TENANT_SITE = {"tenant": "tenant_id", "site": "site_id"}

_models(
    # Inventory.
    ScopeModel("inventory_group", {"group": "id"}, not_found=GROUP_NOT_FOUND, description="Inventory groups"),
    ScopeModel("host", {"group": "group_id"}, not_found=HOST_NOT_FOUND, description="Inventory hosts"),
    # Any record of one host (monitoring polls and alerts, compliance results,
    # software and lifecycle rows, MAC/ARP entries, config records ...).
    ScopeModel("host_record", dict(_HOST), description="Records that belong to one host"),
    # Records that name several hosts (a job, a deployment, a topology link):
    # the row lists them under ``host_ids``; readable when any host is.
    ScopeModel("host_set", {"host": "host_ids"}, description="Records that name several hosts"),
    # Organization.
    ScopeModel("region", {}, shared=True, not_found="Region not found", description="Regions"),
    ScopeModel("tenant_group", {}, shared=True, not_found="Tenant group not found", description="Tenant groups"),
    ScopeModel("tenant", {"tenant": "id"}, not_found="Tenant not found", description="Tenants"),
    ScopeModel("site", {"site": "id", "tenant": "tenant_id"}, not_found="Site not found", description="Sites"),
    ScopeModel("floor", {"site": "site_id"}, not_found="Floor not found", description="Floor plans"),
    # IPAM.
    ScopeModel("ipam_source", {}, shared=True, not_found="IPAM source not found", description="IPAM sources"),
    ScopeModel("ipam_prefix", {"tenant": "tenant_id"}, not_found="Prefix not found", description="IPAM prefixes"),
    ScopeModel(
        "ipam_allocation",
        {"tenant": "tenant_id"},
        not_found="Allocation not found",
        description="IPAM IP addresses (allocations)",
    ),
    ScopeModel("vrf", {"tenant": "tenant_id"}, shared=True, not_found="VRF not found", description="VRFs"),
    ScopeModel("vlan", dict(_TENANT_SITE), shared=True, not_found="VLAN not found", description="VLANs"),
    # Migration 0110: namespaces and RIRs are reference data; a route target
    # and an aggregate belong to their tenant; a VLAN group to the sites of
    # its scope (``scope_site_ids``: its site, or its region's sites). Rows
    # with no key are shared, like VRFs and VLANs.
    ScopeModel("namespace", {}, shared=True, not_found="Namespace not found", description="IPAM namespaces"),
    ScopeModel("rir", {}, shared=True, not_found="RIR not found", description="RIRs"),
    ScopeModel(
        "route_target",
        {"tenant": "tenant_id"},
        shared=True,
        not_found="Route target not found",
        description="Route targets",
    ),
    ScopeModel(
        "aggregate", {"tenant": "tenant_id"}, shared=True, not_found="Aggregate not found", description="Aggregates"
    ),
    ScopeModel(
        "vlan_group",
        {"site": "scope_site_ids"},
        shared=True,
        not_found="VLAN group not found",
        description="VLAN groups (by their site, or the sites of their region)",
    ),
    ScopeModel(
        "interface_address",
        dict(_HOST),
        not_found="Interface address not found",
        description="Interface addresses of hosts",
    ),
    # Circuits.
    ScopeModel("circuit_provider", {}, shared=True, not_found="Provider not found", description="Circuit providers"),
    ScopeModel(
        "provider_network", {}, shared=True, not_found="Provider network not found", description="Provider networks"
    ),
    ScopeModel("circuit_type", {}, shared=True, not_found="Circuit type not found", description="Circuit types"),
    ScopeModel(
        "circuit",
        {"tenant": "tenant_id", "site": "scope_site_ids", "host": "scope_host_ids"},
        not_found="Circuit not found",
        description="Circuits (by tenant, or the sites and hosts of their terminations)",
    ),
    ScopeModel(
        "circuit_termination",
        {"site": "site_id", "host": "host_id", "tenant": "circuit_tenant_id"},
        not_found="Termination not found",
        description="Circuit terminations",
    ),
    # Virtualization.
    ScopeModel("cluster_type", {}, shared=True, not_found="Cluster type not found", description="Cluster types"),
    ScopeModel("cluster_group", {}, shared=True, not_found="Cluster group not found", description="Cluster groups"),
    ScopeModel(
        "cluster",
        {"tenant": "tenant_id", "site": "site_id", "host": "scope_host_ids"},
        not_found="Cluster not found",
        description="Clusters (by tenant, site or member hosts)",
    ),
    ScopeModel(
        "virtual_machine",
        {"tenant": "tenant_id", "site": "cluster_site_id", "host": "scope_host_ids"},
        not_found="Virtual machine not found",
        description="Virtual machines (by tenant, or their cluster's site and hosts)",
    ),
    # Routing.
    ScopeModel(
        "autonomous_system",
        {"tenant": "tenant_id"},
        shared=True,
        not_found="Autonomous system not found",
        description="Autonomous systems",
    ),
    ScopeModel(
        "routing_instance", dict(_HOST), not_found="Routing instance not found", description="Routing instances"
    ),
    # DCIM.
    ScopeModel("rack_role", {}, shared=True, not_found="Rack role not found", description="Rack roles"),
    ScopeModel("rack", dict(_TENANT_SITE), not_found="Rack not found", description="Racks"),
    ScopeModel(
        "rack_reservation",
        {"tenant": "tenant_id", "site": "site_id"},
        not_found="Reservation not found",
        description="Rack reservations (by tenant or the rack's site)",
    ),
    ScopeModel("power_panel", {"site": "site_id"}, not_found="Power panel not found", description="Power panels"),
    ScopeModel(
        "power_feed",
        {"tenant": "tenant_id", "site": "site_id"},
        not_found="Power feed not found",
        description="Power feeds (by tenant or the panel's site)",
    ),
    ScopeModel(
        "cable",
        {"tenant": "tenant_id", "host": "scope_host_ids", "site": "scope_site_ids"},
        not_found="Cable not found",
        description="Cables (by tenant, or the hosts and sites of their ends)",
    ),
    # Catalogues with no host, tenant or site: read by every scoped caller,
    # changed by unrestricted callers only.
    ScopeModel("catalog", {}, shared=True, description="Shared catalogue records"),
)


def _resolve_scope(scope_or_request: Any) -> ObjectScope | None:
    return scope_or_request if isinstance(scope_or_request, ObjectScope) else None


async def _scope_of(scope_or_request: Any) -> ObjectScope:
    scope = _resolve_scope(scope_or_request)
    return scope if scope is not None else await request_scope(scope_or_request)


async def can_access(scope_or_request: Any, model: str, row: dict | None, *, write: bool = False) -> bool:
    """Whether the caller may read (``write``: change) ``row`` of ``model``."""
    spec = get_model(model)
    if row is None:
        return False
    scope = await _scope_of(scope_or_request)
    if scope.unrestricted:
        return True
    keys = spec.row_keys(row)
    if not keys:
        return spec.shared and not write
    allowed = await scope.keys(model, write=write)
    return any(i in allowed.get(attr, frozenset()) for attr, ids in keys.items() for i in ids)


async def filter_rows(model: str, rows: Iterable[dict], scope_or_request: Any, *, write: bool = False) -> list[dict]:
    """The ``rows`` of ``model`` the caller may read (``write``: change), in
    order. An unrestricted caller gets every row (as a list)."""
    spec = get_model(model)
    scope = await _scope_of(scope_or_request)
    rows = list(rows)
    if scope.unrestricted:
        return rows
    allowed = await scope.keys(model, write=write)
    out = []
    for row in rows:
        keys = spec.row_keys(row)
        if not keys:
            if spec.shared and not write:
                out.append(row)
            continue
        if any(i in allowed.get(attr, frozenset()) for attr, ids in keys.items() for i in ids):
            out.append(row)
    return out


async def require_row(
    scope_or_request: Any, model: str, row: dict | None, *, write: bool = False, not_found: str | None = None
) -> dict:
    """``row`` of ``model`` when the caller may read it (on ``write``: change
    it). 404 ``not_found`` (default: the model's) when ``row`` is ``None`` or
    unreadable; 403 ``READ_ONLY_DETAIL`` when readable but not writable."""
    detail = not_found or get_model(model).not_found
    if row is None or not await can_access(scope_or_request, model, row):
        raise HTTPException(status_code=404, detail=detail)
    if write and not await can_access(scope_or_request, model, row, write=True):
        raise HTTPException(status_code=403, detail=READ_ONLY_DETAIL)
    return row


WRITE_SCOPE_DETAIL = "Not writable within your object scope"


async def require_new_row(scope_or_request: Any, model: str, values: dict) -> None:
    """For a create, or an update that changes the keys of a row: 403
    ``WRITE_SCOPE_DETAIL`` unless the caller may change a row of ``model``
    holding ``values`` (the new row, or the new key fields). A scoped caller
    cannot create a row with no key (it would be visible to no one but
    unrestricted callers, or shared)."""
    if not await can_access(scope_or_request, model, values, write=True):
        raise HTTPException(status_code=403, detail=WRITE_SCOPE_DETAIL)


async def require_model_write(scope_or_request: Any) -> None:
    """403 ``WRITE_SCOPE_DETAIL`` for a scoped caller: writes to shared
    reference data (catalogues) are for unrestricted callers only."""
    if (await _scope_of(scope_or_request)).restricted:
        raise HTTPException(status_code=403, detail=WRITE_SCOPE_DETAIL)


async def readable_host_ids(scope_or_request: Any, *, write: bool = False) -> frozenset[int] | None:
    """The host ids the caller may read (``write``: change); ``None`` for an
    unrestricted caller (no filter)."""
    scope = await _scope_of(scope_or_request)
    if scope.unrestricted:
        return None
    reach = await scope.reach()
    return reach.write_hosts if write else reach.read_hosts


async def require_host_ids(
    scope_or_request: Any, host_ids: Iterable[Any], *, write: bool = False, not_found: str = HOST_NOT_FOUND
) -> None:
    """For a scoped caller: 404 ``not_found`` unless every host id (``None``
    and blanks skipped) is readable, and 403 on ``write`` unless writable."""
    scope = await _scope_of(scope_or_request)
    if scope.unrestricted:
        return
    ids = {int(h) for h in host_ids if h is not None and h != ""}
    reach = await scope.reach()
    if not ids <= reach.read_hosts:
        raise HTTPException(status_code=404, detail=not_found)
    if write and not ids <= reach.write_hosts:
        raise HTTPException(status_code=403, detail=READ_ONLY_DETAIL)


async def sql_condition(
    model: str, scope_or_request: Any, *, alias: str = "", write: bool = False
) -> tuple[str, tuple[int, ...]]:
    """A SQL condition (``?`` placeholders) keeping the rows of ``model`` the
    caller may read (``write``: change), for a query whose row columns are
    named like the model's key fields (``alias.`` prefixed when given; list
    fields such as ``scope_host_ids`` are not columns and are skipped).
    ``("", ())`` for an unrestricted caller; ``("1 = 0", ())`` when nothing
    matches. Shared models also keep rows with every key NULL."""
    spec = get_model(model)
    scope = await _scope_of(scope_or_request)
    if scope.unrestricted:
        return "", ()
    prefix = f"{alias}." if alias else ""
    allowed = await scope.keys(model, write=write)
    parts: list[str] = []
    params: list[int] = []
    columns = [(attr, fld) for attr, fld in spec.keys.items() if fld.isidentifier() and not fld.startswith("scope_")]
    for attr, fld in columns:
        ids = sorted(allowed.get(attr, frozenset()))
        if ids:
            parts.append(f"{prefix}{fld} IN ({','.join('?' * len(ids))})")
            params.extend(ids)
    if spec.shared and not write:
        parts.append("(" + " AND ".join(f"{prefix}{fld} IS NULL" for _, fld in columns) + ")" if columns else "1 = 1")
    if not parts:
        return "1 = 0", ()
    return "(" + " OR ".join(parts) + ")", tuple(params)


def model_catalog() -> list[dict]:
    """The registry as data (for the admin scope rule editor and the docs)."""
    return [
        {
            "name": m.name,
            "keys": sorted(m.keys),
            "shared": m.shared,
            "description": m.description,
            "rule_attributes": [a for a in ("tenant", "site") if a in m.keys],
        }
        for m in sorted(MODELS.values(), key=lambda m: m.name)
    ]


# ── Route markers ─────────────────────────────────────────────────────────────

_MARKER = "__plexus_object_scope__"
_F = TypeVar("_F", bound=Callable[..., Any])


def scoped(kind: str) -> Callable[[_F], _F]:
    """Mark a route as checking object scope. ``kind`` names how (``group``,
    ``host``, ``hosts``, ``list``, ``create``, ``refused`` ...); the GET
    sweep test drives every scoped GET route with a ``group_id`` or
    ``host_id`` path parameter with an out-of-scope id."""
    if not kind:
        raise ValueError("scoped() needs a kind")

    def mark(fn: _F) -> _F:
        setattr(fn, _MARKER, ("scoped", kind))
        return fn

    return mark


def scope_exempt(reason: str) -> Callable[[_F], _F]:
    """Mark a route as returning and changing no host or inventory group data."""
    if not reason or not reason.strip():
        raise ValueError("scope_exempt() needs a reason")

    def mark(fn: _F) -> _F:
        setattr(fn, _MARKER, ("exempt", reason))
        return fn

    return mark


def scope_marker(endpoint: Callable[..., Any]) -> tuple[str, str] | None:
    """``("scoped", kind)``, ``("exempt", reason)`` or None for an unmarked route."""
    marker = getattr(endpoint, _MARKER, None)
    return marker if isinstance(marker, tuple) else None


def enforced_routers() -> list[Any]:
    """The router objects named in ``SCOPE_ENFORCED_ROUTERS``."""
    routers = []
    for ref in SCOPE_ENFORCED_ROUTERS:
        module_name, attr = ref.split(":", 1)
        routers.append(getattr(importlib.import_module(module_name), attr))
    return routers


# The features whose GraphQL fields filter by the caller's scope: the
# inventory types and their configuration backups and interface data (read
# through readable hosts only), and the models ``GraphQLContext.visible``
# filters with ``filter_rows`` (IPAM, organization, circuits, DCIM,
# virtualization, routing, hardware lifecycle). For a scoped caller the
# GraphQL context keeps only these, so a field whose REST counterpart is
# enrolled but whose resolver does not filter yet answers "Access denied"
# instead of returning every row. Extend it as resolvers adopt
# ``filter_rows``/``sql_condition``.
GRAPHQL_SCOPED_FEATURES: frozenset[str] = frozenset(
    {
        "graphql",
        "inventory",
        "config-backups",
        "reports",
        "ipam",
        "organization",
        "circuits",
        "dcim",
        "virtualization",
        "routing",
        "lifecycle",
    }
)


def graphql_features(features: frozenset[str] | None, scope: ObjectScope) -> frozenset[str] | None:
    """The feature set of a GraphQL context: unchanged for an unrestricted
    caller (``None``: every feature), else only ``GRAPHQL_SCOPED_FEATURES``."""
    if scope.unrestricted:
        return features
    return frozenset(features or ()) & GRAPHQL_SCOPED_FEATURES


def enforced_features(features: Iterable[str]) -> list[str]:
    """``features`` without the keys a scoped user may not use (order kept)."""
    return [f for f in features if f in SCOPE_ENFORCED_FEATURES]
