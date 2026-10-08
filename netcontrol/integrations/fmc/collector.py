"""FMC collector - gathers every payload a Cisco FMC topology build needs.

``collect_fmc`` reads one FMC domain with an :class:`FmcClient` and returns
the *raw* API payloads. It does no interpretation - ``normalize.build_snapshot``
owns that - so a saved capture can be re-normalised without calling the FMC.

What is read (under ``/api/fmc_config/v1/domain/{uuid}`` unless noted):

  - ``/api/fmc_platform/v1/info/serverversion``  the FMC version
  - ``devices/devicerecords``                     every managed FTD (required)
  - ``devicehapairs/ftddevicehapairs`` (+ ``{id}/monitoredinterfaces``),
    ``deviceclusters/ftddevicecluster``          HA pairs and clusters
  - ``assignment/policyassignments``              which devices each policy targets
  - ``object/networks``, ``hosts``, ``ranges``, ``fqdns``, ``networkgroups``,
    ``securityzones``, ``interfacegroups``,
    ``protocolportobjects``, ``portobjectgroups``,
    ``icmpv4objects``                             the names routes, NAT, VPN and
                                                  policies refer to
  - ``policies/ravpns`` (+ connection profiles, address assignment and
    access interface settings), ``object/ipv4addresspools``
                                                  the remote access VPN side
  - per device on the map, every interface kind (physical, sub-interface,
    EtherChannel, redundant, VLAN, VTI, loopback, bridge group, inline set)
  - per device on the map, its routing: virtual routers, static routes,
    BGP, OSPF, EIGRP, ECMP zones, policy-based routes
  - ``policies/ftdnatpolicies`` (+ the rules of the ones in use)
  - ``policies/accesspolicies`` (+ the first rules of the ones in use),
    ``policies/prefilterpolicies`` (+ the first rules of the ones in use
    that are not the default prefilter policy)
  - ``policies/ftds2svpns`` (+ endpoints, IKE and IPsec settings),
    ``health/tunnelstatuses``                    site-to-site VPN
  - ``health/alerts``, ``deployment/deployabledevices``
  - ``health/ravpnsessions``                      connected remote access users
                                                  (FMC 7.3 and later)

Failure policy: the login and the device list are required; everything else
is best-effort and a failure is recorded in ``errors`` and surfaced in the
map's collection report. A resource an older FMC release does not serve (a
newer interface kind, virtual routers, EIGRP, health alerts...) answers 404
or 405: that is no failure, only a gap, so it is listed in ``unsupported``
instead. HA pairs are read once, through their primary: the secondary has
the same configuration.

Secrets: every payload goes through ``scrub_secrets`` and the FMC-specific
``_scrub``, so a pre-shared key returned by the IKE settings never reaches
the database.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.fmc.client import CONFIG_PATH, PLATFORM_PATH, FmcApiError, FmcClient
from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.fmc")

DEFAULT_OPTIONS: dict[str, Any] = {
    # The FMC API user. The password is the entry's write-only secret.
    "username": "",
    # Limit the build to devices whose name contains this text. Empty = all.
    "device_name_contains": "",
    # Draw every managed device; off = only those with a remote access VPN policy.
    "include_all_devices": True,
    # Every interface kind of each device on the map.
    "include_interfaces": True,
    # Virtual routers, static routes, BGP, OSPF, EIGRP, policy-based routes, ECMP zones.
    "include_routing": True,
    # Site-to-site VPN topologies, endpoints, IKE / IPsec settings, tunnel status.
    "include_s2s_vpn": True,
    # NAT policies and their rules.
    "include_nat": True,
    # Access control policies, their rules (capped) and prefilter policies.
    "include_access_policies": True,
    # Health alerts and devices with a pending deployment.
    "include_health": True,
    # Connected remote access users (FMC 7.3+ health API).
    "include_sessions": True,
    # Verify the FMC's TLS certificate.
    "verify_tls": True,
    # Attach data Plexus already collected over SNMP/SSH for inventory hosts
    # that match a device.
    "inventory_enrich": True,
}

_BOOL_OPTIONS = (
    "include_all_devices",
    "include_interfaces",
    "include_routing",
    "include_s2s_vpn",
    "include_nat",
    "include_access_policies",
    "include_health",
    "include_sessions",
    "verify_tls",
    "inventory_enrich",
)

# One page of access control rules per policy: a large policy holds
# thousands, which would cost minutes of the FMC's 120 requests a minute
# and bury the node details. The policy's real count is kept beside them.
MAX_ACCESS_RULES = 1000
MAX_NAT_RULES = 1000

ProgressCallback = Callable[[dict[str, Any]], None]

# Policy types FMC uses for remote access VPN (compared lower-case, no separators).
RA_VPN_POLICY_TYPES = ("ravpn",)
NAT_POLICY_TYPES = ("ftdnatpolicy",)
ACCESS_POLICY_TYPES = ("accesspolicy",)
PREFILTER_POLICY_TYPES = ("prefilterpolicy",)

# Interface resources of a device record and the ``type`` FMC gives their
# items (set when an item lacks one, so the normalizer can always tell the
# kind). Physical and sub-interfaces exist on every release; the others are
# newer, or model-specific, and a 404 for them is not an error.
INTERFACE_RESOURCES: tuple[tuple[str, str, bool], ...] = (
    ("physicalinterfaces", "PhysicalInterface", False),
    ("subinterfaces", "SubInterface", False),
    ("etherchannelinterfaces", "EtherChannelInterface", True),
    ("redundantinterfaces", "RedundantInterface", True),
    ("vlaninterfaces", "VlanInterface", True),
    ("virtualtunnelinterfaces", "VTIInterface", True),
    ("loopbackinterfaces", "LoopbackInterface", True),
    ("bridgegroupinterfaces", "BridgeGroupInterface", True),
    ("inlinesets", "InlineSet", True),
)

# Routing resources read per virtual router (or per device on an FMC
# without virtual routers) and where they land in ``routing[device]``.
_VR_ROUTING = (
    ("ipv4staticroutes", "static_v4"),
    ("ipv6staticroutes", "static_v6"),
    ("bgp", "bgp"),
    ("ospfv2routes", "ospf"),
    ("eigrproutes", "eigrp"),
)

OBJECT_RESOURCES = (
    ("networks", "networks"),
    ("hosts", "hosts"),
    ("ranges", "ranges"),
    ("fqdns", "fqdns"),
    ("networkgroups", "groups"),
    ("securityzones", "zones"),
    ("interfacegroups", "interface_groups"),
    ("protocolportobjects", "ports"),
    ("portobjectgroups", "port_groups"),
    ("icmpv4objects", "icmp"),
)

# The prefilter policy every FMC has; it holds no rules of its own.
DEFAULT_PREFILTER_NAME = "default prefilter policy"

# Keys that hold IKE pre-shared keys (``manualPreSharedKey``...), which the
# generic scrubber does not recognise.
_FMC_SECRET_FRAGMENTS = ("presharedkey", "sharedsecret", "sharedkey")

_MISSING = (404, 405)


def sanitize_options(raw: object) -> dict[str, Any]:
    """Coerce stored/user-supplied build options onto the known schema."""
    src = raw if isinstance(raw, dict) else {}
    opts = dict(DEFAULT_OPTIONS)
    for key in _BOOL_OPTIONS:
        if key in src:
            opts[key] = bool(src[key])
    opts["username"] = str(src.get("username") or "").strip()[:120]
    opts["device_name_contains"] = str(src.get("device_name_contains") or "").strip()[:200]
    return opts


def _kind(value: Any) -> str:
    """An FMC ``type`` compared loosely: lower-case, no separators."""
    return str(value or "").lower().replace("_", "").replace("-", "").replace(" ", "")


def is_ra_vpn_policy(policy: Any) -> bool:
    return _kind((policy or {}).get("type")) in RA_VPN_POLICY_TYPES


def is_policy_of(policy: Any, types: tuple[str, ...]) -> bool:
    return isinstance(policy, dict) and _kind(policy.get("type")) in types


def _scrub(value: Any) -> Any:
    """``scrub_secrets`` plus the FMC's own secret-bearing keys."""
    cleaned = scrub_secrets(value)

    def walk(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                k: walk(v)
                for k, v in item.items()
                if not any(fragment in str(k).lower() for fragment in _FMC_SECRET_FRAGMENTS)
            }
        if isinstance(item, list):
            return [walk(v) for v in item]
        return item

    return walk(cleaned)


def _error(scope: str, path: str, exc: FmcApiError) -> dict[str, Any]:
    message = f"{exc}: {exc.detail}" if exc.detail else str(exc)
    return {"scope": scope, "path": path, "status": exc.status_code, "message": message}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _items_or_self(body: Any) -> list[dict]:
    """A settings resource as a list: its ``items`` when it is a collection,
    the object itself otherwise."""
    if isinstance(body, dict) and "items" in body:
        return [i for i in body.get("items") or [] if isinstance(i, dict)]
    return [body] if isinstance(body, dict) and body else []


def _dicts(value: Any) -> list[dict]:
    return [i for i in value or [] if isinstance(i, dict)] if isinstance(value, list) else []


def _ref(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def ha_members(pair: dict) -> list[dict]:
    """The members of an HA pair record, primary first."""
    members = []
    for key in ("primary", "secondary"):
        ref = _ref(pair.get(key))
        if _text(ref.get("id")) or _text(ref.get("name")):
            members.append(ref)
    return members


def cluster_members(cluster: dict) -> list[dict]:
    """The units of a cluster record, control unit first. Reads both naming
    generations (``masterDevice``/``slaveDevices`` and
    ``controlDevice``/``dataDevices``); a unit's device is in
    ``deviceDetails``."""

    def device(entry: Any) -> dict:
        entry = _ref(entry)
        details = _ref(entry.get("deviceDetails"))
        return details or entry

    members: list[dict] = []
    control = cluster.get("controlDevice") or cluster.get("masterDevice")
    if control:
        members.append(device(control))
    for entry in cluster.get("dataDevices") or cluster.get("slaveDevices") or []:
        members.append(device(entry))
    return [m for m in members if _text(m.get("id")) or _text(m.get("name"))]


class TargetResolver:
    """Resolves a policy assignment target to member device ids.

    A target is a device, or an HA pair or cluster container (``type``
    ``DeviceHAPair`` / ``DeviceCluster``): a container stands for every one of
    its members. Targets are matched by id, then by name."""

    def __init__(self, devices: list[dict], ha_pairs: list[dict], clusters: list[dict]) -> None:
        self.ids = {_text(d.get("id")) for d in devices if d.get("id")}
        self.by_name = {_text(d.get("name")).lower(): _text(d["id"]) for d in devices if d.get("id")}
        self.containers: dict[str, list[str]] = {}
        self.container_names: dict[str, str] = {}
        for record, members in [(p, ha_members(p)) for p in ha_pairs] + [(c, cluster_members(c)) for c in clusters]:
            if not isinstance(record, dict):
                continue
            resolved = [self._device(m) for m in members]
            ids = [i for i in resolved if i]
            key = _text(record.get("id"))
            if key:
                self.containers[key] = ids
            if _text(record.get("name")):
                self.container_names[_text(record.get("name")).lower()] = key

    def _device(self, ref: dict) -> str:
        ident = _text(ref.get("id"))
        if ident in self.ids:
            return ident
        return self.by_name.get(_text(ref.get("name")).lower(), "")

    def resolve(self, target: Any) -> list[str]:
        if not isinstance(target, dict):
            return []
        ident = _text(target.get("id"))
        if ident in self.containers:
            return list(self.containers[ident])
        if ident in self.ids:
            return [ident]
        name = _text(target.get("name")).lower()
        if name in self.by_name:
            return [self.by_name[name]]
        if name in self.container_names:
            return list(self.containers.get(self.container_names[name], []))
        return []


def assigned_devices(
    assignments: list[dict], types: tuple[str, ...], resolver: TargetResolver, policies: list[dict] | None = None
) -> dict[str, list[str]]:
    """``policy id -> device ids`` for the policies of ``types``, from the
    assignments and from the ``targets`` a policy record may carry itself."""
    found: dict[str, list[str]] = {}

    def add(policy_id: str, target: Any) -> None:
        for device_id in resolver.resolve(target):
            members = found.setdefault(policy_id, [])
            if device_id not in members:
                members.append(device_id)

    for policy in policies or []:
        for target in policy.get("targets") or []:
            add(_text(policy.get("id")), target)
    for assignment in assignments:
        if not isinstance(assignment, dict) or not is_policy_of(assignment.get("policy"), types):
            continue
        policy_id = _text(_ref(assignment.get("policy")).get("id"))
        for target in assignment.get("targets") or []:
            add(policy_id, target)
    return found


async def collect_fmc(
    client: FmcClient,
    domain: str,
    options: dict[str, Any] | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Collect one FMC domain. Raises ``FmcApiError`` only if the login fails,
    the domain is unknown, or the device list cannot be read."""
    opts = sanitize_options(options)
    errors: list[dict[str, Any]] = []
    unsupported: list[str] = []
    # login, version, devices, HA pairs, clusters, assignments, the objects,
    # RA VPN policies and pools; per-policy and per-device calls are added
    # as they become known.
    total = 8 + len(OBJECT_RESOURCES) + int(opts["include_sessions"])
    total += int(opts["include_nat"]) + 2 * int(opts["include_access_policies"])
    total += 2 * int(opts["include_s2s_vpn"]) + 2 * int(opts["include_health"])
    done = 0

    def report(phase: str, **fields: Any) -> None:
        if progress is not None:
            progress({"phase": phase, "calls_done": done, "calls_total": total, **fields})

    base = ""  # the domain's configuration root, known after login

    def short(path: str) -> str:
        # Reported relative to the domain, which is what an operator reads.
        relative = path.removeprefix(base) if base else path
        return relative.removeprefix(CONFIG_PATH).removeprefix(PLATFORM_PATH)

    async def best_effort(path: str, scope: str, *, mode: str = "all", optional: bool = False, limit: int = 0) -> Any:
        """``mode`` "all": every item of a collection; "one": the decoded
        body; "page": the first page of ``limit`` items (the decoded body).
        ``optional``: a 404 / 405 means the release does not serve it."""
        nonlocal done
        try:
            if mode == "all":
                return await client.get_all(path)
            if mode == "page":
                return await client.get(path, {"expanded": "true", "limit": limit, "offset": 0})
            return await client.get(path)
        except FmcApiError as exc:
            if optional and exc.status_code in _MISSING:
                if short(path) not in unsupported:
                    unsupported.append(short(path))
            else:
                errors.append(_error(scope, short(path), exc))
            return None
        finally:
            done += 1

    report("fmc login")
    await client.login()
    resolved = client.resolve_domain(domain)
    base = f"{CONFIG_PATH}/domain/{resolved['uuid']}"
    done += 1

    version = ""
    info = await best_effort(f"{PLATFORM_PATH}/info/serverversion", "fmc")
    for item in info or []:
        version = _text(item.get("serverVersion")) or version

    report("fmc devices")
    devices = _scrub(await client.get_all(f"{base}/devices/devicerecords"))
    done += 1
    needle = opts["device_name_contains"].lower()
    devices = [
        d
        for d in devices
        if isinstance(d, dict) and d.get("id") and (not needle or needle in _text(d.get("name")).lower())
    ]
    report("fmc devices", devices=len(devices))

    report("fmc ha")
    ha_pairs = _dicts(_scrub(await best_effort(f"{base}/devicehapairs/ftddevicehapairs", "ha") or []))
    clusters = _dicts(_scrub(await best_effort(f"{base}/deviceclusters/ftddevicecluster", "clusters") or []))
    assignments = _dicts(_scrub(await best_effort(f"{base}/assignment/policyassignments", "policies") or []))
    resolver = TargetResolver(devices, ha_pairs, clusters)
    device_ids = {_text(d["id"]) for d in devices}
    ha_pairs_here = [p for p in ha_pairs if set(resolver.containers.get(_text(p.get("id")), [])) & device_ids]
    total += len(ha_pairs_here)
    ha_monitored: dict[str, list[dict]] = {}
    for pair in ha_pairs_here:
        pid = _text(pair.get("id"))
        report("fmc ha", ha_pairs=len(ha_pairs_here))
        found = await best_effort(
            f"{base}/devicehapairs/ftddevicehapairs/{pid}/monitoredinterfaces",
            f"HA pair {pair.get('name')}",
            optional=True,
        )
        if found is not None:
            ha_monitored[pid] = _dicts(_scrub(found))

    report("fmc objects")
    objects: dict[str, list[dict]] = {}
    for resource, key in OBJECT_RESOURCES:
        objects[key] = _dicts(_scrub(await best_effort(f"{base}/object/{resource}", "objects") or []))

    report("fmc vpn policies")
    policies = [
        p for p in _dicts(_scrub(await best_effort(f"{base}/policies/ravpns", "policies") or [])) if p.get("id")
    ]
    policies = [p for p in policies if is_ra_vpn_policy(p) or not p.get("type")]

    total += 3 * len(policies)
    policy_details: dict[str, dict[str, Any]] = {}
    for policy in policies:
        pid = _text(policy["id"])
        report("fmc vpn policies", networks=len(policies))
        detail_base = f"{base}/policies/ravpns/{pid}"
        scope = f"policy {policy.get('name')}"
        policy_details[pid] = _scrub(
            {
                "connection_profiles": await best_effort(f"{detail_base}/connectionprofiles", scope) or [],
                # Settings resources: one object on some releases, a one-item
                # collection on others.
                "address_assignment": _items_or_self(
                    await best_effort(f"{detail_base}/addressassignmentsettings", scope, mode="one")
                ),
                "access_interfaces": _items_or_self(
                    await best_effort(f"{detail_base}/accessinterfacesettings", scope, mode="one")
                ),
            }
        )

    report("fmc pools")
    pools = _dicts(_scrub(await best_effort(f"{base}/object/ipv4addresspools", "pools") or []))

    # Which devices a remote access VPN policy targets: without
    # ``include_all_devices`` only those are drawn (and read further).
    ra_targets = assigned_devices(assignments, RA_VPN_POLICY_TYPES, resolver, policies)
    mapping_known = bool(ra_targets) or any(
        isinstance(a, dict) and is_ra_vpn_policy(a.get("policy")) for a in assignments
    )
    headends = {device_id for ids in ra_targets.values() for device_id in ids}
    on_map = [d for d in devices if opts["include_all_devices"] or not mapping_known or _text(d["id"]) in headends]
    on_map_ids = [_text(d["id"]) for d in on_map]
    device_by_id = {_text(d["id"]): d for d in devices}

    # An HA pair is configured once, on its primary: read the primary and
    # reuse what it answers for the secondary.
    pair_of: dict[str, dict] = {}
    for pair in ha_pairs:
        for member in resolver.containers.get(_text(pair.get("id")), []):
            pair_of[member] = pair

    def config_owner(device_id: str) -> str:
        pair = pair_of.get(device_id)
        members = resolver.containers.get(_text(pair.get("id")), []) if pair else []
        return members[0] if members else device_id

    owners: list[str] = []
    for device_id in on_map_ids:
        owner = config_owner(device_id)
        if owner not in owners:
            owners.append(owner)

    def add_total(count: int) -> None:
        nonlocal total
        total += count

    def owner_name(device_id: str) -> str:
        return _text(device_by_id.get(device_id, {}).get("name")) or device_id

    interfaces: dict[str, list[dict]] = {}
    if opts["include_interfaces"]:
        total += len(INTERFACE_RESOURCES) * len(owners)
        for owner in owners:
            report("fmc interfaces", devices=len(on_map))
            found_ifaces = await _read_interfaces(best_effort, base, owner, f"device {owner_name(owner)}")
            container = pair_of.get(owner)
            if not found_ifaces and container is not None:
                # Some releases keep the configuration of a pair on the pair.
                total += len(INTERFACE_RESOURCES)
                found_ifaces = await _read_interfaces(
                    best_effort, base, _text(container.get("id")), f"HA pair {container.get('name')}", optional=True
                )
            interfaces[owner] = _scrub(found_ifaces)
        for device_id in on_map_ids:
            owner = config_owner(device_id)
            if device_id != owner and owner in interfaces:
                interfaces[device_id] = [dict(i) for i in interfaces[owner]]

    routing: dict[str, dict[str, list[dict]]] = {}
    if opts["include_routing"]:
        total += 2 * len(owners)
        for owner in owners:
            report("fmc routing", devices=len(on_map))
            routing[owner] = await _read_routing(best_effort, base, owner, f"device {owner_name(owner)}", add_total)
        for device_id in on_map_ids:
            owner = config_owner(device_id)
            if device_id != owner and owner in routing:
                routing[device_id] = routing[owner]

    nat_policies: list[dict] = []
    nat_rules: dict[str, list[dict]] = {}
    if opts["include_nat"]:
        report("fmc nat")
        nat_policies = [
            p for p in _dicts(_scrub(await best_effort(f"{base}/policies/ftdnatpolicies", "nat") or [])) if p.get("id")
        ]
        in_use = _policies_in_use(nat_policies, assignments, NAT_POLICY_TYPES, resolver, set(on_map_ids))
        total += len(in_use)
        for policy in in_use:
            report("fmc nat", policies=len(in_use))
            body = await best_effort(
                f"{base}/policies/ftdnatpolicies/{_text(policy['id'])}/natrules",
                f"NAT policy {policy.get('name')}",
                mode="page",
                limit=MAX_NAT_RULES,
            )
            if body is not None:
                nat_rules[_text(policy["id"])] = _dicts(_scrub(body.get("items")))[:MAX_NAT_RULES]

    access_policies: list[dict] = []
    access_rules: dict[str, list[dict]] = {}
    access_rule_counts: dict[str, int] = {}
    prefilter_policies: list[dict] = []
    prefilter_rules: dict[str, list[dict]] = {}
    prefilter_rule_counts: dict[str, int] = {}
    if opts["include_access_policies"]:
        report("fmc access policies")
        access_policies = [
            p
            for p in _dicts(_scrub(await best_effort(f"{base}/policies/accesspolicies", "access policies") or []))
            if p.get("id")
        ]
        prefilter_policies = _dicts(
            _scrub(await best_effort(f"{base}/policies/prefilterpolicies", "access policies", optional=True) or [])
        )
        in_use = _policies_in_use(access_policies, assignments, ACCESS_POLICY_TYPES, resolver, set(on_map_ids))
        # A device record names its access policy even when no assignment does.
        for device in on_map:
            ref = _ref(device.get("accessPolicy"))
            named = next((p for p in access_policies if _text(p["id"]) == _text(ref.get("id"))), None)
            if named is not None and named not in in_use:
                in_use.append(named)
        total += len(in_use)
        for policy in in_use:
            pid = _text(policy["id"])
            report("fmc access policies", policies=len(in_use))
            body = await best_effort(
                f"{base}/policies/accesspolicies/{pid}/accessrules",
                f"access policy {policy.get('name')}",
                mode="page",
                limit=MAX_ACCESS_RULES,
            )
            if body is None:
                continue
            rules = _dicts(body.get("items"))[:MAX_ACCESS_RULES]
            access_rules[pid] = _scrub(rules)
            try:
                access_rule_counts[pid] = int(_ref(body.get("paging")).get("count") or len(rules))
            except TypeError, ValueError:
                access_rule_counts[pid] = len(rules)
        # The prefilter policies in use: named by an access policy read
        # above, or assigned to a device on the map. The default one has no
        # rules to read.
        wanted: list[str] = []
        for policy in in_use:
            ref = _ref(policy.get("prefilterPolicySetting"))
            if _text(ref.get("id")):
                wanted.append(_text(ref["id"]))
        for pid, targets in assigned_devices(assignments, PREFILTER_POLICY_TYPES, resolver, prefilter_policies).items():
            if set(targets) & set(on_map_ids):
                wanted.append(pid)
        by_id = {_text(p.get("id")): p for p in prefilter_policies if p.get("id")}
        prefilters = [
            pid
            for pid in dict.fromkeys(wanted)
            if _text(by_id.get(pid, {}).get("name")).lower() != DEFAULT_PREFILTER_NAME
        ]
        total += len(prefilters)
        for pid in prefilters:
            report("fmc access policies", policies=len(in_use))
            body = await best_effort(
                f"{base}/policies/prefilterpolicies/{pid}/prefilterrules",
                f"prefilter policy {by_id.get(pid, {}).get('name') or pid}",
                mode="page",
                limit=MAX_ACCESS_RULES,
                optional=True,
            )
            if body is None:
                continue
            rules = _dicts(body.get("items"))[:MAX_ACCESS_RULES]
            prefilter_rules[pid] = _scrub(rules)
            try:
                prefilter_rule_counts[pid] = int(_ref(body.get("paging")).get("count") or len(rules))
            except TypeError, ValueError:
                prefilter_rule_counts[pid] = len(rules)

    s2s_vpns: list[dict] = []
    s2s_details: dict[str, dict[str, Any]] = {}
    tunnel_status: list[dict] | None = None
    if opts["include_s2s_vpn"]:
        report("fmc s2s vpn")
        s2s_vpns = [
            t
            for t in _dicts(_scrub(await best_effort(f"{base}/policies/ftds2svpns", "site-to-site VPN") or []))
            if t.get("id")
        ]
        total += 3 * len(s2s_vpns)
        for topology in s2s_vpns:
            tid = _text(topology["id"])
            report("fmc s2s vpn", topologies=len(s2s_vpns))
            scope = f"VPN topology {topology.get('name')}"
            detail_base = f"{base}/policies/ftds2svpns/{tid}"
            s2s_details[tid] = _scrub(
                {
                    "endpoints": await best_effort(f"{detail_base}/endpoints", scope) or [],
                    "ike": _items_or_self(await best_effort(f"{detail_base}/ikesettings", scope, mode="one")),
                    "ipsec": _items_or_self(await best_effort(f"{detail_base}/ipsecsettings", scope, mode="one")),
                }
            )
        found_status = await best_effort(f"{base}/health/tunnelstatuses", "site-to-site VPN", optional=True)
        if found_status is not None:
            tunnel_status = _dicts(_scrub(found_status))

    health_alerts: list[dict] | None = None
    deployable: list[dict] | None = None
    if opts["include_health"]:
        report("fmc health")
        found_alerts = await best_effort(f"{base}/health/alerts", "health", optional=True)
        if found_alerts is not None:
            health_alerts = _dicts(_scrub(found_alerts))
        found_deployable = await best_effort(f"{base}/deployment/deployabledevices", "health")
        if found_deployable is not None:
            deployable = _dicts(_scrub(found_deployable))

    sessions: list[dict] | None = None
    if opts["include_sessions"]:
        report("fmc sessions")
        found_sessions = await best_effort(f"{base}/health/ravpnsessions", "sessions")
        if found_sessions is not None:
            sessions = _dicts(_scrub(found_sessions))

    report("collected")
    LOGGER.info(
        "fmc: collected FMC %s domain %s - %d devices, %d HA pairs, %d clusters, %d RA VPN policies, "
        "%d VPN topologies, %d sessions, %d calls, %d errors, %d unsupported",
        client.base_url,
        resolved["name"],
        len(devices),
        len(ha_pairs),
        len(clusters),
        len(policies),
        len(s2s_vpns),
        len(sessions or []),
        client.stats["requests"],
        len(errors),
        len(unsupported),
    )
    return {
        "fmc": {
            "url": client.base_url,
            "name": "",
            "version": version,
            "domain": resolved["name"],
            "domain_uuid": resolved["uuid"],
            "domains": [dict(d) for d in client.domains],
        },
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "devices": devices,
        "on_map": on_map_ids,
        "ha_pairs": ha_pairs,
        "ha_monitored": ha_monitored,
        "clusters": clusters,
        "policies": policies,
        "assignments": assignments,
        "policy_details": policy_details,
        "pools": pools,
        "objects": objects,
        "interfaces": interfaces,
        "routing": routing,
        "nat_policies": nat_policies,
        "nat_rules": nat_rules,
        "access_policies": access_policies,
        "access_rules": access_rules,
        "access_rule_counts": access_rule_counts,
        "prefilter_policies": prefilter_policies,
        "prefilter_rules": prefilter_rules,
        "prefilter_rule_counts": prefilter_rule_counts,
        "s2s_vpns": s2s_vpns,
        "s2s_details": s2s_details,
        "tunnel_status": tunnel_status,
        "health_alerts": health_alerts,
        "deployable": deployable,
        "sessions": sessions,
        "errors": errors,
        "unsupported": unsupported,
        "stats": dict(client.stats),
        "options": opts,
    }


def _policies_in_use(
    policies: list[dict],
    assignments: list[dict],
    types: tuple[str, ...],
    resolver: TargetResolver,
    on_map: set[str],
) -> list[dict]:
    """The policies assigned to at least one device on the map (only those
    get their rules read)."""
    targets = assigned_devices(assignments, types, resolver, policies)
    return [p for p in policies if set(targets.get(_text(p["id"]), [])) & on_map]


async def _read_interfaces(best_effort, base: str, device_id: str, scope: str, *, optional: bool = False) -> list[dict]:
    found: list[dict] = []
    for resource, kind, newer in INTERFACE_RESOURCES:
        items = await best_effort(
            f"{base}/devices/devicerecords/{device_id}/{resource}", scope, optional=optional or newer
        )
        for item in items or []:
            if isinstance(item, dict):
                item.setdefault("type", kind)
                found.append(item)
    return found


async def _read_routing(best_effort, base: str, device_id: str, scope: str, add_total) -> dict[str, list[dict]]:
    """The routing of one device, in the shape the normalizer reads:
    ``virtual_routers`` and, per protocol, items tagged with ``vr`` (the
    virtual router's name; "Global" for the device-level configuration)."""
    root = f"{base}/devices/devicerecords/{device_id}/routing"
    routing: dict[str, list[dict]] = {
        "virtual_routers": [],
        "static_v4": [],
        "static_v6": [],
        "bgp": [],
        "ospf": [],
        "eigrp": [],
        "pbr": [],
        "ecmp": [],
    }

    def tag(items: Any, vr: str) -> list[dict]:
        return [{"vr": vr, **i} for i in _scrub(items or []) if isinstance(i, dict)]

    routers = await best_effort(f"{root}/virtualrouters", scope, optional=True)
    if routers is not None:
        routers = _dicts(_scrub(routers))
        routing["virtual_routers"] = routers
        add_total((len(_VR_ROUTING) + 1) * len(routers))
        for router in routers:
            vr_id, vr_name = _text(router.get("id")), _text(router.get("name")) or "Global"
            for resource, key in _VR_ROUTING:
                routing[key] += tag(
                    await best_effort(f"{root}/virtualrouters/{vr_id}/{resource}", scope, optional=True), vr_name
                )
            routing["ecmp"] += tag(
                await best_effort(f"{root}/virtualrouters/{vr_id}/ecmpzones", scope, optional=True), vr_name
            )
    if routers is None or not any(_text(r.get("name")).lower() == "global" for r in routers):
        # The global routing table lives at the device level (and is all
        # there is on a release without virtual routers).
        add_total(len(_VR_ROUTING))
        for resource, key in _VR_ROUTING:
            optional = key not in ("static_v4", "static_v6")
            routing[key] += tag(await best_effort(f"{root}/{resource}", scope, optional=optional), "Global")
    routing["pbr"] = tag(await best_effort(f"{root}/policybasedroutes", scope, optional=True), "")
    return routing
