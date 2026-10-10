"""Panorama collector - gathers every payload a Panorama topology build needs.

``collect_panorama`` reads one Panorama with a :class:`PanoramaClient` and
returns the *raw* XML API answers as plain data (``client.xml_to_data``). It
does no interpretation - ``normalize.build_snapshot`` owns that - so a saved
capture can be re-normalised without calling Panorama.

What is read (``<P>`` is ``/config/devices/entry[@name='localhost.localdomain']``):

  - ``type=version``, ``<show><system><info/></system></show>``   Panorama itself
  - ``<show><devices><all/></devices></show>``    every managed firewall (required)
  - ``<show><devicegroups/></show>``, ``/config/readonly/.../device-group/entry``
                                                 device groups, members, hierarchy
  - ``<show><templates/></show>``, ``<show><template-stack/></show>``,
    ``<P>/template-stack``                       templates, stacks, their order,
                                                 variables and stack overrides
  - ``/config/shared/<kind>`` and ``<P>/device-group/entry[@name='X']/<kind>``
    for address, address-group, service, service-group, application-group
  - the ``pre-rulebase`` and ``post-rulebase`` security and NAT rules, and the
    default security rules, of shared and each device group in use
  - per template in use, ``.../config/devices/entry/network/interface``,
    ``virtual-router``, ``ike/gateway``, ``tunnel/ipsec``,
    ``tunnel/global-protect-gateway``, ``vsys`` and the template variables
  - per connected firewall on the map, through Panorama (``target=<serial>``):
    ``show interface all``, ``show routing route``, BGP peers, ``show vpn
    ipsec-sa``, ``show vpn flow``, HA state and the GlobalProtect users

Failure policy: the login and the device list are required; everything else
is best-effort and a failure is recorded in ``errors`` and surfaced in the
map's collection report. A configuration node that does not exist is no
failure (``config_show`` answers ``None``). A firewall that uses the Advanced
Routing Engine answers the legacy routing commands with an error: that is a
gap, listed in ``unsupported``, not a failure. A firewall that is not
connected to Panorama is not asked for its state (``state_skipped``).

Configuration lives in templates, not on a device, so the two members of an
HA pair (which share a template stack) are read once; their state is read
from both.

Secrets: every payload goes through ``scrub_secrets`` and ``_scrub``, so an
IKE pre-shared key, a BGP or OSPF authentication key, a password hash or an
SNMP community never reaches the database. The API key is never stored.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.integrations.panorama.client import PanoramaApiError, PanoramaClient
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.panorama")

DEFAULT_OPTIONS: dict[str, Any] = {
    # The Panorama admin to generate an API key for. Empty: the entry's
    # secret is the API key itself; set: the secret is this admin's password.
    "username": "",
    # Verify Panorama's TLS certificate.
    "verify_tls": True,
    # Limit the build to firewalls whose hostname contains this text. Empty = all.
    "device_name_contains": "",
    # Interfaces and zones of the templates and template stacks.
    "include_interfaces": True,
    # Virtual routers, static routes, BGP, OSPF (and the routing table and
    # BGP peers with the device state).
    "include_routing": True,
    # Security rules and the default security rules.
    "include_security_policies": True,
    # NAT rules.
    "include_nat": True,
    # IKE gateways and IPsec tunnels (and their state with the device state).
    "include_vpn": True,
    # GlobalProtect gateways (and the connected users with the device state).
    "include_global_protect": True,
    # Operational state read through Panorama from each connected firewall.
    "include_device_state": True,
    # Attach data Plexus already collected over SNMP/SSH for inventory hosts
    # that match a firewall.
    "inventory_enrich": True,
}

_BOOL_OPTIONS = (
    "verify_tls",
    "include_interfaces",
    "include_routing",
    "include_security_policies",
    "include_nat",
    "include_vpn",
    "include_global_protect",
    "include_device_state",
    "inventory_enrich",
)

ProgressCallback = Callable[[dict[str, Any]], None]

PANORAMA_ROOT = "/config/devices/entry[@name='localhost.localdomain']"
SHARED_ROOT = "/config/shared"
READONLY_DEVICE_GROUPS = "/config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry"
TEMPLATE_STACKS = f"{PANORAMA_ROOT}/template-stack"
SHARED = "shared"

OBJECT_KINDS = ("address", "address-group", "service", "service-group", "application-group")
RULEBASES = ("pre", "post")

# Network configuration of a template: key in ``template_config[name]`` ->
# path under the template's device and the option that wants it.
TEMPLATE_PARTS: tuple[tuple[str, str, str, str], ...] = (
    ("interface", "network/interface", "include_interfaces", "panorama network"),
    ("vsys", "vsys", "include_interfaces", "panorama network"),
    ("virtual-router", "network/virtual-router", "include_routing", "panorama network"),
    ("ike-gateway", "network/ike/gateway", "include_vpn", "panorama vpn"),
    ("ipsec", "network/tunnel/ipsec", "include_vpn", "panorama vpn"),
    (
        "global-protect-gateway",
        "network/tunnel/global-protect-gateway",
        "include_global_protect",
        "panorama global protect",
    ),
)

COMMAND_SYSTEM_INFO = "<show><system><info/></system></show>"
COMMAND_DEVICES = "<show><devices><all/></devices></show>"
COMMAND_DEVICE_GROUPS = "<show><devicegroups/></show>"
COMMAND_TEMPLATES = "<show><templates/></show>"
COMMAND_TEMPLATE_STACKS = "<show><template-stack/></show>"

# Operational commands read from each firewall: key in ``state[serial]``,
# the command and the option that wants it (``""``: always).
STATE_COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("interfaces", "<show><interface>all</interface></show>", ""),
    ("routes", "<show><routing><route/></routing></show>", "include_routing"),
    ("bgp_peers", "<show><routing><protocol><bgp><peer/></bgp></protocol></routing></show>", "include_routing"),
    ("ipsec_sa", "<show><vpn><ipsec-sa/></vpn></show>", "include_vpn"),
    ("vpn_flow", "<show><vpn><flow/></vpn></show>", "include_vpn"),
    ("ha", "<show><high-availability><state/></high-availability></show>", ""),
    (
        "gp_users",
        "<show><global-protect-gateway><current-user/></global-protect-gateway></show>",
        "include_global_protect",
    ),
)

# Keys that hold secrets the generic scrubber does not recognise: IKE
# pre-shared keys, routing authentication keys, password hashes, SNMP
# communities. ``key`` and ``secret`` are dropped as whole names only.
_SECRET_FRAGMENTS = ("pre-shared", "preshared", "shared-key", "phash", "password-hash", "community", "md5")
_SECRET_NAMES = ("key", "secret", "auth-key", "private-key", "certificate-key")


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


def _scrub(value: Any) -> Any:
    """``scrub_secrets`` plus the PAN-OS secret-bearing keys."""
    cleaned = scrub_secrets(value)

    def walk(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                k: walk(v)
                for k, v in item.items()
                if str(k).lower().lstrip("@") not in _SECRET_NAMES
                and not any(fragment in str(k).lower() for fragment in _SECRET_FRAGMENTS)
            }
        if isinstance(item, list):
            return [walk(v) for v in item]
        return item

    return walk(cleaned)


def _text(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("#text") or value.get("@name") or ""
    return str(value or "").strip() if not isinstance(value, (list, dict)) else ""


def entries(value: Any) -> list[dict]:
    """A list of ``entry`` dicts from any shape a payload may take: a list,
    one entry (a dict with ``@name``), a dict holding an ``entry`` list."""
    if isinstance(value, list):
        return [i for i in value if isinstance(i, dict)]
    if isinstance(value, dict):
        if "entry" in value:
            return entries(value["entry"])
        if "@name" in value:
            return [value]
    return []


def members(value: Any) -> list[str]:
    """A ``member`` list as strings (one member may come as a plain string)."""
    if isinstance(value, list):
        return [_text(v) for v in value if _text(v)]
    if isinstance(value, dict) and "member" in value:
        return members(value["member"])
    text = _text(value)
    return [text] if text else []


def _name(item: dict) -> str:
    return _text(item.get("@name"))


def _safe(name: str) -> bool:
    """Whether a name can be put inside an xpath predicate as is."""
    return bool(name) and "'" not in name and "]" not in name


def dg_xpath(device_group: str) -> str:
    return f"{PANORAMA_ROOT}/device-group/entry[@name='{device_group}']"


def scope_root(scope: str) -> str:
    return SHARED_ROOT if scope == SHARED else dg_xpath(scope)


def template_device_xpath(template: str) -> str:
    return f"{PANORAMA_ROOT}/template/entry[@name='{template}']/config/devices/entry[@name='localhost.localdomain']"


def device_group_members(device_groups: list[dict]) -> dict[str, str]:
    """firewall serial -> the device group it is in."""
    found: dict[str, str] = {}
    for group in device_groups:
        for device in entries(group.get("devices")):
            serial = _text(device.get("serial")) or _name(device)
            if serial:
                found.setdefault(serial, _name(group))
    return found


def ancestors(device_group: str, parents: dict[str, str]) -> list[str]:
    """The device groups above ``device_group``, nearest first (shared not
    included)."""
    chain: list[str] = []
    current = parents.get(device_group, "")
    while current and current != SHARED and current not in chain and current != device_group:
        chain.append(current)
        current = parents.get(current, "")
    return chain


def descendants(device_group: str, parents: dict[str, str]) -> set[str]:
    """``device_group`` and every device group below it."""
    found = {device_group}
    changed = True
    while changed:
        changed = False
        for child, parent in parents.items():
            if parent in found and child not in found:
                found.add(child)
                changed = True
    return found


def stack_of_devices(stacks: list[dict], templates: list[dict], stack_config: list[dict]) -> dict[str, dict]:
    """firewall serial -> ``{"stack": name, "template": name}`` (the
    template stack it is assigned to, or the template for a firewall
    assigned to a template directly)."""
    found: dict[str, dict] = {}
    for stack in [*stacks, *stack_config]:
        for device in entries(stack.get("devices")):
            serial = _text(device.get("serial")) or _name(device)
            if serial:
                found.setdefault(serial, {"stack": _name(stack), "template": ""})
    for template in templates:
        for device in entries(template.get("devices")):
            serial = _text(device.get("serial")) or _name(device)
            if serial and serial not in found:
                found[serial] = {"stack": "", "template": _name(template)}
    return found


def stack_templates(stack: dict) -> list[str]:
    """The templates of a stack, highest priority first."""
    return members(stack.get("templates"))


def ha_peer(device: dict) -> str:
    """The serial of a firewall's HA peer, when it has one."""
    ha = device.get("ha") if isinstance(device.get("ha"), dict) else {}
    peer = ha.get("peer") if isinstance(ha.get("peer"), dict) else {}
    return _text(peer.get("serial"))


def _error(scope: str, path: str, exc: PanoramaApiError) -> dict[str, Any]:
    message = f"{exc}: {exc.detail}" if exc.detail else str(exc)
    return {"scope": scope, "path": path, "status": exc.status_code, "message": message}


def _short(path: str) -> str:
    """A path as an operator reads it: relative to Panorama's own device."""
    return path.replace(PANORAMA_ROOT, "").replace(SHARED_ROOT, "/shared") or path


async def collect_panorama(
    client: PanoramaClient,
    device_group: str,
    options: dict[str, Any] | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Collect one Panorama. ``device_group`` blank reads every device group;
    otherwise only that device group and those below it. Raises
    ``PanoramaApiError`` only if the login fails, the device group is
    unknown, or the device list cannot be read."""
    opts = sanitize_options(options)
    errors: list[dict[str, Any]] = []
    unsupported: list[str] = []
    # login, system info, devices, device groups, hierarchy, templates,
    # stacks and their configuration; per scope, template and firewall
    # calls are added as they become known.
    total = 8
    done = 0

    def report(phase: str, **fields: Any) -> None:
        if progress is not None:
            progress({"phase": phase, "calls_done": done, "calls_total": total, **fields})

    async def config(xpath: str, scope: str) -> Any:
        nonlocal done
        try:
            return _scrub(await client.config_show(xpath))
        except PanoramaApiError as exc:
            errors.append(_error(scope, _short(xpath), exc))
            return None
        finally:
            done += 1

    async def op(cmd: str, scope: str, target: str | None = None) -> Any:
        nonlocal done
        try:
            return _scrub(await client.op(cmd, target))
        except PanoramaApiError as exc:
            errors.append(_error(scope, cmd, exc))
            return None
        finally:
            done += 1

    report("panorama login")
    await client.login()
    info = await client.version()
    done += 1
    system = await op(COMMAND_SYSTEM_INFO, "panorama")
    system = system.get("system", system) if isinstance(system, dict) else {}

    report("panorama devices")
    try:
        found = _scrub(await client.op(COMMAND_DEVICES))
    finally:
        done += 1
    devices = [d for d in entries(found) if _text(d.get("serial")) or _name(d)]
    for device in devices:
        device.setdefault("serial", _name(device))
    report("panorama devices", devices=len(devices))

    report("panorama device groups")
    device_groups = entries(await op(COMMAND_DEVICE_GROUPS, "device groups"))
    hierarchy = entries(await config(READONLY_DEVICE_GROUPS, "device groups"))
    parents = {_name(g): _text(g.get("parent-dg")) for g in hierarchy if _name(g)}
    for group in device_groups:
        parents.setdefault(_name(group), "")
    membership = device_group_members(device_groups)

    wanted_group = (device_group or "").strip()
    in_scope: set[str] | None = None
    if wanted_group:
        known = {name.lower(): name for name in parents}
        if wanted_group.lower() not in known:
            visible = ", ".join(sorted(parents)) or "none"
            raise PanoramaApiError(
                f"Panorama device group {wanted_group!r} not found", detail=f"The device groups are: {visible}"
            )
        wanted_group = known[wanted_group.lower()]
        in_scope = descendants(wanted_group, parents)

    needle = opts["device_name_contains"].lower()
    by_serial = {_text(d["serial"]): d for d in devices}

    def wanted(device: dict) -> bool:
        serial = _text(device["serial"])
        if in_scope is not None and membership.get(serial) not in in_scope:
            return False
        return not needle or needle in _text(device.get("hostname")).lower()

    on_map = [_text(d["serial"]) for d in devices if wanted(d)]
    # An HA pair is one box: a member on the map brings its peer.
    for serial in list(on_map):
        peer = ha_peer(by_serial[serial])
        if peer in by_serial and peer not in on_map and (in_scope is None or membership.get(peer) in in_scope):
            on_map.append(peer)
    report("panorama device groups", device_groups=len(parents), devices=len(on_map))

    report("panorama templates")
    templates = entries(await op(COMMAND_TEMPLATES, "templates"))
    stacks = entries(await op(COMMAND_TEMPLATE_STACKS, "templates"))
    stack_config = entries(await config(TEMPLATE_STACKS, "templates"))
    assignment = stack_of_devices(stacks, templates, stack_config)
    stack_by_name = {_name(s): s for s in stack_config if _name(s)}
    for stack in stacks:
        if _name(stack) and _name(stack) not in stack_by_name:
            stack_by_name[_name(stack)] = stack
    needed_templates: list[str] = []
    for serial in on_map:
        assigned = assignment.get(serial) or {}
        names = stack_templates(stack_by_name.get(assigned.get("stack", ""), {})) or [assigned.get("template", "")]
        for name in names:
            if name and _safe(name) and name not in needed_templates:
                needed_templates.append(name)

    # Shared, then the device group of each firewall on the map and its ancestors.
    scopes: list[str] = [SHARED]
    for serial in on_map:
        group = membership.get(serial, "")
        for name in [group, *ancestors(group, parents)] if group else []:
            if _safe(name) and name not in scopes:
                scopes.append(name)

    total += len(scopes) * len(OBJECT_KINDS)
    total += len(scopes) * (len(RULEBASES) + 1) if opts["include_security_policies"] else 0
    total += len(scopes) * len(RULEBASES) if opts["include_nat"] else 0
    parts = [p for p in TEMPLATE_PARTS if opts[p[2]]]
    total += len(needed_templates) * (len(parts) + 1) if parts else 0

    report("panorama objects")
    objects: dict[str, dict[str, list[dict]]] = {}
    for scope in scopes:
        report("panorama objects", scopes=len(scopes))
        root = scope_root(scope)
        objects[scope] = {kind: entries(await config(f"{root}/{kind}", f"objects {scope}")) for kind in OBJECT_KINDS}

    security_rules: dict[str, dict[str, list[dict]]] = {}
    default_rules: dict[str, list[dict]] = {}
    if opts["include_security_policies"]:
        report("panorama policies")
        for scope in scopes:
            report("panorama policies", scopes=len(scopes))
            root = scope_root(scope)
            security_rules[scope] = {
                base: entries(await config(f"{root}/{base}-rulebase/security/rules", f"security rules {scope}"))
                for base in RULEBASES
            }
            default_rules[scope] = entries(
                await config(f"{root}/post-rulebase/default-security-rules/rules", f"security rules {scope}")
            )

    nat_rules: dict[str, dict[str, list[dict]]] = {}
    if opts["include_nat"]:
        report("panorama nat")
        for scope in scopes:
            report("panorama nat", scopes=len(scopes))
            root = scope_root(scope)
            nat_rules[scope] = {
                base: entries(await config(f"{root}/{base}-rulebase/nat/rules", f"NAT rules {scope}"))
                for base in RULEBASES
            }

    template_config: dict[str, dict[str, Any]] = {}
    for name in needed_templates:
        template_config[name] = {}
    for phase in ("panorama network", "panorama vpn", "panorama global protect"):
        wanted_parts = [p for p in parts if p[3] == phase]
        if not wanted_parts:
            continue
        report(phase)
        for name in needed_templates:
            report(phase, templates=len(needed_templates))
            device_root = template_device_xpath(name)
            if phase == "panorama network":
                template_config[name]["variable"] = entries(
                    await config(f"{PANORAMA_ROOT}/template/entry[@name='{name}']/variable", f"template {name}")
                )
            for key, path, _option, _phase in wanted_parts:
                found = await config(f"{device_root}/{path}", f"template {name}")
                template_config[name][key] = entries(found) if key not in ("interface",) else found or {}
    if parts and "panorama network" not in {p[3] for p in parts}:
        # Variables are read with the network; without it, separately.
        for name in needed_templates:
            template_config[name]["variable"] = entries(
                await config(f"{PANORAMA_ROOT}/template/entry[@name='{name}']/variable", f"template {name}")
            )

    state: dict[str, dict[str, Any]] = {}
    state_skipped: dict[str, str] = {}
    if opts["include_device_state"]:
        report("panorama device state")
        commands = [c for c in STATE_COMMANDS if not c[2] or opts[c[2]]]
        connected = []
        for serial in on_map:
            if _text(by_serial[serial].get("connected")).lower() == "yes":
                connected.append(serial)
            else:
                state_skipped[serial] = "not connected to Panorama"
        total += len(connected) * len(commands)
        for serial in connected:
            report("panorama device state", devices=len(connected))
            hostname = _text(by_serial[serial].get("hostname")) or serial
            scope = f"firewall {hostname}"
            found_state: dict[str, Any] = {}
            advanced = False
            for key, cmd, _option in commands:
                if advanced and key == "bgp_peers":
                    done += 1
                    continue
                try:
                    found_state[key] = _scrub(await client.op(cmd, serial))
                except PanoramaApiError as exc:
                    if key == "routes" and "advanced" in f"{exc} {exc.detail}".lower():
                        advanced = True
                        note = f"advanced routing engine ({hostname})"
                        if note not in unsupported:
                            unsupported.append(note)
                    else:
                        errors.append(_error(scope, cmd, exc))
                finally:
                    done += 1
            state[serial] = found_state

    report("collected")
    LOGGER.info(
        "panorama: collected Panorama %s - %d firewalls (%d on the map), %d device groups, %d templates, "
        "%d calls, %d errors, %d unsupported",
        client.base_url,
        len(devices),
        len(on_map),
        len(parents),
        len(needed_templates),
        client.stats["requests"],
        len(errors),
        len(unsupported),
    )
    return {
        "panorama": {
            "url": client.base_url,
            "name": "",
            "hostname": _text(system.get("hostname")),
            "version": _text(info.get("sw-version")) or _text(system.get("sw-version")),
            "model": _text(info.get("model")) or _text(system.get("model")),
            "serial": _text(info.get("serial")) or _text(system.get("serial")),
            "ip": _text(system.get("ip-address")),
            "device_group": wanted_group,
        },
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "devices": devices,
        "on_map": on_map,
        "device_groups": device_groups,
        "dg_parents": parents,
        "templates": templates,
        "template_stacks": stacks,
        "stack_config": stack_config,
        "objects": objects,
        "security_rules": security_rules if opts["include_security_policies"] else None,
        "default_rules": default_rules,
        "nat_rules": nat_rules if opts["include_nat"] else None,
        "template_config": template_config,
        "state": state,
        "state_skipped": state_skipped,
        "errors": errors,
        "unsupported": unsupported,
        "stats": dict(client.stats),
        "options": opts,
    }
