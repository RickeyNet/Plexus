"""FMC collector - gathers every payload an AnyConnect topology build needs.

``collect_fmc`` reads one FMC domain with an :class:`FmcClient` and returns
the *raw* API payloads. It does no interpretation - ``normalize.build_snapshot``
owns that - so a saved capture can be re-normalised without calling the FMC.

What is read (all under ``/api/fmc_config/v1/domain/{uuid}``):

  - ``devices/devicerecords``                 every managed FTD (required)
  - ``policies/ravpns``                       the remote access VPN policies
  - ``assignment/policyassignments``          which devices each policy targets
  - ``policies/ravpns/{id}/connectionprofiles``, ``.../addressassignmentsettings``,
    ``.../accessinterfacesettings``           per policy: profiles, pools, access interfaces
  - ``object/ipv4addresspools``               the address pools (VPN client subnets)
  - ``devices/devicerecords/{id}/physicalinterfaces`` and ``.../subinterfaces``
                                              the interfaces of each device on the map
  - ``health/ravpnsessions``                  the connected remote access users
                                              (FMC 7.3 and later)

Failure policy: the login and the device list are required; everything else
is best-effort and a failure is recorded in ``errors`` and surfaced in the
map's collection report. A device whose interfaces cannot be read still
appears, without its access interface address; an FMC that does not serve
session data still draws every headend, without its users.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from netcontrol.integrations.anyconnect.client import CONFIG_PATH, PLATFORM_PATH, FmcApiError, FmcClient
from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.anyconnect")

DEFAULT_OPTIONS: dict[str, Any] = {
    # The FMC API user. The password is the entry's write-only secret.
    "username": "",
    # Limit the build to devices whose name contains this text. Empty = all.
    "device_name_contains": "",
    # Draw every managed device, not only those with a remote access VPN policy.
    "include_all_devices": False,
    # The interfaces of each device on the map (for the access interface address).
    "include_interfaces": True,
    # Connected remote access users (FMC 7.3+ health API).
    "include_sessions": True,
    # Verify the FMC's TLS certificate.
    "verify_tls": True,
    # Attach data Plexus already collected over SNMP/SSH for inventory hosts
    # that match a device.
    "inventory_enrich": True,
}

_BOOL_OPTIONS = ("include_all_devices", "include_interfaces", "include_sessions", "verify_tls", "inventory_enrich")

ProgressCallback = Callable[[dict[str, Any]], None]

# Policy types FMC uses for remote access VPN (compared lower-case, no separators).
RA_VPN_POLICY_TYPES = ("ravpn",)


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


def is_ra_vpn_policy(policy: Any) -> bool:
    kind = str((policy or {}).get("type") or "").lower().replace("_", "").replace("-", "")
    return kind in RA_VPN_POLICY_TYPES


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
    # login, version, devices, policies, assignments, pools (+ per-policy and
    # per-device calls, added as they become known).
    total = 6 + int(opts["include_sessions"])
    done = 0

    def report(phase: str, **fields: Any) -> None:
        if progress is not None:
            progress({"phase": phase, "calls_done": done, "calls_total": total, **fields})

    base = ""  # the domain's configuration root, known after login

    async def best_effort(path: str, scope: str, *, paged: bool = True) -> Any:
        nonlocal done
        try:
            return await (client.get_all(path) if paged else client.get(path))
        except FmcApiError as exc:
            # Reported relative to the domain, which is what an operator reads.
            short = path.removeprefix(base) if base else path
            errors.append(_error(scope, short.removeprefix(CONFIG_PATH).removeprefix(PLATFORM_PATH), exc))
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
    devices = scrub_secrets(await client.get_all(f"{base}/devices/devicerecords"))
    done += 1
    needle = opts["device_name_contains"].lower()
    devices = [
        d
        for d in devices
        if isinstance(d, dict) and d.get("id") and (not needle or needle in _text(d.get("name")).lower())
    ]
    report("fmc devices", devices=len(devices))

    report("fmc vpn policies")
    policies = [p for p in scrub_secrets(await best_effort(f"{base}/policies/ravpns", "policies") or []) if p.get("id")]
    assignments = scrub_secrets(await best_effort(f"{base}/assignment/policyassignments", "policies") or [])
    policies = [p for p in policies if is_ra_vpn_policy(p) or not p.get("type")]

    total += 3 * len(policies)
    policy_details: dict[str, dict[str, Any]] = {}
    for policy in policies:
        pid = _text(policy["id"])
        report("fmc vpn policies", networks=len(policies))
        detail_base = f"{base}/policies/ravpns/{pid}"
        scope = f"policy {policy.get('name')}"
        policy_details[pid] = scrub_secrets(
            {
                "connection_profiles": await best_effort(f"{detail_base}/connectionprofiles", scope) or [],
                # Settings resources: one object on some releases, a one-item
                # collection on others.
                "address_assignment": _items_or_self(
                    await best_effort(f"{detail_base}/addressassignmentsettings", scope, paged=False)
                ),
                "access_interfaces": _items_or_self(
                    await best_effort(f"{detail_base}/accessinterfacesettings", scope, paged=False)
                ),
            }
        )

    report("fmc pools")
    pools = scrub_secrets(await best_effort(f"{base}/object/ipv4addresspools", "pools") or [])

    # Which devices a remote access VPN policy targets, to limit the
    # per-device interface calls to the devices that will be drawn.
    targeted: set[str] = set()
    mapping_known = False
    for policy in policies:
        for target in policy.get("targets") or []:
            if isinstance(target, dict) and target.get("id"):
                targeted.add(_text(target["id"]))
                mapping_known = True
    for assignment in assignments:
        if not isinstance(assignment, dict) or not is_ra_vpn_policy(assignment.get("policy")):
            continue
        mapping_known = True
        for target in assignment.get("targets") or []:
            if isinstance(target, dict) and target.get("id"):
                targeted.add(_text(target["id"]))
    names_targeted: set[str] = set()
    for assignment in assignments:
        if isinstance(assignment, dict) and is_ra_vpn_policy(assignment.get("policy")):
            names_targeted.update(
                _text(t.get("name")).lower() for t in assignment.get("targets") or [] if isinstance(t, dict)
            )
    on_map = [
        d
        for d in devices
        if opts["include_all_devices"]
        or not mapping_known
        or _text(d["id"]) in targeted
        or _text(d.get("name")).lower() in names_targeted
    ]

    interfaces: dict[str, list[dict]] = {}
    if opts["include_interfaces"]:
        total += 2 * len(on_map)
        for device in on_map:
            did = _text(device["id"])
            report("fmc interfaces", devices=len(on_map))
            found: list[dict] = []
            for resource in ("physicalinterfaces", "subinterfaces"):
                items = await best_effort(
                    f"{base}/devices/devicerecords/{did}/{resource}", f"device {device.get('name')}"
                )
                found.extend(i for i in items or [] if isinstance(i, dict))
            interfaces[did] = scrub_secrets(found)

    sessions: list[dict] | None = None
    if opts["include_sessions"]:
        report("fmc sessions")
        found_sessions = await best_effort(f"{base}/health/ravpnsessions", "sessions")
        if found_sessions is not None:
            sessions = [s for s in scrub_secrets(found_sessions) if isinstance(s, dict)]

    report("collected")
    LOGGER.info(
        "anyconnect: collected FMC %s domain %s - %d devices, %d RA VPN policies, %d sessions, %d calls, %d errors",
        client.base_url,
        resolved["name"],
        len(devices),
        len(policies),
        len(sessions or []),
        client.stats["requests"],
        len(errors),
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
        "on_map": [_text(d["id"]) for d in on_map],
        "policies": policies,
        "assignments": [a for a in assignments if isinstance(a, dict)],
        "policy_details": policy_details,
        "pools": [p for p in pools if isinstance(p, dict)],
        "interfaces": interfaces,
        "sessions": sessions,
        "errors": errors,
        "stats": dict(client.stats),
        "options": opts,
    }
