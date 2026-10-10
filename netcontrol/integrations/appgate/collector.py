"""Appgate SDP collector - gathers every payload a topology build needs.

``collect_appgate`` reads one collective with an :class:`AppgateClient` and
returns the *raw* admin API answers. It does no interpretation -
``normalize.build_snapshot`` owns that - so a saved capture can be
re-normalised without calling the Controller.

What is read (every path is under ``/admin``):

  - ``/version``, ``/login``             the peer API version, the sign-in
  - ``/appliances``                      every appliance and its roles (required)
  - ``/appliances/status``               health, version, sessions per appliance
                                         (``/stats/appliances`` before 6.3)
  - ``/sites``, ``/sites/status``        sites, their network subnets, name
                                         resolution, and their health (``/sites``
                                         is required)
  - ``/policies``, ``/entitlements``,    what each user may reach, for the
    ``/conditions``, ``/ringfence-rules``  Entitlements rule set of each Gateway
  - ``/ip-pools``, ``/identity-providers`` the addresses clients get
  - ``/stats/active-sessions/dn``        the users connected now
                                         (``/on-boarded-devices`` before it existed)
  - ``/session-info/{dn}``               per connected user (``MAX_SESSION_DETAILS``
                                         at most): the Gateways they have a tunnel
                                         to, their tunnel address, and which
                                         entitlements each Gateway grants them
  - ``/global-settings``, ``/license``   the collective's name and licence

Failure policy: the version, the login, the appliances and the sites are
required; everything else is best-effort and a failure is recorded in
``errors`` and surfaced in the map's collection report.

Secrets: every payload goes through ``scrub_secrets`` and ``_scrub``, so an
appliance's certificates (``httpsP12`` and the like), SSH and SNMP settings,
log forwarder credentials, cloud resolver keys and identity provider bind
passwords and shared secrets never reach the database. The password and the
token are never stored.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from netcontrol.integrations.appgate.client import AppgateApiError, AppgateClient
from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.appgate")

DEFAULT_OPTIONS: dict[str, Any] = {
    # The admin user Plexus signs in as; the entry's secret is its password.
    "username": "",
    # Verify the Controller's TLS certificate.
    "verify_tls": True,
    # Limit the build to sites whose name contains this text. Empty = all.
    "site_name_contains": "",
    # Health, version and sessions of every appliance (and of every site).
    "include_appliance_state": True,
    # Policies, entitlements, conditions and ringfence rules.
    "include_entitlements": True,
    # The users connected with the Appgate Client.
    "include_users": True,
    # Per connected user, the Gateways and entitlements it holds.
    "include_session_details": True,
    # Attach data Plexus already collected over SNMP/SSH for inventory hosts
    # that match an appliance.
    "inventory_enrich": True,
}

_BOOL_OPTIONS = (
    "verify_tls",
    "include_appliance_state",
    "include_entitlements",
    "include_users",
    "include_session_details",
    "inventory_enrich",
)

# Per-user access details are one call per user: beyond this many users
# are drawn without them (no tunnel address, no entitlements).
MAX_SESSION_DETAILS = 500

ProgressCallback = Callable[[dict[str, Any]], None]

# (raw key, path) of the policy calls.
POLICY_PATHS = (
    ("policies", "/policies"),
    ("entitlements", "/entitlements"),
    ("conditions", "/conditions"),
    ("ringfence_rules", "/ringfence-rules"),
)
POOL_PATHS = (("ip_pools", "/ip-pools"), ("identity_providers", "/identity-providers"))

# Appliance settings that are secrets or noise for a map: certificates,
# SSH, SNMP, metrics exporters, NTP keys.
_APPLIANCE_DROPPED = ("sshServer", "snmpServer", "prometheusExporter", "ntp", "healthcheckServer")
# Key fragments that name a secret the generic scrubber does not know.
_SECRET_FRAGMENTS = ("p12", "decryptionkey", "accesskey", "secretkey", "awssecret", "privatekey", "bindpassword")
# Identity providers: anything that names a key, besides secrets and passwords.
_PROVIDER_FRAGMENTS = ("key", "certificate")
_PROVIDER_KEPT = ("ipPoolV4", "ipPoolV6")
# Cloud and DNS resolvers of a site: their credentials.
_RESOLVER_FRAGMENTS = ("username", "accesskeyid", "clientid", "tenantid", "key")


def sanitize_options(raw: object) -> dict[str, Any]:
    """Coerce stored/user-supplied build options onto the known schema."""
    src = raw if isinstance(raw, dict) else {}
    opts = dict(DEFAULT_OPTIONS)
    for key in _BOOL_OPTIONS:
        if key in src:
            opts[key] = bool(src[key])
    opts["username"] = str(src.get("username") or "").strip()[:120]
    opts["site_name_contains"] = str(src.get("site_name_contains") or "").strip()[:200]
    return opts


def _drop(value: Any, fragments: tuple[str, ...], kept: tuple[str, ...] = ()) -> Any:
    """``value`` without the keys whose name holds one of ``fragments``."""
    if isinstance(value, dict):
        return {
            k: _drop(v, fragments, kept)
            for k, v in value.items()
            if k in kept or not any(fragment in str(k).lower() for fragment in fragments)
        }
    if isinstance(value, list):
        return [_drop(v, fragments, kept) for v in value]
    return value


def _scrub(value: Any) -> Any:
    """``scrub_secrets`` plus the Appgate secret-bearing keys."""
    return _drop(scrub_secrets(value), _SECRET_FRAGMENTS)


def scrub_appliance(appliance: dict) -> dict:
    """An appliance without its certificates, SSH and SNMP settings, and
    with only whether its log forwarder is on (not its destinations, which
    carry tokens and keys)."""
    cleaned = {k: v for k, v in _scrub(appliance).items() if k not in _APPLIANCE_DROPPED}
    forwarder = cleaned.get("logForwarder")
    if isinstance(forwarder, dict):
        cleaned["logForwarder"] = {"enabled": bool(forwarder.get("enabled"))}
    return cleaned


def scrub_site(site: dict) -> dict:
    """A site without the credentials of its cloud and DNS resolvers."""
    cleaned = _scrub(site)
    resolution = cleaned.get("nameResolution")
    if isinstance(resolution, dict):
        cleaned["nameResolution"] = _drop(resolution, _RESOLVER_FRAGMENTS)
    return cleaned


def scrub_identity_provider(provider: dict) -> dict:
    """An identity provider without its bind password, shared secret,
    client secret or decryption key."""
    return _drop(_scrub(provider), _PROVIDER_FRAGMENTS, _PROVIDER_KEPT)


def _error(scope: str, path: str, exc: AppgateApiError) -> dict[str, Any]:
    message = f"{exc}: {exc.detail}" if exc.detail else str(exc)
    return {"scope": scope, "path": path, "status": exc.status_code, "message": message}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _role_on(appliance: dict, role: str) -> bool:
    found = appliance.get(role)
    return isinstance(found, dict) and bool(found.get("enabled"))


async def collect_appgate(
    client: AppgateClient,
    options: dict[str, Any] | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Collect one collective. Raises ``AppgateApiError`` only if the
    version, the login, the appliances or the sites cannot be read."""
    opts = sanitize_options(options)
    errors: list[dict[str, Any]] = []
    # version, login, appliances, sites, global settings, licence, pools;
    # the per-user calls are added once the user count is known.
    total = 6 + len(POOL_PATHS)
    total += 2 * int(opts["include_appliance_state"])
    total += len(POLICY_PATHS) * int(opts["include_entitlements"])
    total += int(opts["include_users"])
    done = 0

    def report(phase: str, **fields: Any) -> None:
        if progress is not None:
            progress({"phase": phase, "calls_done": done, "calls_total": total, **fields})

    async def best_effort(scope: str, path: str, *, listed: bool = True) -> Any:
        nonlocal done
        try:
            return await client.get_list(path) if listed else await client.get(path)
        except AppgateApiError as exc:
            errors.append(_error(scope, path, exc))
            return None
        finally:
            done += 1

    report("appgate version")
    peer_version = await client.negotiate()
    done += 1
    await client.login()
    done += 1

    report("appgate appliances")
    try:
        appliances = [scrub_appliance(a) for a in await client.get_list("/appliances")]
    finally:
        done += 1
    report("appgate appliances", devices=len(appliances))

    appliance_status: list[dict] | None = None
    if opts["include_appliance_state"]:
        try:
            appliance_status = [_scrub(s) for s in await client.get_list("/appliances/status")]
        except AppgateApiError as exc:
            if exc.status_code == 404:
                # Before 6.3 the same objects come from a deprecated path.
                try:
                    appliance_status = [_scrub(s) for s in await client.get_list("/stats/appliances")]
                except AppgateApiError as fallback:
                    errors.append(_error("collective", "/stats/appliances", fallback))
            else:
                errors.append(_error("collective", "/appliances/status", exc))
        done += 1

    report("appgate sites")
    try:
        sites = [scrub_site(s) for s in await client.get_list("/sites")]
    finally:
        done += 1
    site_status: list[dict] | None = None
    if opts["include_appliance_state"]:
        found = await best_effort("collective", "/sites/status")
        site_status = _scrub(found) if found is not None else None
    settings = await best_effort("collective", "/global-settings", listed=False)
    global_settings = _scrub(settings) if isinstance(settings, dict) else None
    found_license = await best_effort("collective", "/license", listed=False)
    license_info = _scrub(found_license) if isinstance(found_license, dict) else None

    # The site filter: sites by name, and the appliances of the sites kept
    # (an appliance with no site, and every Controller, stays).
    needle = opts["site_name_contains"].lower()
    if needle:
        sites = [s for s in sites if needle in _text(s.get("name")).lower()]
        kept = {_text(s.get("id")) for s in sites}
        appliances = [
            a
            for a in appliances
            if not _text(a.get("site")) or _text(a.get("site")) in kept or _role_on(a, "controller")
        ]
        on_map = {_text(a.get("id")) for a in appliances}
        if appliance_status is not None:
            appliance_status = [s for s in appliance_status if _text(s.get("id")) in on_map]
        if site_status is not None:
            site_status = [s for s in site_status if _text(s.get("id")) in kept]
    report("appgate sites", networks=len(sites), devices=len(appliances))

    policy: dict[str, list[dict] | None] = {key: None for key, _path in POLICY_PATHS}
    if opts["include_entitlements"]:
        report("appgate policy")
        for key, path in POLICY_PATHS:
            found = await best_effort("policy", path)
            policy[key] = _scrub(found) if found is not None else None

    report("appgate pools")
    pools: dict[str, list[dict] | None] = {}
    for key, path in POOL_PATHS:
        found = await best_effort("identity", path)
        if found is None:
            pools[key] = None
        elif key == "identity_providers":
            pools[key] = [scrub_identity_provider(p) for p in found]
        else:
            pools[key] = _scrub(found)

    sessions: list[dict] | None = None
    sessions_source = ""
    if opts["include_users"]:
        report("appgate users")
        try:
            sessions = _scrub(await client.get_list("/stats/active-sessions/dn"))
            sessions_source = "active-sessions"
        except AppgateApiError as exc:
            if exc.status_code == 404:
                # An older Controller: the devices on-boarded, connected or not.
                try:
                    sessions = _scrub(await client.get_list("/on-boarded-devices"))
                    sessions_source = "on-boarded-devices"
                except AppgateApiError as fallback:
                    errors.append(_error("users", "/on-boarded-devices", fallback))
            else:
                errors.append(_error("users", "/stats/active-sessions/dn", exc))
        done += 1
        report("appgate users", users=len(sessions or []))

    session_details: dict[str, dict] | None = None
    skipped = 0
    if sessions and sessions_source == "active-sessions" and opts["include_session_details"]:
        names = [_text(s.get("distinguishedName")) for s in sessions if _text(s.get("distinguishedName"))]
        names = list(dict.fromkeys(names))
        wanted, skipped = names[:MAX_SESSION_DETAILS], max(0, len(names) - MAX_SESSION_DETAILS)
        total += len(wanted)
        session_details = {}
        failed: list[AppgateApiError] = []
        report("appgate sessions", users=len(wanted))
        for dn in wanted:
            try:
                found = await client.get(f"/session-info/{quote(dn, safe='')}")
            except AppgateApiError as exc:
                # 404: the user signed out since the list was read.
                if exc.status_code != 404:
                    failed.append(exc)
                found = None
            done += 1
            if isinstance(found, dict):
                session_details[dn] = _scrub(found)
            if done % 25 == 0:
                report("appgate sessions", users=len(wanted))
        if failed:
            first = failed[0]
            errors.append(
                {
                    "scope": "users",
                    "path": f"/session-info ({len(failed)} of {len(wanted)} users)",
                    "status": first.status_code,
                    "message": f"{first}: {first.detail}" if first.detail else str(first),
                }
            )

    report("collected")
    LOGGER.info(
        "appgate: collected collective %s - peer v%d, %d appliances, %d sites, %d users (%d with details), "
        "%d calls, %d errors",
        client.base_url,
        peer_version,
        len(appliances),
        len(sites),
        len(sessions or []),
        len(session_details or {}),
        client.stats["requests"],
        len(errors),
    )
    collective_name = _text((global_settings or {}).get("collectiveName"))
    return {
        "collective": {
            "name": collective_name,
            "collective_name": collective_name,
            "collective_id": _text((global_settings or {}).get("collectiveId")),
            "peer_version": peer_version,
            "controller": client.base_url.removeprefix("https://"),
        },
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "appliances": appliances,
        "appliance_status": appliance_status,
        "sites": sites,
        "site_status": site_status,
        "policies": policy["policies"],
        "entitlements": policy["entitlements"],
        "conditions": policy["conditions"],
        "ringfence_rules": policy["ringfence_rules"],
        "identity_providers": pools["identity_providers"],
        "ip_pools": pools["ip_pools"],
        "sessions": sessions,
        "sessions_source": sessions_source,
        "session_details": session_details,
        "sessions_skipped": skipped,
        "license": license_info,
        "global_settings": global_settings,
        "errors": errors,
        "stats": dict(client.stats),
        "options": opts,
    }
