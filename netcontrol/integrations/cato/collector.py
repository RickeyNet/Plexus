"""Cato account collector - gathers every payload a topology build needs.

``collect_account`` reads one account with a :class:`CatoClient` and returns
the *raw* API payloads. It does no interpretation - ``normalize.build_snapshot``
owns that - so a saved capture can be re-normalised without calling Cato.

What is read:

  - ``accountSnapshot.sites``   sites, their Sockets, WAN links and the PoP
                                each one is connected to (required)
  - ``accountSnapshot.users``   remote (SDP client) users that are connected:
                                where they connect from, their PoP, VPN IP,
                                device and recent connections
  - ``entityLookup``            the network ranges and LAN interfaces of every
                                site, for subnets

Failure policy: the site list is required; everything else is best-effort and
a failure is recorded in ``errors`` and surfaced in the map's collection
report. GraphQL rejects a whole query when it names one field the schema does
not have, so the site and user queries have reduced fallbacks: a schema
difference costs detail (HA state, recent connections, and only as a last
resort the WAN links), not the map.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from netcontrol.integrations.cato.client import CatoApiError, CatoClient
from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.cato")

DEFAULT_OPTIONS: dict[str, Any] = {
    # Limit the build to sites whose name contains this text. Empty = all.
    "site_name_contains": "",
    # Remote users connected with the Cato Client.
    "include_users": True,
    # Network ranges (subnets) behind every site.
    "include_ranges": True,
    # Attach data Plexus already collected over SNMP/SSH for inventory hosts
    # that match a Socket.
    "inventory_enrich": True,
}

_BOOL_OPTIONS = ("include_users", "include_ranges", "inventory_enrich")

_LOOKUP_PAGE_SIZE = 1000
_LOOKUP_FALLBACK_PAGE_SIZE = 50
_MAX_LOOKUP_ITEMS = 100_000

ProgressCallback = Callable[[dict[str, Any]], None]

_INTERFACE_INFO = "id name upstreamBandwidth downstreamBandwidth destType wanRole"

SITES_QUERY = """
query plexusSites($accountID: ID!) {
  accountSnapshot(accountID: $accountID) {
    id
    timestamp
    sites {
      id
      connectivityStatus
      operationalStatus
      lastConnected
      connectedSince
      popName
      hostCount
      haStatus { readiness wanConnectivity keepalive socketVersion }
      info {
        name type description countryCode countryName countryStateName cityName address isHA connType
        interfaces { @IFACE@ }
        sockets { id serial isPrimary platform version }
        ipsec { isPrimary catoIP remoteIP ikeVersion }
      }
      devices {
        id name identifier connected haRole type lastConnected connectedSince lastPopName
        internalIP version osType osVersion
        socketInfo { id serial isPrimary platform version }
        interfaces {
          id name connected physicalPort popName tunnelUptime tunnelRemoteIP type
          tunnelRemoteIPInfo { ip countryName city provider }
          info { @IFACE@ }
        }
      }
    }
  }
}
""".replace("@IFACE@", _INTERFACE_INFO)

# Used when Cato refuses the full query: the Sockets and their WAN links
# without the detail (HA state, bandwidth, provider) a schema may lack. The
# WAN links' public addresses tie a vSocket to its AWS or Azure instance.
SITES_QUERY_WAN = """
query plexusSitesWan($accountID: ID!) {
  accountSnapshot(accountID: $accountID) {
    id
    sites {
      id
      connectivityStatus
      popName
      info { name type description connType isHA }
      devices {
        id name connected haRole lastPopName internalIP
        socketInfo { serial isPrimary platform }
        interfaces { id name connected popName tunnelRemoteIP }
      }
    }
  }
}
"""

# Used when Cato refuses that too: the fields every schema version has.
SITES_QUERY_BASIC = """
query plexusSitesBasic($accountID: ID!) {
  accountSnapshot(accountID: $accountID) {
    id
    sites {
      id
      connectivityStatus
      popName
      info { name type description connType isHA }
      devices { id name connected }
    }
  }
}
"""

USERS_QUERY = """
query plexusUsers($accountID: ID!) {
  accountSnapshot(accountID: $accountID) {
    users {
      id name connectivityStatus operationalStatus deviceName uptime lastConnected version
      popName remoteIP internalIP osType osVersion connectedInOffice
      remoteIPInfo { ip countryCode countryName city state provider latitude longitude }
      info { name status email phoneNumber origin authMethod }
      recentConnections {
        duration interfaceName deviceName lastConnected popName remoteIP
        remoteIPInfo { countryName city state provider }
      }
    }
  }
}
"""

# Used when Cato refuses the full query: the user fields every schema has.
USERS_QUERY_BASIC = """
query plexusUsersBasic($accountID: ID!) {
  accountSnapshot(accountID: $accountID) {
    users {
      id name connectivityStatus operationalStatus deviceName uptime lastConnected version
      popName remoteIP internalIP osType osVersion connectedInOffice
      remoteIPInfo { countryName city provider }
      info { name status email origin authMethod }
    }
  }
}
"""

LOOKUP_QUERY = """
query plexusLookup($accountID: ID!, $type: EntityType!, $limit: Int, $from: Int) {
  entityLookup(accountID: $accountID, type: $type, limit: $limit, from: $from) {
    total
    items { entity { id name type } description helperFields }
  }
}
"""

VALIDATE_QUERY = """
query plexusValidate($accountID: ID!) {
  accountSnapshot(accountID: $accountID) { id }
}
"""


def sanitize_options(raw: object) -> dict[str, Any]:
    """Coerce stored/user-supplied build options onto the known schema."""
    src = raw if isinstance(raw, dict) else {}
    opts = dict(DEFAULT_OPTIONS)
    for key in _BOOL_OPTIONS:
        if key in src:
            opts[key] = bool(src[key])
    opts["site_name_contains"] = str(src.get("site_name_contains") or "").strip()[:200]
    return opts


def _error(scope: str, path: str, exc: CatoApiError) -> dict[str, Any]:
    message = f"{exc}: {exc.detail}" if exc.detail else str(exc)
    return {"scope": scope, "path": path, "status": exc.status_code, "message": message}


async def _lookup(client: CatoClient, account_id: str, entity_type: str) -> list[dict]:
    """Every entity of one type, following ``from``/``limit`` paging."""
    items: list[dict] = []
    page_size = _LOOKUP_PAGE_SIZE
    while len(items) < _MAX_LOOKUP_ITEMS:
        variables = {"accountID": account_id, "type": entity_type, "limit": page_size, "from": len(items)}
        try:
            data = await client.query("plexusLookup", LOOKUP_QUERY, variables)
        except CatoApiError as exc:
            # The largest page a tenant accepts is not documented; fall back
            # to the API's default page size before giving up.
            if exc.graphql and not items and page_size != _LOOKUP_FALLBACK_PAGE_SIZE:
                page_size = _LOOKUP_FALLBACK_PAGE_SIZE
                continue
            raise
        result = data.get("entityLookup") or {}
        page = [i for i in result.get("items") or [] if isinstance(i, dict)]
        items.extend(page)
        try:
            total = int(result.get("total") or 0)
        except TypeError, ValueError:
            total = 0
        if not page or len(items) >= total:
            break
    return items


async def collect_account(
    client: CatoClient,
    account_id: str,
    options: dict[str, Any] | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Collect one account. Raises ``CatoApiError`` only if the site list
    cannot be read."""
    opts = sanitize_options(options)
    errors: list[dict[str, Any]] = []
    total = 1 + int(opts["include_users"]) + 2 * int(opts["include_ranges"])
    done = 0

    def report(phase: str, **fields: Any) -> None:
        if progress is not None:
            progress({"phase": phase, "calls_done": done, "calls_total": total, **fields})

    variables = {"accountID": account_id}

    report("cato sites")
    try:
        data = await client.query("plexusSites", SITES_QUERY, variables)
    except CatoApiError as exc:
        if not exc.graphql:
            raise
        errors.append(_error("account", "accountSnapshot.sites (full detail)", exc))
        try:
            data = await client.query("plexusSitesWan", SITES_QUERY_WAN, variables)
        except CatoApiError as exc:
            if not exc.graphql:
                raise
            errors.append(_error("account", "accountSnapshot.sites (WAN links)", exc))
            data = await client.query("plexusSitesBasic", SITES_QUERY_BASIC, variables)
    done += 1
    snapshot = scrub_secrets(data.get("accountSnapshot") or {})
    needle = opts["site_name_contains"].lower()
    sites = [
        s
        for s in snapshot.get("sites") or []
        if isinstance(s, dict)
        and s.get("id") is not None
        and (not needle or needle in str((s.get("info") or {}).get("name") or "").lower())
    ]
    report("cato sites", networks=len(sites), devices=sum(len(s.get("devices") or []) for s in sites))

    users: list[dict] = []
    if opts["include_users"]:
        report("cato users")
        try:
            try:
                data = await client.query("plexusUsers", USERS_QUERY, variables)
            except CatoApiError as exc:
                if not exc.graphql:
                    raise
                errors.append(_error("account", "accountSnapshot.users (full detail)", exc))
                data = await client.query("plexusUsersBasic", USERS_QUERY_BASIC, variables)
            found = scrub_secrets((data.get("accountSnapshot") or {}).get("users") or [])
            users = [u for u in found if isinstance(u, dict)]
        except CatoApiError as exc:
            errors.append(_error("account", "accountSnapshot.users", exc))
        done += 1

    lookups: dict[str, list[dict]] = {"siteRange": [], "networkInterface": []}
    if opts["include_ranges"]:
        for entity_type in lookups:
            report("cato ranges")
            try:
                lookups[entity_type] = scrub_secrets(await _lookup(client, account_id, entity_type))
            except CatoApiError as exc:
                errors.append(_error("account", f"entityLookup {entity_type}", exc))
            done += 1

    report("collected")
    LOGGER.info(
        "cato: collected account %s - %d sites, %d users, %d calls, %d errors",
        account_id,
        len(sites),
        len(users),
        client.stats["requests"],
        len(errors),
    )
    return {
        "account": {"id": str(account_id)},
        "timestamp": snapshot.get("timestamp") or "",
        "sites": sites,
        "users": users,
        "ranges": lookups["siteRange"],
        "interfaces": lookups["networkInterface"],
        "errors": errors,
        "stats": dict(client.stats),
        "options": opts,
    }
