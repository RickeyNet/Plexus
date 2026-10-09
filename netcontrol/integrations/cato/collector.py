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
  - ``site.bgpPeerList``        the BGP peers of every site, for path tracing:
                                Cato has no route table in its API, so a site
                                with a BGP peer may learn routes not collected.
                                One call per site: the schema (confirmed from
                                Cato's CLI repository,
                                ``queryPayloads/query.site.bgpPeerList.txt``)
                                has no account-wide form
  - ``policy.wanFirewall``      the WAN firewall rules (site, user and range
                                to site, user and range), for path tracing
  - ``policy.internetFirewall`` the Internet firewall rules, for path tracing

Failure policy: the site list is required; everything else is best-effort and
a failure is recorded in ``errors`` and surfaced in the map's collection
report. GraphQL rejects a whole query when it names one field the schema does
not have, so the site, user, BGP peer and firewall queries have reduced
fallbacks: a schema difference costs detail (HA state, recent connections,
ASNs and advertised routes, the rarer rule fields, and only as a last resort
the WAN links), not the map.
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
    # Network ranges (subnets) behind every site, and the sites' BGP peers:
    # the routing data path tracing has.
    "include_ranges": True,
    # The WAN and Internet firewall rules, which path tracing evaluates at
    # the Cato Cloud.
    "include_firewall": True,
    # Attach data Plexus already collected over SNMP/SSH for inventory hosts
    # that match a Socket.
    "inventory_enrich": True,
}

_BOOL_OPTIONS = ("include_users", "include_ranges", "include_firewall", "inventory_enrich")

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

# The BGP peers of one site hang off ``site(accountId:)``, spelled like
# ``policy(accountId:)`` below. The schema is confirmed from Cato's CLI
# repository (``queryPayloads/query.site.bgpPeerList.txt``): ``input`` is
# required and names one site, so there is no account-wide list, and the
# payload holds ``bgpPeer`` (a list) and ``total``. The ASNs and what Cato
# advertises to the peer are detail for the node's table. ``md5AuthKey`` is a
# secret and is never selected.
BGP_PEERS_OF_SITE_QUERY = """
query plexusBgpPeersOfSite($accountId: ID!, $input: BgpPeerListInput!) {
  site(accountId: $accountId) {
    bgpPeerList(input: $input) {
      bgpPeer {
        id name site { id name } peerAsn catoAsn peerIp catoIp
        advertiseDefaultRoute advertiseAllRoutes advertiseSummaryRoutes summaryRoute { route }
      }
      total
    }
  }
}
"""

# Used when Cato refuses the full query: which sites have a BGP peer, which
# is all path tracing needs.
BGP_PEERS_OF_SITE_QUERY_BASIC = """
query plexusBgpPeersOfSiteBasic($accountId: ID!, $input: BgpPeerListInput!) {
  site(accountId: $accountId) {
    bgpPeerList(input: $input) {
      bgpPeer { id name site { id name } peerIp }
      total
    }
  }
}
"""

# The firewall policies hang off ``policy(accountId:)`` - spelled
# ``accountId``, unlike ``accountSnapshot(accountID:)``. A rule's source and
# destination list objects (sites, ranges, users, groups...) by reference.
_REF = "{ id name }"
_ENDPOINT = (
    "ip subnet ipRange { from to } host @REF@ site @REF@ siteNetworkSubnet @REF@ networkInterface @REF@ "
    "floatingSubnet @REF@ user @REF@ usersGroup @REF@ group @REF@ systemGroup @REF@ globalIpRange @REF@"
)
_SERVICE = "standard @REF@ custom { port portRange { from to } protocol }"
_APPS = "application @REF@ customApp @REF@ appCategory @REF@ customCategory @REF@ sanctionedAppsCategory @REF@"
_RULE_CONTEXT = "connectionOrigin country @REF@ device @REF@ deviceOS schedule { activeOn } exceptions { name }"

WAN_FIREWALL_QUERY = (
    """
query plexusWanFirewall($accountId: ID!) {
  policy(accountId: $accountId) {
    wanFirewall {
      policy {
        enabled
        rules {
          rule {
            id name description index enabled action direction
            section @REF@
            source { @ENDPOINT@ }
            destination { @ENDPOINT@ }
            application { @APPS@ domain fqdn ip subnet ipRange { from to } globalIpRange @REF@ }
            service { @SERVICE@ }
            @CONTEXT@
          }
        }
      }
    }
  }
}
""".replace("@ENDPOINT@", _ENDPOINT)
    .replace("@APPS@", _APPS)
    .replace("@SERVICE@", _SERVICE)
    .replace("@CONTEXT@", _RULE_CONTEXT)
    .replace("@REF@", _REF)
)

# Used when Cato refuses the full query: what a rule matches on by address
# and port. The normalizer treats such rules as incomplete.
WAN_FIREWALL_QUERY_BASIC = """
query plexusWanFirewallBasic($accountId: ID!) {
  policy(accountId: $accountId) {
    wanFirewall {
      policy {
        enabled
        rules {
          rule {
            id name index enabled action direction
            source { ip subnet }
            destination { ip subnet }
            service { custom { port portRange { from to } protocol } }
          }
        }
      }
    }
  }
}
"""

INTERNET_FIREWALL_QUERY = (
    """
query plexusInternetFirewall($accountId: ID!) {
  policy(accountId: $accountId) {
    internetFirewall {
      policy {
        enabled
        rules {
          rule {
            id name description index enabled action
            section @REF@
            source { @ENDPOINT@ }
            destination {
              ip subnet ipRange { from to } fqdn domain country @REF@ @APPS@ remoteAsn globalIpRange @REF@
            }
            service { @SERVICE@ }
            @CONTEXT@
          }
        }
      }
    }
  }
}
""".replace("@ENDPOINT@", _ENDPOINT)
    .replace("@APPS@", _APPS)
    .replace("@SERVICE@", _SERVICE)
    .replace("@CONTEXT@", _RULE_CONTEXT)
    .replace("@REF@", _REF)
)

# Used when Cato refuses the full query (see WAN_FIREWALL_QUERY_BASIC).
INTERNET_FIREWALL_QUERY_BASIC = """
query plexusInternetFirewallBasic($accountId: ID!) {
  policy(accountId: $accountId) {
    internetFirewall {
      policy {
        enabled
        rules {
          rule {
            id name index enabled action
            source { ip subnet }
            destination { ip subnet }
            service { custom { port portRange { from to } protocol } }
          }
        }
      }
    }
  }
}
"""

# (payload key, GraphQL field, full query, reduced query)
_FIREWALLS = (
    ("wan_firewall", "wanFirewall", WAN_FIREWALL_QUERY, WAN_FIREWALL_QUERY_BASIC),
    ("internet_firewall", "internetFirewall", INTERNET_FIREWALL_QUERY, INTERNET_FIREWALL_QUERY_BASIC),
)

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


def _peer_items(data: dict) -> list[dict]:
    items = ((data.get("site") or {}).get("bgpPeerList") or {}).get("bgpPeer") or []
    return [p for p in items if isinstance(p, dict)]


async def _bgp_peers(
    client: CatoClient, account_id: str, site_ids: list[str], errors: list[dict[str, Any]]
) -> list[dict]:
    """The BGP peers of every site, as Cato returns them: one call per site,
    in full until Cato refuses that, then with the reduced fields for that
    site and the rest. Raises the ``CatoApiError`` of the reduced query if
    Cato refuses that too."""
    reduced = False
    peers: list[dict] = []
    for site_id in site_ids:
        variables = {"accountId": account_id, "input": {"site": {"by": "ID", "input": site_id}}}
        data: dict | None = None
        if not reduced:
            try:
                data = await client.query("plexusBgpPeersOfSite", BGP_PEERS_OF_SITE_QUERY, variables)
            except CatoApiError as exc:
                if not exc.graphql:
                    raise
                errors.append(_error("account", "site.bgpPeerList (full detail)", exc))
                reduced = True
        if data is None:
            data = await client.query("plexusBgpPeersOfSiteBasic", BGP_PEERS_OF_SITE_QUERY_BASIC, variables)
        for peer in _peer_items(data):
            # The site asked for is the peer's, whether Cato names it or not.
            peers.append({**peer, "site": peer.get("site") or {"id": site_id}})
    return scrub_secrets(peers)


async def _firewall(
    client: CatoClient, account_id: str, field: str, full: str, basic: str, errors: list[dict[str, Any]]
) -> dict[str, Any]:
    """One firewall policy: ``{"enabled", "rules", "reduced"}``, the rules
    as Cato returns them. ``reduced`` is set when Cato refused the full query
    and the rules hold only their addresses and ports."""
    variables = {"accountId": account_id}
    operation = "plexus" + field[0].upper() + field[1:]
    reduced = False
    try:
        data = await client.query(operation, full, variables)
    except CatoApiError as exc:
        if not exc.graphql:
            raise
        errors.append(_error("account", f"policy.{field} (full detail)", exc))
        reduced = True
        data = await client.query(f"{operation}Basic", basic, variables)
    policy = ((data.get("policy") or {}).get(field) or {}).get("policy") or {}
    rules = [r.get("rule") for r in policy.get("rules") or [] if isinstance(r, dict)]
    return {
        "enabled": policy.get("enabled", True) is not False,
        "rules": scrub_secrets([r for r in rules if isinstance(r, dict)]),
        "reduced": reduced,
    }


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
    total = (
        1
        + int(opts["include_users"])
        + 3 * int(opts["include_ranges"])
        + len(_FIREWALLS) * int(opts["include_firewall"])
    )
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

    # None: not collected, so the normalizer tells it from a site with no peer.
    bgp_peers: list[dict] | None = None
    if opts["include_ranges"]:
        report("cato routing")
        try:
            bgp_peers = await _bgp_peers(client, account_id, [str(s["id"]) for s in sites], errors)
        except CatoApiError as exc:
            errors.append(_error("account", "site.bgpPeerList", exc))
        done += 1

    # None: not collected, so the normalizer tells it from an empty policy.
    firewalls: dict[str, dict[str, Any] | None] = {key: None for key, *_rest in _FIREWALLS}
    if opts["include_firewall"]:
        for key, field, full, basic in _FIREWALLS:
            report("cato firewall")
            try:
                firewalls[key] = await _firewall(client, account_id, field, full, basic, errors)
            except CatoApiError as exc:
                errors.append(_error("account", f"policy.{field}", exc))
            done += 1

    def rule_count(key: str) -> int:
        return len((firewalls[key] or {}).get("rules") or [])

    report("collected")
    LOGGER.info(
        "cato: collected account %s - %d sites, %d users, %d BGP peers, %d WAN and %d internet firewall rules, "
        "%d calls, %d errors",
        account_id,
        len(sites),
        len(users),
        len(bgp_peers or []),
        rule_count("wan_firewall"),
        rule_count("internet_firewall"),
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
        "bgp_peers": bgp_peers,
        "wan_firewall": firewalls["wan_firewall"],
        "internet_firewall": firewalls["internet_firewall"],
        "errors": errors,
        "stats": dict(client.stats),
        "options": opts,
    }
