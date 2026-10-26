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
  - ``policy.splitTunnel``      the Split Tunnel policy (which traffic of a
                                remote user's Cato Client leaves the device
                                directly), read with the users. ``@beta`` in
                                Cato's schema; the key needs the SDP Split
                                Tunnel permission
  - ``events``                  the latest Client Connectivity Policy event
                                of each user device (last 7 days): the
                                Split Tunnel configuration the Client
                                applied, read with the users by
                                ``client_reports.collect_client_reports``
  - ``object.globalIpRangeList`` the account's global IP range objects, so a
                                firewall or Split Tunnel rule that names one
                                can be evaluated
  - ``policy.<the other 15>``   every other policy Cato's API has (``POLICIES``
                                lists all 18), for the details of the Cato
                                Cloud and of the sites and users they name;
                                listed, not applied in path tracing
  - ``policy.<x>.policyList``   the sub-policies of the WAN, Internet and
                                Socket LAN firewalls (listed, not evaluated)
  - ``groups``, ``user.usersGroupList``, ``container.list``,
    ``customAppData``           the objects rules name: groups and users
                                groups with their members (so a rule naming
                                one can be resolved), IP range and FQDN
                                containers, custom applications
  - ``site.*``, ``networkConfig``, ``accountManagement``
                                the configuration of every site and the
                                account's DHCP and DNS configuration, read
                                by ``site_config.collect_site_config``
                                (several queries per site)

Failure policy: the site list is required; everything else is best-effort and
a failure is recorded in ``errors`` and surfaced in the map's collection
report. GraphQL rejects a whole query when it names one field the schema does
not have, so the site, user, BGP peer and policy queries have reduced
fallbacks: a schema difference costs detail (HA state, recent connections,
ASNs and advertised routes, the rarer rule fields, and only as a last resort
the WAN links), not the map. Every policy is ``@beta`` in Cato's schema and
may need a permission of its own on the API key: one that is refused is
recorded as not collected and the rest still load.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, NamedTuple

from netcontrol.integrations.cato.client import CatoApiError, CatoClient, error_entry, note_entry
from netcontrol.integrations.cato.client_reports import collect_client_reports
from netcontrol.integrations.cato.site_config import collect_site_config, planned_calls
from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.cato")

DEFAULT_OPTIONS: dict[str, Any] = {
    # Limit the build to sites whose name contains this text. Empty = all.
    "site_name_contains": "",
    # Remote users connected with the Cato Client, and the Split Tunnel
    # policy that decides which of their traffic goes to Cato.
    "include_users": True,
    # Network ranges (subnets) behind every site, and the sites' BGP peers:
    # the routing data path tracing has.
    "include_ranges": True,
    # The WAN and Internet firewall rules, which path tracing evaluates at
    # the Cato Cloud, and the global IP range objects the rules name.
    "include_firewall": True,
    # Every other policy (WAN network, Socket LAN, TLS inspection, client
    # connectivity, IP allocation...) and the objects rules name (groups,
    # users groups, containers, custom applications).
    "include_policies": True,
    # The configuration of every site (network ranges with DHCP, static and
    # known hosts, Socket configuration, location, backhauling, Wi-Fi SSIDs,
    # DNS override) and the account's DHCP and DNS configuration: several
    # queries per site, see ``site_config``.
    "include_site_config": True,
    # With the users: the latest Client Connectivity Policy event of each
    # user device (last 7 days, Cato's ``events``), the Split Tunnel
    # configuration the Client reports applying. See ``client_reports``.
    "include_client_reports": True,
    # Attach data Plexus already collected over SNMP/SSH for inventory hosts
    # that match a Socket.
    "inventory_enrich": True,
}

_BOOL_OPTIONS = (
    "include_users",
    "include_ranges",
    "include_firewall",
    "include_policies",
    "include_site_config",
    "include_client_reports",
    "inventory_enrich",
)

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

# ── Policies ───────────────────────────────────────────────────────────────
#
# Every policy hangs off ``policy(accountId:)`` - spelled ``accountId``,
# unlike ``accountSnapshot(accountID:)`` - as ``<field> { policy { enabled
# rules { rule { ... } } } }``; ``policy`` with no ``input`` reads the
# published policy. The rule fields are Cato's schema (the public SDL at
# api.catonetworks.com/api/schema), every one of them except secrets: a
# rule names objects (sites, ranges, users, groups...) by ``{ id name }``.
# Macros keep the shapes the policies share in one place; ``_expand``
# resolves them.
_MACROS = {
    "@REF@": "{ id name }",
    "@RANGE@": "{ from to }",
    "@BASE@": "id name description index enabled section @REF@",
    # A source or destination of the WAN and Internet firewalls, the WAN
    # network policy and TLS inspection.
    "@ENDPOINT@": (
        "ip subnet ipRange @RANGE@ host @REF@ site @REF@ siteNetworkSubnet @REF@ networkInterface @REF@ "
        "floatingSubnet @REF@ user @REF@ usersGroup @REF@ group @REF@ systemGroup @REF@ globalIpRange @REF@"
    ),
    # A source or destination on a Socket's LAN (Socket LAN, Socket bypass).
    "@LAN_ENDPOINT@": (
        "ip subnet ipRange @RANGE@ vlan host @REF@ siteNetworkSubnet @REF@ networkInterface @REF@ "
        "floatingSubnet @REF@ group @REF@ globalIpRange @REF@"
    ),
    "@SERVICE@": "standard @REF@ custom { port portRange @RANGE@ protocol }",
    "@SOCKET_SERVICE@": "custom { port portRange @RANGE@ protocol } simple { name }",
    "@SERVICE_APP@": "customService { port portRange @RANGE@ protocol } customServiceIp { name ip ipRange @RANGE@ } service @REF@",
    "@APPS@": "application @REF@ customApp @REF@ appCategory @REF@ customCategory @REF@ sanctionedAppsCategory @REF@",
    "@SCHEDULE@": "schedule { activeOn customRecurring { days from to } customTimeframe { from to } }",
    "@ALERT@": "enabled frequency mailingList @REF@ subscriptionGroup @REF@ webhook @REF@",
    "@TRACKING@": "tracking { alert { @ALERT@ } event { enabled } }",
    "@ACTIVE_PERIOD@": "activePeriod { effectiveFrom expiresAt useEffectiveFrom useExpiresAt }",
    "@ORIGIN@": "connectionOrigin connectionsOriginList",
    "@DEVICE@": "device @REF@ deviceOS deviceAttributes { category manufacturer model os osVersion type }",
    "@CLIENT_USERS@": "source { user @REF@ usersGroup @REF@ }",
    "@SITES@": "site { site @REF@ group @REF@ }",
    "@WAN_APP@": "@APPS@ domain fqdn ip subnet ipRange @RANGE@ globalIpRange @REF@",
    "@INTERNET_DEST@": (
        "ip subnet ipRange @RANGE@ fqdn domain remoteAsn country @REF@ @APPS@ globalIpRange @REF@ group @REF@ "
        "containers { ipAddressRangeContainer @REF@ fqdnContainer @REF@ }"
    ),
    "@BYPASS_DEST@": "ip subnet ipRange @RANGE@ domain fqdn application @REF@ customApp @REF@ globalIpRange @REF@",
    "@WAN_NETWORK_APP@": (
        "domain fqdn application @REF@ appCategory @REF@ customApp @REF@ customCategory @REF@ @SERVICE_APP@"
    ),
    "@TRANSPORT@": "transportType primaryInterfaceRole secondaryInterfaceRole",
    "@APP_CONTROL@": (
        "action actionConfig { userNotification @REF@ } severity source { country @REF@ @ENDPOINT@ } "
        "application { appCategory @REF@ application @REF@ applicationType customApp @REF@ customCategory @REF@ "
        "sanctionedAppsCategory @REF@ } "
        "accessMethod { accessMethod operator value valueSet @REF@ } "
        "applicationActivity { activity @REF@ field @REF@ operator value valueSet @REF@ } applicationActivitySatisfy "
        "applicationContext { applicationTenant { operator value valueSet @REF@ } } "
        "applicationCriteria { attributes { "
        "complianceAttributes { hippa isae3402 iso27001 pciDss soc1 soc2 soc3 sox } "
        "securityAttributes { auditTrail encryptionAtRest httpSecurityHeaders mfa rbac sso tlsEnforcement "
        "trustedCertificate } } originCountry @REF@ risk { risk riskOperator } } applicationCriteriaSatisfy "
        "device @REF@ @SCHEDULE@ @TRACKING@"
    ),
    "@FILE_ATTRIBUTES@": (
        "fileAttribute { contentTypeGroupValues @REF@ contentTypeValues @REF@ fileAttribute operator value } "
        "fileAttributeSatisfy"
    ),
}


def _expand(text: str) -> str:
    """``text`` with every macro of ``_MACROS`` resolved."""
    while "@" in text:
        expanded = text
        for macro, value in _MACROS.items():
            expanded = expanded.replace(macro, value)
        if expanded == text:
            break
        text = expanded
    return text


def _operation(field: str, suffix: str = "") -> str:
    """The operation name of a policy query: ``plexusWanFirewall``."""
    return "plexus" + field[0].upper() + field[1:] + suffix


def _policy_query(field: str, rule: str, *, policy: str = "", reduced: bool = False) -> str:
    """The query of one policy: its state, ``policy`` (fields of the policy
    itself), and ``rule`` for each rule."""
    return _expand(
        f"""
query {_operation(field, "Basic" if reduced else "")}($accountId: ID!) {{
  policy(accountId: $accountId) {{
    {field} {{
      policy {{
        enabled {policy}
        rules {{
          rule {{ {rule} }}
        }}
      }}
    }}
  }}
}}
"""
    )


# What every rule of every policy has: the reduced query of the policies
# path tracing does not evaluate.
_BASIC_RULE = "id name index enabled"

WAN_FIREWALL_QUERY = _policy_query(
    "wanFirewall",
    "@BASE@ action direction @ORIGIN@ "
    "source { @ENDPOINT@ } destination { @ENDPOINT@ } application { @WAN_APP@ } service { @SERVICE@ } "
    "country @REF@ @DEVICE@ @SCHEDULE@ @ACTIVE_PERIOD@ @TRACKING@ actionConfig { userNotification @REF@ } "
    "exceptions { name direction @ORIGIN@ source { @ENDPOINT@ } destination { @ENDPOINT@ } "
    "application { @WAN_APP@ } service { @SERVICE@ } country @REF@ @DEVICE@ }",
)

# Used when Cato refuses the full query: what a rule matches on by address
# and port. The normalizer treats such rules as incomplete.
WAN_FIREWALL_QUERY_BASIC = _policy_query(
    "wanFirewall",
    "id name index enabled action direction source { ip subnet } destination { ip subnet } "
    "service { custom { port portRange @RANGE@ protocol } }",
    reduced=True,
)

INTERNET_FIREWALL_QUERY = _policy_query(
    "internetFirewall",
    "@BASE@ action @ORIGIN@ source { @ENDPOINT@ } destination { @INTERNET_DEST@ } service { @SERVICE@ } "
    "country @REF@ @DEVICE@ @SCHEDULE@ @ACTIVE_PERIOD@ @TRACKING@ "
    "actionConfig { rbiProfile @REF@ userNotification @REF@ } "
    "exceptions { name @ORIGIN@ source { @ENDPOINT@ } destination { @INTERNET_DEST@ } service { @SERVICE@ } "
    "country @REF@ @DEVICE@ }",
)

# Used when Cato refuses the full query (see WAN_FIREWALL_QUERY_BASIC).
INTERNET_FIREWALL_QUERY_BASIC = _policy_query(
    "internetFirewall",
    "id name index enabled action source { ip subnet } destination { ip subnet } "
    "service { custom { port portRange @RANGE@ protocol } }",
    reduced=True,
)

# The Split Tunnel policy (Access > Split Tunnel Policy): an ordered rule base
# that picks, per remote user, which traffic the Cato Client sends to Cato and
# which leaves the device directly. Its fields are also confirmed from Cato's
# CLI repository (``queryPayloads/query.policy.splitTunnel.policy.txt``).
# Domains, FQDNs and the DNS exclusions are plain strings; destination IP
# ranges are global IP range objects, resolved like the firewall rules' ones.
SPLIT_TUNNEL_QUERY = _policy_query(
    "splitTunnel",
    "@BASE@ action source { user @REF@ usersGroup @REF@ } platform country @REF@ "
    "destination { application @REF@ globalIpRange @REF@ domain fqdn } sourceNetwork { sourceNetworkType } "
    "coverage dnsExclusion { domain } routingPriority",
)

# Used when Cato refuses the full query: who a rule applies to and the IP
# ranges it names. The normalizer treats such rules as incomplete.
SPLIT_TUNNEL_QUERY_BASIC = _policy_query(
    "splitTunnel",
    "id name index enabled action source { user @REF@ usersGroup @REF@ } platform "
    "destination { globalIpRange @REF@ } sourceNetwork { sourceNetworkType }",
    reduced=True,
)


class PolicySpec(NamedTuple):
    key: str  # payload key, the snake_case of ``field``
    field: str  # field of ``policy(accountId:)``
    label: str  # name of the policy in the details
    full: str  # every rule field
    basic: str  # the fields every schema version has
    option: str  # build option that asks for it


def _spec(key: str, field: str, label: str, rule: str, *, policy: str = "") -> PolicySpec:
    """A policy path tracing does not evaluate: listed in the details."""
    return PolicySpec(
        key,
        field,
        label,
        _policy_query(field, rule, policy=policy),
        _policy_query(field, _BASIC_RULE, reduced=True),
        "include_policies",
    )


# Every policy of Cato's API (``type PolicyQueries``), in the order they are
# read. The first three are evaluated by path tracing; the rest are listed.
POLICIES: tuple[PolicySpec, ...] = (
    PolicySpec(
        "wan_firewall", "wanFirewall", "WAN firewall", WAN_FIREWALL_QUERY, WAN_FIREWALL_QUERY_BASIC, "include_firewall"
    ),
    PolicySpec(
        "internet_firewall",
        "internetFirewall",
        "Internet firewall",
        INTERNET_FIREWALL_QUERY,
        INTERNET_FIREWALL_QUERY_BASIC,
        "include_firewall",
    ),
    # Read with the users it routes.
    PolicySpec(
        "split_tunnel", "splitTunnel", "Split Tunnel", SPLIT_TUNNEL_QUERY, SPLIT_TUNNEL_QUERY_BASIC, "include_users"
    ),
    _spec(
        "anti_malware_file_hash",
        "antiMalwareFileHash",
        "Anti-malware file hash",
        "@BASE@ action fileName sha256 expirationDate",
    ),
    _spec(
        "application_control",
        "applicationControl",
        "Application control",
        "@BASE@ ruleType applicationRule { @APP_CONTROL@ } "
        "dataRule { @APP_CONTROL@ dlpProfile { contentProfile @REF@ edmProfile @REF@ } @FILE_ATTRIBUTES@ } "
        "fileRule { @APP_CONTROL@ @FILE_ATTRIBUTES@ }",
        policy="additionalAttributes { dataControlEnabled }",
    ),
    _spec(
        "app_tenant_restriction",
        "appTenantRestriction",
        "App tenant restriction",
        "@BASE@ action severity application @REF@ headers { name value } @SCHEDULE@ "
        "source { country @REF@ @ENDPOINT@ }",
    ),
    _spec(
        "client_connectivity",
        "clientConnectivity",
        "Client connectivity",
        "@BASE@ action confidenceLevel connectionOrigin platform country @REF@ device @REF@ @CLIENT_USERS@ "
        "sourceRange { globalIpRange @REF@ }",
    ),
    _spec(
        "dynamic_ip_allocation",
        "dynamicIpAllocation",
        "Dynamic IP allocation",
        "@BASE@ platform country @REF@ devicePostureProfile @REF@ range { globalIpRange @REF@ } @CLIENT_USERS@",
    ),
    _spec(
        "private_access",
        "privateAccess",
        "Private access",
        "@BASE@ action { action } @ORIGIN@ platform applications { application @REF@ } country @REF@ device @REF@ "
        "@SCHEDULE@ @ACTIVE_PERIOD@ @TRACKING@ source { user @REF@ usersGroup @REF@ systemGroup @REF@ } "
        "userAttributes { riskScore { category operator } }",
    ),
    _spec(
        "remote_port_fwd",
        "remotePortFwd",
        "Remote port forwarding",
        "@BASE@ forwardIcmp internalIp restrictionType externalIp @REF@ externalPortRange @RANGE@ "
        "internalPortRange @RANGE@ remoteIPs { ip subnet ipRange @RANGE@ globalIpRange @REF@ } tracking { @ALERT@ }",
    ),
    _spec(
        "sdp_static_ip_allocation",
        "sdpStaticIpAllocation",
        "SDP static IP allocation",
        "@BASE@ ip source { user @REF@ }",
    ),
    # ``authenticationConfig.kerberosConfig.encryptedKeytab`` is a secret
    # and is never selected.
    _spec(
        "site_web_proxy",
        "siteWebProxy",
        "Site web proxy",
        "@BASE@ allowedDestinationProtocol fqdn port shouldAssociateWithAllSites associatedSite @REF@ "
        "authenticationConfig { method kerberosConfig { isEnabled } } "
        "webProxyTraffic { rule { @BASE@ action destination { domain fqdn ip } "
        "source { ip subnet ipRange @RANGE@ site @REF@ siteNetworkSubnet @REF@ networkInterface @REF@ "
        "group @REF@ globalIpRange @REF@ } } }",
    ),
    _spec(
        "socket_bypass",
        "socketBypass",
        "Socket bypass",
        "@BASE@ action { port event { enabled } } @SITES@ source { @LAN_ENDPOINT@ } "
        "destination { @BYPASS_DEST@ } service { @SOCKET_SERVICE@ } "
        "exception { name @SITES@ source { @LAN_ENDPOINT@ } destination { @BYPASS_DEST@ } "
        "service { @SOCKET_SERVICE@ } }",
    ),
    _spec(
        "socket_lan",
        "socketLan",
        "Socket LAN",
        "@BASE@ direction transport @SITES@ source { @LAN_ENDPOINT@ systemGroup @REF@ } "
        "destination { @LAN_ENDPOINT@ systemGroup @REF@ } service { @SOCKET_SERVICE@ } nat { enabled natType } "
        "firewall { ruleType subPolicy @REF@ rule { @BASE@ action direction "
        "application { ip subnet ipRange @RANGE@ domain fqdn application @REF@ customApp @REF@ "
        "globalIpRange @REF@ } "
        "source { @LAN_ENDPOINT@ systemGroup @REF@ site @REF@ mac } "
        "destination { @LAN_ENDPOINT@ systemGroup @REF@ site @REF@ } "
        "service { @SOCKET_SERVICE@ standard @REF@ } @TRACKING@ } }",
    ),
    _spec("terminal_server", "terminalServer", "Terminal server", "@BASE@ allowedHostIP @REF@ excludeTraffic @REF@"),
    _spec(
        "tls_inspect",
        "tlsInspect",
        "TLS inspection",
        "@BASE@ action untrustedCertificateAction @ORIGIN@ platform country @REF@ devicePostureProfile @REF@ "
        "source { @ENDPOINT@ } application { ip subnet ipRange @RANGE@ domain fqdn remoteAsn tlsInspectCategory "
        "country @REF@ globalIpRange @REF@ application @REF@ appCategory @REF@ customApp @REF@ "
        "customCategory @REF@ @SERVICE_APP@ }",
        policy="additionalAttributes { defaultRuleAction defaultRuleUntrustedCertificateAction }",
    ),
    _spec(
        "wan_network",
        "wanNetwork",
        "WAN network",
        "@BASE@ ruleType routeType bandwidthPriority @REF@ source { @ENDPOINT@ } destination { @ENDPOINT@ } "
        "application { @WAN_NETWORK_APP@ } configuration { activeTcpAcceleration packetLossMitigation "
        "preserveSourcePort allocationIp @REF@ backhaulingSite @REF@ popLocation @REF@ "
        "primaryTransport { @TRANSPORT@ } secondaryTransport { @TRANSPORT@ } } "
        "exceptions { name source { @ENDPOINT@ } destination { @ENDPOINT@ } application { @WAN_NETWORK_APP@ } }",
    ),
    _spec(
        "ztna_always_on",
        "ztnaAlwaysOn",
        "ZTNA always-on",
        "@BASE@ action allowFailOpen allowUserBypass antiTamperMode platform bypassDuration { time unit } "
        "devicePostureProfile @REF@ @CLIENT_USERS@",
    ),
)

# The policies with sub-policies (policy levels): their ``policyList``,
# read as ``<key>_policies``. Listed only: path tracing evaluates the main
# policy. (payload key, GraphQL field, list input type)
POLICY_LISTS = (
    ("wan_firewall", "wanFirewall", "WanFirewallPolicyListInput"),
    ("internet_firewall", "internetFirewall", "InternetFirewallPolicyListInput"),
    ("socket_lan", "socketLan", "SocketLanPolicyListInput"),
)

_SPEC = {spec.key: spec for spec in POLICIES}
# The progress phase of a policy, by the option that asks for it.
_PHASES = {"include_firewall": "cato firewall", "include_users": "cato split tunnel"}


def _policy_list_query(field: str, input_type: str) -> str:
    return f"""
query {_operation(field, "Policies")}($accountId: ID!, $input: {input_type}!) {{
  policy(accountId: $accountId) {{
    {field} {{
      policyList(input: $input) {{
        items {{ id name description enabled policyLevel }}
        paging {{ total }}
      }}
    }}
  }}
}}
"""


# ── Objects rules name ─────────────────────────────────────────────────────
#
# Groups (sites, ranges, hosts... of any type) and users groups, with their
# members so a rule naming one can be resolved; containers (lists of IP
# ranges or FQDNs, which Cato hands out only as a file download, so their
# contents are not read); custom applications.

GROUP_LIST_QUERY = """
query plexusGroups($accountId: ID!, $input: GroupListInput) {
  groups(accountId: $accountId) {
    groupList(input: $input) {
      items { id name description membersCount membersCountPerType { type membersCount } }
      paging { total }
    }
  }
}
"""

GROUP_MEMBERS_QUERY = """
query plexusGroupMembers($accountId: ID!, $group: GroupRefInput!, $input: GroupMembersListInput!) {
  groups(accountId: $accountId) {
    group(input: $group) {
      id
      members(input: $input) {
        items { id name type }
        paging { total }
      }
    }
  }
}
"""

USERS_GROUP_LIST_QUERY = """
query plexusUsersGroups($accountId: ID!, $input: UsersGroupListInput!) {
  user(accountId: $accountId) {
    usersGroupList(input: $input) {
      items { id name description membersCount importType directoryId }
      paging { total }
    }
  }
}
"""

USERS_GROUP_MEMBERS_QUERY = """
query plexusUsersGroupMembers($accountId: ID!, $group: UsersGroupInput!, $input: UsersGroupMembersInput!) {
  user(accountId: $accountId) {
    usersGroup(input: $group) {
      members(input: $input) {
        items { id displayName email userId }
        paging { total }
      }
    }
  }
}
"""

# ``syncData.url`` may carry a token in its query string: never selected.
CONTAINERS_QUERY = """
query plexusContainers($accountId: ID!, $input: ContainerSearchInput!) {
  container(accountId: $accountId) {
    list(input: $input) {
      containers {
        __typename id name description size
        syncData { fileType timeInterval timeUnit }
        syncDataAudit { errorMsg lastSyncAttempt lastSynced }
      }
    }
  }
}
"""

CUSTOM_APPLICATIONS_QUERY = """
query plexusCustomApplications($accountId: ID!, $input: CustomApplicationListInput!) {
  customAppData(accountId: $accountId) {
    customApplicationList(input: $input) {
      items {
        id name description category { id name }
        criteria {
          protocol port portRange { from to }
          destination { domain fqdn destinationIp { ip subnet ipRange { from to } } }
        }
      }
      paging { total }
    }
  }
}
"""

# Page sizes are the schema's defaults, which every tenant accepts.
_GROUP_PAGE = 100
_USERS_GROUP_PAGE = 50
_POLICY_LIST_PAGE = 100
# Caps: the list of objects, the groups whose members are read (one call or
# more each) and the members read per group (a directory-synced "all
# users" group runs to thousands; 200 pages at the cap). A group past a cap
# keeps ``members: None`` and the cap is a collection error.
_MAX_OBJECTS = 5000
_MAX_GROUPS_WITH_MEMBERS = 500
_MAX_GROUP_MEMBERS = 10000

# The account's global IP ranges: objects defined once (Networking > IP
# Ranges) and named by rules of any policy. ``ipRange`` is ``from-to`` text,
# ``subnet`` the CIDR when the range is one. The schema is confirmed from
# Cato's CLI repository (``queryPayloads/query.object.txt``); the list input
# only filters, there is no paging, so one query returns every object.
GLOBAL_IP_RANGES_QUERY = """
query plexusGlobalIpRanges($accountId: ID!) {
  object(accountId: $accountId) {
    globalIpRangeList {
      items { id name description ipRange subnet }
      total
    }
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


def _cap_error(path: str, message: str) -> dict[str, Any]:
    """A collection error for data left out at a cap, not refused by Cato."""
    return note_entry("account", path, message)


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
                errors.append(error_entry("account", "site.bgpPeerList (full detail)", exc))
                reduced = True
        if data is None:
            data = await client.query("plexusBgpPeersOfSiteBasic", BGP_PEERS_OF_SITE_QUERY_BASIC, variables)
        for peer in _peer_items(data):
            # The site asked for is the peer's, whether Cato names it or not.
            peers.append({**peer, "site": peer.get("site") or {"id": site_id}})
    return scrub_secrets(peers)


async def _policy(
    client: CatoClient, account_id: str, field: str, full: str, basic: str, errors: list[dict[str, Any]]
) -> dict[str, Any]:
    """One policy under ``policy.<field>.policy``: ``{"enabled", "rules",
    "reduced"}``, the rules as Cato returns them, and ``attributes`` (the
    policy's ``additionalAttributes``) when it has them. ``reduced`` is set
    when Cato refused the full query and the rules hold only the fields of
    the reduced one."""
    variables = {"accountId": account_id}
    operation = _operation(field)
    reduced = False
    try:
        data = await client.query(operation, full, variables)
    except CatoApiError as exc:
        if not exc.graphql:
            raise
        errors.append(error_entry("account", f"policy.{field} (full detail)", exc))
        reduced = True
        data = await client.query(f"{operation}Basic", basic, variables)
    policy = ((data.get("policy") or {}).get(field) or {}).get("policy") or {}
    rules = [r.get("rule") for r in policy.get("rules") or [] if isinstance(r, dict)]
    found: dict[str, Any] = {
        "enabled": policy.get("enabled", True) is not False,
        "rules": scrub_secrets([r for r in rules if isinstance(r, dict)]),
        "reduced": reduced,
    }
    if isinstance(policy.get("additionalAttributes"), dict):
        found["attributes"] = scrub_secrets(policy["additionalAttributes"])
    return found


Payload = Callable[[dict], dict]


async def _paged(
    client: CatoClient,
    operation: str,
    query: str,
    variables: dict[str, Any],
    payload: Payload,
    page_size: int,
    limit: int,
) -> tuple[list[dict], int]:
    """``(items, total)`` of a list with ``paging { total }``, read page by
    page with ``input.paging`` until ``total`` or ``limit`` items. ``total``
    is what Cato reports, so a list cut at ``limit`` can be told."""
    items: list[dict] = []
    total = 0
    while len(items) < limit:
        page_input = {**variables.get("input", {}), "paging": {"limit": page_size, "from": len(items)}}
        result = payload(await client.query(operation, query, {**variables, "input": page_input}))
        page = [i for i in result.get("items") or [] if isinstance(i, dict)]
        items.extend(page)
        total = _count((result.get("paging") or {}).get("total"))
        if not page or len(items) >= total:
            break
    return items[:limit], max(total, len(items))


def _count(value: Any) -> int:
    try:
        return int(value or 0)
    except TypeError, ValueError:
        return 0


async def _policy_list(client: CatoClient, account_id: str, field: str, input_type: str) -> list[dict]:
    """The sub-policies of one policy."""
    items, _total = await _paged(
        client,
        _operation(field, "Policies"),
        _policy_list_query(field, input_type),
        {"accountId": account_id},
        lambda data: ((data.get("policy") or {}).get(field) or {}).get("policyList") or {},
        _POLICY_LIST_PAGE,
        _MAX_OBJECTS,
    )
    return scrub_secrets(items)


async def _members(
    client: CatoClient,
    groups: list[dict],
    read: Callable[[dict], Any],
    path: str,
    errors: list[dict[str, Any]],
) -> None:
    """Fill ``members`` of every group, in place: the list ``read(group)``
    returns, or ``None`` when it was not read in full (a cap, or Cato
    refused it; after a refusal no other group is asked). Each cap or
    refusal is one collection error saying how much was read."""
    over_count = {id(g) for g in groups if _count(g.get("membersCount")) > _MAX_GROUP_MEMBERS}
    refused: CatoApiError | None = None
    asked = 0
    for group in groups:
        group["members"] = None
        if id(group) in over_count or asked >= _MAX_GROUPS_WITH_MEMBERS or refused is not None:
            continue
        asked += 1
        try:
            group["members"] = await read(group)
        except CatoApiError as exc:
            refused = exc
    read_in_full = sum(1 for g in groups if g["members"] is not None)
    if refused is not None:
        error = error_entry("account", path, refused)
        error["message"] += f" (members of {read_in_full} of {len(groups)} groups read)"
        errors.append(error)
    if over_count:
        errors.append(
            _cap_error(
                path,
                f"{len(over_count)} groups have more than {_MAX_GROUP_MEMBERS} members: their members were not read",
            )
        )
    skipped = len(groups) - len(over_count) - _MAX_GROUPS_WITH_MEMBERS
    if skipped > 0:
        errors.append(
            _cap_error(
                path,
                f"the members of {skipped} groups were not read: Plexus reads the members of "
                f"{_MAX_GROUPS_WITH_MEMBERS} groups at most",
            )
        )


async def _groups(client: CatoClient, account_id: str, errors: list[dict[str, Any]]) -> list[dict]:
    """The account's groups and their members (``{id name type}`` each)."""
    variables: dict[str, Any] = {"accountId": account_id, "input": {}}
    groups, total = await _paged(
        client,
        "plexusGroups",
        GROUP_LIST_QUERY,
        variables,
        lambda data: (data.get("groups") or {}).get("groupList") or {},
        _GROUP_PAGE,
        _MAX_OBJECTS,
    )
    if total > len(groups):
        errors.append(_cap_error("groups.groupList", f"{len(groups)} of {total} groups read"))

    async def read(group: dict) -> list[dict] | None:
        members, count = await _paged(
            client,
            "plexusGroupMembers",
            GROUP_MEMBERS_QUERY,
            {"accountId": account_id, "group": {"by": "ID", "input": str(group.get("id"))}, "input": {}},
            lambda data: ((data.get("groups") or {}).get("group") or {}).get("members") or {},
            _GROUP_PAGE,
            _MAX_GROUP_MEMBERS,
        )
        return members if count <= len(members) else None

    await _members(client, groups, read, "groups.group.members", errors)
    return scrub_secrets(groups)


async def _users_groups(client: CatoClient, account_id: str, errors: list[dict[str, Any]]) -> list[dict]:
    """The account's users groups and their members (``{id displayName
    email userId}`` each)."""
    groups, total = await _paged(
        client,
        "plexusUsersGroups",
        USERS_GROUP_LIST_QUERY,
        {"accountId": account_id, "input": {}},
        lambda data: (data.get("user") or {}).get("usersGroupList") or {},
        _USERS_GROUP_PAGE,
        _MAX_OBJECTS,
    )
    if total > len(groups):
        errors.append(_cap_error("user.usersGroupList", f"{len(groups)} of {total} users groups read"))

    async def read(group: dict) -> list[dict] | None:
        ref = {"group": {"by": "ID", "input": str(group.get("id"))}}
        members, count = await _paged(
            client,
            "plexusUsersGroupMembers",
            USERS_GROUP_MEMBERS_QUERY,
            {"accountId": account_id, "group": ref, "input": {}},
            lambda data: ((data.get("user") or {}).get("usersGroup") or {}).get("members") or {},
            _USERS_GROUP_PAGE,
            _MAX_GROUP_MEMBERS,
        )
        return members if count <= len(members) else None

    await _members(client, groups, read, "user.usersGroup.members", errors)
    return scrub_secrets(groups)


async def _containers(client: CatoClient, account_id: str) -> list[dict]:
    """The account's containers. Their contents are a file download only
    (``downloadFile``, base64 of an undocumented format): ``members`` is
    ``None``, not read."""
    variables = {"accountId": account_id, "input": {"refs": [], "types": []}}
    data = await client.query("plexusContainers", CONTAINERS_QUERY, variables)
    found = ((data.get("container") or {}).get("list") or {}).get("containers") or []
    return scrub_secrets([{**c, "members": None} for c in found if isinstance(c, dict)][:_MAX_OBJECTS])


async def _custom_applications(client: CatoClient, account_id: str, errors: list[dict[str, Any]]) -> list[dict]:
    items, total = await _paged(
        client,
        "plexusCustomApplications",
        CUSTOM_APPLICATIONS_QUERY,
        {"accountId": account_id, "input": {}},
        lambda data: (data.get("customAppData") or {}).get("customApplicationList") or {},
        _GROUP_PAGE,
        _MAX_OBJECTS,
    )
    if total > len(items):
        errors.append(_cap_error("customAppData.customApplicationList", f"{len(items)} of {total} read"))
    return scrub_secrets(items)


# The objects read with the policies: (payload key, query path).
_OBJECTS: tuple[tuple[str, str], ...] = (
    ("groups", "groups.groupList"),
    ("user_groups", "user.usersGroupList"),
    ("containers", "container.list"),
    ("custom_applications", "customAppData.customApplicationList"),
)


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
    policies = [spec for spec in POLICIES if opts[spec.option]]
    # Sub-policies are other configuration: read with the policies.
    policy_lists = [entry for entry in POLICY_LISTS if opts["include_policies"] and opts[_SPEC[entry[0]].option]]
    read_reports = opts["include_users"] and opts["include_client_reports"]
    total = (
        1
        + int(opts["include_users"])
        # The first page of the Client reports; more pages add to the total.
        + int(read_reports)
        + 3 * int(opts["include_ranges"])
        + len(policies)
        # The global IP ranges, which rules of every policy name.
        + int(bool(policies))
        + len(policy_lists)
        + len(_OBJECTS) * int(opts["include_policies"])
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
        errors.append(error_entry("account", "accountSnapshot.sites (full detail)", exc))
        try:
            data = await client.query("plexusSitesWan", SITES_QUERY_WAN, variables)
        except CatoApiError as exc:
            if not exc.graphql:
                raise
            errors.append(error_entry("account", "accountSnapshot.sites (WAN links)", exc))
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

    # None: not collected, so the normalizer adds no configuration section.
    site_config: dict[str, Any] | None = None
    if opts["include_site_config"]:
        total += planned_calls(len(sites))

        def site_report(phase: str, calls: int = 0, **fields: Any) -> None:
            nonlocal done
            done += calls
            report(phase, **fields)

        site_config = await collect_site_config(client, account_id, sites, errors, report=site_report)

    users: list[dict] = []
    if opts["include_users"]:
        report("cato users")
        try:
            try:
                data = await client.query("plexusUsers", USERS_QUERY, variables)
            except CatoApiError as exc:
                if not exc.graphql:
                    raise
                errors.append(error_entry("account", "accountSnapshot.users (full detail)", exc))
                data = await client.query("plexusUsersBasic", USERS_QUERY_BASIC, variables)
            found = scrub_secrets((data.get("accountSnapshot") or {}).get("users") or [])
            users = [u for u in found if isinstance(u, dict)]
        except CatoApiError as exc:
            errors.append(error_entry("account", "accountSnapshot.users", exc))
        done += 1

    # None: not collected, so the normalizer says so instead of "no report".
    client_reports: dict[str, Any] | None = None
    if read_reports:

        def reports_report(phase: str, calls: int = 0, planned: int = 0, **fields: Any) -> None:
            nonlocal done, total
            done += calls
            total += planned
            report(phase, **fields)

        client_reports = await collect_client_reports(client, account_id, errors, report=reports_report)

    lookups: dict[str, list[dict]] = {"siteRange": [], "networkInterface": []}
    if opts["include_ranges"]:
        for entity_type in lookups:
            report("cato ranges")
            try:
                lookups[entity_type] = scrub_secrets(await _lookup(client, account_id, entity_type))
            except CatoApiError as exc:
                errors.append(error_entry("account", f"entityLookup {entity_type}", exc))
            done += 1

    # None: not collected, so the normalizer tells it from a site with no peer.
    bgp_peers: list[dict] | None = None
    if opts["include_ranges"]:
        report("cato routing")
        try:
            bgp_peers = await _bgp_peers(client, account_id, [str(s["id"]) for s in sites], errors)
        except CatoApiError as exc:
            errors.append(error_entry("account", "site.bgpPeerList", exc))
        done += 1

    # None: not collected, so the normalizer tells it from an empty policy
    # (and, for the Split Tunnel policy, says the users' routing rests on a
    # policy it does not have instead of taking them for full tunnel).
    collected: dict[str, Any] = {spec.key: None for spec in POLICIES}
    for spec in policies:
        report(_PHASES.get(spec.option, "cato policies"))
        try:
            collected[spec.key] = await _policy(client, account_id, spec.field, spec.full, spec.basic, errors)
        except CatoApiError as exc:
            errors.append(error_entry("account", f"policy.{spec.field}", exc))
        done += 1

    # None: not collected, so a rule naming a global IP range stays unresolved.
    global_ip_ranges: list[dict] | None = None
    if policies:
        report(_PHASES.get(policies[0].option, "cato policies"))
        try:
            data = await client.query("plexusGlobalIpRanges", GLOBAL_IP_RANGES_QUERY, {"accountId": account_id})
            found = ((data.get("object") or {}).get("globalIpRangeList") or {}).get("items") or []
            global_ip_ranges = scrub_secrets([r for r in found if isinstance(r, dict)])
        except CatoApiError as exc:
            errors.append(error_entry("account", "object.globalIpRangeList", exc))
        done += 1

    for key, field, input_type in POLICY_LISTS:
        collected[f"{key}_policies"] = None
    for key, field, input_type in policy_lists:
        report("cato policies")
        try:
            collected[f"{key}_policies"] = await _policy_list(client, account_id, field, input_type)
        except CatoApiError as exc:
            errors.append(error_entry("account", f"policy.{field}.policyList", exc))
        done += 1

    # None: not collected, so a rule naming a group stays unresolved.
    objects: dict[str, list[dict] | None] = {key: None for key, _path in _OBJECTS}
    if opts["include_policies"]:
        readers: dict[str, Callable[[], Any]] = {
            "groups": lambda: _groups(client, account_id, errors),
            "user_groups": lambda: _users_groups(client, account_id, errors),
            "containers": lambda: _containers(client, account_id),
            "custom_applications": lambda: _custom_applications(client, account_id, errors),
        }
        for key, path in _OBJECTS:
            report("cato objects")
            try:
                objects[key] = await readers[key]()
            except CatoApiError as exc:
                errors.append(error_entry("account", path, exc))
            done += 1

    def rule_count(key: str) -> int:
        return len((collected[key] or {}).get("rules") or [])

    split_rules = rule_count("split_tunnel")
    report("collected", split_tunnel_rules=split_rules)
    LOGGER.info(
        "cato: collected account %s - %d sites, %d users, %d BGP peers, %d WAN and %d internet firewall rules, "
        "%d split tunnel rules, %d of %d other policies (%d rules), %d global IP ranges, %d groups, "
        "%d users groups, %d calls, %d errors",
        account_id,
        len(sites),
        len(users),
        len(bgp_peers or []),
        rule_count("wan_firewall"),
        rule_count("internet_firewall"),
        split_rules,
        sum(1 for spec in POLICIES[3:] if collected[spec.key] is not None),
        len(POLICIES) - 3,
        sum(rule_count(spec.key) for spec in POLICIES[3:]),
        len(global_ip_ranges or []),
        len(objects["groups"] or []),
        len(objects["user_groups"] or []),
        client.stats["requests"],
        len(errors),
    )
    return {
        "account": {"id": str(account_id)},
        "timestamp": snapshot.get("timestamp") or "",
        "sites": sites,
        "users": users,
        "client_reports": client_reports,
        "ranges": lookups["siteRange"],
        "interfaces": lookups["networkInterface"],
        "bgp_peers": bgp_peers,
        **collected,
        "global_ip_ranges": global_ip_ranges,
        **objects,
        "site_config": site_config,
        "errors": errors,
        "stats": dict(client.stats),
        "options": opts,
    }
