"""Cato site and network configuration - per-site settings and account DHCP/DNS.

``collect_site_config`` reads, with a :class:`CatoClient`, the configuration
Cato keeps for every site and the account-wide network configuration, and
returns the *raw* payloads; ``site_config_sections`` and
``account_config_sections`` turn them into node detail sections (a site's
Socket nodes and the Cato Cloud node). ``build_sample_site_config`` is the
same payload for the bundled demo account.

What is read, per site (``SITE_CALLS`` queries, each naming one site):

  - ``site.networkRangeList``        the site's network ranges as configured:
                                     type, VLAN, local IP, gateway, DHCP
                                     (range, relay group, lease time),
                                     Internet only, mDNS reflector, NAT
  - ``site.staticHostList``          static hosts (name, IP, MAC)
  - ``site.knownHostList``           known hosts: DHCP-allocated and
                                     discovered hosts with their lease and
                                     last activity, following ``pageInfo``
                                     paging up to ``MAX_KNOWN_HOSTS`` a site
  - ``site.siteSocketConfiguration`` the primary and secondary Socket: model,
                                     version, serial, management IP,
                                     registration, Wi-Fi support; sent only
                                     for a site the snapshot lists a Socket
                                     for (an IPsec site has none and Cato
                                     answers with an error)
  - ``site.siteGeneralDetails``      site type, location, time zone,
                                     preferred PoPs, working hours, SIP ACL
  - ``site.siteBackhauling``         backhauling gateway settings
  - ``site.wifiSsidList``            the Wi-Fi SSIDs of a Wi-Fi Socket (never
                                     a passphrase: the schema's SSID summary
                                     has none, and the payload is scrubbed)
  - ``networkConfig.dns.siteSettings`` the site's DNS override (``{}`` when
                                     Cato answers null: the site uses the
                                     account default)

and once per account (``ACCOUNT_CALLS`` queries):

  - ``accountManagement.account``    name, plan, status, tenancy, time zone
  - ``networkConfig.dhcp.settings``  lease time and DHCP relay
  - ``networkConfig.dhcp.optionList`` DHCP options
  - ``networkConfig.dhcp.relayGroupList`` DHCP relay groups
  - ``networkConfig.dns.settings``   account DNS servers and suffixes
  - ``networkConfig.dns.forwardingRuleList`` DNS forwarding rules
  - ``networkConfig.dns.serverSetList`` DNS server sets
  - ``networkConfig.dns.suffixSetList`` DNS suffix sets

Every field name is taken from Cato's published GraphQL schema; all of these
queries are ``@beta`` or ``@rollout`` there, so every one is best-effort.

Failure policy: nothing here is required. A query that fails is recorded in
``errors`` (the map's collection report) and its payload is ``None`` - not
collected - while ``[]`` and ``{}`` mean read and empty. Queries whose detail
a schema may lack (ranges, known hosts, SSIDs, general details, the account)
fall back to a reduced field set when Cato refuses the full one, as the
collector's queries do. A per-site query that fails for the first
``_GIVE_UP_AFTER`` sites in a row without ever succeeding (a permission the
key lacks, a query the tenant does not have) is not sent for the remaining
sites, and one error entry says so.

Cost: Cato paces requests at about one a second, so per-site reads dominate
the collection time - ``SITE_CALLS`` calls a site plus one per extra page of
known hosts (100 a page), roughly 8 s a site. Only the first ``MAX_SITES``
sites are read (about 35 minutes at the cap); one error entry records the
sites skipped. ``planned_calls`` gives the count for a progress total.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from netcontrol.integrations.cato.client import CatoApiError, CatoClient, error_entry, note_entry
from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.integrations.meraki.normalize import _add, _s, kv_section, subnet_label, table_section
from netcontrol.integrations.meraki.subnets import _cidr

# At about one request a second, 250 sites are ~2000 calls (~35 minutes).
MAX_SITES = 250
# Known hosts a site: 10 pages of Cato's default page size.
MAX_KNOWN_HOSTS = 1000
_PAGE_SIZE = 100
_MAX_LIST_ITEMS = 10_000
# A per-site query refused this many times in a row, never answered, is not
# sent for the remaining sites.
_GIVE_UP_AFTER = 3

PHASE = "cato site config"

SiteConfigReport = Callable[..., None]

SITE_KEYS = (
    "ranges",
    "static_hosts",
    "known_hosts",
    "socket_configuration",
    "general",
    "backhauling",
    "wifi_ssids",
    "dns",
)

# ── Per-site queries ──────────────────────────────────────────────────────────

# ``site(accountId:)`` is spelled like ``policy(accountId:)``. A site is named
# by ``SiteRefInput { by: ID, input }``.
RANGES_QUERY = """
query plexusSiteNetworkRanges($accountId: ID!, $input: NetworkRangeListInput!) {
  site(accountId: $accountId) {
    networkRangeList(input: $input) {
      items {
        networkRangeId name subnet rangeType vlan localIp gateway internetOnly mdnsReflector translatedSubnet
        azureFloatingIp gcpLoadBalancerIp primaryManagementIp secondaryManagementIp
        dhcpSettings { dhcpType ipRange relayGroupId dhcpMicrosegmentation leaseTimeSettings { leaseTime timeUnit } }
      }
      total
    }
  }
}
"""

RANGES_QUERY_BASIC = """
query plexusSiteNetworkRangesBasic($accountId: ID!, $input: NetworkRangeListInput!) {
  site(accountId: $accountId) {
    networkRangeList(input: $input) {
      items { networkRangeId name subnet rangeType vlan localIp gateway internetOnly }
      total
    }
  }
}
"""

STATIC_HOSTS_QUERY = """
query plexusSiteStaticHosts($accountId: ID!, $site: SiteRefInput!) {
  site(accountId: $accountId) {
    staticHostList(site: $site) { items { hostId name ip macAddress } }
  }
}
"""

KNOWN_HOSTS_QUERY = """
query plexusSiteKnownHosts($accountId: ID!, $input: SiteKnownHostListInput!) {
  site(accountId: $accountId) {
    knownHostList(input: $input) {
      knownHost {
        ip macAddress hostName identity operatingSystem ipAllocationType dhcpRange
        networkRange { name subnet }
        leaseTimeSeconds expiresInSeconds lastActivitySeconds
      }
      pageInfo { total }
    }
  }
}
"""

KNOWN_HOSTS_QUERY_BASIC = """
query plexusSiteKnownHostsBasic($accountId: ID!, $input: SiteKnownHostListInput!) {
  site(accountId: $accountId) {
    knownHostList(input: $input) {
      knownHost { ip macAddress hostName ipAllocationType }
      pageInfo { total }
    }
  }
}
"""

_SOCKET = (
    "description managementIp serial socketInfo { isPrimary model platform registrationStatus version wifiSupported }"
)

SOCKET_CONFIGURATION_QUERY = """
query plexusSiteSocketConfiguration($accountId: ID!, $input: SiteSocketConfigurationInput!) {
  site(accountId: $accountId) {
    siteSocketConfiguration(input: $input) {
      primarySocketConfiguration { @SOCKET@ }
      secondarySocketConfiguration { @SOCKET@ }
    }
  }
}
""".replace("@SOCKET@", _SOCKET)

GENERAL_QUERY = """
query plexusSiteGeneralDetails($accountId: ID!, $site: SiteRefInput!) {
  site(accountId: $accountId) {
    siteGeneralDetails(site: $site) {
      description disableAclForSip siteType
      siteLocation { address cityName countryCode stateCode timezone }
      preferredPopLocation { preferredOnly primary { id name } secondary { id name } }
      workingHours { override workingDays fromTimeMinuteOffset toTimeMinuteOffset }
    }
  }
}
"""

GENERAL_QUERY_BASIC = """
query plexusSiteGeneralDetailsBasic($accountId: ID!, $site: SiteRefInput!) {
  site(accountId: $accountId) {
    siteGeneralDetails(site: $site) {
      description siteType
      siteLocation { address cityName countryCode stateCode timezone }
    }
  }
}
"""

BACKHAULING_QUERY = """
query plexusSiteBackhauling($accountId: ID!, $site: SiteRefInput!) {
  site(accountId: $accountId) {
    siteBackhauling(site: $site) { destination nextHopIP preferredSocketPort useAsBackhaulingGW }
  }
}
"""

# ``WifiSsid`` carries a security summary only (mode, protocol); no field of
# the type holds a passphrase.
WIFI_SSIDS_QUERY = """
query plexusSiteWifiSsids($accountId: ID!, $input: WifiSsidListInput!) {
  site(accountId: $accountId) {
    wifiSsidList(input: $input) {
      wifiSsid {
        id name enabled band category subnet localIp dhcp { dhcpSubnet } internetOnly mdnsEnabled
        microsegmentationEnabled visible security { authProtocol mode trackAuthentication }
      }
      pageInfo { total }
    }
  }
}
"""

WIFI_SSIDS_QUERY_BASIC = """
query plexusSiteWifiSsidsBasic($accountId: ID!, $input: WifiSsidListInput!) {
  site(accountId: $accountId) {
    wifiSsidList(input: $input) {
      wifiSsid { id name enabled band subnet localIp }
      pageInfo { total }
    }
  }
}
"""

DNS_SITE_QUERY = """
query plexusSiteDnsSettings($accountId: ID!, $site: SiteRefInput!) {
  networkConfig(accountId: $accountId) {
    dns { siteSettings(site: $site) { siteId primaryServer secondaryServer suffix } }
  }
}
"""

# ── Account-wide queries ──────────────────────────────────────────────────────

ACCOUNT_QUERY = """
query plexusAccountInfo($accountId: ID!) {
  accountManagement(accountId: $accountId) {
    account { id name description plan status tenancy timeZone type }
  }
}
"""

ACCOUNT_QUERY_BASIC = """
query plexusAccountInfoBasic($accountId: ID!) {
  accountManagement(accountId: $accountId) { account { id name description } }
}
"""

DHCP_SETTINGS_QUERY = """
query plexusDhcpSettings($accountId: ID!) {
  networkConfig(accountId: $accountId) {
    dhcp { settings { leaseTime relay { enabled timeout group { id name } } } }
  }
}
"""

# The list inputs default their sort; only ``paging`` is sent.
DHCP_OPTIONS_QUERY = """
query plexusDhcpOptions($accountId: ID!, $input: NetworkConfigDhcpOptionListInput!) {
  networkConfig(accountId: $accountId) {
    dhcp { optionList(input: $input) { items { id tag type value description } paging { total } } }
  }
}
"""

DHCP_RELAY_GROUPS_QUERY = """
query plexusDhcpRelayGroups($accountId: ID!, $input: NetworkConfigDhcpRelayGroupListInput!) {
  networkConfig(accountId: $accountId) {
    dhcp { relayGroupList(input: $input) { items { id name server } paging { total } } }
  }
}
"""

DNS_SETTINGS_QUERY = """
query plexusDnsSettings($accountId: ID!) {
  networkConfig(accountId: $accountId) {
    dns { settings { primaryServer secondaryServer suffix acceptDnsRequestsOnLanInterfaceIp } }
  }
}
"""

DNS_FORWARDING_RULES_QUERY = """
query plexusDnsForwardingRules($accountId: ID!, $input: NetworkConfigDnsForwardingRuleListInput!) {
  networkConfig(accountId: $accountId) {
    dns { forwardingRuleList(input: $input) { items { id domain server } paging { total } } }
  }
}
"""

DNS_SERVER_SETS_QUERY = """
query plexusDnsServerSets($accountId: ID!, $input: NetworkConfigDnsServerSetListInput!) {
  networkConfig(accountId: $accountId) {
    dns { serverSetList(input: $input) { items { id name server } paging { total } } }
  }
}
"""

DNS_SUFFIX_SETS_QUERY = """
query plexusDnsSuffixSets($accountId: ID!, $input: NetworkConfigDnsSuffixSetListInput!) {
  networkConfig(accountId: $accountId) {
    dns { suffixSetList(input: $input) { items { id name suffix } paging { total } } }
  }
}
"""


# ── Reading ───────────────────────────────────────────────────────────────────


def _dig(data: Any, *path: str) -> Any:
    for key in path:
        data = data.get(key) if isinstance(data, dict) else None
    return data


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> list[dict]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except TypeError, ValueError:
        return 0


@dataclass(frozen=True)
class _Spec:
    """One read: the payload ``key``, the ``path`` errors name, the queries,
    where the result sits in ``data``, and for a paged list where the item
    list and the total sit and which variable holds ``paging``."""

    key: str
    path: str
    operation: str
    full: str
    basic: str | None
    result: tuple[str, ...]
    items: str = ""  # a list: the field holding the items under ``result``
    total: tuple[str, ...] = ()  # a paged list: the total under ``result``
    cap: int = _MAX_LIST_ITEMS
    site_variable: str = "input"  # "site": ``site: SiteRefInput``; "input": ``input: {site}``
    socket_only: bool = False  # sent only for a site the snapshot lists a Socket for


@dataclass
class _State:
    reduced: bool = False
    failures: int = 0
    answered: bool = False
    disabled: bool = False


_SITE_SPECS = (
    _Spec(
        "ranges",
        "site.networkRangeList",
        "plexusSiteNetworkRanges",
        RANGES_QUERY,
        RANGES_QUERY_BASIC,
        ("site", "networkRangeList"),
        items="items",
    ),
    _Spec(
        "static_hosts",
        "site.staticHostList",
        "plexusSiteStaticHosts",
        STATIC_HOSTS_QUERY,
        None,
        ("site", "staticHostList"),
        items="items",
        site_variable="site",
    ),
    _Spec(
        "known_hosts",
        "site.knownHostList",
        "plexusSiteKnownHosts",
        KNOWN_HOSTS_QUERY,
        KNOWN_HOSTS_QUERY_BASIC,
        ("site", "knownHostList"),
        items="knownHost",
        total=("pageInfo", "total"),
        cap=MAX_KNOWN_HOSTS,
    ),
    _Spec(
        "socket_configuration",
        "site.siteSocketConfiguration",
        "plexusSiteSocketConfiguration",
        SOCKET_CONFIGURATION_QUERY,
        None,
        ("site", "siteSocketConfiguration"),
        socket_only=True,
    ),
    _Spec(
        "general",
        "site.siteGeneralDetails",
        "plexusSiteGeneralDetails",
        GENERAL_QUERY,
        GENERAL_QUERY_BASIC,
        ("site", "siteGeneralDetails"),
        site_variable="site",
    ),
    _Spec(
        "backhauling",
        "site.siteBackhauling",
        "plexusSiteBackhauling",
        BACKHAULING_QUERY,
        None,
        ("site", "siteBackhauling"),
        site_variable="site",
    ),
    _Spec(
        "wifi_ssids",
        "site.wifiSsidList",
        "plexusSiteWifiSsids",
        WIFI_SSIDS_QUERY,
        WIFI_SSIDS_QUERY_BASIC,
        ("site", "wifiSsidList"),
        items="wifiSsid",
    ),
    _Spec(
        "dns",
        "networkConfig.dns.siteSettings",
        "plexusSiteDnsSettings",
        DNS_SITE_QUERY,
        None,
        ("networkConfig", "dns", "siteSettings"),
        site_variable="site",
    ),
)

# Keys are "<group>.<name>" for the nested payload, or a top-level name.
_ACCOUNT_SPECS = (
    _Spec(
        "account",
        "accountManagement.account",
        "plexusAccountInfo",
        ACCOUNT_QUERY,
        ACCOUNT_QUERY_BASIC,
        ("accountManagement", "account"),
    ),
    _Spec(
        "dhcp.settings",
        "networkConfig.dhcp.settings",
        "plexusDhcpSettings",
        DHCP_SETTINGS_QUERY,
        None,
        ("networkConfig", "dhcp", "settings"),
    ),
    _Spec(
        "dhcp.options",
        "networkConfig.dhcp.optionList",
        "plexusDhcpOptions",
        DHCP_OPTIONS_QUERY,
        None,
        ("networkConfig", "dhcp", "optionList"),
        items="items",
        total=("paging", "total"),
    ),
    _Spec(
        "dhcp.relay_groups",
        "networkConfig.dhcp.relayGroupList",
        "plexusDhcpRelayGroups",
        DHCP_RELAY_GROUPS_QUERY,
        None,
        ("networkConfig", "dhcp", "relayGroupList"),
        items="items",
        total=("paging", "total"),
    ),
    _Spec(
        "dns.settings",
        "networkConfig.dns.settings",
        "plexusDnsSettings",
        DNS_SETTINGS_QUERY,
        None,
        ("networkConfig", "dns", "settings"),
    ),
    _Spec(
        "dns.forwarding_rules",
        "networkConfig.dns.forwardingRuleList",
        "plexusDnsForwardingRules",
        DNS_FORWARDING_RULES_QUERY,
        None,
        ("networkConfig", "dns", "forwardingRuleList"),
        items="items",
        total=("paging", "total"),
    ),
    _Spec(
        "dns.server_sets",
        "networkConfig.dns.serverSetList",
        "plexusDnsServerSets",
        DNS_SERVER_SETS_QUERY,
        None,
        ("networkConfig", "dns", "serverSetList"),
        items="items",
        total=("paging", "total"),
    ),
    _Spec(
        "dns.suffix_sets",
        "networkConfig.dns.suffixSetList",
        "plexusDnsSuffixSets",
        DNS_SUFFIX_SETS_QUERY,
        None,
        ("networkConfig", "dns", "suffixSetList"),
        items="items",
        total=("paging", "total"),
    ),
)

# Queries a site and queries an account, for the collector's progress total.
SITE_CALLS = len(_SITE_SPECS)
ACCOUNT_CALLS = len(_ACCOUNT_SPECS)


def planned_calls(site_count: int) -> int:
    """The queries ``collect_site_config`` plans for ``site_count`` sites
    (extra known-host pages and reduced fallbacks come on top)."""
    return ACCOUNT_CALLS + SITE_CALLS * min(max(0, site_count), MAX_SITES)


async def _fetch(client: CatoClient, operation: str, query: str, spec: _Spec, variables: dict) -> tuple[Any, int]:
    """One read: the payload (a list, or an object - ``{}`` when Cato answers
    null) and, for a paged list, the total Cato reports (else the count)."""
    if not spec.items:
        data = await client.query(operation, query, variables)
        found = _dig(data, *spec.result)
        return (found if isinstance(found, dict) else {}), 1
    items: list[dict] = []
    total = 0
    while True:
        if spec.total:
            page_input = {**variables.get("input", {}), "paging": {"limit": _PAGE_SIZE, "from": len(items)}}
            page_vars = {**variables, "input": page_input}
        else:
            page_vars = variables
        data = await client.query(operation, query, page_vars)
        result = _dig(data, *spec.result)
        page = _dicts(_dig(result, spec.items))
        items.extend(page)
        total = _int(_dig(result, *spec.total)) if spec.total else len(items)
        if not spec.total or not page or len(items) >= total or len(items) >= spec.cap:
            break
    return items[: spec.cap], max(total, len(items))


async def _read(
    client: CatoClient, spec: _Spec, state: _State, variables: dict, errors: list[dict[str, Any]]
) -> tuple[Any, int]:
    """``_fetch`` with the full query, or the reduced one once Cato refused
    the full one and answered the reduced one."""
    if state.reduced and spec.basic:
        return await _fetch(client, f"{spec.operation}Basic", spec.basic, spec, variables)
    try:
        return await _fetch(client, spec.operation, spec.full, spec, variables)
    except CatoApiError as exc:
        if not exc.graphql or not spec.basic:
            raise
        found = await _fetch(client, f"{spec.operation}Basic", spec.basic, spec, variables)
        errors.append(error_entry("account", f"{spec.path} (full detail)", exc))
        state.reduced = True
        return found


def _has_socket(site: dict) -> bool:
    """Whether the account snapshot lists a Socket for ``site``: a device,
    or Socket info. An IPsec or cloud-interconnect site has neither, and
    Cato answers its Socket configuration with an error."""
    return bool(site.get("devices")) or bool((site.get("info") or {}).get("sockets"))


def _site_variables(spec: _Spec, account_id: str, site_id: str) -> dict[str, Any]:
    ref = {"by": "ID", "input": site_id}
    if spec.site_variable == "site":
        return {"accountId": account_id, "site": ref}
    return {"accountId": account_id, "input": {"site": ref}}


async def collect_site_config(
    client: CatoClient,
    account_id: str,
    sites: list[dict],
    errors: list[dict[str, Any]],
    report: SiteConfigReport | None = None,
) -> dict[str, Any]:
    """Read the account's network configuration and the configuration of
    ``sites`` (the collector's filtered site list). Never raises
    ``CatoApiError``: failures are appended to ``errors``.

    ``report(phase, calls=n, **fields)`` is called with the planned queries
    finished since the previous call (``planned_calls`` in all), so the
    collector can advance its progress count."""

    def progress(calls: int = 0, **fields: Any) -> None:
        if report is not None:
            report(PHASE, calls=calls, **fields)

    payload: dict[str, Any] = {
        "account": None,
        "dhcp": {"settings": None, "options": None, "relay_groups": None},
        "dns": {"settings": None, "forwarding_rules": None, "server_sets": None, "suffix_sets": None},
        "sites": {},
    }
    progress()
    for spec in _ACCOUNT_SPECS:
        variables: dict[str, Any] = {"accountId": account_id}
        if spec.total:
            variables["input"] = {}
        try:
            found, _total = await _read(client, spec, _State(), variables, errors)
            group, _dot, name = spec.key.rpartition(".")
            (payload[group] if group else payload)[name] = scrub_secrets(found)
        except CatoApiError as exc:
            errors.append(error_entry("account", spec.path, exc))
        progress(calls=1)

    chosen = [s for s in sites if isinstance(s, dict) and s.get("id") is not None]
    if len(chosen) > MAX_SITES:
        errors.append(
            note_entry(
                "account",
                "site configuration",
                f"Read for the first {MAX_SITES} of {len(chosen)} sites; "
                f"{len(chosen) - MAX_SITES} sites were skipped to bound the collection time",
            )
        )
        chosen = chosen[:MAX_SITES]

    states = {spec.key: _State() for spec in _SITE_SPECS}
    for index, site in enumerate(chosen):
        site_id = str(site["id"])
        name = str((site.get("info") or {}).get("name") or f"Site {site_id}")
        entry: dict[str, Any] = dict.fromkeys(SITE_KEYS)
        for spec in _SITE_SPECS:
            state = states[spec.key]
            if state.disabled or (spec.socket_only and not _has_socket(site)):
                progress(calls=1)
                continue
            try:
                found, total = await _read(client, spec, state, _site_variables(spec, account_id, site_id), errors)
                entry[spec.key] = scrub_secrets(found)
                state.answered = True
                if spec.items and total > len(found):
                    errors.append(
                        note_entry(
                            f"site {name}", spec.path, f"First {len(found)} of {total} read (the per-site limit)"
                        )
                    )
            except CatoApiError as exc:
                errors.append(error_entry(f"site {name}", spec.path, exc))
                state.failures += 1
                remaining = len(chosen) - index - 1
                if not state.answered and state.failures >= _GIVE_UP_AFTER and remaining:
                    state.disabled = True
                    errors.append(
                        note_entry(
                            "account",
                            spec.path,
                            f"Failed for the first {state.failures} sites and was not sent for the "
                            f"remaining {remaining}",
                        )
                    )
            progress(calls=1, site=name)
        payload["sites"][site_id] = entry
    return payload


# ── Sections ──────────────────────────────────────────────────────────────────

_DURATION_UNITS = (("d", 86400), ("h", 3600), ("m", 60), ("s", 1))
_DAYS = ("MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY")
_BANDS = {"BAND_2P4G": "2.4 GHz", "BAND_5G": "5 GHz", "BOTH": "2.4 and 5 GHz"}
_YES_NO_UNKNOWN = {"TRUE": "Yes", "FALSE": "No", "UNKNOWN": "Unknown"}

RANGE_SETTINGS_COLUMNS = [
    "Subnet",
    "Name",
    "Type",
    "VLAN",
    "Local IP",
    "Gateway",
    "DHCP",
    "Internet only",
    "mDNS",
    "Translated subnet",
]
STATIC_HOST_COLUMNS = ["Name", "IP", "MAC"]
KNOWN_HOST_COLUMNS = ["IP", "MAC", "Host name", "Identity", "OS", "Allocation", "Range", "Lease", "Last activity"]
WIFI_COLUMNS = [
    "SSID",
    "Category",
    "Enabled",
    "Band",
    "Subnet",
    "Local IP",
    "DHCP",
    "Security",
    "Internet only",
    "Visible",
]


def _duration(seconds: Any) -> str:
    """``93784`` -> ``1d 2h``: the two largest units; ``""`` when unknown."""
    if seconds is None or isinstance(seconds, bool):
        return ""
    try:
        left = int(seconds)
    except TypeError, ValueError:
        return ""
    if left <= 0:
        return "0s"
    parts: list[str] = []
    for unit, size in _DURATION_UNITS:
        count, left = divmod(left, size)
        if count:
            parts.append(f"{count}{unit}")
        if len(parts) == 2:
            break
    return " ".join(parts)


def _ip_order(value: Any) -> tuple[int, int, str]:
    """Sort key for an address or subnet: numeric, unparsable text last."""
    text = _s(value).strip()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return (9, 0, text)
    return (network.version, int(network.network_address), text)


def _subnet(value: Any) -> str:
    return _cidr(value) or _s(value)


def _lease_time(settings: Any) -> str:
    """``DhcpLeaseTimeSettings`` as text: ``8 hours``, ``1 day``."""
    if not isinstance(settings, dict) or settings.get("leaseTime") is None:
        return ""
    amount = _s(settings.get("leaseTime"))
    unit = _s(settings.get("timeUnit")).lower()
    return f"{amount} {unit[:-1] if amount == '1' and unit.endswith('s') else unit}".strip()


def _relay_group_names(raw: dict) -> dict[str, str]:
    groups = _dig(raw, "dhcp", "relay_groups")
    return {_s(g.get("id")): _s(g.get("name")) for g in _dicts(groups) if g.get("id") is not None}


def _range_dhcp(settings: Any, relay_names: dict[str, str]) -> str:
    """A range's ``dhcpSettings`` as one cell."""
    if not isinstance(settings, dict):
        return ""
    kind = _s(settings.get("dhcpType"))
    parts: list[str] = []
    if kind == "DHCP_RANGE":
        parts.append(f"Range {_s(settings.get('ipRange'))}".strip())
    elif kind == "DHCP_RELAY":
        group = _s(settings.get("relayGroupId"))
        parts.append(f"Relay to {relay_names.get(group) or group}".strip())
    elif kind == "DHCP_DISABLED":
        parts.append("Disabled")
    elif kind == "ACCOUNT_DEFAULT":
        parts.append("Account default")
    elif kind:
        parts.append(kind)
    lease = _lease_time(settings.get("leaseTimeSettings"))
    if lease:
        parts.append(f"lease {lease}")
    if settings.get("dhcpMicrosegmentation") is True:
        parts.append("microsegmentation")
    return ", ".join(parts)


def _minutes(offset: Any) -> str:
    if offset is None or isinstance(offset, bool):
        return ""
    try:
        hours, minutes = divmod(int(offset), 60)
    except TypeError, ValueError:
        return ""
    return f"{hours:02d}:{minutes:02d}"


def _working_hours(hours: Any) -> str:
    if not isinstance(hours, dict):
        return ""
    if hours.get("override") is False:
        return "Account working hours"
    listed = {_s(d).upper() for d in hours.get("workingDays") or []}
    days = ", ".join(d[:3].title() for d in _DAYS if d in listed)
    span = "-".join(
        t for t in (_minutes(hours.get("fromTimeMinuteOffset")), _minutes(hours.get("toTimeMinuteOffset"))) if t
    )
    return " ".join(p for p in (days, span) if p)


def _location(location: Any) -> str:
    if not isinstance(location, dict):
        return ""
    return _s(
        [location.get("address"), location.get("cityName"), location.get("stateCode"), location.get("countryCode")]
    )


def _site_settings(entry: dict) -> dict | None:
    general = _dict(entry.get("general"))
    backhaul = _dict(entry.get("backhauling"))
    pops = _dict(general.get("preferredPopLocation"))
    location = _dict(general.get("siteLocation"))
    rows: list[tuple[str, Any]] = [
        ("Description", general.get("description")),
        ("Site type", general.get("siteType")),
        ("Location", _location(location)),
        ("Time zone", location.get("timezone")),
        ("Preferred PoP (primary)", _dig(pops, "primary", "name")),
        ("Preferred PoP (secondary)", _dig(pops, "secondary", "name")),
        ("Preferred PoPs only", pops.get("preferredOnly")),
        ("Working hours", _working_hours(general.get("workingHours"))),
        ("ACL for SIP disabled", general.get("disableAclForSip")),
        ("Backhauling gateway", backhaul.get("useAsBackhaulingGW")),
        ("Backhauling destination", backhaul.get("destination")),
        ("Backhauling next hop", backhaul.get("nextHopIP")),
        ("Backhauling preferred Socket port", backhaul.get("preferredSocketPort")),
    ]
    dns = entry.get("dns")
    if isinstance(dns, dict):
        if dns:
            rows += [
                ("Site DNS servers", [dns.get("primaryServer"), dns.get("secondaryServer")]),
                ("Site DNS suffixes", dns.get("suffix")),
            ]
        else:
            rows.append(("Site DNS", "Account default (no site override)"))
    return kv_section("Site settings", rows)


def _socket_sections(entry: dict, serial: str) -> list[dict]:
    config = entry.get("socket_configuration")
    if not isinstance(config, dict):
        return []
    sockets = [
        (role, _dict(config.get(field)))
        for role, field in (("Primary", "primarySocketConfiguration"), ("Secondary", "secondarySocketConfiguration"))
        if isinstance(config.get(field), dict)
    ]
    mine = [(role, s) for role, s in sockets if serial and _s(s.get("serial")).strip() == serial]
    shown = mine or sockets
    sections: list[dict] = []
    for role, socket in shown:
        info = _dict(socket.get("socketInfo"))
        title = "Socket configuration" if len(shown) == 1 else f"Socket configuration ({role.lower()})"
        _add(
            sections,
            kv_section(
                title,
                [
                    ("Role", role),
                    ("Model", info.get("model")),
                    ("Platform", info.get("platform")),
                    ("Version", info.get("version")),
                    ("Serial", socket.get("serial")),
                    ("Management IP", socket.get("managementIp")),
                    ("Registration", info.get("registrationStatus")),
                    ("Wi-Fi support", _YES_NO_UNKNOWN.get(_s(info.get("wifiSupported")), info.get("wifiSupported"))),
                    ("Description", socket.get("description")),
                ],
            ),
        )
    return sections


def _range_rows(entry: dict, relay_names: dict[str, str]) -> list[list[Any]]:
    ranges = sorted(_dicts(entry.get("ranges")), key=lambda r: _ip_order(r.get("subnet")))
    return [
        [
            _subnet(r.get("subnet")),
            r.get("name"),
            r.get("rangeType"),
            r.get("vlan"),
            r.get("localIp"),
            r.get("gateway"),
            _range_dhcp(r.get("dhcpSettings"), relay_names),
            r.get("internetOnly"),
            r.get("mdnsReflector"),
            r.get("translatedSubnet"),
        ]
        for r in ranges
    ]


def _known_host_row(host: dict) -> list[Any]:
    network = _dict(host.get("networkRange"))
    lease = _duration(host.get("leaseTimeSeconds"))
    expires = _duration(host.get("expiresInSeconds"))
    if lease and expires:
        lease = f"{lease} (expires in {expires})"
    active = _duration(host.get("lastActivitySeconds"))
    return [
        host.get("ip"),
        host.get("macAddress"),
        host.get("hostName"),
        host.get("identity"),
        host.get("operatingSystem"),
        host.get("ipAllocationType"),
        subnet_label(network.get("name"), network.get("subnet")) or host.get("dhcpRange"),
        lease,
        f"{active} ago" if active else "",
    ]


def _security(security: Any) -> str:
    if not isinstance(security, dict):
        return ""
    mode = _s(security.get("mode"))
    if mode == "OPEN":
        return "Open"
    protocol = _s(security.get("authProtocol"))
    return f"{mode} ({protocol})" if mode and protocol else mode or protocol


def _wifi_row(ssid: dict) -> list[Any]:
    dhcp = _dig(ssid, "dhcp", "dhcpSubnet")
    return [
        ssid.get("name"),
        _s(ssid.get("category")).title(),
        ssid.get("enabled"),
        _BANDS.get(_s(ssid.get("band")), ssid.get("band")),
        ssid.get("subnet"),
        ssid.get("localIp"),
        f"Subnet {dhcp}" if dhcp else "",
        _security(ssid.get("security")),
        ssid.get("internetOnly"),
        ssid.get("visible"),
    ]


def site_config_sections(raw: dict | None, site_id: str, serial: str = "") -> list[dict]:
    """The detail sections for a site's node: ``raw`` is the payload of
    ``collect_site_config``. ``serial`` (a Socket's) narrows "Socket
    configuration" to that Socket; without it, or when it matches none, every
    Socket of the site is listed. Sections without data, and data that was
    not collected, are left out (the collection report lists the failures)."""
    entry = _dig(raw, "sites", str(site_id))
    if not isinstance(entry, dict):
        return []
    sections: list[dict] = []
    _add(sections, _site_settings(entry))
    sections.extend(_socket_sections(entry, serial.strip()))
    _add(
        sections,
        table_section(
            "Network range settings", RANGE_SETTINGS_COLUMNS, _range_rows(entry, _relay_group_names(raw or {}))
        ),
    )
    hosts = sorted(_dicts(entry.get("static_hosts")), key=lambda h: _ip_order(h.get("ip")))
    _add(
        sections,
        table_section(
            "Static hosts", STATIC_HOST_COLUMNS, [[h.get("name"), h.get("ip"), h.get("macAddress")] for h in hosts]
        ),
    )
    known = sorted(_dicts(entry.get("known_hosts")), key=lambda h: _ip_order(h.get("ip")))
    _add(sections, table_section("Known hosts", KNOWN_HOST_COLUMNS, [_known_host_row(h) for h in known]))
    ssids = sorted(_dicts(entry.get("wifi_ssids")), key=lambda w: _s(w.get("name")).lower())
    _add(sections, table_section("Wi-Fi SSIDs", WIFI_COLUMNS, [_wifi_row(w) for w in ssids]))
    return sections


def account_config_sections(raw: dict | None) -> list[dict]:
    """The detail sections for the Cato Cloud node: the account and its
    DHCP and DNS configuration, from the payload of ``collect_site_config``."""
    raw = _dict(raw)
    sections: list[dict] = []
    account = _dict(raw.get("account"))
    _add(
        sections,
        kv_section(
            "Account",
            [
                ("Name", account.get("name")),
                ("Account ID", account.get("id")),
                ("Description", account.get("description")),
                ("Type", account.get("type")),
                ("Plan", account.get("plan")),
                ("Status", account.get("status")),
                ("Tenancy", account.get("tenancy")),
                ("Time zone", account.get("timeZone")),
            ],
        ),
    )
    dhcp = _dig(raw, "dhcp", "settings")
    if isinstance(dhcp, dict):
        relay = _dict(dhcp.get("relay"))
        lease = dhcp.get("leaseTime")
        timeout = relay.get("timeout")
        _add(
            sections,
            kv_section(
                "DHCP settings",
                [
                    ("Lease time", f"{_duration(lease)} ({lease} s)" if lease is not None else None),
                    ("DHCP relay", relay.get("enabled")),
                    ("Relay group", _dig(relay, "group", "name")),
                    ("Relay timeout", f"{timeout} s" if timeout is not None else None),
                ],
            ),
        )
    options = sorted(_dicts(_dig(raw, "dhcp", "options")), key=lambda o: _int(o.get("tag")))
    _add(
        sections,
        table_section(
            "DHCP options",
            ["Tag", "Type", "Value", "Description"],
            [[o.get("tag"), o.get("type"), o.get("value"), o.get("description")] for o in options],
        ),
    )
    groups = _dicts(_dig(raw, "dhcp", "relay_groups"))
    _add(
        sections,
        table_section("DHCP relay groups", ["Name", "Servers"], [[g.get("name"), g.get("server")] for g in groups]),
    )
    dns = _dig(raw, "dns", "settings")
    if isinstance(dns, dict):
        _add(
            sections,
            kv_section(
                "DNS settings",
                [
                    ("Primary server", dns.get("primaryServer")),
                    ("Secondary server", dns.get("secondaryServer")),
                    ("Search suffixes", dns.get("suffix")),
                    ("Accepts DNS requests on the LAN interface IP", dns.get("acceptDnsRequestsOnLanInterfaceIp")),
                ],
            ),
        )
    rules = _dicts(_dig(raw, "dns", "forwarding_rules"))
    _add(
        sections,
        table_section(
            "DNS forwarding rules", ["Domain", "Servers"], [[r.get("domain"), r.get("server")] for r in rules]
        ),
    )
    servers = _dicts(_dig(raw, "dns", "server_sets"))
    _add(
        sections,
        table_section("DNS server sets", ["Name", "Servers"], [[s.get("name"), s.get("server")] for s in servers]),
    )
    suffixes = _dicts(_dig(raw, "dns", "suffix_sets"))
    _add(
        sections,
        table_section("DNS suffix sets", ["Name", "Suffixes"], [[s.get("name"), s.get("suffix")] for s in suffixes]),
    )
    return sections


# ── Demo data ─────────────────────────────────────────────────────────────────


def _socket_config(serial: str, model: str, *, primary: bool, ip: str, wifi: str = "FALSE") -> dict:
    return {
        "description": f"Demo {model}",
        "managementIp": ip,
        "serial": serial,
        "socketInfo": {
            "isPrimary": primary,
            "model": model,
            "platform": model,
            "registrationStatus": "ASSIGNED_SITE",
            "version": "22.0.19221",
            "wifiSupported": wifi,
        },
    }


def _network_range(
    ident: str, name: str, subnet: str, kind: str, *, vlan: int | None, local_ip: str, dhcp: dict
) -> dict:
    return {
        "networkRangeId": ident,
        "name": name,
        "subnet": subnet,
        "rangeType": kind,
        "vlan": vlan,
        "localIp": local_ip,
        "gateway": None,
        "internetOnly": False,
        "mdnsReflector": kind == "VLAN",
        "translatedSubnet": None,
        "azureFloatingIp": None,
        "gcpLoadBalancerIp": None,
        "primaryManagementIp": None,
        "secondaryManagementIp": None,
        "dhcpSettings": dhcp,
    }


def _dhcp_range(ip_range: str, hours: int) -> dict:
    return {
        "dhcpType": "DHCP_RANGE",
        "ipRange": ip_range,
        "relayGroupId": None,
        "dhcpMicrosegmentation": False,
        "leaseTimeSettings": {"leaseTime": hours, "timeUnit": "HOURS"},
    }


def _known_host(ip: str, mac: str, name: str, os_name: str, network: tuple[str, str], **fields: Any) -> dict:
    return {
        "ip": ip,
        "macAddress": mac,
        "hostName": name,
        "identity": fields.get("identity"),
        "operatingSystem": os_name,
        "ipAllocationType": fields.get("allocation", "DYNAMIC"),
        "dhcpRange": network[1],
        "networkRange": {"name": network[0], "subnet": network[1]},
        "leaseTimeSeconds": fields.get("lease", 28800),
        "expiresInSeconds": fields.get("expires", 17400),
        "lastActivitySeconds": fields.get("active", 95),
    }


def _general(site_type: str, city: str, state: str, timezone: str, pop: str) -> dict:
    return {
        "description": "Demo site",
        "disableAclForSip": False,
        "siteType": site_type,
        "siteLocation": {
            "address": "",
            "cityName": city,
            "countryCode": "US",
            "stateCode": state,
            "timezone": timezone,
        },
        "preferredPopLocation": {
            "preferredOnly": False,
            "primary": {"id": f"pop-{pop.lower().replace(' ', '-')}", "name": pop} if pop else None,
            "secondary": None,
        },
        "workingHours": {
            "override": False,
            "workingDays": [],
            "fromTimeMinuteOffset": None,
            "toTimeMinuteOffset": None,
        },
    }


def build_sample_site_config() -> dict[str, Any]:
    """The configuration of the demo account of ``sample.build_sample_raw``,
    in the shape ``collect_site_config`` returns: every section shows."""
    servers = ("Servers", "10.50.10.0/24")
    hq_users = ("Users", "10.50.20.0/24")
    madison = ("Users", "10.60.20.0/24")
    no_backhaul = {"destination": None, "nextHopIP": None, "preferredSocketPort": None, "useAsBackhaulingGW": False}
    hq_general = _general("DATACENTER", "Ashburn", "VA", "America/New_York", "Ashburn")
    hq_general["workingHours"] = {
        "override": True,
        "workingDays": ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"],
        "fromTimeMinuteOffset": 7 * 60,
        "toTimeMinuteOffset": 19 * 60,
    }
    sites: dict[str, dict[str, Any]] = {
        "1001": {
            "ranges": [
                _network_range(
                    "nr-1001-1",
                    "Native",
                    "10.50.1.0/24",
                    "Native",
                    vlan=None,
                    local_ip="10.50.1.1",
                    dhcp={
                        "dhcpType": "DHCP_DISABLED",
                        "ipRange": None,
                        "relayGroupId": None,
                        "dhcpMicrosegmentation": False,
                        "leaseTimeSettings": None,
                    },
                ),
                _network_range(
                    "nr-1001-10",
                    "Servers",
                    "10.50.10.0/24",
                    "VLAN",
                    vlan=10,
                    local_ip="10.50.10.1",
                    dhcp={
                        "dhcpType": "DHCP_RELAY",
                        "ipRange": None,
                        "relayGroupId": "rg-1",
                        "dhcpMicrosegmentation": False,
                        "leaseTimeSettings": None,
                    },
                ),
                _network_range(
                    "nr-1001-20",
                    "Users",
                    "10.50.20.0/24",
                    "VLAN",
                    vlan=20,
                    local_ip="10.50.20.1",
                    dhcp=_dhcp_range("10.50.20.100-10.50.20.250", 8),
                ),
            ],
            "static_hosts": [
                {"hostId": "sh-1", "name": "dc01", "ip": "10.50.10.10", "macAddress": "00:50:56:aa:10:10"},
                {"hostId": "sh-2", "name": "printer-hq", "ip": "10.50.20.20", "macAddress": "00:1b:a9:20:20:20"},
            ],
            "known_hosts": [
                # Priya is the sample user connected from the HQ office.
                _known_host(
                    "10.50.20.101",
                    "3c:22:fb:01:01:01",
                    "HQ-LT-0101",
                    "Windows",
                    hq_users,
                    identity="priya.nair@example.com",
                ),
                _known_host("10.50.20.102", "3c:22:fb:01:01:02", "HQ-LT-0102", "macOS", hq_users, active=3600),
                _known_host(
                    "10.50.10.10",
                    "00:50:56:aa:10:10",
                    "dc01",
                    "Windows Server",
                    servers,
                    allocation="RESERVED",
                    lease=None,
                    expires=None,
                    active=12,
                ),
            ],
            "socket_configuration": {
                "primarySocketConfiguration": _socket_config("X1700-0001-AAAA", "X1700", primary=True, ip="10.50.1.2"),
                "secondarySocketConfiguration": _socket_config(
                    "X1700-0002-BBBB", "X1700", primary=False, ip="10.50.1.3"
                ),
            },
            "general": hq_general,
            "backhauling": {
                "destination": "LOCAL_GATEWAY_IP",
                "nextHopIP": "10.50.1.254",
                "preferredSocketPort": "LAN 01",
                "useAsBackhaulingGW": True,
            },
            "wifi_ssids": [],
            "dns": {},
        },
        "1002": {
            "ranges": [
                _network_range(
                    "nr-1002-20",
                    "Users",
                    "10.60.20.0/24",
                    "Native",
                    vlan=None,
                    local_ip="10.60.20.1",
                    dhcp=_dhcp_range("10.60.20.50-10.60.20.200", 24),
                ),
                _network_range(
                    "nr-1002-30",
                    "Guest Wi-Fi",
                    "10.60.30.0/24",
                    "VLAN",
                    vlan=30,
                    local_ip="10.60.30.1",
                    dhcp={
                        "dhcpType": "ACCOUNT_DEFAULT",
                        "ipRange": None,
                        "relayGroupId": None,
                        "dhcpMicrosegmentation": True,
                        "leaseTimeSettings": None,
                    },
                ),
            ],
            "static_hosts": [
                {"hostId": "sh-3", "name": "printer-madison", "ip": "10.60.20.20", "macAddress": "00:1b:a9:60:20:20"},
            ],
            "known_hosts": [
                _known_host(
                    "10.60.20.51",
                    "3c:22:fb:02:02:51",
                    "MAD-LT-0051",
                    "Windows",
                    madison,
                    identity="front.desk@example.com",
                    active=40,
                ),
            ],
            "socket_configuration": {
                "primarySocketConfiguration": _socket_config(
                    "X1500-0003-CCCC", "X1500", primary=True, ip="10.60.20.2", wifi="TRUE"
                ),
                "secondarySocketConfiguration": None,
            },
            "general": _general("BRANCH", "Madison", "WI", "America/Chicago", "New York"),
            "backhauling": no_backhaul,
            "wifi_ssids": [
                {
                    "id": "ssid-1",
                    "name": "Madison-Guest",
                    "enabled": True,
                    "band": "BOTH",
                    "category": "GUEST",
                    "subnet": "10.60.30.0/24",
                    "localIp": "10.60.30.1",
                    "dhcp": {"dhcpSubnet": "10.60.30.0/24"},
                    "internetOnly": True,
                    "mdnsEnabled": False,
                    "microsegmentationEnabled": True,
                    "visible": True,
                    "security": {"authProtocol": "WPA2", "mode": "PSK", "trackAuthentication": False},
                }
            ],
            "dns": {
                "siteId": "1002",
                "primaryServer": "10.50.10.10",
                "secondaryServer": "10.50.10.11",
                "suffix": ["madison.example.com"],
            },
        },
        "1003": {
            "ranges": [
                _network_range(
                    "nr-1003-20",
                    "Users",
                    "10.61.20.0/24",
                    "Native",
                    vlan=None,
                    local_ip="10.61.20.1",
                    dhcp=_dhcp_range("10.61.20.50-10.61.20.200", 24),
                ),
            ],
            "static_hosts": [],
            # Disconnected: no host seen.
            "known_hosts": [],
            "socket_configuration": {
                "primarySocketConfiguration": _socket_config("X1500-0004-DDDD", "X1500", primary=True, ip=""),
                "secondarySocketConfiguration": None,
            },
            "general": _general("BRANCH", "Denver", "CO", "America/Denver", ""),
            "backhauling": no_backhaul,
            "wifi_ssids": [],
            "dns": {},
        },
        "1004": {
            "ranges": [
                _network_range(
                    "nr-1004-1",
                    "VPC",
                    "172.21.0.0/16",
                    "Native",
                    vlan=None,
                    local_ip="",
                    dhcp={
                        "dhcpType": "DHCP_DISABLED",
                        "ipRange": None,
                        "relayGroupId": None,
                        "dhcpMicrosegmentation": False,
                        "leaseTimeSettings": None,
                    },
                ),
            ],
            "static_hosts": [],
            "known_hosts": [],
            # An IPsec site has no Socket.
            "socket_configuration": None,
            "general": _general("CLOUD_DC", "Ashburn", "VA", "America/New_York", ""),
            "backhauling": no_backhaul,
            "wifi_ssids": [],
            "dns": {},
        },
    }
    return {
        "account": {
            "id": "sample",
            "name": "Sample Cato Account",
            "description": "Demo account",
            "plan": "COMMERCIAL",
            "status": "ACTIVE",
            "tenancy": "SINGLE_TENANT",
            "timeZone": "America/New_York",
            "type": "CUSTOMER",
        },
        "dhcp": {
            "settings": {
                "leaseTime": 86400,
                "relay": {"enabled": True, "timeout": 30, "group": {"id": "rg-1", "name": "HQ-DHCP"}},
            },
            "options": [
                {"id": "opt-1", "tag": 42, "type": "IP", "value": "10.50.10.10", "description": "NTP server"},
                {"id": "opt-2", "tag": 15, "type": "ASCII", "value": "example.com", "description": "Domain name"},
            ],
            "relay_groups": [{"id": "rg-1", "name": "HQ-DHCP", "server": ["10.50.10.10", "10.50.10.11"]}],
        },
        "dns": {
            "settings": {
                "primaryServer": "10.50.10.10",
                "secondaryServer": "10.50.10.11",
                "suffix": ["example.com"],
                "acceptDnsRequestsOnLanInterfaceIp": True,
            },
            "forwarding_rules": [{"id": "fw-1", "domain": "corp.example.com", "server": ["10.50.10.10"]}],
            "server_sets": [{"id": "ss-1", "name": "Public resolvers", "server": ["192.0.2.53", "198.51.100.53"]}],
            "suffix_sets": [{"id": "sx-1", "name": "Corporate", "suffix": ["example.com", "corp.example.com"]}],
        },
        "sites": sites,
    }
