"""OPNsense collector - gathers every payload a topology build needs.

``collect_opnsense`` reads one firewall with an :class:`OpnsenseClient` and
returns the *raw* API answers. It does no interpretation -
``normalize.build_snapshot`` owns that - so a saved capture can be
re-normalised without calling the firewall.

What is read (every path is under ``/api``; where two are named, the newer
``snake_case`` form is tried first and the ``camelCase`` form of 24.7 to
25.1 second, see ``client``). Paths and answer shapes were checked against
the OPNsense core source (``opnsense/core``, the 25.7 tag and master) and
the API reference at docs.opnsense.org:

  - ``diagnostics/system/system_information``   host name and version strings
  - ``core/firmware/status`` (GET)               product, version, pending
                                                 updates of the last check (a GET
                                                 never starts a new check)
  - ``interfaces/overview/interfaces_info``      interfaces, addresses, link
                                                 state, VLAN tags (since 24.1)
  - ``routes/gateway/status``                    gateways: status, loss, delay,
                                                 stddev (dpinger)
  - ``diagnostics/interface/get_routes``         the routing table
  - ``ipsec/sessions/search_phase1``             IPsec connections and whether
                                                 each has an SA
  - ``ipsec/sessions/search_phase2`` (POST,      the child SAs (phase 2) of each
    ``{"id": <phase 1 name>}``)                  connection that has an SA; the
                                                 action reads ``id`` with
                                                 ``getPost``, so it is a POST that
                                                 only reads
  - ``ipsec/connections/search_child``           the child SAs configured for a
    (``?connection=<uuid>``)                     connection of the "Connections"
                                                 model (23.1+): only for phase 1
                                                 rows whose ``ikeid`` is a UUID;
                                                 legacy tunnels are not counted
  - ``wireguard/service/show``                   WireGuard interfaces and peers
                                                 with their latest handshake
  - ``openvpn/service/search_sessions``          OpenVPN instances and the
                                                 clients connected to servers
  - ``diagnostics/interface/get_vip_status``     CARP virtual IPs (interface,
                                                 VHID, MASTER / BACKUP / INIT /
                                                 DISABLED) and the global
                                                 ``carp`` state (demotion,
                                                 allow, maintenance mode)
  - ``diagnostics/interface/search_arp``         the ARP table (``get_arp``, a
                                                 plain list, on older releases;
                                                 never ``flush_arp``)
  - ``diagnostics/interface/search_ndp``         the NDP table (``get_ndp``)
  - ``dhcpv4/leases/search_lease``,              DHCP leases of whichever
    ``dhcpv6/leases/search_lease`` (ISC),        backends the firewall has; a
    ``kea/leases4/search``,                      backend that answers 404 is not
    ``kea/leases6/search`` (Kea),                there and is skipped quietly,
    ``dnsmasq/leases/search`` (Dnsmasq)          and so is a refused (403) Kea
                                                 or Dnsmasq read when config.xml
                                                 shows that service as off
                                                 (``lease_backends_off``).
                                                 The search actions are read
                                                 with GET (all rows); the Kea,
                                                 Dnsmasq and DHCPv6 row shapes
                                                 are not verified against a
                                                 firewall (see
                                                 docs/opnsense-topology.md)
  - ``firewall/filter_util/rule_stats``          the filter rule counters
                                                 (evaluations, packets, bytes,
                                                 states) by rule uuid, for the
                                                 rule views (24.1+; an older
                                                 release answers 404, a warning)
  - health (``collect_health``; 24.7+, the dashboard widgets' calls):
    ``diagnostics/system/system_resources``      memory (``hw.physmem``, used,
                                                 ZFS ARC)
    ``diagnostics/system/system_disk``           the file systems (``df``)
    ``diagnostics/system/system_temperature``    the temperature sensors
    ``diagnostics/system/system_time``           uptime and load averages (load
                                                 averages since 25.1)
    ``diagnostics/activity/get_activity``        ``top``'s header lines, for the
                                                 CPU line (``CPU: x% user ...
                                                 y% idle``); the process list is
                                                 dropped. Never the streaming
                                                 ``diagnostics/cpu_usage/stream``
    ``diagnostics/firewall/pf_states``           the state table: ``current``
                                                 and ``limit``
    ``core/service/search``                      the services the configuration
                                                 enables (``pluginctl -S``), each
                                                 with ``running``; never start,
                                                 stop or restart.
                                                 An endpoint that answers 404 is
                                                 left out with one ``info``
                                                 warning naming all of them
  - certificates (``collect_certificates``; 24.7+, see ``certificates``):
    ``trust/cert/search``, ``trust/ca/search``   the certificates and CAs
                                                 with their expiry; the rows
                                                 carry the private keys, so
                                                 only a few fields are kept.
                                                 Without the API (both 404)
                                                 the ``<cert>`` / ``<ca>`` of
                                                 config.xml are parsed instead
  - IDS alerts (``collect_ids_alerts``, see ``ids``):
    ``ids/service/status``,                      whether the IDS is enabled;
    ``ids/service/query_alerts`` (POST),         then its alerts, newest first,
    ``ids/settings/get_rule_info/{sid}``         only those newer than the
                                                 newest one stored, and the
                                                 classtype of each new
                                                 signature. Bounded by
                                                 ``ids.IDS_*``; an IDS that is
                                                 off reads nothing more
  - ``core/firmware/running``, ``core/firmware/audit`` (POST),
    ``core/firmware/upgradestatus``              the security audit
                                                 (``pkg audit -F``), run in the
                                                 background and polled
  - ``core/backup/download/this``                ``config.xml`` (the newest
                                                 entry of the configuration
                                                 history, written on every save)
  - ``firewall/alias_util/aliases``,             the pf tables behind the
    ``firewall/alias_util/list/{alias}``         aliases config.xml cannot
                                                 resolve (URL tables, GeoIP,
                                                 host names...; which ones:
                                                 ``opnsense_config``'s
                                                 ``table_aliases`` of the XML
                                                 just read), for the path
                                                 trace. ``aliases`` lists the
                                                 loaded tables (``pfctl -sT``,
                                                 a plain list of names);
                                                 ``list`` answers a search
                                                 (``total``, ``rows`` of
                                                 ``{"ip": ...}``, ``!`` before
                                                 a negated entry) of at most
                                                 9999 rows on a GET. Only
                                                 after config.xml was read;
                                                 never ``add``, ``delete``,
                                                 ``flush`` or
                                                 ``find_references``. Bounded
                                                 by ``ALIAS_TABLE_*`` (see
                                                 ``_collect_alias_tables``)

Failure policy: every call is best-effort. A failed call is recorded in
``errors`` (named by its path and HTTP status, so a missing privilege or an
endpoint an older release lacks says which) and the collection goes on. A
rejected key (HTTP 401) or an unreachable firewall on the first call fails
the collection, as does a collection where no call answered.

Secrets: every payload goes through ``scrub_secrets``; interface rows keep
only a few of the configuration fields OPNsense attaches to them, and the
firmware status only its product and update fields (a business licence
keeps its expiry, nothing else). ``config.xml`` holds password hashes,
private keys and pre-shared keys: it is returned under ``config_xml`` for
the caller to store as a configuration backup and is never part of the
snapshot. Its DNS names and DHCP reservations (``names.names_from_config``:
no secrets) are returned under ``names`` for IPAM.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.integrations.opnsense.certificates import CERTIFICATE_PARTS, certificates_from_config, keep_rows
from netcontrol.integrations.opnsense.client import OpnsenseApiError, OpnsenseClient
from netcontrol.integrations.opnsense.ids import (
    IDS_MAX_PAGES,
    IDS_MAX_RULE_LOOKUPS,
    IDS_PAGE_ROWS,
    IDS_PRIVILEGE,
    PATH_IDS_ALERTS,
    PATH_IDS_RULE_INFO,
    PATH_IDS_STATUS,
    STATUS_DISABLED,
    STATUS_UNAVAILABLE,
    alert_rows,
    row_sid,
    row_time,
    rule_classtype,
)
from netcontrol.integrations.opnsense.names import names_from_config
from netcontrol.integrations.pathtrace.opnsense_config import parse_document, parse_xml
from netcontrol.integrations.traffic import parse_time
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.opnsense")

DEFAULT_OPTIONS: dict[str, Any] = {
    # Verify the firewall's TLS certificate.
    "verify_tls": True,
    # Gateway status (dpinger): status, loss, delay, stddev.
    "include_gateways": True,
    # IPsec (with the phase 2 child SAs), WireGuard and OpenVPN tunnel state.
    "include_vpn": True,
    # CARP / high availability: the virtual IPs and their state.
    "include_ha": True,
    # The routing table.
    "include_routes": True,
    # The security audit of the installed packages (pkg audit).
    "include_firmware_audit": True,
    # The ARP and NDP tables and the DHCP leases (ISC, Kea, Dnsmasq), fed
    # into MAC tracking and the DHCP leases of IPAM.
    "include_clients": True,
    # The filter rule counters (unused rules in the rule views).
    "include_rule_stats": True,
    # Health (CPU, memory, disks, temperature, state table) and the services
    # with whether each runs.
    "include_health": True,
    # The pf tables of the aliases config.xml cannot resolve (URL tables,
    # GeoIP, host names), for the path trace. Needs config.xml.
    "include_alias_tables": True,
    # The certificates and CAs of the trust store with their expiry (no key,
    # no PEM), for expiry alerts; config.xml on a release without the API.
    "include_certificates": True,
    # The intrusion detection (Suricata) alerts, kept as security events,
    # when the IDS is enabled. Also read by the monitoring poll.
    "include_ids_alerts": True,
    # Store config.xml as a configuration backup of the matching inventory host.
    "config_backup": True,
    # Attach data Plexus already collected over SNMP/SSH for the inventory
    # host that matches the firewall.
    "inventory_enrich": True,
}

_BOOL_OPTIONS = tuple(DEFAULT_OPTIONS)

ProgressCallback = Callable[[dict[str, Any]], None]

# Phase names the progress callback reports (the Topology page shows them).
PHASE_SYSTEM = "opnsense system"
PHASE_INTERFACES = "opnsense interfaces"
PHASE_GATEWAYS = "opnsense gateways"
PHASE_VPN = "opnsense vpn"
PHASE_ROUTES = "opnsense routes"
PHASE_HA = "opnsense ha"
PHASE_CLIENTS = "opnsense clients"
PHASE_RULES = "opnsense rules"
PHASE_HEALTH = "opnsense health"
PHASE_CERTIFICATES = "opnsense certificates"
PHASE_IDS = "opnsense ids alerts"
PHASE_FIRMWARE = "opnsense firmware"
PHASE_CONFIG = "opnsense config"
PHASE_ALIAS_TABLES = "opnsense alias tables"

# API paths, newer form first.
PATH_SYSTEM = ("diagnostics/system/system_information", "diagnostics/system/systemInformation")
PATH_FIRMWARE_STATUS = ("core/firmware/status",)
PATH_INTERFACES = ("interfaces/overview/interfaces_info", "interfaces/overview/interfacesInfo")
PATH_GATEWAYS = ("routes/gateway/status",)
PATH_ROUTES = ("diagnostics/interface/get_routes", "diagnostics/interface/getRoutes")
PATH_IPSEC = ("ipsec/sessions/search_phase1", "ipsec/sessions/searchPhase1")
PATH_IPSEC_PHASE2 = ("ipsec/sessions/search_phase2", "ipsec/sessions/searchPhase2")
PATH_IPSEC_CHILDREN = ("ipsec/connections/search_child", "ipsec/connections/searchChild")
PATH_CARP = ("diagnostics/interface/get_vip_status", "diagnostics/interface/getVipStatus")
PATH_WIREGUARD = ("wireguard/service/show",)
PATH_OPENVPN = ("openvpn/service/search_sessions", "openvpn/service/searchSessions")
# The ARP and NDP tables: the search form (22.1+) first, the plain list of
# older releases last.
PATH_ARP = (
    "diagnostics/interface/search_arp",
    "diagnostics/interface/searchArp",
    "diagnostics/interface/get_arp",
    "diagnostics/interface/getArp",
)
PATH_NDP = (
    "diagnostics/interface/search_ndp",
    "diagnostics/interface/searchNdp",
    "diagnostics/interface/get_ndp",
    "diagnostics/interface/getNdp",
)
# The DHCP lease backends: (key, name, paths, the privilege that grants them).
# A firewall runs one or two of them; a backend the release or its plugins
# lack answers 404 and is skipped without a warning.
LEASE_BACKENDS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("isc4", "ISC DHCPv4", ("dhcpv4/leases/search_lease", "dhcpv4/leases/searchLease"), "Status: DHCP leases"),
    ("isc6", "ISC DHCPv6", ("dhcpv6/leases/search_lease", "dhcpv6/leases/searchLease"), "Status: DHCPv6 leases"),
    ("kea4", "Kea DHCPv4", ("kea/leases4/search",), "Services: DHCP: Kea(v4)"),
    ("kea6", "Kea DHCPv6", ("kea/leases6/search",), "Services: DHCP: Kea(v6)"),
    ("dnsmasq", "Dnsmasq DHCP", ("dnsmasq/leases/search",), "Services: Dnsmasq DNS/DHCP: Settings"),
)
# Where config.xml says whether a lease backend's service is on (the Kea and
# Dnsmasq models: ``general/enabled``, ``enable``). ISC DHCP is enabled per
# interface and is not listed: its refused read always warns.
_LEASE_SWITCHES = {
    "kea4": "OPNsense/Kea/dhcp4/general/enabled",
    "kea6": "OPNsense/Kea/dhcp6/general/enabled",
    "dnsmasq": "dnsmasq/enable",
}
NO_LEASES_MESSAGE = "No DHCP lease endpoint answered (ISC, Kea, Dnsmasq): no DHCP leases were read"
PATH_RULE_STATS = ("firewall/filter_util/rule_stats", "firewall/filter_util/ruleStats")
# The pf tables behind the aliases (``AliasUtilController``; read-only actions only).
PATH_ALIAS_TABLES = ("firewall/alias_util/aliases",)
PATH_ALIAS_TABLE = "firewall/alias_util/list/"
ALIAS_TABLE_PRIVILEGE = "Diagnostics: PF Table IP addresses"
# Bounds of the alias table reads: entries kept per table (the 9999 rows a
# GET of ``list`` answers at most), entries over all tables, tables read.
# The built-in giants (the downloaded bogon tables, 100,000+ entries) are
# never read.
ALIAS_TABLE_MAX_ENTRIES = 9999
ALIAS_TABLES_MAX_ENTRIES = 30000
ALIAS_TABLES_MAX_READS = 30
ALIAS_TABLES_SKIPPED = ("bogons", "bogonsv6")
# Health: (key, paths, the privilege that grants them). The monitoring poll
# reads all but ``services`` (``POLL_HEALTH_PARTS``).
HEALTH_PARTS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (
        "resources",
        ("diagnostics/system/system_resources", "diagnostics/system/systemResources"),
        "Lobby: Dashboard",
    ),
    ("disk", ("diagnostics/system/system_disk", "diagnostics/system/systemDisk"), "Lobby: Dashboard"),
    (
        "temperature",
        ("diagnostics/system/system_temperature", "diagnostics/system/systemTemperature"),
        "Lobby: Dashboard",
    ),
    ("time", ("diagnostics/system/system_time", "diagnostics/system/systemTime"), "Lobby: Dashboard"),
    (
        "activity",
        ("diagnostics/activity/get_activity", "diagnostics/activity/getActivity"),
        "Diagnostics: System Activity",
    ),
    ("pf_states", ("diagnostics/firewall/pf_states", "diagnostics/firewall/pfStates"), "Lobby: Dashboard"),
    ("services", ("core/service/search",), "Status: Services"),
)
POLL_HEALTH_PARTS = tuple(key for key, _paths, _privilege in HEALTH_PARTS if key != "services")
PATH_FIRMWARE_RUNNING = "core/firmware/running"
PATH_AUDIT = "core/firmware/audit"
PATH_AUDIT_STATUS = "core/firmware/upgradestatus"
PATH_CONFIG = "core/backup/download/this"
CONFIG_PRIVILEGE = "Diagnostics: Configuration History"
NOT_CONFIG_XML_MESSAGE = "The configuration download did not answer with an OPNsense config.xml"

# The audit runs in the background on the firewall: how often and how many
# times its progress is read before the collection stops waiting.
AUDIT_POLL_SECONDS = 2.0
AUDIT_MAX_POLLS = 45
_AUDIT_MARKER = "AUDIT SECURITY"
_DONE_MARKER = "***DONE***"

# The interface configuration fields kept (OPNsense attaches the whole
# interface section of config.xml to each row).
_INTERFACE_CONFIG_KEPT = ("descr", "enable", "ipaddr", "ipaddrv6", "subnet", "subnetv6", "mtu", "gateway")
# The firmware status fields kept.
_FIRMWARE_KEPT = (
    "status",
    "status_msg",
    "status_reboot",
    "needs_reboot",
    "upgrade_needs_reboot",
    "upgrade_major_version",
    "last_check",
    "os_version",
    "product_target",
)
_PRODUCT_KEPT = (
    "product_name",
    "product_version",
    "product_latest",
    "product_arch",
    "product_series",
    "product_nickname",
    "product_id",
    "product_abi",
    "product_time",
)

_VULNERABLE = re.compile(r"^(?P<name>\S+)-(?P<version>[^-\s]+) is vulnerable:?\s*$")
_PROBLEMS = re.compile(r"(\d+) problem\(s\) in (\d+) (?:installed )?package\(s\) found")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
# What ``pkg audit -F`` (freebsd/pkg ``src/audit.c``, ``libpkg/pkg_audit.c``)
# and OPNsense's ``output_cmd`` print when the audit did not run to its end:
# the vulnerability database could not be fetched, opened or read, or the
# package database could not be. Lower case.
_AUDIT_FAILURES = (
    "cannot fetch vulnxml",
    "cannot process vulnxml",
    "unable to open vulnxml",
    "try running 'pkg audit -f' first",
    "insufficient privileges to read the package database",
    "error accessing the package database",
    "cannot get a read lock",
    "cannot get an advisory lock",
    "insufficient space for audit database",
    "audit database exceeds size limit",
    "cannot extract audit database",
    "cannot read audit database",
    "safety violation",
)
_VUXML_ID = re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.html", re.IGNORECASE)


def sanitize_options(raw: object) -> dict[str, Any]:
    """Coerce stored/user-supplied build options onto the known schema."""
    src = raw if isinstance(raw, dict) else {}
    opts = dict(DEFAULT_OPTIONS)
    for key in _BOOL_OPTIONS:
        if key in src:
            opts[key] = bool(src[key])
    return opts


def _error(scope: str, exc: OpnsenseApiError, *, paths: tuple[str, ...] = ()) -> dict[str, Any]:
    """A collection warning for a failed call: what was refused and why."""
    path = exc.path or ("/" + paths[0] if paths else "")
    message = f"{exc}: {exc.detail}" if exc.detail else str(exc)
    if exc.status_code == 403:
        message += " (the API user lacks the privilege for this page)"
    elif exc.status_code == 404:
        message += " (this OPNsense release has no such endpoint, or the plugin is not installed)"
    return {"scope": scope, "path": path, "status": exc.status_code, "message": message}


def info_warning(scope: str, path: str, message: str) -> dict[str, Any]:
    """A warning about what the firewall reported (an update pending, a
    vulnerable package, a config backup not stored), not about a failed
    call. ``info`` tells availability tracking that the collection itself
    was complete."""
    return {"scope": scope, "path": path, "status": None, "message": message, "info": True}


def _rows(body: Any, key: str = "rows") -> list[dict]:
    """The records of an OPNsense search answer (``{"rows": [...]}``) or of
    a plain list."""
    found = body.get(key) if isinstance(body, dict) else body
    return [r for r in found if isinstance(r, dict)] if isinstance(found, list) else []


def scrub_interface(row: dict) -> dict:
    """An interface row with only the configuration fields Plexus shows."""
    cleaned = {k: v for k, v in row.items() if k not in ("config", "statistics")}
    config = row.get("config")
    if isinstance(config, dict):
        cleaned["config"] = {k: config[k] for k in _INTERFACE_CONFIG_KEPT if k in config}
    return scrub_secrets(cleaned)


def scrub_firmware(status: Any) -> dict | None:
    """The firmware status without the mirror, repository and licence details."""
    if not isinstance(status, dict):
        return None
    cleaned: dict[str, Any] = {k: status[k] for k in _FIRMWARE_KEPT if k in status}
    found = status.get("product")
    product: dict[str, Any] = found if isinstance(found, dict) else {}
    cleaned["product"] = {k: product[k] for k in _PRODUCT_KEPT if k in product}
    license_info = product.get("product_license")
    if isinstance(license_info, dict) and license_info.get("valid_to"):
        cleaned["product"]["license_valid_to"] = license_info["valid_to"]
    packages = status.get("all_packages")
    if isinstance(packages, dict):
        packages = list(packages.values())
    if isinstance(packages, list):
        cleaned["updates"] = [
            {k: p.get(k) for k in ("name", "old", "new", "reason")} for p in packages if isinstance(p, dict)
        ]
    sets = status.get("all_sets")
    if isinstance(sets, dict):
        sets = list(sets.values())
    if isinstance(sets, list):
        cleaned["upgrade_sets"] = [
            {k: p.get(k) for k in ("name", "old", "new", "reason")} for p in sets if isinstance(p, dict)
        ]
    return scrub_secrets(cleaned)


def _audit_failure(line: str) -> str:
    """The line when it reports that the audit could not run (see
    ``_AUDIT_FAILURES``; any other ``pkg:`` error line too, e.g. a fetch
    error such as ``pkg: https://...: No address record``), else ``""``."""
    lowered = line.lower()
    if any(marker in lowered for marker in _AUDIT_FAILURES):
        return line
    if lowered.startswith("pkg:") and not lowered.startswith("pkg: warning"):
        return line
    return ""


def parse_audit_log(text: str) -> dict[str, Any]:
    """The findings of a ``pkg audit`` run from its log, as the firmware
    progress log carries it: per vulnerable package its name and version,
    and per issue its description, CVE ids and VuXML link; and whether the
    audit verifiably ran to its end (``completed``).

    ``pkg audit`` prints (freebsd/pkg ``src/audit.c``)::

        openssl-3.0.14 is vulnerable:
          OpenSSL -- multiple vulnerabilities
          CVE: CVE-2024-0001
          WWW: https://vuxml.FreeBSD.org/freebsd/<id>.html

        1 problem(s) in 1 package(s) found.

    The result line is printed only when the vulnerability database was
    fetched and processed, also when nothing is vulnerable ("0 problem(s)
    in 0 package(s) found."); a failed fetch ends ``pkg audit`` before it.
    The audit is ``completed`` only with that line, no failure line (see
    ``_audit_failure``) and findings that agree with it. Otherwise
    ``incomplete_reason`` says why and the findings (if any) are partial:
    "no findings" then means nothing.
    """
    findings: list[dict[str, Any]] = []
    package: dict[str, str] | None = None
    issue: dict[str, Any] | None = None
    problems: int | None = None
    packages: int | None = None
    failure = ""
    for line in (text or "").splitlines():
        stripped = line.strip()
        counted = _PROBLEMS.search(stripped)
        if counted:
            problems, packages = int(counted.group(1)), int(counted.group(2))
            package = issue = None
            continue
        failure = failure or _audit_failure(stripped)
        match = _VULNERABLE.match(stripped) if not line.startswith((" ", "\t")) else None
        if match:
            package = {"package": match.group("name"), "version": match.group("version")}
            issue = None
            continue
        if package is None or not stripped:
            continue
        if stripped.startswith("CVE:"):
            if issue is not None:
                cve = stripped.removeprefix("CVE:").strip()
                if cve and cve not in issue["cves"]:
                    issue["cves"].append(cve)
            continue
        if stripped.startswith("WWW:"):
            if issue is not None:
                url = stripped.removeprefix("WWW:").strip()
                issue["url"] = url
                found = _VUXML_ID.search(url)
                issue["vuxml_id"] = found.group(1).lower() if found else ""
                issue = None
            continue
        if stripped.startswith(("Affected versions:", "Packages that depend on", "<", ">", "=")):
            continue
        if issue is None:
            issue = {**package, "description": stripped, "cves": [], "url": "", "vuxml_id": ""}
            findings.append(issue)
    reason = ""
    if failure:
        reason = f"pkg audit reported an error: {failure[:200]}"
    elif problems is None:
        reason = "the log has no pkg audit result line (the audit was cut short or its output is incomplete)"
    elif bool(packages) != bool(findings):
        reason = f"the result line reports {packages} vulnerable package(s) but the log lists {len(findings)} issue(s)"
    return {
        "findings": findings,
        "problems": problems if problems is not None else len(findings),
        "completed": not reason,
        "incomplete_reason": reason,
    }


def incomplete_audit(log: str, reason: str) -> dict[str, Any]:
    """The result of an audit that did not verifiably finish: whatever the
    log shows so far, never ``completed``."""
    return {
        "ran_at": datetime.now(UTC).isoformat(timespec="seconds"),
        **parse_audit_log(log),
        "completed": False,
        "incomplete_reason": reason,
    }


async def download_config(client: OpnsenseClient) -> str | None:
    """The firewall's ``config.xml`` (``PATH_CONFIG``, privilege
    ``CONFIG_PRIVILEGE``), as text: password hashes, private keys and
    pre-shared keys included, so the caller stores it as a configuration
    backup and nowhere else. ``None`` when the answer is not an OPNsense
    config.xml (a login page, a proxy's error page). Raises
    ``OpnsenseApiError`` for a failed call. Used by the collection and by a
    backup policy run (``netcontrol.routes.opnsense_backup``)."""
    text = await client.get_text(PATH_CONFIG)
    return text if "<opnsense" in text[:4096] else None


async def collect_opnsense(
    client: OpnsenseClient,
    options: dict[str, Any] | None = None,
    progress: ProgressCallback | None = None,
    *,
    want_config: bool | None = None,
    ids_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect one firewall. Raises ``OpnsenseApiError`` only when the key
    is rejected, the firewall cannot be reached, or no call answered.
    ``want_config`` (default: the ``config_backup`` option) reads config.xml.
    ``ids_state``: what the IDS read starts from (``{"since", "classtypes"}``,
    see ``collect_ids_alerts``); without it every alert of the first pages
    is read."""
    opts = sanitize_options(options)
    if want_config is None:
        want_config = bool(opts["config_backup"])
    errors: list[dict[str, Any]] = []
    total = 3 + int(opts["include_gateways"]) + 3 * int(opts["include_vpn"]) + int(opts["include_routes"])
    total += int(opts["include_ha"]) + 3 * int(opts["include_firmware_audit"]) + int(want_config)
    total += (2 + len(LEASE_BACKENDS)) * int(opts["include_clients"])
    total += int(opts["include_rule_stats"])
    total += len(HEALTH_PARTS) * int(opts["include_health"])
    total += len(CERTIFICATE_PARTS) * int(opts["include_certificates"])
    # The IDS status; its pages and rule lookups are added as they are made.
    total += int(opts["include_ids_alerts"])
    done = 0
    answered = 0
    first_error: OpnsenseApiError | None = None

    def report(phase: str, **fields: Any) -> None:
        if progress is not None:
            progress({"phase": phase, "calls_done": done, "calls_total": total, **fields})

    async def best_effort(
        scope: str, paths: tuple[str, ...], *, params: dict | None = None, body: dict | None = None
    ) -> Any:
        nonlocal done, answered, first_error
        try:
            if body is not None:
                _path, found = await client.post_first(paths, body)
            else:
                _path, found = await client.get_first(paths, params)
            answered += 1
            return found
        except OpnsenseApiError as exc:
            if exc.transport or exc.status_code == 401:
                # A wrong key or a firewall that cannot be reached: nothing
                # else would answer either.
                raise
            first_error = first_error or exc
            errors.append(_error(scope, exc, paths=paths))
            return None
        finally:
            done += 1

    report(PHASE_SYSTEM)
    found = await best_effort("system", PATH_SYSTEM)
    system = scrub_secrets(found) if isinstance(found, dict) else None
    found = await best_effort("firmware", PATH_FIRMWARE_STATUS)
    firmware = scrub_firmware(found)

    report(PHASE_INTERFACES)
    found = await best_effort("interfaces", PATH_INTERFACES)
    interfaces = [scrub_interface(r) for r in _rows(found)] if found is not None else None
    report(PHASE_INTERFACES, interfaces=len(interfaces or []))

    gateways: list[dict] | None = None
    if opts["include_gateways"]:
        report(PHASE_GATEWAYS)
        found = await best_effort("gateways", PATH_GATEWAYS)
        gateways = scrub_secrets(_rows(found, "items")) if found is not None else None
        report(PHASE_GATEWAYS, gateways=len(gateways or []))

    vpn: dict[str, Any] = dict.fromkeys(VPN_KEYS)
    if opts["include_vpn"]:
        report(PHASE_VPN)

        def count_children(ipsec: list[dict]) -> None:
            nonlocal total
            total += sum(1 for r in ipsec if r.get("connected") and r.get("name"))
            total += sum(1 for r in ipsec if _UUID.match(str(r.get("ikeid") or "")))

        vpn = await collect_vpn(best_effort, on_ipsec=count_children)
        report(PHASE_VPN, tunnels=sum(len(vpn[k] or []) for k in ("ipsec", "wireguard", "openvpn")))

    carp: dict[str, Any] | None = None
    if opts["include_ha"]:
        report(PHASE_HA)
        found = await best_effort("ha", PATH_CARP)
        if isinstance(found, dict):
            state = found.get("carp")
            carp = scrub_secrets({"rows": _rows(found), "carp": state if isinstance(state, dict) else {}})

    routes: list[dict] | None = None
    if opts["include_routes"]:
        report(PHASE_ROUTES)
        found = await best_effort("routes", PATH_ROUTES)
        routes = scrub_secrets(_rows(found)) if found is not None else None

    clients: dict[str, Any] | None = None
    if opts["include_clients"]:
        report(PHASE_CLIENTS)
        clients, answered_clients = await _collect_clients(client, errors)
        done += 2 + len(LEASE_BACKENDS)
        answered += answered_clients
        report(
            PHASE_CLIENTS,
            arp=len(clients["arp"] or []),
            ndp=len(clients["ndp"] or []),
            leases=sum(len(rows) for rows in (clients["leases"] or {}).values()),
        )

    rule_stats: dict[str, Any] | None = None
    if opts["include_rule_stats"]:
        report(PHASE_RULES)
        found = await best_effort("rules", PATH_RULE_STATS)
        rule_stats = scrub_secrets(found) if isinstance(found, dict) else None

    health: dict[str, Any] | None = None
    if opts["include_health"]:
        report(PHASE_HEALTH)
        health, answered_health = await collect_health(client, errors)
        done += len(HEALTH_PARTS)
        answered += answered_health
        report(PHASE_HEALTH, services=len(health["services"] or []))

    certificates: dict[str, Any] | None = None
    no_trust_api = False
    if opts["include_certificates"]:
        report(PHASE_CERTIFICATES)
        certificates, answered_certificates, no_trust_api = await collect_certificates(client, errors)
        done += len(CERTIFICATE_PARTS)
        answered += answered_certificates
        if certificates is not None:
            report(PHASE_CERTIFICATES, certificates=len(certificates["certificates"]))

    ids_alerts: dict[str, Any] | None = None
    if opts["include_ids_alerts"]:
        report(PHASE_IDS)
        state = ids_state or {}
        ids_alerts, ids_calls, answered_ids = await collect_ids_alerts(
            client, errors, since=state.get("since"), classtypes=state.get("classtypes")
        )
        total += ids_calls - 1
        done += ids_calls
        answered += answered_ids
        report(PHASE_IDS, alerts=len((ids_alerts or {}).get("rows") or []))

    audit: dict[str, Any] | None = None
    if opts["include_firmware_audit"]:
        report(PHASE_FIRMWARE)
        audit = await _run_audit(client, errors)
        done += 3
        if audit is not None:
            answered += 1

    config_xml: str | None = None
    if want_config:
        report(PHASE_CONFIG)
        try:
            config_xml = await download_config(client)
            answered += 1
            if config_xml is None:
                errors.append(
                    {"scope": "config", "path": "/" + PATH_CONFIG, "status": None, "message": NOT_CONFIG_XML_MESSAGE}
                )
        except OpnsenseApiError as exc:
            if exc.transport or exc.status_code == 401:
                raise
            first_error = first_error or exc
            errors.append(_error("config", exc, paths=(PATH_CONFIG,)))
        done += 1

    if clients is not None and config_xml:
        await _drop_refused_idle_leases(clients, config_xml, errors)

    alias_tables: dict[str, Any] | None = None
    wanted: list[str] = []
    if opts["include_alias_tables"] and config_xml:
        # Parsing config.xml is CPU work: kept off the event loop.
        wanted = await asyncio.to_thread(tables_wanted, config_xml)
    if wanted:
        report(PHASE_ALIAS_TABLES)
        total += 1
        listed = await best_effort("alias tables", PATH_ALIAS_TABLES)
        _name_privilege(errors, "alias tables", ALIAS_TABLE_PRIVILEGE)
        if listed is not None:
            plan = plan_alias_tables(wanted, listed)
            started = done
            total += len(plan["read"])
            alias_tables = await _collect_alias_tables(plan, best_effort, errors)
            # Fewer reads than planned when a refusal or the entry bound stopped them.
            total -= len(plan["read"]) - (done - started)
            report(PHASE_ALIAS_TABLES, tables=len(alias_tables["tables"]))
    elif opts["include_alias_tables"] and config_xml:
        # No alias needs a table: none is stored (any older ones are dropped).
        alias_tables = await _collect_alias_tables(plan_alias_tables([], []), best_effort, errors)

    if no_trust_api:
        certificates = await _certificates_fallback(config_xml, errors)

    # The DNS names and DHCP reservations for IPAM (see ``names``): parsed
    # while the XML is in hand (CPU work, off the event loop); none without it.
    names = await asyncio.to_thread(names_from_config, config_xml) if config_xml else None

    if not answered and first_error is not None:
        raise first_error

    report("collected")
    LOGGER.info(
        "opnsense: collected firewall %s - %d interfaces, %d gateways, %d calls, %d errors",
        client.base_url,
        len(interfaces or []),
        len(gateways or []),
        client.stats["requests"],
        len(errors),
    )
    return {
        "firewall": {
            "name": "",
            "base_url": client.base_url,
            "address": urlsplit(client.base_url).hostname or "",
        },
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "system": system,
        "firmware": firmware,
        "interfaces": interfaces,
        "gateways": gateways,
        "routes": routes,
        **vpn,
        "carp": carp,
        "clients": clients,
        "rule_stats": rule_stats,
        "health": health,
        "certificates": certificates,
        # Never part of the snapshot: the caller stores them as security events.
        "ids_alerts": ids_alerts,
        "audit": audit,
        # Never part of the snapshot: the caller stores it as a config backup.
        "config_xml": config_xml,
        # Never part of the snapshot: the caller stores it for the path trace.
        "alias_tables": alias_tables,
        # Never part of the snapshot: the caller stores them as IPAM allocations.
        "names": names,
        "errors": errors,
        "stats": dict(client.stats),
        "options": opts,
    }


# The VPN part of a collection (``collect_vpn``), as raw keys.
VPN_KEYS = ("ipsec", "ipsec_phase2", "ipsec_child_config", "wireguard", "openvpn", "vpn_read_at")


async def collect_vpn(
    best_effort: Callable[..., Awaitable[Any]],
    *,
    configured: bool = True,
    on_ipsec: Callable[[list[dict]], None] | None = None,
) -> dict[str, Any]:
    """The VPN payloads (``VPN_KEYS``): the IPsec connections with their
    child SAs (``_collect_ipsec_children``; the configured ones only with
    ``configured``), the WireGuard interfaces and peers and the OpenVPN
    instances and sessions, and when they were read (``vpn_read_at``, UTC
    ISO; the traffic rates are computed over it). A part that did not
    answer is ``None``. ``best_effort(scope, paths, params=, body=)``
    answers a call or ``None`` (``collect_opnsense``'s, or ``call_reader``'s
    for the monitoring poll); ``on_ipsec`` is told the connections before
    their child SAs are read."""
    found = await best_effort("vpn", PATH_IPSEC)
    ipsec = scrub_secrets(_rows(found)) if found is not None else None
    ipsec_phase2 = ipsec_child_config = None
    if ipsec:
        if on_ipsec is not None:
            on_ipsec(ipsec)
        ipsec_phase2, ipsec_child_config = await _collect_ipsec_children(ipsec, best_effort, configured=configured)
    found = await best_effort("vpn", PATH_WIREGUARD)
    wireguard = scrub_secrets(_rows(found)) if found is not None else None
    found = await best_effort("vpn", PATH_OPENVPN)
    openvpn = scrub_secrets(_rows(found)) if found is not None else None
    return {
        "ipsec": ipsec,
        "ipsec_phase2": ipsec_phase2,
        "ipsec_child_config": ipsec_child_config,
        "wireguard": wireguard,
        "openvpn": openvpn,
        "vpn_read_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }


def call_reader(client: OpnsenseClient, errors: list[dict[str, Any]]) -> Callable[..., Awaitable[Any]]:
    """A ``best_effort`` for ``collect_vpn`` outside a collection: one
    call's answer, or ``None`` with a warning in ``errors``. A rejected key
    or an unreachable firewall raises."""

    async def read(scope: str, paths: tuple[str, ...], *, params: dict | None = None, body: dict | None = None) -> Any:
        try:
            if body is not None:
                return (await client.post_first(paths, body))[1]
            return (await client.get_first(paths, params))[1]
        except OpnsenseApiError as exc:
            if exc.transport or exc.status_code == 401:
                raise
            errors.append(_error(scope, exc, paths=paths))
            return None

    return read


async def _collect_ipsec_children(
    ipsec: list[dict], best_effort: Callable[..., Awaitable[Any]], *, configured: bool = True
) -> tuple[dict[str, list[dict]] | None, dict[str, list[dict]] | None]:
    """The child SAs of each IPsec connection: the installed ones of every
    connection that has an SA (``search_phase2``, by phase 1 name) and,
    with ``configured``, the configured ones of every connection of the
    Connections model (``search_child``, by its UUID). A call that is
    refused or unknown is not repeated for the next connection (one
    warning, the map without that part). ``None`` for a part that never
    answered or was not read."""
    phase2: dict[str, list[dict]] | None = None
    found_config: dict[str, list[dict]] | None = None
    phase2_ok, config_ok = True, configured
    for row in ipsec:
        name = str(row.get("name") or "")
        if phase2_ok and row.get("connected") and name:
            found = await best_effort("vpn", PATH_IPSEC_PHASE2, body={"id": name})
            if found is None:
                phase2_ok = False
            else:
                phase2 = phase2 if phase2 is not None else {}
                phase2[name] = scrub_secrets(_rows(found))
        ikeid = str(row.get("ikeid") or "")
        if config_ok and _UUID.match(ikeid):
            found = await best_effort("vpn", PATH_IPSEC_CHILDREN, params={"connection": ikeid})
            if found is None:
                config_ok = False
            else:
                found_config = found_config if found_config is not None else {}
                found_config[ikeid] = scrub_secrets(_rows(found))
    return phase2, found_config


async def _collect_clients(client: OpnsenseClient, errors: list[dict[str, Any]]) -> tuple[dict[str, Any], int]:
    """The ARP and NDP tables and the leases of every DHCP backend that
    answers, and how many calls answered. ``arp`` / ``ndp`` are ``None``
    when not read; ``leases`` maps each backend that answered to its rows
    (``None`` when none did). A refused call is a warning that names the
    privilege it needs; a lease backend that is not there (404: not on this
    release, plugin not installed) is skipped quietly, with one ``info``
    warning when no backend answered at all."""
    answered = 0

    async def read(paths: tuple[str, ...], privilege: str, *, quiet_404: bool = False) -> list[dict] | None:
        nonlocal answered
        try:
            _path, found = await client.get_first(paths)
        except OpnsenseApiError as exc:
            if exc.transport or exc.status_code == 401:
                raise
            if not (quiet_404 and exc.status_code == 404):
                warning = _error("clients", exc, paths=paths)
                if exc.status_code == 403:
                    warning["message"] += f"; privilege needed: {privilege}"
                errors.append(warning)
            return None
        answered += 1
        return scrub_secrets(_rows(found))

    arp = await read(PATH_ARP, "Diagnostics: ARP Table")
    ndp = await read(PATH_NDP, "Diagnostics: NDP Table")
    leases: dict[str, list[dict]] = {}
    for key, _name, paths, privilege in LEASE_BACKENDS:
        rows = await read(paths, privilege, quiet_404=True)
        if rows is not None:
            leases[key] = rows
    if not leases:
        _note_no_leases(errors)
    return {"arp": arp, "ndp": ndp, "leases": leases or None}, answered


def _note_no_leases(errors: list[dict[str, Any]]) -> None:
    """One ``info`` warning that no lease backend answered, unless a refused
    clients call already says why."""
    if not any(e.get("scope") == "clients" and e.get("status") == 403 for e in errors):
        errors.append(info_warning("clients", "/" + LEASE_BACKENDS[0][2][0], NO_LEASES_MESSAGE))


def lease_backends_off(config_xml: str) -> set[str]:
    """The lease backends (keys of ``LEASE_BACKENDS``) whose service
    ``config_xml`` shows as off: Kea DHCPv4 / DHCPv6 not enabled, Dnsmasq
    not enabled or without a DHCP range. Empty when the text is no OPNsense
    configuration. ISC DHCP is never in it."""
    root = parse_xml(config_xml)
    if root is None:
        return set()
    off = {key for key, path in _LEASE_SWITCHES.items() if (root.findtext(path) or "").strip() != "1"}
    if not any(len(ranges) for ranges in root.findall("dnsmasq/dhcp_ranges")):
        off.add("dnsmasq")
    return off


def _refused_lease_paths(errors: list[dict[str, Any]], keys: set[str] | None = None) -> set[str]:
    """The warning paths of the refused (403) lease reads of the backends
    ``keys`` (default: those config.xml can show as off)."""
    wanted = _LEASE_SWITCHES.keys() if keys is None else keys
    paths = {"/" + path for key, _name, backend, _privilege in LEASE_BACKENDS if key in wanted for path in backend}
    return {
        str(e.get("path"))
        for e in errors
        if e.get("scope") == "clients" and e.get("status") == 403 and e.get("path") in paths
    }


async def _drop_refused_idle_leases(clients: dict[str, Any], config_xml: str, errors: list[dict[str, Any]]) -> None:
    """Take the refused (403) lease reads of the backends ``config_xml``
    shows as off out of ``errors``: a firewall that does not run Kea or
    Dnsmasq DHCP has no leases there, so its API user needs no privilege
    for them (they also allow changing that service). Without
    ``config_xml`` (**Config backup** off, the download refused) the
    warnings stay."""
    if not _refused_lease_paths(errors):
        return
    # Parsing config.xml is CPU work: kept off the event loop.
    off = await asyncio.to_thread(lease_backends_off, config_xml)
    dropped = _refused_lease_paths(errors, off)
    if not dropped:
        return
    errors[:] = [e for e in errors if not (e.get("scope") == "clients" and e.get("path") in dropped)]
    if not clients.get("leases"):
        _note_no_leases(errors)


# The fields kept of a ``core/service/search`` row.
_SERVICE_KEPT = ("id", "name", "description", "running", "locked")
# ``top`` prints a handful of header lines; more is not a header.
_MAX_ACTIVITY_HEADERS = 20


def _health_part(key: str, body: Any) -> Any:
    """One health answer as it is kept: the activity's header lines only
    (its process list names every command line), the service rows with
    ``_SERVICE_KEPT``, the temperature rows, else the scrubbed answer."""
    if key == "activity":
        headers = body.get("headers") if isinstance(body, dict) else None
        if not isinstance(headers, list):
            return None
        return {"headers": [h for h in headers if isinstance(h, str)][:_MAX_ACTIVITY_HEADERS]}
    if key == "services":
        return [{k: row.get(k) for k in _SERVICE_KEPT} for row in _rows(body)]
    if key == "temperature":
        return scrub_secrets(_rows(body))
    return scrub_secrets(body) if isinstance(body, dict) else None


async def collect_health(
    client: OpnsenseClient, errors: list[dict[str, Any]], parts: tuple[str, ...] | None = None
) -> tuple[dict[str, Any], int]:
    """The health answers (``HEALTH_PARTS``; ``parts``: only those keys)
    and how many calls answered. A part that was not read is ``None``. A
    refused call is a warning that names the privilege it needs; an
    endpoint the release lacks (404) is left out, with one ``info`` warning
    for all of them. A rejected key or an unreachable firewall raises."""
    health: dict[str, Any] = {key: None for key, _paths, _privilege in HEALTH_PARTS}
    missing: list[str] = []
    answered = 0
    for key, paths, privilege in HEALTH_PARTS:
        if parts is not None and key not in parts:
            continue
        try:
            _path, found = await client.get_first(paths)
        except OpnsenseApiError as exc:
            if exc.transport or exc.status_code == 401:
                raise
            if exc.status_code == 404:
                missing.append("/" + paths[0])
                continue
            warning = _error("health", exc, paths=paths)
            if exc.status_code == 403:
                warning["message"] += f"; privilege needed: {privilege}"
            errors.append(warning)
            continue
        answered += 1
        health[key] = _health_part(key, found)
    if missing:
        errors.append(
            info_warning(
                "health",
                missing[0],
                "This OPNsense release has no " + ", ".join(missing) + ": that part of the health was not read",
            )
        )
    return health, answered


async def collect_certificates(
    client: OpnsenseClient, errors: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, int, bool]:
    """The certificates and CAs of the trust store (``CERTIFICATE_PARTS``,
    each row with only the fields ``certificates.keep_rows`` keeps: the
    answers carry the private keys, which are dropped here), how many calls
    answered, and whether the release has no trust API (both answered 404:
    the caller falls back to config.xml). ``None`` when nothing answered. A
    refused call is a warning that names the privilege it needs. A rejected
    key or an unreachable firewall raises."""
    found: dict[str, Any] = {"source": "api", "certificates": [], "authorities": []}
    answered = missing = 0
    for key, paths, privilege in CERTIFICATE_PARTS:
        try:
            _path, body = await client.get_first(paths)
        except OpnsenseApiError as exc:
            if exc.transport or exc.status_code == 401:
                raise
            if exc.status_code == 404:
                missing += 1
                continue
            warning = _error("certificates", exc, paths=paths)
            if exc.status_code == 403:
                warning["message"] += f"; privilege needed: {privilege}"
            errors.append(warning)
            continue
        answered += 1
        found[key] = scrub_secrets(keep_rows(body, key))
    if not answered:
        return None, 0, missing == len(CERTIFICATE_PARTS)
    return found, answered, False


async def _certificates_fallback(config_xml: str | None, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The certificates of ``config_xml`` for a release without the trust
    API, with an ``info`` warning that says where they came from, or that
    they were not read (no config.xml)."""
    path = "/" + CERTIFICATE_PARTS[0][1][0]
    found = await asyncio.to_thread(certificates_from_config, config_xml) if config_xml else None
    if found is None:
        errors.append(
            info_warning(
                "certificates",
                path,
                "This OPNsense release has no trust API (24.7+) and config.xml was not read: "
                "certificate expiry is not tracked",
            )
        )
        return None
    errors.append(
        info_warning(
            "certificates",
            path,
            "This OPNsense release has no trust API (24.7+): the certificates were read from config.xml",
        )
    )
    return found


async def collect_ids_alerts(
    client: OpnsenseClient,
    errors: list[dict[str, Any]],
    *,
    since: str | None = None,
    classtypes: dict[int, str] | None = None,
) -> tuple[dict[str, Any] | None, int, int]:
    """The intrusion detection alerts (see ``ids``), how many calls were
    made and how many answered.

    The IDS status first: an IDS that is ``disabled`` reads nothing more, and
    a firewall without the IDS API (404) is ``unavailable``, quietly. Then
    the alerts, newest first, ``IDS_PAGE_ROWS`` a page, until a row older
    than ``since`` (the newest event stored, UTC text; ``None``: no stop), a
    short page or ``IDS_MAX_PAGES`` (``truncated``: older new alerts were
    left unread). Then the classtype of each new signature not in
    ``classtypes`` (sid -> classtype already known), at most
    ``IDS_MAX_RULE_LOOKUPS`` (``lookups_skipped``: how many were left).
    ``None`` when the status call was refused or failed; a refused page or
    lookup keeps what was read with a warning. A rejected key or an
    unreachable firewall raises."""
    calls = answered = 0

    def refused(exc: OpnsenseApiError, paths: tuple[str, ...]) -> None:
        warning = _error("ids", exc, paths=paths)
        if exc.status_code == 403:
            warning["message"] += f"; privilege needed: {IDS_PRIVILEGE}"
        errors.append(warning)

    try:
        calls += 1
        _path, body = await client.get_first(PATH_IDS_STATUS)
    except OpnsenseApiError as exc:
        if exc.transport or exc.status_code == 401:
            raise
        if exc.status_code == 404:
            return {"status": STATUS_UNAVAILABLE, "rows": [], "classtypes": {}}, calls, answered
        refused(exc, PATH_IDS_STATUS)
        return None, calls, answered
    answered += 1
    status = str((body.get("status") if isinstance(body, dict) else "") or "unknown").strip().lower()[:20]
    found: dict[str, Any] = {
        "status": status,
        "read_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "since": since,
        "rows": [],
        "classtypes": {},
        "pages": 0,
        "truncated": False,
        "lookups_skipped": 0,
    }
    if status == STATUS_DISABLED:
        return found, calls, answered
    cutoff = parse_time(since) if since else None
    for page in range(1, IDS_MAX_PAGES + 1):
        try:
            calls += 1
            _path, body = await client.post_first(PATH_IDS_ALERTS, {"rowCount": IDS_PAGE_ROWS, "current": page})
        except OpnsenseApiError as exc:
            if exc.transport or exc.status_code == 401:
                raise
            refused(exc, PATH_IDS_ALERTS)
            break
        answered += 1
        found["pages"] = page
        rows = alert_rows(body)
        older = False
        for row in rows:
            at = row_time(row)
            if cutoff is not None and at is not None and at < cutoff:
                older = True
                break
            found["rows"].append(row)
        if older or len(rows) < IDS_PAGE_ROWS:
            break
    else:
        found["truncated"] = True
    known = classtypes or {}
    wanted: list[int] = []
    for row in found["rows"]:
        sid = row_sid(row)
        alert = row.get("alert")
        if sid is None or sid in known or sid in wanted or (isinstance(alert, dict) and alert.get("category")):
            continue
        wanted.append(sid)
    for position, sid in enumerate(wanted[:IDS_MAX_RULE_LOOKUPS]):
        paths = tuple(f"{path}{sid}" for path in PATH_IDS_RULE_INFO)
        try:
            calls += 1
            _path, body = await client.get_first(paths)
        except OpnsenseApiError as exc:
            if exc.transport or exc.status_code == 401:
                raise
            refused(exc, paths)
            found["lookups_skipped"] = len(wanted) - position - 1
            break
        answered += 1
        found["classtypes"][sid] = rule_classtype(body)
    else:
        found["lookups_skipped"] = max(0, len(wanted) - IDS_MAX_RULE_LOOKUPS)
    return found, calls, answered


async def _run_audit(client: OpnsenseClient, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Start the security audit and wait for its result. ``None`` (with a
    warning) when it could not be started; an audit that started but did
    not verifiably finish (still running when the wait ends, a firmware
    task error, a log without pkg audit's result line, a fetch error) is
    returned with ``completed`` false and the reason, so nothing is
    concluded from it."""
    log = ""
    try:
        running = await client.get(PATH_FIRMWARE_RUNNING)
        if isinstance(running, dict) and str(running.get("status") or "").strip().lower() == "busy":
            errors.append(
                info_warning(
                    "firmware",
                    "/" + PATH_FIRMWARE_RUNNING,
                    "The security audit was skipped: another firmware task is running on the firewall",
                )
            )
            return None
        await client.post(PATH_AUDIT)
        for _attempt in range(AUDIT_MAX_POLLS):
            await asyncio.sleep(AUDIT_POLL_SECONDS)
            status = await client.get(PATH_AUDIT_STATUS)
            status = status if isinstance(status, dict) else {}
            log = str(status.get("log") or "")
            if str(status.get("status") or "") == "done" and _AUDIT_MARKER in log and _DONE_MARKER in log:
                return {"ran_at": datetime.now(UTC).isoformat(timespec="seconds"), **parse_audit_log(log)}
            if str(status.get("status") or "") == "error":
                return incomplete_audit(log, "the firmware task reported an error")
    except OpnsenseApiError as exc:
        if exc.transport or exc.status_code == 401:
            raise
        errors.append(_error("firmware", exc, paths=(PATH_AUDIT,)))
        return None
    return incomplete_audit(log, "the audit did not finish while the collection waited for it")


# ── Alias tables ─────────────────────────────────────────────────────────────


def _name_privilege(errors: list[dict[str, Any]], scope: str, privilege: str) -> None:
    """Name the privilege a refused (403) call of ``scope`` needs in its warning."""
    for warning in errors:
        if (
            warning.get("scope") == scope
            and warning.get("status") == 403
            and "privilege needed" not in warning["message"]
        ):
            warning["message"] += f"; privilege needed: {privilege}"


def tables_wanted(config_xml: str) -> list[str]:
    """The aliases of ``config_xml`` whose pf table the path trace needs:
    those the configuration cannot resolve, as the path trace reader finds
    them (``OpnsenseConfig.table_aliases``)."""
    config = parse_document(config_xml)
    return list(config.table_aliases) if config is not None else []


def plan_alias_tables(wanted: list[str], listed: Any) -> dict[str, list[str]]:
    """Which wanted tables to read (``read``, in order, at most
    ``ALIAS_TABLES_MAX_READS``), which are built-in giants never read
    (``skipped``), which pf has not loaded (``missing``: the ``aliases``
    answer lacks them) and which the read bound leaves out (``not_read``).
    Names match the loaded tables case-insensitively, spelled as pf has them."""
    loaded = {str(n).lower(): str(n) for n in (listed if isinstance(listed, list) else []) if str(n or "").strip()}
    plan: dict[str, list[str]] = {"read": [], "skipped": [], "missing": [], "not_read": []}
    for name in dict.fromkeys(wanted):
        if name.lower() in ALIAS_TABLES_SKIPPED:
            plan["skipped"].append(name)
        elif name.lower() not in loaded:
            plan["missing"].append(name)
        elif len(plan["read"]) < ALIAS_TABLES_MAX_READS:
            plan["read"].append(loaded[name.lower()])
        else:
            plan["not_read"].append(name)
    return plan


def table_entries(body: Any) -> tuple[list[str], int]:
    """The entries of a ``list/{alias}`` answer and how many the table holds:
    a search answer (``{"total", "rows": [{"ip": ...}]}``) or the plain
    ``{"items": [...]}`` of older releases (rows or strings)."""
    if isinstance(body, dict):
        rows = body.get("rows") if isinstance(body.get("rows"), list) else body.get("items")
    else:
        rows = body
    entries = [
        str((row.get("ip") if isinstance(row, dict) else row) or "").strip() for row in rows or [] if row is not None
    ]
    entries = [e for e in entries if e]
    total = body.get("total") if isinstance(body, dict) else None
    count = int(total) if isinstance(total, int | str) and str(total).isdigit() else len(entries)
    return entries, max(count, len(entries))


async def _collect_alias_tables(
    plan: dict[str, list[str]], best_effort: Callable[..., Awaitable[Any]], errors: list[dict[str, Any]]
) -> dict[str, Any]:
    """Read the planned tables within the bounds: at most
    ``ALIAS_TABLE_MAX_ENTRIES`` entries kept per table and
    ``ALIAS_TABLES_MAX_ENTRIES`` over all of them; a table cut short is
    ``truncated``. A refused or failed read is a warning (one only: the
    next tables are not tried after a 403) and the table is left out, so
    the trace leaves its alias unresolved. What was skipped is an ``info``
    warning."""
    tables: list[dict[str, Any]] = []
    budget = ALIAS_TABLES_MAX_ENTRIES
    not_read = list(plan["not_read"])
    for position, name in enumerate(plan["read"]):
        if budget <= 0:
            not_read.extend(plan["read"][position:])
            break
        before = len(errors)
        found = await best_effort("alias tables", (PATH_ALIAS_TABLE + quote(name, safe=""),))
        if found is None:
            _name_privilege(errors, "alias tables", ALIAS_TABLE_PRIVILEGE)
            if any(e.get("status") == 403 for e in errors[before:]):
                not_read.extend(plan["read"][position + 1 :])
                break
            continue
        entries, total = table_entries(found)
        kept = entries[: min(ALIAS_TABLE_MAX_ENTRIES, budget)]
        budget -= len(kept)
        tables.append({"name": name, "entries": kept, "total": total, "truncated": total > len(kept)})
    cut = [t["name"] for t in tables if t["truncated"]]
    notes = []
    if cut:
        notes.append(f"cut at the entry limit: {', '.join(cut)}")
    if not_read:
        notes.append(f"not read (over the limit of {ALIAS_TABLES_MAX_READS} tables or entries): {', '.join(not_read)}")
    if plan["skipped"]:
        notes.append(f"never read (built-in tables too large): {', '.join(plan['skipped'])}")
    if plan["missing"]:
        notes.append(f"not loaded in pf: {', '.join(plan['missing'])}")
    if notes:
        errors.append(
            info_warning(
                "alias tables",
                "/" + PATH_ALIAS_TABLES[0],
                f"Alias tables {'; '.join(notes)}. The path trace leaves what they do not hold unresolved",
            )
        )
    return {
        "read_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tables": tables,
        "skipped": list(plan["skipped"]),
        "missing": list(plan["missing"]),
        "not_read": not_read,
    }
