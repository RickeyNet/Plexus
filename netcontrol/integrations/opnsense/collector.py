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
  - ``wireguard/service/show``                   WireGuard interfaces and peers
                                                 with their latest handshake
  - ``openvpn/service/search_sessions``          OpenVPN instances and the
                                                 clients connected to servers
  - ``core/firmware/running``, ``core/firmware/audit`` (POST),
    ``core/firmware/upgradestatus``              the security audit
                                                 (``pkg audit -F``), run in the
                                                 background and polled
  - ``core/backup/download/this``                ``config.xml`` (the newest
                                                 entry of the configuration
                                                 history, written on every save)

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
snapshot.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from netcontrol.integrations.meraki.collector import scrub_secrets
from netcontrol.integrations.opnsense.client import OpnsenseApiError, OpnsenseClient
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.opnsense")

DEFAULT_OPTIONS: dict[str, Any] = {
    # Verify the firewall's TLS certificate.
    "verify_tls": True,
    # Gateway status (dpinger): status, loss, delay, stddev.
    "include_gateways": True,
    # IPsec, WireGuard and OpenVPN tunnel state.
    "include_vpn": True,
    # The routing table.
    "include_routes": True,
    # The security audit of the installed packages (pkg audit).
    "include_firmware_audit": True,
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
PHASE_FIRMWARE = "opnsense firmware"
PHASE_CONFIG = "opnsense config"

# API paths, newer form first.
PATH_SYSTEM = ("diagnostics/system/system_information", "diagnostics/system/systemInformation")
PATH_FIRMWARE_STATUS = ("core/firmware/status",)
PATH_INTERFACES = ("interfaces/overview/interfaces_info", "interfaces/overview/interfacesInfo")
PATH_GATEWAYS = ("routes/gateway/status",)
PATH_ROUTES = ("diagnostics/interface/get_routes", "diagnostics/interface/getRoutes")
PATH_IPSEC = ("ipsec/sessions/search_phase1", "ipsec/sessions/searchPhase1")
PATH_WIREGUARD = ("wireguard/service/show",)
PATH_OPENVPN = ("openvpn/service/search_sessions", "openvpn/service/searchSessions")
PATH_FIRMWARE_RUNNING = "core/firmware/running"
PATH_AUDIT = "core/firmware/audit"
PATH_AUDIT_STATUS = "core/firmware/upgradestatus"
PATH_CONFIG = "core/backup/download/this"

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


def parse_audit_log(text: str) -> dict[str, Any]:
    """The findings of a ``pkg audit`` run from its log, as the firmware
    progress log carries it: per vulnerable package its name and version,
    and per issue its description, CVE ids and VuXML link.

    ``pkg audit`` prints (freebsd/pkg ``src/audit.c``)::

        openssl-3.0.14 is vulnerable:
          OpenSSL -- multiple vulnerabilities
          CVE: CVE-2024-0001
          WWW: https://vuxml.FreeBSD.org/freebsd/<id>.html

        1 problem(s) in 1 package(s) found.
    """
    findings: list[dict[str, Any]] = []
    package: dict[str, str] | None = None
    issue: dict[str, Any] | None = None
    problems: int | None = None
    for line in (text or "").splitlines():
        stripped = line.strip()
        counted = _PROBLEMS.search(stripped)
        if counted:
            problems = int(counted.group(1))
            package = issue = None
            continue
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
    return {"findings": findings, "problems": problems if problems is not None else len(findings)}


async def collect_opnsense(
    client: OpnsenseClient,
    options: dict[str, Any] | None = None,
    progress: ProgressCallback | None = None,
    *,
    want_config: bool | None = None,
) -> dict[str, Any]:
    """Collect one firewall. Raises ``OpnsenseApiError`` only when the key
    is rejected, the firewall cannot be reached, or no call answered.
    ``want_config`` (default: the ``config_backup`` option) reads config.xml."""
    opts = sanitize_options(options)
    if want_config is None:
        want_config = bool(opts["config_backup"])
    errors: list[dict[str, Any]] = []
    total = 3 + int(opts["include_gateways"]) + 3 * int(opts["include_vpn"]) + int(opts["include_routes"])
    total += 3 * int(opts["include_firmware_audit"]) + int(want_config)
    done = 0
    answered = 0
    first_error: OpnsenseApiError | None = None

    def report(phase: str, **fields: Any) -> None:
        if progress is not None:
            progress({"phase": phase, "calls_done": done, "calls_total": total, **fields})

    async def best_effort(scope: str, paths: tuple[str, ...]) -> Any:
        nonlocal done, answered, first_error
        try:
            _path, body = await client.get_first(paths)
            answered += 1
            return body
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

    ipsec = wireguard = openvpn = None
    if opts["include_vpn"]:
        report(PHASE_VPN)
        found = await best_effort("vpn", PATH_IPSEC)
        ipsec = scrub_secrets(_rows(found)) if found is not None else None
        found = await best_effort("vpn", PATH_WIREGUARD)
        wireguard = scrub_secrets(_rows(found)) if found is not None else None
        found = await best_effort("vpn", PATH_OPENVPN)
        openvpn = scrub_secrets(_rows(found)) if found is not None else None
        report(PHASE_VPN, tunnels=len(ipsec or []) + len(wireguard or []) + len(openvpn or []))

    routes: list[dict] | None = None
    if opts["include_routes"]:
        report(PHASE_ROUTES)
        found = await best_effort("routes", PATH_ROUTES)
        routes = scrub_secrets(_rows(found)) if found is not None else None

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
            text = await client.get_text(PATH_CONFIG)
            answered += 1
            if "<opnsense" in text[:4096]:
                config_xml = text
            else:
                errors.append(
                    {
                        "scope": "config",
                        "path": "/" + PATH_CONFIG,
                        "status": None,
                        "message": "The configuration download did not answer with an OPNsense config.xml",
                    }
                )
        except OpnsenseApiError as exc:
            if exc.transport or exc.status_code == 401:
                raise
            first_error = first_error or exc
            errors.append(_error("config", exc, paths=(PATH_CONFIG,)))
        done += 1

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
        "ipsec": ipsec,
        "wireguard": wireguard,
        "openvpn": openvpn,
        "audit": audit,
        # Never part of the snapshot: the caller stores it as a config backup.
        "config_xml": config_xml,
        "errors": errors,
        "stats": dict(client.stats),
        "options": opts,
    }


async def _run_audit(client: OpnsenseClient, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Start the security audit and wait for its result. ``None`` (with a
    warning) when it could not run or did not finish in time."""
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
                break
    except OpnsenseApiError as exc:
        if exc.transport or exc.status_code == 401:
            raise
        errors.append(_error("firmware", exc, paths=(PATH_AUDIT,)))
        return None
    errors.append(
        {
            "scope": "firmware",
            "path": "/" + PATH_AUDIT_STATUS,
            "status": None,
            "message": "The security audit did not finish while the collection waited for it",
        }
    )
    return None
