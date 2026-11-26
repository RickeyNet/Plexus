"""
inventory.py -- Inventory group/host CRUD, discovery, and SNMP profile routes.
"""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import re
import socket
import uuid

import routes.database as db
import yaml
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from routes.db.inventory import _tree_ordered

import netcontrol.routes.state as state
from netcontrol.account_rules import API_TOKEN_USER
from netcontrol.bulk_import import host_csv_header, host_csv_row, host_export_records
from netcontrol.data_validation import enforce as enforce_validation_rules, pick as rule_values
from netcontrol.device_categories import DEVICE_CATEGORIES
from netcontrol.drivers import DriverCapabilityError, GenericDriver, get_driver, supports_cli
from netcontrol.drivers.show_version import ShowVersionFacts, parse_show_version
from netcontrol.hardware_components import collect_over_ssh
from netcontrol.integrations.apc import nmc_cli
from netcontrol.integrations.apc.firmware import DEVICE_TYPE as APC_UPS_DEVICE_TYPE
from netcontrol.integrations.meraki.enrich import load_inventory_index
from netcontrol.integrations.software.versions import classify_host
from netcontrol.managed_targets import (
    ADDRESS_AWAITING_CONFIRMATION,
    address_confirmed as host_address_confirmed,
    address_writer_id,
    caller_confirms_addresses,
    same_address,
    unmanaged_addresses,
)
from netcontrol.object_scope import (
    READ_ONLY_DETAIL,
    ObjectScope,
    readable_host_ids,
    request_scope,
    require_group,
    require_host,
    require_hosts,
    scope_exempt,
    scoped,
)
from netcontrol.routes import background_jobs
from netcontrol.routes.custom_fields import attach_custom_data, matching_keys
from netcontrol.routes.dcim import (
    HostPlacementValues,
    apply_host_placement,
    check_host_placement,
    sent_placement_values,
)
from netcontrol.routes.device_model import (
    HostDeviceValues,
    attach_device_data,
    audit_device_write,
    check_device_values,
    describe_values,
    matching_host_ids,
    sent_device_values,
)
from netcontrol.routes.host_identity import host_ip_problem, is_placeholder_hostname, placeholder_hostname
from netcontrol.routes.icmp import _probe_discovery_target_icmp
from netcontrol.routes.ipam_push import push_inventory_host_allocation
from netcontrol.routes.shared import (
    DISCOVERY_RUNS,
    _audit,
    _corr_id,
    _get_session,
    _run_show_command,
    _run_show_commands,
    _session_user_id,
    caller_is_admin,
    fan_out,
    require_credential_access,
    service_credential,
    supervise_task,
)
from netcontrol.routes.snmp import (
    PYSMNP_AVAILABLE,  # noqa: F401
    _collect_interface_ips,
    _discover_neighbors,  # noqa: F401
    _infer_device_category,
    _probe_discovery_target_snmp,
    _snmp_get,
    _snmp_walk,  # noqa: F401
)
from netcontrol.secret_fields import SNMP_SECRET_FIELDS, mask_secret_fields, merge_secret_fields
from netcontrol.telemetry import configure_logging, increment_metric, redact_value

LOGGER = configure_logging("plexus.inventory")

# Two routers: one for inventory-feature routes, one for admin routes
router = APIRouter()
admin_router = APIRouter()


async def _notify_flow_collector_host_changed(
    old_ip: str | None = None,
    new_ip: str | None = None,
    host_id: int | None = None,
) -> None:
    """Refresh the flow collector's in-memory exporter->host cache.

    Imported lazily to avoid a circular dependency at module load time and
    wrapped in a broad except so any inventory write that touches a host
    is never blocked by a flow-collector error.
    """
    try:
        from netcontrol.routes.flow_collector import on_host_changed

        await on_host_changed(old_ip=old_ip, new_ip=new_ip, host_id=host_id)
    except Exception as exc:
        LOGGER.debug("flow_collector cache refresh skipped: %s", type(exc).__name__)


def _validate_host_ip(ip_str: str) -> str:
    """Validate that a host IP is a valid unicast address not in reserved ranges."""
    problem = host_ip_problem(ip_str)
    if problem == "invalid":
        raise HTTPException(400, f"Invalid IP address: {ip_str}")
    if problem:
        raise HTTPException(400, f"IP address {ip_str} is in a reserved range and cannot be added to inventory")
    return ip_str


# An EC2 instance ID: ``i-`` and hex (8 or 17 digits on AWS; the demo
# account's are shorter).
_AWS_INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{1,17}$", re.IGNORECASE)


def _validate_aws_instance_id(value: str | None) -> str | None:
    """Trim an AWS instance ID; ``''`` clears it, ``None`` leaves it as is."""
    if value is None:
        return None
    value = value.strip()
    if value and not _AWS_INSTANCE_ID_RE.match(value):
        raise HTTPException(422, f"Invalid AWS instance ID {value!r}: expected an EC2 instance ID such as i-0abc1234")
    return value


def _check_snmp_profile_id(value: str | None) -> str | None:
    """Trim an SNMP profile id; ``''`` clears an assignment, ``None`` leaves
    it as is, and an id that names no profile is a 400."""
    if value is None:
        return None
    value = str(value).strip()
    if value and value not in state.SNMP_PROFILES:
        raise HTTPException(400, "SNMP profile not found")
    return value


def _invalidate_topology_cache() -> None:
    """Drop the assembled /api/topology cache after a host changes, so a host
    that is an AWS instance (by address or ID) is on the map at once."""
    from netcontrol.routes.topology import invalidate_topology_cache

    invalidate_topology_cache()


# ── Pydantic Models ──────────────────────────────────────────────────────────


class GroupCreate(BaseModel):
    name: str
    description: str = ""
    # The parent group; None (or omitted) for a top-level group.
    parent_id: int | None = None


class GroupUpdate(BaseModel):
    name: str
    description: str = ""
    # Omitted leaves the parent as it is; null moves the group to the top level.
    parent_id: int | None = None


class HostCreate(HostDeviceValues):
    """A new host. The device values (``device_type_id``, ``role_id``,
    ``lifecycle_status_id``, ``site_id``, ``location_detail``) are optional;
    a host created without ``lifecycle_status_id`` gets the default status."""

    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"
    vrf_name: str = ""
    vlan_id: str = ""
    # The EC2 instance this host is, matched before its addresses on the AWS map.
    aws_instance_id: str = ""
    # The host's own SNMP profile, used instead of its group's; "" inherits.
    snmp_profile_id: str = ""


# The most hosts one bulk add request takes. The Topology page's "Add to
# inventory" sends a larger selection as several requests of this size.
BULK_ADD_MAX_HOSTS = 500

# Why a bulk add entry is skipped, by what matched it to an inventory host
# (``InventoryIndex.match_key``).
_BULK_SKIP_REASONS = {
    "instance": "AWS instance is already in inventory",
    "serial": "Serial number is already in inventory",
    "ip": "IP address is already in inventory",
    "name": "A host with this name is already in inventory",
}


class HostBulkCreate(BaseModel):
    hosts: list[HostCreate] = Field(default_factory=list)


class HostBulkEntry(HostCreate):
    """One host of a grouped bulk add: the group by id, by the names of its
    path from the top (``["Meraki", "HQ"]``; each missing level is created),
    or by the name of a top-level group (created when missing). At most one
    of the three; none uses the body's default ``group_id``."""

    group_id: int | None = None
    group_name: str | None = None
    group_path: list[str] | None = None
    # The device's serial, from the map: matched against inventory before
    # adding and stored on the new host, so later collections link to it.
    serial_number: str = Field(default="", max_length=128)


class HostBulkCreateGrouped(BaseModel):
    hosts: list[HostBulkEntry] = Field(default_factory=list)
    # The group of entries that name no group_id, group_name or group_path.
    group_id: int | None = None


# Description of the groups a grouped bulk add creates.
BULK_ADD_GROUP_DESCRIPTION = "Added from the Topology map"


class HostUpdate(HostDeviceValues, HostPlacementValues):
    """A host edit. A device value that is left out keeps its stored value;
    so does a rack placement value (``rack_id``, ``rack_position``,
    ``rack_face``, checked like ``PUT /api/dcim/hosts/{id}/placement``)."""

    hostname: str
    ip_address: str
    device_type: str = "cisco_ios"
    vrf_name: str | None = None
    vlan_id: str | None = None
    # None leaves it unchanged; "" clears it.
    aws_instance_id: str | None = None
    # None leaves it unchanged; "" returns the host to its group's SNMP config.
    snmp_profile_id: str | None = None
    # Optional - when present, the host is moved to the new group as part
    # of the update so renaming and re-grouping happen in one round-trip.
    group_id: int | None = None


class FetchSerialRequest(BaseModel):
    credential_id: int


class HostSnmpProfileAssign(BaseModel):
    host_ids: list[int] = Field(default_factory=list)
    # "" returns the hosts to their group's SNMP config.
    snmp_profile_id: str = ""


# Most CIDR entries one discovery request may name: max_hosts is at most
# 4096, so more entries than that can only repeat or overlap each other.
DISCOVERY_MAX_CIDRS = 4096
# Most addresses _expand_scan_targets walks for one request, repeats and
# overlaps included (the largest single CIDR it accepts).
DISCOVERY_MAX_EXPANDED_ADDRESSES = 65536


class DiscoveryScanRequest(BaseModel):
    cidrs: list[str] = Field(default_factory=list, max_length=DISCOVERY_MAX_CIDRS)
    timeout_seconds: float = Field(default=state.DISCOVERY_DEFAULT_TIMEOUT_SECONDS, ge=0.05, le=5.0)
    max_hosts: int = Field(default=state.DISCOVERY_DEFAULT_MAX_HOSTS, ge=1, le=4096)
    device_type: str = "unknown"
    hostname_prefix: str = "discovered"
    use_snmp: bool = True
    use_icmp: bool = True
    # Read model, serial, software version, hostname and the OS (device
    # type) over SSH ``show version`` from every host that answers.
    use_ssh: bool = True
    # A stored credential the caller may use (remembered for the group);
    # none: the credential the group remembers, else the Plexus service
    # credential (see _resolve_discovery_ssh).
    credential_id: int | None = None
    # Without credential_id: sign in with the Plexus service credential even
    # when the group remembers another, and make the group forget it.
    use_service_credential: bool = False

    model_config = ConfigDict(extra="forbid")


class DiscoverySyncRequest(DiscoveryScanRequest):
    remove_absent: bool = False


class DiscoveryOnboardRequest(BaseModel):
    discovered_hosts: list[dict] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


# ── Discovery helpers ────────────────────────────────────────────────────────


def _expand_scan_targets(cidrs: list[str], max_hosts: int) -> list[str]:
    """The host addresses of ``cidrs`` in order, each once, at most
    ``max_hosts``. Runs on the event loop before a scan starts, so its work
    is bounded whatever the input: a CIDR named twice is expanded once, and
    at most ``max(max_hosts * 10, DISCOVERY_MAX_EXPANDED_ADDRESSES)``
    addresses are walked in all (ValueError past that, as for one CIDR
    that large)."""
    budget = max(max_hosts * 10, DISCOVERY_MAX_EXPANDED_ADDRESSES)
    networks: dict[ipaddress.IPv4Network | ipaddress.IPv6Network, str] = {}
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        # Reject absurdly large subnets early to avoid CPU spin
        if network.num_addresses > budget:
            raise ValueError(
                f"CIDR {cidr} contains {network.num_addresses:,} addresses - maximum allowed is {budget:,}"
            )
        networks.setdefault(network, cidr)

    targets: list[str] = []
    seen: set[str] = set()
    walked = 0
    for network in networks:
        for host in network.hosts():
            walked += 1
            if walked > budget:
                raise ValueError(
                    f"The CIDR list repeats or overlaps itself too much: more than {budget:,} addresses "
                    "to walk. Remove the overlapping entries."
                )
            ip_str = str(host)
            if ip_str in seen:
                continue
            seen.add(ip_str)
            targets.append(ip_str)
            if len(targets) >= max_hosts:
                return targets
    return targets


async def _probe_discovery_target(
    ip_address: str,
    timeout_seconds: float,
    device_type: str,
    hostname_prefix: str,
    use_snmp: bool,
    snmp_config: dict,
    use_icmp: bool = True,
) -> dict | None:
    if use_snmp:
        snmp_hit = await _probe_discovery_target_snmp(ip_address, timeout_seconds, snmp_config)
        if snmp_hit is not None:
            return snmp_hit

    detected_port = 0
    detected_protocol = ""
    banner_sample = ""
    for port in state.DISCOVERY_PROBE_PORTS:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_address, port), timeout=timeout_seconds)
            if port == 22:
                try:
                    banner = await asyncio.wait_for(reader.read(256), timeout=timeout_seconds)
                    banner_sample = banner.decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner_sample = ""
            detected_port = port
            detected_protocol = "ssh" if port == 22 else "https"
            break
        except Exception:
            continue
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as exc:
                    LOGGER.debug("discovery: error closing probe connection to %s:%s: %s", ip_address, port, exc)
    if not detected_port:
        # Last-resort ICMP probe so hosts that block SNMP/22/443 but still
        # answer ping (firewalls with locked-down mgmt planes, appliances
        # without an SSH surface) surface in the discovery sweep.  The
        # caller can disable this for pure-SNMP networks.
        if use_icmp:
            icmp_hit = await _probe_discovery_target_icmp(
                ip_address,
                timeout_seconds,
                hostname_prefix,
            )
            if icmp_hit is not None:
                return icmp_hit
        return None

    try:
        # Reverse DNS blocks for the resolver timeout; run it off the event
        # loop so a large discovery sweep can't freeze every other request.
        hostname = (await asyncio.to_thread(socket.gethostbyaddr, ip_address))[0]
    except Exception:
        hostname = placeholder_hostname(hostname_prefix, ip_address)

    inferred_device_type = device_type
    inferred_os = "unknown"
    inferred_vendor = "unknown"
    if banner_sample:
        lower_banner = banner_sample.lower()
        if "cisco" in lower_banner:
            inferred_vendor = "cisco"
            # Distinguish IOS-XE from classic IOS - Catalyst 9xxx, 3850,
            # 3650, ISR 1000/4000, ASR 1000, etc. all run IOS-XE.
            # SSH banners rarely include OS detail, so also match on
            # sysDescr variants: "IOS XE", "IOS-XE", "(CAT9K_IOSXE)".
            if "ios-xe" in lower_banner or "iosxe" in lower_banner or "ios xe" in lower_banner:
                inferred_device_type = "cisco_xe"
            elif "nx-os" in lower_banner or "nxos" in lower_banner:
                inferred_device_type = "cisco_nxos"
            elif "ios-xr" in lower_banner or "iosxr" in lower_banner or "ios xr" in lower_banner:
                inferred_device_type = "cisco_xr"
            elif "firepower" in lower_banner or "ftd" in lower_banner:
                inferred_device_type = "cisco_ftd"
            elif "adaptive security" in lower_banner or "asa" in lower_banner:
                inferred_device_type = "cisco_asa"
            else:
                inferred_device_type = "cisco_ios"
        elif "juniper" in lower_banner or "junos" in lower_banner:
            inferred_vendor = "juniper"
            inferred_device_type = "juniper_junos"
        elif "arista" in lower_banner:
            inferred_vendor = "arista"
            inferred_device_type = "arista_eos"
        elif "forti" in lower_banner:
            inferred_vendor = "fortinet"
            inferred_device_type = "fortinet"

        if "ios-xe" in lower_banner or "iosxe" in lower_banner or "ios xe" in lower_banner:
            inferred_os = "ios-xe"
        elif "ios-xr" in lower_banner or "iosxr" in lower_banner or "ios xr" in lower_banner:
            inferred_os = "ios-xr"
        elif "ios" in lower_banner:
            inferred_os = "ios"
        elif "nx-os" in lower_banner or "nxos" in lower_banner:
            inferred_os = "nx-os"
        elif "junos" in lower_banner:
            inferred_os = "junos"
        elif "eos" in lower_banner:
            inferred_os = "eos"
        elif "fortios" in lower_banner:
            inferred_os = "fortios"

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "device_type": inferred_device_type,
        "status": "online",
        "discovery": {
            "protocol": detected_protocol,
            "port": detected_port,
            "banner": banner_sample,
            "vendor": inferred_vendor,
            "os": inferred_os,
        },
    }


# ── SSH show version enrichment ──────────────────────────────────────────────
#
# A reachable host is read over SSH (``show version``) so its model, serial,
# software version, hostname and OS come from the device, with no SNMP. The
# OS ``show version`` reports is the host's device_type: an SSH banner
# (``SSH-2.0-Cisco-1.25``) names the vendor, never IOS vs IOS XE.

# Cap on one host's whole login + ``show version``; a slow or silent host is
# recorded as an SSH failure on that host, never a failed scan.
DISCOVERY_SSH_TIMEOUT_SECONDS = 45.0
_DISCOVERY_SSH_CONNECT_OPTIONS = {"conn_timeout": 10, "auth_timeout": 15, "banner_timeout": 15}
# Per command on an APC card (``upsabout``, ``about``): Netmiko's default.
_APC_CARD_READ_TIMEOUT_SECONDS = 10

# Netmiko platforms discovery may open a session with; any other guess
# (``unknown``, a free-text type) opens the generic Cisco handler, whose
# ``show version`` reads IOS, IOS XE, NX-OS and IOS XR alike.
_SSH_SESSION_TYPES = frozenset(
    {
        "cisco_ios",
        "cisco_xe",
        "cisco_nxos",
        "cisco_xr",
        "cisco_asa",
        "cisco_ftd",
        "arista_eos",
        "juniper_junos",
        "paloalto_panos",
        "fortinet",
        "aruba_aoscx",
        "aruba_osswitch",
        "netgear_prosafe",
    }
)


async def _resolve_discovery_ssh(
    body: DiscoveryScanRequest,
    session: dict | None,
    *,
    group: dict | None = None,
    unattended: bool = False,
    correlation_id: str = "",
    request: Request | None = None,
    targets: list[str] | None = None,
) -> tuple[dict | None, dict]:
    """The credential discovery reads ``show version`` with, and the base of
    the ``ssh_enrichment`` summary reported with the result.

    The service credential (step 3) signs in to ``targets`` only when the
    caller of ``request`` is an admin or every target is an inventory host
    they may change; otherwise 403 (``_require_service_targets``).

    In order:

    1. An explicit ``credential_id``: it must pass the usual access check
       (403/404 on failure) and is remembered for ``group``.
    2. Unless ``use_service_credential`` (which makes ``group`` forget its
       credential), the credential ``group`` remembers, when the caller may
       use it. ``unattended`` (the scheduled sync, no user session) uses it
       only when it is a service credential. A remembered credential that
       cannot be used falls back to step 3 with a ``note``, never an error;
       one deleted since counts as none.
    3. The Plexus service credential; when none is set, SSH enrichment is
       skipped (and says why) but the scan runs.
    """
    if not body.use_ssh:
        return None, {
            "enabled": False,
            "credential": None,
            "credential_source": None,
            "skipped_reason": "Reading show version over SSH is turned off",
            "note": "",
        }
    note = ""
    credential: dict | None = None
    if body.credential_id is not None:
        credential = await require_credential_access(body.credential_id, session=session, allow_service=True)
        source = "explicit"
        if group is not None and not unattended:
            await _remember_group_credential(group, credential, session, correlation_id)
    else:
        if group is not None and body.use_service_credential:
            if not unattended:
                await _remember_group_credential(group, None, session, correlation_id)
        elif group is not None:
            credential, note = await _group_credential(group, session, unattended=unattended)
        source = "group"
        if credential is None:
            credential = await service_credential()
            source = "service"
            if credential is not None and not unattended:
                await _require_service_targets(request, targets or [])
        if credential is None:
            return None, {
                "enabled": True,
                "credential": None,
                "credential_source": None,
                "skipped_reason": (
                    "No Plexus service credential is set: pick a credential or set one in Settings "
                    "to read model, serial and version over SSH"
                ),
                "note": note,
            }
    name = str(credential.get("name") or "").strip() or f"credential {credential.get('id')}"
    return credential, {
        "enabled": True,
        "credential": name,
        "credential_source": source,
        "skipped_reason": "",
        "note": note,
    }


SERVICE_CREDENTIAL_TARGETS_DETAIL = (
    "Discovery signs in with the Plexus service credential only to inventory hosts you can change, "
    "and {count} address(es) to scan ({shown}) are not. Pick a credential of your own, turn off "
    "reading show version over SSH, or ask an admin to run this scan."
)


async def _require_service_targets(request: Request | None, targets: list[str]) -> None:
    """403 unless the caller may have the Plexus service credential sign in
    to every one of ``targets``: an admin (or the API token) to any
    address, anyone else only to inventory hosts they may change. Discovery
    addresses come from the request, so they may be a device the caller
    controls."""
    if await caller_is_admin(request):
        return
    outside = await unmanaged_addresses(targets, request)
    if outside:
        shown = ", ".join(outside[:3]) + (", ..." if len(outside) > 3 else "")
        raise HTTPException(403, SERVICE_CREDENTIAL_TARGETS_DETAIL.format(count=len(outside), shown=shown))


SNMP_WITHHELD_REASON = (
    "The group's SNMP settings are sent only to the addresses of confirmed inventory hosts you can change; "
    "the other addresses were probed without SNMP (TCP and ICMP). An admin can scan them with SNMP."
)


async def _snmp_withheld_targets(
    request: Request | None, body: DiscoveryScanRequest, targets: list[str]
) -> tuple[frozenset[str], dict]:
    """The ``targets`` probed without the group's SNMP config (communities
    and SNMPv3 keys are admin-only secrets) and the ``snmp_withheld``
    summary reported with the result. An admin (or the API token) sends it
    to every target; anyone else only to the address of a confirmed
    inventory host they may change (``managed_targets.unmanaged_addresses``).
    Worked out in the route handler, where the request is at hand."""
    withheld: frozenset[str] = frozenset()
    if body.use_snmp and targets and not await caller_is_admin(request):
        withheld = frozenset(await unmanaged_addresses(targets, request))
    return withheld, {"count": len(withheld), "reason": SNMP_WITHHELD_REASON if withheld else ""}


async def _group_credential(group: dict, session: dict | None, *, unattended: bool) -> tuple[dict | None, str]:
    """The credential ``group`` remembers for discovery, if the caller may use
    it, and a note when one is remembered but cannot be used."""
    remembered = group.get("discovery_credential_id")
    if remembered is None:
        return None, ""
    if unattended:
        # No user to check a personal credential against: service only.
        credential = await db.get_credential_raw(int(remembered))
        if credential is None:
            return None, ""
        if not credential.get("is_service"):
            return None, (
                "The group remembers a personal credential; the scheduled sync signs in only "
                "with service credentials, so the Plexus service credential is used"
            )
        return credential, ""
    try:
        return await require_credential_access(int(remembered), session=session, allow_service=True), ""
    except HTTPException as exc:
        if exc.status_code == 404:
            return None, ""  # deleted since: as if none were remembered
        return None, (
            f"The credential this group remembers cannot be used ({exc.detail}); "
            "the Plexus service credential is used instead"
        )


async def _remember_group_credential(
    group: dict, credential: dict | None, session: dict | None, correlation_id: str = ""
) -> None:
    """Remember ``credential`` as the one ``group``'s discovery signs in with.
    ``None`` or the Plexus service credential is the default: the group
    forgets its credential. Audited when it changes."""
    new_id: int | None = None
    if credential is not None:
        service = await service_credential()
        if service is None or int(service["id"]) != int(credential["id"]):
            new_id = int(credential["id"])
    old_id = group.get("discovery_credential_id")
    if old_id == new_id:
        return
    group_id = int(group["id"])
    await db.set_group_discovery_credential(group_id, new_id)
    group["discovery_credential_id"] = new_id
    await _audit(
        "inventory",
        "group.discovery_credential",
        user=session["user"] if session and session.get("user") else API_TOKEN_USER,
        detail=f"group_id={group_id} credential_id={new_id or 'service'} previous={old_id or 'service'}",
        correlation_id=correlation_id,
    )


def _ssh_enrichment_summary(base: dict, discovered: list[dict]) -> dict:
    """``base`` plus how many hosts were read over SSH, and each failure."""
    attempted = enriched = 0
    failures: list[dict] = []
    for host in discovered:
        ssh = (host.get("discovery") or {}).get("ssh")
        if not isinstance(ssh, dict):
            continue
        attempted += 1
        if ssh.get("ok"):
            enriched += 1
        else:
            failures.append({"ip_address": host.get("ip_address", ""), "error": str(ssh.get("error") or "")})
    return {**base, "attempted": attempted, "enriched": enriched, "failed": len(failures), "failures": failures}


def _ssh_session_type(device_type: str | None) -> str:
    dt = str(device_type or "").strip()
    return dt if dt in _SSH_SESSION_TYPES else "cisco_ios"


def _show_version_command(device_type: str) -> str:
    try:
        return get_driver(device_type).show_version_command()
    except DriverCapabilityError:
        return "show version"


def _apply_show_version_facts(host: dict, facts: ShowVersionFacts) -> None:
    """Overlay what ``show version`` reported on a probe result. A recognized
    OS is the device_type (``discovery.device_type_source = "ssh"`` tells the
    planner it is authoritative); a fact the output lacks keeps the probe's
    (SNMP) value."""
    discovery = host.setdefault("discovery", {})
    discovery["ssh"] = {"ok": True, "facts": facts.to_dict()}
    if facts.os_device_type:
        host["device_type"] = facts.os_device_type
        discovery["device_type_source"] = "ssh"
        discovery["vendor"] = facts.os_device_type.split("_", 1)[0]
        platform, _ = classify_host(facts.os_device_type, facts.model, facts.software_version)
        if platform:
            discovery["os"] = platform
    if facts.model:
        host["model"] = facts.model
    if facts.software_version:
        host["software_version"] = facts.software_version
    if facts.serial_number:
        host["serial_number"] = facts.serial_number
    if facts.hostname and not str(host.get("sys_name") or "").strip():
        # The configured hostname is a device identity like sysName.
        host["sys_name"] = facts.hostname
        host["hostname"] = facts.hostname
    if not host.get("device_category") and facts.model:
        category = _infer_device_category(facts.model, "", str(host.get("device_type") or ""))
        if category:
            host["device_category"] = category


async def _enrich_with_show_version(host: dict, credential: dict) -> None:
    """Read ``show version`` from a reachable probe result over SSH and apply
    it. Hosts with no SSH surface (HTTPS-only or ping-only) are left alone;
    a failure is recorded on the host as ``discovery.ssh.error``."""
    discovery = host.setdefault("discovery", {})
    protocol = str(discovery.get("protocol") or "")
    # TCP 22 answered, or SNMP answered (which does not probe port 22).
    if protocol != "ssh" and not protocol.startswith("snmp"):
        return
    # SNMP identified a platform with no command line Plexus can drive (an APC
    # UPS card, an Instant On switch): its facts came from SNMP, and a Cisco
    # session would only fail on it (``enable`` and ``show version``).
    if not supports_cli(host.get("device_type")):
        return
    session_type = _ssh_session_type(host.get("device_type"))
    target = {"ip_address": host["ip_address"], "device_type": session_type}
    try:
        async with state.device_op_semaphore():
            output = await asyncio.wait_for(
                _run_show_command(
                    target,
                    credential,
                    _show_version_command(session_type),
                    autodetect=False,
                    # The OS is not known yet: a device that has no Cisco-style
                    # enable mode still answers show version in user mode.
                    enable_optional=True,
                    **_DISCOVERY_SSH_CONNECT_OPTIONS,
                ),
                timeout=DISCOVERY_SSH_TIMEOUT_SECONDS,
            )
    except TimeoutError:
        discovery["ssh"] = {"ok": False, "error": f"SSH timed out after {DISCOVERY_SSH_TIMEOUT_SECONDS:g}s"}
        return
    except Exception as exc:
        detail = redact_value(str(exc)).strip().splitlines()
        discovery["ssh"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {detail[0][:200]}" if detail else type(exc).__name__,
        }
        return
    text = output if isinstance(output, str) else ""
    facts = parse_show_version(text)
    if facts.empty and nmc_cli.status_line(text) is not None:
        # An APC Network Management Card answers an unknown command with an
        # NMC status code ("E101: Command Not Found"): ask it what UPS it is.
        facts = await _read_apc_card_facts(target, credential)
    if facts.empty:
        discovery["ssh"] = {"ok": False, "error": "show version output named no model, version or OS"}
        return
    _apply_show_version_facts(host, facts)


async def _read_apc_card_facts(target: dict, credential: dict) -> ShowVersionFacts:
    """``upsabout`` and ``about`` from an APC Network Management Card, read
    in one session, as the facts a ``show version`` would give: a card with
    a UPS behind it (a UPS ID or model) is an ``apc_ups``; anything else (a
    PDU or transfer switch card, a failed read) gives no facts. The host's
    software version for this type is the card's firmware (``about``), the
    one SNMP discovery takes from the sysDescr; when ``about`` is not
    answered the UPS is still identified, without a version."""
    try:
        async with state.device_op_semaphore():
            outputs = await asyncio.wait_for(
                asyncio.to_thread(
                    _run_show_commands,
                    target,
                    credential,
                    (nmc_cli.UPSABOUT, nmc_cli.ABOUT),
                    read_timeout=_APC_CARD_READ_TIMEOUT_SECONDS,
                    autodetect=False,
                    enable_optional=True,
                    **_DISCOVERY_SSH_CONNECT_OPTIONS,
                ),
                timeout=DISCOVERY_SSH_TIMEOUT_SECONDS,
            )
    except Exception as exc:
        LOGGER.debug("discovery: upsabout failed on %s: %s", target.get("ip_address"), type(exc).__name__)
        return ShowVersionFacts()
    ups_output = outputs.get(nmc_cli.UPSABOUT, "")
    about = nmc_cli.parse_upsabout(ups_output)
    if nmc_cli.command_error(ups_output) or not (about.ups_id or about.model):
        return ShowVersionFacts()
    card_output = outputs.get(nmc_cli.ABOUT, "")
    card_firmware = "" if nmc_cli.command_error(card_output) else nmc_cli.parse_about(card_output).firmware
    return ShowVersionFacts(
        os_device_type=APC_UPS_DEVICE_TYPE,
        model=about.model or None,
        software_version=card_firmware or None,
        serial_number=about.serial or None,
    )


async def _scan_target(
    ip_address: str,
    body: DiscoveryScanRequest,
    snmp_config: dict,
    probe_slots: asyncio.Semaphore,
    credential: dict | None,
    *,
    snmp_withheld: frozenset[str] = frozenset(),
) -> dict | None:
    """Probe one target (SNMP, TCP 22/443, ICMP) inside the probe fan-out
    cap, then, outside it, read ``show version`` over SSH when a credential
    was resolved. Every discovery entry point scans through this. A target
    in ``snmp_withheld`` (``_snmp_withheld_targets``) is probed without
    SNMP."""
    async with probe_slots:
        host = await _probe_discovery_target(
            ip_address=ip_address,
            timeout_seconds=body.timeout_seconds,
            device_type=body.device_type,
            hostname_prefix=body.hostname_prefix,
            use_snmp=body.use_snmp and ip_address not in snmp_withheld,
            snmp_config=snmp_config,
            use_icmp=body.use_icmp,
        )
    if host is not None and credential is not None:
        await _enrich_with_show_version(host, credential)
    return host


async def _discover_hosts(
    request: DiscoveryScanRequest,
    group_id: int | None = None,
    *,
    credential: dict | None = None,
    snmp_withheld: frozenset[str] = frozenset(),
) -> tuple[int, list[dict]]:
    targets = _expand_scan_targets(request.cidrs, request.max_hosts)
    semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)

    discovered_raw = await asyncio.gather(
        *[_scan_target(ip, request, snmp_cfg, semaphore, credential, snmp_withheld=snmp_withheld) for ip in targets]
    )
    discovered = [item for item in discovered_raw if item is not None]
    discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
    return len(targets), discovered


def _is_fallback_hostname(name: str) -> bool:
    """True for discovery's synthetic names (no real sysName was learned)."""
    n = (name or "").strip()
    return n.startswith("snmp-") or n.startswith("host-")


def _norm_name(name: str) -> str:
    """Normalize a hostname for identity comparison (case + domain insensitive)."""
    return (name or "").strip().lower().split(".")[0]


def _normalize_discovered_entry(host: dict) -> dict | None:
    """Flatten a raw probe result into the fields the dedup planner needs."""
    ip = str(host.get("ip_address", "")).strip()
    if not ip:
        return None
    hostname = str(host.get("hostname") or "").strip() or placeholder_hostname("host", ip)
    # A "real" sysName is a stable per-device identity; the snmp-/host- fallback
    # and "<prefix>-<ip>" placeholder names are per-IP and must NOT be used to
    # group devices or to rename the host they match.
    explicit_sys = str(host.get("sys_name") or "").strip()
    if explicit_sys:
        sys_name = explicit_sys
    elif not _is_fallback_hostname(hostname) and not is_placeholder_hostname(hostname, ip):
        sys_name = hostname
    else:
        sys_name = ""
    discovery = host.get("discovery") or {}
    probe_protocol = str(discovery.get("protocol", "")).strip()
    return {
        "ip": ip,
        "hostname": hostname,
        "sys_name_norm": _norm_name(sys_name) if sys_name else "",
        "serial": str(host.get("serial_number") or "").strip(),
        "device_type": str(host.get("device_type") or "unknown").strip() or "unknown",
        "status": str(host.get("status") or "online").strip() or "online",
        "model": str(host.get("model") or "").strip(),
        "software_version": str(host.get("software_version") or "").strip(),
        "device_category": str(host.get("device_category") or "").strip(),
        "probe_protocol": probe_protocol,
        "snmp_reachable": probe_protocol.startswith("snmp"),
        # The device_type is the OS the device's own show version reported.
        "ssh_typed": discovery.get("device_type_source") == "ssh",
    }


def _build_discovery_plan(
    discovered: list[dict],
    existing_hosts: list[dict],
    existing_ip_index: dict[str, int],
    interface_ip_map: dict[str, list[str]],
) -> dict:
    """Decide adds / updates / IP-alias sets / duplicate suppressions.

    A physical device owns many interface IPs. Discovered IPs are grouped into
    one device when they share a serial number, a real sysName, or membership
    in another IP's SNMP ipAddrTable (interface_ip_map). Each device maps to at
    most one inventory host; its other IPs become aliases. Pre-existing
    duplicate host rows are suppressed (deleted) only on STRONG evidence — the
    duplicate's IP appears in the device's own ipAddrTable, or it shares the
    serial — never on a sysName match alone.

    Pure function (no I/O) so the dedup logic is unit-testable.
    """
    entries_by_ip = {e["ip"]: e for e in discovered}

    # ── Union-find over discovered IPs ────────────────────────────────────
    parent = {ip: ip for ip in entries_by_ip}

    def _find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a: str, b: str) -> None:
        if a in parent and b in parent:
            ra, rb = _find(a), _find(b)
            if ra != rb:
                parent[rb] = ra

    by_serial: dict[str, str] = {}
    for e in discovered:
        if e["serial"]:
            by_serial.setdefault(e["serial"], e["ip"])
            _union(by_serial[e["serial"]], e["ip"])
    by_name: dict[str, str] = {}
    for e in discovered:
        if e["sys_name_norm"]:
            by_name.setdefault(e["sys_name_norm"], e["ip"])
            _union(by_name[e["sys_name_norm"]], e["ip"])
    for ip, iface in interface_ip_map.items():
        if ip not in parent:
            continue
        for other in iface:
            if other in parent:
                _union(ip, other)

    groups: dict[str, list[str]] = {}
    for ip in entries_by_ip:
        groups.setdefault(_find(ip), []).append(ip)

    # ── Existing-host lookups ─────────────────────────────────────────────
    existing_by_id = {h["id"]: h for h in existing_hosts}
    existing_by_serial: dict[str, dict] = {}
    existing_by_name: dict[str, dict] = {}
    for h in existing_hosts:
        s = (h.get("serial_number") or "").strip()
        if s:
            existing_by_serial.setdefault(s, h)
        hn = (h.get("hostname") or "").strip()
        if hn and not _is_fallback_hostname(hn) and not is_placeholder_hostname(hn, h.get("ip_address") or ""):
            existing_by_name.setdefault(_norm_name(hn), h)

    plan: dict = {"add": [], "update": [], "delete": [], "matched": 0, "covered_ips": set()}

    for ips in groups.values():
        entries = [entries_by_ip[ip] for ip in ips]
        group_ips = set(ips)
        iface_ips: set[str] = set()
        for ip in ips:
            iface_ips.update(interface_ip_map.get(ip, []))
        full_ips = group_ips | iface_ips
        plan["covered_ips"] |= full_ips

        snmp_entries = [e for e in entries if e["snmp_reachable"]]
        any_snmp = bool(snmp_entries)
        serial = next((e["serial"] for e in entries if e["serial"]), "")
        sys_norm = next((e["sys_name_norm"] for e in entries if e["sys_name_norm"]), "")
        real_hostname = next(
            (e["hostname"] for e in entries if e["sys_name_norm"]),
            (snmp_entries or entries)[0]["hostname"],
        )
        # Device type precedence: the OS show version reported over SSH, then
        # SNMP sysDescr, then any probe's guess (SSH banner, caller default).
        ssh_typed = [e for e in entries if e.get("ssh_typed") and e["device_type"] != "unknown"]
        device_type = (
            next((e["device_type"] for e in ssh_typed), "")
            or next((e["device_type"] for e in snmp_entries if e["device_type"] != "unknown"), "")
            or next((e["device_type"] for e in entries if e["device_type"] != "unknown"), "unknown")
        )
        model = next((e["model"] for e in entries if e["model"]), "")
        sw = next((e["software_version"] for e in entries if e["software_version"]), "")
        category = next((e["device_category"] for e in entries if e["device_category"]), "")
        status = next((e["status"] for e in snmp_entries), entries[0]["status"])

        # Canonical existing host: serial > known IP (primary/alias) > sysName.
        canonical = None
        if serial and serial in existing_by_serial:
            canonical = existing_by_serial[serial]
        if canonical is None:
            for ip in list(group_ips) + sorted(iface_ips):
                hid = existing_ip_index.get(ip)
                if hid is not None and hid in existing_by_id:
                    canonical = existing_by_id[hid]
                    break
        if canonical is None and sys_norm and sys_norm in existing_by_name:
            canonical = existing_by_name[sys_norm]

        canonical_id = canonical["id"] if canonical else None

        # Strong duplicates of THIS device: another existing host whose primary
        # IP is in the device's ipAddrTable, or that shares its serial.
        for h in existing_hosts:
            if canonical_id is not None and h["id"] == canonical_id:
                continue
            hip = (h.get("ip_address") or "").strip()
            hser = (h.get("serial_number") or "").strip()
            if (hser and serial and hser == serial) or (hip and hip in iface_ips):
                if h["id"] not in plan["delete"]:
                    plan["delete"].append(h["id"])

        if canonical is None:
            primary_ip = (
                snmp_entries[0]["ip"] if snmp_entries else sorted(group_ips, key=lambda x: ipaddress.ip_address(x))[0]
            )
            plan["add"].append(
                {
                    "hostname": real_hostname,
                    "ip": primary_ip,
                    "device_type": device_type,
                    "status": status,
                    "model": model,
                    "software_version": sw,
                    "device_category": category,
                    "serial_number": serial,
                    "alias_ips": sorted(full_ips - {primary_ip}),
                }
            )
        else:
            primary_ip = (canonical.get("ip_address") or "").strip()
            eff_hostname = real_hostname if sys_norm else canonical.get("hostname")
            existing_dt = canonical.get("device_type", "unknown")
            eff_dt = device_type
            # Only an *explicit* SSH/HTTPS probe is low-confidence (its banner
            # reveals vendor but not OS variant); a blank protocol, any SNMP
            # probe, or an OS read from show version over SSH is
            # authoritative (and may correct cisco_ios to cisco_xe). A
            # low-confidence probe may only fill an unknown type, never
            # overwrite an established one.
            low_confidence = (
                not ssh_typed and not any_snmp and any(e["probe_protocol"] in ("ssh", "https") for e in entries)
            )
            if low_confidence and existing_dt != "unknown" and device_type != existing_dt:
                eff_dt = existing_dt
            elif device_type == "unknown" and existing_dt != "unknown":
                eff_dt = existing_dt
            plan["update"].append(
                {
                    "host_id": canonical_id,
                    "hostname": eff_hostname,
                    "ip": primary_ip,
                    "device_type": eff_dt,
                    "status": status,
                    "model": model,
                    "software_version": sw,
                    "device_category": category,
                    "serial_number": serial,
                    "alias_ips": sorted(full_ips - {primary_ip}),
                }
            )

    # "matched" = devices reconciled this cycle (adds + updates), preserving the
    # pre-dedup meaning of "how many discovered devices were processed".
    plan["matched"] = len(plan["add"]) + len(plan["update"])
    return plan


async def _sync_group_hosts(
    group_id: int,
    discovered_hosts: list[dict],
    remove_absent: bool = False,
    *,
    interface_ip_resolver=None,
    address_confirmed: bool | None = None,
    address_set_by: int | None = None,
) -> dict:
    """Reconcile discovered devices into inventory, deduplicating a
    multi-interface device into a single host (see _build_discovery_plan).

    ``interface_ip_resolver`` is an injectable ``async (ip) -> list[str]`` used
    only in tests; in production the device's SNMP ipAddrTable is walked.

    ``address_confirmed``: whether the addresses this sync adds or changes
    count as confirmed by an admin (``managed_targets``); ``None``: as the
    acting user of the request decides (an admin or the API token: yes).
    Unconfirmed, the group's SNMP config is walked only on the addresses of
    hosts an admin already confirmed. ``address_set_by``: the signed-in user
    recorded as having set those addresses; with ``address_confirmed``
    ``None`` the acting user of the request.
    """
    if address_confirmed is None:
        confirmed = await caller_confirms_addresses()
        address_set_by = await address_writer_id()
    else:
        confirmed = address_confirmed
    existing_hosts = await db.get_hosts_for_group(group_id)
    existing_by_id = {h["id"]: h for h in existing_hosts}
    existing_ip_index = await db.get_host_ip_index(group_id)

    normalized = [n for n in (_normalize_discovered_entry(h) for h in discovered_hosts) if n]

    # ── Learn each device's full interface-IP set via SNMP ipAddrTable ────
    # Walk one representative IP per device (deduped by serial/sysName) so a
    # device with many IPs isn't walked once per IP.
    interface_ip_map: dict[str, list[str]] = {}
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)
    if interface_ip_resolver is not None:
        for e in normalized:
            if e["snmp_reachable"]:
                interface_ip_map[e["ip"]] = await interface_ip_resolver(e["ip"])
    elif snmp_cfg.get("enabled"):
        reps: dict[str, str] = {}
        for e in normalized:
            if e["snmp_reachable"]:
                reps.setdefault(e["serial"] or e["sys_name_norm"] or e["ip"], e["ip"])
        targets = list(reps.values())
        if not confirmed:
            # The shared SNMP config goes only to a confirmed address.
            trusted = {str(h.get("ip_address") or "").strip() for h in existing_hosts if host_address_confirmed(h)}
            targets = [ip for ip in targets if ip in trusted]
        sem = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))

        async def _walk(ip: str) -> list[str]:
            async with sem:
                return await _collect_interface_ips(
                    ip,
                    float(snmp_cfg.get("timeout_seconds", 2.0)),
                    snmp_cfg,
                )

        walked = await asyncio.gather(*[_walk(ip) for ip in targets], return_exceptions=True)
        for ip, res in zip(targets, walked):
            if isinstance(res, list):
                interface_ip_map[ip] = res

    plan = _build_discovery_plan(normalized, existing_hosts, existing_ip_index, interface_ip_map)

    added = updated = removed = 0
    # Never delete a host we're keeping as a canonical update target.
    keep_ids = {u["host_id"] for u in plan["update"]}

    async def _write_device_info(host_id: int, item: dict, existing: dict | None) -> None:
        model = item.get("model", "")
        sw = item.get("software_version", "")
        category = item.get("device_category", "")
        if model or sw or category:
            await db.update_host_device_info(
                host_id,
                model or (existing or {}).get("model", ""),
                sw or (existing or {}).get("software_version", ""),
                category or (existing or {}).get("device_category", ""),
            )
        serial = item.get("serial_number", "")
        if serial and serial != (existing or {}).get("serial_number", ""):
            await db.update_host_serial(host_id, serial)
        await db.set_host_ip_aliases(host_id, item["ip"], item.get("alias_ips", []))

    # ── Updates (existing hosts first, so IDs/ordering stay stable) ───────
    for item in plan["update"]:
        existing = existing_by_id.get(item["host_id"], {})
        if existing.get("hostname") != item["hostname"] or existing.get("device_type") != item["device_type"]:
            await db.update_host(
                item["host_id"],
                item["hostname"],
                item["ip"],
                item["device_type"],
                address_confirmed=confirmed,
                address_set_by=address_set_by,
            )
            await push_inventory_host_allocation(
                hostname=item["hostname"],
                ip_address=item["ip"],
                source_hint="discovery-update",
            )
            updated += 1
        await _write_device_info(item["host_id"], item, existing)
        await db.update_host_status(item["host_id"], item["status"])

    # ── Adds ──────────────────────────────────────────────────────────────
    for item in plan["add"]:
        _validate_host_ip(item["ip"])
        try:
            new_id = await db.add_host(
                group_id,
                item["hostname"],
                item["ip"],
                item["device_type"],
                address_confirmed=confirmed,
                address_set_by=address_set_by,
            )
        except ValueError:
            # Race/duplicate within the payload - reconciled on the next pass.
            continue
        await db.update_host_status(new_id, item["status"])
        await push_inventory_host_allocation(
            hostname=item["hostname"],
            ip_address=item["ip"],
            source_hint="discovery-add",
        )
        await _write_device_info(new_id, item, None)
        try:
            await db.apply_graph_templates_to_host(new_id)
        except Exception as exc:
            LOGGER.debug("inventory: failed to apply graph templates to host %s: %s", new_id, exc)
        added += 1

    # ── Suppress pre-existing duplicate host rows (strong evidence only) ──
    for dup_id in plan["delete"]:
        if dup_id in keep_ids:
            continue
        await db.remove_host(dup_id)
        removed += 1

    # ── remove_absent: drop hosts no device claims this cycle ─────────────
    if remove_absent:
        covered = plan["covered_ips"]
        for h in existing_hosts:
            if h["id"] in keep_ids or h["id"] in plan["delete"]:
                continue
            if (h.get("ip_address") or "").strip() in covered:
                continue
            await db.remove_host(h["id"])
            removed += 1

    if added or updated or removed:
        await _notify_flow_collector_host_changed()

    return {
        "added": added,
        "updated": updated,
        "removed": removed,
        "matched": plan["matched"],
        "existing_before": len(existing_hosts),
        "existing_after": len(existing_hosts) + added - removed,
    }


async def _software_changed() -> None:
    """Hosts were reconciled with what their devices report: bring the
    software version tracker and its alerts up to date, so a version a sync
    read (an upgraded switch) does not wait for the tracker's own interval.
    Best-effort; the hosts are already stored."""
    from netcontrol.routes.software import refresh_after_collection

    await refresh_after_collection()


# ── Background loops ─────────────────────────────────────────────────────────


async def _run_discovery_sync_once() -> dict:
    DISCOVERY_SYNC_CONFIG = state.DISCOVERY_SYNC_CONFIG
    if not DISCOVERY_SYNC_CONFIG.get("enabled"):
        return {"enabled": False, "profiles": 0, "synced_groups": 0, "errors": 0}

    profiles = DISCOVERY_SYNC_CONFIG.get("profiles", [])
    synced_groups = 0
    errors = 0
    for profile in profiles:
        group_id = int(profile.get("group_id", 0))
        if group_id <= 0:
            continue
        group = await db.get_group(group_id)
        if not group:
            errors += 1
            LOGGER.warning("discovery sync: skipped missing group_id=%s", group_id)
            continue
        try:
            body = DiscoverySyncRequest.model_validate(
                {
                    "cidrs": profile.get("cidrs", []),
                    "timeout_seconds": profile.get("timeout_seconds", state.DISCOVERY_DEFAULT_TIMEOUT_SECONDS),
                    "max_hosts": profile.get("max_hosts", state.DISCOVERY_DEFAULT_MAX_HOSTS),
                    "device_type": profile.get("device_type", "unknown"),
                    "hostname_prefix": profile.get("hostname_prefix", "discovered"),
                    "use_snmp": profile.get("use_snmp", True),
                    "remove_absent": profile.get("remove_absent", False),
                }
            )
            # Unattended: the group's remembered credential when it is a
            # service credential, else the Plexus service credential (never
            # a user's personal credential: there is no session to check).
            credential, _ = await _resolve_discovery_ssh(body, None, group=group, unattended=True)
            _, discovered = await _discover_hosts(body, group_id=group_id, credential=credential)
            # The profiles are an admin's (``/api/admin/discovery-sync``): the
            # addresses this run finds in their ranges count as confirmed.
            result = await _sync_group_hosts(
                group_id, discovered, remove_absent=body.remove_absent, address_confirmed=True
            )
            synced_groups += 1
            LOGGER.info(
                "discovery sync: group_id=%s discovered=%s added=%s updated=%s removed=%s",
                group_id,
                len(discovered),
                result["added"],
                result["updated"],
                result["removed"],
            )
            increment_metric("inventory.discovery.sync.success")
        except Exception as exc:
            errors += 1
            LOGGER.warning("discovery sync failed for group_id=%s: %s", group_id, redact_value(str(exc)))
            increment_metric("inventory.discovery.sync.failed")

    if synced_groups:
        await _software_changed()

    return {
        "enabled": True,
        "profiles": len(profiles),
        "synced_groups": synced_groups,
        "errors": errors,
    }


async def _discovery_sync_loop() -> None:
    # The first scan runs here, before the first sleep, in the background:
    # startup (``lifespan``) does not wait for it.
    while True:
        try:
            await _run_discovery_sync_once()
            await asyncio.sleep(
                int(
                    state.DISCOVERY_SYNC_CONFIG.get(
                        "interval_seconds", state.DISCOVERY_SYNC_DEFAULTS["interval_seconds"]
                    )
                )
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("discovery sync loop failure: %s", redact_value(str(exc)))
            increment_metric("inventory.discovery.sync.loop.failed")
            await asyncio.sleep(state.DISCOVERY_SYNC_DEFAULTS["interval_seconds"])


# ══════════════════════════════════════════════════════════════════════════════
# Admin routes (admin_router - registered with require_admin dependency)
# ══════════════════════════════════════════════════════════════════════════════


@admin_router.get("/api/admin/discovery-sync")
async def admin_get_discovery_sync_config():
    return state.DISCOVERY_SYNC_CONFIG


@admin_router.put("/api/admin/discovery-sync")
async def admin_update_discovery_sync_config(body: dict):
    state.DISCOVERY_SYNC_CONFIG = state._sanitize_discovery_sync_config(body)
    await db.set_auth_setting("discovery_sync", state.DISCOVERY_SYNC_CONFIG)
    return state.DISCOVERY_SYNC_CONFIG


@admin_router.post("/api/admin/discovery-sync/run-now")
async def admin_run_discovery_sync_now():
    result = await _run_discovery_sync_once()
    return {"ok": True, "result": result}


class HostAddressConfirm(BaseModel):
    """The hosts whose addresses an admin confirms: ``host_ids``, the hosts
    of ``group_id``, or both."""

    host_ids: list[int] = Field(default_factory=list, max_length=10000)
    group_id: int | None = None


async def _confirm_addresses(request: Request, host_ids: list[int]) -> dict:
    """Confirm the addresses of ``host_ids`` (``managed_targets``): shared
    secrets may then go to them. Audited with each host and its address."""
    hosts = {int(h["id"]): h for h in await db.get_hosts_by_ids(sorted(set(host_ids)))}
    confirmed = await db.confirm_host_addresses(list(hosts))
    if confirmed:
        session = _get_session(request)
        shown = ", ".join(f"{hid}={hosts[hid].get('ip_address', '')}" for hid in confirmed[:50])
        await _audit(
            "inventory",
            "host.address_confirmed",
            user=session["user"] if session else API_TOKEN_USER,
            detail=f"confirmed={len(confirmed)} hosts: {shown}" + (" ..." if len(confirmed) > 50 else ""),
            correlation_id=_corr_id(request),
        )
    return {"ok": True, "confirmed": confirmed, "already_confirmed": sorted(set(hosts) - set(confirmed))}


@admin_router.post("/api/admin/hosts/{host_id}/confirm-address")
async def admin_confirm_host_address(host_id: int, request: Request):
    """Confirm one host's address (admin only)."""
    if await db.get_host(host_id) is None:
        raise HTTPException(404, "Host not found")
    return await _confirm_addresses(request, [host_id])


@admin_router.post("/api/admin/hosts/confirm-address")
async def admin_confirm_host_addresses(body: HostAddressConfirm, request: Request):
    """Confirm the addresses of a list of hosts and/or every host of a
    group (admin only)."""
    ids = list(body.host_ids)
    if body.group_id is not None:
        if await db.get_group(body.group_id) is None:
            raise HTTPException(404, "Group not found")
        ids += [int(h["id"]) for h in await db.get_hosts_for_group(body.group_id)]
    if not ids:
        raise HTTPException(400, "Give host_ids or group_id")
    return await _confirm_addresses(request, ids)


def _sanitized_snmp(sanitize, *args) -> dict:
    """``sanitize(*args)`` for a request body; ``400`` when ``port``,
    ``timeout_seconds`` or ``retries`` is not a number."""
    try:
        return sanitize(*args)
    except TypeError, ValueError, OverflowError:
        raise HTTPException(400, "port, timeout_seconds and retries must be numbers") from None


@admin_router.get("/api/admin/snmp-discovery")
async def admin_get_snmp_discovery_config():
    # Secrets are write-only, as in the per-group profile below.
    return mask_secret_fields(state.SNMP_DISCOVERY_CONFIG, SNMP_SECRET_FIELDS)


@admin_router.put("/api/admin/snmp-discovery")
async def admin_update_snmp_discovery_config(body: dict):
    # A secret sent as the mask, or left out, keeps the stored one.
    body = merge_secret_fields(body, state.SNMP_DISCOVERY_CONFIG, SNMP_SECRET_FIELDS)
    state.SNMP_DISCOVERY_CONFIG = _sanitized_snmp(state._sanitize_snmp_discovery_config, body)
    await db.set_auth_setting("snmp_discovery", state.SNMP_DISCOVERY_CONFIG)
    return mask_secret_fields(state.SNMP_DISCOVERY_CONFIG, SNMP_SECRET_FIELDS)


@admin_router.get("/api/admin/snmp-discovery-profiles")
async def admin_get_snmp_discovery_profiles():
    return {
        group_id: mask_secret_fields(profile, SNMP_SECRET_FIELDS)
        for group_id, profile in state.SNMP_DISCOVERY_PROFILES.items()
    }


# ── Named SNMP Profiles CRUD ─────────────────────────────────────────────────
# NOTE: GET /api/admin/snmp-profiles is on the main `router` (inventory
# feature), because every inventory user's profile picker needs the list.
# Only admins get the stored profiles; others get the public view.

# The SNMP secrets of a profile (named or a group's discovery profile) are
# ``secret_fields.SNMP_SECRET_FIELDS``.


def public_snmp_profile(profile: dict) -> dict:
    """A named SNMP profile without its secrets: what a picker needs, and
    which secrets are set."""
    v3 = profile.get("v3") or {}
    return {
        "id": profile.get("id", ""),
        "name": profile.get("name", ""),
        "enabled": bool(profile.get("enabled")),
        "version": profile.get("version", "2c"),
        "port": profile.get("port", 161),
        "has_community": bool(profile.get("community")),
        "has_v3_auth_password": bool(v3.get("auth_password")),
        "has_v3_priv_password": bool(v3.get("priv_password")),
    }


@router.get("/api/admin/snmp-profiles")
@scope_exempt("SNMP profile definitions: no host or inventory group data")
async def admin_list_snmp_profiles(request: Request):
    """Admins (the profile editor) get the stored profiles; other inventory
    users the public view, never a community string or v3 key."""
    if await caller_is_admin(request):
        return list(state.SNMP_PROFILES.values())
    return [public_snmp_profile(p) for p in state.SNMP_PROFILES.values()]


async def _validate_snmp_profile_secrets(profile: dict):
    """Check that any {{secret.NAME}} references in v3 passwords exist."""
    from routes.secret_resolver import extract_secret_names, has_secret_references

    v3 = profile.get("v3", {})
    for field_name in ("auth_password", "priv_password"):
        value = v3.get(field_name, "")
        if has_secret_references(value):
            names = extract_secret_names([value])
            for name in names:
                row = await db.get_secret_variable_by_name(name)
                if row is None:
                    raise HTTPException(
                        400,
                        f"Secret variable '{name}' not found. Create it in Credentials \u2192 Secret Variables first.",
                    )


@admin_router.post("/api/admin/snmp-profiles")
async def admin_create_snmp_profile(body: dict):
    profile_id = str(uuid.uuid4())
    profile = _sanitized_snmp(state._sanitize_snmp_profile, profile_id, body)
    if not profile["name"]:
        raise HTTPException(400, "Profile name is required")
    await _validate_snmp_profile_secrets(profile)
    state.SNMP_PROFILES[profile_id] = profile
    await db.set_auth_setting("snmp_profiles", state.SNMP_PROFILES)
    return profile


@admin_router.put("/api/admin/snmp-profiles/{profile_id}")
async def admin_update_snmp_profile(profile_id: str, body: dict):
    if profile_id not in state.SNMP_PROFILES:
        raise HTTPException(404, "Profile not found")
    profile = _sanitized_snmp(state._sanitize_snmp_profile, profile_id, body)
    if not profile["name"]:
        raise HTTPException(400, "Profile name is required")
    await _validate_snmp_profile_secrets(profile)
    state.SNMP_PROFILES[profile_id] = profile
    await db.set_auth_setting("snmp_profiles", state.SNMP_PROFILES)
    return profile


@admin_router.delete("/api/admin/snmp-profiles/{profile_id}")
async def admin_delete_snmp_profile(profile_id: str):
    if profile_id not in state.SNMP_PROFILES:
        raise HTTPException(404, "Profile not found")
    del state.SNMP_PROFILES[profile_id]
    # Unassign any groups using this profile
    changed = False
    for gid in list(state.GROUP_SNMP_ASSIGNMENTS):
        if state.GROUP_SNMP_ASSIGNMENTS[gid] == profile_id:
            del state.GROUP_SNMP_ASSIGNMENTS[gid]
            changed = True
    await db.set_auth_setting("snmp_profiles", state.SNMP_PROFILES)
    if changed:
        await db.set_auth_setting("group_snmp_assignments", state.GROUP_SNMP_ASSIGNMENTS)
    # Hosts that used it fall back to their group's config.
    await db.clear_host_snmp_profile(profile_id)
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# Inventory-feature routes (router - registered with require_auth + require_feature("inventory"))
# ══════════════════════════════════════════════════════════════════════════════


# ── Group SNMP Profile Assignment ────────────────────────────────────────────


@router.get("/api/inventory/snmp-profile-assignments")
@scoped("list")
async def list_snmp_profile_assignments(request: Request):
    """Return SNMP profile assignments for all inventory groups in one call
    (the groups the caller may read)."""
    scope = await request_scope(request)
    assignments = []
    for group_id, profile_id in state.GROUP_SNMP_ASSIGNMENTS.items():
        if not scope.can_read_group(group_id):
            continue
        profile = state.SNMP_PROFILES.get(profile_id) if profile_id else None
        assignments.append(
            {
                "group_id": group_id,
                "snmp_profile_id": profile_id,
                "profile_name": profile["name"] if profile else "",
            }
        )
    return {"assignments": assignments}


@router.get("/api/inventory/{group_id}/snmp-profile-assignment")
@scoped("group")
async def get_group_snmp_profile_assignment(group_id: int, request: Request):
    await require_group(request, group_id)
    profile_id = state.GROUP_SNMP_ASSIGNMENTS.get(group_id, "")
    profile = state.SNMP_PROFILES.get(profile_id) if profile_id else None
    return {"group_id": group_id, "snmp_profile_id": profile_id, "profile_name": profile["name"] if profile else ""}


async def assign_group_snmp_profile(group_id: int, profile_id: str) -> dict:
    """Assign the named SNMP profile to an inventory group (``""`` removes
    the assignment) and persist it. The caller checks that the group
    exists; an unknown profile raises 400."""
    profile_id = _check_snmp_profile_id(str(profile_id or "")) or ""
    if profile_id:
        state.GROUP_SNMP_ASSIGNMENTS[group_id] = profile_id
    else:
        state.GROUP_SNMP_ASSIGNMENTS.pop(group_id, None)
    await db.set_auth_setting("group_snmp_assignments", state.GROUP_SNMP_ASSIGNMENTS)
    profile = state.SNMP_PROFILES.get(profile_id) if profile_id else None
    return {"group_id": group_id, "snmp_profile_id": profile_id, "profile_name": profile["name"] if profile else ""}


@router.put("/api/inventory/{group_id}/snmp-profile-assignment")
@scoped("group")
async def update_group_snmp_profile_assignment(group_id: int, body: dict, request: Request):
    await require_group(request, group_id, write=True)
    return await assign_group_snmp_profile(group_id, str(body.get("snmp_profile_id", "")))


# ── Inventory Group CRUD ─────────────────────────────────────────────────────


def _id_key(row: dict) -> str:
    return str(row["id"])


def _visible_tree(scope: ObjectScope, groups: list[dict]) -> list[dict]:
    """The groups a scoped caller may read, as a tree of their own: a group
    whose parent is hidden becomes a top-level group (``parent_id`` None) and
    ``path``/``depth`` are recomputed over the visible groups only."""
    if scope.unrestricted:
        return groups
    visible = scope.filter_groups(groups)
    for group in visible:
        if not scope.can_read_group(group.get("parent_id")):
            group["parent_id"] = None
    return _tree_ordered(visible)


@router.get("/api/inventory")
@scoped("list")
async def list_groups(request: Request, include_hosts: bool = Query(default=False)):
    """Every group (with its hosts when ``include_hosts``), each carrying its
    ``tags`` and ``custom_fields``; hosts also carry their device model
    display objects. ``tag=`` (repeatable) and ``cf.<key>=`` filter: with
    hosts, each group keeps only its matching hosts and groups left empty are
    dropped; without, only matching groups are listed. The device filters
    (``manufacturer_id=`` and the rest) are host filters: without hosts, a
    group is listed when it has a matching host."""
    keys = await matching_keys("host" if include_hosts else "group", request.query_params)
    host_ids = await matching_host_ids(request.query_params)
    session = _get_session(request)
    user_id = session.get("user_id") if session else None
    if user_id is not None:
        if include_hosts:
            groups = await db.get_all_groups_with_hosts_for_user(int(user_id))
        else:
            groups = await db.get_all_groups_for_user(int(user_id))
    elif include_hosts:
        groups = await db.get_all_groups_with_hosts()
    else:
        groups = await db.get_all_groups()
    groups = _visible_tree(await request_scope(request), groups)
    if include_hosts and (keys is not None or host_ids is not None):
        for group in groups:
            group["hosts"] = _filter_hosts(group["hosts"], keys, host_ids)
        groups = [g for g in groups if g["hosts"]]
    elif not include_hosts:
        if keys is not None:
            groups = [g for g in groups if _id_key(g) in keys]
        if host_ids is not None:
            with_hosts = set(host_ids.values())
            groups = [g for g in groups if g["id"] in with_hosts]
    await attach_custom_data("group", groups, _id_key)
    if include_hosts:
        hosts = [h for g in groups for h in g["hosts"]]
        await attach_custom_data("host", hosts, _id_key)
        await attach_device_data(hosts)
    return groups


def _filter_hosts(hosts: list[dict], keys: set[str] | None, host_ids: dict[int, int] | None) -> list[dict]:
    """The hosts matching the tag and custom field filters (``keys``) and
    the device filters (``host_ids``); ``None`` is no filter."""
    return [h for h in hosts if (keys is None or _id_key(h) in keys) and (host_ids is None or int(h["id"]) in host_ids)]


class GroupReorderRequest(BaseModel):
    ordered_ids: list[int]


@router.post("/api/inventory/groups/reorder")
@scoped("list")
async def reorder_groups(payload: GroupReorderRequest, request: Request):
    user_id = _session_user_id(request)
    # A scoped caller orders only the groups they may read.
    scope = await request_scope(request)
    ordered_ids = [gid for gid in payload.ordered_ids if scope.can_read_group(gid)]
    await db.set_user_group_order(user_id, ordered_ids)
    return {"ok": True}


@router.get("/api/inventory/export/csv")
@scoped("list")
async def export_inventory_csv(request: Request):
    """Export all inventory hosts (that the caller may read) as a CSV file:
    the host columns (the driver key as ``Platform``, the group's path as
    ``Group``), the device model columns, then ``Tags`` (names joined with
    ``; ``) and one column per custom field that applies to hosts, in
    display order. Bulk import reads this file back as it is."""
    fields, records = await host_export_records(
        (await request_scope(request)).filter_hosts(await db.get_all_hosts_for_export())
    )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(host_csv_header(fields))
    for record in records:
        writer.writerow(host_csv_row(record, fields))
    return StreamingResponse(
        io.StringIO(output.getvalue()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inventory_export.csv"},
    )


@router.get("/api/inventory/export/yaml")
@scoped("list")
async def export_inventory_yaml(request: Request):
    """The hosts of the CSV export as YAML: a list of objects with the
    columns as snake_case keys, ``tags`` a list and ``custom_fields`` the
    values by field key. Bulk import reads this file back as it is."""
    _fields, records = await host_export_records(
        (await request_scope(request)).filter_hosts(await db.get_all_hosts_for_export())
    )
    return Response(
        content=yaml.safe_dump(records, sort_keys=False, allow_unicode=True),
        media_type="application/yaml",
        headers={"Content-Disposition": "attachment; filename=inventory_export.yaml"},
    )


_SIBLING_NAME_TAKEN = "A group with that name already exists at this level"


# A scoped caller cannot create or move a group to the top level.
_TOP_LEVEL_NEEDS_ALL = "Only accounts with access to all devices can place a group at the top level"


async def _check_group_parent(request: Request, scope: ObjectScope, parent_id: int | None) -> None:
    """A scoped caller may put a group only under a group they may write."""
    if scope.unrestricted:
        return
    if parent_id is None:
        raise HTTPException(403, _TOP_LEVEL_NEEDS_ALL)
    await require_group(request, parent_id, write=True)


@router.post("/api/inventory", status_code=201)
@scoped("create")
async def create_group(body: GroupCreate, request: Request):
    await _check_group_parent(request, await request_scope(request), body.parent_id)
    await enforce_validation_rules("group", {"name": body.name, "description": body.description})
    try:
        gid = await db.create_group(body.name, body.description, parent_id=body.parent_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        if db._is_unique_violation(exc):
            raise HTTPException(409, _SIBLING_NAME_TAKEN)
        raise
    return {"id": gid, "name": body.name, "parent_id": body.parent_id}


@router.put("/api/inventory/{group_id}")
@scoped("group")
async def update_group(group_id: int, body: GroupUpdate, request: Request):
    group = await require_group(request, group_id, write=True)
    move = {"parent_id": body.parent_id} if "parent_id" in body.model_fields_set else {}
    scope = await request_scope(request)
    if move and scope.restricted and body.parent_id != group.get("parent_id"):
        # Moving needs write on where the group is and where it goes.
        await _check_group_parent(request, scope, group.get("parent_id"))
        await _check_group_parent(request, scope, body.parent_id)
    await enforce_validation_rules(
        "group", {"name": body.name, "description": body.description}, existing=rule_values(group, "group")
    )
    try:
        await db.update_group(group_id, body.name, body.description, **move)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        if db._is_unique_violation(exc):
            raise HTTPException(409, _SIBLING_NAME_TAKEN)
        raise
    return {"ok": True}


@router.get("/api/inventory/{group_id}")
@scoped("group")
async def get_group(group_id: int, request: Request):
    """A group with its hosts; ``tag=``, ``cf.<key>=`` and the device
    filters keep only the matching hosts."""
    group = await require_group(request, group_id)
    scope = await request_scope(request)
    if scope.restricted:
        # Its place in the caller's own tree (see _visible_tree).
        mine = next(g for g in _visible_tree(scope, await db.get_all_groups()) if g["id"] == group["id"])
        group.update(parent_id=mine["parent_id"], path=mine["path"], depth=mine["depth"])
    hosts = await _group_hosts(group_id, request)
    result = {**group, "hosts": hosts}
    await attach_custom_data("group", [result], _id_key)
    return result


@router.delete("/api/inventory/{group_id}")
@scoped("group")
async def delete_group(group_id: int, request: Request):
    if (await request_scope(request)).restricted:
        await require_group(request, group_id, write=True)
    try:
        await db.delete_group(group_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True}


# ── Hosts ────────────────────────────────────────────────────────────────────


@router.get("/api/inventory/{group_id}/hosts")
@scoped("group")
async def list_hosts(group_id: int, request: Request):
    """A group's hosts with their ``tags``, ``custom_fields`` and device
    model display objects; ``tag=``, ``cf.<key>=`` and the device filters
    keep only the matching hosts."""
    if (await request_scope(request)).restricted:
        await require_group(request, group_id)
    return await _group_hosts(group_id, request)


async def _group_hosts(group_id: int, request: Request) -> list[dict]:
    keys = await matching_keys("host", request.query_params)
    host_ids = await matching_host_ids(request.query_params)
    hosts = _filter_hosts(await db.get_hosts_for_group(group_id), keys, host_ids)
    await attach_custom_data("host", hosts, _id_key)
    await attach_device_data(hosts)
    return hosts


async def _insert_host(
    group_id: int, body: HostCreate, *, address_confirmed: bool, address_set_by: int | None = None
) -> int:
    """Validate and insert one host, then run the per-host follow-ups.

    Shared by the single and bulk add routes. Raises ``HTTPException`` for an
    invalid address, instance ID, SNMP profile or device model id and
    ``ValueError`` when the group already has a host with that IP. The caller
    invalidates the topology cache and audits the device values.
    ``address_confirmed``: the caller is an admin or the API token
    (``managed_targets.caller_confirms_addresses``); ``address_set_by``: the
    signed-in user who wrote the address (``managed_targets.address_writer_id``).
    """
    _validate_host_ip(body.ip_address)
    aws_instance_id = _validate_aws_instance_id(body.aws_instance_id) or ""
    snmp_profile_id = _check_snmp_profile_id(body.snmp_profile_id) or ""
    device_values = sent_device_values(body)
    await check_device_values(device_values)
    await enforce_validation_rules(
        "host",
        {
            "hostname": body.hostname,
            "ip_address": body.ip_address,
            "device_type": body.device_type,
            "vrf_name": body.vrf_name or "",
            "vlan_id": str(body.vlan_id or ""),
            "aws_instance_id": aws_instance_id,
        },
    )
    hid = await db.add_host(
        group_id,
        body.hostname,
        body.ip_address,
        body.device_type,
        vrf_name=body.vrf_name or "",
        vlan_id=str(body.vlan_id or ""),
        aws_instance_id=aws_instance_id,
        snmp_profile_id=snmp_profile_id,
        address_confirmed=address_confirmed,
        address_set_by=address_set_by,
    )
    if device_values:
        await db.set_host_device_fields(hid, device_values, lock=True)
    await after_host_write(hid, body.hostname, body.ip_address, created=True)
    return hid


async def after_host_write(host_id: int, hostname: str, ip_address: str, *, created: bool, prior_ip: str = "") -> None:
    """The follow-ups of a host write once it is stored: graph templates for
    a new host, the IPAM push and the flow collector's host cache. Shared by
    the host routes and bulk import (``netcontrol.bulk_import``)."""
    if created:
        # Auto-apply graph templates to manually added host
        try:
            await db.apply_graph_templates_to_host(host_id)
        except Exception as exc:
            LOGGER.warning("inventory: failed to apply graph templates to host %s: %s", host_id, exc)
    await push_inventory_host_allocation(
        hostname=hostname,
        ip_address=ip_address,
        source_hint="inventory-add" if created else "inventory-update",
    )
    await _notify_flow_collector_host_changed(
        old_ip=None if created else (prior_ip or None),
        new_ip=ip_address or None,
        host_id=host_id,
    )


@router.post("/api/inventory/{group_id}/hosts", status_code=201)
@scoped("group")
async def add_host(group_id: int, body: HostCreate, request: Request):
    if (await request_scope(request)).restricted:
        await require_group(request, group_id, write=True)
    elif not await db.get_group(group_id):
        raise HTTPException(404, "Group not found")
    try:
        hid = await _insert_host(
            group_id,
            body,
            address_confirmed=await caller_confirms_addresses(request),
            address_set_by=await address_writer_id(request),
        )
    except ValueError:
        raise HTTPException(409, "A host with that IP address already exists in this group")
    device_values = sent_device_values(body)
    if device_values:
        await audit_device_write(request, "host_create", f"host={hid} {describe_values(device_values)}")
    # The map may have a place for the host already (an AWS instance with
    # its address or ID): show it on the next load, not after the cache TTL.
    _invalidate_topology_cache()
    return {"id": hid}


async def _bulk_add(entries: list[HostBulkEntry], default_group_id: int | None, request: Request) -> dict:
    """Add many hosts, each to its own group (the Topology page's "Add to inventory").

    An entry names its group by ``group_id``, ``group_path`` (the names from
    the top, e.g. ``["Meraki", "HQ"]``) or ``group_name`` (a top-level group),
    at most one of them, or none to use ``default_group_id``. A level of a
    path (or a named group) that does not exist is created once, and only
    when a host is about to go into it; ``groups_created`` lists every level
    created. Each entry is validated like a single add. An entry that is
    already a host in any group is skipped, naming that host: matched like
    the Topology map matches its nodes to hosts (``InventoryIndex``), by AWS
    instance ID, serial number, IP address (a host's own or one of its
    interface addresses) or hostname, including the hosts this request
    added. One bad entry never fails the batch: it is listed under ``errors``.
    """
    if len(entries) > BULK_ADD_MAX_HOSTS:
        raise HTTPException(400, f"At most {BULK_ADD_MAX_HOSTS} hosts can be added at once")
    scope = await request_scope(request)
    if scope.restricted and default_group_id is not None:
        await require_group(request, default_group_id, write=True)
    groups = await db.get_all_groups()
    name_by_id: dict[int, str] = {g["id"]: g["name"] for g in groups}
    path_by_id: dict[int, str] = {g["id"]: g["path"] for g in groups}
    if default_group_id is not None and default_group_id not in name_by_id:
        raise HTTPException(404, "Group not found")
    added: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    groups_created: list[dict] = []
    id_by_path: dict[tuple[str, ...], int] = {}
    index = await load_inventory_index()
    confirms = await caller_confirms_addresses(request)
    writer = await address_writer_id(request)

    async def group_for(path: tuple[str, ...]) -> int:
        if path in id_by_path:
            return id_by_path[path]
        levels = await db.get_or_create_group_path(list(path), description=BULK_ADD_GROUP_DESCRIPTION)
        for level in levels:
            name_by_id[level["id"]] = level["name"]
            path_by_id[level["id"]] = level["path"]
            if level["created"]:
                groups_created.append({k: level[k] for k in ("id", "name", "parent_id", "path")})
        id_by_path[path] = levels[-1]["id"]
        return id_by_path[path]

    for entry in entries:
        entry.ip_address = entry.ip_address.strip()
        entry.hostname = entry.hostname.strip() or entry.ip_address
        names = {"hostname": entry.hostname, "ip_address": entry.ip_address}
        group_name = (entry.group_name or "").strip()
        group_path = tuple(n.strip() for n in entry.group_path or ())
        if sum((entry.group_id is not None, bool(group_name), bool(group_path))) > 1:
            errors.append({**names, "error": "Give one of group_id, group_name or group_path, not several"})
            continue
        if any(not n for n in group_path):
            errors.append({**names, "error": "A group path cannot have an empty name"})
            continue
        if group_name:
            group_path = (group_name,)
        group_id = entry.group_id if entry.group_id is not None else default_group_id
        if group_path:
            group_id = None
        if group_id is None and not group_path:
            errors.append({**names, "error": "No group given"})
            continue
        if scope.restricted and group_path:
            # Named groups may be created at the top level: all devices only.
            errors.append({**names, "error": _TOP_LEVEL_NEEDS_ALL})
            continue
        if group_id is not None and (group_id not in name_by_id or not scope.can_read_group(group_id)):
            errors.append({**names, "error": "Group not found"})
            continue
        if group_id is not None and not scope.can_write_group(group_id):
            errors.append({**names, "error": READ_ONLY_DETAIL})
            continue
        entry.serial_number = entry.serial_number.strip()
        existing, matched_by = index.match_key(
            serial=entry.serial_number,
            ips=[entry.ip_address],
            name=entry.hostname,
            instance_id=entry.aws_instance_id or "",
        )
        if existing:
            seen = scope.can_read_group(existing.get("group_id"))
            skipped.append(
                {
                    **names,
                    "reason": _BULK_SKIP_REASONS[matched_by],
                    # A host the caller may not read is not named.
                    "host_id": existing.get("id") if seen else None,
                    "group_id": existing.get("group_id") if seen else None,
                }
            )
            continue
        try:
            # Validate before creating a group, so a bad entry leaves none behind.
            _validate_host_ip(entry.ip_address)
            _validate_aws_instance_id(entry.aws_instance_id)
            _check_snmp_profile_id(entry.snmp_profile_id)
            if group_id is None:
                label = db.GROUP_PATH_SEPARATOR.join(group_path)
                try:
                    group_id = await group_for(group_path)
                except Exception as exc:
                    LOGGER.warning("inventory: bulk add could not create group %r: %s", label, exc)
                    errors.append({**names, "error": f"Could not create group {label!r}"})
                    continue
            hid = await _insert_host(group_id, entry, address_confirmed=confirms, address_set_by=writer)
            if entry.serial_number:
                await db.update_host_serial(hid, entry.serial_number)
        except HTTPException as exc:
            detail = exc.detail["message"] if isinstance(exc.detail, dict) else str(exc.detail)
            errors.append({**names, "error": detail})
            continue
        except ValueError:
            errors.append({**names, "error": "A host with that IP address already exists in this group"})
            continue
        index.add(
            {
                "id": hid,
                **names,
                "group_id": group_id,
                "aws_instance_id": entry.aws_instance_id,
                "serial_number": entry.serial_number,
            }
        )
        added.append(
            {
                "id": hid,
                **names,
                "group_id": group_id,
                "group_name": name_by_id[group_id],
                "group_path": path_by_id[group_id],
            }
        )
    if added or groups_created:
        _invalidate_topology_cache()
    session = _get_session(request)
    scope = f"group_id={default_group_id} " if default_group_id is not None else ""
    await _audit(
        "inventory",
        "host.bulk_added",
        user=session["user"] if session else "",
        detail=(
            f"{scope}added={len(added)} skipped={len(skipped)} errors={len(errors)} "
            f"groups_created={len(groups_created)}"
        ),
        correlation_id=_corr_id(request),
    )
    return {"added": added, "skipped": skipped, "errors": errors, "groups_created": groups_created}


@router.post("/api/inventory/hosts/bulk")
@scoped("hosts")
async def bulk_add_hosts_grouped(body: HostBulkCreateGrouped, request: Request):
    """Add many hosts, each to the group it names (created when missing)."""
    return await _bulk_add(body.hosts, body.group_id, request)


@router.post("/api/inventory/{group_id}/hosts/bulk")
@scoped("group")
async def bulk_add_hosts(group_id: int, body: HostBulkCreate, request: Request):
    """Add many hosts to one group (see ``_bulk_add``)."""
    # exclude_unset: a device value an entry did not send stays unsent.
    entries = [HostBulkEntry(**h.model_dump(exclude_unset=True)) for h in body.hosts]
    result = await _bulk_add(entries, group_id, request)
    result.pop("groups_created")
    return result


@router.put("/api/hosts/{host_id}")
@scoped("host")
async def update_host(host_id: int, body: HostUpdate, request: Request):
    if (await request_scope(request)).restricted:
        host = await require_host(request, host_id, write=True)
        if body.group_id is not None and int(body.group_id) != host.get("group_id"):
            await require_group(request, int(body.group_id), write=True)
    if body.ip_address:
        _validate_host_ip(body.ip_address)
    aws_instance_id = _validate_aws_instance_id(body.aws_instance_id)
    snmp_profile_id = _check_snmp_profile_id(body.snmp_profile_id)
    device_values = sent_device_values(body)
    await check_device_values(device_values)
    prior = await db.get_host(host_id)
    prior_ip = (prior.get("ip_address") if prior else "") or ""
    await enforce_validation_rules(
        "host",
        {
            "hostname": body.hostname,
            "ip_address": body.ip_address,
            "device_type": body.device_type,
            "vrf_name": body.vrf_name,
            "vlan_id": body.vlan_id,
            "aws_instance_id": aws_instance_id,
        },
        existing=rule_values(prior, "host") if prior else None,
    )
    # Rack placement (DCIM): checked before anything is written, against the
    # site this edit leaves the host at.
    placement_values = sent_placement_values(body)
    if prior and (placement_values or "site_id" in device_values):
        await check_host_placement(
            host_id, placement_values, device_values.get("site_id"), site_sent="site_id" in device_values
        )
    await db.update_host(
        host_id,
        body.hostname,
        body.ip_address,
        body.device_type,
        vrf_name=body.vrf_name,
        vlan_id=body.vlan_id,
        aws_instance_id=aws_instance_id,
        snmp_profile_id=snmp_profile_id,
        # Used only when the address changes (managed_targets).
        address_confirmed=await caller_confirms_addresses(request),
        address_set_by=await address_writer_id(request),
    )
    if device_values and await db.set_host_device_fields(host_id, device_values, lock=True):
        await audit_device_write(request, "host_update", f"host={host_id} {describe_values(device_values)}")
    if prior and placement_values and await apply_host_placement(host_id, placement_values):
        await audit_device_write(request, "host_place", f"host={host_id} {describe_values(placement_values)}")
    _invalidate_topology_cache()
    # Optional re-group as part of the same edit. The (group_id, ip_address)
    # unique key means moving to a group that already has this IP will fail
    # with an asyncpg/sqlite UniqueViolationError - surface as a clean 409.
    if body.group_id is not None:
        try:
            await db.move_hosts([host_id], int(body.group_id))
        except Exception as exc:
            msg = str(exc).lower()
            if "unique" in msg or "duplicate key" in msg:
                raise HTTPException(409, "Target group already has a host with this IP address")
            raise
    await after_host_write(host_id, body.hostname, body.ip_address, created=False, prior_ip=prior_ip)
    return {"ok": True}


_VALID_CATEGORIES = {*DEVICE_CATEGORIES, ""}


@router.patch("/api/hosts/{host_id}/category")
@scoped("host")
async def update_host_category(host_id: int, body: dict, request: Request):
    if (await request_scope(request)).restricted:
        await require_host(request, host_id, write=True)
    category = str(body.get("device_category", "")).strip().lower()
    if category not in _VALID_CATEGORIES:
        raise HTTPException(400, "Invalid device category")
    _db = await db.get_db()
    try:
        await _db.execute(
            "UPDATE hosts SET device_category = ? WHERE id = ?",
            (category, host_id),
        )
        await _db.commit()
    finally:
        await _db.close()
    # A category that names a role fills the host's role when it has none.
    await db.link_host_hardware(host_id, category=category)
    return {"ok": True}


@router.delete("/api/hosts/{host_id}")
@scoped("host")
async def remove_host(host_id: int, request: Request):
    if (await request_scope(request)).restricted:
        await require_host(request, host_id, write=True)
    prior = await db.get_host(host_id)
    prior_ip = (prior.get("ip_address") if prior else "") or ""
    await db.remove_host(host_id)
    if prior_ip:
        await _notify_flow_collector_host_changed(old_ip=prior_ip)
    return {"ok": True}


@router.post("/api/hosts/{host_id}/fetch-serial")
@scoped("host")
async def fetch_host_serial(host_id: int, body: FetchSerialRequest, request: Request):
    """SSH to the device and pull its chassis serial via the vendor driver.

    Stores the parsed serial in the DB and returns it.  Requires a stored
    credential ID so the caller selects which credential set to use.
    The show command and the parser both come from the device's driver,
    so NX-OS hosts (which print "Processor Board ID" instead of "System
    Serial Number") and future non-Cisco vendors work without branching
    here.

    On a driver with ``show inventory`` (Cisco) it also reads and stores
    the host's hardware components (``components``: the number stored),
    unless the host has a complete SNMP hardware read within the last
    12 hours: SNMP is the component source of a host it works on, SSH of
    a host it does not (``hardware_components.collect_over_ssh``).
    """
    host = await require_host(request, host_id, write=True)
    cred = await require_credential_access(body.credential_id, session=_get_session(request))

    driver = get_driver(host.get("device_type"))
    if isinstance(driver, GenericDriver):
        raise HTTPException(
            422,
            f"No driver registered for device_type={host.get('device_type')!r}; "
            "cannot fetch serial number for this vendor.",
        )

    try:
        output = await _run_show_command(host, cred, driver.serial_number_show_command())
    except Exception:
        LOGGER.warning("fetch-serial SSH failed for host_id=%s ip=%s", host_id, host.get("ip_address"))
        raise HTTPException(502, "Could not connect to device")

    serial = driver.parse_serial_number(output) or ""

    if not serial:
        raise HTTPException(422, "Serial number not found in command output")

    await db.update_host_serial(host_id, serial)
    # Every hardware component with a serial too, when the driver has
    # ``show inventory`` (Cisco); 0 otherwise or when it fails.
    components = await collect_over_ssh(host, lambda command: _run_show_command(host, cred, command))
    session = _get_session(request)
    await _audit(
        "inventory",
        "host.serial_fetched",
        user=session["user"] if session else "",
        detail=f"host_id={host_id} serial={serial} components={components}",
        correlation_id=_corr_id(request),
    )
    return {"host_id": host_id, "serial_number": serial, "components": components}


@router.post("/api/groups/{group_id}/fetch-serials")
@scoped("group")
async def bulk_fetch_group_serials(group_id: int, body: FetchSerialRequest, request: Request):
    """Fetch serial numbers for all hosts in a group concurrently (max 5 SSH at a time).

    Each result row carries ``components``: the hardware components stored
    from ``show inventory`` (Cisco), 0 for another driver, a failure, or a
    host with a recent complete SNMP hardware read (SNMP is its source)."""
    await require_group(request, group_id, write=True)
    cred = await require_credential_access(body.credential_id, session=_get_session(request))
    hosts = await db.get_hosts_for_group(group_id)
    if not hosts:
        return {"results": []}

    sem = state.device_op_semaphore()

    async def _fetch_one(host: dict) -> dict:
        async with sem:
            # Per-host driver lookup keeps the bulk-fetch generic across
            # mixed-vendor groups - an IOS host and an NX-OS host in the
            # same group both work, with each getting its own show command
            # and parser.  Unknown vendors are surfaced as a per-row error
            # rather than aborting the whole batch.
            driver = get_driver(host.get("device_type"))
            if isinstance(driver, GenericDriver):
                return {
                    "host_id": host["id"],
                    "hostname": host["hostname"],
                    "error": f"No driver for device_type={host.get('device_type')!r}",
                    "ok": False,
                    "components": 0,
                }
            try:
                output = await _run_show_command(host, cred, driver.serial_number_show_command())
                serial = driver.parse_serial_number(output) or ""
                if serial:
                    await db.update_host_serial(host["id"], serial)
                    components = await collect_over_ssh(host, lambda command: _run_show_command(host, cred, command))
                    return {
                        "host_id": host["id"],
                        "hostname": host["hostname"],
                        "serial_number": serial,
                        "ok": True,
                        "components": components,
                    }
                return {
                    "host_id": host["id"],
                    "hostname": host["hostname"],
                    "error": "Not found in output",
                    "ok": False,
                    "components": 0,
                }
            except Exception:
                LOGGER.warning(
                    "bulk-fetch-serial SSH failed for host_id=%s ip=%s",
                    host["id"],
                    host.get("ip_address"),
                )
                return {
                    "host_id": host["id"],
                    "hostname": host["hostname"],
                    "error": "Connection failed",
                    "ok": False,
                    "components": 0,
                }

    results = list(await asyncio.gather(*[_fetch_one(h) for h in hosts]))
    session = _get_session(request)
    ok_count = sum(1 for r in results if r.get("ok"))
    await _audit(
        "inventory",
        "host.serial_bulk_fetched",
        user=session["user"] if session else "",
        detail=f"group_id={group_id} total={len(hosts)} ok={ok_count}",
        correlation_id=_corr_id(request),
    )
    return {"results": results}


@router.post("/api/hosts/bulk-delete")
@scoped("hosts")
async def bulk_delete_hosts(body: dict, request: Request):
    host_ids = body.get("host_ids", [])
    if not host_ids or not isinstance(host_ids, list):
        raise HTTPException(400, "host_ids must be a non-empty list")
    host_ids = [int(h) for h in host_ids]
    # Every host must be writable for a scoped caller (else nothing is deleted).
    await require_hosts(request, host_ids, write=True)
    deleted = await db.bulk_delete_hosts(host_ids)
    # Refresh the flow collector cache once for the whole batch; specific
    # exporter rows are unlinked by the ON DELETE SET NULL FK so we just
    # need the in-memory map to drop the deleted IPs.
    await _notify_flow_collector_host_changed()
    return {"deleted": deleted}


@router.post("/api/hosts/move")
@scoped("hosts")
async def move_hosts(body: dict, request: Request):
    host_ids = body.get("host_ids", [])
    target_group_id = body.get("target_group_id")
    if not host_ids or not isinstance(host_ids, list):
        raise HTTPException(400, "host_ids must be a non-empty list")
    if not target_group_id:
        raise HTTPException(400, "target_group_id is required")
    target_group_id = int(target_group_id)
    scope = await request_scope(request)
    group = await db.get_group(target_group_id)
    if not group or not scope.can_read_group(target_group_id):
        raise HTTPException(404, "Target group not found")
    if not scope.can_write_group(target_group_id):
        raise HTTPException(403, READ_ONLY_DETAIL)
    host_ids = [int(h) for h in host_ids]
    # Moving needs write on every host's group too.
    await require_hosts(request, host_ids, write=True)
    moved = await db.move_hosts(host_ids, target_group_id)
    return {"moved": moved}


@router.post("/api/hosts/snmp-profile")
@scoped("hosts")
async def set_hosts_snmp_profile(body: HostSnmpProfileAssign, request: Request):
    """Give many hosts their own SNMP profile (``""``: inherit the group's).
    ``updated`` is the number of hosts written; unknown ids are skipped."""
    if not body.host_ids:
        raise HTTPException(400, "host_ids must be a non-empty list")
    profile_id = _check_snmp_profile_id(body.snmp_profile_id) or ""
    host_ids = list(dict.fromkeys(body.host_ids))
    await require_hosts(request, host_ids, write=True)
    updated = await db.set_hosts_snmp_profile(host_ids, profile_id)
    return {"ok": True, "updated": updated}


# ── Discovery routes ─────────────────────────────────────────────────────────


@router.get("/api/inventory/discovery/ssh-defaults")
@scope_exempt("which service credential discovery uses: no host or inventory group data")
async def discovery_ssh_defaults():
    """The credential discovery reads ``show version`` with by default: the
    Plexus service credential, when one is set."""
    service = await service_credential()
    return {
        "service_credential": service is not None,
        "service_credential_id": int(service["id"]) if service else None,
        "service_credential_name": str(service.get("name") or "") if service else None,
    }


@router.get("/api/inventory/{group_id}/discovery/ssh-defaults")
@scoped("group")
async def group_discovery_ssh_defaults(group_id: int, request: Request):
    """The service defaults plus ``group_credential_id``: the credential the
    group's discovery remembers (null: none, or deleted since)."""
    group = await require_group(request, group_id)
    remembered = group.get("discovery_credential_id")
    if remembered is not None and not await db.get_credential_raw(int(remembered), resolve_external=False):
        remembered = None
    return {**await discovery_ssh_defaults(), "group_credential_id": remembered}


@router.delete("/api/inventory/{group_id}/discovery/credential")
@scoped("group")
async def forget_group_discovery_credential(group_id: int, request: Request):
    """Forget the group's remembered discovery credential: scans and syncs
    with no credential go back to the Plexus service credential."""
    group = await require_group(request, group_id, write=True)
    await _remember_group_credential(group, None, _get_session(request), _corr_id(request))
    return {"ok": True, "group_credential_id": None}


@router.post("/api/inventory/{group_id}/discovery/scan", status_code=202)
@scoped("group")
async def discovery_scan(group_id: int, body: DiscoveryScanRequest, request: Request):
    """Launch a discovery scan as a background job.

    A full-CIDR probe (up to 4096 hosts) can run for minutes; running it
    inline held the HTTP request open the whole time. The scan now runs as a
    background task - poll GET /api/inventory/discovery/jobs/{job_id} for
    progress and the result (same payload shape the inline response had).
    The SSE variant at .../discovery/scan/stream is unchanged.
    """
    group = await require_group(request, group_id, write=True)
    with DISCOVERY_RUNS.claim(request) as slot:
        try:
            targets = _expand_scan_targets(body.cidrs, body.max_hosts)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        credential, ssh_base = await _resolve_discovery_ssh(
            body, _get_session(request), group=group, correlation_id=_corr_id(request), request=request, targets=targets
        )
        snmp_withheld, snmp_summary = await _snmp_withheld_targets(request, body, targets)

        job = background_jobs.create_job(
            "discovery-scan",
            {"group_id": group_id, "scanned": 0, "total": len(targets), "found": 0},
        )
        task = asyncio.create_task(
            _run_discovery_scan_job(
                job["job_id"],
                group_id,
                body,
                targets,
                credential=credential,
                ssh_base=ssh_base,
                snmp_withheld=snmp_withheld,
                snmp_summary=snmp_summary,
            )
        )
        # The caller's discovery slot is held until the job ends.
        slot.release_when_done(task)
        supervise_task(task, "discovery-scan")
    return {"job_id": job["job_id"], "status": "running", "group_id": group_id, "total_targets": len(targets)}


async def _run_discovery_scan_job(
    job_id: str,
    group_id: int,
    body: DiscoveryScanRequest,
    targets: list[str],
    *,
    credential: dict | None = None,
    ssh_base: dict | None = None,
    snmp_withheld: frozenset[str] = frozenset(),
    snmp_summary: dict | None = None,
) -> None:
    """Background task: probe every target, tracking progress on the job.
    ``snmp_withheld`` / ``snmp_summary``: from ``_snmp_withheld_targets``,
    worked out by the route for its caller."""
    semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
    snmp_cfg = state._resolve_snmp_discovery_config(group_id)

    try:
        discovered: list[dict] = []
        scanned = 0
        # fan_out cancels the probes still pending when this fails or the
        # job task is cancelled (shutdown).
        async with fan_out(
            _scan_target(ip, body, snmp_cfg, semaphore, credential, snmp_withheld=snmp_withheld) for ip in targets
        ) as finished:
            for coro in finished:
                result = await coro
                scanned += 1
                if result is not None:
                    discovered.append(result)
                background_jobs.update_progress(job_id, scanned=scanned, found=len(discovered))
        discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
        background_jobs.finish_job(
            job_id,
            "completed",
            result={
                "group_id": group_id,
                "scanned_hosts": len(targets),
                "discovered_count": len(discovered),
                "discovered_hosts": discovered,
                "ssh_enrichment": _ssh_enrichment_summary(ssh_base or {}, discovered),
                "snmp_withheld": snmp_summary or {"count": 0, "reason": ""},
            },
        )
    except Exception as exc:
        LOGGER.exception("inventory: discovery scan job %s failed", job_id)
        background_jobs.finish_job(job_id, "failed", error=str(exc))


def _job_group_id(job: dict) -> int | None:
    """The inventory group a discovery-scan job scans for."""
    group_id = (job.get("progress") or {}).get("group_id")
    return int(group_id) if group_id is not None else None


@router.get("/api/inventory/discovery/jobs/{job_id}")
@scoped("job")
async def get_discovery_scan_job(job_id: str, request: Request = None):
    """Poll a discovery-scan job launched by POST .../discovery/scan."""
    job = background_jobs.get_job(job_id, kind="discovery-scan")
    # A job of a group the caller may not read answers like an unknown one.
    if job is None or not (await request_scope(request)).can_read_group(_job_group_id(job)):
        raise HTTPException(404, "Discovery job not found (it may have expired)")
    return job


@router.post("/api/inventory/{group_id}/discovery/scan/stream")
@scoped("group")
async def discovery_scan_stream(group_id: int, body: DiscoveryScanRequest, request: Request):
    """SSE streaming scan -- yields per-host results as they complete."""
    group = await require_group(request, group_id, write=True)
    # Held until the stream ends (released at once if this handler fails).
    with DISCOVERY_RUNS.claim(request) as slot:
        try:
            targets = _expand_scan_targets(body.cidrs, body.max_hosts)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        total = len(targets)
        semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
        snmp_cfg = state._resolve_snmp_discovery_config(group_id)
        credential, ssh_base = await _resolve_discovery_ssh(
            body, _get_session(request), group=group, correlation_id=_corr_id(request), request=request, targets=targets
        )
        snmp_withheld, snmp_summary = await _snmp_withheld_targets(request, body, targets)

        async def _scan_one(ip_address: str) -> tuple[str, dict | None]:
            return ip_address, await _scan_target(
                ip_address, body, snmp_cfg, semaphore, credential, snmp_withheld=snmp_withheld
            )

        async def event_generator():
            # Send initial metadata
            start = {"type": "start", "total": total, "ssh_enrichment": ssh_base, "snmp_withheld": snmp_summary}
            yield f"data: {json.dumps(start)}\n\n"

            scanned = 0
            discovered = []
            # A client that goes away cancels the probes still pending.
            async with fan_out(_scan_one(ip) for ip in targets) as finished:
                for coro in finished:
                    ip_address, result = await coro
                    scanned += 1
                    if result is not None:
                        discovered.append(result)
                    yield f"data: {json.dumps({'type': 'progress', 'scanned': scanned, 'total': total, 'ip': ip_address, 'found': result is not None, 'host': result})}\n\n"

            discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))
            done = {
                "type": "done",
                "scanned_hosts": total,
                "discovered_count": len(discovered),
                "discovered_hosts": discovered,
                "ssh_enrichment": _ssh_enrichment_summary(ssh_base, discovered),
                "snmp_withheld": snmp_summary,
            }
            yield f"data: {json.dumps(done)}\n\n"

        return slot.stream(event_generator())


@router.get("/api/inventory/{group_id}/snmp-discovery-profile")
@scoped("group")
async def get_group_snmp_discovery_profile(group_id: int, request: Request):
    await require_group(request, group_id)
    profile = state.SNMP_DISCOVERY_PROFILES.get(group_id) or state._sanitize_snmp_discovery_profile(group_id, {})
    # Secrets are write-only: masked here, kept on a write that sends the mask.
    return mask_secret_fields(profile, SNMP_SECRET_FIELDS)


async def _require_usable_snmp_secrets(request: Request, stored: dict | None, profile: dict) -> None:
    """A group's SNMP secrets are resolved with no user when the group is
    polled or scanned, so a ``{{secret.NAME}}`` the saving user writes into
    one must name a secret variable they may use (403 otherwise). A secret
    kept as stored (sent as the mask, or unchanged) is not checked again."""
    from routes.secret_resolver import require_usable_secret_references

    from netcontrol.secret_fields import destination_changes, map_secret_paths

    changed = list(SNMP_SECRET_FIELDS) if stored is None else destination_changes(stored, profile, SNMP_SECRET_FIELDS)
    texts: list[str] = []

    def _collect(value: object) -> object:
        texts.append(str(value or ""))
        return value

    map_secret_paths(profile, changed, _collect)
    await require_usable_secret_references(request, texts)


@router.put("/api/inventory/{group_id}/snmp-discovery-profile")
@scoped("group")
async def update_group_snmp_discovery_profile(group_id: int, body: dict, request: Request):
    await require_group(request, group_id, write=True)
    # A secret sent as the mask, or left out, keeps the stored one.
    body = merge_secret_fields(body, state.SNMP_DISCOVERY_PROFILES.get(group_id), SNMP_SECRET_FIELDS)
    profile = _sanitized_snmp(state._sanitize_snmp_discovery_profile, group_id, body)
    await _require_usable_snmp_secrets(request, state.SNMP_DISCOVERY_PROFILES.get(group_id), profile)
    state.SNMP_DISCOVERY_PROFILES[group_id] = profile
    await db.set_auth_setting("snmp_discovery_profiles", state.SNMP_DISCOVERY_PROFILES)
    return mask_secret_fields(profile, SNMP_SECRET_FIELDS)


@router.post("/api/inventory/{group_id}/snmp-discovery-profile/test")
@scoped("group")
async def test_group_snmp_profile(group_id: int, body: dict, request: Request):
    # Uses the group's SNMP credentials against an address: a write.
    await require_group(request, group_id, write=True)
    target_ip = str(body.get("target_ip", "")).strip()
    if not target_ip:
        raise HTTPException(400, "target_ip is required")
    # The group's community or v3 keys go to target_ip, so a non-admin may
    # only test a host of this group they may change; any address is admin-only.
    if not await caller_is_admin(request):
        writable = await readable_host_ids(request, write=True)
        if not any(
            same_address(h.get("ip_address"), target_ip)
            and (writable is None or int(h["id"]) in writable)
            and host_address_confirmed(h)
            for h in await db.get_hosts_for_group(group_id)
        ):
            raise HTTPException(
                403,
                "The SNMP test can only target a host of this group; an admin can test any address",
            )
    snmp_config = state._resolve_snmp_discovery_config(group_id)
    if not snmp_config.get("enabled"):
        raise HTTPException(400, "SNMP is not enabled for this group")
    return await _snmp_test(target_ip, snmp_config)


@router.post("/api/hosts/{host_id}/snmp-profile/test")
@scoped("host")
async def test_host_snmp_profile(host_id: int, request: Request):
    """SNMP GET against the host's address with its effective SNMP config
    (its own profile, else its group's)."""
    # Sends the SNMP credentials to the device: a write, like the group test.
    host = await require_host(request, host_id, write=True)
    target_ip = str(host.get("ip_address") or "").strip()
    if not target_ip:
        raise HTTPException(400, "Host has no IP address")
    # The SNMP config is shared: only to a confirmed address, unless an admin asks.
    if not host_address_confirmed(host) and not await caller_is_admin(request):
        raise HTTPException(403, f"The SNMP test cannot run: the host's {ADDRESS_AWAITING_CONFIRMATION}")
    snmp_config = state._resolve_host_snmp_config(host)
    if not snmp_config.get("enabled"):
        raise HTTPException(400, "SNMP is not enabled for this host (its own profile or its group's)")
    return await _snmp_test(target_ip, snmp_config)


async def _snmp_test(target_ip: str, snmp_config: dict) -> dict:
    """One SNMP GET of ``target_ip`` with ``snmp_config``: the SNMP test
    response of the group and host routes."""
    timeout = float(snmp_config.get("timeout_seconds", 1.2))
    try:
        result = await _snmp_get(target_ip, timeout, snmp_config)
    except Exception as exc:
        LOGGER.warning("SNMP test failed for %s: %s", target_ip, exc)
        return {
            "success": False,
            "target_ip": target_ip,
            "error": "SNMP query failed - check credentials and connectivity.",
        }
    if result is None:
        return {
            "success": False,
            "target_ip": target_ip,
            "error": "SNMP query failed -- no response or bad credentials",
        }
    return {"success": True, "target_ip": target_ip, "result": result}


@router.post("/api/inventory/{group_id}/discovery/sync")
@scoped("group")
async def discovery_sync(group_id: int, body: DiscoverySyncRequest, request: Request):
    group = await require_group(request, group_id, write=True)

    # If no CIDRs provided, auto-populate from the group's existing host IPs
    if not body.cidrs:
        existing_hosts = await db.get_hosts_for_group(group_id)
        host_ips = [str(h["ip_address"]) for h in existing_hosts if h.get("ip_address")]
        if not host_ips:
            raise HTTPException(400, "Group has no hosts to sync. Add hosts first or provide CIDR targets.")
        body.cidrs = host_ips

    with DISCOVERY_RUNS.claim(request):
        try:
            targets = _expand_scan_targets(body.cidrs, body.max_hosts)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        session = _get_session(request)
        credential, ssh_base = await _resolve_discovery_ssh(
            body, session, group=group, correlation_id=_corr_id(request), request=request, targets=targets
        )
        snmp_withheld, snmp_summary = await _snmp_withheld_targets(request, body, targets)
        scanned_count, discovered = await _discover_hosts(
            body, group_id=group_id, credential=credential, snmp_withheld=snmp_withheld
        )
    sync_result = await _sync_group_hosts(
        group_id,
        discovered,
        remove_absent=body.remove_absent,
        address_confirmed=await caller_confirms_addresses(request),
        address_set_by=await address_writer_id(request),
    )
    await _software_changed()
    audit_user = session["user"] if session else API_TOKEN_USER

    await _audit(
        "inventory",
        "discovery.sync",
        user=audit_user,
        detail=(
            f"group_id={group_id} scanned={scanned_count} discovered={len(discovered)} "
            f"added={sync_result['added']} updated={sync_result['updated']} removed={sync_result['removed']}"
        ),
        correlation_id=_corr_id(request),
    )

    return {
        "group_id": group_id,
        "scanned_hosts": scanned_count,
        "discovered_count": len(discovered),
        "sync": sync_result,
        "ssh_enrichment": _ssh_enrichment_summary(ssh_base, discovered),
        "snmp_withheld": snmp_summary,
    }


@router.post("/api/inventory/{group_id}/discovery/sync/stream")
@scoped("group")
async def discovery_sync_stream(group_id: int, body: DiscoverySyncRequest, request: Request):
    """SSE streaming sync -- yields per-host probe progress, then a final
    'done' event carrying the add/update/remove counts. Mirrors
    discovery_scan_stream so the frontend can reuse its progress UI."""
    group = await require_group(request, group_id, write=True)

    # If no CIDRs provided, auto-populate from the group's existing host IPs
    # (same behaviour as the non-streaming /discovery/sync endpoint).
    if not body.cidrs:
        existing_hosts = await db.get_hosts_for_group(group_id)
        host_ips = [str(h["ip_address"]) for h in existing_hosts if h.get("ip_address")]
        if not host_ips:
            raise HTTPException(400, "Group has no hosts to sync. Add hosts first or provide CIDR targets.")
        body.cidrs = host_ips

    # Held until the stream ends (released at once if this handler fails).
    with DISCOVERY_RUNS.claim(request) as slot:
        try:
            targets = _expand_scan_targets(body.cidrs, body.max_hosts)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        total = len(targets)
        semaphore = asyncio.Semaphore(max(1, state.DISCOVERY_MAX_CONCURRENT_PROBES))
        snmp_cfg = state._resolve_snmp_discovery_config(group_id)
        session = _get_session(request)
        credential, ssh_base = await _resolve_discovery_ssh(
            body, session, group=group, correlation_id=_corr_id(request), request=request, targets=targets
        )
        snmp_withheld, snmp_summary = await _snmp_withheld_targets(request, body, targets)
        # Decided here, where the request is at hand, not in the generator.
        confirms = await caller_confirms_addresses(request)
        writer = await address_writer_id(request)

        async def _scan_one(ip_address: str) -> tuple[str, dict | None]:
            return ip_address, await _scan_target(
                ip_address, body, snmp_cfg, semaphore, credential, snmp_withheld=snmp_withheld
            )

        audit_user = session["user"] if session else API_TOKEN_USER
        corr_id = _corr_id(request)

        async def event_generator():
            start = {"type": "start", "total": total, "ssh_enrichment": ssh_base, "snmp_withheld": snmp_summary}
            yield f"data: {json.dumps(start)}\n\n"

            scanned = 0
            discovered = []
            # A client that goes away cancels the probes still pending.
            async with fan_out(_scan_one(ip) for ip in targets) as finished:
                for coro in finished:
                    ip_address, result = await coro
                    scanned += 1
                    if result is not None:
                        discovered.append(result)
                    yield f"data: {json.dumps({'type': 'progress', 'scanned': scanned, 'total': total, 'ip': ip_address, 'found': result is not None, 'host': result})}\n\n"

            discovered.sort(key=lambda item: ipaddress.ip_address(item["ip_address"]))

            # Persisting phase: probing is done, now reconcile with the DB.
            yield f"data: {json.dumps({'type': 'syncing', 'discovered_count': len(discovered)})}\n\n"
            sync_result = await _sync_group_hosts(
                group_id,
                discovered,
                remove_absent=body.remove_absent,
                address_confirmed=confirms,
                address_set_by=writer,
            )
            await _software_changed()

            await _audit(
                "inventory",
                "discovery.sync",
                user=audit_user,
                detail=(
                    f"group_id={group_id} scanned={total} discovered={len(discovered)} "
                    f"added={sync_result['added']} updated={sync_result['updated']} removed={sync_result['removed']}"
                ),
                correlation_id=corr_id,
            )

            done = {
                "type": "done",
                "scanned_hosts": total,
                "discovered_count": len(discovered),
                "sync": sync_result,
                "ssh_enrichment": _ssh_enrichment_summary(ssh_base, discovered),
                "snmp_withheld": snmp_summary,
            }
            yield f"data: {json.dumps(done)}\n\n"

        return slot.stream(event_generator())


@router.post("/api/inventory/{group_id}/discovery/onboard")
@scoped("group")
async def discovery_onboard(group_id: int, body: DiscoveryOnboardRequest, request: Request):
    await require_group(request, group_id, write=True)
    if not body.discovered_hosts:
        raise HTTPException(400, "No discovered hosts provided")

    sync_result = await _sync_group_hosts(
        group_id,
        body.discovered_hosts,
        remove_absent=False,
        address_confirmed=await caller_confirms_addresses(request),
        address_set_by=await address_writer_id(request),
    )
    await _software_changed()
    session = _get_session(request)
    audit_user = session["user"] if session else API_TOKEN_USER
    await _audit(
        "inventory",
        "discovery.onboard",
        user=audit_user,
        detail=(
            f"group_id={group_id} provided={len(body.discovered_hosts)} "
            f"added={sync_result['added']} updated={sync_result['updated']}"
        ),
        correlation_id=_corr_id(request),
    )
    return {
        "group_id": group_id,
        "provided_count": len(body.discovered_hosts),
        "sync": sync_result,
    }
