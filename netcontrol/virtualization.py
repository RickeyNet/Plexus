"""Virtualization rules: value validation for clusters, virtual machines and
VM interfaces, and the mapping of discovered cloud compute instances to
virtual machines.

Storage lives in ``routes.db.virtualization``, the API and the cloud sync in
``netcontrol.routes.virtualization``. See ``docs/virtualization.md``.

Validators raise ``CustomFieldError`` with a message for the person (the
routes answer it as a 422 naming the field).

Cloud mapping (``vm_from_resource``) is pure: it reads one ``cloud_resources``
row (with its decoded ``metadata``) and the CIDRs of the account's subnets
and returns the VM values, its interfaces and their addresses. Which
resource types are compute instances is ``COMPUTE_RESOURCE_TYPES``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from netcontrol.custom_fields import CustomFieldError, clean_name, clean_text
from netcontrol.integrations.meraki.clients import normalize_mac

NAME_MAX = 100
DESCRIPTION_MAX = 500
COMMENTS_MAX = 5000
PLATFORM_MAX = 100
INTERFACE_NAME_MAX = 64
MTU_MIN = 68
MTU_MAX = 65536
# Upper bounds that catch typos (a memory size in bytes, not MB).
VCPUS_MAX = 4096
MEMORY_MB_MAX = 64 * 1024 * 1024
DISK_GB_MAX = 1024 * 1024
ADDRESSES_MAX = 64

VM_STATUSES: tuple[str, ...] = ("active", "offline", "planned", "staged", "failed", "decommissioning")
INTERFACE_MODES: tuple[str, ...] = ("", "access", "tagged")
ORIGINS: tuple[str, ...] = ("manual", "discovered")

# ``aa:bb:cc:dd:ee:ff``, ``aa-bb-cc-dd-ee-ff``, ``aabb.ccdd.eeff`` or 12 bare hex digits.
_MAC = re.compile(
    r"^(?:[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12})$",
    re.IGNORECASE,
)


# ── Validation ───────────────────────────────────────────────────────────────


def clean_object_name(raw: object, label: str = "Name") -> str:
    """A cluster, type, group or VM name: trimmed, 1 to ``NAME_MAX``."""
    return clean_name(raw, label, NAME_MAX)


def clean_interface_name(raw: object) -> str:
    """A VM interface name: trimmed, 1 to ``INTERFACE_NAME_MAX``."""
    return clean_name(raw, "Name", INTERFACE_NAME_MAX)


def clean_description(raw: object) -> str:
    return clean_text(raw, "Description", DESCRIPTION_MAX)


def clean_comments(raw: object) -> str:
    return clean_text(raw, "Comments", COMMENTS_MAX)


def clean_platform(raw: object) -> str:
    return clean_text(raw, "Platform", PLATFORM_MAX)


def clean_status(raw: object) -> str:
    status = raw.strip().lower() if isinstance(raw, str) else ""
    if status not in VM_STATUSES:
        raise CustomFieldError(f"Status must be one of {', '.join(VM_STATUSES)}.")
    return status


def clean_count(raw: object, label: str, limit: int) -> int | None:
    """An optional whole number from 0 to ``limit`` (``None``: unset)."""
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= limit:
        raise CustomFieldError(f"{label} must be a whole number from 0 to {limit}.")
    return raw


def clean_mac(raw: object) -> str:
    """A MAC address in canonical ``aa:bb:cc:dd:ee:ff`` form, or ``''``."""
    text = raw.strip() if isinstance(raw, str) else ""
    if not text:
        return ""
    if not _MAC.match(text):
        raise CustomFieldError("MAC address must look like aa:bb:cc:dd:ee:ff.")
    return normalize_mac(text)


def clean_mtu(raw: object) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or not MTU_MIN <= raw <= MTU_MAX:
        raise CustomFieldError(f"MTU must be a whole number from {MTU_MIN} to {MTU_MAX}.")
    return raw


def clean_mode(raw: object) -> str:
    mode = raw.strip().lower() if isinstance(raw, str) else ""
    if mode not in INTERFACE_MODES:
        raise CustomFieldError("Mode must be access, tagged or empty.")
    return mode


def clean_primary_ip(raw: object, version: int) -> str:
    """An IPv4 (``version`` 4) or IPv6 address without a prefix length,
    canonical form, or ``''``."""
    text = raw.strip() if isinstance(raw, str) else ""
    if not text:
        return ""
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise CustomFieldError(f"Primary IPv{version} must be an IPv{version} address.") from exc
    if address.version != version:
        raise CustomFieldError(f"Primary IPv{version} must be an IPv{version} address.")
    return str(address)


def clean_interface_address(raw: object) -> str:
    """An interface address in CIDR form (``192.0.2.10/24``), canonical.
    A bare address gets the host length (/32 or /128)."""
    text = raw.strip() if isinstance(raw, str) else ""
    if not text:
        raise CustomFieldError("Address must not be empty.")
    try:
        interface = ipaddress.ip_interface(text)
    except ValueError as exc:
        raise CustomFieldError(f"'{text}' is not an IP address in CIDR form (192.0.2.10/24).") from exc
    return interface.with_prefixlen


def clean_interface_addresses(raw: object) -> list[str]:
    """A list of distinct CIDR addresses, in the given order."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise CustomFieldError("Addresses must be a list.")
    if len(raw) > ADDRESSES_MAX:
        raise CustomFieldError(f"An interface carries at most {ADDRESSES_MAX} addresses.")
    out: list[str] = []
    for item in raw:
        address = clean_interface_address(item)
        if address in out:
            raise CustomFieldError(f"Address {address} is listed twice.")
        out.append(address)
    return out


# ── Cloud compute instances ──────────────────────────────────────────────────

# The ``cloud_resources.resource_type`` of a compute instance, per provider.
COMPUTE_RESOURCE_TYPES: dict[str, tuple[str, ...]] = {
    "aws": ("instance",),
    "azure": ("vm",),
    "gcp": ("instance",),
}
# The cluster type the sync files each provider's clusters under.
CLOUD_CLUSTER_TYPES: dict[str, str] = {"aws": "AWS EC2", "azure": "Azure", "gcp": "GCP"}
CLOUD_PROVIDER_LABELS: dict[str, str] = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}

# Provider instance states (lower case) and the VM status they mean. Azure's
# Network API answers no power state, so its VMs are stored with an empty
# status: a VM the discovery found counts as active.
_STATUS_MAP: dict[str, str] = {
    "": "active",
    "running": "active",
    "succeeded": "active",
    "pending": "staged",
    "starting": "staged",
    "provisioning": "staged",
    "staging": "staged",
    "creating": "staged",
    "stopping": "offline",
    "stopped": "offline",
    "shutting-down": "offline",
    "terminated": "offline",
    "suspending": "offline",
    "suspended": "offline",
    "deallocated": "offline",
    "deallocating": "offline",
    "repairing": "offline",
    "failed": "failed",
    "deleting": "decommissioning",
}


def cloud_status(raw: object) -> str:
    """The VM status of a provider's instance state; unknown states count as
    active (the discovery found the instance)."""
    return _STATUS_MAP.get(str(raw or "").strip().lower(), "active")


def cloud_cluster_key(provider: str, account_id: int, region: str) -> str:
    return f"{provider}:{int(account_id)}:{region or 'global'}"


def cloud_cluster_name(provider: str, account_name: str, region: str) -> str:
    label = CLOUD_PROVIDER_LABELS.get(provider, provider.upper())
    return clean_text(f"{label} {account_name.strip()} {region or 'global'}".strip(), "Name", NAME_MAX)[:NAME_MAX]


def subnet_cidrs(provider: str, resources: list[dict]) -> dict[str, str]:
    """The CIDR of each subnet resource, by the id an instance interface names
    it with (the resource uid without ``<provider>:subnet:``, and the
    ``subnet_id`` the metadata holds)."""
    out: dict[str, str] = {}
    prefix = f"{provider}:subnet:"
    for resource in resources:
        if resource.get("resource_type") != "subnet" or not resource.get("cidr"):
            continue
        cidr = str(resource["cidr"]).split(",")[0].strip()
        uid = str(resource.get("resource_uid") or "")
        if uid.startswith(prefix):
            out[uid[len(prefix) :]] = cidr
        meta = resource.get("metadata") or {}
        if isinstance(meta, dict) and meta.get("subnet_id"):
            out[str(meta["subnet_id"])] = cidr
    return out


def _with_length(ip: str, cidr: str) -> str | None:
    """``ip`` as an interface address with the subnet's prefix length when it
    lies in ``cidr``, else the host length; ``None`` when it is not an IP."""
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    try:
        network = ipaddress.ip_network(cidr, strict=False) if cidr else None
    except ValueError:
        network = None
    if network is not None and network.version == address.version and address in network:
        return f"{address}/{network.prefixlen}"
    return f"{address}/{address.max_prefixlen}"


def _interface_name(provider: str, raw: dict, index: int) -> str:
    if provider == "aws":
        name = raw.get("id") or f"eth{raw.get('device_index', index)}"
    else:
        name = raw.get("name") or raw.get("id") or f"nic{index}"
    return str(name).strip()[:INTERFACE_NAME_MAX] or f"nic{index}"


def _interfaces(provider: str, meta: dict, subnets: dict[str, str]) -> list[dict]:
    out: list[dict] = []
    names: set[str] = set()
    for index, raw in enumerate(meta.get("interfaces") or []):
        if not isinstance(raw, dict):
            continue
        name = _interface_name(provider, raw, index)
        if name.lower() in names:
            continue
        names.add(name.lower())
        cidr = subnets.get(str(raw.get("subnet_id") or ""), "")
        addresses: list[str] = []
        for ip in [*(raw.get("private_ips") or []), *(raw.get("public_ips") or [])]:
            # Public addresses are NAT'ed to the instance: host length.
            address = _with_length(ip, cidr if ip in (raw.get("private_ips") or []) else "")
            if address and address not in addresses and len(addresses) < ADDRESSES_MAX:
                addresses.append(address)
        mac = raw.get("mac") or ""
        try:
            mac = clean_mac(mac)
        except CustomFieldError:
            mac = ""
        description = str(raw.get("description") or "").strip()[:DESCRIPTION_MAX]
        out.append({"name": name, "mac_address": mac, "description": description, "addresses": addresses})
    return out


def _description(provider: str, meta: dict) -> str:
    """A line saying what the instance is: its size and where it runs."""
    if provider == "aws":
        kind, where = meta.get("instance_type"), meta.get("availability_zone")
        text = f"EC2 {kind}" if kind else "EC2 instance"
    elif provider == "gcp":
        kind, where = meta.get("machine_type"), meta.get("zone")
        text = f"Compute Engine {kind}" if kind else "Compute Engine instance"
    else:
        group = meta.get("resource_group")
        return f"Azure VM in resource group {group}" if group else "Azure VM"
    return f"{text} in {where}" if where else text


def vm_from_resource(provider: str, resource: dict, subnets: dict[str, str]) -> dict:
    """The VM values (``name``, ``status``, ``platform``, ``primary_ip4``,
    ``primary_ip6``, ``description``) and ``interfaces`` (each with its
    ``addresses``) of one discovered compute instance."""
    meta = resource.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}
    uid = str(resource.get("resource_uid") or "")
    name = str(resource.get("name") or "").strip() or uid.rsplit(":", 1)[-1] or uid
    interfaces = _interfaces(provider, meta, subnets)
    ip4 = ip6 = ""
    candidates = [meta.get("private_ip") or ""] + [a.split("/")[0] for i in interfaces for a in i["addresses"]]
    for candidate in candidates:
        try:
            address = ipaddress.ip_address(str(candidate).strip())
        except ValueError:
            continue
        if address.version == 4 and not ip4:
            ip4 = str(address)
        elif address.version == 6 and not ip6:
            ip6 = str(address)
    return {
        "name": name[:NAME_MAX],
        "status": cloud_status(resource.get("status")),
        "platform": str(meta.get("platform") or "").strip()[:PLATFORM_MAX],
        "primary_ip4": ip4,
        "primary_ip6": ip6,
        "description": _description(provider, meta)[:DESCRIPTION_MAX],
        "interfaces": interfaces,
    }


def decoded_metadata(resource: dict) -> dict[str, Any]:
    """A ``cloud_resources`` row with ``metadata`` decoded from ``metadata_json``."""
    out = dict(resource)
    raw = out.get("metadata_json") or "{}"
    try:
        meta = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        meta = {}
    out["metadata"] = meta if isinstance(meta, dict) else {}
    return out
