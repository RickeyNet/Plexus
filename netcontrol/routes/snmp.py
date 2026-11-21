"""
snmp.py -- Shared SNMP infrastructure (no routes).

Provides pysnmp helpers, SNMP get/walk, CDP address parsing,
neighbor discovery, and vendor-OS inference used by inventory
and topology route modules.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from collections.abc import Awaitable, Callable
from typing import Any

from netcontrol.device_categories import device_type_category
from netcontrol.routes.host_identity import interface_ip, placeholder_hostname
from netcontrol.routes.state import _resolve_snmp_discovery_config  # noqa: F401
from netcontrol.telemetry import configure_logging

LOGGER = configure_logging("plexus.snmp")

# ── pysnmp imports (optional dependency) ─────────────────────────────────────

try:
    from pysnmp.hlapi.v3arch import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        bulk_walk_cmd,
        get_cmd,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
        usmDESPrivProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        walk_cmd,
    )
    from pysnmp.proto import errind

    # The error text of a request the device never answered.
    SNMP_TIMEOUT_ERROR = str(errind.requestTimedOut)
    PYSMNP_AVAILABLE = True
except Exception:
    CommunityData = None
    ContextData = None
    ObjectIdentity = None
    ObjectType = None
    SnmpEngine = None
    UdpTransportTarget = None
    UsmUserData = None
    get_cmd = None
    walk_cmd = None
    bulk_walk_cmd = None
    usmAesCfb128Protocol = None
    usmAesCfb192Protocol = None
    usmAesCfb256Protocol = None
    usmDESPrivProtocol = None
    usmHMACMD5AuthProtocol = None
    usmHMACSHAAuthProtocol = None
    usmHMAC192SHA256AuthProtocol = None
    usmHMAC384SHA512AuthProtocol = None
    SNMP_TIMEOUT_ERROR = "No SNMP response received before timeout"
    PYSMNP_AVAILABLE = False


# ── Helpers ──────────────────────────────────────────────────────────────────


# Model-string patterns → device category.  Order matters: first match wins.
_CATEGORY_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Cisco wireless controllers
    (re.compile(r"C9800|AIR-CT|WLC|C3504", re.I), "wlc"),
    # Cisco wireless APs
    (re.compile(r"AIR-AP|AIR-CAP|C9120|C9130|C9136|C9162|C9164|CW916", re.I), "wireless"),
    # Cisco IP phones
    (re.compile(r"CP-\d|IP\s?Phone|SEP[0-9A-F]", re.I), "phone"),
    # Cisco routers - ISR, ASR, CSR, NCS
    (re.compile(r"ISR\d|ASR\d|CSR1|NCS-|C8[0-9]{3}|CISCO[0-9]{4}", re.I), "router"),
    # Cisco switches - Catalyst 9xxx, 3xxx, 2xxx series
    (re.compile(r"C9[0-9]{3}|C3[0-9]{3}|C2[0-9]{3}|WS-C|C1[01][0-9]{2}F?", re.I), "switch"),
    # Cisco Nexus
    (re.compile(r"N[3579]K|N[0-9]{4}|Nexus", re.I), "switch"),
    # Fortinet - everything is a firewall appliance
    (re.compile(r"forti", re.I), "firewall"),
    # Juniper routers
    (re.compile(r"MX\d|PTX|ACX|SRX[0-9]{4}", re.I), "router"),
    # Juniper switches
    (re.compile(r"EX\d|QFX", re.I), "switch"),
    # Juniper firewalls (SRX3xx, SRX1500 etc.)
    (re.compile(r"SRX[0-9]{2,3}$", re.I), "firewall"),
    # Arista switches
    (re.compile(r"DCS-|CCS-", re.I), "switch"),
    # Palo Alto firewalls
    (re.compile(r"PA-\d", re.I), "firewall"),
    # Generic server patterns
    (re.compile(r"UCS|PowerEdge|ProLiant|server", re.I), "server"),
]


def _infer_device_category(model: str, sys_descr: str, device_type: str) -> str:
    """Infer a device category from model string, sysDescr, or device_type.

    Returns one of ``netcontrol.device_categories.DEVICE_CATEGORIES``, or
    empty string (let the frontend fall back to device_type shape).
    """
    # A type that implies its category (an APC card is a UPS) wins over model text.
    category = device_type_category(device_type)
    if category:
        return category
    # An APC UPS card, known by its sysDescr alone (a CDP / LLDP neighbor's platform).
    if any(_apc_device_type(text) for text in (model, sys_descr) if text):
        return "ups"
    for text in (model, sys_descr):
        for pattern, category in _CATEGORY_PATTERNS:
            if pattern.search(text or ""):
                return category
    # Fallback: Fortinet device_type → firewall
    if device_type == "fortinet":
        return "firewall"
    # Every Aruba platform Plexus detects is a switch.
    if device_type.startswith("aruba_"):
        return "switch"
    if device_type == "netgear_ap":
        return "wireless"
    if device_type.startswith("netgear_"):
        return "switch"
    return ""


# sysDescr of the HPE Aruba switch lines (none names its OS in words Plexus
# could match otherwise). An Instant On switch is told by the words
# "Instant On" alone, whatever surrounds them in a given firmware:
#   Instant On:  "Aruba Instant On 1830 24G 2SFP Switch JL812A, InstantOn_1830_2.9.1.17 (...)"
#   AOS-CX:      "Aruba JL668A FL.10.10.1020"
#   AOS-Switch:  "Aruba JL253A 2930F-24G-4SFP+ Switch, revision WC.16.10.0003, ROM WC.16.01.0006 (...)"
#                "ProCurve J9019B Switch 2510B-24, revision Q.11.57, ROM Q.10.02 (...)"
_INSTANT_ON = re.compile(r"instant\s*on", re.IGNORECASE)
_INSTANT_ON_VERSION = re.compile(r"InstantOn_\w+?_(\d[\d.]*)", re.IGNORECASE)
_AOSCX = re.compile(r"arubaos-cx|aos-cx|\b[A-Z]{2}\.10\.\d{2}\.\d{4}\b")
_AOSCX_VERSION = re.compile(r"\b([A-Z]{2}\.10\.\d{2}\.\d{4}\w*)")
_AOS_SWITCH = re.compile(r"procurve|\brevision\s+[A-Z]{1,2}\.\d+\.\d+.*\bROM\b", re.IGNORECASE)
_AOS_SWITCH_VERSION = re.compile(r"\brevision\s+([A-Z]{1,2}\.\d+\.\d+(?:\.\d+)?\w*)", re.IGNORECASE)
# The HPE product number (JL812A, J9773A) and, on AOS-Switch, the model after it.
_HPE_PRODUCT_NUMBER = re.compile(r"\b(J[A-Z0-9]\d{3,4}[A-Z])\b")
_AOS_SWITCH_MODEL = re.compile(r"\bJ[A-Z0-9]\d{3,4}[A-Z]\s+(?:Switch\s+)?([\w+/-]*\d[\w+/-]*)")


_ARUBA_OS_NAMES = {"aruba_instant_on": "instant-on", "aruba_aoscx": "aos-cx", "aruba_osswitch": "aos-switch"}


def _aruba_device_type(sys_descr: str) -> str:
    """The Aruba device type a sysDescr names, or ``""``."""
    text = sys_descr or ""
    if _INSTANT_ON.search(text):
        return "aruba_instant_on"
    if _AOS_SWITCH.search(text):
        return "aruba_osswitch"
    if _AOSCX.search(text):
        return "aruba_aoscx"
    return ""


# sysDescr of the Netgear lines: the model, the product description, then
# the firmware and the boot code. A recent one names neither "NETGEAR" nor
# "ProSAFE", so a model that opens the text is enough:
#   managed:  "M4300-28G ProSAFE 24-port 1G and 2-port 10GBASE-T and 2-port 10G SFP+, 12.0.17.6, B1.0.0.17"
#             "M4250-10G2F-PoE+ 8x1G PoE+ 125W and 2x1G and 2xSFP Managed Switch, 13.0.4.26, 1.0.0.11"
#   smart:    "GS724Tv4 ProSafe 24-port Gigabit Ethernet Smart Switch, 6.3.1.33, B1.0.0.4"
#   AP:       names its model (WAX620, WAC510), seldom its firmware
_NETGEAR = re.compile(r"netgear|prosafe", re.IGNORECASE)
_NETGEAR_MANAGED_MODEL = re.compile(r"\b(M[4-7]\d{3}(?:-[\w+]+)*|[GX]SM\d{4}\w*)")
_NETGEAR_SMART_MODEL = re.compile(r"\b((?:GS|XS|MS)\d{3,4}T\w*|GC\d{3}\w*)")
# Zyxel names its access points WAX too.
_NETGEAR_AP_MODEL = re.compile(r"\b(W(?:AX|AC|BE|NDAP|NAP)\d{3}\w*)")
_NETGEAR_VERSION = re.compile(r",\s*(\d+\.\d+\.\d+(?:\.\d+)?)\s*(?:,|$)")
_NETGEAR_MODELS = {
    "netgear_ap": _NETGEAR_AP_MODEL,
    "netgear_prosafe": _NETGEAR_MANAGED_MODEL,
    "netgear_smart": _NETGEAR_SMART_MODEL,
}
_NETGEAR_OS_NAMES = {
    "netgear_prosafe": "netgear-managed",
    "netgear_smart": "netgear-smart",
    "netgear_ap": "netgear-ap",
}


def _netgear_device_type(sys_descr: str) -> str:
    """The Netgear device type a sysDescr names, or ``""``. A switch model
    counts when it opens the text or the text names Netgear, so another
    vendor's model with the same letters is not taken for one."""
    text = (sys_descr or "").strip()
    if "zyxel" in text.lower():
        return ""
    named = bool(_NETGEAR.search(text))
    for device_type, pattern in _NETGEAR_MODELS.items():
        match = pattern.search(text)
        if match and (named or match.start() == 0 or device_type == "netgear_ap"):
            return device_type
    if named and "access point" in text.lower():
        return "netgear_ap"
    return ""


# sysDescr of an APC Network Management Card (NMC2 AP9630 / AP9631 / AP9635,
# NMC3 AP9640 / AP9641 / AP9643). It names the card, not the UPS behind it:
#   "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2 PN:apc_hw05_aos_682.bin
#    AF1:v6.8.2 AN1:apc_hw05_sumx_682.bin MN:AP9631 HR:05 SN: ZA0000000001
#    MD:01/01/2015) (Embedded PowerNet SNMP Agent SW v2.2 compatible)"
# PF is the card's operating system (AOS) firmware, AF1 / AN1 the firmware
# and file of its application module, which tells a UPS card (``sumx``,
# ``su``, ``sy``) from a PDU (``rpdu``), transfer switch (``ats``) or
# cooling unit card. The UPS model, firmware and serial are read from
# PowerNet-MIB by the monitoring poll (``netcontrol/integrations/apc/snmp.py``).
_APC_NMC = re.compile(r"APC Web/SNMP Management Card|Embedded PowerNet SNMP Agent", re.IGNORECASE)
_APC_NMC_FIELD = re.compile(r"\b(MB|PF|PN|AF1|AN1|MN|HR|SN|MD):\s*([^\s)]+)")
_APC_NMC_APPLICATION = re.compile(r"^apc_hw[0-9a-z]+_([a-z0-9]+)_", re.IGNORECASE)
_APC_UPS_APPLICATIONS = ("su", "sy", "smx", "ups")
_APC_OS_NAMES = {"apc_ups": "apc-nmc"}
# PowerNet-MIB identity of the UPS behind the card (scalars; ``.0`` is the
# instance). Read by the discovery GET and the monitoring poll.
APC_UPS_MODEL_OID = "1.3.6.1.4.1.318.1.1.1.1.1.1"  # upsBasicIdentModel
APC_UPS_SERIAL_OID = "1.3.6.1.4.1.318.1.1.1.1.2.3"  # upsAdvIdentSerialNumber


def parse_apc_nmc_sys_descr(sys_descr: str) -> dict[str, str]:
    """The card facts of an APC Network Management Card sysDescr (format
    above), ``{}`` for any other text: ``nmc_model`` (MN), ``nmc_firmware``
    (PF, the AOS release without its ``v``), ``nmc_application`` (the
    application module, ``sumx``), ``nmc_application_firmware`` (AF1),
    ``nmc_serial`` (SN) and ``nmc_hardware`` (HR)."""
    text = sys_descr or ""
    if not _APC_NMC.search(text):
        return {}
    fields = {key: value for key, value in _APC_NMC_FIELD.findall(text)}
    application = _APC_NMC_APPLICATION.match(fields.get("AN1", ""))
    return {
        "nmc_model": fields.get("MN", ""),
        "nmc_firmware": fields.get("PF", "").lstrip("vV"),
        "nmc_application": application.group(1).lower() if application else "",
        "nmc_application_firmware": fields.get("AF1", "").lstrip("vV"),
        "nmc_serial": fields.get("SN", ""),
        "nmc_hardware": fields.get("HR", ""),
    }


def _apc_device_type(sys_descr: str) -> str:
    """``apc_ups`` for the card of a UPS, ``""`` for any other text (a PDU
    or transfer switch card is APC too, but not a type Plexus has)."""
    facts = parse_apc_nmc_sys_descr(sys_descr)
    if not facts:
        return ""
    application = facts["nmc_application"]
    if application:
        return "apc_ups" if application.startswith(_APC_UPS_APPLICATIONS) else ""
    return "apc_ups" if re.search(r"\bups\b", sys_descr, re.IGNORECASE) else ""


def _infer_vendor_os_from_text(raw_text: str) -> tuple[str, str, str]:
    lowered = (raw_text or "").lower()
    vendor = "unknown"
    detected_type = "unknown"
    os_name = "unknown"

    if "cisco" in lowered:
        vendor = "cisco"
        # Distinguish IOS-XE from classic IOS - Catalyst 9xxx, 3850,
        # 3650, ISR 1000/4000, ASR 1000, etc. all run IOS-XE.
        # sysDescr variants: "Cisco IOS XE Software", "IOS-XE", "(CAT9K_IOSXE)", etc.
        if "ios-xe" in lowered or "iosxe" in lowered or "ios xe" in lowered:
            detected_type = "cisco_xe"
        elif "nx-os" in lowered or "nxos" in lowered:
            detected_type = "cisco_nxos"
        elif "ios-xr" in lowered or "iosxr" in lowered or "ios xr" in lowered:
            detected_type = "cisco_xr"
        else:
            detected_type = "cisco_ios"
    elif "juniper" in lowered or "junos" in lowered:
        vendor = "juniper"
        detected_type = "juniper_junos"
    elif "arista" in lowered:
        vendor = "arista"
        detected_type = "arista_eos"
    elif "forti" in lowered:
        vendor = "fortinet"
        detected_type = "fortinet"
    elif _aruba_device_type(raw_text or ""):
        vendor = "aruba"
        detected_type = _aruba_device_type(raw_text or "")
    elif _netgear_device_type(raw_text or ""):
        vendor = "netgear"
        detected_type = _netgear_device_type(raw_text or "")
    elif _NETGEAR.search(raw_text or ""):
        # A Netgear device of a line Plexus does not tell: the type stays unknown.
        vendor = "netgear"
    elif _APC_NMC.search(raw_text or ""):
        # An APC card: a UPS is ``apc_ups``; a PDU or transfer switch stays unknown.
        vendor = "apc"
        detected_type = _apc_device_type(raw_text or "") or "unknown"

    if detected_type in _ARUBA_OS_NAMES:
        os_name = _ARUBA_OS_NAMES[detected_type]
    elif detected_type in _NETGEAR_OS_NAMES:
        os_name = _NETGEAR_OS_NAMES[detected_type]
    elif detected_type in _APC_OS_NAMES:
        os_name = _APC_OS_NAMES[detected_type]
    elif "ios-xe" in lowered or "iosxe" in lowered or "ios xe" in lowered:
        os_name = "ios-xe"
    elif "ios-xr" in lowered or "iosxr" in lowered or "ios xr" in lowered:
        os_name = "ios-xr"
    elif "ios" in lowered:
        os_name = "ios"
    elif "nx-os" in lowered or "nxos" in lowered:
        os_name = "nx-os"
    elif "junos" in lowered:
        os_name = "junos"
    elif "eos" in lowered:
        os_name = "eos"
    elif "fortios" in lowered:
        os_name = "fortios"

    return vendor, detected_type, os_name


def _parse_model_and_version(sys_descr: str) -> tuple[str, str]:
    """Extract hardware model and software version from an SNMP sysDescr string."""
    model = ""
    version = ""
    if not sys_descr:
        return model, version

    # Cisco IOS / IOS-XE: "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)E10, ..."
    # Also handles: "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, ..."
    m = re.search(r"Version\s+([\d.()a-zA-Z]+)", sys_descr)
    if m:
        version = m.group(1)

    # Try to grab the model from the software image name in parens, e.g. "(C3750E-UNIVERSALK9-M)"
    m = re.search(r"\(([A-Z0-9][\w-]+)\)", sys_descr)
    if m:
        model = m.group(1)

    # Cisco NX-OS: "Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 10.3(2), ..."
    if not model:
        m = re.search(r"Cisco\s+\S+\s+([\w-]+)", sys_descr)
        if m and m.group(1).lower() not in ("ios", "software", "nx-os(tm)"):
            model = m.group(1)

    # Juniper: "Juniper Networks, Inc. ex4300-48t ..."
    if "juniper" in sys_descr.lower():
        m = re.search(r"Juniper\s+Networks,?\s+Inc\.?\s+([\w-]+)", sys_descr, re.IGNORECASE)
        if m:
            model = m.group(1)
        m = re.search(r"JUNOS\s+([\d.A-Za-z-]+)", sys_descr)
        if m:
            version = m.group(1)

    # Arista: "Arista Networks EOS version 4.28.3M running on an Arista Networks DCS-7050TX-64"
    if "arista" in sys_descr.lower():
        m = re.search(r"version\s+([\d.]+\w*)", sys_descr, re.IGNORECASE)
        if m:
            version = m.group(1)
        m = re.search(r"(DCS-[\w-]+)", sys_descr)
        if m:
            model = m.group(1)

    # HPE Aruba (formats above ``_aruba_device_type``): the version has its
    # own pattern per line; the model is the one printed after the product
    # number on AOS-Switch, else the product number.
    aruba_type = _aruba_device_type(sys_descr)
    if aruba_type:
        version_pattern = {
            "aruba_instant_on": _INSTANT_ON_VERSION,
            "aruba_aoscx": _AOSCX_VERSION,
            "aruba_osswitch": _AOS_SWITCH_VERSION,
        }[aruba_type]
        m = version_pattern.search(sys_descr)
        version = m.group(1) if m else version
        m = _AOS_SWITCH_MODEL.search(sys_descr) if aruba_type == "aruba_osswitch" else None
        m = m or _HPE_PRODUCT_NUMBER.search(sys_descr)
        model = m.group(1) if m else ""

    # Netgear (formats above ``_netgear_device_type``): the model, and the
    # firmware as the first dotted number after a comma.
    netgear_type = _netgear_device_type(sys_descr)
    if netgear_type:
        m = _NETGEAR_MODELS[netgear_type].search(sys_descr)
        model = m.group(1) if m else ""
        m = _NETGEAR_VERSION.search(sys_descr)
        version = m.group(1) if m else ""

    # APC UPS card: the version is the card's (AOS) firmware. The model is
    # left empty: the sysDescr names the card (AP9631), the host is the UPS,
    # whose model ``_snmp_get`` and the monitoring poll read from PowerNet-MIB.
    if _apc_device_type(sys_descr):
        model, version = "", parse_apc_nmc_sys_descr(sys_descr)["nmc_firmware"]

    return model, version


# ── Secret resolution helper ─────────────────────────────────────────────────


async def _resolve_snmp_secrets(snmp_config: dict) -> dict:
    """Resolve {{secret.NAME}} placeholders in v3 auth/priv passwords.

    Returns a shallow copy of *snmp_config* with passwords replaced by
    their decrypted values.  If there are no secret references the
    original dict is returned unchanged (fast path).
    """
    v3 = snmp_config.get("v3")
    if not isinstance(v3, dict):
        return snmp_config
    auth_pw = str(v3.get("auth_password", ""))
    priv_pw = str(v3.get("priv_password", ""))
    try:
        from routes.secret_resolver import has_secret_references, resolve_secrets

        if not (has_secret_references(auth_pw) or has_secret_references(priv_pw)):
            return snmp_config
        resolved = await resolve_secrets([auth_pw, priv_pw])
        cfg = dict(snmp_config)
        cfg["v3"] = dict(v3)
        cfg["v3"]["auth_password"] = resolved[0].strip()
        cfg["v3"]["priv_password"] = resolved[1].strip()
        LOGGER.debug(
            "SNMPv3 secret resolution: auth_key_len=%d priv_key_len=%d",
            len(cfg["v3"]["auth_password"]),
            len(cfg["v3"]["priv_password"]),
        )
        return cfg
    except Exception as exc:
        LOGGER.error("SNMPv3 secret resolution FAILED - using raw value as password: %s", exc)
        return snmp_config


# ── SNMP Get ─────────────────────────────────────────────────────────────────


# The identity a discovery / test GET reads from every device.
_IDENTITY_OIDS = (
    "1.3.6.1.2.1.1.1.0",  # sysDescr
    "1.3.6.1.2.1.1.5.0",  # sysName
    "1.3.6.1.2.1.47.1.1.1.1.13.1",  # entPhysicalModelName.1 (chassis)
    "1.3.6.1.2.1.47.1.1.1.1.11.1",  # entPhysicalSerialNum.1 (chassis)
)


async def _snmp_get(ip_address: str, timeout_seconds: float, snmp_config: dict) -> dict | None:
    """Returns device info dict on success, None on no response, raises on auth/config errors."""
    if not PYSMNP_AVAILABLE:
        raise RuntimeError("pysnmp library is not available")
    _required_imports = [
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        get_cmd,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
        usmDESPrivProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
    ]
    if any(obj is None for obj in _required_imports):
        raise RuntimeError("pysnmp imported but one or more required symbols are None")
    if not snmp_config.get("enabled", False):
        return None

    # Resolve {{secret.NAME}} references in v3 passwords
    cfg = await _resolve_snmp_secrets(snmp_config)
    version = str(cfg.get("version", "2c"))
    port = int(cfg.get("port", 161))
    retries = int(cfg.get("retries", 0))
    timeout = max(timeout_seconds, float(cfg.get("timeout_seconds", timeout_seconds)))

    auth_data = None
    if version == "3":
        v3 = cfg.get("v3", {})
        username = str(v3.get("username", "")).strip()
        auth_password = str(v3.get("auth_password", "")).strip()
        priv_password = str(v3.get("priv_password", "")).strip()
        if not username or not auth_password:
            return None
        auth_map = {
            "md5": usmHMACMD5AuthProtocol,
            "sha": usmHMACSHAAuthProtocol,
            "sha256": usmHMAC192SHA256AuthProtocol,
            "sha512": usmHMAC384SHA512AuthProtocol,
        }
        priv_map = {
            "des": usmDESPrivProtocol,
            "aes128": usmAesCfb128Protocol,
            "aes192": usmAesCfb192Protocol,
            "aes256": usmAesCfb256Protocol,
        }
        auth_proto_key = str(v3.get("auth_protocol", "sha")).lower()
        priv_proto_key = str(v3.get("priv_protocol", "aes128")).lower()
        auth_proto = auth_map.get(auth_proto_key, usmHMACSHAAuthProtocol)
        priv_proto = priv_map.get(priv_proto_key, usmAesCfb128Protocol)
        if priv_password:
            auth_data = UsmUserData(
                username,
                authKey=auth_password,
                privKey=priv_password,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        else:
            auth_data = UsmUserData(
                username,
                authKey=auth_password,
                authProtocol=auth_proto,
            )
        # SNMPv3 engine discovery consumes retry rounds: the first
        # exchange learns the remote engineID (usmStats.4 report),
        # and only the subsequent retry carries the real authenticated
        # request.  With retries=0 the authenticated GET never fires.
        # Guarantee at least 2 retries so the handshake can complete.
        retries = max(retries, 2)
    else:
        community = str(cfg.get("community", "public")).strip()
        if not community:
            return None
        auth_data = CommunityData(community, mpModel=1)

    async def _get(auth: Any, oids: tuple[str, ...]) -> tuple[Any, Any, Any]:
        """One SNMP GET of ``oids``: (error_indication, error_status, var_binds)."""
        engine = SnmpEngine()
        try:
            transport = await UdpTransportTarget.create((ip_address, port), timeout=timeout, retries=retries)
            error_indication, error_status, _error_index, var_binds = await get_cmd(
                engine, auth, transport, ContextData(), *(ObjectType(ObjectIdentity(oid)) for oid in oids)
            )
        finally:
            engine.close_dispatcher()
        return error_indication, error_status, var_binds

    error_indication, error_status, var_binds = await _get(auth_data, _IDENTITY_OIDS)

    # If SNMPv3 fails, fall back to v2c using the community string if available.
    if (error_indication or error_status) and version == "3":
        v3_err = str(error_indication or error_status.prettyPrint())
        community = str(cfg.get("community", "")).strip()
        if community:
            LOGGER.warning(
                "SNMPv3 failed for %s (%s), falling back to v2c",
                ip_address,
                v3_err,
            )
            auth_data = CommunityData(community, mpModel=1)
            error_indication, error_status, var_binds = await _get(auth_data, _IDENTITY_OIDS)
            if not error_indication and not error_status:
                version = "2c-fallback"
            else:
                raise RuntimeError(f"SNMPv3 failed for {ip_address}: {v3_err}")
        else:
            raise RuntimeError(f"SNMPv3 failed for {ip_address}: {v3_err}")
    elif error_indication:
        raise RuntimeError(f"SNMP v{version} error for {ip_address}: {error_indication}")
    elif error_status:
        raise RuntimeError(f"SNMP v{version} error for {ip_address}: {error_status.prettyPrint()}")

    values = {str(name): str(value) for name, value in var_binds}
    sys_descr = values.get("1.3.6.1.2.1.1.1.0", "")
    sys_name = values.get("1.3.6.1.2.1.1.5.0", "")
    ent_model = values.get("1.3.6.1.2.1.47.1.1.1.1.13.1", "")
    ent_serial = values.get("1.3.6.1.2.1.47.1.1.1.1.11.1", "")

    # pysnmp returns special objects (NoSuchInstance, NoSuchObject, endOfMibView)
    # that str() converts to long descriptive strings - treat those as empty.
    if sys_name and any(m in sys_name.lower() for m in _SNMP_BAD_MARKERS):
        sys_name = ""
    if sys_descr and any(m in sys_descr.lower() for m in _SNMP_BAD_MARKERS):
        sys_descr = ""
    if ent_model and any(m in ent_model.lower() for m in _SNMP_BAD_MARKERS):
        ent_model = ""
    if ent_serial and any(m in ent_serial.lower() for m in _SNMP_BAD_MARKERS):
        ent_serial = ""
    vendor, detected_type, os_name = _infer_vendor_os_from_text(sys_descr)
    hw_model, sw_version = _parse_model_and_version(sys_descr)
    # Prefer entPhysicalModelName (actual hardware PID like C9300-48T) over
    # the software image name parsed from sysDescr (like CAT9K_LITE_IOSXE).
    if ent_model.strip():
        hw_model = ent_model.strip()
    if detected_type == "apc_ups":
        # The card has no ENTITY-MIB chassis row; the UPS's own model and
        # serial are PowerNet-MIB scalars, read in a second GET so other
        # devices are never asked for them.
        ups_model, ups_serial = await _apc_ups_identity(_get, auth_data, ip_address)
        hw_model = ups_model or hw_model
        ent_serial = ups_serial or ent_serial
    category = _infer_device_category(hw_model, sys_descr, detected_type)
    return {
        "hostname": sys_name or placeholder_hostname("snmp", ip_address),
        "ip_address": ip_address,
        "device_type": detected_type,
        "device_category": category,
        "status": "online",
        "model": hw_model,
        "software_version": sw_version,
        # sysName and chassis serial are stable device identities (unlike the
        # per-interface IP), used by discovery to dedup a multi-interface
        # device into a single host. sys_name is "" when the device returned
        # no/blank sysName, so callers must treat it as "no identity".
        "sys_name": sys_name,
        "serial_number": ent_serial.strip(),
        "discovery": {
            "protocol": f"snmpv{version}",
            "port": port,
            "vendor": vendor,
            "os": os_name,
            "sys_descr": sys_descr,
            "auth": "configured",
        },
    }


async def _apc_ups_identity(
    get: Callable[..., Awaitable[tuple[Any, Any, Any]]], auth: Any, ip_address: str
) -> tuple[str, str]:
    """The (model, serial) of the UPS behind an APC card, read with ``get``
    (``_snmp_get``'s GET); ``("", "")`` for any field the card did not
    answer. Best-effort: a failed GET leaves both empty."""
    model_oid, serial_oid = f"{APC_UPS_MODEL_OID}.0", f"{APC_UPS_SERIAL_OID}.0"
    try:
        error_indication, error_status, var_binds = await get(auth, (model_oid, serial_oid))
    except Exception as exc:
        LOGGER.warning("APC UPS identity read failed for %s: %s", ip_address, exc)
        return "", ""
    if error_indication or error_status:
        LOGGER.warning("APC UPS identity read failed for %s: %s", ip_address, error_indication or error_status)
        return "", ""
    values = {str(name): _snmp_str(value) for name, value in var_binds}
    return values.get(model_oid, ""), values.get(serial_oid, "")


async def _probe_discovery_target_snmp(ip_address: str, timeout_seconds: float, snmp_config: dict) -> dict | None:
    try:
        return await _snmp_get(ip_address, timeout_seconds, snmp_config)
    except Exception as exc:
        LOGGER.warning("SNMP probe failed for %s: %s", ip_address, exc)
        return None


# ipAddrTable.ipAdEntAddr — every IPv4 address configured on the device. The
# value (and the OID suffix) is the dotted-quad interface IP.
IP_AD_ENT_ADDR_OID = "1.3.6.1.2.1.4.20.1.1"


async def _collect_interface_ips(ip_address: str, timeout_seconds: float, snmp_config: dict) -> list[str]:
    """Walk the device's ipAddrTable and return its configured IPv4 interface
    IPs (loopback/link-local/multicast excluded).

    Used by discovery to learn every IP a device owns so its other interface
    IPs aren't onboarded as separate hosts. Best-effort: returns [] on any SNMP
    failure or when pysnmp is unavailable.
    """
    if not PYSMNP_AVAILABLE:
        return []
    try:
        rows = await _snmp_walk(
            ip_address,
            timeout_seconds,
            snmp_config,
            IP_AD_ENT_ADDR_OID,
            max_rows=512,
        )
    except Exception as exc:
        LOGGER.debug("interface-IP walk failed for %s: %s", ip_address, exc)
        return []

    out: list[str] = []
    seen: set[str] = set()
    for oid, value in rows.items():
        # Prefer the value; fall back to the last 4 OID octets.
        candidate = str(value).strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            candidate = ".".join(oid.rsplit(".", 4)[-4:]) if oid.count(".") >= 4 else ""
        text = interface_ip(candidate)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


# ── SNMP Walk & Build Auth ───────────────────────────────────────────────────


def _build_snmp_auth(snmp_config: dict):
    """Build pysnmp auth_data from config dict. Returns (auth_data, version, port, timeout, retries) or None."""
    if not PYSMNP_AVAILABLE:
        return None
    cfg = snmp_config
    if not cfg.get("enabled", False):
        return None
    version = str(cfg.get("version", "2c"))
    port = int(cfg.get("port", 161))
    retries = int(cfg.get("retries", 0))
    timeout = float(cfg.get("timeout_seconds", 2.0))

    if version == "3":
        v3 = cfg.get("v3", {})
        username = str(v3.get("username", "")).strip()
        auth_password = str(v3.get("auth_password", "")).strip()
        priv_password = str(v3.get("priv_password", "")).strip()
        if not username or not auth_password:
            return None
        auth_map = {
            "md5": usmHMACMD5AuthProtocol,
            "sha": usmHMACSHAAuthProtocol,
            "sha256": usmHMAC192SHA256AuthProtocol,
            "sha512": usmHMAC384SHA512AuthProtocol,
        }
        priv_map = {
            "des": usmDESPrivProtocol,
            "aes128": usmAesCfb128Protocol,
            "aes192": usmAesCfb192Protocol,
            "aes256": usmAesCfb256Protocol,
        }
        auth_proto = auth_map.get(str(v3.get("auth_protocol", "sha")).lower(), usmHMACSHAAuthProtocol)
        priv_proto = priv_map.get(str(v3.get("priv_protocol", "aes128")).lower(), usmAesCfb128Protocol)
        if priv_password:
            auth_data = UsmUserData(
                username, authKey=auth_password, privKey=priv_password, authProtocol=auth_proto, privProtocol=priv_proto
            )
        else:
            auth_data = UsmUserData(username, authKey=auth_password, authProtocol=auth_proto)
        # SNMPv3 engine discovery needs extra retries (see _snmp_get).
        retries = max(retries, 2)
    else:
        community = str(cfg.get("community", "public")).strip()
        if not community:
            return None
        auth_data = CommunityData(community, mpModel=1)

    return auth_data, version, port, timeout, retries


# GETBULK max-repetitions: varbinds requested per PDU on the v2c/v3 bulk walk.
# 25 balances fewer round-trips against oversized responses / UDP fragmentation.
_SNMP_BULK_MAX_REPETITIONS = 25


async def _snmp_walk(
    ip_address: str,
    timeout_seconds: float,
    snmp_config: dict,
    base_oid: str,
    max_rows: int = 500,
    return_errors: bool = False,
    engine: Any = None,
):
    """Walk an SNMP OID subtree and return {oid: value} dict.

    Default return is the bare dict (back-compat for many callers). When
    ``return_errors=True`` returns ``(results, error_text_or_None)`` so the
    caller can distinguish "device responded with an empty table" from
    "timeout / authentication failure / no SNMP agent" — those used to look
    identical to callers, which made silent collection failures effectively
    invisible.

    ``engine``: a pysnmp engine the caller shares between its requests to
    one device and closes itself, so an SNMPv3 device is discovered (engine
    ID, then time) once instead of once per request. Without it the walk
    opens and closes its own.
    """
    # Resolve {{secret.NAME}} references in v3 passwords before building auth
    snmp_config = await _resolve_snmp_secrets(snmp_config)
    auth_tuple = _build_snmp_auth(snmp_config)
    if auth_tuple is None:
        return ({}, "SNMP not configured") if return_errors else {}
    auth_data, version, port, timeout, retries = auth_tuple
    timeout = max(timeout, timeout_seconds)

    own_engine = engine is None
    if own_engine:
        engine = SnmpEngine()
    transport = await UdpTransportTarget.create((ip_address, port), timeout=timeout, retries=retries)
    results: dict[str, str] = {}
    row_count = 0
    error_text: str | None = None
    # Cisco IOS/IOS-XE exposes the per-VLAN bridge/Q-BRIDGE FDB under an
    # SNMPv3 context named "vlan-<id>" -- the v3 equivalent of the v2c
    # "<community>@<vlan>" trick. Honour an optional context name so per-VLAN
    # FDB walks work over SNMPv3 (otherwise every MAC lands in VLAN 0).
    context_name = str(snmp_config.get("snmp_context", "") or "").strip()
    context_data = ContextData(contextName=context_name) if context_name else ContextData()
    # GETBULK (bulk_walk_cmd) fetches up to _SNMP_BULK_MAX_REPETITIONS varbinds
    # per PDU instead of one-per-round-trip GETNEXT (walk_cmd), cutting round
    # trips ~25x on large tables (interface counters, FDB/ARP). GETBULK is a
    # v2c/v3-only PDU, so fall back to GETNEXT for v1. Both generators yield the
    # same (errInd, errStat, errIdx, varBinds) rows, so the loop is unchanged.
    if version == "1" or bulk_walk_cmd is None:
        walker = walk_cmd(
            engine,
            auth_data,
            transport,
            context_data,
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        )
    else:
        walker = bulk_walk_cmd(
            engine,
            auth_data,
            transport,
            context_data,
            0,
            _SNMP_BULK_MAX_REPETITIONS,
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        )
    try:
        async for error_indication, error_status, _error_index, var_binds in walker:
            if error_indication:
                error_text = str(error_indication)
                break
            if error_status:
                error_text = _error_status_text(error_status)
                break
            for name, value in var_binds:
                oid_str = str(name)
                results[oid_str] = value
            row_count += 1
            if row_count >= max_rows:
                break
    except Exception as exc:
        error_text = f"{type(exc).__name__}: {exc}"
    finally:
        if own_engine:
            engine.close_dispatcher()
    if return_errors:
        return results, error_text
    return results


def _error_status_text(error_status: Any) -> str:
    """A PDU error status as its MIB name (noSuchName, authorizationError
    ...), which is what an operator wants to see."""
    try:
        return str(error_status.prettyPrint())
    except Exception:
        return str(error_status)


async def _snmp_get_values(
    ip_address: str,
    timeout_seconds: float,
    snmp_config: dict,
    oids: tuple[str, ...],
    *,
    engine: Any = None,
) -> tuple[dict[str, Any], str | None]:
    """GET the instances ``oids`` in one request: ``({oid: value}, error)``.

    The dict is empty, with the reason as ``error``, when the device did not
    answer or refused the request. An object the device does not have is in
    the dict with pysnmp's NoSuchObject / NoSuchInstance value (``_snmp_str``
    gives ""). ``engine``: as for :func:`_snmp_walk`."""
    snmp_config = await _resolve_snmp_secrets(snmp_config)
    auth_tuple = _build_snmp_auth(snmp_config)
    if auth_tuple is None:
        return {}, "SNMP not configured"
    auth_data, _version, port, timeout, retries = auth_tuple
    timeout = max(timeout, timeout_seconds)

    own_engine = engine is None
    if own_engine:
        engine = SnmpEngine()
    try:
        transport = await UdpTransportTarget.create((ip_address, port), timeout=timeout, retries=retries)
        error_indication, error_status, _error_index, var_binds = await get_cmd(
            engine, auth_data, transport, ContextData(), *(ObjectType(ObjectIdentity(oid)) for oid in oids)
        )
    except Exception as exc:
        return {}, f"{type(exc).__name__}: {exc}"
    finally:
        if own_engine:
            engine.close_dispatcher()
    if error_indication:
        return {}, str(error_indication)
    if error_status:
        return {}, _error_status_text(error_status)
    return {str(name): value for name, value in var_binds}, None


# ── CDP Address Parser ───────────────────────────────────────────────────────


_SNMP_BAD_MARKERS = ("no such instance", "no such object", "endofmibview")


def _snmp_str(raw_value) -> str:
    """Convert an SNMP value to a clean string, returning '' for pysnmp
    sentinel values (NoSuchInstance, NoSuchObject, endOfMibView)."""
    s = str(raw_value).strip()
    if s and any(m in s.lower() for m in _SNMP_BAD_MARKERS):
        return ""
    return s


# ── SNMP trap decoding ───────────────────────────────────────────────────────

SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"  # snmpTrapOID.0
_SNMP_GENERIC_TRAPS = "1.3.6.1.6.3.1.1.5"  # snmpTraps (coldStart = .1)


def decode_snmp_trap(data: bytes) -> dict | None:
    """Decode an SNMPv1 or SNMPv2c trap datagram with pysnmp's BER codec.

    Returns ``{"version": "v1" | "v2c", "community", "trap_oid",
    "agent_address", "varbinds": [(oid, text)]}``. A v1 trap's OID is
    formed as RFC 3584 does: ``enterprise.0.specific`` for an
    enterprise-specific trap, ``snmpTraps.(generic + 1)`` otherwise; the
    agent address is set only on v1. None for anything else: SNMPv3 (its
    PDU needs the user's keys), a PDU that is not a trap, bytes that are
    not valid BER, or pysnmp not installed.
    """
    try:
        from pyasn1.codec.ber import decoder as ber_decoder
        from pysnmp.proto import api as snmp_api
    except ImportError:
        return None
    try:
        version = int(snmp_api.decodeMessageVersion(data))
        proto = snmp_api.PROTOCOL_MODULES.get(version)
        if proto is None:
            return None
        message, _rest = ber_decoder.decode(data, asn1Spec=proto.Message())
        pdu = proto.apiMessage.get_pdu(message)
        trap_pdu = proto.TrapPDU() if version == snmp_api.SNMP_VERSION_1 else proto.SNMPv2TrapPDU()
        if not pdu.isSameTypeWith(trap_pdu):
            return None
        community = bytes(proto.apiMessage.get_community(message).asOctets()).decode("utf-8", "replace")
        varbinds = [(oid.prettyPrint(), value.prettyPrint()) for oid, value in proto.apiTrapPDU.get_varbinds(pdu)]
        if version == snmp_api.SNMP_VERSION_1:
            generic = int(proto.apiTrapPDU.get_generic_trap(pdu))
            enterprise = proto.apiTrapPDU.get_enterprise(pdu).prettyPrint()
            trap_oid = (
                f"{enterprise}.0.{int(proto.apiTrapPDU.get_specific_trap(pdu))}"
                if generic == 6
                else f"{_SNMP_GENERIC_TRAPS}.{generic + 1}"
            )
            agent_address = proto.apiTrapPDU.get_agent_address(pdu).prettyPrint()
        else:
            trap_oid = next((value for oid, value in varbinds if oid == SNMP_TRAP_OID), "")
            agent_address = ""
    except Exception:  # noqa: BLE001 - untrusted network input: anything malformed is "not a trap"
        return None
    return {
        "version": "v1" if version == snmp_api.SNMP_VERSION_1 else "v2c",
        "community": community,
        "trap_oid": trap_oid,
        "agent_address": agent_address,
        "varbinds": varbinds,
    }


def _parse_cdp_address(raw_value) -> str:
    """Convert CDP cdpCacheAddress (binary) to dotted IPv4 string."""
    try:
        raw_bytes = bytes(raw_value)
        if len(raw_bytes) == 4:
            return socket.inet_ntoa(raw_bytes)
        return raw_bytes.hex()
    except Exception:
        return str(raw_value)


# ── Neighbor Discovery ───────────────────────────────────────────────────────


async def _discover_neighbors(
    host_id: int, ip_address: str, snmp_config: dict, timeout_seconds: float = 5.0
) -> tuple[list[dict], list[dict]]:
    """Discover CDP/LLDP/OSPF/BGP neighbors and poll interface counters.

    Returns (neighbors_list, interface_stats_list).
    All independent SNMP walks run in parallel for speed.
    """
    neighbors: list[dict] = []

    def _walk(oid):
        return _snmp_walk(ip_address, timeout_seconds, snmp_config, oid)

    # ── Phase 1: Parallel walk of ALL OID groups ──
    # ifName / ifDescr (need ifName first, ifDescr as fallback)
    if_name_oid = "1.3.6.1.2.1.31.1.1.1.1"
    if_descr_oid = "1.3.6.1.2.1.2.2.1.2"

    # Interface counters
    if_hc_in_oid = "1.3.6.1.2.1.31.1.1.1.6"  # ifHCInOctets (64-bit)
    if_hc_out_oid = "1.3.6.1.2.1.31.1.1.1.10"  # ifHCOutOctets (64-bit)
    if_in_octets_oid = "1.3.6.1.2.1.2.2.1.10"  # ifInOctets (32-bit fallback)
    if_out_octets_oid = "1.3.6.1.2.1.2.2.1.16"  # ifOutOctets (32-bit fallback)
    if_high_speed_oid = "1.3.6.1.2.1.31.1.1.1.15"  # ifHighSpeed (Mbps)
    if_speed_oid = "1.3.6.1.2.1.2.2.1.5"  # ifSpeed (bps)

    # CDP OIDs
    cdp_device_id_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
    cdp_address_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
    cdp_port_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
    cdp_platform_base = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

    # LLDP OIDs
    lldp_sys_name_base = "1.0.8802.1.1.2.1.4.1.1.9"
    lldp_port_id_base = "1.0.8802.1.1.2.1.4.1.1.7"
    lldp_port_desc_base = "1.0.8802.1.1.2.1.4.1.1.8"
    lldp_sys_desc_base = "1.0.8802.1.1.2.1.4.1.1.10"
    lldp_man_addr_base = "1.0.8802.1.1.2.1.4.2.1.4"

    # OSPF OIDs
    ospf_nbr_rtr_id_base = "1.3.6.1.2.1.14.10.1.3"
    ospf_nbr_state_base = "1.3.6.1.2.1.14.10.1.6"

    # BGP OIDs
    bgp_peer_state_base = "1.3.6.1.2.1.15.3.1.2"
    bgp_peer_remote_as_base = "1.3.6.1.2.1.15.3.1.9"

    LOGGER.info("topology: starting parallel SNMP walks for %s (%s)", ip_address, host_id)

    # Fire ALL walks in parallel - one round-trip instead of 17 sequential ones
    (
        if_names,
        if_descr,
        hc_in,
        hc_out,
        lo_in,
        lo_out,
        high_speed_raw,
        speed_raw,
        cdp_device_ids,
        cdp_addresses,
        cdp_ports,
        cdp_platforms,
        lldp_names,
        lldp_port_ids,
        lldp_port_descs,
        lldp_sys_descs,
        lldp_man_addrs,
        ospf_rtr_ids,
        ospf_states,
        bgp_states,
        bgp_remote_as,
    ) = await asyncio.gather(
        _walk(if_name_oid),
        _walk(if_descr_oid),
        _walk(if_hc_in_oid),
        _walk(if_hc_out_oid),
        _walk(if_in_octets_oid),
        _walk(if_out_octets_oid),
        _walk(if_high_speed_oid),
        _walk(if_speed_oid),
        _walk(cdp_device_id_base),
        _walk(cdp_address_base),
        _walk(cdp_port_base),
        _walk(cdp_platform_base),
        _walk(lldp_sys_name_base),
        _walk(lldp_port_id_base),
        _walk(lldp_port_desc_base),
        _walk(lldp_sys_desc_base),
        _walk(lldp_man_addr_base),
        _walk(ospf_nbr_rtr_id_base),
        _walk(ospf_nbr_state_base),
        _walk(bgp_peer_state_base),
        _walk(bgp_peer_remote_as_base),
    )

    LOGGER.info(
        "topology: SNMP walks complete for %s - CDP:%d LLDP:%d OSPF:%d BGP:%d ifStats:%d",
        ip_address,
        len(cdp_device_ids),
        len(lldp_names),
        len(ospf_rtr_ids),
        len(bgp_states),
        len(hc_in) or len(lo_in),
    )

    # ── Build ifIndex -> interface name map ──
    effective_if_names = if_names or if_descr
    if_index_map: dict[str, str] = {}
    for oid, val in effective_if_names.items():
        parts = oid.rsplit(".", 1)
        if len(parts) == 2:
            if_index_map[parts[1]] = str(val)

    # ── Interface counter stats ──
    # Prefer 64-bit counters, fall back to 32-bit
    in_octets_raw = hc_in or lo_in
    out_octets_raw = hc_out or lo_out
    # Prefer ifHighSpeed (Mbps), fall back to ifSpeed (bps -> Mbps)
    if not high_speed_raw:
        effective_speed = speed_raw
    else:
        effective_speed = high_speed_raw

    if_stats: list[dict] = []
    all_if_indexes = set()
    for oid in list(in_octets_raw.keys()) + list(out_octets_raw.keys()):
        idx = oid.rsplit(".", 1)[-1] if "." in oid else ""
        if idx:
            all_if_indexes.add(idx)

    for idx in all_if_indexes:
        in_val = 0
        out_val = 0
        speed_mbps = 0
        for oid, val in in_octets_raw.items():
            if oid.endswith("." + idx):
                try:
                    in_val = int(val)
                except (ValueError, TypeError) as exc:
                    LOGGER.debug("topology: bad in-octets value from %s for ifIndex %s: %s", ip_address, idx, exc)
                break
        for oid, val in out_octets_raw.items():
            if oid.endswith("." + idx):
                try:
                    out_val = int(val)
                except (ValueError, TypeError) as exc:
                    LOGGER.debug("topology: bad out-octets value from %s for ifIndex %s: %s", ip_address, idx, exc)
                break
        for oid, val in effective_speed.items():
            if oid.endswith("." + idx):
                try:
                    raw_speed = int(val)
                    speed_mbps = raw_speed if high_speed_raw else raw_speed // 1_000_000
                except (ValueError, TypeError) as exc:
                    LOGGER.debug("topology: bad interface speed value from %s for ifIndex %s: %s", ip_address, idx, exc)
                break

        if_stats.append(
            {
                "host_id": host_id,
                "if_index": int(idx),
                "if_name": if_index_map.get(idx, f"ifIndex-{idx}"),
                "if_speed_mbps": speed_mbps,
                "in_octets": in_val,
                "out_octets": out_val,
            }
        )

    # ── CDP Neighbor Parsing ──
    for oid, device_name_val in cdp_device_ids.items():
        suffix = oid[len(cdp_device_id_base) :]
        if not suffix:
            continue
        parts = suffix.lstrip(".").split(".")
        if_index = parts[0] if parts else ""
        local_iface = if_index_map.get(if_index, f"ifIndex-{if_index}")

        remote_name = _snmp_str(device_name_val)
        if "(" in remote_name:
            remote_name = remote_name.split("(")[0].strip()

        addr_oid = cdp_address_base + suffix
        port_oid = cdp_port_base + suffix
        plat_oid = cdp_platform_base + suffix

        remote_ip = ""
        if addr_oid in cdp_addresses:
            remote_ip = _parse_cdp_address(cdp_addresses[addr_oid])

        remote_port = _snmp_str(cdp_ports.get(port_oid, ""))
        platform = _snmp_str(cdp_platforms.get(plat_oid, ""))

        neighbors.append(
            {
                "source_host_id": host_id,
                "source_ip": ip_address,
                "local_interface": local_iface,
                "remote_device_name": remote_name,
                "remote_ip": remote_ip,
                "remote_interface": remote_port,
                "protocol": "cdp",
                "remote_platform": platform,
            }
        )

    # ── LLDP Neighbor Parsing ──
    lldp_addr_map: dict[str, str] = {}
    for oid, val in lldp_man_addrs.items():
        suffix = oid[len(lldp_man_addr_base) :]
        parts = suffix.lstrip(".").split(".")
        if len(parts) >= 3:
            key = f"{parts[0]}.{parts[1]}.{parts[2]}"
            try:
                raw = bytes(val)
                if len(raw) == 4:
                    lldp_addr_map[key] = socket.inet_ntoa(raw)
            except Exception as exc:
                LOGGER.debug(
                    "topology: failed to parse LLDP management address from %s (oid %s): %s", ip_address, oid, exc
                )

    for oid, sys_name_val in lldp_names.items():
        suffix = oid[len(lldp_sys_name_base) :]
        if not suffix:
            continue
        parts = suffix.lstrip(".").split(".")
        local_port_num = parts[1] if len(parts) >= 2 else ""
        lldp_key = ".".join(parts[:3]) if len(parts) >= 3 else suffix.lstrip(".")

        local_iface = if_index_map.get(local_port_num, f"port-{local_port_num}")
        remote_name = _snmp_str(sys_name_val)

        port_id_oid = lldp_port_id_base + suffix
        port_desc_oid = lldp_port_desc_base + suffix
        sys_desc_oid = lldp_sys_desc_base + suffix

        remote_port_raw = _snmp_str(lldp_port_ids.get(port_id_oid, ""))
        remote_port_desc = _snmp_str(lldp_port_descs.get(port_desc_oid, ""))
        remote_port = remote_port_desc or remote_port_raw

        sys_desc = _snmp_str(lldp_sys_descs.get(sys_desc_oid, ""))
        remote_ip = lldp_addr_map.get(lldp_key, "")

        already_found = any(
            n["remote_device_name"].lower() == remote_name.lower() and n["local_interface"] == local_iface
            for n in neighbors
        )
        if already_found:
            continue

        neighbors.append(
            {
                "source_host_id": host_id,
                "source_ip": ip_address,
                "local_interface": local_iface,
                "remote_device_name": remote_name or f"lldp-{remote_port_raw}",
                "remote_ip": remote_ip,
                "remote_interface": remote_port,
                "protocol": "lldp",
                "remote_platform": sys_desc[:200] if sys_desc else "",
            }
        )

    # ── OSPF Neighbor Parsing ──
    for oid, rtr_id_val in ospf_rtr_ids.items():
        suffix = oid[len(ospf_nbr_rtr_id_base) :].lstrip(".")
        parts = suffix.split(".")
        if len(parts) >= 4:
            nbr_ip = ".".join(parts[:4])
        else:
            continue

        rtr_id = _snmp_str(rtr_id_val)
        state_oid = ospf_nbr_state_base + "." + suffix
        state_val = _snmp_str(ospf_states.get(state_oid, ""))

        already_found = any(n["remote_ip"] == nbr_ip for n in neighbors)
        if already_found:
            continue

        neighbors.append(
            {
                "source_host_id": host_id,
                "source_ip": ip_address,
                "local_interface": "",
                "remote_device_name": rtr_id or nbr_ip,
                "remote_ip": nbr_ip,
                "remote_interface": "",
                "protocol": "ospf",
                "remote_platform": f"OSPF state={state_val}" if state_val else "",
            }
        )

    # ── BGP Peer Parsing ──
    for oid, state_val in bgp_states.items():
        suffix = oid[len(bgp_peer_state_base) :].lstrip(".")
        parts = suffix.split(".")
        if len(parts) >= 4:
            peer_ip = ".".join(parts[:4])
        else:
            continue

        as_oid = bgp_peer_remote_as_base + "." + suffix
        remote_as = _snmp_str(bgp_remote_as.get(as_oid, ""))

        already_found = any(n["remote_ip"] == peer_ip for n in neighbors)
        if already_found:
            continue

        neighbors.append(
            {
                "source_host_id": host_id,
                "source_ip": ip_address,
                "local_interface": "",
                "remote_device_name": f"AS{remote_as}" if remote_as else peer_ip,
                "remote_ip": peer_ip,
                # The peer address keeps two peers of one AS apart: the
                # stored link is unique per device, interfaces and name.
                "remote_interface": peer_ip,
                "protocol": "bgp",
                "remote_platform": f"AS {remote_as}, state={state_val}" if remote_as else "",
            }
        )

    return neighbors, if_stats


# ── SNMP Table Walking (auto-discovery of interfaces as data sources) ─────


async def snmp_table_walk(
    ip_address: str, snmp_config: dict, table_oids: list[str], timeout_seconds: float = 5.0, max_rows: int = 1000
) -> dict[str, dict[str, str]]:
    """Walk multiple SNMP OID subtrees in parallel and correlate rows by index suffix.

    Returns {table_oid: {index_suffix: value}} for each OID walked.
    """
    if not table_oids:
        return {}

    async def _walk_one(oid):
        return oid, await _snmp_walk(ip_address, timeout_seconds, snmp_config, oid, max_rows)

    results_raw = await asyncio.gather(*[_walk_one(oid) for oid in table_oids], return_exceptions=True)
    tables: dict[str, dict[str, str]] = {}
    for res in results_raw:
        if isinstance(res, Exception):
            continue
        oid_prefix, raw_data = res
        indexed: dict[str, str] = {}
        for full_oid, val in raw_data.items():
            # Extract index suffix (everything after the base OID prefix)
            if full_oid.startswith(oid_prefix):
                suffix = full_oid[len(oid_prefix) :].lstrip(".")
            else:
                # Fallback: use last dotted component
                suffix = full_oid.rsplit(".", 1)[-1] if "." in full_oid else full_oid
            val_str = _snmp_str(val) if not isinstance(val, str) else val
            indexed[suffix] = val_str
        tables[oid_prefix] = indexed
    return tables


async def auto_discover_data_sources(
    host_id: int, ip_address: str, snmp_config: dict, timeout_seconds: float = 5.0
) -> dict:
    """Walk ifTable/ifXTable to enumerate interfaces as independent data sources.

    Also discovers storage entries (hrStorageTable) if available.
    Returns {"interfaces": count, "storage": count, "total": count}.
    """
    import routes.database as db

    # OIDs for interface discovery
    IF_TABLE_OIDS = [
        "1.3.6.1.2.1.31.1.1.1.1",  # ifName
        "1.3.6.1.2.1.2.2.1.2",  # ifDescr
        "1.3.6.1.2.1.2.2.1.3",  # ifType
        "1.3.6.1.2.1.2.2.1.5",  # ifSpeed (bps)
        "1.3.6.1.2.1.31.1.1.1.15",  # ifHighSpeed (Mbps)
        "1.3.6.1.2.1.2.2.1.7",  # ifAdminStatus
        "1.3.6.1.2.1.2.2.1.8",  # ifOperStatus
        "1.3.6.1.2.1.2.2.1.6",  # ifPhysAddress (MAC)
        # Per-port VLAN membership. Walked here so MAC tracking can tag every
        # learned MAC with the port's access VLAN (or PVID for trunks) instead
        # of relying on per-VLAN Q-BRIDGE walks, which require SNMPv3 contexts
        # the user often isn't authorised for.
        "1.3.6.1.4.1.9.9.68.1.2.2.1.2",  # vmVlan (Cisco access-port VLAN; harmless on non-Cisco)
        "1.3.6.1.2.1.17.7.1.4.5.1.1",  # dot1qPvid (standard PVID, indexed by dot1dBasePort)
    ]

    # OIDs for storage discovery (HOST-RESOURCES-MIB)
    STORAGE_TABLE_OIDS = [
        "1.3.6.1.2.1.25.2.3.1.2",  # hrStorageType
        "1.3.6.1.2.1.25.2.3.1.3",  # hrStorageDescr
        "1.3.6.1.2.1.25.2.3.1.4",  # hrStorageAllocationUnits
        "1.3.6.1.2.1.25.2.3.1.5",  # hrStorageSize
        "1.3.6.1.2.1.25.2.3.1.6",  # hrStorageUsed
    ]

    counts = {"interfaces": 0, "storage": 0, "total": 0}

    # Walk interface and storage tables in parallel
    try:
        if_tables, storage_tables = await asyncio.gather(
            snmp_table_walk(ip_address, snmp_config, IF_TABLE_OIDS, timeout_seconds),
            snmp_table_walk(ip_address, snmp_config, STORAGE_TABLE_OIDS, timeout_seconds),
            return_exceptions=False,
        )
    except Exception as exc:
        LOGGER.warning("data_source_discovery: SNMP table walk failed for %s: %s", ip_address, str(exc))
        return counts

    # ── Process interfaces ──
    if_name_data = if_tables.get("1.3.6.1.2.1.31.1.1.1.1", {})
    if_descr_data = if_tables.get("1.3.6.1.2.1.2.2.1.2", {})
    if_type_data = if_tables.get("1.3.6.1.2.1.2.2.1.3", {})
    if_speed_data = if_tables.get("1.3.6.1.2.1.2.2.1.5", {})
    if_high_speed_data = if_tables.get("1.3.6.1.2.1.31.1.1.1.15", {})
    if_admin_data = if_tables.get("1.3.6.1.2.1.2.2.1.7", {})
    if_oper_data = if_tables.get("1.3.6.1.2.1.2.2.1.8", {})
    if_mac_data = if_tables.get("1.3.6.1.2.1.2.2.1.6", {})
    if_vmvlan_data = if_tables.get("1.3.6.1.4.1.9.9.68.1.2.2.1.2", {})  # ifIndex -> access vlan
    pvid_by_bridge_port = if_tables.get("1.3.6.1.2.1.17.7.1.4.5.1.1", {})  # dot1dBasePort -> pvid

    # Translate dot1qPvid (indexed by dot1dBasePort) to ifIndex via a quick
    # supplementary walk. Skip on failure -- vmVlan alone covers Cisco access
    # ports, which is the common case here.
    if_pvid_data: dict[str, str] = {}
    if pvid_by_bridge_port:
        try:
            bp_map = await _snmp_walk(ip_address, timeout_seconds, snmp_config, "1.3.6.1.2.1.17.1.4.1.2", max_rows=2000)
            bp_to_ifindex: dict[str, str] = {}
            for oid, val in bp_map.items():
                bp = oid.rsplit(".", 1)[-1] if "." in oid else ""
                if bp:
                    bp_to_ifindex[bp] = str(val).strip()
            for bp, pvid in pvid_by_bridge_port.items():
                if_idx = bp_to_ifindex.get(bp)
                if if_idx:
                    if_pvid_data[if_idx] = pvid
        except Exception as exc:
            LOGGER.warning("data_source_discovery: dot1qPvid bridge-port walk failed for %s: %s", ip_address, exc)

    # Collect all known if_indexes
    all_indexes = set()
    for table in [if_name_data, if_descr_data, if_type_data]:
        all_indexes.update(table.keys())

    for idx in sorted(all_indexes, key=lambda x: int(x) if x.isdigit() else 0):
        if_name = if_name_data.get(idx, "") or if_descr_data.get(idx, f"ifIndex-{idx}")
        if_type = if_type_data.get(idx, "")
        speed_raw = if_high_speed_data.get(idx, "")
        if not speed_raw:
            speed_bps = if_speed_data.get(idx, "0")
            try:
                speed_mbps = int(speed_bps) // 1_000_000
            except ValueError, TypeError:
                speed_mbps = 0
        else:
            try:
                speed_mbps = int(speed_raw)
            except ValueError, TypeError:
                speed_mbps = 0

        admin_status = if_admin_data.get(idx, "")
        oper_status = if_oper_data.get(idx, "")
        mac = if_mac_data.get(idx, "")

        # Resolve per-port VLAN: prefer Cisco vmVlan (access ports), fall back
        # to the standard dot1qPvid for non-Cisco bridges. Stored as int when
        # parseable, otherwise omitted -- MAC tracking treats "no VLAN" as 0.
        port_vlan_raw = if_vmvlan_data.get(idx, "") or if_pvid_data.get(idx, "")
        try:
            port_vlan = int(str(port_vlan_raw).strip()) if port_vlan_raw else 0
        except ValueError, TypeError:
            port_vlan = 0

        oids_info = {
            "if_type": if_type,
            "speed_mbps": speed_mbps,
            "admin_status": admin_status,
            "oper_status": oper_status,
            "mac": mac,
            "vlan": port_vlan,
        }

        try:
            await db.upsert_snmp_data_source(
                host_id=host_id,
                ds_type="interface",
                instance_key=str(idx),
                name=if_name,
                instance_label=if_name,
                table_oid="1.3.6.1.2.1.2.2.1",
                index_oid="1.3.6.1.2.1.2.2.1.1",
                oids_json=json.dumps(oids_info),
            )
            counts["interfaces"] += 1
        except Exception as exc:
            LOGGER.debug("data_source_discovery: failed to store interface %s for host %s: %s", idx, host_id, exc)

    # ── Process storage entries ──
    storage_type_data = storage_tables.get("1.3.6.1.2.1.25.2.3.1.2", {})
    storage_descr_data = storage_tables.get("1.3.6.1.2.1.25.2.3.1.3", {})
    storage_alloc_data = storage_tables.get("1.3.6.1.2.1.25.2.3.1.4", {})
    storage_size_data = storage_tables.get("1.3.6.1.2.1.25.2.3.1.5", {})

    for idx in storage_descr_data:
        descr = storage_descr_data.get(idx, "")
        if not descr:
            continue
        storage_info = {
            "storage_type": storage_type_data.get(idx, ""),
            "alloc_units": storage_alloc_data.get(idx, ""),
            "size": storage_size_data.get(idx, ""),
        }
        try:
            await db.upsert_snmp_data_source(
                host_id=host_id,
                ds_type="storage",
                instance_key=f"hr-{idx}",
                name=descr,
                instance_label=descr,
                table_oid="1.3.6.1.2.1.25.2.3.1",
                index_oid="1.3.6.1.2.1.25.2.3.1.1",
                oids_json=json.dumps(storage_info),
            )
            counts["storage"] += 1
        except Exception as exc:
            LOGGER.debug("data_source_discovery: failed to store storage entry %s for host %s: %s", idx, host_id, exc)

    counts["total"] = counts["interfaces"] + counts["storage"]
    LOGGER.info(
        "data_source_discovery: host %s (%s) - %d interfaces, %d storage entries",
        host_id,
        ip_address,
        counts["interfaces"],
        counts["storage"],
    )
    return counts
