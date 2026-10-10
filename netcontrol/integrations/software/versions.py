"""Software versions: parsing, ordering, platform classification and
advisory matching.

Every source Plexus has reports versions in its own shape - an SNMP sysDescr
("Version 17.9.4a"), a Meraki firmware name ("wired-18-107-2"), a Cato
Socket build ("22.0.19221"), an FMC device record ("7.4.1 (build 172)") -
so the tracker reduces each to one ``version`` string and a ``platform``
key, and orders versions by their numeric and alphabetic parts rather than
as text, so ``17.9.4a`` is newer than ``17.9.4`` and ``15.2(7)E10`` is
newer than ``15.2(7)E8``.

Advisories name the versions they affect with a small specification
grammar (see :func:`version_matches`), so a hand-written advisory can cover
a range ("<17.6.5") while an advisory synced from Cisco PSIRT lists the
exact versions Cisco answered for.
"""

from __future__ import annotations

import operator
import re
from typing import Any

# ── Platforms ────────────────────────────────────────────────────────────────

# key -> label and the Cisco PSIRT openVuln ``OSType`` the platform can be
# queried by (``None``: the platform has no version query at Cisco PSIRT).
PLATFORMS: dict[str, dict[str, Any]] = {
    "ios": {"label": "Cisco IOS", "psirt": "ios"},
    "ios-xe": {"label": "Cisco IOS XE", "psirt": "iosxe"},
    "ios-xr": {"label": "Cisco IOS XR", "psirt": "iosxr"},
    "nx-os": {"label": "Cisco NX-OS", "psirt": "nxos"},
    "asa": {"label": "Cisco ASA", "psirt": "asa"},
    "ftd": {"label": "Cisco Secure Firewall Threat Defense", "psirt": "ftd"},
    "fmc": {"label": "Cisco Secure Firewall Management Center", "psirt": "fmc"},
    "fxos": {"label": "Cisco FXOS", "psirt": "fxos"},
    "meraki-mx": {"label": "Meraki MX", "psirt": None},
    "meraki-ms": {"label": "Meraki MS", "psirt": None},
    "meraki-mr": {"label": "Meraki MR", "psirt": None},
    "meraki-mg": {"label": "Meraki MG", "psirt": None},
    "meraki-mv": {"label": "Meraki MV", "psirt": None},
    "meraki-mt": {"label": "Meraki MT", "psirt": None},
    "meraki": {"label": "Meraki", "psirt": None},
    "cato-socket": {"label": "Cato Socket", "psirt": None},
    "junos": {"label": "Juniper Junos", "psirt": None},
    "eos": {"label": "Arista EOS", "psirt": None},
    "fortios": {"label": "FortiOS", "psirt": None},
    "pan-os": {"label": "PAN-OS", "psirt": None},
    "panorama": {"label": "Palo Alto Panorama", "psirt": None},
    "appgate": {"label": "Appgate SDP appliance", "psirt": None},
    "other": {"label": "Other", "psirt": None},
}

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
_SEVERITY_ALIASES = {"informational": "info", "information": "info", "moderate": "medium", "important": "high"}

_DEVICE_TYPE_PLATFORMS = {
    "cisco_xe": "ios-xe",
    "cisco_ios": "ios",
    "cisco_nxos": "nx-os",
    "cisco_xr": "ios-xr",
    "cisco_ftd": "ftd",
    "cisco_asa": "asa",
    "juniper_junos": "junos",
    "arista_eos": "eos",
    "fortinet_fortios": "fortios",
    "fortinet": "fortios",
    "paloalto_panos": "pan-os",
}

_MERAKI_KIND_PLATFORMS = {
    "appliance": "meraki-mx",
    "switch": "meraki-ms",
    "wireless": "meraki-mr",
    "cellularGateway": "meraki-mg",
    "camera": "meraki-mv",
    "sensor": "meraki-mt",
}

# Keyword -> platform, for a host whose driver does not say.
_TEXT_PLATFORMS = (
    ("ios xe", "ios-xe"),
    ("ios-xe", "ios-xe"),
    ("iosxe", "ios-xe"),
    ("ios xr", "ios-xr"),
    ("ios-xr", "ios-xr"),
    ("nx-os", "nx-os"),
    ("nxos", "nx-os"),
    ("adaptive security appliance", "asa"),
    ("threat defense", "ftd"),
    ("firepower", "ftd"),
    ("meraki", "meraki"),
    ("junos", "junos"),
    ("arista", "eos"),
    ("forti", "fortios"),
    ("pan-os", "pan-os"),
    ("palo alto", "pan-os"),
)

# An IOS XE release is 16.x or later with three dotted parts; classic IOS
# is "15.2(7)E8". A host polled by the cisco_ios driver may run either.
_IOS_XE_RELEASE = re.compile(r"^(1[6-9]|[2-9]\d)\.\d+\.\d+")

# Rows of a snapshot node's detail sections that carry its version.
VERSION_ROW_KEYS = ("Firmware", "Software", "Socket version", "Version")

_VERSION_RE = re.compile(r"\d[\w.()\-]*")
_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


# ── Version strings ──────────────────────────────────────────────────────────


def extract_version(raw: Any) -> str:
    """The version inside a free-text version field.

    ``"Version 17.9.4a, RELEASE SOFTWARE"`` -> ``"17.9.4a"``;
    ``"wired-18-107-2"`` -> ``"18-107-2"``; ``"v7.2.5,build1517"`` ->
    ``"7.2.5"``; ``"7.4.1 (build 172)"`` -> ``"7.4.1"``.
    """
    match = _VERSION_RE.search(str(raw or ""))
    return match.group(0).rstrip(".-(") if match else ""


def version_tokens(text: Any) -> tuple[tuple[int, Any], ...]:
    """The comparable form of a version: its numbers and letters in order.

    Numbers compare as numbers and sort after letters at the same position,
    so ``17.09.4`` equals ``17.9.4``, ``17.9.4a`` is newer than ``17.9.4``
    and ``15.2(7)E10`` is newer than ``15.2(7)E8``. Text before the version
    (``wired-``, ``Version``) is ignored, so ``wired-18-107-2`` equals
    ``18.107.2``.
    """
    return tuple(
        (1, int(part)) if part.isdigit() else (0, part.lower()) for part in _TOKEN_RE.findall(extract_version(text))
    )


def canonical_version(text: Any) -> str:
    """One spelling for equal versions: ``wired-18-107-2`` and ``18.107.2``
    both become ``18.107.2``; ``15.2(7)E8`` is kept as written."""
    version = extract_version(text)
    if "(" in version:
        return version
    return (
        version.replace("-", ".") if "-" in version and version.replace("-", "").replace(".", "").isdigit() else version
    )


def compare_versions(a: Any, b: Any) -> int:
    """-1, 0 or 1 as ``a`` is older than, the same as or newer than ``b``."""
    ka, kb = version_tokens(a), version_tokens(b)
    return (ka > kb) - (ka < kb)


def newest_version(versions: list[str]) -> str:
    """The newest of ``versions`` (``""`` when the list is empty)."""
    return max((v for v in versions if v), key=version_tokens, default="")


# ── Version specifications ───────────────────────────────────────────────────

_OPERATORS = {
    "<=": operator.le,
    ">=": operator.ge,
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    ">": operator.gt,
}


def _constraint_matches(key: tuple, constraint: str) -> bool:
    for symbol, compare in _OPERATORS.items():
        if constraint.startswith(symbol):
            other = version_tokens(constraint[len(symbol) :])
            return bool(other) and compare(key, other)
    if ".." in constraint:
        low, high = (version_tokens(side) for side in constraint.split("..", 1))
        return (not low or low <= key) and (not high or key <= high) and bool(low or high)
    if constraint.endswith("*"):
        prefix = version_tokens(constraint[:-1])
        return bool(prefix) and key[: len(prefix)] == prefix
    return key == version_tokens(constraint)


def version_matches(version: Any, spec: str) -> bool:
    """Whether ``version`` satisfies one specification.

    A specification is a comma-separated list of constraints that must all
    hold: an exact version (``17.9.4a``), a prefix (``17.9.*``), a
    comparison (``<17.6.5``, ``>=15.2(7)E8``), or an inclusive range
    (``17.3..17.6.4``). Versions compare as in :func:`version_tokens`.
    """
    key = version_tokens(version)
    constraints = [part.strip() for part in str(spec or "").split(",") if part.strip()]
    if not key or not constraints:
        return False
    return all(_constraint_matches(key, constraint) for constraint in constraints)


def version_affected(version: Any, specs: list[str]) -> bool:
    """Whether ``version`` satisfies any of ``specs``."""
    return any(version_matches(version, spec) for spec in specs or [])


def validate_version_spec(spec: str) -> str:
    """``""`` when ``spec`` is well-formed, else what is wrong with it."""
    constraints = [part.strip() for part in str(spec or "").split(",") if part.strip()]
    if not constraints:
        return "empty version specification"
    for constraint in constraints:
        body = constraint
        for symbol in _OPERATORS:
            if constraint.startswith(symbol):
                body = constraint[len(symbol) :]
                break
        if ".." in body:
            low, high = body.split("..", 1)
            if not version_tokens(low) and not version_tokens(high):
                return f"range {constraint!r} has no bounds"
            continue
        if not version_tokens(body.rstrip("*")):
            return f"{constraint!r} is not a version"
    return ""


# ── Severity ─────────────────────────────────────────────────────────────────


def normalize_severity(raw: Any, default: str = "medium") -> str:
    text = str(raw or "").strip().lower()
    text = _SEVERITY_ALIASES.get(text, text)
    return text if text in _SEVERITY_RANK else default


def severity_at_least(severity: str, floor: str) -> bool:
    """Whether ``severity`` is as severe as ``floor`` or more."""
    return _SEVERITY_RANK.get(normalize_severity(severity), 99) <= _SEVERITY_RANK.get(normalize_severity(floor), 99)


# ── Classification ───────────────────────────────────────────────────────────


def classify_host(device_type: Any, model: Any, raw_version: Any) -> tuple[str, str]:
    """``(platform, version)`` of an inventory host from its driver, model
    and the version string SNMP or SSH stored for it."""
    version = canonical_version(raw_version)
    text = f"{model or ''} {raw_version or ''}".lower()
    platform = _DEVICE_TYPE_PLATFORMS.get(str(device_type or "").strip().lower(), "")
    if platform == "ios" and ("xe" in text or _IOS_XE_RELEASE.match(version)):
        platform = "ios-xe"
    if platform == "ftd" and "adaptive security" in text:
        platform = "asa"
    if not platform:
        platform = next((key for needle, key in _TEXT_PLATFORMS if needle in text), "")
    if not platform and version:
        platform = "other"
    return platform, version


def _version_row(node: dict) -> str:
    for section in node.get("sections") or []:
        if section.get("kind") != "kv":
            continue
        for row in section.get("rows") or []:
            if isinstance(row, list) and len(row) >= 2 and row[0] in VERSION_ROW_KEYS and str(row[1]).strip():
                return str(row[1]).strip()
    return ""


# A Cisco FMC snapshot; "anyconnect" is its provider key of earlier releases.
_FMC_PROVIDERS = ("fmc", "anyconnect")
# Management servers whose own node (kind "cloud") reports a version.
_MANAGER_PLATFORMS = ("fmc", "panorama")


def _snapshot_platform(provider: str, node: dict) -> str:
    kind = str(node.get("kind") or "")
    model = str(node.get("model") or "").lower()
    if provider == "meraki":
        return _MERAKI_KIND_PLATFORMS.get(kind, "meraki")
    if provider == "cato":
        return "cato-socket"
    if provider in _FMC_PROVIDERS:
        if "management center" in model:
            return "fmc"
        return "asa" if "adaptive security" in model else "ftd"
    if provider == "panorama":
        # Panorama itself, and the PAN-OS firewalls it manages (the same
        # platform as a PAN-OS firewall found in the inventory).
        return "panorama" if kind == "cloud" else "pan-os"
    if provider == "appgate":
        # Every appliance (Controller, Gateway, Portal...) runs the same image.
        return "appgate" if kind == "appliance" else ""
    return ""


def snapshot_devices(snapshot: dict, provider: str) -> list[dict[str, Any]]:
    """The devices of a topology snapshot that report a software version.

    Meraki devices carry their firmware, Cato Sockets their Socket version,
    the FTDs of a Cisco FMC their software and the FMC its own version, the
    firewalls of a Palo Alto Panorama their PAN-OS and Panorama its own, the
    appliances of an Appgate SDP collective their appliance version; all
    are read from the detail sections the snapshot already holds, so
    snapshots collected before the tracker existed are covered. Nodes
    without a version (a Cato IPsec site, a PoP, a users node) are skipped.
    AWS snapshots carry no software versions.
    """
    if provider not in ("meraki", "cato", "panorama", "appgate", *_FMC_PROVIDERS):
        return []
    site_names = {s.get("id"): s.get("name") or s.get("id") or "" for s in snapshot.get("sites") or []}
    devices: list[dict[str, Any]] = []
    for node in snapshot.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        kind = str(node.get("kind") or "")
        if kind in ("wan", "external", "vpn_peer", "users", "user", "vpc"):
            continue
        raw_version = _version_row(node)
        platform = _snapshot_platform(provider, node)
        if not raw_version or not platform or (kind == "cloud" and platform not in _MANAGER_PLATFORMS):
            continue
        version = canonical_version(raw_version)
        if not version:
            continue
        inventory = node.get("inventory") if isinstance(node.get("inventory"), dict) else {}
        devices.append(
            {
                "node_id": str(node.get("id") or ""),
                "name": str(node.get("label") or node.get("serial") or node.get("id") or ""),
                "kind": kind,
                "model": str(node.get("model") or ""),
                "serial": str(node.get("serial") or ""),
                "site": str(site_names.get(node.get("site"), "") or ""),
                "platform": platform,
                "version": version,
                "raw_version": raw_version,
                "host_id": inventory.get("host_id") if inventory else None,
            }
        )
    return devices


# ── Advisory matching ────────────────────────────────────────────────────────


def advisory_applies(device: dict, advisory: dict) -> bool:
    """Whether ``advisory`` names the platform, product and version of
    ``device``. An advisory without a platform applies to every platform;
    ``product_match`` is a case-insensitive substring of the model."""
    if not advisory.get("enabled", True):
        return False
    platform = str(advisory.get("platform") or "")
    if platform and platform != str(device.get("platform") or ""):
        return False
    product = str(advisory.get("product_match") or "").strip().lower()
    if product and product not in str(device.get("model") or "").lower():
        return False
    return version_affected(device.get("version"), list(advisory.get("affected_versions") or []))


def find_advisory_matches(devices: list[dict], advisories: list[dict]) -> list[dict[str, Any]]:
    """Every ``(device_key, advisory_id, severity)`` where the advisory
    applies to the device, most severe first."""
    matches: list[dict[str, Any]] = []
    for device in devices:
        for advisory in advisories:
            if advisory_applies(device, advisory):
                matches.append(
                    {
                        "device_key": device["device_key"],
                        "advisory_id": advisory["advisory_id"],
                        "severity": normalize_severity(advisory.get("severity")),
                    }
                )
    matches.sort(key=lambda m: (_SEVERITY_RANK[m["severity"]], m["device_key"], m["advisory_id"]))
    return matches


def version_spread(devices: list[dict]) -> list[dict[str, Any]]:
    """Per platform: how many devices run each version, the newest version
    seen and the most common one, newest version first."""
    by_platform: dict[str, dict[str, int]] = {}
    for device in devices:
        platform = str(device.get("platform") or "other")
        version = str(device.get("version") or "")
        if not version:
            continue
        by_platform.setdefault(platform, {})
        by_platform[platform][version] = by_platform[platform].get(version, 0) + 1
    spread: list[dict[str, Any]] = []
    for platform, counts in by_platform.items():
        newest = newest_version(list(counts))
        most_common = max(counts, key=lambda v: (counts[v], version_tokens(v)))
        total = sum(counts.values())
        versions = [
            {"version": version, "count": count, "behind_newest": version != newest}
            for version, count in sorted(counts.items(), key=lambda item: version_tokens(item[0]), reverse=True)
        ]
        spread.append(
            {
                "platform": platform,
                "label": PLATFORMS.get(platform, PLATFORMS["other"])["label"],
                "device_count": total,
                "version_count": len(counts),
                "newest_version": newest,
                "most_common_version": most_common,
                "behind_newest": total - counts[newest],
                "versions": versions,
            }
        )
    spread.sort(key=lambda p: (-p["device_count"], p["label"]))
    return spread
