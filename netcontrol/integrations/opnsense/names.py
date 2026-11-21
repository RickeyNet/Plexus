"""OPNsense DNS names and DHCP reservations, read from ``config.xml``.

The collection parses them from the ``config.xml`` it downloads for the
**Config backup** option (``collector.collect_opnsense``, under the raw key
``names``) and ``netcontrol.routes.opnsense_collection.store_names`` keeps
them as the allocations of the firewall's IPAM source. Without config.xml
(the option off, the download refused) nothing is read: no API call and no
privilege beyond the configuration download is used.

What is read (checked against ``opnsense/core`` master, OPNsense 25.7 / 26.1
era, and the 20.7, 24.7 and 25.1 tags for the older layouts):

  - Unbound host overrides: the MVC model ``models/OPNsense/Unbound/
    Unbound.xml`` mounted at ``//OPNsense/unboundplus``, ``hosts/host``
    (``enabled``, ``hostname``, ``domain``, ``rr``, ``server``,
    ``description``) and ``aliases/alias`` (``enabled``, ``host``: the uuid of
    its host override, ``hostname`` / ``domain`` / ``description``, each
    falling back to the host's as ``plugins.inc.d/unbound.inc`` does). Only
    A / AAAA records with an address are names; MX and TXT records, disabled
    entries and wildcard (``*``) names are left out; an empty host name is the
    domain itself. Read only while ``general/enabled`` is ``1`` (Unbound
    serves nothing otherwise). The pre-MVC layout (20.7 and older,
    ``unbound/hosts``: ``host``, ``domain``, ``rr``, ``ip``, ``descr``,
    ``aliases/item`` with ``host`` / ``domain`` / ``descr``) is read while
    ``unbound/enable`` is set.
  - Dnsmasq hosts: ``dnsmasq/hosts`` (MVC model ``Dnsmasq/Dnsmasq.xml``
    mounted at ``/dnsmasq`` from 25.7; the same element names before):
    ``host``, ``domain``, ``ip`` (a comma list from 25.7), ``hwaddr`` (a
    comma list), ``client_id``, ``ignore``, ``descr`` and ``aliases`` (a
    comma list, or the legacy ``aliases/item`` with ``host`` / ``domain``).
    Read only while ``dnsmasq/enable`` is set; partial IPv6 addresses
    (``::10``) are skipped as ``plugins.inc.d/dnsmasq.inc`` does. A host with
    a hardware address or client id is a DHCP reservation when Dnsmasq has a
    DHCP range and the host is not ``ignore``-d.
  - ISC DHCP static mappings: ``dhcpd/<interface>/staticmap`` (``mac``,
    ``cid``, ``ipaddr``, ``hostname``, ``domain``, ``descr``) and
    ``dhcpdv6/<interface>/staticmap`` (``duid``, ``ipaddrv6``, ``hostname``,
    ``domainsearchlist``, ``descr``), as ``dhcpd_staticmap`` in
    ``plugins.inc.d/dhcpd.inc`` (core up to 25.7, the ``os-isc-dhcp``
    plugin since) returns them: only on an interface whose DHCP service is
    enabled, only with an address; the domain is the mapping's, else the
    interface's, first entry only. An IPv6 mapping on a ``track6``
    interface holds only a suffix and is skipped.
  - Kea reservations: ``//OPNsense/Kea/dhcp4/reservations/reservation``
    (``subnet``: the uuid of a ``subnets/subnet4``, ``ip_address``,
    ``hw_address``, ``client_id``, ``hostname``, ``description``,
    ``option_data/domain_name``) and ``//OPNsense/Kea/dhcp6/reservations/
    reservation`` (``ip_address``, ``duid``, ``hw_address``, ``hostname``,
    ``domain_search``, ``description``), read only while that service's
    ``general/enabled`` is ``1``.

A host name without a dot is qualified with the entry's domain, else the
system domain (``system/domain``), the way Unbound and Dnsmasq register
static mappings. Nothing here is secret (names, addresses, MAC / DUID /
client ids, descriptions); the XML itself never leaves the collector.
"""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree  # nosec B405 - types only; parsing goes through safe_xml
from collections.abc import Callable
from typing import Any

from netcontrol.integrations.meraki.clients import normalize_mac
from netcontrol.integrations.pathtrace.opnsense_config import parse_xml
from netcontrol.sync.transport import canonical_address

# Where a name or reservation comes from, in the order their names are
# preferred for an address (an explicit DNS record first).
ORIGIN_UNBOUND = "unbound"
ORIGIN_DNSMASQ = "dnsmasq"
ORIGIN_ISC = "isc"
ORIGIN_KEA = "kea"
ORIGINS: tuple[tuple[str, str], ...] = (
    (ORIGIN_UNBOUND, "Unbound host override"),
    (ORIGIN_DNSMASQ, "Dnsmasq host"),
    (ORIGIN_ISC, "ISC DHCP static mapping"),
    (ORIGIN_KEA, "Kea reservation"),
)
ORIGIN_LABELS = dict(ORIGINS)
_ORDER = {key: index for index, (key, _label) in enumerate(ORIGINS)}

# The ``status`` of the IPAM allocations (NetBox's IP address statuses, which
# IPAM shows as they are): a DHCP reservation holds its address for a client.
STATUS_RESERVED = "reserved"
STATUS_ACTIVE = "active"

_ON = ("1", "yes", "on", "true")


def _text(element: ElementTree.Element | None, path: str) -> str:
    if element is None:
        return ""
    found = element.find(path)
    return (found.text or "").strip() if found is not None else ""


def _set(element: ElementTree.Element | None, path: str) -> bool:
    """A legacy flag (``<enable/>``, ``<enable>1</enable>``): present and not ``0``."""
    if element is None:
        return False
    found = element.find(path)
    return found is not None and (found.text or "").strip().lower() not in ("0", "no", "off", "false")


def _on(element: ElementTree.Element | None, path: str) -> bool:
    """An MVC boolean (``1`` / ``0``): on only when ``1``."""
    return _text(element, path).lower() in _ON


def _split(value: str) -> list[str]:
    return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]


def _address(value: str) -> str:
    try:
        return canonical_address(value)
    except ValueError:
        return ""


def _fqdn(host: str, domain: str, fallback: str = "") -> str:
    """``host.domain`` lower case, the domain alone for an empty host, ``""``
    for a wildcard or nothing. A host with a dot is already qualified."""
    host, domain = host.strip().rstrip(".").lower(), (domain or fallback).strip().strip(".").lower()
    if "*" in host or "*" in domain:
        return ""
    if not host:
        return domain
    if "." in host or not domain:
        return host
    return f"{host}.{domain}"


def _entry(
    origin: str,
    address: str,
    names: list[str],
    description: str = "",
    *,
    reserved: bool = False,
    mac: str = "",
    duid: str = "",
    client_id: str = "",
    interface: str = "",
    subnet: str = "",
) -> dict[str, Any] | None:
    canonical = _address(address)
    if not canonical:
        return None
    return {
        "address": canonical,
        "origin": origin,
        "names": [n for n in dict.fromkeys(names) if n],
        "description": description.strip(),
        "reserved": reserved,
        "mac": normalize_mac(mac),
        "duid": duid.strip().lower(),
        "client_id": client_id.strip().lower(),
        "interface": interface,
        "subnet": subnet,
    }


# ── Unbound ──────────────────────────────────────────────────────────────────


def _unbound(root: ElementTree.Element, system_domain: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    model = root.find("OPNsense/unboundplus")
    if model is not None and _on(model, "general/enabled"):
        aliases: dict[str, list[ElementTree.Element]] = {}
        for alias in model.findall("aliases/alias"):
            if _on(alias, "enabled"):
                aliases.setdefault(_text(alias, "host"), []).append(alias)
        for host in model.findall("hosts/host"):
            rr = _text(host, "rr").upper() or "A"
            if not _on(host, "enabled") or rr not in ("A", "AAAA"):
                continue
            hostname, domain = _text(host, "hostname"), _text(host, "domain")
            names = [_fqdn(hostname, domain)]
            for alias in aliases.get(str(host.get("uuid") or "").strip(), []):
                names.append(_fqdn(_text(alias, "hostname") or hostname, _text(alias, "domain") or domain))
            entry = _entry(ORIGIN_UNBOUND, _text(host, "server"), names, _text(host, "description"))
            if entry is not None and entry["names"]:
                found.append(entry)
    legacy = root.find("unbound")
    if legacy is not None and _set(legacy, "enable"):
        for host in legacy.findall("hosts"):
            rr = _text(host, "rr").upper()
            if rr and rr not in ("A", "AAAA"):
                continue
            hostname, domain = _text(host, "host"), _text(host, "domain")
            names = [_fqdn(hostname, domain)]
            for alias in host.findall("aliases/item"):
                names.append(_fqdn(_text(alias, "host") or hostname, _text(alias, "domain") or domain))
            entry = _entry(ORIGIN_UNBOUND, _text(host, "ip"), names, _text(host, "descr"))
            if entry is not None and entry["names"]:
                found.append(entry)
    return found


# ── Dnsmasq ──────────────────────────────────────────────────────────────────


def _dnsmasq(root: ElementTree.Element, system_domain: str) -> list[dict[str, Any]]:
    service = root.find("dnsmasq")
    if service is None or not _set(service, "enable"):
        return []
    serves_dhcp = any(len(ranges) for ranges in service.findall("dhcp_ranges"))
    found: list[dict[str, Any]] = []
    for host in service.findall("hosts"):
        hostname, domain = _text(host, "host"), _text(host, "domain")
        if not hostname or hostname == "*":
            continue
        names = [_fqdn(hostname, domain, system_domain)]
        items = host.findall("aliases/item")
        if items:
            names += [_fqdn(_text(i, "host"), _text(i, "domain") or domain) for i in items]
        else:
            names += [_fqdn(a, "") for a in _split(_text(host, "aliases"))]
        macs = _split(_text(host, "hwaddr"))
        client_id = _text(host, "client_id")
        client_id = "" if client_id == "*" else client_id
        reserved = serves_dhcp and not _on(host, "ignore") and bool(macs or client_id)
        for ip in _split(_text(host, "ip")):
            if ip.startswith("::"):
                continue  # a partial IPv6 address (a suffix)
            entry = _entry(
                ORIGIN_DNSMASQ,
                ip,
                names,
                _text(host, "descr"),
                reserved=reserved,
                mac=macs[0] if macs else "",
                client_id=client_id,
            )
            if entry is not None:
                found.append(entry)
    return found


# ── ISC DHCP ─────────────────────────────────────────────────────────────────


def _interface_label(root: ElementTree.Element, key: str) -> str:
    return _text(root.find(f"interfaces/{key}"), "descr") or key


def _isc(root: ElementTree.Element, system_domain: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for section, inet in (("dhcpd", 4), ("dhcpdv6", 6)):
        holder = root.find(section)
        for interface in list(holder) if holder is not None else []:
            if not _set(interface, "enable"):
                continue
            key = interface.tag
            if inet == 6 and _text(root.find(f"interfaces/{key}"), "ipaddrv6").lower() == "track6":
                continue  # the mappings hold a suffix of a prefix config.xml does not know
            for mapping in interface.findall("staticmap"):
                address = _text(mapping, "ipaddr" if inet == 4 else "ipaddrv6")
                if not address:
                    continue
                domain = (
                    (_text(mapping, "domainsearchlist") if inet == 6 else "")
                    or _text(mapping, "domain")
                    or (_text(interface, "domainsearchlist") if inet == 6 else "")
                    or _text(interface, "domain")
                )
                domain = domain.replace(";", " ").split()[0] if domain.strip() else ""
                hostname = _text(mapping, "hostname").replace(" ", "_")
                entry = _entry(
                    ORIGIN_ISC,
                    address,
                    [_fqdn(hostname, domain, system_domain)] if hostname else [],
                    _text(mapping, "descr"),
                    reserved=True,
                    mac=_text(mapping, "mac"),
                    duid=_text(mapping, "duid"),
                    client_id=_text(mapping, "cid"),
                    interface=_interface_label(root, key),
                )
                if entry is not None:
                    found.append(entry)
    return found


# ── Kea ──────────────────────────────────────────────────────────────────────


def _kea(root: ElementTree.Element, system_domain: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for family, subnet_tag in (("dhcp4", "subnet4"), ("dhcp6", "subnet6")):
        model = root.find(f"OPNsense/Kea/{family}")
        if model is None or not _on(model, "general/enabled"):
            continue
        subnets = {str(s.get("uuid") or "").strip(): s for s in model.findall(f"subnets/{subnet_tag}")}
        for reservation in model.findall("reservations/reservation"):
            subnet = subnets.get(_text(reservation, "subnet"))
            if family == "dhcp4":
                domain = _text(reservation, "option_data/domain_name") or _text(subnet, "option_data/domain_name")
            else:
                domain = next(iter(_split(_text(reservation, "domain_search"))), "") or next(
                    iter(_split(_text(subnet, "option_data/domain_search"))), ""
                )
            hostname = _text(reservation, "hostname")
            entry = _entry(
                ORIGIN_KEA,
                _text(reservation, "ip_address"),
                [_fqdn(hostname, domain, system_domain)] if hostname else [],
                _text(reservation, "description"),
                reserved=True,
                mac=_text(reservation, "hw_address"),
                duid=_text(reservation, "duid"),
                client_id=_text(reservation, "client_id"),
                interface=_text(subnet, "description"),
                subnet=_text(subnet, "subnet"),
            )
            if entry is not None:
                found.append(entry)
    return found


# ── Records ──────────────────────────────────────────────────────────────────


def _merge(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One record per address: the names of every entry (the preferred
    origin's first), its origins, the first description, MAC, DUID, client
    id and DHCP interface found, and whether any entry reserves it."""
    by_address: dict[str, dict[str, Any]] = {}
    for entry in sorted(entries, key=lambda e: _ORDER.get(e["origin"], len(_ORDER))):
        record = by_address.setdefault(
            entry["address"],
            {
                "address": entry["address"],
                "names": [],
                "origins": [],
                "description": "",
                "reserved": False,
                "mac": "",
                "duid": "",
                "client_id": "",
                "interface": "",
                "subnet": "",
            },
        )
        record["names"] += [n for n in entry["names"] if n not in record["names"]]
        if entry["origin"] not in record["origins"]:
            record["origins"].append(entry["origin"])
        record["reserved"] = record["reserved"] or entry["reserved"]
        for key in ("description", "mac", "duid", "client_id", "interface", "subnet"):
            record[key] = record[key] or entry[key]
    return list(by_address.values())


def names_from_config(config_xml: str | None) -> dict[str, Any] | None:
    """The DNS names and DHCP reservations of a ``config.xml``: ``records``
    (one per address, see ``_merge``) and ``counts`` (entries read per
    origin). ``None`` when the text is no OPNsense configuration."""
    root = parse_xml(config_xml or "")
    if root is None:
        return None
    system_domain = _text(root, "system/domain")
    entries: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for origin, reader in (
        (ORIGIN_UNBOUND, _unbound),
        (ORIGIN_DNSMASQ, _dnsmasq),
        (ORIGIN_ISC, _isc),
        (ORIGIN_KEA, _kea),
    ):
        found = reader(root, system_domain)
        counts[origin] = len(found)
        entries += found
    return {"records": _merge(entries), "counts": counts}


def ipam_allocations(
    records: list[dict[str, Any]], subnet_of: Callable[[str], str] | None = None
) -> list[dict[str, Any]]:
    """The records as allocations of ``db.replace_ipam_source_snapshot``:
    ``dns_name`` the first name, ``status`` ``reserved`` for a DHCP
    reservation (``active`` for a DNS name only), the description and the
    rest in ``metadata``. ``subnet_of(address)`` answers the
    ``prefix_subnet`` (the firewall subnet that holds the address, ``""``)."""
    allocations: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict) or not record.get("address"):
            continue
        names = [str(n) for n in record.get("names") or []]
        origins = [str(o) for o in record.get("origins") or []]
        metadata: dict[str, Any] = {
            "source": "opnsense",
            "origins": [ORIGIN_LABELS.get(o, o) for o in origins],
            "names": names,
        }
        for key in ("mac", "duid", "client_id", "interface", "subnet"):
            if record.get(key):
                metadata["dhcp_" + key if key in ("interface", "subnet") else key] = record[key]
        allocations.append(
            {
                "address": record["address"],
                "prefix_subnet": subnet_of(record["address"]) if subnet_of else "",
                "dns_name": names[0] if names else "",
                "status": STATUS_RESERVED if record.get("reserved") else STATUS_ACTIVE,
                "description": record.get("description") or "",
                "metadata": metadata,
            }
        )
    return allocations
