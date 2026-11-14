"""Device model for hosts: the constants and rules, with no I/O.

A host points at four managed records (a device type with its
manufacturer, a role, a lifecycle status, a site) plus free-text location
detail. This module holds what both the storage layer
(``routes.db.device_model``) and the API (``netcontrol.routes.device_model``)
need: the manufacturer name a discovered device gets, the name limits, and
the parsing of the list filters.

``hosts.device_type`` (the SSH driver key) and ``hosts.status`` (polled
reachability) are not part of this model and keep their meaning.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from netcontrol.custom_fields import TAG_NAME_MAX, TEXT_MAX, clean_name

__all__ = [
    "DESCRIPTION_MAX",
    "DEVICE_FILTER_KEYS",
    "HOST_DEVICE_FIELDS",
    "HOST_DEVICE_ID_FIELDS",
    "LOCATION_DETAIL_MAX",
    "MANUFACTURER_NAME_MAX",
    "MANUFACTURER_PREFIXES",
    "MAX_ID",
    "MODEL_MAX",
    "PART_NUMBER_MAX",
    "ROLE_NAME_MAX",
    "UNKNOWN_MANUFACTURER",
    "U_HEIGHT_MAX",
    "clean_name",
    "manufacturer_name",
    "parse_device_filters",
]

MANUFACTURER_NAME_MAX = 100
MODEL_MAX = 100
PART_NUMBER_MAX = 100
U_HEIGHT_MAX = 100
# Roles and statuses share the tag name limit and the tag color palette.
ROLE_NAME_MAX = TAG_NAME_MAX
DESCRIPTION_MAX = TEXT_MAX
LOCATION_DETAIL_MAX = 200
# The largest id a Postgres INTEGER column holds.
MAX_ID = 2_147_483_647

UNKNOWN_MANUFACTURER = "Unknown"

# A vendor word or driver key prefix, and the manufacturer it names. First
# match wins. Migration 0085 carries its own copy for the backfill; keep the
# two in step when adding a vendor.
MANUFACTURER_PREFIXES: tuple[tuple[str, str], ...] = (
    ("meraki", "Cisco Meraki"),
    ("cisco", "Cisco"),
    ("juniper", "Juniper"),
    ("arista", "Arista"),
    ("fortinet", "Fortinet"),
    ("paloalto", "Palo Alto Networks"),
    ("aruba", "Aruba"),
    ("hp", "HPE"),
    ("dell", "Dell"),
    ("extreme", "Extreme Networks"),
    ("huawei", "Huawei"),
    ("mikrotik", "MikroTik"),
    ("checkpoint", "Check Point"),
    ("f5", "F5"),
    ("ubiquiti", "Ubiquiti"),
    ("vyos", "VyOS"),
)

# The stored host values of the model; a host write may send any of them.
HOST_DEVICE_ID_FIELDS: tuple[str, ...] = ("device_type_id", "role_id", "lifecycle_status_id", "site_id")
HOST_DEVICE_FIELDS: tuple[str, ...] = (*HOST_DEVICE_ID_FIELDS, "location_detail")

# List filters: the host fields plus the manufacturer of the device type.
DEVICE_FILTER_KEYS: tuple[str, ...] = ("manufacturer_id", *HOST_DEVICE_ID_FIELDS)
NONE_FILTER = "none"

_NOT_ALNUM = re.compile(r"[^a-z0-9]+")


def _match(text: str) -> str | None:
    key = _NOT_ALNUM.sub("", (text or "").lower())
    if not key:
        return None
    for prefix, name in MANUFACTURER_PREFIXES:
        if key.startswith(prefix):
            return name
    return None


def manufacturer_name(vendor: str, device_type: str) -> str:
    """The manufacturer of a device from its vendor text (``"Cisco
    Systems"``) or, failing that, its driver key (``"cisco_xe"``);
    ``"Unknown"`` when neither names a known vendor."""
    return _match(vendor) or _match(device_type) or UNKNOWN_MANUFACTURER


def parse_device_filters(items: Iterable[tuple[str, str]]) -> tuple[dict[str, list[int | None]], dict[str, str]]:
    """The device filters among query string ``items``.

    Returns ``(filters, errors)``: ``filters`` maps each key of
    ``DEVICE_FILTER_KEYS`` that was given to its values, an id or ``None``
    for ``none`` (no value); ``errors`` maps a key to a message for each
    value that is neither. Other keys are ignored.
    """
    filters: dict[str, list[int | None]] = {}
    errors: dict[str, str] = {}
    for key, raw in items:
        if key not in DEVICE_FILTER_KEYS:
            continue
        text = (raw or "").strip().lower()
        value: int | None
        if text == NONE_FILTER:
            value = None
        elif text.isascii() and text.isdigit() and 0 < int(text) <= MAX_ID:
            value = int(text)
        else:
            errors[key] = f"{key} must be an id or '{NONE_FILTER}'."
            continue
        values = filters.setdefault(key, [])
        if value not in values:
            values.append(value)
    return filters, errors
