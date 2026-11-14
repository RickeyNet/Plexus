"""Device model rules (``netcontrol.device_model``), no database."""

from __future__ import annotations

import pytest
from netcontrol.custom_fields import CustomFieldError, clean_tag_name
from netcontrol.device_model import (
    DEVICE_FILTER_KEYS,
    MANUFACTURER_PREFIXES,
    MAX_ID,
    UNKNOWN_MANUFACTURER,
    clean_name,
    manufacturer_name,
    parse_device_filters,
)


@pytest.mark.parametrize(
    ("vendor", "device_type", "expected"),
    [
        ("", "cisco_ios", "Cisco"),
        ("", "cisco_xe", "Cisco"),
        ("", "CISCO_NXOS", "Cisco"),
        ("", "juniper_junos", "Juniper"),
        ("", "arista_eos", "Arista"),
        ("", "fortinet", "Fortinet"),
        ("", "paloalto_panos", "Palo Alto Networks"),
        ("", "meraki", "Cisco Meraki"),
        ("", "hp_procurve", "HPE"),
        ("", "linux", UNKNOWN_MANUFACTURER),
        ("", "", UNKNOWN_MANUFACTURER),
        ("Cisco Systems", "unknown", "Cisco"),
        ("Palo Alto Networks", "", "Palo Alto Networks"),
        ("juniper", "cisco_ios", "Juniper"),
        ("unknown", "arista_eos", "Arista"),
        ("  ", "fortinet_fortios", "Fortinet"),
        ("Example Corp", "", UNKNOWN_MANUFACTURER),
    ],
)
def test_manufacturer_name(vendor, device_type, expected):
    assert manufacturer_name(vendor, device_type) == expected


def test_every_driver_package_has_a_manufacturer():
    from pathlib import Path

    import netcontrol.drivers as drivers

    names = [
        p.stem for p in Path(drivers.__file__).parent.glob("*.py") if p.stem not in ("__init__", "base", "show_version")
    ]
    assert names
    for name in names:
        assert manufacturer_name("", name) != UNKNOWN_MANUFACTURER, name


def test_migration_carries_the_same_prefix_table():
    import importlib

    migration = importlib.import_module("routes.migrations.0085_add_device_model")
    assert migration._MANUFACTURER_PREFIXES == MANUFACTURER_PREFIXES


def test_clean_name():
    assert clean_name("  Core  ", "Role name", 50) == "Core"
    with pytest.raises(CustomFieldError, match="Role name must not be empty"):
        clean_name("   ", "Role name", 50)
    with pytest.raises(CustomFieldError, match="must not be empty"):
        clean_name(None, "Role name", 50)
    with pytest.raises(CustomFieldError, match="at most 5 characters"):
        clean_name("abcdef", "Model", 5)
    assert clean_name("abcde", "Model", 5) == "abcde"


def test_clean_tag_name_still_uses_its_own_label():
    assert clean_tag_name(" edge ") == "edge"
    with pytest.raises(CustomFieldError, match="Tag name must not be empty"):
        clean_tag_name("")
    with pytest.raises(CustomFieldError, match="Tag name must be at most 50"):
        clean_tag_name("x" * 51)


def test_parse_device_filters_ids_and_none():
    filters, errors = parse_device_filters(
        [
            ("role_id", "2"),
            ("role_id", "none"),
            ("role_id", "2"),
            ("site_id", " NONE "),
            ("manufacturer_id", "7"),
            ("tag", "core"),
            ("cf.owner", "net"),
        ]
    )
    assert errors == {}
    assert filters == {"role_id": [2, None], "site_id": [None], "manufacturer_id": [7]}


@pytest.mark.parametrize("raw", ["", "abc", "-1", "0", "1.5", str(MAX_ID + 1), "١"])
def test_parse_device_filters_rejects_bad_values(raw):
    filters, errors = parse_device_filters([("device_type_id", raw), ("role_id", "3")])
    assert set(errors) == {"device_type_id"}
    assert "none" in errors["device_type_id"]
    assert filters == {"role_id": [3]}


def test_parse_device_filters_accepts_the_largest_id():
    filters, errors = parse_device_filters([("lifecycle_status_id", str(MAX_ID))])
    assert errors == {} and filters == {"lifecycle_status_id": [MAX_ID]}


def test_filter_keys():
    assert DEVICE_FILTER_KEYS == ("manufacturer_id", "device_type_id", "role_id", "lifecycle_status_id", "site_id")
