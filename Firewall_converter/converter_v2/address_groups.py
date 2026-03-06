from __future__ import annotations

from typing import Any

from Firewall_converter.converter_v2.core.address_group_converter import AddressGroupConverter

from .models import FTDAddressGroupObject


def convert_address_groups_v2(
    fortigate_config: dict[str, Any],
    address_object_names: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert FortiGate address groups using a typed v2 adapter."""
    normalized_address_object_names = address_object_names or set()
    legacy_output = AddressGroupConverter(
        fortigate_config=fortigate_config,
        address_object_names=normalized_address_object_names,
    ).convert()
    typed_objects = [FTDAddressGroupObject.from_legacy(item) for item in legacy_output]
    return [item.to_legacy_dict() for item in typed_objects]
