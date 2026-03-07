from __future__ import annotations

from typing import Any

from Firewall_converter.FortiGateToFTDTool.address_converter import AddressConverter

from .models import FTDAddressObject


def convert_addresses_v2(fortigate_config: dict[str, Any]) -> list[dict[str, str]]:
    """Convert FortiGate address objects using a typed v2 adapter.

    This v2 path intentionally reuses v1 conversion behavior for parity,
    then normalizes the output into typed models before exporting legacy
    payload dictionaries. That lets us refactor internals incrementally
    without changing current operator-visible output.
    """
    legacy_output = AddressConverter(fortigate_config).convert()
    typed_objects = [FTDAddressObject.from_legacy(item) for item in legacy_output]
    return [item.to_legacy_dict() for item in typed_objects]
