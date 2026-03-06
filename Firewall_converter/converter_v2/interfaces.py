from __future__ import annotations

from typing import Any

from Firewall_converter.converter_v2.core.interface_converter import InterfaceConverter

from .models import FTDInterfaceBundle


def convert_interfaces_v2(
    fortigate_config: dict[str, Any],
    target_model: str = "ftd-3120",
    custom_ha_port: str | None = None,
) -> dict[str, Any]:
    """Convert FortiGate interfaces using a typed v2 adapter."""
    normalized_custom_ha_port = custom_ha_port or ""
    legacy_output = InterfaceConverter(
        fortigate_config=fortigate_config,
        target_model=target_model,
        custom_ha_port=normalized_custom_ha_port,
    ).convert()
    typed_bundle = FTDInterfaceBundle.from_legacy(legacy_output)
    return typed_bundle.to_legacy_dict()
