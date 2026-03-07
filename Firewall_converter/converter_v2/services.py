from __future__ import annotations

from typing import Any

from Firewall_converter.FortiGateToFTDTool.service_converter import ServiceConverter

from .models import FTDServiceObject


def convert_services_v2(fortigate_config: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert FortiGate service objects using a typed v2 adapter.

    This keeps legacy conversion behavior for parity while introducing typed
    v2 internals as a migration step.
    """
    legacy_output = ServiceConverter(fortigate_config).convert()
    typed_objects = [FTDServiceObject.from_legacy(item) for item in legacy_output]
    return [item.to_legacy_dict() for item in typed_objects]
