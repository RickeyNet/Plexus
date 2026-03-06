from __future__ import annotations

from typing import Any

from Firewall_converter.FortiGateToFTDTool.service_group_converter import ServiceGroupConverter

from .models import FTDServiceGroupObject


def convert_service_groups_v2(
    fortigate_config: dict[str, Any],
    split_services: set[str] | None = None,
    service_name_mapping: dict[str, list[tuple[str, str]]] | None = None,
    skipped_services: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert FortiGate service groups using a typed v2 adapter."""
    normalized_split_services = split_services or set()
    normalized_service_name_mapping = service_name_mapping or {}
    normalized_skipped_services = skipped_services or set()

    legacy_output = ServiceGroupConverter(
        fortigate_config=fortigate_config,
        split_services=normalized_split_services,
        service_name_mapping=normalized_service_name_mapping,
        skipped_services=normalized_skipped_services,
    ).convert()
    typed_objects = [FTDServiceGroupObject.from_legacy(item) for item in legacy_output]
    return [item.to_legacy_dict() for item in typed_objects]
