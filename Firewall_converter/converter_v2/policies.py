from __future__ import annotations

from typing import Any

from Firewall_converter.FortiGateToFTDTool.policy_converter import PolicyConverter

from .models import FTDAccessRuleObject


def convert_policies_v2(
    fortigate_config: dict[str, Any],
    split_services: set[str] | None = None,
    service_name_mapping: dict[str, list[tuple[str, str]]] | None = None,
    skipped_services: set[str] | None = None,
    address_name_mapping: dict[str, str] | None = None,
    address_group_members: dict[str, list[str]] | None = None,
    address_groups: set[str] | None = None,
    service_groups: set[str] | None = None,
    interface_name_mapping: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Convert FortiGate policies using a typed v2 adapter."""
    normalized_split_services = split_services or set()
    normalized_service_name_mapping = service_name_mapping or {}
    normalized_skipped_services = skipped_services or set()
    normalized_address_name_mapping = address_name_mapping or {}
    normalized_address_group_members = address_group_members or {}
    normalized_address_groups = address_groups or set()
    normalized_service_groups = service_groups or set()
    normalized_interface_name_mapping = interface_name_mapping or {}

    legacy_output = PolicyConverter(
        fortigate_config=fortigate_config,
        split_services=normalized_split_services,
        service_name_mapping=normalized_service_name_mapping,
        skipped_services=normalized_skipped_services,
        address_name_mapping=normalized_address_name_mapping,
        address_group_members=normalized_address_group_members,
        address_groups=normalized_address_groups,
        service_groups=normalized_service_groups,
        interface_name_mapping=normalized_interface_name_mapping,
    ).convert()
    typed_objects = [FTDAccessRuleObject.from_legacy(item) for item in legacy_output]
    return [item.to_legacy_dict() for item in typed_objects]
