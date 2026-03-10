# Firewall Converter Deprecation Notes

This project now treats `converter_v2` as the primary converter implementation.

## Current Status

- Active converter implementation: `Firewall_converter/converter_v2/core/`
- Active converter entrypoint: `Firewall_converter/converter_v2/fortigate_converter_v2.py`
- Legacy converter entrypoint: removed (`FortiGateToFTDTool/fortigate_converter.py`)

## Freeze Policy

The following modules in `Firewall_converter/FortiGateToFTDTool/` are frozen for
compatibility and should not receive new conversion features:

- `address_converter.py`
- `address_group_converter.py`
- `service_converter.py`
- `service_group_converter.py`
- `interface_converter.py`
- `route_converter.py`
- `policy_converter.py`

Allowed changes in the frozen modules:

- Critical bug fixes that unblock production usage
- Safety fixes
- Behavior-preserving cleanup needed for maintenance

All new conversion behavior and feature work must be implemented under
`Firewall_converter/converter_v2/core/` and wired through the v2 adapter/entrypoint.

## Import/Cleanup Scope

`FortiGateToFTDTool` still owns importer/cleanup tooling and remains active for:

- `ftd_api_importer.py`
- `ftd_api_cleanup.py`
- `concurrency_utils.py`

These scripts remain in place and are not deprecated.