#!/usr/bin/env python3
"""Fail CI when critical module coverage drops below defined thresholds.

Usage:
  python tools/coverage_gate.py coverage.json
  python tools/coverage_gate.py coverage.json netcontrol/app.py:49
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DEFAULT_RULES = {
    "netcontrol/app.py": 49.0,
    # Floor from tests/test_monitoring.py (alert eval, suppression,
    # availability, escalation). Raise as endpoint/poller tests land.
    "netcontrol/routes/monitoring.py": 20.0,
    # Floor from tests/test_jobs.py (param coercion, queue ordering,
    # dependency gating, event writer). The runner itself is untested.
    "netcontrol/routes/jobs.py": 25.0,
    # Typed job inputs and per-job run/commit permissions: the rules.
    # Measured by tests/test_job_inputs.py (93%); do not lower it to land
    # a change.
    "netcontrol/job_inputs.py": 90.0,
    # The shared four-eyes approval rules (jobs and deployments). Measured
    # by tests/test_job_approvals.py (100%); do not lower it to land a change.
    "netcontrol/approvals.py": 95.0,
    # AI access (MCP): the token check, the dispatcher every call goes
    # through and the secret masking. Floors sit a few points under what
    # tests/test_mcp_*.py measure; do not lower them to land a change.
    "netcontrol/mcp/auth.py": 95.0,
    "netcontrol/mcp/dispatch.py": 90.0,
    "netcontrol/mcp/redact.py": 90.0,
    "netcontrol/mcp/registry.py": 95.0,
    "netcontrol/mcp/server.py": 85.0,
    "netcontrol/routes/mcp_tokens.py": 90.0,
    # Custom fields and tags: the value rules and the API. Measured by
    # tests/test_custom_fields_*.py; do not lower them to land a change.
    "netcontrol/custom_fields.py": 95.0,
    "netcontrol/routes/custom_fields.py": 85.0,
    # Device model: the rules and the API. Measured by
    # tests/test_device_model_*.py; do not lower them to land a change.
    "netcontrol/device_model.py": 95.0,
    "netcontrol/routes/device_model.py": 85.0,
    # VRF and VLAN records and interface addresses: the rules and the API.
    # Measured by tests/test_network_objects_*.py; do not lower them to
    # land a change.
    "netcontrol/network_objects.py": 95.0,
    "netcontrol/routes/network_objects.py": 85.0,
    # Routing objects (intended BGP state): the rules and compliance, the
    # storage and the API. Measured by tests/test_routing.py (99%, 93%,
    # 82%+); do not lower them to land a change.
    "netcontrol/routing.py": 95.0,
    "routes/db/routing.py": 88.0,
    "netcontrol/routes/routing.py": 80.0,
    # Sync framework: the diff engine and models, the adapters against fake
    # APIs, the runner, storage and API. Measured by
    # tests/test_sync_framework.py (99%, 89%, 74-92%, 75%, 88%, 82%); do not
    # lower them to land a change.
    "netcontrol/sync/engine.py": 95.0,
    "netcontrol/sync/models.py": 85.0,
    "netcontrol/sync/transport.py": 70.0,
    "netcontrol/sync/adapters/base.py": 85.0,
    "netcontrol/sync/adapters/netbox.py": 88.0,
    "netcontrol/sync/adapters/servicenow.py": 85.0,
    "netcontrol/sync/adapters/plexus.py": 70.0,
    "netcontrol/sync/runner.py": 70.0,
    "netcontrol/routes/sync.py": 78.0,
    "routes/db/sync.py": 85.0,
    # Circuits: the rules, storage and API. Measured by
    # tests/test_circuits.py; do not lower them to land a change.
    "netcontrol/circuits.py": 95.0,
    "netcontrol/routes/circuits.py": 90.0,
    "routes/db/circuits.py": 90.0,
    # Physical DCIM: the rules (fit, elevation, trace, power), storage and
    # API. Measured by tests/test_dcim.py; do not lower them to land a
    # change.
    "netcontrol/dcim.py": 95.0,
    "netcontrol/routes/dcim.py": 90.0,
    "routes/db/dcim.py": 88.0,
    "routes/db/dcim_cables.py": 88.0,
    # ChatOps: signatures, dispatcher, commands, formatters, storage and the
    # inbound and admin API. Measured by tests/test_chatops.py; do not lower
    # them to land a change.
    "netcontrol/chatops/signatures.py": 95.0,
    "netcontrol/chatops/replies.py": 90.0,
    "netcontrol/chatops/dispatcher.py": 88.0,
    "netcontrol/chatops/commands.py": 85.0,
    "netcontrol/chatops/notify.py": 95.0,
    "netcontrol/chatops/adapters.py": 70.0,
    "netcontrol/routes/chatops.py": 85.0,
    "routes/db/chatops.py": 90.0,
    # External secrets providers: the providers, the resolution choke
    # point, storage and API. Measured by tests/test_secrets_providers.py
    # (94%+ each); do not lower them to land a change.
    "netcontrol/secrets_providers/base.py": 95.0,
    "netcontrol/secrets_providers/service.py": 95.0,
    "netcontrol/secrets_providers/vault.py": 95.0,
    "netcontrol/secrets_providers/aws.py": 88.0,
    "netcontrol/secrets_providers/azure.py": 90.0,
    "netcontrol/routes/secrets_providers.py": 95.0,
    "routes/db/secrets_providers.py": 90.0,
    # Locations and tenancy: the rules, storage and API. Measured by
    # tests/test_organization.py; do not lower them to land a change.
    "netcontrol/organization.py": 95.0,
    "netcontrol/routes/organization.py": 90.0,
    "routes/db/organization.py": 90.0,
    # Virtualization: the rules and cloud mapping, storage and API with the
    # cloud sync. Measured by tests/test_virtualization.py; do not lower
    # them to land a change.
    "netcontrol/virtualization.py": 90.0,
    "netcontrol/routes/virtualization.py": 90.0,
    "routes/db/virtualization.py": 90.0,
    # Bulk import: the parser, adapters and commit, and the routes.
    # Measured by tests/test_bulk_import.py; do not lower them to land a
    # change.
    "netcontrol/bulk_import.py": 90.0,
    "netcontrol/routes/bulk_import.py": 90.0,
    # Intended configuration generation: the rules (sandboxed render,
    # comparison) and the API. Measured by tests/test_intended_config_*.py;
    # do not lower them to land a change.
    "netcontrol/intended_config.py": 95.0,
    "netcontrol/routes/intended_config.py": 85.0,
    # OIDC single sign-on protocol (discovery, JWKS, token exchange, ID
    # token validation). Measured by tests/test_oidc_*.py; do not lower it
    # to land a change.
    "netcontrol/oidc.py": 95.0,
    # Object-level permissions (inventory group scopes, the fail-closed
    # rule's helpers). Measured by tests/test_object_scope_*.py; do not
    # lower it to land a change.
    "netcontrol/object_scope.py": 95.0,
    # Read-only GraphQL API: access checks and batched readers, query limits,
    # schema and routes. Measured by tests/test_graphql_api.py; do not lower
    # them to land a change.
    "netcontrol/graphql_api/context.py": 90.0,
    "netcontrol/graphql_api/limits.py": 95.0,
    "netcontrol/graphql_api/schema.py": 82.0,
    "netcontrol/routes/graphql.py": 90.0,
    # Plugin framework: declaration validation, discovery / allow-list /
    # failure isolation, and the manifest and router mounting. Measured by
    # tests/test_plugins.py; do not lower them to land a change.
    "netcontrol/plugins/base.py": 88.0,
    "netcontrol/plugins/registry.py": 82.0,
    "netcontrol/routes/plugins.py": 90.0,
    # Event webhooks: matching, signing, delivery/retry, the API, and the
    # object-change events behind them. Measured by tests/test_webhooks.py;
    # do not lower them to land a change.
    "netcontrol/routes/webhooks.py": 85.0,
    "routes/db/change_events.py": 75.0,
    # Per-object change log: the recorder, access rules per type and scope,
    # filters and retention. Measured by tests/test_object_changes.py; do
    # not lower them to land a change.
    "netcontrol/routes/object_changes.py": 85.0,
    "routes/db/object_changes.py": 92.0,
    # Hardware lifecycle: the stage / coverage / alert rules, storage and the
    # API with the alert check. Measured by tests/test_hardware_lifecycle.py
    # (100%, 96%, 98%); do not lower them to land a change.
    "netcontrol/hardware_lifecycle.py": 95.0,
    "routes/db/hardware_lifecycle.py": 90.0,
    "netcontrol/routes/hardware_lifecycle.py": 90.0,
    # Git data sources: remote/branch rules, the git runner's credential
    # handling, checkout parsing, sync/import and the API. Measured by
    # tests/test_git_sources.py; do not lower them to land a change.
    "netcontrol/git_sources.py": 90.0,
    "netcontrol/routes/git_sources.py": 83.0,
    "routes/db/git_sources.py": 92.0,
    # APC Smart-UPS firmware updates: the file name / update rules, the NMC
    # CLI parsing and the Upgrades phases. Measured by tests/test_apc_ups_*.py
    # (99%, 97%, 86%); do not lower them to land a change.
    "netcontrol/integrations/apc/firmware.py": 95.0,
    "netcontrol/integrations/apc/nmc_cli.py": 92.0,
    "netcontrol/integrations/apc/upgrade.py": 80.0,
    # APC Smart-UPS monitoring: the PowerNet-MIB readings and alerts, and the
    # trap decoding / host match / alert / re-poll path. Measured by
    # tests/test_apc_ups*.py (100%, 100%); do not lower them to land a change.
    "netcontrol/integrations/apc/snmp.py": 95.0,
    "netcontrol/integrations/apc/traps.py": 95.0,
    # Syslog alert rules: parsing, the built-in rules, the engine and its
    # triggers, storage and the API, and the shared re-poll scheduler.
    # Measured by tests/test_syslog_rules.py and tests/test_apc_ups_traps.py
    # (96%, 98%, 98%, 92%); do not lower them to land a change.
    "netcontrol/syslog_rules.py": 92.0,
    "netcontrol/routes/syslog_rules.py": 92.0,
    "routes/db/syslog_rules.py": 92.0,
    "netcontrol/monitoring_repoll.py": 88.0,
    # Syslog rule activity analysis; measured by tests/test_syslog_activity.py.
    "netcontrol/syslog_activity.py": 92.0,
    # Request body limit and the size-capped per-IP tracker maps. Measured
    # by tests/test_body_limit.py and tests/test_bounded_map.py; do not
    # lower them to land a change.
    "netcontrol/body_limit.py": 90.0,
    "netcontrol/bounded_map.py": 95.0,
    # Source allowlist and per-source rate limit of the trap, syslog and
    # flow listeners. Measured by tests/test_listener_sources.py.
    "netcontrol/listener_sources.py": 90.0,
}


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _parse_rules(args: list[str]) -> dict[str, float]:
    if not args:
        return dict(DEFAULT_RULES)

    parsed: dict[str, float] = {}
    for raw in args:
        if ":" not in raw:
            raise ValueError(f"Invalid rule '{raw}'. Expected format path:min_percent")
        path, minimum = raw.rsplit(":", 1)
        parsed[_normalize_path(path)] = float(minimum)
    return parsed


def _find_percent_covered(files: dict, wanted_path: str) -> float | None:
    wanted_norm = _normalize_path(wanted_path)

    for file_path, file_info in files.items():
        current_norm = _normalize_path(file_path)
        if current_norm == wanted_norm or current_norm.endswith("/" + wanted_norm):
            summary = file_info.get("summary", {})
            if "percent_covered" in summary:
                return float(summary["percent_covered"])
            if "percent_covered_display" in summary:
                return float(summary["percent_covered_display"])
    return None


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python tools/coverage_gate.py <coverage.json> [path:min_percent ...]")
        return 2

    coverage_path = Path(sys.argv[1])
    if not coverage_path.exists():
        print(f"Coverage report not found: {coverage_path}")
        return 2

    try:
        rules = _parse_rules(sys.argv[2:])
    except ValueError as exc:
        print(str(exc))
        return 2

    data = json.loads(coverage_path.read_text(encoding="utf-8"))
    files = data.get("files", {})

    failures: list[str] = []
    for target, minimum in rules.items():
        covered = _find_percent_covered(files, target)
        if covered is None:
            failures.append(f"- {target}: file missing from coverage report")
            continue
        if covered < minimum:
            failures.append(f"- {target}: {covered:.2f}% < required {minimum:.2f}%")
        else:
            print(f"PASS {target}: {covered:.2f}% >= {minimum:.2f}%")

    if failures:
        print("Critical module coverage gate failed:")
        for item in failures:
            print(item)
        return 1

    print("Critical module coverage gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
