from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import netcontrol.app as app_module
from netcontrol.version import APP_VERSION


def test_fastapi_metadata_uses_shared_app_version():
    assert app_module.app.version == APP_VERSION


def _canonical(value: object) -> object:
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        items = [_canonical(v) for v in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def _load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def test_converter_v2_entrypoint_matches_legacy_artifacts(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    legacy_script = repo_root / "Firewall_converter" / "FortiGateToFTDTool" / "fortigate_converter.py"
    v2_script = repo_root / "Firewall_converter" / "converter_v2" / "fortigate_converter_v2.py"

    fortigate_config = {
        "system_interface": [
            {
                "port2": {
                    "alias": "inside",
                    "ip": "10.0.1.1/24",
                    "allowaccess": "ping",
                    "status": "up",
                }
            },
            {
                "port3": {
                    "alias": "outside",
                    "ip": "10.0.2.1/24",
                    "allowaccess": "ping",
                    "status": "up",
                }
            },
        ],
        "firewall_address": [
            {
                "LAN_NET": {
                    "subnet": ["10.0.1.0", "255.255.255.0"],
                    "comment": "LAN subnet",
                }
            },
            {
                "WAN_TARGET": {
                    "subnet": ["10.0.2.10", "255.255.255.255"],
                    "comment": "WAN host",
                }
            },
        ],
        "firewall_addrgrp": [
            {
                "LAN_GROUP": {
                    "member": ["LAN_NET"],
                }
            }
        ],
        "firewall_service_custom": [
            {
                "HTTPS": {
                    "tcp-portrange": "443",
                }
            },
            {
                "DNS": {
                    "tcp-portrange": "53",
                    "udp-portrange": "53",
                }
            },
        ],
        "firewall_service_group": [
            {
                "WEB_GROUP": {
                    "member": ["HTTPS", "DNS"],
                }
            }
        ],
        "firewall_policy": [
            {
                10: {
                    "name": "Allow_Web",
                    "srcintf": ["inside"],
                    "dstintf": ["outside"],
                    "action": "accept",
                    "srcaddr": ["LAN_GROUP"],
                    "dstaddr": ["WAN_TARGET"],
                    "service": ["WEB_GROUP"],
                }
            }
        ],
        "router_static": [
            {
                1: {
                    "dst": ["0.0.0.0", "0.0.0.0"],
                    "gateway": "10.0.2.254",
                    "distance": 1,
                    "device": "port3",
                    "comment": "Default route",
                }
            }
        ],
    }

    config_path = tmp_path / "sample_fortigate.yaml"
    config_path.write_text(json.dumps(fortigate_config, indent=2), encoding="utf-8")

    legacy_result = subprocess.run(
        [sys.executable, str(legacy_script), str(config_path), "--output", "legacy", "--target-model", "ftd-3120"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert legacy_result.returncode == 0, legacy_result.stderr or legacy_result.stdout

    v2_result = subprocess.run(
        [sys.executable, str(v2_script), str(config_path), "--output", "v2", "--target-model", "ftd-3120"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert v2_result.returncode == 0, v2_result.stderr or v2_result.stdout

    artifact_suffixes = [
        "address_objects.json",
        "address_groups.json",
        "service_objects.json",
        "service_groups.json",
        "access_rules.json",
        "static_routes.json",
        "physical_interfaces.json",
        "subinterfaces.json",
        "etherchannels.json",
        "bridge_groups.json",
        "security_zones.json",
        "summary.json",
        "metadata.json",
    ]

    for suffix in artifact_suffixes:
        legacy_path = tmp_path / f"legacy_{suffix}"
        v2_path = tmp_path / f"v2_{suffix}"
        assert legacy_path.exists(), f"Missing legacy artifact: {legacy_path.name}"
        assert v2_path.exists(), f"Missing v2 artifact: {v2_path.name}"

        legacy_payload_raw = _load_json(legacy_path)
        v2_payload_raw = _load_json(v2_path)
        if suffix == "metadata.json":
            assert isinstance(legacy_payload_raw, dict)
            assert isinstance(v2_payload_raw, dict)
            legacy_payload_raw["output_basename"] = "_normalized"
            v2_payload_raw["output_basename"] = "_normalized"

        legacy_payload = _canonical(legacy_payload_raw)
        v2_payload = _canonical(v2_payload_raw)
        assert v2_payload == legacy_payload, f"Artifact mismatch for {suffix}"
