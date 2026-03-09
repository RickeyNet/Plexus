from Firewall_converter.FortiGateToFTDTool.ftd_api_importer import (
    disable_cts_sgt_settings,
    is_cts_sgt_enabled,
)


def test_is_cts_sgt_enabled_detects_explicit_boolean_flags() -> None:
    assert is_cts_sgt_enabled({"ctsEnabled": True}) is True
    assert is_cts_sgt_enabled({"securityGroupTagging": True}) is True
    assert is_cts_sgt_enabled({"ctsEnabled": False}) is False


def test_is_cts_sgt_enabled_detects_nested_cts_and_tag_assignment() -> None:
    assert is_cts_sgt_enabled({"cts": {"enabled": True}}) is True
    assert is_cts_sgt_enabled({"cts": {"mode": "MANUAL"}}) is True
    assert is_cts_sgt_enabled({"securityGroupTag": 42}) is True
    assert is_cts_sgt_enabled({"securityGroupTag": 0}) is False


def test_disable_cts_sgt_settings_clears_relevant_fields() -> None:
    payload = {
        "name": "Eth1_3",
        "ctsEnabled": True,
        "securityGroupTagging": True,
        "securityGroupTag": 123,
        "cts": {
            "enabled": True,
            "mode": "MANUAL",
            "securityGroupTag": 123,
        },
    }

    disable_cts_sgt_settings(payload)

    assert payload["ctsEnabled"] is False
    assert payload["securityGroupTagging"] is False
    assert "securityGroupTag" not in payload
    assert payload["cts"]["enabled"] is False
    assert payload["cts"]["mode"] == "DISABLED"
    assert "securityGroupTag" not in payload["cts"]
