"""Unit tests for compliance rule evaluation (netcontrol.routes.compliance).

Regression coverage for the ``must_contain`` / ``must_not_contain`` false-pass:
a naive substring check reports a device with a hardening feature *disabled*
(``no service password-encryption``) as compliant, because the disabled line
still contains the bare directive text. Evaluation is now line-anchored and
negation-aware.
"""

from __future__ import annotations

from netcontrol.routes.compliance import _config_has_directive, _evaluate_rule

# A config where the affirmative directive is present.
CONFIG_ENABLED = """
hostname sw1
service password-encryption
ip ssh version 2
"""

# A config where the same feature is explicitly disabled.
CONFIG_DISABLED = """
hostname sw1
no service password-encryption
ip ssh version 2
"""


def test_must_contain_passes_when_feature_enabled():
    rule = {"type": "must_contain", "pattern": "service password-encryption"}
    assert _evaluate_rule(rule, CONFIG_ENABLED)["passed"] is True


def test_must_contain_fails_when_feature_disabled():
    # The disabled line contains the substring but must NOT count as present.
    rule = {"type": "must_contain", "pattern": "service password-encryption"}
    result = _evaluate_rule(rule, CONFIG_DISABLED)
    assert result["passed"] is False
    assert "Missing" in result["detail"]


def test_must_contain_missing_entirely():
    rule = {"type": "must_contain", "pattern": "service password-encryption"}
    assert _evaluate_rule(rule, "hostname sw1\n")["passed"] is False


def test_must_not_contain_passes_when_disabled():
    # "ip http server" is prohibited; "no ip http server" means it's off → pass.
    rule = {"type": "must_not_contain", "pattern": "ip http server"}
    cfg = "hostname sw1\nno ip http server\n"
    assert _evaluate_rule(rule, cfg)["passed"] is True


def test_must_not_contain_fails_when_present():
    rule = {"type": "must_not_contain", "pattern": "ip http server"}
    cfg = "hostname sw1\nip http server\n"
    assert _evaluate_rule(rule, cfg)["passed"] is False


def test_negation_pattern_matches_negation_line():
    # An operator can require the "no ..." form to be present.
    rule = {"type": "must_contain", "pattern": "no ip http server"}
    assert _evaluate_rule(rule, "no ip http server\n")["passed"] is True
    assert _evaluate_rule(rule, "ip http server\n")["passed"] is False


def test_directive_helper_ignores_leading_whitespace():
    # Nested/indented config lines still match after stripping.
    assert _config_has_directive("  service password-encryption\n",
                                 "service password-encryption") is True
    assert _config_has_directive("  no service password-encryption\n",
                                 "service password-encryption") is False


def test_empty_pattern_auto_passes():
    assert _evaluate_rule({"type": "must_contain", "pattern": ""}, "")["passed"] is True


def test_regex_match_and_invalid_regex():
    ok = _evaluate_rule({"type": "regex_match", "pattern": r"ssh version \d"},
                        CONFIG_ENABLED)
    assert ok["passed"] is True
    bad = _evaluate_rule({"type": "regex_match", "pattern": "("}, CONFIG_ENABLED)
    assert bad["passed"] is False
    assert "Invalid regex" in bad["detail"]


def test_unknown_rule_type_fails_closed():
    result = _evaluate_rule({"type": "sorcery", "pattern": "x"}, "x")
    assert result["passed"] is False
    assert "Unknown rule type" in result["detail"]
