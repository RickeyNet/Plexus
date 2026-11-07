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
    assert _config_has_directive("  service password-encryption\n", "service password-encryption") is True
    assert _config_has_directive("  no service password-encryption\n", "service password-encryption") is False


def test_empty_pattern_auto_passes():
    assert _evaluate_rule({"type": "must_contain", "pattern": ""}, "")["passed"] is True


def test_regex_match_and_invalid_regex():
    ok = _evaluate_rule({"type": "regex_match", "pattern": r"ssh version \d"}, CONFIG_ENABLED)
    assert ok["passed"] is True
    bad = _evaluate_rule({"type": "regex_match", "pattern": "("}, CONFIG_ENABLED)
    assert bad["passed"] is False
    assert "Invalid regex" in bad["detail"]


def test_regex_match_runs_on_re2():
    """Rule patterns are RE2: lookarounds are reported as invalid, and a
    polynomial-backtracking pattern over a long line finishes at once."""
    import time

    look = _evaluate_rule({"type": "regex_match", "pattern": r"hostname (?!sw)\S+"}, CONFIG_ENABLED)
    assert look["passed"] is False
    assert "Invalid regex" in look["detail"] and "lookarounds" in look["detail"]

    start = time.monotonic()
    slow = _evaluate_rule({"type": "regex_match", "pattern": "a*a*a*a*a*a*b"}, "a" * 5000)
    assert slow["passed"] is False
    assert time.monotonic() - start < 1.0

    # Multiline: ^ anchors at each line, as with re.MULTILINE before.
    assert _evaluate_rule({"type": "regex_match", "pattern": r"^ip ssh version 2$"}, CONFIG_ENABLED)["passed"]


def test_validate_regex_rules():
    from netcontrol.routes.compliance import validate_regex_rules

    assert validate_regex_rules([{"type": "regex_match", "pattern": r"ip ssh time-out\s+\d+"}]) is None
    assert validate_regex_rules([{"type": "must_contain", "pattern": "("}]) is None
    err = validate_regex_rules([{"name": "No default", "type": "regex_match", "pattern": r"(?!x)y"}])
    assert err is not None and err.startswith("Rule No default: invalid regex")


def test_builtin_regex_rules_compile_on_re2():
    from netcontrol.routes.compliance import validate_regex_rules
    from routes.builtin_compliance_profiles import BUILTIN_PROFILES

    for name, _description, _severity, rules in BUILTIN_PROFILES:
        assert validate_regex_rules(rules) is None, name


def test_builtin_native_vlan_and_hostname_rules():
    """The RE2 rewrites of the two built-in lookahead rules keep their meaning."""
    from routes.builtin_compliance_profiles import HOSTNAME_NOT_DEFAULT, NATIVE_VLAN_NOT_1

    def passes(pattern: str, config: str) -> bool:
        return _evaluate_rule({"type": "regex_match", "pattern": pattern}, config)["passed"]

    for vlan, ok in (("1", False), ("10", True), ("2", True), ("100", True), ("999", True)):
        assert passes(NATIVE_VLAN_NOT_1, f" switchport trunk native vlan {vlan}\n") is ok, vlan

    for host, ok in (
        ("Router", False),
        ("switch", False),
        ("Router1", False),
        ("Switch-01", False),
        ("core-sw1", True),
        ("Rout", True),
        ("Swatch", True),
        ("s1", True),
        ("r-edge-01", True),
    ):
        assert passes(HOSTNAME_NOT_DEFAULT, f"version 17\nhostname {host}\n") is ok, host


def test_migration_0080_rewrites_only_builtin_patterns():
    import importlib
    import json

    from routes.builtin_compliance_profiles import HOSTNAME_NOT_DEFAULT, NATIVE_VLAN_NOT_1

    mod = importlib.import_module("routes.migrations.0080_compliance_builtin_patterns_re2")
    stored = json.dumps(
        [
            {"name": "a", "type": "regex_match", "pattern": r"hostname\s+(?!Router|Switch)\S+"},
            {"name": "b", "type": "regex_match", "pattern": r"switchport trunk native vlan\s+(?!1\b)\d+"},
            {"name": "c", "type": "regex_match", "pattern": r"hostname (?!lab)\S+"},
            {"name": "d", "type": "must_contain", "pattern": r"hostname\s+(?!Router|Switch)\S+"},
        ]
    )
    rules = json.loads(mod._rewrite(stored))
    assert [r["pattern"] for r in rules] == [
        HOSTNAME_NOT_DEFAULT,
        NATIVE_VLAN_NOT_1,
        r"hostname (?!lab)\S+",
        r"hostname\s+(?!Router|Switch)\S+",
    ]
    assert mod._rewrite(json.dumps([{"type": "regex_match", "pattern": "x"}])) is None
    assert mod._rewrite("not json") is None


def test_unknown_rule_type_fails_closed():
    result = _evaluate_rule({"type": "sorcery", "pattern": "x"}, "x")
    assert result["passed"] is False
    assert "Unknown rule type" in result["detail"]


def _console_login_rule() -> dict:
    from routes.builtin_compliance_profiles import BUILTIN_PROFILES

    for _name, _desc, _sev, rules in BUILTIN_PROFILES:
        for rule in rules:
            if rule["name"] == "Login local for console fallback":
                return rule
    raise AssertionError("builtin console login rule not found")


def test_console_login_rule_matches_login_inside_con_block():
    rule = _console_login_rule()
    cfg = "line con 0\n exec-timeout 5 0\n login authentication default\nline vty 0 4\n login local\n"
    assert _evaluate_rule(rule, cfg)["passed"] is True
    assert _evaluate_rule(rule, cfg.replace("\n", "\r\n"))["passed"] is True


def test_console_login_rule_ignores_login_in_later_sections():
    # The vty block's "login local" must not satisfy the console check when
    # the con 0 block itself has no login directive.
    rule = _console_login_rule()
    cfg = "line con 0\n exec-timeout 5 0\nline vty 0 4\n login local\n"
    assert _evaluate_rule(rule, cfg)["passed"] is False
