"""Intended configuration rules (``netcontrol.intended_config``), with no I/O:
validators, scope, template selection, context merge, the sandboxed render
and its limits, the address filters, and the comparison."""

from __future__ import annotations

import netcontrol.intended_config as ic
import pytest
from netcontrol.custom_fields import CustomFieldError
from netcontrol.intended_config import (
    Renderer,
    RenderIssue,
    check_syntax,
    clean_context_data,
    clean_description,
    clean_device_type,
    clean_kind,
    clean_name_value,
    clean_template_text,
    clean_weight,
    compare_configs,
    config_lines,
    merge_contexts,
    scope_matches,
    select_template,
    verdict,
)

HOST = {"id": 7, "device_type": "cisco_ios", "role_id": 2, "site_id": 3, "group_id": 4}


def _template(tid: int, name: str, kind: str = "device", enabled: bool = True, **scope) -> dict:
    return {"id": tid, "name": name, "kind": kind, "enabled": enabled, "device_type": "", **scope}


def _render(text: str, variables: dict | None = None, **others: str):
    return Renderer({"t": text, **others}).render("t", variables or {})


# ── Validators ───────────────────────────────────────────────────────────────


def test_validators_accept_and_trim():
    assert clean_name_value("  edge  ") == "edge"
    assert clean_description(" d ") == "d"
    assert clean_device_type(" cisco_ios ") == "cisco_ios"
    assert clean_kind("snippet") == "snippet"
    assert clean_template_text("  keep spacing ") == "  keep spacing "
    assert clean_weight(0) == 0 and clean_weight(100000) == 100000
    assert clean_context_data({"ntp": ["192.0.2.1"]}) == '{"ntp":["192.0.2.1"]}'


@pytest.mark.parametrize(
    ("fn", "raw"),
    [
        (clean_name_value, ""),
        (clean_name_value, "x" * 101),
        (clean_description, "d" * 501),
        (clean_device_type, "x" * 65),
        (clean_kind, "router"),
        (clean_template_text, "x" * (ic.TEMPLATE_TEXT_MAX + 1)),
        (clean_weight, -1),
        (clean_weight, 100001),
        (clean_weight, True),
        (clean_context_data, ["not", "an", "object"]),
        (clean_context_data, {"k": "v" * ic.CONTEXT_DATA_MAX}),
    ],
    ids=lambda value: getattr(value, "__name__", None) or str(value)[:20],
)
def test_validators_refuse(fn, raw):
    with pytest.raises(CustomFieldError):
        fn(raw)


# ── Scope, selection, merge ──────────────────────────────────────────────────


def test_scope_matches_every_set_field():
    assert scope_matches({"device_type": ""}, HOST)
    assert scope_matches({"device_type": "cisco_ios", "role_id": 2, "site_id": 3, "group_id": 4}, HOST)
    assert not scope_matches({"device_type": "juniper_junos"}, HOST)
    assert not scope_matches({"role_id": 9}, HOST)
    assert not scope_matches({"site_id": 3}, {**HOST, "site_id": None})
    assert scope_matches({"host_id": 8}, HOST)  # host scope ignored unless asked
    assert not scope_matches({"host_id": 8}, HOST, with_host=True)
    assert scope_matches({"host_id": 7}, HOST, with_host=True)


def test_deleted_scope_id_matches_nothing():
    """A role, site or group that was deleted: hosts point at no such id
    (their reference was cleared), so the scope matches no host."""
    hosts = [HOST, {**HOST, "id": 8, "role_id": None}, {**HOST, "id": 9, "site_id": None}]
    deleted = {"device_type": "", "role_id": 99}
    assert not any(scope_matches(deleted, h) for h in hosts)
    assert not any(scope_matches({"host_id": 404}, h, with_host=True) for h in hosts)


def test_select_template_most_specific_then_name():
    templates = [
        _template(1, "any"),
        _template(2, "driver", device_type="cisco_ios"),
        _template(3, "role", role_id=2),
        _template(4, "site", site_id=3),
        _template(5, "B group", group_id=4),
        _template(6, "a group", group_id=4),
        _template(7, "snippet", kind="snippet"),
        _template(8, "disabled", enabled=False, group_id=4, site_id=3),
        _template(9, "other group", group_id=5, site_id=3, role_id=2, device_type="cisco_ios"),
    ]
    assert select_template(templates, HOST)["name"] == "a group"
    assert select_template(templates[:5], HOST)["name"] == "B group"
    assert select_template(templates[:4], HOST)["name"] == "site"
    assert select_template(templates[:3], HOST)["name"] == "role"
    assert select_template(templates[:2], HOST)["name"] == "driver"
    assert select_template([_template(1, "b"), _template(2, "A")], HOST)["name"] == "A"
    assert select_template([_template(7, "s", kind="snippet"), templates[7]], HOST) is None
    assert select_template([], HOST) is None


def test_merge_contexts_by_weight_then_name_deep():
    contexts = [
        {"id": 1, "name": "b", "weight": 10, "enabled": True, "data": {"ntp": {"a": 1, "b": 2}, "l": [1]}},
        {"id": 2, "name": "A", "weight": 10, "enabled": True, "data": {"ntp": {"a": 0}, "x": "first"}},
        {"id": 3, "name": "z", "weight": 1, "enabled": True, "data": {"x": "base", "l": [0, 0]}},
        {"id": 4, "name": "host", "weight": 50, "enabled": True, "host_id": 7, "data": {"ntp": {"c": 3}, "l": [9]}},
        {"id": 5, "name": "other", "weight": 0, "enabled": True, "host_id": 8, "data": {"x": "no"}},
        {"id": 6, "name": "off", "weight": 0, "enabled": False, "data": {"x": "no"}},
        {"id": 7, "name": "bad", "weight": 0, "enabled": True, "data": "not a dict"},
    ]
    merged, used = merge_contexts(contexts, HOST)
    assert [c["name"] for c in used] == ["bad", "z", "A", "b", "host"]
    assert merged == {"x": "first", "l": [9], "ntp": {"a": 1, "b": 2, "c": 3}}


# ── Rendering ────────────────────────────────────────────────────────────────


def test_render_tidies_whitespace_and_blocks():
    text = "hostname {{ host.name }}   \n{% for i in range(2) %}\ninterface Gi0/{{ i }}\n{% endfor %}\n\n\n"
    result = _render(text, {"host": {"name": "edge-r1"}})
    assert result.ok and result.config_text == "hostname edge-r1\ninterface Gi0/0\ninterface Gi0/1\n"
    assert _render("{# only a comment #}").config_text == ""


def test_render_include_and_import_of_snippets_by_name_ignoring_case():
    result = _render(
        "{% include 'NTP' %}\n{% import 'macros' as m %}{{ m.desc('uplink') }}\n",
        {"servers": ["192.0.2.1", "192.0.2.2"]},
        ntp="{% for s in servers %}\nntp server {{ s }}\n{% endfor %}",
        macros="{% macro desc(d) %} description {{ d }}{% endmacro %}",
    )
    assert result.config_text == "ntp server 192.0.2.1\nntp server 192.0.2.2\n description uplink\n"


def test_render_error_carries_message_template_and_line():
    result = _render("a\nb\n{{ missing }}\n")
    assert not result.ok and result.config_text == ""
    assert result.error == RenderIssue("'missing' is undefined", "t", 3)
    nested = _render("line\n{% include 'inner' %}\n", inner="ok\n\n{{ host.nope }}\n", host={})
    assert (nested.error.template, nested.error.line) == ("inner", 3)
    assert nested.error.as_text().endswith("(template 'inner', line 3)")
    assert nested.error.as_dict() == {"message": nested.error.message, "template": "inner", "line": 3}
    missing = _render("{% include 'nowhere' %}")
    assert missing.error.message == "No template named 'nowhere' to include."
    assert RenderIssue("plain").as_text() == "plain"


def test_syntax_check_gives_message_and_line():
    assert check_syntax("hostname {{ host.name }}\n") is None
    issue = check_syntax("a\nb\n{% if %}\n", "base")
    assert issue is not None and issue.line == 3 and issue.template == "base" and issue.message
    assert _render("{% for %}").error.line == 1


@pytest.mark.parametrize(
    "text",
    [
        "{{ ''.__class__.__mro__ }}",
        "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "{{ cycler.__init__.__globals__ }}",
        "{{ items.append(1) }}",
        "{{ lipsum() }}",
        "{{ range.__self__ }}",
    ],
)
def test_sandbox_refuses_escapes(text):
    result = _render(text, {"items": []})
    assert not result.ok
    assert any(word in result.error.message for word in ("unsafe", "undefined", "has no attribute"))


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("{% for i in range(10001) %}{% endfor %}", "range() may produce at most"),
        ("{{ 'x' * 2000000 }}", "repeated value"),
        ("{{ [0] * 2000000 }}", "repeated value"),
        ("{{ '%2000000d' % 1 }}", "format width"),
        ("{{ '{:2000000}'.format(1) }}", "format width"),
        ("{{ 'a'|center(2000000) }}", "larger than"),
        ("{{ '%2000000s'|format('a') }}", "format width"),
        ("{{ 2 ** 10000000 }}", "power is too large"),
        ("{{ 'aaaa'.replace('a', 'b' * 600000) }}", "replaced text"),
        ("{{ 'aaaa'|replace('a', 'b' * 600000) }}", "replaced text"),
        ("{{ ('\t' * 1000).expandtabs(2000) }}", "expanded text"),
        ("{% set ns = namespace(s='aa') %}{% for i in range(40) %}{% set ns.s = ns.s ~ ns.s %}{% endfor %}", "joined"),
        ("{% set ns = namespace(s='aa') %}{% for i in range(40) %}{% set ns.s = ns.s + ns.s %}{% endfor %}", "joined"),
        (
            "{% set ns = namespace(s='aa') %}{% for i in range(40) %}{% set ns.s = [ns.s, ns.s]|join %}{% endfor %}",
            "longer",
        ),
        ("{% set ns = namespace(s='a' * 900000) %}{{ [ns.s, ns.s] }}", "output value"),
        ("{% for i in range(10000) %}{{ 'y' * 200 }}{% endfor %}", "output is longer"),
    ],
)
def test_render_limits(text, fragment):
    result = _render(text)
    assert not result.ok and fragment in result.error.message, result.error


def test_render_stops_when_idle_too_long(monkeypatch):
    monkeypatch.setattr(ic, "RENDER_IDLE_SECONDS", 0.05)
    result = _render("{% for a in range(10000) %}{% for b in range(10000) %}{% endfor %}{% endfor %}")
    assert not result.ok and "without output" in result.error.message


def test_recursion_is_an_error_not_a_crash():
    assert "too deeply" in _render("{% include 't' %}").error.message
    assert "too deeply" in _render("{% macro f() %}{{ f() }}{% endmacro %}{{ f() }}").error.message


def test_ordinary_filters_and_loops_still_work():
    result = _render(
        "{{ 'a,b'|replace(',', ';')|upper }} {{ [1, 2]|map('string')|join('-') }} {{ x|default(3000000) }}\n"
        "{% for k, v in d|dictsort %}{{ k }}={{ v }} {{ loop.index }}/{{ loop.length }}\n{% endfor %}"
        "{{ '%-5s|'|format('ab') }}{{ '{:>4}'.format('x') }}{{ 'ab' ~ 1 }}{{ 3 * 2 }}{{ 2 ** 8 }}{{ '%d' % 5 }}",
        {"d": {"b": 2, "a": 1}},
    )
    assert result.ok, result.error
    # format, str.format, ~, *, ** and % in that order.
    assert result.config_text == "A;B 1-2 3000000\na=1 1/2\nb=2 2/2\n" + "ab   |" + "   x" + "ab1" + "6" + "256" + "5\n"


# ── Address filters ──────────────────────────────────────────────────────────


def test_address_filters():
    result = _render(
        "{{ '192.0.2.0/24'|netmask }} {{ '192.0.2.5/24'|wildcard }} {{ '192.0.2.9/24'|network }} "
        "{{ '192.0.2.0/26'|prefixlen }} {{ '192.0.2.0/24'|nth_host(1) }} {{ '192.0.2.0/24'|nth_host(-2) }} "
        "{{ '192.0.2.5/24'|ip }} {{ '2001:db8::1/64'|network }}"
    )
    assert result.config_text == "255.255.255.0 0.0.0.255 192.0.2.0 26 192.0.2.1 192.0.2.254 192.0.2.5 2001:db8::\n"


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("{{ 'nope'|netmask }}", "netmask: 'nope' is not an address"),
        ("{{ '192.0.2.0/24'|nth_host(300) }}", "has no address number 300"),
        ("{{ '192.0.2.0/24'|nth_host('a') }}", "is not a whole number"),
    ],
)
def test_address_filter_errors(text, fragment):
    assert fragment in _render(text).error.message


# ── Comparison ───────────────────────────────────────────────────────────────


INTENDED = """hostname edge-r1
!
interface GigabitEthernet0/1
 description uplink
 ip address 192.0.2.1 255.255.255.0
interface GigabitEthernet0/2
 description access
ntp server 192.0.2.10
"""

BACKUP = """! Last configuration change
hostname edge-r1
interface GigabitEthernet0/1
 description uplink
 ip address 192.0.2.1 255.255.255.0
 shutdown
  # a comment line
interface GigabitEthernet0/3
 description spare
logging host 192.0.2.20
"""


def test_config_lines_paths_ignore_comments_and_blanks():
    lines = config_lines("a\n b\n  c\n\n! x\n # y\n d\ne\n")
    assert lines == [
        ("a", ("a",)),
        (" b", ("a", "b")),
        ("  c", ("a", "b", "c")),
        ("", None),
        ("! x", None),
        (" # y", None),
        (" d", ("a", "d")),
        ("e", ("e",)),
    ]
    assert config_lines("") == []


def test_compare_missing_with_missing_parent_and_extra_only_under_intended_parents():
    result = compare_configs(INTENDED, BACKUP)
    missing = [line["text"] for line in result.lines if line["missing"]]
    assert missing == ["interface GigabitEthernet0/2", " description access", "ntp server 192.0.2.10"]
    assert result.lines[1] == {"text": "!", "missing": False}
    # ``shutdown`` sits under an intended parent; GigabitEthernet0/3 and the
    # logging line are top level (never extra), and its child sits under a
    # parent the intended text lacks.
    assert result.extra == [{"path": ["interface GigabitEthernet0/1"], "text": "shutdown"}]
    assert (result.missing_count, result.extra_count) == (3, 1)


def test_compare_identical_is_compliant():
    result = compare_configs(INTENDED, INTENDED)
    assert result.missing_count == 0 and result.extra_count == 0
    assert verdict("ok", True, result) == "compliant"
    assert verdict("ok", True, compare_configs(INTENDED, BACKUP)) == "non_compliant"
    assert verdict("ok", False, None) == "unknown"
    assert verdict("error", True, result) == "unknown"


def test_compare_duplicate_extra_listed_once():
    result = compare_configs("router bgp 65000\n neighbor 192.0.2.1\n", "router bgp 65000\n x\n x\n")
    assert result.extra == [{"path": ["router bgp 65000"], "text": "x"}]
