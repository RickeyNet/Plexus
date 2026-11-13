"""Custom field value validation and canonical forms (``netcontrol.custom_fields``)."""

from __future__ import annotations

import pytest
from netcontrol.custom_fields import CustomFieldError, canonical_value, clean_tag_name, typed_value


def F(field_type: str, **kw) -> dict:
    return {"key": "k", "label": "Owner", "field_type": field_type, "choices": [], **kw}


@pytest.mark.parametrize(
    "ftype,raw,stored",
    [
        ("text", "  core team ", "core team"),
        ("number", "10.50", "10.5"),
        ("number", 7, "7"),
        ("number", "-0", "0"),
        ("number", "1E+3", "1000"),
        ("number", 2.5, "2.5"),
        ("number", "0.000125", "0.000125"),
        ("boolean", True, "true"),
        ("boolean", False, "false"),
        ("boolean", "false", "false"),
        ("boolean", " Yes ", "true"),
        ("boolean", 0, "false"),
        ("date", "2026-02-28", "2026-02-28"),
        ("url", " https://example.com/x ", "https://example.com/x"),
        ("url", "http://198.51.100.7:8080/", "http://198.51.100.7:8080/"),
        ("text", None, ""),
        ("number", "", ""),
        ("url", "   ", ""),
    ],
)
def test_canonical(ftype, raw, stored):
    assert canonical_value(F(ftype), raw) == stored


@pytest.mark.parametrize(
    "ftype,raw",
    [
        ("text", "x" * 1001),
        ("number", "abc"),
        ("number", "nan"),
        ("number", "inf"),
        ("number", True),
        ("number", [1]),
        ("boolean", "maybe"),
        ("boolean", 2),
        ("date", "2026-02-30"),
        ("date", "02/28/2026"),
        ("date", 20260228),
        ("url", "ftp://example.com"),
        ("url", "https://"),
        ("url", "javascript:alert(1)"),
        ("url", "https://[bad"),
        ("text", {"a": 1}),
        ("colour", "red"),
    ],
)
def test_rejects(ftype, raw):
    with pytest.raises(CustomFieldError, match="^Owner"):
        canonical_value(F(ftype), raw)


def test_text_at_the_limit_is_kept():
    assert canonical_value(F("text"), "x" * 1000) == "x" * 1000


def test_select():
    f = F("select", choices=["prod", "lab"])
    assert canonical_value(f, "lab") == "lab"
    assert canonical_value(f, " prod ") == "prod"
    with pytest.raises(CustomFieldError, match="^Owner"):
        canonical_value(f, "dev")


def test_label_falls_back_to_key():
    with pytest.raises(CustomFieldError, match="^rack"):
        canonical_value({"key": "rack", "field_type": "number"}, "x")


def test_typed():
    assert typed_value("number", "7") == 7 and typed_value("number", "10.5") == 10.5
    assert isinstance(typed_value("number", "7"), int)
    assert typed_value("boolean", "true") is True and typed_value("boolean", "false") is False
    assert typed_value("date", "2026-02-28") == "2026-02-28"
    assert typed_value("text", "core") == "core"
    # A stored value that no longer parses is returned as text, not dropped.
    assert typed_value("number", "abc") == "abc"


def test_tag_name():
    assert clean_tag_name("  pci-scope ") == "pci-scope"
    assert clean_tag_name("t" * 50) == "t" * 50
    for bad in ("", "   ", "t" * 51, None):
        with pytest.raises(CustomFieldError):
            clean_tag_name(bad)
