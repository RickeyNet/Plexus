"""YAML from an upload or a git checkout is loaded without aliases.

``yaml.safe_load`` resolves ``*name`` to the anchored node, so a small file
can make a later walk or serialisation cost N x K visits (a list of aliases
to one wide mapping) or grow exponentially (nested aliases). Bulk import and
git config contexts load through ``netcontrol.yaml_safe`` and refuse them.
"""

from __future__ import annotations

from pathlib import Path

import netcontrol.bulk_import as bulk_import
import netcontrol.git_sources as gs
import pytest
import yaml
from netcontrol.bulk_import import BulkImportError, parse_records
from netcontrol.yaml_safe import AliasNotAccepted, safe_load_no_alias

# Nine references per level: 9**6 leaves from a document of a few lines.
NESTED_ALIASES = """
a: &a [x, x, x, x, x, x, x, x, x]
b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]
c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]
d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]
e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]
f: [*e, *e, *e, *e, *e, *e, *e, *e, *e]
"""


def test_plain_documents_load_like_safe_load():
    text = "- hostname: sw1\n  ip_address: 192.0.2.10\n- hostname: sw2\n  tags: [core, lab]\n"
    assert safe_load_no_alias(text) == yaml.safe_load(text)
    assert safe_load_no_alias("") is None
    # An anchor nobody refers to costs nothing and is accepted.
    assert safe_load_no_alias("base: &base {mtu: 1500}\n") == {"base": {"mtu": 1500}}


def test_alias_is_refused_before_anything_is_built():
    with pytest.raises(AliasNotAccepted) as exc:
        safe_load_no_alias(NESTED_ALIASES)
    assert isinstance(exc.value, yaml.YAMLError)
    assert "aliases" in str(exc.value).splitlines()[0]
    with pytest.raises(AliasNotAccepted):
        safe_load_no_alias("defaults: &d {mtu: 1500}\nport:\n  <<: *d\n")


def test_no_python_objects_are_built():
    with pytest.raises(yaml.YAMLError):
        safe_load_no_alias("!!python/object/apply:os.getcwd []\n")


def test_bulk_import_refuses_aliases():
    text = "row: &row {hostname: sw1, ip_address: 192.0.2.10}\nrows:\n  - *row\n  - *row\n"
    with pytest.raises(BulkImportError) as exc:
        parse_records(text, "yaml")
    assert "aliases" in str(exc.value)


def test_bulk_import_counts_rows_before_building_records(monkeypatch):
    """The row cap is checked on the parsed list, not after one record per
    row has been built (each record visits every key of its row)."""
    built: list[int] = []
    monkeypatch.setattr(bulk_import, "MAX_IMPORT_ROWS", 3)
    monkeypatch.setattr(bulk_import, "_record", lambda index, item: built.append(index))
    with pytest.raises(BulkImportError) as exc:
        parse_records('[{"hostname": "a"}, {"hostname": "b"}, {"hostname": "c"}, {"hostname": "d"}]', "json")
    assert "4 rows" in str(exc.value)
    assert built == []


def test_git_config_context_with_aliases_is_skipped():
    out = gs.Collected()
    rel = "config_contexts/ntp.yml"
    assert gs._context_item(rel, Path(rel), NESTED_ALIASES, out) is None
    assert out.warnings == [{"path": rel, "message": "Skipped: not valid YAML (AliasNotAccepted)."}]

    plain = gs.Collected()
    item = gs._context_item(rel, Path(rel), "ntp:\n  servers: [192.0.2.1, 192.0.2.2]\n", plain)
    assert item is not None and plain.warnings == []
