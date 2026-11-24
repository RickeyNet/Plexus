"""
yaml_safe.py -- YAML loading for text the server did not write.

``yaml.safe_load`` builds no arbitrary objects, but it still resolves
aliases (``*name``) to the anchored node. The loaded value then holds the
same object many times over, and any later step that walks or serialises
it pays for every reference: a list of N aliases to a K-key mapping costs
N x K visits, and nested aliases ("billion laughs") grow exponentially
from a few hundred bytes. An import file or a config context has no need
for aliases, so the loader here refuses them.
"""

from __future__ import annotations

from typing import Any

import yaml
from yaml.composer import ComposerError
from yaml.events import AliasEvent


class AliasNotAccepted(ComposerError):
    """The document holds an alias; its class name is shown in skip warnings."""


class _NoAliasLoader(yaml.SafeLoader):
    """``SafeLoader`` that fails on the first alias."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            event = self.peek_event()
            raise AliasNotAccepted(None, None, "YAML aliases (*name) are not accepted", event.start_mark)
        return super().compose_node(parent, index)


def safe_load_no_alias(text: str) -> Any:
    """``yaml.safe_load(text)``, except that a document with an alias
    raises ``yaml.YAMLError`` before anything is built from it."""
    loader = _NoAliasLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()
