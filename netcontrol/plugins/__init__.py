"""Plexus plugin framework.

Third-party packages add API routes, database tables (through their own
migrations), sidebar entries, declarative pages and background work by
exposing a ``PlexusPlugin``. See ``docs/plugin-development.md``.
"""

from netcontrol.plugins.base import (
    FormBlock,
    FormField,
    NavItem,
    PlexusPlugin,
    PluginError,
    PluginPage,
    TableBlock,
    TableColumn,
    TextBlock,
    feature_key,
    table_prefix,
)
from netcontrol.plugins.registry import PluginRecord, PluginRegistry, registry

__all__ = [
    "FormBlock",
    "FormField",
    "NavItem",
    "PlexusPlugin",
    "PluginError",
    "PluginPage",
    "PluginRecord",
    "PluginRegistry",
    "TableBlock",
    "TableColumn",
    "TextBlock",
    "feature_key",
    "registry",
    "table_prefix",
]
