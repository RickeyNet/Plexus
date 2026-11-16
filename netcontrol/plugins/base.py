"""What a plugin declares: the ``PlexusPlugin`` config object and the
declarative navigation and page models the frontend renders.

A plugin package exposes one ``PlexusPlugin`` (see
``docs/plugin-development.md``). Everything here is validated when the plugin
is registered, so a malformed declaration fails that plugin alone, at load
time, instead of breaking a page in the browser.

Pages are declarative JSON, not code: the frontend's plugin page host renders
``text``, ``table`` and ``form`` blocks whose data paths are relative to the
plugin's own API (``/api/plugins/<name>/``). No plugin JavaScript runs in the
Plexus origin.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

# Lower-case, starts with a letter: it is the URL segment, the table prefix
# (``plugin_<name>_``) and part of the feature key, so it must be safe in all
# three.
PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,59}$")
# A data path relative to the plugin's API: plain segments only. No scheme,
# no leading slash, no "..", no query string, so a page can only ever reach
# the plugin's own routes.
_RELATIVE_PATH_RE = re.compile(r"^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$")

MAX_BLOCKS_PER_PAGE = 20
MAX_PAGES = 20
MAX_NAV_ITEMS = 20

AsyncHook = Callable[[], Coroutine[Any, Any, None]]


class PluginError(ValueError):
    """A plugin declaration is invalid; the message says why."""


def feature_key(name: str) -> str:
    """The access-group feature key that gates plugin ``name``'s API and pages."""
    return f"plugin:{name}"


def table_prefix(name: str) -> str:
    """The prefix every table a plugin's migrations create must carry."""
    return f"plugin_{name}_"


def _relative_path(value: str) -> str:
    if not _RELATIVE_PATH_RE.match(value):
        raise ValueError("must be a path relative to the plugin API, e.g. 'items' or 'items/summary'")
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TextBlock(_Strict):
    """A paragraph of plain text (never HTML or markdown)."""

    type: Literal["text"]
    id: str = Field(pattern=_SLUG_RE.pattern)
    text: str = Field(min_length=1, max_length=2000)


class TableColumn(_Strict):
    key: str = Field(min_length=1, max_length=60)
    label: str = Field(min_length=1, max_length=60)


class TableBlock(_Strict):
    """A table filled by ``GET /api/plugins/<name>/<source>``, which returns a
    JSON list of objects (or ``{"items": [...]}``)."""

    type: Literal["table"]
    id: str = Field(pattern=_SLUG_RE.pattern)
    title: str = Field(default="", max_length=80)
    source: str
    columns: list[TableColumn] = Field(min_length=1, max_length=12)
    empty_text: str = Field(default="Nothing to show yet.", max_length=200)

    @field_validator("source")
    @classmethod
    def _check_source(cls, value: str) -> str:
        return _relative_path(value)


class FormField(_Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    label: str = Field(min_length=1, max_length=60)
    type: Literal["text", "number", "textarea", "select", "checkbox"] = "text"
    required: bool = False
    options: list[str] = Field(default_factory=list, max_length=50)
    help: str = Field(default="", max_length=200)


class FormBlock(_Strict):
    """A form that sends its fields as a JSON object to
    ``<method> /api/plugins/<name>/<submit>``. ``refreshes`` names table
    blocks on the same page to reload after a successful submit."""

    type: Literal["form"]
    id: str = Field(pattern=_SLUG_RE.pattern)
    title: str = Field(default="", max_length=80)
    submit: str
    method: Literal["POST", "PUT"] = "POST"
    submit_label: str = Field(default="Save", min_length=1, max_length=40)
    fields: list[FormField] = Field(min_length=1, max_length=20)
    refreshes: list[str] = Field(default_factory=list, max_length=MAX_BLOCKS_PER_PAGE)

    @field_validator("submit")
    @classmethod
    def _check_submit(cls, value: str) -> str:
        return _relative_path(value)


PageBlock = Annotated[TextBlock | TableBlock | FormBlock, Field(discriminator="type")]


class PluginPage(_Strict):
    """One page, served in the SPA at ``/plugins/<name>/<id>``."""

    id: str = Field(pattern=_SLUG_RE.pattern)
    title: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)
    blocks: list[PageBlock] = Field(min_length=1, max_length=MAX_BLOCKS_PER_PAGE)


class NavItem(_Strict):
    """A sidebar entry (under the Plugins group) that opens one of the
    plugin's pages."""

    label: str = Field(min_length=1, max_length=40)
    page: str = Field(pattern=_SLUG_RE.pattern)


_PAGES = TypeAdapter(list[PluginPage])
_NAV = TypeAdapter(list[NavItem])


@dataclass
class PlexusPlugin:
    """The config object a plugin package exposes.

    Only ``name`` and ``version`` are required; every hook is optional.
    ``migrations`` is the dotted name of a package holding migration modules
    (``0001_create_items.py`` with ``VERSION``, ``DESCRIPTION`` and
    ``async def up(db)``), applied in the plugin's own namespace.
    """

    name: str
    version: str
    label: str = ""
    description: str = ""
    min_plexus_version: str | None = None
    max_plexus_version: str | None = None
    router: APIRouter | None = None
    migrations: str | None = None
    navigation: list[Any] = field(default_factory=list)
    pages: list[Any] = field(default_factory=list)
    startup: AsyncHook | None = None
    shutdown: AsyncHook | None = None
    background_tasks: list[AsyncHook] = field(default_factory=list)


@dataclass(frozen=True)
class ValidatedDeclarations:
    pages: list[PluginPage]
    navigation: list[NavItem]


def _pydantic_message(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        parts = []
        for err in errors()[:5]:
            loc = ".".join(str(p) for p in err.get("loc", ()))
            parts.append(f"{loc}: {err.get('msg')}" if loc else str(err.get("msg")))
        return "; ".join(parts)
    return str(exc)


def validate_plugin(plugin: object) -> ValidatedDeclarations:
    """Check a plugin's declarations; raise ``PluginError`` naming the first
    problem. Returns the parsed pages and navigation."""
    if not isinstance(plugin, PlexusPlugin):
        raise PluginError(f"expected a PlexusPlugin, got {type(plugin).__name__}")
    if not isinstance(plugin.name, str) or not PLUGIN_NAME_RE.match(plugin.name):
        raise PluginError("name must be 1 to 40 lower-case letters, digits or '_', starting with a letter")
    if not isinstance(plugin.version, str) or not plugin.version.strip():
        raise PluginError("version is required")
    if plugin.router is not None and not isinstance(plugin.router, APIRouter):
        raise PluginError("router must be a fastapi.APIRouter")
    if plugin.migrations is not None and not (isinstance(plugin.migrations, str) and plugin.migrations.strip()):
        raise PluginError("migrations must be the dotted name of a package")
    for hook_name in ("startup", "shutdown"):
        hook = getattr(plugin, hook_name)
        if hook is not None and not callable(hook):
            raise PluginError(f"{hook_name} must be an async callable")
    if not all(callable(t) for t in plugin.background_tasks):
        raise PluginError("background_tasks must be async callables")
    if len(plugin.pages) > MAX_PAGES:
        raise PluginError(f"at most {MAX_PAGES} pages")
    if len(plugin.navigation) > MAX_NAV_ITEMS:
        raise PluginError(f"at most {MAX_NAV_ITEMS} navigation items")
    try:
        pages = _PAGES.validate_python([_as_data(p) for p in plugin.pages])
    except ValueError as exc:
        raise PluginError(f"pages: {_pydantic_message(exc)}") from None
    try:
        navigation = _NAV.validate_python([_as_data(n) for n in plugin.navigation])
    except ValueError as exc:
        raise PluginError(f"navigation: {_pydantic_message(exc)}") from None

    page_ids = [p.id for p in pages]
    if len(set(page_ids)) != len(page_ids):
        raise PluginError("pages: page ids must be unique")
    for page in pages:
        block_ids = [b.id for b in page.blocks]
        if len(set(block_ids)) != len(block_ids):
            raise PluginError(f"pages.{page.id}: block ids must be unique")
        tables = {b.id for b in page.blocks if isinstance(b, TableBlock)}
        for block in page.blocks:
            if isinstance(block, FormBlock):
                unknown = [r for r in block.refreshes if r not in tables]
                if unknown:
                    raise PluginError(f"pages.{page.id}.{block.id}: refreshes unknown table {unknown[0]!r}")
    if (pages or navigation) and plugin.router is None:
        raise PluginError("pages need a router to serve their data")
    for item in navigation:
        if item.page not in page_ids:
            raise PluginError(f"navigation: {item.label!r} opens unknown page {item.page!r}")
    return ValidatedDeclarations(pages=pages, navigation=navigation)


def _as_data(value: Any) -> Any:
    return value.model_dump() if isinstance(value, BaseModel) else value
