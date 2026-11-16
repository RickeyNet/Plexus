"""Plugin discovery, registration and lifecycle.

Only plugins named in the allow-list (``PLEXUS_PLUGINS``, comma-separated)
are imported. Installed entry points (group ``plexus.plugins``) that are not
listed are reported as ``disabled`` without being imported.

Every step a plugin takes - import, validation, version check, migrations,
startup - is isolated: an exception marks that plugin ``failed`` with the
reason and is logged; Plexus itself keeps starting.

Statuses:
  disabled  installed (entry point found) but not in the allow-list
  failed    import, declaration, version, migration or startup error
  loaded    registered and mounted; startup not run yet
  active    migrations applied and startup done; its API answers
"""

from __future__ import annotations

import asyncio
import importlib
import os
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any

from netcontrol.plugins.base import (
    NavItem,
    PlexusPlugin,
    PluginError,
    PluginPage,
    feature_key,
    table_prefix,
    validate_plugin,
)
from netcontrol.telemetry import configure_logging
from netcontrol.version import APP_VERSION, parse_semver

LOGGER = configure_logging("plexus.plugins")

ENTRY_POINT_GROUP = "plexus.plugins"
ALLOW_LIST_ENV = "PLEXUS_PLUGINS"
# A startup hook that hangs must not hold Plexus' own startup hostage.
STARTUP_TIMEOUT_SECONDS = 60.0
SHUTDOWN_TIMEOUT_SECONDS = 15.0

STATUS_DISABLED = "disabled"
STATUS_FAILED = "failed"
STATUS_LOADED = "loaded"
STATUS_ACTIVE = "active"


@dataclass
class PluginRecord:
    name: str
    status: str
    source: str
    version: str = ""
    label: str = ""
    description: str = ""
    min_plexus_version: str | None = None
    max_plexus_version: str | None = None
    errors: list[str] = field(default_factory=list)
    plugin: PlexusPlugin | None = None
    pages: list[PluginPage] = field(default_factory=list)
    navigation: list[NavItem] = field(default_factory=list)
    tasks: list[asyncio.Task] = field(default_factory=list)
    migrations_applied: int = 0

    @property
    def feature_key(self) -> str:
        return feature_key(self.name)

    def fail(self, stage: str, exc: BaseException | str) -> None:
        message = exc if isinstance(exc, str) else f"{type(exc).__name__}: {exc}"
        self.status = STATUS_FAILED
        self.errors.append(f"{stage}: {message}")
        LOGGER.error("plugin %s failed at %s: %s", self.name, stage, message)


def allow_list(raw: str | None = None) -> list[str]:
    """The plugin names (or ``module[:attr]`` paths) the admin enabled."""
    value = os.environ.get(ALLOW_LIST_ENV, "") if raw is None else raw
    out: list[str] = []
    for part in value.split(","):
        name = part.strip()
        if name and name not in out:
            out.append(name)
    return out


def check_version(plugin: PlexusPlugin, current: str = APP_VERSION) -> str | None:
    """Why ``plugin`` cannot run on Plexus ``current``, or None when it can.

    Bounds are inclusive. A version that does not parse (a development
    build) is not gated, so a checkout can still load any plugin."""
    now = parse_semver(current)
    if now is None:
        return None
    for bound, label in ((plugin.min_plexus_version, "min"), (plugin.max_plexus_version, "max")):
        if not bound:
            continue
        parsed = parse_semver(bound)
        if parsed is None:
            return f"{label}_plexus_version {bound!r} is not a version (expected X.Y.Z)"
        if label == "min" and now < parsed:
            return f"requires Plexus >= {bound}; this is {current}"
        if label == "max" and now > parsed:
            return f"requires Plexus <= {bound}; this is {current}"
    return None


def _resolve(obj: Any) -> Any:
    """A loaded entry point or module path may be the PlexusPlugin itself, a
    module exposing ``plugin``, or a zero-argument factory returning one."""
    if isinstance(obj, PlexusPlugin):
        return obj
    if hasattr(obj, "__spec__") and hasattr(obj, "plugin"):  # a module
        return _resolve(obj.plugin)
    if callable(obj):
        return obj()
    return obj


class PluginRegistry:
    def __init__(self) -> None:
        self._records: dict[str, PluginRecord] = {}
        self._features: list[str] | None = None

    # ── Introspection ────────────────────────────────────────────────────

    def records(self) -> list[PluginRecord]:
        return sorted(self._records.values(), key=lambda r: r.name)

    def get(self, name: str) -> PluginRecord | None:
        return self._records.get(name)

    def is_active(self, name: str) -> bool:
        record = self._records.get(name)
        return record is not None and record.status == STATUS_ACTIVE

    def bind_feature_flags(self, features: list[str]) -> None:
        """Give the registry the shared FEATURE_FLAGS list (``state``) so each
        plugin's ``plugin:<name>`` / ``plugin:<name>.write`` keys can be
        granted in access groups like any core feature."""
        self._features = features
        for record in self._records.values():
            if record.status != STATUS_DISABLED and record.plugin is not None:
                self._add_features(record.name)

    def _add_features(self, name: str) -> None:
        if self._features is None:
            return
        for key in (feature_key(name), f"{feature_key(name)}.write"):
            if key not in self._features:
                self._features.append(key)

    def reset(self) -> None:
        """Forget every plugin (tests). Feature keys added are removed too."""
        for record in self._records.values():
            if self._features is not None:
                for key in (record.feature_key, f"{record.feature_key}.write"):
                    while key in self._features:
                        self._features.remove(key)
        self._records.clear()

    # ── Registration ─────────────────────────────────────────────────────

    def register(self, obj: Any, *, source: str = "direct") -> PluginRecord:
        """Validate and record one plugin object. Never raises: a bad plugin
        comes back as a ``failed`` record."""
        try:
            plugin = _resolve(obj)
        except Exception as exc:
            record = PluginRecord(name=source, status=STATUS_FAILED, source=source)
            record.fail("load", exc)
            self._records.setdefault(record.name, record)
            return record
        name = getattr(plugin, "name", None)
        record = PluginRecord(
            name=name if isinstance(name, str) and name else source,
            status=STATUS_LOADED,
            source=source,
            version=str(getattr(plugin, "version", "") or ""),
            label=str(getattr(plugin, "label", "") or "") or (name if isinstance(name, str) else ""),
            description=str(getattr(plugin, "description", "") or ""),
            min_plexus_version=getattr(plugin, "min_plexus_version", None),
            max_plexus_version=getattr(plugin, "max_plexus_version", None),
        )
        existing = self._records.get(record.name)
        if existing is not None and existing.status != STATUS_DISABLED:
            if existing.plugin is plugin:
                return existing
            record.fail("register", f"a plugin named {record.name!r} is already registered (from {existing.source})")
            return record
        try:
            declarations = validate_plugin(plugin)
        except PluginError as exc:
            record.fail("validate", str(exc))
            self._records[record.name] = record
            return record
        reason = check_version(plugin)
        if reason:
            record.fail("version", reason)
            self._records[record.name] = record
            return record
        record.plugin = plugin
        record.pages = declarations.pages
        record.navigation = declarations.navigation
        self._records[record.name] = record
        self._add_features(record.name)
        LOGGER.info("plugin %s %s registered from %s", record.name, record.version, source)
        return record

    def discover(self, *, enabled: list[str] | None = None, entry_points: Any = None) -> list[PluginRecord]:
        """Load the allow-listed plugins.

        ``enabled`` defaults to ``PLEXUS_PLUGINS``; ``entry_points`` to the
        installed ``plexus.plugins`` entry points. An allow-listed name with
        no entry point is imported as ``module[:attr]`` (attr ``plugin`` by
        default), for a plugin placed on the Python path without packaging.
        """
        wanted = allow_list() if enabled is None else enabled
        eps = list(metadata.entry_points(group=ENTRY_POINT_GROUP) if entry_points is None else entry_points)
        by_name = {ep.name: ep for ep in eps}
        out: list[PluginRecord] = []
        for ep in eps:
            if ep.name in wanted or ep.name in self._records:
                continue
            dist = getattr(ep, "dist", None)
            self._records[ep.name] = PluginRecord(
                name=ep.name,
                status=STATUS_DISABLED,
                source=f"entry point {ep.value}",
                version=str(getattr(dist, "version", "") or ""),
                label=ep.name,
            )
        for name in wanted:
            existing = self._records.get(name)
            if existing is not None and existing.status != STATUS_DISABLED:
                out.append(existing)
                continue
            ep = by_name.get(name)
            source = f"entry point {ep.value}" if ep is not None else name
            try:
                obj = ep.load() if ep is not None else _import_target(name)
            except BaseException as exc:  # an import may raise SystemExit too
                if isinstance(exc, KeyboardInterrupt):
                    raise
                record = PluginRecord(name=name, status=STATUS_FAILED, source=source)
                record.fail("import", exc)
                self._records[name] = record
                out.append(record)
                continue
            record = self.register(obj, source=source)
            if record.name != name and ep is not None:
                # The entry point's name is what admins list; keep the two
                # in step so the allow-list stays readable.
                record.fail("register", f"entry point {name!r} declares plugin name {record.name!r}")
            # A disabled placeholder under the entry point name is replaced.
            if self._records.get(name) is not None and self._records[name].status == STATUS_DISABLED:
                del self._records[name]
            out.append(record)
        return out

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(self, get_db, supervise) -> None:
        """Apply migrations, run startup hooks and start background tasks of
        every ``loaded`` plugin. ``get_db`` is ``routes.database.get_db``;
        ``supervise`` is ``shared.supervise_task``."""
        from routes.migrations.runner import run_plugin_migrations

        for record in self.records():
            if record.status != STATUS_LOADED or record.plugin is None:
                continue
            plugin = record.plugin
            if plugin.migrations:
                try:
                    conn = await get_db()
                    try:
                        record.migrations_applied = await run_plugin_migrations(
                            conn, record.name, plugin.migrations, table_prefix(record.name)
                        )
                    finally:
                        await conn.close()
                except Exception as exc:
                    record.fail("migrations", exc)
                    continue
            if plugin.startup is not None:
                try:
                    await asyncio.wait_for(plugin.startup(), timeout=STARTUP_TIMEOUT_SECONDS)
                except TimeoutError:
                    record.fail("startup", f"did not finish within {STARTUP_TIMEOUT_SECONDS:.0f}s")
                    continue
                except Exception as exc:
                    record.fail("startup", exc)
                    continue
            for index, factory in enumerate(plugin.background_tasks):
                try:
                    task: asyncio.Task = asyncio.create_task(factory(), name=f"plugin:{record.name}:{index}")
                except Exception as exc:
                    record.fail("background task", exc)
                    break
                supervise(task, f"plugin {record.name} background task {index}")
                record.tasks.append(task)
            if record.status == STATUS_FAILED:
                await _cancel(record.tasks)
                continue
            record.status = STATUS_ACTIVE
            LOGGER.info("plugin %s active", record.name)

    async def stop(self) -> None:
        """Cancel background tasks and run shutdown hooks. Errors are logged,
        never raised, so one plugin cannot stop the rest of shutdown."""
        for record in self.records():
            await _cancel(record.tasks)
            record.tasks = []
            plugin = record.plugin
            if record.status != STATUS_ACTIVE or plugin is None:
                continue
            if plugin.shutdown is not None:
                try:
                    await asyncio.wait_for(plugin.shutdown(), timeout=SHUTDOWN_TIMEOUT_SECONDS)
                except Exception as exc:
                    LOGGER.warning("plugin %s shutdown failed: %s: %s", record.name, type(exc).__name__, exc)
            record.status = STATUS_LOADED


async def _cancel(tasks: list[asyncio.Task]) -> None:
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


def _import_target(target: str) -> Any:
    module_name, _, attr = target.partition(":")
    module = importlib.import_module(module_name)
    return getattr(module, attr) if attr else module


# The process-wide registry app.py loads at import and starts in its lifespan.
registry = PluginRegistry()
