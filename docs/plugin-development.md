# Plugin development

Plexus can be extended by plugins: Python packages that add API routes,
database tables, sidebar entries, pages and background work without changing
Plexus itself. A worked example lives in
[`examples/plexus_plugin_example`](../examples/plexus_plugin_example/pyproject.toml).

Plugins run inside the Plexus process with the same rights as Plexus. Install
only plugins you trust, as you would any other server package.

## Enabling a plugin

1. Install the plugin package into the Python environment Plexus runs in
   (`pip install plexus-plugin-example`, or add it to your image).
2. List its name in the `PLEXUS_PLUGINS` environment variable,
   comma-separated: `PLEXUS_PLUGINS=example,other`.
3. Restart Plexus.

Nothing loads only because it is installed. An installed plugin that is not
listed shows as **disabled** under **Settings > Plugins** and is never
imported.

A listed name is looked up among the installed entry points of the
`plexus.plugins` group. When no entry point has that name, it is imported as
a module path instead (`module` or `module:attribute`, the attribute
defaulting to `plugin`), so a plugin can also be placed on the Python path
without packaging.

Each plugin gets a feature key, `plugin:<name>`, plus `plugin:<name>.write`
for writes. Admins grant them in **Settings > Access Groups** like any other
feature; admins and the API token always pass. Users whose access groups
limit them to selected inventory groups never get plugin features, because
Plexus cannot check that a plugin respects that limit.

## Statuses and failure isolation

| Status | Meaning |
|--------|---------|
| `disabled` | Installed (an entry point exists) but not listed in `PLEXUS_PLUGINS` |
| `failed` | It did not import, its declaration is invalid, its Plexus version range excludes this release, its migrations failed, or its startup hook raised or took longer than 60 seconds |
| `loaded` | Registered and its routes are mounted; startup has not run yet |
| `active` | Migrations applied and startup done; its API answers |

A failing plugin is logged and recorded with the reason, and Plexus starts
anyway. Its routes answer `503` while it is not active. The reasons are shown
to admins in **Settings > Plugins** and in `GET /api/plugins`.

## The plugin object

A plugin package exposes one `PlexusPlugin` (from `netcontrol.plugins`). The
entry point may name the object itself, a module with a `plugin` attribute,
or a function returning the object.

```toml
# pyproject.toml
[project.entry-points."plexus.plugins"]
example = "plexus_plugin_example:plugin"
```

```python
from netcontrol.plugins import PlexusPlugin

plugin = PlexusPlugin(
    name="example",                 # lower case, letters, digits and "_"; max 40
    version="0.1.0",
    label="Spare Parts",            # shown in the UI; defaults to name
    description="Spare hardware on hand at each site.",
    min_plexus_version="1.0.0",     # inclusive bounds, X.Y.Z; optional
    max_plexus_version=None,
    router=router,                  # a fastapi.APIRouter; optional
    migrations="plexus_plugin_example.migrations",  # optional
    navigation=[{"label": "Spare Parts", "page": "spares"}],
    pages=[...],                    # see "Pages" below
    startup=startup,                # async def startup() -> None; optional
    shutdown=shutdown,              # async def shutdown() -> None; optional
    background_tasks=[poll_loop],   # async callables started after startup
)
```

The entry point name must equal `name`; the plugin fails to load otherwise.
Version bounds compare against the running Plexus version; a development
build whose version does not parse as `X.Y.Z` is not gated.

## API routes

The router is mounted at `/api/plugins/<name>/`. A route declared as
`@router.get("/spares")` answers at `/api/plugins/example/spares`. Plexus adds
the same checks as its own routes:

- a signed-in session or the API token (`401` otherwise);
- the `plugin:<name>` feature for reads and `plugin:<name>.write` for
  `POST`, `PUT`, `PATCH` and `DELETE` (`403` otherwise);
- the CSRF token on writes made with a session cookie;
- the plugin being `active` (`503` otherwise).

Use Plexus' own helpers for the rest: `routes.database.get_db()` for a
database connection (always `await conn.close()` in a `finally`),
`netcontrol.routes.shared._session_user(request)` for the caller's user name
and `netcontrol.routes.shared._audit(...)` to write an audit event.

## Migrations

`migrations` names a package of migration modules written exactly like core
ones (`routes/migrations/`): files named `0001_short_name.py`, each with
`VERSION`, `DESCRIPTION` and `async def up(db)`, in the portable SQL dialect
(`?` placeholders).

```python
VERSION = 1
DESCRIPTION = "Create plugin_example_spares"


async def up(db) -> None:
    await db.execute(
        "CREATE TABLE IF NOT EXISTS plugin_example_spares ("
        " id SERIAL PRIMARY KEY, part TEXT NOT NULL, site TEXT NOT NULL DEFAULT '')"
    )
```

- They run at startup, after the core migrations, under the same lock.
- They are tracked per plugin in `plugin_schema_migrations` (plugin, version),
  so plugin version numbers never collide with core numbers or another
  plugin's.
- Every table, index, view or sequence a plugin migration creates, alters or
  drops, and every table it writes to, must be named `plugin_<name>_...`.
  A statement that reaches outside that namespace is refused and the plugin
  is marked failed. Foreign keys to core tables (`REFERENCES hosts(id)`) and
  reads are allowed.
- Migrations only move forward; there is no down step. Make each one
  idempotent (`IF NOT EXISTS`).

## Navigation and pages

Plugin pages are **declarative JSON**, rendered by Plexus' own React
components. A plugin ships no JavaScript and nothing of the plugin runs in
the browser. This keeps plugin UI from reading the session, calling admin
APIs or breaking the shell, keeps the look consistent, and needs no build
step in the plugin. A plugin that needs a richer UI can serve it from its
own API under a page the admin links to, outside the Plexus shell.

Each page is shown at `/plugins/<name>/<page id>`. Each `navigation` item adds
an entry to a **Plugins** group in the sidebar, shown to users who hold the
plugin's feature key.

```python
pages=[
    {
        "id": "spares",                 # lower case, digits and "-"
        "title": "Spare Parts",
        "description": "Spare hardware on hand at each site.",
        "blocks": [
            {
                "type": "form",
                "id": "add-spare",
                "title": "Add a spare",
                "submit": "spares",     # POST /api/plugins/example/spares
                "method": "POST",       # or "PUT"
                "submit_label": "Add spare",
                "fields": [
                    {"name": "part", "label": "Part", "required": True},
                    {"name": "quantity", "label": "Quantity", "type": "number"},
                ],
                "refreshes": ["spares-table"],
            },
            {
                "type": "table",
                "id": "spares-table",
                "title": "On hand",
                "source": "spares",     # GET /api/plugins/example/spares
                "columns": [
                    {"key": "part", "label": "Part"},
                    {"key": "quantity", "label": "Quantity"},
                ],
                "empty_text": "No spares recorded yet.",
            },
        ],
    }
]
```

Block types:

| Type | Fields | Behaviour |
|------|--------|-----------|
| `text` | `id`, `text` (up to 2000 characters) | A paragraph of plain text; never HTML or markdown |
| `table` | `id`, `title`, `source`, `columns` (1 to 12 of `key`, `label`), `empty_text` | `GET` of `source`; the response is a JSON list of objects or `{"items": [...]}`. Each cell is shown as text (objects as JSON) |
| `form` | `id`, `title`, `submit`, `method`, `submit_label`, `fields` (1 to 20), `refreshes` | Sends the fields as a JSON object. Field `type` is `text`, `number`, `textarea`, `select` (with `options`) or `checkbox`; `required` and `help` are optional. Numbers are sent as numbers, checkboxes as booleans, and an empty optional field is left out. After success the form clears and the named table blocks reload |

`source` and `submit` are paths relative to the plugin's API: plain segments
such as `spares` or `spares/summary`, with no leading `/`, no `..` and no
query string, so a page can only reach its own plugin's routes. A page has at
most 20 blocks; a plugin at most 20 pages and 20 navigation items. Every
declaration is validated when the plugin loads; an invalid one fails the
plugin with the reason.

## Startup, shutdown and background tasks

- `startup` runs once after the plugin's migrations, with a 60-second limit.
- Each `background_tasks` entry is called once after startup and run as a
  supervised task: a crash is logged and does not affect Plexus. Write loops
  that handle their own errors, as Plexus' own loops do.
- At shutdown the tasks are cancelled and then `shutdown` runs, with a
  15-second limit; an error there is logged and ignored.

## The manifest API

`GET /api/plugins` (any signed-in user) returns `{"admin": bool, "plugins":
[...]}`. Users get the active plugins whose feature they hold, each with
`name`, `label`, `version`, `description`, `status`, `feature`, `navigation`
and `pages`. Admins and the API token get every plugin, including disabled
and failed ones, with `source`, `min_plexus_version`, `max_plexus_version`,
`errors`, `has_router`, `migrations`, `migrations_applied` and
`background_tasks` as well.

## Testing a plugin

The Plexus test suite loads the example plugin from its source directory and
registers it directly, without installing it (`tests/test_plugins.py`):

```python
from netcontrol.plugins import registry
from netcontrol.routes.plugins import mount_plugin_routers
import netcontrol.app as app_module

registry.register(my_plugin.plugin, source="test")
mount_plugin_routers(app_module.app, app_module.require_feature_method)
# Start the app (TestClient) to run migrations and startup.
```

Call `registry.reset()` afterwards so the next test starts clean.
