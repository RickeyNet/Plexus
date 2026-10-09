import datetime as _dt
import sys

# Python 3.11 added datetime.UTC as a convenience alias.  Polyfill it for
# older interpreters so the production code (which uses ``from datetime import
# UTC``) can be imported without modification during tests.
if sys.version_info < (3, 11) and not hasattr(_dt, "UTC"):
    _dt.UTC = _dt.UTC

import asyncio
import os
import threading
from urllib.parse import unquote, urlsplit, urlunsplit

# ── Backend selection for the test suite ────────────────────────────────────
#
# Default (PLEXUS_TEST_PG_URL unset): SQLite.
#
# scripts/dev-env.ps1 / dev-env.sh export APP_DB_ENGINE=postgres and an
# APP_DATABASE_URL pointing at the developer's dev database.  routes.database
# (and every routes.migrations module) reads APP_DB_ENGINE at import time, so
# running pytest from such a shell used to send every "SQLite" test, which
# only monkeypatches DB_PATH to a tmp file, straight into the live dev
# database.  Pin the engine to sqlite before anything imports routes.*.
#
# Tests that genuinely target Postgres (tests/test_postgres_backend.py) opt in
# explicitly by monkeypatching ``routes.database.DB_ENGINE`` and
# ``APP_DATABASE_URL``; the migration runner then hands that engine to the
# migrations.  APP_DATABASE_URL is deliberately left untouched: the smoke
# tests' skip condition reads it.
#
# Opt-in Postgres mode (PLEXUS_TEST_PG_URL=postgresql://.../<name>_test):
# the WHOLE suite runs on Postgres.  The database named in the URL is
# DESTROYED and recreated over and over, so the name must end in ``_test``
# and must not be ``plexus`` (the dev database); otherwise pytest refuses to
# start.  At session start the schema is built once (init_db) into
# ``<name>_template``; before each test that follows a test which touched
# the database, ``<name>`` is dropped and re-cloned from that template
# (CREATE DATABASE ... TEMPLATE), so every test starts from the post-init_db
# state.  DB_PATH monkeypatching is harmless (ignored on Postgres).  Tests
# that are inherently SQLite-specific carry ``@pytest.mark.sqlite_only`` and
# are skipped in this mode.  Under pytest-xdist each worker gets its own
# ``<name>_<worker>`` database.  See DEVSETUP.md.
_PG_TEST_URL_RAW = os.environ.get("PLEXUS_TEST_PG_URL", "").strip()
_PG_MODE_ERROR = ""
PG_MODE = False
_PG_TEST_URL = ""  # URL of the per-test database (what the app connects to)
_PG_TEMPLATE_URL = ""
_PG_MAINT_URL = ""  # the "postgres" maintenance database, for DROP/CREATE
_PG_DB_NAME = ""
_PG_TEMPLATE_NAME = ""


def _pg_url_with_db(parts, name: str) -> str:
    return urlunsplit((parts.scheme, parts.netloc, "/" + name, parts.query, parts.fragment))


if _PG_TEST_URL_RAW:
    _parts = urlsplit(_PG_TEST_URL_RAW)
    _configured_name = unquote(_parts.path.lstrip("/"))
    if _parts.scheme not in ("postgresql", "postgres"):
        _PG_MODE_ERROR = f"PLEXUS_TEST_PG_URL must be a postgresql:// URL (got scheme {_parts.scheme!r})"
    elif not _configured_name:
        _PG_MODE_ERROR = "PLEXUS_TEST_PG_URL must name a database (postgresql://user:pw@host:port/<name>_test)"
    elif _configured_name == "plexus" or not _configured_name.endswith("_test"):
        _PG_MODE_ERROR = (
            f"PLEXUS_TEST_PG_URL names database {_configured_name!r}; the suite DROPS and "
            "recreates that database, so its name must end in '_test' and must not be "
            "'plexus' (the dev database). Refusing to run."
        )
    else:
        PG_MODE = True
        _worker = os.environ.get("PYTEST_XDIST_WORKER", "").strip()
        _PG_DB_NAME = f"{_configured_name}_{_worker}" if _worker else _configured_name
        _PG_TEMPLATE_NAME = f"{_PG_DB_NAME}_template"
        _PG_TEST_URL = _pg_url_with_db(_parts, _PG_DB_NAME)
        _PG_TEMPLATE_URL = _pg_url_with_db(_parts, _PG_TEMPLATE_NAME)
        _PG_MAINT_URL = _pg_url_with_db(_parts, "postgres")

_TEST_DB_ENGINE = "postgres" if PG_MODE else "sqlite"
os.environ["APP_DB_ENGINE"] = _TEST_DB_ENGINE
# The app's startup guard (routes.database.ensure_supported_db_engine) refuses
# to boot on sqlite; the in-process suite is the one sanctioned exception.
os.environ.setdefault("PLEXUS_ALLOW_SQLITE_ENGINE", "1")
if PG_MODE:
    os.environ["APP_DATABASE_URL"] = _PG_TEST_URL

import pytest
import routes.database as _db
import routes.db.audit as _db_audit
import starlette.testclient as _stc

# Belt and braces: routes.database may already have been imported (pytest
# plugins, rootdir conftest, ...) before the environment was pinned above.
_db.DB_ENGINE = _TEST_DB_ENGINE
if PG_MODE:
    _db.APP_DATABASE_URL = _PG_TEST_URL


def pytest_configure(config):
    # The sqlite_only marker itself is registered in pytest.ini.
    if _PG_MODE_ERROR:
        raise pytest.UsageError(_PG_MODE_ERROR)


def pytest_collection_modifyitems(config, items):
    if not PG_MODE:
        return
    skip = pytest.mark.skip(reason="sqlite_only: skipped in Postgres mode (PLEXUS_TEST_PG_URL)")
    for item in items:
        if item.get_closest_marker("sqlite_only") is not None:
            item.add_marker(skip)


# ── Postgres mode: per-loop pools and per-test database reset ───────────────
#
# The app keeps ONE module-global asyncpg pool, created on whichever loop
# first calls get_db().  Production has a single loop; the suite does not:
# pytest-asyncio gives every test its own loop, sync tests call asyncio.run()
# repeatedly, and TestClient runs the app on a portal-thread loop that can be
# live at the same time as the test's own loop.  An asyncpg pool is bound to
# its loop, so in Postgres mode get_db()'s pool lookup is replaced with one
# that keeps a pool per running loop, and close_db_pool() closes the calling
# loop's pool.  After each test every remaining pool is closed (or, if its
# loop is already gone, terminated) so nothing survives into the next test.

_pg_pools: dict = {}  # loop -> asyncpg pool
_pg_pool_locks: dict = {}  # loop -> asyncio.Lock
_pg_registry_lock = threading.Lock()
_pg_dirty = True  # the per-test DB must be (re)cloned before the next test


async def _pg_get_pool_per_loop():
    global _pg_dirty
    _pg_dirty = True
    loop = asyncio.get_running_loop()
    with _pg_registry_lock:
        pool = _pg_pools.get(loop)
        lock = _pg_pool_locks.setdefault(loop, asyncio.Lock())
    if pool is not None and not pool._closed:
        _db._pg_pool = pool
        return pool
    async with lock:
        with _pg_registry_lock:
            pool = _pg_pools.get(loop)
        if pool is None or pool._closed:
            # Mirror routes.database._get_pg_pool, which pins the session
            # time zone so TEXT timestamps cast to timestamptz compare to NOW().
            pool = await _db.asyncpg.create_pool(
                _db.APP_DATABASE_URL, min_size=1, max_size=10, server_settings={"timezone": "UTC"}
            )
            with _pg_registry_lock:
                _pg_pools[loop] = pool
    _db._pg_pool = pool
    return pool


_orig_close_db_pool = _db.close_db_pool


async def _pg_close_db_pool_per_loop():
    loop = asyncio.get_running_loop()
    with _pg_registry_lock:
        pool = _pg_pools.pop(loop, None)
        _pg_pool_locks.pop(loop, None)
    # The original closes whatever _db._pg_pool holds (and the SQLite bits).
    _db._pg_pool = pool
    await _orig_close_db_pool()


if PG_MODE:
    _db._get_pg_pool = _pg_get_pool_per_loop
    _db.close_db_pool = _pg_close_db_pool_per_loop


def _pg_dispose_pools_sync() -> None:
    """Close every per-loop pool from synchronous teardown."""
    with _pg_registry_lock:
        items = list(_pg_pools.items())
        _pg_pools.clear()
        _pg_pool_locks.clear()
    _db._pg_pool = None
    for loop, pool in items:
        try:
            if not loop.is_closed() and not loop.is_running():
                loop.run_until_complete(asyncio.wait_for(pool.close(), timeout=5))
                continue
        except Exception:
            pass
        try:
            pool.terminate()
        except Exception:
            # The loop is closed, so the transports cannot be aborted
            # cleanly; the server side is reaped by DROP DATABASE ... FORCE.
            pass


def _pg_run(coro):
    """Run admin coroutines on a private loop (never touches the test's loop)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _pg_admin(*statements: str) -> None:
    conn = await _db.asyncpg.connect(_PG_MAINT_URL)
    try:
        for stmt in statements:
            await conn.execute(stmt)
    finally:
        await conn.close()


def _pg_clone_test_db() -> None:
    _pg_run(
        _pg_admin(
            f'DROP DATABASE IF EXISTS "{_PG_DB_NAME}" WITH (FORCE)',
            f'CREATE DATABASE "{_PG_DB_NAME}" TEMPLATE "{_PG_TEMPLATE_NAME}"',
        )
    )


def _pg_build_template() -> None:
    _pg_run(
        _pg_admin(
            f'DROP DATABASE IF EXISTS "{_PG_TEMPLATE_NAME}" WITH (FORCE)',
            f'CREATE DATABASE "{_PG_TEMPLATE_NAME}"',
        )
    )
    saved_url, saved_engine = _db.APP_DATABASE_URL, _db.DB_ENGINE
    _db.APP_DATABASE_URL, _db.DB_ENGINE = _PG_TEMPLATE_URL, "postgres"
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_db.init_db())
        loop.run_until_complete(_pg_close_db_pool_per_loop())
    finally:
        loop.close()
        _pg_dispose_pools_sync()
        _db._held.set(None)
        _db.APP_DATABASE_URL, _db.DB_ENGINE = saved_url, saved_engine


@pytest.fixture(scope="session", autouse=True)
def _pg_session_template():
    if PG_MODE:
        _pg_build_template()
    yield


@pytest.fixture(autouse=True)
def _pg_fresh_database(_pg_session_template):
    """Postgres mode: give the test a pristine clone of the template DB."""
    global _pg_dirty
    if PG_MODE and _pg_dirty:
        _pg_dispose_pools_sync()
        _pg_clone_test_db()
        _pg_dirty = False
    yield


# ── Leaked TestClient tracking ───────────────────────────────────────────────
#
# Several test files call ``client.__enter__()`` in a plain helper and never
# exit the client.  Each leak leaves the app's portal thread, event loop and
# ~24 background loop tasks running for the rest of the pytest process.  Those
# zombie loops keep doing DB work against the *current* module-level state
# (DB_PATH, the SQLite singleton, asyncio locks) from a foreign thread, which
# corrupts later tests: asyncio primitives are not thread-safe, so a leaked
# loop contending on the access lock can leave the active test's waiter
# unwoken forever — order-dependent hangs and flaky failures.
#
# Wrap __enter__/__exit__ to keep a registry of live clients, and force-close
# any leftovers after each test.  DB_PATH is stashed at enter time and
# restored around the forced close because the test's ``monkeypatch`` fixture
# (which set DB_PATH) tears down before this autouse fixture runs.

_live_clients: list = []
_orig_enter = _stc.TestClient.__enter__
_orig_exit = _stc.TestClient.__exit__


def _tracking_enter(self):
    result = _orig_enter(self)
    self._plexus_db_path = _db.DB_PATH
    _live_clients.append(self)
    return result


def _tracking_exit(self, *exc):
    # Idempotent: tests/fixtures may close explicitly while a helper-registered
    # finalizer (or this conftest's safety net) also fires. The second exit of
    # an already-shut-down client must be a no-op, not an error.
    if getattr(self, "_plexus_exited", False):
        return None
    self._plexus_exited = True
    try:
        return _orig_exit(self, *exc)
    finally:
        try:
            _live_clients.remove(self)
        except ValueError:
            pass


_stc.TestClient.__enter__ = _tracking_enter
_stc.TestClient.__exit__ = _tracking_exit


@pytest.fixture(autouse=True)
def _reset_db_singleton():
    """Close leaked TestClients and dispose shared DB state after every test.

    pytest-asyncio gives each test its own event loop, and many sync tests
    call asyncio.run() repeatedly (a fresh, then-closed loop each time).  The
    module-level connection singleton is owned by the loop that built it, so
    without teardown a connection (and its non-daemon worker thread, holding
    the WAL file lock) would leak into the next test and make failures depend
    on run order.  Tearing it down here keeps each test isolated.  The helper
    is loop-independent, so it is safe whether or not a loop is still live.
    """
    yield
    # Shut down leaked clients first: their lifespan shutdown needs the DB
    # machinery still intact, and nothing they hold may survive into the
    # next test.
    while _live_clients:
        client = _live_clients.pop()
        client._plexus_exited = True
        saved_path = _db.DB_PATH
        _db.DB_PATH = getattr(client, "_plexus_db_path", saved_path)
        try:
            _orig_exit(client, None, None)
        except Exception:
            pass
        finally:
            _db.DB_PATH = saved_path
    _db._dispose_sqlite_singleton_sync()
    if PG_MODE:
        # Pools are bound to (now mostly closed) per-test loops.
        _pg_dispose_pools_sync()
        _db.APP_DATABASE_URL = _PG_TEST_URL
    # monkeypatch already restores DB_ENGINE for tests that opt into Postgres,
    # but a test that assigns the attribute directly (or a leaked client)
    # must not leave the next test pointed at a real database (SQLite mode)
    # or at SQLite (Postgres mode).
    _db.DB_ENGINE = _TEST_DB_ENGINE
    # Same hazard for the audit chain lock: if a test's loop closes while a
    # task is suspended inside add_audit_event's critical section, the task
    # is abandoned mid-`async with` and the lock stays held forever.  The
    # next acquire (e.g. app-lifespan audit writes) would then wait on a
    # release that never comes — an order-dependent hang, not a failure.
    _db_audit._audit_chain_lock = asyncio.Lock()
