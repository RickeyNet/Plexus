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

import pytest

# ── Test database (PostgreSQL only) ─────────────────────────────────────────
#
# Plexus runs on PostgreSQL only, and so does the suite.  PLEXUS_TEST_PG_URL
# is REQUIRED and names a throwaway database, e.g.
#
#     postgresql://plexus:<password>@127.0.0.1:5432/plexus_test
#
# The database named in the URL is DESTROYED and recreated over and over, so
# the name must end in ``_test`` and must not be ``plexus`` (the dev
# database); otherwise pytest refuses to start.  The suite never falls back to
# APP_DATABASE_URL: scripts/dev-env.ps1 / dev-env.sh export that for the
# developer's live database, and the suite DROPs whatever it is pointed at.
#
# At session start the schema is built once (init_db) into
# ``<name>_template``; before each test that follows a test which touched the
# database, ``<name>`` is dropped and re-cloned from that template (CREATE
# DATABASE ... TEMPLATE), so every test starts from the post-init_db state.
# Under pytest-xdist each worker gets its own ``<name>_<worker>`` database.
# See DEVSETUP.md.
_PG_TEST_URL_RAW = os.environ.get("PLEXUS_TEST_PG_URL", "").strip()
_PG_MODE_ERROR = ""
_PG_TEST_URL = ""  # URL of the per-test database (what the app connects to)
_PG_TEMPLATE_URL = ""
_PG_MAINT_URL = ""  # the "postgres" maintenance database, for DROP/CREATE
_PG_DB_NAME = ""
_PG_TEMPLATE_NAME = ""


def _pg_url_with_db(parts, name: str) -> str:
    return urlunsplit((parts.scheme, parts.netloc, "/" + name, parts.query, parts.fragment))


if not _PG_TEST_URL_RAW:
    _PG_MODE_ERROR = (
        "PLEXUS_TEST_PG_URL is not set. The test suite runs on PostgreSQL only and needs a "
        "throwaway database it may DROP and recreate, e.g. "
        "PLEXUS_TEST_PG_URL=postgresql://plexus:<password>@127.0.0.1:5432/plexus_test "
        "(the name must end in '_test'). It never falls back to APP_DATABASE_URL. See DEVSETUP.md."
    )
else:
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
        _worker = os.environ.get("PYTEST_XDIST_WORKER", "").strip()
        _PG_DB_NAME = f"{_configured_name}_{_worker}" if _worker else _configured_name
        _PG_TEMPLATE_NAME = f"{_PG_DB_NAME}_template"
        _PG_TEST_URL = _pg_url_with_db(_parts, _PG_DB_NAME)
        _PG_TEMPLATE_URL = _pg_url_with_db(_parts, _PG_TEMPLATE_NAME)
        _PG_MAINT_URL = _pg_url_with_db(_parts, "postgres")

if _PG_MODE_ERROR:
    # Fail fast, before anything imports routes.* with whatever
    # APP_DATABASE_URL the shell happens to carry.
    raise pytest.UsageError(_PG_MODE_ERROR)

# Pin the app to the per-test database before anything imports routes.*.
os.environ["APP_DB_ENGINE"] = "postgres"
os.environ["APP_DATABASE_URL"] = _PG_TEST_URL

import routes.database as _db  # noqa: E402
import routes.db.audit as _db_audit  # noqa: E402
import starlette.testclient as _stc  # noqa: E402

# Belt and braces: routes.database may already have been imported (pytest
# plugins, rootdir conftest, ...) before the environment was pinned above.
_db.APP_DATABASE_URL = _PG_TEST_URL


def pytest_configure(config):
    # Normally unreachable (the import-time check above raises first); kept so
    # the guard holds even if this module is ever loaded as a plain plugin.
    if _PG_MODE_ERROR or not _PG_TEST_URL:
        raise pytest.UsageError(_PG_MODE_ERROR or "PLEXUS_TEST_PG_URL is required")


# ── Per-loop pools and per-test database reset ──────────────────────────────
#
# The app keeps ONE module-global asyncpg pool, created on whichever loop
# first calls get_db().  Production has a single loop; the suite does not:
# pytest-asyncio gives every test its own loop, sync tests call asyncio.run()
# repeatedly, and TestClient runs the app on a portal-thread loop that can be
# live at the same time as the test's own loop.  An asyncpg pool is bound to
# its loop, so get_db()'s pool lookup is replaced with one that keeps a pool
# per running loop, and close_db_pool() closes the calling loop's pool.
# After each test every remaining pool is closed (or, if its loop is already
# gone, terminated) so nothing survives into the next test.

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
    # The original closes whatever _db._pg_pool holds.
    _db._pg_pool = pool
    await _orig_close_db_pool()


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
    saved_url = _db.APP_DATABASE_URL
    _db.APP_DATABASE_URL = _PG_TEMPLATE_URL
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_db.init_db())
        loop.run_until_complete(_pg_close_db_pool_per_loop())
    finally:
        loop.close()
        _pg_dispose_pools_sync()
        _db._held.set(None)
        _db.APP_DATABASE_URL = saved_url


@pytest.fixture(scope="session", autouse=True)
def _pg_session_template():
    _pg_build_template()
    yield


@pytest.fixture(autouse=True)
def _pg_fresh_database(_pg_session_template):
    """Give the test a pristine clone of the template DB."""
    global _pg_dirty
    if _pg_dirty:
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
# (the pool registry, asyncio locks) from a foreign thread, which corrupts
# later tests: asyncio primitives are not thread-safe, so a leaked loop
# contending on a lock can leave the active test's waiter unwoken forever —
# order-dependent hangs and flaky failures.
#
# Wrap __enter__/__exit__ to keep a registry of live clients, and force-close
# any leftovers after each test.

_live_clients: list = []
_orig_enter = _stc.TestClient.__enter__
_orig_exit = _stc.TestClient.__exit__


def _tracking_enter(self):
    result = _orig_enter(self)
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
    asyncpg pools are owned by the loops that built them, so without teardown
    a pool would leak into the next test and make failures depend on run
    order.  Tearing them down here keeps each test isolated; the helper is
    loop-independent, so it is safe whether or not a loop is still live.
    """
    yield
    # Shut down leaked clients first: their lifespan shutdown needs the DB
    # machinery still intact, and nothing they hold may survive into the
    # next test.
    while _live_clients:
        client = _live_clients.pop()
        client._plexus_exited = True
        try:
            _orig_exit(client, None, None)
        except Exception:
            pass
    # A test that failed mid-section must not leave a held connection behind.
    _db._held.set(None)
    # Pools are bound to (now mostly closed) per-test loops.
    _pg_dispose_pools_sync()
    # A test (or leaked client) that repointed the app must not leave the
    # next test aimed at another database.
    _db.APP_DATABASE_URL = _PG_TEST_URL
    # Same hazard for the audit chain lock: if a test's loop closes while a
    # task is suspended inside add_audit_event's critical section, the task
    # is abandoned mid-`async with` and the lock stays held forever.  The
    # next acquire (e.g. app-lifespan audit writes) would then wait on a
    # release that never comes — an order-dependent hang, not a failure.
    _db_audit._audit_chain_lock = asyncio.Lock()
