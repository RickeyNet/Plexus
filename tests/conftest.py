import datetime as _dt
import sys

# Python 3.11 added datetime.UTC as a convenience alias.  Polyfill it for
# older interpreters so the production code (which uses ``from datetime import
# UTC``) can be imported without modification during tests.
if sys.version_info < (3, 11) and not hasattr(_dt, "UTC"):
    _dt.UTC = _dt.UTC

import asyncio

import pytest
import routes.database as _db
import routes.db.audit as _db_audit
import starlette.testclient as _stc

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
        saved_path = _db.DB_PATH
        _db.DB_PATH = getattr(client, "_plexus_db_path", saved_path)
        try:
            _orig_exit(client, None, None)
        except Exception:
            pass
        finally:
            _db.DB_PATH = saved_path
    _db._dispose_sqlite_singleton_sync()
    # Same hazard for the audit chain lock: if a test's loop closes while a
    # task is suspended inside add_audit_event's critical section, the task
    # is abandoned mid-`async with` and the lock stays held forever.  The
    # next acquire (e.g. app-lifespan audit writes) would then wait on a
    # release that never comes — an order-dependent hang, not a failure.
    _db_audit._audit_chain_lock = asyncio.Lock()
