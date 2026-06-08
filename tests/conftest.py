import datetime as _dt
import sys

# Python 3.11 added datetime.UTC as a convenience alias.  Polyfill it for
# older interpreters so the production code (which uses ``from datetime import
# UTC``) can be imported without modification during tests.
if sys.version_info < (3, 11) and not hasattr(_dt, "UTC"):
    _dt.UTC = _dt.UTC

import pytest
import routes.database as _db


@pytest.fixture(autouse=True)
def _reset_db_singleton():
    """Dispose the shared SQLite connection after every test.

    pytest-asyncio gives each test its own event loop, and many sync tests
    call asyncio.run() repeatedly (a fresh, then-closed loop each time).  The
    module-level connection singleton is owned by the loop that built it, so
    without teardown a connection (and its non-daemon worker thread, holding
    the WAL file lock) would leak into the next test and make failures depend
    on run order.  Tearing it down here keeps each test isolated.  The helper
    is loop-independent, so it is safe whether or not a loop is still live.
    """
    yield
    _db._dispose_sqlite_singleton_sync()
