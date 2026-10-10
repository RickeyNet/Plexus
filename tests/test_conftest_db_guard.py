"""Guard: the test suite must never default to the Postgres backend.

tests/conftest.py pins APP_DB_ENGINE=sqlite so that running pytest from a
shell with scripts/dev-env.* dot-sourced cannot write fixtures into the
developer's dev database.  Only tests that explicitly monkeypatch
``routes.database.DB_ENGINE`` (tests/test_postgres_backend.py) use Postgres.
"""

from __future__ import annotations

import asyncio
import os

import pytest
import routes.database as db_module

# These assert the SQLite default; PLEXUS_TEST_PG_URL deliberately changes it.
pytestmark = pytest.mark.sqlite_only


def test_default_engine_is_sqlite():
    assert os.environ["APP_DB_ENGINE"] == "sqlite"
    assert db_module.DB_ENGINE == "sqlite"


def test_db_path_tests_build_their_own_sqlite_file(tmp_path, monkeypatch):
    # Even with APP_DATABASE_URL set (dev-env shell), a DB_PATH-based test
    # must create and use its own SQLite file.
    db_path = tmp_path / "guard.db"
    monkeypatch.setattr(db_module, "DB_PATH", str(db_path))
    asyncio.run(db_module.init_db())
    assert db_path.exists()
