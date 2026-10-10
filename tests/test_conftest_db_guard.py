"""Guard: the test suite must only ever run against a throwaway Postgres database.

tests/conftest.py requires PLEXUS_TEST_PG_URL, refuses database names that do
not end in ``_test`` (or that are ``plexus``, the dev database), and points the
app at that database before anything imports ``routes.*``.  Running pytest from
a shell with scripts/dev-env.* dot-sourced (which exports APP_DATABASE_URL for
the developer's live database) must never let a test write there.
"""

from __future__ import annotations

import os
from urllib.parse import unquote, urlsplit

import routes.database as db_module


def _db_name(url: str) -> str:
    return unquote(urlsplit(url).path.lstrip("/"))


def test_engine_is_postgres():
    assert os.environ["APP_DB_ENGINE"] == "postgres"


def test_app_points_at_a_throwaway_test_database():
    name = _db_name(db_module.APP_DATABASE_URL)
    assert name != "plexus"
    # Under pytest-xdist each worker appends its id: <name>_test_<worker>.
    worker = os.environ.get("PYTEST_XDIST_WORKER", "").strip()
    base = name[: -(len(worker) + 1)] if worker and name.endswith(f"_{worker}") else name
    assert base.endswith("_test"), name
    assert os.environ["APP_DATABASE_URL"] == db_module.APP_DATABASE_URL
