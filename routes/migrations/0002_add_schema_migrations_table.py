"""
This is a no-op migration that exists solely to verify the migration
framework works end-to-end.  The ``schema_migrations`` table is already
created by the runner itself; this file serves as a template for future
migrations.

To create a new migration:
  1. Copy this file as ``NNNN_short_description.py`` (increment NNNN).
  2. Set VERSION to the same integer as the filename prefix.
  3. Write your schema changes in the ``up()`` function.
  4. Restart the application — the runner applies it automatically.
"""

VERSION = 2
DESCRIPTION = "No-op: verify migration framework"


async def up(db) -> None:
    # Nothing to do — the schema_migrations table is created by the runner.
    pass
