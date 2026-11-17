"""
Migration 0099: circuits (carrier circuits and where they terminate).

Adds:

  - circuit_providers - a carrier: ``name`` (unique ignoring case),
    ``account``, ``portal_url``, ``noc_contact``, ``admin_contact``,
    ``comments`` and the stamps. A provider with circuits cannot be deleted.
  - provider_networks - a network of a provider a circuit can end in (an
    MPLS cloud, an internet service): ``provider_id`` (deleted with the
    provider), ``name`` (unique per provider ignoring case), ``description``.
  - circuit_types - a kind of circuit (``Internet``, ``MPLS``...): ``name``
    (unique ignoring case), ``description``. A type in use cannot be deleted.
  - circuits - ``cid`` (the provider's circuit id, unique per provider
    ignoring case), ``provider_id`` and ``circuit_type_id`` (both RESTRICT),
    ``status`` (``planned``, ``provisioning``, ``active``, ``offline``,
    ``deprovisioning``, ``decommissioned``), ``tenant_id`` (cleared when the
    tenant goes), ``install_date`` and ``termination_date`` (``YYYY-MM-DD``
    text, ``''`` when unset), ``commit_rate_kbps`` (NULL when unset),
    ``description``, ``comments``, ``billing_circuit_id`` (the bandwidth
    billing record of migration 0009 the circuit is billed by, cleared when
    that record goes) and the stamps.
  - circuit_terminations - the A and Z ends of a circuit (deleted with it):
    ``term_side`` (``A`` or ``Z``, one of each per circuit), exactly one of
    ``site_id`` (a ``geo_sites`` row; the termination goes with the site) or
    ``provider_network_id`` (RESTRICT), optionally the device and port it
    lands on (``host_id``, cleared when the host goes, and
    ``interface_name`` as interface inventory and stats name it),
    ``port_speed_kbps``, ``upstream_speed_kbps``, ``xconnect_id``,
    ``pp_info``, ``description`` and the stamps. ``id`` is a plain SERIAL:
    cables (DCIM) point at a termination by it.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 99
DESCRIPTION = "Add circuits, circuit providers, provider networks, circuit types and terminations"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT '',
            updated_by  TEXT NOT NULL DEFAULT ''
"""

_STATUSES = "'planned', 'provisioning', 'active', 'offline', 'deprovisioning', 'decommissioned'"


async def up(db) -> None:
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS circuit_providers (
            id            SERIAL PRIMARY KEY,
            name          TEXT NOT NULL,
            account       TEXT NOT NULL DEFAULT '',
            portal_url    TEXT NOT NULL DEFAULT '',
            noc_contact   TEXT NOT NULL DEFAULT '',
            admin_contact TEXT NOT NULL DEFAULT '',
            comments      TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_circuit_providers_name ON circuit_providers (lower(name))")
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS provider_networks (
            id          SERIAL PRIMARY KEY,
            provider_id INTEGER NOT NULL REFERENCES circuit_providers(id) ON DELETE CASCADE,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_networks_name ON provider_networks (provider_id, lower(name))"
    )
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS circuit_types (
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_circuit_types_name ON circuit_types (lower(name))")
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS circuits (
            id                 SERIAL PRIMARY KEY,
            cid                TEXT    NOT NULL,
            provider_id        INTEGER NOT NULL REFERENCES circuit_providers(id) ON DELETE RESTRICT,
            circuit_type_id    INTEGER NOT NULL REFERENCES circuit_types(id) ON DELETE RESTRICT,
            status             TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ({_STATUSES})),
            tenant_id          INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            install_date       TEXT    NOT NULL DEFAULT '',
            termination_date   TEXT    NOT NULL DEFAULT '',
            commit_rate_kbps   BIGINT  CHECK (commit_rate_kbps IS NULL OR commit_rate_kbps >= 0),
            description        TEXT    NOT NULL DEFAULT '',
            comments           TEXT    NOT NULL DEFAULT '',
            billing_circuit_id INTEGER REFERENCES billing_circuits(id) ON DELETE SET NULL,
            {_STAMPS}
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_circuits_provider_cid ON circuits (provider_id, lower(cid))"
    )
    for column in ("circuit_type_id", "tenant_id", "status", "billing_circuit_id"):
        await db.execute(f"CREATE INDEX IF NOT EXISTS idx_circuits_{column} ON circuits ({column})")
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS circuit_terminations (
            id                  SERIAL PRIMARY KEY,
            circuit_id          INTEGER NOT NULL REFERENCES circuits(id) ON DELETE CASCADE,
            term_side           TEXT    NOT NULL CHECK (term_side IN ('A', 'Z')),
            site_id             INTEGER REFERENCES geo_sites(id) ON DELETE CASCADE,
            provider_network_id INTEGER REFERENCES provider_networks(id) ON DELETE RESTRICT,
            host_id             INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            interface_name      TEXT    NOT NULL DEFAULT '',
            port_speed_kbps     BIGINT  CHECK (port_speed_kbps IS NULL OR port_speed_kbps >= 0),
            upstream_speed_kbps BIGINT  CHECK (upstream_speed_kbps IS NULL OR upstream_speed_kbps >= 0),
            xconnect_id         TEXT    NOT NULL DEFAULT '',
            pp_info             TEXT    NOT NULL DEFAULT '',
            description         TEXT    NOT NULL DEFAULT '',
            {_STAMPS},
            UNIQUE (circuit_id, term_side),
            CHECK ((site_id IS NULL) <> (provider_network_id IS NULL))
        )
        """
    )
    for column in ("site_id", "provider_network_id", "host_id"):
        await db.execute(
            f"CREATE INDEX IF NOT EXISTS idx_circuit_terminations_{column} ON circuit_terminations ({column})"
        )
    await db.commit()
