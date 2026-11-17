"""
Migration 0101: routing objects (the intended BGP state of devices).

Adds:

  - autonomous_systems - an AS number (``asn``, 1 to 4294967295, unique),
    ``description``, ``tenant_id`` (cleared when the tenant is deleted),
    ``rir`` (the registry that assigned it, free text), ``comments`` and the
    stamps.
  - routing_instances - a routing process of a device (``host_id``, deleted
    with the host): ``name`` (``default`` or a VRF-specific instance; unique
    per host, ignoring case), ``vrf_id`` (cleared when the VRF goes), the
    local ``autonomous_system_id`` (an AS in use cannot be deleted),
    ``router_id`` (IPv4 text or empty), ``status`` (``planned``, ``active``,
    ``decommissioned``), ``description`` and the stamps.
  - bgp_peer_groups - a named template of an instance (deleted with it;
    name unique per instance, ignoring case): optional ``remote_asn_id``
    (cleared when the AS goes), ``import_policy``, ``export_policy``,
    ``description`` and the stamps.
  - bgp_peerings - one intended BGP session of an instance (deleted with
    it): optional ``peer_group_id`` (cleared when the group goes),
    ``local_address`` (may be empty), ``remote_address`` (unique per
    instance), ``remote_asn_id`` (an AS in use cannot be deleted), optional
    ``remote_host_id`` (the peer when it is a Plexus device; cleared when
    the host goes), ``status`` (``planned``, ``active``, ``disabled``,
    ``decommissioned``), ``address_families`` (comma-separated, from a fixed
    set), ``import_policy``, ``export_policy``, ``description`` and the
    stamps.

Addresses, families and the router id are validated by the application
(``netcontrol.routing``). Timestamps are written by Plexus as UTC
``YYYY-MM-DD HH:MM:SS`` text. Every step is idempotent.
"""

from __future__ import annotations

VERSION = 101
DESCRIPTION = "Add autonomous systems, routing instances, BGP peer groups and BGP peerings"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT '',
            updated_by  TEXT NOT NULL DEFAULT ''
"""


async def up(db) -> None:
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS autonomous_systems (
            id          SERIAL PRIMARY KEY,
            asn         BIGINT NOT NULL CHECK (asn BETWEEN 1 AND 4294967295),
            description TEXT NOT NULL DEFAULT '',
            tenant_id   INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            rir         TEXT NOT NULL DEFAULT '',
            comments    TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_autonomous_systems_asn ON autonomous_systems (asn)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_autonomous_systems_tenant ON autonomous_systems (tenant_id)")
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS routing_instances (
            id                   SERIAL PRIMARY KEY,
            host_id              INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            name                 TEXT NOT NULL,
            vrf_id               INTEGER REFERENCES vrfs(id) ON DELETE SET NULL,
            autonomous_system_id INTEGER NOT NULL REFERENCES autonomous_systems(id) ON DELETE RESTRICT,
            router_id            TEXT NOT NULL DEFAULT '',
            status               TEXT NOT NULL DEFAULT 'active'
                                 CHECK (status IN ('planned', 'active', 'decommissioned')),
            description          TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_routing_instances_host_name ON routing_instances (host_id, lower(name))"
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_routing_instances_as ON routing_instances (autonomous_system_id)")
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS bgp_peer_groups (
            id                  SERIAL PRIMARY KEY,
            routing_instance_id INTEGER NOT NULL REFERENCES routing_instances(id) ON DELETE CASCADE,
            name                TEXT NOT NULL,
            remote_asn_id       INTEGER REFERENCES autonomous_systems(id) ON DELETE SET NULL,
            import_policy       TEXT NOT NULL DEFAULT '',
            export_policy       TEXT NOT NULL DEFAULT '',
            description         TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_bgp_peer_groups_instance_name "
        "ON bgp_peer_groups (routing_instance_id, lower(name))"
    )
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS bgp_peerings (
            id                  SERIAL PRIMARY KEY,
            routing_instance_id INTEGER NOT NULL REFERENCES routing_instances(id) ON DELETE CASCADE,
            peer_group_id       INTEGER REFERENCES bgp_peer_groups(id) ON DELETE SET NULL,
            local_address       TEXT NOT NULL DEFAULT '',
            remote_address      TEXT NOT NULL,
            remote_asn_id       INTEGER NOT NULL REFERENCES autonomous_systems(id) ON DELETE RESTRICT,
            remote_host_id      INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
            status              TEXT NOT NULL DEFAULT 'active'
                                CHECK (status IN ('planned', 'active', 'disabled', 'decommissioned')),
            address_families    TEXT NOT NULL DEFAULT '',
            import_policy       TEXT NOT NULL DEFAULT '',
            export_policy       TEXT NOT NULL DEFAULT '',
            description         TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_bgp_peerings_instance_remote "
        "ON bgp_peerings (routing_instance_id, remote_address)"
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_bgp_peerings_remote_as ON bgp_peerings (remote_asn_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_bgp_peerings_group ON bgp_peerings (peer_group_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_bgp_peerings_remote_host ON bgp_peerings (remote_host_id)")
    await db.commit()
