"""
Migration 0100: virtualization (clusters and virtual machines).

Adds:

  - cluster_types - the kind of a cluster (``VMware vSphere``, ``Proxmox``,
    ``AWS EC2``...): ``name`` (unique ignoring case), ``description``.
  - cluster_groups - a free grouping of clusters: ``name`` (unique ignoring
    case), ``description``.
  - clusters - a pool of compute: ``name`` (unique ignoring case),
    ``cluster_type_id`` (required; a type with clusters cannot be deleted),
    ``cluster_group_id``, ``site_id`` (``geo_sites``) and ``tenant_id``
    (cleared when the group, site or tenant goes), ``description``,
    ``comments``, ``origin`` (``manual`` or ``discovered``) and
    ``cloud_key`` (``provider:account id:region`` of a cluster the cloud sync
    created; ``''`` otherwise, unique when set).
  - cluster_hosts - the physical hypervisors (``hosts``) of a cluster; one
    row per pair, deleted with either side.
  - virtual_machines - ``name`` (unique per cluster ignoring case),
    ``cluster_id`` (required; a cluster with VMs cannot be deleted),
    ``status`` (``active``, ``offline``, ``planned``, ``staged``, ``failed``,
    ``decommissioning``), ``role_id`` (``device_roles``) and ``tenant_id``
    (cleared when they go), ``platform``, ``vcpus``, ``memory_mb``,
    ``disk_gb``, ``primary_ip4``, ``primary_ip6``, the discovered cloud
    resource it mirrors (``cloud_resource_id``, unique, cleared when the
    resource row goes, plus ``cloud_account_id`` and ``cloud_resource_uid``,
    which survive the snapshot replace a cloud discovery does, so the next
    sync finds the VM again), ``origin``, ``description``, ``comments``.
  - vm_interfaces - a VM's interfaces: ``name`` (unique per VM ignoring
    case), ``enabled``, ``mac_address``, ``mtu``, ``mode`` (``access``,
    ``tagged`` or ``''``), ``untagged_vlan_id`` (``vlans``) and ``vrf_id``
    (``vrfs``), cleared when those go, ``description``.
  - vm_interface_addresses - the CIDR addresses of a VM interface, unique
    per interface.

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 100
DESCRIPTION = "Add virtualization: cluster types, groups, clusters, virtual machines and VM interfaces"

_STAMPS = """
            created_by  TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT '',
            updated_by  TEXT NOT NULL DEFAULT ''
"""


async def up(db) -> None:
    for table in ("cluster_types", "cluster_groups"):
        await db.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table} (
                id          SERIAL PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                {_STAMPS}
            )
            """  # nosec B608 - fixed table names
        )
        await db.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{table}_name ON {table} (lower(name))")

    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS clusters (
            id               SERIAL PRIMARY KEY,
            name             TEXT NOT NULL,
            cluster_type_id  INTEGER NOT NULL REFERENCES cluster_types(id) ON DELETE RESTRICT,
            cluster_group_id INTEGER REFERENCES cluster_groups(id) ON DELETE SET NULL,
            site_id          INTEGER REFERENCES geo_sites(id) ON DELETE SET NULL,
            tenant_id        INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            description      TEXT NOT NULL DEFAULT '',
            comments         TEXT NOT NULL DEFAULT '',
            origin           TEXT NOT NULL DEFAULT 'manual',
            cloud_key        TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_clusters_name ON clusters (lower(name))")
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_clusters_cloud_key ON clusters (cloud_key) WHERE cloud_key <> ''"
    )
    for column in ("cluster_type_id", "cluster_group_id", "site_id", "tenant_id"):
        await db.execute(f"CREATE INDEX IF NOT EXISTS idx_clusters_{column} ON clusters ({column})")

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS cluster_hosts (
            cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
            host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (cluster_id, host_id)
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_cluster_hosts_host ON cluster_hosts (host_id)")

    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS virtual_machines (
            id                 SERIAL PRIMARY KEY,
            name               TEXT NOT NULL,
            cluster_id         INTEGER NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
            status             TEXT NOT NULL DEFAULT 'active',
            role_id            INTEGER REFERENCES device_roles(id) ON DELETE SET NULL,
            tenant_id          INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            platform           TEXT NOT NULL DEFAULT '',
            vcpus              INTEGER,
            memory_mb          INTEGER,
            disk_gb            INTEGER,
            primary_ip4        TEXT NOT NULL DEFAULT '',
            primary_ip6        TEXT NOT NULL DEFAULT '',
            cloud_resource_id  INTEGER UNIQUE REFERENCES cloud_resources(id) ON DELETE SET NULL,
            cloud_account_id   INTEGER REFERENCES cloud_accounts(id) ON DELETE SET NULL,
            cloud_resource_uid TEXT NOT NULL DEFAULT '',
            origin             TEXT NOT NULL DEFAULT 'manual',
            description        TEXT NOT NULL DEFAULT '',
            comments           TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_virtual_machines_cluster_name "
        "ON virtual_machines (cluster_id, lower(name))"
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_virtual_machines_cloud_uid "
        "ON virtual_machines (cloud_account_id, cloud_resource_uid) WHERE cloud_resource_uid <> ''"
    )
    for column in ("status", "role_id", "tenant_id", "cloud_account_id"):
        await db.execute(f"CREATE INDEX IF NOT EXISTS idx_virtual_machines_{column} ON virtual_machines ({column})")

    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS vm_interfaces (
            id               SERIAL PRIMARY KEY,
            vm_id            INTEGER NOT NULL REFERENCES virtual_machines(id) ON DELETE CASCADE,
            name             TEXT NOT NULL,
            enabled          INTEGER NOT NULL DEFAULT 1,
            mac_address      TEXT NOT NULL DEFAULT '',
            mtu              INTEGER,
            mode             TEXT NOT NULL DEFAULT '',
            untagged_vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL,
            vrf_id           INTEGER REFERENCES vrfs(id) ON DELETE SET NULL,
            description      TEXT NOT NULL DEFAULT '',
            {_STAMPS}
        )
        """
    )
    await db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vm_interfaces_vm_name ON vm_interfaces (vm_id, lower(name))"
    )

    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS vm_interface_addresses (
            id              SERIAL PRIMARY KEY,
            vm_interface_id INTEGER NOT NULL REFERENCES vm_interfaces(id) ON DELETE CASCADE,
            address         TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT '',
            UNIQUE (vm_interface_id, address)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vm_interface_addresses_address ON vm_interface_addresses (address)"
    )
    await db.commit()
