"""Sync framework: bidirectional synchronisation between Plexus and external
sources of truth (NetBox, Nautobot, ServiceNow CMDB).

- ``models``: the object types Plexus syncs, their natural keys and fields,
  value normalisation and the per-job field mappings.
- ``engine``: the diff engine (natural keys, per-field diffs) and the plan
  that turns a diff into create / update / delete / conflict entries for a
  direction and conflict policy.
- ``adapters``: one adapter per system (``plexus``, ``netbox``/``nautobot``,
  ``servicenow``), each loading records and applying planned entries.
- ``transport``: the guarded HTTP JSON client the remote adapters (and the
  IPAM / DHCP provider adapters) share.
- ``runner``: runs a stored job (dry run or real), records the run and its
  per-object outcomes, and the scheduler loop.

Docs: ``docs/sync-framework.md``.
"""
