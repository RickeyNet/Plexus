"""Stateful vendor-API integrations (REST/cloud clients).

Distinct from ``netcontrol.drivers.*``, which are *stateless* command
builders that do no network I/O.  Integrations here own connections,
auth tokens, and sessions - they talk to off-box / on-box management
APIs and normalise the results into Plexus's existing tables so the
monitoring, drift, topology, and compliance engines work unchanged.

First integration: ``cisco_fdm`` (Cisco FTD managed on-box by Firepower
Device Manager).
"""
