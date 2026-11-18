"""APC Smart-UPS behind an APC Network Management Card (NMC2 / NMC3).

The card answers SNMP (PowerNet-MIB, enterprise 318) and has its own
command line over SSH, but nothing Plexus runs over SSH applies to a UPS:
there are no show tables, routes, VLANs or a running configuration to back
up. Plexus monitors it over SNMP and ICMP like the SNMP-only switches and
never opens a Netmiko session to it (``cli = False``), so jobs, config
backups, inventory collection and the SSH part of the monitoring poll skip
it. What the poll reads from the card is in
``netcontrol/integrations/apc/snmp.py``; ``docs/apc-ups.md`` has the setup.
"""

from __future__ import annotations

from netcontrol.drivers.base import Driver, register_driver


@register_driver
class ApcUpsDriver(Driver):
    """An APC Smart-UPS through its Network Management Card: SNMP and ICMP
    only. Every command capability keeps the raising default."""

    device_types = ("apc_ups",)
    vendor = "apc"
    display_name = "APC Smart-UPS (NMC)"
    cli = False
