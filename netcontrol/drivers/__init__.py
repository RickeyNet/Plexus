"""Multi-vendor device driver framework.

A ``Driver`` encapsulates everything platform-specific about a device:
which command syntax to emit, which ``show`` command verifies a change,
which Netmiko ``device_type`` string to use when opening a session.

Plexus has historically used Cisco-flavoured ``device_type`` strings
(``cisco_ios`` / ``cisco_xe`` / ``cisco_nxos``) sprinkled across the
codebase with per-platform ``if/elif`` chains.  The drivers package
replaces that pattern with a single ABC and a registry, so adding a new
vendor is one class instead of edits in a dozen files.

Phase 1 (this commit) ships the interface plus the three Cisco drivers
needed to back the existing NetFlow playbook.  Later phases will fold in
backup, monitoring, and topology call sites, and ship real drivers for
Juniper / Arista / etc.

Public surface::

    from netcontrol.drivers import Driver, get_driver, register_driver
    drv = get_driver("cisco_xe")
    cmds = drv.build_netflow_config(...)
"""

# Importing the concrete drivers registers them as a side-effect.
from netcontrol.drivers import (  # noqa: F401
    arista_eos,
    cisco_ios,
    cisco_nxos,
    cisco_xe,
    cisco_xr,
    juniper_junos,
)
from netcontrol.drivers.base import (
    Driver,
    DriverCapabilityError,
    GenericDriver,
    NetflowConfig,
    get_driver,
    register_driver,
    registered_device_types,
)

__all__ = [
    "Driver",
    "DriverCapabilityError",
    "GenericDriver",
    "NetflowConfig",
    "get_driver",
    "register_driver",
    "registered_device_types",
]
