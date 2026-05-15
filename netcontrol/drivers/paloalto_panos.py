"""Palo Alto PAN-OS driver — monitoring-only firewall surface.

PAN-OS firewalls are part of the Plexus inventory but the deployment
does not push config changes, NetFlow, SNMPv3, or software upgrades to
them through Plexus — those are owned by the firewall team's own
tooling.  What Plexus *does* need is monitoring: SNMP polling for CPU
/ memory / uptime (handled vendor-agnostically by ``metrics_engine``
via the ``paloalto`` OID preset) and the inventory "fetch serial"
flow, which is what this driver exists to support.

Only the two health-check methods are implemented:

  - ``serial_number_show_command()`` returns ``show system info | match
    serial`` — PAN-OS supports the ``| match`` pipe filter and prints
    one line of the form ``serial: 015351000123`` (all-lowercase label,
    colon + single space + value).
  - ``parse_serial_number()`` anchors on the lowercase ``serial:``
    prefix.  PAN-OS prints several keys whose names *contain* the word
    "serial" (e.g. ``serial-number-status``, ``cloud-serial-id``);
    anchoring on the colon position avoids those by requiring the key
    to be exactly ``serial`` followed by ``:``.

All other Driver capabilities (NetFlow build, SNMPv3 surface, save,
running-config capture, upgrade verbs) intentionally remain at the
base ``DriverCapabilityError`` — Plexus does not drive those flows for
firewalls, and a clear capability error is the right thing to surface
if a future caller accidentally points a Cisco-only route at a PAN-OS
host.
"""

from __future__ import annotations

from netcontrol.drivers.base import Driver, register_driver


@register_driver
class PaloAltoPANOSDriver(Driver):
    device_types = ("paloalto_panos",)
    vendor = "paloalto"
    display_name = "Palo Alto PAN-OS"

    def serial_number_show_command(self) -> str:
        # ``show system info`` prints ~40 lines of chassis / software
        # facts; ``| match serial`` narrows that to the serial line(s).
        # PAN-OS does not implement ``| include`` (that is Cisco's
        # spelling) — sending it would parse-error on the firewall.
        return "show system info | match serial"

    def parse_serial_number(self, output: str) -> str | None:
        # PAN-OS line:  ``serial: 015351000123``
        # Anchor on the exact ``serial:`` prefix (not ``serial`` alone)
        # to avoid matching neighbouring keys like ``serial-number-status``
        # or ``cloud-serial-id`` that the ``| match serial`` filter will
        # also return.  Splitting on the first colon yields the value.
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("serial:"):
                parts = stripped.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
        return None
