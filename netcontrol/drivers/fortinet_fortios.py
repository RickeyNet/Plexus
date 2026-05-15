"""Fortinet FortiOS driver — monitoring-only firewall surface.

FortiGate / FortiOS sits in the Plexus inventory alongside Palo Alto
for the same reason: Plexus monitors firewalls but does not push
config, NetFlow, SNMPv3, or software upgrades to them.  Monitoring is
SNMP-based and already vendor-agnostic in ``metrics_engine`` (the
``fortinet`` OID preset covers CPU / memory / uptime); this driver
fills in the only piece that still needs a vendor-specific CLI call,
inventory "fetch serial".

Only the two health-check methods are implemented:

  - ``serial_number_show_command()`` returns ``get hardware status``.
    FortiOS does not implement a Cisco-style ``| include`` filter
    (the closest thing, ``| grep``, exists in newer releases but is
    not universal across the FortiGate models Plexus monitors), so the
    driver pulls the full ~12-line output and lets the parser pick
    out the serial.
  - ``parse_serial_number()`` anchors on ``Serial number:`` —
    capitalised ``S``, lowercase ``n``, with a colon.  That label is
    lexically identical to Arista EOS's serial line; that is fine in
    practice because each driver only sees output from its own
    device, but the test suite guards against a future refactor that
    would let the FortiOS parser accept an IOS-XR ``Serial Number``
    (capital ``N``) line — mirroring the cross-vendor parser-boundary
    tests added in earlier driver phases.

All other Driver capabilities (NetFlow build, SNMPv3 surface, save,
running-config capture, upgrade verbs) intentionally remain at the
base ``DriverCapabilityError`` — Plexus does not drive those flows
for firewalls.
"""

from __future__ import annotations

from netcontrol.drivers.base import Driver, register_driver


@register_driver
class FortinetFortiOSDriver(Driver):
    device_types = ("fortinet",)
    vendor = "fortinet"
    display_name = "Fortinet FortiOS"

    def serial_number_show_command(self) -> str:
        # ``get hardware status`` prints chassis identity (model,
        # serial, board revision, firmware) in ~12 lines.  No pipe
        # filter is used because ``| include`` is Cisco syntax and
        # FortiOS ``| grep`` is not universally available across the
        # models we monitor — the parser handles the narrowing.
        return "get hardware status"

    def parse_serial_number(self, output: str) -> str | None:
        # FortiOS line: ``Serial number: FGT60E1234567890``
        # Case-sensitive ``startswith`` on the canonical FortiGate
        # label.  Capital ``S``, lowercase ``n`` is what FortiOS
        # emits — IOS-XR's ``Serial Number`` (capital ``N``) would
        # also match a case-insensitive parser, so the strict form
        # here is the cross-vendor regression guard.
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Serial number:"):
                parts = stripped.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
        return None
