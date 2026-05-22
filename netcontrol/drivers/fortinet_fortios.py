"""Fortinet FortiOS driver - monitoring-only firewall surface + SNMPv3.

FortiGate / FortiOS sits in the Plexus inventory alongside Palo Alto
for the same reason: Plexus monitors firewalls but does not push
config, NetFlow, or software upgrades to them.  SNMPv3 is the one
exception (Phase 12): it is the credential the metrics poller
authenticates with, so it's part of monitoring rather than a
firewall-team config concern.  CPU / memory / uptime polling is
already vendor-agnostic in ``metrics_engine`` (the ``fortinet`` OID
preset); this driver fills in the vendor-specific CLI calls - the
inventory "fetch serial" flow and the four SNMPv3 commands.

Implemented:

  - The two health-check methods.  ``serial_number_show_command()``
    returns ``get hardware status``.  FortiOS does not implement a
    Cisco-style ``| include`` filter (the closest thing, ``| grep``,
    exists in newer releases but is not universal across the FortiGate
    models Plexus monitors), so the driver pulls the full ~12-line
    output and lets the parser pick out the serial.
    ``parse_serial_number()`` anchors on ``Serial number:`` -
    capitalised ``S``, lowercase ``n``, with a colon.  That label is
    lexically identical to Arista EOS's serial line; that is fine in
    practice because each driver only sees output from its own
    device, but the test suite guards against a future refactor that
    would let the FortiOS parser accept an IOS-XR ``Serial Number``
    (capital ``N``) line - mirroring the cross-vendor parser-boundary
    tests added in earlier driver phases.
  - The four SNMPv3 methods.  FortiOS stores SNMP under ``config
    system snmp ...``; the show/verify commands use the ``get system
    snmp ...`` operational form (no Cisco ``| include`` filter
    exists).  The SNMP engine ID is *platform-managed*: with
    ``engine-id`` left at its default FortiOS deterministically
    derives it from the hardware serial (fixed Fortinet prefix +
    serial-as-hex), so it is stable across reboots and across
    adding/removing SNMPv3 users - there is no Cisco-IOS-style
    regenerate-on-config-change behaviour that the pin step exists to
    defend against.  The engine-ID show and pin commands therefore
    return empty strings (same contract as NX-OS / Junos / PAN-OS)
    and the shared ``pin_snmp_engine_id`` helper emits its
    "platform-managed; skipping pin" info event rather than running a
    command at the FortiGate.

NetFlow build, save, running-config capture, and the upgrade verbs
intentionally remain at the base ``DriverCapabilityError`` - Plexus
does not drive those flows for firewalls.
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
        # models we monitor - the parser handles the narrowing.
        return "get hardware status"

    def parse_serial_number(self, output: str) -> str | None:
        # FortiOS line: ``Serial number: FGT60E1234567890``
        # Case-sensitive ``startswith`` on the canonical FortiGate
        # label.  Capital ``S``, lowercase ``n`` is what FortiOS
        # emits - IOS-XR's ``Serial Number`` (capital ``N``) would
        # also match a case-insensitive parser, so the strict form
        # here is the cross-vendor regression guard.
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Serial number:"):
                parts = stripped.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
        return None

    # ── SNMPv3 capability surface ──────────────────────────────────────────

    def snmpv3_show_existing_command(self) -> str:
        # FortiOS keeps SNMPv3 users in their own table, so the
        # "existing" snapshot is the user list itself.  ``get system
        # snmp user`` shows the effective config (defaults included),
        # which is the most useful "before" view.  Cisco's ``show
        # running-config | include snmp-server`` parse-errors here.
        return "get system snmp user"

    def snmpv3_engine_id_show_command(self) -> str:
        # Platform-managed: with ``engine-id`` at its default FortiOS
        # derives it deterministically from the hardware serial, so it
        # is stable across reboots and SNMP config changes.  Empty
        # string short-circuits the playbook's pin step - same
        # contract as NX-OS / Junos / PAN-OS.
        return ""

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        # Counterpart to the empty show command: pinning is a no-op
        # because the serial-derived engine ID never regenerates on
        # SNMP user changes the way Cisco IOS's does.
        return ""

    def snmpv3_verify_users_command(self) -> str:
        # Same command as the "before" snapshot - re-reading the user
        # table after the push is the verification.  ``get`` (not
        # ``show``) so defaults are visible if the template omitted
        # an optional field.
        return "get system snmp user"
