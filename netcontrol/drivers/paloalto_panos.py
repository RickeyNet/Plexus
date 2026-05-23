"""Palo Alto PAN-OS driver - monitoring-only firewall surface + SNMPv3.

PAN-OS firewalls are part of the Plexus inventory but the deployment
does not push config changes, NetFlow, or software upgrades to them
through Plexus - those are owned by the firewall team's own tooling.
What Plexus *does* own is monitoring, and SNMPv3 is part of that: it's
the credential the metrics poller authenticates with, so Phase 12
lights up the SNMPv3 capability surface on the firewall drivers while
NetFlow / save / running-config / upgrade verbs stay unimplemented.

Implemented:

  - The two health-check methods (``serial_number_show_command`` /
    ``parse_serial_number``) - ``show system info | match serial``;
    parser anchors on the exact lowercase ``serial:`` prefix so the
    neighbouring ``serial-number-status`` / ``cloud-serial-id`` keys
    the ``| match`` filter also returns can't be mistaken for the
    chassis serial.
  - The four SNMPv3 methods.  PAN-OS stores SNMP under the
    ``deviceconfig system snmp-setting`` config path (not Cisco
    ``snmp-server`` lines) and has no ``| include`` filter, so the
    show/verify commands scope by config path instead.  The engine ID
    is *platform-managed* (auto-derived from the chassis serial when
    blank, no operational ``show snmp engineID``), so the engine-ID
    show and pin commands return empty strings - the same contract
    NX-OS / Junos use, which makes the playbook's shared
    ``pin_snmp_engine_id`` helper emit its "platform-managed; skipping
    pin" info event instead of running a Cisco-shaped command at the
    firewall.

NetFlow build, save, running-config capture, and the upgrade verbs
intentionally remain at the base ``DriverCapabilityError`` - Plexus
does not drive those flows for firewalls, and a clear capability error
is the right thing to surface if a future caller accidentally points a
Cisco-only route at a PAN-OS host.
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
        # spelling) - sending it would parse-error on the firewall.
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

    # ── SNMPv3 capability surface ──────────────────────────────────────────

    def snmpv3_show_existing_command(self) -> str:
        # Read the SNMP config subtree.  Cisco's ``show running-config
        # | include snmp-server`` parse-errors on PAN-OS; scoping by
        # the config path is the idiomatic "filter to SNMP only" form.
        return (
            "show config running xpath "
            "devices/entry/deviceconfig/system/snmp-setting"
        )

    def snmpv3_engine_id_show_command(self) -> str:
        # Platform-managed: PAN-OS auto-derives the engine ID from the
        # chassis serial and exposes no operational show-engine-ID
        # command.  Empty string short-circuits the playbook's pin
        # step - same contract as NX-OS / Junos.
        return ""

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        # Counterpart to the empty show command: pinning is a no-op
        # because the engine ID is already stable across reboots (it
        # tracks the serial).
        return ""

    def snmpv3_verify_users_command(self) -> str:
        # The v3 subtree of the same snmp-setting path is the "after"
        # verification view.  Cisco's ``show snmp user`` does not exist
        # on PAN-OS.
        return (
            "show config running xpath "
            "devices/entry/deviceconfig/system/snmp-setting/access-setting/version/v3"
        )
