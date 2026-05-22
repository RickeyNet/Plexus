"""Cisco FTD / ASA driver — monitoring-only firewall surface + SNMPv3.

Cisco FTD (Firepower Threat Defense) and classic ASA share the same
LINA datapath and therefore the same operational CLI for the verbs
Plexus cares about: ``show version`` for chassis identity, IOS-style
``snmp-server`` configuration, and the CISCO-PROCESS-MIB /
CISCO-ENHANCED-MEMPOOL-MIB OID sets used by ``metrics_engine``.  One
driver class registers itself for both ``cisco_ftd`` and ``cisco_asa``
device_types — the same pattern ``cisco_nxos`` / ``cisco_nxos_ssh``
already use — so the firewall team can label hosts either way without
duplicating capability code.

FTDs are most commonly managed by FMC.  In FMC-managed mode the device
still has a usable read CLI (``show`` commands work), but the
running-config it returns reflects the *pushed* policy rather than the
authoritative source of truth, which lives in FMC.  For that reason
this driver intentionally leaves ``capture_running_config_command`` at
the base ``DriverCapabilityError`` — same line we hold for Fortinet
and Palo Alto.  If a future operator decides Plexus should back up
FTD running-config anyway (for "what's actually deployed" history
rather than authoritative recovery), the override is a one-liner;
the decision is policy, not vendor capability.

Implemented:

  - The two health-check methods.  ``serial_number_show_command()``
    returns ``show version | include Serial Number`` (FTD's LINA CLI
    accepts the Cisco-style ``| include`` filter — unlike PAN-OS or
    FortiOS).  ``parse_serial_number()`` anchors on ``Serial Number:``
    (capital ``N``, with a colon), which is what ASA/FTD emit;
    IOS-classic emits ``System Serial Number`` (handled by
    ``cisco_ios.py``), so the two parsers don't collide even though
    both share the LINA-style ``| include`` filter.
  - The four SNMPv3 methods.  ASA/FTD use IOS-flavoured
    ``snmp-server`` configuration and expose ``show snmp engineID`` /
    ``show snmp user`` operationally — same shape as ``cisco_ios``.
    Engine ID is *not* platform-managed here: ASA/FTD regenerate the
    local engine ID under some reboot / failover conditions, so the
    pin command is real (not the empty-string short-circuit Fortinet
    and Palo Alto use).

NetFlow build, save, and the upgrade verbs intentionally remain at
the base ``DriverCapabilityError``.  Plexus does not drive those
flows for firewalls; surfacing a clear capability error if a future
caller accidentally points a Cisco-IOS-only route at an FTD is the
right behaviour.
"""

from __future__ import annotations

from netcontrol.drivers.base import Driver, register_driver


@register_driver
class CiscoFTDDriver(Driver):
    device_types = ("cisco_ftd", "cisco_asa")
    vendor = "cisco"
    display_name = "Cisco FTD / ASA"

    def serial_number_show_command(self) -> str:
        # LINA CLI accepts ``| include`` (same filter as IOS).  Both
        # ASA and FTD print a ``Serial Number: <S/N>`` line near the
        # top of ``show version``; the filter narrows ~80 lines down
        # to one or two.
        return "show version | include Serial Number"

    def parse_serial_number(self, output: str) -> str | None:
        # ASA/FTD line: ``Serial Number: JAD12345ABC``
        # Distinct from IOS-classic's ``System Serial Number`` line
        # (handled by cisco_ios.py) — the substring match here would
        # not match IOS output, so the cross-vendor parser-boundary
        # is preserved without needing a stricter anchor.
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Serial Number:"):
                parts = stripped.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
        return None

    # ── SNMPv3 capability surface ──────────────────────────────────────────

    def snmpv3_show_existing_command(self) -> str:
        return "show running-config | include snmp-server"

    def snmpv3_engine_id_show_command(self) -> str:
        # ASA/FTD expose the operational engine ID the same way IOS
        # does.  Not platform-managed: the local engine ID can change
        # under some reboot / HA-failover conditions, so the pin
        # step is real (counterpart command below).
        return "show snmp engineID"

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        return f"snmp-server engineID local {engine_id}"

    def snmpv3_verify_users_command(self) -> str:
        return "show snmp user"
