"""Arista EOS driver - second non-Cisco vendor after Juniper Junos.

Arista's CLI is deliberately Cisco-IOS-flavoured (Arista marketed early
on around "looks like IOS, runs like Linux") so syntactically most of
the show / config commands are within one or two tokens of IOS-XE.  The
differences that motivate a dedicated driver instead of reusing
``CiscoXEDriver``:

  - NetFlow on EOS uses ``flow tracking hardware`` / ``flow tracking
    sampled`` rather than Cisco's Flexible NetFlow ``flow record`` +
    ``flow exporter`` + ``flow monitor`` triad.  The tracker is the
    closest analogue but the syntax is its own thing - feeding Cisco
    Flexible NetFlow lines at EOS would parse-error on the first ``flow
    record`` line.
  - EOS chassis serial line in ``show version`` is labelled
    ``Serial number:`` (lowercase ``n``, with a colon and space), not
    ``System Serial Number  :`` like IOS / IOS-XE.  The IOS include
    filter would return zero rows on EOS and the IOS parser would
    never find a serial.
  - Upgrade is single-phase: ``install source <path>`` validates and
    sets the boot image, then ``reload now`` reboots into it.  No
    operator-visible commit step (EOS auto-persists the boot image
    selection on successful boot, same pattern Junos / NX-OS use).
  - ``copy running-config startup-config`` is the canonical save -
    ``write memory`` also works on EOS but the explicit copy form is
    what Arista's documentation calls out and what NX-OS uses too, so
    using it here keeps the save surface consistent across the two
    datacenter drivers.
"""

from __future__ import annotations

from netcontrol.drivers.base import Driver, NetflowConfig, register_driver


@register_driver
class AristaEOSDriver(Driver):
    device_types = ("arista_eos",)
    vendor = "arista"
    display_name = "Arista EOS"

    def build_netflow_config(self, cfg: NetflowConfig) -> list[str]:
        # EOS "flow tracking" is the v9/IPFIX-capable analogue to
        # Cisco's Flexible NetFlow.  ``hardware`` enables tracking in
        # ASIC fast-path (which is what every production deployment
        # wants); ``sampled`` is the software-path variant and is
        # intentionally not used here.  The exporter sits inside the
        # tracker block, which means port + collector + version are
        # all nested under one stanza rather than being separate
        # top-level config objects like on IOS-XE.
        sample_rate = max(cfg.sampling_rate, 1)
        cmds = [
            "flow tracking hardware",
            f"  tracker {cfg.monitor_name}",
            f"    exporter {cfg.exporter_name}",
            f"      collector {cfg.collector_ip} port {cfg.collector_port}",
            "      format ipfix version 10",
            "      template interval 60000",
            "    exit",
            "    record export on inactive timeout 15000",
            "    record export on interval 60000",
            "  exit",
            f"  sample {sample_rate}",
            "  no shutdown",
            "exit",
        ]
        for intf in cfg.interfaces:
            cmds += [
                f"interface {intf}",
                f"  flow tracker hardware {cfg.monitor_name}",
                "exit",
            ]
        return cmds

    def netflow_verify_command(self) -> str:
        # ``show flow tracking hardware`` is the EOS analogue to Cisco's
        # ``show flow exporter`` - it prints the tracker state, exporter
        # status, and per-interface attachment counts.  Sending the Cisco
        # form at EOS would parse-error (no ``flow`` top-level show
        # command with that wording).
        return "show flow tracking hardware"

    def capture_running_config_command(self) -> str:
        return "show running-config"

    def save_config_commands(self) -> list[str]:
        # EOS accepts both ``write memory`` and ``copy running-config
        # startup-config``; the latter is Arista's documented form and
        # mirrors the NX-OS driver, so the explicit-copy save surface
        # is consistent across the two datacenter platforms.
        return ["copy running-config startup-config"]

    def snmpv3_show_existing_command(self) -> str:
        # EOS mirrors IOS-XE's ``snmp-server`` config noun, so the same
        # include filter works.
        return "show running-config | include snmp-server"

    def snmpv3_engine_id_show_command(self) -> str:
        # EOS supports ``snmp-server engineID local`` as a config knob
        # and prints the running engine ID via ``show snmp engineID`` -
        # so unlike NX-OS / Junos, pinning is meaningful here.  Engine
        # ID regen would localize-invalidate SNMPv3 keys, same risk as
        # on IOS / IOS-XE.
        return "show snmp engineID"

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        return f"snmp-server engineID local {engine_id}"

    def snmpv3_verify_users_command(self) -> str:
        # ``show snmp user`` is the common form across IOS / IOS-XE /
        # NX-OS / EOS.
        return "show snmp user"

    def show_version_command(self) -> str:
        return "show version"

    def serial_number_show_command(self) -> str:
        # EOS labels the chassis serial ``Serial number:`` (note
        # lowercase ``n``).  The IOS form ``System Serial Number``
        # does not appear in EOS ``show version`` output, so the
        # IOS include filter would return zero rows here.
        return "show version | include Serial number"

    def parse_serial_number(self, output: str) -> str | None:
        # Typical EOS line: ``Serial number:                          JPE19450ABC``
        # (colon + variable whitespace + value).  Anchoring on the
        # leading "Serial number" phrase (no anchor on the colon
        # position - EOS releases vary in column alignment) and
        # splitting on the colon yields the value.
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("serial number"):
                parts = stripped.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
        return None

    # ── Software upgrade capability surface ────────────────────────────────
    #
    # EOS upgrade is single-phase: ``install source <path>`` validates
    # the image, sets the boot image variable, and copies the package
    # into place; ``reload now`` reboots into the new image.  There
    # is no operator-visible commit knob analogous to IOS-XE's
    # ``install commit`` - EOS persists the boot image selection on
    # successful boot.  Same overall shape as Junos and NX-OS, so
    # ``upgrade_has_discrete_prestage()`` stays at the base False and
    # ``upgrade_commit_command()`` returns an empty string.
    # ``upgrade_install_add_command`` intentionally still raises
    # ``DriverCapabilityError`` as defense-in-depth: the route should
    # consult ``upgrade_has_discrete_prestage()`` and skip the
    # prestage call entirely, but if a future caller bypasses the
    # gate the raise surfaces the bug instead of silently shipping
    # IOS-XE syntax at an EOS session.

    def upgrade_activate_commands(self, image_path: str) -> list[str]:
        # Two-command activate: ``install source`` is the validate +
        # set-boot-image step (executes synchronously and prints any
        # validation error before the prompt comes back); ``reload
        # now`` triggers the reboot and drops the SSH session.  Using
        # ``reload now`` instead of bare ``reload`` skips the "Save
        # current configuration?" / "Proceed with reload?" prompts
        # that ``reload`` alone would fire and block the route on.
        return [
            f"install source {image_path}",
            "reload now",
        ]

    def upgrade_commit_command(self) -> str:
        # No analogue to IOS-XE's ``install commit`` on EOS - the box
        # auto-persists the new boot image once it successfully boots.
        # Empty string short-circuits the commit step in the route
        # (same pattern Junos / NX-OS use).
        return ""
