"""Juniper Junos driver — the first non-Cisco driver in the framework.

Junos diverges from Cisco IOS / IOS-XE / NX-OS in nearly every capability:

  - Configuration syntax is "set ..." statements, not config-mode stanzas.
  - There is no ``running-config`` vs ``startup-config`` split; the
    candidate config is persisted by ``commit``, so ``save_config_commands``
    returns an empty list (Netmiko's ``save_config`` on a Junos session
    calls ``commit`` itself).
  - NetFlow is configured as a sampling instance under
    ``forwarding-options``; there is no per-interface ``ip flow ingress``
    line, the binding is via a firewall filter referenced from the
    interface family.  Plexus models the global half of that here and
    leaves per-interface binding to the caller (filter names depend on
    site policy and aren't generic enough to template).
  - Chassis serial is reported by ``show chassis hardware`` on the line
    that starts with "Chassis ".  The serial is the second whitespace-
    separated token after the label.
"""

from __future__ import annotations

from netcontrol.drivers.base import Driver, NetflowConfig, register_driver


@register_driver
class JuniperJunosDriver(Driver):
    device_types = ("juniper_junos",)
    vendor = "juniper"
    display_name = "Juniper Junos"

    def build_netflow_config(self, cfg: NetflowConfig) -> list[str]:
        # Junos "set" form for j-flow / IPFIX sampling.  Emits the
        # sampling instance, template, and per-interface family-inet
        # sampling toggle.  Per-interface enablement assumes inet (IPv4)
        # family; sites running pure inet6 would need a follow-up edit.
        sampling_rate = max(cfg.sampling_rate, 1)
        template = cfg.record_name  # reuse the generic name as the template id
        instance = cfg.monitor_name  # and as the sampling-instance id
        cmds = [
            # Forwarding-options: sampling instance with collector + version.
            f"set forwarding-options sampling instance {instance} family inet "
            f"output flow-server {cfg.collector_ip} port {cfg.collector_port}",
            f"set forwarding-options sampling instance {instance} family inet "
            f"output flow-server {cfg.collector_ip} version9 template {template}",
            # Sampling input: rate=1 means "every packet"; Junos's
            # native knob is the same "1 out of N" ratio.
            f"set forwarding-options sampling instance {instance} input "
            f"rate {sampling_rate}",
            # Services-style flow template (v9) with the same 5-tuple +
            # counters as the Cisco drivers emit.
            f"set services flow-monitoring version9 template {template} "
            "flow-active-timeout 60",
            f"set services flow-monitoring version9 template {template} "
            "template-refresh-rate packets 1000 seconds 60",
            f"set services flow-monitoring version9 template {template} "
            "ipv4-template",
        ]
        for intf in cfg.interfaces:
            cmds.append(
                f"set interfaces {intf} unit 0 family inet sampling input"
            )
            cmds.append(
                f"set interfaces {intf} unit 0 family inet sampling output"
            )
        return cmds

    def netflow_verify_command(self) -> str:
        # Junos exposes the sampling state under "show services accounting"
        # for the services-style template, and "show forwarding-options
        # sampling" for the instance.  The latter is the closest analogue
        # to Cisco's "show flow exporter" (proves the collector is wired
        # up) so it's what the driver returns.
        return "show forwarding-options sampling"

    def capture_running_config_command(self) -> str:
        # ``| display set`` prints the config as discrete "set ..." lines,
        # which is what Plexus's backup/diff code expects (text lines, not
        # the curly-brace tree).
        return "show configuration | display set"

    def save_config_commands(self) -> list[str]:
        # Junos has no running-vs-startup split: ``commit`` persists the
        # candidate config.  Netmiko's ``save_config()`` on a Junos
        # session invokes commit itself, so the driver returns an empty
        # list to signal "no extra save step needed beyond commit".
        return []

    def snmpv3_show_existing_command(self) -> str:
        # Print just the SNMP stanza as set lines; mirrors what the Cisco
        # drivers do with "| include snmp-server".
        return "show configuration snmp | display set"

    def snmpv3_engine_id_show_command(self) -> str:
        # Junos persists the SNMP engine ID across reboots and does not
        # expose a routinely-configurable pin knob (the ``set snmp
        # engine-id`` form exists but is rarely used outside high-
        # security templates).  Returning an empty string short-circuits
        # the engine-ID pin step in the playbook — same pattern NX-OS
        # uses.  Sites that *do* pin engine IDs on Junos can subclass.
        return ""

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        # Counterpart to the empty show command above.  Pin is a no-op.
        return ""

    def snmpv3_verify_users_command(self) -> str:
        return "show snmp v3 user"

    def show_version_command(self) -> str:
        return "show version"

    def serial_number_show_command(self) -> str:
        # ``show chassis hardware`` is the canonical way to read the
        # chassis serial on Junos; ``| match Chassis`` filters down to
        # the one line we want.  Anchoring on the word "Chassis " (with
        # trailing space) avoids matching the FPC/PIC chassis lines that
        # share the table.
        return "show chassis hardware | match Chassis"

    # ── Software upgrade capability surface ────────────────────────────────
    #
    # Junos does not have a "stage now, activate later" workflow.  The
    # canonical operational command is ``request system software add
    # <package> no-validate reboot`` which validates the package, lays
    # it down on alternate slice, and reboots the box - all in one
    # operation.  ``no-validate`` skips the cross-platform validation
    # step that's irrelevant when the operator has already chosen the
    # right package for the model (and would otherwise prompt for
    # confirmation, which can't run non-interactively before the reboot
    # drops the SSH session).  There is no separate commit step: once
    # the new image is booted the candidate config is committed
    # automatically and the box is "running the new version" - so the
    # driver also reports ``upgrade_has_discrete_prestage()`` as False
    # (inherited from the base) so the upgrade route skips the install-
    # add prestage call entirely.

    def upgrade_activate_commands(self, image_path: str) -> list[str]:
        # Single-command activate-and-reboot.  ``no-validate`` is
        # critical for non-interactive execution: without it Junos
        # prints a "validate this package on this platform?" prompt
        # that blocks the SSH session forever, then the route would
        # never see the reboot.  ``reboot`` is the same word the
        # CLI accepts inline; appending it skips a second prompt
        # ("Reboot the system?") that fires when the add finishes.
        return [f"request system software add {image_path} no-validate reboot"]

    def upgrade_commit_command(self) -> str:
        # Junos persists the new image on its own: the boot media
        # carries forward the candidate config + new package, and
        # there is no operator-visible "commit my upgrade choice"
        # knob analogous to IOS-XE's ``install commit``.  Returning
        # an empty string short-circuits the commit step in the
        # route (same pattern NX-OS would use).
        return ""

    def parse_serial_number(self, output: str) -> str | None:
        # The Junos table is whitespace-aligned, e.g.:
        #   Item             Version  Part number  Serial number  Description
        #   Chassis                                JN12345AB      EX4300-48T
        # We anchor on lines that *start* with "Chassis" (not lines
        # that merely contain it - "Routing Engine 0" lines also list
        # the chassis description) and pick the first token that looks
        # like a serial (alphanumeric, length >= 6).  Length filter
        # rules out the empty Version / Part-number columns that may
        # appear on chassis rows where those fields are blank.
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped.startswith("Chassis"):
                continue
            # Drop the "Chassis" label itself and look at the remaining
            # whitespace-separated columns.
            rest = stripped[len("Chassis"):].split()
            for token in rest:
                if len(token) >= 6 and token.replace("-", "").isalnum():
                    return token
            return None
        return None
