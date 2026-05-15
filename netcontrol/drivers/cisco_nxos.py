"""Cisco NX-OS driver (Flexible NetFlow, requires ``feature netflow``)."""

from __future__ import annotations

from netcontrol.drivers.base import Driver, NetflowConfig, register_driver


@register_driver
class CiscoNXOSDriver(Driver):
    # Netmiko exposes both ssh and non-ssh transports under separate
    # device_type strings; both map to the same NX-OS syntax here.
    device_types = ("cisco_nxos", "cisco_nxos_ssh")
    vendor = "cisco"
    display_name = "Cisco NX-OS"

    def build_netflow_config(self, cfg: NetflowConfig) -> list[str]:
        cmds = [
            "feature netflow",
            f"flow record {cfg.record_name}",
            " match ipv4 source address",
            " match ipv4 destination address",
            " match transport source-port",
            " match transport destination-port",
            " match ip protocol",
            " collect counter bytes",
            " collect counter packets",
            " collect timestamp sys-uptime first",
            " collect timestamp sys-uptime last",
            "exit",
            f"flow exporter {cfg.exporter_name}",
            f" destination {cfg.collector_ip}",
            f" transport udp {cfg.collector_port}",
            " version 9",
            " source loopback0",
            "exit",
            f"flow monitor {cfg.monitor_name}",
            f" record {cfg.record_name}",
            f" exporter {cfg.exporter_name}",
            "exit",
        ]
        if cfg.sampling_rate > 1:
            cmds += [
                f"sampler {cfg.sampler_name}",
                f" mode 1 out-of {cfg.sampling_rate}",
                "exit",
            ]
        for intf in cfg.interfaces:
            cmds.append(f"interface {intf}")
            cmds.append(f" ip flow monitor {cfg.monitor_name} input")
            if cfg.sampling_rate > 1:
                cmds.append(
                    f" ip flow monitor {cfg.monitor_name} sampler {cfg.sampler_name}"
                )
            cmds.append("exit")
        return cmds

    def netflow_verify_command(self) -> str:
        return "show flow exporter PLEXUS-EXPORT"

    def capture_running_config_command(self) -> str:
        return "show running-config"

    def save_config_commands(self) -> list[str]:
        # NX-OS doesn't accept "write memory" - the canonical save command
        # is the explicit copy form.
        return ["copy running-config startup-config"]

    def snmpv3_show_existing_command(self) -> str:
        # NX-OS accepts the same include-style filter as IOS/XE.
        return "show running-config | include snmp-server"

    def snmpv3_engine_id_show_command(self) -> str:
        # NX-OS persists the SNMP engine ID across reloads automatically
        # and does not expose a configurable ``snmp-server engineID
        # local`` knob.  Returning an empty string signals the playbook
        # to skip the engine-ID pin step entirely on this platform.
        return ""

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        # Counterpart to the empty show-command above.  Pinning is a no-op
        # on NX-OS because the engine ID is already stable.
        return ""

    def snmpv3_verify_users_command(self) -> str:
        return "show snmp user"

    def show_version_command(self) -> str:
        return "show version"

    def serial_number_show_command(self) -> str:
        # NX-OS labels the chassis serial "Processor Board ID" in show
        # version output (not "System Serial Number" like IOS/XE), so the
        # include filter has to match that phrase instead.
        return 'show version | include "Processor Board ID"'

    def parse_serial_number(self, output: str) -> str | None:
        # Typical NX-OS line: "Processor Board ID FOX1234ABCD"
        # Note: NX-OS uses a space after the label, not a colon - parser
        # has to handle both the "Label: VALUE" and "Label VALUE" shapes.
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Processor Board ID"):
                # Strip the label prefix and any optional colon/whitespace.
                tail = stripped[len("Processor Board ID"):].lstrip(": ").strip()
                if tail:
                    return tail
        return None

    # ── Software upgrade capability surface ────────────────────────────────
    #
    # NX-OS does not split the upgrade into add/activate/commit the way
    # IOS-XE install-mode does.  The canonical operational command is
    # ``install all nxos <image>`` which validates the image, copies
    # it into the active boot variable, and reboots the chassis - all
    # in one operation.  There is no operator-visible commit step:
    # once the new image boots successfully NX-OS sets it as the
    # persistent boot variable on its own, so the driver reports
    # ``upgrade_has_discrete_prestage()`` as False (inherited from the
    # base) and ``upgrade_commit_command()`` as an empty string (same
    # pattern Junos uses).  ``upgrade_install_add_command`` stays
    # raising ``DriverCapabilityError`` as defense-in-depth: the
    # upgrade route should consult ``upgrade_has_discrete_prestage()``
    # and skip install-add entirely on this platform, but if a future
    # caller bypasses the gate the raise surfaces the bug instead of
    # silently sending IOS-XE syntax at an NX-OS session.

    def upgrade_activate_commands(self, image_path: str) -> list[str]:
        # Single combined add-and-reboot.  ``install all nxos`` does
        # the compatibility check, sets the boot variable, copies the
        # image to standby if applicable (dual-sup chassis), and
        # initiates the reload - all without an intermediate operator
        # prompt when the image and platform are compatible.  The
        # image_path is the device-side full path (typically
        # ``bootflash:nxos.10.3.4a.M.bin``); the driver doesn't
        # second-guess the caller's path format.
        return [f"install all nxos {image_path}"]

    def upgrade_commit_command(self) -> str:
        # NX-OS commits the new boot variable automatically once the
        # device boots into the new image; there is no analogue to
        # IOS-XE's ``install commit``.  Returning an empty string
        # short-circuits the commit step in the upgrade route (same
        # pattern Junos uses).
        return ""
