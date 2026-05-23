"""Cisco IOS-XR driver - service-provider / core platform.

IOS-XR is the third Cisco driver, after IOS and IOS-XE, and the second
driver overall to expose ``upgrade_has_discrete_prestage() == True``.
The differences that motivate a dedicated driver instead of reusing
``CiscoXEDriver``:

  - NetFlow on XR uses ``flow exporter-map`` / ``flow monitor-map`` /
    ``sampler-map`` nouns, not IOS-XE's ``flow exporter`` / ``flow
    monitor``.  The per-interface attachment is also different:
    ``flow ipv4 monitor <name> sampler <name> ingress`` rather than
    XE's ``ip flow monitor <name> input``.  Feeding XE Flexible NetFlow
    config at an XR session would parse-error on the very first
    ``flow record`` line - XR does not have that command.
  - ``show version`` on XR labels the chassis serial as
    ``Serial Number   :`` (with the second word capitalised - distinct
    from EOS's lowercase-n ``Serial number:``).  The IOS / IOS-XE
    filter (``System Serial Number``) returns zero rows on XR, and
    the EOS filter (lowercase ``number``) is case-sensitive so it
    would also miss.
  - Upgrade syntax is install-mode like IOS-XE but uses distinct verbs:
    ``install add source <path>`` to stage, ``install activate`` to
    activate the newly-added packages (no path argument - activate
    operates on whatever was just added, same shape as XE), and
    ``install commit`` to finalize.  XR returns a packaging operation
    ID from ``install add source`` but bare ``install activate``
    activates all newly-added inactive packages, so the route does
    not have to parse and pass an op-id between phases.
  - Save form is ``commit`` (XR is commit-based - the running and
    candidate configs are distinct), not ``write memory`` or ``copy
    running-config startup-config``.  XR's NetFlow / SNMP playbooks
    have to commit the candidate to make changes live; without the
    commit, the candidate sits pending forever and an operator
    reviewing the box would see "no changes."
"""

from __future__ import annotations

from netcontrol.drivers.base import Driver, NetflowConfig, register_driver


@register_driver
class CiscoXRDriver(Driver):
    device_types = ("cisco_xr",)
    vendor = "cisco"
    display_name = "Cisco IOS-XR"

    def build_netflow_config(self, cfg: NetflowConfig) -> list[str]:
        # XR NetFlow has its own noun set: ``flow exporter-map`` (not
        # ``flow exporter``), ``flow monitor-map`` (not ``flow monitor``),
        # ``sampler-map`` (not ``sampler``).  The exporter destination
        # and transport are inside the exporter-map stanza, then the
        # monitor-map references the exporter by name.  Per-interface
        # attachment is ``flow ipv4 monitor <name> [sampler <name>]
        # ingress`` - the ``ipv4`` keyword is required (XR also has
        # ``flow ipv6 monitor`` and ``flow mpls monitor`` variants and
        # makes the operator pick).
        cmds = [
            f"flow exporter-map {cfg.exporter_name}",
            f" destination {cfg.collector_ip}",
            f" transport udp {cfg.collector_port}",
            " version v9",
            "  options interface-table",
            "  options sampler-table",
            "  template data timeout 60",
            " !",
            "exit",
            f"flow monitor-map {cfg.monitor_name}",
            " record ipv4",
            f" exporter {cfg.exporter_name}",
            " cache entries 65535",
            " cache timeout active 60",
            " cache timeout inactive 15",
            "exit",
        ]
        if cfg.sampling_rate > 1:
            # XR's sampler-map uses ``random 1 out-of <N>``, same shape
            # as IOS-XE's ``mode random 1 out-of N`` minus the leading
            # ``mode`` keyword.  Sampler is only emitted when sampling
            # is actually requested - matches the XE driver's pattern.
            cmds += [
                f"sampler-map {cfg.sampler_name}",
                f" random 1 out-of {cfg.sampling_rate}",
                "exit",
            ]
        for intf in cfg.interfaces:
            cmds.append(f"interface {intf}")
            if cfg.sampling_rate > 1:
                cmds.append(
                    f" flow ipv4 monitor {cfg.monitor_name} sampler "
                    f"{cfg.sampler_name} ingress"
                )
            else:
                cmds.append(f" flow ipv4 monitor {cfg.monitor_name} ingress")
            cmds.append("exit")
        return cmds

    def netflow_verify_command(self) -> str:
        # XR's ``show flow exporter-map`` is the analogue to IOS-XE's
        # ``show flow exporter``.  The IOS-XE wording (no ``-map``
        # suffix) does not exist on XR and parse-errors.  The exporter
        # name is interpolated from the NetflowConfig default the
        # builder uses; callers that override ``exporter_name`` should
        # construct the verify command themselves (matches the XE
        # driver's pattern - Plexus always uses PLEXUS-EXPORT today).
        return "show flow exporter-map PLEXUS-EXPORT"

    def capture_running_config_command(self) -> str:
        # XR has a running config concept similar to IOS - ``show
        # running-config`` dumps the active committed config.  The
        # candidate-config side is reached via ``show configuration``
        # but the backup code wants the committed view, which is what
        # this returns.
        return "show running-config"

    def save_config_commands(self) -> list[str]:
        # XR is commit-based: edits go into a candidate config and must
        # be committed before they take effect.  ``commit`` is the
        # canonical save - there is no ``write memory`` or ``copy
        # running-config startup-config`` on XR.  Empty list would
        # leave the candidate config pending forever and the operator
        # would see "no changes" on the box.
        return ["commit"]

    def snmpv3_show_existing_command(self) -> str:
        # XR accepts the same include-filter form as IOS / IOS-XE for
        # show-running output.
        return "show running-config | include snmp-server"

    def snmpv3_engine_id_show_command(self) -> str:
        # XR supports ``snmp-server engineID local`` as a config knob
        # (same as IOS / IOS-XE / EOS) and prints the running engine
        # ID via ``show snmp engineid`` (note: lowercase ``id`` on XR,
        # not ``engineID`` - XR's CLI is case-insensitive on input but
        # the help / completion shows the lowercase form).  Engine ID
        # regen would localize-invalidate SNMPv3 keys, same risk as
        # on the other IOS-family platforms - so pinning is meaningful
        # here, unlike NX-OS / Junos.
        return "show snmp engineid"

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        return f"snmp-server engineID local {engine_id}"

    def snmpv3_verify_users_command(self) -> str:
        # ``show snmp user`` is the common form across IOS / IOS-XE /
        # NX-OS / EOS / XR.
        return "show snmp user"

    def show_version_command(self) -> str:
        return "show version"

    def serial_number_show_command(self) -> str:
        # XR labels the chassis serial ``Serial Number`` (capital N,
        # space-separated from a colon).  The IOS form ``System Serial
        # Number`` does not appear in XR ``show version`` output, so
        # the IOS include filter would return zero rows here.  EOS's
        # lowercase-n filter would also miss because XR's casing is
        # different.
        return 'show version | include "Serial Number"'

    def parse_serial_number(self, output: str) -> str | None:
        # Typical XR line: ``Serial Number   : FOX2436A0XX``
        # (label + variable whitespace + colon + variable whitespace +
        # value).  Anchoring on the literal "Serial Number" phrase
        # (case-sensitive to avoid matching EOS-style "Serial number"
        # mistakenly) and splitting on the colon yields the value.
        # The case-sensitivity is the explicit boundary between this
        # parser and the EOS parser; a future refactor that switches
        # to ``.lower()`` would silently start accepting EOS-shaped
        # lines and the cross-vendor parser-mixup is exactly the bug
        # the driver framework exists to prevent.
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Serial Number"):
                parts = stripped.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
        return None

    # ── Software upgrade capability surface ────────────────────────────────
    #
    # IOS-XR has a two-phase install model similar to IOS-XE but with
    # different verbs.  ``install add source <path>`` stages the
    # package(s) into the install repository (returns a packaging op
    # ID, which the route does not have to parse - the subsequent
    # ``install activate`` activates all newly-added inactive
    # packages, same shape as XE's path-less activate).  ``install
    # commit`` finalizes the activate so it survives the next reload
    # without auto-rollback.  Without commit, XR will auto-rollback
    # on next reload, same risk as XE's commit step.

    def upgrade_has_discrete_prestage(self) -> bool:
        # XR has a real two-phase workflow: ``install add source``
        # pre-stages the package into the install repository; ``install
        # activate`` later picks up the staged packages and reboots.
        # The route uses this to keep the slow transfer / add phase
        # distinct from the activate-and-reboot phase, so an operator
        # can approve activate in a maintenance window after the
        # upload completes (same shape as IOS-XE install mode).
        return True

    def upgrade_install_add_command(self, image_path: str) -> str:
        # ``install add source <path>`` - the ``source`` keyword is
        # required (without it XR interprets the command as ``install
        # add`` with a missing argument and prompts interactively).
        # ``image_path`` is the full device-side path (e.g.
        # ``harddisk:asr9k-mini-x64-7.5.2.iso``) - XR's filesystem is
        # ``harddisk:`` or ``disk0:`` rather than IOS-XE's ``flash:``,
        # but the driver does not second-guess the caller's path
        # format.
        return f"install add source {image_path}"

    def upgrade_activate_commands(self, image_path: str) -> list[str]:
        # Bare ``install activate`` activates every newly-added
        # inactive package - no ID argument needed when staging and
        # activate run back-to-back in the route, which is the only
        # caller.  ``image_path`` is not interpolated because the
        # activate operates on whatever was just added.  XR will
        # prompt for confirmation by default; ``synchronous`` makes
        # the command block until activate completes (or the reload
        # drops the SSH session, whichever comes first) so the route's
        # "send command then watch for SSH drop" pattern works
        # uniformly across XE and XR.  ``prompt-level none`` (an XE
        # noun) is not valid on XR - the synchronous keyword is the
        # XR equivalent of suppressing the interactive prompt.
        return ["install activate synchronous"]

    def upgrade_commit_command(self) -> str:
        # Without ``install commit`` an XR box auto-rolls-back to the
        # prior image on the *next* reload, silently undoing the
        # upgrade.  Same risk and same fix as IOS-XE install mode.
        return "install commit"
