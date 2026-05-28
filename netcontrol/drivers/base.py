"""Driver ABC, registry, and shared dataclasses.

A ``Driver`` is stateless: methods take parameters and return data
(command lists, show-command strings).  Network I/O stays in the
caller (the playbook or route handler) so drivers remain trivially
unit-testable without Netmiko or a real device.

Registration is by Plexus ``device_type`` string (the same value stored
on ``hosts.device_type`` and accepted by Netmiko).  A single driver
class can register itself for several device_types via the
``device_types`` class variable; ``cisco_nxos`` and ``cisco_nxos_ssh``
share one driver, for example.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


class DriverCapabilityError(NotImplementedError):
    """Raised when a driver is asked for a capability it does not implement.

    Subclasses ``NotImplementedError`` so callers can catch the standard
    type, but the dedicated subclass makes it obvious in logs/tracebacks
    that the failure is a driver gap (add the method to the vendor's
    driver) versus a generic abstract-method bug.
    """


def _normalise_mac(raw: str) -> str:
    """Convert any common MAC representation to lower-case colon-separated hex.

    Cisco show output uses Cisco-style ``aabb.ccdd.eeff``; Arista / Junos
    print ``aa:bb:cc:dd:ee:ff``; some platforms print hyphen-separated.
    The downstream sqlite/postgres rows store the colon form, so we
    canonicalise here once.
    """
    hex_only = "".join(c for c in raw.lower() if c in "0123456789abcdef")
    if len(hex_only) != 12:
        return raw.strip().lower()
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2))


@dataclass(frozen=True, slots=True)
class NetflowConfig:
    """Inputs to ``Driver.build_netflow_config``.

    Kept as a dataclass (rather than positional args) so future fields
    - export protocol version, source interface override, IPFIX vs v9
    selection - can be added without changing every driver signature.
    """

    collector_ip: str
    collector_port: int
    interfaces: list[str]
    sampling_rate: int = 1
    exporter_name: str = "PLEXUS-EXPORT"
    monitor_name: str = "PLEXUS-MON"
    record_name: str = "PLEXUS-RECORD"
    sampler_name: str = "PLEXUS-SAMPLER"


class Driver:
    """Vendor-neutral capability surface for a network device.

    Concrete drivers override ``device_types`` (the set of Plexus
    device_type strings they handle) and whichever capability methods
    they support.  Anything left as the base implementation raises
    ``DriverCapabilityError`` so callers fail loudly rather than
    silently doing the wrong thing.
    """

    device_types: ClassVar[tuple[str, ...]] = ()
    vendor: ClassVar[str] = "generic"
    display_name: ClassVar[str] = "Generic"

    def build_netflow_config(self, cfg: NetflowConfig) -> list[str]:
        """Return the config-mode command lines that enable NetFlow export."""
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement build_netflow_config()"
        )

    def netflow_verify_command(self) -> str:
        """Return a ``show`` command that confirms the exporter is up."""
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement netflow_verify_command()"
        )

    def capture_running_config_command(self) -> str:
        """Return the show command that dumps the device's running config.

        The result is consumed by config-backup and lab snapshot code that
        SSHes to the device, runs the command, and stores the raw text.
        Vendor-specific because e.g. Juniper Junos uses
        ``show configuration | display set`` while Cisco uses
        ``show running-config``.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement capture_running_config_command()"
        )

    def save_config_commands(self) -> list[str]:
        """Return the command(s) that persist running-config to startup.

        Returned as a list because some platforms (NX-OS) want a single
        ``copy running-config startup-config`` while others may need
        multiple steps.  An empty list means "no save step required"
        (e.g. Junos commit semantics, where ``commit`` already persists).

        Most callers will prefer Netmiko's ``conn.save_config()`` which
        handles vendor quirks automatically; this exists for routes that
        push config without Netmiko's high-level helper.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement save_config_commands()"
        )

    # ── MAC address-table capability surface ───────────────────────────────
    #
    # The mac_tracking collector historically polled the bridge / Q-BRIDGE
    # MIB over SNMP, which on Cisco needs a per-VLAN SNMPv3 context dance
    # to see anything beyond VLAN 1.  CLI scraping with ntc-templates
    # parses the same data from one ``show mac address-table`` command
    # without any of that ceremony.  The driver owns the command and the
    # row-normalisation so the collector stays vendor-neutral.
    #
    # The default implementation here covers every CLI that ships
    # Cisco-style output (``show mac address-table`` returning a vlan /
    # mac / type / port-name table parseable by the bundled ntc-template
    # ``cisco_ios_show_mac_address-table``).  That's IOS, IOS-XE, NX-OS,
    # and Arista EOS — all four can rely on the base implementation.
    # Junos, Palo Alto, Fortinet, Cisco XR all need overrides if/when MAC
    # tracking is wanted there.

    def mac_table_show_command(self) -> str:
        """Return the show command that dumps the device's MAC address table.

        Raises ``DriverCapabilityError`` by default so a firewall driver
        (which has no L2 forwarding table) doesn't accidentally get a
        switch-only command shipped to its SSH session.  Switch / bridge
        drivers override.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement mac_table_show_command()"
        )

    def parse_mac_table(self, parsed_rows: list[dict]) -> list[dict]:
        """Normalise textfsm-parsed rows into the collector's schema.

        Input is what Netmiko returns from ``send_command(...,
        use_textfsm=True)`` — a list of dicts whose keys come from the
        ntc-template column names (vendor-specific).  Output is a list of
        ``{"mac", "vlan", "port", "type"}`` dicts the collector can hand
        straight to ``upsert_mac_entry``.

        Default raises ``DriverCapabilityError`` to match the show-command
        contract above; switch drivers override with vendor-appropriate
        column names.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement parse_mac_table()"
        )

    @staticmethod
    def _parse_cisco_style_mac_rows(parsed_rows: list[dict]) -> list[dict]:
        """Shared helper for drivers whose textfsm template matches the
        cisco_ios ``show mac address-table`` schema (vlan / destination_address
        / type / destination_port).  IOS, IOS-XE, NX-OS and Arista EOS all
        use this layout, so they call into this helper rather than duplicating
        the row-normalisation logic.
        """
        out: list[dict] = []
        for row in parsed_rows or []:
            mac_raw = (row.get("destination_address")
                       or row.get("mac") or row.get("mac_address") or "").strip()
            if not mac_raw:
                continue
            vlan_raw = str(row.get("vlan", "")).strip()
            try:
                vlan = int(vlan_raw)
            except (ValueError, TypeError):
                # Cisco prints "All" for system / multicast entries — skip
                # them, they're not learnt MACs.
                continue
            port = (row.get("destination_port") or row.get("ports")
                    or row.get("port") or "").strip()
            if not port or port.lower() in ("cpu", "router", "switch"):
                continue
            type_raw = str(row.get("type", "dynamic")).strip().lower()
            out.append({
                "mac": _normalise_mac(mac_raw),
                "vlan": vlan,
                "port": port,
                "type": type_raw if type_raw in ("dynamic", "static") else "dynamic",
            })
        return out

    # ── SNMPv3 capability surface ──────────────────────────────────────────
    #
    # SNMPv3 provisioning happens in a single playbook
    # (``templates/playbooks/snmpv3_configurator.py``).  The playbook owns
    # the high-level flow (show existing → pin engine ID → push user
    # template → verify); each step's vendor-specific command comes from
    # the driver so the playbook itself can be vendor-neutral.

    def snmpv3_show_existing_command(self) -> str:
        """Return a show command that prints the device's current SNMP config.

        Used by the SNMPv3 playbook as the "before" snapshot so the
        operator can see what was already there.  Cisco platforms use
        ``show running-config | include snmp-server``; Junos would be
        ``show configuration snmp | display set``.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement snmpv3_show_existing_command()"
        )

    def snmpv3_engine_id_show_command(self) -> str:
        """Return the show command that prints the local SNMP engine ID.

        Returns an empty string when the platform doesn't expose engine
        ID pinning as a config knob (NX-OS persists the engine ID by
        default, so pinning is unnecessary and ``snmp-server engineID
        local`` is not a valid command).
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement snmpv3_engine_id_show_command()"
        )

    def snmpv3_engine_id_pin_command(self, engine_id: str) -> str:
        """Return the config line that pins the SNMP engine ID.

        Cisco IOS / IOS-XE regenerate the engine ID when certain
        ``snmp-server`` lines are added or removed.  Because SNMPv3 keys
        are *localized* to the engine ID, regeneration silently
        invalidates every existing user - monitoring then breaks until
        the keys are re-cut.  Pinning the current ID before any change
        keeps the keys valid.

        Returns an empty string when the platform doesn't support
        pinning (see ``snmpv3_engine_id_show_command``).
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement snmpv3_engine_id_pin_command()"
        )

    def snmpv3_verify_users_command(self) -> str:
        """Return the show command that lists configured SNMPv3 users.

        Used as the "after" verification step in the SNMPv3 playbook.
        ``show snmp user`` is the de-facto common command across IOS,
        IOS-XE, and NX-OS; Junos uses ``show snmp v3 user``.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement snmpv3_verify_users_command()"
        )

    # ── Health-check / fingerprint capability surface ──────────────────────
    #
    # Inventory's "fetch serial" feature and the upgrade pre-stage health
    # check both need to read the device's chassis identity (serial,
    # model, software version).  Each platform spells these differently:
    # IOS / IOS-XE expose "System Serial Number" via ``show version``,
    # NX-OS calls the same field "Processor Board ID" in its ``show
    # version`` output, Junos uses ``show chassis hardware`` and prints
    # "Serial number" lines.  The driver owns both the command to run
    # and the parser that pulls the serial out so callers don't have to
    # branch on device_type.

    def show_version_command(self) -> str:
        """Return the full ``show version`` command for this platform.

        Used by the upgrade pre-stage code that needs the unfiltered
        version output to extract both software version and chassis
        model.  Most platforms accept ``show version`` verbatim; Junos
        would override with ``show version detail``.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement show_version_command()"
        )

    def serial_number_show_command(self) -> str:
        """Return an include-filtered show command for the serial line only.

        The inventory fetch-serial UI fires this against many hosts in
        parallel; filtering at the device (rather than pulling the
        whole ``show version`` over SSH) keeps the round-trip small.
        IOS / IOS-XE use ``show version | include System Serial Number``;
        NX-OS uses ``show version | include "Processor Board"`` because
        the NX-OS chassis serial is printed as "Processor Board ID" not
        "System Serial Number".
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement serial_number_show_command()"
        )

    def parse_serial_number(self, output: str) -> str | None:
        """Extract the chassis serial from ``show version`` output.

        Accepts either the full ``show version`` output or the
        filtered output from ``serial_number_show_command()`` - the
        parser scans line-by-line for the platform's serial label.
        Returns ``None`` when no serial line is found (the caller
        decides whether that is a 422 or a "try again later").
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement parse_serial_number()"
        )

    # ── Software upgrade capability surface ────────────────────────────────
    #
    # The upgrades route (``netcontrol/routes/upgrades.py``) historically
    # hard-coded Cisco IOS-XE "install mode" verbs: ``install add file``
    # to pre-stage, ``install activate prompt-level none`` to activate +
    # reload, ``install commit`` to make the new image permanent.  Junos
    # uses ``request system software add`` + ``request system reboot``
    # in a single phase (no separate add/activate split); NX-OS uses
    # ``install all nxos``; classic IOS uses ``copy tftp:`` + ``boot
    # system flash:`` + ``reload``.  These methods give the driver a
    # place to surface the right verb so the route doesn't have to
    # branch on device_type.  Routes that have only implemented the
    # IOS-XE flow can still call ``upgrade_install_add_command`` on a
    # Junos host and get a clear ``DriverCapabilityError`` instead of
    # silently shipping Cisco syntax to a Juniper SSH session.

    def upgrade_has_discrete_prestage(self) -> bool:
        """Return True if the platform has a separate "stage image" step.

        IOS-XE install mode splits the workflow in two: ``install add
        file`` pre-stages the package, then a later ``install activate``
        flips to it and reloads.  The upgrade route runs both as
        distinct phases (``transfer`` ends with the install-add;
        ``activate`` runs after operator approval).

        Junos collapses the two into a single ``request system software
        add ... reboot`` operation - there is no "staged but not yet
        activated" state to land in - so the route must skip the
        prestage call and let the activate phase do both at once.

        Default is False so drivers that don't override (Junos, NX-OS,
        classic IOS) get the single-phase shape, which matches the
        majority of non-IOS-XE vendors.  IOS-XE returns True.
        """
        return False

    def upgrade_install_add_command(self, image_path: str) -> str:
        """Return the command that pre-stages a software image.

        ``image_path`` is the full device-side path (e.g.
        ``flash:cat9k_iosxe.17.09.04a.SPA.bin``).  IOS-XE: ``install
        add file <path>``.  Platforms that don't have a discrete
        pre-stage step (Junos performs add+activate as one operation)
        should raise ``DriverCapabilityError`` so the caller routes
        through ``upgrade_activate_commands`` instead.

        Callers should consult ``upgrade_has_discrete_prestage()`` and
        skip this call entirely when it returns False - otherwise the
        ``DriverCapabilityError`` raised here will surface as a "pre-
        stage not supported" error in the operator log, which is
        misleading for platforms that simply don't need pre-staging.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement upgrade_install_add_command()"
        )

    def upgrade_activate_commands(self, image_path: str) -> list[str]:
        """Return the command(s) that activate the staged image and reboot.

        Returns a list because some platforms need multiple steps
        (e.g. Junos: ``request system software add ... no-validate``
        then ``request system reboot``).  The final command in the
        list is expected to trigger the reload - the caller treats a
        dropped SSH session after the last command as success.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement upgrade_activate_commands()"
        )

    def upgrade_commit_command(self) -> str:
        """Return the command that makes the new image permanent.

        Cisco IOS-XE install mode rolls back automatically on the
        next reload unless ``install commit`` runs after the activate
        completes.  NX-OS auto-commits.  Junos persists on commit.
        Platforms with no separate commit step should return an empty
        string so the caller can short-circuit.
        """
        raise DriverCapabilityError(
            f"{type(self).__name__} does not implement upgrade_commit_command()"
        )


class GenericDriver(Driver):
    """Fallback used when no driver is registered for a device_type.

    All capability methods raise ``DriverCapabilityError`` so an
    unknown vendor never silently falls through to a Cisco code path -
    the operator gets a clear "no driver for foo_os" error instead.
    """

    vendor = "unknown"
    display_name = "Unknown"


_REGISTRY: dict[str, type[Driver]] = {}


def register_driver(cls: type[Driver]) -> type[Driver]:
    """Class decorator that registers ``cls`` for each of its device_types.

    Re-registering an existing device_type is a programming error and
    raises ``ValueError`` - silently shadowing a driver would make
    "which driver am I getting?" depend on import order.
    """
    if not cls.device_types:
        raise ValueError(
            f"{cls.__name__} must declare a non-empty device_types tuple "
            "before it can be registered."
        )
    for dt in cls.device_types:
        existing = _REGISTRY.get(dt)
        if existing is not None and existing is not cls:
            raise ValueError(
                f"device_type {dt!r} already registered to {existing.__name__}; "
                f"cannot re-register to {cls.__name__}"
            )
        _REGISTRY[dt] = cls
    return cls


def get_driver(device_type: str | None) -> Driver:
    """Return a driver instance for ``device_type``, or ``GenericDriver``.

    ``None`` and unknown strings both yield the generic driver - callers
    that care about the distinction should check ``isinstance(drv,
    GenericDriver)`` or inspect ``drv.vendor``.
    """
    if not device_type:
        return GenericDriver()
    cls = _REGISTRY.get(device_type, GenericDriver)
    return cls()


def registered_device_types() -> tuple[str, ...]:
    """Sorted tuple of every device_type that currently has a driver.

    Useful for surfacing supported platforms in the UI or for
    diagnostics endpoints.
    """
    return tuple(sorted(_REGISTRY.keys()))
