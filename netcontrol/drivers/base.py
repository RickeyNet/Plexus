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
