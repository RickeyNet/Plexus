from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FTDAddressObject:
    """Typed representation of an FTD network object emitted by address conversion."""

    name: str
    description: str
    type: str
    sub_type: str
    value: str

    @classmethod
    def from_legacy(cls, payload: dict[str, Any]) -> "FTDAddressObject":
        return cls(
            name=str(payload.get("name", "")),
            description=str(payload.get("description", "")),
            type=str(payload.get("type", "")),
            sub_type=str(payload.get("subType", "")),
            value=str(payload.get("value", "")),
        )

    def to_legacy_dict(self) -> dict[str, str]:
        # Preserve legacy wire format key names while keeping typed internals.
        return {
            "name": self.name,
            "description": self.description,
            "type": self.type,
            "subType": self.sub_type,
            "value": self.value,
        }


@dataclass(frozen=True)
class FTDServiceObject:
    """Typed representation of an FTD TCP/UDP service object."""

    name: str
    is_system_defined: bool
    port: str
    type: str

    @classmethod
    def from_legacy(cls, payload: dict[str, Any]) -> "FTDServiceObject":
        return cls(
            name=str(payload.get("name", "")),
            is_system_defined=bool(payload.get("isSystemDefined", False)),
            port=str(payload.get("port", "")),
            type=str(payload.get("type", "")),
        )

    def to_legacy_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "isSystemDefined": self.is_system_defined,
            "port": self.port,
            "type": self.type,
        }


@dataclass(frozen=True)
class FTDStaticRouteObject:
    """Typed representation of an FTD static route entry."""

    name: str
    iface: dict[str, Any]
    networks: list[dict[str, Any]]
    gateway: dict[str, Any]
    metric_value: Any
    ip_type: str
    type: str

    @classmethod
    def from_legacy(cls, payload: dict[str, Any]) -> "FTDStaticRouteObject":
        return cls(
            name=str(payload.get("name", "")),
            iface=dict(payload.get("iface", {})),
            networks=list(payload.get("networks", [])),
            gateway=dict(payload.get("gateway", {})),
            metric_value=payload.get("metricValue", 1),
            ip_type=str(payload.get("ipType", "")),
            type=str(payload.get("type", "")),
        )

    def to_legacy_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "iface": self.iface,
            "networks": self.networks,
            "gateway": self.gateway,
            "metricValue": self.metric_value,
            "ipType": self.ip_type,
            "type": self.type,
        }


@dataclass(frozen=True)
class FTDAddressGroupObject:
    """Typed representation of an FTD network object group."""

    name: str
    is_system_defined: bool
    objects: list[dict[str, Any]]
    type: str

    @classmethod
    def from_legacy(cls, payload: dict[str, Any]) -> "FTDAddressGroupObject":
        return cls(
            name=str(payload.get("name", "")),
            is_system_defined=bool(payload.get("isSystemDefined", False)),
            objects=list(payload.get("objects", [])),
            type=str(payload.get("type", "")),
        )

    def to_legacy_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "isSystemDefined": self.is_system_defined,
            "objects": self.objects,
            "type": self.type,
        }


@dataclass(frozen=True)
class FTDServiceGroupObject:
    """Typed representation of an FTD port object group."""

    name: str
    is_system_defined: bool
    objects: list[dict[str, Any]]
    type: str

    @classmethod
    def from_legacy(cls, payload: dict[str, Any]) -> "FTDServiceGroupObject":
        return cls(
            name=str(payload.get("name", "")),
            is_system_defined=bool(payload.get("isSystemDefined", False)),
            objects=list(payload.get("objects", [])),
            type=str(payload.get("type", "")),
        )

    def to_legacy_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "isSystemDefined": self.is_system_defined,
            "objects": self.objects,
            "type": self.type,
        }


@dataclass(frozen=True)
class FTDAccessRuleObject:
    """Typed representation of an FTD access rule entry."""

    name: str
    rule_id: int
    source_zones: list[dict[str, Any]]
    destination_zones: list[dict[str, Any]]
    source_networks: list[dict[str, Any]]
    destination_networks: list[dict[str, Any]]
    destination_ports: list[dict[str, Any]]
    rule_action: str
    event_log_action: str
    log_files: bool
    type: str

    @classmethod
    def from_legacy(cls, payload: dict[str, Any]) -> "FTDAccessRuleObject":
        return cls(
            name=str(payload.get("name", "")),
            rule_id=int(payload.get("ruleId", 0)),
            source_zones=list(payload.get("sourceZones", [])),
            destination_zones=list(payload.get("destinationZones", [])),
            source_networks=list(payload.get("sourceNetworks", [])),
            destination_networks=list(payload.get("destinationNetworks", [])),
            destination_ports=list(payload.get("destinationPorts", [])),
            rule_action=str(payload.get("ruleAction", "")),
            event_log_action=str(payload.get("eventLogAction", "")),
            log_files=bool(payload.get("logFiles", False)),
            type=str(payload.get("type", "")),
        )

    def to_legacy_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ruleId": self.rule_id,
            "sourceZones": self.source_zones,
            "destinationZones": self.destination_zones,
            "sourceNetworks": self.source_networks,
            "destinationNetworks": self.destination_networks,
            "destinationPorts": self.destination_ports,
            "ruleAction": self.rule_action,
            "eventLogAction": self.event_log_action,
            "logFiles": self.log_files,
            "type": self.type,
        }


@dataclass(frozen=True)
class FTDInterfaceBundle:
    """Typed representation of interface conversion output bundle."""

    physical_interfaces: list[dict[str, Any]]
    subinterfaces: list[dict[str, Any]]
    etherchannels: list[dict[str, Any]]
    bridge_groups: list[dict[str, Any]]
    security_zones: list[dict[str, Any]]

    @classmethod
    def from_legacy(cls, payload: dict[str, Any]) -> "FTDInterfaceBundle":
        return cls(
            physical_interfaces=list(payload.get("physical_interfaces", [])),
            subinterfaces=list(payload.get("subinterfaces", [])),
            etherchannels=list(payload.get("etherchannels", [])),
            bridge_groups=list(payload.get("bridge_groups", [])),
            security_zones=list(payload.get("security_zones", [])),
        )

    def to_legacy_dict(self) -> dict[str, Any]:
        return {
            "physical_interfaces": self.physical_interfaces,
            "subinterfaces": self.subinterfaces,
            "etherchannels": self.etherchannels,
            "bridge_groups": self.bridge_groups,
            "security_zones": self.security_zones,
        }
