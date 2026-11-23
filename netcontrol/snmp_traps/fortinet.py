"""Fortinet FortiOS traps.

From the MIB texts: FORTINET-CORE-MIB and FORTINET-FORTIGATE-MIB.
Generated from the MIBs (OIDs, object names, enumerations); the severity
and the one-line meaning are Plexus's. See docs/snmp-traps.md.
"""

from __future__ import annotations

from netcontrol.snmp_traps.model import TrapDef, TrapObject

OBJECTS: dict[str, TrapObject] = {
    "fnSysSerial": TrapObject("1.3.6.1.4.1.12356.100.1.1.1"),
    "fnGenTrapMsg": TrapObject("1.3.6.1.4.1.12356.100.1.3.1.1"),
    "fgVpnTrapLocalGateway": TrapObject("1.3.6.1.4.1.12356.101.12.3.2"),
    "fgVpnTrapRemoteGateway": TrapObject("1.3.6.1.4.1.12356.101.12.3.3"),
    "fgVpnTrapPhase1Name": TrapObject("1.3.6.1.4.1.12356.101.12.3.4"),
    "fgWcApVdom": TrapObject("1.3.6.1.4.1.12356.101.14.1.1"),
    "fgWcApSerial": TrapObject("1.3.6.1.4.1.12356.101.14.1.2"),
    "fgWcApName": TrapObject("1.3.6.1.4.1.12356.101.14.1.3"),
    "fgFcSwVdom": TrapObject("1.3.6.1.4.1.12356.101.15.1.1"),
    "fgFcSwSerial": TrapObject("1.3.6.1.4.1.12356.101.15.1.2"),
    "fgFcSwName": TrapObject("1.3.6.1.4.1.12356.101.15.1.3"),
    "fgServerLoadBalanceRealServerAddress": TrapObject("1.3.6.1.4.1.12356.101.16.1.1"),
    "fgServerLoadBalanceVirtualServerName": TrapObject("1.3.6.1.4.1.12356.101.16.1.2"),
    "fgServerLoadBalanceRealServerAddress6": TrapObject("1.3.6.1.4.1.12356.101.16.1.3"),
    "fgPerCpuHighDetails": TrapObject("1.3.6.1.4.1.12356.101.4.4.4.1"),
}

TRAPS: tuple[TrapDef, ...] = (
    TrapDef(
        "1.3.6.1.4.1.12356.100.1.3.0.101",
        "fnTrapCpuThreshold",
        "FORTINET-CORE-MIB",
        "warning",
        "CPU usage over the configured threshold",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.100.1.3.0.102",
        "fnTrapMemThreshold",
        "FORTINET-CORE-MIB",
        "warning",
        "Memory usage over the configured threshold",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.100.1.3.0.103",
        "fnTrapLogDiskThreshold",
        "FORTINET-CORE-MIB",
        "warning",
        "Log disk usage over the configured threshold",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.100.1.3.0.104",
        "fnTrapTempHigh",
        "FORTINET-CORE-MIB",
        "critical",
        "Temperature sensor over its threshold",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.100.1.3.0.105",
        "fnTrapVoltageOutOfRange",
        "FORTINET-CORE-MIB",
        "warning",
        "Voltage out of range",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.100.1.3.0.106",
        "fnTrapPowerSupply",
        "FORTINET-CORE-MIB",
        "warning",
        "Power supply event (failure or restore)",
    ),
    TrapDef("1.3.6.1.4.1.12356.100.1.3.0.108", "fnTrapFanFailure", "FORTINET-CORE-MIB", "warning", "Fan failed"),
    TrapDef(
        "1.3.6.1.4.1.12356.100.1.3.0.201", "fnTrapIpChange", "FORTINET-CORE-MIB", "info", "Interface IP address changed"
    ),
    TrapDef("1.3.6.1.4.1.12356.101.2.0.301", "fgTrapVpnTunUp", "FORTINET-FORTIGATE-MIB", "info", "VPN tunnel up"),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.302", "fgTrapVpnTunDown", "FORTINET-FORTIGATE-MIB", "warning", "VPN tunnel down"
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.401",
        "fgTrapHaSwitch",
        "FORTINET-FORTIGATE-MIB",
        "warning",
        "HA cluster member became primary (failover)",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.402",
        "fgTrapHaStateChange",
        "FORTINET-FORTIGATE-MIB",
        "warning",
        "HA cluster member changed state",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.403", "fgTrapHaHBFail", "FORTINET-FORTIGATE-MIB", "critical", "HA heartbeat failed"
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.404",
        "fgTrapHaMemberDown",
        "FORTINET-FORTIGATE-MIB",
        "critical",
        "HA cluster member down",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.405",
        "fgTrapHaMemberUp",
        "FORTINET-FORTIGATE-MIB",
        "info",
        "HA cluster member joined",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.701",
        "fgTrapFazDisconnect",
        "FORTINET-FORTIGATE-MIB",
        "warning",
        "Disconnected from FortiAnalyzer",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.1102",
        "fgTrapPerCpuHigh",
        "FORTINET-FORTIGATE-MIB",
        "warning",
        "Per-CPU usage over the configured threshold",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.1101",
        "fgTrapServerLoadBalanceRealServerDown",
        "FORTINET-FORTIGATE-MIB",
        "warning",
        "Load-balanced real server down",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.901",
        "fgTrapFcSwUp",
        "FORTINET-FORTIGATE-MIB",
        "info",
        "Managed FortiSwitch session up",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.902",
        "fgTrapFcSwDown",
        "FORTINET-FORTIGATE-MIB",
        "warning",
        "Managed FortiSwitch session down",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.801", "fgTrapWcApUp", "FORTINET-FORTIGATE-MIB", "info", "Managed access point up"
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.2.0.802",
        "fgTrapWcApDown",
        "FORTINET-FORTIGATE-MIB",
        "warning",
        "Managed access point down",
    ),
    TrapDef(
        "1.3.6.1.4.1.12356.101.6.0.1003",
        "fgFmTrapConfChange",
        "FORTINET-FORTIGATE-MIB",
        "info",
        "Configuration changed outside FortiManager",
    ),
)
