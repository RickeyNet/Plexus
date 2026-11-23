# SNMP Traps

Plexus's SNMP trap receiver (UDP 10162 by default, Settings > Syslog &
Traps) stores every trap it receives (Monitoring > Events). Each SNMPv1 or
v2c trap, each SNMPv2c inform, and each SNMPv3 trap from an inventory host
that passes the [SNMPv3 checks](#snmpv3), is decoded and named from the
trap registry, so a stored trap reads

```text
linkDown: ifIndex 12, ifDescr GigabitEthernet1/0/12, ifAdminStatus up, ifOperStatus down
```

instead of its size. For a trap from an inventory host that carries the
host's SNMP community (SNMPv3: that is authenticated with the host's
SNMPv3 user), the server also acts on it:

- **Alerts**: the built-in trap rules below raise or resolve a monitoring
  alert, with notifications through the alert notification channels.
- **Configuration change**: a trap that says the running configuration
  changed starts the configuration backup and drift check of that host,
  through the same trigger the syslog configuration-change messages use.
- **Faster detection**: a trap that names a state change a rule acts on
  (an interface, module, power supply, fan, temperature, neighbor or HA
  change, a restart) starts a monitoring poll of the host within seconds.

APC UPS traps (PowerNet-MIB) keep their own handler, which raises the UPS
alerts under the poll's keys: see [APC UPS](apc-ups.md#snmp-traps).

The rules are listed under **Monitoring > Configure > Syslog Rules**, in
the **SNMP trap rules** section below the syslog rules.

## Intake

1. **Source**: the datagram passes the listener source allowlist and its
   per-source rate limit ([administration.md](administration.md#listener-sources)).
   A refused datagram is not parsed, stored or answered.
2. **Decode**: a v1 trap, a v2c trap or a v2c inform is decoded. An
   inform is answered at once with the Response its sender waits for (the
   same request id and varbinds, to the address and port it came from).
   An SNMPv3 datagram from an inventory host is held whole for the batch
   writer, which decodes it with that host's SNMPv3 user (see
   [SNMPv3](#snmpv3)); one from any other source, and anything that does
   not decode, is stored with its size and nothing more.
3. **Name**: the trap OID is looked up in the registry, and every varbind
   whose OID falls under an object of the registry is named (an
   enumerated value by its label: `ifOperStatus down`). An unknown trap is
   stored as `SNMP trap <oid>: <oid> = <value>, ...`. A v1 trap of a MIB
   whose notification OID has no `0` before its last number (JUNIPER-MIB's
   chassis traps) arrives as `enterprise.0.specific` (RFC 3584) and is
   still found.
4. **Store**: the event is stored with its name and text (`message`), its
   trap OID (`oid`) and the severity of the registry, or the severity of
   the rule the trap raises (`info` for a trap that clears one).
5. **Believe**: in the batch writer, a trap whose source is an inventory
   host (its primary address or a recorded interface address) is acted on
   only when its community is the one stored for that host (its SNMP
   profile, else its group's settings). A trap with another community is
   dropped and counted (`trap_dropped_community`). An SNMPv3 trap is
   believed when it passed the SNMPv3 checks with that host's user; one
   that fails them is dropped and counted (`trap_dropped_v3`). A trap from
   a source admitted by an extra network or the `any` policy has no host
   whose community or user could be checked: it is stored, never acted
   on.

All of this happens in the receiver's bounded queue: a datagram never
causes a database query before it is queued.

## SNMPv3

An SNMPv3 trap is checked with the SNMPv3 user of the inventory host it
comes from: the same user, authentication and privacy protocols and
passphrases the monitoring poll uses (the host's own SNMP profile, else its
group's SNMP settings, else the global settings; `{{secret.NAME}}`
passphrases are resolved as for the poll). There is no separate trap user.
The host's SNMP settings must be SNMPv3 with a user and an authentication
passphrase; a host polled over v2c has no SNMPv3 user and every SNMPv3 trap
from it is dropped.

The checks follow the User-based Security Model (RFC 3414), in order:

1. **User**: the message's user name is the host's SNMPv3 user.
2. **Security level**: the message's level is exactly the host's: authPriv
   when the host has a privacy passphrase, else authNoPriv. A weaker
   message (authNoPriv or noAuthNoPriv to an authPriv host, noAuthNoPriv
   to an authNoPriv host) is refused even when it is signed correctly, and
   so is a stronger one.
3. **Authentication**: the HMAC digest (MD5, SHA-1, SHA-256 or SHA-512, as
   set on the host) is checked with the key localized to the engine ID the
   message carries (the sending device's own engine ID, which needs no
   configuration in Plexus).
4. **Time window**: per source address and engine ID, Plexus remembers the
   highest engine boots and time it has accepted and lets the engine time
   run with its own clock. A message with a lower boots count, or more than
   150 seconds behind, is refused; an exact copy of a message already
   accepted is refused too. The first authenticated message from an engine
   Plexus has not seen starts that record (there is nothing to compare it
   with), and the record is kept in memory only: after a Plexus restart the
   next message from each engine is accepted the same way.
5. **Privacy**: an authPriv message is decrypted with DES, AES-128, AES-192
   or AES-256, as set on the host. AES-192 and AES-256 keys are extended in
   one of two ways that vendors disagree on: the Reeder form (Cisco and
   most others, the one the poll uses) and the Blumenthal form (net-snmp).
   Plexus tries the poll's form and then the other, so both kinds of
   device are decoded.

A message that fails the user, level, authentication, time window or
privacy check is dropped (not stored) and counted as `trap_dropped_v3`
(**SNMPv3 refused** under **Settings > Syslog & Traps**); the reason is
logged at debug level. An SNMPv3 inform (or any message with the
reportable flag), an engine ID discovery probe, a PDU that is not a trap
and an authenticated message whose content does not decode are stored
with their size and never acted on.

**Upgrading:** every SNMPv3 trap used to be stored undecoded. Now an SNMPv3
trap from an inventory host that fails the checks above is dropped instead
of stored. For each device that sends SNMPv3 traps, set its trap user,
authentication and privacy protocols and passphrases to the host's SNMPv3
poll user in Plexus, with exactly the same security level, and send traps
(not informs); or send v1 / v2c traps with the host's community instead.

To check a host's SNMPv3 user end to end, send a test trap from a machine
whose address is recorded on the host, with net-snmp (`-e` sets the
sending engine ID, any 5 to 32 octets):

```text
snmptrap -v 3 -e 0x80001f8880aabbccdd -u example-user -l authPriv \
  -a SHA -A 'example-auth-pass' -x AES -X 'example-priv-pass' \
  192.0.2.10:162 '' 1.3.6.1.6.3.1.1.5.1
```

It should appear in Monitoring > Events as `coldStart`.

## Built-in rules

Built-in rules ship with Plexus. You can turn each one off or change its
severity (**Disable** / the severity list in the **SNMP trap rules**
section); the traps, threshold and auto-resolve time are fixed.

| Rule (metric) | Raised by | Resolved by | Instance | Threshold | Auto-resolve | Severity |
|---|---|---|---|---|---|---|
| Interface down (`trap_link_down`) | `linkDown` with `ifAdminStatus` up (an interface an operator shut down raises nothing) | `linkUp` | `ifIndex <n>` | Every trap | 24 h | warning |
| Module down (`trap_module`) | `cefcModuleStatusChange` to failed, missing, diagFailed, outOfServiceEnvTemp, poweredDown or powerDenied; `cefcFRURemoved`; `cswStackMemberRemoved`; JUNIPER-MIB `jnxFruRemoval` / `PowerOff` / `Failed` / `Offline` of an FPC, SFM, control board, routing engine, SIB, PIC, line card chassis, FEB, switch fabric board or adapter card (not `jnxFruOfflineReason` configPowerOff, cliCommand or buttonPress); `jnxVccpMemberDown`; AOS-CX VSF member `not_present`, `communication_failure` or `in_other_fragment`, `arubaWiredModuleRemovedNotification`; PAN-OS `panHWSlotFailureTrap` / `RemovedTrap` / `PoweroffTrap` | `cefcModuleStatusChange` to ok (or an okBut... state), `cefcFRUInserted`, `cswStackNewMember`, `jnxFruOnline` / `jnxFruOK`, `jnxVccpMemberUp`, VSF member `ready`, `arubaWiredModuleInsertedNotification`, `panHWSlotUpTrap` | `entPhysicalIndex <n>`, `switch <n>`, `FRU <index>`, `member <n>`, the module name, the PAN-OS object | Every trap | 24 h | critical |
| Power supply fault (`trap_power_supply`) | `ciscoEnvMonSuppStatusChangeNotif` / `ciscoEnvMonRedundantSupplyNotification` critical, shutdown or notFunctioning; `jnxPowerSupplyFailure`, `jnxPowerSupplyInputFailure`; `panHWPsFailureTrap`, `panHWPsRemovedTrap`; `hpicfPowerSupplyStatusTrap` faulted or removed; `boxsPowSupplyStateChange` removal, failure or losepower | The same Cisco traps normal, `jnxPowerSupplyOK` / `InputOK`, `panHWPsInsertedTrap`, `hpicfPowerSupplyStatusTrap` ok, `boxsPowSupplyStateChange` becomeoperational | `supply <n>`, the Juniper `jnxContentsDescr` (`<descr> input` for an input failure), the PAN-OS object | Every trap | 24 h | critical |
| Fan fault (`trap_fan`) | `ciscoEnvMonFanStatusChangeNotif` / `ciscoEnvMonFanNotification` critical, shutdown or notFunctioning; `cefcFanTrayStatusChange` down; `jnxFanFailure`; `fnTrapFanFailure`; `panHWFanFailureTrap`, `panHWFanRemovedTrap`; `boxsFanStateChange` removal, failure or losepower; Netgear `fanFailureTrap` | The same Cisco traps normal / up, `jnxFanOK`, `panHWFanInsertedTrap`, `boxsFanStateChange` becomeoperational | `fan <n>`, `fan tray <n>`, the Juniper description, the PAN-OS object (FortiOS and `fanFailureTrap`: per device) | Every trap | 24 h | warning |
| Temperature alarm (`trap_temperature`) | `ciscoEnvMonTempStatusChangeNotif` / `ciscoEnvMonTemperatureNotification` warning, critical or shutdown; `jnxOverTemperature`; `fnTrapTempHigh`; `boxsTemperatureStateChange` warning, critical or shutdown; `boxsThermalShutdown` | `ciscoEnvMonTempStatusChangeNotif` normal, `jnxTemperatureOK`, `boxsTemperatureStateChange` normal | `sensor <n>`, the Juniper description (FortiOS, thermal shutdown: per device) | Every trap | 24 h | critical |
| BGP neighbor down (`trap_bgp_neighbor`) | BGP4-MIB `bgpBackwardTransNotification` / `bgpBackwardTransition`; CISCO-BGP4-MIB `cbgpBackwardTransition`, `cbgpPeer2BackwardTransNotification`, `cbgpPeer2BackwardTransition`, and `cbgpFsmStateChange` / `cbgpPeer2FsmStateChange` from established to another state; `jnxBgpM2BackwardTransition`; `aristaBgp4V2BackwardTransitionNotification`; PAN-OS `panROUTINGRoutedBGPPeerLeftEstablishedTrap` | `bgpEstablishedNotification` / `bgpEstablished`, `cbgpPeer2EstablishedNotification`, an FSM change to established, `jnxBgpM2Established`, `aristaBgp4V2EstablishedNotification`, `panROUTINGRoutedBGPPeerEnterEstablishedTrap` | The peer address (from the table index, IPv4 or IPv6, or the remote address varbind; PAN-OS: `peer IP: <x>` in the description) | Every trap | Clear trap only | critical |
| OSPF neighbor down (`trap_ospf_neighbor`) | `ospfNbrStateChange` / `ospfVirtNbrStateChange` to down; PAN-OS `panROUTINGRoutedOSPFNeighborDownTrap` | `ospfNbrStateChange` to full or twoWay (where two routers that are neither DR nor BDR stay), `ospfVirtNbrStateChange` to full; `panROUTINGRoutedOSPFNeighborFullTrap` | The neighbor router id (PAN-OS: per firewall) | Every trap | Clear trap only | critical |
| HA failover or switchover (`trap_ha_switchover`) | `ciscoRFSwactNotif`, `cswStackNewMaster`, `jnxRedundancySwitchover`, `jnxJsChassisClusterSwitchover`, `fgTrapHaSwitch`, `fgTrapHaMemberDown`, `panHAStateChangeTrap`, `vrrpTrapNewMaster`, `vrrpv3NewMaster`, AOS-CX `keepAliveDown`, `islDown` | `fgTrapHaMemberUp`, `keepAliveUp`, `islUp` | Per device, or the member serial, redundancy group, VRRP `<ifIndex>.<VRID>`, `VSX keepalive` / `VSX ISL` | Every trap | 60 min | warning |
| Device or agent restarted (`trap_device_restart`) | `coldStart`, `warmStart`, `nsNotifyStart`, `nsNotifyRestart`, `nsNotifyShutdown`, `ucdStart`, `ucdShutdown`, `jnxDyingGasp`, `panGeneralSystemStartTrap`, `panGeneralSystemShutdownTrap` | Time only | Per device | Every trap | 60 min | warning |
| SNMP authentication failures (`trap_snmp_auth_failure`) | `authenticationFailure` | Time only | Per device | 5 within 5 min | 30 min | warning |

How the rules behave is the syslog rule engine's
([syslog-rules.md](syslog-rules.md#how-a-message-becomes-an-alert)): the
same threshold counters (two traps for the same host, rule and instance
less than 5 seconds apart count once), one alert per rule, host and
instance (a repeat bumps the open alert's occurrence count), suppressions
by host, group or metric (Monitoring > Configure > Suppressions lists the
`Trap:` metrics), and auto-resolve checked every minute. Alerts are raised
only while monitoring is on.

**Their own family.** A trap alert has type `trap`, metric `trap_<rule>` and
the key `trap:<rule>:<host>:<instance>`. A trap resolves only a trap alert
of its own host; it never resolves a syslog alert (`syslog_<rule>`) or an
alert of the poll (`module_down` and the polled checks,
[monitoring.md](monitoring.md)), and none of those resolves a trap alert.
A suppression of `syslog_fan` does not cover `trap_fan`. When a device
sends both syslog and traps for one event, both alerts open: turn one rule
off when that is too much.

A single interface down is an alert here (unlike the syslog **Interface
flapping** rule, which counts three). Most platforms send `linkDown` for
every interface unless told otherwise (Cisco IOS: `snmp trap link-status`
is on per interface by default), so an access switch raises one alert per
port that goes down. Stop the traps on the access ports (`no snmp trap
link-status` on Cisco IOS), or turn the rule off, or suppress
`trap_link_down` for the hosts whose ports go down all day. The hardware rules resolve after 24
hours without a new trap because several forms have no recovery trap; the
poll's own checks keep reporting what is still down.

## Configuration change trigger

| Trap | Condition |
|---|---|
| CISCO-CONFIG-MAN-MIB `ciscoConfigManEvent` | `ccmHistoryEventConfigDestination` running (a copy to startup is a save, not a change) |
| CISCO-CONFIG-MAN-MIB `ccmCLIRunningConfigChanged` | Always |
| JUNIPER-CFGMGMT-MIB `jnxCmCfgChange` | Always |
| FORTINET-FORTIGATE-MIB `fgFmTrapConfChange` | Always |
| ARUBAWIRED-CONFIG-MIB `arubaWiredConfigurationChangeNotification` | Always |
| PAN-TRAPS `panConfigTrap` | `panConfigCmd` `commit` and `panConfigResult` `Succeeded` |

The trap starts the same run a syslog configuration-change message does
([syslog-rules.md](syslog-rules.md#configuration-change-trigger)): 60
seconds after the last change, no more than 10 minutes after the first,
at most once per host every 5 minutes, through the host group's backup
policy. It does not depend on monitoring being on.

## Re-poll trigger

A trap that raises or clears a rule (as shipped, whether the rule is on or
not), except an authentication failure, polls the host 5 seconds later; a
trap that says the device is going down (`jnxDyingGasp`,
`nsNotifyShutdown`, `ucdShutdown`, `panGeneralSystemShutdownTrap`) after
30 seconds. A host is re-polled at most once a minute, and not while one is
already waiting (the syslog re-poll's limits, shared with it). Nothing is
re-polled while monitoring is off.

## Switches

Settings > Syslog & Traps (admin):

- **Raise alerts from SNMP trap rules** (`trap_alerts`): the alerts above.
- **Back up the config on a change message** (`config_change_trigger`) and
  **Re-poll on link down, module down or reload** (`repoll_trigger`):
  shared with syslog.

Each is on by default; turning one off stops that behaviour only, and
traps are still stored.

The API: `GET /api/monitoring/trap-rules` (needs **monitoring**) lists the
rules in the syslog rules' shape (`source` `trap`, `tags` and
`clear_tags` the trap names); `PATCH /api/monitoring/trap-rules/builtin/{key}`
(`enabled`, `severity`; needs **monitoring.write**, audit logged as
`trap_rule.builtin_updated`). The override is stored with the syslog
rules' overrides under `trap_<key>`. A user limited to selected inventory
groups can read the rules but not change them.

## Traps named per vendor

The registry (`netcontrol/snmp_traps/`) has one table per vendor,
generated from the MIB texts (OIDs, object names and enumerations); the
stored severity and the one-line meaning are Plexus's. Any varbind under a
named object is named whatever trap carries it.

- **Standard MIBs**: SNMPv2-MIB `coldStart`, `warmStart`,
  `authenticationFailure`; IF-MIB `linkDown`, `linkUp`; ENTITY-MIB
  `entConfigChange`; ENTITY-STATE-MIB `entStateOperDisabled`,
  `entStateOperEnabled`; BGP4-MIB `bgpEstablishedNotification`,
  `bgpBackwardTransNotification`, `bgpEstablished`,
  `bgpBackwardTransition`; OSPF-TRAP-MIB `ospfNbrStateChange`,
  `ospfVirtNbrStateChange`, `ospfIfStateChange`, `ospfVirtIfStateChange`,
  `ospfIfConfigError`, `ospfIfAuthFailure`, `ospfRestartStatusChange`;
  BRIDGE-MIB `newRoot`, `topologyChange`; VRRP-MIB `vrrpTrapNewMaster`,
  `vrrpTrapAuthFailure`; VRRPV3-MIB `vrrpv3NewMaster`, `vrrpv3ProtoError`;
  RMON-MIB `risingAlarm`, `fallingAlarm`.
- **net-snmp (OPNsense, Linux)**: NET-SNMP-AGENT-MIB `nsNotifyStart`,
  `nsNotifyShutdown`, `nsNotifyRestart`; UCD-SNMP-MIB `ucdStart`,
  `ucdShutdown`.
- **Cisco IOS / IOS XE / IOS XR / NX-OS / ASA / FTD**:
  CISCO-ENTITY-FRU-CONTROL-MIB `cefcModuleStatusChange`,
  `cefcPowerStatusChange`, `cefcFRUInserted`, `cefcFRURemoved`,
  `cefcUnrecognizedFRU`, `cefcFanTrayStatusChange`,
  `cefcPowerSupplyOutputChange`; CISCO-ENVMON-MIB
  `ciscoEnvMonShutdownNotification`, `ciscoEnvMonVoltageNotification`,
  `ciscoEnvMonTemperatureNotification`, `ciscoEnvMonFanNotification`,
  `ciscoEnvMonRedundantSupplyNotification`,
  `ciscoEnvMonVoltStatusChangeNotif`, `ciscoEnvMonTempStatusChangeNotif`,
  `ciscoEnvMonFanStatusChangeNotif`, `ciscoEnvMonSuppStatusChangeNotif`;
  CISCO-CONFIG-MAN-MIB `ciscoConfigManEvent`, `ccmCLIRunningConfigChanged`;
  CISCO-STACKWISE-MIB `cswStackPortChange`, `cswStackNewMaster`,
  `cswStackMismatch`, `cswStackRingRedundant`, `cswStackNewMember`,
  `cswStackMemberRemoved`; CISCO-RF-MIB `ciscoRFSwactNotif`,
  `ciscoRFProgressionNotif`; CISCO-BGP4-MIB `cbgpFsmStateChange`,
  `cbgpBackwardTransition`, `cbgpPrefixThresholdExceeded`,
  `cbgpPrefixThresholdClear`, `cbgpPeer2EstablishedNotification`,
  `cbgpPeer2BackwardTransNotification`, `cbgpPeer2FsmStateChange`,
  `cbgpPeer2BackwardTransition`, `cbgpPeer2PrefixThresholdExceeded`,
  `cbgpPeer2PrefixThresholdClear`; CISCO-ENTITY-SENSOR-MIB
  `entSensorThresholdNotification`,
  `entSensorThresholdRecoveryNotification`; CISCO-SYSLOG-MIB
  `clogMessageGenerated`.
- **Juniper Junos**: JUNIPER-MIB `jnxPowerSupplyFailure`,
  `jnxPowerSupplyInputFailure`, `jnxFanFailure`, `jnxOverTemperature`,
  `jnxRedundancySwitchover`, `jnxFruRemoval`, `jnxFruInsertion`,
  `jnxFruPowerOff`, `jnxFruPowerOn`, `jnxFruFailed`, `jnxFruOffline`,
  `jnxFruOnline`, `jnxFruCheck`, `jnxHardDiskFailed`, `jnxDyingGasp`,
  `jnxPowerSupplyOK`, `jnxPowerSupplyInputOK`, `jnxFanOK`,
  `jnxTemperatureOK`, `jnxFruOK`, `jnxHardDiskOK`; BGP4-V2-MIB-JUNIPER
  `jnxBgpM2Established`, `jnxBgpM2BackwardTransition`; JUNIPER-CFGMGMT-MIB
  `jnxCmCfgChange`, `jnxCmRescueChange`; JUNIPER-CHASSIS-CLUSTER-MIB
  `jnxJsChassisClusterSwitchover`; JUNIPER-VIRTUALCHASSIS-MIB
  `jnxVccpMemberDown`, `jnxVccpMemberUp`, `jnxVccpPortDown`,
  `jnxVccpPortUp`.
- **Arista EOS**: ARISTA-BGP4V2-MIB `aristaBgp4V2EstablishedNotification`,
  `aristaBgp4V2BackwardTransitionNotification`; ARISTA-ENTITY-SENSOR-MIB
  `aristaEntSensorAlarm`; EOS also sends the standard traps.
- **Fortinet FortiOS**: FORTINET-CORE-MIB `fnTrapCpuThreshold`,
  `fnTrapMemThreshold`, `fnTrapLogDiskThreshold`, `fnTrapTempHigh`,
  `fnTrapVoltageOutOfRange`, `fnTrapPowerSupply`, `fnTrapFanFailure`,
  `fnTrapIpChange`; FORTINET-FORTIGATE-MIB `fgTrapVpnTunUp`,
  `fgTrapVpnTunDown`, `fgTrapHaSwitch`, `fgTrapHaStateChange`,
  `fgTrapHaHBFail`, `fgTrapHaMemberDown`, `fgTrapHaMemberUp`,
  `fgTrapFazDisconnect`, `fgTrapPerCpuHigh`,
  `fgTrapServerLoadBalanceRealServerDown`, `fgTrapFcSwUp`,
  `fgTrapFcSwDown`, `fgTrapWcApUp`, `fgTrapWcApDown`, `fgFmTrapConfChange`.
- **Palo Alto PAN-OS**: PAN-TRAPS names one trap per system log event id
  (more than 600). Named here: `panGeneralSystemStartTrap`,
  `panGeneralSystemShutdownTrap`, `panGeneralAuthFailTrap`,
  `panConfigTrap`, `panHAStateChangeTrap`, `panHAPreemptTrap`,
  `panHADataplaneDownTrap`, `panHAPathMonitorDownTrap`,
  `panHAPathMonitorUpTrap`, `panHALinkMonitorDownTrap`,
  `panHALinkMonitorUpTrap`, `panHASplitBrainTrap`,
  `panHAPeerSplitBrainTrap`, `panHAHa1LinkChangeTrap`,
  `panHAHa2LinkChangeTrap`, `panHWSlotUpTrap`, `panHWSlotFailureTrap`,
  `panHWSlotRemovedTrap`, `panHWSlotInsertedTrap`, `panHWSlotPoweroffTrap`,
  `panHWPsInsertedTrap`, `panHWPsRemovedTrap`, `panHWPsFailureTrap`,
  `panHWFanInsertedTrap`, `panHWFanRemovedTrap`, `panHWFanFailureTrap`,
  `panHWInsufficientPowerTrap`, `panHWDiskErrorsTrap`,
  `panPORTLinkChangeTrap`, `panROUTINGRoutedBGPPeerEnterEstablishedTrap`,
  `panROUTINGRoutedBGPPeerLeftEstablishedTrap`,
  `panROUTINGRoutedOSPFNeighborFullTrap`,
  `panROUTINGRoutedOSPFNeighborDownTrap`. The other system log traps are
  stored under their OID, their varbinds named all the same (they carry the
  same `panSystem*` objects).
- **HPE Aruba AOS-CX**: ARUBAWIRED-POWERSUPPLY-MIB
  `arubaWiredPSUStateNotification`; ARUBAWIRED-FAN-MIB
  `arubaWiredFanStateNotification`; ARUBAWIRED-FANTRAY-MIB
  `arubaWiredFanTrayStateNotification`; ARUBAWIRED-TEMPSENSOR-MIB
  `arubaWiredTempSensorStateNotification`; ARUBAWIRED-MODULE-MIB
  `arubaWiredModuleStateNotification`,
  `arubaWiredModuleInsertedNotification`,
  `arubaWiredModuleRemovedNotification`,
  `arubaWiredModuleUnrecognizedNotification`; ARUBAWIRED-VSF-MIB and
  ARUBAWIRED-VSFv2-MIB member and fragment status changes;
  ARUBAWIRED-VSX-MIB `islUp`, `islDown`, `keepAliveUp`, `keepAliveDown`;
  ARUBAWIRED-CONFIG-MIB `arubaWiredConfigurationChangeNotification`.
- **HPE Aruba AOS-Switch**: HP-ICF-CHASSIS `hpicfSensorTrap`,
  `hpicfPowerSupplyStatusTrap`; HP-ICF-BASIC `hpicfSelfTestTrap`;
  HP-ICF-FAULT-FINDER-MIB `hpicfFaultFinderTrap`.
- **Aruba Instant On**: the standard MIBs.
- **Netgear**: NETGEAR-SWITCHING-MIB `linkFailureTrap`, `fanFailureTrap`,
  `powerSupplyStatusChangeTrap`, `failedUserLoginTrap`, `userLockoutTrap`,
  `stpInstanceNewRootTrap`, `stpInstanceTopologyChangeTrap`;
  NETGEAR-BOXSERVICES-PRIVATE-MIB `boxsFanStateChange`,
  `boxsPowSupplyStateChange`, `boxsTemperatureChange`,
  `boxsTemperatureStateChange`, `boxsThermalShutdown`.

**Sources.** The MIB texts were read from the LibreNMS MIB collection
(which carries the vendors' MIB files: `mibs/`, `mibs/cisco`,
`mibs/juniper`, `mibs/arista`, `mibs/fortinet`, `mibs/paloaltonetworks`,
`mibs/arubaos-cx`, `mibs/hp`, `mibs/netgear`) and compiled with pysmi;
PAN-TRAPS, which does not compile, was read as text, its OIDs from
PAN-COMMON-MIB (`panCommonEventEventsV2` is
`1.3.6.1.4.1.25461.2.1.3.2.0`) and PAN-GLOBAL-REG. The VRRP-MIB file of
that collection is a later draft; the `vrrpOperMasterIpAddr` object of RFC
2787 is named from the same file.

## Device configuration

Send traps to the Plexus server's address on the trap receiver's port (UDP
162 published to 10162 in Docker), with the host's polling community, from
an address Plexus knows (the host's primary address or a recorded
interface address). The examples use `192.0.2.10` for Plexus and an
invented community.

```text
! Cisco IOS / IOS XE: every trap the release supports, sent as informs
! (acknowledged by Plexus; "traps" instead of "informs" sends plain traps)
snmp-server enable traps
snmp-server host 192.0.2.10 informs version 2c example-community

! Juniper Junos
set snmp trap-group plexus version v2
set snmp trap-group plexus targets 192.0.2.10
set snmp trap-group plexus categories chassis link routing configuration startup
```

The trap and inform command names differ by release: see the SNMP
configuration guide of your platform. FortiOS (`config system snmp
community`), PAN-OS (Device > Server Profiles > SNMP Trap, V2c), AOS-CX
(`snmp-server host 192.0.2.10 trap version v2c community ...`) and
AOS-Switch (`snmp-server host 192.0.2.10 community ...`) each name a trap
receiver with its community.

## Known gaps

- **Not run against a live device**: every form above was written from
  the MIB definitions and checked against invented samples built from
  them (`tests/test_snmp_traps.py`). Monitoring > Events shows what your
  devices send: an unknown trap is stored under its OID.
- **SNMPv3 informs** are stored with their size only and never answered:
  Plexus is not an SNMPv3 authoritative engine (that needs its own engine
  ID and engine boots kept across restarts). Send SNMPv3 traps, or SNMPv2c
  informs.
- **SNMPv3 replay record** is kept in memory: after a restart the first
  message from each engine is accepted without a reference (see
  [SNMPv3](#snmpv3)). SNMPv3 traps have not been checked against a live
  device.
- **Cisco ASA / FTD failover**: CISCO-FIREWALL-MIB has no failover
  notification, and no other Cisco MIB with one was retrieved; ASA failover
  reaches Plexus as syslog.
- **Sensor traps without a sensor type**: CISCO-ENTITY-SENSOR-MIB
  `entSensorThreshold*`, ARISTA-ENTITY-SENSOR-MIB `aristaEntSensorAlarm`
  and HP-ICF-CHASSIS `hpicfSensorTrap` do not say whether the sensor is a
  temperature, fan or voltage sensor: named only. ENTITY-STATE-MIB
  `entStateOperDisabled` / `Enabled` name no entity class: named only.
- **Fortinet**: `fnTrapPowerSupply` reports a failure and a restore with
  the same OID and a message text (`fnGenTrapMsg`) the MIB does not
  define: named only. `fnTrapFanFailure` and `fnTrapTempHigh` have no
  recovery trap and are per firewall.
- **HPE Aruba AOS-CX**: the power supply, fan, fan tray, temperature
  sensor and module states are free text the MIBs do not enumerate: named
  and stored, no rule. Only the VSF member status has documented values.
- **HPE Aruba AOS-Switch**: no configuration change trap (the HP
  CONFIG-MIB retrieved does not compile); `hpicfSensorTrap` names no
  sensor type.
- **Palo Alto PAN-OS**: OSPF alerts are per firewall (the trap names no
  neighbor); the Advanced Routing Engine has no traps in PAN-TRAPS; the
  BGP peer is read from the description (`peer IP: <x>`), the form of the
  syslog rule.
- **Netgear**: `powerSupplyStatusChangeTrap` and `linkFailureTrap` carry
  no varbinds; NETGEAR-SMART-SWITCHING-MIB (smart switches, other OIDs) is
  not named.
- **Aruba Instant On**: no Instant On MIB was found; only the standard
  traps are named.
- **Cisco `clogMessageGenerated`** is stored with its facility, severity,
  mnemonic and text; its syslog text is not run through the syslog rules.
- Threshold counters (the authentication failure rule) live in memory and
  start empty after a restart.
