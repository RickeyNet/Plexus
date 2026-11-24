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

- **Alerts**: the built-in trap rules below, and your own
  [custom trap rules](#custom-rules), raise or resolve a monitoring alert,
  with notifications through the alert notification channels.
- **Cisco syslog over SNMP**: a CISCO-SYSLOG-MIB `clogMessageGenerated`
  trap goes through the syslog rules as the syslog message it carries
  ([below](#cisco-syslog-messages-sent-as-traps)).
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
   with). The record (boots and time per source and engine ID, not the
   copies) is stored: written at most once a minute, only for the engines
   whose time moved, and when Plexus stops, and loaded when the trap
   receiver starts, with each engine's clock run on by the time that
   passed. After a restart, an older boot or a message more than 150
   seconds behind is still refused. What remains: an exact copy of a
   message from the last 150 seconds before the restart is accepted once
   more (the copies are not stored), and after a crash, the movement since
   the last write (at most a minute) is lost. The record keeps the 4096
   most recently seen engines, as the memory does.
5. **Privacy**: an authPriv message is decrypted with DES, AES-128, AES-192
   or AES-256, as set on the host. AES-192 and AES-256 keys are extended in
   one of two ways that vendors disagree on: the Reeder form (Cisco and
   most others, the one the poll uses) and the Blumenthal form (net-snmp).
   Plexus tries the poll's form and then the other, so both kinds of
   device are decoded.

A message that fails the user, level, authentication, time window or
privacy check is dropped (not stored) and counted as `trap_dropped_v3`
(**SNMPv3 refused** under **Settings > Syslog & Traps**); the reason is
logged at debug level. A PDU that is not a trap and an authenticated
message whose content does not decode are stored with their size and never
acted on, and so is an SNMPv3 inform or engine ID discovery probe from a
source that is not an inventory host, or while the receiver's engine is not
started (see below).

**Upgrading:** every SNMPv3 trap used to be stored undecoded. Now an SNMPv3
trap from an inventory host that fails the checks above is dropped instead
of stored. For each device that sends SNMPv3 traps, set its trap user,
authentication and privacy protocols and passphrases to the host's SNMPv3
poll user in Plexus, with exactly the same security level; or send v1 / v2c
traps with the host's community instead.

### SNMPv3 informs

For an inform the roles turn round (RFC 3414 section 1.5.1): the receiver
is the authoritative engine, so the sender must use Plexus's engine ID,
boots and time, and the user's keys are localized to Plexus's engine ID.
The trap receiver has its own SNMPv3 engine for this:

- **Engine ID**: generated once in the RFC 3411 format (`80004fb805`
  followed by 12 random octets) and stored; it never changes, so a device
  configured with it keeps working across restarts and upgrades.
  `GET /api/admin/metrics/receivers/config` returns it as `trap_engine_id`
  ([administration.md](administration.md#syslog--traps)), and Plexus logs
  it when the trap receiver starts.
- **Engine boots**: stored and incremented each time the trap receiver
  starts listening; the engine time counts the seconds since. Only the
  process that binds the trap port counts a boot.
- **Discovery**: a message with the reportable flag for another engine ID
  (an empty one: a discovery probe, RFC 3414 section 4) from an inventory
  host is answered at once with a Report carrying
  `usmStatsUnknownEngineIDs` and Plexus's engine ID, boots and time.
- **The inform**: checked with the host's SNMPv3 poll user exactly as a
  trap is (user, exact security level, authentication, privacy), then
  against Plexus's own clock (RFC 3414 section 3.2 step 7a: the same boots,
  and a time within 150 seconds); an exact copy is refused. A stale inform
  gets an authenticated `usmStatsNotInTimeWindows` Report, from which the
  sender takes Plexus's boots and time and sends again; that exchange is
  neither stored nor counted as a refusal. An accepted inform is answered
  with its Response (the same request id and varbinds, at the inform's
  security level), then stored, named and acted on like a trap.
- **Refused informs** (unknown user, wrong security level, digest or
  privacy) are dropped and counted as `trap_dropped_v3`, and get no
  answer. No Report is sent for them: a sender needs only the discovery
  and time-window Reports, and the others would tell anyone who can spoof
  an inventory address which user names exist.
- **Limits**: only inventory hosts get an answer, only to a message with
  the reportable flag, after the source allowlist and rate limit, and no
  answer is more than three times the size of the message it answers (or
  larger than the sender accepts); a larger Response is not sent (the
  inform is still accepted). The receiver answers within about 0.1 second
  of the batch writer taking the inform.

If the receiver's engine cannot start (the database is unreachable when
the trap receiver starts), informs are stored with their size and not
answered, as before.

Configure a device to send informs with the host's SNMPv3 poll user,
localized to Plexus's engine ID. An invented example, Plexus at
`192.0.2.10` with engine ID `80004fb805aabbccddeeff001122334455`:

```text
! Cisco IOS / IOS XE: the remote engine ID and the user on it come first
snmp-server engineID remote 192.0.2.10 udp-port 162 80004fb805aabbccddeeff001122334455
snmp-server user example-user example-group remote 192.0.2.10 udp-port 162 v3 auth sha example-auth-pass priv aes 128 example-priv-pass
snmp-server group example-group v3 priv
snmp-server host 192.0.2.10 informs version 3 priv example-user
```

With net-snmp, `snmpinform` discovers the engine ID itself:

```text
snmpinform -v 3 -u example-user -l authPriv -a SHA -A 'example-auth-pass' \
  -x AES -X 'example-priv-pass' 192.0.2.10:162 '' 1.3.6.1.6.3.1.1.5.1
```

It should return without a timeout and appear in Monitoring > Events as
`coldStart`.

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
| Spanning tree root changed (`trap_stp_root_change`) | BRIDGE-MIB `newRoot` (the device became the root); Netgear `stpInstanceNewRootTrap` | Time only | Per device (Netgear: `instance <MST id>`) | Every trap | 60 min | warning |
| Spanning tree topology changes (`trap_stp_topology_change`) | BRIDGE-MIB `topologyChange`; Netgear `stpInstanceTopologyChangeTrap` | Time only | Per device (Netgear: `instance <MST id>`) | 5 within 10 min | 30 min | warning |
| Port error-disabled (`trap_port_err_disabled`) | CISCO-ERR-DISABLE-MIB `cErrDisableInterfaceEventRev1`, `cErrDisableInterfaceEvent` (the cause is in `cErrDisableIfStatusCause`) | Time only | `ifIndex <n>` (`ifIndex <n> vlan <v>` for a port-VLAN pair) | Every trap | 24 h | warning |
| Port security violation (`trap_port_security`) | CISCO-PORT-SECURITY-MIB `cpsSecureMacAddrViolation`, `cpsTrunkSecureMacAddrViolation`, `cpsIfVlanSecureMacAddrViolation` | Time only | The `ifName`, else `ifIndex <n>`, else per device | Every trap | 60 min | warning |
| MAC address flapping (`trap_mac_flap`) | CISCO-MAC-NOTIFICATION-MIB `cmnMacMoveNotification` | Time only | `vlan <n>` | 3 within 10 min | 30 min | warning |
| HSRP failover (`trap_hsrp_state`) | CISCO-HSRP-MIB `cHsrpStateChange` to active, or to initial, learn, listen or speak (the group left active or standby) | Time only | `ifIndex <n> group <g>` | Every trap | 60 min | warning |
| EIGRP neighbor down (`trap_eigrp_neighbor`) | CISCO-EIGRP-MIB `cEigrpNbrDownEvent` | Time only (the MIB has no neighbor up trap) | The peer address | Every trap | 24 h | critical |
| IS-IS adjacency down (`trap_isis_adjacency`) | ISIS-MIB `isisAdjacencyChange` and CISCO-IETF-ISIS-MIB `ciiAdjacencyChange` to down or failed | The same traps to up | `<system ID> circuit <n>` (the system ID is the first 6 bytes of the LSP ID) | Every trap | Clear trap only | critical |
| IPsec tunnel down (`trap_ipsec_tunnel`) | CISCO-IPSEC-FLOW-MONITOR-MIB `cikeTunnelStop`; FortiOS `fgTrapVpnTunDown` | `cikeTunnelStart`; `fgTrapVpnTunUp` | The remote peer address (FortiOS: the remote gateway, else the phase 1 name) | Every trap | Clear trap only | critical |
| IP SLA probe down (`trap_ip_sla`) | CISCO-RTTMON-MIB `rttMonNotification` with `rttMonReactVar` timeout, connectionLoss or verifyError and `rttMonReactOccurred` true | The same with `rttMonReactOccurred` false | `probe <rttMonCtrlAdminIndex>` | Every trap | Clear trap only | warning |
| PoE fault (`trap_poe_fault`) | POWER-ETHERNET-MIB `pethPsePortOnOffNotification` with `pethPsePortDetectionStatus` fault or otherFault | The same with deliveringPower | `PoE port <group>.<port>` | Every trap | 24 h | warning |

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
alert of the poll (`module_down` and the polled checks, among them
`ha_role_change` and `device_restarted`, which report a failover and a
restart from the polled state: [monitoring.md](monitoring.md)), and none
of those resolves a trap alert.
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

## Custom rules

A custom trap rule raises an alert for a trap the built-in rules do not
cover, including one the registry does not name (stored under its OID).
Create it with **+ New Trap Rule** in the **SNMP trap rules** section.

- **Raising traps**: comma separated trap OIDs (`1.3.6.1.4.1.32473.2.0.5`),
  OID prefixes ending in `.*` (`1.3.6.1.4.1.32473.2.*`: every trap under
  it), or trap names the registry knows (`cefcModuleStatusChange`; a name
  it does not know is refused: use the OID). A v1 trap's
  `enterprise.0.specific` OID also matches the notification OID without
  the `0`, as the registry looks it up.
- **Only when** (optional, at most 10): conditions on the varbinds, all of
  which must hold. Each names a varbind by its registry object name
  (`ifAdminStatus`) or its OID (an instance OID under it matches too), an
  operator and a value: `equals` (ignoring case), `contains` (ignoring
  case) or `matches` (an RE2 regular expression, ignoring case). The
  value tested is the decoded value and, for an enumerated object, its
  label too: `ifAdminStatus equals up` and `ifAdminStatus equals 1` both
  hold for an interface that is up. A trap without the varbind fails the
  condition.
- **Instance**: the varbind whose value (or whose index, after the
  object's name: `ifIndex 12`) names what the alert is about, one alert per
  rule, host and instance. Blank, or a trap without that varbind: one alert
  per device.
- **Clearing traps** (optional), with their own conditions: a matching
  trap resolves the open alert of the same host and instance.
- **Severity, threshold, auto-resolve, enabled**: as for a custom syslog
  rule ([syslog-rules.md](syslog-rules.md#custom-rules)).

A custom rule is evaluated next to the built-in rules, by the same engine:
its alert has type `trap`, metric `trap_custom_<id>` and the key
`trap:custom_<id>:<host>:<instance>`, so suppressions by host, group or
that metric apply, and the alert is scoped to the host's inventory group
like every monitoring alert. Disabling or deleting a custom rule resolves
its open alerts. A custom rule neither starts a re-poll nor changes the
severity a trap is stored with (the built-in rules do).

The **Test Trap** box of the editor takes a trap OID and its varbinds (one
per line, `OID = value`) and shows the trap's name and named varbinds,
what the draft rule and every other trap rule would do, the triggers it
starts and, for a `clogMessageGenerated` trap, its syslog line and what
the syslog rules do with it. The API also takes a stored trap
(`event_id`, an SNMPv1 or v2c trap of at most 1000 bytes: the stored row
keeps that much of the datagram).

## Cisco syslog messages sent as traps

A Cisco device with `snmp-server enable traps syslog` sends each syslog
message (at or above the `logging history` severity) as a CISCO-SYSLOG-MIB
`clogMessageGenerated` trap, with `clogHistFacility`, `clogHistSeverity`,
`clogHistMsgName` and `clogHistMsgText`. For a believed trap (the same
condition as for the trap rules), Plexus builds the syslog line it carries,
`%FACILITY-SEVERITY-MNEMONIC: text` (`clogHistSeverity` emergency(1) to
debug(8) as the syslog digit 0 to 7), and runs it through the syslog rules
and triggers: the built-in and custom syslog rules, the configuration
change trigger and the re-poll trigger
([syslog-rules.md](syslog-rules.md#cisco-syslog-messages-sent-as-snmp-traps)).
A trap whose facility or mnemonic does not make a tag is left alone.

The alerts it raises are syslog alerts (type `syslog`, metric
`syslog_<rule>`, the syslog dedup key), so a device that sends the same
message as syslog and as a trap meets one alert, not two. It follows the
syslog switches (**Raise alerts from syslog rules**, the re-poll and
configuration triggers), not **Raise alerts from SNMP trap rules**: turning
trap alerts off does not stop it. The syslog transport switch (**Act on UDP
messages**) does not apply: the trap was believed by its community or
SNMPv3 user. How the threshold counters count a message that arrives both
ways is in [syslog-rules.md](syslog-rules.md#cisco-syslog-messages-sent-as-snmp-traps).

## Restart

The threshold counters (the authentication failure rule, and any custom
rule with a threshold above one) live in memory. At startup, the process
whose trap receiver listens rebuilds them from the stored traps of the
longest enabled threshold window (at most 1 hour, the newest 20,000
traps), each counted at its age, as the syslog counters are rebuilt; the
syslog line of a stored `clogMessageGenerated` trap is counted for the
syslog threshold rules too. Nothing is raised, resolved or re-polled.

The stored event does not record whether a trap was believed (a v1 / v2c
trap with the wrong community is never stored, but an undecodable one and
an SNMPv3 one are), so each stored trap is decoded again from the bytes the
row keeps and counted only when it carries the community stored for its
host now. An SNMPv3 trap (its keys are not kept with it, and its time
window has passed), an APC trap, a trap larger than 1000 bytes and a trap
whose community no longer matches are not counted.

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

- **Raise alerts from SNMP trap rules** (`trap_alerts`): the alerts of the
  built-in and custom trap rules.
- **Back up the config on a change message** (`config_change_trigger`) and
  **Re-poll on link down, module down or reload** (`repoll_trigger`):
  shared with syslog.
- **Raise alerts from syslog rules** (`syslog_alerts`): the syslog alerts
  of a `clogMessageGenerated` trap.

Each is on by default; turning one off stops that behaviour only, and
traps are still stored.

The API (all under `/api/monitoring/trap-rules`; reads need
**monitoring**, every POST, PUT, PATCH and DELETE **monitoring.write**):

- `GET` lists the built-in then the custom rules in the syslog rules'
  shape (`source` `trap`; a built-in rule's `tags` and `clear_tags` are
  the trap names; a custom rule has `match_type` `trap`, `pattern` and
  `clear_pattern` its traps and `trap_match` its `conditions`,
  `clear_conditions` and `instance`).
- `PATCH /builtin/{key}` (`enabled`, `severity`) overrides a built-in
  rule, stored with the syslog rules' overrides under `trap_<key>` (audit
  `trap_rule.builtin_updated`).
- `POST` creates a custom rule, `PUT /{id}` updates one (the fields left
  out keep their value), `DELETE /{id}` deletes one (audit
  `trap_rule.created`, `.updated`, `.deleted`; an invalid rule answers
  400 with the reason). A syslog rule's id is not found here, and the
  reverse.
- `POST /test` (`event_id`, or `trap_oid` and `varbinds` as
  `[[oid, value], ...]`, and optionally `rule`, an unsaved custom rule)
  explains what the rules would do. A stored trap is read only from a host
  the caller can see.

A user limited to selected inventory groups can read the rules but not
change them.

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
  RMON-MIB `risingAlarm`, `fallingAlarm`; POWER-ETHERNET-MIB
  `pethPsePortOnOffNotification`; ISIS-MIB `isisAdjacencyChange`.
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
  `clogMessageGenerated`; CISCO-HSRP-MIB `cHsrpStateChange`;
  CISCO-IPSEC-FLOW-MONITOR-MIB `cikeTunnelStart`, `cikeTunnelStop`;
  CISCO-ERR-DISABLE-MIB `cErrDisableInterfaceEvent`,
  `cErrDisableInterfaceEventRev1`; CISCO-PORT-SECURITY-MIB
  `cpsSecureMacAddrViolation`, `cpsTrunkSecureMacAddrViolation`,
  `cpsIfVlanSecureMacAddrViolation`; CISCO-MAC-NOTIFICATION-MIB
  `cmnMacMoveNotification`; CISCO-EIGRP-MIB `cEigrpNbrDownEvent`;
  CISCO-IETF-ISIS-MIB `ciiAdjacencyChange`; CISCO-RTTMON-MIB
  `rttMonNotification`.
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
2787 is named from the same file. The MIBs of the event rule packs
(CISCO-HSRP-MIB, CISCO-IPSEC-FLOW-MONITOR-MIB, CISCO-ERR-DISABLE-MIB,
CISCO-PORT-SECURITY-MIB, CISCO-MAC-NOTIFICATION-MIB, CISCO-EIGRP-MIB,
CISCO-IETF-ISIS-MIB, CISCO-RTTMON-MIB, POWER-ETHERNET-MIB and ISIS-MIB)
were read from Cisco's own MIB repository (`github.com/cisco/cisco-mibs`,
`v2/`), their OIDs resolved from the MIB texts.

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
- **SNMPv3 informs** are answered only for inventory hosts; a retransmitted
  inform (a new message with the same request id, sent when the Response
  was lost or late) is stored and acted on again. Informs, discovery and
  the time-window Report have been checked against pysnmp as the sender,
  not against a live device.
- **SNMPv3 replay record**: an exact copy of a trap from the last 150
  seconds before a restart is accepted once more after it, and a crash
  loses up to a minute of the record (see [SNMPv3](#snmpv3)). SNMPv3 traps
  have not been checked against a live device.
- **Cisco ASA / FTD failover**: CISCO-FIREWALL-MIB has no failover
  notification, and no other Cisco MIB with one was retrieved; ASA failover
  reaches Plexus as syslog, and the poll reads the failover state of the
  pair ([monitoring.md](monitoring.md#ha-and-redundancy-state)).
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
- **Cisco `clogMessageGenerated`**: the syslog line is built from the
  CISCO-SYSLOG-MIB varbind definitions, not from a live device's traps. A
  message that reaches Plexus both as syslog and as a trap more than 5
  seconds apart counts twice towards a syslog threshold rule (see
  [syslog-rules.md](syslog-rules.md#cisco-syslog-messages-sent-as-snmp-traps)).
- **Restart**: an SNMPv3 trap is not counted when the threshold counters
  are rebuilt (see [Restart](#restart)).
- **Custom rules** start no re-poll and do not change the severity a trap is
  stored with.
- **Event rule packs**:
  - `newRoot` is sent by the bridge that became the root, not by the
    others, and BRIDGE-MIB traps name no VLAN or instance: both spanning
    tree rules are per device (Netgear's per-instance traps name the MST
    instance).
  - CISCO-HSRP-MIB `cHsrpStateChange` carries the new state only, so a
    router leaving standby for speak raises the alert as well as one
    leaving active.
  - CISCO-EIGRP-MIB has no neighbor up notification: the EIGRP alert
    resolves after 24 hours (the syslog rule resolves on the up message).
  - CISCO-IPSEC-FLOW-MONITOR-MIB `cipSecTunnelStart` / `Stop` (IPsec SAs)
    are not named: an SA stops and a new one starts with a new index at
    every rekey, so they would open an alert per rekey; the IKE tunnel
    traps are used. `cikeSysFailure`, `cikeProtocolFailure` and the other
    failure traps are not named.
  - IP SLA: only the reachability reactions (timeout, connection loss,
    verify error) of `rttMonNotification` raise; round trip time, jitter,
    loss and MOS thresholds are stored without a rule. `rttMonNotificationV2`
    and the older `rttMonConnectionChangeNotification` /
    `rttMonTimeoutNotification` are not named.
  - PoE: POWER-ETHERNET-MIB names the port by its PSE group and port index,
    not its ifIndex.
  - No trap rule for optics (the CISCO-ENTITY-SENSOR-MIB threshold traps
    name no sensor type), AAA servers, NTP, licenses, certificates or
    crashes: no notification for them was confirmed in the MIBs retrieved
    (`CISCO-NTP-MIB`, `CISCO-SMART-LIC-MIB` and the AAA server MIBs were
    not searched). Those events reach Plexus as syslog
    ([syslog-rules.md](syslog-rules.md#event-rule-packs)) or as
    `clogMessageGenerated` traps.
  - Juniper, Arista, HPE Aruba and PAN-OS traps for layer 2 events, IS-IS,
    VPN tunnels and PoE beyond the standard MIBs above are not named
    (their vendor MIBs were not searched for them). FortiOS
    `fgTrapVpnTunUp` / `Down` are the only non-Cisco VPN traps with a rule.
