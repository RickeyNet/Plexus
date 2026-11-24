# Syslog Rules

Plexus's syslog receiver stores every message it receives (Monitoring >
Events). For a message whose source is an inventory host, the server also
acts on it:

- **Alerts**: the message is matched against the syslog alert rules (the
  built-in rules below and your own) and raises or resolves a monitoring
  alert, with notifications through the alert notification channels.
- **Configuration change**: a message that says the device's configuration
  changed (`%SYS-5-CONFIG_I` and its equivalents) starts a configuration
  backup and drift check of that host, instead of waiting for the backup
  schedule.
- **Faster down detection**: an interface-down, module down or back
  online, reload, restart, temperature or HA switchover message starts a
  monitoring poll of that host
  within seconds, instead of waiting for the next poll.

An OPNsense firewall's messages also act when it is no inventory host: a
gateway alarm, CARP transition, VPN tunnel up / down or configuration save
starts a collection of the firewall's topology source within seconds (see
[OPNsense re-collect trigger](#opnsense-re-collect-trigger)).

The rules are set up under **Monitoring > Configure > Syslog Rules**. The
same engine runs the SNMP trap rules (built-in and custom), listed in that
tab below the syslog rules, as their own alert family: see
[SNMP Traps](snmp-traps.md). A Cisco syslog message sent as an SNMP trap
goes through the syslog rules too (see
[below](#cisco-syslog-messages-sent-as-snmp-traps)).

## How a message becomes an alert

1. **Source**: the message's source address is looked up among the
   inventory hosts' addresses and their recorded interface addresses (a
   device often sends syslog from an interface other than its primary
   address). By default a message from an address that is not in the
   inventory is dropped by the receiver's source allowlist; one admitted
   through its extra networks or the `any` policy
   ([administration.md](administration.md#listener-sources)) is stored and
   nothing more.
2. **Tag**: Plexus reads the message's event tag: the Cisco-style
   `%FACILITY-SEVERITY-MNEMONIC` (IOS, IOS XE, IOS XR, NX-OS, ASA, Arista
   EOS), compared without its severity digit (`%LINK-3-UPDOWN` is
   `LINK-UPDOWN`), or the Junos tag (`SNMP_TRAP_LINK_DOWN`). RFC 3164 and
   RFC 5424 headers, sequence numbers and timestamps before the tag are
   skipped. Vendors without such a tag get one from their own format:

   | Vendor | Tag | Example | Text the built-in patterns test |
   |---|---|---|---|
   | Fortinet FortiOS (key=value) | `FGT-<logid>` | `FGT-0100032002` | The `msg` value (else the line from `logid=` on); the tag shown is the `logdesc` |
   | Palo Alto PAN-OS SYSTEM log (default CSV format) | `PAN-SYSTEM-<EVENT ID>` | `PAN-SYSTEM-AUTH-FAIL` | The Description field |
   | Palo Alto PAN-OS CONFIG log | `PAN-CONFIG` | `PAN-CONFIG` | The line from the Command field on (`commit,ops,Web,Succeeded,...`) |
   | Palo Alto PAN-OS, other log types | `PAN-<TYPE>` | `PAN-TRAFFIC`, `PAN-THREAT` | The line from the Subtype field on |
   | HPE Aruba AOS-CX (`Event\|<id>\|<severity>\|...`) | `AOSCX-<event id>` | `AOSCX-404` | The text after the fifth `\|` |
   | HPE Aruba AOS-Switch / ProCurve (`<event id> <facility>: ...`) | `AOSS-<event id>`, five digits as written | `AOSS-00077` | The text after the facility (the facility is also the program) |

   A custom **Tag** rule takes these tags too. A PAN-OS firewall must send
   the default log format (a custom format has no fixed field positions).
   Plexus also reads the message's *program*: the RFC 5424
   APP-NAME or the RFC 3164 `program[pid]:` (`dpinger`, `charon`,
   `audit`, `sshd`). Messages without a tag, OPNsense's among them, are
   matched by their program and the text after it.
3. **Match**: each enabled rule is checked. A rule that matches names an
   *instance* when it can (the interface or the neighbor in the message).
4. **Threshold**: a rule with a threshold raises only when that many
   matches for the same host and instance arrive within its window. Two
   matches less than 5 seconds apart count once (a link going down logs
   both `LINK-3-UPDOWN` and `LINEPROTO-5-UPDOWN`).
5. **Alert**: the alert has type `syslog`, metric `syslog_<rule key>` and
   one alert key per rule, host and instance, so a repeat bumps the
   occurrence count of the open alert instead of opening a new one. Its
   message names the rule, the instance and the message that raised it. A
   suppression for the host, its group or the metric (Monitoring >
   Configure > Suppressions lists the built-in metrics) applies.
6. **Resolve**: a message that matches the rule's clear pattern resolves
   the alert of the same host and instance. A UDP source address can be
   forged, so a syslog message resolves only an alert that syslog raised
   (type `syslog`) for the host it came from: an alert raised by polling
   stays until polling clears it. A rule with an auto-resolve
   time also resolves its alerts once no new match has arrived for that
   long (checked every minute).

Alerts are raised only while monitoring is on (Monitoring > Settings).

## Built-in rules

Built-in rules ship with Plexus. You can turn each one off or change its
severity; the patterns, threshold and auto-resolve time are fixed.

| Rule (metric) | Raised by | Resolved by | Threshold | Auto-resolve | Severity | Device families |
|---|---|---|---|---|---|---|
| Interface flapping (`syslog_link_flap`) | An interface going down: `LINK-3-UPDOWN` and `LINEPROTO-5-UPDOWN` ... `changed state to down`, IOS XR `PKT_INFRA-LINK-3-UPDOWN` / `PKT_INFRA-LINEPROTO-5-UPDOWN`, ASA and FTD `411002`, NX-OS `ETHPORT-5-IF_DOWN_LINK_FAILURE` / `IF_DOWN_ERROR_DISABLED` / `IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN`, Junos `SNMP_TRAP_LINK_DOWN` with `ifAdminStatus up`, FortiOS `FGT-0100020099` (Interface status changed) `Interface <name> was turned down`, PAN-OS `link-change` `<port>: Down ...`, AOS-CX `AOSCX-404` `Link status for interface <name> is down`, AOS-Switch `AOSS-00077` `port <name> is now off-line` | Time only | 3 within 10 min, per interface | 30 min | warning | Cisco IOS / IOS XE, IOS XR, NX-OS, ASA, FTD, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| OSPF neighbor down (`syslog_ospf_neighbor`) | `OSPF-5-ADJCHG` / `OSPFv3-5-ADJCHG` / IOS XR `ROUTING-OSPF-5-ADJCHG` ... `to DOWN`, NX-OS `OSPF-5-NBRSTATE` ... `to DOWN` and `OSPF-5-ADJCHANGE` ... `went DOWN`, EOS `OSPF-4-OSPF_ADJACENCY_TEARDOWN`, Junos `RPD_OSPF_NBRDOWN`, FortiOS `FGT-0103020302` (OSPF neighbor status changed) `ADJCHANGE: neighbor <if:local-remote> Down`, PAN-OS `routed-OSPF-neighbor-down` (one alert per firewall: the message names no neighbor), AOS-CX `AOSCX-2401` / `AOSCX-2404` `AdjChg: Nbr <router-id> on <interface>...: <state> -> Down`, AOS-Switch `AOSS-02703` `ADJCHG: Neighbor with Router ID <id> on <interface> moved to <state> state - adj lost` | The same tags ... `to FULL` / `went FULL`, EOS `OSPF_ADJACENCY_ESTABLISHED`, Junos `RPD_OSPF_NBRUP`, FortiOS `... neighbor <if:local-remote> Up`, PAN-OS `routed-OSPF-neighbor-full`, AOS-CX `... -> Full`, AOS-Switch `... - adj formed` | Every match, per neighbor | Clear message only | critical | Cisco IOS / IOS XE, IOS XR, NX-OS, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| BGP neighbor down (`syslog_bgp_neighbor`) | `BGP-5-ADJCHANGE` / IOS XR `ROUTING-BGP-5-ADJCHANGE` / FortiOS `FGT-0103020300` (BGP neighbor status changed) `neighbor X Down`, `BGP-5-NBR_RESET`, EOS `BGP-5-ADJCHANGE` `old state Established ... new state` other than Established, Junos `RPD_BGP_NEIGHBOR_STATE_CHANGED` `from Established to` another state, PAN-OS `routed-BGP-peer-left-established`, AOS-CX `AOSCX-2902` `<peer>: Peer down. ...`, AOS-Switch `AOSS-03073` `BGP: Peer down` (one alert per switch: the message names no peer) | `neighbor X Up`, EOS `new state Established`, Junos `to Established`, PAN-OS `routed-BGP-peer-enter-established`, AOS-CX `AOSCX-2901` `<peer>: Peer up. ...`, AOS-Switch `AOSS-03072` `BGP: Peer up` | Every match, per neighbor | Clear message only | critical | Cisco IOS / IOS XE, IOS XR, NX-OS, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| Power supply fault (`syslog_power_supply`) | IOS XE `IOSXE_PEM-3-PEMFAIL`, Catalyst 9000 `PLATFORM_FEP-1-FRU_PS_SIGNAL_FAULTY`, Catalyst 3750-X / 3560-X `PLATFORM_ENV-1-FRU_PS_SIGNAL_FAULTY`, NX-OS `PLATFORM-2-PS_FAIL`, EOS `PWRMGMT-3-PSU_STATUS_FAILED` and `PWRMGMT-4-INPUT_POWER_LOSS`, Junos `CHASSISD_SNMP_TRAP*` `Power Supply failed`, FortiOS `FGT-0100022105` (Power supply failed) and `FGT-0100022114` (Power supply failed warning), PAN-OS `ps-failure` `Alarm on Power Supply #<n>`, AOS-CX `AOSCX-304` `PSU <name> faulted`, AOS-Switch `AOSS-00071` `Power Supply failure: Supply: <Main or RPS>- ...` and `AOSS-02797` `Internal power supply <bay> is faulted`, IOS XR `PLATFORM-PWR_MGMT-2-MODULE_FAILURE` / `PLATFORM-PWRMON-2-MODULE_FAILURE` `Power-module <name> failure condition ...` and `PLATFORM-ENVMON-2-POWERSUPPLY_NONOP` `<name> is Non-Operational`, ASA and FTD `735004` `Power Supply <n>: Failure Detected` and `735006` `Power Supply Unit Redundancy Lost` | `IOSXE_PEM-6-PEMOK`, `PLATFORM_FEP-6-FRU_PS_SIGNAL_OK`, `PLATFORM-2-PS_OK`, EOS `PWRMGMT-3-PSU_STATUS_OK`, Junos `Power Supply OK`, FortiOS `FGT-0100022104` (Power supply restored) and `FGT-0100022115` (Power supply restored notification), AOS-Switch `Power Supply OK: ...` and `Internal power supply <bay> is ok`, IOS XR `PLATFORM-ENVMON-6-POWERSUPPLY_NONOP_CLEAR` `<name> has become operational`, ASA and FTD `735003` `Power Supply <n>: OK` and `735005` `Power Supply Unit Redundancy OK`; PAN-OS, AOS-CX and the IOS XR `Power-module` forms by time only | Every match, per power supply (FortiOS and 3750-X: per device) | 24 h | critical | Cisco IOS XE (ASR 1000, ISR 4000, Catalyst 9000), Catalyst 3750-X / 3560-X, NX-OS, IOS XR, ASA, FTD, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| Fan fault (`syslog_fan`) | IOS XE `IOSXE_PEM-3-FANFAIL`, Catalyst 2960 / 3560 / 3750 `HARDWARE-2-FAN_ERROR`, Catalyst 3750-X / 3560-X `PLATFORM_ENV-1-FAN` and `PLATFORM_ENV-1-FRU_PS_FAN_FAILED`, ISR G2 `ENVMON-3-FAN_FAIL` (older ISRs `FAN_FAILED`), NX-OS `PLATFORM-2-FANMOD_FAN_FAIL`, EOS `ENVMON-3-FANFAILED`, Junos `CHASSISD_SNMP_TRAP*` `Fan/Blower failed`, PAN-OS `fan-failure` `Alarm on Fan Tray #<n>`, FortiOS `FGT-0100022108` (Fan anomaly), AOS-CX `AOSCX-214` `...: Fan <name> faulted, reason: ...`, AOS-Switch `AOSS-00070` `Fan failure: Fan: <n> ...`, IOS XR `PLATFORM-ENVMON-2-FAN_FAIL` `Fan failure on slot <slot>, fan <n>, RPM <rpm>` and `PLATFORM-ENVMON-2-FANTRAY_FAIL` `Fan tray failure on slot <slot>`, Catalyst 9000 `PLATFORM_THERMAL-1-FRU_FAN_FAILURE` `Switch <n>: System fan <n> failed`, ASA and FTD `735002` `Cooling Fan <n>: Failure Detected` and `735012` `Power Supply <n>: Fan Failure Detected` | `IOSXE_PEM-6-FANOK`, ISR G2 `ENVMON-3-FAN_OK`, `PLATFORM-2-FANMOD_FAN_OK`, EOS `ENVMON-3-FANOK`, Junos `Fan/Blower OK`, FortiOS `FGT-0100022151` (Fan normal), AOS-Switch `Fan OK: Fan: <n> ...`, IOS XR `PLATFORM-ENVMON-2-FAN_CLEAR` / `FANTRAY_CLEAR` `Fan [tray ]failure cleared on slot ...`, Catalyst 9000 `PLATFORM_THERMAL-6-FRU_FAN_RECOVERY` `Switch <n>: System fan <n> recovered to normal status`, ASA and FTD `735001` `Cooling Fan <n>: OK` and `735011` `Power Supply <n>: Fan OK`; the classic Catalyst, PAN-OS and AOS-CX forms by time only | Every match, per fan (FortiOS: per device; IOS XR `<slot>/<fan>` or the fan tray's slot; Catalyst 9000 `<switch>/<fan>`; ASA `Cooling Fan <n>` or the power supply whose fan it is) | 24 h | warning | Cisco IOS XE (ASR 1000, ISR 4000, Catalyst 9000), Catalyst 2960 / 3560 / 3750 (classic IOS), ISR G2, NX-OS, IOS XR, ASA, FTD, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| Module down (`syslog_module`) | IOS XE `IOSXE_OIR-6-OFFLINECARD` `Card (<type>) offline in slot <slot>` and `IOSXE_OIR-6-REMCARD` `Card (<type>) removed from [chassis <n> ]slot <slot>`, SPAs and line card sub-modules `IOSXE_OIR-6-REMSPA` `SPA removed from subslot <s/b>, interfaces disabled`, `SPA_OIR-6-OFFLINECARD` `SPA (<type>) offline in subslot <s/b>` and `SPA_OIR-6-REMCARD` `Card removed from subslot <s/b>, interfaces disabled`, Catalyst 3750 / 2975 stack `STACKMGR-4-SWITCH_REMOVED` `Switch <n> has been REMOVED from the stack`, Catalyst 6500 `C6KPWR-SP-4-DISABLED` `power to module in slot <n> set off (<reason>)`, NX-OS `MODULE-2-MOD_FAIL`, `MODULE-2-MOD_FAILURE`, `MODULE-2-MOD_NOT_ALIVE`, `PLATFORM-2-MOD_REMOVE`, `PLATFORM-2-MOD_PWRDN`, `PLATFORM-2-MOD_PWRFAIL`, `PLATFORM-3-MOD_PWRFAIL_MULTI`, `PLATFORM-2-MOD_PWRDENY`, `PLATFORM-3-MOD_BRINGUP_MULTI_LIMIT` and, for fabric modules, `PLATFORM-2-XBAR_REMOVE`, `PLATFORM-5-XBAR_PWRDN`, `PLATFORM-3-XBAR_PWRFAIL`, Junos `CHASSISD_SNMP_TRAP*` `FRU removal` / `FRU power off` / `FRU failed` / `FRU offline` of an FPC, PIC, routing engine, control board, SIB, SFM, FEB, switch fabric board, line card chassis or adapter card (not when `jnxFruOfflineReason` is 5, 7 or 8: powered off in the configuration, by a CLI command or the offline button), Catalyst 4500 `C4K_IOSMODPORTMAN-6-MODULEREMOVED` `Module <n> is removed`, `MODULEOFFLINE` `Module <n> is offline`, `C4K_CHASSIS-3-MODULEBRINGUPTIMEDOUT` and `INSUFFICIENTPOWERSHUTDOWN` `Holding module in slot <n> in reset, ...`, IOS XR `PLATFORM-INVMGR-5-OIROUT` / `PLATFORM-OIRD-5-OIROUT` `OIR: Node <node> removed`, `PLATFORM-SHELFMGR-3-NODE_RESET_BRINGDOWN`, `SHUTDOWN`, `FAILED_LOAD`, `INRESET_BRINGDOWN` and `SHUTDOWN_ON_ENVMON_ALARM` (`... node <node> ...`), EOS `HARDWARE-3-CARD_LOST_POWER`, `CARD_LOST_COMMUNICATION`, `CARD_FAIL_TO_POWER_ON` / `_FINAL`, `FRU-6-CARD_REMOVED` and `FRU-3-CARD_FAILURE`, FortiOS `FGT-0100022111` (FPC down due to PSU action), AOS-CX `AOSCX-3202` `<type> module <name> removed`, `AOSCX-3207` `<type> module <name> has failed: <reason>` and VSF `AOSCX-9913` `Lost member <id> with <reason>`, AOS-Switch `AOSS-00402` `Stack member <id> lost.` | IOS XE `IOSXE_OIR-6-ONLINECARD` and `SPA_OIR-6-ONLINECARD` `... online in [chassis <n> ]slot / subslot ...`, stack `STACKMGR-5-SWITCH_READY` `Switch <n> is READY`, NX-OS `MODULE-5-MOD_OK` `Module <n> is online`, `MODULE-5-ACTIVE_SUP_OK` / `STANDBY_SUP_OK` `Supervisor <n> is active / standby`, `MODULE-5-XBAR_OK` `Xbar <n> is online`, Junos `FRU online`, Catalyst 4500 `C4K_IOSMODPORTMAN-6-MODULEONLINE` `Module <n> (...) is online`, EOS `HARDWARE-6-CARD_POWERED_ON` `Card <name> has been powered on. ...`, FortiOS `FGT-0100022112` (FPC up due to PSU action); the Catalyst 6500, IOS XR, AOS-CX and AOS-Switch forms by time only | Every match, per slot / subslot (IOS XE `<chassis>/<slot>` on StackWise Virtual), stack member, NX-OS module or `Xbar <n>`, Junos `jnxFruName`, Catalyst 4500 module, IOS XR node, EOS card, AOS-CX module or VSF member (FortiOS: per chassis) | 24 h | critical | Cisco IOS XE (Catalyst 9400 / 9600, StackWise Virtual, ASR 1000, ISR 4000), Catalyst 3750 / 2975 stacks (classic IOS), Catalyst 6500 and 4500, NX-OS, IOS XR, Arista EOS, Juniper Junos, Fortinet FortiOS (FortiGate 6000 / 7000), HPE Aruba AOS-CX, AOS-Switch |
| Temperature alarm (`syslog_temperature`) | IOS XE `ENVIRONMENTAL-1-ALERT` `Temp: <sensor>, Location: <slot>, State: <state>, Reading: ...` (the same mnemonic's voltage and fan sensors are not counted) and `... PVT temperature sensor on Asic: <n> ...`, `IOSXE_PEM-3-TEMPERATURE_RAISE`, Catalyst 9000 `PLATFORM_THERMAL-3-OVERTEMP`, `-4-SECONDARY_OVERTEMP`, `-2-OVERTEMP_SHUTDOWN`, `-3-UNDERTEMP`, `-2-UNDERTEMP_SHUTDOWN` `Switch <n>: ...`, classic Catalyst `HARDWARE-2-THERMAL_WARNING`, `HARDWARE-1-THERMAL_CRITICAL`, `HARDWARE-2/1-PSU_THERMAL_WARNING / CRITICAL`, `PLATFORM_ENV-1-TEMP`, `PLATFORM_ENV-2-THERMAL_WARNING`, `PLATFORM_ENV-1-THERMAL_CRITICAL`, `ENVMON` `CPU_WARNING_OVERTEMP`, `CPU_CRITICAL_OVERTEMP`, `IN_OUTLET_OVERTEMP`, `INTAKE_ABNORMTEMP`, `ONBOARD_OVERTEMP`, `MODULE_OVERTEMP`, `POWER_OVERTEMP` `Warning: <sensor> temperature <n>C exceeds ...`, Catalyst 4500 `C4K_IOSMODPORTMAN-4-TEMPHIGH`, `-2-CRITICALTEMP`, `MODULETEMPHIGH`, `MODULECRITICALTEMP`, `MODULESHUTDOWNTEMP` and `C4K_CHASSIS-2-OVERHEATINGSHUTDOWN`, NX-OS `PLATFORM-2-MOD_TEMPMAJALRM`, `MOD_TEMPMINALRM`, `PLATFORM-0-MOD_TEMPWARMALRM`, `PLATFORM-2-MOD_TEMPSHUTDOWN` and `PLATFORM-0-SYS_SHUTDOWN` `... due to major temperature alarm`, IOS XR `PLATFORM-ENVMON-2-CHASSIS_OVERTEMP`, `-2-CARD_OVERTEMP` and their `_SHUTDOWN` forms, ASA and FTD `735007`, `735008`, `735015`, `735016`, `735018`, `735019` `<sensor>: Temp: <n> C, Critical / Warm` and the thermal shutdowns `735022`, `735024`, `735027`, `735029`, EOS `ENVMON-0-CARDOVERHEATWARNING`, `CARDOVERHEATSHUTDOWN`, `POWERSUPPLY_OVERHEAT_WARNING` / `_CRITICAL`, `SYSTEMOVERHEATWARNING`, `SYSTEMOVERHEATSHUTDOWN`, Junos `CHASSISD_OVER_TEMP_CONDITION`, `CHASSISD_OVER_TEMP_SHUTDOWN_TIME`, `CHASSISD_HIGH_TEMP_CONDITION`, `CHASSISD_CHASSIS_FIRE_TEMP`, `CHASSISD_TEMP_HOT_NOTICE`, `CHASSISD_FRU_HIGH_TEMP_CONDITION`, `CHASSISD_FRU_OVER_TEMP_CONDITION`, `CHASSISD_FRU_SENSOR_TEMP_WARNING`, `CHASSISD_RE_WARM_TEMP_CONDITION`, `CHASSISD_RE_OVER_TEMP_*` and `CHASSISD_SNMP_TRAP*` `Over Temperature`, FortiOS `FGT-0100022109` (Temperature too high) and `FGT-0100022152` (Temperature too low), AOS-CX `AOSCX-803` `Over-temperature for sensor <name>, <n> degC`, AOS-Switch `AOSS-00424` `Over-temperature detected` | IOS XE `ENVIRONMENTAL-5-SENSOROK` `Temp: ... State: normal`, `PLATFORM_THERMAL-6-TEMP_NORMAL`, `HARDWARE-5-THERMAL_NORMAL`, `HARDWARE-5-PSU_THERMAL_NORMAL`, `ENVMON-6-CPU_TEMP_OK`, `IN_OUTLET_TEMP_OK`, `ONBOARD_TEMP_OK`, `MODULE_TEMP_OK`, `POWER_TEMP_OK` `<sensor> temperature normal`, Catalyst 4500 `TEMPOK`, `MODULETEMPOK`, `C4K_CHASSIS-4-OVERHEATINGOVER`, NX-OS `PLATFORM-2-MOD_TEMPOK` / `MOD_TEMPMAJOR_OK` (not `MOD_TEMPRECOVER`: a minor alarm is still pending), IOS XR `CHASSIS_OVERTEMP_CLEAR` / `CARD_OVERTEMP_CLEAR`, ASA and FTD `735017`, `735020`, `735021`, `735026` `<sensor>: Temp: <n> C, OK`, EOS `ENVMON-0-CARDTEMPNORMAL`, `POWERSUPPLY_TEMP_NORMAL`, `SYSTEMTEMPNORMAL`, Junos `CHASSISD_SNMP_TRAP*` `Temperature back to normal`, FortiOS `FGT-0100022153` (Temperature normal); the other Junos forms, AOS-CX and AOS-Switch by time only | Every match, per sensor (IOS XE `<sensor>/<slot>`, Catalyst 9000 switch, NX-OS `<module>/<sensor>`, IOS XR slot, ASA `CPU <n>` / `Chassis Ambient <n>` / ..., EOS card or power supply, Junos FRU or Routing Engine, AOS-CX sensor; FortiOS, classic Catalyst and AOS-Switch: per device) | 24 h | critical | Cisco IOS XE (ASR 1000, ISR 4000, Catalyst 9000), Catalyst 2960 / 3560 / 3750 (classic IOS), Catalyst 4500, NX-OS, IOS XR, ASA, FTD, Arista EOS, Juniper Junos, Fortinet FortiOS, HPE Aruba AOS-CX, AOS-Switch |
| HA failover or switchover (`syslog_ha_switchover`) | IOS XE `REDUNDANCY-3-SWITCHOVER` `RP switchover <reason>` and `REDUNDANCY-3-STANDBY_LOST`, Catalyst 4500 `C4K_REDUNDANCY-6-SWITCHOVER`, Catalyst 3750 stack `STACKMGR-4-MASTER_ELECTED` `Switch <n> has been elected as MASTER of the stack`, NX-OS `SYSMGR-2-HASWITCHOVER_PRE_START`, `HASWITCHOVER_START`, `WARMSWITCHOVER_START`, `SWITCHOVER_OVER`, `SWITCHOVER_THRESHOLD_EXCEEDED`, `STANDBY_BOOT_FAILED`, `REDUNDANCY_HEARTBEAT_FAILURE`, IOS XR `HA-REDCON-6-GO_ACTIVE`, `HA-REDCON-6-STANDBY_CONNECTION_DOWN`, `PLATFORM-REDDRV-5-GO_ACTIVE` and `PLATFORM-REDDRV-7-ROLE_CHANGE` `... role change to ACTIVE ...`, ASA and FTD failover `104001` `Switching to ACTIVE`, `104002` `Switching to STANDBY`, `104003` `Switching to FAILED`, `104500` / `104501` (cloud HA), `103001` `No response from other firewall`, `103004` `Other firewall reports this firewall failed`, `105005` `Lost Failover communications with mate on interface ...`, `105011` `Failover cable communication failure`, `105032` `LAN Failover interface is down`, `105043` `Failover interface failed`, `105037` `Both units are switching back and forth ...`, EOS `REDUNDANCY-5-SWITCHOVER_START`, `SWITCHOVER_COMPLETE`, `REDUNDANCY-2-IS_DISABLED`, `OTHER_DISABLED` and MLAG `STATE_INACTIVE_CONNECTION_CLOSED`, `STATE_INACTIVE_HEARTBEAT_TIMEOUT`, `STATE_INACTIVE_LOCAL_INTERFACE_DOWN`, `STATE_PRIMARY_PEER_LINK_DOWN`, `PEER_EVENT_HEARTBEAT_TIMEOUT`, Junos `CHASSISD_LOST_MASTERSHIP`, `UI_MASTERSHIP_EVENT`, `JSRPD_RG_STATE_CHANGE` `Redundancy-group <n> transitioned from ...`, `JSRPD_HA_SRG_STATE_CHANGE`, `JSRPD_HA_CONTROL_LINK_DOWN`, `JSRPD_HA_FAB_LINK_DOWN`, `JSRPD_SPLIT_BRAIN`, FortiOS `FGT-0108037892` (Virtual cluster member state moved), `FGT-0108037893` (member dead), `FGT-0108037898` (HA device interface failed), `FGT-0108037901` (Heartbeat device interface down), `FGT-0108035013` (HA failover failed), `FGT-0108035016` (HA failover success), PAN-OS `state-change` `HA Group <n>: Moved from state <x> to state <y>`, AOS-CX `AOSCX-7001` `VSX ISL port <port> is down` and `AOSCX-7005` `VSX Keepalive failed`, AOS-Switch `AOSS-03278` `Member <id> elected as commander. ...` | EOS MLAG `STATE_PRIMARY`, `STATE_SECONDARY` `MLAG is active as ...`, `STATE_PRIMARY_PEER_LINK_UP`, Junos `JSRPD_HA_CONTROL_LINK_UP`, `JSRPD_HA_FAB_LINK_UP`; the others by time only | Every match, per device (EOS `MLAG`, Junos redundancy group, SRG, `control link` / `fabric link`, PAN-OS `HA Group <n>`, AOS-CX `VSX ISL` / `VSX Keepalive`, classic stack switch number) | 60 min | warning | Cisco IOS XE, Catalyst 3750 stacks, NX-OS, IOS XR, ASA, FTD, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| Device restarted (`syslog_device_restart`) | The reload and restart messages of the [re-poll trigger](#re-poll-trigger): a device announcing a reload or shutdown and a device back up | Time only | Every match, per device | 60 min | warning | Cisco IOS / IOS XE, IOS XR, NX-OS, ASA, FTD, Arista EOS, Juniper Junos, Fortinet FortiOS, HPE Aruba AOS-CX, AOS-Switch |
| Repeated login failures (`syslog_auth_failure`) | `SEC_LOGIN-4-LOGIN_FAILED`, IOS XR `SECURITY-LOGIN-4-AUTHEN_FAILED`, NX-OS `AUTHPRIV-3-SYSTEM_MSG` with `Authentication failed`, ASA `113005`, `113015`, `605004`, `611102` (FTD the same but `605004`, which its guide does not list), Junos `SSHD_LOGIN_FAILED`, `LOGIN_FAILED`, program `sshd` `Failed password for ...` / `Failed keyboard-interactive/pam for ...` (Arista EOS and other OpenSSH hosts), OPNsense program `audit` `user ... could not authenticate for ...` (web GUI, and SSH through the firewall's authentication), FortiOS `FGT-0100032002` (Admin login failed), PAN-OS `auth-fail` (not the ones about the authentication server: `Time clock does not match ...`, `Wrong realm ...`, `Server certificate: ...`, `KDC Spoofing ...`), AOS-CX `AOSCX-5210` and `AOSCX-5216` (SSH login failed), AOS-Switch `AOSS-00419` (invalid user name / password) and `AOSS-03345` (SSH login failed) | Time only | 5 within 5 min, per device (from any source) | 30 min | warning | Cisco IOS / IOS XE, IOS XR, NX-OS, ASA, FTD, Arista EOS, Juniper Junos, OPNsense, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |

A single interface down is not an alert: access ports go down all day. An
interface an operator shut down (`LINK-5-CHANGED ... administratively
down`, NX-OS `IF_DOWN_ADMIN_DOWN`, Junos `ifAdminStatus down`) is not
counted (except on AOS-Switch, whose disabled ports also log `port ... is
now off-line`; the event log reference gives no other message for them).
OSPF and BGP neighbor alerts are critical because a lost
adjacency changes where traffic goes; they stay open until the neighbor
is back (or someone acknowledges the alert), since a time-out would hide
a neighbor that is still down.

A module down alert is critical: a line card or stack member takes all its
ports with it. A module inserted or booting (`IOSXE_OIR-6-INSCARD`,
`INSSPA`, NX-OS `MOD_DETECT`, `MOD_PWRUP`, stack `SWITCH_ADDED`, Junos `FRU
insertion` / `FRU power on`) raises nothing, nor does a SPA an operator
stops (`IOSXE_OIR-6-SOFT_STOPSPA`) or a Junos FRU taken offline from the
configuration, the CLI or its button. A module usually logs several of the
forms at once (offline, then removed); they are one alert per instance. An
IOS XE line card logs both its slot (`Card (cc) offline in slot 3`) and its
sub-module (`SPA ... offline in subslot 3/0`), so it opens two alerts, and
both resolve when it is back online. The rule resolves after 24 hours
without a new match because the Catalyst 6500 power-off has no recovery
message; the SNMP poll's module check
([Hardware module health](monitoring.md#hardware-module-health), which
the re-poll runs within seconds) keeps reporting a module that is still
down.

The temperature, HA and restart rules are the syslog side of the trap
rules with the same keys (`trap_temperature`, `trap_ha_switchover`,
`trap_device_restart`, see [SNMP Traps](snmp-traps.md#built-in-rules)), with
the same severities and auto-resolve times, so a device that reports the
event by syslog alerts the same way as one that sends the trap. The two
are separate alert families: a suppression of one metric does not cover
the other. A temperature alarm resolves when the same sensor reports
normal again; a form without a documented recovery message resolves
after 24 hours. Most HA messages report an event, not a state, so the HA
alert resolves 60 minutes after the last one; the polled HA state
([monitoring.md](monitoring.md#ha-and-redundancy-state)) reports a pair
that stays degraded. The restart rule raises on every reload and restart
message the re-poll trigger acts on, so a syslog-only device that reboots
faster than the ping down threshold still raises an alert; the re-poll
still runs.

## Event rule packs

Three groups of built-in rules cover layer 2 events, routing and tunnel
neighbors beyond OSPF and BGP, and device health warnings. They are
built-in rules like the ones above (turn each off or change its severity
the same way) and today match Cisco forms only; the other vendors are in
[Known gaps](#known-gaps). The SNMP trap side of the same events is in
[snmp-traps.md](snmp-traps.md#built-in-rules).

| Rule (metric) | Raised by | Resolved by | Instance | Threshold | Auto-resolve | Severity |
|---|---|---|---|---|---|---|
| Spanning tree root changed (`syslog_stp_root_change`) | `SPANTREE-5-ROOTCHANGE` `Root Changed for <vlan n>: ...` | Time only | `vlan <n>` | Every match | 60 min | warning |
| Spanning tree topology changes (`syslog_stp_topology_change`) | `SPANTREE-5-TOPOTRAP` `Topology Change Trap for <vlan n>` | Time only | `vlan <n>` | 5 within 10 min | 30 min | warning |
| Spanning tree guard blocking a port (`syslog_stp_guard`) | `SPANTREE-2-ROOTGUARD_BLOCK`, `LOOPGUARD_BLOCK` `... blocking port <port> on <vlan>`, `BRIDGE_ASSURANCE_BLOCK` | The matching `..._UNBLOCK` | `<port>/<vlan>` (Bridge Assurance: `<port>`) | Every match | 24 h | warning |
| Port error-disabled (`syslog_port_err_disabled`) | `PM-4-ERR_DISABLE` (and `PM-SP-4-ERR_DISABLE`) `<cause> error detected on <port>, putting <port> in err-disable state`, `PM-4-ERR_DISABLE_VP` `... on <port> vlan <n>`: every cause, BPDU guard, UDLD, port security, storm control, link flap and loopback among them | Time only | `<port>` (`<port>/<vlan>`) | Every match | 24 h | warning |
| Port security violation (`syslog_port_security`) | `PORT_SECURITY-2-PSECURE_VIOLATION` `Security violation occurred, caused by MAC address <mac> on port <port>.`, `PSECURE_VIOLATION_VLAN` | Time only | `<port>` | Every match | 60 min | warning |
| Traffic storm (`syslog_storm_control`) | `STORM_CONTROL-3-FILTERED` `A <type> storm detected on <port>. ...`, `STORM_CONTROL-3-SHUTDOWN` / `STORM_CONTROL-2-SHUTDOWN` | `STORM_CONTROL-5-ABATED` `A <type> storm abated on <port>. ...` | `<port>` | Every match | 24 h | warning |
| MAC address flapping (`syslog_mac_flap`) | `SW_MATM-4-MACFLAP_NOTIF` `Host <mac> in vlan <n> is flapping between port <a> and port <b>` | Time only | `vlan <n>` | 3 within 10 min | 30 min | warning |
| Duplex mismatch (`syslog_duplex_mismatch`) | `CDP-4-DUPLEX_MISMATCH` `duplex mismatch discovered on <port> ...` | Time only | `<port>` | Every match | 60 min | warning |
| HSRP failover (`syslog_hsrp_state`) | `HSRP-5-STATECHANGE` `<interface> Grp <n> state <old> -> <new>` and the older `STANDBY-6-STATECHANGE` `Standby: <n>: <interface> state <old> -> <new>`, when the group enters or leaves Active | Time only | `<interface>/<group>` | Every match | 60 min | warning |
| EIGRP neighbor down (`syslog_eigrp_neighbor`) | `DUAL-5-NBRCHANGE`, NX-OS `EIGRP-5-NBRCHANGE_DUAL` `... Neighbor <address> (<interface>) is down: <reason>` | The same tags `... is up: ...` | The neighbor address | Every match | Clear message only | critical |
| IS-IS adjacency down (`syslog_isis_adjacency`) | `CLNS-5-ADJCHANGE` `ISIS: Adjacency to <neighbor> (<interface>) Down, <reason>`, NX-OS `ISIS-5-ADJCHANGE` `... adj L<level> <neighbor> over <interface> - DOWN ...` | The same tags `Up` / `- UP` | `<neighbor>/<interface>` | Every match | Clear message only | critical |
| IPsec tunnel down (`syslog_ipsec_tunnel`) | `CRYPTO-5-SESSION_STATUS` `Crypto session is DOWN. Peer <address>:<port> ...` (or `Crypto tunnel is DOWN`) | `... is UP. Peer ...` | `<address>:<port>` | Every match | Clear message only | critical |
| IP SLA probe down (`syslog_ip_sla`) | `TRACK-6-STATE` `<track> ip sla <n> reachability Up -> Down` (or `state`) | `... Down -> Up` | `<track> ip sla <n>` | Every match | Clear message only | warning |
| PoE fault (`syslog_poe_fault`) | `ILPOWER-3-CONTROLLER_PORT_ERR`, `ILPOWER-5-ILPOWER_POWER_DENY`, `ILPOWER-5-INVALID_IEEE_CLASS`, `ILPOWER-4-LOG_OVERDRAWN`, `ILPOWER-3-SHUT_OVERDRAWN` | `ILPOWER-5-POWER_GRANTED`, `ILPOWER-5-CLR_OVERDRAWN` | `<port>` | Every match | 24 h | warning |
| Optic light level out of range (`syslog_optic_power`) | `SFF8472-5-THRESHOLD_VIOLATION` (any severity digit) `<port>: Rx power low alarm; ...`: Rx or Tx power, high or low, warning or alarm | Time only | `<port>` | Every match | 24 h | warning |
| AAA server not responding (`syslog_aaa_server`) | `RADIUS-4-RADIUS_DEAD`, IOS XE `RADIUS_AUDIT_MESSAGE-6-RADIUS_DEAD` `... RADIUS server <address>:<ports> is not responding.` | `RADIUS-4-RADIUS_ALIVE` | `<address>:<ports>` | Every match | 24 h | warning |
| NTP synchronization lost (`syslog_ntp_sync`) | `NTP-4-UNSYNC` `NTP sync is lost` | `NTP-5-PEERSYNC` | Per device | Every match | Clear message only | warning |
| License expiring or expired (`syslog_license_expiry`) | Smart Licensing `SMART_LIC-4-EVAL_WILL_EXPIRE_WARNING`, `SMART_LIC-3-EVAL_EXPIRED`, `EVAL_EXPIRED_WARNING`, `SMART_LIC-5-AUTHORIZATION_EXPIRED`, `SMART_LIC-3-AUTH_RENEW_FAILED`, `ID_CERT_EXPIRED`, `ID_CERT_EXPIRED_WARNING` | Time only | Per device | Every match | 24 h | warning |
| Certificate expiring or expired (`syslog_certificate_expiry`) | `PKI-4-CERT_EXPIRY_WARNING`, `PKI-1-CERT_EXPIRY_ALERT`, `PKI-2-CERT_RENEW_FAIL` `... for trustpoint <name> ...`, `PKI-3-CERTIFICATE_INVALID_EXPIRED` `... certificate SN: <serial> has expired.` | Time only | The trustpoint or serial, else per device | Every match | 24 h | warning |
| Software crash or memory failure (`syslog_software_fault`) | `SYS-2-MALLOCFAIL`, `PLATFORM-1-CRASHED`, NX-OS `SYSMGR-2-SERVICE_CRASHED` `Service "<name>" (PID <n>) hasn't caught signal <n> ...` | Time only | The NX-OS service, else per device | Every match | 24 h | critical |

Device families: Cisco IOS / IOS XE for every rule; Cisco NX-OS also for
EIGRP, IS-IS and software crashes.

- **Err-disable** is one rule for every cause, since a port that BPDU
  guard, UDLD, port security or storm control disables logs
  `PM-4-ERR_DISABLE` with the cause. `PM-4-ERR_RECOVER` only says a
  recovery is attempted, so it resolves nothing: a port that fails again
  logs `ERR_DISABLE` again and keeps the alert open, and the alert resolves
  24 hours after the last one. A port security violation in `shutdown`
  mode opens both a port security and an err-disable alert.
- **Noisy events** count towards a threshold: topology changes (5 within
  10 minutes per VLAN) and MAC moves (3 within 10 minutes per VLAN; a
  loop moves many hosts, so the alert is per VLAN, not per MAC address). A
  root change raises at once. `SPANTREE-5-TOPOTRAP` is logged when the
  switch sends its spanning tree topology change trap.
- **HSRP**: a group entering Active (this router took over) or leaving it
  (it gave the role up) raises the alert on that router; moves between
  Speak, Standby and Listen do not. It resolves after 60 minutes, as the
  HA switchover rules do.
- **Expiry warnings** repeat while the condition lasts (Smart Licensing
  sends them daily or weekly; CDP repeats a duplex mismatch every CDP
  interval), so each alert stays open while they keep coming and resolves
  after the auto-resolve time once they stop.

**Sources.** The tags and the template of each message are from the Cisco
System Message Guide for Catalyst Series Switches, IOS XE 17.3.x (and
16.12.x), and the Nexus 9000 NX-OS System Routing Messages Reference
10.6(2)F (EIGRP, IS-IS). The sample texts the patterns are written from:
the Catalyst 3750 ... 2960 Switch System Message Guide (`SPANTREE-5-ROOTCHANGE`,
`TOPOTRAP`), the Cisco TechNotes "Errdisable Port State Recovery on the
Cisco IOS Platforms" (`PM-4-ERR_DISABLE`), "Troubleshoot MAC Address Flap
Notifications" (`SW_MATM`), "Understand and Troubleshoot HSRP Problems"
(`HSRP` / `STANDBY`), the EIGRP neighbor TechNote 118974 (`DUAL`),
"Troubleshoot IS-IS Adjacency Issues" (`CLNS`), the IOS "IP Security VPN
Monitoring" configuration guide (`CRYPTO-5-SESSION_STATUS`), "Understand
AAA Dead Detection" (`RADIUS_AUDIT_MESSAGE-6-RADIUS_DEAD`) and Cisco Field
Notice FN64180 (`SYSMGR-2-SERVICE_CRASHED`). Where no Cisco document showed
the full text, the form was taken from log samples on the Cisco Community
(`PORT_SECURITY-2-PSECURE_VIOLATION`, `SFF8472-5-THRESHOLD_VIOLATION`,
`RADIUS-4-RADIUS_ALIVE`, `NTP-5-PEERSYNC`) or the ipSpace.net reliable
static routing article (`TRACK-6-STATE`).

## Custom rules

Click **+ New Syslog Rule** and fill in:

| Field | Meaning |
|---|---|
| **Name** | Shown in the alert message |
| **Match** | **Tag**: comma separated tags, with or without the severity digit (`SPANTREE-2-BLOCK_BPDUGUARD`, `UI_COMMIT_COMPLETED`). **Contains**: text anywhere in the message, ignoring case. **Regex**: a pattern searched in the message, ignoring case |
| **Raise pattern** | What raises the alert |
| **Clear pattern** | Optional: what resolves it (same match type) |
| **Severity** | Info, Warning or Critical |
| **Matches to raise** / **Within (seconds)** | The threshold: 1 raises on every match |
| **Auto-resolve (min, 0 = off)** | Resolve after this long without a new match; 0 waits for a clear message |

Regex patterns run on RE2: matching takes time linear in the message, and
lookarounds and backreferences are refused when the rule is saved. A group
named `instance` (else the first group) names the instance, so
`BPDU on port (?P<instance>\S+)` raises one alert per port. A custom rule's
metric is `syslog_custom_<id>`. Deleting a custom rule resolves its open
alerts.

**Test against a sample message** (in the rule dialog) shows the tag Plexus
reads from a message you paste (and its program), whether the rule you are
writing raises or clears on it and with which instance, which other rules
match, and whether the message starts a configuration backup, a re-poll or
an OPNsense re-collection (and why: gateway, CARP, VPN or configuration).
Nothing is saved or raised by a test.

The API: `GET /api/monitoring/syslog-rules` (built-in and custom rules,
needs **monitoring**), `POST` (create), `PUT /{id}` and `DELETE /{id}`
(custom rules), `PATCH /builtin/{key}` (`enabled`, `severity`) and
`POST /test` (`message`, optional `rule`): the changes need
**monitoring.write** and are audit logged. A user limited to selected
inventory groups can read the rules but not change them.

## Checking the rules against received traffic

The built-in patterns follow the vendors' documentation; your devices may
log other forms. The **Received messages** section of **Monitoring >
Configure > Syslog Rules** shows what the rules did with the syslog
messages received in the last 24 hours (or up to 7 days):

- **Matches per rule**: for each rule that matched at least once, how many
  messages raised and cleared it, on how many hosts, and when it last
  matched. Disabled rules are counted too, so you can see what one would
  do before turning it on. The configuration change, re-poll and OPNsense
  re-collect triggers show how often each fired.
- **Unmatched messages**: the messages of inventory hosts that no rule and
  no trigger acted on, grouped by event tag (an untagged message by its
  program, else in one group of its own), most frequent first (top 100).
  Each group shows its count, hosts, device types, when it was last seen
  and its newest message as a sample. **Create rule** on a row starts a
  new custom rule from that group.
- **Related**: a hint that an unmatched group looks like the subject of a
  built-in rule or trigger (an OSPF, BGP, link, power supply, fan, module,
  temperature, HA, login, configuration or reload message), from keywords in its tag (or program
  and sample). A related group is worth a look: it may be a form of the
  message the built-in rule misses. The hint is a keyword guess, not a
  match; most unmatched messages are routine and need no rule.
- **Tag of**: the group's tag is one a built-in rule or trigger handles,
  but the text of these messages did not meet its pattern. Usually that
  is the opposite event (`LINK-3-UPDOWN` ... `changed state to up` for
  the interface flapping rule, which counts downs); when the sample shows
  the event the rule is for, the wording differs on that platform and the
  rule misses it.
- **Unknown sources**: source addresses that are not an inventory host
  (nor one of its recorded interface addresses), with their message
  counts (top 20). Their messages are stored only; add the device to the
  inventory, or record the address it sends from, to have it acted on.
- **Stored only (UDP)**: while **Act on UDP messages** is off (see
  [Transports](#transports)), a message that arrived over UDP and meets a
  rule or trigger is counted here and not as a match, because the receiver
  stores it and does nothing more. The count uses the switch as it is set
  now, not as it was when the message arrived. A UDP message no rule meets
  is still listed under unmatched messages.

The analysis reads the stored messages when you open it (nothing extra is
stored), newest first, at most 50,000 of them: when the window holds more,
it covers the newest 50,000 and says so. It covers the messages still
kept (Events retention). A user limited to selected inventory groups sees
the messages of their groups' hosts only, and no unknown sources.

The API: `GET /api/monitoring/syslog-rules/activity?hours=24` (`hours` 1
to 168, needs **monitoring**) returns `scanned`, `truncated`, `matched`,
`unmatched`, `unknown_source`, `rules` (`key`, `raised`, `cleared`,
`hosts`, `last_at`), `triggers`, `unmatched_tags` (`tag`, `raw_tag`,
`program`, `count`, `hosts`, `device_types`, `last_at`, `sample`,
`related`, `known_tag`), `unknown_sources` (`source_ip`, `count`,
`last_at`), `transports` (the scanned messages of inventory hosts per
transport: `{"udp": n, "tcp": n, "tls": n}`), `udp_hosts` (how many
inventory hosts sent at least one message over UDP in the window),
`udp_actions` (the **Act on UDP messages** switch, see
[Transports](#transports)) and `udp_stored_only` (the UDP messages that
meet a rule or trigger while that switch is off; in neither `matched` nor
`unmatched`).

## Configuration change trigger

These messages start a backup and drift check of the host:

| Device family | Message |
|---|---|
| Cisco IOS / IOS XE, Arista EOS | `SYS-5-CONFIG_I` |
| Cisco NX-OS | `VSHD-5-VSHD_SYSLOG_CONFIG_I` |
| Cisco IOS XR | `MGBL-CONFIG-6-DB_COMMIT` |
| Cisco ASA, Cisco FTD | `111008` (a configuration command); `111010` except `show`, `ping`, `traceroute`, `more` and `dir` (FTD logs them as `%FTD-5-111008` / `111010`) |
| Juniper Junos | `UI_COMMIT_COMPLETED` |
| Fortinet FortiOS | `FGT-0100044544` (Path configured), `FGT-0100044545` (Object configured), `FGT-0100044546` (Attribute configured), `FGT-0100044547` (Object attribute configured): FortiOS applies each change at once. `44548` (Action performed, an `execute` command) is no change |
| Palo Alto PAN-OS | A CONFIG log of a `commit` whose result is `Succeeded`, or the SYSTEM log `Commit job succeeded` that ends the commit job (`PAN-SYSTEM-GENERAL`). Candidate edits (`set`, `edit`, `delete` ...) change nothing until the commit, and a `Submitted` or `Failed` commit is left out |
| HPE Aruba AOS-Switch | `AOSS-03125` `new Startup Config Seq Num = <n> by <UI>`: the startup configuration was saved (`write memory`). A change to the running configuration that is never saved logs nothing the reference lists, see [Known gaps](#known-gaps) |
| HPE Aruba AOS-CX | None: the event log reference has no configuration change event, see [Known gaps](#known-gaps) |

- **Debounce**: one configuration session logs several messages, so the
  run starts 60 seconds after the host's last configuration message, but
  no later than 10 minutes after the first message of the pending run: a
  steady stream of (possibly forged) messages cannot postpone the backup
  for ever.
- **Cooldown**: at most one run (one backup session to the device) per
  host every 5 minutes, however many messages arrive. Messages during the
  cooldown keep one pending run, which starts when the cooldown ends.
- **Backup**: the host is backed up through the first enabled backup
  policy of its inventory group (Configuration > Backups) with that
  policy's credential. The backup row's method is `syslog`. An unchanged
  configuration writes no new row. A host whose group has no enabled
  backup policy is not backed up.
- **Drift**: when drift checking is on and the host has a baseline, the
  configuration just backed up is stored as a drift snapshot (method
  `syslog`) and compared with the baseline; a difference opens a drift
  event as the scheduled check does. No second session is opened.

The configuration change trigger does not depend on monitoring being on.

## Re-poll trigger

| Message | Re-poll after |
|---|---|
| An interface going down (every form in the Interface flapping row above, from the first one) | 5 s |
| A module down or back online (every raise and clear form in the Module down row above) | 5 s |
| Reload: `SYS-5-RELOAD`, ASA and FTD `199001`, NX-OS `PLATFORM-2-PFM_SYSTEM_RESET`, IOS XR `INSTALL-INSTMGR-4-CALLING_PLATFORM_RELOAD_NODES_ALL`, Junos `UI_REBOOT_EVENT`, FortiOS `FGT-0100032138` (Device rebooted), `FGT-0100032200` (Device shutdown) and `FGT-0100032545` (Scheduled daily reboot started), AOS-Switch `AOSS-00063` (SYSTEM went down), AOS-CX `AOSCX-706` (Initiating system reboot) and `AOSCX-707` (Initiating chassis thermal reboot) | 30 s (the device logs it before it goes down) |
| Restart: `SYS-5-RESTART`, `SYS-6-BOOTTIME`, ASA and FTD `199002`, IOS XR `PLATFORM-SHELFMGR-6-SYSTEM_COLD_START`, EOS `SYS-5-SYSTEM_RESTARTED`, `SYS-3-KERNEL_PANIC` and `HARDWARE-4-WATCHDOG_ERROR` (`Reboot due to ...`), Junos `SNMPD_TRAP_COLD_START` and `SNMPD_TRAP_WARM_START`, FortiOS `FGT-0100032009` (FortiGate started), AOS-Switch `AOSS-00066` (System Booted) and `AOSS-00064` (the crash reason of a switch that went down), AOS-CX `AOSCX-1206` (Module rebooted) and `AOSCX-1236` (Module unexpected reboot) | 5 s |
| A temperature alarm or its recovery (every raise and clear form in the Temperature alarm row above) | 5 s |
| An HA switchover, failover or peer / link loss, or its documented recovery (every raise and clear form in the HA failover or switchover row above) | 5 s |

The reload and restart messages also raise the **Device restarted** rule
(`syslog_device_restart`); turning that rule off leaves the re-poll.
The temperature and HA rows re-poll as the trap rules of the same keys do
(`trap_temperature` as a module change, which also reads the hardware
components again; `trap_ha_switchover` as a state change).

A re-poll is the full monitoring poll of that one host, so its state,
availability, charts and poll alerts catch up. A host is re-polled at most
once a minute, and not while one is already waiting. Nothing is re-polled
while monitoring is off.

## OPNsense re-collect trigger

An OPNsense firewall's gateways, CARP roles, VPN tunnels and config.xml
reach Plexus through the collection of its topology source (hourly by
default). These messages start that collection within seconds instead:

| Reason | Program | Message |
|---|---|---|
| Gateway | `dpinger` | The gateway watcher's `ALERT: <gateway> (Addr: ... Alarm: <old> -> <new> ...)` and `MONITOR: ...` lines, and dpinger's own `<gateway> <address>: Alarm latency ...` / `Clear latency ...` |
| CARP | `kernel` | `carp: <vhid>@<interface>: <state> -> <state> (<reason>)` (INIT, BACKUP, MASTER) and `carp: demoted by <n> to <m> (<reason>)` |
| VPN | `charon` | IPsec phase 1: `IKE_SA <name>[<n>] established between ...`, `deleting IKE_SA ...`, `IKE_SA deleted`, and `CHILD_SA <name>{<n>} closed` |
| VPN | `openvpn_server<n>`, `openvpn_client<n>` | An instance's `Initialization Sequence Completed` and `SIGUSR1[...] / SIGHUP[...] / SIGTERM[...] received, process restarting / exiting` (not the lines of one client of a server instance) |
| Configuration | `config`, `audit` | `config-event: new_config <backup file>` and `user <name> changed configuration to ...` |
| IDS (a read, not a collection) | `suricata` | An alert line `[1:<sid>:<rev>] <signature> [Classification: ...] [Priority: <n>] ...` (`[Drop] ` first in IPS mode) and an eve record over syslog with `"event_type":"alert"` |

- **IDS alerts**: a Suricata alert does not collect the source; it reads
  only its IDS alerts (the ones newer than the newest stored, see
  [IDS alerts](opnsense-topology.md#ids-alerts)), with the same 5-second
  delay and once-a-minute interval, but it is not one of the hour's 6
  collections and is not held back by them. A collection asked for while
  the hour's runs are used up waits for the hour; an IDS read pending at
  the same time runs on its own.
- **Which source**: the message's source address is matched to the
  OPNsense source(s) of the firewall: through the inventory host it
  resolves to (the host the newest collection matched the firewall to),
  and through the firewall's API address, interface addresses and CARP
  virtual IPs from its newest collection, so a firewall that is no
  inventory host triggers too, once its sending address is admitted by
  the receiver's source allowlist (add it to the extra networks:
  [administration.md](administration.md#listener-sources)). The map is
  rebuilt at most once a minute.
- **The run**: the full collection the schedule and **Collect now** run
  (snapshot, availability tracking, config.xml backup and drift, software
  refresh, recorded as built by `syslog`), 5 seconds after the first
  message, at most once a minute and 6 times an hour per source (a
  seventh waits until the first of those is an hour old; the scheduled
  collection is not counted or delayed). Messages during that minute
  or during the run leave one more run. A source whose collection is
  already running is retried 15 seconds later; two collections of one
  source never run at once.
- **No alerts of their own**: the availability tracker raises and resolves
  the gateway, tunnel and CARP alerts (with their SLA, persistence and
  mutes) from the fresh collection, so these messages never raise a
  syslog alert themselves. A custom rule can still match them.

The trigger does not depend on monitoring being on. Setting up the
firewall: [OPNsense in the Topology Map](opnsense-topology.md#syslog).

## Cisco syslog messages sent as SNMP traps

A Cisco device can send its syslog messages as CISCO-SYSLOG-MIB
`clogMessageGenerated` traps (`snmp-server enable traps syslog`). For such
a trap from an inventory host that carries the host's SNMP community (or
is authenticated with its SNMPv3 user), Plexus builds the line it carries
from its varbinds, `%<clogHistFacility>-<clogHistSeverity - 1>-<clogHistMsgName>: <clogHistMsgText>`
(`%SYS-5-CONFIG_I: Configured from console by admin on vty0`), and hands it
to the syslog rules as a message of that host: the built-in and custom
rules, the configuration change trigger and the re-poll trigger. The trap
itself is still stored as a trap ([SNMP Traps](snmp-traps.md#cisco-syslog-messages-sent-as-traps)).

The alerts are syslog alerts with the syslog alert key, so the same
message received as syslog and as a trap meets in one alert. The
switches below apply to it (**Raise alerts from syslog rules**, not the
trap alerts switch); **Act on UDP messages** does not, since the trap was
believed by its community or SNMPv3 user.

**Threshold counters when both arrive.** Each copy is a match of the rule
for the same host and instance. Two matches less than 5 seconds apart
count once (step 4 of [How a message becomes an alert](#how-a-message-becomes-an-alert)),
so a device that sends the message both ways at once counts it once, and
a rule with a threshold of one raises one alert, not a bump. Copies more
than 5 seconds apart (a delayed trap, a queue on the device) count twice:
a threshold rule (Interface flapping, Repeated login failures, a custom
rule with a threshold) can then raise early. Send the messages one way
only when that matters: either syslog (`logging host`) or the trap
(`snmp-server enable traps syslog` with `logging history`), not both. The
configuration change and re-poll triggers are debounced and rate limited
per host, so a message received twice starts one run.

## Switches

The receiver settings (Settings > Syslog & Traps, admin) have a switch for
each of the four behaviours: **Raise alerts from syslog rules**, **Back up
the config on a change message**, **Re-poll on link down, module down or reload** and
**Re-collect OPNsense on a state change**. Each is on by default; turning
one off stops that behaviour only, and messages are still stored. A fifth
switch, **Act on UDP messages**, stops all four for messages that arrived
over UDP (see [Transports](#transports)).

## Transports

The syslog receiver has three listeners, each turned on and given its
port under Settings > Syslog & Traps. They can run at the same time, so
devices can move one by one. Every stored message records how it arrived
(`transport`: `udp`, `tcp` or `tls`), shown in Monitoring > Events.

| Listener | Default port | What it protects against |
|---|---|---|
| **UDP** | 1514 | Nothing on its own: the source address of a datagram can be forged, so anything that can reach the port can send a message "from" an inventory host. The source allowlist and rate limit ([administration.md](administration.md#listener-sources)) bound what a forged message can start |
| **TCP** (RFC 6587) | 1514 | A forged source address: a TCP connection needs the reply to the address it claims. A host on the path between the device and Plexus can still read and change the messages |
| **TLS** (RFC 5425) | 6514 | A forged source address, and reading or changing the messages on the way: the connection is encrypted and the device checks Plexus's server certificate |
| **TLS with client certificates** (mutual TLS) | 6514 | All of the above, and a sender that has no certificate from your device CA: with **Require client certificates** on, only a device holding a certificate the stored client CA signed can connect |
| **TLS with the host named in the certificate** | 6514 | All of the above, and one device's certificate used to send as another device: with **Certificate must name the host** on, the certificate must name the inventory host at the connection's source address |

TCP and UDP can use the same port number. The TCP and TLS listeners
cannot share a port.

- **Framing**: both stream listeners read octet-counted frames
  (`<length> <message>`, RFC 6587 and RFC 5425) and newline-terminated
  frames (LF, CRLF or NUL), detected per message, so one connection may
  mix them. A message longer than 8192 bytes, or a malformed length,
  closes the connection (counted as an error).
- **Sources**: the same source allowlist and per-source rate limit as UDP.
  A connection from an address the allowlist refuses is closed at once
  (counted in **Dropped (source)**); every message on an open connection
  counts against the rate limit. With mutual TLS, the certificate proves
  the device belongs to you, and the connection's source address (which
  TCP does not let anyone forge) still decides which inventory host a
  message is from.
- **Certificate names the host**: with **Require client certificates** on,
  **Certificate must name the host** also checks each connection, after
  the handshake and before any message is read. The certificate is
  accepted when a subject alternative name IP address equals the source
  address (an IPv4-mapped IPv6 address counts as IPv4), or when a SAN DNS
  name or the subject common name matches the hostname of the inventory
  host at that address: equal ignoring case, or one is a name without a
  dot equal to the first label of the other (`core-sw1` matches
  `core-sw1.example.com`). Wildcard names never match. A source that is no
  inventory host (admitted by an extra network or the `any` policy) needs
  the SAN IP address. A refused connection is closed and counted
  (**Certificate not for host**); without the check, the certificate of
  one device could send from another device's address as that device.
- **Limits**: at most 1024 open connections, 8 per source address; a
  connection over a limit is closed and counted (**Refused**). The TLS
  handshake must finish within 10 seconds. There is no idle timeout,
  because devices keep one connection open and may send nothing for
  hours; TCP keepalive closes connections whose device went away.
- **Status**: each listener shows whether it runs and on which port, the
  messages received, errors (unreadable messages, framing errors and
  failed TLS handshakes), the last message, the connections open now and
  the connections refused (and, for TLS, those refused because the
  certificate did not name the host), since it last started. A TLS
  listener that is
  on but cannot start (no certificate) shows why.

### Act on UDP messages

**Act on UDP messages** (on by default) decides whether a message that
arrived over UDP may raise or resolve an alert, start a configuration
backup, a re-poll or an OPNsense re-collection. Turned off, UDP messages
are still received and stored (Monitoring > Events, **Received
messages**), but nothing acts on them; messages over TCP and TLS act as
before. The restore at startup then skips UDP messages too. It can only be
turned off while the TCP or TLS listener is on.

The recommended order:

1. Store or generate a server certificate and turn on the TLS listener
   (and the TCP listener for devices that cannot send TLS).
2. Move devices to TCP or TLS, one platform at a time.
3. Watch the transport counts in **Received messages** (Monitoring >
   Configure > Syslog Rules): it shows how many messages of inventory
   hosts arrived over each transport and how many hosts still send UDP.
4. When no host you rely on sends UDP, turn **Act on UDP messages** off.

### Certificates

The TLS listener needs a server certificate, managed under Settings >
Syslog & Traps:

- **Generate**: a self-signed certificate (EC P-256) for the names and
  addresses devices use to reach Plexus (DNS names or IP addresses, up to
  32), valid 1 to 3650 days (825 by default). Each device must then trust
  that certificate: import it as a trusted certificate (a trustpoint on
  Cisco).
- **Upload**: a certificate from your own CA, in PEM, with any
  intermediates after it, and its private key (PEM, not encrypted). The
  key must belong to the certificate, and an expired certificate is
  refused. Devices that trust your CA need nothing more.
- **Client CA**: for mutual TLS, the PEM certificate(s) of the CA that
  signs your devices' client certificates. **Require client certificates**
  can be turned on only while a client CA is stored, and the CA cannot be
  removed while it is on. **Certificate must name the host** can be turned
  on only while client certificates are required; issue each device a
  certificate with its address as a SAN IP address or its inventory
  hostname as a SAN DNS name or common name. Turning it on or off restarts
  the TLS listener, so open connections reconnect and are checked.

The private key is encrypted at rest and never shown again, in the
settings, the API or the audit log. Saving a new certificate or client CA
restarts the TLS listener: open TLS connections drop and devices
reconnect. The certificate cannot be removed while the TLS listener is on.

### Device configuration for TCP and TLS

The examples use `192.0.2.10` for Plexus and the default ports.

```text
! Cisco IOS / IOS XE: TCP
logging host 192.0.2.10 transport tcp port 1514

! Cisco ASA: TCP, or TLS with "secure"
logging host inside 192.0.2.10 tcp/1514
logging host inside 192.0.2.10 tcp/6514 secure
logging permit-hostdown
```

- **Cisco ASA**: with TCP syslog, the ASA stops passing new connections
  when it cannot reach the syslog server (for example while Plexus
  restarts) unless `logging permit-hostdown` is configured. Configure it.
- **Cisco IOS XE TLS**: IOS XE sends syslog over TLS through a TLS profile
  (`logging host ... transport tls`) that names a trustpoint holding the
  Plexus certificate or its CA. See "Configuring Secure Syslog" in the
  System Management Configuration Guide of your release. Classic IOS
  without that feature can send TCP only.
- **Cisco NX-OS, Arista EOS, Juniper Junos, HPE Aruba, Fortinet FortiOS,
  Palo Alto PAN-OS**: each can send syslog over TCP or TLS on current
  releases; set the transport (TCP or TLS / SSL), the port and, for TLS,
  the trusted CA as the vendor's logging or system management guide for
  your release describes.
- **OPNsense**: in the remote logging destination, pick a TCP or TLS
  transport and the matching port, as the OPNsense logging documentation
  describes.

## Device configuration

Send syslog to the Plexus server's address on the syslog receiver's port
(UDP 1514 unless Settings > Syslog & Traps says otherwise; for TCP and TLS
see [Device configuration for TCP and TLS](#device-configuration-for-tcp-and-tls)). The examples use
`192.0.2.10` for Plexus. Interface and neighbor messages are level 3 to 5,
login failures level 4 to 6 and module messages level 2 to 6 (IOS XE logs
a card or SPA going offline at level 6), so send at least `informational`
for every rule to see its messages.

```text
! Cisco IOS / IOS XE
logging host 192.0.2.10 transport udp port 1514
logging trap informational
login on-failure log

! Cisco NX-OS
logging server 192.0.2.10 6 port 1514 use-vrf management

! Cisco ASA
logging enable
logging trap informational
logging host inside 192.0.2.10 udp/1514

! Arista EOS
logging host 192.0.2.10 1514
logging trap informational

! Juniper Junos
set system syslog host 192.0.2.10 any info
set system syslog host 192.0.2.10 port 1514
```

- **Fortinet FortiOS**: under `config log syslogd setting` set `status
  enable`, `server` to the Plexus address and `port` to the receiver's
  port, and keep the event log on (`config log eventfilter`, `event
  enable`, with `system` and `router` events). Keep the default `format`
  (`default`; `rfc5424` works too); `csv` and `cef` are not read. See
  Fortinet's "Log settings and targets" in the FortiOS Administration
  Guide.
- **Palo Alto PAN-OS**: add a Syslog server profile (Device > Server
  Profiles > Syslog) with the Plexus address, UDP, the receiver's port and
  the BSD or IETF format, leave the custom log format empty, and forward
  the System and Configuration logs to it (Device > Log Settings).
- **HPE Aruba AOS-CX**: `logging 192.0.2.10 udp 1514 severity info`
  (add `vrf mgmt` when the switch reaches Plexus through its management
  port); the AOS-CX Monitoring Guide lists the options of your release.
- **HPE Aruba AOS-Switch**: `logging 192.0.2.10` sends to UDP 514.
  Publish that port to the receiver (add `"514:1514/udp"` to the ports in
  `docker-compose.yml`), or set the port on the switch when your release
  supports it, as the ArubaOS-Switch Management and Configuration Guide
  describes.

Send from an address Plexus knows: the host's primary address or one of
its recorded interface addresses (discovery records them), for example
with `logging source-interface` on Cisco IOS.

## Known gaps

- Only hosts in the inventory are acted on; messages from other addresses
  are stored only (except the OPNsense re-collect trigger, which also
  knows the firewalls of OPNsense sources by their collected addresses).
- **Vendor rules not yet seen on a live device**: the Fortinet FortiOS,
  Palo Alto PAN-OS, HPE Aruba AOS-CX and AOS-Switch forms, the classic
  Catalyst, ISR G2 and Arista EOS power supply and fan forms, and the
  temperature, HA, Cisco FTD, IOS XR and Catalyst 4500 forms, were written
  from the vendors' log message references and checked against invented
  samples only. **Received messages** under Monitoring > Configure >
  Syslog Rules shows whether your devices' messages match them (a **Tag
  of** row means a known tag whose text did not match).
- **Fortinet FortiOS**: the FortiOS Log Message Reference lists each log
  id with its `logdesc` and fields but not the text of its `msg`, so the
  forms that test the `msg` are not confirmed by it: the OSPF Down / Up
  wording of `FGT-0103020302` (taken from the BGP form) and the "Link
  monitor: Interface ... was turned down" form of `FGT-0100020099`, the
  only form of that id that counts as a link down. Log id `20090`
  (Interface link status changed, fields `intf` and `status`) is not
  built in, because the reference gives no values for `status`. Power
  supply and fan alerts are one per firewall, since their messages name
  the unit in no documented form. Power supply ids differ by release:
  `22104` (Power supply restored) is listed up to 7.4 and not in 7.6;
  `22114` / `22115` mean "Power supply failed warning" / "Power supply
  restored notification" from 7.2, but "power redundancy degrade" /
  "power redundancy failure" in 6.4. A `22115` message whose text says
  fail, redundancy or degrade therefore does not resolve the alert; the
  reference gives no text for either release, so a 6.4 message worded
  otherwise would.
- **Palo Alto PAN-OS**: only the default (CSV) log format is read. OSPF
  and BGP events are those of the legacy routing engine; the PAN-OS
  system log reference lists no event ids of the Advanced Routing Engine,
  so its neighbor changes are not built in. A failed power supply or fan
  tray has no recovery event in the reference, so those alerts resolve
  after 24 hours. The reference lists no reload or restart event, so
  neither the re-poll trigger nor the **Device restarted** rule covers
  PAN-OS. `auth-fail` is logged for every authentication the firewall
  rejects, VPN and portal users as well as administrators, with the same
  event id and subtype; its description names the auth profile, vsys and
  admin role but nothing the reference defines as telling an
  administrator login apart. On a busy VPN gateway raise the threshold of
  **Repeated login failures** or turn the rule off. The `Commit job
  succeeded` form is taken from a log sample of an old release; the
  current reference does not list it.
- **HPE Aruba AOS-CX**: the AOS-CX Event Log Message Reference (10.17) has
  no configuration change event (event `6801` `Copying configs from: ...
  to: ...` reports a copy, such as `write memory`, and is not built in).
  The PSU fault (`AOSCX-304`) and fan fault (`AOSCX-214`) have no
  documented recovery message (`301` `PSU <name> changed state to
  <state>` and `216` `Status of fan <name> has changed from <old> to
  <new>` give no state values), so those alerts resolve after 24 hours.
  The OSPF forms match the new state `Down` / `Full` (RFC 2328 state
  names, ignoring case); the reference shows the template without state
  values. Write a custom **Tag** rule (`AOSCX-<event id>`) for other
  events your switches log.
- **HPE Aruba AOS-Switch**: the forms follow the Event Log Message
  Reference for ArubaOS-Switch 16.09 (the newest release found). It lists
  no running configuration change event (`logging notify
  running-config-change` is not in it), so only a saved startup
  configuration (`AOSS-03125`) starts a backup. `BGP: Peer down` / `Peer
  up` name no peer, so one alert per switch: a peer coming up resolves it
  while another may still be down. OSPF and BGP events of other ids
  (`2702` state moves, `3077` Peer timeout) are not built in. A port
  disabled in the configuration also logs `port ... is now off-line`
  (event `77`; the reference gives no separate message) and counts as a
  link down.
- **Classic Cisco hardware**: the classic Catalyst fan and power supply
  forms have no recovery message (their alerts resolve after 24 hours),
  and ISR G2 power supply messages are not built in: no ISR G2 or IOS
  15M&T system message guide could be retrieved (Cisco has retired them).
  The Catalyst guide 17.3.x lists `ENVMON-1-POWER_WARNING`,
  `ENVMON-3-POWER_ERROR` and `ENVMON-5-POWER_NOTICE` for the CGS 2520 and
  1900 components with the bare template `: <text>`, which does not tell
  a failure from a recovery, so they are not built in. Write a custom
  **Tag** rule for the power supply message your routers log.
- **Module down**: the forms come from the Cisco System Message Guide for
  Catalyst Series Switches (IOS XE 17.3.x and 16.12.x: `IOSXE_OIR`,
  `SPA_OIR`), the Cisco TechNote "Troubleshoot Hardware Failure on
  Catalyst 9600" (sample `IOSXE_OIR` / `SPA_OIR` lines), the Catalyst
  3750, 3560, 3550, 2975, 2970 and 2960 Switch System Message Guide
  (`STACKMGR`), the Cisco TechNote "Line Cards Power Down due to
  Communication Failures Troubleshooting Guide" (Catalyst 6500
  `C6KPWR`), the Nexus 9000 System Messages Reference (`MODULE`,
  `PLATFORM`) and JUNIPER-MIB (the `jnxFru*` traps chassisd logs as
  `CHASSISD_SNMP_TRAP*`). Not built in:
  - **Catalyst 9000 stacks (IOS XE)**: the IOS XE system message guides
    (16.12.x, 17.3.x) do not list `STACKMGR`. Cisco community logs show IOS
    XE stacks logging `STACKMGR-4-SWITCH_REMOVED` with the classic text
    after a prefix (`Switch 1 R0/0: stack_mgr: Switch 3 has been removed
    from the stack.`), which the classic form matches, but no Cisco
    reference confirms it or the IOS XE wording of `SWITCH_READY`. A
    member that never logs `SWITCH_READY` resolves after 24 hours.
  - **Catalyst 6500**: the TechNote shows `C6KPWR-SP-4-DISABLED` with a
    fault reason; no reference gives the reason text of a module an
    operator powered off (`no power enable module`), so that is counted
    too, and no reference gives a recovery message (the classic `OIR`
    `REMCARD` / `INSCARD` forms appear only in community logs), so the
    alert resolves after 24 hours.
  - **Catalyst 4500**: the forms follow the Catalyst 4500 System Message
    Guide 15.1(1)SG. `MODULEOFFLINE` does not say why, so a module an
    operator took offline counts too.
  - **NX-OS**: `PLATFORM-2-MOD_PWRDN` does not say why a module was
    powered down; one powered off from the CLI also logs
    `PLATFORM-2-PFM_MODULE_POWER_OFF` (not counted) and may log
    `MOD_PWRDN` after it, which raises the alert. Diagnostic and software
    failures that may leave the module online (`MODULE-2-MOD_DIAG_FAIL`,
    `MOD_SOMEPORTS_FAILED`, `MOD_MAJORSWFAIL`, `XBAR_DIAG_FAIL`) and the
    fabric module forms that name it in lower case (`MODULE-2-XBAR_FAIL`,
    `XBAR_FAILURE`: `Initialization of xbar <n> failed`, an instance that
    `Xbar <n> is online` would not resolve) are not built in.
  - **Juniper Junos**: the trap names and varbinds come from JUNIPER-MIB;
    the Junos System Log Messages Reference entries for chassisd's own
    FRU messages (`CHASSISD_FRU_OFFLINE_NOTICE`, `CHASSISD_FRU_ONLINE` and
    similar) could not be retrieved, so only the trap forms are built in.
  - **Cisco IOS XR**: the forms follow the IOS XR System Error Message
    Reference 5.1.1 (32-bit IOS XR on ASR 9000, CRS, XR 12000); the
    64-bit IOS XR and XR7 message sets (NCS) were not retrieved. The node
    state change messages (`SHELFMGR-6-NODE_STATE_CHANGE`,
    `INVMGR-6-NODE_STATE_CHANGE`) give no state values, so there is no
    recovery message: the alerts resolve after 24 hours.
  - **Arista EOS**: the only EOS System Message Guide that could be
    retrieved is 4.12.10 (2015); newer releases may name more forms. That
    guide prints the multi-word mnemonics without their underscores; they
    are written with them (`CARD_LOST_POWER`), as EOS logs show for the
    fan and power supply mnemonics. `CARD_POWERED_OFF` is also logged for
    an operator's power off and is not counted.
  - **HPE Aruba AOS-CX and AOS-Switch**: the HPE Aruba event log reference
    pages refuse automated reading, so the module (`3202`, `3207`), VSF
    (`9913`) and stack member (`AOS-Switch 402`) forms were taken from the
    search excerpts of those pages; no recovery message text was found, so
    the alerts resolve after 24 hours. AOS-CX `AOSCX-1206` / `AOSCX-1236`
    (Module rebooted) are restart forms (the **Device restarted** rule).
  - **Fortinet FortiOS**: only `22111` / `22112` (FPC down / up due to a
    PSU action, FortiGate 6000 / 7000) are in the reference, without msg
    text, so one alert per chassis.
  - **Palo Alto PAN-OS**: the system log reference has no event id for a
    slot or card failure (only messages without an id, such as `Thermal
    alarm on slot <id>`), so none is built in.
  - The polled module check covers Cisco and Juniper over SNMP, and the
    polled HA check covers stack and VSF members (Cisco StackWise, AOS-CX
    VSF: [monitoring.md](monitoring.md#ha-and-redundancy-state)). Write a
    custom **Tag** rule for other module messages your devices log.
- **Temperature alarm**: the forms come from the Cisco System Message Guide
  for Catalyst Series Switches (IOS XE 17.3.x and 16.12.x), the System
  Message Guide for Catalyst Switches 15.2(6)E2 (classic Catalyst), the
  Catalyst 4500 guide 15.1(1)SG, the Nexus 9000 System Messages Reference
  10.6(2)F, the IOS XR reference 5.1.1, the ASA and FTD syslog message
  guides, the EOS System Message Guide 4.12.10, the Junos System Log
  Explorer, the FortiOS 7.6 Log Message Reference and the HPE Aruba event
  log references (search excerpts, as above). Not built in or limited:
  - The IOS XE `ENVIRONMENTAL-1-ALERT` text is matched in the form of the
    Cisco TechNotes (`Temp: Inlet 1, Location: R0, State: ...`); the guide
    shows the template without commas, which matches too.
  - The `ENVMON` temperature mnemonics are listed in the Catalyst guide for
    the CGS 2520 and 3900 components; no ISR G2 guide could be retrieved
    to confirm them on the 1900 / 2900 / 3900.
  - NX-OS `MOD_TEMPRECOVER` (major alarm recovered, minor pending) and
    `MOD_TEMPFAIL` (sensor failed), IOS XR `DIE_OVERTEMP_*` and
    `ENVMON-2-TEMP` (their wording does not say rising or falling), Arista
    `XCVR_OVERHEAT_*` (transceivers, no recovery message) and
    `HARDWARE-4-POWER_SUPPLY_OVERHEAT_WARNING` (it names the supply in
    another form than its recovery message) are not built in.
  - Junos: the reference gives no recovery message for the `CHASSISD_*`
    temperature forms, so they resolve after 24 hours. The
    `CHASSISD_SNMP_TRAP*` `Over Temperature` / `Temperature back to normal`
    wording is taken from a public Junos log sample; the System Log
    Explorer gives only the generic trap template.
  - FortiOS `22109` / `22152` / `22153` have no msg text in the reference:
    one alert per firewall. AOS-CX `802` (critical temperature shutdown),
    `804` (back to safe temperature) and `806` (ambient), and AOS-Switch
    `556` (temperature normal) and the 16.08 ids (`553` / `557`) were not
    retrieved with their text and are not built in; their alerts resolve
    after 24 hours.
  - **Palo Alto PAN-OS**: temperature appears only as messages without an
    event id (`Thermal alarm on slot <id>`, `Shutting down ... for thermal
    temperature`); none is built in.
- **HA failover or switchover**: from the same references as the
  temperature alarm. Most forms report an event, so one alert per device
  that resolves 60 minutes after the last one (the polled HA state is the
  backstop). Not built in or limited:
  - **Cisco ASA / FTD**: the failover link and interface recovery messages
    (`105031`, `105042`, `105004`, `104004`) are not clears, since the
    alert is per firewall and they would also resolve a switchover.
    Monitored interface failures (`105007`, `105009 ... Failed`) are left
    to the interface rule, and the legacy serial failover cable messages
    (`101001` to `101005`) and the cluster messages (`747xxx`; the FTD
    guide's entries could not be read) are not built in. A unit that
    boots as active also logs `104001`.
  - **Catalyst 9000 stacks**: no Cisco reference with the IOS XE message of
    a new active switch was found (`STACKMGR` is not in the IOS XE guides).
  - **Arista EOS**: names are from the 4.12.10 guide, as for the module
    forms. A switchover has no recovery message; MLAG back to active
    resolves the `MLAG` alert.
  - **Juniper Junos**: `JSRPD_RG_STATE_CHANGE` is counted for every
    transition, a normal start included. Virtual Chassis master changes
    have no tag in the System Log Explorer.
  - **Fortinet FortiOS**: the HA ids are those of the 7.6 reference with the
    `0108` prefix of the Fortinet community samples; their msg names no
    member in a documented form. `37910` (Heartbeat packet lost) is not
    built in (one lost packet is no failover); `37894` (member joined) and
    `37902` (heartbeat interface up) are not clears, as the alert is per
    firewall.
  - **Palo Alto PAN-OS**: the system log reference has no HA section. The
    `state-change` event id and its `HA Group <n>: Moved from state ...`
    text come from a Palo Alto knowledge base example that shows the event
    id truncated (`state-c`); HA1 / HA2 port down messages are the
    `link-change` forms of the interface rule.
  - **HPE Aruba**: VSX `7001` / `7005` and AOS-Switch `3278` come from the
    search excerpts of the event log reference; the recovery messages
    (`7002`, `7006`) and the AOS-CX VSF conductor election (`9915`) were
    not retrieved with their text.
- **Device restarted**: the rule raises on the reload and restart forms
  of the re-poll trigger. IOS XR has no documented reload command message
  in the 5.1.1 reference (only the install reload and the cold start are
  built in). PAN-OS lists no reload, restart or shutdown event in its
  system log reference. AOS-CX `1206` / `1236` report a module reboot,
  which on a fixed switch is the switch itself.
- **Event rule packs** ([Event rule packs](#event-rule-packs)): checked
  against invented samples only. Not built in:
  - **Cisco forms without a confirmed text**: `RADIUS-4-RADIUS_ALIVE` is
    matched by the classic text (`RADIUS server <address>:<ports> is being
    marked alive`, from community logs; the guide gives no text), and no
    reference shows an IOS XE `RADIUS_AUDIT_MESSAGE` alive form, so those
    alerts resolve after 24 hours. TACACS+ has no dead / alive message in
    the IOS XE guide. `NTP-4-PEERUNREACH` / `PEERREACH` (one peer) are not
    built in, only the loss of synchronization. The NX-OS IS-IS form gives
    no state values: `- DOWN` / `- UP` are assumed. Bridge Assurance names
    the port and VLAN in a form the guide does not separate, so its alert
    is per port. `UDLD-4-UDLD_PORT_DISABLED` and the storm control
    shutdown are counted through the `PM-4-ERR_DISABLE` message they come
    with; `SPANTREE-2-BLOCK_BPDUGUARD` names the port in its long form
    (`GigabitEthernet4/1`) while `ERR_DISABLE` uses the short one
    (`Gi4/1`), so it is left to `ERR_DISABLE` to avoid two alerts.
  - **Tracebacks**: a traceback is appended to another message
    (`-Traceback= ...`), not a message of its own; the rules match by tag,
    so it is not built in. A `SYS-2-MALLOCFAIL` with a traceback raises the
    software fault rule.
  - **Cisco NX-OS** layer 2, HSRP, IP SLA, PoE, optics, AAA, NTP, license
    and certificate messages; **IOS XR** IS-IS, EIGRP and the health
    messages; **ASA / FTD** VPN tunnels: the NX-OS System Messages
    Reference (non-routing) and the IOS XR and ASA message references
    were not searched far enough to confirm the texts.
  - **Juniper Junos** (`RPD_ISIS_ADJDOWN`, `KMD_VPN_DOWN_ALARM_USER`,
    `L2ALD_MAC_MOVE_*`, BPDU block, `NTPD`, `CHASSISD` optic and PoE
    messages), **Arista EOS** (`ETH-4-HOSTFLAP`, `SPANTREE`, IS-IS),
    **HPE Aruba** AOS-CX and AOS-Switch: the vendors' system log references
    could not be retrieved (only third-party samples were found).
  - **Fortinet FortiOS** IPsec: log id `37138` (IPsec connection status
    changed) lists an `action` field but no values for tunnel up and down,
    so no form is built in (as for `20090`); the VPN tunnel traps cover it
    ([snmp-traps.md](snmp-traps.md#built-in-rules)).
  - **Palo Alto PAN-OS**: no IPsec tunnel or Advanced Routing Engine event
    id was confirmed in the system log reference.
- **Netgear and APC** send syslog in their own formats; no built-in rule
  or trigger matches them. Netgear publishes no log message reference for
  its managed switches (the M4200 / M4300 / M4350 manuals describe the
  `environment trap` settings but no message text). APC (Schneider)
  documents event texts such as `UPS: On battery due to an input power
  problem` (event `0x0109`) and `System: Coldstart` / `System:
  Warmstart`, but not the syslog line they are sent in (the NMC user
  guide could not be read), so no tag or program to match them is known.
  Custom **Contains** rules work on them; APC UPS state changes also
  arrive as SNMP traps.
- API-polled platforms (Cato, AWS, Azure, GCP, Meraki, Cisco FMC,
  Panorama, Appgate) send no syslog to Plexus; their state comes from the
  scheduled collections and, for Meraki, its alert feed
  ([Vendor Monitoring Coverage](vendor-monitoring-coverage.md)).
- Threshold counters and pending configuration-change runs are kept in
  memory. At start Plexus rebuilds them from the stored messages: the
  counters of enabled threshold rules from the messages of the longest
  threshold window (at most one hour, the newest 20,000 messages), without
  raising or resolving anything, and a host's configuration-change run
  when its last configuration message is less than 5 minutes old and no
  backup was taken since (only TCP and TLS messages while **Act on UDP
  messages** is off).
- Messages sent while Plexus is down or restarting are lost over UDP. Over
  TCP or TLS a device sees the connection close and connects again, but
  do not count on it to resend what it logged meanwhile: most devices do
  not keep those messages. Saving a new TLS certificate also drops the
  open TLS connections.
- Syslog over UDP is not authenticated: anything that can reach the
  receiver port can send a message with an inventory host's source
  address. Move devices to TCP or TLS and turn off **Act on UDP messages**
  ([Transports](#transports)); until then the rate limits above bound
  what a forged message can start (one backup per host every 5 minutes,
  one re-poll per host a minute, 6 OPNsense re-collections per source an
  hour). Plain TCP stops forged source addresses but not a host on the
  path between the device and Plexus; TLS stops that too, mutual TLS
  also refuses senders without a device certificate, and **Certificate
  must name the host** refuses a device certificate used from another
  inventory host's address. Restrict the ports
  to your device networks in the firewall
  ([deploy/FIREWALL.md](../deploy/FIREWALL.md)).
