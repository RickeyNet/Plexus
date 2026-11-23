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
  online, reload or restart message starts a monitoring poll of that host
  within seconds, instead of waiting for the next poll.

An OPNsense firewall's messages also act when it is no inventory host: a
gateway alarm, CARP transition, VPN tunnel up / down or configuration save
starts a collection of the firewall's topology source within seconds (see
[OPNsense re-collect trigger](#opnsense-re-collect-trigger)).

The rules are set up under **Monitoring > Configure > Syslog Rules**. The
same engine runs the built-in SNMP trap rules, listed in that tab below the
syslog rules, as their own alert family: see [SNMP Traps](snmp-traps.md).

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
| Interface flapping (`syslog_link_flap`) | An interface going down: `LINK-3-UPDOWN` and `LINEPROTO-5-UPDOWN` ... `changed state to down`, IOS XR `PKT_INFRA-LINK-3-UPDOWN` / `PKT_INFRA-LINEPROTO-5-UPDOWN`, ASA `411002`, NX-OS `ETHPORT-5-IF_DOWN_LINK_FAILURE` / `IF_DOWN_ERROR_DISABLED` / `IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN`, Junos `SNMP_TRAP_LINK_DOWN` with `ifAdminStatus up`, FortiOS `FGT-0100020099` (Interface status changed) `Interface <name> was turned down`, PAN-OS `link-change` `<port>: Down ...`, AOS-CX `AOSCX-404` `Link status for interface <name> is down`, AOS-Switch `AOSS-00077` `port <name> is now off-line` | Time only | 3 within 10 min, per interface | 30 min | warning | Cisco IOS / IOS XE, IOS XR, NX-OS, ASA, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| OSPF neighbor down (`syslog_ospf_neighbor`) | `OSPF-5-ADJCHG` / `OSPFv3-5-ADJCHG` / IOS XR `ROUTING-OSPF-5-ADJCHG` ... `to DOWN`, NX-OS `OSPF-5-NBRSTATE` ... `to DOWN` and `OSPF-5-ADJCHANGE` ... `went DOWN`, EOS `OSPF-4-OSPF_ADJACENCY_TEARDOWN`, Junos `RPD_OSPF_NBRDOWN`, FortiOS `FGT-0103020302` (OSPF neighbor status changed) `ADJCHANGE: neighbor <if:local-remote> Down`, PAN-OS `routed-OSPF-neighbor-down` (one alert per firewall: the message names no neighbor), AOS-CX `AOSCX-2401` / `AOSCX-2404` `AdjChg: Nbr <router-id> on <interface>...: <state> -> Down`, AOS-Switch `AOSS-02703` `ADJCHG: Neighbor with Router ID <id> on <interface> moved to <state> state - adj lost` | The same tags ... `to FULL` / `went FULL`, EOS `OSPF_ADJACENCY_ESTABLISHED`, Junos `RPD_OSPF_NBRUP`, FortiOS `... neighbor <if:local-remote> Up`, PAN-OS `routed-OSPF-neighbor-full`, AOS-CX `... -> Full`, AOS-Switch `... - adj formed` | Every match, per neighbor | Clear message only | critical | Cisco IOS / IOS XE, IOS XR, NX-OS, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| BGP neighbor down (`syslog_bgp_neighbor`) | `BGP-5-ADJCHANGE` / IOS XR `ROUTING-BGP-5-ADJCHANGE` / FortiOS `FGT-0103020300` (BGP neighbor status changed) `neighbor X Down`, `BGP-5-NBR_RESET`, EOS `BGP-5-ADJCHANGE` `old state Established ... new state` other than Established, Junos `RPD_BGP_NEIGHBOR_STATE_CHANGED` `from Established to` another state, PAN-OS `routed-BGP-peer-left-established`, AOS-CX `AOSCX-2902` `<peer>: Peer down. ...`, AOS-Switch `AOSS-03073` `BGP: Peer down` (one alert per switch: the message names no peer) | `neighbor X Up`, EOS `new state Established`, Junos `to Established`, PAN-OS `routed-BGP-peer-enter-established`, AOS-CX `AOSCX-2901` `<peer>: Peer up. ...`, AOS-Switch `AOSS-03072` `BGP: Peer up` | Every match, per neighbor | Clear message only | critical | Cisco IOS / IOS XE, IOS XR, NX-OS, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| Power supply fault (`syslog_power_supply`) | IOS XE `IOSXE_PEM-3-PEMFAIL`, Catalyst 9000 `PLATFORM_FEP-1-FRU_PS_SIGNAL_FAULTY`, Catalyst 3750-X / 3560-X `PLATFORM_ENV-1-FRU_PS_SIGNAL_FAULTY`, NX-OS `PLATFORM-2-PS_FAIL`, EOS `PWRMGMT-3-PSU_STATUS_FAILED` and `PWRMGMT-4-INPUT_POWER_LOSS`, Junos `CHASSISD_SNMP_TRAP*` `Power Supply failed`, FortiOS `FGT-0100022105` (Power supply failed) and `FGT-0100022114` (Power supply failed warning), PAN-OS `ps-failure` `Alarm on Power Supply #<n>`, AOS-CX `AOSCX-304` `PSU <name> faulted`, AOS-Switch `AOSS-00071` `Power Supply failure: Supply: <Main or RPS>- ...` and `AOSS-02797` `Internal power supply <bay> is faulted` | `IOSXE_PEM-6-PEMOK`, `PLATFORM_FEP-6-FRU_PS_SIGNAL_OK`, `PLATFORM-2-PS_OK`, EOS `PWRMGMT-3-PSU_STATUS_OK`, Junos `Power Supply OK`, FortiOS `FGT-0100022104` (Power supply restored) and `FGT-0100022115` (Power supply restored notification), AOS-Switch `Power Supply OK: ...` and `Internal power supply <bay> is ok`; PAN-OS and AOS-CX by time only | Every match, per power supply (FortiOS and 3750-X: per device) | 24 h | critical | Cisco IOS XE (ASR 1000, ISR 4000, Catalyst 9000), Catalyst 3750-X / 3560-X, NX-OS, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| Fan fault (`syslog_fan`) | IOS XE `IOSXE_PEM-3-FANFAIL`, Catalyst 2960 / 3560 / 3750 `HARDWARE-2-FAN_ERROR`, Catalyst 3750-X / 3560-X `PLATFORM_ENV-1-FAN` and `PLATFORM_ENV-1-FRU_PS_FAN_FAILED`, ISR G2 `ENVMON-3-FAN_FAIL` (older ISRs `FAN_FAILED`), NX-OS `PLATFORM-2-FANMOD_FAN_FAIL`, EOS `ENVMON-3-FANFAILED`, Junos `CHASSISD_SNMP_TRAP*` `Fan/Blower failed`, PAN-OS `fan-failure` `Alarm on Fan Tray #<n>`, FortiOS `FGT-0100022108` (Fan anomaly), AOS-CX `AOSCX-214` `...: Fan <name> faulted, reason: ...`, AOS-Switch `AOSS-00070` `Fan failure: Fan: <n> ...` | `IOSXE_PEM-6-FANOK`, ISR G2 `ENVMON-3-FAN_OK`, `PLATFORM-2-FANMOD_FAN_OK`, EOS `ENVMON-3-FANOK`, Junos `Fan/Blower OK`, FortiOS `FGT-0100022151` (Fan normal), AOS-Switch `Fan OK: Fan: <n> ...`; the classic Catalyst, PAN-OS and AOS-CX forms by time only | Every match, per fan (FortiOS: per device) | 24 h | warning | Cisco IOS XE (ASR 1000, ISR 4000), Catalyst 2960 / 3560 / 3750 (classic IOS), ISR G2, NX-OS, Arista EOS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |
| Module down (`syslog_module`) | IOS XE `IOSXE_OIR-6-OFFLINECARD` `Card (<type>) offline in slot <slot>` and `IOSXE_OIR-6-REMCARD` `Card (<type>) removed from [chassis <n> ]slot <slot>`, SPAs and line card sub-modules `IOSXE_OIR-6-REMSPA` `SPA removed from subslot <s/b>, interfaces disabled`, `SPA_OIR-6-OFFLINECARD` `SPA (<type>) offline in subslot <s/b>` and `SPA_OIR-6-REMCARD` `Card removed from subslot <s/b>, interfaces disabled`, Catalyst 3750 / 2975 stack `STACKMGR-4-SWITCH_REMOVED` `Switch <n> has been REMOVED from the stack`, Catalyst 6500 `C6KPWR-SP-4-DISABLED` `power to module in slot <n> set off (<reason>)`, NX-OS `MODULE-2-MOD_FAIL`, `MODULE-2-MOD_FAILURE`, `MODULE-2-MOD_NOT_ALIVE`, `PLATFORM-2-MOD_REMOVE`, `PLATFORM-2-MOD_PWRDN`, `PLATFORM-2-MOD_PWRFAIL`, `PLATFORM-3-MOD_PWRFAIL_MULTI`, `PLATFORM-2-MOD_PWRDENY`, `PLATFORM-3-MOD_BRINGUP_MULTI_LIMIT` and, for fabric modules, `PLATFORM-2-XBAR_REMOVE`, `PLATFORM-5-XBAR_PWRDN`, `PLATFORM-3-XBAR_PWRFAIL`, Junos `CHASSISD_SNMP_TRAP*` `FRU removal` / `FRU power off` / `FRU failed` / `FRU offline` of an FPC, PIC, routing engine, control board, SIB, SFM, FEB, switch fabric board, line card chassis or adapter card (not when `jnxFruOfflineReason` is 5, 7 or 8: powered off in the configuration, by a CLI command or the offline button) | IOS XE `IOSXE_OIR-6-ONLINECARD` and `SPA_OIR-6-ONLINECARD` `... online in [chassis <n> ]slot / subslot ...`, stack `STACKMGR-5-SWITCH_READY` `Switch <n> is READY`, NX-OS `MODULE-5-MOD_OK` `Module <n> is online`, `MODULE-5-ACTIVE_SUP_OK` / `STANDBY_SUP_OK` `Supervisor <n> is active / standby`, `MODULE-5-XBAR_OK` `Xbar <n> is online`, Junos `FRU online`; the Catalyst 6500 form by time only | Every match, per slot / subslot (IOS XE `<chassis>/<slot>` on StackWise Virtual), stack member, NX-OS module or `Xbar <n>`, Junos `jnxFruName` | 24 h | critical | Cisco IOS XE (Catalyst 9400 / 9600, StackWise Virtual, ASR 1000, ISR 4000), Catalyst 3750 / 2975 stacks (classic IOS), Catalyst 6500 (classic IOS), NX-OS, Juniper Junos |
| Repeated login failures (`syslog_auth_failure`) | `SEC_LOGIN-4-LOGIN_FAILED`, IOS XR `SECURITY-LOGIN-4-AUTHEN_FAILED`, NX-OS `AUTHPRIV-3-SYSTEM_MSG` with `Authentication failed`, ASA `113005`, `113015`, `605004`, `611102`, Junos `SSHD_LOGIN_FAILED`, `LOGIN_FAILED`, program `sshd` `Failed password for ...` / `Failed keyboard-interactive/pam for ...` (Arista EOS and other OpenSSH hosts), OPNsense program `audit` `user ... could not authenticate for ...` (web GUI, and SSH through the firewall's authentication), FortiOS `FGT-0100032002` (Admin login failed), PAN-OS `auth-fail` (not the ones about the authentication server: `Time clock does not match ...`, `Wrong realm ...`, `Server certificate: ...`, `KDC Spoofing ...`), AOS-CX `AOSCX-5210` and `AOSCX-5216` (SSH login failed), AOS-Switch `AOSS-00419` (invalid user name / password) and `AOSS-03345` (SSH login failed) | Time only | 5 within 5 min, per device (from any source) | 30 min | warning | Cisco IOS / IOS XE, IOS XR, NX-OS, ASA, Arista EOS, Juniper Junos, OPNsense, Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba AOS-CX, AOS-Switch |

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
  login, configuration or reload message), from keywords in its tag (or program
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
| Cisco ASA | `111008` (a configuration command); `111010` except `show`, `ping`, `traceroute`, `more` and `dir` |
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
| Reload: `SYS-5-RELOAD`, ASA `199001`, NX-OS `PLATFORM-2-PFM_SYSTEM_RESET`, Junos `UI_REBOOT_EVENT`, FortiOS `FGT-0100032138` (Device rebooted) and `FGT-0100032200` (Device shutdown), AOS-Switch `AOSS-00063` (SYSTEM went down), AOS-CX `AOSCX-706` (Initiating system reboot) and `AOSCX-707` (Initiating chassis thermal reboot) | 30 s (the device logs it before it goes down) |
| Restart: `SYS-5-RESTART`, `SYS-6-BOOTTIME`, ASA `199002`, Junos `SNMPD_TRAP_COLD_START`, FortiOS `FGT-0100032009` (FortiGate started), AOS-Switch `AOSS-00066` (System Booted) and `AOSS-00064` (the crash reason of a switch that went down), AOS-CX `AOSCX-1206` (Module rebooted) and `AOSCX-1236` (Module unexpected reboot) | 5 s |

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
  Palo Alto PAN-OS, HPE Aruba AOS-CX and AOS-Switch forms, and the classic
  Catalyst, ISR G2 and Arista EOS power supply and fan forms, were written
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
  after 24 hours. The reference lists no reload or restart event, so none
  is built in. `auth-fail` is logged for every authentication the firewall
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
  and ISR G2 power supply messages are not built in: no Cisco reference
  that names their `ENVMON` power supply mnemonics was found (the ISR G2
  troubleshooting guide and the Cisco IOS system message guides could not
  be retrieved). Write a custom **Tag** rule for the power supply message
  your routers log.
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
  - **Catalyst 4500** (`C4K_CHASSIS`, `C4K_IOSMODPORTMAN`): no reference
    giving the module removed / failed message text was retrieved.
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
  - **Cisco IOS XR, Arista EOS, HPE Aruba AOS-CX and AOS-Switch, Fortinet
    FortiOS, Palo Alto PAN-OS**: no module, line card or stack member
    message form was confirmed in a reference (the IOS XR system error
    message reference, the Arista EOS System Message Guide and the HPE
    Aruba event log references could not be retrieved, and no FortiOS or
    PAN-OS log reference entry for a module or slot event was found). AOS-CX `AOSCX-1206` /
    `AOSCX-1236` (Module rebooted) stay restart re-poll triggers. Write a
    custom **Tag** rule for the module messages your devices log; the
    polled module check covers Cisco and Juniper over SNMP.
- **Netgear and APC** send syslog in their own formats; no built-in rule
  or trigger matches them. Custom rules work on them.
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
