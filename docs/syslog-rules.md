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
- **Faster down detection**: an interface-down, reload or restart message
  starts a monitoring poll of that host within seconds, instead of waiting
  for the next poll.

An OPNsense firewall's messages also act when it is no inventory host: a
gateway alarm, CARP transition, VPN tunnel up / down or configuration save
starts a collection of the firewall's topology source within seconds (see
[OPNsense re-collect trigger](#opnsense-re-collect-trigger)).

The rules are set up under **Monitoring > Configure > Syslog Rules**.

## How a message becomes an alert

1. **Source**: the message's source address is looked up among the
   inventory hosts' addresses and their recorded interface addresses (a
   device often sends syslog from an interface other than its primary
   address). A message from an address that is not in the inventory is
   stored and nothing more.
2. **Tag**: Plexus reads the message's event tag: the Cisco-style
   `%FACILITY-SEVERITY-MNEMONIC` (IOS, IOS XE, IOS XR, NX-OS, ASA, Arista
   EOS), compared without its severity digit (`%LINK-3-UPDOWN` is
   `LINK-UPDOWN`), or the Junos tag (`SNMP_TRAP_LINK_DOWN`). RFC 3164 and
   RFC 5424 headers, sequence numbers and timestamps before the tag are
   skipped. Plexus also reads the message's *program*: the RFC 5424
   APP-NAME or the RFC 3164 `program[pid]:` (`dpinger`, `charon`,
   `audit`). Messages without a tag, OPNsense's among them, are matched by
   their program and the text after it.
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
   the alert of the same host and instance. A rule with an auto-resolve
   time also resolves its alerts once no new match has arrived for that
   long (checked every minute).

Alerts are raised only while monitoring is on (Monitoring > Settings).

## Built-in rules

Built-in rules ship with Plexus. You can turn each one off or change its
severity; the patterns, threshold and auto-resolve time are fixed.

| Rule (metric) | Raised by | Resolved by | Threshold | Auto-resolve | Severity | Device families |
|---|---|---|---|---|---|---|
| Interface flapping (`syslog_link_flap`) | An interface going down: `LINK-3-UPDOWN` and `LINEPROTO-5-UPDOWN` ... `changed state to down`, IOS XR `PKT_INFRA-LINK-3-UPDOWN` / `PKT_INFRA-LINEPROTO-5-UPDOWN`, ASA `411002`, NX-OS `ETHPORT-5-IF_DOWN_LINK_FAILURE` / `IF_DOWN_ERROR_DISABLED` / `IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN`, Junos `SNMP_TRAP_LINK_DOWN` with `ifAdminStatus up` | Time only | 3 within 10 min, per interface | 30 min | warning | Cisco IOS / IOS XE, IOS XR, NX-OS, ASA, Arista EOS, Juniper Junos |
| OSPF neighbor down (`syslog_ospf_neighbor`) | `OSPF-5-ADJCHG` / `OSPFv3-5-ADJCHG` / IOS XR `ROUTING-OSPF-5-ADJCHG` ... `to DOWN`, NX-OS `OSPF-5-NBRSTATE` ... `to DOWN` and `OSPF-5-ADJCHANGE` ... `went DOWN`, EOS `OSPF-4-OSPF_ADJACENCY_TEARDOWN`, Junos `RPD_OSPF_NBRDOWN` | The same tags ... `to FULL` / `went FULL`, EOS `OSPF_ADJACENCY_ESTABLISHED`, Junos `RPD_OSPF_NBRUP` | Every match, per neighbor | Clear message only | critical | Cisco IOS / IOS XE, IOS XR, NX-OS, Arista EOS, Juniper Junos |
| BGP neighbor down (`syslog_bgp_neighbor`) | `BGP-5-ADJCHANGE` / IOS XR `ROUTING-BGP-5-ADJCHANGE` `neighbor X Down`, `BGP-5-NBR_RESET`, EOS `BGP-5-ADJCHANGE` `old state Established ... new state` other than Established, Junos `RPD_BGP_NEIGHBOR_STATE_CHANGED` `from Established to` another state | `neighbor X Up`, EOS `new state Established`, Junos `to Established` | Every match, per neighbor | Clear message only | critical | Cisco IOS / IOS XE, IOS XR, NX-OS, Arista EOS, Juniper Junos |
| Power supply fault (`syslog_power_supply`) | IOS XE `IOSXE_PEM-3-PEMFAIL`, Catalyst 9000 `PLATFORM_FEP-1-FRU_PS_SIGNAL_FAULTY`, NX-OS `PLATFORM-2-PS_FAIL`, Junos `CHASSISD_SNMP_TRAP*` `Power Supply failed` | `IOSXE_PEM-6-PEMOK`, `PLATFORM_FEP-6-FRU_PS_SIGNAL_OK`, `PLATFORM-2-PS_OK`, Junos `Power Supply OK` | Every match, per power supply | 24 h | critical | Cisco IOS XE (ASR 1000, ISR 4000, Catalyst 9000), NX-OS, Juniper Junos |
| Fan fault (`syslog_fan`) | IOS XE `IOSXE_PEM-3-FANFAIL`, NX-OS `PLATFORM-2-FANMOD_FAN_FAIL`, Junos `CHASSISD_SNMP_TRAP*` `Fan/Blower failed` | `IOSXE_PEM-6-FANOK`, `PLATFORM-2-FANMOD_FAN_OK`, Junos `Fan/Blower OK` | Every match, per fan | 24 h | warning | Cisco IOS XE (ASR 1000, ISR 4000), NX-OS, Juniper Junos |
| Repeated login failures (`syslog_auth_failure`) | `SEC_LOGIN-4-LOGIN_FAILED`, IOS XR `SECURITY-LOGIN-4-AUTHEN_FAILED`, NX-OS `AUTHPRIV-3-SYSTEM_MSG` with `Authentication failed`, ASA `113005`, `113015`, `605004`, `611102`, Junos `SSHD_LOGIN_FAILED`, `LOGIN_FAILED`, OPNsense program `audit` `user ... could not authenticate for ...` (web GUI, and SSH through the firewall's authentication) | Time only | 5 within 5 min, per device (from any source) | 30 min | warning | Cisco IOS / IOS XE, IOS XR, NX-OS, ASA, Juniper Junos, OPNsense |

A single interface down is not an alert: access ports go down all day. An
interface an operator shut down (`LINK-5-CHANGED ... administratively
down`, NX-OS `IF_DOWN_ADMIN_DOWN`, Junos `ifAdminStatus down`) is not
counted. OSPF and BGP neighbor alerts are critical because a lost
adjacency changes where traffic goes; they stay open until the neighbor
is back (or someone acknowledges the alert), since a time-out would hide
a neighbor that is still down.

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
  built-in rule or trigger (an OSPF, BGP, link, power supply, fan, login,
  configuration or reload message), from keywords in its tag (or program
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
`related`, `known_tag`) and `unknown_sources` (`source_ip`, `count`,
`last_at`).

## Configuration change trigger

These messages start a backup and drift check of the host:

| Device family | Message |
|---|---|
| Cisco IOS / IOS XE, Arista EOS | `SYS-5-CONFIG_I` |
| Cisco NX-OS | `VSHD-5-VSHD_SYSLOG_CONFIG_I` |
| Cisco IOS XR | `MGBL-CONFIG-6-DB_COMMIT` |
| Cisco ASA | `111008` (a configuration command); `111010` except `show`, `ping`, `traceroute`, `more` and `dir` |
| Juniper Junos | `UI_COMMIT_COMPLETED` |

- **Debounce**: one configuration session logs several messages, so the
  run starts 60 seconds after the host's last configuration message.
- **Cooldown**: at most one run per host every 5 minutes. Messages during
  the cooldown keep one pending run, which starts when the cooldown ends.
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
| Reload: `SYS-5-RELOAD`, ASA `199001`, NX-OS `PLATFORM-2-PFM_SYSTEM_RESET`, Junos `UI_REBOOT_EVENT` | 30 s (the device logs it before it goes down) |
| Restart: `SYS-5-RESTART`, `SYS-6-BOOTTIME`, ASA `199002`, Junos `SNMPD_TRAP_COLD_START` | 5 s |

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

- **Which source**: the message's source address is matched to the
  OPNsense source(s) of the firewall: through the inventory host it
  resolves to (the host the newest collection matched the firewall to),
  and through the firewall's API address, interface addresses and CARP
  virtual IPs from its newest collection, so a firewall that is no
  inventory host triggers too. The map is rebuilt at most once a minute.
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
the config on a change message**, **Re-poll on link down or reload** and
**Re-collect OPNsense on a state change**. Each is on by default; turning
one off stops that behaviour only, and messages are still stored.

## Device configuration

Send syslog to the Plexus server's address on the syslog receiver's port
(UDP 1514 unless Settings > Syslog & Traps says otherwise). The examples use
`192.0.2.10` for Plexus. Interface and neighbor messages are level 3 to 5,
login failures level 4 to 6, so send at least `informational` for every
rule to see its messages.

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

Send from an address Plexus knows: the host's primary address or one of
its recorded interface addresses (discovery records them), for example
with `logging source-interface` on Cisco IOS.

## Known gaps

- Only hosts in the inventory are acted on; messages from other addresses
  are stored only (except the OPNsense re-collect trigger, which also
  knows the firewalls of OPNsense sources by their collected addresses).
- Power supply and fan messages of classic IOS Catalyst switches (2960,
  3750), ISR G2 routers and Arista EOS are not built in: write a custom
  rule for the messages your hardware logs.
- Arista EOS login failures are logged by `sshd` without a tag and are not
  built in; a custom **Contains** rule (`Failed password`) covers them.
- Fortinet FortiOS, Palo Alto PAN-OS, HPE Aruba, Netgear and APC send
  syslog in their own formats; no built-in rule or trigger matches them
  yet. Custom rules work on them.
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
  backup was taken since. Messages sent while Plexus was down are lost
  (syslog over UDP is not queued by the device).
- Syslog over UDP is not authenticated: anything that can reach the
  receiver port can send a message with an inventory host's source
  address. The rate limits above bound what that can start (one backup
  per host every 5 minutes, one re-poll per host a minute, 6 OPNsense
  re-collections per source an hour); restrict the
  port to your device networks in the firewall
  ([deploy/FIREWALL.md](../deploy/FIREWALL.md)).
