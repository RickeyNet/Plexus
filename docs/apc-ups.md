# APC Smart-UPS

Plexus monitors an APC Smart-UPS through the APC Network Management Card
(NMC) fitted in it: NMC2 (AP9630, AP9631, AP9635) and NMC3 (AP9640,
AP9641, AP9643). The card answers SNMP with Schneider Electric's
PowerNet-MIB (enterprise `1.3.6.1.4.1.318`), and Plexus reads the UPS's
battery, output and identity from it in every monitoring poll.

| Device type | SNMP | SSH | Examples |
|---|---|---|---|
| `apc_ups` (APC Smart-UPS (NMC)) | Yes | **Not used** | SMT1500, SMX3000, SRT5K, SRTL, SMTL behind an NMC2 or NMC3 |

The card has a command line over SSH, but nothing Plexus runs over SSH
applies to a UPS (there are no routes, VLANs, neighbors or a running
configuration to back up), so the type has no SSH driver: jobs, deployments,
configuration backups, drift, compliance, inventory collection and the SSH
part of the monitoring poll skip it, the same as the SNMP-only Netgear and
Aruba Instant On switches. UPS firmware updates are the exception: they go
through the Upgrades tool, which talks to the card on its own (see
[upgrade-tool-guide.md](upgrade-tool-guide.md)).

A UPS with no card, or a card on a PDU, transfer switch or cooling unit, is
not this type: add it as an **ICMP-only** host if it has an address.

## Adding a UPS

1. On the card's web page, enable SNMP access:
   - **SNMPv3** (recommended): *Configuration > Network > SNMPv3 > Access*,
     enable it. The card has a fixed set of user profiles (four) that cannot
     be added or deleted: pick one that is not in use (its *Access Control*
     entry is disabled or has no NMS address; changing a used profile cuts
     off whatever polls with it), click its name under *User Profiles* and
     set a user name, SHA (or SHA-256) authentication and AES (or AES-256)
     privacy with their passphrases. Then click the matching entry under
     *Access Control*, enable it, select that user and enter the Plexus
     server's address as the NMS host.
   - **SNMPv1** (read-only community): *Configuration > Network > SNMPv1 >
     Access*, enable it; under *Access Control* set a community with
     *Read* access and the Plexus server's address as the NMS IP. Recent card
     firmware ships with SNMPv1 off and the community `public` changed or
     disabled; do not leave `public` in use.
   Plexus only reads: no write access is needed.
2. In Plexus, add the UPS in Inventory with the device type **APC Smart-UPS
   (NMC)** and give its group or the host an SNMP profile with the same
   version and credentials. Discovery recognises the card from its system
   description ("APC Web/SNMP Management Card ... AN1:apc_hw05_sumx_...")
   and suggests the type; a card whose application module is a PDU, transfer
   switch or cooling module is not taken for a UPS. It then reads the UPS's
   model and serial (`upsBasicIdentModel`, `upsAdvIdentSerialNumber`) in a
   second GET, since the card has no ENTITY-MIB chassis row. Without SNMP, discovery
   with an SSH credential (the card's login) also recognises it: the card
   answers `show version` with `E101: Command Not Found`, so Plexus asks
   `upsabout` and `about` in one more login and adds the UPS with its model
   and serial and the card's firmware as its software version (the AOS
   release in `about`, the same value SNMP discovery reads from the
   sysDescr; the application module's version when `about` lists no AOS
   section). Monitoring, the UPS firmware row of the software tracker and
   the alerts still need the SNMP profile.
3. Turn on monitoring (Monitoring > Settings) if it is not on. Each poll
   keeps the UPS's model and serial on the host up to date.

## What Plexus collects

Each monitoring poll (ICMP + SNMP) reads:

| Value | PowerNet-MIB object | OID |
|---|---|---|
| UPS model | `upsBasicIdentModel` | `1.3.6.1.4.1.318.1.1.1.1.1.1.0` |
| UPS firmware | `upsAdvIdentFirmwareRevision` | `1.3.6.1.4.1.318.1.1.1.1.2.1.0` |
| UPS serial | `upsAdvIdentSerialNumber` | `1.3.6.1.4.1.318.1.1.1.1.2.3.0` |
| Battery status | `upsBasicBatteryStatus` (unknown, normal, low, fault, no battery) | `1.3.6.1.4.1.318.1.1.1.2.1.1.0` |
| Battery capacity % | `upsAdvBatteryCapacity` | `1.3.6.1.4.1.318.1.1.1.2.2.1.0` |
| Runtime remaining | `upsAdvBatteryRunTimeRemaining` (TimeTicks, shown in minutes) | `1.3.6.1.4.1.318.1.1.1.2.2.3.0` |
| Battery needs replacing | `upsAdvBatteryReplaceIndicator` | `1.3.6.1.4.1.318.1.1.1.2.2.4.0` |
| Output status | `upsBasicOutputStatus` (on line, on battery, bypass, off...) | `1.3.6.1.4.1.318.1.1.1.4.1.1.0` |
| Output load % | `upsAdvOutputLoad` | `1.3.6.1.4.1.318.1.1.1.4.2.3.0` |
| Input voltage (V) | `upsHighPrecInputLineVoltage` (tenths of a volt), else `upsAdvInputLineVoltage` (volts) | `1.3.6.1.4.1.318.1.1.1.3.3.1.0`, `1.3.6.1.4.1.318.1.1.1.3.2.1.0` |
| Input frequency (Hz) | `upsHighPrecInputFrequency` (tenths of a hertz), else `upsAdvInputFrequency` (hertz) | `1.3.6.1.4.1.318.1.1.1.3.3.4.0`, `1.3.6.1.4.1.318.1.1.1.3.2.4.0` |
| Last transfer cause | `upsAdvInputLineFailCause` (no transfer, high line voltage, brownout, blackout, small / deep momentary sag, small / large momentary spike, self-test, rate of voltage change) | `1.3.6.1.4.1.318.1.1.1.3.2.5.0` |
| Output voltage (V) | `upsHighPrecOutputVoltage` (tenths of a volt), else `upsAdvOutputVoltage` (volts) | `1.3.6.1.4.1.318.1.1.1.4.3.1.0`, `1.3.6.1.4.1.318.1.1.1.4.2.1.0` |
| Battery temperature (°C) | `upsHighPrecExtdBatteryTemperature` (tenths, may be negative), else `upsHighPrecBatteryTemperature` (tenths), else `upsAdvBatteryTemperature` (degrees) | `1.3.6.1.4.1.318.1.1.1.2.3.13.0`, `1.3.6.1.4.1.318.1.1.1.2.3.2.0`, `1.3.6.1.4.1.318.1.1.1.2.2.2.0` |
| Probe temperature (°C) | `uioSensorStatusTemperatureDegC`: the first probe with a valid reading on the card's universal I/O ports (AP9335T / AP9335TH) | `1.3.6.1.4.1.318.1.1.25.1.2.1.6` (table) |
| Card model, card firmware (AOS), application module and firmware, card serial | the card's `sysDescr` (`MN`, `PF`, `AN1`, `AF1`, `SN`) | `1.3.6.1.2.1.1.1.0` |

A reading the UPS does not answer (no such object on an older model, or the
"not present" value: 255 for the two older temperature objects, -1 for a
probe) is empty, never 0. A real 0 is kept: the input reads 0 V during a
blackout.

Plus, as for every SNMP host: uptime (`sysUpTime`), the card's network
interface (IF-MIB), and ICMP latency and loss. A UPS has no CPU or memory to
read, so those stay empty and their built-in alerts never fire.

The card's SNMP agent is small: it answers SNMPv3 slowly and holds few
requests at a time. Plexus polls a UPS in one SNMP session, one request
after the other: the objects above are read in a few GET requests (ten
objects each), not a walk per object, and the interface tables are walked
one at a time. A card that does not answer the first request is not asked
again in that poll.

Where it goes:

- **Device page** (Monitoring > a device): a *UPS* card with the output and
  battery state, capacity, runtime, load, input voltage and frequency,
  output voltage, last transfer cause, battery (and probe) temperature, and
  the UPS and card identity and firmware; the *Overview* charts show battery
  capacity, output load, runtime, input / output voltage, input frequency
  and temperature instead of CPU and memory.
- **History**: battery capacity (`ups_battery_capacity_pct`), runtime
  (`ups_runtime_minutes`), output load (`ups_output_load_pct`), input and
  output voltage (`ups_input_voltage_v`, `ups_output_voltage_v`), input
  frequency (`ups_input_frequency_hz`), battery and probe temperature
  (`ups_battery_temperature_c`, `ups_probe_temperature_c`) and the output
  and battery state codes (`ups_output_status`, `ups_battery_status`) are
  metric samples, rolled up hourly and daily like CPU and memory, so they
  outlive the raw-poll retention. The newest state is kept per host
  (`GET /api/monitoring/hosts/{host_id}/vendor-status`).
- **Host fields**: the UPS model and serial, and the card firmware as the
  host's software version (the version that security advisories name).
- **Role**: an `apc_ups` host is in the `ups` device category with the UPS
  role, so the Topology map draws it with the UPS (battery) icon and the
  Ansible inventory can filter on `device_category=ups`. A CDP / LLDP
  neighbor whose platform is a UPS card is drawn the same way. A role set by
  hand is kept.
- **Availability and SLA**: the host is up while it answers the poll,
  through the same pipeline as every inventory host (transitions, uptime %,
  latency, loss, SLA targets evaluated on the server).

## Alerts

Raised on the server by the monitoring poll (and by the UPS's SNMP traps,
below) into the monitoring alerts and the notification channels, once per
condition (deduplicated like the other built-in checks) and resolved
automatically when the UPS stops reporting it:

| Alert metric | Raised when | Severity |
|---|---|---|
| `ups_on_battery` | Output status *on battery* | Warning; critical when the battery is also low |
| `ups_battery` | Battery status low, fault or no battery present; or the replace indicator is set | Critical for low / fault / no battery, warning for replace only |
| `ups_output` | Output status off, timed sleeping or sleeping until power returns; or on bypass (software, switched, hardware failure, emergency static) | Critical when off or on hardware-failure / emergency bypass, warning on software or switched bypass |
| `ups_overload` | Output load 100 % or more of the UPS's rating | Critical |
| `ups_battery_temperature` | Battery temperature 40 °C or more | Warning from 40 °C, critical from 50 °C |
| `ups_communication` | Trap only: the card lost communication with the UPS (`communicationLost`, `onbatterycommunicationLost`) | Critical; resolved by `communicationEstablished` or by a poll that reads a known output state |

The temperature thresholds are one constant, `BATTERY_TEMPERATURE_C` in
`netcontrol/integrations/apc/snmp.py`: lead-acid batteries are rated at
20-25 °C and lose about half their life for every 8-10 °C above that, so
40 °C is already a sustained problem and 50 °C an urgent one.

A self-test (*on battery test*) does not alert. Each can be suppressed per
host or group (Monitoring > Suppressions). Input voltage and frequency have
no built-in alert, since the right band depends on the mains (230 V / 50 Hz
or 120 V / 60 Hz) and on the UPS's own transfer points: use alert rules.
Alert rules can use `ups_battery_capacity_pct`, `ups_runtime_minutes`,
`ups_output_load_pct`, `ups_input_voltage_v`, `ups_input_frequency_hz`,
`ups_output_voltage_v`, `ups_battery_temperature_c` and
`ups_probe_temperature_c` as metrics, for example *runtime below 10
minutes*, *load above 80 %*, *input voltage below 207 V* or *probe
temperature above 30 °C*.

### No alerts, or no UPS state

A UPS that is on line with a healthy battery raises nothing: the alerts
above appear only while a condition holds. The Software page's
vulnerability alerts need an advisory for the `apc-nmc` or `apc-ups`
platform, and none is fetched automatically (see below). To tell a quiet UPS
from one Plexus cannot read, open **Monitoring > the device**: the *UPS*
card shows the output and battery state of the last poll. When the card is
missing:

- **Monitoring is off.** It is off on a new installation: turn it on in
  **Monitoring > Settings**. Nothing is polled, stored or alerted on until
  then, and the `<host> (UPS)` row of the software tracker stays absent.
- **The host has no SNMP profile**, or its group's profile is not the
  card's: the poll uses the host's own profile, else its group's.
- **The card does not answer.** Each poll that reads no state logs
  `monitoring: no UPS state read from <host> over SNMP: <reason>` on the
  server. *No SNMP response received before timeout* is the card's access
  control (the NMS address of the SNMPv3 access entry), a firewall, or
  SNMPv3 switched off; *Unknown USM user*, *Wrong SNMP PDU digest* and
  *Unsupported SNMP security level* are the user name, the authentication
  passphrase or protocol, and the privacy settings. Discovery logs the same
  reasons as `SNMP probe failed for <address>` when it falls back to SSH.

## SNMP traps

The card sends a trap the moment the UPS changes state. Plexus's SNMP trap
receiver stores every trap it accepts (Monitoring > Events) and, for a
PowerNet-MIB trap (enterprise `1.3.6.1.4.1.318`, SNMPv1 or SNMPv2c) from a
UPS in the inventory, acts on it at once:

1. **Accept**: the datagram's source must be an inventory host address
   (or in the listener allowlist's extra networks, see
   [administration.md](administration.md#listener-sources)). An SNMPv1 or
   SNMPv2c trap from an inventory host must carry the community stored
   for that host: its own SNMP profile, else its group's SNMP settings, the
   same community the poll uses. A trap with another community is dropped
   (not stored) and counted as `trap_dropped_community`.
2. **Match**: the trap's source address is looked up among the inventory
   hosts' addresses and recorded interface addresses. An SNMPv1 trap's
   agent address (a field inside the packet, as forgeable as the rest) is
   used only when the source itself is an inventory host that is not a UPS
   (a relay in inventory); a trap whose source is not an inventory host is
   stored and never acted on, so a UPS behind NAT needs its translated
   address recorded on the host. Only an `apc_ups` host is acted on, and
   only with that host's community. A trap from anything else is stored
   and nothing more.
3. **Alert**: the trap raises or resolves the built-in alert it names, under
   the same alert key the poll uses, so a trap and a poll never make two
   alerts for one condition and each resolves the other's. A suppression
   for the host, its group or the metric applies to traps too.
4. **Re-poll**: the host is polled a few seconds later (the full monitoring
   poll of that one host), so its state on the device page, its charts and
   every alert catch up. A burst of traps is one re-poll. The poll stays
   authoritative: it re-raises what the UPS still reports and resolves what
   it no longer does.

Nothing is acted on while monitoring is off (Monitoring > Settings). The
decoded trap goes through the receiver's bounded event queue: storing it
and acting on it happen in the queue's batch writer, at most about a second
after it arrived.

**Upgrading:** traps were accepted from any source with any community
before. Now a card whose trap community differs from the community stored
for its host, or whose traps arrive from an address that is not the host's
(only the v1 agent address matched it), raises and resolves nothing; set the
card's trap receiver community to the host's SNMP community and record the
address the traps come from on the host.

| Trap (number) | Effect |
|---|---|
| `upsOnBattery` (5) | Raises `ups_on_battery` (warning) |
| `powerRestored` (9) | Resolves `ups_on_battery` |
| `lowBattery` (7) | Raises `ups_battery` (critical) |
| `returnFromLowBattery` (11) | Resolves `ups_battery` |
| `upsBatteryNeedsReplacement` (17) | Raises `ups_battery` (warning) |
| `upsBatteryReplaced` (36) | Resolves `ups_battery` |
| `noBatteries` (80) / `noBatteriesCleared` (81) | Raises (critical) / resolves `ups_battery` |
| `upsOverload` (2) / `upsOverloadCleared` (33) | Raises (critical) / resolves `ups_overload` |
| `upsTurnedOff` (12), `upsSleeping` (13) | Raises `ups_output` (critical) |
| `hardwareFailureBypass` (20) | Raises `ups_output` (critical) |
| `softwareBypass` (21), `switchedBypass` (22) | Raises `ups_output` (warning) |
| `returnFromBypass` (23), `upsTurnedOn` (30), `upsWokeUp` (14) | Resolves `ups_output` |
| `communicationLost` (1), `onbatterycommunicationLost` (733) | Raises `ups_communication` (critical) |
| `communicationEstablished` (8) | Resolves `ups_communication` |
| `batteryOverTemperature` (53) / `...Cleared` (54), `upsInternalOverTemperature` (353) / `...Cleared` (354), `upsDiagnosticsFailed` (3), `upsDiagnosticsPassed` (10), `upsDischarged` (4), `dischargeCleared` (38), `upsRebootStarted` (15), and any other APC trap | Re-poll only (the battery temperature alert is evaluated by the poll against Plexus's thresholds, not the card's) |

The numbers are the TRAP-TYPE values of PowerNet-MIB; an SNMPv2c card sends
trap `1.3.6.1.4.1.318.0.<number>`. A decoded APC trap is stored with its
name, the card's text (`mtrapargsString`) and its MIB severity.

### Pointing the card at Plexus

1. **Turn on the trap receiver.** In **Settings > Syslog & Traps**, tick
   **Enabled** for SNMP traps and save. It listens on UDP 10162 (an
   unprivileged port) on every interface, and starts with Plexus from then
   on. The Docker stack publishes host port 162 to it, so the card sends to
   the standard port 162; without Docker, the card sends to 10162. Open that
   UDP port from the card's network to the Plexus server.
2. **Add Plexus as a trap receiver on the card**: *Configuration >
   Network > SNMPv1 > Trap Receivers* (NMC2: *Administration > Network >
   SNMPv1 > trap receivers*), *Add Trap Receiver*: the Plexus server's
   address as the NMS IP / host name, **SNMPv1** or **SNMPv2c** as the
   trap type, the community stored for the UPS host in Plexus (its SNMP
   profile, else its group's SNMP settings: Plexus drops a trap with any
   other community), and the port (162 with Docker, else 10162) where the
   card offers one.
3. **Enable the UPS events** for that receiver: *Configuration >
   Notification > Event Actions* (*by Event* or *by Group*), and make sure
   the trap action is on for at least *UPS: On battery*, *Power restored*,
   *Low battery*, *Battery needs replacing*, *Overload*, *Bypass*, *UPS
   turned off / on* and *Communication lost / established*. They are on by
   default for a new receiver.
4. Start a UPS self-test from the card's UPS control page: the card sends
   `upsDiagnosticsPassed` (10), which should appear in Monitoring > Events
   as *APC upsDiagnosticsPassed* with the UPS as its host.

SNMPv3 traps are received and stored, but not decoded, authenticated or
acted on (Plexus has no trap user keys): use an SNMPv1 or SNMPv2c trap
receiver for the immediate alerts, even when the poll uses SNMPv3. A host
whose SNMP profile is SNMPv3 needs a community set in that profile (the
v2c fallback community) for its v1 / v2c traps to be accepted.

## Software versions and advisories

The software tracker lists an `apc_ups` host twice:

| Tracked device | Platform | Version |
|---|---|---|
| The host (the card) | `apc-nmc` (APC Network Management Card) | Card AOS firmware (`PF` in the sysDescr), e.g. `6.8.2` or `1.4.2.1` |
| `<host> (UPS)` | `apc-ups` (APC Smart-UPS firmware) | UPS firmware from `upsAdvIdentFirmwareRevision`, e.g. `UPS 09.3 (ID18)` tracked as `9.3` |

A firmware update the Upgrades tool verified polls the UPS at once and
rebuilds the tracker, so the `<host> (UPS)` version and its alerts follow
the campaign without waiting for the next monitoring poll. Monitoring must
be enabled for that poll to run.

Advisories for either platform are entered by hand or imported (Software >
Advisories). Schneider Electric publishes its security notifications as
documents, with no version-matched vulnerability API, and Plexus has no
NVD client, so there is no automatic advisory source: this is a documented
gap in [vendor-monitoring-coverage.md](vendor-monitoring-coverage.md).

## Firmware updates

Updating the UPS firmware through the card is part of the Upgrades tool:
see [upgrade-tool-guide.md](upgrade-tool-guide.md).

## Limits

- Without the trap receiver (or with SNMPv3 traps), a power event is seen
  at the next poll (the monitoring interval, 300 s by default), not when
  the card sends it.
- The trap community is not checked: a forged trap can raise an alert, which
  the re-poll a few seconds later resolves when the UPS does not report it.
- Only the first UPS of the card is read; a parallel or three-phase
  Symmetra / Galaxy system's per-module and per-phase tables are not.
- Outlet groups, probe humidity and the probes of an external environmental
  monitor are not collected; with several temperature probes, only the
  first valid one is.
- `upsAdvIdentSerialNumber` is the serial of the UPS's microprocessor; on
  older UPSs it differs from the label on the rear.
- A UPS with no card (USB or serial only) cannot be monitored over the
  network.
