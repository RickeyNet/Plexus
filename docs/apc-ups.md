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
     enable it; under *User Profiles* set a user with SHA authentication and
     AES privacy; under *Access Control* allow the Plexus server's address
     for that user.
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
   switch or cooling module is not taken for a UPS.
3. Turn on monitoring (Monitoring > Settings) if it is not on. The first poll
   fills in the UPS's model and serial on the host.

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
| Card model, card firmware (AOS), application module and firmware, card serial | the card's `sysDescr` (`MN`, `PF`, `AN1`, `AF1`, `SN`) | `1.3.6.1.2.1.1.1.0` |

Plus, as for every SNMP host: uptime (`sysUpTime`), the card's network
interface (IF-MIB), and ICMP latency and loss. A UPS has no CPU or memory to
read, so those stay empty and their built-in alerts never fire.

Where it goes:

- **Device page** (Monitoring > a device): a *UPS* card with the output and
  battery state, capacity, runtime, load, and the UPS and card identity and
  firmware; the *Overview* charts show battery capacity, output load and
  runtime instead of CPU and memory.
- **History**: battery capacity (`ups_battery_capacity_pct`), runtime
  (`ups_runtime_minutes`), output load (`ups_output_load_pct`) and the
  output and battery state codes (`ups_output_status`, `ups_battery_status`)
  are metric samples, rolled up hourly and daily like CPU and memory, so they
  outlive the raw-poll retention. The newest state is kept per host
  (`GET /api/monitoring/hosts/{host_id}/vendor-status`).
- **Host fields**: the UPS model and serial, and the card firmware as the
  host's software version (the version that security advisories name).
- **Availability and SLA**: the host is up while it answers the poll,
  through the same pipeline as every inventory host (transitions, uptime %,
  latency, loss, SLA targets evaluated on the server).

## Alerts

Raised on the server by the monitoring poll into the monitoring alerts and
the notification channels, once per condition (deduplicated like the other
built-in checks) and resolved automatically when the UPS stops reporting it:

| Alert metric | Raised when | Severity |
|---|---|---|
| `ups_on_battery` | Output status *on battery* | Warning; critical when the battery is also low |
| `ups_battery` | Battery status low, fault or no battery present; or the replace indicator is set | Critical for low / fault / no battery, warning for replace only |
| `ups_output` | Output status off, timed sleeping or sleeping until power returns; or on bypass (software, switched, hardware failure, emergency static) | Critical when off or on hardware-failure / emergency bypass, warning on software or switched bypass |

A self-test (*on battery test*) does not alert. Each can be suppressed per
host or group (Monitoring > Suppressions). Alert rules can also use
`ups_battery_capacity_pct`, `ups_runtime_minutes` and
`ups_output_load_pct` as metrics, for example *runtime below 10 minutes* or
*load above 80 %*.

## Software versions and advisories

The software tracker lists an `apc_ups` host twice:

| Tracked device | Platform | Version |
|---|---|---|
| The host (the card) | `apc-nmc` (APC Network Management Card) | Card AOS firmware (`PF` in the sysDescr), e.g. `6.8.2` or `1.4.2.1` |
| `<host> (UPS)` | `apc-ups` (APC Smart-UPS firmware) | UPS firmware from `upsAdvIdentFirmwareRevision`, e.g. `UPS 09.3 (ID18)` tracked as `9.3` |

Advisories for either platform are entered by hand or imported (Software >
Advisories). Schneider Electric publishes its security notifications as
documents, with no version-matched vulnerability API, and Plexus has no
NVD client, so there is no automatic advisory source: this is a documented
gap in [vendor-monitoring-coverage.md](vendor-monitoring-coverage.md).

## Firmware updates

Updating the UPS firmware through the card is part of the Upgrades tool:
see [upgrade-tool-guide.md](upgrade-tool-guide.md).

## Limits

- No SNMP traps: a power event is seen at the next poll (the monitoring
  interval, 300 s by default; shorten it in Monitoring > Settings if UPS
  alerts must be faster), not when the card sends it.
- Only the first UPS of the card is read; a parallel or three-phase
  Symmetra / Galaxy system's per-module and per-phase tables are not.
- Input voltage and frequency, temperatures, outlet groups and
  environmental probes are not collected.
- `upsAdvIdentSerialNumber` is the serial of the UPS's microprocessor; on
  older UPSs it differs from the label on the rear.
- A UPS with no card (USB or serial only) cannot be monitored over the
  network.
