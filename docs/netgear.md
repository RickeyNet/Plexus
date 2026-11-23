# Netgear switches and access points

Plexus manages three lines of Netgear devices as inventory hosts. Which
one a device is decides what Plexus can do with it, because only the fully
managed switches have a command line.

| Line | Device type | SNMP | SSH | Examples |
|---|---|---|---|---|
| Fully managed switches | `netgear_prosafe` | Yes | Yes | M4250, M4300, M4350, M4500; M4100, M5300, M6100, M7100, GSM72xx |
| Smart switches (Smart, Smart Managed Pro, S350) | `netgear_smart` | Yes | **No** | GS108T, GS308T, GS724T, GS752TP, XS716T, MS510TX |
| Access points | `netgear_ap` | Yes, when enabled | **No** | WAX610, WAX620, WAX630, WBE750, WAC510 |

Plus switches (GS105E, GS308E, GS316EP) have neither SNMP nor a command
line: add one as an **ICMP-only** host.

The device type is set on the host (Inventory, *Device type*). Discovery and
the *Add to inventory* dialog of the topology map suggest it from the
device's SNMP system description.

This is the first stage of Netgear support. What is not built yet is listed
under [Limits](#limits).

## What each line supports

| Feature | Managed switch | Smart switch | Access point |
|---|---|---|---|
| Availability, latency, loss, SLA targets (ICMP + SNMP) | Yes | Yes | Yes |
| Interface state and counters, graphs (IF-MIB) | Yes | Yes | Yes |
| CPU and memory | HOST-RESOURCES-MIB, when the device answers it | Same | Same |
| Topology links (LLDP over SNMP) | Yes | Yes | When the access point answers LLDP-MIB |
| MAC and ARP tracking (SNMP) | Yes | Yes | No |
| VLANs, neighbors and MAC table over SSH | Yes | No | No |
| Port table over SSH | No (SNMP) | No | No |
| Route table collection | Yes | No | No |
| Configuration backup, drift, compliance | Yes | No | No |
| Configuration push (jobs, deployments) | Yes | No | No |
| Model, serial and version at discovery | SNMP + `show version` | SNMP | SNMP |
| Software version tracking | Platform `netgear-managed` | Platform `netgear-smart` | Platform `netgear-ap` |
| SNMPv3 setup playbook, NetFlow / sFlow setup, software upgrade tool | No | No | No |

## Fully managed switches

The command line of these switches derives from Broadcom's ICOS (FASTPATH).
Plexus opens the session with Netmiko's `netgear_prosafe` class and parses
the tables with the ntc-templates of `broadcom_icos`, which is the command
set the switch prints (ntc-templates has no Netgear templates).

Enable SSH on the switch (`ip ssh server enable`, after generating the
keys) and give the host a credential whose user reaches privileged mode;
set the enable password as the credential's secret when the switch asks for
one.

Commands Plexus sends over SSH:

| Purpose | Command |
|---|---|
| Configuration backup | `show running-config`; `show running-config all` for backup search |
| Save after a push | `write memory confirm` |
| Routes | `show ip route` |
| VLANs | `show vlan brief` |
| Neighbors | `show isdp neighbors`, `show lldp remote-device all` |
| MAC addresses | `show mac-addr-table` |
| Version, model, serial | `show version` |

ISDP is the switch's CDP: its neighbors are stored as CDP neighbors. The
LLDP summary table has no management address, so an LLDP neighbor is
matched to a host by its name; a neighbor that sends no system name is left
out. The switch's own addresses in the MAC table (status *Management*) are
not stored.

## Smart switches

A smart switch is configured from its web page or from Netgear Insight; it
has no SSH or Telnet server. Plexus monitors it and cannot configure it.

1. In the switch's web interface, open **System → SNMP**, and set a
   read-only community (SNMPv1/v2c) or an SNMPv3 user. A switch managed
   from the Insight cloud may not offer SNMP: manage it locally.
2. In Plexus, add the switch with the device type **Netgear smart switch**
   and give its group or the host an SNMP profile.

## Access points

An access point is configured from its web page (standalone) or from
Insight.

1. Open the access point's web interface in standalone mode and enable
   SNMP under **Management → Maintenance → Remote Management** (off by
   default; SNMPv1 and v2c with a read-only community on the WAX series).
2. In Plexus, add it with the device type **Netgear access point** and an
   SNMP profile with that community.

An access point managed from Insight that offers no SNMP is an ICMP-only
host.

No SSH session is opened to a smart switch or an access point: the
monitoring poll's SSH step and the inventory collection skip it, and
anything that needs a session (a configuration capture or restore, a show
command, a playbook) is refused with a message saying the device has no
command line.

## Software advisories

Netgear publishes security advisories as web pages, with no version-matched
vulnerability API, so advisories for the three platforms are entered by
hand or imported (`docs/software-versions.md`). See
`docs/vendor-monitoring-coverage.md`.

## Limits

- Nothing here has been run against a Netgear device. The driver is tested
  against invented sample output parsed with the same ntc-templates Plexus
  uses at run time. Those templates were written for other vendors' ICOS
  switches; a table a Netgear release prints in another form (a `lag 1`
  interface in the MAC table, for one) is listed as *not parsed* and the
  stored one stays.
- The system description formats of the three lines are taken from
  examples, and that of the access points is not known: a device discovery
  does not recognize gets its type set by hand.
- The port table is not read over SSH (ntc-templates has no template for
  `show port all`); ports, their state and their counters come from SNMP.
  VLAN membership per port is therefore not stored for these switches.
- No vendor CPU / memory OID set is built in. A switch that does not answer
  HOST-RESOURCES-MIB shows no CPU or memory until a vendor OID override
  (Monitoring, vendor OIDs) names the OIDs of its private MIB.
- The monitoring poll reads a managed switch's power supplies, fans and
  temperature sensors from NETGEAR-BOXSERVICES-PRIVATE-MIB, and the BGP
  peers and OSPF neighbors of any of the three from BGP4-MIB and OSPF-MIB
  (see `docs/monitoring.md#power-supplies-fans-and-temperature`). Smart
  switches and access points are not read for their environment.
- The path trace reads a managed switch's configuration and route table
  with the Cisco IOS reader, which was not written for them: treat its
  result for a Netgear hop as unverified.
- No built-in SNMPv3 template, no Ansible `network_os` mapping, no wireless
  client or radio data from access points, and no Netgear Insight cloud
  source.
- A VRF of an M4500 is not read: only the default routing table.
