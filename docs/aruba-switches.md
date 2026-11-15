# HPE Aruba and HP switches

Plexus manages three families of HPE Aruba Networking switches as inventory
hosts. Which one a switch is decides what Plexus can do with it, because the
families do not offer the same management interfaces.

| Family | Device type | SNMP | SSH | Examples |
|---|---|---|---|---|
| AOS-CX | `aruba_aoscx` | Yes | Yes | CX 6000, 6100, 6200, 6300, 6400, 8xxx |
| AOS-Switch (ArubaOS-Switch, HP ProCurve) | `aruba_osswitch` (also `aruba_procurve`, `hp_procurve`) | Yes | Yes | 2530, 2540, 2920, 2930F/M, 3810M, 5400R, ProCurve 2510/2610/2910 |
| Instant On | `aruba_instant_on` | Yes, read-only | **No** | Instant On 1830, 1930, 1960 |

The device type is set on the host (Inventory, *Device type*). Discovery and
the *Add to inventory* dialog of the topology map suggest it from the
switch's SNMP system description.

## What each family supports

| Feature | AOS-CX | AOS-Switch / ProCurve | Instant On |
|---|---|---|---|
| Availability, latency, loss, SLA targets (ICMP + SNMP) | Yes | Yes | Yes |
| Interface state and counters, graphs (IF-MIB) | Yes | Yes | Yes |
| CPU and memory | HOST-RESOURCES-MIB | HP `STATISTICS-MIB` and `NETSWITCH-MIB` | HOST-RESOURCES-MIB, when the switch answers it |
| Topology links (LLDP over SNMP) | Yes | Yes | Yes |
| MAC and ARP tracking (SNMP) | Yes | Yes | Yes |
| VLANs, ports, neighbors and MAC table over SSH | Yes | Yes | No |
| Route table collection | Yes | Yes | No |
| Configuration backup, drift, compliance, risk analysis | Yes | Yes | No |
| Configuration push (jobs, deployments, playbooks) | Yes | Yes | No |
| Path trace (ACLs and routes from the backup) | Yes | Yes | No |
| SNMPv3 setup playbook | Yes | Yes | No |
| Model, serial and version at discovery | SNMP + `show version` / `show system` | SNMP + `show version` / `show system information` | SNMP |
| Software version tracking | Platform `aos-cx` | Platform `aos-switch` | Platform `instant-on` |
| NetFlow / sFlow setup, software upgrade tool | No | No | No |

## Instant On switches (1830, 1930, 1960)

An Instant On switch has no command line: there is no SSH or Telnet server
on it, in either management mode. It is configured from the Instant On
portal or mobile app (cloud mode) or from its own web interface (local
mode). Plexus therefore monitors it and cannot configure it.

To monitor one:

1. Put the switch in **local management mode**. SNMP cannot be enabled on a
   switch managed from the Instant On cloud portal. Changing the mode resets
   the switch to its factory defaults.
2. In the switch's web interface, open **Setup Network → SNMP**, enable
   SNMP and set a read-only community. The 1830 answers SNMPv1 and v2c with
   a read-only community; it has no SNMPv3 and accepts no SNMP writes.
3. In Plexus, add the switch to an inventory group with the device type
   **Aruba Instant On**, and give the group or the host an SNMP profile with
   that community (v2c).

Plexus then polls it like any SNMP host. No SSH session is opened to a host
of this type: the monitoring poll's SSH step and the inventory collection
skip it, and anything that needs a session (a configuration capture or
restore, a show command, a playbook) is refused with a message saying the
device has no command line. The same switch added with an SSH device type
would fail each of those with a connection timeout instead.

## AOS-CX

Commands Plexus sends over SSH:

| Purpose | Command |
|---|---|
| Configuration backup | `show running-config`; `show running-config all` for backup search |
| Save after a push | `write memory` |
| Routes | `show ip route`, `show ip route all-vrfs` |
| VLANs | `show vlan` |
| Ports | `show interface` |
| Neighbors | `show lldp neighbor-info detail` |
| MAC addresses | `show mac-address-table` |
| Version, serial | `show version`, `show system` |

A VLAN shut down in the configuration is stored as suspended; one that is
down only because no port is up is stored as active. AOS-CX has no route
summary command, so the monitoring poll reads the whole table at each route
collection.

## AOS-Switch and HP ProCurve

`aruba_osswitch`, `aruba_procurve` and `hp_procurve` are one platform.

| Purpose | Command |
|---|---|
| Configuration backup | `show running-config` |
| Save after a push | `write memory` |
| Routes | `show ip route` |
| VLANs | `show vlans`; the `vlan N` blocks of the configuration when it is not parsed |
| Ports | `show interfaces brief` and `show interfaces status` |
| Neighbors | `show cdp neighbors detail`, `show lldp info remote-device` |
| MAC addresses | `show mac-address` |
| Version, serial | `show version`, `show system information` |

`show interfaces status` gives the port names and VLANs. A release that does
not have it still stores the ports, without names or VLANs. A port with
several tagged VLANs prints `multi`; the port is stored as a trunk whose
allowed VLANs are unknown. The switch lists LLDP neighbors in its CDP table
too, by MAC address; those rows are dropped and the LLDP entry is kept.

## Ansible

The Ansible inventory maps `aruba_aoscx` to `arubanetworks.aoscx.aoscx` and
the AOS-Switch types to `community.network.procurve`. The collections are
not installed with Plexus; install the one a playbook needs on the Ansible
runner.

## Software advisories

HPE publishes security bulletins but no version-matched vulnerability API,
so advisories for the three platforms are entered by hand or imported
(`docs/software-versions.md`). See `docs/vendor-monitoring-coverage.md`.

## Limits

- The drivers are tested against sample output parsed with the same
  ntc-templates Plexus uses at run time, not against every model and
  release. A table a switch prints in a form no template parses is listed
  as *not parsed* and the stored one stays.
- AOS-CX and Instant On have no vendor CPU/memory OID set; a switch that
  does not answer HOST-RESOURCES-MIB shows no CPU or memory. A vendor OID
  override (Monitoring, vendor OIDs) can name others.
- HP Comware switches (`hp_comware`) have no driver: they are sent the
  Cisco IOS commands.
