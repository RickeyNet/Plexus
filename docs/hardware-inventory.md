# Hardware inventory

Plexus keeps a list of every hardware component with a serial number on
each inventory host: the chassis, stack members, supervisors, line cards
and other modules, power supplies, fan trays and pluggable transceivers. It
keeps the history of those components too, so you can see when a module
was replaced (old serial and new serial), installed, removed, moved to
another slot, or changed (a new model or revision under the same serial).

The device page has a **Hardware** tab with the components and their
history. The **Hardware** page (in the sidebar after Inventory) lists every
component across devices (search by serial, model, name, slot or hostname,
export as CSV) under **Components**, and every change under **Changes**.

This is separate from the single chassis serial on the host record
(`hosts.serial_number`, read by discovery or the **Fetch serial** action).
That serial is filled from the chassis component only when the host has
none; it is never overwritten, because discovery matches hosts by it.

## Who can use it

| Action | Needs |
|---|---|
| See a host's components and history, the fleet lists and the CSV | The `inventory` feature |
| Read a host's components now (**Refresh hardware**) | `inventory` and `inventory.write` |

Accounts limited to selected inventory groups see the components and
history of the hosts of those groups only. The history of a deleted host
is shown to unrestricted accounts only.

## What is read, per vendor

| Platform (inventory device type) | Source | Notes |
|---|---|---|
| Cisco IOS, IOS XE, NX-OS, IOS XR, ASA, FTD | SNMP ENTITY-MIB `entPhysicalTable`; SSH `show inventory` with **Fetch serial** | Both tested with invented rows and output only. |
| Juniper Junos (`juniper`, `juniper_junos`) | SNMP JUNIPER-MIB `jnxContentsTable` plus the box serial (`jnxBoxSerialNo`); ENTITY-MIB when the Juniper table lists no serial | Whether a given Junos release also answers ENTITY-MIB is not confirmed; the Juniper table is read first. Category from `jnxFruType` of the same index. |
| Arista EOS, Palo Alto PAN-OS, Fortinet FortiOS, HPE Aruba AOS-Switch and AOS-CX, Netgear | SNMP ENTITY-MIB `entPhysicalTable` | Standard MIB; what each platform lists in it (and whether it lists transceivers) is not confirmed against a live device. No SSH source. |
| Any other SNMP-polled device type | SNMP ENTITY-MIB | Read when the device answers it; nothing stored otherwise. |
| APC UPS, ICMP-only hosts | Not read | No ENTITY-MIB component table. |
| API sources (Meraki, Cato, AWS, Azure, GCP and others) | Not read | Not inventory hosts with SNMP; their serials come from the vendor API views. |

Over SSH only the Cisco `show inventory` form is parsed (one parser for all
six Cisco platforms). Other vendors' SSH inventory commands (Junos `show
chassis hardware`, EOS `show inventory`, and so on) are not read.

### The SNMP read

One walk of the serial column `entPhysicalSerialNum`
(1.3.6.1.2.1.47.1.1.1.1.11). Only rows with a real serial are kept: empty
values, "N/A", "Unknown", "none", all-zero strings and pysnmp's "no such
instance" answers are dropped. For those rows only, the other columns are
read with GETs of 20 objects each: description, contained-in, class,
parent position, name, hardware, firmware and software revision, model
name and the field-replaceable flag; then the class and name of their
parents that have no serial (to locate a component and to tell an optic
sitting in a port).

For Junos the walk is of `jnxContentsSerialNo` (1.3.6.1.4.1.2636.3.1.8.1.7),
then GETs of the description, revision, part number, chassis description,
model and `jnxFruType` of those rows and the three box scalars.

### Category

| Category | ENTITY-MIB rule |
|---|---|
| `chassis` | Class chassis(3) |
| `power_supply` | Class powerSupply(6) |
| `fan` | Class fan(7) |
| `transceiver` | Class port(10) with its own serial, a row contained in a port, or a row whose model or description starts with an optic family (SFP, QSFP, XFP, GBIC, CFP, GLC- ...) or whose name or description says "transceiver" or is an interface name |
| `module` | Class module(9) not matched above |
| `other` | Any other class (stack, container, CPU, sensor ...) |

Over SSH the category comes from the text: an optic PID, description or
interface name is a transceiver; "power supply", "PSU" or "PEM" a power
supply; "fan" a fan; a name "Chassis", "Rack 0" or "Switch 2" (a stack
member), or a chassis description on a name that is not a slot's, the
chassis; anything else with a PID a module. On Junos, `jnxFruType` gives
modules, power supplies and fans; "Xcvr" rows are transceivers.

### Slot

`slot` is where the component sits: its `entPhysicalName` ("Slot 3
Linecard", "Power Supply Module 1", "Te1/1/1"), else the name of its
parent, else its description. Over SSH it is the `show inventory` NAME; on
Junos the `jnxContentsDescr` ("FPC: ... @ 0/*/*", "PEM 0").

### One component per serial

A fixed switch often reports its built-in module with the chassis serial,
and a stack member's module with the member's serial. Two rows of one read
with the same serial are one component: the row of the first category in
the order chassis, module, power supply, fan, transceiver, other; then a
field replaceable unit before one that is not; then the first in MIB
order. Serials are compared trimmed and without regard to case.

## When it is read

* **By the monitoring poll**, for a host that answered SNMP in that poll
  (sysUpTime or the interface table), at most once every 6 hours
  (`COLLECT_INTERVAL_SECONDS`). The time of the last complete read is
  stored per host, so a restart does not cause a read of every host.
* **Sooner after a hardware event.** A module going down or coming online,
  a reload or a restart, from the built-in syslog rules or SNMP trap rules,
  marks the host: its next poll that reaches the device reads the
  components too (the re-poll those rules schedule, or the next scheduled
  poll after a reload). The mark is kept in memory; a server restart drops
  it and the 6-hour read catches the change instead.
* **While something is pending.** While a component is missing (absent
  from a complete read, not yet removed) or an empty read waits for
  confirmation, every poll reads again.
* **After a read that was not read** (a timeout), the poll tries again
  after 30 minutes, not at every poll.
* **On demand**: **Refresh hardware** on the device page's Hardware tab
  (`POST /api/hosts/{host_id}/hardware/refresh`) reads the host now with its
  SNMP profile (its own, else its group's). The SNMP credentials go only to
  a host whose address an admin set or confirmed, unless an admin asks.
* **Over SSH**: **Fetch serial** (one host or a whole group) also runs
  `show inventory` on Cisco hosts and stores the components (source `ssh`),
  unless the host has a complete SNMP read from the last 12 hours (twice
  the poll's interval). SNMP is the source of a host it works on, SSH the
  source of a host it does not; the two do not take turns on one host,
  because they name slots differently and some components are listed
  by one and not the other (they would go missing, be removed and be
  installed again at each switch). The response then counts 0
  components for that host.

## Three outcomes of a read

* **Not read**: the walk was cut short (a timeout, or its row cap of 20,000
  rows: every entity of the device is walked, with or without a serial),
  a GET of the rows went unanswered, or the device listed more than 2,000
  serials. Nothing changes; the host shows "not read" with the reason, and
  the last complete read stays.
* **Read with components**: compared with the stored ones (below).
* **Read with none**: for a host with stored components this is not
  believed at once (a device just after a reload may list nothing); it
  counts as not read until it happens in 3 reads in a row. A host with no
  stored component simply has none.

## How each change is decided

The identity of a component is its serial on that host. The SNMP index
(`entPhysicalIndex`) is not used: a reload may renumber it, and a
renumbered index alone is no change.

| Event | When |
|---|---|
| `baseline` | The first read with components of a host: one event for the host with the count ("First hardware read: 14 components with a serial."), no event per component. |
| `replaced` | A slot now holds a serial other than the present or missing one stored for it, and the stored one is not in the read. Recorded at once (no `removed` event); the old component is marked removed, and the event names the previous serial and model. Also when the slot's component was already removed (a swap that took longer than the removal confirmation) within the last 30 days (`REPLACE_WINDOW_SECONDS`): the event names the most recently removed one and its detail says when it was removed. |
| `installed` | A serial not present on the host before, in a slot with no present or missing component and none removed from it in the last 30 days, or the same serial back after it was removed. When that serial was last seen on another host (present or removed there), the event carries that host in `previous_host_id` / `previous_hostname` (its `detail` does not name it; a caller who cannot read that host gets both fields empty). |
| `moved` | The same serial in another slot name on the same host. |
| `removed` | A component absent from a complete read after it has been missing for at least 30 minutes (`REMOVE_CONFIRM_SECONDS`). The first complete read without it marks it `missing` (no event) and records when; the host is read at every poll while it is missing; if it is back before it is removed, nothing happened and it is `present` again. Time and not only a count of reads decides it: with a poll every few minutes, a line card still booting after a chassis reload would otherwise read as removed and installed again. |
| `changed` | The same serial with another model, hardware, firmware or software revision. Both values must be set: a value that appears or goes blank is stored without an event (a blank value keeps the stored one). |

When a read comes from another source than the stored components (SNMP
after SSH, or the other way), slot names are not comparable (the two
sources name slots differently), so that read matches by serial only: no
`replaced`, `moved` or `changed` is inferred from it. Components it does
not list go missing, and new serials are `installed`, as usual.

A removed serial that comes back on the same host is `installed` again.

## Limits and gaps

* Nothing has been read from a live device in development: the readers are
  tested with invented ENTITY-MIB and JUNIPER-MIB rows and invented `show
  inventory` output. What each platform puts in ENTITY-MIB (transceivers
  in particular) is not confirmed.
* No alert is raised for a hardware change; the history is for looking
  back. Module failures alert through the module health checks and syslog
  and trap rules ([monitoring.md](monitoring.md)).
* SSH collection is Cisco `show inventory` only, and only with **Fetch
  serial**; the poll does not log in over SSH for it.
* A component without a serial (many fans and sensors) is not listed.
* Two hosts in the inventory that are the same device list the same
  serials twice.
* The history is not pruned automatically ([DATA_RETENTION.md](../DATA_RETENTION.md)).

## API

See [api-reference.md](api-reference.md#hardware-inventory).
