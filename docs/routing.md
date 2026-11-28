# Routing (intended BGP state)

Plexus already sees the BGP neighbors of your devices. The Routing page lets
you record what each device **should** have: its autonomous systems, routing
instances and BGP peerings. Plexus then compares that intent with the
neighbors it observes and shows what matches, what is down, what is missing
and what nobody planned.

| Record | Known by | Example |
|---|---|---|
| **Autonomous system** | Its number | AS65001 "Campus core" |
| **Routing instance** | Device and name | edge-r1, `default`, local AS65001, router ID `192.0.2.1` |
| **BGP peer group** | Instance and name | edge-r1 `default`, `UPSTREAM`, remote AS65002 |
| **BGP peering** | Instance and remote address | edge-r1 `default` to `192.0.2.2`, AS65002 |

Open it from **Assets > Routing**. Reading needs the **Routing** feature;
adding, changing and deleting needs **Routing (write)** (`routing.write`).
Admins have both. Accounts limited to selected inventory groups see the
routing instances, peer groups and peerings of their devices and the
autonomous systems of their tenants (untenanted ones read only).

## Autonomous systems

An AS has a number from 1 to 4294967295 (type it as `65001`, `AS65001` or in
asdot form `1.10`), an optional description, tenant, RIR and comments. Each
number is recorded once and never changes after the record is made.

An AS that a routing instance (as its local AS) or a peering (as its remote
AS) still uses cannot be deleted; the answer says what uses it. A peer
group that names it only loses its remote AS.

## Routing instances

A routing instance is a BGP process of a device:

- **Name**: `default`, or the name of a VRF-specific instance. Unique per
  device, ignoring case.
- **Local AS** (required), **VRF** (optional; empty is the global table),
  **router ID** (an IPv4 address or empty).
- **Status**: planned, active or decommissioned.

The device of an instance never changes. Deleting an instance deletes its
peer groups and peerings; deleting a device deletes its instances.

## Peer groups and peerings

A **peer group** belongs to one instance and holds what its peerings share:
an optional remote AS and import / export policy names. Deleting a group
keeps its peerings, without a group.

A **peering** is one intended BGP session of an instance:

- **Remote address** (required) and **local address** (optional), both IP
  addresses of one family. One peering per instance and remote address.
- **Remote AS** (required).
- **Peer group** (optional; it must belong to the same instance) and **peer
  device** (when the peer is a Plexus device).
- **Status**: planned, active, disabled or decommissioned.
- **Address families**, any of `ipv4-unicast`, `ipv4-multicast`,
  `ipv4-labeled-unicast`, `ipv4-flowspec`, `ipv6-unicast`,
  `ipv6-multicast`, `ipv6-labeled-unicast`, `ipv6-flowspec`,
  `vpnv4-unicast`, `vpnv6-unicast`, `l2vpn-evpn`, `l2vpn-vpls`,
  `link-state`, `rtc` (`vpnv4`, `vpnv6` and `evpn` are accepted as
  shorthand).
- **Import / export policy** names and a description.

Lists filter by device, AS number (the local or the remote AS), status,
tenant (of the device or of the AS) and free text.

A user whose access is limited to some device groups sees a peering when
they can read the device of its instance. The peer device is named only
when they can read that device too; otherwise the peering shows no peer
device (`remote_host_id` null, `remote_hostname` empty) and keeps its
remote address and AS. Saving such a peering from the edit form keeps the
stored peer device.

## Intended vs observed (Compliance)

The **Compliance** tab compares every peering with the BGP neighbors that
neighbor discovery stored for its device (the SNMP BGP4-MIB peer table read
by topology discovery; Plexus polls nothing new for this). Each row has one
state:

| State | Meaning |
|---|---|
| **Matched** | The neighbor is observed and its session is established. |
| **Down** | The neighbor is observed, but the session is not established (idle, connect, active...). |
| **Missing** | An active peering whose neighbor is not observed. |
| **ASN mismatch** | The neighbor is observed with a different remote AS than intended. |
| **Unexpected** | An observed neighbor that no peering of the device names. |
| **No data** | Neighbor discovery has never stored anything for the device, so nothing can be said. |

Rules:

- Only **active** peerings are expected. A planned, disabled or
  decommissioned peering appears only when its neighbor is observed (and
  then its neighbor is not unexpected).
- A device counts as discovered once neighbor discovery stored any neighbor
  or interface counters for it. Until then its active peerings are **No
  data**, never **Missing**.
- Without a device selected, the tab compares the devices that have a
  routing instance. Select a device to see its unexpected neighbors even when
  it has no instance yet.

### Suggest from observed

Select a device on the Compliance tab and choose **Suggest from observed**.
Plexus lists the device's observed neighbors that have no peering, with
their remote AS and session state, and proposes established sessions as
active and the rest as planned. Nothing is created until you pick the
neighbors and confirm. You choose the instance to record them into, or
describe a new one (its local AS is needed: discovery does not read it).
Missing AS records are created along the way.

### Device page

The **Interfaces** tab of a device shows a small **BGP intent** section: the
device's instances and peerings, each with its compliance state.

### Limits of the observed data

- The BGP4-MIB peer table is IPv4 only, and holds the default instance.
  IPv6 and VRF peerings are compared, but are reported **Missing** when the
  device does not expose them over SNMP.
- A neighbor already found over CDP or LLDP on the same address is stored
  as that neighbor, not as a BGP peer.
- Cloud BGP sessions (AWS, Azure, GCP, Cato) and controller-reported ones
  (Meraki, FMC, Panorama) live in their topology collections, not on
  devices, and are not compared.

## Change log and audit

Every create, change and delete of an AS, instance, peer group or peering
is in the change log (object types `autonomous_system`,
`routing_instance`, `bgp_peer_group`, `bgp_peering`, readable with the
Routing feature) and in the audit log (category `routing`). Peer groups and
peerings deleted together with their instance are not logged one by one.

## API

All under `/api/routing` (see [API reference](api-reference.md#routing-intended-bgp-state)):

| Method | Path | |
|---|---|---|
| GET, POST | `/autonomous-systems` | `?tenant_id=&search=` |
| GET, PUT, DELETE | `/autonomous-systems/{id}` | GET adds `routing_instances`, `peerings`; DELETE in use: 409 |
| GET, POST | `/instances` | `?host_id=&asn=&status=&tenant_id=&search=` |
| GET, PUT, DELETE | `/instances/{id}` | GET adds `peer_groups`, `peerings` |
| GET, POST | `/peer-groups` | `?routing_instance_id=&host_id=&search=` |
| GET, PUT, DELETE | `/peer-groups/{id}` | |
| GET, POST | `/peerings` | `?host_id=&routing_instance_id=&asn=&status=&tenant_id=&search=` |
| GET, PUT, DELETE | `/peerings/{id}` | |
| GET | `/compliance` | `?host_id=&state=`: `rows`, `summary`, `hosts` |
| GET | `/suggestions?host_id=` | proposals; creates nothing |
| POST | `/suggestions/accept` | `{host_id, routing_instance_id \| new_instance, peerings: [...]}` |

A bad value answers 422 with `{"message", "fields": {field: message}}`, a
duplicate 409, an unknown id 404. Example:

```json
POST /api/routing/peerings
{"routing_instance_id": 3, "remote_address": "2001:db8::2", "local_address": "2001:db8::1",
 "remote_asn_id": 7, "status": "active", "address_families": ["ipv6-unicast"]}
```
