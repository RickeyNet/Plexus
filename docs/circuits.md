# Circuits

Plexus keeps a record of the carrier circuits you buy: who provides each
one, what kind of service it is, its status and committed rate, and where
each end lands, down to the device port. Open **Assets > Circuits**.

| Record | What it is | Example |
|---|---|---|
| **Provider** | The carrier a circuit is bought from | Example Carrier, account `ACC-1001` |
| **Provider network** | A network of a provider that a circuit can end in | Example Carrier's MPLS cloud |
| **Circuit type** | The kind of service | Internet, MPLS, Dark fibre |
| **Circuit** | One carrier service, known by the provider's circuit ID | `CKT-1001`, Internet, 100 Mbps |
| **Termination** | One end of a circuit: A or Z | A: site HQ, edge-r1 `GigabitEthernet0/1` |

The page has three tabs: **Circuits**, **Providers** (with each provider's
networks) and **Circuit types**. Each record's detail panel shows its
change log.

Circuits are separate from bandwidth billing (Reports > Billing). A circuit
can point at the billing record that bills it, but the two are kept apart:
billing works on an interface with a customer and a commit rate for the
95th-percentile report, while a circuit describes the carrier service.

## Who can use it

| Action | Needs |
|---|---|
| See circuits, providers, networks and types | The `circuits` feature |
| Add, change or delete them | `circuits` and `circuits.write` (admins have both) |

Grant the features to an access group in Settings.
Accounts limited to selected inventory groups see the circuits of their
tenants and those terminating on their devices or sites; providers,
provider networks and circuit types are read only for them (see
[object-level permissions](object-permissions.md)).

Every change is written to the audit log under the `circuits` category and
to the change log (`circuit_provider`, `provider_network`, `circuit_type`,
`circuit`, `circuit_termination`), and is sent to event webhooks that
subscribe to those types.

## Providers and provider networks

A provider has a name (unique, ignoring case, up to 100 characters), and
optionally an account number, a portal URL (`http://` or `https://`), NOC
and admin contacts, and comments.

A provider network has a name that is unique within its provider (ignoring
case) and a description. It cannot move to another provider.

- A provider that has circuits, or whose networks have terminations, cannot
  be deleted. Deleting an unused provider deletes its networks too.
- A provider network that a termination ends in cannot be deleted.

## Circuit types

A circuit type has a name (unique, ignoring case) and a description. A type
that circuits use cannot be deleted.

## Circuits

| Field | Rule |
|---|---|
| Circuit ID | Required, up to 100 characters; unique per provider, ignoring case |
| Provider, circuit type | Required. Neither can be deleted while the circuit exists |
| Status | `planned`, `provisioning`, `active` (default), `offline`, `deprovisioning` or `decommissioned` |
| Tenant | Optional; cleared when the tenant is deleted |
| Install date, termination date | Optional, `YYYY-MM-DD`; the termination date cannot be before the install date |
| Commit rate | Optional, whole kbps |
| Description, comments | Optional |
| Billing circuit | Optional link to a bandwidth billing record; cleared when that record is deleted. The picker shows only to users with the `reports` feature |

The circuits list filters by provider, type and status, and searches the
circuit ID and description (ignoring case). The API also filters by tenant,
site and device.

## Terminations

A circuit has at most one **A** and one **Z** termination. Each ends at
**either** a site **or** a provider network, never both and never neither.
Optionally a termination names the device it lands on and the interface,
plus port and upstream speeds (kbps), a cross-connect ID, the patch panel /
port and a description.

- The device must exist. An interface needs a device.
- The interface picker offers the names Plexus already knows for the device
  (collected interface inventory, polled interface counters and cables).
  Another name can be typed, for a port Plexus has not read yet.
- Deleting a site deletes the terminations at it. Deleting a device clears
  the termination's device (the interface name stays).
- Cables (DCIM) can connect to a termination by its id.

## Utilisation

When a circuit has a commit rate and a termination on a device port, the
circuit's detail panel and the device page show the port's latest in and
out rate, and each as a share of the commit rate. The rate comes from the
interface counters the topology poller already stores for the device (the
same numbers the utilisation weathermap uses); nothing extra is polled.
Without counters for the port (or its speed), or without a commit rate,
the circuit has no utilisation row.

## Device page

The **Interfaces** tab of a device lists the circuits with a termination on
that device: circuit ID, provider, status, side, interface, commit rate and
the latest in / out rate.

## API

All under `/api/circuits`, see [api-reference.md](api-reference.md#circuits).

```http
POST /api/circuits/circuits
{
  "cid": "CKT-1001",
  "provider_id": 1,
  "circuit_type_id": 1,
  "status": "active",
  "commit_rate_kbps": 100000,
  "terminations": [
    {"term_side": "A", "site_id": 3, "host_id": 12, "interface_name": "GigabitEthernet0/1"},
    {"term_side": "Z", "provider_network_id": 2}
  ]
}
```

A refused write answers `422` with `detail.fields`: the field names, or
`terminations.<A|Z>.<field>` for a termination. A duplicate name or circuit
ID, or a delete of a record in use, answers `409`.

## Storage

Migration 0099 adds `circuit_providers`, `provider_networks`,
`circuit_types`, `circuits` and `circuit_terminations`. The site-or-network
rule and one termination per side are enforced by the database as well.
