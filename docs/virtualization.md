# Virtualization

Plexus models the virtual machines you run and the clusters that run them,
next to the physical devices of the inventory. Open **Assets >
Virtualization**.

| Record | What it is | Example |
|---|---|---|
| **Cluster type** | What runs a cluster | VMware vSphere, Proxmox, AWS EC2 |
| **Cluster group** | A free grouping of clusters | Production, Lab |
| **Cluster** | A pool of compute, optionally at a site and of a tenant | `cl-east`, vSphere, site HQ |
| **Cluster host** | A physical hypervisor (an inventory host) in a cluster | `esx-01.example.com` |
| **Virtual machine** | A VM in a cluster | `web-01`, 4 vCPU, 8 GB, `192.0.2.10` |
| **VM interface** | A VM's interface with its MAC, MTU, VLAN, VRF and addresses | `eth0`, `192.0.2.10/24` |

The page has four tabs: **Virtual machines**, **Clusters**, **Cluster
types** and **Cluster groups**. A VM's detail panel lists its interfaces
and addresses, links to its cluster and to the cloud resource it mirrors,
and shows its change log; a cluster's lists its hypervisor hosts and VMs.
The device page of a host that is a cluster member says which clusters it
is a hypervisor of.

## Who can use it

| Action | Needs |
|---|---|
| See clusters, VMs, types and groups | The `virtualization` feature |
| Add, change or delete them, add or remove cluster hosts | `virtualization` and `virtualization.write` (admins have both) |
| Run the cloud sync by hand | An admin |

Grant the features to an access group in Settings. Accounts limited to
selected inventory groups see the clusters of their tenants, sites and
devices and the virtual machines in them; cluster types and groups are read
only for them (see [object-level permissions](object-permissions.md)).

Every change is written to the audit log under the `virtualization`
category and to the change log (`cluster_type`, `cluster_group`, `cluster`,
`virtual_machine`, `vm_interface`), and is sent to event webhooks that
subscribe to those types.

## Rules

- Names of cluster types, cluster groups and clusters are unique, ignoring
  case. A VM name is unique within its cluster; an interface name within
  its VM.
- A cluster needs a type. A VM needs a cluster.
- A cluster type or group that a cluster uses, and a cluster that holds
  VMs, cannot be deleted (409 naming the count). Deleting a cluster
  removes its host memberships, never the hosts. Deleting a VM deletes its
  interfaces and their addresses.
- VM status is one of `active`, `offline`, `planned`, `staged`, `failed`,
  `decommissioning`. Role is a device role (the same list hosts use).
- Primary IPv4 / IPv6 are single addresses of that family. Interface
  addresses are in CIDR form (`192.0.2.10/24`, `2001:db8::10/64`); a bare
  address is stored with the host length. An address appears once per
  interface.
- A MAC address is accepted as `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`,
  `aabb.ccdd.eeff` or 12 hex digits and stored as `aa:bb:cc:dd:ee:ff`. MTU
  is 68 to 65536. Mode is `access`, `tagged` or none; an untagged VLAN
  needs a mode.
- A refused value answers 422 with `detail = {message, fields}`; the
  dialogs show each message under its field.

## Cloud instances as virtual machines

Plexus mirrors the compute instances Cloud Visibility discovers as
virtual machines. The sync runs after every stored discovery (manual,
scheduled, live or sample) and from **Sync cloud instances** on the
Virtual machines tab (admins; `POST /api/virtualization/sync-cloud`).
A failed sync is logged and never fails the discovery.

| Provider | Resource type mirrored | Cluster type | Cluster | Interfaces |
|---|---|---|---|---|
| AWS | `instance` (EC2) | AWS EC2 | one per account and region | one per network interface, named by its ENI id |
| Azure | `vm` | Azure | one per subscription and region | one per NIC, by NIC name |
| GCP | `instance` (Compute Engine) | GCP | one per project and region | one per network interface (`nic0`...) |

For each instance the sync stores:

- **Name** from the instance (an AWS instance without a Name tag is named
  by its id). Two instances with one name in one cluster: the second gets
  its instance id appended.
- **Status** from the provider state: running is `active`; pending,
  provisioning and starting are `staged`; stopping, stopped, terminated,
  suspended and deallocated are `offline`; failed is `failed`. Azure's
  network API reports no power state, so an Azure VM found by the
  discovery is `active`.
- **Platform** (AWS `PlatformDetails`), **primary IPv4 / IPv6** (the
  primary private address), a **description** naming the instance size and
  zone (or the Azure resource group).
- **Interfaces** with their MAC when the provider reports one, and their
  private addresses with the prefix length of their subnet, public
  addresses as host addresses (/32). GCP alias ranges are not stored.
- The **link to the cloud resource** (shown on the VM, linked to Cloud
  Visibility).

vCPUs, memory and disk are not reported by the network discovery APIs and
stay empty for cloud VMs (gap).

How the sync treats existing VMs:

- A sync with nothing new changes nothing (no changes, no change log
  entries).
- **A VM a person edited is never overwritten.** Saving a discovered VM,
  or adding, changing or removing one of its interfaces, makes it `manual`;
  from then on the sync only refreshes its link to the cloud resource.
- A discovered VM whose instance is no longer in the account's snapshot is
  set to `offline`, never deleted; it becomes active again if the instance
  comes back. When the cloud account is deleted, its discovered VMs are
  set offline at the next full sync.
- Deleting a discovered VM whose instance still exists brings it back at
  the next sync.
- A cluster the sync created can be renamed, given a group, site or tenant;
  the sync finds it by its key, not its name.

## API

All under `/api/virtualization`; see [API reference](api-reference.md#virtualization).
