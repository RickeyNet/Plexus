# Hardware lifecycle

Plexus keeps the vendor's end-of-life dates for your hardware and the
support contracts that cover each device, shows where every device stands,
and raises a monitoring alert when a device passes or nears its last date of
support or its contract coverage runs out. It is the hardware counterpart of
the software tracker ([software-versions.md](software-versions.md)), which
covers software versions and CVE advisories. Open **Software > Lifecycle**.

| Record | What it is | Example |
|---|---|---|
| **End-of-life notice** | The vendor's end-of-life dates for one hardware model: a device type, or a part number | Example Networks EX-1000: end of sale 2026-01-31, last date of support 2031-01-31 |
| **Support contract** | A support contract with a provider and the devices it covers | Example Support Co `SC-1001`, 24x7x4, ends 2027-06-30, 12 devices |

The tab has three sections: **Devices** (every inventory device with its
stage, end of sale, last date of support, next milestone and contract
coverage, and the fleet summary above it), **End-of-life notices** and
**Support contracts**. The device page shows a **Hardware lifecycle**
section with the notices that apply to the device and its contracts.

## Who can use it

| Action | Needs |
|---|---|
| See notices, contracts, device status and the CSV report | The `lifecycle` feature |
| Add, change or delete notices and contracts, change the alert settings, run the alert check | `lifecycle` and `lifecycle.write` (admins have both) |

Grant the features to an access group in Settings. Accounts limited to
selected inventory groups see the lifecycle status and contracts of their
devices; notices are read only and the alert settings and check are refused
(see [object-level permissions](object-permissions.md)).

Every change is written to the audit log under the `lifecycle` category and
to the change log (`hardware_notice`, `support_contract`), and is sent to
event webhooks that subscribe to those types. Changing which devices a
contract covers is audited (`hosts=<count>`); the change log records the
contract's own fields.

## End-of-life notices

A notice applies to **either** a device type of the device model catalogue
([device-model.md](device-model.md)) **or** a part number, never both.

- **Device type**: one notice per device type. It applies to every device of
  that type and is deleted with the device type.
- **Part number**: unique ignoring case, no spaces. It applies to every
  device whose device type has that part number or that model, and to every
  device with a module (DCIM, [dcim.md](dcim.md)) of that part number,
  ignoring case. Use it for line cards, power supplies and other modules,
  or for a model named by its part number.

A notice has four optional milestones, `YYYY-MM-DD`, in the order they fall
due. A milestone cannot be before an earlier one that is set.

| Milestone | Meaning |
|---|---|
| End of sale | The last day the vendor sells the product |
| End of software maintenance | The last software release with bug fixes |
| End of security fixes | The last software release with security fixes |
| Last date of support | The vendor stops supporting the hardware |

Plus a documentation URL (`http://` or `https://`, the vendor's notice) and
comments. A milestone is passed on its date.

## Support contracts

| Field | Rule |
|---|---|
| Provider | Required, up to 100 characters: the vendor or reseller |
| Contract ID | Required, up to 100 characters; unique per provider, ignoring case |
| Start date, end date | Optional, `YYYY-MM-DD`; the end date (the last day covered) cannot be before the start date. Without an end date the contract never expires |
| Cost, currency | Optional: a cost from 0 with at most two decimals, and an ISO 4217 code (`USD`, `EUR`) |
| Support level | Optional, for example `24x7x4` or `Next business day` |
| Description, comments | Optional |
| Covered devices | Any inventory devices. A device can be covered by several contracts; deleting a device or a contract removes the link |

A contract's state on a day: **Not started** (before its start date),
**Active**, **Expiring** (its end date within the contract warning window,
60 days by default) or **Expired** (after its end date).

## Device status

For each device, Plexus folds the notices that apply to it and the
contracts that cover it into one status:

- **Stage**: the furthest milestone any of its notices has passed: *No
  notice*, *Announced* (a notice applies, no milestone passed yet), *End of
  sale*, *End of SW maintenance*, *End of security fixes* or *End of
  support*.
- **End of sale** and **last date of support**: the earliest such dates of
  its notices, with the days to them (negative: passed).
- **Next milestone**: the nearest milestone still to come.
- **Coverage**: *Covered* by a contract in force, *Expiring* (the latest end
  of the contracts in force is within the warning window), *Expired* (it had
  contracts, none in force), *Not started* (its only contracts start later)
  or *No contract*. A contract in force without an end date always covers.

The **Devices** section filters by stage, coverage and a search of the
name, IP address and device type. **Export CSV** downloads the filtered list
(`GET /api/lifecycle/status/export`), one row per device with its dates,
stage, coverage and contracts. Text a person entered is guarded against
spreadsheet formulas.

## Alerts

A server-side check runs every six hours (first three minutes after start)
and on **Run alert check** (`POST /api/lifecycle/check`). For every device
it raises a monitoring alert (alert type `hardware_lifecycle`, on the
device, in **Monitoring > Alerts** and to the notification channels like
every monitoring alert) for:

| Condition | Severity |
|---|---|
| Past its last date of support | warning |
| Its last date of support within the support warning window (180 days by default) | info |
| Contract coverage expired | warning |
| Contract coverage expiring within the contract warning window | info |

A condition alerts once while it lasts: the check remembers it
(`hardware_lifecycle_alerts`), so acknowledging the alert does not bring it
back at the next check. When the condition clears (a contract is renewed, a
notice changes, the device is covered again), its alert is acknowledged as
`auto-resolved`. A device moving from *nearing* to *past* its last date of
support gets a new alert. Contracts that cover no device do not alert.

**Alert settings** (`lifecycle.write`): alerts on or off (off resolves every
open lifecycle alert at the next check), the contract warning window and the
support warning window (1 to 3650 days each).

## API

All under `/api/lifecycle`, see
[api-reference.md](api-reference.md#hardware-lifecycle).

```http
POST /api/lifecycle/notices
{"device_type_id": 4, "end_of_sale": "2026-01-31", "end_of_support": "2031-01-31",
 "documentation_url": "https://www.example.com/eol/ex-1000"}

POST /api/lifecycle/contracts
{"provider": "Example Support Co", "contract_id": "SC-1001", "end_date": "2027-06-30",
 "support_level": "24x7x4", "cost": "1500.00", "currency": "USD", "host_ids": [12, 13]}
```

A refused write answers `422` with `detail.fields`; a duplicate device type,
part number or contract ID answers `409`.

## Storage

Migration 0103 adds `hardware_notices`, `support_contracts`,
`support_contract_hosts`, `hardware_lifecycle_settings` and
`hardware_lifecycle_alerts`. The device-type-or-part-number rule and the
uniqueness rules are enforced by the database as well.

## Limits

- Notices are entered by hand (or through the API). No vendor publishes a
  hardware end-of-life feed Plexus can match by model, so there is no sync.
- Software end-of-life is not a notice: software versions and their
  advisories are the software tracker's.
- Cloud resources and API-collected devices (Meraki, Cato and the other
  integrations) are not inventory hosts and get no lifecycle status; see
  [vendor-monitoring-coverage.md](vendor-monitoring-coverage.md).
