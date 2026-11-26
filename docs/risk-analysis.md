# Risk analysis

Risk analysis scores a proposed configuration change before you make it. You
give the commands you plan to send. Plexus applies them to a copy of the
current running configuration, shows the predicted diff, checks which
network areas the commands touch and whether they break compliance rules, and
gives the change a score from 0 to 100 % and a level: Low, Medium, High or
Critical. You use it to review a change, approve it, and link the approved
analysis to a deployment.

## Where it is

Open **Change > Changes**. **Risk Analysis** is the first tab of the Change
Management page. The other tabs are described in
[Change management](change-management.md).

You need the `risk-analysis` feature. The **New Analysis** form fills its
lists from other pages, so you also need:

- `inventory` for the **Target Group** list,
- `credentials` and a credential of your own for the **Credential** list
  (see [Running jobs](jobs.md#managing-credentials-and-secrets)),
- `templates` to pick an instruction set as the **Source**.

**Offline Analysis** needs none of these.

## Running an analysis against devices

1. Choose **New Analysis**. The form is titled "Pre-Change Risk Analysis".
2. **Change Type:** **Template**, **Policy / ACL**, **Route**, **NAT** or
   **Manual**. This is a label for the record; it does not change the score.
3. **Target Group:** the inventory group. Every host in the group is
   analysed.
4. **Credential:** required. Plexus uses it to read each host's running
   configuration.
5. **Source:** pick an instruction set, or keep **- Enter commands manually
   -** and type the commands in **Proposed Commands (one per line)**.
6. Choose **Analyze Risk**.

For each host Plexus uses a configuration backup that is at most 15 minutes
old, or reads the running configuration from the device. A summary then
shows the level, the score, the number of hosts analysed, the compliance
violations and the affected areas. Choose **Open details** to see the full
record.

## Running an offline analysis

Use this for a device Plexus cannot reach, or to try a change on pasted text.

1. Choose **Offline Analysis**.
2. Pick the **Change Type** (**Policy / ACL**, **Route**, **NAT** or
   **Manual**).
3. Paste the configuration into **Current Running Config**.
4. Type the commands into **Proposed Commands (one per line)**.
5. Choose **Analyze**. The details open.

No device is contacted and no compliance check is made.

## How the change is simulated

Plexus does not run the commands. It edits the configuration text:

- Blank lines and lines that start with `!` or `#` are skipped.
- A line that starts with `no ` removes every configuration line that
  contains the rest of the command, ignoring case. For example `no shutdown`
  removes every line that contains `shutdown`, on every interface.
- Any other line is added at the end of the configuration.

The diff between the original text and the edited text is the **Predicted
Config Diff**. Because commands are not merged into their sections, the
diff is an estimate; a real device may behave differently. To test on a
real network operating system, use the [Lab](lab-mode.md).

## How the score is calculated

The score is the sum of four parts, capped at 100 %:

| Part | Adds |
|---|---|
| Number of commands | more than 5: 5 %, more than 10: 10 %, more than 20: 15 %, more than 50: 20 % |
| Critical areas touched | up to 40 %, see below |
| Lines removed in the diff | 1 or more: 5 %, more than 5: 10 %, more than 10: 15 %, more than 20: 20 % |
| New compliance violations | 1 or more: 10 %, more than 2: 15 %, more than 5: 20 % |

A command belongs to an area when it contains one of the area's keywords
(ignoring case). Each area adds its weight times (matching commands / 3), at
most its full weight. Three matching commands give the full weight.

| Area | Weight | Keywords |
|---|---|---|
| Routing | 25 % | `router ospf`, `router bgp`, `router eigrp`, `router rip`, `ip route`, `ipv6 route`, `network `, `redistribute`, `route-map`, `prefix-list`, `as-path` |
| ACL / Policy | 20 % | `access-list`, `ip access-list`, `permit `, `deny `, `access-group`, `policy-map`, `class-map`, `service-policy` |
| NAT | 20 % | `ip nat `, `nat `, `object network`, `nat (`, `static (`, `pat-pool`, `xlate` |
| Interface | 15 % | `interface `, `shutdown`, `no shutdown`, `ip address`, `switchport`, `channel-group`, `vlan ` |
| Security / AAA | 20 % | `crypto `, `ipsec `, `ikev2`, `tunnel `, `aaa `, `radius`, `tacacs`, `enable secret`, `username `, `snmp-server community`, `line vty`, `ssh ` |

New compliance violations are counted per host. Plexus runs every enabled
compliance profile assigned to the host's group against the configuration
before and after the change. The violations are the extra failed rules.

The level comes from the score:

| Score | Level | Badge |
|---|---|---|
| 70 % or more | Critical | Red, solid |
| 50 % to 69 % | High | Red |
| 30 % to 49 % | Medium | Amber |
| below 30 % | Low | Blue |

For example, `ip route 198.51.100.0 255.255.255.0 192.0.2.1` and
`ip route 203.0.113.0 255.255.255.0 192.0.2.1` touch Routing twice: 25 % x
2/3 = about 17 %. With no removed lines and no violations the score is 17 %,
level Low.

## Reading the result

The list shows each analysis with its level, score, target, change type,
**Approved** or **Pending**, the affected areas, the time and the user. A bar
under each row shows the score. Filter by level or search by host name, group
or change type. The strip at the top counts **Total**, **High risk** (High and
Critical), **Approved**, **Pending** and the **Last analysis** time.

**Details** opens "Risk Analysis Details":

| Section | Shows |
|---|---|
| Level and **Risk Score** | The result. |
| Target, Change type, Status, Created | The record. |
| **Affected Areas** | The areas the commands touch. |
| **Risk Factors** | Plain reasons, for example "Removes 3 line(s) from running config". |
| **Change Volume** | Commands and diff lines added and removed. |
| **Compliance Impact** | Per profile: new violations, improvements, and each rule that changed (`REGRESS` or `IMPROVE`). |
| **Proposed Commands** | The commands analysed. |
| **Predicted Config Diff** | The simulated diff. |

## Approving and using an analysis

In the details choose **Approve Change** and confirm. You are recorded as the
approver. An approved analysis can then be picked as **Linked Risk Analysis
(optional)** when you create a deployment; that list offers approved
analyses among the 50 newest. Linking a High or Critical analysis makes the
deployment require approval. See [Deployments](deployments.md).

## Rules worth knowing

- **Group results.** The score and level are the highest of all hosts. The
  affected areas are combined. The diff, risk factors, compliance impact and
  target shown in the details come from the first host only.
- **Unreachable hosts.** A host whose configuration cannot be read scores 0.
  If no host can be read, the analysis is saved as Low with 0 %.
- **Instruction sets.** The selected instruction set's own text is used.
  Vendor variants are not chosen per host and `{{secret.NAME}}` references
  are not filled in.
- **Secrets are masked.** An analysis run against a device follows the rule
  for device configuration
  ([Config backups and drift](config-backups-and-drift.md)): without
  `config-backups.write` and write access to the device, the captured
  configuration, the **Predicted Config Diff**, the **Proposed Commands**
  and the commands listed under an affected area show secret values as
  `********`. That includes commands you typed yourself. The stored analysis
  keeps the commands as entered. An offline analysis is shown as it was
  entered to every user who can see it, so do not paste secrets into one.
- **Approval is final.** There is no way to withdraw an approval. Any user
  with the feature can approve any analysis, including their own.
- **Deleting** an analysis removes it after you confirm. Any user with the
  feature can delete any analysis.
- **List size.** The page loads the 200 newest analyses.

## Who can do what

| Action | Needs |
|---|---|
| See, run, approve and delete analyses | `risk-analysis` feature |
| Fill the target, credential and source lists | `inventory`, `credentials`, `templates` features |
| Use a credential | You must own it |

Analyses are written to the audit log under `risk-analysis`
(`analysis.created`, `analysis.offline`, `analysis.approved`,
`analysis.deleted`). See [Audit log](audit-log.md).

## API

All routes follow the usual session and CSRF rules. See also
[API reference](api-reference.md).

```
POST   /api/risk-analysis/analyze
POST   /api/risk-analysis/analyze-offline
GET    /api/risk-analysis?host_id=&group_id=&risk_level=&limit=100   (limit 1 to 500)
GET    /api/risk-analysis/summary
GET    /api/risk-analysis/{id}
POST   /api/risk-analysis/{id}/approve
DELETE /api/risk-analysis/{id}
```

`analyze` takes one target: `host_ids`, `host_id` or `group_id`, and either
`proposed_commands` or `template_id`.

```json
POST /api/risk-analysis/analyze
{
  "change_type": "route",
  "group_id": 4,
  "credential_id": 5,
  "proposed_commands": [
    "ip route 198.51.100.0 255.255.255.0 192.0.2.1",
    "no ip route 203.0.113.0 255.255.255.0 192.0.2.254"
  ]
}
```

```json
{
  "id": 57,
  "risk_level": "low",
  "risk_score": 0.217,
  "hosts_analyzed": 2,
  "total_compliance_violations": 0,
  "affected_areas": ["Routing"],
  "host_results": [ "... one object per host ..." ]
}
```

No commands gives `400`; a group with no hosts gives `400` "No target hosts
found". `risk_score` is 0 to 1; the UI shows it as a percentage.
