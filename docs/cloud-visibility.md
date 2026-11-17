# Cloud Visibility

Cloud Visibility connects Plexus to AWS accounts, Azure subscriptions and
GCP projects. It reads their networks, gateways, connections and security
rules, and optionally their flow logs and traffic metrics, and shows them
next to the on-premises devices. Discovered accounts also appear on the
Topology map. In this guide "account" means an AWS account, an Azure
subscription or a GCP project.

## Where it is and what you need

- **Observe > Cloud Visibility** in the sidebar. The tabs are **Accounts**,
  **Topology**, **Flow Logs**, **Traffic Metrics** and **Policy**. The
  **Provider** filter beside the tabs applies to every tab; the account
  filter shows on every tab except **Accounts**.
- The feature is experimental and hidden from the sidebar on a new install.
  An admin shows it under **Settings > Features**. The page always shows a
  "has not been tested yet" warning.
- You need the `cloud-visibility` feature to see the page. Adding, changing,
  deleting and discovering accounts, and the sync settings, are admin-only.
- Live reads need the provider's SDK on the Plexus server
  (`pip install -r requirements-cloud.txt`). The **Live reads** row on the
  Accounts tab shows each provider as **ready** or **unavailable**, with the
  missing packages. Without it, **Discover** is disabled for that provider.

## Add an account

1. On **Accounts**, click **Add cloud account**.
2. Choose the **Provider** and enter a **Name**.
3. Enter the identifier:

   | Provider | Field | Notes |
   |---|---|---|
   | AWS | **AWS account ID** (for example `123456789012`) | Optional, shown in the table |
   | Azure | **Subscription ID** (for example `00000000-0000-0000-0000-000000000000`) | The subscription discovery reads |
   | GCP | **Project ID** (for example `example-project`) | The project discovery, flow logs and traffic metrics read |

4. AWS only: **Regions**, comma-separated. Left empty, only `us-east-1` is
   read. Tick **All regions** to read every region enabled for the account.
5. Under **How Plexus signs in**, choose a method and fill in its fields:

   | Provider | Method | Fields |
   |---|---|---|
   | AWS | **Access key** | **Access key ID**, **Secret access key**, optional **Session token** (temporary keys starting with `ASIA`) |
   | AWS | **IAM role** | **Role ARN**, optional **External ID**, optional access key to assume the role with |
   | AWS | **Credentials of the Plexus server** | Optional **Profile name** from the server's AWS configuration |
   | Azure | **Service principal** | **Tenant ID**, **Client (application) ID**, **Client secret** |
   | Azure | **Credentials of the Plexus server** | None: the server's managed identity or environment credentials |
   | GCP | **Service account key** | **Key file contents** (the JSON key) |
   | GCP | **Credentials of the Plexus server** | None: the server's Application Default Credentials |

6. Optionally open **Flow logs and traffic metrics (optional)**. Discovery
   and the Topology map need none of these:

   | Provider | Flow logs | Traffic metrics |
   |---|---|---|
   | AWS | **Flow log group** in CloudWatch Logs | **Resource IDs**, and optionally **Metric names**, **Metric namespace**, **Resource dimension** |
   | Azure | **Storage account**, **Container**, optional **Storage account key** | **Resource IDs**, optionally **Metric names** |
   | GCP | Read from Cloud Logging for the project | Optionally **Metric types** |

   Azure flow logs are VNet flow logs (container
   `insights-logs-flowlogflowevent`) or, for older setups, NSG flow logs
   (`insights-logs-networksecuritygroupflowevent`, versions 1 and 2).
   Microsoft stopped new NSG flow logs on 30 June 2025 and retires them on
   30 September 2027. Without **Metric names**, each Azure resource gets
   the metrics of its type: network interfaces `BytesReceivedRate`,
   `BytesSentRate`, `PacketsReceivedRate`, `PacketsSentRate`; virtual
   machines and scale sets `Network In Total`, `Network Out Total`; VPN
   gateways `TunnelIngressBytes`, `TunnelEgressBytes`,
   `TunnelIngressPackets`, `TunnelEgressPackets`. A resource of another
   type is skipped with a warning until **Metric names** is set.

7. **Additional settings (JSON, rarely needed)** takes keys that have no
   field, for example `{"role_session_name": "plexus"}` for AWS.
8. Add **Notes** if you want, keep **Enabled** ticked and click **Create**.

A new enabled account is discovered at once. The page then says whether
scheduled discovery is on; when it is off, **Turn on** switches it on.

The permissions each provider needs for discovery are in
[AWS permissions](aws-topology.md#permissions),
[Azure permissions](azure-topology.md#permissions) and
[GCP permissions](gcp-topology.md#permissions).

## Manage accounts

| Column | Shows |
|---|---|
| **Name** | The name, a **disabled** badge, the provider and **Shown on Topology map** when the account is enabled and has resources |
| **Identifier** | The account, subscription or project ID |
| **Regions** | AWS: the regions or **All regions**; Azure **Whole subscription**; GCP **Whole project** |
| **Last sync** | The status of the last discovery (or **never**), its message, the time and the number of nodes and edges |
| **Sync readiness** | **Flow logs ready** or **Flow logs need setup**, **Metrics ready** or **Metrics need setup**, with the missing fields |
| **Actions** | **Discover**, **Edit**, delete |

- **Discover** asks for confirmation and reads the account again. If
  discovery fails, the last snapshot is kept and the error is shown in
  **Last sync**. A section skipped for a missing permission does not fail
  discovery; the message names it.
- **Edit** keeps the stored sign-in, which is encrypted and never shown.
  **Change sign-in and sync settings** replaces all of it, flow log and
  traffic settings included; **Keep what is stored** cancels that. The
  provider cannot be changed.
- Delete removes the account and everything discovered from it: resources,
  connections, policy rules and traffic metrics.
- An account that is not **Enabled** is skipped by scheduled discovery and
  left off the Topology map.

## What the tabs show

| Tab | Shows |
|---|---|
| **Topology** | Tiles (accounts, **Cloud Resources**, **Cloud Links**, **Route Objects**, **Gateways**, **Attachment Links**, **Hybrid Links**), one card per provider, route paths with **Route focus** (**All routes**, **Flagged routes**, **Public egress**, **Hybrid path**), and the **Resources**, **Connections** and **Hybrid Links** tables |
| **Flow Logs** | **Flows**, **Total Bytes**, **Total Packets**, **Unique Sources**, **Unique Destinations**, **Last Seen**, **Traffic over time** and **Top talkers** (ranked by **Source IP** or **Destination IP**) |
| **Traffic Metrics** | **Samples**, **Metric Names**, **Resources**, **Total Value**, **Average Value**, **Last Seen**, **Metric total over time** and **Top resources** |
| **Policy** | **Effective policy views** per resource (rules, public ingress, open egress, deny rules) and the **Rule inventory**, filtered by **Exposure**, **Direction** and **Action** |

Flow Logs and Traffic Metrics have a **Time window** (1 hour to 7 days), a
limit and a **Timeline bucket** (1 to 60 minutes). They show data only after
a pull; see the next section. Every tab except **Policy** refreshes every
60 seconds.

**Hybrid Links** pair inventory hosts with one cloud gateway of the account
(for AWS a Direct Connect, VPN connection, transit gateway or VPC, in that
order). They are inferred, not read from the cloud: their state is
`unverified`. A discovery from this page pairs the first two inventory
hosts.

## Schedules and pulls

| Job | Default | Range | Where to set it |
|---|---|---|---|
| Discovery of every enabled account | Off, every 3600 s | 300 to 86400 s | **Turn on** after adding an account, or `PUT /api/cloud/discovery-sync/config` |
| Flow log pull | Off, every 300 s, lookback 15 min | 60 to 3600 s; lookback 5 to 1440 min | **Flow sync** on the Flow Logs tab |
| Traffic metric pull | Off, every 300 s, lookback 15 min | 60 to 3600 s; lookback 5 to 1440 min | **Traffic sync** on the Traffic Metrics tab |

In **Flow sync** and **Traffic sync**, tick **Pull flow logs on a schedule**
(or **Pull traffic metrics on a schedule**), set **Interval (seconds)** and
**Lookback (minutes)**, and click **Save sync settings**. **Pull all** pulls
every eligible account now; **Pull selected account** pulls the account
chosen in the filter. The panel shows the last run, its errors and, per
account, the end of the last pull. The form accepts a lookback from 1; the
server raises values under 5 to 5.

## How it relates to the Topology map

Every enabled AWS, Azure and GCP account that has been discovered joins the
Topology map, and the map follows each new discovery. Accounts are managed
here, not on the Topology page: the Topology **Sources** dialog lists them,
and its **Collect Now** runs the same discovery as **Discover**. What is
drawn and how cloud entities join availability tracking is in
[AWS in the Topology Map](aws-topology.md),
[Azure in the Topology Map](azure-topology.md) and
[GCP in the Topology Map](gcp-topology.md).

Each stored discovery also mirrors the account's compute instances (AWS
EC2, Azure VMs, GCP Compute Engine) as virtual machines under **Assets >
Virtualization**; see [Virtualization](virtualization.md#cloud-instances-as-virtual-machines).

## Rules worth knowing

- **One entry per account.** One entry reads one AWS account, one Azure
  subscription or one GCP project. Add one entry per account.
- **A discovery replaces the snapshot** of the account. A failed discovery
  keeps the previous one.
- **Demo accounts.** The Topology **Sources** dialog can load sample
  accounts. They show sample data and scheduled discovery skips them.
  Delete them here when done.
- **Retention.** Cloud flow records share the NetFlow table and its
  retention (48 hours by default); see [Data retention](../DATA_RETENTION.md).
  Traffic metrics are kept 168 hours (7 days).
- **Credentials are write-only.** The API never returns them; it reports
  only whether some are stored.

## Who can do what

| Action | Needs |
|---|---|
| Open Cloud Visibility and read every tab | The `cloud-visibility` feature |
| Show the page in the sidebar | Admin, under **Settings > Features** |
| Add, edit, delete or discover an account | Admin |
| Change discovery, flow or traffic schedules, pull now, see sync cursors | Admin |
| See the cloud accounts on the Topology map | The `topology` feature |

Account changes, discoveries and schedule changes are written to the audit
log under `cloud_visibility`.

## API

The full list is in [API reference](api-reference.md).

| Method and path | Purpose |
|---|---|
| `GET /api/cloud/providers` | Providers and whether live reads are ready |
| `GET /api/cloud/accounts?provider=`, `POST`, `PUT/DELETE /api/cloud/accounts/{id}` | Accounts |
| `POST /api/cloud/accounts/{id}/discover` | Discover now; `GET .../discover/progress` while it runs |
| `GET /api/cloud/topology?provider=&account_id=` | Resources, connections, hybrid links and counts |
| `GET /api/cloud/flow-logs/summary`, `/top-talkers`, `/timeline` | Flow data (`hours` 1 to 720) |
| `GET /api/cloud/traffic-metrics/summary`, `/top-resources`, `/timeline` | Traffic metric data |
| `GET /api/cloud/policies/effective`, `GET /api/cloud/policies/rules` | Policy |
| `GET/PUT /api/cloud/discovery-sync/config`, `/flow-sync/config`, `/traffic-sync/config` | Schedules |
| `POST /api/cloud/flow-sync/pull?account_id=`, `POST /api/cloud/traffic-sync/pull?account_id=` | Pull now |

Add an Azure subscription with a service principal:

```json
POST /api/cloud/accounts
{
  "provider": "azure",
  "name": "Example production",
  "account_identifier": "00000000-0000-0000-0000-000000000000",
  "auth_type": "service_principal",
  "auth_config": {
    "subscription_id": "00000000-0000-0000-0000-000000000000",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "00000000-0000-0000-0000-000000000000",
    "client_secret": "example-secret"
  },
  "enabled": true
}
```

The answer is `{"ok": true, "account": {...}}`. The account carries
`has_auth_config` and `sync_readiness`, never the stored settings. An
unknown provider gives `400`.

Turn on scheduled discovery every two hours:

```json
PUT /api/cloud/discovery-sync/config
{ "enabled": true, "interval_seconds": 7200 }
```

```json
{ "ok": true, "config": { "enabled": true, "interval_seconds": 7200 } }
```
