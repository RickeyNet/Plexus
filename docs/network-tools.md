# Network tools

The Network Tools page has two tools:

- **MAC Tracking** finds where a device is connected. It searches the MAC
  address tables and ARP tables that Plexus collects from switches and
  routers, and records when a MAC address moves to another port or VLAN.
- **Traffic Analysis** shows who sends the most traffic, which services carry
  it, and how it changes over time. It reads the NetFlow, sFlow and IPFIX
  records that devices export to Plexus.

## Where it is and what you need

- Open **Observe > Network Tools** in the sidebar. Each tool is a tab.
- The **MAC Tracking** tab needs the `mac-tracking` feature. The **Traffic
  Analysis** tab needs the `traffic-analysis` feature. You see only the tabs
  you have access to.
- MAC Tracking collects from hosts whose inventory group has SNMP turned on.
  It first tries SSH with the service credential (or the default credential)
  set in Settings, on platforms whose driver can read the MAC table. It falls
  back to SNMP for the MAC table. ARP is always read over SNMP.
- Traffic Analysis needs the flow collector to be on and devices exporting to
  it. See [NetFlow / sFlow / IPFIX](flow-collector.md) for setup, ports and
  retention.

## MAC Tracking

The tab has three views: **Search**, **Moves** and **By Host**.

### Collect the tables

Select **Collect Now** at the top of the tab. Plexus walks every host in
every group with SNMP turned on. This runs in the background. While it runs,
a banner shows how many hosts are done and how many MACs and ARP entries it
has found so far. When it ends, a banner shows the totals. If some hosts
returned partial data or none, open the diagnostics line to see why.

Only one full collection runs at a time. Starting a second one while the
first runs gives the error "A full MAC/ARP collection is already running".

Scheduled topology discovery also collects MAC and ARP tables from each host
it walks, so the tables fill in without **Collect Now** when that schedule is
on.

### Search for a device

1. Open **Search**.
2. Type a MAC address, an IP address, a port name, or a Meraki client name
   in the search box. MAC addresses match in any format: with `:`, `-`, `.`
   or no separator. Part of a value also matches, for example the first 6
   hex digits of a MAC address.
3. Select **Search**. Select **Clear** to go back to the full list.

With no search, the list shows the most recently seen entries.

| Column | Meaning |
|---|---|
| **MAC Address** | The MAC. A description and manufacturer show under it when known. |
| **IP Address** | The IP learned from an ARP table for this MAC. |
| **Seen On** | The switch (inventory host) that reported the MAC. A **Meraki** badge marks a client reported by a Meraki device, with its network name. |
| **Port** | The port the MAC was learned on. For a wireless Meraki client, the SSID. |
| **VLAN** | The VLAN the MAC was learned on. |
| **Type** | The entry type, for example `dynamic`. |
| **First Seen** / **Last Seen** | When Plexus first and last saw this entry. |

Select **History** on a row to see each place this MAC was seen: time,
switch, port, VLAN and IP. History is not available for Meraki clients.

The tiles above the search box show **Total Entries**, **Unique MACs**,
**Switches Reporting**, **Meraki Clients** (when there are any) and **Last
Collected**. Meraki clients come from a Meraki collection on the Topology
page, not from **Collect Now**.

### Review moves

A move is recorded when a MAC changes port or VLAN on the same switch. The
same MAC seen on another switch is not a move: a MAC is normally visible on
its access switch and on every uplink switch at once. Sightings on uplink
ports are not used for moves. The first time a MAC is seen on a switch only
sets its starting point.

1. Open **Moves**.
2. Choose a status (**Open**, **Acknowledged** or **All statuses**) and,
   if you want, one switch (**All switches** shows every switch).
3. Read the list:

   | Column | Meaning |
   |---|---|
   | **MAC Address** | The MAC that moved. |
   | **Changed** | What changed: `port`, `vlan`, `ip`, or several of them. |
   | **From** / **To** | Switch and port, VLAN, and IP before and after. |
   | **Detected** | When the move was found. |
   | **Status** | `open` (yellow) or `acknowledged` (green). |

4. Select **Acknowledge** on a row when you have checked the move, or
   **Acknowledge all open** to acknowledge every open move on every switch.
5. Select **Log** to see the event's history: when it was detected and who
   acknowledged it.

The tiles show the number of **Open**, **Acknowledged** and **Total** moves.

### Find hosts that return nothing

Open **By Host** to see what each inventory host returned.

| Filter | Shows |
|---|---|
| **Silent** (default) | Hosts with SNMP on that returned no MAC entries. |
| **Reporting** | Hosts that returned at least one MAC entry. |
| **All hosts** | Every host. |

The table shows **Host**, **IP**, **Group**, **SNMP** (`enabled` or `off`),
**MAC rows**, **Unique MACs**, **ARP rows** and **Last MAC seen**. A
`silent` badge marks a silent host. Common causes are a device that does not
bridge, wrong SNMP credentials, an ACL that blocks the poller, or a device
that needs per-VLAN SNMPv3 contexts.

Select **Collect** on a row to walk that one host now. The result shows
under the row: the numbers collected and any error messages. **Collect** is
turned off for a host whose group has SNMP off.

## Traffic Analysis

### Choose what to see

- Use the time bar at the top of the page to choose the window. The flow
  views support up to 7 days. A longer range is cut to 7 days, and the page
  says so.
- Use **All hosts** to choose one exporting device, or keep all of them.
- The badges on the right show whether the **NetFlow** and **sFlow**
  listeners are `running` or `stopped`.

### Views

| Tab | What it shows |
|---|---|
| **Top Talkers** | Two charts and tables, **Top Sources** and **Top Destinations**: the 10 IP addresses with the most bytes, with **Traffic** and **Flows**. |
| **Top Applications** | The 15 largest destination port and protocol pairs by bytes. Well known ports show a service name. |
| **Conversations** | The 15 source and destination IP pairs with the most bytes, with **Traffic** and **Flows**. |
| **Timeline** | Traffic in bits per second over the window. |
| **Exporters** | Every device that has sent flows to Plexus. |

The timeline groups records into buckets: 1 minute for a window of 1 hour,
5 minutes up to 6 hours, and 15 minutes for longer windows. The last bucket
may show too little if it has not closed yet.

The **Exporters** table has these columns:

| Column | Meaning |
|---|---|
| **Exporter IP** | The source address of the flow packets. |
| **Host** | The inventory host with that address, or `(unresolved)`. |
| **Type** | The flow protocol and version, for example `netflow_v9` or `sflow_v5`. |
| **Packets** | Flow packets received from this exporter. |
| **Sampling** | The sampling rate, shown as `1:N`, when the exporter reports one. |
| **First Seen** / **Last Seen** | When packets from this exporter first and last arrived. |

If no device has exported yet, the tab says to send NetFlow v5, v9 or IPFIX
to UDP 2055, or sFlow v5 to UDP 6343 (the default ports).

## Rules worth knowing

- **MAC table entries are not removed on a schedule.** An entry stays until
  a newer collection updates it or someone calls the cleanup endpoint, which
  removes entries not seen for a number of days (default 30).
- **Move events and MAC history are pruned** after 90 days by default. The
  pruning runs every hour.
- **Search returns up to 5,000 rows** by default. The API allows up to
  50,000.
- **The moves list shows up to 500 events** in the page. The API allows up
  to 1,000 per request.
- **The flow views read raw flow records.** Raw records are kept for 48
  hours by default (see [NetFlow / sFlow / IPFIX](flow-collector.md)), so a
  7 day window shows only what is still kept.

## Who can do what

| Action | Needs |
|---|---|
| Search, view moves and the by-host table | The `mac-tracking` feature |
| Collect now, acknowledge moves | The `mac-tracking` feature |
| See traffic views and exporters | The `traffic-analysis` feature |
| Turn the flow collector on or off, change its ports and retention | Admin |

Admins pass every feature check. Acknowledging moves is written to the audit
log under the `mac-tracking` category.

## API

All routes are under the same session and CSRF rules as the rest of the
Plexus API. Examples use invented data. See
[API reference](api-reference.md) for the full list.

```
GET  /api/mac-tracking/search?query=&limit=
GET  /api/mac-tracking/stats
GET  /api/mac-tracking/by-host
GET  /api/mac-tracking/host/{host_id}
GET  /api/mac-tracking/history/{mac_address}
POST /api/mac-tracking/collect[?host_id=]
GET  /api/mac-tracking/collect/jobs/{job_id}
POST /api/mac-tracking/cleanup?days=30
GET  /api/mac-tracking/moves?status=open|acknowledged&host_id=&limit=
GET  /api/mac-tracking/moves/summary
POST /api/mac-tracking/moves/{event_id}/acknowledge
POST /api/mac-tracking/moves/acknowledge-all

GET  /api/flows/top-talkers?hours=&direction=src|dst&host_id=&limit=
GET  /api/flows/top-applications?hours=&host_id=&limit=
GET  /api/flows/top-conversations?hours=&host_id=&limit=
GET  /api/flows/timeline?hours=&bucket_minutes=&host_id=
GET  /api/flows/status
GET  /api/flows/exporters
```

`POST /api/mac-tracking/collect` with `host_id` walks one host and returns
the result at once. A host whose group has SNMP off gives `400`. Without
`host_id` it starts a background job:

```json
{ "job_id": "3f2a9c", "status": "running", "hosts_total": 48 }
```

Poll `GET /api/mac-tracking/collect/jobs/{job_id}` until `status` is no
longer `running`. The `result` has `macs_found`, `arps_found`,
`hosts_collected`, `errors` and `host_errors`.

A search result row (some fields left out):

```json
{
  "mac_address": "00:00:5e:00:53:01",
  "ip_address": "192.0.2.25",
  "hostname": "access-sw-01",
  "host_id": 42,
  "port_name": "Gi1/0/12",
  "vlan": 20,
  "entry_type": "dynamic",
  "first_seen": "2026-11-01 08:00:00",
  "last_seen": "2026-11-14 09:30:00"
}
```

`POST /api/mac-tracking/moves/acknowledge-all` takes
`{"event_ids": []}`. An empty list acknowledges every open move; a list of
ids acknowledges only those. The answer is
`{"ok": true, "acknowledged": <count>}`.

The flow endpoints accept `hours` from 1 to 168 and `limit` from 1 to 100.
`bucket_minutes` on the timeline is 1 to 60.
